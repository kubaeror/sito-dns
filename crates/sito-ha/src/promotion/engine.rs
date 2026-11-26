//! Client-side automatic-promotion engine (ADR-0010).
//!
//! The engine owns the safety-critical sequence:
//!
//! 1. startup acquisition / read-only fallback,
//! 2. candidate eligibility and heartbeat wait,
//! 3. acquire (`term + 1`) with the published baseline only,
//! 4. atomic promotion state write,
//! 5. pre-publish quiesce with baseline renewal,
//! 6. hello-only reconciliation against witness + baseline + peers,
//! 7. `publishing` state, first push, `published` state, renewal,
//! 8. effective-role switch, and
//! 9. renewal conflict handling and durable self-fencing.
//!
//! The engine is transport-agnostic through [`LeaseBackend`] and
//! runtime-agnostic through [`PromotionHost`]. The production witness client and
//! master/slave runtime implement those traits; tests use the real in-process
//! TLS witness with a deterministic host.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sito_ha_types::bundle::{AppliedWatermark, ConfigBundle};
use sito_ha_types::config::PromotionConfig;
use sito_ha_types::status::PublicationState;
use sito_stats::MetricsRegistry;
use tracing::{info, warn};

use crate::error::HaError;
use crate::witness::{AcquireRequest, LeaseInfo, LeaseRecord, RenewRequest};

use super::audit::{
    COMPLETED, FENCED, LEASE_ACQUIRED, LEASE_LOST, LEASE_RENEWED, MANUAL_CONFIRMATION_CONFIRMED,
    MANUAL_CONFIRMATION_REQUIRED, PUBLISH_ABORTED, PromotionAudit, QUIESCED, RECONCILED, REFUSED,
};
use super::witness_client::{WITNESS_REQUEST_TIMEOUT, WitnessClient, WitnessClientError};

use super::acquisition::{AcquisitionDecision, AcquisitionRole, LocalContent, decide_acquisition};
use super::clock::{
    BoxFuture, ManualMonotonicClock, MonotonicClock, PromotionTimers, SystemMonotonicClock,
    SystemTimers,
};
use super::confirm::ConfirmationStore;
use super::fence::{FenceMarker, FencePersistOutcome, FenceReason, FenceStore};
use super::reconcile::{LatePeerLatch, PeerReport, ReconcileDecision, ReconcileInput, evaluate};
use super::renewal::{RenewalAction, SelfFenceCheck, SelfFenceDeadline, classify_renewal_error};
use super::state::{
    HaStateStore, LoadedState, PersistedMasterState, PromotionBookkeeping, PublicationBaseline,
};

/// Minimal witness operations the engine needs.
///
/// Boxed futures keep the trait object-safe without an async-trait dependency.
pub trait LeaseBackend: Send + Sync + 'static {
    /// `GET /v1/info`.
    fn info(&self) -> BoxFuture<'_, Result<LeaseInfo, WitnessClientError>>;
    /// `GET /v1/lease`.
    fn lease(&self) -> BoxFuture<'_, Result<Option<LeaseRecord>, WitnessClientError>>;
    /// `POST /v1/lease/acquire`.
    fn acquire(
        &self,
        request: AcquireRequest,
    ) -> BoxFuture<'_, Result<LeaseRecord, WitnessClientError>>;
    /// `POST /v1/lease/renew`.
    fn renew(
        &self,
        request: RenewRequest,
    ) -> BoxFuture<'_, Result<LeaseRecord, WitnessClientError>>;
}

impl LeaseBackend for WitnessClient {
    fn info(&self) -> BoxFuture<'_, Result<LeaseInfo, WitnessClientError>> {
        Box::pin(async move { WitnessClient::info(self).await })
    }

    fn lease(&self) -> BoxFuture<'_, Result<Option<LeaseRecord>, WitnessClientError>> {
        Box::pin(async move { WitnessClient::lease(self).await })
    }

    fn acquire(
        &self,
        request: AcquireRequest,
    ) -> BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        Box::pin(async move { WitnessClient::acquire(self, &request).await })
    }

    fn renew(
        &self,
        request: RenewRequest,
    ) -> BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        Box::pin(async move { WitnessClient::renew(self, &request).await })
    }
}

/// Configured node role from `config.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfiguredRole {
    /// `server.role = "master"`.
    Master,
    /// `server.role = "slave"`.
    Slave,
}

impl ConfiguredRole {
    /// Parses the configured role string. Only the two supported roles are
    /// promotion-aware; anything else is treated as a slave (never writable
    /// from promotion).
    #[must_use]
    pub fn from_config(role: &str) -> Self {
        if role == "master" {
            Self::Master
        } else {
            Self::Slave
        }
    }
}

/// Effective in-memory role. Promotion never rewrites `config.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveRole {
    /// Running the slave replication worker.
    Slave,
    /// Running the master listener.
    Master,
}

/// Eligibility facts supplied by the runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Eligibility {
    /// The slave is degraded (apply/mTLS/transport failure).
    pub degraded: bool,
    /// A sticky divergence/fork latch is active.
    pub diverged_or_forked: bool,
    /// A pushed configuration requires a restart that has not happened.
    pub restart_required: bool,
    /// A foreign/stale `ha_state.toml` exists that is not this node's own
    /// in-progress promotion.
    pub foreign_or_stale_state: bool,
    /// The master signing key or mTLS certificate expected by slaves is not
    /// provisioned/matching on this node.
    pub identity_mismatch: bool,
}

/// A signed pending bundle prepared by the host.
#[derive(Debug, Clone)]
pub struct PreparedBundle {
    /// The bundle at `(term, version)`.
    pub bundle: ConfigBundle,
    /// BLAKE3 hash of the signed payload (normalized).
    pub hash: String,
}

/// A monotonic self-fence deadline handle for the first publish.
///
/// The first publish performs a durable state write before it enqueues the
/// bundle. A slow fsync must not let the push happen after the local deadline
/// (or the witness expiry). The host consults [`Self::is_safe`] immediately
/// before installing/enqueueing the bundle; the engine fences when the host
/// reports that the deadline was missed.
#[derive(Clone)]
pub struct PublishDeadline {
    clock: Arc<dyn MonotonicClock>,
    deadline_millis: u64,
}

impl PublishDeadline {
    /// Builds a deadline handle for `deadline_millis` (monotonic milliseconds).
    #[must_use]
    pub fn new(clock: Arc<dyn MonotonicClock>, deadline_millis: u64) -> Self {
        Self {
            clock,
            deadline_millis,
        }
    }

    /// Whether the local self-fence deadline is still in the future.
    #[must_use]
    pub fn is_safe(&self) -> bool {
        self.clock
            .boot_millis()
            .is_ok_and(|now| now < self.deadline_millis)
    }

    /// The remaining safe time, if the boot clock is readable.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        let now = self.clock.boot_millis().ok()?;
        Some(Duration::from_millis(
            self.deadline_millis.saturating_sub(now),
        ))
    }
}

/// Runtime integration points for the engine.
pub trait PromotionHost: Send + Sync + 'static {
    /// Applies the slave watermark and current local document to a bundle built
    /// at `(term, version)`. Must not install or persist the bundle.
    fn prepare_bundle(&self, term: u64, version: u64) -> Result<PreparedBundle, String>;

    /// Returns the durable applied watermark, if any.
    fn applied_watermark(&self) -> Option<AppliedWatermark>;

    /// Returns the latest **durably published** bundle baseline, if any.
    ///
    /// The engine refreshes its witness renewal baseline from this hook so a
    /// normal configuration publish does not leave the witness at the first
    /// promoted version. The implementation must read durable state only
    /// (`ha_state.toml`): an in-memory value that has not completed its second
    /// durable write is an uncommitted/pending version and must never be sent
    /// to the witness (ADR-0010, "Publish baseline vs pending promotion
    /// version").
    fn current_published_baseline(&self) -> Option<PublicationBaseline> {
        None
    }

    /// Returns the public key recorded with the persisted master state, if the
    /// runtime can supply it.
    ///
    /// A promoted candidate may have no prior `ha_state.toml` and therefore no
    /// recorded key; the engine writes this value with its own state so key
    /// loss stays detectable after a promotion.
    fn signing_key_pubkey(&self) -> Option<String> {
        None
    }

    /// Computes the signed-payload hash of a bundle already on disk.
    ///
    /// Used only for legacy state files that predate the promotion bookkeeping;
    /// a host that cannot recompute it leaves the state unknown and the engine
    /// stays read-only.
    fn hash_bundle(&self, _bundle: &ConfigBundle) -> Result<String, String> {
        Err("the host cannot recompute a legacy bundle hash".to_string())
    }

    /// Returns peer reports observed after the reconcile window, draining the
    /// runtime's queue.
    ///
    /// A peer that reports a term/version above this master after the
    /// reconciliation window is a late ahead peer: it must be latched, never
    /// overwritten, and the master must stop pushing to it.
    fn take_late_peer_reports(&self) -> Vec<PeerReport> {
        Vec::new()
    }

    /// Records a late ahead/diverged peer after reconciliation: mark it
    /// diverged and stop pushing to it.
    fn latch_peer(&self, _report: &PeerReport, _reason: &str) {}

    /// Returns local eligibility facts.
    fn eligibility(&self) -> Eligibility;

    /// Whether a master frame arrived within the effective heartbeat timeout.
    fn master_alive(&self) -> bool;

    /// Enables or disables mutating API requests. `reason` is the stable
    /// readiness/status reason.
    fn set_writable(&self, writable: bool, reason: Option<String>);

    /// Switches the effective role, stopping the other role first. The host
    /// must never run both roles at once.
    fn switch_role(&self, role: EffectiveRole) -> BoxFuture<'_, Result<(), String>>;

    /// Starts the replication listener in hello-only mode (no `ConfigPush`).
    fn begin_hello_only(&self) -> BoxFuture<'_, Result<(), String>>;

    /// Ends hello-only mode and closes/wakes sessions without sending a push.
    fn end_hello_only(&self) -> BoxFuture<'_, Result<(), String>>;

    /// Waits for the reconcile window and returns the peer reports observed.
    fn collect_reconcile_reports(&self) -> BoxFuture<'_, Result<Vec<PeerReport>, String>>;

    /// Publishes the first bundle: enqueue it to connected slaves and make it
    /// the active bundle. Returns the signed-payload hash that was pushed.
    ///
    /// The host must consult `deadline` after its durable pre-publish write and
    /// immediately before installing/enqueueing the bundle. If the deadline is
    /// no longer safe, it must return an error without pushing.
    fn publish_first<'a>(
        &'a self,
        prepared: &'a PreparedBundle,
        deadline: &'a PublishDeadline,
    ) -> BoxFuture<'a, Result<String, String>>;

    /// Stops publishing immediately (fence step 2).
    fn stop_publishing(&self);

    /// Closes replication sessions with `reason` (fence step 2).
    fn close_replication_sessions(&self, reason: &str);

    /// Critical local failure (both fence writes failed): log and exit non-zero.
    fn critical_local_failure(&self, reason: &str);
}

/// Promotion phase for the internal/status surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionPhase {
    /// Feature disabled.
    Disabled,
    /// Candidate waiting for master loss.
    WaitingForMasterLoss,
    /// Manual confirmation file required/awaited.
    ManualConfirmationRequired,
    /// Acquiring the lease.
    Acquiring,
    /// Pre-publish quiesce.
    Quiescing,
    /// Hello-only reconciliation.
    Reconciling,
    /// First push in progress.
    Publishing,
    /// Writable master.
    Master,
    /// Durable fence; never re-acquires.
    Fenced,
    /// Refused/aborted; stays read-only.
    Aborted,
    /// Witness unavailable/auth/TLS; retrying.
    Unavailable,
}

impl PromotionPhase {
    /// Stable status state string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::WaitingForMasterLoss => "waiting_for_master_loss",
            Self::ManualConfirmationRequired => "manual_confirmation_required",
            Self::Acquiring => "acquiring",
            Self::Quiescing => "quiescing",
            Self::Reconciling => "reconciling",
            Self::Publishing => "publishing",
            Self::Master => "master",
            Self::Fenced => "fenced",
            Self::Aborted => "aborted",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Internal promotion snapshot used by the engine and C3b2c's public status
/// builder. This is an implementation detail; the public JSON object is C3b2c.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionSnapshot {
    /// Feature enabled.
    pub enabled: bool,
    /// Node is the designated candidate.
    pub candidate: bool,
    /// Cluster identifier.
    pub cluster_id: Option<String>,
    /// Node identifier.
    pub node_id: Option<String>,
    /// Current phase.
    pub phase: PromotionPhase,
    /// Stable reason code, if any.
    pub reason: Option<String>,
    /// Term held or attempted.
    pub term: u64,
    /// Active bundle version.
    pub version: u64,
    /// Active bundle hash.
    pub bundle_hash: String,
    /// Active publication state.
    pub publication_state: PublicationState,
    /// Last published version.
    pub published_version: u64,
    /// Last published hash.
    pub published_hash: String,
    /// Witness revision of the current grant.
    pub lease_revision: Option<u64>,
    /// Last witness probe reachable.
    pub witness_reachable: bool,
    /// Remaining quiesce time.
    pub quiesce_remaining_secs: u64,
    /// Remaining reconcile time.
    pub reconcile_remaining_secs: u64,
    /// Witness-reported expiry of the current grant, Unix milliseconds.
    pub lease_expires_unix_ms: Option<i64>,
    /// Seconds until `lease_expires_unix_ms`, computed at snapshot time from
    /// the local wall clock. Display-only; never a safety input.
    pub lease_expires_in_secs: Option<u64>,
    /// Unix milliseconds of the last acquisition/renewal attempt.
    pub last_attempt_unix_ms: Option<i64>,
    /// Whether this node currently holds a live lease grant.
    ///
    /// Computed from the in-memory grant plus the self-fence deadline, not from
    /// the last status phase: a terminal read-only/abort must report false even
    /// while the supervisor is still shutting down.
    pub lease_held: bool,
    /// Promotion start timestamp.
    pub promoted_at_unix_ms: Option<i64>,
    /// Durable fence present.
    pub fenced: bool,
}

impl PromotionSnapshot {
    fn disabled() -> Self {
        Self {
            enabled: false,
            candidate: false,
            cluster_id: None,
            node_id: None,
            phase: PromotionPhase::Disabled,
            reason: Some("promotion_disabled".to_string()),
            term: 0,
            version: 0,
            bundle_hash: "none".to_string(),
            publication_state: PublicationState::Published,
            published_version: 0,
            published_hash: "none".to_string(),
            lease_revision: None,
            witness_reachable: false,
            quiesce_remaining_secs: 0,
            reconcile_remaining_secs: 0,
            lease_expires_unix_ms: None,
            lease_expires_in_secs: None,
            last_attempt_unix_ms: None,
            lease_held: false,
            promoted_at_unix_ms: None,
            fenced: false,
        }
    }
}

#[derive(Debug, Clone)]
struct LeaseGrant {
    holder: String,
    term: u64,
    revision: u64,
    baseline: PublicationBaseline,
}

/// Outcome of one acquisition/publication attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionOutcome {
    /// Feature disabled.
    Disabled,
    /// Became a writable master.
    Master,
    /// Waiting for master loss (candidate).
    Waiting,
    /// Manual confirmation required.
    ManualConfirmationRequired,
    /// A fence marker blocks the node.
    Fenced,
    /// Read-only with a stable reason; retry later where appropriate.
    ReadOnly {
        /// Stable reason code.
        reason: String,
        /// Whether a later retry can succeed (witness/transport).
        retryable: bool,
    },
}

#[derive(Debug)]
struct EngineInner {
    snapshot: PromotionSnapshot,
    loaded: Option<PersistedMasterState>,
    bookkeeping: Option<PromotionBookkeeping>,
    grant: Option<LeaseGrant>,
    deadline: Option<SelfFenceDeadline>,
    boot_id: Option<String>,
    last_wall_unix_ms: Option<i64>,
    last_witness_now_unix_ms: Option<i64>,
    pending: Option<PreparedBundle>,
    /// Hash of the bundle staged by the crashed promotion at the version being
    /// reused. Reconciliation may use it as proof that the old publish
    /// succeeded; it is never sent to the witness as a new baseline.
    reconcile_proof_hash: Option<String>,
    latched: LatePeerLatch,
    last_acquire_conflict: bool,
    booted: bool,
}

/// The promotion engine.
pub struct PromotionEngine {
    config: PromotionConfig,
    role: ConfiguredRole,
    cluster_id: String,
    node_id: String,
    holder: String,
    backend: Arc<dyn LeaseBackend>,
    host: Arc<dyn PromotionHost>,
    state: HaStateStore,
    fence: FenceStore,
    confirm: ConfirmationStore,
    clock: Arc<dyn MonotonicClock>,
    timers: Arc<dyn PromotionTimers>,
    /// Optional ADR-0010 metrics sink owned by the runtime.
    metrics: Option<MetricsRegistry>,
    inner: Mutex<EngineInner>,
    data_dir: std::path::PathBuf,
    /// Effective candidate heartbeat timeout from `ha.ping_interval_secs`.
    heartbeat_timeout_secs: u64,
    /// Test-only hook to fail the durable `published` state write after a
    /// successful first push (the ADR's crash-window test).
    #[cfg(test)]
    fail_published_state_write: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_pending_state_write: std::sync::atomic::AtomicBool,
    /// Test-only hook invoked after the quiesce window completes and before
    /// reconciliation starts. Lets a test fail the boot clock exactly at the
    /// reconcile-window read.
    #[cfg(test)]
    quiesce_complete_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl PromotionEngine {
    /// Builds the engine for a validated promotion configuration.
    ///
    /// `data_dir` supplies `ha_state.toml`, the fence markers and the one-shot
    /// confirmation file.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: PromotionConfig,
        role: ConfiguredRole,
        data_dir: impl Into<std::path::PathBuf>,
        backend: Arc<dyn LeaseBackend>,
        host: Arc<dyn PromotionHost>,
    ) -> Result<Self, HaError> {
        Self::with_runtime(
            config,
            role,
            data_dir,
            backend,
            host,
            Arc::new(SystemMonotonicClock),
            Arc::new(SystemTimers),
        )
    }

    /// Builds the engine with injected clocks/timers (deterministic tests).
    #[allow(clippy::too_many_arguments)]
    pub fn with_runtime(
        config: PromotionConfig,
        role: ConfiguredRole,
        data_dir: impl Into<std::path::PathBuf>,
        backend: Arc<dyn LeaseBackend>,
        host: Arc<dyn PromotionHost>,
        clock: Arc<dyn MonotonicClock>,
        timers: Arc<dyn PromotionTimers>,
    ) -> Result<Self, HaError> {
        let data_dir = data_dir.into();
        let heartbeat_timeout_secs = config.effective_heartbeat_timeout_secs(15);
        if !config.enabled {
            return Ok(Self {
                config,
                role,
                cluster_id: String::new(),
                node_id: String::new(),
                holder: String::new(),
                backend,
                host,
                state: HaStateStore::new(data_dir.join("ha_state.toml")),
                fence: FenceStore::new(data_dir.clone(), "", ""),
                confirm: ConfirmationStore::with_path(data_dir.join("ha_promote.confirm"), "", ""),
                clock,
                timers,
                metrics: None,
                inner: Mutex::new(EngineInner {
                    snapshot: PromotionSnapshot::disabled(),
                    loaded: None,
                    bookkeeping: None,
                    grant: None,
                    deadline: None,
                    boot_id: None,
                    last_wall_unix_ms: None,
                    last_witness_now_unix_ms: None,
                    pending: None,
                    reconcile_proof_hash: None,
                    latched: LatePeerLatch::default(),
                    last_acquire_conflict: false,
                    booted: false,
                }),
                data_dir,
                heartbeat_timeout_secs,
                #[cfg(test)]
                fail_published_state_write: std::sync::atomic::AtomicBool::new(false),
                #[cfg(test)]
                fail_pending_state_write: std::sync::atomic::AtomicBool::new(false),
                #[cfg(test)]
                quiesce_complete_hook: Mutex::new(None),
            });
        }
        let cluster_id = config
            .cluster_id
            .clone()
            .ok_or_else(|| HaError::Validation {
                field: "ha.promotion.cluster_id".to_string(),
                reason: "cluster_id is required when promotion is enabled".to_string(),
            })?;
        let node_id = config.node_id.clone().ok_or_else(|| HaError::Validation {
            field: "ha.promotion.node_id".to_string(),
            reason: "node_id is required when promotion is enabled".to_string(),
        })?;
        let boot_id = format!(
            "{:016x}{:016x}",
            rand::random::<u64>(),
            rand::random::<u64>()
        );
        let holder = format!("{node_id}/{boot_id}");
        let state = HaStateStore::new(data_dir.join("ha_state.toml"))
            .with_identity(cluster_id.clone(), node_id.clone());
        let fence = FenceStore::new(data_dir.clone(), cluster_id.clone(), node_id.clone());
        let confirm = ConfirmationStore::new(data_dir.clone(), cluster_id.clone(), node_id.clone());
        let (initial_phase, initial_reason) = match (role, config.candidate) {
            (ConfiguredRole::Master, _) => (PromotionPhase::Acquiring, None),
            (ConfiguredRole::Slave, true) => {
                (PromotionPhase::WaitingForMasterLoss, Some("not_candidate"))
            }
            (ConfiguredRole::Slave, false) => (PromotionPhase::Aborted, Some("not_candidate")),
        };
        let snapshot = PromotionSnapshot {
            enabled: true,
            candidate: config.candidate,
            cluster_id: Some(cluster_id.clone()),
            node_id: Some(node_id.clone()),
            phase: initial_phase,
            reason: initial_reason.map(str::to_string),
            term: 0,
            version: 0,
            bundle_hash: "none".to_string(),
            publication_state: PublicationState::Published,
            published_version: 0,
            published_hash: "none".to_string(),
            lease_revision: None,
            witness_reachable: false,
            quiesce_remaining_secs: 0,
            reconcile_remaining_secs: 0,
            lease_expires_unix_ms: None,
            lease_expires_in_secs: None,
            last_attempt_unix_ms: None,
            lease_held: false,
            promoted_at_unix_ms: None,
            fenced: false,
        };
        Ok(Self {
            config,
            role,
            cluster_id,
            node_id,
            holder,
            backend,
            host,
            state,
            fence,
            confirm,
            clock,
            timers,
            metrics: None,
            inner: Mutex::new(EngineInner {
                snapshot,
                loaded: None,
                bookkeeping: None,
                grant: None,
                deadline: None,
                boot_id: None,
                last_wall_unix_ms: None,
                last_witness_now_unix_ms: None,
                pending: None,
                reconcile_proof_hash: None,
                latched: LatePeerLatch::default(),
                last_acquire_conflict: false,
                booted: false,
            }),
            data_dir,
            heartbeat_timeout_secs,
            #[cfg(test)]
            fail_published_state_write: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_pending_state_write: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            quiesce_complete_hook: Mutex::new(None),
        })
    }

    /// Overrides the effective heartbeat timeout (the runtime passes
    /// `max(45, 3 * ha.ping_interval_secs)` when the config omits it).
    #[must_use]
    pub fn with_heartbeat_timeout_secs(mut self, secs: u64) -> Self {
        self.heartbeat_timeout_secs = secs.max(1);
        self
    }

    /// Attaches the runtime metrics registry for the ADR-0010 families.
    #[must_use]
    pub fn with_metrics(mut self, metrics: MetricsRegistry) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Test-only: make the next durable `published` state write fail.
    #[cfg(test)]
    pub fn fail_published_state_write(&self) {
        self.fail_published_state_write
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test-only: make the next pending-state write fail.
    #[cfg(test)]
    pub fn fail_pending_state_write(&self) {
        self.fail_pending_state_write
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test-only: run `hook` after quiesce and before the reconcile-window
    /// clock read.
    #[cfg(test)]
    pub fn set_quiesce_complete_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self
            .quiesce_complete_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
    }

    #[cfg(test)]
    fn run_quiesce_complete_hook(&self) {
        let hook = self
            .quiesce_complete_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Current internal snapshot.
    #[must_use]
    pub fn snapshot(&self) -> PromotionSnapshot {
        let (mut snapshot, grant_present, deadline_safe) = {
            let inner = self.lock();
            let deadline_safe = inner.deadline.as_ref().is_some_and(|deadline| {
                matches!(deadline.check(self.clock.as_ref()), SelfFenceCheck::Safe)
            });
            (inner.snapshot.clone(), inner.grant.is_some(), deadline_safe)
        };
        snapshot.lease_expires_in_secs = snapshot.lease_expires_unix_ms.map(|expires| {
            let now = self.clock.wall_unix_ms();
            let remaining_ms = expires.saturating_sub(now);
            u64::try_from(remaining_ms / 1_000).unwrap_or(0)
        });
        snapshot.lease_held = !snapshot.fenced && grant_present && deadline_safe;
        snapshot
    }

    /// Test-only: the armed self-fence deadline in monotonic milliseconds.
    #[cfg(test)]
    #[must_use]
    pub fn self_fence_deadline_millis(&self) -> Option<u64> {
        self.lock()
            .deadline
            .as_ref()
            .map(SelfFenceDeadline::deadline_millis)
    }

    /// The current self-fence deadline as a monotonic handle for the first
    /// publish. `None` before a lease is held or after a fence.
    #[must_use]
    pub fn publish_deadline(&self) -> Option<PublishDeadline> {
        let deadline_millis = self
            .lock()
            .deadline
            .as_ref()
            .map(SelfFenceDeadline::deadline_millis)?;
        Some(PublishDeadline::new(
            Arc::clone(&self.clock),
            deadline_millis,
        ))
    }

    /// Updates the status-only waiting phase for a candidate whose master is
    /// still alive. This does not acquire, discard a confirmation or touch the
    /// write gate.
    pub fn note_waiting_for_master(&self, reason: &str) {
        self.set_phase(PromotionPhase::WaitingForMasterLoss, Some(reason));
    }

    /// The per-process witness holder identity (`node_id/boot_uuid`).
    #[must_use]
    pub fn holder(&self) -> &str {
        &self.holder
    }

    /// The data directory.
    #[must_use]
    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    /// The fence store, exposed for the C3b2c `clear-fence` CLI.
    #[must_use]
    pub fn fence_store(&self) -> &FenceStore {
        &self.fence
    }

    /// The confirmation store, exposed for the C3b2c `confirm-promotion` CLI.
    #[must_use]
    pub fn confirmation_store(&self) -> &ConfirmationStore {
        &self.confirm
    }

    /// Boots the engine: fence/state inspection, read-only gating, and
    /// role-appropriate initial phase. Never touches the witness.
    pub fn boot(&self) -> Result<PromotionOutcome, HaError> {
        if !self.config.enabled {
            return Ok(PromotionOutcome::Disabled);
        }
        // Fail closed before any load/refusal path: an enabled node is
        // read-only until it has a live lease and a successful first publish.
        self.host
            .set_writable(false, Some("ha_promotion_starting".to_string()));
        // A restart discards any unconsumed manual confirmation: it is
        // one-shot and must not authorize a second process incarnation.
        self.confirm.discard();
        self.fence.check_integrity()?;

        if let Some(marker) = self.fence.load()? {
            let mut inner = self.lock();
            inner.snapshot.fenced = true;
            inner.snapshot.phase = PromotionPhase::Fenced;
            inner.snapshot.reason = Some("fenced_until_reconciled".to_string());
            inner.snapshot.term = marker.fenced_term;
            drop(inner);
            self.host
                .set_writable(false, Some("ha_promotion_fenced".to_string()));
            // A fenced configured master must stop accepting new slaves too.
            self.host.stop_publishing();
            self.host.close_replication_sessions("fenced");
            self.lock().booted = true;
            return Ok(PromotionOutcome::Fenced);
        }

        let loaded = self.state.load()?;
        // Copy the active bundle hash as well as its term/version. A restarted
        // master with the witness down must not report `version = N` with
        // `bundle_hash = "none"`; "none" is valid only at version 0.
        let active_hash = match &loaded {
            LoadedState::Missing => None,
            LoadedState::Present { state, bookkeeping } => match bookkeeping {
                Some(bookkeeping) => Some(if bookkeeping.has_pending_bundle() {
                    bookkeeping
                        .pending_hash
                        .clone()
                        .unwrap_or_else(|| bookkeeping.published_hash.clone())
                } else {
                    bookkeeping.published_hash.clone()
                }),
                // Legacy state without promotion bookkeeping: compute the
                // signed-payload hash instead of assuming the bundle is absent.
                None => self.host.hash_bundle(&state.bundle).ok(),
            },
        };
        let (phase, reason) = {
            let mut inner = self.lock();
            match &loaded {
                LoadedState::Missing => {
                    inner.loaded = None;
                    inner.bookkeeping = None;
                }
                LoadedState::Present { state, bookkeeping } => {
                    inner.loaded = Some((**state).clone());
                    inner.bookkeeping.clone_from(bookkeeping);
                    inner.snapshot.term = state.bundle.term;
                    inner.snapshot.version = state.bundle.version;
                    if let Some(hash) = active_hash.clone() {
                        inner.snapshot.bundle_hash = hash;
                    }
                    inner.snapshot.publication_state = bookkeeping
                        .as_ref()
                        .map_or(PublicationState::Published, |b| b.publication_state);
                    if let Some(bookkeeping) = bookkeeping {
                        inner.snapshot.published_version = bookkeeping.published_version;
                        inner
                            .snapshot
                            .published_hash
                            .clone_from(&bookkeeping.published_hash);
                        inner.snapshot.promoted_at_unix_ms = bookkeeping.promoted_at_unix_ms;
                    }
                }
            }
            match (self.role, self.config.candidate) {
                (ConfiguredRole::Master, _) => {
                    // Do not claim the witness is unavailable before the first
                    // probe; the supervisor immediately enters acquisition.
                    inner.snapshot.phase = PromotionPhase::Acquiring;
                    inner.snapshot.reason = None;
                    (PromotionPhase::Acquiring, None)
                }
                (ConfiguredRole::Slave, true) => {
                    inner.snapshot.phase = PromotionPhase::WaitingForMasterLoss;
                    inner.snapshot.reason = Some("not_candidate".to_string());
                    (
                        PromotionPhase::WaitingForMasterLoss,
                        Some("not_candidate".to_string()),
                    )
                }
                (ConfiguredRole::Slave, false) => {
                    inner.snapshot.phase = PromotionPhase::Aborted;
                    inner.snapshot.reason = Some("not_candidate".to_string());
                    (PromotionPhase::Aborted, Some("not_candidate".to_string()))
                }
            }
        };
        if self.role == ConfiguredRole::Master {
            self.host
                .set_writable(false, Some("ha_promotion_witness_unavailable".to_string()));
        }
        self.lock().booted = true;
        Ok(match phase {
            PromotionPhase::WaitingForMasterLoss => PromotionOutcome::Waiting,
            _ if self.role == ConfiguredRole::Master => PromotionOutcome::ReadOnly {
                reason: "witness_unavailable".to_string(),
                retryable: true,
            },
            _ => PromotionOutcome::ReadOnly {
                reason: reason.unwrap_or_else(|| "not_candidate".to_string()),
                retryable: false,
            },
        })
    }

    /// Runs a full master startup: acquire, quiesce, reconcile, publish.
    pub async fn start_master(&self) -> PromotionOutcome {
        if !self.config.enabled {
            return PromotionOutcome::Disabled;
        }
        if self.role != ConfiguredRole::Master {
            return PromotionOutcome::ReadOnly {
                reason: "not_candidate".to_string(),
                retryable: false,
            };
        }
        let booted = self.lock().booted;
        if !booted {
            match self.boot() {
                Ok(PromotionOutcome::Fenced) => return PromotionOutcome::Fenced,
                Ok(_) => {}
                Err(error) => {
                    self.set_phase(PromotionPhase::Aborted, Some("promotion_interrupted"));
                    return PromotionOutcome::ReadOnly {
                        reason: format!("promotion_interrupted: {error}"),
                        retryable: false,
                    };
                }
            }
        }
        if self.is_fenced() {
            return PromotionOutcome::Fenced;
        }
        match self.acquire(AcquisitionRole::Master, "restart").await {
            AcquireOutcome::Acquired => {}
            AcquireOutcome::Outcome(outcome) => return outcome,
        }
        self.finish_promotion().await
    }

    /// Runs one candidate attempt after the caller observed master loss.
    ///
    /// `master_alive` is the caller's liveness view. It is a gate for waiting,
    /// never the safety decision; the witness lease remains authoritative.
    pub async fn candidate_attempt(&self, master_alive: bool) -> PromotionOutcome {
        if !self.config.enabled {
            return PromotionOutcome::Disabled;
        }
        if self.role != ConfiguredRole::Slave || !self.config.candidate {
            self.set_phase(PromotionPhase::Aborted, Some("not_candidate"));
            self.record_refusal("not_candidate");
            self.audit(REFUSED, "refused", Some("not_candidate"), 0, 0, None);
            return PromotionOutcome::ReadOnly {
                reason: "not_candidate".to_string(),
                retryable: false,
            };
        }
        let booted = self.lock().booted;
        if !booted {
            match self.boot() {
                Ok(PromotionOutcome::Fenced) => return PromotionOutcome::Fenced,
                Ok(_) => {}
                Err(error) => {
                    self.set_phase(PromotionPhase::Aborted, Some("promotion_interrupted"));
                    return PromotionOutcome::ReadOnly {
                        reason: format!("promotion_interrupted: {error}"),
                        retryable: false,
                    };
                }
            }
        }
        if self.is_fenced() {
            self.set_phase(PromotionPhase::Fenced, Some("fenced_until_reconciled"));
            return PromotionOutcome::Fenced;
        }
        if master_alive || self.host.master_alive() {
            // The master returned before the confirmation was consumed.
            self.confirm.discard();
            self.set_phase(PromotionPhase::WaitingForMasterLoss, Some("master_alive"));
            return PromotionOutcome::Waiting;
        }

        let eligibility = self.host.eligibility();
        if eligibility.identity_mismatch {
            self.set_phase(PromotionPhase::Aborted, Some("candidate_identity_mismatch"));
            self.record_refusal("candidate_identity_mismatch");
            self.audit(
                REFUSED,
                "refused",
                Some("candidate_identity_mismatch"),
                0,
                0,
                None,
            );
            return PromotionOutcome::ReadOnly {
                reason: "candidate_identity_mismatch".to_string(),
                retryable: false,
            };
        }
        if eligibility.degraded
            || eligibility.diverged_or_forked
            || eligibility.restart_required
            || eligibility.foreign_or_stale_state
        {
            let reason = "candidate_diverged";
            self.set_phase(PromotionPhase::Aborted, Some(reason));
            self.record_refusal(reason);
            self.audit(REFUSED, "refused", Some(reason), 0, 0, None);
            return PromotionOutcome::ReadOnly {
                reason: reason.to_string(),
                retryable: false,
            };
        }

        if self.config.require_manual_confirmation {
            // Do not consume a one-shot confirmation while another live holder
            // owns the lease. The file remains for a later attempt only if the
            // witness confirms master loss; a stale file is age-limited.
            let now = match self.backend.info().await {
                Ok(info) => {
                    self.record_witness_request("info", "success");
                    self.lock().last_witness_now_unix_ms = Some(info.now_unix_ms);
                    Some(info.now_unix_ms)
                }
                Err(error) => {
                    self.record_witness_request("info", "error");
                    let reason = error.reason_code();
                    self.set_phase(PromotionPhase::Unavailable, Some(reason));
                    self.record_refusal(reason);
                    self.audit(REFUSED, "witness_error", Some(reason), 0, 0, None);
                    return PromotionOutcome::ReadOnly {
                        reason: reason.to_string(),
                        retryable: error.is_retryable(),
                    };
                }
            };
            match self.backend.lease().await {
                Ok(Some(record))
                    if record.holder != self.holder
                        && now.is_some_and(|now| !record.is_expired(now)) =>
                {
                    self.record_witness_request("lease", "success");
                    self.set_phase(
                        PromotionPhase::WaitingForMasterLoss,
                        Some("lease_held_by_other"),
                    );
                    return PromotionOutcome::ReadOnly {
                        reason: "lease_held_by_other".to_string(),
                        retryable: true,
                    };
                }
                Ok(_) => {
                    self.record_witness_request("lease", "success");
                }
                Err(error) => {
                    self.record_witness_request("lease", "error");
                    let reason = error.reason_code();
                    self.set_phase(PromotionPhase::Unavailable, Some(reason));
                    return PromotionOutcome::ReadOnly {
                        reason: reason.to_string(),
                        retryable: error.is_retryable(),
                    };
                }
            }
            let max_age_ms = i64::try_from(self.heartbeat_timeout_secs.saturating_mul(1_000))
                .unwrap_or(i64::MAX);
            let now = self.clock.wall_unix_ms();
            match self.confirm.consume(now, max_age_ms) {
                Ok(_) => {
                    info!(
                        node_id = %self.node_id,
                        "manual promotion confirmation consumed"
                    );
                    self.audit(
                        MANUAL_CONFIRMATION_CONFIRMED,
                        "confirmed",
                        None,
                        self.lock().snapshot.term,
                        0,
                        Some(&self.holder),
                    );
                }
                Err(error) => {
                    self.set_phase(
                        PromotionPhase::ManualConfirmationRequired,
                        Some("manual_confirmation_required"),
                    );
                    self.audit(
                        MANUAL_CONFIRMATION_REQUIRED,
                        "waiting",
                        Some("manual_confirmation_required"),
                        self.lock().snapshot.term,
                        0,
                        Some(&self.holder),
                    );
                    let _ = error;
                    return PromotionOutcome::ManualConfirmationRequired;
                }
            }
        }

        match self.acquire(AcquisitionRole::Candidate, "automatic").await {
            AcquireOutcome::Acquired => self.finish_promotion().await,
            AcquireOutcome::Outcome(outcome) => outcome,
        }
    }

    /// Renews the current lease once.
    ///
    /// Safety rules enforced here:
    ///
    /// * the request always carries the **published** baseline, never the
    ///   staged/pending bundle version;
    /// * every witness call is bounded by the remaining self-fence deadline, so
    ///   a slow/hung witness cannot leave the write gate open past the lease
    ///   expiry;
    /// * a conflict that only advances a revision is retried; the deadline is
    ///   re-armed only by an actual successful renewal ACK;
    /// * a successful ACK observed after the deadline is not accepted.
    pub async fn renew_once(&self) -> Result<u64, HaError> {
        {
            let mut inner = self.lock();
            inner.snapshot.last_attempt_unix_ms = Some(self.clock.wall_unix_ms());
        }
        let grant = {
            let inner = self.lock();
            inner.grant.clone()
        };
        let Some(mut grant) = grant else {
            return Err(HaError::Validation {
                field: "ha.promotion".to_string(),
                reason: "cannot renew without a lease grant".to_string(),
            });
        };
        // Read only the durable published baseline from the host. During a
        // promotion the in-memory active bundle is staged at a higher version,
        // and a normal publish advances the coordinator's in-memory bookkeeping
        // before its second durable write; neither may become the witness
        // baseline.
        if let Some(latest) = self.host.current_published_baseline() {
            if latest.version > grant.baseline.version {
                if self.is_staged_baseline(latest.version) {
                    self.fence(
                        FenceReason::LeaseVersionRegression,
                        "the host returned a staged/pending version as the published renewal baseline",
                    )?;
                    return Err(HaError::Connection(
                        "host published baseline is a pending promotion version".to_string(),
                    ));
                }
                grant.baseline = latest;
                let mut inner = self.lock();
                if let Some(ref mut current) = inner.grant {
                    current.baseline = grant.baseline.clone();
                }
                inner.snapshot.published_version = grant.baseline.version;
                inner
                    .snapshot
                    .published_hash
                    .clone_from(&grant.baseline.hash);
            } else if latest.version == grant.baseline.version
                && !hashes_equal(&latest.hash, &grant.baseline.hash)
            {
                self.fence(
                    FenceReason::LeaseVersionRegression,
                    "local published baseline diverged from the renewal baseline",
                )?;
                return Err(HaError::Connection(
                    "local published baseline fork".to_string(),
                ));
            }
        }
        let mut witness_now = self.refresh_witness_now().await?;
        let mut higher_baseline_retries = 0u32;
        let mut adopted_revision_retries = 0u32;
        loop {
            let request = RenewRequest {
                holder: grant.holder.clone(),
                term: grant.term,
                expected_revision: grant.revision,
                version: grant.baseline.version,
                bundle_hash: grant.baseline.hash.clone(),
                ttl_secs: self.config.lease_ttl_secs,
            };
            // Arm from the request start: the witness expiry is at or after
            // `start + TTL`, so a local deadline derived from the start cannot
            // outlive the witness record even when the response is slow.
            let boot_before = self.current_boot_millis("lease renewal start")?;
            let result = match self
                .bounded_witness_call("lease renewal", self.backend.renew(request))
                .await
            {
                Ok(result) => result,
                Err(error) => {
                    self.record_witness_request("renew", "error");
                    if let Some(metrics) = self.metrics.as_ref() {
                        metrics.inc_ha_promotion_lease_renew_failure();
                    }
                    return Err(error);
                }
            };
            match result {
                Ok(record) => {
                    self.record_witness_request("renew", "success");
                    // Never accept an ACK that only arrives after the local
                    // deadline: a slow witness call must not extend the gate.
                    if self.check_self_fence()? {
                        return Err(HaError::Connection(
                            "the renewal ACK arrived after the self-fence deadline".to_string(),
                        ));
                    }
                    self.record_successful_renewal(record.revision, boot_before)?;
                    self.lock().snapshot.lease_expires_unix_ms = Some(record.expires_unix_ms);
                    self.record_last_success();
                    let (term, version) = {
                        let inner = self.lock();
                        (inner.snapshot.term, inner.snapshot.published_version)
                    };
                    self.audit(
                        LEASE_RENEWED,
                        "renewed",
                        None,
                        term,
                        version,
                        Some(&record.holder),
                    );
                    return Ok(record.revision);
                }
                Err(error) => {
                    self.record_witness_request("renew", "error");
                    if let Some(metrics) = self.metrics.as_ref() {
                        metrics.inc_ha_promotion_lease_renew_failure();
                    }
                    // Re-read the witness clock at classification time; a
                    // timestamp captured before the request can be stale by
                    // more than the TTL on a slow/retried renewal.
                    let fresh_now = self.refresh_witness_now().await?;
                    if fresh_now.is_none() && error.current_record().is_some() {
                        // A conflict that cannot be classified without the
                        // witness clock is uncertain lease state: fail closed
                        // rather than retrying with a record we cannot judge.
                        let detail = "cannot classify a renewal conflict without the witness clock";
                        self.fence(FenceReason::LeaseLost, detail)?;
                        return Err(HaError::Connection(detail.to_string()));
                    }
                    witness_now = fresh_now.or(witness_now);
                    let action = classify_renewal_error(
                        &error,
                        &grant.holder,
                        grant.term,
                        &grant.baseline,
                        witness_now,
                    );
                    match action {
                        RenewalAction::RetryHigherBaseline { revision } => {
                            higher_baseline_retries += 1;
                            if higher_baseline_retries > 2 {
                                self.fence(
                                    FenceReason::LeaseVersionRegression,
                                    "witness repeatedly refused the higher published baseline",
                                )?;
                                return Err(HaError::Connection(
                                    "witness baseline retry exhausted".to_string(),
                                ));
                            }
                            // Adopt the revision only; the deadline is re-armed
                            // by the successful renewal that must follow.
                            self.adopt_grant_revision(&mut grant, revision);
                        }
                        RenewalAction::AdoptRevision { revision } => {
                            adopted_revision_retries += 1;
                            if adopted_revision_retries > 2 {
                                self.fence(
                                    FenceReason::LeaseLost,
                                    "witness kept reporting a revision that could not be renewed",
                                )?;
                                return Err(HaError::Connection(
                                    "witness revision adoption retry exhausted".to_string(),
                                ));
                            }
                            // A lost ACK proves the witness still holds this
                            // grant, but it did not extend it now. Retry the
                            // renewal; do not re-arm the deadline on a 409.
                            self.adopt_grant_revision(&mut grant, revision);
                        }
                        other => return self.handle_renewal_action(other),
                    }
                }
            }
        }
    }

    /// Replaces the in-memory grant revision after a lost-ACK conflict.
    fn adopt_grant_revision(&self, grant: &mut LeaseGrant, revision: u64) {
        grant.revision = revision;
        if let Some(ref mut current) = self.lock().grant {
            current.revision = revision;
        }
        self.lock().snapshot.lease_revision = Some(revision);
    }

    /// Whether `version` is the staged (not yet published) bundle version of an
    /// in-progress promotion.
    fn is_staged_baseline(&self, version: u64) -> bool {
        let inner = self.lock();
        let staged = inner
            .bookkeeping
            .as_ref()
            .is_some_and(PromotionBookkeeping::has_pending_bundle);
        staged
            && inner
                .pending
                .as_ref()
                .is_some_and(|pending| version >= pending.bundle.version)
    }

    /// Fetches `GET /v1/info`, bounded by the self-fence deadline, and records
    /// the witness clock. A transport failure is returned as `None`; a missing
    /// deadline/timeout fences and returns an error.
    async fn refresh_witness_now(&self) -> Result<Option<i64>, HaError> {
        if let Ok(info) = self
            .bounded_witness_call("witness info", self.backend.info())
            .await?
        {
            self.record_witness_request("info", "success");
            self.lock().last_witness_now_unix_ms = Some(info.now_unix_ms);
            Ok(Some(info.now_unix_ms))
        } else {
            self.record_witness_request("info", "error");
            Ok(None)
        }
    }

    fn current_boot_millis(&self, label: &str) -> Result<u64, HaError> {
        self.clock.boot_millis().map_err(|detail| {
            let message = format!("{label}: boot clock unavailable: {detail}");
            let _ = self.fence(FenceReason::ClockAnomaly, &message);
            HaError::Connection(message)
        })
    }

    /// Checks the self-fence deadline and returns the remaining call budget.
    ///
    /// The budget is capped by the witness request timeout so one call cannot
    /// consume the whole lease window, and by the remaining deadline so the
    /// caller returns (and fences) before the witness record can expire.
    fn renewal_budget(&self, label: &str) -> Result<Duration, HaError> {
        let deadline = {
            let inner = self.lock();
            inner.deadline.clone()
        };
        let Some(deadline) = deadline else {
            let message = format!("{label}: no self-fence deadline is armed");
            let _ = self.fence(FenceReason::LeaseLost, &message);
            return Err(HaError::Connection(message));
        };
        if self.deadline_fenced(&deadline, label)? {
            return Err(HaError::Connection(format!(
                "{label}: the self-fence deadline passed before the witness call"
            )));
        }
        let now = self.current_boot_millis(label)?;
        let remaining = deadline.remaining(now);
        if remaining.is_zero() {
            let message =
                format!("{label}: the self-fence deadline passed before the witness call");
            let _ = self.fence(FenceReason::LeaseLost, &message);
            return Err(HaError::Connection(message));
        }
        Ok(remaining.min(WITNESS_REQUEST_TIMEOUT))
    }

    /// Applies the full deadline/clock integrity check and fences when it is
    /// unsafe. Returns `true` when the caller must stop.
    fn deadline_fenced(&self, deadline: &SelfFenceDeadline, label: &str) -> Result<bool, HaError> {
        match deadline.check(self.clock.as_ref()) {
            SelfFenceCheck::Safe => Ok(false),
            SelfFenceCheck::DeadlinePassed => {
                self.fence(
                    FenceReason::LeaseLost,
                    &format!("{label}: self-fence deadline passed"),
                )?;
                Ok(true)
            }
            SelfFenceCheck::ClockUnavailable(detail) => {
                self.fence(
                    FenceReason::ClockAnomaly,
                    &format!("{label}: boot clock unavailable: {detail}"),
                )?;
                Ok(true)
            }
            SelfFenceCheck::BootIdChanged => {
                self.fence(
                    FenceReason::ClockAnomaly,
                    &format!("{label}: boot identity changed"),
                )?;
                Ok(true)
            }
            SelfFenceCheck::WallStep => {
                self.fence(
                    FenceReason::ClockAnomaly,
                    &format!("{label}: wall clock stepped beyond the lease TTL"),
                )?;
                Ok(true)
            }
        }
    }

    /// Runs one witness call with the remaining self-fence budget.
    ///
    /// On timeout the node fences immediately: the API gate must never stay
    /// open while a renewal that could outlive the lease is in flight.
    async fn bounded_witness_call<T, F>(&self, label: &str, future: F) -> Result<T, HaError>
    where
        F: Future<Output = T>,
    {
        let budget = self.renewal_budget(label)?;
        if let Ok(output) = tokio::time::timeout(budget, future).await {
            Ok(output)
        } else {
            let message = format!("{label} did not complete before the self-fence deadline");
            let _ = self.fence(FenceReason::LeaseLost, &message);
            Err(HaError::Connection(message))
        }
    }

    /// Checks the self-fence deadline and fences when required.
    pub fn check_self_fence(&self) -> Result<bool, HaError> {
        let deadline = {
            let inner = self.lock();
            inner.deadline.clone()
        };
        let Some(deadline) = deadline else {
            return Ok(false);
        };
        match deadline.check(self.clock.as_ref()) {
            SelfFenceCheck::Safe => Ok(false),
            SelfFenceCheck::DeadlinePassed => {
                self.fence(FenceReason::LeaseLost, "self-fence deadline passed")?;
                Ok(true)
            }
            SelfFenceCheck::ClockUnavailable(detail) => {
                self.fence(
                    FenceReason::ClockAnomaly,
                    &format!("boot clock unavailable: {detail}"),
                )?;
                Ok(true)
            }
            SelfFenceCheck::BootIdChanged => {
                self.fence(FenceReason::ClockAnomaly, "boot identity changed")?;
                Ok(true)
            }
            SelfFenceCheck::WallStep => {
                self.fence(
                    FenceReason::ClockAnomaly,
                    "wall clock stepped beyond the lease TTL",
                )?;
                Ok(true)
            }
        }
    }

    /// Records a late ahead peer after reconciliation. The peer is latched and
    /// never overwritten; a healthy master keeps publishing to others.
    pub fn note_late_peer(&self, report: &PeerReport) -> bool {
        let (term, version) = {
            let inner = self.lock();
            (inner.snapshot.term, inner.snapshot.version)
        };
        let mut inner = self.lock();
        let newly_latched = inner.latched.record_late_report(report, term, version);
        drop(inner);
        if newly_latched {
            let reason = format!(
                "peer '{}' reported term {} version {} after the reconcile window; latched as diverged",
                report.instance, report.have_term, report.have_version
            );
            self.host.latch_peer(report, &reason);
            warn!(instance = %report.instance, reason, "latched a late ahead peer");
        }
        newly_latched
    }

    /// Drains late peer reports from the runtime and latches any ahead peer.
    ///
    /// Returns the number of newly latched instances. Called by the runtime's
    /// long-running renewal loop: a peer that connects after the reconcile
    /// window and reports a term/version above this master is never overwritten
    /// and receives no further pushes.
    pub fn process_late_peer_reports(&self) -> usize {
        let reports = self.host.take_late_peer_reports();
        reports
            .iter()
            .filter(|report| self.note_late_peer(report))
            .count()
    }

    /// Latched late-ahead peers.
    #[must_use]
    pub fn latched_peers(&self) -> Vec<String> {
        self.lock()
            .latched
            .instances()
            .map(str::to_string)
            .collect()
    }

    /// The current confirmation file path (C3b2c CLI helper).
    #[must_use]
    pub fn confirmation_path(&self) -> &std::path::Path {
        self.confirm.path()
    }

    async fn finish_promotion(&self) -> PromotionOutcome {
        if let Err(outcome) = self.quiesce().await {
            return outcome;
        }
        self.reconcile_and_publish().await
    }

    async fn quiesce(&self) -> Result<(), PromotionOutcome> {
        self.set_phase(PromotionPhase::Quiescing, None);
        let Ok(start) = self.clock.boot_millis() else {
            let _ = self.fence(FenceReason::ClockAnomaly, "boot clock unavailable");
            return Err(PromotionOutcome::Fenced);
        };
        let end = start.saturating_add(self.config.lease_ttl_secs.saturating_mul(1_000));
        loop {
            let Ok(now) = self.clock.boot_millis() else {
                let _ = self.fence(FenceReason::ClockAnomaly, "boot clock unavailable");
                return Err(PromotionOutcome::Fenced);
            };
            if now >= end {
                break;
            }
            let remaining = end - now;
            let step = remaining.min(self.config.renew_interval_secs.saturating_mul(1_000).max(1));
            {
                let mut inner = self.lock();
                inner.snapshot.quiesce_remaining_secs = remaining.div_ceil(1_000);
            }
            self.timers
                .sleep(std::time::Duration::from_millis(step))
                .await;
            self.renew_for_quiesce().await?;
            if self.check_self_fence().unwrap_or(false) {
                return Err(PromotionOutcome::Fenced);
            }
        }
        {
            self.lock().snapshot.quiesce_remaining_secs = 0;
        }
        let (term, version) = {
            let inner = self.lock();
            (inner.snapshot.term, inner.snapshot.published_version)
        };
        self.audit(
            QUIESCED,
            "quiesced",
            None,
            term,
            version,
            Some(&self.holder),
        );
        #[cfg(test)]
        self.run_quiesce_complete_hook();
        Ok(())
    }

    async fn renew_for_quiesce(&self) -> Result<(), PromotionOutcome> {
        match self.renew_once().await {
            Ok(_) => Ok(()),
            Err(_) if self.is_fenced() => Err(PromotionOutcome::Fenced),
            Err(error) => {
                // A transport failure is retried until the self-fence deadline.
                // Anything conclusive already fenced in `renew_once`.
                warn!(error = %error, "lease renewal during quiesce failed; continuing until the deadline");
                Ok(())
            }
        }
    }

    /// Single terminal read-only transition after acquisition/hello-only.
    ///
    /// It must end hello-only and deny replication admission/close sessions;
    /// merely blocking the API gate leaves the listener admitting peers.
    fn transition_read_only(
        &self,
        phase: PromotionPhase,
        reason: &str,
        retryable: bool,
    ) -> PromotionOutcome {
        self.host.set_writable(false, Some(reason.to_string()));
        self.set_phase(phase, Some(reason));
        if !retryable {
            // A terminal read-only/abort will not renew this term. Do not keep
            // advertising a grant/revision/expiry the node is no longer using.
            self.clear_lease_diagnostics();
        }
        self.record_refusal(reason);
        let (term, version) = {
            let inner = self.lock();
            (inner.snapshot.term, inner.snapshot.published_version)
        };
        self.audit(REFUSED, "read_only", Some(reason), term, version, None);
        PromotionOutcome::ReadOnly {
            reason: reason.to_string(),
            retryable,
        }
    }

    /// Clears the in-memory grant and its diagnostic lease fields.
    ///
    /// Callers use this only on a terminal path that will not renew the term.
    fn clear_lease_diagnostics(&self) {
        let mut inner = self.lock();
        inner.grant = None;
        inner.deadline = None;
        inner.snapshot.lease_revision = None;
        inner.snapshot.lease_expires_unix_ms = None;
        inner.snapshot.lease_expires_in_secs = None;
        inner.snapshot.lease_held = false;
    }

    async fn reconcile_and_publish(&self) -> PromotionOutcome {
        self.set_phase(PromotionPhase::Reconciling, None);
        let (grant, baseline, publish_version, publication_state, prepared) = {
            let inner = self.lock();
            let Some(grant) = inner.grant.clone() else {
                drop(inner);
                return self.transition_read_only(
                    PromotionPhase::Aborted,
                    "lease_record_missing",
                    true,
                );
            };
            let Some(ref bookkeeping) = inner.bookkeeping else {
                drop(inner);
                return self.transition_read_only(
                    PromotionPhase::Aborted,
                    "promotion_interrupted",
                    false,
                );
            };
            let Some(ref prepared) = inner.pending else {
                drop(inner);
                return self.transition_read_only(
                    PromotionPhase::Aborted,
                    "promotion_interrupted",
                    false,
                );
            };
            (
                grant.clone(),
                bookkeeping.baseline(),
                prepared.bundle.version,
                bookkeeping.publication_state,
                prepared.clone(),
            )
        };

        if let Err(error) = self.host.begin_hello_only().await {
            let _ = self.fence(
                FenceReason::RoleSwitchFailed,
                &format!("hello-only listener failed: {error}"),
            );
            return PromotionOutcome::Fenced;
        }
        // Renew and check the self-fence throughout the reconcile window: a
        // valid `reconcile_window_secs` may be longer than the lease TTL, and a
        // silent holder would let another candidate acquire T+1 before our
        // first publish. An unavailable boot clock must fence, never skip the
        // window and proceed to the first publish.
        let window_start = match self.clock.boot_millis() {
            Ok(now) => now,
            Err(detail) => {
                let _ = self.fence(
                    FenceReason::ClockAnomaly,
                    &format!("reconciliation: boot clock unavailable: {detail}"),
                );
                return PromotionOutcome::Fenced;
            }
        };
        let window_end =
            window_start.saturating_add(self.config.reconcile_window_secs.saturating_mul(1_000));
        loop {
            let now = match self.clock.boot_millis() {
                Ok(now) => now,
                Err(detail) => {
                    let _ = self.fence(
                        FenceReason::ClockAnomaly,
                        &format!("reconciliation: boot clock unavailable: {detail}"),
                    );
                    return PromotionOutcome::Fenced;
                }
            };
            if now >= window_end {
                break;
            }
            let remaining = window_end - now;
            self.lock().snapshot.reconcile_remaining_secs = remaining.div_ceil(1_000);
            let step = remaining.min(self.config.renew_interval_secs.saturating_mul(1_000).max(1));
            self.timers
                .sleep(std::time::Duration::from_millis(step))
                .await;
            if let Err(outcome) = self.renew_for_quiesce().await {
                return outcome;
            }
            if self.check_self_fence().unwrap_or(false) {
                return PromotionOutcome::Fenced;
            }
        }
        let peers = match self.host.collect_reconcile_reports().await {
            Ok(peers) => peers,
            Err(error) => {
                warn!(error = %error, "reconciliation report collection failed");
                self.record_publish_abort("candidate_hash_unknown");
                return self.transition_read_only(
                    PromotionPhase::Aborted,
                    "candidate_hash_unknown",
                    false,
                );
            }
        };
        self.lock().snapshot.reconcile_remaining_secs = 0;

        let witness = match self.backend.lease().await {
            Ok(Some(record)) => {
                self.record_witness_request("lease", "success");
                record
            }
            Ok(None) => {
                self.record_witness_request("lease", "success");
                let _ = self.fence(
                    FenceReason::LeaseRecordMissing,
                    "witness record disappeared",
                );
                return PromotionOutcome::Fenced;
            }
            Err(error) => {
                self.record_witness_request("lease", "error");
                return self.transition_read_only(
                    PromotionPhase::Unavailable,
                    error.reason_code(),
                    error.is_retryable(),
                );
            }
        };

        let proof_hash = self.lock().reconcile_proof_hash.clone();
        let live_now = if let Ok(info) = self.backend.info().await {
            self.record_witness_request("info", "success");
            self.lock().last_witness_now_unix_ms = Some(info.now_unix_ms);
            Some(info.now_unix_ms)
        } else {
            self.record_witness_request("info", "error");
            None
        };
        if !lease_is_live(&witness, &grant, live_now) {
            let _ = self.fence(
                FenceReason::LeaseLost,
                "the witness record is not a live grant held by this node at the first-publish boundary",
            );
            return PromotionOutcome::Fenced;
        }

        let decision = evaluate(&ReconcileInput {
            term: grant.term,
            witness,
            baseline,
            publish_version,
            publication_state,
            pending_hash: proof_hash,
            peers,
        });
        if !matches!(&decision, ReconcileDecision::Abort(_)) {
            let (term, version) = {
                let inner = self.lock();
                (inner.snapshot.term, inner.snapshot.published_version)
            };
            self.audit(
                RECONCILED,
                "reconciled",
                None,
                term,
                version,
                Some(&self.holder),
            );
        }

        match decision {
            ReconcileDecision::Abort(reason) => {
                self.host
                    .close_replication_sessions("reconciliation aborted");
                // Let the lease expire; the node never publishes or becomes
                // writable in this term.
                self.lock().grant = None;
                self.lock().deadline = None;
                self.record_publish_abort(reason.code());
                let (term, version) = {
                    let inner = self.lock();
                    (inner.snapshot.term, inner.snapshot.published_version)
                };
                self.audit(
                    PUBLISH_ABORTED,
                    "aborted",
                    Some(reason.code()),
                    term,
                    version,
                    Some(&self.holder),
                );
                self.transition_read_only(PromotionPhase::Aborted, reason.code(), false)
            }
            ReconcileDecision::AlreadyPublished => self.complete_already_published().await,
            ReconcileDecision::Publish => {
                if let Err(error) = self.renew_once().await {
                    warn!(error = %error, "renewal at the first-publish boundary failed");
                    if self.is_fenced() {
                        return PromotionOutcome::Fenced;
                    }
                    return self.transition_read_only(PromotionPhase::Aborted, "lease_lost", true);
                }
                self.complete_first_publish(&prepared, publish_version)
                    .await
            }
        }
    }

    async fn complete_already_published(&self) -> PromotionOutcome {
        // A reachable slave proved the staged bundle at `publish_version` with
        // the pending hash was published by the interrupted (old-term)
        // promotion. That proof establishes `(publish_version, proof_hash)` as
        // the published baseline. It does **not** make the in-memory bundle at
        // that version publishable under the new term: the acquire path may
        // have re-prepared it with a fresh timestamp/term, so its signed hash
        // is different from the proof hash. Adopting it would (a) advertise a
        // same-version/different-hash baseline and self-fence on renewal, and
        // (b) persist over the recovered published state. Instead write one
        // pending state for the *next* version with the proven baseline and
        // publish that above the proof, exactly as the ADR requires.
        let (proven_version, proof_hash, term) = {
            let inner = self.lock();
            let Some(ref loaded) = inner.loaded else {
                drop(inner);
                return self.transition_read_only(
                    PromotionPhase::Aborted,
                    "promotion_interrupted",
                    false,
                );
            };
            let Some(ref bookkeeping) = inner.bookkeeping else {
                drop(inner);
                return self.transition_read_only(
                    PromotionPhase::Aborted,
                    "promotion_interrupted",
                    false,
                );
            };
            if !bookkeeping.has_pending_bundle() {
                drop(inner);
                return self.transition_read_only(
                    PromotionPhase::Aborted,
                    "promotion_interrupted",
                    false,
                );
            }
            let Some(proof_hash) = inner.reconcile_proof_hash.clone() else {
                drop(inner);
                return self.transition_read_only(
                    PromotionPhase::Aborted,
                    "promotion_interrupted",
                    false,
                );
            };
            (loaded.bundle.version, proof_hash, loaded.bundle.term)
        };
        if proven_version == 0 {
            return self.transition_read_only(
                PromotionPhase::Aborted,
                "promotion_interrupted",
                false,
            );
        }
        let Some(next_version) = proven_version.checked_add(1) else {
            let _ = self.fence(FenceReason::StateWriteFailed, "publish version overflow");
            return PromotionOutcome::Fenced;
        };
        info!(
            proven_version,
            next_version,
            "reconciliation proved the pending publish succeeded; publishing above the proven baseline"
        );
        let next = match self.host.prepare_bundle(term, next_version) {
            Ok(next) => next,
            Err(error) => {
                let _ = self.fence(
                    FenceReason::StateWriteFailed,
                    &format!("cannot prepare the post-recovery bundle: {error}"),
                );
                return PromotionOutcome::Fenced;
            }
        };
        let proven = match PublicationBaseline::new(proven_version, &proof_hash) {
            Ok(proven) => proven,
            Err(error) => {
                let _ = self.fence(
                    FenceReason::StateWriteFailed,
                    &format!("invalid recovered published baseline: {error}"),
                );
                return PromotionOutcome::Fenced;
            }
        };
        if let Err(error) = self.write_post_recovery_pending_state(&next, term, &proven) {
            let _ = self.fence(
                FenceReason::StateWriteFailed,
                &format!("cannot persist the post-recovery pending state: {error}"),
            );
            return PromotionOutcome::Fenced;
        }
        self.lock().reconcile_proof_hash = None;
        // Renew with the proven published baseline before the new-term
        // publish. The staged `next` version is never sent to the witness.
        {
            let mut inner = self.lock();
            if let Some(ref mut grant) = inner.grant {
                grant.baseline = proven.clone();
            }
        }
        if let Err(error) = self.renew_published().await {
            warn!(error = %error, "post-recovery renewal failed");
            if self.is_fenced() {
                return PromotionOutcome::Fenced;
            }
            return self.transition_read_only(PromotionPhase::Aborted, "lease_lost", true);
        }
        self.complete_first_publish(&next, next_version).await
    }

    async fn complete_first_publish(
        &self,
        prepared: &PreparedBundle,
        publish_version: u64,
    ) -> PromotionOutcome {
        // ADR: set `publishing` atomically *before* the first push.
        {
            let mut inner = self.lock();
            let Some(ref mut bookkeeping) = inner.bookkeeping else {
                drop(inner);
                return self.transition_read_only(
                    PromotionPhase::Aborted,
                    "promotion_interrupted",
                    false,
                );
            };
            bookkeeping.publication_state = PublicationState::Publishing;
            bookkeeping.pending_hash = Some(prepared.hash.clone());
            inner.snapshot.publication_state = PublicationState::Publishing;
            inner.snapshot.version = publish_version;
            inner.snapshot.bundle_hash.clone_from(&prepared.hash);
        }
        if let Err(error) = self.persist_current_state() {
            let _ = self.fence(
                FenceReason::StateWriteFailed,
                &format!("cannot persist 'publishing' state: {error}"),
            );
            return PromotionOutcome::Fenced;
        }

        // The reconcile window is over: normal push-on-Hello may resume. The
        // first push itself is explicit (not a broadcast) so the exact staged
        // bundle is delivered.
        if let Err(error) = self.host.end_hello_only().await {
            let _ = self.fence(
                FenceReason::RoleSwitchFailed,
                &format!("cannot end hello-only mode: {error}"),
            );
            return PromotionOutcome::Fenced;
        }
        self.set_phase(PromotionPhase::Publishing, None);
        // One final live-lease check immediately before the first push. This
        // is deliberately after the 'publishing' state write: a lost lease
        // must fence, never push.
        if let Err(error) = self.renew_once().await {
            warn!(error = %error, "renewal immediately before the first push failed");
            if self.is_fenced() {
                return PromotionOutcome::Fenced;
            }
            return self.transition_read_only(PromotionPhase::Aborted, "lease_lost", true);
        }
        // The first publish includes a durable state write and an enqueue. A
        // slow fsync or broadcast must not push after the local deadline; the
        // host re-checks this handle immediately before the push and aborts
        // without enqueueing when it is no longer safe.
        let Some(deadline) = self.publish_deadline() else {
            let _ = self.fence(
                FenceReason::LeaseLost,
                "no self-fence deadline is armed before the first publish",
            );
            return PromotionOutcome::Fenced;
        };
        if !deadline.is_safe() {
            let _ = self.fence(
                FenceReason::LeaseLost,
                "the self-fence deadline passed before the first publish",
            );
            return PromotionOutcome::Fenced;
        }
        let published_hash = match self.host.publish_first(prepared, &deadline).await {
            Ok(hash) => hash,
            Err(error) => {
                warn!(error = %error, "first publish failed; state remains 'publishing' for reconciliation");
                // A slow pre-publish write may have consumed the lease budget;
                // fence instead of leaving an open gate for a later retry.
                if self.check_self_fence().unwrap_or(false) {
                    return PromotionOutcome::Fenced;
                }
                self.record_publish_abort("promotion_interrupted");
                return self.transition_read_only(
                    PromotionPhase::Aborted,
                    "promotion_interrupted",
                    true,
                );
            }
        };
        if !hashes_equal(&published_hash, &prepared.hash) {
            let _ = self.fence(
                FenceReason::StateWriteFailed,
                "the pushed bundle hash does not match the staged bundle",
            );
            return PromotionOutcome::Fenced;
        }

        if let Err(error) = self.write_published_state(prepared) {
            // The ADR is explicit: do not renew the witness with the new
            // version if the durable "published" state write failed.
            warn!(error = %error, "published state write failed after the first push");
            self.record_publish_abort("promotion_interrupted");
            return self.transition_read_only(
                PromotionPhase::Aborted,
                "promotion_interrupted",
                false,
            );
        }

        if let Err(error) = self.renew_published().await {
            warn!(error = %error, "post-publish renewal failed");
            return self.transition_read_only(PromotionPhase::Aborted, "lease_lost", false);
        }
        self.become_master().await
    }

    async fn become_master(&self) -> PromotionOutcome {
        if let Err(error) = self.host.switch_role(EffectiveRole::Master).await {
            let _ = self.fence(
                FenceReason::RoleSwitchFailed,
                &format!("cannot switch to the master role: {error}"),
            );
            return PromotionOutcome::Fenced;
        }
        self.host.set_writable(true, None);
        let (term, version) = {
            let inner = self.lock();
            (inner.snapshot.term, inner.snapshot.version)
        };
        self.set_phase(PromotionPhase::Master, None);
        info!(
            node_id = %self.node_id,
            term,
            version,
            "automatic promotion complete; node is the writable master"
        );
        self.audit(COMPLETED, "master", None, term, version, Some(&self.holder));
        PromotionOutcome::Master
    }

    async fn acquire(&self, role: AcquisitionRole, origin: &str) -> AcquireOutcome {
        self.set_phase(PromotionPhase::Acquiring, None);
        {
            let mut inner = self.lock();
            inner.snapshot.last_attempt_unix_ms = Some(self.clock.wall_unix_ms());
        }
        let record = match self.backend.lease().await {
            Ok(record) => {
                self.record_witness_request("lease", "success");
                self.lock().snapshot.witness_reachable = true;
                record
            }
            Err(error) => {
                self.record_witness_request("lease", "error");
                self.lock().snapshot.witness_reachable = false;
                let reason = error.reason_code();
                self.set_phase(PromotionPhase::Unavailable, Some(reason));
                self.record_attempt("witness_error");
                self.record_refusal(reason);
                self.audit(REFUSED, "witness_error", Some(reason), 0, 0, None);
                if self.role == ConfiguredRole::Master {
                    self.host.set_writable(false, Some(reason.to_string()));
                }
                return AcquireOutcome::Outcome(PromotionOutcome::ReadOnly {
                    reason: reason.to_string(),
                    retryable: error.is_retryable(),
                });
            }
        };

        let witness_now = if record
            .as_ref()
            .is_some_and(|record| record.holder == self.holder && record.term > 0)
        {
            // An own-holder record may have expired while this process was
            // paused. Expiry is judged with the witness clock; without it the
            // engine must not assume the grant is still live.
            if let Ok(info) = self.backend.info().await {
                self.record_witness_request("info", "success");
                self.lock().last_witness_now_unix_ms = Some(info.now_unix_ms);
                Some(info.now_unix_ms)
            } else {
                self.record_witness_request("info", "error");
                None
            }
        } else {
            None
        };

        let local = self.local_content(role);
        let decision = decide_acquisition(role, &local, record.as_ref(), &self.holder, witness_now);
        match decision {
            AcquisitionDecision::Refuse(refusal) => {
                let reason = match role {
                    AcquisitionRole::Candidate => refusal.code(),
                    AcquisitionRole::Master => refusal.master_code(),
                };
                self.set_phase(PromotionPhase::Aborted, Some(reason));
                self.clear_lease_diagnostics();
                self.record_attempt("refused");
                self.record_refusal(reason);
                self.audit(REFUSED, "refused", Some(reason), 0, 0, None);
                if role == AcquisitionRole::Master {
                    self.host.set_writable(false, Some(reason.to_string()));
                }
                AcquireOutcome::Outcome(PromotionOutcome::ReadOnly {
                    reason: reason.to_string(),
                    retryable: false,
                })
            }
            AcquisitionDecision::Acquire(plan) => {
                // Capture the local clock before any witness call and arm the
                // self-fence deadline from the *request start*: the witness
                // expiry is at or after `start + TTL`, so the local deadline
                // can never outlive the grant even when the response or the
                // following state write is slow. An unavailable boot clock
                // fences instead of arming from a guessed zero.
                let boot_before = match self.clock.boot_millis() {
                    Ok(now) => now,
                    Err(detail) => {
                        let _ = self.fence(
                            FenceReason::ClockAnomaly,
                            &format!("acquisition: boot clock unavailable: {detail}"),
                        );
                        return AcquireOutcome::Outcome(PromotionOutcome::Fenced);
                    }
                };
                let boot_id = match self.clock.boot_id() {
                    Ok(boot_id) => boot_id,
                    Err(detail) => {
                        let _ = self.fence(
                            FenceReason::ClockAnomaly,
                            &format!("acquisition: boot identity unavailable: {detail}"),
                        );
                        return AcquireOutcome::Outcome(PromotionOutcome::Fenced);
                    }
                };
                let wall = self.clock.wall_unix_ms();
                let record = if plan.existing_grant {
                    // The witness still holds this process' live grant (for
                    // example a retried attempt after a transient failure).
                    // Resume renewal/quiesce instead of trying to re-acquire.
                    let Some(record) = record.clone() else {
                        return AcquireOutcome::Outcome(PromotionOutcome::ReadOnly {
                            reason: "lease_record_missing".to_string(),
                            retryable: true,
                        });
                    };
                    record
                } else {
                    let request = AcquireRequest {
                        holder: self.holder.clone(),
                        node_id: self.node_id.clone(),
                        expected_term: plan.expected_term,
                        expected_revision: plan.expected_revision,
                        term: plan.term,
                        version: plan.baseline.version,
                        bundle_hash: plan.baseline.hash.clone(),
                        ttl_secs: self.config.lease_ttl_secs,
                    };
                    match self.backend.acquire(request).await {
                        Ok(record) => {
                            self.record_witness_request("acquire", "success");
                            record
                        }
                        Err(WitnessClientError::Conflict { .. }) => {
                            self.record_witness_request("acquire", "conflict");
                            self.lock().last_acquire_conflict = true;
                            self.set_phase(
                                PromotionPhase::WaitingForMasterLoss,
                                Some("lease_held_by_other"),
                            );
                            self.record_attempt("conflict");
                            self.audit(
                                REFUSED,
                                "conflict",
                                Some("lease_held_by_other"),
                                0,
                                0,
                                None,
                            );
                            return AcquireOutcome::Outcome(PromotionOutcome::ReadOnly {
                                reason: "lease_held_by_other".to_string(),
                                retryable: true,
                            });
                        }
                        Err(error) => {
                            self.record_witness_request("acquire", "error");
                            let reason = error.reason_code();
                            self.set_phase(PromotionPhase::Unavailable, Some(reason));
                            self.record_attempt("witness_error");
                            self.record_refusal(reason);
                            self.audit(REFUSED, "witness_error", Some(reason), 0, 0, None);
                            if role == AcquisitionRole::Master {
                                self.host.set_writable(false, Some(reason.to_string()));
                            }
                            return AcquireOutcome::Outcome(PromotionOutcome::ReadOnly {
                                reason: reason.to_string(),
                                retryable: error.is_retryable(),
                            });
                        }
                    }
                };
                if record.holder != self.holder
                    || record.term != plan.term
                    || (!plan.existing_grant && record.version != plan.baseline.version)
                {
                    self.set_phase(PromotionPhase::Aborted, Some("promotion_interrupted"));
                    let _ = self.fence(
                        FenceReason::StateWriteFailed,
                        "acquire returned a record that does not match the request",
                    );
                    return AcquireOutcome::Outcome(PromotionOutcome::Fenced);
                }
                let prepared = match self.host.prepare_bundle(record.term, plan.publish_version) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        let _ = self.fence(
                            FenceReason::StateWriteFailed,
                            &format!("cannot prepare the pending bundle: {error}"),
                        );
                        return AcquireOutcome::Outcome(PromotionOutcome::Fenced);
                    }
                };
                if let Err(error) =
                    self.write_pending_state(&record, &plan, &prepared, origin, role, &local)
                {
                    let _ = self.fence(
                        FenceReason::StateWriteFailed,
                        &format!("cannot persist the promotion state: {error}"),
                    );
                    return AcquireOutcome::Outcome(PromotionOutcome::Fenced);
                }
                let grant = LeaseGrant {
                    holder: record.holder.clone(),
                    term: record.term,
                    revision: record.revision,
                    baseline: plan.baseline.clone(),
                };
                let deadline = SelfFenceDeadline::arm(
                    boot_before,
                    boot_id.clone(),
                    wall,
                    self.config.lease_ttl_secs,
                    self.config.renew_interval_secs,
                );
                {
                    let mut inner = self.lock();
                    inner.grant = Some(grant);
                    inner.deadline = Some(deadline);
                    inner.boot_id = Some(boot_id);
                    inner.last_wall_unix_ms = Some(wall);
                    inner.pending = Some(prepared);
                    inner.snapshot.term = record.term;
                    inner.snapshot.version = plan.publish_version;
                    inner.snapshot.bundle_hash = inner
                        .pending
                        .as_ref()
                        .map_or("none", |p| p.hash.as_str())
                        .to_string();
                    inner.snapshot.publication_state = PublicationState::Pending;
                    inner.snapshot.published_version = plan.baseline.version;
                    inner
                        .snapshot
                        .published_hash
                        .clone_from(&plan.baseline.hash);
                    inner.snapshot.lease_revision = Some(record.revision);
                    inner.snapshot.lease_expires_unix_ms = Some(record.expires_unix_ms);
                    inner.snapshot.witness_reachable = true;
                    inner.snapshot.promoted_at_unix_ms = Some(self.clock.wall_unix_ms());
                }
                self.record_attempt("success");
                self.record_last_success();
                self.audit(
                    LEASE_ACQUIRED,
                    "acquired",
                    Some(origin),
                    record.term,
                    plan.publish_version,
                    Some(&record.holder),
                );
                // ADR-0010: stop the slave worker / start the master listener
                // immediately after acquisition, and keep the listener
                // hello-only through quiesce and reconciliation. The node must
                // never run both roles at once.
                if let Err(error) = self.host.switch_role(EffectiveRole::Master).await {
                    let _ = self.fence(
                        FenceReason::RoleSwitchFailed,
                        &format!("cannot switch to the master role after acquisition: {error}"),
                    );
                    return AcquireOutcome::Outcome(PromotionOutcome::Fenced);
                }
                if let Err(error) = self.host.begin_hello_only().await {
                    let _ = self.fence(
                        FenceReason::RoleSwitchFailed,
                        &format!("cannot enter hello-only mode after acquisition: {error}"),
                    );
                    return AcquireOutcome::Outcome(PromotionOutcome::Fenced);
                }
                AcquireOutcome::Acquired
            }
        }
    }

    fn local_content(&self, role: AcquisitionRole) -> LocalContent {
        let (pending_version, state_term, state_version, state_bundle, bookkeeping) = {
            let inner = self.lock();
            let state = inner.loaded.clone();
            (
                state.as_ref().map_or(0, |state| state.bundle.version),
                state.as_ref().map_or(0, |state| state.bundle.term),
                state.as_ref().map_or(0, |state| state.bundle.version),
                state.as_ref().map(|state| state.bundle.clone()),
                inner.bookkeeping.clone(),
            )
        };
        let state_hash = state_bundle
            .as_ref()
            .and_then(|bundle| self.host.hash_bundle(bundle).ok());

        match role {
            AcquisitionRole::Master => {
                let (last_version, last_hash) = bookkeeping.as_ref().map_or((0, None), |b| {
                    (
                        b.last_applied_version.unwrap_or(0),
                        b.last_applied_hash.clone(),
                    )
                });
                let mut local =
                    LocalContent::master(state_term, bookkeeping, last_version, last_hash);
                local.state_version = state_version;
                local.state_hash = state_hash;
                local.pending_version = pending_version;
                local
            }
            AcquisitionRole::Candidate => {
                let watermark = self.host.applied_watermark();
                let (applied_term, applied_version, applied_hash) =
                    watermark.map_or((0, 0, None), |watermark| {
                        (
                            watermark.term,
                            watermark.version,
                            Some(watermark.payload_hash.clone()),
                        )
                    });
                let mut local = LocalContent::candidate(
                    applied_term,
                    applied_version,
                    applied_hash,
                    bookkeeping,
                );
                local.state_term = state_term;
                local.state_version = state_version;
                local.state_hash = state_hash;
                local.pending_version = pending_version;
                local
            }
        }
    }

    fn write_pending_state(
        &self,
        record: &LeaseRecord,
        plan: &super::acquisition::AcquirePlan,
        prepared: &PreparedBundle,
        origin: &str,
        role: AcquisitionRole,
        local: &LocalContent,
    ) -> Result<(), HaError> {
        let mut state = self.current_state_with_bundle(prepared.bundle.clone());
        let previous_state = self.lock().bookkeeping.clone();
        let previous_bundle_version = self
            .lock()
            .loaded
            .as_ref()
            .map_or(0, |state| state.bundle.version);
        let proof_hash = previous_state.as_ref().and_then(|bookkeeping| {
            (bookkeeping.publication_state == PublicationState::Publishing
                && previous_bundle_version == plan.publish_version)
                .then(|| bookkeeping.pending_hash.clone())
                .flatten()
        });
        let publication_state = if plan.reusing_pending
            && previous_state
                .as_ref()
                .is_some_and(|b| b.publication_state == PublicationState::Publishing)
        {
            PublicationState::Publishing
        } else {
            PublicationState::Pending
        };
        // While a `publishing` bundle at this exact version is being re-tested,
        // keep the old pending hash durable: it is the hash a surviving slave
        // (or the witness record) can prove. The freshly prepared bundle is
        // not published yet and must not replace that crash-proof in the state
        // file. `complete_first_publish` replaces it immediately before the
        // first push.
        let durable_pending_hash = proof_hash.clone().or_else(|| Some(prepared.hash.clone()));
        let bookkeeping = PromotionBookkeeping {
            publication_state,
            published_version: plan.baseline.version,
            published_hash: plan.baseline.hash.clone(),
            pending_hash: durable_pending_hash,
            promotion_origin: Some(origin.to_string()),
            lease_holder: Some(record.holder.clone()),
            cluster_id: Some(self.cluster_id.clone()),
            node_id: Some(self.node_id.clone()),
            promoted_at_unix_ms: Some(self.clock.wall_unix_ms()),
            last_applied_version: Some(local.applied_version),
            last_applied_hash: local.applied_hash.clone(),
        };
        bookkeeping.apply_to(&mut state);
        #[cfg(test)]
        if self
            .fail_pending_state_write
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(HaError::Io(std::io::Error::other(
                "injected pending-state write failure",
            )));
        }
        state.bundle.term = record.term;
        state.bundle.version = plan.publish_version;
        // The bundle built by the host must already be at the publish version;
        // a mismatch is a programming error, not a reason to publish.
        if state.bundle.version != prepared.bundle.version || state.bundle.term != record.term {
            return Err(HaError::Validation {
                field: "ha_state".to_string(),
                reason: "prepared bundle term/version does not match the acquire plan".to_string(),
            });
        }
        self.state.save(&state)?;
        let mut inner = self.lock();
        inner.loaded = Some(state);
        inner.bookkeeping = Some(bookkeeping);
        inner.reconcile_proof_hash = proof_hash;
        inner.snapshot.term = record.term;
        inner.snapshot.publication_state = publication_state;
        let _ = role;
        Ok(())
    }

    /// Persists the post-recovery pending state.
    ///
    /// The recovered proof establishes `published` as the last actually
    /// published baseline; the new-term bundle at `prepared.bundle.version` is
    /// the staged version one above it. Both are written atomically so a crash
    /// can never lose the proven baseline or skip the staged version.
    fn write_post_recovery_pending_state(
        &self,
        prepared: &PreparedBundle,
        term: u64,
        published: &PublicationBaseline,
    ) -> Result<(), HaError> {
        let mut state = self.current_state_with_bundle(prepared.bundle.clone());
        state.bundle.term = term;
        state.bundle.version = prepared.bundle.version;
        {
            let mut inner = self.lock();
            let Some(ref mut bookkeeping) = inner.bookkeeping else {
                return Err(HaError::Validation {
                    field: "ha_state".to_string(),
                    reason: "no promotion bookkeeping for the post-recovery publish".to_string(),
                });
            };
            bookkeeping.publication_state = PublicationState::Pending;
            bookkeeping.published_version = published.version;
            bookkeeping.published_hash.clone_from(&published.hash);
            bookkeeping.pending_hash = Some(prepared.hash.clone());
            bookkeeping.promotion_origin = Some("restart".to_string());
            bookkeeping.promoted_at_unix_ms = Some(self.clock.wall_unix_ms());
            bookkeeping.apply_to(&mut state);
            inner.snapshot.version = prepared.bundle.version;
            inner.snapshot.bundle_hash.clone_from(&prepared.hash);
            inner.snapshot.publication_state = PublicationState::Pending;
            inner.snapshot.published_version = published.version;
            inner.snapshot.published_hash.clone_from(&published.hash);
        }
        self.state.save(&state)?;
        let mut inner = self.lock();
        inner.loaded = Some(state);
        inner.pending = Some(prepared.clone());
        Ok(())
    }

    fn write_published_state(&self, prepared: &PreparedBundle) -> Result<(), HaError> {
        #[cfg(test)]
        if self
            .fail_published_state_write
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(HaError::Io(std::io::Error::other(
                "injected published-state write failure",
            )));
        }
        {
            let mut inner = self.lock();
            let Some(ref mut bookkeeping) = inner.bookkeeping else {
                return Err(HaError::Validation {
                    field: "ha_state".to_string(),
                    reason: "no promotion bookkeeping to publish".to_string(),
                });
            };
            bookkeeping.publication_state = PublicationState::Published;
            bookkeeping.published_version = prepared.bundle.version;
            bookkeeping.published_hash.clone_from(&prepared.hash);
            bookkeeping.pending_hash = None;
            inner.snapshot.publication_state = PublicationState::Published;
            inner.snapshot.published_version = prepared.bundle.version;
            inner.snapshot.published_hash.clone_from(&prepared.hash);
            inner.snapshot.version = prepared.bundle.version;
            inner.snapshot.bundle_hash.clone_from(&prepared.hash);
        }
        self.persist_current_state()
    }

    fn persist_current_state(&self) -> Result<(), HaError> {
        let (bookkeeping, bundle) = {
            let inner = self.lock();
            let Some(bookkeeping) = inner.bookkeeping.clone() else {
                return Err(HaError::Validation {
                    field: "ha_state".to_string(),
                    reason: "no promotion bookkeeping to persist".to_string(),
                });
            };
            let bundle = inner
                .loaded
                .as_ref()
                .map(|state| state.bundle.clone())
                .or_else(|| inner.pending.as_ref().map(|p| p.bundle.clone()));
            let Some(bundle) = bundle else {
                return Err(HaError::Validation {
                    field: "ha_state".to_string(),
                    reason: "no bundle to persist".to_string(),
                });
            };
            (bookkeeping, bundle)
        };
        let mut state = self.current_state_with_bundle(bundle);
        bookkeeping.apply_to(&mut state);
        self.state.save(&state)?;
        self.lock().loaded = Some(state);
        Ok(())
    }

    fn current_state_with_bundle(&self, bundle: ConfigBundle) -> PersistedMasterState {
        let previous = self.lock().loaded.clone();
        PersistedMasterState {
            protocol_version: crate::protocol::PROTOCOL_VERSION,
            bundle,
            // A candidate may have no prior `ha_state.toml` (and a prior state
            // may predate the identity field). Preserve the durable value when
            // present and otherwise record the runtime's signing key so key
            // loss stays detectable after a promotion.
            signing_key_pubkey: previous
                .as_ref()
                .and_then(|state| state.signing_key_pubkey.clone())
                .or_else(|| self.host.signing_key_pubkey()),
            publication_state: None,
            published_version: None,
            published_hash: None,
            pending_hash: None,
            promotion_origin: None,
            lease_holder: None,
            cluster_id: None,
            node_id: None,
            promoted_at_unix_ms: None,
            last_applied_version: None,
            last_applied_hash: None,
        }
    }

    fn record_successful_renewal(
        &self,
        revision: u64,
        arm_boot_millis: u64,
    ) -> Result<(), HaError> {
        let boot_id = match self.clock.boot_id() {
            Ok(boot_id) => boot_id,
            Err(detail) => {
                let message = format!("renewal ACK: boot identity unavailable: {detail}");
                let _ = self.fence(FenceReason::ClockAnomaly, &message);
                return Err(HaError::Connection(message));
            }
        };
        let wall = self.clock.wall_unix_ms();
        let boot_now = match self.clock.boot_millis() {
            Ok(now) => now,
            Err(detail) => {
                let message = format!("renewal ACK: boot clock unavailable: {detail}");
                let _ = self.fence(FenceReason::ClockAnomaly, &message);
                return Err(HaError::Connection(message));
            }
        };
        // Arm from the request start, not the response time: the witness
        // expiry is at or after `request_start + TTL`, so the local deadline
        // stays before the record can be granted elsewhere even when the
        // response is slow. A request that consumed the whole budget leaves no
        // safe window: fence immediately instead of returning a lease that is
        // already past its local deadline.
        let deadline = SelfFenceDeadline::arm(
            arm_boot_millis,
            boot_id,
            wall,
            self.config.lease_ttl_secs,
            self.config.renew_interval_secs,
        );
        if deadline.remaining(boot_now).is_zero() {
            let message = "renewal ACK left no self-fence budget; fencing";
            let _ = self.fence(FenceReason::LeaseLost, message);
            return Err(HaError::Connection(message.to_string()));
        }
        let mut inner = self.lock();
        if let Some(ref mut grant) = inner.grant {
            grant.revision = revision;
        }
        inner.deadline = Some(deadline);
        inner.last_wall_unix_ms = Some(wall);
        inner.snapshot.lease_revision = Some(revision);
        inner.snapshot.witness_reachable = true;
        Ok(())
    }

    async fn renew_published(&self) -> Result<(), HaError> {
        // The durable published baseline is the only value that may be sent to
        // the witness. `pending` is the active bundle and may be a staged
        // version; it is never a renewal baseline.
        let baseline = {
            let inner = self.lock();
            let Some(ref bookkeeping) = inner.bookkeeping else {
                return Err(HaError::Validation {
                    field: "ha.promotion".to_string(),
                    reason: "no promotion bookkeeping to renew".to_string(),
                });
            };
            bookkeeping.baseline()
        };
        {
            let mut inner = self.lock();
            let Some(ref mut grant) = inner.grant else {
                return Err(HaError::Validation {
                    field: "ha.promotion".to_string(),
                    reason: "cannot renew without a lease grant".to_string(),
                });
            };
            grant.baseline = baseline;
        }
        self.renew_once().await.map(|_| ())
    }

    fn handle_renewal_action(&self, action: RenewalAction) -> Result<u64, HaError> {
        match action {
            RenewalAction::AdoptRevision { .. } | RenewalAction::RetryHigherBaseline { .. } => {
                // These are handled as *retries* in `renew_once`; treating one
                // as a successful ACK would re-arm the deadline without the
                // witness extending the lease.
                Err(HaError::Connection(
                    "renewal revision adoption must be retried, not accepted".to_string(),
                ))
            }
            RenewalAction::RetryTransport => Err(HaError::Connection(
                "witness renewal failed; retry before the self-fence deadline".to_string(),
            )),
            RenewalAction::Fence { reason, detail } => {
                let fence_reason = fence_reason_from_code(reason);
                self.fence(fence_reason, &detail)?;
                Err(HaError::Connection(format!("fenced: {reason}: {detail}")))
            }
        }
    }

    /// Persists the durable fence, stops publishing/accepting writes, and
    /// refuses all future automatic acquisition.
    pub fn fence(&self, reason: FenceReason, detail: &str) -> Result<(), HaError> {
        let term = self.lock().snapshot.term;
        let marker = FenceMarker::new(
            self.cluster_id.clone(),
            self.node_id.clone(),
            term,
            reason,
            self.clock.wall_unix_ms(),
        );
        let outcome = self.fence.persist(&marker);
        // ADR order: the marker is written before the node stops accepting
        // writes. These steps are all local and must happen even when the
        // marker write failed.
        self.host.stop_publishing();
        self.host.close_replication_sessions("fenced");
        self.host
            .set_writable(false, Some("ha_promotion_fenced".to_string()));
        {
            let mut inner = self.lock();
            inner.snapshot.fenced = true;
            inner.snapshot.phase = PromotionPhase::Fenced;
            inner.snapshot.reason = Some(reason.code().to_string());
            inner.snapshot.term = marker.fenced_term;
            // A fence means no live grant: do not keep advertising the old
            // revision/expiry or a stale reachable witness.
            inner.snapshot.lease_revision = None;
            inner.snapshot.lease_expires_unix_ms = None;
            inner.snapshot.lease_expires_in_secs = None;
            inner.snapshot.lease_held = false;
            inner.snapshot.witness_reachable = false;
            inner.grant = None;
            inner.deadline = None;
        }
        warn!(
            node_id = %self.node_id,
            reason = reason.code(),
            detail,
            "HA promotion self-fenced; a restart stays read-only until an operator clears the marker"
        );
        if let Some(metrics) = self.metrics.as_ref() {
            metrics.inc_ha_promotion_fenced(reason.code());
        }
        let (term, version) = {
            let inner = self.lock();
            (inner.snapshot.term, inner.snapshot.published_version)
        };
        if matches!(
            reason,
            FenceReason::LeaseLost
                | FenceReason::LeaseRecordMissing
                | FenceReason::LeaseVersionRegression
        ) {
            self.audit(
                LEASE_LOST,
                "lost",
                Some(reason.code()),
                term,
                version,
                Some(&self.holder),
            );
        }
        self.audit(
            FENCED,
            "fenced",
            Some(reason.code()),
            term,
            version,
            Some(&self.holder),
        );
        match outcome {
            FencePersistOutcome::Durable | FencePersistOutcome::PendingOnly => Ok(()),
            FencePersistOutcome::Undurable => {
                let integrity = self.fence.check_integrity();
                self.host.critical_local_failure(&format!(
                    "both fence markers failed: {detail}; data-dir integrity: {integrity:?}"
                ));
                Err(HaError::Validation {
                    field: "ha_fence".to_string(),
                    reason: format!(
                        "both fence writes failed; process must exit non-zero (data-dir integrity: {integrity:?})"
                    ),
                })
            }
        }
    }

    fn is_fenced(&self) -> bool {
        self.fence.load().ok().flatten().is_some() || self.lock().snapshot.fenced
    }

    fn set_phase(&self, phase: PromotionPhase, reason: Option<&str>) {
        let mut inner = self.lock();
        inner.snapshot.phase = phase;
        inner.snapshot.reason = reason.map(str::to_string);
    }

    fn record_attempt(&self, result: &str) {
        if let Some(metrics) = self.metrics.as_ref() {
            metrics.inc_ha_promotion_attempt(result);
        }
    }

    fn record_witness_request(&self, op: &str, result: &str) {
        // The status field is a last-probe observation: only a successful call
        // proves reachability. A transport/auth/5xx failure (and any other
        // failed probe) clears it immediately instead of leaving a stale `true`
        // until fencing. A CAS conflict (409) is a real witness answer and
        // therefore still reachable.
        self.lock().snapshot.witness_reachable = matches!(result, "success" | "conflict");
        let bounded = if result == "error" {
            "witness_error"
        } else {
            result
        };
        if let Some(metrics) = self.metrics.as_ref() {
            metrics.inc_ha_promotion_witness_request(op, bounded);
        }
    }

    fn record_refusal(&self, reason: &str) {
        if let Some(metrics) = self.metrics.as_ref() {
            metrics.inc_ha_promotion_refusal(reason);
        }
    }

    fn record_publish_abort(&self, reason: &str) {
        if let Some(metrics) = self.metrics.as_ref() {
            metrics.inc_ha_promotion_publish_abort(reason);
        }
    }

    fn record_last_success(&self) {
        if let Some(metrics) = self.metrics.as_ref() {
            let now = self.clock.wall_unix_ms().max(0);
            metrics.set_ha_promotion_last_success_seconds(u64::try_from(now / 1_000).unwrap_or(0));
        }
    }

    fn audit(
        &self,
        event: &'static str,
        outcome: &str,
        reason: Option<&str>,
        term: u64,
        version: u64,
        holder: Option<&str>,
    ) {
        let mut record =
            PromotionAudit::new(event, &self.node_id, outcome).with_bundle(term, version);
        if let Some(reason) = reason {
            record = record.with_reason(reason);
        }
        if let Some(holder) = holder {
            record = record.with_holder(holder);
        }
        record.emit();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, EngineInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

enum AcquireOutcome {
    Acquired,
    Outcome(PromotionOutcome),
}

fn fence_reason_from_code(code: &str) -> FenceReason {
    match code {
        "lease_version_regression" => FenceReason::LeaseVersionRegression,
        "lease_record_missing" => FenceReason::LeaseRecordMissing,
        "witness_auth_failed" => FenceReason::WitnessAuthFailed,
        "witness_protocol_mismatch" => FenceReason::WitnessProtocolMismatch,
        "clock_step" => FenceReason::ClockAnomaly,
        _ => FenceReason::LeaseLost,
    }
}

fn lease_is_live(record: &LeaseRecord, grant: &LeaseGrant, witness_now: Option<i64>) -> bool {
    let not_expired = witness_now.is_some_and(|now| !record.is_expired(now));
    record.holder == grant.holder
        && record.term == grant.term
        && record.revision >= grant.revision
        && not_expired
}

fn hashes_equal(left: &str, right: &str) -> bool {
    left.trim()
        .trim_start_matches("blake3:")
        .eq_ignore_ascii_case(right.trim().trim_start_matches("blake3:"))
}

/// Convenience constructor for a deterministic test clock.
#[must_use]
pub fn manual_clock(boot_millis: u64, wall_unix_ms: i64) -> Arc<ManualMonotonicClock> {
    Arc::new(ManualMonotonicClock::new(boot_millis, wall_unix_ms))
}
