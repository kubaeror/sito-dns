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

use std::sync::{Arc, Mutex};

use sito_ha_types::bundle::{AppliedWatermark, ConfigBundle};
use sito_ha_types::config::PromotionConfig;
use sito_ha_types::status::PublicationState;
use tracing::{info, warn};

use crate::error::HaError;
use crate::witness::{AcquireRequest, LeaseInfo, LeaseRecord, RenewRequest};

use super::witness_client::{WitnessClient, WitnessClientError};

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

/// Runtime integration points for the engine.
pub trait PromotionHost: Send + Sync + 'static {
    /// Applies the slave watermark and current local document to a bundle built
    /// at `(term, version)`. Must not install or persist the bundle.
    fn prepare_bundle(&self, term: u64, version: u64) -> Result<PreparedBundle, String>;

    /// Returns the durable applied watermark, if any.
    fn applied_watermark(&self) -> Option<AppliedWatermark>;

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
    fn publish_first(&self, prepared: &PreparedBundle) -> BoxFuture<'_, Result<String, String>>;

    /// Makes an already-published bundle active without re-pushing it (used
    /// when reconciliation proves a crash-interrupted publish succeeded).
    fn adopt_published(&self, prepared: &PreparedBundle) -> BoxFuture<'_, Result<(), String>>;

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
    inner: Mutex<EngineInner>,
    data_dir: std::path::PathBuf,
    /// Effective candidate heartbeat timeout from `ha.ping_interval_secs`.
    heartbeat_timeout_secs: u64,
    /// Test-only hook to fail the durable `published` state write after a
    /// successful first push (the ADR's crash-window test).
    #[cfg(test)]
    fail_published_state_write: std::sync::atomic::AtomicBool,
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
        let snapshot = PromotionSnapshot {
            enabled: true,
            candidate: config.candidate,
            cluster_id: Some(cluster_id.clone()),
            node_id: Some(node_id.clone()),
            phase: PromotionPhase::Unavailable,
            reason: None,
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
        })
    }

    /// Overrides the effective heartbeat timeout (the runtime passes
    /// `max(45, 3 * ha.ping_interval_secs)` when the config omits it).
    #[must_use]
    pub fn with_heartbeat_timeout_secs(mut self, secs: u64) -> Self {
        self.heartbeat_timeout_secs = secs.max(1);
        self
    }

    /// Test-only: make the next durable `published` state write fail.
    #[cfg(test)]
    pub fn fail_published_state_write(&self) {
        self.fail_published_state_write
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Current internal snapshot.
    #[must_use]
    pub fn snapshot(&self) -> PromotionSnapshot {
        self.lock().snapshot.clone()
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
        // A restart discards any unconsumed manual confirmation: it is
        // one-shot and must not authorize a second process incarnation.
        self.confirm.discard();

        if let Some(marker) = self.fence.load()? {
            let mut inner = self.lock();
            inner.snapshot.fenced = true;
            inner.snapshot.phase = PromotionPhase::Fenced;
            inner.snapshot.reason = Some("fenced_until_reconciled".to_string());
            inner.snapshot.term = marker.fenced_term;
            drop(inner);
            self.host
                .set_writable(false, Some("ha_promotion_fenced".to_string()));
            self.lock().booted = true;
            return Ok(PromotionOutcome::Fenced);
        }

        let loaded = self.state.load()?;
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
                    inner.snapshot.phase = PromotionPhase::Unavailable;
                    inner.snapshot.reason = Some("witness_unavailable".to_string());
                    (
                        PromotionPhase::Unavailable,
                        Some("witness_unavailable".to_string()),
                    )
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
        let _ = reason;
        self.lock().booted = true;
        Ok(match phase {
            PromotionPhase::WaitingForMasterLoss => PromotionOutcome::Waiting,
            _ => PromotionOutcome::ReadOnly {
                reason: "not_candidate".to_string(),
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
            return PromotionOutcome::ReadOnly {
                reason: reason.to_string(),
                retryable: false,
            };
        }

        if self.config.require_manual_confirmation {
            let max_age_ms = i64::try_from(self.heartbeat_timeout_secs.saturating_mul(1_000))
                .unwrap_or(i64::MAX);
            let now = self.clock.wall_unix_ms();
            match self.confirm.consume(now, max_age_ms) {
                Ok(_) => {
                    info!(
                        node_id = %self.node_id,
                        "manual promotion confirmation consumed"
                    );
                }
                Err(error) => {
                    self.set_phase(
                        PromotionPhase::ManualConfirmationRequired,
                        Some("manual_confirmation_required"),
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
    pub async fn renew_once(&self) -> Result<u64, HaError> {
        let grant = {
            let inner = self.lock();
            inner.grant.clone()
        };
        let Some(grant) = grant else {
            return Err(HaError::Validation {
                field: "ha.promotion".to_string(),
                reason: "cannot renew without a lease grant".to_string(),
            });
        };
        let witness_now = match self.backend.info().await {
            Ok(info) => {
                self.lock().last_witness_now_unix_ms = Some(info.now_unix_ms);
                Some(info.now_unix_ms)
            }
            Err(_) => None,
        };
        let request = RenewRequest {
            holder: grant.holder.clone(),
            term: grant.term,
            expected_revision: grant.revision,
            version: grant.baseline.version,
            bundle_hash: grant.baseline.hash.clone(),
            ttl_secs: self.config.lease_ttl_secs,
        };
        match self.backend.renew(request).await {
            Ok(record) => {
                self.record_successful_renewal(record.revision);
                Ok(record.revision)
            }
            Err(error) => {
                let action = classify_renewal_error(
                    &error,
                    &grant.holder,
                    grant.term,
                    &grant.baseline,
                    witness_now,
                );
                self.handle_renewal_action(action)
            }
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
        inner.latched.record_late_report(report, term, version)
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

    async fn reconcile_and_publish(&self) -> PromotionOutcome {
        self.set_phase(PromotionPhase::Reconciling, None);
        let (grant, baseline, publish_version, publication_state, prepared) = {
            let inner = self.lock();
            let Some(grant) = inner.grant.clone() else {
                return PromotionOutcome::ReadOnly {
                    reason: "lease_record_missing".to_string(),
                    retryable: true,
                };
            };
            let Some(ref bookkeeping) = inner.bookkeeping else {
                return PromotionOutcome::ReadOnly {
                    reason: "promotion_interrupted".to_string(),
                    retryable: false,
                };
            };
            let Some(ref prepared) = inner.pending else {
                return PromotionOutcome::ReadOnly {
                    reason: "promotion_interrupted".to_string(),
                    retryable: false,
                };
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
        self.lock().snapshot.reconcile_remaining_secs = self.config.reconcile_window_secs;
        self.timers
            .sleep(std::time::Duration::from_secs(
                self.config.reconcile_window_secs,
            ))
            .await;
        let peers = match self.host.collect_reconcile_reports().await {
            Ok(peers) => peers,
            Err(error) => {
                let _ = self.host.end_hello_only().await;
                self.set_phase(PromotionPhase::Aborted, Some("candidate_hash_unknown"));
                warn!(error = %error, "reconciliation report collection failed");
                return PromotionOutcome::ReadOnly {
                    reason: "candidate_hash_unknown".to_string(),
                    retryable: false,
                };
            }
        };
        self.lock().snapshot.reconcile_remaining_secs = 0;

        let witness = match self.backend.lease().await {
            Ok(Some(record)) => record,
            Ok(None) => {
                let _ = self.host.end_hello_only().await;
                let _ = self.fence(
                    FenceReason::LeaseRecordMissing,
                    "witness record disappeared",
                );
                return PromotionOutcome::Fenced;
            }
            Err(error) => {
                let _ = self.host.end_hello_only().await;
                self.set_phase(PromotionPhase::Unavailable, Some(error.reason_code()));
                return PromotionOutcome::ReadOnly {
                    reason: error.reason_code().to_string(),
                    retryable: error.is_retryable(),
                };
            }
        };

        let proof_hash = self.lock().reconcile_proof_hash.clone();
        if witness.holder != grant.holder
            || witness.term != grant.term
            || witness.revision < grant.revision
        {
            let _ = self.host.end_hello_only().await;
            let _ = self.fence(
                FenceReason::LeaseLost,
                "the witness record changed to another holder/term before the first publish",
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

        match decision {
            ReconcileDecision::Abort(reason) => {
                let _ = self.host.end_hello_only().await;
                self.host
                    .close_replication_sessions("reconciliation aborted");
                self.set_phase(PromotionPhase::Aborted, Some(reason.code()));
                self.host
                    .set_writable(false, Some(reason.code().to_string()));
                // Let the lease expire; the node never publishes or becomes
                // writable in this term.
                self.lock().grant = None;
                self.lock().deadline = None;
                PromotionOutcome::ReadOnly {
                    reason: reason.code().to_string(),
                    retryable: false,
                }
            }
            ReconcileDecision::AlreadyPublished => self.complete_already_published(&prepared).await,
            ReconcileDecision::Publish => {
                self.complete_first_publish(&prepared, publish_version)
                    .await
            }
        }
    }

    async fn complete_already_published(&self, _prepared: &PreparedBundle) -> PromotionOutcome {
        // A reachable slave (or the witness record) proved the staged bundle
        // was published, but the interrupted publish used the *old* term. A
        // new term must still publish a strictly higher version above the
        // proven baseline; adopting the old-term bundle alone would leave the
        // new term with no published bundle and could overwrite a same-version
        // slave.
        let (proven, term) = {
            let inner = self.lock();
            let Some(ref loaded) = inner.loaded else {
                return PromotionOutcome::ReadOnly {
                    reason: "promotion_interrupted".to_string(),
                    retryable: false,
                };
            };
            let Some(ref bookkeeping) = inner.bookkeeping else {
                return PromotionOutcome::ReadOnly {
                    reason: "promotion_interrupted".to_string(),
                    retryable: false,
                };
            };
            let Some(proof_hash) = inner.reconcile_proof_hash.clone() else {
                return PromotionOutcome::ReadOnly {
                    reason: "promotion_interrupted".to_string(),
                    retryable: false,
                };
            };
            let _ = bookkeeping;
            (
                PreparedBundle {
                    bundle: loaded.bundle.clone(),
                    hash: proof_hash,
                },
                loaded.bundle.term,
            )
        };
        info!(
            version = proven.bundle.version,
            "reconciliation proved the pending publish succeeded; establishing the published baseline"
        );
        if let Err(error) = self.write_published_state(&proven) {
            let _ = self.host.end_hello_only().await;
            warn!(error = %error, "failed to persist the recovered 'published' state");
            self.set_phase(PromotionPhase::Aborted, Some("promotion_interrupted"));
            self.host
                .set_writable(false, Some("promotion_interrupted".to_string()));
            return PromotionOutcome::ReadOnly {
                reason: "promotion_interrupted".to_string(),
                retryable: false,
            };
        }
        self.lock().pending = Some(proven.clone());
        self.lock().reconcile_proof_hash = None;
        if let Err(error) = self.host.adopt_published(&proven).await {
            let _ = self.host.end_hello_only().await;
            let _ = self.fence(
                FenceReason::RoleSwitchFailed,
                &format!("cannot adopt published bundle: {error}"),
            );
            return PromotionOutcome::Fenced;
        }
        if let Err(error) = self.renew_published().await {
            let _ = self.host.end_hello_only().await;
            warn!(error = %error, "post-publish renewal failed");
            return PromotionOutcome::ReadOnly {
                reason: "lease_lost".to_string(),
                retryable: false,
            };
        }

        // The new term still needs its own publish strictly above the proven
        // baseline. Prepare it at the current term and continue through the
        // normal first-publish path.
        let Some(next_version) = proven.bundle.version.checked_add(1) else {
            let _ = self.host.end_hello_only().await;
            let _ = self.fence(FenceReason::StateWriteFailed, "publish version overflow");
            return PromotionOutcome::Fenced;
        };
        let next = match self.host.prepare_bundle(term, next_version) {
            Ok(next) => next,
            Err(error) => {
                let _ = self.host.end_hello_only().await;
                let _ = self.fence(
                    FenceReason::StateWriteFailed,
                    &format!("cannot prepare the post-recovery bundle: {error}"),
                );
                return PromotionOutcome::Fenced;
            }
        };
        if let Err(error) = self.write_next_pending_state(&next, term) {
            let _ = self.host.end_hello_only().await;
            let _ = self.fence(
                FenceReason::StateWriteFailed,
                &format!("cannot persist the post-recovery pending state: {error}"),
            );
            return PromotionOutcome::Fenced;
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
                return PromotionOutcome::ReadOnly {
                    reason: "promotion_interrupted".to_string(),
                    retryable: false,
                };
            };
            bookkeeping.publication_state = PublicationState::Publishing;
            bookkeeping.pending_hash = Some(prepared.hash.clone());
            inner.snapshot.publication_state = PublicationState::Publishing;
            inner.snapshot.version = publish_version;
            inner.snapshot.bundle_hash.clone_from(&prepared.hash);
        }
        if let Err(error) = self.persist_current_state() {
            let _ = self.host.end_hello_only().await;
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
        let published_hash = match self.host.publish_first(prepared).await {
            Ok(hash) => hash,
            Err(error) => {
                self.set_phase(PromotionPhase::Aborted, Some("promotion_interrupted"));
                self.host
                    .set_writable(false, Some("promotion_interrupted".to_string()));
                warn!(error = %error, "first publish failed; state remains 'publishing' for reconciliation");
                return PromotionOutcome::ReadOnly {
                    reason: "promotion_interrupted".to_string(),
                    retryable: true,
                };
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
            self.set_phase(PromotionPhase::Aborted, Some("promotion_interrupted"));
            self.host
                .set_writable(false, Some("promotion_interrupted".to_string()));
            // The ADR is explicit: do not renew the witness with the new
            // version if the durable "published" state write failed.
            warn!(error = %error, "published state write failed after the first push");
            return PromotionOutcome::ReadOnly {
                reason: "promotion_interrupted".to_string(),
                retryable: false,
            };
        }

        if let Err(error) = self.renew_published().await {
            warn!(error = %error, "post-publish renewal failed");
            return PromotionOutcome::ReadOnly {
                reason: "lease_lost".to_string(),
                retryable: false,
            };
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
        PromotionOutcome::Master
    }

    async fn acquire(&self, role: AcquisitionRole, origin: &str) -> AcquireOutcome {
        self.set_phase(PromotionPhase::Acquiring, None);
        let record = match self.backend.lease().await {
            Ok(record) => {
                self.lock().snapshot.witness_reachable = true;
                record
            }
            Err(error) => {
                self.lock().snapshot.witness_reachable = false;
                let reason = error.reason_code();
                self.set_phase(PromotionPhase::Unavailable, Some(reason));
                if self.role == ConfiguredRole::Master {
                    self.host.set_writable(false, Some(reason.to_string()));
                }
                return AcquireOutcome::Outcome(PromotionOutcome::ReadOnly {
                    reason: reason.to_string(),
                    retryable: error.is_retryable(),
                });
            }
        };

        let local = self.local_content(role);
        let decision = decide_acquisition(role, &local, record.as_ref(), &self.holder);
        match decision {
            AcquisitionDecision::ExistingGrant => {
                AcquireOutcome::Outcome(PromotionOutcome::ReadOnly {
                    reason: "lease_held_by_other".to_string(),
                    retryable: true,
                })
            }
            AcquisitionDecision::Refuse(refusal) => {
                let reason = match role {
                    AcquisitionRole::Candidate => refusal.code(),
                    AcquisitionRole::Master => refusal.master_code(),
                };
                self.set_phase(PromotionPhase::Aborted, Some(reason));
                if role == AcquisitionRole::Master {
                    self.host.set_writable(false, Some(reason.to_string()));
                }
                AcquireOutcome::Outcome(PromotionOutcome::ReadOnly {
                    reason: reason.to_string(),
                    retryable: false,
                })
            }
            AcquisitionDecision::Acquire(plan) => {
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
                let record = match self.backend.acquire(request).await {
                    Ok(record) => record,
                    Err(WitnessClientError::Conflict { .. }) => {
                        self.lock().last_acquire_conflict = true;
                        self.set_phase(
                            PromotionPhase::WaitingForMasterLoss,
                            Some("lease_held_by_other"),
                        );
                        return AcquireOutcome::Outcome(PromotionOutcome::ReadOnly {
                            reason: "lease_held_by_other".to_string(),
                            retryable: true,
                        });
                    }
                    Err(error) => {
                        let reason = error.reason_code();
                        self.set_phase(PromotionPhase::Unavailable, Some(reason));
                        if role == AcquisitionRole::Master {
                            self.host.set_writable(false, Some(reason.to_string()));
                        }
                        return AcquireOutcome::Outcome(PromotionOutcome::ReadOnly {
                            reason: reason.to_string(),
                            retryable: error.is_retryable(),
                        });
                    }
                };
                if record.holder != self.holder
                    || record.term != plan.term
                    || record.version != plan.baseline.version
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
                let boot_id = self.clock.boot_id().unwrap_or_default();
                let wall = self.clock.wall_unix_ms();
                let boot_now = self.clock.boot_millis().unwrap_or(0);
                let deadline = SelfFenceDeadline::arm(
                    boot_now,
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
                    inner.snapshot.witness_reachable = true;
                    inner.snapshot.promoted_at_unix_ms = Some(self.clock.wall_unix_ms());
                }
                AcquireOutcome::Acquired
            }
        }
    }

    fn local_content(&self, role: AcquisitionRole) -> LocalContent {
        let inner = self.lock();
        let pending_version = inner
            .loaded
            .as_ref()
            .map_or(0, |state| state.bundle.version);
        let state_term = inner.loaded.as_ref().map_or(0, |state| state.bundle.term);
        let bookkeeping = inner.bookkeeping.clone();
        drop(inner);

        match role {
            AcquisitionRole::Master => {
                let (last_version, last_hash) = bookkeeping.as_ref().map_or((0, None), |b| {
                    (
                        b.last_applied_version.unwrap_or(0),
                        b.last_applied_hash.clone(),
                    )
                });
                LocalContent {
                    pending_version,
                    ..LocalContent::master(state_term, bookkeeping, last_version, last_hash)
                }
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
                LocalContent {
                    pending_version,
                    ..LocalContent::candidate(
                        applied_term,
                        applied_version,
                        applied_hash,
                        bookkeeping,
                    )
                }
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
        let bookkeeping = PromotionBookkeeping {
            publication_state,
            published_version: plan.baseline.version,
            published_hash: plan.baseline.hash.clone(),
            pending_hash: Some(prepared.hash.clone()),
            promotion_origin: Some(origin.to_string()),
            lease_holder: Some(record.holder.clone()),
            cluster_id: Some(self.cluster_id.clone()),
            node_id: Some(self.node_id.clone()),
            promoted_at_unix_ms: Some(self.clock.wall_unix_ms()),
            last_applied_version: Some(local.applied_version),
            last_applied_hash: local.applied_hash.clone(),
        };
        bookkeeping.apply_to(&mut state);
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

    fn write_next_pending_state(
        &self,
        prepared: &PreparedBundle,
        term: u64,
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
            bookkeeping.pending_hash = Some(prepared.hash.clone());
            bookkeeping.promotion_origin = Some("restart".to_string());
            bookkeeping.promoted_at_unix_ms = Some(self.clock.wall_unix_ms());
            bookkeeping.apply_to(&mut state);
            inner.snapshot.version = prepared.bundle.version;
            inner.snapshot.bundle_hash.clone_from(&prepared.hash);
            inner.snapshot.publication_state = PublicationState::Pending;
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
            signing_key_pubkey: previous
                .as_ref()
                .and_then(|state| state.signing_key_pubkey.clone()),
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

    fn record_successful_renewal(&self, revision: u64) {
        let boot_id = self.clock.boot_id().unwrap_or_default();
        let wall = self.clock.wall_unix_ms();
        let boot_now = self.clock.boot_millis().unwrap_or(0);
        let mut inner = self.lock();
        if let Some(ref mut grant) = inner.grant {
            grant.revision = revision;
        }
        inner.deadline = Some(SelfFenceDeadline::arm(
            boot_now,
            boot_id,
            wall,
            self.config.lease_ttl_secs,
            self.config.renew_interval_secs,
        ));
        inner.last_wall_unix_ms = Some(wall);
        inner.snapshot.lease_revision = Some(revision);
        inner.snapshot.witness_reachable = true;
    }

    async fn renew_published(&self) -> Result<(), HaError> {
        let prepared = {
            let inner = self.lock();
            inner.pending.clone()
        };
        let Some(prepared) = prepared else {
            return Err(HaError::Validation {
                field: "ha.promotion".to_string(),
                reason: "no published bundle to renew".to_string(),
            });
        };
        {
            let mut inner = self.lock();
            if let Some(ref mut grant) = inner.grant {
                grant.baseline = PublicationBaseline {
                    version: prepared.bundle.version,
                    hash: prepared.hash.clone(),
                };
            }
        }
        self.renew_once().await.map(|_| ())
    }

    fn handle_renewal_action(&self, action: RenewalAction) -> Result<u64, HaError> {
        match action {
            RenewalAction::Continue { revision }
            | RenewalAction::AdoptRevision { revision }
            | RenewalAction::RetryHigherBaseline { revision } => {
                self.record_successful_renewal(revision);
                Ok(revision)
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
            inner.snapshot.reason = Some("fenced".to_string());
            inner.grant = None;
            inner.deadline = None;
        }
        warn!(
            node_id = %self.node_id,
            reason = reason.code(),
            detail,
            "HA promotion self-fenced; a restart stays read-only until an operator clears the marker"
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
