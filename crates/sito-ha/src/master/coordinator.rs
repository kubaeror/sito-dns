//! Master HA coordinator managing connected replica slaves and configuration push dissemination.

use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, error, info, warn};

use sito_stats::MetricsRegistry;

use crate::bundle::{ConfigBundle, build_and_sign_push};
use crate::config::HaConfig;
use crate::crypto::Ed25519SigningKey;
use crate::error::HaError;
use crate::master::tracker::{ActiveSlave, SlaveStatsSummary, SlaveSummary};
use crate::protocol::{AckConflict, HaMessage};
use crate::readiness::{HaReadiness, HaReadinessState};
use crate::transport::{MAX_WS_MESSAGE_SIZE, WS_SEND_TIMEOUT, build_server_tls_config, ws_config};

/// Maximum number of published envelopes kept for delayed ACK binding.
///
/// A slave may acknowledge a bundle after the master has published newer
/// ones, and multiple slaves may report a fork for the same envelope. The
/// history is coordinator-wide and pruned only by this bound, never by an
/// individual slave's ACK.
pub const MAX_PUBLISH_HISTORY: usize = 64;

/// Maximum bytes queued for one slave before the master falls back to
/// coalesced delivery.
///
/// The channel capacity alone bounds the number of queued pushes, not their
/// size: with 1 MiB bundles a slow peer could otherwise pin tens of MiB.
pub const MAX_SLAVE_QUEUE_BYTES: usize = MAX_WS_MESSAGE_SIZE * 4;

/// Maximum concurrently unauthenticated/active handshake slots per source IP.
const MAX_HANDSHAKES_PER_IP: usize = 8;

/// Identifies one slave session for queue accounting.
///
/// `instance` alone is not unique across reconnects: a superseded session can
/// still drain its channel after the replacement registered. Keying by the
/// connection id keeps the old session's bytes from being charged to (or
/// subtracted from) the new session.
type SessionKey = (String, u64);

/// Outcome of publishing a configuration bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// The bundle was persisted and queued for at least one connected slave.
    Published { version: u64, term: u64 },
    /// The bundle was persisted but no slave is currently connected.
    NoSlaves,
    /// The signed envelope exceeds the WebSocket message limit and was not
    /// persisted or broadcast.
    TooLarge { bytes: usize, limit: usize },
}

/// A published envelope retained for delayed ACK binding.
///
/// Entries are shared by all slaves and pruned only in publish order by
/// [`MAX_PUBLISH_HISTORY`]; an individual ACK must not remove an entry because
/// another slave may still report a fork for the same envelope.
#[derive(Debug, Clone)]
struct PublishedEnvelope {
    term: u64,
    version: u64,
    payload_hash: String,
}

/// On-disk master state.
///
/// `ConfigBundle` is flattened so files written by 1.9.3 (a bare bundle JSON
/// document) still deserialize. New writes add the signing-key identity; an
/// older reader ignores the unknown top-level field.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedMasterState {
    #[serde(flatten)]
    bundle: ConfigBundle,
    /// Hex Ed25519 public key that signed the persisted bundle/state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_key_pubkey: Option<String>,
}

/// Maximum amount by which an authenticated peer may report being ahead of the
/// master's sequence before the report is treated as implausible (and therefore
/// hostile or corrupt) instead of as promotion evidence.
///
/// A single replica must never be able to freeze publishing by reporting a
/// gigantic version: values above this bound are rejected without touching the
/// master's counter or persisted state.
pub const MAX_PEER_VERSION_LEAD: u64 = 1_000_000;

/// Outcome of a manual resynchronization request, surfaced honestly by the
/// `/ha/resync` API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResyncOutcome {
    /// Version of the replicated configuration bundle.
    pub version: u64,
    /// Whether an active bundle exists to re-push. When false the request was
    /// accepted but there is nothing to replicate yet.
    pub active_bundle: bool,
    /// Connected slaves for which a push was queued (or coalesced).
    pub slaves_notified: usize,
}

/// Test-only hook invoked inside the blocking state writer before the file is
/// written. It receives the version of the bundle being persisted so a test can
/// observe and slow down individual writes without affecting production builds.
#[cfg(test)]
type StateWriteHook = Arc<dyn Fn(u64) + Send + Sync>;

/// Severity of a recorded divergence. Ordered so a fork outranks a term
/// mismatch, which outranks a same-term version gap; `mark_diverged` never
/// downgrades an existing higher-severity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DivergenceKind {
    /// Same term, peer reports a version above the master.
    Ahead,
    /// Peer reports a newer term (this master is stale).
    Term,
    /// Same term and version but a different signed payload (fork).
    Fork,
}

/// A divergence observed for one connected slave.
#[derive(Debug, Clone)]
struct Divergence {
    kind: DivergenceKind,
    acked_version: u64,
    acked_term: u64,
    reason: String,
}

/// Per-IP accounting for accepted HA connections.
///
/// The global connection semaphore bounds total slots, but a single source
/// could still consume all of them before authenticating. This budget makes
/// the unauthenticated handshake/session surface per-IP as well.
#[derive(Debug, Default)]
struct HandshakeBudget {
    active: Mutex<HashMap<IpAddr, usize>>,
}

impl HandshakeBudget {
    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<HandshakePermit> {
        let mut active = self.active.lock().unwrap();
        let count = active.entry(ip).or_insert(0);
        if *count >= MAX_HANDSHAKES_PER_IP {
            return None;
        }
        *count += 1;
        Some(HandshakePermit {
            budget: Arc::clone(self),
            ip,
        })
    }
}

struct HandshakePermit {
    budget: Arc<HandshakeBudget>,
    ip: IpAddr,
}

impl Drop for HandshakePermit {
    fn drop(&mut self) {
        let mut active = self.budget.active.lock().unwrap();
        if let Some(count) = active.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(&self.ip);
            }
        }
    }
}

/// Master HA coordinator.
#[derive(Clone)]
pub struct MasterCoordinator {
    pub instance_name: String,
    pub signing_key: Arc<Ed25519SigningKey>,
    pub current_version: Arc<AtomicU64>,
    /// Cluster epoch/term. Bumped only by an explicit operator promotion
    /// (`with_term` or a restored `ha_state.toml`), never by peer input.
    pub current_term: Arc<AtomicU64>,
    pub active_bundle: Arc<Mutex<Option<ConfigBundle>>>,
    pub active_push: Arc<Mutex<Option<HaMessage>>>,
    pub slaves: Arc<Mutex<HashMap<String, ActiveSlave>>>,
    pub metrics: MetricsRegistry,
    pub slave_token: Option<String>,
    /// Heartbeat interval in seconds (watchdog removes slaves silent for 3× this).
    pub ping_interval_secs: u64,
    /// Path where the active version/bundle are persisted across restarts.
    state_path: Arc<Mutex<Option<PathBuf>>>,
    /// Slaves with an asynchronous fallback delivery already scheduled.
    pending_fallbacks: Arc<Mutex<HashSet<SessionKey>>>,
    /// Last stale version for which a catch-up push was already attempted per slave.
    stale_repushes: Arc<Mutex<HashMap<String, u64>>>,
    /// Serializes bundle publication so the version check and store cannot
    /// interleave and regress the active version.
    publish_lock: Arc<Mutex<()>>,
    /// Serializes asynchronous publication (including the state write) so two
    /// concurrent async publishers cannot complete their writes out of order.
    persist_lock: Arc<tokio::sync::Mutex<()>>,
    /// Monotonic id assigned to each accepted slave connection.
    next_connection_id: Arc<AtomicU64>,
    /// Test-only hook called by the asynchronous state writer.
    #[cfg(test)]
    state_write_hook: Arc<Mutex<Option<StateWriteHook>>>,
    /// Divergence records per currently connected slave. They are sticky: only
    /// that slave's applied ACK for the current term/version or a disconnect
    /// removes them, never an unrelated version advance or a global resync.
    diverged: Arc<Mutex<HashMap<String, Divergence>>>,
    /// Bounded, coordinator-wide history of published envelopes used to bind
    /// delayed ACKs (including forks reported by multiple slaves).
    active_push_history: Arc<Mutex<VecDeque<PublishedEnvelope>>>,
    /// Bytes currently queued per slave session.
    queued_bytes: Arc<Mutex<HashMap<SessionKey, usize>>>,
    /// Most recent publish failure, surfaced through HA readiness.
    last_publish_error: Arc<Mutex<Option<String>>>,
    /// True while a background publish retry is already scheduled.
    publish_retry_running: Arc<AtomicBool>,
    /// Whether the replication listener is actually serving. Updated by
    /// `spawn_master_server` and surfaced by `/ha/status` and `/health`.
    readiness: HaReadinessState,
}

impl MasterCoordinator {
    /// Creates a new MasterCoordinator.
    pub fn new(
        instance_name: String,
        initial_version: u64,
        signing_key: Arc<Ed25519SigningKey>,
        metrics: MetricsRegistry,
    ) -> Self {
        #[allow(clippy::cast_precision_loss)]
        {
            metrics.set_ha_config_version("local", initial_version as f64);
            metrics.set_ha_config_version(&instance_name, initial_version as f64);
        }
        metrics.set_ha_slaves_connected(0);

        Self {
            instance_name,
            signing_key,
            current_version: Arc::new(AtomicU64::new(initial_version)),
            current_term: Arc::new(AtomicU64::new(0)),
            active_bundle: Arc::new(Mutex::new(None)),
            active_push: Arc::new(Mutex::new(None)),
            slaves: Arc::new(Mutex::new(HashMap::new())),
            metrics,
            slave_token: None,
            ping_interval_secs: 15,
            state_path: Arc::new(Mutex::new(None)),
            pending_fallbacks: Arc::new(Mutex::new(HashSet::new())),
            stale_repushes: Arc::new(Mutex::new(HashMap::new())),
            publish_lock: Arc::new(Mutex::new(())),
            persist_lock: Arc::new(tokio::sync::Mutex::new(())),
            next_connection_id: Arc::new(AtomicU64::new(1)),
            #[cfg(test)]
            state_write_hook: Arc::new(Mutex::new(None)),
            diverged: Arc::new(Mutex::new(HashMap::new())),
            active_push_history: Arc::new(Mutex::new(VecDeque::new())),
            queued_bytes: Arc::new(Mutex::new(HashMap::new())),
            last_publish_error: Arc::new(Mutex::new(None)),
            publish_retry_running: Arc::new(AtomicBool::new(false)),
            readiness: HaReadinessState::not_ready("master replication listener has not started"),
        }
    }

    /// Current readiness of the master replication path.
    ///
    /// A running listener is not enough: a publish that failed to persist or
    /// broadcast must make the node unready until a later publish succeeds, so
    /// `/health` cannot stay green while slaves never receive the config.
    #[must_use]
    pub fn readiness(&self) -> HaReadiness {
        let listener = self.readiness.snapshot();
        if !listener.ready {
            return listener;
        }
        if let Some(error) = self.last_publish_error.lock().unwrap().clone() {
            return HaReadiness::not_ready(format!(
                "last HA configuration publish failed: {error}"
            ));
        }
        listener
    }

    fn set_publish_error(&self, error: Option<String>) {
        *self.last_publish_error.lock().unwrap() = error;
    }

    /// Records a publish failure detected before the bundle reaches the
    /// coordinator (read/serialize/sanitize/empty/secret-scan errors).
    ///
    /// Keeps HA readiness false so `/health` cannot stay green while the API
    /// cannot build a replicable bundle.
    pub fn mark_publish_failed(&self, reason: impl Into<String>) {
        self.set_publish_error(Some(reason.into()));
    }

    /// Starts a publish retry if one is not already running.
    ///
    /// Returns false when a retry task is already in flight so a burst of
    /// failed API applies cannot spawn an unbounded number of retry loops.
    pub fn begin_publish_retry(&self) -> bool {
        !self.publish_retry_running.swap(true, Ordering::SeqCst)
    }

    /// Marks the background publish retry as finished.
    pub fn end_publish_retry(&self) {
        self.publish_retry_running.store(false, Ordering::SeqCst);
    }

    /// Marks the replication listener as serving connections.
    pub fn mark_replication_ready(&self) {
        self.readiness.mark_ready();
    }

    /// Records a listener/TLS failure that prevents replication.
    pub fn mark_replication_failed(&self, reason: impl Into<String>) {
        self.readiness.mark_failed(reason);
    }

    /// Records an intentionally disabled listener (`replication_port = 0`).
    ///
    /// This is not a failure: the operator explicitly turned HA off. Keeping a
    /// reason makes the disabled state visible in `/ha/status`.
    pub fn mark_replication_disabled(&self) {
        self.readiness
            .mark_ready_with_reason("replication_port is 0 (replication disabled)");
    }

    /// Enables persistence of the active configuration version/bundle to `path`.
    #[must_use]
    pub fn with_state_path(mut self, path: PathBuf) -> Self {
        self.state_path = Arc::new(Mutex::new(Some(path)));
        self
    }

    /// Sets the cluster epoch/term for an explicit promotion.
    ///
    /// Normal nodes restore the term from `ha_state.toml`. This builder exists
    /// for an embedded/operator promotion path (and tests): every bundle
    /// published afterwards must carry this term. A stale master that has not
    /// been promoted this way can never overwrite a newer slave.
    #[must_use]
    pub fn with_term(self, term: u64) -> Self {
        self.current_term.store(term, Ordering::SeqCst);
        self
    }

    /// Installs a test-only hook invoked inside the blocking state writer.
    #[cfg(test)]
    #[must_use]
    fn with_state_write_hook(mut self, hook: StateWriteHook) -> Self {
        self.state_write_hook = Arc::new(Mutex::new(Some(hook)));
        self
    }

    /// Writes `payload` to `path` atomically (0600 temp file, fsync, rename).
    fn write_state_file(path: &std::path::Path, payload: &[u8]) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(payload)?;
            file.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            file.write_all(payload)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }

    /// Serializes `bundle` for the state file, if a state path exists.
    fn serialized_bundle(
        &self,
        bundle: &ConfigBundle,
    ) -> std::io::Result<Option<(PathBuf, Vec<u8>)>> {
        let path = self.state_path.lock().unwrap().clone();
        let Some(path) = path else {
            return Ok(None);
        };
        let state = PersistedMasterState {
            bundle: bundle.clone(),
            signing_key_pubkey: Some(self.signing_key.public_key_hex()),
        };
        let payload = serde_json::to_vec_pretty(&state).map_err(|e| {
            std::io::Error::other(format!("failed to serialize HA master state: {e}"))
        })?;
        Ok(Some((path, payload)))
    }

    /// Persists `bundle` synchronously.
    fn persist_bundle(&self, bundle: &ConfigBundle) -> std::io::Result<()> {
        if let Some((path, payload)) = self.serialized_bundle(bundle)? {
            Self::write_state_file(&path, &payload)?;
        }
        Ok(())
    }

    /// Persists `bundle` on the blocking pool.
    ///
    /// The caller thread only clones the path/payload; all filesystem work
    /// (directory creation, 0600 write, `sync_all`, rename) runs in
    /// `spawn_blocking` so a slow disk cannot stall a tokio worker.
    async fn persist_bundle_async(&self, bundle: &ConfigBundle) -> std::io::Result<()> {
        let Some((path, payload)) = self.serialized_bundle(bundle)? else {
            return Ok(());
        };
        #[cfg(test)]
        let version = bundle.version;
        #[cfg(test)]
        let hook = self.state_write_hook.lock().unwrap().clone();
        tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            if let Some(hook) = hook.as_ref() {
                hook(version);
            }
            Self::write_state_file(&path, &payload)
        })
        .await
        .map_err(|e| std::io::Error::other(format!("HA state writer task failed: {e}")))?
    }

    /// Restores the persisted version/bundle, if any.
    ///
    /// A corrupt state file is moved aside and treated as absent so a master
    /// never silently publishes a rollback; the sequence then restarts from a
    /// fresh v1 only when no state can be recovered.
    pub fn restore_state(&self) -> Result<Option<u64>, HaError> {
        let path = self.state_path.lock().unwrap().clone();
        let Some(path) = path else {
            return Ok(None);
        };
        let data = match std::fs::read_to_string(&path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(HaError::Validation {
                    field: "ha_state".to_string(),
                    reason: format!("Failed to read {}: {e}", path.display()),
                });
            }
        };
        let state: PersistedMasterState = match serde_json::from_str(&data) {
            Ok(state) => state,
            Err(e) => {
                let backup = path.with_extension(format!("corrupt.{}", Utc::now().timestamp()));
                if let Err(rename_err) = std::fs::rename(&path, &backup) {
                    warn!(error = %rename_err, "Failed to move corrupt HA state aside");
                }
                warn!(
                    error = %e,
                    backup = %backup.display(),
                    "Corrupt HA state detected; backing up and starting fresh"
                );
                return Ok(None);
            }
        };
        if let Some(expected) = state.signing_key_pubkey {
            let actual = self.signing_key.public_key_hex();
            if expected != actual {
                return Err(HaError::Validation {
                    field: "ha_signing_key".to_string(),
                    reason: format!(
                        "HA state at {} was written by signing key {expected}, but the loaded key is {actual}. ha_signing.key was lost or replaced. Restore the original key from backup, or delete the state file and re-enroll every slave with this master's new master_pubkey after an explicit higher-version promotion",
                        path.display()
                    ),
                });
            }
        }
        let bundle = state.bundle;
        if bundle.version == 0 {
            return Ok(None);
        }
        if bundle.version == u64::MAX {
            // A state file at the ceiling can never advance again. Treat it as
            // a hard error instead of silently resuming a frozen master; the
            // operator must restore a backup or re-seed the sequence.
            return Err(HaError::Validation {
                field: "version".to_string(),
                reason: format!(
                    "Persisted HA state at {} has version u64::MAX and can never advance; restore the state file from backup or re-seed an explicit version",
                    path.display()
                ),
            });
        }
        if bundle.term == u64::MAX {
            return Err(HaError::Validation {
                field: "term".to_string(),
                reason: format!(
                    "Persisted HA state at {} has term u64::MAX and can never advance; restore the state file from backup or re-seed an explicit term",
                    path.display()
                ),
            });
        }
        // State files written by older versions may still embed structured
        // client secrets; strip them before signing/broadcasting.
        let mut bundle = bundle;
        bundle.strip_structured_secrets();
        let push = build_and_sign_push(&bundle, &self.signing_key)?;
        Self::ensure_push_fits(&push)?;
        self.current_version.store(bundle.version, Ordering::SeqCst);
        self.current_term.store(bundle.term, Ordering::SeqCst);
        *self.active_bundle.lock().unwrap() = Some(bundle.clone());
        *self.active_push.lock().unwrap() = Some(push.clone());
        self.record_published_envelope(&push);
        // Upgrade a legacy state file with the signing-key identity so a
        // future key loss is detectable. A write failure here is actionable:
        // silently continuing would keep the key-loss blind spot.
        self.persist_bundle(&bundle)?;
        #[allow(clippy::cast_precision_loss)]
        {
            self.metrics
                .set_ha_config_version("local", bundle.version as f64);
            self.metrics
                .set_ha_config_version(&self.instance_name, bundle.version as f64);
        }
        info!(
            version = bundle.version,
            "Restored persisted HA master state"
        );
        Ok(Some(bundle.version))
    }

    /// Sets the heartbeat ping interval (used for the liveness watchdog).
    #[must_use]
    pub fn with_ping_interval_secs(mut self, secs: u64) -> Self {
        self.ping_interval_secs = secs.max(1);
        self
    }

    /// Sets the required slave authentication token.
    #[must_use]
    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.slave_token = token;
        self
    }

    /// Returns the currently active master configuration version.
    pub fn get_current_version(&self) -> u64 {
        self.current_version.load(Ordering::SeqCst)
    }

    /// Returns the current cluster epoch/term.
    pub fn get_current_term(&self) -> u64 {
        self.current_term.load(Ordering::SeqCst)
    }

    /// Returns true when any divergence (version gap, stale term, or fork) is
    /// currently latched.
    pub fn is_diverged(&self) -> bool {
        !self.diverged.lock().unwrap().is_empty()
    }

    /// Returns the most severe recorded divergence reason, if any.
    pub fn diverged_reason(&self) -> Option<String> {
        self.diverged
            .lock()
            .unwrap()
            .values()
            .max_by_key(|d| (d.kind, d.acked_version, d.acked_term))
            .map(|d| d.reason.clone())
    }

    /// Records a divergence for one instance, keeping the most severe kind and
    /// version that instance reported.
    ///
    /// Records are deliberately sticky: nothing here is cleared by an
    /// unrelated version advance or by another slave's success. Only that
    /// slave's applied ACK for the master's current term/version, an explicit
    /// disconnect, or an explicit operator promotion clears them.
    fn mark_diverged(
        &self,
        kind: DivergenceKind,
        instance: &str,
        acked_version: u64,
        acked_term: u64,
        reason: String,
    ) {
        let mut diverged = self.diverged.lock().unwrap();
        if diverged
            .get(instance)
            .is_none_or(|d| (kind, acked_version) >= (d.kind, d.acked_version))
        {
            diverged.insert(
                instance.to_string(),
                Divergence {
                    kind,
                    acked_version,
                    acked_term,
                    reason,
                },
            );
            self.metrics.set_ha_diverged(instance, true);
        }
    }

    /// Clears one instance's divergence record after it successfully applied
    /// the master's current bundle/term.
    ///
    /// Divergence is per-slave and clearing it is per-slave: an operator
    /// resync only re-pushes the bundle and never clears another slave's
    /// advisory record before that slave proves recovery by ACKing the current
    /// term/version.
    fn clear_divergence_for(&self, instance: &str) {
        let slaves = self.slaves.lock().unwrap();
        let mut diverged = self.diverged.lock().unwrap();
        if diverged.remove(instance).is_some() && slaves.contains_key(instance) {
            self.metrics.set_ha_diverged(instance, false);
        }
    }

    /// Validates monotonicity, sanitizes and signs `bundle` without publishing
    /// it. Returns the prepared bundle, version, push message and the version
    /// that was current at validation time. The caller must hold
    /// [`Self::publish_lock`].
    fn prepare_bundle(
        &self,
        bundle: ConfigBundle,
    ) -> Result<(ConfigBundle, u64, HaMessage, u64), HaError> {
        // Secret material must never be stored, persisted or signed: the
        // structured `clients` value is sanitized exactly like `config_toml`.
        let mut bundle = bundle;
        bundle.strip_structured_secrets();

        let version = bundle.version;
        let current = self.current_version.load(Ordering::SeqCst);
        if version <= current {
            return Err(HaError::Validation {
                field: "version".to_string(),
                reason: format!(
                    "Refusing to publish non-monotonic configuration version {version} (current {current})"
                ),
            });
        }
        if version == u64::MAX {
            return Err(HaError::Validation {
                field: "version".to_string(),
                reason: "Refusing to publish configuration version u64::MAX: the sequence could never advance again"
                    .to_string(),
            });
        }
        let current_term = self.get_current_term();
        if bundle.term != current_term {
            return Err(HaError::Validation {
                field: "term".to_string(),
                reason: format!(
                    "Refusing to publish bundle term {} while the master is at term {current_term}; term changes are an explicit promotion",
                    bundle.term
                ),
            });
        }
        if bundle.term == u64::MAX {
            return Err(HaError::Validation {
                field: "term".to_string(),
                reason: "Refusing to publish term u64::MAX: the epoch could never advance again"
                    .to_string(),
            });
        }

        let push_msg = build_and_sign_push(&bundle, &self.signing_key)?;
        Self::ensure_push_fits(&push_msg)?;
        Ok((bundle, version, push_msg, current))
    }

    /// Rejects a signed envelope that cannot fit the WebSocket message limit
    /// before it is persisted or broadcast. An oversized bundle must be an
    /// apply error, not a config that every slave rejects forever.
    fn ensure_push_fits(push: &HaMessage) -> Result<(), HaError> {
        let bytes = push.to_json()?.len();
        if bytes > MAX_WS_MESSAGE_SIZE {
            return Err(HaError::BundleTooLarge {
                bytes,
                limit: MAX_WS_MESSAGE_SIZE,
            });
        }
        Ok(())
    }

    /// Records a published envelope in the bounded ACK-binding history.
    fn record_published_envelope(&self, push: &HaMessage) {
        let HaMessage::ConfigPush {
            term,
            version,
            payload_hash_blake3,
            ..
        } = push
        else {
            return;
        };
        let mut history = self.active_push_history.lock().unwrap();
        history.push_back(PublishedEnvelope {
            term: *term,
            version: *version,
            payload_hash: payload_hash_blake3
                .trim_start_matches("blake3:")
                .to_string(),
        });
        while history.len() > MAX_PUBLISH_HISTORY {
            history.pop_front();
        }
    }

    /// Publishes a prepared bundle. The caller must hold
    /// [`Self::publish_lock`] and have persisted the bundle first.
    fn publish_prepared(&self, bundle: ConfigBundle, version: u64, push_msg: &HaMessage) {
        self.current_version.store(version, Ordering::SeqCst);
        *self.active_bundle.lock().unwrap() = Some(bundle);
        *self.active_push.lock().unwrap() = Some(push_msg.clone());
        self.record_published_envelope(push_msg);
    }

    /// Publishes the active configuration version to the HA metrics.
    fn record_published_version(&self, version: u64) {
        #[allow(clippy::cast_precision_loss)]
        {
            self.metrics.set_ha_config_version("local", version as f64);
            self.metrics
                .set_ha_config_version(&self.instance_name, version as f64);
        }
    }

    /// Sets and signs a new configuration bundle, immediately broadcasting it to all connected slaves.
    ///
    /// This synchronous variant is startup/test-only: `init_ha` publishes the
    /// initial bundle before the async replication loop starts. It does not take
    /// [`Self::persist_lock`], so it must not race [`Self::update_bundle_async`]
    /// in production, otherwise a sync write landing during an async
    /// conflict-restore could overwrite the newer state file.
    pub fn update_bundle(&self, bundle: ConfigBundle) -> Result<u64, HaError> {
        let result = self.update_bundle_inner(bundle);
        self.record_publish_result(&result);
        result
    }

    fn update_bundle_inner(&self, bundle: ConfigBundle) -> Result<u64, HaError> {
        // Serialize the check-then-store: two concurrent publishers could
        // otherwise both pass the monotonicity check and store out of order,
        // regressing the active version and broadcasting a stale bundle.
        let _publish_guard = self
            .publish_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (bundle, version, push_msg, _previous) = self.prepare_bundle(bundle)?;
        // Persist before publishing: a failed write must leave both the
        // in-memory active bundle/push and the version sequence untouched.
        self.persist_bundle(&bundle)?;
        self.publish_prepared(bundle, version, &push_msg);
        self.record_published_version(version);

        // Broadcast to all active slaves
        self.broadcast(&push_msg);

        info!(
            version,
            "Master updated configuration bundle and broadcasted push to connected slaves"
        );

        Ok(version)
    }

    fn record_publish_result<T>(&self, result: &Result<T, HaError>) {
        match result {
            Ok(_) => self.set_publish_error(None),
            Err(HaError::BundleTooLarge { bytes, limit }) => self.set_publish_error(Some(format!(
                "bundle would be {bytes} bytes, above the {limit}-byte replication limit"
            ))),
            Err(e) => self.set_publish_error(Some(e.to_string())),
        }
    }

    /// Async variant of [`Self::update_bundle`] that persists state on the
    /// blocking pool.
    ///
    /// `persist_lock` serializes the whole publish-and-write sequence so two
    /// concurrent async publishers cannot complete their state writes out of
    /// order. The standard `publish_lock` is only held for the in-memory
    /// check/store/sign step and is dropped before awaiting the disk write.
    pub async fn update_bundle_async(&self, bundle: ConfigBundle) -> Result<u64, HaError> {
        let result = self.update_bundle_async_inner(bundle).await;
        self.record_publish_result(&result);
        result.map(|(version, _)| version)
    }

    /// Publishes a bundle and reports the observable outcome.
    ///
    /// This is the variant API/config callers use: a `TooLarge` outcome is not
    /// a transport error, it is a configuration that cannot be replicated and
    /// must be treated as an apply error by the caller. Publication failures
    /// are also recorded in HA readiness.
    pub async fn publish_bundle_async(
        &self,
        bundle: ConfigBundle,
    ) -> Result<PublishOutcome, HaError> {
        match self.update_bundle_async_inner(bundle).await {
            Ok((version, notified)) => {
                self.set_publish_error(None);
                if notified == 0 {
                    Ok(PublishOutcome::NoSlaves)
                } else {
                    Ok(PublishOutcome::Published {
                        version,
                        term: self.get_current_term(),
                    })
                }
            }
            Err(HaError::BundleTooLarge { bytes, limit }) => {
                self.set_publish_error(Some(format!(
                    "bundle would be {bytes} bytes, above the {limit}-byte replication limit"
                )));
                Ok(PublishOutcome::TooLarge { bytes, limit })
            }
            Err(e) => {
                self.set_publish_error(Some(e.to_string()));
                Err(e)
            }
        }
    }

    async fn update_bundle_async_inner(
        &self,
        bundle: ConfigBundle,
    ) -> Result<(u64, usize), HaError> {
        let _persist_guard = self.persist_lock.lock().await;

        let (bundle, version, push_msg, previous_version) = {
            let _publish_guard = self
                .publish_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.prepare_bundle(bundle)?
        };

        // Persist the prepared document first. Until this succeeds nothing is
        // visible through `active_push`/`current_version`, so a newly
        // connecting slave can never receive a bundle the master did not
        // durably publish.
        if let Err(e) = self.persist_bundle_async(&bundle).await {
            error!(error = %e, "Failed to persist HA master state");
            return Err(HaError::Io(e));
        }

        let conflict = {
            let _publish_guard = self
                .publish_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // A synchronous publisher may have advanced the sequence while the
            // write was in flight. Publishing our older prepared version would
            // regress the cluster, so report the conflict and restore the
            // now-active bundle instead. Only detect and clone under the
            // standard lock: it must never be held across the awaited write.
            if self.current_version.load(Ordering::SeqCst) == previous_version {
                self.publish_prepared(bundle, version, &push_msg);
                None
            } else {
                Some(self.active_bundle.lock().unwrap().clone())
            }
        };

        if let Some(active) = conflict {
            // `persist_lock` is still held, so no async publisher can interleave
            // with this restore. The write runs on the blocking pool: a
            // synchronous `std::fs` write here would stall a tokio worker.
            if let Some(active) = active
                && let Err(e) = self.persist_bundle_async(&active).await
            {
                error!(error = %e, "Failed to restore HA master state after a concurrent publish");
            }
            return Err(HaError::Validation {
                field: "version".to_string(),
                reason: format!(
                    "Concurrent publish advanced the HA configuration version above {version}"
                ),
            });
        }

        self.record_published_version(version);

        // Broadcast to all active slaves
        let notified = self.broadcast(&push_msg);

        info!(
            version,
            "Master updated configuration bundle and broadcasted push to connected slaves"
        );

        Ok((version, notified))
    }

    /// Broadcasts a message to all connected slaves.
    ///
    /// Returns the number of slaves for which delivery was queued (a full
    /// queue with a coalesced fallback task counts as queued).
    pub fn broadcast(&self, msg: &HaMessage) -> usize {
        let wire_size = msg.to_json().map_or(0, |json| json.len());
        let mut notified = 0;
        let slaves = self.slaves.lock().unwrap();
        let mut queued = self.queued_bytes.lock().unwrap();
        for slave in slaves.values() {
            let instance = &slave.instance;
            let session = (instance.clone(), slave.connection_id);
            let current = queued.get(&session).copied().unwrap_or(0);
            if wire_size > 0 && current.saturating_add(wire_size) > MAX_SLAVE_QUEUE_BYTES {
                // The per-slave byte budget is exhausted even though the
                // message-count channel may still have room: coalesce instead
                // of letting a slow peer pin tens of MiB of bundles.
                warn!(
                    instance = %instance,
                    queued_bytes = current,
                    message_bytes = wire_size,
                    limit = MAX_SLAVE_QUEUE_BYTES,
                    "HA push byte budget exhausted; scheduling coalesced delivery"
                );
                self.schedule_coalesced_delivery(instance, slave.connection_id, &slave.sender, msg);
                notified += 1;
                continue;
            }
            match slave.sender.try_send(msg.clone()) {
                Ok(()) => {
                    if wire_size > 0 {
                        *queued.entry(session).or_insert(0) += wire_size;
                    }
                    notified += 1;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Queue is full: do not silently drop the update. Coalesce
                    // fallback deliveries per slave so a slow or stalled replica
                    // cannot spawn unbounded tasks; the task sends the latest
                    // active bundle when the channel has room.
                    self.schedule_coalesced_delivery(
                        instance,
                        slave.connection_id,
                        &slave.sender,
                        msg,
                    );
                    // The push will be delivered by the coalesced fallback
                    // task (either this one or one already pending).
                    notified += 1;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    debug!(instance = %slave.instance, "HA push channel closed");
                }
            }
        }
        notified
    }

    /// Queues `msg` for one slave session and records its wire size in the
    /// per-session byte budget when the queue accepted it.
    ///
    /// Every non-broadcast send path (initial push, resync, catch-up repush)
    /// must go through this helper so the coalesced-delivery budget reflects
    /// all bytes queued for a slave, not only broadcast traffic. The caller
    /// passes the precomputed `wire_size` so the budget decision and the send
    /// use the same value.
    ///
    /// An over-budget send is refused before touching the channel; callers may
    /// coalesce it instead of growing the queue.
    fn try_queue_accounted(
        &self,
        instance: &str,
        connection_id: u64,
        sender: &mpsc::Sender<HaMessage>,
        wire_size: usize,
        msg: HaMessage,
    ) -> Result<(), String> {
        let session = (instance.to_string(), connection_id);
        // Hold the accounting lock across the budget check, `try_send` and the
        // increment: the session loop subtracts under the same lock, and
        // releasing it in between would let the subtract observe the old value
        // and turn the later increment into phantom bytes.
        let mut queued = self.queued_bytes.lock().unwrap();
        // Registration installs the session key and reconnect removes every
        // old key for the instance. A missing key therefore means this sender
        // belongs to a superseded session: refuse instead of recreating
        // accounting for a channel nobody will drain.
        let Some(current) = queued.get(&session).copied() else {
            return Err("slave session is no longer active".to_string());
        };
        if wire_size > 0 && current.saturating_add(wire_size) > MAX_SLAVE_QUEUE_BYTES {
            return Err(format!(
                "per-slave queue byte budget exhausted ({current} + {wire_size} > {MAX_SLAVE_QUEUE_BYTES})"
            ));
        }
        sender.try_send(msg).map_err(|e| e.to_string())?;
        if wire_size > 0 {
            *queued.entry(session).or_insert(0) += wire_size;
        }
        Ok(())
    }

    /// Removes `wire_size` from one session's queued-byte accounting.
    ///
    /// Keying by `(instance, connection_id)` ensures a superseded session that
    /// drains its old channel after a reconnect cannot subtract from the
    /// replacement session's budget.
    fn account_drained(&self, instance: &str, connection_id: u64, wire_size: usize) {
        if wire_size == 0 {
            return;
        }
        let mut queued = self.queued_bytes.lock().unwrap();
        if let Some(current) = queued.get_mut(&(instance.to_string(), connection_id)) {
            *current = current.saturating_sub(wire_size);
        }
    }

    /// Schedules at most one coalesced delivery task per slave session.
    ///
    /// The task captures the session's `connection_id` and re-checks ownership
    /// before waiting, delivering, or charging bytes. A superseded task must
    /// never charge the replacement session, and it must stop waiting on the
    /// old session's budget.
    fn schedule_coalesced_delivery(
        &self,
        instance: &str,
        connection_id: u64,
        sender: &mpsc::Sender<HaMessage>,
        fallback_msg: &HaMessage,
    ) {
        let instance = instance.to_string();
        let session = (instance.clone(), connection_id);
        let first_schedule = self
            .pending_fallbacks
            .lock()
            .unwrap()
            .insert(session.clone());
        if !first_schedule {
            debug!(
                instance = %instance,
                connection_id,
                "HA fallback delivery already pending; coalescing push"
            );
            return;
        }
        let coordinator = self.clone();
        let sender = sender.clone();
        let fallback = fallback_msg.clone();
        tokio::spawn(async move {
            // Prefer the latest active bundle; fall back to the message that
            // could not be enqueued.
            let latest = coordinator
                .active_push
                .lock()
                .unwrap()
                .clone()
                .or(Some(fallback));
            if let Some(latest) = latest {
                let size = latest.to_json().map_or(0, |json| json.len());
                // Wait only while this exact session still owns the active
                // entry. After a reconnect the old task must not wait on,
                // deliver to, or charge the replacement session.
                //
                // The bytes are reserved *before* the awaited send: the
                // session loop can receive and subtract as soon as the send
                // completes, so accounting after the await would race and
                // leave phantom bytes.
                let mut reserved = false;
                loop {
                    let (owns, has_room) = {
                        let slaves = coordinator.slaves.lock().unwrap();
                        let owns = slaves
                            .get(&instance)
                            .is_some_and(|s| s.connection_id == connection_id);
                        if owns {
                            let mut queued = coordinator.queued_bytes.lock().unwrap();
                            let current = queued.get(&session).copied().unwrap_or(0);
                            if size == 0 || current.saturating_add(size) <= MAX_SLAVE_QUEUE_BYTES {
                                if size > 0 {
                                    *queued.entry(session.clone()).or_insert(0) += size;
                                }
                                (true, true)
                            } else {
                                (true, false)
                            }
                        } else {
                            (false, false)
                        }
                    };
                    if !owns {
                        break;
                    }
                    if has_room {
                        reserved = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                if reserved && let Err(e) = sender.send(latest).await {
                    // The send failed, so release the reservation. The key may
                    // already be gone if a reconnect superseded this session.
                    if size > 0 {
                        let mut queued = coordinator.queued_bytes.lock().unwrap();
                        if let Some(current) = queued.get_mut(&session) {
                            *current = current.saturating_sub(size);
                        }
                    }
                    warn!(instance = %instance, "Failed to deliver queued HA push: {e}");
                }
            }
            coordinator
                .pending_fallbacks
                .lock()
                .unwrap()
                .remove(&session);
        });
    }

    /// Re-pushes the active bundle to one slave that acknowledged a stale
    /// version, at most once per acknowledged version to avoid retry loops.
    fn maybe_repush(&self, instance: &str, stale_version: u64) {
        let mut repushed = self.stale_repushes.lock().unwrap();
        if repushed.get(instance) == Some(&stale_version) {
            return;
        }
        repushed.insert(instance.to_string(), stale_version);
        drop(repushed);

        if let Some(push) = self.active_push.lock().unwrap().clone() {
            let target = {
                let slaves = self.slaves.lock().unwrap();
                slaves
                    .get(instance)
                    .map(|slave| (slave.sender.clone(), slave.connection_id))
            };
            if let Some((sender, connection_id)) = target {
                let wire_size = push.to_json().map_or(0, |json| json.len());
                if let Err(e) = self.try_queue_accounted(
                    instance,
                    connection_id,
                    &sender,
                    wire_size,
                    push.clone(),
                ) {
                    warn!(
                        instance = %instance,
                        error = %e,
                        "Catch-up push could not be queued; coalescing"
                    );
                    self.schedule_coalesced_delivery(instance, connection_id, &sender, &push);
                }
            }
        }
    }

    /// Triggers a re-push of the current active configuration bundle to all slaves.
    ///
    /// This is the explicit operator recovery action. It does **not** clear any
    /// divergence record: H-10 requires the record to clear only after that
    /// specific slave ACKs the current term/version, because a queued re-push
    /// is not proof that the slave recovered.
    pub fn trigger_resync(&self) -> ResyncOutcome {
        let push_opt = self.active_push.lock().unwrap().clone();
        let slaves_notified = match push_opt {
            Some(ref push) => self.broadcast(push),
            None => 0,
        };
        ResyncOutcome {
            version: self.get_current_version(),
            active_bundle: push_opt.is_some(),
            slaves_notified,
        }
    }

    /// Returns a list of summaries for all currently connected replica slaves.
    pub fn list_slaves(&self) -> Vec<SlaveSummary> {
        let cur_v = self.get_current_version();
        let slaves = self.slaves.lock().unwrap();
        let diverged = self.diverged.lock().unwrap();
        slaves
            .values()
            .map(|s| s.to_summary(cur_v, diverged.contains_key(&s.instance)))
            .collect()
    }

    /// Returns the count of currently connected slaves.
    pub fn connected_slave_count(&self) -> usize {
        self.slaves.lock().unwrap().len()
    }

    /// Handles a new incoming WebSocket connection from a replica slave.
    pub async fn handle_connection<S>(
        &self,
        mut ws_stream: tokio_tungstenite::WebSocketStream<S>,
        peer_addr: SocketAddr,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        info!(peer = %peer_addr, "Accepted incoming HA replica connection; waiting for Hello");

        // Step 1: Wait for Hello message with timeout
        let hello_msg = match tokio::time::timeout(Duration::from_secs(10), ws_stream.next()).await
        {
            Ok(Some(Ok(WsMessage::Text(txt)))) => match HaMessage::from_json(&txt) {
                Ok(HaMessage::Hello {
                    instance,
                    have_version,
                    have_term,
                    capabilities,
                    token,
                    role,
                    protocol_version,
                }) => (
                    instance,
                    have_version,
                    have_term,
                    capabilities,
                    token,
                    role,
                    protocol_version,
                ),
                Ok(other) => {
                    warn!(peer = %peer_addr, "Unexpected message instead of Hello: {other:?}");
                    return;
                }
                Err(e) => {
                    warn!(peer = %peer_addr, "Invalid Hello message JSON: {e}");
                    return;
                }
            },
            Ok(Some(Ok(WsMessage::Binary(bin)))) => {
                if let Ok(txt) = std::str::from_utf8(&bin) {
                    match HaMessage::from_json(txt) {
                        Ok(HaMessage::Hello {
                            instance,
                            have_version,
                            have_term,
                            capabilities,
                            token,
                            role,
                            protocol_version,
                        }) => (
                            instance,
                            have_version,
                            have_term,
                            capabilities,
                            token,
                            role,
                            protocol_version,
                        ),
                        _ => return,
                    }
                } else {
                    return;
                }
            }
            _ => {
                warn!(peer = %peer_addr, "Timed out or connection closed before Hello received");
                return;
            }
        };

        let (slave_instance, have_version, have_term, capabilities, token, role, protocol_version) =
            hello_msg;

        // Protocol version negotiation
        if let Some(version) = protocol_version
            && version != crate::protocol::PROTOCOL_VERSION
        {
            warn!(
                instance = %slave_instance,
                peer = %peer_addr,
                version,
                expected = crate::protocol::PROTOCOL_VERSION,
                "Rejecting slave with incompatible HA protocol version"
            );
            return;
        }

        // Role validation: only replica slaves may connect.
        match role.as_deref() {
            Some("slave") => {}
            Some(other) => {
                warn!(
                    instance = %slave_instance,
                    peer = %peer_addr,
                    role = %other,
                    "Rejecting HA connection with non-slave role"
                );
                return;
            }
            None => {
                warn!(
                    instance = %slave_instance,
                    peer = %peer_addr,
                    "Legacy Hello without role field; assuming slave for backwards compatibility"
                );
            }
        }

        // Verify slave authentication token if configured (constant-time compare)
        if let Some(ref required_token) = self.slave_token {
            let provided = token.as_deref().unwrap_or("");
            let tokens_match = provided.len() == required_token.len()
                && bool::from(provided.as_bytes().ct_eq(required_token.as_bytes()));
            if !tokens_match {
                warn!(
                    instance = %slave_instance,
                    peer = %peer_addr,
                    "Slave authentication failed: invalid or missing token"
                );
                return;
            }
        }

        info!(
            instance = %slave_instance,
            have_version,
            peer = %peer_addr,
            "Received authenticated Hello from replica slave"
        );

        // Reject implausible peer versions before they can influence the local
        // sequence. An authenticated replica reporting `u64::MAX` (or any
        // value far beyond the master's counter) would otherwise seed the
        // version and make every subsequent publish non-monotonic, freezing
        // replication.
        let current = self.get_current_version();
        if have_version > current.saturating_add(MAX_PEER_VERSION_LEAD) {
            error!(
                instance = %slave_instance,
                peer = %peer_addr,
                have_version,
                current,
                max_lead = MAX_PEER_VERSION_LEAD,
                "Rejecting Hello with an implausible have_version"
            );
            return;
        }

        // Term/version continuity is checked, never repaired automatically from
        // peer input. A replica that is ahead in the same term (lost/corrupt
        // `ha_state.toml`, forked master) or in a newer term (this master is
        // stale) must not cause the master to adopt its counter and republish
        // its own possibly-stale bundle. Instead surface the divergence and
        // require an explicit promotion/resync.
        let current = self.get_current_version();
        let current_term = self.get_current_term();
        if have_term > current_term {
            let reason = format!(
                "slave '{slave_instance}' reports term {have_term} above the master's term {current_term}: this master is stale and must not overwrite the cluster"
            );
            error!(
                instance = %slave_instance,
                peer = %peer_addr,
                have_term,
                current_term,
                "{reason}"
            );
            self.mark_diverged(
                DivergenceKind::Term,
                &slave_instance,
                have_version,
                have_term,
                reason,
            );
        }
        if have_term == current_term && have_version > current {
            let reason = format!(
                "slave '{slave_instance}' reports version {have_version} above the master's version {current} in term {current_term}: version continuity is broken (promoted slave or lost/corrupt ha_state.toml); explicit promotion is required"
            );
            error!(
                instance = %slave_instance,
                peer = %peer_addr,
                have_version,
                current,
                current_term,
                "{reason}"
            );
            self.mark_diverged(
                DivergenceKind::Ahead,
                &slave_instance,
                have_version,
                current_term,
                reason,
            );
        }

        let (tx, mut rx) = mpsc::channel::<HaMessage>(32);
        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);

        // Register slave in tracking map. A reconnecting instance replaces the
        // previous entry; `connection_id` lets the superseded session detect
        // that it no longer owns the entry.
        {
            let mut slaves = self.slaves.lock().unwrap();
            // A reconnecting instance starts with an empty queue; accounting
            // from every superseded session must not leak into the new one.
            // Keys include the connection id, so drop every key for this
            // instance and install the new session's zero baseline.
            {
                let mut queued = self.queued_bytes.lock().unwrap();
                queued.retain(|(instance, _), _| instance != &slave_instance);
                queued.insert((slave_instance.clone(), connection_id), 0);
            }
            slaves.insert(
                slave_instance.clone(),
                ActiveSlave {
                    instance: slave_instance.clone(),
                    remote_addr: peer_addr,
                    // Never trust the peer's Hello claim for the *reported*
                    // synced version: only an applied ACK proves it.
                    synced_version: 0,
                    last_ping: Instant::now(),
                    connected_at: Utc::now(),
                    last_stats: None,
                    sender: tx.clone(),
                    capabilities: capabilities.clone(),
                    connection_id,
                },
            );
            #[allow(clippy::cast_possible_wrap)]
            self.metrics.set_ha_slaves_connected(slaves.len() as i64);
            self.metrics.set_ha_config_version(&slave_instance, 0.0);
        }

        // Always enqueue the current push on connect; a slave that is already
        // up to date acknowledges without re-applying. This avoids trusting the
        // client-reported `have_version`, which an inflated value could use to
        // suppress replication.
        if let Some(ref push) = *self.active_push.lock().unwrap() {
            let cur_v = self.get_current_version();
            info!(
                instance = %slave_instance,
                have_version,
                cur_v,
                "Pushing current configuration bundle to newly connected slave"
            );
            let wire_size = push.to_json().map_or(0, |json| json.len());
            if let Err(e) = self.try_queue_accounted(
                &slave_instance,
                connection_id,
                &tx,
                wire_size,
                push.clone(),
            ) {
                warn!(instance = %slave_instance, error = %e, "Initial HA push could not be queued; coalescing");
                self.schedule_coalesced_delivery(&slave_instance, connection_id, &tx, push);
            }
        }

        // Heartbeat ping interval (watchdog closes sessions silent for 3× this)
        let ping_secs = self.ping_interval_secs.max(1);
        let mut ping_interval = tokio::time::interval(Duration::from_secs(ping_secs));
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Session loop
        loop {
            tokio::select! {
                // Outgoing messages queued for this slave
                Some(msg) = rx.recv() => {
                    let wire_size = msg.to_json().map_or(0, |json| json.len());
                    self.account_drained(&slave_instance, connection_id, wire_size);
                    if send_master_message(&mut ws_stream, &msg, "configuration push").await.is_err() {
                        break;
                    }
                }

                // Periodic ping + liveness watchdog
                _ = ping_interval.tick() => {
                    let (superseded, stale) = {
                        let slaves = self.slaves.lock().unwrap();
                        match slaves.get(&slave_instance) {
                            Some(s) if s.connection_id == connection_id => (
                                false,
                                s.last_ping.elapsed()
                                    > Duration::from_secs(ping_secs.saturating_mul(3)),
                            ),
                            // Replaced by a newer connection (or removed):
                            // this session must stop acting on the entry.
                            _ => (true, false),
                        }
                    };
                    if superseded {
                        debug!(
                            instance = %slave_instance,
                            "HA session superseded by a newer connection; closing"
                        );
                        break;
                    }
                    if stale {
                        warn!(
                            instance = %slave_instance,
                            "HA slave heartbeat timed out; closing replication session"
                        );
                        break;
                    }
                    #[allow(clippy::cast_sign_loss)]
                    let ts = Utc::now().timestamp_millis() as u64;
                    let ping = HaMessage::Ping { ts };
                    if send_master_message(&mut ws_stream, &ping, "heartbeat ping").await.is_err() {
                        break;
                    }
                }

                // Incoming messages from slave
                msg_opt = ws_stream.next() => {
                    match msg_opt {
                        Some(Ok(WsMessage::Text(txt))) => {
                            if !self.process_slave_msg(&slave_instance, connection_id, &txt) {
                                break;
                            }
                        }
                        Some(Ok(WsMessage::Binary(bin))) => {
                            if let Ok(txt) = std::str::from_utf8(&bin)
                                && !self.process_slave_msg(&slave_instance, connection_id, txt) {
                                    break;
                                }
                        }
                        Some(Ok(WsMessage::Pong(_))) => {
                            let mut slaves = self.slaves.lock().unwrap();
                            if let Some(s) = slaves.get_mut(&slave_instance)
                                && s.connection_id == connection_id
                            {
                                s.last_ping = Instant::now();
                            }
                        }
                        Some(Ok(WsMessage::Close(_))) | None => {
                            info!(instance = %slave_instance, "Replica slave disconnected");
                            break;
                        }
                        Some(Err(e)) => {
                            warn!(instance = %slave_instance, "WebSocket receive error: {e}");
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        // Cleanup disconnected slave. Only remove the entry when this session
        // still owns it: a slow teardown of an old connection must not evict
        // the reconnected slave's live entry or its metric label.
        if self.unregister_session(&slave_instance, connection_id) {
            self.metrics.remove_ha_config_version(&slave_instance);
            info!(instance = %slave_instance, "Unregistered replica slave from active tracker");
        } else {
            debug!(
                instance = %slave_instance,
                "Superseded HA session ended; live entry left untouched"
            );
        }
    }

    /// Removes the tracked slave entry if it still belongs to `connection_id`.
    ///
    /// Returns true when this session owned the entry (and removed it); false
    /// when a newer connection has replaced it, in which case the live entry is
    /// left untouched.
    fn unregister_session(&self, instance: &str, connection_id: u64) -> bool {
        let mut slaves = self.slaves.lock().unwrap();
        let owned = slaves
            .get(instance)
            .is_some_and(|s| s.connection_id == connection_id);
        if owned {
            slaves.remove(instance);
            // Drop the per-slave catch-up and divergence bookkeeping with the
            // session so neither map nor its metric label can grow across
            // reconnects.
            self.stale_repushes.lock().unwrap().remove(instance);
            self.diverged.lock().unwrap().remove(instance);
            self.queued_bytes
                .lock()
                .unwrap()
                .remove(&(instance.to_string(), connection_id));
            self.metrics.remove_ha_diverged(instance);
        }
        #[allow(clippy::cast_possible_wrap)]
        self.metrics.set_ha_slaves_connected(slaves.len() as i64);
        owned
    }

    /// Returns the payload hash of a still-retained published envelope.
    fn published_envelope_hash(&self, term: u64, version: u64) -> Option<String> {
        self.active_push_history
            .lock()
            .unwrap()
            .iter()
            .find(|envelope| envelope.term == term && envelope.version == version)
            .map(|envelope| envelope.payload_hash.clone())
    }

    fn process_slave_msg(&self, slave_instance: &str, connection_id: u64, text: &str) -> bool {
        let msg = match HaMessage::from_json(text) {
            Ok(m) => m,
            Err(e) => {
                warn!(instance = %slave_instance, "Failed to parse incoming message: {e}");
                return true;
            }
        };

        match msg {
            HaMessage::Ack {
                version,
                term,
                applied,
                conflict,
                error,
            } => {
                // Ignore acknowledgements from a superseded connection: the
                // entry now belongs to a newer session.
                let owned = {
                    let slaves = self.slaves.lock().unwrap();
                    slaves
                        .get(slave_instance)
                        .is_some_and(|s| s.connection_id == connection_id)
                };
                if !owned {
                    return true;
                }

                let current = self.get_current_version();
                let current_term = self.get_current_term();
                if version > current.saturating_add(MAX_PEER_VERSION_LEAD) {
                    // Never use an implausible peer-driven version as a seed,
                    // a rebase input, or a persisted value. A single replica
                    // must not be able to freeze publishing with `u64::MAX`.
                    // This applies to `applied:false` ACKs too: a forged
                    // rejection must not carry an unbounded version.
                    error!(
                        instance = %slave_instance,
                        acked_version = version,
                        current,
                        max_lead = MAX_PEER_VERSION_LEAD,
                        applied,
                        "Ignoring ACK with an implausible version"
                    );
                    return true;
                }

                if term > current_term {
                    // The replica knows a newer epoch: this master is stale.
                    // Adopting the peer's counter would let a partitioned old
                    // master overwrite newer configuration, so only surface the
                    // divergence and require an explicit promotion.
                    let reason = format!(
                        "slave '{slave_instance}' acknowledged term {term} above the master's term {current_term}: this master is stale and must not overwrite the cluster"
                    );
                    error!(
                        instance = %slave_instance,
                        acked_version = version,
                        acked_term = term,
                        current,
                        current_term,
                        "{reason}"
                    );
                    self.mark_diverged(DivergenceKind::Term, slave_instance, version, term, reason);
                    return true;
                }

                if !applied {
                    if conflict == Some(AckConflict::SameVersionFork) {
                        // Only a push the master actually sent can prove a
                        // fork. The bounded published-envelope history keeps
                        // recently superseded bundles, so an ACK that arrives
                        // after a newer publish is still attributed correctly.
                        // Without this binding an authenticated replica could
                        // latch a fabricated fork for any version.
                        let Some(published_hash) = self.published_envelope_hash(term, version)
                        else {
                            warn!(
                                instance = %slave_instance,
                                acked_version = version,
                                acked_term = term,
                                current,
                                current_term,
                                "Ignoring same-version fork ACK without a matching published envelope"
                            );
                            return true;
                        };
                        // Same term and version but different content: this is
                        // the fork signal. Record it so the slave is reported
                        // unsynced and can never silently "win" the fork; this
                        // does not stop publishing to other replicas.
                        let reason = format!(
                            "slave '{slave_instance}' rejected term {term} version {version} with a same-version payload-hash fork (published envelope {published_hash}): resolve the fork or promote the slave"
                        );
                        error!(
                            instance = %slave_instance,
                            acked_version = version,
                            acked_term = term,
                            current_term,
                            "{reason}"
                        );
                        self.mark_diverged(
                            DivergenceKind::Fork,
                            slave_instance,
                            version,
                            term,
                            reason,
                        );
                        if let Some(slave) = self.slaves.lock().unwrap().get_mut(slave_instance)
                            && slave.connection_id == connection_id
                        {
                            slave.synced_version = 0;
                        }
                    }
                    warn!(
                        instance = %slave_instance,
                        version,
                        term,
                        conflict = ?conflict,
                        error = ?error,
                        "Slave failed to apply configuration bundle"
                    );
                    return true;
                }

                if term < current_term {
                    // Our epoch is newer; the replica is stale even if its
                    // old-epoch version counter is higher. Re-push the active
                    // bundle of the current term so it adopts the promotion.
                    warn!(
                        instance = %slave_instance,
                        acked_version = version,
                        acked_term = term,
                        current_term,
                        "Slave acknowledged an older term; re-pushing the current-term active bundle"
                    );
                    self.maybe_repush(slave_instance, version);
                } else if version == current {
                    info!(
                        instance = %slave_instance,
                        version,
                        term,
                        "Slave successfully applied configuration bundle"
                    );
                    let mut slaves = self.slaves.lock().unwrap();
                    if let Some(s) = slaves.get_mut(slave_instance)
                        && s.connection_id == connection_id
                    {
                        s.synced_version = version;
                    } else {
                        // An older connection acknowledging after its entry was
                        // replaced must not update the live session.
                        return true;
                    }
                    drop(slaves);
                    #[allow(clippy::cast_precision_loss)]
                    self.metrics
                        .set_ha_config_version(slave_instance, version as f64);
                    self.stale_repushes.lock().unwrap().remove(slave_instance);
                    // This slave has accepted the current term/version, so any
                    // divergence record for it (fork, ahead, newer-term) is now
                    // resolved. Other slaves' records are untouched: H-10
                    // clears divergence per acknowledging slave.
                    self.clear_divergence_for(slave_instance);
                } else if version < current {
                    warn!(
                        instance = %slave_instance,
                        acked_version = version,
                        current,
                        "Slave acknowledged a stale configuration version; re-pushing the active bundle"
                    );
                    self.maybe_repush(slave_instance, version);
                } else {
                    // Same term but a version above the master's means version
                    // continuity is broken (promoted slave, restored from an
                    // older state file, or forked master). Do not auto-rebase:
                    // that would let this stale master overwrite newer slaves.
                    let reason = format!(
                        "slave '{slave_instance}' acknowledged version {version} above the master's current version {current} in term {current_term}: version continuity is broken (promoted slave or lost/corrupt ha_state.toml); explicit promotion is required"
                    );
                    error!(
                        instance = %slave_instance,
                        acked_version = version,
                        current,
                        current_term,
                        "{reason}"
                    );
                    self.mark_diverged(
                        DivergenceKind::Ahead,
                        slave_instance,
                        version,
                        current_term,
                        reason,
                    );
                }
            }
            HaMessage::StatsReport {
                window_s,
                queries,
                blocked,
                upstreams,
            } => {
                let upstreams_count = upstreams.len();
                let mut slaves = self.slaves.lock().unwrap();
                let Some(s) = slaves.get_mut(slave_instance) else {
                    return true;
                };
                if s.connection_id != connection_id {
                    return true;
                }
                if !s.capabilities.iter().any(|c| c == "stats-v1") {
                    warn!(
                        instance = %slave_instance,
                        "Ignoring StatsReport from slave that did not advertise the 'stats-v1' capability"
                    );
                    return true;
                }
                s.last_stats = Some(SlaveStatsSummary {
                    window_s,
                    queries,
                    blocked,
                    upstreams_count,
                });
            }
            HaMessage::Pong { .. } => {
                let mut slaves = self.slaves.lock().unwrap();
                if let Some(s) = slaves.get_mut(slave_instance)
                    && s.connection_id == connection_id
                {
                    s.last_ping = Instant::now();
                }
            }
            HaMessage::Hello { .. } => {
                // Resync requested: always re-push the active bundle; the slave
                // acknowledges without re-applying when it is already current.
                if let Some(ref push) = *self.active_push.lock().unwrap() {
                    let sender = {
                        let slaves = self.slaves.lock().unwrap();
                        slaves
                            .get(slave_instance)
                            .filter(|s| s.connection_id == connection_id)
                            .map(|s| s.sender.clone())
                    };
                    if let Some(sender) = sender {
                        let wire_size = push.to_json().map_or(0, |json| json.len());
                        if let Err(e) = self.try_queue_accounted(
                            slave_instance,
                            connection_id,
                            &sender,
                            wire_size,
                            push.clone(),
                        ) {
                            warn!(
                                instance = %slave_instance,
                                error = %e,
                                "Resync push could not be queued; coalescing"
                            );
                            self.schedule_coalesced_delivery(
                                slave_instance,
                                connection_id,
                                &sender,
                                push,
                            );
                        }
                    }
                }
            }
            _ => {}
        }

        true
    }
}

/// Sends one HA message to a replica with a hard write deadline.
///
/// A peer that stops reading must not pin the session task (or its queue)
/// forever; the caller closes the session on timeout.
async fn send_master_message<S>(
    ws_stream: &mut tokio_tungstenite::WebSocketStream<S>,
    message: &HaMessage,
    context: &str,
) -> Result<(), HaError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let json = message.to_json()?;
    timeout(
        WS_SEND_TIMEOUT,
        ws_stream.send(WsMessage::Text(json.into())),
    )
    .await
    .map_err(|_| {
        HaError::Timeout(format!(
            "HA master {context} send timed out after {WS_SEND_TIMEOUT:?}"
        ))
    })?
    .map_err(|e| HaError::Connection(format!("Failed to send {context}: {e}")))
}

/// Maximum concurrently accepted slave connections (handshake + session).
const MAX_SLAVE_CONNECTIONS: usize = 64;
/// Upper bound on the TLS handshake and WebSocket upgrade of a slave
/// connection; a slowloris peer must not pin a task or socket indefinitely.
const MASTER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Spawns the master WebSocket replication server listener.
pub fn spawn_master_server(
    ha_config: HaConfig,
    mut coordinator: MasterCoordinator,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    if coordinator.slave_token.is_none() {
        coordinator.slave_token.clone_from(&ha_config.slave_token);
    }
    coordinator = coordinator.with_ping_interval_secs(ha_config.ping_interval_secs);
    tokio::spawn(async move {
        if ha_config.replication_port == 0 {
            // The startup no-op metric is recorded by the production call site
            // (`init_ha`); incrementing it here would double count when both
            // paths run, and this function is not called for port 0 there.
            coordinator.mark_replication_disabled();
            info!("Master HA replication is disabled (replication_port is 0)");
            return;
        }

        // mTLS setup or explicit insecure plaintext check
        let tls_acceptor = if let (Some(cert_path), Some(key_path)) =
            (&ha_config.cert, &ha_config.key)
        {
            match build_server_tls_config(
                cert_path,
                key_path,
                &ha_config.pinned_slave_fingerprints,
                ha_config.ca.as_deref(),
            ) {
                Ok(cfg) => Some(TlsAcceptor::from(cfg)),
                Err(e) => {
                    coordinator
                        .metrics
                        .inc_ha_startup_noop("master", "tls_init_failed");
                    coordinator
                        .mark_replication_failed(format!("master mTLS initialization failed: {e}"));
                    error!("Failed to initialize mTLS for master HA replication server: {e}");
                    return;
                }
            }
        } else {
            if !ha_config.allow_insecure_ws {
                coordinator.mark_replication_failed(
                    "master replication refused to serve plaintext without allow_insecure_ws",
                );
                error!(
                    "Master HA replication requires TLS (cert and key configured) unless allow_insecure_ws is true. Refusing to serve plaintext replication."
                );
                return;
            }
            None
        };

        let listen_addr = format!("{}:{}", ha_config.listen_addr, ha_config.replication_port);
        let listener = match TcpListener::bind(&listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                coordinator
                    .metrics
                    .inc_ha_startup_noop("master", "bind_failed");
                coordinator.mark_replication_failed(format!(
                    "Failed to bind master replication listener on '{listen_addr}': {e}"
                ));
                error!("Failed to bind master HA replication listener on '{listen_addr}': {e}");
                return;
            }
        };

        coordinator.mark_replication_ready();
        info!(addr = %listen_addr, "Master HA replication listener active");

        let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_SLAVE_CONNECTIONS));
        let handshake_budget = Arc::new(HandshakeBudget::default());

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Shutting down master HA replication listener");
                        break;
                    }
                }

                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((tcp_stream, peer_addr)) => {
                            let Ok(permit) = connection_semaphore.clone().try_acquire_owned() else {
                                warn!(
                                    peer = %peer_addr,
                                    "HA slave connection limit ({MAX_SLAVE_CONNECTIONS}) reached; rejecting"
                                );
                                continue;
                            };
                            let Some(handshake_permit) = handshake_budget.try_acquire(peer_addr.ip()) else {
                                warn!(
                                    peer = %peer_addr,
                                    limit = MAX_HANDSHAKES_PER_IP,
                                    "HA per-IP connection/handshake limit reached; rejecting"
                                );
                                continue;
                            };
                            let coord = coordinator.clone();
                            let acceptor_opt = tls_acceptor.clone();

                            tokio::spawn(async move {
                                let _permit = permit;
                                let _handshake_permit = handshake_permit;
                                let upgrade = async {
                                    if let Some(acceptor) = acceptor_opt {
                                        let tls_stream = timeout(
                                            MASTER_HANDSHAKE_TIMEOUT,
                                            acceptor.accept(tcp_stream),
                                        )
                                        .await
                                        .map_err(|_| "mTLS handshake timed out".to_string())?
                                        .map_err(|e| format!("mTLS handshake rejected: {e}"))?;
                                        let ws_stream = timeout(
                                            MASTER_HANDSHAKE_TIMEOUT,
                                            tokio_tungstenite::accept_async_with_config(
                                                tls_stream,
                                                Some(ws_config()),
                                            ),
                                        )
                                        .await
                                        .map_err(|_| "WebSocket upgrade timed out".to_string())?
                                        .map_err(|e| format!("WebSocket upgrade failed: {e}"))?;
                                        coord.handle_connection(ws_stream, peer_addr).await;
                                    } else {
                                        let ws_stream = timeout(
                                            MASTER_HANDSHAKE_TIMEOUT,
                                            tokio_tungstenite::accept_async_with_config(
                                                tcp_stream,
                                                Some(ws_config()),
                                            ),
                                        )
                                        .await
                                        .map_err(|_| "WebSocket upgrade timed out".to_string())?
                                        .map_err(|e| format!("Plain WebSocket upgrade failed: {e}"))?;
                                        coord.handle_connection(ws_stream, peer_addr).await;
                                    }
                                    Ok::<(), String>(())
                                };
                                if let Err(e) = upgrade.await {
                                    warn!(peer = %peer_addr, "{e}");
                                }
                            });
                        }
                        Err(e) => {
                            warn!("Accept error on master HA replication listener: {e}");
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master::tracker::ActiveSlave;

    fn test_coordinator() -> MasterCoordinator {
        let key = Arc::new(Ed25519SigningKey::generate().unwrap());
        MasterCoordinator::new(
            "test-master".to_string(),
            1,
            key,
            sito_stats::MetricsRegistry::new("test", "test"),
        )
    }

    fn test_bundle(version: u64) -> ConfigBundle {
        ConfigBundle {
            version,
            term: 0,
            timestamp: 1,
            config_toml: "config_version = 2\n[server]\nrole = \"slave\"\n".to_string(),
            custom_rules: vec![],
            rewrites: None,
            clients: None,
            lists: vec![],
        }
    }

    #[test]
    fn test_update_bundle_rejects_non_monotonic_versions() {
        let coordinator = test_coordinator();
        assert_eq!(coordinator.update_bundle(test_bundle(2)).unwrap(), 2);

        // Equal and lower versions must be rejected.
        assert!(coordinator.update_bundle(test_bundle(2)).is_err());
        assert!(coordinator.update_bundle(test_bundle(1)).is_err());
        assert_eq!(coordinator.get_current_version(), 2);

        assert_eq!(coordinator.update_bundle(test_bundle(3)).unwrap(), 3);
    }

    #[test]
    fn test_concurrent_update_bundle_never_regresses_version() {
        use std::sync::Arc as StdArc;

        let coordinator = StdArc::new(test_coordinator());
        let first = StdArc::clone(&coordinator);
        let second = StdArc::clone(&coordinator);

        // Versions 2 and 3 race: the lock must prevent 3 from being stored
        // and then overwritten by 2 (or vice versa).
        let t1 = std::thread::spawn(move || first.update_bundle(test_bundle(2)));
        let t2 = std::thread::spawn(move || second.update_bundle(test_bundle(3)));
        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();

        let final_version = coordinator.get_current_version();
        assert!(
            final_version == 2 || final_version == 3,
            "unexpected final version {final_version}"
        );
        let active = coordinator
            .active_bundle
            .lock()
            .unwrap()
            .clone()
            .expect("active bundle");
        assert_eq!(
            active.version, final_version,
            "active bundle must match the published version"
        );
        // Any successful publish must not exceed the final version.
        for version in [r1, r2].into_iter().flatten() {
            assert!(version <= final_version);
        }
    }

    #[test]
    fn test_state_persists_and_restores_across_restart() {
        let dir = std::env::temp_dir().join(format!("sito_ha_state_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state_path = dir.join("ha_state.toml");
        let key = Arc::new(Ed25519SigningKey::generate().unwrap());

        let first = MasterCoordinator::new(
            "test-master".to_string(),
            0,
            key.clone(),
            sito_stats::MetricsRegistry::new("test", "test"),
        )
        .with_state_path(state_path.clone());
        assert_eq!(first.restore_state().unwrap(), None);
        assert_eq!(first.update_bundle(test_bundle(1)).unwrap(), 1);
        assert_eq!(first.update_bundle(test_bundle(2)).unwrap(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&state_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "persisted HA state must remain owner-only");
        }

        // Simulate a restart: the same signing key and state path must resume
        // at v2 instead of resetting to v1 (which slaves reject as a rollback).
        let second = MasterCoordinator::new(
            "test-master".to_string(),
            0,
            key,
            sito_stats::MetricsRegistry::new("test", "test"),
        )
        .with_state_path(state_path.clone());
        assert_eq!(second.restore_state().unwrap(), Some(2));
        assert_eq!(second.get_current_version(), 2);
        assert!(second.update_bundle(test_bundle(2)).is_err());
        assert_eq!(second.update_bundle(test_bundle(3)).unwrap(), 3);

        // Corrupt state is moved aside and treated as absent.
        std::fs::write(&state_path, "not-json").unwrap();
        let third = MasterCoordinator::new(
            "test-master".to_string(),
            0,
            Arc::new(Ed25519SigningKey::generate().unwrap()),
            sito_stats::MetricsRegistry::new("test", "test"),
        )
        .with_state_path(state_path.clone());
        assert_eq!(third.restore_state().unwrap(), None);
        let corrupt_backups: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("ha_state.corrupt.")
            })
            .collect();
        assert_eq!(
            corrupt_backups.len(),
            1,
            "corrupt state must be moved aside instead of deleted"
        );
        assert_eq!(third.update_bundle(test_bundle(1)).unwrap(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_restore_preserves_term_and_legacy_state_defaults_to_zero() {
        let dir = std::env::temp_dir().join(format!(
            "sito_ha_term_state_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let state_path = dir.join("ha_state.toml");
        let key = Arc::new(Ed25519SigningKey::generate().unwrap());

        let mut promoted = test_bundle(5);
        promoted.term = 2;
        std::fs::write(&state_path, serde_json::to_vec(&promoted).unwrap()).unwrap();
        let restored = MasterCoordinator::new(
            "test-master".to_string(),
            0,
            key.clone(),
            sito_stats::MetricsRegistry::new("test", "test"),
        )
        .with_state_path(state_path.clone());
        assert_eq!(restored.restore_state().unwrap(), Some(5));
        assert_eq!(restored.get_current_term(), 2);

        // State written before terms existed has no `term` field and must load
        // as epoch 0.
        let legacy = r#"{"version":6,"timestamp":1,"config_toml":"config_version = 2\n[server]\nrole = \"slave\"\n","custom_rules":[],"lists":[]}"#;
        std::fs::write(&state_path, legacy).unwrap();
        let legacy_restored = MasterCoordinator::new(
            "test-master".to_string(),
            0,
            key,
            sito_stats::MetricsRegistry::new("test", "test"),
        )
        .with_state_path(state_path.clone());
        assert_eq!(legacy_restored.restore_state().unwrap(), Some(6));
        assert_eq!(legacy_restored.get_current_term(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_async_persist_roundtrip_and_permissions() {
        let dir = std::env::temp_dir().join(format!(
            "sito_ha_async_state_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let state_path = dir.join("ha_state.toml");
        let key = Arc::new(Ed25519SigningKey::generate().unwrap());
        let coordinator = MasterCoordinator::new(
            "test-master".to_string(),
            1,
            key.clone(),
            sito_stats::MetricsRegistry::new("test", "test"),
        )
        .with_state_path(state_path.clone());

        assert_eq!(
            coordinator
                .update_bundle_async(test_bundle(4))
                .await
                .unwrap(),
            4
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&state_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "async state writes must stay owner-only");
        }
        assert!(
            !state_path.with_extension("tmp").exists(),
            "the temporary file must be renamed away"
        );

        // The same signing key must restore the persisted state. Using a new
        // key must fail closed with an actionable error (H-08).
        let wrong = test_coordinator().with_state_path(state_path.clone());
        let err = wrong
            .restore_state()
            .expect_err("a replaced signing key must not silently re-sign persisted state");
        assert!(
            err.to_string()
                .contains("ha_signing.key was lost or replaced"),
            "the key-loss error must be actionable: {err}"
        );

        let restored = MasterCoordinator::new(
            "test-master".to_string(),
            1,
            key,
            sito_stats::MetricsRegistry::new("test", "test"),
        )
        .with_state_path(state_path);
        assert_eq!(restored.restore_state().unwrap(), Some(4));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// On a current-thread runtime a synchronous state write would starve the
    /// ticker; `spawn_blocking` keeps the runtime responsive.
    #[tokio::test]
    async fn test_state_write_does_not_block_runtime() {
        let dir = std::env::temp_dir().join(format!(
            "sito_ha_nonblocking_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let coordinator = test_coordinator()
            .with_state_path(dir.join("ha_state.toml"))
            .with_state_write_hook(Arc::new(|_version| {
                // Simulate a slow disk inside the blocking-pool writer instead
                // of using an unreplicable multi-MiB bundle (which publish must
                // now reject before persisting).
                std::thread::sleep(Duration::from_millis(200));
            }));

        let ticks = Arc::new(AtomicU64::new(0));
        let ticker_ticks = ticks.clone();
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1)).await;
                ticker_ticks.fetch_add(1, Ordering::Relaxed);
            }
        });
        // Let the ticker start before measuring.
        tokio::task::yield_now().await;
        let before = ticks.load(Ordering::Relaxed);

        coordinator
            .update_bundle_async(test_bundle(2))
            .await
            .unwrap();
        let after = ticks.load(Ordering::Relaxed);

        ticker.abort();
        assert!(
            after > before,
            "the tokio runtime must keep ticking while HA state is written (before={before}, after={after})"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Forces the conflict branch and asserts the state write restoring the
    /// concurrent publisher's active bundle runs on the blocking pool: on a
    /// current-thread runtime a synchronous write would starve the ticker.
    #[tokio::test(flavor = "current_thread")]
    async fn test_conflict_restore_uses_blocking_pool() {
        let dir = std::env::temp_dir().join(format!(
            "sito_ha_conflict_blocking_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let ticks = Arc::new(AtomicU64::new(0));
        let ticker_ticks = ticks.clone();
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1)).await;
                ticker_ticks.fetch_add(1, Ordering::Relaxed);
            }
        });

        // Track each async state write and how far the ticker advanced while
        // the conflict-restore write ran (the second write).
        let writes = Arc::new(AtomicU64::new(0));
        let restore_ticks = Arc::new(AtomicU64::new(0));
        let written_versions = Arc::new(Mutex::new(Vec::new()));
        let first_write_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook = {
            let ticks = ticks.clone();
            let writes = writes.clone();
            let restore_ticks = restore_ticks.clone();
            let written_versions = written_versions.clone();
            let first_write_started = first_write_started.clone();
            Arc::new(move |version: u64| {
                let write_index = writes.fetch_add(1, Ordering::SeqCst) + 1;
                written_versions.lock().unwrap().push(version);
                if write_index == 1 {
                    first_write_started.store(true, Ordering::SeqCst);
                }
                let start = ticks.load(Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(150));
                if write_index == 2 {
                    let end = ticks.load(Ordering::Relaxed);
                    restore_ticks.store(end.saturating_sub(start), Ordering::SeqCst);
                }
            })
        };

        let coordinator = test_coordinator()
            .with_state_path(dir.join("ha_state.toml"))
            .with_state_write_hook(hook);

        // Advance the sequence synchronously while the stale publisher's first
        // write is in flight: this forces the conflict-restore branch.
        let sync_coordinator = coordinator.clone();
        let started = first_write_started.clone();
        let sync_advance = tokio::spawn(async move {
            while !started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
            sync_coordinator.update_bundle(test_bundle(3)).unwrap();
        });

        let err = coordinator
            .update_bundle_async(test_bundle(2))
            .await
            .expect_err("the stale async publish must report a conflict");
        assert!(
            matches!(err, HaError::Validation { .. }),
            "expected a version conflict, got {err:?}"
        );
        sync_advance.await.unwrap();

        assert_eq!(
            *written_versions.lock().unwrap(),
            vec![2, 3],
            "both the stale write and the conflict restore must use the async writer"
        );
        assert!(
            restore_ticks.load(Ordering::SeqCst) > 0,
            "the tokio runtime must keep ticking while the conflict restore writes state"
        );

        ticker.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The conflict restore must leave the concurrently published active bundle
    /// (not the stale prepared one) on disk.
    #[tokio::test(flavor = "current_thread")]
    async fn test_conflict_restore_persists_active_bundle() {
        let dir = std::env::temp_dir().join(format!(
            "sito_ha_conflict_persist_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let state_path = dir.join("ha_state.toml");

        let first_write_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook = {
            let started = first_write_started.clone();
            Arc::new(move |_version: u64| {
                started.store(true, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(100));
            })
        };
        let coordinator = test_coordinator()
            .with_state_path(state_path.clone())
            .with_state_write_hook(hook);

        let sync_coordinator = coordinator.clone();
        let started = first_write_started.clone();
        let sync_advance = tokio::spawn(async move {
            while !started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
            sync_coordinator.update_bundle(test_bundle(3)).unwrap();
        });

        let err = coordinator
            .update_bundle_async(test_bundle(2))
            .await
            .expect_err("the stale async publish must report a conflict");
        assert!(
            matches!(err, HaError::Validation { .. }),
            "expected a version conflict, got {err:?}"
        );
        sync_advance.await.unwrap();

        assert_eq!(
            coordinator.get_current_version(),
            3,
            "the concurrent publish must not regress"
        );
        let active = coordinator
            .active_bundle
            .lock()
            .unwrap()
            .clone()
            .expect("active bundle");
        assert_eq!(active.version, 3);
        let persisted: ConfigBundle =
            serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
        assert_eq!(
            persisted, active,
            "the restored state file must contain the active bundle"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_persist_failure_propagates() {
        let dir = std::env::temp_dir().join(format!(
            "sito_ha_persist_fail_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let coordinator = test_coordinator().with_state_path(dir.join("ha_state.toml"));
        // Establish a previous good publish so "unchanged" is meaningful.
        coordinator.update_bundle(test_bundle(2)).unwrap();
        let before_version = coordinator.get_current_version();
        let before_bundle = coordinator
            .active_bundle
            .lock()
            .unwrap()
            .clone()
            .expect("previous active bundle");
        let before_push = coordinator
            .active_push
            .lock()
            .unwrap()
            .clone()
            .expect("previous active push");
        let before_push_version = match before_push {
            HaMessage::ConfigPush { version, .. } => version,
            other => panic!("expected a ConfigPush, got {other:?}"),
        };

        // A regular file where the state directory should be makes every
        // create_dir_all/write attempt fail deterministically.
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"blocked").unwrap();
        *coordinator.state_path.lock().unwrap() = Some(blocker.join("ha_state.toml"));

        let err = coordinator
            .update_bundle_async(test_bundle(3))
            .await
            .expect_err("a failed state write must not be reported as success");
        assert!(
            matches!(err, HaError::Io(_)),
            "expected an I/O error, got {err:?}"
        );
        assert_eq!(
            coordinator.get_current_version(),
            before_version,
            "a failed persist must not advance the published version"
        );
        assert_eq!(
            *coordinator.active_bundle.lock().unwrap(),
            Some(before_bundle),
            "a failed persist must leave the previously active bundle in place"
        );
        let after_push = coordinator
            .active_push
            .lock()
            .unwrap()
            .clone()
            .expect("active push must remain");
        let after_push_version = match after_push {
            HaMessage::ConfigPush { version, .. } => version,
            other => panic!("expected a ConfigPush, got {other:?}"),
        };
        assert_eq!(
            after_push_version, before_push_version,
            "a failed persist must not replace the active push"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// I5: `init_ha` owns the `replication_disabled` no-op counter. The spawned
    /// listener must not double count it when `init_ha` already recorded it.
    #[tokio::test]
    async fn test_master_replication_disabled_is_not_double_counted() {
        let coordinator = test_coordinator();
        let metrics = coordinator.metrics.clone();
        metrics.inc_ha_startup_noop("master", "replication_disabled");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = spawn_master_server(
            HaConfig {
                replication_port: 0,
                ..Default::default()
            },
            coordinator,
            shutdown_rx,
        );
        handle.await.unwrap();

        let rendered = metrics.render_prometheus();
        assert!(
            rendered.contains(
                r#"sito_ha_startup_noop_total{role="master",reason="replication_disabled"} 1"#
            ),
            "the disabled listener must stay observable without double counting: {rendered}"
        );
        assert!(
            !rendered.contains(
                r#"sito_ha_startup_noop_total{role="master",reason="replication_disabled"} 2"#
            ),
            "spawn_master_server must not increment the startup no-op again"
        );
        let _ = shutdown_tx.send(true);
    }

    #[tokio::test]
    async fn test_master_bind_failure_records_startup_noop() {
        // Keep the probe listener bound so the master cannot bind the port.
        let port_lease = sito_test_support::reserve_port().unwrap();
        let port = port_lease.port();
        let coordinator = test_coordinator();
        let metrics = coordinator.metrics.clone();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = spawn_master_server(
            HaConfig {
                replication_port: port,
                listen_addr: "127.0.0.1".to_string(),
                allow_insecure_ws: true,
                slave_token: Some("tok".to_string()),
                ..Default::default()
            },
            coordinator,
            shutdown_rx,
        );
        handle.await.unwrap();

        let rendered = metrics.render_prometheus();
        assert!(
            rendered
                .contains(r#"sito_ha_startup_noop_total{role="master",reason="bind_failed"} 1"#),
            "a listener bind failure must be observable: {rendered}"
        );
        drop(port_lease);
    }

    #[tokio::test]
    async fn test_master_tls_init_failure_records_startup_noop() {
        let coordinator = test_coordinator();
        let observer = coordinator.clone();
        let metrics = coordinator.metrics.clone();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = spawn_master_server(
            HaConfig {
                replication_port: 1,
                listen_addr: "127.0.0.1".to_string(),
                cert: Some(PathBuf::from("/nonexistent/sito-master.crt")),
                key: Some(PathBuf::from("/nonexistent/sito-master.key")),
                pinned_slave_fingerprints: vec!["blake3:deadbeef".to_string()],
                ..Default::default()
            },
            coordinator,
            shutdown_rx,
        );
        handle.await.unwrap();

        let rendered = metrics.render_prometheus();
        assert!(
            rendered.contains(
                r#"sito_ha_startup_noop_total{role="master",reason="tls_init_failed"} 1"#
            ),
            "a TLS init failure must be observable: {rendered}"
        );

        // The operator-facing readiness signal must carry the same failure:
        // DNS health alone used to hide a master that never started replication.
        let readiness = observer.readiness();
        assert!(!readiness.ready, "TLS failure must leave HA not ready");
        let reason = readiness.reason.unwrap_or_default();
        assert!(
            reason.contains("mTLS"),
            "readiness must name the TLS failure: {reason}"
        );
    }

    #[tokio::test]
    async fn test_master_listener_bind_marks_readiness_ready() {
        let coordinator = test_coordinator();
        let observer = coordinator.clone();
        let port = sito_test_support::reserve_port_number().unwrap();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = spawn_master_server(
            HaConfig {
                replication_port: port,
                listen_addr: "127.0.0.1".to_string(),
                allow_insecure_ws: true,
                slave_token: Some("tok".to_string()),
                ..Default::default()
            },
            coordinator,
            shutdown_rx,
        );

        let mut readiness = observer.readiness();
        for _ in 0..50 {
            if readiness.ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            readiness = observer.readiness();
        }
        assert!(
            readiness.ready,
            "a bound replication listener must be reported ready: {readiness:?}"
        );
        assert!(readiness.reason.is_none());

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn test_master_bind_failure_marks_readiness_failed() {
        // Keep the probe listener bound so the master cannot bind the port.
        let port_lease = sito_test_support::reserve_port().unwrap();
        let port = port_lease.port();
        let coordinator = test_coordinator();
        let observer = coordinator.clone();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = spawn_master_server(
            HaConfig {
                replication_port: port,
                listen_addr: "127.0.0.1".to_string(),
                allow_insecure_ws: true,
                slave_token: Some("tok".to_string()),
                ..Default::default()
            },
            coordinator,
            shutdown_rx,
        );
        handle.await.unwrap();

        let readiness = observer.readiness();
        assert!(!readiness.ready, "a bind failure must leave HA not ready");
        assert!(
            readiness
                .reason
                .unwrap_or_default()
                .contains("Failed to bind"),
            "readiness must name the bind failure"
        );
        drop(port_lease);
    }

    #[tokio::test]
    async fn test_master_replication_disabled_is_ready_and_explained() {
        let coordinator = test_coordinator();
        coordinator.mark_replication_disabled();
        let readiness = coordinator.readiness();
        assert!(
            readiness.ready,
            "an explicitly disabled replication listener is not a failure"
        );
        assert!(
            readiness
                .reason
                .unwrap_or_default()
                .contains("replication_port"),
            "the disabled state must be explained"
        );
    }

    #[tokio::test]
    async fn test_broadcast_falls_back_to_async_delivery_when_queue_full() {
        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (tx, mut rx) = mpsc::channel::<HaMessage>(1);
        // Fill the queue so broadcast's try_send fails.
        tx.send(HaMessage::Ping { ts: 1 }).await.unwrap();
        coordinator.slaves.lock().unwrap().insert(
            "slave-1".to_string(),
            ActiveSlave {
                instance: "slave-1".to_string(),
                remote_addr: "127.0.0.1:12345".parse().unwrap(),
                synced_version: 1,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx.clone(),
                capabilities: vec!["stats-v1".to_string()],
                connection_id: 1,
            },
        );

        coordinator.broadcast(&HaMessage::Ping { ts: 2 });

        // First message drains the queue; the coalesced fallback delivers the
        // latest active configuration bundle (not the superseded broadcast).
        assert!(rx.recv().await.is_some());
        let delivered = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("fallback delivery timed out")
            .expect("channel closed");
        assert!(matches!(delivered, HaMessage::ConfigPush { .. }));

        // Cleanup removes the per-instance metric label.
        coordinator.metrics.set_ha_config_version("slave-1", 1.0);
        coordinator.metrics.remove_ha_config_version("slave-1");
    }

    #[tokio::test]
    async fn test_broadcast_respects_per_slave_queue_byte_budget() {
        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (tx, mut rx) = mpsc::channel::<HaMessage>(8);
        coordinator.slaves.lock().unwrap().insert(
            "slow-slave".to_string(),
            ActiveSlave {
                instance: "slow-slave".to_string(),
                remote_addr: "127.0.0.1:12345".parse().unwrap(),
                synced_version: 0,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 1,
            },
        );
        // Pretend the session has a full byte budget queued even though the
        // message-count channel has room.
        coordinator
            .queued_bytes
            .lock()
            .unwrap()
            .insert(("slow-slave".to_string(), 1), MAX_SLAVE_QUEUE_BYTES);

        assert_eq!(coordinator.broadcast(&HaMessage::Ping { ts: 2 }), 1);
        // The coalesced task must wait for the byte budget instead of queueing
        // another message.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            rx.try_recv().is_err(),
            "the byte budget must block delivery while the queue is full"
        );

        // Draining the accounting (as the session loop does after a read)
        // releases the coalesced delivery.
        coordinator
            .queued_bytes
            .lock()
            .unwrap()
            .remove(&("slow-slave".to_string(), 1));
        let delivered = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("coalesced delivery timed out")
            .expect("channel closed");
        assert!(matches!(delivered, HaMessage::ConfigPush { .. }));
    }

    /// Regression (deferred D2): every non-broadcast send path must account
    /// its bytes, a rejected send must not inflate the budget, and an
    /// over-budget send must be refused before it touches the channel.
    #[tokio::test]
    async fn test_try_queue_accounted_tracks_bytes_and_rejects_full_queue() {
        let coordinator = test_coordinator();
        let (tx, mut rx) = mpsc::channel::<HaMessage>(1);
        let msg = HaMessage::Ping { ts: 7 };
        let size = msg.to_json().unwrap().len();
        let key = ("slave-1".to_string(), 1);
        // Registration installs the session key; the helper refuses to create
        // accounting for an unregistered/superseded session.
        coordinator
            .queued_bytes
            .lock()
            .unwrap()
            .insert(key.clone(), 0);

        coordinator
            .try_queue_accounted("slave-1", 1, &tx, size, msg.clone())
            .expect("queue has room");
        assert_eq!(
            coordinator.queued_bytes.lock().unwrap().get(&key).copied(),
            Some(size),
            "a queued message must be accounted"
        );

        // The single-slot channel is full: a rejected send must not add bytes.
        assert!(
            coordinator
                .try_queue_accounted("slave-1", 1, &tx, size, msg.clone())
                .is_err()
        );
        assert_eq!(
            coordinator.queued_bytes.lock().unwrap().get(&key).copied(),
            Some(size),
            "a rejected send must not change the accounting"
        );

        let _ = rx.recv().await;
        drop(rx);
        // A closed channel must not add bytes either.
        assert!(
            coordinator
                .try_queue_accounted("slave-1", 1, &tx, size, msg.clone())
                .is_err()
        );
        assert_eq!(
            coordinator.queued_bytes.lock().unwrap().get(&key).copied(),
            Some(size)
        );

        // A sender whose session key was removed by a reconnect must not
        // recreate accounting for a channel nobody will drain.
        let (unregistered_tx, mut unregistered_rx) = mpsc::channel::<HaMessage>(4);
        assert!(
            coordinator
                .try_queue_accounted("slave-3", 3, &unregistered_tx, size, msg.clone())
                .is_err(),
            "an unregistered/superseded session must be refused"
        );
        assert!(
            unregistered_rx.try_recv().is_err(),
            "a refused session must not receive the message"
        );

        // An over-budget send is refused before it is queued, so a coalesced
        // fallback can take over instead of growing the queue.
        let (over_tx, mut over_rx) = mpsc::channel::<HaMessage>(4);
        let over_key = ("slave-2".to_string(), 9);
        coordinator
            .queued_bytes
            .lock()
            .unwrap()
            .insert(over_key.clone(), MAX_SLAVE_QUEUE_BYTES);
        let err = coordinator
            .try_queue_accounted("slave-2", 9, &over_tx, size, msg)
            .expect_err("an over-budget send must be refused");
        assert!(err.contains("budget"), "unexpected error: {err}");
        assert!(
            over_rx.try_recv().is_err(),
            "an over-budget send must not touch the channel"
        );
        assert_eq!(
            coordinator
                .queued_bytes
                .lock()
                .unwrap()
                .get(&over_key)
                .copied(),
            Some(MAX_SLAVE_QUEUE_BYTES),
            "a refused send must not change the accounting"
        );
    }

    /// Regression (deferred D2): a reconnecting instance used to inherit the
    /// superseded session's `queued_bytes`, so the coalesced-delivery loop
    /// could spin until phantom accounting cleared. Registration must reset it.
    #[tokio::test]
    async fn test_reconnect_resets_per_slave_queue_accounting() {
        use tokio_tungstenite::tungstenite::protocol::Role;
        use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

        let coordinator = test_coordinator();
        // No active bundle: registration has nothing to enqueue, so any
        // remaining value after registration is phantom accounting. The key
        // carries a superseded connection id.
        coordinator
            .queued_bytes
            .lock()
            .unwrap()
            .insert(("slave-1".to_string(), 999), MAX_SLAVE_QUEUE_BYTES);

        let (server_socket, client_socket) = tokio::io::duplex(64 * 1024);
        let server_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            server_socket,
            Role::Server,
            Some(WebSocketConfig::default()),
        )
        .await;
        let mut client_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            client_socket,
            Role::Client,
            Some(WebSocketConfig::default()),
        )
        .await;

        let coord = coordinator.clone();
        let session = tokio::spawn(async move {
            coord
                .handle_connection(server_ws, "127.0.0.1:1000".parse().unwrap())
                .await;
        });

        let hello = HaMessage::Hello {
            instance: "slave-1".to_string(),
            have_version: 0,
            have_term: 0,
            capabilities: vec![],
            token: None,
            role: Some("slave".to_string()),
            protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
        };
        client_ws
            .send(WsMessage::Text(hello.to_json().unwrap().into()))
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if coordinator.slaves.lock().unwrap().contains_key("slave-1") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the reconnecting session must register");

        let active_connection_id = coordinator.slaves.lock().unwrap()["slave-1"].connection_id;
        let queued = coordinator.queued_bytes.lock().unwrap();
        assert_eq!(
            queued
                .get(&("slave-1".to_string(), active_connection_id))
                .copied(),
            Some(0),
            "registration must install a zero baseline for the new session"
        );
        assert!(
            !queued.contains_key(&("slave-1".to_string(), 999)),
            "phantom accounting from the superseded session must be reset"
        );

        session.abort();
    }

    /// Regression (deferred D2): a superseded session draining its old channel
    /// must subtract from its own session key, not the replacement's.
    #[tokio::test]
    async fn test_superseded_session_drain_does_not_charge_new_session() {
        let coordinator = test_coordinator();
        let old_key = ("slave-1".to_string(), 1);
        let new_key = ("slave-1".to_string(), 2);
        coordinator
            .queued_bytes
            .lock()
            .unwrap()
            .insert(old_key.clone(), 500);
        coordinator
            .queued_bytes
            .lock()
            .unwrap()
            .insert(new_key.clone(), 700);

        // The old session drains after the reconnect completed.
        coordinator.account_drained("slave-1", 1, 500);

        let queued = coordinator.queued_bytes.lock().unwrap();
        assert_eq!(queued.get(&old_key).copied(), Some(0));
        assert_eq!(
            queued.get(&new_key).copied(),
            Some(700),
            "the replacement session's budget must not be reduced by the old drain"
        );
    }

    /// Regression (deferred D2): a coalesced fallback task spawned for a
    /// superseded session must stop when it loses ownership, and must not
    /// deliver to or charge the replacement session.
    #[tokio::test]
    async fn test_pending_coalesced_task_does_not_charge_reconnected_session() {
        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (old_tx, _old_rx) = mpsc::channel::<HaMessage>(4);
        coordinator.slaves.lock().unwrap().insert(
            "slave-1".to_string(),
            ActiveSlave {
                instance: "slave-1".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 0,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: old_tx,
                capabilities: vec![],
                connection_id: 1,
            },
        );
        let old_key = ("slave-1".to_string(), 1);
        coordinator
            .queued_bytes
            .lock()
            .unwrap()
            .insert(old_key.clone(), MAX_SLAVE_QUEUE_BYTES);

        // Broadcast sees the exhausted budget and schedules the fallback task.
        assert_eq!(coordinator.broadcast(&HaMessage::Ping { ts: 2 }), 1);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if coordinator
                    .pending_fallbacks
                    .lock()
                    .unwrap()
                    .contains(&old_key)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the fallback task must be pending");

        // Reconnect: replace the active entry and reset the superseded
        // session's accounting.
        let (new_tx, mut new_rx) = mpsc::channel::<HaMessage>(4);
        {
            let mut slaves = coordinator.slaves.lock().unwrap();
            coordinator
                .queued_bytes
                .lock()
                .unwrap()
                .retain(|(instance, _), _| instance != "slave-1");
            slaves.insert(
                "slave-1".to_string(),
                ActiveSlave {
                    instance: "slave-1".to_string(),
                    remote_addr: "127.0.0.1:1001".parse().unwrap(),
                    synced_version: 0,
                    last_ping: Instant::now(),
                    connected_at: Utc::now(),
                    last_stats: None,
                    sender: new_tx,
                    capabilities: vec![],
                    connection_id: 2,
                },
            );
        }

        // The old task must notice it lost ownership and exit.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !coordinator
                    .pending_fallbacks
                    .lock()
                    .unwrap()
                    .contains(&old_key)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the superseded fallback task must exit");

        assert_eq!(
            coordinator
                .queued_bytes
                .lock()
                .unwrap()
                .get(&("slave-1".to_string(), 2))
                .copied(),
            None,
            "the superseded task must not charge the replacement session"
        );
        assert!(
            new_rx.try_recv().is_err(),
            "the superseded task must not deliver to the replacement session"
        );
    }

    #[test]
    fn test_per_ip_handshake_budget_is_bounded_and_released() {
        let budget = Arc::new(HandshakeBudget::default());
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let mut permits = Vec::new();
        for _ in 0..MAX_HANDSHAKES_PER_IP {
            permits.push(
                budget
                    .try_acquire(ip)
                    .expect("a slot must be available below the per-IP limit"),
            );
        }
        assert!(
            budget.try_acquire(ip).is_none(),
            "the per-IP handshake budget must be bounded"
        );
        // A different source IP has its own budget.
        assert!(
            budget
                .try_acquire("198.51.100.20".parse().unwrap())
                .is_some()
        );
        permits.pop();
        assert!(
            budget.try_acquire(ip).is_some(),
            "dropping a permit must release a slot"
        );
    }

    #[test]
    fn test_unregister_superseded_session_keeps_live_entry() {
        let coordinator = test_coordinator();
        let (old_tx, _old_rx) = mpsc::channel::<HaMessage>(1);
        let (new_tx, _new_rx) = mpsc::channel::<HaMessage>(1);

        let entry = |connection_id: u64, sender: mpsc::Sender<HaMessage>| ActiveSlave {
            instance: "slave-1".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 1,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender,
            capabilities: vec![],
            connection_id,
        };

        coordinator
            .slaves
            .lock()
            .unwrap()
            .insert("slave-1".to_string(), entry(1, old_tx));
        // A reconnect replaces the tracked entry.
        coordinator
            .slaves
            .lock()
            .unwrap()
            .insert("slave-1".to_string(), entry(2, new_tx));

        // The old session tearing down later must not evict the live entry.
        assert!(!coordinator.unregister_session("slave-1", 1));
        assert!(
            coordinator.slaves.lock().unwrap().contains_key("slave-1"),
            "superseded session must not remove the reconnected slave"
        );

        // The owning session still cleans up normally.
        assert!(coordinator.unregister_session("slave-1", 2));
        assert!(!coordinator.slaves.lock().unwrap().contains_key("slave-1"));
    }

    #[tokio::test]
    async fn test_stale_repushes_are_cleaned_up_on_disconnect() {
        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (tx, _rx) = mpsc::channel::<HaMessage>(4);
        coordinator.slaves.lock().unwrap().insert(
            "slave-1".to_string(),
            ActiveSlave {
                instance: "slave-1".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 1,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 7,
            },
        );

        // A stale ACK records one catch-up attempt for the session.
        let ack = HaMessage::Ack {
            version: 1,
            term: 0,
            conflict: None,
            applied: true,
            error: None,
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("slave-1", 7, &ack));
        assert_eq!(
            coordinator.stale_repushes.lock().unwrap().get("slave-1"),
            Some(&1),
            "the catch-up attempt must be recorded"
        );

        // Disconnecting must drop the bookkeeping, otherwise the map grows
        // without bound across reconnects.
        assert!(coordinator.unregister_session("slave-1", 7));
        assert!(
            coordinator.stale_repushes.lock().unwrap().is_empty(),
            "stale_repushes must not leak across sessions"
        );
    }

    #[test]
    fn test_update_bundle_strips_structured_client_secrets() {
        let coordinator = test_coordinator();
        let mut secrets = toml::Table::new();
        secrets.insert(
            "kids-tablet".to_string(),
            toml::Value::String("client_shared_secret_9876".to_string()),
        );
        let mut clients = toml::Table::new();
        clients.insert("client_id_secrets".to_string(), toml::Value::Table(secrets));

        let bundle = ConfigBundle {
            clients: Some(toml::Value::Table(clients)),
            ..test_bundle(2)
        };
        coordinator.update_bundle(bundle).unwrap();

        let stored = coordinator
            .active_bundle
            .lock()
            .unwrap()
            .clone()
            .expect("active bundle");
        let serialized = stored.to_json().unwrap();
        assert!(
            !serialized.contains("client_shared_secret_9876"),
            "stored/persisted bundle must not contain client secrets: {serialized}"
        );
        assert!(!serialized.contains("client_id_secrets"));
        assert!(stored.clients.is_some(), "non-secret client data is kept");
    }

    #[tokio::test]
    async fn test_ahead_slave_same_term_does_not_seed_or_rebase() {
        use tokio_tungstenite::tungstenite::protocol::Role;
        use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

        let coordinator = test_coordinator();
        // Active bundle at v2 while the connecting slave reports v10.
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (server_socket, client_socket) = tokio::io::duplex(256 * 1024);
        let server_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            server_socket,
            Role::Server,
            Some(WebSocketConfig::default()),
        )
        .await;
        let mut client_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            client_socket,
            Role::Client,
            Some(WebSocketConfig::default()),
        )
        .await;

        let coord = coordinator.clone();
        let session = tokio::spawn(async move {
            coord
                .handle_connection(server_ws, "127.0.0.1:1000".parse().unwrap())
                .await;
        });

        let hello = HaMessage::Hello {
            instance: "promoted-slave".to_string(),
            have_version: 10,
            have_term: 0,
            capabilities: vec![],
            token: None,
            role: Some("slave".to_string()),
            protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
        };
        client_ws
            .send(WsMessage::Text(hello.to_json().unwrap().into()))
            .await
            .unwrap();

        // A slave ahead in the *same* term is divergence evidence, not
        // authority. The master must not adopt its version or re-publish its
        // own bundle above it.
        let pushed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match client_ws.next().await {
                    Some(Ok(WsMessage::Text(txt))) => {
                        if let Ok(msg @ HaMessage::ConfigPush { .. }) = HaMessage::from_json(&txt) {
                            break msg;
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => panic!("connection closed before a ConfigPush"),
                }
            }
        })
        .await
        .expect("timed out waiting for the current push");
        let (push_version, push_term) = match pushed {
            HaMessage::ConfigPush { version, term, .. } => (version, term),
            other => panic!("expected ConfigPush, got {other:?}"),
        };
        assert_eq!(push_version, 2, "the master must keep its own version");
        assert_eq!(push_term, 0, "the master must keep its own term");
        assert_eq!(coordinator.get_current_version(), 2);
        assert_eq!(coordinator.get_current_term(), 0);
        assert!(
            coordinator.is_diverged(),
            "a same-term version gap must be surfaced as divergence"
        );
        let reason = coordinator.diverged_reason().unwrap();
        assert!(
            reason.contains("continuity") && reason.contains("explicit promotion"),
            "reason: {reason}"
        );

        // No automatic rebase on the ahead ACK either.
        let ack = HaMessage::Ack {
            version: 10,
            term: 0,
            conflict: None,
            applied: true,
            error: None,
        };
        client_ws
            .send(WsMessage::Text(ack.to_json().unwrap().into()))
            .await
            .unwrap();
        let extra = tokio::time::timeout(Duration::from_millis(300), async {
            loop {
                match client_ws.next().await {
                    Some(Ok(WsMessage::Text(txt))) => {
                        if matches!(HaMessage::from_json(&txt), Ok(HaMessage::ConfigPush { .. })) {
                            break true;
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => break false,
                }
            }
        })
        .await;
        assert!(
            !matches!(extra, Ok(true)),
            "an ahead ACK must not trigger an automatic rebase push"
        );
        assert_eq!(coordinator.get_current_version(), 2);
        assert_eq!(coordinator.get_current_term(), 0);

        session.abort();
    }

    #[tokio::test]
    async fn test_slave_ahead_ack_marks_diverged_without_republishing() {
        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (tx, mut rx) = mpsc::channel::<HaMessage>(8);
        coordinator.slaves.lock().unwrap().insert(
            "slave-1".to_string(),
            ActiveSlave {
                instance: "slave-1".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 50,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 1,
            },
        );

        // A slave acknowledging a version above the master's is a continuity
        // error, not something to auto-repair: doing so would publish this
        // master's possibly-stale bundle over newer configuration.
        let ack = HaMessage::Ack {
            version: 50,
            term: 0,
            conflict: None,
            applied: true,
            error: None,
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("slave-1", 1, &ack));
        assert!(coordinator.is_diverged(), "divergence must be surfaced");
        let rendered = coordinator.metrics.render_prometheus();
        assert!(
            rendered.contains(r#"sito_ha_diverged{instance="slave-1"} 1"#),
            "the per-slave divergence gauge must be raised: {rendered}"
        );
        let reason = coordinator.diverged_reason().unwrap();
        assert!(
            reason.contains("continuity") && reason.contains("explicit promotion"),
            "reason: {reason}"
        );
        assert_eq!(
            coordinator.get_current_version(),
            2,
            "the master must not rebase to the divergent version"
        );
        assert!(
            rx.try_recv().is_err(),
            "no recovery push may be queued automatically"
        );
    }

    #[tokio::test]
    async fn test_same_version_fork_ack_marks_divergence_and_unsyncs_slave() {
        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (tx, _rx) = mpsc::channel::<HaMessage>(8);
        coordinator.slaves.lock().unwrap().insert(
            "forked-slave".to_string(),
            ActiveSlave {
                instance: "forked-slave".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 2,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 1,
            },
        );

        let ack = HaMessage::Ack {
            version: 2,
            term: 0,
            applied: false,
            conflict: Some(AckConflict::SameVersionFork),
            error: Some("same-version payload fork".to_string()),
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("forked-slave", 1, &ack));
        assert!(
            coordinator.is_diverged(),
            "a fork ACK must latch divergence"
        );
        let reason = coordinator.diverged_reason().unwrap();
        assert!(reason.contains("fork"), "reason: {reason}");
        assert_eq!(
            coordinator.slaves.lock().unwrap()["forked-slave"].synced_version,
            0,
            "a rejected fork push must not leave the slave reported as synced"
        );
    }

    /// Important 1 regression: the published-envelope history is shared by all
    /// slaves. One slave's ACK must not remove the envelope before another
    /// slave reports the same-version fork for it.
    #[tokio::test]
    async fn test_two_slaves_both_record_fork_for_same_published_envelope() {
        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        for (instance, connection_id) in [("fork-a", 1), ("fork-b", 2)] {
            let (tx, _rx) = mpsc::channel::<HaMessage>(8);
            coordinator.slaves.lock().unwrap().insert(
                instance.to_string(),
                ActiveSlave {
                    instance: instance.to_string(),
                    remote_addr: format!("127.0.0.1:{connection_id}").parse().unwrap(),
                    synced_version: 2,
                    last_ping: Instant::now(),
                    connected_at: Utc::now(),
                    last_stats: None,
                    sender: tx,
                    capabilities: vec![],
                    connection_id,
                },
            );
        }

        let ack = HaMessage::Ack {
            version: 2,
            term: 0,
            applied: false,
            conflict: Some(AckConflict::SameVersionFork),
            error: Some("same-version payload fork".to_string()),
        }
        .to_json()
        .unwrap();

        assert!(coordinator.process_slave_msg("fork-a", 1, &ack));
        assert!(coordinator.process_slave_msg("fork-b", 2, &ack));

        let summaries = coordinator.list_slaves();
        for instance in ["fork-a", "fork-b"] {
            let summary = summaries
                .iter()
                .find(|s| s.instance == instance)
                .expect("tracked slave");
            assert!(
                summary.diverged,
                "{instance} must be reported diverged for the shared envelope: {summaries:?}"
            );
            assert_eq!(
                summary.synced_version, 0,
                "{instance} must be marked unsynced after its fork ACK"
            );
        }
        assert!(coordinator.is_diverged());
    }

    #[tokio::test]
    async fn test_term_divergence_survives_other_slave_and_clears_on_own_ack() {
        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (tx_a, _rx_a) = mpsc::channel::<HaMessage>(8);
        coordinator.slaves.lock().unwrap().insert(
            "newer-term-slave".to_string(),
            ActiveSlave {
                instance: "newer-term-slave".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 0,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx_a,
                capabilities: vec![],
                connection_id: 1,
            },
        );
        let (tx_b, _rx_b) = mpsc::channel::<HaMessage>(8);
        coordinator.slaves.lock().unwrap().insert(
            "synced-slave".to_string(),
            ActiveSlave {
                instance: "synced-slave".to_string(),
                remote_addr: "127.0.0.1:1001".parse().unwrap(),
                synced_version: 0,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx_b,
                capabilities: vec![],
                connection_id: 2,
            },
        );

        // Slave A knows a newer term: sticky term divergence.
        let newer_term = HaMessage::Ack {
            version: 3,
            term: 1,
            applied: true,
            conflict: None,
            error: None,
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("newer-term-slave", 1, &newer_term));
        assert!(coordinator.is_diverged());
        assert!(coordinator.diverged_reason().unwrap().contains("term"));

        // Slave B applying the master's current version must not clear the
        // unrelated term divergence.
        let synced = HaMessage::Ack {
            version: 2,
            term: 0,
            applied: true,
            conflict: None,
            error: None,
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("synced-slave", 2, &synced));
        assert!(
            coordinator.is_diverged(),
            "a different slave's success must not clear a term divergence"
        );
        assert!(coordinator.diverged_reason().unwrap().contains("term"));
        let summaries = coordinator.list_slaves();
        let newer = summaries
            .iter()
            .find(|s| s.instance == "newer-term-slave")
            .unwrap();
        assert!(
            newer.diverged,
            "latched divergence must be visible in the API summary"
        );
        let rendered = coordinator.metrics.render_prometheus();
        assert!(
            rendered.contains(r#"sito_ha_diverged{instance="newer-term-slave"} 1"#),
            "the sticky gauge must stay raised: {rendered}"
        );

        // H-10: an operator resync re-pushes the bundle but does not clear
        // another slave's advisory record before that slave proves recovery.
        coordinator.trigger_resync();
        assert!(
            coordinator.is_diverged(),
            "a resync must not clear divergence before the slave ACKs"
        );
        assert!(coordinator.process_slave_msg("newer-term-slave", 1, &synced));
        assert!(
            !coordinator.is_diverged(),
            "the acknowledging slave's own divergence must clear"
        );
        assert!(
            coordinator
                .metrics
                .render_prometheus()
                .contains(r#"sito_ha_diverged{instance="newer-term-slave"} 0"#),
            "the per-slave divergence gauge must be zeroed after the ACK"
        );
    }

    #[tokio::test]
    async fn test_fork_divergence_does_not_block_publishing_and_clears_on_accept() {
        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (tx, _rx) = mpsc::channel::<HaMessage>(8);
        coordinator.slaves.lock().unwrap().insert(
            "forked-slave".to_string(),
            ActiveSlave {
                instance: "forked-slave".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 0,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 1,
            },
        );
        let (other_tx, mut other_rx) = mpsc::channel::<HaMessage>(8);
        coordinator.slaves.lock().unwrap().insert(
            "other-slave".to_string(),
            ActiveSlave {
                instance: "other-slave".to_string(),
                remote_addr: "127.0.0.1:1001".parse().unwrap(),
                synced_version: 0,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: other_tx,
                capabilities: vec![],
                connection_id: 2,
            },
        );

        let fork = HaMessage::Ack {
            version: 2,
            term: 0,
            applied: false,
            conflict: Some(AckConflict::SameVersionFork),
            error: Some("same-version payload fork".to_string()),
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("forked-slave", 1, &fork));
        assert!(coordinator.diverged_reason().unwrap().contains("fork"));

        // One forked replica must not stop the master's sequence or the push
        // to healthy replicas.
        assert_eq!(coordinator.update_bundle(test_bundle(3)).unwrap(), 3);
        match other_rx.try_recv().expect("healthy slave must receive v3") {
            HaMessage::ConfigPush { version, term, .. } => {
                assert_eq!(version, 3);
                assert_eq!(term, 0);
            }
            other => panic!("expected ConfigPush, got {other:?}"),
        }
        assert!(coordinator.is_diverged(), "the fork stays visible");
        let forked = coordinator
            .list_slaves()
            .into_iter()
            .find(|s| s.instance == "forked-slave")
            .unwrap();
        assert!(forked.diverged, "the forked slave must stay unsynced");

        // A resync does not fabricate recovery: it re-pushes the current
        // bundle and keeps the real fork latch until the slave accepts it.
        let outcome = coordinator.trigger_resync();
        assert!(outcome.active_bundle);
        assert!(
            coordinator.is_diverged(),
            "a resync must not clear a real fork latch"
        );

        // Once the slave accepts the current bundle (after promotion or local
        // reconciliation), its own latch clears.
        let accepted = HaMessage::Ack {
            version: 3,
            term: 0,
            applied: true,
            conflict: None,
            error: None,
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("forked-slave", 1, &accepted));
        assert!(!coordinator.is_diverged());
    }

    #[tokio::test]
    async fn test_fabricated_fork_ack_without_matching_push_is_ignored() {
        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (tx, _rx) = mpsc::channel::<HaMessage>(8);
        coordinator.slaves.lock().unwrap().insert(
            "liar-slave".to_string(),
            ActiveSlave {
                instance: "liar-slave".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 0,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 1,
            },
        );

        // No push was ever sent at version 999, so this cannot prove a fork.
        let fabricated = HaMessage::Ack {
            version: 999,
            term: 0,
            applied: false,
            conflict: Some(AckConflict::SameVersionFork),
            error: Some("fabricated".to_string()),
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("liar-slave", 1, &fabricated));
        assert!(
            !coordinator.is_diverged(),
            "a fork ACK must be bound to a push the master sent"
        );

        // Even `u64::MAX` in an applied:false ACK is rejected before it can
        // influence state, and publishing continues.
        let huge = HaMessage::Ack {
            version: u64::MAX,
            term: 0,
            applied: false,
            conflict: Some(AckConflict::SameVersionFork),
            error: None,
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("liar-slave", 1, &huge));
        assert!(!coordinator.is_diverged());
        assert_eq!(coordinator.update_bundle(test_bundle(3)).unwrap(), 3);
    }

    #[tokio::test]
    async fn test_same_term_ahead_divergence_clears_only_on_slave_ack() {
        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (tx, _rx) = mpsc::channel::<HaMessage>(8);
        coordinator.slaves.lock().unwrap().insert(
            "ahead-slave".to_string(),
            ActiveSlave {
                instance: "ahead-slave".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 0,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 1,
            },
        );

        let ahead = HaMessage::Ack {
            version: 50,
            term: 0,
            applied: true,
            conflict: None,
            error: None,
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("ahead-slave", 1, &ahead));
        assert!(coordinator.is_diverged());

        // The ACK for the master's own version proves this slave recovered:
        // per-slave divergence clears only now, not on a global resync.
        let current = HaMessage::Ack {
            version: 2,
            term: 0,
            applied: true,
            conflict: None,
            error: None,
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("ahead-slave", 1, &current));
        assert!(
            !coordinator.is_diverged(),
            "the acknowledging slave's ahead divergence must clear"
        );

        // A resync without a matching ACK does not clear anything.
        assert!(coordinator.process_slave_msg("ahead-slave", 1, &ahead));
        assert!(coordinator.is_diverged());
        coordinator.trigger_resync();
        assert!(
            coordinator.is_diverged(),
            "a resync alone must not clear divergence"
        );
    }

    #[tokio::test]
    async fn test_ack_from_newer_term_marks_master_stale() {
        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();
        coordinator.current_term.store(1, Ordering::SeqCst);

        let (tx, mut rx) = mpsc::channel::<HaMessage>(8);
        coordinator.slaves.lock().unwrap().insert(
            "newer-slave".to_string(),
            ActiveSlave {
                instance: "newer-slave".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 3,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 1,
            },
        );

        let ack = HaMessage::Ack {
            version: 3,
            term: 2,
            conflict: None,
            applied: true,
            error: None,
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("newer-slave", 1, &ack));
        assert!(coordinator.is_diverged());
        let reason = coordinator.diverged_reason().unwrap();
        assert!(reason.contains("term"), "reason: {reason}");
        assert_eq!(
            coordinator.get_current_version(),
            2,
            "a stale master must not adopt a newer term's version"
        );
        assert_eq!(
            coordinator.get_current_term(),
            1,
            "the master must not raise its term from peer input"
        );
        assert!(
            rx.try_recv().is_err(),
            "a stale master must not republish over a newer epoch"
        );
    }

    #[tokio::test]
    async fn test_hello_from_newer_term_rejects_stale_master() {
        use tokio_tungstenite::tungstenite::protocol::Role;
        use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (server_socket, client_socket) = tokio::io::duplex(64 * 1024);
        let server_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            server_socket,
            Role::Server,
            Some(WebSocketConfig::default()),
        )
        .await;
        let mut client_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            client_socket,
            Role::Client,
            Some(WebSocketConfig::default()),
        )
        .await;

        let coord = coordinator.clone();
        let session = tokio::spawn(async move {
            coord
                .handle_connection(server_ws, "127.0.0.1:1000".parse().unwrap())
                .await;
        });

        let hello = HaMessage::Hello {
            instance: "newer-slave".to_string(),
            have_version: 3,
            have_term: 1,
            capabilities: vec![],
            token: None,
            role: Some("slave".to_string()),
            protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
        };
        client_ws
            .send(WsMessage::Text(hello.to_json().unwrap().into()))
            .await
            .unwrap();

        // The stale master registers the replica and sends its own bundle; the
        // replica rejects it on term, and the master surfaces the divergence.
        let pushed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match client_ws.next().await {
                    Some(Ok(WsMessage::Text(txt))) => {
                        if let Ok(msg @ HaMessage::ConfigPush { .. }) = HaMessage::from_json(&txt) {
                            break msg;
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => panic!("connection closed before a ConfigPush"),
                }
            }
        })
        .await
        .expect("timed out waiting for the master push");
        match pushed {
            HaMessage::ConfigPush { version, term, .. } => {
                assert_eq!(version, 2, "the stale master must not rebase its version");
                assert_eq!(term, 0, "the stale master must not adopt the newer term");
            }
            other => panic!("expected a ConfigPush, got {other:?}"),
        }
        assert_eq!(coordinator.get_current_version(), 2);
        assert_eq!(coordinator.get_current_term(), 0);
        assert!(
            coordinator.is_diverged(),
            "the newer-term replica must surface the divergence"
        );
        let reason = coordinator.diverged_reason().unwrap();
        assert!(reason.contains("term"), "reason: {reason}");

        session.abort();
    }

    #[test]
    fn test_promoted_master_keeps_version_continuity_in_new_term() {
        let key = Arc::new(Ed25519SigningKey::generate().unwrap());
        let coordinator = MasterCoordinator::new(
            "promoted-master".to_string(),
            10,
            key,
            sito_stats::MetricsRegistry::new("test", "test"),
        )
        .with_term(1);

        // The explicit promotion continues above the previous sequence.
        let mut promoted = test_bundle(11);
        promoted.term = 1;
        assert_eq!(coordinator.update_bundle(promoted).unwrap(), 11);
        assert_eq!(coordinator.get_current_term(), 1);

        // A stale term-0 coordinator cannot publish a higher version into the
        // promoted cluster.
        let mut stale = test_bundle(12);
        stale.term = 0;
        let err = coordinator
            .update_bundle(stale)
            .expect_err("a stale term must not publish over the promoted epoch");
        assert!(matches!(err, HaError::Validation { ref field, .. } if field == "term"));
        assert_eq!(coordinator.get_current_version(), 11);
        assert_eq!(coordinator.get_current_term(), 1);
    }

    #[test]
    fn test_unregister_removes_divergence_metric_series() {
        let coordinator = test_coordinator();
        let (tx, _rx) = mpsc::channel::<HaMessage>(1);
        coordinator.slaves.lock().unwrap().insert(
            "slave-1".to_string(),
            ActiveSlave {
                instance: "slave-1".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 1,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 1,
            },
        );
        coordinator.mark_diverged(
            DivergenceKind::Term,
            "slave-1",
            50,
            0,
            "continuity broken".to_string(),
        );
        assert!(
            coordinator
                .metrics
                .render_prometheus()
                .contains(r#"sito_ha_diverged{instance="slave-1"} 1"#),
            "the mark path must raise the gauge before disconnect"
        );

        assert!(coordinator.unregister_session("slave-1", 1));
        let rendered = coordinator.metrics.render_prometheus();
        assert!(
            !rendered.contains(r#"sito_ha_diverged{instance="slave-1"}"#),
            "the divergence series must be removed on disconnect: {rendered}"
        );
        assert!(
            !coordinator.is_diverged(),
            "the divergence record must be dropped with the session"
        );
    }

    /// A disconnected instance's divergence record and series are both removed,
    /// so a later divergence on another instance must not recreate it.
    #[test]
    fn test_disconnected_divergence_is_never_recreated() {
        let coordinator = test_coordinator();
        let (tx, _rx) = mpsc::channel::<HaMessage>(1);
        coordinator.slaves.lock().unwrap().insert(
            "slave-a".to_string(),
            ActiveSlave {
                instance: "slave-a".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 1,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 1,
            },
        );
        coordinator.mark_diverged(
            DivergenceKind::Ahead,
            "slave-a",
            50,
            0,
            "a is ahead".to_string(),
        );
        assert!(coordinator.unregister_session("slave-a", 1));

        // A more severe divergence on a different, connected instance.
        let (tx, _rx) = mpsc::channel::<HaMessage>(1);
        coordinator.slaves.lock().unwrap().insert(
            "slave-b".to_string(),
            ActiveSlave {
                instance: "slave-b".to_string(),
                remote_addr: "127.0.0.1:1001".parse().unwrap(),
                synced_version: 1,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 2,
            },
        );
        coordinator.mark_diverged(
            DivergenceKind::Ahead,
            "slave-b",
            60,
            0,
            "b is ahead".to_string(),
        );

        let rendered = coordinator.metrics.render_prometheus();
        assert!(
            rendered.contains(r#"sito_ha_diverged{instance="slave-b"} 1"#),
            "the live divergence must be exposed: {rendered}"
        );
        assert!(
            !rendered.contains(r#"sito_ha_diverged{instance="slave-a"}"#),
            "a disconnected instance must not get a recreated series: {rendered}"
        );
        assert_eq!(coordinator.diverged_reason().as_deref(), Some("b is ahead"));
    }

    #[test]
    fn test_slave_summary_flags_diverged_slave() {
        let entry = ActiveSlave {
            instance: "slave-1".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 9,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: mpsc::channel::<HaMessage>(1).0,
            capabilities: vec![],
            connection_id: 1,
        };
        let diverged = entry.to_summary(5, false);
        assert!(diverged.diverged);
        assert_eq!(diverged.lag, 0, "diverged lag must not look in sync");

        let synced = entry.to_summary(9, false);
        assert!(!synced.diverged);
        assert_eq!(synced.lag, 0);

        let behind = entry.to_summary(12, false);
        assert!(!behind.diverged);
        assert_eq!(behind.lag, 3);

        // A latched divergence (fork/term/ahead) must be visible even when the
        // version counter alone would look in sync.
        let latched = entry.to_summary(9, true);
        assert!(latched.diverged);
        assert_eq!(latched.lag, 0);
    }

    #[tokio::test]
    async fn test_master_rejects_oversized_websocket_hello() {
        let port = sito_test_support::reserve_port_number().unwrap();
        let coordinator = test_coordinator().with_token(Some("tok".to_string()));
        let master_cfg = HaConfig {
            replication_port: port,
            listen_addr: "127.0.0.1".to_string(),
            allow_insecure_ws: true,
            slave_token: Some("tok".to_string()),
            ..Default::default()
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let _server = spawn_master_server(master_cfg, coordinator.clone(), shutdown_rx);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}"))
            .await
            .expect("connect to master");

        // A valid Hello whose instance string blows past the 1 MiB cap: the
        // codec must reject it, so the slave is never registered.
        let hello = HaMessage::Hello {
            instance: "x".repeat(2 * 1024 * 1024),
            have_version: 0,
            have_term: 0,
            capabilities: vec![],
            token: Some("tok".to_string()),
            role: Some("slave".to_string()),
            protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
        };
        let _ = ws
            .send(WsMessage::Text(hello.to_json().unwrap().into()))
            .await;

        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match ws.next().await {
                    Some(Ok(WsMessage::Close(_)) | Err(_)) | None => break,
                    _ => {}
                }
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "the master must close an oversized WebSocket message"
        );
        assert_eq!(
            coordinator.connected_slave_count(),
            0,
            "an oversized Hello must not register a slave"
        );

        let _ = shutdown_tx.send(true);
    }

    #[test]
    fn test_update_bundle_rejects_u64_max_version() {
        let coordinator = test_coordinator();
        let err = coordinator
            .update_bundle(test_bundle(u64::MAX))
            .expect_err("u64::MAX must never be persisted as the active version");
        assert!(
            matches!(err, HaError::Validation { ref field, .. } if field == "version"),
            "unexpected error: {err:?}"
        );
        assert_eq!(
            coordinator.get_current_version(),
            1,
            "a rejected publish must not advance the sequence"
        );
        assert!(
            coordinator.active_bundle.lock().unwrap().is_none(),
            "a rejected publish must not store an active bundle"
        );
    }

    #[test]
    fn test_restore_rejects_u64_max_state_instead_of_freezing() {
        let dir = std::env::temp_dir().join(format!(
            "sito_ha_max_state_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let state_path = dir.join("ha_state.toml");
        std::fs::write(
            &state_path,
            serde_json::to_vec(&test_bundle(u64::MAX)).unwrap(),
        )
        .unwrap();

        let coordinator = test_coordinator().with_state_path(state_path);
        let err = coordinator
            .restore_state()
            .expect_err("a persisted u64::MAX sequence must fail closed");
        assert!(matches!(err, HaError::Validation { ref field, .. } if field == "version"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_hello_u64_max_does_not_seed_or_register() {
        use tokio_tungstenite::tungstenite::protocol::Role;
        use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (server_socket, client_socket) = tokio::io::duplex(64 * 1024);
        let server_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            server_socket,
            Role::Server,
            Some(WebSocketConfig::default()),
        )
        .await;
        let mut client_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            client_socket,
            Role::Client,
            Some(WebSocketConfig::default()),
        )
        .await;

        let coord = coordinator.clone();
        let session = tokio::spawn(async move {
            coord
                .handle_connection(server_ws, "127.0.0.1:1000".parse().unwrap())
                .await;
        });

        let hello = HaMessage::Hello {
            instance: "hostile-slave".to_string(),
            have_version: u64::MAX,
            have_term: 0,
            capabilities: vec![],
            token: None,
            role: Some("slave".to_string()),
            protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
        };
        client_ws
            .send(WsMessage::Text(hello.to_json().unwrap().into()))
            .await
            .unwrap();

        // The master closes the session without pushing or adopting the value.
        let closed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match client_ws.next().await {
                    Some(Ok(WsMessage::Close(_)) | Err(_)) | None => break,
                    _ => {}
                }
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "an implausible Hello must close the session"
        );
        session.await.unwrap();
        assert_eq!(
            coordinator.get_current_version(),
            2,
            "u64::MAX must never seed the master sequence"
        );
        assert_eq!(coordinator.connected_slave_count(), 0);
    }

    #[tokio::test]
    async fn test_ack_u64_max_does_not_freeze_publishing() {
        let coordinator = test_coordinator();
        coordinator.update_bundle(test_bundle(2)).unwrap();

        let (tx, mut rx) = mpsc::channel::<HaMessage>(8);
        coordinator.slaves.lock().unwrap().insert(
            "hostile-slave".to_string(),
            ActiveSlave {
                instance: "hostile-slave".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 2,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 1,
            },
        );

        let ack = HaMessage::Ack {
            version: u64::MAX,
            term: 0,
            conflict: None,
            applied: true,
            error: None,
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("hostile-slave", 1, &ack));

        assert_eq!(
            coordinator.get_current_version(),
            2,
            "an implausible ACK must not change the master sequence"
        );
        assert!(
            rx.try_recv().is_err(),
            "an implausible ACK must not trigger a rebase push"
        );
        assert_eq!(
            coordinator.update_bundle(test_bundle(3)).unwrap(),
            3,
            "publishing must keep working after an implausible ACK"
        );
    }
}
