//! Master HA coordinator managing connected replica slaves and configuration push dissemination.

use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
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
use crate::protocol::HaMessage;
use crate::transport::{build_server_tls_config, ws_config};

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

/// A version-continuity violation observed on a slave acknowledgement.
#[derive(Debug, Clone)]
struct Divergence {
    acked_version: u64,
    reason: String,
}

/// Master HA coordinator.
#[derive(Clone)]
pub struct MasterCoordinator {
    pub instance_name: String,
    pub signing_key: Arc<Ed25519SigningKey>,
    pub current_version: Arc<AtomicU64>,
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
    pending_fallbacks: Arc<Mutex<HashSet<String>>>,
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
    /// Version-continuity violations per currently connected slave; an entry is
    /// removed when a push above its version is applied or the slave
    /// disconnects, so the metric series cannot outlive the record.
    diverged: Arc<Mutex<HashMap<String, Divergence>>>,
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
            diverged: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Enables persistence of the active configuration version/bundle to `path`.
    #[must_use]
    pub fn with_state_path(mut self, path: PathBuf) -> Self {
        self.state_path = Arc::new(Mutex::new(Some(path)));
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
        let payload = serde_json::to_vec_pretty(bundle).map_err(|e| {
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
        tokio::task::spawn_blocking(move || Self::write_state_file(&path, &payload))
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
        let bundle: ConfigBundle = match serde_json::from_str(&data) {
            Ok(bundle) => bundle,
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
        if bundle.version == 0 {
            return Ok(None);
        }
        // State files written by older versions may still embed structured
        // client secrets; strip them before signing/broadcasting.
        let mut bundle = bundle;
        bundle.strip_structured_secrets();
        let push = build_and_sign_push(&bundle, &self.signing_key)?;
        self.current_version.store(bundle.version, Ordering::SeqCst);
        *self.active_bundle.lock().unwrap() = Some(bundle.clone());
        *self.active_push.lock().unwrap() = Some(push);
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

    /// Returns true when a version-continuity violation (a slave acknowledging
    /// a version above the master's) is currently recorded.
    pub fn is_diverged(&self) -> bool {
        !self.diverged.lock().unwrap().is_empty()
    }

    /// Returns the most severe recorded divergence reason, if any.
    pub fn diverged_reason(&self) -> Option<String> {
        self.diverged
            .lock()
            .unwrap()
            .values()
            .max_by_key(|d| d.acked_version)
            .map(|d| d.reason.clone())
    }

    /// Records a version-continuity violation for one instance, keeping the
    /// most severe version that instance reported.
    fn mark_diverged(&self, instance: &str, acked_version: u64, reason: String) {
        let mut diverged = self.diverged.lock().unwrap();
        if diverged
            .get(instance)
            .is_none_or(|d| acked_version >= d.acked_version)
        {
            diverged.insert(
                instance.to_string(),
                Divergence {
                    acked_version,
                    reason,
                },
            );
            self.metrics.set_ha_diverged(instance, true);
        }
    }

    /// Clears each divergence record once a version above its divergent one was
    /// successfully applied by the master's slaves (or the operator published
    /// past it).
    ///
    /// The slaves lock is held across the connectivity check and gauge update
    /// so a concurrent disconnect cannot remove the record/metric and have this
    /// path recreate a stale `0` series.
    fn clear_divergence_above(&self, version: u64) {
        let slaves = self.slaves.lock().unwrap();
        let mut diverged = self.diverged.lock().unwrap();
        let cleared: Vec<String> = diverged
            .iter()
            .filter(|(_, d)| version > d.acked_version)
            .map(|(instance, _)| instance.clone())
            .collect();
        for instance in cleared {
            diverged.remove(&instance);
            if slaves.contains_key(&instance) {
                self.metrics.set_ha_diverged(&instance, false);
            }
        }
    }

    /// Raises the local sequence to `have_version` when an authenticated slave
    /// reports a higher version.
    ///
    /// This is the promotion/state-loss guard: a promoted slave (or a master
    /// whose `ha_state.toml` was lost or corrupt) must continue *above* the
    /// highest version in the cluster instead of restarting at v1, otherwise
    /// every push is silently ignored by the remaining slaves. An operator can
    /// override the sequence by seeding a higher `ha_state.toml` or by
    /// publishing a higher bundle version explicitly.
    ///
    /// Returns true when the local sequence was raised.
    fn seed_version_from_hello(&self, instance: &str, have_version: u64) -> bool {
        let mut current = self.current_version.load(Ordering::SeqCst);
        loop {
            if have_version <= current {
                return false;
            }
            match self.current_version.compare_exchange_weak(
                current,
                have_version,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }

        warn!(
            instance = %instance,
            have_version,
            previous = current,
            "Slave reports a version above the master's sequence; seeding the master version to preserve monotonic continuity"
        );
        #[allow(clippy::cast_precision_loss)]
        {
            self.metrics
                .set_ha_config_version("local", have_version as f64);
            self.metrics
                .set_ha_config_version(&self.instance_name, have_version as f64);
        }
        true
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

        let push_msg = build_and_sign_push(&bundle, &self.signing_key)?;
        Ok((bundle, version, push_msg, current))
    }

    /// Publishes a prepared bundle. The caller must hold
    /// [`Self::publish_lock`] and have persisted the bundle first.
    fn publish_prepared(&self, bundle: ConfigBundle, version: u64, push_msg: HaMessage) {
        self.current_version.store(version, Ordering::SeqCst);
        *self.active_bundle.lock().unwrap() = Some(bundle);
        *self.active_push.lock().unwrap() = Some(push_msg);
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
    pub fn update_bundle(&self, bundle: ConfigBundle) -> Result<u64, HaError> {
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
        self.publish_prepared(bundle, version, push_msg.clone());
        self.record_published_version(version);

        // Broadcast to all active slaves
        self.broadcast(&push_msg);

        info!(
            version,
            "Master updated configuration bundle and broadcasted push to connected slaves"
        );

        Ok(version)
    }

    /// Async variant of [`Self::update_bundle`] that persists state on the
    /// blocking pool.
    ///
    /// `persist_lock` serializes the whole publish-and-write sequence so two
    /// concurrent async publishers cannot complete their state writes out of
    /// order. The standard `publish_lock` is only held for the in-memory
    /// check/store/sign step and is dropped before awaiting the disk write.
    pub async fn update_bundle_async(&self, bundle: ConfigBundle) -> Result<u64, HaError> {
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

        {
            let _publish_guard = self
                .publish_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // A synchronous publisher may have advanced the sequence while the
            // write was in flight. Publishing our older prepared version would
            // regress the cluster, so restore the now-active state file and
            // report the conflict instead. Keep `publish_guard` for the restore
            // write so no newer publisher can interleave and be overwritten.
            if self.current_version.load(Ordering::SeqCst) != previous_version {
                let active = self.active_bundle.lock().unwrap().clone();
                if let Some(active) = active
                    && let Err(e) = self.persist_bundle(&active)
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
            self.publish_prepared(bundle, version, push_msg.clone());
        }

        self.record_published_version(version);

        // Broadcast to all active slaves
        self.broadcast(&push_msg);

        info!(
            version,
            "Master updated configuration bundle and broadcasted push to connected slaves"
        );

        Ok(version)
    }

    /// Broadcasts a message to all connected slaves.
    ///
    /// Returns the number of slaves for which delivery was queued (a full
    /// queue with a coalesced fallback task counts as queued).
    pub fn broadcast(&self, msg: &HaMessage) -> usize {
        let mut notified = 0;
        let slaves = self.slaves.lock().unwrap();
        for slave in slaves.values() {
            match slave.sender.try_send(msg.clone()) {
                Ok(()) => {
                    notified += 1;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Queue is full: do not silently drop the update. Coalesce
                    // fallback deliveries per slave so a slow or stalled replica
                    // cannot spawn unbounded tasks; the task sends the latest
                    // active bundle when the channel has room.
                    let instance = slave.instance.clone();
                    let first_schedule = self
                        .pending_fallbacks
                        .lock()
                        .unwrap()
                        .insert(instance.clone());
                    // The push will be delivered by the coalesced fallback
                    // task (either this one or one already pending).
                    notified += 1;
                    if !first_schedule {
                        debug!(
                            instance = %instance,
                            "HA fallback delivery already pending; coalescing push"
                        );
                        continue;
                    }
                    warn!(
                        instance = %instance,
                        "HA push queue full; scheduling coalesced asynchronous delivery"
                    );
                    let coordinator = self.clone();
                    let sender = slave.sender.clone();
                    let fallback = msg.clone();
                    tokio::spawn(async move {
                        // Prefer the latest active bundle; fall back to the
                        // message that could not be enqueued.
                        let latest = coordinator
                            .active_push
                            .lock()
                            .unwrap()
                            .clone()
                            .or(Some(fallback));
                        if let Some(latest) = latest
                            && let Err(e) = sender.send(latest).await
                        {
                            warn!(instance = %instance, "Failed to deliver queued HA push: {e}");
                        }
                        coordinator
                            .pending_fallbacks
                            .lock()
                            .unwrap()
                            .remove(&instance);
                    });
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    debug!(instance = %slave.instance, "HA push channel closed");
                }
            }
        }
        notified
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
            let slaves = self.slaves.lock().unwrap();
            if let Some(slave) = slaves.get(instance)
                && let Err(e) = slave.sender.try_send(push)
            {
                warn!(instance = %instance, "Catch-up push could not be queued: {e}");
            }
        }
    }

    /// Triggers a re-push of the current active configuration bundle to all slaves.
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
        slaves.values().map(|s| s.to_summary(cur_v)).collect()
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
                    capabilities,
                    token,
                    role,
                    protocol_version,
                }) => (
                    instance,
                    have_version,
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
                            capabilities,
                            token,
                            role,
                            protocol_version,
                        }) => (
                            instance,
                            have_version,
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

        let (slave_instance, have_version, capabilities, token, role, protocol_version) = hello_msg;

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

        let (tx, mut rx) = mpsc::channel::<HaMessage>(32);
        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);

        // Version continuity: a promoted slave (or a master whose
        // `ha_state.toml` was lost) reports a version above the local
        // sequence. Seed the sequence from it *before* publishing anything,
        // then re-publish the active bundle under a version above it so the
        // remaining slaves actually apply it instead of ignoring every push.
        let seeded = self.seed_version_from_hello(&slave_instance, have_version);
        let active_bundle = self.active_bundle.lock().unwrap().clone();
        if seeded && let Some(bundle) = active_bundle {
            let next_version = self.get_current_version().saturating_add(1);
            let mut rebased = bundle;
            rebased.version = next_version;
            if let Err(e) = self.update_bundle_async(rebased).await {
                warn!(
                    instance = %slave_instance,
                    version = next_version,
                    "Failed to republish the active bundle after seeding the version: {e}"
                );
            }
        }

        // Register slave in tracking map. A reconnecting instance replaces the
        // previous entry; `connection_id` lets the superseded session detect
        // that it no longer owns the entry.
        {
            let mut slaves = self.slaves.lock().unwrap();
            slaves.insert(
                slave_instance.clone(),
                ActiveSlave {
                    instance: slave_instance.clone(),
                    remote_addr: peer_addr,
                    synced_version: have_version,
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
            #[allow(clippy::cast_precision_loss)]
            self.metrics
                .set_ha_config_version(&slave_instance, have_version as f64);
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
            if let Err(e) = tx.try_send(push.clone()) {
                warn!(instance = %slave_instance, "Initial HA push could not be queued: {e}");
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
                    if let Ok(json) = msg.to_json()
                        && ws_stream.send(WsMessage::Text(json.into())).await.is_err() {
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
                    if let Ok(json) = ping.to_json()
                        && ws_stream.send(WsMessage::Text(json.into())).await.is_err() {
                            break;
                        }
                }

                // Incoming messages from slave
                msg_opt = ws_stream.next() => {
                    match msg_opt {
                        Some(Ok(WsMessage::Text(txt))) => {
                            if !self.process_slave_msg(&slave_instance, connection_id, &txt).await {
                                break;
                            }
                        }
                        Some(Ok(WsMessage::Binary(bin))) => {
                            if let Ok(txt) = std::str::from_utf8(&bin)
                                && !self.process_slave_msg(&slave_instance, connection_id, txt).await {
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
            self.metrics.remove_ha_diverged(instance);
        }
        #[allow(clippy::cast_possible_wrap)]
        self.metrics.set_ha_slaves_connected(slaves.len() as i64);
        owned
    }

    async fn process_slave_msg(
        &self,
        slave_instance: &str,
        connection_id: u64,
        text: &str,
    ) -> bool {
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
                applied,
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
                if applied && version == current {
                    info!(
                        instance = %slave_instance,
                        version,
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
                    // Applying a version above the last divergence restores
                    // continuity.
                    self.clear_divergence_above(version);
                } else if applied && version < current {
                    warn!(
                        instance = %slave_instance,
                        acked_version = version,
                        current,
                        "Slave acknowledged a stale configuration version; re-pushing the active bundle"
                    );
                    self.maybe_repush(slave_instance, version);
                } else if applied {
                    // A slave ahead of the master means version continuity is
                    // broken (promoted slave, restored from an older state
                    // file, or forked master). Every push below its version is
                    // silently ignored, so surface it loudly and recover by
                    // republishing above the reported version.
                    let reason = format!(
                        "slave '{slave_instance}' acknowledged version {version} above the master's current version {current}: version continuity is broken (promoted slave or lost/corrupt ha_state.toml)"
                    );
                    error!(
                        instance = %slave_instance,
                        acked_version = version,
                        current,
                        "{reason}"
                    );
                    self.mark_diverged(slave_instance, version, reason);
                    let active_bundle = self.active_bundle.lock().unwrap().clone();
                    if let Some(bundle) = active_bundle
                        && bundle.version <= version
                    {
                        let next_version = version.saturating_add(1);
                        let mut rebased = bundle;
                        rebased.version = next_version;
                        warn!(
                            instance = %slave_instance,
                            version = next_version,
                            "Republishing the active bundle above the divergent version"
                        );
                        if let Err(e) = self.update_bundle_async(rebased).await {
                            error!(
                                instance = %slave_instance,
                                version = next_version,
                                "Failed to republish above the divergent version: {e}"
                            );
                        }
                    }
                } else {
                    warn!(
                        instance = %slave_instance,
                        version,
                        error = ?error,
                        "Slave failed to apply configuration bundle"
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
                    let slaves = self.slaves.lock().unwrap();
                    if let Some(s) = slaves.get(slave_instance)
                        && s.connection_id == connection_id
                        && let Err(e) = s.sender.try_send(push.clone())
                    {
                        warn!(instance = %slave_instance, "Resync push could not be queued: {e}");
                    }
                }
            }
            _ => {}
        }

        true
    }
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
                    error!("Failed to initialize mTLS for master HA replication server: {e}");
                    return;
                }
            }
        } else {
            if !ha_config.allow_insecure_ws {
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
                error!("Failed to bind master HA replication listener on '{listen_addr}': {e}");
                return;
            }
        };

        info!(addr = %listen_addr, "Master HA replication listener active");

        let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_SLAVE_CONNECTIONS));

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
                            let coord = coordinator.clone();
                            let acceptor_opt = tls_acceptor.clone();

                            tokio::spawn(async move {
                                let _permit = permit;
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
            timestamp: 1,
            config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
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

    #[tokio::test]
    async fn test_async_persist_roundtrip_and_permissions() {
        let dir = std::env::temp_dir().join(format!(
            "sito_ha_async_state_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let state_path = dir.join("ha_state.toml");
        let coordinator = test_coordinator().with_state_path(state_path.clone());

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

        let restored = test_coordinator().with_state_path(state_path);
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
        let coordinator = test_coordinator().with_state_path(dir.join("ha_state.toml"));

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

        // A large payload makes the blocking write long enough to observe.
        let mut big_bundle = test_bundle(2);
        big_bundle.config_toml = "x".repeat(16 * 1024 * 1024);
        coordinator.update_bundle_async(big_bundle).await.unwrap();
        let after = ticks.load(Ordering::Relaxed);

        ticker.abort();
        assert!(
            after > before,
            "the tokio runtime must keep ticking while HA state is written (before={before}, after={after})"
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
        // A regular file where the state directory should be makes every
        // create_dir_all/write attempt fail deterministically.
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"blocked").unwrap();
        let coordinator = test_coordinator().with_state_path(blocker.join("ha_state.toml"));
        let before_version = coordinator.get_current_version();

        let err = coordinator
            .update_bundle_async(test_bundle(2))
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
        assert!(
            coordinator.active_push.lock().unwrap().is_none(),
            "a failed persist must not expose an active push to new slaves"
        );
        assert!(
            coordinator.active_bundle.lock().unwrap().is_none(),
            "a failed persist must not leave an active bundle"
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
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
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
        drop(probe);
    }

    #[tokio::test]
    async fn test_master_tls_init_failure_records_startup_noop() {
        let coordinator = test_coordinator();
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
            applied: true,
            error: None,
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("slave-1", 7, &ack).await);
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
    async fn test_ahead_slave_seeds_version_and_receives_republished_bundle() {
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
            capabilities: vec![],
            token: None,
            role: Some("slave".to_string()),
            protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
        };
        client_ws
            .send(WsMessage::Text(hello.to_json().unwrap().into()))
            .await
            .unwrap();

        // The master seeds from Hello and republishes the active bundle above
        // v10 so the slave actually applies it.
        let pushed = tokio::time::timeout(Duration::from_secs(5), client_ws.next())
            .await
            .expect("timed out waiting for the catch-up push")
            .expect("connection closed")
            .expect("websocket error");
        let push_version = match HaMessage::from_json(&pushed.into_text().unwrap()).unwrap() {
            HaMessage::ConfigPush { version, .. } => version,
            other => panic!("expected ConfigPush, got {other:?}"),
        };
        assert!(
            push_version >= 11,
            "a slave at v10 must be pushed a version above 10, got {push_version}"
        );
        assert!(coordinator.get_current_version() >= 11);

        // Acking the new version restores continuity.
        let ack = HaMessage::Ack {
            version: push_version,
            applied: true,
            error: None,
        };
        client_ws
            .send(WsMessage::Text(ack.to_json().unwrap().into()))
            .await
            .unwrap();
        let synced = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if coordinator
                    .list_slaves()
                    .first()
                    .is_some_and(|s| s.synced_version == push_version)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(synced.is_ok(), "slave must be reported synced after ACK");
        assert!(!coordinator.is_diverged());

        session.abort();
    }

    #[tokio::test]
    async fn test_slave_ahead_ack_marks_diverged_and_republishes() {
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
        // error, not something to ignore.
        let ack = HaMessage::Ack {
            version: 50,
            applied: true,
            error: None,
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("slave-1", 1, &ack).await);
        assert!(coordinator.is_diverged(), "divergence must be surfaced");
        let rendered = coordinator.metrics.render_prometheus();
        assert!(
            rendered.contains(r#"sito_ha_diverged{instance="slave-1"} 1"#),
            "the per-slave divergence gauge must be raised: {rendered}"
        );
        let reason = coordinator.diverged_reason().unwrap();
        assert!(reason.contains("continuity"), "reason: {reason}");
        let remediated = coordinator.get_current_version();
        assert!(
            remediated > 50,
            "the master must republish above the divergent version, got {remediated}"
        );

        // The recovery push is queued for the divergent slave.
        let push = rx.try_recv().expect("catch-up push must be queued");
        assert!(matches!(push, HaMessage::ConfigPush { version, .. } if version == remediated));

        // Applying a version above the divergent one clears the flag.
        let ack = HaMessage::Ack {
            version: remediated,
            applied: true,
            error: None,
        }
        .to_json()
        .unwrap();
        assert!(coordinator.process_slave_msg("slave-1", 1, &ack).await);
        assert!(!coordinator.is_diverged());
        let rendered = coordinator.metrics.render_prometheus();
        assert!(
            rendered.contains(r#"sito_ha_diverged{instance="slave-1"} 0"#),
            "recovering continuity must zero the gauge: {rendered}"
        );
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
        coordinator.mark_diverged("slave-1", 50, "continuity broken".to_string());
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
        coordinator.mark_diverged("slave-a", 50, "a is ahead".to_string());
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
        coordinator.mark_diverged("slave-b", 60, "b is ahead".to_string());

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
        let diverged = entry.to_summary(5);
        assert!(diverged.diverged);
        assert_eq!(diverged.lag, 0, "diverged lag must not look in sync");

        let synced = entry.to_summary(9);
        assert!(!synced.diverged);
        assert_eq!(synced.lag, 0);

        let behind = entry.to_summary(12);
        assert!(!behind.diverged);
        assert_eq!(behind.lag, 3);
    }

    #[tokio::test]
    async fn test_master_rejects_oversized_websocket_hello() {
        let port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
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
}
