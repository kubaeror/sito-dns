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
use crate::transport::build_server_tls_config;

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
    /// Monotonic id assigned to each accepted slave connection.
    next_connection_id: Arc<AtomicU64>,
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
            next_connection_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Enables persistence of the active configuration version/bundle to `path`.
    #[must_use]
    pub fn with_state_path(mut self, path: PathBuf) -> Self {
        self.state_path = Arc::new(Mutex::new(Some(path)));
        self
    }

    /// Persists the active bundle and version so a restart continues the
    /// monotonic sequence instead of resetting to 1 (which slaves reject).
    fn persist_state(&self) {
        let path = self.state_path.lock().unwrap().clone();
        let Some(path) = path else {
            return;
        };
        let Some(bundle) = self.active_bundle.lock().unwrap().clone() else {
            return;
        };
        let payload = match serde_json::to_vec_pretty(&bundle) {
            Ok(payload) => payload,
            Err(e) => {
                error!(error = %e, "Failed to serialize HA master state");
                return;
            }
        };
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            error!(error = %e, path = %parent.display(), "Failed to create HA state directory");
            return;
        }
        let tmp = path.with_extension("tmp");
        let write_result = {
            #[cfg(unix)]
            {
                use std::io::Write as _;
                use std::os::unix::fs::OpenOptionsExt as _;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp)
                    .and_then(|mut file| file.write_all(&payload))
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&tmp, &payload)
            }
        };
        if let Err(e) = write_result {
            error!(error = %e, path = %tmp.display(), "Failed to persist HA master state");
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            error!(error = %e, path = %path.display(), "Failed to atomically commit HA master state");
        }
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

    /// Sets and signs a new configuration bundle, immediately broadcasting it to all connected slaves.
    pub fn update_bundle(&self, bundle: ConfigBundle) -> Result<u64, HaError> {
        // Serialize the check-then-store: two concurrent publishers could
        // otherwise both pass the monotonicity check and store out of order,
        // regressing the active version and broadcasting a stale bundle.
        let _publish_guard = self
            .publish_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

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
        self.current_version.store(version, Ordering::SeqCst);

        let push_msg = build_and_sign_push(&bundle, &self.signing_key)?;

        *self.active_bundle.lock().unwrap() = Some(bundle);
        *self.active_push.lock().unwrap() = Some(push_msg.clone());
        self.persist_state();

        #[allow(clippy::cast_precision_loss)]
        {
            self.metrics.set_ha_config_version("local", version as f64);
            self.metrics
                .set_ha_config_version(&self.instance_name, version as f64);
        }

        // Broadcast to all active slaves
        self.broadcast(&push_msg);

        info!(
            version,
            "Master updated configuration bundle and broadcasted push to connected slaves"
        );

        Ok(version)
    }

    /// Broadcasts a message to all connected slaves.
    pub fn broadcast(&self, msg: &HaMessage) {
        let slaves = self.slaves.lock().unwrap();
        for slave in slaves.values() {
            match slave.sender.try_send(msg.clone()) {
                Ok(()) => {}
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
    pub fn trigger_resync(&self) -> u64 {
        let push_opt = self.active_push.lock().unwrap().clone();
        if let Some(ref push) = push_opt {
            self.broadcast(push);
        }
        self.get_current_version()
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
        }
        #[allow(clippy::cast_possible_wrap)]
        self.metrics.set_ha_slaves_connected(slaves.len() as i64);
        owned
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
                } else if applied && version < current {
                    warn!(
                        instance = %slave_instance,
                        acked_version = version,
                        current,
                        "Slave acknowledged a stale configuration version; re-pushing the active bundle"
                    );
                    self.maybe_repush(slave_instance, version);
                } else if applied {
                    warn!(
                        instance = %slave_instance,
                        acked_version = version,
                        current,
                        "Slave acknowledged a configuration version from the future; ignoring"
                    );
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
                                            tokio_tungstenite::accept_async(tls_stream),
                                        )
                                        .await
                                        .map_err(|_| "WebSocket upgrade timed out".to_string())?
                                        .map_err(|e| format!("WebSocket upgrade failed: {e}"))?;
                                        coord.handle_connection(ws_stream, peer_addr).await;
                                    } else {
                                        let ws_stream = timeout(
                                            MASTER_HANDSHAKE_TIMEOUT,
                                            tokio_tungstenite::accept_async(tcp_stream),
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
        assert_eq!(third.update_bundle(test_bundle(1)).unwrap(), 1);

        let _ = std::fs::remove_dir_all(&dir);
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
}
