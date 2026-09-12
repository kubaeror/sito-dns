//! Master HA coordinator managing connected replica slaves and configuration push dissemination.

use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
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
        }
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
                    // Queue is full: do not silently drop the update. Fall back to
                    // an async send so the message is delivered once there is room.
                    warn!(
                        instance = %slave.instance,
                        "HA push queue full; scheduling asynchronous delivery"
                    );
                    let sender = slave.sender.clone();
                    let queued = msg.clone();
                    tokio::spawn(async move {
                        if let Err(e) = sender.send(queued).await {
                            warn!("Failed to deliver queued HA push: {e}");
                        }
                    });
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    debug!(instance = %slave.instance, "HA push channel closed");
                }
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

        // Register slave in tracking map
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
                    let stale = {
                        let slaves = self.slaves.lock().unwrap();
                        slaves.get(&slave_instance).is_some_and(|s| {
                            s.last_ping.elapsed() > Duration::from_secs(ping_secs.saturating_mul(3))
                        })
                    };
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
                            if !self.process_slave_msg(&slave_instance, &txt) {
                                break;
                            }
                        }
                        Some(Ok(WsMessage::Binary(bin))) => {
                            if let Ok(txt) = std::str::from_utf8(&bin)
                                && !self.process_slave_msg(&slave_instance, txt) {
                                    break;
                                }
                        }
                        Some(Ok(WsMessage::Pong(_))) => {
                            let mut slaves = self.slaves.lock().unwrap();
                            if let Some(s) = slaves.get_mut(&slave_instance) {
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

        // Cleanup disconnected slave
        {
            let mut slaves = self.slaves.lock().unwrap();
            slaves.remove(&slave_instance);
            #[allow(clippy::cast_possible_wrap)]
            self.metrics.set_ha_slaves_connected(slaves.len() as i64);
        }
        self.metrics.remove_ha_config_version(&slave_instance);
        info!(instance = %slave_instance, "Unregistered replica slave from active tracker");
    }

    fn process_slave_msg(&self, slave_instance: &str, text: &str) -> bool {
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
                if applied {
                    info!(
                        instance = %slave_instance,
                        version,
                        "Slave successfully applied configuration bundle"
                    );
                    let mut slaves = self.slaves.lock().unwrap();
                    if let Some(s) = slaves.get_mut(slave_instance) {
                        s.synced_version = version;
                    }
                    #[allow(clippy::cast_precision_loss)]
                    self.metrics
                        .set_ha_config_version(slave_instance, version as f64);
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
                if let Some(s) = slaves.get_mut(slave_instance) {
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
            }
            HaMessage::Pong { .. } => {
                let mut slaves = self.slaves.lock().unwrap();
                if let Some(s) = slaves.get_mut(slave_instance) {
                    s.last_ping = Instant::now();
                }
            }
            HaMessage::Hello { .. } => {
                // Resync requested: always re-push the active bundle; the slave
                // acknowledges without re-applying when it is already current.
                if let Some(ref push) = *self.active_push.lock().unwrap() {
                    let slaves = self.slaves.lock().unwrap();
                    if let Some(s) = slaves.get(slave_instance)
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
                            let coord = coordinator.clone();
                            let acceptor_opt = tls_acceptor.clone();

                            tokio::spawn(async move {
                                if let Some(acceptor) = acceptor_opt {
                                    match acceptor.accept(tcp_stream).await {
                                        Ok(tls_stream) => {
                                            match tokio_tungstenite::accept_async(tls_stream).await {
                                                Ok(ws_stream) => {
                                                    coord.handle_connection(ws_stream, peer_addr).await;
                                                }
                                                Err(e) => {
                                                    warn!(peer = %peer_addr, "WebSocket upgrade failed: {e}");
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!(peer = %peer_addr, "mTLS handshake rejected: {e}");
                                        }
                                    }
                                } else {
                                    match tokio_tungstenite::accept_async(tcp_stream).await {
                                        Ok(ws_stream) => {
                                            coord.handle_connection(ws_stream, peer_addr).await;
                                        }
                                        Err(e) => {
                                            warn!(peer = %peer_addr, "Plain WebSocket upgrade failed: {e}");
                                        }
                                    }
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
            },
        );

        coordinator.broadcast(&HaMessage::Ping { ts: 2 });

        // First message drains the queue; the queued fallback push follows.
        assert!(rx.recv().await.is_some());
        let delivered = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("fallback delivery timed out")
            .expect("channel closed");
        assert!(matches!(delivered, HaMessage::Ping { ts: 2 }));

        // Cleanup removes the per-instance metric label.
        coordinator.metrics.set_ha_config_version("slave-1", 1.0);
        coordinator.metrics.remove_ha_config_version("slave-1");
    }
}
