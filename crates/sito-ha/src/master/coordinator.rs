//! Master HA coordinator managing connected replica slaves and configuration push dissemination.

use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{error, info, warn};

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
        }
    }

    /// Returns the currently active master configuration version.
    pub fn get_current_version(&self) -> u64 {
        self.current_version.load(Ordering::SeqCst)
    }

    /// Sets and signs a new configuration bundle, immediately broadcasting it to all connected slaves.
    pub fn update_bundle(&self, bundle: ConfigBundle) -> Result<u64, HaError> {
        let version = bundle.version;
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
            let _ = slave.sender.try_send(msg.clone());
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
                }) => (instance, have_version, capabilities),
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
                        }) => (instance, have_version, capabilities),
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

        let (slave_instance, have_version, _) = hello_msg;
        info!(
            instance = %slave_instance,
            have_version,
            peer = %peer_addr,
            "Received Hello from replica slave"
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
                },
            );
            #[allow(clippy::cast_possible_wrap)]
            self.metrics.set_ha_slaves_connected(slaves.len() as i64);
            #[allow(clippy::cast_precision_loss)]
            self.metrics
                .set_ha_config_version(&slave_instance, have_version as f64);
        }

        // If slave is behind current version, immediately enqueue push
        let cur_v = self.get_current_version();
        if have_version < cur_v
            && let Some(ref push) = *self.active_push.lock().unwrap()
        {
            info!(
                instance = %slave_instance,
                have_version,
                cur_v,
                "Slave is behind master version; pushing latest bundle immediately"
            );
            let _ = tx.try_send(push.clone());
        }

        // Heartbeat ping interval
        let mut ping_interval = tokio::time::interval(Duration::from_secs(15));
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

                // Periodic ping
                _ = ping_interval.tick() => {
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
            HaMessage::Hello { have_version, .. } => {
                // Resync requested
                let cur_v = self.get_current_version();
                if have_version < cur_v
                    && let Some(ref push) = *self.active_push.lock().unwrap()
                {
                    let slaves = self.slaves.lock().unwrap();
                    if let Some(s) = slaves.get(slave_instance) {
                        let _ = s.sender.try_send(push.clone());
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
    coordinator: MasterCoordinator,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listen_addr = format!("{}:{}", ha_config.listen_addr, ha_config.replication_port);
        let listener = match TcpListener::bind(&listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind master HA replication listener on '{listen_addr}': {e}");
                return;
            }
        };

        info!(addr = %listen_addr, "Master HA replication listener active");

        // Optional mTLS setup
        let tls_acceptor = if let (Some(cert_path), Some(key_path)) =
            (&ha_config.cert, &ha_config.key)
        {
            match build_server_tls_config(cert_path, key_path, &ha_config.pinned_slave_fingerprints)
            {
                Ok(cfg) => Some(TlsAcceptor::from(cfg)),
                Err(e) => {
                    error!("Failed to initialize mTLS for master HA replication server: {e}");
                    return;
                }
            }
        } else {
            None
        };

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
