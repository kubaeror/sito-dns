//! Master listener bootstrap.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Maximum concurrently accepted slave connections (handshake + session).
/// Maximum simultaneously admitted/handshaking HA connections across all peers
/// (listener-level semaphore). Slots are released when the session ends.
pub(super) const MAX_SLAVE_CONNECTIONS: usize = 64;
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
    coordinator = coordinator
        .with_ping_interval_secs(ha_config.ping_interval_secs)
        .with_slave_requirements(ha_config.require_slaves, ha_config.require_all_slaves);
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
            // A pin or CA is only enforceable inside the TLS handshake. If
            // either is configured, serving plaintext would silently drop the
            // control, so refuse instead of downgrading. Configuration
            // validation rejects this too; this is the runtime guard.
            if !ha_config.pinned_slave_fingerprints.is_empty() || ha_config.ca.is_some() {
                coordinator.mark_replication_failed(
                    "master replication refused plaintext while pin/CA material is configured",
                );
                error!(
                    "Master HA replication has pinned_slave_fingerprints or ca configured without a TLS cert/key. Refusing to serve plaintext and silently ignore them."
                );
                return;
            }
            None
        };

        let listen_addr = if ha_config.listen_addr.contains(':') {
            format!("[{}]:{}", ha_config.listen_addr, ha_config.replication_port)
        } else {
            format!("{}:{}", ha_config.listen_addr, ha_config.replication_port)
        };
        let listener =
            match TcpListener::bind((ha_config.listen_addr.as_str(), ha_config.replication_port))
                .await
            {
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
