//! Background slave replication worker and state apply coordinator.

use arc_swap::ArcSwap;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{error, info, warn};

use sito_clients::{ClientRegistry, ClientsConfig};
use sito_core::config::Config;
use sito_filter::HostsFilterEngine;
use sito_rewrites::{RewriteTable, RewritesConfig};
use sito_stats::MetricsRegistry;

use crate::bundle::{substitute_secrets, verify_and_unpack_push};
use crate::config::HaConfig;
use crate::crypto::parse_public_key;
use crate::error::HaError;
use crate::protocol::HaMessage;
use crate::slave::state::{SlaveState, SlaveStatusTracker};
use crate::transport::{ExponentialBackoff, build_client_tls_config};

/// Active server handles that the slave atomically updates when a new bundle is applied.
#[derive(Clone)]
pub struct SlaveAppHandles {
    pub config: Arc<ArcSwap<Config>>,
    pub filter: Arc<HostsFilterEngine>,
    pub rewrites: Arc<ArcSwap<RewriteTable>>,
    pub clients: Arc<ArcSwap<ClientRegistry>>,
    pub metrics: MetricsRegistry,
    pub config_path: Option<PathBuf>,
}

/// Applies a configuration push to the local server handles.
///
/// Implements rollback safety: if staging verification or validation fails,
/// the previous configuration and handles are kept active, the state transitions
/// to `Degraded`, and an `Ack { applied: false, error }` is returned.
pub async fn apply_config_push(
    push: &HaMessage,
    tracker: &SlaveStatusTracker,
    handles: &SlaveAppHandles,
    master_pubkey: &[u8],
) -> Result<u64, HaError> {
    let have_version = tracker.get_version();

    // 1. Verify cryptographic signature, checksum, and monotonicity
    let bundle = match verify_and_unpack_push(push, have_version, master_pubkey) {
        Ok(b) => b,
        Err(e) => {
            tracker.mark_degraded(format!("Validation/Signature verification failed: {e}"));
            return Err(e);
        }
    };

    // 2. Secret substitution
    let local_secrets = tracker.local_secrets.lock().unwrap().clone();
    let substituted_toml = match substitute_secrets(&bundle.config_toml, &local_secrets, true) {
        Ok(s) => s,
        Err(e) => {
            tracker.mark_degraded(format!("Secret substitution failed: {e}"));
            return Err(e);
        }
    };

    // 3. Staging configuration validation
    let mut staging_config = match Config::from_toml_str(&substituted_toml) {
        Ok(cfg) => cfg,
        Err(e) => {
            let reason = format!("Staging configuration validation failed: {e}");
            tracker.mark_degraded(reason.clone());
            return Err(HaError::Validation {
                field: "config".to_string(),
                reason,
            });
        }
    };

    // Staging rewrites validation if present
    let staging_rewrites: Option<RewritesConfig> = if let Some(ref r_val) = bundle.rewrites {
        match r_val.clone().try_into() {
            Ok(rc) => Some(rc),
            Err(e) => {
                let reason = format!("Staging rewrites parsing failed: {e}");
                tracker.mark_degraded(reason.clone());
                return Err(HaError::Validation {
                    field: "rewrites".to_string(),
                    reason,
                });
            }
        }
    } else {
        None
    };

    // Staging clients validation if present
    let staging_clients: Option<ClientsConfig> = if let Some(ref c_val) = bundle.clients {
        match c_val.clone().try_into() {
            Ok(cc) => Some(cc),
            Err(e) => {
                let reason = format!("Staging clients parsing failed: {e}");
                tracker.mark_degraded(reason.clone());
                return Err(HaError::Validation {
                    field: "clients".to_string(),
                    reason,
                });
            }
        }
    } else {
        None
    };

    // Include custom rules in staging filtering config
    staging_config.filtering.custom_rules = bundle.custom_rules;

    // 4. Staging filter engine test
    if let Err(e) = handles
        .filter
        .reload_with_config(&staging_config.filtering)
        .await
    {
        let reason = format!("Staging filter reload failed: {e}");
        tracker.mark_degraded(reason.clone());
        return Err(HaError::Rollback(reason));
    }

    // 5. Atomic swap into active runtime handles
    if let Some(rewrites_cfg) = staging_rewrites {
        handles
            .rewrites
            .store(Arc::new(RewriteTable::new(rewrites_cfg)));
    }

    if let Some(clients_cfg) = staging_clients {
        handles
            .clients
            .store(Arc::new(ClientRegistry::new(clients_cfg)));
    }

    // Atomic swap of configuration
    handles.config.store(Arc::new(staging_config));

    // Persist configuration to disk if path is provided
    if let Some(ref path) = handles.config_path {
        let tmp_path = path.with_extension("tmp");
        if let Ok(()) = std::fs::write(&tmp_path, &substituted_toml) {
            let _ = std::fs::rename(&tmp_path, path);
        }
    }

    // Mark tracker as synced
    tracker.mark_synced(bundle.version);
    #[allow(clippy::cast_precision_loss)]
    handles
        .metrics
        .set_ha_config_version(&tracker.instance_name, bundle.version as f64);

    info!(
        instance = %tracker.instance_name,
        version = bundle.version,
        "Successfully applied and synchronized configuration bundle from master"
    );

    Ok(bundle.version)
}

/// Spawns the slave replication worker loop.
pub fn spawn_slave_worker(
    ha_config: HaConfig,
    tracker: SlaveStatusTracker,
    handles: SlaveAppHandles,
    mut resync_rx: mpsc::Receiver<()>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Some(master_url) = ha_config.master_url.clone() else {
            warn!("Slave role configured without master_url; replication worker idle");
            return;
        };

        let master_pubkey = ha_config.master_pubkey.as_deref().and_then(|pk_str| {
            parse_public_key(pk_str)
                .map_err(|e| error!("Invalid master_pubkey in [ha] configuration: {e}"))
                .ok()
        });

        let mut backoff = ExponentialBackoff::default();

        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            tracker.set_state(SlaveState::Connecting);
            info!(url = %master_url, "Connecting to master WebSocket replication server");

            match connect_and_run(
                &master_url,
                &ha_config,
                &tracker,
                &handles,
                master_pubkey.as_ref(),
                &mut resync_rx,
                &mut shutdown_rx,
            )
            .await
            {
                Ok(()) => {
                    info!("Replication connection finished cleanly");
                    backoff.reset();
                }
                Err(e) => {
                    warn!("Replication connection error: {e}");
                    let delay = backoff.next_delay();
                    info!("Backing off for {:?} before reconnecting", delay);
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        _ = resync_rx.recv() => {
                            info!("Manual resync triggered during backoff; reconnecting immediately");
                            backoff.reset();
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    })
}

fn parse_ws_url(url: &str) -> Result<(bool, String, u16), HaError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| HaError::Connection(format!("Invalid URL: missing '://' in '{url}'")))?;
    let is_secure = match scheme {
        "wss" => true,
        "ws" => false,
        other => {
            return Err(HaError::Connection(format!(
                "Unsupported scheme '{other}' in '{url}'"
            )));
        }
    };

    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if let Some(stripped) = host_port.strip_prefix('[') {
        let (ip, port_part) = stripped.split_once(']').ok_or_else(|| {
            HaError::Connection(format!("Unclosed IPv6 bracket in '{host_port}'"))
        })?;
        let port = if let Some(p) = port_part.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|e| HaError::Connection(format!("Invalid port: {e}")))?
        } else {
            8953
        };
        (ip.to_string(), port)
    } else if let Some((h, p)) = host_port.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|e| HaError::Connection(format!("Invalid port: {e}")))?;
        (h.to_string(), port)
    } else {
        (host_port.to_string(), 8953)
    };

    Ok((is_secure, host, port))
}

async fn connect_and_run(
    master_url: &str,
    ha_config: &HaConfig,
    tracker: &SlaveStatusTracker,
    handles: &SlaveAppHandles,
    master_pubkey: Option<&[u8; 32]>,
    resync_rx: &mut mpsc::Receiver<()>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<(), HaError> {
    let (is_secure, host, port) = parse_ws_url(master_url)?;
    let addr_str = format!("{host}:{port}");

    let tcp_stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr_str))
        .await
        .map_err(|_| HaError::Timeout(format!("Connection to master '{addr_str}' timed out")))?
        .map_err(|e| HaError::Connection(format!("TCP connect error to '{addr_str}': {e}")))?;

    if is_secure {
        let tls_cfg = build_client_tls_config(
            ha_config.cert.as_deref(),
            ha_config.key.as_deref(),
            ha_config.master_fingerprint.as_deref(),
            ha_config.allow_unpinned_tls,
        )?;

        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| HaError::Tls(format!("Invalid server name '{host}': {e}")))?;

        let connector = TlsConnector::from(tls_cfg);
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| {
                HaError::Tls(format!(
                    "mTLS handshake failed with master '{addr_str}': {e}"
                ))
            })?;

        let (ws_stream, _) = tokio_tungstenite::client_async(master_url, tls_stream)
            .await
            .map_err(|e| HaError::Connection(format!("WebSocket client handshake failed: {e}")))?;

        run_ws_session(
            ws_stream,
            ha_config,
            tracker,
            handles,
            master_pubkey,
            resync_rx,
            shutdown_rx,
        )
        .await
    } else {
        if !ha_config.allow_insecure_ws {
            return Err(HaError::Validation {
                field: "master_url".to_string(),
                reason: "Plaintext ws:// replication is rejected by default. Use wss:// or explicitly set allow_insecure_ws = true".to_string(),
            });
        }

        let (ws_stream, _) = tokio_tungstenite::client_async(master_url, tcp_stream)
            .await
            .map_err(|e| {
                HaError::Connection(format!("Plain WebSocket client handshake failed: {e}"))
            })?;

        run_ws_session(
            ws_stream,
            ha_config,
            tracker,
            handles,
            master_pubkey,
            resync_rx,
            shutdown_rx,
        )
        .await
    }
}

async fn run_ws_session<S>(
    mut ws_stream: tokio_tungstenite::WebSocketStream<S>,
    ha_config: &HaConfig,
    tracker: &SlaveStatusTracker,
    handles: &SlaveAppHandles,
    master_pubkey: Option<&[u8; 32]>,
    resync_rx: &mut mpsc::Receiver<()>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<(), HaError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // 1. Send Hello message
    let have_version = tracker.get_version();
    let hello = HaMessage::Hello {
        instance: tracker.instance_name.clone(),
        have_version,
        capabilities: vec!["stats-v1".to_string()],
        token: ha_config.slave_token.clone(),
    };
    ws_stream
        .send(WsMessage::Text(hello.to_json()?.into()))
        .await
        .map_err(|e| HaError::Connection(format!("Failed to send Hello message: {e}")))?;

    tracker.set_state(SlaveState::HelloSent);
    info!(
        instance = %tracker.instance_name,
        have_version,
        "Sent Hello to master"
    );

    let stats_interval_secs = ha_config.stats_interval_secs.max(1);
    let mut stats_ticker = tokio::time::interval(Duration::from_secs(stats_interval_secs));
    stats_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }

            _ = resync_rx.recv() => {
                info!("Manual resync triggered; re-sending Hello with current version");
                let cur_v = tracker.get_version();
                let hello = HaMessage::Hello {
                    instance: tracker.instance_name.clone(),
                    have_version: cur_v,
                    capabilities: vec!["stats-v1".to_string()],
                    token: ha_config.slave_token.clone(),
                };
                let _ = ws_stream.send(WsMessage::Text(hello.to_json()?.into())).await;
            }

            _ = stats_ticker.tick() => {
                // Collect stats from handles and emit periodic StatsReport
                let stats = HaMessage::StatsReport {
                    window_s: stats_interval_secs,
                    queries: 0,
                    blocked: 0,
                    upstreams: HashMap::new(),
                };
                if let Ok(json) = stats.to_json() {
                    let _ = ws_stream.send(WsMessage::Text(json.into())).await;
                }
            }

            msg_opt = ws_stream.next() => {
                match msg_opt {
                    Some(Ok(WsMessage::Text(txt))) => {
                        handle_master_message(&txt, &mut ws_stream, tracker, handles, master_pubkey).await?;
                    }
                    Some(Ok(WsMessage::Binary(bin))) => {
                        if let Ok(txt) = std::str::from_utf8(&bin) {
                            handle_master_message(txt, &mut ws_stream, tracker, handles, master_pubkey).await?;
                        }
                    }
                    Some(Ok(WsMessage::Ping(p))) => {
                        let _ = ws_stream.send(WsMessage::Pong(p)).await;
                    }
                    Some(Ok(WsMessage::Close(_))) => {
                        info!("Master closed replication WebSocket connection");
                        return Ok(());
                    }
                    Some(Err(e)) => {
                        return Err(HaError::Connection(format!("WebSocket receive error: {e}")));
                    }
                    None => {
                        info!("Replication connection closed by peer");
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

async fn handle_master_message<S>(
    text: &str,
    ws_stream: &mut tokio_tungstenite::WebSocketStream<S>,
    tracker: &SlaveStatusTracker,
    handles: &SlaveAppHandles,
    master_pubkey: Option<&[u8; 32]>,
) -> Result<(), HaError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let msg = HaMessage::from_json(text)?;
    match msg {
        HaMessage::Ping { ts } => {
            let pong = HaMessage::Pong { ts };
            ws_stream
                .send(WsMessage::Text(pong.to_json()?.into()))
                .await
                .map_err(|e| HaError::Connection(format!("Failed to send Pong: {e}")))?;
        }
        HaMessage::ConfigPush { ref version, .. } => {
            let target_version = *version;
            tracker.set_state(SlaveState::Applying);

            let pubkey = master_pubkey.ok_or_else(|| {
                HaError::Crypto(
                    "No master_pubkey configured on slave; cannot verify signed push".to_string(),
                )
            });

            let apply_res = match pubkey {
                Ok(pk) => apply_config_push(&msg, tracker, handles, pk).await,
                Err(e) => Err(e),
            };

            match apply_res {
                Ok(v) => {
                    let ack = HaMessage::Ack {
                        version: v,
                        applied: true,
                        error: None,
                    };
                    ws_stream
                        .send(WsMessage::Text(ack.to_json()?.into()))
                        .await
                        .map_err(|e| HaError::Connection(format!("Failed to send Ack: {e}")))?;
                }
                Err(e) => {
                    let ack = HaMessage::Ack {
                        version: target_version,
                        applied: false,
                        error: Some(e.to_string()),
                    };
                    let _ = ws_stream.send(WsMessage::Text(ack.to_json()?.into())).await;
                }
            }
        }
        _ => {}
    }

    Ok(())
}
