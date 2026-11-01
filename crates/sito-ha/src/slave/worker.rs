//! Background slave replication worker and state apply coordinator.

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
use crate::protocol::{HaMessage, UpstreamReport};
use crate::slave::state::{SlaveState, SlaveStatusTracker};
use crate::transport::{ExponentialBackoff, build_client_tls_config};

/// Active server handles that the slave atomically updates when a new bundle is applied.
///
/// Config/clients/rewrites are published through [`RuntimeState`] so the query
/// pipeline observes them in the same coherent snapshot as the file watcher
/// and API paths do; the individual handles must not be written directly.
#[derive(Clone)]
pub struct SlaveAppHandles {
    pub runtime: Arc<sito_runtime::RuntimeState>,
    pub filter: Arc<HostsFilterEngine>,
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
    // Fail closed: a push referencing a secret this slave does not have must be
    // rejected rather than silently replacing credentials with empty strings.
    let substituted_toml = match substitute_secrets(&bundle.config_toml, &local_secrets, false) {
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

    // Staging clients validation if present. Per-client shared secrets are
    // stripped from replicated configuration; keep the node-local values.
    let mut staging_clients: Option<ClientsConfig> = if let Some(ref c_val) = bundle.clients {
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
    if let Some(ref mut clients) = staging_clients {
        for (name, secret) in local_client_id_secrets(handles.config_path.as_deref()) {
            clients.client_id_secrets.entry(name).or_insert(secret);
        }
    }

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

    // 5. Atomic swap into the coherent runtime snapshot. Publishing through
    // `RuntimeState::replace` keeps the pipeline from observing a torn mix of
    // old and new components (direct handle stores bypassed the snapshot).
    let current = handles.runtime.snapshot();
    let snapshot = sito_runtime::RuntimeSnapshot {
        config: Arc::new(staging_config),
        clients: staging_clients.map_or_else(
            || current.clients.clone(),
            |cfg| {
                Arc::new(ClientRegistry::with_routeros_leases(
                    cfg,
                    current.clients.routeros_leases_store(),
                ))
            },
        ),
        rewrites: staging_rewrites.map_or_else(
            || current.rewrites.clone(),
            |cfg| Arc::new(RewriteTable::new(cfg)),
        ),
    };
    handles.runtime.replace(snapshot);

    // Persist configuration to disk if path is provided. The pushed TOML can
    // contain substituted credentials, so write atomically with 0600. The
    // master's sanitized bundle has `[ha]` stripped and `instance_name`
    // removed; without merging the local replication settings back in, a
    // slave restart would boot without its master URL/pins and stop
    // replicating.
    if let Some(ref path) = handles.config_path {
        let persisted = merge_local_replication_config(&substituted_toml, path);
        if let Err(e) = write_private_atomic(path, &persisted) {
            error!(
                error = %e,
                path = %path.display(),
                "Failed to persist applied configuration to disk"
            );
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

/// Merges the slave's local replication settings into a pushed configuration
/// before it is persisted:
///
/// * `[ha]` (master URL, certificates, pins, token) is slave-local and is
///   removed by `sanitize_config_for_bundle` on the master.
/// * `server.instance_name` identifies this slave and is also removed on the
///   master.
/// * `server.data_dir` points at slave-local state and must not be replaced
///   by the master's path.
///
/// Returns the input unchanged when either TOML cannot be parsed.
fn merge_local_replication_config(pushed_toml: &str, local_path: &std::path::Path) -> String {
    let Ok(local_raw) = std::fs::read_to_string(local_path) else {
        return pushed_toml.to_string();
    };
    let (Ok(mut pushed), Ok(local)) = (
        pushed_toml.parse::<toml::Table>(),
        local_raw.parse::<toml::Table>(),
    ) else {
        return pushed_toml.to_string();
    };

    if let Some(ha) = local.get("ha") {
        pushed.insert("ha".to_string(), ha.clone());
    }
    if let (Some(toml::Value::Table(local_server)), Some(toml::Value::Table(server))) =
        (local.get("server"), pushed.get_mut("server"))
    {
        for key in ["instance_name", "data_dir"] {
            if let Some(value) = local_server.get(key) {
                server.insert(key.to_string(), value.clone());
            }
        }
    }
    // Per-client shared secrets and RouterOS credentials are stripped from the
    // replicated config; restore the node-local values so a restart keeps them.
    if let Some(secrets) = local
        .get("clients")
        .and_then(|c| c.get("client_id_secrets"))
        && let Some(toml::Value::Table(clients)) = pushed.get_mut("clients")
    {
        clients.insert("client_id_secrets".to_string(), secrets.clone());
    }
    if let Some(local_credentials) = local
        .get("integrations")
        .and_then(|i| i.get("mikrotik"))
        .and_then(toml::Value::as_table)
        && let Some(pushed_mikrotik) = pushed
            .get_mut("integrations")
            .and_then(|i| i.as_table_mut())
            .and_then(|i| i.get_mut("mikrotik"))
            .and_then(toml::Value::as_table_mut)
    {
        for key in ["token", "password"] {
            if let Some(value) = local_credentials.get(key) {
                pushed_mikrotik.insert(key.to_string(), value.clone());
            }
        }
    }

    toml::to_string_pretty(&pushed).unwrap_or_else(|_| pushed_toml.to_string())
}

/// Reads the node-local `[clients] client_id_secrets` table (name -> secret).
fn local_client_id_secrets(path: Option<&std::path::Path>) -> HashMap<String, String> {
    let Some(path) = path else {
        return HashMap::new();
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    let Ok(table) = raw.parse::<toml::Table>() else {
        return HashMap::new();
    };
    table
        .get("clients")
        .and_then(|clients| clients.get("client_id_secrets"))
        .and_then(toml::Value::as_table)
        .map(|secrets| {
            secrets
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .as_str()
                        .map(|secret| (name.clone(), secret.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Atomically writes `contents` to `path`, restricting permissions to the
/// owner on Unix. Used for pushed configuration that may embed credentials.
fn write_private_atomic(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    let tmp_path = path.with_extension("tmp");
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, contents)?;
    }
    std::fs::rename(&tmp_path, path)
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
        // Tracks whether the resync channel still has senders; a closed channel
        // returns `None` immediately and would otherwise busy-spin the select.
        let mut resync_open = true;

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
                    // Avoid a tight reconnect loop when the master accepts and
                    // immediately closes the connection.
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_secs(1)) => {}
                        msg = resync_rx.recv(), if resync_open => {
                            if msg.is_none() {
                                resync_open = false;
                            } else {
                                info!("Manual resync triggered; reconnecting immediately");
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Replication connection error: {e}");
                    let delay = backoff.next_delay();
                    info!("Backing off for {:?} before reconnecting", delay);
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        msg = resync_rx.recv(), if resync_open => {
                            if msg.is_none() {
                                resync_open = false;
                            } else {
                                info!("Manual resync triggered during backoff; reconnecting immediately");
                                backoff.reset();
                            }
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
            ha_config.ca.as_deref(),
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
        role: Some("slave".to_string()),
        protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
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
    let mut stats_ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(stats_interval_secs),
        Duration::from_secs(stats_interval_secs),
    );
    stats_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let (mut last_queries, mut last_blocked) = handles.metrics.get_queries_and_blocked();
    // See `spawn_slave_worker`: a closed channel must disable the branch
    // instead of resolving `None` forever.
    let mut resync_open = true;

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }

            msg = resync_rx.recv(), if resync_open => {
                if msg.is_none() {
                    resync_open = false;
                    continue;
                }
                info!("Manual resync triggered; re-sending Hello with current version");
                let cur_v = tracker.get_version();
                let hello = HaMessage::Hello {
                    instance: tracker.instance_name.clone(),
                    have_version: cur_v,
                    capabilities: vec!["stats-v1".to_string()],
                    token: ha_config.slave_token.clone(),
                    role: Some("slave".to_string()),
                    protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
                };
                let _ = ws_stream.send(WsMessage::Text(hello.to_json()?.into())).await;
            }

            _ = stats_ticker.tick() => {
                // Collect stats from handles and emit periodic StatsReport
                let (total_q, total_b) = handles.metrics.get_queries_and_blocked();
                let queries = total_q.saturating_sub(last_queries);
                let blocked = total_b.saturating_sub(last_blocked);
                last_queries = total_q;
                last_blocked = total_b;

                let upstream_reports = handles.metrics.get_upstream_reports();
                let mut upstreams = HashMap::new();
                for (name, (rtt_ms, errors)) in upstream_reports {
                    upstreams.insert(name, UpstreamReport { rtt_ms, errors });
                }

                let stats = HaMessage::StatsReport {
                    window_s: stats_interval_secs,
                    queries,
                    blocked,
                    upstreams,
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

            // Already at (or ahead of) this version: acknowledge without
            // re-applying. The master always pushes on connect.
            if target_version <= tracker.get_version() {
                let ack = HaMessage::Ack {
                    version: tracker.get_version(),
                    applied: true,
                    error: None,
                };
                ws_stream
                    .send(WsMessage::Text(ack.to_json()?.into()))
                    .await
                    .map_err(|e| HaError::Connection(format!("Failed to send Ack: {e}")))?;
                return Ok(());
            }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_local_replication_config_preserves_ha_and_identity() {
        let dir = std::env::temp_dir().join(format!("sito_ha_merge_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");

        let local = r#"
config_version = 1

[server]
role = "slave"
instance_name = "slave-1"
data_dir = "/var/lib/sito"

[ha]
master_url = "wss://master.example:8953"
master_pubkey = "abc123"
cert = "/etc/sito/slave.crt"
key = "/etc/sito/slave.key"

[clients]
client_id_secrets = { "kids-tablet" = "s3cret-value" }

[integrations.mikrotik]
url = "https://192.168.1.1"
password = "routeros-password"
"#;
        std::fs::write(&path, local).unwrap();

        // Sanitized bundle from the master: no [ha], no instance_name, no
        // client secrets and no RouterOS password.
        let pushed = r#"
config_version = 1

[server]
role = "slave"
data_dir = "/var/lib/sito-master"

[clients]

[integrations.mikrotik]
url = "https://192.168.1.1"
"#;

        let merged = merge_local_replication_config(pushed, &path);
        let table: toml::Table = merged.parse().unwrap();

        let ha = table.get("ha").expect("[ha] must be preserved");
        assert_eq!(
            ha.get("master_url").and_then(toml::Value::as_str),
            Some("wss://master.example:8953")
        );
        let server = table.get("server").unwrap();
        assert_eq!(
            server.get("instance_name").and_then(toml::Value::as_str),
            Some("slave-1")
        );
        assert_eq!(
            server.get("data_dir").and_then(toml::Value::as_str),
            Some("/var/lib/sito")
        );
        assert_eq!(
            server.get("role").and_then(toml::Value::as_str),
            Some("slave")
        );
        assert_eq!(
            table
                .get("clients")
                .and_then(|c| c.get("client_id_secrets"))
                .and_then(|s| s.get("kids-tablet"))
                .and_then(toml::Value::as_str),
            Some("s3cret-value"),
            "node-local client secrets must survive a push"
        );
        assert_eq!(
            table
                .get("integrations")
                .and_then(|i| i.get("mikrotik"))
                .and_then(|m| m.get("password"))
                .and_then(toml::Value::as_str),
            Some("routeros-password"),
            "node-local RouterOS credentials must survive a push"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_local_client_id_secrets_reads_table() {
        let dir = std::env::temp_dir().join(format!("sito_ha_secrets_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "[clients]\nclient_id_secrets = { \"phone\" = \"abc\" }\n",
        )
        .unwrap();
        let secrets = local_client_id_secrets(Some(&path));
        assert_eq!(secrets.get("phone").map(String::as_str), Some("abc"));
        assert!(local_client_id_secrets(None).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_merge_local_replication_config_without_local_file_is_noop() {
        let pushed = "config_version = 1\n[server]\nrole = \"slave\"\n";
        let merged = merge_local_replication_config(
            pushed,
            std::path::Path::new("/nonexistent/config.toml"),
        );
        assert_eq!(merged, pushed);
    }
}
