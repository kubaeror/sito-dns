//! Background slave replication worker and state apply coordinator.

use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{error, info, warn};

use sito_clients::{ClientRegistry, ClientsConfig};
use sito_core::config::{Config, FilterListConfig};
use sito_filter::HostsFilterEngine;
use sito_rewrites::{RewriteTable, RewritesConfig};
use sito_stats::MetricsRegistry;
use sito_stats::metrics::MetricsSnapshot;

use crate::bundle::{ConfigBundle, substitute_secrets, verify_and_unpack_push};
use crate::config::HaConfig;
use crate::crypto::parse_public_key;
use crate::error::HaError;
use crate::protocol::{HaMessage, UpstreamReport};
use crate::slave::state::{SlaveState, SlaveStatusTracker};
use crate::transport::{
    ExponentialBackoff, SLAVE_HANDSHAKE_TIMEOUT, build_client_tls_config, ws_config,
};

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
/// Implements rollback safety: if staging verification, validation or the
/// atomic persist fails, the previous configuration stays live, the state
/// transitions to `Degraded`, and an error is returned (the caller then ACKs
/// `applied: false`). Persisting happens before the push is acknowledged, so a
/// push is never reported as applied when it is not durable.
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

    // 2. Secret substitution. Placeholders resolve from the process
    // environment only (`DNSD_SECRET_<NAME>`, then `<NAME>`); there is no
    // on-disk local secret store. Fail closed: a push referencing a secret
    // this slave does not have must be rejected rather than silently replacing
    // credentials with empty strings.
    let substituted_toml = match substitute_secrets(&bundle.config_toml, &HashMap::new(), false) {
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

    // The structured bundle fields are authoritative: a `null` `rewrites`
    // value means "remove the local rewrites", not "keep the previous ones".
    // The same decision is applied to the live runtime and to the persisted
    // file below so a restart observes exactly what was applied.
    let staging_rewrites: Option<RewritesConfig> = match bundle.rewrites {
        Some(ref r_val) => match r_val.clone().try_into() {
            Ok(rc) => Some(rc),
            Err(e) => {
                let reason = format!("Staging rewrites parsing failed: {e}");
                tracker.mark_degraded(reason.clone());
                return Err(HaError::Validation {
                    field: "rewrites".to_string(),
                    reason,
                });
            }
        },
        None => None,
    };

    // Staging clients validation if present. Per-client shared secrets are
    // stripped from replicated configuration; keep the node-local values.
    let mut staging_clients: Option<ClientsConfig> = match bundle.clients {
        Some(ref c_val) => match c_val.clone().try_into() {
            Ok(cc) => Some(cc),
            Err(e) => {
                let reason = format!("Staging clients parsing failed: {e}");
                tracker.mark_degraded(reason.clone());
                return Err(HaError::Validation {
                    field: "clients".to_string(),
                    reason,
                });
            }
        },
        None => None,
    };
    if let Some(ref mut clients) = staging_clients {
        for (name, secret) in read_local_client_id_secrets(handles.config_path.as_deref()).await {
            clients.client_id_secrets.entry(name).or_insert(secret);
        }
    }

    // Mirror the authoritative fields into the parsed Config so the snapshot,
    // the filter engine and the persisted file cannot disagree.
    staging_config.clients = match staging_clients {
        Some(ref clients) => {
            Some(
                toml::Value::try_from(clients).map_err(|e| HaError::Validation {
                    field: "clients".to_string(),
                    reason: format!("Failed to serialize staged clients configuration: {e}"),
                })?,
            )
        }
        None => None,
    };
    staging_config.rewrites.clone_from(&bundle.rewrites);
    staging_config
        .filtering
        .custom_rules
        .clone_from(&bundle.custom_rules);
    staging_config.filtering.lists = bundle
        .lists
        .iter()
        .map(|meta| FilterListConfig {
            name: meta.name.clone(),
            url: meta.url.clone(),
            enabled: meta.enabled,
            refresh_hours: meta.refresh_hours,
        })
        .collect();

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

    // 5. Persist before the configuration becomes live or is acknowledged. A
    // failed atomic write is an apply failure: never advance the applied
    // watermark or ACK `applied: true` for a push that is not durable. The
    // local `[ha]`/identity settings are merged back in.
    if let Some(ref path) = handles.config_path {
        let persisted = build_persisted_config(
            &substituted_toml,
            &bundle,
            path,
            staging_config.clients.clone(),
        )
        .await;
        if let Err(e) = write_private_atomic(path, &persisted).await {
            let reason = format!(
                "Failed to persist applied configuration to '{}': {e}",
                path.display()
            );
            error!(
                error = %e,
                path = %path.display(),
                "Failed to persist pushed configuration; refusing to acknowledge the push"
            );
            tracker.mark_degraded(reason.clone());
            return Err(HaError::Rollback(reason));
        }
    }

    // 6. Atomic swap into the coherent runtime snapshot. Publishing through
    // `RuntimeState::replace` keeps the pipeline from observing a torn mix of
    // old and new components (direct handle stores bypassed the snapshot).
    // An absent `clients`/`rewrites` bundle field removes the component
    // (authoritative removal), matching the persisted file.
    let current = handles.runtime.snapshot();
    let snapshot = sito_runtime::RuntimeSnapshot {
        config: Arc::new(staging_config),
        clients: staging_clients.map_or_else(
            || Arc::new(ClientRegistry::new(Default::default())),
            |cfg| {
                Arc::new(ClientRegistry::with_routeros_leases(
                    cfg,
                    current.clients.routeros_leases_store(),
                ))
            },
        ),
        rewrites: staging_rewrites.map_or_else(
            || Arc::new(RewriteTable::new(Default::default())),
            |cfg| Arc::new(RewriteTable::new(cfg)),
        ),
    };
    handles.runtime.replace(snapshot);

    // Mark tracker as synced (a successful apply is the only path that clears
    // a `Degraded` state).
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

/// Builds the TOML document that is persisted after a successful push.
///
/// Merges slave-local state back into the pushed configuration:
///
/// * `[ha]` (master URL, certificates, pins, token) is slave-local and is
///   removed by `sanitize_config_for_bundle` on the master.
/// * `server.instance_name`/`server.data_dir` identify this node and must not
///   be replaced by the master's values.
/// * `[integrations.mikrotik]` credentials are stripped from the replicated
///   configuration and restored from the local file.
///
/// The structured bundle fields (`clients`, `rewrites`, `lists`,
/// `custom_rules`) are authoritative: a missing field removes the
/// corresponding configuration instead of keeping the previous copy, so the
/// persisted file matches the runtime snapshot exactly. Returns the pushed
/// TOML unchanged when it cannot be parsed.
async fn build_persisted_config(
    pushed_toml: &str,
    bundle: &ConfigBundle,
    local_path: &std::path::Path,
    clients_value: Option<toml::Value>,
) -> String {
    let Ok(mut pushed) = pushed_toml.parse::<toml::Table>() else {
        return pushed_toml.to_string();
    };
    let local = tokio::fs::read_to_string(local_path)
        .await
        .ok()
        .and_then(|raw| raw.parse::<toml::Table>().ok());

    if let Some(ref local) = local {
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
    }

    // Authoritative removal: the bundle's structured fields decide whether the
    // section exists at all. `clients_value` already includes the node-local
    // `client_id_secrets` merged back in.
    match clients_value {
        Some(value) => {
            pushed.insert("clients".to_string(), value);
        }
        None => {
            pushed.remove("clients");
        }
    }
    match bundle.rewrites {
        Some(ref value) => {
            pushed.insert("rewrites".to_string(), value.clone());
        }
        None => {
            pushed.remove("rewrites");
        }
    }
    if pushed.contains_key("filtering")
        || !bundle.custom_rules.is_empty()
        || !bundle.lists.is_empty()
    {
        let filtering = pushed
            .entry("filtering".to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if let toml::Value::Table(filtering) = filtering {
            filtering.insert(
                "custom_rules".to_string(),
                toml::Value::Array(
                    bundle
                        .custom_rules
                        .iter()
                        .map(|r| toml::Value::String(r.clone()))
                        .collect(),
                ),
            );
            match toml::Value::try_from(&bundle.lists) {
                Ok(lists) => {
                    filtering.insert("lists".to_string(), lists);
                }
                Err(e) => {
                    warn!(error = %e, "Failed to serialize bundle list metadata; keeping pushed lists");
                }
            }
        }
    }

    toml::to_string_pretty(&pushed).unwrap_or_else(|_| pushed_toml.to_string())
}

/// Reads the node-local `[clients] client_id_secrets` table (name -> secret).
async fn read_local_client_id_secrets(path: Option<&std::path::Path>) -> HashMap<String, String> {
    let Some(path) = path else {
        return HashMap::new();
    };
    let Ok(raw) = tokio::fs::read_to_string(path).await else {
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
///
/// Uses `tokio::fs` so the async apply path never blocks a runtime worker.
async fn write_private_atomic(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let tmp_path = path.with_extension("tmp");
    #[cfg(unix)]
    {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .await?;
        file.write_all(contents.as_bytes()).await?;
        file.sync_all().await?;
    }
    #[cfg(not(unix))]
    {
        tokio::fs::write(&tmp_path, contents).await?;
    }
    tokio::fs::rename(&tmp_path, path).await
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

            // A previously failed apply stays visible while reconnecting: the
            // `Degraded` state (and its reason) is only cleared by a successful
            // apply or an early ACK for the version already running.
            if tracker.get_state() != SlaveState::Degraded {
                tracker.set_state(SlaveState::Connecting);
            }
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
        let tls_stream = tokio::time::timeout(
            SLAVE_HANDSHAKE_TIMEOUT,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| {
            HaError::Timeout(format!(
                "mTLS handshake with master '{addr_str}' timed out after {SLAVE_HANDSHAKE_TIMEOUT:?}"
            ))
        })?
        .map_err(|e| {
            HaError::Tls(format!(
                "mTLS handshake failed with master '{addr_str}': {e}"
            ))
        })?;

        let (ws_stream, _) = tokio::time::timeout(
            SLAVE_HANDSHAKE_TIMEOUT,
            tokio_tungstenite::client_async_with_config(master_url, tls_stream, Some(ws_config())),
        )
        .await
        .map_err(|_| {
            HaError::Timeout(format!(
                "WebSocket handshake with master '{addr_str}' timed out after {SLAVE_HANDSHAKE_TIMEOUT:?}"
            ))
        })?
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

        let (ws_stream, _) = tokio::time::timeout(
            SLAVE_HANDSHAKE_TIMEOUT,
            tokio_tungstenite::client_async_with_config(master_url, tcp_stream, Some(ws_config())),
        )
        .await
        .map_err(|_| {
            HaError::Timeout(format!(
                "Plain WebSocket handshake with '{addr_str}' timed out after {SLAVE_HANDSHAKE_TIMEOUT:?}"
            ))
        })?
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
    // Registry counters are lifetime totals: remember the previous snapshot
    // and report window-scoped deltas instead of mislabelling lifetime values
    // as a `window_s` measurement. `window_started_at` tracks the real length
    // of each reporting window (which can exceed the ticker interval when the
    // session loop is delayed).
    let mut window_started_at = Instant::now();
    let mut last_stats_snapshot = handles.metrics.snapshot();
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
                // Report the activity observed since the previous report; the
                // registry only exposes lifetime totals and lifetime upstream
                // RTT accumulators.
                let window_s = window_started_at.elapsed().as_secs().max(1);
                window_started_at = Instant::now();
                let (stats, snapshot) =
                    build_stats_report(&handles.metrics, &last_stats_snapshot, window_s);
                last_stats_snapshot = snapshot;
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

/// Builds a window-scoped stats report from the registry and the snapshot
/// taken at the previous report.
///
/// The registry only exposes lifetime counters and lifetime upstream RTT
/// accumulators; sending those under a `window_s` label would misreport them
/// as recent activity (audit WP-7.3). The report therefore carries deltas
/// since the previous report, including per-upstream RTT samples and upstream
/// error counts. Returns the message to send and the snapshot to pass to the
/// next call.
fn build_stats_report(
    metrics: &MetricsRegistry,
    previous: &MetricsSnapshot,
    window_s: u64,
) -> (HaMessage, MetricsSnapshot) {
    let snapshot = metrics.snapshot();
    let delta = snapshot.delta_since(previous);

    let mut upstreams = HashMap::with_capacity(delta.upstreams.len());
    for (name, upstream) in &delta.upstreams {
        upstreams.insert(
            name.clone(),
            UpstreamReport {
                rtt_ms: upstream.mean_rtt_ms(),
                errors: upstream.errors,
            },
        );
    }

    (
        HaMessage::StatsReport {
            window_s,
            queries: delta.queries,
            blocked: delta.blocked,
            upstreams,
        },
        snapshot,
    )
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
                // The connection is fully synchronized: reflect that instead of
                // leaving the state at `hello_sent`. A `Degraded` state is only
                // cleared by a successful apply, so an early ACK for the
                // already-running version must not clear it.
                if tracker.get_state() != SlaveState::Degraded {
                    tracker.mark_synced(tracker.get_version());
                }
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
    use crate::bundle::build_and_sign_push;

    async fn test_handles(config_path: Option<PathBuf>) -> SlaveAppHandles {
        let base_config = Config::default();
        let config_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(base_config.clone())));
        let filter_engine = Arc::new(
            HostsFilterEngine::init(base_config.filtering.clone(), std::env::temp_dir()).await,
        );
        let rewrites_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(RewriteTable::new(
            Default::default(),
        ))));
        let clients_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(ClientRegistry::new(
            Default::default(),
        ))));
        let runtime = Arc::new(sito_runtime::RuntimeState::new(
            config_arc,
            clients_arc,
            rewrites_arc,
        ));
        SlaveAppHandles {
            runtime,
            filter: filter_engine,
            metrics: MetricsRegistry::new("0.1.0", "slave"),
            config_path,
        }
    }

    fn test_bundle(
        version: u64,
        config_toml: &str,
        clients: Option<toml::Value>,
        rewrites: Option<toml::Value>,
    ) -> ConfigBundle {
        ConfigBundle {
            version,
            timestamp: 1,
            config_toml: config_toml.to_string(),
            custom_rules: vec!["||pushed-rule.example^".to_string()],
            rewrites,
            clients,
            lists: vec![],
        }
    }

    #[tokio::test]
    async fn test_persisted_config_preserves_ha_and_identity() {
        let dir = std::env::temp_dir().join(format!("sito_ha_merge_{}", rand::random::<u64>()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
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
        tokio::fs::write(&path, local).await.unwrap();

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

        let mut sanitized_clients = toml::Table::new();
        sanitized_clients.insert(
            "client_id_secrets".to_string(),
            toml::Value::Table({
                let mut t = toml::Table::new();
                t.insert(
                    "kids-tablet".to_string(),
                    toml::Value::String("s3cret-value".to_string()),
                );
                t
            }),
        );

        let bundle = test_bundle(2, pushed, Some(toml::Value::Table(sanitized_clients)), None);
        let merged = build_persisted_config(pushed, &bundle, &path, bundle.clients.clone()).await;
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

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn test_local_client_id_secrets_reads_table() {
        let dir = std::env::temp_dir().join(format!("sito_ha_secrets_{}", rand::random::<u64>()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("config.toml");
        tokio::fs::write(
            &path,
            "[clients]\nclient_id_secrets = { \"phone\" = \"abc\" }\n",
        )
        .await
        .unwrap();
        let secrets = read_local_client_id_secrets(Some(&path)).await;
        assert_eq!(secrets.get("phone").map(String::as_str), Some("abc"));
        assert!(read_local_client_id_secrets(None).await.is_empty());
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn test_persisted_config_without_local_file_keeps_pushed_sections() {
        let pushed = "config_version = 1\n[server]\nrole = \"slave\"\n";
        let mut bundle = test_bundle(1, pushed, None, None);
        bundle.custom_rules = vec![];
        let merged = build_persisted_config(
            pushed,
            &bundle,
            std::path::Path::new("/nonexistent/config.toml"),
            None,
        )
        .await;
        let table: toml::Table = merged.parse().unwrap();
        let expected: toml::Table = pushed.parse().unwrap();
        assert_eq!(
            table, expected,
            "a missing local file must not change the pushed configuration"
        );
    }

    /// Absent `clients`/`rewrites` in the bundle are authoritative removals:
    /// the runtime snapshot and the persisted file must agree (a restart must
    /// observe what was applied).
    #[tokio::test]
    async fn test_absent_clients_and_rewrites_are_removed_consistently() {
        let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
        let dir = std::env::temp_dir().join(format!("sito_ha_absent_{}", rand::random::<u64>()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("config.toml");
        tokio::fs::write(
            &path,
            "[server]\nrole = \"slave\"\ninstance_name = \"slave-absent\"\n\n[clients]\nentries = []\n\n[rewrites]\nttl = 60\n",
        )
        .await
        .unwrap();

        let tracker = SlaveStatusTracker::new("slave-absent".to_string(), 0, None);
        let handles = test_handles(Some(path.clone())).await;
        let before = handles.runtime.snapshot();

        let config_toml = r#"
config_version = 1

[server]
role = "slave"

[clients]
entries = []

[rewrites]
ttl = 60
"#;
        let push =
            build_and_sign_push(&test_bundle(1, config_toml, None, None), &signing_key).unwrap();
        let applied = apply_config_push(&push, &tracker, &handles, &signing_key.public_key())
            .await
            .unwrap();
        assert_eq!(applied, 1);
        assert_eq!(tracker.get_state(), SlaveState::Synced);

        // Runtime: the components were replaced (authoritative removal), not
        // kept from the previous snapshot, and the snapshot config no longer
        // carries the structured sections.
        let snapshot = handles.runtime.snapshot();
        assert!(!Arc::ptr_eq(&snapshot.clients, &before.clients));
        assert!(!Arc::ptr_eq(&snapshot.rewrites, &before.rewrites));
        assert!(snapshot.config.clients.is_none());
        assert!(snapshot.config.rewrites.is_none());
        assert_eq!(snapshot.config.filtering.custom_rules.len(), 1);

        // Disk: a restart loads the same (absent) sections.
        let persisted: toml::Table = tokio::fs::read_to_string(&path)
            .await
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            persisted.get("clients").is_none(),
            "absent clients must be removed from the persisted file"
        );
        assert!(
            persisted.get("rewrites").is_none(),
            "absent rewrites must be removed from the persisted file"
        );
        assert_eq!(
            persisted
                .get("server")
                .and_then(|s| s.get("instance_name"))
                .and_then(toml::Value::as_str),
            Some("slave-absent"),
            "node identity survives"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// A failed persist must not advance the version or ACK as applied; a
    /// later successful attempt applies the same push.
    #[tokio::test]
    async fn test_persist_failure_is_apply_failure_and_retry_succeeds() {
        let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
        let dir = std::env::temp_dir().join(format!("sito_ha_persist_{}", rand::random::<u64>()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        // Point at a path whose parent directory does not exist: the atomic
        // write must fail.
        let path = dir.join("missing").join("config.toml");

        let tracker = SlaveStatusTracker::new("slave-persist".to_string(), 0, None);
        tracker.set_state(SlaveState::Synced);
        let handles = test_handles(Some(path.clone())).await;

        let config_toml = "config_version = 1\n[server]\nrole = \"slave\"\n";
        let bundle = test_bundle(2, config_toml, None, None);
        let push = build_and_sign_push(&bundle, &signing_key).unwrap();

        let err = apply_config_push(&push, &tracker, &handles, &signing_key.public_key())
            .await
            .expect_err("persist failure must be reported as an apply failure");
        assert!(matches!(err, HaError::Rollback(_)));
        assert_eq!(tracker.get_state(), SlaveState::Degraded);
        assert_eq!(
            tracker.get_version(),
            0,
            "the applied-version watermark must not advance without a durable write"
        );
        assert!(
            handles
                .runtime
                .snapshot()
                .config
                .filtering
                .custom_rules
                .is_empty(),
            "runtime configuration must not be replaced when persistence fails"
        );

        // Repair the path and re-apply: the same push succeeds.
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        let applied = apply_config_push(&push, &tracker, &handles, &signing_key.public_key())
            .await
            .unwrap();
        assert_eq!(applied, 2);
        assert_eq!(tracker.get_state(), SlaveState::Synced);
        assert_eq!(tracker.get_version(), 2);
        assert_eq!(
            handles
                .runtime
                .snapshot()
                .config
                .filtering
                .custom_rules
                .len(),
            1
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// The early-ACK path must reach `Synced`, but it must never clear a
    /// `Degraded` state without a successful apply.
    #[tokio::test]
    async fn test_early_ack_marks_synced_but_keeps_degraded() {
        use tokio_tungstenite::tungstenite::protocol::Role;

        // Two raw WebSocket ends over a duplex pipe: the slave writes its ACK
        // on one end and the test reads it on the other.
        let (slave_socket, peer_socket) = tokio::io::duplex(64 * 1024);
        let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            slave_socket,
            Role::Client,
            Some(ws_config()),
        )
        .await;
        let mut peer = tokio_tungstenite::WebSocketStream::from_raw_socket(
            peer_socket,
            Role::Server,
            Some(ws_config()),
        )
        .await;
        let tracker = SlaveStatusTracker::new("slave-early".to_string(), 5, None);
        let handles = test_handles(None).await;
        let push = HaMessage::ConfigPush {
            version: 5,
            hash_blake3: "hash".to_string(),
            signature_ed25519: "sig".to_string(),
            payload_b64: "payload".to_string(),
            payload_hash_blake3: "hash".to_string(),
        };
        let text = push.to_json().unwrap();

        tracker.set_state(SlaveState::HelloSent);
        handle_master_message(&text, &mut ws, &tracker, &handles, None)
            .await
            .unwrap();
        assert_eq!(tracker.get_state(), SlaveState::Synced);
        assert_eq!(tracker.get_version(), 5);
        let ack = peer.next().await.unwrap().unwrap();
        let ack = HaMessage::from_json(&ack.into_text().unwrap()).unwrap();
        assert!(matches!(
            ack,
            HaMessage::Ack {
                version: 5,
                applied: true,
                ..
            }
        ));

        // Degraded is preserved by an early ACK (nothing was applied).
        tracker.mark_degraded("previous apply failed".to_string());
        handle_master_message(&text, &mut ws, &tracker, &handles, None)
            .await
            .unwrap();
        assert_eq!(tracker.get_state(), SlaveState::Degraded);
        assert_eq!(
            tracker.degraded_reason.lock().unwrap().as_deref(),
            Some("previous apply failed")
        );
    }

    /// A stalled peer must not pin the slave: the plaintext WebSocket
    /// handshake is bounded by `SLAVE_HANDSHAKE_TIMEOUT`.
    #[tokio::test(start_paused = true)]
    async fn test_stalled_websocket_handshake_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Accept and send nothing: the HTTP upgrade never completes.
        let stall = tokio::spawn(async move {
            let _conn = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });

        let ha_config = HaConfig {
            master_url: Some(format!("ws://127.0.0.1:{port}")),
            allow_insecure_ws: true,
            ..Default::default()
        };
        let tracker = SlaveStatusTracker::new("slave-stall".to_string(), 0, None);
        let handles = test_handles(None).await;
        let mut resync_rx = {
            let (_tx, rx) = mpsc::channel(1);
            rx
        };
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let started = tokio::time::Instant::now();
        let err = connect_and_run(
            ha_config.master_url.as_deref().unwrap(),
            &ha_config,
            &tracker,
            &handles,
            None,
            &mut resync_rx,
            &mut shutdown_rx,
        )
        .await
        .expect_err("stalled handshake must time out");
        assert!(
            matches!(err, HaError::Timeout(_)),
            "expected a timeout error, got {err:?}"
        );
        assert!(started.elapsed() >= SLAVE_HANDSHAKE_TIMEOUT);
        stall.abort();
    }

    /// A failed apply must survive reconnects: `Degraded` is not cleared by a
    /// new connection attempt, only by a successful apply.
    #[tokio::test]
    async fn test_degraded_state_survives_reconnect_attempts() {
        let port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let ha_config = HaConfig {
            master_url: Some(format!("ws://127.0.0.1:{port}")),
            allow_insecure_ws: true,
            ..Default::default()
        };
        let tracker = SlaveStatusTracker::new("slave-degraded".to_string(), 4, None);
        tracker.mark_degraded("previous apply failed".to_string());
        let handles = test_handles(None).await;
        let (_resync_tx, resync_rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let worker =
            spawn_slave_worker(ha_config, tracker.clone(), handles, resync_rx, shutdown_rx);

        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            tracker.get_state(),
            SlaveState::Degraded,
            "reconnecting must not clear a Degraded state"
        );
        assert_eq!(
            tracker.degraded_reason.lock().unwrap().as_deref(),
            Some("previous apply failed")
        );

        let _ = shutdown_tx.send(true);
        worker.abort();
    }

    /// The WebSocket codec cap applies to the slave too: an oversized push is
    /// rejected before it is parsed, not applied or ACKed.
    #[tokio::test]
    async fn test_slave_rejects_oversized_push() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let fake_master = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            // Read the Hello, then send a valid but oversized push.
            let _ = ws.next().await;
            let big = HaMessage::ConfigPush {
                version: 99,
                hash_blake3: "h".to_string(),
                signature_ed25519: "s".to_string(),
                payload_b64: "x".repeat(2 * 1024 * 1024),
                payload_hash_blake3: "h".to_string(),
            };
            let _ = ws
                .send(WsMessage::Text(big.to_json().unwrap().into()))
                .await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
        let ha_config = HaConfig {
            master_url: Some(format!("ws://127.0.0.1:{port}")),
            master_pubkey: Some(signing_key.public_key_hex()),
            allow_insecure_ws: true,
            ..Default::default()
        };
        let tracker = SlaveStatusTracker::new("slave-oversize".to_string(), 0, None);
        let handles = test_handles(None).await;
        let (_resync_tx, resync_rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let worker =
            spawn_slave_worker(ha_config, tracker.clone(), handles, resync_rx, shutdown_rx);

        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(
            !matches!(
                tracker.get_state(),
                SlaveState::Degraded | SlaveState::Synced
            ),
            "an oversized push must be rejected by the codec, not processed (state: {:?})",
            tracker.get_state()
        );
        assert_eq!(tracker.get_version(), 0);

        let _ = shutdown_tx.send(true);
        worker.abort();
        fake_master.abort();
    }

    /// The WP-5.1 end-to-end scenario: a realistic master config with a
    /// `[tls] key` path and structured `client_id_secrets` must replicate
    /// successfully (no unresolvable `${SECRET:tls_key}` placeholder) and the
    /// wire bundle must not carry the client secret.
    #[tokio::test]
    async fn test_push_with_tls_path_and_client_secrets_applies() {
        use crate::bundle::sanitize_config_for_bundle;

        let master_toml = r#"
config_version = 1

[server]
role = "master"
instance_name = "master-prod"

[ha]
replication_port = 8953

[tls]
cert = "/etc/sito/cert.pem"
key = "/etc/sito/tls.key"

[clients]
client_id_secrets = { "kids-tablet" = "client_shared_secret_9876" }
"#;
        let sanitized = sanitize_config_for_bundle(master_toml).unwrap();
        assert!(
            sanitized.contains("key = \"/etc/sito/tls.key\""),
            "the TLS key path must survive sanitization: {sanitized}"
        );
        assert!(!sanitized.contains("${SECRET:"));

        let mut secrets = toml::Table::new();
        secrets.insert(
            "kids-tablet".to_string(),
            toml::Value::String("client_shared_secret_9876".to_string()),
        );
        let mut clients = toml::Table::new();
        clients.insert("client_id_secrets".to_string(), toml::Value::Table(secrets));

        let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
        let bundle = ConfigBundle {
            clients: Some(toml::Value::Table(clients)),
            ..test_bundle(2, &sanitized, None, None)
        };
        let push = build_and_sign_push(&bundle, &signing_key).unwrap();

        let dir = std::env::temp_dir().join(format!("sito_ha_tls_{}", rand::random::<u64>()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("config.toml");
        // The slave keeps its node-local secret.
        tokio::fs::write(
            &path,
            "[server]\nrole = \"slave\"\ninstance_name = \"slave-tls\"\n\n[clients]\nclient_id_secrets = { \"kids-tablet\" = \"client_shared_secret_9876\" }\n",
        )
        .await
        .unwrap();

        let tracker = SlaveStatusTracker::new("slave-tls".to_string(), 0, None);
        let handles = test_handles(Some(path.clone())).await;
        apply_config_push(&push, &tracker, &handles, &signing_key.public_key())
            .await
            .expect("a config with a TLS key path and client secrets must replicate");
        assert_eq!(tracker.get_state(), SlaveState::Synced);

        // The persisted configuration keeps the node-local secret and the TLS
        // path, and a restart can parse it.
        let persisted: toml::Table = tokio::fs::read_to_string(&path)
            .await
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            persisted
                .get("tls")
                .and_then(|t| t.get("key"))
                .and_then(toml::Value::as_str),
            Some("/etc/sito/tls.key")
        );
        assert_eq!(
            persisted
                .get("clients")
                .and_then(|c| c.get("client_id_secrets"))
                .and_then(|s| s.get("kids-tablet"))
                .and_then(toml::Value::as_str),
            Some("client_shared_secret_9876"),
            "the node-local secret must be restored on the slave"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// `bundle.lists` is authoritative: the runtime filter engine and the
    /// persisted file both get the metadata carried by the bundle.
    #[tokio::test]
    async fn test_bundle_list_metadata_is_authoritative() {
        use crate::bundle::FilterListMetadata;

        let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
        let dir = std::env::temp_dir().join(format!("sito_ha_lists_{}", rand::random::<u64>()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("config.toml");
        // The local/pushed TOML has no lists at all.
        tokio::fs::write(&path, "[server]\nrole = \"slave\"\n")
            .await
            .unwrap();

        let tracker = SlaveStatusTracker::new("slave-lists".to_string(), 0, None);
        let handles = test_handles(Some(path.clone())).await;

        let mut bundle = test_bundle(
            1,
            "config_version = 1\n[server]\nrole = \"slave\"\n",
            None,
            None,
        );
        bundle.lists = vec![FilterListMetadata {
            name: "bundle-list".to_string(),
            url: "https://lists.example/hosts.txt".to_string(),
            enabled: true,
            refresh_hours: Some(12),
        }];
        let push = build_and_sign_push(&bundle, &signing_key).unwrap();
        apply_config_push(&push, &tracker, &handles, &signing_key.public_key())
            .await
            .unwrap();

        let snapshot = handles.runtime.snapshot();
        assert_eq!(snapshot.config.filtering.lists.len(), 1);
        assert_eq!(snapshot.config.filtering.lists[0].name, "bundle-list");
        assert_eq!(snapshot.config.filtering.lists[0].refresh_hours, Some(12));

        let persisted: toml::Table = tokio::fs::read_to_string(&path)
            .await
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            persisted
                .get("filtering")
                .and_then(|f| f.get("lists"))
                .and_then(toml::Value::as_array)
                .and_then(|lists| lists.first())
                .and_then(|list| list.get("name"))
                .and_then(toml::Value::as_str),
            Some("bundle-list"),
            "the persisted file must expose the bundle's list metadata"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// Regression for audit WP-7.3: the metrics registry only holds lifetime
    /// counters and lifetime upstream RTT accumulators, so a report labelled
    /// with `window_s` must carry deltas since the previous report instead of
    /// those lifetime values. Before the fix, `upstreams[*].rtt_ms`/`errors`
    /// were the lifetime mean/total, so the idle second window below would
    /// repeat them instead of reporting zero.
    #[test]
    fn test_stats_report_carries_window_deltas_not_lifetime_totals() {
        let metrics = MetricsRegistry::new("0.1.0", "test");

        // Activity before the first snapshot is outside every report window.
        metrics.inc_queries("udp", 1, "allowed");
        metrics.inc_queries("udp", 1, "blocked");
        metrics.observe_upstream_rtt("1.1.1.1:53", 0.020);
        metrics.inc_upstream_errors("1.1.1.1:53", "timeout");
        let initial = metrics.snapshot();

        // Window 1: three queries (one blocked), one 30 ms RTT sample, one error.
        metrics.inc_queries("udp", 1, "allowed");
        metrics.inc_queries("udp", 28, "allowed");
        metrics.inc_queries("udp", 1, "blocked");
        metrics.observe_upstream_rtt("1.1.1.1:53", 0.030);
        metrics.inc_upstream_errors("1.1.1.1:53", "timeout");

        let (report, snapshot) = build_stats_report(&metrics, &initial, 30);
        match &report {
            HaMessage::StatsReport {
                window_s,
                queries,
                blocked,
                upstreams,
            } => {
                assert_eq!(*window_s, 30);
                assert_eq!(
                    *queries, 3,
                    "only queries since the previous snapshot belong to the window"
                );
                assert_eq!(*blocked, 1);
                let upstream = upstreams.get("1.1.1.1:53").expect("upstream report");
                assert!(
                    (upstream.rtt_ms - 30.0).abs() < 1e-6,
                    "window mean must not mix in pre-window samples: {}",
                    upstream.rtt_ms
                );
                assert_eq!(upstream.errors, 1);
            }
            other => panic!("expected a StatsReport, got {other:?}"),
        }

        // Window 2: no new activity. The lifetime totals are still non-zero, so
        // a report built from them would fail every assertion below.
        let (report, _snapshot) = build_stats_report(&metrics, &snapshot, 30);
        match &report {
            HaMessage::StatsReport {
                queries,
                blocked,
                upstreams,
                ..
            } => {
                assert_eq!(*queries, 0);
                assert_eq!(*blocked, 0);
                let upstream = upstreams.get("1.1.1.1:53").expect("upstream report");
                assert!(
                    upstream.rtt_ms.abs() < f64::EPSILON,
                    "an idle window must report no RTT samples, got {}",
                    upstream.rtt_ms
                );
                assert_eq!(upstream.errors, 0);
            }
            other => panic!("expected a StatsReport, got {other:?}"),
        }
    }
}
