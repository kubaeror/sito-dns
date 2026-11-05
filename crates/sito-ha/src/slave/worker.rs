//! Background slave replication worker and state apply coordinator.

use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{error, info, warn};

use sito_clients::ClientsConfig;
use sito_core::config::{Config, FilterListConfig};
use sito_filter::HostsFilterEngine;
use sito_rewrites::RewritesConfig;
use sito_stats::MetricsRegistry;
use sito_stats::metrics::MetricsSnapshot;

use crate::bundle::{
    ConfigBundle, push_payload_hash, substitute_secrets, verify_and_unpack_push_with_watermark,
    watermark_covers,
};
use crate::config::HaConfig;
use crate::crypto::parse_public_key;
use crate::error::HaError;
use crate::protocol::{AckConflict, HaMessage, UpstreamReport};
use crate::slave::state::{SlaveState, SlaveStatusTracker};
use crate::transport::{
    ExponentialBackoff, SLAVE_HANDSHAKE_TIMEOUT, build_client_tls_config, ws_config,
};

/// Applies and persists a configuration pushed by the master.
///
/// Implemented by the `sito` binary on top of
/// `sito_api::config_apply::apply_and_persist_document`, so every component
/// (upstreams, filter, clients, rewrites, cache, query-log privacy, runtime
/// snapshot and the hook-owned DNSSEC/scoped-upstream/rate-limiter/listener/log
/// level pieces) is applied before a pushed bundle is acknowledged. The trait
/// lives here so `sito-ha` does not depend on `sito-api`.
pub trait SlaveConfigApplier: Send + Sync {
    /// Applies `cfg` to the live server and atomically persists `document`.
    ///
    /// On failure the live components must have been rolled back to the
    /// previous configuration and no document may have been persisted.
    fn apply_and_persist<'a>(
        &'a self,
        cfg: &'a Config,
        document: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// Active server handles that the slave atomically updates when a new bundle is applied.
///
/// Config/clients/rewrites are published through [`RuntimeState`] so the query
/// pipeline observes them in the same coherent snapshot as the file watcher
/// and API paths do; the individual handles must not be written directly.
/// [`SlaveAppHandles::applier`] is the single apply/persist path.
#[derive(Clone)]
pub struct SlaveAppHandles {
    pub runtime: Arc<sito_runtime::RuntimeState>,
    pub filter: Arc<HostsFilterEngine>,
    pub metrics: MetricsRegistry,
    pub config_path: Option<PathBuf>,
    pub applier: Arc<dyn SlaveConfigApplier>,
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
    let watermark = tracker.get_watermark();

    // 1. Verify cryptographic signature, checksum, term and monotonicity
    //    against the persisted watermark (not only the in-memory counter, so a
    //    process restart cannot lose the replay guard).
    let bundle =
        match verify_and_unpack_push_with_watermark(push, watermark.as_ref(), master_pubkey) {
            Ok(b) => b,
            Err(e) => {
                tracker.mark_degraded(format!("Validation/Signature verification failed: {e}"));
                return Err(e);
            }
        };
    let payload_hash = match push_payload_hash(push) {
        Ok(hash) => hash,
        Err(e) => {
            tracker.mark_degraded(format!("Validation/Signature verification failed: {e}"));
            return Err(e);
        }
    };

    // Before the first watermark exists (fresh node or a test harness), fall
    // back to the in-memory applied version so the monotonicity guard is not
    // weakened by the watermark refactor.
    if watermark.is_none() && bundle.version <= tracker.get_version() {
        let err = HaError::Validation {
            field: "version".to_string(),
            reason: format!(
                "Push version {} is not greater than the current applied version {} (monotonicity violation/replay rejected)",
                bundle.version,
                tracker.get_version()
            ),
        };
        tracker.mark_degraded(format!("Validation/Signature verification failed: {err}"));
        return Err(err);
    }

    // An identical re-delivery of the already-applied bundle needs no work and
    // must not rewrite local configuration; acknowledge it as synced. A newer
    // term with the same payload only records the promoted epoch.
    if let Some(ref applied) = watermark
        && bundle.version == applied.version
        && payload_hash == applied.normalized_hash()
    {
        if bundle.term > applied.term {
            tracker.persist_watermark(bundle.version, bundle.term, &payload_hash)?;
        }
        tracker.mark_synced_with_term(bundle.version, bundle.term);
        return Ok(bundle.version);
    }

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
    // Validate the typed rewrites here; the raw value is copied verbatim into
    // the applied/persisted configuration below so a restart observes exactly
    // what was applied.
    let _staging_rewrites: Option<RewritesConfig> = match bundle.rewrites {
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
    // Node-local state is read from the live runtime snapshot, not re-read
    // from disk: the file may be unreadable or mid-edit, and the running
    // configuration is the authoritative node-local state.
    let live_config = handles.runtime.config_handle().load_full();
    if let Some(ref mut clients) = staging_clients {
        for (name, secret) in local_client_id_secrets(&live_config) {
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

    // 4. Build the document that will be persisted. Node-local settings
    //    (`[ha]`, instance identity, RouterOS credentials) are merged back in,
    //    and the bundle's structured clients/rewrites/lists remain
    //    authoritative. Applying exactly this document guarantees the running
    //    configuration and the file a restart loads cannot diverge.
    let document = match build_persisted_config(
        &substituted_toml,
        &bundle,
        handles.config_path.as_deref(),
        &live_config,
        staging_config.clients.clone(),
    )
    .await
    {
        Ok(document) => document,
        Err(e) => {
            let reason = format!(
                "Refusing to persist pushed configuration without the node-local configuration: {e}"
            );
            error!(error = %e, "Refusing to apply pushed configuration");
            tracker.mark_degraded(reason.clone());
            return Err(HaError::Rollback(reason));
        }
    };
    let apply_config = match Config::from_toml_str(&document) {
        Ok(cfg) => cfg,
        Err(e) => {
            let reason = format!("Merged pushed configuration is invalid: {e}");
            tracker.mark_degraded(reason.clone());
            return Err(HaError::Validation {
                field: "config".to_string(),
                reason,
            });
        }
    };

    // 5. Single apply/persist path. The applier applies every component
    //    (including the hook-owned DNSSEC/listener/scoped-upstream pieces) and
    //    persists the document atomically. It rolls the in-memory apply back
    //    when the persist fails, so on `Err` nothing has changed durably or
    //    live, the version does not advance, and the caller ACKs
    //    `applied: false`.
    if let Err(e) = handles
        .applier
        .apply_and_persist(&apply_config, &document)
        .await
    {
        let reason = format!("Failed to apply pushed configuration: {e}");
        error!(
            error = %e,
            "Failed to apply pushed configuration; refusing to acknowledge the push"
        );
        tracker.mark_degraded(reason.clone());
        return Err(HaError::Rollback(reason));
    }

    // Persist the applied-version watermark before acknowledging: a crash
    // between apply and ACK must still leave a restart able to reject replays.
    if let Err(e) = tracker.persist_watermark(bundle.version, bundle.term, &payload_hash) {
        let reason = format!("Failed to persist the applied-version watermark: {e}");
        error!(
            error = %e,
            version = bundle.version,
            "Configuration was applied but the watermark could not be persisted; refusing to acknowledge"
        );
        tracker.mark_degraded(reason.clone());
        return Err(HaError::Rollback(reason));
    }

    // Mark tracker as synced (a successful apply is the only path that clears
    // a `Degraded` state).
    tracker.mark_synced_with_term(bundle.version, bundle.term);
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
/// * `server.role` is forced to `slave`; `server.instance_name` and
///   `server.data_dir` identify this node and must not be replaced by the
///   master's values.
/// * `[integrations.mikrotik]` credentials are stripped from the replicated
///   configuration and restored from the live node-local configuration.
///
/// The node-local values come from the running configuration, not a fresh disk
/// read: a transient read error or a mid-edit file must not silently drop
/// `[ha]`/identity/credentials. When `local_path` is set, the file is still
/// read once to fail the push if it is unreadable or unparseable, because
/// persisting over it would destroy the only copy of that node-local state.
///
/// The structured bundle fields (`clients`, `rewrites`, `lists`,
/// `custom_rules`) are authoritative: a missing field removes the
/// corresponding configuration instead of keeping the previous copy, so the
/// persisted file matches the runtime snapshot exactly.
async fn build_persisted_config(
    pushed_toml: &str,
    bundle: &ConfigBundle,
    local_path: Option<&std::path::Path>,
    live: &Config,
    clients_value: Option<toml::Value>,
) -> Result<String, HaError> {
    let mut pushed = pushed_toml
        .parse::<toml::Table>()
        .map_err(|e| HaError::Validation {
            field: "config".to_string(),
            reason: format!("Pushed configuration is not valid TOML: {e}"),
        })?;

    if let Some(path) = local_path {
        let raw = tokio::fs::read_to_string(path).await.map_err(HaError::Io)?;
        raw.parse::<toml::Table>()
            .map_err(|e| HaError::Validation {
                field: "config".to_string(),
                reason: format!(
                    "Cannot parse node-local configuration '{}': {e}",
                    path.display()
                ),
            })?;
    }

    // `[ha]` is node-local. If the live configuration has none, never leave
    // the master's copy in place.
    match live.ha {
        Some(ref ha) => {
            pushed.insert("ha".to_string(), ha.clone());
        }
        None => {
            pushed.remove("ha");
        }
    }

    let server = pushed
        .entry("server".to_string())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(|| HaError::Validation {
            field: "server".to_string(),
            reason: "Pushed [server] section is not a table".to_string(),
        })?;
    server.insert("role".to_string(), toml::Value::String("slave".to_string()));
    server.insert(
        "instance_name".to_string(),
        toml::Value::String(live.server.instance_name.clone()),
    );
    server.insert(
        "data_dir".to_string(),
        toml::Value::String(live.server.data_dir.to_string_lossy().into_owned()),
    );

    if let Some(local_credentials) = live
        .integrations
        .as_ref()
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

    toml::to_string_pretty(&pushed).map_err(|e| HaError::Serialization(e.to_string()))
}

/// Reads the node-local `[clients] client_id_secrets` table (name -> secret)
/// from the live configuration.
fn local_client_id_secrets(config: &Config) -> HashMap<String, String> {
    config
        .clients
        .as_ref()
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

/// Test-only applier used by the `sito-ha` unit and end-to-end tests.
///
/// Production implements [`SlaveConfigApplier`] in the `sito` binary on top of
/// `sito-api`. This stand-in mirrors the observable ordering that matters for
/// the worker tests: apply to the live handles, persist, and roll back when the
/// write fails.
#[cfg(test)]
pub(crate) mod test_support {
    use super::SlaveConfigApplier;
    use sito_core::config::Config;
    use sito_filter::HostsFilterEngine;
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::Arc;

    pub(crate) struct TestApplier {
        runtime: Arc<sito_runtime::RuntimeState>,
        filter: Arc<HostsFilterEngine>,
        config_path: Option<PathBuf>,
    }

    impl TestApplier {
        pub(crate) fn new(
            runtime: Arc<sito_runtime::RuntimeState>,
            filter: Arc<HostsFilterEngine>,
            config_path: Option<PathBuf>,
        ) -> Self {
            Self {
                runtime,
                filter,
                config_path,
            }
        }
    }

    impl SlaveConfigApplier for TestApplier {
        fn apply_and_persist<'a>(
            &'a self,
            cfg: &'a Config,
            document: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                let previous = self.runtime.snapshot();
                let previous_config = previous.config.clone();

                self.filter
                    .reload_with_config(&cfg.filtering)
                    .await
                    .map_err(|e| e.to_string())?;

                let clients: sito_clients::ClientsConfig = match cfg.clients.as_ref() {
                    Some(value) => value.clone().try_into().map_err(|e| format!("{e}"))?,
                    None => sito_clients::ClientsConfig::default(),
                };
                let rewrites: sito_rewrites::RewritesConfig = match cfg.rewrites.as_ref() {
                    Some(value) => value.clone().try_into().map_err(|e| format!("{e}"))?,
                    None => sito_rewrites::RewritesConfig::default(),
                };
                self.runtime.replace(sito_runtime::RuntimeSnapshot {
                    config: Arc::new(cfg.clone()),
                    clients: Arc::new(sito_clients::ClientRegistry::with_stores(
                        clients,
                        previous.clients.routeros_leases_store(),
                        previous.clients.unidentified_store(),
                    )),
                    rewrites: Arc::new(sito_rewrites::RewriteTable::new(rewrites)),
                });

                if let Some(path) = self.config_path.as_deref()
                    && let Err(e) = tokio::fs::write(path, document).await
                {
                    // Persist failures must leave the live configuration
                    // untouched, exactly like the production applier.
                    self.runtime.replace((*previous).clone());
                    let _ = self
                        .filter
                        .reload_with_config(&previous_config.filtering)
                        .await;
                    return Err(e.to_string());
                }
                Ok(())
            })
        }
    }
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
            handles
                .metrics
                .inc_ha_startup_noop("slave", "missing_master_url");
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
        have_term: tracker.get_term(),
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
                    have_term: tracker.get_term(),
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
        HaMessage::ConfigPush {
            ref version,
            ref term,
            ref payload_hash_blake3,
            ..
        } => {
            let target_version = *version;
            let push_term = *term;

            // A push from an older epoch is a stale master and must never
            // overwrite newer configuration, even when its version counter is
            // higher. Within the same epoch the version must advance, and a
            // same-version push is only acceptable when it is the identical
            // signed payload.
            if let Some(watermark) = tracker.get_watermark() {
                if watermark.forked && push_term <= watermark.term {
                    // A fork was already latched: only a strictly higher-term
                    // promotion may resume replication.
                    let _ = tracker.latch_fork(watermark.version, watermark.term);
                    tracker.mark_degraded(format!(
                        "HA fork latched at term {} version {}: refusing term {push_term} until explicit higher-term promotion",
                        watermark.term, watermark.forked_at_version
                    ));
                    let ack = HaMessage::Ack {
                        version: watermark.version,
                        term: watermark.term,
                        applied: false,
                        conflict: Some(AckConflict::SameVersionFork),
                        error: Some(format!(
                            "Term {push_term} is blocked by the latched same-version fork at term {} version {}",
                            watermark.term, watermark.forked_at_version
                        )),
                    };
                    ws_stream
                        .send(WsMessage::Text(ack.to_json()?.into()))
                        .await
                        .map_err(|e| HaError::Connection(format!("Failed to send Ack: {e}")))?;
                    return Ok(());
                }
                if push_term < watermark.term {
                    let ack = HaMessage::Ack {
                        version: watermark.version,
                        term: watermark.term,
                        applied: false,
                        conflict: Some(AckConflict::StaleTerm),
                        error: Some(format!(
                            "Push term {push_term} is below the applied term {} (stale master/epoch rejected)",
                            watermark.term
                        )),
                    };
                    ws_stream
                        .send(WsMessage::Text(ack.to_json()?.into()))
                        .await
                        .map_err(|e| HaError::Connection(format!("Failed to send Ack: {e}")))?;
                    return Ok(());
                }
                if push_term > watermark.term && target_version <= watermark.version {
                    let reason = format!(
                        "Higher-term push (term {push_term} version {target_version}) must continue above the applied version {}; a term bump does not permit a version rollback",
                        watermark.version
                    );
                    tracker.mark_degraded(reason.clone());
                    let ack = HaMessage::Ack {
                        version: watermark.version,
                        term: watermark.term,
                        applied: false,
                        conflict: Some(AckConflict::StaleVersion),
                        error: Some(reason),
                    };
                    ws_stream
                        .send(WsMessage::Text(ack.to_json()?.into()))
                        .await
                        .map_err(|e| HaError::Connection(format!("Failed to send Ack: {e}")))?;
                    return Ok(());
                }
                if push_term == watermark.term {
                    if target_version < watermark.version {
                        let ack = HaMessage::Ack {
                            version: watermark.version,
                            term: watermark.term,
                            applied: false,
                            conflict: Some(AckConflict::StaleVersion),
                            error: Some(format!(
                                "Push version {target_version} is below the applied watermark {} (replay rejected)",
                                watermark.version
                            )),
                        };
                        ws_stream
                            .send(WsMessage::Text(ack.to_json()?.into()))
                            .await
                            .map_err(|e| HaError::Connection(format!("Failed to send Ack: {e}")))?;
                        return Ok(());
                    }
                    if target_version == watermark.version {
                        if !watermark_covers(
                            &watermark,
                            push_term,
                            target_version,
                            payload_hash_blake3,
                        ) {
                            // Same term and version but different content: this
                            // is a fork. Latch it durably so the next same-term
                            // version from the forked master cannot overwrite
                            // the applied configuration.
                            if let Err(e) = tracker.latch_fork(watermark.version, watermark.term) {
                                warn!(
                                    error = %e,
                                    "Failed to persist the HA fork latch"
                                );
                            }
                            let reason = format!(
                                "Same-version payload fork at term {} version {}: master content differs from the applied bundle",
                                watermark.term, watermark.version
                            );
                            tracker.mark_degraded(reason.clone());
                            let ack = HaMessage::Ack {
                                version: watermark.version,
                                term: watermark.term,
                                applied: false,
                                conflict: Some(AckConflict::SameVersionFork),
                                error: Some(reason),
                            };
                            ws_stream
                                .send(WsMessage::Text(ack.to_json()?.into()))
                                .await
                                .map_err(|e| {
                                    HaError::Connection(format!("Failed to send Ack: {e}"))
                                })?;
                            return Ok(());
                        }
                        let ack = HaMessage::Ack {
                            version: watermark.version,
                            term: watermark.term,
                            applied: true,
                            conflict: None,
                            error: None,
                        };
                        ws_stream
                            .send(WsMessage::Text(ack.to_json()?.into()))
                            .await
                            .map_err(|e| HaError::Connection(format!("Failed to send Ack: {e}")))?;
                        if tracker.get_state() != SlaveState::Degraded {
                            tracker.mark_synced_with_term(watermark.version, watermark.term);
                        }
                        return Ok(());
                    }
                }
            }

            if push_term < tracker.get_term() {
                let ack = HaMessage::Ack {
                    version: tracker.get_version(),
                    term: tracker.get_term(),
                    applied: false,
                    conflict: Some(AckConflict::StaleTerm),
                    error: Some(format!(
                        "Push term {push_term} is below the current term {} (stale master/epoch rejected)",
                        tracker.get_term()
                    )),
                };
                ws_stream
                    .send(WsMessage::Text(ack.to_json()?.into()))
                    .await
                    .map_err(|e| HaError::Connection(format!("Failed to send Ack: {e}")))?;
                return Ok(());
            }

            // Already at (or ahead of) this version in the same term:
            // acknowledge without re-applying. The master always pushes on
            // connect.
            if push_term == tracker.get_term() && target_version <= tracker.get_version() {
                let ack = HaMessage::Ack {
                    version: tracker.get_version(),
                    term: tracker.get_term(),
                    applied: true,
                    conflict: None,
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
                        term: tracker.get_term(),
                        applied: true,
                        conflict: None,
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
                        term: push_term,
                        applied: false,
                        conflict: None,
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

    #[tokio::test]
    async fn test_slave_missing_master_url_records_startup_noop() {
        let handles = test_handles(None).await;
        let metrics = handles.metrics.clone();
        let tracker = SlaveStatusTracker::new("slave-idle".to_string(), 0, None);
        let (_resync_tx, resync_rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let worker = spawn_slave_worker(
            HaConfig {
                master_url: None,
                ..Default::default()
            },
            tracker,
            handles,
            resync_rx,
            shutdown_rx,
        );
        worker.await.unwrap();

        let rendered = metrics.render_prometheus();
        assert!(
            rendered.contains(
                r#"sito_ha_startup_noop_total{role="slave",reason="missing_master_url"} 1"#
            ),
            "an idle slave worker must be observable: {rendered}"
        );
        let _ = shutdown_tx.send(true);
    }

    async fn test_handles(config_path: Option<PathBuf>) -> SlaveAppHandles {
        // Mirror production: the live runtime configuration is the parsed
        // on-disk configuration (when the test provides one).
        let base_config = match config_path.as_deref() {
            Some(path) => match tokio::fs::read_to_string(path).await {
                Ok(raw) => Config::from_toml_str(&raw).unwrap_or_default(),
                Err(_) => Config::default(),
            },
            None => Config::default(),
        };
        let config_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(base_config.clone())));
        let filter_engine = Arc::new(
            HostsFilterEngine::init(base_config.filtering.clone(), std::env::temp_dir()).await,
        );
        let rewrites_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(
            sito_rewrites::RewriteTable::new(Default::default()),
        )));
        let clients_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(
            sito_clients::ClientRegistry::new(Default::default()),
        )));
        let runtime = Arc::new(sito_runtime::RuntimeState::new(
            config_arc,
            clients_arc,
            rewrites_arc,
        ));
        let applier = Arc::new(crate::slave::worker::test_support::TestApplier::new(
            runtime.clone(),
            filter_engine.clone(),
            config_path.clone(),
        ));
        SlaveAppHandles {
            runtime,
            filter: filter_engine,
            metrics: MetricsRegistry::new("0.1.0", "slave"),
            config_path,
            applier,
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
            term: 0,
            timestamp: 1,
            config_toml: config_toml.to_string(),
            custom_rules: vec!["||pushed-rule.example^".to_string()],
            rewrites,
            clients,
            lists: vec![],
        }
    }

    #[derive(Debug, Clone)]
    struct ApplierObservation {
        upstream_servers: Vec<String>,
        dnssec_validate: bool,
        dnssec_nta: Vec<String>,
        state: SlaveState,
        version: u64,
    }

    struct RecordingApplier {
        observation: Arc<std::sync::Mutex<Option<ApplierObservation>>>,
        tracker: SlaveStatusTracker,
    }

    impl SlaveConfigApplier for RecordingApplier {
        fn apply_and_persist<'a>(
            &'a self,
            cfg: &'a Config,
            _document: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                *self
                    .observation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(ApplierObservation {
                        upstream_servers: cfg.upstream.servers.clone(),
                        dnssec_validate: cfg.dns.dnssec.validate,
                        dnssec_nta: cfg.dns.dnssec.nta.clone(),
                        state: self.tracker.get_state(),
                        version: self.tracker.get_version(),
                    });
                Ok(())
            })
        }
    }

    struct FailingApplier;

    impl SlaveConfigApplier for FailingApplier {
        fn apply_and_persist<'a>(
            &'a self,
            _cfg: &'a Config,
            _document: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async { Err("listener rebind failed".to_string()) })
        }
    }

    /// Reads the next slave ACK from the peer end of an in-memory WebSocket.
    async fn read_ack<S>(peer: &mut tokio_tungstenite::WebSocketStream<S>) -> HaMessage
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use futures_util::StreamExt as _;
        let message = peer.next().await.unwrap().unwrap();
        HaMessage::from_json(&message.into_text().unwrap()).unwrap()
    }

    /// D-01: every component must be applied before the push is acknowledged.
    /// The recording applier sees the new upstream/DNSSEC configuration, the
    /// tracker is still `Applying`, and the applied-version watermark is still
    /// the old one inside the callback.
    #[tokio::test]
    async fn test_push_applies_all_components_before_ack() {
        use tokio_tungstenite::tungstenite::protocol::Role;

        let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
        let tracker = SlaveStatusTracker::new("slave-before-ack".to_string(), 4, None);
        let observation = Arc::new(std::sync::Mutex::new(None));
        let mut handles = test_handles(None).await;
        handles.applier = Arc::new(RecordingApplier {
            observation: observation.clone(),
            tracker: tracker.clone(),
        });

        let config_toml = r#"
config_version = 1

[server]
role = "slave"

[upstream]
servers = ["9.9.9.9"]

[dns.dnssec]
validate = true
mode = "validate"
nta = ["internal.example"]
"#;
        let push =
            build_and_sign_push(&test_bundle(5, config_toml, None, None), &signing_key).unwrap();

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

        tracker.set_state(SlaveState::HelloSent);
        handle_master_message(
            &push.to_json().unwrap(),
            &mut ws,
            &tracker,
            &handles,
            Some(&signing_key.public_key()),
        )
        .await
        .unwrap();

        let observation = observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .expect("the applier must run before the ACK");
        assert_eq!(
            observation.state,
            SlaveState::Applying,
            "the push must still be in flight while components are applied"
        );
        assert_eq!(
            observation.version, 4,
            "the watermark must not advance before the apply succeeds"
        );
        assert_eq!(observation.upstream_servers, vec!["9.9.9.9".to_string()]);
        assert!(observation.dnssec_validate);
        assert_eq!(observation.dnssec_nta, vec!["internal.example".to_string()]);

        assert!(matches!(
            read_ack(&mut peer).await,
            HaMessage::Ack {
                version: 5,
                term: 0,
                conflict: None,
                applied: true,
                ..
            }
        ));
        assert_eq!(tracker.get_state(), SlaveState::Synced);
        assert_eq!(tracker.get_version(), 5);
    }

    /// D-01: a component failure is an apply failure: the watermark stays put,
    /// the state becomes `Degraded`, and the ACK says `applied: false`.
    #[tokio::test]
    async fn test_component_failure_is_apply_failure() {
        use tokio_tungstenite::tungstenite::protocol::Role;

        let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
        let tracker = SlaveStatusTracker::new("slave-apply-fail".to_string(), 4, None);
        let mut handles = test_handles(None).await;
        let before_config = handles.runtime.snapshot().config.clone();
        handles.applier = Arc::new(FailingApplier);

        let push = build_and_sign_push(
            &test_bundle(
                5,
                "config_version = 1\n[server]\nrole = \"slave\"\n",
                None,
                None,
            ),
            &signing_key,
        )
        .unwrap();

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

        tracker.set_state(SlaveState::HelloSent);
        handle_master_message(
            &push.to_json().unwrap(),
            &mut ws,
            &tracker,
            &handles,
            Some(&signing_key.public_key()),
        )
        .await
        .unwrap();

        assert_eq!(tracker.get_state(), SlaveState::Degraded);
        assert_eq!(
            tracker.get_version(),
            4,
            "a failed component apply must not advance the watermark"
        );
        assert!(
            Arc::ptr_eq(&before_config, &handles.runtime.snapshot().config),
            "the live runtime must not be replaced by a failed apply"
        );
        match read_ack(&mut peer).await {
            HaMessage::Ack {
                version,
                applied,
                error,
                ..
            } => {
                assert_eq!(version, 5);
                assert!(!applied);
                assert!(
                    error.unwrap_or_default().contains("listener rebind failed"),
                    "the ACK must carry the apply failure"
                );
            }
            other => panic!("expected an ACK, got {other:?}"),
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
        let live = Config::from_toml_str(local).expect("node-local config");
        let merged =
            build_persisted_config(pushed, &bundle, Some(&path), &live, bundle.clients.clone())
                .await
                .expect("build persisted config");
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
    async fn test_local_client_id_secrets_read_from_live_config() {
        let live =
            Config::from_toml_str("[clients]\nclient_id_secrets = { \"phone\" = \"abc\" }\n")
                .expect("live config");
        let secrets = local_client_id_secrets(&live);
        assert_eq!(secrets.get("phone").map(String::as_str), Some("abc"));
        assert!(
            local_client_id_secrets(&Config::default()).is_empty(),
            "a node without client secrets must yield no client id secrets"
        );
    }

    /// I4: without a local path there is nothing to protect, so the pushed
    /// sections survive and only the forced node-local fields are merged.
    #[tokio::test]
    async fn test_persisted_config_without_local_file_keeps_pushed_sections() {
        let pushed = "config_version = 1\n[server]\nrole = \"slave\"\n";
        let mut bundle = test_bundle(1, pushed, None, None);
        bundle.custom_rules = vec![];
        let live = Config::default();
        let merged = build_persisted_config(pushed, &bundle, None, &live, None)
            .await
            .expect("build persisted config");
        let table: toml::Table = merged.parse().unwrap();
        assert_eq!(
            table
                .get("server")
                .and_then(|server| server.get("role"))
                .and_then(toml::Value::as_str),
            Some("slave")
        );
        assert_eq!(
            table
                .get("server")
                .and_then(|server| server.get("instance_name"))
                .and_then(toml::Value::as_str),
            Some(live.server.instance_name.as_str()),
            "node identity must come from the live configuration"
        );
        let expected_data_dir = live.server.data_dir.to_string_lossy();
        assert_eq!(
            table
                .get("server")
                .and_then(|server| server.get("data_dir"))
                .and_then(toml::Value::as_str),
            Some(expected_data_dir.as_ref()),
            "the node data directory must come from the live configuration"
        );
    }

    /// I4 regression: the local file is expected but unreadable/unparseable.
    /// The push must fail (applied:false) and the file must stay untouched.
    #[tokio::test]
    async fn test_unparseable_local_config_rejects_push_and_keeps_file() {
        let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
        let dir = std::env::temp_dir().join(format!("sito_ha_corrupt_{}", rand::random::<u64>()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("config.toml");
        let corrupt = "[server\nrole = \"slave\"\n";
        tokio::fs::write(&path, corrupt).await.unwrap();

        let mut handles = test_handles(None).await;
        handles.config_path = Some(path.clone());
        let tracker = SlaveStatusTracker::new("slave-corrupt".to_string(), 0, None);
        let config_toml = "config_version = 1\n[server]\nrole = \"slave\"\n";
        let push =
            build_and_sign_push(&test_bundle(1, config_toml, None, None), &signing_key).unwrap();

        let err = apply_config_push(&push, &tracker, &handles, &signing_key.public_key())
            .await
            .expect_err("an unparseable local config must reject the push");
        assert!(matches!(err, HaError::Rollback(_)));
        assert_eq!(tracker.get_state(), SlaveState::Degraded);
        assert_eq!(tracker.get_version(), 0);
        assert_eq!(
            tokio::fs::read_to_string(&path).await.unwrap(),
            corrupt,
            "the push must not overwrite the node-local configuration"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
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
        assert_eq!(
            handles.filter.rule_count(),
            0,
            "the live filter snapshot must be rolled back when persistence fails"
        );

        // Repair the path and re-apply: the same push succeeds. The local file
        // must exist and parse because a push never overwrites node-local
        // state it could not read.
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, "config_version = 1\n[server]\nrole = \"slave\"\n")
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

    /// A restart restores the applied watermark and rejects both an older
    /// signed bundle and a same-version bundle with different content.
    #[tokio::test]
    async fn test_restart_rejects_replay_and_same_version_content_swap() {
        let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "sito_ha_watermark_worker_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let watermark_path = dir.join("ha_watermark.toml");
        let config_toml = "config_version = 1\n[server]\nrole = \"slave\"\n";

        let first = SlaveStatusTracker::new("slave-restart".to_string(), 0, None)
            .with_watermark_path(watermark_path.clone())
            .unwrap();
        let handles = test_handles(None).await;
        let push_v2 =
            build_and_sign_push(&test_bundle(2, config_toml, None, None), &signing_key).unwrap();
        assert_eq!(
            apply_config_push(&push_v2, &first, &handles, &signing_key.public_key())
                .await
                .unwrap(),
            2
        );

        // Simulate a process restart: only the on-disk watermark survives.
        let restarted = SlaveStatusTracker::new("slave-restart".to_string(), 0, None)
            .with_watermark_path(watermark_path.clone())
            .unwrap();
        assert_eq!(restarted.get_version(), 2);
        let restarted_handles = test_handles(None).await;

        let old_push =
            build_and_sign_push(&test_bundle(1, config_toml, None, None), &signing_key).unwrap();
        assert!(
            apply_config_push(
                &old_push,
                &restarted,
                &restarted_handles,
                &signing_key.public_key()
            )
            .await
            .is_err(),
            "an older signed bundle must be rejected after restart"
        );
        assert_eq!(
            restarted.get_version(),
            2,
            "a rejected replay must not advance the watermark"
        );

        let mut swapped = test_bundle(2, config_toml, None, None);
        swapped.custom_rules = vec!["||content-swap.example^".to_string()];
        let swapped_push = build_and_sign_push(&swapped, &signing_key).unwrap();
        assert!(
            apply_config_push(
                &swapped_push,
                &restarted,
                &restarted_handles,
                &signing_key.public_key()
            )
            .await
            .is_err(),
            "same-version content replay must be rejected"
        );
        assert!(
            restarted_handles
                .runtime
                .snapshot()
                .config
                .filtering
                .custom_rules
                .is_empty(),
            "rejected replays must not change the live configuration"
        );

        // Forward progress still works after the restart.
        let push_v3 =
            build_and_sign_push(&test_bundle(3, config_toml, None, None), &signing_key).unwrap();
        assert_eq!(
            apply_config_push(
                &push_v3,
                &restarted,
                &restarted_handles,
                &signing_key.public_key()
            )
            .await
            .unwrap(),
            3
        );
        let persisted = restarted.get_watermark().expect("watermark");
        assert_eq!(persisted.version, 3);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// The watermark is durable before the push is acknowledged.
    #[tokio::test]
    async fn test_watermark_is_persisted_before_ack() {
        use tokio_tungstenite::tungstenite::protocol::Role;

        let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "sito_ha_watermark_ack_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let watermark_path = dir.join("ha_watermark.toml");
        let tracker = SlaveStatusTracker::new("slave-ack".to_string(), 0, None)
            .with_watermark_path(watermark_path.clone())
            .unwrap();
        let handles = test_handles(None).await;
        let push = build_and_sign_push(
            &test_bundle(
                1,
                "config_version = 1\n[server]\nrole = \"slave\"\n",
                None,
                None,
            ),
            &signing_key,
        )
        .unwrap();

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

        tracker.set_state(SlaveState::HelloSent);
        handle_master_message(
            &push.to_json().unwrap(),
            &mut ws,
            &tracker,
            &handles,
            Some(&signing_key.public_key()),
        )
        .await
        .unwrap();

        assert!(matches!(
            read_ack(&mut peer).await,
            HaMessage::Ack {
                version: 1,
                term: 0,
                conflict: None,
                applied: true,
                ..
            }
        ));
        let persisted: crate::bundle::AppliedWatermark =
            serde_json::from_str(&tokio::fs::read_to_string(&watermark_path).await.unwrap())
                .unwrap();
        assert_eq!(persisted.version, 1);
        assert_eq!(
            persisted.payload_hash,
            push_payload_hash(&push).unwrap(),
            "the ACK must only be sent after the exact signed payload is on disk"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// A same-version payload fork latches the slave: every further push in the
    /// same term is rejected until an explicit higher-term promotion arrives.
    #[tokio::test]
    async fn test_same_version_fork_latches_and_blocks_same_term_versions() {
        use tokio_tungstenite::tungstenite::protocol::Role;

        let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "sito_ha_fork_latch_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let watermark_path = dir.join("ha_watermark.toml");
        let tracker = SlaveStatusTracker::new("slave-fork".to_string(), 0, None)
            .with_watermark_path(watermark_path.clone())
            .unwrap();
        let handles = test_handles(None).await;
        let config_toml = "config_version = 1\n[server]\nrole = \"slave\"\n";

        // Applied state: term 0, version 50, payload B.
        let applied = ConfigBundle {
            term: 0,
            ..test_bundle(50, config_toml, None, None)
        };
        let applied_push = build_and_sign_push(&applied, &signing_key).unwrap();
        assert_eq!(
            apply_config_push(&applied_push, &tracker, &handles, &signing_key.public_key())
                .await
                .unwrap(),
            50
        );
        assert!(!tracker.is_forked());

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

        // Same term and version, different content: fork signal.
        let mut forked = test_bundle(50, config_toml, None, None);
        forked.term = 0;
        forked.custom_rules = vec!["||fork-a.example^".to_string()];
        let forked_push = build_and_sign_push(&forked, &signing_key).unwrap();
        tracker.set_state(SlaveState::Synced);
        handle_master_message(
            &forked_push.to_json().unwrap(),
            &mut ws,
            &tracker,
            &handles,
            Some(&signing_key.public_key()),
        )
        .await
        .unwrap();

        match read_ack(&mut peer).await {
            HaMessage::Ack {
                version,
                term,
                applied,
                conflict,
                ..
            } => {
                assert_eq!(version, 50);
                assert_eq!(term, 0);
                assert!(!applied);
                assert_eq!(conflict, Some(AckConflict::SameVersionFork));
            }
            other => panic!("expected an ACK, got {other:?}"),
        }
        assert!(tracker.is_forked(), "the fork must be latched");
        assert_eq!(
            tracker.get_state(),
            SlaveState::Degraded,
            "a fork must degrade the slave immediately"
        );
        let persisted: crate::bundle::AppliedWatermark =
            serde_json::from_str(&tokio::fs::read_to_string(&watermark_path).await.unwrap())
                .unwrap();
        assert!(persisted.forked, "the latch must be durable");
        assert_eq!(persisted.version, 50);

        // The forked master's next version in the same term is refused.
        let forked_next = ConfigBundle {
            term: 0,
            ..test_bundle(51, config_toml, None, None)
        };
        let forked_next_push = build_and_sign_push(&forked_next, &signing_key).unwrap();
        handle_master_message(
            &forked_next_push.to_json().unwrap(),
            &mut ws,
            &tracker,
            &handles,
            Some(&signing_key.public_key()),
        )
        .await
        .unwrap();
        match read_ack(&mut peer).await {
            HaMessage::Ack {
                version,
                applied,
                conflict,
                ..
            } => {
                assert_eq!(version, 50);
                assert!(!applied);
                assert_eq!(conflict, Some(AckConflict::SameVersionFork));
            }
            other => panic!("expected an ACK, got {other:?}"),
        }
        assert_eq!(tracker.get_version(), 50);
        let live_rules = &handles.runtime.snapshot().config.filtering.custom_rules;
        assert!(
            !live_rules
                .iter()
                .any(|rule| rule.contains("fork-a.example")),
            "the forked configuration must never become live: {live_rules:?}"
        );

        // An explicit higher-term promotion (with a higher version) resumes
        // replication and clears the latch.
        let promoted = ConfigBundle {
            term: 1,
            ..test_bundle(51, config_toml, None, None)
        };
        let promoted_push = build_and_sign_push(&promoted, &signing_key).unwrap();
        handle_master_message(
            &promoted_push.to_json().unwrap(),
            &mut ws,
            &tracker,
            &handles,
            Some(&signing_key.public_key()),
        )
        .await
        .unwrap();
        match read_ack(&mut peer).await {
            HaMessage::Ack {
                version,
                term,
                applied,
                conflict,
                ..
            } => {
                assert_eq!(version, 51);
                assert_eq!(term, 1);
                assert!(applied);
                assert_eq!(conflict, None);
            }
            other => panic!("expected an ACK, got {other:?}"),
        }
        assert_eq!(tracker.get_version(), 51);
        assert_eq!(tracker.get_term(), 1);
        assert!(!tracker.is_forked(), "a higher term clears the latch");
        assert!(!tracker.get_watermark().unwrap().forked);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// A stale master from an older term must not overwrite a newer slave,
    /// even when its version counter is higher.
    #[tokio::test]
    async fn test_stale_master_push_is_rejected_without_overwriting() {
        use tokio_tungstenite::tungstenite::protocol::Role;

        let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "sito_ha_stale_master_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let tracker = SlaveStatusTracker::new("slave-epoch".to_string(), 0, None)
            .with_watermark_path(dir.join("ha_watermark.toml"))
            .unwrap();
        let handles = test_handles(None).await;

        // The slave has applied an epoch-1, version-5 bundle.
        let current = ConfigBundle {
            term: 1,
            ..test_bundle(
                5,
                "config_version = 1\n[server]\nrole = \"slave\"\n",
                None,
                None,
            )
        };
        let current_push = build_and_sign_push(&current, &signing_key).unwrap();
        assert_eq!(
            apply_config_push(&current_push, &tracker, &handles, &signing_key.public_key())
                .await
                .unwrap(),
            5
        );
        assert_eq!(tracker.get_term(), 1);

        // A stale epoch-0 master offers a higher version.
        let stale = ConfigBundle {
            term: 0,
            ..test_bundle(
                6,
                "config_version = 1\n[server]\nrole = \"slave\"\n",
                None,
                None,
            )
        };
        let stale_push = build_and_sign_push(&stale, &signing_key).unwrap();

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

        tracker.set_state(SlaveState::Synced);
        handle_master_message(
            &stale_push.to_json().unwrap(),
            &mut ws,
            &tracker,
            &handles,
            Some(&signing_key.public_key()),
        )
        .await
        .unwrap();

        match read_ack(&mut peer).await {
            HaMessage::Ack {
                version,
                term,
                applied,
                error,
                ..
            } => {
                assert_eq!(version, 5);
                assert_eq!(term, 1);
                assert!(!applied);
                assert!(
                    error.unwrap_or_default().contains("stale master/epoch"),
                    "the ACK must explain the rejected epoch"
                );
            }
            other => panic!("expected an ACK, got {other:?}"),
        }
        assert_eq!(tracker.get_version(), 5);
        assert_eq!(tracker.get_term(), 1);
        assert_eq!(
            tracker.get_watermark().unwrap().version,
            5,
            "the stale push must not advance the watermark"
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
            term: 0,
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
                term: 0,
                conflict: None,
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
                term: 0,
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
