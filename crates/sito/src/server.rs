//! Server lifecycle and runner implementation.

use notify::{Event, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{error, info, warn};

use arc_swap::ArcSwap;
use sito_cache::DnsCache;
use sito_core::config::Config;
use sito_dnssec::DnssecValidator;
use sito_filter::HostsFilterEngine;
use sito_stats::{MetricsRegistry, QueryLogWriter, StatsDb};
use sito_transport::{
    AcmeChallengeAvailability, AcmeServiceConfig, CertWatcher, Doh3Config, DohConfig, DoqConfig,
    DotConfig, TcpConfig, TlsAcceptorManager, TlsManagerSet, UdpConfig, generate_self_signed_cert,
    load_server_config, load_server_config_with_challenges, record_bootstrap_cert,
    start_acme_manager_for_transports, start_doh_listener, start_doh3_listener, start_doq_listener,
    start_dot_listener, start_tcp_listener, start_udp_listener, write_secret_file,
};
use sito_upstream::{BootstrapResolver, UpstreamManager};

use crate::pipeline::DnsPipeline;

/// Parses the optional `[clients]` section, surfacing type errors instead of
/// silently discarding all client policies.
pub(crate) fn clients_from_config(config: &Config) -> anyhow::Result<sito_clients::ClientsConfig> {
    match config.clients.as_ref() {
        Some(value) => value
            .clone()
            .try_into()
            .map_err(|e| anyhow::anyhow!("invalid [clients] configuration: {e}")),
        None => Ok(sito_clients::ClientsConfig::default()),
    }
}

/// Maps client-group policy onto the filter engine's per-group rule sets.
///
/// Groups that define neither `lists` nor `custom_rules` are skipped so the
/// engine does not compile empty snapshots.
pub(crate) fn group_rule_sets(
    clients: &sito_clients::ClientsConfig,
) -> Vec<sito_filter::GroupRuleSet> {
    let mut groups: Vec<sito_filter::GroupRuleSet> = clients
        .groups
        .iter()
        .filter(|(_, group)| !group.lists.is_empty() || !group.custom_rules.is_empty())
        .map(|(name, group)| sito_filter::GroupRuleSet {
            name: name.clone(),
            lists: group.lists.clone(),
            custom_rules: group.custom_rules.clone(),
        })
        .collect();
    groups.sort_by(|a, b| a.name.cmp(&b.name));
    groups
}

/// Parses the optional `[rewrites]` section, surfacing type errors.
pub(crate) fn rewrites_from_config(
    config: &Config,
) -> anyhow::Result<sito_rewrites::RewritesConfig> {
    match config.rewrites.as_ref() {
        Some(value) => value
            .clone()
            .try_into()
            .map_err(|e| anyhow::anyhow!("invalid [rewrites] configuration: {e}")),
        None => Ok(sito_rewrites::RewritesConfig::default()),
    }
}

/// Parses the optional `[integrations]` section, surfacing type errors.
pub(crate) fn integrations_from_config(
    config: &Config,
) -> anyhow::Result<Option<sito_clients::IntegrationsConfig>> {
    match config.integrations.as_ref() {
        Some(value) => value
            .clone()
            .try_into::<sito_clients::IntegrationsConfig>()
            .map(Some)
            .map_err(|e| anyhow::anyhow!("invalid [integrations] configuration: {e}")),
        None => Ok(None),
    }
}

/// Validates every TOML-valued configuration section at startup and in
/// `check-config`, so a type error aborts instead of silently falling back to
/// defaults (which could drop trusted proxies, client policies or HA settings).
///
/// The implementation is shared with the API write paths
/// (`sito_api::config_validation`) so an accepted configuration is always one
/// the server can load.
pub fn validate_typed_sections(config: &Config) -> anyhow::Result<()> {
    sito_api::config_validation::validate_typed_sections(config)
}

/// Query-log writer channel capacity (entries).
const QUERYLOG_BUFFER: usize = 10_000;
/// How often the query-log drop counter is published to Prometheus.
const QUERYLOG_METRICS_INTERVAL: Duration = Duration::from_secs(5);
/// Graceful shutdown budget for draining in-flight queries.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// Stats retention sweep interval (retention_days is re-read every cycle).
const RETENTION_INTERVAL: Duration = Duration::from_hours(24);
/// Debounce window for config file watcher events.
const WATCHER_DEBOUNCE: Duration = Duration::from_millis(100);
/// Periodic flush interval for the persistent DNSSEC chain cache.
const CHAIN_CACHE_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// Current UNIX time truncated to the DNSSEC serial-number width.
fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

/// Resolves the config path to an absolute path so the file watcher can watch
/// its parent directory even for the default relative `config.toml`. Symlinks
/// are resolved when the file exists; otherwise it is anchored to the current
/// working directory.
fn canonical_config_path(path: &Path) -> PathBuf {
    match std::fs::canonicalize(path) {
        Ok(resolved) => resolved,
        Err(_) => std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()),
    }
}

/// Compares two sanitized bundle documents semantically, falling back to byte
/// comparison when either side is not valid TOML. Used at master startup to
/// decide whether `config.toml` still matches the persisted bundle.
fn sanitized_configs_equal(a: &str, b: &str) -> bool {
    match (a.parse::<toml::Table>(), b.parse::<toml::Table>()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Builds one protocol's hot-reloadable TLS acceptor and starts its certificate
/// watcher.
///
/// Errors are fatal: a configured encrypted listener must never silently fall
/// back to "not running" because its certificate material is unreadable,
/// expired, or does not match the key.
#[allow(clippy::too_many_arguments)]
fn build_tls_acceptor(
    protocol: &str,
    cert: &Path,
    key: &Path,
    sni_tuples: &[(String, PathBuf, PathBuf)],
    alpn: &[Vec<u8>],
    challenge_keys: Option<Arc<dashmap::DashMap<String, Arc<rustls::sign::CertifiedKey>>>>,
    cert_watchers: &mut Vec<sito_transport::CertWatcher>,
) -> anyhow::Result<TlsAcceptorManager> {
    let config = match challenge_keys.clone() {
        Some(keys) => {
            load_server_config_with_challenges(cert, key, sni_tuples, alpn.to_vec(), keys)
        }
        None => load_server_config(cert, key, sni_tuples, alpn.to_vec()),
    }
    .map_err(|e| anyhow::anyhow!("Failed to initialize {protocol} TLS configuration: {e}"))?;

    let manager = match challenge_keys {
        Some(keys) => TlsAcceptorManager::with_challenge_keys(config, keys),
        None => TlsAcceptorManager::new(config),
    };
    match CertWatcher::start(cert, key, sni_tuples, alpn, manager.clone()) {
        Ok(watcher) => cert_watchers.push(watcher),
        Err(e) => warn!(protocol, "Certificate watcher failed to start: {e}"),
    }
    Ok(manager)
}

/// What encrypted listeners should do with the material found at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TlsStartupMaterial {
    /// Serve this certificate/key pair.
    Pair(PathBuf, PathBuf),
    /// No usable pair exists; write a short-lived bootstrap pair.
    GenerateBootstrap,
    /// No trusted pair and bootstrap serving is not opted in.
    Disabled,
}

/// Selects the startup action for encrypted listeners.
///
/// When ACME is enabled, a usable CA-issued certificate stored on disk takes
/// precedence over static `[tls]` files so a restart cannot silently revert
/// DoH/DoT/DoQ/DoH3 to stale static material. A bootstrap placeholder never
/// wins over a real static pair. If no trusted pair exists, a bootstrap is
/// generated only when the operator opted in with
/// `acme.allow_bootstrap_cert = true`; otherwise encrypted listeners stay
/// disabled until a real certificate is available.
fn choose_tls_material(
    static_pair: Option<(PathBuf, PathBuf)>,
    acme_pair: Option<(PathBuf, PathBuf)>,
    acme_pair_usable: bool,
    acme_enabled: bool,
    allow_bootstrap_cert: bool,
) -> TlsStartupMaterial {
    if !acme_enabled {
        return static_pair.map_or(TlsStartupMaterial::Disabled, |(cert, key)| {
            TlsStartupMaterial::Pair(cert, key)
        });
    }

    if let Some((cert, key)) = acme_pair
        && acme_pair_usable
    {
        return TlsStartupMaterial::Pair(cert, key);
    }
    if let Some((cert, key)) = static_pair {
        return TlsStartupMaterial::Pair(cert, key);
    }
    if allow_bootstrap_cert {
        TlsStartupMaterial::GenerateBootstrap
    } else {
        TlsStartupMaterial::Disabled
    }
}

/// Record whether a TCP DoH listener actually bound port 443 with the
/// `acme-tls/1` ALPN. Called after every bind/rebind so ACME challenge
/// selection reflects reality rather than configuration intent.
fn record_doh_listener_binding(
    availability: &AcmeChallengeAvailability,
    config: &Config,
    doh_manager: Option<&TlsAcceptorManager>,
    doh_bound: bool,
) {
    let advertises_acme_alpn = doh_manager.is_some_and(|manager| {
        manager
            .alpn_protocols()
            .iter()
            .any(|protocol| protocol.as_slice() == b"acme-tls/1")
    });
    availability
        .set_tls_alpn_available(doh_bound && config.dns.doh_port == 443 && advertises_acme_alpn);
}

/// Builds per-client upstream managers, reusing existing managers by key so a
/// hot reload does not re-resolve unchanged upstream scopes.
async fn build_scoped_upstreams(
    config: &Config,
    clients: &sito_clients::ClientsConfig,
    existing: &HashMap<String, Arc<UpstreamManager>>,
) -> HashMap<String, Arc<UpstreamManager>> {
    // Build from the current config on every call. Capturing a startup resolver
    // here would leave scoped upstreams on old bootstrap/allow_private_targets
    // settings after a hot reload.
    let bootstrap = BootstrapResolver::from_config(&config.upstream);
    let mut scoped: HashMap<String, Arc<UpstreamManager>> = HashMap::new();
    for entry in &clients.entries {
        if entry.use_global_upstreams {
            continue;
        }
        let Some(ref servers) = entry.upstreams else {
            continue;
        };
        if servers.is_empty() {
            continue;
        }
        let key = scoped_upstream_key(config, servers);
        if scoped.contains_key(&key) {
            continue;
        }
        if let Some(manager) = existing.get(&key) {
            scoped.insert(key, manager.clone());
            continue;
        }
        let mut upstream_cfg = config.upstream.clone();
        upstream_cfg.servers.clone_from(servers);
        upstream_cfg.per_domain.clear();
        match UpstreamManager::from_config(&upstream_cfg, &bootstrap).await {
            Ok(manager) => {
                info!(
                    client = %entry.name,
                    servers = ?servers,
                    "Initialized per-client upstream scope"
                );
                scoped.insert(key, Arc::new(manager));
            }
            Err(e) => warn!(
                client = %entry.name,
                error = %e,
                "Failed to initialize per-client upstreams; this client falls back to global upstreams"
            ),
        }
    }
    scoped
}

/// Reuse key for a per-client upstream scope.
///
/// Includes every inherited `[upstream]` setting that affects manager
/// construction, not just the server list. Otherwise a reload that only changes
/// the bootstrap, timeout, strategy, pool size or `allow_private_targets` would
/// keep the stale manager (and its old SSRF policy) alive.
fn scoped_upstream_key(config: &Config, servers: &[String]) -> String {
    let up = &config.upstream;
    format!(
        "{}|bootstrap={:?}|timeout_ms={}|strategy={:?}|pool_size={}|allow_private_targets={}",
        servers.join(","),
        up.bootstrap,
        up.timeout_ms,
        up.strategy,
        up.pool_size,
        up.allow_private_targets
    )
}

/// High-availability role setup produced by [`init_ha`].
struct HaRuntime {
    config: sito_ha::HaConfig,
    coordinator: Option<sito_ha::MasterCoordinator>,
    tracker: Option<sito_ha::SlaveStatusTracker>,
    resync_sender: Option<tokio::sync::mpsc::Sender<()>>,
    /// Slave worker receiver, spawned only after [`ServerContext`] and the
    /// apply hooks exist so the worker can receive the shared
    /// [`HaConfigApplier`].
    resync_receiver: Option<tokio::sync::mpsc::Receiver<()>>,
}

/// Initializes the HA role. Master setup is complete on return; a slave only
/// gets its tracker and resync channel here because its worker needs the
/// server context and apply hooks built later in startup.
fn init_ha(
    config: &Config,
    config_path: &Path,
    metrics: &sito_stats::MetricsRegistry,
    shutdown_rx: &watch::Receiver<bool>,
) -> anyhow::Result<HaRuntime> {
    let ha_config: sito_ha::HaConfig = config
        .ha
        .as_ref()
        .map(sito_ha::HaConfig::from_toml_value)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid HA configuration: {e}"))?
        .unwrap_or_else(|| sito_ha::HaConfig {
            replication_port: 0,
            ..Default::default()
        });

    ha_config
        .validate(&config.server.role)
        .map_err(|e| anyhow::anyhow!("HA configuration validation failed: {e}"))?;

    let (master_coordinator, slave_tracker, resync_sender, resync_receiver) = if config.server.role
        == "master"
    {
        // The replication listener is only spawned when the port is non-zero;
        // record the no-op here so a production master with
        // `replication_port = 0` is observable. `spawn_master_server` no longer
        // increments this counter (it would double count when both run).
        if ha_config.replication_port == 0 {
            metrics.inc_ha_startup_noop("master", "replication_disabled");
            info!("Master HA replication is disabled (replication_port is 0)");
        }

        // Load or create master Ed25519 signing key (0600 on Unix)
        let signing_key_path = config.server.data_dir.join("ha_signing.key");
        let signing_key = Arc::new(sito_ha::Ed25519SigningKey::load_or_create(
            &signing_key_path,
        )?);

        let coordinator = sito_ha::MasterCoordinator::new(
            config.server.instance_name.clone(),
            0,
            signing_key.clone(),
            metrics.clone(),
        )
        .with_state_path(config.server.data_dir.join("ha_state.toml"));

        if ha_config.replication_port == 0 {
            coordinator.mark_replication_disabled();
        }

        // Continue the version sequence across restarts; only a master with no
        // recoverable state starts a fresh v1 sequence.
        let restored_version = coordinator.restore_state()?;

        let initial_toml = match std::fs::read_to_string(config_path) {
            Ok(raw) => raw,
            Err(_) => toml::to_string_pretty(config).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to serialize the running configuration for the initial HA bundle: {e}"
                )
            })?,
        };
        let sanitized_toml = sito_ha::sanitize_config_for_bundle(&initial_toml).map_err(|e| {
            anyhow::anyhow!(
                "Failed to sanitize '{}' for the HA bundle: {e}",
                config_path.display()
            )
        })?;
        if sanitized_toml.trim().is_empty() {
            anyhow::bail!(
                "Refusing to publish an empty initial HA bundle derived from '{}'",
                config_path.display()
            );
        }
        if let Some(ref token) = ha_config.slave_token
            && let Err(e) = sito_ha::scan_for_secrets(&sanitized_toml, &[token.as_str()])
        {
            anyhow::bail!("Refusing to publish HA bundle with a leaked secret: {e}");
        }
        let list_metadata: Vec<sito_ha::FilterListMetadata> = config
            .filtering
            .lists
            .iter()
            .map(|l| sito_ha::FilterListMetadata {
                name: l.name.clone(),
                url: l.url.clone(),
                enabled: l.enabled,
                refresh_hours: l.refresh_hours,
            })
            .collect();

        // Runs on every startup and on an explicit reconciliation: the bundle
        // is always built from the configuration currently on disk.
        let build_bundle = |version: u64| -> sito_ha::ConfigBundle {
            #[allow(clippy::cast_sign_loss)]
            sito_ha::ConfigBundle {
                version,
                term: coordinator.get_current_term(),
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                config_toml: sanitized_toml.clone(),
                custom_rules: config.filtering.custom_rules.clone(),
                rewrites: config.rewrites.clone(),
                clients: config.clients.clone(),
                lists: list_metadata.clone(),
            }
        };

        if let Some(restored_version) = restored_version {
            // A restart must never resume a bundle that no longer matches the
            // current `config.toml`: slaves would stay on the old shared
            // configuration indefinitely. Republish a fresh `N + 1` bundle
            // whenever the sanitized document differs (semantically, so a
            // formatting-only rewrite does not churn the sequence).
            let restored_bundle = coordinator
                .active_bundle
                .lock()
                .unwrap()
                .as_ref()
                .map(|bundle| bundle.config_toml.clone());
            let config_changed = restored_bundle
                .as_deref()
                .is_none_or(|restored| !sanitized_configs_equal(restored, &sanitized_toml));

            if config_changed {
                let next_version = restored_version.checked_add(1).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Cannot reconcile the HA bundle: persisted version {restored_version} cannot advance"
                    )
                })?;
                coordinator.update_bundle(build_bundle(next_version))?;
                info!(
                    version = next_version,
                    previous_version = restored_version,
                    "Republished HA configuration bundle because config.toml changed since the persisted bundle"
                );
            } else {
                info!(
                    version = restored_version,
                    "Resumed HA configuration sequence from persisted state"
                );
            }
        } else {
            coordinator.update_bundle(build_bundle(1))?;
            info!("Published initial HA configuration bundle version 1");
        }

        // Spawn master replication listener if replication_port > 0
        let _master_server_handle = if ha_config.replication_port > 0 {
            Some(sito_ha::spawn_master_server(
                ha_config.clone(),
                coordinator.clone(),
                shutdown_rx.clone(),
            ))
        } else {
            None
        };

        (Some(coordinator), None, None, None)
    } else {
        // Slave role. The worker is spawned by `run_server_full` once the
        // server context and apply hooks exist, so a push can apply every
        // component before it is acknowledged.
        let tracker = sito_ha::SlaveStatusTracker::new(
            config.server.instance_name.clone(),
            0,
            ha_config.master_url.clone(),
        )
        .with_watermark_path(config.server.data_dir.join("ha_watermark.toml"))?;
        // A local edit/revert while the process was stopped must not let the
        // next identical push take the same-version early-ACK path. Compare the
        // on-disk document with the digest recorded when the bundle was applied.
        if let Ok(document) = std::fs::read_to_string(config_path) {
            tracker
                .verify_applied_config(&document)
                .map_err(|e| anyhow::anyhow!("Failed to verify applied HA configuration: {e}"))?;
            if tracker.requires_full_apply() {
                tracing::warn!(
                    path = %config_path.display(),
                    local_drift = tracker.has_local_config_drift(),
                    "Local HA configuration is unverified or drifted from the last applied bundle; a full apply is required before an early Synced ACK"
                );
            }
        }
        let (resync_tx, resync_rx) = tokio::sync::mpsc::channel(4);
        (None, Some(tracker), Some(resync_tx), Some(resync_rx))
    };

    Ok(HaRuntime {
        config: ha_config,
        coordinator: master_coordinator,
        tracker: slave_tracker,
        resync_sender,
        resync_receiver,
    })
}

/// Long-lived runtime components created during startup.
struct RuntimeComponents {
    stats_db: StatsDb,
    metrics: MetricsRegistry,
    querylog_writer: QueryLogWriter,
    querylog_sender: sito_stats::QueryLogSender,
    upstream_manager: Arc<UpstreamManager>,
    cache: Arc<DnsCache>,
    filter_engine: Arc<HostsFilterEngine>,
}

/// Opens the stats database and initializes metrics, query logging, upstreams,
/// cache and the filter engine together with their background tasks.
/// Maps the filter crate's status into the metrics crate's primitive view
/// (the filter crate cannot depend on `sito-stats`).
fn filter_status_metrics(status: &sito_filter::FilterStatus) -> sito_stats::FilterStatusMetrics {
    sito_stats::FilterStatusMetrics {
        state: match status.state {
            sito_filter::FilterState::Disabled => 0,
            sito_filter::FilterState::Loading => 1,
            sito_filter::FilterState::Ready => 2,
            sito_filter::FilterState::Failed => 3,
        },
        loaded_lists: u64::try_from(status.loaded_lists).unwrap_or(u64::MAX),
        failed_lists: u64::try_from(status.failed_lists.len()).unwrap_or(u64::MAX),
        degraded_groups: u64::try_from(status.degraded_groups.len()).unwrap_or(u64::MAX),
        dropped_regex_patterns: u64::try_from(status.dropped_regex_patterns).unwrap_or(u64::MAX),
    }
}

async fn init_runtime_components(
    config: &Config,
    shutdown_rx: &watch::Receiver<bool>,
) -> anyhow::Result<RuntimeComponents> {
    // Ensure data directory exists
    tokio::fs::create_dir_all(&config.server.data_dir).await?;

    // Initialize Stats SQLite DB
    let db_path = config.server.data_dir.join("stats.db");
    let stats_db = StatsDb::open(&db_path).await?;

    // Initialize Prometheus metrics registry with 18 metrics per Table 14.2
    let metrics = MetricsRegistry::new(
        env!("CARGO_PKG_VERSION"),
        option_env!("SITO_BUILD_COMMIT").unwrap_or("unknown"),
    );

    // Initialize QueryLogWriter (10k buffer per M5.1)
    let querylog_writer = QueryLogWriter::spawn_with_anonymize(
        stats_db.clone(),
        QUERYLOG_BUFFER,
        config.privacy.anonymize_querylog,
    );
    let querylog_sender = querylog_writer.sender();

    // Forward querylog drop counters to Prometheus (the writer cannot depend on
    // the metrics registry directly without a circular dependency).
    {
        let sender = querylog_sender.clone();
        let metrics = metrics.clone();
        let mut drop_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(QUERYLOG_METRICS_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        metrics.set_querylog_dropped(sender.dropped_total());
                    }
                    res = drop_shutdown.changed() => {
                        if res.is_err() || *drop_shutdown.borrow() {
                            metrics.set_querylog_dropped(sender.dropped_total());
                            break;
                        }
                    }
                }
            }
        });
    }

    // Initialize upstream manager with bootstrap resolver
    let bootstrap = BootstrapResolver::from_config(&config.upstream);
    let upstream_manager =
        Arc::new(UpstreamManager::from_config(&config.upstream, &bootstrap).await?);
    let _health_handle = upstream_manager.start_health_prober(shutdown_rx.clone());

    // Initialize cache
    let cache = Arc::new(DnsCache::new(config.dns.cache.clone()));

    // Initialize hosts filter. The observer records both the initial load and
    // every scheduled refresh in `sito_filter_compile_seconds`.
    let filter_engine = Arc::new(
        HostsFilterEngine::init_with_observer(
            config.filtering.clone(),
            config.server.data_dir.clone(),
            Some(metrics.compile_observer()),
        )
        .await,
    );
    // Publish the initial load result and then keep the gauges in sync with
    // every API/scheduled reload.
    metrics.set_filter_status(filter_status_metrics(&filter_engine.status()));
    {
        let metrics = metrics.clone();
        filter_engine.set_status_observer(Arc::new(move |status| {
            metrics.set_filter_status(filter_status_metrics(status));
        }));
    }
    let _refresh_handle = filter_engine
        .clone()
        .spawn_refresh_task(shutdown_rx.clone());

    Ok(RuntimeComponents {
        stats_db,
        metrics,
        querylog_writer,
        querylog_sender,
        upstream_manager,
        cache,
        filter_engine,
    })
}

/// Handles shared with [`run_config_watcher`].
struct ConfigWatcher {
    ctx: sito_api::ServerContext,
    /// Hook-owned components shared with the REST/UI config write paths.
    hooks: Arc<ServerApplyHooks>,
    shutdown_rx: watch::Receiver<bool>,
}

/// Applies the components that are not reachable through [`ServerContext`]:
/// DNSSEC validator, per-client scoped upstreams, rate limiters, DNS listener
/// rebind and the log level. Shared by the file watcher and the API/UI config
/// write paths through [`sito_api::config_apply::ConfigApplyHooks`].
struct ServerApplyHooks {
    filter: Arc<HostsFilterEngine>,
    dnssec: Arc<ArcSwap<DnssecValidator>>,
    /// Authenticated DNSSEC chain statuses shared across validator swaps. A
    /// hot reload must not forget that a zone was proven signed/unsigned.
    dnssec_chain_cache: Arc<sito_dnssec::ChainCache>,
    scoped_upstreams: Arc<ArcSwap<HashMap<String, Arc<UpstreamManager>>>>,
    rate_limiters: Arc<std::sync::Mutex<Vec<Arc<sito_transport::RateLimiter>>>>,
    listener_manager: Arc<tokio::sync::Mutex<Option<DnsListenerManager>>>,
    listener_acceptors: Arc<tokio::sync::Mutex<Option<ListenerAcceptors>>>,
    pipeline: Arc<DnsPipeline>,
}

impl sito_api::config_apply::ConfigApplyHooks for ServerApplyHooks {
    fn apply<'a>(
        &'a self,
        cfg: &'a Config,
        clients: &'a sito_clients::ClientsConfig,
    ) -> sito_api::config_apply::ApplyFuture<'a> {
        Box::pin(async move {
            if crate::logging::reload_level(&cfg.server.log_level) {
                info!(
                    level = %cfg.server.log_level,
                    "Applied hot-reloaded log level"
                );
            }

            // Per-group rule sets must follow the client policy snapshot.
            self.filter.set_group_rules(group_rule_sets(clients));

            // DNSSEC settings are not read through the config snapshot at query
            // time; swap the validator so mode/anchors/NTAs apply immediately.
            // The chain cache is reused so a reload does not lose authenticated
            // signed/unsigned zone evidence.
            self.dnssec
                .store(Arc::new(DnssecValidator::from_config_with_cache(
                    &cfg.dns.dnssec,
                    Some(self.dnssec_chain_cache.clone()),
                )));

            // Rebuild per-client upstream scopes, reusing managers whose
            // upstream set is unchanged.
            let rebuilt_scoped = {
                let existing = self.scoped_upstreams.load_full();
                build_scoped_upstreams(cfg, clients, &existing).await
            };
            self.scoped_upstreams.store(Arc::new(rebuilt_scoped));

            if let Ok(limiters) = self.rate_limiters.lock() {
                for limiter in limiters.iter() {
                    limiter.set_rate(cfg.dns.rate_limit_per_ip);
                }
            }

            // Rebind listeners when bind/port/related settings change. The
            // manager stays in the slot across failures so a later event can
            // retry instead of orphaning the server.
            {
                let mut slot = self.listener_manager.lock().await;
                if let Some(manager) = slot.as_mut()
                    && manager.needs_restart(cfg)
                {
                    let acceptors = self.listener_acceptors.lock().await.clone();
                    if let Some(acceptors) = acceptors {
                        info!("DNS listener bindings changed; rebinding in-process");
                        if let Err(e) = manager
                            .restart(
                                cfg,
                                self.pipeline.clone(),
                                acceptors,
                                self.rate_limiters.clone(),
                            )
                            .await
                        {
                            return Err(sito_api::error::ProblemDetails::internal_error(format!(
                                "Failed to rebind DNS listeners: {e}"
                            )));
                        }
                    } else {
                        warn!("Listener TLS acceptors unavailable; keeping current listeners");
                    }
                }
            }

            Ok(())
        })
    }
}

/// Production [`sito_ha::SlaveConfigApplier`] backed by the shared
/// [`ServerContext`] and the hook-owned components.
///
/// This is the single apply/persist path for pushed HA configurations: the
/// slave worker calls it before advancing the applied-version watermark or
/// ACKing `applied: true`.
pub struct HaConfigApplier {
    ctx: sito_api::ServerContext,
    hooks: Arc<dyn sito_api::config_apply::ConfigApplyHooks>,
    /// Set only after `init_tls_and_acme` and `DnsListenerManager::start` have
    /// produced the listener generation and shared rate limiters. Before that,
    /// a push must not be acknowledged: applying it would silently skip the
    /// listener/rate-limit components.
    listeners_ready: Arc<std::sync::atomic::AtomicBool>,
}

impl HaConfigApplier {
    #[must_use]
    pub fn new(
        ctx: sito_api::ServerContext,
        hooks: Arc<dyn sito_api::config_apply::ConfigApplyHooks>,
    ) -> Self {
        Self {
            ctx,
            hooks,
            listeners_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Opens the readiness gate after the DNS listeners and rate limiters exist.
    pub fn mark_listeners_ready(&self) {
        self.listeners_ready
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl sito_ha::SlaveConfigApplier for HaConfigApplier {
    fn apply_and_persist<'a>(
        &'a self,
        cfg: &'a Config,
        document: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        // Never acknowledge a push before the listener generation and shared
        // rate limiters exist: otherwise a listener/rate-limit change would be
        // silently skipped while the rest is applied and persisted.
        if !self
            .listeners_ready
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Box::pin(async {
                Err("DNS listeners and rate limiters are not initialized yet".to_string())
            });
        }

        Box::pin(async move {
            // A restart-only field cannot take effect in this process. The HA
            // persist path rejects such a push *before* applying or persisting
            // anything: the worker then ACKs `applied: false`, and the live
            // configuration and the persisted file both keep the previous
            // state instead of claiming a change only a restart could honor.
            match sito_api::config_apply::apply_and_persist_document_rejecting_restart(
                &self.ctx,
                cfg,
                document,
                sito_api::config_apply::FilterApply::Sync,
                Some(&*self.hooks),
            )
            .await
            {
                Ok(report) => {
                    if !report.restart_required.is_empty() {
                        // The lock-held pre-check uses the same matrix, so this
                        // is a defensive backstop rather than a normal path.
                        warn!(
                            fields = ?report.restart_required,
                            "HA push applied but reported restart-only fields; the acknowledgement may be incomplete"
                        );
                    }
                    Ok(())
                }
                Err(e) => Err(e.detail),
            }
        })
    }
}

/// Spawns the pending slave worker once the listener generation and shared
/// rate limiters exist.
///
/// The applier's readiness gate is opened here, immediately before spawning, so
/// a push can never be acknowledged while listener/rate-limit components are
/// still uninitialized. Master roles have no pending receiver and are a no-op.
#[allow(clippy::too_many_arguments)]
fn spawn_slave_worker_after_listeners(
    ha_runtime: &mut HaRuntime,
    server_ctx: &sito_api::ServerContext,
    hooks: &Arc<ServerApplyHooks>,
    runtime: &Arc<sito_runtime::RuntimeState>,
    filter_engine: &Arc<HostsFilterEngine>,
    metrics: &sito_stats::MetricsRegistry,
    config_path: &Path,
    shutdown_rx: &watch::Receiver<bool>,
) {
    let (Some(tracker), Some(resync_rx)) = (
        ha_runtime.tracker.clone(),
        ha_runtime.resync_receiver.take(),
    ) else {
        return;
    };
    if ha_runtime.config.master_url.is_none() {
        metrics.inc_ha_startup_noop("slave", "missing_master_url");
        tracker.set_connection_error(Some(
            "master_url is not configured; replication cannot start".to_string(),
        ));
        warn!("Slave role configured without master_url; replication worker idle");
        return;
    }

    let applier = Arc::new(HaConfigApplier::new(server_ctx.clone(), hooks.clone()));
    applier.mark_listeners_ready();
    let slave_handles = sito_ha::SlaveAppHandles {
        runtime: runtime.clone(),
        filter: filter_engine.clone(),
        metrics: metrics.clone(),
        config_path: Some(config_path.to_path_buf()),
        applier,
    };
    let _slave_worker_handle = sito_ha::spawn_slave_worker(
        ha_runtime.config.clone(),
        tracker,
        slave_handles,
        resync_rx,
        shutdown_rx.clone(),
    );
}

/// Watches the configuration file and applies hot reloads in-process. Returns
/// when shutdown is signalled, when the watcher cannot be initialized, or when
/// the watched directory disappears.
async fn run_config_watcher(watcher: ConfigWatcher) {
    let ConfigWatcher {
        ctx,
        hooks,
        shutdown_rx: mut watcher_shutdown_rx,
    } = watcher;
    let watcher_config_path = ctx.config_path.clone();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let event_filter_path = watcher_config_path.clone();
    let mut watcher = match notify::recommended_watcher(move |res: Result<Event, _>| {
        if let Ok(event) = res
            && (event.kind.is_modify() || event.kind.is_create())
            && event.paths.iter().any(|path| {
                path == &event_filter_path || path.file_name() == event_filter_path.file_name()
            })
        {
            let _ = tx.send(());
        }
    }) {
        Ok(w) => w,
        Err(e) => {
            error!(
                error = %e,
                "Failed to initialize config file watcher; hot reload is DISABLED until restart"
            );
            return;
        }
    };

    // Watch the parent directory so a config file created after startup
    // (first-run wizard) is also picked up.
    let watch_target = watcher_config_path
        .parent()
        .map_or_else(|| watcher_config_path.clone(), std::path::Path::to_path_buf);
    if let Err(e) = watcher.watch(&watch_target, RecursiveMode::NonRecursive) {
        error!(
            error = %e,
            path = %watch_target.display(),
            "Failed to watch config directory; hot reload is DISABLED until restart"
        );
        return;
    }

    loop {
        tokio::select! {
            res = watcher_shutdown_rx.changed() => {
                if res.is_err() || *watcher_shutdown_rx.borrow() {
                    break;
                }
            }
            Some(()) = rx.recv() => {
                // Debounce brief bursts of file writes
                tokio::time::sleep(WATCHER_DEBOUNCE).await;
                while rx.try_recv().is_ok() {}

                match tokio::fs::read_to_string(&watcher_config_path).await {
                    Ok(content) => {
                        use sito_api::config_apply::ConfigFileApplyOutcome;
                        // Same apply/validate pipeline as every API write path.
                        // A document that already matches the runtime (the HA
                        // applier's own write or an identical save) is skipped.
                        match sito_api::config_apply::apply_config_document_event(
                            &ctx,
                            &content,
                            sito_api::config_apply::FilterApply::Sync,
                            Some(&*hooks),
                        )
                        .await
                        {
                            ConfigFileApplyOutcome::SelfWriteIgnored => {
                                info!(
                                    "Ignoring file-watcher event: the file already matches the running configuration (self-write or unchanged)"
                                );
                            }
                            ConfigFileApplyOutcome::Applied(report) => {
                                info!("Detected external configuration file change; hot-reloaded");
                                if !report.restart_required.is_empty() {
                                    warn!(
                                        fields = ?report.restart_required,
                                        "Configuration hot-reloaded; these settings need a restart to take effect"
                                    );
                                }
                            }
                            ConfigFileApplyOutcome::Rejected(e) => {
                                error!(
                                    status = e.status,
                                    detail = %e.detail,
                                    "Rejecting config hot-reload: configuration cannot be applied"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read modified configuration file: {e}");
                    }
                }
            }
        }
    }
}

/// Loads the embedded parental-control and service-blocking registries.
///
/// Uses the non-panicking `try_bundled()` loaders: corrupted embedded data is
/// a packaging/build defect, so startup must be able to report it and exit
/// cleanly instead of aborting with a panic.
fn load_bundled_registries() -> anyhow::Result<(
    Arc<sito_clients::ParentalRegistry>,
    Arc<sito_clients::ServiceRegistry>,
)> {
    let parental = sito_clients::ParentalRegistry::try_bundled().map_err(|e| {
        anyhow::anyhow!(
            "failed to load embedded parental-control lists (corrupt bundled data): {e}"
        )
    })?;
    let services = sito_clients::ServiceRegistry::try_bundled().map_err(|e| {
        anyhow::anyhow!(
            "failed to load embedded service-blocking rules (corrupt bundled data): {e}"
        )
    })?;
    Ok((Arc::new(parental), Arc::new(services)))
}

/// Runs the complete sito DNS server with graceful shutdown handling.
pub async fn run_server(config: Config) -> anyhow::Result<()> {
    let config_path = config.server.data_dir.join("config.toml");
    run_server_full(config, config_path, None, false).await
}

/// Runs the DNS server with an optional custom shutdown receiver (useful for testing).
pub async fn run_server_with_shutdown(
    config: Config,
    custom_shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    let config_path = config.server.data_dir.join("config.toml");
    run_server_full(config, config_path, custom_shutdown, false).await
}

/// Startup phases that expose different listeners. The admin UI starts even in
/// setup-pending mode; DNS listeners start only after setup (or immediately in
/// a normal boot), so their warning is emitted at that transition.
#[derive(Clone, Copy)]
enum ExposurePhase {
    Startup,
    DnsListeners,
}

/// Returns the exposure warnings relevant to a startup phase.
fn exposure_warnings_for_phase(config: &Config, phase: ExposurePhase) -> Vec<String> {
    let warning = match phase {
        ExposurePhase::Startup => config.web_exposure_warning(),
        ExposurePhase::DnsListeners => config.dns_exposure_warning(),
    };
    warning.into_iter().collect()
}

/// Runs the DNS server with custom config path, shutdown receiver, and setup-pending mode.
pub async fn run_server_full(
    config: Config,
    config_path: impl AsRef<Path>,
    custom_shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
    setup_pending: bool,
) -> anyhow::Result<()> {
    validate_typed_sections(&config)?;

    // Make the historical wildcard defaults visible at startup. This is a
    // warning, not a refusal: existing Docker/quickstart configurations must
    // keep starting. 1.10.0 changes the defaults and is documented separately.
    for warning in exposure_warnings_for_phase(&config, ExposurePhase::Startup) {
        warn!("NETWORK EXPOSURE: {warning}");
    }

    // Hold a single-instance lease for the whole server lifetime. The reset
    // commands use the same lease to distinguish "stopped" from "running" and
    // refuse to pretend that credentials/sessions were revoked live.
    let _service_lease =
        crate::service_lock::ServiceLease::acquire(&config.server.data_dir).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                anyhow::anyhow!(
                    "Another sito server is already running for data directory '{}'. Stop it before starting a second instance. ({e})",
                    config.server.data_dir.display()
                )
            } else {
                anyhow::anyhow!(
                    "Failed to acquire the service lease in '{}': {e}",
                    config.server.data_dir.display()
                )
            }
        })?;

    // Canonicalize so the file watcher compares absolute event paths, and so
    // the default relative `config.toml` still yields a watchable directory.
    let config_path_buf = canonical_config_path(config_path.as_ref());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let in_flight = Arc::new(AtomicUsize::new(0));

    let components = init_runtime_components(&config, &shutdown_rx).await?;
    let stats_db = components.stats_db;
    let metrics = components.metrics;
    let querylog_writer = components.querylog_writer;
    let querylog_sender = components.querylog_sender;
    let upstream_manager = components.upstream_manager;
    let cache = components.cache;
    let filter_engine = components.filter_engine;
    metrics.set_filter_rules(filter_engine.rule_count());

    // Initialize DNSSEC validator. The authenticated chain cache lives under
    // the data dir and is reused across hot reloads; it is deliberately not
    // part of HA bundles or backups (each node rebuilds its own).
    let dnssec_chain_cache = Arc::new(sito_dnssec::ChainCache::new(Some(
        config.server.data_dir.join("dnssec-chain-cache.toml"),
    )));
    dnssec_chain_cache.load(unix_now());
    let dnssec_swap = Arc::new(ArcSwap::from(Arc::new(
        DnssecValidator::from_config_with_cache(
            &config.dns.dnssec,
            Some(dnssec_chain_cache.clone()),
        ),
    )));

    // Initialize client registry
    let clients_config = clients_from_config(&config)?;
    // Compile per-group rule sets so group `lists`/`custom_rules` actually
    // apply (previously they were stored but never evaluated).
    filter_engine.set_group_rules(group_rule_sets(&clients_config));

    // Build per-client upstream managers for entries that opt out of the globals.
    let scoped_upstreams: Arc<ArcSwap<HashMap<String, Arc<UpstreamManager>>>> =
        Arc::new(ArcSwap::from(Arc::new(
            build_scoped_upstreams(&config, &clients_config, &HashMap::new()).await,
        )));

    let client_registry = Arc::new(sito_clients::ClientRegistry::new(clients_config));

    // Initialize parental and service registries
    let (parental_registry, service_registry) = load_bundled_registries()?;
    let runtime_lists = Arc::new(sito_clients::RuntimeLists::from_arcs(
        parental_registry.clone(),
        service_registry.clone(),
    ));
    let integrations = integrations_from_config(&config)?;
    if let Some(ref integrations) = integrations
        && let Some(ref lists_cfg) = integrations.lists
    {
        let lists_cfg = lists_cfg.clone();
        if let Err(e) = lists_cfg.validate() {
            warn!("Ignoring invalid [integrations.lists] configuration: {e}");
        } else if !lists_cfg.categories.is_empty() {
            let lists_store = runtime_lists.clone();
            let lists_data_dir = config.server.data_dir.clone();
            let lists_shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                run_list_refresh(lists_cfg, lists_store, lists_data_dir, lists_shutdown).await;
            });
        }
    }

    // Initialize local rewrites table
    let rewrites_config = rewrites_from_config(&config)?;
    let rewrite_table = Arc::new(sito_rewrites::RewriteTable::new(rewrites_config));

    // Initialize MikroTik RouterOS integration if configured
    if let Some(integrations) = integrations
        && let Some(mikrotik_cfg) = integrations.mikrotik
        && mikrotik_cfg.enabled
    {
        let _routeros_handle = sito_clients::spawn_routeros_sync(
            mikrotik_cfg,
            client_registry.clone(),
            shutdown_rx.clone(),
        );
    }

    // Setup ArcSwaps for hot-reloadable components and a coherent runtime view
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config.clone())));
    let clients_arc = Arc::new(ArcSwap::new(client_registry.clone()));
    let rewrites_arc = Arc::new(ArcSwap::new(rewrite_table.clone()));
    let runtime = Arc::new(sito_runtime::RuntimeState::new(
        config_arc.clone(),
        clients_arc.clone(),
        rewrites_arc.clone(),
    ));

    // Construct pipeline with query logging and Prometheus metrics
    let pipeline = Arc::new(
        DnsPipeline::new(
            config_arc.clone(),
            filter_engine.clone(),
            cache.clone(),
            upstream_manager.clone(),
            dnssec_swap.load_full(),
            clients_arc.clone(),
            parental_registry,
            service_registry,
            rewrites_arc.clone(),
            in_flight.clone(),
        )
        .with_runtime(runtime.clone())
        .with_runtime_lists(runtime_lists.clone())
        .with_shared_dnssec(dnssec_swap.clone())
        .with_shared_scoped_upstreams(scoped_upstreams.clone())
        .with_stats(querylog_sender.clone(), metrics.clone()),
    );

    // Initialize High Availability (HA) clustering subsystem per role
    let mut ha_runtime = init_ha(&config, &config_path_buf, &metrics, &shutdown_rx)?;
    let _ha_config = ha_runtime.config.clone();
    let (master_coordinator, slave_tracker, resync_sender) = (
        ha_runtime.coordinator.clone(),
        ha_runtime.tracker.clone(),
        ha_runtime.resync_sender.clone(),
    );

    // Administrative REST API server
    let auth_cfg = config.get_auth_config();
    // Only bootstrap the default admin when no persisted configuration exists
    // (setup wizard / --no-setup first boot). If config.toml exists but
    // users.toml is missing, fail closed instead of silently re-enabling the
    // default credentials.
    let bootstrap_allowed = !config_path_buf.exists();
    let auth_mgr = Arc::new(sito_api::AuthManager::with_storage_full(
        &config.server.data_dir,
        auth_cfg.session_ttl_hours,
        auth_cfg.login_rate_limit,
        bootstrap_allowed,
        auth_cfg.session_persist,
        auth_cfg.token_default_ttl_days,
    )?);
    auth_mgr.spawn_pruner(shutdown_rx.clone());

    let (dns_start_tx, mut dns_start_rx) = tokio::sync::mpsc::unbounded_channel();
    let dns_starter = if setup_pending {
        Some(dns_start_tx)
    } else {
        None
    };

    // Rate limiters created by listeners; shared so hot reloads can update them.
    let rate_limiters: Arc<std::sync::Mutex<Vec<Arc<sito_transport::RateLimiter>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    // Listener generation and TLS acceptors, shared so bind/port changes can be
    // applied in-process by the watcher and the API/UI config write paths.
    let listener_manager: Arc<tokio::sync::Mutex<Option<DnsListenerManager>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let listener_acceptors: Arc<tokio::sync::Mutex<Option<ListenerAcceptors>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    let apply_hooks = Arc::new(ServerApplyHooks {
        filter: filter_engine.clone(),
        dnssec: dnssec_swap.clone(),
        dnssec_chain_cache: dnssec_chain_cache.clone(),
        scoped_upstreams: scoped_upstreams.clone(),
        rate_limiters: rate_limiters.clone(),
        listener_manager: listener_manager.clone(),
        listener_acceptors: listener_acceptors.clone(),
        pipeline: pipeline.clone(),
    });

    let server_ctx = sito_api::ServerContext {
        config: config_arc.clone(),
        runtime: runtime.clone(),
        runtime_lists: runtime_lists.clone(),
        config_path: config_path_buf.clone(),
        auth_mgr,
        stats_db: stats_db.clone(),
        querylog_sender: querylog_sender.clone(),
        metrics: metrics.clone(),
        filter: filter_engine.clone(),
        cache: cache.clone(),
        upstream: upstream_manager.clone(),
        clients: clients_arc.clone(),
        rewrites: rewrites_arc.clone(),
        start_time: Instant::now(),
        restore_tokens: Arc::new(Mutex::new(HashMap::new())),
        apply_lock: Arc::new(tokio::sync::Mutex::new(())),
        master_coordinator: master_coordinator.clone(),
        slave_tracker: slave_tracker.clone(),
        resync_sender,
        setup_pending: Arc::new(std::sync::atomic::AtomicBool::new(setup_pending)),
        dns_starter,
    };

    let api_router = sito_api::create_router_with_hooks(
        server_ctx.clone(),
        sito_api::config_apply::ApplyHooks::new(apply_hooks.clone()),
    );
    let web_cfg = config_arc.load().get_web_config();
    if web_cfg.enabled {
        let web_addr = SocketAddr::new(web_cfg.bind, web_cfg.port);
        let listener = tokio::net::TcpListener::bind(web_addr).await.map_err(|e| {
            anyhow::anyhow!("Failed to bind web admin interface to {web_addr}: {e}")
        })?;
        let bound_addr = listener.local_addr()?;
        let mut api_shutdown_rx = shutdown_rx.clone();
        let make_svc = api_router.into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, make_svc)
                .with_graceful_shutdown(async move {
                    while !*api_shutdown_rx.borrow_and_update() {
                        if api_shutdown_rx.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await;
        });
        info!("sito admin REST API listening on http://{bound_addr}");
    }

    // Periodic stats retention cleanup task (every 24h).
    // `retention_days` is read on every cycle so config hot-reload applies.
    let retention_db = stats_db.clone();
    let retention_config = config_arc.clone();
    let mut retention_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RETENTION_INTERVAL);
        interval.tick().await;
        loop {
            tokio::select! {
                res = retention_shutdown_rx.changed() => {
                    if res.is_err() || *retention_shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    let retention_days = retention_config.load().get_stats_config().retention_days;
                    if let Err(e) = retention_db.cleanup_retention(retention_days).await {
                        warn!("Error during stats retention cleanup: {e}");
                    }
                }
            }
        }
    });

    // Periodic DNSSEC chain-cache flush. The query path only updates an
    // in-memory dirty flag; disk I/O stays on this background task (and on the
    // shutdown path below).
    let flush_cache = dnssec_chain_cache.clone();
    let mut flush_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CHAIN_CACHE_FLUSH_INTERVAL);
        interval.tick().await;
        loop {
            tokio::select! {
                result = flush_shutdown_rx.changed() => {
                    if result.is_err() || *flush_shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    if !flush_cache.is_dirty() {
                        continue;
                    }
                    let cache = flush_cache.clone();
                    let _ = tokio::task::spawn_blocking(move || cache.flush()).await;
                }
            }
        }
    });

    // Spawn config file watcher for hot-reload. It shares the same
    // apply/validate pipeline and hook components as the API/UI write paths.
    tokio::spawn(run_config_watcher(ConfigWatcher {
        ctx: server_ctx.clone(),
        hooks: apply_hooks.clone(),
        shutdown_rx: shutdown_rx.clone(),
    }));

    let mut cert_watchers = init_tls_and_acme(&config, &shutdown_rx, &listener_acceptors).await?;

    if setup_pending {
        info!(
            "Server running in setup-pending mode: DNS listeners (ports 53/853/443) are not bound until setup completes via web panel"
        );
        tokio::select! {
            res = wait_for_shutdown_signal(custom_shutdown) => {
                res?;
            }
            Some(()) = dns_start_rx.recv() => {
                info!("Setup wizard completed: binding and starting DNS listeners in-process...");
                let current_cfg = config_arc.load();
                // The wizard may have configured TLS/ACME after startup, when
                // the initial acceptors were built from the empty config.
                // Re-initialize so DoT/DoH/DoQ listen immediately instead of
                // requiring a restart.
                match init_tls_and_acme(&current_cfg, &shutdown_rx, &listener_acceptors).await {
                    Ok(watchers) => cert_watchers.extend(watchers),
                    Err(e) => warn!(
                        error = %e,
                        "Failed to initialize TLS after setup; encrypted listeners may be unavailable"
                    ),
                }
                let acceptors = listener_acceptors
                    .lock()
                    .await
                    .clone()
                    .unwrap_or(ListenerAcceptors {
                        dot: None,
                        doh: None,
                        doq: None,
                        doh3: None,
                        acme_challenges: AcmeChallengeAvailability::default(),
                    });
                for warning in
                    exposure_warnings_for_phase(&current_cfg, ExposurePhase::DnsListeners)
                {
                    warn!("NETWORK EXPOSURE: {warning}");
                }
                let manager = DnsListenerManager::start(
                    &current_cfg,
                    pipeline.clone(),
                    acceptors,
                    rate_limiters.clone(),
                )
                .await?;
                *listener_manager.lock().await = Some(manager);
                spawn_slave_worker_after_listeners(
                    &mut ha_runtime,
                    &server_ctx,
                    &apply_hooks,
                    &runtime,
                    &filter_engine,
                    &metrics,
                    &config_path_buf,
                    &shutdown_rx,
                );

                info!(
                    port = current_cfg.dns.port,
                    bind = ?current_cfg.dns.bind,
                    "sito DNS server successfully initialized and listening"
                );

                wait_for_shutdown_signal(None).await?;
            }
        }
    } else {
        let acceptors = listener_acceptors
            .lock()
            .await
            .clone()
            .unwrap_or(ListenerAcceptors {
                dot: None,
                doh: None,
                doq: None,
                doh3: None,
                acme_challenges: AcmeChallengeAvailability::default(),
            });
        // Start from the current configuration (the watcher may already have
        // applied a file change during startup), not the stale startup copy.
        let listener_config = config_arc.load();
        for warning in exposure_warnings_for_phase(&listener_config, ExposurePhase::DnsListeners) {
            warn!("NETWORK EXPOSURE: {warning}");
        }
        let manager = DnsListenerManager::start(
            &listener_config,
            pipeline.clone(),
            acceptors,
            rate_limiters.clone(),
        )
        .await?;
        *listener_manager.lock().await = Some(manager);
        spawn_slave_worker_after_listeners(
            &mut ha_runtime,
            &server_ctx,
            &apply_hooks,
            &runtime,
            &filter_engine,
            &metrics,
            &config_path_buf,
            &shutdown_rx,
        );

        info!(
            port = listener_config.dns.port,
            bind = ?listener_config.dns.bind,
            "sito DNS server successfully initialized and listening"
        );

        // Wait for termination signal
        wait_for_shutdown_signal(custom_shutdown).await?;
    }

    shutdown_server(
        &shutdown_tx,
        &listener_manager,
        &in_flight,
        querylog_writer,
        cert_watchers,
        &dnssec_chain_cache,
    )
    .await;
    Ok(())
}

/// Stops listeners, drains in-flight queries within the shutdown budget,
/// flushes the query log and releases the certificate watchers.
async fn shutdown_server(
    shutdown_tx: &watch::Sender<bool>,
    listener_manager: &tokio::sync::Mutex<Option<DnsListenerManager>>,
    in_flight: &AtomicUsize,
    querylog_writer: QueryLogWriter,
    cert_watchers: Vec<sito_transport::CertWatcher>,
    dnssec_chain_cache: &sito_dnssec::ChainCache,
) {
    info!("Initiating graceful shutdown (stopping listeners)...");
    let _ = shutdown_tx.send(true);
    let current_manager = listener_manager.lock().await.take();
    if let Some(mut manager) = current_manager {
        manager.stop().await;
    }

    // Wait for in-flight queries to finish (5 s timeout per plan section 3.5)
    let shutdown_deadline = std::time::Instant::now() + SHUTDOWN_DRAIN_TIMEOUT;
    while in_flight.load(Ordering::SeqCst) > 0 {
        if std::time::Instant::now() >= shutdown_deadline {
            warn!(
                remaining = in_flight.load(Ordering::SeqCst),
                "Graceful shutdown timeout reached; draining remaining queries"
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    info!("Flushing and shutting down query log writer...");
    querylog_writer.shutdown().await;

    // Persist any authenticated DNSSEC chain statuses before exiting.
    if let Err(error) = dnssec_chain_cache.flush() {
        warn!(error = %error, "Failed to flush DNSSEC chain cache during shutdown");
    }

    // Stop certificate watchers after listeners have drained.
    drop(cert_watchers);

    info!("Graceful shutdown complete, exiting");
}

/// Loads certificates and ACME configuration, builds the per-protocol TLS
/// acceptors, publishes them for in-process listener rebinds, starts the ACME
/// renewal manager and returns the certificate watchers that must stay alive.
async fn init_tls_and_acme(
    config: &Config,
    shutdown_rx: &watch::Receiver<bool>,
    listener_acceptors: &tokio::sync::Mutex<Option<ListenerAcceptors>>,
) -> anyhow::Result<Vec<sito_transport::CertWatcher>> {
    // ACME and TLS setup
    let acme_cfg = config.get_acme_config();
    let is_acme_enabled = acme_cfg
        .as_ref()
        .is_some_and(|a| a.enabled && !a.domains.is_empty());

    let (cert_file, key_file, sni_tuples) = if let Some(tls_cfg) = config.get_tls_config() {
        if let (Some(cert), Some(key)) = (&tls_cfg.cert, &tls_cfg.key) {
            (Some(cert.clone()), Some(key.clone()), tls_cfg.sni_tuples())
        } else {
            (None, None, Vec::new())
        }
    } else {
        (None, None, Vec::new())
    };
    let static_pair = match (cert_file, key_file) {
        (Some(cert), Some(key)) => Some((cert, key)),
        _ => None,
    };

    // Build the ACME service configuration once; it is also used to decide
    // whether an existing stored certificate should take precedence over
    // static `[tls]` material at startup.
    let acme_service_cfg = if is_acme_enabled {
        let Some(acme) = acme_cfg.as_ref() else {
            // `is_acme_enabled` is derived from `acme_cfg`; this guard
            // keeps the startup path panic-free even if that changes.
            anyhow::bail!("ACME is enabled but the ACME configuration is missing");
        };
        let email = if let Some(email) = acme.email.clone() {
            email
        } else {
            warn!(
                "[acme] enabled without an account email; using admin@example.com. Set acme.email to receive expiry notices."
            );
            "admin@example.com".to_string()
        };
        let storage_dir = acme
            .cache_dir
            .clone()
            .unwrap_or_else(|| config.server.data_dir.join("acme"));
        Some(
            AcmeServiceConfig::new(email, acme.domains.clone(), storage_dir)
                .with_staging(acme.staging),
        )
    } else {
        None
    };

    let (acme_pair, acme_pair_usable) = if let Some(service_cfg) = &acme_service_cfg {
        let cert_path = service_cfg.storage_dir.join("cert.pem");
        let key_path = service_cfg.storage_dir.join("key.pem");
        let pair = (cert_path.exists() && key_path.exists()).then_some((cert_path, key_path));
        let usable = pair.is_some()
            && !service_cfg.is_bootstrap_cert()
            && !service_cfg.stored_cert_is_expired();
        (pair, usable)
    } else {
        (None, false)
    };

    // D12: bootstrap serving is opt-in and defaults to fail-closed.
    let allow_bootstrap_cert = acme_cfg
        .as_ref()
        .is_some_and(|acme| acme.enabled && acme.allow_bootstrap_cert);
    let material = match choose_tls_material(
        static_pair,
        acme_pair,
        acme_pair_usable,
        is_acme_enabled,
        allow_bootstrap_cert,
    ) {
        TlsStartupMaterial::Pair(cert, key) => Some((cert, key)),
        TlsStartupMaterial::Disabled => None,
        TlsStartupMaterial::GenerateBootstrap => {
            let Some(service_cfg) = &acme_service_cfg else {
                anyhow::bail!(
                    "Bootstrap certificate was requested but ACME configuration is missing"
                );
            };
            std::fs::create_dir_all(&service_cfg.storage_dir).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to create ACME storage directory {}: {e}",
                    service_cfg.storage_dir.display()
                )
            })?;
            let (cert_pem, key_pem) = generate_self_signed_cert(&service_cfg.domains)
                .map_err(|e| anyhow::anyhow!("Failed to generate bootstrap certificate: {e}"))?;
            let cert_path = service_cfg.storage_dir.join("cert.pem");
            let key_path = service_cfg.storage_dir.join("key.pem");
            std::fs::write(&cert_path, cert_pem).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to write bootstrap certificate to {}: {e}",
                    cert_path.display()
                )
            })?;
            // The bootstrap private key must be 0600: local users must not
            // read it before ACME replaces it.
            write_secret_file(&key_path, key_pem.as_bytes()).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to write bootstrap key to {}: {e}",
                    key_path.display()
                )
            })?;
            record_bootstrap_cert(&service_cfg.storage_dir).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to record bootstrap certificate in {}: {e}",
                    service_cfg.storage_dir.display()
                )
            })?;
            info!(
                "Generated bootstrap self-signed certificate in {:?} (allow_bootstrap_cert = true)",
                service_cfg.storage_dir
            );
            Some((cert_path, key_path))
        }
    };

    if material.is_none() && is_acme_enabled {
        warn!(
            "ACME is enabled but no trusted certificate is available and \
             acme.allow_bootstrap_cert is false; encrypted listeners are disabled \
             until ACME issuance completes and the server is restarted"
        );
    }

    let http01_challenges = Arc::new(dashmap::DashMap::<String, String>::new());
    let challenge_keys = Arc::new(dashmap::DashMap::new());
    // Kept alive for the lifetime of the server so certificate hot-reload works.
    let mut cert_watchers: Vec<sito_transport::CertWatcher> = Vec::new();

    let (dot_acceptor_mgr, doh_acceptor_mgr, doq_acceptor_mgr, doh3_acceptor_mgr) =
        if let Some((cert, key)) = &material {
            let doh_mgr = build_tls_acceptor(
                "doh",
                cert,
                key,
                &sni_tuples,
                &[b"h2".to_vec(), b"http/1.1".to_vec(), b"acme-tls/1".to_vec()],
                Some(challenge_keys.clone()),
                &mut cert_watchers,
            )?;
            let dot_mgr = build_tls_acceptor(
                "dot",
                cert,
                key,
                &sni_tuples,
                &[b"dot".to_vec()],
                None,
                &mut cert_watchers,
            )?;
            let doq_mgr = build_tls_acceptor(
                "doq",
                cert,
                key,
                &sni_tuples,
                &[b"doq".to_vec()],
                None,
                &mut cert_watchers,
            )?;
            let doh3_mgr = build_tls_acceptor(
                "doh3",
                cert,
                key,
                &sni_tuples,
                &[b"h3".to_vec()],
                None,
                &mut cert_watchers,
            )?;
            (Some(dot_mgr), Some(doh_mgr), Some(doq_mgr), Some(doh3_mgr))
        } else {
            (None, None, None, None)
        };

    // Live challenge state starts fail-safe: no TLS-ALPN-01 until a 443 DoH
    // listener actually binds (done later by `start_dns_listeners`).
    let acme_challenges = AcmeChallengeAvailability::new(false, false);

    // If ACME is enabled, start ACME renewal background manager
    if let (Some(service_cfg), Some(acme)) = (acme_service_cfg, acme_cfg.as_ref()) {
        // Dedicated plaintext HTTP-01 listener (ACME validators always use port 80).
        let mut http01_available = false;
        if acme.http_port > 0 {
            let acme_http_addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                acme.http_port,
            );
            match sito_transport::start_acme_http01_listener(
                acme_http_addr,
                http01_challenges.clone(),
                shutdown_rx.clone(),
            )
            .await
            {
                Ok(_handle) => {
                    http01_available = true;
                    info!(
                        port = acme.http_port,
                        "ACME HTTP-01 challenge listener active"
                    );
                }
                Err(e) => warn!(
                    port = acme.http_port,
                    error = %e,
                    "Failed to bind ACME HTTP-01 listener; HTTP-01 validation will not be available"
                ),
            }
        }

        acme_challenges.set_http01_available(http01_available);
        let managers = TlsManagerSet {
            dot: dot_acceptor_mgr.clone(),
            doh: doh_acceptor_mgr.clone(),
            doq: doq_acceptor_mgr.clone(),
            doh3: doh3_acceptor_mgr.clone(),
        };
        let _acme_handle = start_acme_manager_for_transports(
            service_cfg,
            managers,
            Some(http01_challenges.clone()),
            acme_challenges.clone(),
            shutdown_rx.clone(),
        );
    }

    // Share TLS acceptors with the config watcher for in-process listener rebinds.
    *listener_acceptors.lock().await = Some(ListenerAcceptors {
        dot: dot_acceptor_mgr,
        doh: doh_acceptor_mgr,
        doq: doq_acceptor_mgr,
        doh3: doh3_acceptor_mgr,
        acme_challenges,
    });

    Ok(cert_watchers)
}

/// Periodically refreshes `[integrations.lists]` categories through the
/// shared subscription downloader (ETag/disk cache/size caps) and swaps the
/// runtime registries on success.
pub(crate) async fn run_list_refresh(
    config: sito_clients::ListCategoriesConfig,
    store: Arc<sito_clients::RuntimeLists>,
    data_dir: PathBuf,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let fetcher =
        sito_filter::subscription::SubscriptionFetcher::default().with_file_root(data_dir.clone());
    let default_hours = config.refresh_hours.max(1);
    let mut entries: Vec<(String, String, Duration, tokio::time::Instant)> = config
        .categories
        .into_iter()
        .map(|(name, source)| {
            let hours = source.refresh_hours.unwrap_or(default_hours).max(1);
            (
                name,
                source.url,
                Duration::from_secs(hours.saturating_mul(3600)),
                tokio::time::Instant::now(),
            )
        })
        .collect();
    if entries.is_empty() {
        return;
    }

    while let Some((next_idx, _)) = entries.iter().enumerate().min_by_key(|(_, entry)| entry.3) {
        let wait = entries[next_idx]
            .3
            .saturating_duration_since(tokio::time::Instant::now());

        tokio::select! {
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            () = tokio::time::sleep(wait) => {
                let name = entries[next_idx].0.clone();
                let url = entries[next_idx].1.clone();
                let cache_name = format!("integration-{name}");
                match fetcher.fetch_or_cached(&cache_name, &url, &data_dir).await {
                    Ok(content) => match store.apply_content(&name, &content) {
                        Ok(entries) => {
                            store.mark_refreshed(&name, &url);
                            info!(
                                category = %name,
                                url = %url,
                                entries,
                                "Refreshed curated list category"
                            );
                        }
                        Err(e) => warn!(
                            category = %name,
                            "Ignoring invalid refreshed curated list: {e}"
                        ),
                    },
                    Err(e) => warn!(
                        category = %name,
                        url = %url,
                        "Failed to refresh curated list: {e}"
                    ),
                }
                entries[next_idx].3 =
                    tokio::time::Instant::now() + entries[next_idx].2;
            }
        }
    }
}

/// TLS acceptor managers shared with the config watcher so listeners can be
/// rebound without restarting the process.
#[derive(Clone)]
struct ListenerAcceptors {
    dot: Option<TlsAcceptorManager>,
    doh: Option<TlsAcceptorManager>,
    doq: Option<TlsAcceptorManager>,
    doh3: Option<TlsAcceptorManager>,
    /// Live ACME challenge-listener state, updated after every DNS bind.
    acme_challenges: AcmeChallengeAvailability,
}

/// Settings that determine how the DNS listeners are constructed. Changing
/// any of them requires stopping and rebinding the affected listeners.
#[derive(Clone, PartialEq, Eq)]
struct ListenerPlan {
    bind: Vec<std::net::IpAddr>,
    port: u16,
    dot_port: u16,
    doh_port: u16,
    doq_port: u16,
    doh3_port: u16,
    doh_dedicated_hostname: String,
    allow_plaintext_doh: bool,
    edns_udp_size: u16,
    max_tcp_connections: usize,
    dot_padding: bool,
}

impl ListenerPlan {
    fn from_config(config: &Config) -> Self {
        Self {
            bind: config.dns.bind.clone(),
            port: config.dns.port,
            dot_port: config.dns.dot_port,
            doh_port: config.dns.doh_port,
            doq_port: config.dns.doq_port,
            doh3_port: config.dns.doh3_port,
            doh_dedicated_hostname: config.dns.doh_dedicated_hostname.clone(),
            allow_plaintext_doh: config.dns.allow_plaintext_doh,
            edns_udp_size: config.dns.edns_udp_size,
            max_tcp_connections: config.dns.max_tcp_connections,
            dot_padding: config.dns.dot_padding,
        }
    }
}

/// Owns one generation of DNS listener tasks and supports rebinding.
struct DnsListenerManager {
    shutdown_tx: watch::Sender<bool>,
    handles: Vec<tokio::task::JoinHandle<()>>,
    rate_limiters: Arc<std::sync::Mutex<Vec<Arc<sito_transport::RateLimiter>>>>,
    plan: ListenerPlan,
    config: Config,
}

impl DnsListenerManager {
    async fn start(
        config: &Config,
        pipeline: Arc<DnsPipeline>,
        acceptors: ListenerAcceptors,
        rate_limiters: Arc<std::sync::Mutex<Vec<Arc<sito_transport::RateLimiter>>>>,
    ) -> anyhow::Result<Self> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let acme_challenges = acceptors.acme_challenges.clone();
        let (handles, limiters) = start_dns_listeners(
            config,
            pipeline,
            shutdown_rx,
            acceptors.dot,
            acceptors.doh,
            acceptors.doq,
            acceptors.doh3,
            acme_challenges,
        )
        .await?;

        if let Ok(mut registry) = rate_limiters.lock() {
            registry.clear();
            registry.extend(limiters);
        }

        Ok(Self {
            shutdown_tx,
            handles,
            rate_limiters,
            plan: ListenerPlan::from_config(config),
            config: config.clone(),
        })
    }

    fn needs_restart(&self, config: &Config) -> bool {
        self.plan != ListenerPlan::from_config(config)
    }

    async fn stop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Ok(mut registry) = self.rate_limiters.lock() {
            registry.clear();
        }
        for handle in self.handles.drain(..) {
            let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        }
    }

    /// Stops the current listeners and binds a new generation. If the new
    /// bindings cannot be established, the previous configuration is restored.
    ///
    /// The manager is never consumed: even when the new bind *and* the revert
    /// fail, an empty manager stays in the slot so a later config event can
    /// attempt a rebind instead of leaving the server permanently orphaned.
    async fn restart(
        &mut self,
        config: &Config,
        pipeline: Arc<DnsPipeline>,
        acceptors: ListenerAcceptors,
        rate_limiters: Arc<std::sync::Mutex<Vec<Arc<sito_transport::RateLimiter>>>>,
    ) -> anyhow::Result<()> {
        let previous = self.config.clone();
        self.stop().await;

        match Self::start(
            config,
            pipeline.clone(),
            acceptors.clone(),
            rate_limiters.clone(),
        )
        .await
        {
            Ok(manager) => {
                *self = manager;
                Ok(())
            }
            Err(e) => {
                warn!(
                    "Failed to bind new DNS listener configuration ({e}); restoring previous bindings"
                );
                match Self::start(&previous, pipeline, acceptors, rate_limiters).await {
                    Ok(reverted) => {
                        *self = reverted;
                        Err(e)
                    }
                    Err(revert) => {
                        self.config = previous;
                        self.plan = ListenerPlan::from_config(&self.config);
                        Err(anyhow::anyhow!("{e}; revert failed: {revert}"))
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_dns_listeners(
    config: &Config,
    pipeline: Arc<DnsPipeline>,
    shutdown_rx: watch::Receiver<bool>,
    dot_acceptor_mgr: Option<TlsAcceptorManager>,
    doh_acceptor_mgr: Option<TlsAcceptorManager>,
    doq_acceptor_mgr: Option<TlsAcceptorManager>,
    doh3_acceptor_mgr: Option<TlsAcceptorManager>,
    acme_challenges: AcmeChallengeAvailability,
) -> anyhow::Result<(
    Vec<tokio::task::JoinHandle<()>>,
    Vec<Arc<sito_transport::RateLimiter>>,
)> {
    let worker_count = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let mut handles = Vec::new();
    // No TLS-ALPN-01 until a 443 DoH listener actually binds in this pass.
    acme_challenges.set_tls_alpn_available(false);
    let mut doh_443_bound = false;

    // One limiter per client IP shared by every listener (all bind addresses
    // and protocols), so an attacker cannot multiply the budget by switching
    // transport or destination address.
    let shared_limiter = Arc::new(sito_transport::RateLimiter::new(
        config.dns.rate_limit_per_ip,
        config.dns.rate_limit_per_ip * 2,
    ));
    let rate_limiters = vec![shared_limiter.clone()];

    for bind_ip in &config.dns.bind {
        let addr = SocketAddr::new(*bind_ip, config.dns.port);

        // Start UDP listener
        let udp_config = UdpConfig {
            bind_addr: addr,
            worker_count,
            edns_udp_size: config.dns.edns_udp_size,
            rate_limit_per_ip: config.dns.rate_limit_per_ip,
            rate_limiter: Some(shared_limiter.clone()),
        };
        let udp_handles = start_udp_listener(&udp_config, &pipeline, &shutdown_rx)?;
        handles.extend(udp_handles);

        // Start TCP listener
        let tcp_config = TcpConfig {
            bind_addr: addr,
            max_connections: config.dns.max_tcp_connections,
            idle_timeout: Duration::from_secs(10),
            rate_limit_per_ip: config.dns.rate_limit_per_ip,
            rate_limiter: Some(shared_limiter.clone()),
        };
        let tcp_handle =
            start_tcp_listener(tcp_config, pipeline.clone(), shutdown_rx.clone()).await?;
        handles.push(tcp_handle);

        // Start DoT listener if dot_port > 0 and TLS is configured
        if config.dns.dot_port > 0 && dot_acceptor_mgr.is_none() {
            error!(
                addr = %SocketAddr::new(*bind_ip, config.dns.dot_port),
                "DoT port is configured but no TLS certificate/ACME material is available; the DoT listener is NOT running"
            );
        }
        if config.dns.dot_port > 0
            && let Some(ref dot_mgr) = dot_acceptor_mgr
        {
            let dot_addr = SocketAddr::new(*bind_ip, config.dns.dot_port);
            let mut dot_config = DotConfig::new(dot_addr, dot_mgr.clone());
            dot_config.dot_padding = config.dns.dot_padding;
            dot_config.rate_limit_per_ip = config.dns.rate_limit_per_ip;
            dot_config.rate_limiter = Some(shared_limiter.clone());
            dot_config.max_connections = config.dns.max_tcp_connections;
            let dot_handle =
                start_dot_listener(dot_config, pipeline.clone(), shutdown_rx.clone()).await?;
            handles.push(dot_handle);
        }

        // Start DoH listener if doh_port > 0. Plaintext HTTP DoH is only
        // started on unprivileged loopback ports or when explicitly opted in.
        if config.dns.doh_port > 0 {
            let plaintext_allowed = config.dns.allow_plaintext_doh
                || (bind_ip.is_loopback() && config.dns.doh_port >= 1024);
            if doh_acceptor_mgr.is_none() && !plaintext_allowed {
                warn!(
                    addr = %SocketAddr::new(*bind_ip, config.dns.doh_port),
                    "DoH port configured without TLS on a non-loopback address; skipping plaintext DoH listener (set dns.allow_plaintext_doh = true to override)"
                );
            } else {
                let doh_addr = SocketAddr::new(*bind_ip, config.dns.doh_port);
                let dedicated_host = (!config.dns.doh_dedicated_hostname.trim().is_empty())
                    .then(|| config.dns.doh_dedicated_hostname.trim().to_string());
                // Only advertise HTTP/3 when a DoH3 listener can actually be
                // started (port configured and TLS material available); a
                // bind failure is logged at error level below.
                let alt_svc_port = (config.dns.doh3_port > 0 && doh3_acceptor_mgr.is_some())
                    .then_some(config.dns.doh3_port);
                let mut doh_config = DohConfig::new(doh_addr, doh_acceptor_mgr.clone())
                    .with_alt_svc_port(alt_svc_port)
                    .with_dedicated_hostname(dedicated_host);
                doh_config.rate_limit_per_ip = config.dns.rate_limit_per_ip;
                doh_config.rate_limiter = Some(shared_limiter.clone());
                doh_config.max_connections = config.dns.max_tcp_connections;
                let doh_handle =
                    start_doh_listener(doh_config, pipeline.clone(), shutdown_rx.clone()).await?;
                handles.push(doh_handle);
                if config.dns.doh_port == 443 {
                    doh_443_bound = true;
                }
            }
        }

        // Start DoQ listener if doq_port > 0 and TLS is configured
        if config.dns.doq_port > 0
            && let Some(ref doq_mgr) = doq_acceptor_mgr
        {
            let doq_addr = SocketAddr::new(*bind_ip, config.dns.doq_port);
            let mut doq_config = DoqConfig::new(doq_addr, Some(doq_mgr.clone()));
            doq_config.rate_limit_per_ip = config.dns.rate_limit_per_ip;
            doq_config.rate_limiter = Some(shared_limiter.clone());
            doq_config.max_connections = config.dns.max_tcp_connections;
            match start_doq_listener(doq_config, pipeline.clone(), shutdown_rx.clone()).await {
                Ok(doq_handle) => handles.push(doq_handle),
                Err(e) => error!("Failed to start the configured DoQ listener on {doq_addr}: {e}"),
            }
        }

        // Start DoH3 listener if doh3_port > 0 and TLS is configured
        if config.dns.doh3_port > 0
            && let Some(ref doh3_mgr) = doh3_acceptor_mgr
        {
            let doh3_addr = SocketAddr::new(*bind_ip, config.dns.doh3_port);
            let dedicated_host = (!config.dns.doh_dedicated_hostname.trim().is_empty())
                .then(|| config.dns.doh_dedicated_hostname.trim().to_string());
            let mut doh3_config = Doh3Config::new(doh3_addr, Some(doh3_mgr.clone()))
                .with_dedicated_hostname(dedicated_host);
            doh3_config.rate_limit_per_ip = config.dns.rate_limit_per_ip;
            doh3_config.rate_limiter = Some(shared_limiter.clone());
            doh3_config.max_connections = config.dns.max_tcp_connections;
            match start_doh3_listener(doh3_config, pipeline.clone(), shutdown_rx.clone()).await {
                Ok(doh3_handle) => handles.push(doh3_handle),
                Err(e) => {
                    error!("Failed to start the configured DoH3 listener on {doh3_addr}: {e}");
                }
            }
        }
    }

    record_doh_listener_binding(
        &acme_challenges,
        config,
        doh_acceptor_mgr.as_ref(),
        doh_443_bound,
    );

    Ok((handles, rate_limiters))
}

async fn wait_for_shutdown_signal(
    mut custom_shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())?;

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT signal");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM signal");
            }
            () = async {
                if let Some(rx) = custom_shutdown.as_mut() {
                    rx.await.ok();
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                info!("Received programmatic shutdown signal");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT signal");
            }
            () = async {
                if let Some(rx) = custom_shutdown.as_mut() {
                    rx.await.ok();
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                info!("Received programmatic shutdown signal");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::canonical_config_path;
    use super::*;
    use std::path::Path;

    #[test]
    fn test_canonical_config_path_for_relative_default() {
        let resolved = canonical_config_path(Path::new("config.toml"));
        assert!(
            resolved.is_absolute(),
            "relative paths must become absolute: {resolved:?}"
        );
        assert_eq!(
            resolved.file_name(),
            Some(std::ffi::OsStr::new("config.toml"))
        );
        assert!(
            resolved.parent().is_some_and(|p| !p.as_os_str().is_empty()),
            "the watcher needs a watchable parent directory"
        );
    }

    #[test]
    fn test_canonical_config_path_existing_file() {
        let dir = std::env::temp_dir().join(format!("sito_cfg_path_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.toml");
        std::fs::write(&file, "config_version = 1\n").unwrap();
        let resolved = canonical_config_path(&file);
        assert!(resolved.is_absolute());
        assert_eq!(
            resolved.file_name(),
            Some(std::ffi::OsStr::new("config.toml"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn scoped_clients(servers: &[&str]) -> sito_clients::ClientsConfig {
        let mut clients = sito_clients::ClientsConfig::default();
        clients.entries.push(sito_clients::ClientEntryConfig {
            name: "corp".to_string(),
            ids: Vec::new(),
            group: "default".to_string(),
            ignore_query_log: false,
            ignore_stats: false,
            use_global_upstreams: false,
            upstreams: Some(servers.iter().map(|server| (*server).to_string()).collect()),
            trusted: false,
        });
        clients
    }

    /// Important 3: changing a global upstream setting such as
    /// `allow_private_targets` must rebuild per-client scoped managers on a hot
    /// reload instead of reusing the old SSRF policy.
    #[tokio::test]
    async fn test_scoped_upstream_reload_rebuilds_on_allow_private_targets_change() {
        let mut config = Config::default();
        config.upstream.servers = vec!["1.1.1.1".to_string()];
        let clients = scoped_clients(&["udp://127.0.0.1:53"]);

        let first = build_scoped_upstreams(&config, &clients, &HashMap::new()).await;
        assert_eq!(first.len(), 1);
        let first_key = first.keys().next().unwrap().clone();
        let first_manager = first.values().next().unwrap().clone();

        config.upstream.allow_private_targets = true;
        let second = build_scoped_upstreams(&config, &clients, &first).await;
        assert_eq!(second.len(), 1);
        let second_key = second.keys().next().unwrap().clone();
        let second_manager = second.values().next().unwrap().clone();

        assert_ne!(
            first_key, second_key,
            "the reuse key must include allow_private_targets"
        );
        assert!(
            !Arc::ptr_eq(&first_manager, &second_manager),
            "a changed SSRF policy must not reuse the stale scoped manager"
        );
    }

    /// The reuse key must also change when inherited connection settings change,
    /// not only when the server list changes.
    #[test]
    fn test_scoped_upstream_key_includes_inherited_settings() {
        let mut config = Config::default();
        let servers = vec!["tls://dns.example".to_string()];
        let base = scoped_upstream_key(&config, &servers);

        config.upstream.bootstrap = vec!["1.1.1.1".parse().unwrap()];
        assert_ne!(base, scoped_upstream_key(&config, &servers));

        let mut config = Config::default();
        config.upstream.timeout_ms += 1;
        assert_ne!(base, scoped_upstream_key(&config, &servers));

        let mut config = Config::default();
        config.upstream.strategy = sito_core::config::UpstreamStrategy::Parallel;
        assert_ne!(base, scoped_upstream_key(&config, &servers));

        let mut config = Config::default();
        config.upstream.pool_size += 1;
        assert_ne!(base, scoped_upstream_key(&config, &servers));

        let mut config = Config::default();
        config.upstream.allow_private_targets = true;
        assert_ne!(base, scoped_upstream_key(&config, &servers));
    }

    /// I5 regression: the production `init_ha` call site records the
    /// `replication_disabled` no-op for a master with a zero replication port.
    #[tokio::test]
    async fn test_init_ha_records_master_replication_disabled_noop() {
        let dir = std::env::temp_dir().join(format!("sito_init_ha_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut config = Config::default();
        config.server.role = "master".to_string();
        config.server.data_dir = dir.clone();
        config.ha = None;

        let metrics = sito_stats::MetricsRegistry::new("1.9.0", "test");
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let runtime = init_ha(&config, &dir.join("config.toml"), &metrics, &shutdown_rx)
            .expect("init_ha must succeed for a master with replication disabled");
        assert!(runtime.coordinator.is_some());

        let rendered = metrics.render_prometheus();
        assert!(
            rendered.contains(
                r#"sito_ha_startup_noop_total{role="master",reason="replication_disabled"} 1"#
            ),
            "the production startup path must expose the no-op: {rendered}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: a master restart with a persisted `ha_state.toml` used to
    /// resume the old bundle and never compare it with `config.toml`, leaving
    /// every slave on stale configuration. A changed config must republish at
    /// `N + 1`; an unchanged config must resume the existing sequence.
    #[tokio::test]
    async fn test_master_restart_republishes_changed_config() {
        let dir =
            std::env::temp_dir().join(format!("sito_init_ha_reconcile_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");

        let mut config = Config::default();
        config.server.role = "master".to_string();
        config.server.instance_name = "master-reconcile".to_string();
        config.server.data_dir = dir.clone();
        config.ha = None;
        config.upstream.servers = vec!["1.1.1.1".to_string()];
        std::fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let metrics = sito_stats::MetricsRegistry::new("1.9.0", "test");
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let first = init_ha(&config, &config_path, &metrics, &shutdown_rx)
            .expect("first master startup must publish v1");
        let first_coordinator = first.coordinator.expect("master coordinator");
        assert_eq!(
            first_coordinator.current_version.load(Ordering::SeqCst),
            1,
            "a fresh master must start at version 1"
        );
        drop(first_coordinator);

        // Restarting with an unchanged config must not churn the sequence.
        let unchanged = init_ha(&config, &config_path, &metrics, &shutdown_rx)
            .expect("unchanged restart must succeed");
        let unchanged_coordinator = unchanged.coordinator.expect("master coordinator");
        assert_eq!(
            unchanged_coordinator.current_version.load(Ordering::SeqCst),
            1,
            "an unchanged config must resume the persisted version"
        );
        let unchanged_bundle = unchanged_coordinator
            .active_bundle
            .lock()
            .unwrap()
            .clone()
            .expect("restored bundle");
        assert!(
            unchanged_bundle.config_toml.contains("1.1.1.1"),
            "an unchanged restart must keep the persisted bundle"
        );
        drop(unchanged_coordinator);

        // Editing the master config and restarting must publish N + 1 so
        // connected slaves pick up the new shared configuration.
        config.upstream.servers = vec!["9.9.9.9".to_string()];
        std::fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();
        let changed = init_ha(&config, &config_path, &metrics, &shutdown_rx)
            .expect("changed restart must republish the bundle");
        let changed_coordinator = changed.coordinator.expect("master coordinator");
        assert_eq!(
            changed_coordinator.current_version.load(Ordering::SeqCst),
            2,
            "a changed config must republish at N + 1"
        );
        let changed_bundle = changed_coordinator
            .active_bundle
            .lock()
            .unwrap()
            .clone()
            .expect("republished bundle");
        assert!(
            changed_bundle.config_toml.contains("9.9.9.9"),
            "the republished bundle must carry the current config: {}",
            changed_bundle.config_toml
        );
        assert!(
            !changed_bundle.config_toml.contains("1.1.1.1"),
            "the republished bundle must not carry the stale config: {}",
            changed_bundle.config_toml
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_bundled_registries_load_without_panicking() {
        // Startup must use the fallible loaders: corrupt embedded data has to
        // surface as a startup error, not a panic. This pins that the shipped
        // bundled data loads cleanly through that path.
        let (parental, services) =
            load_bundled_registries().expect("embedded bundled lists must load");
        assert!(
            !parental.lists().is_empty(),
            "parental lists must be present"
        );
        assert!(
            services.service_count() > 0,
            "service rules must be present"
        );
    }

    /// Regression (P1-12/Important 2): TLS-ALPN-01 must only be offered when
    /// DoH actually bound TCP 443. A failed/absent bind or a custom DoH port
    /// must fall back to HTTP-01.
    #[test]
    fn test_acme_challenge_availability_requires_bound_443() {
        let dir = std::env::temp_dir().join(format!(
            "sito_acme_bind_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let (cert_pem, key_pem) =
            generate_self_signed_cert(&["localhost".to_string()]).expect("self-signed cert");
        std::fs::write(&cert, cert_pem).unwrap();
        std::fs::write(&key, key_pem).unwrap();
        let manager = TlsAcceptorManager::new(
            load_server_config(&cert, &key, &[], vec![b"acme-tls/1".to_vec()]).expect("TLS config"),
        );

        let mut config = Config::default();
        config.dns.doh_port = 443;
        let availability = AcmeChallengeAvailability::default();

        // The ACME manager starts before the DNS bind: nothing is available.
        assert!(!availability.options().tls_alpn_available);

        record_doh_listener_binding(&availability, &config, Some(&manager), false);
        assert!(
            !availability.options().tls_alpn_available,
            "a failed/absent 443 bind must not enable TLS-ALPN-01"
        );

        config.dns.doh_port = 8443;
        record_doh_listener_binding(&availability, &config, Some(&manager), true);
        assert!(
            !availability.options().tls_alpn_available,
            "TLS-ALPN-01 needs port 443, not just any bound TLS listener"
        );

        config.dns.doh_port = 443;
        record_doh_listener_binding(&availability, &config, Some(&manager), true);
        assert!(
            availability.options().tls_alpn_available,
            "a bound 443 DoH listener with acme-tls/1 enables TLS-ALPN-01"
        );

        record_doh_listener_binding(&availability, &config, None, true);
        assert!(!availability.options().tls_alpn_available);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression (P1-12/P2-13): a restart must prefer the stored ACME
    /// certificate over static `[tls]` files, but a bootstrap placeholder must
    /// not displace a real static pair.
    #[test]
    fn test_choose_tls_material_prefers_acme_certificate_on_restart() {
        let static_pair = Some((
            PathBuf::from("/etc/sito/static-cert.pem"),
            PathBuf::from("/etc/sito/static-key.pem"),
        ));
        let acme_pair = Some((
            PathBuf::from("/var/lib/sito/acme/cert.pem"),
            PathBuf::from("/var/lib/sito/acme/key.pem"),
        ));
        let static_pair_value = static_pair.clone().expect("static pair");
        let acme_pair_value = acme_pair.clone().expect("acme pair");

        assert_eq!(
            choose_tls_material(static_pair.clone(), acme_pair.clone(), true, true, false),
            TlsStartupMaterial::Pair(acme_pair_value.0.clone(), acme_pair_value.1.clone()),
            "a usable ACME certificate must win over static material after restart"
        );
        assert_eq!(
            choose_tls_material(static_pair.clone(), acme_pair.clone(), false, true, true),
            TlsStartupMaterial::Pair(static_pair_value.0.clone(), static_pair_value.1.clone()),
            "a bootstrap placeholder must not displace a real static pair"
        );
        assert_eq!(
            choose_tls_material(None, acme_pair.clone(), false, true, false),
            TlsStartupMaterial::Disabled,
            "D12: bootstrap must not be served by default"
        );
        assert_eq!(
            choose_tls_material(None, acme_pair.clone(), false, true, true),
            TlsStartupMaterial::GenerateBootstrap,
            "opting in allows a fresh bootstrap while ACME issues"
        );
        assert_eq!(
            choose_tls_material(None, None, false, true, false),
            TlsStartupMaterial::Disabled,
            "ACME-only with no certificate is fail-closed by default"
        );
        assert_eq!(
            choose_tls_material(None, None, false, true, true),
            TlsStartupMaterial::GenerateBootstrap,
            "ACME-only with the opt-in generates a bootstrap certificate"
        );
        assert_eq!(
            choose_tls_material(static_pair.clone(), None, false, true, false),
            TlsStartupMaterial::Pair(static_pair_value.0.clone(), static_pair_value.1.clone()),
            "without ACME material the static pair is used while issuance runs"
        );
        assert_eq!(
            choose_tls_material(static_pair.clone(), acme_pair.clone(), false, false, false),
            TlsStartupMaterial::Pair(static_pair_value.0.clone(), static_pair_value.1.clone()),
            "with ACME disabled only static material is used"
        );
    }

    /// Critical 1 regression: a CA-issued certificate with only ~5 days left
    /// has a ~90-day lifetime. It must not be classified as a bootstrap
    /// placeholder and must not be overwritten during startup selection.
    #[test]
    fn test_short_remaining_validity_does_not_trigger_bootstrap_replacement() {
        let dir = std::env::temp_dir().join(format!(
            "sito_acme_short_remaining_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");

        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "sito test CA");
        let now = time::OffsetDateTime::now_utc();
        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let mut leaf_params = rcgen::CertificateParams::new(vec!["dns.example.test".to_string()])
            .expect("leaf params");
        leaf_params.not_before = now - time::Duration::days(85);
        leaf_params.not_after = now + time::Duration::days(5);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .expect("leaf cert");

        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, leaf_cert.pem()).expect("write cert");
        write_secret_file(&key_path, leaf_key.serialize_pem().as_bytes()).expect("write key");

        let config = AcmeServiceConfig::new(
            "admin@example.test".to_string(),
            vec!["dns.example.test".to_string()],
            dir.clone(),
        )
        .with_renew_before_days(30);
        assert!(
            !config.is_bootstrap_cert(),
            "remaining validity must not classify a CA certificate as bootstrap"
        );

        let acme_pair = Some((cert_path.clone(), key_path.clone()));
        let acme_pair_value = acme_pair.clone().expect("acme pair");
        let acme_pair_usable = !config.is_bootstrap_cert() && !config.stored_cert_is_expired();
        assert_eq!(
            choose_tls_material(None, acme_pair.clone(), acme_pair_usable, true, false),
            TlsStartupMaterial::Pair(acme_pair_value.0.clone(), acme_pair_value.1.clone()),
            "a still-valid CA certificate must be retained even though renewal is due"
        );

        // An actually expired CA certificate is not served, but is not
        // overwritten either: encrypted listeners are disabled by default.
        let expired_key = rcgen::KeyPair::generate().expect("expired leaf key");
        let mut expired_params =
            rcgen::CertificateParams::new(vec!["dns.example.test".to_string()])
                .expect("expired leaf params");
        expired_params.not_before = now - time::Duration::days(90);
        expired_params.not_after = now - time::Duration::hours(1);
        let expired_cert = expired_params
            .signed_by(
                &expired_key,
                &rcgen::Issuer::from_params(&ca_params, &ca_key),
            )
            .expect("expired leaf cert");
        std::fs::write(&cert_path, expired_cert.pem()).expect("write expired cert");
        write_secret_file(&key_path, expired_key.serialize_pem().as_bytes())
            .expect("write expired key");
        assert!(
            config.stored_cert_is_expired(),
            "the expired certificate must be detected"
        );
        assert_eq!(
            choose_tls_material(None, acme_pair, false, true, false),
            TlsStartupMaterial::Disabled,
            "an expired CA certificate must not be replaced or served without opt-in"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression (P0-1): invalid configured certificate material must abort
    /// startup for the encrypted listeners instead of silently running without
    /// them.
    #[tokio::test]
    async fn test_invalid_tls_material_is_fatal() {
        let dir = std::env::temp_dir().join(format!(
            "sito_tls_fatal_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut config = Config::default();
        config.tls = Some(sito_core::config::TlsConfig {
            cert: Some(dir.join("missing-cert.pem")),
            key: Some(dir.join("missing-key.pem")),
            sni_certs: Vec::new(),
        });

        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let acceptors = tokio::sync::Mutex::new(None);
        let result = init_tls_and_acme(&config, &shutdown_rx, &acceptors).await;
        assert!(
            result.is_err(),
            "unreadable certificate material must fail startup, not disable encrypted listeners"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_tls_acceptors_rebuilt_from_updated_config() {
        // The setup wizard can configure TLS after startup; re-initializing
        // must populate the acceptors so encrypted listeners bind immediately.
        let (cert_pem, key_pem) =
            generate_self_signed_cert(&["localhost".to_string()]).expect("self-signed cert");
        let dir = std::env::temp_dir().join(format!("sito_tls_reinit_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();

        let mut config = Config::default();
        config.tls = Some(sito_core::config::TlsConfig {
            cert: Some(cert_path),
            key: Some(key_path),
            sni_certs: Vec::new(),
        });

        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let acceptors = tokio::sync::Mutex::new(None);
        let watchers = init_tls_and_acme(&config, &shutdown_rx, &acceptors)
            .await
            .expect("TLS initialization");

        let snapshot = acceptors
            .lock()
            .await
            .clone()
            .expect("acceptors must be stored");
        assert!(snapshot.dot.is_some(), "DoT acceptor must exist");
        assert!(snapshot.doh.is_some(), "DoH acceptor must exist");
        assert!(snapshot.doq.is_some(), "DoQ acceptor must exist");
        assert!(snapshot.doh3.is_some(), "DoH3 acceptor must exist");

        drop(watchers);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: the DNS warning must not claim listeners exist during
    /// setup-pending mode, and the post-wizard transition must use the
    /// configuration the wizard actually wrote.
    #[test]
    fn test_exposure_warning_phases_suppress_dns_while_setup_pending() {
        let default = Config::default();
        let startup = exposure_warnings_for_phase(&default, ExposurePhase::Startup);
        assert_eq!(
            startup.len(),
            1,
            "setup-pending startup must warn only for the admin UI: {startup:?}"
        );
        assert!(startup[0].contains("admin web UI"));
        assert!(
            !startup.iter().any(|w| w.contains("DNS listeners")),
            "DNS is not bound during setup-pending mode: {startup:?}"
        );

        let dns_starting = exposure_warnings_for_phase(&default, ExposurePhase::DnsListeners);
        assert_eq!(
            dns_starting.len(),
            1,
            "the DNS transition must emit exactly the DNS warning: {dns_starting:?}"
        );
        assert!(dns_starting[0].contains("DNS listeners"));

        // The wizard may change dns.bind to loopback; the transition warning
        // must use the then-current configuration, not the startup defaults.
        let mut completed = Config::default();
        completed.dns.bind = vec!["127.0.0.1".parse().expect("valid loopback")];
        assert!(
            exposure_warnings_for_phase(&completed, ExposurePhase::DnsListeners).is_empty(),
            "a loopback DNS bind must not warn after setup completes"
        );
    }
}
