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
    AcmeServiceConfig, CertWatcher, Doh3Config, DohConfig, DoqConfig, DotConfig, TcpConfig,
    TlsAcceptorManager, UdpConfig, generate_self_signed_cert, load_server_config,
    load_server_config_with_challenges, start_acme_manager, start_doh_listener,
    start_doh3_listener, start_doq_listener, start_dot_listener, start_tcp_listener,
    start_udp_listener,
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

/// Builds one protocol's hot-reloadable TLS acceptor and starts its certificate
/// watcher. Returns `None` (with a warning) when the certificate material cannot
/// be loaded, matching the previous per-protocol behaviour.
#[allow(clippy::too_many_arguments)]
fn build_tls_acceptor(
    protocol: &str,
    cert: &Path,
    key: &Path,
    sni_tuples: &[(String, PathBuf, PathBuf)],
    alpn: &[Vec<u8>],
    challenge_keys: Option<Arc<dashmap::DashMap<String, Arc<rustls::sign::CertifiedKey>>>>,
    cert_watchers: &mut Vec<sito_transport::CertWatcher>,
) -> Option<TlsAcceptorManager> {
    let config = match challenge_keys.clone() {
        Some(keys) => {
            load_server_config_with_challenges(cert, key, sni_tuples, alpn.to_vec(), keys)
        }
        None => load_server_config(cert, key, sni_tuples, alpn.to_vec()),
    };
    match config {
        Ok(config) => {
            let manager = match challenge_keys {
                Some(keys) => TlsAcceptorManager::with_challenge_keys(config, keys),
                None => TlsAcceptorManager::new(config),
            };
            match CertWatcher::start(cert, key, sni_tuples, alpn, manager.clone()) {
                Ok(watcher) => cert_watchers.push(watcher),
                Err(e) => warn!(protocol, "Certificate watcher failed to start: {e}"),
            }
            Some(manager)
        }
        Err(e) => {
            warn!(protocol, "Failed to initialize TLS configuration: {e}");
            None
        }
    }
}

/// Builds per-client upstream managers, reusing existing managers by key so a
/// hot reload does not re-resolve unchanged upstream scopes.
async fn build_scoped_upstreams(
    config: &Config,
    bootstrap: &BootstrapResolver,
    clients: &sito_clients::ClientsConfig,
    existing: &HashMap<String, Arc<UpstreamManager>>,
) -> HashMap<String, Arc<UpstreamManager>> {
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
        let key = servers.join(",");
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
        match UpstreamManager::from_config(&upstream_cfg, bootstrap).await {
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

/// High-availability role setup produced by [`init_ha`].
struct HaRuntime {
    config: sito_ha::HaConfig,
    coordinator: Option<sito_ha::MasterCoordinator>,
    tracker: Option<sito_ha::SlaveStatusTracker>,
    resync_sender: Option<tokio::sync::mpsc::Sender<()>>,
}

/// Initializes the HA role (master replication server or slave worker) and
/// returns the shared handles plus the validated HA configuration.
#[allow(clippy::too_many_arguments)]
fn init_ha(
    config: &Config,
    config_path: &Path,
    metrics: &sito_stats::MetricsRegistry,
    runtime: &Arc<sito_runtime::RuntimeState>,
    filter_engine: &Arc<HostsFilterEngine>,
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

    let (master_coordinator, slave_tracker, resync_sender) = if config.server.role == "master" {
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

        // Continue the version sequence across restarts; only a master with no
        // recoverable state starts a fresh v1 sequence.
        let restored_version = coordinator.restore_state()?;

        let initial_toml = std::fs::read_to_string(config_path)
            .unwrap_or_else(|_| toml::to_string_pretty(config).unwrap_or_default());
        let sanitized_toml = sito_ha::sanitize_config_for_bundle(&initial_toml).unwrap_or_default();
        if let Some(ref token) = ha_config.slave_token
            && let Err(e) = sito_ha::scan_for_secrets(&sanitized_toml, &[token.as_str()])
        {
            anyhow::bail!("Refusing to publish HA bundle with a leaked secret: {e}");
        }
        let list_metadata = config
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

        if restored_version.is_none() {
            #[allow(clippy::cast_sign_loss)]
            let initial_bundle = sito_ha::ConfigBundle {
                version: 1,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                config_toml: sanitized_toml,
                custom_rules: config.filtering.custom_rules.clone(),
                rewrites: config.rewrites.clone(),
                clients: config.clients.clone(),
                lists: list_metadata,
            };
            coordinator.update_bundle(initial_bundle)?;
            info!("Published initial HA configuration bundle version 1");
        } else {
            info!(
                version = restored_version.unwrap_or_default(),
                "Resumed HA configuration sequence from persisted state"
            );
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

        (Some(coordinator), None, None)
    } else {
        // Slave role
        let tracker = sito_ha::SlaveStatusTracker::new(
            config.server.instance_name.clone(),
            0,
            ha_config.master_url.clone(),
        );

        let slave_handles = sito_ha::SlaveAppHandles {
            runtime: runtime.clone(),
            filter: filter_engine.clone(),
            metrics: metrics.clone(),
            config_path: Some(config_path.to_path_buf()),
        };

        let (resync_tx, resync_rx) = tokio::sync::mpsc::channel(4);

        if ha_config.master_url.is_some() {
            let _slave_worker_handle = sito_ha::spawn_slave_worker(
                ha_config.clone(),
                tracker.clone(),
                slave_handles,
                resync_rx,
                shutdown_rx.clone(),
            );
        }

        (None, Some(tracker), Some(resync_tx))
    };

    Ok(HaRuntime {
        config: ha_config,
        coordinator: master_coordinator,
        tracker: slave_tracker,
        resync_sender,
    })
}

/// Long-lived runtime components created during startup.
struct RuntimeComponents {
    stats_db: StatsDb,
    metrics: MetricsRegistry,
    querylog_writer: QueryLogWriter,
    querylog_sender: sito_stats::QueryLogSender,
    bootstrap: BootstrapResolver,
    upstream_manager: Arc<UpstreamManager>,
    cache: Arc<DnsCache>,
    filter_engine: Arc<HostsFilterEngine>,
}

/// Opens the stats database and initializes metrics, query logging, upstreams,
/// cache and the filter engine together with their background tasks.
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
                    _ = drop_shutdown.changed() => {
                        if *drop_shutdown.borrow() {
                            metrics.set_querylog_dropped(sender.dropped_total());
                            break;
                        }
                    }
                }
            }
        });
    }

    // Initialize upstream manager with bootstrap resolver
    let bootstrap = BootstrapResolver::new(
        config.upstream.bootstrap.clone(),
        Duration::from_millis(config.upstream.timeout_ms),
    );
    let upstream_manager =
        Arc::new(UpstreamManager::from_config(&config.upstream, &bootstrap).await?);
    let _health_handle = upstream_manager.start_health_prober(shutdown_rx.clone());

    // Initialize cache
    let cache = Arc::new(DnsCache::new(config.dns.cache.clone()));

    // Initialize hosts filter
    let filter_engine = Arc::new(
        HostsFilterEngine::init(config.filtering.clone(), config.server.data_dir.clone()).await,
    );
    let _refresh_handle = filter_engine
        .clone()
        .spawn_refresh_task(shutdown_rx.clone());

    Ok(RuntimeComponents {
        stats_db,
        metrics,
        querylog_writer,
        querylog_sender,
        bootstrap,
        upstream_manager,
        cache,
        filter_engine,
    })
}

/// Handles shared with [`run_config_watcher`].
struct ConfigWatcher {
    config_path: PathBuf,
    runtime: Arc<sito_runtime::RuntimeState>,
    rate_limiters: Arc<std::sync::Mutex<Vec<Arc<sito_transport::RateLimiter>>>>,
    listener_manager: Arc<tokio::sync::Mutex<Option<DnsListenerManager>>>,
    listener_acceptors: Arc<tokio::sync::Mutex<Option<ListenerAcceptors>>>,
    pipeline: Arc<DnsPipeline>,
    filter: Arc<HostsFilterEngine>,
    coordinator: Option<sito_ha::MasterCoordinator>,
    upstream: Arc<UpstreamManager>,
    bootstrap: BootstrapResolver,
    querylog: sito_stats::QueryLogSender,
    cache: Arc<DnsCache>,
    dnssec: Arc<ArcSwap<DnssecValidator>>,
    scoped_upstreams: Arc<ArcSwap<HashMap<String, Arc<UpstreamManager>>>>,
    shutdown_rx: watch::Receiver<bool>,
}

/// Watches the configuration file and applies hot reloads in-process. Returns
/// when shutdown is signalled, when the watcher cannot be initialized, or when
/// the watched directory disappears.
async fn run_config_watcher(watcher: ConfigWatcher) {
    let ConfigWatcher {
        config_path: watcher_config_path,
        runtime: watcher_runtime,
        rate_limiters: watcher_rate_limiters,
        listener_manager: watcher_listener_manager,
        listener_acceptors: watcher_listener_acceptors,
        pipeline: watcher_pipeline,
        filter: watcher_filter,
        coordinator: watcher_coordinator,
        upstream: watcher_upstream,
        bootstrap: watcher_bootstrap,
        querylog: watcher_querylog,
        cache: watcher_cache,
        dnssec: watcher_dnssec,
        scoped_upstreams: watcher_scoped_upstreams,
        shutdown_rx: mut watcher_shutdown_rx,
    } = watcher;

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
            warn!("Failed to initialize config file watcher: {e}");
            return;
        }
    };

    // Watch the parent directory so a config file created after startup
    // (first-run wizard) is also picked up.
    let watch_target = watcher_config_path
        .parent()
        .map_or_else(|| watcher_config_path.clone(), std::path::Path::to_path_buf);
    if let Err(e) = watcher.watch(&watch_target, RecursiveMode::NonRecursive) {
        warn!(
            "Failed to watch config directory {}: {e}",
            watch_target.display()
        );
        return;
    }

    loop {
        tokio::select! {
            _ = watcher_shutdown_rx.changed() => {
                if *watcher_shutdown_rx.borrow() {
                    break;
                }
            }
            Some(()) = rx.recv() => {
                // Debounce brief bursts of file writes
                tokio::time::sleep(WATCHER_DEBOUNCE).await;
                while rx.try_recv().is_ok() {}

                match tokio::fs::read_to_string(&watcher_config_path).await {
                    Ok(content) => match Config::from_toml_str(&content) {
                        Ok(new_cfg) => {
                            if let Err(e) = validate_typed_sections(&new_cfg) {
                                error!(
                                    error = %e,
                                    "Rejecting config hot-reload: invalid configuration section"
                                );
                                continue;
                            }
                            info!("Detected configuration file change, hot-reloading");
                            if crate::logging::reload_level(&new_cfg.server.log_level) {
                                info!(
                                    level = %new_cfg.server.log_level,
                                    "Applied hot-reloaded log level"
                                );
                            }
                            if let Err(e) =
                                watcher_filter.reload_with_config(&new_cfg.filtering).await
                            {
                                error!(error = %e, "Failed to hot-reload filter configuration");
                            }
                            let new_rewrites_cfg = match rewrites_from_config(&new_cfg) {
                                Ok(cfg) => cfg,
                                Err(e) => {
                                    error!(error = %e, "Rejecting config hot-reload");
                                    continue;
                                }
                            };
                            let new_rewrites =
                                sito_rewrites::RewriteTable::new(new_rewrites_cfg);

                            let new_clients_cfg = match clients_from_config(&new_cfg) {
                                Ok(cfg) => cfg,
                                Err(e) => {
                                    error!(error = %e, "Rejecting config hot-reload");
                                    continue;
                                }
                            };
                            let new_clients =
                                sito_clients::ClientRegistry::new(new_clients_cfg.clone());

                            // DNSSEC settings are not read through the config
                            // snapshot at query time; swap the validator so
                            // mode/anchors/NTAs apply immediately.
                            watcher_dnssec.store(Arc::new(DnssecValidator::from_config(
                                &new_cfg.dns.dnssec,
                            )));

                            // Rebuild per-client upstream scopes, reusing
                            // managers whose upstream set is unchanged.
                            let rebuilt_scoped = {
                                let existing = watcher_scoped_upstreams.load_full();
                                build_scoped_upstreams(
                                    &new_cfg,
                                    &watcher_bootstrap,
                                    &new_clients_cfg,
                                    &existing,
                                )
                                .await
                            };
                            watcher_scoped_upstreams.store(Arc::new(rebuilt_scoped));

                            if let Err(e) = watcher_upstream
                                .reload(&new_cfg.upstream, &watcher_bootstrap)
                                .await
                            {
                                warn!("Failed to hot-reload upstream configuration: {e}");
                            }
                            watcher_querylog
                                .set_anonymize(new_cfg.privacy.anonymize_querylog);
                            watcher_cache.update_config(new_cfg.dns.cache.clone()).await;
                            if let Ok(limiters) = watcher_rate_limiters.lock() {
                                for limiter in limiters.iter() {
                                    limiter.set_rate(new_cfg.dns.rate_limit_per_ip);
                                }
                            }

                            // Publish config, clients and rewrites together so a
                            // query cannot observe a half-applied reload.
                            watcher_runtime.replace(sito_runtime::RuntimeSnapshot {
                                config: Arc::new(new_cfg.clone()),
                                clients: Arc::new(new_clients),
                                rewrites: Arc::new(new_rewrites),
                            });

                            // Rebind listeners when bind/port/related settings change.
                            let current_manager =
                                watcher_listener_manager.lock().await.take();
                            if let Some(manager) = current_manager {
                                if manager.needs_restart(&new_cfg) {
                                    let acceptors =
                                        watcher_listener_acceptors.lock().await.clone();
                                    if let Some(acceptors) = acceptors {
                                        info!("DNS listener bindings changed; rebinding in-process");
                                        match manager
                                            .restart(
                                                &new_cfg,
                                                watcher_pipeline.clone(),
                                                acceptors,
                                                watcher_rate_limiters.clone(),
                                            )
                                            .await
                                        {
                                            Ok(new_manager) => {
                                                *watcher_listener_manager.lock().await =
                                                    Some(new_manager);
                                            }
                                            Err(e) => {
                                                error!("Failed to rebind DNS listeners: {e}");
                                            }
                                        }
                                    } else {
                                        warn!(
                                            "Listener TLS acceptors unavailable; keeping current listeners"
                                        );
                                        *watcher_listener_manager.lock().await =
                                            Some(manager);
                                    }
                                } else {
                                    *watcher_listener_manager.lock().await = Some(manager);
                                }
                            }

                            if let Some(ref coord) = watcher_coordinator {
                                let next_version = coord.get_current_version() + 1;
                                let sanitized_toml = sito_ha::sanitize_config_for_bundle(&content).unwrap_or_default();
                                let list_metadata = new_cfg.filtering.lists.iter().map(|l| sito_ha::FilterListMetadata {
                                    name: l.name.clone(),
                                    url: l.url.clone(),
                                    enabled: l.enabled,
                                    refresh_hours: l.refresh_hours,
                                }).collect();

                                #[allow(clippy::cast_sign_loss)]
                                let new_bundle = sito_ha::ConfigBundle {
                                    version: next_version,
                                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                                    config_toml: sanitized_toml,
                                    custom_rules: new_cfg.filtering.custom_rules.clone(),
                                    rewrites: new_cfg.rewrites.clone(),
                                    clients: new_cfg.clients.clone(),
                                    lists: list_metadata,
                                };

                                if let Err(e) = coord.update_bundle(new_bundle) {
                                    warn!("Failed to broadcast updated bundle to slaves: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Ignoring invalid hot-reloaded configuration: {e}");
                        }
                    },
                    Err(e) => {
                        warn!("Failed to read modified configuration file: {e}");
                    }
                }
            }
        }
    }
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

/// Runs the DNS server with custom config path, shutdown receiver, and setup-pending mode.
pub async fn run_server_full(
    config: Config,
    config_path: impl AsRef<Path>,
    custom_shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
    setup_pending: bool,
) -> anyhow::Result<()> {
    validate_typed_sections(&config)?;
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
    let bootstrap = components.bootstrap;
    let upstream_manager = components.upstream_manager;
    let cache = components.cache;
    let filter_engine = components.filter_engine;

    // Initialize DNSSEC validator
    let dnssec_swap = Arc::new(ArcSwap::from(Arc::new(DnssecValidator::from_config(
        &config.dns.dnssec,
    ))));

    // Initialize client registry
    let clients_config = clients_from_config(&config)?;

    // Build per-client upstream managers for entries that opt out of the globals.
    let scoped_upstreams: Arc<ArcSwap<HashMap<String, Arc<UpstreamManager>>>> =
        Arc::new(ArcSwap::from(Arc::new(
            build_scoped_upstreams(&config, &bootstrap, &clients_config, &HashMap::new()).await,
        )));

    let client_registry = Arc::new(sito_clients::ClientRegistry::new(clients_config));

    // Initialize parental and service registries
    let parental_registry = Arc::new(sito_clients::ParentalRegistry::bundled());
    let service_registry = Arc::new(sito_clients::ServiceRegistry::bundled());
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
    let ha_runtime = init_ha(
        &config,
        &config_path_buf,
        &metrics,
        &runtime,
        &filter_engine,
        &shutdown_rx,
    )?;
    let _ha_config = ha_runtime.config;
    let (master_coordinator, slave_tracker, resync_sender) = (
        ha_runtime.coordinator,
        ha_runtime.tracker,
        ha_runtime.resync_sender,
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
        master_coordinator: master_coordinator.clone(),
        slave_tracker: slave_tracker.clone(),
        resync_sender,
        setup_pending: Arc::new(std::sync::atomic::AtomicBool::new(setup_pending)),
        dns_starter,
    };

    let api_router = sito_api::create_router(server_ctx);
    let web_cfg = config_arc.load().get_web_config();
    if web_cfg.enabled {
        let web_addr = SocketAddr::new(web_cfg.bind, web_cfg.port);
        // DNS TLS does not terminate the admin UI: axum serves plain HTTP here
        // regardless, so warn whenever the UI is reachable beyond loopback.
        if !web_cfg.bind.is_loopback() {
            warn!(
                "Admin web UI listening on {web_addr} over plain HTTP; credentials and the setup token are transmitted in plaintext. Terminate TLS in front of it (reverse proxy) or bind to loopback."
            );
        }
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
                _ = retention_shutdown_rx.changed() => {
                    if *retention_shutdown_rx.borrow() {
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

    // Rate limiters created by listeners; shared so the watcher can hot-update.
    let rate_limiters: Arc<std::sync::Mutex<Vec<Arc<sito_transport::RateLimiter>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    // Listener generation and TLS acceptors, shared with the config watcher so
    // bind/port changes can be applied in-process.
    let listener_manager: Arc<tokio::sync::Mutex<Option<DnsListenerManager>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let listener_acceptors: Arc<tokio::sync::Mutex<Option<ListenerAcceptors>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    // Spawn config file watcher for hot-reload
    tokio::spawn(run_config_watcher(ConfigWatcher {
        config_path: config_path_buf.clone(),
        runtime: runtime.clone(),
        rate_limiters: rate_limiters.clone(),
        listener_manager: listener_manager.clone(),
        listener_acceptors: listener_acceptors.clone(),
        pipeline: pipeline.clone(),
        filter: filter_engine.clone(),
        coordinator: master_coordinator.clone(),
        upstream: upstream_manager.clone(),
        bootstrap: bootstrap.clone(),
        querylog: querylog_sender.clone(),
        cache: cache.clone(),
        dnssec: dnssec_swap.clone(),
        scoped_upstreams: scoped_upstreams.clone(),
        shutdown_rx: shutdown_rx.clone(),
    }));

    let cert_watchers = init_tls_and_acme(&config, &shutdown_rx, &listener_acceptors).await?;

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
                let acceptors = listener_acceptors
                    .lock()
                    .await
                    .clone()
                    .unwrap_or(ListenerAcceptors {
                        dot: None,
                        doh: None,
                        doq: None,
                        doh3: None,
                    });
                let manager = DnsListenerManager::start(
                    &current_cfg,
                    pipeline.clone(),
                    acceptors,
                    rate_limiters.clone(),
                )
                .await?;
                *listener_manager.lock().await = Some(manager);

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
            });
        let manager =
            DnsListenerManager::start(&config, pipeline.clone(), acceptors, rate_limiters.clone())
                .await?;
        *listener_manager.lock().await = Some(manager);

        info!(
            port = config.dns.port,
            bind = ?config.dns.bind,
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
) {
    info!("Initiating graceful shutdown (stopping listeners)...");
    let _ = shutdown_tx.send(true);
    let current_manager = listener_manager.lock().await.take();
    if let Some(manager) = current_manager {
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

    // If static cert/key not provided, but ACME is enabled, establish ACME storage directory and bootstrap cert
    let (effective_cert, effective_key) = match (cert_file, key_file) {
        (Some(c), Some(k)) => (Some(c), Some(k)),
        _ if is_acme_enabled => {
            let acme = acme_cfg.as_ref().unwrap();
            let storage_dir = acme
                .cache_dir
                .clone()
                .unwrap_or_else(|| config.server.data_dir.join("acme"));
            let cert_path = storage_dir.join("cert.pem");
            let key_path = storage_dir.join("key.pem");

            if !cert_path.exists() || !key_path.exists() {
                let _ = tokio::fs::create_dir_all(&storage_dir).await;
                match generate_self_signed_cert(&acme.domains) {
                    Ok((cert_pem, key_pem)) => {
                        let _ = tokio::fs::write(&cert_path, cert_pem).await;
                        let _ = tokio::fs::write(&key_path, key_pem).await;
                        info!(
                            "Generated bootstrap self-signed certificate in {:?}",
                            storage_dir
                        );
                    }
                    Err(e) => {
                        warn!("Failed to generate bootstrap self-signed certificate: {e}");
                    }
                }
            }
            if cert_path.exists() && key_path.exists() {
                (Some(cert_path), Some(key_path))
            } else {
                (None, None)
            }
        }
        _ => (None, None),
    };

    let http01_challenges = Arc::new(dashmap::DashMap::<String, String>::new());
    let challenge_keys = Arc::new(dashmap::DashMap::new());
    // Kept alive for the lifetime of the server so certificate hot-reload works.
    let mut cert_watchers: Vec<sito_transport::CertWatcher> = Vec::new();

    let (dot_acceptor_mgr, doh_acceptor_mgr, doq_acceptor_mgr, doh3_acceptor_mgr) =
        if let (Some(cert), Some(key)) = (&effective_cert, &effective_key) {
            let doh_mgr = build_tls_acceptor(
                "doh",
                cert,
                key,
                &sni_tuples,
                &[b"h2".to_vec(), b"http/1.1".to_vec(), b"acme-tls/1".to_vec()],
                Some(challenge_keys.clone()),
                &mut cert_watchers,
            );
            let dot_mgr = build_tls_acceptor(
                "dot",
                cert,
                key,
                &sni_tuples,
                &[b"dot".to_vec()],
                None,
                &mut cert_watchers,
            );
            let doq_mgr = build_tls_acceptor(
                "doq",
                cert,
                key,
                &sni_tuples,
                &[b"doq".to_vec()],
                None,
                &mut cert_watchers,
            );
            let doh3_mgr = build_tls_acceptor(
                "doh3",
                cert,
                key,
                &sni_tuples,
                &[b"h3".to_vec()],
                None,
                &mut cert_watchers,
            );
            (dot_mgr, doh_mgr, doq_mgr, doh3_mgr)
        } else {
            (None, None, None, None)
        };

    // If ACME is enabled, start ACME renewal background manager
    if let Some(acme) = acme_cfg
        && acme.enabled
        && !acme.domains.is_empty()
    {
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
        let doh_alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"acme-tls/1".to_vec()];
        let service_cfg =
            AcmeServiceConfig::new(email, acme.domains, storage_dir).with_staging(acme.staging);

        // Dedicated plaintext HTTP-01 listener (ACME validators always use port 80).
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

        let _acme_handle = start_acme_manager(
            service_cfg,
            doh_acceptor_mgr.clone(),
            Some(http01_challenges.clone()),
            doh_alpn,
            shutdown_rx.clone(),
        );
    }

    // Share TLS acceptors with the config watcher for in-process listener rebinds.
    *listener_acceptors.lock().await = Some(ListenerAcceptors {
        dot: dot_acceptor_mgr,
        doh: doh_acceptor_mgr,
        doq: doq_acceptor_mgr,
        doh3: doh3_acceptor_mgr,
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
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
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
        let (handles, limiters) = start_dns_listeners(
            config,
            pipeline,
            shutdown_rx,
            acceptors.dot,
            acceptors.doh,
            acceptors.doq,
            acceptors.doh3,
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

    async fn stop(mut self) {
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
    async fn restart(
        self,
        config: &Config,
        pipeline: Arc<DnsPipeline>,
        acceptors: ListenerAcceptors,
        rate_limiters: Arc<std::sync::Mutex<Vec<Arc<sito_transport::RateLimiter>>>>,
    ) -> anyhow::Result<Self> {
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
            Ok(manager) => Ok(manager),
            Err(e) => {
                warn!(
                    "Failed to bind new DNS listener configuration ({e}); restoring previous bindings"
                );
                Self::start(&previous, pipeline, acceptors, rate_limiters)
                    .await
                    .map_err(|revert| anyhow::anyhow!("{e}; revert failed: {revert}"))
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
) -> anyhow::Result<(
    Vec<tokio::task::JoinHandle<()>>,
    Vec<Arc<sito_transport::RateLimiter>>,
)> {
    let worker_count = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let mut handles = Vec::new();

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
                let mut doh_config = DohConfig::new(doh_addr, doh_acceptor_mgr.clone())
                    .with_alt_svc_port(if config.dns.doh3_port > 0 {
                        Some(config.dns.doh3_port)
                    } else {
                        None
                    })
                    .with_dedicated_hostname(dedicated_host);
                doh_config.rate_limit_per_ip = config.dns.rate_limit_per_ip;
                doh_config.rate_limiter = Some(shared_limiter.clone());
                doh_config.max_connections = config.dns.max_tcp_connections;
                let doh_handle =
                    start_doh_listener(doh_config, pipeline.clone(), shutdown_rx.clone()).await?;
                handles.push(doh_handle);
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
                Err(e) => warn!("Failed to start DoQ listener on {doq_addr}: {e}"),
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
                Err(e) => warn!("Failed to start DoH3 listener on {doh3_addr}: {e}"),
            }
        }
    }

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
}
