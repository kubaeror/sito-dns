//! Server lifecycle and runner implementation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{info, warn};

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

#[derive(serde::Deserialize, Default)]
struct IntegrationsConfig {
    mikrotik: Option<sito_clients::RouterOsConfig>,
}

/// Runs the complete sito DNS server with graceful shutdown handling.
pub async fn run_server(config: Config) -> anyhow::Result<()> {
    let config_path = config.server.data_dir.join("config.toml");
    run_server_full(config, config_path, None).await
}

/// Runs the DNS server with an optional custom shutdown receiver (useful for testing).
pub async fn run_server_with_shutdown(
    config: Config,
    custom_shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    let config_path = config.server.data_dir.join("config.toml");
    run_server_full(config, config_path, custom_shutdown).await
}

/// Runs the DNS server with custom config path and shutdown receiver.
pub async fn run_server_full(
    config: Config,
    config_path: impl AsRef<Path>,
    custom_shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    let config_path_buf = config_path.as_ref().to_path_buf();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let in_flight = Arc::new(AtomicUsize::new(0));

    // Ensure data directory exists
    tokio::fs::create_dir_all(&config.server.data_dir).await?;

    // Initialize Stats SQLite DB
    let db_path = config.server.data_dir.join("stats.db");
    let stats_db = StatsDb::open(&db_path).await?;

    // Initialize QueryLogWriter (10k buffer per M5.1)
    let querylog_writer = QueryLogWriter::spawn(stats_db.clone(), 10_000);
    let querylog_sender = querylog_writer.sender();

    // Initialize Prometheus metrics registry with 18 metrics per Table 14.2
    let metrics = MetricsRegistry::new(env!("CARGO_PKG_VERSION"), "git");

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
    let _refresh_handle = filter_engine.clone().spawn_refresh_task();

    // Initialize DNSSEC validator
    let dnssec = Arc::new(DnssecValidator::from_config(&config.dns.dnssec));

    // Initialize client registry
    let clients_config: sito_clients::ClientsConfig = config
        .clients
        .as_ref()
        .and_then(|v| v.clone().try_into().ok())
        .unwrap_or_default();
    let client_registry = Arc::new(sito_clients::ClientRegistry::new(clients_config));

    // Initialize parental and service registries
    let parental_registry = Arc::new(sito_clients::ParentalRegistry::bundled());
    let service_registry = Arc::new(sito_clients::ServiceRegistry::bundled());

    // Initialize local rewrites table
    let rewrites_config: sito_rewrites::RewritesConfig = config
        .rewrites
        .as_ref()
        .and_then(|v| v.clone().try_into().ok())
        .unwrap_or_default();
    let rewrite_table = Arc::new(sito_rewrites::RewriteTable::new(rewrites_config));

    // Initialize MikroTik RouterOS integration if configured
    if let Some(ref int_val) = config.integrations
        && let Ok(integrations) = int_val.clone().try_into::<IntegrationsConfig>()
        && let Some(mikrotik_cfg) = integrations.mikrotik
        && mikrotik_cfg.enabled
    {
        let _routeros_handle = sito_clients::spawn_routeros_sync(
            mikrotik_cfg,
            client_registry.clone(),
            shutdown_rx.clone(),
        );
    }

    // Construct pipeline with query logging and Prometheus metrics
    let pipeline = Arc::new(
        DnsPipeline::new(
            Arc::new(config.clone()),
            filter_engine.clone(),
            cache.clone(),
            upstream_manager.clone(),
            dnssec,
            client_registry.clone(),
            parental_registry,
            service_registry,
            rewrite_table.clone(),
            in_flight.clone(),
        )
        .with_stats(querylog_sender.clone(), metrics.clone()),
    );

    // Setup ArcSwaps for hot-reloadable components
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config.clone())));
    let clients_arc = Arc::new(ArcSwap::new(client_registry.clone()));
    let rewrites_arc = Arc::new(ArcSwap::new(rewrite_table.clone()));

    // Initialize High Availability (HA) clustering subsystem per role
    let ha_config: sito_ha::HaConfig = config
        .ha
        .as_ref()
        .and_then(|v| v.clone().try_into().ok())
        .unwrap_or_default();

    let (master_coordinator, slave_tracker, resync_sender) = if config.server.role == "master" {
        // Load or create master Ed25519 signing key (0600 on Unix)
        let signing_key_path = config.server.data_dir.join("ha_signing.key");
        let signing_key = Arc::new(sito_ha::Ed25519SigningKey::load_or_create(
            &signing_key_path,
        )?);

        let coordinator = sito_ha::MasterCoordinator::new(
            config.server.instance_name.clone(),
            1,
            signing_key.clone(),
            metrics.clone(),
        );

        let initial_toml = std::fs::read_to_string(&config_path_buf)
            .unwrap_or_else(|_| toml::to_string_pretty(&config).unwrap_or_default());
        let sanitized_toml = sito_ha::sanitize_config_for_bundle(&initial_toml).unwrap_or_default();
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
        let _ = coordinator.update_bundle(initial_bundle);

        // Spawn master replication listener if replication_port > 0
        let _master_server_handle = sito_ha::spawn_master_server(
            ha_config.clone(),
            coordinator.clone(),
            shutdown_rx.clone(),
        );

        (Some(coordinator), None, None)
    } else {
        // Slave role
        let tracker = sito_ha::SlaveStatusTracker::new(
            config.server.instance_name.clone(),
            0,
            ha_config.master_url.clone(),
        );

        let slave_handles = sito_ha::SlaveAppHandles {
            config: config_arc.clone(),
            filter: filter_engine.clone(),
            rewrites: rewrites_arc.clone(),
            clients: clients_arc.clone(),
            metrics: metrics.clone(),
            config_path: Some(config_path_buf.clone()),
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

    // Administrative REST API server
    let auth_cfg = config.get_auth_config();
    let auth_mgr = Arc::new(sito_api::AuthManager::with_storage(
        &config.server.data_dir,
        auth_cfg.session_ttl_hours,
        auth_cfg.login_rate_limit,
    ));

    let server_ctx = sito_api::ServerContext {
        config: config_arc.clone(),
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
    };

    let api_router = sito_api::create_router(server_ctx);
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

    // Periodic stats retention cleanup task (every 24h)
    let retention_db = stats_db.clone();
    let retention_days = config_arc.load().get_stats_config().retention_days;
    let mut retention_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_hours(24));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = retention_shutdown_rx.changed() => {
                    if *retention_shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    if let Err(e) = retention_db.cleanup_retention(retention_days).await {
                        warn!("Error during stats retention cleanup: {e}");
                    }
                }
            }
        }
    });

    // Spawn config file watcher for hot-reload
    let watcher_config_path = config_path_buf.clone();
    let watcher_config_arc = config_arc.clone();
    let watcher_filter = filter_engine.clone();
    let watcher_coordinator = master_coordinator.clone();
    let mut watcher_shutdown_rx = shutdown_rx.clone();

    tokio::spawn(async move {
        use notify::{Event, RecursiveMode, Watcher};
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut watcher = match notify::recommended_watcher(move |res: Result<Event, _>| {
            if let Ok(event) = res
                && (event.kind.is_modify() || event.kind.is_create())
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

        if watcher_config_path.exists()
            && let Err(e) = watcher.watch(&watcher_config_path, RecursiveMode::NonRecursive)
        {
            warn!(
                "Failed to watch config file {}: {e}",
                watcher_config_path.display()
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
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    while rx.try_recv().is_ok() {}

                    match tokio::fs::read_to_string(&watcher_config_path).await {
                        Ok(content) => match Config::from_toml_str(&content) {
                            Ok(new_cfg) => {
                                info!("Detected configuration file change, hot-reloading");
                                let _ = watcher_filter.reload_with_config(&new_cfg.filtering).await;
                                watcher_config_arc.store(Arc::new(new_cfg.clone()));

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
    });

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

    let (dot_acceptor_mgr, doh_acceptor_mgr, doq_acceptor_mgr, doh3_acceptor_mgr) =
        if let (Some(cert), Some(key)) = (&effective_cert, &effective_key) {
            let doh_alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"acme-tls/1".to_vec()];
            let doh_mgr = match load_server_config_with_challenges(
                cert,
                key,
                &sni_tuples,
                doh_alpn.clone(),
                challenge_keys.clone(),
            ) {
                Ok(cfg) => {
                    let mgr = TlsAcceptorManager::with_challenge_keys(cfg, challenge_keys.clone());
                    let _ = CertWatcher::start(cert, key, &sni_tuples, &doh_alpn, mgr.clone());
                    Some(mgr)
                }
                Err(e) => {
                    warn!("Failed to initialize DoH TLS configuration: {e}");
                    None
                }
            };

            let dot_alpn = vec![b"dot".to_vec()];
            let dot_mgr = match load_server_config(cert, key, &sni_tuples, dot_alpn.clone()) {
                Ok(cfg) => {
                    let mgr = TlsAcceptorManager::new(cfg);
                    let _ = CertWatcher::start(cert, key, &sni_tuples, &dot_alpn, mgr.clone());
                    Some(mgr)
                }
                Err(e) => {
                    warn!("Failed to initialize DoT TLS configuration: {e}");
                    None
                }
            };

            let doq_alpn = vec![b"doq".to_vec()];
            let doq_mgr = match load_server_config(cert, key, &sni_tuples, doq_alpn.clone()) {
                Ok(cfg) => {
                    let mgr = TlsAcceptorManager::new(cfg);
                    let _ = CertWatcher::start(cert, key, &sni_tuples, &doq_alpn, mgr.clone());
                    Some(mgr)
                }
                Err(e) => {
                    warn!("Failed to initialize DoQ TLS configuration: {e}");
                    None
                }
            };

            let doh3_alpn = vec![b"h3".to_vec()];
            let doh3_mgr = match load_server_config(cert, key, &sni_tuples, doh3_alpn.clone()) {
                Ok(cfg) => {
                    let mgr = TlsAcceptorManager::new(cfg);
                    let _ = CertWatcher::start(cert, key, &sni_tuples, &doh3_alpn, mgr.clone());
                    Some(mgr)
                }
                Err(e) => {
                    warn!("Failed to initialize DoH3 TLS configuration: {e}");
                    None
                }
            };

            (dot_mgr, doh_mgr, doq_mgr, doh3_mgr)
        } else {
            (None, None, None, None)
        };

    // If ACME is enabled, start ACME renewal background manager
    if let Some(acme) = acme_cfg
        && acme.enabled
        && !acme.domains.is_empty()
    {
        let email = acme
            .email
            .clone()
            .unwrap_or_else(|| "admin@example.com".to_string());
        let storage_dir = acme
            .cache_dir
            .clone()
            .unwrap_or_else(|| config.server.data_dir.join("acme"));
        let doh_alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"acme-tls/1".to_vec()];
        let service_cfg =
            AcmeServiceConfig::new(email, acme.domains, storage_dir).with_staging(acme.staging);
        let _acme_handle = start_acme_manager(
            service_cfg,
            doh_acceptor_mgr.clone(),
            Some(http01_challenges.clone()),
            doh_alpn,
            shutdown_rx.clone(),
        );
    }

    let worker_count = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);

    let mut all_handles = Vec::new();

    // Bind listeners
    for bind_ip in &config.dns.bind {
        let addr = SocketAddr::new(*bind_ip, config.dns.port);

        // Start UDP listener
        let udp_config = UdpConfig {
            bind_addr: addr,
            worker_count,
            edns_udp_size: config.dns.edns_udp_size,
            rate_limit_per_ip: config.dns.rate_limit_per_ip,
        };
        let udp_handles = start_udp_listener(udp_config, &pipeline, &shutdown_rx)?;
        all_handles.extend(udp_handles);

        // Start TCP listener
        let tcp_config = TcpConfig {
            bind_addr: addr,
            max_connections: config.dns.max_tcp_connections,
            idle_timeout: Duration::from_secs(10),
            rate_limit_per_ip: config.dns.rate_limit_per_ip,
        };
        let tcp_handle =
            start_tcp_listener(tcp_config, pipeline.clone(), shutdown_rx.clone()).await?;
        all_handles.push(tcp_handle);

        // Start DoT listener if dot_port > 0 and TLS is configured
        if config.dns.dot_port > 0
            && let Some(ref dot_mgr) = dot_acceptor_mgr
        {
            let dot_addr = SocketAddr::new(*bind_ip, config.dns.dot_port);
            let mut dot_config = DotConfig::new(dot_addr, dot_mgr.clone());
            dot_config.dot_padding = config.dns.dot_padding;
            dot_config.rate_limit_per_ip = config.dns.rate_limit_per_ip;
            dot_config.max_connections = config.dns.max_tcp_connections;
            let dot_handle =
                start_dot_listener(dot_config, pipeline.clone(), shutdown_rx.clone()).await?;
            all_handles.push(dot_handle);
        }

        // Start DoH listener if doh_port > 0 and (TLS configured or non-default port)
        if config.dns.doh_port > 0 && (doh_acceptor_mgr.is_some() || config.dns.doh_port != 443) {
            let doh_addr = SocketAddr::new(*bind_ip, config.dns.doh_port);
            let mut doh_config = DohConfig::new(doh_addr, doh_acceptor_mgr.clone())
                .with_http01_challenges(http01_challenges.clone())
                .with_alt_svc_port(if config.dns.doh3_port > 0 {
                    Some(config.dns.doh3_port)
                } else {
                    None
                });
            doh_config.rate_limit_per_ip = config.dns.rate_limit_per_ip;
            doh_config.max_connections = config.dns.max_tcp_connections;
            let doh_handle =
                start_doh_listener(doh_config, pipeline.clone(), shutdown_rx.clone()).await?;
            all_handles.push(doh_handle);
        }

        // Start DoQ listener if doq_port > 0 and TLS is configured
        if config.dns.doq_port > 0
            && let Some(ref doq_mgr) = doq_acceptor_mgr
        {
            let doq_addr = SocketAddr::new(*bind_ip, config.dns.doq_port);
            let mut doq_config = DoqConfig::new(doq_addr, Some(doq_mgr.clone()));
            doq_config.rate_limit_per_ip = config.dns.rate_limit_per_ip;
            doq_config.max_connections = config.dns.max_tcp_connections;
            match start_doq_listener(doq_config, pipeline.clone(), shutdown_rx.clone()).await {
                Ok(doq_handle) => all_handles.push(doq_handle),
                Err(e) => warn!("Failed to start DoQ listener on {doq_addr}: {e}"),
            }
        }

        // Start DoH3 listener if doh3_port > 0 and TLS is configured
        if config.dns.doh3_port > 0
            && let Some(ref doh3_mgr) = doh3_acceptor_mgr
        {
            let doh3_addr = SocketAddr::new(*bind_ip, config.dns.doh3_port);
            let mut doh3_config = Doh3Config::new(doh3_addr, Some(doh3_mgr.clone()));
            doh3_config.rate_limit_per_ip = config.dns.rate_limit_per_ip;
            doh3_config.max_connections = config.dns.max_tcp_connections;
            match start_doh3_listener(doh3_config, pipeline.clone(), shutdown_rx.clone()).await {
                Ok(doh3_handle) => all_handles.push(doh3_handle),
                Err(e) => warn!("Failed to start DoH3 listener on {doh3_addr}: {e}"),
            }
        }
    }

    let _ = all_handles;

    info!(
        port = config.dns.port,
        bind = ?config.dns.bind,
        "sito DNS server successfully initialized and listening"
    );

    // Wait for termination signal
    wait_for_shutdown_signal(custom_shutdown).await?;

    info!("Initiating graceful shutdown (stopping listeners)...");
    let _ = shutdown_tx.send(true);

    // Wait for in-flight queries to finish (5 s timeout per plan section 3.5)
    let shutdown_deadline = std::time::Instant::now() + Duration::from_secs(5);
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

    info!("Graceful shutdown complete, exiting");
    Ok(())
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
