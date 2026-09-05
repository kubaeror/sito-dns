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
    CertWatcher, DohConfig, DotConfig, TcpConfig, TlsAcceptorManager, UdpConfig,
    load_server_config, start_doh_listener, start_dot_listener, start_tcp_listener,
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
    if let Some(ref int_val) = config.integrations {
        if let Ok(integrations) = int_val.clone().try_into::<IntegrationsConfig>() {
            if let Some(mikrotik_cfg) = integrations.mikrotik {
                if mikrotik_cfg.enabled {
                    let _routeros_handle = sito_clients::spawn_routeros_sync(
                        mikrotik_cfg,
                        client_registry.clone(),
                        shutdown_rx.clone(),
                    );
                }
            }
        }
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

    // Administrative REST API server
    let server_ctx = sito_api::ServerContext {
        config: config_arc.clone(),
        config_path: config_path_buf.clone(),
        auth_mgr: Arc::new(sito_api::AuthManager::new()),
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
    };

    let api_router = sito_api::create_router(server_ctx);
    if let Ok(listener) = tokio::net::TcpListener::bind("0.0.0.0:3000").await {
        let mut api_shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, api_router)
                .with_graceful_shutdown(async move {
                    while !*api_shutdown_rx.borrow_and_update() {
                        if api_shutdown_rx.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await;
        });
        info!("sito admin REST API listening on http://0.0.0.0:3000");
    }

    // Spawn config file watcher for hot-reload
    let watcher_config_path = config_path_buf.clone();
    let watcher_config_arc = config_arc.clone();
    let watcher_filter = filter_engine.clone();
    let mut watcher_shutdown_rx = shutdown_rx.clone();

    tokio::spawn(async move {
        use notify::{Event, RecursiveMode, Watcher};
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut watcher = match notify::recommended_watcher(move |res: Result<Event, _>| {
            if let Ok(event) = res {
                if event.kind.is_modify() || event.kind.is_create() {
                    let _ = tx.send(());
                }
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!("Failed to initialize config file watcher: {e}");
                return;
            }
        };

        if watcher_config_path.exists() {
            if let Err(e) = watcher.watch(&watcher_config_path, RecursiveMode::NonRecursive) {
                warn!(
                    "Failed to watch config file {}: {e}",
                    watcher_config_path.display()
                );
                return;
            }
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
                                watcher_config_arc.store(Arc::new(new_cfg));
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

    // Load TLS configuration if configured
    let (dot_acceptor_mgr, doh_acceptor_mgr) = if let Some(tls_cfg) = config.get_tls_config() {
        if let (Some(cert), Some(key)) = (&tls_cfg.cert, &tls_cfg.key) {
            let sni_tuples = tls_cfg.sni_tuples();
            let dot_mgr = match load_server_config(cert, key, &sni_tuples, vec![b"dot".to_vec()]) {
                Ok(cfg) => {
                    let mgr = TlsAcceptorManager::new(cfg);
                    let _ =
                        CertWatcher::start(cert, key, &sni_tuples, &[b"dot".to_vec()], mgr.clone());
                    Some(mgr)
                }
                Err(e) => {
                    warn!("Failed to initialize DoT TLS configuration: {}", e);
                    None
                }
            };

            let doh_mgr = match load_server_config(
                cert,
                key,
                &sni_tuples,
                vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            ) {
                Ok(cfg) => {
                    let mgr = TlsAcceptorManager::new(cfg);
                    let _ = CertWatcher::start(
                        cert,
                        key,
                        &sni_tuples,
                        &[b"h2".to_vec(), b"http/1.1".to_vec()],
                        mgr.clone(),
                    );
                    Some(mgr)
                }
                Err(e) => {
                    warn!("Failed to initialize DoH TLS configuration: {}", e);
                    None
                }
            };

            (dot_mgr, doh_mgr)
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

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
        if config.dns.dot_port > 0 {
            if let Some(ref dot_mgr) = dot_acceptor_mgr {
                let dot_addr = SocketAddr::new(*bind_ip, config.dns.dot_port);
                let mut dot_config = DotConfig::new(dot_addr, dot_mgr.clone());
                dot_config.dot_padding = config.dns.dot_padding;
                dot_config.rate_limit_per_ip = config.dns.rate_limit_per_ip;
                dot_config.max_connections = config.dns.max_tcp_connections;
                let dot_handle =
                    start_dot_listener(dot_config, pipeline.clone(), shutdown_rx.clone()).await?;
                all_handles.push(dot_handle);
            }
        }

        // Start DoH listener if doh_port > 0 and (TLS configured or non-default port)
        if config.dns.doh_port > 0 && (doh_acceptor_mgr.is_some() || config.dns.doh_port != 443) {
            let doh_addr = SocketAddr::new(*bind_ip, config.dns.doh_port);
            let mut doh_config = DohConfig::new(doh_addr, doh_acceptor_mgr.clone());
            doh_config.rate_limit_per_ip = config.dns.rate_limit_per_ip;
            doh_config.max_connections = config.dns.max_tcp_connections;
            let doh_handle =
                start_doh_listener(doh_config, pipeline.clone(), shutdown_rx.clone()).await?;
            all_handles.push(doh_handle);
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
