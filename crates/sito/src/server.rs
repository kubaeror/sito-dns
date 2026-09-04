//! Server lifecycle and runner implementation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::watch;
use tracing::{info, warn};

use sito_cache::DnsCache;
use sito_core::config::Config;
use sito_filter::HostsFilterEngine;
use sito_transport::{TcpConfig, UdpConfig, start_tcp_listener, start_udp_listener};
use sito_upstream::{BootstrapResolver, UpstreamManager};

use crate::pipeline::DnsPipeline;

/// Runs the complete sito DNS server with graceful shutdown handling.
pub async fn run_server(config: Config) -> anyhow::Result<()> {
    run_server_with_shutdown(config, None).await
}

/// Runs the DNS server with an optional custom shutdown receiver (useful for testing).
pub async fn run_server_with_shutdown(
    config: Config,
    custom_shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let in_flight = Arc::new(AtomicUsize::new(0));

    // Ensure data directory exists
    tokio::fs::create_dir_all(&config.server.data_dir).await?;

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

    // Construct pipeline
    let pipeline = Arc::new(DnsPipeline::new(
        Arc::new(config.clone()),
        filter_engine,
        cache,
        upstream_manager,
        in_flight.clone(),
    ));

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
