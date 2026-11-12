//! Listener planning, start/rebind/stop, and signal handling.

#[allow(clippy::wildcard_imports)]
use super::*;

/// TLS acceptor managers shared with the config watcher so listeners can be
/// rebound without restarting the process.
#[derive(Clone)]
pub(super) struct ListenerAcceptors {
    pub(super) dot: Option<TlsAcceptorManager>,
    pub(super) doh: Option<TlsAcceptorManager>,
    pub(super) doq: Option<TlsAcceptorManager>,
    pub(super) doh3: Option<TlsAcceptorManager>,
    /// Live ACME challenge-listener state, updated after every DNS bind.
    pub(super) acme_challenges: AcmeChallengeAvailability,
}

/// Settings that determine how the DNS listeners are constructed. Changing
/// any of them requires stopping and rebinding the affected listeners.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct ListenerPlan {
    pub(super) bind: Vec<std::net::IpAddr>,
    pub(super) port: u16,
    pub(super) dot_port: u16,
    pub(super) doh_port: u16,
    pub(super) doq_port: u16,
    pub(super) doh3_port: u16,
    pub(super) doh_dedicated_hostname: String,
    pub(super) allow_plaintext_doh: bool,
    pub(super) edns_udp_size: u16,
    pub(super) max_tcp_connections: usize,
    pub(super) dot_padding: bool,
}

impl ListenerPlan {
    pub(super) fn from_config(config: &Config) -> Self {
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
pub(super) struct DnsListenerManager {
    pub(super) shutdown_tx: watch::Sender<bool>,
    pub(super) handles: Vec<tokio::task::JoinHandle<()>>,
    pub(super) rate_limiters: Arc<std::sync::Mutex<Vec<Arc<sito_transport::RateLimiter>>>>,
    pub(super) plan: ListenerPlan,
    pub(super) config: Config,
}

impl DnsListenerManager {
    pub(super) async fn start(
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

    pub(super) fn needs_restart(&self, config: &Config) -> bool {
        self.plan != ListenerPlan::from_config(config)
    }

    pub(super) async fn stop(&mut self) {
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
    pub(super) async fn restart(
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
pub(super) async fn start_dns_listeners(
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

pub(super) async fn wait_for_shutdown_signal(
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
