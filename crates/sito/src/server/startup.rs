//! Server startup orchestration.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Runs the DNS server with an optional custom shutdown receiver (useful for testing).
pub async fn run_server_with_shutdown(
    config: Config,
    custom_shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    let config_path = config.server.data_dir.join("config.toml");
    run_server_full(config, config_path, custom_shutdown, false).await
}

/// Runs the DNS server with custom config path, shutdown receiver, and setup-pending mode.
///
/// Acquires the service lease for `config.server.data_dir` for the whole server
/// lifetime. Callers that already acquired it before a bootstrap mutation must
/// use [`run_server_with_lease`] so the same lease is held continuously.
pub async fn run_server_full(
    config: Config,
    config_path: impl AsRef<Path>,
    custom_shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
    setup_pending: bool,
) -> anyhow::Result<()> {
    let service_lease = crate::service_lock::acquire_service_lease(&config.server.data_dir)?;
    run_server_with_lease(
        config,
        config_path,
        custom_shutdown,
        setup_pending,
        service_lease,
    )
    .await
}

/// Runs the DNS server with a caller-held service lease.
///
/// The lease must have been acquired before any bootstrap mutation (P2-90) and
/// is held until this function returns, covering the whole server lifetime.
pub async fn run_server_with_lease(
    config: Config,
    config_path: impl AsRef<Path>,
    custom_shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
    setup_pending: bool,
    service_lease: crate::service_lock::ServiceLease,
) -> anyhow::Result<()> {
    validate_typed_sections(&config)?;

    // Make the historical wildcard defaults visible at startup. This is a
    // warning, not a refusal: existing Docker/quickstart configurations must
    // keep starting. 1.10.0 changes the defaults and is documented separately.
    for warning in exposure_warnings_for_phase(&config, ExposurePhase::Startup) {
        warn!("NETWORK EXPOSURE: {warning}");
    }

    // Hold the single-instance lease for the whole server lifetime. The reset
    // commands use the same lease to distinguish "stopped" from "running" and
    // refuse to pretend that credentials/sessions were revoked live.
    let _service_lease = service_lease;

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
    filter_engine.set_group_rules(sito_runtime::group_rule_sets(&clients_config));

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

    // Initialize MikroTik RouterOS integration if configured. The HTTP stack
    // lives in the optional `sito-routeros` crate; a build without the
    // `routeros` feature rejects an enabled integration during config
    // validation instead of silently ignoring it.
    #[cfg(feature = "routeros")]
    if let Some(integrations) = integrations
        && let Some(mikrotik_cfg) = integrations.mikrotik
        && mikrotik_cfg.enabled
    {
        let _routeros_handle = sito_routeros::spawn_routeros_sync(
            mikrotik_cfg,
            client_registry.clone(),
            shutdown_rx.clone(),
        );
    }

    // Setup ArcSwaps for hot-reloadable components and a coherent runtime view
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config.clone())));
    let clients_arc = Arc::new(ArcSwap::new(client_registry.clone()));
    let rewrites_arc = Arc::new(ArcSwap::new(rewrite_table.clone()));
    let runtime = Arc::new(
        sito_runtime::RuntimeState::new(
            config_arc.clone(),
            clients_arc.clone(),
            rewrites_arc.clone(),
        )
        .with_cache(cache.clone()),
    );
    // Seed the coherent snapshot with the components created above. This is
    // startup bootstrap, not an apply, so the generation is not advanced.
    runtime.bootstrap_components(
        Some(filter_engine.snapshot()),
        filter_engine.group_snapshots(),
        sito_runtime::DnssecPolicy::from_validator(&config.dns.dnssec, dnssec_swap.load_full()),
        sito_runtime::TransportPolicy::from(&config),
    );
    // Scheduled/partial list refreshes publish outside a config apply; keep
    // the runtime snapshot (and therefore the query path) on the new rules.
    {
        let refresh_runtime = Arc::clone(&runtime);
        filter_engine.set_snapshot_observer(Arc::new(move |snapshot, groups| {
            // Called while the filter engine holds its reload guard, so the
            // config generation cannot change between the read and publish.
            let expected = refresh_runtime.generation();
            if let Err(error) = refresh_runtime.publish_filter(Some(snapshot), groups, expected) {
                tracing::debug!(
                    error = %error,
                    "Discarding a scheduled blocklist refresh that raced a config apply"
                );
            }
        }));
    }

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

    // Server-owned readiness (listeners/TLS) read by `/health` and `/status`.
    let readiness = Arc::new(sito_api::ReadinessState::default());

    let apply_hooks = Arc::new(ServerApplyHooks {
        dnssec: dnssec_swap.clone(),
        dnssec_chain_cache: dnssec_chain_cache.clone(),
        scoped_upstreams: scoped_upstreams.clone(),
        rate_limiters: rate_limiters.clone(),
        listener_manager: listener_manager.clone(),
        listener_acceptors: listener_acceptors.clone(),
        pipeline: pipeline.clone(),
        readiness: readiness.clone(),
    });

    // D12 readiness state shared with the API. Challenge flags are updated by
    // `init_tls_and_acme`/`start_dns_listeners`; issuance errors by the ACME
    // manager.
    let acme_challenges = AcmeChallengeAvailability::new(false, false);

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
        readiness: readiness.clone(),
        acme_challenges: Some(acme_challenges.clone()),
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
    // `retention_days`, `rollup_retention_days` and `rollup_client_names` are
    // read on every cycle so config hot-reload applies. A bounded catch-up
    // sweep runs on every startup after a short delay (capped at 5 minutes)
    // plus jitter, so restart-heavy deployments still retain data.
    let retention_db = stats_db.clone();
    let retention_config = config_arc.clone();
    let retention_metrics = metrics.clone();
    let mut retention_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let last_success = retention_db
            .retention_last_success_ms()
            .await
            .unwrap_or_else(|e| {
                warn!("Could not read last stats retention timestamp: {e}");
                None
            });
        let interval_ms = i64::try_from(RETENTION_INTERVAL.as_millis()).unwrap_or(i64::MAX);
        let base_delay_ms = retention_startup_delay_ms(last_success, now_ms, interval_ms);
        let jitter_ms = (rand::random::<u64>() % (RETENTION_STARTUP_JITTER_MAX_SECS * 1000 + 1))
            .try_into()
            .unwrap_or(i64::MAX);
        let delay_ms = base_delay_ms.saturating_add(jitter_ms).max(0);
        let delay = Duration::from_millis(u64::try_from(delay_ms).unwrap_or(u64::MAX));

        // Always run one bounded catch-up at startup. The delay only avoids
        // duplicate work when the last sweep is recent; it is capped so a
        // restart-heavy process still runs retention within a few minutes.
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            res = retention_shutdown_rx.changed() => {
                if res.is_err() || *retention_shutdown_rx.borrow() {
                    return;
                }
            }
        }
        run_stats_retention_sweep(&retention_db, &retention_config, &retention_metrics).await;

        let mut interval = tokio::time::interval(RETENTION_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Consume the immediate first tick; the startup catch-up above ran.
        interval.tick().await;
        loop {
            tokio::select! {
                res = retention_shutdown_rx.changed() => {
                    if res.is_err() || *retention_shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    run_stats_retention_sweep(
                        &retention_db,
                        &retention_config,
                        &retention_metrics,
                    ).await;
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

    let mut cert_watchers =
        init_tls_and_acme(&config, &shutdown_rx, &listener_acceptors, &acme_challenges).await?;
    {
        let acceptors = listener_acceptors.lock().await.clone();
        publish_tls_readiness(&readiness, &config, acceptors.as_ref(), None);
    }

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
                let tls_init_error = match init_tls_and_acme(
                    &current_cfg,
                    &shutdown_rx,
                    &listener_acceptors,
                    &acme_challenges,
                )
                .await
                {
                    Ok(watchers) => {
                        cert_watchers.extend(watchers);
                        None
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "Failed to initialize TLS after setup; encrypted listeners may be unavailable"
                        );
                        Some(e)
                    }
                };
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
                // A failure here used to be a warning only; readiness now
                // reflects that a configured encrypted listener is not serving.
                publish_tls_readiness(
                    &readiness,
                    &current_cfg,
                    Some(&acceptors),
                    tls_init_error.as_ref(),
                );
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
                readiness.set_listeners_ready();
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
        readiness.set_listeners_ready();
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
