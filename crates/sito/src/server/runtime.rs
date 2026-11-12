//! Runtime components, retention scheduling, and list refresh.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Long-lived runtime components created during startup.
pub(super) struct RuntimeComponents {
    pub(super) stats_db: StatsDb,
    pub(super) metrics: MetricsRegistry,
    pub(super) querylog_writer: QueryLogWriter,
    pub(super) querylog_sender: sito_stats::QueryLogSender,
    pub(super) upstream_manager: Arc<UpstreamManager>,
    pub(super) cache: Arc<DnsCache>,
    pub(super) filter_engine: Arc<HostsFilterEngine>,
}

/// Delay before the first retention sweep after startup.
///
/// Normally this is the time remaining until `last_success + interval`, but it
/// is capped so a process that restarts more often than the interval still
/// runs a bounded catch-up within [`RETENTION_STARTUP_CATCHUP_MAX_DELAY_MS`].
/// `None`/an old timestamp means run immediately (subject only to jitter).
pub(super) fn retention_startup_delay_ms(
    last_success_ms: Option<i64>,
    now_ms: i64,
    interval_ms: i64,
) -> i64 {
    let Some(last) = last_success_ms else {
        return 0;
    };
    last.saturating_add(interval_ms)
        .saturating_sub(now_ms)
        .clamp(0, RETENTION_STARTUP_CATCHUP_MAX_DELAY_MS)
}

/// Runs one retention sweep and publishes its outcome to Prometheus.
pub(super) async fn run_stats_retention_sweep(
    db: &StatsDb,
    config: &ArcSwap<Config>,
    metrics: &MetricsRegistry,
) {
    let stats = config.load().get_stats_config();
    let started = Instant::now();
    match db
        .cleanup_retention_with_policy(
            stats.retention_days,
            stats.rollup_retention_days,
            stats.rollup_client_names,
        )
        .await
    {
        Ok(report) => {
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            metrics.record_retention_success(
                elapsed_ms,
                report.deleted_records,
                report.rollup_deleted_records,
                stats.rollup_retention_days,
            );
            info!(
                deleted = report.deleted_records,
                rollup_deleted = report.rollup_deleted_records,
                chunks = report.chunks,
                elapsed_ms,
                "stats retention sweep completed"
            );
        }
        Err(e) => {
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            metrics.record_retention_failure(elapsed_ms);
            warn!("Error during stats retention cleanup: {e}");
        }
    }
}

pub(super) async fn init_runtime_components(
    config: &Config,
    shutdown_rx: &watch::Receiver<bool>,
) -> anyhow::Result<RuntimeComponents> {
    // Ensure data directory exists
    tokio::fs::create_dir_all(&config.server.data_dir).await?;

    // Initialize Stats SQLite DB
    let db_path = config.server.data_dir.join("stats.db");
    let stats_config = config.get_stats_config();
    let stats_db =
        StatsDb::open_with_rollup_client_names(&db_path, stats_config.rollup_client_names).await?;

    // Initialize Prometheus metrics registry with 18 metrics per Table 14.2
    let metrics = MetricsRegistry::new(
        env!("CARGO_PKG_VERSION"),
        option_env!("SITO_BUILD_COMMIT").unwrap_or("unknown"),
    );
    metrics.set_rollup_retention_days(stats_config.rollup_retention_days);
    if let Ok(Some(last_success_ms)) = stats_db.retention_last_success_ms().await {
        metrics
            .set_retention_last_success_seconds(u64::try_from(last_success_ms / 1000).unwrap_or(0));
    }
    if stats_config.rollup_retention_days < stats_config.retention_days {
        warn!(
            retention_days = stats_config.retention_days,
            rollup_retention_days = stats_config.rollup_retention_days,
            "stats.rollup_retention_days is shorter than stats.retention_days; archived totals will expire before detailed rows"
        );
    }

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
    //
    // Group custom rules are a real source even when global
    // `filtering.lists`/`custom_rules` are empty; pass the actual group rule
    // sets so the initial reload can verify at least one compiles, instead of
    // trusting raw text that may be comment-only or invalid.
    let initial_clients = clients_from_config(config)?;
    let initial_group_rules = sito_runtime::group_rule_sets(&initial_clients);
    let filter_engine = Arc::new(
        HostsFilterEngine::init_with_observer_and_group_sources(
            config.filtering.clone(),
            config.server.data_dir.clone(),
            Some(metrics.compile_observer()),
            initial_group_rules,
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
