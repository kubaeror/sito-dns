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

    // Startup policy is parsed once. Never migrate silently: an older database
    // is refused unless SITO_DB_AUTO_MIGRATE opts into the backup path.
    let auto_migrate = crate::db_startup::DbAutoMigrate::from_env()?;

    // Initialize Stats SQLite DB
    let stats_config = config.get_stats_config();
    let stats_db = crate::db_startup::prepare_stats_db(
        &config.server.data_dir,
        stats_config.rollup_client_names,
        auto_migrate,
    )
    .await?;

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

/// Retry period when no curated list category has a representable refresh
/// deadline, so the task re-evaluates instead of spinning.
const UNSCHEDULABLE_REFRESH_RETRY: Duration = Duration::from_secs(3600);

/// Converts a configured `[integrations.lists]` refresh interval in hours into
/// a safe [`Duration`].
///
/// Clamps to `1..=MAX_REFRESH_HOURS`. Config validation already rejects `0` and
/// values above the cap; the runtime clamp is defense in depth for configs
/// constructed without validation, and keeps the hour-to-second multiplication
/// from overflowing.
fn integration_refresh_interval(hours: u64) -> Duration {
    Duration::from_secs(
        hours
            .clamp(1, sito_core::config::MAX_REFRESH_HOURS)
            .saturating_mul(3600),
    )
}

/// Returns the next refresh deadline, or `None` when the platform `Instant`
/// cannot represent it.
///
/// The interval is already clamped to one year, so `None` only happens when the
/// platform clock is exhausted; callers skip such categories rather than
/// scheduling them in the past (which would hot-loop the refresh task).
fn integration_next_deadline(
    now: tokio::time::Instant,
    interval: Duration,
) -> Option<tokio::time::Instant> {
    now.checked_add(interval)
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
    let default_hours = config.refresh_hours;
    let mut entries: Vec<(String, String, Duration, Option<tokio::time::Instant>)> = config
        .categories
        .into_iter()
        .map(|(name, source)| {
            let hours = source.refresh_hours.unwrap_or(default_hours);
            let interval = integration_refresh_interval(hours);
            // Refresh immediately on startup (bundled data is only the
            // fallback until the first successful download), then reschedule
            // through `integration_next_deadline` after every refresh.
            (
                name,
                source.url,
                interval,
                Some(tokio::time::Instant::now()),
            )
        })
        .collect();
    if entries.is_empty() {
        return;
    }

    loop {
        // Pick the earliest representable deadline. A category whose
        // reschedule yielded `None` was warned about there and is skipped.
        let Some((next_idx, deadline)) = entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| entry.3.map(|deadline| (index, deadline)))
            .min_by_key(|(_, deadline)| *deadline)
        else {
            // No category is schedulable: wait before re-evaluating instead of
            // hot-looping the selection.
            tokio::select! {
                res = shutdown_rx.changed() => {
                    if res.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                () = tokio::time::sleep(UNSCHEDULABLE_REFRESH_RETRY) => {
                    for entry in &mut entries {
                        if entry.3.is_none() {
                            entry.3 = integration_next_deadline(tokio::time::Instant::now(), entry.2);
                        }
                    }
                }
            }
            continue;
        };

        let wait = deadline.saturating_duration_since(tokio::time::Instant::now());

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
                // Record the attempt before the network/file read so status
                // consumers see in-flight work even if the fetch stalls.
                store.record_attempt(&name, None);
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
                        Err(e) => {
                            store.record_attempt(&name, Some(e.clone()));
                            warn!(
                                category = %name,
                                "Ignoring invalid refreshed curated list: {e}"
                            );
                        }
                    },
                    Err(e) => {
                        store.record_attempt(&name, Some(e.to_string()));
                        warn!(
                            category = %name,
                            url = %url,
                            "Failed to refresh curated list: {e}"
                        );
                    }
                }
                let next = integration_next_deadline(
                    tokio::time::Instant::now(),
                    entries[next_idx].2,
                );
                entries[next_idx].3 = next;
                if next.is_none() {
                    warn!(
                        category = %name,
                        "Skipping curated list category: next refresh deadline is not representable on this platform"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sito_core::config::MAX_REFRESH_HOURS;

    #[test]
    fn test_integration_refresh_interval_is_bounded() {
        let cap = Duration::from_secs(MAX_REFRESH_HOURS * 3600);
        assert_eq!(integration_refresh_interval(0), Duration::from_secs(3600));
        assert_eq!(integration_refresh_interval(1), Duration::from_secs(3600));
        assert_eq!(integration_refresh_interval(MAX_REFRESH_HOURS), cap);
        assert_eq!(integration_refresh_interval(u64::MAX), cap);
    }

    #[tokio::test]
    async fn test_list_refresh_failure_records_last_error() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito_list_refresh_failure_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let mut config = sito_clients::ListCategoriesConfig::default();
        config.categories.insert(
            "adult".to_string(),
            sito_clients::ListSourceConfig {
                url: format!("file://{}", temp_dir.join("missing.txt").display()),
                refresh_hours: None,
                license: None,
            },
        );
        let store = std::sync::Arc::new(
            sito_clients::RuntimeLists::try_new().expect("bundled lists must load"),
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(run_list_refresh(
            config,
            store.clone(),
            temp_dir.clone(),
            shutdown_rx,
        ));

        let mut recorded = None;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(25)).await;
            if let Some(status) = store
                .statuses()
                .into_iter()
                .find(|status| status.category == "adult")
                && status.last_error.is_some()
            {
                recorded = Some(status);
                break;
            }
        }
        let status = recorded.expect("a failed fetch must record last_error");
        assert!(
            !status.last_error.unwrap().is_empty(),
            "last_error must carry the fetch failure"
        );
        assert!(status.last_attempt_unix.is_some());
        assert!(
            status.bundled,
            "a failed refresh keeps the bundled fallback active"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_integration_next_deadline_is_bounded() {
        let now = tokio::time::Instant::now();
        let interval = integration_refresh_interval(u64::MAX);
        let deadline = integration_next_deadline(now, interval)
            .expect("a clamped one-year interval must be representable");
        assert!(deadline > now, "the deadline must be in the future");
        assert_eq!(deadline - now, interval);
        assert_eq!(
            integration_next_deadline(now, Duration::from_secs(u64::MAX)),
            None,
            "checked_add must reject a duration beyond the platform Instant range"
        );
    }
}
