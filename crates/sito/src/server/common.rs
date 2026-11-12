//! Configuration adapters, shared constants, and startup warnings.

#[allow(clippy::wildcard_imports)]
use super::*;

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
pub(super) const QUERYLOG_BUFFER: usize = 10_000;
/// How often the query-log drop counter is published to Prometheus.
pub(super) const QUERYLOG_METRICS_INTERVAL: Duration = Duration::from_secs(5);
/// Graceful shutdown budget for draining in-flight queries.
pub(super) const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// Stats retention sweep interval (retention_days is re-read every cycle).
pub(super) const RETENTION_INTERVAL: Duration = Duration::from_hours(24);
/// Maximum random delay before the startup catch-up sweep so a fleet of
/// restarted nodes does not all compact SQLite at once.
pub(super) const RETENTION_STARTUP_JITTER_MAX_SECS: u64 = 60;
/// Even when the persisted last success is recent, run a bounded catch-up
/// within this window so restart-heavy deployments still retain data.
pub(super) const RETENTION_STARTUP_CATCHUP_MAX_DELAY_MS: i64 = 5 * 60 * 1000;
/// Debounce window for config file watcher events.
pub(super) const WATCHER_DEBOUNCE: Duration = Duration::from_millis(100);
/// Periodic flush interval for the persistent DNSSEC chain cache.
pub(super) const CHAIN_CACHE_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// Current UNIX time truncated to the DNSSEC serial-number width.
pub(super) fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

/// Resolves the config path to an absolute path so the file watcher can watch
/// its parent directory even for the default relative `config.toml`. Symlinks
/// are resolved when the file exists; otherwise it is anchored to the current
/// working directory.
pub(super) fn canonical_config_path(path: &Path) -> PathBuf {
    match std::fs::canonicalize(path) {
        Ok(resolved) => resolved,
        Err(_) => std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()),
    }
}

/// Compares two sanitized bundle documents semantically, falling back to byte
/// comparison when either side is not valid TOML. Used at master startup to
/// decide whether `config.toml` still matches the persisted bundle.
pub(super) fn sanitized_configs_equal(a: &str, b: &str) -> bool {
    match (a.parse::<toml::Table>(), b.parse::<toml::Table>()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Opens the stats database and initializes metrics, query logging, upstreams,
/// cache and the filter engine together with their background tasks.
/// Maps the filter crate's status into the metrics crate's primitive view
/// (the filter crate cannot depend on `sito-stats`).
pub(super) fn filter_status_metrics(
    status: &sito_filter::FilterStatus,
) -> sito_stats::FilterStatusMetrics {
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
        unavailable: u64::from(status.unavailable),
    }
}

/// Loads the embedded parental-control and service-blocking registries.
///
/// Uses the non-panicking `try_bundled()` loaders: corrupted embedded data is
/// a packaging/build defect, so startup must be able to report it and exit
/// cleanly instead of aborting with a panic.
pub(super) fn load_bundled_registries() -> anyhow::Result<(
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

/// Startup phases that expose different listeners. The admin UI starts even in
/// setup-pending mode; DNS listeners start only after setup (or immediately in
/// a normal boot), so their warning is emitted at that transition.
#[derive(Clone, Copy)]
pub(super) enum ExposurePhase {
    Startup,
    DnsListeners,
}

/// Returns the exposure warnings relevant to a startup phase.
pub(super) fn exposure_warnings_for_phase(config: &Config, phase: ExposurePhase) -> Vec<String> {
    let warning = match phase {
        ExposurePhase::Startup => config.web_exposure_warning(),
        ExposurePhase::DnsListeners => config.dns_exposure_warning(),
    };
    warning.into_iter().collect()
}
