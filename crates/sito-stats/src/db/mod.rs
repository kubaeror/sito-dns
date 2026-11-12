//! SQLite stats storage: schema, query log, rollups, and retention.
//!
//! The facade keeps the public `StatsDb` type; storage concerns live in the
//! sibling modules.

//! SQLite database storage engine for query logging and historical statistics.

use crate::entry::QueryLogEntry;
use crate::error::StatsError;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Connection, Pool, Row, Sqlite, SqliteConnection};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use utoipa::ToSchema;

mod querylog;
mod retention;
mod schema;
mod support;

/// Maximum number of rows returned by the per-client/per-upstream aggregate
/// queries. The endpoints used to return one row per distinct client or
/// upstream with no bound, so a resolver with many short-lived addresses could
/// produce an unbounded response.
pub const MAX_AGGREGATE_ROWS: usize = 1_000;

/// Number of top entries persisted per hour and dimension in `stats_hourly`.
/// Rollup top lists are a bounded summary of pruned rows, not a full archive.
const ROLLUP_TOP_N: usize = 100;

/// Minimum number of rows a retention sweep must delete before the database is
/// vacuumed. `VACUUM` rewrites the whole file, so it is only worth running
/// after a meaningful amount of data was freed.
const VACUUM_MIN_DELETED_ROWS: u64 = 1_000;

/// Prefix for keyed BLAKE3 client identifiers stored in `stats_hourly`.
/// The colon-only form is deliberately longer than an IP literal can be, and
/// `is_hashed_client_id` additionally requires exactly 64 hex characters.
const ROLLUP_HASH_PREFIX: &str = "blake3:";

/// Legacy prefix used by an earlier unreleased build. Recognized only when it
/// is followed by exactly 64 hex characters, so a real IPv6 address such as
/// `b3::1` is still hashed rather than mistaken for a stored digest.
const LEGACY_ROLLUP_HASH_PREFIX: &str = "b3:";

/// Maximum number of detailed query-log rows processed in one retention
/// transaction. A single busy hour is sub-chunked by `id` to keep the writer
/// lock short even when millions of rows share one hour.
const RETENTION_ROWS_PER_CHUNK: i64 = 5_000;

/// Per-install salt file name under the stats data directory.
const SALT_FILE_NAME: &str = "stats-salt";

/// How long dashboard aggregates may be served from memory before a fresh
/// scan is allowed. Keeps 5 s UI polling from repeatedly scanning SQLite.
const DASHBOARD_CACHE_TTL: Duration = Duration::from_secs(45);

/// Rows per transaction in the one-time legacy rollup PII backfill.
const ROLLUP_PII_BACKFILL_BATCH: i64 = 1_000;

/// One row-bounded retention chunk: hour plus `(ts, id)` cursor bounds.
#[derive(Clone, Copy)]
struct RetentionChunk {
    hour: i64,
    lower: (i64, i64),
    upper: (i64, i64),
}

/// Bounded per-hour rollup payloads extracted from rows about to be pruned.
#[derive(Default, Clone)]
struct HourRollup {
    /// `(qname, total, blocked)`
    domains: Vec<(String, i64, i64)>,
    /// `(client_ip, client_name, total, blocked, last_seen)`
    clients: Vec<(String, Option<String>, i64, i64, i64)>,
    /// `(upstream, total, errors, elapsed_us_sum)`
    upstreams: Vec<(String, i64, i64, i64)>,
}

type DomainTop = (String, i64, i64);
type ClientTop = (String, Option<String>, i64, i64, i64);
type UpstreamTop = (String, i64, i64, i64);

fn decode_tops<T: serde::de::DeserializeOwned>(json: Option<&str>) -> Vec<T> {
    json.and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

fn encode_tops<T: Serialize>(items: &[T]) -> String {
    serde_json::to_string(items).unwrap_or_else(|_| "[]".to_string())
}

/// Keeps the lexicographically largest non-empty client name so the label is
/// deterministic when a client IP was seen under several names.
fn keep_max_name(current: &mut Option<String>, candidate: Option<String>) {
    if let Some(candidate) = candidate
        && current
            .as_deref()
            .is_none_or(|existing| existing < candidate.as_str())
    {
        *current = Some(candidate);
    }
}

fn merge_domain_tops(
    existing: Vec<DomainTop>,
    incoming: Vec<DomainTop>,
    limit: usize,
) -> Vec<DomainTop> {
    let mut merged: HashMap<String, (i64, i64)> = HashMap::new();
    for (qname, total, blocked) in existing.into_iter().chain(incoming) {
        let entry = merged.entry(qname).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(total);
        entry.1 = entry.1.saturating_add(blocked);
    }
    let mut items: Vec<DomainTop> = merged
        .into_iter()
        .map(|(qname, (total, blocked))| (qname, total, blocked))
        .collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items.truncate(limit);
    items
}

fn merge_blocked_domains(
    existing: Vec<(String, i64)>,
    incoming: Vec<(String, i64)>,
    limit: usize,
) -> Vec<(String, i64)> {
    let mut merged: HashMap<String, i64> = HashMap::new();
    for (qname, blocked) in existing.into_iter().chain(incoming) {
        let entry = merged.entry(qname).or_insert(0);
        *entry = entry.saturating_add(blocked);
    }
    let mut items: Vec<(String, i64)> = merged.into_iter().collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items.truncate(limit);
    items
}

fn merge_client_tops(
    existing: Vec<ClientTop>,
    incoming: Vec<ClientTop>,
    limit: usize,
) -> Vec<ClientTop> {
    let mut merged: HashMap<String, (Option<String>, i64, i64, i64)> = HashMap::new();
    for (ip, name, total, blocked, last_seen) in existing.into_iter().chain(incoming) {
        let entry = merged.entry(ip).or_insert((None, 0, 0, 0));
        keep_max_name(&mut entry.0, name);
        entry.1 = entry.1.saturating_add(total);
        entry.2 = entry.2.saturating_add(blocked);
        entry.3 = entry.3.max(last_seen);
    }
    let mut items: Vec<ClientTop> = merged
        .into_iter()
        .map(|(ip, (name, total, blocked, last_seen))| (ip, name, total, blocked, last_seen))
        .collect();
    items.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    items.truncate(limit);
    items
}

fn merge_upstream_tops(
    existing: Vec<UpstreamTop>,
    incoming: Vec<UpstreamTop>,
    limit: usize,
) -> Vec<UpstreamTop> {
    let mut merged: HashMap<String, (i64, i64, i64)> = HashMap::new();
    for (upstream, total, errors, elapsed_sum) in existing.into_iter().chain(incoming) {
        let entry = merged.entry(upstream).or_insert((0, 0, 0));
        entry.0 = entry.0.saturating_add(total);
        entry.1 = entry.1.saturating_add(errors);
        entry.2 = entry.2.saturating_add(elapsed_sum);
    }
    let mut items: Vec<UpstreamTop> = merged
        .into_iter()
        .map(|(upstream, (total, errors, elapsed_sum))| (upstream, total, errors, elapsed_sum))
        .collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items.truncate(limit);
    items
}

/// Query log filter parameters for pagination and search.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct QueryLogFilter {
    pub client: Option<String>,
    pub domain: Option<String>,
    pub status: Option<String>,
    pub qtype: Option<u16>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub cursor: Option<i64>,
    pub limit: Option<usize>,
    /// Whether to run the `COUNT(*)` used for `total_count`. Defaults to
    /// `true` for API compatibility; the live UI refresh sets it to `false`
    /// so the 3 s poll does not scan the filtered table.
    pub include_total: Option<bool>,
}

/// Paginated page of query logs.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct QueryLogPage {
    pub entries: Vec<QueryLogEntry>,
    pub next_cursor: Option<String>,
    pub total_count: Option<i64>,
}

/// Aggregated global statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct GlobalStats {
    pub total_queries: i64,
    pub blocked_queries: i64,
    pub cached_queries: i64,
    pub blocked_percentage: f64,
    pub top_domains: Vec<(String, i64)>,
    pub top_blocked_domains: Vec<(String, i64)>,
    pub top_clients: Vec<(String, i64)>,
}

/// Aggregated statistics per client.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClientStats {
    pub client_ip: String,
    pub client_name: Option<String>,
    pub total_queries: i64,
    pub blocked_queries: i64,
    pub last_seen: i64,
}

/// Aggregated statistics per upstream resolver.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpstreamStats {
    pub upstream: String,
    pub total_queries: i64,
    pub error_queries: i64,
    pub avg_elapsed_us: i64,
    pub share_percentage: f64,
}

/// Retention pruning report.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct RetentionReport {
    /// Hourly buckets folded into `stats_hourly` by this sweep.
    pub aggregated_hours: usize,
    /// Detailed query-log rows deleted by this sweep.
    pub deleted_records: u64,
    /// Expired `stats_hourly` rows deleted by rollup retention.
    #[serde(default)]
    pub rollup_deleted_records: u64,
    /// Number of short retention transactions/batches committed.
    #[serde(default)]
    pub chunks: usize,
}

/// Cached dashboard aggregates. Each entry is keyed by the requested window
/// and expires after [`DASHBOARD_CACHE_TTL`].
#[derive(Default)]
struct StatsCache {
    global: Mutex<Option<CachedGlobal>>,
    hourly: Mutex<Option<CachedHourly>>,
    upstream: Mutex<Option<CachedUpstream>>,
}

struct CachedGlobal {
    window_ms: i64,
    at: Instant,
    value: GlobalStats,
}

struct CachedHourly {
    hours: u32,
    at: Instant,
    value: Vec<HourlyActivity>,
}

struct CachedUpstream {
    window_ms: i64,
    at: Instant,
    value: Vec<UpstreamStats>,
}

/// SQLite database client managing WAL connections, migrations, and queries.
#[derive(Clone)]
pub struct StatsDb {
    pool: Pool<Sqlite>,
    db_path: Option<PathBuf>,
    /// Per-install key for hashing rollup client identifiers.
    salt: Arc<[u8; 32]>,
    /// Default policy used by the compatibility retention wrapper and
    /// one-time rollup backfill.
    rollup_client_names: bool,
    cache: Arc<StatsCache>,
}

/// Builds the shared `query_log` filter predicate used by both the page query
/// and the `total_count` query. Cursor pagination and `LIMIT` are deliberately
/// not part of this predicate.
fn filtered_query(base: &str, filter: &QueryLogFilter) -> sqlx::QueryBuilder<Sqlite> {
    let mut builder = sqlx::QueryBuilder::new(base);

    if let Some(from) = filter.from {
        builder.push(" AND ts >= ");
        builder.push_bind(from);
    }
    if let Some(to) = filter.to {
        builder.push(" AND ts <= ");
        builder.push_bind(to);
    }
    if let Some(ref status) = filter.status {
        builder.push(" AND verdict = ");
        builder.push_bind(status);
    }
    if let Some(qtype) = filter.qtype {
        builder.push(" AND qtype = ");
        builder.push_bind(i64::from(qtype));
    }
    if let Some(ref client) = filter.client {
        builder.push(" AND (client_ip = ");
        builder.push_bind(client);
        builder.push(" OR client_name = ");
        builder.push_bind(client);
        builder.push(")");
    }
    if let Some(ref domain) = filter.domain {
        builder.push(" AND qname LIKE ");
        let escaped = domain
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{escaped}%");
        builder.push_bind(pattern);
        builder.push(" ESCAPE '\\'");
    }

    builder
}

/// Existing `stats_hourly` top lists for the hours being rolled up again:
/// `hour -> (top_domains, top_clients, top_upstreams)`.
type ExistingRollups = HashMap<i64, (Option<String>, Option<String>, Option<String>)>;

/// Extracts bounded per-hour top lists for the rows in `[start, end)` and
/// `[id_start, id_end]` inside the retention transaction.
async fn collect_hour_rollups(
    conn: &mut SqliteConnection,
    start: i64,
    end: i64,
    id_start: i64,
    id_end: i64,
    rollups: &mut HashMap<i64, HourRollup>,
) -> Result<(), StatsError> {
    let limit = i64::try_from(ROLLUP_TOP_N).unwrap_or(100);

    // Domains: union of the top-N by total and by blocked count, so both
    // `top_domains` and `top_blocked_domains` stay representative after the
    // per-hour lists are merged.
    let domain_rows = sqlx::query(
        r"
        SELECT hour, qname, total, blocked FROM (
            SELECT
                (ts / 3600000) * 3600000 AS hour,
                qname,
                COUNT(*) AS total,
                SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) AS blocked,
                ROW_NUMBER() OVER (
                    PARTITION BY (ts / 3600000) * 3600000
                    ORDER BY COUNT(*) DESC, qname ASC
                ) AS rn_total,
                ROW_NUMBER() OVER (
                    PARTITION BY (ts / 3600000) * 3600000
                    ORDER BY SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) DESC, qname ASC
                ) AS rn_blocked
            FROM query_log
            WHERE ts >= ? AND ts < ? AND id >= ? AND id <= ?
            GROUP BY (ts / 3600000) * 3600000, qname
        )
        WHERE rn_total <= ? OR rn_blocked <= ?
        ",
    )
    .bind(start)
    .bind(end)
    .bind(id_start)
    .bind(id_end)
    .bind(limit)
    .bind(limit)
    .fetch_all(&mut *conn)
    .await?;

    for row in domain_rows {
        let hour: i64 = row.get("hour");
        rollups.entry(hour).or_default().domains.push((
            row.get::<String, _>("qname"),
            row.get::<Option<i64>, _>("total").unwrap_or(0),
            row.get::<Option<i64>, _>("blocked").unwrap_or(0),
        ));
    }

    // Clients: top-N by total with a deterministic name per IP.
    let client_rows = sqlx::query(
        r"
        SELECT hour, client_ip, client_name, total, blocked, last_seen FROM (
            SELECT
                (ts / 3600000) * 3600000 AS hour,
                client_ip,
                MAX(client_name) AS client_name,
                COUNT(*) AS total,
                SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) AS blocked,
                MAX(ts) AS last_seen,
                ROW_NUMBER() OVER (
                    PARTITION BY (ts / 3600000) * 3600000
                    ORDER BY COUNT(*) DESC, client_ip ASC
                ) AS rn
            FROM query_log
            WHERE ts >= ? AND ts < ? AND id >= ? AND id <= ?
            GROUP BY (ts / 3600000) * 3600000, client_ip
        )
        WHERE rn <= ?
        ",
    )
    .bind(start)
    .bind(end)
    .bind(id_start)
    .bind(id_end)
    .bind(limit)
    .fetch_all(&mut *conn)
    .await?;

    for row in client_rows {
        let hour: i64 = row.get("hour");
        rollups.entry(hour).or_default().clients.push((
            row.get::<String, _>("client_ip"),
            row.get::<Option<String>, _>("client_name"),
            row.get::<Option<i64>, _>("total").unwrap_or(0),
            row.get::<Option<i64>, _>("blocked").unwrap_or(0),
            row.get::<Option<i64>, _>("last_seen").unwrap_or(0),
        ));
    }

    // Upstreams: top-N by total.
    let upstream_rows = sqlx::query(
        r"
        SELECT hour, upstream, total, errors, elapsed_sum FROM (
            SELECT
                (ts / 3600000) * 3600000 AS hour,
                upstream,
                COUNT(*) AS total,
                SUM(CASE WHEN rcode IS NOT NULL AND rcode != 0 THEN 1 ELSE 0 END) AS errors,
                SUM(COALESCE(elapsed_us, 0)) AS elapsed_sum,
                ROW_NUMBER() OVER (
                    PARTITION BY (ts / 3600000) * 3600000
                    ORDER BY COUNT(*) DESC, upstream ASC
                ) AS rn
            FROM query_log
            WHERE ts >= ? AND ts < ? AND id >= ? AND id <= ? AND upstream IS NOT NULL
            GROUP BY (ts / 3600000) * 3600000, upstream
        )
        WHERE rn <= ?
        ",
    )
    .bind(start)
    .bind(end)
    .bind(id_start)
    .bind(id_end)
    .bind(limit)
    .fetch_all(&mut *conn)
    .await?;

    for row in upstream_rows {
        let hour: i64 = row.get("hour");
        rollups.entry(hour).or_default().upstreams.push((
            row.get::<String, _>("upstream"),
            row.get::<Option<i64>, _>("total").unwrap_or(0),
            row.get::<Option<i64>, _>("errors").unwrap_or(0),
            row.get::<Option<i64>, _>("elapsed_sum").unwrap_or(0),
        ));
    }

    Ok(())
}

/// Loads the already-stored top lists for the hours being rolled up. Queries
/// are chunked so a very long retention period cannot exceed SQLite's bound
/// variable limit.
async fn load_existing_rollups(
    conn: &mut SqliteConnection,
    hours: &[i64],
) -> Result<ExistingRollups, StatsError> {
    /// Hours per `IN (...)` statement.
    const HOURS_PER_QUERY: usize = 500;

    let mut existing = ExistingRollups::new();
    for chunk in hours.chunks(HOURS_PER_QUERY) {
        let mut builder = sqlx::QueryBuilder::new(
            "SELECT hour, top_domains, top_clients, top_upstreams FROM stats_hourly WHERE hour IN (",
        );
        {
            let mut separated = builder.separated(", ");
            for hour in chunk {
                separated.push_bind(*hour);
            }
            separated.push_unseparated(")");
        }

        for row in builder.build().fetch_all(&mut *conn).await? {
            existing.insert(
                row.get("hour"),
                (
                    row.get("top_domains"),
                    row.get("top_clients"),
                    row.get("top_upstreams"),
                ),
            );
        }
    }

    Ok(existing)
}

fn random_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::rng().fill(&mut salt);
    salt
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), StatsError> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(_) => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), StatsError> {
    Ok(())
}

/// Creates the database file with mode 0600 before SQLite opens it, and
/// repairs an existing file. Symlinks are refused so a hostile data directory
/// cannot redirect writes outside it.
fn ensure_private_db_file(path: &Path) -> Result<(), StatsError> {
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(StatsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to use symlinked stats database '{}'",
                path.display()
            ),
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                set_private_permissions(path)
            }
            Err(e) => Err(e.into()),
        }
    }
    #[cfg(not(unix))]
    {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Loads the per-install 32-byte salt, creating it atomically with mode 0600
/// when it does not exist. A short/corrupt salt is a hard error: regenerating
/// it would silently change every stored rollup hash.
fn load_or_create_salt(directory: &Path) -> Result<[u8; 32], StatsError> {
    use std::io::Write;

    let path = directory.join(SALT_FILE_NAME);
    std::fs::create_dir_all(directory)?;
    if let Ok(meta) = std::fs::symlink_metadata(&path)
        && meta.file_type().is_symlink()
    {
        return Err(StatsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to use symlinked stats salt '{}'", path.display()),
        )));
    }

    #[cfg(unix)]
    let mut options = {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.mode(0o600);
        options
    };
    #[cfg(not(unix))]
    let mut options = std::fs::OpenOptions::new();

    match options.write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            let salt = random_salt();
            file.write_all(&salt)?;
            file.sync_all()?;
            set_private_permissions(&path)?;
            Ok(salt)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Repair permissions on an existing file before reading it.
            set_private_permissions(&path)?;
            let bytes = std::fs::read(&path)?;
            let salt: [u8; 32] = bytes.try_into().map_err(|_| {
                StatsError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "stats salt '{}' must contain exactly 32 bytes",
                        path.display()
                    ),
                ))
            })?;
            Ok(salt)
        }
        Err(e) => Err(e.into()),
    }
}

/// Hourly activity bucket for dashboard time-series charts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct HourlyActivity {
    pub timestamp_sec: i64,
    pub total_queries: i64,
    pub blocked_queries: i64,
}
