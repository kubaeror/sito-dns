//! SQLite database storage engine for query logging and historical statistics.

use crate::entry::QueryLogEntry;
use crate::error::StatsError;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Pool, Row, Sqlite, SqliteConnection};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use utoipa::ToSchema;

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

/// Bounded per-hour rollup payloads extracted from rows about to be pruned.
#[derive(Default)]
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
    pub aggregated_hours: usize,
    pub deleted_records: u64,
}

/// SQLite database client managing WAL connections, migrations, and queries.
#[derive(Clone)]
pub struct StatsDb {
    pool: Pool<Sqlite>,
    db_path: Option<PathBuf>,
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

/// Extracts bounded per-hour top lists for the rows below `cutoff` inside the
/// retention transaction.
async fn collect_hour_rollups(
    conn: &mut SqliteConnection,
    cutoff: i64,
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
            WHERE ts < ?
            GROUP BY (ts / 3600000) * 3600000, qname
        )
        WHERE rn_total <= ? OR rn_blocked <= ?
        ",
    )
    .bind(cutoff)
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
            WHERE ts < ?
            GROUP BY (ts / 3600000) * 3600000, client_ip
        )
        WHERE rn <= ?
        ",
    )
    .bind(cutoff)
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
            WHERE ts < ? AND upstream IS NOT NULL
            GROUP BY (ts / 3600000) * 3600000, upstream
        )
        WHERE rn <= ?
        ",
    )
    .bind(cutoff)
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

impl StatsDb {
    /// Returns a reference to the underlying SQLite connection pool.
    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }

    /// Opens or creates an in-memory SQLite database (primarily for testing).
    pub async fn in_memory() -> Result<Self, StatsError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        let db = Self {
            pool,
            db_path: None,
        };
        db.run_migrations().await?;
        Ok(db)
    }

    /// Opens or creates a SQLite database on disk in WAL mode.
    pub async fn open(db_path: impl AsRef<Path>) -> Result<Self, StatsError> {
        let path = db_path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(10));

        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .connect_with(options)
            .await?;

        let db = Self {
            pool,
            db_path: Some(path),
        };
        db.run_migrations().await?;
        Ok(db)
    }

    /// Runs embedded SQL migrations.
    pub async fn run_migrations(&self) -> Result<(), StatsError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(StatsError::Migration)?;
        Ok(())
    }

    /// Inserts a batch of query log entries within a single transaction.
    pub async fn insert_batch(&self, entries: &[QueryLogEntry]) -> Result<(), StatsError> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;

        for entry in entries {
            sqlx::query(
                r"
                INSERT INTO query_log (
                    ts, client_ip, client_name, qname, qtype, rcode,
                    verdict, rule, list_source, upstream, elapsed_us, dnssec, proto
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ",
            )
            .bind(entry.ts)
            .bind(&entry.client_ip)
            .bind(&entry.client_name)
            .bind(&entry.qname)
            .bind(i64::from(entry.qtype))
            .bind(entry.rcode.map(i64::from))
            .bind(&entry.verdict)
            .bind(&entry.rule)
            .bind(&entry.list_source)
            .bind(&entry.upstream)
            .bind(entry.elapsed_us)
            .bind(&entry.dnssec)
            .bind(&entry.proto)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Queries logs with filters and cursor-based pagination.
    pub async fn query_logs(&self, filter: &QueryLogFilter) -> Result<QueryLogPage, StatsError> {
        let limit = filter.limit.unwrap_or(50).clamp(1, 1000);
        let fetch_limit = limit + 1;

        // `total_count` counts every row matching the filters regardless of the
        // cursor, so it stays stable while paging.
        let mut count_builder = filtered_query("SELECT COUNT(*) FROM query_log WHERE 1=1", filter);
        let total_count: i64 = count_builder
            .build_query_scalar()
            .fetch_one(&self.pool)
            .await?;

        let mut builder = filtered_query(
            "SELECT id, ts, client_ip, client_name, qname, qtype, rcode, verdict, rule, list_source, upstream, elapsed_us, dnssec, proto FROM query_log WHERE 1=1",
            filter,
        );

        if let Some(cursor) = filter.cursor {
            builder.push(" AND id < ");
            builder.push_bind(cursor);
        }

        builder.push(" ORDER BY id DESC LIMIT ");
        builder.push_bind(i64::try_from(fetch_limit).unwrap_or(1001));

        let rows = builder.build().fetch_all(&self.pool).await?;

        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            let id: i64 = row.get(0);
            let ts: i64 = row.get(1);
            let client_ip: String = row.get(2);
            let client_name: Option<String> = row.get(3);
            let qname: String = row.get(4);
            let qtype_i64: i64 = row.get(5);
            let rcode_i64: Option<i64> = row.get(6);
            let verdict: String = row.get(7);
            let rule: Option<String> = row.get(8);
            let list_source: Option<String> = row.get(9);
            let upstream: Option<String> = row.get(10);
            let elapsed_us: Option<i64> = row.get(11);
            let dnssec: Option<String> = row.get(12);
            let proto: String = row.get(13);

            entries.push(QueryLogEntry {
                id: Some(id),
                ts,
                client_ip,
                client_name,
                qname,
                qtype: qtype_i64 as u16,
                rcode: rcode_i64.map(|c| c as u8),
                verdict,
                rule,
                list_source,
                upstream,
                elapsed_us,
                dnssec,
                proto,
            });
        }

        let next_cursor = if entries.len() > limit {
            entries.truncate(limit);
            entries.last().and_then(|e| e.id).map(|id| id.to_string())
        } else {
            None
        };

        Ok(QueryLogPage {
            entries,
            next_cursor,
            total_count: Some(total_count),
        })
    }

    /// Deletes all entries from the query log after folding them into the
    /// hourly rollups, so clearing the log does not silently reset the
    /// statistics totals.
    pub async fn delete_query_logs(&self) -> Result<u64, StatsError> {
        let report = self.rollup_and_delete(i64::MAX).await?;
        Ok(report.deleted_records)
    }

    /// Computes global aggregates for a specified time window in milliseconds.
    ///
    /// Rows pruned by retention are served from the `stats_hourly` rollups, so
    /// windows longer than the detailed retention period still report totals
    /// and top lists instead of silently under-reporting. Rollup top lists are
    /// bounded summaries (`ROLLUP_TOP_N` per hour), so the merged top-10 is
    /// exact for retained data and representative for older windows.
    pub async fn get_global_stats(&self, window_ms: i64) -> Result<GlobalStats, StatsError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let cutoff = now_ms.saturating_sub(window_ms);

        let row = sqlx::query(
            r"
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN rule IN ('cache', 'stale_cache') OR verdict = 'stale' THEN 1 ELSE 0 END) as cached
            FROM query_log
            WHERE ts >= ?
            ",
        )
        .bind(cutoff)
        .fetch_one(&self.pool)
        .await?;

        let mut total_queries: i64 = row.get::<Option<i64>, _>("total").unwrap_or(0);
        let mut blocked_queries: i64 = row.get::<Option<i64>, _>("blocked").unwrap_or(0);
        let mut cached_queries: i64 = row.get::<Option<i64>, _>("cached").unwrap_or(0);

        // Merge the hourly rollups whose bucket overlaps the window. Rollup
        // buckets and live rows are disjoint (pruned rows are deleted), so the
        // two sources can be summed even for a partially-pruned hour.
        let archived = sqlx::query(
            r"
            SELECT
                COALESCE(SUM(queries), 0) as total,
                COALESCE(SUM(blocked), 0) as blocked,
                COALESCE(SUM(cached), 0) as cached
            FROM stats_hourly
            WHERE hour + 3600000 > ?
            ",
        )
        .bind(cutoff)
        .fetch_one(&self.pool)
        .await?;
        total_queries = total_queries.saturating_add(archived.get::<i64, _>("total"));
        blocked_queries = blocked_queries.saturating_add(archived.get::<i64, _>("blocked"));
        cached_queries = cached_queries.saturating_add(archived.get::<i64, _>("cached"));

        let blocked_percentage = if total_queries > 0 {
            (blocked_queries as f64 / total_queries as f64) * 100.0
        } else {
            0.0
        };

        // Top lists: merge the live top-N with the archived top-N lists so a
        // window longer than the detailed retention still reports the largest
        // domains and clients instead of only the retained tail.
        let merged_domains = merge_domain_tops(
            self.live_domain_tops(cutoff, ROLLUP_TOP_N).await?,
            self.archived_domain_tops(cutoff).await?,
            ROLLUP_TOP_N,
        );

        let mut top_domains: Vec<(String, i64)> = merged_domains
            .iter()
            .map(|(qname, total, _)| (qname.clone(), *total))
            .collect();
        top_domains.truncate(10);

        // Blocked domains are ranked separately so a heavily blocked domain is
        // not dropped just because it ranks below the total-query top-N.
        let mut top_blocked_domains = merge_blocked_domains(
            self.live_blocked_domain_tops(cutoff, ROLLUP_TOP_N).await?,
            self.archived_blocked_domain_tops(cutoff).await?,
            ROLLUP_TOP_N,
        );
        top_blocked_domains.truncate(10);

        let mut top_clients_by_label: HashMap<String, i64> = HashMap::new();
        for (ip, name, total, _, _) in merge_client_tops(
            self.live_client_tops(cutoff, ROLLUP_TOP_N).await?,
            self.archived_client_tops(cutoff).await?,
            ROLLUP_TOP_N,
        ) {
            let label = name.unwrap_or(ip);
            let entry = top_clients_by_label.entry(label).or_insert(0);
            *entry = entry.saturating_add(total);
        }
        let mut top_clients: Vec<(String, i64)> = top_clients_by_label.into_iter().collect();
        top_clients.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top_clients.truncate(10);

        Ok(GlobalStats {
            total_queries,
            blocked_queries,
            cached_queries,
            blocked_percentage,
            top_domains,
            top_blocked_domains,
            top_clients,
        })
    }

    /// Computes per-client statistics, bounded to [`MAX_AGGREGATE_ROWS`] rows
    /// with a deterministic ordering (largest total first, then IP) and a
    /// deterministic `client_name` (`MAX(client_name)` when an address was
    /// seen under several names). Rows pruned by retention are merged back in
    /// from the hourly rollups.
    pub async fn get_client_stats(&self, window_ms: i64) -> Result<Vec<ClientStats>, StatsError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let cutoff = now_ms.saturating_sub(window_ms);

        let merged = merge_client_tops(
            self.live_client_tops(cutoff, MAX_AGGREGATE_ROWS).await?,
            self.archived_client_tops(cutoff).await?,
            MAX_AGGREGATE_ROWS,
        );

        Ok(merged
            .into_iter()
            .map(
                |(client_ip, client_name, total_queries, blocked_queries, last_seen)| ClientStats {
                    client_ip,
                    client_name,
                    total_queries,
                    blocked_queries,
                    last_seen,
                },
            )
            .collect())
    }

    /// Number of distinct clients seen in the window, including archived
    /// hourly rollups. Used for the `X-Total-Count` response header so callers
    /// can tell when [`MAX_AGGREGATE_ROWS`] truncated the list.
    ///
    /// Archived rollups keep at most `ROLLUP_TOP_N` clients per hour, so the
    /// count is exact for retained data and a lower bound for older windows.
    pub async fn count_client_stats(&self, window_ms: i64) -> Result<i64, StatsError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let cutoff = now_ms.saturating_sub(window_ms);

        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM (
                SELECT client_ip FROM query_log WHERE ts >= ?
                UNION
                SELECT je.value ->> 0
                FROM stats_hourly, json_each(COALESCE(stats_hourly.top_clients, '[]')) AS je
                WHERE stats_hourly.hour + 3600000 > ?
            )
            ",
        )
        .bind(cutoff)
        .bind(cutoff)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    /// Computes per-upstream statistics, bounded to [`MAX_AGGREGATE_ROWS`]
    /// rows with a deterministic ordering (largest total first, then name).
    /// Rows pruned by retention are merged back in from the hourly rollups.
    pub async fn get_upstream_stats(
        &self,
        window_ms: i64,
    ) -> Result<Vec<UpstreamStats>, StatsError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let cutoff = now_ms.saturating_sub(window_ms);

        let merged = merge_upstream_tops(
            self.live_upstream_tops(cutoff, MAX_AGGREGATE_ROWS).await?,
            self.archived_upstream_tops(cutoff).await?,
            MAX_AGGREGATE_ROWS,
        );

        let total_all: i64 = merged.iter().map(|(_, total, _, _)| *total).sum();

        Ok(merged
            .into_iter()
            .map(|(upstream, total_queries, error_queries, elapsed_sum)| {
                let avg_elapsed_us = if total_queries > 0 {
                    elapsed_sum / total_queries
                } else {
                    0
                };
                let share_percentage = if total_all > 0 {
                    (total_queries as f64 / total_all as f64) * 100.0
                } else {
                    0.0
                };

                UpstreamStats {
                    upstream,
                    total_queries,
                    error_queries,
                    avg_elapsed_us,
                    share_percentage,
                }
            })
            .collect())
    }

    /// Number of distinct upstreams seen in the window, including archived
    /// hourly rollups. Used for the `X-Total-Count` response header.
    pub async fn count_upstream_stats(&self, window_ms: i64) -> Result<i64, StatsError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let cutoff = now_ms.saturating_sub(window_ms);

        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM (
                SELECT upstream FROM query_log WHERE ts >= ? AND upstream IS NOT NULL
                UNION
                SELECT je.value ->> 0
                FROM stats_hourly, json_each(COALESCE(stats_hourly.top_upstreams, '[]')) AS je
                WHERE stats_hourly.hour + 3600000 > ?
            )
            ",
        )
        .bind(cutoff)
        .bind(cutoff)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    /// Live top domains inside the window, ordered deterministically.
    async fn live_domain_tops(
        &self,
        cutoff: i64,
        limit: usize,
    ) -> Result<Vec<DomainTop>, StatsError> {
        let rows = sqlx::query(
            r"
            SELECT qname,
                   COUNT(*) as total,
                   SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) as blocked
            FROM query_log
            WHERE ts >= ?
            GROUP BY qname
            ORDER BY total DESC, qname ASC
            LIMIT ?
            ",
        )
        .bind(cutoff)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("qname"),
                    r.get::<Option<i64>, _>("total").unwrap_or(0),
                    r.get::<Option<i64>, _>("blocked").unwrap_or(0),
                )
            })
            .collect())
    }

    /// Live top blocked domains inside the window, ranked by blocked count.
    async fn live_blocked_domain_tops(
        &self,
        cutoff: i64,
        limit: usize,
    ) -> Result<Vec<(String, i64)>, StatsError> {
        let rows = sqlx::query(
            r"
            SELECT qname,
                   COUNT(*) as blocked
            FROM query_log
            WHERE ts >= ? AND verdict = 'blocked'
            GROUP BY qname
            ORDER BY blocked DESC, qname ASC
            LIMIT ?
            ",
        )
        .bind(cutoff)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("qname"),
                    r.get::<Option<i64>, _>("blocked").unwrap_or(0),
                )
            })
            .collect())
    }

    /// Archived top domains from `stats_hourly` buckets overlapping the window.
    async fn archived_domain_tops(&self, cutoff: i64) -> Result<Vec<DomainTop>, StatsError> {
        let rows = sqlx::query(
            r"
            SELECT je.value ->> 0 AS qname,
                   SUM(CAST(je.value ->> 1 AS INTEGER)) AS total,
                   SUM(CAST(je.value ->> 2 AS INTEGER)) AS blocked
            FROM stats_hourly, json_each(COALESCE(stats_hourly.top_domains, '[]')) AS je
            WHERE stats_hourly.hour + 3600000 > ?
            GROUP BY qname
            ORDER BY total DESC, qname ASC
            LIMIT ?
            ",
        )
        .bind(cutoff)
        .bind(i64::try_from(ROLLUP_TOP_N).unwrap_or(100))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("qname"),
                    r.get::<Option<i64>, _>("total").unwrap_or(0),
                    r.get::<Option<i64>, _>("blocked").unwrap_or(0),
                )
            })
            .collect())
    }

    /// Archived top blocked domains from `stats_hourly` buckets overlapping the
    /// window, ranked by blocked count.
    async fn archived_blocked_domain_tops(
        &self,
        cutoff: i64,
    ) -> Result<Vec<(String, i64)>, StatsError> {
        let rows = sqlx::query(
            r"
            SELECT je.value ->> 0 AS qname,
                   SUM(CAST(je.value ->> 2 AS INTEGER)) AS blocked
            FROM stats_hourly, json_each(COALESCE(stats_hourly.top_domains, '[]')) AS je
            WHERE stats_hourly.hour + 3600000 > ?
            GROUP BY qname
            HAVING SUM(CAST(je.value ->> 2 AS INTEGER)) > 0
            ORDER BY blocked DESC, qname ASC
            LIMIT ?
            ",
        )
        .bind(cutoff)
        .bind(i64::try_from(ROLLUP_TOP_N).unwrap_or(100))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("qname"),
                    r.get::<Option<i64>, _>("blocked").unwrap_or(0),
                )
            })
            .collect())
    }

    /// Live per-client aggregates inside the window, ordered deterministically.
    async fn live_client_tops(
        &self,
        cutoff: i64,
        limit: usize,
    ) -> Result<Vec<ClientTop>, StatsError> {
        let rows = sqlx::query(
            r"
            SELECT client_ip,
                   MAX(client_name) as client_name,
                   COUNT(*) as total,
                   SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) as blocked,
                   MAX(ts) as last_seen
            FROM query_log
            WHERE ts >= ?
            GROUP BY client_ip
            ORDER BY total DESC, client_ip ASC
            LIMIT ?
            ",
        )
        .bind(cutoff)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("client_ip"),
                    r.get::<Option<String>, _>("client_name"),
                    r.get::<Option<i64>, _>("total").unwrap_or(0),
                    r.get::<Option<i64>, _>("blocked").unwrap_or(0),
                    r.get::<Option<i64>, _>("last_seen").unwrap_or(0),
                )
            })
            .collect())
    }

    /// Archived per-client aggregates from `stats_hourly` buckets overlapping
    /// the window.
    async fn archived_client_tops(&self, cutoff: i64) -> Result<Vec<ClientTop>, StatsError> {
        let rows = sqlx::query(
            r"
            SELECT je.value ->> 0 AS client_ip,
                   MAX(NULLIF(je.value ->> 1, '')) AS client_name,
                   SUM(CAST(je.value ->> 2 AS INTEGER)) AS total,
                   SUM(CAST(je.value ->> 3 AS INTEGER)) AS blocked,
                   MAX(CAST(je.value ->> 4 AS INTEGER)) AS last_seen
            FROM stats_hourly, json_each(COALESCE(stats_hourly.top_clients, '[]')) AS je
            WHERE stats_hourly.hour + 3600000 > ?
            GROUP BY client_ip
            ORDER BY total DESC, client_ip ASC
            LIMIT ?
            ",
        )
        .bind(cutoff)
        .bind(i64::try_from(MAX_AGGREGATE_ROWS).unwrap_or(1000))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("client_ip"),
                    r.get::<Option<String>, _>("client_name"),
                    r.get::<Option<i64>, _>("total").unwrap_or(0),
                    r.get::<Option<i64>, _>("blocked").unwrap_or(0),
                    r.get::<Option<i64>, _>("last_seen").unwrap_or(0),
                )
            })
            .collect())
    }

    /// Live per-upstream aggregates inside the window, ordered deterministically.
    async fn live_upstream_tops(
        &self,
        cutoff: i64,
        limit: usize,
    ) -> Result<Vec<UpstreamTop>, StatsError> {
        let rows = sqlx::query(
            r"
            SELECT upstream,
                   COUNT(*) as total,
                   SUM(CASE WHEN rcode IS NOT NULL AND rcode != 0 THEN 1 ELSE 0 END) as errors,
                   SUM(COALESCE(elapsed_us, 0)) as elapsed_sum
            FROM query_log
            WHERE ts >= ? AND upstream IS NOT NULL
            GROUP BY upstream
            ORDER BY total DESC, upstream ASC
            LIMIT ?
            ",
        )
        .bind(cutoff)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("upstream"),
                    r.get::<Option<i64>, _>("total").unwrap_or(0),
                    r.get::<Option<i64>, _>("errors").unwrap_or(0),
                    r.get::<Option<i64>, _>("elapsed_sum").unwrap_or(0),
                )
            })
            .collect())
    }

    /// Archived per-upstream aggregates from `stats_hourly` buckets overlapping
    /// the window.
    async fn archived_upstream_tops(&self, cutoff: i64) -> Result<Vec<UpstreamTop>, StatsError> {
        let rows = sqlx::query(
            r"
            SELECT je.value ->> 0 AS upstream,
                   SUM(CAST(je.value ->> 1 AS INTEGER)) AS total,
                   SUM(CAST(je.value ->> 2 AS INTEGER)) AS errors,
                   SUM(CAST(je.value ->> 3 AS INTEGER)) AS elapsed_sum
            FROM stats_hourly, json_each(COALESCE(stats_hourly.top_upstreams, '[]')) AS je
            WHERE stats_hourly.hour + 3600000 > ?
            GROUP BY upstream
            ORDER BY total DESC, upstream ASC
            LIMIT ?
            ",
        )
        .bind(cutoff)
        .bind(i64::try_from(MAX_AGGREGATE_ROWS).unwrap_or(1000))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("upstream"),
                    r.get::<Option<i64>, _>("total").unwrap_or(0),
                    r.get::<Option<i64>, _>("errors").unwrap_or(0),
                    r.get::<Option<i64>, _>("elapsed_sum").unwrap_or(0),
                )
            })
            .collect())
    }

    /// Aggregates older logs into `stats_hourly` and prunes query logs older
    /// than the retention period.
    ///
    /// The aggregate read, the rollup upsert, the watermark update and the
    /// delete all run in a single `BEGIN IMMEDIATE` transaction. Producers
    /// cannot interleave a (possibly backdated) insert between the read and the
    /// delete, so no pruned row can be deleted without being aggregated.
    /// Because deleted rows no longer exist, the watermark is not used to skip
    /// rows: every row below the cutoff is aggregated exactly once.
    ///
    /// After a sweep that removed at least [`VACUUM_MIN_DELETED_ROWS`] rows the
    /// database is vacuumed, so pages freed by retention are returned to the OS
    /// instead of growing the file forever.
    pub async fn cleanup_retention(
        &self,
        retention_days: u32,
    ) -> Result<RetentionReport, StatsError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let retention_ms = i64::from(retention_days) * 24 * 3600 * 1000;
        let cutoff = now_ms.saturating_sub(retention_ms);

        let report = self.rollup_and_delete(cutoff).await?;

        if report.deleted_records >= VACUUM_MIN_DELETED_ROWS
            && let Err(e) = self.vacuum().await
        {
            // Rollup and delete already committed; a failed compaction must not
            // make the sweep look failed or lose the report.
            tracing::warn!(error = %e, "stats retention vacuum failed");
        }

        Ok(report)
    }

    /// Folds every row below `cutoff` into `stats_hourly` and deletes exactly
    /// those rows in one transaction. [`Self::delete_query_logs`] reuses it with
    /// `cutoff = i64::MAX` so clearing the log preserves aggregate history.
    async fn rollup_and_delete(&self, cutoff: i64) -> Result<RetentionReport, StatsError> {
        // `BEGIN IMMEDIATE` takes the write lock up front so concurrent writers
        // wait instead of failing the aggregate/delete with `SQLITE_BUSY`.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

        // Aggregate hourly buckets for every entry below the cutoff. The
        // previous implementation filtered by `id > watermark_id`, which lost
        // rows whose timestamp (and therefore id order) was inverted by
        // concurrent producers. Aggregating and deleting the exact same
        // predicate inside one transaction makes ordering irrelevant.
        let hours_to_aggregate = sqlx::query(
            r"
            SELECT
                (ts / 3600000) * 3600000 as hour,
                COUNT(*) as queries,
                SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN rule IN ('cache', 'stale_cache') OR verdict = 'stale' THEN 1 ELSE 0 END) as cached,
                MAX(id) as max_id,
                MAX(ts) as max_ts
            FROM query_log
            WHERE ts < ?
            GROUP BY hour
            ",
        )
        .bind(cutoff)
        .fetch_all(&mut *tx)
        .await?;

        let affected_hours: Vec<i64> = hours_to_aggregate
            .iter()
            .map(|row| row.get("hour"))
            .collect();
        let mut rollups: HashMap<i64, HourRollup> = HashMap::new();
        if !affected_hours.is_empty() {
            collect_hour_rollups(&mut tx, cutoff, &mut rollups).await?;
        }
        let existing_rollups = load_existing_rollups(&mut tx, &affected_hours).await?;

        let mut aggregated_hours = 0;
        let mut max_seen_id = 0i64;
        let mut max_seen_ts = 0i64;

        for row in hours_to_aggregate {
            let hour: i64 = row.get("hour");
            let queries: i64 = row.get::<Option<i64>, _>("queries").unwrap_or(0);
            let blocked: i64 = row.get::<Option<i64>, _>("blocked").unwrap_or(0);
            let cached: i64 = row.get::<Option<i64>, _>("cached").unwrap_or(0);
            if let Some(mid) = row.get::<Option<i64>, _>("max_id") {
                max_seen_id = max_seen_id.max(mid);
            }
            if let Some(mts) = row.get::<Option<i64>, _>("max_ts") {
                max_seen_ts = max_seen_ts.max(mts);
            }

            // Merge the new top lists into the ones already stored for this
            // hour: a partially-pruned hour can be rolled up again later.
            let mut rollup = rollups.remove(&hour).unwrap_or_default();
            let (existing_domains, existing_clients, existing_upstreams) =
                existing_rollups.get(&hour).cloned().unwrap_or_default();
            rollup.domains = merge_domain_tops(
                decode_tops(existing_domains.as_deref()),
                rollup.domains,
                // Keep room for the union of the top-N by total and by blocked
                // count, so a blocked-heavy domain survives the rollup even
                // when it ranks below the total-query top-N.
                ROLLUP_TOP_N * 2,
            );
            rollup.clients = merge_client_tops(
                decode_tops(existing_clients.as_deref()),
                rollup.clients,
                ROLLUP_TOP_N,
            );
            rollup.upstreams = merge_upstream_tops(
                decode_tops(existing_upstreams.as_deref()),
                rollup.upstreams,
                ROLLUP_TOP_N,
            );

            sqlx::query(
                r"
                INSERT INTO stats_hourly (hour, queries, blocked, cached, top_domains, top_clients, top_upstreams)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hour) DO UPDATE SET
                    queries = queries + excluded.queries,
                    blocked = blocked + excluded.blocked,
                    cached = cached + excluded.cached,
                    top_domains = excluded.top_domains,
                    top_clients = excluded.top_clients,
                    top_upstreams = excluded.top_upstreams
                ",
            )
            .bind(hour)
            .bind(queries)
            .bind(blocked)
            .bind(cached)
            .bind(encode_tops(&rollup.domains))
            .bind(encode_tops(&rollup.clients))
            .bind(encode_tops(&rollup.upstreams))
            .execute(&mut *tx)
            .await?;

            aggregated_hours += 1;
        }

        // Delete exactly the rows that were aggregated above (same predicate in
        // the same transaction).
        let del_res = sqlx::query("DELETE FROM query_log WHERE ts < ?")
            .bind(cutoff)
            .execute(&mut *tx)
            .await?;

        // Record the highest timestamp/id processed for observability. The
        // watermark is informational now that aggregation and deletion share a
        // transaction; `MAX` keeps it monotonic across runs.
        if max_seen_ts > 0 || max_seen_id > 0 {
            sqlx::query(
                r"
                INSERT INTO stats_watermark (key, last_id, last_ts)
                VALUES ('hourly_aggregation', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    last_id = MAX(stats_watermark.last_id, excluded.last_id),
                    last_ts = MAX(stats_watermark.last_ts, excluded.last_ts)
                ",
            )
            .bind(max_seen_id)
            .bind(max_seen_ts)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(RetentionReport {
            aggregated_hours,
            deleted_records: del_res.rows_affected(),
        })
    }

    /// Triggers SQLite `VACUUM` and truncates the WAL so the compacted file
    /// size is immediately visible on disk (WAL mode otherwise keeps the freed
    /// pages in the sidecar file).
    pub async fn vacuum(&self) -> Result<(), StatsError> {
        sqlx::query("VACUUM").execute(&self.pool).await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Returns the database file size in bytes if stored on disk.
    ///
    /// WAL mode keeps recent writes in `<db>-wal` and index metadata in
    /// `<db>-shm`; both count towards the on-disk footprint and are included.
    pub async fn db_size_bytes(&self) -> Result<u64, StatsError> {
        let Some(ref path) = self.db_path else {
            return Ok(0);
        };

        let mut total = 0u64;
        for suffix in ["", "-wal", "-shm"] {
            let mut candidate = path.as_os_str().to_os_string();
            candidate.push(suffix);
            match tokio::fs::metadata(PathBuf::from(candidate)).await {
                Ok(meta) => total = total.saturating_add(meta.len()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(StatsError::Io(e)),
            }
        }
        Ok(total)
    }

    /// Returns aggregated activity for the last N hours bucketed by hour.
    pub async fn get_hourly_activity(&self, hours: u32) -> Result<Vec<HourlyActivity>, StatsError> {
        let now_sec = chrono::Utc::now().timestamp();
        let current_hour_sec = (now_sec / 3600) * 3600;
        let hours_i64 = i64::from(hours.max(1));
        let start_hour_sec = current_hour_sec - (hours_i64 - 1) * 3600;
        let start_ms = start_hour_sec * 1000;

        let rows = sqlx::query(
            r"
            SELECT
                (ts / 3600000) * 3600 as hour_sec,
                COUNT(*) as total,
                SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) as blocked
            FROM query_log
            WHERE ts >= ?
            GROUP BY hour_sec
            ",
        )
        .bind(start_ms)
        .fetch_all(&self.pool)
        .await?;

        let mut map = std::collections::HashMap::new();
        for r in rows {
            let hour_sec: i64 = r.get("hour_sec");
            let total: i64 = r.get::<Option<i64>, _>("total").unwrap_or(0);
            let blocked: i64 = r.get::<Option<i64>, _>("blocked").unwrap_or(0);
            map.insert(hour_sec, (total, blocked));
        }

        // Also merge stats_hourly in case older logs were pruned by retention.
        // A live query and an archived rollup can legitimately cover the same
        // hour (retention prunes part of an hour), so the two are added
        // together rather than one silently replacing the other.
        let archived_rows = sqlx::query(
            r"
            SELECT
                (hour / 3600000) * 3600 as hour_sec,
                queries as total,
                blocked
            FROM stats_hourly
            WHERE hour >= ?
            ",
        )
        .bind(start_ms)
        .fetch_all(&self.pool)
        .await?;

        for r in archived_rows {
            let hour_sec: i64 = r.get("hour_sec");
            let total: i64 = r.get::<Option<i64>, _>("total").unwrap_or(0);
            let blocked: i64 = r.get::<Option<i64>, _>("blocked").unwrap_or(0);
            let entry = map.entry(hour_sec).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(total);
            entry.1 = entry.1.saturating_add(blocked);
        }

        let mut result = Vec::with_capacity(hours as usize);
        for h in 0..hours_i64 {
            let h_sec = start_hour_sec + h * 3600;
            let (total, blocked) = map.get(&h_sec).copied().unwrap_or((0, 0));
            result.push(HourlyActivity {
                timestamp_sec: h_sec,
                total_queries: total,
                blocked_queries: blocked,
            });
        }

        Ok(result)
    }
}

/// Hourly activity bucket for dashboard time-series charts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct HourlyActivity {
    pub timestamp_sec: i64,
    pub total_queries: i64,
    pub blocked_queries: i64,
}
