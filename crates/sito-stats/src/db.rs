//! SQLite database storage engine for query logging and historical statistics.

use crate::entry::QueryLogEntry;
use crate::error::StatsError;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Pool, Row, Sqlite};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use utoipa::ToSchema;

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

        let mut builder: sqlx::QueryBuilder<Sqlite> = sqlx::QueryBuilder::new(
            "SELECT id, ts, client_ip, client_name, qname, qtype, rcode, verdict, rule, list_source, upstream, elapsed_us, dnssec, proto FROM query_log WHERE 1=1",
        );

        if let Some(cursor) = filter.cursor {
            builder.push(" AND id < ");
            builder.push_bind(cursor);
        }
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
            total_count: None,
        })
    }

    /// Deletes all entries from the query log.
    pub async fn delete_query_logs(&self) -> Result<u64, StatsError> {
        let res = sqlx::query("DELETE FROM query_log")
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// Computes global aggregates for a specified time window in milliseconds.
    pub async fn get_global_stats(&self, window_ms: i64) -> Result<GlobalStats, StatsError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let cutoff = now_ms.saturating_sub(window_ms);

        let row = sqlx::query(
            r"
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN verdict = 'stale' OR rule = 'cache' THEN 1 ELSE 0 END) as cached
            FROM query_log
            WHERE ts >= ?
            ",
        )
        .bind(cutoff)
        .fetch_one(&self.pool)
        .await?;

        let total_queries: i64 = row.get::<Option<i64>, _>("total").unwrap_or(0);
        let blocked_queries: i64 = row.get::<Option<i64>, _>("blocked").unwrap_or(0);
        let cached_queries: i64 = row.get::<Option<i64>, _>("cached").unwrap_or(0);

        let blocked_percentage = if total_queries > 0 {
            (blocked_queries as f64 / total_queries as f64) * 100.0
        } else {
            0.0
        };

        // Top 10 domains
        let top_domains_rows = sqlx::query(
            r"
            SELECT qname, COUNT(*) as count
            FROM query_log
            WHERE ts >= ?
            GROUP BY qname
            ORDER BY count DESC
            LIMIT 10
            ",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;

        let mut top_domains = Vec::new();
        for r in top_domains_rows {
            let qname: String = r.get("qname");
            let count: i64 = r.get("count");
            top_domains.push((qname, count));
        }

        // Top 10 blocked domains
        let top_blocked_rows = sqlx::query(
            r"
            SELECT qname, COUNT(*) as count
            FROM query_log
            WHERE ts >= ? AND verdict = 'blocked'
            GROUP BY qname
            ORDER BY count DESC
            LIMIT 10
            ",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;

        let mut top_blocked_domains = Vec::new();
        for r in top_blocked_rows {
            let qname: String = r.get("qname");
            let count: i64 = r.get("count");
            top_blocked_domains.push((qname, count));
        }

        // Top 10 clients
        let top_clients_rows = sqlx::query(
            r"
            SELECT COALESCE(client_name, client_ip) as client, COUNT(*) as count
            FROM query_log
            WHERE ts >= ?
            GROUP BY client
            ORDER BY count DESC
            LIMIT 10
            ",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;

        let mut top_clients = Vec::new();
        for r in top_clients_rows {
            let client: String = r.get("client");
            let count: i64 = r.get("count");
            top_clients.push((client, count));
        }

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

    /// Computes per-client statistics.
    pub async fn get_client_stats(&self, window_ms: i64) -> Result<Vec<ClientStats>, StatsError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let cutoff = now_ms.saturating_sub(window_ms);

        let rows = sqlx::query(
            r"
            SELECT
                client_ip,
                client_name,
                COUNT(*) as total,
                SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) as blocked,
                MAX(ts) as last_seen
            FROM query_log
            WHERE ts >= ?
            GROUP BY client_ip
            ORDER BY total DESC
            ",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;

        let mut stats = Vec::new();
        for r in rows {
            let client_ip: String = r.get("client_ip");
            let client_name: Option<String> = r.get("client_name");
            let total_queries: i64 = r.get::<Option<i64>, _>("total").unwrap_or(0);
            let blocked_queries: i64 = r.get::<Option<i64>, _>("blocked").unwrap_or(0);
            let last_seen: i64 = r.get::<Option<i64>, _>("last_seen").unwrap_or(0);

            stats.push(ClientStats {
                client_ip,
                client_name,
                total_queries,
                blocked_queries,
                last_seen,
            });
        }

        Ok(stats)
    }

    /// Computes per-upstream statistics.
    pub async fn get_upstream_stats(
        &self,
        window_ms: i64,
    ) -> Result<Vec<UpstreamStats>, StatsError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let cutoff = now_ms.saturating_sub(window_ms);

        let rows = sqlx::query(
            r"
            SELECT
                COALESCE(upstream, 'unknown') as upstream,
                COUNT(*) as total,
                SUM(CASE WHEN rcode IS NOT NULL AND rcode != 0 THEN 1 ELSE 0 END) as errors,
                AVG(COALESCE(elapsed_us, 0)) as avg_elapsed
            FROM query_log
            WHERE ts >= ? AND upstream IS NOT NULL
            GROUP BY upstream
            ORDER BY total DESC
            ",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;

        let mut total_all = 0i64;
        let mut raw = Vec::new();

        for r in rows {
            let upstream: String = r.get("upstream");
            let total_queries: i64 = r.get::<Option<i64>, _>("total").unwrap_or(0);
            let error_queries: i64 = r.get::<Option<i64>, _>("errors").unwrap_or(0);
            let avg_elapsed: f64 = r.get::<Option<f64>, _>("avg_elapsed").unwrap_or(0.0);

            total_all += total_queries;
            raw.push((upstream, total_queries, error_queries, avg_elapsed as i64));
        }

        let mut stats = Vec::new();
        for (upstream, total_queries, error_queries, avg_elapsed_us) in raw {
            let share_percentage = if total_all > 0 {
                (total_queries as f64 / total_all as f64) * 100.0
            } else {
                0.0
            };

            stats.push(UpstreamStats {
                upstream,
                total_queries,
                error_queries,
                avg_elapsed_us,
                share_percentage,
            });
        }

        Ok(stats)
    }

    /// Returns the watermark (last_id, last_ts) for a given key, or None if not set.
    pub async fn get_watermark(&self, key: &str) -> Result<Option<(i64, i64)>, StatsError> {
        let row = sqlx::query("SELECT last_id, last_ts FROM stats_watermark WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| (r.get("last_id"), r.get("last_ts"))))
    }

    /// Aggregates older logs into `stats_hourly` and prunes query logs older than retention period.
    pub async fn cleanup_retention(
        &self,
        retention_days: u32,
    ) -> Result<RetentionReport, StatsError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let retention_ms = i64::from(retention_days) * 24 * 3600 * 1000;
        let cutoff = now_ms.saturating_sub(retention_ms);

        let watermark_id: i64 = sqlx::query_scalar(
            "SELECT last_id FROM stats_watermark WHERE key = 'hourly_aggregation'",
        )
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(0);

        // Aggregate hourly buckets for entries newer than watermark up to cutoff
        let hours_to_aggregate = sqlx::query(
            r"
            SELECT
                (ts / 3600000) * 3600000 as hour,
                COUNT(*) as queries,
                SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN verdict = 'stale' OR rule = 'cache' THEN 1 ELSE 0 END) as cached,
                MAX(id) as max_id,
                MAX(ts) as max_ts
            FROM query_log
            WHERE ts < ? AND id > ?
            GROUP BY hour
            ",
        )
        .bind(cutoff)
        .bind(watermark_id)
        .fetch_all(&self.pool)
        .await?;

        let mut aggregated_hours = 0;
        let mut max_seen_id = watermark_id;
        let mut max_seen_ts = 0i64;
        let mut tx = self.pool.begin().await?;

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

            sqlx::query(
                r"
                INSERT INTO stats_hourly (hour, queries, blocked, cached, top_domains, top_clients)
                VALUES (?, ?, ?, ?, '[]', '[]')
                ON CONFLICT(hour) DO UPDATE SET
                    queries = queries + excluded.queries,
                    blocked = blocked + excluded.blocked,
                    cached = cached + excluded.cached
                ",
            )
            .bind(hour)
            .bind(queries)
            .bind(blocked)
            .bind(cached)
            .execute(&mut *tx)
            .await?;

            aggregated_hours += 1;
        }

        if max_seen_id > watermark_id {
            sqlx::query(
                r"
                INSERT INTO stats_watermark (key, last_id, last_ts)
                VALUES ('hourly_aggregation', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    last_id = excluded.last_id,
                    last_ts = excluded.last_ts
                ",
            )
            .bind(max_seen_id)
            .bind(max_seen_ts)
            .execute(&mut *tx)
            .await?;
        }

        // Delete pruned rows
        let del_res = sqlx::query("DELETE FROM query_log WHERE ts < ?")
            .bind(cutoff)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(RetentionReport {
            aggregated_hours,
            deleted_records: del_res.rows_affected(),
        })
    }

    /// Triggers SQLite database VACUUM.
    pub async fn vacuum(&self) -> Result<(), StatsError> {
        sqlx::query("VACUUM").execute(&self.pool).await?;
        Ok(())
    }

    /// Returns the database file size in bytes if stored on disk.
    pub async fn db_size_bytes(&self) -> Result<u64, StatsError> {
        if let Some(ref path) = self.db_path {
            let meta = tokio::fs::metadata(path).await?;
            Ok(meta.len())
        } else {
            Ok(0)
        }
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

        // Also check stats_hourly in case older logs were pruned by retention
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
        .await
        .unwrap_or_default();

        for r in archived_rows {
            let hour_sec: i64 = r.get("hour_sec");
            let total: i64 = r.get::<Option<i64>, _>("total").unwrap_or(0);
            let blocked: i64 = r.get::<Option<i64>, _>("blocked").unwrap_or(0);
            map.entry(hour_sec).or_insert((total, blocked));
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
