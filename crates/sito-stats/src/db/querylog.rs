//! Query-log reads, dashboard statistics, and top-N aggregation.

#[allow(clippy::wildcard_imports, unused_imports)]
use super::*;

/// Builds one newest-first query-log page statement.
///
/// The cursor predicate is the row-value form `(ts, id) < (?, ?)` so SQLite can
/// seek the `(ts, id)` keyset index (`idx_ql_ts_id`, or `idx_ql_ts`, which
/// carries the rowid `id`) instead of scanning and sorting. `fetch_limit` is
/// `page_limit + 1`; the caller drops the extra row and uses it only as a
/// "there is another page" signal.
fn query_log_page_builder(
    filter: &QueryLogFilter,
    cursor: Option<(i64, i64)>,
    fetch_limit: usize,
) -> sqlx::QueryBuilder<Sqlite> {
    let mut builder = filtered_query(
        "SELECT id, ts, client_ip, client_name, qname, qtype, rcode, verdict, rule, list_source, upstream, elapsed_us, dnssec, proto FROM query_log WHERE 1=1",
        filter,
    );

    if let Some((ts, id)) = cursor {
        builder.push(" AND (ts, id) < (");
        builder.push_bind(ts);
        builder.push(", ");
        builder.push_bind(id);
        builder.push(")");
    }

    builder.push(" ORDER BY ts DESC, id DESC LIMIT ");
    builder.push_bind(i64::try_from(fetch_limit).unwrap_or(i64::MAX));
    builder
}

impl StatsDb {
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

    /// Queries logs with filters and opaque keyset pagination.
    ///
    /// The page is ordered newest first by `(ts, id)` and the cursor predicate
    /// is the row-value form `(ts, id) < (?, ?)`, which lets SQLite seek the
    /// `(ts, id)` keyset index. No `COUNT(*)` runs on this path: callers learn
    /// that the end was reached from `next_cursor == None`.
    pub async fn query_logs(&self, filter: &QueryLogFilter) -> Result<QueryLogPage, StatsError> {
        let limit = filter
            .limit
            .unwrap_or(DEFAULT_QUERYLOG_LIMIT)
            .clamp(1, MAX_QUERYLOG_LIMIT);
        // Fetch one extra row to decide whether another page exists without a
        // second query or a count.
        let fetch_limit = limit + 1;

        let cursor = filter
            .cursor
            .as_deref()
            .map(|raw| cursor::decode_cursor(filter, raw))
            .transpose()?;

        let mut builder = query_log_page_builder(filter, cursor, fetch_limit);
        let rows = builder.build().fetch_all(&self.pool).await?;

        let mut items = Vec::with_capacity(rows.len());
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

            items.push(QueryLogEntry {
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

        // The extra row only signals another page; the cursor points at the
        // last row actually returned so the next page starts strictly below it.
        let next_cursor = if items.len() > limit {
            items.truncate(limit);
            items.last().and_then(|entry| {
                entry
                    .id
                    .map(|id| cursor::encode_cursor(filter, entry.ts, id))
            })
        } else {
            None
        };

        Ok(QueryLogPage { items, next_cursor })
    }

    /// Deletes the query log and hourly rollups. This is the default
    /// “clear query log” behavior: identifiable browsing history is erased
    /// from both detailed and aggregate storage.
    pub async fn delete_query_logs(&self) -> Result<u64, StatsError> {
        self.delete_query_logs_with_options(false).await
    }

    /// Clears the detailed query log while folding its rows into hourly
    /// rollups. Used by the explicit `--keep-aggregates`/`keep_aggregates`
    /// opt-in.
    pub async fn delete_query_logs_keep_aggregates(&self) -> Result<u64, StatsError> {
        self.delete_query_logs_with_options(true).await
    }

    /// Clears the query log, optionally preserving aggregate rollups.
    ///
    /// A large clear is followed by `VACUUM` (and a WAL truncate) so deleted
    /// pages do not remain readable in free space or grow the file forever.
    /// `secure_delete=ON` is set on every connection so overwritten/deleted
    /// content is zeroed by SQLite as well.
    pub async fn delete_query_logs_with_options(
        &self,
        keep_aggregates: bool,
    ) -> Result<u64, StatsError> {
        self.delete_query_logs_with_policy(keep_aggregates, self.rollup_client_names_enabled())
            .await
    }

    /// Clears the query log with an explicit rollup client-name policy (the
    /// API passes the live configuration so a hot-reloaded setting applies).
    ///
    /// `keep_aggregates = true` folds the whole `query_log` range into hourly
    /// rollups in one transaction before deleting it; that operator-requested
    /// path is deliberately not hour-bounded and is documented as the
    /// whole-range memory/lock residual (P2-61). The default
    /// `keep_aggregates = false` deletes both tables atomically without
    /// aggregating.
    ///
    /// `rollup_client_names` is the caller's captured policy, not an override:
    /// a live `false` from [`StatsDb::set_rollup_client_names`] is
    /// authoritative and strips client names in this path too.
    pub async fn delete_query_logs_with_policy(
        &self,
        keep_aggregates: bool,
        rollup_client_names: bool,
    ) -> Result<u64, StatsError> {
        let (deleted, total_deleted) = if keep_aggregates {
            let report = self
                .rollup_and_delete_range(i64::MIN, i64::MAX, rollup_client_names)
                .await?;
            (report.deleted_records, report.deleted_records)
        } else {
            // Delete both tables atomically so a crash cannot leave the
            // detailed log empty while identifiable rollups survive.
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let deleted = sqlx::query("DELETE FROM query_log")
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let rollups = sqlx::query("DELETE FROM stats_hourly")
                .execute(&mut *tx)
                .await?
                .rows_affected();
            sqlx::query("DELETE FROM stats_watermark WHERE key = 'hourly_aggregation'")
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            (deleted, deleted.saturating_add(rollups))
        };

        self.invalidate_stats_cache();
        if total_deleted >= VACUUM_MIN_DELETED_ROWS
            && let Err(e) = self.vacuum().await
        {
            tracing::warn!(error = %e, "stats clear vacuum failed");
        }
        Ok(deleted)
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

    /// Invalidates all cached dashboard aggregates. Called after clear and
    /// retention so the next dashboard poll reflects the deleted history.
    pub fn invalidate_stats_cache(&self) {
        let mut global = sito_core::sync::lock_or_recover(&self.cache.global);
        *global = None;
        drop(global);
        let mut hourly = sito_core::sync::lock_or_recover(&self.cache.hourly);
        *hourly = None;
        drop(hourly);
        let mut upstream = sito_core::sync::lock_or_recover(&self.cache.upstream);
        *upstream = None;
    }

    /// Dashboard global statistics served from a short-lived cache.
    pub async fn get_global_stats_cached(&self, window_ms: i64) -> Result<GlobalStats, StatsError> {
        {
            let guard = sito_core::sync::lock_or_recover(&self.cache.global);
            if let Some(cached) = guard.as_ref()
                && cached.window_ms == window_ms
                && cached.at.elapsed() < DASHBOARD_CACHE_TTL
            {
                return Ok(cached.value.clone());
            }
        }

        let value = self.get_global_stats(window_ms).await?;
        let mut guard = sito_core::sync::lock_or_recover(&self.cache.global);
        *guard = Some(CachedGlobal {
            window_ms,
            at: Instant::now(),
            value: value.clone(),
        });
        Ok(value)
    }

    /// Dashboard per-upstream statistics served from a short-lived cache.
    pub async fn get_upstream_stats_cached(
        &self,
        window_ms: i64,
    ) -> Result<Vec<UpstreamStats>, StatsError> {
        {
            let guard = sito_core::sync::lock_or_recover(&self.cache.upstream);
            if let Some(cached) = guard.as_ref()
                && cached.window_ms == window_ms
                && cached.at.elapsed() < DASHBOARD_CACHE_TTL
            {
                return Ok(cached.value.clone());
            }
        }

        let value = self.get_upstream_stats(window_ms).await?;
        let mut guard = sito_core::sync::lock_or_recover(&self.cache.upstream);
        *guard = Some(CachedUpstream {
            window_ms,
            at: Instant::now(),
            value: value.clone(),
        });
        Ok(value)
    }

    /// Dashboard hourly activity served from a short-lived cache.
    pub async fn get_hourly_activity_cached(
        &self,
        hours: u32,
    ) -> Result<Vec<HourlyActivity>, StatsError> {
        {
            let guard = sito_core::sync::lock_or_recover(&self.cache.hourly);
            if let Some(cached) = guard.as_ref()
                && cached.hours == hours
                && cached.at.elapsed() < DASHBOARD_CACHE_TTL
            {
                return Ok(cached.value.clone());
            }
        }

        let value = self.get_hourly_activity(hours).await?;
        let mut guard = sito_core::sync::lock_or_recover(&self.cache.hourly);
        *guard = Some(CachedHourly {
            hours,
            at: Instant::now(),
            value: value.clone(),
        });
        Ok(value)
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
    pub(super) async fn live_domain_tops(
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
    pub(super) async fn live_blocked_domain_tops(
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
    pub(super) async fn archived_domain_tops(
        &self,
        cutoff: i64,
    ) -> Result<Vec<DomainTop>, StatsError> {
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
    pub(super) async fn archived_blocked_domain_tops(
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
    pub(super) async fn live_client_tops(
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
    pub(super) async fn archived_client_tops(
        &self,
        cutoff: i64,
    ) -> Result<Vec<ClientTop>, StatsError> {
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
    pub(super) async fn live_upstream_tops(
        &self,
        cutoff: i64,
        limit: usize,
    ) -> Result<Vec<UpstreamTop>, StatsError> {
        let rows = sqlx::query(
            r"
            SELECT upstream,
                   COUNT(*) as total,
                   SUM(CASE WHEN rcode IS NOT NULL AND rcode NOT IN (0, 3) THEN 1 ELSE 0 END) as errors,
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
    pub(super) async fn archived_upstream_tops(
        &self,
        cutoff: i64,
    ) -> Result<Vec<UpstreamTop>, StatsError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn entry(ts: i64, qname: &str, verdict: &str) -> QueryLogEntry {
        QueryLogEntry::new(ts, "192.0.2.10", None, qname, 1, Some(0), verdict, "udp")
    }

    /// Walks every page and returns `(ts, id)` for each row in order. Panics if
    /// the cursor ever repeats or the walk does not terminate quickly.
    async fn walk(db: &StatsDb, filter: QueryLogFilter) -> Vec<(i64, i64)> {
        let mut seen = Vec::new();
        let mut cursor = None;
        for _ in 0..1_000 {
            let page = db
                .query_logs(&QueryLogFilter {
                    cursor: cursor.clone(),
                    ..filter.clone()
                })
                .await
                .expect("page query");
            for item in &page.items {
                seen.push((item.ts, item.id.expect("query rows always carry an id")));
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => return seen,
            }
        }
        panic!("cursor walk did not terminate; rows={}", seen.len());
    }

    #[tokio::test]
    async fn test_query_logs_pages_newest_first_without_duplicates() {
        let db = StatsDb::in_memory().await.unwrap();
        let base = 1_700_000_000_000;
        let entries: Vec<_> = (0..120)
            .map(|i| entry(base + i, &format!("host-{i}.example"), "allowed"))
            .collect();
        db.insert_batch(&entries).await.unwrap();

        let rows = walk(
            &db,
            QueryLogFilter {
                limit: Some(25),
                ..Default::default()
            },
        )
        .await;

        assert_eq!(rows.len(), 120, "every row must be returned exactly once");
        assert_eq!(
            rows.iter().map(|(_, id)| *id).collect::<HashSet<_>>().len(),
            120,
            "no row may be duplicated across pages"
        );
        assert!(
            rows.windows(2).all(|pair| pair[0] > pair[1]),
            "rows must be strictly descending by (ts, id)"
        );
        assert_eq!(rows.first().unwrap().0, base + 119, "newest row first");
        assert_eq!(rows.last().unwrap().0, base, "oldest row last");
    }

    #[tokio::test]
    async fn test_query_logs_same_timestamp_pages_by_id() {
        let db = StatsDb::in_memory().await.unwrap();
        let ts = 1_700_000_000_000;
        let entries: Vec<_> = (0..9)
            .map(|i| entry(ts, &format!("same-{i}.example"), "allowed"))
            .collect();
        db.insert_batch(&entries).await.unwrap();

        let rows = walk(
            &db,
            QueryLogFilter {
                limit: Some(2),
                ..Default::default()
            },
        )
        .await;

        assert_eq!(rows.len(), 9);
        assert!(rows.iter().all(|(row_ts, _)| *row_ts == ts));
        let ids: Vec<i64> = rows.iter().map(|(_, id)| *id).collect();
        assert_eq!(
            ids.iter().copied().collect::<HashSet<_>>().len(),
            9,
            "same-timestamp rows must not repeat"
        );
        assert!(
            ids.windows(2).all(|pair| pair[0] > pair[1]),
            "same-timestamp ties must page deterministically by id: {ids:?}"
        );
    }

    #[tokio::test]
    async fn test_query_logs_pages_keep_filters_and_bind_cursor_to_them() {
        let db = StatsDb::in_memory().await.unwrap();
        let base = 1_700_000_000_000;
        let mut entries = Vec::new();
        for i in 0..30 {
            entries.push(entry(base + i * 2, "blocked.example", "blocked"));
            entries.push(entry(base + i * 2 + 1, "allowed.example", "allowed"));
        }
        db.insert_batch(&entries).await.unwrap();

        let blocked_filter = QueryLogFilter {
            status: Some("blocked".into()),
            limit: Some(7),
            ..Default::default()
        };
        let rows = walk(&db, blocked_filter.clone()).await;
        assert_eq!(rows.len(), 30, "filter must apply on every page");

        // Changing the page size is allowed: `limit` is not filter-bound.
        let first = db.query_logs(&blocked_filter).await.unwrap();
        let resized = db
            .query_logs(&QueryLogFilter {
                status: Some("blocked".into()),
                limit: Some(30),
                cursor: first.next_cursor.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            resized.items.len(),
            23,
            "changing limit must continue from the same keyset position"
        );

        // Replaying the cursor under a different filter is a clear error, not
        // a silently wrong page.
        let err = db
            .query_logs(&QueryLogFilter {
                status: Some("allowed".into()),
                limit: Some(7),
                cursor: first.next_cursor,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, StatsError::InvalidCursor(_)),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_query_logs_last_page_has_no_cursor() {
        let db = StatsDb::in_memory().await.unwrap();
        let empty = db.query_logs(&QueryLogFilter::default()).await.unwrap();
        assert_eq!(
            empty.items,
            Vec::<QueryLogEntry>::new(),
            "an empty table has an empty first page"
        );
        assert!(empty.next_cursor.is_none());

        let base = 1_700_000_000_000;
        let entries: Vec<_> = (0..3)
            .map(|i| entry(base + i, "small.example", "allowed"))
            .collect();
        db.insert_batch(&entries).await.unwrap();

        let page = db.query_logs(&QueryLogFilter::default()).await.unwrap();
        assert_eq!(page.items.len(), 3);
        assert!(
            page.next_cursor.is_none(),
            "a page that consumed every row is the last page"
        );
    }

    #[tokio::test]
    async fn test_query_logs_limit_clamps_between_one_and_five_hundred() {
        let db = StatsDb::in_memory().await.unwrap();
        let base = 1_700_000_000_000;
        let entries: Vec<_> = (0..510)
            .map(|i| entry(base + i, "clamp.example", "allowed"))
            .collect();
        db.insert_batch(&entries).await.unwrap();

        let one = db
            .query_logs(&QueryLogFilter {
                limit: Some(0),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(one.items.len(), 1, "limit=0 clamps to 1");

        let capped = db
            .query_logs(&QueryLogFilter {
                limit: Some(usize::MAX),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(capped.items.len(), MAX_QUERYLOG_LIMIT);
        assert!(capped.next_cursor.is_some());

        let rest = db
            .query_logs(&QueryLogFilter {
                limit: Some(usize::MAX),
                cursor: capped.next_cursor,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rest.items.len(), 10);
        assert!(rest.next_cursor.is_none());

        let default_page = db.query_logs(&QueryLogFilter::default()).await.unwrap();
        assert_eq!(default_page.items.len(), DEFAULT_QUERYLOG_LIMIT);
    }

    #[tokio::test]
    async fn test_query_logs_rejects_invalid_cursor() {
        let db = StatsDb::in_memory().await.unwrap();
        db.insert_batch(&[entry(1_700_000_000_000, "cursor.example", "allowed")])
            .await
            .unwrap();

        for bad in ["not base64!!", "AAAA", "e30"] {
            let err = db
                .query_logs(&QueryLogFilter {
                    cursor: Some(bad.into()),
                    ..Default::default()
                })
                .await
                .unwrap_err();
            assert!(
                matches!(err, StatsError::InvalidCursor(_)),
                "'{bad}' must be rejected as InvalidCursor, got {err}"
            );
        }
    }

    #[tokio::test]
    async fn test_query_log_page_uses_ts_index_seek_and_no_count() {
        let db = StatsDb::in_memory().await.unwrap();
        let filter = QueryLogFilter::default();

        let builder = query_log_page_builder(&filter, None, 51);
        let sql = builder.sql().as_str().to_string();
        assert!(
            !sql.to_ascii_uppercase().contains("COUNT("),
            "the query-log read path must not run COUNT(*): {sql}"
        );
        assert!(
            sql.contains("ORDER BY ts DESC, id DESC"),
            "pages must be newest first: {sql}"
        );

        let builder = query_log_page_builder(&filter, Some((10, 20)), 51);
        let sql = builder.sql().as_str().to_string();
        assert!(
            sql.contains("(ts, id) < (?, ?)"),
            "cursor must use the row-value form: {sql}"
        );

        // A filtered cursor page must keep the same no-count, seekable shape.
        let filtered = QueryLogFilter {
            status: Some("blocked".into()),
            qtype: Some(1),
            ..Default::default()
        };
        let builder = query_log_page_builder(&filtered, Some((10, 20)), 51);
        let filtered_sql = builder.sql().as_str().to_string();
        assert!(
            !filtered_sql.to_ascii_uppercase().contains("COUNT("),
            "a filtered page must not run COUNT(*): {filtered_sql}"
        );

        // The row-value predicate is seekable: SQLite reports a ts index range
        // rather than a scan plus a temporary sort B-tree. `id` is the rowid,
        // so both `idx_ql_ts(ts)` and `idx_ql_ts_id(ts, id)` encode the same
        // `(ts, id)` keyset order; the planner may pick either.
        // Bind counts must match each statement so SQLite can compile it. The
        // actual values do not affect the plan/opcode shape.
        for (page_sql, bind_count) in [(&sql, 3usize), (&filtered_sql, 5usize)] {
            let mut plan_query = sqlx::query(sqlx::AssertSqlSafe(format!(
                "EXPLAIN QUERY PLAN {page_sql}"
            )));
            for _ in 0..bind_count {
                plan_query = plan_query.bind(10i64);
            }
            let plan_rows = plan_query.fetch_all(db.pool()).await.unwrap();
            let plan = plan_rows
                .iter()
                .map(|row| row.get::<String, _>("detail"))
                .collect::<Vec<_>>()
                .join(" | ");
            assert!(
                plan.contains("USING INDEX idx_ql_ts"),
                "cursor page must seek a (ts, id) index: {plan}"
            );
            assert!(
                !plan.to_ascii_uppercase().contains("TEMP B-TREE"),
                "cursor page must not sort into a temp B-tree: {plan}"
            );
            assert!(
                !plan.to_ascii_uppercase().contains("SCAN query_log"),
                "cursor page must seek, not scan the table: {plan}"
            );

            // Strengthen the evidence from the plan to the VDBE program: an
            // indexed seek/prev loop, no `Count` opcode for a COUNT(*), and no
            // sorter opcode. This inspects exactly the SQL the page builder
            // produces rather than trusting the source text alone.
            let opcode_rows = {
                let mut opcode_query =
                    sqlx::query(sqlx::AssertSqlSafe(format!("EXPLAIN {page_sql}")));
                for _ in 0..bind_count {
                    opcode_query = opcode_query.bind(10i64);
                }
                opcode_query.fetch_all(db.pool()).await.unwrap()
            };
            let opcodes = opcode_rows
                .iter()
                .map(|row| row.get::<String, _>("opcode"))
                .collect::<Vec<_>>();
            assert!(
                !opcodes
                    .iter()
                    .any(|opcode| opcode == "Count" || opcode == "CountZero"),
                "the page program must not count rows: {opcodes:?}"
            );
            assert!(
                opcodes.iter().any(|opcode| {
                    matches!(opcode.as_str(), "SeekGE" | "SeekGT" | "SeekLE" | "SeekLT")
                }),
                "the page program must seek the keyset index: {opcodes:?}"
            );
            assert!(
                !opcodes.iter().any(|opcode| {
                    matches!(
                        opcode.as_str(),
                        "SorterOpen" | "SorterInsert" | "SorterSort"
                    )
                }),
                "the page program must not sort: {opcodes:?}"
            );
            assert!(
                opcodes.iter().any(|opcode| opcode == "Prev"),
                "newest-first pages must walk the index backwards: {opcodes:?}"
            );
        }
    }
}
