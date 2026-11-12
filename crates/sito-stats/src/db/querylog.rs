//! Query-log reads, dashboard statistics, and top-N aggregation.

#[allow(clippy::wildcard_imports, unused_imports)]
use super::*;

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

    /// Queries logs with filters and cursor-based pagination.
    pub async fn query_logs(&self, filter: &QueryLogFilter) -> Result<QueryLogPage, StatsError> {
        let limit = filter.limit.unwrap_or(50).clamp(1, 1000);
        let fetch_limit = limit + 1;

        // `total_count` counts every row matching the filters regardless of the
        // cursor, so it stays stable while paging. It is optional because the
        // live UI refresh must not run a whole-table count every few seconds.
        let total_count = if filter.include_total.unwrap_or(true) {
            let mut count_builder =
                filtered_query("SELECT COUNT(*) FROM query_log WHERE 1=1", filter);
            let total: i64 = count_builder
                .build_query_scalar()
                .fetch_one(&self.pool)
                .await?;
            Some(total)
        } else {
            None
        };

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
            total_count,
        })
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
        self.delete_query_logs_with_policy(keep_aggregates, self.rollup_client_names)
            .await
    }

    /// Clears the query log with an explicit rollup client-name policy (the
    /// API passes the live configuration so a hot-reloaded setting applies).
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
        let mut global = self
            .cache
            .global
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *global = None;
        drop(global);
        let mut hourly = self
            .cache
            .hourly
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *hourly = None;
        drop(hourly);
        let mut upstream = self
            .cache
            .upstream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *upstream = None;
    }

    /// Dashboard global statistics served from a short-lived cache.
    pub async fn get_global_stats_cached(&self, window_ms: i64) -> Result<GlobalStats, StatsError> {
        {
            let guard = self
                .cache
                .global
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(cached) = guard.as_ref()
                && cached.window_ms == window_ms
                && cached.at.elapsed() < DASHBOARD_CACHE_TTL
            {
                return Ok(cached.value.clone());
            }
        }

        let value = self.get_global_stats(window_ms).await?;
        let mut guard = self
            .cache
            .global
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let guard = self
                .cache
                .upstream
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(cached) = guard.as_ref()
                && cached.window_ms == window_ms
                && cached.at.elapsed() < DASHBOARD_CACHE_TTL
            {
                return Ok(cached.value.clone());
            }
        }

        let value = self.get_upstream_stats(window_ms).await?;
        let mut guard = self
            .cache
            .upstream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let guard = self
                .cache
                .hourly
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(cached) = guard.as_ref()
                && cached.hours == hours
                && cached.at.elapsed() < DASHBOARD_CACHE_TTL
            {
                return Ok(cached.value.clone());
            }
        }

        let value = self.get_hourly_activity(hours).await?;
        let mut guard = self
            .cache
            .hourly
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
