//! Hour-chunked retention, rollups, and PII-safe aggregate maintenance.

#[allow(clippy::wildcard_imports, unused_imports)]
use super::*;

impl StatsDb {
    /// Aggregates older detailed logs into `stats_hourly` and prunes
    /// `query_log` rows older than the retention period.
    ///
    /// Hourly rollups are **not** deleted by this method; use
    /// [`Self::cleanup_retention_with_policy`] (or the deprecated
    /// [`Self::cleanup_retention`] wrapper) for the full retention policy.
    ///
    /// Each expired hour is processed in its own short `BEGIN IMMEDIATE`
    /// transaction, so a large backlog cannot hold the writer lock for the
    /// whole sweep. Inside a chunk the aggregate read, rollup upsert, watermark
    /// update and delete share one transaction: producers cannot interleave a
    /// (possibly backdated) insert between the read and the delete, so no
    /// pruned row can be deleted without being aggregated. Because deleted rows
    /// no longer exist, the watermark is not used to skip rows.
    ///
    /// After a sweep that removed at least [`VACUUM_MIN_DELETED_ROWS`] rows the
    /// database is vacuumed, so pages freed by retention are returned to the OS
    /// instead of growing the file forever.
    pub async fn cleanup_detailed_retention(
        &self,
        retention_days: u32,
    ) -> Result<RetentionReport, StatsError> {
        self.cleanup_retention_inner(retention_days, None, self.rollup_client_names)
            .await
    }

    /// Compatibility retention sweep.
    ///
    /// Delegates to [`Self::cleanup_retention_with_policy`] with the default
    /// `stats.rollup_retention_days` (365) instead of silently pruning detailed
    /// rows only. The wrapper cannot see the runtime configuration, so a
    /// deployment with a non-default rollup retention must call
    /// [`Self::cleanup_retention_with_policy`] directly. Use
    /// [`Self::cleanup_detailed_retention`] when the caller deliberately wants
    /// to keep hourly rollups.
    #[deprecated(
        note = "use cleanup_detailed_retention for detailed rows only, or cleanup_retention_with_policy for an explicit rollup policy"
    )]
    pub async fn cleanup_retention(
        &self,
        retention_days: u32,
    ) -> Result<RetentionReport, StatsError> {
        let rollup_retention_days = sito_core::config::StatsConfig::default().rollup_retention_days;
        self.cleanup_retention_with_policy(
            retention_days,
            rollup_retention_days,
            self.rollup_client_names,
        )
        .await
    }

    /// Full retention sweep with explicit rollup policy.
    ///
    /// Detailed query-log rows are processed in bounded hour buckets, each in
    /// its own short `BEGIN IMMEDIATE` transaction. Expired `stats_hourly`
    /// rows (and therefore their domains and hashed client identifiers) are
    /// removed separately according to `rollup_retention_days`.
    pub async fn cleanup_retention_with_policy(
        &self,
        retention_days: u32,
        rollup_retention_days: u32,
        rollup_client_names: bool,
    ) -> Result<RetentionReport, StatsError> {
        self.cleanup_retention_inner(
            retention_days,
            Some(rollup_retention_days),
            rollup_client_names,
        )
        .await
    }

    pub(super) async fn cleanup_retention_inner(
        &self,
        retention_days: u32,
        rollup_retention_days: Option<u32>,
        rollup_client_names: bool,
    ) -> Result<RetentionReport, StatsError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let retention_ms = i64::from(retention_days) * 24 * 3600 * 1000;
        let cutoff = now_ms.saturating_sub(retention_ms);

        let mut report = RetentionReport::default();
        let mut conn = self.pool.acquire().await?;
        Self::ensure_retention_temp_tables(&mut conn).await?;
        // A previous failed sweep may have left rows on this pooled connection.
        Self::clear_retention_temp_all(&mut conn).await?;

        // Find the next expired timestamp with an index seek (`MIN(ts)` over
        // `idx_ql_ts`), process that hour in row-bounded `(ts, id)` chunks, then
        // repeat. This avoids a full `GROUP BY hour` scan of the whole expired
        // range and keeps each write transaction short.
        loop {
            let next_ts: Option<i64> =
                sqlx::query_scalar("SELECT MIN(ts) FROM query_log WHERE ts < ?")
                    .bind(cutoff)
                    .fetch_one(&mut *conn)
                    .await?;
            let Some(next_ts) = next_ts else { break };

            // `div_euclid` floors negative timestamps too, so a negative `ts`
            // row cannot produce an hour bucket above the row and spin forever.
            let hour = next_ts.div_euclid(3_600_000) * 3_600_000;
            let end = hour.saturating_add(3_600_000).min(cutoff);
            if end <= hour {
                break;
            }

            // Accumulate exact per-hour counts across chunks in temp tables so
            // a heavy hitter that is not in any single chunk's top-N survives.
            Self::clear_retention_temp_hour(&mut conn, hour).await?;

            // Snapshot the pre-sweep top lists once. Each chunk writes
            // `pre_sweep + cumulative temp counts` (replacing the previous
            // chunk's value), so writing every chunk is crash-safe without
            // double counting.
            let existing_rollups = load_existing_rollups(&mut conn, &[hour]).await?;
            let existing_tops = existing_rollups.get(&hour).cloned().unwrap_or_default();

            let mut lower = (hour, 0i64);
            loop {
                // The first `(ts, id)` row past this chunk, if any. The
                // `(ts, id)` index supports this cursor without a temp B-tree.
                let hour_upper = (end, i64::MIN);
                let boundary: Option<(i64, i64)> = sqlx::query_as(
                    r"
                    SELECT ts, id FROM query_log INDEXED BY idx_ql_ts_id
                    WHERE (ts, id) >= (?, ?) AND (ts, id) < (?, ?)
                    ORDER BY ts ASC, id ASC
                    LIMIT 1 OFFSET ?
                    ",
                )
                .bind(lower.0)
                .bind(lower.1)
                .bind(hour_upper.0)
                .bind(hour_upper.1)
                .bind(RETENTION_ROWS_PER_CHUNK)
                .fetch_optional(&mut *conn)
                .await?;
                let (upper, done) = boundary.map_or((hour_upper, true), |cursor| (cursor, false));

                let deleted = self
                    .rollup_and_delete_chunk(
                        &mut conn,
                        &RetentionChunk { hour, lower, upper },
                        &existing_tops,
                        done,
                        rollup_client_names,
                    )
                    .await?;
                report.deleted_records += deleted;
                report.chunks += 1;

                if done {
                    break;
                }
                lower = upper;
            }
            report.aggregated_hours += 1;
        }

        if let Some(rollup_days) = rollup_retention_days {
            report.rollup_deleted_records =
                self.delete_expired_rollups(rollup_days, now_ms).await?;
        }

        let total_deleted = report
            .deleted_records
            .saturating_add(report.rollup_deleted_records);
        if total_deleted >= VACUUM_MIN_DELETED_ROWS
            && let Err(e) = self.vacuum().await
        {
            // Rollup and delete already committed; a failed compaction must not
            // make the sweep look failed or lose the report.
            tracing::warn!(error = %e, "stats retention vacuum failed");
        }

        self.invalidate_stats_cache();
        if let Err(e) = self.record_retention_success(now_ms).await {
            // The sweep itself committed; a marker write failure must not turn
            // a successful deletion into a failed sweep.
            tracing::warn!(error = %e, "failed to record stats retention success marker");
        }
        Ok(report)
    }

    /// Deletes expired hourly rollups in bounded autocommit batches.
    pub(super) async fn delete_expired_rollups(
        &self,
        rollup_retention_days: u32,
        now_ms: i64,
    ) -> Result<u64, StatsError> {
        const ROLLUP_DELETE_BATCH: i64 = 1_000;
        let retention_ms = i64::from(rollup_retention_days) * 24 * 3600 * 1000;
        let cutoff = now_ms.saturating_sub(retention_ms);

        let mut total = 0u64;
        loop {
            let deleted = sqlx::query(
                r"
                DELETE FROM stats_hourly
                WHERE hour IN (
                    SELECT hour FROM stats_hourly
                    WHERE hour + 3600000 <= ?
                    ORDER BY hour ASC
                    LIMIT ?
                )
                ",
            )
            .bind(cutoff)
            .bind(ROLLUP_DELETE_BATCH)
            .execute(&self.pool)
            .await?
            .rows_affected();
            total = total.saturating_add(deleted);
            if deleted == 0 {
                break;
            }
        }
        Ok(total)
    }

    /// Creates the per-connection temp tables used to accumulate exact
    /// per-hour top-N counts across row-bounded chunks.
    pub(super) async fn ensure_retention_temp_tables(
        conn: &mut SqliteConnection,
    ) -> Result<(), StatsError> {
        for sql in [
            r"
            CREATE TEMP TABLE IF NOT EXISTS retention_domain_counts (
                hour INTEGER NOT NULL,
                qname TEXT NOT NULL,
                total INTEGER NOT NULL DEFAULT 0,
                blocked INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (hour, qname)
            ) WITHOUT ROWID
            ",
            r"
            CREATE TEMP TABLE IF NOT EXISTS retention_client_counts (
                hour INTEGER NOT NULL,
                client_ip TEXT NOT NULL,
                client_name TEXT NOT NULL DEFAULT '',
                total INTEGER NOT NULL DEFAULT 0,
                blocked INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (hour, client_ip)
            ) WITHOUT ROWID
            ",
            r"
            CREATE TEMP TABLE IF NOT EXISTS retention_upstream_counts (
                hour INTEGER NOT NULL,
                upstream TEXT NOT NULL,
                total INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0,
                elapsed_sum INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (hour, upstream)
            ) WITHOUT ROWID
            ",
        ] {
            sqlx::query(sql).execute(&mut *conn).await?;
        }
        Ok(())
    }

    pub(super) async fn clear_retention_temp_all(
        conn: &mut SqliteConnection,
    ) -> Result<(), StatsError> {
        sqlx::query("DELETE FROM retention_domain_counts")
            .execute(&mut *conn)
            .await?;
        sqlx::query("DELETE FROM retention_client_counts")
            .execute(&mut *conn)
            .await?;
        sqlx::query("DELETE FROM retention_upstream_counts")
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    pub(super) async fn clear_retention_temp_hour(
        conn: &mut SqliteConnection,
        hour: i64,
    ) -> Result<(), StatsError> {
        sqlx::query("DELETE FROM retention_domain_counts WHERE hour = ?")
            .bind(hour)
            .execute(&mut *conn)
            .await?;
        sqlx::query("DELETE FROM retention_client_counts WHERE hour = ?")
            .bind(hour)
            .execute(&mut *conn)
            .await?;
        sqlx::query("DELETE FROM retention_upstream_counts WHERE hour = ?")
            .bind(hour)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    /// Reads the exact accumulated per-hour top lists from the temp tables.
    pub(super) async fn load_temp_hour_tops(
        conn: &mut SqliteConnection,
        hour: i64,
    ) -> Result<HourRollup, StatsError> {
        let limit = i64::try_from(ROLLUP_TOP_N).unwrap_or(100);

        let domains: Vec<DomainTop> = sqlx::query_as(
            r"
            SELECT qname, total, blocked FROM (
                SELECT qname, total, blocked,
                    ROW_NUMBER() OVER (ORDER BY total DESC, qname ASC) AS rn_total,
                    ROW_NUMBER() OVER (ORDER BY blocked DESC, qname ASC) AS rn_blocked
                FROM retention_domain_counts WHERE hour = ?
            )
            WHERE rn_total <= ? OR rn_blocked <= ?
            ",
        )
        .bind(hour)
        .bind(limit)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?;

        let clients: Vec<ClientTop> = sqlx::query_as(
            "SELECT client_ip, NULLIF(client_name, ''), total, blocked, last_seen \
             FROM retention_client_counts WHERE hour = ? \
             ORDER BY total DESC, client_ip ASC LIMIT ?",
        )
        .bind(hour)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?;

        let upstreams: Vec<UpstreamTop> = sqlx::query_as(
            "SELECT upstream, total, errors, elapsed_sum FROM retention_upstream_counts \
             WHERE hour = ? ORDER BY total DESC, upstream ASC LIMIT ?",
        )
        .bind(hour)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?;

        Ok(HourRollup {
            domains,
            clients,
            upstreams,
        })
    }

    /// Hashes client identifiers and applies the name policy to a rollup.
    pub(super) fn normalize_hour_rollup(
        &self,
        mut rollup: HourRollup,
        rollup_client_names: bool,
    ) -> HourRollup {
        for client in &mut rollup.clients {
            client.0 = self.hash_client_ip(&client.0);
            if !rollup_client_names {
                client.1 = None;
            }
        }
        rollup
    }

    /// Merges fresh full-hour top lists with the lists already stored for a
    /// partially-pruned hour.
    pub(super) fn merge_hour_rollup(
        &self,
        existing: (Option<String>, Option<String>, Option<String>),
        rollup: HourRollup,
        rollup_client_names: bool,
    ) -> HourRollup {
        let mut rollup = self.normalize_hour_rollup(rollup, rollup_client_names);
        let (existing_domains, existing_clients, existing_upstreams) = existing;

        let mut existing_clients: Vec<ClientTop> = decode_tops(existing_clients.as_deref());
        for client in &mut existing_clients {
            client.0 = self.hash_client_ip(&client.0);
            if !rollup_client_names {
                client.1 = None;
            }
        }

        rollup.domains = merge_domain_tops(
            decode_tops(existing_domains.as_deref()),
            rollup.domains,
            // Keep room for the union of the top-N by total and by blocked
            // count, so a blocked-heavy domain survives the rollup even when
            // it ranks below the total-query top-N.
            ROLLUP_TOP_N * 2,
        );
        rollup.clients = merge_client_tops(existing_clients, rollup.clients, ROLLUP_TOP_N);
        rollup.upstreams = merge_upstream_tops(
            decode_tops(existing_upstreams.as_deref()),
            rollup.upstreams,
            ROLLUP_TOP_N,
        );
        rollup
    }

    /// Folds every row in `[start, end)` into `stats_hourly` and deletes
    /// exactly those rows in one transaction. Used by the explicit
    /// `keep_aggregates` clear path (which is not row-bounded because the
    /// operator requested a full clear).
    pub(super) async fn rollup_and_delete_range(
        &self,
        start: i64,
        end: i64,
        rollup_client_names: bool,
    ) -> Result<RetentionReport, StatsError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

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
            WHERE ts >= ? AND ts < ?
            GROUP BY hour
            ",
        )
        .bind(start)
        .bind(end)
        .fetch_all(&mut *tx)
        .await?;

        let affected_hours: Vec<i64> = hours_to_aggregate
            .iter()
            .map(|row| row.get("hour"))
            .collect();
        let mut rollups: HashMap<i64, HourRollup> = HashMap::new();
        if !affected_hours.is_empty() {
            collect_hour_rollups(&mut tx, start, end, i64::MIN, i64::MAX, &mut rollups).await?;
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

            let rollup = rollups.remove(&hour).unwrap_or_default();
            let existing = existing_rollups.get(&hour).cloned().unwrap_or_default();
            let rollup = self.merge_hour_rollup(existing, rollup, rollup_client_names);

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

        let del_res = sqlx::query("DELETE FROM query_log WHERE ts >= ? AND ts < ?")
            .bind(start)
            .bind(end)
            .execute(&mut *tx)
            .await?;

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
            rollup_deleted_records: 0,
            chunks: 1,
        })
    }

    /// Aggregates and deletes one row-bounded `(ts, id)` chunk. The exact
    /// accumulated top lists are written on every chunk so a crash cannot lose
    /// contributions from already-deleted rows.
    pub(super) async fn rollup_and_delete_chunk(
        &self,
        conn: &mut SqliteConnection,
        chunk: &RetentionChunk,
        existing_tops: &(Option<String>, Option<String>, Option<String>),
        final_hour: bool,
        rollup_client_names: bool,
    ) -> Result<u64, StatsError> {
        let RetentionChunk { hour, lower, upper } = *chunk;
        // `BEGIN IMMEDIATE` takes the write lock up front so concurrent writers
        // wait instead of failing the aggregate/delete with `SQLITE_BUSY`.
        let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;

        let row = sqlx::query(
            r"
            SELECT
                COUNT(*) as queries,
                SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN rule IN ('cache', 'stale_cache') OR verdict = 'stale' THEN 1 ELSE 0 END) as cached,
                MAX(id) as max_id,
                MAX(ts) as max_ts
            FROM query_log INDEXED BY idx_ql_ts_id
            WHERE (ts, id) >= (?, ?) AND (ts, id) < (?, ?)
            ",
        )
        .bind(lower.0)
        .bind(lower.1)
        .bind(upper.0)
        .bind(upper.1)
        .fetch_one(&mut *tx)
        .await?;

        let queries: i64 = row.get::<Option<i64>, _>("queries").unwrap_or(0);
        let blocked: i64 = row.get::<Option<i64>, _>("blocked").unwrap_or(0);
        let cached: i64 = row.get::<Option<i64>, _>("cached").unwrap_or(0);
        let max_seen_id = row.get::<Option<i64>, _>("max_id").unwrap_or(0);
        let max_seen_ts = row.get::<Option<i64>, _>("max_ts").unwrap_or(0);

        // Accumulate exact per-hour counts for this chunk. The temp tables are
        // updated in the same transaction as the delete, so a crash cannot
        // leave deleted rows without their counts.
        sqlx::query(
            r"
            INSERT INTO retention_domain_counts (hour, qname, total, blocked)
            SELECT ?, qname, COUNT(*), SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END)
            FROM query_log INDEXED BY idx_ql_ts_id
            WHERE (ts, id) >= (?, ?) AND (ts, id) < (?, ?)
            GROUP BY qname
            ON CONFLICT(hour, qname) DO UPDATE SET
                total = total + excluded.total,
                blocked = blocked + excluded.blocked
            ",
        )
        .bind(hour)
        .bind(lower.0)
        .bind(lower.1)
        .bind(upper.0)
        .bind(upper.1)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r"
            INSERT INTO retention_client_counts (hour, client_ip, client_name, total, blocked, last_seen)
            SELECT ?, client_ip, COALESCE(MAX(client_name), ''), COUNT(*),
                   SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END), MAX(ts)
            FROM query_log INDEXED BY idx_ql_ts_id
            WHERE (ts, id) >= (?, ?) AND (ts, id) < (?, ?)
            GROUP BY client_ip
            ON CONFLICT(hour, client_ip) DO UPDATE SET
                total = total + excluded.total,
                blocked = blocked + excluded.blocked,
                last_seen = MAX(last_seen, excluded.last_seen),
                client_name = CASE
                    WHEN client_name = '' THEN excluded.client_name
                    WHEN excluded.client_name = '' THEN client_name
                    WHEN excluded.client_name > client_name THEN excluded.client_name
                    ELSE client_name
                END
            ",
        )
        .bind(hour)
        .bind(lower.0)
        .bind(lower.1)
        .bind(upper.0)
        .bind(upper.1)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r"
            INSERT INTO retention_upstream_counts (hour, upstream, total, errors, elapsed_sum)
            SELECT ?, upstream, COUNT(*),
                   SUM(CASE WHEN rcode IS NOT NULL AND rcode != 0 THEN 1 ELSE 0 END),
                   SUM(COALESCE(elapsed_us, 0))
            FROM query_log INDEXED BY idx_ql_ts_id
            WHERE (ts, id) >= (?, ?) AND (ts, id) < (?, ?)
              AND upstream IS NOT NULL
            GROUP BY upstream
            ON CONFLICT(hour, upstream) DO UPDATE SET
                total = total + excluded.total,
                errors = errors + excluded.errors,
                elapsed_sum = elapsed_sum + excluded.elapsed_sum
            ",
        )
        .bind(hour)
        .bind(lower.0)
        .bind(lower.1)
        .bind(upper.0)
        .bind(upper.1)
        .execute(&mut *tx)
        .await?;

        // Write the accumulated top lists on every chunk, not only the final
        // one. If the process dies after a non-final chunk, the top-list
        // contributions of the deleted rows are already durable; the next
        // sweep merges the remaining rows into them.
        let tops = Self::load_temp_hour_tops(&mut tx, hour).await?;
        let merged = self.merge_hour_rollup(existing_tops.clone(), tops, rollup_client_names);
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
        .bind(encode_tops(&merged.domains))
        .bind(encode_tops(&merged.clients))
        .bind(encode_tops(&merged.upstreams))
        .execute(&mut *tx)
        .await?;

        // Delete exactly the rows that were aggregated above (same predicate in
        // the same transaction).
        let del_res = sqlx::query(
            "DELETE FROM query_log INDEXED BY idx_ql_ts_id WHERE (ts, id) >= (?, ?) AND (ts, id) < (?, ?)",
        )
        .bind(lower.0)
        .bind(lower.1)
        .bind(upper.0)
        .bind(upper.1)
        .execute(&mut *tx)
        .await?;

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
        if final_hour {
            Self::clear_retention_temp_hour(conn, hour).await?;
        }
        Ok(del_res.rows_affected())
    }
}
