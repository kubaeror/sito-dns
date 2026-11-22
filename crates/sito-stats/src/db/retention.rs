//! Hour-chunked retention, rollups, and PII-safe aggregate maintenance.
//!
//! # Bounded normal retention
//!
//! [`StatsDb::cleanup_detailed_retention`] and
//! [`StatsDb::cleanup_retention_with_policy`] process one expired hour at a
//! time in row-bounded `(ts, id)` chunks, each in its own short
//! `BEGIN IMMEDIATE` transaction. Exact per-hour domain/client/upstream counts
//! accumulate in per-connection SQLite temp tables
//! ([`StatsDb::ensure_retention_temp_tables`]). Those tables are cleared at
//! sweep start and after each hour, so their memory is bounded to roughly one
//! hour of distinct domains/clients/upstreams rather than the whole retention
//! range. The rows can transiently contain raw client IPs during a sweep; they
//! are never persisted to another table.
//!
//! # Keep-aggregates clear
//!
//! The `keep_aggregates` clear path ([`StatsDb::rollup_and_delete_range`])
//! reuses the same bounded shape. It discovers the oldest remaining row, folds
//! that hour into `stats_hourly` in row-bounded `(ts, id)` chunks, then repeats
//! for the next hour until the requested range is empty. Each chunk is its own
//! `BEGIN IMMEDIATE` transaction, so the writer lock is held for at most
//! [`RETENTION_ROWS_PER_CHUNK`] rows and the per-connection temp tables hold at
//! most one hour of distinct domains/clients/upstreams. Every committed chunk
//! already contains the rollup contributions of the rows it deleted, so a
//! crash or interruption loses only the uncommitted chunk and re-running the
//! clear safely continues: the next pass starts again at the oldest remaining
//! hour and merges into the already-stored rollups. The clear remains
//! documented as requiring the service stopped (the CLI takes the service
//! lease), so no producer can interleave an insert between the aggregate read
//! and the delete.
//!
//! Chunking no longer makes the clear atomic across the whole range (it never
//! could without one long transaction); it is atomic *per chunk*: the
//! aggregate read, temp-table accumulation, rollup upsert, watermark update and
//! delete of those rows share one transaction. A row is therefore never
//! deleted without its rollup contribution being committed.
//!
//! # Scale residual (90 days / 1M rows)
//!
//! `test_retention_handles_multiple_hours_across_days` covers a multi-day,
//! multi-hour sweep. A true 1M-row/90-day soak is not part of the unit suite
//! (it would dominate CI); the chunking keeps each write transaction bounded
//! and the total sweep remains O(rows) with scheduled startup catch-up. Use
//! `benches/stats_bench.rs` or a production-sized database for capacity
//! testing. This is a documented residual rather than an untested claim.
//!
//! # `stats_watermark`
//!
//! The table is still written on every aggregated chunk, but it is **not read
//! to decide which rows to aggregate**. That is deliberate: the aggregate read,
//! rollup upsert, watermark update and delete share one transaction, so a row
//! can never be deleted without being aggregated, and re-inserted/backdated
//! rows must be re-aggregated rather than skipped by an `id > watermark`
//! predicate. The writes are retained as a bounded progress/diagnostic record
//! and for compatibility with the v1.9 schema (and its tests); removing them is
//! a schema/behavior change deferred to a later cleanup. See
//! `test_retention_watermark_prevents_double_counting` and
//! `test_retention_aggregates_backdated_rows_after_watermark`.

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
        self.cleanup_retention_inner(retention_days, None, self.rollup_client_names_enabled())
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
            self.rollup_client_names_enabled(),
        )
        .await
    }

    /// Full retention sweep with explicit rollup policy.
    ///
    /// Detailed query-log rows are processed in bounded hour buckets, each in
    /// its own short `BEGIN IMMEDIATE` transaction. Expired `stats_hourly`
    /// rows (and therefore their domains and hashed client identifiers) are
    /// removed separately according to `rollup_retention_days`.
    ///
    /// `rollup_client_names` is the caller's captured policy. The live
    /// [`Self::set_rollup_client_names`] policy is authoritative: a live
    /// `false` overrides a captured `true` at merge/write time, so this
    /// argument cannot re-insert names after a live scrub.
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
            // double counting. A scrub may land between this read and the
            // chunk transaction; `merge_hour_rollup` re-reads the live policy
            // inside the transaction and strips names, so the stale snapshot
            // cannot resurrect them.
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
        // The caller's bool is the policy captured when the sweep was
        // scheduled. The live atomic is authoritative at write time: a
        // `set_rollup_client_names(false)` that lands while a sweep is in
        // flight must not be undone by this chunk re-inserting names.
        let allow_names = rollup_client_names && self.rollup_client_names_enabled();
        for client in &mut rollup.clients {
            client.0 = self.hash_client_ip(&client.0);
            if !allow_names {
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
        // Read the live policy once at merge time, inside the caller's write
        // transaction (retention chunks and the keep-aggregates clear both
        // hold `BEGIN IMMEDIATE`). A concurrent policy flip either happens
        // before this read (so names are stripped here) or after the commit
        // (so the scrub that follows the flip sees this row).
        let allow_names = rollup_client_names && self.rollup_client_names_enabled();
        let mut rollup = self.normalize_hour_rollup(rollup, allow_names);
        let (existing_domains, existing_clients, existing_upstreams) = existing;

        let mut existing_clients: Vec<ClientTop> = decode_tops(existing_clients.as_deref());
        for client in &mut existing_clients {
            client.0 = self.hash_client_ip(&client.0);
            if !allow_names {
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
    /// exactly those rows, in bounded chunks.
    ///
    /// Used by the explicit `keep_aggregates` clear path. The oldest remaining
    /// row is discovered with an indexed `MIN(ts)`; its hour is processed in
    /// row-bounded `(ts, id)` chunks of [`RETENTION_ROWS_PER_CHUNK`], then the
    /// loop repeats for the next remaining hour. Each chunk is its own
    /// `BEGIN IMMEDIATE` transaction (see [`Self::rollup_and_delete_chunk`]),
    /// so the writer lock is bounded by one chunk rather than the whole range,
    /// and memory is bounded to roughly one hour of distinct values in the
    /// per-connection temp tables.
    ///
    /// A committed chunk has already written the rollup contributions of the
    /// rows it deleted, so an interrupted clear leaves a consistent prefix.
    /// Re-running the clear starts again at the oldest remaining hour, merges
    /// the remaining rows into the stored rollups and finishes the clear
    /// without double counting: per-chunk counters are added, while the top
    /// lists are replaced with `existing + cumulative temp counts`.
    pub(super) async fn rollup_and_delete_range(
        &self,
        start: i64,
        end: i64,
        rollup_client_names: bool,
    ) -> Result<RetentionReport, StatsError> {
        let mut report = RetentionReport::default();
        let mut conn = self.pool.acquire().await?;
        Self::ensure_retention_temp_tables(&mut conn).await?;
        // A previous interrupted run may have left rows on this pooled
        // connection. The temp tables are only an in-flight accumulator; the
        // durable contributions live in `stats_hourly` after each commit.
        Self::clear_retention_temp_all(&mut conn).await?;

        loop {
            // The oldest row still inside the requested range. After each hour
            // is deleted this walks forward, so the scan never revisits a
            // processed hour unless a concurrent producer backdates a row into
            // it (the service is documented as stopped for this operation).
            let next_ts: Option<i64> =
                sqlx::query_scalar("SELECT MIN(ts) FROM query_log WHERE ts >= ? AND ts < ?")
                    .bind(start)
                    .bind(end)
                    .fetch_one(&mut *conn)
                    .await?;
            let Some(next_ts) = next_ts else { break };

            // `div_euclid` floors negative timestamps too, so a negative `ts`
            // row cannot produce an hour bucket above the row and spin forever.
            let hour = next_ts.div_euclid(3_600_000) * 3_600_000;
            let hour_start = hour.max(start);
            let hour_end = hour.saturating_add(3_600_000).min(end);
            if hour_end <= hour_start || next_ts >= hour_end {
                // Only reachable for a malformed timestamp at the very top of
                // `i64`, where the exclusive upper bound saturates to
                // `i64::MAX` (the previous whole-range path also left
                // `i64::MAX` itself outside the range). Stop rather than loop
                // forever.
                break;
            }

            // Accumulate exact per-hour counts across chunks. The table is
            // cleared per hour, so its size is bounded by one hour of distinct
            // domains/clients/upstreams, not the whole clear range.
            Self::clear_retention_temp_hour(&mut conn, hour).await?;

            // Snapshot the pre-clear top lists once per hour. Each chunk writes
            // `pre_clear + cumulative temp counts` (replacing the previous
            // chunk's value), so writing every chunk is crash-safe without
            // double counting. A live `rollup_client_names` flip is still
            // honoured because `merge_hour_rollup` re-reads the live policy
            // inside each chunk transaction.
            let existing_rollups = load_existing_rollups(&mut conn, &[hour]).await?;
            let existing_tops = existing_rollups.get(&hour).cloned().unwrap_or_default();

            let hour_upper = (hour_end, i64::MIN);
            let mut lower = (hour_start, i64::MIN);
            loop {
                // The first `(ts, id)` row past this chunk, if any. The
                // `(ts, id)` index supports this cursor without a temp B-tree.
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
                report.deleted_records = report.deleted_records.saturating_add(deleted);
                report.chunks = report.chunks.saturating_add(1);

                if done {
                    break;
                }
                lower = upper;
            }
            report.aggregated_hours = report.aggregated_hours.saturating_add(1);
        }

        Ok(report)
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
                   SUM(CASE WHEN rcode IS NOT NULL AND rcode NOT IN (0, 3) THEN 1 ELSE 0 END),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::QueryLogEntry;

    const HOUR_MS: i64 = 3_600_000;

    fn hour_of(ts: i64) -> i64 {
        ts.div_euclid(HOUR_MS) * HOUR_MS
    }

    fn entry(ts: i64, qname: &str, verdict: &str) -> QueryLogEntry {
        QueryLogEntry {
            id: None,
            ts,
            client_ip: "10.0.0.1".into(),
            client_name: None,
            qname: qname.into(),
            qtype: 1,
            rcode: Some(0),
            verdict: verdict.into(),
            rule: None,
            list_source: None,
            upstream: None,
            elapsed_us: None,
            dnssec: None,
            proto: "udp".into(),
        }
    }

    async fn detailed_rows(db: &StatsDb) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM query_log")
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn hour_totals(db: &StatsDb, hour: i64) -> (i64, i64, i64) {
        sqlx::query_as("SELECT queries, blocked, cached FROM stats_hourly WHERE hour = ?")
            .bind(hour)
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn hour_top_domains(db: &StatsDb, hour: i64) -> Vec<(String, i64, i64)> {
        let payload: String =
            sqlx::query_scalar("SELECT top_domains FROM stats_hourly WHERE hour = ?")
                .bind(hour)
                .fetch_one(db.pool())
                .await
                .unwrap();
        serde_json::from_str(&payload).unwrap()
    }

    /// B5: a multi-hour clear deletes every detailed row, folds each hour into
    /// its own rollup, and preserves a rollup that already existed for an hour
    /// (`existing + cleared`, not replacing it).
    #[tokio::test]
    async fn test_keep_aggregates_clear_chunks_multiple_hours_and_preserves_rollups() {
        let db = StatsDb::in_memory().await.unwrap();
        let h0 = hour_of(1_600_000_000_000);
        let h1 = h0 + HOUR_MS;
        let h2 = h0 + 2 * HOUR_MS;

        // Pre-existing rollup for h0 must survive and be added to, not
        // replaced by, the clear's contribution.
        sqlx::query(
            "INSERT INTO stats_hourly (hour, queries, blocked, cached, top_domains, top_clients, top_upstreams) \
             VALUES (?, 7, 2, 1, ?, '[]', '[]')",
        )
        .bind(h0)
        .bind(r#"[["pre-existing.example",5,2]]"#)
        .execute(db.pool())
        .await
        .unwrap();

        let mut entries = vec![
            entry(h0 + 1, "a.example", "allowed"),
            entry(h0 + 2, "a.example", "blocked"),
            entry(h0 + 3, "b.example", "allowed"),
        ];
        entries.push(entry(h1 + 1, "c.example", "allowed"));
        let mut cached = entry(h2 + 1, "d.example", "allowed");
        cached.rule = Some("cache".into());
        entries.push(cached);
        entries.push(entry(h2 + 2, "d.example", "blocked"));
        db.insert_batch(&entries).await.unwrap();

        let report = db
            .rollup_and_delete_range(i64::MIN, i64::MAX, false)
            .await
            .unwrap();
        assert_eq!(report.deleted_records, 6);
        assert_eq!(report.aggregated_hours, 3);
        assert_eq!(report.chunks, 3, "one small chunk per hour");
        assert_eq!(detailed_rows(&db).await, 0);

        let (q0, b0, c0) = hour_totals(&db, h0).await;
        assert_eq!(q0, 7 + 3, "pre-existing rollup totals are preserved");
        assert_eq!(b0, 2 + 1);
        assert_eq!(c0, 1);
        let tops = hour_top_domains(&db, h0).await;
        assert_eq!(
            tops.first(),
            Some(&("pre-existing.example".to_string(), 5, 2)),
            "the pre-clear top list must be merged, not dropped: {tops:?}"
        );
        assert_eq!(
            tops.iter().find(|(qname, _, _)| qname == "a.example"),
            Some(&("a.example".to_string(), 2, 1)),
            "cleared rows are folded once into the existing rollup: {tops:?}"
        );

        assert_eq!(hour_totals(&db, h1).await, (1, 0, 0));
        assert_eq!(hour_totals(&db, h2).await, (2, 1, 1));
        assert_eq!(
            hour_top_domains(&db, h2).await.first(),
            Some(&("d.example".to_string(), 2, 1))
        );
    }

    /// B5: one hour larger than the chunk size is processed in bounded chunks
    /// and aggregated exactly once (no duplicate totals or top-list entries).
    #[tokio::test]
    async fn test_keep_aggregates_clear_sub_chunks_a_busy_hour() {
        let db = StatsDb::in_memory().await.unwrap();
        let hour = hour_of(1_600_000_000_000);
        let rows = 2 * RETENTION_ROWS_PER_CHUNK + 3;

        let entries: Vec<QueryLogEntry> = (0..rows)
            .map(|i| {
                entry(
                    hour + i,
                    "busy.example",
                    if i % 2 == 0 { "blocked" } else { "allowed" },
                )
            })
            .collect();
        db.insert_batch(&entries).await.unwrap();

        let report = db
            .rollup_and_delete_range(i64::MIN, i64::MAX, false)
            .await
            .unwrap();
        assert_eq!(report.deleted_records, u64::try_from(rows).unwrap());
        assert_eq!(report.aggregated_hours, 1);
        assert_eq!(
            report.chunks, 3,
            "{rows} rows must be split into 5,000-row chunks"
        );
        assert_eq!(detailed_rows(&db).await, 0);

        let blocked = (rows + 1) / 2;
        assert_eq!(
            hour_totals(&db, hour).await,
            (rows, blocked, 0),
            "the busy hour must be counted exactly once"
        );
        assert_eq!(
            hour_top_domains(&db, hour).await,
            vec![("busy.example".to_string(), rows, blocked)],
            "chunk boundaries must not duplicate a domain's counts"
        );
    }

    /// B5: a backdated row inserted after a clear is re-aggregated exactly
    /// once, and a second clear is idempotent.
    #[tokio::test]
    async fn test_keep_aggregates_clear_reaggregates_backdated_rows_once() {
        let db = StatsDb::in_memory().await.unwrap();
        let hour = hour_of(1_600_000_000_000);
        db.insert_batch(&[
            entry(hour + 100, "backdated.example", "allowed"),
            entry(hour + 200, "backdated.example", "allowed"),
        ])
        .await
        .unwrap();

        assert_eq!(db.delete_query_logs_keep_aggregates().await.unwrap(), 2);
        assert_eq!(hour_totals(&db, hour).await, (2, 0, 0));

        // A stale, too-high watermark must not make the backdated row look
        // already aggregated; the clear never reads it to skip rows.
        sqlx::query(
            "UPDATE stats_watermark SET last_id = 1000000 WHERE key = 'hourly_aggregation'",
        )
        .execute(db.pool())
        .await
        .unwrap();
        db.insert_batch(&[entry(hour + 50, "backdated.example", "blocked")])
            .await
            .unwrap();

        assert_eq!(db.delete_query_logs_keep_aggregates().await.unwrap(), 1);
        assert_eq!(hour_totals(&db, hour).await, (3, 1, 0));
        assert_eq!(
            hour_top_domains(&db, hour).await,
            vec![("backdated.example".to_string(), 3, 1)],
            "the backdated row must be added once, not re-counted"
        );
        assert_eq!(detailed_rows(&db).await, 0);

        // Idempotent rerun: nothing left to aggregate, no totals change.
        assert_eq!(db.delete_query_logs_keep_aggregates().await.unwrap(), 0);
        assert_eq!(hour_totals(&db, hour).await, (3, 1, 0));
    }

    /// B5: a failure in a later chunk keeps the earlier committed chunks and
    /// their rollup contributions; a rerun finishes without double counting.
    #[tokio::test]
    async fn test_keep_aggregates_clear_resumes_after_mid_run_failure() {
        let db = StatsDb::in_memory().await.unwrap();
        let h0 = hour_of(1_600_000_000_000);
        let h1 = h0 + HOUR_MS;

        // Three full chunks in h0 so the injected failure lands on its third
        // chunk, after two chunks of the same hour have committed.
        let rows: i64 = 3 * RETENTION_ROWS_PER_CHUNK;
        let mut entries: Vec<QueryLogEntry> = (0..rows)
            .map(|i| entry(h0 + i, "resume.example", "allowed"))
            .collect();
        entries.push(entry(h1 + 1, "later.example", "allowed"));
        entries.push(entry(h1 + 2, "later.example", "blocked"));
        db.insert_batch(&entries).await.unwrap();

        // Fail the third `stats_hourly` upsert, i.e. h0's third chunk. Each
        // chunk executes exactly one upsert, so the counter counts chunks.
        sqlx::query("CREATE TABLE clear_fail_counter (n INTEGER NOT NULL)")
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO clear_fail_counter (n) VALUES (0)")
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query(
            r"
            CREATE TRIGGER fail_clear_third_chunk
            BEFORE INSERT ON stats_hourly
            BEGIN
                UPDATE clear_fail_counter SET n = n + 1;
                SELECT CASE
                    WHEN (SELECT n FROM clear_fail_counter) > 2
                    THEN RAISE(ABORT, 'injected clear failure')
                END;
            END
            ",
        )
        .execute(db.pool())
        .await
        .unwrap();

        let err = db.rollup_and_delete_range(i64::MIN, i64::MAX, false).await;
        assert!(err.is_err(), "the injected failure must surface");

        // Two h0 chunks committed before the failure; the third chunk rolled
        // back atomically and h1 was never reached.
        let committed_rows = 2 * RETENTION_ROWS_PER_CHUNK;
        assert_eq!(detailed_rows(&db).await, rows + 2 - committed_rows);
        assert_eq!(hour_totals(&db, h0).await, (committed_rows, 0, 0));
        let h1_rollups: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM stats_hourly WHERE hour = ?")
                .bind(h1)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(h1_rollups, 0);

        sqlx::query("DROP TRIGGER fail_clear_third_chunk")
            .execute(db.pool())
            .await
            .unwrap();

        let report = db
            .rollup_and_delete_range(i64::MIN, i64::MAX, false)
            .await
            .unwrap();
        assert_eq!(
            report.deleted_records,
            u64::try_from(rows + 2 - committed_rows).unwrap()
        );
        assert_eq!(report.aggregated_hours, 2);
        assert_eq!(report.chunks, 2, "remaining h0 chunk plus all of h1");
        assert_eq!(detailed_rows(&db).await, 0);

        assert_eq!(
            hour_totals(&db, h0).await,
            (rows, 0, 0),
            "resuming must add only the remaining rows, not re-add committed chunks"
        );
        assert_eq!(hour_totals(&db, h1).await, (2, 1, 0));
        assert_eq!(
            hour_top_domains(&db, h0).await,
            vec![("resume.example".to_string(), rows, 0)]
        );
    }

    /// B5 guard: the default clear path is untouched. It still deletes the
    /// detailed rows and all rollups (including a pre-existing one) instead of
    /// folding anything.
    #[tokio::test]
    async fn test_default_clear_still_deletes_rows_and_rollups_across_hours() {
        let db = StatsDb::in_memory().await.unwrap();
        let h0 = hour_of(1_600_000_000_000);
        let h1 = h0 + HOUR_MS;

        sqlx::query(
            "INSERT INTO stats_hourly (hour, queries, blocked, cached, top_domains, top_clients, top_upstreams) \
             VALUES (?, 7, 2, 1, '[]', '[]', '[]')",
        )
        .bind(h0)
        .execute(db.pool())
        .await
        .unwrap();

        db.insert_batch(&[
            entry(h0 + 1, "default-clear.example", "allowed"),
            entry(h0 + 2, "default-clear.example", "blocked"),
            entry(h1 + 1, "default-clear.example", "allowed"),
        ])
        .await
        .unwrap();

        assert_eq!(db.delete_query_logs().await.unwrap(), 3);
        assert_eq!(detailed_rows(&db).await, 0);
        let rollups: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stats_hourly")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(rollups, 0, "the default clear must not preserve rollups");
        let watermark: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM stats_watermark WHERE key = 'hourly_aggregation'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(watermark, 0);
    }

    /// B5: a malformed `i64::MAX` timestamp must not make hour discovery spin
    /// forever. The reachable rows are still cleared (the old whole-range path
    /// also left `i64::MAX` itself outside its exclusive upper bound).
    #[tokio::test]
    async fn test_keep_aggregates_clear_terminates_on_max_timestamp_row() {
        let db = StatsDb::in_memory().await.unwrap();
        let hour = hour_of(1_600_000_000_000);
        db.insert_batch(&[
            entry(hour + 1, "normal.example", "allowed"),
            entry(i64::MAX, "pathological.example", "allowed"),
        ])
        .await
        .unwrap();

        let report = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            db.rollup_and_delete_range(i64::MIN, i64::MAX, false),
        )
        .await
        .expect("hour discovery must not spin on an i64::MAX timestamp")
        .unwrap();
        assert_eq!(report.deleted_records, 1);
        assert_eq!(report.aggregated_hours, 1);
        assert_eq!(detailed_rows(&db).await, 1);
        assert_eq!(hour_totals(&db, hour).await, (1, 0, 0));
    }

    /// B5: a large keep-aggregates clear vacuums and truncates the WAL after
    /// the final chunk, and leaves `secure_delete` enabled.
    #[tokio::test]
    async fn test_keep_aggregates_clear_vacuums_and_truncates_wal() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito-stats-clear-agg-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let db = StatsDb::open(&db_path).await.unwrap();

        let hour = hour_of(1_600_000_000_000);
        let padding = "x".repeat(200);
        let mut entries = Vec::new();
        for i in 0..3_000i64 {
            let mut entry = entry(hour + i, "vacuum-clear.example", "allowed");
            entry.client_ip = format!("10.{}.{}.{}", i / 65_536, (i / 256) % 256, i % 256);
            entry.rule = Some(format!("{padding}-{i}"));
            entries.push(entry);
        }
        db.insert_batch(&entries).await.unwrap();
        db.vacuum().await.unwrap();
        let before = db.db_size_bytes().await.unwrap();

        let deleted = db.delete_query_logs_keep_aggregates().await.unwrap();
        assert_eq!(deleted, 3_000);
        assert_eq!(hour_totals(&db, hour).await, (3_000, 0, 0));

        let secure_delete: i64 = sqlx::query_scalar("PRAGMA secure_delete")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(secure_delete, 1, "secure_delete must stay enabled");
        let freelist: i64 = sqlx::query_scalar("PRAGMA freelist_count")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(freelist, 0, "VACUUM must return the cleared pages");

        let after = db.db_size_bytes().await.unwrap();
        assert!(
            after < before,
            "a large keep-aggregates clear must vacuum \
             (before={before}, after={after})"
        );
        let wal_path = temp_dir.join("stats.db-wal");
        if let Ok(meta) = std::fs::metadata(&wal_path) {
            assert_eq!(meta.len(), 0, "the WAL must be truncated after the clear");
        }

        db.pool().close().await;
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
