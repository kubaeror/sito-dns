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
//! most one hour of distinct domains/clients/upstreams. The top-list
//! accumulator is cumulative for the hour (not cleared per chunk), so a heavy
//! hitter below a chunk-local top-N but in the hour's top-N is preserved; the
//! counters themselves are added per chunk and never double count. Every
//! committed chunk already contains the rollup contributions of the rows it
//! deleted, so a crash or interruption loses only the uncommitted chunk and
//! re-running the clear safely continues from the oldest remaining row.
//!
//! A clear chunk re-reads the current `stats_hourly` row **inside** its
//! transaction. It merges the pre-clear snapshot plus the run's cumulative temp
//! counts, and adds any positive-only top-list delta made by another writer
//! between chunks (normally impossible under the shared maintenance lock, but
//! preserved defensively). A zero-row chunk is ignored: it never creates or
//! increments a rollup. If a rollup row existed at hour start but was deleted
//! mid-run (rollup retention), later chunks delete the detailed rows without
//! resurrecting it.
//!
//! Top-list exactness has one documented bounded-summary limit across a
//! **failed** run: the last committed chunk stores only the hour's top-N, so an
//! entity that was below that bounded snapshot at the interruption point cannot
//! be recovered by the retry (only its remaining chunks are counted). Totals
//! (queries/blocked/cached) stay exact, and an uninterrupted run matches
//! retention's cumulative top-N behavior.
//!
//! [`StatsDb::cleanup_retention_inner`] and this clear share an in-process
//! maintenance lock, so a live API/UI clear cannot interleave with the
//! retention scheduler and overwrite its top lists. The CLI clear additionally
//! takes the service lease and refuses a live server (unless `--force`); the
//! API path cannot stop the writer, so a row inserted after its hour was
//! processed can survive until the next clear/retention. Use the stopped CLI
//! path when a complete clear is required.
//!
//! Chunking no longer makes the clear atomic across the whole range (it never
//! could without one long transaction); it is atomic *per chunk*: the
//! aggregate read, temp-table accumulation, rollup merge/upsert, watermark
//! update and delete of those rows share one transaction. A row is therefore
//! never deleted without its rollup contribution being committed.
//!
//! # Scale residual (90 days / 1M rows)
//!
//! `test_retention_handles_multiple_hours_across_days` covers a multi-day,
//! multi-hour sweep. The 1M-row/90-day capacity evidence lives in the
//! `#[ignore]`d `db::capacity_tests` module (it would dominate CI), which runs
//! retention and the chunked clear on a deterministic 1M-row fixture and
//! asserts exact rollup totals, one committed chunk per ceil(rows/5,000), and
//! bounded process memory. The chunking keeps each write transaction bounded
//! and the total sweep remains O(rows) with scheduled startup catch-up.
//! Measured dev-host results are recorded in `docs/2.0-migration.md`; they are
//! not a production SLA.
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
        // Serialize with the keep-aggregates clear (including a live API/UI
        // clear). Both paths read existing rollup state and then replace top
        // lists; interleaving would let one overwrite the other's contribution.
        let _maintenance = self.maintenance_lock.lock().await;

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

            // `hour_bounds` floors negative timestamps and clamps only the
            // unrepresentable edges of `i64`, so it cannot panic or wrap for
            // `i64::MIN`.
            let (hour, bucket_end) = hour_bounds(next_ts);
            let end = bucket_end.min(cutoff);
            if end <= hour || next_ts < hour {
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
            let mut chunk_base = ChunkRollupBase::Snapshot(&existing_tops);

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
                        &mut chunk_base,
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

    /// Adds external-only top-list deltas to an already merged hour rollup.
    ///
    /// The keep-aggregates clear rebuilds the hour's top lists from its
    /// pre-clear snapshot plus cumulative temp counts on every chunk. If
    /// another writer updated the live row between chunks (normally impossible
    /// under the shared maintenance lock, but possible for an out-of-process
    /// writer), the positive-only delta is accumulated in
    /// [`ClearRollupState::external`] and merged here so it is not replaced.
    fn merge_external_rollup(
        &self,
        mut merged: HourRollup,
        external: &HourRollup,
        rollup_client_names: bool,
    ) -> HourRollup {
        if external.domains.is_empty()
            && external.clients.is_empty()
            && external.upstreams.is_empty()
        {
            return merged;
        }
        let external = self.normalize_hour_rollup(external.clone(), rollup_client_names);
        merged.domains = merge_domain_tops(merged.domains, external.domains, ROLLUP_TOP_N * 2);
        merged.clients = merge_client_tops(merged.clients, external.clients, ROLLUP_TOP_N);
        merged.upstreams = merge_upstream_tops(merged.upstreams, external.upstreams, ROLLUP_TOP_N);
        merged
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
    /// Re-running the clear starts again at the oldest remaining hour and adds
    /// only that run's remaining rows. The top-list accumulator is cumulative
    /// for the hour, so heavy hitters below a chunk-local top-N survive. Each
    /// chunk re-reads the current `stats_hourly` row inside its own transaction
    /// to preserve a concurrent update and to avoid resurrecting a deleted
    /// row; counters are added per chunk and top lists are a merged summary.
    /// A failed run's stored top-N is bounded, so an entity below it at the
    /// failure point cannot be recovered by the retry (documented residual).
    pub(super) async fn rollup_and_delete_range(
        &self,
        start: i64,
        end: i64,
        rollup_client_names: bool,
    ) -> Result<RetentionReport, StatsError> {
        // Serialize with retention. The API/UI clear runs while the server (and
        // its retention scheduler) is live; without this lock a sweep could
        // replace the top lists this clear just merged, or delete a rollup row
        // the clear is about to update.
        let _maintenance = self.maintenance_lock.lock().await;

        let mut report = RetentionReport::default();
        let mut conn = self.pool.acquire().await?;
        Self::ensure_retention_temp_tables(&mut conn).await?;
        // A previous interrupted run may have left rows on this pooled
        // connection. The temp tables are only an in-flight accumulator; the
        // durable contributions live in `stats_hourly` after each commit.
        Self::clear_retention_temp_all(&mut conn).await?;

        loop {
            // The oldest row still inside the requested range. After each hour
            // is deleted this walks forward. A producer inserting a backdated
            // row into an already-processed hour is picked up on the next
            // iteration (the API/UI clear runs live; the CLI path holds the
            // service lease).
            let next_ts: Option<i64> =
                sqlx::query_scalar("SELECT MIN(ts) FROM query_log WHERE ts >= ? AND ts < ?")
                    .bind(start)
                    .bind(end)
                    .fetch_one(&mut *conn)
                    .await?;
            let Some(next_ts) = next_ts else { break };

            // `hour_bounds` floors negative timestamps and clamps only the
            // unrepresentable edges of `i64`, so it cannot panic or wrap for
            // `i64::MIN`.
            let (hour, bucket_end) = hour_bounds(next_ts);
            let hour_start = hour.max(start);
            let hour_end = bucket_end.min(end);
            if hour_end <= hour_start || next_ts < hour_start || next_ts >= hour_end {
                // Only reachable for a malformed timestamp at the very top of
                // `i64`, where the exclusive upper bound saturates to
                // `i64::MAX` (the previous whole-range path also left
                // `i64::MAX` itself outside the range). Stop rather than loop
                // forever.
                break;
            }

            // Whether this hour already has a rollup row before the clear
            // touches it. If it does and the row disappears while the clear is
            // running (rollup retention), later chunks must not resurrect it.
            let hour_had_rollup: i64 =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM stats_hourly WHERE hour = ?)")
                    .bind(hour)
                    .fetch_one(&mut *conn)
                    .await?;

            // Top lists are cumulative for the hour (the temp tables are not
            // cleared per chunk), so a domain below the chunk-local top-N but
            // in the hour's top-N is not dropped. Counters are still added per
            // chunk, so totals do not double count.
            Self::clear_retention_temp_hour(&mut conn, hour).await?;
            let existing = load_existing_rollups(&mut conn, &[hour])
                .await?
                .get(&hour)
                .cloned()
                .unwrap_or_default();
            let mut clear_state = ClearRollupState {
                existing,
                external: HourRollup::default(),
                last_written: None,
                allow_insert: hour_had_rollup == 0,
            };

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

                let mut base = ChunkRollupBase::CurrentRow(&mut clear_state);
                let deleted = self
                    .rollup_and_delete_chunk(
                        &mut conn,
                        &RetentionChunk { hour, lower, upper },
                        &mut base,
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
    ///
    /// `base` selects how the chunk's top lists are merged:
    /// [`ChunkRollupBase::Snapshot`] for retention's cumulative sweep, and
    /// [`ChunkRollupBase::CurrentRow`] for the keep-aggregates clear, which uses
    /// the run's cumulative temp counts plus the pre-clear snapshot (and any
    /// external top-list delta observed between chunks).
    pub(super) async fn rollup_and_delete_chunk(
        &self,
        conn: &mut SqliteConnection,
        chunk: &RetentionChunk,
        base: &mut ChunkRollupBase<'_>,
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

        // A bounded clear can discover a chunk whose rows were removed by a
        // concurrent writer. Do not create or increment a rollup for zero rows.
        if queries == 0 && matches!(base, ChunkRollupBase::CurrentRow(_)) {
            drop(tx);
            return Ok(0);
        }

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
        // contributions of the deleted rows are already durable. The top lists
        // are cumulative for the hour, so a heavy hitter below a chunk-local
        // top-N is not dropped; counters below are still per-chunk deltas.
        let tops = Self::load_temp_hour_tops(&mut tx, hour).await?;
        let mut write_rollup = true;
        let merged = match base {
            ChunkRollupBase::Snapshot(snapshot) => {
                self.merge_hour_rollup((*snapshot).clone(), tops, rollup_client_names)
            }
            ChunkRollupBase::CurrentRow(state) => {
                // Re-read inside this transaction so a row deleted between
                // chunks is not resurrected and an external top-list update is
                // captured rather than overwritten.
                let current: Option<StoredTops> = sqlx::query_as(
                    r"
                    SELECT top_domains, top_clients, top_upstreams
                    FROM stats_hourly WHERE hour = ?
                    ",
                )
                .bind(hour)
                .fetch_optional(&mut *tx)
                .await?;
                match current {
                    Some(stored) => {
                        if let Some(last_written) = state.last_written.as_ref() {
                            accumulate_external_delta(&mut state.external, &stored, last_written);
                        }
                        let base_merged = self.merge_hour_rollup(
                            state.existing.clone(),
                            tops,
                            rollup_client_names,
                        );
                        self.merge_external_rollup(
                            base_merged,
                            &state.external,
                            rollup_client_names,
                        )
                    }
                    None => {
                        if state.allow_insert {
                            let base_merged = self.merge_hour_rollup(
                                StoredTops::default(),
                                tops,
                                rollup_client_names,
                            );
                            self.merge_external_rollup(
                                base_merged,
                                &state.external,
                                rollup_client_names,
                            )
                        } else {
                            // The row was deleted after this clear observed it
                            // (for example by rollup retention). Delete the
                            // detailed rows but do not resurrect it.
                            write_rollup = false;
                            HourRollup::default()
                        }
                    }
                }
            }
        };
        if write_rollup {
            let encoded = (
                encode_tops(&merged.domains),
                encode_tops(&merged.clients),
                encode_tops(&merged.upstreams),
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
            .bind(&encoded.0)
            .bind(&encoded.1)
            .bind(&encoded.2)
            .execute(&mut *tx)
            .await?;
            if let ChunkRollupBase::CurrentRow(state) = base {
                state.last_written = Some((Some(encoded.0), Some(encoded.1), Some(encoded.2)));
                state.allow_insert = false;
            }
        }

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

/// Accumulates positive-only top-list deltas between two stored snapshots.
///
/// Used only by the keep-aggregates clear's external-update guard. Counts that
/// decreased are ignored: our own cumulative temp counts are authoritative for
/// the rows this clear deletes, while an external writer can only add rows'
/// contributions.
fn accumulate_external_delta(
    external: &mut HourRollup,
    current: &StoredTops,
    last_written: &StoredTops,
) {
    let previous_domains: Vec<DomainTop> = decode_tops(last_written.0.as_deref());
    let previous: HashMap<&str, (i64, i64)> = previous_domains
        .iter()
        .map(|(qname, total, blocked)| (qname.as_str(), (*total, *blocked)))
        .collect();
    for (qname, total, blocked) in decode_tops::<DomainTop>(current.0.as_deref()) {
        let (prev_total, prev_blocked) = previous.get(qname.as_str()).copied().unwrap_or((0, 0));
        let total = total.saturating_sub(prev_total).max(0);
        let blocked = blocked.saturating_sub(prev_blocked).max(0);
        if total > 0 || blocked > 0 {
            external.domains.push((qname, total, blocked));
        }
    }

    let previous_clients: Vec<ClientTop> = decode_tops(last_written.1.as_deref());
    let previous: HashMap<&str, (i64, i64, i64)> = previous_clients
        .iter()
        .map(|(client_ip, _, total, blocked, last_seen)| {
            (client_ip.as_str(), (*total, *blocked, *last_seen))
        })
        .collect();
    for (client_ip, client_name, total, blocked, last_seen) in
        decode_tops::<ClientTop>(current.1.as_deref())
    {
        let (prev_total, prev_blocked, prev_last_seen) = previous
            .get(client_ip.as_str())
            .copied()
            .unwrap_or((0, 0, 0));
        let total = total.saturating_sub(prev_total).max(0);
        let blocked = blocked.saturating_sub(prev_blocked).max(0);
        let last_seen = if last_seen > prev_last_seen {
            last_seen
        } else {
            0
        };
        if total > 0 || blocked > 0 || last_seen > 0 {
            external
                .clients
                .push((client_ip, client_name, total, blocked, last_seen));
        }
    }

    let previous_upstreams: Vec<UpstreamTop> = decode_tops(last_written.2.as_deref());
    let previous: HashMap<&str, (i64, i64, i64)> = previous_upstreams
        .iter()
        .map(|(upstream, total, errors, elapsed_sum)| {
            (upstream.as_str(), (*total, *errors, *elapsed_sum))
        })
        .collect();
    for (upstream, total, errors, elapsed_sum) in decode_tops::<UpstreamTop>(current.2.as_deref()) {
        let (prev_total, prev_errors, prev_elapsed) = previous
            .get(upstream.as_str())
            .copied()
            .unwrap_or((0, 0, 0));
        let total = total.saturating_sub(prev_total).max(0);
        let errors = errors.saturating_sub(prev_errors).max(0);
        let elapsed_sum = elapsed_sum.saturating_sub(prev_elapsed).max(0);
        if total > 0 || errors > 0 || elapsed_sum > 0 {
            external
                .upstreams
                .push((upstream, total, errors, elapsed_sum));
        }
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

        // The watermark is a diagnostic: it records the highest id/ts seen and
        // a backdated (older-ts) row must not lower it. It is never read to
        // skip rows.
        let (last_id, last_ts): (i64, i64) = sqlx::query_as(
            "SELECT last_id, last_ts FROM stats_watermark WHERE key = 'hourly_aggregation'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert!(last_id > 0);
        assert_eq!(
            last_ts,
            hour + 200,
            "the watermark keeps the highest processed timestamp"
        );

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

    /// B5 fix: `i64::MIN` and negative timestamps must neither panic nor wrap.
    /// The unrepresentable bucket below `i64::MIN` is clamped, negative
    /// timestamps are floored, and exact hour-boundary rows land in the right
    /// bucket.
    #[tokio::test]
    async fn test_keep_aggregates_clear_handles_extreme_and_boundary_timestamps() {
        let db = StatsDb::in_memory().await.unwrap();
        let h = hour_of(1_600_000_000_000);
        db.insert_batch(&[
            entry(i64::MIN, "min.example", "allowed"),
            entry(i64::MIN + 1, "min.example", "blocked"),
            entry(i64::MIN + HOUR_MS - 1, "min.example", "allowed"),
            entry(i64::MIN + HOUR_MS, "next-min.example", "allowed"),
            entry(-1, "neg-zero.example", "allowed"),
            entry(-HOUR_MS, "neg-hour.example", "blocked"),
            entry(-HOUR_MS - 1, "neg-prev.example", "allowed"),
            entry(h, "boundary.example", "allowed"),
            entry(h + HOUR_MS - 1, "boundary.example", "allowed"),
            entry(h + HOUR_MS, "next-boundary.example", "allowed"),
            entry(h + HOUR_MS + 1, "next-boundary.example", "blocked"),
        ])
        .await
        .unwrap();

        let report = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            db.rollup_and_delete_range(i64::MIN, i64::MAX, false),
        )
        .await
        .expect("i64::MIN must not panic or spin hour discovery")
        .unwrap();
        assert_eq!(report.deleted_records, 11);
        assert_eq!(report.aggregated_hours, 6);
        assert_eq!(detailed_rows(&db).await, 0);

        // The first 775,808 ms above `i64::MIN` belong to the unrepresentable
        // bucket below it and are clamped to `i64::MIN`; the next representable
        // bucket starts at `i64::MIN + 775_808` (`-9223372036854000000`).
        assert_eq!(hour_totals(&db, i64::MIN).await, (2, 1, 0));
        assert_eq!(hour_totals(&db, i64::MIN + 775_808).await, (2, 0, 0));
        assert_eq!(hour_totals(&db, -HOUR_MS).await, (2, 1, 0));
        assert_eq!(hour_totals(&db, -2 * HOUR_MS).await, (1, 0, 0));
        assert_eq!(hour_totals(&db, h).await, (2, 0, 0));
        assert_eq!(hour_totals(&db, h + HOUR_MS).await, (2, 1, 0));
    }

    /// B5 fix: the shared hour-bucket helper is also used by retention, so the
    /// retention sweep must handle `i64::MIN` and negative timestamps too.
    #[tokio::test]
    async fn test_retention_handles_extreme_and_negative_timestamps() {
        let db = StatsDb::in_memory().await.unwrap();
        db.insert_batch(&[
            entry(i64::MIN, "ret-min.example", "allowed"),
            entry(i64::MIN + 1, "ret-min.example", "blocked"),
            entry(-1, "ret-neg.example", "allowed"),
            entry(-HOUR_MS, "ret-neg.example", "allowed"),
        ])
        .await
        .unwrap();

        let report = db.cleanup_detailed_retention(90).await.unwrap();
        assert_eq!(report.deleted_records, 4);
        assert_eq!(report.aggregated_hours, 2);
        assert_eq!(detailed_rows(&db).await, 0);
        assert_eq!(hour_totals(&db, i64::MIN).await, (2, 1, 0));
        assert_eq!(hour_totals(&db, -HOUR_MS).await, (2, 0, 0));
    }

    /// B5 fix: after a mid-hour failure the stored rollup has partial top
    /// lists. The retry must merge the remaining chunks' cumulative counts
    /// into that stored row, not replace it with only the remaining rows (the
    /// 27 → 18 regression when the heavy hitter was already in the snapshot).
    #[tokio::test]
    async fn test_keep_aggregates_clear_resume_preserves_top_lists() {
        let db = StatsDb::in_memory().await.unwrap();
        let h = hour_of(1_600_000_000_000);
        let rows = 3 * RETENTION_ROWS_PER_CHUNK;

        // 27 heavy hits: 18 in the first two chunks, 9 in the failed third
        // chunk. A single-domain counter test cannot see the top-list loss.
        let mut heavy = std::collections::HashSet::new();
        for k in 0..18 {
            heavy.insert(k * 500);
        }
        for k in 0..9 {
            heavy.insert(10_000 + k * 500);
        }
        let entries: Vec<QueryLogEntry> = (0..rows)
            .map(|i| {
                if heavy.contains(&i) {
                    entry(h + i, "heavy.example", "allowed")
                } else {
                    entry(h + i, &format!("light-{i}.example"), "allowed")
                }
            })
            .collect();
        db.insert_batch(&entries).await.unwrap();

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

        assert!(
            db.rollup_and_delete_range(i64::MIN, i64::MAX, false)
                .await
                .is_err()
        );
        let partial = hour_top_domains(&db, h).await;
        assert_eq!(
            partial
                .iter()
                .find(|(qname, _, _)| qname == "heavy.example")
                .map(|(_, total, _)| *total),
            Some(18),
            "the two committed chunks must have stored 18 heavy hits: {partial:?}"
        );

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
            u64::try_from(RETENTION_ROWS_PER_CHUNK).unwrap()
        );
        assert_eq!(hour_totals(&db, h).await, (rows, 0, 0));
        let tops = hour_top_domains(&db, h).await;
        assert_eq!(
            tops.iter()
                .find(|(qname, _, _)| qname == "heavy.example")
                .map(|(_, total, _)| *total),
            Some(27),
            "the retry must add the remaining 9 heavy hits to the stored 18: {tops:?}"
        );
        assert_eq!(detailed_rows(&db).await, 0);
    }

    async fn run_clear_chunk(
        db: &StatsDb,
        hour: i64,
        lower: (i64, i64),
        upper: (i64, i64),
        allow_insert: bool,
    ) -> u64 {
        let mut conn = db.pool.acquire().await.unwrap();
        StatsDb::ensure_retention_temp_tables(&mut conn)
            .await
            .unwrap();
        StatsDb::clear_retention_temp_hour(&mut conn, hour)
            .await
            .unwrap();
        let existing = load_existing_rollups(&mut conn, &[hour])
            .await
            .unwrap()
            .get(&hour)
            .cloned()
            .unwrap_or_default();
        let mut state = ClearRollupState {
            existing,
            external: HourRollup::default(),
            last_written: None,
            allow_insert,
        };
        let mut base = ChunkRollupBase::CurrentRow(&mut state);
        db.rollup_and_delete_chunk(
            &mut conn,
            &RetentionChunk { hour, lower, upper },
            &mut base,
            true,
            false,
        )
        .await
        .unwrap()
    }

    /// B5 fix: a concurrent rollup writer (retention) may update `stats_hourly`
    /// between two clear chunks. The next chunk must merge that live row, not
    /// replace it with a pre-run snapshot.
    #[tokio::test]
    async fn test_keep_aggregates_clear_merges_concurrent_rollup_update() {
        let db = StatsDb::in_memory().await.unwrap();
        let h = hour_of(1_600_000_000_000);
        sqlx::query(
            "INSERT INTO stats_hourly (hour, queries, blocked, cached, top_domains, top_clients, top_upstreams) \
             VALUES (?, 5, 0, 0, ?, '[]', '[]')",
        )
        .bind(h)
        .bind(r#"[["baseline.example",5,0]]"#)
        .execute(db.pool())
        .await
        .unwrap();
        let entries: Vec<QueryLogEntry> = (0..10)
            .map(|i| entry(h + i, "clear.example", "allowed"))
            .collect();
        db.insert_batch(&entries).await.unwrap();

        let deleted = run_clear_chunk(&db, h, (h, i64::MIN), (h + 5, i64::MIN), false).await;
        assert_eq!(deleted, 5);
        assert_eq!(hour_totals(&db, h).await, (10, 0, 0));

        // Simulate retention committing an unrelated update before the next
        // clear chunk begins. Its +2 and external domain must survive.
        sqlx::query(
            "UPDATE stats_hourly SET queries = queries + 2, top_domains = ? WHERE hour = ?",
        )
        .bind(r#"[["clear.example",5,0],["baseline.example",5,0],["external.example",2,0]]"#)
        .bind(h)
        .execute(db.pool())
        .await
        .unwrap();

        let deleted = run_clear_chunk(&db, h, (h + 5, i64::MIN), (h + 10, i64::MIN), false).await;
        assert_eq!(deleted, 5);
        assert_eq!(
            hour_totals(&db, h).await,
            (17, 0, 0),
            "clear counters add to the concurrent update (5 + 5 + 2 + 5)"
        );
        let tops: std::collections::HashMap<String, i64> = hour_top_domains(&db, h)
            .await
            .into_iter()
            .map(|(qname, total, _)| (qname, total))
            .collect();
        assert_eq!(tops.get("clear.example"), Some(&10));
        assert_eq!(tops.get("baseline.example"), Some(&5));
        assert_eq!(
            tops.get("external.example"),
            Some(&2),
            "a concurrent rollup update must not be replaced by stale top lists"
        );
        assert_eq!(detailed_rows(&db).await, 0);
    }

    /// B5 fix: if rollup retention deletes the row between clear chunks, later
    /// chunks must delete the detailed rows without resurrecting the rollup.
    /// Zero-row chunks must not create an empty rollup either.
    #[tokio::test]
    async fn test_keep_aggregates_clear_does_not_resurrect_deleted_rollup() {
        let db = StatsDb::in_memory().await.unwrap();
        let h = hour_of(1_600_000_000_000);
        sqlx::query(
            "INSERT INTO stats_hourly (hour, queries, blocked, cached, top_domains, top_clients, top_upstreams) \
             VALUES (?, 1, 0, 0, '[]', '[]', '[]')",
        )
        .bind(h)
        .execute(db.pool())
        .await
        .unwrap();
        let entries: Vec<QueryLogEntry> = (0..10)
            .map(|i| entry(h + i, "gone.example", "allowed"))
            .collect();
        db.insert_batch(&entries).await.unwrap();

        assert_eq!(
            run_clear_chunk(&db, h, (h, i64::MIN), (h + 5, i64::MIN), false).await,
            5
        );
        sqlx::query("DELETE FROM stats_hourly WHERE hour = ?")
            .bind(h)
            .execute(db.pool())
            .await
            .unwrap();

        assert_eq!(
            run_clear_chunk(&db, h, (h + 5, i64::MIN), (h + 10, i64::MIN), false).await,
            5
        );
        let rollups: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stats_hourly WHERE hour = ?")
            .bind(h)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(rollups, 0, "a deleted rollup must not be re-created");
        assert_eq!(detailed_rows(&db).await, 0);

        // Empty-range chunk with insertion allowed: still no empty rollup row.
        assert_eq!(
            run_clear_chunk(&db, h, (h + 100, i64::MIN), (h + 200, i64::MIN), true).await,
            0
        );
        let rollups: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stats_hourly WHERE hour = ?")
            .bind(h)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(rollups, 0, "zero-row chunks must not create a rollup");
    }

    /// B5 fix: a live API/UI clear and the retention scheduler share the
    /// in-process maintenance lock. Whichever runs first, rollup totals and
    /// top lists must be preserved exactly once.
    #[tokio::test]
    async fn test_keep_aggregates_clear_and_retention_serialize() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let old_hour = hour_of(now - 100 * 86_400_000);
        let recent_hour = hour_of(now - 86_400_000);
        let mut entries = Vec::new();
        for i in 0..5 {
            entries.push(entry(old_hour + i, "old.example", "allowed"));
        }
        for i in 0..7 {
            entries.push(entry(
                recent_hour + i,
                "recent.example",
                if i == 0 { "blocked" } else { "allowed" },
            ));
        }
        db.insert_batch(&entries).await.unwrap();

        let retention = db.cleanup_retention_with_policy(90, 365, false);
        let clear = db.delete_query_logs_with_policy(true, false);
        let (retention, clear) = tokio::join!(retention, clear);
        retention.unwrap();
        clear.unwrap();

        assert_eq!(detailed_rows(&db).await, 0);
        let (total_queries, total_blocked): (i64, i64) = sqlx::query_as(
            "SELECT COALESCE(SUM(queries), 0), COALESCE(SUM(blocked), 0) FROM stats_hourly",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(total_queries, 12, "no row may be lost or double counted");
        assert_eq!(total_blocked, 1);
        assert_eq!(hour_totals(&db, old_hour).await, (5, 0, 0));
        assert_eq!(hour_totals(&db, recent_hour).await, (7, 1, 0));
        assert_eq!(
            hour_top_domains(&db, old_hour).await,
            vec![("old.example".to_string(), 5, 0)]
        );
        assert_eq!(
            hour_top_domains(&db, recent_hour).await,
            vec![("recent.example".to_string(), 7, 1)]
        );
    }

    /// B5 minor: a clear that is resumed in sub-threshold runs still vacuums on
    /// the run that completes it, even when that run deleted fewer than the
    /// normal 1,000-row threshold.
    #[tokio::test]
    async fn test_keep_aggregates_clear_retry_vacuums_on_completion() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito-stats-clear-retry-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let db = StatsDb::open(&db_path).await.unwrap();

        let padding = "x".repeat(200);
        let h0 = hour_of(1_600_000_000_000);
        let h1 = h0 + HOUR_MS;
        let mut entries = Vec::new();
        for i in 0..900i64 {
            let mut e = entry(h0 + i, "retry-vacuum.example", "allowed");
            e.rule = Some(format!("{padding}-a{i}"));
            entries.push(e);
        }
        for i in 0..900i64 {
            let mut e = entry(h1 + i, "retry-vacuum.example", "allowed");
            e.rule = Some(format!("{padding}-b{i}"));
            entries.push(e);
        }
        db.insert_batch(&entries).await.unwrap();
        db.vacuum().await.unwrap();
        let before = db.db_size_bytes().await.unwrap();

        // Fail the second hour's only chunk, so the first run deletes 900
        // rows (< the 1,000 threshold) and the retry deletes the rest.
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
            CREATE TRIGGER fail_clear_second_hour
            BEFORE INSERT ON stats_hourly
            BEGIN
                UPDATE clear_fail_counter SET n = n + 1;
                SELECT CASE
                    WHEN (SELECT n FROM clear_fail_counter) > 1
                    THEN RAISE(ABORT, 'injected clear failure')
                END;
            END
            ",
        )
        .execute(db.pool())
        .await
        .unwrap();
        assert!(db.delete_query_logs_keep_aggregates().await.is_err());
        assert_eq!(detailed_rows(&db).await, 900);
        sqlx::query("DROP TRIGGER fail_clear_second_hour")
            .execute(db.pool())
            .await
            .unwrap();

        // The completing run deletes 900 rows: below the threshold, but the
        // detailed log is now empty, so the clear must vacuum anyway.
        assert_eq!(db.delete_query_logs_keep_aggregates().await.unwrap(), 900);
        let freelist: i64 = sqlx::query_scalar("PRAGMA freelist_count")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(freelist, 0, "the completing retry must vacuum");
        let after = db.db_size_bytes().await.unwrap();
        assert!(
            after < before,
            "the vacuumed database must shrink (before={before}, after={after})"
        );
        assert_eq!(
            hour_totals(&db, h0).await.0 + hour_totals(&db, h1).await.0,
            1_800
        );

        db.pool().close().await;
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Builds the retention fixture that hides its global heavy hitter below
    /// every chunk-local top-100: each 5,000-row block has 100 distractors
    /// with 10 hits and 9 hits for `heavy.example`, so the hour total (27) is
    /// the only top-N ranking in which the heavy hitter appears.
    fn heavy_hitter_fixture(
        hour: i64,
        blocks: usize,
        distractors_per_block: usize,
    ) -> Vec<QueryLogEntry> {
        let mut entries = Vec::new();
        let mut ts = hour;
        for block in 0..blocks {
            for i in 0..distractors_per_block {
                for _ in 0..10 {
                    entries.push(entry(
                        ts,
                        &format!("distract-{block}-{i}.example"),
                        "allowed",
                    ));
                    ts += 1;
                }
            }
            for _ in 0..9 {
                entries.push(entry(ts, "heavy.example", "allowed"));
                ts += 1;
            }
            let filler = RETENTION_ROWS_PER_CHUNK as usize - distractors_per_block * 10 - 9;
            for i in 0..filler {
                entries.push(entry(ts, &format!("filler-{block}-{i}.example"), "allowed"));
                ts += 1;
            }
        }
        entries
    }

    /// B5 re-review fix: the clear's top lists must be cumulative for the hour.
    /// A heavy hitter below every chunk-local top-100 (9 hits vs 100
    /// distractors with 10) must still appear with its full 27 hits.
    #[tokio::test]
    async fn test_keep_aggregates_clear_preserves_heavy_hitter_across_chunks() {
        let db = StatsDb::in_memory().await.unwrap();
        let hour = hour_of(1_600_000_000_000);
        let entries = heavy_hitter_fixture(hour, 3, 100);
        assert_eq!(entries.len(), 15_000);
        db.insert_batch(&entries).await.unwrap();

        let deleted = db.delete_query_logs_keep_aggregates().await.unwrap();
        assert_eq!(deleted, 15_000);
        assert_eq!(hour_totals(&db, hour).await, (15_000, 0, 0));
        let tops = hour_top_domains(&db, hour).await;
        assert_eq!(
            tops.iter()
                .find(|(qname, _, _)| qname == "heavy.example")
                .map(|(_, total, _)| *total),
            Some(27),
            "a multi-chunk heavy hitter must not be dropped by chunk-local top-N: {tops:?}"
        );
    }

    /// B5 re-review fix, documented approximation: after a mid-hour failure the
    /// stored top lists are truncated to the hour's top-N at that point. A
    /// heavy hitter that was below that bounded snapshot (here 9 hits against
    /// 300 distractors with 10 in the committed chunk) cannot be recovered by
    /// the retry; only its remaining chunks are counted. Totals stay exact.
    /// A successful (uninterrupted) run is exact (previous test).
    #[tokio::test]
    async fn test_keep_aggregates_clear_retry_keeps_bounded_top_n_approximation() {
        let db = StatsDb::in_memory().await.unwrap();
        let hour = hour_of(1_600_000_000_000);
        let entries = heavy_hitter_fixture(hour, 3, 300);
        assert_eq!(entries.len(), 15_000);
        db.insert_batch(&entries).await.unwrap();

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
            CREATE TRIGGER fail_clear_second_chunk
            BEFORE INSERT ON stats_hourly
            BEGIN
                UPDATE clear_fail_counter SET n = n + 1;
                SELECT CASE
                    WHEN (SELECT n FROM clear_fail_counter) > 1
                    THEN RAISE(ABORT, 'injected clear failure')
                END;
            END
            ",
        )
        .execute(db.pool())
        .await
        .unwrap();
        assert!(db.delete_query_logs_keep_aggregates().await.is_err());

        // The committed first chunk's 300 distractors (10 each) fill the
        // bounded top-200, so its 9 heavy hits were not persisted.
        let partial = hour_top_domains(&db, hour).await;
        assert!(
            partial.iter().all(|(qname, _, _)| qname != "heavy.example"),
            "the bounded partial snapshot cannot contain the below-top-N hitter: {partial:?}"
        );

        sqlx::query("DROP TRIGGER fail_clear_second_chunk")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(
            db.delete_query_logs_keep_aggregates().await.unwrap(),
            10_000
        );
        assert_eq!(hour_totals(&db, hour).await, (15_000, 0, 0));
        let tops = hour_top_domains(&db, hour).await;
        assert_eq!(
            tops.iter()
                .find(|(qname, _, _)| qname == "heavy.example")
                .map(|(_, total, _)| *total),
            Some(18),
            "the retry recovers only the remaining chunks; the first 9 were below the persisted bounded snapshot: {tops:?}"
        );
    }

    /// The external-update guard only adds positive deltas between the row we
    /// wrote and the row we later observe; decreases are ignored because our
    /// own cumulative temp counts are authoritative for cleared rows.
    #[test]
    fn test_accumulate_external_delta_is_positive_only() {
        let last: StoredTops = (
            Some(r#"[["a.example",5,0],["b.example",2,1]]"#.to_string()),
            Some(r#"[["10.0.0.1",null,5,1,100]]"#.to_string()),
            Some(r#"[["1.1.1.1:53",5,0,500]]"#.to_string()),
        );
        let current: StoredTops = (
            Some(r#"[["a.example",7,1],["c.example",3,0]]"#.to_string()),
            Some(r#"[["10.0.0.1","name",7,2,200]]"#.to_string()),
            Some(r#"[["1.1.1.1:53",8,1,800]]"#.to_string()),
        );
        let mut external = HourRollup::default();
        accumulate_external_delta(&mut external, &current, &last);
        assert_eq!(
            external.domains,
            vec![
                ("a.example".to_string(), 2, 1),
                ("c.example".to_string(), 3, 0),
            ]
        );
        assert_eq!(
            external.clients,
            vec![("10.0.0.1".to_string(), Some("name".to_string()), 2, 1, 200)]
        );
        assert_eq!(
            external.upstreams,
            vec![("1.1.1.1:53".to_string(), 3, 1, 300)]
        );
    }
}
