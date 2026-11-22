//! Bounded, crash-resumable retroactive anonymization of `query_log`.
//!
//! Masking is computed in Rust with the same [`crate::anonymize_ip`] helper the
//! live writer uses, so a retroactive run and the forward-only writer agree on
//! the IPv4 /24, IPv6 /56 and IPv4-mapped forms. Rows are read and updated in
//! key-ordered chunks, one transaction per chunk: memory stays bounded, a crash
//! loses at most the uncommitted chunk, and a rerun simply skips the rows that
//! already carry a masked address and no client name.
//!
//! `stats_hourly` is deliberately not touched here. Its identifier scrub is
//! owned by the rollup PII backfill and the `rollup_client_names` policy; this
//! module only rewrites detailed `query_log` rows.

#[allow(clippy::wildcard_imports, unused_imports)]
use super::*;
use crate::anonymize_ip;
use std::net::IpAddr;

/// Default number of rows read and updated per transaction.
///
/// A full `--all` anonymization may cover a very large table. One thousand rows
/// keeps the write lock short while amortizing the per-chunk transaction and
/// commit cost.
pub const ANONYMIZE_QUERYLOG_CHUNK_ROWS: usize = 1_000;

/// Result of one bounded anonymization chunk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueryLogAnonymizeChunk {
    /// Highest `query_log.id` read by this chunk. The next chunk starts after
    /// it. Equal to the caller's cursor when the chunk was empty.
    pub last_id: i64,
    /// Rows read (and therefore considered) by this chunk.
    pub processed: u64,
    /// Rows whose stored values actually changed.
    pub changed: u64,
    /// Rows that needed no `UPDATE`: the stored address was already masked and
    /// the client name was already `NULL`. (A malformed address with no name is
    /// unchanged for the same reason and is also counted here.)
    pub already_anonymized: u64,
    /// Rows whose `client_ip` could not be parsed. Their address is preserved
    /// (there is no safe mask to compute) but a client name is still cleared.
    pub unparseable: u64,
}

/// Aggregate result of a complete chunked anonymization run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueryLogAnonymizeReport {
    /// Rows read across every chunk.
    pub processed: u64,
    /// Rows that were updated (address masked and/or name cleared).
    pub changed: u64,
    /// Rows skipped because no update was needed: already masked with a NULL
    /// name, or an unparseable address with no name to clear.
    pub already_anonymized: u64,
    /// Rows with a malformed `client_ip` (address preserved, name cleared).
    pub unparseable: u64,
    /// Number of non-empty chunks committed.
    pub chunks: u64,
    /// Whether the post-run `VACUUM`/WAL truncate ran.
    pub vacuumed: bool,
}

/// Read-only preview of a retroactive anonymization, used by `--dry-run`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueryLogAnonymizePlan {
    /// Detailed rows that exist in the database copy.
    pub scanned: u64,
    /// Rows a real run would update.
    pub would_change: u64,
    /// Rows that need no update (already masked with a NULL name).
    pub already_anonymized: u64,
    /// Rows whose malformed `client_ip` cannot be masked.
    pub unparseable: u64,
}

/// What a row needs, computed identically by the planner and the writer.
struct RowAnonymization {
    changed: bool,
    masked_ip: Option<String>,
    unparseable: bool,
}

fn anonymize_row(client_ip: &str, client_name: Option<&str>) -> RowAnonymization {
    match client_ip.parse::<IpAddr>() {
        Ok(ip) => {
            let masked = anonymize_ip(ip);
            let changed = client_name.is_some() || masked != client_ip;
            RowAnonymization {
                changed,
                masked_ip: Some(masked),
                unparseable: false,
            }
        }
        Err(_) => RowAnonymization {
            // The client name is PII regardless of whether the address is
            // parseable, so clearing it still counts as a change. Without a
            // parsable address there is no mask to apply; leave the value
            // untouched rather than guessing or corrupting it.
            changed: client_name.is_some(),
            masked_ip: None,
            unparseable: true,
        },
    }
}

impl StatsDb {
    /// Anonymizes one bounded chunk of `query_log`.
    ///
    /// Rows are selected by ascending `id` with `id > after_id`. The whole
    /// read/update/commit is one `BEGIN IMMEDIATE` transaction, so a crash
    /// either keeps the chunk or discards it; a rerun from the same cursor is
    /// always safe. Already-anonymized rows are detected per row and skipped
    /// without an `UPDATE`.
    pub async fn anonymize_query_log_chunk(
        &self,
        after_id: i64,
        limit: usize,
    ) -> Result<QueryLogAnonymizeChunk, StatsError> {
        let limit = i64::try_from(limit.max(1)).unwrap_or(i64::MAX);
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let rows = sqlx::query(
            "SELECT id, client_ip, client_name FROM query_log \
             WHERE id > ? ORDER BY id ASC LIMIT ?",
        )
        .bind(after_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;

        let mut chunk = QueryLogAnonymizeChunk {
            last_id: after_id,
            ..QueryLogAnonymizeChunk::default()
        };
        for row in &rows {
            let id: i64 = row.get("id");
            let client_ip: String = row.get("client_ip");
            let client_name: Option<String> = row.get("client_name");
            chunk.last_id = id;
            chunk.processed = chunk.processed.saturating_add(1);

            let action = anonymize_row(&client_ip, client_name.as_deref());
            if action.unparseable {
                chunk.unparseable = chunk.unparseable.saturating_add(1);
            }
            if !action.changed {
                chunk.already_anonymized = chunk.already_anonymized.saturating_add(1);
                continue;
            }

            let new_ip = action.masked_ip.as_deref().unwrap_or(&client_ip);
            sqlx::query("UPDATE query_log SET client_ip = ?, client_name = NULL WHERE id = ?")
                .bind(new_ip)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            chunk.changed = chunk.changed.saturating_add(1);
        }

        tx.commit().await?;
        Ok(chunk)
    }

    /// Anonymizes every `query_log` row in bounded, independently committed
    /// chunks, then vacuums when at least one row changed.
    ///
    /// A second run reports `changed = 0` and performs no `VACUUM`: the rows
    /// already carry a masked address and a NULL client name, so repeating the
    /// command is safe and cheap on the update path.
    ///
    /// A full `--all` run always vacuums when anything changed (rather than
    /// waiting for the retention threshold): anonymization is a privacy
    /// rewrite, and `VACUUM` plus `PRAGMA wal_checkpoint(TRUNCATE)` removes the
    /// old unmasked values still reachable through free pages and the WAL
    /// after the per-chunk updates. No rows are removed, so a large anonymize
    /// may not shrink the file much, but the old bytes no longer remain in
    /// free space.
    pub async fn anonymize_query_log(
        &self,
        chunk_rows: usize,
    ) -> Result<QueryLogAnonymizeReport, StatsError> {
        let chunk_rows = chunk_rows.max(1);
        let mut report = QueryLogAnonymizeReport::default();
        let mut cursor = 0_i64;
        loop {
            let chunk = self.anonymize_query_log_chunk(cursor, chunk_rows).await?;
            if chunk.processed == 0 {
                break;
            }
            report.processed = report.processed.saturating_add(chunk.processed);
            report.changed = report.changed.saturating_add(chunk.changed);
            report.already_anonymized = report
                .already_anonymized
                .saturating_add(chunk.already_anonymized);
            report.unparseable = report.unparseable.saturating_add(chunk.unparseable);
            report.chunks = report.chunks.saturating_add(1);
            cursor = chunk.last_id;
        }

        if report.changed > 0 {
            self.vacuum().await?;
            report.vacuumed = true;
        }
        self.invalidate_stats_cache();
        Ok(report)
    }

    /// Counts what a real anonymization would change without opening the live
    /// database read-write.
    ///
    /// Callers pass a private copy and therefore cannot create `-wal`/`-shm`
    /// sidecars next to the live `stats.db` or modify its bytes.
    pub async fn inspect_anonymize_plan(
        db_path: impl AsRef<Path>,
    ) -> Result<QueryLogAnonymizePlan, StatsError> {
        let path = db_path.as_ref();
        let options = SqliteConnectOptions::new()
            .filename(path)
            .read_only(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;

        let mut plan = QueryLogAnonymizePlan::default();
        let mut cursor = 0_i64;
        loop {
            let rows = sqlx::query(
                "SELECT id, client_ip, client_name FROM query_log \
                 WHERE id > ? ORDER BY id ASC LIMIT ?",
            )
            .bind(cursor)
            .bind(i64::try_from(ANONYMIZE_QUERYLOG_CHUNK_ROWS).unwrap_or(i64::MAX))
            .fetch_all(&pool)
            .await?;
            if rows.is_empty() {
                break;
            }

            for row in &rows {
                let id: i64 = row.get("id");
                let client_ip: String = row.get("client_ip");
                let client_name: Option<String> = row.get("client_name");
                cursor = id;
                plan.scanned = plan.scanned.saturating_add(1);
                let action = anonymize_row(&client_ip, client_name.as_deref());
                if action.unparseable {
                    plan.unparseable = plan.unparseable.saturating_add(1);
                }
                if action.changed {
                    plan.would_change = plan.would_change.saturating_add(1);
                } else {
                    plan.already_anonymized = plan.already_anonymized.saturating_add(1);
                }
            }
        }

        pool.close().await;
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::QueryLogEntry;

    fn entry(ts: i64, ip: &str, name: Option<&str>, qname: &str) -> QueryLogEntry {
        QueryLogEntry::new(
            ts,
            ip,
            name.map(ToString::to_string),
            qname,
            1,
            Some(0),
            "allowed",
            "udp",
        )
    }

    async fn rows(db: &StatsDb) -> Vec<(i64, String, Option<String>, String, String)> {
        sqlx::query(
            "SELECT ts, client_ip, client_name, qname, verdict FROM query_log ORDER BY id ASC",
        )
        .fetch_all(db.pool())
        .await
        .unwrap()
        .into_iter()
        .map(|row| {
            (
                row.get("ts"),
                row.get("client_ip"),
                row.get("client_name"),
                row.get("qname"),
                row.get("verdict"),
            )
        })
        .collect()
    }

    #[tokio::test]
    async fn test_anonymize_query_log_masks_ips_and_clears_names() {
        let db = StatsDb::in_memory().await.unwrap();
        db.insert_batch(&[
            entry(1_000, "192.168.1.123", Some("laptop"), "a.test"),
            entry(
                1_001,
                "2001:db8:abcd:0012:3456:7890:1234:5678",
                Some("phone"),
                "b.test",
            ),
            entry(1_002, "::ffff:198.51.100.20", Some("mapped"), "c.test"),
            entry(1_003, "192.168.1.0", None, "already.test"),
        ])
        .await
        .unwrap();
        let before = rows(&db).await;
        assert_eq!(before.len(), 4);

        let report = db.anonymize_query_log(2).await.unwrap();
        assert_eq!(report.processed, 4);
        assert_eq!(report.changed, 3, "the already-masked row is skipped");
        assert_eq!(report.already_anonymized, 1);
        assert_eq!(report.unparseable, 0);
        assert!(report.vacuumed);

        let after = rows(&db).await;
        assert_eq!(after.len(), 4, "anonymization never deletes rows");
        assert_eq!(after[0].1, "192.168.1.0");
        assert_eq!(after[1].1, "2001:db8:abcd::");
        assert_eq!(after[2].1, "198.51.100.0", "mapped IPv6 masks as IPv4 /24");
        assert_eq!(after[3].1, "192.168.1.0");
        for (index, row) in after.iter().enumerate() {
            assert_eq!(row.2, None, "row {index} must lose client_name");
            assert_eq!(row.0, before[index].0, "ts is preserved");
            assert_eq!(row.3, before[index].3, "qname is preserved");
            assert_eq!(row.4, before[index].4, "verdict is preserved");
        }
    }

    #[tokio::test]
    async fn test_anonymize_query_log_second_run_changes_nothing() {
        let db = StatsDb::in_memory().await.unwrap();
        db.insert_batch(&[
            entry(1_000, "10.1.2.3", Some("one"), "a.test"),
            entry(1_001, "10.1.2.4", Some("two"), "b.test"),
        ])
        .await
        .unwrap();

        let first = db.anonymize_query_log(1).await.unwrap();
        assert_eq!(first.changed, 2);
        assert!(first.vacuumed);
        let after_first = rows(&db).await;

        let second = db.anonymize_query_log(1).await.unwrap();
        assert_eq!(second.processed, 2);
        assert_eq!(second.changed, 0, "a rerun must change zero rows");
        assert_eq!(second.already_anonymized, 2);
        assert!(!second.vacuumed, "a no-op run must not vacuum");
        assert_eq!(rows(&db).await, after_first, "rows stay byte-identical");
    }

    #[tokio::test]
    async fn test_anonymize_query_log_chunk_boundary_and_resume() {
        let db = StatsDb::in_memory().await.unwrap();
        let entries: Vec<QueryLogEntry> = (0..5)
            .map(|i| {
                entry(
                    1_000 + i,
                    &format!("192.0.2.{}", i + 1),
                    Some("client"),
                    &format!("q{i}.test"),
                )
            })
            .collect();
        db.insert_batch(&entries).await.unwrap();

        // A crash after one committed chunk loses nothing already committed.
        let first = db.anonymize_query_log_chunk(0, 2).await.unwrap();
        assert_eq!(first.processed, 2);
        assert_eq!(first.changed, 2);
        assert!(first.last_id > 0);

        // The complete run starts from zero, skips the two committed rows, and
        // finishes the remaining three in two more chunks.
        let report = db.anonymize_query_log(2).await.unwrap();
        assert_eq!(report.processed, 5);
        assert_eq!(report.changed, 3);
        assert_eq!(report.already_anonymized, 2);
        assert_eq!(report.chunks, 3);
        assert!(rows(&db).await.iter().all(|row| row.2.is_none()));

        // An exact chunk multiple ends with one empty read and still reports
        // every non-empty chunk.
        let db = StatsDb::in_memory().await.unwrap();
        let entries: Vec<QueryLogEntry> = (0..4)
            .map(|i| entry(2_000 + i, &format!("198.51.100.{}", i + 1), None, "x.test"))
            .collect();
        db.insert_batch(&entries).await.unwrap();
        let report = db.anonymize_query_log(2).await.unwrap();
        assert_eq!(report.processed, 4);
        assert_eq!(report.changed, 4);
        assert_eq!(report.chunks, 2);
    }

    #[tokio::test]
    async fn test_anonymize_query_log_clears_name_for_unparseable_ip() {
        let db = StatsDb::in_memory().await.unwrap();
        db.insert_batch(&[
            entry(1_000, "not-an-ip", Some("legacy"), "a.test"),
            entry(1_001, "also-bad", None, "b.test"),
        ])
        .await
        .unwrap();

        let report = db.anonymize_query_log(10).await.unwrap();
        assert_eq!(report.processed, 2);
        assert_eq!(report.unparseable, 2);
        assert_eq!(report.changed, 1, "only the named row needs an update");

        let rows = rows(&db).await;
        assert_eq!(rows[0].1, "not-an-ip", "an unparseable IP is not corrupted");
        assert_eq!(rows[0].2, None);
        assert_eq!(rows[1].1, "also-bad");
        assert_eq!(rows[1].2, None);

        let second = db.anonymize_query_log(10).await.unwrap();
        assert_eq!(second.changed, 0);
        assert_eq!(second.unparseable, 2);
    }

    fn temp_db(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "sito-stats-anonymize-{label}-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("stats.db");
        (dir, db_path)
    }

    #[tokio::test]
    async fn test_inspect_anonymize_plan_is_read_only() {
        let (dir, db_path) = temp_db("plan");
        let db = StatsDb::open(&db_path).await.unwrap();
        db.insert_batch(&[
            entry(1_000, "192.0.2.10", Some("named"), "a.test"),
            entry(1_001, "192.0.2.0", None, "b.test"),
            entry(1_002, "bad", Some("legacy"), "c.test"),
        ])
        .await
        .unwrap();
        db.pool().close().await;
        let before = std::fs::read(&db_path).unwrap();

        let plan = StatsDb::inspect_anonymize_plan(&db_path).await.unwrap();
        assert_eq!(plan.scanned, 3);
        assert_eq!(plan.would_change, 2);
        assert_eq!(plan.already_anonymized, 1);
        assert_eq!(plan.unparseable, 1);
        assert_eq!(std::fs::read(&db_path).unwrap(), before);
        // A read-only connection to a WAL database may create an empty
        // sidecar; production callers pass a private copy so the live data
        // directory stays untouched (`inspect_anonymize_without_writes`).
        for sidecar in ["stats.db-wal", "stats.db-shm"] {
            let path = dir.join(sidecar);
            if path.exists() {
                std::fs::remove_file(path).unwrap();
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_anonymize_query_log_vacuums_and_secure_delete_is_on() {
        let (dir, db_path) = temp_db("vacuum");
        let db = StatsDb::open(&db_path).await.unwrap();
        let long_name = "x".repeat(256);
        let entries: Vec<QueryLogEntry> = (0..2_000)
            .map(|i| {
                entry(
                    1_000 + i,
                    &format!("192.0.2.{}", (i % 250) + 1),
                    Some(&long_name),
                    &format!("q{i}.example.test"),
                )
            })
            .collect();
        db.insert_batch(&entries).await.unwrap();
        db.vacuum().await.unwrap();
        let before = db.db_size_bytes().await.unwrap();

        let report = db
            .anonymize_query_log(ANONYMIZE_QUERYLOG_CHUNK_ROWS)
            .await
            .unwrap();
        assert_eq!(report.processed, 2_000);
        assert_eq!(report.changed, 2_000);
        assert_eq!(report.chunks, 2);
        assert!(report.vacuumed);

        let secure_delete: i64 = sqlx::query_scalar("PRAGMA secure_delete")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(secure_delete, 1, "secure_delete must stay enabled");
        let freelist: i64 = sqlx::query_scalar("PRAGMA freelist_count")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(freelist, 0, "VACUUM must return free pages");
        let after = db.db_size_bytes().await.unwrap();
        assert!(
            after < before,
            "dropping long client names must shrink the vacuumed database: \
             before={before}, after={after}"
        );

        db.pool().close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
