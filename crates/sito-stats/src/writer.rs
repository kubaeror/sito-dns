//! Dedicated single-writer background pipeline for query logging per ADR-0003 and section 14.1.

use crate::db::StatsDb;
use crate::entry::QueryLogEntry;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{error, warn};

/// Default capacity for bounded query log channel per plan section 14.1.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 10_000;
/// Batch size threshold before immediate write to disk.
pub const BATCH_SIZE_THRESHOLD: usize = 1000;
/// Batch time interval before flushing accumulated entries to disk.
pub const BATCH_TIME_INTERVAL: Duration = Duration::from_secs(5);
/// Maximum attempts to persist a batch before dropping it and counting the loss.
///
/// A retention sweep processes row-bounded chunks, but a slow disk can still
/// hold the write lock past the pool's busy timeout. The extra attempts (with
/// bounded backoff) keep the no-drop guarantee instead of discarding a batch
/// after a short transient stall.
const MAX_FLUSH_ATTEMPTS: u32 = 5;
/// Base delay between failed flush attempts (exponential, capped).
const FLUSH_RETRY_BASE_DELAY: Duration = Duration::from_millis(50);
/// Upper bound for the exponential flush backoff.
const FLUSH_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);
/// Overall budget for the final shutdown flush.
///
/// Normal flushes may wait out a slow disk (30 s busy timeout × attempts), but
/// service managers stop a process on a fixed deadline. The shutdown flush is
/// bounded so the final batch is either committed or counted as dropped before
/// the process is killed.
const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(3);

/// Bounded exponential backoff for a failed flush attempt.
fn flush_retry_delay(attempt: u32) -> Duration {
    let exponent = attempt.saturating_sub(1).min(16);
    FLUSH_RETRY_BASE_DELAY
        .saturating_mul(1u32 << exponent)
        .min(FLUSH_RETRY_MAX_DELAY)
}

/// Removes `count` settled entries from the pending counter without
/// underflowing if an outer shutdown timeout has already reconciled it.
fn settle_pending(pending_entries: &AtomicU64, count: usize) {
    let count = count as u64;
    let _ = pending_entries.try_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
        Some(pending.saturating_sub(count))
    });
}

/// Persists `batch`, retrying transient SQLite failures a bounded number of
/// times. On persistent failure the entries are dropped and counted in
/// `dropped_total` so data loss is observable instead of silent.
async fn flush_batch(
    db: &StatsDb,
    batch: &mut Vec<QueryLogEntry>,
    dropped_total: &AtomicU64,
    pending_entries: &AtomicU64,
    reason: &'static str,
    deadline: Option<tokio::time::Instant>,
) {
    if batch.is_empty() {
        return;
    }

    let mut attempt = 1u32;
    loop {
        let result = match deadline {
            Some(deadline) => {
                if let Ok(result) = tokio::time::timeout_at(deadline, db.insert_batch(batch)).await
                {
                    result
                } else {
                    error!(
                        dropped = batch.len(),
                        "Failed to flush query log batch ({reason}) before the shutdown deadline; dropping entries"
                    );
                    settle_pending(pending_entries, batch.len());
                    dropped_total.fetch_add(batch.len() as u64, Ordering::Relaxed);
                    batch.clear();
                    return;
                }
            }
            None => db.insert_batch(batch).await,
        };
        match result {
            Ok(()) => {
                settle_pending(pending_entries, batch.len());
                batch.clear();
                return;
            }
            Err(e) if attempt < MAX_FLUSH_ATTEMPTS => {
                warn!(
                    attempt,
                    max_attempts = MAX_FLUSH_ATTEMPTS,
                    error = %e,
                    "Failed to flush query log batch ({reason}); retrying"
                );
                tokio::time::sleep(flush_retry_delay(attempt)).await;
                attempt += 1;
            }
            Err(e) => {
                error!(
                    error = %e,
                    dropped = batch.len(),
                    "Failed to flush query log batch ({reason}) after {attempt} attempts; dropping entries"
                );
                settle_pending(pending_entries, batch.len());
                dropped_total.fetch_add(batch.len() as u64, Ordering::Relaxed);
                batch.clear();
                return;
            }
        }
    }
}

enum WriterCommand {
    Entry(Box<QueryLogEntry>),
    Flush(oneshot::Sender<()>),
    Shutdown(oneshot::Sender<()>),
}

/// Handle for pushing query logs to the background writer.
#[derive(Clone)]
pub struct QueryLogSender {
    tx: mpsc::Sender<WriterCommand>,
    /// Entries dropped by the pipeline: channel backpressure plus batches whose
    /// SQLite flush failed after bounded retries.
    dropped_total: Arc<AtomicU64>,
    /// Entries accepted by `try_send` but not yet committed or counted as
    /// dropped. `QueryLogWriter::shutdown` uses this to account for a batch
    /// abandoned by the outer shutdown deadline.
    pending_entries: Arc<AtomicU64>,
    live_tail_tx: broadcast::Sender<QueryLogEntry>,
    anonymize: Arc<AtomicBool>,
}

impl QueryLogSender {
    /// Whether the writer task has exited (the channel is closed).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Attempts to enqueue a query log entry.
    ///
    /// If anonymization is enabled, masks the client IP address.
    /// If the channel is full, drops the entry without blocking the DNS hot path
    /// and increments `sito_querylog_dropped_total`.
    pub fn try_send(&self, mut entry: QueryLogEntry) -> bool {
        if self.anonymize.load(Ordering::Relaxed)
            && let Ok(ip) = entry.client_ip.parse::<IpAddr>()
        {
            entry.client_ip = crate::anonymize_ip(ip);
        }

        // Broadcast immediately to live-tail listeners regardless of storage queue
        let _ = self.live_tail_tx.send(entry.clone());

        // Increment before enqueueing so the writer can never observe an entry
        // it has already persisted but whose pending count was not raised yet.
        self.pending_entries.fetch_add(1, Ordering::Relaxed);
        if self
            .tx
            .try_send(WriterCommand::Entry(Box::new(entry)))
            .is_ok()
        {
            true
        } else {
            self.pending_entries.fetch_sub(1, Ordering::Relaxed);
            self.dropped_total.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Sets whether client IPs should be anonymized before logging.
    pub fn set_anonymize(&self, enabled: bool) {
        self.anonymize.store(enabled, Ordering::Relaxed);
    }

    /// Returns the total number of query log events dropped, either because the
    /// ingest channel was full or because a SQLite batch flush failed after
    /// bounded retries.
    pub fn dropped_total(&self) -> u64 {
        self.dropped_total.load(Ordering::Relaxed)
    }

    /// Subscribes to the real-time query log stream for WebSocket live-tailing.
    pub fn subscribe(&self) -> broadcast::Receiver<QueryLogEntry> {
        self.live_tail_tx.subscribe()
    }

    /// Flushes any pending buffered logs to SQLite and awaits completion.
    pub async fn flush(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(WriterCommand::Flush(ack_tx)).await.is_ok() {
            let _ = ack_rx.await;
        }
    }

    /// Shuts down the background writer cleanly, flushing any remaining buffered logs.
    pub async fn shutdown(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(WriterCommand::Shutdown(ack_tx)).await.is_ok() {
            let _ = ack_rx.await;
        }
    }
}

/// Manages the background writer loop.
pub struct QueryLogWriter {
    sender: QueryLogSender,
    join_handle: tokio::task::JoinHandle<()>,
}

impl QueryLogWriter {
    /// Spawns a dedicated single-writer task with the given database and channel capacity.
    pub fn spawn(db: StatsDb, capacity: usize) -> Self {
        Self::spawn_with_anonymize(db, capacity, false)
    }

    /// Spawns a dedicated single-writer task with the given database, channel capacity, and anonymization toggle.
    pub fn spawn_with_anonymize(db: StatsDb, capacity: usize, anonymize: bool) -> Self {
        let (tx, mut rx) = mpsc::channel(capacity);
        let dropped_total = Arc::new(AtomicU64::new(0));
        let pending_entries = Arc::new(AtomicU64::new(0));
        let (live_tail_tx, _) = broadcast::channel(1000);
        let anonymize_arc = Arc::new(AtomicBool::new(anonymize));

        let sender = QueryLogSender {
            tx,
            dropped_total: Arc::clone(&dropped_total),
            pending_entries: Arc::clone(&pending_entries),
            live_tail_tx: live_tail_tx.clone(),
            anonymize: anonymize_arc,
        };
        let writer_pending_entries = Arc::clone(&pending_entries);

        let join_handle = tokio::spawn(async move {
            let mut batch: Vec<QueryLogEntry> = Vec::with_capacity(BATCH_SIZE_THRESHOLD);
            let mut interval = tokio::time::interval(BATCH_TIME_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    cmd = rx.recv() => {
                        match cmd {
                            Some(WriterCommand::Entry(entry)) => {
                                batch.push(*entry);
                                if batch.len() >= BATCH_SIZE_THRESHOLD {
                                    flush_batch(
                                        &db,
                                        &mut batch,
                                        &dropped_total,
                                        &writer_pending_entries,
                                        "size threshold",
                                        None,
                                    )
                                    .await;
                                }
                            }
                            Some(WriterCommand::Flush(ack)) => {
                                flush_batch(
                                    &db,
                                    &mut batch,
                                    &dropped_total,
                                    &writer_pending_entries,
                                    "explicit flush",
                                    None,
                                )
                                .await;
                                let _ = ack.send(());
                            }
                            Some(WriterCommand::Shutdown(ack)) => {
                                let deadline =
                                    tokio::time::Instant::now() + SHUTDOWN_FLUSH_TIMEOUT;
                                flush_batch(
                                    &db,
                                    &mut batch,
                                    &dropped_total,
                                    &writer_pending_entries,
                                    "shutdown",
                                    Some(deadline),
                                )
                                .await;
                                let _ = ack.send(());
                                break;
                            }
                            None => {
                                let deadline =
                                    tokio::time::Instant::now() + SHUTDOWN_FLUSH_TIMEOUT;
                                flush_batch(
                                    &db,
                                    &mut batch,
                                    &dropped_total,
                                    &writer_pending_entries,
                                    "channel close",
                                    Some(deadline),
                                )
                                .await;
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        flush_batch(
                            &db,
                            &mut batch,
                            &dropped_total,
                            &writer_pending_entries,
                            "timer tick",
                            None,
                        )
                        .await;
                    }
                }
            }
        });

        Self {
            sender,
            join_handle,
        }
    }

    /// Returns a cloneable sender handle for enqueuing query logs.
    pub fn sender(&self) -> QueryLogSender {
        self.sender.clone()
    }

    /// Configure IP anonymization on the writer.
    #[must_use]
    pub fn with_anonymize(self, enabled: bool) -> Self {
        self.sender.set_anonymize(enabled);
        self
    }

    /// Shuts down the writer cleanly, flushing any remaining buffered logs, and
    /// waits for task exit.
    ///
    /// The wait is bounded so a service manager stop deadline cannot kill the
    /// process while this future is still waiting on a wedged disk. The
    /// shutdown flush itself also has a shorter deadline. If the outer bound
    /// expires while a normal flush is still in progress, the writer task is
    /// aborted and every entry it has accepted but not committed is added to
    /// `dropped_total`, so shutdown never loses a batch silently.
    pub async fn shutdown(self) {
        let QueryLogWriter {
            sender,
            mut join_handle,
        } = self;
        let dropped_total = Arc::clone(&sender.dropped_total);
        let pending_entries = Arc::clone(&sender.pending_entries);
        let deadline =
            tokio::time::Instant::now() + SHUTDOWN_FLUSH_TIMEOUT + Duration::from_secs(1);

        if tokio::time::timeout_at(deadline, sender.shutdown())
            .await
            .is_err()
        {
            warn!(
                "Query log writer shutdown command exceeded the {}s deadline",
                SHUTDOWN_FLUSH_TIMEOUT.as_secs() + 1
            );
            // Stop the task so the pending counter is stable before accounting
            // for an in-flight normal flush.
            join_handle.abort();
        }
        if tokio::time::timeout_at(deadline, &mut join_handle)
            .await
            .is_err()
        {
            warn!(
                "Query log writer did not exit before the {}s shutdown deadline",
                SHUTDOWN_FLUSH_TIMEOUT.as_secs() + 1
            );
            join_handle.abort();
            // Do not let task cancellation itself exceed the stop budget.
            let _ = tokio::time::timeout(Duration::from_secs(1), &mut join_handle).await;
        }

        let abandoned = pending_entries.swap(0, Ordering::SeqCst);
        if abandoned > 0 {
            dropped_total.fetch_add(abandoned, Ordering::Relaxed);
            warn!(
                dropped = abandoned,
                "Query log writer shutdown abandoned uncommitted entries"
            );
        }
    }

    /// Waits for the writer task to exit **without a deadline**.
    ///
    /// This is intended for tests and callers that already bound shutdown
    /// themselves. Production shutdown uses [`Self::shutdown`], which bounds
    /// the wait and accounts for abandoned entries.
    pub async fn wait(self) {
        let _ = self.join_handle.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection;
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};

    #[test]
    fn test_flush_retry_delay_is_bounded_and_grows() {
        assert_eq!(flush_retry_delay(1), Duration::from_millis(50));
        assert_eq!(flush_retry_delay(2), Duration::from_millis(100));
        assert_eq!(flush_retry_delay(3), Duration::from_millis(200));
        assert_eq!(flush_retry_delay(4), Duration::from_millis(400));
        assert_eq!(flush_retry_delay(5), Duration::from_millis(800));
        assert_eq!(flush_retry_delay(6), FLUSH_RETRY_MAX_DELAY);
        assert_eq!(flush_retry_delay(u32::MAX), FLUSH_RETRY_MAX_DELAY);
    }

    /// Deferred D4a: a slow disk that holds the write lock past a short stall
    /// must not make the writer discard the batch.
    #[tokio::test]
    async fn test_writer_waits_out_a_slow_write_lock_without_dropping() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_writer_lock_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let db = StatsDb::open(&db_path).await.unwrap();

        let lock_options = SqliteConnectOptions::new()
            .filename(&db_path)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(30));
        let mut lock_conn = sqlx::SqliteConnection::connect_with(&lock_options)
            .await
            .unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut lock_conn)
            .await
            .unwrap();

        let writer = QueryLogWriter::spawn(db.clone(), 16);
        let sender = writer.sender();
        let entry = QueryLogEntry::new(
            chrono::Utc::now().timestamp_millis(),
            "192.0.2.10",
            None,
            "slow-lock.example",
            1,
            Some(0),
            "allowed",
            "udp",
        );
        assert!(sender.try_send(entry));

        // Release the lock after a stall that exceeds the old retry delay but
        // stays well inside the busy timeout.
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            sqlx::query("COMMIT").execute(&mut lock_conn).await.unwrap();
        });

        sender.flush().await;
        release.await.unwrap();
        writer.shutdown().await;

        assert_eq!(
            sender.dropped_total(),
            0,
            "a slow write lock must not drop a query-log batch"
        );
        let page = db
            .query_logs(&crate::QueryLogFilter::default())
            .await
            .unwrap();
        assert_eq!(page.entries.len(), 1);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Deferred D4a review: the shutdown flush must be bounded even when the
    /// write lock is held longer than the shutdown budget, and the uncommitted
    /// batch must be counted as dropped.
    #[tokio::test]
    async fn test_shutdown_flush_deadline_counts_dropped_batch() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_shutdown_deadline_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let db = StatsDb::open(&db_path).await.unwrap();

        let lock_options = SqliteConnectOptions::new()
            .filename(&db_path)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(30));
        let mut lock_conn = sqlx::SqliteConnection::connect_with(&lock_options)
            .await
            .unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut lock_conn)
            .await
            .unwrap();

        let mut batch = vec![QueryLogEntry::new(
            chrono::Utc::now().timestamp_millis(),
            "192.0.2.12",
            None,
            "shutdown-deadline.example",
            1,
            Some(0),
            "allowed",
            "udp",
        )];
        let dropped = std::sync::atomic::AtomicU64::new(0);
        let pending = std::sync::atomic::AtomicU64::new(1);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        let started = std::time::Instant::now();
        flush_batch(&db, &mut batch, &dropped, &pending, "test", Some(deadline)).await;
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "the shutdown flush must not wait for the full busy timeout (elapsed {elapsed:?})"
        );
        assert_eq!(batch.len(), 0);
        assert_eq!(pending.load(Ordering::Relaxed), 0);
        assert_eq!(
            dropped.load(Ordering::Relaxed),
            1,
            "an uncommitted shutdown batch must be counted as dropped"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Deferred D4a re-review: if the writer is already inside a normal
    /// (undeadlined) flush when shutdown is requested, the outer shutdown
    /// deadline must abort the writer and count the in-flight batch as dropped
    /// instead of leaving it uncounted.
    #[tokio::test]
    async fn test_shutdown_counts_in_flight_normal_flush() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_shutdown_in_flight_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let db = StatsDb::open(&db_path).await.unwrap();

        let lock_options = SqliteConnectOptions::new()
            .filename(&db_path)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(30));
        let mut lock_conn = sqlx::SqliteConnection::connect_with(&lock_options)
            .await
            .unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut lock_conn)
            .await
            .unwrap();

        let writer = QueryLogWriter::spawn(db.clone(), 2_000);
        let sender = writer.sender();
        for i in 0..BATCH_SIZE_THRESHOLD {
            assert!(sender.try_send(QueryLogEntry::new(
                chrono::Utc::now().timestamp_millis(),
                "192.0.2.13",
                None,
                format!("in-flight-{i}.example"),
                1,
                Some(0),
                "allowed",
                "udp",
            )));
        }

        // Let the writer drain the channel and enter the size-threshold flush,
        // which blocks on the external write lock. Shutdown then queues behind
        // that normal (undeadlined) flush.
        tokio::time::sleep(Duration::from_millis(300)).await;

        let started = std::time::Instant::now();
        writer.shutdown().await;
        let elapsed = started.elapsed();

        assert!(
            elapsed >= Duration::from_secs(3),
            "shutdown must wait for the bounded stop budget (elapsed {elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_secs(6),
            "shutdown must return at the outer bound (elapsed {elapsed:?})"
        );
        assert_eq!(
            sender.dropped_total(),
            BATCH_SIZE_THRESHOLD as u64,
            "an in-flight normal flush abandoned by shutdown must be counted as dropped"
        );

        drop(lock_conn);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Deferred D4a review: assert the on-disk pool actually uses the raised
    /// busy timeout. The old 10 s value fails this assertion.
    #[tokio::test]
    async fn test_on_disk_busy_timeout_is_30s() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_busy_timeout_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let db = StatsDb::open(&db_path).await.unwrap();

        let busy_timeout: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(
            busy_timeout, 30_000,
            "on-disk StatsDb must use the 30 s busy timeout"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Deferred D4a review: a permanently failing insert must exhaust the
    /// retry budget (four retries, ~750 ms of backoff) and count the batch as
    /// dropped. The old three-attempt policy finished in ~150 ms.
    #[tokio::test]
    async fn test_writer_retry_budget_is_bounded_and_counts_dropped_batch() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_writer_retry_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let db = StatsDb::open(&db_path).await.unwrap();
        sqlx::query("DROP TABLE query_log")
            .execute(db.pool())
            .await
            .unwrap();

        let writer = QueryLogWriter::spawn(db.clone(), 16);
        let sender = writer.sender();
        assert!(
            sender.try_send(QueryLogEntry::new(
                chrono::Utc::now().timestamp_millis(),
                "192.0.2.11",
                None,
                "retry-budget.example",
                1,
                Some(0),
                "allowed",
                "udp",
            )),
            "the entry must reach the writer queue"
        );

        let started = std::time::Instant::now();
        sender.flush().await;
        let elapsed = started.elapsed();
        writer.shutdown().await;

        assert_eq!(
            sender.dropped_total(),
            1,
            "a permanently failing batch must be counted as dropped"
        );
        assert!(
            elapsed >= Duration::from_millis(600),
            "the writer must exercise the full retry budget before dropping (elapsed {elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the retry budget must remain bounded (elapsed {elapsed:?})"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
