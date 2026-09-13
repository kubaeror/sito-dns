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
const MAX_FLUSH_ATTEMPTS: u32 = 3;
/// Delay between failed flush attempts.
const FLUSH_RETRY_DELAY: Duration = Duration::from_millis(50);

/// Persists `batch`, retrying transient SQLite failures a bounded number of
/// times. On persistent failure the entries are dropped and counted in
/// `dropped_total` so data loss is observable instead of silent.
async fn flush_batch(
    db: &StatsDb,
    batch: &mut Vec<QueryLogEntry>,
    dropped_total: &AtomicU64,
    reason: &'static str,
) {
    if batch.is_empty() {
        return;
    }

    let mut attempt = 1u32;
    loop {
        match db.insert_batch(batch).await {
            Ok(()) => {
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
                tokio::time::sleep(FLUSH_RETRY_DELAY).await;
                attempt += 1;
            }
            Err(e) => {
                error!(
                    error = %e,
                    dropped = batch.len(),
                    "Failed to flush query log batch ({reason}) after {attempt} attempts; dropping entries"
                );
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
    live_tail_tx: broadcast::Sender<QueryLogEntry>,
    anonymize: Arc<AtomicBool>,
}

impl QueryLogSender {
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

        if self
            .tx
            .try_send(WriterCommand::Entry(Box::new(entry)))
            .is_ok()
        {
            true
        } else {
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
        let (live_tail_tx, _) = broadcast::channel(1000);
        let anonymize_arc = Arc::new(AtomicBool::new(anonymize));

        let sender = QueryLogSender {
            tx,
            dropped_total: Arc::clone(&dropped_total),
            live_tail_tx: live_tail_tx.clone(),
            anonymize: Arc::clone(&anonymize_arc),
        };

        let join_handle = tokio::spawn(async move {
            let mut batch: Vec<QueryLogEntry> = Vec::with_capacity(BATCH_SIZE_THRESHOLD);
            let mut interval = tokio::time::interval(BATCH_TIME_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    cmd = rx.recv() => {
                        match cmd {
                            Some(WriterCommand::Entry(mut entry)) => {
                                if anonymize_arc.load(Ordering::Relaxed)
                                    && let Ok(ip) = entry.client_ip.parse::<IpAddr>()
                                {
                                    entry.client_ip = crate::anonymize_ip(ip);
                                }
                                batch.push(*entry);
                                if batch.len() >= BATCH_SIZE_THRESHOLD {
                                    flush_batch(&db, &mut batch, &dropped_total, "size threshold").await;
                                }
                            }
                            Some(WriterCommand::Flush(ack)) => {
                                flush_batch(&db, &mut batch, &dropped_total, "explicit flush").await;
                                let _ = ack.send(());
                            }
                            Some(WriterCommand::Shutdown(ack)) => {
                                flush_batch(&db, &mut batch, &dropped_total, "shutdown").await;
                                let _ = ack.send(());
                                break;
                            }
                            None => {
                                flush_batch(&db, &mut batch, &dropped_total, "channel close").await;
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        flush_batch(&db, &mut batch, &dropped_total, "timer tick").await;
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

    /// Shuts down the writer cleanly, flushing any remaining buffered logs, and waits for task exit.
    pub async fn shutdown(self) {
        self.sender.shutdown().await;
        let _ = self.join_handle.await;
    }

    /// Waits for the writer task to exit.
    pub async fn wait(self) {
        let _ = self.join_handle.await;
    }
}
