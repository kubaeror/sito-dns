//! Dedicated single-writer background pipeline for query logging per ADR-0003 and section 14.1.

use crate::db::StatsDb;
use crate::entry::QueryLogEntry;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::error;

/// Default capacity for bounded query log channel per plan section 14.1.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 10_000;
/// Batch size threshold before immediate write to disk.
pub const BATCH_SIZE_THRESHOLD: usize = 1000;
/// Batch time interval before flushing accumulated entries to disk.
pub const BATCH_TIME_INTERVAL: Duration = Duration::from_secs(5);

enum WriterCommand {
    Entry(Box<QueryLogEntry>),
    Flush(oneshot::Sender<()>),
    Shutdown(oneshot::Sender<()>),
}

/// Handle for pushing query logs to the background writer.
#[derive(Clone)]
pub struct QueryLogSender {
    tx: mpsc::Sender<WriterCommand>,
    dropped_total: Arc<AtomicU64>,
    live_tail_tx: broadcast::Sender<QueryLogEntry>,
}

impl QueryLogSender {
    /// Attempts to enqueue a query log entry.
    ///
    /// If the channel is full, drops the entry without blocking the DNS hot path
    /// and increments `sito_querylog_dropped_total`.
    pub fn try_send(&self, entry: QueryLogEntry) -> bool {
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

    /// Returns the total number of dropped query log events due to channel backpressure.
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
        let (tx, mut rx) = mpsc::channel(capacity);
        let dropped_total = Arc::new(AtomicU64::new(0));
        let (live_tail_tx, _) = broadcast::channel(1000);

        let sender = QueryLogSender {
            tx,
            dropped_total: Arc::clone(&dropped_total),
            live_tail_tx: live_tail_tx.clone(),
        };

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
                                    if let Err(e) = db.insert_batch(&batch).await {
                                        error!("Failed to flush query log batch: {}", e);
                                    }
                                    batch.clear();
                                }
                            }
                            Some(WriterCommand::Flush(ack)) => {
                                if !batch.is_empty() {
                                    if let Err(e) = db.insert_batch(&batch).await {
                                        error!("Failed to flush query log batch on flush: {}", e);
                                    }
                                    batch.clear();
                                }
                                let _ = ack.send(());
                            }
                            Some(WriterCommand::Shutdown(ack)) => {
                                if !batch.is_empty() {
                                    if let Err(e) = db.insert_batch(&batch).await {
                                        error!("Failed to flush query log batch on shutdown: {}", e);
                                    }
                                    batch.clear();
                                }
                                let _ = ack.send(());
                                break;
                            }
                            None => {
                                if !batch.is_empty() {
                                    if let Err(e) = db.insert_batch(&batch).await {
                                        error!("Failed to flush query log batch on channel close: {}", e);
                                    }
                                    batch.clear();
                                }
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            if let Err(e) = db.insert_batch(&batch).await {
                                error!("Failed to flush query log batch on tick: {}", e);
                            }
                            batch.clear();
                        }
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
