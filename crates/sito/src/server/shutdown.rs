//! Graceful shutdown and drain.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Stops listeners, drains in-flight queries within the shutdown budget,
/// flushes the query log and releases the certificate watchers.
pub(super) async fn shutdown_server(
    shutdown_tx: &watch::Sender<bool>,
    listener_manager: &tokio::sync::Mutex<Option<DnsListenerManager>>,
    in_flight: &AtomicUsize,
    querylog_writer: QueryLogWriter,
    cert_watchers: Vec<sito_transport::CertWatcher>,
    dnssec_chain_cache: &sito_dnssec::ChainCache,
) {
    info!("Initiating graceful shutdown (stopping listeners)...");
    let _ = shutdown_tx.send(true);
    let current_manager = listener_manager.lock().await.take();
    if let Some(mut manager) = current_manager {
        manager.stop().await;
    }

    // Wait for in-flight queries to finish (5 s timeout per plan section 3.5)
    let shutdown_deadline = std::time::Instant::now() + SHUTDOWN_DRAIN_TIMEOUT;
    while in_flight.load(Ordering::SeqCst) > 0 {
        if std::time::Instant::now() >= shutdown_deadline {
            warn!(
                remaining = in_flight.load(Ordering::SeqCst),
                "Graceful shutdown timeout reached; draining remaining queries"
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    info!("Flushing and shutting down query log writer...");
    querylog_writer.shutdown().await;

    // Persist any authenticated DNSSEC chain statuses before exiting.
    if let Err(error) = dnssec_chain_cache.flush() {
        warn!(error = %error, "Failed to flush DNSSEC chain cache during shutdown");
    }

    // Stop certificate watchers after listeners have drained.
    drop(cert_watchers);

    info!("Graceful shutdown complete, exiting");
}
