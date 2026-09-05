//! `sito-stats`
//!
//! Query logging, persistent SQLite storage, and Prometheus metrics for sito:
//! - SQLite storage engine with Write-Ahead Logging (WAL) and schema migrations
//! - Non-blocking bounded query log ingestion pipeline with backpressure drop counters
//! - IP address anonymization (/24 for IPv4, /56 for IPv6) per section 14.3
//! - Automated retention pruning and hourly rollup aggregations
//! - Complete Prometheus metrics registry matching section 14.2

pub mod anonymize;
pub mod db;
pub mod entry;
pub mod error;
pub mod metrics;
pub mod writer;

pub use anonymize::anonymize_ip;
pub use db::{
    ClientStats, GlobalStats, HourlyActivity, QueryLogFilter, QueryLogPage, RetentionReport,
    StatsDb, UpstreamStats,
};
pub use entry::QueryLogEntry;
pub use error::StatsError;
pub use metrics::MetricsRegistry;
pub use writer::{DEFAULT_CHANNEL_CAPACITY, QueryLogSender, QueryLogWriter};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_database_insert_and_query() {
        let db = StatsDb::in_memory().await.unwrap();

        let base_ts = chrono::Utc::now().timestamp_millis() - 100_000;
        let mut entries = Vec::new();
        for i in 0..50 {
            entries.push(QueryLogEntry {
                id: None,
                ts: base_ts + i * 1000,
                client_ip: format!("192.168.1.{}", 10 + i % 5),
                client_name: Some("device-1".into()),
                qname: format!("domain{}.example.com", i % 10),
                qtype: 1,
                rcode: Some(0),
                verdict: if i % 2 == 0 {
                    "allowed".into()
                } else {
                    "blocked".into()
                },
                rule: None,
                list_source: None,
                upstream: Some("tls://1.1.1.1".into()),
                elapsed_us: Some(1500 + i * 10),
                dnssec: Some("secure".into()),
                proto: "udp".into(),
            });
        }

        db.insert_batch(&entries).await.unwrap();

        // Query all logs with limit 20
        let page1 = db
            .query_logs(&QueryLogFilter {
                limit: Some(20),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(page1.entries.len(), 20);
        assert!(page1.next_cursor.is_some());

        // Paginate using cursor
        let cursor_id: i64 = page1.next_cursor.unwrap().parse().unwrap();
        let page2 = db
            .query_logs(&QueryLogFilter {
                cursor: Some(cursor_id),
                limit: Some(20),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(page2.entries.len(), 20);

        // Filter by verdict = blocked
        let blocked_page = db
            .query_logs(&QueryLogFilter {
                status: Some("blocked".into()),
                limit: Some(100),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(blocked_page.entries.len(), 25);

        // Global stats
        let stats = db.get_global_stats(86_400_000 * 365).await.unwrap();
        assert_eq!(stats.total_queries, 50);
        assert_eq!(stats.blocked_queries, 25);
        assert!((stats.blocked_percentage - 50.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_writer_pipeline_batching_and_overflow() {
        let db = StatsDb::in_memory().await.unwrap();
        // Very small channel capacity to easily trigger drops
        let writer = QueryLogWriter::spawn(db.clone(), 5);
        let sender = writer.sender();

        let mut live_tail = sender.subscribe();

        let entry = QueryLogEntry {
            id: None,
            ts: 1_700_000_000_000,
            client_ip: "10.0.0.1".into(),
            client_name: None,
            qname: "test.com".into(),
            qtype: 1,
            rcode: Some(0),
            verdict: "allowed".into(),
            rule: None,
            list_source: None,
            upstream: None,
            elapsed_us: Some(500),
            dnssec: None,
            proto: "udp".into(),
        };

        // Send one entry and verify live tail receives it
        assert!(sender.try_send(entry.clone()));
        let received = live_tail.recv().await.unwrap();
        assert_eq!(received.qname, "test.com");

        // Now saturate channel to test drop counter
        for _ in 0..100 {
            sender.try_send(entry.clone());
        }

        // Must have dropped some entries without blocking
        assert!(sender.dropped_total() > 0);

        sender.flush().await;

        let page = db.query_logs(&QueryLogFilter::default()).await.unwrap();
        assert!(!page.entries.is_empty());

        sender.shutdown().await;
    }

    #[tokio::test]
    async fn test_retention_cleaner_and_aggregation() {
        let db = StatsDb::in_memory().await.unwrap();

        let old_ts = 1_000_000_000_000; // far in past
        let recent_ts = chrono::Utc::now().timestamp_millis();

        let entries = vec![
            QueryLogEntry {
                id: None,
                ts: old_ts,
                client_ip: "192.168.1.1".into(),
                client_name: None,
                qname: "ancient.com".into(),
                qtype: 1,
                rcode: Some(0),
                verdict: "blocked".into(),
                rule: None,
                list_source: None,
                upstream: None,
                elapsed_us: None,
                dnssec: None,
                proto: "udp".into(),
            },
            QueryLogEntry {
                id: None,
                ts: recent_ts,
                client_ip: "192.168.1.1".into(),
                client_name: None,
                qname: "recent.com".into(),
                qtype: 1,
                rcode: Some(0),
                verdict: "allowed".into(),
                rule: None,
                list_source: None,
                upstream: None,
                elapsed_us: None,
                dnssec: None,
                proto: "udp".into(),
            },
        ];

        db.insert_batch(&entries).await.unwrap();

        // Prune logs older than 90 days
        let report = db.cleanup_retention(90).await.unwrap();
        assert_eq!(report.deleted_records, 1);
        assert_eq!(report.aggregated_hours, 1);

        // Verify ancient log was deleted and recent log remains
        let remaining = db.query_logs(&QueryLogFilter::default()).await.unwrap();
        assert_eq!(remaining.entries.len(), 1);
        assert_eq!(remaining.entries[0].qname, "recent.com");
    }

    #[tokio::test]
    async fn test_persistence_restart() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito-test-db-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db_path = temp_dir.join("stats.db");

        {
            let db = StatsDb::open(&db_path).await.unwrap();
            let entry = QueryLogEntry {
                id: None,
                ts: 1_700_000_000_000,
                client_ip: "192.168.1.100".into(),
                client_name: Some("persisted-host".into()),
                qname: "persisted.org".into(),
                qtype: 1,
                rcode: Some(0),
                verdict: "allowed".into(),
                rule: None,
                list_source: None,
                upstream: None,
                elapsed_us: Some(120),
                dnssec: None,
                proto: "udp".into(),
            };
            db.insert_batch(&[entry]).await.unwrap();
        } // Connection closed

        // Re-open and verify record survived restart
        {
            let db = StatsDb::open(&db_path).await.unwrap();
            let page = db.query_logs(&QueryLogFilter::default()).await.unwrap();
            assert_eq!(page.entries.len(), 1);
            assert_eq!(page.entries[0].qname, "persisted.org");
            assert_eq!(
                page.entries[0].client_name.as_deref(),
                Some("persisted-host")
            );
        }

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_50k_insertion_performance() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito-perf-db-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db_path = temp_dir.join("stats.db");
        let db = StatsDb::open(&db_path).await.unwrap();

        let count = 50_000;
        let mut entries = Vec::with_capacity(count);
        let base_ts = chrono::Utc::now().timestamp_millis();
        for i in 0..count {
            entries.push(QueryLogEntry {
                id: None,
                ts: base_ts + i64::try_from(i).unwrap_or(0),
                client_ip: "10.0.0.5".into(),
                client_name: None,
                qname: "speedtest.example".into(),
                qtype: 1,
                rcode: Some(0),
                verdict: "allowed".into(),
                rule: None,
                list_source: None,
                upstream: None,
                elapsed_us: Some(250),
                dnssec: None,
                proto: "udp".into(),
            });
        }

        let start = std::time::Instant::now();
        // Insert in 1000-item chunks (standard batch size)
        for chunk in entries.chunks(1000) {
            db.insert_batch(chunk).await.unwrap();
        }
        let elapsed = start.elapsed();
        println!("50,000 entries inserted in {elapsed:?}");
        assert!(
            elapsed < Duration::from_secs(10),
            "Insertion took {elapsed:?}, expected < 10s"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_get_hourly_activity() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();

        let entries = vec![
            QueryLogEntry {
                id: None,
                ts: now - 1800 * 1000,
                client_ip: "192.168.1.1".into(),
                client_name: None,
                qname: "test1.com".into(),
                qtype: 1,
                rcode: Some(0),
                verdict: "allowed".into(),
                rule: None,
                list_source: None,
                upstream: None,
                elapsed_us: Some(100),
                dnssec: None,
                proto: "udp".into(),
            },
            QueryLogEntry {
                id: None,
                ts: now - 1800 * 1000 + 10,
                client_ip: "192.168.1.2".into(),
                client_name: None,
                qname: "ad.tracker.com".into(),
                qtype: 1,
                rcode: Some(0),
                verdict: "blocked".into(),
                rule: Some("ad.tracker.com".into()),
                list_source: None,
                upstream: None,
                elapsed_us: Some(50),
                dnssec: None,
                proto: "udp".into(),
            },
        ];

        db.insert_batch(&entries).await.unwrap();
        let activity = db.get_hourly_activity(24).await.unwrap();
        assert_eq!(activity.len(), 24);
        let total_queries: i64 = activity.iter().map(|a| a.total_queries).sum();
        let blocked_queries: i64 = activity.iter().map(|a| a.blocked_queries).sum();
        assert_eq!(total_queries, 2);
        assert_eq!(blocked_queries, 1);
    }
}
