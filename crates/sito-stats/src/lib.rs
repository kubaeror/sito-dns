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
    ClientStats, GlobalStats, HourlyActivity, MAX_AGGREGATE_ROWS, QueryLogFilter, QueryLogPage,
    RetentionReport, StatsDb, UpstreamStats,
};
pub use entry::QueryLogEntry;
pub use error::StatsError;
pub use metrics::{FilterStatusMetrics, MetricsRegistry};
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
        assert!(
            !page.entries.is_empty(),
            "query log must contain at least one entry"
        );

        sender.shutdown().await;
    }

    #[tokio::test]
    async fn test_writer_anonymize_ip_toggle() {
        let db = StatsDb::in_memory().await.unwrap();
        let writer = QueryLogWriter::spawn_with_anonymize(db.clone(), 100, true);
        let sender = writer.sender();

        let mut live_tail = sender.subscribe();

        let entry = QueryLogEntry {
            id: None,
            ts: chrono::Utc::now().timestamp_millis(),
            client_ip: "192.168.1.100".into(),
            client_name: None,
            qname: "privacy.test".into(),
            qtype: 1,
            rcode: Some(0),
            verdict: "allowed".into(),
            rule: None,
            list_source: None,
            upstream: Some("1.1.1.1:53".into()),
            elapsed_us: Some(500),
            dnssec: None,
            proto: "udp".into(),
        };

        assert!(sender.try_send(entry));
        let live = live_tail.recv().await.unwrap();
        assert_eq!(live.client_ip, "192.168.1.0");

        sender.flush().await;

        let page = db.query_logs(&QueryLogFilter::default()).await.unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].client_ip, "192.168.1.0");
        assert_eq!(page.entries[0].upstream, Some("1.1.1.1:53".into()));

        // Toggle off
        sender.set_anonymize(false);
        let entry2 = QueryLogEntry {
            id: None,
            ts: chrono::Utc::now().timestamp_millis(),
            client_ip: "10.45.99.123".into(),
            client_name: None,
            qname: "raw.test".into(),
            qtype: 1,
            rcode: Some(0),
            verdict: "allowed".into(),
            rule: None,
            list_source: None,
            upstream: Some("8.8.8.8:53".into()),
            elapsed_us: Some(300),
            dnssec: None,
            proto: "udp".into(),
        };

        assert!(sender.try_send(entry2));
        let live2 = live_tail.recv().await.unwrap();
        assert_eq!(live2.client_ip, "10.45.99.123");

        sender.flush().await;
        let page2 = db.query_logs(&QueryLogFilter::default()).await.unwrap();
        assert_eq!(page2.entries.len(), 2);
        assert_eq!(page2.entries[0].client_ip, "10.45.99.123");
        assert_eq!(page2.entries[0].upstream, Some("8.8.8.8:53".into()));

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

        // Timing budgets are environment-gated so shared CI runners and
        // pre-commit hooks do not fail on scheduling noise. Functional
        // correctness is always asserted below.
        if std::env::var_os("SITO_PERF_TESTS").is_some() {
            assert!(
                elapsed < Duration::from_secs(30),
                "Insertion took {elapsed:?}, expected < 30s"
            );
        } else {
            println!("Timing assertion skipped; set SITO_PERF_TESTS=1 to enforce");
        }

        // Always verify every entry is retrievable through the paginated API.
        let mut total = 0usize;
        let mut cursor = None;
        loop {
            let page = db
                .query_logs(&QueryLogFilter {
                    limit: Some(1000),
                    cursor,
                    ..Default::default()
                })
                .await
                .unwrap();
            total += page.entries.len();
            match page.next_cursor {
                Some(next) => cursor = next.parse::<i64>().ok(),
                None => break,
            }
        }
        assert_eq!(total, count, "all inserted entries must be queryable");

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

    #[tokio::test]
    async fn test_retention_watermark_prevents_double_counting() {
        let db = StatsDb::in_memory().await.unwrap();

        let hour_ts = 1_000_000_000_000i64;
        let entry1 = QueryLogEntry {
            id: None,
            ts: hour_ts,
            client_ip: "10.0.0.1".into(),
            client_name: None,
            qname: "double1.com".into(),
            qtype: 1,
            rcode: Some(0),
            verdict: "allowed".into(),
            rule: None,
            list_source: None,
            upstream: None,
            elapsed_us: None,
            dnssec: None,
            proto: "udp".into(),
        };
        let entry2 = QueryLogEntry {
            id: None,
            ts: hour_ts + 100,
            client_ip: "10.0.0.2".into(),
            client_name: None,
            qname: "double2.com".into(),
            qtype: 1,
            rcode: Some(0),
            verdict: "blocked".into(),
            rule: None,
            list_source: None,
            upstream: None,
            elapsed_us: None,
            dnssec: None,
            proto: "udp".into(),
        };

        db.insert_batch(&[entry1, entry2]).await.unwrap();

        // 1st aggregation: entries are older than 90 days
        let rep1 = db.cleanup_retention(90).await.unwrap();
        assert_eq!(rep1.aggregated_hours, 1);
        assert_eq!(rep1.deleted_records, 2);

        let watermark = sqlx::query_as::<_, (i64, i64)>(
            "SELECT last_id, last_ts FROM stats_watermark WHERE key = 'hourly_aggregation'",
        )
        .fetch_optional(db.pool())
        .await
        .unwrap();
        assert!(watermark.is_some());
        let (wm_id, wm_ts) = watermark.unwrap();
        assert!(wm_id >= 2);
        assert!(wm_ts > 0);

        // Verify stats_hourly has exactly 2 queries
        let (queries, blocked): (i64, i64) = sqlx::query_as(
            "SELECT queries, blocked FROM stats_hourly WHERE hour = (1000000000000 / 3600000) * 3600000",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(queries, 2);
        assert_eq!(blocked, 1);

        // Run cleanup_retention again - should aggregate 0 hours because watermark prevents double counting
        let rep2 = db.cleanup_retention(90).await.unwrap();
        assert_eq!(rep2.aggregated_hours, 0);
        assert_eq!(rep2.deleted_records, 0);

        let (queries2, blocked2): (i64, i64) = sqlx::query_as(
            "SELECT queries, blocked FROM stats_hourly WHERE hour = (1000000000000 / 3600000) * 3600000",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(queries2, 2);
        assert_eq!(blocked2, 1);

        // Insert another entry in the same hour
        let entry3 = QueryLogEntry {
            id: None,
            ts: hour_ts + 200,
            client_ip: "10.0.0.3".into(),
            client_name: None,
            qname: "double3.com".into(),
            qtype: 1,
            rcode: Some(0),
            verdict: "allowed".into(),
            rule: None,
            list_source: None,
            upstream: None,
            elapsed_us: None,
            dnssec: None,
            proto: "udp".into(),
        };
        db.insert_batch(&[entry3]).await.unwrap();

        // 3rd cleanup should only aggregate entry3 (1 new query, not re-aggregating entry1 and entry2)
        let rep3 = db.cleanup_retention(90).await.unwrap();
        assert_eq!(rep3.aggregated_hours, 1);
        assert_eq!(rep3.deleted_records, 1);

        let (queries3, blocked3): (i64, i64) = sqlx::query_as(
            "SELECT queries, blocked FROM stats_hourly WHERE hour = (1000000000000 / 3600000) * 3600000",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(queries3, 3);
        assert_eq!(blocked3, 1);
    }

    #[tokio::test]
    async fn test_query_logs_with_special_characters_sql_injection_safe() {
        let db = StatsDb::in_memory().await.unwrap();

        let entries = vec![
            QueryLogEntry {
                id: None,
                ts: 1_700_000_000_000,
                client_ip: "10.0.0.1".into(),
                client_name: Some("client' OR '1'='1".into()),
                qname: "foo%bar'baz.com".into(),
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
            QueryLogEntry {
                id: None,
                ts: 1_700_000_000_100,
                client_ip: "10.0.0.2".into(),
                client_name: Some("normal-client".into()),
                qname: "regular.org".into(),
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
        ];

        db.insert_batch(&entries).await.unwrap();

        // Query by client with quote injection
        let res_client = db
            .query_logs(&QueryLogFilter {
                client: Some("client' OR '1'='1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(res_client.entries.len(), 1);
        assert_eq!(res_client.entries[0].qname, "foo%bar'baz.com");

        // Query by domain with percent and quote
        let res_domain = db
            .query_logs(&QueryLogFilter {
                domain: Some("foo%bar'".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(res_domain.entries.len(), 1);
        assert_eq!(res_domain.entries[0].qname, "foo%bar'baz.com");

        // Query with malicious status injection
        let res_status = db
            .query_logs(&QueryLogFilter {
                status: Some("' OR 1=1 --".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(res_status.entries.len(), 0);
    }

    #[test]
    fn test_metrics_registry_queries_and_upstream_reports() {
        let metrics = MetricsRegistry::new("1.0.0", "test");
        metrics.inc_queries("udp", 1, "allowed");
        metrics.inc_queries("udp", 28, "blocked");
        metrics.inc_queries("tcp", 1, "allowed");

        let (total, blocked) = metrics.get_queries_and_blocked();
        assert_eq!(total, 3);
        assert_eq!(blocked, 1);

        metrics.observe_upstream_rtt("1.1.1.1:53", 0.025);
        metrics.observe_upstream_rtt("1.1.1.1:53", 0.035);
        metrics.inc_upstream_errors("1.1.1.1:53", "timeout");
        metrics.inc_upstream_errors("8.8.8.8:53", "network");

        let upstreams = metrics.get_upstream_reports();
        assert_eq!(upstreams.len(), 2);
        let u1 = upstreams.get("1.1.1.1:53").unwrap();
        assert!((u1.0 - 30.0).abs() < 1e-3);
        assert_eq!(u1.1, 1);

        let u2 = upstreams.get("8.8.8.8:53").unwrap();
        assert!(u2.0.abs() < 1e-6);
        assert_eq!(u2.1, 1);
    }

    fn retention_entry(ts: i64, qname: &str, verdict: &str, rule: Option<&str>) -> QueryLogEntry {
        QueryLogEntry {
            id: None,
            ts,
            client_ip: "10.0.0.1".into(),
            client_name: None,
            qname: qname.into(),
            qtype: 1,
            rcode: Some(0),
            verdict: verdict.into(),
            rule: rule.map(str::to_string),
            list_source: None,
            upstream: None,
            elapsed_us: None,
            dnssec: None,
            proto: "udp".into(),
        }
    }

    #[tokio::test]
    async fn test_retention_aggregates_backdated_rows_after_watermark() {
        let db = StatsDb::in_memory().await.unwrap();

        let hour_ts = 1_000_000_000_000i64;
        db.insert_batch(&[
            retention_entry(hour_ts, "double1.com", "allowed", None),
            retention_entry(hour_ts + 100, "double2.com", "blocked", None),
        ])
        .await
        .unwrap();

        let rep1 = db.cleanup_retention(90).await.unwrap();
        assert_eq!(rep1.aggregated_hours, 1);
        assert_eq!(rep1.deleted_records, 2);

        // Simulate a watermark recorded from an out-of-order producer: the
        // stored `last_id` is higher than any id a later backdated insert can
        // receive. The old `id > watermark` filter skipped such rows and then
        // deleted them unaggregated.
        sqlx::query(
            "UPDATE stats_watermark SET last_id = 1000000 WHERE key = 'hourly_aggregation'",
        )
        .execute(db.pool())
        .await
        .unwrap();

        // Backdated row: new id, timestamp older than the previous watermark ts.
        db.insert_batch(&[retention_entry(
            hour_ts + 50,
            "double3.com",
            "allowed",
            None,
        )])
        .await
        .unwrap();

        let rep2 = db.cleanup_retention(90).await.unwrap();
        assert_eq!(rep2.aggregated_hours, 1);
        assert_eq!(rep2.deleted_records, 1);

        let (queries, blocked): (i64, i64) = sqlx::query_as(
            "SELECT queries, blocked FROM stats_hourly WHERE hour = (1000000000000 / 3600000) * 3600000",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(queries, 3, "backdated row must not be lost");
        assert_eq!(blocked, 1);

        // The row was aggregated and pruned, not silently deleted.
        let remaining = db.query_logs(&QueryLogFilter::default()).await.unwrap();
        assert!(
            remaining.entries.is_empty(),
            "pruned query log must have no entries left: {:?}",
            remaining.entries
        );
    }

    #[tokio::test]
    async fn test_retention_rolls_back_when_aggregation_fails() {
        let db = StatsDb::in_memory().await.unwrap();
        db.insert_batch(&[retention_entry(
            1_000_000_000_000i64,
            "rollback.test",
            "allowed",
            None,
        )])
        .await
        .unwrap();

        // Force the rollup upsert to fail after the aggregate read.
        sqlx::query("DROP TABLE stats_hourly")
            .execute(db.pool())
            .await
            .unwrap();

        let err = db.cleanup_retention(90).await;
        assert!(err.is_err(), "cleanup must surface the aggregation failure");

        // Aggregate, watermark update and delete share one transaction, so the
        // row must survive the failed cleanup.
        let page = db.query_logs(&QueryLogFilter::default()).await.unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].qname, "rollback.test");
    }

    #[tokio::test]
    async fn test_hourly_activity_merges_archived_and_live_hour() {
        let db = StatsDb::in_memory().await.unwrap();

        let current_hour_sec = (chrono::Utc::now().timestamp() / 3600) * 3600;
        let target_hour_sec = current_hour_sec - 2 * 3600;
        let target_hour_ms = target_hour_sec * 1000;

        // Archived rollup for a partially-pruned hour.
        sqlx::query(
            "INSERT INTO stats_hourly (hour, queries, blocked, cached, top_domains, top_clients) \
             VALUES (?, 5, 2, 0, '[]', '[]')",
        )
        .bind(target_hour_ms)
        .execute(db.pool())
        .await
        .unwrap();

        // Live rows still inside retention for the same hour.
        db.insert_batch(&[retention_entry(
            target_hour_ms + 1000,
            "live.test",
            "allowed",
            None,
        )])
        .await
        .unwrap();

        let activity = db.get_hourly_activity(24).await.unwrap();
        let bucket = activity
            .iter()
            .find(|a| a.timestamp_sec == target_hour_sec)
            .expect("target hour bucket");
        assert_eq!(
            bucket.total_queries, 6,
            "archived counts must not be dropped"
        );
        assert_eq!(bucket.blocked_queries, 2);
    }

    #[tokio::test]
    async fn test_cached_counter_counts_cache_and_stale_cache_rules() {
        let db = StatsDb::in_memory().await.unwrap();
        let old_ts = 1_000_000_000_000i64;
        db.insert_batch(&[
            retention_entry(old_ts, "hit.test", "allowed", Some("cache")),
            retention_entry(old_ts + 1, "stale.test", "allowed", Some("stale_cache")),
            retention_entry(old_ts + 2, "plain.test", "allowed", None),
            retention_entry(old_ts + 3, "blocked.test", "blocked", None),
        ])
        .await
        .unwrap();

        let stats = db.get_global_stats(86_400_000 * 365 * 100).await.unwrap();
        assert_eq!(stats.total_queries, 4);
        assert_eq!(stats.cached_queries, 2);
        assert_eq!(stats.blocked_queries, 1);

        let report = db.cleanup_retention(90).await.unwrap();
        assert_eq!(report.aggregated_hours, 1);
        let (cached, blocked): (i64, i64) = sqlx::query_as(
            "SELECT cached, blocked FROM stats_hourly WHERE hour = (1000000000000 / 3600000) * 3600000",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(cached, 2, "stale_cache rule must count as cached");
        assert_eq!(blocked, 1);
    }

    #[tokio::test]
    async fn test_global_stats_top_domains_and_clients() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let mut entries = Vec::new();
        for i in 0..3 {
            let mut entry = retention_entry(now + i, "popular.example", "allowed", None);
            entry.client_ip = "192.168.1.10".into();
            entries.push(entry);
        }
        let mut entry = retention_entry(now + 10, "blocked.example", "blocked", None);
        entry.client_ip = "192.168.1.20".into();
        entries.push(entry);
        db.insert_batch(&entries).await.unwrap();

        let stats = db.get_global_stats(86_400_000).await.unwrap();
        assert_eq!(
            stats.top_domains.first(),
            Some(&("popular.example".to_string(), 3))
        );
        assert_eq!(
            stats.top_blocked_domains.first(),
            Some(&("blocked.example".to_string(), 1))
        );
        assert_eq!(
            stats.top_clients.first(),
            Some(&("192.168.1.10".to_string(), 3))
        );
    }

    /// WP-7.2: retention populates the hourly top lists and long windows are
    /// answered from the rollups instead of silently under-reporting.
    #[tokio::test]
    async fn test_retention_populates_rollups_and_long_window_merges_them() {
        // Client names are opt-in; enable them to verify the merge path. The
        // raw IP must still never appear in the rollup.
        let db = StatsDb::in_memory_with_rollup_client_names(true)
            .await
            .unwrap();
        // Older than the 90-day retention period, but inside the 365-day
        // statistics window used below.
        let old_ts = chrono::Utc::now().timestamp_millis() - 100 * 86_400_000;
        let mut entries = Vec::new();
        for i in 0..5 {
            let mut entry =
                retention_entry(old_ts + i * 60_000, "archived.example", "allowed", None);
            entry.client_ip = "10.9.9.9".into();
            entry.client_name = Some("archived-host".into());
            entry.upstream = Some("tls://9.9.9.9".into());
            entry.elapsed_us = Some(1_000);
            entries.push(entry);
        }
        for i in 0..3 {
            let mut entry =
                retention_entry(old_ts + i * 60_000, "blocked.example", "blocked", None);
            entry.client_ip = "10.8.8.8".into();
            entry.upstream = Some("tls://8.8.8.8".into());
            entry.elapsed_us = Some(2_000);
            entries.push(entry);
        }
        db.insert_batch(&entries).await.unwrap();

        let report = db.cleanup_retention(90).await.unwrap();
        assert_eq!(report.deleted_records, 8);

        // The hourly rollup carries bounded top lists (previously always '[]').
        let (top_domains, top_clients, top_upstreams): (String, String, String) = sqlx::query_as(
            "SELECT top_domains, top_clients, top_upstreams FROM stats_hourly LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_ne!(top_domains, "[]");
        assert_ne!(top_clients, "[]");
        assert_ne!(top_upstreams, "[]");

        // A 365-day window must include the pruned rows via the rollups.
        let stats = db.get_global_stats(365 * 86_400_000).await.unwrap();
        assert_eq!(stats.total_queries, 8);
        assert_eq!(stats.blocked_queries, 3);
        assert_eq!(
            stats.top_domains.first(),
            Some(&("archived.example".to_string(), 5))
        );
        assert_eq!(
            stats.top_blocked_domains.first(),
            Some(&("blocked.example".to_string(), 3))
        );
        assert_eq!(
            stats.top_clients.first(),
            Some(&("archived-host".to_string(), 5))
        );

        let clients = db.get_client_stats(365 * 86_400_000).await.unwrap();
        let archived = clients
            .iter()
            .find(|c| c.client_name.as_deref() == Some("archived-host"))
            .expect("archived client must be merged into a long window");
        assert!(
            archived.client_ip.starts_with("blake3:"),
            "rollup client IP must be a keyed hash, got {}",
            archived.client_ip
        );
        assert_eq!(archived.total_queries, 5);

        // No raw client IP may survive in the rollup payload.
        let raw_payload: String = sqlx::query_scalar(
            "SELECT COALESCE(GROUP_CONCAT(top_clients, ''), '') FROM stats_hourly",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert!(
            !raw_payload.contains("10.9.9.9") && !raw_payload.contains("10.8.8.8"),
            "raw client IPs must not be stored in stats_hourly: {raw_payload}"
        );

        let upstreams = db.get_upstream_stats(365 * 86_400_000).await.unwrap();
        let tls = upstreams
            .iter()
            .find(|u| u.upstream == "tls://9.9.9.9")
            .expect("archived upstream must be merged into a long window");
        assert_eq!(tls.total_queries, 5);
        assert_eq!(tls.avg_elapsed_us, 1_000);
    }

    /// WP-7.2: re-rolling a partially pruned hour merges (not replaces) the
    /// stored top lists.
    #[tokio::test]
    async fn test_rollup_tops_merge_across_repeated_sweeps() {
        let db = StatsDb::in_memory().await.unwrap();
        let hour_ts = 1_000_000_000_000i64;
        db.insert_batch(&[retention_entry(hour_ts, "first.test", "allowed", None)])
            .await
            .unwrap();
        let rep1 = db.cleanup_retention(90).await.unwrap();
        assert_eq!(rep1.aggregated_hours, 1);

        db.insert_batch(&[retention_entry(
            hour_ts + 10,
            "second.test",
            "allowed",
            None,
        )])
        .await
        .unwrap();
        let rep2 = db.cleanup_retention(90).await.unwrap();
        assert_eq!(rep2.aggregated_hours, 1);

        let (top_domains,): (String,) = sqlx::query_as(
            "SELECT top_domains FROM stats_hourly WHERE hour = (1000000000000 / 3600000) * 3600000",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        let tops: Vec<(String, i64, i64)> = serde_json::from_str(&top_domains).unwrap();
        let names: Vec<&str> = tops.iter().map(|(qname, _, _)| qname.as_str()).collect();
        assert!(
            names.contains(&"first.test"),
            "first sweep top must survive"
        );
        assert!(
            names.contains(&"second.test"),
            "second sweep top must be merged in"
        );
    }

    /// P1-19: the default “clear query log” erases both detailed rows and
    /// aggregate rollups.
    #[tokio::test]
    async fn test_delete_query_logs_default_clears_rollups() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        db.insert_batch(&[
            retention_entry(now - 1_000, "keep-total.example", "allowed", None),
            retention_entry(now - 900, "keep-total.example", "blocked", None),
        ])
        .await
        .unwrap();

        let deleted = db.delete_query_logs().await.unwrap();
        assert_eq!(deleted, 2);
        let remaining = db.query_logs(&QueryLogFilter::default()).await.unwrap();
        assert!(
            remaining.entries.is_empty(),
            "delete_query_logs must remove all entries: {:?}",
            remaining.entries
        );

        let rollups: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stats_hourly")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(rollups, 0, "default clear must delete stats_hourly");
        let stats = db.get_global_stats(86_400_000).await.unwrap();
        assert_eq!(stats.total_queries, 0);
    }

    /// P1-19: `--keep-aggregates` folds rows into `stats_hourly` so totals
    /// survive the clear.
    #[tokio::test]
    async fn test_delete_query_logs_keep_aggregates_preserves_rollups() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        db.insert_batch(&[
            retention_entry(now - 1_000, "keep-total.example", "allowed", None),
            retention_entry(now - 900, "keep-total.example", "blocked", None),
        ])
        .await
        .unwrap();

        let deleted = db.delete_query_logs_keep_aggregates().await.unwrap();
        assert_eq!(deleted, 2);
        let remaining = db.query_logs(&QueryLogFilter::default()).await.unwrap();
        assert_eq!(remaining.entries.len(), 0);

        let rollups: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stats_hourly")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(rollups, 1, "keep-aggregates must preserve rollups");
        let stats = db.get_global_stats(86_400_000).await.unwrap();
        assert_eq!(
            stats.total_queries, 2,
            "keep-aggregates must not reset aggregate totals"
        );
        assert_eq!(stats.blocked_queries, 1);
        assert_eq!(
            stats.top_domains.first(),
            Some(&("keep-total.example".to_string(), 2))
        );
    }

    /// WP-7.2: `cleanup_retention` vacuums after a large sweep so pages freed
    /// by the delete are returned to the filesystem.
    #[tokio::test]
    async fn test_retention_vacuum_shrinks_database_after_large_delete() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito-vacuum-db-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db_path = temp_dir.join("stats.db");
        let db = StatsDb::open(&db_path).await.unwrap();

        let old_ts = 1_000_000_000_000i64;
        let padding = "x".repeat(200);
        let mut entries = Vec::new();
        for i in 0..3_000i64 {
            let mut entry = retention_entry(old_ts + i, "vacuum.test", "allowed", None);
            entry.client_ip = format!("10.{}.{}.{}", i / 65_536, (i / 256) % 256, i % 256);
            entry.rule = Some(format!("{padding}-{i}"));
            entries.push(entry);
        }
        db.insert_batch(&entries).await.unwrap();

        let before = db.db_size_bytes().await.unwrap();
        let report = db.cleanup_retention(90).await.unwrap();
        assert_eq!(report.deleted_records, 3_000);
        let after = db.db_size_bytes().await.unwrap();
        assert!(
            after < before,
            "vacuum must shrink the database after a large retention delete \
             (before={before}, after={after})"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// WP-7.2: pagination exposes the number of rows matching the filters.
    #[tokio::test]
    async fn test_query_logs_total_count_matches_filters() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let mut entries = Vec::new();
        for i in 0..50 {
            let verdict = if i % 2 == 0 { "allowed" } else { "blocked" };
            entries.push(retention_entry(now + i, "count.test", verdict, None));
        }
        db.insert_batch(&entries).await.unwrap();

        let page = db
            .query_logs(&QueryLogFilter {
                limit: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page.entries.len(), 10);
        assert_eq!(page.total_count, Some(50));

        let blocked = db
            .query_logs(&QueryLogFilter {
                status: Some("blocked".into()),
                limit: Some(100),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(blocked.total_count, Some(25));

        // The cursor must not change the total.
        let cursor = page.next_cursor.unwrap().parse::<i64>().unwrap();
        let page2 = db
            .query_logs(&QueryLogFilter {
                cursor: Some(cursor),
                limit: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page2.total_count, Some(50));
    }

    /// WP-7.3: the per-client aggregate is bounded, deterministically ordered
    /// and reports the total number of distinct clients.
    #[tokio::test]
    async fn test_client_stats_are_bounded_and_deterministic() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let clients = 3_000i64;
        let mut entries = Vec::new();
        for i in 0..clients {
            for r in 0..=(i % 3) {
                let mut entry = retention_entry(now + i + r, "client.test", "allowed", None);
                entry.client_ip = format!("10.{}.{}.{}", i / 65_536, (i / 256) % 256, i % 256);
                entry.client_name = Some(format!("host-{}", i % 10));
                entries.push(entry);
            }
        }
        db.insert_batch(&entries).await.unwrap();

        let stats = db.get_client_stats(86_400_000).await.unwrap();
        assert_eq!(
            stats.len(),
            MAX_AGGREGATE_ROWS,
            "result set must be bounded"
        );
        assert_eq!(
            db.count_client_stats(86_400_000).await.unwrap(),
            clients,
            "distinct client total must be reported"
        );
        assert!(stats.windows(2).all(|w| {
            w[0].total_queries > w[1].total_queries
                || (w[0].total_queries == w[1].total_queries && w[0].client_ip < w[1].client_ip)
        }));

        // One address seen under several names keeps MAX(client_name).
        let db2 = StatsDb::in_memory().await.unwrap();
        let mut first = retention_entry(now, "name.test", "allowed", None);
        first.client_ip = "10.1.1.1".into();
        first.client_name = Some("zulu".into());
        let mut second = retention_entry(now + 1, "name.test", "allowed", None);
        second.client_ip = "10.1.1.1".into();
        second.client_name = Some("alpha".into());
        db2.insert_batch(&[first, second]).await.unwrap();
        let stats = db2.get_client_stats(86_400_000).await.unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].client_name.as_deref(), Some("zulu"));
    }

    /// WP-7.3: the per-upstream aggregate is bounded, deterministically ordered
    /// and reports the total number of distinct upstreams.
    #[tokio::test]
    async fn test_upstream_stats_are_bounded_and_deterministic() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let upstreams = 3_000i64;
        let mut entries = Vec::new();
        for i in 0..upstreams {
            for r in 0..=(i % 3) {
                let mut entry = retention_entry(now + i + r, "upstream.test", "allowed", None);
                entry.upstream = Some(format!(
                    "tls://10.{}.{}.{}",
                    i / 65_536,
                    (i / 256) % 256,
                    i % 256
                ));
                entry.elapsed_us = Some(100);
                entries.push(entry);
            }
        }
        db.insert_batch(&entries).await.unwrap();

        let stats = db.get_upstream_stats(86_400_000).await.unwrap();
        assert_eq!(
            stats.len(),
            MAX_AGGREGATE_ROWS,
            "result set must be bounded"
        );
        assert_eq!(
            db.count_upstream_stats(86_400_000).await.unwrap(),
            upstreams,
            "distinct upstream total must be reported"
        );
        assert!(stats.windows(2).all(|w| {
            w[0].total_queries > w[1].total_queries
                || (w[0].total_queries == w[1].total_queries && w[0].upstream < w[1].upstream)
        }));
    }

    /// WP-7.2/7.3: blocked domains are ranked independently of the total-query
    /// ranking, so a heavily blocked domain outside the total top-N is still
    /// reported.
    #[tokio::test]
    async fn test_top_blocked_domains_ranked_independently() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let mut entries = Vec::new();
        // 120 noise domains with three queries each: enough to push the
        // blocked-heavy domain out of the top-100 by total.
        for i in 0..120 {
            for k in 0..3 {
                let mut entry = retention_entry(
                    now + i * 3 + k,
                    &format!("noise-{i}.example"),
                    "allowed",
                    None,
                );
                entry.client_ip = "10.0.0.1".into();
                entries.push(entry);
            }
        }
        // The blocked-heavy domain: two queries, both blocked.
        for k in 0..2 {
            let mut entry =
                retention_entry(now + 100_000 + k, "blocked-heavy.example", "blocked", None);
            entry.client_ip = "10.0.0.2".into();
            entries.push(entry);
        }
        db.insert_batch(&entries).await.unwrap();

        let stats = db.get_global_stats(86_400_000).await.unwrap();
        assert_eq!(
            stats.top_blocked_domains.first(),
            Some(&("blocked-heavy.example".to_string(), 2)),
            "blocked ranking must not depend on the total-query ranking"
        );
    }

    /// WP-7.2/7.3: a blocked-heavy domain that is outside the top-N by total
    /// must survive the hourly rollup and still be reported for a long window.
    #[tokio::test]
    async fn test_rollup_keeps_blocked_heavy_domain_outside_total_top_n() {
        let db = StatsDb::in_memory().await.unwrap();
        // Older than retention, inside the 365-day window used below.
        let old_ts = chrono::Utc::now().timestamp_millis() - 100 * 86_400_000;
        let mut entries = Vec::new();
        for i in 0..120 {
            for k in 0..3 {
                let mut entry = retention_entry(
                    old_ts + i * 3 + k,
                    &format!("noise-{i}.example"),
                    "allowed",
                    None,
                );
                entry.client_ip = "10.0.0.1".into();
                entries.push(entry);
            }
        }
        for k in 0..2 {
            let mut entry = retention_entry(
                old_ts + 100_000 + k,
                "blocked-heavy.example",
                "blocked",
                None,
            );
            entry.client_ip = "10.0.0.2".into();
            entries.push(entry);
        }
        db.insert_batch(&entries).await.unwrap();

        let report = db.cleanup_retention(90).await.unwrap();
        assert_eq!(report.deleted_records, 120 * 3 + 2);

        let stats = db.get_global_stats(365 * 86_400_000).await.unwrap();
        assert_eq!(
            stats.top_blocked_domains.first(),
            Some(&("blocked-heavy.example".to_string(), 2)),
            "rollup must keep the top-blocked union, not only the top-total list"
        );
    }

    /// WP-7.2: rows arriving after a clear are added to the folded totals
    /// without double counting the cleared rows.
    #[tokio::test]
    async fn test_delete_query_logs_then_new_rows_do_not_double_count() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        db.insert_batch(&[retention_entry(
            now - 1_000,
            "same-hour.example",
            "allowed",
            None,
        )])
        .await
        .unwrap();
        db.delete_query_logs_keep_aggregates().await.unwrap();
        db.insert_batch(&[retention_entry(
            now - 500,
            "same-hour.example",
            "blocked",
            None,
        )])
        .await
        .unwrap();

        let stats = db.get_global_stats(86_400_000).await.unwrap();
        assert_eq!(stats.total_queries, 2);
        assert_eq!(stats.blocked_queries, 1);
        assert_eq!(
            stats.top_domains.first(),
            Some(&("same-hour.example".to_string(), 2))
        );
    }

    #[tokio::test]
    async fn test_client_ip_ts_index_exists() {
        let db = StatsDb::in_memory().await.unwrap();
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_ql_client_ip_ts'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(
            count, 1,
            "(client_ip, ts) index must be created by migration"
        );
    }

    #[tokio::test]
    async fn test_db_size_includes_wal_and_shm_sidecars() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito-size-db-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db_path = temp_dir.join("stats.db");
        let db = StatsDb::open(&db_path).await.unwrap();
        db.insert_batch(&[retention_entry(
            1_700_000_000_000,
            "size.test",
            "allowed",
            None,
        )])
        .await
        .unwrap();

        let main = tokio::fs::metadata(&db_path).await.unwrap().len();
        let wal = match tokio::fs::metadata(format!("{}-wal", db_path.display())).await {
            Ok(meta) => meta.len(),
            Err(_) => 0,
        };
        let shm = match tokio::fs::metadata(format!("{}-shm", db_path.display())).await {
            Ok(meta) => meta.len(),
            Err(_) => 0,
        };

        let total = db.db_size_bytes().await.unwrap();
        assert_eq!(total, main + wal + shm);
        assert!(total >= main);

        // In-memory databases have no on-disk footprint.
        let memory = StatsDb::in_memory().await.unwrap();
        assert_eq!(memory.db_size_bytes().await.unwrap(), 0);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_writer_counts_batches_dropped_after_flush_failure() {
        let db = StatsDb::in_memory().await.unwrap();
        let writer = QueryLogWriter::spawn(db.clone(), 10);
        let sender = writer.sender();

        // Simulate a persistent storage failure: every insert fails.
        sqlx::query("DROP TABLE query_log")
            .execute(db.pool())
            .await
            .unwrap();

        assert!(sender.try_send(retention_entry(
            1_700_000_000_000,
            "lost.test",
            "allowed",
            None
        )));
        sender.flush().await;

        assert!(
            sender.dropped_total() >= 1,
            "failed flush must be counted instead of silently discarded"
        );

        sender.shutdown().await;
    }

    /// P1-19: rollups store keyed hashes, never raw client IPs, and client
    /// names are omitted unless explicitly enabled.
    #[tokio::test]
    async fn test_rollup_pii_hashes_client_ip_and_omits_names_by_default() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let first_hour = now - 100 * 86_400_000;
        let second_hour = first_hour + 3_600_000;

        let mut first = retention_entry(first_hour, "pii.example", "allowed", None);
        first.client_ip = "192.168.1.42".into();
        first.client_name = Some("secret-laptop".into());
        let mut second = retention_entry(second_hour, "pii.example", "allowed", None);
        second.client_ip = "192.168.1.42".into();
        second.client_name = Some("secret-laptop".into());
        db.insert_batch(&[first, second]).await.unwrap();

        db.cleanup_retention(90).await.unwrap();

        let rows: Vec<(i64, String)> =
            sqlx::query_as("SELECT hour, top_clients FROM stats_hourly ORDER BY hour ASC")
                .fetch_all(db.pool())
                .await
                .unwrap();
        assert_eq!(rows.len(), 2);

        let mut hashes = Vec::new();
        for (_, payload) in &rows {
            assert!(
                !payload.contains("192.168.1.42"),
                "raw IP leaked: {payload}"
            );
            assert!(
                !payload.contains("secret-laptop"),
                "client name leaked: {payload}"
            );
            let tops: Vec<(String, Option<String>, i64, i64, i64)> =
                serde_json::from_str(payload).unwrap();
            assert_eq!(tops.len(), 1);
            assert!(tops[0].0.starts_with("blake3:"));
            assert!(tops[0].1.is_none(), "names are opt-in");
            hashes.push(tops[0].0.clone());
        }
        assert_eq!(
            hashes[0], hashes[1],
            "the same client IP must hash stably across hours"
        );

        let clients = db.get_client_stats(365 * 86_400_000).await.unwrap();
        assert_eq!(clients.len(), 1);
        assert!(clients[0].client_ip.starts_with("blake3:"));
        assert!(clients[0].client_name.is_none());
    }

    /// P1-19: rollups (and their domains) are deleted after
    /// `rollup_retention_days`, independently of detailed-log retention.
    #[tokio::test]
    async fn test_rollup_retention_deletes_expired_domains_and_rows() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let expired = now - 400 * 86_400_000;
        let retained = now - 100 * 86_400_000;

        db.insert_batch(&[
            retention_entry(expired, "expired-domain.example", "allowed", None),
            retention_entry(retained, "retained-domain.example", "allowed", None),
        ])
        .await
        .unwrap();

        let report = db
            .cleanup_retention_with_policy(90, 365, false)
            .await
            .unwrap();
        assert_eq!(report.deleted_records, 2);
        assert_eq!(report.rollup_deleted_records, 1);

        let domains: String = sqlx::query_scalar(
            "SELECT COALESCE(GROUP_CONCAT(top_domains, ''), '') FROM stats_hourly",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert!(!domains.contains("expired-domain.example"));
        assert!(domains.contains("retained-domain.example"));
    }

    /// P1-24: retention commits bounded chunks and records a startup
    /// catch-up timestamp.
    #[tokio::test]
    async fn test_retention_uses_bounded_chunks_and_records_success() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let start = now - 200 * 86_400_000;

        let mut entries = Vec::new();
        for hour in 0..60 {
            entries.push(retention_entry(
                start + hour * 3_600_000,
                "chunk.example",
                "allowed",
                None,
            ));
        }
        db.insert_batch(&entries).await.unwrap();

        assert!(db.retention_last_success_ms().await.unwrap().is_none());
        let report = db
            .cleanup_retention_with_policy(90, 365, false)
            .await
            .unwrap();
        assert_eq!(report.deleted_records, 60);
        assert!(
            report.chunks >= 2,
            "a multi-hour backlog must be split into bounded transactions, got {}",
            report.chunks
        );
        assert!(db.retention_last_success_ms().await.unwrap().is_some());

        // A second sweep has nothing left but still refreshes the marker.
        let second = db
            .cleanup_retention_with_policy(90, 365, false)
            .await
            .unwrap();
        assert_eq!(second.deleted_records, 0);
        assert_eq!(second.chunks, 0);
        assert!(db.retention_last_success_ms().await.unwrap().is_some());
    }

    /// P1-24: the query-log writer must not drop a batch while a bounded
    /// retention sweep is running.
    #[tokio::test]
    async fn test_retention_concurrent_insert_does_not_drop_batches() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let start = now - 200 * 86_400_000;

        let mut old_entries = Vec::new();
        for hour in 0..50 {
            for offset in 0..20 {
                old_entries.push(retention_entry(
                    start + hour * 3_600_000 + offset,
                    "backlog.example",
                    "allowed",
                    None,
                ));
            }
        }
        db.insert_batch(&old_entries).await.unwrap();

        let writer = QueryLogWriter::spawn(db.clone(), 10_000);
        let sender = writer.sender();

        let send = async {
            for i in 0..500 {
                assert!(
                    sender.try_send(retention_entry(
                        now - 1_000 + i,
                        "concurrent.example",
                        "allowed",
                        None,
                    )),
                    "channel must not overflow"
                );
            }
            sender.flush().await;
        };

        let (report, ()) = tokio::join!(db.cleanup_retention_with_policy(90, 365, false), send);
        let report = report.unwrap();
        assert_eq!(report.deleted_records, 1_000);
        assert_eq!(
            sender.dropped_total(),
            0,
            "a bounded sweep must not drop query-log batches"
        );
        sender.shutdown().await;

        let page = db
            .query_logs(&QueryLogFilter {
                limit: Some(1_000),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page.entries.len(), 500);
        assert!(page.entries.iter().all(|e| e.qname == "concurrent.example"));
    }

    /// P1-23: the live query-log refresh can skip the filtered `COUNT(*)`.
    #[tokio::test]
    async fn test_query_logs_include_total_is_optional() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        db.insert_batch(&[
            retention_entry(now, "total.example", "allowed", None),
            retention_entry(now + 1, "total.example", "allowed", None),
        ])
        .await
        .unwrap();

        let page = db
            .query_logs(&QueryLogFilter {
                include_total: Some(false),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.total_count, None);

        let with_total = db.query_logs(&QueryLogFilter::default()).await.unwrap();
        assert_eq!(with_total.total_count, Some(2));
    }

    /// P1-23: dashboard aggregates are cached briefly and clear/retention
    /// invalidates the cache immediately.
    #[tokio::test]
    async fn test_dashboard_cache_serves_within_ttl_and_clear_invalidates() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        db.insert_batch(&[retention_entry(now, "cache.example", "allowed", None)])
            .await
            .unwrap();

        let first = db.get_global_stats_cached(86_400_000).await.unwrap();
        assert_eq!(first.total_queries, 1);

        // A write inside the TTL is not observed by the cached dashboard read.
        db.insert_batch(&[retention_entry(now + 1, "cache.example", "allowed", None)])
            .await
            .unwrap();
        let cached = db.get_global_stats_cached(86_400_000).await.unwrap();
        assert_eq!(cached.total_queries, 1);

        // Clearing invalidates immediately.
        db.delete_query_logs().await.unwrap();
        let cleared = db.get_global_stats_cached(86_400_000).await.unwrap();
        assert_eq!(cleared.total_queries, 0);
    }

    /// P1-19: a v1.9 database (no `stats_meta`, raw rollup payloads) is
    /// upgraded additively; the old binary's schema/migrator view stays valid.
    #[tokio::test]
    async fn test_migration_from_v19_schema_hashes_rollups_and_stays_old_compatible() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito-stats-v19-migration-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let url = format!("sqlite://{}?mode=rwc", db_path.display());

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        for sql in [
            include_str!("../migrations/20260905000000_init.sql"),
            include_str!("../migrations/20260906000000_watermark.sql"),
            include_str!("../migrations/20260913000000_client_ip_index.sql"),
        ] {
            sqlx::raw_sql(sql).execute(&pool).await.unwrap();
        }
        let now = chrono::Utc::now().timestamp_millis();
        let hour = ((now - 100 * 86_400_000) / 3_600_000) * 3_600_000;
        sqlx::query(
            "INSERT INTO stats_hourly (hour, queries, blocked, cached, top_domains, top_clients) \
             VALUES (?, 5, 1, 0, ?, ?)",
        )
        .bind(hour)
        .bind(r#"[["legacy.example",5,1]]"#)
        .bind(r#"[["10.9.9.9","legacy-host",5,1,123]]"#)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO query_log (ts, client_ip, client_name, qname, qtype, rcode, verdict, proto) \
             VALUES (?, '10.9.9.9', 'legacy-host', 'legacy.example', 1, 0, 'allowed', 'udp')",
        )
        .bind(now - 1_000)
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let db = StatsDb::open(&db_path).await.unwrap();

        // One-time backfill hashed the raw IP and dropped the name.
        let payload: String = sqlx::query_scalar("SELECT top_clients FROM stats_hourly LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert!(!payload.contains("10.9.9.9"));
        assert!(!payload.contains("legacy-host"));
        assert!(payload.contains("blake3:"));

        // The new metadata table exists but is not recorded as a sqlx
        // migration, so an old 1.9.3 migrator does not see an unknown version.
        let has_meta: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='stats_meta'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(has_meta, 1);
        let versions: Vec<i64> =
            sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
                .fetch_all(db.pool())
                .await
                .unwrap();
        assert_eq!(
            versions,
            vec![
                20_260_905_000_000i64,
                20_260_906_000_000,
                20_260_913_000_000,
                20_260_922_000_000,
            ],
            "no new sqlx migration version may be visible to 1.9.3"
        );

        // Old 1.9.3-style access (old columns only) still works.
        let old_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM query_log")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(old_rows, 1);
        sqlx::query(
            "INSERT INTO query_log (ts, client_ip, client_name, qname, qtype, rcode, verdict, proto) \
             VALUES (?, '10.0.0.1', NULL, 'old-code.example', 1, 0, 'allowed', 'udp')",
        )
        .bind(now)
        .execute(db.pool())
        .await
        .unwrap();
        let (ts, qname): (i64, String) =
            sqlx::query_as("SELECT ts, qname FROM query_log ORDER BY id DESC LIMIT 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(ts, now);
        assert_eq!(qname, "old-code.example");

        drop(db);
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_stats_files_are_private_and_loose_permissions_are_repaired() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir =
            std::env::temp_dir().join(format!("sito-stats-perms-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let salt_path = temp_dir.join("stats-salt");
        std::fs::write(&salt_path, [0u8; 32]).unwrap();
        std::fs::set_permissions(&salt_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let db = StatsDb::open(&db_path).await.unwrap();
        db.insert_batch(&[retention_entry(
            chrono::Utc::now().timestamp_millis(),
            "perms.example",
            "allowed",
            None,
        )])
        .await
        .unwrap();
        db.repair_permissions().unwrap();

        for path in [
            db_path.clone(),
            salt_path.clone(),
            temp_dir.join("stats.db-wal"),
            temp_dir.join("stats.db-shm"),
        ] {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} must be 0600, got {mode:o}", path.display());
        }

        drop(db);
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    async fn create_legacy_db(path: &std::path::Path) -> sqlx::SqlitePool {
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        for sql in [
            include_str!("../migrations/20260905000000_init.sql"),
            include_str!("../migrations/20260906000000_watermark.sql"),
            include_str!("../migrations/20260913000000_client_ip_index.sql"),
        ] {
            sqlx::raw_sql(sql).execute(&pool).await.unwrap();
        }
        pool
    }

    /// P1-19 Important 2: a real IPv6 literal with the legacy `b3:` prefix must
    /// still be hashed, not mistaken for a stored digest.
    #[tokio::test]
    async fn test_b3_ipv6_literal_is_hashed_not_treated_as_digest() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let mut entry = retention_entry(
            now - 100 * 86_400_000,
            "ipv6-prefix.example",
            "allowed",
            None,
        );
        entry.client_ip = "b3::1".into();
        db.insert_batch(&[entry]).await.unwrap();
        db.cleanup_retention(90).await.unwrap();

        let payload: String = sqlx::query_scalar("SELECT top_clients FROM stats_hourly LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert!(
            !payload.contains("\"b3::1\""),
            "IPv6 literal must not be stored raw: {payload}"
        );
        let tops: Vec<(String, Option<String>, i64, i64, i64)> =
            serde_json::from_str(&payload).unwrap();
        assert!(tops[0].0.starts_with("blake3:"));
    }

    /// P1-19 Important 3: malformed legacy payloads are neutralized before the
    /// backfill marker is written.
    #[tokio::test]
    async fn test_backfill_neutralizes_malformed_rollup_payload() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito-stats-malformed-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let pool = create_legacy_db(&db_path).await;
        let now = chrono::Utc::now().timestamp_millis();
        let hour = ((now - 100 * 86_400_000) / 3_600_000) * 3_600_000;
        sqlx::query(
            "INSERT INTO stats_hourly (hour, queries, blocked, cached, top_domains, top_clients) \
             VALUES (?, 5, 1, 0, '[]', ?)",
        )
        .bind(hour)
        .bind("not-json 10.9.9.9 legacy-host")
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let db = StatsDb::open(&db_path).await.unwrap();
        let payload: String = sqlx::query_scalar("SELECT top_clients FROM stats_hourly LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(payload, "[]", "malformed payload must be neutralized");
        let marker: Option<String> =
            sqlx::query_scalar("SELECT value FROM stats_meta WHERE key = 'rollup_pii_v2'")
                .fetch_optional(db.pool())
                .await
                .unwrap();
        assert_eq!(marker.as_deref(), Some("1"));

        drop(db);
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// P1-19 Important 4: switching `rollup_client_names` true -> false scrubs
    /// names from already-written rollups on the next startup.
    #[tokio::test]
    async fn test_rollup_client_names_true_to_false_scrubs_existing_names() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito-stats-name-transition-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let now = chrono::Utc::now().timestamp_millis();
        let mut entry = retention_entry(now - 100 * 86_400_000, "names.example", "allowed", None);
        entry.client_ip = "10.7.7.7".into();
        entry.client_name = Some("named-device".into());

        {
            let db = StatsDb::open_with_rollup_client_names(&db_path, true)
                .await
                .unwrap();
            db.insert_batch(&[entry]).await.unwrap();
            db.cleanup_retention(90).await.unwrap();
            let payload: String =
                sqlx::query_scalar("SELECT top_clients FROM stats_hourly LIMIT 1")
                    .fetch_one(db.pool())
                    .await
                    .unwrap();
            assert!(payload.contains("named-device"));
        }

        let db = StatsDb::open_with_rollup_client_names(&db_path, false)
            .await
            .unwrap();
        let payload: String = sqlx::query_scalar("SELECT top_clients FROM stats_hourly LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert!(!payload.contains("named-device"));
        assert!(!payload.contains("10.7.7.7"));
        assert!(payload.contains("blake3:"));

        drop(db);
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// P1-19: names are preserved by a legacy backfill when explicitly enabled.
    #[tokio::test]
    async fn test_backfill_preserves_names_when_enabled() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito-stats-backfill-names-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let pool = create_legacy_db(&db_path).await;
        let now = chrono::Utc::now().timestamp_millis();
        let hour = ((now - 100 * 86_400_000) / 3_600_000) * 3_600_000;
        sqlx::query(
            "INSERT INTO stats_hourly (hour, queries, blocked, cached, top_domains, top_clients) \
             VALUES (?, 5, 1, 0, '[]', ?)",
        )
        .bind(hour)
        .bind(r#"[["10.9.9.9","legacy-host",5,1,123]]"#)
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let db = StatsDb::open_with_rollup_client_names(&db_path, true)
            .await
            .unwrap();
        let payload: String = sqlx::query_scalar("SELECT top_clients FROM stats_hourly LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert!(payload.contains("legacy-host"));
        assert!(!payload.contains("10.9.9.9"));
        assert!(payload.contains("blake3:"));

        drop(db);
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// P1-19: the salt persists across restarts and a corrupt salt is rejected.
    #[tokio::test]
    async fn test_salt_persists_and_corrupt_salt_is_rejected() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito-stats-salt-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let salt_path = temp_dir.join("stats-salt");
        let now = chrono::Utc::now().timestamp_millis();
        let mut entry = retention_entry(now - 100 * 86_400_000, "salt.example", "allowed", None);
        entry.client_ip = "10.6.6.6".into();

        let first_hash = {
            let db = StatsDb::open(&db_path).await.unwrap();
            db.insert_batch(&[entry.clone()]).await.unwrap();
            db.cleanup_retention(90).await.unwrap();
            let payload: String =
                sqlx::query_scalar("SELECT top_clients FROM stats_hourly LIMIT 1")
                    .fetch_one(db.pool())
                    .await
                    .unwrap();
            let tops: Vec<(String, Option<String>, i64, i64, i64)> =
                serde_json::from_str(&payload).unwrap();
            tops[0].0.clone()
        };
        assert_eq!(std::fs::metadata(&salt_path).unwrap().len(), 32);

        {
            let db = StatsDb::open(&db_path).await.unwrap();
            let mut second = entry;
            second.ts += 3_600_000;
            db.insert_batch(&[second]).await.unwrap();
            db.cleanup_retention(90).await.unwrap();
            let payloads: Vec<String> =
                sqlx::query_scalar("SELECT top_clients FROM stats_hourly ORDER BY hour")
                    .fetch_all(db.pool())
                    .await
                    .unwrap();
            let hashes: Vec<String> = payloads
                .iter()
                .map(|payload| {
                    let tops: Vec<(String, Option<String>, i64, i64, i64)> =
                        serde_json::from_str(payload).unwrap();
                    tops[0].0.clone()
                })
                .collect();
            assert!(hashes.iter().all(|hash| hash == &first_hash));
        }

        std::fs::write(&salt_path, [0u8; 31]).unwrap();
        assert!(
            StatsDb::open(&db_path).await.is_err(),
            "a short salt must be rejected instead of silently regenerated"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// P1-19: default clear vacuums a large deletion and keeps
    /// `secure_delete=ON`.
    #[tokio::test]
    async fn test_clear_query_log_vacuums_and_secure_delete_is_on() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito-stats-clear-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("stats.db");
        let db = StatsDb::open(&db_path).await.unwrap();

        let padding = "x".repeat(200);
        let old_ts = 1_000_000_000_000i64;
        let mut entries = Vec::new();
        for i in 0..3_000i64 {
            let mut entry = retention_entry(old_ts + i, "clear.test", "allowed", None);
            entry.rule = Some(format!("{padding}-{i}"));
            entries.push(entry);
        }
        db.insert_batch(&entries).await.unwrap();

        let before = db.db_size_bytes().await.unwrap();
        let deleted = db.delete_query_logs().await.unwrap();
        assert_eq!(deleted, 3_000);
        let after = db.db_size_bytes().await.unwrap();
        assert!(
            after < before,
            "large clear must vacuum (before={before}, after={after})"
        );

        let secure_delete: i64 = sqlx::query_scalar("PRAGMA secure_delete")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(secure_delete, 1, "secure_delete must be enabled");

        drop(db);
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// P1-24 Important 7: a single busy hour is sub-chunked by row count.
    #[tokio::test]
    async fn test_large_single_hour_is_row_bounded() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let hour = ((now - 200 * 86_400_000) / 3_600_000) * 3_600_000;
        let mut entries = Vec::new();
        for i in 0..12_000i64 {
            entries.push(retention_entry(
                hour + i,
                "busy-hour.example",
                "allowed",
                None,
            ));
        }
        db.insert_batch(&entries).await.unwrap();

        let report = db
            .cleanup_retention_with_policy(90, 365, false)
            .await
            .unwrap();
        assert_eq!(report.deleted_records, 12_000);
        assert_eq!(
            report.chunks, 3,
            "12,000 rows must be split into 5,000-row chunks"
        );
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM query_log")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(remaining, 0);
    }

    /// P1-24 Important 5: hour discovery uses the `ts` index instead of a
    /// full-range `GROUP BY` scan.
    #[tokio::test]
    async fn test_retention_hour_discovery_uses_ts_index() {
        use sqlx::Row;
        let db = StatsDb::in_memory().await.unwrap();
        let rows = sqlx::query("EXPLAIN QUERY PLAN SELECT MIN(ts) FROM query_log WHERE ts < ?")
            .bind(0i64)
            .fetch_all(db.pool())
            .await
            .unwrap();
        let plan = rows
            .iter()
            .map(|row| row.get::<String, _>("detail"))
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(
            plan.contains("idx_ql_ts"),
            "hour discovery must use idx_ql_ts: {plan}"
        );
    }

    /// P1-24 Important 7: chunk boundary, aggregate and delete predicates use
    /// the `(ts, id)` index and do not sort the whole hour.
    #[tokio::test]
    async fn test_retention_chunk_queries_use_ts_id_index() {
        use sqlx::Row;
        let db = StatsDb::in_memory().await.unwrap();
        let index_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_ql_ts_id'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(index_count, 1, "(ts, id) index must be created");

        let boundary = sqlx::query(
            r"
            EXPLAIN QUERY PLAN
            SELECT ts, id FROM query_log INDEXED BY idx_ql_ts_id
            WHERE (ts, id) >= (?, ?) AND (ts, id) < (?, ?)
            ORDER BY ts ASC, id ASC LIMIT 1 OFFSET ?
            ",
        )
        .bind(0i64)
        .bind(0i64)
        .bind(1i64)
        .bind(0i64)
        .bind(5_000i64)
        .fetch_all(db.pool())
        .await
        .unwrap();
        let boundary_plan = boundary
            .iter()
            .map(|row| row.get::<String, _>("detail"))
            .collect::<Vec<_>>()
            .join(" | ");
        let bytecode = sqlx::query(
            r"
            EXPLAIN SELECT ts, id FROM query_log INDEXED BY idx_ql_ts_id
            WHERE (ts, id) >= (?, ?) AND (ts, id) < (?, ?)
            ORDER BY ts ASC, id ASC LIMIT 1 OFFSET ?
            ",
        )
        .bind(0i64)
        .bind(0i64)
        .bind(1i64)
        .bind(0i64)
        .bind(5_000i64)
        .fetch_all(db.pool())
        .await
        .unwrap();
        let opcodes: Vec<String> = bytecode
            .iter()
            .map(|row| row.get::<String, _>("opcode"))
            .collect();
        assert!(
            opcodes.iter().any(|op| op == "SeekGE") && opcodes.iter().any(|op| op == "IdxGT"),
            "chunk boundary must use a range seek on idx_ql_ts_id, not a full scan: {opcodes:?}"
        );
        assert!(
            boundary_plan.contains("idx_ql_ts_id"),
            "chunk boundary must use idx_ql_ts_id: {boundary_plan}"
        );
        assert!(
            !boundary_plan.contains("TEMP B-TREE"),
            "chunk boundary must not sort the whole hour: {boundary_plan}"
        );

        let aggregate = sqlx::query(
            r"
            EXPLAIN QUERY PLAN
            SELECT COUNT(*) FROM query_log INDEXED BY idx_ql_ts_id
            WHERE (ts, id) >= (?, ?) AND (ts, id) < (?, ?)
            ",
        )
        .bind(0i64)
        .bind(0i64)
        .bind(1i64)
        .bind(0i64)
        .fetch_all(db.pool())
        .await
        .unwrap();
        let aggregate_plan = aggregate
            .iter()
            .map(|row| row.get::<String, _>("detail"))
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(
            aggregate_plan.contains("idx_ql_ts_id"),
            "chunk aggregate must use idx_ql_ts_id: {aggregate_plan}"
        );
    }

    /// Important 7: a large same-timestamp hour is still split into bounded
    /// chunks by the `(ts, id)` cursor.
    #[tokio::test]
    async fn test_large_same_timestamp_hour_is_row_bounded() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let hour = ((now - 200 * 86_400_000) / 3_600_000) * 3_600_000;
        let ts = hour + 1_234;
        let mut entries = Vec::new();
        for _ in 0..12_000 {
            entries.push(retention_entry(ts, "same-ts.example", "allowed", None));
        }
        db.insert_batch(&entries).await.unwrap();

        let report = db
            .cleanup_retention_with_policy(90, 365, false)
            .await
            .unwrap();
        assert_eq!(report.deleted_records, 12_000);
        assert_eq!(
            report.chunks, 3,
            "same-timestamp rows must still be split into 5,000-row chunks"
        );
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM query_log")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(remaining, 0);
    }

    /// Important regression: a heavy hitter spread across many chunks must not
    /// be lost because each chunk's top-N is computed separately.
    #[tokio::test]
    async fn test_rollup_top_n_preserves_heavy_hitter_across_chunks() {
        let db = StatsDb::in_memory().await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let hour = ((now - 200 * 86_400_000) / 3_600_000) * 3_600_000;
        let mut entries = Vec::new();
        let mut ts = hour;

        // Three blocks of 5,000 rows each. Each block has 100 distinct
        // distractors with 10 hits and 9 hits for the target. The target is
        // below every chunk's top-100 but is the global heavy hitter (27 hits).
        for block in 0..3 {
            for i in 0..100 {
                for _ in 0..10 {
                    entries.push(retention_entry(
                        ts,
                        &format!("distract-{block}-{i}.example"),
                        "allowed",
                        None,
                    ));
                    ts += 1;
                }
            }
            for _ in 0..9 {
                entries.push(retention_entry(ts, "heavy.example", "allowed", None));
                ts += 1;
            }
            for i in 0..3_991 {
                entries.push(retention_entry(
                    ts,
                    &format!("filler-{block}-{i}.example"),
                    "allowed",
                    None,
                ));
                ts += 1;
            }
        }
        assert_eq!(entries.len(), 15_000);
        db.insert_batch(&entries).await.unwrap();

        let report = db
            .cleanup_retention_with_policy(90, 365, false)
            .await
            .unwrap();
        assert_eq!(report.deleted_records, 15_000);
        assert!(
            report.chunks >= 3,
            "expected multiple row-bounded chunks, got {}",
            report.chunks
        );

        let payload: String =
            sqlx::query_scalar("SELECT top_domains FROM stats_hourly WHERE hour = ?")
                .bind(hour)
                .fetch_one(db.pool())
                .await
                .unwrap();
        let tops: Vec<(String, i64, i64)> = serde_json::from_str(&payload).unwrap();
        let heavy = tops
            .iter()
            .find(|(qname, _, _)| qname == "heavy.example")
            .expect("heavy hitter must survive the per-hour rollup");
        assert_eq!(
            heavy.1, 27,
            "heavy hitter count must be exact across chunks: {tops:?}"
        );
    }
}
