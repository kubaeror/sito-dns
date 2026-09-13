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

        let watermark = db.get_watermark("hourly_aggregation").await.unwrap();
        assert!(watermark.is_some());
        let (wm_id, _) = watermark.unwrap();
        assert!(wm_id >= 2);

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
        assert!(remaining.entries.is_empty());
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
}
