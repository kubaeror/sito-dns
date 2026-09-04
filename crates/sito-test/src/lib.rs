//! Integration test harness and mock servers for sito.

pub mod client;
pub mod harness;
pub mod mock;

pub use client::TestDnsClient;
pub use harness::TestServerInstance;
pub use mock::MockDnsServer;

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{RData, RecordType};
    use sito_core::config::{Config, FilterListConfig};
    use sito_proto::rdata::{A, AAAA};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    /// 1. Acceptance test: dig @127.0.0.1 example.com -> NOERROR via fake upstream
    #[tokio::test]
    async fn test_acceptance_query_forwarding_noerror() {
        let mock_upstream = MockDnsServer::spawn().await.unwrap();
        mock_upstream.add_a_record("example.com", Ipv4Addr::new(93, 184, 216, 34), 300);

        let mut config = Config::default();
        config.upstream.servers = vec![mock_upstream.addr().to_string()];

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();

        let resp = client
            .query_udp("example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            resp.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(
            resp.answers[0].data,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34)))
        );

        server.shutdown().await.unwrap();
    }

    /// 2. Acceptance test: Listed domain -> 0.0.0.0 (A) and :: (AAAA); other types -> NOERROR/NODATA
    #[tokio::test]
    async fn test_acceptance_blocking_zero_ip_and_nodata() {
        let mock_upstream = MockDnsServer::spawn().await.unwrap();
        let mut config = Config::default();
        config.upstream.servers = vec![mock_upstream.addr().to_string()];
        config.filtering.custom_rules = vec!["0.0.0.0 ads.tracker.com".to_string()];

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();

        // Query A record for listed domain -> 0.0.0.0
        let resp_a = client
            .query_udp("ads.tracker.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            resp_a.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(resp_a.answers.len(), 1);
        assert_eq!(resp_a.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

        // Query AAAA record for listed domain -> ::
        let resp_aaaa = client
            .query_udp("ads.tracker.com", RecordType::AAAA)
            .await
            .unwrap();
        assert_eq!(
            resp_aaaa.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(resp_aaaa.answers.len(), 1);
        assert_eq!(
            resp_aaaa.answers[0].data,
            RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))
        );

        // Query TXT record for listed domain -> NOERROR with empty answers (NODATA)
        let resp_txt = client
            .query_udp("ads.tracker.com", RecordType::TXT)
            .await
            .unwrap();
        assert_eq!(
            resp_txt.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(resp_txt.answers.len(), 0);

        // Verify that upstream was NEVER queried for blocked domain
        assert_eq!(mock_upstream.query_count(), 0);

        server.shutdown().await.unwrap();
    }

    /// 3. Acceptance test: Second query -> cache hit, TTL decremented
    #[tokio::test]
    async fn test_acceptance_cache_hit_and_ttl_decrement() {
        let mock_upstream = MockDnsServer::spawn().await.unwrap();
        mock_upstream.add_a_record("cached.example.com", Ipv4Addr::new(1, 2, 3, 4), 100);

        let mut config = Config::default();
        config.upstream.servers = vec![mock_upstream.addr().to_string()];
        config.dns.cache.min_ttl = 10;
        config.dns.cache.max_ttl = 3600;

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();

        // 1st query -> cache miss, resolves via upstream
        let resp1 = client
            .query_udp("cached.example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(mock_upstream.query_count(), 1);
        let ttl1 = resp1.answers[0].ttl;
        assert_eq!(ttl1, 100);

        // Wait 1.1 second
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // 2nd query -> cache hit, TTL decremented, upstream NOT called again
        let resp2 = client
            .query_udp("cached.example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(mock_upstream.query_count(), 1); // Still 1!
        let ttl2 = resp2.answers[0].ttl;
        assert!(
            ttl2 < ttl1,
            "Cached TTL was not decremented: ttl1={ttl1}, ttl2={ttl2}"
        );

        server.shutdown().await.unwrap();
    }

    /// 4. Acceptance test: Upstream 1 dead -> answers from upstream 2 within <100ms over timeout
    #[tokio::test]
    async fn test_acceptance_upstream_failover() {
        let mock_upstream1 = MockDnsServer::spawn().await.unwrap();
        let mock_upstream2 = MockDnsServer::spawn().await.unwrap();

        mock_upstream2.add_a_record("failover.test", Ipv4Addr::new(10, 0, 0, 1), 300);

        // Make upstream 1 drop packets (dead)
        mock_upstream1.set_alive(false);

        let mut config = Config::default();
        config.upstream.timeout_ms = 400; // 400ms timeout
        config.upstream.servers = vec![
            mock_upstream1.addr().to_string(),
            mock_upstream2.addr().to_string(),
        ];

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client().with_timeout(Duration::from_millis(2000));

        let start = std::time::Instant::now();
        let resp = client
            .query_udp("failover.test", RecordType::A)
            .await
            .unwrap();
        let elapsed = start.elapsed();

        assert_eq!(
            resp.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(
            resp.answers[0].data,
            RData::A(A(Ipv4Addr::new(10, 0, 0, 1)))
        );

        // Upstream 2 answered
        assert_eq!(mock_upstream2.query_count(), 1);

        // Total time should be upstream 1 timeout (~400ms) + small overhead (<100ms)
        assert!(
            elapsed >= Duration::from_millis(350),
            "Elapsed was suspiciously fast: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(700),
            "Failover took too long: {elapsed:?}"
        );

        server.shutdown().await.unwrap();
    }

    /// 5. Acceptance test: check-config rejects bad TOML with a message pointing at the field
    #[test]
    fn test_acceptance_check_config_rejects_bad_field() {
        let temp_dir = std::env::temp_dir().join(format!("sito_bad_cfg_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let bad_field_config = temp_dir.join("bad_port.toml");
        std::fs::write(&bad_field_config, "config_version = 1\n[dns]\nport = 0\n").unwrap();

        let err = sito::cli::run_check_config(&bad_field_config).unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("dns.port"),
            "Error message did not point at field: {err_msg}"
        );

        let bad_ttl_config = temp_dir.join("bad_ttl.toml");
        std::fs::write(
            &bad_ttl_config,
            "config_version = 1\n[dns.cache]\nmin_ttl = 500\nmax_ttl = 100\n",
        )
        .unwrap();

        let err2 = sito::cli::run_check_config(&bad_ttl_config).unwrap_err();
        let err2_msg = err2.to_string();
        assert!(
            err2_msg.contains("dns.cache.min_ttl"),
            "Error message did not point at field: {err2_msg}"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// 6. Acceptance test: Shutdown during in-flight queries -> no panic, exits cleanly <= 6s
    #[tokio::test]
    async fn test_acceptance_graceful_shutdown_under_load() {
        let mock_upstream = MockDnsServer::spawn().await.unwrap();
        mock_upstream.add_a_record("load.test", Ipv4Addr::new(8, 8, 8, 8), 300);

        let mut config = Config::default();
        config.upstream.servers = vec![mock_upstream.addr().to_string()];

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();

        // Spawn 100 concurrent queries in background
        for _ in 0..100 {
            let client = client.clone();
            tokio::spawn(async move {
                let _ = client.query_udp("load.test", RecordType::A).await;
            });
        }

        let start = std::time::Instant::now();
        let shutdown_res = server.shutdown().await;
        let elapsed = start.elapsed();

        assert!(shutdown_res.is_ok(), "Shutdown failed: {shutdown_res:?}");
        assert!(
            elapsed <= Duration::from_secs(6),
            "Shutdown took longer than 6s: {elapsed:?}"
        );
    }

    /// Test hosts list loading from file:// URL with blocking
    #[tokio::test]
    async fn test_hosts_list_from_file_uri() {
        let temp_dir = std::env::temp_dir().join(format!("sito_file_list_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let hosts_file = temp_dir.join("hosts.txt");
        std::fs::write(
            &hosts_file,
            "0.0.0.0 downloaded-ad.com\n127.0.0.1 spy.evil.net\n",
        )
        .unwrap();

        let mut config = Config::default();
        config.filtering.lists = vec![FilterListConfig {
            name: "local_hosts".to_string(),
            url: format!("file://{}", hosts_file.display()),
            enabled: true,
            refresh_hours: None,
        }];

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();

        let resp1 = client
            .query_udp("downloaded-ad.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(resp1.answers.len(), 1);
        assert_eq!(resp1.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

        let resp2 = client
            .query_udp("spy.evil.net", RecordType::A)
            .await
            .unwrap();
        assert_eq!(resp2.answers.len(), 1);
        assert_eq!(resp2.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

        server.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
