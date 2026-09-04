//! Integration test harness and mock servers for sito.

pub mod client;
pub mod harness;
pub mod mock;

pub use client::{DotConnection, TestDnsClient};
pub use harness::{TestServerInstance, generate_expired_test_cert, generate_test_cert};
pub use mock::MockDnsServer;

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{Name, RData, RecordType};
    use sito_core::config::{Config, FilterListConfig};
    use sito_proto::rdata::{A, AAAA, CNAME, PTR};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
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

    /// 8. Acceptance test: DoT query (kdig equivalent) -> NOERROR
    #[tokio::test]
    async fn test_acceptance_dot_query_noerror() {
        let (cert_pem, key_pem) = generate_test_cert(&["sito-test.local", "127.0.0.1"]);
        let temp_dir = std::env::temp_dir().join(format!("sito_dot_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");
        tokio::fs::write(&cert_file, cert_pem).await.unwrap();
        tokio::fs::write(&key_file, key_pem).await.unwrap();

        let mock_upstream = MockDnsServer::spawn().await.unwrap();
        mock_upstream.add_a_record("secure.example.com", Ipv4Addr::new(93, 184, 216, 34), 300);

        let mut config = Config::default();
        config.upstream.servers = vec![mock_upstream.addr().to_string()];
        config.dns.dot_port = 0;
        config.tls = Some(sito_core::config::TlsConfig {
            cert: Some(cert_file),
            key: Some(key_file),
            sni_certs: Vec::new(),
        });

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();

        let resp = client
            .query_dot(
                server.dot_addr(),
                "sito-test.local",
                "secure.example.com",
                RecordType::A,
            )
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
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// 9. Acceptance test: DoH queries (curl --doh-url equivalent) via POST and GET, asserting no-store header
    #[tokio::test]
    async fn test_acceptance_doh_queries_and_no_store() {
        let (cert_pem, key_pem) = generate_test_cert(&["sito-test.local", "127.0.0.1"]);
        let temp_dir = std::env::temp_dir().join(format!("sito_doh_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");
        tokio::fs::write(&cert_file, cert_pem).await.unwrap();
        tokio::fs::write(&key_file, key_pem).await.unwrap();

        let mock_upstream = MockDnsServer::spawn().await.unwrap();
        mock_upstream.add_a_record("doh.example.com", Ipv4Addr::new(192, 0, 2, 1), 300);

        let mut config = Config::default();
        config.upstream.servers = vec![mock_upstream.addr().to_string()];
        config.dns.doh_port = 0;
        config.tls = Some(sito_core::config::TlsConfig {
            cert: Some(cert_file),
            key: Some(key_file),
            sni_certs: Vec::new(),
        });

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();

        // Check POST query
        let doh_url = server.doh_url("/dns-query");
        let resp_post = client
            .query_doh_post(&doh_url, "doh.example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            resp_post.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(resp_post.answers.len(), 1);
        assert_eq!(
            resp_post.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))
        );

        // Check GET query
        let resp_get = client
            .query_doh_get(&doh_url, "doh.example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            resp_get.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(resp_get.answers.len(), 1);
        assert_eq!(
            resp_get.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))
        );

        // Check Cache-Control: no-store header on raw HTTP response
        let http_client = client.doh_http_client().unwrap();
        let query_wire = sito_proto::encode_message(&resp_post).unwrap();
        let http_resp = http_client
            .post(&doh_url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query_wire)
            .send()
            .await
            .unwrap();

        assert_eq!(http_resp.status(), 200);
        let cache_control = http_resp
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cache_control.contains("no-store"));

        // Check DoH query with ClientID in path
        let client_url = server.doh_url("/dns-query/alice-phone");
        let resp_client = client
            .query_doh_post(&client_url, "doh.example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            resp_client.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );

        server.shutdown().await.unwrap();
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// 10. Acceptance test: DNSSEC validation (Secure -> AD=1, Bogus -> SERVFAIL, NTA -> Bypass)
    #[tokio::test]
    async fn test_acceptance_dnssec_validation_secure_bogus_and_nta() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use hickory_proto::dnssec::PublicKey;
        use hickory_proto::dnssec::rdata::DNSSECRData;
        use hickory_proto::rr::{RData, Record};
        use sito_dnssec::test_util::create_test_signed_domain;

        let mock_upstream = MockDnsServer::spawn().await.unwrap();

        // 1. Setup Secure domain
        let (origin_secure, dnskey, a_record, rrsig_record, _) =
            create_test_signed_domain("sigok.example.com.");
        let pubkey_b64 = BASE64_STANDARD.encode(dnskey.public_key().public_bytes());

        mock_upstream.add_custom_response(
            "sigok.example.com",
            RecordType::A,
            vec![a_record.clone(), rrsig_record.clone()],
            vec![Record::from_rdata(
                origin_secure.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
            )],
        );

        // 2. Setup Bogus domain (tampered data)
        let (origin_bogus, dnskey_bogus, _a_orig, rrsig_bogus, _) =
            create_test_signed_domain("sigfail.example.com.");
        let bogus_tampered_record = Record::from_rdata(
            origin_bogus.clone(),
            300,
            RData::A(A(Ipv4Addr::new(6, 6, 6, 6))),
        );
        let pubkey_bogus_b64 = BASE64_STANDARD.encode(dnskey_bogus.public_key().public_bytes());

        mock_upstream.add_custom_response(
            "sigfail.example.com",
            RecordType::A,
            vec![bogus_tampered_record, rrsig_bogus],
            vec![Record::from_rdata(
                origin_bogus,
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(dnskey_bogus)),
            )],
        );

        // 3. Setup NTA domain (tampered data, but domain in NTA list)
        let (origin_nta, dnskey_nta, _a_orig_nta, rrsig_nta, _) =
            create_test_signed_domain("bypass.example.com.");
        let nta_tampered_record = Record::from_rdata(
            origin_nta.clone(),
            300,
            RData::A(A(Ipv4Addr::new(7, 7, 7, 7))),
        );
        let pubkey_nta_b64 = BASE64_STANDARD.encode(dnskey_nta.public_key().public_bytes());

        mock_upstream.add_custom_response(
            "bypass.example.com",
            RecordType::A,
            vec![nta_tampered_record, rrsig_nta],
            vec![Record::from_rdata(
                origin_nta,
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(dnskey_nta)),
            )],
        );

        let mut config = Config::default();
        config.upstream.servers = vec![mock_upstream.addr().to_string()];
        config.dns.dnssec.validate = true;
        config.dns.dnssec.mode = "validate".to_string();
        config.dns.dnssec.nta = vec!["bypass.example.com".to_string()];
        config.dns.dnssec.trust_anchors = vec![
            format!("sigok.example.com.:13:{pubkey_b64}"),
            format!("sigfail.example.com.:13:{pubkey_bogus_b64}"),
            format!("bypass.example.com.:13:{pubkey_nta_b64}"),
        ];

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();

        // Query 1: sigok -> NOERROR with AD=1
        let resp_ok = client
            .query_udp("sigok.example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            resp_ok.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert!(
            resp_ok.metadata.authentic_data,
            "AD bit must be set for verified DNSSEC zone"
        );

        // Query 2: sigfail -> SERVFAIL (Bogus signature)
        let resp_fail = client
            .query_udp("sigfail.example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            resp_fail.metadata.response_code,
            hickory_proto::op::ResponseCode::ServFail
        );

        // Query 3: bypass -> NOERROR, AD=0 (NTA bypass)
        let resp_nta = client
            .query_udp("bypass.example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            resp_nta.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert!(
            !resp_nta.metadata.authentic_data,
            "AD bit must not be set for NTA bypassed zone"
        );

        server.shutdown().await.unwrap();
    }

    /// 11. Acceptance test: Cert reload without restart and without dropping persistent DoT connections
    #[tokio::test]
    async fn test_acceptance_cert_reload_without_disconnecting_persistent_dot() {
        let (cert1_pem, key1_pem) = generate_test_cert(&["cert1.sito.local", "127.0.0.1"]);
        let temp_dir =
            std::env::temp_dir().join(format!("sito_reload_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");
        tokio::fs::write(&cert_file, cert1_pem).await.unwrap();
        tokio::fs::write(&key_file, key1_pem).await.unwrap();

        let mock_upstream = MockDnsServer::spawn().await.unwrap();
        mock_upstream.add_a_record("reload.test", Ipv4Addr::new(10, 1, 1, 1), 300);

        let mut config = Config::default();
        config.upstream.servers = vec![mock_upstream.addr().to_string()];
        config.dns.dot_port = 0;
        config.tls = Some(sito_core::config::TlsConfig {
            cert: Some(cert_file.clone()),
            key: Some(key_file.clone()),
            sni_certs: Vec::new(),
        });

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();

        // 1. Establish persistent DoT connection on cert1
        let mut conn = client
            .connect_dot(server.dot_addr(), "cert1.sito.local", None)
            .await
            .unwrap();

        let resp1 = conn.query("reload.test", RecordType::A).await.unwrap();
        assert_eq!(
            resp1.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );

        // 2. Overwrite certificate and key with cert2 (new SAN)
        let (cert2_pem, key2_pem) = generate_test_cert(&["cert2.sito.local", "127.0.0.1"]);
        tokio::fs::write(&cert_file, cert2_pem).await.unwrap();
        tokio::fs::write(&key_file, key2_pem).await.unwrap();

        // Allow cert watcher debouncer / fs event to process
        tokio::time::sleep(Duration::from_millis(500)).await;

        // 3. Existing persistent connection STILL works and serves queries!
        let resp2 = conn.query("reload.test", RecordType::A).await.unwrap();
        assert_eq!(
            resp2.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );

        // 4. New connection connects using the new cert2 SNI
        let mut conn2 = client
            .connect_dot(server.dot_addr(), "cert2.sito.local", None)
            .await
            .unwrap();
        let resp3 = conn2.query("reload.test", RecordType::A).await.unwrap();
        assert_eq!(
            resp3.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );

        server.shutdown().await.unwrap();
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// 12. Acceptance test: Blocking and cache behave identically across all 4 transports (UDP, TCP, DoT, DoH)
    #[tokio::test]
    async fn test_acceptance_all_four_transports_matrix() {
        let (cert_pem, key_pem) = generate_test_cert(&["sito-test.local", "127.0.0.1"]);
        let temp_dir =
            std::env::temp_dir().join(format!("sito_matrix_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");
        tokio::fs::write(&cert_file, cert_pem).await.unwrap();
        tokio::fs::write(&key_file, key_pem).await.unwrap();

        let mock_upstream = MockDnsServer::spawn().await.unwrap();
        mock_upstream.add_a_record("allowed-domain.org", Ipv4Addr::new(9, 9, 9, 9), 300);

        let mut config = Config::default();
        config.upstream.servers = vec![mock_upstream.addr().to_string()];
        config.dns.dot_port = 0;
        config.dns.doh_port = 0;
        config.filtering.custom_rules = vec!["||blocked-matrix.com^".to_string()];
        config.tls = Some(sito_core::config::TlsConfig {
            cert: Some(cert_file),
            key: Some(key_file),
            sni_certs: Vec::new(),
        });

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();
        let doh_url = server.doh_url("/dns-query");

        // --- Verify Blocking across all 4 transports ---
        // 1. UDP
        let udp_block = client
            .query_udp("blocked-matrix.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            udp_block.answers[0].data,
            RData::A(A(Ipv4Addr::UNSPECIFIED))
        );

        // 2. TCP
        let tcp_block = client
            .query_tcp("blocked-matrix.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            tcp_block.answers[0].data,
            RData::A(A(Ipv4Addr::UNSPECIFIED))
        );

        // 3. DoT
        let dot_block = client
            .query_dot(
                server.dot_addr(),
                "sito-test.local",
                "blocked-matrix.com",
                RecordType::A,
            )
            .await
            .unwrap();
        assert_eq!(
            dot_block.answers[0].data,
            RData::A(A(Ipv4Addr::UNSPECIFIED))
        );

        // 4. DoH
        let doh_block = client
            .query_doh_post(&doh_url, "blocked-matrix.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            doh_block.answers[0].data,
            RData::A(A(Ipv4Addr::UNSPECIFIED))
        );

        // --- Verify Caching across all 4 transports ---
        // First query via UDP populates cache
        let r_udp = client
            .query_udp("allowed-domain.org", RecordType::A)
            .await
            .unwrap();
        assert_eq!(mock_upstream.query_count(), 1);
        let orig_ttl = r_udp.answers[0].ttl;

        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Query via TCP hits cache with decremented TTL
        let r_tcp = client
            .query_tcp("allowed-domain.org", RecordType::A)
            .await
            .unwrap();
        assert_eq!(mock_upstream.query_count(), 1);
        assert!(r_tcp.answers[0].ttl < orig_ttl);

        // Query via DoT hits cache
        let r_dot = client
            .query_dot(
                server.dot_addr(),
                "sito-test.local",
                "allowed-domain.org",
                RecordType::A,
            )
            .await
            .unwrap();
        assert_eq!(mock_upstream.query_count(), 1);
        assert!(r_dot.answers[0].ttl < orig_ttl);

        // Query via DoH hits cache
        let r_doh = client
            .query_doh_get(&doh_url, "allowed-domain.org", RecordType::A)
            .await
            .unwrap();
        assert_eq!(mock_upstream.query_count(), 1);
        assert!(r_doh.answers[0].ttl < orig_ttl);

        server.shutdown().await.unwrap();
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// 13. Acceptance test: Policy Matrix across multiple clients and groups (M4.6)
    /// Devices: kid-device (kids), adult-device (adults), guest-device (bypass), unknown (default)
    /// Tests: ad domain, adult domain, tiktok, safe search on Google
    #[tokio::test]
    async fn test_acceptance_m4_policy_matrix_devices_and_groups() {
        let (cert_pem, key_pem) = generate_test_cert(&["sito-test.local", "127.0.0.1"]);
        let temp_dir =
            std::env::temp_dir().join(format!("sito_matrix_p_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");
        tokio::fs::write(&cert_file, cert_pem).await.unwrap();
        tokio::fs::write(&key_file, key_pem).await.unwrap();

        let mock_upstream = MockDnsServer::spawn().await.unwrap();
        mock_upstream.add_a_record("ad-tracker.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        mock_upstream.add_a_record("pornhub.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        mock_upstream.add_a_record("tiktok.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        mock_upstream.add_a_record("www.google.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        mock_upstream.add_a_record("allowed-clean.com", Ipv4Addr::new(1, 2, 3, 4), 300);

        let clients_val: toml::Value = toml::from_str(
            r#"
            [[entries]]
            name = "kid-device"
            ids = ["kid-client"]
            group = "kids"

            [[entries]]
            name = "adult-device"
            ids = ["adult-client"]
            group = "adults"

            [[entries]]
            name = "guest-device"
            ids = ["guest-client"]
            group = "bypass"

            [groups.kids]
            filtering = true
            safe_search = true
            parental = true
            parental_categories = ["adult"]
            [[groups.kids.blocked_services]]
            service = "tiktok"

            [groups.adults]
            filtering = true
            safe_search = false
            parental = false

            [groups.bypass]
            filtering = false
        "#,
        )
        .unwrap();

        let mut config = Config::default();
        config.upstream.servers = vec![mock_upstream.addr().to_string()];
        config.filtering.custom_rules = vec!["||ad-tracker.com^".to_string()];
        config.clients = Some(clients_val);
        config.dns.doh_port = 0;
        config.tls = Some(sito_core::config::TlsConfig {
            cert: Some(cert_file),
            key: Some(key_file),
            sni_certs: Vec::new(),
        });

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();

        let doh_kid = server.doh_url("/dns-query/kid-client");
        let doh_adult = server.doh_url("/dns-query/adult-client");
        let doh_bypass = server.doh_url("/dns-query/guest-client");
        let doh_default = server.doh_url("/dns-query");

        // --- 1. General Ad Domain (ad-tracker.com) ---
        // Kid: blocked
        let r = client
            .query_doh_post(&doh_kid, "ad-tracker.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
        // Adult: blocked
        let r = client
            .query_doh_post(&doh_adult, "ad-tracker.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
        // Bypass: allowed (1.2.3.4)
        let r = client
            .query_doh_post(&doh_bypass, "ad-tracker.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
        // Default unknown: blocked
        let r = client
            .query_doh_post(&doh_default, "ad-tracker.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

        // --- 2. Parental Control Domain (pornhub.com) ---
        // Kid: blocked by parental
        let r = client
            .query_doh_post(&doh_kid, "pornhub.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
        // Adult: allowed
        let r = client
            .query_doh_post(&doh_adult, "pornhub.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
        // Bypass: allowed
        let r = client
            .query_doh_post(&doh_bypass, "pornhub.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
        // Default unknown: allowed (parental is false on default)
        let r = client
            .query_doh_post(&doh_default, "pornhub.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));

        // --- 3. Blocked Service (tiktok.com) ---
        // Kid: blocked by service
        let r = client
            .query_doh_post(&doh_kid, "tiktok.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
        // Adult: allowed
        let r = client
            .query_doh_post(&doh_adult, "tiktok.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
        // Bypass: allowed
        let r = client
            .query_doh_post(&doh_bypass, "tiktok.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));

        // --- 4. Safe Search Domain (www.google.com) ---
        // Kid: CNAME forcesafesearch.google.com.
        let r = client
            .query_doh_post(&doh_kid, "www.google.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].record_type(), RecordType::CNAME);
        assert_eq!(
            r.answers[0].data,
            RData::CNAME(CNAME(
                Name::from_str("forcesafesearch.google.com.").unwrap()
            ))
        );
        // Adult: allowed upstream
        let r = client
            .query_doh_post(&doh_adult, "www.google.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].record_type(), RecordType::A);
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
        // Bypass: allowed upstream
        let r = client
            .query_doh_post(&doh_bypass, "www.google.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(r.answers[0].record_type(), RecordType::A);

        server.shutdown().await.unwrap();
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// 14. Acceptance test: Local DNS rewrites with wildcards, auto-PTR, CNAME chaining, and exception_clients
    #[tokio::test]
    async fn test_acceptance_m4_local_rewrites_wildcard_and_auto_ptr() {
        let (cert_pem, key_pem) = generate_test_cert(&["sito-test.local", "127.0.0.1"]);
        let temp_dir =
            std::env::temp_dir().join(format!("sito_rewrites_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");
        tokio::fs::write(&cert_file, cert_pem).await.unwrap();
        tokio::fs::write(&key_file, key_pem).await.unwrap();

        let mock_upstream = MockDnsServer::spawn().await.unwrap();
        mock_upstream.add_a_record("nas.lan", Ipv4Addr::new(100, 100, 100, 100), 300);

        let rewrites_val: toml::Value = toml::from_str(r#"
            auto_ptr = true
            entries = [
                { domain = "*.home.arpa", type = "A", answer = "192.168.1.10" },
                { domain = "printer.lan", type = "A", answer = "192.168.1.50" },
                { domain = "app.lan", type = "CNAME", answer = "web.lan" },
                { domain = "web.lan", type = "A", answer = "192.168.1.80" },
                { domain = "nas.lan", type = "A", answer = "192.168.1.90", exception_clients = ["admin-laptop"] }
            ]
        "#).unwrap();

        let clients_val: toml::Value = toml::from_str(
            r#"
            [[entries]]
            name = "admin-laptop"
            ids = ["admin-laptop"]
            group = "default"
        "#,
        )
        .unwrap();

        let mut config = Config::default();
        config.upstream.servers = vec![mock_upstream.addr().to_string()];
        config.rewrites = Some(rewrites_val);
        config.clients = Some(clients_val);
        config.dns.doh_port = 0;
        config.tls = Some(sito_core::config::TlsConfig {
            cert: Some(cert_file),
            key: Some(key_file),
            sni_certs: Vec::new(),
        });

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();

        // 1. Wildcard *.home.arpa matches nas.home.arpa
        let r = client
            .query_udp("nas.home.arpa", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            r.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 10)))
        );

        // Multi-level subdomain also matches wildcard *.home.arpa
        let r = client
            .query_udp("sub.device.home.arpa", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            r.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 10)))
        );

        // 2. Exact A record for printer.lan
        let r = client
            .query_udp("printer.lan", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            r.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 50)))
        );

        // 3. Auto-PTR reverse query for printer.lan (192.168.1.50 -> 50.1.168.192.in-addr.arpa)
        let r_ptr = client
            .query_udp("50.1.168.192.in-addr.arpa", RecordType::PTR)
            .await
            .unwrap();
        assert_eq!(r_ptr.answers.len(), 1);
        assert_eq!(r_ptr.answers[0].record_type(), RecordType::PTR);
        assert_eq!(
            r_ptr.answers[0].data,
            RData::PTR(PTR(Name::from_str("printer.lan.").unwrap()))
        );

        // 4. CNAME local chain: app.lan -> web.lan -> 192.168.1.80
        let r_cname = client.query_udp("app.lan", RecordType::A).await.unwrap();
        assert_eq!(r_cname.answers.len(), 2);
        assert_eq!(
            r_cname.answers[0].data,
            RData::CNAME(CNAME(Name::from_str("web.lan.").unwrap()))
        );
        assert_eq!(
            r_cname.answers[1].data,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 80)))
        );

        // 5. Exception clients: standard query gets local rewrite 192.168.1.90
        let r_nas = client.query_udp("nas.lan", RecordType::A).await.unwrap();
        assert_eq!(
            r_nas.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 90)))
        );

        // Excepted client (admin-laptop) bypasses rewrite and gets upstream response (100.100.100.100)
        let doh_admin = server.doh_url("/dns-query/admin-laptop");
        let r_admin = client
            .query_doh_post(&doh_admin, "nas.lan", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            r_admin.answers[0].data,
            RData::A(A(Ipv4Addr::new(100, 100, 100, 100)))
        );

        server.shutdown().await.unwrap();
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// 15. Acceptance test: ADR-0007 Precedence ($important beats rewrite; rewrite beats standard block)
    #[tokio::test]
    async fn test_acceptance_m4_adr007_precedence_important_vs_rewrite() {
        let mock_upstream = MockDnsServer::spawn().await.unwrap();

        let rewrites_val: toml::Value = toml::from_str(
            r#"
            entries = [
                { domain = "printer.lan", type = "A", answer = "192.168.1.50" },
                { domain = "tracker.lan", type = "A", answer = "192.168.1.99" }
            ]
        "#,
        )
        .unwrap();

        let mut config = Config::default();
        config.upstream.servers = vec![mock_upstream.addr().to_string()];
        config.filtering.custom_rules = vec![
            "||printer.lan^".to_string(),           // standard block
            "||tracker.lan^$important".to_string(), // important block
        ];
        config.rewrites = Some(rewrites_val);

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();

        // 1. Local rewrite beats standard block:
        // printer.lan has a local rewrite and standard block ||printer.lan^
        // Local rewrite MUST win over standard block
        let r_printer = client
            .query_udp("printer.lan", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            r_printer.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 50)))
        );

        // 2. $important block beats local rewrite:
        // tracker.lan has a local rewrite and ||tracker.lan^$important
        // $important block MUST win over local rewrite per ADR-0007
        let r_tracker = client
            .query_udp("tracker.lan", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            r_tracker.answers[0].data,
            RData::A(A(Ipv4Addr::UNSPECIFIED))
        );

        server.shutdown().await.unwrap();
    }

    /// 16. Acceptance test: Client identification by DoT SNI subdomain
    #[tokio::test]
    async fn test_acceptance_m4_dot_sni_client_identification() {
        let (cert_pem, key_pem) =
            generate_test_cert(&["sito-test.local", "127.0.0.1", "phone.dns.sito-test.local"]);
        let temp_dir = std::env::temp_dir().join(format!("sito_sni_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");
        tokio::fs::write(&cert_file, cert_pem).await.unwrap();
        tokio::fs::write(&key_file, key_pem).await.unwrap();

        let mock_upstream = MockDnsServer::spawn().await.unwrap();
        mock_upstream.add_a_record("www.google.com", Ipv4Addr::new(1, 2, 3, 4), 300);

        let clients_val: toml::Value = toml::from_str(
            r#"
            [[entries]]
            name = "phone"
            ids = ["phone"]
            group = "kids"

            [groups.kids]
            safe_search = true
        "#,
        )
        .unwrap();

        let mut config = Config::default();
        config.upstream.servers = vec![mock_upstream.addr().to_string()];
        config.clients = Some(clients_val);
        config.dns.dot_port = 0;
        config.tls = Some(sito_core::config::TlsConfig {
            cert: Some(cert_file),
            key: Some(key_file),
            sni_certs: Vec::new(),
        });

        let server = TestServerInstance::spawn(config).await.unwrap();
        let client = server.client();

        // Connect via DoT with SNI "phone.dns.sito-test.local"
        // Client identification resolves "phone" -> group "kids" -> safe search enabled!
        let r = client
            .query_dot(
                server.dot_addr(),
                "phone.dns.sito-test.local",
                "www.google.com",
                RecordType::A,
            )
            .await
            .unwrap();

        assert_eq!(r.answers[0].record_type(), RecordType::CNAME);
        assert_eq!(
            r.answers[0].data,
            RData::CNAME(CNAME(
                Name::from_str("forcesafesearch.google.com.").unwrap()
            ))
        );

        server.shutdown().await.unwrap();
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// 17. Acceptance test: Check-config rejects invalid cron expression in TOML
    #[test]
    fn test_acceptance_check_config_rejects_bad_cron() {
        let temp_dir = std::env::temp_dir().join(format!("sito_check_cron_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let bad_cron_path = temp_dir.join("bad_cron.toml");
        let toml_content = r#"
config_version = 1
[server]
role = "master"

[clients]
[clients.groups.kids]
schedule_enabled = true
schedule = "99 99 99 99 99 99"
"#;
        std::fs::write(&bad_cron_path, toml_content).unwrap();
        let err = sito::cli::run_check_config(&bad_cron_path)
            .expect_err("Should fail due to invalid cron");
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("Clients configuration validation failed")
                || err_msg.contains("schedule"),
            "Error should mention clients validation failure: {err_msg}"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
