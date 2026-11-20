//! `sito-upstream`
//!
//! Upstream DNS server forwarding, plain UDP/TCP fallback, DoT with connection pooling,
//! bootstrap resolver, and health-aware failover manager.

pub mod bootstrap;
pub mod doh;
pub mod doq;
pub mod dot;
pub mod health;
pub mod key_fetch;
pub mod manager;
pub mod plain;
pub mod upstream;

pub use bootstrap::BootstrapResolver;
pub use doh::HttpsUpstream;
pub use doq::QuicUpstream;
pub use dot::DotUpstream;
pub use health::{HealthStatus, UpstreamHealth};
pub use key_fetch::UpstreamKeyFetcher;
pub use manager::{PreparedUpstream, UpstreamManager, UpstreamQueryError};
pub use plain::PlainUpstream;
pub use upstream::Upstream;

#[cfg(test)]
mod tests {
    use super::*;
    use sito_core::config::UpstreamStrategy;
    use sito_core::error::UpstreamError;
    use sito_proto::rdata::{A, AAAA};
    use sito_proto::{
        Message, MessageType, Name, OpCode, Query, RData, Record, RecordType, ResponseCode,
        decode_message, encode_message,
    };
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;
    use tokio::net::{TcpListener, UdpSocket};

    // Fake mock upstream
    struct MockUpstream {
        succeed: bool,
        call_count: Arc<AtomicU32>,
    }

    #[async_trait::async_trait]
    impl Upstream for MockUpstream {
        async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.succeed {
                let mut resp = Message::response(msg.metadata.id, msg.metadata.op_code);
                resp.queries = msg.queries.clone();
                resp.metadata.response_code = ResponseCode::NoError;
                resp.answers.push(Record::from_rdata(
                    msg.queries[0].name().clone(),
                    300,
                    RData::A(A(std::net::Ipv4Addr::new(8, 8, 8, 8))),
                ));
                Ok(resp)
            } else {
                Err(UpstreamError::Timeout)
            }
        }
    }

    #[tokio::test]
    async fn test_failover_when_first_upstream_fails() {
        let calls_dead = Arc::new(AtomicU32::new(0));
        let calls_alive = Arc::new(AtomicU32::new(0));

        let dead_upstream = Arc::new(MockUpstream {
            succeed: false,
            call_count: Arc::clone(&calls_dead),
        });

        let alive_upstream = Arc::new(MockUpstream {
            succeed: true,
            call_count: Arc::clone(&calls_alive),
        });

        let manager = UpstreamManager::with_upstreams(
            vec![
                ("dead.dns".to_string(), dead_upstream),
                ("alive.dns".to_string(), alive_upstream),
            ],
            UpstreamStrategy::Failover,
            Duration::from_millis(500),
        );

        let mut query = Message::new(100, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));

        let res = manager
            .resolve(&query)
            .await
            .expect("failover should succeed");
        assert_eq!(res.metadata.response_code, ResponseCode::NoError);
        assert_eq!(calls_dead.load(Ordering::SeqCst), 1);
        assert_eq!(calls_alive.load(Ordering::SeqCst), 1);
    }

    /// Spawns a mock bootstrap DNS server answering A and AAAA queries.
    /// `ipv4`/`ipv6` may be `None` to synthesize an empty NOERROR answer.
    fn spawn_bootstrap_server(
        ipv4: Option<std::net::Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
    ) -> (SocketAddr, Arc<AtomicU32>) {
        spawn_bootstrap_answers(ipv4.into_iter().collect(), ipv6.into_iter().collect())
    }

    /// Spawns a mock bootstrap server returning every supplied A/AAAA record.
    fn spawn_bootstrap_answers(
        ipv4s: Vec<std::net::Ipv4Addr>,
        ipv6s: Vec<std::net::Ipv6Addr>,
    ) -> (SocketAddr, Arc<AtomicU32>) {
        let query_count = Arc::new(AtomicU32::new(0));
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let socket = tokio::net::UdpSocket::from_std(listener).unwrap();
        let count = Arc::clone(&query_count);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let Ok(query) = decode_message(&buf[..len]) else {
                    continue;
                };
                let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                resp.queries = query.queries.clone();
                resp.metadata.response_code = ResponseCode::NoError;
                let qname = query.queries[0].name().clone();
                match query.queries[0].query_type() {
                    RecordType::A => {
                        for v4 in &ipv4s {
                            resp.answers.push(Record::from_rdata(
                                qname.clone(),
                                300,
                                RData::A(A(*v4)),
                            ));
                        }
                    }
                    RecordType::AAAA => {
                        for v6 in &ipv6s {
                            resp.answers.push(Record::from_rdata(
                                qname.clone(),
                                300,
                                RData::AAAA(AAAA(*v6)),
                            ));
                        }
                    }
                    _ => {}
                }
                if let Ok(encoded) = encode_message(&resp) {
                    let _ = socket.send_to(&encoded, peer).await;
                }
            }
        });
        (addr, query_count)
    }

    /// Spawns a mock bootstrap server whose A answers rotate from `first` to
    /// `second` after the first lookup. Used to prove denied answers are not
    /// cached and forced refreshes bypass the cache.
    fn spawn_rotating_bootstrap(
        first: std::net::Ipv4Addr,
        second: std::net::Ipv4Addr,
    ) -> (SocketAddr, Arc<AtomicU32>) {
        let query_count = Arc::new(AtomicU32::new(0));
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let socket = tokio::net::UdpSocket::from_std(listener).unwrap();
        let count = Arc::clone(&query_count);
        tokio::spawn(async move {
            let mut a_index = 0u32;
            let mut buf = [0u8; 1024];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let Ok(query) = decode_message(&buf[..len]) else {
                    continue;
                };
                let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                resp.queries = query.queries.clone();
                resp.metadata.response_code = ResponseCode::NoError;
                if query.queries[0].query_type() == RecordType::A {
                    let ip = if a_index == 0 { first } else { second };
                    a_index += 1;
                    resp.answers.push(Record::from_rdata(
                        query.queries[0].name().clone(),
                        300,
                        RData::A(A(ip)),
                    ));
                }
                if let Ok(encoded) = encode_message(&resp) {
                    let _ = socket.send_to(&encoded, peer).await;
                }
            }
        });
        (addr, query_count)
    }

    /// Mock bootstrap server that only answers queries with RD=1, refusing
    /// RD=0 like many recursive resolvers do.
    fn spawn_rd_enforcing_bootstrap(
        v4: Option<std::net::Ipv4Addr>,
        v6: Option<std::net::Ipv6Addr>,
    ) -> SocketAddr {
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let socket = tokio::net::UdpSocket::from_std(listener).unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                let Ok(query) = decode_message(&buf[..len]) else {
                    continue;
                };
                let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                resp.queries = query.queries.clone();
                if query.metadata.recursion_desired {
                    resp.metadata.response_code = ResponseCode::NoError;
                    match (query.queries[0].query_type(), v4, v6) {
                        (RecordType::A, Some(v4), _) => {
                            resp.answers.push(Record::from_rdata(
                                query.queries[0].name().clone(),
                                300,
                                RData::A(A(v4)),
                            ));
                        }
                        (RecordType::AAAA, _, Some(v6)) => {
                            resp.answers.push(Record::from_rdata(
                                query.queries[0].name().clone(),
                                300,
                                RData::AAAA(AAAA(v6)),
                            ));
                        }
                        _ => {}
                    }
                } else {
                    resp.metadata.response_code = ResponseCode::Refused;
                }
                if let Ok(encoded) = encode_message(&resp) {
                    let _ = socket.send_to(&encoded, peer).await;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_bootstrap_queries_set_recursion_desired() {
        let mock_addr =
            spawn_rd_enforcing_bootstrap(Some(std::net::Ipv4Addr::new(4, 4, 4, 4)), None);
        let bootstrap = BootstrapResolver::new(vec![mock_addr.ip()], Duration::from_millis(1000))
            .with_port(mock_addr.port());

        let ips = bootstrap
            .resolve_hostname("rd.example.com")
            .await
            .expect("bootstrap queries must set RD=1");
        assert_eq!(
            ips,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(4, 4, 4, 4))]
        );
    }

    #[tokio::test]
    async fn test_bootstrap_aaaa_query_sets_recursion_desired() {
        let v6 = std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let mock_addr = spawn_rd_enforcing_bootstrap(None, Some(v6));
        let bootstrap = BootstrapResolver::new(vec![mock_addr.ip()], Duration::from_millis(1000))
            .with_port(mock_addr.port());

        let ips = bootstrap
            .resolve_hostname("rd-aaaa.example.com")
            .await
            .expect("AAAA bootstrap queries must set RD=1");
        assert_eq!(ips, vec![std::net::IpAddr::V6(v6)]);
    }

    #[tokio::test]
    async fn test_bootstrap_rejects_private_answers_by_default() {
        let (mock_addr, _) =
            spawn_bootstrap_server(Some(std::net::Ipv4Addr::new(10, 0, 0, 1)), None);
        let bootstrap = BootstrapResolver::new(vec![mock_addr.ip()], Duration::from_millis(1000))
            .with_port(mock_addr.port());

        let result = bootstrap.resolve_hostname("private.example.com").await;
        let error = result.expect_err("bootstrap must reject private answers by default");
        assert!(
            error.to_string().contains("allow_private_targets"),
            "the error must tell the operator how to opt in: {error}"
        );
    }

    #[tokio::test]
    async fn test_bootstrap_rejects_nat64_embedded_private_answers() {
        // 64:ff9b::192.168.1.1 embeds a private IPv4 target; the shared SSRF
        // helper unwraps it and must reject the answer by default.
        let embedded = std::net::Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xc0a8, 0x0101);
        let (mock_addr, _) = spawn_bootstrap_server(None, Some(embedded));
        let bootstrap = BootstrapResolver::new(vec![mock_addr.ip()], Duration::from_millis(1000))
            .with_port(mock_addr.port());

        let result = bootstrap.resolve_hostname("nat64.example.com").await;
        assert!(
            result.is_err(),
            "NAT64-embedded private targets must be rejected: {result:?}"
        );
    }

    /// Mixed answers keep the public candidates and silently drop private ones;
    /// a single denied record must not poison the whole resolution.
    #[tokio::test]
    async fn test_bootstrap_mixed_answers_keep_only_public_candidates() {
        let public_v4 = std::net::Ipv4Addr::new(8, 8, 8, 8);
        let public_v6 = std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let (mock_addr, _) = spawn_bootstrap_answers(
            vec![std::net::Ipv4Addr::new(10, 0, 0, 1), public_v4],
            vec![
                std::net::Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1),
                public_v6,
            ],
        );
        let bootstrap = BootstrapResolver::new(vec![mock_addr.ip()], Duration::from_millis(1000))
            .with_port(mock_addr.port());

        let ips = bootstrap
            .resolve_hostname("mixed.example.com")
            .await
            .expect("public candidates must survive a mixed answer");
        assert_eq!(
            ips,
            vec![
                std::net::IpAddr::V4(public_v4),
                std::net::IpAddr::V6(public_v6)
            ],
            "private candidates must be dropped and no fallback may use them"
        );
    }

    /// IPv4-mapped, 6to4 and Teredo answers that embed a private IPv4 target
    /// must be rejected by the bootstrap layer, not only by the shared helper.
    #[tokio::test]
    async fn test_bootstrap_rejects_ipv4_embedded_private_answers() {
        for embedded in [
            // ::ffff:10.0.0.1
            std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001),
            // 6to4 2002:0a00:0001::/48 -> 10.0.0.1
            std::net::Ipv6Addr::new(0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 0),
            // Teredo 2001:0::/32 -> 10.0.0.1 (bitwise inverted)
            std::net::Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0xf5ff, 0xfffe),
        ] {
            let (mock_addr, _) = spawn_bootstrap_server(None, Some(embedded));
            let bootstrap =
                BootstrapResolver::new(vec![mock_addr.ip()], Duration::from_millis(1000))
                    .with_port(mock_addr.port());

            let result = bootstrap.resolve_hostname("embedded.example.com").await;
            assert!(
                result.is_err(),
                "embedded private target {embedded} must be rejected: {result:?}"
            );
        }
    }

    /// A denied-only answer must not enter the cache: the next lookup has to
    /// query the bootstrap again and can pick up a corrected public answer.
    #[tokio::test]
    async fn test_bootstrap_denied_answer_is_not_cached() {
        let private = std::net::Ipv4Addr::new(10, 0, 0, 1);
        let public = std::net::Ipv4Addr::new(9, 9, 9, 9);
        let (mock_addr, query_count) = spawn_rotating_bootstrap(private, public);
        let bootstrap = BootstrapResolver::new(vec![mock_addr.ip()], Duration::from_millis(1000))
            .with_port(mock_addr.port());

        let denied = bootstrap.resolve_hostname("uncached.example.com").await;
        assert!(
            denied.is_err(),
            "the first (private-only) answer must be denied: {denied:?}"
        );

        let ips = bootstrap
            .resolve_hostname("uncached.example.com")
            .await
            .expect("a later lookup must re-resolve instead of reusing a denied result");
        assert_eq!(ips, vec![std::net::IpAddr::V4(public)]);
        assert!(
            query_count.load(Ordering::SeqCst) >= 4,
            "the denied result must not be cached (A+AAAA queries expected for both lookups)"
        );
    }

    /// An explicit IP literal is the intentional allowlist path: it is an
    /// operator choice and bypasses the bootstrap SSRF denylist.
    #[tokio::test]
    async fn test_bootstrap_ip_literal_bypasses_denylist() {
        let bootstrap = BootstrapResolver::new(
            vec![std::net::Ipv4Addr::new(9, 9, 9, 9).into()],
            Duration::from_millis(100),
        );
        for literal in ["10.0.0.1", "127.0.0.1", "::1"] {
            let ips = bootstrap
                .resolve_hostname(literal)
                .await
                .expect("an explicit IP literal must not be denied");
            assert_eq!(ips, vec![literal.parse::<std::net::IpAddr>().unwrap()]);
        }
    }

    /// The manager resolves a hostname through the bootstrap resolver before
    /// constructing any transport, so the default deny policy rejects a
    /// private target at that point and the opt-in admits it.
    #[tokio::test]
    async fn test_manager_rejects_private_hostname_before_building_transport() {
        let (mock_addr, _) =
            spawn_bootstrap_server(Some(std::net::Ipv4Addr::new(10, 0, 0, 1)), None);
        let mut config = sito_core::config::UpstreamConfig {
            servers: vec!["tls://private-upstream.example".to_string()],
            bootstrap: vec![mock_addr.ip()],
            timeout_ms: 1000,
            ..Default::default()
        };

        let denied = BootstrapResolver::from_config(&config).with_port(mock_addr.port());
        let Err(error) = UpstreamManager::from_config(&config, &denied).await else {
            panic!("a private hostname target must be rejected by default");
        };
        assert!(
            error.to_string().contains("allow_private_targets"),
            "the error must point at the opt-in: {error}"
        );

        config.allow_private_targets = true;
        let allowed = BootstrapResolver::from_config(&config).with_port(mock_addr.port());
        UpstreamManager::from_config(&config, &allowed)
            .await
            .expect("allow_private_targets must admit the private hostname target");
    }

    #[tokio::test]
    async fn test_bootstrap_allows_private_answers_when_opted_in() {
        let (mock_addr, _) =
            spawn_bootstrap_server(Some(std::net::Ipv4Addr::new(10, 0, 0, 1)), None);
        let bootstrap = BootstrapResolver::new(vec![mock_addr.ip()], Duration::from_millis(1000))
            .with_port(mock_addr.port())
            .with_allow_private_targets(true);

        let ips = bootstrap
            .resolve_hostname("private.example.com")
            .await
            .expect("opt-in must allow private bootstrap targets");
        assert_eq!(
            ips,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))]
        );
    }

    #[tokio::test]
    async fn test_bootstrap_from_config_applies_allow_private_targets() {
        let (mock_addr, _) =
            spawn_bootstrap_server(Some(std::net::Ipv4Addr::new(10, 0, 0, 1)), None);

        let denied_config = sito_core::config::UpstreamConfig {
            bootstrap: vec![mock_addr.ip()],
            timeout_ms: 1000,
            ..Default::default()
        };
        let denied = BootstrapResolver::from_config(&denied_config).with_port(mock_addr.port());
        assert!(
            denied
                .resolve_hostname("private.example.com")
                .await
                .is_err(),
            "from_config must preserve the default deny policy"
        );

        let allowed_config = sito_core::config::UpstreamConfig {
            allow_private_targets: true,
            ..denied_config
        };
        let allowed = BootstrapResolver::from_config(&allowed_config).with_port(mock_addr.port());
        assert_eq!(
            allowed
                .resolve_hostname("private.example.com")
                .await
                .unwrap(),
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))]
        );
    }

    #[tokio::test]
    async fn test_bootstrap_resolves_hostname_mock() {
        let (mock_addr, _) =
            spawn_bootstrap_server(Some(std::net::Ipv4Addr::new(1, 2, 3, 4)), None);

        let bootstrap = BootstrapResolver::new(vec![mock_addr.ip()], Duration::from_millis(1000))
            .with_port(mock_addr.port());

        let ips = bootstrap
            .resolve_hostname("dot.example.com")
            .await
            .expect("bootstrap should resolve hostname");

        assert_eq!(
            ips,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))]
        );
    }

    #[tokio::test]
    async fn test_bootstrap_resolves_ipv6_only_hostname() {
        let v6 = std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let (mock_addr, _) = spawn_bootstrap_server(None, Some(v6));

        let bootstrap = BootstrapResolver::new(vec![mock_addr.ip()], Duration::from_millis(1000))
            .with_port(mock_addr.port());

        let ips = bootstrap
            .resolve_hostname("v6-only.example.com")
            .await
            .expect("IPv6-only hostname must resolve via AAAA");
        assert_eq!(ips, vec![std::net::IpAddr::V6(v6)]);
    }

    #[tokio::test]
    async fn test_bootstrap_concurrent_lookups_are_single_flight() {
        let (mock_addr, query_count) =
            spawn_bootstrap_server(Some(std::net::Ipv4Addr::new(9, 9, 9, 9)), None);

        let bootstrap = BootstrapResolver::new(vec![mock_addr.ip()], Duration::from_millis(1000))
            .with_port(mock_addr.port());

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let bootstrap = bootstrap.clone();
            tasks.push(tokio::spawn(async move {
                bootstrap.resolve_hostname("shared.example.com").await
            }));
        }
        for task in tasks {
            let ips = task
                .await
                .expect("join")
                .expect("concurrent bootstrap lookup");
            assert_eq!(
                ips,
                vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(9, 9, 9, 9))]
            );
        }

        // One resolution attempt = one A + one AAAA query, not 16x that.
        let total = query_count.load(Ordering::SeqCst);
        assert!(
            total <= 2,
            "concurrent lookups must share a single resolution (saw {total} queries)"
        );
    }

    #[tokio::test]
    async fn test_plain_upstream_tc_fallback_to_tcp() {
        // Bind UDP and TCP on the same ephemeral port
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp_listener.local_addr().unwrap().port();
        let udp_socket = UdpSocket::bind(format!("127.0.0.1:{port}")).await.unwrap();
        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        // UDP handler returns TC=1 (truncation)
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if let Ok((len, peer)) = udp_socket.recv_from(&mut buf).await
                && let Ok(query) = decode_message(&buf[..len])
            {
                let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                resp.queries = query.queries.clone();
                resp.metadata.truncation = true; // Set TC=1
                if let Ok(encoded) = encode_message(&resp) {
                    let _ = udp_socket.send_to(&encoded, peer).await;
                }
            }
        });

        // TCP handler returns full answer
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            if let Ok((mut stream, _)) = tcp_listener.accept().await {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_ok() {
                    let req_len = u16::from_be_bytes(len_buf) as usize;
                    let mut req_buf = vec![0u8; req_len];
                    if stream.read_exact(&mut req_buf).await.is_ok()
                        && let Ok(query) = decode_message(&req_buf)
                    {
                        let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                        resp.queries = query.queries.clone();
                        resp.metadata.response_code = ResponseCode::NoError;
                        resp.answers.push(Record::from_rdata(
                            query.queries[0].name().clone(),
                            300,
                            RData::A(A(std::net::Ipv4Addr::new(7, 7, 7, 7))),
                        ));
                        if let Ok(encoded) = encode_message(&resp) {
                            let resp_len = encoded.len() as u16;
                            let _ = stream.write_all(&resp_len.to_be_bytes()).await;
                            let _ = stream.write_all(&encoded).await;
                            let _ = stream.flush().await;
                        }
                    }
                }
            }
        });

        let upstream = PlainUpstream::new(server_addr, Duration::from_secs(2));
        let mut query = Message::new(500, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("tcp-fallback.test.").unwrap(),
            RecordType::A,
        ));

        let resp = upstream
            .resolve(&query)
            .await
            .expect("query with fallback should succeed");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(
            resp.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(7, 7, 7, 7)))
        );
    }
}
