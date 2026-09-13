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
pub use manager::UpstreamManager;
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
                        if let Some(v4) = ipv4 {
                            resp.answers
                                .push(Record::from_rdata(qname, 300, RData::A(A(v4))));
                        }
                    }
                    RecordType::AAAA => {
                        if let Some(v6) = ipv6 {
                            resp.answers.push(Record::from_rdata(
                                qname,
                                300,
                                RData::AAAA(AAAA(v6)),
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
