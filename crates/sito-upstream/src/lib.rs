//! `sito-upstream`
//!
//! Upstream DNS server forwarding, plain UDP/TCP fallback, DoT with connection pooling,
//! bootstrap resolver, and health-aware failover manager.

pub mod bootstrap;
pub mod dot;
pub mod health;
pub mod manager;
pub mod plain;
pub mod upstream;

pub use bootstrap::BootstrapResolver;
pub use dot::DotUpstream;
pub use health::{HealthStatus, UpstreamHealth};
pub use manager::UpstreamManager;
pub use plain::PlainUpstream;
pub use upstream::Upstream;

#[cfg(test)]
mod tests {
    use super::*;
    use sito_core::config::UpstreamStrategy;
    use sito_core::error::UpstreamError;
    use sito_proto::rdata::A;
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

    #[tokio::test]
    async fn test_bootstrap_resolves_hostname_mock() {
        // Spawn a mock plain DNS server on an ephemeral port acting as bootstrap DNS
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if let Ok((len, peer)) = mock_socket.recv_from(&mut buf).await
                && let Ok(query) = decode_message(&buf[..len])
            {
                let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                resp.queries = query.queries.clone();
                resp.metadata.response_code = ResponseCode::NoError;
                // Return 1.2.3.4 for any query
                resp.answers.push(Record::from_rdata(
                    query.queries[0].name().clone(),
                    300,
                    RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
                ));
                if let Ok(encoded) = encode_message(&resp) {
                    let _ = mock_socket.send_to(&encoded, peer).await;
                }
            }
        });

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
