//! `sito-transport`
//!
//! Multi-protocol DNS transport listeners (UDP, TCP) with SO_REUSEPORT,
//! IP_PKTINFO, EDNS(0), RFC 7766 pipelining, and per-IP rate limiting.

pub mod handler;
pub mod limiter;
pub mod pktinfo;
pub mod tcp;
pub mod udp;

pub use handler::QueryHandler;
pub use limiter::RateLimiter;
pub use tcp::{TcpConfig, start_tcp_listener};
pub use udp::{UdpConfig, create_reuseport_udp_socket, start_udp_listener};

#[cfg(test)]
mod tests {
    use super::*;
    use sito_core::client::ClientContext;
    use sito_proto::rdata::A;
    use sito_proto::{
        Message, MessageType, Name, OpCode, Query, RData, Record, RecordType, ResponseCode,
        decode_message, encode_message,
    };
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UdpSocket};
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_udp_query_and_response() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Create socket to get an ephemeral port
        let std_socket = create_reuseport_udp_socket(&bind_addr).unwrap();
        let port = std_socket.local_addr().unwrap().port();
        drop(std_socket);

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let config = UdpConfig {
            bind_addr: actual_addr,
            worker_count: 2,
            edns_udp_size: 1232,
            rate_limit_per_ip: 100,
        };

        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            let qname = query.queries[0].name().clone();
            resp.answers.push(Record::from_rdata(
                qname,
                300,
                RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
            ));
            Some(resp)
        });

        let _handles = start_udp_listener(config, &handler, &shutdown_rx).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut query = Message::new(1001, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));

        let encoded = encode_message(&query).unwrap();
        client.send_to(&encoded, actual_addr).await.unwrap();

        let mut buf = [0u8; 1024];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("timeout waiting for UDP response")
            .unwrap();

        let resp = decode_message(&buf[..len]).unwrap();
        assert_eq!(resp.metadata.id, 1001);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(
            resp.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4)))
        );

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test]
    async fn test_udp_truncation_when_exceeding_buffer() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let std_socket = create_reuseport_udp_socket(&bind_addr).unwrap();
        let port = std_socket.local_addr().unwrap().port();
        drop(std_socket);

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let config = UdpConfig {
            bind_addr: actual_addr,
            worker_count: 1,
            edns_udp_size: 1232,
            rate_limit_per_ip: 100,
        };

        // Handler generates a huge response > 512 bytes
        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            let qname = query.queries[0].name().clone();
            for i in 0..50 {
                resp.answers.push(Record::from_rdata(
                    qname.clone(),
                    300,
                    RData::A(A(std::net::Ipv4Addr::new(10, 0, 0, i))),
                ));
            }
            Some(resp)
        });

        let _handles = start_udp_listener(config, &handler, &shutdown_rx).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Plain query without EDNS (max payload 512)
        let mut query = Message::new(2002, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("huge.example.com.").unwrap(),
            RecordType::A,
        ));

        let encoded = encode_message(&query).unwrap();
        client.send_to(&encoded, actual_addr).await.unwrap();

        let mut buf = [0u8; 2048];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("timeout waiting for UDP response")
            .unwrap();

        let resp = decode_message(&buf[..len]).unwrap();
        assert_eq!(resp.metadata.id, 2002);
        // Must be marked as truncated (TC=1)
        assert!(resp.metadata.truncation, "response should have TC=1 set");

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test]
    async fn test_tcp_query_and_pipelining() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let config = TcpConfig {
            bind_addr: actual_addr,
            max_connections: 10,
            idle_timeout: Duration::from_secs(5),
            rate_limit_per_ip: 100,
        };

        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            let qname = query.queries[0].name().clone();
            resp.answers.push(Record::from_rdata(
                qname,
                300,
                RData::A(A(std::net::Ipv4Addr::new(9, 9, 9, 9))),
            ));
            Some(resp)
        });

        let _handle = start_tcp_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut stream = TcpStream::connect(actual_addr).await.unwrap();

        // Send 3 pipelined queries over single TCP connection
        for id in 3001..=3003 {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.queries.push(Query::query(
                Name::from_str("tcp.example.com.").unwrap(),
                RecordType::A,
            ));
            let encoded = encode_message(&query).unwrap();
            let len = encoded.len() as u16;
            stream.write_all(&len.to_be_bytes()).await.unwrap();
            stream.write_all(&encoded).await.unwrap();
        }
        stream.flush().await.unwrap();

        // Read 3 responses
        let mut received_ids = Vec::new();
        for _ in 3001..=3003 {
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.unwrap();
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            let mut resp_buf = vec![0u8; resp_len];
            stream.read_exact(&mut resp_buf).await.unwrap();
            let resp = decode_message(&resp_buf).unwrap();
            received_ids.push(resp.metadata.id);
        }

        assert_eq!(received_ids.len(), 3);
        assert!(received_ids.contains(&3001));
        assert!(received_ids.contains(&3002));
        assert!(received_ids.contains(&3003));

        let _ = shutdown_tx.send(true);
    }
}
