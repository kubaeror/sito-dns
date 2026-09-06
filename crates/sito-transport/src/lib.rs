//! `sito-transport`
//!
//! Multi-protocol DNS transport listeners (UDP, TCP) with SO_REUSEPORT,
//! IP_PKTINFO, EDNS(0), RFC 7766 pipelining, and per-IP rate limiting.

#[cfg(not(unix))]
compile_error!("sito-transport requires a Unix-based operating system (Linux/macOS)");

pub mod acme;
pub mod doh;
pub mod doh3;
pub mod doq;
pub mod dot;
pub mod handler;
pub mod limiter;
pub mod pktinfo;
pub mod tcp;
pub mod tls;
pub mod udp;

pub use acme::{
    AcmeServiceConfig, days_until_expiration, generate_tls_alpn_01_cert,
    obtain_or_renew_certificate, start_acme_manager,
};
pub use doh::{DohConfig, start_doh_listener};
pub use doh3::{Doh3Config, build_quinn_h3_server_config, start_doh3_listener};
pub use doq::{DoqConfig, build_quinn_server_config, start_doq_listener};
pub use dot::{DotConfig, start_dot_listener};
pub use handler::QueryHandler;
pub use limiter::RateLimiter;
pub use tcp::{TcpConfig, start_tcp_listener};
pub use tls::{
    CertWatcher, DynamicCertResolver, TlsAcceptorManager, TlsError, build_server_config,
    generate_self_signed_cert, load_certificates, load_private_key, load_server_config,
    load_server_config_with_challenges, validate_certificate_validity,
};
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
    async fn test_udp_concurrent_queries_no_head_of_line_blocking() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let std_socket = create_reuseport_udp_socket(&bind_addr).unwrap();
        let port = std_socket.local_addr().unwrap().port();
        drop(std_socket);

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        // Single worker listener to guarantee tests run on the same worker
        let config = UdpConfig {
            bind_addr: actual_addr,
            worker_count: 1,
            edns_udp_size: 1232,
            rate_limit_per_ip: 100,
        };

        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let qname = query.queries[0].name().clone();
            let is_slow = qname.to_string().starts_with("slow");

            if is_slow {
                // Simulate slow upstream resolution (e.g. 200ms)
                tokio::time::sleep(Duration::from_millis(200)).await;
            }

            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
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

        // 1. Send slow query
        let mut slow_query = Message::new(100, MessageType::Query, OpCode::Query);
        slow_query.queries.push(Query::query(
            Name::from_str("slow.example.com.").unwrap(),
            RecordType::A,
        ));
        let slow_encoded = encode_message(&slow_query).unwrap();
        client.send_to(&slow_encoded, actual_addr).await.unwrap();

        // 2. Immediately send fast query
        let mut fast_query = Message::new(200, MessageType::Query, OpCode::Query);
        fast_query.queries.push(Query::query(
            Name::from_str("fast.example.com.").unwrap(),
            RecordType::A,
        ));
        let fast_encoded = encode_message(&fast_query).unwrap();
        client.send_to(&fast_encoded, actual_addr).await.unwrap();

        // 3. First packet received must be the fast response (id 200) despite being sent second!
        let mut buf = [0u8; 1024];
        let (len1, _) =
            tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut buf))
                .await
                .expect("fast response should arrive before slow query completes")
                .unwrap();
        let resp1 = decode_message(&buf[..len1]).unwrap();
        assert_eq!(
            resp1.metadata.id, 200,
            "Fast query must not be blocked by slow query"
        );

        // 4. Second packet received should be the slow response (id 100)
        let (len2, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("slow response should arrive eventually")
            .unwrap();
        let resp2 = decode_message(&buf[..len2]).unwrap();
        assert_eq!(resp2.metadata.id, 100);

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

    #[tokio::test]
    async fn test_dot_query_and_padding() {
        use crate::tls::generate_test_cert;
        use rustls_pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let temp_dir = std::env::temp_dir().join(format!("sito_dot_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");

        let (cert_pem, key_pem) = generate_test_cert(&["localhost", "dot.example.com"]);
        std::fs::write(&cert_file, cert_pem).unwrap();
        std::fs::write(&key_file, key_pem).unwrap();

        let server_config =
            load_server_config(&cert_file, &key_file, &[], vec![b"dot".to_vec()]).unwrap();
        let acceptor_mgr = TlsAcceptorManager::new(server_config);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let mut config = DotConfig::new(actual_addr, acceptor_mgr);
        config.dot_padding = true;

        let handler = Arc::new(|query: Message, client: ClientContext| async move {
            assert_eq!(client.sni.as_deref(), Some("dot.example.com"));
            assert_eq!(
                client.id.as_ref().map(sito_core::ClientId::as_str),
                Some("dot.example.com")
            );

            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            let qname = query.queries[0].name().clone();
            resp.answers.push(Record::from_rdata(
                qname,
                300,
                RData::A(A(std::net::Ipv4Addr::new(1, 1, 1, 1))),
            ));
            Some(resp)
        });

        let _handle = start_dot_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Build client config trusting our cert and offering ALPN "dot"
        let mut root_store = rustls::RootCertStore::empty();
        let certs = load_certificates(&cert_file).unwrap();
        for c in certs {
            root_store.add(c).unwrap();
        }

        let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        client_config.alpn_protocols = vec![b"dot".to_vec()];

        let connector = TlsConnector::from(Arc::new(client_config));
        let tcp_stream = TcpStream::connect(actual_addr).await.unwrap();
        let server_name = ServerName::try_from("dot.example.com").unwrap().to_owned();
        let mut tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

        // Send a query
        let mut query = Message::new(4001, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("dot.example.com.").unwrap(),
            RecordType::A,
        ));
        let encoded = encode_message(&query).unwrap();
        let len = encoded.len() as u16;
        tls_stream.write_all(&len.to_be_bytes()).await.unwrap();
        tls_stream.write_all(&encoded).await.unwrap();
        tls_stream.flush().await.unwrap();

        // Read response
        let mut len_buf = [0u8; 2];
        tls_stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        tls_stream.read_exact(&mut resp_buf).await.unwrap();

        let resp = decode_message(&resp_buf).unwrap();
        assert_eq!(resp.metadata.id, 4001);
        assert_eq!(resp.answers.len(), 1);
        // Verify RFC 8467 response padding to 468 bytes multiple
        assert_eq!(
            resp_len % sito_proto::DOT_PADDING_BLOCK_SIZE,
            0,
            "Response must be padded to block size 468"
        );

        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_dot_alpn_mismatch_rejected() {
        use crate::tls::generate_test_cert;
        use rustls_pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let temp_dir = std::env::temp_dir().join(format!("sito_dot_alpn_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");

        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);
        std::fs::write(&cert_file, cert_pem).unwrap();
        std::fs::write(&key_file, key_pem).unwrap();

        let server_config =
            load_server_config(&cert_file, &key_file, &[], vec![b"dot".to_vec()]).unwrap();
        let acceptor_mgr = TlsAcceptorManager::new(server_config);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let config = DotConfig::new(actual_addr, acceptor_mgr);

        let handler = Arc::new(|_query: Message, _client: ClientContext| async move { None });

        let _handle = start_dot_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut root_store = rustls::RootCertStore::empty();
        let certs = load_certificates(&cert_file).unwrap();
        for c in certs {
            root_store.add(c).unwrap();
        }

        // Client offers only "h2", which must be rejected on DoT
        let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec()];

        let connector = TlsConnector::from(Arc::new(client_config));
        let tcp_stream = TcpStream::connect(actual_addr).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap().to_owned();
        let connect_res = connector.connect(server_name, tcp_stream).await;

        assert!(
            connect_res.is_err(),
            "Handshake with mismatched ALPN must fail"
        );

        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_dot_pipelining() {
        use crate::tls::generate_test_cert;
        use rustls_pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let temp_dir = std::env::temp_dir().join(format!("sito_dot_pipe_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");

        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);
        std::fs::write(&cert_file, cert_pem).unwrap();
        std::fs::write(&key_file, key_pem).unwrap();

        let server_config =
            load_server_config(&cert_file, &key_file, &[], vec![b"dot".to_vec()]).unwrap();
        let acceptor_mgr = TlsAcceptorManager::new(server_config);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let config = DotConfig::new(actual_addr, acceptor_mgr);

        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            let qname = query.queries[0].name().clone();
            resp.answers.push(Record::from_rdata(
                qname,
                300,
                RData::A(A(std::net::Ipv4Addr::new(8, 8, 8, 8))),
            ));
            Some(resp)
        });

        let _handle = start_dot_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut root_store = rustls::RootCertStore::empty();
        let certs = load_certificates(&cert_file).unwrap();
        for c in certs {
            root_store.add(c).unwrap();
        }

        let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        client_config.alpn_protocols = vec![b"dot".to_vec()];

        let connector = TlsConnector::from(Arc::new(client_config));
        let tcp_stream = TcpStream::connect(actual_addr).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap().to_owned();
        let mut tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

        // Send 5 pipelined queries
        for id in 5001..=5005 {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.queries.push(Query::query(
                Name::from_str("pipe.example.com.").unwrap(),
                RecordType::A,
            ));
            let encoded = encode_message(&query).unwrap();
            let len = encoded.len() as u16;
            tls_stream.write_all(&len.to_be_bytes()).await.unwrap();
            tls_stream.write_all(&encoded).await.unwrap();
        }
        tls_stream.flush().await.unwrap();

        let mut received = Vec::new();
        for _ in 5001..=5005 {
            let mut len_buf = [0u8; 2];
            tls_stream.read_exact(&mut len_buf).await.unwrap();
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            let mut resp_buf = vec![0u8; resp_len];
            tls_stream.read_exact(&mut resp_buf).await.unwrap();
            let resp = decode_message(&resp_buf).unwrap();
            received.push(resp.metadata.id);
        }

        assert_eq!(received.len(), 5);
        for id in 5001..=5005 {
            assert!(received.contains(&id));
        }

        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_dot_idle_timeout() {
        use crate::tls::generate_test_cert;
        use rustls_pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let temp_dir =
            std::env::temp_dir().join(format!("sito_dot_timeout_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");

        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);
        std::fs::write(&cert_file, cert_pem).unwrap();
        std::fs::write(&key_file, key_pem).unwrap();

        let server_config =
            load_server_config(&cert_file, &key_file, &[], vec![b"dot".to_vec()]).unwrap();
        let acceptor_mgr = TlsAcceptorManager::new(server_config);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let mut config = DotConfig::new(actual_addr, acceptor_mgr);
        config.idle_timeout = Duration::from_millis(150);

        let handler = Arc::new(|_query: Message, _client: ClientContext| async move { None });

        let _handle = start_dot_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut root_store = rustls::RootCertStore::empty();
        let certs = load_certificates(&cert_file).unwrap();
        for c in certs {
            root_store.add(c).unwrap();
        }

        let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        client_config.alpn_protocols = vec![b"dot".to_vec()];

        let connector = TlsConnector::from(Arc::new(client_config));
        let tcp_stream = TcpStream::connect(actual_addr).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap().to_owned();
        let mut tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

        // Wait for idle timeout to fire on server side
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut buf = [0u8; 1];
        let res = tls_stream.read(&mut buf).await;
        // Should return 0 bytes read (EOF)
        assert_eq!(res.unwrap(), 0);

        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_doh_plain_post_and_get() {
        use base64::Engine;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let config = DohConfig::new(actual_addr, None);

        let handler = Arc::new(|query: Message, client: ClientContext| async move {
            if let Some(ref id) = client.id
                && id.as_str() == "alice"
            {
                let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                resp.queries = query.queries.clone();
                resp.metadata.response_code = ResponseCode::NoError;
                let qname = query.queries[0].name().clone();
                resp.answers.push(Record::from_rdata(
                    qname,
                    300,
                    RData::A(A(std::net::Ipv4Addr::new(1, 1, 1, 1))),
                ));
                return Some(resp);
            }

            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            let qname = query.queries[0].name().clone();
            resp.answers.push(Record::from_rdata(
                qname,
                300,
                RData::A(A(std::net::Ipv4Addr::new(2, 2, 2, 2))),
            ));
            Some(resp)
        });

        let _handle = start_doh_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let base_url = format!("http://127.0.0.1:{port}");

        // 1. POST /dns-query
        let mut query = Message::new(6001, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("doh.example.com.").unwrap(),
            RecordType::A,
        ));
        let wire_query = encode_message(&query).unwrap();

        let resp = client
            .post(format!("{base_url}/dns-query"))
            .header("Content-Type", "application/dns-message")
            .body(wire_query.clone())
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/dns-message"
        );
        assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");

        let body_bytes = resp.bytes().await.unwrap();
        let dns_resp = decode_message(&body_bytes).unwrap();
        assert_eq!(dns_resp.metadata.id, 6001);
        assert_eq!(
            dns_resp.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(2, 2, 2, 2)))
        );

        // 2. GET /dns-query?dns=<base64url>
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&wire_query);
        let resp = client
            .get(format!("{base_url}/dns-query?dns={b64}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let body_bytes = resp.bytes().await.unwrap();
        let dns_resp = decode_message(&body_bytes).unwrap();
        assert_eq!(dns_resp.metadata.id, 6001);

        // 3. POST /dns-query/alice (route-based client ID)
        let resp = client
            .post(format!("{base_url}/dns-query/alice"))
            .header("Content-Type", "application/dns-message")
            .body(wire_query)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let body_bytes = resp.bytes().await.unwrap();
        let dns_resp = decode_message(&body_bytes).unwrap();
        assert_eq!(
            dns_resp.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(1, 1, 1, 1)))
        );

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test]
    async fn test_doh_error_responses() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let config = DohConfig::new(actual_addr, None);

        let handler = Arc::new(|_query: Message, _client: ClientContext| async move { None });
        let _handle = start_doh_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let base_url = format!("http://127.0.0.1:{port}");

        // Wrong content type on POST -> 415
        let resp = client
            .post(format!("{base_url}/dns-query"))
            .header("Content-Type", "text/plain")
            .body("not-a-dns-message")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE);

        // Missing dns param on GET -> 400
        let resp = client
            .get(format!("{base_url}/dns-query"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

        // Invalid base64 on GET -> 400
        let resp = client
            .get(format!("{base_url}/dns-query?dns=%%%invalid%%%"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

        // Unsupported method (PUT) -> 501
        let resp = client
            .put(format!("{base_url}/dns-query"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_IMPLEMENTED);

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test]
    async fn test_doh_tls_and_h2() {
        use crate::tls::generate_test_cert;

        let temp_dir = std::env::temp_dir().join(format!("sito_doh_tls_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");

        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);
        std::fs::write(&cert_file, &cert_pem).unwrap();
        std::fs::write(&key_file, &key_pem).unwrap();

        let server_config = load_server_config(
            &cert_file,
            &key_file,
            &[],
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        )
        .unwrap();
        let acceptor_mgr = TlsAcceptorManager::new(server_config);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let config = DohConfig::new(actual_addr, Some(acceptor_mgr));

        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            let qname = query.queries[0].name().clone();
            resp.answers.push(Record::from_rdata(
                qname,
                300,
                RData::A(A(std::net::Ipv4Addr::new(5, 5, 5, 5))),
            ));
            Some(resp)
        });

        let _handle = start_doh_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let root_cert = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(root_cert)
            .build()
            .unwrap();

        let mut query = Message::new(7001, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("doh-tls.example.com.").unwrap(),
            RecordType::A,
        ));
        let wire_query = encode_message(&query).unwrap();

        let resp = client
            .post(format!("https://localhost:{port}/dns-query"))
            .header("Content-Type", "application/dns-message")
            .body(wire_query)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/dns-message"
        );
        let body = resp.bytes().await.unwrap();
        let dns_resp = decode_message(&body).unwrap();
        assert_eq!(dns_resp.metadata.id, 7001);

        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
