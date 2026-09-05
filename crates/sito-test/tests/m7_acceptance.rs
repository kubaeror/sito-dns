//! Acceptance tests for Phase M7: DoQ, DoH3, Anti-Bypass, ACME, and DNSCrypt.

#![allow(clippy::pedantic)]

use bytes::{Buf, Bytes};
use http::header;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use tokio::sync::watch;

use sito_cache::DnsCache;
use sito_clients::{
    ClientEntryConfig, ClientRegistry, ClientsConfig, ParentalRegistry, ServiceRegistry,
};
use sito_core::client::ClientContext;
use sito_core::config::Config;
use sito_dnssec::DnssecValidator;
use sito_filter::{AntiBypassRegistry, HostsFilterEngine};
use sito_proto::rdata::A;
use sito_proto::{
    Message, MessageType, Name, OpCode, Query, RData, Record, RecordType, ResponseCode,
    decode_message, encode_message,
};
use sito_rewrites::RewriteTable;
use sito_stats::{MetricsRegistry, QueryLogWriter, StatsDb};
use sito_transport::{
    Doh3Config, DohConfig, DoqConfig, QueryHandler, TlsAcceptorManager, build_quinn_server_config,
    days_until_expiration, generate_self_signed_cert, generate_tls_alpn_01_cert, load_certificates,
    load_server_config, load_server_config_with_challenges, start_doh_listener,
    start_doh3_listener, start_doq_listener,
};
use sito_upstream::{BootstrapResolver, UpstreamManager};

fn create_mock_tls_pair(domain: &str) -> (String, String) {
    generate_self_signed_cert(&[domain.to_string()]).expect("generate self-signed cert")
}

#[tokio::test]
async fn test_m7_doq_query_and_early_data_disabled() {
    let (cert_pem, key_pem) = create_mock_tls_pair("localhost");
    let temp_dir = std::env::temp_dir().join(format!("sito_doq_test_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let cert_path = temp_dir.join("cert.pem");
    let key_path = temp_dir.join("key.pem");
    tokio::fs::write(&cert_path, &cert_pem).await.unwrap();
    tokio::fs::write(&key_path, &key_pem).await.unwrap();

    let server_cfg = load_server_config(&cert_path, &key_path, &[], vec![b"doq".to_vec()])
        .expect("load server config");

    // Verify RFC 9250 & Section 5.5: 0-RTT strictly disabled
    let _quinn_server_cfg = build_quinn_server_config(server_cfg.clone(), Duration::from_secs(30))
        .expect("build quinn server config");
    assert_eq!(
        server_cfg.max_early_data_size, 0,
        "0-RTT early data must be disabled"
    );

    let acceptor_mgr = TlsAcceptorManager::new(server_cfg);

    let udp_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp_socket.local_addr().unwrap().port();
    drop(udp_socket);

    let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
    let doq_config = DoqConfig::new(actual_addr, Some(acceptor_mgr));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handler = Arc::new(|query: Message, client: ClientContext| async move {
        assert_eq!(client.proto, "doq", "Protocol metric label must be doq");
        let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
        resp.queries = query.queries.clone();
        resp.metadata.response_code = ResponseCode::NoError;
        resp.answers.push(Record::from_rdata(
            query.queries[0].name().clone(),
            300,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        ));
        Some(resp)
    });

    let _server_handle = start_doq_listener(doq_config, handler, shutdown_rx)
        .await
        .expect("start doq listener");

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Build QUIC client trusting our test cert
    let mut root_store = rustls::RootCertStore::empty();
    let certs = load_certificates(&cert_path).unwrap();
    for c in certs {
        root_store.add(c).unwrap();
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"doq".to_vec()];

    let quic_client_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_tls)).unwrap();
    let client_cfg = quinn::ClientConfig::new(Arc::new(quic_client_crypto));

    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_cfg);

    let connection = client_endpoint
        .connect(actual_addr, "localhost")
        .unwrap()
        .await
        .expect("quic connect");

    // Open bidirectional stream per RFC 9250
    let (mut send, mut recv) = connection.open_bi().await.unwrap();

    let mut query = Message::new(42, MessageType::Query, OpCode::Query);
    query.queries.push(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::A,
    ));
    let wire = encode_message(&query).unwrap();

    let len = wire.len() as u16;
    send.write_all(&len.to_be_bytes()).await.unwrap();
    send.write_all(&wire).await.unwrap();
    send.finish().unwrap();

    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    recv.read_exact(&mut resp_buf).await.unwrap();

    let decoded = decode_message(&resp_buf).unwrap();
    assert_eq!(decoded.metadata.id, 42);
    assert_eq!(decoded.metadata.response_code, ResponseCode::NoError);
    assert_eq!(decoded.answers.len(), 1);

    let _ = shutdown_tx.send(true);
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_m7_doh3_post_and_get_queries() {
    let (cert_pem, key_pem) = create_mock_tls_pair("localhost");
    let temp_dir = std::env::temp_dir().join(format!("sito_doh3_test_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let cert_path = temp_dir.join("cert.pem");
    let key_path = temp_dir.join("key.pem");
    tokio::fs::write(&cert_path, &cert_pem).await.unwrap();
    tokio::fs::write(&key_path, &key_pem).await.unwrap();

    let server_cfg = load_server_config(&cert_path, &key_path, &[], vec![b"h3".to_vec()])
        .expect("load server config");
    let acceptor_mgr = TlsAcceptorManager::new(server_cfg);

    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let bound_addr = SocketAddr::from(([127, 0, 0, 1], port));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let doh3_cfg = Doh3Config::new(bound_addr, Some(acceptor_mgr));

    let handler = Arc::new(|query: Message, client: ClientContext| async move {
        assert_eq!(client.proto, "doh3", "Protocol metric label must be doh3");
        let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
        resp.queries = query.queries.clone();
        resp.metadata.response_code = ResponseCode::NoError;
        let qname = query.queries[0].name().clone();
        resp.answers.push(Record::from_rdata(
            qname,
            300,
            RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
        ));
        Some(resp)
    });

    let _h = start_doh3_listener(doh3_cfg, handler, shutdown_rx)
        .await
        .expect("start doh3 listener");

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut root_store = rustls::RootCertStore::empty();
    let certs = load_certificates(&cert_path).unwrap();
    for c in certs {
        root_store.add(c).unwrap();
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic_client_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_tls)).unwrap();
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint
        .set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_crypto)));

    let quic_conn = client_endpoint
        .connect(bound_addr, "localhost")
        .unwrap()
        .await
        .expect("h3 connect");

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(quic_conn))
        .await
        .unwrap();

    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    // Test POST /dns-query
    let mut query = Message::new(1234, MessageType::Query, OpCode::Query);
    query.queries.push(Query::query(
        Name::from_str("h3test.example.").unwrap(),
        RecordType::A,
    ));
    let wire = encode_message(&query).unwrap();

    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://localhost/dns-query")
        .header(header::CONTENT_TYPE, "application/dns-message")
        .header(header::ACCEPT, "application/dns-message")
        .body(())
        .unwrap();

    let mut stream = send_request.send_request(req).await.unwrap();
    stream.send_data(Bytes::from(wire)).await.unwrap();
    stream.finish().await.unwrap();

    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);

    let mut body_bytes = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let slice = chunk.chunk();
            body_bytes.extend_from_slice(slice);
            let len = slice.len();
            chunk.advance(len);
        }
    }
    let decoded = decode_message(&body_bytes).unwrap();
    assert_eq!(decoded.metadata.id, 1234);
    assert_eq!(decoded.answers.len(), 1);

    // Test GET /dns-query?dns=...
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&body_bytes);
    let get_uri = format!("https://localhost/dns-query?dns={b64}");
    let get_req = http::Request::builder()
        .method(http::Method::GET)
        .uri(&get_uri)
        .header(header::ACCEPT, "application/dns-message")
        .body(())
        .unwrap();

    let mut get_stream = send_request.send_request(get_req).await.unwrap();
    get_stream.finish().await.unwrap();
    let get_resp = get_stream.recv_response().await.unwrap();
    assert_eq!(get_resp.status(), http::StatusCode::OK);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_m7_doh_alt_svc_header_advertisement() {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    drop(listener);

    let doh_config = DohConfig::new(local_addr, None).with_alt_svc_port(Some(443));

    let handler = Arc::new(|query: Message, _client: ClientContext| async move {
        let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
        resp.metadata.response_code = ResponseCode::NoError;
        Some(resp)
    });

    let _handle = start_doh_listener(doh_config, handler, shutdown_rx)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = reqwest::Client::new();
    let mut query = Message::new(101, MessageType::Query, OpCode::Query);
    query.queries.push(Query::query(
        Name::from_str("altsvc.test.").unwrap(),
        RecordType::A,
    ));
    let wire = encode_message(&query).unwrap();

    let resp = client
        .post(format!("http://{local_addr}/dns-query"))
        .header("Content-Type", "application/dns-message")
        .body(wire)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let alt_svc = resp
        .headers()
        .get("alt-svc")
        .expect("Alt-Svc header must be present");
    assert_eq!(alt_svc.to_str().unwrap(), "h3=\":443\"; ma=86400");
}

#[tokio::test]
async fn test_m7_anti_doh_bypass_filter_and_pipeline() {
    let registry = AntiBypassRegistry::bundled();
    assert!(
        registry.domain_count() > 0,
        "Bundled resolvers must not be empty"
    );

    // Verify known resolvers are detected
    assert!(registry.matches_domain("cloudflare-dns.com"));
    assert!(registry.matches_domain("1dot1dot1dot1.cloudflare-dns.com"));
    assert!(registry.matches_domain("dns.google"));
    assert!(registry.matches_domain("dns.quad9.net"));
    assert!(registry.matches_domain("doh.cleanbrowsing.org"));
    assert!(registry.matches_ip(&"1.1.1.1".parse().unwrap()));
    assert!(registry.matches_ip(&"8.8.8.8".parse().unwrap()));
    assert!(registry.matches_ip(&"9.9.9.9".parse().unwrap()));
    assert!(!registry.matches_domain("example.com"));
    assert!(!registry.matches_domain("myinternal.local"));

    // Pipeline test with AntiDohBypassMode
    let temp_dir = std::env::temp_dir().join(format!("sito_m7_bypass_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let db_path = temp_dir.join("stats.db");
    let stats_db = StatsDb::open(&db_path).await.unwrap();
    let querylog_writer = QueryLogWriter::spawn(stats_db, 100);
    let metrics = MetricsRegistry::new("0.1.0", "test");

    let filter_engine =
        Arc::new(HostsFilterEngine::init(Default::default(), temp_dir.clone()).await);
    let cache = Arc::new(DnsCache::new(Default::default()));
    let bootstrap =
        BootstrapResolver::new(vec!["127.0.0.1".parse().unwrap()], Duration::from_secs(1));
    let upstream = Arc::new(
        UpstreamManager::from_config(&Default::default(), &bootstrap)
            .await
            .unwrap(),
    );
    let dnssec = Arc::new(DnssecValidator::from_config(&Default::default()));

    let mut clients_cfg = ClientsConfig::default();
    let trusted_ip: IpAddr = "192.168.1.50".parse().unwrap();
    clients_cfg.entries.push(ClientEntryConfig {
        name: "Trusted Laptop".to_string(),
        ids: vec!["192.168.1.50".to_string()],
        group: "default".to_string(),
        ignore_query_log: false,
        ignore_stats: false,
        use_global_upstreams: true,
        upstreams: None,
        trusted: true,
    });
    let client_registry = Arc::new(ClientRegistry::new(clients_cfg));
    let parental = Arc::new(ParentalRegistry::bundled());
    let service = Arc::new(ServiceRegistry::bundled());
    let rewrites = Arc::new(RewriteTable::new(Default::default()));
    let in_flight = Arc::new(AtomicUsize::new(0));

    // Test Mode: block_all
    let mut config_block_all = Config::default();
    config_block_all.filtering.anti_doh_bypass = "block_all".to_string();

    let pipeline = Arc::new(
        sito::pipeline::DnsPipeline::new(
            Arc::new(config_block_all),
            filter_engine.clone(),
            cache.clone(),
            upstream.clone(),
            dnssec.clone(),
            client_registry.clone(),
            parental.clone(),
            service.clone(),
            rewrites.clone(),
            in_flight.clone(),
        )
        .with_stats(querylog_writer.sender(), metrics.clone()),
    );

    let untrusted_client = ClientContext::new("192.168.1.100".parse().unwrap());

    let mut query = Message::new(1, MessageType::Query, OpCode::Query);
    query.queries.push(Query::query(
        Name::from_str("cloudflare-dns.com.").unwrap(),
        RecordType::A,
    ));

    let resp = pipeline
        .handle(query.clone(), untrusted_client.clone())
        .await
        .unwrap();
    // Blocked with anti-DoH bypass response (0.0.0.0)
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1);
    match &resp.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(0, 0, 0, 0)),
        _ => panic!("Expected 0.0.0.0 block record"),
    }

    // Test Mode: block_except_trusted
    let mut config_trusted_only = Config::default();
    config_trusted_only.filtering.anti_doh_bypass = "block_except_trusted".to_string();

    let pipeline_trusted = Arc::new(
        sito::pipeline::DnsPipeline::new(
            Arc::new(config_trusted_only),
            filter_engine.clone(),
            cache.clone(),
            upstream.clone(),
            dnssec.clone(),
            client_registry.clone(),
            parental.clone(),
            service.clone(),
            rewrites.clone(),
            in_flight.clone(),
        )
        .with_stats(querylog_writer.sender(), metrics.clone()),
    );

    // Untrusted client must still be blocked
    let resp_untrusted = pipeline_trusted
        .handle(query.clone(), untrusted_client)
        .await
        .unwrap();
    assert_eq!(resp_untrusted.answers.len(), 1);
    match &resp_untrusted.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(0, 0, 0, 0)),
        _ => panic!("Expected 0.0.0.0 block record"),
    }

    // Trusted client context
    let trusted_client_ctx = ClientContext::new(trusted_ip);
    let resp_trusted = pipeline_trusted
        .handle(query.clone(), trusted_client_ctx)
        .await
        .unwrap();
    // Not blocked by anti_doh_bypass (will return answer from cache/upstream or empty if mock upstream)
    for ans in &resp_trusted.answers {
        if let RData::A(a) = &ans.data {
            assert_ne!(
                a.0,
                Ipv4Addr::new(0, 0, 0, 0),
                "Trusted client must not be 0.0.0.0 sinkholed"
            );
        }
    }

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_m7_acme_certificate_management() {
    let (cert_pem, key_pem) = create_mock_tls_pair("example.com");

    // Test expiration calculation
    let days = days_until_expiration(cert_pem.as_bytes()).expect("calculate days until expiration");
    assert!(
        days >= 30,
        "Fresh certificate should have >= 30 days validity, got {days}"
    );

    // Test TLS-ALPN-01 challenge cert generation (RFC 8737)
    let key_auth = "token123.thumbprint456";
    let (challenge_cert, challenge_key) =
        generate_tls_alpn_01_cert("example.com", key_auth).expect("generate tls-alpn-01 cert");
    assert!(!challenge_cert.is_empty());

    // Test dynamic challenge registration on TlsAcceptorManager
    let temp_dir = std::env::temp_dir().join(format!("sito_m7_acme_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let cert_path = temp_dir.join("cert.pem");
    let key_path = temp_dir.join("key.pem");
    tokio::fs::write(&cert_path, &cert_pem).await.unwrap();
    tokio::fs::write(&key_path, &key_pem).await.unwrap();

    let challenges = Arc::new(dashmap::DashMap::new());
    let server_cfg = load_server_config_with_challenges(
        &cert_path,
        &key_path,
        &[],
        vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"acme-tls/1".to_vec()],
        challenges.clone(),
    )
    .unwrap();

    let mgr = TlsAcceptorManager::with_challenge_keys(server_cfg, challenges.clone());

    // Register challenge cert
    let certified_key =
        sito_transport::tls::create_certified_key(vec![challenge_cert], &challenge_key).unwrap();
    mgr.register_challenge("example.com", certified_key);

    assert!(challenges.contains_key("example.com"));
    mgr.unregister_challenge("example.com");
    assert!(!challenges.contains_key("example.com"));

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[test]
fn test_m7_dnscrypt_documentation_complete() {
    let doc_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("docs/dnscrypt.md");

    assert!(
        doc_path.exists(),
        "docs/dnscrypt.md must exist per ADR-0006"
    );
    let content = std::fs::read_to_string(&doc_path).expect("read docs/dnscrypt.md");
    assert!(content.contains("ADR-0006"), "Must reference ADR-0006");
    assert!(
        content.contains("dnscrypt-wrapper"),
        "Must explain dnscrypt-wrapper deployment"
    );
    assert!(
        content.contains("dnscrypt-proxy"),
        "Must explain dnscrypt-proxy deployment"
    );
    assert!(
        content.contains("XSalsa20-Poly1305") || content.contains("X25519"),
        "Must describe protocol cryptography"
    );
}
