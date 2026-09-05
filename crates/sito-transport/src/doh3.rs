//! RFC 9250 / RFC 9114 compliant DNS over HTTP/3 (DoH3) listener.
//!
//! Provides a dedicated HTTP/3 over QUIC listener on 443/udp (or configured port),
//! supporting both POST and GET (?dns=) methods, path-based ClientID routing
//! (`/dns-query` and `/dns-query/{client_id}`), and per-IP rate limiting.

use bytes::{Buf, Bytes};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, info, trace, warn};

use sito_core::client::ClientContext;
use sito_proto::{decode_message, encode_message};

use crate::handler::QueryHandler;
use crate::limiter::RateLimiter;
use crate::tls::TlsAcceptorManager;

/// Configuration options for the DoH3 listener.
#[derive(Clone)]
pub struct Doh3Config {
    pub bind_addr: SocketAddr,
    pub acceptor_mgr: Option<TlsAcceptorManager>,
    pub server_config: Option<rustls::ServerConfig>,
    pub max_connections: usize,
    pub rate_limit_per_ip: u32,
    pub idle_timeout: Duration,
}

impl Doh3Config {
    pub fn new(bind_addr: SocketAddr, acceptor_mgr: Option<TlsAcceptorManager>) -> Self {
        Self {
            bind_addr,
            acceptor_mgr,
            server_config: None,
            max_connections: 256,
            rate_limit_per_ip: 20,
            idle_timeout: Duration::from_secs(30),
        }
    }

    #[must_use]
    pub fn with_server_config(mut self, server_config: rustls::ServerConfig) -> Self {
        self.server_config = Some(server_config);
        self
    }
}

/// Builds a `quinn::ServerConfig` from a `rustls::ServerConfig` configured for HTTP/3.
pub fn build_quinn_h3_server_config(
    mut rustls_cfg: rustls::ServerConfig,
    idle_timeout: Duration,
) -> Result<quinn::ServerConfig, String> {
    // RFC 9114: ALPN MUST include "h3"
    rustls_cfg.alpn_protocols = vec![b"h3".to_vec()];
    // Plan 5.5: 0-RTT strictly disabled
    rustls_cfg.max_early_data_size = 0;

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(rustls_cfg))
        .map_err(|e| format!("Failed to create QUIC crypto server config for H3: {e}"))?;

    let mut quinn_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport_cfg = quinn::TransportConfig::default();
    let timeout = quinn::IdleTimeout::try_from(idle_timeout)
        .map_err(|e| format!("Invalid idle timeout: {e}"))?;
    transport_cfg.max_idle_timeout(Some(timeout));
    transport_cfg.max_concurrent_bidi_streams(100u32.into());
    transport_cfg.max_concurrent_uni_streams(100u32.into());

    quinn_cfg.transport_config(Arc::new(transport_cfg));

    Ok(quinn_cfg)
}

fn decode_base64url(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
}

/// Start the DNS over HTTP/3 (DoH3) listener.
pub async fn start_doh3_listener<H: QueryHandler + 'static>(
    config: Doh3Config,
    handler: Arc<H>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let rustls_cfg = if let Some(ref custom_cfg) = config.server_config {
        custom_cfg.clone()
    } else if let Some(ref mgr) = config.acceptor_mgr {
        mgr.current_config().as_ref().clone()
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DoH3 listener requires TLS configuration (acceptor_mgr or server_config)",
        ));
    };

    let quinn_cfg = build_quinn_h3_server_config(rustls_cfg, config.idle_timeout)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let endpoint = quinn::Endpoint::server(quinn_cfg, config.bind_addr)?;
    let local_addr = endpoint.local_addr()?;
    info!("DoH3 listener started on {}", local_addr);

    let rate_limiter = Arc::new(RateLimiter::new(
        config.rate_limit_per_ip,
        config.rate_limit_per_ip * 2,
    ));
    rate_limiter.spawn_pruner(shutdown_rx.clone());
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let acceptor_mgr = config.acceptor_mgr.clone();

    let endpoint_accept = endpoint.clone();
    let mut accept_shutdown_rx = shutdown_rx.clone();

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = accept_shutdown_rx.changed() => {
                    if *accept_shutdown_rx.borrow() {
                        debug!("DoH3 listener stopping due to shutdown");
                        endpoint_accept.close(0u32.into(), b"Server shutdown");
                        break;
                    }
                }
                Some(incoming) = endpoint_accept.accept() => {
                    let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                        warn!(
                            "DoH3 max connections ({}) reached; rejecting incoming QUIC connection",
                            config.max_connections
                        );
                        incoming.refuse();
                        continue;
                    };

                    let handler = Arc::clone(&handler);
                    let rate_limiter = Arc::clone(&rate_limiter);

                    tokio::spawn(async move {
                        let _permit = permit;
                        let conn = match incoming.await {
                            Ok(c) => c,
                            Err(e) => {
                                debug!("DoH3 QUIC handshake failed: {}", e);
                                return;
                            }
                        };

                        let peer_addr = conn.remote_address();
                        let client_ip = peer_addr.ip();

                        if !rate_limiter.check(client_ip) {
                            debug!("DoH3 rate limit exceeded for client {}", client_ip);
                            conn.close(1u32.into(), b"Rate limit exceeded");
                            return;
                        }

                        let sni = conn.handshake_data().and_then(|any| {
                            any.downcast_ref::<quinn::crypto::rustls::HandshakeData>()
                                .and_then(|hd| hd.server_name.clone())
                        });

                        trace!("DoH3 QUIC connection established from {}", peer_addr);

                        let mut h3_conn = match h3::server::builder()
                            .build(h3_quinn::Connection::new(conn))
                            .await
                        {
                            Ok(c) => c,
                            Err(e) => {
                                debug!("DoH3 H3 connection setup failed from {}: {}", peer_addr, e);
                                return;
                            }
                        };

                        while let Ok(Some(resolver)) = h3_conn.accept().await {
                            let handler = Arc::clone(&handler);
                            let rate_limiter = Arc::clone(&rate_limiter);
                            let sni = sni.clone();

                            tokio::spawn(async move {
                                if !rate_limiter.check(client_ip) {
                                    debug!("DoH3 rate limit exceeded for client {}", client_ip);
                                    return;
                                }

                                let (req, mut stream) = match resolver.resolve_request().await {
                                    Ok(r) => r,
                                    Err(e) => {
                                        debug!("DoH3 failed resolving request from {}: {}", peer_addr, e);
                                        return;
                                    }
                                };

                                let path = req.uri().path();
                                let method = req.method().clone();

                                // Route: /dns-query or /dns-query/{client_id}
                                let client_id = if path == "/dns-query" {
                                    None
                                } else if let Some(stripped) = path.strip_prefix("/dns-query/") {
                                    let cid = stripped.trim_matches('/');
                                    if cid.is_empty() {
                                        None
                                    } else {
                                        Some(cid.to_string())
                                    }
                                } else {
                                    let resp = http::Response::builder()
                                        .status(http::StatusCode::NOT_FOUND)
                                        .body(())
                                        .unwrap();
                                    let _ = stream.send_response(resp).await;
                                    let _ = stream.finish().await;
                                    return;
                                };

                                let wire_bytes = match method {
                                    http::Method::POST => {
                                        let is_dns_message = req
                                            .headers()
                                            .get(http::header::CONTENT_TYPE)
                                            .and_then(|v| v.to_str().ok())
                                            .is_some_and(|ct| {
                                                ct.split(';')
                                                    .next()
                                                    .unwrap_or("")
                                                    .trim()
                                                    .eq_ignore_ascii_case("application/dns-message")
                                            });

                                        if !is_dns_message {
                                            let resp = http::Response::builder()
                                                .status(http::StatusCode::UNSUPPORTED_MEDIA_TYPE)
                                                .body(())
                                                .unwrap();
                                            let _ = stream.send_response(resp).await;
                                            let _ = stream.finish().await;
                                            return;
                                        }

                                        let mut body_bytes = Vec::new();
                                        while let Ok(Some(mut chunk)) = stream.recv_data().await {
                                            let remaining = chunk.remaining();
                                            let mut chunk_buf = vec![0u8; remaining];
                                            chunk.copy_to_slice(&mut chunk_buf);
                                            body_bytes.extend_from_slice(&chunk_buf);
                                        }

                                        if body_bytes.is_empty() {
                                            let resp = http::Response::builder()
                                                .status(http::StatusCode::BAD_REQUEST)
                                                .body(())
                                                .unwrap();
                                            let _ = stream.send_response(resp).await;
                                            let _ = stream.finish().await;
                                            return;
                                        }
                                        body_bytes
                                    }
                                    http::Method::GET => {
                                        let query_str = req.uri().query().unwrap_or("");
                                        let mut dns_param = None;
                                        for pair in query_str.split('&') {
                                            if let Some((k, v)) = pair.split_once('=')
                                                && k == "dns" {
                                                    dns_param = Some(v);
                                                    break;
                                                }
                                        }

                                        let Some(param) = dns_param else {
                                            let resp = http::Response::builder()
                                                .status(http::StatusCode::BAD_REQUEST)
                                                .body(())
                                                .unwrap();
                                            let _ = stream.send_response(resp).await;
                                            let _ = stream.finish().await;
                                            return;
                                        };

                                        let Ok(b) = decode_base64url(param) else {
                                            let resp = http::Response::builder()
                                                .status(http::StatusCode::BAD_REQUEST)
                                                .body(())
                                                .unwrap();
                                            let _ = stream.send_response(resp).await;
                                            let _ = stream.finish().await;
                                            return;
                                        };
                                        b
                                    }
                                    _ => {
                                        let resp = http::Response::builder()
                                            .status(http::StatusCode::METHOD_NOT_ALLOWED)
                                            .body(())
                                            .unwrap();
                                        let _ = stream.send_response(resp).await;
                                        let _ = stream.finish().await;
                                        return;
                                    }
                                };

                                let query = match decode_message(&wire_bytes) {
                                    Ok(q) => q,
                                    Err(e) => {
                                        debug!("DoH3 invalid DNS message from {}: {}", peer_addr, e);
                                        let resp = http::Response::builder()
                                            .status(http::StatusCode::BAD_REQUEST)
                                            .body(())
                                            .unwrap();
                                        let _ = stream.send_response(resp).await;
                                        let _ = stream.finish().await;
                                        return;
                                    }
                                };

                                let mut client_ctx = match (client_id, sni) {
                                    (Some(cid), Some(ref s)) => {
                                        let mut ctx = ClientContext::with_id(client_ip, cid);
                                        ctx.sni = Some(s.clone());
                                        ctx
                                    }
                                    (Some(cid), None) => ClientContext::with_id(client_ip, cid),
                                    (None, Some(ref s)) => ClientContext::with_sni(client_ip, s),
                                    (None, None) => ClientContext::new(client_ip),
                                };
                                client_ctx.proto = "doh3".to_string();

                                let response = handler.handle(query, client_ctx).await;

                                if let Some(resp) = response
                                    && let Ok(encoded) = encode_message(&resp) {
                                        let http_resp = http::Response::builder()
                                            .status(http::StatusCode::OK)
                                            .header(http::header::CONTENT_TYPE, "application/dns-message")
                                            .header(http::header::CACHE_CONTROL, "no-store")
                                            .body(())
                                            .unwrap();

                                        if stream.send_response(http_resp).await.is_ok() {
                                            let _ = stream.send_data(Bytes::from(encoded)).await;
                                            let _ = stream.finish().await;
                                        }
                                        return;
                                    }

                                let no_content = http::Response::builder()
                                    .status(http::StatusCode::NO_CONTENT)
                                    .body(())
                                    .unwrap();
                                let _ = stream.send_response(no_content).await;
                                let _ = stream.finish().await;
                            });
                        }
                    });
                }
            }
        }
    });

    // Cert reload watcher
    if let Some(mgr) = acceptor_mgr {
        let idle_timeout = config.idle_timeout;

        tokio::spawn(async move {
            let mut last_config = mgr.current_config();
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    () = tokio::time::sleep(Duration::from_millis(500)) => {
                        let current = mgr.current_config();
                        if !Arc::ptr_eq(&last_config, &current) {
                            debug!("DoH3 detected reloaded TLS configuration, updating QUIC endpoint");
                            if let Ok(new_quinn_cfg) = build_quinn_h3_server_config(current.as_ref().clone(), idle_timeout) {
                                endpoint.set_server_config(Some(new_quinn_cfg));
                            }
                            last_config = current;
                        }
                    }
                }
            }
        });
    }

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::generate_test_cert;
    use base64::Engine;
    use sito_proto::rdata::A;
    use sito_proto::{
        Message, MessageType, Name, OpCode, Query, RData, Record, RecordType, ResponseCode,
        decode_message, encode_message,
    };
    use std::str::FromStr;
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_doh3_post_and_get() {
        let temp_dir = std::env::temp_dir().join(format!("sito_doh3_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");

        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);
        std::fs::write(&cert_file, cert_pem).unwrap();
        std::fs::write(&key_file, key_pem).unwrap();

        let server_config =
            crate::tls::load_server_config(&cert_file, &key_file, &[], vec![b"h3".to_vec()])
                .unwrap();
        let acceptor_mgr = TlsAcceptorManager::new(server_config);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let config = Doh3Config::new(actual_addr, Some(acceptor_mgr));

        let handler = Arc::new(|query: Message, client: ClientContext| async move {
            assert_eq!(client.proto, "doh3");
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            let qname = query.queries[0].name().clone();
            resp.answers.push(Record::from_rdata(
                qname,
                300,
                RData::A(A(std::net::Ipv4Addr::new(3, 3, 3, 3))),
            ));
            Some(resp)
        });

        let listener_handle = start_doh3_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut root_store = rustls::RootCertStore::empty();
        let certs = crate::tls::load_certificates(&cert_file).unwrap();
        for c in certs {
            root_store.add(c).unwrap();
        }

        let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];

        let quic_client_crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_tls)).unwrap();
        let client_config = quinn::ClientConfig::new(Arc::new(quic_client_crypto));
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);

        let conn = client_endpoint
            .connect(actual_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let quinn_conn = h3_quinn::Connection::new(conn);
        let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        // 1. POST query to /dns-query
        let mut query = Message::new(8001, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("doh3.example.com.").unwrap(),
            RecordType::A,
        ));
        let wire_query = encode_message(&query).unwrap();

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost/dns-query")
            .header(http::header::CONTENT_TYPE, "application/dns-message")
            .header(http::header::ACCEPT, "application/dns-message")
            .body(())
            .unwrap();

        let mut stream = send_request.send_request(req).await.unwrap();
        stream.send_data(wire_query.clone().into()).await.unwrap();
        stream.finish().await.unwrap();

        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "application/dns-message"
        );

        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }

        let dns_resp = decode_message(&body).unwrap();
        assert_eq!(dns_resp.metadata.id, 8001);
        assert_eq!(
            dns_resp.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(3, 3, 3, 3)))
        );

        // 2. GET query to /dns-query?dns=<base64url>
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&wire_query);
        let req_get = http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("https://localhost/dns-query?dns={b64}"))
            .header(http::header::ACCEPT, "application/dns-message")
            .body(())
            .unwrap();

        let mut get_stream = send_request.send_request(req_get).await.unwrap();
        get_stream.finish().await.unwrap();

        let get_resp = get_stream.recv_response().await.unwrap();
        assert_eq!(get_resp.status(), http::StatusCode::OK);

        let mut get_body = Vec::new();
        while let Some(mut chunk) = get_stream.recv_data().await.unwrap() {
            get_body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }
        let get_dns_resp = decode_message(&get_body).unwrap();
        assert_eq!(get_dns_resp.metadata.id, 8001);

        drop(send_request);
        driver_task.abort();
        let _ = shutdown_tx.send(true);
        let _ = listener_handle.await;
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
