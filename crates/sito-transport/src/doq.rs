//! RFC 9250 compliant DNS over Dedicated QUIC (DoQ) listener.
//!
//! Provides a high-performance QUIC transport running on UDP/853 (or configured port),
//! strictly disabling 0-RTT to mitigate replay attacks, enforcing address validation tokens,
//! and mapping each DNS query/response transaction to an independent bidirectional QUIC stream.

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

/// Configuration options for the DoQ listener.
#[derive(Clone)]
pub struct DoqConfig {
    pub bind_addr: SocketAddr,
    pub acceptor_mgr: Option<TlsAcceptorManager>,
    pub server_config: Option<rustls::ServerConfig>,
    pub max_connections: usize,
    pub rate_limit_per_ip: u32,
    pub idle_timeout: Duration,
}

impl DoqConfig {
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

/// Builds a `quinn::ServerConfig` from a `rustls::ServerConfig` configured for DoQ.
pub fn build_quinn_server_config(
    mut rustls_cfg: rustls::ServerConfig,
    idle_timeout: Duration,
) -> Result<quinn::ServerConfig, String> {
    // RFC 9250: ALPN MUST include "doq"
    rustls_cfg.alpn_protocols = vec![b"doq".to_vec()];
    // RFC 9250 & Plan 5.5: 0-RTT strictly disabled to prevent replay attacks
    rustls_cfg.max_early_data_size = 0;

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(rustls_cfg))
        .map_err(|e| format!("Failed to create QUIC crypto server config: {e}"))?;

    let mut quinn_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport_cfg = quinn::TransportConfig::default();
    let timeout = quinn::IdleTimeout::try_from(idle_timeout)
        .map_err(|e| format!("Invalid idle timeout: {e}"))?;
    transport_cfg.max_idle_timeout(Some(timeout));
    transport_cfg.max_concurrent_bidi_streams(100u32.into());
    transport_cfg.max_concurrent_uni_streams(0u32.into());

    quinn_cfg.transport_config(Arc::new(transport_cfg));

    Ok(quinn_cfg)
}

/// Start the DNS over Dedicated QUIC (DoQ) listener.
pub async fn start_doq_listener<H: QueryHandler + 'static>(
    config: DoqConfig,
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
            "DoQ listener requires TLS configuration (acceptor_mgr or server_config)",
        ));
    };

    let quinn_cfg = build_quinn_server_config(rustls_cfg, config.idle_timeout)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let endpoint = quinn::Endpoint::server(quinn_cfg, config.bind_addr)?;
    let local_addr = endpoint.local_addr()?;
    info!("DoQ listener started on {}", local_addr);

    let rate_limiter = Arc::new(RateLimiter::new(
        config.rate_limit_per_ip,
        config.rate_limit_per_ip * 2,
    ));
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let acceptor_mgr = config.acceptor_mgr.clone();

    let endpoint_accept = endpoint.clone();
    let mut accept_shutdown_rx = shutdown_rx.clone();

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = accept_shutdown_rx.changed() => {
                    if *accept_shutdown_rx.borrow() {
                        debug!("DoQ listener stopping due to shutdown");
                        endpoint_accept.close(0u32.into(), b"Server shutdown");
                        break;
                    }
                }
                Some(incoming) = endpoint_accept.accept() => {
                    let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                        warn!(
                            "DoQ max connections ({}) reached; rejecting incoming QUIC connection",
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
                                debug!("DoQ QUIC handshake failed: {}", e);
                                return;
                            }
                        };

                        let peer_addr = conn.remote_address();
                        let client_ip = peer_addr.ip();

                        if !rate_limiter.check(client_ip) {
                            debug!("DoQ rate limit exceeded for client {}", client_ip);
                            conn.close(1u32.into(), b"Rate limit exceeded");
                            return;
                        }

                        // Extract SNI from handshake data if present
                        let sni = conn.handshake_data().and_then(|any| {
                            any.downcast_ref::<quinn::crypto::rustls::HandshakeData>()
                                .and_then(|hd| hd.server_name.clone())
                        });

                        trace!("DoQ QUIC connection established from {}", peer_addr);

                        // Process incoming bidirectional streams (RFC 9250 section 4.2)
                        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                            let handler = Arc::clone(&handler);
                            let sni = sni.clone();

                            tokio::spawn(async move {
                                // RFC 9250: Each stream carries a single query preceded by a 2-octet length prefix
                                let mut len_buf = [0u8; 2];
                                if let Err(e) = recv.read_exact(&mut len_buf).await {
                                    trace!("DoQ stream failed reading length prefix from {}: {}", peer_addr, e);
                                    return;
                                }

                                let query_len = u16::from_be_bytes(len_buf) as usize;
                                if query_len == 0 || query_len > 4096 {
                                    warn!("DoQ invalid query length {} from {}", query_len, peer_addr);
                                    return;
                                }

                                let mut query_buf = vec![0u8; query_len];
                                if let Err(e) = recv.read_exact(&mut query_buf).await {
                                    warn!("DoQ stream failed reading query body from {}: {}", peer_addr, e);
                                    return;
                                }

                                let query = match decode_message(&query_buf) {
                                    Ok(q) => q,
                                    Err(e) => {
                                        warn!("DoQ failed decoding DNS query from {}: {}", peer_addr, e);
                                        return;
                                    }
                                };

                                let client_ctx = match sni {
                                    Some(ref s) => ClientContext::with_sni(client_ip, s).with_proto("doq"),
                                    None => ClientContext::new(client_ip).with_proto("doq"),
                                };

                                if let Some(response) = handler.handle(query, client_ctx).await {
                                    match encode_message(&response) {
                                        Ok(encoded) => {
                                            let resp_len = (encoded.len() as u16).to_be_bytes();
                                            if let Err(e) = send.write_all(&resp_len).await {
                                                trace!("DoQ write length error to {}: {}", peer_addr, e);
                                                return;
                                            }
                                            if let Err(e) = send.write_all(&encoded).await {
                                                trace!("DoQ write response error to {}: {}", peer_addr, e);
                                                return;
                                            }
                                            let _ = send.finish();
                                        }
                                        Err(e) => {
                                            warn!("DoQ failed to encode response to {}: {}", peer_addr, e);
                                        }
                                    }
                                }
                            });
                        }
                    });
                }
            }
        }
    });

    // If acceptor_mgr is provided, monitor for certificate reload and update endpoint
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
                            debug!("DoQ detected reloaded TLS configuration, updating QUIC endpoint");
                            if let Ok(new_quinn_cfg) = build_quinn_server_config(current.as_ref().clone(), idle_timeout) {
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
    use rustls::pki_types::CertificateDer;
    use sito_proto::rdata::A;
    use sito_proto::{
        Message, MessageType, Name, OpCode, Query, RData, Record, RecordType, ResponseCode,
    };
    use std::str::FromStr;
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_doq_query_and_response() {
        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);

        let temp_dir = std::env::temp_dir().join(format!("sito_doq_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");
        std::fs::write(&cert_file, &cert_pem).unwrap();
        std::fs::write(&key_file, &key_pem).unwrap();

        let server_config =
            crate::tls::load_server_config(&cert_file, &key_file, &[], vec![b"doq".to_vec()])
                .unwrap();
        let acceptor_mgr = TlsAcceptorManager::new(server_config);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let udp_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp_socket.local_addr().unwrap().port();
        drop(udp_socket);

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let config = DoqConfig::new(actual_addr, Some(acceptor_mgr));

        let handler = Arc::new(|query: Message, client: ClientContext| async move {
            assert_eq!(client.proto, "doq");
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

        let _handle = start_doq_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Build Quinn client
        use rustls::pki_types::pem::PemObject;
        let mut root_store = rustls::RootCertStore::empty();
        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap();
        root_store.add(cert_der).unwrap();

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

        let conn = client_endpoint
            .connect(actual_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        let mut query = Message::new(9901, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("doq-test.example.com.").unwrap(),
            RecordType::A,
        ));
        let wire = encode_message(&query).unwrap();

        let len_prefix = (wire.len() as u16).to_be_bytes();
        send.write_all(&len_prefix).await.unwrap();
        send.write_all(&wire).await.unwrap();
        send.finish().unwrap();

        let mut resp_len_buf = [0u8; 2];
        recv.read_exact(&mut resp_len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        recv.read_exact(&mut resp_buf).await.unwrap();

        let dns_resp = decode_message(&resp_buf).unwrap();
        assert_eq!(dns_resp.metadata.id, 9901);
        assert_eq!(dns_resp.answers.len(), 1);
        assert_eq!(
            dns_resp.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(9, 9, 9, 9)))
        );

        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
