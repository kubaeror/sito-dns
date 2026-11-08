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
use sito_proto::{decode_message, encode_message, truncate_for_framing};

use crate::handler::QueryHandler;
use crate::limiter::RateLimiter;
use crate::tcp::frame_prefix;
use crate::tls::TlsAcceptorManager;

/// Maximum DNS message size accepted over a DoQ stream (RFC 9250, 2-octet
/// length prefix; the DNS-over-TCP ceiling is 65535 bytes).
/// RFC 9250 §4.3 DoQ stream error codes used when abandoning a stream.
const DOQ_INTERNAL_ERROR: u32 = 1;
const DOQ_PROTOCOL_ERROR: u32 = 2;
const DOQ_EXCESSIVE_LOAD: u32 = 4;

/// Upper bound on handling a single QUIC stream: a client that opens a stream
/// and never completes the length prefix/body must not pin a task forever.
const STREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounded wait for the QUIC/TLS handshake. A connection slot must not be held
/// by a peer that never completes the handshake.
const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-stream QUIC flow-control window. A DoQ query is at most 65,537 bytes
/// (2-octet length prefix + DNS message), so 128 KiB is enough headroom while
/// making the old quinn default of 1.25 MiB per stream impossible.
pub(crate) const DOQ_STREAM_RECEIVE_WINDOW: u32 = 128 * 1024;

/// Per-connection QUIC flow-control window. With at most
/// [`DOQ_MAX_BIDI_STREAMS`] concurrent streams this bounds buffered query data
/// to the connection window instead of tens of GiB.
pub(crate) const DOQ_CONNECTION_RECEIVE_WINDOW: u32 = 2 * 1024 * 1024;

/// Maximum number of concurrent client-initiated bidirectional streams.
///
/// quinn's default is effectively unbounded (`VarInt::MAX`); 100 was still
/// enough for one connection to spawn tens of thousands of tasks across the
/// connection cap. Sixteen is ample for pipelined DNS queries.
pub(crate) const DOQ_MAX_BIDI_STREAMS: u32 = 16;

/// Global in-flight stream budget per DoQ endpoint, expressed as a multiple of
/// the connection cap. Acquired before a stream body is read.
const DOQ_STREAMS_PER_CONNECTION: usize = 4;

/// Configuration options for the DoQ listener.
#[derive(Clone)]
pub struct DoqConfig {
    pub bind_addr: SocketAddr,
    pub acceptor_mgr: Option<TlsAcceptorManager>,
    pub server_config: Option<rustls::ServerConfig>,
    pub max_connections: usize,
    pub rate_limit_per_ip: u32,
    /// Optional shared limiter; lets the server hot-reload the rate
    /// limit while keeping listener state. Built from `rate_limit_per_ip`
    /// when absent.
    pub rate_limiter: Option<Arc<RateLimiter>>,
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
            rate_limiter: None,
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
    transport_cfg.max_concurrent_bidi_streams(DOQ_MAX_BIDI_STREAMS.into());
    transport_cfg.max_concurrent_uni_streams(0u32.into());
    transport_cfg.stream_receive_window(quinn::VarInt::from_u32(DOQ_STREAM_RECEIVE_WINDOW));
    transport_cfg.receive_window(quinn::VarInt::from_u32(DOQ_CONNECTION_RECEIVE_WINDOW));

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

    let rate_limiter = config.rate_limiter.clone().unwrap_or_else(|| {
        Arc::new(RateLimiter::new(
            config.rate_limit_per_ip,
            RateLimiter::burst_for_rate(config.rate_limit_per_ip),
        ))
    });
    rate_limiter.spawn_pruner(shutdown_rx.clone());
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    // Global stream budget: bounds buffered query bodies/tasks even when a
    // client keeps every allowed connection open.
    let stream_semaphore = Arc::new(Semaphore::new(
        config
            .max_connections
            .saturating_mul(DOQ_STREAMS_PER_CONNECTION)
            .max(1),
    ));
    let per_ip_limiter = crate::admission::PerIpConnectionLimiter::new(
        crate::admission::DEFAULT_MAX_CONNECTIONS_PER_IP,
    );
    let acceptor_mgr = config.acceptor_mgr.clone();

    let endpoint_accept = endpoint.clone();
    let mut accept_shutdown_rx = shutdown_rx.clone();

    let handle = tokio::spawn(async move {
        let mut connection_tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                res = accept_shutdown_rx.changed() => {
                    if res.is_err() || *accept_shutdown_rx.borrow() {
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
                    let Some(per_ip_permit) = per_ip_limiter.try_acquire(incoming.remote_address().ip()) else {
                        warn!(
                            "DoQ per-IP connection limit ({}) reached; rejecting connection",
                            crate::admission::DEFAULT_MAX_CONNECTIONS_PER_IP
                        );
                        incoming.refuse();
                        continue;
                    };

                    let handler = Arc::clone(&handler);
                    let rate_limiter = Arc::clone(&rate_limiter);
                    let stream_semaphore = Arc::clone(&stream_semaphore);

                    connection_tasks.spawn(async move {
                        let _permit = permit;
                        let _per_ip_permit = per_ip_permit;
                        let conn = match tokio::time::timeout(QUIC_HANDSHAKE_TIMEOUT, incoming).await {
                            Ok(Ok(c)) => c,
                            Ok(Err(e)) => {
                                debug!("DoQ QUIC handshake failed: {}", e);
                                return;
                            }
                            Err(_) => {
                                debug!(
                                    "DoQ QUIC handshake timed out after {}s",
                                    QUIC_HANDSHAKE_TIMEOUT.as_secs()
                                );
                                return;
                            }
                        };

                        let peer_addr = conn.remote_address();
                        let client_ip = peer_addr.ip();

                        // Rate limiting is per query (stream) below; the
                        // connection cap already bounds connection setup.
                        // Extract SNI from handshake data if present
                        let sni = conn.handshake_data().and_then(|any| {
                            any.downcast_ref::<quinn::crypto::rustls::HandshakeData>()
                                .and_then(|hd| hd.server_name.clone())
                        });

                        trace!("DoQ QUIC connection established from {}", peer_addr);

                        // Process incoming bidirectional streams (RFC 9250 section 4.2)
                        let mut stream_tasks = tokio::task::JoinSet::new();
                        loop {
                            tokio::select! {
                                accept_res = conn.accept_bi() => {
                                    let Ok((send, recv)) = accept_res else {
                                        break;
                                    };
                            let Ok(stream_permit) = stream_semaphore.clone().try_acquire_owned() else {
                                warn!(
                                    "DoQ global stream limit reached; abandoning stream from {}",
                                    client_ip
                                );
                                let mut send = send;
                                let _ = send.reset(DOQ_EXCESSIVE_LOAD.into());
                                continue;
                            };

                            // Admit the query before reading any body data: a
                            // client must not force buffering by opening
                            // streams while over its rate budget.
                            if !rate_limiter.check(client_ip) {
                                debug!(
                                    "DoQ per-query rate limit exceeded for client {}",
                                    client_ip
                                );
                                let mut send = send;
                                let _ = send.reset(DOQ_EXCESSIVE_LOAD.into());
                                continue;
                            }

                            let handler = Arc::clone(&handler);
                            let sni = sni.clone();

                            stream_tasks.spawn(async move {
                              let _stream_permit = stream_permit;
                              let mut send = send;
                              let mut recv = recv;
                              let timed = tokio::time::timeout(
                                STREAM_TIMEOUT,
                                async {
                                // RFC 9250: Each stream carries a single query preceded by a 2-octet length prefix
                                let mut len_buf = [0u8; 2];
                                if let Err(e) = recv.read_exact(&mut len_buf).await {
                                    trace!("DoQ stream failed reading length prefix from {}: {}", peer_addr, e);
                                    // RFC 9250 §4.3: abandon the stream explicitly
                                    // instead of leaving the client waiting.
                                    let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
                                    return;
                                }

                                let query_len = u16::from_be_bytes(len_buf) as usize;
                                if query_len == 0 {
                                    warn!("DoQ zero-length query from {}", peer_addr);
                                    let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
                                    return;
                                }

                                let mut query_buf = vec![0u8; query_len];
                                if let Err(e) = recv.read_exact(&mut query_buf).await {
                                    warn!("DoQ stream failed reading query body from {}: {}", peer_addr, e);
                                    let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
                                    return;
                                }

                                // Rate admission happened before the body read.
                                let query = match decode_message(&query_buf) {
                                    Ok(mut q) => {
                                        // RFC 9250 §4.2.1: the DNS Message ID on
                                        // the wire MUST be 0; a non-zero ID is a
                                        // protocol error (§4.3.3).
                                        if q.metadata.id != 0 {
                                            warn!(
                                                "DoQ query with non-zero message ID {} from {}",
                                                q.metadata.id, peer_addr
                                            );
                                            let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
                                            return;
                                        }
                                        q.metadata.id = 0;
                                        q
                                    }
                                    Err(e) => {
                                        warn!("DoQ failed decoding DNS query from {}: {}", peer_addr, e);
                                        let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
                                        return;
                                    }
                                };

                                let client_ctx = match sni {
                                    Some(ref s) => ClientContext::with_sni(client_ip, s).with_proto("doq"),
                                    None => ClientContext::new(client_ip).with_proto("doq"),
                                };

                                if let Some(mut response) = handler.handle(query, client_ctx).await {
                                    // RFC 9250 §4.2.1: responses always carry ID 0.
                                    response.metadata.id = 0;
                                    match encode_message(&response) {
                                        Ok(encoded) => {
                                            let encoded =
                                                if frame_prefix(encoded.len()).is_none() {
                                                    warn!(
                                                        "DoQ response of {} bytes exceeds the 65535-byte limit; sending TC=1",
                                                        encoded.len()
                                                    );
                                                    let Some(truncated) =
                                                        truncate_for_framing(&encoded)
                                                    else {
                                                        warn!(
                                                            "DoQ response from {} could not be truncated to fit the 65535-byte limit",
                                                            peer_addr
                                                        );
                                                        let _ = send.reset(DOQ_INTERNAL_ERROR.into());
                                                        return;
                                                    };
                                                    truncated
                                                } else {
                                                    encoded
                                                };
                                            let Some(resp_len) = frame_prefix(encoded.len()) else {
                                                let _ = send.reset(DOQ_INTERNAL_ERROR.into());
                                                return;
                                            };
                                            // A write error means the peer already
                                            // abandoned the stream; no reset needed.
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
                                            let _ = send.reset(DOQ_INTERNAL_ERROR.into());
                                        }
                                    }
                                }
                                },
                              )
                              .await;
                              if timed.is_err() {
                                  debug!("DoQ stream from {} timed out", peer_addr);
                                  // A client that never completes the length
                                  // prefix/body gets an explicit protocol error
                                  // instead of a silently finished stream.
                                  let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
                              }
                            });
                            // Reap completed stream tasks continuously, not
                            // only when the connection closes.
                            crate::admission::reap_finished(&mut stream_tasks);
                                }
                                Some(_) = stream_tasks.join_next(), if !stream_tasks.is_empty() => {}
                            }
                        }
                        // The connection is gone; abort any streams still
                        // blocked on a peer and wait for their tasks to finish.
                        stream_tasks.abort_all();
                        while stream_tasks.join_next().await.is_some() {}
                    });
                    crate::admission::reap_finished(&mut connection_tasks);
                }
            }
        }
        // The endpoint is closed; wait for connection tasks so shutdown does
        // not leave detached tasks behind.
        while connection_tasks.join_next().await.is_some() {}
    });

    // If acceptor_mgr is provided, monitor for certificate reload and update endpoint
    if let Some(mgr) = acceptor_mgr {
        let idle_timeout = config.idle_timeout;

        tokio::spawn(async move {
            let mut last_config = mgr.current_config();
            loop {
                tokio::select! {
                    res = shutdown_rx.changed() => {
                        if res.is_err() || *shutdown_rx.borrow() {
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
    use rustls::pki_types::pem::PemObject;
    use sito_proto::rdata::A;
    use sito_proto::{
        Message, MessageType, Name, OpCode, Query, RData, Record, RecordType, ResponseCode,
    };
    use sito_test_support::reserve_udp_port_number;
    use std::str::FromStr;
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_doq_query_and_response() {
        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);

        let temp_dir =
            std::env::temp_dir().join(format!("sito_doq_test_qr_{}", std::process::id()));
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
        let port = reserve_udp_port_number().unwrap();

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

        // RFC 9250 §4.2.1: the on-the-wire message ID must be 0.
        let mut query = Message::new(0, MessageType::Query, OpCode::Query);
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
        assert_eq!(dns_resp.metadata.id, 0);
        assert_eq!(dns_resp.answers.len(), 1);
        assert_eq!(
            dns_resp.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(9, 9, 9, 9)))
        );

        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_doq_rejects_non_zero_message_id() {
        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);

        let temp_dir =
            std::env::temp_dir().join(format!("sito_doq_test_badid_{}", std::process::id()));
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
        let port = reserve_udp_port_number().unwrap();

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

        // RFC 9250 §4.3.3: a non-zero message ID is a fatal protocol error.
        let mut query = Message::new(1234, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("doq-test.example.com.").unwrap(),
            RecordType::A,
        ));
        let wire = encode_message(&query).unwrap();

        let len_prefix = (wire.len() as u16).to_be_bytes();
        send.write_all(&len_prefix).await.unwrap();
        send.write_all(&wire).await.unwrap();
        send.finish().unwrap();

        // The server must abandon the stream with DOQ_PROTOCOL_ERROR (2).
        let mut resp_len_buf = [0u8; 2];
        let err = recv
            .read_exact(&mut resp_len_buf)
            .await
            .expect_err("a non-zero message ID must be rejected");
        match err {
            quinn::ReadExactError::ReadError(quinn::ReadError::Reset(code)) => {
                assert_eq!(code.into_inner(), u64::from(DOQ_PROTOCOL_ERROR));
            }
            other => panic!("expected a DOQ_PROTOCOL_ERROR reset, got {other:?}"),
        }

        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Regression: a stream whose length prefix or body is truncated used to
    /// be abandoned silently (the send side was merely finished), so the
    /// client saw a clean, empty stream instead of an RFC 9250 protocol error.
    #[tokio::test]
    async fn test_doq_truncated_stream_is_reset_with_protocol_error() {
        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);

        let temp_dir =
            std::env::temp_dir().join(format!("sito_doq_test_trunc_{}", std::process::id()));
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
        let port = reserve_udp_port_number().unwrap();

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let config = DoqConfig::new(actual_addr, Some(acceptor_mgr));

        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            Some(resp)
        });

        let _handle = start_doq_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

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

        // 1. Truncated length prefix: only one of the two prefix octets.
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&[0x00]).await.unwrap();
        send.finish().unwrap();

        let mut resp_len_buf = [0u8; 2];
        let err = recv
            .read_exact(&mut resp_len_buf)
            .await
            .expect_err("a truncated length prefix must be rejected");
        match err {
            quinn::ReadExactError::ReadError(quinn::ReadError::Reset(code)) => {
                assert_eq!(code.into_inner(), u64::from(DOQ_PROTOCOL_ERROR));
            }
            other => panic!("expected a DOQ_PROTOCOL_ERROR reset, got {other:?}"),
        }

        // 2. Truncated body: the length prefix promises more bytes than sent.
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&[0x00, 0x40]).await.unwrap();
        send.write_all(&[0u8; 3]).await.unwrap();
        send.finish().unwrap();

        let mut resp_len_buf = [0u8; 2];
        let err = recv
            .read_exact(&mut resp_len_buf)
            .await
            .expect_err("a truncated query body must be rejected");
        match err {
            quinn::ReadExactError::ReadError(quinn::ReadError::Reset(code)) => {
                assert_eq!(code.into_inner(), u64::from(DOQ_PROTOCOL_ERROR));
            }
            other => panic!("expected a DOQ_PROTOCOL_ERROR reset, got {other:?}"),
        }

        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    fn doq_test_acceptor(name: &str) -> (TlsAcceptorManager, String, std::path::PathBuf) {
        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);
        let temp_dir = std::env::temp_dir().join(format!("sito_doq_{name}_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");
        std::fs::write(&cert_file, &cert_pem).unwrap();
        std::fs::write(&key_file, &key_pem).unwrap();
        let server_config =
            crate::tls::load_server_config(&cert_file, &key_file, &[], vec![b"doq".to_vec()])
                .unwrap();
        (TlsAcceptorManager::new(server_config), cert_pem, temp_dir)
    }

    async fn connect_doq(
        actual_addr: SocketAddr,
        cert_pem: &str,
    ) -> (quinn::Endpoint, quinn::Connection) {
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
        (client_endpoint, conn)
    }

    fn doq_query(id: u16) -> Message {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("doq-test.example.com.").unwrap(),
            RecordType::A,
        ));
        query
    }

    /// P1-10: QUIC flow-control windows and stream caps must be explicit and
    /// bounded; quinn defaults allow 1.25 MiB per stream and effectively
    /// unbounded streams per connection.
    #[test]
    fn test_doq_quic_windows_and_stream_caps_are_bounded() {
        const {
            assert!(
                DOQ_STREAM_RECEIVE_WINDOW >= 65_537,
                "the stream window must fit one maximum-size DNS message"
            );
        };
        const {
            assert!(
                DOQ_STREAM_RECEIVE_WINDOW <= 256 * 1024,
                "the per-stream window must not allow megabyte-scale buffering"
            );
        };
        const {
            assert!(
                DOQ_CONNECTION_RECEIVE_WINDOW <= 4 * 1024 * 1024,
                "the per-connection window must be bounded"
            );
        };
        const {
            assert!(
                DOQ_MAX_BIDI_STREAMS <= 32,
                "one connection must not be able to create thousands of stream tasks"
            );
        };
    }

    /// P1-10: rate admission happens before the query body is read. With the
    /// budget exhausted, opening a stream without sending any bytes must be
    /// rejected immediately instead of pinning a task until the body timeout.
    #[tokio::test]
    async fn test_doq_rate_check_before_body_read() {
        let (acceptor_mgr, cert_pem, temp_dir) = doq_test_acceptor("rate_before_body");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let port = reserve_udp_port_number().unwrap();
        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));

        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            Some(resp)
        });

        let mut config = DoqConfig::new(actual_addr, Some(acceptor_mgr));
        // Burst of one: the first query spends the only token.
        config.rate_limiter = Some(Arc::new(RateLimiter::new(1, 1)));
        let _handle = start_doq_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (_client_endpoint, conn) = connect_doq(actual_addr, &cert_pem).await;

        let wire = encode_message(&doq_query(0)).unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&(wire.len() as u16).to_be_bytes())
            .await
            .unwrap();
        send.write_all(&wire).await.unwrap();
        send.finish().unwrap();
        let mut len_buf = [0u8; 2];
        recv.read_exact(&mut len_buf)
            .await
            .expect("the first query is admitted");

        // Second stream: send one byte so the QUIC stream is created, then
        // stop. The rate check must run (and fail) before the server waits for
        // the rest of a body it will reject.
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&[0]).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), recv.read_exact(&mut len_buf))
            .await
            .expect("the server must not wait for a body it will reject");
        match result {
            Err(quinn::ReadExactError::ReadError(quinn::ReadError::Reset(code))) => {
                assert_eq!(code.into_inner(), u64::from(DOQ_EXCESSIVE_LOAD));
            }
            other => panic!("expected a DOQ_EXCESSIVE_LOAD reset, got {other:?}"),
        }

        let _ = send.finish();
        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// P1-10: a global stream semaphore bounds in-flight stream tasks even
    /// when the client keeps one connection open.
    #[tokio::test]
    async fn test_doq_global_stream_semaphore_rejects_excess_streams() {
        let (acceptor_mgr, cert_pem, temp_dir) = doq_test_acceptor("stream_cap");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let port = reserve_udp_port_number().unwrap();
        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));

        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            Some(resp)
        });

        let mut config = DoqConfig::new(actual_addr, Some(acceptor_mgr));
        config.max_connections = 1; // stream budget = 4
        config.rate_limiter = Some(Arc::new(RateLimiter::new(0, 0)));
        let _handle = start_doq_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (_client_endpoint, conn) = connect_doq(actual_addr, &cert_pem).await;

        // Four streams stall after one byte and hold the budget.
        let mut held = Vec::new();
        for _ in 0..4 {
            let (mut send, recv) = conn.open_bi().await.unwrap();
            send.write_all(&[0]).await.unwrap();
            held.push((send, recv));
        }

        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&[0]).await.unwrap();
        let mut len_buf = [0u8; 2];
        let result = tokio::time::timeout(Duration::from_secs(2), recv.read_exact(&mut len_buf))
            .await
            .expect("the excess stream must be rejected without waiting for a body");
        match result {
            Err(quinn::ReadExactError::ReadError(quinn::ReadError::Reset(code))) => {
                assert_eq!(code.into_inner(), u64::from(DOQ_EXCESSIVE_LOAD));
            }
            other => panic!("expected a DOQ_EXCESSIVE_LOAD reset, got {other:?}"),
        }

        drop(held);
        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_doq_accepts_queries_larger_than_4096_bytes() {
        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);

        let temp_dir =
            std::env::temp_dir().join(format!("sito_doq_large_test_{}", std::process::id()));
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
        let port = reserve_udp_port_number().unwrap();

        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let config = DoqConfig::new(actual_addr, Some(acceptor_mgr));

        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            Some(resp)
        });

        let _handle = start_doq_listener(config, handler, shutdown_rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

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

        // RFC 9250 permits DNS messages up to 65535 bytes; build a single-
        // question query well above the previous 4096-byte server cap using an
        // EDNS padding option (the pipeline rejects multi-question messages).
        let mut query = Message::new(0, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("large-query.example.com.").unwrap(),
            RecordType::A,
        ));
        let mut edns = sito_proto::Edns::new();
        edns.set_max_payload(4096);
        edns.options_mut()
            .insert(sito_proto::rdata::opt::EdnsOption::Unknown(
                12,
                vec![0u8; 5000],
            ));
        query.set_edns(edns);
        let wire = encode_message(&query).unwrap();
        assert!(
            wire.len() > 4096,
            "test query must exceed the old 4096-byte cap (got {} bytes)",
            wire.len()
        );

        // The query ID is rewritten to 0 on the wire per RFC 9250.
        send.write_all(&(wire.len() as u16).to_be_bytes())
            .await
            .unwrap();
        send.write_all(&wire).await.unwrap();
        send.finish().unwrap();

        let mut resp_len_buf = [0u8; 2];
        recv.read_exact(&mut resp_len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        recv.read_exact(&mut resp_buf).await.unwrap();

        let dns_resp = decode_message(&resp_buf).unwrap();
        assert_eq!(dns_resp.queries.len(), query.queries.len());

        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
