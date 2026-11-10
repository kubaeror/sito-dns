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
use sito_proto::{decode_message, encode_message, truncate_for_framing};

use crate::handler::QueryHandler;
use crate::limiter::RateLimiter;
use crate::tls::TlsAcceptorManager;

/// Maximum accepted DoH request body: 65535 bytes (the DNS-over-TCP size ceiling).
const MAX_DOH3_BODY_BYTES: usize = 65_535;

/// Upper bound on a single stream step (request setup, each body chunk): a
/// client that opens a stream and stalls must not pin a task forever.
const STREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// Total wall-clock budget for one DoH3 request, including all body chunks and
/// handler work. Per-step timeouts alone let a client reset the clock forever
/// by dribbling one chunk at a time.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounded wait for the QUIC/TLS handshake.
const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of concurrent client-initiated bidirectional streams.
pub(crate) const DOH3_MAX_BIDI_STREAMS: u32 = 16;

/// Global in-flight request budget per DoH3 endpoint, expressed as a multiple
/// of the connection cap.
const DOH3_REQUESTS_PER_CONNECTION: usize = 4;

/// Overridable timing limits for the DoH3 listener.
///
/// Production uses [`Doh3Limits::default`]; tests inject short deadlines so a
/// behaviour that would otherwise need a ten-second stall can be exercised
/// quickly.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Doh3Limits {
    pub request_timeout: Duration,
    pub handshake_timeout: Duration,
}

impl Default for Doh3Limits {
    fn default() -> Self {
        Self {
            request_timeout: REQUEST_TIMEOUT,
            handshake_timeout: QUIC_HANDSHAKE_TIMEOUT,
        }
    }
}

/// Maximum accepted size of an HTTP/3 field section (request headers). The
/// default in h3 0.0.8 is `VarInt::MAX`, which lets a peer force unbounded
/// buffering before the limit is checked.
const MAX_DOH3_FIELD_SECTION_BYTES: u64 = 16 * 1024;

/// Minimal response-stream surface used to answer a request-deadline expiry.
///
/// A DoH3 deadline can fire before any response header is sent (answer 504) or
/// after the handler already started the response (headers are no longer
/// writable, so reset the stream). Keeping the decision in one helper makes
/// both branches testable without a live QUIC connection.
trait TimeoutResponseStream {
    type Error;

    async fn send_gateway_timeout(&mut self) -> Result<(), Self::Error>;
    async fn finish_response(&mut self) -> Result<(), Self::Error>;
    fn reset_stream(&mut self);
}

impl TimeoutResponseStream for h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes> {
    type Error = h3::error::StreamError;

    async fn send_gateway_timeout(&mut self) -> Result<(), Self::Error> {
        let response = http::Response::builder()
            .status(http::StatusCode::GATEWAY_TIMEOUT)
            .body(())
            .unwrap();
        self.send_response(response).await
    }

    async fn finish_response(&mut self) -> Result<(), Self::Error> {
        self.finish().await
    }

    fn reset_stream(&mut self) {
        self.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    }
}

/// Answers a request-deadline expiry: 504 when the response is still writable,
/// otherwise reset the stream because headers were already sent.
async fn finish_request_timeout<S: TimeoutResponseStream>(stream: &mut S) {
    if stream.send_gateway_timeout().await.is_ok() {
        let _ = stream.finish_response().await;
    } else {
        stream.reset_stream();
    }
}

/// Configuration options for the DoH3 listener.
#[derive(Clone)]
pub struct Doh3Config {
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
    /// When set, requests whose authority/Host does not match are rejected with 421.
    pub dedicated_hostname: Option<String>,
}

impl Doh3Config {
    pub fn new(bind_addr: SocketAddr, acceptor_mgr: Option<TlsAcceptorManager>) -> Self {
        Self {
            bind_addr,
            acceptor_mgr,
            server_config: None,
            max_connections: 256,
            rate_limit_per_ip: 20,
            rate_limiter: None,
            idle_timeout: Duration::from_secs(30),
            dedicated_hostname: None,
        }
    }

    /// Restricts this DoH3 listener to a single Host/authority name.
    #[must_use]
    pub fn with_dedicated_hostname(mut self, hostname: Option<String>) -> Self {
        self.dedicated_hostname = hostname.filter(|h| !h.trim().is_empty());
        self
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
    transport_cfg.max_concurrent_bidi_streams(DOH3_MAX_BIDI_STREAMS.into());
    transport_cfg.max_concurrent_uni_streams(DOH3_MAX_BIDI_STREAMS.into());
    // The h3 0.0.8 frame decoder buffers a complete HEADERS payload before the
    // field-section limit applies, so the QUIC flow-control windows are the
    // effective memory bound for a request. Keep them small: 128 KiB per
    // stream and 2 MiB per connection (previously the connection window was
    // effectively unbounded).
    transport_cfg.stream_receive_window(quinn::VarInt::from_u32(128 * 1024));
    transport_cfg.receive_window(quinn::VarInt::from_u32(2 * 1024 * 1024));

    quinn_cfg.transport_config(Arc::new(transport_cfg));

    Ok(quinn_cfg)
}

fn decode_base64url(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
}

/// Decodes one form-urlencoded component (`+` is a space, `%XX` escapes are
/// percent-decoded).
fn form_url_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let high = (bytes[i + 1] as char).to_digit(16);
                let low = (bytes[i + 2] as char).to_digit(16);
                if let (Some(high), Some(low)) = (high, low) {
                    #[allow(clippy::cast_possible_truncation)]
                    out.push((high * 16 + low) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Extracts the `dns` query parameter with the same form-urlencoded semantics
/// as the DoH (axum) path: percent-encoded values are decoded and the last
/// occurrence wins when the parameter is repeated.
fn decode_dns_query_param(query: &str) -> Option<String> {
    let mut value = None;
    for pair in query.split('&') {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        if form_url_decode(raw_key) == "dns" {
            value = Some(form_url_decode(raw_value));
        }
    }
    value
}

/// Start the DNS over HTTP/3 (DoH3) listener.
pub async fn start_doh3_listener<H: QueryHandler + 'static>(
    config: Doh3Config,
    handler: Arc<H>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    start_doh3_listener_with_limits(config, handler, shutdown_rx, Doh3Limits::default())
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn start_doh3_listener_with_limits<H: QueryHandler + 'static>(
    config: Doh3Config,
    handler: Arc<H>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    limits: Doh3Limits,
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

    let rate_limiter = config.rate_limiter.clone().unwrap_or_else(|| {
        Arc::new(RateLimiter::new(
            config.rate_limit_per_ip,
            RateLimiter::burst_for_rate(config.rate_limit_per_ip),
        ))
    });
    rate_limiter.spawn_pruner(shutdown_rx.clone());
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let per_ip_limiter = crate::admission::PerIpConnectionLimiter::new(
        crate::admission::DEFAULT_MAX_CONNECTIONS_PER_IP,
    );
    let request_semaphore = Arc::new(Semaphore::new(
        config
            .max_connections
            .saturating_mul(DOH3_REQUESTS_PER_CONNECTION)
            .max(1),
    ));
    let acceptor_mgr = config.acceptor_mgr.clone();
    let dedicated_hostname = config.dedicated_hostname.clone();

    let endpoint_accept = endpoint.clone();
    let mut accept_shutdown_rx = shutdown_rx.clone();

    let handle = tokio::spawn(async move {
        let mut connection_tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                res = accept_shutdown_rx.changed() => {
                    if res.is_err() || *accept_shutdown_rx.borrow() {
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
                    let Some(per_ip_permit) = per_ip_limiter.try_acquire(incoming.remote_address().ip()) else {
                        warn!(
                            "DoH3 per-IP connection limit ({}) reached; rejecting connection",
                            crate::admission::DEFAULT_MAX_CONNECTIONS_PER_IP
                        );
                        incoming.refuse();
                        continue;
                    };

                    let handler = Arc::clone(&handler);
                    let rate_limiter = Arc::clone(&rate_limiter);
                    let request_semaphore = Arc::clone(&request_semaphore);
                    let dedicated_hostname = dedicated_hostname.clone();

                    connection_tasks.spawn(async move {
                        let _permit = permit;
                        let _per_ip_permit = per_ip_permit;
                        let conn = match tokio::time::timeout(limits.handshake_timeout, incoming).await {
                            Ok(Ok(c)) => c,
                            Ok(Err(e)) => {
                                debug!("DoH3 QUIC handshake failed: {}", e);
                                return;
                            }
                            Err(_) => {
                                debug!(
                                    "DoH3 QUIC handshake timed out after {}s",
                                    limits.handshake_timeout.as_secs()
                                );
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

                        let mut h3_server = h3::server::builder();
                        h3_server.max_field_section_size(MAX_DOH3_FIELD_SECTION_BYTES);
                        let mut h3_conn = match h3_server
                            .build(h3_quinn::Connection::new(conn))
                            .await
                        {
                            Ok(c) => c,
                            Err(e) => {
                                debug!("DoH3 H3 connection setup failed from {}: {}", peer_addr, e);
                                return;
                            }
                        };

                        let mut request_tasks = tokio::task::JoinSet::new();
                        loop {
                            tokio::select! {
                                accept_res = h3_conn.accept() => {
                                    let Ok(Some(resolver)) = accept_res else {
                                        break;
                                    };
                            let handler = Arc::clone(&handler);
                            let rate_limiter = Arc::clone(&rate_limiter);
                            let request_semaphore = Arc::clone(&request_semaphore);
                            let sni = sni.clone();
                            let dedicated_hostname = dedicated_hostname.clone();

                            request_tasks.spawn(async move {
                                if !rate_limiter.check(client_ip) {
                                    debug!("DoH3 rate limit exceeded for client {}", client_ip);
                                    return;
                                }

                                let Ok(_request_permit) = request_semaphore.clone().try_acquire_owned() else {
                                    debug!(
                                        "DoH3 global request limit reached for client {}",
                                        client_ip
                                    );
                                    let busy = tokio::time::timeout(limits.request_timeout, async {
                                        if let Ok(Ok((_req, mut stream))) = tokio::time::timeout(
                                            STREAM_TIMEOUT,
                                            resolver.resolve_request(),
                                        )
                                        .await
                                        {
                                            let resp = http::Response::builder()
                                                .status(http::StatusCode::SERVICE_UNAVAILABLE)
                                                .header(http::header::RETRY_AFTER, "1")
                                                .body(())
                                                .unwrap();
                                            let _ = stream.send_response(resp).await;
                                            let _ = stream.finish().await;
                                        }
                                    })
                                    .await;
                                    if busy.is_err() {
                                        debug!(
                                            "DoH3 503 response to {} exceeded the {}s deadline",
                                            client_ip,
                                            limits.request_timeout.as_secs()
                                        );
                                    }
                                    return;
                                };

                                let deadline =
                                    tokio::time::Instant::now() + limits.request_timeout;
                                let (req, mut stream) = match tokio::time::timeout_at(
                                    deadline,
                                    resolver.resolve_request(),
                                )
                                .await
                                {
                                    Ok(Ok(r)) => r,
                                    Ok(Err(e)) => {
                                        debug!(
                                            "DoH3 failed resolving request from {}: {}",
                                            peer_addr, e
                                        );
                                        return;
                                    }
                                    Err(_) => {
                                        debug!(
                                            "DoH3 request setup timed out for {}",
                                            peer_addr
                                        );
                                        return;
                                    }
                                };

                                let handled = tokio::time::timeout_at(deadline, async {

                                if let Some(ref expected) = dedicated_hostname {
                                    let host = req
                                        .uri()
                                        .host()
                                        .map(str::to_string)
                                        .or_else(|| {
                                            req.headers()
                                                .get(http::header::HOST)
                                                .and_then(|v| v.to_str().ok())
                                                .map(|h| {
                                                    h.split(':').next().unwrap_or(h).to_string()
                                                })
                                        });
                                    let matches = host
                                        .is_some_and(|h| h.eq_ignore_ascii_case(expected.trim()));
                                    if !matches {
                                        let resp = http::Response::builder()
                                            .status(http::StatusCode::MISDIRECTED_REQUEST)
                                            .body(())
                                            .unwrap();
                                        let _ = stream.send_response(resp).await;
                                        let _ = stream.finish().await;
                                        return;
                                    }
                                }

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
                                        loop {
                                            let mut chunk = match tokio::time::timeout(
                                                STREAM_TIMEOUT,
                                                stream.recv_data(),
                                            )
                                            .await
                                            {
                                                Ok(Ok(Some(chunk))) => chunk,
                                                Ok(Ok(None)) => break,
                                                Ok(Err(e)) => {
                                                    // A mid-body error must never be
                                                    // treated as a complete message.
                                                    debug!(
                                                        "DoH3 body receive error from {}: {}",
                                                        peer_addr, e
                                                    );
                                                    return;
                                                }
                                                Err(_) => {
                                                    debug!(
                                                        "DoH3 body receive timed out for {}",
                                                        peer_addr
                                                    );
                                                    return;
                                                }
                                            };
                                            let remaining = chunk.remaining();
                                            if body_bytes.len().saturating_add(remaining)
                                                > MAX_DOH3_BODY_BYTES
                                            {
                                                warn!(
                                                    "DoH3 request body from {} exceeds {} bytes; rejecting",
                                                    peer_addr, MAX_DOH3_BODY_BYTES
                                                );
                                                let resp = http::Response::builder()
                                                    .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                                                    .body(())
                                                    .unwrap();
                                                let _ = stream.send_response(resp).await;
                                                let _ = stream.finish().await;
                                                return;
                                            }
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
                                        let Some(param) = decode_dns_query_param(query_str) else {
                                            let resp = http::Response::builder()
                                                .status(http::StatusCode::BAD_REQUEST)
                                                .body(())
                                                .unwrap();
                                            let _ = stream.send_response(resp).await;
                                            let _ = stream.finish().await;
                                            return;
                                        };

                                        match decode_base64url(&param) {
                                            Ok(b) if b.len() <= MAX_DOH3_BODY_BYTES => b,
                                            Ok(_) => {
                                                let resp = http::Response::builder()
                                                    .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                                                    .body(())
                                                    .unwrap();
                                                let _ = stream.send_response(resp).await;
                                                let _ = stream.finish().await;
                                                return;
                                            }
                                            Err(_) => {
                                                let resp = http::Response::builder()
                                                    .status(http::StatusCode::BAD_REQUEST)
                                                    .body(())
                                                    .unwrap();
                                                let _ = stream.send_response(resp).await;
                                                let _ = stream.finish().await;
                                                return;
                                            }
                                        }
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
                                        // DNS-over-HTTPS carries a single DNS
                                        // message; responses over the 65,535-byte
                                        // framing limit must be truncated with
                                        // TC=1 rather than emitted oversized.
                                        let encoded = if encoded.len() > MAX_DOH3_BODY_BYTES {
                                            warn!(
                                                "DoH3 response of {} bytes exceeds the 65535-byte limit; sending TC=1",
                                                encoded.len()
                                            );
                                            if let Some(truncated) = truncate_for_framing(&encoded) {
                                                truncated
                                            } else {
                                                let resp = http::Response::builder()
                                                    .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                                                    .body(())
                                                    .unwrap();
                                                let _ = stream.send_response(resp).await;
                                                let _ = stream.finish().await;
                                                return;
                                            }
                                        } else {
                                            encoded
                                        };
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
                                }).await;
                                if handled.is_err() {
                                    debug!(
                                        "DoH3 request from {} exceeded the {}s deadline",
                                        client_ip,
                                        limits.request_timeout.as_secs()
                                    );
                                    // DoH returns 504 on its request deadline; keep
                                    // the transports operationally consistent. If
                                    // the response has already started, the stream
                                    // is no longer writable, so reset it instead.
                                    finish_request_timeout(&mut stream).await;
                                }
                            });
                            // Reap completed request tasks continuously, not
                            // only when the H3 connection closes.
                            crate::admission::reap_finished(&mut request_tasks);
                                }
                                Some(_) = request_tasks.join_next(), if !request_tasks.is_empty() => {}
                            }
                        }
                        request_tasks.abort_all();
                        while request_tasks.join_next().await.is_some() {}
                    });
                    crate::admission::reap_finished(&mut connection_tasks);
                }
            }
        }
        // The endpoint is closed; wait for connection tasks so shutdown does
        // not leave detached tasks behind.
        while connection_tasks.join_next().await.is_some() {}
    });

    // Cert reload watcher
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
    use sito_test_support::reserve_udp_port_number;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::watch;

    /// Test double for the request-deadline response branch.
    ///
    /// h3's `RequestStream` has no public way to mark a response as already
    /// started without a live peer, so the "headers sent" state is modelled
    /// here: `send_response` fails exactly as it does on a second header block.
    #[derive(Default)]
    struct FakeTimeoutStream {
        headers_sent: bool,
        finished: bool,
        reset: bool,
    }

    // The trait mirrors the async h3 methods; the fake completes immediately.
    #[allow(clippy::unused_async_trait_impl)]
    impl TimeoutResponseStream for FakeTimeoutStream {
        type Error = ();

        async fn send_gateway_timeout(&mut self) -> Result<(), Self::Error> {
            if self.headers_sent {
                // h3 refuses a second response header block on the stream.
                Err(())
            } else {
                Ok(())
            }
        }

        async fn finish_response(&mut self) -> Result<(), Self::Error> {
            self.finished = true;
            Ok(())
        }

        fn reset_stream(&mut self) {
            self.reset = true;
        }
    }

    /// Deferred D4a: the "headers already sent, reset stream" deadline branch
    /// used to be untested. A stream whose response already started must be
    /// cancelled instead of trying (and failing) to send a second 504.
    #[tokio::test]
    async fn test_doh3_deadline_resets_stream_when_headers_already_sent() {
        let mut stream = FakeTimeoutStream {
            headers_sent: true,
            ..FakeTimeoutStream::default()
        };

        finish_request_timeout(&mut stream).await;

        assert!(
            stream.reset,
            "a stream whose headers were already sent must be reset"
        );
        assert!(
            !stream.finished,
            "the helper must not finish a stream that could not accept a 504"
        );
    }

    /// The writable branch still answers 504 and finishes the stream.
    #[tokio::test]
    async fn test_doh3_deadline_sends_gateway_timeout_when_writable() {
        let mut stream = FakeTimeoutStream::default();

        finish_request_timeout(&mut stream).await;

        assert!(
            stream.finished,
            "a writable stream must be answered with 504 and finished"
        );
        assert!(
            !stream.reset,
            "a writable stream must not be reset after sending 504"
        );
    }

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
        let port = reserve_udp_port_number().unwrap();

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

        // 3. GET with percent-encoded base64 padding (`%3D`): the DoH (axum)
        // path percent-decodes the query parameter, so DoH3 must too.
        let padded = base64::engine::general_purpose::URL_SAFE.encode(&wire_query);
        assert!(
            padded.contains('='),
            "test fixture must produce base64 padding to exercise %3D decoding"
        );
        let percent_encoded = padded.replace('=', "%3D");
        let req_percent = http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("https://localhost/dns-query?dns={percent_encoded}"))
            .header(http::header::ACCEPT, "application/dns-message")
            .body(())
            .unwrap();

        let mut percent_stream = send_request.send_request(req_percent).await.unwrap();
        percent_stream.finish().await.unwrap();

        let percent_resp = percent_stream.recv_response().await.unwrap();
        assert_eq!(percent_resp.status(), http::StatusCode::OK);

        let mut percent_body = Vec::new();
        while let Some(mut chunk) = percent_stream.recv_data().await.unwrap() {
            percent_body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }
        let percent_dns_resp = decode_message(&percent_body).unwrap();
        assert_eq!(percent_dns_resp.metadata.id, 8001);

        drop(send_request);
        driver_task.abort();
        let _ = shutdown_tx.send(true);
        let _ = listener_handle.await;
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// P1-14: DoH3 responses over the 65,535-byte DNS framing limit must be
    /// truncated (TC=1) rather than sent as an oversized body.
    #[tokio::test]
    async fn test_doh3_truncates_oversized_response() {
        let temp_dir = std::env::temp_dir().join(format!("sito_doh3_large_{}", std::process::id()));
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
        let port = reserve_udp_port_number().unwrap();
        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));

        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            let qname = query.queries[0].name().clone();
            for i in 0..6000u32 {
                resp.answers.push(Record::from_rdata(
                    qname.clone(),
                    300,
                    RData::A(A(std::net::Ipv4Addr::from(i))),
                ));
            }
            Some(resp)
        });

        let listener_handle = start_doh3_listener(
            Doh3Config::new(actual_addr, Some(acceptor_mgr)),
            handler,
            shutdown_rx,
        )
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
        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let wire = encode_message(&{
            let mut query = Message::new(9001, MessageType::Query, OpCode::Query);
            query.queries.push(Query::query(
                Name::from_str("large.doh3.example.").unwrap(),
                RecordType::A,
            ));
            query
        })
        .unwrap();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&wire);
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("https://localhost/dns-query?dns={b64}"))
            .header(http::header::ACCEPT, "application/dns-message")
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);

        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }
        assert!(
            body.len() <= 65_535,
            "a DoH3 DNS response must fit the 65535-byte framing limit (got {})",
            body.len()
        );
        let dns_resp = decode_message(&body).unwrap();
        assert!(
            dns_resp.metadata.truncation,
            "an oversized DoH3 response must be truncated with TC=1"
        );

        drop(send_request);
        driver_task.abort();
        let _ = shutdown_tx.send(true);
        let _ = listener_handle.await;
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Regression: the GET `dns` parameter used to be split on `&`/`=` without
    /// percent-decoding, so a `%3D`-encoded (padded) base64 value was rejected
    /// even though the DoH path accepts it.
    /// P2-17: the whole DoH3 request is bounded by one total deadline. A
    /// client that sends headers and one body byte then stalls must be cut off
    /// without waiting for the per-chunk 10 s timeout. Deferred D3: the
    /// deadline returns HTTP 504 (like DoH) instead of resetting the stream.
    #[tokio::test]
    async fn test_doh3_total_request_deadline_returns_gateway_timeout() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_doh3_deadline_{}", std::process::id()));
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
        let port = reserve_udp_port_number().unwrap();
        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));

        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            Some(resp)
        });

        let listener_handle = start_doh3_listener_with_limits(
            Doh3Config::new(actual_addr, Some(acceptor_mgr)),
            handler,
            shutdown_rx,
            Doh3Limits {
                request_timeout: Duration::from_millis(300),
                handshake_timeout: Duration::from_secs(5),
            },
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut root_store = rustls::RootCertStore::empty();
        for c in crate::tls::load_certificates(&cert_file).unwrap() {
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
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_tls)).unwrap(),
        ));
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let conn = client_endpoint
            .connect(actual_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost/dns-query")
            .header(http::header::CONTENT_TYPE, "application/dns-message")
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(req).await.unwrap();
        // One body byte only: the server must not wait for the rest.
        stream.send_data(Bytes::from_static(&[0])).await.unwrap();

        let response = tokio::time::timeout(Duration::from_secs(2), stream.recv_response())
            .await
            .expect("the total request deadline must fire well before the per-chunk timeout")
            .expect("the stalled request must receive a 504 response, not a stream reset");
        assert_eq!(
            response.status(),
            http::StatusCode::GATEWAY_TIMEOUT,
            "the DoH3 deadline must mirror DoH and return 504"
        );

        drop(send_request);
        driver_task.abort();
        let _ = shutdown_tx.send(true);
        let _ = listener_handle.await;
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// P1-11/P2-17: the DoH3 global request cap returns 503 when saturated.
    #[tokio::test]
    async fn test_doh3_global_request_cap_returns_503() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_doh3_request_cap_{}", std::process::id()));
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
        let port = reserve_udp_port_number().unwrap();
        let actual_addr = SocketAddr::from(([127, 0, 0, 1], port));

        let entered = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(AtomicBool::new(false));
        let handler = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            Arc::new(move |query: Message, _client: ClientContext| {
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                async move {
                    entered.fetch_add(1, Ordering::SeqCst);
                    while !release.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                    resp.queries = query.queries.clone();
                    Some(resp)
                }
            })
        };

        let mut config = Doh3Config::new(actual_addr, Some(acceptor_mgr));
        // Request budget = max_connections * 4 = 4.
        config.max_connections = 1;
        config.rate_limiter = Some(Arc::new(RateLimiter::new(0, 0)));
        let listener_handle = start_doh3_listener_with_limits(
            config,
            handler,
            shutdown_rx,
            Doh3Limits {
                request_timeout: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(5),
            },
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut root_store = rustls::RootCertStore::empty();
        for c in crate::tls::load_certificates(&cert_file).unwrap() {
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
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_tls)).unwrap(),
        ));
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let conn = client_endpoint
            .connect(actual_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let wire = encode_message(&{
            let mut query = Message::new(9500, MessageType::Query, OpCode::Query);
            query.queries.push(Query::query(
                Name::from_str("busy.doh3.example.").unwrap(),
                RecordType::A,
            ));
            query
        })
        .unwrap();

        let request = |wire: Vec<u8>| {
            let req = http::Request::builder()
                .method(http::Method::POST)
                .uri("https://localhost/dns-query")
                .header(http::header::CONTENT_TYPE, "application/dns-message")
                .body(())
                .unwrap();
            (req, wire)
        };

        let mut held = Vec::new();
        for _ in 0..4 {
            let (req, body) = request(wire.clone());
            let mut stream = send_request.send_request(req).await.unwrap();
            stream.send_data(Bytes::from(body)).await.unwrap();
            stream.finish().await.unwrap();
            held.push(stream);
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while entered.load(Ordering::SeqCst) < 4 {
            assert!(
                std::time::Instant::now() < deadline,
                "four requests must reach the handler and hold the request budget"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let (req, body) = request(wire);
        let mut overflow = send_request.send_request(req).await.unwrap();
        overflow.send_data(Bytes::from(body)).await.unwrap();
        overflow.finish().await.unwrap();
        let overflow_resp = tokio::time::timeout(Duration::from_secs(3), overflow.recv_response())
            .await
            .expect("the global request cap must answer promptly")
            .expect("a 503 response");
        assert_eq!(
            overflow_resp.status(),
            http::StatusCode::SERVICE_UNAVAILABLE,
            "the saturated global request cap must return 503"
        );

        release.store(true, Ordering::SeqCst);
        for mut stream in held {
            let resp = tokio::time::timeout(Duration::from_secs(3), stream.recv_response())
                .await
                .expect("the held requests must complete")
                .expect("a response");
            assert_eq!(resp.status(), http::StatusCode::OK);
            while let Ok(Ok(Some(_))) =
                tokio::time::timeout(Duration::from_secs(2), stream.recv_data()).await
            {
                // Drain bodies so the client driver can finish cleanly.
            }
        }

        drop(send_request);
        driver_task.abort();
        let _ = shutdown_tx.send(true);
        let _ = listener_handle.await;
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_doh3_get_dns_param_decoding_matches_doh() {
        assert_eq!(decode_dns_query_param("dns=abc"), Some("abc".to_string()));
        // Percent-encoded '=' (base64 padding) must survive decoding.
        assert_eq!(
            decode_dns_query_param("dns=ab%3D%3D"),
            Some("ab==".to_string())
        );
        // Percent-encoded key.
        assert_eq!(decode_dns_query_param("%64ns=abc"), Some("abc".to_string()));
        // `+` is a space in form-urlencoded data.
        assert_eq!(decode_dns_query_param("dns=a+b"), Some("a b".to_string()));
        // The last occurrence wins, matching the DoH HashMap extractor.
        assert_eq!(
            decode_dns_query_param("dns=first&dns=second"),
            Some("second".to_string())
        );
        // A value containing '=' is not truncated.
        assert_eq!(decode_dns_query_param("dns=a=b"), Some("a=b".to_string()));
        assert_eq!(decode_dns_query_param("other=abc"), None);
        assert_eq!(decode_dns_query_param(""), None);
    }
}
