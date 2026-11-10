//! RFC 8484 compliant DNS over HTTPS (DoH) listener supporting HTTP/2 and HTTP/1.1,
//! GET (?dns=) and POST methods, path-based ClientID routing, and rate limiting.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, info, trace, warn};

/// Bounded wait for the TLS handshake; slowloris clients must not hold a
/// connection permit indefinitely.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounded wait for request headers once the connection is established.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Read-idle timeout for established DoH connections: a peer that completes
/// the handshake and then sends nothing must not hold a connection permit
/// indefinitely.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum lifetime of one DoH connection, independent of activity. A peer
/// that keeps a connection busy (or dribbles just enough bytes) still releases
/// its connection slot.
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(300);

/// Total wall-clock budget for reading and answering one DoH request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of concurrent HTTP/2 streams per connection.
const MAX_H2_CONCURRENT_STREAMS: u32 = 32;

/// Maximum DNS message size accepted on the DoH path (RFC 8484 over the
/// 65535-byte DNS-over-TCP framing limit). Larger bodies are rejected before
/// buffering beyond this bound.
pub(crate) const MAX_DOH_BODY_BYTES: usize = 65_535;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use base64::Engine;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;

use sito_core::client::ClientContext;
use sito_proto::{decode_message, encode_message, truncate_for_framing};

use crate::handler::QueryHandler;
use crate::limiter::RateLimiter;
use crate::tls::TlsAcceptorManager;

/// Configuration options for the DoH listener.
#[derive(Clone)]
pub struct DohConfig {
    pub bind_addr: SocketAddr,
    pub acceptor_mgr: Option<TlsAcceptorManager>,
    pub max_connections: usize,
    pub rate_limit_per_ip: u32,
    /// Optional shared limiter; lets the server hot-reload the rate
    /// limit while keeping listener state. Built from `rate_limit_per_ip`
    /// when absent.
    pub rate_limiter: Option<Arc<RateLimiter>>,
    pub alt_svc_port: Option<u16>,
    /// When set, requests whose Host header does not match are rejected with 421.
    pub dedicated_hostname: Option<String>,
}

impl DohConfig {
    pub fn new(bind_addr: SocketAddr, acceptor_mgr: Option<TlsAcceptorManager>) -> Self {
        Self {
            bind_addr,
            acceptor_mgr,
            max_connections: 256,
            rate_limit_per_ip: 20,
            rate_limiter: None,
            alt_svc_port: Some(443),
            dedicated_hostname: None,
        }
    }

    #[must_use]
    pub fn with_alt_svc_port(mut self, port: Option<u16>) -> Self {
        self.alt_svc_port = port;
        self
    }

    /// Restricts this DoH listener to a single Host/SNI name.
    #[must_use]
    pub fn with_dedicated_hostname(mut self, hostname: Option<String>) -> Self {
        self.dedicated_hostname = hostname.filter(|h| !h.trim().is_empty());
        self
    }
}

struct DohState<H: QueryHandler> {
    handler: Arc<H>,
    rate_limiter: Arc<RateLimiter>,
    /// Global in-flight request budget. Acquired before any request body is
    /// read so a client cannot force buffering simply by opening streams.
    request_semaphore: Arc<Semaphore>,
    alt_svc_header: Option<HeaderValue>,
    dedicated_hostname: Option<String>,
}

/// Normalizes an authority or hostname: strips user-info, a port and IPv6
/// brackets, and a trailing root dot.
fn normalize_host(value: &str) -> String {
    let value = value.trim();
    let value = value.rsplit_once('@').map_or(value, |(_, host)| host);
    let host = if let Some(rest) = value.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        value.split(':').next().unwrap_or(value)
    };
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Effective host of a request: the URI authority (HTTP/2 and HTTP/3
/// `:authority`) or the `Host` header (HTTP/1.1).
fn request_host(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    let raw = uri
        .authority()
        .map(|authority| authority.as_str().to_string())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        })?;
    let host = normalize_host(&raw);
    (!host.is_empty()).then_some(host)
}

/// Returns true when the request authority/Host matches the configured
/// dedicated hostname.
///
/// HTTP/2 (and HTTP/3) do not send a `Host` header; the authority travels in
/// the `:authority` pseudo-header and is exposed through the request URI. Only
/// checking `Host` rejected every HTTP/2 request with 421.
fn host_matches(uri: &Uri, headers: &HeaderMap, expected: &str) -> bool {
    let expected = normalize_host(expected);
    !expected.is_empty() && request_host(uri, headers).is_some_and(|host| host == expected)
}

/// Wraps a connection so that a read-idle peer cannot hold its permit
/// forever. Any successful read refreshes the deadline; the connection is
/// closed with a timeout error when no bytes arrive for `IDLE_TIMEOUT`.
struct IdleTimeoutStream<S> {
    inner: S,
    sleep: Pin<Box<tokio::time::Sleep>>,
    timeout: Duration,
}

impl<S> IdleTimeoutStream<S> {
    fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            sleep: Box::pin(tokio::time::sleep(timeout)),
            timeout,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleTimeoutStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                // Only reset the idle deadline when the peer actually made
                // progress. A zero-length read is EOF (or a wake-up without
                // data) and must not extend the connection's lifetime.
                if buf.filled().len() > before {
                    this.sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + this.timeout);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => match this.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "DoH connection idle timeout",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTimeoutStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Builds the hyper connection builder with header-read timeouts enabled.
fn connection_builder() -> ConnBuilder<TokioExecutor> {
    let mut builder = ConnBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .timer(TokioTimer::new());
    builder
        .http2()
        .max_concurrent_streams(Some(MAX_H2_CONCURRENT_STREAMS))
        .timer(TokioTimer::new());
    builder
}

fn decode_base64url(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
}

/// Total request budget and admission are enforced before the body is read.
///
/// The previous implementation extracted `Bytes` before this function ran, so
/// axum buffered up to `DefaultBodyLimit` for every request before the rate
/// check. Reading the body only after admission bounds both memory and work.
#[allow(clippy::too_many_arguments)]
async fn handle_doh_request<H: QueryHandler>(
    state: Arc<DohState<H>>,
    peer_addr: SocketAddr,
    client_id: Option<String>,
    params: HashMap<String, String>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let headers = parts.headers;

    if let Some(ref expected) = state.dedicated_hostname
        && !host_matches(&uri, &headers, expected)
    {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            "Misdirected Request: unknown DoH hostname",
        )
            .into_response();
    }

    let client_ip = peer_addr.ip();
    if !state.rate_limiter.check(client_ip) {
        debug!("DoH rate limit exceeded for client {}", client_ip);
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }

    let Ok(_request_permit) = state.request_semaphore.clone().try_acquire_owned() else {
        debug!("DoH global request limit reached for client {}", client_ip);
        let mut response = (
            StatusCode::SERVICE_UNAVAILABLE,
            "Server is handling too many DNS requests",
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return response;
    };

    if let Ok(response) = tokio::time::timeout(
        REQUEST_TIMEOUT,
        process_doh_request(
            Arc::clone(&state),
            client_ip,
            client_id,
            method,
            uri,
            headers,
            params,
            body,
        ),
    )
    .await
    {
        response
    } else {
        debug!(
            "DoH request from {} exceeded the {}s deadline",
            client_ip,
            REQUEST_TIMEOUT.as_secs()
        );
        (StatusCode::GATEWAY_TIMEOUT, "DNS request timed out").into_response()
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_doh_request<H: QueryHandler>(
    state: Arc<DohState<H>>,
    client_ip: std::net::IpAddr,
    client_id: Option<String>,
    method: Method,
    _uri: Uri,
    headers: HeaderMap,
    params: HashMap<String, String>,
    body: Body,
) -> Response {
    let wire_bytes = match method {
        Method::POST => {
            let is_dns_message = headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ct| {
                    ct.split(';')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .eq_ignore_ascii_case("application/dns-message")
                });

            if !is_dns_message {
                return (
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Unsupported Media Type: expected application/dns-message",
                )
                    .into_response();
            }

            // `to_bytes` enforces the cap while streaming, so an oversized
            // body is rejected without buffering it in full.
            let Ok(body) = to_bytes(body, MAX_DOH_BODY_BYTES).await else {
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "DNS message exceeds the 65535-byte limit",
                )
                    .into_response();
            };

            if body.is_empty() {
                return (StatusCode::BAD_REQUEST, "Empty DNS query body").into_response();
            }
            body.to_vec()
        }
        Method::GET => {
            let Some(dns_param) = params.get("dns") else {
                return (StatusCode::BAD_REQUEST, "Missing 'dns' query parameter").into_response();
            };

            match decode_base64url(dns_param) {
                Ok(bytes) if bytes.len() <= MAX_DOH_BODY_BYTES => bytes,
                Ok(_) => {
                    return (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "DNS message exceeds the 65535-byte limit",
                    )
                        .into_response();
                }
                Err(e) => {
                    debug!("DoH base64url decode error: {}", e);
                    return (StatusCode::BAD_REQUEST, "Invalid base64url encoding").into_response();
                }
            }
        }
        _ => {
            return (StatusCode::NOT_IMPLEMENTED, "Method Not Implemented").into_response();
        }
    };

    let query = match decode_message(&wire_bytes) {
        Ok(q) => q,
        Err(e) => {
            debug!("DoH decode DNS message error: {}", e);
            return (StatusCode::BAD_REQUEST, "Malformed DNS message").into_response();
        }
    };

    let client_ctx = match client_id {
        Some(cid) => ClientContext::with_id(client_ip, cid).with_proto("doh"),
        None => ClientContext::new(client_ip).with_proto("doh"),
    };

    let response = state.handler.handle(query, client_ctx).await;

    match response {
        Some(resp) => match encode_message(&resp) {
            Ok(encoded) => {
                // RFC 8484 carries one DNS message; a response over the
                // 65,535-byte DNS framing limit cannot be represented and
                // must be truncated (TC=1) instead of emitting an oversized
                // `application/dns-message` body.
                let encoded = if encoded.len() > MAX_DOH_BODY_BYTES {
                    warn!(
                        "DoH response of {} bytes exceeds the 65535-byte limit; sending TC=1",
                        encoded.len()
                    );
                    match truncate_for_framing(&encoded) {
                        Some(truncated) => truncated,
                        None => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "DNS response could not be truncated",
                            )
                                .into_response();
                        }
                    }
                } else {
                    encoded
                };

                let mut resp_builder = Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/dns-message")
                    .header(header::CACHE_CONTROL, "no-store");
                if let Some(ref alt_svc) = state.alt_svc_header {
                    resp_builder = resp_builder.header(header::ALT_SVC, alt_svc);
                }
                resp_builder
                    .body(Body::from(encoded))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
            Err(e) => {
                warn!("DoH failed to encode DNS response: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to encode DNS response",
                )
                    .into_response()
            }
        },
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn doh_route<H: QueryHandler>(
    State(state): State<Arc<DohState<H>>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    Query(params): Query<HashMap<String, String>>,
    request: Request,
) -> Response {
    handle_doh_request(state, peer_addr, None, params, request).await
}

async fn doh_route_with_client<H: QueryHandler>(
    State(state): State<Arc<DohState<H>>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    Path(client_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    request: Request,
) -> Response {
    handle_doh_request(state, peer_addr, Some(client_id), params, request).await
}

/// Inserts the connection's peer address into every request as a
/// [`ConnectInfo`] extension.
///
/// The router is built once at listener startup; this wrapper is the only
/// per-connection state, so accepted connections no longer rebuild a
/// middleware layer around the whole stack.
#[derive(Clone, Copy)]
struct InsertPeerAddr<S> {
    inner: S,
    peer_addr: SocketAddr,
}

impl<S, B> hyper::service::Service<hyper::Request<B>> for InsertPeerAddr<S>
where
    S: hyper::service::Service<hyper::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn call(&self, mut req: hyper::Request<B>) -> Self::Future {
        req.extensions_mut().insert(ConnectInfo(self.peer_addr));
        self.inner.call(req)
    }
}

/// Start the DNS over HTTPS listener.
pub async fn start_doh_listener<H: QueryHandler + 'static>(
    config: DohConfig,
    handler: Arc<H>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let listener = crate::net::bind_tcp_listener(config.bind_addr)?;
    let local_addr = listener.local_addr()?;
    info!("DoH listener started on {}", local_addr);

    let alt_svc_header = config.alt_svc_port.map(|p| {
        let val = format!("h3=\":{p}\"; ma=86400");
        HeaderValue::from_str(&val).expect("valid alt-svc header value")
    });

    let state = Arc::new(DohState {
        handler,
        rate_limiter: config.rate_limiter.clone().unwrap_or_else(|| {
            Arc::new(RateLimiter::new(
                config.rate_limit_per_ip,
                RateLimiter::burst_for_rate(config.rate_limit_per_ip),
            ))
        }),
        // Two in-flight requests per connection slot: enough for ordinary
        // HTTP/2 concurrency while still bounding pre-body buffering.
        request_semaphore: Arc::new(Semaphore::new(
            config.max_connections.saturating_mul(2).max(2),
        )),
        alt_svc_header,
        dedicated_hostname: config.dedicated_hostname,
    });
    state.rate_limiter.spawn_pruner(shutdown_rx.clone());

    let app = Router::new()
        .route("/dns-query", any(doh_route::<H>))
        .route("/dns-query/{client_id}", any(doh_route_with_client::<H>))
        // Reject oversized bodies before they are buffered (the handler also
        // checks, but this bounds memory per request).
        .layer(axum::extract::DefaultBodyLimit::max(MAX_DOH_BODY_BYTES))
        .with_state(state);

    // Built once: `TowerToHyperService` is `Copy` and the router clone is
    // `Arc`-cheap, so no per-connection stack construction is needed.
    let router_service = TowerToHyperService::new(app);

    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let per_ip_limiter = crate::admission::PerIpConnectionLimiter::new(
        crate::admission::DEFAULT_MAX_CONNECTIONS_PER_IP,
    );
    let acceptor_mgr = config.acceptor_mgr;

    let handle = tokio::spawn(async move {
        let mut accept_backoff = crate::admission::AcceptBackoff::default();
        loop {
            tokio::select! {
                res = shutdown_rx.changed() => {
                    if res.is_err() || *shutdown_rx.borrow() {
                        debug!("DoH listener stopping due to shutdown");
                        break;
                    }
                }
                accept_res = listener.accept() => {
                    let (tcp_stream, peer_addr) = match accept_res {
                        Ok(conn) => {
                            accept_backoff.reset();
                            conn
                        }
                        Err(e) => {
                            let delay = accept_backoff.next_delay();
                            warn!(
                                "DoH accept error: {}; retrying after {:?}",
                                e, delay
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                    };

                    let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                        warn!(
                            "DoH max connections ({}) reached; rejecting connection from {}",
                            config.max_connections, peer_addr
                        );
                        continue;
                    };
                    let Some(per_ip_permit) = per_ip_limiter.try_acquire(peer_addr.ip()) else {
                        warn!(
                            "DoH per-IP connection limit ({}) reached; rejecting connection from {}",
                            crate::admission::DEFAULT_MAX_CONNECTIONS_PER_IP, peer_addr
                        );
                        continue;
                    };

                    let hyper_service = InsertPeerAddr {
                        inner: router_service.clone(),
                        peer_addr,
                    };
                    let maybe_mgr = acceptor_mgr.clone();

                    tokio::spawn(async move {
                        let _permit = permit;
                        let _per_ip_permit = per_ip_permit;

                        if let Some(mgr) = maybe_mgr {
                            let acceptor = mgr.acceptor();
                            match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp_stream)).await {
                                Ok(Ok(tls_stream)) => {
                                    let io = TokioIo::new(IdleTimeoutStream::new(
                                        tls_stream,
                                        IDLE_TIMEOUT,
                                    ));
                                    match timeout(
                                        MAX_CONNECTION_LIFETIME,
                                        connection_builder()
                                            .serve_connection_with_upgrades(io, hyper_service),
                                    )
                                    .await
                                    {
                                        Ok(Ok(())) => {}
                                        Ok(Err(e)) => {
                                            trace!("DoH TLS connection error for {}: {}", peer_addr, e);
                                        }
                                        Err(_) => {
                                            debug!(
                                                "DoH TLS connection for {} reached the {}s lifetime",
                                                peer_addr,
                                                MAX_CONNECTION_LIFETIME.as_secs()
                                            );
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    debug!("DoH TLS handshake error for {}: {}", peer_addr, e);
                                }
                                Err(_) => {
                                    debug!(
                                        "DoH TLS handshake timed out after {}s for {}",
                                        TLS_HANDSHAKE_TIMEOUT.as_secs(),
                                        peer_addr
                                    );
                                }
                            }
                        } else {
                            let io = TokioIo::new(IdleTimeoutStream::new(
                                tcp_stream,
                                IDLE_TIMEOUT,
                            ));
                            match timeout(
                                MAX_CONNECTION_LIFETIME,
                                connection_builder()
                                    .serve_connection_with_upgrades(io, hyper_service),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    trace!("DoH plain HTTP connection error for {}: {}", peer_addr, e);
                                }
                                Err(_) => {
                                    debug!(
                                        "DoH plain HTTP connection for {} reached the {}s lifetime",
                                        peer_addr,
                                        MAX_CONNECTION_LIFETIME.as_secs()
                                    );
                                }
                            }
                        }
                    });
                }
            }
        }
    });

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sito_proto::rdata::A;
    use sito_proto::{Message, MessageType, Name, OpCode, Query, RData, Record, RecordType};
    use sito_test_support::reserve_port_number;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[test]
    fn test_dedicated_hostname_matching() {
        // HTTP/1.1: Host header with a port.
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            HeaderValue::from_static("dns.example.com:8443"),
        );
        let uri: Uri = "/dns-query".parse().expect("uri");
        assert!(host_matches(&uri, &headers, "dns.example.com"));
        assert!(host_matches(&uri, &headers, "DNS.EXAMPLE.COM."));
        assert!(!host_matches(&uri, &headers, "other.example.com"));

        let empty = HeaderMap::new();
        assert!(!host_matches(&uri, &empty, "dns.example.com"));

        // HTTP/2: authority in the URI, no Host header.
        let uri: Uri = "https://dns.example.com/dns-query".parse().expect("uri");
        assert!(host_matches(&uri, &HeaderMap::new(), "dns.example.com"));

        // IPv6 literal and a trailing-dot FQDN.
        let uri: Uri = "https://[2001:db8::1]:443/dns-query".parse().expect("uri");
        assert!(host_matches(&uri, &HeaderMap::new(), "[2001:db8::1]"));
        let uri: Uri = "https://dns.example.com./dns-query".parse().expect("uri");
        assert!(host_matches(&uri, &HeaderMap::new(), "dns.example.com"));
    }

    /// The per-connection `ConnectInfo` extension must reach the route
    /// handlers as the peer address (replacing the per-connection middleware
    /// layer built by the previous implementation).
    #[tokio::test]
    async fn test_doh_connect_info_peer_addr_reaches_handler() {
        use sito_proto::{Message, MessageType, Name, OpCode, Query, RecordType};
        use std::str::FromStr;
        use std::sync::Mutex;

        let port = reserve_port_number().unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        let seen: Arc<Mutex<Option<ClientContext>>> = Arc::new(Mutex::new(None));
        let seen_handler = Arc::clone(&seen);
        let handler = move |query: Message, client: ClientContext| {
            let seen = Arc::clone(&seen_handler);
            async move {
                *seen.lock().unwrap() = Some(client);
                let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                resp.queries = query.queries.clone();
                Some(resp)
            }
        };

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = start_doh_listener(DohConfig::new(addr, None), Arc::new(handler), shutdown_rx)
            .await
            .unwrap();

        let mut query = Message::new(7001, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("connect-info.example.").unwrap(),
            RecordType::A,
        ));
        let wire = encode_message(&query).unwrap();

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/dns-query"))
            .header("Content-Type", "application/dns-message")
            .body(wire)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let body = resp.bytes().await.unwrap();
        let dns_resp = decode_message(&body).unwrap();
        assert_eq!(dns_resp.metadata.id, 7001);

        let observed = seen.lock().unwrap().clone().expect("handler must run");
        assert_eq!(observed.ip, std::net::Ipv4Addr::LOCALHOST);
        assert_eq!(observed.proto, "doh");

        let _ = shutdown_tx.send(true);
        handle.await.unwrap();
    }

    /// Alt-Svc must only be advertised when a DoH3 port is configured; the
    /// default `DohConfig::new` advertises 443, and `alt_svc_port = None`
    /// (no DoH3 listener) must produce no header at all.
    #[tokio::test]
    async fn test_alt_svc_header_matches_doh3_port_configuration() {
        use sito_proto::{Message, MessageType, Name, OpCode, Query, RecordType};
        use std::str::FromStr;

        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            Some(resp)
        });

        let mut query = Message::new(9001, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("alt-svc.example.").unwrap(),
            RecordType::A,
        ));
        let wire = encode_message(&query).unwrap();

        let post = |addr: SocketAddr, wire: Vec<u8>| async move {
            reqwest::Client::new()
                .post(format!("http://{addr}/dns-query"))
                .header("Content-Type", "application/dns-message")
                .body(wire)
                .send()
                .await
                .unwrap()
        };

        // No DoH3 port configured: no Alt-Svc advertisement.
        let port = reserve_port_number().unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = start_doh_listener(
            DohConfig::new(addr, None).with_alt_svc_port(None),
            Arc::clone(&handler),
            shutdown_rx,
        )
        .await
        .unwrap();

        let resp = post(addr, wire.clone()).await;
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert!(
            resp.headers().get("alt-svc").is_none(),
            "Alt-Svc must not be advertised without a DoH3 port"
        );
        let _ = shutdown_tx.send(true);
        handle.await.unwrap();

        // Configured DoH3 port: advertised as h3.
        let port = reserve_port_number().unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = start_doh_listener(
            DohConfig::new(addr, None).with_alt_svc_port(Some(8443)),
            handler,
            shutdown_rx,
        )
        .await
        .unwrap();

        let resp = post(addr, wire).await;
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(
            resp.headers().get("alt-svc").map(|v| v.to_str().unwrap()),
            Some("h3=\":8443\"; ma=86400")
        );
        let _ = shutdown_tx.send(true);
        handle.await.unwrap();
    }

    fn test_query(id: u16, name: &str) -> Message {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        query
    }

    /// P1-11: a rate-limited request must be rejected from its headers without
    /// waiting for (or buffering) the request body. The old handler extracted
    /// `Bytes`, so it blocked on a body that never arrived before the rate
    /// check could run.
    #[tokio::test]
    async fn test_doh_rate_check_before_body_read() {
        let port = reserve_port_number().unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        let handler = Arc::new(|query: Message, _client: ClientContext| async move {
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            Some(resp)
        });

        let mut config = DohConfig::new(addr, None);
        config.rate_limiter = Some(Arc::new(RateLimiter::new(1, 1)));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = start_doh_listener(config, handler, shutdown_rx)
            .await
            .unwrap();

        // Spend the single token with a complete request.
        let wire = encode_message(&test_query(1, "rate.example.")).unwrap();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&wire);
        let mut first = TcpStream::connect(addr).await.unwrap();
        first
            .write_all(
                format!(
                    "GET /dns-query?dns={b64} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        first.read_to_end(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
            "the first request must be admitted"
        );

        // A POST with a declared body but no body bytes. Admission must reject
        // it before hyper/axum waits for the body.
        let mut second = TcpStream::connect(addr).await.unwrap();
        second
            .write_all(
                b"POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: 100\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();

        let mut buf = [0u8; 256];
        let read = tokio::time::timeout(Duration::from_secs(2), second.read(&mut buf))
            .await
            .expect("the rate limit must be enforced before reading the body")
            .unwrap();
        let text = String::from_utf8_lossy(&buf[..read]);
        assert!(
            text.starts_with("HTTP/1.1 429"),
            "expected 429 before the body is read, got: {text}"
        );

        let _ = shutdown_tx.send(true);
        handle.await.unwrap();
    }

    /// P1-11: a global request cap bounds in-flight requests independently of
    /// the connection cap and returns 503 when exhausted.
    #[tokio::test]
    async fn test_doh_global_request_cap_returns_503() {
        let port = reserve_port_number().unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

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

        let mut config = DohConfig::new(addr, None);
        // Global request budget is max_connections * 2 = 4.
        config.max_connections = 2;
        config.rate_limiter = Some(Arc::new(RateLimiter::new(0, 0)));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = start_doh_listener(config, handler, shutdown_rx)
            .await
            .unwrap();

        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .unwrap();
        let url = format!("http://{addr}/dns-query");
        let wire = encode_message(&test_query(2, "busy.example.")).unwrap();

        let mut requests = Vec::new();
        for _ in 0..4 {
            let client = client.clone();
            let url = url.clone();
            let wire = wire.clone();
            requests.push(tokio::spawn(async move {
                client
                    .post(url)
                    .header("Content-Type", "application/dns-message")
                    .body(wire)
                    .send()
                    .await
            }));
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while entered.load(Ordering::SeqCst) < 4 {
            assert!(
                std::time::Instant::now() < deadline,
                "four requests must reach the handler"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let overflow = client
            .post(&url)
            .header("Content-Type", "application/dns-message")
            .body(wire)
            .send()
            .await
            .unwrap();
        assert_eq!(
            overflow.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "the global request cap must answer 503"
        );

        release.store(true, Ordering::SeqCst);
        for request in requests {
            assert_eq!(
                request.await.unwrap().unwrap().status(),
                reqwest::StatusCode::OK
            );
        }

        let _ = shutdown_tx.send(true);
        handle.await.unwrap();
    }

    /// P1-14: a DNS response larger than the 65,535-byte framing limit must be
    /// returned truncated (TC=1), never as an oversized DNS message.
    #[tokio::test]
    async fn test_doh_truncates_oversized_response() {
        let port = reserve_port_number().unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

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

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = start_doh_listener(DohConfig::new(addr, None), handler, shutdown_rx)
            .await
            .unwrap();

        let wire = encode_message(&test_query(3, "large.example.")).unwrap();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&wire);
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/dns-query?dns={b64}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let body = resp.bytes().await.unwrap();
        assert!(
            body.len() <= MAX_DOH_BODY_BYTES,
            "a DNS response must fit the 65535-byte framing limit (got {})",
            body.len()
        );
        let dns_resp = decode_message(&body).unwrap();
        assert!(
            dns_resp.metadata.truncation,
            "an oversized response must be truncated with TC=1"
        );

        let _ = shutdown_tx.send(true);
        handle.await.unwrap();
    }
}
