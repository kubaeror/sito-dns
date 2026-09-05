//! RFC 8484 compliant DNS over HTTPS (DoH) listener supporting HTTP/2 and HTTP/1.1,
//! GET (?dns=) and POST methods, path-based ClientID routing, and rate limiting.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, info, trace, warn};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use base64::Engine;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;

use sito_core::client::ClientContext;
use sito_proto::{decode_message, encode_message};

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
    pub http01_challenges: Option<Arc<dashmap::DashMap<String, String>>>,
    pub alt_svc_port: Option<u16>,
}

impl DohConfig {
    pub fn new(bind_addr: SocketAddr, acceptor_mgr: Option<TlsAcceptorManager>) -> Self {
        Self {
            bind_addr,
            acceptor_mgr,
            max_connections: 256,
            rate_limit_per_ip: 20,
            http01_challenges: None,
            alt_svc_port: Some(443),
        }
    }

    #[must_use]
    pub fn with_http01_challenges(
        mut self,
        challenges: Arc<dashmap::DashMap<String, String>>,
    ) -> Self {
        self.http01_challenges = Some(challenges);
        self
    }

    #[must_use]
    pub fn with_alt_svc_port(mut self, port: Option<u16>) -> Self {
        self.alt_svc_port = port;
        self
    }
}

struct DohState<H: QueryHandler> {
    handler: Arc<H>,
    rate_limiter: Arc<RateLimiter>,
    http01_challenges: Option<Arc<dashmap::DashMap<String, String>>>,
    alt_svc_header: Option<HeaderValue>,
}

fn decode_base64url(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
}

async fn handle_doh_request<H: QueryHandler>(
    state: Arc<DohState<H>>,
    peer_addr: SocketAddr,
    client_id: Option<String>,
    method: Method,
    headers: HeaderMap,
    params: HashMap<String, String>,
    body: Bytes,
) -> Response {
    let client_ip = peer_addr.ip();
    if !state.rate_limiter.check(client_ip) {
        debug!("DoH rate limit exceeded for client {}", client_ip);
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }

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
                Ok(bytes) => bytes,
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
                let mut resp_builder = Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/dns-message")
                    .header(header::CACHE_CONTROL, "no-store");
                if let Some(ref alt_svc) = state.alt_svc_header {
                    resp_builder = resp_builder.header(header::ALT_SVC, alt_svc);
                }
                resp_builder
                    .body(axum::body::Body::from(encoded))
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
    Extension(peer_addr): Extension<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    handle_doh_request(state, peer_addr, None, method, headers, params, body).await
}

async fn doh_route_with_client<H: QueryHandler>(
    State(state): State<Arc<DohState<H>>>,
    Extension(peer_addr): Extension<SocketAddr>,
    Path(client_id): Path<String>,
    method: Method,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    handle_doh_request(
        state,
        peer_addr,
        Some(client_id),
        method,
        headers,
        params,
        body,
    )
    .await
}

async fn acme_http01_route<H: QueryHandler>(
    State(state): State<Arc<DohState<H>>>,
    Path(token): Path<String>,
) -> Response {
    if let Some(ref store) = state.http01_challenges {
        if let Some(key_auth) = store.get(&token) {
            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/plain")],
                key_auth.clone(),
            )
                .into_response();
        }
    }
    StatusCode::NOT_FOUND.into_response()
}

/// Start the DNS over HTTPS listener.
pub async fn start_doh_listener<H: QueryHandler + 'static>(
    config: DohConfig,
    handler: Arc<H>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    let local_addr = listener.local_addr()?;
    info!("DoH listener started on {}", local_addr);

    let alt_svc_header = config.alt_svc_port.map(|p| {
        let val = format!("h3=\":{p}\"; ma=86400");
        HeaderValue::from_str(&val).expect("valid alt-svc header value")
    });

    let state = Arc::new(DohState {
        handler,
        rate_limiter: Arc::new(RateLimiter::new(
            config.rate_limit_per_ip,
            config.rate_limit_per_ip * 2,
        )),
        http01_challenges: config.http01_challenges,
        alt_svc_header,
    });

    let app = Router::new()
        .route("/dns-query", any(doh_route::<H>))
        .route("/dns-query/{client_id}", any(doh_route_with_client::<H>))
        .route(
            "/.well-known/acme-challenge/{token}",
            axum::routing::get(acme_http01_route::<H>),
        )
        .with_state(state);

    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let acceptor_mgr = config.acceptor_mgr;

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        debug!("DoH listener stopping due to shutdown");
                        break;
                    }
                }
                accept_res = listener.accept() => {
                    let (tcp_stream, peer_addr) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("DoH accept error: {}", e);
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

                    let app = app.clone();
                    let maybe_mgr = acceptor_mgr.clone();

                    tokio::spawn(async move {
                        let _permit = permit;

                        let connection_app = app.clone().layer(axum::middleware::from_fn(
                            move |mut req: axum::extract::Request, next: axum::middleware::Next| {
                                req.extensions_mut().insert(peer_addr);
                                next.run(req)
                            },
                        ));

                        let hyper_service = TowerToHyperService::new(connection_app);

                        if let Some(mgr) = maybe_mgr {
                            let acceptor = mgr.acceptor();
                            match acceptor.accept(tcp_stream).await {
                                Ok(tls_stream) => {
                                    let io = TokioIo::new(tls_stream);
                                    let conn_builder = ConnBuilder::new(TokioExecutor::new());
                                    if let Err(e) = conn_builder.serve_connection_with_upgrades(io, hyper_service).await {
                                        trace!("DoH TLS connection error for {}: {}", peer_addr, e);
                                    }
                                }
                                Err(e) => {
                                    debug!("DoH TLS handshake error for {}: {}", peer_addr, e);
                                }
                            }
                        } else {
                            let io = TokioIo::new(tcp_stream);
                            let conn_builder = ConnBuilder::new(TokioExecutor::new());
                            if let Err(e) = conn_builder.serve_connection_with_upgrades(io, hyper_service).await {
                                trace!("DoH plain HTTP connection error for {}: {}", peer_addr, e);
                            }
                        }
                    });
                }
            }
        }
    });

    Ok(handle)
}
