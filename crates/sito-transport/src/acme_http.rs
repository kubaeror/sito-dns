//! Dedicated plaintext HTTP-01 listener for ACME validation (RFC 8555).
//!
//! Serves only `/.well-known/acme-challenge/{token}` so ACME validators can
//! reach the challenge on port 80 without exposing the general DoH listener.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use dashmap::DashMap;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::admission::{AcceptBackoff, PerIpConnectionLimiter};
use crate::limiter::RateLimiter;

/// Resource limits for the ACME HTTP-01 listener. The challenge endpoint is
/// publicly reachable by design, so it needs the same slowloris and flood
/// bounds as the DNS listeners even before ACME is configured.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AcmeHttpLimits {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub connection_lifetime: Duration,
    pub header_read_timeout: Duration,
    pub rate_per_sec: u32,
}

impl Default for AcmeHttpLimits {
    fn default() -> Self {
        Self {
            max_connections: 32,
            max_connections_per_ip: 4,
            connection_lifetime: Duration::from_secs(60),
            header_read_timeout: Duration::from_secs(10),
            rate_per_sec: 20,
        }
    }
}

#[derive(Clone)]
struct ChallengeState {
    challenges: Arc<DashMap<String, String>>,
}

async fn challenge_response(
    State(state): State<ChallengeState>,
    Path(token): Path<String>,
) -> Response {
    match state.challenges.get(&token) {
        Some(entry) => (
            StatusCode::OK,
            [("content-type", "text/plain")],
            entry.value().clone(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Starts the ACME HTTP-01 listener and returns a join handle for its
/// serving task(s).
///
/// When `bind_addr` is a wildcard address, the opposite wildcard family is
/// bound as well (`[::]` with `IPV6_V6ONLY` for an IPv4 wildcard, `0.0.0.0`
/// for an IPv6 wildcard) so validators reach the challenge over both address
/// families. A failure to bind one family is logged and never disables the
/// other; an error is only returned when no address could be bound.
pub async fn start_acme_http01_listener(
    bind_addr: SocketAddr,
    challenges: Arc<DashMap<String, String>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let mut listeners = Vec::with_capacity(2);
    let mut first_error = None;

    match crate::net::bind_tcp_listener(bind_addr) {
        Ok(listener) => listeners.push(listener),
        Err(e) => {
            warn!(
                addr = %bind_addr,
                error = %e,
                "ACME HTTP-01 listener failed to bind address"
            );
            first_error = Some(e);
        }
    }

    if bind_addr.ip().is_unspecified() {
        // Bind the port the primary listener actually got: with `port = 0`
        // the two families must still share one port.
        let port = listeners
            .first()
            .and_then(|listener| listener.local_addr().ok())
            .map_or(bind_addr.port(), |addr| addr.port());
        let secondary = match bind_addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        };
        match crate::net::bind_tcp_listener(secondary) {
            Ok(listener) => listeners.push(listener),
            Err(e) => warn!(
                addr = %secondary,
                error = %e,
                "ACME HTTP-01 listener failed to bind the additional address; \
                 continuing with the other family"
            ),
        }
    }

    if listeners.is_empty() {
        return Err(first_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "no ACME HTTP-01 address could be bound",
            )
        }));
    }

    let mut handles = Vec::with_capacity(listeners.len());
    for listener in listeners {
        match start_acme_http01_listener_on(listener, Arc::clone(&challenges), shutdown_rx.clone())
        {
            Ok(handle) => handles.push(handle),
            Err(e) => error!(
                error = %e,
                "ACME HTTP-01 listener failed to start on a bound address"
            ),
        }
    }

    if handles.is_empty() {
        return Err(first_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "no ACME HTTP-01 address could be served",
            )
        }));
    }

    // A single family keeps the historical one-handle return; both families
    // are supervised behind one handle (shutdown is driven by the watch
    // channel the caller passed in).
    if handles.len() == 1 {
        return Ok(handles.remove(0));
    }

    Ok(tokio::spawn(async move {
        for handle in handles {
            let _ = handle.await;
        }
    }))
}

/// Serves ACME HTTP-01 challenges on an already-bound listener.
pub fn start_acme_http01_listener_on(
    listener: TcpListener,
    challenges: Arc<DashMap<String, String>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    start_acme_http01_listener_on_with_limits(
        listener,
        challenges,
        shutdown_rx,
        AcmeHttpLimits::default(),
    )
}

/// Serves ACME HTTP-01 challenges with explicit resource limits.
pub(crate) fn start_acme_http01_listener_on_with_limits(
    listener: TcpListener,
    challenges: Arc<DashMap<String, String>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    limits: AcmeHttpLimits,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let local_addr = listener.local_addr()?;
    info!("ACME HTTP-01 listener started on http://{local_addr}");

    let app = Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            get(challenge_response),
        )
        .with_state(ChallengeState { challenges });
    let service = TowerToHyperService::new(app);

    let semaphore = Arc::new(Semaphore::new(limits.max_connections.max(1)));
    let per_ip_limiter = PerIpConnectionLimiter::new(limits.max_connections_per_ip);
    let rate_limiter = Arc::new(RateLimiter::new(
        limits.rate_per_sec,
        RateLimiter::burst_for_rate(limits.rate_per_sec),
    ));
    rate_limiter.spawn_pruner(shutdown_rx.clone());

    let handle = tokio::spawn(async move {
        let mut accept_backoff = AcceptBackoff::default();
        let mut tasks = tokio::task::JoinSet::new();

        loop {
            tokio::select! {
                res = shutdown_rx.changed() => {
                    if res.is_err() || *shutdown_rx.borrow() {
                        debug!("ACME HTTP-01 listener stopping due to shutdown");
                        break;
                    }
                }
                accept_res = listener.accept() => {
                    let (stream, peer_addr) = match accept_res {
                        Ok(conn) => {
                            accept_backoff.reset();
                            conn
                        }
                        Err(e) => {
                            let delay = accept_backoff.next_delay();
                            warn!(
                                "ACME HTTP-01 accept error: {}; retrying after {:?}",
                                e, delay
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                    };

                    if !rate_limiter.check(peer_addr.ip()) {
                        debug!(
                            "ACME HTTP-01 connection rate limit exceeded for {}",
                            peer_addr.ip()
                        );
                        continue;
                    }

                    let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                        debug!(
                            "ACME HTTP-01 max connections ({}) reached; dropping connection from {}",
                            limits.max_connections, peer_addr
                        );
                        continue;
                    };
                    let Some(per_ip_permit) = per_ip_limiter.try_acquire(peer_addr.ip()) else {
                        debug!(
                            "ACME HTTP-01 per-IP connection limit ({}) reached; dropping connection from {}",
                            limits.max_connections_per_ip, peer_addr
                        );
                        continue;
                    };

                    let service = service.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _per_ip_permit = per_ip_permit;
                        let mut builder = ConnBuilder::new(TokioExecutor::new());
                        builder
                            .http1()
                            .header_read_timeout(limits.header_read_timeout)
                            .timer(TokioTimer::new());
                        let io = TokioIo::new(stream);
                        if tokio::time::timeout(
                            limits.connection_lifetime,
                            builder.serve_connection(io, service),
                        )
                        .await
                        .is_err()
                        {
                            debug!(
                                "ACME HTTP-01 connection from {} reached the {}s lifetime",
                                peer_addr,
                                limits.connection_lifetime.as_secs()
                            );
                        }
                    });
                    crate::admission::reap_finished(&mut tasks);
                }
            }
        }

        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    });

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).to_string();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = text
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .to_string();
        (status, body)
    }

    #[tokio::test]
    async fn test_acme_http01_listener_serves_only_known_tokens() {
        let challenges: Arc<DashMap<String, String>> = Arc::new(DashMap::new());
        challenges.insert("known-token".to_string(), "key-auth-value".to_string());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle =
            start_acme_http01_listener_on(listener, Arc::clone(&challenges), shutdown_rx).unwrap();
        let (status, body) = http_get(addr, "/.well-known/acme-challenge/known-token").await;
        assert_eq!(status, 200);
        assert_eq!(body, "key-auth-value");

        let (status, _) = http_get(addr, "/.well-known/acme-challenge/unknown-token").await;
        assert_eq!(status, 404);

        // No other routes are exposed.
        let (status, _) = http_get(addr, "/dns-query").await;
        assert_eq!(status, 404);

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }

    /// Regression: the HTTP-01 listener must also bind the IPv6 wildcard (with
    /// `IPV6_V6ONLY`) so validators that reach the challenge over IPv6 are
    /// served; previously only `0.0.0.0` was bound.
    #[tokio::test]
    async fn test_acme_http01_listener_binds_both_wildcard_families() {
        let challenges: Arc<DashMap<String, String>> = Arc::new(DashMap::new());
        challenges.insert("known-token".to_string(), "key-auth-value".to_string());

        // Pick a port that is free on both families. The shared broker keeps
        // the v4 reservation until the test process exits, so no other test in
        // this binary can race us before start_acme_http01_listener binds it.
        let port = loop {
            let port =
                sito_test_support::reserve_port_number().expect("reserve an ACME HTTP-01 port");
            match std::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, port)) {
                Ok(v6) => {
                    drop(v6);
                    break port;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {}
                // No IPv6 on this host: the v4 assertion below is the only one.
                Err(_) => break port,
            }
        };

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = start_acme_http01_listener(
            SocketAddr::from(([0, 0, 0, 0], port)),
            Arc::clone(&challenges),
            shutdown_rx,
        )
        .await
        .unwrap();

        let (status, body) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            http_get(
                SocketAddr::from(([127, 0, 0, 1], port)),
                "/.well-known/acme-challenge/known-token",
            ),
        )
        .await
        .expect("IPv4 challenge request timed out");
        assert_eq!(status, 200);
        assert_eq!(body, "key-auth-value");

        // IPv6 is optional on the host; only assert when the v6 wildcard can
        // be bound at all (the listener tolerates a v6 bind failure by design).
        if std::net::TcpListener::bind("[::]:0").is_ok() {
            let (status, body) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                http_get(
                    SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
                    "/.well-known/acme-challenge/known-token",
                ),
            )
            .await
            .expect("IPv6 challenge request timed out");
            assert_eq!(status, 200, "IPv6 validators must reach the challenge");
            assert_eq!(body, "key-auth-value");
        }

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    /// P2-20: the HTTP-01 listener bounds connections, per-source connections
    /// and connection lifetime, and resumes serving after a slot is released.
    #[tokio::test]
    async fn test_acme_http01_connection_limits_and_lifetime() {
        let challenges: Arc<DashMap<String, String>> = Arc::new(DashMap::new());
        challenges.insert("known-token".to_string(), "key-auth-value".to_string());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = start_acme_http01_listener_on_with_limits(
            listener,
            Arc::clone(&challenges),
            shutdown_rx,
            AcmeHttpLimits {
                // Global capacity is deliberately larger than the per-IP cap
                // so this test proves the per-IP limit independently.
                max_connections: 2,
                max_connections_per_ip: 1,
                connection_lifetime: Duration::from_millis(250),
                header_read_timeout: Duration::from_millis(200),
                rate_per_sec: 100,
            },
        )
        .unwrap();

        // Hold the only connection slot without sending a request.
        let mut held = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The second connection is accepted and dropped immediately.
        let mut second = TcpStream::connect(addr).await.unwrap();
        second
            .write_all(
                b"GET /.well-known/acme-challenge/known-token HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), second.read_to_end(&mut buf)).await;
        assert!(
            !String::from_utf8_lossy(&buf).contains("200 OK"),
            "a second connection must not be served while the slot is held"
        );

        // The lifetime (or header timeout) releases the slot; service resumes.
        tokio::time::sleep(Duration::from_millis(400)).await;
        let (status, body) = tokio::time::timeout(
            Duration::from_secs(3),
            http_get(addr, "/.well-known/acme-challenge/known-token"),
        )
        .await
        .expect("a new connection must be served after the slot is released");
        assert_eq!(status, 200);
        assert_eq!(body, "key-auth-value");

        let _ = held.shutdown().await;
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }
}
