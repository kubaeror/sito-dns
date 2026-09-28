//! Dedicated plaintext HTTP-01 listener for ACME validation (RFC 8555).
//!
//! Serves only `/.well-known/acme-challenge/{token}` so ACME validators can
//! reach the challenge on port 80 without exposing the general DoH listener.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use dashmap::DashMap;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

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
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let local_addr = listener.local_addr()?;
    info!("ACME HTTP-01 listener started on http://{local_addr}");

    let app = Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            get(challenge_response),
        )
        .with_state(ChallengeState { challenges });

    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                while !*shutdown_rx.borrow_and_update() {
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
        {
            warn!("ACME HTTP-01 listener stopped with error: {e}");
        }
    });

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

        // Pick a port that is free on both families.
        let port = loop {
            let probe = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
            let port = probe.local_addr().unwrap().port();
            // Release the v4 probe first: a dual-stack `[::]` bind conflicts
            // with an actively-listening `0.0.0.0` socket.
            drop(probe);
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
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }
}
