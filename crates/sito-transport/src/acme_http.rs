//! Dedicated plaintext HTTP-01 listener for ACME validation (RFC 8555).
//!
//! Serves only `/.well-known/acme-challenge/{token}` so ACME validators can
//! reach the challenge on port 80 without exposing the general DoH listener.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use dashmap::DashMap;
use tokio::net::TcpListener;
use tracing::{info, warn};

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

/// Starts the ACME HTTP-01 listener and returns its join handle.
pub async fn start_acme_http01_listener(
    bind_addr: SocketAddr,
    challenges: Arc<DashMap<String, String>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(bind_addr).await?;
    start_acme_http01_listener_on(listener, challenges, shutdown_rx)
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
}
