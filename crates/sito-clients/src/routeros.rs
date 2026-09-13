//! MikroTik RouterOS DHCP lease synchronization (M4.5).
//!
//! Queries RouterOS REST API (>= 7.1) at `GET /rest/ip/dhcp-server/lease`
//! to synchronize active DHCP leases into `ClientRegistry`.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

use crate::mac::normalize_mac;
use crate::registry::{ClientRegistry, RouterOsLease};

/// Configuration for MikroTik RouterOS integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterOsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_url")]
    pub url: String,
    pub token_env: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub password_env: Option<String>,
    #[serde(default = "default_interval_s")]
    pub interval_s: u64,
    /// Accept invalid/untrusted TLS certificates from the RouterOS API
    /// (default false; enable only for self-signed router certificates).
    #[serde(default)]
    pub allow_invalid_certs: bool,
}

fn default_url() -> String {
    "https://192.168.1.1".to_string()
}

fn default_interval_s() -> u64 {
    300
}

impl Default for RouterOsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_url(),
            token_env: Some("MIKROTIK_API_TOKEN".to_string()),
            username: None,
            password: None,
            password_env: None,
            interval_s: default_interval_s(),
            allow_invalid_certs: false,
        }
    }
}

/// Maximum accepted RouterOS REST response size (1 MiB). Lease tables for
/// even large networks fit comfortably; a larger body is treated as an error
/// instead of being buffered into memory.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Errors occurring during RouterOS lease synchronization.
#[derive(Debug, Error)]
pub enum RouterOsError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    #[error("RouterOS returned HTTP status {0}: {1}")]
    BadStatus(StatusCode, String),

    #[error("RouterOS response exceeds the {limit}-byte limit")]
    ResponseTooLarge { limit: usize },

    #[error("JSON deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Raw lease schema from RouterOS REST API (`/rest/ip/dhcp-server/lease`).
#[derive(Debug, Clone, Deserialize)]
pub struct RawRouterOsLease {
    #[serde(default, alias = "address", alias = "ip")]
    pub address: Option<String>,

    #[serde(default, rename = "mac-address", alias = "mac_address", alias = "mac")]
    pub mac_address: Option<String>,

    #[serde(default, rename = "host-name", alias = "hostname", alias = "host_name")]
    pub host_name: Option<String>,

    #[serde(default)]
    pub comment: Option<String>,

    #[serde(default)]
    pub status: Option<String>,

    #[serde(default)]
    pub disabled: Option<serde_json::Value>,
}

impl RawRouterOsLease {
    pub fn into_lease(self) -> Option<RouterOsLease> {
        // Filter out explicitly disabled leases
        if let Some(ref d) = self.disabled
            && (d.as_bool() == Some(true) || d.as_str() == Some("true"))
        {
            return None;
        }

        let mac_raw = self.mac_address?;
        let mac = normalize_mac(&mac_raw)?;
        let ip = self.address.and_then(|addr| {
            let clean = addr.split('/').next().unwrap_or(&addr);
            IpAddr::from_str(clean).ok()
        });

        Some(RouterOsLease {
            mac,
            ip,
            hostname: self.host_name.filter(|h| !h.trim().is_empty()),
            comment: self.comment.filter(|c| !c.trim().is_empty()),
        })
    }
}

/// Fetch and parse DHCP leases from RouterOS REST API.
pub async fn fetch_routeros_leases(
    client: &reqwest::Client,
    config: &RouterOsConfig,
) -> Result<Vec<RouterOsLease>, RouterOsError> {
    let endpoint = if config.url.ends_with("/rest/ip/dhcp-server/lease") {
        config.url.clone()
    } else {
        format!(
            "{}/rest/ip/dhcp-server/lease",
            config.url.trim_end_matches('/')
        )
    };

    let mut req = client.get(&endpoint);

    // Authentication: check token_env first; if present in env, use bearer auth,
    // otherwise fall through to username/password basic auth.
    let mut authenticated = false;
    if let Some(ref token_key) = config.token_env
        && let Ok(token) = std::env::var(token_key)
        && !token.trim().is_empty()
    {
        req = req.bearer_auth(token.trim());
        authenticated = true;
    }

    if !authenticated && let Some(ref username) = config.username {
        let password = if let Some(ref pwd_env) = config.password_env {
            std::env::var(pwd_env).unwrap_or_default()
        } else {
            config.password.clone().unwrap_or_default()
        };
        req = req.basic_auth(username, Some(&password));
    }

    let response = req.send().await?;
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(RouterOsError::BadStatus(status, text));
    }

    let body = read_capped_body(response, MAX_RESPONSE_BYTES).await?;
    let raw_leases: Vec<RawRouterOsLease> = serde_json::from_slice(&body)?;
    let leases = raw_leases
        .into_iter()
        .filter_map(RawRouterOsLease::into_lease)
        .collect();

    Ok(leases)
}

/// Streams an HTTP body into memory while enforcing a hard byte cap.
///
/// `Content-Length` is checked up front and chunked/streamed bodies are
/// counted as they arrive, so neither a lied-about length nor a chunked
/// response can exhaust memory.
async fn read_capped_body(
    response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, RouterOsError> {
    if let Some(length) = response.content_length()
        && length > limit as u64
    {
        return Err(RouterOsError::ResponseTooLarge { limit });
    }

    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(RouterOsError::ResponseTooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Background task synchronizing RouterOS DHCP leases periodically.
pub fn spawn_routeros_sync(
    config: RouterOsConfig,
    registry: Arc<ClientRegistry>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if !config.enabled {
            return;
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(config.allow_invalid_certs)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let interval = Duration::from_secs(config.interval_s.max(5));
        let mut ticker = tokio::time::interval(interval);

        loop {
            tokio::select! {
                res = shutdown_rx.changed() => {
                    match res {
                        Ok(()) if *shutdown_rx.borrow() => {
                            info!("RouterOS DHCP lease sync task shutting down");
                            break;
                        }
                        Ok(()) => {}
                        Err(_) => break,
                    }
                }
                _ = ticker.tick() => {
                    match fetch_routeros_leases(&client, &config).await {
                        Ok(leases) => {
                            info!(count = leases.len(), "Synced RouterOS DHCP leases");
                            registry.update_routeros_leases(leases);
                        }
                        Err(err) => {
                            warn!(error = %err, "Failed to sync RouterOS DHCP leases; retaining previous leases");
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientsConfig;
    use sito_core::ClientContext;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_routeros_fetch_and_graceful_degradation() {
        // Start a mock HTTP server on random local port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn mock RouterOS responder
        tokio::spawn(async move {
            // Request 1: successful 200 OK with RouterOS JSON lease payload
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;

                let body = r#"[
                    {
                        ".id": "*1",
                        "address": "192.168.1.150",
                        "mac-address": "AA:BB:CC:DD:EE:01",
                        "host-name": "alice-laptop",
                        "comment": "Alice Laptop",
                        "status": "bound",
                        "disabled": "false"
                    },
                    {
                        ".id": "*2",
                        "address": "192.168.1.151",
                        "mac-address": "AA:BB:CC:DD:EE:02",
                        "host-name": "bob-phone",
                        "status": "bound",
                        "disabled": false
                    },
                    {
                        ".id": "*3",
                        "address": "192.168.1.152",
                        "mac-address": "AA:BB:CC:DD:EE:03",
                        "disabled": "true"
                    }
                ]"#;

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }

            // Request 2: simulated router error 500 Internal Error
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;

                let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let config = RouterOsConfig {
            enabled: true,
            url: format!("http://127.0.0.1:{port}"),
            token_env: None,
            username: Some("admin".to_string()),
            password: Some("secret".to_string()),
            password_env: None,
            interval_s: 300,
            allow_invalid_certs: false,
        };

        let client = reqwest::Client::new();
        let leases = fetch_routeros_leases(&client, &config)
            .await
            .expect("Fetch leases should succeed");

        // Disabled lease *3 should be filtered out, leaving 2 active leases
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(
            leases[0].ip,
            Some(IpAddr::from_str("192.168.1.150").unwrap())
        );
        assert_eq!(leases[0].hostname.as_deref(), Some("alice-laptop"));
        assert_eq!(leases[0].comment.as_deref(), Some("Alice Laptop"));

        // Update ClientRegistry with these leases
        let registry = Arc::new(ClientRegistry::new(ClientsConfig::default()));
        registry.update_routeros_leases(leases);

        // Verify client identification by IP using RouterOS lease
        let mut ctx = ClientContext::new(IpAddr::from_str("192.168.1.150").unwrap());
        let _policy = registry.resolve(&mut ctx, chrono::Utc::now());

        // The MAC learned from the lease is populated, but the client-chosen
        // DHCP hostname is not trusted for identity by default.
        assert_eq!(ctx.mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(ctx.client_name, None);

        // Second request should fail with 500 BadStatus (graceful degradation)
        let err = fetch_routeros_leases(&client, &config)
            .await
            .expect_err("Should fail with 500");
        match err {
            RouterOsError::BadStatus(status, _) => {
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            }
            other => panic!("Unexpected error: {other:?}"),
        }

        // Previous leases are retained in registry
        let mut ctx2 = ClientContext::new(IpAddr::from_str("192.168.1.151").unwrap());
        let _policy2 = registry.resolve(&mut ctx2, chrono::Utc::now());
        assert_eq!(ctx2.mac.as_deref(), Some("aa:bb:cc:dd:ee:02"));
        assert_eq!(ctx2.client_name, None);
    }

    #[test]
    fn test_routeros_tls_verification_is_on_by_default() {
        let config = RouterOsConfig::default();
        assert!(
            !config.allow_invalid_certs,
            "TLS verification must be enabled unless explicitly opted out"
        );
    }

    #[tokio::test]
    async fn test_routeros_oversized_response_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                // Announce a body larger than the cap but never send it; the
                // client must reject based on Content-Length alone.
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    MAX_RESPONSE_BYTES + 1
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let config = RouterOsConfig {
            enabled: true,
            url: format!("http://127.0.0.1:{port}"),
            token_env: None,
            username: None,
            password: None,
            password_env: None,
            interval_s: 300,
            allow_invalid_certs: false,
        };

        let err = fetch_routeros_leases(&reqwest::Client::new(), &config)
            .await
            .expect_err("oversized body must be rejected");
        assert!(
            matches!(err, RouterOsError::ResponseTooLarge { limit } if limit == MAX_RESPONSE_BYTES),
            "unexpected error: {err:?}"
        );
    }
}
