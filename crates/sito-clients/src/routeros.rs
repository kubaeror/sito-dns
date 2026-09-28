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
use tracing::{error, info, warn};

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

/// Request timeout applied to every RouterOS HTTP client.
pub const ROUTEROS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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

    #[error("failed to build the RouterOS HTTP client: {0}")]
    ClientBuild(String),

    #[error(
        "RouterOS password environment variable '{variable}' is not set or empty; \
         refusing to authenticate with an empty password"
    )]
    MissingPasswordEnv { variable: String },
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

        // Only active (`bound`) leases may identify clients. Waiting/offered/
        // expired/conflict leases still occupy an address (or none at all) and
        // must never grant a client entry's group/trusted policy. A lease with
        // no `status` field is rejected as unverifiable.
        let bound = self
            .status
            .as_deref()
            .is_some_and(|status| status.trim().eq_ignore_ascii_case("bound"));
        if !bound {
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
        let password = match config.password_env.as_deref() {
            // A configured env var that cannot be resolved is a configuration
            // error: never silently send an empty password.
            Some(variable) => std::env::var(variable)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(|value| value.trim().to_string())
                .ok_or_else(|| RouterOsError::MissingPasswordEnv {
                    variable: variable.to_string(),
                })?,
            None => config.password.clone().unwrap_or_default(),
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

/// Builds the RouterOS HTTP client with the configured TLS and timeout
/// settings.
///
/// A build failure is returned to the caller: it must never be papered over
/// with a default client that silently drops the 10-second timeout or the
/// `allow_invalid_certs` setting.
pub fn build_routeros_client(config: &RouterOsConfig) -> Result<reqwest::Client, RouterOsError> {
    build_routeros_client_with_timeout(config, ROUTEROS_REQUEST_TIMEOUT)
}

fn build_routeros_client_with_timeout(
    config: &RouterOsConfig,
    timeout: Duration,
) -> Result<reqwest::Client, RouterOsError> {
    reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(config.allow_invalid_certs)
        .build()
        .map_err(|e| RouterOsError::ClientBuild(e.to_string()))
}

/// Test seam: forces [`init_sync_client`] down the build-failure path.
#[cfg(test)]
static FORCE_CLIENT_BUILD_FAILURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Builds the client used by the lease-sync task, or reports the failure and
/// disables the task.
///
/// Unlike `reqwest::Client::new()`, this never panics and never drops the
/// configured timeout/TLS settings.
fn init_sync_client(config: &RouterOsConfig) -> Option<reqwest::Client> {
    #[cfg(test)]
    if FORCE_CLIENT_BUILD_FAILURE.load(std::sync::atomic::Ordering::SeqCst) {
        return report_client_build_failure(&RouterOsError::ClientBuild(
            "forced test failure".to_string(),
        ));
    }

    match build_routeros_client(config) {
        Ok(client) => Some(client),
        Err(err) => report_client_build_failure(&err),
    }
}

fn report_client_build_failure(err: &RouterOsError) -> Option<reqwest::Client> {
    error!(
        error = %err,
        "Failed to build the RouterOS HTTP client; DHCP lease sync is disabled"
    );
    None
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

        let Some(client) = init_sync_client(&config) else {
            return;
        };

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
        let _policy = registry.resolve(&mut ctx, registry.now());

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
        let _policy2 = registry.resolve(&mut ctx2, registry.now());
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

    #[test]
    fn test_routeros_only_bound_leases_identify_clients() {
        let raw = |status: Option<&str>| RawRouterOsLease {
            address: Some("192.168.1.10".to_string()),
            mac_address: Some("AA:BB:CC:DD:EE:0A".to_string()),
            host_name: Some("some-host".to_string()),
            comment: None,
            status: status.map(str::to_string),
            disabled: None,
        };

        assert!(
            raw(Some("bound")).into_lease().is_some(),
            "a bound lease must be usable"
        );
        assert!(
            raw(Some("BOUND")).into_lease().is_some(),
            "status comparison must be case-insensitive"
        );

        for status in [
            Some("waiting"),
            Some("offered"),
            Some("expired"),
            Some("busy"),
            Some("conflict"),
            None,
        ] {
            assert!(
                raw(status).into_lease().is_none(),
                "lease status {status:?} must not identify a client"
            );
        }
    }

    #[test]
    fn test_routeros_client_build_failure_is_not_replaced_by_a_default_client() {
        let config = RouterOsConfig {
            enabled: true,
            url: "http://127.0.0.1:1".to_string(),
            token_env: None,
            username: None,
            password: None,
            password_env: None,
            interval_s: 300,
            allow_invalid_certs: false,
        };

        // The happy path builds a client carrying the configured settings.
        assert!(init_sync_client(&config).is_some());

        // A build failure must abort the task instead of silently falling back
        // to `reqwest::Client::new()` (which drops the timeout/TLS settings and
        // can panic).
        FORCE_CLIENT_BUILD_FAILURE.store(true, std::sync::atomic::Ordering::SeqCst);
        let client = init_sync_client(&config);
        FORCE_CLIENT_BUILD_FAILURE.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(
            client.is_none(),
            "a failed client build must not be replaced by a default client"
        );
    }

    #[tokio::test]
    async fn test_routeros_client_applies_configured_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                // Accept the request but never answer it.
                tokio::time::sleep(Duration::from_secs(5)).await;
                let _ = socket.shutdown().await;
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

        // The production client uses ROUTEROS_REQUEST_TIMEOUT; a shortened
        // timeout proves the setting is applied to the client that fetches.
        let client = build_routeros_client_with_timeout(&config, Duration::from_millis(100))
            .expect("client must build");
        let err = fetch_routeros_leases(&client, &config)
            .await
            .expect_err("a stalled response must hit the configured timeout");
        assert!(
            matches!(err, RouterOsError::RequestFailed(ref e) if e.is_timeout()),
            "unexpected error: {err:?}"
        );
        assert_eq!(ROUTEROS_REQUEST_TIMEOUT, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn test_routeros_missing_password_env_errors_instead_of_empty_password() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let accepted_clone = Arc::clone(&accepted);

        tokio::spawn(async move {
            if listener.accept().await.is_ok() {
                accepted_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let config = RouterOsConfig {
            enabled: true,
            url: format!("http://127.0.0.1:{port}"),
            token_env: None,
            username: Some("admin".to_string()),
            password: Some("ignored-when-password-env-is-set".to_string()),
            password_env: Some("SITO_TEST_ROUTEROS_UNSET_PASSWORD".to_string()),
            interval_s: 300,
            allow_invalid_certs: false,
        };

        let err = fetch_routeros_leases(&reqwest::Client::new(), &config)
            .await
            .expect_err("an unresolvable password_env must be a config error");
        assert!(
            matches!(err, RouterOsError::MissingPasswordEnv { ref variable }
                if variable == "SITO_TEST_ROUTEROS_UNSET_PASSWORD"),
            "unexpected error: {err:?}"
        );

        // Never send a request with an empty password.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !accepted.load(std::sync::atomic::Ordering::SeqCst),
            "no request may be sent when password_env cannot be resolved"
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
