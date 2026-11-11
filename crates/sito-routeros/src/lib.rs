//! MikroTik RouterOS DHCP lease synchronization (M4.5), optional integration.
//!
//! This crate is compiled only when `sito` is built with `--features routeros`
//! and is not part of the default binary. (The default binary still links
//! `reqwest` for ACME and the self-updater; it does not link this RouterOS
//! client.) It queries the RouterOS REST API (>= 7.1) at
//! `GET /rest/ip/dhcp-server/lease` and synchronizes active DHCP leases into
//! `sito_clients::ClientRegistry`.
//!
//! The plain `RouterOsConfig` data type stays in `sito-clients` so the default
//! build keeps parsing `[integrations.mikrotik]`.
//!
//! Security bar (D15): no environment proxy, a hard cap on error bodies, no
//! silent token fallback, and leases fetched with TLS verification disabled
//! are marked unverified so they never identify clients.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use serde::Deserialize;
use thiserror::Error;
use tracing::{error, info, warn};

pub use sito_clients::RouterOsConfig;
use sito_clients::normalize_mac;
use sito_clients::{ClientRegistry, RouterOsLease};

/// Maximum accepted RouterOS REST response size (1 MiB). Lease tables for
/// even large networks fit comfortably; a larger body is treated as an error
/// instead of being buffered into memory.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Maximum accepted RouterOS error-body size. Error bodies are diagnostic
/// only; a hostile or misconfigured router must not be able to exhaust memory
/// through an unbounded `4xx`/`5xx` response.
const MAX_ERROR_BODY_BYTES: usize = 4 * 1024;

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

    #[error(
        "RouterOS token environment variable '{variable}' is not set or empty; \
         refusing to fall back to basic authentication (provide the token or \
         remove token_env to use username/password)"
    )]
    MissingTokenEnv { variable: String },
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
    /// Converts a raw REST row into a lease.
    ///
    /// `verified` is false when the API client was built with
    /// `allow_invalid_certs = true`; such leases are display-only (D10/D15).
    pub fn into_lease(self, verified: bool) -> Option<RouterOsLease> {
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
            verified,
        })
    }
}

/// Whether leases from this configuration may grant client identity.
///
/// Identity is only authenticated by an `https://` connection whose
/// certificate was verified. A plaintext `http://` URL has no peer
/// certificate (even when `allow_invalid_certs` is false), and a non-HTTP(S)
/// scheme is unsupported; both are display-only.
fn leases_are_verified(config: &RouterOsConfig) -> bool {
    if config.allow_invalid_certs {
        return false;
    }
    reqwest::Url::parse(&config.url).is_ok_and(|url| url.scheme() == "https")
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

    // Authentication: a configured token_env is mandatory. Falling through
    // to basic auth when the operator asked for a bearer token would silently
    // downgrade the configured credential.
    let mut authenticated = false;
    if let Some(ref token_key) = config.token_env {
        let token = std::env::var(token_key)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| RouterOsError::MissingTokenEnv {
                variable: token_key.clone(),
            })?;
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
        let text = match read_capped_body(response, MAX_ERROR_BODY_BYTES).await {
            Ok(body) => String::from_utf8_lossy(&body).into_owned(),
            Err(_) => format!("<error body omitted: exceeds {MAX_ERROR_BODY_BYTES} bytes>"),
        };
        return Err(RouterOsError::BadStatus(status, text));
    }

    let body = read_capped_body(response, MAX_RESPONSE_BYTES).await?;
    let raw_leases: Vec<RawRouterOsLease> = serde_json::from_slice(&body)?;
    // Only HTTPS with certificate verification authenticates the peer; a
    // plaintext URL or an insecure-TLS client is display-only (D10/D15).
    let verified = leases_are_verified(config);
    let leases = raw_leases
        .into_iter()
        .filter_map(|raw| raw.into_lease(verified))
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
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
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
        if !leases_are_verified(&config) {
            if config.allow_invalid_certs {
                warn!(
                    "RouterOS TLS verification is disabled (allow_invalid_certs = true); \
                     leases are display-only and will not identify clients"
                );
            } else {
                warn!(
                    url = %config.url,
                    "RouterOS URL does not use https; leases are display-only and will not identify clients"
                );
            }
        }

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
    use sito_clients::ClientsConfig;
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
        assert!(
            !leases[0].verified,
            "the mock URL is plaintext http://, so the leases are display-only"
        );

        // Update ClientRegistry with these leases
        let registry = Arc::new(ClientRegistry::new(ClientsConfig::default()));
        registry.update_routeros_leases(leases);

        // Verify client identification by IP using RouterOS lease
        let mut ctx = ClientContext::new(IpAddr::from_str("192.168.1.150").unwrap());
        let _policy = registry.resolve(&mut ctx, registry.now());

        // A plaintext HTTP lease must not populate identity. (Verified-lease
        // matching over HTTPS is covered by the registry unit tests.)
        assert_eq!(ctx.mac, None);
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
        assert_eq!(ctx2.mac, None);
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
            raw(Some("bound")).into_lease(true).is_some(),
            "a bound lease must be usable"
        );
        assert!(
            raw(Some("BOUND")).into_lease(true).is_some(),
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
                raw(status).into_lease(true).is_none(),
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

    #[tokio::test]
    async fn test_routeros_missing_token_env_errors_instead_of_basic_fallback() {
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
            token_env: Some("SITO_TEST_ROUTEROS_UNSET_TOKEN".to_string()),
            username: Some("admin".to_string()),
            password: Some("secret".to_string()),
            password_env: None,
            interval_s: 300,
            allow_invalid_certs: false,
        };

        let err = fetch_routeros_leases(&reqwest::Client::new(), &config)
            .await
            .expect_err("a configured but unresolved token_env must be an error");
        assert!(
            matches!(err, RouterOsError::MissingTokenEnv { ref variable }
                if variable == "SITO_TEST_ROUTEROS_UNSET_TOKEN"),
            "unexpected error: {err:?}"
        );

        // Never downgrade to basic auth (or send any request) when the
        // configured bearer token cannot be resolved.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !accepted.load(std::sync::atomic::Ordering::SeqCst),
            "no request may be sent when token_env cannot be resolved"
        );
    }

    #[tokio::test]
    async fn test_routeros_error_body_is_capped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                // Announce an error body larger than the diagnostic cap. It
                // must not be buffered into memory; the status error carries a
                // short omission marker instead.
                let resp = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    MAX_ERROR_BODY_BYTES + 1
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
            .expect_err("an error response must be returned as BadStatus");
        match err {
            RouterOsError::BadStatus(status, text) => {
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                assert!(
                    text.len() <= 128 && text.contains("omitted"),
                    "error body must be replaced by a short cap marker: {text:?}"
                );
            }
            other => panic!("Unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_routeros_plaintext_and_unverified_tls_never_grant_identity() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = r#"[
            {
                "address": "192.168.1.150",
                "mac-address": "AA:BB:CC:DD:EE:01",
                "status": "bound"
            }
        ]"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );

        tokio::spawn(async move {
            for _ in 0..2 {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket.write_all(response.as_bytes()).await;
                }
            }
        });

        let base = RouterOsConfig {
            enabled: true,
            url: format!("http://127.0.0.1:{port}"),
            token_env: None,
            username: None,
            password: None,
            password_env: None,
            interval_s: 300,
            allow_invalid_certs: false,
        };

        // A plaintext URL has no certificate to verify, even with
        // `allow_invalid_certs = false`: the peer identity is unauthenticated.
        let client = reqwest::Client::new();
        let plaintext = fetch_routeros_leases(&client, &base)
            .await
            .expect("first fetch");
        assert!(
            plaintext.iter().all(|lease| !lease.verified),
            "a plaintext http:// URL must never yield verified leases"
        );

        // `allow_invalid_certs = true` keeps the data for display but marks it
        // unverified so the registry cannot use it for identity (D10/D15).
        let insecure = RouterOsConfig {
            allow_invalid_certs: true,
            ..base
        };
        let unverified = fetch_routeros_leases(&client, &insecure)
            .await
            .expect("second fetch");
        assert!(
            unverified.iter().all(|lease| !lease.verified),
            "unverified TLS must never grant client identity"
        );
    }

    #[test]
    fn test_routeros_identity_requires_https_and_verified_certificates() {
        let https = RouterOsConfig {
            enabled: true,
            url: "https://router.lan".to_string(),
            token_env: None,
            username: None,
            password: None,
            password_env: None,
            interval_s: 300,
            allow_invalid_certs: false,
        };
        assert!(
            leases_are_verified(&https),
            "https:// with certificate verification must yield identity-capable leases"
        );

        let plaintext = RouterOsConfig {
            url: "http://router.lan".to_string(),
            ..https.clone()
        };
        assert!(
            !leases_are_verified(&plaintext),
            "plaintext http:// must never yield identity-capable leases"
        );

        let insecure_tls = RouterOsConfig {
            allow_invalid_certs: true,
            ..https.clone()
        };
        assert!(
            !leases_are_verified(&insecure_tls),
            "https:// with certificate verification disabled must not grant identity"
        );

        let unsupported = RouterOsConfig {
            url: "ftp://router.lan".to_string(),
            ..https
        };
        assert!(
            !leases_are_verified(&unsupported),
            "a non-HTTP(S) scheme must never grant identity"
        );
    }
}
