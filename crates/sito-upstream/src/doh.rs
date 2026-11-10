//! DNS-over-HTTPS (DoH, RFC 8484) upstream transport.
//!
//! Sends `application/dns-message` requests over HTTP/2 (falling back to the
//! HTTP/1.1 GET form when the server rejects POST) and validates that the
//! response answers the outgoing query.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use tracing::trace;

use crate::upstream::{Upstream, validate_response};
use sito_core::error::UpstreamError;
use sito_proto::{Message, decode_message, encode_message};

/// Maximum accepted DoH response body (DNS-over-TCP size ceiling).
const MAX_DOH_RESPONSE_BYTES: usize = 65_535;

/// Default RFC 8484 path used when an operator configures a bare
/// `https://host` target.
pub(crate) const DEFAULT_DOH_PATH: &str = "/dns-query";

/// Parses and normalizes a DoH URL.
///
/// A bare `https://host` (or `https://host/`) is completed to
/// `https://host/dns-query`. Without this the manager's parsed default path
/// would be discarded and POSTs would be sent to `/`.
fn normalize_doh_url(url: &str) -> Result<reqwest::Url, UpstreamError> {
    let mut parsed = reqwest::Url::parse(url)
        .map_err(|e| UpstreamError::BadResponse(format!("invalid DoH URL '{url}': {e}")))?;
    if parsed.scheme() != "https" {
        return Err(UpstreamError::BadResponse(format!(
            "DoH upstream URL must use https:// (got '{}')",
            parsed.scheme()
        )));
    }
    if parsed.host_str().is_none() {
        return Err(UpstreamError::BadResponse(format!(
            "DoH URL '{url}' has no host"
        )));
    }
    if parsed.path().is_empty() || parsed.path() == "/" {
        parsed.set_path(DEFAULT_DOH_PATH);
    }
    Ok(parsed)
}

/// A DNS-over-HTTPS upstream (RFC 8484).
pub struct HttpsUpstream {
    url: reqwest::Url,
    client: reqwest::Client,
}

impl std::fmt::Debug for HttpsUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsUpstream")
            .field("url", &self.url.as_str())
            .finish_non_exhaustive()
    }
}

impl HttpsUpstream {
    /// Creates a DoH upstream that connects to `resolved_ips` while preserving
    /// the URL hostname for TLS SNI/Host validation.
    pub fn new(
        url: &str,
        resolved_ips: &[IpAddr],
        timeout_duration: Duration,
    ) -> Result<Self, UpstreamError> {
        let parsed = normalize_doh_url(url)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| UpstreamError::BadResponse(format!("DoH URL '{url}' has no host")))?
            .to_string();
        let port = parsed.port_or_known_default().unwrap_or(443);

        let mut builder = reqwest::Client::builder()
            .timeout(timeout_duration)
            .user_agent(concat!("sito/", env!("CARGO_PKG_VERSION")))
            // Never follow redirects: a malicious/compromised upstream must not
            // be able to exfiltrate DNS queries to arbitrary hosts.
            .redirect(reqwest::redirect::Policy::none())
            // Do not use ambient HTTP(S)_PROXY settings: a system proxy would
            // bypass `resolve_to_addrs` pinning and could see every DNS query.
            .no_proxy()
            .pool_max_idle_per_host(4);
        if !resolved_ips.is_empty() {
            let addrs: Vec<SocketAddr> = resolved_ips
                .iter()
                .map(|ip| SocketAddr::new(*ip, port))
                .collect();
            builder = builder.resolve_to_addrs(&host, &addrs);
        }
        let client = builder
            .build()
            .map_err(|e| UpstreamError::BadResponse(format!("failed to build DoH client: {e}")))?;

        Ok(Self {
            url: parsed,
            client,
        })
    }

    /// Constructs an upstream from a caller-provided HTTP client.
    ///
    /// This is intended for tests and custom TLS configurations; production
    /// callers should use [`HttpsUpstream::new`]. It deliberately bypasses the
    /// production client setup:
    ///
    /// - the URL is parsed as-is, so a bare `https://host` is **not** completed
    ///   to `/dns-query` (`normalize_doh_url` is skipped);
    /// - the supplied client decides proxy and address-pinning behavior. In
    ///   particular this does **not** call `.no_proxy()` or
    ///   `.resolve_to_addrs()`, so ambient `HTTP(S)_PROXY` settings can redirect
    ///   DNS queries;
    /// - the caller must also disable redirects
    ///   (`redirect(reqwest::redirect::Policy::none())`); `new` does so itself.
    #[must_use]
    pub fn with_client(url: &str, client: reqwest::Client, _timeout_duration: Duration) -> Self {
        Self {
            url: reqwest::Url::parse(url).expect("valid DoH URL"),
            client,
        }
    }

    async fn post(&self, msg: &Message) -> Result<Message, UpstreamError> {
        let encoded = encode_message(msg).map_err(|e| UpstreamError::BadResponse(e.to_string()))?;
        let response = self
            .client
            .post(self.url.clone())
            .header(CONTENT_TYPE, "application/dns-message")
            .header(ACCEPT, "application/dns-message")
            .body(encoded)
            .send()
            .await
            .map_err(|e| UpstreamError::Io(e.to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::METHOD_NOT_ALLOWED
            || status == reqwest::StatusCode::NOT_IMPLEMENTED
        {
            return Err(UpstreamError::Unsupported);
        }
        if !status.is_success() {
            return Err(UpstreamError::BadResponse(format!(
                "DoH upstream returned HTTP {status}"
            )));
        }

        Self::decode_response(response, msg).await
    }

    async fn get(&self, msg: &Message) -> Result<Message, UpstreamError> {
        // RFC 8484 section 4.1: GET queries are sent with ID 0.
        let mut query = msg.clone();
        query.metadata.id = 0;
        let encoded =
            encode_message(&query).map_err(|e| UpstreamError::BadResponse(e.to_string()))?;
        let dns_param = URL_SAFE_NO_PAD.encode(encoded);
        let mut url = self.url.clone();
        url.query_pairs_mut().append_pair("dns", &dns_param);

        let response = self
            .client
            .get(url)
            .header(ACCEPT, "application/dns-message")
            .send()
            .await
            .map_err(|e| UpstreamError::Io(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            return Err(UpstreamError::BadResponse(format!(
                "DoH upstream returned HTTP {status} for GET"
            )));
        }

        // Validate against the wire query (ID 0), then restore the caller's ID.
        // Validating against `msg` before restoring would always fail on ID.
        let mut decoded = Self::decode_response(response, &query).await?;
        decoded.metadata.id = msg.metadata.id;
        Ok(decoded)
    }

    async fn decode_response(
        response: reqwest::Response,
        query: &Message,
    ) -> Result<Message, UpstreamError> {
        // RFC 8484 section 4.2: the response MUST carry the DNS media type.
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let mime = content_type.split(';').next().unwrap_or("").trim();
        if !mime.eq_ignore_ascii_case("application/dns-message") {
            return Err(UpstreamError::BadResponse(format!(
                "DoH upstream returned invalid Content-Type '{mime}'"
            )));
        }

        if let Some(len) = response.content_length()
            && len > MAX_DOH_RESPONSE_BYTES as u64
        {
            return Err(UpstreamError::BadResponse(format!(
                "DoH response body of {len} bytes exceeds the {MAX_DOH_RESPONSE_BYTES} byte limit"
            )));
        }

        // Stream the body with a hard cap so an upstream cannot make us buffer
        // an arbitrarily large response before the size check.
        let mut body: Vec<u8> = Vec::new();
        let mut response = response;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| UpstreamError::Io(e.to_string()))?
        {
            if body.len() + chunk.len() > MAX_DOH_RESPONSE_BYTES {
                return Err(UpstreamError::BadResponse(format!(
                    "DoH response body exceeds the {MAX_DOH_RESPONSE_BYTES} byte limit"
                )));
            }
            body.extend_from_slice(&chunk);
        }

        let message = decode_message(&body)
            .map_err(|e| UpstreamError::BadResponse(format!("invalid DoH response: {e}")))?;
        validate_response(query, &message)?;
        Ok(message)
    }
}

#[async_trait::async_trait]
impl Upstream for HttpsUpstream {
    async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
        trace!(url = %self.url, "Sending DNS query over DoH");
        match self.post(msg).await {
            Ok(response) => Ok(response),
            Err(UpstreamError::Unsupported) => {
                trace!(url = %self.url, "DoH POST unsupported; retrying with GET");
                self.get(msg).await
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sito_proto::{MessageType, OpCode, Query, RecordType};
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn make_query(id: u16) -> Message {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            sito_proto::Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        query
    }

    fn http_response(
        status: &str,
        content_type: Option<&str>,
        extra_header: Option<&str>,
        body: &[u8],
    ) -> Vec<u8> {
        let mut head = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if let Some(ct) = content_type {
            head.push_str("Content-Type: ");
            head.push_str(ct);
            head.push_str("\r\n");
        }
        if let Some(extra) = extra_header {
            head.push_str(extra);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        let mut out = head.into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// Minimal one-shot-per-connection HTTP/1.1 server driven by a responder
    /// closure that receives the request head (request line + headers).
    async fn spawn_http_server(
        responder: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static,
    ) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = Arc::new(responder);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let responder = Arc::clone(&responder);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 2048];
                    let header_end = loop {
                        let Ok(n) = stream.read(&mut tmp).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let content_length: usize = head
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    while buf.len() < header_end + content_length {
                        let Ok(n) = stream.read(&mut tmp).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let response = responder(&head);
                    let _ = stream.write_all(&response).await;
                    let _ = stream.flush().await;
                });
            }
        });
        addr
    }

    /// Minimal HTTP/1.1 server: POST returns an echo response, GET returns 405.
    async fn spawn_post_only_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 1024];
                    let header_end;
                    loop {
                        let Ok(n) = stream.read(&mut tmp).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = pos + 4;
                            break;
                        }
                    }

                    let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let content_length: usize = headers
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    let mut body = buf[header_end..].to_vec();
                    while body.len() < content_length {
                        let Ok(n) = stream.read(&mut tmp).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        body.extend_from_slice(&tmp[..n]);
                    }

                    let query = decode_message(&body).expect("valid query");
                    let mut resp =
                        Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                    resp.metadata.response_code = sito_proto::ResponseCode::NoError;
                    resp.queries = query.queries.clone();
                    let encoded = encode_message(&resp).unwrap();
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        encoded.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&encoded).await;
                    let _ = stream.flush().await;
                });
            }
        });
        addr
    }

    /// Serializes tests that mutate process-wide proxy environment variables.
    static DOH_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Restores a proxy-related environment variable when dropped.
    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: the owning test holds DOH_TEST_LOCK, and no other test in
            // this binary builds an HTTPS reqwest client concurrently.
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: see `set`.
            unsafe { std::env::remove_var(key) };
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: see `set`.
            unsafe {
                match self.previous.take() {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    /// Binds a listener that counts accepted connections. Accepted sockets are
    /// dropped immediately so a proxied client fails fast instead of hanging.
    async fn spawn_counting_listener() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&count);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });
        (addr, count)
    }

    /// Important 1: production DoH must ignore ambient HTTPS proxy settings.
    /// Otherwise a system proxy would receive every DNS query and bypass the
    /// `resolve_to_addrs` pinning.
    #[tokio::test]
    async fn test_doh_new_ignores_ambient_https_proxy() {
        let _serial = DOH_TEST_LOCK.lock().await;
        let (proxy_addr, proxy_connections) = spawn_counting_listener().await;
        let (target_addr, target_connections) = spawn_counting_listener().await;

        let _proxy = EnvGuard::set("HTTPS_PROXY", format!("http://{proxy_addr}"));
        let _all_proxy = EnvGuard::set("ALL_PROXY", format!("http://{proxy_addr}"));
        let _lower_proxy = EnvGuard::set("https_proxy", format!("http://{proxy_addr}"));
        let _no_proxy = EnvGuard::remove("NO_PROXY");
        let _no_proxy_lower = EnvGuard::remove("no_proxy");

        let upstream = HttpsUpstream::new(
            &format!("https://127.0.0.1:{}/dns-query", target_addr.port()),
            &[IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            Duration::from_millis(500),
        )
        .expect("DoH client");

        // The target is a plain TCP listener, so the TLS handshake fails; the
        // important assertion is *where* the connection went.
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            upstream.resolve(&make_query(0x5151)),
        )
        .await;

        assert_eq!(
            proxy_connections.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "production DoH must not use an ambient HTTPS proxy"
        );
        assert!(
            target_connections.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "the DoH request must connect directly to the pinned target"
        );
    }

    #[tokio::test]
    async fn test_doh_bare_host_uses_default_dns_query_path() {
        let _serial = DOH_TEST_LOCK.lock().await;
        let upstream = HttpsUpstream::new("https://dns.example", &[], Duration::from_secs(1))
            .expect("bare DoH URL must be accepted");
        assert!(
            format!("{upstream:?}").contains("https://dns.example/dns-query"),
            "pathless DoH targets must use /dns-query: {upstream:?}"
        );
    }

    #[tokio::test]
    async fn test_doh_post_success_and_validation() {
        let _serial = DOH_TEST_LOCK.lock().await;
        let addr = spawn_post_only_server().await;
        let upstream = HttpsUpstream::with_client(
            &format!("http://{addr}/dns-query"),
            reqwest::Client::new(),
            Duration::from_secs(2),
        );

        let query = make_query(0x1234);
        let resp = upstream
            .resolve(&query)
            .await
            .expect("DoH POST should succeed");
        assert_eq!(resp.metadata.id, 0x1234);
        assert_eq!(resp.queries.len(), 1);
    }

    #[tokio::test]
    async fn test_doh_response_id_mismatch_rejected() {
        let _serial = DOH_TEST_LOCK.lock().await;
        // Server responds with a different ID than requested.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let Ok(n) = stream.read(&mut tmp).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let query = make_query(0x1234);
            let mut resp = Message::new(0x9999, MessageType::Response, OpCode::Query);
            resp.queries = query.queries.clone();
            let encoded = encode_message(&resp).unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                encoded.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&encoded).await;
        });

        let upstream = HttpsUpstream::with_client(
            &format!("http://{addr}/dns-query"),
            reqwest::Client::new(),
            Duration::from_secs(2),
        );
        let err = upstream.resolve(&make_query(0x1234)).await.unwrap_err();
        assert!(matches!(err, UpstreamError::BadResponse(_)));
    }

    #[tokio::test]
    async fn test_doh_get_fallback_validates_and_restores_id() {
        let _serial = DOH_TEST_LOCK.lock().await;
        // POST is rejected with 405; the GET form must then succeed even
        // though the wire query uses ID 0 and the caller's ID is non-zero.
        let addr = spawn_http_server(|head| {
            if head.starts_with("POST") {
                return http_response(
                    "405 Method Not Allowed",
                    Some("application/dns-message"),
                    None,
                    b"",
                );
            }
            let request_line = head.lines().next().unwrap_or("");
            assert!(
                request_line.starts_with("GET "),
                "expected GET: {request_line}"
            );
            let dns_param = request_line
                .split("dns=")
                .nth(1)
                .expect("dns parameter")
                .split(' ')
                .next()
                .unwrap();
            let wire = URL_SAFE_NO_PAD.decode(dns_param).expect("base64url");
            let query = decode_message(&wire).expect("valid query");
            assert_eq!(query.metadata.id, 0, "RFC 8484 GET queries use ID 0");
            let mut resp = Message::new(0, MessageType::Response, OpCode::Query);
            resp.queries = query.queries.clone();
            let body = encode_message(&resp).unwrap();
            http_response("200 OK", Some("application/dns-message"), None, &body)
        })
        .await;

        let upstream = HttpsUpstream::with_client(
            &format!("http://{addr}/dns-query"),
            reqwest::Client::new(),
            Duration::from_secs(2),
        );

        let query = make_query(0x2222);
        let resp = upstream
            .resolve(&query)
            .await
            .expect("DoH GET fallback must succeed");
        assert_eq!(resp.metadata.id, 0x2222, "caller ID must be restored");
        assert_eq!(resp.queries.len(), 1);
    }

    #[tokio::test]
    async fn test_doh_redirects_are_not_followed() {
        let _serial = DOH_TEST_LOCK.lock().await;
        let addr = spawn_http_server(|_head| {
            http_response(
                "302 Found",
                Some("text/plain"),
                Some("Location: http://127.0.0.1:1/dns-query\r\n"),
                b"",
            )
        })
        .await;

        // Mirror the production client configuration from `HttpsUpstream::new`.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let upstream = HttpsUpstream::with_client(
            &format!("http://{addr}/dns-query"),
            client,
            Duration::from_secs(2),
        );
        let err = upstream.resolve(&make_query(0x3333)).await.unwrap_err();
        // A followed redirect would surface as an I/O error from the unreachable
        // target; the raw HTTP error proves the redirect policy is disabled.
        assert!(
            matches!(err, UpstreamError::BadResponse(ref msg) if msg.contains("302")),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_doh_missing_content_type_rejected() {
        let _serial = DOH_TEST_LOCK.lock().await;
        let addr = spawn_http_server(|_head| {
            let body =
                encode_message(&Message::new(0, MessageType::Response, OpCode::Query)).unwrap();
            http_response("200 OK", None, None, &body)
        })
        .await;

        let upstream = HttpsUpstream::with_client(
            &format!("http://{addr}/dns-query"),
            reqwest::Client::new(),
            Duration::from_secs(2),
        );
        let err = upstream.resolve(&make_query(0x4444)).await.unwrap_err();
        assert!(matches!(err, UpstreamError::BadResponse(_)));
    }
}
