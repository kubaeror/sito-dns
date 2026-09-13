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
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| UpstreamError::BadResponse(format!("invalid DoH URL '{url}': {e}")))?;
        if parsed.scheme() != "https" {
            return Err(UpstreamError::BadResponse(format!(
                "DoH upstream URL must use https:// (got '{}')",
                parsed.scheme()
            )));
        }
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

    /// Constructs an upstream from a caller-provided HTTP client (used by tests
    /// and custom TLS configurations).
    ///
    /// The caller is responsible for disabling redirects on the supplied client
    /// (`redirect(reqwest::redirect::Policy::none())`); `new` does so itself.
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

    #[tokio::test]
    async fn test_doh_post_success_and_validation() {
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
