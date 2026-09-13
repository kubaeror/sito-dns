//! HTTP security middleware: baseline security headers, Origin/Referer checks
//! and session-bound CSRF tokens.

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, HOST, ORIGIN, REFERER, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::{IpAddr, SocketAddr};
use subtle::ConstantTimeEq;

use crate::auth::client_ip::is_https_request;
use crate::auth::session::extract_session_cookie;
use crate::error::ProblemDetails;
use crate::state::ServerContext;

/// Maximum accepted form body when the CSRF middleware needs to inspect it.
pub const MAX_CSRF_FORM_BODY: usize = 256 * 1024;

/// Header used by the UI to echo the session-bound CSRF token.
pub const CSRF_HEADER: &str = "x-csrf-token";

fn peer_addr(request: &Request) -> Option<SocketAddr> {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0)
}

/// Returns true for responses that must never be cached (auth/config/session
/// state and anything that sets a cookie).
fn is_sensitive_path(path: &str) -> bool {
    path.starts_with("/api/v1/auth")
        || path.starts_with("/api/v1/config")
        || path.starts_with("/api/v1/system")
        || path.starts_with("/ui/login")
        || path.starts_with("/ui/logout")
        || path.starts_with("/ui/wizard")
        || path == "/login"
        || path == "/wizard"
}

/// Adds baseline security headers to every response.
pub async fn security_headers_middleware(
    State(ctx): State<ServerContext>,
    request: Request,
    next: Next,
) -> Response {
    let config = ctx.config.load();
    let trusted_proxies = config.get_web_config().trusted_proxies.clone();
    let tls_enabled = config.get_tls_config().is_some();
    let peer = peer_addr(&request);
    let is_https = is_https_request(peer, request.headers(), &trusted_proxies, tls_enabled);
    let path = request.uri().path().to_string();

    let mut response = next.run(request).await;

    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    // Swagger UI ships its own inline bootstrap script; keep a documented
    // exception for the documentation path only.
    let csp = if path.starts_with("/api/docs") {
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
         style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; \
         connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; \
         form-action 'self'; object-src 'none'"
    } else {
        // `'unsafe-eval'` is required by the bundled Alpine.js and HTMX builds
        // (x-data expressions and hx-on handlers); inline scripts and inline
        // event handlers were removed from the templates so `'unsafe-inline'`
        // is not needed for scripts. `style-src 'unsafe-inline'` remains a
        // documented exception for the inline `style=` attributes used by the
        // existing markup.
        "default-src 'self'; script-src 'self' 'unsafe-eval'; \
         style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; \
         connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; \
         form-action 'self'; object-src 'none'"
    };
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_str(csp).unwrap_or(HeaderValue::from_static("default-src 'self'")),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=(), payment=(), usb=()"),
    );
    headers.insert(
        HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );
    if is_https {
        headers.insert(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    if is_sensitive_path(&path) || headers.contains_key(SET_COOKIE) {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }

    response
}

fn reject(detail: &'static str) -> Response {
    ProblemDetails::forbidden(detail).into_response()
}

/// Extracts `scheme` and `authority` from an absolute URL such as
/// `https://example.com:8443/path`.
fn split_origin(value: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = value.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    // Strip userinfo if present.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if host.is_empty() {
        return None;
    }
    Some((scheme, host))
}

/// The authority the server believes the client used, derived from the Host
/// header (or `X-Forwarded-Host` when the peer is a trusted proxy).
fn expected_authority(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted_proxies: &[IpAddr],
) -> Option<String> {
    let peer_trusted = peer.is_some_and(|addr| trusted_proxies.contains(&addr.ip()));
    if peer_trusted
        && let Some(forwarded) = headers.get("x-forwarded-host")
        && let Ok(value) = forwarded.to_str()
        && let Some(first) = value.split(',').next()
        && !first.trim().is_empty()
    {
        return Some(first.trim().to_string());
    }
    headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.trim().to_string())
}

/// Normalizes an authority by removing the default port for the scheme.
fn normalize_authority(authority: &str, scheme: &str) -> String {
    let authority = authority.to_ascii_lowercase();
    if scheme.eq_ignore_ascii_case("https") {
        authority
            .strip_suffix(":443")
            .unwrap_or(&authority)
            .to_string()
    } else if scheme.eq_ignore_ascii_case("http") {
        authority
            .strip_suffix(":80")
            .unwrap_or(&authority)
            .to_string()
    } else {
        authority
    }
}

/// True when `value` (Origin or Referer URL) refers to the same origin as the
/// request, using only proxy headers supplied by configured trusted proxies.
fn same_origin(
    value: &str,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted_proxies: &[IpAddr],
    tls_enabled: bool,
) -> bool {
    let Some((scheme, authority)) = split_origin(value) else {
        return false;
    };
    let expected_scheme = if is_https_request(peer, headers, trusted_proxies, tls_enabled) {
        "https"
    } else {
        "http"
    };
    if !scheme.eq_ignore_ascii_case(expected_scheme) {
        return false;
    }
    let Some(expected) = expected_authority(headers, peer, trusted_proxies) else {
        return false;
    };
    normalize_authority(authority, scheme) == normalize_authority(&expected, expected_scheme)
}

/// Decodes a `application/x-www-form-urlencoded` field (percent-decoding and
/// `+`-as-space) so the CSRF token matches what Axum's `Form` extractor sees.
fn form_field(body: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    for pair in text.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(percent_decode(value).trim().to_string());
        }
    }
    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            // Decode on raw bytes: slicing a `str` here can land inside a
            // multi-byte UTF-8 sequence and panic the process (panic = abort).
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Extracts the CSRF token from the `X-CSRF-Token` header or (for
/// form-encoded bodies) the `csrf_token` form field. The body is buffered and
/// restored so downstream handlers still see it.
async fn extract_csrf_token(request: Request) -> Result<(Request, Option<String>), Box<Response>> {
    let header_token = request
        .headers()
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string);
    if let Some(header_value) = header_token {
        return Ok((request, Some(header_value)));
    }

    let is_form = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.to_ascii_lowercase()
                .starts_with("application/x-www-form-urlencoded")
        });
    if !is_form {
        return Ok((request, None));
    }

    let (parts, body) = request.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_CSRF_FORM_BODY).await else {
        return Err(Box::new(
            (StatusCode::PAYLOAD_TOO_LARGE, "CSRF form body too large").into_response(),
        ));
    };
    let token = form_field(&bytes, "csrf_token");
    Ok((Request::from_parts(parts, Body::from(bytes)), token))
}

/// Rejects cross-origin mutating requests and enforces session-bound CSRF
/// tokens for requests that authenticate via the session cookie.
///
/// * Browser/session requests must carry a matching `Origin` (or `Referer`)
///   and the session's CSRF token.
/// * Bearer-token requests are exempt from the double-submit token but a
///   supplied `Origin`/`Referer` must still match.
/// * `Origin: null` is always rejected.
pub async fn csrf_protection_middleware(
    State(ctx): State<ServerContext>,
    mut request: Request,
    next: Next,
) -> Response {
    let is_mutating = matches!(
        *request.method(),
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    );
    if !is_mutating {
        return next.run(request).await;
    }

    // HTTP/2 carries the authority in the request URI rather than a `Host`
    // header; normalize it so the Origin check has a comparable authority.
    if request.headers().get(HOST).is_none()
        && let Some(authority) = request.uri().authority().map(ToString::to_string)
        && let Ok(value) = HeaderValue::from_str(&authority)
    {
        request.headers_mut().insert(HOST, value);
    }

    let config = ctx.config.load();
    let trusted_proxies = config.get_web_config().trusted_proxies.clone();
    let tls_enabled = config.get_tls_config().is_some();
    let peer = peer_addr(&request);

    let session = request
        .headers()
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(extract_session_cookie)
        .and_then(|id| ctx.auth_mgr.validate_session(&id));

    let origin = request
        .headers()
        .get(ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    let referer = request
        .headers()
        .get(REFERER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim);

    if let Some(origin) = origin {
        if origin.eq_ignore_ascii_case("null") {
            return reject("Cross-origin request rejected (Origin: null)");
        }
        if !same_origin(
            origin,
            request.headers(),
            peer,
            &trusted_proxies,
            tls_enabled,
        ) {
            return reject("Cross-origin request rejected (CSRF protection)");
        }
    } else if session.is_some() {
        // Missing Origin on a browser session: fail closed. A valid `Referer`
        // is accepted as a fallback for older browsers. Bearer-token clients
        // (CLI/API) are not browser-ambient and may omit both.
        match referer {
            Some(referer)
                if same_origin(
                    referer,
                    request.headers(),
                    peer,
                    &trusted_proxies,
                    tls_enabled,
                ) => {}
            _ => {
                return reject("Missing Origin/Referer on mutating request (CSRF protection)");
            }
        }
    } else if let Some(referer) = referer
        && !same_origin(
            referer,
            request.headers(),
            peer,
            &trusted_proxies,
            tls_enabled,
        )
    {
        return reject("Cross-origin request rejected (CSRF protection)");
    }
    drop(config);

    // Session-bound double-submit token.
    if let Some(session) = session {
        let (request, token) = match extract_csrf_token(request).await {
            Ok(result) => result,
            Err(response) => return *response,
        };
        let expected = session.csrf_token.as_bytes();
        let supplied = token.as_deref().unwrap_or("").as_bytes();
        if expected.is_empty()
            || expected.len() != supplied.len()
            || !bool::from(expected.ct_eq(supplied))
        {
            return reject("CSRF token missing or invalid");
        }
        return next.run(request).await;
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::str::FromStr;

    fn headers_with_host(host: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_str(host).unwrap());
        headers
    }

    #[test]
    fn test_split_origin() {
        assert_eq!(
            split_origin("https://example.com/path"),
            Some(("https", "example.com"))
        );
        assert_eq!(
            split_origin("http://example.com:8080/x?y=1"),
            Some(("http", "example.com:8080"))
        );
        assert_eq!(split_origin("null"), None);
        assert_eq!(split_origin("not-a-url"), None);
    }

    #[test]
    fn test_same_origin_matching() {
        let headers = headers_with_host("example.com:8080");
        assert!(same_origin(
            "http://example.com:8080/dashboard",
            &headers,
            None,
            &[],
            false
        ));
        assert!(!same_origin(
            "http://evil.example.com:8080/",
            &headers,
            None,
            &[],
            false
        ));
        assert!(!same_origin(
            "https://example.com:8080/",
            &headers,
            None,
            &[],
            false
        ));
        assert!(!same_origin("null", &headers, None, &[], false));
        assert!(!same_origin(
            "http://example.com/",
            &headers,
            None,
            &[],
            false
        ));

        // Default ports are normalized.
        let headers = headers_with_host("example.com");
        assert!(same_origin(
            "http://example.com:80/",
            &headers,
            None,
            &[],
            false
        ));
        let headers = headers_with_host("example.com:443");
        assert!(same_origin(
            "https://example.com/",
            &headers,
            None,
            &[],
            true
        ));
    }

    #[test]
    fn test_forwarded_host_only_trusted_from_proxy() {
        let mut headers = headers_with_host("internal.local:8080");
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("dns.example.com"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));

        let proxy_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec![proxy_ip];
        let peer = SocketAddr::from_str("10.0.0.1:5555").unwrap();

        assert!(same_origin(
            "https://dns.example.com/",
            &headers,
            Some(peer),
            &trusted,
            false
        ));
        // Untrusted peer cannot use forwarded headers.
        assert!(!same_origin(
            "https://dns.example.com/",
            &headers,
            Some(SocketAddr::from_str("198.51.100.1:5555").unwrap()),
            &trusted,
            false
        ));
    }

    #[test]
    fn test_form_field_extraction() {
        let body = b"address=1.1.1.1&csrf_token=deadbeef&x=1";
        assert_eq!(form_field(body, "csrf_token"), Some("deadbeef".to_string()));
        assert_eq!(form_field(body, "missing"), None);
        assert_eq!(
            form_field(b"csrf_token=hello+world", "csrf_token"),
            Some("hello world".to_string())
        );
        assert_eq!(
            form_field(b"csrf_token=a%2Fb", "csrf_token"),
            Some("a/b".to_string())
        );
    }

    #[test]
    fn test_form_field_percent_decode_non_ascii_does_not_panic() {
        // Regression: a `%` followed by a multi-byte UTF-8 sequence used to
        // slice a `str` at a non-char-boundary and abort the process.
        assert_eq!(
            form_field("csrf_token=%€".as_bytes(), "csrf_token"),
            Some("%€".to_string())
        );
        assert_eq!(
            form_field("csrf_token=%é".as_bytes(), "csrf_token"),
            Some("%é".to_string())
        );
        // Truncated escape at the very end is preserved literally.
        assert_eq!(
            form_field(b"csrf_token=abc%", "csrf_token"),
            Some("abc%".to_string())
        );
        // Invalid hex falls through byte-by-byte.
        assert_eq!(
            form_field(b"csrf_token=%zz", "csrf_token"),
            Some("%zz".to_string())
        );
    }

    #[test]
    fn test_sensitive_paths() {
        assert!(is_sensitive_path("/api/v1/auth/login"));
        assert!(is_sensitive_path("/api/v1/config"));
        assert!(is_sensitive_path("/ui/login"));
        assert!(is_sensitive_path("/wizard"));
        assert!(!is_sensitive_path("/dashboard"));
        assert!(!is_sensitive_path("/static/app.js"));
    }
}
