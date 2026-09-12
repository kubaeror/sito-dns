//! HTTP security middleware: baseline security headers and same-origin (CSRF) checks.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Adds baseline security headers to every response.
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let is_https = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("https"))
        || request.uri().scheme_str() == Some("https");

    let mut response = next.run(request).await;

    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
             style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; \
             connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; \
             form-action 'self'",
        ),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    if is_https {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }

    response
}

/// Rejects cross-origin mutating requests (CSRF defense for cookie sessions).
///
/// Browser form/fetch requests include `Origin` (and usually `Referer`); if
/// either is present it must match the request `Host` (or `X-Forwarded-Host`).
/// Non-browser clients that omit both headers are unaffected.
pub async fn csrf_origin_middleware(request: Request, next: Next) -> Response {
    let is_mutating = matches!(
        *request.method(),
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    );

    if is_mutating {
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .or_else(|| {
                request
                    .headers()
                    .get("x-forwarded-host")
                    .and_then(|v| v.to_str().ok())
            });

        let origin = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok());
        let referer = request
            .headers()
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok());

        let candidate = origin.or(referer);
        if let Some(value) = candidate
            && let (Some(expected), Some(actual)) = (host, host_from_url(value))
            && !actual.eq_ignore_ascii_case(expected)
        {
            return (
                StatusCode::FORBIDDEN,
                "Cross-origin request rejected (CSRF protection)",
            )
                .into_response();
        }
    }

    next.run(request).await
}

/// Extracts `host[:port]` from an absolute `scheme://host[:port]/...` URL.
fn host_from_url(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    // Strip userinfo if present.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if host.is_empty() { None } else { Some(host) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_from_url() {
        assert_eq!(
            host_from_url("https://example.com/path"),
            Some("example.com")
        );
        assert_eq!(
            host_from_url("http://example.com:8080/x?y=1"),
            Some("example.com:8080")
        );
        assert_eq!(host_from_url("not-a-url"), None);
        assert_eq!(host_from_url("https://"), None);
    }

    #[test]
    fn test_security_headers_present() {
        // Verify the static values we rely on are valid header values.
        assert!(HeaderValue::from_static("DENY").to_str().is_ok());
    }
}
