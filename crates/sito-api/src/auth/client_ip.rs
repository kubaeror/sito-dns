//! Client IP resolution logic with trusted proxy validation.

use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use axum::http::request::Parts;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

/// Extractor for optional peer SocketAddr from Axum connection info.
#[derive(Debug, Clone, Copy, Default)]
pub struct MaybeConnectInfo(pub Option<SocketAddr>);

impl<S> axum::extract::FromRequestParts<S> for MaybeConnectInfo
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> {
        let addr = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0);
        std::future::ready(Ok(MaybeConnectInfo(addr)))
    }
}

/// Resolves the effective client IP address from optional peer address and HTTP headers.
///
/// `X-Forwarded-For` is only trusted when the direct peer address is in
/// `trusted_proxies`, and only the last (proxy-appended) entry is considered.
/// Without peer information the direct client cannot be authenticated, so
/// client-supplied forwarding headers are ignored entirely.
pub fn resolve_client_ip(
    peer_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[IpAddr],
) -> String {
    if let Some(peer) = peer_addr {
        let peer_ip = peer.ip();
        // If the peer is a trusted proxy, inspect X-Forwarded-For
        if trusted_proxies.contains(&peer_ip)
            && let Some(forwarded) = headers.get("x-forwarded-for")
            && let Ok(val) = forwarded.to_str()
        {
            // Reverse proxies append the client IP to X-Forwarded-For. Only the
            // last entry was written by the trusted proxy; earlier entries are
            // attacker-controlled and must never be used.
            if let Some(last) = val.rsplit(',').next() {
                let candidate = last.trim();
                if let Ok(ip) = candidate.parse::<IpAddr>() {
                    return ip.to_string();
                }
            }
        }
        // Direct client or untrusted proxy
        return peer_ip.to_string();
    }

    // No peer information available: do not trust client-supplied headers.
    "127.0.0.1".to_string()
}

/// Determines if the request arrived over HTTPS, either directly (if server is configured with TLS)
/// or via a trusted reverse proxy with `X-Forwarded-Proto: https`.
pub fn is_https_request(
    peer_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[IpAddr],
    tls_enabled: bool,
) -> bool {
    if tls_enabled {
        return true;
    }

    if let Some(peer) = peer_addr {
        if trusted_proxies.contains(&peer.ip())
            && let Some(proto) = headers.get("x-forwarded-proto")
            && let Ok(val) = proto.to_str()
        {
            return val.eq_ignore_ascii_case("https");
        }
    } else if let Some(proto) = headers.get("x-forwarded-proto")
        && let Ok(val) = proto.to_str()
    {
        return val.eq_ignore_ascii_case("https");
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::str::FromStr;

    #[test]
    fn test_untrusted_proxy_ignores_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 10.0.0.1"),
        );
        let peer = SocketAddr::from_str("198.51.100.2:12345").unwrap();
        let trusted: Vec<IpAddr> = vec![];

        let ip = resolve_client_ip(Some(peer), &headers, &trusted);
        assert_eq!(ip, "198.51.100.2");
    }

    #[test]
    fn test_trusted_proxy_uses_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.0.2.1"));
        let proxy_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = SocketAddr::new(proxy_ip, 12345);
        let trusted = vec![proxy_ip];

        let ip = resolve_client_ip(Some(peer), &headers, &trusted);
        assert_eq!(ip, "192.0.2.1");
    }

    #[test]
    fn test_trusted_proxy_prevents_client_spoofing_via_last_entry() {
        let mut headers = HeaderMap::new();
        // Client attempted to spoof 1.1.1.1, but trusted proxy appended real client IP 203.0.113.55
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.1.1.1, 203.0.113.55"),
        );
        let proxy_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = SocketAddr::new(proxy_ip, 12345);
        let trusted = vec![proxy_ip];

        let ip = resolve_client_ip(Some(peer), &headers, &trusted);
        assert_eq!(ip, "203.0.113.55");
    }

    #[test]
    fn test_trusted_proxy_fallback_to_peer_if_last_entry_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.42, not-an-ip"),
        );
        let proxy_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = SocketAddr::new(proxy_ip, 12345);
        let trusted = vec![proxy_ip];

        let ip = resolve_client_ip(Some(peer), &headers, &trusted);
        assert_eq!(ip, "10.0.0.1");
    }

    #[test]
    fn test_trusted_proxy_invalid_forwarded_falls_back_to_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        let proxy_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = SocketAddr::new(proxy_ip, 12345);
        let trusted = vec![proxy_ip];

        let ip = resolve_client_ip(Some(peer), &headers, &trusted);
        assert_eq!(ip, "10.0.0.1");
    }

    #[test]
    fn test_no_connect_info_ignores_forwarded_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.50"));
        let ip = resolve_client_ip(None, &headers, &[]);
        assert_eq!(ip, "127.0.0.1");

        let empty_headers = HeaderMap::new();
        let default_ip = resolve_client_ip(None, &empty_headers, &[]);
        assert_eq!(default_ip, "127.0.0.1");
    }

    #[test]
    fn test_is_https_request() {
        let empty_headers = HeaderMap::new();
        assert!(!is_https_request(None, &empty_headers, &[], false));
        assert!(is_https_request(None, &empty_headers, &[], true));

        let mut https_headers = HeaderMap::new();
        https_headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(is_https_request(None, &https_headers, &[], false));

        let proxy_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = SocketAddr::new(proxy_ip, 12345);
        // Untrusted proxy
        assert!(!is_https_request(Some(peer), &https_headers, &[], false));
        // Trusted proxy
        assert!(is_https_request(
            Some(peer),
            &https_headers,
            &[proxy_ip],
            false
        ));
    }
}
