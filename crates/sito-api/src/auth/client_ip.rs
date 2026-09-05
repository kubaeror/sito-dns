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
/// Only trusts `X-Forwarded-For` if the direct peer address is in `trusted_proxies`.
/// If peer address is not available (e.g. mock test harnesses), `X-Forwarded-For`
/// will be used if present and valid, otherwise defaults to `"127.0.0.1"`.
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
            && let Some(first) = val.split(',').next()
        {
            let candidate = first.trim();
            if candidate.parse::<IpAddr>().is_ok() {
                return candidate.to_string();
            }
        }
        // Direct client or untrusted proxy
        return peer_ip.to_string();
    }

    // Direct unit test / test harness without socket
    if let Some(forwarded) = headers.get("x-forwarded-for")
        && let Ok(val) = forwarded.to_str()
        && let Some(first) = val.split(',').next()
    {
        let candidate = first.trim();
        if candidate.parse::<IpAddr>().is_ok() {
            return candidate.to_string();
        }
    }

    "127.0.0.1".to_string()
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
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 10.0.0.1"),
        );
        let proxy_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = SocketAddr::new(proxy_ip, 12345);
        let trusted = vec![proxy_ip];

        let ip = resolve_client_ip(Some(peer), &headers, &trusted);
        assert_eq!(ip, "1.2.3.4");
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
    fn test_no_connect_info_falls_back_to_forwarded_or_localhost() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.50"));
        let ip = resolve_client_ip(None, &headers, &[]);
        assert_eq!(ip, "192.168.1.50");

        let empty_headers = HeaderMap::new();
        let default_ip = resolve_client_ip(None, &empty_headers, &[]);
        assert_eq!(default_ip, "127.0.0.1");
    }
}
