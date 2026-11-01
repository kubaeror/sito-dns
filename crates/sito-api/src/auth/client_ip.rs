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

/// Explicit admin-transport scheme settings read from the raw `[web]` table.
///
/// The admin UI is served over plain HTTP by axum; TLS is terminated either by
/// an explicit `web.public_url` declaration or by a reverse proxy in front of
/// it. The DNS TLS material (`[tls]`/`[dns.tls]`) only secures DoT/DoH and must
/// never be used to decide the admin scheme: doing so marks plain-HTTP browser
/// sessions as secure, which makes `Secure` cookies invisible and rejects every
/// mutating Origin check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdminSchemeConfig {
    /// Scheme of the configured external admin URL (`web.public_url`), lowercased.
    /// When set it is authoritative and the request-derived scheme is ignored,
    /// because the operator has declared how the UI is reached.
    pub public_url_scheme: Option<String>,
    /// `web.tls_terminated_by_proxy = true`: TLS is terminated by a trusted
    /// reverse proxy in front of this server.
    pub tls_terminated_by_proxy: bool,
}

impl AdminSchemeConfig {
    /// True when requests are considered to arrive over HTTPS regardless of
    /// per-request headers (explicit operator declaration only).
    #[must_use]
    pub fn is_always_https(&self) -> bool {
        match &self.public_url_scheme {
            Some(scheme) => scheme.eq_ignore_ascii_case("https"),
            None => self.tls_terminated_by_proxy,
        }
    }
}

/// Builds [`AdminSchemeConfig`] from the raw `[web]` TOML table. Unknown or
/// wrongly-typed keys fall back to the secure-by-default `false`.
#[must_use]
pub fn admin_scheme_config(web: Option<&toml::Value>) -> AdminSchemeConfig {
    let Some(web) = web else {
        return AdminSchemeConfig::default();
    };
    let Ok(table) = web.clone().try_into::<toml::Table>() else {
        return AdminSchemeConfig::default();
    };

    let public_url_scheme = table
        .get("public_url")
        .and_then(toml::Value::as_str)
        .and_then(|url| url.split_once("://").map(|(scheme, _)| scheme))
        .map(str::trim)
        .filter(|scheme| !scheme.is_empty())
        .map(str::to_ascii_lowercase);

    let tls_terminated_by_proxy = table
        .get("tls_terminated_by_proxy")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);

    AdminSchemeConfig {
        public_url_scheme,
        tls_terminated_by_proxy,
    }
}

/// Determines if the request arrived over HTTPS.
///
/// The scheme is derived only from the explicit admin-transport setting
/// (`web.public_url` / `web.tls_terminated_by_proxy`) or from
/// `X-Forwarded-Proto: https` sent by a configured trusted proxy. The DNS TLS
/// configuration is deliberately not an input: a DoT/DoH certificate does not
/// secure the admin UI.
///
/// An untrusted peer cannot influence the scheme: its `X-Forwarded-Proto`
/// value is ignored entirely.
pub fn is_https_request(
    peer_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[IpAddr],
    scheme: &AdminSchemeConfig,
) -> bool {
    if let Some(expected) = &scheme.public_url_scheme {
        return expected.eq_ignore_ascii_case("https");
    }

    if let Some(peer) = peer_addr
        && trusted_proxies.contains(&peer.ip())
        && let Some(proto) = headers.get("x-forwarded-proto")
        && let Ok(val) = proto.to_str()
    {
        return val.eq_ignore_ascii_case("https");
    }

    scheme.tls_terminated_by_proxy
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
        let plain = AdminSchemeConfig::default();
        assert!(!is_https_request(None, &empty_headers, &[], &plain));

        let mut https_headers = HeaderMap::new();
        https_headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        // Without peer information the header must not be trusted.
        assert!(!is_https_request(None, &https_headers, &[], &plain));

        let proxy_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = SocketAddr::new(proxy_ip, 12345);
        // Untrusted proxy
        assert!(!is_https_request(Some(peer), &https_headers, &[], &plain));
        // Trusted proxy
        assert!(is_https_request(
            Some(peer),
            &https_headers,
            &[proxy_ip],
            &plain
        ));
    }

    #[test]
    fn test_admin_scheme_never_derives_from_dns_tls() {
        // Regression: the DNS DoT/DoH certificate (`[tls]`) used to be passed
        // as `tls_enabled`, which made a plain-HTTP admin UI believe it was
        // serving HTTPS (Secure cookies ignored, HSTS over HTTP, every CSRF
        // Origin check rejected).
        let headers = HeaderMap::new();
        let scheme = admin_scheme_config(None);
        assert!(!is_https_request(None, &headers, &[], &scheme));
        assert!(!scheme.is_always_https());
    }

    #[test]
    fn test_admin_scheme_from_web_table() {
        let https_public = toml::from_str::<toml::Value>(
            r#"
            public_url = "https://dns.example.com"
            tls_terminated_by_proxy = false
            "#,
        )
        .unwrap();
        let scheme = admin_scheme_config(Some(&https_public));
        assert_eq!(scheme.public_url_scheme.as_deref(), Some("https"));
        assert!(is_https_request(None, &HeaderMap::new(), &[], &scheme));

        let http_public =
            toml::from_str::<toml::Value>(r#"public_url = "http://dns.example.com:8080""#).unwrap();
        let scheme = admin_scheme_config(Some(&http_public));
        assert_eq!(scheme.public_url_scheme.as_deref(), Some("http"));
        // Explicit http declaration wins over a spoofed forwarded header.
        let mut forwarded = HeaderMap::new();
        forwarded.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        let proxy_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = SocketAddr::new(proxy_ip, 12345);
        assert!(!is_https_request(
            Some(peer),
            &forwarded,
            &[proxy_ip],
            &scheme
        ));

        let proxy_terminated =
            toml::from_str::<toml::Value>(r"tls_terminated_by_proxy = true").unwrap();
        let scheme = admin_scheme_config(Some(&proxy_terminated));
        assert!(scheme.tls_terminated_by_proxy);
        assert!(scheme.is_always_https());

        // Invalid public_url fails closed to plain HTTP.
        let garbage = toml::from_str::<toml::Value>(r#"public_url = "not a url""#).unwrap();
        let scheme = admin_scheme_config(Some(&garbage));
        assert_eq!(scheme.public_url_scheme, None);
        assert!(!scheme.is_always_https());
    }

    #[test]
    fn test_admin_scheme_untrusted_forwarded_proto_ignored() {
        let proxy_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let attacker: IpAddr = "198.51.100.7".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));

        let scheme = AdminSchemeConfig {
            public_url_scheme: None,
            tls_terminated_by_proxy: false,
        };
        assert!(!is_https_request(
            Some(SocketAddr::new(attacker, 5555)),
            &headers,
            &[proxy_ip],
            &scheme
        ));
        assert!(is_https_request(
            Some(SocketAddr::new(proxy_ip, 5555)),
            &headers,
            &[proxy_ip],
            &scheme
        ));

        // `web.tls_terminated_by_proxy = true` is an operator declaration and
        // does not depend on the peer, but never on request headers.
        let declared = AdminSchemeConfig {
            public_url_scheme: None,
            tls_terminated_by_proxy: true,
        };
        assert!(is_https_request(
            Some(SocketAddr::new(attacker, 5555)),
            &headers,
            &[],
            &declared
        ));
    }
}
