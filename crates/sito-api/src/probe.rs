//! SSRF-safe upstream probe helper used by the REST API and web UI.
//!
//! Probes resolve their target exactly once, reject addresses that are not
//! globally routable (loopback, link-local, private, CGNAT, metadata,
//! documentation, multicast, ...) and pin the resolved address so a hostile
//! DNS server cannot rebind the connection to an internal host.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr as _;
use std::time::Duration;

use sito_upstream::Upstream as _;

/// Maximum number of upstream servers probed in a single REST request.
pub const MAX_PROBE_SERVERS: usize = 16;

/// Per-probe timeout.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Returns true when an IP must never be used as an outbound probe target.
pub fn is_forbidden_probe_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_probe_ipv4(*v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_forbidden_probe_ipv4(v4);
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                // Documentation 2001:db8::/32
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)
                // Deprecated site-local fec0::/10
                || (v6.segments()[0] & 0xffc0) == 0xfec0
        }
    }
}

fn is_forbidden_probe_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        // Carrier-grade NAT 100.64.0.0/10
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
        // Benchmarking 198.18.0.0/15
        || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
        // Reserved 240.0.0.0/4
        || octets[0] >= 240
        // 192.0.0.0/24 IETF protocol assignments
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        // 198.51.100.0/24 and 203.0.113.0/24 are covered by is_documentation
        // 192.88.99.0/24 (6to4 relay anycast)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
}

/// Resolves `host:port` once, rejects any non-global address and returns the
/// first (pinned) socket address.
pub async fn resolve_probe_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS resolution of {host} failed: {e}"))?
        .collect();

    if addrs.is_empty() {
        return Err(format!("Could not resolve {host}"));
    }

    for addr in &addrs {
        if is_forbidden_probe_ip(&addr.ip()) {
            return Err(format!(
                "Target {host} resolves to a restricted address ({})",
                addr.ip()
            ));
        }
    }

    Ok(addrs[0])
}

fn split_probe_host_port(addr_str: &str, scheme: &str, default_port: u16) -> (String, u16) {
    let rest = addr_str
        .strip_prefix(&format!("{scheme}://"))
        .unwrap_or(addr_str);
    let authority = rest.split('/').next().unwrap_or(rest);
    if let Some(inner) = authority.strip_prefix('[')
        && let Some((host, tail)) = inner.split_once(']')
    {
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return (host.to_string(), port);
    }
    if let Some((host, port)) = authority.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return (host.to_string(), port);
    }
    (authority.to_string(), default_port)
}

/// Probes a single upstream target (UDP, DoT, DoH or DoQ) and returns the
/// measured RTT in milliseconds.
pub async fn probe_upstream_target(addr_str: &str, probe_domain: &str) -> Result<f64, String> {
    let start = std::time::Instant::now();
    let qname = sito_proto::Name::from_str(probe_domain)
        .unwrap_or_else(|_| sito_proto::Name::from_str("example.com").unwrap());

    if addr_str.starts_with("tls://") {
        let (host, port) = split_probe_host_port(addr_str, "tls", 853);
        let addr = resolve_probe_addr(&host, port).await?;

        let stream = tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(addr))
            .await
            .map_err(|_| "Connection timed out".to_string())?
            .map_err(|e| format!("TCP connection failed: {e}"))?;
        drop(stream);
        return Ok(start.elapsed().as_secs_f64() * 1000.0);
    }

    if addr_str.starts_with("https://") {
        let (host, port) = split_probe_host_port(addr_str, "https", 443);
        let addr = resolve_probe_addr(&host, port).await?;
        let doh = sito_upstream::HttpsUpstream::new(addr_str, &[addr.ip()], PROBE_TIMEOUT)
            .map_err(|e| format!("Invalid DoH upstream: {e}"))?;
        let mut query =
            sito_proto::Message::new(0, sito_proto::MessageType::Query, sito_proto::OpCode::Query);
        query
            .queries
            .push(sito_proto::Query::query(qname, sito_proto::RecordType::A));
        doh.resolve(&query)
            .await
            .map_err(|e| format!("DoH query failed: {e}"))?;
        return Ok(start.elapsed().as_secs_f64() * 1000.0);
    }

    if addr_str.starts_with("quic://") {
        let (host, port) = split_probe_host_port(addr_str, "quic", 853);
        let addr = resolve_probe_addr(&host, port).await?;
        let doq = sito_upstream::QuicUpstream::new(&host, addr, PROBE_TIMEOUT)
            .map_err(|e| format!("Invalid DoQ upstream: {e}"))?;
        let mut query =
            sito_proto::Message::new(0, sito_proto::MessageType::Query, sito_proto::OpCode::Query);
        query
            .queries
            .push(sito_proto::Query::query(qname, sito_proto::RecordType::A));
        doq.resolve(&query)
            .await
            .map_err(|e| format!("DoQ query failed: {e}"))?;
        return Ok(start.elapsed().as_secs_f64() * 1000.0);
    }

    // Standard UDP probe
    let target = addr_str.strip_prefix("udp://").unwrap_or(addr_str);
    let target_addr: SocketAddr = if let Ok(sa) = target.parse() {
        sa
    } else {
        let (host, port) = split_probe_host_port(target, "udp", 53);
        resolve_probe_addr(&host, port).await?
    };
    if is_forbidden_probe_ip(&target_addr.ip()) {
        return Err(format!(
            "Target resolves to a restricted address ({})",
            target_addr.ip()
        ));
    }

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind local UDP socket: {e}"))?;

    let mut query_msg = sito_proto::Message::new(
        rand::random(),
        sito_proto::MessageType::Query,
        sito_proto::OpCode::Query,
    );
    query_msg.metadata.recursion_desired = true;
    query_msg
        .queries
        .push(sito_proto::Query::query(qname, sito_proto::RecordType::A));
    let wire = sito_proto::encode_message(&query_msg)
        .map_err(|e| format!("Failed to encode DNS probe message: {e}"))?;

    socket
        .send_to(&wire, target_addr)
        .await
        .map_err(|e| format!("UDP send failed: {e}"))?;

    let mut buf = [0u8; 512];
    tokio::time::timeout(PROBE_TIMEOUT, socket.recv_from(&mut buf))
        .await
        .map_err(|_| "Probe query timed out".to_string())?
        .map_err(|e| format!("UDP recv failed: {e}"))?;

    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forbidden_probe_targets() {
        for ip in [
            "127.0.0.1",
            "127.10.0.5",
            "::1",
            "0.0.0.0",
            "::",
            "10.0.0.1",
            "172.16.5.5",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.100.100.200",
            "192.0.2.10",
            "198.51.100.10",
            "203.0.113.10",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "240.0.0.1",
            "fe80::1",
            "fc00::1",
            "fec0::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
            "ff02::1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(
                is_forbidden_probe_ip(&ip),
                "{ip} must be rejected as a probe target"
            );
        }

        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "9.9.9.9"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(
                !is_forbidden_probe_ip(&ip),
                "{ip} must be allowed as a probe target"
            );
        }
    }

    #[tokio::test]
    async fn test_resolve_probe_addr_rejects_private_literals() {
        let err = resolve_probe_addr("127.0.0.1", 53).await.unwrap_err();
        assert!(err.contains("restricted"), "unexpected error: {err}");
        let err = resolve_probe_addr("192.168.0.1", 53).await.unwrap_err();
        assert!(err.contains("restricted"), "unexpected error: {err}");
    }
}
