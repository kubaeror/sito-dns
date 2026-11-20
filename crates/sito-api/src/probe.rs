//! SSRF-safe upstream probe helper used by the REST API and web UI.
//!
//! Probes resolve their target exactly once, reject addresses that are not
//! globally routable (loopback, link-local, private, CGNAT, metadata,
//! documentation, multicast, ...) and pin the resolved address so a hostile
//! DNS server cannot rebind the connection to an internal host.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr as _;
use std::time::Duration;

use sito_proto::Message;
use sito_upstream::Upstream as _;
use sito_upstream::upstream::{is_edns_failure_code, validate_response};

/// Maximum number of upstream servers probed in a single REST request.
pub const MAX_PROBE_SERVERS: usize = 16;

/// Per-probe timeout.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Returns true when an IP must never be used as an outbound probe target.
///
/// Delegates to the shared guard in [`sito_core::ssrf`]; probe-specific policy
/// (the resolver allowlist) lives in the callers.
pub fn is_forbidden_probe_ip(ip: &IpAddr) -> bool {
    sito_core::is_denied_target_ip(*ip)
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

/// Splits `scheme://rest` into a lowercased scheme (when present) and `rest`.
fn split_probe_scheme(addr_str: &str) -> (Option<String>, &str) {
    match addr_str.split_once("://") {
        Some((scheme, rest)) => (Some(scheme.to_ascii_lowercase()), rest),
        None => (None, addr_str),
    }
}

/// Builds the query used by REST/UI probes. RD=1 is required: a recursive
/// resolver may legitimately drop RD=0 queries, which must not look unhealthy.
fn build_probe_query(id: u16, qname: sito_proto::Name) -> Message {
    let mut query = Message::new(
        id,
        sito_proto::MessageType::Query,
        sito_proto::OpCode::Query,
    );
    query.metadata.recursion_desired = true;
    query
        .queries
        .push(sito_proto::Query::query(qname, sito_proto::RecordType::A));
    query
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

/// Validates a direct probe reply.
///
/// The upstream manager accepts a matching-ID FORMERR/BADVERS reply without a
/// question so it can retry once without EDNS. A one-shot probe has no retry
/// path, so a server that can only return an EDNS failure must be reported as
/// down instead of "up" just because it answered at the network layer.
fn validate_probe_reply(query: &Message, response: &Message) -> Result<(), String> {
    validate_response(query, response).map_err(|e| format!("Invalid probe reply: {e}"))?;
    if is_edns_failure_code(response.metadata.response_code) {
        return Err(format!(
            "Upstream could not process the probe query ({})",
            response.metadata.response_code
        ));
    }
    Ok(())
}

/// Probes a single upstream target (UDP, DoT, DoH or DoQ) and returns the
/// measured RTT in milliseconds.
pub async fn probe_upstream_target(addr_str: &str, probe_domain: &str) -> Result<f64, String> {
    let start = std::time::Instant::now();
    let qname = sito_proto::Name::from_str(probe_domain)
        .unwrap_or_else(|_| sito_proto::Name::from_str("example.com").unwrap());
    let (scheme, rest) = split_probe_scheme(addr_str);

    match scheme.as_deref() {
        Some("tls") => {
            let (host, port) = split_probe_host_port(rest, "tls", 853);
            let addr = resolve_probe_addr(&host, port).await?;

            let stream = tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(addr))
                .await
                .map_err(|_| "Connection timed out".to_string())?
                .map_err(|e| format!("TCP connection failed: {e}"))?;
            drop(stream);
            Ok(start.elapsed().as_secs_f64() * 1000.0)
        }
        Some("https") => {
            let (host, port) = split_probe_host_port(rest, "https", 443);
            let addr = resolve_probe_addr(&host, port).await?;
            let url = format!("https://{rest}");
            let doh = sito_upstream::HttpsUpstream::new(&url, &[addr.ip()], PROBE_TIMEOUT)
                .map_err(|e| format!("Invalid DoH upstream: {e}"))?;
            let query = build_probe_query(0, qname);
            let response = doh
                .resolve(&query)
                .await
                .map_err(|e| format!("DoH query failed: {e}"))?;
            validate_probe_reply(&query, &response)?;
            Ok(start.elapsed().as_secs_f64() * 1000.0)
        }
        Some("quic") => {
            let (host, port) = split_probe_host_port(rest, "quic", 853);
            let addr = resolve_probe_addr(&host, port).await?;
            let doq = sito_upstream::QuicUpstream::new(&host, addr, PROBE_TIMEOUT)
                .map_err(|e| format!("Invalid DoQ upstream: {e}"))?;
            let query = build_probe_query(0, qname);
            let response = doq
                .resolve(&query)
                .await
                .map_err(|e| format!("DoQ query failed: {e}"))?;
            validate_probe_reply(&query, &response)?;
            Ok(start.elapsed().as_secs_f64() * 1000.0)
        }
        Some("udp") | None => {
            let target_addr: SocketAddr = if let Ok(sa) = rest.parse() {
                sa
            } else {
                let (host, port) = split_probe_host_port(rest, "udp", 53);
                resolve_probe_addr(&host, port).await?
            };
            if is_forbidden_probe_ip(&target_addr.ip()) {
                return Err(format!(
                    "Target resolves to a restricted address ({})",
                    target_addr.ip()
                ));
            }

            probe_udp_target(target_addr, qname).await
        }
        Some(other) => Err(format!(
            "Unsupported probe scheme '{other}://'; use udp://, tls://, https:// or quic://"
        )),
    }
}

/// Sends one UDP probe to `target_addr` and validates the reply.
///
/// The socket is connected to the target so the kernel drops datagrams from
/// other peers; the response ID/question is still validated because a spoofed
/// datagram from the target address must not count the server as up.
async fn probe_udp_target(target_addr: SocketAddr, qname: sito_proto::Name) -> Result<f64, String> {
    let start = std::time::Instant::now();
    let bind_addr = if target_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("Failed to bind local UDP socket: {e}"))?;
    socket
        .connect(target_addr)
        .await
        .map_err(|e| format!("UDP connect failed: {e}"))?;

    let query_msg = build_probe_query(rand::random(), qname);
    let wire = sito_proto::encode_message(&query_msg)
        .map_err(|e| format!("Failed to encode DNS probe message: {e}"))?;

    socket
        .send(&wire)
        .await
        .map_err(|e| format!("UDP send failed: {e}"))?;

    // A connected UDP socket still delivers datagrams from the target address
    // that are junk, truncated, or for a different query. Ignore those until
    // the probe deadline instead of failing the server on the first packet.
    let deadline = start + PROBE_TIMEOUT;
    let mut buf = [0u8; 512];
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err("Probe query timed out".to_string());
        }
        let bytes_read = match tokio::time::timeout(remaining, socket.recv(&mut buf)).await {
            Err(_) => return Err("Probe query timed out".to_string()),
            Ok(Err(e)) => return Err(format!("UDP recv failed: {e}")),
            Ok(Ok(n)) => n,
        };
        let Ok(response) = sito_proto::decode_message(&buf[..bytes_read]) else {
            continue;
        };
        if validate_response(&query_msg, &response).is_err() {
            continue;
        }
        // The reply belongs to this query: a matching EDNS failure means the
        // server cannot answer probes and must be reported down.
        validate_probe_reply(&query_msg, &response)?;
        return Ok(start.elapsed().as_secs_f64() * 1000.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sito_proto::{MessageType, OpCode, Query, RecordType, ResponseCode};
    use std::str::FromStr;

    fn probe_query() -> Message {
        let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            sito_proto::Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        query
    }

    #[test]
    fn test_probe_scheme_is_case_insensitive() {
        assert_eq!(
            split_probe_scheme("TLS://dns.example"),
            (Some("tls".to_string()), "dns.example")
        );
        assert_eq!(
            split_probe_scheme("QuIc://dns.example"),
            (Some("quic".to_string()), "dns.example")
        );
        assert_eq!(split_probe_scheme("1.1.1.1:53"), (None, "1.1.1.1:53"));
    }

    #[test]
    fn test_probe_query_sets_recursion_desired() {
        let qname = sito_proto::Name::from_str("example.com.").unwrap();
        let query = build_probe_query(0x1234, qname);
        assert!(
            query.metadata.recursion_desired,
            "REST/UI probes must ask the upstream for recursion (RD=1)"
        );
        assert_eq!(query.queries.len(), 1);
    }

    /// Deferred D4b: a matching-ID FORMERR/BADVERS without a question is
    /// accepted by the transport so the manager can retry without EDNS, but a
    /// direct one-shot probe must report the target as unhealthy.
    #[test]
    fn test_probe_rejects_edns_failure_replies() {
        let query = probe_query();
        for code in [ResponseCode::FormErr, ResponseCode::BADVERS] {
            let mut response = Message::response(0x1234, OpCode::Query);
            response.metadata.response_code = code;
            assert!(
                validate_probe_reply(&query, &response).is_err(),
                "a {code} probe reply must not count the server as up"
            );
        }

        let mut response = Message::response(0x1234, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::NoError;
        assert!(validate_probe_reply(&query, &response).is_ok());

        let mut wrong_id = Message::response(0x9999, OpCode::Query);
        wrong_id.queries = query.queries.clone();
        assert!(
            validate_probe_reply(&query, &wrong_id).is_err(),
            "a mismatched probe reply must be rejected"
        );
    }

    /// Deferred D4b review: exercise the actual UDP receive path, not only the
    /// reply-validation helper, so removing the validation call fails a test.
    #[tokio::test]
    async fn test_udp_probe_receive_path_rejects_edns_failure() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let query = sito_proto::decode_message(&buf[..n]).unwrap();
            let mut response = Message::response(query.metadata.id, query.metadata.op_code);
            response.metadata.response_code = ResponseCode::FormErr;
            let bytes = sito_proto::encode_message(&response).unwrap();
            server.send_to(&bytes, peer).await.unwrap();
        });

        let qname = sito_proto::Name::from_str("example.com.").unwrap();
        let err = probe_udp_target(addr, qname)
            .await
            .expect_err("a FORMERR UDP probe reply must not count the server as up");
        assert!(
            err.contains("could not process"),
            "unexpected probe error: {err}"
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_udp_probe_receive_path_accepts_matching_reply() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let query = sito_proto::decode_message(&buf[..n]).unwrap();
            let mut response = Message::response(query.metadata.id, query.metadata.op_code);
            response.queries = query.queries.clone();
            response.metadata.response_code = ResponseCode::NoError;
            let bytes = sito_proto::encode_message(&response).unwrap();
            server.send_to(&bytes, peer).await.unwrap();
        });

        let qname = sito_proto::Name::from_str("example.com.").unwrap();
        let rtt = probe_udp_target(addr, qname)
            .await
            .expect("a matching NOERROR reply must succeed");
        assert!(rtt.is_finite(), "unexpected probe RTT: {rtt}");
        server_task.await.unwrap();
    }

    /// WP-2.7: junk and mismatched datagrams from the probe target must be
    /// ignored until a reply that belongs to this query arrives (or the probe
    /// deadline expires), not treated as the server's answer.
    #[tokio::test]
    async fn test_udp_probe_ignores_mismatched_datagrams() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let query = sito_proto::decode_message(&buf[..n]).unwrap();

            server.send_to(b"not a dns message", peer).await.unwrap();
            let mut wrong_id =
                Message::response(query.metadata.id.wrapping_add(1), query.metadata.op_code);
            wrong_id.queries = query.queries.clone();
            let bytes = sito_proto::encode_message(&wrong_id).unwrap();
            server.send_to(&bytes, peer).await.unwrap();

            let mut response = Message::response(query.metadata.id, query.metadata.op_code);
            response.queries = query.queries.clone();
            response.metadata.response_code = ResponseCode::NoError;
            let bytes = sito_proto::encode_message(&response).unwrap();
            server.send_to(&bytes, peer).await.unwrap();
        });

        let qname = sito_proto::Name::from_str("example.com.").unwrap();
        let rtt = probe_udp_target(addr, qname)
            .await
            .expect("junk and mismatched replies must be ignored");
        assert!(rtt.is_finite(), "unexpected probe RTT: {rtt}");
        server_task.await.unwrap();
    }

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
