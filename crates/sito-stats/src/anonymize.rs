//! IP anonymization utilities per section 14.3.
//!
//! When enabled, masks IPv4 addresses to /24 and IPv6 addresses to /56.
//!
//! # Forward-only writer, explicit retroactive rewrite
//!
//! The setting is applied by the query-log writer before a new row is stored,
//! so it affects writes made after the setting becomes live. Existing
//! `query_log` rows are **not** rewritten when the operator enables it; that is
//! a deliberate explicit step. `sito db anonymize --all` (and
//! `StatsDb::anonymize_query_log`) performs a bounded, crash-resumable
//! retroactive rewrite of the detailed rows in 1,000-row key-ordered chunks,
//! each in its own transaction, followed by `VACUUM`/WAL truncation. Rollup
//! client identifiers are separately hashed by the one-time rollup backfill,
//! and raw IPs/names in old detailed rows remain until that explicit rewrite,
//! retention, or a clear removes them.

use std::net::IpAddr;

/// Anonymizes an IP address by masking host bits:
/// - IPv4: /24 (zeroes out the last octet)
/// - IPv4-mapped IPv6 (`::ffff:a.b.c.d`): the mapped IPv4 /24
/// - IPv4-compatible IPv6 (`::a.b.c.d`): the compatible IPv4 /24
/// - IPv6: /56 (zeroes out the last 72 bits)
///
/// `::` (unspecified) and `::1` (loopback) are IPv6 special addresses rather
/// than IPv4-compatible hosts, so they keep the native IPv6 `/56` mask (both
/// reduce to `::`); they are not client addresses.
pub fn anonymize_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => anonymize_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                // Treating a mapped address as native IPv6 zeroes octets 7..16,
                // collapsing every mapped client to `::`. Mask the IPv4 host
                // part instead so mapped and native IPv4 clients share a /24.
                return anonymize_ipv4(v4);
            }
            if let Some(v4) = ipv4_compatible(&v6) {
                // Deprecated IPv4-compatible spelling (`::a.b.c.d`). It has the
                // same first-96-bits-zero shape as mapped addresses, so native
                // IPv6 `/56` masking would collapse every such client to `::`.
                return anonymize_ipv4(v4);
            }
            let mut octets = v6.octets();
            for b in &mut octets[7..16] {
                *b = 0;
            }
            std::net::Ipv6Addr::from(octets).to_string()
        }
    }
}

fn anonymize_ipv4(v4: std::net::Ipv4Addr) -> String {
    let octets = v4.octets();
    format!("{}.{}.{}.0", octets[0], octets[1], octets[2])
}

/// Returns the embedded IPv4 address for an IPv4-compatible IPv6 address
/// (`::a.b.c.d`, first 96 bits zero), excluding the `::` and `::1` special
/// addresses. Mapped addresses are handled separately by
/// [`std::net::Ipv6Addr::to_ipv4_mapped`].
fn ipv4_compatible(v6: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let octets = v6.octets();
    if !octets[..12].iter().all(|byte| *byte == 0) {
        return None;
    }
    if v6.is_unspecified() || v6.is_loopback() {
        return None;
    }
    Some(std::net::Ipv4Addr::new(
        octets[12], octets[13], octets[14], octets[15],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_anonymize_ipv4() {
        let ip: IpAddr = "192.168.1.123".parse().unwrap();
        assert_eq!(anonymize_ip(ip), "192.168.1.0");

        let ip: IpAddr = "10.45.99.1".parse().unwrap();
        assert_eq!(anonymize_ip(ip), "10.45.99.0");
    }

    #[test]
    fn test_anonymize_ipv6() {
        let ip: IpAddr = "2001:db8:abcd:0012:3456:7890:1234:5678".parse().unwrap();
        let masked = anonymize_ip(ip);
        // /56: 2001:0db8:abcd:0000 -> 2001:db8:abcd::
        let masked_addr = std::net::Ipv6Addr::from_str(&masked).unwrap();
        let octets = masked_addr.octets();
        assert_eq!(&octets[7..16], &[0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&octets[0..7], &[0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x00]);
    }

    /// P2-58: mapped IPv6 addresses must anonymize as IPv4 /24 rather than as
    /// IPv6 /56, which collapsed every mapped client to `::`.
    #[test]
    fn test_anonymize_ipv4_mapped_ipv6() {
        let first: IpAddr = "::ffff:192.0.2.10".parse().unwrap();
        let second: IpAddr = "::ffff:198.51.100.20".parse().unwrap();

        assert_eq!(anonymize_ip(first), "192.0.2.0");
        assert_eq!(anonymize_ip(second), "198.51.100.0");
        assert_ne!(
            anonymize_ip(first),
            anonymize_ip(second),
            "distinct mapped clients must not collapse to the same masked address"
        );
        assert_ne!(anonymize_ip(first), "::");
        assert_eq!(
            anonymize_ip(first),
            anonymize_ip("192.0.2.99".parse().unwrap()),
            "a mapped address and its native IPv4 form must share a /24"
        );
    }

    /// IPv4-compatible IPv6 (`::a.b.c.d`, first 96 bits zero) is a second
    /// spelling of the same client. Treating it as native IPv6 `/56` collapsed
    /// every compatible client to `::`; it must mask the embedded IPv4 /24.
    #[test]
    fn test_anonymize_ipv4_compatible_ipv6() {
        let first: IpAddr = "::192.0.2.10".parse().unwrap();
        let second: IpAddr = "::198.51.100.20".parse().unwrap();

        assert_eq!(anonymize_ip(first), "192.0.2.0");
        assert_eq!(anonymize_ip(second), "198.51.100.0");
        assert_ne!(
            anonymize_ip(first),
            anonymize_ip(second),
            "distinct compatible clients must not collapse to the same masked address"
        );
        assert_ne!(anonymize_ip(first), "::");
        assert_eq!(
            anonymize_ip(first),
            anonymize_ip("192.0.2.99".parse().unwrap()),
            "a compatible address and its native IPv4 form must share a /24"
        );
        assert_eq!(
            anonymize_ip(first),
            anonymize_ip("::ffff:192.0.2.99".parse().unwrap()),
            "compatible and mapped spellings of one client must share a /24"
        );
    }

    /// `::` and `::1` are IPv6 special addresses, not IPv4-compatible client
    /// addresses. They keep the native IPv6 `/56` mask rather than becoming
    /// `0.0.0.0`.
    #[test]
    fn test_anonymize_ipv6_special_addresses() {
        assert_eq!(anonymize_ip("::".parse().unwrap()), "::");
        assert_eq!(anonymize_ip("::1".parse().unwrap()), "::");
    }
}
