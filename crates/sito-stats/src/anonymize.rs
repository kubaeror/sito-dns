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
/// - IPv6: /56 (zeroes out the last 72 bits)
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
}
