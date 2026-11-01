//! SSRF target classification shared by every component that makes outbound
//! connections on behalf of configuration or user input (blocklist
//! subscriptions, upstream probes, webhook-style integrations).
//!
//! The guard rejects loopback, private, link-local (including cloud metadata),
//! CGNAT, benchmarking, documentation, multicast, reserved and translation/
//! encapsulation ranges that embed an IPv4 address. Both IPv4 and IPv6 forms
//! are classified; IPv4-embedding IPv6 prefixes are unwrapped recursively so a
//! `64:ff9b::10.0.0.1`-style literal cannot bypass a v4-only denylist.

use std::net::{IpAddr, Ipv4Addr};

/// Returns true when `ip` must not be used as an outbound target.
#[must_use]
pub fn is_denied_target_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_denied_target_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_denied_target_ipv4(v4);
            }
            let o = v6.octets();
            // Translation/encapsulation prefixes that embed an IPv4 address:
            // unwrap and classify the embedded address.
            let embedded = if o[0] == 0x00
                && o[1] == 0x64
                && o[2] == 0xff
                && o[3] == 0x9b
                && o[4..12].iter().all(|b| *b == 0)
            {
                // NAT64 64:ff9b::/96
                Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
            } else if o[0] == 0x00
                && o[1] == 0x64
                && o[2] == 0xff
                && o[3] == 0x9b
                && o[4] == 0x00
                && o[5] == 0x01
            {
                // Local-use NAT64 64:ff9b:1::/48 (RFC 8215)
                Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
            } else if o[0] == 0x20 && o[1] == 0x02 {
                // 6to4 2002::/16
                Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]))
            } else if o[0] == 0x20 && o[1] == 0x01 && o[2] == 0 && o[3] == 0 {
                // Teredo 2001:0000::/32: client IPv4 is bitwise-inverted.
                Some(Ipv4Addr::new(!o[12], !o[13], !o[14], !o[15]))
            } else if o[..12].iter().all(|b| *b == 0) {
                // Deprecated IPv4-compatible ::/96 (excluding :: and ::1,
                // handled by unspecified/loopback below).
                Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
            } else {
                None
            };
            if let Some(v4) = embedded {
                return is_denied_target_ipv4(v4);
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
                || (seg[0] & 0xffc0) == 0xfec0 // fec0::/10 deprecated site-local
                || (seg[0] == 0x2001 && seg[1] == 0x0db8) // 2001:db8::/32 documentation
                || (seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0) // 100::/64 discard
        }
    }
}

fn is_denied_target_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast()
        || o[0] == 0 // 0.0.0.0/8 "this network"
        || o[0] >= 240 // 240.0.0.0/4 reserved
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
        || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99.0/24 6to4 relay anycast
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_denied_ipv4_ranges() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.0.1",
            "198.18.0.1",
            "192.88.99.1",
            "0.1.2.3",
            "240.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.1",
        ] {
            assert!(
                is_denied_target_ip(IpAddr::from_str(ip).expect("ip")),
                "{ip} must be denied"
            );
        }
        for ip in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "203.0.113.0"] {
            let parsed = IpAddr::from_str(ip).expect("ip");
            // 203.0.113.0/24 is documentation and therefore denied; the rest
            // are global.
            if ip.starts_with("203.0.113") {
                assert!(is_denied_target_ip(parsed), "{ip} must be denied");
            } else {
                assert!(!is_denied_target_ip(parsed), "{ip} must be allowed");
            }
        }
    }

    #[test]
    fn test_denied_ipv6_and_embeddings() {
        for ip in [
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "2001:db8::1",
            "ff02::1",
            "100::1",
            // IPv4 embeddings of a private/link-local target.
            "::ffff:192.168.1.1",
            "64:ff9b::192.168.1.1",
            "64:ff9b:1::10.0.0.1",
            "2002:c0a8:0101::1",        // 6to4 -> 192.168.1.1
            "2001:0:0:0:0:0:3f57:fefe", // Teredo -> 192.168.1.1 (inverted)
            "::192.168.1.1",            // IPv4-compatible
        ] {
            let parsed = IpAddr::from_str(ip).expect("ip");
            assert!(is_denied_target_ip(parsed), "{ip} must be denied");
        }
        for ip in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            let parsed = IpAddr::from_str(ip).expect("ip");
            assert!(!is_denied_target_ip(parsed), "{ip} must be allowed");
        }
    }
}
