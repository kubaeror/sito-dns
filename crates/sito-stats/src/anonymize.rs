//! IP anonymization utilities per section 14.3.
//!
//! When enabled, masks IPv4 addresses to /24 and IPv6 addresses to /56.

use std::net::IpAddr;

/// Anonymizes an IP address by masking host bits:
/// - IPv4: /24 (zeroes out the last octet)
/// - IPv6: /56 (zeroes out the last 72 bits)
pub fn anonymize_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.{}.0", octets[0], octets[1], octets[2])
        }
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            for b in &mut octets[7..16] {
                *b = 0;
            }
            std::net::Ipv6Addr::from(octets).to_string()
        }
    }
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
}
