//! Shared IP network/CIDR matching helpers.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

/// Maximum number of prefixes in each ADR-0011 `[clients.acl] allow`/`deny`
/// list. Shared by the schema validator and the runtime ACL index.
pub const MAX_ACL_PREFIXES: usize = 1024;

/// Error returned when a CIDR block is invalid.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CidrError {
    #[error("invalid CIDR '{0}': expected 'address/prefix'")]
    Invalid(String),

    #[error("CIDR prefix {prefix} is too large for this address family (max {max})")]
    PrefixTooLong { prefix: u8, max: u8 },
}

/// A parsed IPv4/IPv6 CIDR block.
///
/// The address is kept as written; [`IpNetwork::network_address`] masks host
/// bits when a caller needs the canonical network address. Membership tests
/// always mask, so `10.1.2.3/24` and `10.1.2.0/24` are equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNetwork {
    addr: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    /// Builds a network from an address and prefix, validating the prefix
    /// against the address family.
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, CidrError> {
        let max = max_prefix(addr);
        if prefix > max {
            return Err(CidrError::PrefixTooLong { prefix, max });
        }
        Ok(Self { addr, prefix })
    }

    /// Parses `address/prefix` CIDR notation.
    pub fn parse(value: &str) -> Result<Self, CidrError> {
        let (addr, prefix) = value
            .split_once('/')
            .ok_or_else(|| CidrError::Invalid(value.to_string()))?;
        let addr = addr
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| CidrError::Invalid(value.to_string()))?;
        let prefix = prefix
            .trim()
            .parse::<u8>()
            .map_err(|_| CidrError::Invalid(value.to_string()))?;
        Self::new(addr, prefix)
    }

    /// The address as written (host bits are preserved).
    #[must_use]
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length.
    #[must_use]
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Returns true when `target` is inside this network.
    #[must_use]
    pub fn contains(&self, target: IpAddr) -> bool {
        ip_in_subnet(self.addr, self.prefix, target)
    }

    /// The network address with host bits cleared.
    #[must_use]
    pub fn network_address(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(addr) => {
                let mask = v4_mask(self.prefix);
                IpAddr::V4((u32::from(addr) & mask).into())
            }
            IpAddr::V6(addr) => {
                let mask = v6_mask(self.prefix);
                IpAddr::V6((u128::from(addr) & mask).into())
            }
        }
    }
}

impl fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for IpNetwork {
    type Err = CidrError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

fn max_prefix(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else if prefix >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// Canonicalizes a MAC address written in one strict explicit shape.
///
/// Accepts exactly six two-hex-digit groups separated by one consistent `:`
/// or `-` (`aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF`), or three four-hex-digit
/// groups separated by `.` (`aabb.ccdd.eeff`). The result is the lowercase
/// colon form.
///
/// Bare 12-hex strings, mixed separators, IP/CIDR values and free-form names
/// are rejected. Use [`normalize_mac`] for trusted sources (ARP/RouterOS) that
/// may report a bare hex string, and [`normalize_mac_id`] for operator-supplied
/// client identifiers.
#[must_use]
pub fn is_strict_mac(value: &str) -> Option<String> {
    let value = value.trim();
    // An address or CIDR is never a MAC, even when its hex digits happen to
    // count twelve (for example `::aa:bb:cc:dd:ee:ff`).
    if value.is_empty() || value.contains('/') || value.parse::<IpAddr>().is_ok() {
        return None;
    }

    let has_colon = value.contains(':');
    let has_dash = value.contains('-');
    let has_dot = value.contains('.');
    if usize::from(has_colon) + usize::from(has_dash) + usize::from(has_dot) != 1 {
        return None;
    }

    let (separator, group_len, group_count) = if has_colon {
        (':', 2, 6)
    } else if has_dash {
        ('-', 2, 6)
    } else {
        ('.', 4, 3)
    };

    let groups: Vec<&str> = value.split(separator).collect();
    if groups.len() != group_count
        || !groups
            .iter()
            .all(|group| group.len() == group_len && group.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }

    Some(colon_form(&groups.concat()))
}

/// Normalizes a MAC address from a trusted source (ARP table or RouterOS).
///
/// This accepts the strict explicit shapes of [`is_strict_mac`] and, because
/// ARP/RouterOS values are not operator-supplied identities, a bare 12-hex
/// string (for example `aabbccddeeff`). It still rejects mixed separators,
/// IP/CIDR values, names and other junk.
#[must_use]
pub fn normalize_mac(value: &str) -> Option<String> {
    if let Some(mac) = is_strict_mac(value) {
        return Some(mac);
    }

    let value = value.trim();
    if value.len() == 12 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(colon_form(value));
    }

    None
}

/// Normalizes an operator-supplied client identifier into a MAC address.
///
/// Only strict explicit shapes are accepted, so a bare 12-hex string (a
/// hostname or client name that happens to be all hex digits), an IP/CIDR or
/// a name is never mistaken for a MAC identity. The historical explicit
/// `mac:` prefix is still honored; a value after that marker is treated as an
/// explicit MAC and may also use the bare hex form.
#[must_use]
pub fn normalize_mac_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if let Some(prefix) = trimmed.get(..4)
        && prefix.eq_ignore_ascii_case("mac:")
    {
        return normalize_mac(&trimmed[4..]);
    }

    is_strict_mac(trimmed)
}

/// Formats twelve lowercase hex digits as `aa:bb:cc:dd:ee:ff`.
fn colon_form(hex: &str) -> String {
    let mut mac = String::with_capacity(17);
    for (index, digit) in hex.chars().enumerate() {
        if index > 0 && index % 2 == 0 {
            mac.push(':');
        }
        mac.push(digit.to_ascii_lowercase());
    }
    mac
}

/// Returns true when `target` is contained in `network/prefix`.
///
/// Address families must match; an out-of-range prefix returns `false`.
#[must_use]
pub fn ip_in_subnet(network: IpAddr, prefix: u8, target: IpAddr) -> bool {
    match (network, target) {
        (IpAddr::V4(net), IpAddr::V4(tgt)) => {
            if prefix > 32 {
                return false;
            }
            let mask = v4_mask(prefix);
            (u32::from(net) & mask) == (u32::from(tgt) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(tgt)) => {
            if prefix > 128 {
                return false;
            }
            let mask = v6_mask(prefix);
            (u128::from(net) & mask) == (u128::from(tgt) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn ip(value: &str) -> IpAddr {
        IpAddr::from_str(value).unwrap_or_else(|error| panic!("{value}: {error}"))
    }

    #[test]
    fn test_ipv4_prefix_zero_and_host_prefix() {
        let any = IpNetwork::parse("0.0.0.0/0").expect("valid /0");
        assert!(any.contains(ip("0.0.0.0")));
        assert!(any.contains(ip("192.168.1.1")));
        assert!(any.contains(ip("255.255.255.255")));
        assert!(!any.contains(ip("::1")), "v4 network must not match v6");

        let host = IpNetwork::parse("192.168.1.10/32").expect("valid /32");
        assert!(host.contains(ip("192.168.1.10")));
        assert!(!host.contains(ip("192.168.1.11")));
    }

    #[test]
    fn test_ipv4_network_boundaries_and_host_bits() {
        let net = IpNetwork::parse("10.1.2.3/24").expect("host bits are allowed");
        assert_eq!(net.addr(), ip("10.1.2.3"));
        assert_eq!(net.prefix(), 24);
        assert_eq!(net.network_address(), ip("10.1.2.0"));
        assert!(net.contains(ip("10.1.2.0")));
        assert!(net.contains(ip("10.1.2.255")));
        assert!(!net.contains(ip("10.1.3.0")));
    }

    #[test]
    fn test_ipv6_prefix_zero_and_full_prefix() {
        let any = IpNetwork::parse("::/0").expect("valid /0");
        assert!(any.contains(ip("::")));
        assert!(any.contains(ip("2001:db8::1")));
        assert!(
            !any.contains(ip("192.0.2.1")),
            "v6 network must not match v4"
        );

        let host = IpNetwork::parse("2001:db8::1/128").expect("valid /128");
        assert!(host.contains(ip("2001:db8::1")));
        assert!(!host.contains(ip("2001:db8::2")));

        let subnet = IpNetwork::parse("2001:db8:abcd::/48").expect("valid /48");
        assert!(subnet.contains(ip("2001:db8:abcd:ffff::1")));
        assert!(!subnet.contains(ip("2001:db8:abce::1")));
    }

    #[test]
    fn test_mixed_address_families_never_match() {
        assert!(!ip_in_subnet(ip("10.0.0.0"), 8, ip("::1")));
        assert!(!ip_in_subnet(ip("2001:db8::"), 32, ip("192.0.2.1")));
    }

    #[test]
    fn test_prefix_bounds_are_validated() {
        assert!(matches!(
            IpNetwork::parse("192.0.2.1/33"),
            Err(CidrError::PrefixTooLong {
                prefix: 33,
                max: 32
            })
        ));
        assert!(matches!(
            IpNetwork::parse("2001:db8::1/129"),
            Err(CidrError::PrefixTooLong {
                prefix: 129,
                max: 128
            })
        ));
        assert!(!ip_in_subnet(ip("10.0.0.0"), 33, ip("10.0.0.1")));
        assert!(!ip_in_subnet(ip("2001:db8::"), 129, ip("2001:db8::1")));
    }

    #[test]
    fn test_cidr_parse_rejects_invalid_input() {
        assert!(IpNetwork::parse("10.0.0.0").is_err());
        assert!(IpNetwork::parse("10.0.0.0/").is_err());
        assert!(IpNetwork::parse("/24").is_err());
        assert!(IpNetwork::parse("not-an-ip/24").is_err());
        assert!(IpNetwork::parse("10.0.0.0/not-a-prefix").is_err());

        let parsed = IpNetwork::parse(" 10.0.0.0 / 8 ").expect("whitespace is trimmed");
        assert_eq!(parsed.prefix(), 8);
        assert_eq!(parsed.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn test_from_str_and_new_constructor() {
        let parsed: IpNetwork = "192.168.0.0/16".parse().expect("FromStr");
        assert!(parsed.contains(ip("192.168.255.255")));

        let built = IpNetwork::new(ip("192.168.0.1"), 24).expect("new validates the prefix");
        assert_eq!(built.network_address(), ip("192.168.0.0"));
        assert!(IpNetwork::new(ip("192.168.0.1"), 33).is_err());
    }

    #[test]
    fn test_strict_mac_accepts_only_explicit_shapes() {
        for (input, expected) in [
            ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
            ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
            ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
            (" AABB.CCDD.EEFF ", "aa:bb:cc:dd:ee:ff"),
        ] {
            assert_eq!(is_strict_mac(input).as_deref(), Some(expected), "{input}");
        }

        for input in [
            "aabbccddeeff",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "aa:bb-cc:dd:ee:ff",
            "aa.bb.cc.dd.ee.ff",
            "aabb.cdddeeff",
            "aabbc.cdddeeff",
            "::aa:bb:cc:dd:ee:ff",
            "2001:db8::1",
            "192.168.1.1",
            "10.0.0.0/8",
            "aa:bb:cc:dd:ee:ff/24",
            "janes-phone",
            "abc-def-123456",
            "not-a-mac",
        ] {
            assert_eq!(is_strict_mac(input), None, "{input} must not be a MAC");
        }
    }

    #[test]
    fn test_normalize_mac_accepts_bare_hex_for_trusted_sources() {
        assert_eq!(
            normalize_mac("aabbccddeeff").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(
            normalize_mac("AABBCCDDEEFF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(
            normalize_mac("aa:bb:cc:dd:ee:ff").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        // Trusted normalization is still shape-checked.
        assert_eq!(normalize_mac("::aa:bb:cc:dd:ee:ff"), None);
        assert_eq!(normalize_mac("aa:bb-cc:dd:ee:ff"), None);
        assert_eq!(normalize_mac("deadbeefcafé"), None);
    }

    #[test]
    fn test_normalize_mac_id_rejects_bare_hex_and_non_mac_shapes() {
        assert_eq!(
            normalize_mac_id("AA:BB:CC:DD:EE:FF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(
            normalize_mac_id("aabb.ccdd.eeff").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        // The historical explicit marker allows a bare hex MAC.
        assert_eq!(
            normalize_mac_id("mac:aabbccddeeff").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(normalize_mac_id("aabbccddeeff"), None);
        assert_eq!(normalize_mac_id("::aa:bb:cc:dd:ee:ff"), None);
        assert_eq!(normalize_mac_id("10.0.0.0/8"), None);
        assert_eq!(normalize_mac_id("janes-phone"), None);
    }
}
