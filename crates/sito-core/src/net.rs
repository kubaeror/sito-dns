//! Shared IP network/CIDR matching helpers.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

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
}
