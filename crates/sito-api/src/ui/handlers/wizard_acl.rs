//! First-boot wizard client-ACL step (ADR-0011).
//!
//! The wizard is the only automatic path that writes
//! `clients.default_policy = "deny"`. It must never auto-seed a non-loopback
//! network, must never use the request's `X-Forwarded-For`/trusted-proxy
//! resolution (only the raw TCP peer may be suggested), and must preserve the
//! base configuration's existing `[clients.acl]` prefixes when the operator
//! accepts the default.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use sito_clients::config::{AclDefaultPolicy, ClientAclConfig, ClientsConfig};
use sito_core::config::Config;
use sito_core::net::IpNetwork;

/// Whether a candidate came from a live interface, the raw admin peer, or the
/// base configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AclCandidateSource {
    Loopback,
    Interface,
    AdminPeer,
    BaseTemplate,
}

impl AclCandidateSource {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Interface => "interface",
            Self::AdminPeer => "admin connection",
            Self::BaseTemplate => "base configuration",
        }
    }
}

/// Warning classification for a candidate or manually entered network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AclCandidateClass {
    Loopback,
    PrivateV4,
    UlaV6,
    Public,
    BridgeOrTunnel,
}

impl AclCandidateClass {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::PrivateV4 => "private_v4",
            Self::UlaV6 => "ula_v6",
            Self::Public => "public",
            Self::BridgeOrTunnel => "bridge_or_tunnel",
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Loopback => "Loopback (this host only)",
            Self::PrivateV4 => "Private IPv4 (RFC 1918)",
            Self::UlaV6 => "IPv6 ULA (fc00::/7)",
            Self::Public => "Public address",
            Self::BridgeOrTunnel => "Bridge / tunnel / container",
        }
    }

    pub(crate) const fn is_bridge_or_tunnel(self) -> bool {
        matches!(self, Self::BridgeOrTunnel)
    }
}

/// One selectable client network offered by the wizard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AclCandidate {
    /// Canonical `address/prefix` identifier submitted by the form.
    pub(crate) id: String,
    pub(crate) network: IpNetwork,
    pub(crate) interface: String,
    pub(crate) source: AclCandidateSource,
    pub(crate) class: AclCandidateClass,
}

impl AclCandidate {
    pub(crate) fn family(&self) -> &'static str {
        match self.network.addr() {
            IpAddr::V4(_) => "ipv4",
            IpAddr::V6(_) => "ipv6",
        }
    }

    pub(crate) fn address(&self) -> String {
        self.network.addr().to_string()
    }

    pub(crate) fn prefix(&self) -> u8 {
        self.network.prefix()
    }

    pub(crate) fn is_loopback(&self) -> bool {
        is_loopback_network(canonical_network(self.network))
    }

    pub(crate) fn is_public(&self) -> bool {
        is_public_network(canonical_network(self.network))
    }
}

/// Fresh-install form values for the ACL step. Kept separate from the HTTP
/// form so the decision logic is testable without a live request.
#[derive(Debug, Clone, Default)]
pub(crate) struct AclWizardInput<'a> {
    /// Hidden marker rendered only on a fresh-install wizard. Recovery runs
    /// never render the step and must leave the ACL untouched.
    pub(crate) present: bool,
    pub(crate) default_deny: bool,
    pub(crate) selected: &'a [String],
    pub(crate) manual: &'a str,
    pub(crate) loopback_only_ack: bool,
    pub(crate) public_ack: bool,
    pub(crate) allow_entry_ids: bool,
    pub(crate) allow_all: bool,
    pub(crate) allow_all_confirm: &'a str,
}

/// Result of the ACL step: the keys written into `[clients]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AclWizardOutcome {
    pub(crate) default_policy: AclDefaultPolicy,
    pub(crate) acl: ClientAclConfig,
}

/// Returns the typed `[clients]` table of the base configuration, or defaults
/// when the section is absent/unparseable (the base config was already
/// validated by the loader).
pub(crate) fn base_clients(config: &Config) -> ClientsConfig {
    config
        .clients
        .as_ref()
        .and_then(|value| value.clone().try_into().ok())
        .unwrap_or_default()
}

/// True when the base template explicitly sets `default_policy = "allow"`.
/// Used only for the "this template admits every client" warning.
pub(crate) fn base_template_explicit_allow(config: &Config) -> bool {
    config
        .clients
        .as_ref()
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("default_policy"))
        .and_then(toml::Value::as_str)
        .is_some_and(|policy| policy.eq_ignore_ascii_case("allow"))
}

/// Enumerates the live candidates for the wizard: fixed loopback, one entry per
/// usable interface address, and (when it is not already represented) the raw
/// admin peer suggestion.
///
/// `peer` must be the raw TCP peer (`ConnectInfo`), never an
/// `X-Forwarded-For`/trusted-proxy value. No non-loopback candidate is selected
/// by this function; selection is a rendering concern.
pub(crate) fn discover_candidates(peer: Option<IpAddr>) -> Vec<AclCandidate> {
    let mut candidates = vec![
        loopback_candidate(IpAddr::V4(Ipv4Addr::LOCALHOST), 32),
        loopback_candidate(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
    ];
    candidates.extend(system_interface_candidates());
    if let Some(peer) = peer
        && !peer.is_loopback()
        && !peer.is_unspecified()
        && !candidates
            .iter()
            .any(|candidate| candidate.network.contains(peer))
    {
        let (prefix, source) = match peer {
            IpAddr::V4(_) => (24, AclCandidateSource::AdminPeer),
            IpAddr::V6(_) => (64, AclCandidateSource::AdminPeer),
        };
        if let Ok(network) = IpNetwork::new(peer, prefix) {
            candidates.push(AclCandidate {
                id: canonical_id(network),
                network,
                interface: "admin connection (raw peer)".to_string(),
                source,
                class: classify("", network.addr()),
            });
        }
    }
    dedupe_and_sort(candidates)
}

/// Existing template allow prefixes, canonicalized and rendered as prefilled
/// candidates. These are always preserved when the operator accepts default
/// deny, even if no live interface currently exposes the network.
pub(crate) fn template_prefill_candidates(config: &Config) -> Vec<AclCandidate> {
    let clients = base_clients(config);
    let mut out = Vec::new();
    for raw in &clients.acl.allow {
        let Ok(network) = canonical_network_from_str(raw) else {
            // The base config already validated; a value that cannot be
            // canonicalized here is ignored rather than trusting it blindly.
            continue;
        };
        out.push(AclCandidate {
            id: canonical_id(network),
            network,
            interface: "base configuration allow".to_string(),
            source: AclCandidateSource::BaseTemplate,
            class: classify("", network.addr()),
        });
    }
    dedupe_and_sort(out)
}

/// Canonical set of live IDs the server is currently offering.
pub(crate) fn offered_ids(candidates: &[AclCandidate]) -> HashSet<String> {
    candidates.iter().map(|c| c.id.clone()).collect()
}

/// Parses the manual textarea (one address/CIDR per line; commas and
/// whitespace are also accepted) into canonical prefixes.
pub(crate) fn parse_manual_allow(text: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for part in text.split(|ch: char| ch.is_whitespace() || ch == ',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let canonical = canonical_cidr_string(part)?;
        if seen.insert(canonical.clone()) {
            out.push(canonical);
        }
    }
    Ok(out)
}

/// Canonicalizes a submitted address/CIDR; a bare address becomes a host
/// prefix (`/32` or `/128`).
pub(crate) fn canonical_cidr_string(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("empty network".to_string());
    }
    let network = if value.contains('/') {
        IpNetwork::parse(value).map_err(|e| format!("invalid client network '{value}': {e}"))?
    } else {
        let ip = IpAddr::from_str(value).map_err(|_| {
            format!("invalid client network '{value}': expected an IP address or CIDR")
        })?;
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        IpNetwork::new(ip, prefix).map_err(|e| format!("invalid client network '{value}': {e}"))?
    };
    Ok(canonical_id(network))
}

fn canonical_network_from_str(value: &str) -> Result<IpNetwork, String> {
    let canonical = canonical_cidr_string(value)?;
    IpNetwork::parse(&canonical).map_err(|e| e.to_string())
}

fn canonical_network(network: IpNetwork) -> IpNetwork {
    IpNetwork::new(network.network_address(), network.prefix())
        .expect("a canonical network keeps its valid prefix")
}

fn canonical_id(network: IpNetwork) -> String {
    let network = canonical_network(network);
    format!("{}/{}", network.network_address(), network.prefix())
}

/// Applies the wizard ACL step. Must only be called for a true fresh install
/// (`is_first_run && !is_setup_complete()`). Recovery runs never call it.
pub(crate) fn build_acl(
    input: &AclWizardInput<'_>,
    base: &ClientsConfig,
    live: &[AclCandidate],
    prefill: &[AclCandidate],
) -> Result<AclWizardOutcome, String> {
    if !input.present {
        return Err(
            "Client access control step is missing from this fresh-install submission; reload /wizard and select the allowed client networks."
                .to_string(),
        );
    }

    // Unchecking default deny keeps the template's allow policy. No selection
    // is written, so an operator who explicitly keeps allow never gets a
    // silently narrowed ACL.
    if !input.default_deny {
        return Ok(AclWizardOutcome {
            default_policy: AclDefaultPolicy::Allow,
            acl: base.acl.clone(),
        });
    }

    let deny = base.acl.deny.clone();
    let deny_response = base.acl.deny_response;
    let allow_entry_ids = input.allow_entry_ids;

    if input.allow_all {
        if input.allow_all_confirm.trim() != "ALLOW ALL" {
            return Err(
                "Allow-all requires the exact confirmation text 'ALLOW ALL' in client_acl_allow_all_confirm."
                    .to_string(),
            );
        }
        return Ok(AclWizardOutcome {
            default_policy: AclDefaultPolicy::Deny,
            acl: ClientAclConfig {
                allow: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
                deny,
                allow_entry_ids,
                deny_response,
            },
        });
    }

    let offered: HashSet<String> = offered_ids(live)
        .into_iter()
        .chain(offered_ids(prefill))
        .collect();

    // The prefill set is always preserved, and loopback is always allowed.
    // A submitted candidate must be one the server is currently offering (or
    // one of the template prefixes it rendered as prefilled).
    let mut allow = Vec::new();
    let mut seen = HashSet::new();
    for raw in &base.acl.allow {
        let canonical = canonical_cidr_string(raw)?;
        if seen.insert(canonical.clone()) {
            allow.push(canonical);
        }
    }
    for raw in input.selected {
        let canonical = canonical_cidr_string(raw)?;
        if !offered.contains(&canonical) {
            return Err(format!(
                "Selected client network '{canonical}' is not offered by the current interface list; reload the wizard and select a detected network or enter it manually."
            ));
        }
        if seen.insert(canonical.clone()) {
            allow.push(canonical);
        }
    }
    for canonical in parse_manual_allow(input.manual)? {
        if seen.insert(canonical.clone()) {
            allow.push(canonical);
        }
    }
    for loopback in ["127.0.0.1/32", "::1/128"] {
        if seen.insert(loopback.to_string()) {
            allow.push(loopback.to_string());
        }
    }

    // The prefilled template list is preserved but the operator may also have
    // selected a live interface. Validate exposure and the loopback-only
    // acknowledgement against the final list.
    let networks: Vec<IpNetwork> = allow
        .iter()
        .filter_map(|raw| IpNetwork::parse(raw).ok())
        .map(canonical_network)
        .collect();
    let loopback_only = networks.iter().all(|net| is_loopback_network(*net));
    if loopback_only && !input.loopback_only_ack {
        return Err(
            "Only loopback is allowed, so client_acl_loopback_only_ack must be checked to confirm that only this host may resolve."
                .to_string(),
        );
    }
    if networks.iter().any(|net| is_catch_all_network(*net)) {
        return Err(
            "A manual entry or base-template allow prefix is a catch-all (0.0.0.0/0 or ::/0). Enable client_acl_allow_all and type the exact confirmation 'ALLOW ALL'; a public acknowledgement alone is not enough for an open resolver."
                .to_string(),
        );
    }
    if !input.public_ack && networks.iter().any(|net| is_public_network(*net)) {
        return Err(
            "A public client network is selected or entered; client_acl_public_ack must be checked to confirm the resolver will be reachable from the public Internet."
                .to_string(),
        );
    }

    Ok(AclWizardOutcome {
        default_policy: AclDefaultPolicy::Deny,
        acl: ClientAclConfig {
            allow,
            deny,
            allow_entry_ids,
            deny_response,
        },
    })
}

fn loopback_candidate(ip: IpAddr, prefix: u8) -> AclCandidate {
    let network = IpNetwork::new(ip, prefix).expect("fixed loopback prefix is valid");
    AclCandidate {
        id: canonical_id(network),
        network,
        interface: "loopback".to_string(),
        source: AclCandidateSource::Loopback,
        class: AclCandidateClass::Loopback,
    }
}

fn dedupe_and_sort(candidates: Vec<AclCandidate>) -> Vec<AclCandidate> {
    let mut out: Vec<AclCandidate> = Vec::new();
    let mut seen = HashSet::new();
    for candidate in candidates {
        if seen.insert(candidate.id.clone()) {
            out.push(candidate);
        }
    }
    out.sort_by(|a, b| {
        let rank = |source: AclCandidateSource| match source {
            AclCandidateSource::Loopback => 0,
            AclCandidateSource::Interface => 1,
            AclCandidateSource::AdminPeer => 2,
            AclCandidateSource::BaseTemplate => 3,
        };
        rank(a.source)
            .cmp(&rank(b.source))
            .then_with(|| a.interface.cmp(&b.interface))
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

fn classify(interface: &str, ip: IpAddr) -> AclCandidateClass {
    if is_bridge_or_tunnel_name(interface) {
        return AclCandidateClass::BridgeOrTunnel;
    }
    if ip.is_loopback() {
        return AclCandidateClass::Loopback;
    }
    match ip {
        IpAddr::V4(ip) if ip.is_private() => AclCandidateClass::PrivateV4,
        IpAddr::V6(ip) if is_ula_v6(ip) => AclCandidateClass::UlaV6,
        _ => AclCandidateClass::Public,
    }
}

fn is_bridge_or_tunnel_name(interface: &str) -> bool {
    let name = interface.to_ascii_lowercase();
    [
        "docker",
        "br-",
        "veth",
        "virbr",
        "cni",
        "flannel",
        "podman",
        "tun",
        "tap",
        "wg",
        "tailscale",
        "zt",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn is_ula_v6(ip: Ipv6Addr) -> bool {
    matches!(ip.octets()[0], 0xfc | 0xfd)
}

fn is_loopback_network(network: IpNetwork) -> bool {
    match network.network_address() {
        IpAddr::V4(addr) => network.prefix() >= 8 && addr.octets()[0] == 127,
        IpAddr::V6(addr) => network.prefix() == 128 && addr == Ipv6Addr::LOCALHOST,
    }
}

fn is_public_network(network: IpNetwork) -> bool {
    match network.network_address() {
        IpAddr::V4(_) => !v4_network_is_private(network) && !is_loopback_network(network),
        IpAddr::V6(_) => !v6_network_is_ula(network) && !is_loopback_network(network),
    }
}

fn is_catch_all_network(network: IpNetwork) -> bool {
    if network.prefix() != 0 {
        return false;
    }
    match network.network_address() {
        IpAddr::V4(addr) => addr.is_unspecified(),
        IpAddr::V6(addr) => addr.is_unspecified(),
    }
}

fn v4_network_is_private(network: IpNetwork) -> bool {
    let IpAddr::V4(start) = network.network_address() else {
        return false;
    };
    let prefix = network.prefix();
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let start = u32::from(start);
    let end = start | !mask;
    (start >= u32::from(Ipv4Addr::new(10, 0, 0, 0))
        && end <= u32::from(Ipv4Addr::new(10, 255, 255, 255)))
        || (start >= u32::from(Ipv4Addr::new(172, 16, 0, 0))
            && end <= u32::from(Ipv4Addr::new(172, 31, 255, 255)))
        || (start >= u32::from(Ipv4Addr::new(192, 168, 0, 0))
            && end <= u32::from(Ipv4Addr::new(192, 168, 255, 255)))
}

fn v6_network_is_ula(network: IpNetwork) -> bool {
    let IpAddr::V6(start) = network.network_address() else {
        return false;
    };
    if network.prefix() < 7 || !is_ula_v6(start) {
        return false;
    }
    let prefix = network.prefix();
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    let start = u128::from(start);
    let end = start | !mask;
    let ula_start = u128::from(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0));
    let ula_end = u128::from(Ipv6Addr::new(
        0xfdff,
        u16::MAX,
        u16::MAX,
        u16::MAX,
        u16::MAX,
        u16::MAX,
        u16::MAX,
        u16::MAX,
    ));
    start >= ula_start && end <= ula_end
}

// ---------------------------------------------------------------------------
// Interface discovery
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn system_interface_candidates() -> Vec<AclCandidate> {
    use std::ffi::CStr;

    struct IfAddrsGuard(*mut libc::ifaddrs);
    impl Drop for IfAddrsGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from `getifaddrs` and is freed once.
                unsafe { libc::freeifaddrs(self.0) };
            }
        }
    }

    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` writes an owned linked list into `list`.
    if unsafe { libc::getifaddrs(std::ptr::addr_of_mut!(list)) } != 0 {
        return Vec::new();
    }
    let guard = IfAddrsGuard(list);
    let mut out = Vec::new();
    let mut cursor = guard.0;
    while !cursor.is_null() {
        // SAFETY: `cursor` is a node in the list returned by `getifaddrs`.
        let ifa = unsafe { &*cursor };
        cursor = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` points at a `sockaddr` owned by the list.
        let family = unsafe { i32::from((*ifa.ifa_addr).sa_family) };
        if family != libc::AF_INET && family != libc::AF_INET6 {
            continue;
        }
        if ifa.ifa_flags & libc::IFF_UP as u32 == 0 {
            continue;
        }
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();

        let address = if family == libc::AF_INET {
            // SAFETY: the family check guarantees a `sockaddr_in`.
            let sin = unsafe { &*(ifa.ifa_addr.cast::<libc::sockaddr_in>()) };
            IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
        } else {
            // SAFETY: the family check guarantees a `sockaddr_in6`.
            let sin6 = unsafe { &*(ifa.ifa_addr.cast::<libc::sockaddr_in6>()) };
            IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr))
        };
        if !is_usable_interface_address(address) {
            continue;
        }
        let suggested = if address.is_ipv4() { 24 } else { 64 };
        let prefix = interface_prefix(ifa.ifa_netmask, family).unwrap_or(suggested);
        let network = IpNetwork::new(address, prefix)
            .unwrap_or_else(|_| IpNetwork::new(address, suggested).expect("suggested prefix"));
        out.push(AclCandidate {
            id: canonical_id(network),
            network,
            interface: name.clone(),
            source: AclCandidateSource::Interface,
            class: classify(&name, address),
        });
    }
    out
}

#[cfg(not(unix))]
fn system_interface_candidates() -> Vec<AclCandidate> {
    Vec::new()
}

#[cfg(unix)]
fn interface_prefix(netmask: *const libc::sockaddr, family: i32) -> Option<u8> {
    if netmask.is_null() {
        return None;
    }
    // SAFETY: the caller passes the `ifa_netmask` of the same addrinfo whose
    // address family matched.
    if unsafe { i32::from((*netmask).sa_family) } != family {
        return None;
    }
    if family == libc::AF_INET {
        // SAFETY: family matches `sockaddr_in`.
        let sin = unsafe { &*(netmask.cast::<libc::sockaddr_in>()) };
        let mask = u32::from_be(sin.sin_addr.s_addr);
        if mask == 0 || mask.leading_ones() != mask.count_ones() {
            return None;
        }
        u8::try_from(mask.leading_ones()).ok()
    } else {
        // SAFETY: family matches `sockaddr_in6`.
        let sin6 = unsafe { &*(netmask.cast::<libc::sockaddr_in6>()) };
        let mask = u128::from_be_bytes(sin6.sin6_addr.s6_addr);
        if mask == 0 || mask.leading_ones() != mask.count_ones() {
            return None;
        }
        u8::try_from(mask.leading_ones()).ok()
    }
}

fn is_usable_interface_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            !ip.is_loopback()
                && !ip.is_unicast_link_local()
                && !ip.is_unspecified()
                && !ip.is_multicast()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wizard_acl_manual_parsing_canonicalizes_and_dedupes() {
        let parsed = parse_manual_allow(
            "192.168.1.7/24\n192.168.1.0/24\n2001:db8::1\n  \n# not a comment\n",
        )
        .expect_err("a comment is not a network");
        assert!(parsed.contains("invalid client network"));

        let parsed =
            parse_manual_allow("192.168.1.7/24, 192.168.1.0/24\n2001:db8::1").expect("parse");
        assert_eq!(
            parsed,
            vec!["192.168.1.0/24".to_string(), "2001:db8::1/128".to_string()]
        );
    }

    #[test]
    fn test_wizard_acl_public_and_private_classification() {
        let private = canonical_network_from_str("192.168.1.0/24").unwrap();
        let public = canonical_network_from_str("203.0.113.0/24").unwrap();
        let ula = canonical_network_from_str("fd00:1::/64").unwrap();
        let loopback = canonical_network_from_str("127.0.0.1/32").unwrap();
        assert!(!is_public_network(private));
        assert!(is_public_network(public));
        assert!(!is_public_network(ula));
        assert!(!is_public_network(loopback));
        assert!(is_loopback_network(loopback));
        assert!(!is_loopback_network(private));
    }

    #[test]
    fn test_wizard_acl_candidate_discovery_never_preselects() {
        let candidates = discover_candidates(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))));
        assert!(
            candidates
                .iter()
                .any(|c| c.id == "127.0.0.1/32" && c.is_loopback()),
            "fixed loopback candidate must always be offered"
        );
        assert!(
            candidates
                .iter()
                .any(|c| c.id == "::1/128" && c.is_loopback()),
            "fixed IPv6 loopback candidate must always be offered"
        );
        let peer = candidates
            .iter()
            .find(|c| c.source == AclCandidateSource::AdminPeer)
            .expect("public raw peer is shown as a candidate");
        assert_eq!(peer.class, AclCandidateClass::Public);
    }
}
