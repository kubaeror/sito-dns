//! DNS client source-address ACL (ADR-0011).
//!
//! The ACL is a pure function of the shared `[clients]` configuration and the
//! observed peer address. It never consults DoH path/SNI, headers, MAC/ARP,
//! RouterOS leases, secrets or groups. The index is compiled once per client
//! registry snapshot so the query path only scans canonical prefixes.
//!
//! Order is fixed: deny first (deny is authoritative), then explicit allow,
//! then opt-in client-entry allow, then `default_policy`. Longest-prefix match
//! is used only to pick the most specific same-action rule for reporting.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

use sito_core::net::IpNetwork;
use thiserror::Error;

use crate::config::{AclDefaultPolicy, AclDenyResponse, ClientsConfig};

/// Maximum number of prefixes in each explicit `allow`/`deny` list.
pub const MAX_ACL_PREFIXES: usize = 1024;

/// Address family of an ACL decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AclFamily {
    Ipv4,
    Ipv6,
}

impl AclFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

impl fmt::Display for AclFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Admission action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AclAction {
    Allow,
    Deny,
}

impl AclAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Why the action was chosen. These strings are the bounded metric labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AclReason {
    ExplicitAllow,
    ExplicitDeny,
    ClientEntry,
    DefaultPolicy,
}

impl AclReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitAllow => "explicit_allow",
            Self::ExplicitDeny => "explicit_deny",
            Self::ClientEntry => "client_entry",
            Self::DefaultPolicy => "default_policy",
        }
    }
}

/// A canonical (host-bits-masked) ACL prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AclPrefix {
    network: IpNetwork,
}

impl AclPrefix {
    fn new(network: IpNetwork) -> Self {
        // `IpNetwork::new` validates the prefix against the family; the
        // canonical network address makes duplicate detection stable.
        let canonical = IpNetwork::new(network.network_address(), network.prefix())
            .expect("a parsed network keeps its valid prefix");
        Self { network: canonical }
    }

    /// Builds a host prefix from a bare address.
    #[must_use]
    pub fn host(ip: IpAddr) -> Self {
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self::new(IpNetwork::new(ip, prefix).expect("a host prefix is always valid"))
    }

    #[must_use]
    pub fn network(&self) -> IpNetwork {
        self.network
    }

    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.network.prefix()
    }

    #[must_use]
    pub fn family(&self) -> AclFamily {
        match self.network.addr() {
            IpAddr::V4(_) => AclFamily::Ipv4,
            IpAddr::V6(_) => AclFamily::Ipv6,
        }
    }

    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.network.contains(ip)
    }

    /// Canonical label, always `network/prefix` with host bits masked.
    #[must_use]
    pub fn label(&self) -> String {
        format!(
            "{}/{}",
            self.network.network_address(),
            self.network.prefix()
        )
    }

    /// True when every address in the prefix is loopback.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        match self.network.network_address() {
            IpAddr::V4(addr) => self.network.prefix() >= 8 && addr.octets()[0] == 127,
            IpAddr::V6(addr) => {
                self.network.prefix() == 128 && addr == std::net::Ipv6Addr::LOCALHOST
            }
        }
    }
}

impl fmt::Display for AclPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}",
            self.network.network_address(),
            self.network.prefix()
        )
    }
}

/// The admission decision for one observed source address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclDecision<'a> {
    pub action: AclAction,
    pub reason: AclReason,
    pub family: AclFamily,
    /// Most specific matching configured prefix, or `None` for the default
    /// policy. Never a client-supplied value.
    pub matched: Option<&'a AclPrefix>,
}

impl AclDecision<'_> {
    #[must_use]
    pub fn is_denied(&self) -> bool {
        self.action == AclAction::Deny
    }
}

/// A typed ACL configuration error naming the offending key and value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{field}: {message}")]
pub struct AclConfigError {
    pub field: String,
    pub message: String,
}

impl AclConfigError {
    fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

/// Compiled, immutable ACL index carried by a client-registry snapshot.
#[derive(Debug, Clone)]
pub struct AclIndex {
    default_policy: AclDefaultPolicy,
    deny_response: AclDenyResponse,
    allow: Vec<AclPrefix>,
    deny: Vec<AclPrefix>,
    entry_allow: Vec<AclPrefix>,
    warnings: Vec<String>,
}

impl Default for AclIndex {
    fn default() -> Self {
        Self {
            default_policy: AclDefaultPolicy::Allow,
            deny_response: AclDenyResponse::Refused,
            allow: Vec::new(),
            deny: Vec::new(),
            entry_allow: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

impl AclIndex {
    /// Compiles the ACL for `config`, validating `[clients.acl]` and the
    /// opt-in entry ids. Returns the first error rather than silently dropping
    /// a rule.
    pub fn compile(config: &ClientsConfig) -> Result<Self, AclConfigError> {
        let allow = compile_list(&config.acl.allow, "clients.acl.allow")?;
        let deny = compile_list(&config.acl.deny, "clients.acl.deny")?;

        let allow_set: HashSet<IpNetwork> = allow.iter().map(AclPrefix::network).collect();
        for denied in &deny {
            if allow_set.contains(&denied.network()) {
                return Err(AclConfigError::new(
                    "clients.acl.deny",
                    format!(
                        "prefix '{}' appears in both clients.acl.allow and clients.acl.deny; choose one action",
                        denied.label()
                    ),
                ));
            }
        }

        let mut entry_allow = Vec::new();
        let mut warnings = Vec::new();
        if config.acl.allow_entry_ids {
            warnings.push(
                "clients.acl.allow_entry_ids = true: static IP/CIDR values in \
                 clients.entries[].ids are admitted as DNS sources"
                    .to_string(),
            );
            let mut seen = HashSet::new();
            for entry in &config.entries {
                for id in &entry.ids {
                    let Some(prefix) = parse_entry_id(id) else {
                        continue;
                    };
                    if prefix.prefix_len() == 0 {
                        warnings.push(format!(
                            "client entry '{}' id '{id}' is a catch-all prefix '{}': \
                             allow_entry_ids admits every {} source through this entry",
                            entry.name,
                            prefix.label(),
                            prefix.family().as_str()
                        ));
                    }
                    if seen.insert(prefix.network()) {
                        entry_allow.push(prefix);
                    }
                }
            }
            sort_specific_first(&mut entry_allow);
        }

        if config.default_policy == AclDefaultPolicy::Deny
            && !allow.iter().any(|prefix| !prefix.is_loopback())
            && !entry_allow.iter().any(|prefix| !prefix.is_loopback())
        {
            warnings.push(
                "clients.default_policy = \"deny\" with no allow network outside loopback: \
                 DNS clients (including the LAN) will be refused; add [clients.acl] allow \
                 entries or client entry ids deliberately"
                    .to_string(),
            );
        }

        Ok(Self {
            default_policy: config.default_policy,
            deny_response: config.acl.deny_response,
            allow,
            deny,
            entry_allow,
            warnings,
        })
    }

    /// A fail-closed index used only if a hand-built registry contains an
    /// invalid ACL. Server configuration paths validate before this point.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            default_policy: AclDefaultPolicy::Deny,
            deny_response: AclDenyResponse::Refused,
            allow: Vec::new(),
            deny: Vec::new(),
            entry_allow: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[must_use]
    pub fn default_policy(&self) -> AclDefaultPolicy {
        self.default_policy
    }

    #[must_use]
    pub fn deny_response(&self) -> AclDenyResponse {
        self.deny_response
    }

    /// Configuration/startup warnings (opt-in entry admission, catch-all
    /// entry, accidental total lockout). These name configuration only.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Number of explicit allow prefixes (not entry-derived).
    #[must_use]
    pub fn allow_len(&self) -> usize {
        self.allow.len()
    }

    /// Number of explicit deny prefixes.
    #[must_use]
    pub fn deny_len(&self) -> usize {
        self.deny.len()
    }

    /// Number of opt-in entry-derived allow prefixes.
    #[must_use]
    pub fn entry_allow_len(&self) -> usize {
        self.entry_allow.len()
    }

    /// Decides admission for the observed peer address.
    ///
    /// IPv4-mapped IPv6 sources are canonicalized to IPv4 so they match the
    /// same rules as the transport rate limiter. Families never cross-match.
    #[must_use]
    pub fn decide(&self, source: IpAddr) -> AclDecision<'_> {
        let (source, family) = canonical_source(source);

        if let Some(prefix) = first_match(&self.deny, source) {
            return AclDecision {
                action: AclAction::Deny,
                reason: AclReason::ExplicitDeny,
                family,
                matched: Some(prefix),
            };
        }
        if let Some(prefix) = first_match(&self.allow, source) {
            return AclDecision {
                action: AclAction::Allow,
                reason: AclReason::ExplicitAllow,
                family,
                matched: Some(prefix),
            };
        }
        if let Some(prefix) = first_match(&self.entry_allow, source) {
            return AclDecision {
                action: AclAction::Allow,
                reason: AclReason::ClientEntry,
                family,
                matched: Some(prefix),
            };
        }
        AclDecision {
            action: match self.default_policy {
                AclDefaultPolicy::Allow => AclAction::Allow,
                AclDefaultPolicy::Deny => AclAction::Deny,
            },
            reason: AclReason::DefaultPolicy,
            family,
            matched: None,
        }
    }
}

/// Canonicalizes an IPv4-mapped IPv6 source to IPv4 and reports its family.
///
/// The rate limiter keys on the same canonical form; membership always masks.
#[must_use]
pub fn canonical_source(source: IpAddr) -> (IpAddr, AclFamily) {
    if let IpAddr::V6(v6) = source
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        return (IpAddr::V4(v4), AclFamily::Ipv4);
    }
    let family = match source {
        IpAddr::V4(_) => AclFamily::Ipv4,
        IpAddr::V6(_) => AclFamily::Ipv6,
    };
    (source, family)
}

fn first_match(prefixes: &[AclPrefix], source: IpAddr) -> Option<&AclPrefix> {
    prefixes
        .iter()
        .find(|prefix| prefix.family() == family_of(source) && prefix.contains(source))
}

fn family_of(ip: IpAddr) -> AclFamily {
    match ip {
        IpAddr::V4(_) => AclFamily::Ipv4,
        IpAddr::V6(_) => AclFamily::Ipv6,
    }
}

fn compile_list(values: &[String], field: &str) -> Result<Vec<AclPrefix>, AclConfigError> {
    if values.len() > MAX_ACL_PREFIXES {
        return Err(AclConfigError::new(
            field,
            format!(
                "contains {} entries; at most {MAX_ACL_PREFIXES} prefixes are allowed",
                values.len()
            ),
        ));
    }

    let mut prefixes = Vec::with_capacity(values.len());
    let mut seen = HashSet::new();
    for (index, value) in values.iter().enumerate() {
        let prefix = parse_prefix(value).map_err(|message| {
            AclConfigError::new(
                format!("{field}[{index}]"),
                format!("invalid value '{value}': {message}"),
            )
        })?;
        if !seen.insert(prefix.network()) {
            return Err(AclConfigError::new(
                format!("{field}[{index}]"),
                format!("duplicate canonical prefix '{}'", prefix.label()),
            ));
        }
        prefixes.push(prefix);
    }
    sort_specific_first(&mut prefixes);
    Ok(prefixes)
}

fn sort_specific_first(prefixes: &mut [AclPrefix]) {
    prefixes.sort_by(|a, b| {
        b.prefix_len().cmp(&a.prefix_len()).then_with(|| {
            a.network()
                .network_address()
                .cmp(&b.network().network_address())
        })
    });
}

/// Parses one configured `allow`/`deny` value. A bare address is a host
/// prefix (`/32` or `/128`).
fn parse_prefix(value: &str) -> Result<AclPrefix, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("empty prefix".to_string());
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(AclPrefix::host(ip));
    }
    let network = IpNetwork::parse(value).map_err(|e| e.to_string())?;
    Ok(AclPrefix::new(network))
}

/// Parses an entry id as an IP/CIDR allow rule. MAC, hostname, DoH path and
/// SNI ids never parse here and therefore never admit.
fn parse_entry_id(value: &str) -> Option<AclPrefix> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(AclPrefix::host(ip));
    }
    // A CIDR id must start with a literal address, otherwise a DoH path such
    // as `/dns-query/foo` would be considered structure.
    let (address, prefix) = value.split_once('/')?;
    if prefix.is_empty() || address.parse::<IpAddr>().is_err() {
        return None;
    }
    let network = IpNetwork::parse(value).ok()?;
    Some(AclPrefix::new(network))
}

#[cfg(test)]
#[allow(clippy::assert_is_empty)]
mod tests {
    use super::*;
    use crate::config::{ClientEntryConfig, ClientsConfig};
    use std::collections::HashMap;

    fn config(default: AclDefaultPolicy, allow: &[&str], deny: &[&str]) -> ClientsConfig {
        ClientsConfig {
            default_policy: default,
            acl: crate::config::ClientAclConfig {
                allow: allow.iter().map(|s| (*s).to_string()).collect(),
                deny: deny.iter().map(|s| (*s).to_string()).collect(),
                ..Default::default()
            },
            ..ClientsConfig::default()
        }
    }

    fn entry(name: &str, ids: &[&str]) -> ClientEntryConfig {
        ClientEntryConfig {
            name: name.to_string(),
            ids: ids.iter().map(|s| (*s).to_string()).collect(),
            group: "default".to_string(),
            ignore_query_log: false,
            ignore_stats: false,
            use_global_upstreams: true,
            upstreams: None,
            trusted: false,
        }
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn test_acl_defaults_are_compatibility_first() {
        let cfg = ClientsConfig::default();
        assert_eq!(cfg.default_policy, AclDefaultPolicy::Allow);
        assert!(cfg.acl.allow.is_empty());
        assert!(cfg.acl.deny.is_empty());
        assert!(!cfg.acl.allow_entry_ids);
        assert_eq!(cfg.acl.deny_response, AclDenyResponse::Refused);

        let index = AclIndex::compile(&cfg).unwrap();
        let decision = index.decide(ip("203.0.113.10"));
        assert_eq!(decision.action, AclAction::Allow);
        assert_eq!(decision.reason, AclReason::DefaultPolicy);
        assert!(decision.matched.is_none());
        assert!(index.warnings().is_empty());
    }

    #[test]
    fn test_acl_allow_deny_ipv4() {
        let cfg = config(AclDefaultPolicy::Deny, &["192.0.2.0/24"], &[]);
        let index = AclIndex::compile(&cfg).unwrap();
        let inside = index.decide(ip("192.0.2.55"));
        assert_eq!(inside.action, AclAction::Allow);
        assert_eq!(inside.reason, AclReason::ExplicitAllow);
        assert_eq!(inside.matched.unwrap().label(), "192.0.2.0/24");
        assert_eq!(inside.family, AclFamily::Ipv4);

        let outside = index.decide(ip("192.0.3.1"));
        assert_eq!(outside.action, AclAction::Deny);
        assert_eq!(outside.reason, AclReason::DefaultPolicy);
    }

    #[test]
    fn test_acl_allow_deny_ipv6_family_is_independent() {
        let cfg = config(AclDefaultPolicy::Deny, &["2001:db8:1::/64", "::1/128"], &[]);
        let index = AclIndex::compile(&cfg).unwrap();
        assert_eq!(index.decide(ip("2001:db8:1::5")).action, AclAction::Allow);
        assert_eq!(index.decide(ip("::1")).action, AclAction::Allow);
        assert_eq!(index.decide(ip("2001:db8:2::5")).action, AclAction::Deny);
        // `::/0` (here implicit through the default deny) never covers IPv4.
        assert_eq!(index.decide(ip("127.0.0.1")).action, AclAction::Deny);
        assert_eq!(index.decide(ip("2001:db8:1::5")).family, AclFamily::Ipv6);
    }

    #[test]
    fn test_acl_nested_prefix_reports_most_specific() {
        let cfg = config(AclDefaultPolicy::Deny, &["10.1.0.0/16", "10.1.2.0/24"], &[]);
        let index = AclIndex::compile(&cfg).unwrap();
        let decision = index.decide(ip("10.1.2.9"));
        assert_eq!(decision.action, AclAction::Allow);
        assert_eq!(decision.matched.unwrap().label(), "10.1.2.0/24");
    }

    #[test]
    fn test_acl_deny_is_authoritative() {
        let mut cfg = config(
            AclDefaultPolicy::Deny,
            &["10.0.0.0/8", "10.9.9.9/32"],
            &["10.9.0.0/16"],
        );
        cfg.acl.allow_entry_ids = true;
        cfg.entries = vec![entry("guest", &["10.9.9.9"])];
        let index = AclIndex::compile(&cfg).unwrap();
        let decision = index.decide(ip("10.9.9.9"));
        assert_eq!(decision.action, AclAction::Deny);
        assert_eq!(decision.reason, AclReason::ExplicitDeny);
        assert_eq!(decision.matched.unwrap().label(), "10.9.0.0/16");
    }

    #[test]
    fn test_acl_longest_deny_reported() {
        let cfg = config(AclDefaultPolicy::Allow, &[], &["10.0.0.0/8", "10.9.0.0/16"]);
        let index = AclIndex::compile(&cfg).unwrap();
        let decision = index.decide(ip("10.9.1.1"));
        assert_eq!(decision.action, AclAction::Deny);
        assert_eq!(decision.matched.unwrap().label(), "10.9.0.0/16");
    }

    #[test]
    fn test_acl_mapped_ipv6_uses_ipv4_rules() {
        let cfg = config(AclDefaultPolicy::Deny, &["192.0.2.0/24"], &[]);
        let index = AclIndex::compile(&cfg).unwrap();
        let decision = index.decide(ip("::ffff:192.0.2.10"));
        assert_eq!(decision.action, AclAction::Allow);
        assert_eq!(decision.reason, AclReason::ExplicitAllow);
        assert_eq!(decision.family, AclFamily::Ipv4);
    }

    #[test]
    fn test_acl_zero_prefix_is_family_scoped() {
        let cfg = config(AclDefaultPolicy::Deny, &["0.0.0.0/0"], &[]);
        let index = AclIndex::compile(&cfg).unwrap();
        assert_eq!(index.decide(ip("198.51.100.4")).action, AclAction::Allow);
        let v6 = index.decide(ip("2001:db8::1"));
        assert_eq!(v6.action, AclAction::Deny);
        assert_eq!(v6.family, AclFamily::Ipv6);
    }

    #[test]
    fn test_acl_entry_ids_do_not_admit_by_default() {
        let mut cfg = config(AclDefaultPolicy::Deny, &[], &[]);
        cfg.entries = vec![entry("tablet", &["192.0.2.55"])];
        let index = AclIndex::compile(&cfg).unwrap();
        assert_eq!(index.decide(ip("192.0.2.55")).action, AclAction::Deny);
    }

    #[test]
    fn test_acl_entry_ids_opt_in_admits() {
        let mut cfg = config(AclDefaultPolicy::Deny, &[], &[]);
        cfg.acl.allow_entry_ids = true;
        cfg.entries = vec![entry("tablet", &["192.0.2.55", "192.0.2.0/24"])];
        let index = AclIndex::compile(&cfg).unwrap();
        let decision = index.decide(ip("192.0.2.55"));
        assert_eq!(decision.action, AclAction::Allow);
        assert_eq!(decision.reason, AclReason::ClientEntry);
        assert_eq!(decision.matched.unwrap().label(), "192.0.2.55/32");
        assert_eq!(index.decide(ip("192.0.2.99")).action, AclAction::Allow);
    }

    #[test]
    fn test_acl_non_ip_entry_ids_do_not_admit() {
        let mut cfg = config(AclDefaultPolicy::Deny, &[], &[]);
        cfg.acl.allow_entry_ids = true;
        cfg.entries = vec![entry(
            "weird",
            &[
                "aa:bb:cc:dd:ee:ff",
                "mac:aa:bb:cc:dd:ee:ff",
                "kid-tablet",
                "/dns-query/kid-tablet",
            ],
        )];
        let index = AclIndex::compile(&cfg).unwrap();
        assert_eq!(index.entry_allow_len(), 0);
        assert_eq!(index.decide(ip("192.0.2.55")).action, AclAction::Deny);
    }

    #[test]
    fn test_acl_duplicate_and_conflict_rejected() {
        let dup = config(
            AclDefaultPolicy::Allow,
            &["192.168.1.7/24", "192.168.1.0/24"],
            &[],
        );
        let err = AclIndex::compile(&dup).unwrap_err();
        assert!(err.field.starts_with("clients.acl.allow"));
        assert!(err.message.contains("192.168.1.0/24"), "{err}");

        let conflict = config(
            AclDefaultPolicy::Allow,
            &["192.0.2.0/24"],
            &["192.0.2.0/24"],
        );
        let err = AclIndex::compile(&conflict).unwrap_err();
        assert_eq!(err.field, "clients.acl.deny");
        assert!(err.message.contains("192.0.2.0/24"), "{err}");
    }

    #[test]
    fn test_acl_invalid_prefix_and_cap_rejected() {
        for (allow, needle) in [
            ("192.0.2.0/33", "prefix"),
            ("2001:db8::/129", "prefix"),
            ("not-a-network", "invalid value"),
        ] {
            let err =
                AclIndex::compile(&config(AclDefaultPolicy::Allow, &[allow], &[])).unwrap_err();
            assert!(err.field.starts_with("clients.acl.allow"), "{err}");
            assert!(
                err.message.contains(needle) || err.message.contains(allow),
                "{err}"
            );
        }

        let too_many: Vec<String> = (0..=MAX_ACL_PREFIXES)
            .map(|i| format!("198.51.{}.{}/32", 100 + i / 256, i % 256))
            .collect();
        let err = AclIndex::compile(&ClientsConfig {
            acl: crate::config::ClientAclConfig {
                allow: too_many,
                ..Default::default()
            },
            ..ClientsConfig::default()
        })
        .unwrap_err();
        assert_eq!(err.field, "clients.acl.allow");
        assert!(err.message.contains("at most"), "{err}");
    }

    #[test]
    fn test_acl_entry_allow_all_warns() {
        let mut cfg = config(AclDefaultPolicy::Deny, &[], &[]);
        cfg.acl.allow_entry_ids = true;
        cfg.entries = vec![entry("everyone", &["0.0.0.0/0", "::/0"])];
        let index = AclIndex::compile(&cfg).unwrap();
        let warnings = index.warnings().join("\n");
        assert!(warnings.contains("allow_entry_ids = true"), "{warnings}");
        assert!(warnings.contains("everyone"), "{warnings}");
        assert!(warnings.contains("0.0.0.0/0"), "{warnings}");
        assert!(warnings.contains("::/0"), "{warnings}");
        assert_eq!(index.decide(ip("203.0.113.5")).action, AclAction::Allow);
    }

    #[test]
    fn test_acl_loopback_only_deny_warns_and_is_valid() {
        let cfg = config(AclDefaultPolicy::Deny, &["127.0.0.1/32", "::1/128"], &[]);
        let index = AclIndex::compile(&cfg).unwrap();
        assert_eq!(index.decide(ip("127.0.0.1")).action, AclAction::Allow);
        assert_eq!(index.decide(ip("::1")).action, AclAction::Allow);
        assert!(
            index
                .warnings()
                .iter()
                .any(|warning| warning.contains("no allow network outside loopback")),
            "{:?}",
            index.warnings()
        );
    }

    #[test]
    fn test_acl_canonicalizes_host_bits() {
        let cfg = config(AclDefaultPolicy::Deny, &["192.168.1.77/24"], &[]);
        let index = AclIndex::compile(&cfg).unwrap();
        assert_eq!(
            index.decide(ip("192.168.1.42")).matched.unwrap().label(),
            "192.168.1.0/24"
        );
    }

    #[test]
    fn test_acl_groups_and_policy_fields_are_not_inputs() {
        // The index has no group/trusted input at all; this test pins that a
        // deny default is unchanged by a client entry with policy flags.
        let mut cfg = config(AclDefaultPolicy::Deny, &[], &[]);
        cfg.entries = vec![ClientEntryConfig {
            trusted: true,
            ..entry("trusted-laptop", &["192.0.2.10"])
        }];
        cfg.groups = HashMap::from([(
            "default".to_string(),
            crate::config::ClientGroupConfig {
                filtering: false,
                ..Default::default()
            },
        )]);
        let index = AclIndex::compile(&cfg).unwrap();
        assert_eq!(index.decide(ip("192.0.2.10")).action, AclAction::Deny);
    }
}
