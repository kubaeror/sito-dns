//! Rule parser supporting AdGuard Home ABP syntax, hosts format, and modifiers.

use hickory_proto::rr::RecordType;
use sito_core::client::ClientContext;
use sito_proto::normalize_domain;
use std::collections::HashSet;
use std::fmt;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::warn;

/// Standard loopback / broadcast system hostnames to ignore.
pub const IGNORED_HOSTNAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
    "::1",
    "::",
];

/// Rule action kind: Allowlist (`@@`) or Blocklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleKind {
    Allow,
    Block,
}

impl fmt::Display for RuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "@@"),
            Self::Block => Ok(()),
        }
    }
}

/// The pattern specifying how a rule matches domain names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Pattern {
    /// Exact domain match: e.g. hosts file entry `0.0.0.0 ads.example.com` or `|example.com|`.
    Exact(String),
    /// Domain and all its subdomains: e.g. `||example.com^` or plain `example.com`.
    Domain(String),
    /// Prefix match: e.g. `|prefix` (domain starts with `prefix`).
    Prefix(String),
    /// Substring match: e.g. `adserver` (domain contains substring).
    Substring(String),
    /// Wildcard match: e.g. `bad*.example.com` or `*.banner.*`.
    Wildcard(String),
    /// Regular expression: e.g. `/^ads\..*\.com$/`.
    Regex(String),
}

/// Client matcher for `$client` modifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClientMatcher {
    Ip(IpAddr),
    Cidr { ip: IpAddr, prefix: u8 },
    Name(String),
}

impl ClientMatcher {
    pub fn matches(&self, ctx: &ClientContext) -> bool {
        match self {
            Self::Ip(ip) => ctx.ip == *ip,
            Self::Cidr { ip, prefix } => cidr_matches(*ip, *prefix, ctx.ip),
            Self::Name(name) => {
                if let Some(id) = &ctx.id {
                    id.as_str().eq_ignore_ascii_case(name)
                } else {
                    false
                }
            }
        }
    }
}

impl fmt::Display for ClientMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Cidr { ip, prefix } => write!(f, "{ip}/{prefix}"),
            Self::Name(name) => write!(f, "{name}"),
        }
    }
}

/// Verifies whether `target` IP falls within `net_ip/prefix` CIDR block.
pub fn cidr_matches(net_ip: IpAddr, prefix: u8, target: IpAddr) -> bool {
    match (net_ip, target) {
        (IpAddr::V4(net), IpAddr::V4(tgt)) => {
            if prefix > 32 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let net_u32 = u32::from(net);
            let tgt_u32 = u32::from(tgt);
            let mask = if prefix == 32 {
                u32::MAX
            } else {
                !((1u32 << (32 - prefix)) - 1)
            };
            (net_u32 & mask) == (tgt_u32 & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(tgt)) => {
            if prefix > 128 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let net_u128 = u128::from(net);
            let tgt_u128 = u128::from(tgt);
            let mask = if prefix == 128 {
                u128::MAX
            } else {
                !((1u128 << (128 - prefix)) - 1)
            };
            (net_u128 & mask) == (tgt_u128 & mask)
        }
        _ => false,
    }
}

/// Evaluator for `$client` modifier.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientFilter {
    pub positive: Vec<ClientMatcher>,
    pub negative: Vec<ClientMatcher>,
}

impl ClientFilter {
    pub fn matches(&self, ctx: &ClientContext) -> bool {
        // Any negative client match immediately rejects
        for neg in &self.negative {
            if neg.matches(ctx) {
                return false;
            }
        }
        // If positive filters exist, at least one must match
        if !self.positive.is_empty() {
            return self.positive.iter().any(|pos| pos.matches(ctx));
        }
        true
    }
}

impl fmt::Display for ClientFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        for pos in &self.positive {
            parts.push(pos.to_string());
        }
        for neg in &self.negative {
            parts.push(format!("~{neg}"));
        }
        parts.sort();
        write!(f, "{}", parts.join("|"))
    }
}

/// Evaluator for `$dnstype` modifier.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnstypeFilter {
    pub positive: Vec<u16>,
    pub negative: Vec<u16>,
}

impl DnstypeFilter {
    pub fn matches(&self, qtype: RecordType) -> bool {
        let code = u16::from(qtype);
        for neg in &self.negative {
            if *neg == code {
                return false;
            }
        }
        if !self.positive.is_empty() {
            return self.positive.contains(&code);
        }
        true
    }
}

impl fmt::Display for DnstypeFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        for pos in &self.positive {
            parts.push(pos.to_string());
        }
        for neg in &self.negative {
            parts.push(format!("~{neg}"));
        }
        parts.sort();
        write!(f, "{}", parts.join("|"))
    }
}

/// Action to synthesize when a `$dnsrewrite` rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRewriteRule {
    pub rcode: String,
    pub rtype: Option<String>,
    pub value: Option<String>,
}

impl fmt::Display for DnsRewriteRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rtype = self.rtype.as_deref().unwrap_or("");
        let val = self.value.as_deref().unwrap_or("");
        write!(f, "{};{};{}", self.rcode, rtype, val)
    }
}

/// Modifiers attached to an adblock rule.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleModifiers {
    pub important: bool,
    pub badfilter: bool,
    pub client: Option<ClientFilter>,
    pub dnstype: Option<DnstypeFilter>,
    pub denyallow: Option<Vec<String>>,
    pub dnsrewrite: Option<DnsRewriteRule>,
}

impl RuleModifiers {
    /// Checks if a domain matches any `$denyallow` exception.
    pub fn denyallow_matches(&self, fqdn: &str) -> bool {
        if let Some(list) = &self.denyallow {
            let lower = fqdn.to_ascii_lowercase();
            let domain = lower.strip_suffix('.').unwrap_or(&lower);
            for d in list {
                if domain == d || domain.ends_with(&format!(".{d}")) {
                    return true;
                }
            }
        }
        false
    }
}

/// Parsed filter rule representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub kind: RuleKind,
    pub pattern: Pattern,
    pub modifiers: RuleModifiers,
    pub source: String,
    pub line: u32,
    pub raw: String,
    pub canonical: String,
}

/// Computes the canonical representation of a rule for `$badfilter` deduplication.
///
/// Modifiers (excluding `$badfilter`) are sorted deterministically so that
/// modifier ordering in source files does not affect matching.
pub fn compute_canonical(kind: RuleKind, pattern: &Pattern, modifiers: &RuleModifiers) -> String {
    let mut s = String::new();
    if kind == RuleKind::Allow {
        s.push_str("@@");
    }
    match pattern {
        Pattern::Exact(d) => {
            s.push('|');
            s.push_str(d);
            s.push('|');
        }
        Pattern::Domain(d) => {
            s.push_str("||");
            s.push_str(d);
            s.push('^');
        }
        Pattern::Prefix(p) => {
            s.push('|');
            s.push_str(p);
        }
        Pattern::Substring(sub) => {
            s.push_str(sub);
        }
        Pattern::Wildcard(w) => {
            s.push_str(w);
        }
        Pattern::Regex(r) => {
            s.push('/');
            s.push_str(r);
            s.push('/');
        }
    }

    let mut opts = Vec::new();
    if let Some(client) = &modifiers.client {
        opts.push(format!("client={client}"));
    }
    if let Some(denyallow) = &modifiers.denyallow {
        let mut sorted = denyallow.clone();
        sorted.sort();
        opts.push(format!("denyallow={}", sorted.join("|")));
    }
    if let Some(dnstype) = &modifiers.dnstype {
        opts.push(format!("dnstype={dnstype}"));
    }
    if let Some(dnsrewrite) = &modifiers.dnsrewrite {
        opts.push(format!("dnsrewrite={dnsrewrite}"));
    }
    if modifiers.important {
        opts.push("important".to_string());
    }

    if !opts.is_empty() {
        opts.sort();
        s.push('$');
        s.push_str(&opts.join(","));
    }

    s
}

/// Parses a `$client` modifier string (e.g. `192.168.1.1|~laptop|10.0.0.0/8`).
fn parse_client_filter(value: &str) -> Option<ClientFilter> {
    let mut filter = ClientFilter::default();
    for token in value.split(['|', ',']) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let (is_neg, item) = if let Some(stripped) = token.strip_prefix('~') {
            (true, stripped.trim())
        } else {
            (false, token)
        };

        let matcher = if item.contains('/') {
            // CIDR
            let mut parts = item.split('/');
            let ip_str = parts.next()?;
            let prefix_str = parts.next()?;
            let ip = ip_str.parse::<IpAddr>().ok()?;
            let prefix = prefix_str.parse::<u8>().ok()?;
            ClientMatcher::Cidr { ip, prefix }
        } else if let Ok(ip) = item.parse::<IpAddr>() {
            ClientMatcher::Ip(ip)
        } else {
            ClientMatcher::Name(item.to_string())
        };

        if is_neg {
            filter.negative.push(matcher);
        } else {
            filter.positive.push(matcher);
        }
    }

    if filter.positive.is_empty() && filter.negative.is_empty() {
        None
    } else {
        Some(filter)
    }
}

/// Parses a `$dnstype` modifier string (e.g. `A|AAAA` or `~HTTPS,65`).
fn parse_dnstype_filter(value: &str) -> Option<DnstypeFilter> {
    let mut filter = DnstypeFilter::default();
    for token in value.split(['|', ',']) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let (is_neg, item) = if let Some(stripped) = token.strip_prefix('~') {
            (true, stripped.trim())
        } else {
            (false, token)
        };

        let code = if let Ok(num) = item.parse::<u16>() {
            num
        } else if let Ok(rt) = RecordType::from_str(item) {
            u16::from(rt)
        } else if let Ok(rt) = RecordType::from_str(&item.to_ascii_uppercase()) {
            u16::from(rt)
        } else {
            warn!(token = %item, "Invalid dnstype in rule modifier; skipping modifier token");
            continue;
        };

        if is_neg {
            filter.negative.push(code);
        } else {
            filter.positive.push(code);
        }
    }

    if filter.positive.is_empty() && filter.negative.is_empty() {
        None
    } else {
        Some(filter)
    }
}

/// Parses a `$denyallow` modifier string (e.g. `sub.example.com|other.com`).
fn parse_denyallow(value: &str) -> Option<Vec<String>> {
    let mut domains = Vec::new();
    for item in value.split(['|', ',']) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if let Ok(normalized) = normalize_domain(item) {
            domains.push(normalized);
        }
    }
    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

/// Parses a `$dnsrewrite` modifier value.
fn parse_dnsrewrite(value: &str) -> Option<DnsRewriteRule> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.contains(';') {
        // Standard syntax: rcode;rtype;value
        let parts: Vec<&str> = trimmed.split(';').map(str::trim).collect();
        let rcode = parts[0].to_ascii_uppercase();
        let rtype = if parts.len() > 1 && !parts[1].is_empty() {
            Some(parts[1].to_ascii_uppercase())
        } else {
            None
        };
        let val = if parts.len() > 2 && !parts[2].is_empty() {
            Some(parts[2].to_string())
        } else {
            None
        };
        Some(DnsRewriteRule {
            rcode,
            rtype,
            value: val,
        })
    } else {
        // Shorthand syntax
        let upper = trimmed.to_ascii_uppercase();
        if upper == "NXDOMAIN" || upper == "REFUSED" || upper == "SERVFAIL" {
            Some(DnsRewriteRule {
                rcode: upper,
                rtype: None,
                value: None,
            })
        } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
            let rtype = match ip {
                IpAddr::V4(_) => "A".to_string(),
                IpAddr::V6(_) => "AAAA".to_string(),
            };
            Some(DnsRewriteRule {
                rcode: "NOERROR".to_string(),
                rtype: Some(rtype),
                value: Some(trimmed.to_string()),
            })
        } else {
            // CNAME shorthand
            Some(DnsRewriteRule {
                rcode: "NOERROR".to_string(),
                rtype: Some("CNAME".to_string()),
                value: Some(trimmed.to_string()),
            })
        }
    }
}

/// Parses options following `$` in an adblock rule.
///
/// If any option is an unknown/unsupported modifier (e.g. browser cosmetics like `$image`),
/// logs a warning and returns `None`, skipping the rule.
fn parse_modifiers(options_str: &str) -> Option<RuleModifiers> {
    let mut modifiers = RuleModifiers::default();

    for opt in options_str.split(',') {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }

        if opt.eq_ignore_ascii_case("important") {
            modifiers.important = true;
        } else if opt.eq_ignore_ascii_case("badfilter") {
            modifiers.badfilter = true;
        } else if let Some(val) = opt.strip_prefix("client=") {
            modifiers.client = parse_client_filter(val);
        } else if let Some(val) = opt.strip_prefix("dnstype=") {
            modifiers.dnstype = parse_dnstype_filter(val);
        } else if let Some(val) = opt.strip_prefix("denyallow=") {
            modifiers.denyallow = parse_denyallow(val);
        } else if let Some(val) = opt.strip_prefix("dnsrewrite=") {
            modifiers.dnsrewrite = parse_dnsrewrite(val);
        } else {
            // Unknown or unsupported browser modifier (e.g. $script, $image, $third-party)
            warn!(modifier = %opt, "Unsupported or unknown modifier in rule; skipping rule");
            return None;
        }
    }

    Some(modifiers)
}

/// Parses a single line from a filter list or configuration.
///
/// Returns `None` if the line is a comment, blank, invalid, or contains an unknown modifier.
pub fn parse_line(line: &str, source: &str, line_number: u32) -> Option<Rule> {
    let trimmed = line.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with('!')
        || trimmed.starts_with("[Adblock")
    {
        return None;
    }

    // Check for hosts format: `ip domain [domain2...] [# comment]`
    let clean_line = if let Some(idx) = trimmed.find(['#', '!']) {
        trimmed[..idx].trim()
    } else {
        trimmed
    };

    let tokens: Vec<&str> = clean_line.split_whitespace().collect();
    if !tokens.is_empty() && tokens[0].parse::<IpAddr>().is_ok() {
        // Hosts format line
        if tokens.len() < 2 {
            return None;
        }
        let domain_token = tokens[1];
        let lower = domain_token.to_ascii_lowercase();
        let stripped = lower.strip_suffix('.').unwrap_or(&lower);
        if IGNORED_HOSTNAMES.contains(&stripped) {
            return None;
        }
        let normalized = normalize_domain(domain_token).ok()?;
        let pattern = Pattern::Exact(normalized);
        let modifiers = RuleModifiers::default();
        let canonical = compute_canonical(RuleKind::Block, &pattern, &modifiers);
        return Some(Rule {
            kind: RuleKind::Block,
            pattern,
            modifiers,
            source: source.to_string(),
            line: line_number,
            raw: line.to_string(),
            canonical,
        });
    }

    // Adblock Plus / AdGuard syntax
    let (kind, rest) = if let Some(after_allow) = trimmed.strip_prefix("@@") {
        (RuleKind::Allow, after_allow.trim())
    } else {
        (RuleKind::Block, trimmed)
    };

    // Extract pattern and options
    let (pattern_part, options_part) = if let Some(inner) = rest.strip_prefix('/') {
        // Regex pattern: find closing '/'
        let close_idx = inner.find('/')?;
        let actual_close = close_idx + 1;
        let regex_pat = &rest[..=actual_close];
        let after = rest[actual_close + 1..].trim();
        let opts = after.strip_prefix('$');
        (regex_pat, opts)
    } else if let Some(dollar_idx) = rest.find('$') {
        let pat = rest[..dollar_idx].trim();
        let opts = rest[dollar_idx + 1..].trim();
        (pat, Some(opts))
    } else {
        (rest, None)
    };

    let modifiers = if let Some(opts) = options_part {
        parse_modifiers(opts)?
    } else {
        RuleModifiers::default()
    };

    let pattern = parse_pattern(pattern_part)?;
    let canonical = compute_canonical(kind, &pattern, &modifiers);

    Some(Rule {
        kind,
        pattern,
        modifiers,
        source: source.to_string(),
        line: line_number,
        raw: line.to_string(),
        canonical,
    })
}

/// Parses the pattern part of an ABP rule into a `Pattern`.
fn parse_pattern(raw_pattern: &str) -> Option<Pattern> {
    let p = raw_pattern.trim();
    if p.is_empty() {
        return None;
    }

    // Regex: `/pattern/`
    if p.starts_with('/') && p.ends_with('/') && p.len() >= 2 {
        let inner = &p[1..p.len() - 1];
        if inner.is_empty() {
            return None;
        }
        return Some(Pattern::Regex(inner.to_string()));
    }

    // Exact domain anchor: `|domain|`
    if p.starts_with('|') && p.ends_with('|') && p.len() >= 3 && !p[1..].starts_with('|') {
        let inner = &p[1..p.len() - 1];
        let normalized = normalize_domain(inner).ok()?;
        return Some(Pattern::Exact(normalized));
    }

    // Domain match: `||domain^` or `||domain`
    if let Some(domain_part) = p.strip_prefix("||") {
        let domain_cleaned = domain_part
            .strip_suffix('^')
            .unwrap_or(domain_part)
            .trim_end_matches('/');
        if domain_cleaned.contains('*') {
            return Some(Pattern::Wildcard(domain_cleaned.to_string()));
        }
        let normalized = normalize_domain(domain_cleaned).ok()?;
        return Some(Pattern::Domain(normalized));
    }

    // Prefix anchor: `|prefix`
    if let Some(prefix_part) = p.strip_prefix('|') {
        return Some(Pattern::Prefix(prefix_part.to_string()));
    }

    // Wildcard: contains `*`
    if p.contains('*') {
        // If it is just `*something*` without inner stars -> substring
        if p.starts_with('*') && p.ends_with('*') && p.len() >= 3 {
            let inner = &p[1..p.len() - 1];
            if !inner.contains('*') {
                return Some(Pattern::Substring(inner.to_ascii_lowercase()));
            }
        }
        return Some(Pattern::Wildcard(p.to_ascii_lowercase()));
    }

    // Plain rule: if it contains dot and no slash -> Domain match, otherwise Substring
    if p.contains('.') && !p.contains('/') {
        let stripped = p.strip_suffix('^').unwrap_or(p);
        if let Ok(normalized) = normalize_domain(stripped) {
            return Some(Pattern::Domain(normalized));
        }
    }

    Some(Pattern::Substring(p.to_ascii_lowercase()))
}

/// Parses multiple rules from a file or network stream.
///
/// Returns a vector of parsed rules along with the number of skipped lines/rules.
pub fn parse_rules(content: &str, source: &str) -> (Vec<Rule>, usize) {
    let mut rules = Vec::new();
    let mut skipped = 0;

    for (idx, line) in content.lines().enumerate() {
        let line_number = (idx + 1) as u32;
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with('!')
            || trimmed.starts_with("[Adblock")
        {
            continue;
        }

        // Check if hosts format line has multiple domains: e.g. `127.0.0.1 d1.com d2.com`
        let clean_line = if let Some(pos) = trimmed.find(['#', '!']) {
            trimmed[..pos].trim()
        } else {
            trimmed
        };
        let tokens: Vec<&str> = clean_line.split_whitespace().collect();
        if tokens.len() > 2 && tokens[0].parse::<IpAddr>().is_ok() {
            // Multiple domains on a single hosts line
            for domain_token in &tokens[1..] {
                let lower = domain_token.to_ascii_lowercase();
                let stripped = lower.strip_suffix('.').unwrap_or(&lower);
                if IGNORED_HOSTNAMES.contains(&stripped) {
                    continue;
                }
                if let Ok(normalized) = normalize_domain(domain_token) {
                    let pattern = Pattern::Exact(normalized);
                    let modifiers = RuleModifiers::default();
                    let canonical = compute_canonical(RuleKind::Block, &pattern, &modifiers);
                    rules.push(Rule {
                        kind: RuleKind::Block,
                        pattern,
                        modifiers,
                        source: source.to_string(),
                        line: line_number,
                        raw: format!("{} {}", tokens[0], domain_token),
                        canonical,
                    });
                } else {
                    skipped += 1;
                }
            }
            continue;
        }

        if let Some(rule) = parse_line(line, source, line_number) {
            rules.push(rule);
        } else {
            skipped += 1;
        }
    }

    (rules, skipped)
}

/// Legacy hosts-format blocklist parser, maintained for backward compatibility.
pub fn parse_hosts<S: BuildHasher>(content: &str, set: &mut HashSet<String, S>) -> usize {
    let mut added = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with('!')
            || trimmed.starts_with("[Adblock")
        {
            continue;
        }

        let clean_line = if let Some(idx) = trimmed.find(['#', '!']) {
            trimmed[..idx].trim()
        } else {
            trimmed
        };

        if clean_line.is_empty() {
            continue;
        }

        let tokens: Vec<&str> = clean_line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        let domain_tokens: &[&str] = if tokens[0].parse::<IpAddr>().is_ok() {
            &tokens[1..]
        } else {
            &tokens[..]
        };

        for &raw_domain in domain_tokens {
            let lower = raw_domain.to_ascii_lowercase();
            let stripped = lower.strip_suffix('.').unwrap_or(&lower);

            if IGNORED_HOSTNAMES.contains(&stripped) {
                continue;
            }

            if let Ok(normalized) = normalize_domain(raw_domain) {
                if set.insert(normalized) {
                    added += 1;
                }
            }
        }
    }

    added
}

#[cfg(test)]
mod tests {
    use super::*;
    use fnv::FnvHashSet;

    #[test]
    fn test_parse_hosts_basic() {
        let content = r"
# Standard hosts file comment
127.0.0.1 localhost
::1 localhost ip6-localhost
0.0.0.0 ads.example.com
127.0.0.1 tracking.example.org bad.domain.net # inline comment
! ABP style comment
plain-ad.com
";
        let mut set = FnvHashSet::default();
        let count = parse_hosts(content, &mut set);

        assert_eq!(count, 4);
        assert!(set.contains("ads.example.com"));
        assert!(set.contains("tracking.example.org"));
        assert!(set.contains("bad.domain.net"));
        assert!(set.contains("plain-ad.com"));
        assert!(!set.contains("localhost"));
        assert!(!set.contains("ip6-localhost"));
    }

    #[test]
    fn test_parse_hosts_normalization() {
        let content = "0.0.0.0 ADS.EXAMPLE.COM.\n127.0.0.1 Tracker.Org.";
        let mut set = FnvHashSet::default();
        parse_hosts(content, &mut set);

        assert!(set.contains("ads.example.com"));
        assert!(set.contains("tracker.org"));
    }

    #[test]
    fn test_parse_hosts_malformed_ignored() {
        let content = "0.0.0.0 invalid@domain.com\n0.0.0.0 valid.com\n# just a comment\n\n";
        let mut set = FnvHashSet::default();
        parse_hosts(content, &mut set);

        assert!(set.contains("valid.com"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_parse_adblock_domain_rules() {
        let line = "||example.com^";
        let rule = parse_line(line, "test", 1).unwrap();
        assert_eq!(rule.kind, RuleKind::Block);
        assert_eq!(rule.pattern, Pattern::Domain("example.com".to_string()));
        assert!(!rule.modifiers.important);

        let allow_line = "@@||example.com^";
        let allow_rule = parse_line(allow_line, "test", 2).unwrap();
        assert_eq!(allow_rule.kind, RuleKind::Allow);
        assert_eq!(
            allow_rule.pattern,
            Pattern::Domain("example.com".to_string())
        );
    }

    #[test]
    fn test_parse_modifiers_important_and_badfilter() {
        let line = "||example.com^$important";
        let rule = parse_line(line, "test", 1).unwrap();
        assert!(rule.modifiers.important);
        assert!(!rule.modifiers.badfilter);

        let bad_line = "||example.com^$important,badfilter";
        let bad_rule = parse_line(bad_line, "test", 2).unwrap();
        assert!(bad_rule.modifiers.important);
        assert!(bad_rule.modifiers.badfilter);

        // Canonical form of both rules must match!
        assert_eq!(rule.canonical, bad_rule.canonical);
    }

    #[test]
    fn test_parse_client_modifier() {
        let line = "||ad.com^$client=192.168.1.1|10.0.0.0/8|~laptop";
        let rule = parse_line(line, "test", 1).unwrap();
        let client_filter = rule.modifiers.client.unwrap();
        assert_eq!(client_filter.positive.len(), 2);
        assert_eq!(client_filter.negative.len(), 1);

        let ctx_match1 = ClientContext::new("192.168.1.1".parse().unwrap());
        assert!(client_filter.matches(&ctx_match1));

        let ctx_match2 = ClientContext::new("10.5.6.7".parse().unwrap());
        assert!(client_filter.matches(&ctx_match2));

        let mut ctx_neg = ClientContext::new("192.168.1.1".parse().unwrap());
        ctx_neg.id = Some(sito_core::client::ClientId::new("laptop"));
        assert!(!client_filter.matches(&ctx_neg));

        let ctx_nomatch = ClientContext::new("172.16.0.1".parse().unwrap());
        assert!(!client_filter.matches(&ctx_nomatch));
    }

    #[test]
    fn test_parse_dnstype_modifier() {
        let line = "||tracker.com^$dnstype=A|AAAA|~HTTPS";
        let rule = parse_line(line, "test", 1).unwrap();
        let dnstype = rule.modifiers.dnstype.unwrap();
        assert!(dnstype.matches(RecordType::A));
        assert!(dnstype.matches(RecordType::AAAA));
        assert!(!dnstype.matches(RecordType::HTTPS));
        assert!(!dnstype.matches(RecordType::TXT));
    }

    #[test]
    fn test_parse_denyallow_modifier() {
        let line = "||example.org^$denyallow=sub.example.org|good.example.org";
        let rule = parse_line(line, "test", 1).unwrap();
        assert!(rule.modifiers.denyallow_matches("sub.example.org"));
        assert!(rule.modifiers.denyallow_matches("deep.sub.example.org"));
        assert!(rule.modifiers.denyallow_matches("good.example.org"));
        assert!(!rule.modifiers.denyallow_matches("bad.example.org"));
    }

    #[test]
    fn test_parse_dnsrewrite_modifier() {
        let line1 = "||example.com^$dnsrewrite=1.2.3.4";
        let rule1 = parse_line(line1, "test", 1).unwrap();
        assert_eq!(
            rule1.modifiers.dnsrewrite,
            Some(DnsRewriteRule {
                rcode: "NOERROR".to_string(),
                rtype: Some("A".to_string()),
                value: Some("1.2.3.4".to_string()),
            })
        );

        let line2 = "||example.com^$dnsrewrite=NXDOMAIN;;";
        let rule2 = parse_line(line2, "test", 2).unwrap();
        assert_eq!(
            rule2.modifiers.dnsrewrite,
            Some(DnsRewriteRule {
                rcode: "NXDOMAIN".to_string(),
                rtype: None,
                value: None,
            })
        );
    }

    #[test]
    fn test_unknown_modifier_skips_rule_without_aborting() {
        let content = r"
||blocked.com^
||skipped.com^$image
||another-blocked.com^
||skipped2.com^$third-party,script
";
        let (rules, skipped) = parse_rules(content, "test");
        assert_eq!(rules.len(), 2);
        assert_eq!(skipped, 2);
        assert_eq!(rules[0].pattern, Pattern::Domain("blocked.com".to_string()));
        assert_eq!(
            rules[1].pattern,
            Pattern::Domain("another-blocked.com".to_string())
        );
    }

    #[test]
    fn test_regex_rule_parsing() {
        let line = r"/^ad[0-9]+\.example\.com$/$important";
        let rule = parse_line(line, "test", 1).unwrap();
        assert_eq!(
            rule.pattern,
            Pattern::Regex(r"^ad[0-9]+\.example\.com$".to_string())
        );
        assert!(rule.modifiers.important);
    }

    #[test]
    fn test_canonical_rule_representation_dedup() {
        let r1 = "||example.com^$important,client=laptop";
        let r2 = "||example.com^$client=laptop,important";
        let r3 = "||example.com^$client=laptop,important,badfilter";

        let rule1 = parse_line(r1, "t", 1).unwrap();
        let rule2 = parse_line(r2, "t", 2).unwrap();
        let rule3 = parse_line(r3, "t", 3).unwrap();

        assert_eq!(rule1.canonical, rule2.canonical);
        assert_eq!(rule1.canonical, rule3.canonical);
    }
}
