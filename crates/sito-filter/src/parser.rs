//! Rule parser supporting AdGuard Home ABP syntax, hosts format, and modifiers.

use hickory_proto::rr::RecordType;
use sito_core::client::ClientContext;
use sito_proto::normalize_domain;
use std::fmt;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
            // Only identity fields populated by `ClientRegistry::resolve` are
            // trusted here. `ctx.id`/`ctx.sni` are wire-claimed (DoH path, DoT
            // SNI) and must not satisfy a `$client=` matcher on their own.
            Self::Name(name) => {
                if let Some(client_name) = &ctx.client_name
                    && client_name.eq_ignore_ascii_case(name)
                {
                    return true;
                }
                if let Some(group) = &ctx.group
                    && group.eq_ignore_ascii_case(name)
                {
                    return true;
                }
                if let Some(mac) = &ctx.mac
                    && mac.eq_ignore_ascii_case(name)
                {
                    return true;
                }
                false
            }
        }
    }
}

impl fmt::Display for ClientMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Cidr { ip, prefix } => write!(f, "{ip}/{prefix}"),
            Self::Name(name) => {
                // Quote names that contain separators or characters with a
                // special meaning in a modifier list so the canonical form
                // (used for `$badfilter` deduplication) stays unambiguous.
                if !needs_client_quoting(name) {
                    return write!(f, "{name}");
                }
                f.write_char('\'')?;
                for ch in name.chars() {
                    if matches!(ch, '\'' | '"' | '\\' | ',' | '|') {
                        f.write_char('\\')?;
                    }
                    f.write_char(ch)?;
                }
                f.write_char('\'')
            }
        }
    }
}

/// Whether a client name must be quoted to be unambiguously serialized.
fn needs_client_quoting(name: &str) -> bool {
    name.is_empty()
        || name.starts_with('~')
        || name
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '\\' | ',' | '|'))
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
    /// True only for the bare `@@...$dnsrewrite` form, which cancels every
    /// matching rewrite instead of being an explicit NODATA rewrite.
    pub bare: bool,
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
                if sito_core::matches_domain_suffix(domain, d) {
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
        if dnsrewrite.bare {
            opts.push("dnsrewrite".to_string());
        } else {
            opts.push(format!("dnsrewrite={dnsrewrite}"));
        }
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

/// Whether a quote character at this position starts a quoted value.
///
/// Quotes are only honoured at the start of a value (after `=`, `|` or `~`) so
/// an apostrophe inside unquoted data (e.g. `TXT;don't`) does not swallow the
/// remaining modifiers.
fn quote_can_open(quote: Option<char>, prev: Option<char>) -> bool {
    quote.is_none() && matches!(prev, None | Some(',' | '=' | '|' | '~'))
}

/// Splits a modifier list on commas that are neither quoted nor escaped.
///
/// AdGuard allows quoting modifier values (`$client='John, Doe'`) and escaping
/// separators (`\,`, `\|`); splitting on every comma would truncate such a
/// value and silently drop the rule. The original escape sequences are kept
/// here and removed by the modifier-specific parser.
fn split_modifier_list(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut prev: Option<char> = None;
    for (idx, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            prev = Some(ch);
            continue;
        }
        match ch {
            '\\' => {
                escaped = true;
                prev = Some(ch);
            }
            '\'' | '"' if quote == Some(ch) => {
                quote = None;
                prev = Some(ch);
            }
            '\'' | '"' if quote_can_open(quote, prev) => {
                quote = Some(ch);
                prev = Some(ch);
            }
            ',' if quote.is_none() => {
                parts.push(&value[start..idx]);
                start = idx + ch.len_utf8();
                prev = Some(ch);
            }
            c if c.is_whitespace() => {}
            c => prev = Some(c),
        }
    }
    parts.push(&value[start..]);
    parts
}

/// Splits a `|`-separated client value outside quotes and escapes.
fn split_client_tokens(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut prev: Option<char> = None;
    for (idx, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            prev = Some(ch);
            continue;
        }
        match ch {
            '\\' => {
                escaped = true;
                prev = Some(ch);
            }
            '\'' | '"' if quote == Some(ch) => {
                quote = None;
                prev = Some(ch);
            }
            '\'' | '"' if quote_can_open(quote, prev) => {
                quote = Some(ch);
                prev = Some(ch);
            }
            '|' if quote.is_none() => {
                parts.push(&value[start..idx]);
                start = idx + ch.len_utf8();
                prev = Some(ch);
            }
            c if c.is_whitespace() => {}
            c => prev = Some(c),
        }
    }
    parts.push(&value[start..]);
    parts
}

/// Removes one layer of ASCII single/double quotes and unescapes `\x`
/// sequences from a client token.
///
/// Returns `None` for an unterminated quote, trailing garbage after the closing
/// quote, a dangling escape, or an empty name so the caller can reject the rule
/// instead of widening it to all clients.
fn parse_client_token(token: &str) -> Option<String> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }

    let quoted = token.starts_with('\'') || token.starts_with('"');
    let inner = if quoted {
        let quote = token.chars().next()?;
        let mut escaped = false;
        let mut closing = None;
        for (idx, ch) in token.char_indices().skip(1) {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == quote {
                closing = Some(idx);
                break;
            }
        }
        let closing = closing?;
        if !token[closing + quote.len_utf8()..].trim().is_empty() {
            return None;
        }
        &token[quote.len_utf8()..closing]
    } else {
        token
    };

    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            out.push(chars.next()?);
        } else {
            out.push(ch);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Parses a `$client` modifier value (e.g. `192.168.1.1|~laptop|10.0.0.0/8`).
///
/// Values are separated with `|`; the enclosing modifier list uses commas.
/// AdGuard quoting (`$client='John, Doe'`) and escaping (`\,`, `\|`, `\'`) are
/// supported; `~` negation must be placed outside the quotes. Returns `None`
/// when any token cannot be parsed so the caller can skip the whole rule
/// instead of silently dropping the client restriction.
fn parse_client_filter(value: &str) -> Option<ClientFilter> {
    let mut filter = ClientFilter::default();
    for token in split_client_tokens(value) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let (is_neg, item_raw) = if let Some(stripped) = token.strip_prefix('~') {
            (true, stripped.trim())
        } else {
            (false, token)
        };
        let item = parse_client_token(item_raw)?;

        let matcher = if item.contains('/') {
            // CIDR
            let mut parts = item.split('/');
            let ip_str = parts.next()?;
            let prefix_str = parts.next()?;
            if parts.next().is_some() {
                return None;
            }
            let ip = ip_str.parse::<IpAddr>().ok()?;
            let prefix = prefix_str.parse::<u8>().ok()?;
            let max_prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max_prefix {
                return None;
            }
            ClientMatcher::Cidr { ip, prefix }
        } else if let Ok(ip) = item.parse::<IpAddr>() {
            ClientMatcher::Ip(ip)
        } else {
            ClientMatcher::Name(item)
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

/// Parses a `$dnstype` modifier value (e.g. `A|AAAA` or `~HTTPS|65`).
///
/// Values are separated with `|`; the enclosing modifier list uses commas.
fn parse_dnstype_filter(value: &str) -> Option<DnstypeFilter> {
    let mut filter = DnstypeFilter::default();
    for token in value.split('|') {
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

/// Parses a `$denyallow` modifier value (e.g. `sub.example.com|other.com`).
///
/// Values are separated with `|`; the enclosing modifier list uses commas.
fn parse_denyallow(value: &str) -> Option<Vec<String>> {
    let mut domains = Vec::new();
    for item in value.split('|') {
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

/// Response codes accepted in `$dnsrewrite` rules (AdGuard-compatible).
const VALID_DNSREWRITE_RCODES: &[&str] = &[
    "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
];

fn is_valid_rcode(rcode: &str) -> bool {
    VALID_DNSREWRITE_RCODES.contains(&rcode.to_ascii_uppercase().as_str())
}

/// Infers `(rtype, value)` from a shorthand `$dnsrewrite` value.
///
/// IP literals become `A`/`AAAA`; anything else must be a valid domain to be
/// accepted as a `CNAME` target.
fn infer_rewrite_type(value: &str) -> Option<(String, String)> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        let rtype = match ip {
            IpAddr::V4(_) => "A",
            IpAddr::V6(_) => "AAAA",
        };
        return Some((rtype.to_string(), value.to_string()));
    }
    // A CNAME target must be a syntactically valid domain; never emit a
    // bogus CNAME for arbitrary junk.
    normalize_domain(value).ok()?;
    Some(("CNAME".to_string(), value.to_string()))
}

/// Record types the DNS pipeline can synthesize for `$dnsrewrite`.
const SUPPORTED_DNSREWRITE_TYPES: &[&str] = &["A", "AAAA", "CNAME", "PTR", "TXT"];

/// Validates an explicit `rcode;rtype;value` combination.
///
/// Record types the pipeline cannot synthesize are rejected here (with a
/// warning) instead of being accepted and silently answered as NODATA.
fn validate_rewrite(
    rcode: String,
    rtype: Option<String>,
    value: Option<String>,
) -> Option<DnsRewriteRule> {
    match (rtype, value) {
        (None, None) => Some(DnsRewriteRule {
            rcode,
            rtype: None,
            value: None,
            bare: false,
        }),
        (None, Some(v)) => {
            let (rtype, value) = infer_rewrite_type(&v)?;
            Some(DnsRewriteRule {
                rcode,
                rtype: Some(rtype),
                value: Some(value),
                bare: false,
            })
        }
        (Some(_), None) => None,
        (Some(rtype), Some(value)) => {
            if RecordType::from_str(rtype.as_str()).is_err() {
                return None;
            }
            if !SUPPORTED_DNSREWRITE_TYPES.contains(&rtype.as_str()) {
                warn!(
                    record_type = %rtype,
                    "Unsupported $dnsrewrite record type; skipping rule"
                );
                return None;
            }
            match rtype.as_str() {
                "A" => {
                    value.parse::<Ipv4Addr>().ok()?;
                }
                "AAAA" => {
                    value.parse::<Ipv6Addr>().ok()?;
                }
                "CNAME" | "PTR" => {
                    normalize_domain(&value).ok()?;
                }
                "TXT" => {
                    if value.is_empty() {
                        return None;
                    }
                }
                _ => return None,
            }
            Some(DnsRewriteRule {
                rcode,
                rtype: Some(rtype),
                value: Some(value),
                bare: false,
            })
        }
    }
}

/// Parses a `$dnsrewrite` modifier value.
///
/// Supports the standard `rcode;rtype;value` form and the shorthand forms
/// (`NXDOMAIN`, an IP literal, or a CNAME target). Invalid rcodes, record
/// types and values are rejected with `None` so the caller skips the rule
/// instead of synthesizing a bogus CNAME.
fn parse_dnsrewrite(value: &str) -> Option<DnsRewriteRule> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.contains(';') {
        // Standard syntax: rcode;rtype;value. The value keeps any remaining
        // semicolons so TXT data such as `NOERROR;TXT;a;b` is not truncated.
        let mut parts = trimmed.splitn(3, ';');
        let rcode = parts.next()?.trim().to_ascii_uppercase();
        if !is_valid_rcode(&rcode) {
            return None;
        }
        let rtype_raw = parts.next().unwrap_or("").trim();
        let value_raw = parts.next().unwrap_or("").trim();
        let rtype = if rtype_raw.is_empty() {
            None
        } else {
            Some(rtype_raw.to_ascii_uppercase())
        };
        let val = if value_raw.is_empty() {
            None
        } else {
            Some(value_raw.to_string())
        };
        validate_rewrite(rcode, rtype, val)
    } else {
        // Shorthand syntax
        let upper = trimmed.to_ascii_uppercase();
        if is_valid_rcode(&upper) {
            Some(DnsRewriteRule {
                rcode: upper,
                rtype: None,
                value: None,
                bare: false,
            })
        } else {
            let (rtype, value) = infer_rewrite_type(trimmed)?;
            Some(DnsRewriteRule {
                rcode: "NOERROR".to_string(),
                rtype: Some(rtype),
                value: Some(value),
                bare: false,
            })
        }
    }
}

/// Parses options following `$` in an adblock rule.
///
/// Modifiers are comma-separated (commas inside quotes or escaped with `\` do
/// not split). Unknown/unsupported modifiers (e.g. browser cosmetics like
/// `$image`) or unparsable modifier values produce an error so the caller skips
/// the whole rule: a rule must never be widened (for example a client-scoped
/// block becoming global) because one modifier failed.
fn parse_modifiers(options_str: &str, kind: RuleKind) -> Result<RuleModifiers, String> {
    let mut modifiers = RuleModifiers::default();

    for opt in split_modifier_list(options_str) {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }

        let (key, value) = match opt.split_once('=') {
            Some((key, value)) => (key.trim(), Some(value.trim())),
            None => (opt, None),
        };
        let require_value = |value: Option<&str>| {
            value
                .filter(|v| !v.is_empty())
                .map(str::to_string)
                .ok_or_else(|| format!("modifier '{key}' requires a value"))
        };

        if key.eq_ignore_ascii_case("important") {
            modifiers.important = true;
        } else if key.eq_ignore_ascii_case("badfilter") {
            modifiers.badfilter = true;
        } else if key.eq_ignore_ascii_case("client") {
            let val = require_value(value)?;
            modifiers.client = Some(
                parse_client_filter(&val)
                    .ok_or_else(|| format!("invalid $client value '{val}'"))?,
            );
        } else if key.eq_ignore_ascii_case("dnstype") {
            let val = require_value(value)?;
            modifiers.dnstype = Some(
                parse_dnstype_filter(&val)
                    .ok_or_else(|| format!("invalid $dnstype value '{val}'"))?,
            );
        } else if key.eq_ignore_ascii_case("denyallow") {
            let val = require_value(value)?;
            modifiers.denyallow = Some(
                parse_denyallow(&val).ok_or_else(|| format!("invalid $denyallow value '{val}'"))?,
            );
        } else if key.eq_ignore_ascii_case("dnsrewrite") {
            // A bare `$dnsrewrite` is only meaningful on an exception rule,
            // where it cancels every matching rewrite (AdGuard semantics).
            // On a blocking rule it has no valid value and is rejected.
            match value.filter(|v| !v.is_empty()) {
                Some(val) => {
                    modifiers.dnsrewrite = Some(
                        parse_dnsrewrite(val)
                            .ok_or_else(|| format!("invalid $dnsrewrite value '{val}'"))?,
                    );
                }
                None if kind == RuleKind::Allow => {
                    modifiers.dnsrewrite = Some(DnsRewriteRule {
                        rcode: "NOERROR".to_string(),
                        rtype: None,
                        value: None,
                        bare: true,
                    });
                }
                None => return Err("modifier 'dnsrewrite' requires a value".to_string()),
            }
        } else {
            // Unknown or unsupported browser modifier (e.g. $script, $image, $third-party)
            return Err(format!("unsupported or unknown modifier '{opt}'"));
        }
    }

    Ok(modifiers)
}

/// Finds the index of the closing `/` of an ABP regex, skipping escaped
/// slashes (`\/`) and slashes inside character classes (`[/]`).
fn find_regex_terminator(inner: &str) -> Option<usize> {
    let mut escaped = false;
    let mut in_class = false;
    for (idx, ch) in inner.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' => in_class = true,
            ']' => in_class = false,
            '/' if !in_class => return Some(idx),
            _ => {}
        }
    }
    None
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
        // Regex pattern: find the first unescaped closing '/'
        let close_idx = find_regex_terminator(inner)?;
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
        match parse_modifiers(opts, kind) {
            Ok(modifiers) => modifiers,
            Err(reason) => {
                warn!(
                    source = %source,
                    line = line_number,
                    rule = %trimmed,
                    reason = %reason,
                    "Skipping filter rule with unparsable modifiers"
                );
                return None;
            }
        }
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
        let domain_cleaned = domain_part.strip_suffix('^').unwrap_or(domain_part);
        // A path fragment cannot match a DNS query; treating `||example.com/`
        // as a full domain block would widen the rule's meaning. Keep it inert.
        if domain_cleaned.contains('/') {
            return None;
        }
        if domain_cleaned.contains('*') {
            // Query domains are lowercased; keep wildcard anchors in the same
            // case space so matching stays case-insensitive. Keep the `||`
            // prefix when the pattern does not already start with `*` so
            // `wildcard_to_regex` anchors at either the domain start or a
            // subdomain dot boundary (`^(?:.*\.)?`).
            let lower = domain_cleaned.to_ascii_lowercase();
            if lower.starts_with('*') {
                return Some(Pattern::Wildcard(lower));
            }
            return Some(Pattern::Wildcard(format!("||{lower}")));
        }
        let normalized = normalize_domain(domain_cleaned).ok()?;
        return Some(Pattern::Domain(normalized));
    }

    // Prefix anchor: `|prefix`
    if let Some(prefix_part) = p.strip_prefix('|') {
        if prefix_part.contains('/') {
            return None;
        }
        if let Some(exact_part) = prefix_part.strip_suffix('^')
            && !exact_part.contains('*')
        {
            let normalized = normalize_domain(exact_part).ok()?;
            return Some(Pattern::Exact(normalized));
        }
        if prefix_part.contains('*') {
            let cleaned = prefix_part.strip_suffix('^').unwrap_or(prefix_part);
            return Some(Pattern::Wildcard(cleaned.to_ascii_lowercase()));
        }
        return Some(Pattern::Prefix(prefix_part.to_ascii_lowercase()));
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

    // Plain rule: a bare domain blocks the exact host only (AdGuard semantics:
    // `example.org` matches example.org but not its subdomains). Rules with a
    // path cannot match at DNS level and stay inert.
    if p.contains('.') && !p.contains('/') {
        let stripped = p.strip_suffix('^').unwrap_or(p);
        if let Ok(normalized) = normalize_domain(stripped) {
            return Some(Pattern::Exact(normalized));
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

#[cfg(test)]
mod tests {
    use super::*;

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

        // Negative `~laptop` excludes a registry-resolved client name.
        let ctx_neg = ClientContext::new("192.168.1.1".parse().unwrap()).with_client_name("laptop");
        assert!(!client_filter.matches(&ctx_neg));

        // A wire-claimed id is not an authenticated identity and must not
        // activate the negative matcher.
        let ctx_spoofed = ClientContext::with_id("192.168.1.1".parse().unwrap(), "laptop");
        assert!(client_filter.matches(&ctx_spoofed));

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
                bare: false,
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
                bare: false,
            })
        );
    }

    #[test]
    fn test_bare_dnsrewrite_exception_sets_bare() {
        let rule = parse_line("@@||example.com^$dnsrewrite", "test", 1).unwrap();
        let rewrite = rule.modifiers.dnsrewrite.unwrap();
        assert!(rewrite.bare, "the bare form must be marked as bare");
        assert_eq!(rewrite.rcode, "NOERROR");
        assert!(rewrite.rtype.is_none());
        assert!(rewrite.value.is_none());
    }

    #[test]
    fn test_explicit_noerror_dnsrewrite_is_not_bare() {
        // `$dnsrewrite=NOERROR` is an explicit NODATA rewrite, not a
        // cancel-everything bare exception.
        let rule = parse_line("@@||example.com^$dnsrewrite=NOERROR", "test", 1).unwrap();
        let rewrite = rule.modifiers.dnsrewrite.unwrap();
        assert!(!rewrite.bare, "an explicit NOERROR must not be bare");
        assert_eq!(rewrite.rcode, "NOERROR");
        assert!(rewrite.rtype.is_none());
        assert!(rewrite.value.is_none());

        let semicolons = parse_line("@@||example.com^$dnsrewrite=NOERROR;;", "test", 2).unwrap();
        assert!(
            !semicolons.modifiers.dnsrewrite.unwrap().bare,
            "the explicit rcode;rtype;value form must not be bare"
        );
    }

    #[test]
    fn test_canonical_representation_distinguishes_bare_dnsrewrite() {
        let bare = parse_line("@@||example.com^$dnsrewrite", "test", 1).unwrap();
        let explicit = parse_line("@@||example.com^$dnsrewrite=NOERROR", "test", 2).unwrap();
        let valued = parse_line("@@||example.com^$dnsrewrite=1.2.3.4", "test", 3).unwrap();

        assert_eq!(bare.canonical, "@@||example.com^$dnsrewrite");
        assert_eq!(explicit.canonical, "@@||example.com^$dnsrewrite=NOERROR;;");
        assert_eq!(
            valued.canonical,
            "@@||example.com^$dnsrewrite=NOERROR;A;1.2.3.4"
        );
        assert_ne!(
            bare.canonical, explicit.canonical,
            "bare and explicit NOERROR rewrites must not share a canonical form"
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
    fn test_regex_escaped_slash_is_not_treated_as_terminator() {
        let line = r"/a\/b\.com/";
        let rule = parse_line(line, "test", 1).unwrap();
        assert_eq!(rule.pattern, Pattern::Regex(r"a\/b\.com".to_string()));

        // Options after an escaped slash must still be parsed.
        let line_with_opts = r"/a\/b\.com/$important";
        let rule = parse_line(line_with_opts, "test", 2).unwrap();
        assert_eq!(rule.pattern, Pattern::Regex(r"a\/b\.com".to_string()));
        assert!(rule.modifiers.important);

        // A slash inside a character class does not terminate the regex.
        let line_class = r"/[/]ad\.com/";
        let rule = parse_line(line_class, "test", 3).unwrap();
        assert_eq!(rule.pattern, Pattern::Regex(r"[/]ad\.com".to_string()));
    }

    #[test]
    fn test_prefix_and_wildcard_patterns_are_lowercased() {
        // Prefix anchors must be matched against the lowercased query domain.
        let prefix = parse_line("|Ads.Example.", "test", 1).unwrap();
        assert_eq!(prefix.pattern, Pattern::Prefix("ads.example.".to_string()));

        // `||*.example.com^` wildcard anchors are lowercased too.
        let wildcard = parse_line("||*.Example.COM^", "test", 2).unwrap();
        assert_eq!(
            wildcard.pattern,
            Pattern::Wildcard("*.example.com".to_string())
        );

        // Plain wildcards keep their existing lowercasing.
        let plain = parse_line("Bad*.Evil.*", "test", 3).unwrap();
        assert_eq!(plain.pattern, Pattern::Wildcard("bad*.evil.*".to_string()));
    }

    #[test]
    fn test_modifier_values_split_on_pipe_not_comma() {
        // A pipe-separated client value plus a following comma modifier.
        let rule = parse_line("||ad.com^$client=192.168.1.1|laptop,important", "test", 1).unwrap();
        let client = rule.modifiers.client.unwrap();
        assert_eq!(client.positive.len(), 2);
        assert!(rule.modifiers.important);

        // Pipe-separated denyallow values reach the value parser intact.
        let deny = parse_line("||ad.com^$denyallow=a.com|b.com", "test", 2).unwrap();
        let domains = deny.modifiers.denyallow.unwrap();
        assert_eq!(domains, vec!["a.com".to_string(), "b.com".to_string()]);

        // A comma inside a value would have been split as a modifier; the
        // unknown fragment must make the whole rule fail safe (skip), never
        // silently drop only the client restriction.
        assert!(parse_line("||ad.com^$client=1.2.3.4,8.8.8.8", "test", 3).is_none());
    }

    #[test]
    fn test_invalid_client_modifier_skips_rule_instead_of_widening() {
        // A malformed CIDR must not degrade to "matches all clients".
        assert!(parse_line("||ad.com^$client=not-an-ip/24", "test", 1).is_none());
        assert!(parse_line("||ad.com^$client=10.0.0.0/99", "test", 2).is_none());
        assert!(parse_line("||ad.com^$client=", "test", 3).is_none());
        // Empty values for other modifiers are rejected as well.
        assert!(parse_line("||ad.com^$dnstype=", "test", 4).is_none());
        assert!(parse_line("||ad.com^$denyallow=", "test", 5).is_none());
        assert!(parse_line("||ad.com^$dnsrewrite=", "test", 6).is_none());
    }

    #[test]
    fn test_dnsrewrite_validation_rejects_bogus_values() {
        // `NOERROR` is an rcode, not a CNAME target.
        let rcode_only = parse_line("||e.com^$dnsrewrite=NOERROR", "test", 1).unwrap();
        assert_eq!(
            rcode_only.modifiers.dnsrewrite,
            Some(DnsRewriteRule {
                rcode: "NOERROR".to_string(),
                rtype: None,
                value: None,
                bare: false,
            })
        );

        // Unknown rcode / record type / mismatched value are rejected.
        assert!(parse_line("||e.com^$dnsrewrite=BOGUS;A;1.2.3.4", "test", 2).is_none());
        assert!(parse_line("||e.com^$dnsrewrite=NOERROR;NOPE;1.2.3.4", "test", 3).is_none());
        assert!(parse_line("||e.com^$dnsrewrite=NOERROR;A;not-an-ip", "test", 4).is_none());
        assert!(parse_line("||e.com^$dnsrewrite=NOERROR;AAAA;1.2.3.4", "test", 5).is_none());
        assert!(parse_line("||e.com^$dnsrewrite=NOERROR;A;", "test", 6).is_none());
        // Junk shorthand must not become a bogus CNAME.
        assert!(parse_line("||e.com^$dnsrewrite=garbage!!", "test", 7).is_none());

        // Valid explicit A/AAAA/CNAME forms still parse.
        let explicit = parse_line("||e.com^$dnsrewrite=NOERROR;AAAA;::1", "test", 8).unwrap();
        assert_eq!(
            explicit.modifiers.dnsrewrite,
            Some(DnsRewriteRule {
                rcode: "NOERROR".to_string(),
                rtype: Some("AAAA".to_string()),
                value: Some("::1".to_string()),
                bare: false,
            })
        );
        let cname = parse_line("||e.com^$dnsrewrite=cname.example.net", "test", 9).unwrap();
        assert_eq!(
            cname.modifiers.dnsrewrite,
            Some(DnsRewriteRule {
                rcode: "NOERROR".to_string(),
                rtype: Some("CNAME".to_string()),
                value: Some("cname.example.net".to_string()),
                bare: false,
            })
        );
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

    #[test]
    fn test_parser_fuzz_sanity_never_panics() {
        let chars = "abcdefghijklmnopqrstuvwxyz0123456789.-_/*|~@$^,=[]{}()!#";
        let mut state: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            state
        };

        for _ in 0..2000 {
            let len = (next() % 128) as usize;
            let mut line = String::with_capacity(len);
            for _ in 0..len {
                line.push(chars.as_bytes()[(next() as usize) % chars.len()] as char);
            }
            let _ = parse_line(&line, "fuzz", 1);
            let _ = parse_rules(&line, "fuzz");
        }
    }

    #[test]
    fn test_parser_randomized_determinism() {
        // Same pseudo-random input stream as the fuzz-sanity test, but now
        // asserting invariants on successful parses.
        let chars = "abcdefghijklmnopqrstuvwxyz0123456789.-_/*|~@$^,=[]{}()!#";
        let mut state: u64 = 0x0BAD_C0DE_F00D_1234;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            state
        };

        for _ in 0..3000 {
            let len = (next() % 128) as usize;
            let mut line = String::with_capacity(len);
            for _ in 0..len {
                line.push(chars.as_bytes()[(next() as usize) % chars.len()] as char);
            }

            let first = parse_line(&line, "prop", 1).map(|r| r.canonical.clone());
            let second = parse_line(&line, "prop", 1).map(|r| r.canonical.clone());
            assert_eq!(first, second, "parsing must be deterministic for {line:?}");
            if let Some(canonical) = first {
                assert!(
                    !canonical.is_empty(),
                    "parsed rules must have a canonical form: {line:?}"
                );
            }
        }
    }
}
