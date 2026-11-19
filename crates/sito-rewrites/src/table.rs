//! DNS rewrite table implementation supporting exact, wildcard, CNAME chains, and auto-PTR.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use hickory_proto::rr::rdata::{A, AAAA, CNAME, PTR, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use sito_core::client::ClientContext;
use sito_core::domain::NormalizedDomain;
use sito_core::net::IpNetwork;
use tracing::warn;

use crate::config::RewritesConfig;

const DEFAULT_REWRITE_TTL: u32 = 60;

/// Maximum CNAME chain depth before resolution stops (loop protection).
const MAX_CNAME_DEPTH: usize = 8;

/// Parsed local rewrite record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalRecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    Cname(Name),
    Ptr(Name),
    Txt(Vec<String>),
}

/// Result of a local rewrite table lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteLookup {
    /// The table owns the name and produced at least one answer record.
    Answered(Vec<Record>),
    /// The name is owned locally but has no record for the queried type.
    NoData,
    /// The name is not owned locally (or every matching rule is bypassed by a
    /// client exception), so the query must fall through to upstream.
    NotFound,
}

/// Record types that can be stored in the exact rewrite map.
const EXACT_TYPES: [RecordType; 5] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::CNAME,
    RecordType::PTR,
    RecordType::TXT,
];

#[derive(Debug, Clone)]
struct StoredRule {
    wildcard_suffix: Option<NormalizedDomain>,
    record_type: RecordType,
    data: LocalRecordData,
    exception_clients: Vec<String>,
}

/// In-memory table of local DNS rewrites.
#[derive(Debug, Clone)]
pub struct RewriteTable {
    exact: HashMap<(String, RecordType), Vec<StoredRule>>,
    wildcards: Vec<StoredRule>,
    auto_ptr: HashMap<String, StoredRule>,
    ttl: u32,
}

impl Default for RewriteTable {
    fn default() -> Self {
        Self {
            exact: HashMap::new(),
            wildcards: Vec::new(),
            auto_ptr: HashMap::new(),
            ttl: DEFAULT_REWRITE_TTL,
        }
    }
}

impl RewriteTable {
    pub fn new(config: RewritesConfig) -> Self {
        let mut exact: HashMap<(String, RecordType), Vec<StoredRule>> = HashMap::new();
        let mut wildcards = Vec::new();
        let mut auto_ptr_candidates = Vec::new();
        // A TTL of zero would make records uncacheable; keep the historical
        // 60s floor so a misconfigured `ttl = 0` degrades gracefully.
        let ttl = config.ttl.max(1);

        for entry in config.entries {
            let Some((record_type, rdata)) = parse_entry_record(&entry.r#type, &entry.answer)
            else {
                continue;
            };

            let Some(norm_domain) = normalize_domain_key(&entry.domain) else {
                warn!(
                    domain = %entry.domain,
                    "invalid rewrite domain; entry skipped"
                );
                continue;
            };
            let wildcard_suffix = match norm_domain.as_str().strip_prefix("*.") {
                Some(rest) => match NormalizedDomain::parse(rest) {
                    Ok(suffix) => Some(suffix),
                    Err(error) => {
                        warn!(
                            domain = %entry.domain,
                            %error,
                            "invalid rewrite wildcard domain; entry skipped"
                        );
                        continue;
                    }
                },
                None => None,
            };
            let is_wildcard = wildcard_suffix.is_some();

            let rule = StoredRule {
                wildcard_suffix,
                record_type,
                data: rdata.clone(),
                exception_clients: entry.exception_clients.clone(),
            };

            if is_wildcard {
                wildcards.push(rule.clone());
            } else {
                exact
                    .entry((norm_domain.clone().into_string(), record_type))
                    .or_default()
                    .push(rule.clone());

                if config.auto_ptr {
                    // Check if candidate for auto-PTR (non-wildcard A or AAAA
                    // to a non-globally-routable address).
                    if let LocalRecordData::A(ipv4) = rdata {
                        if is_auto_ptr_candidate_v4(&ipv4) {
                            let ptr_name = ipv4_to_in_addr_arpa(&ipv4);
                            if let Ok(target_name) = Name::from_str(&format!("{norm_domain}.")) {
                                auto_ptr_candidates.push((
                                    ptr_name,
                                    StoredRule {
                                        wildcard_suffix: None,
                                        record_type: RecordType::PTR,
                                        data: LocalRecordData::Ptr(target_name),
                                        exception_clients: entry.exception_clients.clone(),
                                    },
                                ));
                            }
                        }
                    } else if let LocalRecordData::AAAA(ipv6) = rdata
                        && is_ula(&ipv6)
                    {
                        let ptr_name = ipv6_to_ip6_arpa(&ipv6);
                        if let Ok(target_name) = Name::from_str(&format!("{norm_domain}.")) {
                            auto_ptr_candidates.push((
                                ptr_name,
                                StoredRule {
                                    wildcard_suffix: None,
                                    record_type: RecordType::PTR,
                                    data: LocalRecordData::Ptr(target_name),
                                    exception_clients: entry.exception_clients.clone(),
                                },
                            ));
                        }
                    }
                }
            }
        }

        let mut auto_ptr = HashMap::new();
        for (ptr_key, rule) in auto_ptr_candidates {
            // Explicit PTR entries take precedence over auto-generated PTR
            if !exact.contains_key(&(ptr_key.clone(), RecordType::PTR)) {
                auto_ptr.entry(ptr_key).or_insert(rule);
            }
        }

        Self {
            exact,
            wildcards,
            auto_ptr,
            ttl,
        }
    }

    /// Look up local rewrite records for a query.
    pub fn lookup(&self, qname: &Name, qtype: RecordType, client: &ClientContext) -> RewriteLookup {
        let mut visited = Vec::new();
        self.lookup_inner(qname, qtype, client, &mut visited, 0)
    }

    fn lookup_inner(
        &self,
        qname: &Name,
        qtype: RecordType,
        client: &ClientContext,
        visited: &mut Vec<String>,
        depth: usize,
    ) -> RewriteLookup {
        if depth > MAX_CNAME_DEPTH {
            return RewriteLookup::NotFound;
        }

        let Some(qname_key) = normalize_domain_key(&qname.to_ascii()) else {
            return RewriteLookup::NotFound;
        };
        let qname_str = qname_key.as_str();
        if visited.iter().any(|seen| seen == qname_str) {
            // CNAME loop detected; stop resolving to avoid unbounded recursion.
            return RewriteLookup::NotFound;
        }
        visited.push(qname_str.to_string());

        // Track two independent facts while walking the table:
        // - `owner_non_excepted`: a non-bypassed rule of any type owns the
        //   name, so an unconfigured qtype is authoritative NODATA.
        // - `applicable_excepted`: a rule that would have answered this query
        //   was bypassed by a client exception, so the query must fall through
        //   instead of being answered NODATA.
        let mut owner_non_excepted = false;
        let mut applicable_excepted = false;

        // 1. Exact match: return every non-excepted rule for (qname, qtype)
        //    in configuration order.
        let mut exact_answers = Vec::new();
        for rtype in EXACT_TYPES {
            let Some(rules) = self.exact.get(&(qname_str.to_string(), rtype)) else {
                continue;
            };
            for rule in rules {
                if is_client_excepted(client, &rule.exception_clients) {
                    if rule_applies_to_qtype(rtype, qtype) {
                        applicable_excepted = true;
                    }
                    continue;
                }
                owner_non_excepted = true;
                if rtype == qtype {
                    exact_answers.push(self.build_record(qname, &rule.data));
                }
            }
        }
        if !exact_answers.is_empty() {
            return RewriteLookup::Answered(exact_answers);
        }

        // 2. Check exact CNAME (when qtype == CNAME, step 1 already returned it)
        if qtype != RecordType::CNAME
            && let Some(rules) = self.exact.get(&(qname_str.to_string(), RecordType::CNAME))
        {
            for rule in rules {
                if !is_client_excepted(client, &rule.exception_clients)
                    && let LocalRecordData::Cname(ref target) = rule.data
                {
                    return match self.resolve_cname(qname, target, qtype, client, visited, depth) {
                        Some(records) => RewriteLookup::Answered(records),
                        None => RewriteLookup::NotFound,
                    };
                }
            }
        }

        // 3. Check auto-PTR table (for PTR queries)
        if let Some(rule) = self.auto_ptr.get(qname_str) {
            if is_client_excepted(client, &rule.exception_clients) {
                if qtype == RecordType::PTR {
                    applicable_excepted = true;
                }
            } else {
                owner_non_excepted = true;
                if qtype == RecordType::PTR {
                    return RewriteLookup::Answered(vec![self.build_record(qname, &rule.data)]);
                }
            }
        }

        // 4. Check wildcard rules. The most specific (longest) matching suffix
        //    wins deterministically, independent of configuration order; all
        //    rules for the queried type at that specificity are returned in
        //    configuration order.
        let mut best_suffix_len: Option<usize> = None;
        let mut matched: Vec<&StoredRule> = Vec::new();
        for rule in &self.wildcards {
            let Some(ref suffix) = rule.wildcard_suffix else {
                continue;
            };
            if !matches_wildcard(&qname_key, suffix) {
                continue;
            }

            if is_client_excepted(client, &rule.exception_clients) {
                if rule_applies_to_qtype(rule.record_type, qtype) {
                    applicable_excepted = true;
                }
                continue;
            }

            owner_non_excepted = true;
            if rule.record_type != qtype && rule.record_type != RecordType::CNAME {
                continue;
            }

            match best_suffix_len {
                Some(len) if suffix.as_str().len() < len => continue,
                Some(len) if suffix.as_str().len() == len => {}
                _ => {
                    best_suffix_len = Some(suffix.as_str().len());
                    matched.clear();
                }
            }
            matched.push(rule);
        }

        let preferred: Vec<&StoredRule> = matched
            .iter()
            .copied()
            .filter(|rule| rule.record_type == qtype)
            .collect();
        if !preferred.is_empty() {
            return RewriteLookup::Answered(
                preferred
                    .iter()
                    .map(|rule| self.build_record(qname, &rule.data))
                    .collect(),
            );
        }
        if let Some(rule) = matched
            .iter()
            .copied()
            .find(|rule| rule.record_type == RecordType::CNAME)
            && let LocalRecordData::Cname(ref target) = rule.data
        {
            return match self.resolve_cname(qname, target, qtype, client, visited, depth) {
                Some(records) => RewriteLookup::Answered(records),
                None => RewriteLookup::NotFound,
            };
        }

        if applicable_excepted {
            // A bypassed rule must fall through to upstream, never NODATA.
            RewriteLookup::NotFound
        } else if owner_non_excepted {
            RewriteLookup::NoData
        } else {
            RewriteLookup::NotFound
        }
    }

    /// Builds the CNAME answer for `qname -> target` and follows the chain.
    ///
    /// When `target` is already on the resolution path the closing CNAME is
    /// suppressed (and logged) so a cycle in the table never reaches clients;
    /// only the valid prefix of the chain is returned.
    fn resolve_cname(
        &self,
        qname: &Name,
        target: &Name,
        qtype: RecordType,
        client: &ClientContext,
        visited: &mut Vec<String>,
        depth: usize,
    ) -> Option<Vec<Record>> {
        let target_key = normalize_domain_key(&target.to_ascii())?.into_string();
        if visited.iter().any(|seen| seen == &target_key) {
            warn!(
                qname = %qname,
                target = %target,
                "CNAME cycle detected in rewrite table; suppressing closing record"
            );
            return None;
        }

        let mut answers = vec![self.build_record(qname, &LocalRecordData::Cname(target.clone()))];
        if let RewriteLookup::Answered(target_answers) =
            self.lookup_inner(target, qtype, client, visited, depth + 1)
        {
            answers.extend(target_answers);
        }
        Some(answers)
    }

    fn build_record(&self, qname: &Name, data: &LocalRecordData) -> Record {
        let rdata = match data {
            LocalRecordData::A(ip) => RData::A(A(*ip)),
            LocalRecordData::AAAA(ip) => RData::AAAA(AAAA(*ip)),
            LocalRecordData::Cname(target) => RData::CNAME(CNAME(target.clone())),
            LocalRecordData::Ptr(target) => RData::PTR(PTR(target.clone())),
            LocalRecordData::Txt(strings) => RData::TXT(TXT::new(strings.clone())),
        };

        Record::from_rdata(qname.clone(), self.ttl, rdata)
    }
}

fn is_client_excepted(client: &ClientContext, exceptions: &[String]) -> bool {
    if exceptions.is_empty() {
        return false;
    }

    let client_ip_str = client.ip.to_string();
    // Only an authenticated, provenance-bearing identity may satisfy a
    // client-specific exception. A wire-claimed DoH path/SNI id or an
    // untrusted identity never bypasses a rewrite.
    let trusted_identity = client
        .identity_ref()
        .filter(sito_core::ClientIdentityRef::may_match_client_exception);

    for exc in exceptions {
        // CIDR exceptions (e.g. `10.0.0.0/8`, `fd00::/8`) match by address
        // range; they are checked before the exact-string comparisons.
        if let Ok(network) = IpNetwork::parse(exc)
            && network.contains(client.ip)
        {
            return true;
        }
        if exc.eq_ignore_ascii_case(&client_ip_str) {
            return true;
        }
        if let Some(identity) = &trusted_identity {
            if let Some(name) = identity.name
                && exc.eq_ignore_ascii_case(name)
            {
                return true;
            }
            if let Some(group) = identity.group
                && exc.eq_ignore_ascii_case(group)
            {
                return true;
            }
            if let Some(mac) = identity.mac
                && exc.eq_ignore_ascii_case(mac)
            {
                return true;
            }
        }
    }

    false
}

/// Normalizes a rewrite domain to the same canonical ASCII/punycode form the
/// filter engine and cache use.
///
/// Queries are matched through `Name::to_ascii()`, so a config entry written
/// as Unicode must become punycode and a config entry written as punycode must
/// stay as-is. Invalid entries are rejected by the caller instead of being
/// silently compared in their raw form.
fn normalize_domain_key(domain: &str) -> Option<NormalizedDomain> {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return None;
    }
    NormalizedDomain::parse(trimmed).ok()
}

fn matches_wildcard(candidate: &NormalizedDomain, suffix: &NormalizedDomain) -> bool {
    // `*.example.com` matches subdomains only, not the apex itself.
    candidate.is_strict_subdomain_of(suffix)
}

/// Whether a stored record type can answer the given query type. A CNAME
/// answers every type; everything else matches exactly.
fn rule_applies_to_qtype(rtype: RecordType, qtype: RecordType) -> bool {
    rtype == RecordType::CNAME || rtype == qtype
}

/// Splits TXT data into the 255-byte character-strings a DNS TXT record allows.
///
/// The split is UTF-8 safe and an empty value yields one empty character-string.
pub fn txt_chunks(value: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < value.len() {
        let mut end = (start + 255).min(value.len());
        while end > start && !value.is_char_boundary(end) {
            end -= 1;
        }
        chunks.push(value[start..end].to_string());
        start = end;
    }
    if chunks.is_empty() {
        chunks.push(String::new());
    }
    chunks
}

fn parse_entry_record(rtype: &str, answer: &str) -> Option<(RecordType, LocalRecordData)> {
    match rtype.to_ascii_uppercase().as_str() {
        "A" => {
            let ip = answer.parse::<Ipv4Addr>().ok()?;
            Some((RecordType::A, LocalRecordData::A(ip)))
        }
        "AAAA" => {
            let ip = answer.parse::<Ipv6Addr>().ok()?;
            Some((RecordType::AAAA, LocalRecordData::AAAA(ip)))
        }
        "CNAME" => {
            let name = Name::from_str(&format!("{}.", answer.trim_end_matches('.'))).ok()?;
            Some((RecordType::CNAME, LocalRecordData::Cname(name)))
        }
        "PTR" => {
            let name = Name::from_str(&format!("{}.", answer.trim_end_matches('.'))).ok()?;
            Some((RecordType::PTR, LocalRecordData::Ptr(name)))
        }
        "TXT" => Some((RecordType::TXT, LocalRecordData::Txt(txt_chunks(answer)))),
        _ => None,
    }
}

/// Checks if an IPv4 address is in RFC1918 space.
pub fn is_rfc1918(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    false
}

/// Checks whether an IPv4 address is a non-globally-routable address that
/// deserves an auto-generated reverse (PTR) record.
///
/// Beyond RFC1918 space this covers loopback (`127.0.0.0/8`), link-local
/// (`169.254.0.0/16`) and carrier-grade NAT (`100.64.0.0/10`, RFC 6598),
/// which are the ranges typically used by home/office LANs that configure
/// local rewrites.
pub fn is_auto_ptr_candidate_v4(ip: &Ipv4Addr) -> bool {
    if is_rfc1918(ip) {
        return true;
    }
    let octets = ip.octets();
    // 127.0.0.0/8 loopback
    if octets[0] == 127 {
        return true;
    }
    // 169.254.0.0/16 link-local
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // 100.64.0.0/10 CGNAT (RFC 6598)
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return true;
    }
    false
}

/// Checks if an IPv6 address is in Unique Local Address (ULA) space (fc00::/7).
pub fn is_ula(ip: &Ipv6Addr) -> bool {
    (ip.octets()[0] & 0xfe) == 0xfc
}

/// Converts an IPv4 address to in-addr.arpa normalized domain string.
pub fn ipv4_to_in_addr_arpa(ip: &Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// Converts an IPv6 address to ip6.arpa normalized domain string.
pub fn ipv6_to_ip6_arpa(ip: &Ipv6Addr) -> String {
    let octets = ip.octets();
    let mut parts = Vec::with_capacity(32);
    for b in octets.iter().rev() {
        parts.push(format!("{:x}", b & 0x0f));
        parts.push(format!("{:x}", (b >> 4) & 0x0f));
    }
    format!("{}.ip6.arpa", parts.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn answered(lookup: RewriteLookup) -> Vec<Record> {
        match lookup {
            RewriteLookup::Answered(records) => records,
            other => panic!("expected Answered, got {other:?}"),
        }
    }

    fn is_answered(lookup: &RewriteLookup) -> bool {
        matches!(lookup, RewriteLookup::Answered(_))
    }

    fn is_not_found(lookup: &RewriteLookup) -> bool {
        matches!(lookup, RewriteLookup::NotFound)
    }

    fn sample_table() -> RewriteTable {
        let toml_str = r#"
auto_ptr = true
entries = [
    { domain = "*.home.arpa", type = "A", answer = "192.168.1.10", exception_clients = ["admin-laptop"] },
    { domain = "special.home.arpa", type = "A", answer = "192.168.1.99" },
    { domain = "printer.lan", type = "A", answer = "192.168.1.50" },
    { domain = "printer-v6.lan", type = "AAAA", answer = "fd00::50" },
    { domain = "router.lan", type = "CNAME", answer = "gateway.lan" },
    { domain = "gateway.lan", type = "A", answer = "192.168.1.1" },
    { domain = "external.lan", type = "CNAME", answer = "external.example.com" }
]
"#;
        let cfg: RewritesConfig = toml::from_str(toml_str).unwrap();
        RewriteTable::new(cfg)
    }

    #[test]
    fn test_exact_a_and_aaaa() {
        let table = sample_table();
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());

        let qname_printer = Name::from_str("printer.lan.").unwrap();
        let answers = answered(table.lookup(&qname_printer, RecordType::A, &client));
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].data, RData::A(A(Ipv4Addr::new(192, 168, 1, 50))));

        let qname_v6 = Name::from_str("printer-v6.lan.").unwrap();
        let answers_v6 = answered(table.lookup(&qname_v6, RecordType::AAAA, &client));
        assert_eq!(answers_v6.len(), 1);
        assert_eq!(
            answers_v6[0].data,
            RData::AAAA(AAAA(Ipv6Addr::from_str("fd00::50").unwrap()))
        );
    }

    #[test]
    fn test_wildcard_matching_and_synthesis() {
        let table = sample_table();
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());

        let qname_nas = Name::from_str("nas.home.arpa.").unwrap();
        let answers = answered(table.lookup(&qname_nas, RecordType::A, &client));
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name, qname_nas);
        assert_eq!(answers[0].data, RData::A(A(Ipv4Addr::new(192, 168, 1, 10))));

        let qname_deep = Name::from_str("foo.bar.home.arpa.").unwrap();
        let answers_deep = answered(table.lookup(&qname_deep, RecordType::A, &client));
        assert_eq!(answers_deep.len(), 1);
        assert_eq!(answers_deep[0].name, qname_deep);
    }

    #[test]
    fn test_exact_beats_wildcard() {
        let table = sample_table();
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());

        let qname = Name::from_str("special.home.arpa.").unwrap();
        let answers = answered(table.lookup(&qname, RecordType::A, &client));
        assert_eq!(answers.len(), 1);
        // Should get .99 from exact match, not .10 from wildcard
        assert_eq!(answers[0].data, RData::A(A(Ipv4Addr::new(192, 168, 1, 99))));
    }

    #[test]
    fn test_cname_cycle_returns_valid_prefix_only() {
        let toml_str = r#"
auto_ptr = false
entries = [
    { domain = "a.lan", type = "CNAME", answer = "b.lan" },
    { domain = "b.lan", type = "CNAME", answer = "a.lan" }
]
"#;
        let cfg: RewritesConfig = toml::from_str(toml_str).unwrap();
        let table = RewriteTable::new(cfg);
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());

        // From `a.lan` only the first (valid) CNAME may be returned; the
        // closing `b.lan -> a.lan` record must be suppressed.
        let answers =
            answered(table.lookup(&Name::from_str("a.lan.").unwrap(), RecordType::A, &client));
        assert_eq!(answers.len(), 1, "closing cycle record must be suppressed");
        assert_eq!(answers[0].record_type(), RecordType::CNAME);
        assert_eq!(
            answers[0].data,
            RData::CNAME(CNAME(Name::from_str("b.lan.").unwrap()))
        );

        // The same holds when the cycle is entered from `b.lan`.
        let answers_b =
            answered(table.lookup(&Name::from_str("b.lan.").unwrap(), RecordType::A, &client));
        assert_eq!(answers_b.len(), 1);
        assert_eq!(
            answers_b[0].data,
            RData::CNAME(CNAME(Name::from_str("a.lan.").unwrap()))
        );
    }

    #[test]
    fn test_self_referencing_cname_is_suppressed() {
        let toml_str = r#"
auto_ptr = false
entries = [
    { domain = "loop.lan", type = "CNAME", answer = "loop.lan" }
]
"#;
        let cfg: RewritesConfig = toml::from_str(toml_str).unwrap();
        let table = RewriteTable::new(cfg);
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());

        // A self-referencing CNAME resolves to no answer (the pipeline falls
        // through to upstream/blocking stages instead of emitting a loop).
        assert!(is_not_found(&table.lookup(
            &Name::from_str("loop.lan.").unwrap(),
            RecordType::A,
            &client
        )));
    }

    #[test]
    fn test_exact_match_returns_all_answers_in_order() {
        let toml_str = r#"
auto_ptr = false
entries = [
    { domain = "multi.lan", type = "A", answer = "192.168.1.10" },
    { domain = "multi.lan", type = "A", answer = "192.168.1.11" },
    { domain = "multi.lan", type = "A", answer = "192.168.1.12" }
]
"#;
        let cfg: RewritesConfig = toml::from_str(toml_str).unwrap();
        let table = RewriteTable::new(cfg);
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());

        let answers = answered(table.lookup(
            &Name::from_str("multi.lan.").unwrap(),
            RecordType::A,
            &client,
        ));
        assert_eq!(answers.len(), 3, "every rule for (domain, type) must match");
        let ips: Vec<Ipv4Addr> = answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect();
        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 11),
                Ipv4Addr::new(192, 168, 1, 12),
            ],
            "answer order must be stable (configuration order)"
        );
    }

    #[test]
    fn test_wildcard_specificity_beats_insertion_order() {
        // The less specific wildcard is configured first on purpose: the
        // longest matching suffix must win deterministically.
        let toml_str = r#"
auto_ptr = false
entries = [
    { domain = "*.home.arpa", type = "A", answer = "192.168.1.10" },
    { domain = "*.sub.home.arpa", type = "A", answer = "192.168.1.20" },
    { domain = "*.home.arpa", type = "A", answer = "192.168.1.11" }
]
"#;
        let cfg: RewritesConfig = toml::from_str(toml_str).unwrap();
        let table = RewriteTable::new(cfg);
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());

        // `x.sub.home.arpa` is covered by both suffixes; only the most
        // specific one may answer.
        let deep = answered(table.lookup(
            &Name::from_str("x.sub.home.arpa.").unwrap(),
            RecordType::A,
            &client,
        ));
        assert_eq!(deep.len(), 1);
        assert_eq!(deep[0].data, RData::A(A(Ipv4Addr::new(192, 168, 1, 20))));

        // `x.home.arpa` only matches `*.home.arpa`; both same-suffix rules
        // answer, in configuration order.
        let shallow = answered(table.lookup(
            &Name::from_str("x.home.arpa.").unwrap(),
            RecordType::A,
            &client,
        ));
        assert_eq!(shallow.len(), 2);
        assert_eq!(shallow[0].data, RData::A(A(Ipv4Addr::new(192, 168, 1, 10))));
        assert_eq!(shallow[1].data, RData::A(A(Ipv4Addr::new(192, 168, 1, 11))));
    }

    #[test]
    fn test_exception_clients_support_cidr() {
        let toml_str = r#"
auto_ptr = false
entries = [
    { domain = "*.lab.lan", type = "A", answer = "10.0.0.5", exception_clients = ["10.10.0.0/16", "fd00::/8"] },
]
"#;
        let cfg: RewritesConfig = toml::from_str(toml_str).unwrap();
        let table = RewriteTable::new(cfg);
        let qname = Name::from_str("nas.lab.lan.").unwrap();

        // In-range IPv4 client is excepted.
        let excepted = ClientContext::new(IpAddr::from_str("10.10.4.7").unwrap());
        assert!(is_not_found(&table.lookup(
            &qname,
            RecordType::A,
            &excepted
        )));

        // In-range IPv6 client is excepted.
        let excepted_v6 = ClientContext::new(IpAddr::from_str("fd00::7").unwrap());
        assert!(is_not_found(&table.lookup(
            &qname,
            RecordType::A,
            &excepted_v6
        )));

        // Out-of-range client still receives the rewrite.
        let allowed = ClientContext::new(IpAddr::from_str("10.11.0.1").unwrap());
        assert!(is_answered(&table.lookup(&qname, RecordType::A, &allowed)));
        let allowed_v6 = ClientContext::new(IpAddr::from_str("fe80::1").unwrap());
        assert!(is_answered(&table.lookup(
            &qname,
            RecordType::A,
            &allowed_v6
        )));
    }

    #[test]
    fn test_configurable_rewrite_ttl() {
        let toml_str = r#"
auto_ptr = false
ttl = 120
entries = [
    { domain = "printer.lan", type = "A", answer = "192.168.1.50" },
]
"#;
        let cfg: RewritesConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.ttl, 120);
        let table = RewriteTable::new(cfg);
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());
        let answers = answered(table.lookup(
            &Name::from_str("printer.lan.").unwrap(),
            RecordType::A,
            &client,
        ));
        assert_eq!(answers[0].ttl, 120);

        // Absent `ttl` keeps the historical 60s default.
        let default_cfg: RewritesConfig = toml::from_str("auto_ptr = false\nentries = []").unwrap();
        assert_eq!(default_cfg.ttl, 60);
        let default_table = RewriteTable::new(default_cfg);
        assert_eq!(default_table.ttl, 60);
    }

    #[test]
    fn test_auto_ptr_includes_cgnat_link_local_and_loopback() {
        assert!(is_auto_ptr_candidate_v4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_auto_ptr_candidate_v4(&Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_auto_ptr_candidate_v4(&Ipv4Addr::new(100, 127, 255, 254)));
        assert!(is_auto_ptr_candidate_v4(&Ipv4Addr::new(169, 254, 1, 1)));
        assert!(is_auto_ptr_candidate_v4(&Ipv4Addr::LOCALHOST));
        assert!(!is_auto_ptr_candidate_v4(&Ipv4Addr::new(100, 128, 0, 1)));
        assert!(!is_auto_ptr_candidate_v4(&Ipv4Addr::new(8, 8, 8, 8)));
        // `is_rfc1918` keeps its strict RFC1918 meaning.
        assert!(!is_rfc1918(&Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_rfc1918(&Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn test_wildcard_does_not_match_apex() {
        let table = sample_table();
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());
        // `*.home.arpa` must not match the bare `home.arpa` apex.
        let qname = Name::from_str("home.arpa.").unwrap();
        assert!(is_not_found(&table.lookup(&qname, RecordType::A, &client)));
    }

    #[test]
    fn test_cname_chain_resolution() {
        let table = sample_table();
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());

        let qname_router = Name::from_str("router.lan.").unwrap();
        let answers = answered(table.lookup(&qname_router, RecordType::A, &client));
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].record_type(), RecordType::CNAME);
        assert_eq!(answers[1].record_type(), RecordType::A);
        assert_eq!(answers[1].data, RData::A(A(Ipv4Addr::new(192, 168, 1, 1))));

        // External CNAME returns only CNAME (including for non-A/AAAA types like HTTPS/TXT)
        let qname_ext = Name::from_str("external.lan.").unwrap();
        let answers_ext = answered(table.lookup(&qname_ext, RecordType::A, &client));
        assert_eq!(answers_ext.len(), 1);
        assert_eq!(answers_ext[0].record_type(), RecordType::CNAME);

        let answers_https = answered(table.lookup(&qname_ext, RecordType::HTTPS, &client));
        assert_eq!(answers_https.len(), 1);
        assert_eq!(answers_https[0].record_type(), RecordType::CNAME);
    }

    #[test]
    fn test_auto_ptr_reverse_lookup() {
        let table = sample_table();
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());

        // 192.168.1.50 -> printer.lan
        let ptr_query = Name::from_str("50.1.168.192.in-addr.arpa.").unwrap();
        let answers = answered(table.lookup(&ptr_query, RecordType::PTR, &client));
        assert_eq!(answers.len(), 1);
        let expected_target = Name::from_str("printer.lan.").unwrap();
        assert_eq!(answers[0].data, RData::PTR(PTR(expected_target)));

        // fd00::50 -> printer-v6.lan
        let v6_arpa = ipv6_to_ip6_arpa(&Ipv6Addr::from_str("fd00::50").unwrap());
        let ptr_v6_query = Name::from_str(&format!("{v6_arpa}.")).unwrap();
        let answers_v6 = answered(table.lookup(&ptr_v6_query, RecordType::PTR, &client));
        assert_eq!(answers_v6.len(), 1);
        let expected_v6_target = Name::from_str("printer-v6.lan.").unwrap();
        assert_eq!(answers_v6[0].data, RData::PTR(PTR(expected_v6_target)));
    }

    #[test]
    fn test_unidentified_client_id_does_not_bypass_exception() {
        let table = sample_table();
        let mut attacker = ClientContext::new(IpAddr::from_str("192.168.1.99").unwrap());
        // Simulates `/dns-query/admin-laptop`: the raw id is attacker-controlled
        // while the client remains unidentified (no resolved client_name).
        attacker.id = Some(sito_core::ClientId::new("admin-laptop"));

        let qname_nas = Name::from_str("nas.home.arpa.").unwrap();
        assert!(
            is_answered(&table.lookup(&qname_nas, RecordType::A, &attacker)),
            "unidentified clients must not match rewrite exceptions by raw id"
        );

        // Identified clients may still be excepted by their resolved identity.
        let mut identified = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());
        identified.client_name = Some("admin-laptop".to_string());
        identified.id = Some(sito_core::ClientId::new("admin-laptop"));
        assert!(is_not_found(&table.lookup(
            &qname_nas,
            RecordType::A,
            &identified
        )));
    }

    /// P1-9: an identified client at a configured IP must not satisfy a
    /// rewrite exception using a DoH-path id that was not registry-resolved.
    #[test]
    fn test_ip_identified_client_cannot_spoof_exception_with_untrusted_id() {
        use sito_core::IdentitySource;

        let table = sample_table();
        let mut client = ClientContext::new(IpAddr::from_str("192.168.1.30").unwrap());
        client.client_name = Some("kitchen".to_string());
        client.id = Some(sito_core::ClientId::new("admin-laptop"));
        // DoH/DoH3 path ids leave this false.
        client.id_authenticated = false;

        let qname_nas = Name::from_str("nas.home.arpa.").unwrap();
        assert!(
            is_answered(&table.lookup(&qname_nas, RecordType::A, &client)),
            "an unauthenticated path id must not bypass a rewrite exception"
        );

        // Even a registry-authenticated raw id is not a policy identity: the
        // exception names the registry-resolved client name, not the secret.
        client.id_authenticated = true;
        client.identity_source = Some(IdentitySource::Secret);
        assert!(
            is_answered(&table.lookup(&qname_nas, RecordType::A, &client)),
            "policy must never match the raw registered id"
        );

        // The registry-resolved identity name may satisfy the exception.
        client.client_name = Some("admin-laptop".to_string());
        assert!(
            is_not_found(&table.lookup(&qname_nas, RecordType::A, &client)),
            "an authenticated identity name may satisfy the exception"
        );
    }

    #[test]
    fn test_exception_requires_authenticated_identity() {
        use sito_core::IdentitySource;

        let table = sample_table();
        let qname = Name::from_str("nas.home.arpa.").unwrap();

        let mut client = ClientContext::new(IpAddr::from_str("192.168.1.30").unwrap());
        client.client_name = Some("admin-laptop".to_string());

        // A display-only SNI/DoH identity cannot satisfy an exception.
        client.identity_source = Some(IdentitySource::TlsSni);
        assert!(
            is_answered(&table.lookup(&qname, RecordType::A, &client)),
            "untrusted identity must not bypass a rewrite exception"
        );
        client.identity_source = Some(IdentitySource::DohPath);
        assert!(is_answered(&table.lookup(&qname, RecordType::A, &client)));

        // The same name from an authenticated identity may.
        client.identity_source = Some(IdentitySource::Ip);
        assert!(is_not_found(&table.lookup(&qname, RecordType::A, &client)));
    }

    #[test]
    fn test_idn_and_trailing_dot_rewrite_domains_match_punycode_queries() {
        let config: RewritesConfig = toml::from_str(
            r#"
entries = [
    { domain = "MÜNCHEN.de.", type = "A", answer = "192.0.2.10" },
    { domain = "*.BÜCHER.example.", type = "A", answer = "192.0.2.11" },
]
"#,
        )
        .unwrap();
        let table = RewriteTable::new(config);
        let client = ClientContext::new(IpAddr::from_str("192.168.1.30").unwrap());

        let exact = Name::from_str("xn--mnchen-3ya.de.").unwrap();
        assert!(
            is_answered(&table.lookup(&exact, RecordType::A, &client)),
            "raw Unicode rewrite domains must match punycode queries"
        );

        let wildcard = Name::from_str("shop.xn--bcher-kva.example.").unwrap();
        assert!(
            is_answered(&table.lookup(&wildcard, RecordType::A, &client)),
            "wildcard IDN rewrite domains must match punycode queries"
        );
    }

    #[test]
    fn test_exception_clients_bypass() {
        let table = sample_table();
        let mut client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());
        client.client_name = Some("admin-laptop".to_string());

        let qname_nas = Name::from_str("nas.home.arpa.").unwrap();
        // admin-laptop is in exception_clients for *.home.arpa -> should bypass and return None
        assert!(is_not_found(&table.lookup(
            &qname_nas,
            RecordType::A,
            &client
        )));

        // But non-excepted client gets the rewrite
        let other_client = ClientContext::new(IpAddr::from_str("192.168.1.30").unwrap());
        assert!(is_answered(&table.lookup(
            &qname_nas,
            RecordType::A,
            &other_client
        )));
    }

    fn exact_a_only_table() -> RewriteTable {
        let config: RewritesConfig = toml::from_str(
            r#"
auto_ptr = false
entries = [
    { domain = "printer.lan", type = "A", answer = "192.168.1.50" },
]
"#,
        )
        .unwrap();
        RewriteTable::new(config)
    }

    /// An exact owner configured only for `A` is authoritative for the name:
    /// other types are NODATA rather than an upstream lookup.
    #[test]
    fn test_exact_owner_returns_nodata_for_unconfigured_types() {
        let table = exact_a_only_table();
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());
        let qname = Name::from_str("printer.lan.").unwrap();

        assert!(matches!(
            table.lookup(&qname, RecordType::A, &client),
            RewriteLookup::Answered(records) if records.len() == 1
        ));
        for qtype in [
            RecordType::AAAA,
            RecordType::TXT,
            RecordType::PTR,
            RecordType::HTTPS,
        ] {
            assert!(
                matches!(table.lookup(&qname, qtype, &client), RewriteLookup::NoData),
                "{qtype:?} must be NODATA for an A-only owner"
            );
        }

        let unknown = Name::from_str("unknown.lan.").unwrap();
        assert!(matches!(
            table.lookup(&unknown, RecordType::A, &client),
            RewriteLookup::NotFound
        ));
    }

    #[test]
    fn test_excepted_client_gets_not_found_not_nodata() {
        let config: RewritesConfig = toml::from_str(
            r#"
auto_ptr = false
entries = [
    { domain = "printer.lan", type = "A", answer = "192.168.1.50", exception_clients = ["10.0.0.0/8"] },
]
"#,
        )
        .unwrap();
        let table = RewriteTable::new(config);
        let qname = Name::from_str("printer.lan.").unwrap();

        let excepted = ClientContext::new(IpAddr::from_str("10.10.4.7").unwrap());
        for qtype in [RecordType::A, RecordType::AAAA, RecordType::TXT] {
            assert!(
                matches!(
                    table.lookup(&qname, qtype, &excepted),
                    RewriteLookup::NotFound
                ),
                "an exception bypass must fall through for {qtype:?}"
            );
        }

        let allowed = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());
        assert!(matches!(
            table.lookup(&qname, RecordType::A, &allowed),
            RewriteLookup::Answered(_)
        ));
        assert!(matches!(
            table.lookup(&qname, RecordType::AAAA, &allowed),
            RewriteLookup::NoData
        ));
    }

    #[test]
    fn test_wildcard_owner_returns_nodata_for_unconfigured_types() {
        let config: RewritesConfig = toml::from_str(
            r#"
auto_ptr = false
entries = [
    { domain = "*.home.arpa", type = "A", answer = "192.168.1.10" },
]
"#,
        )
        .unwrap();
        let table = RewriteTable::new(config);
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());
        let qname = Name::from_str("nas.home.arpa.").unwrap();

        assert!(matches!(
            table.lookup(&qname, RecordType::A, &client),
            RewriteLookup::Answered(_)
        ));
        for qtype in [RecordType::AAAA, RecordType::TXT, RecordType::HTTPS] {
            assert!(
                matches!(table.lookup(&qname, qtype, &client), RewriteLookup::NoData),
                "{qtype:?} must be NODATA for a wildcard A-only owner"
            );
        }
    }

    #[test]
    fn test_auto_ptr_owner_outcomes() {
        let config: RewritesConfig = toml::from_str(
            r#"
auto_ptr = true
entries = [
    { domain = "printer.lan", type = "A", answer = "192.168.1.50" },
]
"#,
        )
        .unwrap();
        let table = RewriteTable::new(config);
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());
        let ptr_name = Name::from_str("50.1.168.192.in-addr.arpa.").unwrap();

        assert!(matches!(
            table.lookup(&ptr_name, RecordType::PTR, &client),
            RewriteLookup::Answered(records) if records.len() == 1
        ));
        assert!(matches!(
            table.lookup(&ptr_name, RecordType::A, &client),
            RewriteLookup::NoData
        ));
    }

    #[test]
    fn test_txt_chunks_splits_long_values_and_preserves_utf8() {
        let ascii = "a".repeat(300);
        let chunks = txt_chunks(&ascii);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 255);
        assert_eq!(chunks[1].len(), 45);
        assert_eq!(chunks.concat(), ascii);

        // 254 ASCII bytes followed by a 2-byte character: the 255-byte
        // boundary falls inside the character and must move back to a
        // UTF-8 boundary.
        let mut unicode = "a".repeat(254);
        unicode.push('é');
        let chunks = txt_chunks(&unicode);
        assert!(chunks.iter().all(|chunk| chunk.len() <= 255));
        assert_eq!(chunks.concat(), unicode);
        assert_eq!(chunks[0], "a".repeat(254));
        assert_eq!(chunks[1], "é");

        assert_eq!(txt_chunks(""), vec![String::new()]);
    }

    #[test]
    fn test_local_txt_entries_are_chunked_on_lookup() {
        let ascii = "a".repeat(300);
        let mut unicode = "b".repeat(254);
        unicode.push('é');
        let config = RewritesConfig {
            auto_ptr: false,
            ttl: 60,
            entries: vec![
                crate::config::RewriteEntryConfig {
                    domain: "long.lan".to_string(),
                    r#type: "TXT".to_string(),
                    answer: ascii.clone(),
                    exception_clients: Vec::new(),
                },
                crate::config::RewriteEntryConfig {
                    domain: "utf8.lan".to_string(),
                    r#type: "TXT".to_string(),
                    answer: unicode.clone(),
                    exception_clients: Vec::new(),
                },
                crate::config::RewriteEntryConfig {
                    domain: "empty.lan".to_string(),
                    r#type: "TXT".to_string(),
                    answer: String::new(),
                    exception_clients: Vec::new(),
                },
            ],
        };
        let table = RewriteTable::new(config);
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());

        for (domain, expected) in [
            ("long.lan.", ascii),
            ("utf8.lan.", unicode),
            ("empty.lan.", String::new()),
        ] {
            let records =
                match table.lookup(&Name::from_str(domain).unwrap(), RecordType::TXT, &client) {
                    RewriteLookup::Answered(records) => records,
                    other => panic!("{domain} must be Answered: {other:?}"),
                };
            assert_eq!(records.len(), 1);
            let RData::TXT(txt) = &records[0].data else {
                panic!("{domain} must be a TXT record");
            };
            let strings = txt
                .txt_data
                .iter()
                .map(|chunk| String::from_utf8(chunk.to_vec()).expect("valid UTF-8"))
                .collect::<Vec<_>>();
            assert!(
                strings.iter().all(|chunk| chunk.len() <= 255),
                "{domain} chunks must fit in one character-string"
            );
            assert_eq!(strings.concat(), expected, "{domain} round-trip");
        }
    }

    /// Regression (audit 6, WP-3.6): punycode config entries must match, and
    /// Unicode config entries must be normalized to punycode.
    #[test]
    fn test_idn_rewrite_entries_match_punycode_queries() {
        let config: RewritesConfig = toml::from_str(
            r#"
            [[entries]]
            domain = "xn--mnchen-3ya.de"
            type = "A"
            answer = "192.0.2.10"

            [[entries]]
            domain = "bücher.example"
            type = "A"
            answer = "192.0.2.11"

            [[entries]]
            domain = "*.xn--mnchen-3ya.de"
            type = "A"
            answer = "192.0.2.12"
        "#,
        )
        .expect("parse rewrites config");
        let table = RewriteTable::new(config);
        let client = ClientContext::new("192.168.1.50".parse().unwrap());

        let puny_apex = Name::from_ascii("xn--mnchen-3ya.de.").unwrap();
        let records = answered(table.lookup(&puny_apex, RecordType::A, &client));
        assert_eq!(records[0].data, RData::A(A(Ipv4Addr::new(192, 0, 2, 10))));

        // The Unicode config entry is normalized to punycode too.
        let unicode_entry = Name::from_ascii("xn--bcher-kva.example.").unwrap();
        let records = answered(table.lookup(&unicode_entry, RecordType::A, &client));
        assert_eq!(records[0].data, RData::A(A(Ipv4Addr::new(192, 0, 2, 11))));

        // Wildcards with IDN suffixes resolve as well.
        let wildcard = Name::from_ascii("shop.xn--mnchen-3ya.de.").unwrap();
        let records = answered(table.lookup(&wildcard, RecordType::A, &client));
        assert_eq!(records[0].data, RData::A(A(Ipv4Addr::new(192, 0, 2, 12))));
    }
}
