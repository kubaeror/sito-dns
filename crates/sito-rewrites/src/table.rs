//! DNS rewrite table implementation supporting exact, wildcard, CNAME chains, and auto-PTR.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use hickory_proto::rr::rdata::{A, AAAA, CNAME, PTR, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use sito_core::client::ClientContext;
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

#[derive(Debug, Clone)]
struct StoredRule {
    wildcard_suffix: Option<String>,
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

            let norm_domain = normalize_domain_key(&entry.domain);
            let is_wildcard = norm_domain.starts_with("*.");

            let rule = StoredRule {
                wildcard_suffix: if is_wildcard {
                    Some(norm_domain["*.".len()..].to_string())
                } else {
                    None
                },
                record_type,
                data: rdata.clone(),
                exception_clients: entry.exception_clients.clone(),
            };

            if is_wildcard {
                wildcards.push(rule.clone());
            } else {
                exact
                    .entry((norm_domain.clone(), record_type))
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
    pub fn lookup(
        &self,
        qname: &Name,
        qtype: RecordType,
        client: &ClientContext,
    ) -> Option<Vec<Record>> {
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
    ) -> Option<Vec<Record>> {
        if depth > MAX_CNAME_DEPTH {
            return None;
        }

        let qname_str = normalize_domain_key(&qname.to_string());
        if visited.iter().any(|seen| seen == &qname_str) {
            // CNAME loop detected; stop resolving to avoid unbounded recursion.
            return None;
        }
        visited.push(qname_str.clone());

        // 1. Exact match: return every non-excepted rule for (qname, qtype)
        //    in configuration order.
        if let Some(rules) = self.exact.get(&(qname_str.clone(), qtype)) {
            let answers: Vec<Record> = rules
                .iter()
                .filter(|rule| !is_client_excepted(client, &rule.exception_clients))
                .map(|rule| self.build_record(qname, &rule.data))
                .collect();
            if !answers.is_empty() {
                return Some(answers);
            }
        }

        // 2. Check exact CNAME if requested qtype is A or AAAA
        if (qtype == RecordType::A || qtype == RecordType::AAAA)
            && let Some(rules) = self.exact.get(&(qname_str.clone(), RecordType::CNAME))
        {
            for rule in rules {
                if !is_client_excepted(client, &rule.exception_clients)
                    && let LocalRecordData::Cname(ref target) = rule.data
                {
                    return self.resolve_cname(qname, target, qtype, client, visited, depth);
                }
            }
        }

        // 3. Check auto-PTR table (for PTR queries)
        if qtype == RecordType::PTR
            && let Some(rule) = self.auto_ptr.get(&qname_str)
            && !is_client_excepted(client, &rule.exception_clients)
        {
            return Some(vec![self.build_record(qname, &rule.data)]);
        }

        // 4. Check wildcard rules. The most specific (longest) matching suffix
        //    wins deterministically, independent of configuration order; all
        //    rules for the queried type at that specificity are returned in
        //    configuration order.
        let mut best_suffix_len: Option<usize> = None;
        let mut matched: Vec<&StoredRule> = Vec::new();
        for rule in &self.wildcards {
            if is_client_excepted(client, &rule.exception_clients) {
                continue;
            }

            if rule.record_type != qtype && rule.record_type != RecordType::CNAME {
                continue;
            }

            let Some(ref suffix) = rule.wildcard_suffix else {
                continue;
            };
            if !matches_wildcard(&qname_str, suffix) {
                continue;
            }

            match best_suffix_len {
                Some(len) if suffix.len() < len => continue,
                Some(len) if suffix.len() == len => {}
                _ => {
                    best_suffix_len = Some(suffix.len());
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
            return Some(
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
            return self.resolve_cname(qname, target, qtype, client, visited, depth);
        }

        None
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
        let target_key = normalize_domain_key(&target.to_string());
        if visited.iter().any(|seen| seen == &target_key) {
            warn!(
                qname = %qname,
                target = %target,
                "CNAME cycle detected in rewrite table; suppressing closing record"
            );
            return None;
        }

        let mut answers = vec![self.build_record(qname, &LocalRecordData::Cname(target.clone()))];
        if let Some(target_answers) = self.lookup_inner(target, qtype, client, visited, depth + 1) {
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

    for exc in exceptions {
        // CIDR exceptions (e.g. `10.0.0.0/8`, `fd00::/8`) match by address
        // range; they are checked before the exact-string comparisons.
        if let Some((network, prefix)) = parse_cidr(exc)
            && ip_in_cidr(network, prefix, client.ip)
        {
            return true;
        }
        if exc.eq_ignore_ascii_case(&client_ip_str) {
            return true;
        }
        if let Some(ref name) = client.client_name
            && exc.eq_ignore_ascii_case(name)
        {
            return true;
        }
        // `client.id` may carry a client-supplied DoH path segment or SNI
        // label when the client was NOT identified, so only honour it for
        // clients that resolved to an entry (mirrors the Secret gate in the
        // client registry). Otherwise `/dns-query/<exception>` could bypass a
        // rewrite exception without authenticating.
        if client.client_name.is_some()
            && let Some(ref id) = client.id
            && exc.eq_ignore_ascii_case(id.as_str())
        {
            return true;
        }
        if let Some(ref group) = client.group
            && exc.eq_ignore_ascii_case(group)
        {
            return true;
        }
        if let Some(ref mac) = client.mac
            && exc.eq_ignore_ascii_case(mac)
        {
            return true;
        }
    }

    false
}

/// Parses `address/prefix` CIDR notation into an IP address and prefix length.
fn parse_cidr(value: &str) -> Option<(IpAddr, u8)> {
    let (addr, prefix) = value.split_once('/')?;
    let addr = addr.trim().parse::<IpAddr>().ok()?;
    let prefix = prefix.trim().parse::<u8>().ok()?;
    let max_prefix = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return None;
    }
    Some((addr, prefix))
}

/// Checks whether `target` falls inside `network/prefix`.
fn ip_in_cidr(network: IpAddr, prefix: u8, target: IpAddr) -> bool {
    match (network, target) {
        (IpAddr::V4(net), IpAddr::V4(tgt)) => {
            if prefix == 0 {
                return true;
            }
            let mask = if prefix >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(net) & mask) == (u32::from(tgt) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(tgt)) => {
            if prefix == 0 {
                return true;
            }
            let mask = if prefix >= 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(net) & mask) == (u128::from(tgt) & mask)
        }
        _ => false,
    }
}

fn normalize_domain_key(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn matches_wildcard(candidate: &str, suffix: &str) -> bool {
    // `*.example.com` matches subdomains only, not the apex itself.
    sito_core::matches_strict_subdomain(candidate, suffix)
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
        "TXT" => Some((
            RecordType::TXT,
            LocalRecordData::Txt(vec![answer.to_string()]),
        )),
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
        let answers = table
            .lookup(&qname_printer, RecordType::A, &client)
            .unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].data, RData::A(A(Ipv4Addr::new(192, 168, 1, 50))));

        let qname_v6 = Name::from_str("printer-v6.lan.").unwrap();
        let answers_v6 = table.lookup(&qname_v6, RecordType::AAAA, &client).unwrap();
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
        let answers = table.lookup(&qname_nas, RecordType::A, &client).unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name, qname_nas);
        assert_eq!(answers[0].data, RData::A(A(Ipv4Addr::new(192, 168, 1, 10))));

        let qname_deep = Name::from_str("foo.bar.home.arpa.").unwrap();
        let answers_deep = table.lookup(&qname_deep, RecordType::A, &client).unwrap();
        assert_eq!(answers_deep.len(), 1);
        assert_eq!(answers_deep[0].name, qname_deep);
    }

    #[test]
    fn test_exact_beats_wildcard() {
        let table = sample_table();
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());

        let qname = Name::from_str("special.home.arpa.").unwrap();
        let answers = table.lookup(&qname, RecordType::A, &client).unwrap();
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
        let answers = table
            .lookup(&Name::from_str("a.lan.").unwrap(), RecordType::A, &client)
            .expect("valid prefix must be returned");
        assert_eq!(answers.len(), 1, "closing cycle record must be suppressed");
        assert_eq!(answers[0].record_type(), RecordType::CNAME);
        assert_eq!(
            answers[0].data,
            RData::CNAME(CNAME(Name::from_str("b.lan.").unwrap()))
        );

        // The same holds when the cycle is entered from `b.lan`.
        let answers_b = table
            .lookup(&Name::from_str("b.lan.").unwrap(), RecordType::A, &client)
            .expect("valid prefix must be returned");
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
        assert!(
            table
                .lookup(
                    &Name::from_str("loop.lan.").unwrap(),
                    RecordType::A,
                    &client
                )
                .is_none()
        );
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

        let answers = table
            .lookup(
                &Name::from_str("multi.lan.").unwrap(),
                RecordType::A,
                &client,
            )
            .unwrap();
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
        let deep = table
            .lookup(
                &Name::from_str("x.sub.home.arpa.").unwrap(),
                RecordType::A,
                &client,
            )
            .unwrap();
        assert_eq!(deep.len(), 1);
        assert_eq!(deep[0].data, RData::A(A(Ipv4Addr::new(192, 168, 1, 20))));

        // `x.home.arpa` only matches `*.home.arpa`; both same-suffix rules
        // answer, in configuration order.
        let shallow = table
            .lookup(
                &Name::from_str("x.home.arpa.").unwrap(),
                RecordType::A,
                &client,
            )
            .unwrap();
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
        assert!(table.lookup(&qname, RecordType::A, &excepted).is_none());

        // In-range IPv6 client is excepted.
        let excepted_v6 = ClientContext::new(IpAddr::from_str("fd00::7").unwrap());
        assert!(table.lookup(&qname, RecordType::A, &excepted_v6).is_none());

        // Out-of-range client still receives the rewrite.
        let allowed = ClientContext::new(IpAddr::from_str("10.11.0.1").unwrap());
        assert!(table.lookup(&qname, RecordType::A, &allowed).is_some());
        let allowed_v6 = ClientContext::new(IpAddr::from_str("fe80::1").unwrap());
        assert!(table.lookup(&qname, RecordType::A, &allowed_v6).is_some());
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
        let answers = table
            .lookup(
                &Name::from_str("printer.lan.").unwrap(),
                RecordType::A,
                &client,
            )
            .unwrap();
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
        assert!(table.lookup(&qname, RecordType::A, &client).is_none());
    }

    #[test]
    fn test_cname_chain_resolution() {
        let table = sample_table();
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());

        let qname_router = Name::from_str("router.lan.").unwrap();
        let answers = table.lookup(&qname_router, RecordType::A, &client).unwrap();
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].record_type(), RecordType::CNAME);
        assert_eq!(answers[1].record_type(), RecordType::A);
        assert_eq!(answers[1].data, RData::A(A(Ipv4Addr::new(192, 168, 1, 1))));

        // External CNAME returns only CNAME
        let qname_ext = Name::from_str("external.lan.").unwrap();
        let answers_ext = table.lookup(&qname_ext, RecordType::A, &client).unwrap();
        assert_eq!(answers_ext.len(), 1);
        assert_eq!(answers_ext[0].record_type(), RecordType::CNAME);
    }

    #[test]
    fn test_auto_ptr_reverse_lookup() {
        let table = sample_table();
        let client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());

        // 192.168.1.50 -> printer.lan
        let ptr_query = Name::from_str("50.1.168.192.in-addr.arpa.").unwrap();
        let answers = table.lookup(&ptr_query, RecordType::PTR, &client).unwrap();
        assert_eq!(answers.len(), 1);
        let expected_target = Name::from_str("printer.lan.").unwrap();
        assert_eq!(answers[0].data, RData::PTR(PTR(expected_target)));

        // fd00::50 -> printer-v6.lan
        let v6_arpa = ipv6_to_ip6_arpa(&Ipv6Addr::from_str("fd00::50").unwrap());
        let ptr_v6_query = Name::from_str(&format!("{v6_arpa}.")).unwrap();
        let answers_v6 = table
            .lookup(&ptr_v6_query, RecordType::PTR, &client)
            .unwrap();
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
            table.lookup(&qname_nas, RecordType::A, &attacker).is_some(),
            "unidentified clients must not match rewrite exceptions by raw id"
        );

        // Identified clients may still be excepted by their resolved identity.
        let mut identified = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());
        identified.client_name = Some("admin-laptop".to_string());
        identified.id = Some(sito_core::ClientId::new("admin-laptop"));
        assert!(
            table
                .lookup(&qname_nas, RecordType::A, &identified)
                .is_none()
        );
    }

    #[test]
    fn test_exception_clients_bypass() {
        let table = sample_table();
        let mut client = ClientContext::new(IpAddr::from_str("192.168.1.20").unwrap());
        client.client_name = Some("admin-laptop".to_string());

        let qname_nas = Name::from_str("nas.home.arpa.").unwrap();
        // admin-laptop is in exception_clients for *.home.arpa -> should bypass and return None
        assert!(table.lookup(&qname_nas, RecordType::A, &client).is_none());

        // But non-excepted client gets the rewrite
        let other_client = ClientContext::new(IpAddr::from_str("192.168.1.30").unwrap());
        assert!(
            table
                .lookup(&qname_nas, RecordType::A, &other_client)
                .is_some()
        );
    }
}
