//! DNS rewrite table implementation supporting exact, wildcard, CNAME chains, and auto-PTR.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use hickory_proto::rr::rdata::{A, AAAA, CNAME, PTR, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use sito_core::client::ClientContext;

use crate::config::RewritesConfig;

const DEFAULT_REWRITE_TTL: u32 = 60;

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
#[derive(Debug, Clone, Default)]
pub struct RewriteTable {
    exact: HashMap<(String, RecordType), Vec<StoredRule>>,
    wildcards: Vec<StoredRule>,
    auto_ptr: HashMap<String, StoredRule>,
}

impl RewriteTable {
    pub fn new(config: RewritesConfig) -> Self {
        let mut exact: HashMap<(String, RecordType), Vec<StoredRule>> = HashMap::new();
        let mut wildcards = Vec::new();
        let mut auto_ptr_candidates = Vec::new();

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
                    // Check if candidate for auto-PTR (non-wildcard A or AAAA to RFC1918/ULA)
                    if let LocalRecordData::A(ipv4) = rdata {
                        if is_rfc1918(&ipv4) {
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
                    } else if let LocalRecordData::AAAA(ipv6) = rdata {
                        if is_ula(&ipv6) {
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
        }
    }

    /// Look up local rewrite records for a query.
    pub fn lookup(
        &self,
        qname: &Name,
        qtype: RecordType,
        client: &ClientContext,
    ) -> Option<Vec<Record>> {
        let qname_str = normalize_domain_key(&qname.to_string());

        // 1. Check exact match
        if let Some(rules) = self.exact.get(&(qname_str.clone(), qtype)) {
            for rule in rules {
                if !is_client_excepted(client, &rule.exception_clients) {
                    return Some(vec![build_record(qname, &rule.data)]);
                }
            }
        }

        // 2. Check exact CNAME if requested qtype is A or AAAA
        if qtype == RecordType::A || qtype == RecordType::AAAA {
            if let Some(rules) = self.exact.get(&(qname_str.clone(), RecordType::CNAME)) {
                for rule in rules {
                    if !is_client_excepted(client, &rule.exception_clients) {
                        if let LocalRecordData::Cname(ref target) = rule.data {
                            let mut answers = vec![build_record(qname, &rule.data)];
                            // Chain resolution: check if target is also in our rewrite table
                            if let Some(target_answers) = self.lookup(target, qtype, client) {
                                answers.extend(target_answers);
                            }
                            return Some(answers);
                        }
                    }
                }
            }
        }

        // 3. Check auto-PTR table (for PTR queries)
        if qtype == RecordType::PTR {
            if let Some(rule) = self.auto_ptr.get(&qname_str) {
                if !is_client_excepted(client, &rule.exception_clients) {
                    return Some(vec![build_record(qname, &rule.data)]);
                }
            }
        }

        // 4. Check wildcard rules
        for rule in &self.wildcards {
            if is_client_excepted(client, &rule.exception_clients) {
                continue;
            }

            if rule.record_type != qtype && rule.record_type != RecordType::CNAME {
                continue;
            }

            if let Some(ref suffix) = rule.wildcard_suffix {
                if matches_wildcard(&qname_str, suffix) {
                    if rule.record_type == RecordType::CNAME {
                        if let LocalRecordData::Cname(ref target) = rule.data {
                            let mut answers = vec![build_record(qname, &rule.data)];
                            if let Some(target_answers) = self.lookup(target, qtype, client) {
                                answers.extend(target_answers);
                            }
                            return Some(answers);
                        }
                    }
                    return Some(vec![build_record(qname, &rule.data)]);
                }
            }
        }

        None
    }
}

fn is_client_excepted(client: &ClientContext, exceptions: &[String]) -> bool {
    if exceptions.is_empty() {
        return false;
    }

    let client_ip_str = client.ip.to_string();

    for exc in exceptions {
        if exc.eq_ignore_ascii_case(&client_ip_str) {
            return true;
        }
        if let Some(ref name) = client.client_name {
            if exc.eq_ignore_ascii_case(name) {
                return true;
            }
        }
        if let Some(ref id) = client.id {
            if exc.eq_ignore_ascii_case(id.as_str()) {
                return true;
            }
        }
        if let Some(ref group) = client.group {
            if exc.eq_ignore_ascii_case(group) {
                return true;
            }
        }
        if let Some(ref mac) = client.mac {
            if exc.eq_ignore_ascii_case(mac) {
                return true;
            }
        }
    }

    false
}

fn build_record(qname: &Name, data: &LocalRecordData) -> Record {
    let rdata = match data {
        LocalRecordData::A(ip) => RData::A(A(*ip)),
        LocalRecordData::AAAA(ip) => RData::AAAA(AAAA(*ip)),
        LocalRecordData::Cname(target) => RData::CNAME(CNAME(target.clone())),
        LocalRecordData::Ptr(target) => RData::PTR(PTR(target.clone())),
        LocalRecordData::Txt(strings) => RData::TXT(TXT::new(strings.clone())),
    };

    Record::from_rdata(qname.clone(), DEFAULT_REWRITE_TTL, rdata)
}

fn normalize_domain_key(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn matches_wildcard(candidate: &str, suffix: &str) -> bool {
    if candidate == suffix {
        return true;
    }
    if candidate.ends_with(&format!(".{suffix}")) {
        return true;
    }
    false
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
