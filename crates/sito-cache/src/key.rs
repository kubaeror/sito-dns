//! Cache lookup key definition.

use sito_proto::rdata::opt::ClientSubnet;
use sito_proto::{DNSClass, Edns, Message, Name, OpCode, RecordType, normalize_domain};

/// Key identifying a unique DNS query for caching.
///
/// Besides the question (name/type/class) the key separates entries by the
/// DNSSEC-relevant client flags and by the EDNS Client Subnet option:
///
/// * `dnssec_ok` mirrors the query's DO bit. Responses fetched with DO=1
///   carry RRSIGs (and may be validated/AD), so they must never be served in
///   place of a DO=0 response and vice versa.
/// * `checking_disabled` mirrors the query's CD bit. CD=1 answers skip
///   validation and are cached with AD cleared; sharing them with CD=0
///   clients would let a client opt the whole cache out of validation.
/// * `ecs` mirrors the RFC 7871 Client Subnet option that this pipeline
///   forwards upstream, so subnet-specific answers are only served to the
///   same client subnet.
/// * `opcode` separates questions with the same name/type/class but a
///   different operation (for example `QUERY` vs `NOTIFY`/`UPDATE`), which
///   may carry completely different semantics.
/// * `edns` records whether the query carried an OPT record. A non-EDNS
///   client is limited to a 512-byte UDP response, so its answer must not
///   share a slot with an EDNS client that negotiated a larger buffer.
///
/// EDNS options that cannot change the answer (COOKIE, NSID, padding and any
/// unknown option) are deliberately **not** part of the key; they are
/// sanitized by the response shaper and must never split or leak cache
/// entries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    /// DNS opcode of the query (RFC 1035 §4.1.1).
    pub opcode: u16,
    /// Whether the query carried an EDNS OPT record (RFC 6891).
    pub edns: bool,
    /// DNSSEC OK (DO) bit of the client query (RFC 3225).
    pub dnssec_ok: bool,
    /// Checking Disabled (CD) bit of the client query (RFC 4035).
    pub checking_disabled: bool,
    /// EDNS Client Subnet option (RFC 7871) when present.
    pub ecs: Option<ClientSubnet>,
}

impl CacheKey {
    /// Create a CacheKey from a query name, record type, and class.
    ///
    /// DO/CD default to `false` and ECS to `None`; use [`CacheKey::from_query`]
    /// (or the `with_*` builders) to key on the full query.
    pub fn new(name: &Name, qtype: RecordType, qclass: DNSClass) -> Self {
        Self {
            qname: normalize_name(name),
            qtype: u16::from(qtype),
            qclass: u16::from(qclass),
            opcode: u16::from(u8::from(OpCode::Query)),
            edns: false,
            dnssec_ok: false,
            checking_disabled: false,
            ecs: None,
        }
    }

    /// Canonical constructor: build a key from the complete client query.
    ///
    /// Includes the question, opcode, EDNS presence, DO/CD bits and the ECS
    /// option that affects the answer. Every other EDNS option is upstream- or
    /// client-local and is sanitized by [`sito_proto::ResponseShaper`].
    ///
    /// Returns `None` when the message carries no question section.
    pub fn for_query(query: &Message) -> Option<Self> {
        let first_query = query.queries.first()?;
        Some(Self {
            qname: normalize_name(first_query.name()),
            qtype: u16::from(first_query.query_type()),
            qclass: u16::from(first_query.query_class()),
            opcode: u16::from(u8::from(query.metadata.op_code)),
            edns: query.edns.is_some(),
            dnssec_ok: query
                .edns
                .as_ref()
                .is_some_and(|edns| edns.flags().dnssec_ok),
            checking_disabled: query.metadata.checking_disabled,
            ecs: ecs_option(query.edns.as_ref()),
        })
    }

    /// Alias for [`CacheKey::for_query`] retained for compatibility.
    ///
    /// Build a key that includes the query's DO/CD bits and ECS option.
    ///
    /// Returns `None` when the message carries no question section.
    pub fn from_query(query: &Message) -> Option<Self> {
        Self::for_query(query)
    }

    /// Sets the DO and CD bits explicitly.
    #[must_use]
    pub fn with_flags(mut self, dnssec_ok: bool, checking_disabled: bool) -> Self {
        self.dnssec_ok = dnssec_ok;
        self.checking_disabled = checking_disabled;
        self
    }

    /// Sets the ECS option explicitly.
    #[must_use]
    pub fn with_ecs(mut self, ecs: Option<ClientSubnet>) -> Self {
        self.ecs = ecs;
        self
    }
}

fn normalize_name(name: &Name) -> String {
    // Use the ASCII/punycode form: `Display`/`to_utf8` UTS46-decodes `xn--`
    // labels, which would key IDN queries under a Unicode variant that
    // `invalidate_domain` (punycode-normalized) can never evict.
    let ascii = name.to_ascii();
    if ascii.is_empty() || ascii == "." {
        // `normalize_domain` rejects the root (empty label); keep a canonical
        // "." so root queries are cacheable and `invalidate_domain(".")` can
        // address them.
        return ".".to_string();
    }
    normalize_domain(&ascii).unwrap_or_else(|_| ascii.trim_end_matches('.').to_ascii_lowercase())
}

/// Extracts the RFC 7871 Client Subnet option from the query's EDNS record.
fn ecs_option(edns: Option<&Edns>) -> Option<ClientSubnet> {
    use sito_proto::rdata::opt::{EdnsCode, EdnsOption};

    match edns?.option(EdnsCode::Subnet) {
        Some(EdnsOption::Subnet(subnet)) => Some(*subnet),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sito_proto::{MessageType, OpCode, Query};
    use std::str::FromStr;

    #[test]
    fn test_key_new_defaults_are_legacy_flags() {
        let name = Name::from_str("Example.COM.").unwrap();
        let key = CacheKey::new(&name, RecordType::A, DNSClass::IN);
        assert_eq!(key.qname, "example.com");
        assert_eq!(key.qtype, u16::from(RecordType::A));
        assert_eq!(key.qclass, u16::from(DNSClass::IN));
        assert!(!key.dnssec_ok);
        assert!(!key.checking_disabled);
        assert!(key.ecs.is_none());
    }

    #[test]
    fn test_idn_query_is_keyed_by_punycode() {
        // `münchen.de` on the wire is `xn--mnchen-3ya.de`; the key must use
        // the punycode form so `invalidate_domain("münchen.de")` (normalized
        // with IDNA) can evict it.
        let name = Name::from_str("xn--mnchen-3ya.de.").unwrap();
        let key = CacheKey::new(&name, RecordType::A, DNSClass::IN);
        assert_eq!(key.qname, "xn--mnchen-3ya.de");
    }

    #[test]
    fn test_key_from_query_includes_do_cd_and_ecs() {
        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        query.metadata.checking_disabled = true;
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.options_mut()
            .insert(sito_proto::rdata::opt::EdnsOption::Subnet(
                ClientSubnet::new("192.0.2.0".parse().unwrap(), 24, 0),
            ));
        query.set_edns(edns);

        let key = CacheKey::from_query(&query).unwrap();
        assert!(key.dnssec_ok);
        assert!(key.checking_disabled);
        assert_eq!(
            key.ecs,
            Some(ClientSubnet::new("192.0.2.0".parse().unwrap(), 24, 0))
        );

        // Plain questions with different flags/ECS must not collide.
        let mut plain = Message::new(1, MessageType::Query, OpCode::Query);
        plain.queries.push(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        let plain_key = CacheKey::from_query(&plain).unwrap();
        assert_ne!(plain_key, key);
    }

    #[test]
    fn test_key_from_query_without_question_is_none() {
        let query = Message::new(1, MessageType::Query, OpCode::Query);
        assert!(CacheKey::from_query(&query).is_none());
    }

    #[test]
    fn test_opcode_is_part_of_the_key() {
        let name = Name::from_str("example.com.").unwrap();
        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(name.clone(), RecordType::A));
        let query_key = CacheKey::from_query(&query).unwrap();

        query.metadata.op_code = OpCode::Notify;
        let notify_key = CacheKey::from_query(&query).unwrap();

        assert_ne!(
            query_key, notify_key,
            "different opcodes must not share a cache entry"
        );
    }

    #[test]
    fn test_root_name_key_is_dot() {
        let key = CacheKey::new(&Name::root(), RecordType::NS, DNSClass::IN);
        assert_eq!(key.qname, ".");

        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(Name::root(), RecordType::NS));
        assert_eq!(CacheKey::from_query(&query).unwrap().qname, ".");
    }

    fn query_with_edns(name: &str) -> Message {
        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        query.set_edns(Edns::new());
        query
    }

    /// P2-23: EDNS presence changes the negotiated UDP payload size, so a
    /// non-EDNS answer must not be served to an EDNS client or vice versa.
    #[test]
    fn test_key_for_query_keys_edns_presence() {
        let name = "edns-presence.example.";
        let mut plain = Message::new(1, MessageType::Query, OpCode::Query);
        plain
            .queries
            .push(Query::query(Name::from_str(name).unwrap(), RecordType::A));

        let edns = query_with_edns(name);
        let plain_key = CacheKey::for_query(&plain).unwrap();
        let edns_key = CacheKey::for_query(&edns).unwrap();

        assert!(!plain_key.edns);
        assert!(edns_key.edns);
        assert_ne!(
            plain_key, edns_key,
            "EDNS presence must split the cache keyspace"
        );
    }

    /// Cookies, NSID, padding and unknown options cannot change the answer;
    /// they must neither split the cache nor cross clients through the key.
    #[test]
    fn test_key_for_query_ignores_non_answer_affecting_edns_options() {
        use sito_proto::rdata::opt::EdnsOption;

        let name = "edns-options.example.";
        let base = query_with_edns(name);
        let base_key = CacheKey::for_query(&base).unwrap();

        let mut optioned = query_with_edns(name);
        let edns = optioned.edns.as_mut().expect("EDNS present");
        edns.options_mut()
            .insert(EdnsOption::Unknown(10, vec![1, 2, 3, 4])); // COOKIE
        edns.options_mut()
            .insert(EdnsOption::Unknown(3, vec![b'n', b's'])); // NSID
        edns.options_mut()
            .insert(EdnsOption::Unknown(12, vec![0; 16])); // padding
        edns.options_mut()
            .insert(EdnsOption::Unknown(65_001, vec![9])); // unknown
        let optioned_key = CacheKey::for_query(&optioned).unwrap();

        assert_eq!(
            base_key, optioned_key,
            "upstream-only EDNS options must not split the cache key"
        );
    }

    /// P2-23: every flag that can change the response is part of the key.
    #[test]
    fn test_key_for_query_separates_do_cd_and_ecs() {
        let name = "flags.example.";
        let mut keys = Vec::new();
        for (do_bit, cd) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut query = query_with_edns(name);
            let edns = query.edns.as_mut().expect("EDNS present");
            edns.set_dnssec_ok(do_bit);
            query.metadata.checking_disabled = cd;
            keys.push(CacheKey::for_query(&query).unwrap());
        }
        for (left, right) in [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)] {
            assert_ne!(
                keys[left], keys[right],
                "DO/CD combinations must not share a cache entry"
            );
        }

        let mut ecs_a = query_with_edns(name);
        ecs_a.edns.as_mut().unwrap().options_mut().insert(
            sito_proto::rdata::opt::EdnsOption::Subnet(ClientSubnet::new(
                "192.0.2.0".parse().unwrap(),
                24,
                0,
            )),
        );
        let mut ecs_b = query_with_edns(name);
        ecs_b.edns.as_mut().unwrap().options_mut().insert(
            sito_proto::rdata::opt::EdnsOption::Subnet(ClientSubnet::new(
                "198.51.100.0".parse().unwrap(),
                24,
                0,
            )),
        );
        assert_ne!(
            CacheKey::for_query(&ecs_a).unwrap(),
            CacheKey::for_query(&ecs_b).unwrap(),
            "different ECS networks must not share a cache entry"
        );
    }

    #[test]
    fn test_key_for_query_is_the_canonical_from_query_alias() {
        let mut query = query_with_edns("alias.example.");
        query.metadata.checking_disabled = true;
        assert_eq!(
            CacheKey::for_query(&query).unwrap(),
            CacheKey::from_query(&query).unwrap()
        );
    }
}
