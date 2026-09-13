//! Cache lookup key definition.

use sito_proto::rdata::opt::ClientSubnet;
use sito_proto::{DNSClass, Edns, Message, Name, RecordType, normalize_domain};

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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
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
            dnssec_ok: false,
            checking_disabled: false,
            ecs: None,
        }
    }

    /// Build a key that includes the query's DO/CD bits and ECS option.
    ///
    /// Returns `None` when the message carries no question section.
    pub fn from_query(query: &Message) -> Option<Self> {
        let first_query = query.queries.first()?;
        Some(Self {
            qname: normalize_name(first_query.name()),
            qtype: u16::from(first_query.query_type()),
            qclass: u16::from(first_query.query_class()),
            dnssec_ok: query
                .edns
                .as_ref()
                .is_some_and(|edns| edns.flags().dnssec_ok),
            checking_disabled: query.metadata.checking_disabled,
            ecs: ecs_option(query.edns.as_ref()),
        })
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
    let raw_name = name.to_string();
    normalize_domain(&raw_name).unwrap_or_else(|_| raw_name.to_ascii_lowercase())
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
}
