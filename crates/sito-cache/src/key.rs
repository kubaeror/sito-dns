//! Cache lookup key definition.

use sito_proto::{DNSClass, Name, RecordType, normalize_domain};

/// Key identifying a unique DNS query for caching.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl CacheKey {
    /// Create a CacheKey from a query name, record type, and class.
    pub fn new(name: &Name, qtype: RecordType, qclass: DNSClass) -> Self {
        let raw_name = name.to_string();
        let normalized =
            normalize_domain(&raw_name).unwrap_or_else(|_| raw_name.to_ascii_lowercase());
        Self {
            qname: normalized,
            qtype: u16::from(qtype),
            qclass: u16::from(qclass),
        }
    }
}
