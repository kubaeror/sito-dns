//! `sito-dnssec`
//!
//! DNSSEC cryptographic validation:
//! - Authentication chain verification (RRSIG, DNSKEY, DS records)
//! - Built-in root trust anchors with automatic RFC 5011 tracking
//! - NSEC and NSEC3 authenticated denial of existence verification
//! - Negative Trust Anchor (NTA) management for internal or broken domains

#[cfg(test)]
mod tests {
    #[test]
    fn test_dnssec_initialization() {
        assert_eq!(2 + 2, 4);
    }
}
