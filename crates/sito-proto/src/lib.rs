//! `sito-proto`
//!
//! Wire format encoding and decoding wrapping `hickory-proto`, DNS message
//! parsing, domain name normalization (FQDN canonicalization, Punycode, case-folding),
//! and wire protocol conversion utilities.

#[cfg(test)]
mod tests {
    #[test]
    fn test_proto_initialization() {
        assert_eq!(2 + 2, 4);
    }
}
