//! Domain name normalization and verification.

use crate::error::ProtoError;
use sito_core::domain::{DomainError, NormalizedDomain};

/// Converts a domain that may contain raw Unicode characters (IDN) into its
/// normalized ASCII/punycode form.
///
/// Configuration and list files written by humans may use `münchen.de`; wire
/// names and compiled matching structures are always punycode. Normalizing
/// both sides through this function keeps matching and cache invalidation
/// working for IDNs.
///
/// The canonical implementation lives in
/// [`sito_core::domain::NormalizedDomain`]; this wrapper preserves the
/// historical `sito_proto::ProtoError` contract.
pub fn normalize_domain_or_idna(raw: &str) -> Result<String, ProtoError> {
    NormalizedDomain::parse_idna(raw)
        .map(NormalizedDomain::into_string)
        .map_err(ProtoError::from)
}

/// Normalize and validate a domain name string:
/// - Lowercase all ASCII characters
/// - Strip trailing dot (root)
/// - Reject non-ASCII Unicode characters (IDN must be punycode encoded)
/// - Verify valid punycode for labels starting with "xn--"
/// - Reject empty labels and invalid characters
///
/// Delegates to [`sito_core::domain::NormalizedDomain::parse_ascii`], which is
/// the canonical implementation.
pub fn normalize_domain(raw: &str) -> Result<String, ProtoError> {
    NormalizedDomain::parse_ascii(raw)
        .map(NormalizedDomain::into_string)
        .map_err(ProtoError::from)
}

impl From<DomainError> for ProtoError {
    fn from(error: DomainError) -> Self {
        match error {
            DomainError::InvalidIdn(value) => Self::InvalidIdn(value),
            DomainError::InvalidCharacter { domain, character } => {
                Self::InvalidCharacter { domain, character }
            }
            DomainError::DomainTooLong { domain, length } => Self::DomainTooLong { domain, length },
            DomainError::LabelTooLong { domain, length } => Self::LabelTooLong { domain, length },
            DomainError::EmptyLabel(value) => Self::EmptyLabel(value),
            DomainError::InvalidPunycode { label, reason } => {
                Self::InvalidPunycode { label, reason }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_uppercase_and_trailing_dot() {
        assert_eq!(normalize_domain("EXAMPLE.COM.").unwrap(), "example.com");
        assert_eq!(
            normalize_domain("Sub.Example.COM").unwrap(),
            "sub.example.com"
        );
    }

    #[test]
    fn test_reject_raw_idn() {
        // Unicode raw characters should be rejected as invalid IDN
        let res = normalize_domain("żółw.pl");
        assert!(matches!(res, Err(ProtoError::InvalidIdn(_))));

        let res2 = normalize_domain("münchen.de");
        assert!(matches!(res2, Err(ProtoError::InvalidIdn(_))));
    }

    #[test]
    fn test_punycode_validation() {
        // Valid punycode for "münchen.de" is "xn--mnchen-3ya.de"
        assert_eq!(
            normalize_domain("XN--MNCHEN-3YA.DE").unwrap(),
            "xn--mnchen-3ya.de"
        );

        // Invalid punycode
        let bad = normalize_domain("xn--invalid-!chars.com");
        assert!(bad.is_err());
    }

    #[test]
    fn test_reject_invalid_characters() {
        let res = normalize_domain("hello@world.com");
        assert!(matches!(res, Err(ProtoError::InvalidCharacter { .. })));

        let res2 = normalize_domain("hello space.com");
        assert!(matches!(res2, Err(ProtoError::InvalidCharacter { .. })));
    }

    #[test]
    fn test_reject_empty_label() {
        assert!(matches!(
            normalize_domain("example..com"),
            Err(ProtoError::EmptyLabel(_))
        ));
        assert!(matches!(
            normalize_domain(".example.com"),
            Err(ProtoError::EmptyLabel(_))
        ));
        assert!(matches!(
            normalize_domain(""),
            Err(ProtoError::EmptyLabel(_))
        ));
        assert!(matches!(
            normalize_domain("."),
            Err(ProtoError::EmptyLabel(_))
        ));
    }

    #[test]
    fn test_normalize_domain_or_idna_converts_unicode() {
        assert_eq!(
            normalize_domain_or_idna("MÜNCHEN.de.").unwrap(),
            "xn--mnchen-3ya.de"
        );
        assert_eq!(
            normalize_domain_or_idna("Example.COM").unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_domain_or_idna("xn--mnchen-3ya.de").unwrap(),
            "xn--mnchen-3ya.de"
        );
        assert!(normalize_domain_or_idna("bad domain.com").is_err());
    }

    #[test]
    fn test_normalize_domain_randomized_invariants() {
        // Deterministic pseudo-random strings over a hostile alphabet
        // (separators, unicode, punycode prefixes).
        let chars: Vec<char> =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/ é中xn--"
                .chars()
                .collect();
        let mut state: u64 = 0xDEAD_BEEF_CAFE_1234;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state
        };

        for _ in 0..3000 {
            let len = (next() % 80) as usize;
            let raw: String = (0..len)
                .map(|_| chars[(next() as usize) % chars.len()])
                .collect();

            if let Ok(normalized) = normalize_domain(&raw) {
                assert!(
                    normalized.is_ascii(),
                    "normalized output must be ASCII: {normalized:?}"
                );
                assert!(
                    normalized.chars().all(|c| !c.is_ascii_uppercase()),
                    "normalized output must be lowercase: {normalized:?}"
                );
                assert!(
                    !normalized.starts_with('.') && !normalized.ends_with('.'),
                    "normalized output must not have edge dots: {normalized:?}"
                );
                assert!(
                    !normalized.split('.').any(str::is_empty),
                    "normalized output must not contain empty labels: {normalized:?}"
                );
                assert!(
                    normalized.split('.').all(|label| label.len() <= 63),
                    "labels must be at most 63 bytes: {normalized:?}"
                );
                assert!(
                    normalized.len() <= 253,
                    "names must be at most 253 bytes: {normalized:?}"
                );
                assert_eq!(
                    normalize_domain(&normalized).expect("normalized output must re-validate"),
                    normalized,
                    "normalization must be idempotent"
                );
            }
        }
    }
}
