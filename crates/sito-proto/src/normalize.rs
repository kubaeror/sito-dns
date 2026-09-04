//! Domain name normalization and verification.

use crate::error::ProtoError;

/// Normalize and validate a domain name string:
/// - Lowercase all ASCII characters
/// - Strip trailing dot (root)
/// - Reject non-ASCII Unicode characters (IDN must be punycode encoded)
/// - Verify valid punycode for labels starting with "xn--"
/// - Reject empty labels and invalid characters
pub fn normalize_domain(raw: &str) -> Result<String, ProtoError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ProtoError::EmptyLabel(raw.to_string()));
    }

    // Reject non-ASCII characters directly (raw IDN)
    for ch in trimmed.chars() {
        if !ch.is_ascii() {
            return Err(ProtoError::InvalidIdn(raw.to_string()));
        }
    }

    // Strip trailing dot
    let without_trailing_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);

    if without_trailing_dot.is_empty() {
        return Err(ProtoError::EmptyLabel(raw.to_string()));
    }

    if without_trailing_dot.len() > 253 {
        return Err(ProtoError::DomainTooLong {
            domain: raw.to_string(),
            length: without_trailing_dot.len(),
        });
    }

    let lowercase = without_trailing_dot.to_ascii_lowercase();
    let labels: Vec<&str> = lowercase.split('.').collect();

    for label in &labels {
        if label.is_empty() {
            return Err(ProtoError::EmptyLabel(raw.to_string()));
        }
        if label.len() > 63 {
            return Err(ProtoError::LabelTooLong {
                domain: raw.to_string(),
                length: label.len(),
            });
        }

        // Validate characters: standard hostname characters are a-z, 0-9, hyphen, underscore
        for ch in label.chars() {
            if !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') {
                return Err(ProtoError::InvalidCharacter {
                    domain: raw.to_string(),
                    character: ch,
                });
            }
        }

        // Punycode verification for IDNA labels starting with "xn--"
        if let Some(punycode_part) = label.strip_prefix("xn--") {
            if punycode_part.is_empty() {
                return Err(ProtoError::InvalidPunycode {
                    label: (*label).to_string(),
                    reason: "empty punycode payload".to_string(),
                });
            }
            if idna::punycode::decode_to_string(punycode_part).is_none() {
                return Err(ProtoError::InvalidPunycode {
                    label: (*label).to_string(),
                    reason: "failed to decode punycode".to_string(),
                });
            }
        }
    }

    Ok(lowercase)
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
}
