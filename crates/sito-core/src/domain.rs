//! Domain matching helpers shared by filtering, blocking and rewrite code.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Error returned when a domain name cannot be normalized.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("Domain name contains non-ASCII characters (raw IDN not allowed): '{0}'")]
    InvalidIdn(String),

    #[error("Domain name contains invalid character '{character}' in '{domain}'")]
    InvalidCharacter { domain: String, character: char },

    #[error("Invalid domain length ({length} bytes, max 253): '{domain}'")]
    DomainTooLong { domain: String, length: usize },

    #[error("Invalid label length ({length} bytes, max 63) in '{domain}'")]
    LabelTooLong { domain: String, length: usize },

    #[error("Empty label or domain name: '{0}'")]
    EmptyLabel(String),

    #[error("Invalid punycode in label '{label}': {reason}")]
    InvalidPunycode { label: String, reason: String },
}

/// A canonical domain name.
///
/// Every instance is lowercased ASCII/punycode with at most one trailing dot
/// removed and validated labels (1..=63 bytes, 253-byte total limit). Raw
/// Unicode labels are converted with IDNA. Unlike the wire-domain helpers in
/// [`NormalizedDomain::parse_ascii`], [`NormalizedDomain::parse`] preserves
/// wildcard labels (`*`, `*.example.com`, `*.banner.*`) and can represent the
/// DNS root (`.`), which cache invalidation uses as a special key.
///
/// All matching code should compare `NormalizedDomain` values (or their
/// [`NormalizedDomain::as_str`] output) instead of re-normalizing raw strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NormalizedDomain(String);

#[derive(Clone, Copy)]
struct ParseOptions {
    idna: bool,
    wildcard: bool,
    root: bool,
}

impl NormalizedDomain {
    /// Parses an operator-facing domain: IDN input is converted to punycode,
    /// ASCII is lowercased, a trailing dot is stripped, wildcard labels are
    /// preserved, and the root (`.`) is accepted.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        normalize(
            raw,
            ParseOptions {
                idna: true,
                wildcard: true,
                root: true,
            },
        )
        .map(Self)
    }

    /// Parses a wire/ASCII domain exactly like the historical
    /// `sito_proto::normalize_domain`: raw Unicode, wildcard labels and the
    /// root are rejected.
    pub fn parse_ascii(raw: &str) -> Result<Self, DomainError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(DomainError::EmptyLabel(raw.to_string()));
        }
        // Preserve the historical error precedence: raw IDN is rejected before
        // any later label validation.
        if !trimmed.is_ascii() {
            return Err(DomainError::InvalidIdn(raw.to_string()));
        }
        normalize(
            raw,
            ParseOptions {
                idna: false,
                wildcard: false,
                root: false,
            },
        )
        .map(Self)
    }

    /// Parses a wire domain, converting raw Unicode labels to punycode.
    ///
    /// This is the historical `sito_proto::normalize_domain_or_idna`
    /// behaviour: wildcards and the root remain invalid, but `münchen.de` is
    /// accepted and normalized to `xn--mnchen-3ya.de`.
    pub fn parse_idna(raw: &str) -> Result<Self, DomainError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(DomainError::EmptyLabel(raw.to_string()));
        }
        if trimmed.is_ascii() {
            return Self::parse_ascii(raw);
        }
        // Convert the whole name (not individual labels) so UTS46 dot
        // equivalents such as the ideographic full stop are mapped to `.`.
        let ascii =
            idna::domain_to_ascii(trimmed).map_err(|_| DomainError::InvalidIdn(raw.to_string()))?;
        Self::parse_ascii(&ascii).map_err(|error| match error {
            DomainError::InvalidIdn(_) => DomainError::InvalidIdn(raw.to_string()),
            other => other,
        })
    }

    /// The DNS root (`.`).
    #[must_use]
    pub fn root() -> Self {
        Self(".".to_string())
    }

    /// The canonical form: lowercase ASCII/punycode, no trailing dot, or `.`
    /// for the root.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True for the root (`.`).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0 == "."
    }

    /// True when any label is the wildcard `*`.
    #[must_use]
    pub fn has_wildcard_labels(&self) -> bool {
        self.0.split('.').any(|label| label == "*")
    }

    /// Returns true when this name equals `suffix` or is a subdomain of it.
    #[must_use]
    pub fn matches_suffix(&self, suffix: &Self) -> bool {
        matches_domain_suffix(self.as_str(), suffix.as_str())
    }

    /// Returns true when this name is a strict subdomain of `suffix`.
    #[must_use]
    pub fn is_strict_subdomain_of(&self, suffix: &Self) -> bool {
        matches_strict_subdomain(self.as_str(), suffix.as_str())
    }

    /// Consumes the wrapper and returns the canonical string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

fn normalize(raw: &str, options: ParseOptions) -> Result<String, DomainError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(DomainError::EmptyLabel(raw.to_string()));
    }
    if trimmed == "." {
        return if options.root {
            Ok(".".to_string())
        } else {
            Err(DomainError::EmptyLabel(raw.to_string()))
        };
    }

    // Strip exactly one trailing dot. A second dot produces an empty label and
    // is rejected below, matching DNS wire semantics.
    let without_trailing_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_trailing_dot.is_empty() {
        return Err(DomainError::EmptyLabel(raw.to_string()));
    }
    // Preserve the historical total-length precedence for ASCII input.
    if without_trailing_dot.is_ascii() && without_trailing_dot.len() > 253 {
        return Err(DomainError::DomainTooLong {
            domain: raw.to_string(),
            length: without_trailing_dot.len(),
        });
    }

    let mut labels = Vec::new();
    for label in without_trailing_dot.split('.') {
        if label.is_empty() {
            return Err(DomainError::EmptyLabel(raw.to_string()));
        }

        if label == "*" {
            if options.wildcard {
                labels.push("*".to_string());
                continue;
            }
            return Err(DomainError::InvalidCharacter {
                domain: raw.to_string(),
                character: '*',
            });
        }

        let ascii = if label.is_ascii() {
            label.to_ascii_lowercase()
        } else if options.idna {
            idna::domain_to_ascii(label).map_err(|_| DomainError::InvalidIdn(raw.to_string()))?
        } else {
            return Err(DomainError::InvalidIdn(raw.to_string()));
        };

        if ascii.is_empty() {
            return Err(DomainError::EmptyLabel(raw.to_string()));
        }
        if ascii.len() > 63 {
            return Err(DomainError::LabelTooLong {
                domain: raw.to_string(),
                length: ascii.len(),
            });
        }
        for ch in ascii.chars() {
            if !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') {
                return Err(DomainError::InvalidCharacter {
                    domain: raw.to_string(),
                    character: ch,
                });
            }
        }
        if let Some(punycode_part) = ascii.strip_prefix("xn--") {
            if punycode_part.is_empty() {
                return Err(DomainError::InvalidPunycode {
                    label: ascii,
                    reason: "empty punycode payload".to_string(),
                });
            }
            if idna::punycode::decode_to_string(punycode_part).is_none() {
                return Err(DomainError::InvalidPunycode {
                    label: ascii,
                    reason: "failed to decode punycode".to_string(),
                });
            }
        }
        labels.push(ascii);
    }

    let normalized = labels.join(".");
    if normalized.len() > 253 {
        return Err(DomainError::DomainTooLong {
            domain: raw.to_string(),
            length: normalized.len(),
        });
    }
    Ok(normalized)
}

impl fmt::Display for NormalizedDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NormalizedDomain {
    type Err = DomainError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw)
    }
}

impl TryFrom<&str> for NormalizedDomain {
    type Error = DomainError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        Self::parse(raw)
    }
}

impl TryFrom<String> for NormalizedDomain {
    type Error = DomainError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

impl From<NormalizedDomain> for String {
    fn from(domain: NormalizedDomain) -> Self {
        domain.0
    }
}

impl Serialize for NormalizedDomain {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NormalizedDomain {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Returns true when `candidate` equals `suffix` or is a subdomain of it.
///
/// Both values are expected to be normalized (lowercase, trailing dot
/// removed). This avoids per-query `format!(".{suffix}")` allocations on the
/// hot path.
#[must_use]
pub fn matches_domain_suffix(candidate: &str, suffix: &str) -> bool {
    if suffix.is_empty() {
        return false;
    }
    if candidate == suffix {
        return true;
    }
    candidate.len() > suffix.len()
        && candidate.ends_with(suffix)
        && candidate.as_bytes()[candidate.len() - suffix.len() - 1] == b'.'
}

/// Like [`matches_domain_suffix`] but requires the candidate to be a strict
/// subdomain (never the suffix itself).
#[must_use]
pub fn matches_strict_subdomain(candidate: &str, suffix: &str) -> bool {
    candidate != suffix && matches_domain_suffix(candidate, suffix)
}

#[cfg(test)]
mod normalized_domain_tests {
    use super::*;

    fn assert_parses_to(input: &str, expected: &str) {
        let parsed = NormalizedDomain::parse(input)
            .unwrap_or_else(|error| panic!("{input:?} must parse: {error}"));
        assert_eq!(parsed.as_str(), expected, "input {input:?}");
        assert_eq!(parsed.to_string(), expected, "input {input:?}");
        assert_eq!(
            parsed.as_str(),
            NormalizedDomain::parse(parsed.as_str())
                .expect("normalization must be idempotent")
                .as_str(),
            "normalization must be idempotent for {input:?}"
        );
    }

    #[test]
    fn test_normalized_domain_table() {
        let cases = [
            ("example.com", "example.com"),
            ("EXAMPLE.COM", "example.com"),
            ("Example.COM.", "example.com"),
            ("sub.example.com", "sub.example.com"),
            ("münchen.de", "xn--mnchen-3ya.de"),
            ("MÜNCHEN.DE.", "xn--mnchen-3ya.de"),
            ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),
            ("XN--MNCHEN-3YA.DE.", "xn--mnchen-3ya.de"),
            ("*.example.com", "*.example.com"),
            ("*", "*"),
            ("*.banner.*", "*.banner.*"),
            ("*.MÜNCHEN.de.", "*.xn--mnchen-3ya.de"),
            ("_dmarc.example.com", "_dmarc.example.com"),
            (".", "."),
        ];
        for (input, expected) in cases {
            assert_parses_to(input, expected);
        }
    }

    #[test]
    fn test_normalized_domain_root_is_representable() {
        let root = NormalizedDomain::parse(".").expect("the root must be representable");
        assert_eq!(root.as_str(), ".");
        assert!(root.is_root());
        assert!(!root.has_wildcard_labels());
    }

    #[test]
    fn test_normalized_domain_invalid_inputs() {
        assert!(matches!(
            NormalizedDomain::parse(""),
            Err(DomainError::EmptyLabel(_))
        ));
        assert!(matches!(
            NormalizedDomain::parse(".."),
            Err(DomainError::EmptyLabel(_))
        ));
        assert!(matches!(
            NormalizedDomain::parse(".example.com"),
            Err(DomainError::EmptyLabel(_))
        ));
        assert!(matches!(
            NormalizedDomain::parse("example..com"),
            Err(DomainError::EmptyLabel(_))
        ));
        assert!(matches!(
            NormalizedDomain::parse("hello world.com"),
            Err(DomainError::InvalidCharacter { character: ' ', .. })
        ));
        assert!(matches!(
            NormalizedDomain::parse("hello@world.com"),
            Err(DomainError::InvalidCharacter { character: '@', .. })
        ));
        // A wildcard is only valid as a complete label.
        assert!(matches!(
            NormalizedDomain::parse("bad*.example.com"),
            Err(DomainError::InvalidCharacter { character: '*', .. })
        ));
        assert!(matches!(
            NormalizedDomain::parse("xn--"),
            Err(DomainError::InvalidPunycode { .. })
        ));
    }

    #[test]
    fn test_normalized_domain_label_and_name_length_limits() {
        let overlong_label = "a".repeat(64);
        assert!(matches!(
            NormalizedDomain::parse(&overlong_label),
            Err(DomainError::LabelTooLong { length: 64, .. })
        ));

        // 4 * 63 + 3 dots = 255 bytes, over the 253-byte limit.
        let label = "a".repeat(63);
        let overlong_name = format!("{label}.{label}.{label}.{label}");
        assert!(matches!(
            NormalizedDomain::parse(&overlong_name),
            Err(DomainError::DomainTooLong { .. })
        ));

        // 253 bytes is the exact boundary and must be accepted
        // (63 + 1 + 63 + 1 + 63 + 1 + 61).
        let label = "a".repeat(63);
        let last = "a".repeat(61);
        let max_name = format!("{label}.{label}.{label}.{last}");
        assert_eq!(max_name.len(), 253);
        assert!(NormalizedDomain::parse(&max_name).is_ok());

        // One byte more must be rejected (63 + 1 + 63 + 1 + 63 + 1 + 62).
        let last = "a".repeat(62);
        let over_boundary = format!("{label}.{label}.{label}.{last}");
        assert_eq!(over_boundary.len(), 254);
        assert!(matches!(
            NormalizedDomain::parse(&over_boundary),
            Err(DomainError::DomainTooLong { length: 254, .. })
        ));
    }

    #[test]
    fn test_normalized_domain_ascii_constructor_keeps_wire_semantics() {
        assert_eq!(
            NormalizedDomain::parse_ascii("EXAMPLE.COM.")
                .unwrap()
                .as_str(),
            "example.com"
        );
        assert_eq!(
            NormalizedDomain::parse_ascii("XN--MNCHEN-3YA.DE")
                .unwrap()
                .as_str(),
            "xn--mnchen-3ya.de"
        );
        // Raw Unicode must be rejected by the ASCII/wire constructor.
        assert!(matches!(
            NormalizedDomain::parse_ascii("münchen.de"),
            Err(DomainError::InvalidIdn(_))
        ));
        // Wildcards and the root are not wire domain names.
        assert!(matches!(
            NormalizedDomain::parse_ascii("*.example.com"),
            Err(DomainError::InvalidCharacter { character: '*', .. })
        ));
        assert!(matches!(
            NormalizedDomain::parse_ascii("."),
            Err(DomainError::EmptyLabel(_))
        ));
    }

    #[test]
    fn test_normalized_domain_idna_wire_constructor() {
        assert_eq!(
            NormalizedDomain::parse_idna("MÜNCHEN.de.")
                .unwrap()
                .as_str(),
            "xn--mnchen-3ya.de"
        );
        assert!(matches!(
            NormalizedDomain::parse_idna("*.example.com"),
            Err(DomainError::InvalidCharacter { character: '*', .. })
        ));
        assert!(matches!(
            NormalizedDomain::parse_idna("."),
            Err(DomainError::EmptyLabel(_))
        ));
    }

    #[test]
    fn test_normalized_domain_serde_roundtrip_and_normalizes_on_deserialize() {
        let domain = NormalizedDomain::parse("MÜNCHEN.DE.").unwrap();
        let json = serde_json::to_string(&domain).expect("serialize");
        assert_eq!(json, "\"xn--mnchen-3ya.de\"");

        let roundtrip: NormalizedDomain = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(roundtrip, domain);

        let from_raw: NormalizedDomain =
            serde_json::from_str("\"EXAMPLE.COM.\"").expect("deserialize normalizes");
        assert_eq!(from_raw.as_str(), "example.com");

        assert!(serde_json::from_str::<NormalizedDomain>("\"bad domain\"").is_err());
    }

    #[test]
    fn test_normalized_domain_suffix_matching() {
        let suffix = NormalizedDomain::parse("example.com").unwrap();
        let strict = NormalizedDomain::parse("sub.example.com").unwrap();
        let apex = NormalizedDomain::parse("example.com").unwrap();
        let unrelated = NormalizedDomain::parse("notexample.com").unwrap();

        assert!(apex.matches_suffix(&suffix));
        assert!(strict.matches_suffix(&suffix));
        assert!(!unrelated.matches_suffix(&suffix));
        assert!(strict.is_strict_subdomain_of(&suffix));
        assert!(!apex.is_strict_subdomain_of(&suffix));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_domain_suffix() {
        assert!(matches_domain_suffix("example.com", "example.com"));
        assert!(matches_domain_suffix("sub.example.com", "example.com"));
        assert!(matches_domain_suffix("a.b.example.com", "example.com"));
        assert!(!matches_domain_suffix("notexample.com", "example.com"));
        assert!(!matches_domain_suffix("example.com.evil", "example.com"));
        assert!(!matches_domain_suffix("example.co", "example.com"));
        assert!(!matches_domain_suffix("anything", ""));

        assert!(!matches_strict_subdomain("example.com", "example.com"));
        assert!(matches_strict_subdomain("sub.example.com", "example.com"));
    }
}
