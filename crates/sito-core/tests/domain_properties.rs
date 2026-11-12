//! Property tests for domain normalization and suffix matching (WP-1.8).
//!
//! Iterations are deliberately bounded (96 cases) so the property lane stays
//! fast; the table-driven unit tests in `src/domain.rs` cover the exhaustive
//! boundary cases.

use proptest::prelude::*;
use sito_core::{NormalizedDomain, matches_domain_suffix};

const CASES: u32 = 96;

fn property_config() -> ProptestConfig {
    ProptestConfig {
        cases: CASES,
        max_shrink_iters: 2_000,
        ..ProptestConfig::default()
    }
}

/// A syntactically valid ASCII label: 1-16 chars, no leading/trailing hyphen.
fn ascii_label() -> impl Strategy<Value = String> {
    "[a-z0-9]([a-z0-9-]{0,14}[a-z0-9])?"
}

fn ascii_domain() -> impl Strategy<Value = String> {
    proptest::collection::vec(ascii_label(), 1..=4).prop_map(|labels| labels.join("."))
}

fn wildcard_label() -> impl Strategy<Value = String> {
    prop_oneof![Just("*".to_string()), ascii_label()]
}

fn wildcard_domain() -> impl Strategy<Value = String> {
    proptest::collection::vec(wildcard_label(), 1..=4).prop_map(|labels| labels.join("."))
}

/// Labels drawn from a small IDN alphabet. The strategy avoids combining
/// marks and leading/trailing hyphens, which UTS-46 intentionally rejects.
fn idn_label() -> impl Strategy<Value = String> {
    let alphabet = vec!["a", "z", "é", "ü", "ß", "ñ", "ø", "中", "例", "δ", "о"];
    (
        proptest::collection::vec(prop::sample::select(alphabet.clone()), 1..=6),
        proptest::collection::vec(prop::sample::select(alphabet), 0..=2),
    )
        .prop_map(|(first, rest)| format!("{}{}", first.join(""), rest.join("")))
}

proptest! {
    #![proptest_config(property_config())]

    #[test]
    fn normalization_is_idempotent_and_never_panics(raw in "\\PC{0,80}") {
        if let Ok(domain) = NormalizedDomain::parse(&raw) {
            let again = NormalizedDomain::parse(domain.as_str())
                .expect("a canonical domain must always re-parse");
            prop_assert_eq!(again.as_str(), domain.as_str());
            prop_assert_eq!(again, domain);
        }
    }

    #[test]
    fn lowercase_and_one_trailing_dot_are_equivalent(domain in ascii_domain()) {
        let canonical = NormalizedDomain::parse(&domain).expect("generated ASCII domain parses");
        let upper_dot = format!("{}.", domain.to_ascii_uppercase());
        let equivalent = NormalizedDomain::parse(&upper_dot)
            .expect("uppercase with one trailing dot must parse");
        prop_assert_eq!(equivalent.as_str(), canonical.as_str());
    }

    #[test]
    fn idn_labels_round_trip_through_punycode(label in idn_label()) {
        let raw = format!("{label}.test");
        let ascii = idna::domain_to_ascii(&raw).expect("generated IDN label is valid");
        let parsed = NormalizedDomain::parse(&raw).expect("IDN input must normalize");
        prop_assert_eq!(parsed.as_str(), ascii.as_str());
        prop_assert!(parsed.as_str().is_ascii());

        // Decoding the canonical punycode and re-encoding must be stable.
        let unicode = idna::domain_to_unicode(parsed.as_str());
        let reencoded = idna::domain_to_ascii(&unicode.0).expect("decoded IDN re-encodes");
        prop_assert_eq!(reencoded, parsed.as_str().to_string());
    }

    #[test]
    fn wildcard_labels_are_preserved_exactly(domain in wildcard_domain()) {
        let parsed = NormalizedDomain::parse(&domain).expect("generated wildcard domain parses");
        let expected_wildcards = domain.split('.').any(|label| label == "*");
        prop_assert_eq!(parsed.has_wildcard_labels(), expected_wildcards);
        prop_assert_eq!(parsed.as_str(), domain.as_str());
        for label in domain.split('.') {
            if label == "*" {
                prop_assert!(
                    parsed.as_str().split('.').any(|canonical| canonical == "*"),
                    "the wildcard label must survive normalization"
                );
            }
        }
    }

    #[test]
    fn suffix_matching_is_reflexive_transitive_and_strict_only_for_children(
        parent in ascii_domain(),
        child in ascii_label(),
    ) {
        let parent = NormalizedDomain::parse(&parent).expect("parent parses");
        let subdomain = format!("{child}.{}", parent.as_str());
        let subdomain = NormalizedDomain::parse(&subdomain).expect("subdomain parses");

        prop_assert!(parent.matches_suffix(&parent));
        prop_assert!(matches_domain_suffix(parent.as_str(), parent.as_str()));
        prop_assert!(subdomain.matches_suffix(&parent));
        prop_assert!(subdomain.is_strict_subdomain_of(&parent));
        prop_assert!(!parent.is_strict_subdomain_of(&subdomain));
        prop_assert!(!parent.is_strict_subdomain_of(&parent));
        prop_assert!(!parent.matches_suffix(&subdomain));
        let doubled = format!("{}.{}", parent.as_str(), parent.as_str());
        prop_assert!(matches_domain_suffix(&doubled, parent.as_str()));
    }

    #[test]
    fn invalid_characters_are_rejected_without_panicking(
        label in ascii_label(),
        bad in prop::sample::select(vec![' ', '@', '#', '$', '%', '/', '\\', ':', '\0', '?']),
    ) {
        let raw = format!("{label}{bad}.example");
        let result = NormalizedDomain::parse(&raw);
        prop_assert!(result.is_err(), "invalid input must be rejected: {:?}", raw);
    }

    #[test]
    fn overlong_labels_are_rejected(label in "[a-z]{64,70}") {
        let nested = format!("{label}.example");
        prop_assert!(NormalizedDomain::parse(&label).is_err());
        prop_assert!(NormalizedDomain::parse(&nested).is_err());
    }
}

#[test]
fn root_matches_only_itself() {
    let root = NormalizedDomain::parse(".").expect("root parses");
    let example = NormalizedDomain::parse("example.com").expect("example parses");
    assert!(root.matches_suffix(&root));
    assert!(!example.matches_suffix(&root));
    assert!(!root.matches_suffix(&example));
}
