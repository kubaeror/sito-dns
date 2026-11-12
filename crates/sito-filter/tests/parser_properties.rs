//! Property tests for the ABP/hosts rule parser (WP-1.8).
//!
//! Iterations are bounded (96 / 64 cases) so the property lane stays fast. The
//! hostile-input unit tests in `src/parser.rs` cover exact budgets.

use proptest::prelude::*;
use sito_filter::{ParseError, ParseLimits, Rule, parse_rules, parse_rules_with_limits};

fn property_config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        max_shrink_iters: 2_000,
        ..ProptestConfig::default()
    }
}

fn ascii_domain() -> impl Strategy<Value = String> {
    proptest::collection::vec("[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?", 1..=3)
        .prop_map(|labels| labels.join("."))
}

/// One modifier in wire order and its expected canonical representation.
///
/// This is an independent oracle: it does not call `compute_canonical`. The
/// parser's canonical form sorts modifiers, sorts `$denyallow` domains, and
/// renders `$dnstype` names as numeric types, all of which are encoded here.
fn option() -> impl Strategy<Value = (&'static str, &'static str)> {
    prop::sample::select(vec![
        ("important", "important"),
        ("dnstype=A", "dnstype=1"),
        ("dnstype=A|AAAA", "dnstype=1|28"),
        ("client=1.2.3.4", "client=1.2.3.4"),
        (
            "denyallow=example.com|foo.test",
            "denyallow=example.com|foo.test",
        ),
        (
            "denyallow=foo.test|example.com",
            "denyallow=example.com|foo.test",
        ),
    ])
}

fn options() -> impl Strategy<Value = Vec<(&'static str, &'static str)>> {
    proptest::collection::vec(option(), 0..=3).prop_map(|options| {
        // A modifier key may appear at most once; the parser (correctly)
        // applies last-wins semantics for conflicting duplicates, which is not
        // the ordering property under test.
        let mut unique: Vec<(&'static str, &'static str)> = Vec::new();
        for (wire, canonical) in options {
            let key = wire.split('=').next().unwrap_or(wire);
            if !unique
                .iter()
                .any(|(seen, _)| seen.split('=').next().unwrap_or(seen) == key)
            {
                unique.push((wire, canonical));
            }
        }
        unique
    })
}

/// Builds a rule and the canonical form an independent oracle expects.
fn block_rule(
    domain: &str,
    options: &[(&'static str, &'static str)],
    allow: bool,
) -> (String, String) {
    let mut base = String::new();
    if allow {
        base.push_str("@@");
    }
    base.push_str("||");
    base.push_str(domain);
    base.push('^');

    if options.is_empty() {
        return (base.clone(), base);
    }

    let wire = format!(
        "{base}${}",
        options
            .iter()
            .map(|(wire, _)| *wire)
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut canonical_options: Vec<&str> =
        options.iter().map(|(_, canonical)| *canonical).collect();
    canonical_options.sort_unstable();
    let expected = format!("{base}${}", canonical_options.join(","));
    (wire, expected)
}

fn parse_one(content: &str) -> Rule {
    let (rules, skipped) =
        parse_rules_with_limits(content, "property", ParseLimits::default()).expect("parse");
    assert_eq!(rules.len(), 1, "expected exactly one rule in {content:?}");
    assert_eq!(skipped, 0, "no lines should be skipped in {content:?}");
    rules.into_iter().next().expect("one rule")
}

proptest! {
    #![proptest_config(property_config(96))]

    #[test]
    fn arbitrary_lines_never_panic(lines in proptest::collection::vec("[ -~]{0,200}", 0..=10)) {
        let content = lines.join("\n");
        let (rules, skipped) = parse_rules(&content, "property-arbitrary");
        let line_count = content.lines().count();
        prop_assert!(skipped <= line_count, "skipped {skipped} of {line_count} lines");
        prop_assert!(rules.len() <= line_count.max(1));
        // A second parse must be byte-for-byte deterministic.
        let (again, skipped_again) = parse_rules(&content, "property-arbitrary");
        prop_assert_eq!(skipped, skipped_again);
        prop_assert_eq!(rules.len(), again.len());
        for (left, right) in rules.iter().zip(&again) {
            prop_assert_eq!(left, right);
        }
    }

    #[test]
    fn parsed_canonical_matches_independent_oracle(
        domain in ascii_domain(),
        options in options(),
        allow in any::<bool>(),
    ) {
        let (wire, expected) = block_rule(&domain, &options, allow);
        let rule = parse_one(&wire);
        prop_assert_eq!(rule.canonical.as_str(), expected.as_str());
    }

    #[test]
    fn modifier_order_does_not_change_the_canonical_form(
        domain in ascii_domain(),
        options in options(),
    ) {
        if options.len() < 2 {
            return Ok(());
        }
        let (wire, expected) = block_rule(&domain, &options, false);
        let forward = parse_one(&wire);
        let mut reversed = options.clone();
        reversed.reverse();
        let (reversed_wire, reversed_expected) = block_rule(&domain, &reversed, false);
        let backward = parse_one(&reversed_wire);
        prop_assert_eq!(reversed_expected.as_str(), expected.as_str());
        prop_assert_eq!(forward.canonical.as_str(), expected.as_str());
        prop_assert_eq!(backward.canonical.as_str(), expected.as_str());
    }

    #[test]
    fn badfilter_suffix_is_recognised_and_excluded_from_the_canonical_form(
        domain in ascii_domain(),
        options in options(),
    ) {
        let (base_wire, expected) = block_rule(&domain, &options, false);
        let base = parse_one(&base_wire);
        // `$badfilter` must not appear in the canonical form even when the
        // base rule already has modifiers.
        let badfilter_wire = if options.is_empty() {
            format!("{base_wire}$badfilter")
        } else {
            format!("{base_wire},badfilter")
        };
        let badfilter = parse_one(&badfilter_wire);

        prop_assert!(!base.modifiers.badfilter);
        prop_assert!(badfilter.modifiers.badfilter);
        prop_assert_eq!(base.canonical.as_str(), expected.as_str());
        prop_assert_eq!(badfilter.canonical.as_str(), expected.as_str());
        prop_assert!(!badfilter.canonical.contains("badfilter"));
    }

    #[test]
    fn long_lines_are_skipped_without_materialising_a_rule(
        filler in "[a-z]{8193,9000}",
        domain in ascii_domain(),
    ) {
        let content = format!("{filler}\n||{domain}^");
        let (rules, skipped) = parse_rules_with_limits(
            &content,
            "property-long-line",
            ParseLimits::default(),
        )
        .expect("long lines below the byte budget are skipped, not rejected");
        prop_assert_eq!(skipped, 1);
        prop_assert_eq!(rules.len(), 1);
        let expected = format!("||{domain}^");
        prop_assert_eq!(rules[0].canonical.as_str(), expected.as_str());
    }
}

proptest! {
    #![proptest_config(property_config(64))]

    #[test]
    fn byte_budget_rejects_without_returning_partial_rules(
        domain in ascii_domain(),
        limit in 1usize..=8,
    ) {
        let content = format!("||{domain}^");
        let result = parse_rules_with_limits(
            &content,
            "property-byte-budget",
            ParseLimits::new(10, limit),
        );
        prop_assume!(content.len() > limit);
        let rejected = matches!(result, Err(ParseError::TooManyBytes { .. }));
        prop_assert!(rejected);
    }
}
