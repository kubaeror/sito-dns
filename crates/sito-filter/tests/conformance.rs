//! Conformance test suite for AdGuard Home filter syntax compatibility.
//!
//! Validates compliance against rule syntax, pattern types, modifiers,
//! precedence levels, and edge cases.

use hickory_proto::rr::RecordType;
use sito_core::client::ClientContext;
use sito_core::verdict::{BlockReason, RewriteAction, Verdict};
use sito_filter::engine::FilterSnapshot;
use sito_filter::parser::parse_rules;

fn default_client() -> ClientContext {
    ClientContext::new("192.168.1.100".parse().unwrap())
}

#[test]
fn test_conformance_exact_domains() {
    let rules = "
# Exact rules using |domain| syntax
|example.com|
|ads.tracker.net|
|sub.domain.co.uk|
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    assert!(matches!(
        snapshot.evaluate("example.com", RecordType::A, &client),
        Verdict::Block(BlockReason::Rule(_))
    ));
    assert!(matches!(
        snapshot.evaluate("ads.tracker.net", RecordType::A, &client),
        Verdict::Block(BlockReason::Rule(_))
    ));
    assert!(matches!(
        snapshot.evaluate("sub.domain.co.uk", RecordType::A, &client),
        Verdict::Block(BlockReason::Rule(_))
    ));

    // Subdomains should NOT match exact rules
    assert!(matches!(
        snapshot.evaluate("sub.example.com", RecordType::A, &client),
        Verdict::Allow(None)
    ));
    assert!(matches!(
        snapshot.evaluate("other.tracker.net", RecordType::A, &client),
        Verdict::Allow(None)
    ));
}

#[test]
fn test_conformance_domain_anchors() {
    let rules = "
||adservice.google.com^
||doubleclick.net^
||analytics.local^
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    // Direct domain match
    assert!(matches!(
        snapshot.evaluate("adservice.google.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("doubleclick.net", RecordType::A, &client),
        Verdict::Block(_)
    ));

    // Subdomain match
    assert!(matches!(
        snapshot.evaluate("sub.adservice.google.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("a.b.c.doubleclick.net", RecordType::A, &client),
        Verdict::Block(_)
    ));

    // Must NOT match superdomain or unrelated suffix
    assert!(matches!(
        snapshot.evaluate("google.com", RecordType::A, &client),
        Verdict::Allow(None)
    ));
    assert!(matches!(
        snapshot.evaluate("notdoubleclick.net", RecordType::A, &client),
        Verdict::Allow(None)
    ));
    assert!(matches!(
        snapshot.evaluate("doubleclick.net.evil.com", RecordType::A, &client),
        Verdict::Allow(None)
    ));
}

#[test]
fn test_conformance_prefix_and_exact_anchors() {
    let rules = "
|http://insecure-ads.
|malware.
|exact-domain.com|
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    assert!(matches!(
        snapshot.evaluate("malware.badsite.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("exact-domain.com", RecordType::A, &client),
        Verdict::Block(_)
    ));

    // exact-domain.com| does not match sub.exact-domain.com
    assert!(matches!(
        snapshot.evaluate("sub.exact-domain.com", RecordType::A, &client),
        Verdict::Allow(None)
    ));
    assert!(matches!(
        snapshot.evaluate("notmalware.com", RecordType::A, &client),
        Verdict::Allow(None)
    ));
}

#[test]
fn test_conformance_wildcards() {
    let rules = "
*bad*.tracker.com
ad.*.telemetry.org
*.telemetry-sink.net
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    assert!(matches!(
        snapshot.evaluate("verybadtracker.tracker.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("ad.us-east.telemetry.org", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("sub.telemetry-sink.net", RecordType::A, &client),
        Verdict::Block(_)
    ));

    // Negative tests
    assert!(matches!(
        snapshot.evaluate("good.tracker.com", RecordType::A, &client),
        Verdict::Allow(None)
    ));
}

#[test]
fn test_conformance_substrings() {
    let rules = "
telemetry-collector
suspicious-tracker
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    assert!(matches!(
        snapshot.evaluate("api.telemetry-collector.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("suspicious-tracker.org", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("safe-collector.com", RecordType::A, &client),
        Verdict::Allow(None)
    ));
}

#[test]
fn test_conformance_regex() {
    let rules = "
/^ad[0-9]+\\.tracking\\.org$/
/[0-9]{3}-telemetry\\.net/
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    assert!(matches!(
        snapshot.evaluate("ad123.tracking.org", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("server-456-telemetry.net", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("adabc.tracking.org", RecordType::A, &client),
        Verdict::Allow(None)
    ));
}

#[test]
fn test_conformance_hosts_format() {
    let rules = "
# Standard /etc/hosts format
0.0.0.0 hosts-ad1.com hosts-ad2.com
127.0.0.1 tracker-local.com
0.0.0.0 malicious.net # inline comment
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    assert!(matches!(
        snapshot.evaluate("hosts-ad1.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("hosts-ad2.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("tracker-local.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("malicious.net", RecordType::A, &client),
        Verdict::Block(_)
    ));
}

#[test]
fn test_conformance_allowlist_precedence() {
    let rules = "
||blocked.com^
@@||safe.blocked.com^
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    // blocked.com and general subdomains are blocked
    assert!(matches!(
        snapshot.evaluate("blocked.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("ads.blocked.com", RecordType::A, &client),
        Verdict::Block(_)
    ));

    // Exception unblocks safe.blocked.com and its children
    assert!(matches!(
        snapshot.evaluate("safe.blocked.com", RecordType::A, &client),
        Verdict::Allow(Some(_))
    ));
    assert!(matches!(
        snapshot.evaluate("sub.safe.blocked.com", RecordType::A, &client),
        Verdict::Allow(Some(_))
    ));
}

#[test]
fn test_conformance_important_modifier() {
    let rules = "
||important-blocked.com^$important
@@||important-blocked.com^

||standard-blocked.com^
@@||standard-blocked.com^$important
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    // 1. $important on block rule beats standard allowlist
    assert!(matches!(
        snapshot.evaluate("important-blocked.com", RecordType::A, &client),
        Verdict::Block(_)
    ));

    // 2. $important on allowlist beats standard blocklist
    assert!(matches!(
        snapshot.evaluate("standard-blocked.com", RecordType::A, &client),
        Verdict::Allow(Some(_))
    ));
}

#[test]
fn test_conformance_denyallow_modifier() {
    let rules = "
||denyallow-parent.com^$denyallow=allowed1.denyallow-parent.com|allowed2.denyallow-parent.com
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    // Parent is blocked
    assert!(matches!(
        snapshot.evaluate("denyallow-parent.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    // Unspecified subdomain is blocked
    assert!(matches!(
        snapshot.evaluate("bad.denyallow-parent.com", RecordType::A, &client),
        Verdict::Block(_)
    ));

    // Allowed subdomains are excluded from blocking
    assert!(matches!(
        snapshot.evaluate("allowed1.denyallow-parent.com", RecordType::A, &client),
        Verdict::Allow(None)
    ));
    assert!(matches!(
        snapshot.evaluate("sub.allowed1.denyallow-parent.com", RecordType::A, &client),
        Verdict::Allow(None)
    ));
    assert!(matches!(
        snapshot.evaluate("allowed2.denyallow-parent.com", RecordType::A, &client),
        Verdict::Allow(None)
    ));
}

#[test]
fn test_conformance_client_modifier() {
    let rules = "
||kids-block.com^$client=192.168.1.50
||guest-subnet-block.com^$client=10.0.0.0/24
||named-client-block.com^$client=laptop-charlie
||inverted-client-block.com^$client=~192.168.1.99
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);

    let client_ip_matched = ClientContext::new("192.168.1.50".parse().unwrap());
    let client_ip_unmatched = ClientContext::new("192.168.1.51".parse().unwrap());
    let client_cidr_matched = ClientContext::new("10.0.0.42".parse().unwrap());
    let client_cidr_unmatched = ClientContext::new("10.0.1.42".parse().unwrap());
    let client_named_matched =
        ClientContext::with_id("192.168.1.10".parse().unwrap(), "laptop-charlie");
    let client_named_unmatched =
        ClientContext::with_id("192.168.1.10".parse().unwrap(), "desktop-alice");
    let client_inv_excluded = ClientContext::new("192.168.1.99".parse().unwrap());
    let client_inv_included = ClientContext::new("192.168.1.88".parse().unwrap());

    // IP match
    assert!(matches!(
        snapshot.evaluate("kids-block.com", RecordType::A, &client_ip_matched),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("kids-block.com", RecordType::A, &client_ip_unmatched),
        Verdict::Allow(None)
    ));

    // CIDR match
    assert!(matches!(
        snapshot.evaluate(
            "guest-subnet-block.com",
            RecordType::A,
            &client_cidr_matched
        ),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate(
            "guest-subnet-block.com",
            RecordType::A,
            &client_cidr_unmatched
        ),
        Verdict::Allow(None)
    ));

    // Name match
    assert!(matches!(
        snapshot.evaluate(
            "named-client-block.com",
            RecordType::A,
            &client_named_matched
        ),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate(
            "named-client-block.com",
            RecordType::A,
            &client_named_unmatched
        ),
        Verdict::Allow(None)
    ));

    // Inverted IP match
    assert!(matches!(
        snapshot.evaluate(
            "inverted-client-block.com",
            RecordType::A,
            &client_inv_excluded
        ),
        Verdict::Allow(None)
    ));
    assert!(matches!(
        snapshot.evaluate(
            "inverted-client-block.com",
            RecordType::A,
            &client_inv_included
        ),
        Verdict::Block(_)
    ));
}

#[test]
fn test_conformance_dnstype_modifier() {
    let rules = "
||type-a-only.com^$dnstype=A
||type-https-only.com^$dnstype=HTTPS
||type-multiple.com^$dnstype=A|AAAA
||type-numeric.com^$dnstype=1
||type-inverted.com^$dnstype=~TXT
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    // A only
    assert!(matches!(
        snapshot.evaluate("type-a-only.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("type-a-only.com", RecordType::AAAA, &client),
        Verdict::Allow(None)
    ));

    // HTTPS only
    assert!(matches!(
        snapshot.evaluate("type-https-only.com", RecordType::HTTPS, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("type-https-only.com", RecordType::A, &client),
        Verdict::Allow(None)
    ));

    // Multiple A | AAAA
    assert!(matches!(
        snapshot.evaluate("type-multiple.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("type-multiple.com", RecordType::AAAA, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("type-multiple.com", RecordType::TXT, &client),
        Verdict::Allow(None)
    ));

    // Numeric (1 == A)
    assert!(matches!(
        snapshot.evaluate("type-numeric.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("type-numeric.com", RecordType::AAAA, &client),
        Verdict::Allow(None)
    ));

    // Inverted ~TXT
    assert!(matches!(
        snapshot.evaluate("type-inverted.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("type-inverted.com", RecordType::TXT, &client),
        Verdict::Allow(None)
    ));
}

#[test]
fn test_conformance_dnsrewrite_modifier() {
    let rules = "
||rewrite-ip.com^$dnsrewrite=NOERROR;A;10.20.30.40
||rewrite-ip-short.com^$dnsrewrite=1.2.3.4
||rewrite-cname.com^$dnsrewrite=cname.example.net
||rewrite-nxdomain.com^$dnsrewrite=NXDOMAIN;;
||rewrite-refused.com^$dnsrewrite=REFUSED;;
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    match snapshot.evaluate("rewrite-ip.com", RecordType::A, &client) {
        Verdict::Rewrite(RewriteAction::DnsRewrite {
            rcode,
            rtype,
            value,
        }) => {
            assert_eq!(rcode, "NOERROR");
            assert_eq!(rtype.as_deref(), Some("A"));
            assert_eq!(value.as_deref(), Some("10.20.30.40"));
        }
        other => panic!("expected Rewrite, got {other:?}"),
    }

    match snapshot.evaluate("rewrite-ip-short.com", RecordType::A, &client) {
        Verdict::Rewrite(RewriteAction::DnsRewrite {
            rcode,
            rtype,
            value,
        }) => {
            assert_eq!(rcode, "NOERROR");
            assert_eq!(rtype.as_deref(), Some("A"));
            assert_eq!(value.as_deref(), Some("1.2.3.4"));
        }
        other => panic!("expected Rewrite, got {other:?}"),
    }

    match snapshot.evaluate("rewrite-cname.com", RecordType::A, &client) {
        Verdict::Rewrite(RewriteAction::DnsRewrite {
            rcode,
            rtype,
            value,
        }) => {
            assert_eq!(rcode, "NOERROR");
            assert_eq!(rtype.as_deref(), Some("CNAME"));
            assert_eq!(value.as_deref(), Some("cname.example.net"));
        }
        other => panic!("expected Rewrite, got {other:?}"),
    }

    match snapshot.evaluate("rewrite-nxdomain.com", RecordType::A, &client) {
        Verdict::Rewrite(RewriteAction::DnsRewrite { rcode, .. }) => {
            assert_eq!(rcode, "NXDOMAIN");
        }
        other => panic!("expected Rewrite, got {other:?}"),
    }

    match snapshot.evaluate("rewrite-refused.com", RecordType::A, &client) {
        Verdict::Rewrite(RewriteAction::DnsRewrite { rcode, .. }) => {
            assert_eq!(rcode, "REFUSED");
        }
        other => panic!("expected Rewrite, got {other:?}"),
    }
}

#[test]
fn test_conformance_badfilter_modifier() {
    let rules = "
||bad-target.com^
||bad-target.com^$badfilter

||keep-target.com^
||different-target.com^$badfilter
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    // bad-target.com was deactivated by its identical rule with $badfilter
    assert!(matches!(
        snapshot.evaluate("bad-target.com", RecordType::A, &client),
        Verdict::Allow(None)
    ));

    // keep-target.com remains active
    assert!(matches!(
        snapshot.evaluate("keep-target.com", RecordType::A, &client),
        Verdict::Block(_)
    ));
}

#[test]
fn test_conformance_corpus_200_rules() {
    use std::fmt::Write;
    let mut rules_src = String::new();
    let mut test_domains = Vec::new();

    // 100 Domain anchor rules (Trie)
    for i in 0..100 {
        let _ = writeln!(rules_src, "||domain-test-{i}.net^");
        test_domains.push((
            format!("sub.domain-test-{i}.net"),
            RecordType::A,
            true, // should block
        ));
    }

    // 50 Hosts entries (Exact HashSet)
    for i in 0..25 {
        let _ = writeln!(rules_src, "0.0.0.0 hostentry-{i}-a.net hostentry-{i}-b.net");
        test_domains.push((format!("hostentry-{i}-a.net"), RecordType::A, true));
        test_domains.push((format!("hostentry-{i}-b.net"), RecordType::A, true));
    }

    // 30 Substring rules (Aho-Corasick)
    for i in 0..30 {
        let _ = writeln!(rules_src, "substring-{i}-token");
        test_domains.push((
            format!("host-substring-{i}-token.info"),
            RecordType::A,
            true,
        ));
    }

    // 15 Prefix rules
    for i in 0..15 {
        let _ = writeln!(rules_src, "|prefix-tag-{i}.");
        test_domains.push((format!("prefix-tag-{i}.example.co"), RecordType::A, true));
    }

    // 5 Wildcard rules
    for i in 0..5 {
        let _ = writeln!(rules_src, "*wildcard-tag-{i}*.org");
        test_domains.push((
            format!("analytics.wildcard-tag-{i}-beta.org"),
            RecordType::A,
            true,
        ));
    }

    // 5 Regex rules
    for i in 0..5 {
        let _ = writeln!(rules_src, "/^regex-{i}\\.com$/");
        test_domains.push((format!("regex-{i}.com"), RecordType::A, true));
    }

    // Allowlist overrides for the first 10 domain rules
    for i in 0..10 {
        let _ = writeln!(rules_src, "@@||domain-test-{i}.net^");
    }

    // Unrelated safe domains (should not block)
    for i in 100..120 {
        test_domains.push((
            format!("completely-unrelated-safe-domain-{i}.com"),
            RecordType::A,
            false,
        ));
    }

    let snapshot = FilterSnapshot::compile(parse_rules(&rules_src, "corpus").0);
    let client = default_client();

    assert!(
        snapshot.rule_count >= 200,
        "Rule count: {}",
        snapshot.rule_count
    );

    // Verify allowlist overrides
    for i in 0..10 {
        let domain = format!("sub.domain-test-{i}.net");
        assert!(
            matches!(
                snapshot.evaluate(&domain, RecordType::A, &client),
                Verdict::Allow(Some(_))
            ),
            "Domain {domain} should be allowed by @@ exception"
        );
    }

    // Verify remaining domain anchors
    for i in 10..100 {
        let domain = format!("sub.domain-test-{i}.net");
        assert!(
            matches!(
                snapshot.evaluate(&domain, RecordType::A, &client),
                Verdict::Block(_)
            ),
            "Domain {domain} should be blocked"
        );
    }

    // Verify rest of test domains
    for (domain, rtype, should_block) in test_domains {
        if domain.starts_with("sub.domain-test-") {
            continue;
        }
        let verdict = snapshot.evaluate(&domain, rtype, &client);
        if should_block {
            assert!(
                matches!(verdict, Verdict::Block(_)),
                "Domain {domain} should be blocked"
            );
        } else {
            assert!(
                matches!(verdict, Verdict::Allow(None)),
                "Domain {domain} should be allowed"
            );
        }
    }
}
