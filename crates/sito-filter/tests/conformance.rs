//! Conformance test suite for AdGuard Home filter syntax compatibility.
//!
//! Validates compliance against rule syntax, pattern types, modifiers,
//! precedence levels, and edge cases.

use hickory_proto::rr::RecordType;
use sito_core::client::ClientContext;
use sito_core::verdict::{BlockReason, RewriteAction, Verdict};
use sito_filter::DnsRewriteRule;
use sito_filter::engine::FilterSnapshot;
use sito_filter::parser::{parse_line, parse_rules};

fn default_client() -> ClientContext {
    ClientContext::new("192.168.1.100".parse().unwrap())
}

/// Collects the effective rewrite list for `domain` exactly like the DNS
/// pipeline does: all matching rewrites, with exception cancellations applied.
fn effective_rewrites(
    snapshot: &FilterSnapshot,
    domain: &str,
    rtype: RecordType,
    client: &ClientContext,
) -> Vec<DnsRewriteRule> {
    let mut allow = Vec::new();
    let mut block = Vec::new();
    snapshot
        .allowlist
        .collect_candidates(domain, &snapshot.interner, &mut allow);
    snapshot
        .blocklist
        .collect_candidates(domain, &snapshot.interner, &mut block);
    let mut rules = snapshot.collect_rewrite_rules(domain, rtype, client, &block, false);
    let mut cancellations =
        snapshot.collect_rewrite_cancellations(domain, rtype, client, &allow, false);
    // `$important` exceptions outrank standard rewrites.
    cancellations
        .extend(snapshot.collect_rewrite_cancellations(domain, rtype, client, &allow, true));
    sito_filter::apply_rewrite_cancellations(&mut rules, &cancellations);
    rules
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
        ClientContext::new("192.168.1.10".parse().unwrap()).with_client_name("laptop-charlie");
    let client_named_unmatched =
        ClientContext::new("192.168.1.10".parse().unwrap()).with_client_name("desktop-alice");
    // Wire-claimed identity must not satisfy `$client=`: only the registry's
    // resolved name/group/MAC are trusted.
    let client_spoofed_by_id =
        ClientContext::with_id("192.168.1.10".parse().unwrap(), "laptop-charlie");
    let client_spoofed_by_sni =
        ClientContext::with_sni("192.168.1.10".parse().unwrap(), "laptop-charlie");
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
    assert!(matches!(
        snapshot.evaluate(
            "named-client-block.com",
            RecordType::A,
            &client_spoofed_by_id
        ),
        Verdict::Allow(None)
    ));
    assert!(matches!(
        snapshot.evaluate(
            "named-client-block.com",
            RecordType::A,
            &client_spoofed_by_sni
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

// --- AdGuard semantics regressions (audit 6, WP-3.5) ---

#[test]
fn test_conformance_bare_domain_blocks_exact_host_only() {
    // AdGuard: `example.org` blocks example.org but not its subdomains.
    let snapshot = FilterSnapshot::compile(parse_rules("example.org\n", "conformance").0);
    let client = default_client();
    assert!(matches!(
        snapshot.evaluate("example.org", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("www.example.org", RecordType::A, &client),
        Verdict::Allow(None)
    ));
}

#[test]
fn test_conformance_path_rule_is_inert_at_dns_level() {
    // `||example.com/path` cannot match a DNS query and must not be widened
    // into a domain block.
    let snapshot = FilterSnapshot::compile(parse_rules("||path-rule.example/\n", "conformance").0);
    let client = default_client();
    assert!(matches!(
        snapshot.evaluate("path-rule.example", RecordType::A, &client),
        Verdict::Allow(None)
    ));
    assert!(matches!(
        snapshot.evaluate("sub.path-rule.example", RecordType::A, &client),
        Verdict::Allow(None)
    ));
}

#[test]
fn test_conformance_denyallow_on_exception_rule() {
    // `@@*$denyallow=blocked.example` allows everything except
    // blocked.example; the denyallow domain must stay blocked.
    let rules = "
@@*$denyallow=blocked.example
||blocked.example^
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();
    assert!(
        matches!(
            snapshot.evaluate("blocked.example", RecordType::A, &client),
            Verdict::Block(_)
        ),
        "denyallow domains must not be allowed by the exception"
    );
    assert!(matches!(
        snapshot.evaluate("other.example", RecordType::A, &client),
        Verdict::Allow(_)
    ));
    assert!(matches!(
        snapshot.evaluate("sub.blocked.example", RecordType::A, &client),
        Verdict::Block(_)
    ));
}

#[test]
fn test_conformance_dnsrewrite_ptr_and_txt() {
    // PTR and TXT rewrites must both parse and produce a rewrite verdict; the
    // DNS pipeline synthesizes the corresponding records.
    let rules = "
||4.3.2.1.in-addr.arpa^$dnsrewrite=NOERROR;PTR;printer.lan.
||txt-rewrite.example^$dnsrewrite=NOERROR;TXT;hello;world
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    match snapshot.evaluate("4.3.2.1.in-addr.arpa", RecordType::PTR, &client) {
        Verdict::Rewrite(RewriteAction::DnsRewrite {
            rcode,
            rtype,
            value,
        }) => {
            assert_eq!(rcode, "NOERROR");
            assert_eq!(rtype.as_deref(), Some("PTR"));
            assert_eq!(value.as_deref(), Some("printer.lan."));
        }
        other => panic!("expected PTR rewrite, got {other:?}"),
    }

    match snapshot.evaluate("txt-rewrite.example", RecordType::TXT, &client) {
        Verdict::Rewrite(RewriteAction::DnsRewrite {
            rcode,
            rtype,
            value,
        }) => {
            assert_eq!(rcode, "NOERROR");
            assert_eq!(rtype.as_deref(), Some("TXT"));
            // Remaining semicolons belong to the TXT data (they are not a
            // second record separator).
            assert_eq!(value.as_deref(), Some("hello;world"));
        }
        other => panic!("expected TXT rewrite, got {other:?}"),
    }
}

#[test]
fn test_conformance_dnsrewrite_unsupported_types_rejected() {
    // Types the pipeline cannot synthesize are rejected at parse time instead
    // of being accepted and silently answered as NODATA.
    assert!(
        parse_line(
            "||ns-rewrite.example^$dnsrewrite=NOERROR;NS;ns.example.net",
            "conformance",
            1
        )
        .is_none()
    );
    assert!(
        parse_line(
            "||mx-rewrite.example^$dnsrewrite=NOERROR;MX;mail.example.net",
            "conformance",
            2
        )
        .is_none()
    );
    // The supported set still parses.
    assert!(
        parse_line(
            "||ptr-rewrite.example^$dnsrewrite=NOERROR;PTR;host.example.net",
            "conformance",
            3
        )
        .is_some()
    );
    assert!(
        parse_line(
            "||txt-rewrite.example^$dnsrewrite=NOERROR;TXT;data",
            "conformance",
            4
        )
        .is_some()
    );
}

#[test]
fn test_conformance_dnsrewrite_aggregates_all_matching_values() {
    // AdGuard returns every A/AAAA value contributed by matching rewrite
    // rules, not just the first one.
    let rules = "
||multi-rewrite.example^$dnsrewrite=1.2.3.4
||multi-rewrite.example^$dnsrewrite=5.6.7.8
||multi-rewrite.example^$dnsrewrite=NOERROR;AAAA;2001:db8::1
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    assert!(matches!(
        snapshot.evaluate("multi-rewrite.example", RecordType::A, &client),
        Verdict::Rewrite(_)
    ));

    let rewrites = effective_rewrites(&snapshot, "multi-rewrite.example", RecordType::A, &client);
    let values: Vec<&str> = rewrites
        .iter()
        .filter_map(|rule| rule.value.as_deref())
        .collect();
    assert_eq!(rewrites.len(), 3, "all matching rewrites must be kept");
    assert!(values.contains(&"1.2.3.4"));
    assert!(values.contains(&"5.6.7.8"));
    assert!(values.contains(&"2001:db8::1"));
}

#[test]
fn test_conformance_dnsrewrite_bare_exception_cancels_all() {
    // `@@||x^$dnsrewrite` cancels every matching rewrite instead of acting as
    // an allow verdict.
    let rules = "
||cancel-all.example^$dnsrewrite=1.2.3.4
@@||cancel-all.example^$dnsrewrite
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    // The exception is not an allow verdict: the rewrite rule still matches.
    assert!(matches!(
        snapshot.evaluate("cancel-all.example", RecordType::A, &client),
        Verdict::Rewrite(_)
    ));
    assert!(
        effective_rewrites(&snapshot, "cancel-all.example", RecordType::A, &client).is_empty(),
        "bare exception must cancel every rewrite"
    );

    // A cancellation-only exception must not unblock a plain blocking rule.
    let plain = "
||plain-block.example^
@@||plain-block.example^$dnsrewrite
";
    let snapshot = FilterSnapshot::compile(parse_rules(plain, "conformance").0);
    assert!(matches!(
        snapshot.evaluate("plain-block.example", RecordType::A, &client),
        Verdict::Block(_)
    ));
}

#[test]
fn test_conformance_dnsrewrite_exception_cancels_specific_value() {
    // `@@||x^$dnsrewrite=value` cancels only the identical rewrite.
    let rules = "
||cancel-one.example^$dnsrewrite=1.2.3.4
||cancel-one.example^$dnsrewrite=5.6.7.8
@@||cancel-one.example^$dnsrewrite=1.2.3.4
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    let rewrites = effective_rewrites(&snapshot, "cancel-one.example", RecordType::A, &client);
    assert_eq!(rewrites.len(), 1, "only the named rewrite is cancelled");
    assert_eq!(rewrites[0].rtype.as_deref(), Some("A"));
    assert_eq!(rewrites[0].value.as_deref(), Some("5.6.7.8"));

    // The explicit rcode;rtype;value form is equivalent.
    let explicit = "
||cancel-explicit.example^$dnsrewrite=NOERROR;A;1.2.3.4
||cancel-explicit.example^$dnsrewrite=5.6.7.8
@@||cancel-explicit.example^$dnsrewrite=NOERROR;A;1.2.3.4
";
    let snapshot = FilterSnapshot::compile(parse_rules(explicit, "conformance").0);
    let rewrites = effective_rewrites(&snapshot, "cancel-explicit.example", RecordType::A, &client);
    assert_eq!(rewrites.len(), 1);
    assert_eq!(rewrites[0].value.as_deref(), Some("5.6.7.8"));
}

#[test]
fn test_rewrite_cancellation_bare_vs_explicit_noerror() {
    // The bare form cancels every rewrite for the owner.
    let bare = "
||bare-cancel.example^$dnsrewrite=1.2.3.4
||bare-cancel.example^$dnsrewrite=5.6.7.8
@@||bare-cancel.example^$dnsrewrite
";
    let snapshot = FilterSnapshot::compile(parse_rules(bare, "conformance").0);
    let client = default_client();
    assert!(
        effective_rewrites(&snapshot, "bare-cancel.example", RecordType::A, &client).is_empty(),
        "a bare exception must cancel every rewrite"
    );

    // An explicit `=NOERROR` only cancels an identical NODATA rewrite, so
    // valued rewrites survive it.
    let explicit = "
||explicit-noerror.example^$dnsrewrite=1.2.3.4
@@||explicit-noerror.example^$dnsrewrite=NOERROR
";
    let snapshot = FilterSnapshot::compile(parse_rules(explicit, "conformance").0);
    let rewrites = effective_rewrites(
        &snapshot,
        "explicit-noerror.example",
        RecordType::A,
        &client,
    );
    assert_eq!(
        rewrites.len(),
        1,
        "an explicit NOERROR must not cancel a valued rewrite"
    );
    assert_eq!(rewrites[0].value.as_deref(), Some("1.2.3.4"));

    // It does cancel the identical NODATA rewrite.
    let nodata = "
||explicit-nodata.example^$dnsrewrite=NOERROR
@@||explicit-nodata.example^$dnsrewrite=NOERROR
";
    let snapshot = FilterSnapshot::compile(parse_rules(nodata, "conformance").0);
    assert!(
        effective_rewrites(&snapshot, "explicit-nodata.example", RecordType::A, &client).is_empty(),
        "an explicit NOERROR must cancel an identical NODATA rewrite"
    );
}

#[test]
fn test_rewrite_cancellation_value_scoped() {
    // A valued exception cancels only the identical rewrite and leaves the
    // other values for the same owner intact.
    let rules = "
||value-scoped.example^$dnsrewrite=1.2.3.4
||value-scoped.example^$dnsrewrite=5.6.7.8
@@||value-scoped.example^$dnsrewrite=1.2.3.4
";
    let snapshot = FilterSnapshot::compile(parse_rules(rules, "conformance").0);
    let client = default_client();

    let rewrites = effective_rewrites(&snapshot, "value-scoped.example", RecordType::A, &client);
    assert_eq!(rewrites.len(), 1);
    assert_eq!(rewrites[0].value.as_deref(), Some("5.6.7.8"));
}

#[test]
fn test_conformance_client_quoted_names_and_escapes() {
    // AdGuard allows single/double quotes and `\` escapes for client names
    // containing spaces, commas, pipes and quotes. `~` stays outside quotes.
    let rules = r#"
||quoted-space.example^$client='Frank\'s laptop'
||quoted-comma.example^$client="Mary's, John's, and Boris's laptops"
||quoted-pipe.example^$client='Device|With|Pipes'
||quoted-negated.example^$client=~'Mary\'s\, John\'s\, and Boris\'s laptops'
"#;
    let (parsed, skipped) = parse_rules(rules, "conformance");
    assert_eq!(skipped, 0, "quoted client rules must not be dropped");
    let snapshot = FilterSnapshot::compile(parsed);

    let frank =
        ClientContext::new("192.168.1.10".parse().unwrap()).with_client_name("Frank's laptop");
    let mary = ClientContext::new("192.168.1.11".parse().unwrap())
        .with_client_name("Mary's, John's, and Boris's laptops");
    let pipes =
        ClientContext::new("192.168.1.12".parse().unwrap()).with_client_name("Device|With|Pipes");
    let other = ClientContext::new("192.168.1.13".parse().unwrap()).with_client_name("other");

    assert!(matches!(
        snapshot.evaluate("quoted-space.example", RecordType::A, &frank),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("quoted-space.example", RecordType::A, &other),
        Verdict::Allow(None)
    ));

    assert!(matches!(
        snapshot.evaluate("quoted-comma.example", RecordType::A, &mary),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("quoted-comma.example", RecordType::A, &other),
        Verdict::Allow(None)
    ));

    assert!(matches!(
        snapshot.evaluate("quoted-pipe.example", RecordType::A, &pipes),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("quoted-pipe.example", RecordType::A, &other),
        Verdict::Allow(None)
    ));

    // Inverted quoted name: excluded for Mary, applies to everyone else.
    assert!(matches!(
        snapshot.evaluate("quoted-negated.example", RecordType::A, &mary),
        Verdict::Allow(None)
    ));
    assert!(matches!(
        snapshot.evaluate("quoted-negated.example", RecordType::A, &other),
        Verdict::Block(_)
    ));

    // Quoting must not break CIDR/IP/negation parsing.
    let basic = "||cidr-quoted.example^$client=10.0.0.0/8|~10.1.2.99\n";
    let snapshot = FilterSnapshot::compile(parse_rules(basic, "conformance").0);
    let cidr = ClientContext::new("10.1.2.3".parse().unwrap());
    let negated = ClientContext::new("10.1.2.99".parse().unwrap());
    let outside = ClientContext::new("172.16.0.1".parse().unwrap());
    assert!(matches!(
        snapshot.evaluate("cidr-quoted.example", RecordType::A, &cidr),
        Verdict::Block(_)
    ));
    assert!(matches!(
        snapshot.evaluate("cidr-quoted.example", RecordType::A, &negated),
        Verdict::Allow(None)
    ));
    assert!(matches!(
        snapshot.evaluate("cidr-quoted.example", RecordType::A, &outside),
        Verdict::Allow(None)
    ));
}

#[test]
fn test_conformance_dnsrewrite_important_exception_cancels_standard_rewrite() {
    // An `$important` cancellation-only exception outranks a standard rewrite.
    let rules = "
||important-cancel.example^$dnsrewrite=1.2.3.4
@@||important-cancel.example^$dnsrewrite,important
";
    let (parsed, skipped) = parse_rules(rules, "conformance");
    assert_eq!(skipped, 0);
    let snapshot = FilterSnapshot::compile(parsed);
    let client = default_client();

    assert!(matches!(
        snapshot.evaluate("important-cancel.example", RecordType::A, &client),
        Verdict::Rewrite(_)
    ));
    assert!(
        effective_rewrites(
            &snapshot,
            "important-cancel.example",
            RecordType::A,
            &client
        )
        .is_empty(),
        "an important exception must cancel a standard rewrite"
    );
}
