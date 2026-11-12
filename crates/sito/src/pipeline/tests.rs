#![cfg(test)]

use super::*;
use sito_core::DnssecMode;
use sito_core::client::ClientContext;
use sito_core::config::FilteringConfig;

/// A fetcher that never answers, simulating a black-holed DS/DNSKEY
/// lookup. The deadline wrapper must not wait for it indefinitely.
struct BlockingFetcher;

#[async_trait::async_trait]
impl sito_core::DnssecKeyFetcher for BlockingFetcher {
    async fn query(
        &self,
        _name: &Name,
        _rtype: RecordType,
    ) -> Result<Message, sito_core::error::UpstreamError> {
        std::future::pending::<Result<Message, sito_core::error::UpstreamError>>().await
    }
}

/// Builds an answer with eight CNAME hops and one relevant (unverifiable)
/// RRSIG, so validation reaches the blocking chain fetch.
fn cname_chain_needing_key_fetch(now: u32) -> Message {
    use hickory_proto::dnssec::Algorithm;
    use hickory_proto::dnssec::rdata::{RRSIG, SigInput};
    use hickory_proto::op::Query;
    use hickory_proto::rr::SerialNumber;

    let origin = Name::from_str("timeout.example.").unwrap();
    let qname = Name::from_str("h0.timeout.example.").unwrap();
    let mut response = Message::new(7, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::A));
    for hop in 0..8 {
        let current = Name::from_str(&format!("h{hop}.timeout.example.")).unwrap();
        let next = Name::from_str(&format!("h{}.timeout.example.", hop + 1)).unwrap();
        response
            .answers
            .push(Record::from_rdata(current, 300, RData::CNAME(CNAME(next))));
    }
    response.answers.push(Record::from_rdata(
        qname,
        300,
        RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::RRSIG(
            RRSIG::from_sig(
                SigInput {
                    type_covered: RecordType::CNAME,
                    algorithm: Algorithm::ECDSAP256SHA256,
                    num_labels: 3,
                    original_ttl: 300,
                    sig_expiration: SerialNumber::new(now.saturating_add(300)),
                    sig_inception: SerialNumber::new(now.saturating_sub(300)),
                    key_tag: 1234,
                    signer_name: origin,
                },
                vec![0u8; 64],
            ),
        )),
    ));
    response
}

#[tokio::test]
async fn test_dnssec_validation_deadline_fails_closed_in_validate_mode() {
    let validator = DnssecValidator::new(sito_dnssec::DnssecMode::Validate, Vec::new());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let mut response = cname_chain_needing_key_fetch(now);

    let outcome = validate_dnssec_with_deadline(
        &validator,
        &mut response,
        Some("blocked"),
        now,
        &BlockingFetcher,
        std::time::Duration::from_millis(25),
    )
    .await;

    assert!(
        matches!(outcome, sito_dnssec::ValidationOutcome::Bogus { .. }),
        "a blocked key fetch must not produce an unvalidated answer: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
    assert_eq!(response.answers.len(), 0);
}

#[tokio::test]
async fn test_dnssec_validation_deadline_keeps_log_only_response() {
    let validator = DnssecValidator::new(sito_dnssec::DnssecMode::LogOnly, Vec::new());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let mut response = cname_chain_needing_key_fetch(now);

    let outcome = validate_dnssec_with_deadline(
        &validator,
        &mut response,
        Some("blocked"),
        now,
        &BlockingFetcher,
        std::time::Duration::from_millis(25),
    )
    .await;

    assert_eq!(outcome, sito_dnssec::ValidationOutcome::Indeterminate);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(!response.metadata.authentic_data);
    assert!(!response.answers.is_empty(), "log-only keeps the response");
}

fn rewrite_rule(rcode: &str, rtype: Option<&str>, value: Option<&str>) -> DnsRewriteRule {
    DnsRewriteRule {
        rcode: rcode.to_string(),
        rtype: rtype.map(str::to_string),
        value: value.map(str::to_string),
        bare: false,
    }
}

/// Builds a case-preserving name. Hickory's `Name::from_str` applies IDNA and
/// lowercases labels, which would hide a stored-vs-client question-case
/// regression; wire labels preserve the bytes the client sent.
fn mixed_name(name: &str) -> Name {
    let labels: Vec<Vec<u8>> = name
        .trim_end_matches('.')
        .split('.')
        .map(|label| label.as_bytes().to_vec())
        .collect();
    let mut name = Name::from_labels(labels).unwrap();
    name.set_fqdn(true);
    name
}

fn rewrite_query(name: &str, qtype: RecordType) -> Message {
    use hickory_proto::op::Query;
    let mut query = Message::new(42, MessageType::Query, OpCode::Query);
    query
        .queries
        .push(Query::query(Name::from_str(name).unwrap(), qtype));
    query
}

#[test]
fn test_make_rewrite_response_synthesizes_ptr_txt_and_aggregates() {
    let long_txt = "x".repeat(300);
    let rules = vec![
        rewrite_rule("NOERROR", Some("A"), Some("10.0.0.1")),
        rewrite_rule("NOERROR", Some("A"), Some("10.0.0.2")),
        rewrite_rule("NOERROR", Some("PTR"), Some("printer.lan.")),
        rewrite_rule("NOERROR", Some("TXT"), Some("hello")),
        rewrite_rule("NOERROR", Some("TXT"), Some(&long_txt)),
    ];

    // A questions aggregate every A value and ignore PTR/TXT rewrites.
    let query = rewrite_query("rewrite.example.", RecordType::A);
    let resp = make_rewrite_response(&query, &rules, 7);
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp.metadata.id, 7);
    assert_eq!(
        resp.answers.len(),
        2,
        "only the two A rewrites are synthesized for an A question"
    );
    let a_values: Vec<_> = resp
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    assert_eq!(
        a_values,
        vec![
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            std::net::Ipv4Addr::new(10, 0, 0, 2)
        ]
    );

    // PTR questions only receive the PTR rewrite.
    let query = rewrite_query("4.3.2.1.in-addr.arpa.", RecordType::PTR);
    let resp = make_rewrite_response(&query, &rules, 8);
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1, "only the PTR rewrite applies");
    assert!(
        matches!(&resp.answers[0].data, RData::PTR(ptr) if ptr.0.to_ascii().trim_end_matches('.') == "printer.lan"),
        "missing PTR record: {:?}",
        resp.answers
    );

    // TXT questions receive the TXT rewrites with 255-byte chunking.
    let query = rewrite_query("txt.example.", RecordType::TXT);
    let resp = make_rewrite_response(&query, &rules, 9);
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    let txt_chunk_counts: Vec<usize> = resp
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::TXT(txt) => Some(txt.txt_data.len()),
            _ => None,
        })
        .collect();
    assert_eq!(
        txt_chunk_counts,
        vec![1, 2],
        "long TXT is split at 255 bytes"
    );
}

#[test]
fn test_make_rewrite_response_matches_query_type() {
    let rules = vec![rewrite_rule("NOERROR", Some("A"), Some("10.0.0.1"))];

    let query = rewrite_query("host.example.", RecordType::A);
    let resp = make_rewrite_response(&query, &rules, 1);
    assert_eq!(resp.answers.len(), 1, "an A rule answers an A question");

    for qtype in [RecordType::AAAA, RecordType::TXT, RecordType::PTR] {
        let query = rewrite_query("host.example.", qtype);
        let resp = make_rewrite_response(&query, &rules, 2);
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NoError,
            "{qtype:?} must be NODATA, not an error"
        );
        assert!(
            resp.answers.is_empty(),
            "{qtype:?} must be NODATA for an A-only rewrite: {:?}",
            resp.answers
        );
    }
}

#[test]
fn test_make_rewrite_response_aggregates_same_type_only() {
    let rules = vec![
        rewrite_rule("NOERROR", Some("A"), Some("10.0.0.1")),
        rewrite_rule("NOERROR", Some("A"), Some("10.0.0.2")),
        rewrite_rule("NOERROR", Some("AAAA"), Some("2001:db8::1")),
        rewrite_rule("NOERROR", Some("TXT"), Some("ignored")),
    ];

    let query = rewrite_query("multi.example.", RecordType::A);
    let resp = make_rewrite_response(&query, &rules, 3);
    assert_eq!(resp.answers.len(), 2, "only the two A rules aggregate");
    assert!(
        resp.answers
            .iter()
            .all(|record| matches!(record.data, RData::A(_))),
        "an A question must not receive AAAA/TXT records: {:?}",
        resp.answers
    );

    let query = rewrite_query("multi.example.", RecordType::AAAA);
    let resp = make_rewrite_response(&query, &rules, 4);
    assert_eq!(resp.answers.len(), 1);
    assert!(matches!(resp.answers[0].data, RData::AAAA(_)));
}

#[test]
fn test_make_rewrite_response_cname_answers_any_type() {
    let rules = vec![rewrite_rule(
        "NOERROR",
        Some("CNAME"),
        Some("target.example.net."),
    )];

    for qtype in [
        RecordType::A,
        RecordType::AAAA,
        RecordType::TXT,
        RecordType::PTR,
    ] {
        let query = rewrite_query("alias.example.", qtype);
        let resp = make_rewrite_response(&query, &rules, 5);
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NoError,
            "{qtype:?}"
        );
        assert_eq!(
            resp.answers.len(),
            1,
            "a CNAME rewrite answers any question type ({qtype:?})"
        );
        assert!(
            matches!(&resp.answers[0].data, RData::CNAME(cname) if cname.0.to_ascii().trim_end_matches('.') == "target.example.net"),
            "expected CNAME answer for {qtype:?}: {:?}",
            resp.answers
        );
    }
}

#[test]
fn test_make_rewrite_response_rcode_wins_over_records() {
    let query = rewrite_query("rewrite.example.", RecordType::A);
    let rules = vec![
        rewrite_rule("NOERROR", Some("A"), Some("1.2.3.4")),
        rewrite_rule("NXDOMAIN", None, None),
    ];
    let resp = make_rewrite_response(&query, &rules, 9);
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        resp.answers.is_empty(),
        "NXDOMAIN rewrite must not carry answers: {:?}",
        resp.answers
    );

    // A non-NOERROR rcode wins even when no record matches the qtype.
    let query = rewrite_query("rewrite.example.", RecordType::AAAA);
    let resp = make_rewrite_response(&query, &rules, 10);
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(resp.answers.len(), 0);
}

#[tokio::test]
async fn test_pipeline_aggregates_and_cancels_dnsrewrite() {
    use std::sync::atomic::Ordering;

    let mut config = Config::default();
    // This test exercises rewrite aggregation/cancellation, not DNSSEC.
    // Keep validation off so the D-05 delegation probe does not add
    // upstream DNSKEY/DS lookups to the call counts asserted below.
    config.dns.dnssec.validate = false;
    config.filtering.custom_rules = vec![
        "||rewrite-pipeline.example^$dnsrewrite=1.2.3.4".to_string(),
        "||rewrite-pipeline.example^$dnsrewrite=5.6.7.8".to_string(),
        "||rewrite-cancelled.example^$dnsrewrite=1.2.3.4".to_string(),
        "@@||rewrite-cancelled.example^$dnsrewrite".to_string(),
        "||rewrite-important-cancelled.example^$dnsrewrite=9.9.9.9".to_string(),
        "@@||rewrite-important-cancelled.example^$dnsrewrite,important".to_string(),
    ];
    let (pipeline, calls, temp_dir) = test_pipeline(config).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());

    // Both A values are returned in one synthesized answer.
    let resp = pipeline
        .handle(
            rewrite_query("rewrite-pipeline.example.", RecordType::A),
            client.clone(),
        )
        .await
        .unwrap();
    let a_values: Vec<_> = resp
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    assert_eq!(
        a_values,
        vec![
            std::net::Ipv4Addr::new(1, 2, 3, 4),
            std::net::Ipv4Addr::new(5, 6, 7, 8)
        ]
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a rewrite must not query upstream"
    );

    // The bare `@@...$dnsrewrite` exception cancels the rewrite and the
    // query is resolved normally.
    let resp = pipeline
        .handle(
            rewrite_query("rewrite-cancelled.example.", RecordType::A),
            client.clone(),
        )
        .await
        .unwrap();
    assert_eq!(resp.answers.len(), 1);
    assert!(
        matches!(resp.answers[0].data, RData::A(A(ip)) if ip == std::net::Ipv4Addr::new(203, 0, 113, 9))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // An `$important` cancellation-only exception outranks a standard
    // rewrite, so the query also resolves upstream.
    let resp = pipeline
        .handle(
            rewrite_query("rewrite-important-cancelled.example.", RecordType::A),
            client,
        )
        .await
        .unwrap();
    assert_eq!(resp.answers.len(), 1);
    assert!(
        matches!(resp.answers[0].data, RData::A(A(ip)) if ip == std::net::Ipv4Addr::new(203, 0, 113, 9))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_pipeline_rewrite_matches_query_type_without_upstream() {
    use std::sync::atomic::Ordering;

    let mut config = Config::default();
    config.dns.dnssec.validate = false;
    config.filtering.custom_rules = vec![
        "||rewrite-type-pipeline.example^$dnsrewrite=1.2.3.4".to_string(),
        "||rewrite-cname-pipeline.example^$dnsrewrite=cname.example.net".to_string(),
    ];
    let (pipeline, calls, temp_dir) = test_pipeline(config).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());

    // The rewrite answers an A question and never queries upstream.
    let resp = pipeline
        .handle(
            rewrite_query("rewrite-type-pipeline.example.", RecordType::A),
            client.clone(),
        )
        .await
        .unwrap();
    assert_eq!(resp.answers.len(), 1);
    assert!(
        matches!(resp.answers[0].data, RData::A(A(ip)) if ip == std::net::Ipv4Addr::new(1, 2, 3, 4))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // Other qtypes match the rule set but have no applicable value: the
    // answer is NOERROR/NODATA, not an upstream fallback.
    for qtype in [RecordType::AAAA, RecordType::TXT] {
        let resp = pipeline
            .handle(
                rewrite_query("rewrite-type-pipeline.example.", qtype),
                client.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NoError,
            "{qtype:?}"
        );
        assert!(
            resp.answers.is_empty(),
            "{qtype:?} must be NODATA instead of querying upstream: {:?}",
            resp.answers
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "{qtype:?} must not query upstream"
        );
    }

    // A CNAME rewrite answers any question type.
    let resp = pipeline
        .handle(
            rewrite_query("rewrite-cname-pipeline.example.", RecordType::TXT),
            client,
        )
        .await
        .unwrap();
    assert_eq!(resp.answers.len(), 1);
    assert!(
        matches!(&resp.answers[0].data, RData::CNAME(cname) if cname.0.to_ascii().trim_end_matches('.') == "cname.example.net")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Collects candidates exactly like [`DnsPipeline::handle`] does and
/// compares the resulting verdicts with the engine's own `evaluate*`
/// wrappers. This guards the WP-18 single-collection refactor against
/// normalization drift and ADR-0007 precedence changes.
#[tokio::test]
async fn test_candidate_path_matches_engine_and_preserves_precedence() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito-pipeline-filter-test-{}", std::process::id()));
    let config = FilteringConfig {
        custom_rules: vec![
            "||blocked.example^".to_string(),
            "@@||sub.blocked.example^".to_string(),
            "||important.sub.blocked.example^$important".to_string(),
            "@@||special.important.sub.blocked.example^$important".to_string(),
            "||xn--mnchen-3ya.de^".to_string(),
        ],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());

    for domain in [
        "blocked.example.",
        "sub.blocked.example.",
        "important.sub.blocked.example.",
        "special.important.sub.blocked.example.",
        "allowed.example.",
    ] {
        let qname = Name::from_str(domain).unwrap();
        let snapshot = engine.snapshot();
        let normalized = normalized_query_domain(&qname);
        let mut candidates = FilterCandidates::default();
        snapshot.allowlist.collect_candidates(
            &normalized,
            &snapshot.interner,
            &mut candidates.allow,
        );
        snapshot.blocklist.collect_candidates(
            &normalized,
            &snapshot.interner,
            &mut candidates.block,
        );

        let expected_important = engine.evaluate_important(&qname, RecordType::A, &client);
        let actual_important = snapshot.evaluate_important_candidates(
            &normalized,
            RecordType::A,
            &client,
            &candidates.allow,
            &candidates.block,
        );
        assert_eq!(
            expected_important.is_some(),
            actual_important.is_some(),
            "{domain}: important outcome presence"
        );
        if let (Some(expected), Some(actual)) = (&expected_important, &actual_important) {
            assert_eq!(expected.is_blocked(), actual.is_blocked(), "{domain}");
            assert_eq!(expected.is_allowed(), actual.is_allowed(), "{domain}");
        }

        let expected_standard = engine.evaluate_standard(&qname, RecordType::A, &client);
        let actual_standard = snapshot.evaluate_standard_candidates(
            &normalized,
            RecordType::A,
            &client,
            &candidates.allow,
            &candidates.block,
        );
        assert_eq!(
            expected_standard.is_blocked(),
            actual_standard.is_blocked(),
            "{domain}"
        );
        assert_eq!(
            expected_standard.is_allowed(),
            actual_standard.is_allowed(),
            "{domain}"
        );
    }

    // ADR-0007 precedence spot checks.
    let standard_block = Name::from_str("blocked.example.").unwrap();
    assert!(
        engine
            .evaluate_standard(&standard_block, RecordType::A, &client)
            .is_blocked()
    );
    let important_allow = Name::from_str("special.important.sub.blocked.example.").unwrap();
    let snapshot = engine.snapshot();
    let normalized = normalized_query_domain(&important_allow);
    let mut candidates = FilterCandidates::default();
    snapshot
        .allowlist
        .collect_candidates(&normalized, &snapshot.interner, &mut candidates.allow);
    snapshot
        .blocklist
        .collect_candidates(&normalized, &snapshot.interner, &mut candidates.block);
    let important = snapshot
        .evaluate_important_candidates(
            &normalized,
            RecordType::A,
            &client,
            &candidates.allow,
            &candidates.block,
        )
        .expect("important allow must match");
    assert!(important.is_allowed());

    // IDNA/punycode names must normalize exactly like the engine does.
    let idn = Name::from_utf8("münchen.de").unwrap();
    assert_eq!(normalized_query_domain(&idn), "xn--mnchen-3ya.de");
    let snapshot = engine.snapshot();
    let normalized = normalized_query_domain(&idn);
    let mut candidates = FilterCandidates::default();
    snapshot
        .allowlist
        .collect_candidates(&normalized, &snapshot.interner, &mut candidates.allow);
    snapshot
        .blocklist
        .collect_candidates(&normalized, &snapshot.interner, &mut candidates.block);
    assert!(
        snapshot
            .evaluate_standard_candidates(
                &normalized,
                RecordType::A,
                &client,
                &candidates.allow,
                &candidates.block,
            )
            .is_blocked(),
        "IDN query must match the punycode rule"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Spawns a UDP mock upstream that answers every query with an A record and
/// (dishonestly) AD=1, counting upstream calls. When `fail` is set and
/// true, the mock answers `SERVFAIL` instead so callers can exercise the
/// pipeline failure path and then recover by clearing the flag.
async fn spawn_mock_upstream(
    fail: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> (
    std::net::SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::atomic::AtomicUsize;

    let mock_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_socket.local_addr().unwrap();
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let call_counter = std::sync::Arc::clone(&calls);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((len, src)) = mock_socket.recv_from(&mut buf).await {
            if let Ok(query) = sito_proto::decode_message(&buf[..len]) {
                call_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let failing = fail
                    .as_ref()
                    .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst));
                let mut resp =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                resp.metadata.response_code = if failing {
                    ResponseCode::ServFail
                } else {
                    ResponseCode::NoError
                };
                // A compromised upstream: AD=1 without any signature.
                resp.metadata.authentic_data = true;
                resp.queries = query.queries.clone();
                if !failing && let Some(question) = query.queries.first() {
                    resp.answers.push(Record::from_rdata(
                        question.name().clone(),
                        300,
                        RData::A(A(std::net::Ipv4Addr::new(203, 0, 113, 9))),
                    ));
                }
                let encoded = sito_proto::encode_message(&resp).unwrap();
                let _ = mock_socket.send_to(&encoded, src).await;
            }
        }
    });
    (mock_addr, calls)
}

/// Builds a pipeline around `upstream` with the standard test registries.
/// A group-only filter configuration must resolve normal queries and block
/// only the group's rule. Before the fix, the empty global source set made
/// the engine unavailable and the pipeline SERVFAILed every client.
#[tokio::test]
async fn test_group_only_filter_configuration_resolves_end_to_end() {
    use sito_clients::{ClientEntryConfig, ClientGroupConfig, ClientsConfig};
    use sito_upstream::{BootstrapResolver, UpstreamManager};
    use std::collections::HashMap;

    let (mock_addr, calls) = spawn_mock_upstream(None).await;
    let mut config = Config::default();
    config.dns.dnssec.validate = false;
    config.filtering.enabled = true;
    config.filtering.fail_closed = true;
    config.filtering.lists.clear();
    config.filtering.custom_rules.clear();
    config.upstream.servers = vec![mock_addr.to_string()];

    let clients = ClientsConfig {
        entries: vec![ClientEntryConfig {
            name: "kid".to_string(),
            ids: vec!["127.0.0.1".to_string()],
            group: "kids".to_string(),
            ignore_query_log: false,
            ignore_stats: false,
            use_global_upstreams: true,
            upstreams: None,
            trusted: false,
        }],
        groups: HashMap::from([(
            "kids".to_string(),
            ClientGroupConfig {
                custom_rules: vec!["||fortnite.example^".to_string()],
                ..Default::default()
            },
        )]),
        ..Default::default()
    };

    let bootstrap = BootstrapResolver::new(vec![], std::time::Duration::from_millis(500));
    let upstream = std::sync::Arc::new(
        UpstreamManager::from_config(&config.upstream, &bootstrap)
            .await
            .unwrap(),
    );
    let validator = sito_dnssec::DnssecValidator::from_config(&config.dns.dnssec);
    let (pipeline, temp_dir) =
        build_test_pipeline_with_clients(config, upstream, validator, clients).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());

    let blocked = pipeline
        .handle(
            rewrite_query("fortnite.example.", RecordType::A),
            client.clone(),
        )
        .await
        .unwrap();
    assert_eq!(blocked.metadata.response_code, ResponseCode::NoError);
    assert!(
        blocked.answers.iter().any(
            |record| matches!(record.data, RData::A(A(ip)) if ip == std::net::Ipv4Addr::UNSPECIFIED)
        ),
        "the group custom rule must block: {blocked:?}"
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a blocked group query must not reach upstream"
    );

    let allowed = pipeline
        .handle(rewrite_query("example.org.", RecordType::A), client)
        .await
        .unwrap();
    assert_eq!(
        allowed.metadata.response_code,
        ResponseCode::NoError,
        "a group-only filter must not SERVFAIL unrelated queries"
    );
    assert_eq!(allowed.answers.len(), 1);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Deferred D3: a CNAME target blocked by a global standard rule stays
/// blocked when the client's group has a `$dnsrewrite` for the same
/// target. The rewrite cannot be applied to an already-resolved CNAME
/// target, so it must be treated as a no-match instead of suppressing the
/// block. A group allow still overrides the global block, and an important
/// rewrite must fall through to the standard checks rather than acting as
/// a real allow.
#[tokio::test]
async fn test_cname_target_group_rewrite_does_not_suppress_global_block_end_to_end() {
    use sito_clients::{ClientEntryConfig, ClientGroupConfig, ClientsConfig};
    use sito_upstream::{BootstrapResolver, UpstreamManager};
    use std::collections::HashMap;

    let (mock_addr, _calls) = spawn_mock_upstream(None).await;
    let mut config = Config::default();
    config.dns.dnssec.validate = false;
    config.filtering.enabled = true;
    config.filtering.fail_closed = false;
    config.filtering.lists.clear();
    config.filtering.custom_rules = vec!["||blocked-target.example^".to_string()];
    config.upstream.servers = vec![mock_addr.to_string()];

    let clients = ClientsConfig {
        entries: vec![
            ClientEntryConfig {
                name: "kid".to_string(),
                ids: vec!["127.0.0.1".to_string()],
                group: "kids".to_string(),
                ignore_query_log: false,
                ignore_stats: false,
                use_global_upstreams: true,
                upstreams: None,
                trusted: false,
            },
            ClientEntryConfig {
                name: "friend".to_string(),
                ids: vec!["127.0.0.2".to_string()],
                group: "friends".to_string(),
                ignore_query_log: false,
                ignore_stats: false,
                use_global_upstreams: true,
                upstreams: None,
                trusted: false,
            },
            ClientEntryConfig {
                name: "important-kid".to_string(),
                ids: vec!["127.0.0.3".to_string()],
                group: "important_kids".to_string(),
                ignore_query_log: false,
                ignore_stats: false,
                use_global_upstreams: true,
                upstreams: None,
                trusted: false,
            },
        ],
        groups: HashMap::from([
            (
                "kids".to_string(),
                ClientGroupConfig {
                    custom_rules: vec![
                        "||blocked-target.example^$dnsrewrite=192.0.2.10".to_string(),
                    ],
                    ..Default::default()
                },
            ),
            (
                "friends".to_string(),
                ClientGroupConfig {
                    custom_rules: vec!["@@||blocked-target.example^".to_string()],
                    ..Default::default()
                },
            ),
            (
                "important_kids".to_string(),
                ClientGroupConfig {
                    custom_rules: vec![
                        "||blocked-target.example^$dnsrewrite=192.0.2.10,important".to_string(),
                    ],
                    ..Default::default()
                },
            ),
        ]),
        ..Default::default()
    };

    let bootstrap = BootstrapResolver::new(vec![], std::time::Duration::from_millis(500));
    let upstream = std::sync::Arc::new(
        UpstreamManager::from_config(&config.upstream, &bootstrap)
            .await
            .unwrap(),
    );
    let validator = sito_dnssec::DnssecValidator::from_config(&config.dns.dnssec);
    let (pipeline, temp_dir) =
        build_test_pipeline_with_clients(config, upstream, validator, clients).await;

    let mut response = Message::new(42, MessageType::Response, OpCode::Query);
    response.queries.push(hickory_proto::op::Query::query(
        Name::from_str("alias.example.").unwrap(),
        RecordType::A,
    ));
    response.answers.push(Record::from_rdata(
        Name::from_str("alias.example.").unwrap(),
        300,
        RData::CNAME(CNAME(Name::from_str("blocked-target.example.").unwrap())),
    ));

    let snapshot = pipeline.runtime.snapshot();
    let mut kid = ClientContext::new("127.0.0.1".parse().unwrap());
    let kid_policy = snapshot.clients.resolve(&mut kid, snapshot.clients.now());
    assert!(
        pipeline.cname_target_blocked(&response, RecordType::A, &kid, &kid_policy),
        "a group rewrite must not suppress a global block on a CNAME target"
    );

    let mut important_kid = ClientContext::new("127.0.0.3".parse().unwrap());
    let important_kid_policy = snapshot
        .clients
        .resolve(&mut important_kid, snapshot.clients.now());
    assert!(
        pipeline.cname_target_blocked(
            &response,
            RecordType::A,
            &important_kid,
            &important_kid_policy,
        ),
        "an important rewrite must fall through to the standard block"
    );

    let mut friend = ClientContext::new("127.0.0.2".parse().unwrap());
    let friend_policy = snapshot
        .clients
        .resolve(&mut friend, snapshot.clients.now());
    assert!(
        !pipeline.cname_target_blocked(&response, RecordType::A, &friend, &friend_policy),
        "a group allow must still override the global block"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Deferred D3 follow-up: candidate order is structural, so a
/// `$dnsrewrite` can precede a block for the same CNAME target in one
/// snapshot. The block must still be detected independently of the
/// rewrite verdict.
#[tokio::test]
async fn test_cname_target_same_snapshot_rewrite_before_block_still_blocks() {
    use sito_upstream::{BootstrapResolver, UpstreamManager};

    let (mock_addr, _calls) = spawn_mock_upstream(None).await;
    let mut config = Config::default();
    config.dns.dnssec.validate = false;
    config.filtering.enabled = true;
    config.filtering.fail_closed = false;
    config.filtering.lists.clear();
    config.filtering.custom_rules = vec![
        "||blocked-target.example^$dnsrewrite=192.0.2.10".to_string(),
        "||blocked-target.example^".to_string(),
    ];
    config.upstream.servers = vec![mock_addr.to_string()];

    let bootstrap = BootstrapResolver::new(vec![], std::time::Duration::from_millis(500));
    let upstream = std::sync::Arc::new(
        UpstreamManager::from_config(&config.upstream, &bootstrap)
            .await
            .unwrap(),
    );
    let (pipeline, temp_dir) = build_test_pipeline(config, upstream).await;

    let mut response = Message::new(43, MessageType::Response, OpCode::Query);
    response.queries.push(hickory_proto::op::Query::query(
        Name::from_str("alias.example.").unwrap(),
        RecordType::A,
    ));
    response.answers.push(Record::from_rdata(
        Name::from_str("alias.example.").unwrap(),
        300,
        RData::CNAME(CNAME(Name::from_str("blocked-target.example.").unwrap())),
    ));

    let snapshot = pipeline.runtime.snapshot();
    let mut client = ClientContext::new("127.0.0.1".parse().unwrap());
    let policy = snapshot
        .clients
        .resolve(&mut client, snapshot.clients.now());
    assert!(
        pipeline.cname_target_blocked(&response, RecordType::A, &client, &policy),
        "a rewrite that precedes a block must not hide the block"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Deferred D3 follow-up: the same-snapshot ordering problem applies to the
/// `$important` tier. An important rewrite before an important block must
/// not hide the block on the CNAME-target path.
#[tokio::test]
async fn test_cname_target_same_snapshot_important_rewrite_before_block_still_blocks() {
    use sito_upstream::{BootstrapResolver, UpstreamManager};

    let (mock_addr, _calls) = spawn_mock_upstream(None).await;
    let mut config = Config::default();
    config.dns.dnssec.validate = false;
    config.filtering.enabled = true;
    config.filtering.fail_closed = false;
    config.filtering.lists.clear();
    config.filtering.custom_rules = vec![
        "||blocked-target.example^$dnsrewrite=192.0.2.10,important".to_string(),
        "||blocked-target.example^$important".to_string(),
    ];
    config.upstream.servers = vec![mock_addr.to_string()];

    let bootstrap = BootstrapResolver::new(vec![], std::time::Duration::from_millis(500));
    let upstream = std::sync::Arc::new(
        UpstreamManager::from_config(&config.upstream, &bootstrap)
            .await
            .unwrap(),
    );
    let (pipeline, temp_dir) = build_test_pipeline(config, upstream).await;

    let mut response = Message::new(44, MessageType::Response, OpCode::Query);
    response.queries.push(hickory_proto::op::Query::query(
        Name::from_str("alias.example.").unwrap(),
        RecordType::A,
    ));
    response.answers.push(Record::from_rdata(
        Name::from_str("alias.example.").unwrap(),
        300,
        RData::CNAME(CNAME(Name::from_str("blocked-target.example.").unwrap())),
    ));

    let snapshot = pipeline.runtime.snapshot();
    let mut client = ClientContext::new("127.0.0.1".parse().unwrap());
    let policy = snapshot
        .clients
        .resolve(&mut client, snapshot.clients.now());
    assert!(
        pipeline.cname_target_blocked(&response, RecordType::A, &client, &policy),
        "an important rewrite that precedes an important block must not hide the block"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// A group custom rule must not mask a configured global list that failed
/// to load: a non-group client gets SERVFAIL (fail closed), not allow-all.
#[tokio::test]
async fn test_group_rule_does_not_mask_failed_global_source_end_to_end() {
    use sito_clients::{ClientEntryConfig, ClientGroupConfig, ClientsConfig};
    use sito_core::config::FilterListConfig;
    use sito_upstream::{BootstrapResolver, UpstreamManager};
    use std::collections::HashMap;

    let (mock_addr, calls) = spawn_mock_upstream(None).await;
    let mut config = Config::default();
    config.dns.dnssec.validate = false;
    config.filtering.enabled = true;
    config.filtering.fail_closed = true;
    config.filtering.custom_rules.clear();
    config.filtering.lists = vec![FilterListConfig {
        name: "dead".to_string(),
        url: "http://127.0.0.1:1/blocklist.txt".to_string(),
        enabled: true,
        refresh_hours: None,
    }];
    config.upstream.servers = vec![mock_addr.to_string()];

    let clients = ClientsConfig {
        entries: vec![ClientEntryConfig {
            name: "kid".to_string(),
            ids: vec!["127.0.0.1".to_string()],
            group: "kids".to_string(),
            ignore_query_log: false,
            ignore_stats: false,
            use_global_upstreams: true,
            upstreams: None,
            trusted: false,
        }],
        groups: HashMap::from([(
            "kids".to_string(),
            ClientGroupConfig {
                custom_rules: vec!["||fortnite.example^".to_string()],
                ..Default::default()
            },
        )]),
        ..Default::default()
    };

    let bootstrap = BootstrapResolver::new(vec![], std::time::Duration::from_millis(500));
    let upstream = std::sync::Arc::new(
        UpstreamManager::from_config(&config.upstream, &bootstrap)
            .await
            .unwrap(),
    );
    let validator = sito_dnssec::DnssecValidator::from_config(&config.dns.dnssec);
    let (pipeline, temp_dir) =
        build_test_pipeline_with_clients(config, upstream, validator, clients).await;

    // 127.0.0.2 does not match the group entry.
    let response = pipeline
        .handle(
            rewrite_query("unrelated.example.", RecordType::A),
            ClientContext::new("127.0.0.2".parse().unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(
        response.metadata.response_code,
        ResponseCode::ServFail,
        "a failed global source must fail closed even when a group rule exists"
    );
    assert!(
        response.answers.is_empty(),
        "fail-closed responses must not leak an unfiltered answer"
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "fail-closed must stop before the upstream"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

async fn build_test_pipeline(
    config: Config,
    upstream: std::sync::Arc<UpstreamManager>,
) -> (DnsPipeline, std::path::PathBuf) {
    let validator = sito_dnssec::DnssecValidator::from_config(&config.dns.dnssec);
    build_test_pipeline_with_validator(config, upstream, validator).await
}

/// Builds a pipeline with a caller-supplied DNSSEC validator (used by
/// tests that need a specific trust anchor).
async fn build_test_pipeline_with_validator(
    config: Config,
    upstream: std::sync::Arc<UpstreamManager>,
    dnssec: sito_dnssec::DnssecValidator,
) -> (DnsPipeline, std::path::PathBuf) {
    build_test_pipeline_with_clients(
        config,
        upstream,
        dnssec,
        sito_clients::ClientsConfig::default(),
    )
    .await
}

/// Builds a pipeline with an explicit client registry, compiling group
/// rule sets from it (used by the group-only end-to-end test).
async fn build_test_pipeline_with_clients(
    mut config: Config,
    upstream: std::sync::Arc<UpstreamManager>,
    dnssec: sito_dnssec::DnssecValidator,
    clients: sito_clients::ClientsConfig,
) -> (DnsPipeline, std::path::PathBuf) {
    use sito_clients::{ClientRegistry, ParentalRegistry, ServiceRegistry};
    use sito_filter::HostsFilterEngine;
    use sito_rewrites::{RewriteTable, RewritesConfig};
    use std::sync::atomic::AtomicUsize;

    let temp_dir = std::env::temp_dir().join(format!(
        "sito-pipeline-audit6-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    config.server.data_dir = temp_dir.clone();
    config.dns.cache.enabled = true;

    let cache = std::sync::Arc::new(DnsCache::new(config.dns.cache.clone()));
    let group_rules = sito_runtime::group_rule_sets(&clients);
    let filter = std::sync::Arc::new(
        HostsFilterEngine::init_with_observer_and_group_sources(
            config.filtering.clone(),
            config.server.data_dir.clone(),
            None,
            group_rules.clone(),
        )
        .await,
    );
    filter.set_group_rules(group_rules);
    let pipeline = DnsPipeline::new(
        std::sync::Arc::new(ArcSwap::new(std::sync::Arc::new(config.clone()))),
        filter,
        cache,
        upstream,
        std::sync::Arc::new(dnssec),
        std::sync::Arc::new(ArcSwap::new(std::sync::Arc::new(ClientRegistry::new(
            clients,
        )))),
        std::sync::Arc::new(
            ParentalRegistry::try_bundled().expect("bundled parental lists must load"),
        ),
        std::sync::Arc::new(ServiceRegistry::try_bundled().expect("bundled services must load")),
        std::sync::Arc::new(ArcSwap::new(std::sync::Arc::new(RewriteTable::new(
            RewritesConfig::default(),
        )))),
        std::sync::Arc::new(AtomicUsize::new(0)),
    );
    (pipeline, temp_dir)
}

/// Builds a pipeline backed by the default successful UDP mock upstream.
async fn test_pipeline(
    mut config: Config,
) -> (
    DnsPipeline,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    std::path::PathBuf,
) {
    use sito_upstream::{BootstrapResolver, UpstreamManager};

    let (mock_addr, calls) = spawn_mock_upstream(None).await;
    config.upstream.servers = vec![mock_addr.to_string()];
    let bootstrap = BootstrapResolver::new(vec![], std::time::Duration::from_millis(500));
    let upstream = std::sync::Arc::new(
        UpstreamManager::from_config(&config.upstream, &bootstrap)
            .await
            .unwrap(),
    );
    let (pipeline, temp_dir) = build_test_pipeline(config, upstream).await;
    (pipeline, calls, temp_dir)
}

/// Builds a pipeline whose mock upstream fails while `fail` is true.
async fn test_pipeline_with_failure_toggle(
    mut config: Config,
    fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> (
    DnsPipeline,
    String,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    std::path::PathBuf,
) {
    use sito_upstream::{BootstrapResolver, UpstreamManager};

    let (mock_addr, calls) = spawn_mock_upstream(Some(std::sync::Arc::clone(&fail))).await;
    let server = mock_addr.to_string();
    config.upstream.servers = vec![server.clone()];
    let bootstrap = BootstrapResolver::new(vec![], std::time::Duration::from_millis(500));
    let upstream = std::sync::Arc::new(
        UpstreamManager::from_config(&config.upstream, &bootstrap)
            .await
            .unwrap(),
    );
    let (pipeline, temp_dir) = build_test_pipeline(config, upstream).await;
    (pipeline, server, calls, temp_dir)
}

/// Attaches metrics (and an in-memory query log writer) to a test pipeline.
async fn with_test_metrics(pipeline: DnsPipeline) -> (DnsPipeline, sito_stats::MetricsRegistry) {
    let stats_db = sito_stats::StatsDb::in_memory().await.unwrap();
    let writer = sito_stats::QueryLogWriter::spawn(stats_db, 100);
    let metrics = sito_stats::MetricsRegistry::new("test", "test");
    let pipeline = pipeline.with_stats(writer.sender(), metrics.clone());
    (pipeline, metrics)
}

/// D-12: a failing upstream is labelled by its configured name, lowers that
/// server's health gauge immediately, and recovers to 1 after a success.
/// No failure may ever be recorded under the legacy `upstream="all"` label.
#[tokio::test]
async fn test_pipeline_upstream_metrics_attribution_and_recovery() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut config = Config::default();
    config.filtering.enabled = false;
    config.dns.dnssec.validate = false;
    let fail = std::sync::Arc::new(AtomicBool::new(true));
    let (pipeline, server, calls, temp_dir) =
        test_pipeline_with_failure_toggle(config, std::sync::Arc::clone(&fail)).await;
    let (pipeline, metrics) = with_test_metrics(pipeline).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let name = Name::from_str("metrics-recovery.example.").unwrap();

    let resp = pipeline
        .handle(
            rewrite_query("metrics-recovery.example.", RecordType::A),
            client.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::ServFail,
        "the failing upstream must surface SERVFAIL"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains(&format!(
            "sito_upstream_errors_total{{upstream=\"{server}\",kind=\"bad_response\"}} 1"
        )),
        "error must be attributed to the configured server: {rendered}"
    );
    assert!(
        rendered.contains(&format!("sito_upstream_health{{upstream=\"{server}\"}} 0")),
        "a failed query must set that server's health gauge to 0: {rendered}"
    );
    assert!(
        !rendered.contains(r#"upstream="all""#),
        "the legacy aggregate label must never be emitted: {rendered}"
    );

    // Recover: the next successful query resets the same server's gauge.
    fail.store(false, Ordering::SeqCst);
    let resp = pipeline
        .handle(rewrite_query(&name.to_ascii(), RecordType::A), client)
        .await
        .unwrap();
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains(&format!("sito_upstream_health{{upstream=\"{server}\"}} 1")),
        "a success must recover the server's health gauge: {rendered}"
    );
    assert!(
        rendered.contains(&format!(
            "sito_upstream_errors_total{{upstream=\"{server}\",kind=\"bad_response\"}} 1"
        )),
        "the error counter is monotonic and keeps the attributed label: {rendered}"
    );
    assert!(!rendered.contains(r#"upstream="all""#));
    assert!(!rendered.contains("unattributed"));

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// D-12: failures that cannot be attributed to one configured server use
/// the constant `unattributed` label and must not write a health gauge.
#[tokio::test]
async fn test_pipeline_unattributed_upstream_label_is_constant() {
    use sito_core::config::UpstreamStrategy;
    use sito_upstream::UpstreamManager;

    let mut config = Config::default();
    config.filtering.enabled = false;
    config.dns.dnssec.validate = false;
    let upstream = std::sync::Arc::new(UpstreamManager::with_upstreams(
        Vec::new(),
        UpstreamStrategy::Failover,
        std::time::Duration::from_millis(500),
    ));
    let (pipeline, temp_dir) = build_test_pipeline(config, upstream).await;
    let (pipeline, metrics) = with_test_metrics(pipeline).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());

    for id in 1..=2 {
        let name = format!("unattributed-{id}.example.");
        let resp = pipeline
            .handle(rewrite_query(&name, RecordType::A), client.clone())
            .await
            .unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
    }

    let rendered = metrics.render_prometheus();
    assert!(
        rendered
            .contains(r#"sito_upstream_errors_total{upstream="unattributed",kind="all_down"} 2"#),
        "unattributable failures must use the constant `unattributed` label: {rendered}"
    );
    assert!(
        !rendered.contains(r#"sito_upstream_health{upstream="unattributed""#),
        "an unattributed failure must not write a health gauge: {rendered}"
    );
    assert!(!rendered.contains(r#"upstream="all""#));
    assert_eq!(
        rendered.matches(r#"upstream="unattributed""#).count(),
        1,
        "`unattributed` is one constant series, not a per-query label: {rendered}"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

fn do_query(id: u16, name: &Name) -> Message {
    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
    query
        .queries
        .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    query.set_edns(edns);
    query
}

#[tokio::test]
async fn test_opcode_notimp_and_edns_badvers() {
    let config = Config::default();
    let (pipeline, _calls, temp_dir) = test_pipeline(config).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let name = Name::from_str("example.com.").unwrap();

    let mut notify = Message::new(1, MessageType::Query, OpCode::Notify);
    notify
        .queries
        .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
    let resp = pipeline.handle(notify, client.clone()).await.unwrap();
    assert_eq!(resp.metadata.response_code, ResponseCode::NotImp);
    assert_eq!(resp.metadata.op_code, OpCode::Notify);

    let mut update = Message::new(2, MessageType::Query, OpCode::Update);
    update
        .queries
        .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
    let resp = pipeline.handle(update, client.clone()).await.unwrap();
    assert_eq!(resp.metadata.response_code, ResponseCode::NotImp);

    let mut v1 = Message::new(3, MessageType::Query, OpCode::Query);
    v1.queries
        .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
    let mut edns = Edns::new();
    edns.set_version(1);
    edns.set_dnssec_ok(true);
    v1.set_edns(edns);
    let resp = pipeline.handle(v1, client).await.unwrap();
    assert_eq!(resp.metadata.response_code, ResponseCode::BADVERS);
    let resp_edns = resp.edns.expect("BADVERS must carry an OPT record");
    assert_eq!(resp_edns.version(), 0);
    assert!(
        resp_edns.options().options.is_empty(),
        "BADVERS response must not echo EDNS options: {:?}",
        resp_edns.options().options
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_do_client_gets_insecure_cache_hit_with_ad_zero() {
    let mut config = Config::default();
    config.filtering.enabled = false;
    let (pipeline, calls, temp_dir) = test_pipeline(config).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let name = Name::from_str("unsigned.example.").unwrap();
    let query = do_query(11, &name);

    let mut cached = Message::response(11, OpCode::Query);
    cached.queries = query.queries.clone();
    cached.answers.push(Record::from_rdata(
        name.clone(),
        300,
        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 11))),
    ));
    cached.metadata.authentic_data = false;
    pipeline
        .cache
        .insert_with_status(&query, &cached, ValidationStatus::Insecure)
        .await;

    let resp = pipeline.handle(query, client.clone()).await.unwrap();
    assert_eq!(resp.answers.len(), 1);
    assert!(
        !resp.metadata.authentic_data,
        "Insecure entries must serve AD=0"
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a DO=1 client must hit the Insecure cache entry instead of re-querying"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_do_client_never_served_unchecked_cache_entry() {
    let mut config = Config::default();
    config.filtering.enabled = false;
    let (pipeline, calls, temp_dir) = test_pipeline(config).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let name = Name::from_str("unchecked.example.").unwrap();
    let query = do_query(12, &name);

    let mut cached = Message::response(12, OpCode::Query);
    cached.queries = query.queries.clone();
    cached.answers.push(Record::from_rdata(
        name.clone(),
        300,
        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 12))),
    ));
    // Forged: an entry cached without validation must never be trusted.
    cached.metadata.authentic_data = true;
    pipeline
        .cache
        .insert_with_status(&query, &cached, ValidationStatus::Unchecked)
        .await;

    let resp = pipeline.handle(query, client.clone()).await.unwrap();
    assert!(
        calls.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "an Unchecked entry must not be served while validation is active"
    );
    assert!(
        !resp.metadata.authentic_data,
        "the upstream AD bit must be replaced by local validation"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// A fresh `Indeterminate` entry is not an authenticated decision (in
/// log-only mode a Bogus result is recorded that way). While validation is
/// active it must force re-resolution instead of being served, so strict
/// mode can return SERVFAIL.
#[tokio::test]
async fn test_do_client_never_served_indeterminate_cache_entry() {
    let mut config = Config::default();
    config.filtering.enabled = false;
    let (pipeline, calls, temp_dir) = test_pipeline(config).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let name = Name::from_str("indeterminate.example.").unwrap();
    let query = do_query(18, &name);

    let mut cached = Message::response(18, OpCode::Query);
    cached.queries = query.queries.clone();
    cached.answers.push(Record::from_rdata(
        name.clone(),
        300,
        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 18))),
    ));
    pipeline
        .cache
        .insert_with_status(&query, &cached, ValidationStatus::Indeterminate)
        .await;

    let resp = pipeline.handle(query, client).await.unwrap();
    assert!(
        calls.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "an Indeterminate entry must not be served while validation is active"
    );
    assert!(
        !resp.metadata.authentic_data,
        "an inconclusive entry must never assert AD"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// RFC 8767 stale answers are not revalidated. An entry cached without
/// local validation (`Unchecked`) must never be served to a client while
/// validation is active, even when the upstream is down.
#[tokio::test]
async fn test_stale_unchecked_entry_is_not_served_under_validation() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut config = Config::default();
    config.filtering.enabled = false;
    config.dns.cache.serve_stale_hours = 1;
    config.dns.cache.min_ttl = 1;
    config.dns.cache.max_ttl = 1;
    config.dns.cache.negative_ttl_max = 1;
    let fail = std::sync::Arc::new(AtomicBool::new(true));
    let (pipeline, _server, calls, temp_dir) =
        test_pipeline_with_failure_toggle(config, fail).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let name = Name::from_str("stale-unchecked.example.").unwrap();
    let query = do_query(15, &name);

    let mut cached = Message::response(15, OpCode::Query);
    cached.queries = query.queries.clone();
    cached.answers.push(Record::from_rdata(
        name.clone(),
        1,
        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 15))),
    ));
    pipeline
        .cache
        .insert_with_status(&query, &cached, ValidationStatus::Unchecked)
        .await;

    // Let the entry leave the fresh window so only the stale path can
    // answer it.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let resp = pipeline.handle(query, client).await.unwrap();
    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::ServFail,
        "a stale Unchecked entry must not bypass active validation"
    );
    assert!(
        resp.answers.is_empty(),
        "the rejected stale answer must not leak records"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// A stale `Indeterminate` entry is not an authenticated decision: it may
/// be an inconclusive answer (or, in log-only mode, a Bogus result cached
/// as Indeterminate). It must not be served to a validating client while
/// the upstream is down.
#[tokio::test]
async fn test_stale_indeterminate_entry_is_not_served_under_validation() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut config = Config::default();
    config.filtering.enabled = false;
    config.dns.cache.serve_stale_hours = 1;
    config.dns.cache.min_ttl = 1;
    config.dns.cache.max_ttl = 1;
    config.dns.cache.negative_ttl_max = 1;
    let fail = std::sync::Arc::new(AtomicBool::new(true));
    let (pipeline, _server, calls, temp_dir) =
        test_pipeline_with_failure_toggle(config, fail).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let name = Name::from_str("stale-indeterminate.example.").unwrap();
    let query = do_query(16, &name);

    let mut cached = Message::response(16, OpCode::Query);
    cached.queries = query.queries.clone();
    cached.answers.push(Record::from_rdata(
        name.clone(),
        1,
        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 16))),
    ));
    pipeline
        .cache
        .insert_with_status(&query, &cached, ValidationStatus::Indeterminate)
        .await;

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let resp = pipeline.handle(query, client).await.unwrap();
    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::ServFail,
        "a stale Indeterminate entry must not be served to a validating client"
    );
    assert!(
        resp.answers.is_empty(),
        "the rejected stale answer must not leak records"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Stale `Insecure` data is an authenticated unsigned decision and remains
/// RFC 8767-servable, with AD cleared.
#[tokio::test]
async fn test_stale_insecure_entry_is_served_with_ad_zero() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut config = Config::default();
    config.filtering.enabled = false;
    config.dns.cache.serve_stale_hours = 1;
    config.dns.cache.min_ttl = 1;
    config.dns.cache.max_ttl = 1;
    config.dns.cache.negative_ttl_max = 1;
    let fail = std::sync::Arc::new(AtomicBool::new(true));
    let (pipeline, _server, calls, temp_dir) =
        test_pipeline_with_failure_toggle(config, fail).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let name = Name::from_str("stale-insecure.example.").unwrap();
    let query = do_query(17, &name);

    let mut cached = Message::response(17, OpCode::Query);
    cached.queries = query.queries.clone();
    cached.answers.push(Record::from_rdata(
        name.clone(),
        1,
        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 17))),
    ));
    pipeline
        .cache
        .insert_with_status(&query, &cached, ValidationStatus::Insecure)
        .await;

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let resp = pipeline.handle(query, client).await.unwrap();
    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::NoError,
        "a stale Insecure entry remains servable as unauthenticated data"
    );
    assert_eq!(resp.answers.len(), 1);
    assert!(
        !resp.metadata.authentic_data,
        "a stale entry must never be served as authenticated"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// A validated Secure NXDOMAIN/NODATA must be cached for DO=0 clients too.
///
/// The pipeline strips NSEC/NSEC3/RRSIG before inserting a DO=0 response.
/// The denial-proof TTL cap must therefore already be applied to the SOA
/// (in `apply_authenticated_ttls`); deriving the cap only from the cached
/// (stripped) records produced a zero lifespan and sent every repeated
/// negative query upstream.
#[tokio::test]
async fn test_do0_secure_negative_answer_is_cached() {
    use hickory_proto::dnssec::TrustAnchors;
    use hickory_proto::dnssec::rdata::{DNSSECRData, NSEC};
    use hickory_proto::rr::{LowerName, RecordSet};
    use sito_dnssec::DnssecMode;
    use sito_proto::rdata::SOA;

    let (origin, dnskey, signer) = sito_dnssec::test_util::create_test_signer("signed.example.");
    let qname = Name::from_str("empty.signed.example.").unwrap();
    let next = Name::from_str("zzz.signed.example.").unwrap();

    // Signed SOA (long-lived) plus a signed NSEC NODATA proof (10 s).
    let soa = Record::from_rdata(
        origin.clone(),
        3600,
        RData::SOA(SOA::new(
            Name::from_str("ns1.signed.example.").unwrap(),
            Name::from_str("hostmaster.signed.example.").unwrap(),
            1,
            7200,
            3600,
            1_209_600,
            3600,
        )),
    );
    let mut soa_set = RecordSet::new(origin.clone(), RecordType::SOA, 3600);
    soa_set.insert(soa.clone(), 0);
    let mut soa_sig = sito_dnssec::test_util::sign_test_rrset(&soa_set, &signer);
    soa_sig.ttl = 3600;

    let nsec = NSEC::new(next, [RecordType::SOA, RecordType::NSEC, RecordType::RRSIG]);
    let nsec_record = Record::from_rdata(qname.clone(), 10, RData::DNSSEC(DNSSECRData::NSEC(nsec)));
    let mut nsec_set = RecordSet::new(qname.clone(), RecordType::NSEC, 10);
    nsec_set.insert(nsec_record.clone(), 0);
    let mut nsec_sig = sito_dnssec::test_util::sign_test_rrset(&nsec_set, &signer);
    nsec_sig.ttl = 10;

    let mut template = Message::new(0, MessageType::Response, OpCode::Query);
    template.metadata.response_code = ResponseCode::NoError;
    template.authorities = vec![soa, soa_sig, nsec_record, nsec_sig];
    template.additionals.push(Record::from_rdata(
        origin.clone(),
        3600,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
    ));

    let mock_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_socket.local_addr().unwrap();
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_task = std::sync::Arc::clone(&calls);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((len, src)) = mock_socket.recv_from(&mut buf).await {
            if let Ok(query) = sito_proto::decode_message(&buf[..len]) {
                calls_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut resp = template.clone();
                resp.metadata.id = query.metadata.id;
                resp.queries = query.queries.clone();
                if let Ok(encoded) = sito_proto::encode_message(&resp) {
                    let _ = mock_socket.send_to(&encoded, src).await;
                }
            }
        }
    });

    let mut config = Config::default();
    config.filtering.enabled = false;
    config.upstream.servers = vec![mock_addr.to_string()];
    config.dns.cache.serve_stale_hours = 0;
    let bootstrap =
        sito_upstream::BootstrapResolver::new(vec![], std::time::Duration::from_millis(500));
    let upstream = std::sync::Arc::new(
        sito_upstream::UpstreamManager::from_config(&config.upstream, &bootstrap)
            .await
            .unwrap(),
    );

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);
    let (pipeline, temp_dir) =
        build_test_pipeline_with_validator(config, upstream, validator).await;

    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let make_query = |id: u16| {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.queries.push(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::A,
        ));
        // No DO bit: a plain client.
        query
    };

    let first = pipeline
        .handle(make_query(1), client.clone())
        .await
        .unwrap();
    assert_eq!(first.metadata.response_code, ResponseCode::NoError);
    assert!(first.answers.is_empty(), "expected a NODATA answer");
    assert!(
        !first.metadata.authentic_data,
        "DO=0 responses never carry AD"
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "first query must reach the upstream"
    );
    let soa_ttl = first
        .authorities
        .iter()
        .find(|record| record.record_type() == RecordType::SOA)
        .expect("negative answer carries an SOA")
        .ttl;
    assert!(
        soa_ttl <= 10,
        "the validator must cap the SOA TTL by the denial proof before the DO=0 strip (got {soa_ttl})"
    );

    let (_, status) = pipeline
        .cache
        .get_for_query_with_status(&make_query(2))
        .await
        .expect("the Secure negative answer must have a non-zero cache lifespan");
    assert_eq!(
        status,
        ValidationStatus::Secure,
        "the denial proof must validate before being cached for DO=0"
    );

    let second = pipeline.handle(make_query(3), client).await.unwrap();
    assert_eq!(second.metadata.response_code, ResponseCode::NoError);
    assert_eq!(second.answers.len(), 0);
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a repeated DO=0 Secure negative must be served from the fresh cache"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_do0_response_is_stripped_and_cache_key_stays_do0() {
    let mut config = Config::default();
    config.filtering.enabled = false;
    config.dns.dnssec.mode = "disabled".to_string();
    config.dns.dnssec.validate = false;
    let (pipeline, calls, temp_dir) = test_pipeline(config).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let name = Name::from_str("rrsig.example.").unwrap();

    // Mock upstream signature record appended by injecting it into the
    // cached response is not possible here; instead assert the DO=0 key is
    // separate from the DO=1 key by observing a second upstream call.
    let mut plain = Message::new(13, MessageType::Query, OpCode::Query);
    plain
        .queries
        .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
    let resp = pipeline
        .handle(plain.clone(), client.clone())
        .await
        .unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(!resp.metadata.authentic_data);

    // Same question with DO=1 must not reuse the DO=0 entry.
    let mut do_query = plain.clone();
    do_query.metadata.id = 14;
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    do_query.set_edns(edns);
    let _ = pipeline.handle(do_query, client).await.unwrap();
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "DO=1 responses must be cached separately from DO=0 entries"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_prefetch_clears_ad_when_no_validation_ran() {
    let mut config = Config::default();
    config.filtering.enabled = false;
    config.dns.dnssec.mode = "disabled".to_string();
    config.dns.dnssec.validate = false;
    config.dns.cache.prefetch = true;
    config.dns.cache.min_ttl = 5;
    config.dns.cache.max_ttl = 10;
    let (pipeline, calls, temp_dir) = test_pipeline(config).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let name = Name::from_str("prefetch-ad.example.").unwrap();

    for id in 1..=3 {
        let resp = pipeline
            .handle(do_query(id, &name), client.clone())
            .await
            .unwrap();
        assert!(
            !resp.metadata.authentic_data,
            "primary path never asserts AD without local validation"
        );
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        calls.load(std::sync::atomic::Ordering::SeqCst) >= 2,
        "prefetch is expected to have re-queried the upstream"
    );

    // Inspect the entry itself: the prefetch writer must clear AD, not
    // merely rely on the read path to mask it.
    let (cached, _) = pipeline
        .cache
        .get_for_query_with_status(&do_query(4, &name))
        .await
        .expect("prefetched entry present");
    assert!(
        !cached.metadata.authentic_data,
        "a prefetched entry must have AD cleared when no local validation ran"
    );

    let resp = pipeline.handle(do_query(4, &name), client).await.unwrap();
    assert!(!resp.metadata.authentic_data);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[test]
fn test_strip_dnssec_records_for_do0_clients() {
    use hickory_proto::rr::rdata::NULL;
    use sito_proto::rdata::opt::EdnsCode;

    let name = Name::from_str("dnssec.example.").unwrap();
    let mut response = Message::new(21, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
    response.answers.push(Record::from_rdata(
        name.clone(),
        300,
        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 21))),
    ));
    for record_type in [
        RecordType::RRSIG,
        RecordType::NSEC,
        RecordType::NSEC3,
        RecordType::DNSKEY,
    ] {
        response.answers.push(Record::from_rdata(
            name.clone(),
            300,
            RData::Unknown {
                code: record_type,
                rdata: NULL::default(),
            },
        ));
    }
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Unknown(u16::from(EdnsCode::DAU), vec![]));
    response.set_edns(edns);

    sito_proto::strip_dnssec_records(&mut response);
    assert_eq!(
        response.answers.len(),
        1,
        "only the A record may remain after DO=0 shaping"
    );
    assert_eq!(response.answers[0].record_type(), RecordType::A);
    assert!(
        response
            .edns
            .as_ref()
            .is_some_and(|e| e.option(EdnsCode::DAU).is_none()),
        "DO-dependent EDNS options must be stripped"
    );
}

#[test]
fn test_response_shaping_strips_upstream_edns_and_opt_for_non_edns_clients() {
    use hickory_proto::rr::rdata::NULL;

    let name = Name::from_str("shape.example.").unwrap();
    let mut query = Message::new(1, MessageType::Query, OpCode::Query);
    query
        .queries
        .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));

    let mut response = Message::response(1, OpCode::Query);
    response.queries = query.queries.clone();
    response.answers.push(Record::from_rdata(
        name.clone(),
        300,
        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 50))),
    ));
    response.answers.push(Record::from_rdata(
        name.clone(),
        300,
        RData::Unknown {
            code: RecordType::RRSIG,
            rdata: NULL::default(),
        },
    ));
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Unknown(10, vec![1, 2, 3, 4])); // COOKIE
    edns.options_mut()
        .insert(EdnsOption::Unknown(3, vec![b'x'])); // NSID
    edns.options_mut()
        .insert(EdnsOption::Unknown(12, vec![0; 8])); // padding
    response.set_edns(edns);

    // A non-EDNS client must never receive an OPT record or DNSSEC data.
    ResponseShaper::shape(&mut response, &query, DnssecMode::Validate);
    assert!(
        response.edns.is_none(),
        "a non-EDNS client must not receive an OPT record"
    );
    assert_eq!(response.answers.len(), 1, "RRSIG must be stripped");

    // An EDNS client gets a fresh OPT with only the DO echo; upstream
    // COOKIE/NSID/padding options are never replayed.
    let mut edns_query = query.clone();
    edns_query.set_edns(Edns::new());
    let mut response = Message::response(1, OpCode::Query);
    response.queries = query.queries.clone();
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Unknown(10, vec![1, 2, 3, 4]));
    edns.options_mut()
        .insert(EdnsOption::Unknown(3, vec![b'x']));
    edns.options_mut()
        .insert(EdnsOption::Unknown(12, vec![0; 8]));
    response.set_edns(edns);

    ResponseShaper::shape(&mut response, &edns_query, DnssecMode::Validate);
    let shaped = response.edns.expect("EDNS clients keep an OPT record");
    assert!(
        shaped.options().options.is_empty(),
        "upstream-only EDNS options must be stripped: {:?}",
        shaped.options().options
    );
    assert!(!shaped.flags().dnssec_ok, "DO must echo the client's bit");
}

#[test]
fn test_response_shaping_copies_question_flags_and_do() {
    use hickory_proto::rr::rdata::NULL;

    let stored_name = Name::from_str("mixed.example.").unwrap();
    let current_name = Name::from_str("MiXeD.ExAmPle.").unwrap();

    let mut query = Message::new(22, MessageType::Query, OpCode::Query);
    query.queries.push(hickory_proto::op::Query::query(
        current_name.clone(),
        RecordType::A,
    ));
    query.metadata.recursion_desired = true;
    query.metadata.checking_disabled = true;
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    query.set_edns(edns);

    let mut response = Message::response(99, OpCode::Notify);
    response.queries.push(hickory_proto::op::Query::query(
        stored_name.clone(),
        RecordType::A,
    ));
    response.metadata.authoritative = true;
    response.metadata.recursion_desired = false;
    response.metadata.checking_disabled = false;
    response.answers.push(Record::from_rdata(
        current_name.clone(),
        300,
        RData::Unknown {
            code: RecordType::RRSIG,
            rdata: NULL::default(),
        },
    ));

    ResponseShaper::shape(&mut response, &query, DnssecMode::Validate);
    assert_eq!(
        response.metadata.id, 22,
        "the response ID must come from the current query"
    );
    assert_eq!(
        response.metadata.op_code,
        OpCode::Query,
        "the response opcode must come from the current query"
    );
    assert!(
        !response.metadata.authoritative,
        "the recursive resolver must never set AA on a shaped response"
    );
    assert!(response.metadata.recursion_desired);
    assert!(response.metadata.checking_disabled);
    assert_eq!(response.queries.len(), 1);
    assert_eq!(
        response.queries[0].name().to_string(),
        current_name.to_string(),
        "the current client question must be echoed, not the stored one"
    );
    assert!(
        response.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
        "the DO bit must echo the current client's request"
    );
    assert_eq!(
        response.answers.len(),
        1,
        "a DO=1 client keeps DNSSEC records"
    );
}

/// P2-84: a cache hit must copy the current question and RD bit, and
/// must not replay the stored entry's ID/RD/CD/AA envelope or its upstream
/// EDNS options to a client that sent OPT.
#[tokio::test]
async fn test_cache_hit_copies_current_question_and_flags() {
    use std::sync::atomic::Ordering;

    let mut config = Config::default();
    config.filtering.enabled = false;
    config.dns.dnssec.validate = false;
    let edns_udp_size = config.dns.edns_udp_size;
    let (pipeline, calls, temp_dir) = test_pipeline(config).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());

    let stored_name = mixed_name("cache-shape.example.");
    let mut stored_query = Message::new(1, MessageType::Query, OpCode::Query);
    stored_query.queries.push(hickory_proto::op::Query::query(
        stored_name.clone(),
        RecordType::A,
    ));
    stored_query.metadata.checking_disabled = true;
    stored_query.set_edns(Edns::new());

    let mut cached = Message::response(1, OpCode::Query);
    cached.queries = stored_query.queries.clone();
    cached.metadata.authoritative = true;
    cached.metadata.recursion_desired = false;
    cached.metadata.authentic_data = true;
    cached.answers.push(Record::from_rdata(
        stored_name.clone(),
        300,
        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 84))),
    ));
    let mut stored_edns = Edns::new();
    stored_edns
        .options_mut()
        .insert(EdnsOption::Unknown(10, vec![1, 2, 3, 4]));
    cached.set_edns(stored_edns);
    pipeline
        .cache
        .insert_with_status(&stored_query, &cached, ValidationStatus::Insecure)
        .await;

    let current_name = mixed_name("CaChE-ShApE.ExAmPlE.");
    let mut current_query = Message::new(2, MessageType::Query, OpCode::Query);
    current_query.queries.push(hickory_proto::op::Query::query(
        current_name.clone(),
        RecordType::A,
    ));
    current_query.metadata.recursion_desired = true;
    // CD is part of the cache key; keep it identical so this is a hit.
    current_query.metadata.checking_disabled = true;
    current_query.set_edns(Edns::new());

    let resp = pipeline
        .handle(current_query, client)
        .await
        .expect("cache hit response");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "this test must exercise the cache path, not upstream"
    );

    assert_eq!(
        resp.metadata.id, 2,
        "the response ID must come from the current query, not the cache entry"
    );
    assert_eq!(resp.metadata.op_code, OpCode::Query);
    assert!(
        !resp.metadata.authoritative,
        "a cache hit must not replay the stored AA bit"
    );
    assert!(
        resp.metadata.recursion_desired,
        "RD must come from the query"
    );
    assert!(
        !resp.metadata.authentic_data,
        "an Insecure cache entry must not keep the stored AD bit"
    );
    assert!(
        resp.metadata.checking_disabled,
        "CD must come from the query"
    );
    let edns = resp
        .edns
        .expect("a cache hit for an EDNS client must include OPT");
    assert_eq!(
        edns.max_payload(),
        edns_udp_size,
        "the resolver advertises its configured payload size"
    );
    assert!(
        edns.options().options.is_empty(),
        "the stored upstream COOKIE must not be replayed: {:?}",
        edns.options().options
    );
    assert_eq!(
        resp.queries[0].name().to_ascii(),
        "CaChE-ShApE.ExAmPlE.",
        "a cache hit must echo the current question, not the stored one"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// P1-13/P2-84: an upstream answer must not replay upstream ID/AA/AD or
/// upstream EDNS options. The shared shaper is the last stage on this path.
#[tokio::test]
async fn test_upstream_response_is_shaped_for_client() {
    use std::sync::atomic::Ordering;

    let mut config = Config::default();
    config.filtering.enabled = false;
    config.dns.dnssec.validate = false;
    let edns_udp_size = config.dns.edns_udp_size;
    let (pipeline, calls, temp_dir) = test_pipeline(config).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());

    let mut query = Message::new(88, MessageType::Query, OpCode::Query);
    query.queries.push(hickory_proto::op::Query::query(
        mixed_name("UpStReAm.Example."),
        RecordType::A,
    ));
    query.metadata.recursion_desired = true;
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    query.set_edns(edns);

    let resp = pipeline
        .handle(query, client)
        .await
        .expect("upstream answer");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    assert_eq!(resp.metadata.id, 88);
    assert_eq!(
        resp.queries[0].name().to_ascii(),
        "UpStReAm.Example.",
        "the upstream response must echo the client question"
    );
    assert!(resp.metadata.recursion_desired);
    assert!(!resp.metadata.authoritative);
    assert!(
        !resp.metadata.authentic_data,
        "the mock upstream forges AD; validation-disabled mode must clear it"
    );
    let edns = resp.edns.expect("EDNS client keeps OPT");
    assert_eq!(edns.max_payload(), edns_udp_size);
    assert!(
        edns.options().options.is_empty(),
        "upstream-only options must be stripped: {:?}",
        edns.options().options
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// P2-84: the stale (RFC 8767) fallback is another response source; it must
/// use the same shaper and never replay the stored question/ID/RD or OPT.
#[tokio::test]
async fn test_stale_response_is_shaped_for_client() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut config = Config::default();
    config.filtering.enabled = false;
    config.dns.cache.serve_stale_hours = 1;
    config.dns.cache.min_ttl = 1;
    config.dns.cache.max_ttl = 1;
    config.dns.cache.negative_ttl_max = 1;
    let edns_udp_size = config.dns.edns_udp_size;
    let fail = std::sync::Arc::new(AtomicBool::new(true));
    let (pipeline, _server, calls, temp_dir) =
        test_pipeline_with_failure_toggle(config, fail).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());

    let stored_name = mixed_name("stale-shape.example.");
    let mut stored_query = Message::new(5, MessageType::Query, OpCode::Query);
    stored_query.queries.push(hickory_proto::op::Query::query(
        stored_name.clone(),
        RecordType::A,
    ));
    stored_query.set_edns(Edns::new());
    let mut cached = Message::response(5, OpCode::Query);
    cached.queries = stored_query.queries.clone();
    cached.metadata.authoritative = true;
    cached.metadata.recursion_desired = false;
    cached.metadata.authentic_data = true;
    cached.answers.push(Record::from_rdata(
        stored_name,
        1,
        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 85))),
    ));
    let mut stored_edns = Edns::new();
    stored_edns
        .options_mut()
        .insert(EdnsOption::Unknown(10, vec![5, 6, 7, 8]));
    cached.set_edns(stored_edns);
    pipeline
        .cache
        .insert_with_status(&stored_query, &cached, ValidationStatus::Insecure)
        .await;

    // Leave the fresh window so only the stale path can answer.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let mut query = Message::new(6, MessageType::Query, OpCode::Query);
    query.queries.push(hickory_proto::op::Query::query(
        mixed_name("StAlE-ShApE.Example."),
        RecordType::A,
    ));
    query.metadata.recursion_desired = true;
    query.set_edns(Edns::new());

    let resp = pipeline.handle(query, client).await.expect("stale answer");
    assert!(
        calls.load(Ordering::SeqCst) >= 1,
        "upstream must have failed"
    );
    assert_eq!(resp.metadata.id, 6);
    assert_eq!(
        resp.queries[0].name().to_ascii(),
        "StAlE-ShApE.Example.",
        "the stale path must echo the current question"
    );
    assert!(resp.metadata.recursion_desired);
    assert!(!resp.metadata.authoritative);
    assert!(
        !resp.metadata.authentic_data,
        "stale data must never be served as authenticated"
    );
    let edns = resp.edns.expect("EDNS client keeps OPT");
    assert_eq!(edns.max_payload(), edns_udp_size);
    assert!(
        edns.options().options.is_empty(),
        "the stored upstream COOKIE must not be replayed: {:?}",
        edns.options().options
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// A local `$dnsrewrite` answer is synthesized before the final shaping
/// point; its envelope must still describe the client query.
#[tokio::test]
async fn test_rewrite_response_is_shaped_for_client() {
    use std::sync::atomic::Ordering;

    let mut config = Config::default();
    config.dns.dnssec.validate = false;
    config.filtering.custom_rules = vec!["||shape-rewrite.example^$dnsrewrite=1.2.3.4".to_string()];
    let edns_udp_size = config.dns.edns_udp_size;
    let (pipeline, calls, temp_dir) = test_pipeline(config).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());

    let mut query = Message::new(44, MessageType::Query, OpCode::Query);
    query.queries.push(hickory_proto::op::Query::query(
        mixed_name("ShApE-ReWrItE.Example."),
        RecordType::A,
    ));
    query.metadata.recursion_desired = true;
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Unknown(10, vec![1, 2, 3, 4]));
    query.set_edns(edns);

    let resp = pipeline
        .handle(query, client)
        .await
        .expect("rewrite response");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a rewrite must not query upstream"
    );
    assert_eq!(resp.metadata.id, 44);
    assert_eq!(resp.queries[0].name().to_ascii(), "ShApE-ReWrItE.Example.");
    assert!(resp.metadata.recursion_desired);
    assert!(!resp.metadata.authoritative);
    assert!(!resp.metadata.authentic_data);
    let edns = resp.edns.expect("EDNS client keeps OPT");
    assert_eq!(edns.max_payload(), edns_udp_size);
    assert!(
        edns.options().options.is_empty(),
        "the client COOKIE must not be echoed by a local rewrite"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// P2-18: QR=1 messages are dropped and multi-question messages are
/// rejected with FORMERR before policy/cache/upstream work starts.
#[tokio::test]
async fn test_pipeline_rejects_qr1_and_multi_question_queries() {
    use std::sync::atomic::Ordering;

    let mut config = Config::default();
    config.filtering.enabled = false;
    config.dns.dnssec.validate = false;
    let (pipeline, calls, temp_dir) = test_pipeline(config).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let name = Name::from_str("reject.example.").unwrap();

    let mut response_message = Message::new(9, MessageType::Response, OpCode::Query);
    response_message
        .queries
        .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
    assert!(
        pipeline
            .handle(response_message, client.clone())
            .await
            .is_none(),
        "a QR=1 message must be dropped"
    );

    let mut multi = Message::new(10, MessageType::Query, OpCode::Query);
    multi
        .queries
        .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
    multi.queries.push(hickory_proto::op::Query::query(
        Name::from_str("second.example.").unwrap(),
        RecordType::AAAA,
    ));
    let resp = pipeline
        .handle(multi, client.clone())
        .await
        .expect("multi-question queries get a FORMERR response");
    assert_eq!(resp.metadata.response_code, ResponseCode::FormErr);
    assert!(
        resp.metadata.recursion_available,
        "FORMERR must consistently advertise recursion availability"
    );
    assert!(
        resp.queries.is_empty(),
        "a multi-question FORMERR must not echo questions"
    );

    let zero = Message::new(11, MessageType::Query, OpCode::Query);
    let resp = pipeline
        .handle(zero, client)
        .await
        .expect("zero-question queries get a FORMERR response");
    assert_eq!(resp.metadata.response_code, ResponseCode::FormErr);
    assert!(
        resp.metadata.recursion_available,
        "zero-question FORMERR must set RA like the multi-question path"
    );

    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "rejected queries must not reach upstream"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[test]
fn test_ecs_policy_off_strips_and_forward_clamps() {
    use hickory_proto::rr::rdata::opt::ClientSubnet;
    use sito_cache::CacheKey;

    let name = Name::from_str("ecs.example.").unwrap();
    let mut query = Message::new(1, MessageType::Query, OpCode::Query);
    query
        .queries
        .push(hickory_proto::op::Query::query(name, RecordType::A));
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Subnet(ClientSubnet::new(
            "192.0.2.55".parse().unwrap(),
            32,
            0,
        )));
    query.set_edns(edns);

    let mut off_config = Config::default();
    off_config.upstream.ecs = UpstreamEcs::Off;
    let off = build_cache_query(&query, &off_config);
    assert!(
        off.edns
            .as_ref()
            .is_some_and(|e| e.option(EdnsCode::Subnet).is_none()),
        "ECS off must strip the client option"
    );

    let mut forward_config = Config::default();
    forward_config.upstream.ecs = UpstreamEcs::Forward;
    let forwarded = build_cache_query(&query, &forward_config);
    let subnet = match forwarded
        .edns
        .as_ref()
        .and_then(|e| e.option(EdnsCode::Subnet))
    {
        Some(EdnsOption::Subnet(subnet)) => *subnet,
        other => panic!("expected ECS option, got {other:?}"),
    };
    assert_eq!(subnet.source_prefix(), 24, "IPv4 ECS must clamp to /24");
    assert_eq!(subnet.scope_prefix(), 0);
    assert_eq!(subnet.addr().to_string(), "192.0.2.0");

    // Two clients in the same /24 share one cache key.
    let mut sibling = query.clone();
    if let Some(edns) = sibling.edns.as_mut() {
        edns.options_mut().remove(EdnsCode::Subnet);
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "192.0.2.200".parse().unwrap(),
                24,
                0,
            )));
    }
    let sibling_forwarded = build_cache_query(&sibling, &forward_config);
    assert_eq!(
        CacheKey::from_query(&forwarded),
        CacheKey::from_query(&sibling_forwarded),
        "clamped ECS must deduplicate cache keys"
    );
}

/// P2-25: the global/group precedence table is consistent across tiers:
/// within a tier `Allow > Rewrite > Block`, the group overlay wins ties,
/// and `$important` always outranks standard rules.
#[test]
fn test_group_global_precedence_table() {
    use sito_core::verdict::{BlockReason, RewriteAction, RuleRef};

    let block = || {
        Verdict::Block(BlockReason::Rule(RuleRef::new(
            "||blocked.example^".to_string(),
        )))
    };
    let allow = || Verdict::Allow(Some(RuleRef::new("@@||allowed.example^".to_string())));
    let no_match = || Verdict::Allow(None);
    let rewrite = || {
        Verdict::Rewrite(RewriteAction::DnsRewrite {
            rcode: "NOERROR".to_string(),
            rtype: Some("A".to_string()),
            value: Some("192.0.2.10".to_string()),
        })
    };

    // Standard tier: a group rewrite overrides a global standard block.
    assert!(matches!(
        combine_standard_verdicts(block(), Some(rewrite())),
        Verdict::Rewrite(_)
    ));
    // A group result with no matching rule must not erase a global block.
    assert!(matches!(
        combine_standard_verdicts(block(), Some(no_match())),
        Verdict::Block(_)
    ));
    // Standard allow outranks a group rewrite.
    assert!(matches!(
        combine_standard_verdicts(allow(), Some(rewrite())),
        Verdict::Allow(_)
    ));
    // Ties go to the group overlay.
    assert!(matches!(
        combine_standard_verdicts(block(), Some(block())),
        Verdict::Block(_)
    ));

    // Important tier: a group `@@...$important` overrides a global
    // `$important` block (the old code returned the global block first).
    assert!(matches!(
        combine_tier_verdicts(Some(block()), Some(allow())),
        Some(Verdict::Allow(_))
    ));
    // A global important allow still beats a group important block.
    assert!(matches!(
        combine_tier_verdicts(Some(allow()), Some(block())),
        Some(Verdict::Allow(_))
    ));
    // Important outranks standard because callers evaluate it first; the
    // helper itself only compares within a tier.
    assert!(combine_tier_verdicts(None, None).is_none());
}

/// Deferred D3 follow-up: on the CNAME-target path a `$dnsrewrite` is not
/// actionable. In the `$important` tier it must be dropped (not converted
/// to `Allow(None)`) so it cannot skip later parental/service/standard
/// checks, and it must not hide an important block.
#[test]
fn test_cname_target_important_rewrite_is_dropped() {
    use sito_core::verdict::{BlockReason, RewriteAction, RuleRef};

    let block = || {
        Verdict::Block(BlockReason::Rule(RuleRef::new(
            "||blocked-target.example^".to_string(),
        )))
    };
    let allow = || {
        Verdict::Allow(Some(RuleRef::new(
            "@@||blocked-target.example^".to_string(),
        )))
    };
    let rewrite = || {
        Verdict::Rewrite(RewriteAction::DnsRewrite {
            rcode: "NOERROR".to_string(),
            rtype: Some("A".to_string()),
            value: Some("192.0.2.10".to_string()),
        })
    };

    // Critical regression: a lone important rewrite is no verdict at all,
    // so the caller falls through to parental/service/standard checks.
    assert!(
        combine_cname_target_tier_verdicts(Some(rewrite()), None).is_none(),
        "an important CNAME rewrite must not become a real allow"
    );
    // A rewrite cannot hide an important block in either position.
    assert!(matches!(
        combine_cname_target_tier_verdicts(Some(block()), Some(rewrite())),
        Some(Verdict::Block(_))
    ));
    assert!(matches!(
        combine_cname_target_tier_verdicts(Some(rewrite()), Some(block())),
        Some(Verdict::Block(_))
    ));
    // A real allow still wins.
    assert!(matches!(
        combine_cname_target_tier_verdicts(Some(allow()), Some(rewrite())),
        Some(Verdict::Allow(Some(_)))
    ));
    assert!(matches!(
        combine_cname_target_tier_verdicts(Some(block()), Some(allow())),
        Some(Verdict::Allow(Some(_)))
    ));
    // Two rewrites are also dropped.
    assert!(combine_cname_target_tier_verdicts(Some(rewrite()), Some(rewrite())).is_none());
}
/// P1-27 regression: the DNSSEC insert epoch must come from the same
/// runtime snapshot as the validator. A query that loaded the old snapshot
/// cannot insert under the new epoch after an apply.
#[tokio::test]
async fn test_pipeline_uses_snapshot_generation_for_dnssec_cache_insert() {
    let mut config = Config::default();
    config.dns.dnssec.validate = false;
    let (pipeline, _calls, temp_dir) = test_pipeline(config.clone()).await;

    let old_snapshot = pipeline.runtime().snapshot();
    let old_generation = old_snapshot.generation;

    let mut next = config.clone();
    next.dns.dnssec.mode = "log_only".to_string();
    let plan = sito_runtime::ApplyPlan {
        config: next.clone(),
        clients: Default::default(),
        rewrites: Default::default(),
        filter: old_snapshot.filter.clone(),
        group_filters: old_snapshot.group_filters.clone(),
        dnssec_policy: sito_runtime::DnssecPolicy::from_config(&next.dns.dnssec),
        cache_policy: next.dns.cache.clone(),
        transport_policy: sito_runtime::TransportPolicy::from(&next),
    };
    pipeline
        .runtime()
        .apply(plan)
        .await
        .expect("policy change apply");
    assert!(pipeline.runtime().generation() > old_generation);

    // The epoch used for an insert must be the snapshot's generation, not
    // a fresh live read that a concurrent apply already advanced.
    assert_eq!(DnsPipeline::cache_epoch_for(&old_snapshot), old_generation);
    assert_ne!(
        DnsPipeline::cache_epoch_for(&old_snapshot),
        pipeline.cache.policy_epoch()
    );

    let name = Name::from_str("generation.example.").unwrap();
    let mut query = Message::new(9, MessageType::Query, OpCode::Query);
    query
        .queries
        .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
    let mut response = Message::response(9, OpCode::Query);
    response.queries = query.queries.clone();
    response.answers.push(Record::from_rdata(
        name.clone(),
        300,
        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 9))),
    ));

    // The in-flight query used the old snapshot's validator and captured
    // its generation; the insert must be rejected.
    assert!(
        !pipeline
            .cache
            .insert_with_status_at_epoch(
                &query,
                &response,
                ValidationStatus::Insecure,
                old_generation,
            )
            .await,
        "an insert tagged with the old snapshot generation must be rejected"
    );
    assert!(
        pipeline
            .cache
            .get(&name, RecordType::A, sito_proto::DNSClass::IN)
            .await
            .is_none()
    );

    // The current generation is accepted.
    let current = pipeline.runtime().generation();
    assert!(
        pipeline
            .cache
            .insert_with_status_at_epoch(&query, &response, ValidationStatus::Insecure, current,)
            .await
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}
