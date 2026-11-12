//! WP-0.3 hostile DNSSEC integration suite.
//!
//! These tests exercise the real UDP query path and the shared chain-cache
//! policy boundary. They complement the focused unit tests in `sito-dnssec`:
//! no validator internals are patched here, only the same public pipeline and
//! cache APIs used in production.

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{LowerName, Name, RData, Record, RecordType};
use sito_core::config::{Config, DnssecConfig};
use sito_dnssec::{ChainCache, DnssecValidator};
use sito_proto::rdata::{A, CNAME};
use sito_proto::{decode_message, encode_message};
use sito_test::fixtures::dnssec::SignedZone;
use sito_test::{MockDnsServer, TestServerInstance};
use tokio::task::JoinHandle;

/// Upstream that answers ordinary names but black-holes DNSKEY/DS lookups.
///
/// Dropping those packets (rather than returning NXDOMAIN) exercises the
/// wall-clock validation deadline: without it the probe future would stay
/// pending forever.
async fn spawn_blackholed_key_upstream() -> (SocketAddr, JoinHandle<()>) {
    let (socket, claim) = sito_test::fixtures::net::bind_claimed_udp()
        .await
        .expect("bind mock");
    let addr = socket.local_addr().expect("mock addr");
    let handle = tokio::spawn(async move {
        let _claim = claim;
        let mut buf = [0u8; 4096];
        loop {
            let Ok((len, src)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let Ok(query) = decode_message(&buf[..len]) else {
                continue;
            };
            let Some(question) = query.queries.first() else {
                continue;
            };
            if matches!(question.query_type(), RecordType::DNSKEY | RecordType::DS) {
                // Deliberately no reply.
                continue;
            }

            let mut response =
                Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            response.metadata.recursion_desired = query.metadata.recursion_desired;
            response.metadata.recursion_available = true;
            response.metadata.checking_disabled = query.metadata.checking_disabled;
            response.queries.clone_from(&query.queries);
            response.metadata.response_code = ResponseCode::NoError;

            let qname = question.name().clone();
            if qname.to_ascii().starts_with("h0.chain.example.") {
                // Eight CNAME hops, unsigned, so the pipeline probes the chain
                // and then blocks on the first key fetch.
                for hop in 0..8u32 {
                    let current = Name::from_str(&format!("h{hop}.chain.example.")).expect("hop");
                    let next =
                        Name::from_str(&format!("h{}.chain.example.", hop + 1)).expect("next");
                    response.answers.push(Record::from_rdata(
                        current,
                        300,
                        RData::CNAME(CNAME(next)),
                    ));
                }
            } else {
                response.answers.push(Record::from_rdata(
                    qname,
                    300,
                    RData::A(A(Ipv4Addr::new(192, 0, 2, 200))),
                ));
            }

            if let Ok(encoded) = encode_message(&response) {
                let _ = socket.send_to(&encoded, src).await;
            }
        }
    });
    (addr, handle)
}

fn validating_config(upstream: SocketAddr) -> Config {
    let mut config = Config::default();
    config.upstream.servers = vec![upstream.to_string()];
    config.dns.dnssec.validate = true;
    config.dns.dnssec.mode = "validate".to_string();
    // Keep each query independent; the policy/deadline behavior must not be
    // masked by a cached status from an earlier test query.
    config.dns.cache.enabled = false;
    config
}

/// CD=1 is the client taking responsibility for validation. Even when a CD=0
/// query for the same unsigned name fails closed with SERVFAIL, CD=1 must get
/// the upstream data with AD=0.
#[tokio::test]
async fn test_m11_cd1_bypasses_post_fetch_indeterminate() {
    let mock = MockDnsServer::spawn().await.expect("mock upstream");
    mock.add_a_record("cd-unsigned.example", Ipv4Addr::new(192, 0, 2, 10), 300);
    let server = TestServerInstance::spawn(validating_config(mock.addr()))
        .await
        .expect("spawn server");
    let client = server.client();

    let strict = client
        .query_udp_dnssec("cd-unsigned.example", RecordType::A)
        .await
        .expect("strict query");
    assert_eq!(
        strict.metadata.response_code,
        ResponseCode::ServFail,
        "a never-proven unsigned zone must fail closed for CD=0: {strict:?}"
    );

    let cd = client
        .query_udp_cd("cd-unsigned.example", RecordType::A)
        .await
        .expect("CD=1 query");
    assert_eq!(
        cd.metadata.response_code,
        ResponseCode::NoError,
        "CD=1 must return the upstream answer: {cd:?}"
    );
    assert!(
        !cd.answers.is_empty(),
        "CD=1 response must carry the unvalidated answer"
    );
    assert!(!cd.metadata.authentic_data, "CD=1 must never assert AD");

    server.shutdown().await.expect("shutdown");
}

/// A blocked DNSKEY/DS fetch must be cut off by the pipeline deadline and
/// return SERVFAIL, not pin the query forever.
#[tokio::test]
async fn test_m11_blocked_key_fetch_is_bounded_and_servfails() {
    let (upstream, upstream_task) = spawn_blackholed_key_upstream().await;
    let server = TestServerInstance::spawn(validating_config(upstream))
        .await
        .expect("spawn server");
    let client = server.client().with_timeout(Duration::from_secs(9));

    let started = Instant::now();
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        client.query_udp_dnssec("blocked.example", RecordType::A),
    )
    .await
    .expect("the query must finish within the test bound")
    .expect("query");
    let elapsed = started.elapsed();

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::ServFail,
        "a blocked key fetch must fail closed: {response:?}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "the DNSSEC deadline must bound a blocked fetch, took {elapsed:?}"
    );

    server.shutdown().await.expect("shutdown");
    upstream_task.abort();
}

/// An eight-CNAME chain under the same blocked-key upstream must still finish
/// inside the deadline. This is the end-to-end amplification bound.
#[tokio::test]
async fn test_m11_eight_hop_chain_is_bounded_end_to_end() {
    let (upstream, upstream_task) = spawn_blackholed_key_upstream().await;
    let server = TestServerInstance::spawn(validating_config(upstream))
        .await
        .expect("spawn server");
    let client = server.client().with_timeout(Duration::from_secs(9));

    let started = Instant::now();
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        client.query_udp_dnssec("h0.chain.example", RecordType::A),
    )
    .await
    .expect("the eight-hop query must finish within the test bound")
    .expect("query");
    let elapsed = started.elapsed();

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::ServFail,
        "the blocked eight-hop chain must fail closed: {response:?}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "the deadline must bound the whole eight-hop chain, took {elapsed:?}"
    );

    server.shutdown().await.expect("shutdown");
    upstream_task.abort();
}

/// A policy change bumps the chain-cache generation. A validator built under
/// the old policy (as an in-flight query would hold) must not insert afterwards
/// and resurrect stale evidence that the reload just flushed.
#[tokio::test]
async fn test_m11_policy_change_rejects_in_flight_cache_insert() {
    let cache = Arc::new(ChainCache::new(None));
    let zone = SignedZone::new("race.example.");
    let origin = zone.origin.clone();
    let (answer, rrsig) = zone.apex_a(Ipv4Addr::new(93, 184, 216, 34));
    let anchor_a = zone.trust_anchor();

    let old_config = DnssecConfig {
        validate: true,
        mode: "validate".to_string(),
        trust_anchors: vec![anchor_a.clone()],
        ..Default::default()
    };
    let old_validator =
        DnssecValidator::from_config_with_cache(&old_config, Some(Arc::clone(&cache)));
    let old_generation = cache.policy_generation();

    // Reload adds an unrelated anchor: the shared cache generation advances.
    let other_zone = SignedZone::new("other.example.");
    let anchor_b = other_zone.trust_anchor();
    let new_config = DnssecConfig {
        validate: true,
        mode: "validate".to_string(),
        trust_anchors: vec![anchor_a, anchor_b],
        ..Default::default()
    };
    let new_validator =
        DnssecValidator::from_config_with_cache(&new_config, Some(Arc::clone(&cache)));
    assert!(
        cache.policy_generation() > old_generation,
        "a policy change must advance the generation"
    );

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let build_response = || {
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message
            .queries
            .push(Query::query(origin.clone(), RecordType::A));
        message.answers.push(answer.clone());
        message.answers.push(rrsig.clone());
        message.additionals.push(zone.dnskey_record());
        message
    };

    // The old validator still validates locally (in-flight query), but its
    // cache insert belongs to the previous policy generation.
    let mut in_flight = build_response();
    assert_eq!(
        old_validator.validate_response(&mut in_flight, Some("old-policy"), now),
        sito_dnssec::ValidationOutcome::Secure
    );
    assert!(
        cache.get(&LowerName::from(&origin), now).is_none(),
        "an old-generation insert must be rejected after the reload"
    );

    // The reloaded validator can populate the same entry under the new policy.
    let mut after_reload = build_response();
    assert_eq!(
        new_validator.validate_response(&mut after_reload, Some("new-policy"), now),
        sito_dnssec::ValidationOutcome::Secure
    );
    assert!(
        cache.get(&LowerName::from(&origin), now).is_some(),
        "the new-policy validator must be able to insert"
    );
}
