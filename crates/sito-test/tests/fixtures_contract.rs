//! Contract tests for the shared mock fixtures (WP-1.8).

use std::time::Duration;

use sito_test::fixtures::acme::MockHttp01Server;
use sito_test::fixtures::dnssec::SignedZone;
use sito_test::fixtures::tls::{
    CertificateFiles, days_until_expiration, expired_certificate, soon_to_expire_certificate,
    test_certificate,
};

#[test]
fn tls_fixtures_cover_valid_expired_and_soon_to_expire_certificates() {
    let valid = test_certificate(&["valid.example.test", "127.0.0.1"]);
    assert!(
        days_until_expiration(&valid.cert_pem) > 300,
        "the standard fixture must be comfortably valid"
    );

    let expired = expired_certificate(&["expired.example.test"]);
    assert!(
        days_until_expiration(&expired.cert_pem) < 0,
        "the expired fixture must be in the past"
    );

    let soon = soon_to_expire_certificate(&["soon.example.test"], 3);
    let days = days_until_expiration(&soon.cert_pem);
    assert!(
        (0..=4).contains(&days),
        "the soon-to-expire fixture must be inside the renewal window, got {days}"
    );

    let files = CertificateFiles::soon_to_expire("contract", &["files.example.test"], 2)
        .expect("write certificate files");
    assert!(files.cert_path().exists());
    assert!(files.key_path().exists());
    let cert_pem = std::fs::read_to_string(files.cert_path()).expect("read cert");
    assert!((0..=3).contains(&days_until_expiration(&cert_pem)));
}

#[tokio::test]
async fn http01_fixture_serves_registered_tokens_only() {
    let server = MockHttp01Server::start().await.expect("start challenge");
    assert!(
        !sito_test_support::claim_ports(&[server.addr().port()]),
        "fixture listeners must claim their port in the broker"
    );
    server.add_token("token-1", "token-1.key-auth");

    let client = reqwest::Client::new();
    let ok = client
        .get(server.url("token-1"))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .expect("challenge request");
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    assert_eq!(ok.text().await.expect("body"), "token-1.key-auth");
    assert_eq!(server.hits(), 1);

    let missing = client
        .get(server.url("token-2"))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .expect("missing challenge request");
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
}

#[test]
fn signed_zone_fixture_exposes_anchor_keys_and_denial_records() {
    use hickory_proto::dnssec::rdata::DNSSECRData;
    use hickory_proto::rr::{Name, RData, RecordType};
    use sito_dnssec::nsec::{NsecDenial, NsecRecord, evaluate_nsec_denial};

    let zone = SignedZone::new("fixture.example.");
    assert_eq!(zone.trust_anchor().split(':').count(), 3);
    assert!(zone.trust_anchor().contains(":13:"));

    let (answer, rrsig) = zone.apex_a(std::net::Ipv4Addr::new(192, 0, 2, 53));
    assert_eq!(answer.record_type(), hickory_proto::rr::RecordType::A);
    assert_eq!(
        rrsig.record_type(),
        hickory_proto::rr::RecordType::RRSIG,
        "the answer must carry a signature"
    );

    let (dnskey_answers, _) = zone.dnskey_rrset();
    assert_eq!(dnskey_answers.len(), 2, "DNSKEY plus its RRSIG");

    let qname = Name::from_ascii("missing.fixture.example.").expect("qname");
    let denial = zone.nsec_covering(&qname);
    assert_eq!(denial.len(), 2, "qname denial plus wildcard denial");
    for (nsec, signature) in &denial {
        assert_eq!(nsec.record_type(), RecordType::NSEC);
        assert_eq!(signature.record_type(), RecordType::RRSIG);
    }

    // Feed the fixture through the production denial evaluator: a covering
    // NSEC for the qname plus one covering `*.fixture.example` must prove
    // NXDOMAIN.
    let records: Vec<NsecRecord<'_>> = denial
        .iter()
        .map(|(record, _)| match &record.data {
            RData::DNSSEC(DNSSECRData::NSEC(nsec)) => NsecRecord {
                owner: &record.name,
                rdata: nsec,
            },
            _ => panic!("fixture denial record must be NSEC"),
        })
        .collect();
    assert_eq!(
        evaluate_nsec_denial(&records, &qname, RecordType::A, true, &zone.origin),
        NsecDenial::Secure,
        "fixture NSEC records must be a complete NXDOMAIN proof"
    );

    // Regression: a record *owned by* the wildcard is an exact wildcard match,
    // not a covering NSEC for `*.fixture.example`. It must not complete the
    // NXDOMAIN proof (this was the old fixture bug).
    let a_owner = Name::from_ascii("a.fixture.example.").expect("owner");
    let zzz = Name::from_ascii("zzz.fixture.example.").expect("next");
    let wildcard = Name::from_ascii("*.fixture.example.").expect("wildcard");
    let old_style = [
        zone.nsec(
            &a_owner,
            &zzz,
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        ),
        zone.nsec(
            &wildcard,
            &zzz,
            &[
                RecordType::A,
                RecordType::NS,
                RecordType::SOA,
                RecordType::RRSIG,
                RecordType::NSEC,
            ],
        ),
    ];
    let old_records: Vec<NsecRecord<'_>> = old_style
        .iter()
        .map(|(record, _)| match &record.data {
            RData::DNSSEC(DNSSECRData::NSEC(nsec)) => NsecRecord {
                owner: &record.name,
                rdata: nsec,
            },
            _ => panic!("fixture denial record must be NSEC"),
        })
        .collect();
    assert_eq!(
        evaluate_nsec_denial(&old_records, &qname, RecordType::A, true, &zone.origin),
        NsecDenial::Incomplete,
        "an exact wildcard-owned NSEC must not prove NXDOMAIN"
    );
}

#[tokio::test]
async fn manual_clock_drives_a_deterministic_mock_upstream_delay() {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use sito_proto::{decode_message, encode_message};
    use sito_test::{ManualClock, MockDnsServer};
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    let clock = Arc::new(ManualClock::new());
    let mock = MockDnsServer::spawn().await.expect("spawn mock");
    mock.add_a_record("slow.example", std::net::Ipv4Addr::new(192, 0, 2, 1), 60);
    mock.set_response_delay(
        Arc::clone(&clock) as Arc<dyn sito_test::Clock>,
        Duration::from_secs(5),
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    socket.connect(mock.addr()).await.expect("connect mock");
    let mut query = Message::new(1, MessageType::Query, OpCode::Query);
    query.queries.push(Query::query(
        Name::from_ascii("slow.example.").expect("name"),
        RecordType::A,
    ));
    let wire = encode_message(&query).expect("encode query");
    let first_wire = wire.clone();
    let receiver = tokio::spawn(async move {
        socket.send(&first_wire).await.expect("send query");
        let mut buffer = [0u8; 4096];
        let len = socket.recv(&mut buffer).await.expect("receive response");
        decode_message(&buffer[..len]).expect("decode response")
    });

    for _ in 0..200 {
        if mock.query_count() == 1 && clock.waiters() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(clock.waiters(), 1, "the mock must park on the manual clock");
    assert!(
        !receiver.is_finished(),
        "no response may be sent before advance"
    );

    // A second query must still be received while the first response is
    // parked: the delay runs in a per-query task, not the receive loop.
    let second_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client 2");
    second_socket
        .connect(mock.addr())
        .await
        .expect("connect mock 2");
    let second_wire = wire.clone();
    second_socket
        .send(&second_wire)
        .await
        .expect("send second query");
    for _ in 0..200 {
        if mock.query_count() == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        mock.query_count(),
        2,
        "the mock receive loop must not be blocked by a parked response"
    );

    clock.advance(Duration::from_secs(5));
    let response = tokio::time::timeout(Duration::from_secs(1), receiver)
        .await
        .expect("the response must be released by the clock advance")
        .expect("receiver task");
    assert_eq!(response.answers.len(), 1);

    let mut buffer = [0u8; 4096];
    let len = tokio::time::timeout(Duration::from_secs(1), second_socket.recv(&mut buffer))
        .await
        .expect("the second response must be released too")
        .expect("receive second response");
    decode_message(&buffer[..len]).expect("decode second response");
}

#[tokio::test]
async fn fake_master_stops_cleanly_before_a_slave_connects() {
    use sito_test::fixtures::ha::FakeMaster;

    let master = FakeMaster::start().await.expect("start fake master");
    master
        .wait_stopped()
        .await
        .expect("wait_stopped must not hang in accept()");
}

#[tokio::test]
async fn fake_master_heartbeat_is_driven_by_the_manual_clock() {
    use futures_util::SinkExt as _;
    use futures_util::StreamExt as _;
    use sito_ha::HaMessage;
    use sito_test::ManualClock;
    use sito_test::fixtures::ha::FakeMaster;
    use std::sync::Arc;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    let master = FakeMaster::start().await.expect("start fake master");
    assert!(
        !sito_test_support::claim_ports(&[master.addr().port()]),
        "FakeMaster must claim its listener port in the broker"
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(master.url())
        .await
        .expect("connect fake master");
    // The fixture consumes the slave's Hello before processing controls.
    ws.send(WsMessage::Text(
        HaMessage::Hello {
            instance: "fixture-slave".to_string(),
            have_version: 0,
            have_term: 0,
            capabilities: vec![],
            token: None,
            role: Some("slave".to_string()),
            protocol_version: Some(sito_ha::PROTOCOL_VERSION),
        }
        .to_json()
        .expect("hello json")
        .into(),
    ))
    .await
    .expect("send hello");

    let clock = Arc::new(ManualClock::new());
    let scheduled = master.schedule_heartbeat(Arc::clone(&clock), Duration::from_secs(15), 42);
    for _ in 0..200 {
        if clock.waiters() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        clock.waiters(),
        1,
        "the heartbeat must wait on the manual clock"
    );

    clock.advance(Duration::from_secs(14));
    tokio::task::yield_now().await;
    assert!(!scheduled.is_finished(), "the heartbeat is not due yet");

    clock.advance(Duration::from_secs(1));
    let frame = tokio::time::timeout(Duration::from_secs(1), ws.next())
        .await
        .expect("heartbeat must arrive after advance")
        .expect("websocket frame")
        .expect("websocket error");
    let text = frame.into_text().expect("text frame");
    assert!(
        text.contains("\"ping\"") && text.contains("42"),
        "expected a ping with ts=42, got {text}"
    );
}
