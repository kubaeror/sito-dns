#![cfg(test)]

use super::test_util::*;
use super::*;
use hickory_proto::op::{MessageType, OpCode, Query};
use hickory_proto::rr::RecordData;
use hickory_proto::rr::RecordType;
use hickory_proto::rr::rdata::A;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

#[test]
fn test_dnssec_secure_validation() {
    let (origin, dnskey, a_record, rrsig_record, _) =
        create_test_signed_domain("secure.example.com.");

    let mut trust_anchors = TrustAnchors::empty();
    trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));

    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(trust_anchors);

    let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(origin.clone(), RecordType::A));
    msg.answers.push(a_record);
    msg.answers.push(rrsig_record);
    msg.additionals.push(Record::from_rdata(
        origin,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("1.1.1.1"), now);

    assert_eq!(outcome, ValidationOutcome::Secure);
    assert!(msg.metadata.authentic_data);
    assert_eq!(validator.metrics.get_validations("secure"), 1);
}

#[test]
fn test_dnssec_bogus_tampered_record() {
    let (origin, dnskey, _a_record, rrsig_record, _) =
        create_test_signed_domain("tampered.example.com.");

    let mut trust_anchors = TrustAnchors::empty();
    trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));

    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(trust_anchors);

    let mut msg = Message::new(2, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(origin.clone(), RecordType::A));
    // Tampered IP (9.9.9.9 instead of 93.184.216.34)
    let tampered_record =
        Record::from_rdata(origin.clone(), 300, RData::A(A(Ipv4Addr::new(9, 9, 9, 9))));
    msg.answers.push(tampered_record);
    msg.answers.push(rrsig_record);
    msg.additionals.push(Record::from_rdata(
        origin,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("8.8.8.8"), now);

    assert!(matches!(
        outcome,
        ValidationOutcome::Bogus { ede_code: 6, .. }
    ));
    assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
    assert!(!msg.metadata.authentic_data);
    assert!(
        msg.answers.is_empty(),
        "bogus response must not carry answers: {:?}",
        msg.answers
    );
    assert_eq!(validator.metrics.get_validations("bogus"), 1);
    assert_eq!(
        validator
            .metrics
            .get_bogus("8.8.8.8", "Cryptographic signature verification failed"),
        1
    );
}

#[test]
fn test_dnssec_bogus_log_only_mode() {
    let (origin, dnskey, _a_record, rrsig_record, _) =
        create_test_signed_domain("logonly.example.com.");

    let mut trust_anchors = TrustAnchors::empty();
    trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));

    let validator =
        DnssecValidator::new(DnssecMode::LogOnly, Vec::new()).with_trust_anchors(trust_anchors);

    let mut msg = Message::new(3, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(origin.clone(), RecordType::A));
    let tampered_record =
        Record::from_rdata(origin.clone(), 300, RData::A(A(Ipv4Addr::new(1, 1, 1, 1))));
    msg.answers.push(tampered_record);
    msg.answers.push(rrsig_record);
    msg.additionals.push(Record::from_rdata(
        origin,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("9.9.9.9"), now);

    assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
    // Log-only mode does not SERVFAIL and preserves answers, but clears AD bit
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert!(!msg.metadata.authentic_data);
    assert_eq!(msg.answers.len(), 2);
}

#[test]
fn test_dnssec_expired_signature() {
    let (origin, dnskey, a_record, rrsig_record, _) =
        create_test_signed_domain("expired.example.com.");

    let mut trust_anchors = TrustAnchors::empty();
    trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));

    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(trust_anchors);

    let mut msg = Message::new(4, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(origin.clone(), RecordType::A));
    msg.answers.push(a_record);
    msg.answers.push(rrsig_record);
    msg.additionals.push(Record::from_rdata(
        origin,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));

    // Validate at a future time past expiration (10 days in future)
    let future =
        (time::OffsetDateTime::now_utc() + Duration::from_hours(240)).unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("1.1.1.1"), future);

    assert_eq!(
        outcome,
        ValidationOutcome::Bogus {
            reason: "Signature expired".to_string(),
            ede_code: EDE_SIGNATURE_EXPIRED,
        }
    );
    assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(validator.metrics.get_validations("bogus"), 1);
    assert_eq!(
        validator.metrics.get_bogus("1.1.1.1", "Signature expired"),
        1
    );
}

use sito_core::error::UpstreamError;

struct StaticFetcher {
    responses: std::collections::HashMap<(LowerName, RecordType), Message>,
    calls: std::sync::atomic::AtomicUsize,
}

impl StaticFetcher {
    fn new() -> Self {
        Self {
            responses: std::collections::HashMap::new(),
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn with(mut self, name: &Name, rtype: RecordType, message: Message) -> Self {
        self.responses
            .insert((LowerName::from(name), rtype), message);
        self
    }

    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl DnssecKeyFetcher for StaticFetcher {
    async fn query(&self, name: &Name, rtype: RecordType) -> Result<Message, UpstreamError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(self
            .responses
            .get(&(LowerName::from(name), rtype))
            .cloned()
            .unwrap_or_else(|| Message::new(0, MessageType::Response, OpCode::Query)))
    }
}

fn fetched_dnskey_message(owner: &Name, keys: &[DNSKEY], signature: Option<Record>) -> Message {
    let mut message = Message::new(0, MessageType::Response, OpCode::Query);
    for key in keys {
        message.additionals.push(Record::from_rdata(
            owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(key.clone())),
        ));
    }
    if let Some(signature) = signature {
        message.additionals.push(signature);
    }
    message
}

/// A fetched DNSKEY response with a self-signature, as a validating
/// resolver's chain walk receives from a signed zone.
fn signed_dnskey_message(
    owner: &Name,
    key: &DNSKEY,
    signer: &hickory_proto::dnssec::DnssecSigner,
) -> Message {
    use hickory_proto::rr::RecordSet;

    let record = Record::from_rdata(
        owner.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(key.clone())),
    );
    let mut set = RecordSet::new(owner.clone(), RecordType::DNSKEY, 0);
    set.insert(record.clone(), 0);
    let signature = sign_test_rrset(&set, signer);
    let mut message = Message::new(0, MessageType::Response, OpCode::Query);
    message.additionals.push(record);
    message.additionals.push(signature);
    message
}

/// A fetched DS response for `child`, signed by the parent zone.
fn signed_ds_fetch_message(
    child: &Name,
    child_key: &DNSKEY,
    parent_signer: &hickory_proto::dnssec::DnssecSigner,
) -> Message {
    use hickory_proto::dnssec::DigestType;
    use hickory_proto::rr::RecordSet;

    let ds = DS::from_key(child_key.public_key(), child, DigestType::SHA256).expect("ds");
    let record = Record::from_rdata(child.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
    let mut set = RecordSet::new(child.clone(), RecordType::DS, 0);
    set.insert(record.clone(), 0);
    let signature = sign_test_rrset(&set, parent_signer);
    let mut message = Message::new(0, MessageType::Response, OpCode::Query);
    message.authorities.push(record);
    message.authorities.push(signature);
    message
}

fn signed_a_response(
    origin: &Name,
    signer: &hickory_proto::dnssec::DnssecSigner,
) -> (Record, Record) {
    use hickory_proto::rr::RecordSet;
    let answer = Record::from_rdata(
        origin.clone(),
        300,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 7))),
    );
    let mut set = RecordSet::new(origin.clone(), RecordType::A, 0);
    set.insert(answer.clone(), 0);
    (answer, sign_test_rrset(&set, signer))
}

#[allow(clippy::too_many_arguments)]
fn signed_nsec_response(
    origin: &Name,
    nsec_owner: &Name,
    next: &Name,
    bitmap: &[RecordType],
    qname: &Name,
    dnskey: &DNSKEY,
    signer: &hickory_proto::dnssec::DnssecSigner,
    response_code: ResponseCode,
) -> Message {
    signed_nsec_response_records(
        origin,
        &[(nsec_owner.clone(), next.clone(), bitmap.to_vec())],
        qname,
        dnskey,
        signer,
        response_code,
    )
}

/// Builds a signed negative response containing one or more NSEC RRsets.
fn signed_nsec_response_records(
    origin: &Name,
    nsecs: &[(Name, Name, Vec<RecordType>)],
    qname: &Name,
    dnskey: &DNSKEY,
    signer: &hickory_proto::dnssec::DnssecSigner,
    response_code: ResponseCode,
) -> Message {
    use hickory_proto::dnssec::rdata::NSEC;
    use hickory_proto::rr::RecordSet;

    let mut msg = Message::new(24, MessageType::Response, OpCode::Query);
    msg.queries.push(Query::query(qname.clone(), RecordType::A));
    msg.metadata.response_code = response_code;

    for (owner, next, bitmap) in nsecs {
        let nsec = NSEC::new(next.clone(), bitmap.iter().copied());
        let nsec_record =
            Record::from_rdata(owner.clone(), 300, RData::DNSSEC(DNSSECRData::NSEC(nsec)));
        let mut set = RecordSet::new(owner.clone(), RecordType::NSEC, 0);
        set.insert(nsec_record.clone(), 0);
        let nsec_sig = sign_test_rrset(&set, signer);
        msg.authorities.push(nsec_record);
        msg.authorities.push(nsec_sig);
    }

    msg.additionals.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
    ));
    msg
}

fn nsec_next(origin: &Name) -> Name {
    Name::from_str(&format!("zzz.{}", origin.to_ascii())).unwrap()
}

#[test]
fn test_nxdomain_with_nsec_is_secure() {
    let (origin, dnskey, signer) = create_test_signer("nsec.example.");
    let qname = Name::from_str("missing.nsec.example.").unwrap();

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    // A complete NXDOMAIN proof: one NSEC covers the qname and another
    // covers the wildcard `*.nsec.example`, so no wildcard could have
    // synthesized the name.
    let bitmap = vec![RecordType::A, RecordType::NSEC, RecordType::RRSIG];
    let mut msg = signed_nsec_response_records(
        &origin,
        &[
            (
                origin.clone(),
                Name::from_str("a.nsec.example.").unwrap(),
                bitmap.clone(),
            ),
            (
                Name::from_str("a.nsec.example.").unwrap(),
                nsec_next(&origin),
                bitmap,
            ),
        ],
        &qname,
        &dnskey,
        &signer,
        ResponseCode::NXDomain,
    );
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("test"), now);

    assert_eq!(outcome, ValidationOutcome::Secure);
    assert!(msg.metadata.authentic_data);
}

#[test]
fn test_nxdomain_without_wildcard_denial_is_bogus() {
    let (origin, dnskey, signer) = create_test_signer("nsec.example.");
    let qname = Name::from_str("missing.nsec.example.").unwrap();

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    // Only the qname is covered; nothing proves that `*.nsec.example` does
    // not exist, so the NXDOMAIN must not be authenticated.
    let mut msg = signed_nsec_response(
        &origin,
        &Name::from_str("a.nsec.example.").unwrap(),
        &nsec_next(&origin),
        &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        &qname,
        &dnskey,
        &signer,
        ResponseCode::NXDomain,
    );
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("test"), now);

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "missing wildcard denial must be Bogus, got {outcome:?}"
    );
    assert!(!msg.metadata.authentic_data);
}

#[test]
fn test_nodata_with_nsec_is_secure() {
    let (origin, dnskey, signer) = create_test_signer("nsec.example.");
    let qname = Name::from_str("empty.nsec.example.").unwrap();

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    // A correct NSEC NODATA proof sits at the queried name and its bitmap
    // denies both the queried type and CNAME.
    let mut msg = signed_nsec_response(
        &origin,
        &qname,
        &nsec_next(&origin),
        &[RecordType::SOA, RecordType::NSEC, RecordType::RRSIG],
        &qname,
        &dnskey,
        &signer,
        ResponseCode::NoError,
    );
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("test"), now);

    assert_eq!(outcome, ValidationOutcome::Secure);
}

/// The validator accepts a denial proof carried in the additional section
/// (`evaluate_denial` and the RRSIG loop both scan it). The SOA TTL cap
/// must use the same sections, otherwise moving a genuine NSEC/RRSIG from
/// authority to additional would leave a Secure negative with the SOA's
/// long lifetime.
#[test]
fn test_negative_proof_in_additionals_caps_soa_ttl() {
    use hickory_proto::dnssec::rdata::NSEC;
    use hickory_proto::rr::RecordSet;
    use hickory_proto::rr::rdata::SOA;

    let (origin, dnskey, signer) = create_test_signer("addl.example.");
    let qname = Name::from_str("empty.addl.example.").unwrap();

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let mut msg = Message::new(30, MessageType::Response, OpCode::Query);
    msg.queries.push(Query::query(qname.clone(), RecordType::A));
    msg.metadata.response_code = ResponseCode::NoError;

    // A long-lived signed SOA in the authority section.
    let soa = Record::from_rdata(
        origin.clone(),
        3600,
        RData::SOA(SOA::new(
            Name::from_str("ns1.addl.example.").unwrap(),
            Name::from_str("hostmaster.addl.example.").unwrap(),
            1,
            7200,
            3600,
            1_209_600,
            3600,
        )),
    );
    let mut soa_set = RecordSet::new(origin.clone(), RecordType::SOA, 3600);
    soa_set.insert(soa.clone(), 0);
    let mut soa_sig = sign_test_rrset(&soa_set, &signer);
    soa_sig.ttl = 3600;
    msg.authorities.push(soa);
    msg.authorities.push(soa_sig);

    // The NSEC NODATA proof and its signature live in the additional
    // section, with a short 10 s lifetime.
    let nsec = NSEC::new(
        Name::from_str("zzz.addl.example.").unwrap(),
        [RecordType::SOA, RecordType::NSEC, RecordType::RRSIG],
    );
    let nsec_record = Record::from_rdata(qname.clone(), 10, RData::DNSSEC(DNSSECRData::NSEC(nsec)));
    let mut nsec_set = RecordSet::new(qname.clone(), RecordType::NSEC, 10);
    nsec_set.insert(nsec_record.clone(), 0);
    let mut nsec_sig = sign_test_rrset(&nsec_set, &signer);
    nsec_sig.ttl = 10;
    msg.additionals.push(nsec_record);
    msg.additionals.push(nsec_sig);
    msg.additionals.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("addl"), now);
    assert_eq!(outcome, ValidationOutcome::Secure);

    let soa_ttl = msg
        .authorities
        .iter()
        .find(|record| record.record_type() == RecordType::SOA)
        .expect("SOA")
        .ttl;
    assert_eq!(
        soa_ttl, 10,
        "the SOA TTL must be capped by an additional-section denial proof"
    );
}

#[test]
fn test_nodata_with_wrong_nsec_bitmap_is_bogus() {
    let (origin, dnskey, signer) = create_test_signer("nsec.example.");
    let qname = Name::from_str("empty.nsec.example.").unwrap();

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    // The bitmap still lists A at the queried name: no denial proof.
    let mut msg = signed_nsec_response(
        &origin,
        &qname,
        &nsec_next(&origin),
        &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        &qname,
        &dnskey,
        &signer,
        ResponseCode::NoError,
    );
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("test"), now);

    assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
    assert!(!msg.metadata.authentic_data);
}

#[test]
fn test_nxdomain_with_wrong_nsec_owner_is_bogus() {
    let (origin, dnskey, signer) = create_test_signer("nsec.example.");
    let qname = Name::from_str("missing.nsec.example.").unwrap();

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    // Owner "aaa" / next "bbb" does not cover "missing".
    let mut msg = signed_nsec_response(
        &origin,
        &Name::from_str("aaa.nsec.example.").unwrap(),
        &Name::from_str("bbb.nsec.example.").unwrap(),
        &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        &qname,
        &dnskey,
        &signer,
        ResponseCode::NXDomain,
    );
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("test"), now);

    assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
    assert!(!msg.metadata.authentic_data);
}

#[test]
fn test_negative_response_with_untrusted_nsec_is_not_secure() {
    let (origin, dnskey, signer) = create_test_signer("nsec.example.");
    let qname = Name::from_str("missing.nsec.example.").unwrap();

    // No anchors: the denial signature verifies cryptographically but the
    // covering zone is not linked to a trust anchor.
    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());

    let mut msg = signed_nsec_response(
        &origin,
        &origin,
        &nsec_next(&origin),
        &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        &qname,
        &dnskey,
        &signer,
        ResponseCode::NXDomain,
    );
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("test"), now);

    // The sync API has no key fetcher, so strict mode fails closed instead
    // of returning AD=0 for an unlinked denial signature.
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "an unlinked denial signature must not be served as AD=0 in strict mode: {outcome:?}"
    );
    assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
    assert!(!msg.metadata.authentic_data);
}

fn signed_optout_nxdomain(
    origin: &Name,
    qname: &Name,
    dnskey: &DNSKEY,
    signer: &hickory_proto::dnssec::DnssecSigner,
    opt_out: bool,
    iterations: u16,
) -> Message {
    use data_encoding::BASE32_DNSSEC;
    use hickory_proto::dnssec::Nsec3HashAlgorithm;
    use hickory_proto::dnssec::rdata::NSEC3;
    use hickory_proto::rr::RecordSet;

    let alg = Nsec3HashAlgorithm::SHA1;
    let encloser_hash = alg.hash(&[], origin, iterations).unwrap().as_ref().to_vec();
    let qname_hash = alg.hash(&[], qname, iterations).unwrap().as_ref().to_vec();
    let mut next = qname_hash.clone();
    for byte in next.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
    let nsec3 = NSEC3::new(
        alg,
        opt_out,
        iterations,
        Vec::new(),
        next,
        [RecordType::SOA, RecordType::RRSIG, RecordType::NSEC3],
    );
    let owner = Name::from_ascii(format!(
        "{}.{}",
        BASE32_DNSSEC.encode(&encloser_hash),
        origin.to_ascii()
    ))
    .unwrap();
    let nsec3_record =
        Record::from_rdata(owner.clone(), 300, RData::DNSSEC(DNSSECRData::NSEC3(nsec3)));
    let mut set = RecordSet::new(owner, RecordType::NSEC3, 0);
    set.insert(nsec3_record.clone(), 0);
    let signature = sign_test_rrset(&set, signer);

    let mut msg = Message::new(25, MessageType::Response, OpCode::Query);
    msg.queries.push(Query::query(qname.clone(), RecordType::A));
    msg.metadata.response_code = ResponseCode::NXDomain;
    msg.authorities.push(nsec3_record);
    msg.authorities.push(signature);
    if !opt_out {
        let wildcard = Name::from_str("*").unwrap().append_domain(origin).unwrap();
        let wc_hash = alg
            .hash(&[], &wildcard, iterations)
            .unwrap()
            .as_ref()
            .to_vec();
        let mut wc_prev = wc_hash.clone();
        for byte in wc_prev.iter_mut().rev() {
            let (val, borrow) = byte.overflowing_sub(1);
            *byte = val;
            if !borrow {
                break;
            }
        }
        let mut wc_next = wc_hash;
        for byte in wc_next.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        let wc_nsec3 = NSEC3::new(
            alg,
            false,
            iterations,
            Vec::new(),
            wc_next,
            [RecordType::A, RecordType::RRSIG, RecordType::NSEC3],
        );
        let wc_owner = Name::from_ascii(format!(
            "{}.{}",
            BASE32_DNSSEC.encode(&wc_prev),
            origin.to_ascii()
        ))
        .unwrap();
        let wc_record = Record::from_rdata(
            wc_owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(wc_nsec3)),
        );
        let mut wc_set = RecordSet::new(wc_owner, RecordType::NSEC3, 0);
        wc_set.insert(wc_record.clone(), 0);
        let wc_sig = sign_test_rrset(&wc_set, signer);
        msg.authorities.push(wc_record);
        msg.authorities.push(wc_sig);
    }
    msg.additionals.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
    ));
    msg
}

#[test]
fn test_nxdomain_optout_nsec3_is_insecure() {
    let (origin, dnskey, signer) = create_test_signer("example.");
    let qname = Name::from_str("missing.example.").unwrap();

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let mut msg = signed_optout_nxdomain(&origin, &qname, &dnskey, &signer, true, 0);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("test"), now);

    assert_eq!(outcome, ValidationOutcome::Insecure);
    assert!(!msg.metadata.authentic_data);
}

#[test]
fn test_nxdomain_nsec3_without_optout_stays_secure() {
    let (origin, dnskey, signer) = create_test_signer("example.");
    let qname = Name::from_str("missing.example.").unwrap();

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let mut msg = signed_optout_nxdomain(&origin, &qname, &dnskey, &signer, false, 0);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("test"), now);

    assert_eq!(outcome, ValidationOutcome::Secure);
    assert!(msg.metadata.authentic_data);
}

#[test]
fn test_nsec3_iterations_over_cap_not_secure() {
    let (origin, dnskey, signer) = create_test_signer("example.");
    let qname = Name::from_str("missing.example.").unwrap();

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    // RFC 9276: proofs above 150 iterations must not be accepted.
    let mut msg = signed_optout_nxdomain(&origin, &qname, &dnskey, &signer, false, 151);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("test"), now);

    assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
    assert!(!msg.metadata.authentic_data);
}

#[test]
fn test_key_cache_ignores_unvalidated_response_keys() {
    let (origin, dnskey, a_record, rrsig_record, _) = create_test_signed_domain("kcache.example.");

    // No trust anchors: signatures verify but the chain is not linked, so
    // the key must never be cached (an attacker-supplied DNSKEY must not
    // outlive the response and poison later validations).
    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    for _ in 0..2 {
        let mut msg = Message::new(23, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        msg.answers.push(a_record.clone());
        msg.answers.push(rrsig_record.clone());
        msg.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
        ));
        let outcome = validator.validate_response(&mut msg, Some("cache-test"), now);
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "an unlinked response must fail closed in strict mode: {outcome:?}"
        );
    }

    assert!(
        validator.key_cache.is_empty(),
        "unexpected cached keys: {}",
        validator.key_cache.len()
    );
    assert_eq!(validator.metrics.key_cache_misses(), 2);
    assert_eq!(validator.metrics.key_cache_hits(), 0);
}

#[test]
fn test_key_cache_does_not_downgrade_validated_entry() {
    let (name, valid, _) = create_test_signer("cache.example.");
    let (_, attacker, _) = create_test_signer("cache.example.");
    let tag = valid.calculate_key_tag().unwrap();
    let lower = LowerName::from(&name);
    let now = 1_000_000u32;

    let cache = KeyCache::new();
    cache.insert_validated_with_now(lower.clone(), tag, valid.clone(), now + 300, now);
    cache.insert_with_now(lower.clone(), tag, attacker.clone(), now + 600, now);

    let cached = cache
        .get_validated(&lower, tag, now)
        .expect("validated key");
    assert_eq!(cached, valid);
    assert_eq!(
        cache.get(&lower, tag, now).expect("cached key"),
        valid,
        "an unvalidated insert must not overwrite a live validated entry"
    );
}

#[test]
fn test_key_cache_purges_expired_and_stays_bounded() {
    let (name, key, _) = create_test_signer("purge.example.");
    let lower = LowerName::from(&name);
    let cache = KeyCache::new();
    let now = 2_000_000u32;
    let insert_now = now - 10;

    cache.insert_validated_with_now(lower.clone(), 1, key.clone(), now - 1, insert_now);
    cache.insert_validated_with_now(lower.clone(), 2, key.clone(), now + 60, insert_now);
    assert_eq!(cache.purge_expired(now), 1);
    assert!(cache.get_validated(&lower, 1, now).is_none());
    assert!(cache.get_validated(&lower, 2, now).is_some());

    // Once the cache exceeds its bound it is cleared: keys are
    // re-discoverable, and an unbounded cache is a memory-exhaustion risk.
    for tag in 0..=(KEY_CACHE_MAX_ENTRIES as u16) {
        cache.insert_validated_with_now(lower.clone(), tag, key.clone(), now + 60, now);
    }
    assert!(cache.len() <= KEY_CACHE_MAX_ENTRIES);
}

#[tokio::test]
async fn test_chain_fetch_resolves_ksk_zsk() {
    use hickory_proto::rr::RecordSet;

    let (origin, ksk, ksk_signer) = create_test_signer("fetch.example.");
    let (_name, zsk, zsk_signer) = create_test_signer("fetch.example.");

    let (answer, answer_sig) = signed_a_response(&origin, &zsk_signer);

    let mut key_set = RecordSet::new(origin.clone(), RecordType::DNSKEY, 0);
    key_set.insert(
        Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(ksk.clone())),
        ),
        0,
    );
    key_set.insert(
        Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(zsk.clone())),
        ),
        0,
    );
    let key_sig = sign_test_rrset(&key_set, &ksk_signer);

    let fetcher = StaticFetcher::new().with(
        &origin,
        RecordType::DNSKEY,
        fetched_dnskey_message(&origin, &[ksk.clone(), zsk.clone()], Some(key_sig)),
    );

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(ksk.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let mut response = Message::new(20, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(origin.clone(), RecordType::A));
    response.answers.push(answer);
    response.answers.push(answer_sig);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("test"), now, &fetcher)
        .await;

    assert_eq!(outcome, ValidationOutcome::Secure);
    assert!(response.metadata.authentic_data);
    assert_eq!(fetcher.calls(), 1);
    // Fetched keys must not leak into the client response.
    assert!(
        response
            .additionals
            .iter()
            .all(|record| !matches!(record.data, RData::DNSSEC(DNSSECRData::DNSKEY(_))))
    );
}

#[tokio::test]
async fn test_chain_fetch_resolves_ds_delegation() {
    use hickory_proto::dnssec::DigestType;
    use hickory_proto::rr::RecordSet;

    let (parent, parent_key, parent_signer) = create_test_signer("example.");
    let (child, child_key, child_signer) = create_test_signer("sub.example.");

    let (answer, answer_sig) = signed_a_response(&child, &child_signer);

    let ds = DS::from_key(child_key.public_key(), &child, DigestType::SHA256).unwrap();
    let ds_record = Record::from_rdata(child.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
    let mut ds_set = RecordSet::new(child.clone(), RecordType::DS, 0);
    ds_set.insert(ds_record.clone(), 0);
    let ds_sig = sign_test_rrset(&ds_set, &parent_signer);
    let mut ds_message = Message::new(0, MessageType::Response, OpCode::Query);
    ds_message.authorities.push(ds_record);
    ds_message.authorities.push(ds_sig);

    let fetcher = StaticFetcher::new()
        .with(
            &child,
            RecordType::DNSKEY,
            fetched_dnskey_message(&child, &[child_key], None),
        )
        .with(&child, RecordType::DS, ds_message)
        .with(
            &parent,
            RecordType::DNSKEY,
            fetched_dnskey_message(&parent, std::slice::from_ref(&parent_key), None),
        );

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(parent_key.public_key(), LowerName::from(&parent));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let mut response = Message::new(21, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(child.clone(), RecordType::A));
    response.answers.push(answer);
    response.answers.push(answer_sig);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("test"), now, &fetcher)
        .await;

    assert_eq!(outcome, ValidationOutcome::Secure);
    assert!(response.metadata.authentic_data);
    assert_eq!(fetcher.calls(), 3);
    assert!(
        response.additionals.is_empty(),
        "unexpected additionals: {:?}",
        response.additionals
    );
}

#[tokio::test]
async fn test_chain_fetch_budget_for_unsigned_delegation() {
    let (origin, _zsk, zsk_signer) = create_test_signer("unsigned.example.");
    let (answer, answer_sig) = signed_a_response(&origin, &zsk_signer);

    let fetcher = StaticFetcher::new();

    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());

    let mut response = Message::new(22, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(origin.clone(), RecordType::A));
    response.answers.push(answer);
    response.answers.push(answer_sig);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("test"), now, &fetcher)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a failed chain fetch must SERVFAIL in validate mode: {outcome:?}"
    );
    // One DNSKEY and one DS lookup for the signer zone, then one
    // unverifiable-signature probe before failing closed.
    assert_eq!(fetcher.calls(), 3);
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(
        response.additionals.is_empty(),
        "unexpected additionals: {:?}",
        response.additionals
    );
}

#[test]
fn test_dnssec_nta_bypass() {
    let origin = Name::from_str("service.internal.corp.").unwrap();
    let validator = DnssecValidator::new(DnssecMode::Validate, vec!["internal.corp".to_string()]);

    let mut msg = Message::new(5, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(origin.clone(), RecordType::A));
    msg.answers.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, None, now);

    assert_eq!(outcome, ValidationOutcome::NtaBypass);
    assert!(!msg.metadata.authentic_data);
    assert_eq!(validator.metrics.get_validations("nta_bypass"), 1);

    // Dynamic NTA removal
    validator.remove_nta("internal.corp");
    assert!(!validator.is_nta(&origin));

    // Now without NTA, an unsigned domain is Insecure
    let outcome2 = validator.validate_response(&mut msg, None, now);
    assert_eq!(outcome2, ValidationOutcome::Insecure);
    assert_eq!(validator.metrics.get_validations("insecure"), 1);
}

#[test]
fn test_ds_digest_match_and_mismatch() {
    use hickory_proto::dnssec::DigestType;

    let (origin, dnskey, _signer) = create_test_signer("child.example.");
    let ds = DS::from_key(dnskey.public_key(), &origin, DigestType::SHA256).unwrap();

    assert_eq!(ds.key_tag(), dnskey.calculate_key_tag().unwrap());
    assert!(ds.covers(&origin, &dnskey).unwrap());

    let tampered = DS::new(
        ds.key_tag(),
        ds.algorithm(),
        ds.digest_type(),
        vec![0u8; ds.digest().len()],
    );
    assert!(!tampered.covers(&origin, &dnskey).unwrap());
}

#[test]
fn test_dnssec_ksk_zsk_chain() {
    use hickory_proto::rr::RecordSet;

    let (origin, ksk, ksk_signer) = create_test_signer("chain.example.");
    let (_zsk_name, zsk, zsk_signer) = create_test_signer("chain.example.");

    let a_record = Record::from_rdata(
        origin.clone(),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
    );
    let mut a_set = RecordSet::new(origin.clone(), RecordType::A, 0);
    a_set.insert(a_record.clone(), 0);
    let a_sig = sign_test_rrset(&a_set, &zsk_signer);

    let mut key_set = RecordSet::new(origin.clone(), RecordType::DNSKEY, 0);
    key_set.insert(
        Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(ksk.clone())),
        ),
        0,
    );
    key_set.insert(
        Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(zsk.clone())),
        ),
        0,
    );
    let key_sig = sign_test_rrset(&key_set, &ksk_signer);

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(ksk.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let mut msg = Message::new(10, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(origin.clone(), RecordType::A));
    msg.answers.push(a_record);
    msg.answers.push(a_sig);
    msg.additionals.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(ksk)),
    ));
    msg.additionals.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(zsk)),
    ));
    msg.additionals.push(key_sig);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("chain-test"), now);

    assert_eq!(outcome, ValidationOutcome::Secure);
    assert!(msg.metadata.authentic_data);
    assert!(
        !validator.key_cache.is_empty(),
        "expected at least one cached key"
    );
}

#[test]
fn test_dnssec_ds_delegation_chain() {
    use hickory_proto::dnssec::DigestType;
    use hickory_proto::rr::RecordSet;

    let (parent, parent_key, parent_signer) = create_test_signer("example.");
    let (child, child_key, child_signer) = create_test_signer("sub.example.");

    // DS record at the child, signed by the parent KSK.
    let ds = DS::from_key(child_key.public_key(), &child, DigestType::SHA256).unwrap();
    let ds_record = Record::from_rdata(child.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
    let mut ds_set = RecordSet::new(child.clone(), RecordType::DS, 0);
    ds_set.insert(ds_record.clone(), 0);
    let ds_sig = sign_test_rrset(&ds_set, &parent_signer);

    // Child A record signed by the child ZSK.
    let a_record = Record::from_rdata(
        child.clone(),
        300,
        RData::A(A(Ipv4Addr::new(198, 51, 100, 7))),
    );
    let mut a_set = RecordSet::new(child.clone(), RecordType::A, 0);
    a_set.insert(a_record.clone(), 0);
    let a_sig = sign_test_rrset(&a_set, &child_signer);

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(parent_key.public_key(), LowerName::from(&parent));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let mut msg = Message::new(11, MessageType::Response, OpCode::Query);
    msg.queries.push(Query::query(child.clone(), RecordType::A));
    msg.answers.push(a_record);
    msg.answers.push(a_sig);
    msg.authorities.push(ds_record);
    msg.authorities.push(ds_sig);
    msg.additionals.push(Record::from_rdata(
        parent.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(parent_key)),
    ));
    msg.additionals.push(Record::from_rdata(
        child.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(child_key)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("ds-test"), now);

    assert_eq!(outcome, ValidationOutcome::Secure);
    assert!(msg.metadata.authentic_data);
}

fn sign_rrset_with_window(
    set: &hickory_proto::rr::RecordSet,
    signer: &hickory_proto::dnssec::DnssecSigner,
    inception: time::OffsetDateTime,
) -> Record {
    let rrsig = RRSIG::from_rrset(set, DNSClass::IN, inception, signer).expect("sign windowed");
    Record::from_rdata(set.name().clone(), 300, rrsig.into_rdata())
}

fn time_at(base: u32, offset_secs: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(i64::from(base) + offset_secs).unwrap()
}

#[test]
fn test_clock_skew_boundaries() {
    use hickory_proto::rr::RecordSet;

    let (origin, dnskey, signer) = create_test_signer("skew.example.");
    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let a_record = Record::from_rdata(
        origin.clone(),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 9))),
    );
    let mut set = RecordSet::new(origin.clone(), RecordType::A, 0);
    set.insert(a_record.clone(), 0);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let validate = |inception_offset: i64| {
        let sig = sign_rrset_with_window(&set, &signer, time_at(now, inception_offset));
        let mut msg = Message::new(30, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        msg.answers.push(a_record.clone());
        msg.answers.push(sig);
        msg.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
        ));
        let outcome = validator.validate_response(&mut msg, Some("skew"), now);
        (outcome, msg.metadata.authentic_data)
    };

    // Window [now+300, now+3900]: now is exactly at inception-300.
    let (outcome, ad) = validate(300);
    assert_eq!(outcome, ValidationOutcome::Secure, "inception boundary");
    assert!(ad);
    // One second past the allowed skew: not yet valid.
    let (outcome, ad) = validate(301);
    assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
    assert!(!ad);

    // Window [now-3900, now-300]: now is exactly at expiration+300.
    let (outcome, ad) = validate(-3900);
    assert_eq!(outcome, ValidationOutcome::Secure, "expiration boundary");
    assert!(ad);
    // One second past the allowed skew: expired.
    let (outcome, ad) = validate(-3901);
    assert_eq!(
        outcome,
        ValidationOutcome::Bogus {
            reason: "Signature expired".to_string(),
            ede_code: EDE_SIGNATURE_EXPIRED,
        }
    );
    assert!(!ad);
}

#[test]
fn test_stripped_rrsig_under_signed_zone_is_bogus() {
    let (origin, dnskey, a_record, rrsig_record, _) = create_test_signed_domain("strip.example.");
    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    let signed_message = |id: u16| {
        let mut msg = Message::new(id, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        msg.answers.push(a_record.clone());
        msg.answers.push(rrsig_record.clone());
        msg.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
        ));
        msg
    };
    let stripped_message = |id: u16| {
        let other = Name::from_str("other.strip.example.").unwrap();
        let mut msg = Message::new(id, MessageType::Response, OpCode::Query);
        msg.queries.push(Query::query(other.clone(), RecordType::A));
        msg.answers.push(Record::from_rdata(
            other,
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 66))),
        ));
        msg
    };

    // Establish that the zone is signed.
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors.clone());
    let mut signed = signed_message(31);
    assert_eq!(
        validator.validate_response(&mut signed, Some("strip"), now),
        ValidationOutcome::Secure
    );

    // A later response under the same zone with the signatures stripped.
    let mut stripped = stripped_message(32);
    let outcome = validator.validate_response(&mut stripped, Some("strip"), now);
    assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
    assert_eq!(stripped.metadata.response_code, ResponseCode::ServFail);
    assert!(!stripped.metadata.authentic_data);

    // Log-only mode clears AD but keeps the (potentially cached) answer.
    let log_only =
        DnssecValidator::new(DnssecMode::LogOnly, Vec::new()).with_trust_anchors(anchors);
    let mut signed = signed_message(33);
    assert_eq!(
        log_only.validate_response(&mut signed, Some("strip"), now),
        ValidationOutcome::Secure
    );
    let mut stripped = stripped_message(34);
    let outcome = log_only.validate_response(&mut stripped, Some("strip"), now);
    assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
    assert_eq!(stripped.metadata.response_code, ResponseCode::NoError);
    assert!(!stripped.metadata.authentic_data);
    assert!(
        !stripped.answers.is_empty(),
        "stripping NSEC records must keep the answers"
    );
}

#[test]
fn test_empty_coverage_rrsig_is_bogus() {
    let (origin, dnskey, _a_record, rrsig_record, _) =
        create_test_signed_domain("emptycov.example.");
    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    // The RRSIG claims to cover A at origin but no A record is present.
    let mut msg = Message::new(34, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(origin.clone(), RecordType::A));
    msg.answers.push(rrsig_record);
    msg.additionals.push(Record::from_rdata(
        origin,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("emptycov"), now);

    assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
    assert!(!msg.metadata.authentic_data);
    assert_ne!(outcome, ValidationOutcome::Secure);
}

#[test]
fn test_unrelated_valid_rrsig_does_not_grant_ad() {
    let (origin, dnskey, a_record, rrsig_record, _) = create_test_signed_domain("rel.example.");
    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let victim = Name::from_str("victim.rel.example.").unwrap();
    let mut msg = Message::new(35, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(victim.clone(), RecordType::A));
    // A forged, unsigned answer for the queried name...
    msg.answers.push(Record::from_rdata(
        victim,
        300,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 66))),
    ));
    // ...plus a perfectly valid signature for an unrelated RRset.
    msg.answers.push(a_record);
    msg.answers.push(rrsig_record);
    msg.additionals.push(Record::from_rdata(
        origin,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("rel"), now);

    assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
    assert!(!msg.metadata.authentic_data);
}

#[test]
fn test_cross_zone_rrsig_does_not_grant_ad() {
    // A validated attacker zone signs an RRset owned by the victim zone.
    // RFC 4035 5.3.1 requires the signer to contain the owner; without the
    // containment check this granted AD=1 for arbitrary names.
    let (attacker, attacker_key, attacker_signer) = create_test_signer("attacker.example.");
    let (victim, _victim_key, _victim_signer) = create_test_signer("victim.example.");
    let (answer, answer_sig) = signed_a_response(&victim, &attacker_signer);

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(attacker_key.public_key(), LowerName::from(&attacker));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let mut msg = Message::new(37, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(victim.clone(), RecordType::A));
    msg.answers.push(answer);
    msg.answers.push(answer_sig);
    msg.additionals.push(Record::from_rdata(
        attacker,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(attacker_key)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("xzone"), now);

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "cross-zone RRSIG must be Bogus, got {outcome:?}"
    );
    assert!(!msg.metadata.authentic_data);
}

#[test]
fn test_cross_zone_ds_is_rejected() {
    use hickory_proto::dnssec::DigestType;
    use hickory_proto::rr::RecordSet;

    let (attacker, attacker_key, attacker_signer) = create_test_signer("attacker.example.");
    let (victim, victim_key, victim_signer) = create_test_signer("victim.example.");
    let (answer, answer_sig) = signed_a_response(&victim, &victim_signer);

    // A DS for victim.example signed by attacker.example's validated key.
    let ds = DS::from_key(victim_key.public_key(), &victim, DigestType::SHA256).unwrap();
    let ds_record = Record::from_rdata(victim.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
    let mut ds_set = RecordSet::new(victim.clone(), RecordType::DS, 0);
    ds_set.insert(ds_record.clone(), 0);
    let ds_sig = sign_test_rrset(&ds_set, &attacker_signer);

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(attacker_key.public_key(), LowerName::from(&attacker));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let mut msg = Message::new(36, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(victim.clone(), RecordType::A));
    msg.answers.push(answer);
    msg.answers.push(answer_sig);
    msg.authorities.push(ds_record);
    msg.authorities.push(ds_sig);
    msg.additionals.push(Record::from_rdata(
        attacker,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(attacker_key)),
    ));
    msg.additionals.push(Record::from_rdata(
        victim,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(victim_key)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("cross-zone"), now);

    assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
    assert!(!msg.metadata.authentic_data);
}

#[test]
fn test_ds_sha1_digest_is_treated_as_unsigned() {
    use hickory_proto::dnssec::DigestType;
    use hickory_proto::rr::RecordSet;

    let (parent, parent_key, parent_signer) = create_test_signer("example.");
    let (child, child_key, child_signer) = create_test_signer("sha1.example.");
    let (answer, answer_sig) = signed_a_response(&child, &child_signer);

    let ds = DS::from_key(child_key.public_key(), &child, DigestType::SHA1).unwrap();
    let ds_record = Record::from_rdata(child.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
    let mut ds_set = RecordSet::new(child.clone(), RecordType::DS, 0);
    ds_set.insert(ds_record.clone(), 0);
    let ds_sig = sign_test_rrset(&ds_set, &parent_signer);

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(parent_key.public_key(), LowerName::from(&parent));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let mut msg = Message::new(37, MessageType::Response, OpCode::Query);
    msg.queries.push(Query::query(child.clone(), RecordType::A));
    msg.answers.push(answer);
    msg.answers.push(answer_sig);
    msg.authorities.push(ds_record);
    msg.authorities.push(ds_sig);
    msg.additionals.push(Record::from_rdata(
        parent,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(parent_key)),
    ));
    msg.additionals.push(Record::from_rdata(
        child,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(child_key)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("sha1-ds"), now);

    // RFC 6840 5.2: an unsupported DS digest makes the delegation
    // unsigned; the answer is served with AD=0, not SERVFAIL.
    assert_eq!(outcome, ValidationOutcome::Insecure);
    assert!(!msg.metadata.authentic_data);
    assert_ne!(msg.metadata.response_code, ResponseCode::ServFail);
}

#[test]
fn test_ds_rsasha1_algorithm_is_treated_as_unsigned() {
    use hickory_proto::dnssec::DigestType;
    use hickory_proto::rr::RecordSet;

    let (parent, parent_key, parent_signer) = create_test_signer("example.");
    let (child, child_key, child_signer) = create_test_signer("sha1alg.example.");
    let (answer, answer_sig) = signed_a_response(&child, &child_signer);

    // RSASHA1 (algorithm 5) is forbidden by RFC 8624; build the DS
    // without a matching key (policy rejects it before digest matching).
    let ds = DS::new(
        child_key.calculate_key_tag().unwrap(),
        hickory_proto::dnssec::Algorithm::from_u8(5),
        DigestType::SHA256,
        vec![0u8; 32],
    );
    let ds_record = Record::from_rdata(child.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
    let mut ds_set = RecordSet::new(child.clone(), RecordType::DS, 0);
    ds_set.insert(ds_record.clone(), 0);
    let ds_sig = sign_test_rrset(&ds_set, &parent_signer);

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(parent_key.public_key(), LowerName::from(&parent));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let mut msg = Message::new(38, MessageType::Response, OpCode::Query);
    msg.queries.push(Query::query(child.clone(), RecordType::A));
    msg.answers.push(answer);
    msg.answers.push(answer_sig);
    msg.authorities.push(ds_record);
    msg.authorities.push(ds_sig);
    msg.additionals.push(Record::from_rdata(
        parent,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(parent_key)),
    ));
    msg.additionals.push(Record::from_rdata(
        child,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(child_key)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("rsasha1-ds"), now);

    assert_eq!(outcome, ValidationOutcome::Insecure);
    assert!(!msg.metadata.authentic_data);
    assert_ne!(msg.metadata.response_code, ResponseCode::ServFail);
}

#[test]
fn test_ed25519_keys_validate() {
    use hickory_proto::dnssec::SigningKey;
    use hickory_proto::dnssec::crypto::Ed25519SigningKey;
    use hickory_proto::rr::RecordSet;

    let origin = Name::from_str("ed25519.example.").unwrap();
    let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
    let key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
    let pub_key = key.to_public_key().unwrap();
    let dnskey = DNSKEY::from_key(&pub_key);
    let signer = hickory_proto::dnssec::DnssecSigner::new(
        dnskey.clone(),
        Box::new(key),
        origin.clone(),
        Duration::from_secs(3600),
    );

    let a_record = Record::from_rdata(
        origin.clone(),
        300,
        RData::A(A(Ipv4Addr::new(198, 51, 100, 42))),
    );
    let mut set = RecordSet::new(origin.clone(), RecordType::A, 0);
    set.insert(a_record.clone(), 0);
    let rrsig = sign_test_rrset(&set, &signer);

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let mut msg = Message::new(39, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(origin.clone(), RecordType::A));
    msg.answers.push(a_record);
    msg.answers.push(rrsig);
    msg.additionals.push(Record::from_rdata(
        origin,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("ed25519"), now);

    assert_eq!(outcome, ValidationOutcome::Secure);
    assert!(msg.metadata.authentic_data);
}

#[tokio::test]
async fn test_root_walk_matches_default_anchor() {
    let anchors = TrustAnchors::default();
    let anchor = anchors.get(0).expect("default root anchor").clone();
    let root = Name::root();
    let root_key = DNSKEY::with_flags(257, anchor);
    let fetcher = StaticFetcher::new().with(
        &root,
        RecordType::DNSKEY,
        fetched_dnskey_message(&root, &[root_key], None),
    );

    let mut budget = 1u8;
    let mut visited = HashSet::new();
    let mut response = Message::new(40, MessageType::Response, OpCode::Query);
    let result = fetch_zone_chain(
        &anchors,
        &fetcher,
        &root,
        &mut budget,
        &mut visited,
        &mut response,
    )
    .await;

    assert_eq!(result, Some(()));
    assert_eq!(fetcher.calls(), 1, "the root DNSKEY must be fetched");
    assert!(
        response
            .additionals
            .iter()
            .any(|record| matches!(&record.data, RData::DNSSEC(DNSSECRData::DNSKEY(_))))
    );
}

#[test]
fn test_root_dnskey_matching_default_anchor_is_validated() {
    let anchors = TrustAnchors::default();
    let anchor = anchors.get(0).expect("default root anchor").clone();
    let root = Name::root();
    let root_key = DNSKEY::with_flags(257, anchor);
    let tag = root_key.calculate_key_tag().unwrap();
    let lower = LowerName::from(&root);

    // `DnssecValidator::new` uses the default root anchors.
    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
    let mut response = Message::new(44, MessageType::Response, OpCode::Query);
    response.additionals.push(Record::from_rdata(
        root.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(root_key.clone())),
    ));
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let fingerprint = dnskey_fingerprint(&root_key);
    let dnskeys = vec![(root.clone(), root_key)];
    let result =
        validator.build_validated_key_set(&response, &dnskeys, &[], now, &mut VerifyBudget::new());

    assert!(result.validated.contains(&(lower.clone(), fingerprint)));
    assert!(
        result.forged.is_empty(),
        "unexpected forged entries: {:?}",
        result.forged
    );
    assert!(
        result.unsupported.is_empty(),
        "unexpected unsupported entries: {:?}",
        result.unsupported
    );
    assert!(
        validator
            .key_cache
            .get_validated(&lower, tag, now)
            .is_some(),
        "a root DNSKEY matching the default anchor must be cached as validated"
    );
}

#[tokio::test]
async fn test_root_walk_fetches_root_dnskey_and_validates() {
    use hickory_proto::dnssec::DigestType;
    use hickory_proto::rr::RecordSet;

    let (root_name, root_key, root_signer) = create_test_signer(".");
    assert_eq!(root_name, Name::root());
    let (zone, zone_key, zone_signer) = create_test_signer("example.");
    let www = Name::from_str("www.example.").unwrap();
    let (answer, answer_sig) = signed_a_response(&www, &zone_signer);

    let ds = DS::from_key(zone_key.public_key(), &zone, DigestType::SHA256).unwrap();
    let ds_record = Record::from_rdata(zone.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
    let mut ds_set = RecordSet::new(zone.clone(), RecordType::DS, 0);
    ds_set.insert(ds_record.clone(), 0);
    let ds_sig = sign_test_rrset(&ds_set, &root_signer);

    let mut ds_message = Message::new(0, MessageType::Response, OpCode::Query);
    ds_message.authorities.push(ds_record);
    ds_message.authorities.push(ds_sig);

    let fetcher = StaticFetcher::new()
        .with(
            &zone,
            RecordType::DNSKEY,
            fetched_dnskey_message(&zone, &[zone_key], None),
        )
        .with(&zone, RecordType::DS, ds_message)
        .with(
            &root_name,
            RecordType::DNSKEY,
            fetched_dnskey_message(&root_name, std::slice::from_ref(&root_key), None),
        );

    // The real root KSK cannot sign test data, so the test root key is
    // added as a root anchor alongside the defaults.
    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
    validator.add_trust_anchor(&root_key, LowerName::from(&root_name));

    let mut response = Message::new(41, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(www.clone(), RecordType::A));
    response.answers.push(answer);
    response.answers.push(answer_sig);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("root-test"), now, &fetcher)
        .await;

    assert_eq!(outcome, ValidationOutcome::Secure);
    assert!(response.metadata.authentic_data);
    // DNSKEY(zone), DS(zone), DNSKEY(root).
    assert_eq!(fetcher.calls(), 3);
}

#[test]
fn test_nta_root_matches_all_names() {
    let validator = DnssecValidator::new(DnssecMode::Validate, vec![".".to_string()]);
    assert!(validator.is_nta(&Name::root()));
    assert!(validator.is_nta(&Name::from_str("example.").unwrap()));
    assert!(validator.is_nta(&Name::from_str("www.example.").unwrap()));
}

#[test]
fn test_nta_evaluated_across_all_questions() {
    let validator = DnssecValidator::new(DnssecMode::Validate, vec!["internal.corp".to_string()]);
    let mut msg = Message::new(42, MessageType::Response, OpCode::Query);
    msg.queries.push(Query::query(
        Name::from_str("public.example.").unwrap(),
        RecordType::A,
    ));
    msg.queries.push(Query::query(
        Name::from_str("host.internal.corp.").unwrap(),
        RecordType::A,
    ));
    msg.answers.push(Record::from_rdata(
        Name::from_str("public.example.").unwrap(),
        300,
        RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, None, now);

    assert_eq!(outcome, ValidationOutcome::NtaBypass);
    assert!(!msg.metadata.authentic_data);
}

#[test]
fn test_apply_ede_replaces_existing_option() {
    let mut msg = Message::new(43, MessageType::Response, OpCode::Query);
    apply_ede(&mut msg, EDE_DNSSEC_BOGUS, "first");
    apply_ede(&mut msg, EDE_DNSSEC_BOGUS, "second");
    let edns = msg.edns.as_ref().expect("EDNS present");
    let ede_count = edns
        .options()
        .options
        .iter()
        .filter(|(code, _)| u16::from(*code) == 15)
        .count();
    assert_eq!(ede_count, 1, "EDE options must not be duplicated");
}

/// Finds a DNSKEY `flags` value that gives `key`'s public material the
/// requested key tag (key tags are only 16-bit checksums, so collisions are
/// trivially constructible).
fn find_same_tag_flags(key: &DNSKEY, target_tag: u16) -> Option<u16> {
    use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

    // The key tag is computed over the wire form, where the flags field is
    // the first 16-bit word and contributes exactly `flags` to the sum.
    // Encode once with zero flags to obtain the flag-independent sum.
    let zero = DNSKEY::with_flags(0, key.public_key().clone());
    let mut bytes = Vec::with_capacity(512);
    {
        let mut encoder = BinEncoder::new(&mut bytes);
        zero.emit(&mut encoder).expect("encode DNSKEY");
    }
    let base_ac: u32 = bytes
        .iter()
        .enumerate()
        .map(|(i, byte)| u32::from(*byte) << if i & 1 == 0 { 8 } else { 0 })
        .sum();

    for flags in 0u32..=0xFFFF {
        // Zone key flag set, revoke flag clear (required by policy).
        if flags & 0x0100 == 0 || flags & 0x0080 != 0 {
            continue;
        }
        let ac = base_ac + flags;
        if ((ac + (ac >> 16)) & 0xFFFF) as u16 == target_tag {
            return Some(flags as u16);
        }
    }
    None
}

/// Builds a key pair whose key tag collides with `target_tag` but whose
/// public key material differs.
///
/// The tag is varied through the DNSKEY flags field. Policy requires the
/// zone-key bit set and the revoke bit clear, so only a quarter of the
/// reachable tag residues is covered per generated key; fresh keys are
/// generated until one collides (expected ~4 attempts).
fn forge_same_tag_key(target_tag: u16) -> (DNSKEY, hickory_proto::dnssec::crypto::EcdsaSigningKey) {
    use hickory_proto::dnssec::SigningKey;
    use hickory_proto::dnssec::crypto::EcdsaSigningKey;

    for _ in 0..256 {
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256)
            .expect("generate fake pkcs8");
        let private = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256)
            .expect("fake key from pkcs8");
        let public = private.to_public_key().expect("fake public key");
        let plain = DNSKEY::from_key(&public);
        if let Some(flags) = find_same_tag_flags(&plain, target_tag) {
            let key = DNSKEY::with_flags(flags, plain.public_key().clone());
            return (key, private);
        }
    }
    panic!("a 16-bit tag collision must be constructible");
}

/// Regression for the same-tag DNSKEY forgery: including the anchored key
/// plus a same-tag forgery must not let the forgery be trusted, and must
/// never replace the anchored key in the validated-key cache.
#[test]
fn test_same_tag_dnskey_forgery_is_not_trusted() {
    use hickory_proto::dnssec::DnssecSigner;

    let (origin, real_key, real_signer) = crate::test_util::create_test_signer("victim.example.");
    let real_tag = real_key.calculate_key_tag().expect("real tag");

    // A different key pair whose tag is forced to collide.
    let (fake_key, fake_private) = forge_same_tag_key(real_tag);
    assert_eq!(fake_key.calculate_key_tag().expect("fake tag"), real_tag);
    assert_ne!(
        dnskey_fingerprint(&fake_key),
        dnskey_fingerprint(&real_key),
        "the forged key must not be the anchored key"
    );
    let fake_signer = DnssecSigner::new(
        fake_key.clone(),
        Box::new(fake_private),
        origin.clone(),
        Duration::from_secs(3600),
    );

    let mut trust_anchors = TrustAnchors::empty();
    trust_anchors.insert_with_name(real_key.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(trust_anchors);

    // Attacker ordering: the forged key first, the anchored key second.
    let (answer, forged_sig) = signed_a_response(&origin, &fake_signer);
    let mut response = Message::new(9, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(origin.clone(), RecordType::A));
    response.answers.push(answer);
    response.answers.push(forged_sig);
    response.additionals.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(fake_key.clone())),
    ));
    response.additionals.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(real_key.clone())),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut response, Some("attacker"), now);
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a same-tag forgery must not validate: {outcome:?}"
    );
    assert!(!response.metadata.authentic_data);

    // The anchored key must still be the cached validated key, and the
    // forged key must never be trusted from the shared tag.
    let lower = LowerName::from(&origin);
    assert!(
        validator
            .key_cache
            .is_validated(&lower, real_tag, &real_key, now),
        "the anchored key must remain validated in the cache"
    );
    assert!(
        !validator
            .key_cache
            .is_validated(&lower, real_tag, &fake_key, now),
        "the forged key must not inherit the anchored key's trust"
    );

    // The legitimate response signed by the anchored key still validates.
    let (legit_answer, legit_sig) = signed_a_response(&origin, &real_signer);
    let mut legit = Message::new(10, MessageType::Response, OpCode::Query);
    legit
        .queries
        .push(Query::query(origin.clone(), RecordType::A));
    legit.answers.push(legit_answer);
    legit.answers.push(legit_sig);
    legit.additionals.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(real_key.clone())),
    ));
    let outcome = validator.validate_response(&mut legit, Some("legit"), now);
    assert_eq!(outcome, ValidationOutcome::Secure);
}

/// Regression: linking a key to a trust anchor (in particular the root key
/// fetched by the chain walk) must not mark the root or any other zone as
/// signed. Doing so turned every unrelated unsigned response into a
/// stripped-signature "Bogus" and SERVFAILed it (audit 6, P0-2).
#[test]
fn test_building_validated_key_set_does_not_mark_zones_signed() {
    let anchors = TrustAnchors::default();
    let anchor = anchors.get(0).expect("default root anchor").clone();
    let root = Name::root();
    let root_key = DNSKEY::with_flags(257, anchor);
    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
    let mut response = Message::new(45, MessageType::Response, OpCode::Query);
    response.additionals.push(Record::from_rdata(
        root.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(root_key.clone())),
    ));
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let result = validator.build_validated_key_set(
        &response,
        &[(root.clone(), root_key)],
        &[],
        now,
        &mut VerifyBudget::new(),
    );
    assert!(
        !result.validated.is_empty(),
        "expected validated keys, got none"
    );
    for name in ["unsigned.example.", "com.", "www.example.org."] {
        let lower = LowerName::from(&Name::from_str(name).expect("name"));
        assert!(
            !validator.signed_zone_contains(&lower, now),
            "{name} must not be recorded as signed just because the root key was linked"
        );
    }
}

/// An unrelated unsigned response after a successful validation must stay
/// Insecure and resolvable (this SERVFAILed before the audit-6 fix).
#[test]
fn test_signed_response_does_not_make_unrelated_unsigned_names_bogus() {
    let (origin, dnskey, a_record, rrsig_record, _) = create_test_signed_domain("signed.example.");

    let mut trust_anchors = TrustAnchors::empty();
    trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(trust_anchors);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    let mut signed = Message::new(1, MessageType::Response, OpCode::Query);
    signed
        .queries
        .push(Query::query(origin.clone(), RecordType::A));
    signed.answers.push(a_record);
    signed.answers.push(rrsig_record);
    signed.additionals.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));
    assert_eq!(
        validator.validate_response(&mut signed, Some("t"), now),
        ValidationOutcome::Secure
    );

    let unrelated = Name::from_str("unrelated.test.").expect("name");
    let mut unsigned = Message::new(2, MessageType::Response, OpCode::Query);
    unsigned
        .queries
        .push(Query::query(unrelated.clone(), RecordType::A));
    unsigned.answers.push(Record::from_rdata(
        unrelated,
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
    ));
    let outcome = validator.validate_response(&mut unsigned, Some("t"), now);
    assert_eq!(
        outcome,
        ValidationOutcome::Insecure,
        "an unrelated unsigned response must not be treated as a downgrade"
    );
    assert_eq!(unsigned.metadata.response_code, ResponseCode::NoError);
    assert!(!unsigned.metadata.authentic_data);
}

/// Within a zone that actually signed data, a response without RRSIGs is
/// still a stripped-signature downgrade and must be Bogus.
#[test]
fn test_stripped_rrsig_in_proven_signed_zone_is_bogus() {
    let (origin, dnskey, a_record, rrsig_record, _) = create_test_signed_domain("signed.example.");

    let mut trust_anchors = TrustAnchors::empty();
    trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(trust_anchors);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let mut signed = Message::new(1, MessageType::Response, OpCode::Query);
    signed
        .queries
        .push(Query::query(origin.clone(), RecordType::A));
    signed.answers.push(a_record);
    signed.answers.push(rrsig_record);
    signed.additionals.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));
    assert_eq!(
        validator.validate_response(&mut signed, Some("t"), now),
        ValidationOutcome::Secure
    );

    let other = Name::from_str("other.signed.example.").expect("name");
    let mut stripped = Message::new(2, MessageType::Response, OpCode::Query);
    stripped
        .queries
        .push(Query::query(other.clone(), RecordType::A));
    stripped.answers.push(Record::from_rdata(
        other,
        300,
        RData::A(A(Ipv4Addr::new(198, 51, 100, 7))),
    ));
    let outcome = validator.validate_response(&mut stripped, Some("t"), now);
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "stripped signatures in a proven-signed zone must stay Bogus: {outcome:?}"
    );
    assert_eq!(stripped.metadata.response_code, ResponseCode::ServFail);
}

/// Regression: the chain walk must reach the root for signers with three or
/// more labels (budget used to be a flat 6, which stopped one level short
/// and left the zone Indeterminate on a cold cache).
#[tokio::test]
async fn test_chain_fetch_reaches_root_for_three_label_signer() {
    /// A DS RRset for `child`, signed by `parent_signer`.
    fn signed_ds(
        child: &Name,
        child_key: &DNSKEY,
        parent_signer: &hickory_proto::dnssec::DnssecSigner,
    ) -> Message {
        use hickory_proto::dnssec::DigestType;
        use hickory_proto::rr::RecordSet;
        let ds = DS::from_key(child_key.public_key(), child, DigestType::SHA256).expect("ds");
        let record = Record::from_rdata(child.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
        let mut set = RecordSet::new(child.clone(), RecordType::DS, 0);
        set.insert(record.clone(), 0);
        let sig = sign_test_rrset(&set, parent_signer);
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.authorities.push(record);
        message.authorities.push(sig);
        message
    }

    let (root_name, root_key, root_signer) = create_test_signer(".");
    let (example, example_key, example_signer) = create_test_signer("example.");
    let (b_example, b_key, b_signer) = create_test_signer("b.example.");
    let (ab_example, ab_key, ab_signer) = create_test_signer("a.b.example.");

    let qname = Name::from_str("www.a.b.example.").unwrap();
    let (answer, answer_sig) = signed_a_response(&qname, &ab_signer);

    let fetcher = StaticFetcher::new()
        .with(
            &ab_example,
            RecordType::DNSKEY,
            fetched_dnskey_message(&ab_example, std::slice::from_ref(&ab_key), None),
        )
        .with(
            &ab_example,
            RecordType::DS,
            signed_ds(&ab_example, &ab_key, &b_signer),
        )
        .with(
            &b_example,
            RecordType::DNSKEY,
            fetched_dnskey_message(&b_example, std::slice::from_ref(&b_key), None),
        )
        .with(
            &b_example,
            RecordType::DS,
            signed_ds(&b_example, &b_key, &example_signer),
        )
        .with(
            &example,
            RecordType::DNSKEY,
            fetched_dnskey_message(&example, std::slice::from_ref(&example_key), None),
        )
        .with(
            &example,
            RecordType::DS,
            signed_ds(&example, &example_key, &root_signer),
        )
        .with(
            &root_name,
            RecordType::DNSKEY,
            fetched_dnskey_message(&root_name, std::slice::from_ref(&root_key), None),
        );

    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
    validator.add_trust_anchor(&root_key, LowerName::from(&root_name));

    let mut response = Message::new(42, MessageType::Response, OpCode::Query);
    response.queries.push(Query::query(qname, RecordType::A));
    response.answers.push(answer);
    response.answers.push(answer_sig);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("cold-cache"), now, &fetcher)
        .await;

    assert_eq!(
        outcome,
        ValidationOutcome::Secure,
        "a 3-label signer must validate from a cold cache"
    );
    // DNSKEY/DS pairs for a.b.example, b.example and example plus the root
    // DNSKEY = 7 fetches, one more than the old flat budget of 6.
    assert_eq!(fetcher.calls(), 7);
}

/// Regression: RRSIGs appended by the chain walk are helper records for
/// DNSKEY/DS RRsets, not evidence that the root (or any other helper
/// zone) signed the response. Marking the root from a fetched root DNSKEY
/// RRSIG made every later response look like a stripped downgrade.
#[tokio::test]
async fn test_chain_helper_rrsigs_do_not_mark_root_as_signed() {
    let (root, root_key, root_signer) = create_test_signer(".");
    let (one, one_key, one_signer) = create_test_signer("one.");

    let qname = Name::from_str("www.one.").expect("qname");
    let (answer, answer_sig) = signed_a_response(&qname, &one_signer);

    let fetcher = StaticFetcher::new()
        .with(
            &one,
            RecordType::DNSKEY,
            signed_dnskey_message(&one, &one_key, &one_signer),
        )
        .with(
            &one,
            RecordType::DS,
            signed_ds_fetch_message(&one, &one_key, &root_signer),
        )
        .with(
            &Name::root(),
            RecordType::DNSKEY,
            signed_dnskey_message(&Name::root(), &root_key, &root_signer),
        );

    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
    validator.add_trust_anchor(&root_key, LowerName::from(&root));

    let mut response = Message::new(77, MessageType::Response, OpCode::Query);
    response.queries.push(Query::query(qname, RecordType::A));
    response.answers.push(answer);
    response.answers.push(answer_sig);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("helper"), now, &fetcher)
        .await;
    assert_eq!(outcome, ValidationOutcome::Secure, "{outcome:?}");

    let root_lower = LowerName::from(&root);
    assert!(
        !validator.signed_zones.contains_key(&root_lower),
        "the root must never be recorded as signed-zone evidence"
    );
    for name in ["com.", "other.test.", "www.example."] {
        let lower = LowerName::from(&Name::from_str(name).expect("name"));
        assert!(
            !validator.signed_zone_contains(&lower, now),
            "helper chain RRSIGs must not make {name} look signed"
        );
    }
    assert!(
        validator.signed_zone_contains(&LowerName::from(&one), now),
        "the zone that actually signed the answer must still be recorded"
    );
}

/// Regression: two different signed zones queried in sequence on a cold
/// cache must both validate. A helper DS/DNSKEY RRSIG for the shared
/// parent/TLD used to mark that ancestor as signed and SERVFAIL the second
/// zone before its chain could be fetched.
#[tokio::test]
async fn test_two_signed_zones_cold_cache_both_secure() {
    let (tld, tld_key, tld_signer) = create_test_signer("example.");
    let (one, one_key, one_signer) = create_test_signer("one.example.");
    let (two, two_key, two_signer) = create_test_signer("two.example.");

    let fetcher = StaticFetcher::new()
        .with(
            &one,
            RecordType::DNSKEY,
            signed_dnskey_message(&one, &one_key, &one_signer),
        )
        .with(
            &one,
            RecordType::DS,
            signed_ds_fetch_message(&one, &one_key, &tld_signer),
        )
        .with(
            &tld,
            RecordType::DNSKEY,
            signed_dnskey_message(&tld, &tld_key, &tld_signer),
        )
        .with(
            &two,
            RecordType::DNSKEY,
            signed_dnskey_message(&two, &two_key, &two_signer),
        )
        .with(
            &two,
            RecordType::DS,
            signed_ds_fetch_message(&two, &two_key, &tld_signer),
        );

    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
    validator.add_trust_anchor(&tld_key, LowerName::from(&tld));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    let qname_one = Name::from_str("a.one.example.").expect("qname");
    let (answer_one, sig_one) = signed_a_response(&qname_one, &one_signer);
    let mut first = Message::new(80, MessageType::Response, OpCode::Query);
    first.queries.push(Query::query(qname_one, RecordType::A));
    first.answers.push(answer_one);
    first.answers.push(sig_one);
    let outcome = validator
        .validate_with_key_fetcher(&mut first, Some("first"), now, &fetcher)
        .await;
    assert_eq!(outcome, ValidationOutcome::Secure, "{outcome:?}");
    assert!(first.metadata.authentic_data);

    let qname_two = Name::from_str("b.two.example.").expect("qname");
    let (answer_two, sig_two) = signed_a_response(&qname_two, &two_signer);
    let mut second = Message::new(81, MessageType::Response, OpCode::Query);
    second.queries.push(Query::query(qname_two, RecordType::A));
    second.answers.push(answer_two);
    second.answers.push(sig_two);
    let outcome = validator
        .validate_with_key_fetcher(&mut second, Some("second"), now, &fetcher)
        .await;
    assert_eq!(
        outcome,
        ValidationOutcome::Secure,
        "a second signed zone must not inherit the first zone's helper evidence: {outcome:?}"
    );
    assert!(second.metadata.authentic_data);
    assert_eq!(second.metadata.response_code, ResponseCode::NoError);
}

/// A validated NSEC denial in the authority section is relevant evidence
/// that the signer zone is signed. A later stripped answer under it must
/// still fail closed rather than downgrade to Insecure.
#[test]
fn test_validated_negative_response_marks_zone_signed() {
    let (origin, dnskey, signer) = create_test_signer("denial.example.");
    let qname = Name::from_str("missing.denial.example.").expect("qname");

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let bitmap = vec![RecordType::A, RecordType::NSEC, RecordType::RRSIG];
    let mut msg = signed_nsec_response_records(
        &origin,
        &[
            (
                origin.clone(),
                Name::from_str("a.denial.example.").expect("next"),
                bitmap.clone(),
            ),
            (
                Name::from_str("a.denial.example.").expect("owner"),
                nsec_next(&origin),
                bitmap,
            ),
        ],
        &qname,
        &dnskey,
        &signer,
        ResponseCode::NXDomain,
    );

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    assert_eq!(
        validator.validate_response(&mut msg, Some("neg"), now),
        ValidationOutcome::Secure
    );
    assert!(
        validator.signed_zone_contains(&LowerName::from(&origin), now),
        "a validated denial must record the signer zone as signed"
    );

    let other = Name::from_str("other.denial.example.").expect("other");
    let mut stripped = Message::new(90, MessageType::Response, OpCode::Query);
    stripped
        .queries
        .push(Query::query(other.clone(), RecordType::A));
    stripped.answers.push(Record::from_rdata(
        other,
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
    ));
    let outcome = validator.validate_response(&mut stripped, Some("neg"), now);
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a stripped answer under a zone proven signed by a denial must stay Bogus: {outcome:?}"
    );
}

/// Important regression: a negative response whose NSEC denial RRSIGs are
/// present but whose DNSKEY is missing must fetch the key instead of
/// SERVFAILing. This mirrors the positive-answer P0 after the key cache
/// expires while signed-zone evidence is still live.
#[tokio::test]
async fn test_negative_response_with_denial_rrsig_fetches_key() {
    let (origin, dnskey, signer) = create_test_signer("negfetch.example.");
    let qname = Name::from_str("missing.negfetch.example.").expect("qname");

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    // Signed-zone evidence survives (cache reload / long-lived denial)
    // while the key cache is empty, as when the DNSKEY TTL expires first.
    validator
        .signed_zones
        .insert(LowerName::from(&origin), now + 300);

    let bitmap = vec![RecordType::A, RecordType::NSEC, RecordType::RRSIG];
    let mut base = signed_nsec_response_records(
        &origin,
        &[
            (
                origin.clone(),
                Name::from_str("a.negfetch.example.").expect("next"),
                bitmap.clone(),
            ),
            (
                Name::from_str("a.negfetch.example.").expect("owner"),
                nsec_next(&origin),
                bitmap,
            ),
        ],
        &qname,
        &dnskey,
        &signer,
        ResponseCode::NXDomain,
    );
    // Simulate an upstream response that omitted the DNSKEY.
    base.additionals
        .retain(|record| !matches!(record.data, RData::DNSSEC(DNSSECRData::DNSKEY(_))));

    let fetcher = StaticFetcher::new().with(
        &origin,
        RecordType::DNSKEY,
        signed_dnskey_message(&origin, &dnskey, &signer),
    );

    let mut msg = base.clone();
    let outcome = validator
        .validate_with_key_fetcher(&mut msg, Some("negfetch"), now, &fetcher)
        .await;
    assert_eq!(
        outcome,
        ValidationOutcome::Secure,
        "the missing DNSKEY must be fetched for a signed denial proof: {outcome:?}"
    );
    assert!(msg.metadata.authentic_data);
    assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(fetcher.calls(), 1, "one DNSKEY fetch must be attempted");

    // Post-fetch/offline strictness: a fresh validator with the same
    // signed-zone evidence but no cached key must fail closed when the
    // denial RRSIG still cannot be checked.
    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let offline_validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);
    offline_validator
        .signed_zones
        .insert(LowerName::from(&origin), now + 300);
    let offline = OfflineFetcher::new();
    let mut msg = base;
    let outcome = offline_validator
        .validate_with_key_fetcher(&mut msg, Some("offline"), now, &offline)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "an unverifiable denial RRSIG must fail closed after the fetch: {outcome:?}"
    );
    assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(msg.answers.len(), 0);
}

/// Deferred D4b: the synchronous API has no key fetcher. A relevant RRSIG
/// without key material must therefore fail closed in strict mode instead
/// of being returned as AD=0; log-only keeps it Indeterminate for
/// diagnostics. Chain-walking callers use `validate_with_key_fetcher`.
#[test]
fn test_sync_validate_response_fails_closed_without_key_fetcher() {
    let (origin, dnskey, a_record, rrsig_record, _) = create_test_signed_domain("reload.example.");

    let build = || {
        let mut response = Message::new(82, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(origin.clone(), RecordType::A));
        response.answers.push(a_record.clone());
        response.answers.push(rrsig_record.clone());
        response
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    let mut trust_anchors = TrustAnchors::empty();
    trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let strict =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(trust_anchors);
    // Simulate signed-zone evidence restored from the persistent chain
    // cache after a restart while the key cache is still empty.
    strict
        .signed_zones
        .insert(LowerName::from(&origin), now + 300);

    let mut response = build();
    let outcome = strict.validate_response(&mut response, Some("reload"), now);
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a relevant RRSIG without key material must fail closed in the sync API: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
    // Deferred D5: the provisional `Indeterminate` returned by the inner
    // pass must not be counted in addition to the Bogus outcome actually
    // served. One sync call is one validation outcome.
    assert_eq!(
        strict.metrics.bogus_total.load(Ordering::Relaxed),
        1,
        "the strict sync conversion must record the Bogus outcome it serves"
    );
    assert_eq!(
        strict.metrics.indeterminate_total.load(Ordering::Relaxed),
        0,
        "the provisional inner Indeterminate must not be double-recorded"
    );

    let log_only = DnssecValidator::new(DnssecMode::LogOnly, Vec::new());
    let mut response = build();
    let outcome = log_only.validate_response(&mut response, Some("reload"), now);
    assert_eq!(outcome, ValidationOutcome::Indeterminate);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(!response.metadata.authentic_data);
    assert_eq!(
        log_only.metrics.indeterminate_total.load(Ordering::Relaxed),
        1,
        "log-only must record its final Indeterminate exactly once"
    );
    assert_eq!(
        log_only.metrics.bogus_total.load(Ordering::Relaxed),
        0,
        "log-only must not record a Bogus outcome"
    );
}

/// Critical regression: a forged answer with a present-but-unverifiable
/// relevant RRSIG under a proven-signed zone must stay Bogus. The
/// "Indeterminate so the chain can be fetched" escape is only valid on the
/// pre-fetch pass; after the fetch fails to produce a key, the response
/// must fail closed instead of being served unvalidated.
#[tokio::test]
async fn test_unverifiable_relevant_rrsig_under_proven_signed_zone_is_bogus() {
    use hickory_proto::rr::RecordSet;

    let (validator, origin, _key, _signer) = signed_zone_validator("victim.example.");
    let qname = Name::from_str("www.victim.example.").expect("qname");
    let (_fake_origin, _fake_key, fake_signer) = create_test_signer("nonexistent.");

    let forged = Record::from_rdata(
        qname.clone(),
        300,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 66))),
    );
    let mut set = RecordSet::new(qname.clone(), RecordType::A, 0);
    set.insert(forged.clone(), 0);
    let fake_rrsig = sign_test_rrset(&set, &fake_signer);
    assert_eq!(
        fake_rrsig.record_type(),
        RecordType::RRSIG,
        "the forgery needs a relevant RRSIG owner/type"
    );

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    assert!(
        validator.signed_zone_contains(&LowerName::from(&origin), now),
        "the victim zone must be proven signed"
    );

    let build_response = || {
        let mut response = Message::new(83, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        response.answers.push(forged.clone());
        response.answers.push(fake_rrsig.clone());
        response
    };

    // NXDOMAIN responses from the chain walk (the fake signer does not
    // exist) and a fully offline fetcher must both fail closed.
    let nxdomain = NxdomainFetcher::new();
    let mut response = build_response();
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("forged"), now, &nxdomain)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "an unverifiable relevant RRSIG under proven signed evidence must be Bogus: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(
        response.answers.is_empty(),
        "a Bogus response must not carry answers"
    );

    let offline = OfflineFetcher::new();
    let mut response = build_response();
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("forged"), now, &offline)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a failed fetch must not downgrade an unverifiable relevant RRSIG: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(response.answers.len(), 0);
}

/// Regression: RFC 4035 5.3.3 - a validated RRset may not be cached (or
/// served with AD=1) beyond its signature's remaining validity.
#[test]
fn test_authenticated_ttl_is_capped_by_signature_expiry() {
    use hickory_proto::dnssec::crypto::EcdsaSigningKey;
    use hickory_proto::dnssec::{DnssecSigner, SigningKey};
    use hickory_proto::rr::RecordSet;

    let origin = Name::from_str("shortsig.example.").unwrap();
    let pkcs8 =
        EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).expect("generate pkcs8");
    let private =
        EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256).expect("key from pkcs8");
    let dnskey = DNSKEY::from_key(&private.to_public_key().expect("public key"));
    let signer = DnssecSigner::new(
        dnskey.clone(),
        Box::new(private),
        origin.clone(),
        Duration::from_secs(30),
    );

    let answer = Record::from_rdata(
        origin.clone(),
        86400,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 9))),
    );
    let mut set = RecordSet::new(origin.clone(), RecordType::A, 86400);
    set.insert(answer.clone(), 0);
    let signature = sign_test_rrset(&set, &signer);

    let mut trust_anchors = TrustAnchors::empty();
    trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(trust_anchors);

    let mut msg = Message::new(3, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(origin.clone(), RecordType::A));
    msg.answers.push(answer);
    msg.answers.push(signature);
    msg.additionals.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("ttl-test"), now);
    assert_eq!(outcome, ValidationOutcome::Secure);

    let answer_ttl = msg
        .answers
        .iter()
        .find(|record| record.record_type() == RecordType::A)
        .expect("answer")
        .ttl;
    assert!(
        answer_ttl <= 30,
        "authenticated TTL must not outlive the signature, got {answer_ttl}"
    );
    let sig_ttl = msg
        .answers
        .iter()
        .find(|record| record.record_type() == RecordType::RRSIG)
        .expect("rrsig")
        .ttl;
    assert!(
        sig_ttl <= 30,
        "the RRSIG TTL must be capped as well, got {sig_ttl}"
    );
}

/// A crafted response must not be able to force unbounded cryptographic
/// work: 128 RRSIGs (bounded by `MAX_RRSIGS`) each offering 64 candidate
/// DNSKEYs (bounded by `MAX_DNSKEYS`) used to mean thousands of ECDSA/RSA
/// verifications per client query.
#[test]
fn test_crafted_dnskey_rrsig_counts_stay_within_verification_budget() {
    let (origin, dnskey, _a_record, rrsig_record, _) =
        create_test_signed_domain("bounded.example.");

    let mut trust_anchors = TrustAnchors::empty();
    trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(trust_anchors);

    let mut msg = Message::new(4, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(origin.clone(), RecordType::A));
    // The signed RRset is replaced with a different address: every
    // candidate key fails verification, which is the attacker's
    // maximum-work case.
    msg.answers.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::A(A(Ipv4Addr::new(198, 51, 100, 9))),
    ));
    for _ in 0..MAX_RRSIGS {
        msg.answers.push(rrsig_record.clone());
    }
    for _ in 0..MAX_DNSKEYS {
        msg.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
        ));
    }

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("crafted"), now);

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "forged data must stay Bogus, got {outcome:?}"
    );
    let attempts = validator.metrics.signature_verifications();
    assert!(
        attempts <= u64::from(MAX_VERIFICATIONS_PER_RESPONSE),
        "crafted response exceeded the verification budget: {attempts} attempts"
    );
}

/// Builds an anchored validator whose `zone` key has already signed
/// validated data (so the zone is recorded as signed) and returns it with
/// the key and signer.
fn signed_zone_validator(
    zone: &str,
) -> (
    DnssecValidator,
    Name,
    DNSKEY,
    hickory_proto::dnssec::DnssecSigner,
) {
    let (origin, dnskey, a_record, rrsig_record, signer) = create_test_signed_domain(zone);
    let mut trust_anchors = TrustAnchors::empty();
    trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(trust_anchors);

    let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(origin.clone(), RecordType::A));
    msg.answers.push(a_record);
    msg.answers.push(rrsig_record);
    msg.additionals.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
    ));
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    assert_eq!(
        validator.validate_response(&mut msg, Some("t"), now),
        ValidationOutcome::Secure
    );
    (validator, origin, dnskey, signer)
}

/// An authenticated DS denial (parent-side delegation NSEC) must let an
/// unsigned delegation resolve as Insecure instead of a stripped-signature
/// SERVFAIL (audit 6, WP-1.2).
#[tokio::test]
async fn test_authenticated_ds_denial_downgrades_child_delegation_to_insecure() {
    let (validator, zone, zone_key, zone_signer) = signed_zone_validator("signed.example.");
    let cut = Name::from_str("unsigned.signed.example.").expect("cut");
    let ds_message = signed_nsec_response(
        &zone,
        &cut,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        &cut,
        &zone_key,
        &zone_signer,
        ResponseCode::NoError,
    );
    let fetcher = StaticFetcher::new().with(&cut, RecordType::DS, ds_message);

    let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");
    let mut response = Message::new(2, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::A));
    response.answers.push(Record::from_rdata(
        qname,
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;
    assert_eq!(
        outcome,
        ValidationOutcome::Insecure,
        "an authenticated DS denial must downgrade to Insecure"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(!response.metadata.authentic_data);
    assert_eq!(fetcher.calls(), 1, "only the cut DS lookup is needed");
}

/// Without an authenticated DS denial the stripped-signature decision must
/// stay fail-closed (Bogus), whether the DS response is empty/unavailable
/// or contains an authenticated DS.
#[tokio::test]
async fn test_unproven_delegation_stays_bogus() {
    use hickory_proto::dnssec::DigestType;
    use hickory_proto::rr::RecordSet;

    let (validator, zone, zone_key, zone_signer) = signed_zone_validator("signed.example.");
    let cut = Name::from_str("unsigned.signed.example.").expect("cut");
    let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    // Case 1: no DS answer at all (network/fetch failure) -> Unknown.
    let fetcher = StaticFetcher::new();
    let mut response = Message::new(3, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::A));
    response.answers.push(Record::from_rdata(
        qname.clone(),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 8))),
    ));
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "an unprovable delegation must fail closed: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);

    // Case 2: an authenticated DS proves the cut is signed -> stripped.
    let (child_zone, child_key, _) = create_test_signer("unsigned.signed.example.");
    assert_eq!(child_zone, cut);
    let ds = DS::from_key(child_key.public_key(), &cut, DigestType::SHA256).expect("ds");
    let ds_record = Record::from_rdata(cut.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
    let mut set = RecordSet::new(cut.clone(), RecordType::DS, 0);
    set.insert(ds_record.clone(), 0);
    let ds_sig = sign_test_rrset(&set, &zone_signer);
    let mut ds_message = Message::new(0, MessageType::Response, OpCode::Query);
    ds_message.answers.push(ds_record);
    ds_message.answers.push(ds_sig);
    ds_message.additionals.push(Record::from_rdata(
        zone.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(zone_key)),
    ));
    let fetcher = StaticFetcher::new().with(&cut, RecordType::DS, ds_message);

    let mut response = Message::new(4, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::A));
    response.answers.push(Record::from_rdata(
        qname,
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 9))),
    ));
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a signed cut with a stripped response must be Bogus: {outcome:?}"
    );
}

/// A name directly inside the signed zone with an authenticated DS NODATA
/// (no NS bit) still requires signatures: Bogus.
#[tokio::test]
async fn test_in_zone_ds_nodata_still_requires_signatures() {
    let (validator, zone, zone_key, zone_signer) = signed_zone_validator("signed.example.");
    let qname = Name::from_str("www.signed.example.").expect("qname");
    let ds_message = signed_nsec_response(
        &zone,
        &qname,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        &qname,
        &zone_key,
        &zone_signer,
        ResponseCode::NoError,
    );
    let fetcher = StaticFetcher::new().with(&qname, RecordType::DS, ds_message);

    let mut response = Message::new(5, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::A));
    response.answers.push(Record::from_rdata(
        qname,
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "an in-zone name still requires signatures: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
}

// ------------------------------------------------------------------
// D-05: persistent chain/negative-DS cache and cold-start delegation probe
// ------------------------------------------------------------------

fn chain_test_path(tag: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sito_d05_{}_{}_{}",
        std::process::id(),
        tag,
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir.join("dnssec-chain-cache.toml")
}

fn d05_validator(cache: Option<Arc<ChainCache>>) -> DnssecValidator {
    DnssecValidator::from_config_with_cache(&DnssecConfig::default(), cache)
        .with_trust_anchors(TrustAnchors::empty())
}

fn anchored_dnskey_message(
    zone: &Name,
    key: &DNSKEY,
    signer: &hickory_proto::dnssec::DnssecSigner,
) -> Message {
    use hickory_proto::rr::RecordSet;
    let mut set = RecordSet::new(zone.clone(), RecordType::DNSKEY, 0);
    set.insert(
        Record::from_rdata(
            zone.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(key.clone())),
        ),
        0,
    );
    let signature = sign_test_rrset(&set, signer);
    fetched_dnskey_message(zone, std::slice::from_ref(key), Some(signature))
}

fn signed_ds_message(
    cut: &Name,
    parent_signer: &hickory_proto::dnssec::DnssecSigner,
    child_key: &DNSKEY,
) -> Message {
    use hickory_proto::dnssec::{DigestType, rdata::DS};
    use hickory_proto::rr::RecordSet;

    let ds = DS::from_key(child_key.public_key(), cut, DigestType::SHA256).expect("ds");
    let ds_record = Record::from_rdata(cut.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
    let mut set = RecordSet::new(cut.clone(), RecordType::DS, 0);
    set.insert(ds_record.clone(), 0);
    let signature = sign_test_rrset(&set, parent_signer);
    let mut message = Message::new(0, MessageType::Response, OpCode::Query);
    message.answers.push(ds_record);
    message.answers.push(signature);
    message
}

/// A DS response proving (via an exact-match parent-side NSEC3) that the
/// delegation at `cut` has no DS and is legitimately unsigned.
fn signed_nsec3_ds_denial(
    parent: &Name,
    cut: &Name,
    key: &DNSKEY,
    signer: &hickory_proto::dnssec::DnssecSigner,
) -> Message {
    use data_encoding::BASE32_DNSSEC;
    use hickory_proto::dnssec::Nsec3HashAlgorithm;
    use hickory_proto::dnssec::rdata::NSEC3;
    use hickory_proto::rr::RecordSet;

    let algorithm = Nsec3HashAlgorithm::SHA1;
    let cut_hash = algorithm.hash(&[], cut, 0).expect("hash").as_ref().to_vec();
    let mut next = cut_hash.clone();
    for byte in next.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
    let nsec3 = NSEC3::new(
        algorithm,
        false,
        0,
        Vec::new(),
        next,
        [RecordType::NS, RecordType::RRSIG, RecordType::NSEC3],
    );
    let owner = Name::from_ascii(format!(
        "{}.{}",
        BASE32_DNSSEC.encode(&cut_hash),
        parent.to_ascii()
    ))
    .expect("NSEC3 owner");
    let record = Record::from_rdata(owner.clone(), 300, RData::DNSSEC(DNSSECRData::NSEC3(nsec3)));
    let mut set = RecordSet::new(owner, RecordType::NSEC3, 0);
    set.insert(record.clone(), 0);
    let signature = sign_test_rrset(&set, signer);

    let mut message = Message::new(26, MessageType::Response, OpCode::Query);
    message
        .queries
        .push(Query::query(cut.clone(), RecordType::DS));
    message.metadata.response_code = ResponseCode::NoError;
    message.authorities.push(record);
    message.authorities.push(signature);
    message.additionals.push(Record::from_rdata(
        parent.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(key.clone())),
    ));
    message
}

fn stripped_response(qname: &Name) -> Message {
    let mut response = Message::new(7, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::A));
    response.answers.push(Record::from_rdata(
        qname.clone(),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 44))),
    ));
    response
}

/// A DS response proving (via a covering NSEC) that `cut` does not exist
/// in `parent`, signed by the parent zone key.
fn covering_nsec_ds_message(
    parent: &Name,
    owner: &Name,
    next: &Name,
    cut: &Name,
    key: &DNSKEY,
    signer: &hickory_proto::dnssec::DnssecSigner,
) -> Message {
    signed_nsec_response_records(
        parent,
        &[(
            owner.clone(),
            next.clone(),
            vec![RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        )],
        cut,
        key,
        signer,
        ResponseCode::NXDomain,
    )
}

/// A stripped CNAME chain: `qname` points at `target`, and both the CNAME
/// and target A records carry no RRSIGs.
fn stripped_cname_response(qname: &Name, target: &Name) -> Message {
    use hickory_proto::rr::rdata::CNAME;
    let mut response = Message::new(8, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::A));
    response.answers.push(Record::from_rdata(
        qname.clone(),
        300,
        RData::CNAME(CNAME(target.clone())),
    ));
    response.answers.push(Record::from_rdata(
        target.clone(),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 45))),
    ));
    response
}

/// Critical regression: a stripped CNAME chain whose *target* is in a
/// signed zone must be Bogus even when the original qname is an
/// authenticated unsigned delegation.
#[tokio::test]
async fn test_stripped_cname_target_in_signed_zone_is_bogus() {
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let unsigned_cut = Name::from_str("unsigned.signed.example.").expect("cut");
    let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");
    let target = Name::from_str("www.signed.example.").expect("target");

    let validator = d05_validator(None);
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

    let unsigned_denial = signed_nsec_response(
        &parent_origin,
        &unsigned_cut,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        &unsigned_cut,
        &parent_key,
        &parent_signer,
        ResponseCode::NoError,
    );
    // The target exists inside the signed zone and is not a delegation.
    let target_in_zone = signed_nsec_response(
        &parent_origin,
        &target,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        &target,
        &parent_key,
        &parent_signer,
        ResponseCode::NoError,
    );
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(&unsigned_cut, RecordType::DS, unsigned_denial)
        .with(&target, RecordType::DS, target_in_zone);

    let mut response = stripped_cname_response(&qname, &target);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a stripped CNAME target in a signed zone must be Bogus: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
    assert!(
        response.answers.is_empty(),
        "bogus response must not carry the target answer: {:?}",
        response.answers
    );
}

/// Important regression: a stripped NXDOMAIN for a name directly in the
/// anchor zone is proven by a *covering* NSEC (owned by another name).
#[tokio::test]
async fn test_stripped_nxdomain_in_anchor_zone_is_bogus() {
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let qname = Name::from_str("missing.signed.example.").expect("qname");

    let validator = d05_validator(None);
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

    let ds_denial = covering_nsec_ds_message(
        &parent_origin,
        &Name::from_str("a.signed.example.").expect("owner"),
        &Name::from_str("z.signed.example.").expect("next"),
        &qname,
        &parent_key,
        &parent_signer,
    );
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(&qname, RecordType::DS, ds_denial);

    let mut response = Message::new(11, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::A));
    response.metadata.response_code = ResponseCode::NXDomain;

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a stripped NXDOMAIN in the anchor zone must be Bogus: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
}

/// Important regression: a stripped wildcard-synthesized answer directly
/// in the anchor zone is proven signed by the same covering-NSEC DS denial.
#[tokio::test]
async fn test_stripped_wildcard_answer_in_anchor_zone_is_bogus() {
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let qname = Name::from_str("wildcard.signed.example.").expect("qname");

    let validator = d05_validator(None);
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

    let ds_denial = covering_nsec_ds_message(
        &parent_origin,
        &Name::from_str("a.signed.example.").expect("owner"),
        &Name::from_str("z.signed.example.").expect("next"),
        &qname,
        &parent_key,
        &parent_signer,
    );
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(&qname, RecordType::DS, ds_denial);

    // The wildcard at *.signed.example. synthesized this A answer; the
    // response carries no RRSIGs.
    let mut response = stripped_response(&qname);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a stripped wildcard answer in the anchor zone must be Bogus: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
}

/// A stripped multi-hop CNAME chain ending in an A record. `targets` are
/// the successive CNAME targets (the first target replaces `qname`).
fn stripped_cname_chain_response(qname: &Name, targets: &[Name]) -> Message {
    use hickory_proto::rr::rdata::CNAME;
    let mut response = Message::new(9, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::A));
    let mut current = qname.clone();
    for target in targets {
        response.answers.push(Record::from_rdata(
            current,
            300,
            RData::CNAME(CNAME(target.clone())),
        ));
        current = target.clone();
    }
    response.answers.push(Record::from_rdata(
        current,
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 46))),
    ));
    response
}

/// Critical regression: unsigned qname → signed intermediate CNAME hop →
/// unsigned final target, all signatures stripped, must be Bogus. Probing
/// only the qname and final target would miss the signed intermediate.
#[tokio::test]
async fn test_stripped_signed_intermediate_cname_hop_is_bogus() {
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let unsigned_cut = Name::from_str("unsigned.signed.example.").expect("unsigned cut");
    let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");
    let mid = Name::from_str("mid.signed.example.").expect("mid");
    let final_cut = Name::from_str("unsigned2.signed.example.").expect("final cut");
    let final_target = Name::from_str("www.unsigned2.signed.example.").expect("final");

    let validator = d05_validator(None);
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

    let unsigned_denial = signed_nsec_response(
        &parent_origin,
        &unsigned_cut,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        &unsigned_cut,
        &parent_key,
        &parent_signer,
        ResponseCode::NoError,
    );
    // The intermediate name lives directly in the signed anchor zone and
    // is not a delegation.
    let mid_in_zone = signed_nsec_response(
        &parent_origin,
        &mid,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        &mid,
        &parent_key,
        &parent_signer,
        ResponseCode::NoError,
    );
    let final_denial = signed_nsec_response(
        &parent_origin,
        &final_cut,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        &final_cut,
        &parent_key,
        &parent_signer,
        ResponseCode::NoError,
    );
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(&unsigned_cut, RecordType::DS, unsigned_denial)
        .with(&mid, RecordType::DS, mid_in_zone)
        .with(&final_cut, RecordType::DS, final_denial);

    let mut response = stripped_cname_chain_response(&qname, &[mid, final_target]);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a stripped signed intermediate CNAME hop must be Bogus: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
    assert!(
        response.answers.is_empty(),
        "bogus response must not carry the chain: {:?}",
        response.answers
    );
}

/// The shared per-response probe budget fails closed instead of probing an
/// unbounded CNAME chain or returning AD=0.
#[tokio::test]
async fn test_cname_probe_budget_exhaustion_fails_closed() {
    let (origin, key, signer) = create_test_signer("example.");
    let qname = Name::from_str("n0.example.").expect("qname");
    let targets: Vec<Name> = (1..=9)
        .map(|index| Name::from_str(&format!("n{index}.example.")).expect("target"))
        .collect();

    let validator = d05_validator(None);
    validator.add_trust_anchor(&key, LowerName::from(&origin));
    // Only the anchor DNSKEY is available; every DS lookup returns an
    // empty message, so each probe is a genuine failed walk.
    let fetcher = StaticFetcher::new().with(
        &origin,
        RecordType::DNSKEY,
        anchored_dnskey_message(&origin, &key, &signer),
    );

    let mut response = stripped_cname_chain_response(&qname, &targets);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "an over-budget CNAME chain must fail closed: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
    assert!(
        fetcher.calls() <= 2 * MAX_CNAME_PROBES + 2,
        "probing must stay within the shared budget, got {} fetches",
        fetcher.calls()
    );
}

/// Positive NSEC3 regression: a *properly signed* NSEC3 NXDOMAIN proof for
/// a name directly in the anchor zone still makes a stripped response
/// Bogus.
#[tokio::test]
async fn test_stripped_nxdomain_with_signed_nsec3_denial_is_bogus() {
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let qname = Name::from_str("missing.signed.example.").expect("qname");

    let validator = d05_validator(None);
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

    let ds_denial = signed_optout_nxdomain(
        &parent_origin,
        &qname,
        &parent_key,
        &parent_signer,
        false,
        0,
    );
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(&qname, RecordType::DS, ds_denial);

    let mut response = Message::new(12, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::A));
    response.metadata.response_code = ResponseCode::NXDomain;

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a signed NSEC3 NXDOMAIN proof must still make a stripped response Bogus: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
}

/// `InZone` may only be inferred from NSEC3 records whose RRset carries an
/// RRSIG verified by a parent-zone key. An unsigned/forged covering proof
/// must not mark the cut signed or persist a Signed zone.
#[tokio::test]
async fn test_forged_nsec3_covering_proof_is_not_inzone_or_signed() {
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let cut = Name::from_str("missing.signed.example.").expect("cut");

    let validator = d05_validator(None);
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

    let mut forged =
        signed_optout_nxdomain(&parent_origin, &cut, &parent_key, &parent_signer, false, 0);
    forged
        .authorities
        .retain(|record| !matches!(record.data, RData::DNSSEC(DNSSECRData::RRSIG(_))));
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(&cut, RecordType::DS, forged);

    let mut response = Message::new(13, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(cut.clone(), RecordType::A));
    response.metadata.response_code = ResponseCode::NXDomain;

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "an unauthenticated covering proof must not produce InZone/Signed: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
    assert!(
        validator
            .chain_cache()
            .get(&LowerName::from(&cut), now)
            .is_none(),
        "a forged proof must not persist a Signed zone"
    );
    assert!(
        !validator.signed_zone_contains(&LowerName::from(&cut), now),
        "a forged proof must not mark the cut signed in memory"
    );
}

/// Important regression: the probe must walk the *shallowest* cuts. A deep
/// name beyond the per-query budget fails closed (Bogus), never AD=0.
#[tokio::test]
async fn test_deep_name_beyond_probe_budget_fails_closed() {
    let (root_origin, root_key, root_signer) = create_test_signer(".");
    let qname = Name::from_str("a.b.c.d.e.f.g.h.i.example.").expect("qname");
    let zone = LowerName::from(&root_origin);

    // The eight shallowest cuts must be the ones walked. Hard-code them so
    // the fixture cannot silently adapt to a deepest-first regression.
    let shallow = [
        "example.",
        "i.example.",
        "h.i.example.",
        "g.h.i.example.",
        "f.g.h.i.example.",
        "e.f.g.h.i.example.",
        "d.e.f.g.h.i.example.",
        "c.d.e.f.g.h.i.example.",
    ];
    let mut fetcher = StaticFetcher::new().with(
        &root_origin,
        RecordType::DNSKEY,
        anchored_dnskey_message(&root_origin, &root_key, &root_signer),
    );
    for cut in shallow {
        let cut_name = Name::from_str(cut).expect("cut");
        let next = Name::from_str(&format!("zzz.{cut}")).expect("next");
        let ds_nodata = signed_nsec_response(
            &root_origin,
            &cut_name,
            &next,
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
            &cut_name,
            &root_key,
            &root_signer,
            ResponseCode::NoError,
        );
        fetcher = fetcher.with(&cut_name, RecordType::DS, ds_nodata);
    }

    let validator = d05_validator(None);
    validator.add_trust_anchor(&root_key, zone);
    let mut response = stripped_response(&qname);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a deep name beyond the probe budget must fail closed: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
    assert!(
        fetcher.calls() > MAX_CHAIN_CUTS,
        "the shallow budget must actually be walked"
    );
}

/// `delegation_cuts` keeps the shallowest cuts and reports truncation.
#[test]
fn test_delegation_cuts_keep_shallowest_budget() {
    let zone = LowerName::from(&Name::from_str(".").expect("root"));
    let name = LowerName::from(&Name::from_str("a.b.c.d.e.f.g.h.i.example.").expect("name"));
    let (cuts, truncated) = delegation_cuts(&name, &zone);
    assert!(truncated, "the test name must exceed the probe budget");
    assert_eq!(cuts.len(), MAX_CHAIN_CUTS);
    assert_eq!(
        cuts.first(),
        Some(&LowerName::from(
            &Name::from_str("example.").expect("shallowest cut")
        )),
        "the budget must keep the shallowest cuts"
    );
    assert_eq!(
        cuts.last(),
        Some(&LowerName::from(
            &Name::from_str("c.d.e.f.g.h.i.example.").expect("eighth cut")
        )),
        "the eighth shallowest cut is the deepest one kept"
    );
}

/// Cold start, no prior signed data: an authenticated DS for the cut must
/// turn a stripped response into Bogus. This is the core D-05 fix.
#[tokio::test]
async fn test_stripped_rrsig_never_validated_zone_is_bogus() {
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let (cut_origin, cut_key, _cut_signer) = create_test_signer("child.signed.example.");

    let validator = d05_validator(None);
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(
            &cut_origin,
            RecordType::DS,
            signed_ds_message(&cut_origin, &parent_signer, &cut_key),
        );

    let mut response = stripped_response(&cut_origin);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a never-validated zone with an authenticated DS must be Bogus: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
    assert!(
        response.answers.is_empty(),
        "bogus response must not carry answers: {:?}",
        response.answers
    );
    assert!(
        fetcher.calls() >= 2,
        "cold start must fetch the anchor DNSKEY and the cut DS"
    );

    // The authenticated decision is cached for the queried name: a repeat
    // stripped response is Bogus without walking the chain again.
    let calls_after_first = fetcher.calls();
    let mut repeat = stripped_response(&cut_origin);
    let repeat_outcome = validator
        .validate_with_key_fetcher(&mut repeat, Some("probe"), now, &fetcher)
        .await;
    assert!(matches!(repeat_outcome, ValidationOutcome::Bogus { .. }));
    assert_eq!(
        fetcher.calls(),
        calls_after_first,
        "the cached signed decision must avoid a second DS walk"
    );
}

/// A genuinely unsigned zone must stay Insecure (NOERROR, AD=0), not Bogus.
#[tokio::test]
async fn test_genuinely_unsigned_zone_authenticated_ds_denial_is_insecure() {
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let cut = Name::from_str("unsigned.signed.example.").expect("cut");
    let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");

    let validator = d05_validator(None);
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

    let ds_denial = signed_nsec_response(
        &parent_origin,
        &cut,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        &cut,
        &parent_key,
        &parent_signer,
        ResponseCode::NoError,
    );
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(&cut, RecordType::DS, ds_denial);

    let mut response = stripped_response(&qname);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert_eq!(
        outcome,
        ValidationOutcome::Insecure,
        "an authenticated DS denial proves the delegation is unsigned"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(!response.metadata.authentic_data);
    assert_eq!(
        response.answers.len(),
        1,
        "insecure answers are passed through"
    );
}

/// A genuinely unsigned zone whose DS denial is authenticated by an exact
/// NSEC3 record (not an NSEC/opt-out covering proof) must also be Insecure,
/// including on a cold start.
#[tokio::test]
async fn test_cold_start_nsec3_ds_denial_is_insecure() {
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let cut = Name::from_str("unsigned.signed.example.").expect("cut");
    let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");

    let validator = d05_validator(None);
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

    let ds_denial = signed_nsec3_ds_denial(&parent_origin, &cut, &parent_key, &parent_signer);
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(&cut, RecordType::DS, ds_denial);

    let mut response = stripped_response(&qname);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert_eq!(
        outcome,
        ValidationOutcome::Insecure,
        "an exact NSEC3 DS denial must prove the delegation is unsigned"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(!response.metadata.authentic_data);
    assert!(
        validator
            .chain_cache()
            .covers_unsigned(&LowerName::from(&cut), now)
            .is_some(),
        "the authenticated unsigned delegation must be cached"
    );
}

/// Important regression (I1): a persistent `Unsigned` chain-cache entry
/// established before `corp.` was anchored must not keep a stripped
/// response under the newly anchored zone Insecure. Adding the anchor
/// invalidates the cached denial and the fresh probe makes it Bogus.
#[tokio::test]
async fn test_cached_unsigned_does_not_override_new_trust_anchor() {
    let (corp_origin, corp_key, corp_signer) = create_test_signer("corp.");
    let qname = Name::from_str("www.corp.").expect("qname");
    let corp_zone = LowerName::from(&corp_origin);

    let cache = Arc::new(ChainCache::new(None));
    let validator =
        DnssecValidator::from_config_with_cache(&DnssecConfig::default(), Some(cache.clone()))
            .with_trust_anchors(TrustAnchors::empty());
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    // A previous (unanchored) run authenticated a DS denial for `corp.`
    // and persisted it for an hour.
    cache.insert(
        corp_zone.clone(),
        ZoneStatus::Unsigned,
        now.saturating_add(3600),
        now,
    );
    assert!(
        !validator.insecure_zone_covers(&corp_zone, now),
        "sanity: the in-memory map starts empty"
    );

    // The operator now anchors `corp.` and reloads.
    validator.add_trust_anchor(&corp_key, corp_zone.clone());
    assert!(
        cache.get(&corp_zone, now).is_none(),
        "the stale unsigned entry must be invalidated by the new anchor"
    );

    let in_zone = signed_nsec_response(
        &corp_origin,
        &qname,
        &Name::from_str("z.corp.").expect("next"),
        &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        &qname,
        &corp_key,
        &corp_signer,
        ResponseCode::NoError,
    );
    let fetcher = StaticFetcher::new()
        .with(
            &corp_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&corp_origin, &corp_key, &corp_signer),
        )
        .with(&qname, RecordType::DS, in_zone);

    let mut response = stripped_response(&qname);
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a stripped response under a newly anchored zone must be Bogus: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
}

/// Regression A: a legitimate unsigned child below a configured anchor
/// must keep its cached proof across a reload. Only an anchor at or below
/// the cached unsigned zone may invalidate it.
#[tokio::test]
async fn test_cached_unsigned_child_below_anchor_survives_reload() {
    use base64::Engine as _;

    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let (child_origin, child_key, _child_signer) = create_test_signer("unsigned.signed.example.");
    let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    let anchor = format!(
        "signed.example:13:{}",
        base64::engine::general_purpose::STANDARD.encode(parent_key.public_key().public_bytes())
    );
    let config = DnssecConfig {
        trust_anchors: vec![anchor],
        ..Default::default()
    };

    let cache = Arc::new(ChainCache::new(None));
    let validator = DnssecValidator::from_config_with_cache(&config, Some(cache.clone()));

    let ds_denial = signed_nsec_response(
        &parent_origin,
        &child_origin,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        &child_origin,
        &parent_key,
        &parent_signer,
        ResponseCode::NoError,
    );
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(&child_origin, RecordType::DS, ds_denial);

    let mut response = stripped_response(&qname);
    let first = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;
    assert_eq!(
        first,
        ValidationOutcome::Insecure,
        "the child delegation is authenticated as unsigned"
    );
    let child_zone = LowerName::from(&child_origin);
    assert!(
        cache.covers_unsigned(&child_zone, now).is_some(),
        "the unsigned child must be cached"
    );

    // Reproduce the hard case: signed evidence for the parent is also
    // cached, so an offline probe would fail closed if the child's unsigned
    // proof were dropped.
    cache.insert(
        LowerName::from(&parent_origin),
        ZoneStatus::Signed,
        now.saturating_add(600),
        now,
    );

    // Reload with the same configured anchor. The child's cached unsigned
    // proof must survive.
    let reloaded = DnssecValidator::from_config_with_cache(&config, Some(cache.clone()));
    assert!(
        cache.covers_unsigned(&child_zone, now).is_some(),
        "reload must not evict a legitimate unsigned child below the anchor"
    );
    let offline = OfflineFetcher::new();
    let mut response = stripped_response(&qname);
    let outcome = reloaded
        .validate_with_key_fetcher(&mut response, Some("offline"), now, &offline)
        .await;
    assert_eq!(
        outcome,
        ValidationOutcome::Insecure,
        "a cached unsigned child must stay Insecure across reload while offline"
    );

    // An anchor at/below the child contradicts its cached denial and must
    // still invalidate it (the original I1 protection).
    let child_anchored = DnssecValidator::from_config_with_cache(&config, Some(cache.clone()));
    child_anchored.add_trust_anchor(&child_key, child_zone.clone());
    assert!(
        cache.covers_unsigned(&child_zone, now).is_none(),
        "an anchor at the cached unsigned zone must invalidate it"
    );
    let offline = OfflineFetcher::new();
    let mut response = stripped_response(&qname);
    let outcome = child_anchored
        .validate_with_key_fetcher(&mut response, Some("offline"), now, &offline)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a newly anchored zone must fail closed: {outcome:?}"
    );
}

/// Regression (deferred D2): a non-root anchor island below an
/// authenticated unsigned delegation must not be shadowed by the parent's
/// Insecure status. `cached_unsigned_zone` already honored the anchor, but
/// `insecure_zone_covers` did not, so a stripped response under the island
/// could take the Insecure shortcut without probing the anchor.
#[tokio::test]
async fn test_anchor_island_under_unsigned_delegation_is_not_insecure() {
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let unsigned_cut = Name::from_str("unsigned.signed.example.").expect("cut");
    let (island_origin, island_key, island_signer) =
        create_test_signer("island.unsigned.signed.example.");
    let qname = Name::from_str("www.island.unsigned.signed.example.").expect("qname");
    let sibling = Name::from_str("www.unsigned.signed.example.").expect("sibling");
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    let validator = d05_validator(None);
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));
    validator.add_trust_anchor(&island_key, LowerName::from(&island_origin));

    // Populate the unsigned parent through the normal validation path: a
    // sibling query authenticates the parent-side DS denial for the
    // unsigned delegation. This is the state that used to shadow the
    // island after a reload.
    let ds_denial = signed_nsec_response(
        &parent_origin,
        &unsigned_cut,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        &unsigned_cut,
        &parent_key,
        &parent_signer,
        ResponseCode::NoError,
    );
    let sibling_fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(&unsigned_cut, RecordType::DS, ds_denial);
    let mut sibling_response = stripped_response(&sibling);
    let sibling_outcome = validator
        .validate_with_key_fetcher(
            &mut sibling_response,
            Some("sibling"),
            now,
            &sibling_fetcher,
        )
        .await;
    assert_eq!(
        sibling_outcome,
        ValidationOutcome::Insecure,
        "the sibling must be authenticated as an unsigned delegation"
    );
    assert!(
        validator
            .insecure_zones
            .contains_key(&LowerName::from(&unsigned_cut)),
        "the normal path must populate the in-memory unsigned zone"
    );

    assert!(
        !validator.insecure_zone_covers(&LowerName::from(&qname), now),
        "the parent's unsigned status must not cover the anchored island"
    );

    // Sibling names outside the island still legitimately use the
    // authenticated parent-side denial.
    assert!(
        validator.insecure_zone_covers(&LowerName::from(&sibling), now),
        "names outside the anchor island must remain Insecure"
    );

    // A stripped answer under the island must fail closed instead of
    // being accepted as an unsigned delegation.
    let in_zone = signed_nsec_response(
        &island_origin,
        &qname,
        &nsec_next(&island_origin),
        &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        &qname,
        &island_key,
        &island_signer,
        ResponseCode::NoError,
    );
    let fetcher = StaticFetcher::new()
        .with(
            &island_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&island_origin, &island_key, &island_signer),
        )
        .with(&qname, RecordType::DS, in_zone);
    let mut response = stripped_response(&qname);
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a stripped response under an anchored island must be Bogus: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
}

/// The `AddedAnchors` arm of `from_config_with_cache` must prune only the
/// affected process-local unsigned zones, leaving unrelated ones intact.
#[test]
fn test_reload_added_anchor_prunes_only_affected_in_memory_unsigned_zones() {
    use base64::Engine as _;

    let (signed_origin, signed_key, _signed_signer) = create_test_signer("signed.example.");
    let (other_origin, other_key, _other_signer) = create_test_signer("other.example.");
    let anchor = |origin: &Name, key: &DNSKEY| {
        format!(
            "{}:13:{}",
            origin.to_ascii().trim_end_matches('.'),
            base64::engine::general_purpose::STANDARD.encode(key.public_key().public_bytes())
        )
    };
    let config_one = DnssecConfig {
        trust_anchors: vec![anchor(&signed_origin, &signed_key)],
        ..Default::default()
    };
    let config_two = DnssecConfig {
        trust_anchors: vec![
            anchor(&signed_origin, &signed_key),
            anchor(&other_origin, &other_key),
        ],
        ..Default::default()
    };

    let validator =
        DnssecValidator::from_config_with_cache(&config_one, Some(Arc::new(ChainCache::new(None))));
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let affected = LowerName::from(&other_origin);
    let unrelated = LowerName::from(
        &Name::from_str("unsigned.signed.example.").expect("unrelated unsigned zone"),
    );
    validator
        .insecure_zones
        .insert(affected.clone(), now.saturating_add(600));
    validator
        .insecure_zones
        .insert(unrelated.clone(), now.saturating_add(600));

    // A reload builds a new validator with empty process-local maps, so the
    // shared policy-apply path is exercised on this validator to retain the
    // seeded `insecure_zones`. Insert the anchor without the direct
    // `add_trust_anchor` invalidation that the policy diff must perform.
    validator.insert_raw_trust_anchor(other_key.public_key(), &affected);
    validator.anchor_zones.insert(affected.clone(), ());
    let change = validator.apply_chain_cache_policy(&config_two);
    assert_eq!(
        change,
        PolicyChange::AddedAnchors(vec![affected.clone()]),
        "the second config only adds the other.example. anchor"
    );
    assert!(
        !validator.insecure_zones.contains_key(&affected),
        "an added anchor must clear the in-memory unsigned zone at the anchor"
    );
    assert!(
        validator.insecure_zones.contains_key(&unrelated),
        "an unrelated in-memory unsigned zone must survive an anchor addition"
    );
}

/// Important regression (I2): an offline probe for a CNAME target in a
/// signed zone must not fall through to Insecure just because the original
/// qname is a legitimately unsigned delegation. In strict mode it fails
/// closed with SERVFAIL.
#[tokio::test]
async fn test_failed_cname_target_probe_fails_closed_not_insecure() {
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let unsigned_cut = Name::from_str("unsigned.signed.example.").expect("cut");
    let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");
    let target = Name::from_str("www.signed.example.").expect("target");

    let validator = d05_validator(None);
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

    let unsigned_denial = signed_nsec_response(
        &parent_origin,
        &unsigned_cut,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        &unsigned_cut,
        &parent_key,
        &parent_signer,
        ResponseCode::NoError,
    );
    // The target's DS lookup is deliberately absent: the probe is offline.
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(&unsigned_cut, RecordType::DS, unsigned_denial);

    let mut response = stripped_cname_response(&qname, &target);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a failed probe for a signed CNAME target must SERVFAIL, not Insecure: {outcome:?}"
    );
    assert!(!response.metadata.authentic_data);
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
}

/// A root-anchored cold start must follow a signed intermediate cut
/// (`tld.`) and still classify a deeper unsigned delegation as Insecure,
/// not Bogus. This guards the nested-unsigned false-positive case.
#[tokio::test]
async fn test_cold_start_follows_signed_cut_before_unsigned_delegation() {
    let (root_origin, root_key, root_signer) = create_test_signer(".");
    let (tld_origin, tld_key, tld_signer) = create_test_signer("tld.");
    let cut = Name::from_str("unsigned.tld.").expect("cut");
    let qname = Name::from_str("www.unsigned.tld.").expect("qname");

    let validator = d05_validator(None);
    validator.add_trust_anchor(&root_key, LowerName::from(&root_origin));

    let tld_ds = signed_ds_message(&tld_origin, &root_signer, &tld_key);
    let tld_denial = signed_nsec_response(
        &tld_origin,
        &cut,
        &Name::from_str("z.tld.").expect("next"),
        &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        &cut,
        &tld_key,
        &tld_signer,
        ResponseCode::NoError,
    );
    let fetcher = StaticFetcher::new()
        .with(
            &root_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&root_origin, &root_key, &root_signer),
        )
        .with(&tld_origin, RecordType::DS, tld_ds)
        .with(
            &tld_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&tld_origin, &tld_key, &tld_signer),
        )
        .with(&cut, RecordType::DS, tld_denial);

    let mut response = stripped_response(&qname);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert_eq!(
        outcome,
        ValidationOutcome::Insecure,
        "a nested unsigned delegation must remain Insecure after walking a signed TLD"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(!response.metadata.authentic_data);
    assert!(
        fetcher.calls() >= 4,
        "the walk must fetch the root keys, the TLD DS/DNSKEY and the denial"
    );
}

/// The authenticated unsigned status is cached: the second query under the
/// same zone does not fetch again.
#[tokio::test]
async fn test_delegation_cache_hit_skips_fetches() {
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let cut = Name::from_str("unsigned.signed.example.").expect("cut");
    let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");

    let cache = Arc::new(ChainCache::new(None));
    let validator = d05_validator(Some(cache.clone()));
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

    let ds_denial = signed_nsec_response(
        &parent_origin,
        &cut,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        &cut,
        &parent_key,
        &parent_signer,
        ResponseCode::NoError,
    );
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(&cut, RecordType::DS, ds_denial);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let mut first = stripped_response(&qname);
    let first_outcome = validator
        .validate_with_key_fetcher(&mut first, Some("probe"), now, &fetcher)
        .await;
    assert_eq!(first_outcome, ValidationOutcome::Insecure);
    let calls_after_first = fetcher.calls();
    assert!(calls_after_first > 0);

    let mut second = stripped_response(&qname);
    let second_outcome = validator
        .validate_with_key_fetcher(&mut second, Some("probe"), now, &fetcher)
        .await;
    assert_eq!(second_outcome, ValidationOutcome::Insecure);
    assert_eq!(
        fetcher.calls(),
        calls_after_first,
        "the cached unsigned delegation must not be re-probed"
    );
}

/// A cached Signed zone makes a stripped response Bogus without any fetch.
#[tokio::test]
async fn test_signed_zone_cache_hit_avoids_ds_fetch() {
    let zone = Name::from_str("child.signed.example.").expect("zone");
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let cache = Arc::new(ChainCache::new(None));
    // The validator records the policy fingerprint on construction; seed
    // the entry afterwards so it belongs to the active policy.
    let validator = d05_validator(Some(cache.clone()));
    assert!(
        Arc::ptr_eq(validator.chain_cache(), &cache),
        "the validator must reuse the supplied cache"
    );
    cache.insert(LowerName::from(&zone), ZoneStatus::Signed, now + 600, now);
    let fetcher = StaticFetcher::new();
    let mut response = stripped_response(&zone);
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a cached signed zone must fail closed immediately: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(fetcher.calls(), 0, "a cache hit must not fetch anything");
}

/// Authenticated statuses survive a restart through the on-disk cache.
#[tokio::test]
async fn test_chain_cache_survives_restart() {
    let path = chain_test_path("restart");
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let (cut_origin, cut_key, _cut_signer) = create_test_signer("child.signed.example.");
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(
            &cut_origin,
            RecordType::DS,
            signed_ds_message(&cut_origin, &parent_signer, &cut_key),
        );

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let first_cache = Arc::new(ChainCache::new(Some(path.clone())));
    first_cache.load(now);
    let first_validator = d05_validator(Some(first_cache.clone()));
    first_validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

    let mut first = stripped_response(&cut_origin);
    let first_outcome = first_validator
        .validate_with_key_fetcher(&mut first, Some("probe"), now, &fetcher)
        .await;
    assert!(matches!(first_outcome, ValidationOutcome::Bogus { .. }));
    assert!(
        matches!(
            first_cache.get(&LowerName::from(&cut_origin), now),
            Some(ChainEntry {
                status: ZoneStatus::Signed,
                ..
            })
        ),
        "the authenticated signed status must be cached"
    );
    first_cache.flush().expect("flush chain cache");

    // "Restart": rebuild the cache and the validator from the same path.
    let second_cache = Arc::new(ChainCache::new(Some(path.clone())));
    second_cache.load(now);
    let second_validator = d05_validator(Some(second_cache.clone()));
    second_validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));
    let second_fetcher = StaticFetcher::new();

    let mut second = stripped_response(&cut_origin);
    let second_outcome = second_validator
        .validate_with_key_fetcher(&mut second, Some("probe"), now, &second_fetcher)
        .await;
    assert!(
        matches!(second_outcome, ValidationOutcome::Bogus { .. }),
        "a persisted signed zone must still fail closed after restart: {second_outcome:?}"
    );
    assert_eq!(
        second_fetcher.calls(),
        0,
        "the persisted cache must avoid a cold-start fetch"
    );

    let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
}

/// An expired cache entry is ignored and the zone is re-probed.
#[tokio::test]
async fn test_chain_cache_expiry_reprobes() {
    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let (cut_origin, cut_key, _cut_signer) = create_test_signer("child.signed.example.");
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    let cache = Arc::new(ChainCache::new(None));
    cache.insert(
        LowerName::from(&cut_origin),
        ZoneStatus::Signed,
        now - 1,
        now - 2,
    );
    assert!(
        cache.get(&LowerName::from(&cut_origin), now).is_none(),
        "expired entries must not be returned"
    );

    let validator = d05_validator(Some(cache));
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(
            &cut_origin,
            RecordType::DS,
            signed_ds_message(&cut_origin, &parent_signer, &cut_key),
        );

    let mut response = stripped_response(&cut_origin);
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;
    assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
    assert!(
        fetcher.calls() >= 2,
        "an expired entry must trigger a fresh walk"
    );
}

/// A corrupt cache file never prevents startup; the probe still works.
#[tokio::test]
async fn test_chain_cache_corrupt_file_ignored() {
    let path = chain_test_path("corrupt");
    std::fs::write(&path, "entries = [ { this is not toml").expect("write corrupt");

    let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
    let (cut_origin, cut_key, _cut_signer) = create_test_signer("child.signed.example.");
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let cache = Arc::new(ChainCache::new(Some(path.clone())));
    cache.load(now);
    assert!(cache.is_empty(), "a corrupt file must load as empty");

    let validator = d05_validator(Some(cache));
    validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));
    let fetcher = StaticFetcher::new()
        .with(
            &parent_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
        )
        .with(
            &cut_origin,
            RecordType::DS,
            signed_ds_message(&cut_origin, &parent_signer, &cut_key),
        );

    let mut response = stripped_response(&cut_origin);
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "cold-start validation must still work after a corrupt cache: {outcome:?}"
    );

    let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
}

/// A fetcher whose upstream answers every chain lookup with NXDOMAIN.
struct NxdomainFetcher {
    calls: std::sync::atomic::AtomicUsize,
}

impl NxdomainFetcher {
    fn new() -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl DnssecKeyFetcher for NxdomainFetcher {
    async fn query(&self, name: &Name, _rtype: RecordType) -> Result<Message, UpstreamError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message
            .queries
            .push(Query::query(name.clone(), RecordType::DNSKEY));
        message.metadata.response_code = ResponseCode::NXDomain;
        Ok(message)
    }
}

struct OfflineFetcher {
    calls: std::sync::atomic::AtomicUsize,
}

impl OfflineFetcher {
    fn new() -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl DnssecKeyFetcher for OfflineFetcher {
    async fn query(&self, _name: &Name, _rtype: RecordType) -> Result<Message, UpstreamError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(UpstreamError::Timeout)
    }
}

/// Offline policy: a never-proven zone fails closed (Bogus/SERVFAIL) and is
/// backed off, cached signed evidence stays fail-closed (Bogus), and cached
/// unsigned evidence stays Insecure.
#[tokio::test]
async fn test_offline_probe_policy() {
    let qname = Name::from_str("www.never.example.").expect("qname");
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    let validator = DnssecValidator::from_config(&DnssecConfig::default());
    let offline = OfflineFetcher::new();
    let mut response = stripped_response(&qname);
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("offline"), now, &offline)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a never-proven zone must fail closed while offline: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
    let calls = offline.calls();
    assert!(calls > 0, "the probe must have been attempted");
    assert!(
        validator
            .chain_cache()
            .get(&LowerName::from(&qname), now)
            .is_none(),
        "a failed probe must never be persisted"
    );

    // A second query inside the backoff window must not fetch again, but
    // strict mode still fails closed.
    let mut second = stripped_response(&qname);
    let second_outcome = validator
        .validate_with_key_fetcher(&mut second, Some("offline"), now, &offline)
        .await;
    assert!(
        matches!(second_outcome, ValidationOutcome::Bogus { .. }),
        "a backed-off failed probe must still SERVFAIL: {second_outcome:?}"
    );
    assert_eq!(
        offline.calls(),
        calls,
        "a failed probe must be backed off to prevent fetch storms"
    );

    // Cached signed evidence: network failure must stay Bogus.
    let (parent_origin, parent_key, _parent_signer) = create_test_signer("signed.example.");
    let child = Name::from_str("child.signed.example.").expect("child");
    let cache = Arc::new(ChainCache::new(None));
    let signed_validator = d05_validator(Some(cache.clone()));
    cache.insert(LowerName::from(&child), ZoneStatus::Signed, now + 600, now);
    signed_validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));
    let offline = OfflineFetcher::new();
    let mut response =
        stripped_response(&Name::from_str("www.child.signed.example.").expect("qname"));
    let outcome = signed_validator
        .validate_with_key_fetcher(&mut response, Some("offline"), now, &offline)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "cached signed evidence must fail closed offline: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(offline.calls() > 0, "the walk must try the network");

    // Cached unsigned evidence: offline stays Insecure with no fetch.
    let unsigned = Name::from_str("unsigned.signed.example.").expect("unsigned");
    let cache = Arc::new(ChainCache::new(None));
    let unsigned_validator = d05_validator(Some(cache.clone()));
    cache.insert(
        LowerName::from(&unsigned),
        ZoneStatus::Unsigned,
        now + 600,
        now,
    );
    let offline = OfflineFetcher::new();
    let mut response =
        stripped_response(&Name::from_str("www.unsigned.signed.example.").expect("qname"));
    let outcome = unsigned_validator
        .validate_with_key_fetcher(&mut response, Some("offline"), now, &offline)
        .await;
    assert_eq!(outcome, ValidationOutcome::Insecure);
    assert_eq!(offline.calls(), 0);
    assert!(!response.metadata.authentic_data);
}

/// P1-1 DNAME residual: hickory-proto 0.26.3 does not reject DNAME on the
/// wire; it decodes it as `RData::Unknown { code: DNAME }`. The validator
/// cannot interpret/follow it and must fail closed (strict mode Bogus with
/// SERVFAIL), never assert AD or serve it as validated.
#[tokio::test]
async fn test_dname_unknown_rdata_fails_closed() {
    use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
    use sito_proto::rdata::NULL;

    let qname = Name::from_str("alias.example.").expect("qname");
    let target = Name::from_str("target.example.").expect("target");
    let mut target_wire = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut target_wire);
        target.emit(&mut encoder).expect("encode DNAME target");
    }
    let mut response = Message::new(1, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::DNAME));
    response.answers.push(Record::from_rdata(
        qname.clone(),
        300,
        RData::Unknown {
            code: RecordType::DNAME,
            rdata: NULL::with(target_wire),
        },
    ));

    // Prove the actual wire mechanism: DNAME survives decode as an
    // unsupported/unknown RDATA, it is not a parse error.
    let wire = sito_proto::encode_message(&response).expect("encode response");
    let mut decoded = sito_proto::decode_message(&wire).expect("DNAME must decode");
    assert!(
        matches!(
            decoded.answers.first().map(|record| &record.data),
            Some(RData::Unknown { code, .. }) if *code == RecordType::DNAME
        ),
        "expected DNAME to decode as RData::Unknown"
    );
    assert_eq!(
        decoded.answers[0].record_type(),
        RecordType::DNAME,
        "the unknown RDATA still reports the DNAME record type"
    );

    let validator = DnssecValidator::from_config(&DnssecConfig::default());
    let offline = OfflineFetcher::new();
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut decoded, Some("offline"), now, &offline)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "DNAME without interpretable/authenticated data must fail closed: {outcome:?}"
    );
    assert_eq!(decoded.metadata.response_code, ResponseCode::ServFail);
    assert!(
        !decoded.metadata.authentic_data,
        "a DNAME response must never be served with AD=1"
    );
}

/// RFC 4035 3.2.3: AD must not be set when the Answer/Authority sections
/// contain an RRset that is not covered by a trusted signature.
#[test]
fn test_unauthenticated_authority_rrset_clears_ad() {
    let (origin, dnskey, a_record, rrsig_record, signer) = create_test_signed_domain("ad.example.");
    let _ = signer;

    let mut trust_anchors = TrustAnchors::empty();
    trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(trust_anchors);

    let ns = Record::from_rdata(
        origin.clone(),
        300,
        RData::NS(hickory_proto::rr::rdata::NS(
            Name::from_str("ns.ad.example.").expect("ns"),
        )),
    );

    let mut msg = Message::new(6, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(origin.clone(), RecordType::A));
    msg.answers.push(a_record);
    msg.answers.push(rrsig_record);
    msg.authorities.push(ns);
    msg.additionals.push(Record::from_rdata(
        origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("ad-test"), now);
    assert_eq!(
        outcome,
        ValidationOutcome::Insecure,
        "an unsigned authority RRset must clear AD"
    );
    assert!(!msg.metadata.authentic_data);
    assert_ne!(msg.metadata.response_code, ResponseCode::ServFail);
}

#[test]
fn test_expired_ds_rrsig_in_trust_chain_is_bogus() {
    use hickory_proto::dnssec::rdata::DS;
    use hickory_proto::dnssec::{DigestType, rdata::DNSSECRData};
    use hickory_proto::rr::RecordSet;

    let (parent_origin, parent_key, parent_signer) = create_test_signer("example.");
    let (child_origin, child_key, child_signer) = create_test_signer("sub.example.");

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(parent_key.public_key(), LowerName::from(&parent_origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    // Sign DS RRset at `now - 7200` with 3600s duration so its RRSIG is expired at `now`.
    let past_utc = time::OffsetDateTime::now_utc() - time::Duration::seconds(7200);
    let ds = DS::from_key(child_key.public_key(), &child_origin, DigestType::SHA256).expect("ds");
    let ds_record = Record::from_rdata(
        child_origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DS(ds)),
    );
    let mut ds_set = RecordSet::new(child_origin.clone(), RecordType::DS, 0);
    ds_set.insert(ds_record.clone(), 0);
    let expired_ds_rrsig =
        RRSIG::from_rrset(&ds_set, DNSClass::IN, past_utc, &parent_signer).expect("sign ds");
    let expired_ds_sig_record = Record::from_rdata(
        child_origin.clone(),
        300,
        RData::DNSSEC(DNSSECRData::RRSIG(expired_ds_rrsig)),
    );

    // Sign child A RRset at `now` (valid).
    let a_record = Record::from_rdata(
        child_origin.clone(),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 55))),
    );
    let mut a_set = RecordSet::new(child_origin.clone(), RecordType::A, 0);
    a_set.insert(a_record.clone(), 0);
    let a_sig = sign_test_rrset(&a_set, &child_signer);

    let mut msg = Message::new(7, MessageType::Response, OpCode::Query);
    msg.queries
        .push(Query::query(child_origin.clone(), RecordType::A));
    msg.answers.push(a_record);
    msg.answers.push(a_sig);
    msg.authorities.push(ds_record);
    msg.authorities.push(expired_ds_sig_record);
    msg.additionals.push(Record::from_rdata(
        parent_origin,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(parent_key)),
    ));
    msg.additionals.push(Record::from_rdata(
        child_origin,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(child_key)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("expired-ds"), now);
    assert_eq!(
        outcome,
        ValidationOutcome::Bogus {
            reason: "Signature expired".to_string(),
            ede_code: EDE_SIGNATURE_EXPIRED,
        }
    );
    assert!(!msg.metadata.authentic_data);
}

#[test]
fn test_signed_cname_to_unsigned_external_zone_without_ds_denial_is_not_insecure() {
    use hickory_proto::rr::RecordSet;
    use hickory_proto::rr::rdata::CNAME;

    let (origin, dnskey, signer) = create_test_signer("signed.example.");
    let alias = Name::from_str("alias.signed.example.").expect("alias");
    let external_target = Name::from_str("www.unsigned.org.").expect("target");

    let mut anchors = TrustAnchors::empty();
    anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
    let validator =
        DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

    let cname_record = Record::from_rdata(
        alias.clone(),
        300,
        RData::CNAME(CNAME(external_target.clone())),
    );
    let mut cname_set = RecordSet::new(alias.clone(), RecordType::CNAME, 0);
    cname_set.insert(cname_record.clone(), 0);
    let cname_sig = sign_test_rrset(&cname_set, &signer);

    let unsigned_a = Record::from_rdata(
        external_target,
        300,
        RData::A(A(Ipv4Addr::new(198, 51, 100, 7))),
    );

    let mut msg = Message::new(8, MessageType::Response, OpCode::Query);
    msg.queries.push(Query::query(alias, RecordType::A));
    msg.answers.push(cname_record);
    msg.answers.push(cname_sig);
    msg.answers.push(unsigned_a);
    msg.additionals.push(Record::from_rdata(
        origin,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator.validate_response(&mut msg, Some("cname-unsigned"), now);
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "without an authenticated DS denial the target is not proven unsigned and strict mode must fail closed: {outcome:?}"
    );
    assert!(!msg.metadata.authentic_data);
    assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
}

/// Hostile regression: absence of signed-zone evidence for a CNAME target
/// is not proof that the target is unsigned. An attacker can strip the
/// target's RRSIG. Only an authenticated DS denial (`insecure_zone_covers`)
/// may downgrade the chain to Insecure; strict mode must fail closed.
#[tokio::test]
async fn test_signed_cname_to_stripped_target_without_ds_denial_is_bogus() {
    use hickory_proto::rr::RecordSet;
    use hickory_proto::rr::rdata::CNAME;

    let (validator, origin, _key, signer) = signed_zone_validator("signed.example.");
    let alias = Name::from_str("alias.signed.example.").expect("alias");
    let target = Name::from_str("www.unsigned.org.").expect("target");

    let cname_record = Record::from_rdata(alias.clone(), 300, RData::CNAME(CNAME(target.clone())));
    let mut cname_set = RecordSet::new(alias.clone(), RecordType::CNAME, 0);
    cname_set.insert(cname_record.clone(), 0);
    let cname_sig = sign_test_rrset(&cname_set, &signer);

    let mut response = Message::new(9, MessageType::Response, OpCode::Query);
    response.queries.push(Query::query(alias, RecordType::A));
    response.answers.push(cname_record);
    response.answers.push(cname_sig);
    // The target answer carries no RRSIG: a stripped signature.
    response.answers.push(Record::from_rdata(
        target,
        300,
        RData::A(A(Ipv4Addr::new(198, 51, 100, 8))),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let offline = OfflineFetcher::new();
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("cname-stripped"), now, &offline)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a stripped CNAME target without a DS denial must fail closed: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(response.answers.len(), 0);
    let _ = origin;
}

/// The fail-closed CNAME rule must not over-block a target whose unsigned
/// delegation is proven by an authenticated DS denial.
#[tokio::test]
async fn test_signed_cname_to_authenticated_unsigned_target_is_insecure() {
    use hickory_proto::rr::RecordSet;
    use hickory_proto::rr::rdata::CNAME;

    let (validator, origin, zone_key, signer) = signed_zone_validator("signed.example.");
    let cut = Name::from_str("unsigned.signed.example.").expect("cut");
    let alias = Name::from_str("alias.signed.example.").expect("alias");
    let target = Name::from_str("www.unsigned.signed.example.").expect("target");

    let ds_message = signed_nsec_response(
        &origin,
        &cut,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        &cut,
        &zone_key,
        &signer,
        ResponseCode::NoError,
    );
    let fetcher = StaticFetcher::new().with(&cut, RecordType::DS, ds_message);

    let cname_record = Record::from_rdata(alias.clone(), 300, RData::CNAME(CNAME(target.clone())));
    let mut cname_set = RecordSet::new(alias.clone(), RecordType::CNAME, 0);
    cname_set.insert(cname_record.clone(), 0);
    let cname_sig = sign_test_rrset(&cname_set, &signer);

    let mut response = Message::new(9, MessageType::Response, OpCode::Query);
    response.queries.push(Query::query(alias, RecordType::A));
    response.answers.push(cname_record);
    response.answers.push(cname_sig);
    response.answers.push(Record::from_rdata(
        target,
        300,
        RData::A(A(Ipv4Addr::new(198, 51, 100, 9))),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("cname-unsigned"), now, &fetcher)
        .await;
    assert_eq!(
        outcome,
        ValidationOutcome::Insecure,
        "an authenticated DS denial must still downgrade the target: {outcome:?}"
    );
    assert!(!response.metadata.authentic_data);
}

/// Hostile regression: one unrelated junk RRSIG must not suppress the
/// unsigned-delegation probe. Before the fix it made the response
/// Indeterminate (AD=0) without ever asking whether the name is a
/// legitimately unsigned delegation.
#[tokio::test]
async fn test_junk_rrsig_does_not_suppress_unsigned_probe() {
    use hickory_proto::rr::RecordSet;

    let (zone, zone_key, zone_signer) = create_test_signer("signed.example.");
    let cut = Name::from_str("unsigned.signed.example.").expect("cut");
    let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");

    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
    validator.add_trust_anchor(&zone_key, LowerName::from(&zone));

    let ds_message = signed_nsec_response(
        &zone,
        &cut,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        &cut,
        &zone_key,
        &zone_signer,
        ResponseCode::NoError,
    );
    let fetcher = StaticFetcher::new()
        .with(
            &zone,
            RecordType::DNSKEY,
            anchored_dnskey_message(&zone, &zone_key, &zone_signer),
        )
        .with(&cut, RecordType::DS, ds_message);

    // A validly signed RRSIG for an RRset that is not in the response and
    // not relevant to the question: pure junk from the validator's point
    // of view.
    let unrelated = Name::from_str("junk.signed.example.").expect("junk");
    let mut set = RecordSet::new(unrelated.clone(), RecordType::A, 0);
    set.insert(
        Record::from_rdata(unrelated, 300, RData::A(A(Ipv4Addr::new(203, 0, 113, 99)))),
        0,
    );
    let junk_sig = sign_test_rrset(&set, &zone_signer);

    let mut response = Message::new(10, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::A));
    response.answers.push(Record::from_rdata(
        qname,
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
    ));
    response.answers.push(junk_sig);

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
        .await;
    assert_eq!(
        outcome,
        ValidationOutcome::Insecure,
        "the probe must run and prove the delegation unsigned"
    );
    assert!(!response.metadata.authentic_data);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
        fetcher.calls() > 0,
        "junk RRSIGs must not suppress the delegation probe"
    );
}

/// Strict post-fetch `Indeterminate` is not an acceptable answer for a
/// validating client: no usable key means SERVFAIL, not AD=0. `LogOnly`
/// keeps the response for diagnostics.
#[tokio::test]
async fn test_post_fetch_indeterminate_fails_closed_except_log_only() {
    let (origin, _dnskey, signer) = create_test_signer("unlinked.example.");
    let (answer, answer_sig) = signed_a_response(&origin, &signer);
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    let build = || {
        let mut response = Message::new(11, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(origin.clone(), RecordType::A));
        response.answers.push(answer.clone());
        response.answers.push(answer_sig.clone());
        response
    };

    let strict = DnssecValidator::new(DnssecMode::Validate, Vec::new());
    let offline = OfflineFetcher::new();
    let mut response = build();
    let outcome = strict
        .validate_with_key_fetcher(&mut response, Some("strict"), now, &offline)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "post-fetch Indeterminate must SERVFAIL in validate mode: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
    assert_eq!(response.answers.len(), 0);
    assert_eq!(
        strict.metrics.bogus_total.load(Ordering::Relaxed),
        1,
        "the strict post-fetch Indeterminate conversion must record Bogus once"
    );
    assert_eq!(
        strict.metrics.indeterminate_total.load(Ordering::Relaxed),
        0,
        "the provisional inner Indeterminate must not be double-recorded"
    );

    let log_only = DnssecValidator::new(DnssecMode::LogOnly, Vec::new());
    let offline = OfflineFetcher::new();
    let mut response = build();
    let outcome = log_only
        .validate_with_key_fetcher(&mut response, Some("log-only"), now, &offline)
        .await;
    assert_eq!(outcome, ValidationOutcome::Indeterminate);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(!response.metadata.authentic_data);
    assert!(!response.answers.is_empty(), "log-only keeps the answer");
    assert_eq!(
        log_only.metrics.indeterminate_total.load(Ordering::Relaxed),
        1,
        "log-only must record its final Indeterminate exactly once"
    );
    assert_eq!(
        log_only.metrics.bogus_total.load(Ordering::Relaxed),
        0,
        "log-only must not record Bogus"
    );
}

/// Critical regression: an unsigned CNAME from an unsigned qname into a
/// target in a known-signed zone must not reach the "junk signature"
/// Insecure shortcut. The unrelated RRSIG only makes `rrsigs` non-empty;
/// it must not hide the stripped signed-target answer.
#[tokio::test]
async fn test_unsigned_cname_to_signed_target_with_junk_rrsig_is_bogus() {
    use hickory_proto::rr::RecordSet;

    let (validator, signed_origin, _key, signer) = signed_zone_validator("signed.example.");
    let qname = Name::from_str("start.unsigned.example.").expect("qname");
    let target = Name::from_str("www.signed.example.").expect("target");

    let mut response = stripped_cname_response(&qname, &target);
    let unrelated = Name::from_str("junk.signed.example.").expect("junk");
    let mut set = RecordSet::new(unrelated.clone(), RecordType::A, 0);
    set.insert(
        Record::from_rdata(unrelated, 300, RData::A(A(Ipv4Addr::new(203, 0, 113, 98)))),
        0,
    );
    response.answers.push(sign_test_rrset(&set, &signer));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    assert!(
        validator.signed_zone_contains(&LowerName::from(&signed_origin), now),
        "the target zone must be seeded as signed"
    );
    let offline = OfflineFetcher::new();
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("junk-cname"), now, &offline)
        .await;

    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a stripped signed CNAME target must not become Insecure: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
}

/// A forged RRSIG that covers the answer owner/type has no usable key. It
/// must not suppress the unsigned-delegation probe (DoS/fail-closed), so
/// the authenticated DS denial can still prove the zone unsigned.
#[tokio::test]
async fn test_forged_covering_rrsig_still_probes_unsigned_delegation() {
    use hickory_proto::rr::RecordSet;

    let (zone, zone_key, zone_signer) = create_test_signer("signed.example.");
    let cut = Name::from_str("unsigned.signed.example.").expect("cut");
    let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");

    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
    validator.add_trust_anchor(&zone_key, LowerName::from(&zone));
    let ds_message = signed_nsec_response(
        &zone,
        &cut,
        &Name::from_str("z.signed.example.").expect("next"),
        &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        &cut,
        &zone_key,
        &zone_signer,
        ResponseCode::NoError,
    );
    let fetcher = StaticFetcher::new()
        .with(
            &zone,
            RecordType::DNSKEY,
            anchored_dnskey_message(&zone, &zone_key, &zone_signer),
        )
        .with(&cut, RecordType::DS, ds_message);

    let answer = Record::from_rdata(
        qname.clone(),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 98))),
    );
    // A cryptographically valid RRSIG from a completely unrelated signer:
    // it covers the answer owner/type but the key is not validated. Also
    // include the matching DNSKEY in the response: an attacker-supplied
    // key must not make the forged signature look verifiable.
    let (attacker_origin, attacker_key, attacker) = create_test_signer("unsigned.signed.example.");
    let mut set = RecordSet::new(qname.clone(), RecordType::A, 0);
    set.insert(answer.clone(), 0);
    let forged_sig = sign_test_rrset(&set, &attacker);

    let mut response = Message::new(13, MessageType::Response, OpCode::Query);
    response.queries.push(Query::query(qname, RecordType::A));
    response.answers.push(answer);
    response.answers.push(forged_sig);
    response.additionals.push(Record::from_rdata(
        attacker_origin,
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(attacker_key)),
    ));

    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("forged-cover"), now, &fetcher)
        .await;
    assert_eq!(
        outcome,
        ValidationOutcome::Insecure,
        "a forged covering RRSIG must not suppress the probe: {outcome:?}"
    );
    assert!(!response.metadata.authentic_data);
    assert!(
        fetcher.calls() > 0,
        "the probe must have been attempted despite the signature"
    );
}

/// CNAME chain response whose CNAME and target A RRset both carry covering
/// RRSIGs from `signer`, with no DNSKEY in the response.
fn covering_fake_cname_response(
    qname: &Name,
    target: &Name,
    signer: &hickory_proto::dnssec::DnssecSigner,
) -> Message {
    use hickory_proto::rr::RecordSet;
    use hickory_proto::rr::rdata::CNAME;

    let cname = Record::from_rdata(qname.clone(), 300, RData::CNAME(CNAME(target.clone())));
    let mut cname_set = RecordSet::new(qname.clone(), RecordType::CNAME, 0);
    cname_set.insert(cname.clone(), 0);
    let cname_sig = sign_test_rrset(&cname_set, signer);

    let answer = Record::from_rdata(
        target.clone(),
        300,
        RData::A(A(Ipv4Addr::new(198, 51, 100, 77))),
    );
    let mut answer_set = RecordSet::new(target.clone(), RecordType::A, 0);
    answer_set.insert(answer.clone(), 0);
    let answer_sig = sign_test_rrset(&answer_set, signer);

    let mut response = Message::new(15, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::A));
    response.answers.push(cname);
    response.answers.push(cname_sig);
    response.answers.push(answer);
    response.answers.push(answer_sig);
    response
}

/// Critical 1: a target proven signed only in the shared chain cache must
/// not be re-admitted to `Insecure` by the qname's authenticated unsigned
/// delegation when covering (fake) RRSIGs are present.
#[tokio::test]
async fn test_chain_cache_only_signed_target_with_covering_fake_rrsigs_is_bogus() {
    let (_, _, fake_signer) = create_test_signer("signed.example.");
    let qname = Name::from_str("start.unsigned.example.").expect("qname");
    let target = Name::from_str("www.signed.example.").expect("target");
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
    validator.insecure_zones.insert(
        LowerName::from(&Name::from_str("unsigned.example.").unwrap()),
        now + 600,
    );
    validator.chain_cache().insert(
        LowerName::from(&Name::from_str("signed.example.").unwrap()),
        ZoneStatus::Signed,
        now + 600,
        now,
    );
    assert!(
        validator.signed_zones.is_empty(),
        "the target must be signed only in the chain cache"
    );
    assert!(
        validator.signed_zone_contains(&LowerName::from(&target), now),
        "signed-chain evidence must consult the shared chain cache"
    );

    let mut response = covering_fake_cname_response(&qname, &target, &fake_signer);
    let offline = OfflineFetcher::new();
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("cache-signed"), now, &offline)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a chain-cache-signed target must fail closed: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
}

/// Critical 1 companion: a fully stripped CNAME chain into a target that
/// is proven signed only in the shared chain cache must be Bogus, not
/// Insecure from the unsigned qname.
#[tokio::test]
async fn test_stripped_cname_to_chain_cache_signed_target_is_bogus() {
    let qname = Name::from_str("plain.unsigned.example.").expect("qname");
    let target = Name::from_str("www.signed.example.").expect("target");
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
    validator.insecure_zones.insert(
        LowerName::from(&Name::from_str("unsigned.example.").unwrap()),
        now + 600,
    );
    validator.chain_cache().insert(
        LowerName::from(&Name::from_str("signed.example.").unwrap()),
        ZoneStatus::Signed,
        now + 600,
        now,
    );
    assert!(validator.signed_zones.is_empty());

    let mut response = stripped_cname_response(&qname, &target);
    let offline = OfflineFetcher::new();
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("stripped-cache-signed"), now, &offline)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a chain-cache-signed stripped target must fail closed: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
}

/// Critical 2: the post-fetch probe must fail closed when the target probe
/// is blocked, even though the qname is a proven unsigned delegation.
#[tokio::test]
async fn test_blocked_target_probe_after_fake_covering_rrsigs_is_bogus() {
    let (_, _, fake_signer) = create_test_signer("signed.example.");
    let qname = Name::from_str("start.unsigned.example.").expect("qname");
    let target = Name::from_str("www.signed.example.").expect("target");
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

    let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
    validator.insecure_zones.insert(
        LowerName::from(&Name::from_str("unsigned.example.").unwrap()),
        now + 600,
    );

    let mut response = covering_fake_cname_response(&qname, &target, &fake_signer);
    let offline = OfflineFetcher::new();
    let outcome = validator
        .validate_with_key_fetcher(&mut response, Some("blocked-target"), now, &offline)
        .await;
    assert!(
        matches!(outcome, ValidationOutcome::Bogus { .. }),
        "a failed target probe must not become Insecure: {outcome:?}"
    );
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(!response.metadata.authentic_data);
    assert!(
        offline.calls() > 0,
        "the blocked target probe must have been attempted"
    );
}

/// A signed wildcard-expanded answer may carry the RRSIG at the wildcard
/// owner (`*.wild.example`) while the RRset is owned by the expanded qname.
/// Both response shapes must validate as Secure without forcing a probe.
#[tokio::test]
async fn test_signed_wildcard_answer_with_wildcard_owned_rrsig_is_secure() {
    use hickory_proto::dnssec::rdata::{RRSIG, SigInput};
    use hickory_proto::dnssec::{Algorithm, TBS};
    use hickory_proto::rr::SerialNumber;

    let (origin, dnskey, signer) = create_test_signer("wild.example.");
    let wildcard = Name::from_str("*.wild.example.").expect("wildcard");
    let now_utc = time::OffsetDateTime::now_utc();
    let now = now_utc.unix_timestamp() as u32;

    for (qname, expect_probe) in [
        (
            Name::from_str("www.wild.example.").expect("single-label qname"),
            false,
        ),
        (
            Name::from_str("foo.bar.wild.example.").expect("multi-label qname"),
            false,
        ),
    ] {
        let answer = Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 97))),
        );
        let input = SigInput {
            type_covered: RecordType::A,
            algorithm: Algorithm::ECDSAP256SHA256,
            // Wildcard RRSIG labels exclude the `*` label.
            num_labels: origin.num_labels(),
            original_ttl: 300,
            sig_expiration: SerialNumber::new(
                now_utc
                    .unix_timestamp()
                    .saturating_add(300)
                    .try_into()
                    .expect("expiration"),
            ),
            sig_inception: SerialNumber::new(
                now_utc
                    .unix_timestamp()
                    .saturating_sub(60)
                    .try_into()
                    .expect("inception"),
            ),
            key_tag: signer.calculate_key_tag().expect("key tag"),
            signer_name: origin.clone(),
        };
        let tbs = TBS::from_input(&qname, DNSClass::IN, &input, std::iter::once(&answer))
            .expect("wildcard tbs");
        let signature = signer.sign(&tbs).expect("wildcard signature");
        let rrsig_data = RRSIG::from_sig(input, signature);

        for rrsig_owner in [wildcard.clone(), qname.clone()] {
            let mut anchors = TrustAnchors::empty();
            anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
            let validator =
                DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

            let mut response = Message::new(14, MessageType::Response, OpCode::Query);
            response
                .queries
                .push(Query::query(qname.clone(), RecordType::A));
            response.answers.push(answer.clone());
            response.answers.push(Record::from_rdata(
                rrsig_owner,
                300,
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig_data.clone())),
            ));
            response.additionals.push(Record::from_rdata(
                origin.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
            ));

            let offline = OfflineFetcher::new();
            let outcome = validator
                .validate_with_key_fetcher(&mut response, Some("wildcard"), now, &offline)
                .await;
            assert_eq!(
                outcome,
                ValidationOutcome::Secure,
                "a signed wildcard answer must validate for {qname}: {outcome:?}"
            );
            assert!(response.metadata.authentic_data);
            assert_eq!(
                offline.calls() > 0,
                expect_probe,
                "a signed wildcard answer must not probe for {qname}"
            );
        }
    }
}

#[test]
fn test_qtype_cname_positive_answer_is_not_negative() {
    use hickory_proto::rr::rdata::CNAME;

    let qname = Name::from_str("alias.example.").expect("qname");
    let target = Name::from_str("target.example.").expect("target");
    let mut response = Message::new(12, MessageType::Response, OpCode::Query);
    response
        .queries
        .push(Query::query(qname.clone(), RecordType::CNAME));
    response.answers.push(Record::from_rdata(
        qname.clone(),
        300,
        RData::CNAME(CNAME(target.clone())),
    ));
    response.metadata.response_code = ResponseCode::NoError;

    assert!(
        !is_negative_response(&response, &qname, RecordType::CNAME),
        "a CNAME at the qname answers QTYPE=CNAME positively"
    );
    assert!(
        is_negative_response(&response, &qname, RecordType::A),
        "the same response is NODATA for QTYPE=A"
    );
}
