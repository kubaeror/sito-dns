use super::{DNSClass, DNSKEY, Name, RData, RRSIG, Record};
use hickory_proto::dnssec::crypto::EcdsaSigningKey;
use hickory_proto::dnssec::{Algorithm, DnssecSigner, SigningKey};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RecordData, RecordSet, RecordType};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

/// Creates an ECDSA P-256 signing key and DNSKEY for *origin_str*.
pub fn create_test_signer(origin_str: &str) -> (Name, DNSKEY, DnssecSigner) {
    let origin = Name::from_str(origin_str).expect("parse origin");
    let pkcs8 =
        EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).expect("generate pkcs8");
    let key =
        EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256).expect("key from pkcs8");
    let pub_key = key.to_public_key().expect("pub key");
    let dnskey = DNSKEY::from_key(&pub_key);
    let signer = DnssecSigner::new(
        dnskey.clone(),
        Box::new(key),
        origin.clone(),
        Duration::from_secs(3600),
    );
    (origin, dnskey, signer)
}

/// Signs an entire RRset (or DNSKEY RRset) and returns the RRSIG record.
pub fn sign_test_rrset(set: &RecordSet, signer: &DnssecSigner) -> Record {
    let now_utc = time::OffsetDateTime::now_utc();
    let rrsig = RRSIG::from_rrset(set, DNSClass::IN, now_utc, signer).expect("sign test rrset");
    Record::from_rdata(set.name().clone(), 300, rrsig.into_rdata())
}

/// Helper that generates a signed test domain with DNSKEY, A record, and matching RRSIG.
pub fn create_test_signed_domain(origin_str: &str) -> (Name, DNSKEY, Record, Record, DnssecSigner) {
    let origin = Name::from_str(origin_str).expect("parse origin");
    let pkcs8 =
        EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).expect("generate pkcs8");
    let key =
        EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256).expect("key from pkcs8");
    let pub_key = key.to_public_key().expect("pub key");
    let dnskey = DNSKEY::from_key(&pub_key);

    let signer = DnssecSigner::new(
        dnskey.clone(),
        Box::new(key),
        origin.clone(),
        Duration::from_secs(3600),
    );

    let a_record = Record::from_rdata(
        origin.clone(),
        300,
        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
    );

    let mut record_set = RecordSet::new(origin.clone(), RecordType::A, 0);
    record_set.insert(a_record.clone(), 0);

    let now_utc = time::OffsetDateTime::now_utc();
    let rrsig = RRSIG::from_rrset(&record_set, DNSClass::IN, now_utc, &signer).expect("sign rrset");
    let rrsig_record = Record::from_rdata(origin.clone(), 300, rrsig.into_rdata());

    (origin, dnskey, a_record, rrsig_record, signer)
}
