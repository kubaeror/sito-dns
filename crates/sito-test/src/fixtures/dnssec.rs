//! Shared DNSSEC signed-zone, key, and denial fixtures.
//!
//! `sito-dnssec::test_util` builds a single signed A record. These fixtures add
//! the pieces the integration security tests need repeatedly: a signer that can
//! sign arbitrary RRsets, DNSKEY/DS answers for the mock upstream, trust-anchor
//! strings, and NSEC denial records. Keys are ECDSA P-256 (algorithm 13).

use std::net::Ipv4Addr;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData};
use hickory_proto::dnssec::{DnssecSigner, PublicKey as _};
use hickory_proto::rr::{Name, RData, Record, RecordSet, RecordType};
use sito_dnssec::test_util::{create_test_signer, sign_test_rrset};
use sito_proto::rdata::A;

/// A signed test zone.
pub struct SignedZone {
    /// Zone origin (fully qualified).
    pub origin: Name,
    /// Zone signing key.
    pub dnskey: DNSKEY,
    signer: DnssecSigner,
}

impl std::fmt::Debug for SignedZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedZone")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl SignedZone {
    /// Creates a fresh ECDSA P-256 zone for `origin`.
    pub fn new(origin: &str) -> Self {
        let origin = Name::from_str(origin).expect("valid fixture origin");
        let (origin, dnskey, signer) = create_test_signer(&origin.to_string());
        Self {
            origin,
            dnskey,
            signer,
        }
    }

    /// The trust-anchor string accepted by `DnssecConfig::trust_anchors`
    /// (`<zone>.:13:<base64 public key>`).
    #[must_use]
    pub fn trust_anchor(&self) -> String {
        format!(
            "{}:13:{}",
            self.origin.to_ascii(),
            BASE64_STANDARD.encode(self.dnskey.public_key().public_bytes())
        )
    }

    /// Signs an existing RRset.
    #[must_use]
    pub fn sign_rrset(&self, set: &RecordSet) -> Record {
        sign_test_rrset(set, &self.signer)
    }

    /// Builds a signed A record for `name`.
    #[must_use]
    pub fn signed_a(&self, name: &str, ip: Ipv4Addr) -> (Record, Record) {
        let owner = Name::from_str(name).expect("valid record name");
        let record = Record::from_rdata(owner.clone(), 300, RData::A(A(ip)));
        let mut set = RecordSet::new(owner, RecordType::A, 0);
        set.insert(record.clone(), 0);
        (record, self.sign_rrset(&set))
    }

    /// A signed A record at the zone apex.
    #[must_use]
    pub fn apex_a(&self, ip: Ipv4Addr) -> (Record, Record) {
        let origin = self.origin.to_string();
        self.signed_a(&origin, ip)
    }

    /// The DNSKEY RRset plus its RRSIG, formatted for the mock upstream.
    #[must_use]
    pub fn dnskey_rrset(&self) -> (Vec<Record>, Vec<Record>) {
        let record = self.dnskey_record();
        let mut set = RecordSet::new(self.origin.clone(), RecordType::DNSKEY, 0);
        set.insert(record.clone(), 0);
        (vec![record, self.sign_rrset(&set)], Vec::new())
    }

    /// The zone DNSKEY as a record (for response additionals).
    #[must_use]
    pub fn dnskey_record(&self) -> Record {
        Record::from_rdata(
            self.origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())),
        )
    }

    /// A signed DS RRset for `child`, signed by this (parent) zone.
    #[must_use]
    pub fn ds_for(&self, child: &SignedZone) -> (Vec<Record>, Vec<Record>) {
        let ds = hickory_proto::dnssec::rdata::DS::from_key(
            child.dnskey.public_key(),
            &child.origin,
            hickory_proto::dnssec::DigestType::SHA256,
        )
        .expect("build DS");
        let record = Record::from_rdata(
            child.origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DS(ds)),
        );
        let mut set = RecordSet::new(child.origin.clone(), RecordType::DS, 0);
        set.insert(record.clone(), 0);
        (vec![record, self.sign_rrset(&set)], Vec::new())
    }

    /// Builds an NSEC denial record at `owner` and its RRSIG.
    ///
    /// `next` is the next owner name in canonical order; `types` is the type
    /// bitmap. Use [`SignedZone::nsec_covering`] to cover a queried name.
    #[must_use]
    pub fn nsec(&self, owner: &Name, next: &Name, types: &[RecordType]) -> (Record, Record) {
        let nsec = hickory_proto::dnssec::rdata::NSEC::new(next.clone(), types.iter().copied());
        let record = Record::from_rdata(owner.clone(), 300, RData::DNSSEC(DNSSECRData::NSEC(nsec)));
        let mut set = RecordSet::new(owner.clone(), RecordType::NSEC, 0);
        set.insert(record.clone(), 0);
        (record, self.sign_rrset(&set))
    }

    /// Builds a complete NSEC NXDOMAIN proof for `qname`.
    ///
    /// Two records are returned:
    /// - `a.<zone>` -> `zzz.<zone>`, covering `qname` (which must sort between
    ///   those owners in canonical order; typical fixture names such as
    ///   `missing.<zone>` do);
    /// - `<zone>` -> `a.<zone>`, covering the wildcard `*.<zone>` so the
    ///   NXDOMAIN cannot have been synthesized by a wildcard.
    ///
    /// Both records are signed. The bitmap at the qname cover is a normal
    /// owner bitmap; the apex cover includes SOA/NS so it is not mistaken for
    /// a parent-side delegation.
    #[must_use]
    pub fn nsec_covering(&self, qname: &Name) -> Vec<(Record, Record)> {
        assert!(
            self.origin.zone_of(qname),
            "the NSEC fixture can only deny names inside {zone}",
            zone = self.origin
        );
        let first =
            Name::from_str(&format!("a.{}", self.origin.to_ascii())).expect("valid fixture owner");
        let next =
            Name::from_str(&format!("zzz.{}", self.origin.to_ascii())).expect("valid fixture next");
        let qname_types = [RecordType::A, RecordType::NSEC, RecordType::RRSIG];
        let apex_types = [
            RecordType::NS,
            RecordType::SOA,
            RecordType::NSEC,
            RecordType::RRSIG,
        ];
        vec![
            self.nsec(&first, &next, &qname_types),
            self.nsec(&self.origin, &first, &apex_types),
        ]
    }
}

/// Convenience: a secure zone plus its mock-upstream DNSKEY answers.
pub fn secure_zone(origin: &str) -> SignedZone {
    SignedZone::new(origin)
}
