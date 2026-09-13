//! RFC 4034/4035 NSEC authenticated denial-of-existence enumeration.
//!
//! The generic validation path proves only that NSEC records carry valid
//! signatures from a chain-validated zone. This module enumerates the NSEC
//! denial proof for NXDOMAIN (the queried name falls between the owner name and
//! the next name in canonical DNS order, wrapping at the zone apex) and for
//! NODATA (the owner name equals the queried name and its type bitmap denies
//! the queried type).

use hickory_proto::dnssec::rdata::NSEC;
use hickory_proto::rr::{Name, RecordType};

/// An NSEC record together with the owner name carrying its bitmap.
#[derive(Debug, Clone, Copy)]
pub struct NsecRecord<'a> {
    /// Owner name of the NSEC RR.
    pub owner: &'a Name,
    /// NSEC RDATA.
    pub rdata: &'a NSEC,
}

/// Outcome of enumerating an NSEC denial proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsecDenial {
    /// A complete proof that the queried name/type does not exist.
    Secure,
    /// The available records do not enumerate a complete proof.
    Incomplete,
}

/// Whether `qname` falls strictly between the NSEC owner name and the next
/// name in canonical DNS order, wrapping around at the zone apex.
#[must_use]
pub fn covers(record: &NsecRecord<'_>, qname: &Name) -> bool {
    let owner = record.owner;
    let next = record.rdata.next_domain_name();
    // An exact match is not a range cover.
    if owner == qname {
        return false;
    }
    if next <= owner {
        // Last NSEC in the zone: the range wraps past the apex.
        qname > owner || qname < next
    } else {
        owner < qname && qname < next
    }
}

/// Enumerates an NSEC denial proof for a negative response.
///
/// Only records whose owner is inside `signer_zone` are considered. For
/// NXDOMAIN the proof is an NSEC covering `qname`; for NODATA (including
/// wildcard NODATA) it is an NSEC at `qname` whose bitmap denies both the
/// queried type and CNAME.
#[must_use]
pub fn evaluate_nsec_denial(
    records: &[NsecRecord<'_>],
    qname: &Name,
    qtype: RecordType,
    nxdomain: bool,
    signer_zone: &Name,
) -> NsecDenial {
    if !signer_zone.zone_of(qname) {
        return NsecDenial::Incomplete;
    }
    let relevant = records
        .iter()
        .filter(|record| signer_zone.zone_of(record.owner));
    let proven = if nxdomain {
        relevant.into_iter().any(|record| covers(record, qname))
    } else {
        relevant.into_iter().any(|record| {
            if *record.owner != *qname {
                return false;
            }
            let types = record.rdata.type_set();
            if types.contains(qtype) || types.contains(RecordType::CNAME) {
                return false;
            }
            // An NSEC at a delegation point from the parent zone (NS without
            // SOA) denies the type only for the parent, not for the child
            // zone that actually owns the name.
            !types.contains(RecordType::NS) || types.contains(RecordType::SOA)
        })
    };
    if proven {
        NsecDenial::Secure
    } else {
        NsecDenial::Incomplete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn nsec(owner: &str, next: &str, types: &[RecordType]) -> (Name, NSEC) {
        (
            Name::from_str(owner).unwrap(),
            NSEC::new(Name::from_str(next).unwrap(), types.iter().copied()),
        )
    }

    #[test]
    fn test_nxdomain_cover_is_secure() {
        let (owner, rdata) = nsec(
            "a.example.",
            "c.example.",
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        );
        let qname = Name::from_str("b.example.").unwrap();
        let records = [NsecRecord {
            owner: &owner,
            rdata: &rdata,
        }];
        assert_eq!(
            evaluate_nsec_denial(
                &records,
                &qname,
                RecordType::A,
                true,
                &Name::from_str("example.").unwrap()
            ),
            NsecDenial::Secure
        );
    }

    #[test]
    fn test_wrap_cover_is_secure() {
        let (owner, rdata) = nsec(
            "z.example.",
            "example.",
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        );
        let qname = Name::from_str("zz.example.").unwrap();
        let records = [NsecRecord {
            owner: &owner,
            rdata: &rdata,
        }];
        assert_eq!(
            evaluate_nsec_denial(
                &records,
                &qname,
                RecordType::A,
                true,
                &Name::from_str("example.").unwrap()
            ),
            NsecDenial::Secure
        );
    }

    #[test]
    fn test_wrong_owner_is_incomplete() {
        let (owner, rdata) = nsec(
            "x.example.",
            "z.example.",
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        );
        let qname = Name::from_str("b.example.").unwrap();
        let records = [NsecRecord {
            owner: &owner,
            rdata: &rdata,
        }];
        assert_eq!(
            evaluate_nsec_denial(
                &records,
                &qname,
                RecordType::A,
                true,
                &Name::from_str("example.").unwrap()
            ),
            NsecDenial::Incomplete
        );
    }

    #[test]
    fn test_nodata_bitmap_controls_proof() {
        let qname = Name::from_str("empty.example.").unwrap();
        let (owner, denying) = nsec(
            "empty.example.",
            "z.example.",
            &[RecordType::SOA, RecordType::NSEC, RecordType::RRSIG],
        );
        let records = [NsecRecord {
            owner: &owner,
            rdata: &denying,
        }];
        assert_eq!(
            evaluate_nsec_denial(
                &records,
                &qname,
                RecordType::A,
                false,
                &Name::from_str("example.").unwrap()
            ),
            NsecDenial::Secure
        );

        // The queried type is present in the bitmap -> no denial.
        let (_, with_a) = nsec(
            "empty.example.",
            "z.example.",
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        );
        let records = [NsecRecord {
            owner: &owner,
            rdata: &with_a,
        }];
        assert_eq!(
            evaluate_nsec_denial(
                &records,
                &qname,
                RecordType::A,
                false,
                &Name::from_str("example.").unwrap()
            ),
            NsecDenial::Incomplete
        );

        // CNAME present in the bitmap -> the name exists and is an alias.
        let (_, with_cname) = nsec(
            "empty.example.",
            "z.example.",
            &[RecordType::CNAME, RecordType::NSEC, RecordType::RRSIG],
        );
        let records = [NsecRecord {
            owner: &owner,
            rdata: &with_cname,
        }];
        assert_eq!(
            evaluate_nsec_denial(
                &records,
                &qname,
                RecordType::A,
                false,
                &Name::from_str("example.").unwrap()
            ),
            NsecDenial::Incomplete
        );

        // Parent-side delegation NSEC (NS without SOA) must not deny types in
        // the delegated child zone.
        let (_, delegation) = nsec(
            "empty.example.",
            "z.example.",
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
        );
        let records = [NsecRecord {
            owner: &owner,
            rdata: &delegation,
        }];
        assert_eq!(
            evaluate_nsec_denial(
                &records,
                &qname,
                RecordType::A,
                false,
                &Name::from_str("example.").unwrap()
            ),
            NsecDenial::Incomplete
        );

        // Apex NSEC with both NS and SOA is still a valid NODATA proof.
        let (_, apex) = nsec(
            "empty.example.",
            "z.example.",
            &[
                RecordType::NS,
                RecordType::SOA,
                RecordType::NSEC,
                RecordType::RRSIG,
            ],
        );
        let records = [NsecRecord {
            owner: &owner,
            rdata: &apex,
        }];
        assert_eq!(
            evaluate_nsec_denial(
                &records,
                &qname,
                RecordType::A,
                false,
                &Name::from_str("example.").unwrap()
            ),
            NsecDenial::Secure
        );
    }
}
