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

/// True when the NSEC bitmap denies `qtype` (and CNAME) at its owner.
///
/// An NSEC at a delegation point from the parent zone (NS without SOA) denies
/// the type only for the parent, not for the child zone that owns the name.
fn denies_type(record: &NsecRecord<'_>, qtype: RecordType) -> bool {
    let types = record.rdata.type_set();
    if types.contains(qtype) || types.contains(RecordType::CNAME) {
        return false;
    }
    !types.contains(RecordType::NS) || types.contains(RecordType::SOA)
}

/// Enumerates an NSEC denial proof for a negative response.
///
/// Only records whose owner is inside `signer_zone` are considered.
///
/// * NXDOMAIN (RFC 4035 §5.4): the qname must be covered by an NSEC and no
///   NSEC may match it, and the wildcard `*.<closest encloser>` must also be
///   covered so a wildcard cannot have synthesized the name. The closest
///   encloser is the longest ancestor of `qname` that is an NSEC owner, or the
///   signer zone apex (which always exists).
/// * NODATA: either an NSEC at `qname` whose bitmap denies the queried type
///   and CNAME, or a wildcard NODATA proof (`*.<ancestor>` denies the type)
///   together with an NSEC covering `qname` to prove the exact name does not
///   exist.
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
    let relevant: Vec<&NsecRecord<'_>> = records
        .iter()
        .filter(|record| signer_zone.zone_of(record.owner))
        .collect();

    if nxdomain {
        // The exact name must not exist and must be covered by an NSEC.
        if relevant.iter().any(|record| record.owner == qname) {
            return NsecDenial::Incomplete;
        }
        if !relevant.iter().any(|record| covers(record, qname)) {
            return NsecDenial::Incomplete;
        }

        // Longest existing ancestor: an NSEC owner, else the zone apex.
        let mut closest = signer_zone.clone();
        for record in &relevant {
            let owner = record.owner;
            if owner != qname && owner.num_labels() > closest.num_labels() && owner.zone_of(qname) {
                closest = owner.clone();
            }
        }

        // No wildcard may have synthesized the name.
        let Ok(wildcard) = Name::from_ascii(format!("*.{}", closest.to_ascii())) else {
            return NsecDenial::Incomplete;
        };
        if !relevant.iter().any(|record| covers(record, &wildcard)) {
            return NsecDenial::Incomplete;
        }
        return NsecDenial::Secure;
    }

    // Exact NODATA: an NSEC at the queried name denying the type.
    if relevant
        .iter()
        .any(|record| record.owner == qname && denies_type(record, qtype))
    {
        return NsecDenial::Secure;
    }

    // Wildcard NODATA: the wildcard covering the name denies the type, and
    // the exact name is proven absent by an NSEC covering it.
    let exact_name_absent = relevant.iter().any(|record| covers(record, qname));
    if exact_name_absent
        && relevant.iter().any(|record| {
            record.owner.is_wildcard()
                && denies_type(record, qtype)
                && record.owner.base_name().zone_of(qname)
        })
    {
        return NsecDenial::Secure;
    }

    NsecDenial::Incomplete
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
        // [a -> c] covers b; [example -> a] covers the wildcard *.example.
        let (owner, rdata) = nsec(
            "a.example.",
            "c.example.",
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        );
        let (wildcard_owner, wildcard_rdata) = nsec(
            "example.",
            "a.example.",
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        );
        let qname = Name::from_str("b.example.").unwrap();
        let records = [
            NsecRecord {
                owner: &owner,
                rdata: &rdata,
            },
            NsecRecord {
                owner: &wildcard_owner,
                rdata: &wildcard_rdata,
            },
        ];
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
    fn test_nxdomain_without_wildcard_denial_is_incomplete() {
        // Only the qname is covered; nothing proves that *.example does not
        // exist, so a wildcard could have synthesized the answer.
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
            NsecDenial::Incomplete
        );
    }

    #[test]
    fn test_wrap_cover_is_secure() {
        // [z -> example] wraps and covers zz; [example -> a] covers *.example.
        let (owner, rdata) = nsec(
            "z.example.",
            "example.",
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        );
        let (wildcard_owner, wildcard_rdata) = nsec(
            "example.",
            "a.example.",
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        );
        let qname = Name::from_str("zz.example.").unwrap();
        let records = [
            NsecRecord {
                owner: &owner,
                rdata: &rdata,
            },
            NsecRecord {
                owner: &wildcard_owner,
                rdata: &wildcard_rdata,
            },
        ];
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

    #[test]
    fn test_wildcard_nodata_is_secure() {
        // `*.example` exists but denies A; `a.example -> c.example` proves the
        // exact queried name (`b.example`) does not exist.
        let zone = Name::from_str("example.").unwrap();
        let qname = Name::from_str("b.example.").unwrap();
        let (wildcard_owner, wildcard_rdata) = nsec(
            "*.example.",
            "c.example.",
            &[RecordType::SOA, RecordType::NSEC, RecordType::RRSIG],
        );
        let (cover_owner, cover_rdata) = nsec(
            "a.example.",
            "c.example.",
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        );
        let records = [
            NsecRecord {
                owner: &wildcard_owner,
                rdata: &wildcard_rdata,
            },
            NsecRecord {
                owner: &cover_owner,
                rdata: &cover_rdata,
            },
        ];
        assert_eq!(
            evaluate_nsec_denial(&records, &qname, RecordType::A, false, &zone),
            NsecDenial::Secure
        );

        // If the wildcard bitmap includes A, no wildcard NODATA is proven.
        let (_, with_a) = nsec(
            "*.example.",
            "c.example.",
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        );
        assert!(with_a.type_set().contains(RecordType::A));
        assert!(!denies_type(
            &NsecRecord {
                owner: &wildcard_owner,
                rdata: &with_a,
            },
            RecordType::A
        ));
        let records = [
            NsecRecord {
                owner: &wildcard_owner,
                rdata: &with_a,
            },
            NsecRecord {
                owner: &cover_owner,
                rdata: &cover_rdata,
            },
        ];
        assert_eq!(
            evaluate_nsec_denial(&records, &qname, RecordType::A, false, &zone),
            NsecDenial::Incomplete
        );

        // A wildcard whose NSEC range does not cover the queried name proves
        // nothing about the exact name: the response stays Incomplete.
        let (other_owner, other_rdata) = nsec(
            "*.example.",
            "aa.example.",
            &[RecordType::SOA, RecordType::NSEC, RecordType::RRSIG],
        );
        let records = [NsecRecord {
            owner: &other_owner,
            rdata: &other_rdata,
        }];
        assert_eq!(
            evaluate_nsec_denial(&records, &qname, RecordType::A, false, &zone),
            NsecDenial::Incomplete
        );
    }
}
