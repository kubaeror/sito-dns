//! RFC 5155 NSEC3 denial-of-existence enumeration.
//!
//! The generic validation path only proves that the NSEC3 records carry valid
//! signatures from a chain-validated zone. This module enumerates the
//! closest-encloser proof so an opt-out NXDOMAIN (which may hide an unsigned
//! delegation) can be downgraded from `Secure` to `Insecure`.

use data_encoding::BASE32_DNSSEC;
use hickory_proto::dnssec::rdata::NSEC3;
use hickory_proto::rr::{Name, RecordType};

/// Maximum NSEC3 iteration count accepted for validation (RFC 9276).
///
/// Records exceeding this bound are ignored, which makes the proof
/// incomplete rather than secure.
pub const MAX_ITERATIONS: u16 = 150;

/// An NSEC3 record together with the owner name carrying its hashed label.
#[derive(Debug, Clone, Copy)]
pub struct Nsec3Record<'a> {
    pub owner: &'a Name,
    pub rdata: &'a NSEC3,
}

/// Outcome of enumerating an NSEC3 denial proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nsec3Denial {
    /// A complete closest-encloser proof without opt-out.
    Secure,
    /// The next closer name is covered by an opt-out NSEC3: an unsigned
    /// delegation may exist, so the response must be treated as insecure.
    OptOut,
    /// The available records do not enumerate a complete proof.
    Incomplete,
}

fn decode_owner_hash(owner: &Name) -> Option<Vec<u8>> {
    let raw = owner.iter().next()?;
    let text = std::str::from_utf8(raw).ok()?.to_ascii_uppercase();
    BASE32_DNSSEC.decode(text.as_bytes()).ok()
}

fn hash_name(record: &Nsec3Record<'_>, name: &Name) -> Option<Vec<u8>> {
    // RFC 9276: never hash a name more than MAX_ITERATIONS times. This check
    // lives here (not only in `evaluate_nsec3_denial`) because `matches` and
    // `covers` are also called from the DS-status paths without a pre-filter.
    if record.rdata.iterations() > MAX_ITERATIONS {
        return None;
    }
    let digest = record
        .rdata
        .hash_algorithm()
        .hash(record.rdata.salt(), name, record.rdata.iterations())
        .ok()?;
    Some(digest.as_ref().to_vec())
}

/// Whether the NSEC3 record matches `name` (hash equals the owner hash).
#[must_use]
pub fn matches(record: &Nsec3Record<'_>, name: &Name) -> bool {
    decode_owner_hash(record.owner)
        .zip(hash_name(record, name))
        .is_some_and(|(owner, hash)| owner == hash)
}

/// Whether the NSEC3 record covers `name` (hash falls strictly between the
/// owner hash and the next hash, with wraparound).
#[must_use]
pub fn covers(record: &Nsec3Record<'_>, name: &Name) -> bool {
    let Some(owner) = decode_owner_hash(record.owner) else {
        return false;
    };
    let Some(hash) = hash_name(record, name) else {
        return false;
    };
    let next = record.rdata.next_hashed_owner_name().to_vec();
    if owner == hash || hash.as_slice() == next.as_slice() {
        return false;
    }
    if owner < next {
        owner < hash && hash < next
    } else {
        hash > owner || hash < next
    }
}

fn wildcard_of(name: &Name) -> Option<Name> {
    Name::from_ascii(format!("*.{}", name.to_ascii())).ok()
}

/// True when the NSEC3 bitmap denies `qtype` (and CNAME) at its owner.
///
/// An NSEC3 at a delegation point from the parent zone (NS without SOA) denies
/// the type only for the parent, not for the child zone that owns the name.
/// The exception is DS: RFC 6840 §4.1/§4.4 accepts a parent-side delegation
/// NSEC3 (NS set, SOA clear, DS clear) as proof that no DS exists at the
/// delegation.
fn denies_type(record: &Nsec3Record<'_>, qtype: RecordType) -> bool {
    let types = record.rdata.type_set();
    if types.contains(qtype) || types.contains(RecordType::CNAME) {
        return false;
    }
    if qtype == RecordType::DS {
        return true;
    }
    !types.contains(RecordType::NS) || types.contains(RecordType::SOA)
}

/// True when the record is a parent-side delegation NSEC3: an NS RRset without
/// the SOA bit that identifies a zone apex.
fn is_delegation(record: &Nsec3Record<'_>) -> bool {
    let types = record.rdata.type_set();
    types.contains(RecordType::NS) && !types.contains(RecordType::SOA)
}

/// Enumerates an NSEC3 denial proof for a negative response.
///
/// `nxdomain` selects the RFC 5155 NXDOMAIN proof (closest encloser plus
/// covering records for the next closer name and the wildcard at the closest
/// encloser) over the NODATA proofs (exact match or wildcard match denying the
/// queried type).
///
/// Only records signed by `signer_zone` itself are considered. NSEC3 owner
/// names are hashes, so records from an ancestor zone (for example the parent
/// of a signed delegation) are otherwise indistinguishable from child-zone
/// records and could be used to prove denial below the cut (RFC 6840 §4.1).
#[must_use]
pub fn evaluate_nsec3_denial(
    records: &[Nsec3Record<'_>],
    qname: &Name,
    qtype: RecordType,
    nxdomain: bool,
    signer_zone: &Name,
) -> Nsec3Denial {
    if !signer_zone.zone_of(qname) {
        return Nsec3Denial::Incomplete;
    }
    let relevant: Vec<Nsec3Record<'_>> = records
        .iter()
        .filter(|record| {
            let owner_zone = record.owner.base_name();
            owner_zone == *signer_zone
        })
        // RFC 9276: iterations above the cap are not accepted; ignoring them
        // yields an incomplete (never secure) proof.
        .filter(|record| record.rdata.iterations() <= MAX_ITERATIONS)
        .copied()
        .collect();
    if relevant.is_empty() {
        return Nsec3Denial::Incomplete;
    }

    // RFC 6840 §4.1: a parent-side NSEC3 that matches a delegation cannot be
    // the closest encloser for a name below the cut. Allowing it would let the
    // parent's hashed ranges prove NXDOMAIN inside a signed child zone. The
    // same record may still prove NODATA for DS at the delegation owner.
    let mut ancestor = qname.clone();
    loop {
        if signer_zone.zone_of(&ancestor)
            && let Some(delegation) = relevant
                .iter()
                .find(|record| matches(record, &ancestor) && is_delegation(record))
        {
            if !nxdomain && qtype == RecordType::DS && ancestor == *qname {
                return if denies_type(delegation, RecordType::DS) {
                    Nsec3Denial::Secure
                } else {
                    Nsec3Denial::Incomplete
                };
            }
            return Nsec3Denial::Incomplete;
        }
        if ancestor == *signer_zone || ancestor.is_root() {
            break;
        }
        ancestor = ancestor.base_name();
    }

    // Walk from the qname towards the root to find the closest encloser.
    let mut candidate = qname.clone();
    let mut next_closer: Option<Name> = None;
    let mut closest: Option<Name> = None;
    loop {
        if relevant.iter().any(|record| matches(record, &candidate)) {
            closest = Some(candidate);
            break;
        }
        if candidate.is_root() {
            break;
        }
        next_closer = Some(candidate.clone());
        candidate = candidate.base_name();
    }
    let Some(closest) = closest else {
        return Nsec3Denial::Incomplete;
    };

    if !nxdomain {
        if closest == *qname {
            // Exact match that denies the queried type. RFC 6840 §4.3 also
            // requires the CNAME bit to be clear, and parent-side delegation
            // NSEC3s (NS without SOA) only deny DS.
            let denied = relevant
                .iter()
                .any(|record| matches(record, qname) && denies_type(record, qtype));
            return if denied {
                Nsec3Denial::Secure
            } else {
                Nsec3Denial::Incomplete
            };
        }
        // Wildcard NODATA (RFC 5155 §8.7) or Opt-Out DS NODATA (RFC 5155 §8.5):
        // requires a covering record for the *next closer* name.
        let Some(next_closer) = next_closer else {
            return Nsec3Denial::Incomplete;
        };
        let covering = relevant.iter().find(|record| covers(record, &next_closer));
        let Some(covering) = covering else {
            return Nsec3Denial::Incomplete;
        };
        // RFC 5155 §9.2: an opt-out span on the next closer name means an
        // unsigned delegation may exist there. It must be treated as insecure
        // even when a wildcard at the closest encloser happens to deny the
        // type; otherwise an attacker can hide an unsigned child behind a
        // wildcard NODATA answer and still get AD=1.
        if covering.rdata.opt_out() {
            return Nsec3Denial::OptOut;
        }
        if let Some(wildcard) = wildcard_of(&closest)
            && relevant
                .iter()
                .any(|record| matches(record, &wildcard) && denies_type(record, qtype))
        {
            return Nsec3Denial::Secure;
        }
        return Nsec3Denial::Incomplete;
    }

    // NXDOMAIN (RFC 5155 §8.4) requires a proper closest encloser, a covering
    // record for the next closer name, and (unless opt-out) a covering record
    // for the wildcard at the closest encloser (`*.<closest>`).
    if closest == *qname {
        return Nsec3Denial::Incomplete;
    }
    let Some(next_closer) = next_closer else {
        return Nsec3Denial::Incomplete;
    };
    let Some(wildcard) = wildcard_of(&closest) else {
        return Nsec3Denial::Incomplete;
    };
    match relevant.iter().find(|record| covers(record, &next_closer)) {
        Some(record) if record.rdata.opt_out() => Nsec3Denial::OptOut,
        Some(_) if relevant.iter().any(|record| covers(record, &wildcard)) => Nsec3Denial::Secure,
        _ => Nsec3Denial::Incomplete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::Nsec3HashAlgorithm;

    fn owner_for(rdata: &NSEC3, zone: &str) -> Name {
        let hash = rdata_hash_example(rdata);
        let label = BASE32_DNSSEC.encode(&hash);
        Name::from_ascii(format!("{label}.{zone}")).expect("valid NSEC3 owner")
    }

    // Re-derives the owner hash from an NSEC3 template by hashing `example.`.
    fn rdata_hash_example(rdata: &NSEC3) -> Vec<u8> {
        let zone = Name::from_ascii("example.").unwrap();
        rdata
            .hash_algorithm()
            .hash(rdata.salt(), &zone, rdata.iterations())
            .unwrap()
            .as_ref()
            .to_vec()
    }

    fn increment(bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        for byte in out.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        out
    }

    fn nssec3_optout_fixture() -> (Name, Name, NSEC3) {
        let qname = Name::from_ascii("missing.example.").unwrap();
        let missing_hash = Nsec3HashAlgorithm::SHA1
            .hash(&[], &qname, 0)
            .unwrap()
            .as_ref()
            .to_vec();
        let rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            true,
            0,
            Vec::new(),
            increment(&missing_hash),
            [RecordType::SOA, RecordType::RRSIG, RecordType::NSEC3],
        );
        let owner = owner_for(&rdata, "example.");
        (qname, owner, rdata)
    }

    #[test]
    fn test_opt_out_nxdomain_enumerates_optout() {
        let (qname, owner, rdata) = nssec3_optout_fixture();
        let records = [Nsec3Record {
            owner: &owner,
            rdata: &rdata,
        }];
        assert_eq!(
            evaluate_nsec3_denial(
                &records,
                &qname,
                RecordType::A,
                true,
                &Name::from_ascii("example.").unwrap()
            ),
            Nsec3Denial::OptOut
        );
    }

    #[test]
    fn test_exact_match_nodata_is_secure() {
        let zone = Name::from_ascii("example.").unwrap();
        let qname = Name::from_ascii("empty.example.").unwrap();
        let next_hash = increment(
            Nsec3HashAlgorithm::SHA1
                .hash(&[], &qname, 0)
                .unwrap()
                .as_ref(),
        );
        let rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            next_hash,
            [RecordType::SOA, RecordType::RRSIG],
        );
        let qname_hash = Nsec3HashAlgorithm::SHA1
            .hash(&[], &qname, 0)
            .unwrap()
            .as_ref()
            .to_vec();
        let label = BASE32_DNSSEC.encode(&qname_hash);
        let owner = Name::from_ascii(format!("{label}.{}", zone.to_ascii())).unwrap();
        let records = [Nsec3Record {
            owner: &owner,
            rdata: &rdata,
        }];
        assert_eq!(
            evaluate_nsec3_denial(
                &records,
                &qname,
                RecordType::A,
                false,
                &Name::from_ascii("example.").unwrap()
            ),
            Nsec3Denial::Secure
        );
        // The queried type is present in the bitmap -> not a denial.
        let with_a = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&qname_hash),
            [RecordType::A, RecordType::RRSIG],
        );
        let records = [Nsec3Record {
            owner: &owner,
            rdata: &with_a,
        }];
        assert_eq!(
            evaluate_nsec3_denial(
                &records,
                &qname,
                RecordType::A,
                false,
                &Name::from_ascii("example.").unwrap()
            ),
            Nsec3Denial::Incomplete
        );
    }

    #[test]
    fn test_empty_records_are_incomplete() {
        let qname = Name::from_ascii("missing.example.").unwrap();
        assert_eq!(
            evaluate_nsec3_denial(
                &[],
                &qname,
                RecordType::A,
                true,
                &Name::from_ascii("example.").unwrap()
            ),
            Nsec3Denial::Incomplete
        );
    }

    #[test]
    fn test_iterations_over_cap_is_incomplete() {
        let zone = Name::from_ascii("example.").unwrap();
        let qname = Name::from_ascii("missing.example.").unwrap();

        for (iterations, expected) in [
            (MAX_ITERATIONS, Nsec3Denial::OptOut),
            (MAX_ITERATIONS + 1, Nsec3Denial::Incomplete),
        ] {
            let encloser_hash = Nsec3HashAlgorithm::SHA1
                .hash(&[], &zone, iterations)
                .unwrap()
                .as_ref()
                .to_vec();
            let qname_hash = Nsec3HashAlgorithm::SHA1
                .hash(&[], &qname, iterations)
                .unwrap()
                .as_ref()
                .to_vec();
            let rdata = NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                true,
                iterations,
                Vec::new(),
                increment(&qname_hash),
                [RecordType::SOA, RecordType::RRSIG],
            );
            let label = BASE32_DNSSEC.encode(&encloser_hash);
            let owner = Name::from_ascii(format!("{label}.{}", zone.to_ascii())).unwrap();
            let records = [Nsec3Record {
                owner: &owner,
                rdata: &rdata,
            }];
            assert_eq!(
                evaluate_nsec3_denial(
                    &records,
                    &qname,
                    RecordType::A,
                    true,
                    &Name::from_ascii("example.").unwrap()
                ),
                expected,
                "iterations={iterations}"
            );
        }
    }

    /// `matches`/`covers` are also reachable from paths that do not pre-filter
    /// on `MAX_ITERATIONS` (the DS-status NSEC3 branches). They must enforce
    /// the RFC 9276 cap themselves instead of hashing the name 65535 times.
    #[test]
    fn test_iterations_above_cap_disable_matches_and_covers() {
        let zone = Name::from_ascii("example.").unwrap();
        let qname = Name::from_ascii("capped.example.").unwrap();
        let iterations = 65535;
        // Computing this hash here is a single deliberate cost; the point is
        // that validation must never perform it for an over-cap record.
        let qname_hash = Nsec3HashAlgorithm::SHA1
            .hash(&[], &qname, iterations)
            .unwrap()
            .as_ref()
            .to_vec();

        let exact_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            iterations,
            Vec::new(),
            increment(&qname_hash),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let exact_label = BASE32_DNSSEC.encode(&qname_hash);
        let exact_owner = Name::from_ascii(format!("{exact_label}.{}", zone.to_ascii())).unwrap();
        let exact = Nsec3Record {
            owner: &exact_owner,
            rdata: &exact_rdata,
        };
        assert!(
            !matches(&exact, &qname),
            "an over-cap NSEC3 must never match"
        );

        let covering_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            iterations,
            Vec::new(),
            increment(&qname_hash),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let covering_label = BASE32_DNSSEC.encode(&decrement(&qname_hash));
        let covering_owner =
            Name::from_ascii(format!("{covering_label}.{}", zone.to_ascii())).unwrap();
        let covering = Nsec3Record {
            owner: &covering_owner,
            rdata: &covering_rdata,
        };
        assert!(
            !covers(&covering, &qname),
            "an over-cap NSEC3 must never cover"
        );

        assert_eq!(
            evaluate_nsec3_denial(
                &[exact],
                &qname,
                RecordType::A,
                false,
                &Name::from_ascii("example.").unwrap()
            ),
            Nsec3Denial::Incomplete,
            "the exact-match/opt-out denial path must ignore over-cap records"
        );
    }

    fn decrement(bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        for byte in out.iter_mut().rev() {
            *byte = byte.wrapping_sub(1);
            if *byte != u8::MAX {
                break;
            }
        }
        out
    }

    #[test]
    fn test_exact_nodata_with_cname_bit_is_not_secure() {
        // RFC 6840 4.3: a matching NSEC3 that denies the queried type must
        // also have the CNAME bit clear, otherwise a positive CNAME answer
        // could be replayed as NODATA.
        let qname = Name::from_ascii("alias.example.").unwrap();
        let qname_hash = Nsec3HashAlgorithm::SHA1
            .hash(&[], &qname, 0)
            .unwrap()
            .as_ref()
            .to_vec();
        let label = BASE32_DNSSEC.encode(&qname_hash);
        let owner = Name::from_ascii(format!("{label}.example.")).unwrap();

        let with_cname = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&qname_hash),
            [RecordType::CNAME, RecordType::RRSIG],
        );
        let records = [Nsec3Record {
            owner: &owner,
            rdata: &with_cname,
        }];
        assert_eq!(
            evaluate_nsec3_denial(
                &records,
                &qname,
                RecordType::A,
                false,
                &Name::from_ascii("example.").unwrap()
            ),
            Nsec3Denial::Incomplete
        );

        // Without the CNAME bit the same bitmat is a valid NODATA proof.
        let without_cname = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&qname_hash),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let records = [Nsec3Record {
            owner: &owner,
            rdata: &without_cname,
        }];
        assert_eq!(
            evaluate_nsec3_denial(
                &records,
                &qname,
                RecordType::A,
                false,
                &Name::from_ascii("example.").unwrap()
            ),
            Nsec3Denial::Secure
        );
    }

    #[test]
    fn test_wildcard_nodata_requires_next_closer_cover() {
        // RFC 5155 8.7: the wildcard NODATA proof must cover the next closer
        // name, not the qname hash.
        let zone = Name::from_ascii("example.").unwrap();
        let qname = Name::from_ascii("a.b.example.").unwrap();
        let next_closer = Name::from_ascii("b.example.").unwrap();

        let hash = |name: &Name| {
            Nsec3HashAlgorithm::SHA1
                .hash(&[], name, 0)
                .unwrap()
                .as_ref()
                .to_vec()
        };
        let owner_of = |hashed: &[u8]| {
            Name::from_ascii(format!("{}.example.", BASE32_DNSSEC.encode(hashed))).unwrap()
        };

        // Closest encloser: example.
        let encloser_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&hash(&zone)),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let encloser_owner = owner_of(&hash(&zone));

        // Wildcard match denying A (and CNAME).
        let wildcard = Name::from_ascii("*.example.").unwrap();
        let wildcard_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&hash(&wildcard)),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let wildcard_owner = owner_of(&hash(&wildcard));

        // Cover for the next closer name (b.example).
        let cover_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&increment(&hash(&next_closer))),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let cover_owner = owner_of(&decrement(&decrement(&hash(&next_closer))));

        let records = [
            Nsec3Record {
                owner: &encloser_owner,
                rdata: &encloser_rdata,
            },
            Nsec3Record {
                owner: &wildcard_owner,
                rdata: &wildcard_rdata,
            },
            Nsec3Record {
                owner: &cover_owner,
                rdata: &cover_rdata,
            },
        ];
        assert_eq!(
            evaluate_nsec3_denial(
                &records,
                &qname,
                RecordType::A,
                false,
                &Name::from_ascii("example.").unwrap()
            ),
            Nsec3Denial::Secure,
            "a cover of the next closer name must complete the proof"
        );

        // A cover of the qname hash only (the pre-fix behavior) proves
        // nothing about the next closer name.
        let qname_cover_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&increment(&hash(&qname))),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let qname_cover_owner = owner_of(&decrement(&decrement(&hash(&qname))));
        let records = [
            Nsec3Record {
                owner: &encloser_owner,
                rdata: &encloser_rdata,
            },
            Nsec3Record {
                owner: &wildcard_owner,
                rdata: &wildcard_rdata,
            },
            Nsec3Record {
                owner: &qname_cover_owner,
                rdata: &qname_cover_rdata,
            },
        ];
        assert_eq!(
            evaluate_nsec3_denial(
                &records,
                &qname,
                RecordType::A,
                false,
                &Name::from_ascii("example.").unwrap()
            ),
            Nsec3Denial::Incomplete
        );
    }

    #[test]
    fn test_nxdomain_requires_wildcard_cover() {
        let zone = Name::from_ascii("example.").unwrap();
        let qname = Name::from_ascii("missing.example.").unwrap();
        let wildcard = Name::from_ascii("*.example.").unwrap();

        let hash = |name: &Name| {
            Nsec3HashAlgorithm::SHA1
                .hash(&[], name, 0)
                .unwrap()
                .as_ref()
                .to_vec()
        };
        let owner_of = |hashed: &[u8]| {
            Name::from_ascii(format!("{}.example.", BASE32_DNSSEC.encode(hashed))).unwrap()
        };

        let encloser_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&hash(&zone)),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let encloser_owner = owner_of(&hash(&zone));

        let next_closer_cover_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&increment(&hash(&qname))),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let next_closer_cover_owner = owner_of(&decrement(&decrement(&hash(&qname))));

        let without_wildcard = [
            Nsec3Record {
                owner: &encloser_owner,
                rdata: &encloser_rdata,
            },
            Nsec3Record {
                owner: &next_closer_cover_owner,
                rdata: &next_closer_cover_rdata,
            },
        ];
        assert_eq!(
            evaluate_nsec3_denial(
                &without_wildcard,
                &qname,
                RecordType::A,
                true,
                &Name::from_ascii("example.").unwrap()
            ),
            Nsec3Denial::Incomplete,
            "RFC 5155 §8.4 requires wildcard at closest encloser to be covered"
        );

        let wildcard_cover_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&increment(&hash(&wildcard))),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let wildcard_cover_owner = owner_of(&decrement(&decrement(&hash(&wildcard))));
        let with_wildcard = [
            Nsec3Record {
                owner: &encloser_owner,
                rdata: &encloser_rdata,
            },
            Nsec3Record {
                owner: &next_closer_cover_owner,
                rdata: &next_closer_cover_rdata,
            },
            Nsec3Record {
                owner: &wildcard_cover_owner,
                rdata: &wildcard_cover_rdata,
            },
        ];
        assert_eq!(
            evaluate_nsec3_denial(
                &with_wildcard,
                &qname,
                RecordType::A,
                true,
                &Name::from_ascii("example.").unwrap()
            ),
            Nsec3Denial::Secure
        );
    }

    #[test]
    fn test_opt_out_next_closer_wildcard_nodata_is_optout() {
        // RFC 5155 §9.2: the next-closer covering NSEC3 being opt-out means an
        // unsigned delegation may exist there, even if a wildcard at the
        // closest encloser denies the type. The response must be Insecure.
        let zone = Name::from_ascii("example.").unwrap();
        let qname = Name::from_ascii("a.b.example.").unwrap();
        let next_closer = Name::from_ascii("b.example.").unwrap();
        let wildcard = Name::from_ascii("*.example.").unwrap();

        let hash = |name: &Name| {
            Nsec3HashAlgorithm::SHA1
                .hash(&[], name, 0)
                .unwrap()
                .as_ref()
                .to_vec()
        };
        let owner_of = |hashed: &[u8]| {
            Name::from_ascii(format!("{}.example.", BASE32_DNSSEC.encode(hashed))).unwrap()
        };

        let encloser_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&hash(&zone)),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let encloser_owner = owner_of(&hash(&zone));
        let wildcard_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&hash(&wildcard)),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let wildcard_owner = owner_of(&hash(&wildcard));
        let cover_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            true,
            0,
            Vec::new(),
            increment(&increment(&hash(&next_closer))),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let cover_owner = owner_of(&decrement(&decrement(&hash(&next_closer))));

        let records = [
            Nsec3Record {
                owner: &encloser_owner,
                rdata: &encloser_rdata,
            },
            Nsec3Record {
                owner: &wildcard_owner,
                rdata: &wildcard_rdata,
            },
            Nsec3Record {
                owner: &cover_owner,
                rdata: &cover_rdata,
            },
        ];
        assert_eq!(
            evaluate_nsec3_denial(&records, &qname, RecordType::A, false, &zone),
            Nsec3Denial::OptOut,
            "an opt-out next-closer cover must not be upgraded by wildcard NODATA"
        );
    }

    #[test]
    fn test_parent_delegation_nsec3_cannot_prove_nxdomain_below_cut() {
        // Hostile parent-side NSEC3 data for child.example must not be able to
        // act as the closest encloser (or cover the next closer/wildcard) for
        // a name inside the child zone (RFC 6840 §4.1).
        let zone = Name::from_ascii("example.").unwrap();
        let child = Name::from_ascii("child.example.").unwrap();
        let x = Name::from_ascii("x.child.example.").unwrap();
        let wildcard = Name::from_ascii("*.child.example.").unwrap();
        let child_qname = Name::from_ascii("*.x.child.example.").unwrap();

        let hash = |name: &Name| {
            Nsec3HashAlgorithm::SHA1
                .hash(&[], name, 0)
                .unwrap()
                .as_ref()
                .to_vec()
        };
        let owner_of = |hashed: &[u8]| {
            Name::from_ascii(format!("{}.example.", BASE32_DNSSEC.encode(hashed))).unwrap()
        };

        let delegation_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&hash(&child)),
            [RecordType::NS, RecordType::RRSIG],
        );
        let delegation_owner = owner_of(&hash(&child));
        let cover_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&increment(&hash(&x))),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let cover_owner = owner_of(&decrement(&decrement(&hash(&x))));
        let wildcard_cover_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&increment(&hash(&wildcard))),
            [RecordType::SOA, RecordType::RRSIG],
        );
        let wildcard_cover_owner = owner_of(&decrement(&decrement(&hash(&wildcard))));

        let records = [
            Nsec3Record {
                owner: &delegation_owner,
                rdata: &delegation_rdata,
            },
            Nsec3Record {
                owner: &cover_owner,
                rdata: &cover_rdata,
            },
            Nsec3Record {
                owner: &wildcard_cover_owner,
                rdata: &wildcard_cover_rdata,
            },
        ];
        for qname in [&x, &child_qname] {
            assert_eq!(
                evaluate_nsec3_denial(&records, qname, RecordType::A, true, &zone),
                Nsec3Denial::Incomplete,
                "parent-side delegation NSEC3 must not prove NXDOMAIN for {qname}"
            );
        }
    }

    #[test]
    fn test_parent_delegation_nsec3_nodata_only_denies_ds() {
        let qname = Name::from_ascii("child.example.").unwrap();
        let qname_hash = Nsec3HashAlgorithm::SHA1
            .hash(&[], &qname, 0)
            .unwrap()
            .as_ref()
            .to_vec();
        let owner =
            Name::from_ascii(format!("{}.example.", BASE32_DNSSEC.encode(&qname_hash))).unwrap();
        let delegation_rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            Vec::new(),
            increment(&qname_hash),
            [RecordType::NS, RecordType::RRSIG],
        );
        let records = [Nsec3Record {
            owner: &owner,
            rdata: &delegation_rdata,
        }];
        assert_eq!(
            evaluate_nsec3_denial(
                &records,
                &qname,
                RecordType::DS,
                false,
                &Name::from_ascii("example.").unwrap()
            ),
            Nsec3Denial::Secure
        );
        assert_eq!(
            evaluate_nsec3_denial(
                &records,
                &qname,
                RecordType::A,
                false,
                &Name::from_ascii("example.").unwrap()
            ),
            Nsec3Denial::Incomplete
        );
    }
}
