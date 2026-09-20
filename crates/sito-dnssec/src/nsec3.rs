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

/// Enumerates an NSEC3 denial proof for a negative response.
///
/// `nxdomain` selects the RFC 5155 NXDOMAIN proof (closest encloser plus a
/// covering record for the next closer name) over the NODATA proofs (exact
/// match or wildcard match denying the queried type). Only records whose zone
/// contains `qname` are considered.
#[must_use]
pub fn evaluate_nsec3_denial(
    records: &[Nsec3Record<'_>],
    qname: &Name,
    qtype: RecordType,
    nxdomain: bool,
) -> Nsec3Denial {
    let relevant: Vec<Nsec3Record<'_>> = records
        .iter()
        .filter(|record| record.owner.base_name().zone_of(qname))
        // RFC 9276: iterations above the cap are not accepted; ignoring them
        // yields an incomplete (never secure) proof.
        .filter(|record| record.rdata.iterations() <= MAX_ITERATIONS)
        .copied()
        .collect();
    if relevant.is_empty() {
        return Nsec3Denial::Incomplete;
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
            // requires the CNAME bit to be clear: without that check a
            // positive CNAME answer could be replayed as NODATA with
            // authenticated NSEC3 records.
            let denied = relevant.iter().any(|record| {
                matches(record, qname)
                    && !record.rdata.type_set().contains(qtype)
                    && !record.rdata.type_set().contains(RecordType::CNAME)
            });
            return if denied {
                Nsec3Denial::Secure
            } else {
                Nsec3Denial::Incomplete
            };
        }
        // Wildcard NODATA: RFC 5155 §8.7 requires a covering record for the
        // *next closer* name (the child of the closest encloser towards
        // qname), not for the qname itself (whose hash may fall elsewhere),
        // and the wildcard match must deny the type and CNAME.
        let Some(wildcard) = wildcard_of(&closest) else {
            return Nsec3Denial::Incomplete;
        };
        let Some(next_closer) = next_closer else {
            return Nsec3Denial::Incomplete;
        };
        let covered = relevant.iter().any(|record| covers(record, &next_closer));
        let denied = relevant.iter().any(|record| {
            matches(record, &wildcard)
                && !record.rdata.type_set().contains(qtype)
                && !record.rdata.type_set().contains(RecordType::CNAME)
        });
        return if covered && denied {
            Nsec3Denial::Secure
        } else {
            Nsec3Denial::Incomplete
        };
    }

    // NXDOMAIN requires a proper closest encloser and a covering record for
    // the next closer name. Opt-out makes the proof insecure.
    if closest == *qname {
        return Nsec3Denial::Incomplete;
    }
    let Some(next_closer) = next_closer else {
        return Nsec3Denial::Incomplete;
    };
    match relevant.iter().find(|record| covers(record, &next_closer)) {
        Some(record) if record.rdata.opt_out() => Nsec3Denial::OptOut,
        Some(_) => Nsec3Denial::Secure,
        None => Nsec3Denial::Incomplete,
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
            evaluate_nsec3_denial(&records, &qname, RecordType::A, true),
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
            evaluate_nsec3_denial(&records, &qname, RecordType::A, false),
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
            evaluate_nsec3_denial(&records, &qname, RecordType::A, false),
            Nsec3Denial::Incomplete
        );
    }

    #[test]
    fn test_empty_records_are_incomplete() {
        let qname = Name::from_ascii("missing.example.").unwrap();
        assert_eq!(
            evaluate_nsec3_denial(&[], &qname, RecordType::A, true),
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
                evaluate_nsec3_denial(&records, &qname, RecordType::A, true),
                expected,
                "iterations={iterations}"
            );
        }
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
            evaluate_nsec3_denial(&records, &qname, RecordType::A, false),
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
            evaluate_nsec3_denial(&records, &qname, RecordType::A, false),
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
            evaluate_nsec3_denial(&records, &qname, RecordType::A, false),
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
            evaluate_nsec3_denial(&records, &qname, RecordType::A, false),
            Nsec3Denial::Incomplete
        );
    }
}
