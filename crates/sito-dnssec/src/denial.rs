//! NSEC/NSEC3 denial evaluation and CNAME helpers.

#[allow(clippy::wildcard_imports)]
use super::*;

/// CNAME target at `name` in the answer section, if any.
pub(super) fn cname_target(response: &Message, name: &Name) -> Option<Name> {
    response.answers.iter().find_map(|record| {
        if record.name == *name
            && let RData::CNAME(cname) = &record.data
            && cname.0 != *name
        {
            Some(cname.0.clone())
        } else {
            None
        }
    })
}

/// Follows a CNAME chain in the answer section and returns the final name.
pub(super) fn negative_answer_name(response: &Message, qname: &Name) -> Name {
    let mut current = qname.clone();
    for _ in 0..16 {
        match cname_target(response, &current) {
            Some(next) => current = next,
            None => break,
        }
    }
    current
}

/// Every name in the CNAME chain starting at `qname` (the query name plus each
/// target), bounded to 16 hops. Used to check signature coverage across a
/// stripped chain, not only at the original qname.
pub(super) fn cname_chain_names(response: &Message, qname: &Name) -> Vec<Name> {
    let mut names = vec![qname.clone()];
    let mut current = qname.clone();
    for _ in 0..16 {
        let Some(next) = cname_target(response, &current) else {
            break;
        };
        if next == current {
            break;
        }
        names.push(next.clone());
        current = next;
    }
    names
}

/// Distinct names in the CNAME chain (query name plus targets), preserving
/// first-seen order. Deduplication matters because a loop or repeated target
/// must not consume the per-response probe budget twice.
pub(super) fn distinct_cname_chain_names(response: &Message, qname: &Name) -> Vec<Name> {
    let mut seen = HashSet::new();
    let mut names = Vec::new();
    for name in cname_chain_names(response, qname) {
        if seen.insert(LowerName::from(&name)) {
            names.push(name);
        }
    }
    names
}

/// Deterministic fingerprint of the trust-anchor and NTA policy that produced
/// a chain-cache entry. Changing an anchor (including its key material) or an
/// NTA invalidates every cached status, because an `Unsigned` proven under the
/// old policy can otherwise override a newly configured anchor.
pub(super) fn policy_fingerprint(trust_anchors: &[String], ntas: &[String]) -> String {
    // FNV-1a keeps the persisted fingerprint short and stable without pulling
    // in a hashing dependency. Collision risk is irrelevant here: a collision
    // only keeps cache entries that the policy would also accept.
    let mut anchors: Vec<&str> = trust_anchors.iter().map(String::as_str).collect();
    anchors.sort_unstable();
    anchors.dedup();
    let mut ntas: Vec<&str> = ntas.iter().map(String::as_str).collect();
    ntas.sort_unstable();
    ntas.dedup();

    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for (tag, values) in [("anchors", anchors), ("ntas", ntas)] {
        for byte in tag.bytes().chain([0xff]) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        for value in values {
            for byte in value.bytes().chain([0xff]) {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
    }
    format!("v1-{hash:016x}")
}

/// Whether a response is negative (NXDOMAIN, or a NODATA answer for the
/// queried name after following any CNAME chain).
pub(super) fn is_negative_response(response: &Message, qname: &Name, qtype: RecordType) -> bool {
    if response.metadata.response_code == ResponseCode::NXDomain {
        return true;
    }
    if response.metadata.response_code != ResponseCode::NoError {
        return false;
    }
    // A CNAME at the queried name *is* the positive answer for QTYPE=CNAME.
    // Following the chain first would inspect the target name and wrongly
    // classify the answer as NODATA, replacing a valid signature check with a
    // denial-proof check that can never succeed.
    if qtype == RecordType::CNAME && cname_target(response, qname).is_some() {
        return false;
    }
    let target = negative_answer_name(response, qname);
    !response.answers.iter().any(|record| {
        record.name == target && (record.record_type() == qtype || qtype == RecordType::ANY)
    })
}

/// RRsets that answer the question: the queried name/type, its CNAME (if any)
/// and every RRset along the CNAME chain.
pub(super) fn relevant_answer_keys(
    response: &Message,
    qname: &Name,
    qtype: RecordType,
) -> HashSet<(LowerName, RecordType)> {
    let mut relevant = HashSet::new();
    if qtype == RecordType::ANY {
        for record in &response.answers {
            if record.name == *qname {
                relevant.insert((LowerName::from(&record.name), record.record_type()));
            }
        }
        return relevant;
    }
    let mut current = qname.clone();
    for _ in 0..16 {
        let lower = LowerName::from(&current);
        relevant.insert((lower.clone(), qtype));
        relevant.insert((lower, RecordType::CNAME));
        match cname_target(response, &current) {
            Some(next) => current = next,
            None => break,
        }
    }
    relevant
}

/// If `qname` begins a CNAME chain whose signed prefix in `trusted_covered`
/// crosses into an unsigned target (with no RRSIGs in `rrsigs` for that target
/// or any subsequent CNAME hop), returns the final unsigned target name.
pub(super) fn signed_cname_to_unsigned_target(
    response: &Message,
    qname: &Name,
    trusted_covered: &HashSet<(LowerName, RecordType)>,
    rrsigs: &[(Name, SIG)],
) -> Option<Name> {
    let mut current = qname.clone();
    let mut saw_signed_cname = false;
    for _ in 0..16 {
        let lower = LowerName::from(&current);
        if trusted_covered.contains(&(lower, RecordType::CNAME))
            && let Some(next) = cname_target(response, &current)
        {
            saw_signed_cname = true;
            current = next;
        } else {
            break;
        }
    }
    if !saw_signed_cname {
        return None;
    }
    let mut tail = current;
    for _ in 0..16 {
        if rrsigs.iter().any(|(owner, _)| *owner == tail) {
            return None;
        }
        match cname_target(response, &tail) {
            Some(next) => tail = next,
            None => break,
        }
    }
    Some(tail)
}

/// A signature that verified cryptographically with a key linked to a trust
/// anchor or to a validated chain.
pub(super) struct TrustedSignature {
    pub(super) owner: LowerName,
    pub(super) covered: RecordType,
    pub(super) signer: LowerName,
    pub(super) signer_name: Name,
}

/// Outcome of enumerating NSEC/NSEC3 denial records for a negative response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DenialResult {
    /// A complete authenticated denial proof.
    Secure,
    /// Only an NSEC3 opt-out proof: an unsigned delegation may exist.
    OptOut,
    /// The available records do not enumerate a complete proof.
    Incomplete,
}

/// Enumerates NSEC/NSEC3 denial proofs using only signatures that verified
/// with validated keys, matched to their denial RRsets.
pub(super) fn evaluate_denial(
    response: &Message,
    negative_name: &Name,
    negative_lower: &LowerName,
    qtype: RecordType,
    trusted_sigs: &[TrustedSignature],
) -> DenialResult {
    let nxdomain = response.metadata.response_code == ResponseCode::NXDomain;
    let mut opt_out = false;
    // NSEC/NSEC3 records grouped by signer zone: a complete denial proof can
    // span several records (e.g. qname cover plus wildcard cover), so the
    // whole signed set must be evaluated together.
    let mut nsec_groups: HashMap<LowerName, (Name, Vec<NsecRecord<'_>>)> = HashMap::new();
    let mut nsec3_groups: HashMap<LowerName, (Name, Vec<Nsec3Record<'_>>)> = HashMap::new();

    for record in response
        .authorities
        .iter()
        .chain(response.additionals.iter())
    {
        let (nsec_rdata, nsec3_rdata) = match &record.data {
            RData::DNSSEC(DNSSECRData::NSEC(nsec)) => (Some(nsec), None),
            RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) => (None, Some(nsec3)),
            _ => (None, None),
        };
        if nsec_rdata.is_none() && nsec3_rdata.is_none() {
            continue;
        }
        let record_lower = LowerName::from(&record.name);
        for trusted in trusted_sigs {
            if trusted.owner != record_lower || !trusted.signer.zone_of(negative_lower) {
                continue;
            }
            match (nsec_rdata, nsec3_rdata) {
                (Some(nsec), _) if trusted.covered == RecordType::NSEC => {
                    nsec_groups
                        .entry(trusted.signer.clone())
                        .or_insert_with(|| (trusted.signer_name.clone(), Vec::new()))
                        .1
                        .push(NsecRecord {
                            owner: &record.name,
                            rdata: nsec,
                        });
                }
                (_, Some(nsec3)) if trusted.covered == RecordType::NSEC3 => {
                    nsec3_groups
                        .entry(trusted.signer.clone())
                        .or_insert_with(|| (trusted.signer_name.clone(), Vec::new()))
                        .1
                        .push(Nsec3Record {
                            owner: &record.name,
                            rdata: nsec3,
                        });
                }
                _ => {}
            }
        }
    }

    for (signer, records) in nsec_groups.values() {
        if evaluate_nsec_denial(records, negative_name, qtype, nxdomain, signer)
            == NsecDenial::Secure
        {
            return DenialResult::Secure;
        }
    }
    for (signer_name, records) in nsec3_groups.values() {
        match evaluate_nsec3_denial(records, negative_name, qtype, nxdomain, signer_name) {
            Nsec3Denial::Secure => return DenialResult::Secure,
            Nsec3Denial::OptOut => opt_out = true,
            Nsec3Denial::Incomplete => {}
        }
    }
    if opt_out {
        DenialResult::OptOut
    } else {
        DenialResult::Incomplete
    }
}
