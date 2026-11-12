//! RRSIG verification and full response validation.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Applies the RFC 4035 §5.3.3 authenticated TTL to every RRset covered by an
/// RRSIG in the response: the TTL must not exceed the received TTL, the
/// RRSIG's Original TTL, or the remaining signature validity. Without this a
/// validated answer with a long record TTL but a short-lived signature would
/// be cached and served with AD=1 after the signature expired.
pub(super) fn apply_authenticated_ttls(response: &mut Message, now: u32) {
    let signatures: Vec<(LowerName, RecordType, RRSIG)> = response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .chain(response.additionals.iter())
        .filter_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some((
                LowerName::from(&record.name),
                rrsig.input().type_covered,
                rrsig.clone(),
            )),
            // Legacy SIG is accepted by the validator too; treat it as the
            // equivalent RRSIG for TTL accounting.
            RData::DNSSEC(DNSSECRData::SIG(sig)) => Some((
                LowerName::from(&record.name),
                sig.input().type_covered,
                RRSIG::from_sig(sig.input().clone(), sig.sig().to_vec()),
            )),
            _ => None,
        })
        .collect();
    if signatures.is_empty() {
        return;
    }
    for section in [
        &mut response.answers,
        &mut response.authorities,
        &mut response.additionals,
    ] {
        for record in section.iter_mut() {
            // RFC 4035 §5.3.3 also caps the signature RR's own TTL.
            match &record.data {
                RData::DNSSEC(DNSSECRData::RRSIG(own)) => {
                    record.ttl = record.ttl.min(own.authenticated_ttl(record, now));
                    continue;
                }
                RData::DNSSEC(DNSSECRData::SIG(sig)) => {
                    let own = RRSIG::from_sig(sig.input().clone(), sig.sig().to_vec());
                    record.ttl = record.ttl.min(own.authenticated_ttl(record, now));
                    continue;
                }
                _ => {}
            }
            let owner = LowerName::from(&record.name);
            let covered = record.record_type();
            if let Some((_, _, rrsig)) = signatures
                .iter()
                .find(|(sig_owner, sig_covered, _)| *sig_owner == owner && *sig_covered == covered)
            {
                record.ttl = record.ttl.min(rrsig.authenticated_ttl(record, now));
            }
        }
    }

    // A negative answer is authenticated by its NSEC/NSEC3 denial proof, not
    // by the SOA. A zone can sign the SOA with a longer TTL/expiry than the
    // proof, so cap the SOA-derived negative TTL here, while the DNSSEC
    // records are still present. The pipeline strips them for DO=0 clients
    // before caching, and the cache must not use the stripped records to
    // decide how long a Secure negative may live.
    let Some(query) = response.queries.first() else {
        return;
    };
    let qname = query.name().clone();
    let qtype = query.query_type();
    if !is_negative_response(response, &qname, qtype) {
        return;
    }
    let Some(denial_ttl) = authenticated_denial_ttl(response) else {
        return;
    };
    for section in [&mut response.answers, &mut response.authorities] {
        for record in section.iter_mut() {
            if matches!(record.data, RData::SOA(_)) {
                record.ttl = record.ttl.min(denial_ttl);
            }
        }
    }
}

/// Minimum authenticated TTL of the NSEC/NSEC3 denial records and the RRSIGs
/// covering them. Returns `None` when the response carries no denial proof.
pub(super) fn authenticated_denial_ttl(response: &Message) -> Option<u32> {
    response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .chain(response.additionals.iter())
        .filter_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::NSEC(_) | DNSSECRData::NSEC3(_)) => Some(record.ttl),
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig))
                if matches!(
                    rrsig.input().type_covered,
                    RecordType::NSEC | RecordType::NSEC3
                ) =>
            {
                Some(record.ttl)
            }
            RData::DNSSEC(DNSSECRData::SIG(sig))
                if matches!(
                    sig.input().type_covered,
                    RecordType::NSEC | RecordType::NSEC3
                ) =>
            {
                Some(record.ttl)
            }
            _ => None,
        })
        .min()
}

/// Verifies `rrsig` over the RRset it covers using `key`.
pub(super) fn verify_rrsig_covered(
    response: &Message,
    owner: &Name,
    rrsig: &SIG,
    key: &DNSKEY,
) -> bool {
    let type_covered = rrsig.input().type_covered;
    let covered: Vec<&Record> = response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .chain(response.additionals.iter())
        .filter(|record| record.record_type() == type_covered && record.name == *owner)
        .collect();
    if covered.is_empty() {
        return false;
    }
    let rrsig_rdata = RRSIG::from_sig(rrsig.input().clone(), rrsig.sig().to_vec());
    key.verify_rrsig(owner, DNSClass::IN, &rrsig_rdata, covered.into_iter())
        .is_ok()
}

/// Whether a signature record at `sig_owner` covers the RRset at
/// `rrset_owner`.
///
/// Normally the names are equal. A wildcard-expanded answer may instead carry
/// the RRSIG at the wildcard owner (`*.example`), with the answer RRset at the
/// expanded qname (`a.example`). In that case the RRSIG Labels field counts the
/// labels below the wildcard and the signed name is the wildcard owner.
pub(super) fn signature_covers_rrset(sig_owner: &Name, sig: &SIG, rrset_owner: &Name) -> bool {
    if sig_owner == rrset_owner {
        return true;
    }
    if !sig_owner.is_wildcard() {
        return false;
    }
    let base = sig_owner.base_name();
    if base == *rrset_owner || !base.zone_of(rrset_owner) {
        return false;
    }
    // RFC 4592: a wildcard may synthesize a name at any depth below the
    // wildcard base when no closer encloser exists. The RRSIG Labels field
    // counts the labels of the wildcard base, and Hickory's `determine_name`
    // reconstructs `*.<base>` from the expanded name for any number of labels.
    rrset_owner.num_labels() > base.num_labels()
        && usize::from(sig.input().num_labels) == usize::from(base.num_labels())
}

/// Whether every RRset relevant to the question carries an RRSIG.
///
/// The unsigned-delegation probe is driven by this predicate. Presence of one
/// signature anywhere is not enough: a forged positive answer plus an
/// unrelated junk RRSIG must still probe, and a signed CNAME whose target
/// answer has no RRSIG must probe that target. Signatures that cover a
/// relevant RRset count even if they turn out to be forged; validation checks
/// them and fails closed.
pub(super) fn response_has_complete_relevant_signatures(
    response: &Message,
    qname: &Name,
    qtype: RecordType,
) -> bool {
    let negative = is_negative_response(response, qname, qtype);
    let relevant = relevant_answer_keys(response, qname, qtype);
    let signature_for = |rrset: &Record| {
        response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .filter_map(|record| {
                let sig: &SIG = match &record.data {
                    RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => rrsig,
                    RData::DNSSEC(DNSSECRData::SIG(sig)) => sig,
                    _ => return None,
                };
                Some((&record.name, sig))
            })
            .any(|(owner, sig)| {
                sig.input().type_covered == rrset.record_type()
                    && signature_covers_rrset(owner, sig, &rrset.name)
            })
    };

    for record in &response.answers {
        if matches!(
            record.data,
            RData::DNSSEC(DNSSECRData::RRSIG(_) | DNSSECRData::SIG(_))
        ) {
            continue;
        }
        let key = (LowerName::from(&record.name), record.record_type());
        if relevant.contains(&key) && !signature_for(record) {
            return false;
        }
    }

    if negative {
        let negative_name = negative_answer_name(response, qname);
        let negative_lower = LowerName::from(&negative_name);
        // A denial proof needs an RRSIG over the NSEC/NSEC3 RRset in this
        // response, signed by a zone containing the negative answer name.
        return response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .any(|record| {
                let sig: &SIG = match &record.data {
                    RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => rrsig,
                    RData::DNSSEC(DNSSECRData::SIG(sig)) => sig,
                    _ => return false,
                };
                matches!(
                    sig.input().type_covered,
                    RecordType::NSEC | RecordType::NSEC3
                ) && LowerName::from(&sig.input().signer_name).zone_of(&negative_lower)
                    && response
                        .answers
                        .iter()
                        .chain(response.authorities.iter())
                        .any(|candidate| {
                            candidate.record_type() == sig.input().type_covered
                                && signature_covers_rrset(&record.name, sig, &candidate.name)
                        })
            });
    }

    true
}

/// Whether the covering signatures for every relevant answer RRset have at
/// least one candidate key.
///
/// A forged RRSIG that covers the answer's owner/type must not suppress the
/// unsigned-delegation probe merely because a signature record exists. When no
/// validated/cached key and no response DNSKEY matches the signature, probing
/// is the only way to tell a stripped unsigned zone from a key-fetch failure;
/// validation still fails closed afterwards if the probe cannot prove the zone
/// unsigned.
pub(super) fn relevant_signatures_have_key_material(
    key_cache: &KeyCache,
    response: &Message,
    qname: &Name,
    qtype: RecordType,
    now: u32,
) -> bool {
    // Only validated cached keys count. An attacker-supplied DNSKEY with the
    // same tag/algorithm must not make a forged RRSIG look verifiable enough to
    // suppress the probe; the chain fetch still gets a chance to validate real
    // keys before the probe runs.
    let signature_has_key = |sig: &SIG| {
        let signer = LowerName::from(&sig.input().signer_name);
        key_cache
            .get_validated(&signer, sig.input().key_tag, now)
            .is_some_and(|cached| cached.algorithm() == sig.input().algorithm)
    };
    let signatures_for = |rrset: &Record, signer_must_cover: Option<&LowerName>| {
        response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .filter_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some((&record.name, &**rrsig)),
                RData::DNSSEC(DNSSECRData::SIG(sig)) => Some((&record.name, sig)),
                _ => None,
            })
            .filter(|(owner, sig)| {
                sig.input().type_covered == rrset.record_type()
                    && signature_covers_rrset(owner, sig, &rrset.name)
                    && signer_must_cover
                        .is_none_or(|zone| LowerName::from(&sig.input().signer_name).zone_of(zone))
            })
            .map(|(_, sig)| sig)
            .collect::<Vec<_>>()
    };

    let relevant = relevant_answer_keys(response, qname, qtype);
    for rrset in &response.answers {
        let key = (LowerName::from(&rrset.name), rrset.record_type());
        if !relevant.contains(&key) {
            continue;
        }
        let signatures = signatures_for(rrset, None);
        if !signatures.is_empty() && !signatures.iter().any(|sig| signature_has_key(sig)) {
            return false;
        }
    }

    // A forged denial RRSIG with no validated key must also be able to fall
    // through to the post-fetch probe; otherwise an unsigned delegation can be
    // forced into SERVFAIL by attaching a fake NSEC/NSEC3 signature.
    if is_negative_response(response, qname, qtype) {
        let negative_lower = LowerName::from(&negative_answer_name(response, qname));
        for rrset in &response.authorities {
            if !matches!(rrset.record_type(), RecordType::NSEC | RecordType::NSEC3) {
                continue;
            }
            let signatures = signatures_for(rrset, Some(&negative_lower));
            if !signatures.is_empty() && !signatures.iter().any(|sig| signature_has_key(sig)) {
                return false;
            }
        }
    }
    true
}

/// Whether an RRSIG is inside its validity window (allowing clock skew).
pub(super) fn rrsig_time_ok(rrsig: &SIG, now: u32) -> bool {
    rrsig_time_failure(rrsig, now).is_none()
}

/// Returns the failure reason and EDE code when an RRSIG is outside its
/// validity window (allowing `MAX_CLOCK_SKEW`).
pub(super) fn rrsig_time_failure(rrsig: &SIG, now: u32) -> Option<(&'static str, u16)> {
    if now.saturating_add(MAX_CLOCK_SKEW) < rrsig.input().sig_inception.get() {
        return Some(("Signature not yet valid", EDE_DNSSEC_BOGUS));
    }
    if now
        > rrsig
            .input()
            .sig_expiration
            .get()
            .saturating_add(MAX_CLOCK_SKEW)
    {
        return Some(("Signature expired", EDE_SIGNATURE_EXPIRED));
    }
    None
}

/// Whether the response contains a signature over `owner`/`type_covered` that
/// verifies with one of `keys` and is signed by `signer_zone`.
pub(super) fn has_valid_rrsig_for(
    response: &Message,
    owner: &Name,
    type_covered: RecordType,
    signer_zone: &LowerName,
    keys: &[DNSKEY],
    now: u32,
    budget: &mut VerifyBudget,
) -> bool {
    for record in response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .chain(response.additionals.iter())
    {
        if record.name != *owner {
            continue;
        }
        let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data else {
            continue;
        };
        if rrsig.input().type_covered != type_covered
            || LowerName::from(&rrsig.input().signer_name) != *signer_zone
            || !rrsig_time_ok(rrsig, now)
        {
            continue;
        }
        for key in keys {
            if key.algorithm() != rrsig.input().algorithm
                || key.calculate_key_tag().ok() != Some(rrsig.input().key_tag)
            {
                continue;
            }
            if !budget.try_consume() {
                return false;
            }
            if verify_rrsig_covered(response, owner, rrsig, key) {
                return true;
            }
        }
    }
    false
}

impl DnssecValidator {
    /// Validates a response, resolving missing DNSKEY/DS records through the
    /// fetcher when the in-response chain is incomplete.
    ///
    /// The synchronous chain walk runs first. Only an `Indeterminate` result
    /// (signatures verified but not linked to an anchor) triggers network
    /// fetches, bounded to a small per-query budget; fetched records are
    /// appended temporarily for validation and removed again.
    pub async fn validate_with_key_fetcher(
        &self,
        response: &mut Message,
        upstream: Option<&str>,
        now: u32,
        fetcher: &dyn DnssecKeyFetcher,
    ) -> ValidationOutcome {
        // A response without RRSIGs is either a stripped-signature downgrade
        // or a legitimate unsigned delegation. Probe the delegation status
        // regardless of prior signed-zone evidence: only an authenticated DS
        // denial may downgrade it to Insecure, otherwise `validate_response`
        // keeps the fail-closed Bogus decision.
        let mut probe_failed = false;
        let mut budget_exhausted = false;
        let mut has_rrsigs = true;
        let mut has_key_material = true;
        let mut query_is_nta = false;
        if self.mode != DnssecMode::Disabled
            && let Some(query) = response.queries.first()
        {
            has_rrsigs = response_has_complete_relevant_signatures(
                response,
                query.name(),
                query.query_type(),
            );
            has_key_material = relevant_signatures_have_key_material(
                &self.key_cache,
                response,
                query.name(),
                query.query_type(),
                now,
            );
            query_is_nta = self.is_nta(query.name());
            if !has_rrsigs && !query_is_nta {
                // Probe every distinct name in the CNAME chain, including
                // intermediate hops: a chain can leave an unsigned zone for a
                // signed one and return to an unsigned zone. A shared
                // per-response budget bounds amplification; names already
                // covered by cached/in-memory evidence are free. A chain that
                // needs more probes than the budget fails closed below.
                let mut probes = 0usize;
                for name in distinct_cname_chain_names(response, query.name()) {
                    let lower = LowerName::from(&name);
                    if probes >= MAX_CNAME_PROBES && !self.unsigned_status_known(&lower, now) {
                        budget_exhausted = true;
                        break;
                    }
                    match self.prepare_unsigned_response(&lower, fetcher, now).await {
                        UnsignedProbe::Covered => {}
                        UnsignedProbe::Probed => probes += 1,
                        UnsignedProbe::Failed => {
                            probes += 1;
                            probe_failed = true;
                        }
                    }
                }
            }
        }

        // A chain that could not be fully probed within the shared budget is
        // treated as a stripped/fail-closed response, not Insecure/AD=0.
        if budget_exhausted && !has_rrsigs && !query_is_nta {
            return self.handle_bogus(
                response,
                upstream,
                "CNAME chain exceeds DNSSEC probe budget",
                EDE_DNSSEC_BOGUS,
            );
        }

        // A never-proven zone with no signatures and no authenticated
        // delegation status is `Indeterminate` (AD=0), never a persistent
        // Insecure/Bogus decision: the probe may simply be offline. Signed
        // evidence anywhere in the CNAME chain must still fail closed.
        //
        // A failed probe on *any* hop is enough. Even when the queried name is
        // a legitimately unsigned delegation, a CNAME can point into a signed
        // zone whose probe failed (offline or blocked DS/DNSKEY fetch); treating
        // that as Insecure would let an on-path attacker strip RRSIGs and drop
        // the probe traffic to get an unvalidated signed-target answer.
        if probe_failed && !has_rrsigs && !query_is_nta {
            let qname = response
                .queries
                .first()
                .map_or_else(Name::root, |q| q.name().clone());
            if !self.signed_chain_contains(response, &qname, now) {
                return self.indeterminate_outcome(response, upstream);
            }
        }

        // Records appended by `fetch_zone_chain` below are helpers for chain
        // building, never evidence about the original response. Remember
        // where they begin so validation can tell them apart.
        let original_additionals = response.additionals.len();
        // One verification budget covers both passes (pre-fetch and strict)
        // for this response, so a crafted message cannot double its work by
        // forcing the chain walk.
        let mut verify_budget = VerifyBudget::new();
        let baseline = self.validate_response_inner(
            response,
            upstream,
            now,
            Some(original_additionals),
            true,
            &mut verify_budget,
        );
        if baseline != ValidationOutcome::Indeterminate || self.mode == DnssecMode::Disabled {
            return baseline;
        }

        let signers = collect_rrsig_signers(response);
        if signers.is_empty() {
            return self.indeterminate_outcome(response, upstream);
        }

        let anchors = self.trust_anchors.load();
        let mut visited = HashSet::new();
        for signer in signers.iter().take(4) {
            // Reaching the root costs one DNSKEY lookup per label plus one DS
            // lookup per non-root level; a fixed budget of 6 could not reach
            // the root from a signer with three or more labels, leaving
            // otherwise valid zones Indeterminate on a cold cache.
            let mut budget = signer
                .num_labels()
                .saturating_mul(2)
                .saturating_add(1)
                .min(31);
            let _ = fetch_zone_chain(
                &anchors,
                fetcher,
                signer,
                &mut budget,
                &mut visited,
                response,
            )
            .await;
        }

        // This is the post-fetch pass: the "relevant RRSIG is present but not
        // checkable yet" escape no longer applies. If the chain walk produced
        // no usable key, a response under proven signed evidence must fail
        // closed rather than be served unvalidated. Running the strict pass
        // even when no fetch succeeded also covers fully offline upstreams.
        let outcome = self.validate_response_inner(
            response,
            upstream,
            now,
            Some(original_additionals),
            false,
            &mut verify_budget,
        );
        response.additionals.truncate(original_additionals);

        // Strict mode is fail-closed: once validation and its chain fetch have
        // run, an `Indeterminate` result (no usable key, blocked fetch, unknown
        // delegation) is not an acceptable answer for a validating client.
        // `LogOnly` keeps the response and AD=0 for diagnostics; CD=1 and
        // disabled validation never reach this path.
        if outcome == ValidationOutcome::Indeterminate {
            // A covering RRSIG with no candidate key may be a forgery over a
            // legitimately unsigned delegation. The chain fetch above already
            // had its chance to produce a key; probing now avoids turning that
            // forgery into a persistent SERVFAIL (DoS) while still failing
            // closed if no authenticated DS denial is found.
            if has_rrsigs && !has_key_material && !query_is_nta {
                let qname = response
                    .queries
                    .first()
                    .map_or_else(Name::root, |query| query.name().clone());
                let mut probes = 0usize;
                let mut post_probe_failed = false;
                let mut post_budget_exhausted = false;
                for name in distinct_cname_chain_names(response, &qname) {
                    let lower = LowerName::from(&name);
                    if probes >= MAX_CNAME_PROBES && !self.unsigned_status_known(&lower, now) {
                        post_budget_exhausted = true;
                        break;
                    }
                    match self.prepare_unsigned_response(&lower, fetcher, now).await {
                        UnsignedProbe::Covered => {}
                        UnsignedProbe::Probed => probes += 1,
                        UnsignedProbe::Failed => {
                            probes += 1;
                            post_probe_failed = true;
                        }
                    }
                }
                // Only an authenticated unsigned delegation covering the
                // final target, with no failed probe anywhere in the chain,
                // may downgrade. Any failed hop is indistinguishable from a
                // blocked DS/DNSKEY fetch for a stripped signed target and
                // must fail closed.
                let target = negative_answer_name(response, &qname);
                let target_unsigned = self.insecure_zone_covers(&LowerName::from(&target), now);
                if !post_probe_failed
                    && !post_budget_exhausted
                    && target_unsigned
                    && !self.signed_chain_contains(response, &qname, now)
                {
                    response.metadata.authentic_data = false;
                    let outcome = ValidationOutcome::Insecure;
                    self.metrics.record_validation(&outcome);
                    return outcome;
                }
            }
            return self.indeterminate_outcome(response, upstream);
        }
        outcome
    }

    /// Walks DS/DNSKEY links present in the response to extend trust from the
    /// configured anchors to zone signing keys.
    ///
    /// Supports two linkage forms without extra network round-trips:
    /// - a DNSKEY RRset self-signed by an anchored/validated key (KSK -> ZSK);
    /// - a DS RRset signed by a validated parent key whose digest matches a
    ///   child DNSKEY (delegation).
    ///
    /// Delegations are only accepted when the RRSIG signer zone equals the
    /// parent DNSKEY owner, the parent is a strict ancestor of the DS owner,
    /// the child key owner equals the DS owner, and the DS digest/algorithm are
    /// allowed by policy (RFC 8624). The fixpoint is bounded and newly
    /// validated keys are cached with the minimum of the record TTL and the
    /// matching signature expiration.
    pub(super) fn build_validated_key_set(
        &self,
        response: &Message,
        dnskeys: &[(Name, DNSKEY)],
        rrsigs: &[(Name, SIG)],
        now: u32,
        budget: &mut VerifyBudget,
    ) -> KeySetBuild {
        let mut result = KeySetBuild::default();
        let anchors = self.trust_anchors.load();

        for (owner, key) in dnskeys {
            if !dnskey_policy_ok(key) {
                continue;
            }
            let Ok(tag) = key.calculate_key_tag() else {
                continue;
            };
            let lower = LowerName::from(owner);
            let anchored = anchors.contains(key.public_key())
                || anchors.contains_with_name(key.public_key(), &lower);
            if anchored || self.key_cache.is_validated(&lower, tag, key, now) {
                // Note: linking a key to an anchor proves the *key*, not that
                // the name is in a signed zone. Marking a zone here (in
                // particular the root, whose key is fetched by the chain walk)
                // would make every descendant without RRSIGs look like a
                // stripped-signature downgrade. Zone evidence is only recorded
                // for signatures that actually validated over response data.
                result
                    .validated
                    .insert((lower.clone(), dnskey_fingerprint(key)));
            }
        }

        let ds_records: Vec<(&Name, &DS)> = response
            .authorities
            .iter()
            .chain(response.additionals.iter())
            .filter_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::DS(ds)) => Some((&record.name, ds)),
                _ => None,
            })
            .take(MAX_DS_RECORDS)
            .collect();

        let mut ds_links: HashMap<LowerName, DsLink> = HashMap::new();

        let mut changed = true;
        let mut rounds = 0u8;
        'walk: while changed && rounds < 16 {
            changed = false;
            rounds += 1;

            for (ds_owner, ds) in &ds_records {
                let lower_ds = LowerName::from(*ds_owner);
                for (parent_owner, parent_key) in dnskeys {
                    if !dnskey_policy_ok(parent_key) {
                        continue;
                    }
                    let Ok(parent_tag) = parent_key.calculate_key_tag() else {
                        continue;
                    };
                    let lower_parent = LowerName::from(parent_owner);
                    if !result
                        .validated
                        .contains(&(lower_parent.clone(), dnskey_fingerprint(parent_key)))
                    {
                        continue;
                    }
                    let mut ds_signed = false;
                    for (owner, sig) in rrsigs {
                        if owner != *ds_owner
                            || sig.input().type_covered != RecordType::DS
                            || LowerName::from(&sig.input().signer_name) != lower_parent
                            || sig.input().key_tag != parent_tag
                        {
                            continue;
                        }
                        if !budget.try_consume() {
                            // Bounded work: stop walking the forged chain.
                            break 'walk;
                        }
                        self.metrics.record_signature_verification();
                        if !verify_rrsig_covered(response, ds_owner, sig, parent_key) {
                            continue;
                        }
                        if let Some(failure) = rrsig_time_failure(sig, now) {
                            result.time_failure.get_or_insert(failure);
                            continue;
                        }
                        ds_signed = true;
                        break;
                    }
                    if !ds_signed {
                        continue;
                    }

                    let link = ds_links.entry(lower_ds.clone()).or_default();
                    link.signed = true;

                    // The DS owner must be a strict subdomain of the signing
                    // parent: a DS for any other name is a cross-zone forgery.
                    if lower_parent == lower_ds || !lower_parent.zone_of(&lower_ds) {
                        link.hierarchy_bad = true;
                        continue;
                    }
                    if !allowed_ds_digest(ds.digest_type())
                        || !allowed_dnskey_algorithm(ds.algorithm())
                    {
                        link.policy_bad = true;
                        continue;
                    }
                    link.supported_present = true;

                    let mut child_keys = dnskeys
                        .iter()
                        .filter(|(child_owner, _)| child_owner == *ds_owner)
                        .peekable();
                    if child_keys.peek().is_some() {
                        link.child_present = true;
                    }
                    for (_child_owner, child_key) in child_keys {
                        if !dnskey_policy_ok(child_key) || child_key.algorithm() != ds.algorithm() {
                            continue;
                        }
                        if !ds.covers(ds_owner, child_key).unwrap_or(false) {
                            continue;
                        }
                        link.matched = true;
                        if result
                            .validated
                            .insert((lower_ds.clone(), dnskey_fingerprint(child_key)))
                        {
                            changed = true;
                        }
                    }
                }
            }

            for (owner, signer_key) in dnskeys {
                if !dnskey_policy_ok(signer_key) {
                    continue;
                }
                let Ok(tag) = signer_key.calculate_key_tag() else {
                    continue;
                };
                let lower = LowerName::from(owner);
                if !result
                    .validated
                    .contains(&(lower.clone(), dnskey_fingerprint(signer_key)))
                {
                    continue;
                }
                let mut rrset_signed = false;
                for (sig_owner, sig) in rrsigs {
                    if sig_owner != owner
                        || sig.input().type_covered != RecordType::DNSKEY
                        || LowerName::from(&sig.input().signer_name) != lower
                        || sig.input().key_tag != tag
                    {
                        continue;
                    }
                    if !budget.try_consume() {
                        // Bounded work: stop walking the forged chain.
                        break 'walk;
                    }
                    self.metrics.record_signature_verification();
                    if !verify_rrsig_covered(response, owner, sig, signer_key) {
                        continue;
                    }
                    if let Some(failure) = rrsig_time_failure(sig, now) {
                        result.time_failure.get_or_insert(failure);
                        continue;
                    }
                    rrset_signed = true;
                    break;
                }
                if !rrset_signed {
                    continue;
                }
                for (other_owner, other_key) in dnskeys {
                    if other_owner != owner || !dnskey_policy_ok(other_key) {
                        continue;
                    }
                    if result
                        .validated
                        .insert((LowerName::from(other_owner), dnskey_fingerprint(other_key)))
                    {
                        changed = true;
                    }
                }
            }
        }

        for (owner, link) in &ds_links {
            if link.hierarchy_bad
                || (link.signed && link.child_present && !link.matched && link.supported_present)
            {
                result.forged.insert(owner.clone());
            } else if link.signed && link.policy_bad && !link.supported_present && !link.matched {
                result.unsupported.insert(owner.clone());
            }
        }

        for (lower, fingerprint) in &result.validated {
            // Insert the DNSKEY whose *bytes* were validated. Matching by tag
            // here would let a same-tag forgery overwrite the validated key.
            let Some((owner, key)) = dnskeys.iter().find(|(owner, key)| {
                LowerName::from(owner) == *lower && dnskey_fingerprint(key) == *fingerprint
            }) else {
                continue;
            };
            let ttl = response
                .answers
                .iter()
                .chain(response.authorities.iter())
                .chain(response.additionals.iter())
                .find(|record| {
                    record.name == *owner
                        && matches!(record.data, RData::DNSSEC(DNSSECRData::DNSKEY(_)))
                })
                .map_or(3600, |record| record.ttl);
            let ttl_expiry = now.saturating_add(ttl);
            let sig_expiry = rrsigs
                .iter()
                .filter(|(_, sig)| {
                    LowerName::from(&sig.input().signer_name) == *lower && rrsig_time_ok(sig, now)
                })
                .map(|(_, sig)| sig.input().sig_expiration.get())
                .min();
            let expiry = sig_expiry.map_or(ttl_expiry, |e| e.min(ttl_expiry));
            let Ok(tag) = key.calculate_key_tag() else {
                continue;
            };
            self.key_cache
                .insert_validated_with_now(lower.clone(), tag, key.clone(), expiry, now);
        }

        result
    }

    /// Validate a response against DNSSEC rules using only records already in
    /// the message (no key fetcher).
    ///
    /// This is the pre-fetch/log-only entry point. It cannot walk or fetch a
    /// missing DNSKEY/DS chain, so in [`DnssecMode::Validate`] an inconclusive
    /// result is converted to the same fail-closed outcome
    /// [`Self::validate_with_key_fetcher`] produces after its fetch: Bogus with
    /// SERVFAIL and no answer. Direct library callers that want to try the
    /// chain walk must use [`Self::validate_with_key_fetcher`]; callers that
    /// intentionally serve unvalidated data use [`DnssecMode::LogOnly`], which
    /// keeps `Indeterminate` with AD=0.
    ///
    /// `validate_response_inner` returns `Indeterminate` provisionally so the
    /// chain-walking caller can still fetch keys. This entry point is the
    /// finalizer, so it records the outcome actually served exactly once.
    pub fn validate_response(
        &self,
        response: &mut Message,
        upstream: Option<&str>,
        now: u32,
    ) -> ValidationOutcome {
        let mut verify_budget = VerifyBudget::new();
        let outcome =
            self.validate_response_inner(response, upstream, now, None, true, &mut verify_budget);
        // Without a fetcher there is no post-fetch pass to rescue an
        // Indeterminate result. Serving it as AD=0 in strict mode would be a
        // fail-open for a caller that only ever invokes this sync API.
        if outcome == ValidationOutcome::Indeterminate {
            return self.indeterminate_outcome(response, upstream);
        }
        outcome
    }

    /// Marks a response secure and records the outcome.
    pub(super) fn secure_outcome(&self, response: &mut Message, now: u32) -> ValidationOutcome {
        apply_authenticated_ttls(response, now);
        response.metadata.authentic_data = true;
        let outcome = ValidationOutcome::Secure;
        self.metrics.record_validation(&outcome);
        outcome
    }

    pub(super) fn handle_bogus(
        &self,
        response: &mut Message,
        upstream: Option<&str>,
        reason: &str,
        ede_code: u16,
    ) -> ValidationOutcome {
        let outcome = ValidationOutcome::Bogus {
            reason: reason.to_string(),
            ede_code,
        };
        self.metrics.record_validation(&outcome);
        self.metrics.record_bogus(upstream, reason);

        match self.mode {
            DnssecMode::Validate => {
                response.metadata.response_code = ResponseCode::ServFail;
                response.metadata.authentic_data = false;
                response.answers.clear();
                apply_ede(response, ede_code, reason);
                outcome
            }
            DnssecMode::LogOnly => {
                warn!(
                    "DNSSEC Bogus validation in log-only mode for upstream {:?}: {}",
                    upstream, reason
                );
                response.metadata.authentic_data = false;
                outcome
            }
            DnssecMode::Disabled => ValidationOutcome::Insecure,
        }
    }
}
