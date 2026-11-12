//! Full DNSSEC response validation phases.
//!
//! `validate_response_inner` is orchestration only: material collection,
//! signature verification, negative-proof decisions, and final fail-closed
//! classification live in focused helpers.

#[allow(clippy::wildcard_imports)]
use super::*;

struct ValidationMaterial {
    response_dnskeys: Vec<(Name, DNSKEY)>,
    rrsigs: Vec<(Name, SIG)>,
    helper_rrsigs: Vec<bool>,
}

struct SignatureCheck {
    accepted: bool,
    first_failure: Option<(&'static str, u16)>,
    policy_violation: bool,
    trusted: Option<TrustedSignature>,
    signer_covers_qname: bool,
    mark_signed_zone: Option<(LowerName, u32)>,
}

impl SignatureCheck {
    fn rejected(first_failure: Option<(&'static str, u16)>, policy_violation: bool) -> Self {
        Self {
            accepted: false,
            first_failure,
            policy_violation,
            trusted: None,
            signer_covers_qname: false,
            mark_signed_zone: None,
        }
    }
}

struct SignatureEvidence {
    key_set: KeySetBuild,
    relevant_keys: HashSet<(LowerName, RecordType)>,
    has_relevant_rrsig: bool,
    has_trusted_sig: bool,
    trusted_covered: HashSet<(LowerName, RecordType)>,
    trusted_sigs: Vec<TrustedSignature>,
    trusted_signer_covers_qname: bool,
    first_failure: Option<(&'static str, u16)>,
    policy_violation: bool,
    rrsigs: Vec<(Name, SIG)>,
    helper_rrsigs: Vec<bool>,
}

impl DnssecValidator {
    /// Validate a response, treating additional-section records starting at
    /// `helper_additionals` as chain-fetch helpers.
    ///
    /// [`fetch_zone_chain`] appends DNSKEY/DS records (and their RRSIGs) to
    /// the response so the chain can be built in one place. Those helper
    /// signatures authenticate helper RRsets, not the original answer.
    ///
    /// `allow_unchecked_signatures` is true only on the pre-fetch pass. It
    /// permits returning `Indeterminate` when a relevant signature cannot be
    /// checked yet, because the caller may still fetch its key.
    pub(super) fn validate_response_inner(
        &self,
        response: &mut Message,
        upstream: Option<&str>,
        now: u32,
        helper_additionals: Option<usize>,
        allow_unchecked_signatures: bool,
        budget: &mut VerifyBudget,
    ) -> ValidationOutcome {
        if self.mode == DnssecMode::Disabled {
            response.metadata.authentic_data = false;
            let outcome = ValidationOutcome::Insecure;
            self.metrics.record_validation(&outcome);
            return outcome;
        }

        // NTA bypass applies to every question in the message.
        if response
            .queries
            .iter()
            .any(|query| self.is_nta(query.name()))
        {
            debug!("Bypassing DNSSEC validation for NTA domain");
            response.metadata.authentic_data = false;
            let outcome = ValidationOutcome::NtaBypass;
            self.metrics.record_validation(&outcome);
            return outcome;
        }

        let Some(query) = response.queries.first() else {
            response.metadata.authentic_data = false;
            // `Indeterminate` is provisional: the entry point that finalizes
            // the outcome records it (or the Bogus/Insecure conversion) once.
            return ValidationOutcome::Indeterminate;
        };
        let qname = query.name().clone();
        let qtype = query.query_type();

        let material = Self::collect_validation_material(response, helper_additionals);
        if material.rrsigs.is_empty() {
            response.metadata.authentic_data = false;
            if self.signed_chain_contains(response, &qname, now) {
                return self.handle_bogus(
                    response,
                    upstream,
                    "Missing RRSIG for zone previously proven signed",
                    EDE_DNSSEC_BOGUS,
                );
            }
            let outcome = ValidationOutcome::Insecure;
            self.metrics.record_validation(&outcome);
            return outcome;
        }

        // Extend trust from anchors to derived keys (DS delegation, KSK->ZSK).
        let key_set = self.build_validated_key_set(
            response,
            &material.response_dnskeys,
            &material.rrsigs,
            now,
            budget,
        );
        let evidence =
            self.build_signature_evidence(response, &qname, qtype, key_set, material, now, budget);
        self.finalize_validation(
            response,
            upstream,
            &qname,
            qtype,
            evidence,
            allow_unchecked_signatures,
            now,
        )
    }

    /// Phase 1: bounded collection of DNSKEY and RRSIG/SIG records.
    fn collect_validation_material(
        response: &Message,
        helper_additionals: Option<usize>,
    ) -> ValidationMaterial {
        let mut response_dnskeys = Vec::new();
        for record in response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .chain(response.additionals.iter())
        {
            if response_dnskeys.len() >= MAX_DNSKEYS {
                break;
            }
            if let RData::DNSSEC(DNSSECRData::DNSKEY(key)) = &record.data {
                response_dnskeys.push((record.name.clone(), key.clone()));
            }
        }

        // Signatures appended by the chain walk are flagged as helpers: they
        // build the key chain but do not authenticate the original response.
        let helper_start = helper_additionals.unwrap_or(usize::MAX);
        let mut rrsigs = Vec::new();
        let mut helper_rrsigs = Vec::new();
        for record in response.answers.iter().chain(response.authorities.iter()) {
            if rrsigs.len() >= MAX_RRSIGS {
                break;
            }
            match &record.data {
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                    rrsigs.push((record.name.clone(), (**rrsig).clone()));
                    helper_rrsigs.push(false);
                }
                RData::DNSSEC(DNSSECRData::SIG(sig)) => {
                    rrsigs.push((record.name.clone(), sig.clone()));
                    helper_rrsigs.push(false);
                }
                _ => {}
            }
        }
        for (index, record) in response.additionals.iter().enumerate() {
            if rrsigs.len() >= MAX_RRSIGS {
                break;
            }
            let is_helper = index >= helper_start;
            match &record.data {
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                    rrsigs.push((record.name.clone(), (**rrsig).clone()));
                    helper_rrsigs.push(is_helper);
                }
                RData::DNSSEC(DNSSECRData::SIG(sig)) => {
                    rrsigs.push((record.name.clone(), sig.clone()));
                    helper_rrsigs.push(is_helper);
                }
                _ => {}
            }
        }

        ValidationMaterial {
            response_dnskeys,
            rrsigs,
            helper_rrsigs,
        }
    }

    /// Phase 2: verify each RRSIG and accumulate trusted coverage/evidence.
    #[allow(clippy::too_many_arguments)]
    fn build_signature_evidence(
        &self,
        response: &Message,
        qname: &Name,
        qtype: RecordType,
        key_set: KeySetBuild,
        material: ValidationMaterial,
        now: u32,
        budget: &mut VerifyBudget,
    ) -> SignatureEvidence {
        let ValidationMaterial {
            response_dnskeys,
            rrsigs,
            helper_rrsigs,
        } = material;
        let qname_lower = LowerName::from(qname);
        let anchors = self.trust_anchors.load();
        let relevant_keys = relevant_answer_keys(response, qname, qtype);
        let has_relevant_rrsig =
            rrsigs
                .iter()
                .zip(helper_rrsigs.iter())
                .any(|((owner, sig), is_helper)| {
                    !is_helper
                        && response
                            .answers
                            .iter()
                            .chain(response.authorities.iter())
                            .any(|record| {
                                record.record_type() == sig.input().type_covered
                                    && relevant_keys.contains(&(
                                        LowerName::from(&record.name),
                                        sig.input().type_covered,
                                    ))
                                    && signature_covers_rrset(owner, sig, &record.name)
                            })
                });

        let mut first_failure = key_set.time_failure;
        let mut policy_violation = false;
        let mut has_trusted_sig = false;
        let mut trusted_covered: HashSet<(LowerName, RecordType)> = HashSet::new();
        let mut trusted_sigs: Vec<TrustedSignature> = Vec::new();
        let mut trusted_signer_covers_qname = false;

        for ((rrsig_owner, rrsig), is_helper) in rrsigs.iter().zip(helper_rrsigs.iter()) {
            let check = self.verify_signature(
                response,
                &response_dnskeys,
                rrsig_owner,
                rrsig,
                *is_helper,
                &key_set,
                &anchors,
                &relevant_keys,
                &qname_lower,
                now,
                budget,
            );
            if let Some(failure) = check.first_failure {
                first_failure.get_or_insert(failure);
            }
            if check.policy_violation {
                policy_violation = true;
            }
            if !check.accepted {
                continue;
            }
            has_trusted_sig = true;
            if let Some(trusted) = check.trusted {
                trusted_covered.insert((trusted.owner.clone(), trusted.covered));
                trusted_sigs.push(trusted);
            }
            if check.signer_covers_qname {
                trusted_signer_covers_qname = true;
            }
            if let Some((zone, expiry)) = check.mark_signed_zone {
                self.mark_signed_zone(&zone, expiry, now);
            }
        }

        SignatureEvidence {
            key_set,
            relevant_keys,
            has_relevant_rrsig,
            has_trusted_sig,
            trusted_covered,
            trusted_sigs,
            trusted_signer_covers_qname,
            first_failure,
            policy_violation,
            rrsigs,
            helper_rrsigs,
        }
    }

    /// Verify one RRSIG against its candidate keys.
    #[allow(clippy::too_many_arguments)]
    fn verify_signature(
        &self,
        response: &Message,
        response_dnskeys: &[(Name, DNSKEY)],
        rrsig_owner: &Name,
        rrsig: &SIG,
        is_helper: bool,
        key_set: &KeySetBuild,
        anchors: &TrustAnchors,
        relevant_keys: &HashSet<(LowerName, RecordType)>,
        qname_lower: &LowerName,
        now: u32,
        budget: &mut VerifyBudget,
    ) -> SignatureCheck {
        let inception = rrsig.input().sig_inception.get();
        let expiration = rrsig.input().sig_expiration.get();
        let type_covered = rrsig.input().type_covered;
        let rrset_owner = if rrsig_owner.is_wildcard() {
            response
                .answers
                .iter()
                .find(|record| {
                    record.record_type() == type_covered
                        && signature_covers_rrset(rrsig_owner, rrsig, &record.name)
                        && relevant_keys.contains(&(LowerName::from(&record.name), type_covered))
                })
                .map_or(rrsig_owner, |record| &record.name)
        } else {
            rrsig_owner
        };

        let rrsig_relevant =
            !is_helper && relevant_keys.contains(&(LowerName::from(rrset_owner), type_covered));
        let mut first_failure = None;

        if now.saturating_add(MAX_CLOCK_SKEW) < inception {
            if rrsig_relevant {
                first_failure = Some(("Signature not yet valid", EDE_DNSSEC_BOGUS));
            }
            return SignatureCheck::rejected(first_failure, false);
        }
        if now > expiration.saturating_add(MAX_CLOCK_SKEW) {
            if rrsig_relevant {
                first_failure = Some(("Signature expired", EDE_SIGNATURE_EXPIRED));
            }
            return SignatureCheck::rejected(first_failure, false);
        }

        let signer_name = &rrsig.input().signer_name;
        let key_tag = rrsig.input().key_tag;
        let lower_signer = LowerName::from(signer_name);
        let candidates = self.signature_candidates(
            response_dnskeys,
            signer_name,
            key_tag,
            rrsig.input().algorithm,
            &lower_signer,
            key_set,
            anchors,
            now,
        );
        if candidates.is_empty() {
            return SignatureCheck::rejected(first_failure, false);
        }

        let covered_records: Vec<&Record> = response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .chain(response.additionals.iter())
            .filter(|r| r.record_type() == type_covered && r.name == *rrset_owner)
            .collect();

        if covered_records.is_empty() {
            if rrsig_relevant {
                first_failure = Some((
                    "RRSIG does not cover any records in the response",
                    EDE_DNSSEC_BOGUS,
                ));
            }
            return SignatureCheck::rejected(first_failure, false);
        }

        let rrsig_rdata = RRSIG::from_sig(rrsig.input().clone(), rrsig.sig().to_vec());
        let mut accepted = false;
        let mut candidate_policy_rejected = false;
        let mut candidate_failure: Option<(&'static str, u16)> = None;

        for dnskey in &candidates {
            if !dnskey_policy_ok(dnskey) {
                candidate_policy_rejected = true;
                continue;
            }

            if !budget.try_consume() {
                break;
            }
            self.metrics.record_signature_verification();
            if dnskey
                .verify_rrsig(
                    rrset_owner,
                    DNSClass::IN,
                    &rrsig_rdata,
                    covered_records.iter().copied(),
                )
                .is_err()
            {
                candidate_failure.get_or_insert((
                    "Cryptographic signature verification failed",
                    EDE_DNSSEC_BOGUS,
                ));
                continue;
            }

            if !lower_signer.zone_of(&LowerName::from(rrset_owner)) {
                candidate_failure.get_or_insert((
                    "RRSIG signer does not contain the RRset owner",
                    EDE_DNSSEC_BOGUS,
                ));
                continue;
            }

            let is_trusted = anchors.contains(dnskey.public_key())
                || anchors.contains_with_name(dnskey.public_key(), &lower_signer)
                || key_set
                    .validated
                    .contains(&(lower_signer.clone(), dnskey_fingerprint(dnskey)))
                || self
                    .key_cache
                    .is_validated(&lower_signer, key_tag, dnskey, now);

            if !is_trusted {
                continue;
            }

            accepted = true;
            break;
        }

        if !accepted {
            if let Some((reason, ede_code)) = candidate_failure
                && rrsig_relevant
            {
                first_failure.get_or_insert((reason, ede_code));
            }
            return SignatureCheck::rejected(first_failure, candidate_policy_rejected);
        }

        let denial_evidence = !is_helper
            && matches!(type_covered, RecordType::NSEC | RecordType::NSEC3)
            && lower_signer.zone_of(qname_lower)
            && response
                .answers
                .iter()
                .chain(response.authorities.iter())
                .any(|record| record.name == *rrsig_owner && record.record_type() == type_covered);
        let mark_signed_zone =
            (rrsig_relevant || denial_evidence).then(|| (lower_signer.clone(), expiration));
        SignatureCheck {
            accepted: true,
            first_failure: None,
            policy_violation: false,
            trusted: Some(TrustedSignature {
                owner: LowerName::from(rrset_owner),
                covered: type_covered,
                signer: lower_signer.clone(),
                signer_name: signer_name.clone(),
            }),
            signer_covers_qname: lower_signer.zone_of(qname_lower),
            mark_signed_zone,
        }
    }

    /// Candidate keys for one RRSIG: validated cache first, then same-owner
    /// response keys with the same tag/algorithm, trusted keys first.
    #[allow(clippy::too_many_arguments)]
    fn signature_candidates(
        &self,
        response_dnskeys: &[(Name, DNSKEY)],
        signer_name: &Name,
        key_tag: u16,
        algorithm: Algorithm,
        lower_signer: &LowerName,
        key_set: &KeySetBuild,
        anchors: &TrustAnchors,
        now: u32,
    ) -> Vec<DNSKEY> {
        let cached_key = self
            .key_cache
            .get(lower_signer, key_tag, now)
            .filter(|key| key.algorithm() == algorithm);
        self.metrics.record_key_cache(cached_key.is_some());
        let mut candidates: Vec<DNSKEY> = Vec::new();
        if let Some(key) = cached_key {
            candidates.push(key);
        }
        for (key_owner, dnskey) in response_dnskeys {
            if key_owner == signer_name
                && dnskey.algorithm() == algorithm
                && dnskey.calculate_key_tag().ok() == Some(key_tag)
            {
                candidates.push(dnskey.clone());
            }
        }
        candidates.sort_by_key(|dnskey| {
            let trusted = anchors.contains(dnskey.public_key())
                || anchors.contains_with_name(dnskey.public_key(), lower_signer)
                || key_set
                    .validated
                    .contains(&(lower_signer.clone(), dnskey_fingerprint(dnskey)))
                || self
                    .key_cache
                    .is_validated(lower_signer, key_tag, dnskey, now);
            !trusted
        });
        candidates.truncate(MAX_CANDIDATE_KEYS_PER_RRSIG);
        candidates
    }

    /// Phase 3-4: negative-proof decisions and final fail-closed classification.
    #[allow(clippy::too_many_arguments)]
    fn finalize_validation(
        &self,
        response: &mut Message,
        upstream: Option<&str>,
        qname: &Name,
        qtype: RecordType,
        evidence: SignatureEvidence,
        allow_unchecked_signatures: bool,
        now: u32,
    ) -> ValidationOutcome {
        let SignatureEvidence {
            key_set,
            relevant_keys,
            has_relevant_rrsig,
            has_trusted_sig,
            trusted_covered,
            trusted_sigs,
            trusted_signer_covers_qname,
            first_failure,
            policy_violation,
            rrsigs,
            helper_rrsigs,
        } = evidence;
        let relevant = &relevant_keys;
        let present_relevant: HashSet<(LowerName, RecordType)> = response
            .answers
            .iter()
            .map(|record| (LowerName::from(&record.name), record.record_type()))
            .filter(|key| relevant.contains(key))
            .collect();
        let all_present_signed = !present_relevant.is_empty()
            && present_relevant
                .iter()
                .all(|key| trusted_covered.contains(key));
        let all_section_rrsets_signed = response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .filter(|record| record.record_type() != RecordType::RRSIG)
            .all(|record| {
                trusted_covered.contains(&(LowerName::from(&record.name), record.record_type()))
            });
        let qname_lower = LowerName::from(qname);
        let cname_to_unsigned_zone =
            signed_cname_to_unsigned_target(response, qname, &trusted_covered, &rrsigs)
                .is_some_and(|target| self.insecure_zone_covers(&LowerName::from(&target), now));
        let negative = is_negative_response(response, qname, qtype);
        let negative_name = if negative {
            negative_answer_name(response, qname)
        } else {
            qname.clone()
        };
        let negative_lower = LowerName::from(&negative_name);
        let has_denial_rrsig = negative
            && rrsigs
                .iter()
                .zip(helper_rrsigs.iter())
                .any(|((owner, sig), is_helper)| {
                    !is_helper
                        && matches!(
                            sig.input().type_covered,
                            RecordType::NSEC | RecordType::NSEC3
                        )
                        && LowerName::from(&sig.input().signer_name).zone_of(&negative_lower)
                        && response
                            .answers
                            .iter()
                            .chain(response.authorities.iter())
                            .any(|record| {
                                record.name == *owner
                                    && record.record_type() == sig.input().type_covered
                            })
                });

        if negative
            && let Some(outcome) = self.finalize_negative(
                response,
                upstream,
                &negative_name,
                &qname_lower,
                &negative_lower,
                qtype,
                &trusted_sigs,
                all_present_signed,
                present_relevant.is_empty(),
                all_section_rrsets_signed,
                has_denial_rrsig,
                allow_unchecked_signatures,
                has_trusted_sig,
                first_failure,
                policy_violation,
                cname_to_unsigned_zone,
                &key_set,
                now,
            )
        {
            return outcome;
        } else if !negative && all_present_signed {
            if !all_section_rrsets_signed {
                debug!(
                    "DNSSEC answer RRsets are authenticated but the response carries unauthenticated RRsets; clearing AD"
                );
                response.metadata.authentic_data = false;
                let outcome = ValidationOutcome::Insecure;
                self.metrics.record_validation(&outcome);
                return outcome;
            }
            return self.secure_outcome(response, now);
        }

        self.finalize_unproven(
            response,
            upstream,
            qname,
            &qname_lower,
            &negative_lower,
            negative,
            all_present_signed,
            &key_set,
            first_failure,
            policy_violation,
            cname_to_unsigned_zone,
            has_relevant_rrsig,
            has_denial_rrsig,
            has_trusted_sig,
            trusted_signer_covers_qname,
            allow_unchecked_signatures,
            now,
        )
    }

    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    fn finalize_negative(
        &self,
        response: &mut Message,
        upstream: Option<&str>,
        negative_name: &Name,
        qname_lower: &LowerName,
        negative_lower: &LowerName,
        qtype: RecordType,
        trusted_sigs: &[TrustedSignature],
        all_present_signed: bool,
        present_relevant_empty: bool,
        all_section_rrsets_signed: bool,
        has_denial_rrsig: bool,
        allow_unchecked_signatures: bool,
        has_trusted_sig: bool,
        first_failure: Option<(&'static str, u16)>,
        policy_violation: bool,
        cname_to_unsigned_zone: bool,
        key_set: &KeySetBuild,
        now: u32,
    ) -> Option<ValidationOutcome> {
        let denial = if trusted_sigs.is_empty() {
            DenialResult::Incomplete
        } else {
            evaluate_denial(response, negative_name, negative_lower, qtype, trusted_sigs)
        };
        match denial {
            DenialResult::Secure if all_present_signed || present_relevant_empty => {
                if !all_section_rrsets_signed {
                    debug!(
                        "DNSSEC denial proof is valid but the response carries unauthenticated RRsets; clearing AD"
                    );
                    response.metadata.authentic_data = false;
                    let outcome = ValidationOutcome::Insecure;
                    self.metrics.record_validation(&outcome);
                    return Some(outcome);
                }
                Some(self.secure_outcome(response, now))
            }
            DenialResult::Secure => Some(self.handle_bogus(
                response,
                upstream,
                "CNAME chain is not signed by a validated zone key",
                EDE_DNSSEC_BOGUS,
            )),
            DenialResult::OptOut => {
                // RFC 5155: only an explicit opt-out downgrades to insecure;
                // every other incomplete proof is bogus.
                debug!("NSEC3 opt-out proof found; negative response treated as insecure");
                response.metadata.authentic_data = false;
                let outcome = ValidationOutcome::Insecure;
                self.metrics.record_validation(&outcome);
                Some(outcome)
            }
            DenialResult::Incomplete => {
                if cname_to_unsigned_zone
                    && key_set.forged.is_empty()
                    && first_failure.is_none()
                    && !policy_violation
                {
                    response.metadata.authentic_data = false;
                    let outcome = ValidationOutcome::Insecure;
                    self.metrics.record_validation(&outcome);
                    return Some(outcome);
                }
                let would_be_secure = has_trusted_sig
                    || all_present_signed
                    || self.signed_zone_contains(qname_lower, now);
                if would_be_secure {
                    if allow_unchecked_signatures && has_denial_rrsig {
                        // Deferrable only on the pre-fetch pass; the strict
                        // post-fetch pass keeps the fail-closed Bogus.
                        None
                    } else {
                        Some(self.handle_bogus(
                            response,
                            upstream,
                            "Negative response lacks a valid NSEC/NSEC3 denial proof",
                            EDE_DNSSEC_BOGUS,
                        ))
                    }
                } else {
                    None
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    fn finalize_unproven(
        &self,
        response: &mut Message,
        upstream: Option<&str>,
        qname: &Name,
        qname_lower: &LowerName,
        negative_lower: &LowerName,
        negative: bool,
        all_present_signed: bool,
        key_set: &KeySetBuild,
        first_failure: Option<(&'static str, u16)>,
        policy_violation: bool,
        cname_to_unsigned_zone: bool,
        has_relevant_rrsig: bool,
        has_denial_rrsig: bool,
        has_trusted_sig: bool,
        trusted_signer_covers_qname: bool,
        allow_unchecked_signatures: bool,
        now: u32,
    ) -> ValidationOutcome {
        if !key_set.forged.is_empty() {
            return self.handle_bogus(
                response,
                upstream,
                "Cross-zone or forged DS record signed by a validated key",
                EDE_DNSSEC_BOGUS,
            );
        }
        if !key_set.unsupported.is_empty() && !all_present_signed {
            // RFC 6840 §5.2: only unsupported digests/algorithms at the
            // delegation means the zone is unsigned, not bogus.
            debug!(
                upstream,
                "DNSSEC: only unsupported DS algorithms at the delegation; treating as unsigned"
            );
            response.metadata.authentic_data = false;
            let outcome = ValidationOutcome::Insecure;
            self.metrics.record_validation(&outcome);
            return outcome;
        }
        if let Some((reason, ede_code)) = first_failure {
            return self.handle_bogus(response, upstream, reason, ede_code);
        }
        if policy_violation {
            return self.handle_bogus(
                response,
                upstream,
                "DNSSEC algorithm not allowed by policy",
                EDE_DNSSEC_BOGUS,
            );
        }
        if cname_to_unsigned_zone {
            response.metadata.authentic_data = false;
            let outcome = ValidationOutcome::Insecure;
            self.metrics.record_validation(&outcome);
            return outcome;
        }
        let signed_zone_evidence = (self.signed_zone_contains(qname_lower, now)
            && !self.insecure_zone_covers(qname_lower, now))
            || trusted_signer_covers_qname;
        let unchecked_rrsig_present = has_relevant_rrsig || has_denial_rrsig;
        if signed_zone_evidence && (!unchecked_rrsig_present || !allow_unchecked_signatures) {
            return self.handle_bogus(
                response,
                upstream,
                "Missing RRSIG for zone previously proven signed",
                EDE_DNSSEC_BOGUS,
            );
        }
        if has_trusted_sig && !has_relevant_rrsig {
            return self.handle_bogus(
                response,
                upstream,
                "No valid RRSIG covers the answer RRset",
                EDE_DNSSEC_BOGUS,
            );
        }
        let signed_chain_evidence = self.signed_chain_contains(response, qname, now)
            || (negative
                && self.signed_zone_contains(negative_lower, now)
                && !self.insecure_zone_covers(negative_lower, now));
        if !has_relevant_rrsig && !has_denial_rrsig && !has_trusted_sig && !signed_chain_evidence {
            response.metadata.authentic_data = false;
            let outcome = ValidationOutcome::Insecure;
            self.metrics.record_validation(&outcome);
            return outcome;
        }

        // RRSIGs were present and valid, but could not link to a trust anchor.
        // Leave the result provisional; the entry point records it once.
        response.metadata.authentic_data = false;
        ValidationOutcome::Indeterminate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The negative-proof "would be secure" guard is scoped to the original
    /// query name, not the final CNAME target: a proven-signed qname with an
    /// incomplete denial proof must stay Bogus even when the target lies in a
    /// different (insecure) zone.
    #[test]
    fn negative_proof_uses_qname_for_signed_zone_guard() {
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        let now = 1_000u32;
        let qname = Name::from_str("www.signed.example.").expect("qname");
        let target = Name::from_str("missing.unsigned.example.").expect("target");
        let qname_lower = LowerName::from(&qname);
        let target_lower = LowerName::from(&target);
        validator.mark_signed_zone(
            &LowerName::from_str("signed.example.").expect("signed zone"),
            now + 300,
            now,
        );
        validator.mark_insecure_zone(
            &LowerName::from_str("unsigned.example.").expect("unsigned zone"),
            now + 300,
            now,
        );
        let mut response = Message::new(
            7,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );

        let outcome = validator.finalize_negative(
            &mut response,
            Some("probe"),
            &target,
            &qname_lower,
            &target_lower,
            RecordType::A,
            &[],
            false,
            false,
            false,
            false,
            false,
            false,
            None,
            false,
            false,
            &KeySetBuild::default(),
            now,
        );

        assert!(
            matches!(outcome, Some(ValidationOutcome::Bogus { .. })),
            "a signed qname with an incomplete denial proof must be Bogus; got {outcome:?} (qname_lower={qname_lower:?})"
        );
    }
}
