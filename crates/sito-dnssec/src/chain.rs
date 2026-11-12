//! Delegation probing, DS/DNSKEY chain walking, and zone evidence.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Fetches the DNSKEY/DS chain for `zone`, appending records to `response`.
///
/// Returns `Some(())` when at least one lookup succeeded. The walk stops at an
/// anchored DNSKEY, at an unsigned delegation (no DS), after the root DNSKEY
/// has been fetched and matched, when the zone was already visited, or when the
/// budget is exhausted.
pub(super) async fn fetch_zone_chain(
    anchors: &TrustAnchors,
    fetcher: &dyn DnssecKeyFetcher,
    zone: &Name,
    budget: &mut u8,
    visited: &mut HashSet<LowerName>,
    response: &mut Message,
) -> Option<()> {
    let mut current = zone.clone();
    let mut depth = 0u8;
    let mut fetched_any = false;

    loop {
        if *budget == 0 || depth > 12 {
            break;
        }
        if !visited.insert(LowerName::from(&current)) {
            break;
        }

        *budget -= 1;
        let Ok(dnskey_message) = fetcher.query(&current, RecordType::DNSKEY).await else {
            break;
        };
        append_dnssec_records(response, &dnskey_message);
        fetched_any = true;
        if fetched_has_anchor(&dnskey_message, &current, anchors) {
            return Some(());
        }

        // The root DNSKEY has been fetched; there is no parent DS to walk to.
        if current.is_root() {
            break;
        }

        if *budget == 0 {
            break;
        }
        *budget -= 1;
        let Ok(ds_message) = fetcher.query(&current, RecordType::DS).await else {
            break;
        };
        append_dnssec_records(response, &ds_message);
        if !fetched_has_ds(&ds_message, &current) {
            // Unsigned delegation: nothing further to walk.
            return Some(());
        }

        let parent = current.base_name();
        if parent == current {
            break;
        }
        current = parent;
        depth += 1;
    }

    fetched_any.then_some(())
}

/// Delegation status inferred from a DS response.
pub(super) enum DsStatus {
    /// The DS RRset is present and authenticated: the child zone is signed.
    /// The value is the DS RRset TTL used as a caching hint.
    Signed(u32),
    /// An authenticated denial proves the delegation has no DS (unsigned),
    /// with the denial RR's TTL as the caching hint.
    Unsigned(u32),
    /// The name is inside the parent zone (no delegation cut here).
    InZone,
    /// No conclusion could be drawn.
    Unknown,
}

/// Determines whether `cut` is a signed delegation, an unsigned delegation or
/// part of the parent zone, using only records authenticated by `parent_keys`.
pub(super) fn ds_response_status(
    response: &Message,
    cut: &Name,
    parent_zone: &LowerName,
    parent_keys: &[DNSKEY],
    now: u32,
) -> DsStatus {
    if !parent_zone.zone_of(&LowerName::from(cut)) {
        return DsStatus::Unknown;
    }
    // Bound the work one fetched DS/denial response can cause.
    let mut budget = VerifyBudget::new();

    // A DS RRset at the cut: only meaningful when signed by the parent.
    let has_ds = response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .any(|record| {
            record.name == *cut && matches!(record.data, RData::DNSSEC(DNSSECRData::DS(_)))
        });
    if has_ds {
        if !has_valid_rrsig_for(
            response,
            cut,
            RecordType::DS,
            parent_zone,
            parent_keys,
            now,
            &mut budget,
        ) {
            return DsStatus::Unknown;
        }
        let ttl = response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .filter(|record| {
                record.name == *cut && matches!(record.data, RData::DNSSEC(DNSSECRData::DS(_)))
            })
            .map(|record| record.ttl)
            .min()
            .unwrap_or(300);
        return DsStatus::Signed(ttl.max(1));
    }

    // NSEC denial at the cut.
    let nsec_records: Vec<&Record> = response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .filter(|record| {
            record.name == *cut && matches!(record.data, RData::DNSSEC(DNSSECRData::NSEC(_)))
        })
        .collect();
    if !nsec_records.is_empty() {
        if !has_valid_rrsig_for(
            response,
            cut,
            RecordType::NSEC,
            parent_zone,
            parent_keys,
            now,
            &mut budget,
        ) {
            return DsStatus::Unknown;
        }
        for record in nsec_records {
            if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = &record.data {
                let types = nsec.type_set();
                if types.contains(RecordType::DS) {
                    return DsStatus::Signed(record.ttl.max(1));
                }
                if types.contains(RecordType::NS) && !types.contains(RecordType::SOA) {
                    return DsStatus::Unsigned(record.ttl.max(1));
                }
            }
        }
        return DsStatus::InZone;
    }

    // NXDOMAIN / wildcard denial at the cut: an authenticated NSEC whose range
    // covers the cut proves the name does not exist in the parent zone, so it
    // is not a delegation cut. This is what makes a stripped NXDOMAIN (or a
    // wildcard-synthesized answer) directly in the anchor zone fail closed.
    for record in response.answers.iter().chain(response.authorities.iter()) {
        if !parent_zone.zone_of(&LowerName::from(&record.name)) {
            continue;
        }
        let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = &record.data else {
            continue;
        };
        // A parent-side delegation NSEC does not prove absence below the cut.
        let types = nsec.type_set();
        if types.contains(RecordType::NS) && !types.contains(RecordType::SOA) {
            continue;
        }
        let nsec_record = NsecRecord {
            owner: &record.name,
            rdata: nsec,
        };
        if nsec::covers(&nsec_record, cut)
            && has_valid_rrsig_for(
                response,
                &record.name,
                RecordType::NSEC,
                parent_zone,
                parent_keys,
                now,
                &mut budget,
            )
        {
            return DsStatus::InZone;
        }
    }

    // NSEC3 denial at the cut.
    let nsec3_records: Vec<&Record> = response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .filter(|record| {
            parent_zone.zone_of(&LowerName::from(&record.name))
                && matches!(record.data, RData::DNSSEC(DNSSECRData::NSEC3(_)))
        })
        .collect();
    if !nsec3_records.is_empty() {
        // Exact match (the owner is a hash, so the zone is the parent zone).
        let exact = nsec3_records.iter().find(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) => nsec3::matches(
                &nsec3::Nsec3Record {
                    owner: &record.name,
                    rdata: nsec3,
                },
                cut,
            ),
            _ => false,
        });
        if let Some(record) = exact {
            let record_name = record.name.clone();
            if !has_valid_rrsig_for(
                response,
                &record_name,
                RecordType::NSEC3,
                parent_zone,
                parent_keys,
                now,
                &mut budget,
            ) {
                return DsStatus::Unknown;
            }
            if let RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) = &record.data {
                let types = nsec3.type_set();
                if types.contains(RecordType::DS) {
                    return DsStatus::Signed(record.ttl.max(1));
                }
                if types.contains(RecordType::NS) && !types.contains(RecordType::SOA) {
                    return DsStatus::Unsigned(record.ttl.max(1));
                }
            }
            return DsStatus::InZone;
        }

        // Opt-out: an unsigned delegation may exist below the covered name.
        let records: Vec<nsec3::Nsec3Record<'_>> = nsec3_records
            .iter()
            .filter_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) => Some(nsec3::Nsec3Record {
                    owner: &record.name,
                    rdata: nsec3,
                }),
                _ => None,
            })
            .collect();
        if nsec3::evaluate_nsec3_denial(
            &records,
            cut,
            RecordType::DS,
            false,
            &Name::from(parent_zone.clone()),
        ) == nsec3::Nsec3Denial::OptOut
        {
            for record in &nsec3_records {
                if let RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) = &record.data
                    && nsec3::covers(
                        &nsec3::Nsec3Record {
                            owner: &record.name,
                            rdata: nsec3,
                        },
                        cut,
                    )
                    && nsec3.opt_out()
                    && has_valid_rrsig_for(
                        response,
                        &record.name,
                        RecordType::NSEC3,
                        parent_zone,
                        parent_keys,
                        now,
                        &mut budget,
                    )
                {
                    return DsStatus::Unsigned(record.ttl.max(1));
                }
            }
        }

        // NXDOMAIN / wildcard denial at the cut (RFC 5155 §8.4/§8.7). A
        // complete non-opt-out proof means the cut is inside the parent zone.
        // An opt-out span may hide an unsigned delegation, so it stays
        // Insecure rather than being declared signed.
        //
        // Only NSEC3 records with an RRSIG that verifies with a parent-zone key
        // may contribute to the proof: the fetcher returns raw upstream data,
        // so an unsigned/forged covering record must not be able to fabricate
        // `InZone` (and thereby persist a Signed zone).
        let authenticated_nsec3: Vec<&Record> = nsec3_records
            .iter()
            .copied()
            .filter(|record| {
                has_valid_rrsig_for(
                    response,
                    &record.name,
                    RecordType::NSEC3,
                    parent_zone,
                    parent_keys,
                    now,
                    &mut budget,
                )
            })
            .collect();
        let authenticated_records: Vec<nsec3::Nsec3Record<'_>> = authenticated_nsec3
            .iter()
            .filter_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) => Some(nsec3::Nsec3Record {
                    owner: &record.name,
                    rdata: nsec3,
                }),
                _ => None,
            })
            .collect();
        match nsec3::evaluate_nsec3_denial(
            &authenticated_records,
            cut,
            RecordType::DS,
            true,
            &Name::from(parent_zone.clone()),
        ) {
            Nsec3Denial::Secure => return DsStatus::InZone,
            Nsec3Denial::OptOut => {
                for record in &authenticated_nsec3 {
                    if let RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) = &record.data
                        && nsec3::covers(
                            &nsec3::Nsec3Record {
                                owner: &record.name,
                                rdata: nsec3,
                            },
                            cut,
                        )
                        && nsec3.opt_out()
                    {
                        return DsStatus::Unsigned(record.ttl.max(1));
                    }
                }
            }
            Nsec3Denial::Incomplete => {}
        }
        return DsStatus::Unknown;
    }

    DsStatus::Unknown
}

/// Result of the DS-based delegation probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DelegationProof {
    /// Authenticated DS denial: the delegation is legitimately unsigned.
    Unsigned,
    /// The data must be signed (a cut is signed or there is no delegation).
    ShouldBeSigned,
    /// The probe could not establish either.
    Unknown,
}

/// Candidate delegation cuts between `zone` (exclusive) and `name` (inclusive),
/// shallowest first. Returns `truncated = true` when the path is deeper than
/// [`MAX_CHAIN_CUTS`]; callers must fail closed in that case instead of using
/// the anchor keys against a cut they never reached.
pub(super) fn delegation_cuts(name: &LowerName, zone: &LowerName) -> (Vec<LowerName>, bool) {
    if zone == name || !zone.zone_of(name) {
        return (Vec::new(), false);
    }
    let mut cuts = Vec::new();
    let mut current = name.clone();
    while current != *zone {
        cuts.push(current.clone());
        let base = current.base_name();
        if base == current {
            break;
        }
        current = base;
    }
    cuts.reverse();
    let truncated = cuts.len() > MAX_CHAIN_CUTS;
    cuts.truncate(MAX_CHAIN_CUTS);
    (cuts, truncated)
}

/// Result of consulting the cache/probe for one name in a CNAME chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnsignedProbe {
    /// Cached or in-memory evidence already answered the question; no fetch.
    Covered,
    /// A probe ran and established an authenticated status.
    Probed,
    /// A probe ran but could not establish a status (network/unknown).
    Failed,
}

/// Result of the DS/DNSKEY trust-extension walk.
#[derive(Default)]
pub(super) struct KeySetBuild {
    /// Keys linked to a trust anchor (directly, via DS, or via a validated
    /// DNSKEY RRset), identified by full public-key bytes (a key tag is not a
    /// unique key identity).
    pub(super) validated: HashSet<(LowerName, Vec<u8>)>,
    /// Zones whose only DS records use an unsupported digest or algorithm:
    /// RFC 6840 §5.2 treats them as unsigned delegations instead of Bogus.
    pub(super) unsupported: HashSet<LowerName>,
    /// Zones whose DS RRset was validly signed by a validated parent but whose
    /// hierarchy or digest did not match (cross-zone or forged DS).
    pub(super) forged: HashSet<LowerName>,
    /// First RRSIG validity-window failure encountered while walking DS/DNSKEY
    /// trust links from a validated parent/signer.
    pub(super) time_failure: Option<(&'static str, u16)>,
}

/// Aggregated state for one DS owner during the trust-extension walk.
#[derive(Default)]
pub(super) struct DsLink {
    pub(super) signed: bool,
    pub(super) hierarchy_bad: bool,
    /// A DS record used an unsupported digest or algorithm.
    pub(super) policy_bad: bool,
    /// At least one DS record used a supported digest and algorithm.
    pub(super) supported_present: bool,
    pub(super) child_present: bool,
    pub(super) matched: bool,
}

impl DnssecValidator {
    /// Probes the delegation status of `name` using authenticated DS responses.
    ///
    /// The walk starts from the closest zone with signed evidence or, on a cold
    /// start, from the closest configured trust anchor: the anchor DNSKEY is
    /// fetched, its self-signature is verified against the anchor, and the
    /// DS/DNSKEY links are followed shallowest-first. An authenticated DS
    /// proves the cut is signed (Bogus if the response carried no RRSIGs) and
    /// an authenticated DS denial proves the delegation is unsigned (Insecure).
    ///
    /// Only authenticated results are recorded. An `Unknown` result (network
    /// failure, missing records, unsupported input) is never written to the
    /// persistent cache.
    pub(super) async fn probe_delegation(
        &self,
        name: &LowerName,
        fetcher: &dyn DnssecKeyFetcher,
        now: u32,
    ) -> DelegationProof {
        let cached_start = self.chain_cache.closest_signed(name, now);
        let memory_start = self.closest_signed_zone(name, now);
        let start = match (memory_start, cached_start) {
            (Some(memory), Some((cached, expiry))) => {
                if cached.num_labels() > memory.num_labels() {
                    self.signed_zones.insert(cached.clone(), expiry);
                    Some(cached)
                } else {
                    Some(memory)
                }
            }
            (Some(memory), None) => Some(memory),
            (None, Some((cached, expiry))) => {
                self.signed_zones.insert(cached.clone(), expiry);
                Some(cached)
            }
            (None, None) => None,
        };

        let mut start_is_signed = false;
        let (mut zone, mut parent_keys) = if let Some(start) = start {
            start_is_signed = true;
            if start == *name {
                // The queried name itself is a zone proven signed: a response
                // without signatures from it is already a downgrade.
                return DelegationProof::ShouldBeSigned;
            }
            match self.keys_for_zone(&start, fetcher, now).await {
                Some((actual_zone, keys)) => (actual_zone, keys),
                // The zone is known to be signed but its keys cannot be
                // re-established (offline restart, expired key cache). Fail
                // closed rather than downgrading.
                None => return DelegationProof::ShouldBeSigned,
            }
        } else {
            let Some(anchor) = self.closest_anchor_zone(name) else {
                return DelegationProof::Unknown;
            };
            match self.seed_anchor_keys(&anchor, fetcher, now).await {
                Some((keys, _expiry)) => (anchor, keys),
                None => return DelegationProof::Unknown,
            }
        };

        let (cuts, truncated) = delegation_cuts(name, &zone);
        if cuts.is_empty() {
            // `name` is the signed start/anchor zone itself.
            self.mark_signed_zone(name, now.saturating_add(CHAIN_STATUS_TTL_MAX), now);
            return DelegationProof::ShouldBeSigned;
        }

        let mut saw_signed = false;
        for cut in cuts {
            if let Some((unsigned_zone, expiry)) = self.cached_unsigned_zone(&cut, now) {
                self.signed_zones.remove(&unsigned_zone);
                self.insecure_zones.insert(unsigned_zone, expiry);
                return DelegationProof::Unsigned;
            }
            if self.insecure_zone_covers(&cut, now) {
                return DelegationProof::Unsigned;
            }

            // A previously authenticated signed cut needs no DS refetch. Its
            // DNSKEYs are still required to authenticate deeper cuts.
            if let Some(entry) = self.chain_cache.get(&cut, now)
                && entry.status == ZoneStatus::Signed
            {
                saw_signed = true;
                self.signed_zones.insert(cut.clone(), entry.expires_at);
                if cut == *name {
                    return DelegationProof::ShouldBeSigned;
                }
                match self.keys_for_zone(&cut, fetcher, now).await {
                    Some((actual_zone, keys)) if actual_zone == cut => {
                        zone = actual_zone;
                        parent_keys = keys;
                    }
                    _ => return DelegationProof::ShouldBeSigned,
                }
                continue;
            }

            let cut_name = Name::from(cut.clone());
            let Ok(ds_response) = fetcher.query(&cut_name, RecordType::DS).await else {
                return if saw_signed || start_is_signed {
                    DelegationProof::ShouldBeSigned
                } else {
                    DelegationProof::Unknown
                };
            };
            match ds_response_status(&ds_response, &cut_name, &zone, &parent_keys, now) {
                DsStatus::Signed(ttl) => {
                    let expiry = now.saturating_add(ttl.clamp(1, CHAIN_STATUS_TTL_MAX));
                    self.mark_signed_zone(&cut, expiry, now);
                    saw_signed = true;
                    if cut == *name {
                        return DelegationProof::ShouldBeSigned;
                    }
                    // DS authenticates the child DNSKEY, which in turn is
                    // needed to authenticate deeper DS answers. A missing
                    // child key must not downgrade the authenticated DS.
                    match self
                        .validate_child_dnskeys(&cut, &ds_response, fetcher, now)
                        .await
                    {
                        Some(keys) => {
                            zone = cut;
                            parent_keys = keys;
                        }
                        None => return DelegationProof::ShouldBeSigned,
                    }
                }
                DsStatus::Unsigned(ttl) => {
                    let expiry = now.saturating_add(ttl.clamp(1, CHAIN_STATUS_TTL_MAX));
                    self.mark_insecure_zone(&cut, expiry, now);
                    debug!(
                        zone = %cut,
                        "Authenticated DS denial proves an unsigned delegation; AD is cleared"
                    );
                    return DelegationProof::Unsigned;
                }
                DsStatus::InZone => {}
                DsStatus::Unknown => {
                    return if saw_signed || start_is_signed {
                        DelegationProof::ShouldBeSigned
                    } else {
                        DelegationProof::Unknown
                    };
                }
            }
        }

        // The delegation path was deeper than the probe budget. Every walk
        // step was authenticated, but the remaining labels were not, so fail
        // closed for this query without persisting an unauthenticated status.
        if truncated {
            self.signed_zones
                .insert(name.clone(), now.saturating_add(CHAIN_STATUS_TTL_MAX));
            return DelegationProof::ShouldBeSigned;
        }

        // Every cut was authenticated as signed or inside the signed parent,
        // so `name` was proven to require signatures. Cache that decision for
        // the queried name as well: a repeated stripped response must be Bogus
        // without re-walking the chain, and the status survives a restart.
        self.mark_signed_zone(name, now.saturating_add(CHAIN_STATUS_TTL_MAX), now);
        DelegationProof::ShouldBeSigned
    }

    /// The closest configured trust-anchor zone covering `name`.
    pub(super) fn closest_anchor_zone(&self, name: &LowerName) -> Option<LowerName> {
        let anchors = self.trust_anchors.load();
        let mut best = None;
        if !anchors.is_empty() {
            let root = LowerName::from(Name::root());
            if root.zone_of(name) {
                best = Some(root);
            }
        }
        for entry in &self.anchor_zones {
            if entry.key().zone_of(name)
                && best
                    .as_ref()
                    .is_none_or(|zone| entry.key().num_labels() > zone.num_labels())
            {
                best = Some(entry.key().clone());
            }
        }
        best
    }

    /// Fetches and validates the DNSKEY RRset at a configured trust anchor.
    ///
    /// Returns the policy-acceptable keys and the earliest expiry. The DNSKEY
    /// RRset must carry a self-signature that verifies with an anchored key;
    /// otherwise nothing is trusted.
    pub(super) async fn seed_anchor_keys(
        &self,
        zone: &LowerName,
        fetcher: &dyn DnssecKeyFetcher,
        now: u32,
    ) -> Option<(Vec<DNSKEY>, u32)> {
        let zone_name = Name::from(zone.clone());
        let message = fetcher.query(&zone_name, RecordType::DNSKEY).await.ok()?;
        let anchors = self.trust_anchors.load();
        let keys: Vec<DNSKEY> = message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .chain(message.additionals.iter())
            .filter(|record| record.name == zone_name)
            .filter_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::DNSKEY(key)) if dnskey_policy_ok(key) => {
                    Some(key.clone())
                }
                _ => None,
            })
            .take(MAX_DNSKEYS)
            .collect();
        let anchored: Vec<DNSKEY> = keys
            .iter()
            .filter(|key| {
                anchors.contains(key.public_key())
                    || anchors.contains_with_name(key.public_key(), zone)
            })
            .cloned()
            .collect();
        if anchored.is_empty()
            || !has_valid_rrsig_for(
                &message,
                &zone_name,
                RecordType::DNSKEY,
                zone,
                &anchored,
                now,
                &mut VerifyBudget::new(),
            )
        {
            return None;
        }

        let ttl = message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .chain(message.additionals.iter())
            .filter(|record| {
                record.name == zone_name
                    && matches!(record.data, RData::DNSSEC(DNSSECRData::DNSKEY(_)))
            })
            .map(|record| record.ttl)
            .min()
            .unwrap_or(300);
        let mut expiry = now.saturating_add(ttl.max(1));
        for record in message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .chain(message.additionals.iter())
        {
            if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data
                && record.name == zone_name
                && rrsig.input().type_covered == RecordType::DNSKEY
                && LowerName::from(&rrsig.input().signer_name) == *zone
                && rrsig_time_ok(rrsig, now)
            {
                expiry = expiry.min(rrsig.input().sig_expiration.get());
            }
        }

        for key in &keys {
            if let Ok(tag) = key.calculate_key_tag() {
                self.key_cache.insert_validated_with_now(
                    zone.clone(),
                    tag,
                    key.clone(),
                    expiry,
                    now,
                );
            }
        }
        Some((keys, expiry))
    }

    /// Obtains validated DNSKEYs for `target`, walking from the closest anchor
    /// when the in-memory key cache is cold.
    ///
    /// Returns the zone the keys actually belong to. If `target` is not itself
    /// a delegation, that is the closest signed ancestor.
    pub(super) async fn keys_for_zone(
        &self,
        target: &LowerName,
        fetcher: &dyn DnssecKeyFetcher,
        now: u32,
    ) -> Option<(LowerName, Vec<DNSKEY>)> {
        let cached = self.key_cache.validated_keys(target, now);
        if !cached.is_empty() {
            return Some((target.clone(), cached));
        }

        let anchor = self.closest_anchor_zone(target)?;
        let (mut keys, _) = self.seed_anchor_keys(&anchor, fetcher, now).await?;
        let mut zone = anchor;
        if zone == *target {
            return Some((zone, keys));
        }

        let (cuts, truncated) = delegation_cuts(target, &zone);
        if truncated {
            // Do not return keys for a zone we never reached.
            return None;
        }
        for cut in cuts {
            let cut_name = Name::from(cut.clone());
            let Ok(ds_response) = fetcher.query(&cut_name, RecordType::DS).await else {
                return None;
            };
            match ds_response_status(&ds_response, &cut_name, &zone, &keys, now) {
                DsStatus::Signed(_) => {
                    keys = self
                        .validate_child_dnskeys(&cut, &ds_response, fetcher, now)
                        .await?;
                    zone = cut;
                }
                DsStatus::InZone => {}
                DsStatus::Unsigned(_) | DsStatus::Unknown => return None,
            }
        }
        Some((zone, keys))
    }

    /// Fetches the DNSKEY RRset for a signed cut and validates it against the
    /// authenticated DS records, then trusts the whole (self-signed) RRset.
    pub(super) async fn validate_child_dnskeys(
        &self,
        cut: &LowerName,
        ds_message: &Message,
        fetcher: &dyn DnssecKeyFetcher,
        now: u32,
    ) -> Option<Vec<DNSKEY>> {
        let cut_name = Name::from(cut.clone());
        let ds_records: Vec<DS> = ds_message
            .answers
            .iter()
            .chain(ds_message.authorities.iter())
            .chain(ds_message.additionals.iter())
            .filter(|record| record.name == cut_name)
            .filter_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::DS(ds)) if allowed_ds_digest(ds.digest_type()) => {
                    Some(ds.clone())
                }
                _ => None,
            })
            .take(MAX_DS_RECORDS)
            .collect();
        if ds_records.is_empty() {
            return None;
        }

        let message = fetcher.query(&cut_name, RecordType::DNSKEY).await.ok()?;
        let keys: Vec<DNSKEY> = message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .chain(message.additionals.iter())
            .filter(|record| record.name == cut_name)
            .filter_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::DNSKEY(key))
                    if dnskey_policy_ok(key) && allowed_dnskey_algorithm(key.algorithm()) =>
                {
                    Some(key.clone())
                }
                _ => None,
            })
            .take(MAX_DNSKEYS)
            .collect();
        let matched: Vec<DNSKEY> = keys
            .iter()
            .filter(|key| {
                ds_records.iter().any(|ds| {
                    ds.algorithm() == key.algorithm() && ds.covers(&cut_name, key).unwrap_or(false)
                })
            })
            .cloned()
            .collect();
        if matched.is_empty()
            || !has_valid_rrsig_for(
                &message,
                &cut_name,
                RecordType::DNSKEY,
                cut,
                &matched,
                now,
                &mut VerifyBudget::new(),
            )
        {
            return None;
        }

        let ttl = message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .chain(message.additionals.iter())
            .filter(|record| {
                record.name == cut_name
                    && matches!(record.data, RData::DNSSEC(DNSSECRData::DNSKEY(_)))
            })
            .map(|record| record.ttl)
            .min()
            .unwrap_or(300);
        let mut expiry = now.saturating_add(ttl.max(1));
        let ds_ttl = ds_message
            .answers
            .iter()
            .chain(ds_message.authorities.iter())
            .chain(ds_message.additionals.iter())
            .filter(|record| {
                record.name == cut_name && matches!(record.data, RData::DNSSEC(DNSSECRData::DS(_)))
            })
            .map(|record| record.ttl)
            .min()
            .unwrap_or(300);
        expiry = expiry.min(now.saturating_add(ds_ttl.max(1)));
        for record in message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .chain(message.additionals.iter())
        {
            if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data
                && record.name == cut_name
                && rrsig.input().type_covered == RecordType::DNSKEY
                && LowerName::from(&rrsig.input().signer_name) == *cut
                && rrsig_time_ok(rrsig, now)
            {
                expiry = expiry.min(rrsig.input().sig_expiration.get());
            }
        }
        for key in &keys {
            if let Ok(tag) = key.calculate_key_tag() {
                self.key_cache.insert_validated_with_now(
                    cut.clone(),
                    tag,
                    key.clone(),
                    expiry,
                    now,
                );
            }
        }
        Some(keys)
    }

    /// Handles a response with no RRSIGs: mirror a cached status or probe the
    /// delegation. Returns `true` when the probe could not establish a status
    /// (never-proven zone, network failure, or active backoff).
    pub(super) async fn prepare_unsigned_response(
        &self,
        name: &LowerName,
        fetcher: &dyn DnssecKeyFetcher,
        now: u32,
    ) -> UnsignedProbe {
        if let Some(entry) = self.chain_cache.get(name, now) {
            let stale_unsigned =
                entry.status == ZoneStatus::Unsigned && self.anchor_affects_unsigned_zone(name);
            if !stale_unsigned {
                match entry.status {
                    ZoneStatus::Signed => {
                        self.insecure_zones.remove(name);
                        self.signed_zones.insert(name.clone(), entry.expires_at);
                    }
                    ZoneStatus::Unsigned => {
                        self.signed_zones.remove(name);
                        self.insecure_zones.insert(name.clone(), entry.expires_at);
                    }
                }
                return UnsignedProbe::Covered;
            }
        }
        if let Some((zone, expiry)) = self.cached_unsigned_zone(name, now) {
            self.signed_zones.remove(&zone);
            self.insecure_zones.insert(zone, expiry);
            return UnsignedProbe::Covered;
        }
        if self.insecure_zone_covers(name, now) {
            return UnsignedProbe::Covered;
        }
        if self.probe_backoff_active(name, now) {
            return UnsignedProbe::Failed;
        }
        if self.probe_delegation(name, fetcher, now).await == DelegationProof::Unknown {
            self.record_probe_failure(name, now);
            UnsignedProbe::Failed
        } else {
            self.probe_backoff.remove(name);
            UnsignedProbe::Probed
        }
    }

    /// Whether `name` already has cached or in-memory coverage, so consulting
    /// it will not consume the per-response probe budget.
    pub(super) fn unsigned_status_known(&self, name: &LowerName, now: u32) -> bool {
        let exact = self.chain_cache.get(name, now);
        let exact_known = exact.is_some_and(|entry| {
            entry.status == ZoneStatus::Signed || !self.anchor_affects_unsigned_zone(name)
        });
        exact_known
            || self.cached_unsigned_zone(name, now).is_some()
            || self.insecure_zone_covers(name, now)
    }

    pub(super) fn probe_backoff_active(&self, name: &LowerName, now: u32) -> bool {
        if self.probe_backoff.len() > CHAIN_CACHE_MAX_ENTRIES {
            self.probe_backoff.retain(|_, until| *until >= now);
            if self.probe_backoff.len() > CHAIN_CACHE_MAX_ENTRIES {
                self.probe_backoff.clear();
            }
        }
        self.probe_backoff
            .get(name)
            .is_some_and(|until| *until >= now)
    }

    pub(super) fn record_probe_failure(&self, name: &LowerName, now: u32) {
        self.probe_backoff
            .insert(name.clone(), now.saturating_add(PROBE_BACKOFF_SECS));
    }

    /// Converts an inconclusive validation result into the configured policy
    /// outcome: strict mode fails closed with SERVFAIL, `LogOnly` keeps the
    /// response with AD cleared, and disabled validation never gets here.
    pub(super) fn indeterminate_outcome(
        &self,
        response: &mut Message,
        upstream: Option<&str>,
    ) -> ValidationOutcome {
        if self.mode == DnssecMode::Validate {
            return self.handle_bogus(
                response,
                upstream,
                "DNSSEC validation could not be completed",
                EDE_DNSSEC_BOGUS,
            );
        }
        response.metadata.authentic_data = false;
        let outcome = ValidationOutcome::Indeterminate;
        self.metrics.record_validation(&outcome);
        outcome
    }
}
