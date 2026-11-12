//! Trust anchors, anchor caching, and anchor-chain policy.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Unique signer zones referenced by RRSIG records in a message.
pub(super) fn collect_rrsig_signers(response: &Message) -> Vec<Name> {
    let mut seen = HashSet::new();
    let mut signers = Vec::new();
    for record in response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .chain(response.additionals.iter())
    {
        let signer = match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some(&rrsig.input().signer_name),
            RData::DNSSEC(DNSSECRData::SIG(sig)) => Some(&sig.input().signer_name),
            _ => None,
        };
        if let Some(signer) = signer
            && seen.insert(LowerName::from(signer))
        {
            signers.push(signer.clone());
        }
    }
    signers
}

/// Copies DNSSEC-relevant records (DNSKEY/DS/RRSIG/SIG) from a fetched message
/// into the response's additional section for chain validation.
pub(super) fn append_dnssec_records(response: &mut Message, fetched: &Message) {
    for record in fetched
        .answers
        .iter()
        .chain(fetched.authorities.iter())
        .chain(fetched.additionals.iter())
    {
        if matches!(
            record.data,
            RData::DNSSEC(
                DNSSECRData::DNSKEY(_)
                    | DNSSECRData::DS(_)
                    | DNSSECRData::RRSIG(_)
                    | DNSSECRData::SIG(_)
            )
        ) {
            response.additionals.push(record.clone());
        }
    }
}

/// Whether a fetched DNSKEY message contains a key anchored for `zone`.
pub(super) fn fetched_has_anchor(fetched: &Message, zone: &Name, anchors: &TrustAnchors) -> bool {
    let lower = LowerName::from(zone);
    fetched
        .answers
        .iter()
        .chain(fetched.authorities.iter())
        .chain(fetched.additionals.iter())
        .any(|record| {
            record.name == *zone
                && matches!(&record.data, RData::DNSSEC(DNSSECRData::DNSKEY(key))
                    if anchors.contains(key.public_key())
                        || anchors.contains_with_name(key.public_key(), &lower))
        })
}

/// Whether a fetched message contains DS records for `zone`.
pub(super) fn fetched_has_ds(fetched: &Message, zone: &Name) -> bool {
    fetched
        .answers
        .iter()
        .chain(fetched.authorities.iter())
        .chain(fetched.additionals.iter())
        .any(|record| {
            record.name == *zone && matches!(&record.data, RData::DNSSEC(DNSSECRData::DS(_)))
        })
}

impl DnssecValidator {
    pub fn new(mode: DnssecMode, ntas: Vec<String>) -> Self {
        Self {
            mode,
            trust_anchors: Arc::new(ArcSwap::from_pointee(TrustAnchors::default())),
            nta_domains: Arc::new(ArcSwap::from_pointee(ntas)),
            key_cache: KeyCache::new(),
            metrics: Arc::new(DnssecMetrics::new()),
            signed_zones: DashMap::new(),
            insecure_zones: DashMap::new(),
            chain_cache: Arc::new(ChainCache::new(None)),
            anchor_zones: DashMap::new(),
            probe_backoff: DashMap::new(),
            policy_generation: AtomicU64::new(0),
        }
    }

    /// Create from a `DnssecConfig`.
    pub fn from_config(config: &DnssecConfig) -> Self {
        Self::from_config_with_cache(config, None)
    }

    /// Create from a `DnssecConfig`, reusing a shared chain cache.
    ///
    /// Production passes the data-dir-backed cache so authenticated chain
    /// statuses survive hot reloads and process restarts. Tests use
    /// [`Self::from_config`], which keeps the cache purely in memory.
    pub fn from_config_with_cache(config: &DnssecConfig, cache: Option<Arc<ChainCache>>) -> Self {
        use base64::Engine;
        let mode = if config.validate {
            DnssecMode::from(config.mode.as_str())
        } else {
            DnssecMode::Disabled
        };
        let mut ntas = config.nta.clone();
        for ntp in &config.ntp {
            if !ntas.contains(ntp) {
                ntas.push(ntp.clone());
            }
        }
        let mut validator = Self::new(mode, ntas);
        if let Some(cache) = cache {
            validator.chain_cache = cache;
        }
        for ta in &config.trust_anchors {
            let parts: Vec<&str> = ta.split(':').collect();
            let (domain, alg, b64) = if parts.len() == 3 {
                (
                    parts[0].trim(),
                    parts[1].trim().parse::<u8>().unwrap_or(13),
                    parts[2].trim(),
                )
            } else if parts.len() == 2 {
                (parts[0].trim(), 13u8, parts[1].trim())
            } else {
                continue;
            };
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                let d = if domain.ends_with('.') {
                    domain.to_string()
                } else {
                    format!("{domain}.")
                };
                if let Ok(name) = Name::from_str(&d) {
                    let lower_name = LowerName::from(&name);
                    let algorithm = match alg {
                        8 => hickory_proto::dnssec::Algorithm::RSASHA256,
                        10 => hickory_proto::dnssec::Algorithm::RSASHA512,
                        13 => hickory_proto::dnssec::Algorithm::ECDSAP256SHA256,
                        14 => hickory_proto::dnssec::Algorithm::ECDSAP384SHA384,
                        15 => hickory_proto::dnssec::Algorithm::ED25519,
                        other => hickory_proto::dnssec::Algorithm::Unknown(other),
                    };
                    let pubkey = PublicKeyBuf::new(bytes, algorithm);
                    // Policy invalidation is handled once, after every anchor
                    // has been inserted; per-anchor invalidation would drop
                    // legitimate unsigned children on every reload.
                    validator.insert_raw_trust_anchor(&pubkey, &lower_name);
                    validator.anchor_zones.insert(lower_name, ());
                }
            }
        }
        // Cached chain statuses are only valid for the trust-anchor/NTA policy
        // that produced them. An `Unsigned` cached before an operator anchors a
        // zone would otherwise keep reporting the newly signed zone as
        // Insecure for the rest of the TTL (a persistent fail-open), and a new
        // NTA changes the classification too. Diff the policy so an unrelated
        // anchor addition preserves legitimate unsigned children.
        validator.apply_chain_cache_policy(config);
        validator
    }

    /// Applies the trust-anchor/NTA policy diff to the shared chain cache and
    /// the process-local unsigned evidence.
    ///
    /// Factored out of [`Self::from_config_with_cache`] so tests can exercise
    /// the policy diff on a validator whose seeded process-local maps are
    /// retained; the constructor always starts with empty maps.
    pub(super) fn apply_chain_cache_policy(&self, config: &DnssecConfig) -> PolicyChange {
        let mut anchor_zones: Vec<String> = self
            .anchor_zones
            .iter()
            .map(|entry| entry.key().to_string())
            .collect();
        anchor_zones.sort_unstable();
        anchor_zones.dedup();
        let mut nta_names: Vec<String> = (**self.nta_domains.load()).clone();
        nta_names.sort_unstable();
        nta_names.dedup();
        let change = self.chain_cache.ensure_policy(
            policy_fingerprint(&config.trust_anchors, &self.nta_domains.load()),
            anchor_zones,
            nta_names,
        );
        // Bind this validator to the generation it was configured under. An
        // older validator kept alive by an in-flight query will fail its next
        // cache insert after a reload changes the policy.
        self.policy_generation
            .store(self.chain_cache.policy_generation(), Ordering::Relaxed);
        match &change {
            PolicyChange::None => {}
            PolicyChange::FullClear => {
                // The cache already dropped every persisted status; mirror that
                // decision in the process-local unsigned evidence.
                self.insecure_zones.clear();
            }
            PolicyChange::AddedAnchors(added) => {
                // `ensure_policy` already evicted the contradicted cache
                // entries; only the in-memory mirror still needs pruning.
                for anchor in added {
                    self.invalidate_in_memory_unsigned_at_or_above(anchor);
                }
            }
        }
        change
    }

    /// The shared chain cache (used to verify reload reuse in tests).
    #[must_use]
    pub fn chain_cache(&self) -> &Arc<ChainCache> {
        &self.chain_cache
    }

    /// Custom trust anchors builder.
    #[must_use]
    pub fn with_trust_anchors(mut self, trust_anchors: TrustAnchors) -> Self {
        self.trust_anchors = Arc::new(ArcSwap::from_pointee(trust_anchors));
        self
    }

    /// Inserts an anchor without touching cached unsigned evidence or
    /// `anchor_zones`. Used during construction where the policy fingerprint
    /// owns invalidation.
    pub(super) fn insert_raw_trust_anchor(&self, key: &PublicKeyBuf, name: &LowerName) {
        let mut anchors = (**self.trust_anchors.load()).clone();
        anchors.insert_with_name(key, name.clone());
        self.trust_anchors.store(Arc::new(anchors));
    }

    /// Dynamically add a trusted anchor from DNSKEY.
    pub fn add_trust_anchor(&self, key: &DNSKEY, name: LowerName) {
        self.insert_raw_trust_anchor(key.public_key(), &name);
        self.invalidate_unsigned_evidence_under(&name);
        self.anchor_zones.insert(name, ());
    }

    /// Dynamically add a trusted anchor from raw public key buffer.
    pub fn add_raw_trust_anchor(&self, key: &PublicKeyBuf, name: LowerName) {
        self.insert_raw_trust_anchor(key, &name);
        self.invalidate_unsigned_evidence_under(&name);
        self.anchor_zones.insert(name, ());
    }

    /// Drops cached unsigned evidence that the new `anchor` contradicts.
    ///
    /// Only a cached zone that is at or above the anchor (the cached zone is an
    /// ancestor of, or equal to, the anchor) is invalidated. A legitimate
    /// unsigned child *below* an anchor is not contradicted by that anchor and
    /// must keep its cached proof, otherwise a reload would turn its stripped
    /// answers Bogus while the DS probe is offline.
    pub(super) fn invalidate_unsigned_evidence_under(&self, anchor: &LowerName) {
        self.invalidate_in_memory_unsigned_at_or_above(anchor);
        self.chain_cache.invalidate_unsigned_at_or_above(anchor);
    }

    /// Memory-only half of [`Self::invalidate_unsigned_evidence_under`], used
    /// after `ChainCache::ensure_policy` already did the targeted cache prune.
    pub(super) fn invalidate_in_memory_unsigned_at_or_above(&self, anchor: &LowerName) -> usize {
        let mut removed = 0usize;
        self.insecure_zones.retain(|zone, _| {
            let keep = !zone.zone_of(anchor);
            if !keep {
                removed += 1;
            }
            keep
        });
        removed
    }

    /// Add a Negative Trust Anchor (NTA) dynamically.
    pub fn add_nta(&self, domain: impl Into<String>) {
        let mut list = (**self.nta_domains.load()).clone();
        list.push(domain.into());
        self.nta_domains.store(Arc::new(list));
    }

    /// Remove an NTA dynamically.
    pub fn remove_nta(&self, domain: &str) {
        let mut list = (**self.nta_domains.load()).clone();
        list.retain(|d| d != domain);
        self.nta_domains.store(Arc::new(list));
    }

    /// Check whether a domain matches any configured Negative Trust Anchor.
    ///
    /// A root NTA (`"."`) matches every name, because every name is inside the
    /// root zone. Empty entries are ignored.
    pub fn is_nta(&self, name: &Name) -> bool {
        let norm = name.to_ascii().trim_end_matches('.').to_ascii_lowercase();
        let ntas = self.nta_domains.load();
        ntas.iter().any(|nta| {
            let raw = nta.trim();
            if raw.is_empty() {
                return false;
            }
            if raw == "." {
                return true;
            }
            let n = raw.trim_end_matches('.').to_ascii_lowercase();
            sito_core::matches_domain_suffix(&norm, &n)
        })
    }

    /// Records that `zone` was proven signed, valid until `expiry`.
    pub(super) fn mark_signed_zone(&self, zone: &LowerName, expiry: u32, now: u32) {
        self.insecure_zones.remove(zone);
        // The root is signed by definition, but it is not evidence that a
        // *descendant* name is signed: unsigned TLDs and delegations live
        // directly below it. Recording the root would make every descendant
        // without RRSIGs look like a stripped-signature downgrade (the P0
        // false SERVFAIL after the first signed zone). It is also never useful
        // for probe starts, because the anchor path already covers it.
        if zone.is_root() {
            return;
        }
        self.signed_zones.insert(zone.clone(), expiry);
        // Only authenticated evidence reaches this method: either a signer of
        // validated response data or an authenticated DS RRset. Persist it so
        // a restart (or hot reload) does not lose the downgrade protection.
        // The generation check rejects writes from a validator that was built
        // under a policy the shared cache has since replaced.
        let generation = self.policy_generation.load(Ordering::Relaxed);
        self.chain_cache.insert_for_generation(
            zone.clone(),
            ZoneStatus::Signed,
            expiry,
            now,
            generation,
        );
    }

    /// Whether `name` is inside a zone previously proven signed (and not
    /// expired), which makes a response without RRSIGs a downgrade attempt.
    pub(super) fn signed_zone_contains(&self, name: &LowerName, now: u32) -> bool {
        if self.signed_zones.len() > SIGNED_ZONE_MAX_ENTRIES {
            self.signed_zones.retain(|_, expiry| *expiry >= now);
            if self.signed_zones.len() > SIGNED_ZONE_MAX_ENTRIES {
                self.signed_zones.clear();
            }
        }
        self.signed_zones.iter().any(|entry| {
            *entry.value() >= now
                && entry.key().zone_of(name)
                // Defensive: entries restored from an old cache may still
                // contain the root. It only covers the root name itself.
                && (!entry.key().is_root() || name.is_root())
        }) || self.chain_cache.closest_signed(name, now).is_some()
    }

    /// Whether any name in the response's CNAME chain (starting at `qname`) is
    /// covered by a zone proven signed and is not under an authenticated
    /// unsigned delegation. A stripped chain must fail closed even when only
    /// the target (not the original qname) belongs to the signed zone.
    pub(super) fn signed_chain_contains(&self, response: &Message, qname: &Name, now: u32) -> bool {
        cname_chain_names(response, qname).iter().any(|name| {
            let lower = LowerName::from(name);
            self.signed_zone_contains(&lower, now) && !self.insecure_zone_covers(&lower, now)
        })
    }

    /// Records that `zone` was proven unsigned by an authenticated DS denial,
    /// valid until `expiry`.
    pub(super) fn mark_insecure_zone(&self, zone: &LowerName, expiry: u32, now: u32) {
        self.signed_zones.remove(zone);
        self.insecure_zones.insert(zone.clone(), expiry);
        let generation = self.policy_generation.load(Ordering::Relaxed);
        self.chain_cache.insert_for_generation(
            zone.clone(),
            ZoneStatus::Unsigned,
            expiry,
            now,
            generation,
        );
    }

    /// Whether `name` is inside a zone proven to be an unsigned delegation.
    ///
    /// A configured non-root anchor island below that unsigned delegation
    /// re-establishes trust at or below the anchor, so the parent's DS denial
    /// must not classify names inside the island as Insecure. This mirrors the
    /// anchor guard in [`Self::cached_unsigned_zone`], but is scoped to the
    /// queried name: sibling names outside the island still legitimately use
    /// the parent's unsigned proof.
    pub(super) fn insecure_zone_covers(&self, name: &LowerName, now: u32) -> bool {
        if self.insecure_zones.len() > SIGNED_ZONE_MAX_ENTRIES {
            self.insecure_zones.retain(|_, expiry| *expiry >= now);
            if self.insecure_zones.len() > SIGNED_ZONE_MAX_ENTRIES {
                self.insecure_zones.clear();
            }
        }
        self.insecure_zones.iter().any(|entry| {
            *entry.value() >= now
                && entry.key().zone_of(name)
                && !self.anchor_island_covers(entry.key(), name)
        })
    }

    /// Whether a configured non-root anchor island at or below `unsigned_zone`
    /// covers `name`, contradicting the cached unsigned delegation for that
    /// name.
    pub(super) fn anchor_island_covers(&self, unsigned_zone: &LowerName, name: &LowerName) -> bool {
        self.anchor_zones.iter().any(|entry| {
            !entry.key().is_root()
                && unsigned_zone.zone_of(entry.key())
                && entry.key().zone_of(name)
        })
    }

    /// Whether a configured non-root anchor is at or below the cached
    /// `unsigned_zone` (the cached zone is an ancestor of, or equal to, the
    /// anchor), and therefore contradicts that cached denial.
    ///
    /// A cached `Unsigned` child *below* a configured anchor is legitimate: the
    /// anchor only covers the signed parent/island, not the child delegation.
    /// Ignoring it would re-probe on every reload and, while offline, turn the
    /// child's stripped answers Bogus.
    pub(super) fn anchor_affects_unsigned_zone(&self, unsigned_zone: &LowerName) -> bool {
        self.anchor_zones
            .iter()
            .any(|entry| !entry.key().is_root() && unsigned_zone.zone_of(entry.key()))
    }

    /// A cached `Unsigned` zone covering `name`, unless a configured anchor at
    /// or below that cached zone now contradicts it.
    pub(super) fn cached_unsigned_zone(
        &self,
        name: &LowerName,
        now: u32,
    ) -> Option<(LowerName, u32)> {
        let (zone, expiry) = self.chain_cache.covers_unsigned(name, now)?;
        if self.anchor_affects_unsigned_zone(&zone) {
            return None;
        }
        Some((zone, expiry))
    }

    /// The closest zone apex that previously signed validated response data and
    /// is a proper ancestor of `name`.
    pub(super) fn closest_signed_zone(&self, name: &LowerName, now: u32) -> Option<LowerName> {
        self.signed_zones
            .iter()
            .filter(|entry| {
                *entry.value() >= now && entry.key() != name && entry.key().zone_of(name)
            })
            .max_by_key(|entry| entry.key().num_labels())
            .map(|entry| entry.key().clone())
    }
}
