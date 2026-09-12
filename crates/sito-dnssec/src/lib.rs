//! `sito-dnssec`
//!
//! DNSSEC cryptographic validation engine supporting RFC 4033/4034/4035 verification,
//! root trust anchors, negative trust anchors (NTA), key caching, RFC 8914 extended DNS errors (EDE),
//! and validation metrics.

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use tracing::{debug, warn};

use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, RRSIG, SIG};
use hickory_proto::dnssec::{PublicKeyBuf, TrustAnchors, Verifier};
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{DNSClass, LowerName, Name, RData, Record, RecordType};
use sito_core::DnssecKeyFetcher;
use sito_core::config::DnssecConfig;

/// DNSSEC validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnssecMode {
    /// Strict validation: bogus queries result in SERVFAIL with EDE.
    #[default]
    Validate,
    /// Permissive validation: log bogus queries and clear AD bit, but return response.
    LogOnly,
    /// DNSSEC validation disabled.
    Disabled,
}

impl From<&str> for DnssecMode {
    fn from(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "log-only" | "log_only" | "log_fail" | "permissive" => Self::LogOnly,
            "disabled" | "off" => Self::Disabled,
            _ => Self::Validate,
        }
    }
}

/// Outcome of a DNSSEC validation check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// Valid signature chain to a trust anchor (AD=1).
    Secure,
    /// Unsigned domain or proof of non-existence of DNSSEC (AD=0).
    Insecure,
    /// Signature verification failed, signature expired, or broken chain.
    Bogus { reason: String, ede_code: u16 },
    /// Inconclusive validation (missing DNSSEC records).
    Indeterminate,
    /// Bypassed validation due to Negative Trust Anchor (NTA).
    NtaBypass,
}

impl ValidationOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Secure => "secure",
            Self::Insecure | Self::NtaBypass => "insecure",
            Self::Bogus { .. } => "bogus",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// RFC 8914 Extended DNS Error (EDE) codes.
pub const EDE_DNSSEC_BOGUS: u16 = 6;
pub const EDE_SIGNATURE_EXPIRED: u16 = 7;

/// Attach an RFC 8914 Extended DNS Error (EDE) option to a DNS response.
pub fn apply_ede(response: &mut Message, code: u16, extra_text: &str) {
    let mut edns = response.edns.clone().unwrap_or_else(|| {
        let mut e = Edns::new();
        e.set_max_payload(1232);
        e.set_version(0);
        e
    });

    let mut payload = Vec::with_capacity(2 + extra_text.len());
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(extra_text.as_bytes());
    edns.options_mut().insert(EdnsOption::Unknown(15, payload));
    response.set_edns(edns);
}

/// Telemetry metrics for DNSSEC validation.
#[derive(Default)]
pub struct DnssecMetrics {
    pub secure_total: AtomicU64,
    pub insecure_total: AtomicU64,
    pub bogus_total: AtomicU64,
    pub indeterminate_total: AtomicU64,
    pub nta_bypass_total: AtomicU64,
    /// DNSKEY lookups served from the validated-key cache.
    pub key_cache_hits: AtomicU64,
    /// DNSKEY lookups that had to be resolved from the response or upstream.
    pub key_cache_misses: AtomicU64,
    pub bogus_by_upstream_reason: DashMap<(String, String), AtomicU64>,
}

impl DnssecMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_validation(&self, outcome: &ValidationOutcome) {
        match outcome {
            ValidationOutcome::Secure => {
                self.secure_total.fetch_add(1, Ordering::Relaxed);
            }
            ValidationOutcome::Insecure => {
                self.insecure_total.fetch_add(1, Ordering::Relaxed);
            }
            ValidationOutcome::Bogus { .. } => {
                self.bogus_total.fetch_add(1, Ordering::Relaxed);
            }
            ValidationOutcome::Indeterminate => {
                self.indeterminate_total.fetch_add(1, Ordering::Relaxed);
            }
            ValidationOutcome::NtaBypass => {
                self.nta_bypass_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Records a validated-key cache lookup.
    pub fn record_key_cache(&self, hit: bool) {
        if hit {
            self.key_cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.key_cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Cumulative validated-key cache hits.
    #[must_use]
    pub fn key_cache_hits(&self) -> u64 {
        self.key_cache_hits.load(Ordering::Relaxed)
    }

    /// Cumulative validated-key cache misses.
    #[must_use]
    pub fn key_cache_misses(&self) -> u64 {
        self.key_cache_misses.load(Ordering::Relaxed)
    }

    pub fn record_bogus(&self, upstream: Option<&str>, reason: &str) {
        let key = (
            upstream.unwrap_or("unknown").to_string(),
            reason.to_string(),
        );
        self.bogus_by_upstream_reason
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_validations(&self, result: &str) -> u64 {
        match result {
            "secure" => self.secure_total.load(Ordering::Relaxed),
            "insecure" => self.insecure_total.load(Ordering::Relaxed),
            "bogus" => self.bogus_total.load(Ordering::Relaxed),
            "indeterminate" => self.indeterminate_total.load(Ordering::Relaxed),
            "nta_bypass" => self.nta_bypass_total.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    pub fn get_bogus(&self, upstream: &str, reason: &str) -> u64 {
        self.bogus_by_upstream_reason
            .get(&(upstream.to_string(), reason.to_string()))
            .map_or(0, |val| val.load(Ordering::Relaxed))
    }
}

/// Cache for validated DNSKEY records.
///
/// Entries track whether the key was linked to a trust anchor (directly, via a
/// DS record or via a validated DNSKEY RRset). Only validated entries may be
/// used to mark a response `Secure`.
#[derive(Default)]
pub struct KeyCache {
    keys: DashMap<(LowerName, u16), (DNSKEY, u32, bool)>,
}

impl KeyCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns any cached key, validated or not (used for signature checks).
    pub fn get(&self, name: &LowerName, key_tag: u16, now: u32) -> Option<DNSKEY> {
        if let Some(entry) = self.keys.get(&(name.clone(), key_tag)) {
            let (key, expires_at, _) = entry.value();
            if now <= *expires_at {
                return Some(key.clone());
            }
        }
        None
    }

    /// Returns a cached key only when it is part of a validated chain.
    pub fn get_validated(&self, name: &LowerName, key_tag: u16, now: u32) -> Option<DNSKEY> {
        if let Some(entry) = self.keys.get(&(name.clone(), key_tag)) {
            let (key, expires_at, validated) = entry.value();
            if *validated && now <= *expires_at {
                return Some(key.clone());
            }
        }
        None
    }

    /// Stores a key that has not (yet) been linked to a trust anchor.
    pub fn insert(&self, name: LowerName, key_tag: u16, key: DNSKEY, expires_at: u32) {
        self.keys.insert((name, key_tag), (key, expires_at, false));
    }

    /// Stores a key that has been linked to a trust anchor by the chain walk.
    pub fn insert_validated(&self, name: LowerName, key_tag: u16, key: DNSKEY, expires_at: u32) {
        self.keys.insert((name, key_tag), (key, expires_at, true));
    }

    /// Number of cached keys (validated and unvalidated). Test/diagnostics helper.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the cache holds no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Unique signer zones referenced by RRSIG records in a message.
fn collect_rrsig_signers(response: &Message) -> Vec<Name> {
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
fn append_dnssec_records(response: &mut Message, fetched: &Message) {
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
fn fetched_has_anchor(fetched: &Message, zone: &Name, anchors: &TrustAnchors) -> bool {
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
fn fetched_has_ds(fetched: &Message, zone: &Name) -> bool {
    fetched
        .answers
        .iter()
        .chain(fetched.authorities.iter())
        .chain(fetched.additionals.iter())
        .any(|record| {
            record.name == *zone && matches!(&record.data, RData::DNSSEC(DNSSECRData::DS(_)))
        })
}

/// Fetches the DNSKEY/DS chain for `zone`, appending records to `response`.
///
/// Returns `Some(())` when at least one lookup succeeded. The walk stops at an
/// anchored DNSKEY, at an unsigned delegation (no DS), at the root, when the
/// zone was already visited, or when the budget is exhausted.
async fn fetch_zone_chain(
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
        if *budget == 0 || depth > 12 || current.is_root() {
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

/// Verifies `rrsig` over the RRset it covers using `key`.
fn verify_rrsig_covered(response: &Message, owner: &Name, rrsig: &SIG, key: &DNSKEY) -> bool {
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

/// DNSSEC validation engine.
pub struct DnssecValidator {
    pub mode: DnssecMode,
    pub trust_anchors: Arc<ArcSwap<TrustAnchors>>,
    pub nta_domains: Arc<ArcSwap<Vec<String>>>,
    pub key_cache: KeyCache,
    pub metrics: Arc<DnssecMetrics>,
}

impl DnssecValidator {
    /// Create a new `DnssecValidator` with default root trust anchors.
    pub fn new(mode: DnssecMode, ntas: Vec<String>) -> Self {
        Self {
            mode,
            trust_anchors: Arc::new(ArcSwap::from_pointee(TrustAnchors::default())),
            nta_domains: Arc::new(ArcSwap::from_pointee(ntas)),
            key_cache: KeyCache::new(),
            metrics: Arc::new(DnssecMetrics::new()),
        }
    }

    /// Create from a `DnssecConfig`.
    pub fn from_config(config: &DnssecConfig) -> Self {
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
        let validator = Self::new(mode, ntas);
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
                        13 => hickory_proto::dnssec::Algorithm::ECDSAP256SHA256,
                        14 => hickory_proto::dnssec::Algorithm::ECDSAP384SHA384,
                        15 => hickory_proto::dnssec::Algorithm::ED25519,
                        other => hickory_proto::dnssec::Algorithm::Unknown(other),
                    };
                    let pubkey = PublicKeyBuf::new(bytes, algorithm);
                    validator.add_raw_trust_anchor(&pubkey, lower_name);
                }
            }
        }
        validator
    }

    /// Custom trust anchors builder.
    #[must_use]
    pub fn with_trust_anchors(mut self, trust_anchors: TrustAnchors) -> Self {
        self.trust_anchors = Arc::new(ArcSwap::from_pointee(trust_anchors));
        self
    }

    /// Dynamically add a trusted anchor from DNSKEY.
    pub fn add_trust_anchor(&self, key: &DNSKEY, name: LowerName) {
        let mut anchors = (**self.trust_anchors.load()).clone();
        anchors.insert_with_name(key.public_key(), name);
        self.trust_anchors.store(Arc::new(anchors));
    }

    /// Dynamically add a trusted anchor from raw public key buffer.
    pub fn add_raw_trust_anchor(&self, key: &PublicKeyBuf, name: LowerName) {
        let mut anchors = (**self.trust_anchors.load()).clone();
        anchors.insert_with_name(key, name);
        self.trust_anchors.store(Arc::new(anchors));
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
    pub fn is_nta(&self, name: &Name) -> bool {
        let norm = name.to_ascii().trim_end_matches('.').to_ascii_lowercase();
        let ntas = self.nta_domains.load();
        ntas.iter().any(|nta| {
            let n = nta.trim_end_matches('.').to_ascii_lowercase();
            norm == n || norm.ends_with(&format!(".{n}"))
        })
    }

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
        let baseline = self.validate_response(response, upstream, now);
        if baseline != ValidationOutcome::Indeterminate || self.mode == DnssecMode::Disabled {
            return baseline;
        }

        let signers = collect_rrsig_signers(response);
        if signers.is_empty() {
            return baseline;
        }

        let original_additionals = response.additionals.len();
        let anchors = self.trust_anchors.load();
        let mut budget = 6u8;
        let mut visited = HashSet::new();
        let mut fetched_any = false;
        for signer in signers.iter().take(4) {
            if budget == 0 {
                break;
            }
            if fetch_zone_chain(
                &anchors,
                fetcher,
                signer,
                &mut budget,
                &mut visited,
                response,
            )
            .await
            .is_some()
            {
                fetched_any = true;
            }
        }

        if !fetched_any {
            response.additionals.truncate(original_additionals);
            return baseline;
        }

        let outcome = self.validate_response(response, upstream, now);
        response.additionals.truncate(original_additionals);
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
    /// The fixpoint is bounded and newly validated keys are cached with the
    /// minimum of the record TTL and the matching signature expiration.
    fn build_validated_key_set(
        &self,
        response: &Message,
        dnskeys: &[(Name, DNSKEY)],
        rrsigs: &[(Name, SIG)],
        now: u32,
    ) -> HashSet<(LowerName, u16)> {
        let mut validated: HashSet<(LowerName, u16)> = HashSet::new();
        let anchors = self.trust_anchors.load();

        for (owner, key) in dnskeys {
            let Ok(tag) = key.calculate_key_tag() else {
                continue;
            };
            let lower = LowerName::from(owner);
            let anchored = anchors.contains(key.public_key())
                || anchors.contains_with_name(key.public_key(), &lower);
            if anchored || self.key_cache.get_validated(&lower, tag, now).is_some() {
                validated.insert((lower, tag));
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
            .collect();

        let mut changed = true;
        let mut rounds = 0u8;
        while changed && rounds < 16 {
            changed = false;
            rounds += 1;

            for (ds_owner, ds) in &ds_records {
                for (parent_owner, parent_key) in dnskeys {
                    let Ok(parent_tag) = parent_key.calculate_key_tag() else {
                        continue;
                    };
                    let lower_parent = LowerName::from(parent_owner);
                    if !validated.contains(&(lower_parent.clone(), parent_tag)) {
                        continue;
                    }
                    let ds_signed = rrsigs.iter().any(|(owner, sig)| {
                        owner == *ds_owner
                            && sig.input().type_covered == RecordType::DS
                            && LowerName::from(&sig.input().signer_name) == lower_parent
                            && sig.input().key_tag == parent_tag
                            && verify_rrsig_covered(response, ds_owner, sig, parent_key)
                    });
                    if !ds_signed {
                        continue;
                    }
                    for (child_owner, child_key) in dnskeys {
                        if child_owner != *ds_owner || child_key.algorithm() != ds.algorithm() {
                            continue;
                        }
                        if !ds.covers(child_owner, child_key).unwrap_or(false) {
                            continue;
                        }
                        if let Ok(tag) = child_key.calculate_key_tag()
                            && validated.insert((LowerName::from(child_owner), tag))
                        {
                            changed = true;
                        }
                    }
                }
            }

            for (owner, signer_key) in dnskeys {
                let Ok(tag) = signer_key.calculate_key_tag() else {
                    continue;
                };
                let lower = LowerName::from(owner);
                if !validated.contains(&(lower, tag)) {
                    continue;
                }
                let rrset_signed = rrsigs.iter().any(|(sig_owner, sig)| {
                    sig_owner == owner
                        && sig.input().type_covered == RecordType::DNSKEY
                        && verify_rrsig_covered(response, owner, sig, signer_key)
                });
                if !rrset_signed {
                    continue;
                }
                for (other_owner, other_key) in dnskeys {
                    if other_owner != owner {
                        continue;
                    }
                    if let Ok(other_tag) = other_key.calculate_key_tag()
                        && validated.insert((LowerName::from(other_owner), other_tag))
                    {
                        changed = true;
                    }
                }
            }
        }

        for (lower, tag) in &validated {
            let Some((owner, key)) = dnskeys.iter().find(|(owner, key)| {
                LowerName::from(owner) == *lower && key.calculate_key_tag().ok() == Some(*tag)
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
                .filter(|(_, sig)| LowerName::from(&sig.input().signer_name) == *lower)
                .map(|(_, sig)| sig.input().sig_expiration.get())
                .min();
            let expiry = sig_expiry.map_or(ttl_expiry, |e| e.min(ttl_expiry));
            self.key_cache
                .insert_validated(lower.clone(), *tag, key.clone(), expiry);
        }

        validated
    }

    /// Validate a response against DNSSEC rules.
    pub fn validate_response(
        &self,
        response: &mut Message,
        upstream: Option<&str>,
        now: u32,
    ) -> ValidationOutcome {
        if self.mode == DnssecMode::Disabled {
            response.metadata.authentic_data = false;
            let outcome = ValidationOutcome::Insecure;
            self.metrics.record_validation(&outcome);
            return outcome;
        }

        // Check NTA bypass
        if let Some(query) = response.queries.first()
            && self.is_nta(query.name())
        {
            debug!(
                "Bypassing DNSSEC validation for NTA domain {}",
                query.name()
            );
            response.metadata.authentic_data = false;
            let outcome = ValidationOutcome::NtaBypass;
            self.metrics.record_validation(&outcome);
            return outcome;
        }

        // Collect DNSKEY records from response
        let mut response_dnskeys = Vec::new();
        for record in response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .chain(response.additionals.iter())
        {
            if let RData::DNSSEC(DNSSECRData::DNSKEY(key)) = &record.data {
                response_dnskeys.push((record.name.clone(), key.clone()));
            }
        }

        // Collect RRSIG records
        let mut rrsigs = Vec::new();
        for record in response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .chain(response.additionals.iter())
        {
            match &record.data {
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                    rrsigs.push((record.name.clone(), (**rrsig).clone()));
                }
                RData::DNSSEC(DNSSECRData::SIG(sig)) => {
                    rrsigs.push((record.name.clone(), sig.clone()));
                }
                _ => {}
            }
        }

        // If no RRSIG records exist, domain is unsigned
        if rrsigs.is_empty() {
            response.metadata.authentic_data = false;
            let outcome = ValidationOutcome::Insecure;
            self.metrics.record_validation(&outcome);
            return outcome;
        }

        // Extend trust from anchors to derived keys (DS delegation, KSK->ZSK).
        let validated_keys =
            self.build_validated_key_set(response, &response_dnskeys, &rrsigs, now);

        // Validate each RRSIG. A response is bogus only if every candidate
        // signature fails; a single valid signature (even if another is
        // expired) is sufficient.
        let mut has_secure_validation = false;
        let mut first_failure: Option<(&'static str, u16)> = None;

        for (rrsig_owner, rrsig) in &rrsigs {
            let inception = rrsig.input().sig_inception.get();
            let expiration = rrsig.input().sig_expiration.get();

            if now < inception {
                first_failure.get_or_insert(("Signature not yet valid", EDE_DNSSEC_BOGUS));
                continue;
            }

            if now > expiration {
                first_failure.get_or_insert(("Signature expired", EDE_SIGNATURE_EXPIRED));
                continue;
            }

            let type_covered = rrsig.input().type_covered;
            let signer_name = &rrsig.input().signer_name;
            let key_tag = rrsig.input().key_tag;

            // Find matching DNSKEY
            let lower_signer = LowerName::from(signer_name);
            let cached_key = self.key_cache.get(&lower_signer, key_tag, now);
            self.metrics.record_key_cache(cached_key.is_some());
            let mut matching_key = cached_key;

            if matching_key.is_none() {
                for (key_owner, dnskey) in &response_dnskeys {
                    if key_owner == signer_name
                        && let Ok(tag) = dnskey.calculate_key_tag()
                        && tag == key_tag
                    {
                        matching_key = Some(dnskey.clone());
                        // Cache for remaining duration up to expiration
                        self.key_cache.insert(
                            lower_signer.clone(),
                            key_tag,
                            dnskey.clone(),
                            expiration,
                        );
                        break;
                    }
                }
            }

            if let Some(dnskey) = matching_key {
                // Collect records covered by this RRSIG
                let covered_records: Vec<&Record> = response
                    .answers
                    .iter()
                    .chain(response.authorities.iter())
                    .filter(|r| r.record_type() == type_covered && r.name == *rrsig_owner)
                    .collect();

                if !covered_records.is_empty() {
                    let rrsig_rdata = RRSIG::from_sig(rrsig.input().clone(), rrsig.sig().to_vec());
                    if dnskey
                        .verify_rrsig(
                            rrsig_owner,
                            DNSClass::IN,
                            &rrsig_rdata,
                            covered_records.into_iter(),
                        )
                        .is_err()
                    {
                        first_failure.get_or_insert((
                            "Cryptographic signature verification failed",
                            EDE_DNSSEC_BOGUS,
                        ));
                        continue;
                    }
                }

                // Check if DNSKEY is trusted (anchor, validated chain, or cache)
                let anchors = self.trust_anchors.load();
                let is_trusted = anchors.contains(dnskey.public_key())
                    || anchors.contains_with_name(dnskey.public_key(), &lower_signer)
                    || validated_keys.contains(&(lower_signer.clone(), key_tag))
                    || self
                        .key_cache
                        .get_validated(&lower_signer, key_tag, now)
                        .is_some();

                if is_trusted {
                    has_secure_validation = true;
                }
            }
        }

        if has_secure_validation {
            response.metadata.authentic_data = true;
            let outcome = ValidationOutcome::Secure;
            self.metrics.record_validation(&outcome);
            outcome
        } else if let Some((reason, ede_code)) = first_failure {
            self.handle_bogus(response, upstream, reason, ede_code)
        } else {
            // RRSIGs were present and valid, but could not link to trust anchor
            response.metadata.authentic_data = false;
            let outcome = ValidationOutcome::Indeterminate;
            self.metrics.record_validation(&outcome);
            outcome
        }
    }

    fn handle_bogus(
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

/// Test utilities for DNSSEC integration tests.
pub mod test_util {
    use super::{DNSClass, DNSKEY, Name, RData, RRSIG, Record};
    use hickory_proto::dnssec::crypto::EcdsaSigningKey;
    use hickory_proto::dnssec::{Algorithm, DnssecSigner, SigningKey};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RecordData, RecordSet, RecordType};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::Duration;

    /// Creates an ECDSA P-256 signing key and DNSKEY for *origin_str*.
    pub fn create_test_signer(origin_str: &str) -> (Name, DNSKEY, DnssecSigner) {
        let origin = Name::from_str(origin_str).expect("parse origin");
        let pkcs8 =
            EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).expect("generate pkcs8");
        let key = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256)
            .expect("key from pkcs8");
        let pub_key = key.to_public_key().expect("pub key");
        let dnskey = DNSKEY::from_key(&pub_key);
        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(key),
            origin.clone(),
            Duration::from_secs(3600),
        );
        (origin, dnskey, signer)
    }

    /// Signs an entire RRset (or DNSKEY RRset) and returns the RRSIG record.
    pub fn sign_test_rrset(set: &RecordSet, signer: &DnssecSigner) -> Record {
        let now_utc = time::OffsetDateTime::now_utc();
        let rrsig = RRSIG::from_rrset(set, DNSClass::IN, now_utc, signer).expect("sign test rrset");
        Record::from_rdata(set.name().clone(), 300, rrsig.into_rdata())
    }

    /// Helper that generates a signed test domain with DNSKEY, A record, and matching RRSIG.
    pub fn create_test_signed_domain(
        origin_str: &str,
    ) -> (Name, DNSKEY, Record, Record, DnssecSigner) {
        let origin = Name::from_str(origin_str).expect("parse origin");
        let pkcs8 =
            EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).expect("generate pkcs8");
        let key = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256)
            .expect("key from pkcs8");
        let pub_key = key.to_public_key().expect("pub key");
        let dnskey = DNSKEY::from_key(&pub_key);

        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(key),
            origin.clone(),
            Duration::from_secs(3600),
        );

        let a_record = Record::from_rdata(
            origin.clone(),
            300,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        );

        let mut record_set = RecordSet::new(origin.clone(), RecordType::A, 0);
        record_set.insert(a_record.clone(), 0);

        let now_utc = time::OffsetDateTime::now_utc();
        let rrsig =
            RRSIG::from_rrset(&record_set, DNSClass::IN, now_utc, &signer).expect("sign rrset");
        let rrsig_record = Record::from_rdata(origin.clone(), 300, rrsig.into_rdata());

        (origin, dnskey, a_record, rrsig_record, signer)
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::*;
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::RecordType;
    use hickory_proto::rr::rdata::A;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::Duration;

    #[test]
    fn test_dnssec_secure_validation() {
        let (origin, dnskey, a_record, rrsig_record, _) =
            create_test_signed_domain("secure.example.com.");

        let mut trust_anchors = TrustAnchors::empty();
        trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));

        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new())
            .with_trust_anchors(trust_anchors);

        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        msg.answers.push(a_record);
        msg.answers.push(rrsig_record);
        msg.additionals.push(Record::from_rdata(
            origin,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("1.1.1.1"), now);

        assert_eq!(outcome, ValidationOutcome::Secure);
        assert!(msg.metadata.authentic_data);
        assert_eq!(validator.metrics.get_validations("secure"), 1);
    }

    #[test]
    fn test_dnssec_bogus_tampered_record() {
        let (origin, dnskey, _a_record, rrsig_record, _) =
            create_test_signed_domain("tampered.example.com.");

        let mut trust_anchors = TrustAnchors::empty();
        trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));

        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new())
            .with_trust_anchors(trust_anchors);

        let mut msg = Message::new(2, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        // Tampered IP (9.9.9.9 instead of 93.184.216.34)
        let tampered_record =
            Record::from_rdata(origin.clone(), 300, RData::A(A(Ipv4Addr::new(9, 9, 9, 9))));
        msg.answers.push(tampered_record);
        msg.answers.push(rrsig_record);
        msg.additionals.push(Record::from_rdata(
            origin,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("8.8.8.8"), now);

        assert!(matches!(
            outcome,
            ValidationOutcome::Bogus { ede_code: 6, .. }
        ));
        assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
        assert!(!msg.metadata.authentic_data);
        assert!(msg.answers.is_empty());
        assert_eq!(validator.metrics.get_validations("bogus"), 1);
        assert_eq!(
            validator
                .metrics
                .get_bogus("8.8.8.8", "Cryptographic signature verification failed"),
            1
        );
    }

    #[test]
    fn test_dnssec_bogus_log_only_mode() {
        let (origin, dnskey, _a_record, rrsig_record, _) =
            create_test_signed_domain("logonly.example.com.");

        let mut trust_anchors = TrustAnchors::empty();
        trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));

        let validator =
            DnssecValidator::new(DnssecMode::LogOnly, Vec::new()).with_trust_anchors(trust_anchors);

        let mut msg = Message::new(3, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        let tampered_record =
            Record::from_rdata(origin.clone(), 300, RData::A(A(Ipv4Addr::new(1, 1, 1, 1))));
        msg.answers.push(tampered_record);
        msg.answers.push(rrsig_record);
        msg.additionals.push(Record::from_rdata(
            origin,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("9.9.9.9"), now);

        assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
        // Log-only mode does not SERVFAIL and preserves answers, but clears AD bit
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert!(!msg.metadata.authentic_data);
        assert_eq!(msg.answers.len(), 2);
    }

    #[test]
    fn test_dnssec_expired_signature() {
        let (origin, dnskey, a_record, rrsig_record, _) =
            create_test_signed_domain("expired.example.com.");

        let mut trust_anchors = TrustAnchors::empty();
        trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));

        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new())
            .with_trust_anchors(trust_anchors);

        let mut msg = Message::new(4, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        msg.answers.push(a_record);
        msg.answers.push(rrsig_record);
        msg.additionals.push(Record::from_rdata(
            origin,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        ));

        // Validate at a future time past expiration (10 days in future)
        let future =
            (time::OffsetDateTime::now_utc() + Duration::from_hours(240)).unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("1.1.1.1"), future);

        assert_eq!(
            outcome,
            ValidationOutcome::Bogus {
                reason: "Signature expired".to_string(),
                ede_code: EDE_SIGNATURE_EXPIRED,
            }
        );
        assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(validator.metrics.get_validations("bogus"), 1);
        assert_eq!(
            validator.metrics.get_bogus("1.1.1.1", "Signature expired"),
            1
        );
    }

    use sito_core::error::UpstreamError;

    struct StaticFetcher {
        responses: std::collections::HashMap<(LowerName, RecordType), Message>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl StaticFetcher {
        fn new() -> Self {
            Self {
                responses: std::collections::HashMap::new(),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn with(mut self, name: &Name, rtype: RecordType, message: Message) -> Self {
            self.responses
                .insert((LowerName::from(name), rtype), message);
            self
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl DnssecKeyFetcher for StaticFetcher {
        async fn query(&self, name: &Name, rtype: RecordType) -> Result<Message, UpstreamError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self
                .responses
                .get(&(LowerName::from(name), rtype))
                .cloned()
                .unwrap_or_else(|| Message::new(0, MessageType::Response, OpCode::Query)))
        }
    }

    fn fetched_dnskey_message(owner: &Name, keys: &[DNSKEY], signature: Option<Record>) -> Message {
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        for key in keys {
            message.additionals.push(Record::from_rdata(
                owner.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(key.clone())),
            ));
        }
        if let Some(signature) = signature {
            message.additionals.push(signature);
        }
        message
    }

    fn signed_a_response(
        origin: &Name,
        signer: &hickory_proto::dnssec::DnssecSigner,
    ) -> (Record, Record) {
        use hickory_proto::rr::RecordSet;
        let answer = Record::from_rdata(
            origin.clone(),
            300,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 7))),
        );
        let mut set = RecordSet::new(origin.clone(), RecordType::A, 0);
        set.insert(answer.clone(), 0);
        (answer, sign_test_rrset(&set, signer))
    }

    fn signed_nsec_response(
        origin: &Name,
        qname: &Name,
        dnskey: &DNSKEY,
        signer: &hickory_proto::dnssec::DnssecSigner,
        response_code: ResponseCode,
    ) -> Message {
        use hickory_proto::dnssec::rdata::NSEC;
        use hickory_proto::rr::RecordSet;

        let next = Name::from_str("zzz.nsec.example.").unwrap();
        let nsec = NSEC::new(next, [RecordType::A, RecordType::NSEC, RecordType::RRSIG]);
        let nsec_record =
            Record::from_rdata(origin.clone(), 300, RData::DNSSEC(DNSSECRData::NSEC(nsec)));
        let mut set = RecordSet::new(origin.clone(), RecordType::NSEC, 0);
        set.insert(nsec_record.clone(), 0);
        let nsec_sig = sign_test_rrset(&set, signer);

        let mut msg = Message::new(24, MessageType::Response, OpCode::Query);
        msg.queries.push(Query::query(qname.clone(), RecordType::A));
        msg.metadata.response_code = response_code;
        msg.authorities.push(nsec_record);
        msg.authorities.push(nsec_sig);
        msg.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
        ));
        msg
    }

    #[test]
    fn test_nxdomain_with_nsec_is_secure() {
        let (origin, dnskey, signer) = create_test_signer("nsec.example.");
        let qname = Name::from_str("missing.nsec.example.").unwrap();

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut msg =
            signed_nsec_response(&origin, &qname, &dnskey, &signer, ResponseCode::NXDomain);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("test"), now);

        assert_eq!(outcome, ValidationOutcome::Secure);
        assert!(msg.metadata.authentic_data);
    }

    #[test]
    fn test_nodata_with_nsec_is_secure() {
        let (origin, dnskey, signer) = create_test_signer("nsec.example.");
        let qname = Name::from_str("empty.nsec.example.").unwrap();

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut msg =
            signed_nsec_response(&origin, &qname, &dnskey, &signer, ResponseCode::NoError);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("test"), now);

        assert_eq!(outcome, ValidationOutcome::Secure);
    }

    #[test]
    fn test_negative_response_with_untrusted_nsec_is_not_secure() {
        let (origin, dnskey, signer) = create_test_signer("nsec.example.");
        let qname = Name::from_str("missing.nsec.example.").unwrap();

        // No anchors: the denial signature verifies cryptographically but the
        // covering zone is not linked to a trust anchor.
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());

        let mut msg =
            signed_nsec_response(&origin, &qname, &dnskey, &signer, ResponseCode::NXDomain);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("test"), now);

        assert_eq!(outcome, ValidationOutcome::Indeterminate);
        assert!(!msg.metadata.authentic_data);
    }

    #[test]
    fn test_key_cache_metrics_across_validations() {
        let (origin, dnskey, a_record, rrsig_record, _) =
            create_test_signed_domain("kcache.example.");

        // No trust anchors: signatures verify but chain is not linked, which
        // still exercises the key cache lookups.
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        for _ in 0..2 {
            let mut msg = Message::new(23, MessageType::Response, OpCode::Query);
            msg.queries
                .push(Query::query(origin.clone(), RecordType::A));
            msg.answers.push(a_record.clone());
            msg.answers.push(rrsig_record.clone());
            msg.additionals.push(Record::from_rdata(
                origin.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
            ));
            let _ = validator.validate_response(&mut msg, Some("cache-test"), now);
        }

        assert_eq!(validator.metrics.key_cache_misses(), 1);
        assert_eq!(validator.metrics.key_cache_hits(), 1);
    }

    #[tokio::test]
    async fn test_chain_fetch_resolves_ksk_zsk() {
        use hickory_proto::rr::RecordSet;

        let (origin, ksk, ksk_signer) = create_test_signer("fetch.example.");
        let (_name, zsk, zsk_signer) = create_test_signer("fetch.example.");

        let (answer, answer_sig) = signed_a_response(&origin, &zsk_signer);

        let mut key_set = RecordSet::new(origin.clone(), RecordType::DNSKEY, 0);
        key_set.insert(
            Record::from_rdata(
                origin.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(ksk.clone())),
            ),
            0,
        );
        key_set.insert(
            Record::from_rdata(
                origin.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(zsk.clone())),
            ),
            0,
        );
        let key_sig = sign_test_rrset(&key_set, &ksk_signer);

        let fetcher = StaticFetcher::new().with(
            &origin,
            RecordType::DNSKEY,
            fetched_dnskey_message(&origin, &[ksk.clone(), zsk.clone()], Some(key_sig)),
        );

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(ksk.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut response = Message::new(20, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(origin.clone(), RecordType::A));
        response.answers.push(answer);
        response.answers.push(answer_sig);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("test"), now, &fetcher)
            .await;

        assert_eq!(outcome, ValidationOutcome::Secure);
        assert!(response.metadata.authentic_data);
        assert_eq!(fetcher.calls(), 1);
        // Fetched keys must not leak into the client response.
        assert!(
            response
                .additionals
                .iter()
                .all(|record| !matches!(record.data, RData::DNSSEC(DNSSECRData::DNSKEY(_))))
        );
    }

    #[tokio::test]
    async fn test_chain_fetch_resolves_ds_delegation() {
        use hickory_proto::dnssec::DigestType;
        use hickory_proto::rr::RecordSet;

        let (parent, parent_key, parent_signer) = create_test_signer("example.");
        let (child, child_key, child_signer) = create_test_signer("sub.example.");

        let (answer, answer_sig) = signed_a_response(&child, &child_signer);

        let ds = DS::from_key(child_key.public_key(), &child, DigestType::SHA256).unwrap();
        let ds_record = Record::from_rdata(child.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
        let mut ds_set = RecordSet::new(child.clone(), RecordType::DS, 0);
        ds_set.insert(ds_record.clone(), 0);
        let ds_sig = sign_test_rrset(&ds_set, &parent_signer);
        let mut ds_message = Message::new(0, MessageType::Response, OpCode::Query);
        ds_message.authorities.push(ds_record);
        ds_message.authorities.push(ds_sig);

        let fetcher = StaticFetcher::new()
            .with(
                &child,
                RecordType::DNSKEY,
                fetched_dnskey_message(&child, &[child_key], None),
            )
            .with(&child, RecordType::DS, ds_message)
            .with(
                &parent,
                RecordType::DNSKEY,
                fetched_dnskey_message(&parent, &[parent_key.clone()], None),
            );

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(parent_key.public_key(), LowerName::from(&parent));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut response = Message::new(21, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(child.clone(), RecordType::A));
        response.answers.push(answer);
        response.answers.push(answer_sig);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("test"), now, &fetcher)
            .await;

        assert_eq!(outcome, ValidationOutcome::Secure);
        assert!(response.metadata.authentic_data);
        assert_eq!(fetcher.calls(), 3);
        assert!(response.additionals.is_empty());
    }

    #[tokio::test]
    async fn test_chain_fetch_budget_for_unsigned_delegation() {
        let (origin, _zsk, zsk_signer) = create_test_signer("unsigned.example.");
        let (answer, answer_sig) = signed_a_response(&origin, &zsk_signer);

        let fetcher = StaticFetcher::new();

        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());

        let mut response = Message::new(22, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(origin.clone(), RecordType::A));
        response.answers.push(answer);
        response.answers.push(answer_sig);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("test"), now, &fetcher)
            .await;

        assert_eq!(outcome, ValidationOutcome::Indeterminate);
        // One DNSKEY and one DS lookup for the signer zone, then stop.
        assert_eq!(fetcher.calls(), 2);
        assert!(response.additionals.is_empty());
    }

    #[test]
    fn test_dnssec_nta_bypass() {
        let origin = Name::from_str("service.internal.corp.").unwrap();
        let validator =
            DnssecValidator::new(DnssecMode::Validate, vec!["internal.corp".to_string()]);

        let mut msg = Message::new(5, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        msg.answers.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, None, now);

        assert_eq!(outcome, ValidationOutcome::NtaBypass);
        assert!(!msg.metadata.authentic_data);
        assert_eq!(validator.metrics.get_validations("nta_bypass"), 1);

        // Dynamic NTA removal
        validator.remove_nta("internal.corp");
        assert!(!validator.is_nta(&origin));

        // Now without NTA, an unsigned domain is Insecure
        let outcome2 = validator.validate_response(&mut msg, None, now);
        assert_eq!(outcome2, ValidationOutcome::Insecure);
        assert_eq!(validator.metrics.get_validations("insecure"), 1);
    }

    #[test]
    fn test_ds_digest_match_and_mismatch() {
        use hickory_proto::dnssec::DigestType;

        let (origin, dnskey, _signer) = create_test_signer("child.example.");
        let ds = DS::from_key(dnskey.public_key(), &origin, DigestType::SHA256).unwrap();

        assert_eq!(ds.key_tag(), dnskey.calculate_key_tag().unwrap());
        assert!(ds.covers(&origin, &dnskey).unwrap());

        let tampered = DS::new(
            ds.key_tag(),
            ds.algorithm(),
            ds.digest_type(),
            vec![0u8; ds.digest().len()],
        );
        assert!(!tampered.covers(&origin, &dnskey).unwrap());
    }

    #[test]
    fn test_dnssec_ksk_zsk_chain() {
        use hickory_proto::rr::RecordSet;

        let (origin, ksk, ksk_signer) = create_test_signer("chain.example.");
        let (_zsk_name, zsk, zsk_signer) = create_test_signer("chain.example.");

        let a_record = Record::from_rdata(
            origin.clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
        );
        let mut a_set = RecordSet::new(origin.clone(), RecordType::A, 0);
        a_set.insert(a_record.clone(), 0);
        let a_sig = sign_test_rrset(&a_set, &zsk_signer);

        let mut key_set = RecordSet::new(origin.clone(), RecordType::DNSKEY, 0);
        key_set.insert(
            Record::from_rdata(
                origin.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(ksk.clone())),
            ),
            0,
        );
        key_set.insert(
            Record::from_rdata(
                origin.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(zsk.clone())),
            ),
            0,
        );
        let key_sig = sign_test_rrset(&key_set, &ksk_signer);

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(ksk.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut msg = Message::new(10, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        msg.answers.push(a_record);
        msg.answers.push(a_sig);
        msg.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(ksk)),
        ));
        msg.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(zsk)),
        ));
        msg.additionals.push(key_sig);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("chain-test"), now);

        assert_eq!(outcome, ValidationOutcome::Secure);
        assert!(msg.metadata.authentic_data);
        assert!(!validator.key_cache.is_empty());
    }

    #[test]
    fn test_dnssec_ds_delegation_chain() {
        use hickory_proto::dnssec::DigestType;
        use hickory_proto::rr::RecordSet;

        let (parent, parent_key, parent_signer) = create_test_signer("example.");
        let (child, child_key, child_signer) = create_test_signer("sub.example.");

        // DS record at the child, signed by the parent KSK.
        let ds = DS::from_key(child_key.public_key(), &child, DigestType::SHA256).unwrap();
        let ds_record = Record::from_rdata(child.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
        let mut ds_set = RecordSet::new(child.clone(), RecordType::DS, 0);
        ds_set.insert(ds_record.clone(), 0);
        let ds_sig = sign_test_rrset(&ds_set, &parent_signer);

        // Child A record signed by the child ZSK.
        let a_record = Record::from_rdata(
            child.clone(),
            300,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 7))),
        );
        let mut a_set = RecordSet::new(child.clone(), RecordType::A, 0);
        a_set.insert(a_record.clone(), 0);
        let a_sig = sign_test_rrset(&a_set, &child_signer);

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(parent_key.public_key(), LowerName::from(&parent));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut msg = Message::new(11, MessageType::Response, OpCode::Query);
        msg.queries.push(Query::query(child.clone(), RecordType::A));
        msg.answers.push(a_record);
        msg.answers.push(a_sig);
        msg.authorities.push(ds_record);
        msg.authorities.push(ds_sig);
        msg.additionals.push(Record::from_rdata(
            parent.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(parent_key)),
        ));
        msg.additionals.push(Record::from_rdata(
            child.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(child_key)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("ds-test"), now);

        assert_eq!(outcome, ValidationOutcome::Secure);
        assert!(msg.metadata.authentic_data);
    }
}
