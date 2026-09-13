//! `sito-dnssec`
//!
//! DNSSEC cryptographic validation engine supporting RFC 4033/4034/4035 verification,
//! root trust anchors, negative trust anchors (NTA), key caching, RFC 8914 extended DNS errors (EDE),
//! and validation metrics.

use std::collections::{HashMap, HashSet};
pub mod nsec;
pub mod nsec3;

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use tracing::{debug, warn};

use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, RRSIG, SIG};
use hickory_proto::dnssec::{
    Algorithm, DigestType, PublicKey, PublicKeyBuf, TrustAnchors, Verifier,
};
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{DNSClass, LowerName, Name, RData, Record, RecordType};
use nsec::{NsecDenial, NsecRecord, evaluate_nsec_denial};
use nsec3::{Nsec3Denial, Nsec3Record, evaluate_nsec3_denial};
use sito_core::DnssecKeyFetcher;
use sito_core::config::DnssecConfig;

/// Maximum number of DNSKEY records collected from a single response.
const MAX_DNSKEYS: usize = 64;
/// Maximum number of DS records considered from a single response.
const MAX_DS_RECORDS: usize = 64;
/// Maximum number of RRSIG records evaluated from a single response.
const MAX_RRSIGS: usize = 128;
/// Hard bound on the validated-key cache; DNSKEYs are re-discoverable.
const KEY_CACHE_MAX_ENTRIES: usize = 4096;
/// Hard bound on the known-signed-zone cache; zones are re-discoverable.
const SIGNED_ZONE_MAX_ENTRIES: usize = 8192;
/// Accepted clock skew around RRSIG inception/expiration (RFC 4035 5.3.1).
const MAX_CLOCK_SKEW: u32 = 300;
/// Minimum accepted RSA modulus size in bits (RFC 8624 3.1).
const MIN_RSA_BITS: usize = 2048;

/// Allowed DNSKEY algorithms (RFC 8624). ED448 is not supported by the
/// underlying crypto backend and is therefore not usable for validation.
fn allowed_dnskey_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::RSASHA256
            | Algorithm::RSASHA512
            | Algorithm::ECDSAP256SHA256
            | Algorithm::ECDSAP384SHA384
            | Algorithm::ED25519
    )
}

/// Allowed DS digest types (RFC 8624): SHA-256 and SHA-384 only.
fn allowed_ds_digest(digest: DigestType) -> bool {
    matches!(digest, DigestType::SHA256 | DigestType::SHA384)
}

/// Bit length of the RSA modulus in a DNSKEY public key (RFC 3110 encoding).
fn rsa_modulus_bits(encoded: &[u8]) -> Option<usize> {
    let (exponent_len, rest) = match encoded.split_first()? {
        (0, rest) if rest.len() >= 2 => {
            let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
            (len, &rest[2..])
        }
        (0, _) => return None,
        (len, rest) => (usize::from(*len), rest),
    };
    if exponent_len == 0 || rest.len() <= exponent_len {
        return None;
    }
    let modulus = &rest[exponent_len..];
    let significant = modulus.iter().position(|byte| *byte != 0)?;
    Some((modulus.len() - significant) * 8)
}

/// Whether a DNSKEY may be used for validation: zone key flag set, not
/// revoked, algorithm allowed by policy, and (for RSA) a modulus of at least
/// 2048 bits.
fn dnskey_policy_ok(key: &DNSKEY) -> bool {
    if !key.zone_key() || key.revoke() || !allowed_dnskey_algorithm(key.algorithm()) {
        return false;
    }
    match key.algorithm() {
        Algorithm::RSASHA256 | Algorithm::RSASHA512 => {
            rsa_modulus_bits(key.public_key().public_bytes())
                .is_some_and(|bits| bits >= MIN_RSA_BITS)
        }
        _ => true,
    }
}

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
    // Replace any previous EDE option instead of appending duplicates.
    edns.options_mut()
        .options
        .retain(|(option_code, _)| u16::from(*option_code) != 15);
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
/// used to mark a response `Secure`; unvalidated keys from response processing
/// are never inserted, and an existing unexpired validated entry is never
/// overwritten by an unvalidated one.
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
    ///
    /// An existing unexpired validated entry is never downgraded. Primarily a
    /// test/diagnostics helper: response processing must use
    /// [`Self::insert_validated`].
    pub fn insert(&self, name: LowerName, key_tag: u16, key: DNSKEY, expires_at: u32) {
        self.insert_with_now(name, key_tag, key, expires_at, Self::system_now());
    }

    /// Stores a key that has been linked to a trust anchor by the chain walk.
    pub fn insert_validated(&self, name: LowerName, key_tag: u16, key: DNSKEY, expires_at: u32) {
        self.insert_validated_with_now(name, key_tag, key, expires_at, Self::system_now());
    }

    /// [`Self::insert`] with an explicit `now` for deterministic callers.
    pub fn insert_with_now(
        &self,
        name: LowerName,
        key_tag: u16,
        key: DNSKEY,
        expires_at: u32,
        now: u32,
    ) {
        let keep_existing = self
            .keys
            .get(&(name.clone(), key_tag))
            .is_some_and(|entry| {
                let (_, existing_expiry, existing_validated) = entry.value();
                *existing_validated && now <= *existing_expiry
            });
        if keep_existing {
            return;
        }
        self.keys.insert((name, key_tag), (key, expires_at, false));
        self.enforce_bounds(now);
    }

    /// [`Self::insert_validated`] with an explicit `now` for deterministic
    /// callers.
    pub fn insert_validated_with_now(
        &self,
        name: LowerName,
        key_tag: u16,
        key: DNSKEY,
        expires_at: u32,
        now: u32,
    ) {
        self.keys.insert((name, key_tag), (key, expires_at, true));
        self.enforce_bounds(now);
    }

    /// Current UNIX timestamp truncated to the DNSSEC serial-number width.
    fn system_now() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32
    }

    /// Removes entries that are not valid at `now`; returns the number purged.
    pub fn purge_expired(&self, now: u32) -> usize {
        let before = self.keys.len();
        self.keys.retain(|_, (_, expires_at, _)| *expires_at >= now);
        before - self.keys.len()
    }

    /// Keeps the cache bounded: purge expired entries first and, if the cache
    /// is still oversized, clear it (keys are re-discoverable).
    fn enforce_bounds(&self, now: u32) {
        self.purge_expired(now);
        if self.keys.len() > KEY_CACHE_MAX_ENTRIES {
            self.keys.clear();
        }
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

/// CNAME target at `name` in the answer section, if any.
fn cname_target(response: &Message, name: &Name) -> Option<Name> {
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
fn negative_answer_name(response: &Message, qname: &Name) -> Name {
    let mut current = qname.clone();
    for _ in 0..16 {
        match cname_target(response, &current) {
            Some(next) => current = next,
            None => break,
        }
    }
    current
}

/// Whether a response is negative (NXDOMAIN, or a NODATA answer for the
/// queried name after following any CNAME chain).
fn is_negative_response(response: &Message, qname: &Name, qtype: RecordType) -> bool {
    if response.metadata.response_code == ResponseCode::NXDomain {
        return true;
    }
    if response.metadata.response_code != ResponseCode::NoError {
        return false;
    }
    let target = negative_answer_name(response, qname);
    !response.answers.iter().any(|record| {
        record.name == target && (record.record_type() == qtype || qtype == RecordType::ANY)
    })
}

/// RRsets that answer the question: the queried name/type, its CNAME (if any)
/// and every RRset along the CNAME chain.
fn relevant_answer_keys(
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

/// A signature that verified cryptographically with a key linked to a trust
/// anchor or to a validated chain.
struct TrustedSignature {
    owner: LowerName,
    covered: RecordType,
    signer: LowerName,
    signer_name: Name,
}

/// Outcome of enumerating NSEC/NSEC3 denial records for a negative response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DenialResult {
    /// A complete authenticated denial proof.
    Secure,
    /// Only an NSEC3 opt-out proof: an unsigned delegation may exist.
    OptOut,
    /// The available records do not enumerate a complete proof.
    Incomplete,
}

/// Enumerates NSEC/NSEC3 denial proofs using only signatures that verified
/// with validated keys, matched to their denial RRsets.
fn evaluate_denial(
    response: &Message,
    negative_name: &Name,
    negative_lower: &LowerName,
    qtype: RecordType,
    trusted_sigs: &[TrustedSignature],
) -> DenialResult {
    let nxdomain = response.metadata.response_code == ResponseCode::NXDomain;
    let mut secure = false;
    let mut opt_out = false;
    let mut nsec3_groups: HashMap<LowerName, Vec<Nsec3Record<'_>>> = HashMap::new();

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
                    let proof = evaluate_nsec_denial(
                        &[NsecRecord {
                            owner: &record.name,
                            rdata: nsec,
                        }],
                        negative_name,
                        qtype,
                        nxdomain,
                        &trusted.signer_name,
                    );
                    if proof == NsecDenial::Secure {
                        secure = true;
                    }
                }
                (_, Some(nsec3)) if trusted.covered == RecordType::NSEC3 => {
                    nsec3_groups
                        .entry(trusted.signer.clone())
                        .or_default()
                        .push(Nsec3Record {
                            owner: &record.name,
                            rdata: nsec3,
                        });
                }
                _ => {}
            }
        }
    }

    if secure {
        return DenialResult::Secure;
    }
    for records in nsec3_groups.values() {
        match evaluate_nsec3_denial(records, negative_name, qtype, nxdomain) {
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
/// anchored DNSKEY, at an unsigned delegation (no DS), after the root DNSKEY
/// has been fetched and matched, when the zone was already visited, or when the
/// budget is exhausted.
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

/// Result of the DS/DNSKEY trust-extension walk.
#[derive(Default)]
struct KeySetBuild {
    /// Keys linked to a trust anchor (directly, via DS, or via a validated
    /// DNSKEY RRset).
    validated: HashSet<(LowerName, u16)>,
    /// Zones whose DS RRset was validly signed by a validated parent but whose
    /// delegation failed the digest/algorithm policy.
    policy_rejected: HashSet<LowerName>,
    /// Zones whose DS RRset was validly signed by a validated parent but whose
    /// hierarchy or digest did not match (cross-zone or forged DS).
    forged: HashSet<LowerName>,
}

/// Aggregated state for one DS owner during the trust-extension walk.
#[derive(Default)]
struct DsLink {
    signed: bool,
    hierarchy_bad: bool,
    policy_bad: bool,
    child_present: bool,
    matched: bool,
}

/// Expiry for a validated key/zone: the minimum of the owner's TTL and the
/// matching signature expiration, defaulting to one hour.
fn key_record_expiry(response: &Message, owner: &Name, rrsigs: &[(Name, SIG)], now: u32) -> u32 {
    let ttl = response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .chain(response.additionals.iter())
        .filter(|record| record.name == *owner)
        .map(|record| record.ttl)
        .min()
        .unwrap_or(3600);
    let ttl_expiry = now.saturating_add(ttl);
    let sig_expiry = rrsigs
        .iter()
        .filter(|(sig_owner, _)| *sig_owner == *owner)
        .map(|(_, sig)| sig.input().sig_expiration.get())
        .min();
    sig_expiry.map_or(ttl_expiry, |e| e.min(ttl_expiry))
}

/// DNSSEC validation engine.
pub struct DnssecValidator {
    pub mode: DnssecMode,
    pub trust_anchors: Arc<ArcSwap<TrustAnchors>>,
    pub nta_domains: Arc<ArcSwap<Vec<String>>>,
    pub key_cache: KeyCache,
    pub metrics: Arc<DnssecMetrics>,
    /// Zones whose DS link or signature chain has been validated, with an
    /// expiry timestamp. A later response under one of these zones that carries
    /// no RRSIG is a stripped-signature downgrade and must not be Insecure.
    signed_zones: DashMap<LowerName, u32>,
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
            signed_zones: DashMap::new(),
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
                        10 => hickory_proto::dnssec::Algorithm::RSASHA512,
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
            norm == n || norm.ends_with(&format!(".{n}"))
        })
    }

    /// Records that `zone` was proven signed, valid until `expiry`.
    fn mark_signed_zone(&self, zone: &LowerName, expiry: u32) {
        self.signed_zones.insert(zone.clone(), expiry);
    }

    /// Whether `name` is inside a zone previously proven signed (and not
    /// expired), which makes a response without RRSIGs a downgrade attempt.
    fn signed_zone_contains(&self, name: &LowerName, now: u32) -> bool {
        if self.signed_zones.len() > SIGNED_ZONE_MAX_ENTRIES {
            self.signed_zones.retain(|_, expiry| *expiry >= now);
            if self.signed_zones.len() > SIGNED_ZONE_MAX_ENTRIES {
                self.signed_zones.clear();
            }
        }
        self.signed_zones
            .iter()
            .any(|entry| *entry.value() >= now && entry.key().zone_of(name))
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
    /// Delegations are only accepted when the RRSIG signer zone equals the
    /// parent DNSKEY owner, the parent is a strict ancestor of the DS owner,
    /// the child key owner equals the DS owner, and the DS digest/algorithm are
    /// allowed by policy (RFC 8624). The fixpoint is bounded and newly
    /// validated keys are cached with the minimum of the record TTL and the
    /// matching signature expiration.
    fn build_validated_key_set(
        &self,
        response: &Message,
        dnskeys: &[(Name, DNSKEY)],
        rrsigs: &[(Name, SIG)],
        now: u32,
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
            if anchored || self.key_cache.get_validated(&lower, tag, now).is_some() {
                result.validated.insert((lower.clone(), tag));
                let expiry = key_record_expiry(response, owner, rrsigs, now);
                self.mark_signed_zone(&lower, expiry);
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
        while changed && rounds < 16 {
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
                        .contains(&(lower_parent.clone(), parent_tag))
                    {
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
                        let Ok(tag) = child_key.calculate_key_tag() else {
                            continue;
                        };
                        link.matched = true;
                        if result.validated.insert((lower_ds.clone(), tag)) {
                            changed = true;
                        }
                        let expiry = key_record_expiry(response, ds_owner, rrsigs, now);
                        self.mark_signed_zone(&lower_ds, expiry);
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
                if !result.validated.contains(&(lower.clone(), tag)) {
                    continue;
                }
                let rrset_signed = rrsigs.iter().any(|(sig_owner, sig)| {
                    sig_owner == owner
                        && sig.input().type_covered == RecordType::DNSKEY
                        && LowerName::from(&sig.input().signer_name) == lower
                        && sig.input().key_tag == tag
                        && verify_rrsig_covered(response, owner, sig, signer_key)
                });
                if !rrset_signed {
                    continue;
                }
                for (other_owner, other_key) in dnskeys {
                    if other_owner != owner || !dnskey_policy_ok(other_key) {
                        continue;
                    }
                    if let Ok(other_tag) = other_key.calculate_key_tag()
                        && result
                            .validated
                            .insert((LowerName::from(other_owner), other_tag))
                    {
                        changed = true;
                    }
                }
                let expiry = key_record_expiry(response, owner, rrsigs, now);
                self.mark_signed_zone(&lower, expiry);
            }
        }

        for (owner, link) in &ds_links {
            if link.hierarchy_bad {
                result.forged.insert(owner.clone());
            } else if link.signed && link.policy_bad && !link.matched {
                result.policy_rejected.insert(owner.clone());
            } else if link.signed && link.child_present && !link.matched {
                result.forged.insert(owner.clone());
            }
        }

        for (lower, tag) in &result.validated {
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
                .insert_validated_with_now(lower.clone(), *tag, key.clone(), expiry, now);
        }

        result
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
            let outcome = ValidationOutcome::Indeterminate;
            self.metrics.record_validation(&outcome);
            return outcome;
        };
        let qname = query.name().clone();
        let qtype = query.query_type();
        let qname_lower = LowerName::from(&qname);

        // Collect DNSKEY records from the response (bounded).
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

        // Collect RRSIG/SIG records (bounded).
        let mut rrsigs = Vec::new();
        for record in response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .chain(response.additionals.iter())
        {
            if rrsigs.len() >= MAX_RRSIGS {
                break;
            }
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

        // A response without RRSIGs under a zone already proven signed is a
        // signature-stripping downgrade, not an unsigned zone.
        if rrsigs.is_empty() {
            response.metadata.authentic_data = false;
            if self.signed_zone_contains(&qname_lower, now) {
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
        let key_set = self.build_validated_key_set(response, &response_dnskeys, &rrsigs, now);

        // Validate each RRSIG. Secure/AD is granted only when the answer RRset
        // relevant to the question (or a complete denial proof) is covered by a
        // signature that verified with a chain-validated key.
        let anchors = self.trust_anchors.load();
        let mut first_failure: Option<(&'static str, u16)> = None;
        let mut policy_violation = false;
        let mut has_trusted_sig = false;
        let mut trusted_covered: HashSet<(LowerName, RecordType)> = HashSet::new();
        let mut trusted_sigs: Vec<TrustedSignature> = Vec::new();
        let mut trusted_signer_covers_qname = false;

        for (rrsig_owner, rrsig) in &rrsigs {
            let inception = rrsig.input().sig_inception.get();
            let expiration = rrsig.input().sig_expiration.get();

            // RFC 4035 5.3.1 with a bounded clock skew: a signature is usable
            // within +/- 300 s of its validity window.
            if now.saturating_add(MAX_CLOCK_SKEW) < inception {
                first_failure.get_or_insert(("Signature not yet valid", EDE_DNSSEC_BOGUS));
                continue;
            }
            if now > expiration.saturating_add(MAX_CLOCK_SKEW) {
                first_failure.get_or_insert(("Signature expired", EDE_SIGNATURE_EXPIRED));
                continue;
            }

            let type_covered = rrsig.input().type_covered;
            let signer_name = &rrsig.input().signer_name;
            let key_tag = rrsig.input().key_tag;

            // Find the matching DNSKEY: first the validated-key cache, then the
            // response itself. The algorithm must match too (RFC 4035 5.3.1).
            // Keys from the response are never cached before they have been
            // linked to a trust anchor.
            let lower_signer = LowerName::from(signer_name);
            let cached_key = self
                .key_cache
                .get(&lower_signer, key_tag, now)
                .filter(|key| key.algorithm() == rrsig.input().algorithm);
            self.metrics.record_key_cache(cached_key.is_some());
            let mut matching_key = cached_key;

            if matching_key.is_none() {
                for (key_owner, dnskey) in &response_dnskeys {
                    if key_owner == signer_name
                        && dnskey.algorithm() == rrsig.input().algorithm
                        && let Ok(tag) = dnskey.calculate_key_tag()
                        && tag == key_tag
                    {
                        matching_key = Some(dnskey.clone());
                        break;
                    }
                }
            }

            let Some(dnskey) = matching_key else {
                // No usable key material: the chain fetch path may resolve it.
                continue;
            };

            if !dnskey_policy_ok(&dnskey) {
                // Signatures exist but every usable key was rejected by
                // policy; this must not silently downgrade to Insecure.
                policy_violation = true;
                continue;
            }

            let covered_records: Vec<&Record> = response
                .answers
                .iter()
                .chain(response.authorities.iter())
                .chain(response.additionals.iter())
                .filter(|r| r.record_type() == type_covered && r.name == *rrsig_owner)
                .collect();

            // An RRSIG that covers nothing in the response cannot authenticate
            // anything and is a validation failure.
            if covered_records.is_empty() {
                first_failure.get_or_insert((
                    "RRSIG does not cover any records in the response",
                    EDE_DNSSEC_BOGUS,
                ));
                continue;
            }

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

            // Check if DNSKEY is trusted (anchor, validated chain, or cache)
            let is_trusted = anchors.contains(dnskey.public_key())
                || anchors.contains_with_name(dnskey.public_key(), &lower_signer)
                || key_set.validated.contains(&(lower_signer.clone(), key_tag))
                || self
                    .key_cache
                    .get_validated(&lower_signer, key_tag, now)
                    .is_some();

            if !is_trusted {
                continue;
            }

            has_trusted_sig = true;
            trusted_covered.insert((LowerName::from(rrsig_owner), type_covered));
            if lower_signer.zone_of(&qname_lower) {
                trusted_signer_covers_qname = true;
            }
            self.mark_signed_zone(&lower_signer, expiration);
            trusted_sigs.push(TrustedSignature {
                owner: LowerName::from(rrsig_owner),
                covered: type_covered,
                signer: lower_signer,
                signer_name: signer_name.clone(),
            });
        }

        // Secure/AD is granted only for the positive answer RRset(s) relevant
        // to the question (including a CNAME chain) or for a complete
        // NSEC/NSEC3 denial proof. Unrelated signatures never grant AD.
        let relevant = relevant_answer_keys(response, &qname, qtype);
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

        let negative = is_negative_response(response, &qname, qtype);
        let negative_name = if negative {
            negative_answer_name(response, &qname)
        } else {
            qname.clone()
        };
        let negative_lower = LowerName::from(&negative_name);

        if negative {
            let denial = if trusted_sigs.is_empty() {
                DenialResult::Incomplete
            } else {
                evaluate_denial(
                    response,
                    &negative_name,
                    &negative_lower,
                    qtype,
                    &trusted_sigs,
                )
            };
            match denial {
                DenialResult::Secure if all_present_signed || present_relevant.is_empty() => {
                    return self.secure_outcome(response);
                }
                DenialResult::Secure => {
                    return self.handle_bogus(
                        response,
                        upstream,
                        "CNAME chain is not signed by a validated zone key",
                        EDE_DNSSEC_BOGUS,
                    );
                }
                DenialResult::OptOut => {
                    // RFC 5155: only an explicit opt-out downgrades to
                    // insecure; every other incomplete proof is bogus.
                    debug!("NSEC3 opt-out proof found; negative response treated as insecure");
                    response.metadata.authentic_data = false;
                    let outcome = ValidationOutcome::Insecure;
                    self.metrics.record_validation(&outcome);
                    return outcome;
                }
                DenialResult::Incomplete => {
                    let would_be_secure = has_trusted_sig
                        || all_present_signed
                        || self.signed_zone_contains(&qname_lower, now);
                    if would_be_secure {
                        return self.handle_bogus(
                            response,
                            upstream,
                            "Negative response lacks a valid NSEC/NSEC3 denial proof",
                            EDE_DNSSEC_BOGUS,
                        );
                    }
                }
            }
        } else if all_present_signed {
            return self.secure_outcome(response);
        }

        if !key_set.forged.is_empty() {
            return self.handle_bogus(
                response,
                upstream,
                "Cross-zone or forged DS record signed by a validated key",
                EDE_DNSSEC_BOGUS,
            );
        }
        if !key_set.policy_rejected.is_empty() {
            return self.handle_bogus(
                response,
                upstream,
                "DNSSEC algorithm or digest not allowed by policy",
                EDE_DNSSEC_BOGUS,
            );
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
        if self.signed_zone_contains(&qname_lower, now) || trusted_signer_covers_qname {
            return self.handle_bogus(
                response,
                upstream,
                "Missing RRSIG for zone previously proven signed",
                EDE_DNSSEC_BOGUS,
            );
        }
        if has_trusted_sig {
            return self.handle_bogus(
                response,
                upstream,
                "No valid RRSIG covers the answer RRset",
                EDE_DNSSEC_BOGUS,
            );
        }

        // RRSIGs were present and valid, but could not link to a trust anchor.
        response.metadata.authentic_data = false;
        let outcome = ValidationOutcome::Indeterminate;
        self.metrics.record_validation(&outcome);
        outcome
    }

    /// Marks a response secure and records the outcome.
    fn secure_outcome(&self, response: &mut Message) -> ValidationOutcome {
        response.metadata.authentic_data = true;
        let outcome = ValidationOutcome::Secure;
        self.metrics.record_validation(&outcome);
        outcome
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
    use hickory_proto::rr::RecordData;
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

    #[allow(clippy::too_many_arguments)]
    fn signed_nsec_response(
        origin: &Name,
        nsec_owner: &Name,
        next: &Name,
        bitmap: &[RecordType],
        qname: &Name,
        dnskey: &DNSKEY,
        signer: &hickory_proto::dnssec::DnssecSigner,
        response_code: ResponseCode,
    ) -> Message {
        use hickory_proto::dnssec::rdata::NSEC;
        use hickory_proto::rr::RecordSet;

        let nsec = NSEC::new(next.clone(), bitmap.iter().copied());
        let nsec_record = Record::from_rdata(
            nsec_owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC(nsec)),
        );
        let mut set = RecordSet::new(nsec_owner.clone(), RecordType::NSEC, 0);
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

    fn nsec_next(origin: &Name) -> Name {
        Name::from_str(&format!("zzz.{}", origin.to_ascii())).unwrap()
    }

    #[test]
    fn test_nxdomain_with_nsec_is_secure() {
        let (origin, dnskey, signer) = create_test_signer("nsec.example.");
        let qname = Name::from_str("missing.nsec.example.").unwrap();

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut msg = signed_nsec_response(
            &origin,
            &origin,
            &nsec_next(&origin),
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
            &qname,
            &dnskey,
            &signer,
            ResponseCode::NXDomain,
        );
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

        // A correct NSEC NODATA proof sits at the queried name and its bitmap
        // denies both the queried type and CNAME.
        let mut msg = signed_nsec_response(
            &origin,
            &qname,
            &nsec_next(&origin),
            &[RecordType::SOA, RecordType::NSEC, RecordType::RRSIG],
            &qname,
            &dnskey,
            &signer,
            ResponseCode::NoError,
        );
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("test"), now);

        assert_eq!(outcome, ValidationOutcome::Secure);
    }

    #[test]
    fn test_nodata_with_wrong_nsec_bitmap_is_bogus() {
        let (origin, dnskey, signer) = create_test_signer("nsec.example.");
        let qname = Name::from_str("empty.nsec.example.").unwrap();

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        // The bitmap still lists A at the queried name: no denial proof.
        let mut msg = signed_nsec_response(
            &origin,
            &qname,
            &nsec_next(&origin),
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
            &qname,
            &dnskey,
            &signer,
            ResponseCode::NoError,
        );
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("test"), now);

        assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
        assert!(!msg.metadata.authentic_data);
    }

    #[test]
    fn test_nxdomain_with_wrong_nsec_owner_is_bogus() {
        let (origin, dnskey, signer) = create_test_signer("nsec.example.");
        let qname = Name::from_str("missing.nsec.example.").unwrap();

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        // Owner "aaa" / next "bbb" does not cover "missing".
        let mut msg = signed_nsec_response(
            &origin,
            &Name::from_str("aaa.nsec.example.").unwrap(),
            &Name::from_str("bbb.nsec.example.").unwrap(),
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
            &qname,
            &dnskey,
            &signer,
            ResponseCode::NXDomain,
        );
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("test"), now);

        assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
        assert!(!msg.metadata.authentic_data);
    }

    #[test]
    fn test_negative_response_with_untrusted_nsec_is_not_secure() {
        let (origin, dnskey, signer) = create_test_signer("nsec.example.");
        let qname = Name::from_str("missing.nsec.example.").unwrap();

        // No anchors: the denial signature verifies cryptographically but the
        // covering zone is not linked to a trust anchor.
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());

        let mut msg = signed_nsec_response(
            &origin,
            &origin,
            &nsec_next(&origin),
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
            &qname,
            &dnskey,
            &signer,
            ResponseCode::NXDomain,
        );
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("test"), now);

        assert_eq!(outcome, ValidationOutcome::Indeterminate);
        assert!(!msg.metadata.authentic_data);
    }

    fn signed_optout_nxdomain(
        origin: &Name,
        qname: &Name,
        dnskey: &DNSKEY,
        signer: &hickory_proto::dnssec::DnssecSigner,
        opt_out: bool,
        iterations: u16,
    ) -> Message {
        use data_encoding::BASE32_DNSSEC;
        use hickory_proto::dnssec::Nsec3HashAlgorithm;
        use hickory_proto::dnssec::rdata::NSEC3;
        use hickory_proto::rr::RecordSet;

        let alg = Nsec3HashAlgorithm::SHA1;
        let encloser_hash = alg.hash(&[], origin, iterations).unwrap().as_ref().to_vec();
        let qname_hash = alg.hash(&[], qname, iterations).unwrap().as_ref().to_vec();
        let mut next = qname_hash.clone();
        for byte in next.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        let nsec3 = NSEC3::new(
            alg,
            opt_out,
            iterations,
            Vec::new(),
            next,
            [RecordType::SOA, RecordType::RRSIG, RecordType::NSEC3],
        );
        let owner = Name::from_ascii(format!(
            "{}.{}",
            BASE32_DNSSEC.encode(&encloser_hash),
            origin.to_ascii()
        ))
        .unwrap();
        let nsec3_record =
            Record::from_rdata(owner.clone(), 300, RData::DNSSEC(DNSSECRData::NSEC3(nsec3)));
        let mut set = RecordSet::new(owner, RecordType::NSEC3, 0);
        set.insert(nsec3_record.clone(), 0);
        let signature = sign_test_rrset(&set, signer);

        let mut msg = Message::new(25, MessageType::Response, OpCode::Query);
        msg.queries.push(Query::query(qname.clone(), RecordType::A));
        msg.metadata.response_code = ResponseCode::NXDomain;
        msg.authorities.push(nsec3_record);
        msg.authorities.push(signature);
        msg.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
        ));
        msg
    }

    #[test]
    fn test_nxdomain_optout_nsec3_is_insecure() {
        let (origin, dnskey, signer) = create_test_signer("example.");
        let qname = Name::from_str("missing.example.").unwrap();

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut msg = signed_optout_nxdomain(&origin, &qname, &dnskey, &signer, true, 0);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("test"), now);

        assert_eq!(outcome, ValidationOutcome::Insecure);
        assert!(!msg.metadata.authentic_data);
    }

    #[test]
    fn test_nxdomain_nsec3_without_optout_stays_secure() {
        let (origin, dnskey, signer) = create_test_signer("example.");
        let qname = Name::from_str("missing.example.").unwrap();

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut msg = signed_optout_nxdomain(&origin, &qname, &dnskey, &signer, false, 0);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("test"), now);

        assert_eq!(outcome, ValidationOutcome::Secure);
        assert!(msg.metadata.authentic_data);
    }

    #[test]
    fn test_nsec3_iterations_over_cap_not_secure() {
        let (origin, dnskey, signer) = create_test_signer("example.");
        let qname = Name::from_str("missing.example.").unwrap();

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        // RFC 9276: proofs above 150 iterations must not be accepted.
        let mut msg = signed_optout_nxdomain(&origin, &qname, &dnskey, &signer, false, 151);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("test"), now);

        assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
        assert!(!msg.metadata.authentic_data);
    }

    #[test]
    fn test_key_cache_ignores_unvalidated_response_keys() {
        let (origin, dnskey, a_record, rrsig_record, _) =
            create_test_signed_domain("kcache.example.");

        // No trust anchors: signatures verify but the chain is not linked, so
        // the key must never be cached (an attacker-supplied DNSKEY must not
        // outlive the response and poison later validations).
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
            let outcome = validator.validate_response(&mut msg, Some("cache-test"), now);
            assert_eq!(outcome, ValidationOutcome::Indeterminate);
        }

        assert!(validator.key_cache.is_empty());
        assert_eq!(validator.metrics.key_cache_misses(), 2);
        assert_eq!(validator.metrics.key_cache_hits(), 0);
    }

    #[test]
    fn test_key_cache_does_not_downgrade_validated_entry() {
        let (name, valid, _) = create_test_signer("cache.example.");
        let (_, attacker, _) = create_test_signer("cache.example.");
        let tag = valid.calculate_key_tag().unwrap();
        let lower = LowerName::from(&name);
        let now = 1_000_000u32;

        let cache = KeyCache::new();
        cache.insert_validated_with_now(lower.clone(), tag, valid.clone(), now + 300, now);
        cache.insert_with_now(lower.clone(), tag, attacker.clone(), now + 600, now);

        let cached = cache
            .get_validated(&lower, tag, now)
            .expect("validated key");
        assert_eq!(cached, valid);
        assert_eq!(
            cache.get(&lower, tag, now).expect("cached key"),
            valid,
            "an unvalidated insert must not overwrite a live validated entry"
        );
    }

    #[test]
    fn test_key_cache_purges_expired_and_stays_bounded() {
        let (name, key, _) = create_test_signer("purge.example.");
        let lower = LowerName::from(&name);
        let cache = KeyCache::new();
        let now = 2_000_000u32;
        let insert_now = now - 10;

        cache.insert_validated_with_now(lower.clone(), 1, key.clone(), now - 1, insert_now);
        cache.insert_validated_with_now(lower.clone(), 2, key.clone(), now + 60, insert_now);
        assert_eq!(cache.purge_expired(now), 1);
        assert!(cache.get_validated(&lower, 1, now).is_none());
        assert!(cache.get_validated(&lower, 2, now).is_some());

        // Once the cache exceeds its bound it is cleared: keys are
        // re-discoverable, and an unbounded cache is a memory-exhaustion risk.
        for tag in 0..=(KEY_CACHE_MAX_ENTRIES as u16) {
            cache.insert_validated_with_now(lower.clone(), tag, key.clone(), now + 60, now);
        }
        assert!(cache.len() <= KEY_CACHE_MAX_ENTRIES);
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
                fetched_dnskey_message(&parent, std::slice::from_ref(&parent_key), None),
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

    fn sign_rrset_with_window(
        set: &hickory_proto::rr::RecordSet,
        signer: &hickory_proto::dnssec::DnssecSigner,
        inception: time::OffsetDateTime,
    ) -> Record {
        let rrsig = RRSIG::from_rrset(set, DNSClass::IN, inception, signer).expect("sign windowed");
        Record::from_rdata(set.name().clone(), 300, rrsig.into_rdata())
    }

    fn time_at(base: u32, offset_secs: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(i64::from(base) + offset_secs).unwrap()
    }

    #[test]
    fn test_clock_skew_boundaries() {
        use hickory_proto::rr::RecordSet;

        let (origin, dnskey, signer) = create_test_signer("skew.example.");
        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let a_record = Record::from_rdata(
            origin.clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 9))),
        );
        let mut set = RecordSet::new(origin.clone(), RecordType::A, 0);
        set.insert(a_record.clone(), 0);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let validate = |inception_offset: i64| {
            let sig = sign_rrset_with_window(&set, &signer, time_at(now, inception_offset));
            let mut msg = Message::new(30, MessageType::Response, OpCode::Query);
            msg.queries
                .push(Query::query(origin.clone(), RecordType::A));
            msg.answers.push(a_record.clone());
            msg.answers.push(sig);
            msg.additionals.push(Record::from_rdata(
                origin.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
            ));
            let outcome = validator.validate_response(&mut msg, Some("skew"), now);
            (outcome, msg.metadata.authentic_data)
        };

        // Window [now+300, now+3900]: now is exactly at inception-300.
        let (outcome, ad) = validate(300);
        assert_eq!(outcome, ValidationOutcome::Secure, "inception boundary");
        assert!(ad);
        // One second past the allowed skew: not yet valid.
        let (outcome, ad) = validate(301);
        assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
        assert!(!ad);

        // Window [now-3900, now-300]: now is exactly at expiration+300.
        let (outcome, ad) = validate(-3900);
        assert_eq!(outcome, ValidationOutcome::Secure, "expiration boundary");
        assert!(ad);
        // One second past the allowed skew: expired.
        let (outcome, ad) = validate(-3901);
        assert_eq!(
            outcome,
            ValidationOutcome::Bogus {
                reason: "Signature expired".to_string(),
                ede_code: EDE_SIGNATURE_EXPIRED,
            }
        );
        assert!(!ad);
    }

    #[test]
    fn test_stripped_rrsig_under_signed_zone_is_bogus() {
        let (origin, dnskey, a_record, rrsig_record, _) =
            create_test_signed_domain("strip.example.");
        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        let signed_message = |id: u16| {
            let mut msg = Message::new(id, MessageType::Response, OpCode::Query);
            msg.queries
                .push(Query::query(origin.clone(), RecordType::A));
            msg.answers.push(a_record.clone());
            msg.answers.push(rrsig_record.clone());
            msg.additionals.push(Record::from_rdata(
                origin.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
            ));
            msg
        };
        let stripped_message = |id: u16| {
            let other = Name::from_str("other.strip.example.").unwrap();
            let mut msg = Message::new(id, MessageType::Response, OpCode::Query);
            msg.queries.push(Query::query(other.clone(), RecordType::A));
            msg.answers.push(Record::from_rdata(
                other,
                300,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 66))),
            ));
            msg
        };

        // Establish that the zone is signed.
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new())
            .with_trust_anchors(anchors.clone());
        let mut signed = signed_message(31);
        assert_eq!(
            validator.validate_response(&mut signed, Some("strip"), now),
            ValidationOutcome::Secure
        );

        // A later response under the same zone with the signatures stripped.
        let mut stripped = stripped_message(32);
        let outcome = validator.validate_response(&mut stripped, Some("strip"), now);
        assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
        assert_eq!(stripped.metadata.response_code, ResponseCode::ServFail);
        assert!(!stripped.metadata.authentic_data);

        // Log-only mode clears AD but keeps the (potentially cached) answer.
        let log_only =
            DnssecValidator::new(DnssecMode::LogOnly, Vec::new()).with_trust_anchors(anchors);
        let mut signed = signed_message(33);
        assert_eq!(
            log_only.validate_response(&mut signed, Some("strip"), now),
            ValidationOutcome::Secure
        );
        let mut stripped = stripped_message(34);
        let outcome = log_only.validate_response(&mut stripped, Some("strip"), now);
        assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
        assert_eq!(stripped.metadata.response_code, ResponseCode::NoError);
        assert!(!stripped.metadata.authentic_data);
        assert!(!stripped.answers.is_empty());
    }

    #[test]
    fn test_empty_coverage_rrsig_is_bogus() {
        let (origin, dnskey, _a_record, rrsig_record, _) =
            create_test_signed_domain("emptycov.example.");
        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        // The RRSIG claims to cover A at origin but no A record is present.
        let mut msg = Message::new(34, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        msg.answers.push(rrsig_record);
        msg.additionals.push(Record::from_rdata(
            origin,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("emptycov"), now);

        assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
        assert!(!msg.metadata.authentic_data);
        assert_ne!(outcome, ValidationOutcome::Secure);
    }

    #[test]
    fn test_unrelated_valid_rrsig_does_not_grant_ad() {
        let (origin, dnskey, a_record, rrsig_record, _) = create_test_signed_domain("rel.example.");
        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let victim = Name::from_str("victim.rel.example.").unwrap();
        let mut msg = Message::new(35, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(victim.clone(), RecordType::A));
        // A forged, unsigned answer for the queried name...
        msg.answers.push(Record::from_rdata(
            victim,
            300,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 66))),
        ));
        // ...plus a perfectly valid signature for an unrelated RRset.
        msg.answers.push(a_record);
        msg.answers.push(rrsig_record);
        msg.additionals.push(Record::from_rdata(
            origin,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("rel"), now);

        assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
        assert!(!msg.metadata.authentic_data);
    }

    #[test]
    fn test_cross_zone_ds_is_rejected() {
        use hickory_proto::dnssec::DigestType;
        use hickory_proto::rr::RecordSet;

        let (attacker, attacker_key, attacker_signer) = create_test_signer("attacker.example.");
        let (victim, victim_key, victim_signer) = create_test_signer("victim.example.");
        let (answer, answer_sig) = signed_a_response(&victim, &victim_signer);

        // A DS for victim.example signed by attacker.example's validated key.
        let ds = DS::from_key(victim_key.public_key(), &victim, DigestType::SHA256).unwrap();
        let ds_record = Record::from_rdata(victim.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
        let mut ds_set = RecordSet::new(victim.clone(), RecordType::DS, 0);
        ds_set.insert(ds_record.clone(), 0);
        let ds_sig = sign_test_rrset(&ds_set, &attacker_signer);

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(attacker_key.public_key(), LowerName::from(&attacker));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut msg = Message::new(36, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(victim.clone(), RecordType::A));
        msg.answers.push(answer);
        msg.answers.push(answer_sig);
        msg.authorities.push(ds_record);
        msg.authorities.push(ds_sig);
        msg.additionals.push(Record::from_rdata(
            attacker,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(attacker_key)),
        ));
        msg.additionals.push(Record::from_rdata(
            victim,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(victim_key)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("cross-zone"), now);

        assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
        assert!(!msg.metadata.authentic_data);
    }

    #[test]
    fn test_ds_sha1_digest_is_bogus() {
        use hickory_proto::dnssec::DigestType;
        use hickory_proto::rr::RecordSet;

        let (parent, parent_key, parent_signer) = create_test_signer("example.");
        let (child, child_key, child_signer) = create_test_signer("sha1.example.");
        let (answer, answer_sig) = signed_a_response(&child, &child_signer);

        let ds = DS::from_key(child_key.public_key(), &child, DigestType::SHA1).unwrap();
        let ds_record = Record::from_rdata(child.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
        let mut ds_set = RecordSet::new(child.clone(), RecordType::DS, 0);
        ds_set.insert(ds_record.clone(), 0);
        let ds_sig = sign_test_rrset(&ds_set, &parent_signer);

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(parent_key.public_key(), LowerName::from(&parent));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut msg = Message::new(37, MessageType::Response, OpCode::Query);
        msg.queries.push(Query::query(child.clone(), RecordType::A));
        msg.answers.push(answer);
        msg.answers.push(answer_sig);
        msg.authorities.push(ds_record);
        msg.authorities.push(ds_sig);
        msg.additionals.push(Record::from_rdata(
            parent,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(parent_key)),
        ));
        msg.additionals.push(Record::from_rdata(
            child,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(child_key)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("sha1-ds"), now);

        assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
        assert!(!msg.metadata.authentic_data);
    }

    #[test]
    fn test_ds_rsasha1_algorithm_is_bogus() {
        use hickory_proto::dnssec::DigestType;
        use hickory_proto::rr::RecordSet;

        let (parent, parent_key, parent_signer) = create_test_signer("example.");
        let (child, child_key, child_signer) = create_test_signer("sha1alg.example.");
        let (answer, answer_sig) = signed_a_response(&child, &child_signer);

        // RSASHA1 (algorithm 5) is forbidden by RFC 8624; build the DS
        // without a matching key (policy rejects it before digest matching).
        let ds = DS::new(
            child_key.calculate_key_tag().unwrap(),
            hickory_proto::dnssec::Algorithm::from_u8(5),
            DigestType::SHA256,
            vec![0u8; 32],
        );
        let ds_record = Record::from_rdata(child.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
        let mut ds_set = RecordSet::new(child.clone(), RecordType::DS, 0);
        ds_set.insert(ds_record.clone(), 0);
        let ds_sig = sign_test_rrset(&ds_set, &parent_signer);

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(parent_key.public_key(), LowerName::from(&parent));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut msg = Message::new(38, MessageType::Response, OpCode::Query);
        msg.queries.push(Query::query(child.clone(), RecordType::A));
        msg.answers.push(answer);
        msg.answers.push(answer_sig);
        msg.authorities.push(ds_record);
        msg.authorities.push(ds_sig);
        msg.additionals.push(Record::from_rdata(
            parent,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(parent_key)),
        ));
        msg.additionals.push(Record::from_rdata(
            child,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(child_key)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("rsasha1-ds"), now);

        assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
        assert!(!msg.metadata.authentic_data);
    }

    #[test]
    fn test_ed25519_keys_validate() {
        use hickory_proto::dnssec::SigningKey;
        use hickory_proto::dnssec::crypto::Ed25519SigningKey;
        use hickory_proto::rr::RecordSet;

        let origin = Name::from_str("ed25519.example.").unwrap();
        let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
        let key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
        let pub_key = key.to_public_key().unwrap();
        let dnskey = DNSKEY::from_key(&pub_key);
        let signer = hickory_proto::dnssec::DnssecSigner::new(
            dnskey.clone(),
            Box::new(key),
            origin.clone(),
            Duration::from_secs(3600),
        );

        let a_record = Record::from_rdata(
            origin.clone(),
            300,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 42))),
        );
        let mut set = RecordSet::new(origin.clone(), RecordType::A, 0);
        set.insert(a_record.clone(), 0);
        let rrsig = sign_test_rrset(&set, &signer);

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut msg = Message::new(39, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        msg.answers.push(a_record);
        msg.answers.push(rrsig);
        msg.additionals.push(Record::from_rdata(
            origin,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("ed25519"), now);

        assert_eq!(outcome, ValidationOutcome::Secure);
        assert!(msg.metadata.authentic_data);
    }

    #[tokio::test]
    async fn test_root_walk_matches_default_anchor() {
        let anchors = TrustAnchors::default();
        let anchor = anchors.get(0).expect("default root anchor").clone();
        let root = Name::root();
        let root_key = DNSKEY::with_flags(257, anchor);
        let fetcher = StaticFetcher::new().with(
            &root,
            RecordType::DNSKEY,
            fetched_dnskey_message(&root, &[root_key], None),
        );

        let mut budget = 1u8;
        let mut visited = HashSet::new();
        let mut response = Message::new(40, MessageType::Response, OpCode::Query);
        let result = fetch_zone_chain(
            &anchors,
            &fetcher,
            &root,
            &mut budget,
            &mut visited,
            &mut response,
        )
        .await;

        assert_eq!(result, Some(()));
        assert_eq!(fetcher.calls(), 1, "the root DNSKEY must be fetched");
        assert!(
            response
                .additionals
                .iter()
                .any(|record| matches!(&record.data, RData::DNSSEC(DNSSECRData::DNSKEY(_))))
        );
    }

    #[test]
    fn test_root_dnskey_matching_default_anchor_is_validated() {
        let anchors = TrustAnchors::default();
        let anchor = anchors.get(0).expect("default root anchor").clone();
        let root = Name::root();
        let root_key = DNSKEY::with_flags(257, anchor);
        let tag = root_key.calculate_key_tag().unwrap();
        let lower = LowerName::from(&root);

        // `DnssecValidator::new` uses the default root anchors.
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        let mut response = Message::new(44, MessageType::Response, OpCode::Query);
        response.additionals.push(Record::from_rdata(
            root.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(root_key.clone())),
        ));
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let dnskeys = vec![(root.clone(), root_key)];
        let result = validator.build_validated_key_set(&response, &dnskeys, &[], now);

        assert!(result.validated.contains(&(lower.clone(), tag)));
        assert!(result.forged.is_empty());
        assert!(result.policy_rejected.is_empty());
        assert!(
            validator
                .key_cache
                .get_validated(&lower, tag, now)
                .is_some(),
            "a root DNSKEY matching the default anchor must be cached as validated"
        );
    }

    #[tokio::test]
    async fn test_root_walk_fetches_root_dnskey_and_validates() {
        use hickory_proto::dnssec::DigestType;
        use hickory_proto::rr::RecordSet;

        let (root_name, root_key, root_signer) = create_test_signer(".");
        assert_eq!(root_name, Name::root());
        let (zone, zone_key, zone_signer) = create_test_signer("example.");
        let www = Name::from_str("www.example.").unwrap();
        let (answer, answer_sig) = signed_a_response(&www, &zone_signer);

        let ds = DS::from_key(zone_key.public_key(), &zone, DigestType::SHA256).unwrap();
        let ds_record = Record::from_rdata(zone.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
        let mut ds_set = RecordSet::new(zone.clone(), RecordType::DS, 0);
        ds_set.insert(ds_record.clone(), 0);
        let ds_sig = sign_test_rrset(&ds_set, &root_signer);

        let mut ds_message = Message::new(0, MessageType::Response, OpCode::Query);
        ds_message.authorities.push(ds_record);
        ds_message.authorities.push(ds_sig);

        let fetcher = StaticFetcher::new()
            .with(
                &zone,
                RecordType::DNSKEY,
                fetched_dnskey_message(&zone, &[zone_key], None),
            )
            .with(&zone, RecordType::DS, ds_message)
            .with(
                &root_name,
                RecordType::DNSKEY,
                fetched_dnskey_message(&root_name, std::slice::from_ref(&root_key), None),
            );

        // The real root KSK cannot sign test data, so the test root key is
        // added as a root anchor alongside the defaults.
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        validator.add_trust_anchor(&root_key, LowerName::from(&root_name));

        let mut response = Message::new(41, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(www.clone(), RecordType::A));
        response.answers.push(answer);
        response.answers.push(answer_sig);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("root-test"), now, &fetcher)
            .await;

        assert_eq!(outcome, ValidationOutcome::Secure);
        assert!(response.metadata.authentic_data);
        // DNSKEY(zone), DS(zone), DNSKEY(root).
        assert_eq!(fetcher.calls(), 3);
    }

    #[test]
    fn test_nta_root_matches_all_names() {
        let validator = DnssecValidator::new(DnssecMode::Validate, vec![".".to_string()]);
        assert!(validator.is_nta(&Name::root()));
        assert!(validator.is_nta(&Name::from_str("example.").unwrap()));
        assert!(validator.is_nta(&Name::from_str("www.example.").unwrap()));
    }

    #[test]
    fn test_nta_evaluated_across_all_questions() {
        let validator =
            DnssecValidator::new(DnssecMode::Validate, vec!["internal.corp".to_string()]);
        let mut msg = Message::new(42, MessageType::Response, OpCode::Query);
        msg.queries.push(Query::query(
            Name::from_str("public.example.").unwrap(),
            RecordType::A,
        ));
        msg.queries.push(Query::query(
            Name::from_str("host.internal.corp.").unwrap(),
            RecordType::A,
        ));
        msg.answers.push(Record::from_rdata(
            Name::from_str("public.example.").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, None, now);

        assert_eq!(outcome, ValidationOutcome::NtaBypass);
        assert!(!msg.metadata.authentic_data);
    }

    #[test]
    fn test_apply_ede_replaces_existing_option() {
        let mut msg = Message::new(43, MessageType::Response, OpCode::Query);
        apply_ede(&mut msg, EDE_DNSSEC_BOGUS, "first");
        apply_ede(&mut msg, EDE_DNSSEC_BOGUS, "second");
        let edns = msg.edns.as_ref().expect("EDNS present");
        let ede_count = edns
            .options()
            .options
            .iter()
            .filter(|(code, _)| u16::from(*code) == 15)
            .count();
        assert_eq!(ede_count, 1, "EDE options must not be duplicated");
    }
}
