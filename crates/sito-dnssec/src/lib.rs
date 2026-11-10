//! `sito-dnssec`
//!
//! DNSSEC cryptographic validation engine supporting RFC 4033/4034/4035 verification,
//! root trust anchors, negative trust anchors (NTA), key caching, RFC 8914 extended DNS errors (EDE),
//! and validation metrics.

use std::collections::{HashMap, HashSet};
pub mod chain_cache;
pub mod nsec;
pub mod nsec3;

use chain_cache::CHAIN_CACHE_MAX_ENTRIES;
pub use chain_cache::{ChainCache, ChainEntry, PolicyChange, PolicyState, ZoneStatus};

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
/// Hard upper bound on cryptographic RRSIG verification attempts for one
/// client response. Upstream data is untrusted: without this bound a crafted
/// message with 64 DNSKEYs and 128 RRSIGs could force thousands of RSA/ECDSA
/// verifications per query.
const MAX_VERIFICATIONS_PER_RESPONSE: u32 = 256;
/// Maximum candidate keys tried for a single RRSIG. Trusted/validated keys are
/// tried first, so this only drops unvalidated response keys.
const MAX_CANDIDATE_KEYS_PER_RRSIG: usize = 8;

/// Per-response budget for cryptographic RRSIG verification attempts.
///
/// Every `verify_rrsig` call in the response-validation path must consume one
/// unit first. A crafted authoritative response cannot make the resolver
/// perform more than `MAX_VERIFICATIONS_PER_RESPONSE` signature checks.
#[derive(Debug)]
struct VerifyBudget {
    remaining: u32,
}

impl VerifyBudget {
    fn new() -> Self {
        Self {
            remaining: MAX_VERIFICATIONS_PER_RESPONSE,
        }
    }

    /// Consumes one verification slot, returning false when the budget is
    /// exhausted. Callers must fail closed (stop verifying) on false.
    fn try_consume(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

/// Hard bound on the validated-key cache; DNSKEYs are re-discoverable.
const KEY_CACHE_MAX_ENTRIES: usize = 4096;
/// Hard bound on the known-signed-zone cache; zones are re-discoverable.
const SIGNED_ZONE_MAX_ENTRIES: usize = 8192;
/// Maximum number of delegation cuts probed for a single name (the previous
/// probe used 8; deeper names fail closed instead of issuing unbounded fetches).
const MAX_CHAIN_CUTS: usize = 8;
/// Maximum cache lifetime for an authenticated DS status (seconds).
const CHAIN_STATUS_TTL_MAX: u32 = 3600;
/// How long a failed delegation probe suppresses further probes for the name.
const PROBE_BACKOFF_SECS: u32 = 30;
/// Maximum number of *distinct CNAME chain names* probed per response. Names
/// already covered by cached/in-memory evidence do not consume the budget.
/// A chain that needs more probes fails closed instead of amplifying fetches.
const MAX_CNAME_PROBES: usize = 8;
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

/// Identity of a validated DNSKEY: its full public-key bytes.
///
/// A 16-bit key tag is not a unique key identity (RFC 4035 §5.3.1): an
/// attacker can pair an anchored key with a same-tag forgery, so trust must
/// always be bound to the exact key material.
fn dnskey_fingerprint(key: &DNSKEY) -> Vec<u8> {
    key.public_key().public_bytes().to_vec()
}

/// Whether two DNSKEYs carry the same public key material.
fn same_public_key(a: &DNSKEY, b: &DNSKEY) -> bool {
    a.algorithm() == b.algorithm() && a.public_key().public_bytes() == b.public_key().public_bytes()
}

/// Applies the RFC 4035 §5.3.3 authenticated TTL to every RRset covered by an
/// RRSIG in the response: the TTL must not exceed the received TTL, the
/// RRSIG's Original TTL, or the remaining signature validity. Without this a
/// validated answer with a long record TTL but a short-lived signature would
/// be cached and served with AD=1 after the signature expired.
fn apply_authenticated_ttls(response: &mut Message, now: u32) {
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
fn authenticated_denial_ttl(response: &Message) -> Option<u32> {
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
    /// Cryptographic RRSIG verification attempts made while validating
    /// responses (bounded per response; see `MAX_VERIFICATIONS_PER_RESPONSE`).
    pub signature_verifications: AtomicU64,
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

    /// Records one cryptographic RRSIG verification attempt.
    pub fn record_signature_verification(&self) {
        self.signature_verifications.fetch_add(1, Ordering::Relaxed);
    }

    /// Cumulative cryptographic RRSIG verification attempts.
    #[must_use]
    pub fn signature_verifications(&self) -> u64 {
        self.signature_verifications.load(Ordering::Relaxed)
    }

    pub fn record_bogus(&self, upstream: Option<&str>, reason: &str) {
        const MAX_BOGUS_REASON_ENTRIES: usize = 256;
        let key = (
            upstream.unwrap_or("unknown").to_string(),
            reason.to_string(),
        );
        if let Some(counter) = self.bogus_by_upstream_reason.get(&key) {
            counter.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.bogus_by_upstream_reason.len() >= MAX_BOGUS_REASON_ENTRIES {
            return;
        }
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

    /// Whether `key` itself (not just some key with the same tag) is a cached
    /// validated key. Trust must never be granted from the tag alone: a key
    /// tag collision would otherwise let a forged DNSKEY inherit an anchored
    /// key's trust.
    #[must_use]
    pub fn is_validated(&self, name: &LowerName, key_tag: u16, key: &DNSKEY, now: u32) -> bool {
        self.keys
            .get(&(name.clone(), key_tag))
            .is_some_and(|entry| {
                let (cached, expires_at, validated) = entry.value();
                *validated && now <= *expires_at && same_public_key(cached, key)
            })
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
    ///
    /// An existing unexpired validated entry with the same tag but different
    /// key material is never overwritten: otherwise a forged key that shares a
    /// tag with a validated key could inherit its trust.
    pub fn insert_validated_with_now(
        &self,
        name: LowerName,
        key_tag: u16,
        key: DNSKEY,
        expires_at: u32,
        now: u32,
    ) {
        if let Some(existing) = self.keys.get(&(name.clone(), key_tag)) {
            let (cached, existing_expiry, existing_validated) = existing.value();
            if *existing_validated && now <= *existing_expiry && !same_public_key(cached, &key) {
                // Keep the original validated key; the different key is either
                // a forgery or a rollover that must be re-validated from
                // scratch.
                return;
            }
        }
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
        // Concurrent inserts between the two `len()` calls can make the
        // difference negative; the count is informational.
        before.saturating_sub(self.keys.len())
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

    /// All unexpired validated keys cached for `name` (any key tag).
    #[must_use]
    pub fn validated_keys(&self, name: &LowerName, now: u32) -> Vec<DNSKEY> {
        self.keys
            .iter()
            .filter(|entry| entry.key().0 == *name)
            .filter_map(|entry| {
                let (key, expires_at, validated) = entry.value();
                (*validated && now <= *expires_at).then(|| key.clone())
            })
            .collect()
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

/// Every name in the CNAME chain starting at `qname` (the query name plus each
/// target), bounded to 16 hops. Used to check signature coverage across a
/// stripped chain, not only at the original qname.
fn cname_chain_names(response: &Message, qname: &Name) -> Vec<Name> {
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
fn distinct_cname_chain_names(response: &Message, qname: &Name) -> Vec<Name> {
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
fn policy_fingerprint(trust_anchors: &[String], ntas: &[String]) -> String {
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
fn is_negative_response(response: &Message, qname: &Name, qtype: RecordType) -> bool {
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

/// If `qname` begins a CNAME chain whose signed prefix in `trusted_covered`
/// crosses into an unsigned target (with no RRSIGs in `rrsigs` for that target
/// or any subsequent CNAME hop), returns the final unsigned target name.
fn signed_cname_to_unsigned_target(
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

/// Whether a signature record at `sig_owner` covers the RRset at
/// `rrset_owner`.
///
/// Normally the names are equal. A wildcard-expanded answer may instead carry
/// the RRSIG at the wildcard owner (`*.example`), with the answer RRset at the
/// expanded qname (`a.example`). In that case the RRSIG Labels field counts the
/// labels below the wildcard and the signed name is the wildcard owner.
fn signature_covers_rrset(sig_owner: &Name, sig: &SIG, rrset_owner: &Name) -> bool {
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
fn response_has_complete_relevant_signatures(
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
fn relevant_signatures_have_key_material(
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
fn rrsig_time_ok(rrsig: &SIG, now: u32) -> bool {
    rrsig_time_failure(rrsig, now).is_none()
}

/// Returns the failure reason and EDE code when an RRSIG is outside its
/// validity window (allowing `MAX_CLOCK_SKEW`).
fn rrsig_time_failure(rrsig: &SIG, now: u32) -> Option<(&'static str, u16)> {
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
fn has_valid_rrsig_for(
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

/// Delegation status inferred from a DS response.
enum DsStatus {
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
fn ds_response_status(
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
enum DelegationProof {
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
fn delegation_cuts(name: &LowerName, zone: &LowerName) -> (Vec<LowerName>, bool) {
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
enum UnsignedProbe {
    /// Cached or in-memory evidence already answered the question; no fetch.
    Covered,
    /// A probe ran and established an authenticated status.
    Probed,
    /// A probe ran but could not establish a status (network/unknown).
    Failed,
}

/// Result of the DS/DNSKEY trust-extension walk.
#[derive(Default)]
struct KeySetBuild {
    /// Keys linked to a trust anchor (directly, via DS, or via a validated
    /// DNSKEY RRset), identified by full public-key bytes (a key tag is not a
    /// unique key identity).
    validated: HashSet<(LowerName, Vec<u8>)>,
    /// Zones whose only DS records use an unsupported digest or algorithm:
    /// RFC 6840 §5.2 treats them as unsigned delegations instead of Bogus.
    unsupported: HashSet<LowerName>,
    /// Zones whose DS RRset was validly signed by a validated parent but whose
    /// hierarchy or digest did not match (cross-zone or forged DS).
    forged: HashSet<LowerName>,
    /// First RRSIG validity-window failure encountered while walking DS/DNSKEY
    /// trust links from a validated parent/signer.
    time_failure: Option<(&'static str, u16)>,
}

/// Aggregated state for one DS owner during the trust-extension walk.
#[derive(Default)]
struct DsLink {
    signed: bool,
    hierarchy_bad: bool,
    /// A DS record used an unsupported digest or algorithm.
    policy_bad: bool,
    /// At least one DS record used a supported digest and algorithm.
    supported_present: bool,
    child_present: bool,
    matched: bool,
}

/// DNSSEC validation engine.
pub struct DnssecValidator {
    pub mode: DnssecMode,
    pub trust_anchors: Arc<ArcSwap<TrustAnchors>>,
    pub nta_domains: Arc<ArcSwap<Vec<String>>>,
    pub key_cache: KeyCache,
    pub metrics: Arc<DnssecMetrics>,
    /// Zones that actually signed response data which validated against a
    /// trust anchor, with an expiry timestamp. A later response under one of
    /// these zones that carries no RRSIG is a stripped-signature downgrade and
    /// must not be Insecure.
    ///
    /// Only signatures over response data mark a zone; linking a key to an
    /// anchor (e.g. the root DNSKEY fetched by the chain walk) proves the key
    /// but not that descendants are authoritative-signed, so it must never
    /// mark a zone as signed.
    signed_zones: DashMap<LowerName, u32>,
    /// Zones proven to be unsigned delegations by an authenticated DS denial
    /// (RFC 4035 §5.2), with an expiry timestamp. Everything below such a zone
    /// is legitimately unsigned and must not be treated as a stripped
    /// signature.
    insecure_zones: DashMap<LowerName, u32>,
    /// Authenticated chain statuses, shared across validator swaps and
    /// optionally persisted under `<data_dir>/dnssec-chain-cache.toml`.
    chain_cache: Arc<ChainCache>,
    /// Configured trust-anchor zone names (the root is derived from the anchor
    /// set itself). Used to decide where a cold-start DNSKEY fetch begins.
    anchor_zones: DashMap<LowerName, ()>,
    /// Short-lived probe backoff so a network outage cannot cause a DS fetch
    /// storm for names that cannot be classified. Never persisted.
    probe_backoff: DashMap<LowerName, u32>,
    /// Chain-cache policy generation this validator was built under. Cache
    /// inserts carrying an older generation are rejected after a hot reload.
    policy_generation: AtomicU64,
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
    fn apply_chain_cache_policy(&self, config: &DnssecConfig) -> PolicyChange {
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
    fn insert_raw_trust_anchor(&self, key: &PublicKeyBuf, name: &LowerName) {
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
    fn invalidate_unsigned_evidence_under(&self, anchor: &LowerName) {
        self.invalidate_in_memory_unsigned_at_or_above(anchor);
        self.chain_cache.invalidate_unsigned_at_or_above(anchor);
    }

    /// Memory-only half of [`Self::invalidate_unsigned_evidence_under`], used
    /// after `ChainCache::ensure_policy` already did the targeted cache prune.
    fn invalidate_in_memory_unsigned_at_or_above(&self, anchor: &LowerName) -> usize {
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
            norm == n || norm.ends_with(&format!(".{n}"))
        })
    }

    /// Records that `zone` was proven signed, valid until `expiry`.
    fn mark_signed_zone(&self, zone: &LowerName, expiry: u32, now: u32) {
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
    fn signed_zone_contains(&self, name: &LowerName, now: u32) -> bool {
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
    fn signed_chain_contains(&self, response: &Message, qname: &Name, now: u32) -> bool {
        cname_chain_names(response, qname).iter().any(|name| {
            let lower = LowerName::from(name);
            self.signed_zone_contains(&lower, now) && !self.insecure_zone_covers(&lower, now)
        })
    }

    /// Records that `zone` was proven unsigned by an authenticated DS denial,
    /// valid until `expiry`.
    fn mark_insecure_zone(&self, zone: &LowerName, expiry: u32, now: u32) {
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
    fn insecure_zone_covers(&self, name: &LowerName, now: u32) -> bool {
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
    fn anchor_island_covers(&self, unsigned_zone: &LowerName, name: &LowerName) -> bool {
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
    fn anchor_affects_unsigned_zone(&self, unsigned_zone: &LowerName) -> bool {
        self.anchor_zones
            .iter()
            .any(|entry| !entry.key().is_root() && unsigned_zone.zone_of(entry.key()))
    }

    /// A cached `Unsigned` zone covering `name`, unless a configured anchor at
    /// or below that cached zone now contradicts it.
    fn cached_unsigned_zone(&self, name: &LowerName, now: u32) -> Option<(LowerName, u32)> {
        let (zone, expiry) = self.chain_cache.covers_unsigned(name, now)?;
        if self.anchor_affects_unsigned_zone(&zone) {
            return None;
        }
        Some((zone, expiry))
    }

    /// The closest zone apex that previously signed validated response data and
    /// is a proper ancestor of `name`.
    fn closest_signed_zone(&self, name: &LowerName, now: u32) -> Option<LowerName> {
        self.signed_zones
            .iter()
            .filter(|entry| {
                *entry.value() >= now && entry.key() != name && entry.key().zone_of(name)
            })
            .max_by_key(|entry| entry.key().num_labels())
            .map(|entry| entry.key().clone())
    }

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
    async fn probe_delegation(
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
    fn closest_anchor_zone(&self, name: &LowerName) -> Option<LowerName> {
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
    async fn seed_anchor_keys(
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
    async fn keys_for_zone(
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
    async fn validate_child_dnskeys(
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
    async fn prepare_unsigned_response(
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
    fn unsigned_status_known(&self, name: &LowerName, now: u32) -> bool {
        let exact = self.chain_cache.get(name, now);
        let exact_known = exact.is_some_and(|entry| {
            entry.status == ZoneStatus::Signed || !self.anchor_affects_unsigned_zone(name)
        });
        exact_known
            || self.cached_unsigned_zone(name, now).is_some()
            || self.insecure_zone_covers(name, now)
    }

    fn probe_backoff_active(&self, name: &LowerName, now: u32) -> bool {
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

    fn record_probe_failure(&self, name: &LowerName, now: u32) {
        self.probe_backoff
            .insert(name.clone(), now.saturating_add(PROBE_BACKOFF_SECS));
    }

    /// Converts an inconclusive validation result into the configured policy
    /// outcome: strict mode fails closed with SERVFAIL, `LogOnly` keeps the
    /// response with AD cleared, and disabled validation never gets here.
    fn indeterminate_outcome(
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
    fn build_validated_key_set(
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

    /// Validate a response, treating additional-section records starting at
    /// `helper_additionals` as chain-fetch helpers.
    ///
    /// [`fetch_zone_chain`] appends DNSKEY/DS records (and their RRSIGs) to
    /// the response so the chain can be built in one place. Those helper
    /// signatures authenticate helper RRsets, not the original answer: they
    /// must never count as signed-zone evidence or as a signature covering the
    /// query. `None` means every record belongs to the original response.
    ///
    /// `allow_unchecked_signatures` is true only on the pre-fetch pass. It
    /// permits returning `Indeterminate` when a relevant signature cannot be
    /// checked yet, because the caller may still fetch its key. The post-fetch
    /// pass sets it to false so an unverifiable signature under proven
    /// signed-zone evidence fails closed.
    fn validate_response_inner(
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
            // the outcome records it (or the Bogus/Insecure conversion) exactly
            // once. Recording here would double-count the same validation.
            return ValidationOutcome::Indeterminate;
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

        // Collect RRSIG/SIG records (bounded). Signatures appended by the
        // chain walk are flagged as helpers: they are usable for building the
        // key chain, but they do not authenticate the original response.
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

        // A response without RRSIGs under a zone already proven signed is a
        // signature-stripping downgrade, not an unsigned zone. Check every
        // name in the CNAME chain: the original name may be unsigned while the
        // target is signed.
        if rrsigs.is_empty() {
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
        let key_set =
            self.build_validated_key_set(response, &response_dnskeys, &rrsigs, now, budget);

        // Validate each RRSIG. Secure/AD is granted only when the answer RRset
        // relevant to the question (or a complete denial proof) is covered by a
        // signature that verified with a chain-validated key.
        let anchors = self.trust_anchors.load();
        let relevant_keys = relevant_answer_keys(response, &qname, qtype);
        // Whether the original response carries an RRSIG that covers an RRset
        // relevant to the question. If it does but the key chain is not yet
        // available, this must stay Indeterminate so the caller can fetch the
        // chain; only a genuinely missing relevant signature is a downgrade.
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
        let mut first_failure: Option<(&'static str, u16)> = key_set.time_failure;
        let mut policy_violation = false;
        let mut has_trusted_sig = false;
        let mut trusted_covered: HashSet<(LowerName, RecordType)> = HashSet::new();
        let mut trusted_sigs: Vec<TrustedSignature> = Vec::new();
        let mut trusted_signer_covers_qname = false;

        for ((rrsig_owner, rrsig), is_helper) in rrsigs.iter().zip(helper_rrsigs.iter()) {
            let inception = rrsig.input().sig_inception.get();
            let expiration = rrsig.input().sig_expiration.get();
            let type_covered = rrsig.input().type_covered;
            // A normal RRSIG is owned by the RRset. A wildcard-expanded answer
            // may carry it at `*.example` instead; map it to the expanded
            // answer name so coverage, verification, and AD accounting use the
            // actual RRset owner (Hickory reconstructs the wildcard name from
            // the RRSIG Labels field during verification).
            let rrset_owner = if rrsig_owner.is_wildcard() {
                response
                    .answers
                    .iter()
                    .find(|record| {
                        record.record_type() == type_covered
                            && signature_covers_rrset(rrsig_owner, rrsig, &record.name)
                            && relevant_keys
                                .contains(&(LowerName::from(&record.name), type_covered))
                    })
                    .map_or(rrsig_owner, |record| &record.name)
            } else {
                rrsig_owner
            };

            // Failures on signatures for RRsets that are not relevant to the
            // question (e.g. stale RRSIGs in the authority section of an
            // otherwise valid answer) must not turn the response Bogus.
            // Chain-helper signatures are never relevant to the query.
            let rrsig_relevant =
                !is_helper && relevant_keys.contains(&(LowerName::from(rrset_owner), type_covered));

            // RFC 4035 5.3.1 with a bounded clock skew: a signature is usable
            // within +/- 300 s of its validity window.
            if now.saturating_add(MAX_CLOCK_SKEW) < inception {
                if rrsig_relevant {
                    first_failure.get_or_insert(("Signature not yet valid", EDE_DNSSEC_BOGUS));
                }
                continue;
            }
            if now > expiration.saturating_add(MAX_CLOCK_SKEW) {
                if rrsig_relevant {
                    first_failure.get_or_insert(("Signature expired", EDE_SIGNATURE_EXPIRED));
                }
                continue;
            }

            let signer_name = &rrsig.input().signer_name;
            let key_tag = rrsig.input().key_tag;

            // Candidate keys for this RRSIG: the validated-key cache plus every
            // response DNSKEY with the same owner, tag and algorithm. Multiple
            // candidates are considered because a key tag is not a unique key
            // identity (RFC 4035 5.3.1): an anchored key and a same-tag forgery
            // can both match, and stopping at the first match would let the
            // forgery shadow -- or inherit -- the real key's trust.
            //
            // Trusted keys are tried first and the list is capped, so a flood
            // of same-tag response keys cannot starve the real signer or
            // multiply the cryptographic work per signature.
            let lower_signer = LowerName::from(signer_name);
            let cached_key = self
                .key_cache
                .get(&lower_signer, key_tag, now)
                .filter(|key| key.algorithm() == rrsig.input().algorithm);
            self.metrics.record_key_cache(cached_key.is_some());
            let mut candidates: Vec<DNSKEY> = Vec::new();
            if let Some(key) = cached_key {
                candidates.push(key);
            }
            for (key_owner, dnskey) in &response_dnskeys {
                if key_owner == signer_name
                    && dnskey.algorithm() == rrsig.input().algorithm
                    && dnskey.calculate_key_tag().ok() == Some(key_tag)
                {
                    candidates.push(dnskey.clone());
                }
            }
            candidates.sort_by_key(|dnskey| {
                let trusted = anchors.contains(dnskey.public_key())
                    || anchors.contains_with_name(dnskey.public_key(), &lower_signer)
                    || key_set
                        .validated
                        .contains(&(lower_signer.clone(), dnskey_fingerprint(dnskey)))
                    || self
                        .key_cache
                        .is_validated(&lower_signer, key_tag, dnskey, now);
                !trusted
            });
            candidates.truncate(MAX_CANDIDATE_KEYS_PER_RRSIG);
            if candidates.is_empty() {
                // No usable key material: the chain fetch path may resolve it.
                continue;
            }

            let covered_records: Vec<&Record> = response
                .answers
                .iter()
                .chain(response.authorities.iter())
                .chain(response.additionals.iter())
                .filter(|r| r.record_type() == type_covered && r.name == *rrset_owner)
                .collect();

            // An RRSIG that covers nothing in the response cannot authenticate
            // anything and is a validation failure.
            if covered_records.is_empty() {
                if rrsig_relevant {
                    first_failure.get_or_insert((
                        "RRSIG does not cover any records in the response",
                        EDE_DNSSEC_BOGUS,
                    ));
                }
                continue;
            }

            let rrsig_rdata = RRSIG::from_sig(rrsig.input().clone(), rrsig.sig().to_vec());
            let mut accepted = false;
            let mut candidate_policy_rejected = false;
            let mut candidate_failure: Option<(&'static str, u16)> = None;

            for dnskey in &candidates {
                if !dnskey_policy_ok(dnskey) {
                    // Signatures exist but every usable key was rejected by
                    // policy; this must not silently downgrade to Insecure.
                    candidate_policy_rejected = true;
                    continue;
                }

                if !budget.try_consume() {
                    // Hard per-response cap; the remaining signatures stay
                    // unverified (never secure).
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

                // RFC 4035 5.3.1: the RRSIG signer must be the zone containing
                // the RRset owner. Without this containment check, any key
                // validated for one domain could authenticate records owned by
                // any other name (cross-zone signature forgery granting AD=1).
                if !lower_signer.zone_of(&LowerName::from(rrset_owner)) {
                    candidate_failure.get_or_insert((
                        "RRSIG signer does not contain the RRset owner",
                        EDE_DNSSEC_BOGUS,
                    ));
                    continue;
                }

                // Trust is bound to the exact key material, never to the tag.
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
                if candidate_policy_rejected {
                    policy_violation = true;
                }
                if let Some((reason, ede_code)) = candidate_failure
                    && rrsig_relevant
                {
                    first_failure.get_or_insert((reason, ede_code));
                }
                continue;
            }

            has_trusted_sig = true;
            trusted_covered.insert((LowerName::from(rrset_owner), type_covered));
            if lower_signer.zone_of(&qname_lower) {
                trusted_signer_covers_qname = true;
            }
            // Zone evidence must come from a signature over the original
            // response data that is relevant to the query. A helper DNSKEY/DS
            // RRSIG proves the helper RRset, not that this query's zone signed
            // anything. A validated NSEC/NSEC3 in the original authority
            // section is the query's denial proof and is relevant too: it
            // proves the zone signs data, so later stripped answers under it
            // must stay fail-closed.
            let denial_evidence = !is_helper
                && matches!(type_covered, RecordType::NSEC | RecordType::NSEC3)
                && lower_signer.zone_of(&qname_lower)
                && response
                    .answers
                    .iter()
                    .chain(response.authorities.iter())
                    .any(|record| {
                        record.name == *rrsig_owner && record.record_type() == type_covered
                    });
            if rrsig_relevant || denial_evidence {
                self.mark_signed_zone(&lower_signer, expiration, now);
            }
            trusted_sigs.push(TrustedSignature {
                owner: LowerName::from(rrset_owner),
                covered: type_covered,
                signer: lower_signer,
                signer_name: signer_name.clone(),
            });
        }

        // Secure/AD is granted only for the positive answer RRset(s) relevant
        // to the question (including a CNAME chain) or for a complete
        // NSEC/NSEC3 denial proof. Unrelated signatures never grant AD.
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

        // RFC 4035 §3.2.3: the AD bit may only be set when every RRset in the
        // Answer and Authority sections is authentic. Additional-section glue
        // is exempt. Without this, an attacker could attach unauthenticated
        // records to an otherwise valid response and have them marked AD=1.
        let all_section_rrsets_signed = response
            .answers
            .iter()
            .chain(response.authorities.iter())
            .filter(|record| record.record_type() != RecordType::RRSIG)
            .all(|record| {
                trusted_covered.contains(&(LowerName::from(&record.name), record.record_type()))
            });

        // A validated CNAME chain whose target crosses into an unsigned zone
        // is Insecure (AD=0) only when an authenticated DS denial proves the
        // target delegation is unsigned. Merely lacking signed-zone evidence
        // is not proof: an attacker can strip the target's RRSIGs. Without the
        // DS denial the strict pass below keeps the response Bogus.
        let cname_to_unsigned_zone =
            signed_cname_to_unsigned_target(response, &qname, &trusted_covered, &rrsigs)
                .is_some_and(|target| self.insecure_zone_covers(&LowerName::from(&target), now));

        let negative = is_negative_response(response, &qname, qtype);
        let negative_name = if negative {
            negative_answer_name(response, &qname)
        } else {
            qname.clone()
        };
        let negative_lower = LowerName::from(&negative_name);

        // Whether the original response carries an NSEC/NSEC3 RRSIG signed by
        // a zone that contains the negative answer name. Its key may simply be
        // missing (DNSKEY TTL shorter than the signed-zone evidence), so on
        // the pre-fetch pass this defers the "missing denial proof" Bogus to
        // the chain fetch instead of false-SERVFAILing.
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
                    if !all_section_rrsets_signed {
                        debug!(
                            "DNSSEC denial proof is valid but the response carries unauthenticated RRsets; clearing AD"
                        );
                        response.metadata.authentic_data = false;
                        let outcome = ValidationOutcome::Insecure;
                        self.metrics.record_validation(&outcome);
                        return outcome;
                    }
                    return self.secure_outcome(response, now);
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
                    if cname_to_unsigned_zone
                        && key_set.forged.is_empty()
                        && first_failure.is_none()
                        && !policy_violation
                    {
                        response.metadata.authentic_data = false;
                        let outcome = ValidationOutcome::Insecure;
                        self.metrics.record_validation(&outcome);
                        return outcome;
                    }
                    let would_be_secure = has_trusted_sig
                        || all_present_signed
                        || self.signed_zone_contains(&qname_lower, now);
                    if would_be_secure {
                        // A denial RRSIG whose key is not available yet is
                        // deferrable only on the pre-fetch pass; the strict
                        // post-fetch pass keeps the fail-closed Bogus.
                        if allow_unchecked_signatures && has_denial_rrsig {
                            // Fall through to Indeterminate so the caller can
                            // fetch the signer's DNSKEY.
                        } else {
                            return self.handle_bogus(
                                response,
                                upstream,
                                "Negative response lacks a valid NSEC/NSEC3 denial proof",
                                EDE_DNSSEC_BOGUS,
                            );
                        }
                    }
                }
            }
        } else if all_present_signed {
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

        if !key_set.forged.is_empty() {
            return self.handle_bogus(
                response,
                upstream,
                "Cross-zone or forged DS record signed by a validated key",
                EDE_DNSSEC_BOGUS,
            );
        }
        if !key_set.unsupported.is_empty() && !all_present_signed {
            // RFC 6840 §5.2: when every DS at the delegation uses an
            // unsupported digest or algorithm, treat the zone as unsigned
            // instead of failing closed.
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
        // A relevant RRSIG that could not be checked because no trusted key is
        // available yet is not a downgrade on the pre-fetch pass: return
        // Indeterminate so `validate_with_key_fetcher` can fetch the chain.
        // After the fetch (or when no fetcher is involved) an unverifiable
        // signature under proven signed-zone evidence must fail closed.
        let signed_zone_evidence = (self.signed_zone_contains(&qname_lower, now)
            && !self.insecure_zone_covers(&qname_lower, now))
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
        // A trusted signature over some unrelated RRset proves a signed zone
        // signed *something*, not that the answer is unsigned. If a relevant
        // RRSIG exists but could not be checked yet, let the caller fetch the
        // chain instead of rejecting it here.
        if has_trusted_sig && !has_relevant_rrsig {
            return self.handle_bogus(
                response,
                upstream,
                "No valid RRSIG covers the answer RRset",
                EDE_DNSSEC_BOGUS,
            );
        }

        // The response carried RRSIGs, but none of them covers (or could ever
        // cover) the answer. Those signatures are junk and must not count as
        // signed-zone evidence: for an otherwise unsigned response the result
        // is Insecure, not Indeterminate. A signed zone with a stripped answer
        // already failed closed in the `signed_zone_evidence` branch above.
        let signed_chain_evidence = self.signed_chain_contains(response, &qname, now)
            || (negative
                && self.signed_zone_contains(&negative_lower, now)
                && !self.insecure_zone_covers(&negative_lower, now));
        if !has_relevant_rrsig && !has_denial_rrsig && !has_trusted_sig && !signed_chain_evidence {
            response.metadata.authentic_data = false;
            let outcome = ValidationOutcome::Insecure;
            self.metrics.record_validation(&outcome);
            return outcome;
        }

        // RRSIGs were present and valid, but could not link to a trust anchor.
        // Leave the result provisional: the caller may still fetch the chain,
        // and whichever entry point finalizes it records the outcome once.
        response.metadata.authentic_data = false;
        ValidationOutcome::Indeterminate
    }

    /// Marks a response secure and records the outcome.
    fn secure_outcome(&self, response: &mut Message, now: u32) -> ValidationOutcome {
        apply_authenticated_ttls(response, now);
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
        assert!(
            msg.answers.is_empty(),
            "bogus response must not carry answers: {:?}",
            msg.answers
        );
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

    /// A fetched DNSKEY response with a self-signature, as a validating
    /// resolver's chain walk receives from a signed zone.
    fn signed_dnskey_message(
        owner: &Name,
        key: &DNSKEY,
        signer: &hickory_proto::dnssec::DnssecSigner,
    ) -> Message {
        use hickory_proto::rr::RecordSet;

        let record = Record::from_rdata(
            owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(key.clone())),
        );
        let mut set = RecordSet::new(owner.clone(), RecordType::DNSKEY, 0);
        set.insert(record.clone(), 0);
        let signature = sign_test_rrset(&set, signer);
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.additionals.push(record);
        message.additionals.push(signature);
        message
    }

    /// A fetched DS response for `child`, signed by the parent zone.
    fn signed_ds_fetch_message(
        child: &Name,
        child_key: &DNSKEY,
        parent_signer: &hickory_proto::dnssec::DnssecSigner,
    ) -> Message {
        use hickory_proto::dnssec::DigestType;
        use hickory_proto::rr::RecordSet;

        let ds = DS::from_key(child_key.public_key(), child, DigestType::SHA256).expect("ds");
        let record = Record::from_rdata(child.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
        let mut set = RecordSet::new(child.clone(), RecordType::DS, 0);
        set.insert(record.clone(), 0);
        let signature = sign_test_rrset(&set, parent_signer);
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.authorities.push(record);
        message.authorities.push(signature);
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
        signed_nsec_response_records(
            origin,
            &[(nsec_owner.clone(), next.clone(), bitmap.to_vec())],
            qname,
            dnskey,
            signer,
            response_code,
        )
    }

    /// Builds a signed negative response containing one or more NSEC RRsets.
    fn signed_nsec_response_records(
        origin: &Name,
        nsecs: &[(Name, Name, Vec<RecordType>)],
        qname: &Name,
        dnskey: &DNSKEY,
        signer: &hickory_proto::dnssec::DnssecSigner,
        response_code: ResponseCode,
    ) -> Message {
        use hickory_proto::dnssec::rdata::NSEC;
        use hickory_proto::rr::RecordSet;

        let mut msg = Message::new(24, MessageType::Response, OpCode::Query);
        msg.queries.push(Query::query(qname.clone(), RecordType::A));
        msg.metadata.response_code = response_code;

        for (owner, next, bitmap) in nsecs {
            let nsec = NSEC::new(next.clone(), bitmap.iter().copied());
            let nsec_record =
                Record::from_rdata(owner.clone(), 300, RData::DNSSEC(DNSSECRData::NSEC(nsec)));
            let mut set = RecordSet::new(owner.clone(), RecordType::NSEC, 0);
            set.insert(nsec_record.clone(), 0);
            let nsec_sig = sign_test_rrset(&set, signer);
            msg.authorities.push(nsec_record);
            msg.authorities.push(nsec_sig);
        }

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

        // A complete NXDOMAIN proof: one NSEC covers the qname and another
        // covers the wildcard `*.nsec.example`, so no wildcard could have
        // synthesized the name.
        let bitmap = vec![RecordType::A, RecordType::NSEC, RecordType::RRSIG];
        let mut msg = signed_nsec_response_records(
            &origin,
            &[
                (
                    origin.clone(),
                    Name::from_str("a.nsec.example.").unwrap(),
                    bitmap.clone(),
                ),
                (
                    Name::from_str("a.nsec.example.").unwrap(),
                    nsec_next(&origin),
                    bitmap,
                ),
            ],
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
    fn test_nxdomain_without_wildcard_denial_is_bogus() {
        let (origin, dnskey, signer) = create_test_signer("nsec.example.");
        let qname = Name::from_str("missing.nsec.example.").unwrap();

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        // Only the qname is covered; nothing proves that `*.nsec.example` does
        // not exist, so the NXDOMAIN must not be authenticated.
        let mut msg = signed_nsec_response(
            &origin,
            &Name::from_str("a.nsec.example.").unwrap(),
            &nsec_next(&origin),
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
            &qname,
            &dnskey,
            &signer,
            ResponseCode::NXDomain,
        );
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("test"), now);

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "missing wildcard denial must be Bogus, got {outcome:?}"
        );
        assert!(!msg.metadata.authentic_data);
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

    /// The validator accepts a denial proof carried in the additional section
    /// (`evaluate_denial` and the RRSIG loop both scan it). The SOA TTL cap
    /// must use the same sections, otherwise moving a genuine NSEC/RRSIG from
    /// authority to additional would leave a Secure negative with the SOA's
    /// long lifetime.
    #[test]
    fn test_negative_proof_in_additionals_caps_soa_ttl() {
        use hickory_proto::dnssec::rdata::NSEC;
        use hickory_proto::rr::RecordSet;
        use hickory_proto::rr::rdata::SOA;

        let (origin, dnskey, signer) = create_test_signer("addl.example.");
        let qname = Name::from_str("empty.addl.example.").unwrap();

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut msg = Message::new(30, MessageType::Response, OpCode::Query);
        msg.queries.push(Query::query(qname.clone(), RecordType::A));
        msg.metadata.response_code = ResponseCode::NoError;

        // A long-lived signed SOA in the authority section.
        let soa = Record::from_rdata(
            origin.clone(),
            3600,
            RData::SOA(SOA::new(
                Name::from_str("ns1.addl.example.").unwrap(),
                Name::from_str("hostmaster.addl.example.").unwrap(),
                1,
                7200,
                3600,
                1_209_600,
                3600,
            )),
        );
        let mut soa_set = RecordSet::new(origin.clone(), RecordType::SOA, 3600);
        soa_set.insert(soa.clone(), 0);
        let mut soa_sig = sign_test_rrset(&soa_set, &signer);
        soa_sig.ttl = 3600;
        msg.authorities.push(soa);
        msg.authorities.push(soa_sig);

        // The NSEC NODATA proof and its signature live in the additional
        // section, with a short 10 s lifetime.
        let nsec = NSEC::new(
            Name::from_str("zzz.addl.example.").unwrap(),
            [RecordType::SOA, RecordType::NSEC, RecordType::RRSIG],
        );
        let nsec_record =
            Record::from_rdata(qname.clone(), 10, RData::DNSSEC(DNSSECRData::NSEC(nsec)));
        let mut nsec_set = RecordSet::new(qname.clone(), RecordType::NSEC, 10);
        nsec_set.insert(nsec_record.clone(), 0);
        let mut nsec_sig = sign_test_rrset(&nsec_set, &signer);
        nsec_sig.ttl = 10;
        msg.additionals.push(nsec_record);
        msg.additionals.push(nsec_sig);
        msg.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("addl"), now);
        assert_eq!(outcome, ValidationOutcome::Secure);

        let soa_ttl = msg
            .authorities
            .iter()
            .find(|record| record.record_type() == RecordType::SOA)
            .expect("SOA")
            .ttl;
        assert_eq!(
            soa_ttl, 10,
            "the SOA TTL must be capped by an additional-section denial proof"
        );
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

        // The sync API has no key fetcher, so strict mode fails closed instead
        // of returning AD=0 for an unlinked denial signature.
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "an unlinked denial signature must not be served as AD=0 in strict mode: {outcome:?}"
        );
        assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
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
        if !opt_out {
            let wildcard = Name::from_str("*").unwrap().append_domain(origin).unwrap();
            let wc_hash = alg
                .hash(&[], &wildcard, iterations)
                .unwrap()
                .as_ref()
                .to_vec();
            let mut wc_prev = wc_hash.clone();
            for byte in wc_prev.iter_mut().rev() {
                let (val, borrow) = byte.overflowing_sub(1);
                *byte = val;
                if !borrow {
                    break;
                }
            }
            let mut wc_next = wc_hash;
            for byte in wc_next.iter_mut().rev() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
            let wc_nsec3 = NSEC3::new(
                alg,
                false,
                iterations,
                Vec::new(),
                wc_next,
                [RecordType::A, RecordType::RRSIG, RecordType::NSEC3],
            );
            let wc_owner = Name::from_ascii(format!(
                "{}.{}",
                BASE32_DNSSEC.encode(&wc_prev),
                origin.to_ascii()
            ))
            .unwrap();
            let wc_record = Record::from_rdata(
                wc_owner.clone(),
                300,
                RData::DNSSEC(DNSSECRData::NSEC3(wc_nsec3)),
            );
            let mut wc_set = RecordSet::new(wc_owner, RecordType::NSEC3, 0);
            wc_set.insert(wc_record.clone(), 0);
            let wc_sig = sign_test_rrset(&wc_set, signer);
            msg.authorities.push(wc_record);
            msg.authorities.push(wc_sig);
        }
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
            assert!(
                matches!(outcome, ValidationOutcome::Bogus { .. }),
                "an unlinked response must fail closed in strict mode: {outcome:?}"
            );
        }

        assert!(
            validator.key_cache.is_empty(),
            "unexpected cached keys: {}",
            validator.key_cache.len()
        );
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
        assert!(
            response.additionals.is_empty(),
            "unexpected additionals: {:?}",
            response.additionals
        );
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

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a failed chain fetch must SERVFAIL in validate mode: {outcome:?}"
        );
        // One DNSKEY and one DS lookup for the signer zone, then one
        // unverifiable-signature probe before failing closed.
        assert_eq!(fetcher.calls(), 3);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(
            response.additionals.is_empty(),
            "unexpected additionals: {:?}",
            response.additionals
        );
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
        assert!(
            !validator.key_cache.is_empty(),
            "expected at least one cached key"
        );
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
        assert!(
            !stripped.answers.is_empty(),
            "stripping NSEC records must keep the answers"
        );
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
    fn test_cross_zone_rrsig_does_not_grant_ad() {
        // A validated attacker zone signs an RRset owned by the victim zone.
        // RFC 4035 5.3.1 requires the signer to contain the owner; without the
        // containment check this granted AD=1 for arbitrary names.
        let (attacker, attacker_key, attacker_signer) = create_test_signer("attacker.example.");
        let (victim, _victim_key, _victim_signer) = create_test_signer("victim.example.");
        let (answer, answer_sig) = signed_a_response(&victim, &attacker_signer);

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(attacker_key.public_key(), LowerName::from(&attacker));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let mut msg = Message::new(37, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(victim.clone(), RecordType::A));
        msg.answers.push(answer);
        msg.answers.push(answer_sig);
        msg.additionals.push(Record::from_rdata(
            attacker,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(attacker_key)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("xzone"), now);

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "cross-zone RRSIG must be Bogus, got {outcome:?}"
        );
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
    fn test_ds_sha1_digest_is_treated_as_unsigned() {
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

        // RFC 6840 5.2: an unsupported DS digest makes the delegation
        // unsigned; the answer is served with AD=0, not SERVFAIL.
        assert_eq!(outcome, ValidationOutcome::Insecure);
        assert!(!msg.metadata.authentic_data);
        assert_ne!(msg.metadata.response_code, ResponseCode::ServFail);
    }

    #[test]
    fn test_ds_rsasha1_algorithm_is_treated_as_unsigned() {
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

        assert_eq!(outcome, ValidationOutcome::Insecure);
        assert!(!msg.metadata.authentic_data);
        assert_ne!(msg.metadata.response_code, ResponseCode::ServFail);
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
        let fingerprint = dnskey_fingerprint(&root_key);
        let dnskeys = vec![(root.clone(), root_key)];
        let result = validator.build_validated_key_set(
            &response,
            &dnskeys,
            &[],
            now,
            &mut VerifyBudget::new(),
        );

        assert!(result.validated.contains(&(lower.clone(), fingerprint)));
        assert!(
            result.forged.is_empty(),
            "unexpected forged entries: {:?}",
            result.forged
        );
        assert!(
            result.unsupported.is_empty(),
            "unexpected unsupported entries: {:?}",
            result.unsupported
        );
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

    /// Finds a DNSKEY `flags` value that gives `key`'s public material the
    /// requested key tag (key tags are only 16-bit checksums, so collisions are
    /// trivially constructible).
    fn find_same_tag_flags(key: &DNSKEY, target_tag: u16) -> Option<u16> {
        use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

        // The key tag is computed over the wire form, where the flags field is
        // the first 16-bit word and contributes exactly `flags` to the sum.
        // Encode once with zero flags to obtain the flag-independent sum.
        let zero = DNSKEY::with_flags(0, key.public_key().clone());
        let mut bytes = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut bytes);
            zero.emit(&mut encoder).expect("encode DNSKEY");
        }
        let base_ac: u32 = bytes
            .iter()
            .enumerate()
            .map(|(i, byte)| u32::from(*byte) << if i & 1 == 0 { 8 } else { 0 })
            .sum();

        for flags in 0u32..=0xFFFF {
            // Zone key flag set, revoke flag clear (required by policy).
            if flags & 0x0100 == 0 || flags & 0x0080 != 0 {
                continue;
            }
            let ac = base_ac + flags;
            if ((ac + (ac >> 16)) & 0xFFFF) as u16 == target_tag {
                return Some(flags as u16);
            }
        }
        None
    }

    /// Builds a key pair whose key tag collides with `target_tag` but whose
    /// public key material differs.
    ///
    /// The tag is varied through the DNSKEY flags field. Policy requires the
    /// zone-key bit set and the revoke bit clear, so only a quarter of the
    /// reachable tag residues is covered per generated key; fresh keys are
    /// generated until one collides (expected ~4 attempts).
    fn forge_same_tag_key(
        target_tag: u16,
    ) -> (DNSKEY, hickory_proto::dnssec::crypto::EcdsaSigningKey) {
        use hickory_proto::dnssec::SigningKey;
        use hickory_proto::dnssec::crypto::EcdsaSigningKey;

        for _ in 0..256 {
            let pkcs8 = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256)
                .expect("generate fake pkcs8");
            let private = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256)
                .expect("fake key from pkcs8");
            let public = private.to_public_key().expect("fake public key");
            let plain = DNSKEY::from_key(&public);
            if let Some(flags) = find_same_tag_flags(&plain, target_tag) {
                let key = DNSKEY::with_flags(flags, plain.public_key().clone());
                return (key, private);
            }
        }
        panic!("a 16-bit tag collision must be constructible");
    }

    /// Regression for the same-tag DNSKEY forgery: including the anchored key
    /// plus a same-tag forgery must not let the forgery be trusted, and must
    /// never replace the anchored key in the validated-key cache.
    #[test]
    fn test_same_tag_dnskey_forgery_is_not_trusted() {
        use hickory_proto::dnssec::DnssecSigner;

        let (origin, real_key, real_signer) =
            crate::test_util::create_test_signer("victim.example.");
        let real_tag = real_key.calculate_key_tag().expect("real tag");

        // A different key pair whose tag is forced to collide.
        let (fake_key, fake_private) = forge_same_tag_key(real_tag);
        assert_eq!(fake_key.calculate_key_tag().expect("fake tag"), real_tag);
        assert_ne!(
            dnskey_fingerprint(&fake_key),
            dnskey_fingerprint(&real_key),
            "the forged key must not be the anchored key"
        );
        let fake_signer = DnssecSigner::new(
            fake_key.clone(),
            Box::new(fake_private),
            origin.clone(),
            Duration::from_secs(3600),
        );

        let mut trust_anchors = TrustAnchors::empty();
        trust_anchors.insert_with_name(real_key.public_key(), LowerName::from(&origin));
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new())
            .with_trust_anchors(trust_anchors);

        // Attacker ordering: the forged key first, the anchored key second.
        let (answer, forged_sig) = signed_a_response(&origin, &fake_signer);
        let mut response = Message::new(9, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(origin.clone(), RecordType::A));
        response.answers.push(answer);
        response.answers.push(forged_sig);
        response.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(fake_key.clone())),
        ));
        response.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(real_key.clone())),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut response, Some("attacker"), now);
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a same-tag forgery must not validate: {outcome:?}"
        );
        assert!(!response.metadata.authentic_data);

        // The anchored key must still be the cached validated key, and the
        // forged key must never be trusted from the shared tag.
        let lower = LowerName::from(&origin);
        assert!(
            validator
                .key_cache
                .is_validated(&lower, real_tag, &real_key, now),
            "the anchored key must remain validated in the cache"
        );
        assert!(
            !validator
                .key_cache
                .is_validated(&lower, real_tag, &fake_key, now),
            "the forged key must not inherit the anchored key's trust"
        );

        // The legitimate response signed by the anchored key still validates.
        let (legit_answer, legit_sig) = signed_a_response(&origin, &real_signer);
        let mut legit = Message::new(10, MessageType::Response, OpCode::Query);
        legit
            .queries
            .push(Query::query(origin.clone(), RecordType::A));
        legit.answers.push(legit_answer);
        legit.answers.push(legit_sig);
        legit.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(real_key.clone())),
        ));
        let outcome = validator.validate_response(&mut legit, Some("legit"), now);
        assert_eq!(outcome, ValidationOutcome::Secure);
    }

    /// Regression: linking a key to a trust anchor (in particular the root key
    /// fetched by the chain walk) must not mark the root or any other zone as
    /// signed. Doing so turned every unrelated unsigned response into a
    /// stripped-signature "Bogus" and SERVFAILed it (audit 6, P0-2).
    #[test]
    fn test_building_validated_key_set_does_not_mark_zones_signed() {
        let anchors = TrustAnchors::default();
        let anchor = anchors.get(0).expect("default root anchor").clone();
        let root = Name::root();
        let root_key = DNSKEY::with_flags(257, anchor);
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        let mut response = Message::new(45, MessageType::Response, OpCode::Query);
        response.additionals.push(Record::from_rdata(
            root.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(root_key.clone())),
        ));
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let result = validator.build_validated_key_set(
            &response,
            &[(root.clone(), root_key)],
            &[],
            now,
            &mut VerifyBudget::new(),
        );
        assert!(
            !result.validated.is_empty(),
            "expected validated keys, got none"
        );
        for name in ["unsigned.example.", "com.", "www.example.org."] {
            let lower = LowerName::from(&Name::from_str(name).expect("name"));
            assert!(
                !validator.signed_zone_contains(&lower, now),
                "{name} must not be recorded as signed just because the root key was linked"
            );
        }
    }

    /// An unrelated unsigned response after a successful validation must stay
    /// Insecure and resolvable (this SERVFAILed before the audit-6 fix).
    #[test]
    fn test_signed_response_does_not_make_unrelated_unsigned_names_bogus() {
        let (origin, dnskey, a_record, rrsig_record, _) =
            create_test_signed_domain("signed.example.");

        let mut trust_anchors = TrustAnchors::empty();
        trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new())
            .with_trust_anchors(trust_anchors);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        let mut signed = Message::new(1, MessageType::Response, OpCode::Query);
        signed
            .queries
            .push(Query::query(origin.clone(), RecordType::A));
        signed.answers.push(a_record);
        signed.answers.push(rrsig_record);
        signed.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        ));
        assert_eq!(
            validator.validate_response(&mut signed, Some("t"), now),
            ValidationOutcome::Secure
        );

        let unrelated = Name::from_str("unrelated.test.").expect("name");
        let mut unsigned = Message::new(2, MessageType::Response, OpCode::Query);
        unsigned
            .queries
            .push(Query::query(unrelated.clone(), RecordType::A));
        unsigned.answers.push(Record::from_rdata(
            unrelated,
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        let outcome = validator.validate_response(&mut unsigned, Some("t"), now);
        assert_eq!(
            outcome,
            ValidationOutcome::Insecure,
            "an unrelated unsigned response must not be treated as a downgrade"
        );
        assert_eq!(unsigned.metadata.response_code, ResponseCode::NoError);
        assert!(!unsigned.metadata.authentic_data);
    }

    /// Within a zone that actually signed data, a response without RRSIGs is
    /// still a stripped-signature downgrade and must be Bogus.
    #[test]
    fn test_stripped_rrsig_in_proven_signed_zone_is_bogus() {
        let (origin, dnskey, a_record, rrsig_record, _) =
            create_test_signed_domain("signed.example.");

        let mut trust_anchors = TrustAnchors::empty();
        trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new())
            .with_trust_anchors(trust_anchors);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let mut signed = Message::new(1, MessageType::Response, OpCode::Query);
        signed
            .queries
            .push(Query::query(origin.clone(), RecordType::A));
        signed.answers.push(a_record);
        signed.answers.push(rrsig_record);
        signed.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        ));
        assert_eq!(
            validator.validate_response(&mut signed, Some("t"), now),
            ValidationOutcome::Secure
        );

        let other = Name::from_str("other.signed.example.").expect("name");
        let mut stripped = Message::new(2, MessageType::Response, OpCode::Query);
        stripped
            .queries
            .push(Query::query(other.clone(), RecordType::A));
        stripped.answers.push(Record::from_rdata(
            other,
            300,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 7))),
        ));
        let outcome = validator.validate_response(&mut stripped, Some("t"), now);
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "stripped signatures in a proven-signed zone must stay Bogus: {outcome:?}"
        );
        assert_eq!(stripped.metadata.response_code, ResponseCode::ServFail);
    }

    /// Regression: the chain walk must reach the root for signers with three or
    /// more labels (budget used to be a flat 6, which stopped one level short
    /// and left the zone Indeterminate on a cold cache).
    #[tokio::test]
    async fn test_chain_fetch_reaches_root_for_three_label_signer() {
        /// A DS RRset for `child`, signed by `parent_signer`.
        fn signed_ds(
            child: &Name,
            child_key: &DNSKEY,
            parent_signer: &hickory_proto::dnssec::DnssecSigner,
        ) -> Message {
            use hickory_proto::dnssec::DigestType;
            use hickory_proto::rr::RecordSet;
            let ds = DS::from_key(child_key.public_key(), child, DigestType::SHA256).expect("ds");
            let record = Record::from_rdata(child.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
            let mut set = RecordSet::new(child.clone(), RecordType::DS, 0);
            set.insert(record.clone(), 0);
            let sig = sign_test_rrset(&set, parent_signer);
            let mut message = Message::new(0, MessageType::Response, OpCode::Query);
            message.authorities.push(record);
            message.authorities.push(sig);
            message
        }

        let (root_name, root_key, root_signer) = create_test_signer(".");
        let (example, example_key, example_signer) = create_test_signer("example.");
        let (b_example, b_key, b_signer) = create_test_signer("b.example.");
        let (ab_example, ab_key, ab_signer) = create_test_signer("a.b.example.");

        let qname = Name::from_str("www.a.b.example.").unwrap();
        let (answer, answer_sig) = signed_a_response(&qname, &ab_signer);

        let fetcher = StaticFetcher::new()
            .with(
                &ab_example,
                RecordType::DNSKEY,
                fetched_dnskey_message(&ab_example, std::slice::from_ref(&ab_key), None),
            )
            .with(
                &ab_example,
                RecordType::DS,
                signed_ds(&ab_example, &ab_key, &b_signer),
            )
            .with(
                &b_example,
                RecordType::DNSKEY,
                fetched_dnskey_message(&b_example, std::slice::from_ref(&b_key), None),
            )
            .with(
                &b_example,
                RecordType::DS,
                signed_ds(&b_example, &b_key, &example_signer),
            )
            .with(
                &example,
                RecordType::DNSKEY,
                fetched_dnskey_message(&example, std::slice::from_ref(&example_key), None),
            )
            .with(
                &example,
                RecordType::DS,
                signed_ds(&example, &example_key, &root_signer),
            )
            .with(
                &root_name,
                RecordType::DNSKEY,
                fetched_dnskey_message(&root_name, std::slice::from_ref(&root_key), None),
            );

        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        validator.add_trust_anchor(&root_key, LowerName::from(&root_name));

        let mut response = Message::new(42, MessageType::Response, OpCode::Query);
        response.queries.push(Query::query(qname, RecordType::A));
        response.answers.push(answer);
        response.answers.push(answer_sig);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("cold-cache"), now, &fetcher)
            .await;

        assert_eq!(
            outcome,
            ValidationOutcome::Secure,
            "a 3-label signer must validate from a cold cache"
        );
        // DNSKEY/DS pairs for a.b.example, b.example and example plus the root
        // DNSKEY = 7 fetches, one more than the old flat budget of 6.
        assert_eq!(fetcher.calls(), 7);
    }

    /// Regression: RRSIGs appended by the chain walk are helper records for
    /// DNSKEY/DS RRsets, not evidence that the root (or any other helper
    /// zone) signed the response. Marking the root from a fetched root DNSKEY
    /// RRSIG made every later response look like a stripped downgrade.
    #[tokio::test]
    async fn test_chain_helper_rrsigs_do_not_mark_root_as_signed() {
        let (root, root_key, root_signer) = create_test_signer(".");
        let (one, one_key, one_signer) = create_test_signer("one.");

        let qname = Name::from_str("www.one.").expect("qname");
        let (answer, answer_sig) = signed_a_response(&qname, &one_signer);

        let fetcher = StaticFetcher::new()
            .with(
                &one,
                RecordType::DNSKEY,
                signed_dnskey_message(&one, &one_key, &one_signer),
            )
            .with(
                &one,
                RecordType::DS,
                signed_ds_fetch_message(&one, &one_key, &root_signer),
            )
            .with(
                &Name::root(),
                RecordType::DNSKEY,
                signed_dnskey_message(&Name::root(), &root_key, &root_signer),
            );

        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        validator.add_trust_anchor(&root_key, LowerName::from(&root));

        let mut response = Message::new(77, MessageType::Response, OpCode::Query);
        response.queries.push(Query::query(qname, RecordType::A));
        response.answers.push(answer);
        response.answers.push(answer_sig);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("helper"), now, &fetcher)
            .await;
        assert_eq!(outcome, ValidationOutcome::Secure, "{outcome:?}");

        let root_lower = LowerName::from(&root);
        assert!(
            !validator.signed_zones.contains_key(&root_lower),
            "the root must never be recorded as signed-zone evidence"
        );
        for name in ["com.", "other.test.", "www.example."] {
            let lower = LowerName::from(&Name::from_str(name).expect("name"));
            assert!(
                !validator.signed_zone_contains(&lower, now),
                "helper chain RRSIGs must not make {name} look signed"
            );
        }
        assert!(
            validator.signed_zone_contains(&LowerName::from(&one), now),
            "the zone that actually signed the answer must still be recorded"
        );
    }

    /// Regression: two different signed zones queried in sequence on a cold
    /// cache must both validate. A helper DS/DNSKEY RRSIG for the shared
    /// parent/TLD used to mark that ancestor as signed and SERVFAIL the second
    /// zone before its chain could be fetched.
    #[tokio::test]
    async fn test_two_signed_zones_cold_cache_both_secure() {
        let (tld, tld_key, tld_signer) = create_test_signer("example.");
        let (one, one_key, one_signer) = create_test_signer("one.example.");
        let (two, two_key, two_signer) = create_test_signer("two.example.");

        let fetcher = StaticFetcher::new()
            .with(
                &one,
                RecordType::DNSKEY,
                signed_dnskey_message(&one, &one_key, &one_signer),
            )
            .with(
                &one,
                RecordType::DS,
                signed_ds_fetch_message(&one, &one_key, &tld_signer),
            )
            .with(
                &tld,
                RecordType::DNSKEY,
                signed_dnskey_message(&tld, &tld_key, &tld_signer),
            )
            .with(
                &two,
                RecordType::DNSKEY,
                signed_dnskey_message(&two, &two_key, &two_signer),
            )
            .with(
                &two,
                RecordType::DS,
                signed_ds_fetch_message(&two, &two_key, &tld_signer),
            );

        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        validator.add_trust_anchor(&tld_key, LowerName::from(&tld));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        let qname_one = Name::from_str("a.one.example.").expect("qname");
        let (answer_one, sig_one) = signed_a_response(&qname_one, &one_signer);
        let mut first = Message::new(80, MessageType::Response, OpCode::Query);
        first.queries.push(Query::query(qname_one, RecordType::A));
        first.answers.push(answer_one);
        first.answers.push(sig_one);
        let outcome = validator
            .validate_with_key_fetcher(&mut first, Some("first"), now, &fetcher)
            .await;
        assert_eq!(outcome, ValidationOutcome::Secure, "{outcome:?}");
        assert!(first.metadata.authentic_data);

        let qname_two = Name::from_str("b.two.example.").expect("qname");
        let (answer_two, sig_two) = signed_a_response(&qname_two, &two_signer);
        let mut second = Message::new(81, MessageType::Response, OpCode::Query);
        second.queries.push(Query::query(qname_two, RecordType::A));
        second.answers.push(answer_two);
        second.answers.push(sig_two);
        let outcome = validator
            .validate_with_key_fetcher(&mut second, Some("second"), now, &fetcher)
            .await;
        assert_eq!(
            outcome,
            ValidationOutcome::Secure,
            "a second signed zone must not inherit the first zone's helper evidence: {outcome:?}"
        );
        assert!(second.metadata.authentic_data);
        assert_eq!(second.metadata.response_code, ResponseCode::NoError);
    }

    /// A validated NSEC denial in the authority section is relevant evidence
    /// that the signer zone is signed. A later stripped answer under it must
    /// still fail closed rather than downgrade to Insecure.
    #[test]
    fn test_validated_negative_response_marks_zone_signed() {
        let (origin, dnskey, signer) = create_test_signer("denial.example.");
        let qname = Name::from_str("missing.denial.example.").expect("qname");

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let bitmap = vec![RecordType::A, RecordType::NSEC, RecordType::RRSIG];
        let mut msg = signed_nsec_response_records(
            &origin,
            &[
                (
                    origin.clone(),
                    Name::from_str("a.denial.example.").expect("next"),
                    bitmap.clone(),
                ),
                (
                    Name::from_str("a.denial.example.").expect("owner"),
                    nsec_next(&origin),
                    bitmap,
                ),
            ],
            &qname,
            &dnskey,
            &signer,
            ResponseCode::NXDomain,
        );

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        assert_eq!(
            validator.validate_response(&mut msg, Some("neg"), now),
            ValidationOutcome::Secure
        );
        assert!(
            validator.signed_zone_contains(&LowerName::from(&origin), now),
            "a validated denial must record the signer zone as signed"
        );

        let other = Name::from_str("other.denial.example.").expect("other");
        let mut stripped = Message::new(90, MessageType::Response, OpCode::Query);
        stripped
            .queries
            .push(Query::query(other.clone(), RecordType::A));
        stripped.answers.push(Record::from_rdata(
            other,
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
        ));
        let outcome = validator.validate_response(&mut stripped, Some("neg"), now);
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a stripped answer under a zone proven signed by a denial must stay Bogus: {outcome:?}"
        );
    }

    /// Important regression: a negative response whose NSEC denial RRSIGs are
    /// present but whose DNSKEY is missing must fetch the key instead of
    /// SERVFAILing. This mirrors the positive-answer P0 after the key cache
    /// expires while signed-zone evidence is still live.
    #[tokio::test]
    async fn test_negative_response_with_denial_rrsig_fetches_key() {
        let (origin, dnskey, signer) = create_test_signer("negfetch.example.");
        let qname = Name::from_str("missing.negfetch.example.").expect("qname");

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        // Signed-zone evidence survives (cache reload / long-lived denial)
        // while the key cache is empty, as when the DNSKEY TTL expires first.
        validator
            .signed_zones
            .insert(LowerName::from(&origin), now + 300);

        let bitmap = vec![RecordType::A, RecordType::NSEC, RecordType::RRSIG];
        let mut base = signed_nsec_response_records(
            &origin,
            &[
                (
                    origin.clone(),
                    Name::from_str("a.negfetch.example.").expect("next"),
                    bitmap.clone(),
                ),
                (
                    Name::from_str("a.negfetch.example.").expect("owner"),
                    nsec_next(&origin),
                    bitmap,
                ),
            ],
            &qname,
            &dnskey,
            &signer,
            ResponseCode::NXDomain,
        );
        // Simulate an upstream response that omitted the DNSKEY.
        base.additionals
            .retain(|record| !matches!(record.data, RData::DNSSEC(DNSSECRData::DNSKEY(_))));

        let fetcher = StaticFetcher::new().with(
            &origin,
            RecordType::DNSKEY,
            signed_dnskey_message(&origin, &dnskey, &signer),
        );

        let mut msg = base.clone();
        let outcome = validator
            .validate_with_key_fetcher(&mut msg, Some("negfetch"), now, &fetcher)
            .await;
        assert_eq!(
            outcome,
            ValidationOutcome::Secure,
            "the missing DNSKEY must be fetched for a signed denial proof: {outcome:?}"
        );
        assert!(msg.metadata.authentic_data);
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(fetcher.calls(), 1, "one DNSKEY fetch must be attempted");

        // Post-fetch/offline strictness: a fresh validator with the same
        // signed-zone evidence but no cached key must fail closed when the
        // denial RRSIG still cannot be checked.
        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let offline_validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);
        offline_validator
            .signed_zones
            .insert(LowerName::from(&origin), now + 300);
        let offline = OfflineFetcher::new();
        let mut msg = base;
        let outcome = offline_validator
            .validate_with_key_fetcher(&mut msg, Some("offline"), now, &offline)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "an unverifiable denial RRSIG must fail closed after the fetch: {outcome:?}"
        );
        assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(msg.answers.len(), 0);
    }

    /// Deferred D4b: the synchronous API has no key fetcher. A relevant RRSIG
    /// without key material must therefore fail closed in strict mode instead
    /// of being returned as AD=0; log-only keeps it Indeterminate for
    /// diagnostics. Chain-walking callers use `validate_with_key_fetcher`.
    #[test]
    fn test_sync_validate_response_fails_closed_without_key_fetcher() {
        let (origin, dnskey, a_record, rrsig_record, _) =
            create_test_signed_domain("reload.example.");

        let build = || {
            let mut response = Message::new(82, MessageType::Response, OpCode::Query);
            response
                .queries
                .push(Query::query(origin.clone(), RecordType::A));
            response.answers.push(a_record.clone());
            response.answers.push(rrsig_record.clone());
            response
        };
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        let mut trust_anchors = TrustAnchors::empty();
        trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let strict = DnssecValidator::new(DnssecMode::Validate, Vec::new())
            .with_trust_anchors(trust_anchors);
        // Simulate signed-zone evidence restored from the persistent chain
        // cache after a restart while the key cache is still empty.
        strict
            .signed_zones
            .insert(LowerName::from(&origin), now + 300);

        let mut response = build();
        let outcome = strict.validate_response(&mut response, Some("reload"), now);
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a relevant RRSIG without key material must fail closed in the sync API: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
        // Deferred D5: the provisional `Indeterminate` returned by the inner
        // pass must not be counted in addition to the Bogus outcome actually
        // served. One sync call is one validation outcome.
        assert_eq!(
            strict.metrics.bogus_total.load(Ordering::Relaxed),
            1,
            "the strict sync conversion must record the Bogus outcome it serves"
        );
        assert_eq!(
            strict.metrics.indeterminate_total.load(Ordering::Relaxed),
            0,
            "the provisional inner Indeterminate must not be double-recorded"
        );

        let log_only = DnssecValidator::new(DnssecMode::LogOnly, Vec::new());
        let mut response = build();
        let outcome = log_only.validate_response(&mut response, Some("reload"), now);
        assert_eq!(outcome, ValidationOutcome::Indeterminate);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(!response.metadata.authentic_data);
        assert_eq!(
            log_only.metrics.indeterminate_total.load(Ordering::Relaxed),
            1,
            "log-only must record its final Indeterminate exactly once"
        );
        assert_eq!(
            log_only.metrics.bogus_total.load(Ordering::Relaxed),
            0,
            "log-only must not record a Bogus outcome"
        );
    }

    /// Critical regression: a forged answer with a present-but-unverifiable
    /// relevant RRSIG under a proven-signed zone must stay Bogus. The
    /// "Indeterminate so the chain can be fetched" escape is only valid on the
    /// pre-fetch pass; after the fetch fails to produce a key, the response
    /// must fail closed instead of being served unvalidated.
    #[tokio::test]
    async fn test_unverifiable_relevant_rrsig_under_proven_signed_zone_is_bogus() {
        use hickory_proto::rr::RecordSet;

        let (validator, origin, _key, _signer) = signed_zone_validator("victim.example.");
        let qname = Name::from_str("www.victim.example.").expect("qname");
        let (_fake_origin, _fake_key, fake_signer) = create_test_signer("nonexistent.");

        let forged = Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 66))),
        );
        let mut set = RecordSet::new(qname.clone(), RecordType::A, 0);
        set.insert(forged.clone(), 0);
        let fake_rrsig = sign_test_rrset(&set, &fake_signer);
        assert_eq!(
            fake_rrsig.record_type(),
            RecordType::RRSIG,
            "the forgery needs a relevant RRSIG owner/type"
        );

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        assert!(
            validator.signed_zone_contains(&LowerName::from(&origin), now),
            "the victim zone must be proven signed"
        );

        let build_response = || {
            let mut response = Message::new(83, MessageType::Response, OpCode::Query);
            response
                .queries
                .push(Query::query(qname.clone(), RecordType::A));
            response.answers.push(forged.clone());
            response.answers.push(fake_rrsig.clone());
            response
        };

        // NXDOMAIN responses from the chain walk (the fake signer does not
        // exist) and a fully offline fetcher must both fail closed.
        let nxdomain = NxdomainFetcher::new();
        let mut response = build_response();
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("forged"), now, &nxdomain)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "an unverifiable relevant RRSIG under proven signed evidence must be Bogus: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(
            response.answers.is_empty(),
            "a Bogus response must not carry answers"
        );

        let offline = OfflineFetcher::new();
        let mut response = build_response();
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("forged"), now, &offline)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a failed fetch must not downgrade an unverifiable relevant RRSIG: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.answers.len(), 0);
    }

    /// Regression: RFC 4035 5.3.3 - a validated RRset may not be cached (or
    /// served with AD=1) beyond its signature's remaining validity.
    #[test]
    fn test_authenticated_ttl_is_capped_by_signature_expiry() {
        use hickory_proto::dnssec::crypto::EcdsaSigningKey;
        use hickory_proto::dnssec::{DnssecSigner, SigningKey};
        use hickory_proto::rr::RecordSet;

        let origin = Name::from_str("shortsig.example.").unwrap();
        let pkcs8 =
            EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).expect("generate pkcs8");
        let private = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256)
            .expect("key from pkcs8");
        let dnskey = DNSKEY::from_key(&private.to_public_key().expect("public key"));
        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(private),
            origin.clone(),
            Duration::from_secs(30),
        );

        let answer = Record::from_rdata(
            origin.clone(),
            86400,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 9))),
        );
        let mut set = RecordSet::new(origin.clone(), RecordType::A, 86400);
        set.insert(answer.clone(), 0);
        let signature = sign_test_rrset(&set, &signer);

        let mut trust_anchors = TrustAnchors::empty();
        trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new())
            .with_trust_anchors(trust_anchors);

        let mut msg = Message::new(3, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        msg.answers.push(answer);
        msg.answers.push(signature);
        msg.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("ttl-test"), now);
        assert_eq!(outcome, ValidationOutcome::Secure);

        let answer_ttl = msg
            .answers
            .iter()
            .find(|record| record.record_type() == RecordType::A)
            .expect("answer")
            .ttl;
        assert!(
            answer_ttl <= 30,
            "authenticated TTL must not outlive the signature, got {answer_ttl}"
        );
        let sig_ttl = msg
            .answers
            .iter()
            .find(|record| record.record_type() == RecordType::RRSIG)
            .expect("rrsig")
            .ttl;
        assert!(
            sig_ttl <= 30,
            "the RRSIG TTL must be capped as well, got {sig_ttl}"
        );
    }

    /// A crafted response must not be able to force unbounded cryptographic
    /// work: 128 RRSIGs (bounded by `MAX_RRSIGS`) each offering 64 candidate
    /// DNSKEYs (bounded by `MAX_DNSKEYS`) used to mean thousands of ECDSA/RSA
    /// verifications per client query.
    #[test]
    fn test_crafted_dnskey_rrsig_counts_stay_within_verification_budget() {
        let (origin, dnskey, _a_record, rrsig_record, _) =
            create_test_signed_domain("bounded.example.");

        let mut trust_anchors = TrustAnchors::empty();
        trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new())
            .with_trust_anchors(trust_anchors);

        let mut msg = Message::new(4, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        // The signed RRset is replaced with a different address: every
        // candidate key fails verification, which is the attacker's
        // maximum-work case.
        msg.answers.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 9))),
        ));
        for _ in 0..MAX_RRSIGS {
            msg.answers.push(rrsig_record.clone());
        }
        for _ in 0..MAX_DNSKEYS {
            msg.additionals.push(Record::from_rdata(
                origin.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
            ));
        }

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("crafted"), now);

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "forged data must stay Bogus, got {outcome:?}"
        );
        let attempts = validator.metrics.signature_verifications();
        assert!(
            attempts <= u64::from(MAX_VERIFICATIONS_PER_RESPONSE),
            "crafted response exceeded the verification budget: {attempts} attempts"
        );
    }

    /// Builds an anchored validator whose `zone` key has already signed
    /// validated data (so the zone is recorded as signed) and returns it with
    /// the key and signer.
    fn signed_zone_validator(
        zone: &str,
    ) -> (
        DnssecValidator,
        Name,
        DNSKEY,
        hickory_proto::dnssec::DnssecSigner,
    ) {
        let (origin, dnskey, a_record, rrsig_record, signer) = create_test_signed_domain(zone);
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
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
        ));
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        assert_eq!(
            validator.validate_response(&mut msg, Some("t"), now),
            ValidationOutcome::Secure
        );
        (validator, origin, dnskey, signer)
    }

    /// An authenticated DS denial (parent-side delegation NSEC) must let an
    /// unsigned delegation resolve as Insecure instead of a stripped-signature
    /// SERVFAIL (audit 6, WP-1.2).
    #[tokio::test]
    async fn test_authenticated_ds_denial_downgrades_child_delegation_to_insecure() {
        let (validator, zone, zone_key, zone_signer) = signed_zone_validator("signed.example.");
        let cut = Name::from_str("unsigned.signed.example.").expect("cut");
        let ds_message = signed_nsec_response(
            &zone,
            &cut,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            &cut,
            &zone_key,
            &zone_signer,
            ResponseCode::NoError,
        );
        let fetcher = StaticFetcher::new().with(&cut, RecordType::DS, ds_message);

        let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");
        let mut response = Message::new(2, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        response.answers.push(Record::from_rdata(
            qname,
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;
        assert_eq!(
            outcome,
            ValidationOutcome::Insecure,
            "an authenticated DS denial must downgrade to Insecure"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(!response.metadata.authentic_data);
        assert_eq!(fetcher.calls(), 1, "only the cut DS lookup is needed");
    }

    /// Without an authenticated DS denial the stripped-signature decision must
    /// stay fail-closed (Bogus), whether the DS response is empty/unavailable
    /// or contains an authenticated DS.
    #[tokio::test]
    async fn test_unproven_delegation_stays_bogus() {
        use hickory_proto::dnssec::DigestType;
        use hickory_proto::rr::RecordSet;

        let (validator, zone, zone_key, zone_signer) = signed_zone_validator("signed.example.");
        let cut = Name::from_str("unsigned.signed.example.").expect("cut");
        let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        // Case 1: no DS answer at all (network/fetch failure) -> Unknown.
        let fetcher = StaticFetcher::new();
        let mut response = Message::new(3, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        response.answers.push(Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 8))),
        ));
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "an unprovable delegation must fail closed: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);

        // Case 2: an authenticated DS proves the cut is signed -> stripped.
        let (child_zone, child_key, _) = create_test_signer("unsigned.signed.example.");
        assert_eq!(child_zone, cut);
        let ds = DS::from_key(child_key.public_key(), &cut, DigestType::SHA256).expect("ds");
        let ds_record = Record::from_rdata(cut.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
        let mut set = RecordSet::new(cut.clone(), RecordType::DS, 0);
        set.insert(ds_record.clone(), 0);
        let ds_sig = sign_test_rrset(&set, &zone_signer);
        let mut ds_message = Message::new(0, MessageType::Response, OpCode::Query);
        ds_message.answers.push(ds_record);
        ds_message.answers.push(ds_sig);
        ds_message.additionals.push(Record::from_rdata(
            zone.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(zone_key)),
        ));
        let fetcher = StaticFetcher::new().with(&cut, RecordType::DS, ds_message);

        let mut response = Message::new(4, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        response.answers.push(Record::from_rdata(
            qname,
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 9))),
        ));
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a signed cut with a stripped response must be Bogus: {outcome:?}"
        );
    }

    /// A name directly inside the signed zone with an authenticated DS NODATA
    /// (no NS bit) still requires signatures: Bogus.
    #[tokio::test]
    async fn test_in_zone_ds_nodata_still_requires_signatures() {
        let (validator, zone, zone_key, zone_signer) = signed_zone_validator("signed.example.");
        let qname = Name::from_str("www.signed.example.").expect("qname");
        let ds_message = signed_nsec_response(
            &zone,
            &qname,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
            &qname,
            &zone_key,
            &zone_signer,
            ResponseCode::NoError,
        );
        let fetcher = StaticFetcher::new().with(&qname, RecordType::DS, ds_message);

        let mut response = Message::new(5, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        response.answers.push(Record::from_rdata(
            qname,
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "an in-zone name still requires signatures: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    }

    // ------------------------------------------------------------------
    // D-05: persistent chain/negative-DS cache and cold-start delegation probe
    // ------------------------------------------------------------------

    fn chain_test_path(tag: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sito_d05_{}_{}_{}",
            std::process::id(),
            tag,
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join("dnssec-chain-cache.toml")
    }

    fn d05_validator(cache: Option<Arc<ChainCache>>) -> DnssecValidator {
        DnssecValidator::from_config_with_cache(&DnssecConfig::default(), cache)
            .with_trust_anchors(TrustAnchors::empty())
    }

    fn anchored_dnskey_message(
        zone: &Name,
        key: &DNSKEY,
        signer: &hickory_proto::dnssec::DnssecSigner,
    ) -> Message {
        use hickory_proto::rr::RecordSet;
        let mut set = RecordSet::new(zone.clone(), RecordType::DNSKEY, 0);
        set.insert(
            Record::from_rdata(
                zone.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(key.clone())),
            ),
            0,
        );
        let signature = sign_test_rrset(&set, signer);
        fetched_dnskey_message(zone, std::slice::from_ref(key), Some(signature))
    }

    fn signed_ds_message(
        cut: &Name,
        parent_signer: &hickory_proto::dnssec::DnssecSigner,
        child_key: &DNSKEY,
    ) -> Message {
        use hickory_proto::dnssec::{DigestType, rdata::DS};
        use hickory_proto::rr::RecordSet;

        let ds = DS::from_key(child_key.public_key(), cut, DigestType::SHA256).expect("ds");
        let ds_record = Record::from_rdata(cut.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
        let mut set = RecordSet::new(cut.clone(), RecordType::DS, 0);
        set.insert(ds_record.clone(), 0);
        let signature = sign_test_rrset(&set, parent_signer);
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.answers.push(ds_record);
        message.answers.push(signature);
        message
    }

    /// A DS response proving (via an exact-match parent-side NSEC3) that the
    /// delegation at `cut` has no DS and is legitimately unsigned.
    fn signed_nsec3_ds_denial(
        parent: &Name,
        cut: &Name,
        key: &DNSKEY,
        signer: &hickory_proto::dnssec::DnssecSigner,
    ) -> Message {
        use data_encoding::BASE32_DNSSEC;
        use hickory_proto::dnssec::Nsec3HashAlgorithm;
        use hickory_proto::dnssec::rdata::NSEC3;
        use hickory_proto::rr::RecordSet;

        let algorithm = Nsec3HashAlgorithm::SHA1;
        let cut_hash = algorithm.hash(&[], cut, 0).expect("hash").as_ref().to_vec();
        let mut next = cut_hash.clone();
        for byte in next.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        let nsec3 = NSEC3::new(
            algorithm,
            false,
            0,
            Vec::new(),
            next,
            [RecordType::NS, RecordType::RRSIG, RecordType::NSEC3],
        );
        let owner = Name::from_ascii(format!(
            "{}.{}",
            BASE32_DNSSEC.encode(&cut_hash),
            parent.to_ascii()
        ))
        .expect("NSEC3 owner");
        let record =
            Record::from_rdata(owner.clone(), 300, RData::DNSSEC(DNSSECRData::NSEC3(nsec3)));
        let mut set = RecordSet::new(owner, RecordType::NSEC3, 0);
        set.insert(record.clone(), 0);
        let signature = sign_test_rrset(&set, signer);

        let mut message = Message::new(26, MessageType::Response, OpCode::Query);
        message
            .queries
            .push(Query::query(cut.clone(), RecordType::DS));
        message.metadata.response_code = ResponseCode::NoError;
        message.authorities.push(record);
        message.authorities.push(signature);
        message.additionals.push(Record::from_rdata(
            parent.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(key.clone())),
        ));
        message
    }

    fn stripped_response(qname: &Name) -> Message {
        let mut response = Message::new(7, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        response.answers.push(Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 44))),
        ));
        response
    }

    /// A DS response proving (via a covering NSEC) that `cut` does not exist
    /// in `parent`, signed by the parent zone key.
    fn covering_nsec_ds_message(
        parent: &Name,
        owner: &Name,
        next: &Name,
        cut: &Name,
        key: &DNSKEY,
        signer: &hickory_proto::dnssec::DnssecSigner,
    ) -> Message {
        signed_nsec_response_records(
            parent,
            &[(
                owner.clone(),
                next.clone(),
                vec![RecordType::A, RecordType::NSEC, RecordType::RRSIG],
            )],
            cut,
            key,
            signer,
            ResponseCode::NXDomain,
        )
    }

    /// A stripped CNAME chain: `qname` points at `target`, and both the CNAME
    /// and target A records carry no RRSIGs.
    fn stripped_cname_response(qname: &Name, target: &Name) -> Message {
        use hickory_proto::rr::rdata::CNAME;
        let mut response = Message::new(8, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        response.answers.push(Record::from_rdata(
            qname.clone(),
            300,
            RData::CNAME(CNAME(target.clone())),
        ));
        response.answers.push(Record::from_rdata(
            target.clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 45))),
        ));
        response
    }

    /// Critical regression: a stripped CNAME chain whose *target* is in a
    /// signed zone must be Bogus even when the original qname is an
    /// authenticated unsigned delegation.
    #[tokio::test]
    async fn test_stripped_cname_target_in_signed_zone_is_bogus() {
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let unsigned_cut = Name::from_str("unsigned.signed.example.").expect("cut");
        let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");
        let target = Name::from_str("www.signed.example.").expect("target");

        let validator = d05_validator(None);
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

        let unsigned_denial = signed_nsec_response(
            &parent_origin,
            &unsigned_cut,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            &unsigned_cut,
            &parent_key,
            &parent_signer,
            ResponseCode::NoError,
        );
        // The target exists inside the signed zone and is not a delegation.
        let target_in_zone = signed_nsec_response(
            &parent_origin,
            &target,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
            &target,
            &parent_key,
            &parent_signer,
            ResponseCode::NoError,
        );
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(&unsigned_cut, RecordType::DS, unsigned_denial)
            .with(&target, RecordType::DS, target_in_zone);

        let mut response = stripped_cname_response(&qname, &target);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a stripped CNAME target in a signed zone must be Bogus: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
        assert!(
            response.answers.is_empty(),
            "bogus response must not carry the target answer: {:?}",
            response.answers
        );
    }

    /// Important regression: a stripped NXDOMAIN for a name directly in the
    /// anchor zone is proven by a *covering* NSEC (owned by another name).
    #[tokio::test]
    async fn test_stripped_nxdomain_in_anchor_zone_is_bogus() {
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let qname = Name::from_str("missing.signed.example.").expect("qname");

        let validator = d05_validator(None);
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

        let ds_denial = covering_nsec_ds_message(
            &parent_origin,
            &Name::from_str("a.signed.example.").expect("owner"),
            &Name::from_str("z.signed.example.").expect("next"),
            &qname,
            &parent_key,
            &parent_signer,
        );
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(&qname, RecordType::DS, ds_denial);

        let mut response = Message::new(11, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        response.metadata.response_code = ResponseCode::NXDomain;

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a stripped NXDOMAIN in the anchor zone must be Bogus: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
    }

    /// Important regression: a stripped wildcard-synthesized answer directly
    /// in the anchor zone is proven signed by the same covering-NSEC DS denial.
    #[tokio::test]
    async fn test_stripped_wildcard_answer_in_anchor_zone_is_bogus() {
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let qname = Name::from_str("wildcard.signed.example.").expect("qname");

        let validator = d05_validator(None);
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

        let ds_denial = covering_nsec_ds_message(
            &parent_origin,
            &Name::from_str("a.signed.example.").expect("owner"),
            &Name::from_str("z.signed.example.").expect("next"),
            &qname,
            &parent_key,
            &parent_signer,
        );
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(&qname, RecordType::DS, ds_denial);

        // The wildcard at *.signed.example. synthesized this A answer; the
        // response carries no RRSIGs.
        let mut response = stripped_response(&qname);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a stripped wildcard answer in the anchor zone must be Bogus: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
    }

    /// A stripped multi-hop CNAME chain ending in an A record. `targets` are
    /// the successive CNAME targets (the first target replaces `qname`).
    fn stripped_cname_chain_response(qname: &Name, targets: &[Name]) -> Message {
        use hickory_proto::rr::rdata::CNAME;
        let mut response = Message::new(9, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        let mut current = qname.clone();
        for target in targets {
            response.answers.push(Record::from_rdata(
                current,
                300,
                RData::CNAME(CNAME(target.clone())),
            ));
            current = target.clone();
        }
        response.answers.push(Record::from_rdata(
            current,
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 46))),
        ));
        response
    }

    /// Critical regression: unsigned qname → signed intermediate CNAME hop →
    /// unsigned final target, all signatures stripped, must be Bogus. Probing
    /// only the qname and final target would miss the signed intermediate.
    #[tokio::test]
    async fn test_stripped_signed_intermediate_cname_hop_is_bogus() {
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let unsigned_cut = Name::from_str("unsigned.signed.example.").expect("unsigned cut");
        let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");
        let mid = Name::from_str("mid.signed.example.").expect("mid");
        let final_cut = Name::from_str("unsigned2.signed.example.").expect("final cut");
        let final_target = Name::from_str("www.unsigned2.signed.example.").expect("final");

        let validator = d05_validator(None);
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

        let unsigned_denial = signed_nsec_response(
            &parent_origin,
            &unsigned_cut,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            &unsigned_cut,
            &parent_key,
            &parent_signer,
            ResponseCode::NoError,
        );
        // The intermediate name lives directly in the signed anchor zone and
        // is not a delegation.
        let mid_in_zone = signed_nsec_response(
            &parent_origin,
            &mid,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
            &mid,
            &parent_key,
            &parent_signer,
            ResponseCode::NoError,
        );
        let final_denial = signed_nsec_response(
            &parent_origin,
            &final_cut,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            &final_cut,
            &parent_key,
            &parent_signer,
            ResponseCode::NoError,
        );
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(&unsigned_cut, RecordType::DS, unsigned_denial)
            .with(&mid, RecordType::DS, mid_in_zone)
            .with(&final_cut, RecordType::DS, final_denial);

        let mut response = stripped_cname_chain_response(&qname, &[mid, final_target]);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a stripped signed intermediate CNAME hop must be Bogus: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
        assert!(
            response.answers.is_empty(),
            "bogus response must not carry the chain: {:?}",
            response.answers
        );
    }

    /// The shared per-response probe budget fails closed instead of probing an
    /// unbounded CNAME chain or returning AD=0.
    #[tokio::test]
    async fn test_cname_probe_budget_exhaustion_fails_closed() {
        let (origin, key, signer) = create_test_signer("example.");
        let qname = Name::from_str("n0.example.").expect("qname");
        let targets: Vec<Name> = (1..=9)
            .map(|index| Name::from_str(&format!("n{index}.example.")).expect("target"))
            .collect();

        let validator = d05_validator(None);
        validator.add_trust_anchor(&key, LowerName::from(&origin));
        // Only the anchor DNSKEY is available; every DS lookup returns an
        // empty message, so each probe is a genuine failed walk.
        let fetcher = StaticFetcher::new().with(
            &origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&origin, &key, &signer),
        );

        let mut response = stripped_cname_chain_response(&qname, &targets);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "an over-budget CNAME chain must fail closed: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
        assert!(
            fetcher.calls() <= 2 * MAX_CNAME_PROBES + 2,
            "probing must stay within the shared budget, got {} fetches",
            fetcher.calls()
        );
    }

    /// Positive NSEC3 regression: a *properly signed* NSEC3 NXDOMAIN proof for
    /// a name directly in the anchor zone still makes a stripped response
    /// Bogus.
    #[tokio::test]
    async fn test_stripped_nxdomain_with_signed_nsec3_denial_is_bogus() {
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let qname = Name::from_str("missing.signed.example.").expect("qname");

        let validator = d05_validator(None);
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

        let ds_denial = signed_optout_nxdomain(
            &parent_origin,
            &qname,
            &parent_key,
            &parent_signer,
            false,
            0,
        );
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(&qname, RecordType::DS, ds_denial);

        let mut response = Message::new(12, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        response.metadata.response_code = ResponseCode::NXDomain;

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a signed NSEC3 NXDOMAIN proof must still make a stripped response Bogus: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
    }

    /// `InZone` may only be inferred from NSEC3 records whose RRset carries an
    /// RRSIG verified by a parent-zone key. An unsigned/forged covering proof
    /// must not mark the cut signed or persist a Signed zone.
    #[tokio::test]
    async fn test_forged_nsec3_covering_proof_is_not_inzone_or_signed() {
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let cut = Name::from_str("missing.signed.example.").expect("cut");

        let validator = d05_validator(None);
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

        let mut forged =
            signed_optout_nxdomain(&parent_origin, &cut, &parent_key, &parent_signer, false, 0);
        forged
            .authorities
            .retain(|record| !matches!(record.data, RData::DNSSEC(DNSSECRData::RRSIG(_))));
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(&cut, RecordType::DS, forged);

        let mut response = Message::new(13, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(cut.clone(), RecordType::A));
        response.metadata.response_code = ResponseCode::NXDomain;

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "an unauthenticated covering proof must not produce InZone/Signed: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
        assert!(
            validator
                .chain_cache()
                .get(&LowerName::from(&cut), now)
                .is_none(),
            "a forged proof must not persist a Signed zone"
        );
        assert!(
            !validator.signed_zone_contains(&LowerName::from(&cut), now),
            "a forged proof must not mark the cut signed in memory"
        );
    }

    /// Important regression: the probe must walk the *shallowest* cuts. A deep
    /// name beyond the per-query budget fails closed (Bogus), never AD=0.
    #[tokio::test]
    async fn test_deep_name_beyond_probe_budget_fails_closed() {
        let (root_origin, root_key, root_signer) = create_test_signer(".");
        let qname = Name::from_str("a.b.c.d.e.f.g.h.i.example.").expect("qname");
        let zone = LowerName::from(&root_origin);

        // The eight shallowest cuts must be the ones walked. Hard-code them so
        // the fixture cannot silently adapt to a deepest-first regression.
        let shallow = [
            "example.",
            "i.example.",
            "h.i.example.",
            "g.h.i.example.",
            "f.g.h.i.example.",
            "e.f.g.h.i.example.",
            "d.e.f.g.h.i.example.",
            "c.d.e.f.g.h.i.example.",
        ];
        let mut fetcher = StaticFetcher::new().with(
            &root_origin,
            RecordType::DNSKEY,
            anchored_dnskey_message(&root_origin, &root_key, &root_signer),
        );
        for cut in shallow {
            let cut_name = Name::from_str(cut).expect("cut");
            let next = Name::from_str(&format!("zzz.{cut}")).expect("next");
            let ds_nodata = signed_nsec_response(
                &root_origin,
                &cut_name,
                &next,
                &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
                &cut_name,
                &root_key,
                &root_signer,
                ResponseCode::NoError,
            );
            fetcher = fetcher.with(&cut_name, RecordType::DS, ds_nodata);
        }

        let validator = d05_validator(None);
        validator.add_trust_anchor(&root_key, zone);
        let mut response = stripped_response(&qname);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a deep name beyond the probe budget must fail closed: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
        assert!(
            fetcher.calls() > MAX_CHAIN_CUTS,
            "the shallow budget must actually be walked"
        );
    }

    /// `delegation_cuts` keeps the shallowest cuts and reports truncation.
    #[test]
    fn test_delegation_cuts_keep_shallowest_budget() {
        let zone = LowerName::from(&Name::from_str(".").expect("root"));
        let name = LowerName::from(&Name::from_str("a.b.c.d.e.f.g.h.i.example.").expect("name"));
        let (cuts, truncated) = delegation_cuts(&name, &zone);
        assert!(truncated, "the test name must exceed the probe budget");
        assert_eq!(cuts.len(), MAX_CHAIN_CUTS);
        assert_eq!(
            cuts.first(),
            Some(&LowerName::from(
                &Name::from_str("example.").expect("shallowest cut")
            )),
            "the budget must keep the shallowest cuts"
        );
        assert_eq!(
            cuts.last(),
            Some(&LowerName::from(
                &Name::from_str("c.d.e.f.g.h.i.example.").expect("eighth cut")
            )),
            "the eighth shallowest cut is the deepest one kept"
        );
    }

    /// Cold start, no prior signed data: an authenticated DS for the cut must
    /// turn a stripped response into Bogus. This is the core D-05 fix.
    #[tokio::test]
    async fn test_stripped_rrsig_never_validated_zone_is_bogus() {
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let (cut_origin, cut_key, _cut_signer) = create_test_signer("child.signed.example.");

        let validator = d05_validator(None);
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(
                &cut_origin,
                RecordType::DS,
                signed_ds_message(&cut_origin, &parent_signer, &cut_key),
            );

        let mut response = stripped_response(&cut_origin);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a never-validated zone with an authenticated DS must be Bogus: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
        assert!(
            response.answers.is_empty(),
            "bogus response must not carry answers: {:?}",
            response.answers
        );
        assert!(
            fetcher.calls() >= 2,
            "cold start must fetch the anchor DNSKEY and the cut DS"
        );

        // The authenticated decision is cached for the queried name: a repeat
        // stripped response is Bogus without walking the chain again.
        let calls_after_first = fetcher.calls();
        let mut repeat = stripped_response(&cut_origin);
        let repeat_outcome = validator
            .validate_with_key_fetcher(&mut repeat, Some("probe"), now, &fetcher)
            .await;
        assert!(matches!(repeat_outcome, ValidationOutcome::Bogus { .. }));
        assert_eq!(
            fetcher.calls(),
            calls_after_first,
            "the cached signed decision must avoid a second DS walk"
        );
    }

    /// A genuinely unsigned zone must stay Insecure (NOERROR, AD=0), not Bogus.
    #[tokio::test]
    async fn test_genuinely_unsigned_zone_authenticated_ds_denial_is_insecure() {
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let cut = Name::from_str("unsigned.signed.example.").expect("cut");
        let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");

        let validator = d05_validator(None);
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

        let ds_denial = signed_nsec_response(
            &parent_origin,
            &cut,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            &cut,
            &parent_key,
            &parent_signer,
            ResponseCode::NoError,
        );
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(&cut, RecordType::DS, ds_denial);

        let mut response = stripped_response(&qname);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert_eq!(
            outcome,
            ValidationOutcome::Insecure,
            "an authenticated DS denial proves the delegation is unsigned"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(!response.metadata.authentic_data);
        assert_eq!(
            response.answers.len(),
            1,
            "insecure answers are passed through"
        );
    }

    /// A genuinely unsigned zone whose DS denial is authenticated by an exact
    /// NSEC3 record (not an NSEC/opt-out covering proof) must also be Insecure,
    /// including on a cold start.
    #[tokio::test]
    async fn test_cold_start_nsec3_ds_denial_is_insecure() {
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let cut = Name::from_str("unsigned.signed.example.").expect("cut");
        let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");

        let validator = d05_validator(None);
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

        let ds_denial = signed_nsec3_ds_denial(&parent_origin, &cut, &parent_key, &parent_signer);
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(&cut, RecordType::DS, ds_denial);

        let mut response = stripped_response(&qname);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert_eq!(
            outcome,
            ValidationOutcome::Insecure,
            "an exact NSEC3 DS denial must prove the delegation is unsigned"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(!response.metadata.authentic_data);
        assert!(
            validator
                .chain_cache()
                .covers_unsigned(&LowerName::from(&cut), now)
                .is_some(),
            "the authenticated unsigned delegation must be cached"
        );
    }

    /// Important regression (I1): a persistent `Unsigned` chain-cache entry
    /// established before `corp.` was anchored must not keep a stripped
    /// response under the newly anchored zone Insecure. Adding the anchor
    /// invalidates the cached denial and the fresh probe makes it Bogus.
    #[tokio::test]
    async fn test_cached_unsigned_does_not_override_new_trust_anchor() {
        let (corp_origin, corp_key, corp_signer) = create_test_signer("corp.");
        let qname = Name::from_str("www.corp.").expect("qname");
        let corp_zone = LowerName::from(&corp_origin);

        let cache = Arc::new(ChainCache::new(None));
        let validator =
            DnssecValidator::from_config_with_cache(&DnssecConfig::default(), Some(cache.clone()))
                .with_trust_anchors(TrustAnchors::empty());
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        // A previous (unanchored) run authenticated a DS denial for `corp.`
        // and persisted it for an hour.
        cache.insert(
            corp_zone.clone(),
            ZoneStatus::Unsigned,
            now.saturating_add(3600),
            now,
        );
        assert!(
            !validator.insecure_zone_covers(&corp_zone, now),
            "sanity: the in-memory map starts empty"
        );

        // The operator now anchors `corp.` and reloads.
        validator.add_trust_anchor(&corp_key, corp_zone.clone());
        assert!(
            cache.get(&corp_zone, now).is_none(),
            "the stale unsigned entry must be invalidated by the new anchor"
        );

        let in_zone = signed_nsec_response(
            &corp_origin,
            &qname,
            &Name::from_str("z.corp.").expect("next"),
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
            &qname,
            &corp_key,
            &corp_signer,
            ResponseCode::NoError,
        );
        let fetcher = StaticFetcher::new()
            .with(
                &corp_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&corp_origin, &corp_key, &corp_signer),
            )
            .with(&qname, RecordType::DS, in_zone);

        let mut response = stripped_response(&qname);
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a stripped response under a newly anchored zone must be Bogus: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
    }

    /// Regression A: a legitimate unsigned child below a configured anchor
    /// must keep its cached proof across a reload. Only an anchor at or below
    /// the cached unsigned zone may invalidate it.
    #[tokio::test]
    async fn test_cached_unsigned_child_below_anchor_survives_reload() {
        use base64::Engine as _;

        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let (child_origin, child_key, _child_signer) =
            create_test_signer("unsigned.signed.example.");
        let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        let anchor = format!(
            "signed.example:13:{}",
            base64::engine::general_purpose::STANDARD
                .encode(parent_key.public_key().public_bytes())
        );
        let config = DnssecConfig {
            trust_anchors: vec![anchor],
            ..Default::default()
        };

        let cache = Arc::new(ChainCache::new(None));
        let validator = DnssecValidator::from_config_with_cache(&config, Some(cache.clone()));

        let ds_denial = signed_nsec_response(
            &parent_origin,
            &child_origin,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            &child_origin,
            &parent_key,
            &parent_signer,
            ResponseCode::NoError,
        );
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(&child_origin, RecordType::DS, ds_denial);

        let mut response = stripped_response(&qname);
        let first = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;
        assert_eq!(
            first,
            ValidationOutcome::Insecure,
            "the child delegation is authenticated as unsigned"
        );
        let child_zone = LowerName::from(&child_origin);
        assert!(
            cache.covers_unsigned(&child_zone, now).is_some(),
            "the unsigned child must be cached"
        );

        // Reproduce the hard case: signed evidence for the parent is also
        // cached, so an offline probe would fail closed if the child's unsigned
        // proof were dropped.
        cache.insert(
            LowerName::from(&parent_origin),
            ZoneStatus::Signed,
            now.saturating_add(600),
            now,
        );

        // Reload with the same configured anchor. The child's cached unsigned
        // proof must survive.
        let reloaded = DnssecValidator::from_config_with_cache(&config, Some(cache.clone()));
        assert!(
            cache.covers_unsigned(&child_zone, now).is_some(),
            "reload must not evict a legitimate unsigned child below the anchor"
        );
        let offline = OfflineFetcher::new();
        let mut response = stripped_response(&qname);
        let outcome = reloaded
            .validate_with_key_fetcher(&mut response, Some("offline"), now, &offline)
            .await;
        assert_eq!(
            outcome,
            ValidationOutcome::Insecure,
            "a cached unsigned child must stay Insecure across reload while offline"
        );

        // An anchor at/below the child contradicts its cached denial and must
        // still invalidate it (the original I1 protection).
        let child_anchored = DnssecValidator::from_config_with_cache(&config, Some(cache.clone()));
        child_anchored.add_trust_anchor(&child_key, child_zone.clone());
        assert!(
            cache.covers_unsigned(&child_zone, now).is_none(),
            "an anchor at the cached unsigned zone must invalidate it"
        );
        let offline = OfflineFetcher::new();
        let mut response = stripped_response(&qname);
        let outcome = child_anchored
            .validate_with_key_fetcher(&mut response, Some("offline"), now, &offline)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a newly anchored zone must fail closed: {outcome:?}"
        );
    }

    /// Regression (deferred D2): a non-root anchor island below an
    /// authenticated unsigned delegation must not be shadowed by the parent's
    /// Insecure status. `cached_unsigned_zone` already honored the anchor, but
    /// `insecure_zone_covers` did not, so a stripped response under the island
    /// could take the Insecure shortcut without probing the anchor.
    #[tokio::test]
    async fn test_anchor_island_under_unsigned_delegation_is_not_insecure() {
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let unsigned_cut = Name::from_str("unsigned.signed.example.").expect("cut");
        let (island_origin, island_key, island_signer) =
            create_test_signer("island.unsigned.signed.example.");
        let qname = Name::from_str("www.island.unsigned.signed.example.").expect("qname");
        let sibling = Name::from_str("www.unsigned.signed.example.").expect("sibling");
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        let validator = d05_validator(None);
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));
        validator.add_trust_anchor(&island_key, LowerName::from(&island_origin));

        // Populate the unsigned parent through the normal validation path: a
        // sibling query authenticates the parent-side DS denial for the
        // unsigned delegation. This is the state that used to shadow the
        // island after a reload.
        let ds_denial = signed_nsec_response(
            &parent_origin,
            &unsigned_cut,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            &unsigned_cut,
            &parent_key,
            &parent_signer,
            ResponseCode::NoError,
        );
        let sibling_fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(&unsigned_cut, RecordType::DS, ds_denial);
        let mut sibling_response = stripped_response(&sibling);
        let sibling_outcome = validator
            .validate_with_key_fetcher(
                &mut sibling_response,
                Some("sibling"),
                now,
                &sibling_fetcher,
            )
            .await;
        assert_eq!(
            sibling_outcome,
            ValidationOutcome::Insecure,
            "the sibling must be authenticated as an unsigned delegation"
        );
        assert!(
            validator
                .insecure_zones
                .contains_key(&LowerName::from(&unsigned_cut)),
            "the normal path must populate the in-memory unsigned zone"
        );

        assert!(
            !validator.insecure_zone_covers(&LowerName::from(&qname), now),
            "the parent's unsigned status must not cover the anchored island"
        );

        // Sibling names outside the island still legitimately use the
        // authenticated parent-side denial.
        assert!(
            validator.insecure_zone_covers(&LowerName::from(&sibling), now),
            "names outside the anchor island must remain Insecure"
        );

        // A stripped answer under the island must fail closed instead of
        // being accepted as an unsigned delegation.
        let in_zone = signed_nsec_response(
            &island_origin,
            &qname,
            &nsec_next(&island_origin),
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
            &qname,
            &island_key,
            &island_signer,
            ResponseCode::NoError,
        );
        let fetcher = StaticFetcher::new()
            .with(
                &island_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&island_origin, &island_key, &island_signer),
            )
            .with(&qname, RecordType::DS, in_zone);
        let mut response = stripped_response(&qname);
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a stripped response under an anchored island must be Bogus: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
    }

    /// The `AddedAnchors` arm of `from_config_with_cache` must prune only the
    /// affected process-local unsigned zones, leaving unrelated ones intact.
    #[test]
    fn test_reload_added_anchor_prunes_only_affected_in_memory_unsigned_zones() {
        use base64::Engine as _;

        let (signed_origin, signed_key, _signed_signer) = create_test_signer("signed.example.");
        let (other_origin, other_key, _other_signer) = create_test_signer("other.example.");
        let anchor = |origin: &Name, key: &DNSKEY| {
            format!(
                "{}:13:{}",
                origin.to_ascii().trim_end_matches('.'),
                base64::engine::general_purpose::STANDARD.encode(key.public_key().public_bytes())
            )
        };
        let config_one = DnssecConfig {
            trust_anchors: vec![anchor(&signed_origin, &signed_key)],
            ..Default::default()
        };
        let config_two = DnssecConfig {
            trust_anchors: vec![
                anchor(&signed_origin, &signed_key),
                anchor(&other_origin, &other_key),
            ],
            ..Default::default()
        };

        let validator = DnssecValidator::from_config_with_cache(
            &config_one,
            Some(Arc::new(ChainCache::new(None))),
        );
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let affected = LowerName::from(&other_origin);
        let unrelated = LowerName::from(
            &Name::from_str("unsigned.signed.example.").expect("unrelated unsigned zone"),
        );
        validator
            .insecure_zones
            .insert(affected.clone(), now.saturating_add(600));
        validator
            .insecure_zones
            .insert(unrelated.clone(), now.saturating_add(600));

        // A reload builds a new validator with empty process-local maps, so the
        // shared policy-apply path is exercised on this validator to retain the
        // seeded `insecure_zones`. Insert the anchor without the direct
        // `add_trust_anchor` invalidation that the policy diff must perform.
        validator.insert_raw_trust_anchor(other_key.public_key(), &affected);
        validator.anchor_zones.insert(affected.clone(), ());
        let change = validator.apply_chain_cache_policy(&config_two);
        assert_eq!(
            change,
            PolicyChange::AddedAnchors(vec![affected.clone()]),
            "the second config only adds the other.example. anchor"
        );
        assert!(
            !validator.insecure_zones.contains_key(&affected),
            "an added anchor must clear the in-memory unsigned zone at the anchor"
        );
        assert!(
            validator.insecure_zones.contains_key(&unrelated),
            "an unrelated in-memory unsigned zone must survive an anchor addition"
        );
    }

    /// Important regression (I2): an offline probe for a CNAME target in a
    /// signed zone must not fall through to Insecure just because the original
    /// qname is a legitimately unsigned delegation. In strict mode it fails
    /// closed with SERVFAIL.
    #[tokio::test]
    async fn test_failed_cname_target_probe_fails_closed_not_insecure() {
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let unsigned_cut = Name::from_str("unsigned.signed.example.").expect("cut");
        let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");
        let target = Name::from_str("www.signed.example.").expect("target");

        let validator = d05_validator(None);
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

        let unsigned_denial = signed_nsec_response(
            &parent_origin,
            &unsigned_cut,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            &unsigned_cut,
            &parent_key,
            &parent_signer,
            ResponseCode::NoError,
        );
        // The target's DS lookup is deliberately absent: the probe is offline.
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(&unsigned_cut, RecordType::DS, unsigned_denial);

        let mut response = stripped_cname_response(&qname, &target);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a failed probe for a signed CNAME target must SERVFAIL, not Insecure: {outcome:?}"
        );
        assert!(!response.metadata.authentic_data);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    }

    /// A root-anchored cold start must follow a signed intermediate cut
    /// (`tld.`) and still classify a deeper unsigned delegation as Insecure,
    /// not Bogus. This guards the nested-unsigned false-positive case.
    #[tokio::test]
    async fn test_cold_start_follows_signed_cut_before_unsigned_delegation() {
        let (root_origin, root_key, root_signer) = create_test_signer(".");
        let (tld_origin, tld_key, tld_signer) = create_test_signer("tld.");
        let cut = Name::from_str("unsigned.tld.").expect("cut");
        let qname = Name::from_str("www.unsigned.tld.").expect("qname");

        let validator = d05_validator(None);
        validator.add_trust_anchor(&root_key, LowerName::from(&root_origin));

        let tld_ds = signed_ds_message(&tld_origin, &root_signer, &tld_key);
        let tld_denial = signed_nsec_response(
            &tld_origin,
            &cut,
            &Name::from_str("z.tld.").expect("next"),
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            &cut,
            &tld_key,
            &tld_signer,
            ResponseCode::NoError,
        );
        let fetcher = StaticFetcher::new()
            .with(
                &root_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&root_origin, &root_key, &root_signer),
            )
            .with(&tld_origin, RecordType::DS, tld_ds)
            .with(
                &tld_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&tld_origin, &tld_key, &tld_signer),
            )
            .with(&cut, RecordType::DS, tld_denial);

        let mut response = stripped_response(&qname);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert_eq!(
            outcome,
            ValidationOutcome::Insecure,
            "a nested unsigned delegation must remain Insecure after walking a signed TLD"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(!response.metadata.authentic_data);
        assert!(
            fetcher.calls() >= 4,
            "the walk must fetch the root keys, the TLD DS/DNSKEY and the denial"
        );
    }

    /// The authenticated unsigned status is cached: the second query under the
    /// same zone does not fetch again.
    #[tokio::test]
    async fn test_delegation_cache_hit_skips_fetches() {
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let cut = Name::from_str("unsigned.signed.example.").expect("cut");
        let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");

        let cache = Arc::new(ChainCache::new(None));
        let validator = d05_validator(Some(cache.clone()));
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

        let ds_denial = signed_nsec_response(
            &parent_origin,
            &cut,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            &cut,
            &parent_key,
            &parent_signer,
            ResponseCode::NoError,
        );
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(&cut, RecordType::DS, ds_denial);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let mut first = stripped_response(&qname);
        let first_outcome = validator
            .validate_with_key_fetcher(&mut first, Some("probe"), now, &fetcher)
            .await;
        assert_eq!(first_outcome, ValidationOutcome::Insecure);
        let calls_after_first = fetcher.calls();
        assert!(calls_after_first > 0);

        let mut second = stripped_response(&qname);
        let second_outcome = validator
            .validate_with_key_fetcher(&mut second, Some("probe"), now, &fetcher)
            .await;
        assert_eq!(second_outcome, ValidationOutcome::Insecure);
        assert_eq!(
            fetcher.calls(),
            calls_after_first,
            "the cached unsigned delegation must not be re-probed"
        );
    }

    /// A cached Signed zone makes a stripped response Bogus without any fetch.
    #[tokio::test]
    async fn test_signed_zone_cache_hit_avoids_ds_fetch() {
        let zone = Name::from_str("child.signed.example.").expect("zone");
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let cache = Arc::new(ChainCache::new(None));
        // The validator records the policy fingerprint on construction; seed
        // the entry afterwards so it belongs to the active policy.
        let validator = d05_validator(Some(cache.clone()));
        assert!(
            Arc::ptr_eq(validator.chain_cache(), &cache),
            "the validator must reuse the supplied cache"
        );
        cache.insert(LowerName::from(&zone), ZoneStatus::Signed, now + 600, now);
        let fetcher = StaticFetcher::new();
        let mut response = stripped_response(&zone);
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a cached signed zone must fail closed immediately: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(fetcher.calls(), 0, "a cache hit must not fetch anything");
    }

    /// Authenticated statuses survive a restart through the on-disk cache.
    #[tokio::test]
    async fn test_chain_cache_survives_restart() {
        let path = chain_test_path("restart");
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let (cut_origin, cut_key, _cut_signer) = create_test_signer("child.signed.example.");
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(
                &cut_origin,
                RecordType::DS,
                signed_ds_message(&cut_origin, &parent_signer, &cut_key),
            );

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let first_cache = Arc::new(ChainCache::new(Some(path.clone())));
        first_cache.load(now);
        let first_validator = d05_validator(Some(first_cache.clone()));
        first_validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));

        let mut first = stripped_response(&cut_origin);
        let first_outcome = first_validator
            .validate_with_key_fetcher(&mut first, Some("probe"), now, &fetcher)
            .await;
        assert!(matches!(first_outcome, ValidationOutcome::Bogus { .. }));
        assert!(
            matches!(
                first_cache.get(&LowerName::from(&cut_origin), now),
                Some(ChainEntry {
                    status: ZoneStatus::Signed,
                    ..
                })
            ),
            "the authenticated signed status must be cached"
        );
        first_cache.flush().expect("flush chain cache");

        // "Restart": rebuild the cache and the validator from the same path.
        let second_cache = Arc::new(ChainCache::new(Some(path.clone())));
        second_cache.load(now);
        let second_validator = d05_validator(Some(second_cache.clone()));
        second_validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));
        let second_fetcher = StaticFetcher::new();

        let mut second = stripped_response(&cut_origin);
        let second_outcome = second_validator
            .validate_with_key_fetcher(&mut second, Some("probe"), now, &second_fetcher)
            .await;
        assert!(
            matches!(second_outcome, ValidationOutcome::Bogus { .. }),
            "a persisted signed zone must still fail closed after restart: {second_outcome:?}"
        );
        assert_eq!(
            second_fetcher.calls(),
            0,
            "the persisted cache must avoid a cold-start fetch"
        );

        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// An expired cache entry is ignored and the zone is re-probed.
    #[tokio::test]
    async fn test_chain_cache_expiry_reprobes() {
        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let (cut_origin, cut_key, _cut_signer) = create_test_signer("child.signed.example.");
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        let cache = Arc::new(ChainCache::new(None));
        cache.insert(
            LowerName::from(&cut_origin),
            ZoneStatus::Signed,
            now - 1,
            now - 2,
        );
        assert!(
            cache.get(&LowerName::from(&cut_origin), now).is_none(),
            "expired entries must not be returned"
        );

        let validator = d05_validator(Some(cache));
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(
                &cut_origin,
                RecordType::DS,
                signed_ds_message(&cut_origin, &parent_signer, &cut_key),
            );

        let mut response = stripped_response(&cut_origin);
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;
        assert!(matches!(outcome, ValidationOutcome::Bogus { .. }));
        assert!(
            fetcher.calls() >= 2,
            "an expired entry must trigger a fresh walk"
        );
    }

    /// A corrupt cache file never prevents startup; the probe still works.
    #[tokio::test]
    async fn test_chain_cache_corrupt_file_ignored() {
        let path = chain_test_path("corrupt");
        std::fs::write(&path, "entries = [ { this is not toml").expect("write corrupt");

        let (parent_origin, parent_key, parent_signer) = create_test_signer("signed.example.");
        let (cut_origin, cut_key, _cut_signer) = create_test_signer("child.signed.example.");
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let cache = Arc::new(ChainCache::new(Some(path.clone())));
        cache.load(now);
        assert!(cache.is_empty(), "a corrupt file must load as empty");

        let validator = d05_validator(Some(cache));
        validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));
        let fetcher = StaticFetcher::new()
            .with(
                &parent_origin,
                RecordType::DNSKEY,
                anchored_dnskey_message(&parent_origin, &parent_key, &parent_signer),
            )
            .with(
                &cut_origin,
                RecordType::DS,
                signed_ds_message(&cut_origin, &parent_signer, &cut_key),
            );

        let mut response = stripped_response(&cut_origin);
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "cold-start validation must still work after a corrupt cache: {outcome:?}"
        );

        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// A fetcher whose upstream answers every chain lookup with NXDOMAIN.
    struct NxdomainFetcher {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl NxdomainFetcher {
        fn new() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl DnssecKeyFetcher for NxdomainFetcher {
        async fn query(&self, name: &Name, _rtype: RecordType) -> Result<Message, UpstreamError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut message = Message::new(0, MessageType::Response, OpCode::Query);
            message
                .queries
                .push(Query::query(name.clone(), RecordType::DNSKEY));
            message.metadata.response_code = ResponseCode::NXDomain;
            Ok(message)
        }
    }

    struct OfflineFetcher {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl OfflineFetcher {
        fn new() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl DnssecKeyFetcher for OfflineFetcher {
        async fn query(&self, _name: &Name, _rtype: RecordType) -> Result<Message, UpstreamError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(UpstreamError::Timeout)
        }
    }

    /// Offline policy: a never-proven zone fails closed (Bogus/SERVFAIL) and is
    /// backed off, cached signed evidence stays fail-closed (Bogus), and cached
    /// unsigned evidence stays Insecure.
    #[tokio::test]
    async fn test_offline_probe_policy() {
        let qname = Name::from_str("www.never.example.").expect("qname");
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        let validator = DnssecValidator::from_config(&DnssecConfig::default());
        let offline = OfflineFetcher::new();
        let mut response = stripped_response(&qname);
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("offline"), now, &offline)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a never-proven zone must fail closed while offline: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
        let calls = offline.calls();
        assert!(calls > 0, "the probe must have been attempted");
        assert!(
            validator
                .chain_cache()
                .get(&LowerName::from(&qname), now)
                .is_none(),
            "a failed probe must never be persisted"
        );

        // A second query inside the backoff window must not fetch again, but
        // strict mode still fails closed.
        let mut second = stripped_response(&qname);
        let second_outcome = validator
            .validate_with_key_fetcher(&mut second, Some("offline"), now, &offline)
            .await;
        assert!(
            matches!(second_outcome, ValidationOutcome::Bogus { .. }),
            "a backed-off failed probe must still SERVFAIL: {second_outcome:?}"
        );
        assert_eq!(
            offline.calls(),
            calls,
            "a failed probe must be backed off to prevent fetch storms"
        );

        // Cached signed evidence: network failure must stay Bogus.
        let (parent_origin, parent_key, _parent_signer) = create_test_signer("signed.example.");
        let child = Name::from_str("child.signed.example.").expect("child");
        let cache = Arc::new(ChainCache::new(None));
        let signed_validator = d05_validator(Some(cache.clone()));
        cache.insert(LowerName::from(&child), ZoneStatus::Signed, now + 600, now);
        signed_validator.add_trust_anchor(&parent_key, LowerName::from(&parent_origin));
        let offline = OfflineFetcher::new();
        let mut response =
            stripped_response(&Name::from_str("www.child.signed.example.").expect("qname"));
        let outcome = signed_validator
            .validate_with_key_fetcher(&mut response, Some("offline"), now, &offline)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "cached signed evidence must fail closed offline: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(offline.calls() > 0, "the walk must try the network");

        // Cached unsigned evidence: offline stays Insecure with no fetch.
        let unsigned = Name::from_str("unsigned.signed.example.").expect("unsigned");
        let cache = Arc::new(ChainCache::new(None));
        let unsigned_validator = d05_validator(Some(cache.clone()));
        cache.insert(
            LowerName::from(&unsigned),
            ZoneStatus::Unsigned,
            now + 600,
            now,
        );
        let offline = OfflineFetcher::new();
        let mut response =
            stripped_response(&Name::from_str("www.unsigned.signed.example.").expect("qname"));
        let outcome = unsigned_validator
            .validate_with_key_fetcher(&mut response, Some("offline"), now, &offline)
            .await;
        assert_eq!(outcome, ValidationOutcome::Insecure);
        assert_eq!(offline.calls(), 0);
        assert!(!response.metadata.authentic_data);
    }

    /// P1-1 DNAME residual: hickory-proto 0.26.3 does not reject DNAME on the
    /// wire; it decodes it as `RData::Unknown { code: DNAME }`. The validator
    /// cannot interpret/follow it and must fail closed (strict mode Bogus with
    /// SERVFAIL), never assert AD or serve it as validated.
    #[tokio::test]
    async fn test_dname_unknown_rdata_fails_closed() {
        use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
        use sito_proto::rdata::NULL;

        let qname = Name::from_str("alias.example.").expect("qname");
        let target = Name::from_str("target.example.").expect("target");
        let mut target_wire = Vec::new();
        {
            let mut encoder = BinEncoder::new(&mut target_wire);
            target.emit(&mut encoder).expect("encode DNAME target");
        }
        let mut response = Message::new(1, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::DNAME));
        response.answers.push(Record::from_rdata(
            qname.clone(),
            300,
            RData::Unknown {
                code: RecordType::DNAME,
                rdata: NULL::with(target_wire),
            },
        ));

        // Prove the actual wire mechanism: DNAME survives decode as an
        // unsupported/unknown RDATA, it is not a parse error.
        let wire = sito_proto::encode_message(&response).expect("encode response");
        let mut decoded = sito_proto::decode_message(&wire).expect("DNAME must decode");
        assert!(
            matches!(
                decoded.answers.first().map(|record| &record.data),
                Some(RData::Unknown { code, .. }) if *code == RecordType::DNAME
            ),
            "expected DNAME to decode as RData::Unknown"
        );
        assert_eq!(
            decoded.answers[0].record_type(),
            RecordType::DNAME,
            "the unknown RDATA still reports the DNAME record type"
        );

        let validator = DnssecValidator::from_config(&DnssecConfig::default());
        let offline = OfflineFetcher::new();
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut decoded, Some("offline"), now, &offline)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "DNAME without interpretable/authenticated data must fail closed: {outcome:?}"
        );
        assert_eq!(decoded.metadata.response_code, ResponseCode::ServFail);
        assert!(
            !decoded.metadata.authentic_data,
            "a DNAME response must never be served with AD=1"
        );
    }

    /// RFC 4035 3.2.3: AD must not be set when the Answer/Authority sections
    /// contain an RRset that is not covered by a trusted signature.
    #[test]
    fn test_unauthenticated_authority_rrset_clears_ad() {
        let (origin, dnskey, a_record, rrsig_record, signer) =
            create_test_signed_domain("ad.example.");
        let _ = signer;

        let mut trust_anchors = TrustAnchors::empty();
        trust_anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new())
            .with_trust_anchors(trust_anchors);

        let ns = Record::from_rdata(
            origin.clone(),
            300,
            RData::NS(hickory_proto::rr::rdata::NS(
                Name::from_str("ns.ad.example.").expect("ns"),
            )),
        );

        let mut msg = Message::new(6, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(origin.clone(), RecordType::A));
        msg.answers.push(a_record);
        msg.answers.push(rrsig_record);
        msg.authorities.push(ns);
        msg.additionals.push(Record::from_rdata(
            origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("ad-test"), now);
        assert_eq!(
            outcome,
            ValidationOutcome::Insecure,
            "an unsigned authority RRset must clear AD"
        );
        assert!(!msg.metadata.authentic_data);
        assert_ne!(msg.metadata.response_code, ResponseCode::ServFail);
    }

    #[test]
    fn test_expired_ds_rrsig_in_trust_chain_is_bogus() {
        use hickory_proto::dnssec::rdata::DS;
        use hickory_proto::dnssec::{DigestType, rdata::DNSSECRData};
        use hickory_proto::rr::RecordSet;

        let (parent_origin, parent_key, parent_signer) = create_test_signer("example.");
        let (child_origin, child_key, child_signer) = create_test_signer("sub.example.");

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(parent_key.public_key(), LowerName::from(&parent_origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        // Sign DS RRset at `now - 7200` with 3600s duration so its RRSIG is expired at `now`.
        let past_utc = time::OffsetDateTime::now_utc() - time::Duration::seconds(7200);
        let ds =
            DS::from_key(child_key.public_key(), &child_origin, DigestType::SHA256).expect("ds");
        let ds_record = Record::from_rdata(
            child_origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DS(ds)),
        );
        let mut ds_set = RecordSet::new(child_origin.clone(), RecordType::DS, 0);
        ds_set.insert(ds_record.clone(), 0);
        let expired_ds_rrsig =
            RRSIG::from_rrset(&ds_set, DNSClass::IN, past_utc, &parent_signer).expect("sign ds");
        let expired_ds_sig_record = Record::from_rdata(
            child_origin.clone(),
            300,
            RData::DNSSEC(DNSSECRData::RRSIG(expired_ds_rrsig)),
        );

        // Sign child A RRset at `now` (valid).
        let a_record = Record::from_rdata(
            child_origin.clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 55))),
        );
        let mut a_set = RecordSet::new(child_origin.clone(), RecordType::A, 0);
        a_set.insert(a_record.clone(), 0);
        let a_sig = sign_test_rrset(&a_set, &child_signer);

        let mut msg = Message::new(7, MessageType::Response, OpCode::Query);
        msg.queries
            .push(Query::query(child_origin.clone(), RecordType::A));
        msg.answers.push(a_record);
        msg.answers.push(a_sig);
        msg.authorities.push(ds_record);
        msg.authorities.push(expired_ds_sig_record);
        msg.additionals.push(Record::from_rdata(
            parent_origin,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(parent_key)),
        ));
        msg.additionals.push(Record::from_rdata(
            child_origin,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(child_key)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("expired-ds"), now);
        assert_eq!(
            outcome,
            ValidationOutcome::Bogus {
                reason: "Signature expired".to_string(),
                ede_code: EDE_SIGNATURE_EXPIRED,
            }
        );
        assert!(!msg.metadata.authentic_data);
    }

    #[test]
    fn test_signed_cname_to_unsigned_external_zone_without_ds_denial_is_not_insecure() {
        use hickory_proto::rr::RecordSet;
        use hickory_proto::rr::rdata::CNAME;

        let (origin, dnskey, signer) = create_test_signer("signed.example.");
        let alias = Name::from_str("alias.signed.example.").expect("alias");
        let external_target = Name::from_str("www.unsigned.org.").expect("target");

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);

        let cname_record = Record::from_rdata(
            alias.clone(),
            300,
            RData::CNAME(CNAME(external_target.clone())),
        );
        let mut cname_set = RecordSet::new(alias.clone(), RecordType::CNAME, 0);
        cname_set.insert(cname_record.clone(), 0);
        let cname_sig = sign_test_rrset(&cname_set, &signer);

        let unsigned_a = Record::from_rdata(
            external_target,
            300,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 7))),
        );

        let mut msg = Message::new(8, MessageType::Response, OpCode::Query);
        msg.queries.push(Query::query(alias, RecordType::A));
        msg.answers.push(cname_record);
        msg.answers.push(cname_sig);
        msg.answers.push(unsigned_a);
        msg.additionals.push(Record::from_rdata(
            origin,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator.validate_response(&mut msg, Some("cname-unsigned"), now);
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "without an authenticated DS denial the target is not proven unsigned and strict mode must fail closed: {outcome:?}"
        );
        assert!(!msg.metadata.authentic_data);
        assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
    }

    /// Hostile regression: absence of signed-zone evidence for a CNAME target
    /// is not proof that the target is unsigned. An attacker can strip the
    /// target's RRSIG. Only an authenticated DS denial (`insecure_zone_covers`)
    /// may downgrade the chain to Insecure; strict mode must fail closed.
    #[tokio::test]
    async fn test_signed_cname_to_stripped_target_without_ds_denial_is_bogus() {
        use hickory_proto::rr::RecordSet;
        use hickory_proto::rr::rdata::CNAME;

        let (validator, origin, _key, signer) = signed_zone_validator("signed.example.");
        let alias = Name::from_str("alias.signed.example.").expect("alias");
        let target = Name::from_str("www.unsigned.org.").expect("target");

        let cname_record =
            Record::from_rdata(alias.clone(), 300, RData::CNAME(CNAME(target.clone())));
        let mut cname_set = RecordSet::new(alias.clone(), RecordType::CNAME, 0);
        cname_set.insert(cname_record.clone(), 0);
        let cname_sig = sign_test_rrset(&cname_set, &signer);

        let mut response = Message::new(9, MessageType::Response, OpCode::Query);
        response.queries.push(Query::query(alias, RecordType::A));
        response.answers.push(cname_record);
        response.answers.push(cname_sig);
        // The target answer carries no RRSIG: a stripped signature.
        response.answers.push(Record::from_rdata(
            target,
            300,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 8))),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let offline = OfflineFetcher::new();
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("cname-stripped"), now, &offline)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a stripped CNAME target without a DS denial must fail closed: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.answers.len(), 0);
        let _ = origin;
    }

    /// The fail-closed CNAME rule must not over-block a target whose unsigned
    /// delegation is proven by an authenticated DS denial.
    #[tokio::test]
    async fn test_signed_cname_to_authenticated_unsigned_target_is_insecure() {
        use hickory_proto::rr::RecordSet;
        use hickory_proto::rr::rdata::CNAME;

        let (validator, origin, zone_key, signer) = signed_zone_validator("signed.example.");
        let cut = Name::from_str("unsigned.signed.example.").expect("cut");
        let alias = Name::from_str("alias.signed.example.").expect("alias");
        let target = Name::from_str("www.unsigned.signed.example.").expect("target");

        let ds_message = signed_nsec_response(
            &origin,
            &cut,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            &cut,
            &zone_key,
            &signer,
            ResponseCode::NoError,
        );
        let fetcher = StaticFetcher::new().with(&cut, RecordType::DS, ds_message);

        let cname_record =
            Record::from_rdata(alias.clone(), 300, RData::CNAME(CNAME(target.clone())));
        let mut cname_set = RecordSet::new(alias.clone(), RecordType::CNAME, 0);
        cname_set.insert(cname_record.clone(), 0);
        let cname_sig = sign_test_rrset(&cname_set, &signer);

        let mut response = Message::new(9, MessageType::Response, OpCode::Query);
        response.queries.push(Query::query(alias, RecordType::A));
        response.answers.push(cname_record);
        response.answers.push(cname_sig);
        response.answers.push(Record::from_rdata(
            target,
            300,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 9))),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("cname-unsigned"), now, &fetcher)
            .await;
        assert_eq!(
            outcome,
            ValidationOutcome::Insecure,
            "an authenticated DS denial must still downgrade the target: {outcome:?}"
        );
        assert!(!response.metadata.authentic_data);
    }

    /// Hostile regression: one unrelated junk RRSIG must not suppress the
    /// unsigned-delegation probe. Before the fix it made the response
    /// Indeterminate (AD=0) without ever asking whether the name is a
    /// legitimately unsigned delegation.
    #[tokio::test]
    async fn test_junk_rrsig_does_not_suppress_unsigned_probe() {
        use hickory_proto::rr::RecordSet;

        let (zone, zone_key, zone_signer) = create_test_signer("signed.example.");
        let cut = Name::from_str("unsigned.signed.example.").expect("cut");
        let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");

        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        validator.add_trust_anchor(&zone_key, LowerName::from(&zone));

        let ds_message = signed_nsec_response(
            &zone,
            &cut,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            &cut,
            &zone_key,
            &zone_signer,
            ResponseCode::NoError,
        );
        let fetcher = StaticFetcher::new()
            .with(
                &zone,
                RecordType::DNSKEY,
                anchored_dnskey_message(&zone, &zone_key, &zone_signer),
            )
            .with(&cut, RecordType::DS, ds_message);

        // A validly signed RRSIG for an RRset that is not in the response and
        // not relevant to the question: pure junk from the validator's point
        // of view.
        let unrelated = Name::from_str("junk.signed.example.").expect("junk");
        let mut set = RecordSet::new(unrelated.clone(), RecordType::A, 0);
        set.insert(
            Record::from_rdata(unrelated, 300, RData::A(A(Ipv4Addr::new(203, 0, 113, 99)))),
            0,
        );
        let junk_sig = sign_test_rrset(&set, &zone_signer);

        let mut response = Message::new(10, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        response.answers.push(Record::from_rdata(
            qname,
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
        ));
        response.answers.push(junk_sig);

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("probe"), now, &fetcher)
            .await;
        assert_eq!(
            outcome,
            ValidationOutcome::Insecure,
            "the probe must run and prove the delegation unsigned"
        );
        assert!(!response.metadata.authentic_data);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(
            fetcher.calls() > 0,
            "junk RRSIGs must not suppress the delegation probe"
        );
    }

    /// Strict post-fetch `Indeterminate` is not an acceptable answer for a
    /// validating client: no usable key means SERVFAIL, not AD=0. `LogOnly`
    /// keeps the response for diagnostics.
    #[tokio::test]
    async fn test_post_fetch_indeterminate_fails_closed_except_log_only() {
        let (origin, _dnskey, signer) = create_test_signer("unlinked.example.");
        let (answer, answer_sig) = signed_a_response(&origin, &signer);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        let build = || {
            let mut response = Message::new(11, MessageType::Response, OpCode::Query);
            response
                .queries
                .push(Query::query(origin.clone(), RecordType::A));
            response.answers.push(answer.clone());
            response.answers.push(answer_sig.clone());
            response
        };

        let strict = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        let offline = OfflineFetcher::new();
        let mut response = build();
        let outcome = strict
            .validate_with_key_fetcher(&mut response, Some("strict"), now, &offline)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "post-fetch Indeterminate must SERVFAIL in validate mode: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
        assert_eq!(response.answers.len(), 0);
        assert_eq!(
            strict.metrics.bogus_total.load(Ordering::Relaxed),
            1,
            "the strict post-fetch Indeterminate conversion must record Bogus once"
        );
        assert_eq!(
            strict.metrics.indeterminate_total.load(Ordering::Relaxed),
            0,
            "the provisional inner Indeterminate must not be double-recorded"
        );

        let log_only = DnssecValidator::new(DnssecMode::LogOnly, Vec::new());
        let offline = OfflineFetcher::new();
        let mut response = build();
        let outcome = log_only
            .validate_with_key_fetcher(&mut response, Some("log-only"), now, &offline)
            .await;
        assert_eq!(outcome, ValidationOutcome::Indeterminate);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(!response.metadata.authentic_data);
        assert!(!response.answers.is_empty(), "log-only keeps the answer");
        assert_eq!(
            log_only.metrics.indeterminate_total.load(Ordering::Relaxed),
            1,
            "log-only must record its final Indeterminate exactly once"
        );
        assert_eq!(
            log_only.metrics.bogus_total.load(Ordering::Relaxed),
            0,
            "log-only must not record Bogus"
        );
    }

    /// Critical regression: an unsigned CNAME from an unsigned qname into a
    /// target in a known-signed zone must not reach the "junk signature"
    /// Insecure shortcut. The unrelated RRSIG only makes `rrsigs` non-empty;
    /// it must not hide the stripped signed-target answer.
    #[tokio::test]
    async fn test_unsigned_cname_to_signed_target_with_junk_rrsig_is_bogus() {
        use hickory_proto::rr::RecordSet;

        let (validator, signed_origin, _key, signer) = signed_zone_validator("signed.example.");
        let qname = Name::from_str("start.unsigned.example.").expect("qname");
        let target = Name::from_str("www.signed.example.").expect("target");

        let mut response = stripped_cname_response(&qname, &target);
        let unrelated = Name::from_str("junk.signed.example.").expect("junk");
        let mut set = RecordSet::new(unrelated.clone(), RecordType::A, 0);
        set.insert(
            Record::from_rdata(unrelated, 300, RData::A(A(Ipv4Addr::new(203, 0, 113, 98)))),
            0,
        );
        response.answers.push(sign_test_rrset(&set, &signer));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        assert!(
            validator.signed_zone_contains(&LowerName::from(&signed_origin), now),
            "the target zone must be seeded as signed"
        );
        let offline = OfflineFetcher::new();
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("junk-cname"), now, &offline)
            .await;

        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a stripped signed CNAME target must not become Insecure: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
    }

    /// A forged RRSIG that covers the answer owner/type has no usable key. It
    /// must not suppress the unsigned-delegation probe (DoS/fail-closed), so
    /// the authenticated DS denial can still prove the zone unsigned.
    #[tokio::test]
    async fn test_forged_covering_rrsig_still_probes_unsigned_delegation() {
        use hickory_proto::rr::RecordSet;

        let (zone, zone_key, zone_signer) = create_test_signer("signed.example.");
        let cut = Name::from_str("unsigned.signed.example.").expect("cut");
        let qname = Name::from_str("www.unsigned.signed.example.").expect("qname");

        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        validator.add_trust_anchor(&zone_key, LowerName::from(&zone));
        let ds_message = signed_nsec_response(
            &zone,
            &cut,
            &Name::from_str("z.signed.example.").expect("next"),
            &[RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            &cut,
            &zone_key,
            &zone_signer,
            ResponseCode::NoError,
        );
        let fetcher = StaticFetcher::new()
            .with(
                &zone,
                RecordType::DNSKEY,
                anchored_dnskey_message(&zone, &zone_key, &zone_signer),
            )
            .with(&cut, RecordType::DS, ds_message);

        let answer = Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 98))),
        );
        // A cryptographically valid RRSIG from a completely unrelated signer:
        // it covers the answer owner/type but the key is not validated. Also
        // include the matching DNSKEY in the response: an attacker-supplied
        // key must not make the forged signature look verifiable.
        let (attacker_origin, attacker_key, attacker) =
            create_test_signer("unsigned.signed.example.");
        let mut set = RecordSet::new(qname.clone(), RecordType::A, 0);
        set.insert(answer.clone(), 0);
        let forged_sig = sign_test_rrset(&set, &attacker);

        let mut response = Message::new(13, MessageType::Response, OpCode::Query);
        response.queries.push(Query::query(qname, RecordType::A));
        response.answers.push(answer);
        response.answers.push(forged_sig);
        response.additionals.push(Record::from_rdata(
            attacker_origin,
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(attacker_key)),
        ));

        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("forged-cover"), now, &fetcher)
            .await;
        assert_eq!(
            outcome,
            ValidationOutcome::Insecure,
            "a forged covering RRSIG must not suppress the probe: {outcome:?}"
        );
        assert!(!response.metadata.authentic_data);
        assert!(
            fetcher.calls() > 0,
            "the probe must have been attempted despite the signature"
        );
    }

    /// CNAME chain response whose CNAME and target A RRset both carry covering
    /// RRSIGs from `signer`, with no DNSKEY in the response.
    fn covering_fake_cname_response(
        qname: &Name,
        target: &Name,
        signer: &hickory_proto::dnssec::DnssecSigner,
    ) -> Message {
        use hickory_proto::rr::RecordSet;
        use hickory_proto::rr::rdata::CNAME;

        let cname = Record::from_rdata(qname.clone(), 300, RData::CNAME(CNAME(target.clone())));
        let mut cname_set = RecordSet::new(qname.clone(), RecordType::CNAME, 0);
        cname_set.insert(cname.clone(), 0);
        let cname_sig = sign_test_rrset(&cname_set, signer);

        let answer = Record::from_rdata(
            target.clone(),
            300,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 77))),
        );
        let mut answer_set = RecordSet::new(target.clone(), RecordType::A, 0);
        answer_set.insert(answer.clone(), 0);
        let answer_sig = sign_test_rrset(&answer_set, signer);

        let mut response = Message::new(15, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        response.answers.push(cname);
        response.answers.push(cname_sig);
        response.answers.push(answer);
        response.answers.push(answer_sig);
        response
    }

    /// Critical 1: a target proven signed only in the shared chain cache must
    /// not be re-admitted to `Insecure` by the qname's authenticated unsigned
    /// delegation when covering (fake) RRSIGs are present.
    #[tokio::test]
    async fn test_chain_cache_only_signed_target_with_covering_fake_rrsigs_is_bogus() {
        let (_, _, fake_signer) = create_test_signer("signed.example.");
        let qname = Name::from_str("start.unsigned.example.").expect("qname");
        let target = Name::from_str("www.signed.example.").expect("target");
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        validator.insecure_zones.insert(
            LowerName::from(&Name::from_str("unsigned.example.").unwrap()),
            now + 600,
        );
        validator.chain_cache().insert(
            LowerName::from(&Name::from_str("signed.example.").unwrap()),
            ZoneStatus::Signed,
            now + 600,
            now,
        );
        assert!(
            validator.signed_zones.is_empty(),
            "the target must be signed only in the chain cache"
        );
        assert!(
            validator.signed_zone_contains(&LowerName::from(&target), now),
            "signed-chain evidence must consult the shared chain cache"
        );

        let mut response = covering_fake_cname_response(&qname, &target, &fake_signer);
        let offline = OfflineFetcher::new();
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("cache-signed"), now, &offline)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a chain-cache-signed target must fail closed: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
    }

    /// Critical 1 companion: a fully stripped CNAME chain into a target that
    /// is proven signed only in the shared chain cache must be Bogus, not
    /// Insecure from the unsigned qname.
    #[tokio::test]
    async fn test_stripped_cname_to_chain_cache_signed_target_is_bogus() {
        let qname = Name::from_str("plain.unsigned.example.").expect("qname");
        let target = Name::from_str("www.signed.example.").expect("target");
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        validator.insecure_zones.insert(
            LowerName::from(&Name::from_str("unsigned.example.").unwrap()),
            now + 600,
        );
        validator.chain_cache().insert(
            LowerName::from(&Name::from_str("signed.example.").unwrap()),
            ZoneStatus::Signed,
            now + 600,
            now,
        );
        assert!(validator.signed_zones.is_empty());

        let mut response = stripped_cname_response(&qname, &target);
        let offline = OfflineFetcher::new();
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("stripped-cache-signed"), now, &offline)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a chain-cache-signed stripped target must fail closed: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    }

    /// Critical 2: the post-fetch probe must fail closed when the target probe
    /// is blocked, even though the qname is a proven unsigned delegation.
    #[tokio::test]
    async fn test_blocked_target_probe_after_fake_covering_rrsigs_is_bogus() {
        let (_, _, fake_signer) = create_test_signer("signed.example.");
        let qname = Name::from_str("start.unsigned.example.").expect("qname");
        let target = Name::from_str("www.signed.example.").expect("target");
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u32;

        let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new());
        validator.insecure_zones.insert(
            LowerName::from(&Name::from_str("unsigned.example.").unwrap()),
            now + 600,
        );

        let mut response = covering_fake_cname_response(&qname, &target, &fake_signer);
        let offline = OfflineFetcher::new();
        let outcome = validator
            .validate_with_key_fetcher(&mut response, Some("blocked-target"), now, &offline)
            .await;
        assert!(
            matches!(outcome, ValidationOutcome::Bogus { .. }),
            "a failed target probe must not become Insecure: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
        assert!(
            offline.calls() > 0,
            "the blocked target probe must have been attempted"
        );
    }

    /// A signed wildcard-expanded answer may carry the RRSIG at the wildcard
    /// owner (`*.wild.example`) while the RRset is owned by the expanded qname.
    /// Both response shapes must validate as Secure without forcing a probe.
    #[tokio::test]
    async fn test_signed_wildcard_answer_with_wildcard_owned_rrsig_is_secure() {
        use hickory_proto::dnssec::rdata::{RRSIG, SigInput};
        use hickory_proto::dnssec::{Algorithm, TBS};
        use hickory_proto::rr::SerialNumber;

        let (origin, dnskey, signer) = create_test_signer("wild.example.");
        let wildcard = Name::from_str("*.wild.example.").expect("wildcard");
        let now_utc = time::OffsetDateTime::now_utc();
        let now = now_utc.unix_timestamp() as u32;

        for (qname, expect_probe) in [
            (
                Name::from_str("www.wild.example.").expect("single-label qname"),
                false,
            ),
            (
                Name::from_str("foo.bar.wild.example.").expect("multi-label qname"),
                false,
            ),
        ] {
            let answer = Record::from_rdata(
                qname.clone(),
                300,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 97))),
            );
            let input = SigInput {
                type_covered: RecordType::A,
                algorithm: Algorithm::ECDSAP256SHA256,
                // Wildcard RRSIG labels exclude the `*` label.
                num_labels: origin.num_labels(),
                original_ttl: 300,
                sig_expiration: SerialNumber::new(
                    now_utc
                        .unix_timestamp()
                        .saturating_add(300)
                        .try_into()
                        .expect("expiration"),
                ),
                sig_inception: SerialNumber::new(
                    now_utc
                        .unix_timestamp()
                        .saturating_sub(60)
                        .try_into()
                        .expect("inception"),
                ),
                key_tag: signer.calculate_key_tag().expect("key tag"),
                signer_name: origin.clone(),
            };
            let tbs = TBS::from_input(&qname, DNSClass::IN, &input, std::iter::once(&answer))
                .expect("wildcard tbs");
            let signature = signer.sign(&tbs).expect("wildcard signature");
            let rrsig_data = RRSIG::from_sig(input, signature);

            for rrsig_owner in [wildcard.clone(), qname.clone()] {
                let mut anchors = TrustAnchors::empty();
                anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
                let validator = DnssecValidator::new(DnssecMode::Validate, Vec::new())
                    .with_trust_anchors(anchors);

                let mut response = Message::new(14, MessageType::Response, OpCode::Query);
                response
                    .queries
                    .push(Query::query(qname.clone(), RecordType::A));
                response.answers.push(answer.clone());
                response.answers.push(Record::from_rdata(
                    rrsig_owner,
                    300,
                    RData::DNSSEC(DNSSECRData::RRSIG(rrsig_data.clone())),
                ));
                response.additionals.push(Record::from_rdata(
                    origin.clone(),
                    300,
                    RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
                ));

                let offline = OfflineFetcher::new();
                let outcome = validator
                    .validate_with_key_fetcher(&mut response, Some("wildcard"), now, &offline)
                    .await;
                assert_eq!(
                    outcome,
                    ValidationOutcome::Secure,
                    "a signed wildcard answer must validate for {qname}: {outcome:?}"
                );
                assert!(response.metadata.authentic_data);
                assert_eq!(
                    offline.calls() > 0,
                    expect_probe,
                    "a signed wildcard answer must not probe for {qname}"
                );
            }
        }
    }

    #[test]
    fn test_qtype_cname_positive_answer_is_not_negative() {
        use hickory_proto::rr::rdata::CNAME;

        let qname = Name::from_str("alias.example.").expect("qname");
        let target = Name::from_str("target.example.").expect("target");
        let mut response = Message::new(12, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::CNAME));
        response.answers.push(Record::from_rdata(
            qname.clone(),
            300,
            RData::CNAME(CNAME(target.clone())),
        ));
        response.metadata.response_code = ResponseCode::NoError;

        assert!(
            !is_negative_response(&response, &qname, RecordType::CNAME),
            "a CNAME at the qname answers QTYPE=CNAME positively"
        );
        assert!(
            is_negative_response(&response, &qname, RecordType::A),
            "the same response is NODATA for QTYPE=A"
        );
    }
}
