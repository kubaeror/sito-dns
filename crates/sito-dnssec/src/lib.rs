//! DNSSEC validation: trust anchors, chain walking, denial, and verification.
//!
//! The facade preserves the historical crate-root API. Validation policy lives
//! in `types`/`keys`; chain state in `anchor`/`chain`; proof evaluation in
//! `denial`; signature verification in `verify`; keys in `cache`.

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
use std::time::{Duration, Instant};

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

/// Default wall-clock budget for one DNSSEC key-fetch pass.
///
/// Used by [`DnssecValidator::validate_with_key_fetcher`], which exists for
/// callers that do not have their own per-query deadline. The resolver
/// pipeline passes its own absolute deadline instead.
///
/// This is deliberately the same 5s as `DNSSEC_VALIDATION_DEADLINE` in
/// `crates/sito/src/pipeline/query.rs`; keep the two in sync so the
/// compatibility wrapper and the resolver pipeline enforce the same bound.
pub const DEFAULT_KEY_FETCH_DEADLINE: Duration = Duration::from_secs(5);

/// Per-query budget for DNSSEC DS/DNSKEY fetches.
///
/// One budget covers every DS/DNSKEY lookup made for a client response/query,
/// not one chain walk: the early CNAME/delegation probes, every cold-start
/// signer walk and the post-fetch probes all draw from it. `remaining` bounds
/// the total count and `deadline` is the absolute wall-clock bound shared by
/// every fetch. Once either limit is reached, [`Self::try_take`] refuses
/// further fetches so validation stops instead of issuing more network I/O.
/// A signer walk that runs after early probes therefore sees a shorter budget
/// than the full allowance.
#[derive(Debug)]
pub struct FetchBudget {
    remaining: u8,
    deadline: Instant,
    /// Optional validation metrics that receive a counter for every refusal.
    metrics: Option<Arc<DnssecMetrics>>,
}

impl FetchBudget {
    /// Creates a budget with `remaining` fetches allowed until `deadline`.
    pub fn new(remaining: u8, deadline: Instant) -> Self {
        Self {
            remaining,
            deadline,
            metrics: None,
        }
    }

    /// Creates a budget that records every refusal in `metrics`.
    ///
    /// Production validation uses this so an exhausted count budget and an
    /// expired deadline are visible and distinguishable in telemetry.
    pub fn with_metrics(remaining: u8, deadline: Instant, metrics: Arc<DnssecMetrics>) -> Self {
        Self {
            remaining,
            deadline,
            metrics: Some(metrics),
        }
    }

    /// The absolute deadline every fetch must respect.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Consumes one fetch slot, returning false when the budget is exhausted
    /// or the deadline has passed. Callers must stop fetching on false.
    ///
    /// A refusal is attributed to exactly one cause: the absolute deadline
    /// takes precedence over count exhaustion because it invalidates the
    /// fetch regardless of how much count budget is left.
    ///
    /// This counts budget decisions only, not fetcher results. An upstream
    /// `UpstreamError::Timeout` is a fetcher outcome, not a refusal, and is
    /// covered by the separate upstream/bogus error metrics instead.
    pub fn try_take(&mut self) -> bool {
        if self.is_expired() {
            if let Some(metrics) = &self.metrics {
                metrics.record_fetch_deadline_exceeded();
            }
            return false;
        }
        if self.remaining == 0 {
            if let Some(metrics) = &self.metrics {
                metrics.record_fetch_budget_exhausted();
            }
            return false;
        }
        self.remaining -= 1;
        true
    }

    /// Records a refusal at an early `is_expired()` guard, before
    /// [`Self::try_take`] is reached.
    ///
    /// Walk and probe entry points check the deadline up front so a caller
    /// contract violation (or a deadline that expired between stages) cannot
    /// start new work. That refusal is the same deadline cause as a
    /// `try_take` refusal and must be visible in the same metric. Counts
    /// nothing when no metrics are attached.
    pub(crate) fn record_deadline_refusal(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_fetch_deadline_exceeded();
        }
    }

    /// Whether the absolute deadline has passed.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
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
/// Largest cold-start DNSKEY/DS allowance the old per-signer design gave one
/// RRSIG signer (`labels * 2 + 1`, capped at 31). A single signer's walk can
/// never exceed this before reaching the root or its depth bound.
const MAX_SIGNER_CHAIN_FETCHES: u8 = 31;
/// Hard cap on DS/DNSKEY fetches one client query may issue across the early
/// CNAME probes, the cold-start signer walks and the post-fetch probes.
///
/// The total is `MAX_SIGNER_CHAIN_FETCHES + 2 * MAX_CNAME_PROBES` (31 + 16),
/// where the second term is the worst-case probe share: one anchor DNSKEY plus
/// one DS lookup per probe. It is a single hard cap, not a reservation split:
/// deep probes draw from the signer share too, so 47 does not guarantee that a
/// cold-start signer walk still has 31 fetches left after a deep probe fan-out;
/// it only guarantees the query never exceeds 47. All callers draw from the
/// same [`FetchBudget`], so a probe fan-out shortens the walk that follows
/// instead of multiplying the query's fetch work.
const MAX_FETCHES_PER_QUERY: u8 = MAX_SIGNER_CHAIN_FETCHES + 2 * MAX_CNAME_PROBES as u8;
/// Accepted clock skew around RRSIG inception/expiration (RFC 4035 5.3.1).
const MAX_CLOCK_SKEW: u32 = 300;
/// Minimum accepted RSA modulus size in bits (RFC 8624 3.1).
const MIN_RSA_BITS: usize = 2048;

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

mod anchor;
mod cache;
mod chain;
mod denial;
mod keys;
mod types;
mod validation;
mod verify;

pub use cache::*;
pub use types::*;

#[allow(clippy::wildcard_imports)]
use anchor::*;
#[allow(clippy::wildcard_imports)]
use chain::*;
#[allow(clippy::wildcard_imports)]
use denial::*;
#[allow(clippy::wildcard_imports)]
use keys::*;
#[allow(clippy::wildcard_imports)]
use verify::*;

pub mod test_util;

#[cfg(test)]
mod tests;
