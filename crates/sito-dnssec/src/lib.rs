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
