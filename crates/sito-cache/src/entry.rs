//! Cache entry representing stored DNS responses.

use sito_proto::Message;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Instant;

/// Monotonic generation that tags cached validation decisions.
///
/// The same value is the cache's DNSSEC policy epoch and the runtime's
/// `RuntimeGeneration`: there is exactly one counter, owned here, so a query
/// cannot pair a cache epoch with a different runtime generation. Every
/// successful runtime apply advances it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyEpoch(u64);

impl PolicyEpoch {
    /// The generation a fresh process starts at.
    pub const INITIAL: Self = Self(1);

    /// Wraps a raw counter value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The underlying counter value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The next generation.
    ///
    /// A counter overflow is not representable in practice (2^64 applies);
    /// saturating keeps the value monotonic instead of wrapping back to a
    /// generation that still has live entries.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl Default for PolicyEpoch {
    fn default() -> Self {
        Self::INITIAL
    }
}

impl std::fmt::Display for PolicyEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// DNSSEC validation state recorded when a response was cached.
///
/// The status lets the pipeline decide whether a cached entry may be served
/// when validation is active: `Insecure`/`Indeterminate` are legitimate
/// answers for unsigned or inconclusive data (served with AD=0), while
/// `Unchecked` means no local validation ran at all and must never be served
/// to a client that relies on the resolver's validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValidationStatus {
    /// Signature chain validated to a trust anchor (AD may be set).
    Secure,
    /// Authenticated proof that the data is unsigned (AD=0).
    Insecure,
    /// Validation was inconclusive (AD=0).
    Indeterminate,
    /// No local validation was performed (CD=1 or validation disabled).
    #[default]
    Unchecked,
}

impl ValidationStatus {
    /// Whether the entry carries an authenticated answer.
    #[must_use]
    pub fn is_secure(self) -> bool {
        matches!(self, Self::Secure)
    }
}

/// A cached DNS response with tracked original TTLs and metrics.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub message: Message,
    pub stored_at: Instant,
    pub max_lifespan_secs: u32,
    pub answer_ttls: Vec<u32>,
    pub authority_ttls: Vec<u32>,
    pub additional_ttls: Vec<u32>,
    pub validation_status: ValidationStatus,
    /// DNSSEC policy generation under which this entry's
    /// `validation_status` was produced. An entry whose generation no longer
    /// matches the cache's current generation must not be served or inserted:
    /// a hot reload can swap the validator while a query is in flight.
    pub policy_epoch: u64,
    pub hits: Arc<AtomicU32>,
    pub estimated_bytes: u32,
}
