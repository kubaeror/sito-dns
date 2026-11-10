//! Cache entry representing stored DNS responses.

use sito_proto::Message;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Instant;

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
