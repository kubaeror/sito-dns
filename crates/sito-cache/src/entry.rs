//! Cache entry representing stored DNS responses.

use sito_proto::Message;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Instant;

/// A cached DNS response with tracked original TTLs and metrics.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub message: Message,
    pub stored_at: Instant,
    pub max_lifespan_secs: u32,
    pub answer_ttls: Vec<u32>,
    pub authority_ttls: Vec<u32>,
    pub additional_ttls: Vec<u32>,
    pub hits: Arc<AtomicU32>,
    pub is_negative: bool,
    pub estimated_bytes: u32,
}
