//! In-memory DNS cache implementation using moka with weighted byte sizing.

use moka::future::Cache;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;
use tracing::{debug, trace};

use sito_core::config::CacheConfig;
use sito_proto::rdata::SOA;
use sito_proto::{DNSClass, Message, Name, RData, RecordType, ResponseCode, encode_message};

use crate::entry::CacheEntry;
use crate::key::CacheKey;

/// High-performance concurrent DNS response cache.
pub struct DnsCache {
    cache: Cache<CacheKey, CacheEntry>,
    config: CacheConfig,
}

impl DnsCache {
    /// Create a new DnsCache from configuration.
    pub fn new(config: CacheConfig) -> Self {
        let max_capacity_bytes = (config.size_mb as u64) * 1024 * 1024;

        let cache = Cache::builder()
            .weigher(|_key: &CacheKey, value: &CacheEntry| -> u32 { value.estimated_bytes })
            .max_capacity(max_capacity_bytes)
            .build();

        Self { cache, config }
    }

    /// Retrieve a response for the given query from cache, adjusting TTLs according to elapsed time.
    pub async fn get(&self, name: &Name, qtype: RecordType, qclass: DNSClass) -> Option<Message> {
        if !self.config.enabled {
            return None;
        }

        let key = CacheKey::new(name, qtype, qclass);
        let entry = self.cache.get(&key).await?;

        let elapsed_secs = entry.stored_at.elapsed().as_secs() as u32;
        if elapsed_secs >= entry.max_lifespan_secs {
            trace!(
                "Cache entry for {} expired (elapsed: {}s, lifespan: {}s)",
                key.qname, elapsed_secs, entry.max_lifespan_secs
            );
            self.cache.invalidate(&key).await;
            return None;
        }

        entry.hits.fetch_add(1, Ordering::Relaxed);
        let mut response = entry.message.clone();

        // Decrement TTLs for answer records
        for (i, record) in response.answers.iter_mut().enumerate() {
            if let Some(&original_ttl) = entry.answer_ttls.get(i) {
                record.ttl = original_ttl.saturating_sub(elapsed_secs);
            }
        }

        // Decrement TTLs for authority records
        for (i, record) in response.authorities.iter_mut().enumerate() {
            if let Some(&original_ttl) = entry.authority_ttls.get(i) {
                record.ttl = original_ttl.saturating_sub(elapsed_secs);
            }
        }

        // Decrement TTLs for additional records
        for (i, record) in response.additionals.iter_mut().enumerate() {
            if let Some(&original_ttl) = entry.additional_ttls.get(i) {
                record.ttl = original_ttl.saturating_sub(elapsed_secs);
            }
        }

        debug!(
            "Cache hit for {} (remaining min TTL: {}s)",
            key.qname,
            entry.max_lifespan_secs.saturating_sub(elapsed_secs)
        );
        Some(response)
    }

    /// Insert a response into the cache, calculating clamped TTLs and entry weight.
    pub async fn insert(&self, query: &Message, response: &Message) {
        if !self.config.enabled {
            return;
        }

        let Some(first_query) = query.queries.first() else {
            return;
        };

        let key = CacheKey::new(
            first_query.name(),
            first_query.query_type(),
            first_query.query_class(),
        );

        let is_nxdomain = response.metadata.response_code == ResponseCode::NXDomain;
        let is_nodata =
            response.metadata.response_code == ResponseCode::NoError && response.answers.is_empty();
        let is_negative = is_nxdomain || is_nodata;

        let mut answer_ttls = Vec::new();
        let mut authority_ttls = Vec::new();
        let mut additional_ttls = Vec::new();

        let max_lifespan_secs = if is_negative {
            // Find SOA record in authority section
            let mut soa_ttl = None;
            for auth in &response.authorities {
                if let RData::SOA(SOA { minimum, .. }) = &auth.data {
                    let effective = auth.ttl.min(*minimum);
                    soa_ttl = Some(effective);
                    break;
                }
            }

            let raw_negative_ttl = soa_ttl.unwrap_or(300);
            raw_negative_ttl.clamp(self.config.min_ttl, self.config.negative_ttl_max)
        } else {
            let mut min_record_ttl = u32::MAX;

            for ans in &response.answers {
                let clamped = ans.ttl.clamp(self.config.min_ttl, self.config.max_ttl);
                answer_ttls.push(clamped);
                min_record_ttl = min_record_ttl.min(clamped);
            }

            for auth in &response.authorities {
                let clamped = auth.ttl.clamp(self.config.min_ttl, self.config.max_ttl);
                authority_ttls.push(clamped);
                min_record_ttl = min_record_ttl.min(clamped);
            }

            for add in &response.additionals {
                let clamped = add.ttl.clamp(self.config.min_ttl, self.config.max_ttl);
                additional_ttls.push(clamped);
                min_record_ttl = min_record_ttl.min(clamped);
            }

            if min_record_ttl == u32::MAX {
                self.config.min_ttl
            } else {
                min_record_ttl
            }
        };

        let serialized_len = encode_message(response).map_or(256, |b| b.len());
        let estimated_bytes = (serialized_len + key.qname.len() + 128) as u32;

        let entry = CacheEntry {
            message: response.clone(),
            stored_at: Instant::now(),
            max_lifespan_secs,
            answer_ttls,
            authority_ttls,
            additional_ttls,
            hits: Arc::new(AtomicU32::new(0)),
            is_negative,
            estimated_bytes,
        };

        trace!(
            "Caching response for {} with lifespan {}s (weight: {}B)",
            key.qname, max_lifespan_secs, estimated_bytes
        );
        self.cache.insert(key, entry).await;
    }

    /// Invalidate all entries in the cache.
    pub fn flush(&self) {
        self.cache.invalidate_all();
    }
}
