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
        let max_stale_secs = entry
            .max_lifespan_secs
            .saturating_add(self.config.serve_stale_hours * 3600);

        if elapsed_secs >= max_stale_secs {
            trace!(
                "Cache entry for {} completely expired (elapsed: {}s, max_stale: {}s)",
                key.qname, elapsed_secs, max_stale_secs
            );
            self.cache.invalidate(&key).await;
            return None;
        }

        if elapsed_secs >= entry.max_lifespan_secs {
            trace!(
                "Cache entry for {} expired for normal queries (elapsed: {}s, lifespan: {}s)",
                key.qname, elapsed_secs, entry.max_lifespan_secs
            );
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

    /// Retrieve a stale cached response according to RFC 8767 when upstreams fail.
    /// TTLs are clamped to 30 seconds as recommended by RFC 8767 section 5.
    pub async fn get_stale(
        &self,
        name: &Name,
        qtype: RecordType,
        qclass: DNSClass,
    ) -> Option<Message> {
        const STALE_SERVE_TTL: u32 = 30;

        if !self.config.enabled || self.config.serve_stale_hours == 0 {
            return None;
        }

        let key = CacheKey::new(name, qtype, qclass);
        let entry = self.cache.get(&key).await?;

        let elapsed_secs = entry.stored_at.elapsed().as_secs() as u32;
        let max_stale_secs = entry
            .max_lifespan_secs
            .saturating_add(self.config.serve_stale_hours * 3600);

        if elapsed_secs >= max_stale_secs {
            self.cache.invalidate(&key).await;
            return None;
        }

        entry.hits.fetch_add(1, Ordering::Relaxed);
        let mut response = entry.message.clone();

        for record in &mut response.answers {
            record.ttl = STALE_SERVE_TTL;
        }
        for record in &mut response.authorities {
            record.ttl = STALE_SERVE_TTL;
        }
        for record in &mut response.additionals {
            record.ttl = STALE_SERVE_TTL;
        }

        debug!(
            "Cache serving stale entry for {} (elapsed: {}s, original lifespan: {}s)",
            key.qname, elapsed_secs, entry.max_lifespan_secs
        );
        Some(response)
    }

    /// Check whether a cached entry is eligible for background prefetch
    /// (prefetch enabled, hits >= 2, and remaining TTL <= 10% of lifespan or <= 10 seconds).
    pub async fn should_prefetch(&self, name: &Name, qtype: RecordType, qclass: DNSClass) -> bool {
        if !self.config.enabled || !self.config.prefetch {
            return false;
        }

        let key = CacheKey::new(name, qtype, qclass);
        if let Some(entry) = self.cache.get(&key).await {
            let elapsed_secs = entry.stored_at.elapsed().as_secs() as u32;
            if elapsed_secs < entry.max_lifespan_secs {
                let remaining = entry.max_lifespan_secs - elapsed_secs;
                let hits = entry.hits.load(Ordering::Relaxed);
                return hits >= 2 && (remaining <= 10 || remaining <= entry.max_lifespan_secs / 10);
            }
        }
        false
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
            let clamped_ttl = raw_negative_ttl.clamp(
                self.config.min_ttl,
                self.config.negative_ttl_max.max(self.config.min_ttl),
            );
            for auth in &response.authorities {
                authority_ttls.push(auth.ttl.min(clamped_ttl));
            }
            clamped_ttl
        } else {
            let mut min_record_ttl = u32::MAX;
            let effective_max_ttl = self.config.max_ttl.max(self.config.min_ttl);

            for ans in &response.answers {
                let clamped = ans.ttl.clamp(self.config.min_ttl, effective_max_ttl);
                answer_ttls.push(clamped);
                min_record_ttl = min_record_ttl.min(clamped);
            }

            for auth in &response.authorities {
                let clamped = auth.ttl.clamp(self.config.min_ttl, effective_max_ttl);
                authority_ttls.push(clamped);
                min_record_ttl = min_record_ttl.min(clamped);
            }

            for add in &response.additionals {
                let clamped = add.ttl.clamp(self.config.min_ttl, effective_max_ttl);
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

    /// Invalidate entries matching the specified domain.
    pub fn invalidate_domain(&self, domain: &str) {
        let normalized =
            sito_proto::normalize_domain(domain).unwrap_or_else(|_| domain.to_ascii_lowercase());
        let norm_clone = normalized.clone();
        let _ = self.cache.invalidate_entries_if(move |k, _v| {
            k.qname == norm_clone || k.qname.ends_with(&format!(".{norm_clone}"))
        });
    }

    /// Approximate memory weight of cached items in bytes.
    pub fn weighted_size(&self) -> u64 {
        self.cache.weighted_size()
    }

    /// Number of active cache entries.
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }
}
