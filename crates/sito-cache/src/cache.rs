//! In-memory DNS cache implementation using moka with weighted byte sizing.

use arc_swap::ArcSwap;
use moka::future::Cache;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;
use tracing::{debug, trace, warn};

use sito_core::config::CacheConfig;
use sito_proto::rdata::SOA;
use sito_proto::{
    DNSClass, Message, MessageType, Name, RData, RecordType, ResponseCode, encode_message,
};

use crate::entry::CacheEntry;
use crate::key::CacheKey;

/// TTL (seconds) clamped onto records served from stale cache per RFC 8767 §5.
const STALE_SERVE_TTL: u32 = 30;

/// Builds a moka cache with the given capacity in megabytes.
fn build_cache(size_mb: u64) -> Cache<CacheKey, Arc<CacheEntry>> {
    Cache::builder()
        .weigher(|_key: &CacheKey, value: &Arc<CacheEntry>| -> u32 { value.estimated_bytes })
        .max_capacity(size_mb.saturating_mul(1024 * 1024))
        .build()
}

/// RAII guard for a per-key single-flight slot.
///
/// Held across the upstream resolution and the cache insert so only one
/// concurrent query per key populates the entry; dropping it releases the slot.
#[must_use = "the single-flight slot is released when the guard is dropped"]
pub struct SingleFlightGuard {
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

/// High-performance concurrent DNS response cache.
///
/// The moka cache instance itself sits behind an `ArcSwap` so `size_mb` can be
/// hot-reloaded: a resize rebuilds the cache and carries over entries that
/// still fit the new capacity. During the swap both generations briefly
/// coexist, so peak memory is old + new size.
///
/// Eviction semantics:
/// * moka evicts by weighted size (approximately; eviction is asynchronous).
/// * [`DnsCache::resize`] carries over only entries that have not passed their
///   stale window; entries inserted into the old generation while a resize is
///   in progress are not carried over.
/// * [`DnsCache::flush`] invalidates the generation that is current at call
///   time. Do not call it concurrently with a resize: entries an in-progress
///   resize already copied can survive the flush.
pub struct DnsCache {
    cache: ArcSwap<Cache<CacheKey, Arc<CacheEntry>>>,
    config: ArcSwap<CacheConfig>,
    /// Per-key single-flight locks. Weak references let finished keys be
    /// replaced lazily; waiters keep their strong reference alive.
    flights: Arc<Mutex<HashMap<CacheKey, Weak<tokio::sync::Mutex<()>>>>>,
}

impl DnsCache {
    /// Create a new DnsCache from configuration.
    pub fn new(config: CacheConfig) -> Self {
        let cache = build_cache(config.size_mb as u64);

        Self {
            cache: ArcSwap::from_pointee(cache),
            config: ArcSwap::new(Arc::new(config)),
            flights: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Applies hot-reloaded cache settings, rebuilding the cache when
    /// `size_mb` changes.
    pub async fn update_config(&self, config: CacheConfig) {
        if self.config.load().size_mb != config.size_mb {
            self.resize(config.size_mb as u64).await;
        }
        self.config.store(Arc::new(config));
    }

    /// Rebuilds the underlying cache with a new capacity in megabytes,
    /// carrying over live entries on a best-effort basis.
    ///
    /// Entries are copied oldest-first in moka iteration order until the new
    /// capacity is exhausted; entries that have already passed their stale
    /// window are dropped instead of being copied. Entries inserted into the
    /// old generation after iteration starts are not carried over. Peak memory
    /// during the rebuild is old + new capacity.
    pub async fn resize(&self, size_mb: u64) {
        let capacity_bytes = size_mb.saturating_mul(1024 * 1024);
        let stale_window_secs = self.config.load().serve_stale_hours.saturating_mul(3600);
        let old = self.cache.load_full();
        let new_cache = build_cache(size_mb);

        let mut carried = 0u64;
        let mut carried_bytes = 0u64;
        let mut skipped_expired = 0u64;
        for (key, entry) in old.iter() {
            let elapsed_secs = entry.stored_at.elapsed().as_secs();
            let fully_expired =
                u64::from(entry.max_lifespan_secs).saturating_add(u64::from(stale_window_secs));
            if elapsed_secs >= fully_expired {
                skipped_expired += 1;
                continue;
            }

            let weight = u64::from(entry.estimated_bytes.max(1));
            if carried > 0 && carried_bytes.saturating_add(weight) > capacity_bytes {
                break;
            }
            new_cache.insert((*key).clone(), entry).await;
            carried += 1;
            carried_bytes = carried_bytes.saturating_add(weight);
        }
        new_cache.run_pending_tasks().await;
        self.cache.store(Arc::new(new_cache));
        debug!(
            "Cache resized to {} MiB (carried over {carried} entries, ~{carried_bytes} bytes, \
             dropped {skipped_expired} fully expired entries)",
            size_mb
        );
    }

    /// Acquires the single-flight slot for `key`.
    ///
    /// Concurrent callers with the same key wait until the first caller drops
    /// the returned guard. To be effective, callers should re-check the cache
    /// after acquiring (the slot holder may already have populated it).
    pub async fn single_flight(&self, key: CacheKey) -> SingleFlightGuard {
        let lock = {
            let mut flights = self
                .flights
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if flights.len() > 1024 {
                flights.retain(|_, weak| weak.strong_count() > 0);
            }
            if let Some(existing) = flights.get(&key).and_then(Weak::upgrade) {
                existing
            } else {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                flights.insert(key, Arc::downgrade(&lock));
                lock
            }
        };
        SingleFlightGuard {
            _guard: lock.lock_owned().await,
        }
    }

    /// Acquires the single-flight slot for the query's cache key.
    pub async fn single_flight_for_query(&self, query: &Message) -> Option<SingleFlightGuard> {
        let key = CacheKey::from_query(query)?;
        Some(self.single_flight(key).await)
    }

    /// Retrieve a response for the given query from cache, adjusting TTLs according to elapsed time.
    pub async fn get(&self, name: &Name, qtype: RecordType, qclass: DNSClass) -> Option<Message> {
        self.get_by_key(&CacheKey::new(name, qtype, qclass)).await
    }

    /// Retrieve a response for `query`, honouring its DO/CD/ECS cache key.
    pub async fn get_for_query(&self, query: &Message) -> Option<Message> {
        self.get_by_key(&CacheKey::from_query(query)?).await
    }

    async fn get_by_key(&self, key: &CacheKey) -> Option<Message> {
        let config = self.config.load();
        if !config.enabled {
            return None;
        }

        let cache = self.cache.load_full();
        let entry = cache.get(key).await?;

        let elapsed_secs = entry.stored_at.elapsed().as_secs() as u32;
        let max_stale_secs = entry
            .max_lifespan_secs
            .saturating_add(config.serve_stale_hours.saturating_mul(3600));

        if elapsed_secs >= max_stale_secs {
            trace!(
                "Cache entry for {} completely expired (elapsed: {}s, max_stale: {}s)",
                key.qname, elapsed_secs, max_stale_secs
            );
            cache.invalidate(key).await;
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
    ///
    /// DNSSEC material is removed before serving: a stale entry is not
    /// revalidated, so it must never claim `AD` and must not carry RRSIGs that
    /// would let a client treat it as authentic.
    /// TTLs are clamped to 30 seconds as recommended by RFC 8767 section 5.
    pub async fn get_stale(
        &self,
        name: &Name,
        qtype: RecordType,
        qclass: DNSClass,
    ) -> Option<Message> {
        self.get_stale_by_key(&CacheKey::new(name, qtype, qclass))
            .await
    }

    /// Retrieve a stale response for `query`, honouring its DO/CD/ECS cache key.
    pub async fn get_stale_for_query(&self, query: &Message) -> Option<Message> {
        self.get_stale_by_key(&CacheKey::from_query(query)?).await
    }

    async fn get_stale_by_key(&self, key: &CacheKey) -> Option<Message> {
        let config = self.config.load();
        if !config.enabled || config.serve_stale_hours == 0 {
            return None;
        }

        let cache = self.cache.load_full();
        let entry = cache.get(key).await?;

        let elapsed_secs = entry.stored_at.elapsed().as_secs() as u32;
        let max_stale_secs = entry
            .max_lifespan_secs
            .saturating_add(config.serve_stale_hours.saturating_mul(3600));

        if elapsed_secs >= max_stale_secs {
            cache.invalidate(key).await;
            return None;
        }

        entry.hits.fetch_add(1, Ordering::Relaxed);
        let mut response = entry.message.clone();

        // Never serve stale data as authenticated (RFC 8767 §5.1 / RFC 6840).
        clear_dnssec_material(&mut response);

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
        self.should_prefetch_by_key(&CacheKey::new(name, qtype, qclass))
            .await
    }

    /// Prefetch check for `query`, honouring its DO/CD/ECS cache key.
    pub async fn should_prefetch_for_query(&self, query: &Message) -> bool {
        match CacheKey::from_query(query) {
            Some(key) => self.should_prefetch_by_key(&key).await,
            None => false,
        }
    }

    async fn should_prefetch_by_key(&self, key: &CacheKey) -> bool {
        let config = self.config.load();
        if !config.enabled || !config.prefetch {
            return false;
        }

        let cache = self.cache.load_full();
        if let Some(entry) = cache.get(key).await {
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
    ///
    /// Only well-formed positive or negative answers are cached:
    /// * the response must be a response message whose question section is
    ///   present and matches the query,
    /// * truncated (TC=1) responses and RCODEs other than NoError/NXDOMAIN are
    ///   never cached,
    /// * NoError responses without an RRset of the queried type are treated as
    ///   NODATA and require an SOA in the authority section (RFC 2308);
    ///   negative answers without an SOA are not cached.
    pub async fn insert(&self, query: &Message, response: &Message) {
        let Some(key) = CacheKey::from_query(query) else {
            return;
        };

        let config = self.config.load();
        if !config.enabled {
            return;
        }

        let Some(first_query) = query.queries.first() else {
            return;
        };

        if response.metadata.message_type != MessageType::Response {
            return;
        }
        if response.metadata.truncation {
            trace!("Not caching truncated response for {}", key.qname);
            return;
        }

        let rcode = response.metadata.response_code;
        if rcode != ResponseCode::NoError && rcode != ResponseCode::NXDomain {
            trace!(
                "Not caching {} response for {} (only NoError/NXDomain are cacheable)",
                rcode, key.qname
            );
            return;
        }

        // A response whose question does not match the query must never be
        // stored, or a mismatched/spoofed upstream reply could be served for
        // the query name later. A response without a question section cannot
        // be verified and is rejected as well (upstream transports already
        // enforce this via `validate_response`).
        let Some(response_question) = response.queries.first() else {
            trace!(
                "Not caching response without a question section for {}",
                key.qname
            );
            return;
        };
        let matches = response_question.name() == first_query.name()
            && response_question.query_type() == first_query.query_type()
            && response_question.query_class() == first_query.query_class();
        if !matches {
            warn!(
                qname = %key.qname,
                "Refusing to cache response with a mismatched question section"
            );
            return;
        }

        // Bailiwick: every answer record must belong to the query name or a
        // CNAME chain reachable from it. Otherwise a spoofed upstream could
        // inject an unrelated RRset under this cache key.
        if !answer_owners_are_relevant(first_query.name(), response) {
            warn!(
                qname = %key.qname,
                "Refusing to cache response with out-of-bailiwick answer owners"
            );
            return;
        }

        // NODATA detection (RFC 2308): a NoError answer without an RRset of
        // the queried type is negative, including CNAME-only chains that never
        // reach the requested type.
        let query_type = first_query.query_type();
        let has_answer_for_query_type = (query_type == RecordType::ANY
            && !response.answers.is_empty())
            || response
                .answers
                .iter()
                .any(|record| record.record_type() == query_type);
        let is_nxdomain = rcode == ResponseCode::NXDomain;
        let is_nodata = rcode == ResponseCode::NoError && !has_answer_for_query_type;
        let is_negative = is_nxdomain || is_nodata;

        let mut answer_ttls = Vec::new();
        let mut authority_ttls = Vec::new();
        let mut additional_ttls = Vec::new();

        let max_lifespan_secs = if is_negative {
            // RFC 2308 requires a SOA record to derive the negative TTL.
            // Without one the answer is not cacheable.
            let Some(soa_ttl) = negative_ttl_from_soa(&response.authorities) else {
                trace!(
                    "Not caching negative response for {} without a SOA record",
                    key.qname
                );
                return;
            };
            let clamped_ttl =
                soa_ttl.clamp(config.min_ttl, config.negative_ttl_max.max(config.min_ttl));
            for auth in &response.authorities {
                authority_ttls.push(auth.ttl.min(clamped_ttl));
            }
            clamped_ttl
        } else {
            let mut min_record_ttl = u32::MAX;
            let effective_max_ttl = config.max_ttl.max(config.min_ttl);

            for ans in &response.answers {
                let clamped = ans.ttl.clamp(config.min_ttl, effective_max_ttl);
                answer_ttls.push(clamped);
                min_record_ttl = min_record_ttl.min(clamped);
            }

            for auth in &response.authorities {
                let clamped = auth.ttl.clamp(config.min_ttl, effective_max_ttl);
                authority_ttls.push(clamped);
                min_record_ttl = min_record_ttl.min(clamped);
            }

            for add in &response.additionals {
                let clamped = add.ttl.clamp(config.min_ttl, effective_max_ttl);
                additional_ttls.push(clamped);
                min_record_ttl = min_record_ttl.min(clamped);
            }

            if min_record_ttl == u32::MAX {
                config.min_ttl
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
            estimated_bytes,
        };

        trace!(
            "Caching response for {} with lifespan {}s (weight: {}B)",
            key.qname, max_lifespan_secs, estimated_bytes
        );
        self.cache.load_full().insert(key, Arc::new(entry)).await;
    }

    /// Invalidate all entries in the current cache generation.
    ///
    /// Entries copied into a generation created by a concurrent [`DnsCache::resize`]
    /// are not affected; see the type-level eviction notes.
    pub fn flush(&self) {
        self.cache.load().invalidate_all();
    }

    /// Invalidate entries matching the specified domain (the name itself and
    /// all strict subdomains).
    ///
    /// This is an O(n) scan of the live cache because moka has no secondary
    /// index; the suffix string is precomputed so the scan performs no
    /// per-entry formatting.
    pub fn invalidate_domain(&self, domain: &str) {
        let normalized =
            sito_proto::normalize_domain(domain).unwrap_or_else(|_| domain.to_ascii_lowercase());
        let subdomain_suffix = format!(".{normalized}");
        let cache = self.cache.load();
        let _ = cache.invalidate_entries_if(move |k, _v| {
            k.qname == normalized || k.qname.ends_with(&subdomain_suffix)
        });
    }

    /// Approximate memory weight of cached items in bytes.
    pub fn weighted_size(&self) -> u64 {
        self.cache.load().weighted_size()
    }
}

/// Removes DNSSEC records and the AD flag from a response.
fn clear_dnssec_material(response: &mut Message) {
    response.metadata.authentic_data = false;
    response
        .answers
        .retain(|record| record.record_type() != RecordType::RRSIG);
    response
        .authorities
        .retain(|record| record.record_type() != RecordType::RRSIG);
    response
        .additionals
        .retain(|record| record.record_type() != RecordType::RRSIG);
}

/// Returns true when every answer record's owner is the query name or a CNAME
/// target reachable from it (bounded walk, cycles stop the walk).
fn answer_owners_are_relevant(qname: &Name, response: &Message) -> bool {
    let mut relevant: Vec<Name> = Vec::new();
    let mut current = qname.clone();
    for _ in 0..16 {
        if relevant.contains(&current) {
            break;
        }
        relevant.push(current.clone());
        let next = response.answers.iter().find_map(|record| {
            if record.record_type() == RecordType::CNAME && record.name == current {
                match &record.data {
                    RData::CNAME(cname) => Some(cname.0.clone()),
                    _ => None,
                }
            } else {
                None
            }
        });
        match next {
            Some(target) => current = target,
            None => break,
        }
    }
    response
        .answers
        .iter()
        .all(|record| relevant.contains(&record.name))
}

/// Derives the RFC 2308 negative TTL from the SOA record in `authorities`
/// (`min(SOA TTL, SOA MINIMUM)`), or `None` when no SOA is present.
fn negative_ttl_from_soa(authorities: &[sito_proto::Record]) -> Option<u32> {
    for auth in authorities {
        if let RData::SOA(SOA { minimum, .. }) = &auth.data {
            return Some(auth.ttl.min(*minimum));
        }
    }
    None
}
