//! In-memory DNS cache implementation using moka with weighted byte sizing.

use arc_swap::ArcSwap;
use moka::future::Cache;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;
use tracing::{debug, trace, warn};

use sito_core::config::CacheConfig;
use sito_proto::rdata::SOA;
use sito_proto::{
    DNSClass, Message, MessageType, Name, RData, Record, RecordType, ResponseCode, encode_message,
};

use crate::entry::{CacheEntry, PolicyEpoch, ValidationStatus};
use crate::key::CacheKey;

/// TTL (seconds) clamped onto records served from stale cache per RFC 8767 §5.
const STALE_SERVE_TTL: u32 = 30;

/// Builds a moka cache with the given capacity in megabytes.
fn build_cache(size_mb: u64) -> Cache<CacheKey, Arc<CacheEntry>> {
    Cache::builder()
        .weigher(|_key: &CacheKey, value: &Arc<CacheEntry>| -> u32 { value.estimated_bytes })
        .max_capacity(size_mb.saturating_mul(1024 * 1024))
        // `invalidate_domain` removes entries with a predicate. Moka refuses
        // `invalidate_entries_if` at runtime unless this is enabled at build
        // time; without it a domain invalidation silently does nothing.
        .support_invalidation_closures()
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
    /// Monotonic DNSSEC policy generation. Entries carry the generation that
    /// produced their validation status; a hot reload advances this value so
    /// old-policy entries become invisible and in-flight inserts from a query
    /// that started under the old policy are rejected.
    policy_epoch: AtomicU64,
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
            // Start at 1 so an entry always carries a meaningful generation.
            policy_epoch: AtomicU64::new(PolicyEpoch::INITIAL.get()),
            flights: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Current DNSSEC policy generation.
    ///
    /// A query must **not** read this live: it captures
    /// `RuntimeSnapshot::generation` together with the validator, and passes
    /// that value to [`Self::insert_with_status_at_epoch`]. A config apply
    /// advances this counter with the validator swap, so the two can never come
    /// from different generations.
    #[must_use]
    pub fn policy_epoch(&self) -> PolicyEpoch {
        PolicyEpoch::new(self.policy_epoch.load(Ordering::Acquire))
    }

    /// Advances the DNSSEC policy generation and returns the new value.
    ///
    /// The runtime calls this once per successful config apply, immediately
    /// before publishing the snapshot that carries the prepared validator. A
    /// query therefore sees the old validator with the old epoch, or the new
    /// validator with the new epoch. Existing entries are filtered by `get`
    /// immediately; the flush only reclaims their memory. Filter-only
    /// refreshes do not call it.
    pub fn advance_policy_epoch(&self) -> PolicyEpoch {
        // Applies are serialized by the runtime write lock; a concurrent
        // reader still observes either the old or the new generation.
        PolicyEpoch::new(
            self.policy_epoch
                .fetch_add(1, Ordering::AcqRel)
                .saturating_add(1),
        )
    }

    /// Applies hot-reloaded cache settings, rebuilding the cache when
    /// `size_mb` changes and re-clamping every live entry to the new TTL
    /// policy.
    ///
    /// The re-clamp is immediate and does not wait for entries to expire:
    /// a lowered `max_ttl`/`negative_ttl_max` caps what is served, and a
    /// raised `min_ttl` raises unvalidated entries to the new floor. Secure
    /// entries keep the `floor = 0` rule so a reload can never extend an
    /// authenticated TTL past its signed lifetime. Entries past their old
    /// lifespan are left to the stale path; a raised `min_ttl` must not
    /// resurrect them as fresh.
    pub async fn update_config(&self, config: CacheConfig) {
        let size_changed = self.config.load().size_mb != config.size_mb;
        // Publish the policy before the resize so the resize uses the new
        // stale window, then re-clamp against the same configuration.
        self.config.store(Arc::new(config.clone()));
        if size_changed {
            self.resize(config.size_mb as u64).await;
        }
        self.reclamp_entries(&config).await;
    }

    /// Rewrites every still-fresh entry so its TTLs obey `config`.
    async fn reclamp_entries(&self, config: &CacheConfig) {
        let cache = self.cache.load_full();
        let stale_window_secs = config.serve_stale_hours.saturating_mul(3600);
        let mut replacements = Vec::new();
        let mut expired = Vec::new();

        for (key, entry) in cache.iter() {
            let elapsed_secs = entry.stored_at.elapsed().as_secs() as u32;
            let fully_expired =
                u64::from(entry.max_lifespan_secs).saturating_add(u64::from(stale_window_secs));
            if u64::from(elapsed_secs) >= fully_expired {
                expired.push((*key).clone());
                continue;
            }
            // Only entries still fresh under the policy they were stored with
            // are eligible. Re-clamping a stale entry with a raised min_ttl
            // would make data whose original lifespan passed fresh again.
            if elapsed_secs >= entry.max_lifespan_secs {
                continue;
            }
            let reclamped = reclamp_entry(&entry, config);
            if reclamped.max_lifespan_secs <= elapsed_secs {
                expired.push((*key).clone());
            } else {
                replacements.push(((*key).clone(), Arc::new(reclamped)));
            }
        }

        let replaced = replacements.len();
        for key in expired {
            cache.invalidate(&key).await;
        }
        for (key, entry) in replacements {
            cache.insert(key, entry).await;
        }
        cache.run_pending_tasks().await;
        debug!(
            "Re-clamped {replaced} cache entries after a cache policy reload (min_ttl={}s, \
             max_ttl={}s, negative_ttl_max={}s, serve_stale_hours={})",
            config.min_ttl, config.max_ttl, config.negative_ttl_max, config.serve_stale_hours
        );
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
            let mut flights = sito_core::sync::lock_or_recover(&self.flights);
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
        let key = CacheKey::for_query(query)?;
        Some(self.single_flight(key).await)
    }

    /// Retrieve a response for the given query from cache, adjusting TTLs according to elapsed time.
    pub async fn get(&self, name: &Name, qtype: RecordType, qclass: DNSClass) -> Option<Message> {
        self.get_by_key(&CacheKey::new(name, qtype, qclass))
            .await
            .map(|(message, _)| message)
    }

    /// Retrieve a response for `query`, honouring its DO/CD/ECS cache key.
    pub async fn get_for_query(&self, query: &Message) -> Option<Message> {
        self.get_for_query_with_status(query)
            .await
            .map(|(message, _)| message)
    }

    /// Retrieve a response and its recorded DNSSEC validation status.
    ///
    /// The pipeline uses the status to decide whether the entry may be served
    /// when validation is active (see [`ValidationStatus`]).
    pub async fn get_for_query_with_status(
        &self,
        query: &Message,
    ) -> Option<(Message, ValidationStatus)> {
        self.get_by_key_with_status(&CacheKey::for_query(query)?)
            .await
            .map(|(message, status, _)| (message, status))
    }

    /// Retrieve a response with its validation status and the DNSSEC policy
    /// generation that produced it.
    ///
    /// This is the epoch-aware form intended for tests and callers that need
    /// to observe the generation. A production query should not normally need
    /// it: `get_for_query_with_status` already refuses entries from an older
    /// generation.
    pub async fn get_for_query_with_status_and_epoch(
        &self,
        query: &Message,
    ) -> Option<(Message, ValidationStatus, u64)> {
        self.get_by_key_with_status(&CacheKey::for_query(query)?)
            .await
    }

    async fn get_by_key(&self, key: &CacheKey) -> Option<(Message, ValidationStatus)> {
        self.get_by_key_with_status(key)
            .await
            .map(|(message, status, _)| (message, status))
    }

    async fn get_by_key_with_status(
        &self,
        key: &CacheKey,
    ) -> Option<(Message, ValidationStatus, u64)> {
        let config = self.config.load();
        if !config.enabled {
            return None;
        }

        let cache = self.cache.load_full();
        let entry = cache.get(key).await?;

        // A policy change makes every entry from an older generation
        // unservable immediately, even before the flush reclaims it.
        if entry.policy_epoch != self.policy_epoch().get() {
            trace!(
                "Ignoring cache entry for {} from DNSSEC policy epoch {} (current {})",
                key.qname,
                entry.policy_epoch,
                self.policy_epoch()
            );
            cache.invalidate(key).await;
            return None;
        }

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
        Some((response, entry.validation_status, entry.policy_epoch))
    }

    /// Retrieve a stale cached response according to RFC 8767 when upstreams fail.
    ///
    /// DNSSEC material is removed before serving: a stale entry is not
    /// revalidated, so it must never claim `AD` and must not carry RRSIGs,
    /// DNSKEYs or denial records that would let a client treat it as
    /// authentic.
    /// TTLs are clamped to 30 seconds as recommended by RFC 8767 section 5.
    pub async fn get_stale(
        &self,
        name: &Name,
        qtype: RecordType,
        qclass: DNSClass,
    ) -> Option<Message> {
        self.get_stale_by_key(&CacheKey::new(name, qtype, qclass))
            .await
            .map(|(message, _, _)| message)
    }

    /// Retrieve a stale response for `query`, honouring its DO/CD/ECS cache key.
    pub async fn get_stale_for_query(&self, query: &Message) -> Option<Message> {
        self.get_stale_for_query_with_status(query)
            .await
            .map(|(message, _)| message)
    }

    /// Retrieve a stale response together with the validation status recorded
    /// when it was cached.
    ///
    /// The pipeline uses the status to apply the same
    /// [`ValidationStatus::Unchecked`] gate as fresh cache hits: stale data is
    /// not revalidated, so an entry cached without local validation must not
    /// be served while validation is active.
    pub async fn get_stale_for_query_with_status(
        &self,
        query: &Message,
    ) -> Option<(Message, ValidationStatus)> {
        self.get_stale_by_key(&CacheKey::for_query(query)?)
            .await
            .map(|(message, status, _)| (message, status))
    }

    async fn get_stale_by_key(&self, key: &CacheKey) -> Option<(Message, ValidationStatus, u64)> {
        let config = self.config.load();
        if !config.enabled || config.serve_stale_hours == 0 {
            return None;
        }

        let cache = self.cache.load_full();
        let entry = cache.get(key).await?;

        if entry.policy_epoch != self.policy_epoch().get() {
            trace!(
                "Ignoring stale cache entry for {} from DNSSEC policy epoch {} (current {})",
                key.qname,
                entry.policy_epoch,
                self.policy_epoch()
            );
            cache.invalidate(key).await;
            return None;
        }

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
        Some((response, entry.validation_status, entry.policy_epoch))
    }

    /// Check whether a cached entry is eligible for background prefetch
    /// (prefetch enabled, hits >= 2, and remaining TTL <= 10% of lifespan or <= 10 seconds).
    pub async fn should_prefetch(&self, name: &Name, qtype: RecordType, qclass: DNSClass) -> bool {
        self.should_prefetch_by_key(&CacheKey::new(name, qtype, qclass))
            .await
    }

    /// Prefetch check for `query`, honouring its DO/CD/ECS cache key.
    pub async fn should_prefetch_for_query(&self, query: &Message) -> bool {
        match CacheKey::for_query(query) {
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
    /// The entry is always stored as [`ValidationStatus::Unchecked`]: an AD bit
    /// supplied by an upstream is not proof that this resolver validated the
    /// data. Callers that did validate must use [`Self::insert_with_status`] or
    /// [`Self::insert_with_status_at_epoch`].
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
        self.insert_with_status(query, response, ValidationStatus::Unchecked)
            .await;
    }

    /// Insert a response together with its DNSSEC validation status.
    ///
    /// The extra parameter lets the pipeline distinguish a validated insecure
    /// answer from one that was never validated, which the plain [`insert`]
    /// convenience method cannot express.
    pub async fn insert_with_status(
        &self,
        query: &Message,
        response: &Message,
        validation_status: ValidationStatus,
    ) {
        self.insert_with_status_at_epoch(query, response, validation_status, self.policy_epoch())
            .await;
    }

    /// Insert a response only when `policy_epoch` is still current.
    ///
    /// Returns `true` when the entry was stored and `false` when a DNSSEC
    /// policy change made the caller's validation decision stale. Pass
    /// `RuntimeSnapshot::generation` from the same snapshot that supplied the
    /// validator; never read `policy_epoch()` live in a query.
    pub async fn insert_with_status_at_epoch(
        &self,
        query: &Message,
        response: &Message,
        validation_status: ValidationStatus,
        policy_epoch: PolicyEpoch,
    ) -> bool {
        let Some(key) = CacheKey::for_query(query) else {
            return false;
        };

        let config = self.config.load();
        if !config.enabled {
            return false;
        }

        let Some(first_query) = query.queries.first() else {
            return false;
        };

        if response.metadata.message_type != MessageType::Response {
            return false;
        }
        if response.metadata.truncation {
            trace!("Not caching truncated response for {}", key.qname);
            return false;
        }

        let rcode = response.metadata.response_code;
        if rcode != ResponseCode::NoError && rcode != ResponseCode::NXDomain {
            trace!(
                "Not caching {} response for {} (only NoError/NXDomain are cacheable)",
                rcode, key.qname
            );
            return false;
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
            return false;
        };
        let matches = response_question.name() == first_query.name()
            && response_question.query_type() == first_query.query_type()
            && response_question.query_class() == first_query.query_class();
        if !matches {
            warn!(
                qname = %key.qname,
                "Refusing to cache response with a mismatched question section"
            );
            return false;
        }

        // Bailiwick: every answer record must belong to the query name or a
        // CNAME chain reachable from it. Otherwise a spoofed upstream could
        // inject an unrelated RRset under this cache key.
        if !answer_owners_are_relevant(first_query.name(), response) {
            warn!(
                qname = %key.qname,
                "Refusing to cache response with out-of-bailiwick answer owners"
            );
            return false;
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

        // `min_ttl` is a floor for *unvalidated* data. Raising a Secure entry
        // would let an AD=1 answer outlive the TTL/RRSIG validity that
        // authenticated it (RFC 4035 §5.3.3).
        let ttl_floor = if validation_status.is_secure() {
            0
        } else {
            config.min_ttl
        };

        let max_lifespan_secs = if is_negative {
            // RFC 2308 requires a SOA record owned by an ancestor of the query
            // name (or of a CNAME target on the chain) to derive the negative
            // TTL. A SOA for an unrelated zone is out of bailiwick and must not
            // be trusted for this name.
            let (chain_names, cname_chain_ttl) = cname_chain(first_query.name(), response);
            let Some(soa_ttl) = negative_ttl_from_soa(&response.authorities, &chain_names) else {
                trace!(
                    "Not caching negative response for {} without a bailiwick SOA record",
                    key.qname
                );
                return false;
            };
            let clamped_ttl = soa_ttl.clamp(ttl_floor, config.negative_ttl_max.max(config.min_ttl));
            // RFC 2308: the negative answer must never outlive the CNAME chain
            // that led to it. Otherwise the cached NODATA/NXDOMAIN would keep
            // being served after the alias TTL expired.
            //
            // A Secure negative answer is proven by its NSEC/NSEC3 denial
            // records (and their RRSIGs), whose TTLs the validator has already
            // capped by the authenticated TTL/signature expiry. The SOA can be
            // signed with a longer lifetime, so the entry must not outlive the
            // denial proof.
            //
            // When the proof is still present (DO=1 responses) apply the same
            // cap here as defense in depth. DO=0 responses are stripped of
            // DNSSEC records before caching; for those, the validator already
            // capped the SOA TTL in `apply_authenticated_ttls`, so no proof
            // here means nothing further to cap (not a zero lifespan).
            let denial_ttl = if validation_status.is_secure() {
                denial_proof_ttl(response)
            } else {
                None
            };
            let max_lifespan = clamped_ttl
                .min(cname_chain_ttl.unwrap_or(u32::MAX))
                .min(denial_ttl.unwrap_or(u32::MAX));

            for answer in &response.answers {
                answer_ttls.push(answer.ttl.min(max_lifespan));
            }
            for auth in &response.authorities {
                authority_ttls.push(auth.ttl.min(max_lifespan));
            }
            for additional in &response.additionals {
                additional_ttls.push(additional.ttl.min(max_lifespan));
            }
            max_lifespan
        } else {
            let mut min_record_ttl = u32::MAX;
            let effective_max_ttl = config.max_ttl.max(config.min_ttl);

            for ans in &response.answers {
                let clamped = ans.ttl.clamp(ttl_floor, effective_max_ttl);
                answer_ttls.push(clamped);
                min_record_ttl = min_record_ttl.min(clamped);
            }

            for auth in &response.authorities {
                let clamped = auth.ttl.clamp(ttl_floor, effective_max_ttl);
                authority_ttls.push(clamped);
                min_record_ttl = min_record_ttl.min(clamped);
            }

            for add in &response.additionals {
                let clamped = add.ttl.clamp(ttl_floor, effective_max_ttl);
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

        // Re-check immediately before the insert. The caller captured the
        // epoch before loading its validator; if a reload advanced the policy
        // while this response was validated/fetched, its status belongs to a
        // policy that no longer exists and must not become visible.
        if policy_epoch != self.policy_epoch() {
            debug!(
                qname = %key.qname,
                policy_epoch = %policy_epoch,
                current = %self.policy_epoch(),
                "Discarding cache insert from an older DNSSEC policy generation"
            );
            return false;
        }

        let entry = CacheEntry {
            message: response.clone(),
            stored_at: Instant::now(),
            max_lifespan_secs,
            answer_ttls,
            authority_ttls,
            additional_ttls,
            validation_status,
            policy_epoch: policy_epoch.get(),
            hits: Arc::new(AtomicU32::new(0)),
            estimated_bytes,
        };

        trace!(
            "Caching response for {} with lifespan {}s (weight: {}B)",
            key.qname, max_lifespan_secs, estimated_bytes
        );
        self.cache.load_full().insert(key, Arc::new(entry)).await;
        true
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
    /// index. The predicate uses the shared suffix matcher, so the scan
    /// performs no per-entry formatting.
    pub fn invalidate_domain(&self, domain: &str) {
        let trimmed = domain.trim();
        // The root name is an ancestor of every cached name, so invalidating
        // it is equivalent to flushing the cache. `normalize_domain(".")`
        // rejects the root, which used to leave root entries unaffected.
        if trimmed.is_empty() || trimmed.trim_end_matches('.').is_empty() {
            self.flush();
            return;
        }
        // The API passes `Name::to_string()` (UTS46-decoded Unicode), while
        // cache keys are `Name::to_ascii()` punycode. Normalize with IDNA so
        // `invalidate_domain("münchen.de")` evicts `xn--mnchen-3ya.de`.
        let normalized = sito_proto::normalize_domain_or_idna(trimmed)
            .unwrap_or_else(|_| trimmed.trim_end_matches('.').to_ascii_lowercase());
        let match_name = normalized.clone();
        let cache = self.cache.load();
        if let Err(error) = cache.invalidate_entries_if(move |k, _v| {
            k.qname == match_name || sito_core::matches_domain_suffix(&k.qname, &match_name)
        }) {
            // This should be unreachable because `build_cache` enables
            // invalidation closures. Flush instead of silently claiming the
            // domain was invalidated while stale entries remain.
            warn!(
                domain = %normalized,
                %error,
                "Cache invalidation predicate failed; flushing the whole cache"
            );
            cache.invalidate_all();
        }
    }

    /// Approximate memory weight of cached items in bytes.
    pub fn weighted_size(&self) -> u64 {
        self.cache.load().weighted_size()
    }

    /// Moves an existing entry's `stored_at` into the past (test only).
    ///
    /// TTL re-clamp tests need to observe an aged entry without sleeping. The
    /// production clock is still `Instant::now()`; only `stored_at` is rewound.
    #[cfg(test)]
    pub(crate) async fn backdate_entry_for_test(&self, query: &Message, age: std::time::Duration) {
        let Some(key) = CacheKey::for_query(query) else {
            return;
        };
        let cache = self.cache.load_full();
        let Some(entry) = cache.get(&key).await else {
            return;
        };
        let Some(stored_at) = Instant::now().checked_sub(age) else {
            return;
        };
        let mut backdated = (*entry).clone();
        backdated.stored_at = stored_at;
        cache.insert(key, Arc::new(backdated)).await;
    }
}

/// Returns `entry` with its TTL vectors and lifespan re-clamped to `config`.
///
/// The cache does not retain the original unclamped TTL, so a re-clamp can
/// tighten a lowered ceiling (`max_ttl`/`negative_ttl_max`) and raise an
/// unvalidated entry to a new `min_ttl` floor, but never un-clamp a raised
/// ceiling. That is intentional: a policy reload must not extend old data as
/// if it had just been fetched.
///
/// Secure entries keep the `floor = 0` rule used by [`DnsCache::insert_with_status`]:
/// `min_ttl` must not extend an authenticated TTL beyond its signed lifetime.
fn reclamp_entry(entry: &CacheEntry, config: &CacheConfig) -> CacheEntry {
    let mut reclamped = entry.clone();
    let floor = if entry.validation_status.is_secure() {
        0
    } else {
        config.min_ttl
    };
    let negative = entry_is_negative(entry);
    let ceiling = if negative {
        config.negative_ttl_max.max(config.min_ttl)
    } else {
        config.max_ttl.max(config.min_ttl)
    };

    if negative {
        // RFC 2308: the negative lifespan is derived from the SOA (and, for
        // Secure answers, the denial proof or CNAME chain). The entry stores
        // that post-cap lifespan, not the original SOA TTL, so a reload may
        // only lower it. Raising it to a new `min_ttl` would outlive the
        // negative proof. Record TTLs are still raised to the new floor while
        // the entry is served.
        let lifespan = entry.max_lifespan_secs.min(ceiling);
        let record_ceiling = lifespan.max(floor);
        for (ttls, records) in [
            (&mut reclamped.answer_ttls, &entry.answer_ttls),
            (&mut reclamped.authority_ttls, &entry.authority_ttls),
            (&mut reclamped.additional_ttls, &entry.additional_ttls),
        ] {
            *ttls = records
                .iter()
                .copied()
                .map(|ttl| ttl.clamp(floor, record_ceiling))
                .collect();
        }
        reclamped.max_lifespan_secs = lifespan;
    } else {
        for (ttls, records) in [
            (&mut reclamped.answer_ttls, &entry.answer_ttls),
            (&mut reclamped.authority_ttls, &entry.authority_ttls),
            (&mut reclamped.additional_ttls, &entry.additional_ttls),
        ] {
            *ttls = records
                .iter()
                .copied()
                .map(|ttl| ttl.clamp(floor, ceiling))
                .collect();
        }
        let min_record_ttl = reclamped
            .answer_ttls
            .iter()
            .chain(reclamped.authority_ttls.iter())
            .chain(reclamped.additional_ttls.iter())
            .copied()
            .min()
            .unwrap_or(config.min_ttl);
        reclamped.max_lifespan_secs = min_record_ttl;
    }

    reclamped
}

/// Whether a cached message represents a negative answer (NXDOMAIN or NODATA).
///
/// Mirrors the NODATA detection in [`DnsCache::insert_with_status_at_epoch`],
/// so a reload classifies an existing entry exactly as the insert did.
fn entry_is_negative(entry: &CacheEntry) -> bool {
    let message = &entry.message;
    if message.metadata.response_code == ResponseCode::NXDomain {
        return true;
    }
    if message.metadata.response_code != ResponseCode::NoError {
        return false;
    }
    let Some(question) = message.queries.first() else {
        return false;
    };
    let query_type = question.query_type();
    let has_answer_for_query_type = (query_type == RecordType::ANY && !message.answers.is_empty())
        || message
            .answers
            .iter()
            .any(|record| record.record_type() == query_type);
    !has_answer_for_query_type
}

/// Removes DNSSEC records and the AD flag from a response.
fn clear_dnssec_material(response: &mut Message) {
    response.metadata.authentic_data = false;
    response
        .answers
        .retain(|record| !record.record_type().is_dnssec());
    response
        .authorities
        .retain(|record| !record.record_type().is_dnssec());
    response
        .additionals
        .retain(|record| !record.record_type().is_dnssec());
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

/// Derives the RFC 2308 negative TTL from the first SOA record in
/// `authorities` (`min(SOA TTL, SOA MINIMUM)`) whose owner is one of
/// `chain_names` or an ancestor of one. A SOA for an unrelated zone is out of
/// bailiwick and is ignored.
fn negative_ttl_from_soa(authorities: &[Record], chain_names: &[Name]) -> Option<u32> {
    for auth in authorities {
        if let RData::SOA(SOA { minimum, .. }) = &auth.data
            && chain_names.iter().any(|name| auth.name.zone_of(name))
        {
            return Some(auth.ttl.min(*minimum));
        }
    }
    None
}

/// Authenticated lifetime of the NSEC/NSEC3 denial proof in `response`.
///
/// Returns the minimum TTL among the denial records and their signatures.
/// The DNSSEC validator's `apply_authenticated_ttls` has already capped every
/// TTL by the RRSIG original TTL and remaining validity, so this minimum is the
/// time the proof remains trustworthy. All three sections are scanned because
/// the validator accepts denial records and signatures from the additional
/// section as well. `None` when no NSEC/NSEC3 is present.
fn denial_proof_ttl(response: &Message) -> Option<u32> {
    let mut saw_denial = false;
    let mut min_ttl = u32::MAX;
    for record in response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .chain(response.additionals.iter())
    {
        match record.record_type() {
            RecordType::NSEC | RecordType::NSEC3 => {
                saw_denial = true;
                min_ttl = min_ttl.min(record.ttl);
            }
            // A signature can expire before the RR it covers. Including every
            // signature RR can only shorten the lifespan.
            RecordType::RRSIG | RecordType::SIG => {
                min_ttl = min_ttl.min(record.ttl);
            }
            _ => {}
        }
    }
    saw_denial.then_some(min_ttl)
}

/// Names on the CNAME chain starting at `qname` (including `qname` itself) and
/// the minimum TTL among the aliases on that chain.
///
/// A negative answer reached through aliases must expire with the shortest
/// alias on the path; otherwise the cached negative would outlive its chain.
/// The names are also the only in-bailiwick owners a negative SOA may cover.
fn cname_chain(qname: &Name, response: &Message) -> (Vec<Name>, Option<u32>) {
    let mut names: Vec<Name> = Vec::new();
    let mut min_ttl: Option<u32> = None;
    let mut current = qname.clone();
    for _ in 0..16 {
        if names.contains(&current) {
            break;
        }
        names.push(current.clone());
        let next = response.answers.iter().find_map(|record| {
            if record.record_type() == RecordType::CNAME && record.name == current {
                match &record.data {
                    RData::CNAME(cname) => {
                        min_ttl = Some(min_ttl.map_or(record.ttl, |ttl| ttl.min(record.ttl)));
                        Some(cname.0.clone())
                    }
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
    (names, min_ttl)
}
