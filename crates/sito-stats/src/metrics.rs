//! Prometheus metrics registry per section 14.2.
//!
//! Exposes all required metrics with cardinality bounds to prevent time-series explosion.
//!
//! Hot-path metrics inter their label values (`proto`, `verdict`, `upstream`,
//! `method`, ...) into dense integer ids once and keep the counters in
//! `RwLock` maps of atomics, so a per-query observation performs no `String`
//! allocation and never takes a *global* exclusive lock. Rendering is the only
//! place that materializes label strings and it sorts them, keeping the
//! exposition output byte-for-byte equivalent to the previous `BTreeMap`
//! implementation.
//!
//! Latency histograms are the one exception to lock-free updates: each
//! interned label (verdict for `sito_query_duration_seconds`, upstream for
//! `sito_upstream_rtt_seconds`) owns a small [`HistogramState`] behind its own
//! mutex (P2-62). The hot `allowed` path therefore serializes only with other
//! queries that share that verdict, not with cache/upstream/filter metrics or
//! other labels. The critical section is a fixed 14-bucket compare-and-add loop
//! and is never held across I/O, formatting or rendering. Both histogram maps
//! are read-mostly `RwLock`s: the write lock is taken only when a label is
//! first observed, and the label sets are bounded (verdicts are a closed set;
//! upstream labels pass through the same bounded interner as the other metric
//! families). Sharding by label would add memory/indirection without removing
//! the per-label serialization that the exposition requires, so the per-label
//! mutex is kept deliberately. `metrics_bench` records the single-threaded
//! per-update cost of `observe_query_duration("allowed", ...)` and a
//! multi-threaded same-label contended throughput group; the losslessness
//! guarantee is pinned by `test_histogram_concurrent_updates_are_not_lost`.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Write;
#[cfg(test)]
use std::sync::PoisonError;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Standard latency buckets for DNS query duration and upstream RTT (in seconds).
const LATENCY_BUCKETS: &[f64] = &[
    0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

#[derive(Debug)]
struct HistogramState {
    counts: Vec<u64>,
    sum: f64,
    sum_ns: u128,
    count: u64,
}

impl Default for HistogramState {
    fn default() -> Self {
        Self::new()
    }
}

impl HistogramState {
    fn new() -> Self {
        Self {
            counts: vec![0; LATENCY_BUCKETS.len()],
            sum: 0.0,
            sum_ns: 0,
            count: 0,
        }
    }

    fn observe(&mut self, val: f64) {
        self.count += 1;
        self.sum += val;
        if val.is_finite() && val > 0.0 {
            self.sum_ns = self
                .sum_ns
                .saturating_add((val * 1_000_000_000.0).round() as u128);
        }
        for (i, &bucket) in LATENCY_BUCKETS.iter().enumerate() {
            if val <= bucket {
                self.counts[i] += 1;
            }
        }
    }
}

/// Shared atomic counter value.
type Counter = Arc<AtomicU64>;
/// Map of interned-label counters.
type CounterMap<K> = RwLock<HashMap<K, Counter>>;
/// Rendered (label, label, label, count) tuple for three-label families.
type ThreeLabelCount = (Arc<str>, Arc<str>, Arc<str>, u64);
/// Map of interned-label histograms; only the first observation for a label
/// allocates and takes the outer write lock.
type HistogramMap = RwLock<HashMap<u32, Arc<Mutex<HistogramState>>>>;

#[derive(Default)]
struct InternerState {
    ids: HashMap<Arc<str>, u32>,
    labels: Vec<Arc<str>>,
}

/// Maximum distinct interned label values per registry. Beyond this, values
/// are collapsed into `__other__` so unbounded input (e.g. raw error strings)
/// cannot grow memory forever.
const MAX_INTERNER_LABELS: usize = 4_096;
/// Label value used once [`MAX_INTERNER_LABELS`] is reached.
const INTERNER_OVERFLOW_LABEL: &str = "__other__";

/// Maximum distinct `prefix` label values on
/// `sito_dns_acl_matched_prefix_total`. Prefixes come from operator
/// configuration, but opted-in client entry ids are not covered by the 1024
/// explicit-list cap, so the exporter collapses beyond this many.
const MAX_ACL_PREFIX_LABELS: usize = 256;

/// Maximum distinct upstream labels in `sito_dnssec_bogus_total`.
///
/// Upstream names come from configuration, but a bug or a future dynamically
/// named upstream source must not be able to grow this standalone map without
/// bound. New labels beyond the cap are collapsed into
/// [`DNSSEC_BOGUS_OVERFLOW_LABEL`] so the total observation count is kept.
const MAX_DNSSEC_BOGUS_UPSTREAMS: usize = 256;
/// Upstream label used for `sito_dnssec_bogus_total` overflow.
const DNSSEC_BOGUS_OVERFLOW_LABEL: &str = "__other__";

/// Query types that keep an exact numeric `qtype` label on
/// `sito_queries_total`. The DNS wire type is a free 16-bit field, so exposing
/// it verbatim would let any client create up to 65 536 permanent series per
/// protocol and verdict. Everything outside this list is collapsed into
/// [`QTYPE_OTHER_LABEL`], bounding the series count to
/// `protocols × (KNOWN_QTYPES.len() + 1) × verdicts`.
///
/// The list covers the types a resolver sees in practice (IANA common and
/// DNSSEC-enabled types).
pub const KNOWN_QTYPES: &[u16] = &[
    1,     // A
    2,     // NS
    5,     // CNAME
    6,     // SOA
    12,    // PTR
    13,    // HINFO
    15,    // MX
    16,    // TXT
    17,    // RP
    24,    // SIG
    25,    // KEY
    28,    // AAAA
    29,    // LOC
    33,    // SRV
    35,    // NAPTR
    36,    // KX
    37,    // CERT
    39,    // DNAME
    41,    // OPT
    43,    // DS
    44,    // SSHFP
    45,    // IPSECKEY
    46,    // RRSIG
    47,    // NSEC
    48,    // DNSKEY
    49,    // DHCID
    50,    // NSEC3
    51,    // NSEC3PARAM
    52,    // TLSA
    53,    // SMIMEA
    55,    // HIP
    59,    // CDS
    60,    // CDNSKEY
    61,    // OPENPGPKEY
    62,    // CSYNC
    63,    // ZONEMD
    64,    // SVCB
    65,    // HTTPS
    99,    // SPF
    108,   // EUI48
    109,   // EUI64
    249,   // TKEY
    250,   // TSIG
    251,   // IXFR
    252,   // AXFR
    255,   // ANY
    256,   // URI
    257,   // CAA
    259,   // DOA
    260,   // AMTRELAY
    32768, // TA
    32769, // DLV
];
/// Label value used for query types outside [`KNOWN_QTYPES`].
const QTYPE_OTHER_LABEL: &str = "__other__";
/// Sentinel stored in the counter key for every [`QTYPE_OTHER_LABEL`] query
/// type. Type 65535 is reserved (RFC 6895), so it never has to be preserved.
const QTYPE_OTHER: u16 = u16::MAX;

const QTYPE_BITMAP_WORDS: usize = 65_536 / 64;

/// Builds a 65 536-bit membership bitmap from [`KNOWN_QTYPES`] at compile time.
const fn qtype_bitmap() -> [u64; QTYPE_BITMAP_WORDS] {
    let mut words = [0u64; QTYPE_BITMAP_WORDS];
    let mut i = 0;
    while i < KNOWN_QTYPES.len() {
        let qtype = KNOWN_QTYPES[i] as usize;
        words[qtype / 64] |= 1u64 << (qtype % 64);
        i += 1;
    }
    words
}

static KNOWN_QTYPE_BITMAP: [u64; QTYPE_BITMAP_WORDS] = qtype_bitmap();

/// Returns true when `qtype` has a dedicated `sito_queries_total` series.
#[inline]
fn is_known_qtype(qtype: u16) -> bool {
    let qtype = qtype as usize;
    KNOWN_QTYPE_BITMAP[qtype / 64] & (1u64 << (qtype % 64)) != 0
}

/// Maps a raw wire query type to the bounded label stored in the counter key.
#[inline]
fn bounded_qtype(qtype: u16) -> u16 {
    if is_known_qtype(qtype) {
        qtype
    } else {
        QTYPE_OTHER
    }
}

/// Interns metric label values into dense integer ids.
///
/// Lookups take a shared `RwLock` read guard and allocate nothing; an id is
/// only assigned (and a `String` only allocated) when a label value is seen for
/// the first time. This keeps the DNS hot path free of per-query `format!` /
/// `to_string()` calls.
struct LabelInterner {
    cap: usize,
    state: RwLock<InternerState>,
}

impl Default for LabelInterner {
    fn default() -> Self {
        Self::new(MAX_INTERNER_LABELS)
    }
}

impl LabelInterner {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            state: RwLock::new(InternerState::default()),
        }
    }

    fn intern(&self, value: &str) -> u32 {
        if let Ok(state) = self.state.read()
            && let Some(&id) = state.ids.get(value)
        {
            return id;
        }

        let mut state = sito_core::sync::write_or_recover(&self.state);
        if let Some(&id) = state.ids.get(value) {
            return id;
        }
        // Collapse new values into a single overflow label once the cap is
        // reached; existing (known) labels keep their ids.
        let value = if state.labels.len() >= self.cap {
            INTERNER_OVERFLOW_LABEL
        } else {
            value
        };
        if let Some(&id) = state.ids.get(value) {
            return id;
        }
        let id = u32::try_from(state.labels.len()).expect("metric label id space exhausted");
        let label: Arc<str> = Arc::from(value);
        state.ids.insert(Arc::clone(&label), id);
        state.labels.push(label);
        id
    }

    fn label(&self, id: u32) -> Arc<str> {
        sito_core::sync::read_or_recover(&self.state)
            .labels
            .get(id as usize)
            .cloned()
            .unwrap_or_else(|| Arc::from(""))
    }

    /// Looks up an existing label id without adding a new interned value.
    fn lookup(&self, value: &str) -> Option<u32> {
        sito_core::sync::read_or_recover(&self.state)
            .ids
            .get(value)
            .copied()
    }
}

/// Increments the counter for `key`, creating it on first use.
///
/// The common path only takes a shared read lock; the write lock is taken once
/// per distinct key (cardinality is bounded by the label sets in use).
fn increment_counter<K>(map: &CounterMap<K>, key: K)
where
    K: std::hash::Hash + Eq,
{
    if let Ok(guard) = map.read()
        && let Some(counter) = guard.get(&key)
    {
        counter.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let mut guard = sito_core::sync::write_or_recover(map);
    guard
        .entry(key)
        .or_insert_with(|| Arc::new(AtomicU64::new(0)))
        .fetch_add(1, Ordering::Relaxed);
}

/// Observes `value` in the histogram for interned label id `id`.
///
/// The map lookup takes a shared lock on the hot path; the per-label mutex is
/// then held only for [`HistogramState::observe`]'s fixed bucket loop. See the
/// module documentation for why per-verdict/per-upstream serialization is
/// bounded and preferable to sharding this small state.
fn observe_histogram(map: &HistogramMap, id: u32, value: f64) {
    let histogram = {
        if let Ok(guard) = map.read()
            && let Some(histogram) = guard.get(&id)
        {
            Arc::clone(histogram)
        } else {
            let mut guard = sito_core::sync::write_or_recover(map);
            Arc::clone(
                guard
                    .entry(id)
                    .or_insert_with(|| Arc::new(Mutex::new(HistogramState::new()))),
            )
        }
    };
    sito_core::sync::lock_or_recover(&histogram).observe(value);
}

/// Thread-safe registry maintaining all Prometheus metrics specified in Table 14.2.
#[derive(Clone)]
pub struct MetricsRegistry {
    labels: Arc<LabelInterner>,
    /// (proto id, qtype, verdict id) -> count
    queries_total: Arc<CounterMap<(u32, u16, u32)>>,
    /// verdict id -> duration histogram
    query_duration: Arc<HistogramMap>,
    /// upstream id -> rtt histogram
    upstream_rtt: Arc<HistogramMap>,
    /// (upstream id, kind id) -> error count
    upstream_errors: Arc<CounterMap<(u32, u32)>>,
    /// upstream id -> health gauge (f64 bits)
    upstream_health: Arc<RwLock<HashMap<u32, AtomicU64>>>,
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    cache_size_bytes: Arc<AtomicI64>,
    dnssec_key_cache_hits: Arc<AtomicU64>,
    dnssec_key_cache_misses: Arc<AtomicU64>,
    dnssec_validations_secure: Arc<AtomicU64>,
    dnssec_validations_insecure: Arc<AtomicU64>,
    dnssec_validations_bogus: Arc<AtomicU64>,
    dnssec_validations_indeterminate: Arc<AtomicU64>,
    dnssec_fetch_budget_failures: Arc<AtomicU64>,
    dnssec_fetch_deadline_failures: Arc<AtomicU64>,
    cache_stale_served: Arc<AtomicU64>,
    dnssec_bogus: Arc<Mutex<BTreeMap<String, u64>>>,
    clients_identified: Arc<CounterMap<u32>>,
    /// (action id, reason id, family id) -> count (ADR-0011).
    acl_decisions: Arc<CounterMap<(u32, u32, u32)>>,
    /// (action id, prefix id, family id) -> count (ADR-0011). The prefix
    /// interner is dedicated and capped so entry-derived ids stay bounded.
    acl_matched_prefix: Arc<CounterMap<(u32, u32, u32)>>,
    acl_prefix_labels: Arc<LabelInterner>,
    /// Denied-and-dropped queries by family (ADR-0011).
    acl_dropped_ipv4: Arc<AtomicU64>,
    acl_dropped_ipv6: Arc<AtomicU64>,
    doh_bypass_blocked: Arc<AtomicU64>,
    /// proto id -> count
    transport_queries_total: Arc<CounterMap<u32>>,
    ha_slaves_connected: Arc<AtomicI64>,
    ha_config_version: Arc<Mutex<BTreeMap<String, f64>>>,
    /// Master-observed version divergence per slave instance (1 = diverged).
    ha_diverged: Arc<Mutex<BTreeMap<String, bool>>>,
    /// HA startup paths that left replication inactive, keyed by (role, reason).
    ha_startup_noop: Arc<Mutex<BTreeMap<(String, String), u64>>>,
    /// HA peers rejected for an incompatible protocol version, keyed by
    /// (role, reason code).
    ha_protocol_rejections: Arc<Mutex<BTreeMap<(String, String), u64>>>,
    querylog_dropped: Arc<AtomicU64>,
    stats_retention_last_success_seconds: Arc<AtomicU64>,
    stats_retention_last_failure_seconds: Arc<AtomicU64>,
    stats_retention_last_duration_millis: Arc<AtomicU64>,
    stats_retention_deleted_rows_total: Arc<AtomicU64>,
    stats_retention_rollup_deleted_rows_total: Arc<AtomicU64>,
    stats_retention_failures_total: Arc<AtomicU64>,
    stats_rollup_retention_days: Arc<AtomicU64>,
    filter_rules: Arc<AtomicU64>,
    filter_state: Arc<AtomicU64>,
    filter_lists_loaded: Arc<AtomicU64>,
    filter_lists_failed: Arc<AtomicU64>,
    filter_degraded_groups: Arc<AtomicU64>,
    filter_dropped_regex: Arc<AtomicU64>,
    filter_unavailable: Arc<AtomicU64>,
    filter_compile_seconds: Arc<Mutex<HistogramState>>,
    build_version: String,
    build_commit: String,
}

/// Filter-engine lifecycle/health values exposed as Prometheus gauges.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FilterStatusMetrics {
    /// `0 = disabled`, `1 = loading`, `2 = ready`, `3 = failed`.
    pub state: u8,
    /// Active compiled rules. `None` leaves the existing
    /// `sito_filter_rules{list="total"}` gauge untouched.
    pub rule_count: Option<usize>,
    /// Configured lists that loaded successfully.
    pub loaded_lists: u64,
    /// Configured lists that failed.
    pub failed_lists: u64,
    /// Groups published in a degraded (partial) form.
    pub degraded_groups: u64,
    /// Regex/wildcard patterns dropped from the active snapshot.
    pub dropped_regex_patterns: u64,
    /// No usable snapshot is active; fail-closed mode answers SERVFAIL.
    pub unavailable: u64,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new("0.1.0", "git-m5")
    }
}

impl MetricsRegistry {
    pub fn new(version: impl Into<String>, commit: impl Into<String>) -> Self {
        Self {
            labels: Arc::new(LabelInterner::default()),
            queries_total: Arc::new(RwLock::new(HashMap::new())),
            query_duration: Arc::new(RwLock::new(HashMap::new())),
            upstream_rtt: Arc::new(RwLock::new(HashMap::new())),
            upstream_errors: Arc::new(RwLock::new(HashMap::new())),
            upstream_health: Arc::new(RwLock::new(HashMap::new())),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            cache_size_bytes: Arc::new(AtomicI64::new(0)),
            dnssec_key_cache_hits: Arc::new(AtomicU64::new(0)),
            dnssec_key_cache_misses: Arc::new(AtomicU64::new(0)),
            dnssec_validations_secure: Arc::new(AtomicU64::new(0)),
            dnssec_validations_insecure: Arc::new(AtomicU64::new(0)),
            dnssec_validations_bogus: Arc::new(AtomicU64::new(0)),
            dnssec_validations_indeterminate: Arc::new(AtomicU64::new(0)),
            dnssec_fetch_budget_failures: Arc::new(AtomicU64::new(0)),
            dnssec_fetch_deadline_failures: Arc::new(AtomicU64::new(0)),
            cache_stale_served: Arc::new(AtomicU64::new(0)),
            dnssec_bogus: Arc::new(Mutex::new(BTreeMap::new())),
            clients_identified: Arc::new(RwLock::new(HashMap::new())),
            acl_decisions: Arc::new(RwLock::new(HashMap::new())),
            acl_matched_prefix: Arc::new(RwLock::new(HashMap::new())),
            acl_prefix_labels: Arc::new(LabelInterner::new(MAX_ACL_PREFIX_LABELS)),
            acl_dropped_ipv4: Arc::new(AtomicU64::new(0)),
            acl_dropped_ipv6: Arc::new(AtomicU64::new(0)),
            doh_bypass_blocked: Arc::new(AtomicU64::new(0)),
            transport_queries_total: Arc::new(RwLock::new(HashMap::new())),
            ha_slaves_connected: Arc::new(AtomicI64::new(0)),
            ha_config_version: Arc::new(Mutex::new(BTreeMap::new())),
            ha_diverged: Arc::new(Mutex::new(BTreeMap::new())),
            ha_startup_noop: Arc::new(Mutex::new(BTreeMap::new())),
            ha_protocol_rejections: Arc::new(Mutex::new(BTreeMap::new())),
            querylog_dropped: Arc::new(AtomicU64::new(0)),
            stats_retention_last_success_seconds: Arc::new(AtomicU64::new(0)),
            stats_retention_last_failure_seconds: Arc::new(AtomicU64::new(0)),
            stats_retention_last_duration_millis: Arc::new(AtomicU64::new(0)),
            stats_retention_deleted_rows_total: Arc::new(AtomicU64::new(0)),
            stats_retention_rollup_deleted_rows_total: Arc::new(AtomicU64::new(0)),
            stats_retention_failures_total: Arc::new(AtomicU64::new(0)),
            stats_rollup_retention_days: Arc::new(AtomicU64::new(0)),
            filter_rules: Arc::new(AtomicU64::new(0)),
            filter_state: Arc::new(AtomicU64::new(0)),
            filter_lists_loaded: Arc::new(AtomicU64::new(0)),
            filter_lists_failed: Arc::new(AtomicU64::new(0)),
            filter_degraded_groups: Arc::new(AtomicU64::new(0)),
            filter_dropped_regex: Arc::new(AtomicU64::new(0)),
            filter_unavailable: Arc::new(AtomicU64::new(0)),
            filter_compile_seconds: Arc::new(Mutex::new(HistogramState::new())),
            build_version: version.into(),
            build_commit: commit.into(),
        }
    }

    pub fn inc_queries(&self, proto: &str, qtype: u16, verdict: &str) {
        let proto_id = self.labels.intern(proto);
        let verdict_id = self.labels.intern(verdict);
        increment_counter(
            &self.queries_total,
            (proto_id, bounded_qtype(qtype), verdict_id),
        );
        increment_counter(&self.transport_queries_total, proto_id);
    }

    pub fn observe_query_duration(&self, verdict: &str, duration_secs: f64) {
        let verdict_id = self.labels.intern(verdict);
        observe_histogram(&self.query_duration, verdict_id, duration_secs);
    }

    pub fn observe_upstream_rtt(&self, upstream: &str, rtt_secs: f64) {
        let upstream_id = self.labels.intern(upstream);
        observe_histogram(&self.upstream_rtt, upstream_id, rtt_secs);
    }

    pub fn inc_upstream_errors(&self, upstream: &str, kind: &str) {
        let upstream_id = self.labels.intern(upstream);
        let kind_id = self.labels.intern(kind);
        increment_counter(&self.upstream_errors, (upstream_id, kind_id));
    }

    /// Removes every per-upstream series for `upstream`: the health gauge, the
    /// RTT histogram, all error-kind counters and the DNSSEC bogus counter.
    ///
    /// Called after a config apply/publish for upstream names that no longer
    /// exist, so removed servers cannot leave stale labels in the exposition
    /// forever. Unknown names are a no-op.
    pub fn remove_upstream_health(&self, upstream: &str) {
        // `dnssec_bogus` is keyed by the raw upstream string rather than an
        // interned label, so prune it even when the interner never saw the name.
        sito_core::sync::lock_or_recover(&self.dnssec_bogus).remove(upstream);

        let Some(upstream_id) = self.labels.lookup(upstream) else {
            return;
        };

        sito_core::sync::write_or_recover(&self.upstream_health).remove(&upstream_id);
        sito_core::sync::write_or_recover(&self.upstream_rtt).remove(&upstream_id);
        sito_core::sync::write_or_recover(&self.upstream_errors)
            .retain(|(label, _kind), _| *label != upstream_id);
    }

    pub fn set_upstream_health(&self, upstream: &str, health: f64) {
        let upstream_id = self.labels.intern(upstream);
        let bits = health.to_bits();
        if let Ok(guard) = self.upstream_health.read()
            && let Some(slot) = guard.get(&upstream_id)
        {
            slot.store(bits, Ordering::Relaxed);
            return;
        }

        let mut guard = sito_core::sync::write_or_recover(&self.upstream_health);
        match guard.get(&upstream_id) {
            Some(slot) => slot.store(bits, Ordering::Relaxed),
            None => {
                guard.insert(upstream_id, AtomicU64::new(bits));
            }
        }
    }

    pub fn inc_cache_hits(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_cache_misses(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_cache_size_bytes(&self, bytes: i64) {
        self.cache_size_bytes.store(bytes, Ordering::Relaxed);
    }

    /// Publishes DNSSEC validated-key cache hit/miss counters.
    ///
    /// Node-wide: the validator and its key cache are shared by all clients,
    /// so this cannot honour a per-client `ignore_stats`.
    pub fn set_dnssec_key_cache(&self, hits: u64, misses: u64) {
        self.dnssec_key_cache_hits.store(hits, Ordering::Relaxed);
        self.dnssec_key_cache_misses
            .store(misses, Ordering::Relaxed);
    }

    /// Publishes the cumulative DNSSEC validation outcome counters.
    ///
    /// This is the outcome view. It is independent of
    /// `sito_dnssec_bogus_total{upstream}`, which counts bogus answers per
    /// upstream; the two families overlap conceptually and must not be summed.
    /// Node-wide: the validator is shared by all clients, so this cannot
    /// honour a per-client `ignore_stats`.
    pub fn set_dnssec_validations(
        &self,
        secure: u64,
        insecure: u64,
        bogus: u64,
        indeterminate: u64,
    ) {
        self.dnssec_validations_secure
            .store(secure, Ordering::Relaxed);
        self.dnssec_validations_insecure
            .store(insecure, Ordering::Relaxed);
        self.dnssec_validations_bogus
            .store(bogus, Ordering::Relaxed);
        self.dnssec_validations_indeterminate
            .store(indeterminate, Ordering::Relaxed);
    }

    /// Publishes the cumulative DNSSEC key-fetch refusal counters,
    /// distinguishing count-budget exhaustion from an expired deadline.
    ///
    /// Node-wide like the other validator counters; not per-client.
    pub fn set_dnssec_fetch_failures(&self, budget: u64, deadline: u64) {
        self.dnssec_fetch_budget_failures
            .store(budget, Ordering::Relaxed);
        self.dnssec_fetch_deadline_failures
            .store(deadline, Ordering::Relaxed);
    }

    pub fn inc_cache_stale_served(&self) {
        self.cache_stale_served.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a bogus answer per upstream.
    ///
    /// This per-upstream view is independent of
    /// `sito_dnssec_validations_total{result="bogus"}`; the two families
    /// overlap and must not be summed. Labels are capped at
    /// [`MAX_DNSSEC_BOGUS_UPSTREAMS`]; surplus upstreams are counted under the
    /// constant `__other__` label.
    pub fn inc_dnssec_bogus(&self, upstream: &str) {
        let mut map = sito_core::sync::lock_or_recover(&self.dnssec_bogus);
        let key = if map.contains_key(upstream)
            || upstream == DNSSEC_BOGUS_OVERFLOW_LABEL
            || map.len() < MAX_DNSSEC_BOGUS_UPSTREAMS
        {
            upstream
        } else {
            DNSSEC_BOGUS_OVERFLOW_LABEL
        };
        *map.entry(key.to_string()).or_insert(0) += 1;
    }

    pub fn inc_clients_identified(&self, method: &str) {
        let method_id = self.labels.intern(method);
        increment_counter(&self.clients_identified, method_id);
    }

    /// Records one DNS client ACL decision (ADR-0011).
    ///
    /// `action` is `allow`/`deny`, `reason` is one of the four bounded reason
    /// labels and `family` is `ipv4`/`ipv6`. No client address or query name
    /// is ever a label.
    pub fn inc_acl_decision(&self, action: &str, reason: &str, family: &str) {
        increment_counter(
            &self.acl_decisions,
            (
                self.labels.intern(action),
                self.labels.intern(reason),
                self.labels.intern(family),
            ),
        );
    }

    /// Records the most specific configured prefix that matched. The value
    /// must already be canonical (`network/prefix` with host bits masked) and
    /// comes only from operator configuration.
    pub fn inc_acl_matched_prefix(&self, action: &str, prefix: &str, family: &str) {
        increment_counter(
            &self.acl_matched_prefix,
            (
                self.labels.intern(action),
                self.acl_prefix_labels.intern(prefix),
                self.labels.intern(family),
            ),
        );
    }

    /// Records a denied query that was silently dropped (`deny_response =
    /// "drop"`). Synthesized REFUSED responses use
    /// `sito_queries_total{verdict="refused"}` instead.
    pub fn inc_acl_dropped(&self, family: &str) {
        match family {
            "ipv6" => self.acl_dropped_ipv6.fetch_add(1, Ordering::Relaxed),
            _ => self.acl_dropped_ipv4.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn inc_doh_bypass_blocked(&self) {
        self.doh_bypass_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_ha_slaves_connected(&self, count: i64) {
        self.ha_slaves_connected.store(count, Ordering::Relaxed);
    }

    pub fn set_ha_config_version(&self, instance: &str, version: f64) {
        let mut map = sito_core::sync::lock_or_recover(&self.ha_config_version);
        map.insert(instance.to_string(), version);
    }

    /// Removes the per-instance HA config version label (e.g. on disconnect) to
    /// prevent unbounded metric cardinality growth.
    pub fn remove_ha_config_version(&self, instance: &str) {
        let mut map = sito_core::sync::lock_or_recover(&self.ha_config_version);
        map.remove(instance);
    }

    /// Publishes whether the master observed a version-continuity divergence
    /// with a slave instance (`1` = diverged, `0` = continuity restored).
    pub fn set_ha_diverged(&self, instance: &str, diverged: bool) {
        let mut map = sito_core::sync::lock_or_recover(&self.ha_diverged);
        map.insert(instance.to_string(), diverged);
    }

    /// Removes the per-instance HA divergence series (e.g. on disconnect) so
    /// metric cardinality cannot grow with churn.
    pub fn remove_ha_diverged(&self, instance: &str) {
        let mut map = sito_core::sync::lock_or_recover(&self.ha_diverged);
        map.remove(instance);
    }

    /// Counts an HA startup path that left replication inactive.
    ///
    /// `role` is `master`/`slave` and `reason` is a fixed, low-cardinality
    /// identifier (`replication_disabled`, `missing_master_url`,
    /// `tls_init_failed`, `bind_failed`).
    pub fn inc_ha_startup_noop(&self, role: &str, reason: &str) {
        let mut map = sito_core::sync::lock_or_recover(&self.ha_startup_noop);
        *map.entry((role.to_string(), reason.to_string()))
            .or_insert(0) += 1;
    }

    /// Counts an HA peer rejected for an incompatible protocol version.
    ///
    /// `role` is the local side (`master`/`slave`) and `reason` is a fixed,
    /// low-cardinality identifier (`version_mismatch`); the detailed,
    /// operator-facing explanation is logged and sent in the close frame.
    pub fn inc_ha_protocol_rejection(&self, role: &str, reason: &str) {
        let mut map = sito_core::sync::lock_or_recover(&self.ha_protocol_rejections);
        *map.entry((role.to_string(), reason.to_string()))
            .or_insert(0) += 1;
    }

    pub fn set_querylog_dropped(&self, dropped: u64) {
        self.querylog_dropped.store(dropped, Ordering::Relaxed);
    }

    /// Publishes the configured rollup retention without waiting for the first
    /// sweep.
    pub fn set_rollup_retention_days(&self, days: u32) {
        self.stats_rollup_retention_days
            .store(u64::from(days), Ordering::Relaxed);
    }

    /// Publishes the persisted last-success timestamp at startup.
    pub fn set_retention_last_success_seconds(&self, seconds: u64) {
        self.stats_retention_last_success_seconds
            .store(seconds, Ordering::Relaxed);
    }

    /// Records a successful retention sweep. Timestamps are unix seconds;
    /// `duration_millis` is wall-clock duration of the whole sweep.
    pub fn record_retention_success(
        &self,
        duration_millis: u64,
        deleted_rows: u64,
        rollup_deleted_rows: u64,
        rollup_retention_days: u32,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.stats_retention_last_success_seconds
            .store(now, Ordering::Relaxed);
        self.stats_retention_last_duration_millis
            .store(duration_millis, Ordering::Relaxed);
        self.stats_retention_deleted_rows_total
            .fetch_add(deleted_rows, Ordering::Relaxed);
        self.stats_retention_rollup_deleted_rows_total
            .fetch_add(rollup_deleted_rows, Ordering::Relaxed);
        self.stats_rollup_retention_days
            .store(u64::from(rollup_retention_days), Ordering::Relaxed);
    }

    /// Records a failed retention sweep.
    pub fn record_retention_failure(&self, duration_millis: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.stats_retention_last_failure_seconds
            .store(now, Ordering::Relaxed);
        self.stats_retention_last_duration_millis
            .store(duration_millis, Ordering::Relaxed);
        self.stats_retention_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Publishes the number of active compiled filter rules.
    pub fn set_filter_rules(&self, count: usize) {
        self.filter_rules
            .store(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Publishes filter-engine lifecycle/health gauges.
    ///
    /// `state` is `0 = disabled`, `1 = loading`, `2 = ready`, `3 = failed`.
    pub fn set_filter_status(&self, status: FilterStatusMetrics) {
        if let Some(rule_count) = status.rule_count {
            self.set_filter_rules(rule_count);
        }
        self.filter_state
            .store(u64::from(status.state), Ordering::Relaxed);
        self.filter_lists_loaded
            .store(status.loaded_lists, Ordering::Relaxed);
        self.filter_lists_failed
            .store(status.failed_lists, Ordering::Relaxed);
        self.filter_degraded_groups
            .store(status.degraded_groups, Ordering::Relaxed);
        self.filter_dropped_regex
            .store(status.dropped_regex_patterns, Ordering::Relaxed);
        self.filter_unavailable
            .store(status.unavailable, Ordering::Relaxed);
    }

    /// Records how long the last filter snapshot compilation took.
    pub fn observe_filter_compile(&self, seconds: f64) {
        let mut hist = sito_core::sync::lock_or_recover(&self.filter_compile_seconds);
        hist.observe(seconds);
    }

    /// Returns an observer that records compile durations in this registry.
    ///
    /// The filter engine cannot depend on `sito-stats`; the server installs
    /// this callback on the engine so startup and scheduled refreshes are
    /// recorded as well as API-triggered reloads.
    #[must_use]
    pub fn compile_observer(&self) -> std::sync::Arc<dyn Fn(f64) + Send + Sync> {
        let registry = self.clone();
        std::sync::Arc::new(move |seconds| registry.observe_filter_compile(seconds))
    }

    /// Returns total query count and blocked query count processed by this registry.
    pub fn get_queries_and_blocked(&self) -> (u64, u64) {
        let map = sito_core::sync::read_or_recover(&self.queries_total);
        let mut total = 0u64;
        let mut blocked = 0u64;
        for (&(_proto, _qtype, verdict), count) in map.iter() {
            let count = count.load(Ordering::Relaxed);
            total += count;
            if self.labels.label(verdict).as_ref() == "blocked" {
                blocked += count;
            }
        }
        (total, blocked)
    }

    /// Returns a map of upstream identifiers to (rtt_ms, total_errors).
    ///
    /// Both values are **lifetime** measurements: the mean of every RTT sample
    /// observed since process start and the total error count. Callers that
    /// need a window-scoped view (e.g. periodic reports) must take two
    /// [`Self::snapshot`]s and use [`MetricsSnapshot::delta_since`].
    pub fn get_upstream_reports(&self) -> std::collections::HashMap<String, (f64, u64)> {
        let mut res = std::collections::HashMap::new();
        {
            let map = sito_core::sync::read_or_recover(&self.upstream_rtt);
            for (&upstream, hist) in map.iter() {
                let hist = sito_core::sync::lock_or_recover(hist);
                let rtt_ms = if hist.count > 0 {
                    (hist.sum / hist.count as f64) * 1000.0
                } else {
                    0.0
                };
                drop(hist);
                res.insert(self.labels.label(upstream).to_string(), (rtt_ms, 0u64));
            }
        }
        {
            let map = sito_core::sync::read_or_recover(&self.upstream_errors);
            for (&(upstream, _kind), count) in map.iter() {
                let entry = res
                    .entry(self.labels.label(upstream).to_string())
                    .or_insert((0.0, 0u64));
                entry.1 += count.load(Ordering::Relaxed);
            }
        }
        res
    }

    /// Captures the lifetime counters and RTT accumulators that back periodic
    /// window reports.
    ///
    /// Take a snapshot, then for each later report call
    /// [`MetricsSnapshot::delta_since`] with the previous snapshot to obtain
    /// the activity observed since then. Unlike [`Self::get_upstream_reports`],
    /// RTT samples are carried as a sum and a sample count, so a window mean
    /// never mixes in samples taken before the window.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let mut queries_total = 0u64;
        let mut blocked_total = 0u64;
        {
            let map = sito_core::sync::read_or_recover(&self.queries_total);
            for (&(_proto, _qtype, verdict), count) in map.iter() {
                let count = count.load(Ordering::Relaxed);
                queries_total += count;
                if self.labels.label(verdict).as_ref() == "blocked" {
                    blocked_total += count;
                }
            }
        }

        let mut upstreams: HashMap<String, UpstreamSnapshot> = HashMap::new();
        {
            let map = sito_core::sync::read_or_recover(&self.upstream_rtt);
            for (&upstream, hist) in map.iter() {
                let hist = sito_core::sync::lock_or_recover(hist);
                upstreams.insert(
                    self.labels.label(upstream).to_string(),
                    UpstreamSnapshot {
                        rtt_sum_secs: hist.sum,
                        rtt_sum_ns: hist.sum_ns,
                        rtt_count: hist.count,
                        errors_total: 0,
                    },
                );
            }
        }
        {
            let map = sito_core::sync::read_or_recover(&self.upstream_errors);
            for (&(upstream, _kind), count) in map.iter() {
                upstreams
                    .entry(self.labels.label(upstream).to_string())
                    .or_default()
                    .errors_total += count.load(Ordering::Relaxed);
            }
        }

        MetricsSnapshot {
            queries_total,
            blocked_total,
            upstreams,
        }
    }

    /// Generates the Prometheus text exposition representation conforming to Table 14.2.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        self.render_query_family(&mut out);
        self.render_acl_family(&mut out);
        self.render_upstream_family(&mut out);
        self.render_cache_family(&mut out);
        self.render_filter_family(&mut out);
        self.render_dnssec_client_family(&mut out);
        self.render_ha_retention_family(&mut out);
        self.render_build_info(&mut out);
        out
    }

    /// Query counters and latency histogram.
    fn render_query_family(&self, out: &mut String) {
        // 1. sito_queries_total
        out.push_str("# HELP sito_queries_total Total DNS queries processed\n");
        out.push_str("# TYPE sito_queries_total counter\n");
        {
            let map = sito_core::sync::read_or_recover(&self.queries_total);
            if map.is_empty() {
                out.push_str(
                    "sito_queries_total{proto=\"udp\",qtype=\"1\",verdict=\"allowed\"} 0\n",
                );
            } else {
                let mut entries: Vec<(Arc<str>, u16, Arc<str>, u64)> = map
                    .iter()
                    .map(|(&(proto, qtype, verdict), count)| {
                        (
                            self.labels.label(proto),
                            qtype,
                            self.labels.label(verdict),
                            count.load(Ordering::Relaxed),
                        )
                    })
                    .collect();
                // BTreeMap ordering: proto, qtype rendered as string, verdict.
                entries.sort_by(|a, b| {
                    a.0.as_ref()
                        .cmp(b.0.as_ref())
                        .then_with(|| a.1.to_string().cmp(&b.1.to_string()))
                        .then_with(|| a.2.as_ref().cmp(b.2.as_ref()))
                });
                for (proto, qtype, verdict, count) in entries {
                    let qtype_label = if qtype == QTYPE_OTHER {
                        QTYPE_OTHER_LABEL.to_string()
                    } else {
                        qtype.to_string()
                    };
                    let _ = writeln!(
                        out,
                        "sito_queries_total{{proto=\"{}\",qtype=\"{}\",verdict=\"{}\"}} {count}",
                        escape_label_value(&proto),
                        qtype_label,
                        escape_label_value(&verdict)
                    );
                }
            }
        }

        // 1b. sito_transport_queries_total
        out.push_str("# HELP sito_transport_queries_total Total DNS queries by transport\n");
        out.push_str("# TYPE sito_transport_queries_total counter\n");
        {
            let map = sito_core::sync::read_or_recover(&self.transport_queries_total);
            if map.is_empty() {
                out.push_str("sito_transport_queries_total{proto=\"udp\"} 0\n");
            } else {
                let mut entries: Vec<(Arc<str>, u64)> = map
                    .iter()
                    .map(|(&proto, count)| {
                        (self.labels.label(proto), count.load(Ordering::Relaxed))
                    })
                    .collect();
                entries.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
                for (proto, count) in entries {
                    let _ = writeln!(
                        out,
                        "sito_transport_queries_total{{proto=\"{}\"}} {count}",
                        escape_label_value(&proto)
                    );
                }
            }
        }

        // 2. sito_query_duration_seconds
        out.push_str("# HELP sito_query_duration_seconds Histogram of query duration in seconds\n");
        out.push_str("# TYPE sito_query_duration_seconds histogram\n");
        {
            let map = sito_core::sync::read_or_recover(&self.query_duration);
            if map.is_empty() {
                for &b in LATENCY_BUCKETS {
                    let _ = writeln!(
                        out,
                        "sito_query_duration_seconds_bucket{{verdict=\"allowed\",le=\"{b}\"}} 0"
                    );
                }
                out.push_str(
                    "sito_query_duration_seconds_bucket{verdict=\"allowed\",le=\"+Inf\"} 0\n",
                );
                out.push_str("sito_query_duration_seconds_sum{verdict=\"allowed\"} 0\n");
                out.push_str("sito_query_duration_seconds_count{verdict=\"allowed\"} 0\n");
            } else {
                let mut entries: Vec<(Arc<str>, Arc<Mutex<HistogramState>>)> = map
                    .iter()
                    .map(|(&verdict, hist)| (self.labels.label(verdict), Arc::clone(hist)))
                    .collect();
                entries.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
                for (verdict, hist) in entries {
                    let hist = sito_core::sync::lock_or_recover(&hist);
                    for (i, &b) in LATENCY_BUCKETS.iter().enumerate() {
                        let c = hist.counts[i];
                        let _ = writeln!(
                            out,
                            "sito_query_duration_seconds_bucket{{verdict=\"{}\",le=\"{b}\"}} {c}",
                            escape_label_value(&verdict)
                        );
                    }
                    let _ = writeln!(
                        out,
                        "sito_query_duration_seconds_bucket{{verdict=\"{}\",le=\"+Inf\"}} {}",
                        escape_label_value(&verdict),
                        hist.count
                    );
                    let _ = writeln!(
                        out,
                        "sito_query_duration_seconds_sum{{verdict=\"{}\"}} {}",
                        escape_label_value(&verdict),
                        hist.sum
                    );
                    let _ = writeln!(
                        out,
                        "sito_query_duration_seconds_count{{verdict=\"{}\"}} {}",
                        escape_label_value(&verdict),
                        hist.count
                    );
                }
            }
        }
    }

    /// DNS client ACL counters (ADR-0011).
    fn render_acl_family(&self, out: &mut String) {
        // 1c. sito_dns_acl_decisions_total
        out.push_str("# HELP sito_dns_acl_decisions_total DNS client ACL admission decisions\n");
        out.push_str("# TYPE sito_dns_acl_decisions_total counter\n");
        {
            let map = sito_core::sync::read_or_recover(&self.acl_decisions);
            if map.is_empty() {
                out.push_str(
                    "sito_dns_acl_decisions_total{action=\"allow\",reason=\"default_policy\",family=\"ipv4\"} 0\n",
                );
            } else {
                let mut entries: Vec<ThreeLabelCount> = map
                    .iter()
                    .map(|(&(action, reason, family), count)| {
                        (
                            self.labels.label(action),
                            self.labels.label(reason),
                            self.labels.label(family),
                            count.load(Ordering::Relaxed),
                        )
                    })
                    .collect();
                entries.sort_by(|a, b| {
                    a.0.as_ref()
                        .cmp(b.0.as_ref())
                        .then_with(|| a.1.as_ref().cmp(b.1.as_ref()))
                        .then_with(|| a.2.as_ref().cmp(b.2.as_ref()))
                });
                for (action, reason, family, count) in entries {
                    let _ = writeln!(
                        out,
                        "sito_dns_acl_decisions_total{{action=\"{}\",reason=\"{}\",family=\"{}\"}} {count}",
                        escape_label_value(&action),
                        escape_label_value(&reason),
                        escape_label_value(&family)
                    );
                }
            }
        }

        // 1d. sito_dns_acl_matched_prefix_total
        out.push_str(
            "# HELP sito_dns_acl_matched_prefix_total DNS client ACL decisions by canonical matched prefix\n",
        );
        out.push_str("# TYPE sito_dns_acl_matched_prefix_total counter\n");
        {
            let map = sito_core::sync::read_or_recover(&self.acl_matched_prefix);
            if map.is_empty() {
                // Neutral placeholder: never synthesize a real configured
                // prefix (0.0.0.0/0) into an empty series.
                out.push_str(
                    "sito_dns_acl_matched_prefix_total{action=\"allow\",prefix=\"__none__\",family=\"ipv4\"} 0\n",
                );
            } else {
                let mut entries: Vec<ThreeLabelCount> = map
                    .iter()
                    .map(|(&(action, prefix, family), count)| {
                        (
                            self.labels.label(action),
                            self.acl_prefix_labels.label(prefix),
                            self.labels.label(family),
                            count.load(Ordering::Relaxed),
                        )
                    })
                    .collect();
                entries.sort_by(|a, b| {
                    a.0.as_ref()
                        .cmp(b.0.as_ref())
                        .then_with(|| a.1.as_ref().cmp(b.1.as_ref()))
                        .then_with(|| a.2.as_ref().cmp(b.2.as_ref()))
                });
                for (action, prefix, family, count) in entries {
                    let _ = writeln!(
                        out,
                        "sito_dns_acl_matched_prefix_total{{action=\"{}\",prefix=\"{}\",family=\"{}\"}} {count}",
                        escape_label_value(&action),
                        escape_label_value(&prefix),
                        escape_label_value(&family)
                    );
                }
            }
        }

        // 1e. sito_dns_acl_dropped_total
        out.push_str(
            "# HELP sito_dns_acl_dropped_total DNS queries denied and silently dropped by the client ACL\n",
        );
        out.push_str("# TYPE sito_dns_acl_dropped_total counter\n");
        let _ = writeln!(
            out,
            "sito_dns_acl_dropped_total{{family=\"ipv4\"}} {}",
            self.acl_dropped_ipv4.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "sito_dns_acl_dropped_total{{family=\"ipv6\"}} {}",
            self.acl_dropped_ipv6.load(Ordering::Relaxed)
        );
    }

    /// Upstream latency, error, and health families.
    fn render_upstream_family(&self, out: &mut String) {
        // 3. sito_upstream_rtt_seconds
        out.push_str("# HELP sito_upstream_rtt_seconds Upstream round-trip time in seconds\n");
        out.push_str("# TYPE sito_upstream_rtt_seconds histogram\n");
        {
            let map = sito_core::sync::read_or_recover(&self.upstream_rtt);
            if map.is_empty() {
                for &b in LATENCY_BUCKETS {
                    let _ = writeln!(
                        out,
                        "sito_upstream_rtt_seconds_bucket{{upstream=\"default\",le=\"{b}\"}} 0"
                    );
                }
                out.push_str(
                    "sito_upstream_rtt_seconds_bucket{upstream=\"default\",le=\"+Inf\"} 0\n",
                );
                out.push_str("sito_upstream_rtt_seconds_sum{upstream=\"default\"} 0\n");
                out.push_str("sito_upstream_rtt_seconds_count{upstream=\"default\"} 0\n");
            } else {
                let mut entries: Vec<(Arc<str>, Arc<Mutex<HistogramState>>)> = map
                    .iter()
                    .map(|(&upstream, hist)| (self.labels.label(upstream), Arc::clone(hist)))
                    .collect();
                entries.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
                for (upstream, hist) in entries {
                    let hist = sito_core::sync::lock_or_recover(&hist);
                    for (i, &b) in LATENCY_BUCKETS.iter().enumerate() {
                        let c = hist.counts[i];
                        let _ = writeln!(
                            out,
                            "sito_upstream_rtt_seconds_bucket{{upstream=\"{}\",le=\"{b}\"}} {c}",
                            escape_label_value(&upstream)
                        );
                    }
                    let _ = writeln!(
                        out,
                        "sito_upstream_rtt_seconds_bucket{{upstream=\"{}\",le=\"+Inf\"}} {}",
                        escape_label_value(&upstream),
                        hist.count
                    );
                    let _ = writeln!(
                        out,
                        "sito_upstream_rtt_seconds_sum{{upstream=\"{}\"}} {}",
                        escape_label_value(&upstream),
                        hist.sum
                    );
                    let _ = writeln!(
                        out,
                        "sito_upstream_rtt_seconds_count{{upstream=\"{}\"}} {}",
                        escape_label_value(&upstream),
                        hist.count
                    );
                }
            }
        }

        // 4. sito_upstream_errors_total
        out.push_str("# HELP sito_upstream_errors_total Total errors encountered per upstream\n");
        out.push_str("# TYPE sito_upstream_errors_total counter\n");
        {
            let map = sito_core::sync::read_or_recover(&self.upstream_errors);
            if map.is_empty() {
                out.push_str(
                    "sito_upstream_errors_total{upstream=\"default\",kind=\"timeout\"} 0\n",
                );
            } else {
                let mut entries: Vec<(Arc<str>, Arc<str>, u64)> = map
                    .iter()
                    .map(|(&(upstream, kind), count)| {
                        (
                            self.labels.label(upstream),
                            self.labels.label(kind),
                            count.load(Ordering::Relaxed),
                        )
                    })
                    .collect();
                entries.sort_by(|a, b| {
                    a.0.as_ref()
                        .cmp(b.0.as_ref())
                        .then_with(|| a.1.as_ref().cmp(b.1.as_ref()))
                });
                for (upstream, kind, count) in entries {
                    let _ = writeln!(
                        out,
                        "sito_upstream_errors_total{{upstream=\"{}\",kind=\"{}\"}} {count}",
                        escape_label_value(&upstream),
                        escape_label_value(&kind)
                    );
                }
            }
        }

        // 5. sito_upstream_health
        out.push_str("# HELP sito_upstream_health Upstream resolver health status (1 = healthy, 0 = degraded/down)\n");
        out.push_str("# TYPE sito_upstream_health gauge\n");
        {
            let map = sito_core::sync::read_or_recover(&self.upstream_health);
            if map.is_empty() {
                out.push_str("sito_upstream_health{upstream=\"default\"} 1\n");
            } else {
                let mut entries: Vec<(Arc<str>, f64)> = map
                    .iter()
                    .map(|(&upstream, health)| {
                        (
                            self.labels.label(upstream),
                            f64::from_bits(health.load(Ordering::Relaxed)),
                        )
                    })
                    .collect();
                entries.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
                for (upstream, health) in entries {
                    let _ = writeln!(
                        out,
                        "sito_upstream_health{{upstream=\"{}\"}} {health}",
                        escape_label_value(&upstream)
                    );
                }
            }
        }
    }

    /// Cache hit/miss, DNSSEC key-cache, and stale-serve families.
    fn render_cache_family(&self, out: &mut String) {
        // 6. sito_cache_hits_total & misses
        out.push_str("# HELP sito_cache_hits_total Total DNS cache hits\n");
        out.push_str("# TYPE sito_cache_hits_total counter\n");
        let _ = writeln!(
            out,
            "sito_cache_hits_total {}",
            self.cache_hits.load(Ordering::Relaxed)
        );

        out.push_str("# HELP sito_cache_misses_total Total DNS cache misses\n");
        out.push_str("# TYPE sito_cache_misses_total counter\n");
        let _ = writeln!(
            out,
            "sito_cache_misses_total {}",
            self.cache_misses.load(Ordering::Relaxed)
        );

        // 7. sito_dnssec_key_cache_* and sito_cache_size_bytes
        out.push_str("# HELP sito_dnssec_key_cache_hits_total DNSSEC validated-key cache hits\n");
        out.push_str("# TYPE sito_dnssec_key_cache_hits_total counter\n");
        let _ = writeln!(
            out,
            "sito_dnssec_key_cache_hits_total {}",
            self.dnssec_key_cache_hits.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP sito_dnssec_key_cache_misses_total DNSSEC validated-key cache misses\n",
        );
        out.push_str("# TYPE sito_dnssec_key_cache_misses_total counter\n");
        let _ = writeln!(
            out,
            "sito_dnssec_key_cache_misses_total {}",
            self.dnssec_key_cache_misses.load(Ordering::Relaxed)
        );
        out.push_str("# HELP sito_cache_size_bytes Current memory size of cache in bytes\n");
        out.push_str("# TYPE sito_cache_size_bytes gauge\n");
        let _ = writeln!(
            out,
            "sito_cache_size_bytes {}",
            self.cache_size_bytes.load(Ordering::Relaxed)
        );

        // 8. sito_cache_stale_served_total
        out.push_str("# HELP sito_cache_stale_served_total Total stale cache answers served\n");
        out.push_str("# TYPE sito_cache_stale_served_total counter\n");
        let _ = writeln!(
            out,
            "sito_cache_stale_served_total {}",
            self.cache_stale_served.load(Ordering::Relaxed)
        );
    }

    /// Filter rule and compile-duration families.
    fn render_filter_family(&self, out: &mut String) {
        // 9. sito_filter_rules
        out.push_str("# HELP sito_filter_rules Number of active filter rules per list\n");
        out.push_str("# TYPE sito_filter_rules gauge\n");
        let _ = writeln!(
            out,
            "sito_filter_rules{{list=\"total\"}} {}",
            self.filter_rules.load(Ordering::Relaxed)
        );

        out.push_str(
            "# HELP sito_filter_state Filter engine lifecycle (0 disabled, 1 loading, 2 ready, 3 failed)\n",
        );
        out.push_str("# TYPE sito_filter_state gauge\n");
        let _ = writeln!(
            out,
            "sito_filter_state {}",
            self.filter_state.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP sito_filter_lists_loaded Configured filter lists loaded in the last reload\n",
        );
        out.push_str("# TYPE sito_filter_lists_loaded gauge\n");
        let _ = writeln!(
            out,
            "sito_filter_lists_loaded {}",
            self.filter_lists_loaded.load(Ordering::Relaxed)
        );
        out.push_str("# HELP sito_filter_lists_failed Configured filter lists that failed in the last reload\n");
        out.push_str("# TYPE sito_filter_lists_failed gauge\n");
        let _ = writeln!(
            out,
            "sito_filter_lists_failed {}",
            self.filter_lists_failed.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP sito_filter_degraded_groups Groups with degraded or unpublishable rules (budget/limit, missing list, invalid-only)\n",
        );
        out.push_str("# TYPE sito_filter_degraded_groups gauge\n");
        let _ = writeln!(
            out,
            "sito_filter_degraded_groups {}",
            self.filter_degraded_groups.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP sito_filter_dropped_regex_patterns Regex/wildcard patterns dropped from the active snapshot\n",
        );
        out.push_str("# TYPE sito_filter_dropped_regex_patterns gauge\n");
        let _ = writeln!(
            out,
            "sito_filter_dropped_regex_patterns {}",
            self.filter_dropped_regex.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP sito_filter_unavailable No usable filter snapshot is active (1 = unavailable; fail_closed answers SERVFAIL)\n",
        );
        out.push_str("# TYPE sito_filter_unavailable gauge\n");
        let _ = writeln!(
            out,
            "sito_filter_unavailable {}",
            self.filter_unavailable.load(Ordering::Relaxed)
        );

        // 10. sito_filter_compile_seconds
        out.push_str(
            "# HELP sito_filter_compile_seconds Compilation duration for filter rule trie\n",
        );
        out.push_str("# TYPE sito_filter_compile_seconds histogram\n");
        {
            let hist = sito_core::sync::lock_or_recover(&self.filter_compile_seconds);
            for (i, &b) in LATENCY_BUCKETS.iter().enumerate() {
                let c = hist.counts[i];
                let _ = writeln!(out, "sito_filter_compile_seconds_bucket{{le=\"{b}\"}} {c}");
            }
            let _ = writeln!(
                out,
                "sito_filter_compile_seconds_bucket{{le=\"+Inf\"}} {}",
                hist.count
            );
            let _ = writeln!(out, "sito_filter_compile_seconds_sum {}", hist.sum);
            let _ = writeln!(out, "sito_filter_compile_seconds_count {}", hist.count);
        }
    }

    /// DNSSEC, client, and DoH bypass families.
    fn render_dnssec_client_family(&self, out: &mut String) {
        // 11a. sito_dnssec_validations_total
        out.push_str(
            "# HELP sito_dnssec_validations_total Total DNSSEC validation outcomes (NTA bypasses excluded)\n",
        );
        out.push_str("# TYPE sito_dnssec_validations_total counter\n");
        for (result, value) in [
            ("secure", &self.dnssec_validations_secure),
            ("insecure", &self.dnssec_validations_insecure),
            ("bogus", &self.dnssec_validations_bogus),
            ("indeterminate", &self.dnssec_validations_indeterminate),
        ] {
            let _ = writeln!(
                out,
                "sito_dnssec_validations_total{{result=\"{result}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }

        // 11. sito_dnssec_bogus_total
        out.push_str("# HELP sito_dnssec_bogus_total Total DNSSEC bogus responses detected\n");
        out.push_str("# TYPE sito_dnssec_bogus_total counter\n");
        {
            let map = sito_core::sync::lock_or_recover(&self.dnssec_bogus);
            if map.is_empty() {
                out.push_str("sito_dnssec_bogus_total{upstream=\"default\"} 0\n");
            } else {
                for (upstream, count) in map.iter() {
                    let _ = writeln!(
                        out,
                        "sito_dnssec_bogus_total{{upstream=\"{}\"}} {count}",
                        escape_label_value(upstream)
                    );
                }
            }
        }

        // 11b. sito_dnssec_fetch_failures_total
        out.push_str(
            "# HELP sito_dnssec_fetch_failures_total Total DNSSEC key fetches refused by budget or deadline\n",
        );
        out.push_str("# TYPE sito_dnssec_fetch_failures_total counter\n");
        let _ = writeln!(
            out,
            "sito_dnssec_fetch_failures_total{{kind=\"budget\"}} {}",
            self.dnssec_fetch_budget_failures.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "sito_dnssec_fetch_failures_total{{kind=\"deadline\"}} {}",
            self.dnssec_fetch_deadline_failures.load(Ordering::Relaxed)
        );

        // 12. sito_clients_identified_total
        out.push_str("# HELP sito_clients_identified_total Total clients successfully identified by method\n");
        out.push_str("# TYPE sito_clients_identified_total counter\n");
        {
            let map = sito_core::sync::read_or_recover(&self.clients_identified);
            if map.is_empty() {
                out.push_str("sito_clients_identified_total{method=\"ip\"} 0\n");
            } else {
                let mut entries: Vec<(Arc<str>, u64)> = map
                    .iter()
                    .map(|(&method, count)| {
                        (self.labels.label(method), count.load(Ordering::Relaxed))
                    })
                    .collect();
                entries.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
                for (method, count) in entries {
                    let _ = writeln!(
                        out,
                        "sito_clients_identified_total{{method=\"{}\"}} {count}",
                        escape_label_value(&method)
                    );
                }
            }
        }

        // 13. sito_doh_bypass_blocked_total
        out.push_str(
            "# HELP sito_doh_bypass_blocked_total Total encrypted DNS bypass attempts blocked\n",
        );
        out.push_str("# TYPE sito_doh_bypass_blocked_total counter\n");
        let _ = writeln!(
            out,
            "sito_doh_bypass_blocked_total {}",
            self.doh_bypass_blocked.load(Ordering::Relaxed)
        );
    }

    /// HA, querylog, and stats-retention families.
    fn render_ha_retention_family(&self, out: &mut String) {
        // 14. sito_ha_slaves_connected
        out.push_str(
            "# HELP sito_ha_slaves_connected Number of HA replica slaves currently connected\n",
        );
        out.push_str("# TYPE sito_ha_slaves_connected gauge\n");
        let _ = writeln!(
            out,
            "sito_ha_slaves_connected {}",
            self.ha_slaves_connected.load(Ordering::Relaxed)
        );

        // 15. sito_ha_config_version
        out.push_str("# HELP sito_ha_config_version Configuration version of HA node instances\n");
        out.push_str("# TYPE sito_ha_config_version gauge\n");
        {
            let map = sito_core::sync::lock_or_recover(&self.ha_config_version);
            if map.is_empty() {
                out.push_str("sito_ha_config_version{instance=\"local\"} 1\n");
            } else {
                for (instance, version) in map.iter() {
                    let _ = writeln!(
                        out,
                        "sito_ha_config_version{{instance=\"{}\"}} {version}",
                        escape_label_value(instance)
                    );
                }
            }
        }

        // 16. sito_ha_diverged
        out.push_str(
            "# HELP sito_ha_diverged Whether the master observed a version-continuity divergence with a slave (1 = diverged)\n",
        );
        out.push_str("# TYPE sito_ha_diverged gauge\n");
        {
            let map = sito_core::sync::lock_or_recover(&self.ha_diverged);
            for (instance, diverged) in map.iter() {
                let _ = writeln!(
                    out,
                    "sito_ha_diverged{{instance=\"{}\"}} {}",
                    escape_label_value(instance),
                    u8::from(*diverged)
                );
            }
        }

        // 17. sito_ha_startup_noop_total
        out.push_str(
            "# HELP sito_ha_startup_noop_total HA startup paths that left replication inactive\n",
        );
        out.push_str("# TYPE sito_ha_startup_noop_total counter\n");
        {
            let map = sito_core::sync::lock_or_recover(&self.ha_startup_noop);
            for ((role, reason), count) in map.iter() {
                let _ = writeln!(
                    out,
                    "sito_ha_startup_noop_total{{role=\"{}\",reason=\"{}\"}} {count}",
                    escape_label_value(role),
                    escape_label_value(reason)
                );
            }
        }

        // 17b. sito_ha_protocol_rejections_total
        {
            let map = sito_core::sync::lock_or_recover(&self.ha_protocol_rejections);
            if !map.is_empty() {
                out.push_str(
                    "# HELP sito_ha_protocol_rejections_total HA peers rejected for an incompatible protocol version\n",
                );
                out.push_str("# TYPE sito_ha_protocol_rejections_total counter\n");
                for ((role, reason), count) in map.iter() {
                    let _ = writeln!(
                        out,
                        "sito_ha_protocol_rejections_total{{role=\"{}\",reason=\"{}\"}} {count}",
                        escape_label_value(role),
                        escape_label_value(reason)
                    );
                }
            }
        }

        // 18. sito_querylog_dropped_total
        out.push_str("# HELP sito_querylog_dropped_total Total query log entries dropped due to buffer overflow\n");
        out.push_str("# TYPE sito_querylog_dropped_total counter\n");
        let _ = writeln!(
            out,
            "sito_querylog_dropped_total {}",
            self.querylog_dropped.load(Ordering::Relaxed)
        );

        // 19. Stats retention / rollup cleanup
        out.push_str("# HELP sito_stats_retention_last_success_seconds Unix timestamp of the last successful stats retention sweep\n");
        out.push_str("# TYPE sito_stats_retention_last_success_seconds gauge\n");
        let _ = writeln!(
            out,
            "sito_stats_retention_last_success_seconds {}",
            self.stats_retention_last_success_seconds
                .load(Ordering::Relaxed)
        );
        out.push_str("# HELP sito_stats_retention_last_failure_seconds Unix timestamp of the last failed stats retention sweep\n");
        out.push_str("# TYPE sito_stats_retention_last_failure_seconds gauge\n");
        let _ = writeln!(
            out,
            "sito_stats_retention_last_failure_seconds {}",
            self.stats_retention_last_failure_seconds
                .load(Ordering::Relaxed)
        );
        out.push_str("# HELP sito_stats_retention_last_duration_millis Duration of the last stats retention sweep\n");
        out.push_str("# TYPE sito_stats_retention_last_duration_millis gauge\n");
        let _ = writeln!(
            out,
            "sito_stats_retention_last_duration_millis {}",
            self.stats_retention_last_duration_millis
                .load(Ordering::Relaxed)
        );
        out.push_str("# HELP sito_stats_retention_deleted_rows_total Detailed query-log rows deleted by retention\n");
        out.push_str("# TYPE sito_stats_retention_deleted_rows_total counter\n");
        let _ = writeln!(
            out,
            "sito_stats_retention_deleted_rows_total {}",
            self.stats_retention_deleted_rows_total
                .load(Ordering::Relaxed)
        );
        out.push_str("# HELP sito_stats_retention_rollup_deleted_rows_total Expired hourly rollup rows deleted by retention\n");
        out.push_str("# TYPE sito_stats_retention_rollup_deleted_rows_total counter\n");
        let _ = writeln!(
            out,
            "sito_stats_retention_rollup_deleted_rows_total {}",
            self.stats_retention_rollup_deleted_rows_total
                .load(Ordering::Relaxed)
        );
        out.push_str("# HELP sito_stats_retention_failures_total Failed stats retention sweeps\n");
        out.push_str("# TYPE sito_stats_retention_failures_total counter\n");
        let _ = writeln!(
            out,
            "sito_stats_retention_failures_total {}",
            self.stats_retention_failures_total.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP sito_stats_rollup_retention_days Configured hourly rollup retention in days\n",
        );
        out.push_str("# TYPE sito_stats_rollup_retention_days gauge\n");
        let _ = writeln!(
            out,
            "sito_stats_rollup_retention_days {}",
            self.stats_rollup_retention_days.load(Ordering::Relaxed)
        );
    }

    /// Build metadata.
    fn render_build_info(&self, out: &mut String) {
        // 20. sito_build_info
        out.push_str("# HELP sito_build_info Build and version metadata\n");
        out.push_str("# TYPE sito_build_info gauge\n");
        let _ = writeln!(
            out,
            "sito_build_info{{version=\"{}\",commit=\"{}\"}} 1",
            escape_label_value(&self.build_version),
            escape_label_value(&self.build_commit)
        );
    }
}

/// Point-in-time copy of the monotonic counters that back window reports.
///
/// Registry counters only ever grow while the process lives, so the difference
/// between two snapshots is a window-scoped measurement; see
/// [`MetricsSnapshot::delta_since`].
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    queries_total: u64,
    blocked_total: u64,
    upstreams: HashMap<String, UpstreamSnapshot>,
}

impl MetricsSnapshot {
    /// Lifetime query total at snapshot time.
    pub fn queries_total(&self) -> u64 {
        self.queries_total
    }

    /// Lifetime blocked-query total at snapshot time.
    pub fn blocked_total(&self) -> u64 {
        self.blocked_total
    }

    /// Per-upstream lifetime accumulators at snapshot time.
    pub fn upstreams(&self) -> &HashMap<String, UpstreamSnapshot> {
        &self.upstreams
    }

    /// Computes the window-scoped difference between `self` (newer) and
    /// `previous` (older).
    ///
    /// A counter that went backwards is treated as reset (process restart or a
    /// replaced registry), and the newer reading is then reported as the whole
    /// window instead of saturating to zero. A reset loses the pre-reset part
    /// of the window, which is the only honest choice without persistent
    /// counters.
    pub fn delta_since(&self, previous: &MetricsSnapshot) -> MetricsDelta {
        let mut upstreams = HashMap::with_capacity(self.upstreams.len());
        for (name, current) in &self.upstreams {
            let prior = previous.upstreams.get(name);
            let (rtt_sum_secs, rtt_count) = match prior {
                Some(p)
                    if current.rtt_count >= p.rtt_count && current.rtt_sum_ns >= p.rtt_sum_ns =>
                {
                    (
                        (current.rtt_sum_ns - p.rtt_sum_ns) as f64 / 1_000_000_000.0,
                        current.rtt_count - p.rtt_count,
                    )
                }
                // Missing or reset accumulator: the current values belong to
                // this window.
                _ => (current.rtt_sum_secs, current.rtt_count),
            };
            let errors = match prior {
                Some(p) => counter_delta(current.errors_total, p.errors_total),
                None => current.errors_total,
            };
            upstreams.insert(
                name.clone(),
                UpstreamDelta {
                    rtt_sum_secs,
                    rtt_count,
                    errors,
                },
            );
        }

        MetricsDelta {
            queries: counter_delta(self.queries_total, previous.queries_total),
            blocked: counter_delta(self.blocked_total, previous.blocked_total),
            upstreams,
        }
    }
}

/// Per-upstream lifetime accumulators captured by [`MetricsRegistry::snapshot`].
#[derive(Debug, Clone, Default)]
pub struct UpstreamSnapshot {
    rtt_sum_secs: f64,
    rtt_sum_ns: u128,
    rtt_count: u64,
    errors_total: u64,
}

impl UpstreamSnapshot {
    /// Sum of every RTT sample in seconds.
    pub fn rtt_sum_secs(&self) -> f64 {
        self.rtt_sum_secs
    }

    /// Number of RTT samples.
    pub fn rtt_count(&self) -> u64 {
        self.rtt_count
    }

    /// Lifetime error total.
    pub fn errors_total(&self) -> u64 {
        self.errors_total
    }
}

/// Window-scoped difference between two [`MetricsSnapshot`]s.
#[derive(Debug, Clone, Default)]
pub struct MetricsDelta {
    /// Queries observed in the window.
    pub queries: u64,
    /// Blocked queries observed in the window.
    pub blocked: u64,
    /// Per-upstream measurements observed in the window.
    pub upstreams: HashMap<String, UpstreamDelta>,
}

/// Window-scoped per-upstream measurements.
#[derive(Debug, Clone, Copy, Default)]
pub struct UpstreamDelta {
    /// Sum of RTT samples observed in the window, in seconds.
    pub rtt_sum_secs: f64,
    /// Number of RTT samples observed in the window.
    pub rtt_count: u64,
    /// Errors observed in the window.
    pub errors: u64,
}

impl UpstreamDelta {
    /// Mean RTT over the window in milliseconds (`0.0` when there is no
    /// sample).
    pub fn mean_rtt_ms(&self) -> f64 {
        if self.rtt_count == 0 {
            0.0
        } else {
            (self.rtt_sum_secs / self.rtt_count as f64) * 1000.0
        }
    }
}

/// Subtracts two monotonic counter readings, treating a decrease as a reset:
/// the newer reading then belongs entirely to the current window.
fn counter_delta(current: u64, previous: u64) -> u64 {
    if current >= previous {
        current - previous
    } else {
        current
    }
}

/// Escapes a Prometheus label value per the exposition format spec.
fn escape_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DNSSEC outcomes and fetch-budget/deadline refusals must be exposed as
    /// stable counter families so an operator can alert on validation failures
    /// separately from upstream stalls.
    #[test]
    fn test_dnssec_validation_and_fetch_failure_metrics_render() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        reg.set_dnssec_validations(7, 3, 2, 1);
        reg.set_dnssec_fetch_failures(5, 4);

        let rendered = reg.render_prometheus();
        // Compare whole lines so a value such as `7` cannot also satisfy a
        // prefix of `70`.
        let assert_line = |line: &str| {
            assert!(
                rendered.lines().any(|rendered_line| rendered_line == line),
                "missing metric line {line:?}:\n{rendered}"
            );
        };
        for (result, value) in [
            ("secure", 7),
            ("insecure", 3),
            ("bogus", 2),
            ("indeterminate", 1),
        ] {
            assert_line(&format!(
                "sito_dnssec_validations_total{{result=\"{result}\"}} {value}"
            ));
        }
        assert_line("sito_dnssec_fetch_failures_total{kind=\"budget\"} 5");
        assert_line("sito_dnssec_fetch_failures_total{kind=\"deadline\"} 4");
    }

    /// P2-62 rationale test: the per-verdict histogram mutex may serialize
    /// same-verdict observations, but it must not lose any of them. Distinct
    /// verdicts use distinct mutexes and remain independent.
    #[test]
    fn test_histogram_concurrent_updates_are_not_lost() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 1_000;

        let reg = std::sync::Arc::new(MetricsRegistry::new("1.0.0", "test"));
        let mut handles = Vec::new();
        for thread in 0..THREADS {
            let reg = std::sync::Arc::clone(&reg);
            handles.push(std::thread::spawn(move || {
                let verdict = if thread % 2 == 0 {
                    "allowed"
                } else {
                    "blocked"
                };
                for _ in 0..PER_THREAD {
                    reg.observe_query_duration(verdict, 0.001);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("histogram writer thread");
        }

        let rendered = reg.render_prometheus();
        for verdict in ["allowed", "blocked"] {
            assert!(
                rendered.contains(&format!(
                    "sito_query_duration_seconds_count{{verdict=\"{verdict}\"}} {}",
                    THREADS / 2 * PER_THREAD
                )),
                "every observation for {verdict} must be retained: {rendered}"
            );
        }
    }

    #[test]
    fn test_metrics_registry_contains_table_14_2() {
        let reg = MetricsRegistry::new("0.1.0", "abc1234");
        reg.inc_queries("udp", 1, "allowed");
        reg.observe_query_duration("allowed", 0.0012);
        reg.observe_upstream_rtt("tls://dns.quad9.net", 0.015);
        reg.inc_upstream_errors("tls://dns.quad9.net", "timeout");
        reg.set_upstream_health("tls://dns.quad9.net", 1.0);
        reg.inc_cache_hits();
        reg.inc_cache_misses();
        reg.set_cache_size_bytes(1024 * 1024);
        reg.inc_cache_stale_served();
        reg.inc_dnssec_bogus("tls://dns.quad9.net");
        reg.set_dnssec_key_cache(7, 3);
        reg.set_dnssec_validations(7, 3, 2, 1);
        reg.set_dnssec_fetch_failures(5, 4);
        reg.inc_clients_identified("ip");
        reg.inc_doh_bypass_blocked();
        reg.set_ha_slaves_connected(2);
        reg.set_ha_config_version("sito-slave-1", 42.0);
        reg.set_ha_diverged("sito-slave-1", true);
        reg.inc_ha_startup_noop("master", "replication_disabled");
        reg.set_querylog_dropped(1);

        let rendered = reg.render_prometheus();

        // Verify all 18 metrics from Table 14.2 are present
        assert!(rendered.contains("sito_queries_total"));
        assert!(rendered.contains("sito_query_duration_seconds"));
        assert!(rendered.contains("sito_upstream_rtt_seconds"));
        assert!(rendered.contains("sito_upstream_errors_total"));
        assert!(rendered.contains("sito_upstream_health"));
        assert!(rendered.contains("sito_cache_hits_total"));
        assert!(rendered.contains("sito_cache_misses_total"));
        assert!(rendered.contains("sito_cache_size_bytes"));
        assert!(rendered.contains("sito_cache_stale_served_total"));
        assert!(rendered.contains("sito_filter_rules"));
        assert!(rendered.contains("sito_filter_compile_seconds"));
        assert!(rendered.contains("sito_dnssec_bogus_total"));
        assert!(rendered.contains("sito_dnssec_key_cache_hits_total 7"));
        assert!(rendered.contains("sito_dnssec_key_cache_misses_total 3"));
        assert!(rendered.contains("sito_dnssec_validations_total{result=\"secure\"} 7"));
        assert!(rendered.contains("sito_dnssec_validations_total{result=\"indeterminate\"} 1"));
        assert!(rendered.contains("sito_dnssec_fetch_failures_total{kind=\"budget\"} 5"));
        assert!(rendered.contains("sito_dnssec_fetch_failures_total{kind=\"deadline\"} 4"));
        assert!(rendered.contains("sito_clients_identified_total"));
        assert!(rendered.contains("sito_doh_bypass_blocked_total"));
        assert!(rendered.contains("sito_ha_slaves_connected"));
        assert!(rendered.contains("sito_ha_config_version"));
        assert!(rendered.contains("sito_ha_diverged"));
        assert!(rendered.contains("sito_ha_startup_noop_total"));
        assert!(rendered.contains("sito_querylog_dropped_total"));
        assert!(rendered.contains("sito_build_info"));
    }

    /// Renders a registry with a fixed sample set and asserts the complete
    /// exposition output. This pins HELP text, TYPE text, sample ordering and
    /// number formatting so the interned-label rewrite cannot change the
    /// Prometheus contract.
    #[test]
    fn test_render_prometheus_golden_output() {
        let reg = MetricsRegistry::new("1.0.0", "abc1234");
        reg.inc_queries("udp", 1, "allowed");
        reg.inc_queries("udp", 28, "blocked");
        reg.inc_queries("tcp", 1, "allowed");
        reg.observe_query_duration("allowed", 0.0012);
        reg.observe_query_duration("blocked", 0.35);
        reg.observe_upstream_rtt("tls://dns.quad9.net", 0.015);
        reg.inc_upstream_errors("tls://dns.quad9.net", "timeout");
        reg.set_upstream_health("tls://dns.quad9.net", 1.0);
        reg.inc_cache_hits();
        reg.inc_cache_misses();
        reg.set_cache_size_bytes(1024 * 1024);
        reg.inc_cache_stale_served();
        reg.inc_dnssec_bogus("tls://dns.quad9.net");
        reg.set_dnssec_key_cache(7, 3);
        reg.set_dnssec_validations(7, 3, 2, 1);
        reg.set_dnssec_fetch_failures(5, 4);
        reg.inc_clients_identified("ip");
        reg.inc_doh_bypass_blocked();
        reg.set_ha_slaves_connected(2);
        reg.set_ha_config_version("sito-slave-1", 42.0);
        reg.set_ha_diverged("sito-slave-1", true);
        reg.inc_ha_startup_noop("master", "replication_disabled");
        reg.set_querylog_dropped(1);
        reg.set_filter_status(FilterStatusMetrics {
            state: 2,
            rule_count: None,
            loaded_lists: 3,
            failed_lists: 1,
            degraded_groups: 1,
            dropped_regex_patterns: 5,
            unavailable: 1,
        });

        let rendered = reg.render_prometheus();
        let expected = r#"# HELP sito_queries_total Total DNS queries processed
# TYPE sito_queries_total counter
sito_queries_total{proto="tcp",qtype="1",verdict="allowed"} 1
sito_queries_total{proto="udp",qtype="1",verdict="allowed"} 1
sito_queries_total{proto="udp",qtype="28",verdict="blocked"} 1
# HELP sito_transport_queries_total Total DNS queries by transport
# TYPE sito_transport_queries_total counter
sito_transport_queries_total{proto="tcp"} 1
sito_transport_queries_total{proto="udp"} 2
# HELP sito_query_duration_seconds Histogram of query duration in seconds
# TYPE sito_query_duration_seconds histogram
sito_query_duration_seconds_bucket{verdict="allowed",le="0.00025"} 0
sito_query_duration_seconds_bucket{verdict="allowed",le="0.0005"} 0
sito_query_duration_seconds_bucket{verdict="allowed",le="0.001"} 0
sito_query_duration_seconds_bucket{verdict="allowed",le="0.0025"} 1
sito_query_duration_seconds_bucket{verdict="allowed",le="0.005"} 1
sito_query_duration_seconds_bucket{verdict="allowed",le="0.01"} 1
sito_query_duration_seconds_bucket{verdict="allowed",le="0.025"} 1
sito_query_duration_seconds_bucket{verdict="allowed",le="0.05"} 1
sito_query_duration_seconds_bucket{verdict="allowed",le="0.1"} 1
sito_query_duration_seconds_bucket{verdict="allowed",le="0.25"} 1
sito_query_duration_seconds_bucket{verdict="allowed",le="0.5"} 1
sito_query_duration_seconds_bucket{verdict="allowed",le="1"} 1
sito_query_duration_seconds_bucket{verdict="allowed",le="2.5"} 1
sito_query_duration_seconds_bucket{verdict="allowed",le="5"} 1
sito_query_duration_seconds_bucket{verdict="allowed",le="+Inf"} 1
sito_query_duration_seconds_sum{verdict="allowed"} 0.0012
sito_query_duration_seconds_count{verdict="allowed"} 1
sito_query_duration_seconds_bucket{verdict="blocked",le="0.00025"} 0
sito_query_duration_seconds_bucket{verdict="blocked",le="0.0005"} 0
sito_query_duration_seconds_bucket{verdict="blocked",le="0.001"} 0
sito_query_duration_seconds_bucket{verdict="blocked",le="0.0025"} 0
sito_query_duration_seconds_bucket{verdict="blocked",le="0.005"} 0
sito_query_duration_seconds_bucket{verdict="blocked",le="0.01"} 0
sito_query_duration_seconds_bucket{verdict="blocked",le="0.025"} 0
sito_query_duration_seconds_bucket{verdict="blocked",le="0.05"} 0
sito_query_duration_seconds_bucket{verdict="blocked",le="0.1"} 0
sito_query_duration_seconds_bucket{verdict="blocked",le="0.25"} 0
sito_query_duration_seconds_bucket{verdict="blocked",le="0.5"} 1
sito_query_duration_seconds_bucket{verdict="blocked",le="1"} 1
sito_query_duration_seconds_bucket{verdict="blocked",le="2.5"} 1
sito_query_duration_seconds_bucket{verdict="blocked",le="5"} 1
sito_query_duration_seconds_bucket{verdict="blocked",le="+Inf"} 1
sito_query_duration_seconds_sum{verdict="blocked"} 0.35
sito_query_duration_seconds_count{verdict="blocked"} 1
# HELP sito_dns_acl_decisions_total DNS client ACL admission decisions
# TYPE sito_dns_acl_decisions_total counter
sito_dns_acl_decisions_total{action="allow",reason="default_policy",family="ipv4"} 0
# HELP sito_dns_acl_matched_prefix_total DNS client ACL decisions by canonical matched prefix
# TYPE sito_dns_acl_matched_prefix_total counter
sito_dns_acl_matched_prefix_total{action="allow",prefix="__none__",family="ipv4"} 0
# HELP sito_dns_acl_dropped_total DNS queries denied and silently dropped by the client ACL
# TYPE sito_dns_acl_dropped_total counter
sito_dns_acl_dropped_total{family="ipv4"} 0
sito_dns_acl_dropped_total{family="ipv6"} 0
# HELP sito_upstream_rtt_seconds Upstream round-trip time in seconds
# TYPE sito_upstream_rtt_seconds histogram
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="0.00025"} 0
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="0.0005"} 0
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="0.001"} 0
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="0.0025"} 0
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="0.005"} 0
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="0.01"} 0
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="0.025"} 1
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="0.05"} 1
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="0.1"} 1
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="0.25"} 1
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="0.5"} 1
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="1"} 1
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="2.5"} 1
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="5"} 1
sito_upstream_rtt_seconds_bucket{upstream="tls://dns.quad9.net",le="+Inf"} 1
sito_upstream_rtt_seconds_sum{upstream="tls://dns.quad9.net"} 0.015
sito_upstream_rtt_seconds_count{upstream="tls://dns.quad9.net"} 1
# HELP sito_upstream_errors_total Total errors encountered per upstream
# TYPE sito_upstream_errors_total counter
sito_upstream_errors_total{upstream="tls://dns.quad9.net",kind="timeout"} 1
# HELP sito_upstream_health Upstream resolver health status (1 = healthy, 0 = degraded/down)
# TYPE sito_upstream_health gauge
sito_upstream_health{upstream="tls://dns.quad9.net"} 1
# HELP sito_cache_hits_total Total DNS cache hits
# TYPE sito_cache_hits_total counter
sito_cache_hits_total 1
# HELP sito_cache_misses_total Total DNS cache misses
# TYPE sito_cache_misses_total counter
sito_cache_misses_total 1
# HELP sito_dnssec_key_cache_hits_total DNSSEC validated-key cache hits
# TYPE sito_dnssec_key_cache_hits_total counter
sito_dnssec_key_cache_hits_total 7
# HELP sito_dnssec_key_cache_misses_total DNSSEC validated-key cache misses
# TYPE sito_dnssec_key_cache_misses_total counter
sito_dnssec_key_cache_misses_total 3
# HELP sito_cache_size_bytes Current memory size of cache in bytes
# TYPE sito_cache_size_bytes gauge
sito_cache_size_bytes 1048576
# HELP sito_cache_stale_served_total Total stale cache answers served
# TYPE sito_cache_stale_served_total counter
sito_cache_stale_served_total 1
# HELP sito_filter_rules Number of active filter rules per list
# TYPE sito_filter_rules gauge
sito_filter_rules{list="total"} 0
# HELP sito_filter_state Filter engine lifecycle (0 disabled, 1 loading, 2 ready, 3 failed)
# TYPE sito_filter_state gauge
sito_filter_state 2
# HELP sito_filter_lists_loaded Configured filter lists loaded in the last reload
# TYPE sito_filter_lists_loaded gauge
sito_filter_lists_loaded 3
# HELP sito_filter_lists_failed Configured filter lists that failed in the last reload
# TYPE sito_filter_lists_failed gauge
sito_filter_lists_failed 1
# HELP sito_filter_degraded_groups Groups with degraded or unpublishable rules (budget/limit, missing list, invalid-only)
# TYPE sito_filter_degraded_groups gauge
sito_filter_degraded_groups 1
# HELP sito_filter_dropped_regex_patterns Regex/wildcard patterns dropped from the active snapshot
# TYPE sito_filter_dropped_regex_patterns gauge
sito_filter_dropped_regex_patterns 5
# HELP sito_filter_unavailable No usable filter snapshot is active (1 = unavailable; fail_closed answers SERVFAIL)
# TYPE sito_filter_unavailable gauge
sito_filter_unavailable 1
# HELP sito_filter_compile_seconds Compilation duration for filter rule trie
# TYPE sito_filter_compile_seconds histogram
sito_filter_compile_seconds_bucket{le="0.00025"} 0
sito_filter_compile_seconds_bucket{le="0.0005"} 0
sito_filter_compile_seconds_bucket{le="0.001"} 0
sito_filter_compile_seconds_bucket{le="0.0025"} 0
sito_filter_compile_seconds_bucket{le="0.005"} 0
sito_filter_compile_seconds_bucket{le="0.01"} 0
sito_filter_compile_seconds_bucket{le="0.025"} 0
sito_filter_compile_seconds_bucket{le="0.05"} 0
sito_filter_compile_seconds_bucket{le="0.1"} 0
sito_filter_compile_seconds_bucket{le="0.25"} 0
sito_filter_compile_seconds_bucket{le="0.5"} 0
sito_filter_compile_seconds_bucket{le="1"} 0
sito_filter_compile_seconds_bucket{le="2.5"} 0
sito_filter_compile_seconds_bucket{le="5"} 0
sito_filter_compile_seconds_bucket{le="+Inf"} 0
sito_filter_compile_seconds_sum 0
sito_filter_compile_seconds_count 0
# HELP sito_dnssec_validations_total Total DNSSEC validation outcomes (NTA bypasses excluded)
# TYPE sito_dnssec_validations_total counter
sito_dnssec_validations_total{result="secure"} 7
sito_dnssec_validations_total{result="insecure"} 3
sito_dnssec_validations_total{result="bogus"} 2
sito_dnssec_validations_total{result="indeterminate"} 1
# HELP sito_dnssec_bogus_total Total DNSSEC bogus responses detected
# TYPE sito_dnssec_bogus_total counter
sito_dnssec_bogus_total{upstream="tls://dns.quad9.net"} 1
# HELP sito_dnssec_fetch_failures_total Total DNSSEC key fetches refused by budget or deadline
# TYPE sito_dnssec_fetch_failures_total counter
sito_dnssec_fetch_failures_total{kind="budget"} 5
sito_dnssec_fetch_failures_total{kind="deadline"} 4
# HELP sito_clients_identified_total Total clients successfully identified by method
# TYPE sito_clients_identified_total counter
sito_clients_identified_total{method="ip"} 1
# HELP sito_doh_bypass_blocked_total Total encrypted DNS bypass attempts blocked
# TYPE sito_doh_bypass_blocked_total counter
sito_doh_bypass_blocked_total 1
# HELP sito_ha_slaves_connected Number of HA replica slaves currently connected
# TYPE sito_ha_slaves_connected gauge
sito_ha_slaves_connected 2
# HELP sito_ha_config_version Configuration version of HA node instances
# TYPE sito_ha_config_version gauge
sito_ha_config_version{instance="sito-slave-1"} 42
# HELP sito_ha_diverged Whether the master observed a version-continuity divergence with a slave (1 = diverged)
# TYPE sito_ha_diverged gauge
sito_ha_diverged{instance="sito-slave-1"} 1
# HELP sito_ha_startup_noop_total HA startup paths that left replication inactive
# TYPE sito_ha_startup_noop_total counter
sito_ha_startup_noop_total{role="master",reason="replication_disabled"} 1
# HELP sito_querylog_dropped_total Total query log entries dropped due to buffer overflow
# TYPE sito_querylog_dropped_total counter
sito_querylog_dropped_total 1
# HELP sito_stats_retention_last_success_seconds Unix timestamp of the last successful stats retention sweep
# TYPE sito_stats_retention_last_success_seconds gauge
sito_stats_retention_last_success_seconds 0
# HELP sito_stats_retention_last_failure_seconds Unix timestamp of the last failed stats retention sweep
# TYPE sito_stats_retention_last_failure_seconds gauge
sito_stats_retention_last_failure_seconds 0
# HELP sito_stats_retention_last_duration_millis Duration of the last stats retention sweep
# TYPE sito_stats_retention_last_duration_millis gauge
sito_stats_retention_last_duration_millis 0
# HELP sito_stats_retention_deleted_rows_total Detailed query-log rows deleted by retention
# TYPE sito_stats_retention_deleted_rows_total counter
sito_stats_retention_deleted_rows_total 0
# HELP sito_stats_retention_rollup_deleted_rows_total Expired hourly rollup rows deleted by retention
# TYPE sito_stats_retention_rollup_deleted_rows_total counter
sito_stats_retention_rollup_deleted_rows_total 0
# HELP sito_stats_retention_failures_total Failed stats retention sweeps
# TYPE sito_stats_retention_failures_total counter
sito_stats_retention_failures_total 0
# HELP sito_stats_rollup_retention_days Configured hourly rollup retention in days
# TYPE sito_stats_rollup_retention_days gauge
sito_stats_rollup_retention_days 0
# HELP sito_build_info Build and version metadata
# TYPE sito_build_info gauge
sito_build_info{version="1.0.0",commit="abc1234"} 1
"#;
        assert_eq!(rendered, expected);
    }

    #[test]
    fn test_ha_config_version_label_escaping_and_removal() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        let hostile = "evil\"}\ninjected";
        reg.set_ha_config_version(hostile, 3.0);

        let rendered = reg.render_prometheus();
        assert!(rendered.contains(r#"instance="evil\"}\ninjected""#));
        assert!(!rendered.contains("\ninjected"));

        reg.remove_ha_config_version(hostile);
        let rendered_after = reg.render_prometheus();
        assert!(!rendered_after.contains("evil"));
    }

    #[test]
    fn test_ha_protocol_rejection_counter_renders_only_when_used() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        assert!(
            !reg.render_prometheus()
                .contains("sito_ha_protocol_rejections_total"),
            "an unused rejection counter must not churn the scrape output"
        );

        reg.inc_ha_protocol_rejection("master", "version_mismatch");
        reg.inc_ha_protocol_rejection("master", "version_mismatch");
        reg.inc_ha_protocol_rejection("slave", "version_mismatch");
        let rendered = reg.render_prometheus();
        assert!(rendered.contains(
            r#"sito_ha_protocol_rejections_total{role="master",reason="version_mismatch"} 2"#
        ));
        assert!(rendered.contains(
            r#"sito_ha_protocol_rejections_total{role="slave",reason="version_mismatch"} 1"#
        ));
    }

    #[test]
    fn test_ha_diverged_gauge_transitions_and_removal() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        assert!(
            !reg.render_prometheus()
                .contains(r#"sito_ha_diverged{instance="slave-1"}"#),
            "no divergence series is rendered before a divergence is observed"
        );

        reg.set_ha_diverged("slave-1", true);
        let rendered = reg.render_prometheus();
        assert!(rendered.contains(r#"sito_ha_diverged{instance="slave-1"} 1"#));

        reg.set_ha_diverged("slave-1", false);
        let rendered = reg.render_prometheus();
        assert!(rendered.contains(r#"sito_ha_diverged{instance="slave-1"} 0"#));

        reg.remove_ha_diverged("slave-1");
        assert!(
            !reg.render_prometheus()
                .contains(r#"sito_ha_diverged{instance="slave-1"}"#),
            "the series must be removed on disconnect"
        );
    }

    #[test]
    fn test_ha_startup_noop_counter_is_keyed_by_role_and_reason() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        reg.inc_ha_startup_noop("master", "replication_disabled");
        reg.inc_ha_startup_noop("master", "replication_disabled");
        reg.inc_ha_startup_noop("slave", "missing_master_url");

        let rendered = reg.render_prometheus();
        assert!(rendered.contains(
            r#"sito_ha_startup_noop_total{role="master",reason="replication_disabled"} 2"#
        ));
        assert!(
            rendered.contains(
                r#"sito_ha_startup_noop_total{role="slave",reason="missing_master_url"} 1"#
            )
        );
    }

    #[test]
    fn test_ha_diverged_label_escaping_and_removal() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        let hostile = "evil\"}\ninjected";
        reg.set_ha_diverged(hostile, true);

        let rendered = reg.render_prometheus();
        assert!(rendered.contains(r#"instance="evil\"}\ninjected""#));
        assert!(!rendered.contains("\ninjected"));

        reg.remove_ha_diverged(hostile);
        assert!(!reg.render_prometheus().contains("evil"));
    }

    #[test]
    fn test_all_label_values_are_escaped() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        let hostile = "a\"b\\c\nd";
        reg.inc_queries(hostile, 1, hostile);
        reg.observe_query_duration(hostile, 0.001);
        reg.observe_upstream_rtt(hostile, 0.001);
        reg.inc_upstream_errors(hostile, hostile);
        reg.set_upstream_health(hostile, 0.5);
        reg.inc_clients_identified(hostile);

        let rendered = reg.render_prometheus();
        let escaped = r#"a\"b\\c\nd"#;
        assert!(rendered.contains(&format!("proto=\"{escaped}\"")));
        assert!(rendered.contains(&format!("verdict=\"{escaped}\"")));
        assert!(rendered.contains(&format!("upstream=\"{escaped}\"")));
        assert!(rendered.contains(&format!("kind=\"{escaped}\"")));
        assert!(rendered.contains(&format!("method=\"{escaped}\"")));
        // The raw (unescaped) label value must never appear in the exposition.
        assert!(!rendered.contains("a\"b\\c\nd"));
    }

    #[test]
    fn test_label_interner_caps_cardinality() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        for i in 0..(MAX_INTERNER_LABELS + 100) {
            reg.inc_upstream_errors(&format!("bounded-{i}"), "io");
            reg.set_upstream_health(&format!("bounded-{i}"), 0.0);
        }
        let labels = reg
            .labels
            .state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .labels
            .len();
        assert!(
            labels <= MAX_INTERNER_LABELS + 1,
            "interner must collapse values after the cap (got {labels})"
        );
        let rendered = reg.render_prometheus();
        assert!(
            rendered.contains(r#"upstream="__other__""#),
            "overflow label must be used once the cap is reached"
        );
        assert!(
            rendered.contains(r#"sito_upstream_health{upstream="__other__"} 0"#),
            "health gauges must share the same bounded label set: {rendered}"
        );
    }

    /// WP-7.1 regression: the client-controlled 16-bit `qtype` must not create
    /// an unbounded number of `sito_queries_total` series. Common types keep
    /// exact labels; everything else collapses into `qtype="__other__"`.
    #[test]
    fn test_queries_total_qtype_cardinality_is_bounded() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        let flood: u32 = 50_000;
        for qtype in 0..flood {
            reg.inc_queries("udp", qtype as u16, "allowed");
        }
        // Common types still get their own exact series.
        reg.inc_queries("udp", 1, "allowed");
        reg.inc_queries("udp", 28, "allowed");

        let series = reg
            .queries_total
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        assert!(
            series <= KNOWN_QTYPES.len() + 1,
            "qtype flood must collapse into the known set plus __other__ (got {series})"
        );

        // No observation is lost: the bounded series still account for every
        // increment.
        let total: u64 = reg
            .queries_total
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(|count| count.load(Ordering::Relaxed))
            .sum();
        assert_eq!(total, u64::from(flood) + 2);

        let rendered = reg.render_prometheus();
        assert!(rendered.contains(r#"qtype="__other__""#));
        assert!(rendered.contains(r#"qtype="1""#));
        assert!(rendered.contains(r#"qtype="28""#));
        // Raw wire values outside the known set are never exposed.
        assert!(!rendered.contains(r#"qtype="40000""#));
    }

    /// WP-2.7: removing an upstream prunes its health gauge, RTT histogram and
    /// every error-kind series, while other upstreams are untouched.
    #[test]
    fn test_removed_upstream_health_series_is_pruned() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        for name in ["removed.example", "kept.example"] {
            reg.observe_upstream_rtt(name, 0.010);
            reg.inc_upstream_errors(name, "timeout");
            reg.set_upstream_health(name, 0.0);
        }

        reg.remove_upstream_health("removed.example");
        // Removing an unknown name must be a no-op, not a panic or a new label.
        reg.remove_upstream_health("never-seen.example");

        let rendered = reg.render_prometheus();
        assert!(
            !rendered.contains("removed.example"),
            "all removed upstream series must be pruned: {rendered}"
        );
        assert!(
            !rendered.contains("never-seen.example"),
            "the removal helper must not intern unknown names: {rendered}"
        );
        for family in [
            "sito_upstream_health{upstream=\"kept.example\"}",
            "sito_upstream_errors_total{upstream=\"kept.example\",kind=\"timeout\"}",
            "sito_upstream_rtt_seconds_count{upstream=\"kept.example\"}",
        ] {
            assert!(
                rendered.contains(family),
                "unrelated upstream series must survive: missing {family}: {rendered}"
            );
        }
    }

    #[test]
    fn test_filter_metrics_are_reported() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        reg.set_filter_rules(42);
        reg.observe_filter_compile(0.25);
        let rendered = reg.render_prometheus();
        assert!(rendered.contains("sito_filter_rules{list=\"total\"} 42"));
        assert!(rendered.contains("sito_filter_compile_seconds_count 1"));
        assert!(rendered.contains("sito_filter_compile_seconds_sum 0.25"));
        assert!(
            rendered.contains("sito_filter_unavailable 0"),
            "the unavailable gauge must be exposed even when healthy"
        );
    }

    /// Regression for audit WP-7.3: [`MetricsSnapshot::delta_since`] must
    /// return window-scoped differences from lifetime counters, including
    /// upstream RTT (sum + samples) and error totals, and must treat a
    /// counter going backwards as a reset instead of saturating to zero.
    #[test]
    fn test_snapshot_delta_is_window_scoped_and_reset_safe() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        reg.inc_queries("udp", 1, "allowed");
        reg.inc_queries("udp", 28, "blocked");
        reg.observe_upstream_rtt("8.8.8.8:53", 0.020);
        reg.observe_upstream_rtt("8.8.8.8:53", 0.030);
        reg.inc_upstream_errors("8.8.8.8:53", "timeout");
        let previous = reg.snapshot();
        assert_eq!(previous.queries_total(), 2);
        assert_eq!(previous.blocked_total(), 1);

        // No new activity: the delta is zero even though lifetime totals are
        // non-zero.
        let delta = reg.snapshot().delta_since(&previous);
        assert_eq!(delta.queries, 0);
        assert_eq!(delta.blocked, 0);
        let upstream = &delta.upstreams["8.8.8.8:53"];
        assert_eq!(upstream.rtt_count, 0);
        assert_eq!(upstream.errors, 0);
        assert!(upstream.mean_rtt_ms().abs() < f64::EPSILON);

        // New activity is measured from the previous snapshot only: the mean
        // must exclude the two pre-window RTT samples.
        reg.inc_queries("udp", 28, "allowed");
        reg.observe_upstream_rtt("8.8.8.8:53", 0.040);
        reg.inc_upstream_errors("8.8.8.8:53", "network");
        let delta = reg.snapshot().delta_since(&previous);
        assert_eq!(delta.queries, 1);
        assert_eq!(delta.blocked, 0);
        let upstream = &delta.upstreams["8.8.8.8:53"];
        assert_eq!(upstream.rtt_count, 1);
        assert!((upstream.mean_rtt_ms() - 40.0).abs() < 1e-6);
        assert_eq!(upstream.errors, 1);

        // A replaced registry (process restart / metrics swap) restarts the
        // counters; the newer reading is the whole window, not zero.
        let reset = MetricsRegistry::new("1.0.0", "test");
        reset.inc_queries("udp", 1, "allowed");
        reset.observe_upstream_rtt("8.8.8.8:53", 0.005);
        let delta = reset.snapshot().delta_since(&previous);
        assert_eq!(delta.queries, 1);
        assert_eq!(delta.blocked, 0);
        let upstream = &delta.upstreams["8.8.8.8:53"];
        assert_eq!(upstream.rtt_count, 1);
        assert_eq!(upstream.errors, 0);
        assert!((upstream.mean_rtt_ms() - 5.0).abs() < 1e-6);
    }
}

#[cfg(test)]
mod allocation_tests {
    use super::{FilterStatusMetrics, MAX_DNSSEC_BOGUS_UPSTREAMS, MetricsRegistry};
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
    }

    /// Allocator that counts allocations per thread so the hot-path test can
    /// assert that repeated metrics updates allocate nothing.
    struct CountingAllocator;

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOCATIONS.with(|count| count.set(count.get() + 1));
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            ALLOCATIONS.with(|count| count.set(count.get() + 1));
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            ALLOCATIONS.with(|count| count.set(count.get() + 1));
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    fn allocations() -> u64 {
        ALLOCATIONS.with(Cell::get)
    }

    /// Regression test for the WP-17 hot-path finding: after labels are
    /// interned and counters exist, a query observation must not allocate or
    /// format strings.
    #[test]
    fn test_metrics_hot_path_does_not_allocate() {
        let reg = MetricsRegistry::new("1.0.0", "test");

        // Warm up: intern labels, create counters and histograms.
        for _ in 0..4 {
            reg.inc_queries("udp", 1, "allowed");
            reg.observe_query_duration("allowed", 0.001);
            reg.observe_upstream_rtt("tls://dns.quad9.net", 0.002);
            reg.inc_upstream_errors("tls://dns.quad9.net", "timeout");
            reg.set_upstream_health("tls://dns.quad9.net", 1.0);
            reg.inc_clients_identified("ip");
        }

        let before = allocations();
        for _ in 0..1000 {
            reg.inc_queries("udp", 1, "allowed");
            reg.observe_query_duration("allowed", 0.001);
            reg.observe_upstream_rtt("tls://dns.quad9.net", 0.002);
            reg.inc_upstream_errors("tls://dns.quad9.net", "timeout");
            reg.set_upstream_health("tls://dns.quad9.net", 1.0);
            reg.inc_clients_identified("ip");
        }
        let after = allocations();

        assert_eq!(
            after, before,
            "metrics hot path must not allocate after warm-up"
        );
    }

    #[test]
    fn test_retention_metrics_record_success_and_failure() {
        use std::sync::atomic::Ordering;
        let reg = MetricsRegistry::new("1.0.0", "test");
        reg.set_rollup_retention_days(365);
        reg.record_retention_success(1_234, 10, 2, 365);

        let rendered = reg.render_prometheus();
        assert!(rendered.contains("sito_stats_retention_last_duration_millis 1234"));
        assert!(rendered.contains("sito_stats_retention_deleted_rows_total 10"));
        assert!(rendered.contains("sito_stats_retention_rollup_deleted_rows_total 2"));
        assert!(rendered.contains("sito_stats_rollup_retention_days 365"));
        assert!(
            reg.stats_retention_last_success_seconds
                .load(Ordering::Relaxed)
                > 0
        );
        assert_eq!(
            reg.stats_retention_failures_total.load(Ordering::Relaxed),
            0
        );

        reg.record_retention_failure(99);
        let rendered = reg.render_prometheus();
        assert!(rendered.contains("sito_stats_retention_failures_total 1"));
        assert!(rendered.contains("sito_stats_retention_last_duration_millis 99"));
        assert!(
            reg.stats_retention_last_failure_seconds
                .load(Ordering::Relaxed)
                > 0
        );
    }

    /// P2-63: removing an upstream from the config must also drop its
    /// `sito_dnssec_bogus_total` series, which uses its own string-keyed map.
    #[test]
    fn test_remove_upstream_health_prunes_dnssec_bogus_series() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        reg.inc_dnssec_bogus("gone.example:53");
        reg.inc_dnssec_bogus("kept.example:53");
        reg.set_upstream_health("gone.example:53", 0.0);
        reg.set_upstream_health("kept.example:53", 1.0);

        reg.remove_upstream_health("gone.example:53");

        let rendered = reg.render_prometheus();
        assert!(
            !rendered.contains(r#"sito_dnssec_bogus_total{upstream="gone.example:53"}"#),
            "a removed upstream must not keep a bogus series: {rendered}"
        );
        assert!(
            !rendered.contains(r#"sito_upstream_health{upstream="gone.example:53"}"#),
            "the health gauge is pruned too: {rendered}"
        );
        assert!(
            rendered.contains(r#"sito_dnssec_bogus_total{upstream="kept.example:53"} 1"#),
            "unrelated bogus series must survive: {rendered}"
        );
    }

    /// P2-63: the standalone bogus map is capped and overflow is collapsed
    /// into a constant label without losing observations.
    #[test]
    fn test_dnssec_bogus_cardinality_is_capped() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        let overflow = 20usize;
        for i in 0..(MAX_DNSSEC_BOGUS_UPSTREAMS + overflow) {
            reg.inc_dnssec_bogus(&format!("bogus-upstream-{i}:53"));
        }

        let rendered = reg.render_prometheus();
        let lines: Vec<&str> = rendered
            .lines()
            .filter(|line| line.starts_with("sito_dnssec_bogus_total{"))
            .collect();
        assert_eq!(
            lines.len(),
            MAX_DNSSEC_BOGUS_UPSTREAMS + 1,
            "the map must keep at most the cap plus the overflow series: {rendered}"
        );
        assert!(
            rendered.contains(r#"sito_dnssec_bogus_total{upstream="__other__"} 20"#),
            "surplus labels must collapse into the constant overflow label: {rendered}"
        );
        let total: u64 = lines
            .iter()
            .map(|line| line.rsplit_once(' ').unwrap().1.parse::<u64>().unwrap())
            .sum();
        assert_eq!(
            total,
            (MAX_DNSSEC_BOGUS_UPSTREAMS + overflow) as u64,
            "collapsing must not lose bogus observations: {rendered}"
        );
    }

    /// P2-63: the status observer carries the compiled rule count so a
    /// scheduled refresh cannot leave `sito_filter_rules` stale.
    #[test]
    fn test_filter_status_updates_rule_gauge() {
        let reg = MetricsRegistry::new("1.0.0", "test");
        reg.set_filter_status(FilterStatusMetrics {
            state: 2,
            rule_count: Some(42),
            ..Default::default()
        });
        assert!(
            reg.render_prometheus()
                .contains(r#"sito_filter_rules{list="total"} 42"#),
            "the status publication must update the rule gauge"
        );

        // A status without a rule count must leave the previous value alone.
        reg.set_filter_status(FilterStatusMetrics {
            state: 2,
            rule_count: None,
            ..Default::default()
        });
        assert!(
            reg.render_prometheus()
                .contains(r#"sito_filter_rules{list="total"} 42"#),
            "a partial status must not reset the rule gauge to zero"
        );
    }

    #[test]
    fn test_acl_metrics_are_bounded_and_private() {
        let reg = MetricsRegistry::new("2.0.0", "test");
        reg.inc_acl_decision("allow", "explicit_allow", "ipv4");
        reg.inc_acl_decision("deny", "explicit_deny", "ipv4");
        reg.inc_acl_decision("deny", "default_policy", "ipv6");
        reg.inc_acl_matched_prefix("allow", "192.168.1.0/24", "ipv4");
        reg.inc_acl_matched_prefix("deny", "192.168.1.128/25", "ipv4");
        reg.inc_acl_dropped("ipv4");
        reg.inc_acl_dropped("ipv6");

        let text = reg.render_prometheus();
        assert!(text.contains(
            r#"sito_dns_acl_decisions_total{action="deny",reason="explicit_deny",family="ipv4"} 1"#
        ));
        assert!(text.contains(
            r#"sito_dns_acl_decisions_total{action="deny",reason="default_policy",family="ipv6"} 1"#
        ));
        assert!(text.contains(
            r#"sito_dns_acl_matched_prefix_total{action="allow",prefix="192.168.1.0/24",family="ipv4"} 1"#
        ));
        assert!(text.contains(r#"sito_dns_acl_dropped_total{family="ipv4"} 1"#));
        assert!(text.contains(r#"sito_dns_acl_dropped_total{family="ipv6"} 1"#));
        // No client address or query name is ever a label.
        assert!(!text.contains("198.51.100."), "no client IP labels: {text}");
        assert!(!text.contains("example.com"), "no qname labels: {text}");

        // Entry-derived prefixes beyond the exporter cap collapse, so scrape
        // size is bounded regardless of the number of configured entry ids.
        for octet in 0..300u16 {
            let prefix = format!("10.{}.{}.0/24", octet / 256, octet % 256);
            reg.inc_acl_matched_prefix("allow", &prefix, "ipv4");
        }
        let text = reg.render_prometheus();
        assert!(
            text.contains(r#"sito_dns_acl_matched_prefix_total{action="allow",prefix="__other__",family="ipv4"}"#),
            "overflow prefixes must collapse into __other__: {text}"
        );
        let distinct: std::collections::HashSet<&str> = text
            .lines()
            .filter(|line| line.starts_with("sito_dns_acl_matched_prefix_total{"))
            .filter_map(|line| line.split("prefix=\"").nth(1))
            .filter_map(|rest| rest.split('"').next())
            .collect();
        assert!(
            distinct.len() <= 257,
            "matched-prefix series must stay bounded: {}",
            distinct.len()
        );
    }
}
