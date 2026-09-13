//! Prometheus metrics registry per section 14.2.
//!
//! Exposes all required metrics with cardinality bounds to prevent time-series explosion.
//!
//! Hot-path metrics inter their label values (`proto`, `verdict`, `upstream`,
//! `method`, ...) into dense integer ids once and keep the counters in
//! `RwLock` maps of atomics, so a per-query observation performs no `String`
//! allocation and never takes a global exclusive lock. Rendering is the only
//! place that materializes label strings and it sorts them, keeping the
//! exposition output byte-for-byte equivalent to the previous `BTreeMap`
//! implementation.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

/// Standard latency buckets for DNS query duration and upstream RTT (in seconds).
const LATENCY_BUCKETS: &[f64] = &[
    0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

#[derive(Debug)]
struct HistogramState {
    counts: Vec<u64>,
    sum: f64,
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
            count: 0,
        }
    }

    fn observe(&mut self, val: f64) {
        self.count += 1;
        self.sum += val;
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
/// Map of interned-label histograms; only the first observation for a label
/// allocates and takes the outer write lock.
type HistogramMap = RwLock<HashMap<u32, Arc<Mutex<HistogramState>>>>;

#[derive(Default)]
struct InternerState {
    ids: HashMap<Arc<str>, u32>,
    labels: Vec<Arc<str>>,
}

/// Interns metric label values into dense integer ids.
///
/// Lookups take a shared `RwLock` read guard and allocate nothing; an id is
/// only assigned (and a `String` only allocated) when a label value is seen for
/// the first time. This keeps the DNS hot path free of per-query `format!` /
/// `to_string()` calls.
#[derive(Default)]
struct LabelInterner {
    state: RwLock<InternerState>,
}

impl LabelInterner {
    fn intern(&self, value: &str) -> u32 {
        if let Ok(state) = self.state.read()
            && let Some(&id) = state.ids.get(value)
        {
            return id;
        }

        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
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
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .labels
            .get(id as usize)
            .cloned()
            .unwrap_or_else(|| Arc::from(""))
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

    let mut guard = map.write().unwrap_or_else(PoisonError::into_inner);
    guard
        .entry(key)
        .or_insert_with(|| Arc::new(AtomicU64::new(0)))
        .fetch_add(1, Ordering::Relaxed);
}

/// Observes `value` in the histogram for interned label id `id`.
fn observe_histogram(map: &HistogramMap, id: u32, value: f64) {
    let histogram = {
        if let Ok(guard) = map.read()
            && let Some(histogram) = guard.get(&id)
        {
            Arc::clone(histogram)
        } else {
            let mut guard = map.write().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(
                guard
                    .entry(id)
                    .or_insert_with(|| Arc::new(Mutex::new(HistogramState::new()))),
            )
        }
    };
    histogram
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .observe(value);
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
    cache_stale_served: Arc<AtomicU64>,
    dnssec_bogus: Arc<Mutex<BTreeMap<String, u64>>>,
    clients_identified: Arc<CounterMap<u32>>,
    doh_bypass_blocked: Arc<AtomicU64>,
    /// proto id -> count
    transport_queries_total: Arc<CounterMap<u32>>,
    ha_slaves_connected: Arc<AtomicI64>,
    ha_config_version: Arc<Mutex<BTreeMap<String, f64>>>,
    querylog_dropped: Arc<AtomicU64>,
    build_version: String,
    build_commit: String,
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
            cache_stale_served: Arc::new(AtomicU64::new(0)),
            dnssec_bogus: Arc::new(Mutex::new(BTreeMap::new())),
            clients_identified: Arc::new(RwLock::new(HashMap::new())),
            doh_bypass_blocked: Arc::new(AtomicU64::new(0)),
            transport_queries_total: Arc::new(RwLock::new(HashMap::new())),
            ha_slaves_connected: Arc::new(AtomicI64::new(0)),
            ha_config_version: Arc::new(Mutex::new(BTreeMap::new())),
            querylog_dropped: Arc::new(AtomicU64::new(0)),
            build_version: version.into(),
            build_commit: commit.into(),
        }
    }

    pub fn inc_queries(&self, proto: &str, qtype: u16, verdict: &str) {
        let proto_id = self.labels.intern(proto);
        let verdict_id = self.labels.intern(verdict);
        increment_counter(&self.queries_total, (proto_id, qtype, verdict_id));
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

    pub fn set_upstream_health(&self, upstream: &str, health: f64) {
        let upstream_id = self.labels.intern(upstream);
        let bits = health.to_bits();
        if let Ok(guard) = self.upstream_health.read()
            && let Some(slot) = guard.get(&upstream_id)
        {
            slot.store(bits, Ordering::Relaxed);
            return;
        }

        let mut guard = self
            .upstream_health
            .write()
            .unwrap_or_else(PoisonError::into_inner);
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
    pub fn set_dnssec_key_cache(&self, hits: u64, misses: u64) {
        self.dnssec_key_cache_hits.store(hits, Ordering::Relaxed);
        self.dnssec_key_cache_misses
            .store(misses, Ordering::Relaxed);
    }

    pub fn inc_cache_stale_served(&self) {
        self.cache_stale_served.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dnssec_bogus(&self, upstream: &str) {
        let mut map = self
            .dnssec_bogus
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *map.entry(upstream.to_string()).or_insert(0) += 1;
    }

    pub fn inc_clients_identified(&self, method: &str) {
        let method_id = self.labels.intern(method);
        increment_counter(&self.clients_identified, method_id);
    }

    pub fn inc_doh_bypass_blocked(&self) {
        self.doh_bypass_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_ha_slaves_connected(&self, count: i64) {
        self.ha_slaves_connected.store(count, Ordering::Relaxed);
    }

    pub fn set_ha_config_version(&self, instance: &str, version: f64) {
        let mut map = self
            .ha_config_version
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        map.insert(instance.to_string(), version);
    }

    /// Removes the per-instance HA config version label (e.g. on disconnect) to
    /// prevent unbounded metric cardinality growth.
    pub fn remove_ha_config_version(&self, instance: &str) {
        let mut map = self
            .ha_config_version
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        map.remove(instance);
    }

    pub fn set_querylog_dropped(&self, dropped: u64) {
        self.querylog_dropped.store(dropped, Ordering::Relaxed);
    }

    pub fn inc_querylog_dropped(&self) {
        self.querylog_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns total query count and blocked query count processed by this registry.
    pub fn get_queries_and_blocked(&self) -> (u64, u64) {
        let map = self
            .queries_total
            .read()
            .unwrap_or_else(PoisonError::into_inner);
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
    pub fn get_upstream_reports(&self) -> std::collections::HashMap<String, (f64, u64)> {
        let mut res = std::collections::HashMap::new();
        {
            let map = self
                .upstream_rtt
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            for (&upstream, hist) in map.iter() {
                let hist = hist.lock().unwrap_or_else(PoisonError::into_inner);
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
            let map = self
                .upstream_errors
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            for (&(upstream, _kind), count) in map.iter() {
                let entry = res
                    .entry(self.labels.label(upstream).to_string())
                    .or_insert((0.0, 0u64));
                entry.1 += count.load(Ordering::Relaxed);
            }
        }
        res
    }

    /// Generates the Prometheus text exposition representation conforming to Table 14.2.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();

        // 1. sito_queries_total
        out.push_str("# HELP sito_queries_total Total DNS queries processed\n");
        out.push_str("# TYPE sito_queries_total counter\n");
        {
            let map = self
                .queries_total
                .read()
                .unwrap_or_else(PoisonError::into_inner);
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
                    let _ = writeln!(
                        out,
                        "sito_queries_total{{proto=\"{}\",qtype=\"{}\",verdict=\"{}\"}} {count}",
                        escape_label_value(&proto),
                        qtype,
                        escape_label_value(&verdict)
                    );
                }
            }
        }

        // 1b. sito_transport_queries_total
        out.push_str("# HELP sito_transport_queries_total Total DNS queries by transport\n");
        out.push_str("# TYPE sito_transport_queries_total counter\n");
        {
            let map = self
                .transport_queries_total
                .read()
                .unwrap_or_else(PoisonError::into_inner);
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
            let map = self
                .query_duration
                .read()
                .unwrap_or_else(PoisonError::into_inner);
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
                    let hist = hist.lock().unwrap_or_else(PoisonError::into_inner);
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

        // 3. sito_upstream_rtt_seconds
        out.push_str("# HELP sito_upstream_rtt_seconds Upstream round-trip time in seconds\n");
        out.push_str("# TYPE sito_upstream_rtt_seconds histogram\n");
        {
            let map = self
                .upstream_rtt
                .read()
                .unwrap_or_else(PoisonError::into_inner);
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
                    let hist = hist.lock().unwrap_or_else(PoisonError::into_inner);
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
            let map = self
                .upstream_errors
                .read()
                .unwrap_or_else(PoisonError::into_inner);
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
            let map = self
                .upstream_health
                .read()
                .unwrap_or_else(PoisonError::into_inner);
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

        // 9. sito_filter_rules
        //
        // The filter engine does not report per-list counts; the family is kept
        // at its default so dashboards and alerts do not break.
        out.push_str("# HELP sito_filter_rules Number of active filter rules per list\n");
        out.push_str("# TYPE sito_filter_rules gauge\n");
        out.push_str("sito_filter_rules{list=\"total\"} 0\n");

        // 10. sito_filter_compile_seconds
        out.push_str(
            "# HELP sito_filter_compile_seconds Compilation duration for filter rule trie\n",
        );
        out.push_str("# TYPE sito_filter_compile_seconds histogram\n");
        {
            let hist = HistogramState::new();
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

        // 11. sito_dnssec_bogus_total
        out.push_str("# HELP sito_dnssec_bogus_total Total DNSSEC bogus responses detected\n");
        out.push_str("# TYPE sito_dnssec_bogus_total counter\n");
        {
            let map = self
                .dnssec_bogus
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
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

        // 12. sito_clients_identified_total
        out.push_str("# HELP sito_clients_identified_total Total clients successfully identified by method\n");
        out.push_str("# TYPE sito_clients_identified_total counter\n");
        {
            let map = self
                .clients_identified
                .read()
                .unwrap_or_else(PoisonError::into_inner);
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
            let map = self
                .ha_config_version
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
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

        // 16. sito_querylog_dropped_total
        out.push_str("# HELP sito_querylog_dropped_total Total query log entries dropped due to buffer overflow\n");
        out.push_str("# TYPE sito_querylog_dropped_total counter\n");
        let _ = writeln!(
            out,
            "sito_querylog_dropped_total {}",
            self.querylog_dropped.load(Ordering::Relaxed)
        );

        // 17. sito_build_info
        out.push_str("# HELP sito_build_info Build and version metadata\n");
        out.push_str("# TYPE sito_build_info gauge\n");
        let _ = writeln!(
            out,
            "sito_build_info{{version=\"{}\",commit=\"{}\"}} 1",
            escape_label_value(&self.build_version),
            escape_label_value(&self.build_commit)
        );

        out
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
        reg.inc_clients_identified("ip");
        reg.inc_doh_bypass_blocked();
        reg.set_ha_slaves_connected(2);
        reg.set_ha_config_version("sito-slave-1", 42.0);
        reg.inc_querylog_dropped();

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
        assert!(rendered.contains("sito_clients_identified_total"));
        assert!(rendered.contains("sito_doh_bypass_blocked_total"));
        assert!(rendered.contains("sito_ha_slaves_connected"));
        assert!(rendered.contains("sito_ha_config_version"));
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
        reg.inc_clients_identified("ip");
        reg.inc_doh_bypass_blocked();
        reg.set_ha_slaves_connected(2);
        reg.set_ha_config_version("sito-slave-1", 42.0);
        reg.inc_querylog_dropped();

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
# HELP sito_dnssec_bogus_total Total DNSSEC bogus responses detected
# TYPE sito_dnssec_bogus_total counter
sito_dnssec_bogus_total{upstream="tls://dns.quad9.net"} 1
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
# HELP sito_querylog_dropped_total Total query log entries dropped due to buffer overflow
# TYPE sito_querylog_dropped_total counter
sito_querylog_dropped_total 1
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
}

#[cfg(test)]
mod allocation_tests {
    use super::MetricsRegistry;
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
}
