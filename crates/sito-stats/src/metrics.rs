//! Prometheus metrics registry per section 14.2.
//!
//! Exposes all required metrics with cardinality bounds to prevent time-series explosion.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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

type QueryMetricKey = (String, String, String);
type UpstreamMetricKey = (String, String);

/// Thread-safe registry maintaining all Prometheus metrics specified in Table 14.2.
#[derive(Clone)]
pub struct MetricsRegistry {
    queries_total: Arc<Mutex<BTreeMap<QueryMetricKey, u64>>>,
    query_duration: Arc<Mutex<BTreeMap<String, HistogramState>>>,
    upstream_rtt: Arc<Mutex<BTreeMap<String, HistogramState>>>,
    upstream_errors: Arc<Mutex<BTreeMap<UpstreamMetricKey, u64>>>,
    upstream_health: Arc<Mutex<BTreeMap<String, f64>>>,
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    cache_size_bytes: Arc<AtomicI64>,
    cache_stale_served: Arc<AtomicU64>,
    filter_rules: Arc<Mutex<BTreeMap<String, i64>>>,
    filter_compile: Arc<Mutex<HistogramState>>,
    dnssec_bogus: Arc<Mutex<BTreeMap<String, u64>>>,
    clients_identified: Arc<Mutex<BTreeMap<String, u64>>>,
    doh_bypass_blocked: Arc<AtomicU64>,
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
            queries_total: Arc::new(Mutex::new(BTreeMap::new())),
            query_duration: Arc::new(Mutex::new(BTreeMap::new())),
            upstream_rtt: Arc::new(Mutex::new(BTreeMap::new())),
            upstream_errors: Arc::new(Mutex::new(BTreeMap::new())),
            upstream_health: Arc::new(Mutex::new(BTreeMap::new())),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            cache_size_bytes: Arc::new(AtomicI64::new(0)),
            cache_stale_served: Arc::new(AtomicU64::new(0)),
            filter_rules: Arc::new(Mutex::new(BTreeMap::new())),
            filter_compile: Arc::new(Mutex::new(HistogramState::new())),
            dnssec_bogus: Arc::new(Mutex::new(BTreeMap::new())),
            clients_identified: Arc::new(Mutex::new(BTreeMap::new())),
            doh_bypass_blocked: Arc::new(AtomicU64::new(0)),
            ha_slaves_connected: Arc::new(AtomicI64::new(0)),
            ha_config_version: Arc::new(Mutex::new(BTreeMap::new())),
            querylog_dropped: Arc::new(AtomicU64::new(0)),
            build_version: version.into(),
            build_commit: commit.into(),
        }
    }

    pub fn inc_queries(&self, proto: &str, qtype: u16, verdict: &str) {
        let mut map = self.queries_total.lock().unwrap();
        let key = (proto.to_string(), qtype.to_string(), verdict.to_string());
        *map.entry(key).or_insert(0) += 1;
    }

    pub fn observe_query_duration(&self, verdict: &str, duration_secs: f64) {
        let mut map = self.query_duration.lock().unwrap();
        map.entry(verdict.to_string())
            .or_default()
            .observe(duration_secs);
    }

    pub fn observe_upstream_rtt(&self, upstream: &str, rtt_secs: f64) {
        let mut map = self.upstream_rtt.lock().unwrap();
        map.entry(upstream.to_string())
            .or_default()
            .observe(rtt_secs);
    }

    pub fn inc_upstream_errors(&self, upstream: &str, kind: &str) {
        let mut map = self.upstream_errors.lock().unwrap();
        let key = (upstream.to_string(), kind.to_string());
        *map.entry(key).or_insert(0) += 1;
    }

    pub fn set_upstream_health(&self, upstream: &str, health: f64) {
        let mut map = self.upstream_health.lock().unwrap();
        map.insert(upstream.to_string(), health);
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

    pub fn inc_cache_stale_served(&self) {
        self.cache_stale_served.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_filter_rules(&self, list: &str, count: i64) {
        let mut map = self.filter_rules.lock().unwrap();
        map.insert(list.to_string(), count);
    }

    pub fn observe_filter_compile_seconds(&self, duration_secs: f64) {
        let mut hist = self.filter_compile.lock().unwrap();
        hist.observe(duration_secs);
    }

    pub fn inc_dnssec_bogus(&self, upstream: &str) {
        let mut map = self.dnssec_bogus.lock().unwrap();
        *map.entry(upstream.to_string()).or_insert(0) += 1;
    }

    pub fn inc_clients_identified(&self, method: &str) {
        let mut map = self.clients_identified.lock().unwrap();
        *map.entry(method.to_string()).or_insert(0) += 1;
    }

    pub fn inc_doh_bypass_blocked(&self) {
        self.doh_bypass_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_ha_slaves_connected(&self, count: i64) {
        self.ha_slaves_connected.store(count, Ordering::Relaxed);
    }

    pub fn set_ha_config_version(&self, instance: &str, version: f64) {
        let mut map = self.ha_config_version.lock().unwrap();
        map.insert(instance.to_string(), version);
    }

    pub fn set_querylog_dropped(&self, dropped: u64) {
        self.querylog_dropped.store(dropped, Ordering::Relaxed);
    }

    pub fn inc_querylog_dropped(&self) {
        self.querylog_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Generates the Prometheus text exposition representation conforming to Table 14.2.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();

        // 1. sito_queries_total
        out.push_str("# HELP sito_queries_total Total DNS queries processed\n");
        out.push_str("# TYPE sito_queries_total counter\n");
        {
            let map = self.queries_total.lock().unwrap();
            if map.is_empty() {
                out.push_str(
                    "sito_queries_total{proto=\"udp\",qtype=\"1\",verdict=\"allowed\"} 0\n",
                );
            } else {
                for ((proto, qtype, verdict), count) in map.iter() {
                    let _ = writeln!(
                        out,
                        "sito_queries_total{{proto=\"{proto}\",qtype=\"{qtype}\",verdict=\"{verdict}\"}} {count}"
                    );
                }
            }
        }

        // 2. sito_query_duration_seconds
        out.push_str("# HELP sito_query_duration_seconds Histogram of query duration in seconds\n");
        out.push_str("# TYPE sito_query_duration_seconds histogram\n");
        {
            let map = self.query_duration.lock().unwrap();
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
                for (verdict, hist) in map.iter() {
                    for (i, &b) in LATENCY_BUCKETS.iter().enumerate() {
                        let c = hist.counts[i];
                        let _ = writeln!(
                            out,
                            "sito_query_duration_seconds_bucket{{verdict=\"{verdict}\",le=\"{b}\"}} {c}"
                        );
                    }
                    let _ = writeln!(
                        out,
                        "sito_query_duration_seconds_bucket{{verdict=\"{verdict}\",le=\"+Inf\"}} {}",
                        hist.count
                    );
                    let _ = writeln!(
                        out,
                        "sito_query_duration_seconds_sum{{verdict=\"{verdict}\"}} {}",
                        hist.sum
                    );
                    let _ = writeln!(
                        out,
                        "sito_query_duration_seconds_count{{verdict=\"{verdict}\"}} {}",
                        hist.count
                    );
                }
            }
        }

        // 3. sito_upstream_rtt_seconds
        out.push_str("# HELP sito_upstream_rtt_seconds Upstream round-trip time in seconds\n");
        out.push_str("# TYPE sito_upstream_rtt_seconds histogram\n");
        {
            let map = self.upstream_rtt.lock().unwrap();
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
                for (upstream, hist) in map.iter() {
                    for (i, &b) in LATENCY_BUCKETS.iter().enumerate() {
                        let c = hist.counts[i];
                        let _ = writeln!(
                            out,
                            "sito_upstream_rtt_seconds_bucket{{upstream=\"{upstream}\",le=\"{b}\"}} {c}"
                        );
                    }
                    let _ = writeln!(
                        out,
                        "sito_upstream_rtt_seconds_bucket{{upstream=\"{upstream}\",le=\"+Inf\"}} {}",
                        hist.count
                    );
                    let _ = writeln!(
                        out,
                        "sito_upstream_rtt_seconds_sum{{upstream=\"{upstream}\"}} {}",
                        hist.sum
                    );
                    let _ = writeln!(
                        out,
                        "sito_upstream_rtt_seconds_count{{upstream=\"{upstream}\"}} {}",
                        hist.count
                    );
                }
            }
        }

        // 4. sito_upstream_errors_total
        out.push_str("# HELP sito_upstream_errors_total Total errors encountered per upstream\n");
        out.push_str("# TYPE sito_upstream_errors_total counter\n");
        {
            let map = self.upstream_errors.lock().unwrap();
            if map.is_empty() {
                out.push_str(
                    "sito_upstream_errors_total{upstream=\"default\",kind=\"timeout\"} 0\n",
                );
            } else {
                for ((upstream, kind), count) in map.iter() {
                    let _ = writeln!(
                        out,
                        "sito_upstream_errors_total{{upstream=\"{upstream}\",kind=\"{kind}\"}} {count}"
                    );
                }
            }
        }

        // 5. sito_upstream_health
        out.push_str("# HELP sito_upstream_health Upstream resolver health status (1 = healthy, 0 = degraded/down)\n");
        out.push_str("# TYPE sito_upstream_health gauge\n");
        {
            let map = self.upstream_health.lock().unwrap();
            if map.is_empty() {
                out.push_str("sito_upstream_health{upstream=\"default\"} 1\n");
            } else {
                for (upstream, health) in map.iter() {
                    let _ = writeln!(
                        out,
                        "sito_upstream_health{{upstream=\"{upstream}\"}} {health}"
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

        // 7. sito_cache_size_bytes
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
        out.push_str("# HELP sito_filter_rules Number of active filter rules per list\n");
        out.push_str("# TYPE sito_filter_rules gauge\n");
        {
            let map = self.filter_rules.lock().unwrap();
            if map.is_empty() {
                out.push_str("sito_filter_rules{list=\"total\"} 0\n");
            } else {
                for (list, count) in map.iter() {
                    let _ = writeln!(out, "sito_filter_rules{{list=\"{list}\"}} {count}");
                }
            }
        }

        // 10. sito_filter_compile_seconds
        out.push_str(
            "# HELP sito_filter_compile_seconds Compilation duration for filter rule trie\n",
        );
        out.push_str("# TYPE sito_filter_compile_seconds histogram\n");
        {
            let hist = self.filter_compile.lock().unwrap();
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
            let map = self.dnssec_bogus.lock().unwrap();
            if map.is_empty() {
                out.push_str("sito_dnssec_bogus_total{upstream=\"default\"} 0\n");
            } else {
                for (upstream, count) in map.iter() {
                    let _ = writeln!(
                        out,
                        "sito_dnssec_bogus_total{{upstream=\"{upstream}\"}} {count}"
                    );
                }
            }
        }

        // 12. sito_clients_identified_total
        out.push_str("# HELP sito_clients_identified_total Total clients successfully identified by method\n");
        out.push_str("# TYPE sito_clients_identified_total counter\n");
        {
            let map = self.clients_identified.lock().unwrap();
            if map.is_empty() {
                out.push_str("sito_clients_identified_total{method=\"ip\"} 0\n");
            } else {
                for (method, count) in map.iter() {
                    let _ = writeln!(
                        out,
                        "sito_clients_identified_total{{method=\"{method}\"}} {count}"
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
            let map = self.ha_config_version.lock().unwrap();
            if map.is_empty() {
                out.push_str("sito_ha_config_version{instance=\"local\"} 1\n");
            } else {
                for (instance, version) in map.iter() {
                    let _ = writeln!(
                        out,
                        "sito_ha_config_version{{instance=\"{instance}\"}} {version}"
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
            self.build_version, self.build_commit
        );

        out
    }
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
        reg.set_filter_rules("oisd", 250_000);
        reg.observe_filter_compile_seconds(0.12);
        reg.inc_dnssec_bogus("tls://dns.quad9.net");
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
        assert!(rendered.contains("sito_clients_identified_total"));
        assert!(rendered.contains("sito_doh_bypass_blocked_total"));
        assert!(rendered.contains("sito_ha_slaves_connected"));
        assert!(rendered.contains("sito_ha_config_version"));
        assert!(rendered.contains("sito_querylog_dropped_total"));
        assert!(rendered.contains("sito_build_info"));
    }
}
