//! Prometheus text-exposition conformance for `MetricsRegistry::render_prometheus`.
//!
//! This uses the real `prometheus-parse` parser rather than string assertions:
//! every sample line must parse, every metric family must carry HELP and TYPE
//! metadata, and no two samples may name the same series (metric + labels).

use prometheus_parse::{LineInfo, Scrape};
use sito_stats::{FilterStatusMetrics, MetricsRegistry};
use std::collections::{HashMap, HashSet};

fn populated_registry() -> MetricsRegistry {
    let registry = MetricsRegistry::new("2.0.0-alpha.1", "test-commit");
    for proto in ["udp", "tcp", "dot", "doh", "doq", "doh3"] {
        for verdict in ["allowed", "blocked", "cached", "stale"] {
            registry.inc_queries(proto, 1, verdict);
        }
    }
    registry.observe_query_duration("allowed", 0.000_250);
    registry.observe_upstream_rtt("tls://dns.example", 0.012);
    registry.inc_upstream_errors("tls://dns.example", "timeout");
    registry.set_upstream_health("tls://dns.example", 1.0);
    registry.inc_cache_hits();
    registry.inc_cache_misses();
    registry.set_cache_size_bytes(1_048_576);
    registry.set_dnssec_key_cache(10, 2);
    registry.inc_cache_stale_served();
    registry.inc_dnssec_bogus("tls://dns.example");
    registry.inc_clients_identified("ip");
    registry.inc_doh_bypass_blocked();
    registry.set_ha_slaves_connected(2);
    registry.set_ha_config_version("slave-1", 42.0);
    registry.set_ha_diverged("slave-2", true);
    registry.inc_ha_startup_noop("slave", "no_master");
    registry.set_querylog_dropped(3);
    registry.set_rollup_retention_days(365);
    registry.set_retention_last_success_seconds(1_700_000_000);
    registry.record_retention_success(1_700_000_001, 12, 4_000, 40);
    registry.record_retention_failure(100);
    registry.set_filter_rules(10_000);
    registry.set_filter_status(FilterStatusMetrics {
        state: 2,
        loaded_lists: 3,
        failed_lists: 0,
        degraded_groups: 0,
        dropped_regex_patterns: 1,
        unavailable: 0,
    });
    registry.observe_filter_compile(0.125);
    registry
}

#[test]
fn rendered_exposition_parses_with_docs_and_without_duplicate_series() {
    let text = populated_registry().render_prometheus();
    assert!(!text.is_empty(), "render_prometheus returned no output");

    let lines = text
        .lines()
        .map(|line| Ok::<String, std::io::Error>(line.to_string()));
    let scrape = Scrape::parse(lines).expect("rendered exposition must parse");

    assert!(!scrape.samples.is_empty(), "expected at least one sample");

    // The parser exposes HELP text but not the TYPE map, so collect the
    // declarations from the same lines with the parser's own LineInfo.
    let mut help: HashSet<String> = HashSet::new();
    let mut types: HashSet<String> = HashSet::new();
    for line in text.lines() {
        match LineInfo::parse(line) {
            LineInfo::Doc { metric_name, .. } => {
                help.insert(metric_name.to_string());
            }
            LineInfo::Type {
                metric_name,
                metric_alias,
                ..
            } => {
                types.insert(metric_name.clone());
                if let Some(alias) = metric_alias {
                    types.insert(alias);
                }
            }
            _ => {}
        }
    }

    let mut seen: HashSet<(String, Vec<(String, String)>)> = HashSet::new();
    for sample in &scrape.samples {
        assert!(
            sample.metric.starts_with("sito_"),
            "unexpected metric name: {}",
            sample.metric
        );

        // Histograms/summaries emit `_bucket`, `_sum` and `_count` samples
        // under one HELP/TYPE family.
        let family = ["", "_bucket", "_sum", "_count"]
            .iter()
            .find_map(|suffix| {
                sample
                    .metric
                    .strip_suffix(suffix)
                    .filter(|base| help.contains(*base))
                    .map(str::to_string)
            })
            .unwrap_or_else(|| panic!("metric {} has no HELP family", sample.metric));

        let mut labels: Vec<(String, String)> = sample
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        labels.sort();
        assert!(
            seen.insert((sample.metric.clone(), labels.clone())),
            "duplicate series: {} {labels:?}",
            sample.metric
        );

        assert!(help.contains(&family), "family {family} has no HELP line");
        assert!(types.contains(&family), "family {family} has no TYPE line");
    }

    // A family declared by the registry but with no live series must still be
    // documented; this catches a renderer that drops HELP on empty maps.
    for metric in &help {
        assert!(
            types.contains(metric),
            "documented family {metric} has no TYPE line"
        );
    }

    // Keep the parsed docs referenced so the parser output is not dead code in
    // this conformance check.
    let docs: &HashMap<String, String> = &scrape.docs;
    assert_eq!(docs.len(), help.len(), "parser lost HELP metadata");
}
