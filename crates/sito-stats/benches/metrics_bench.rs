//! Criterion benchmarks for the Prometheus metrics registry.
//!
//! A populated registry is reused for every iteration so the measurement is
//! the update/render path, not LabelInterner setup.

use criterion::{Criterion, criterion_group, criterion_main};
use sito_stats::MetricsRegistry;
use std::hint::black_box;

fn populated_registry() -> MetricsRegistry {
    let registry = MetricsRegistry::new("2.0.0-alpha.1", "bench");
    for proto in ["udp", "tcp", "dot", "doh"] {
        for verdict in ["allowed", "blocked", "cached"] {
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
    registry.inc_clients_identified("ip");
    registry.set_ha_slaves_connected(2);
    registry.set_ha_config_version("slave-1", 42.0);
    registry.set_filter_rules(10_000);
    registry
}

fn bench_metrics(c: &mut Criterion) {
    let registry = populated_registry();

    let mut group = c.benchmark_group("metrics");
    group.bench_function("inc_queries", |b| {
        b.iter(|| registry.inc_queries("udp", 1, "allowed"));
    });
    group.bench_function("observe_query_duration", |b| {
        b.iter(|| registry.observe_query_duration(black_box("allowed"), black_box(0.000_3)));
    });
    group.bench_function("observe_upstream_rtt", |b| {
        b.iter(|| registry.observe_upstream_rtt(black_box("tls://dns.example"), black_box(0.011)));
    });
    group.bench_function("render_prometheus", |b| {
        b.iter(|| {
            let body = registry.render_prometheus();
            black_box(body);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_metrics);
criterion_main!(benches);
