//! Criterion benchmarks for the Prometheus metrics registry.
//!
//! A populated registry is reused for every iteration so the measurement is
//! the update/render path, not LabelInterner setup.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
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
    // P2-62: this records the single-threaded per-update cost of the hot
    // `allowed` histogram (one small mutex around a fixed bucket loop).
    // Contention losslessness is covered by the concurrent-update test, not
    // by this criterion loop.
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

/// Measures same-label contention on the `allowed` histogram.
///
/// `metrics_bench::metrics` is single-threaded by design. This group compares
/// the per-observation cost of one writer with N writers hammering the same
/// verdict label. Each iteration performs `threads * OBSERVATIONS_PER_THREAD`
/// observations, so the scoped thread spawn/join is amortized and criterion's
/// element throughput is directly comparable across thread counts. Compare
/// `observe_query_duration_1_thread` with `observe_query_duration_N_threads`
/// before considering sharding the per-label `HistogramState`.
fn bench_contended_histogram(c: &mut Criterion) {
    const OBSERVATIONS_PER_THREAD: usize = 1_000;
    let workers = std::thread::available_parallelism()
        .map_or(4, std::num::NonZeroUsize::get)
        .clamp(2, 8);
    let registry = std::sync::Arc::new(populated_registry());

    let mut group = c.benchmark_group("metrics_contended");
    for threads in [1usize, workers] {
        group.throughput(Throughput::Elements(
            (threads * OBSERVATIONS_PER_THREAD) as u64,
        ));
        group.bench_function(format!("observe_query_duration_{threads}_threads"), |b| {
            b.iter(|| {
                std::thread::scope(|scope| {
                    for _ in 0..threads {
                        let registry = std::sync::Arc::clone(&registry);
                        scope.spawn(move || {
                            for _ in 0..OBSERVATIONS_PER_THREAD {
                                registry.observe_query_duration(
                                    black_box("allowed"),
                                    black_box(0.000_3),
                                );
                            }
                        });
                    }
                });
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_metrics, bench_contended_histogram);
criterion_main!(benches);
