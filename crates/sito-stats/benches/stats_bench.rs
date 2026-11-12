//! Criterion benchmarks for query-log persistence.
//!
//! Uses an in-memory SQLite database so the numbers describe the writer/SQL
//! path rather than the host filesystem. The dataset is fixed and bounded;
//! the insert benchmark grows the table only for the duration of the
//! measurement.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use sito_stats::db::{QueryLogFilter, StatsDb};
use sito_stats::entry::QueryLogEntry;
use std::hint::black_box;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime")
}

fn sample_entries(count: i64, base_ts: i64) -> Vec<QueryLogEntry> {
    (0..count)
        .map(|i| QueryLogEntry {
            id: None,
            ts: base_ts + i,
            client_ip: format!("192.168.1.{}", 10 + i % 5),
            client_name: Some("bench-client".to_string()),
            qname: format!("host-{}.example.com", i % 500),
            qtype: if i % 2 == 0 { 1 } else { 28 },
            rcode: Some(0),
            verdict: if i % 3 == 0 { "blocked" } else { "allowed" }.to_string(),
            rule: None,
            list_source: None,
            upstream: Some("tls://dns.example".to_string()),
            elapsed_us: Some(500 + i),
            dnssec: Some("secure".to_string()),
            proto: "udp".to_string(),
        })
        .collect()
}

fn bench_query_log(c: &mut Criterion) {
    let rt = runtime();

    // Read benchmarks use a fixed 500-row database so a previous insert
    // iteration cannot make the page query progressively slower.
    let read_db = rt
        .block_on(StatsDb::in_memory())
        .expect("in-memory stats db");
    rt.block_on(read_db.insert_batch(&sample_entries(500, 1_700_000_000_000)))
        .expect("seed query log");

    let batch = sample_entries(100, 1_700_000_000_000);
    let page_filter = QueryLogFilter {
        limit: Some(50),
        include_total: Some(false),
        ..Default::default()
    };
    let filtered = QueryLogFilter {
        qtype: Some(1),
        from: Some(1_700_000_000_000),
        to: Some(1_700_000_000_500),
        limit: Some(50),
        include_total: Some(true),
        ..Default::default()
    };

    let mut group = c.benchmark_group("stats_querylog");
    // Each insert iteration gets a fresh in-memory database, so the timed
    // operation is a bounded 100-row batch rather than an ever-growing table.
    group.bench_function("insert_batch_100_fresh_db", |b| {
        b.iter_batched(
            || {
                rt.block_on(StatsDb::in_memory())
                    .expect("in-memory stats db")
            },
            |db| {
                rt.block_on(db.insert_batch(black_box(&batch)))
                    .expect("insert batch");
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("page_50_without_total", |b| {
        b.iter(|| {
            let page = rt
                .block_on(read_db.query_logs(black_box(&page_filter)))
                .expect("query page");
            black_box(page);
        });
    });
    group.bench_function("page_50_filtered_with_total", |b| {
        b.iter(|| {
            let page = rt
                .block_on(read_db.query_logs(black_box(&filtered)))
                .expect("query filtered page");
            black_box(page);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_query_log);
criterion_main!(benches);
