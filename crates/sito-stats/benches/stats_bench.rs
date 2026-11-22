//! Criterion benchmarks for query-log persistence.
//!
//! Uses an in-memory SQLite database so the numbers describe the writer/SQL
//! path rather than the host filesystem. The dataset is fixed and bounded;
//! the insert benchmark grows the table only for the duration of the
//! measurement.

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use sito_stats::db::{QueryLogFilter, StatsDb};
use sito_stats::entry::QueryLogEntry;
use std::hint::black_box;

/// Number of rows in the cursor-vs-offset dataset. 100k is deep enough that an
/// offset page at the end must walk (or sort) almost the whole table, while the
/// keyset page still seeks one index position.
const SCALE_ROWS: i64 = 100_000;

/// Page size used by both strategies so the comparison is apples-to-apples.
const PAGE: i64 = 50;

/// Offset page SQL mirroring the page projection. Offset pagination has to
/// count/skip `OFFSET` rows before returning `LIMIT` rows.
const OFFSET_PAGE_SQL: &str = r"
    SELECT id, ts, client_ip, client_name, qname, qtype, rcode, verdict,
           rule, list_source, upstream, elapsed_us, dnssec, proto
    FROM query_log
    ORDER BY ts DESC, id DESC
    LIMIT 51 OFFSET ?";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime")
}

fn seed_scale_rows(rt: &tokio::runtime::Runtime, db: &StatsDb, count: i64) {
    // Five rows share each timestamp so the keyset's id tie-break is real.
    rt.block_on(async {
        sqlx::query(
            r"
            WITH RECURSIVE seq(x) AS (
                SELECT 0
                UNION ALL
                SELECT x + 1 FROM seq WHERE x + 1 < ?
            )
            INSERT INTO query_log (
                ts, client_ip, client_name, qname, qtype, rcode,
                verdict, rule, list_source, upstream, elapsed_us, dnssec, proto
            )
            SELECT
                1700000000000 + (x / 5),
                printf('192.168.1.%d', 10 + (x % 200)),
                NULL,
                printf('host-%d.example.com', x % 500),
                CASE WHEN x % 2 = 0 THEN 1 ELSE 28 END,
                0,
                CASE WHEN x % 3 = 0 THEN 'blocked' ELSE 'allowed' END,
                NULL, NULL, 'tls://dns.example', 500 + (x % 1000), 'secure', 'udp'
            FROM seq
            ",
        )
        .bind(count)
        .execute(db.pool())
        .await
        .expect("seed scale query log");
    });
}

/// Pages from the top until at least `rows` rows were consumed and returns the
/// cursor at that boundary. Used for the "deep" keyset page.
fn cursor_after(rt: &tokio::runtime::Runtime, db: &StatsDb, rows: usize) -> String {
    let mut cursor = None;
    let mut seen = 0usize;
    while seen < rows {
        let page = rt
            .block_on(db.query_logs(&QueryLogFilter {
                limit: Some(500),
                cursor: cursor.clone(),
                ..Default::default()
            }))
            .expect("seed walk page");
        seen += page.items.len();
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    cursor.expect("deep cursor exists before the end of the dataset")
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
        ..Default::default()
    };
    let filtered = QueryLogFilter {
        qtype: Some(1),
        from: Some(1_700_000_000_000),
        to: Some(1_700_000_000_500),
        limit: Some(50),
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
    group.bench_function("page_50", |b| {
        b.iter(|| {
            let page = rt
                .block_on(read_db.query_logs(black_box(&page_filter)))
                .expect("query page");
            black_box(page);
        });
    });
    group.bench_function("page_50_filtered", |b| {
        b.iter(|| {
            let page = rt
                .block_on(read_db.query_logs(black_box(&filtered)))
                .expect("query filtered page");
            black_box(page);
        });
    });
    group.finish();
}

fn bench_cursor_vs_offset(c: &mut Criterion) {
    let rt = runtime();

    let scale_db = rt
        .block_on(StatsDb::in_memory())
        .expect("in-memory stats db");
    seed_scale_rows(&rt, &scale_db, SCALE_ROWS);

    let first = rt
        .block_on(scale_db.query_logs(&QueryLogFilter {
            limit: Some(PAGE as usize),
            ..Default::default()
        }))
        .expect("first page");
    let shallow_cursor = first.next_cursor.expect("another page exists");
    let deep_cursor = cursor_after(&rt, &scale_db, SCALE_ROWS as usize - 500);

    let first_filter = QueryLogFilter {
        limit: Some(PAGE as usize),
        ..Default::default()
    };
    let shallow_filter = QueryLogFilter {
        limit: Some(PAGE as usize),
        cursor: Some(shallow_cursor),
        ..Default::default()
    };
    let deep_filter = QueryLogFilter {
        limit: Some(PAGE as usize),
        cursor: Some(deep_cursor),
        ..Default::default()
    };

    let mut group = c.benchmark_group("stats_querylog_cursor_vs_offset");
    group.throughput(Throughput::Elements(PAGE as u64));

    // Keyset: SQLite seeks one position in the (ts, id) index, so page cost is
    // independent of how deep the cursor is.
    group.bench_function("keyset_first_page_50", |b| {
        b.iter(|| {
            let page = rt
                .block_on(scale_db.query_logs(black_box(&first_filter)))
                .expect("keyset first page");
            black_box(page);
        });
    });
    group.bench_function("keyset_next_page_50_shallow", |b| {
        b.iter(|| {
            let page = rt
                .block_on(scale_db.query_logs(black_box(&shallow_filter)))
                .expect("keyset shallow page");
            black_box(page);
        });
    });
    group.bench_function("keyset_next_page_50_deep", |b| {
        b.iter(|| {
            let page = rt
                .block_on(scale_db.query_logs(black_box(&deep_filter)))
                .expect("keyset deep page");
            black_box(page);
        });
    });

    // Offset: the database must produce/sort and discard every row before the
    // offset, so the deep page is dramatically more expensive. This is the
    // behavior the cursor replaced.
    group.bench_function("offset_page_50_at_100", |b| {
        b.iter(|| {
            let rows = rt
                .block_on(
                    sqlx::query(OFFSET_PAGE_SQL)
                        .bind(100i64)
                        .fetch_all(scale_db.pool()),
                )
                .expect("offset shallow page");
            black_box(rows);
        });
    });
    group.bench_function("offset_page_50_at_99900", |b| {
        b.iter(|| {
            let rows = rt
                .block_on(
                    sqlx::query(OFFSET_PAGE_SQL)
                        .bind(SCALE_ROWS - 100)
                        .fetch_all(scale_db.pool()),
                )
                .expect("offset deep page");
            black_box(rows);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_query_log, bench_cursor_vs_offset);
criterion_main!(benches);
