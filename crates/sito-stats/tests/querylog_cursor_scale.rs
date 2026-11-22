//! Release-scale evidence for the opaque query-log cursor (task A7).
//!
//! These tests complement the focused unit tests in `src/db/querylog.rs`:
//!
//! - 100k rows are paged end-to-end with a small limit, checked for strict
//!   `(ts, id)` newest-first ordering, no duplicates/omissions, a final
//!   `next_cursor == None`, filter-consistent pages and cursor rejection.
//! - The 1M-row test is `#[ignore]`d so default CI stays fast. Run it with:
//!   `cargo test -p sito-stats --all-features --test querylog_cursor_scale \
//!    -- --ignored --nocapture`
//!   It prints seed/walk timings and asserts documented upper bounds.
//! - Concurrent changes are modelled on a real SQLite file: inserting newer
//!   rows between pages and deleting rows between pages must never make the
//!   cursor duplicate or skip the rows that remain.
//!
//! Keyset semantics: the cursor is a position, not a snapshot. Rows inserted
//! above the cursor are not returned by later pages; deleted rows simply
//! disappear. Everything else keeps its relative order.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use sito_stats::db::DEFAULT_QUERYLOG_LIMIT;
use sito_stats::{QueryLogEntry, QueryLogFilter, StatsDb, StatsError};

const BASE_TS: i64 = 1_700_000_000_000;
const HUNDRED_THOUSAND: usize = 100_000;

/// Generous, documented bounds for the unoptimized debug-build 1M-row test.
/// They are intended to catch accidental quadratic behavior, not to benchmark.
const ONE_MILLION_SEED_BOUND: Duration = Duration::from_secs(180);
const ONE_MILLION_WALK_BOUND: Duration = Duration::from_secs(120);

/// Seeds `count` deterministic rows directly through SQLite.
///
/// Five consecutive rows share one timestamp, so the `(ts, id)` id tie-break is
/// exercised heavily. Rows are otherwise a fixed function of their sequence
/// number, which lets the tests compute exact filter counts.
async fn seed_rows(db: &StatsDb, count: usize) {
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
            ? + (x / 5),
            printf('192.0.2.%d', 10 + (x % 200)),
            NULL,
            printf('host-%d.example.com', x % 1000),
            CASE WHEN x % 7 = 0 THEN 28 ELSE 1 END,
            0,
            CASE WHEN x % 3 = 0 THEN 'blocked' ELSE 'allowed' END,
            NULL,
            NULL,
            'tls://dns.example',
            100 + (x % 500),
            'secure',
            'udp'
        FROM seq
        ",
    )
    .bind(i64::try_from(count).expect("row count fits i64"))
    .bind(BASE_TS)
    .execute(db.pool())
    .await
    .expect("seed deterministic query-log rows");
}

fn assert_strictly_descending(rows: &[(i64, i64)]) {
    for pair in rows.windows(2) {
        assert!(
            pair[0] > pair[1],
            "rows must be strictly descending by (ts, id), got {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }
}

/// Walks every page until `next_cursor == None`, returning `(ts, id)` keys.
async fn walk_collect(
    db: &StatsDb,
    filter: &QueryLogFilter,
    max_pages: usize,
) -> (Vec<(i64, i64)>, usize) {
    let page_limit = filter.limit.unwrap_or(DEFAULT_QUERYLOG_LIMIT);
    let mut rows = Vec::new();
    let mut cursor = filter.cursor.clone();
    let mut pages = 0;

    loop {
        pages += 1;
        assert!(
            pages <= max_pages,
            "cursor walk exceeded {max_pages} pages; the cursor is not advancing"
        );
        let page = db
            .query_logs(&QueryLogFilter {
                cursor: cursor.clone(),
                ..filter.clone()
            })
            .await
            .expect("query-log page");
        assert!(
            page.items.len() <= page_limit,
            "page {} returned {} rows, above limit {page_limit}",
            pages,
            page.items.len()
        );
        for entry in &page.items {
            // Every page must re-apply the filter, not just the first one.
            if let Some(from) = filter.from {
                assert!(entry.ts >= from, "row older than `from`: {entry:?}");
            }
            if let Some(to) = filter.to {
                assert!(entry.ts <= to, "row newer than `to`: {entry:?}");
            }
            if let Some(ref status) = filter.status {
                assert_eq!(&entry.verdict, status, "row does not match `status`");
            }
            if let Some(qtype) = filter.qtype {
                assert_eq!(entry.qtype, qtype, "row does not match `qtype`");
            }
            if let Some(ref client) = filter.client {
                assert!(
                    entry.client_ip == *client
                        || entry.client_name.as_deref() == Some(client.as_str()),
                    "row does not match `client`: {entry:?}"
                );
            }
            if let Some(ref domain) = filter.domain {
                // Test filters use plain substrings; LIKE metacharacters are
                // not exercised here (the cursor binds the raw filter value).
                assert!(
                    entry.qname.contains(domain),
                    "row does not match `domain`: {entry:?}"
                );
            }
        }
        rows.extend(
            page.items
                .iter()
                .map(|entry| (entry.ts, entry.id.expect("query rows carry an id"))),
        );
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return (rows, pages),
        }
    }
}

/// Walks all pages while keeping only O(page + last key) state, for the 1M test.
struct WalkSummary {
    rows: usize,
    pages: usize,
    last_page_len: usize,
    max_page_len: usize,
}

async fn walk_bounded(db: &StatsDb, filter: &QueryLogFilter, max_pages: usize) -> WalkSummary {
    let page_limit = filter.limit.unwrap_or(DEFAULT_QUERYLOG_LIMIT);
    let mut rows = 0usize;
    let mut pages = 0usize;
    let mut max_page_len = 0usize;
    let mut last_page_len;
    let mut previous: Option<(i64, i64)> = None;
    let mut cursor = filter.cursor.clone();

    loop {
        pages += 1;
        assert!(
            pages <= max_pages,
            "cursor walk exceeded {max_pages} pages; the cursor is not advancing"
        );
        let page = db
            .query_logs(&QueryLogFilter {
                cursor: cursor.clone(),
                ..filter.clone()
            })
            .await
            .expect("query-log page");

        assert!(
            page.items.len() <= page_limit,
            "page {pages} returned {} rows, above limit {page_limit}",
            page.items.len()
        );
        max_page_len = max_page_len.max(page.items.len());
        last_page_len = page.items.len();

        for entry in &page.items {
            let key = (entry.ts, entry.id.expect("query rows carry an id"));
            if let Some(previous) = previous {
                assert!(
                    previous > key,
                    "rows must be strictly descending by (ts, id), got {previous:?} then {key:?}"
                );
            }
            previous = Some(key);
            rows += 1;
        }

        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => {
                return WalkSummary {
                    rows,
                    pages,
                    last_page_len,
                    max_page_len,
                };
            }
        }
    }
}

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sito-stats-cursor-{label}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

async fn cleanup(db: StatsDb, dir: &PathBuf) {
    db.pool().close().await;
    drop(db);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn test_100k_cursor_pagination_scale() {
    const LIMIT: usize = 97;
    const BLOCKED_LIMIT: usize = 89;

    let db = StatsDb::in_memory().await.unwrap();
    seed_rows(&db, HUNDRED_THOUSAND).await;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM query_log")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(total as usize, HUNDRED_THOUSAND, "seed must be complete");

    // 1. Unfiltered: every row exactly once, strictly newest-first, and the
    //    walk ends only when the server returns `next_cursor: null`.
    let (rows, pages) = walk_collect(
        &db,
        &QueryLogFilter {
            limit: Some(LIMIT),
            ..Default::default()
        },
        2_000,
    )
    .await;

    assert_eq!(rows.len(), HUNDRED_THOUSAND, "no rows may be omitted");
    assert_eq!(
        rows.iter().map(|(_, id)| *id).collect::<HashSet<_>>().len(),
        HUNDRED_THOUSAND,
        "no row may be duplicated across pages"
    );
    assert_strictly_descending(&rows);
    assert_eq!(
        pages,
        HUNDRED_THOUSAND.div_ceil(LIMIT),
        "the walk must take exactly ceil(rows/limit) pages"
    );

    let newest_ts = BASE_TS + i64::try_from(HUNDRED_THOUSAND - 1).unwrap() / 5;
    assert_eq!(
        rows.first().copied(),
        Some((newest_ts, i64::try_from(HUNDRED_THOUSAND).unwrap())),
        "the newest (ts, id) row must be first"
    );
    assert_eq!(
        rows.last().copied(),
        Some((BASE_TS, 1)),
        "the oldest (ts, id) row must be last"
    );

    // The last page must be the only page without a cursor: replaying the
    // final page's (absent) cursor is not possible, so instead assert the
    // walk never terminated early by checking the exact page count above.

    // 2. Filter-constrained pagination stays consistent across pages.
    let expected_blocked = HUNDRED_THOUSAND.div_ceil(3);
    let (blocked_rows, blocked_pages) = walk_collect(
        &db,
        &QueryLogFilter {
            status: Some("blocked".into()),
            limit: Some(BLOCKED_LIMIT),
            ..Default::default()
        },
        2_000,
    )
    .await;
    assert_eq!(
        blocked_rows.len(),
        expected_blocked,
        "verdict filter must apply on every page"
    );
    assert_eq!(blocked_pages, expected_blocked.div_ceil(BLOCKED_LIMIT));
    assert_strictly_descending(&blocked_rows);
    let blocked_page = db
        .query_logs(&QueryLogFilter {
            status: Some("blocked".into()),
            limit: Some(BLOCKED_LIMIT * 2),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        blocked_page
            .items
            .iter()
            .all(|entry| entry.verdict == "blocked"),
        "every filtered page row must match the filter"
    );

    // 3. Domain (LIKE) filter: exactly 100 sequence numbers end in 7.
    let (domain_rows, _) = walk_collect(
        &db,
        &QueryLogFilter {
            domain: Some("host-7.example.com".into()),
            limit: Some(31),
            ..Default::default()
        },
        1_000,
    )
    .await;
    assert_eq!(domain_rows.len(), 100, "domain filter count");
    assert_strictly_descending(&domain_rows);

    // 4. Time-range filter: ts = BASE + x/5, so 1001 whole five-row buckets.
    let (range_rows, _) = walk_collect(
        &db,
        &QueryLogFilter {
            from: Some(BASE_TS + 1_000),
            to: Some(BASE_TS + 2_000),
            limit: Some(53),
            ..Default::default()
        },
        1_000,
    )
    .await;
    assert_eq!(range_rows.len(), 1_001 * 5, "time-range filter count");
    assert_strictly_descending(&range_rows);

    // 5. A cursor is bound to its filter set, not to the data snapshot.
    let first = db
        .query_logs(&QueryLogFilter {
            limit: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();
    let cursor = first.next_cursor.expect("100k rows have another page");
    let err = db
        .query_logs(&QueryLogFilter {
            status: Some("blocked".into()),
            limit: Some(10),
            cursor: Some(cursor.clone()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, StatsError::InvalidCursor(_)),
        "filter-mismatched cursor must be rejected, got {err}"
    );

    let err = db
        .query_logs(&QueryLogFilter {
            from: Some(BASE_TS + 1),
            limit: Some(10),
            cursor: Some(cursor),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, StatsError::InvalidCursor(_)),
        "changing any bound filter field must invalidate the cursor, got {err}"
    );
}

#[tokio::test]
async fn test_invalid_cursor_is_rejected_before_any_rows_are_read() {
    let db = StatsDb::in_memory().await.unwrap();
    db.insert_batch(&[QueryLogEntry::new(
        BASE_TS,
        "192.0.2.1",
        None,
        "cursor.example",
        1,
        Some(0),
        "allowed",
        "udp",
    )])
    .await
    .unwrap();

    for bad in ["", "not base64!!", "AAAA", "e30"] {
        let err = db
            .query_logs(&QueryLogFilter {
                cursor: Some(bad.into()),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, StatsError::InvalidCursor(_)),
            "'{bad}' must be rejected as InvalidCursor, got {err}"
        );
    }
}

/// Inserts newer rows between pages: a keyset cursor must not re-read or skip
/// rows that were already in range. New rows are visible only to requests that
/// start a fresh page above them.
#[tokio::test]
async fn test_insert_newer_rows_between_pages_does_not_duplicate_or_skip() {
    const SEEDED: usize = 2_000;
    const LIMIT: usize = 50;

    let dir = temp_dir("insert-between-pages");
    let db_path = dir.join("stats.db");
    let db = StatsDb::open(&db_path).await.unwrap();

    let entries: Vec<_> = (0..SEEDED)
        .map(|i| {
            QueryLogEntry::new(
                BASE_TS + i64::try_from(i).unwrap(),
                "192.0.2.10",
                None,
                "seed.example",
                1,
                Some(0),
                "allowed",
                "udp",
            )
        })
        .collect();
    db.insert_batch(&entries).await.unwrap();

    let first = db
        .query_logs(&QueryLogFilter {
            limit: Some(LIMIT),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(first.items.len(), LIMIT);
    let first_ids: HashSet<i64> = first
        .items
        .iter()
        .map(|entry| entry.id.expect("id"))
        .collect();
    let cursor = first.next_cursor.clone().expect("more seeded rows");

    // Newer than every seeded row: above the cursor, so later pages must not
    // see them. A fresh first page must see them first.
    let newer: Vec<_> = (0..25)
        .map(|i| {
            QueryLogEntry::new(
                BASE_TS + 5_000 + i64::from(i),
                "192.0.2.11",
                None,
                "newer.example",
                1,
                Some(0),
                "allowed",
                "udp",
            )
        })
        .collect();
    db.insert_batch(&newer).await.unwrap();
    let new_ids: HashSet<i64> =
        sqlx::query_scalar::<_, i64>("SELECT id FROM query_log WHERE qname = 'newer.example'")
            .fetch_all(db.pool())
            .await
            .unwrap()
            .into_iter()
            .collect();
    assert_eq!(new_ids.len(), newer.len());

    let (rest, _) = walk_collect(
        &db,
        &QueryLogFilter {
            cursor: Some(cursor),
            limit: Some(LIMIT),
            ..Default::default()
        },
        100,
    )
    .await;
    let rest_ids: HashSet<i64> = rest.iter().map(|(_, id)| *id).collect();

    assert_eq!(
        rest_ids.len() + first_ids.len(),
        SEEDED,
        "the original walk must still return every seeded row exactly once"
    );
    assert!(
        first_ids.intersection(&rest_ids).next().is_none(),
        "no seeded row may be duplicated across the insert"
    );
    assert!(
        new_ids.is_disjoint(&rest_ids),
        "newer rows are above the cursor and must not appear in later pages"
    );
    assert_strictly_descending(&rest);

    // A fresh first page observes the newer rows, newest first.
    let fresh = db
        .query_logs(&QueryLogFilter {
            limit: Some(25),
            ..Default::default()
        })
        .await
        .unwrap();
    let fresh_ids: HashSet<i64> = fresh
        .items
        .iter()
        .map(|entry| entry.id.expect("id"))
        .collect();
    assert_eq!(fresh_ids, new_ids, "new rows are visible on a fresh page");
    let fresh_keys: Vec<(i64, i64)> = fresh
        .items
        .iter()
        .map(|entry| (entry.ts, entry.id.expect("id")))
        .collect();
    assert_strictly_descending(&fresh_keys);

    // Continuing from that fresh page reaches the seeded tail without overlap.
    let after_fresh = db
        .query_logs(&QueryLogFilter {
            cursor: fresh.next_cursor.clone(),
            limit: Some(25),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        after_fresh
            .items
            .iter()
            .all(|entry| !new_ids.contains(&entry.id.expect("id"))),
        "the page after the new rows must be seeded rows"
    );

    cleanup(db, &dir).await;
}

/// Deletes rows between pages: the cursor stays a valid position, already-read
/// rows do not repeat, and rows deleted ahead simply disappear (no snapshot).
#[tokio::test]
async fn test_delete_rows_between_pages_keeps_cursor_valid() {
    const SEEDED: usize = 2_000;
    const LIMIT: usize = 50;

    let dir = temp_dir("delete-between-pages");
    let db_path = dir.join("stats.db");
    let db = StatsDb::open(&db_path).await.unwrap();

    // Unique, ascending timestamps mean ids are 1..=SEEDED in insert order.
    let entries: Vec<_> = (0..SEEDED)
        .map(|i| {
            QueryLogEntry::new(
                BASE_TS + i64::try_from(i).unwrap(),
                "192.0.2.20",
                None,
                "delete.example",
                1,
                Some(0),
                "allowed",
                "udp",
            )
        })
        .collect();
    db.insert_batch(&entries).await.unwrap();

    let first = db
        .query_logs(&QueryLogFilter {
            limit: Some(LIMIT),
            ..Default::default()
        })
        .await
        .unwrap();
    let first_ids: HashSet<i64> = first
        .items
        .iter()
        .map(|entry| entry.id.expect("id"))
        .collect();
    let cursor = first.next_cursor.clone().expect("more seeded rows");

    // Page 1 is newest-first: ids SEEDED..=SEEDED-LIMIT+1. Delete the very
    // next row (the first row the cursor would return) and an already-read row.
    let deleted_ahead = i64::try_from(SEEDED - LIMIT).unwrap();
    let deleted_behind = i64::try_from(SEEDED).unwrap();
    assert!(first_ids.contains(&deleted_behind));
    for id in [deleted_ahead, deleted_behind] {
        let affected = sqlx::query("DELETE FROM query_log WHERE id = ?")
            .bind(id)
            .execute(db.pool())
            .await
            .unwrap()
            .rows_affected();
        assert_eq!(affected, 1, "delete id {id}");
    }

    // The cursor still decodes and pages; data changes do not alter the filter
    // binding. The deleted-ahead row is absent, the deleted-behind row was
    // already returned, and every other seeded row appears exactly once.
    let (rest, _) = walk_collect(
        &db,
        &QueryLogFilter {
            cursor: Some(cursor),
            limit: Some(LIMIT),
            ..Default::default()
        },
        100,
    )
    .await;

    let rest_ids: HashSet<i64> = rest.iter().map(|(_, id)| *id).collect();
    assert!(
        !rest_ids.contains(&deleted_ahead),
        "a row deleted ahead of the cursor must not be returned"
    );
    assert!(
        !rest_ids.contains(&deleted_behind),
        "an already-returned deleted row must not repeat"
    );
    assert!(
        first_ids.intersection(&rest_ids).next().is_none(),
        "no row may be duplicated across the delete"
    );
    assert_eq!(
        rest_ids.len() + first_ids.len(),
        SEEDED - 1,
        "only the row deleted ahead may be missing"
    );
    assert_strictly_descending(&rest);

    cleanup(db, &dir).await;
}

/// Gated 1M-row scale test.
///
/// Not part of default CI. It seeds 1M deterministic rows and walks every page
/// with the maximum page size while keeping O(page) memory. Bounds are printed
/// and asserted; the measured runtimes are recorded in the A7 report.
#[tokio::test]
#[ignore = "1M-row scale test; run explicitly with --ignored --nocapture"]
async fn test_1m_cursor_walk_completes_within_documented_bounds() {
    const ROWS: usize = 1_000_000;
    const LIMIT: usize = 500;

    let db = StatsDb::in_memory().await.unwrap();

    let seed_started = Instant::now();
    seed_rows(&db, ROWS).await;
    let seed_elapsed = seed_started.elapsed();
    println!("A7 1M seed: {ROWS} rows in {seed_elapsed:?}");
    assert!(
        seed_elapsed < ONE_MILLION_SEED_BOUND,
        "1M seeding took {seed_elapsed:?}, above the documented bound {ONE_MILLION_SEED_BOUND:?}"
    );

    let walk_started = Instant::now();
    let summary = walk_bounded(
        &db,
        &QueryLogFilter {
            limit: Some(LIMIT),
            ..Default::default()
        },
        ROWS.div_ceil(LIMIT) + 10,
    )
    .await;
    let walk_elapsed = walk_started.elapsed();
    let rows_per_sec = summary.rows as f64 / walk_elapsed.as_secs_f64().max(f64::EPSILON);
    println!(
        "A7 1M walk: {} rows across {} pages in {:?} ({rows_per_sec:.0} rows/s), \
         last page {} rows, max page {} rows",
        summary.rows, summary.pages, walk_elapsed, summary.last_page_len, summary.max_page_len
    );

    assert_eq!(summary.rows, ROWS, "every row must be seen exactly once");
    assert_eq!(
        summary.pages,
        ROWS.div_ceil(LIMIT),
        "the walk must take exactly ceil(rows/limit) pages"
    );
    assert_eq!(summary.max_page_len, LIMIT);
    assert!(
        summary.last_page_len > 0 && summary.last_page_len <= LIMIT,
        "the final page must be non-empty and within the limit"
    );
    assert!(
        walk_elapsed < ONE_MILLION_WALK_BOUND,
        "1M walk took {walk_elapsed:?}, above the documented bound {ONE_MILLION_WALK_BOUND:?}"
    );
}
