//! Task B6: gated 1M-row / 90-day DB capacity and soak evidence.
//!
//! These are evidence tests, not unit tests, and are `#[ignore]`d so the
//! default CI suite stays fast. They write a deterministic fixture to a real
//! SQLite file (WAL) because the file size and the on-disk vacuum behavior are
//! part of the measurement.
//!
//! Run them explicitly (single-threaded so the process-RSS number is not
//! polluted by a second test running in parallel):
//!
//! ```text
//! cargo test -p sito-stats --all-features --lib db::capacity_tests \
//!     -- --ignored --nocapture --test-threads=1
//! ```
//!
//! The absolute numbers are dev-machine observations, not a production SLA.
//! The assertions are deliberately generous: they catch accidental quadratic
//! behavior and an unbounded whole-table transaction, while the printed
//! measurements are the actual evidence recorded in the B6 report and
//! `docs/2.0-migration.md`.
//!
//! The 1M test covers, on one seeded database, in this order:
//!
//! 1. 90-day retention (`retention_days = 90`) expiring the oldest two days,
//!    including a partially expired hour at the cutoff.
//! 2. the full-scale chunked `keep_aggregates` clear of every remaining row.
//! 3. backdated rows inserted into an already-aggregated hour, re-aggregated
//!    exactly once (no double count, watermark not lowered).
//!
//! Rollup counters are checked against the fixture totals before and after both
//! paths, so a single row counted twice or lost fails the test.
//!
//! The chunk count a report returns is produced by the implementation itself,
//! so on its own it only proves loop iterations. To independently pin
//! transaction boundaries, each measured sweep runs with a second pooled
//! connection polling `stats_hourly` and `PRAGMA data_version`. Committed
//! rollup rows must become visible *while* the sweep is still running, and
//! `data_version` (which changes when another connection commits) must change
//! multiple times. A regression that wrapped the outer loop in one
//! `BEGIN IMMEDIATE`/`COMMIT` while keeping the counter would show zero
//! intermediate commits and fail.

use super::*;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Total fixture rows: one million.
const FIXTURE_ROWS: i64 = 1_000_000;

/// Rows distributed uniformly over the 90-day (2,160-hour) window.
const UNIFORM_ROWS: i64 = 940_000;

/// Extra rows concentrated in one heavy hour, to sub-chunk a busy hour.
const HEAVY_ROWS: i64 = 60_000;

/// Fixture span in days.
const FIXTURE_DAYS: i64 = 90;

/// Hours in the fixture span.
const FIXTURE_HOURS: i64 = FIXTURE_DAYS * 24;

/// The oldest fixture hour is this many days before the current hour. Two days
/// of margin means `retention_days = 90` expires the oldest two days (plus a
/// partial hour at the cutoff) while the newest row is ~2 days old, exactly at
/// the capacity point a 90-day deployment reaches.
const BASE_AGE_DAYS: i64 = 92;

/// Day and hour (inside the retained window) holding the heavy hour.
const HEAVY_DAY: i64 = 30;
const HEAVY_HOUR_OF_DAY: i64 = 12;

const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;

/// Generous debug-build crash guards. These are **not** performance targets.
const SEED_BOUND: Duration = Duration::from_secs(600);
const RETENTION_BOUND: Duration = Duration::from_secs(600);
const CLEAR_BOUND: Duration = Duration::from_secs(600);
const ANONYMIZE_BOUND: Duration = Duration::from_secs(600);

/// A gross memory-blowup guard, not a memory bound. The observed whole-process
/// peak is 16-34 MiB (the progress probe contributes a polling connection);
/// this ceiling is ~15x that and would catch a design that pulled the whole
/// 1M-row table (or a large batch of it) into Rust. The printed
/// `VmHWM`/`VmRSS` values are the actual observation.
const PEAK_RSS_CEILING_KIB: u64 = 512_000;

/// Exact timestamp-distribution shape of the 90-day fixture, computed from the
/// deterministic seed formula. Most timestamps are shared by seven consecutive
/// rows; the rest are the batch groups split by an hour (or uniform/heavy
/// slice) boundary.
const FIXTURE_DISTINCT_TIMESTAMPS: i64 = 144_711;
const FIXTURE_TIMESTAMPS_WITH_SEVEN_ROWS: i64 = 141_004;
const FIXTURE_MAX_ROWS_PER_TIMESTAMP: i64 = 7;

struct FixtureSummary {
    base_hour_ms: i64,
    heavy_hour: i64,
    total_blocked: i64,
    total_cached: i64,
    distinct_hours: i64,
    newest_ts: i64,
}

fn fixture_base_hour_ms() -> i64 {
    let now_ms = chrono::Utc::now().timestamp_millis();
    (now_ms / HOUR_MS) * HOUR_MS - BASE_AGE_DAYS * DAY_MS
}

/// Deterministic 1M-row / 90-day fixture.
///
/// Distribution: uniform over 2,160 epoch hours (`ts` aligned to real hours);
/// most seven-row batches share one timestamp (141,004 of 144,711 timestamps;
/// the rest are batches split by an hour or slice boundary) so `(ts, id)` chunk
/// boundaries fall inside same-timestamp batches; six qtypes, three verdicts,
/// two upstreams, many clients/names and 5,000 domains. The heavy hour is day
/// 30 at 12:00 and holds 60,000 extra rows plus the uniform rows for that hour.
async fn seed_fixture(db: &StatsDb, rows: i64, base_hour_ms: i64) -> FixtureSummary {
    // Keep the full-fixture uniform/heavy ratio for smaller subsets.
    let uniform_rows = UNIFORM_ROWS * rows / FIXTURE_ROWS;
    // Fixture hours are real epoch hours: oldest = `base_hour_ms`.
    let heavy_hour = base_hour_ms + HEAVY_DAY * DAY_MS + HEAVY_HOUR_OF_DAY * HOUR_MS;
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
            (CASE WHEN x < ?
                  THEN ? + (((x * ?) / ?) / 24) * ? + (((x * ?) / ?) % 24) * ?
                  ELSE ?
             END)
            -- Seven consecutive rows share a millisecond; the multiplier
            -- scatters those batches across the full hour.
            + (((x / 7) * 7919) % 360000) * 10,
            printf('198.51.%d.%d', (x / 256) % 256, x % 256),
            CASE WHEN x % 3 = 0 THEN printf('device-%d', x % 200) ELSE NULL END,
            printf('host-%d.example.com', x % 5000),
            CASE x % 20 WHEN 0 THEN 28 WHEN 1 THEN 16 WHEN 2 THEN 65
                        WHEN 3 THEN 15 WHEN 4 THEN 12 ELSE 1 END,
            CASE WHEN x % 13 = 0 THEN 3 ELSE 0 END,
            CASE WHEN x % 5 = 0 THEN 'blocked'
                 WHEN x % 97 = 0 THEN 'stale'
                 ELSE 'allowed' END,
            CASE WHEN x % 11 = 0 THEN 'cache' ELSE NULL END,
            CASE WHEN x % 5 = 0 THEN 'blocklist' ELSE NULL END,
            CASE WHEN x % 2 = 0 THEN 'tls://1.1.1.1:853'
                 ELSE 'tls://9.9.9.9:853' END,
            100 + (x % 20000),
            CASE WHEN x % 11 = 0 THEN 'insecure' ELSE 'secure' END,
            CASE WHEN x % 7 = 0 THEN 'doh'
                 WHEN x % 5 = 0 THEN 'dot'
                 ELSE 'udp' END
        FROM seq
        ",
    )
    .bind(rows)
    .bind(uniform_rows)
    .bind(base_hour_ms)
    .bind(FIXTURE_HOURS)
    .bind(uniform_rows)
    .bind(DAY_MS)
    .bind(FIXTURE_HOURS)
    .bind(uniform_rows)
    .bind(HOUR_MS)
    .bind(heavy_hour)
    .execute(db.pool())
    .await
    .expect("seed deterministic capacity fixture");
    fixture_summary(db, base_hour_ms, heavy_hour).await
}

async fn fixture_summary(db: &StatsDb, base_hour_ms: i64, heavy_hour: i64) -> FixtureSummary {
    let (_, blocked, cached, hours, newest): (i64, i64, i64, i64, i64) = sqlx::query_as(
        r"
        SELECT COUNT(*),
               COALESCE(SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN rule IN ('cache', 'stale_cache')
                                  OR verdict = 'stale' THEN 1 ELSE 0 END), 0),
               COUNT(DISTINCT ts / 3600000),
               COALESCE(MAX(ts), 0)
        FROM query_log
        ",
    )
    .fetch_one(db.pool())
    .await
    .expect("fixture totals");
    FixtureSummary {
        base_hour_ms,
        heavy_hour,
        total_blocked: blocked,
        total_cached: cached,
        distinct_hours: hours,
        newest_ts: newest,
    }
}

/// A rollup total triple: `(queries, blocked, cached)`.
async fn rollup_totals(db: &StatsDb) -> (i64, i64, i64) {
    sqlx::query_as(
        r"
        SELECT COALESCE(SUM(queries), 0),
               COALESCE(SUM(blocked), 0),
               COALESCE(SUM(cached), 0)
        FROM stats_hourly
        ",
    )
    .fetch_one(db.pool())
    .await
    .expect("rollup totals")
}

async fn detailed_rows(db: &StatsDb) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM query_log")
        .fetch_one(db.pool())
        .await
        .expect("detailed row count")
}

/// Expected number of committed 5,000-row chunks for the rows currently in
/// `query_log`: the per-hour ceiling sum. Equality with a report's `chunks`
/// proves every transaction was row-bounded (the chunk cursor uses
/// `LIMIT 1 OFFSET 5000`).
async fn expected_chunks(db: &StatsDb) -> i64 {
    sqlx::query_scalar(
        r"
        SELECT COALESCE(SUM((c + 4999) / 5000), 0)
        FROM (SELECT ts / 3600000 AS hour, COUNT(*) AS c
              FROM query_log GROUP BY hour)
        ",
    )
    .fetch_one(db.pool())
    .await
    .expect("expected chunk count")
}

async fn busiest_hour(db: &StatsDb) -> (i64, i64) {
    sqlx::query_as(
        r"
        SELECT ts / 3600000, COUNT(*)
        FROM query_log
        GROUP BY ts / 3600000
        ORDER BY COUNT(*) DESC, ts / 3600000 ASC
        LIMIT 1
        ",
    )
    .fetch_one(db.pool())
    .await
    .expect("busiest hour")
}

/// Peak and current resident set size from `/proc/self/status`, in KiB.
fn rss_kib(field: &str) -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            return rest
                .trim_start_matches(':')
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok());
        }
    }
    None
}

fn print_memory(label: &str) {
    println!(
        "B6 {label}: VmHWM={:?} KiB, VmRSS={:?} KiB",
        rss_kib("VmHWM"),
        rss_kib("VmRSS")
    );
}

fn assert_bounded_memory(label: &str) {
    if let Some(peak) = rss_kib("VmHWM") {
        assert!(
            peak < PEAK_RSS_CEILING_KIB,
            "{label}: process VmHWM {peak} KiB exceeds the {PEAK_RSS_CEILING_KIB} KiB crash guard"
        );
    }
}

/// Removes the fixture directory when the test ends, including on panic, so a
/// failed 1M run cannot leave a 200+ MiB database plus WAL behind. Declare it
/// before the `StatsDb` so unwinding drops the pool first.
struct TempDbDir(PathBuf);

impl TempDbDir {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "sito-stats-capacity-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).expect("create capacity temp dir");
        Self(dir)
    }

    fn db_path(&self) -> PathBuf {
        self.0.join("stats.db")
    }
}

impl Drop for TempDbDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Independent evidence of committed progress during a sweep.
struct ProgressReport {
    samples: u64,
    /// Lower bound on commits made by the sweep: `PRAGMA data_version` (read on
    /// a second connection) changes at most once per poll interval, so several
    /// commits between samples collapse into one observation.
    commits: u64,
    /// Samples where the committed `stats_hourly` row count was strictly
    /// between its initial and final value.
    partial_rollups: u64,
    initial_rollups: i64,
    final_rollups: i64,
}

async fn progress_snapshot(conn: &mut SqliteConnection) -> (i64, i64) {
    // `stats_hourly` is the rollup table: each committed chunk adds or updates
    // at most one row, so its row count is a cheap committed-progress signal.
    let rollups: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stats_hourly")
        .fetch_one(&mut *conn)
        .await
        .expect("progress probe rollup count");
    // Read on the same pinned connection: SQLite changes this value when any
    // *other* connection commits, giving an independent commit-boundary signal.
    let data_version: i64 = sqlx::query_scalar("PRAGMA data_version")
        .fetch_one(&mut *conn)
        .await
        .expect("progress probe data_version");
    (rollups, data_version)
}

/// Runs `future` while a second pooled connection polls committed state.
///
/// The sweep future is polled by the same task via `select!` (no extra runtime
/// thread), so this works on the default current-thread `#[tokio::test]`
/// runtime. The returned duration covers only the sweep future; the probe adds
/// a small amount of read load.
async fn run_with_progress<F, T>(
    db: &StatsDb,
    label: &str,
    future: F,
) -> (T, Duration, ProgressReport)
where
    F: std::future::Future<Output = T>,
{
    let mut conn = db
        .pool()
        .acquire()
        .await
        .expect("progress probe connection");
    let (initial_rollups, initial_version) = progress_snapshot(&mut conn).await;
    let mut last_version = initial_version;
    let mut commits = 0u64;
    let mut samples = Vec::new();
    // Sampling every 20 ms keeps the read load small (the probe must not distort
    // the measured wall time) while still observing hundreds of commits on the
    // multi-second sweeps.
    let mut ticker = tokio::time::interval(Duration::from_millis(20));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    tokio::pin!(future);
    let started = Instant::now();
    let value = loop {
        tokio::select! {
            value = &mut future => break value,
            _ = ticker.tick() => {
                let (rollups, version) = progress_snapshot(&mut conn).await;
                if version != last_version {
                    commits += 1;
                    last_version = version;
                }
                samples.push(rollups);
            }
        }
    };
    let elapsed = started.elapsed();
    let (final_rollups, final_version) = progress_snapshot(&mut conn).await;
    if final_version != last_version {
        commits += 1;
    }
    let partial_rollups = samples
        .iter()
        .filter(|&&rollups| rollups > initial_rollups && rollups < final_rollups)
        .count() as u64;
    let report = ProgressReport {
        samples: samples.len() as u64,
        commits,
        partial_rollups,
        initial_rollups,
        final_rollups,
    };
    println!(
        "B6 progress probe ({label}): samples={}, distinct_commits_observed={}, \
         partial_rollup_samples={}, rollup_rows {}->{}",
        report.samples,
        report.commits,
        report.partial_rollups,
        report.initial_rollups,
        report.final_rollups
    );
    (value, elapsed, report)
}

/// Asserts that the second connection observed multiple distinct commits.
/// `min_commits` is a conservative floor on the polling-observed count, which
/// collapses commits that happen between two samples.
fn assert_multiple_commits(report: &ProgressReport, label: &str, min_commits: u64) {
    assert!(
        report.commits >= min_commits,
        "{label}: the second connection observed only {} distinct commits, expected at least \
         {min_commits}; the run may have wrapped everything in one transaction",
        report.commits
    );
}

/// Asserts that a sweep was observably committed incrementally, not one
/// transaction around the whole loop.
fn assert_incremental_commits(report: &ProgressReport, label: &str, min_commits: u64) {
    assert_multiple_commits(report, label, min_commits);
    assert!(
        report.partial_rollups >= 1,
        "{label}: committed stats_hourly rows never appeared between {} and {} during the \
         sweep; progress was not visible mid-run",
        report.initial_rollups,
        report.final_rollups
    );
}

/// Exact fixture-shape assertions: 90 real hours, six qtypes, and the
/// deterministic same-timestamp batch distribution.
async fn assert_fixture_shape(db: &StatsDb) {
    let (distinct, max_per_ts, seven_row_ts): (i64, i64, i64) = sqlx::query_as(
        r"
        SELECT COUNT(*), COALESCE(MAX(c), 0),
               COALESCE(SUM(CASE WHEN c = 7 THEN 1 ELSE 0 END), 0)
        FROM (SELECT ts, COUNT(*) AS c FROM query_log GROUP BY ts)
        ",
    )
    .fetch_one(db.pool())
    .await
    .expect("fixture timestamp distribution");
    assert_eq!(
        distinct, FIXTURE_DISTINCT_TIMESTAMPS,
        "deterministic fixture must produce the documented timestamp distribution"
    );
    assert_eq!(max_per_ts, FIXTURE_MAX_ROWS_PER_TIMESTAMP);
    assert_eq!(
        seven_row_ts, FIXTURE_TIMESTAMPS_WITH_SEVEN_ROWS,
        "most batch groups share one timestamp; only boundary groups split"
    );

    let qtypes: Vec<i64> =
        sqlx::query_scalar("SELECT DISTINCT qtype FROM query_log ORDER BY qtype")
            .fetch_all(db.pool())
            .await
            .expect("fixture qtypes");
    assert_eq!(qtypes, vec![1, 12, 15, 16, 28, 65], "six qtypes");
}

/// Gated 1M-row / 90-day retention + chunked clear + backdated-row evidence.
#[tokio::test]
#[ignore = "1M-row / 90-day capacity evidence; run explicitly with --ignored --nocapture"]
async fn test_1m_rows_90_days_retention_clear_and_backdated() {
    let dir = TempDbDir::new("1m-90d");
    let db = StatsDb::open(dir.db_path()).await.unwrap();
    let base_hour_ms = fixture_base_hour_ms();

    // ---- Fixture ---------------------------------------------------------
    let seed_started = Instant::now();
    let fixture = seed_fixture(&db, FIXTURE_ROWS, base_hour_ms).await;
    let seed_elapsed = seed_started.elapsed();
    let seeded_size = db.db_size_bytes().await.unwrap();
    println!(
        "B6 fixture: {FIXTURE_ROWS} rows, {} hours, seed {:?}, DB {:.1} MiB",
        fixture.distinct_hours,
        seed_elapsed,
        seeded_size as f64 / (1024.0 * 1024.0)
    );
    println!(
        "B6 fixture totals: blocked={}, cached={}, newest_ts={}, base_hour_ms={}",
        fixture.total_blocked, fixture.total_cached, fixture.newest_ts, fixture.base_hour_ms
    );
    assert!(
        seed_elapsed < SEED_BOUND,
        "1M seed took {seed_elapsed:?}, above the {SEED_BOUND:?} crash guard"
    );
    assert_eq!(
        fixture.distinct_hours, FIXTURE_HOURS,
        "the fixture must span exactly 90 days"
    );
    let (busy_hour_index, busy_rows) = busiest_hour(&db).await;
    assert_eq!(
        busy_hour_index * HOUR_MS,
        fixture.heavy_hour,
        "heavy hour must be day 30/12:00"
    );
    assert!(
        busy_rows >= HEAVY_ROWS,
        "the heavy hour must hold at least the {HEAVY_ROWS} concentrated rows, got {busy_rows}"
    );
    println!(
        "B6 heavy hour {}: {busy_rows} rows -> {} chunks at 5,000 rows",
        fixture.heavy_hour,
        (busy_rows + 4_999) / 5_000
    );
    assert!(
        (busy_rows - 1) / 5000 >= 10,
        "the heavy hour must be sub-chunked into >10 chunks"
    );
    assert_fixture_shape(&db).await;
    print_memory("after seed");

    // Compact once so the retention/clear sizes start from a vacuumed file.
    let vacuum_started = Instant::now();
    db.vacuum().await.unwrap();
    let vacuum_elapsed = vacuum_started.elapsed();
    let compacted_size = db.db_size_bytes().await.unwrap();
    println!(
        "B6 post-seed vacuum: {:?}, DB {:.1} MiB (from {:.1} MiB)",
        vacuum_elapsed,
        compacted_size as f64 / (1024.0 * 1024.0),
        seeded_size as f64 / (1024.0 * 1024.0)
    );

    // ---- 90-day retention ------------------------------------------------
    let (retention, retention_elapsed, retention_progress) = run_with_progress(
        &db,
        "retention(90d)",
        db.cleanup_retention_with_policy(90, 365, false),
    )
    .await;
    let retention = retention.expect("90-day retention sweep");
    assert_incremental_commits(&retention_progress, "retention(90d)", 5);
    let remaining = detailed_rows(&db).await;
    let after_retention_size = db.db_size_bytes().await.unwrap();
    let retention_rollups = rollup_totals(&db).await;
    println!(
        "B6 retention(90d): {:?}, deleted={}, aggregated_hours={}, chunks={}, \
         remaining_rows={}, DB {:.1} MiB",
        retention_elapsed,
        retention.deleted_records,
        retention.aggregated_hours,
        retention.chunks,
        remaining,
        after_retention_size as f64 / (1024.0 * 1024.0)
    );
    assert!(
        retention_elapsed < RETENTION_BOUND,
        "retention took {retention_elapsed:?}, above the {RETENTION_BOUND:?} crash guard"
    );
    assert_eq!(
        retention.deleted_records + u64::try_from(remaining).unwrap(),
        u64::try_from(FIXTURE_ROWS).unwrap(),
        "every fixture row is either pruned or still present"
    );
    assert!(
        (48..=50).contains(&retention.aggregated_hours),
        "a 90-day deadline over a 92-day fixture must expire the oldest ~2 days \
         (48 full hours plus a partial cutoff hour), got {} hours",
        retention.aggregated_hours
    );
    assert_eq!(
        retention.chunks, retention.aggregated_hours,
        "each expired hour has <5,000 rows, so it must be exactly one bounded chunk"
    );
    assert_eq!(
        retention_rollups.0,
        i64::try_from(retention.deleted_records).unwrap(),
        "the retention rollups must account for exactly the deleted rows once"
    );
    assert!(
        retention_rollups.1 <= fixture.total_blocked && retention_rollups.2 <= fixture.total_cached,
        "retention rollups must not exceed the fixture totals"
    );
    assert!(
        after_retention_size < compacted_size,
        "a retention sweep that removed rows must shrink the vacuumed DB \
         ({after_retention_size} >= {compacted_size})"
    );
    assert_bounded_memory("after retention");
    print_memory("after retention");

    // ---- keep_aggregates clear (full remaining fixture) ------------------
    let expected_clear_chunks = expected_chunks(&db).await;
    let (clear_report, clear_elapsed, clear_progress) = run_with_progress(
        &db,
        "keep-aggregates clear",
        db.rollup_and_delete_range(i64::MIN, i64::MAX, false),
    )
    .await;
    let clear_report = clear_report.expect("chunked keep-aggregates clear");
    assert_incremental_commits(&clear_progress, "keep-aggregates clear", 50);
    println!(
        "B6 keep-aggregates clear: {:?}, deleted={}, aggregated_hours={}, chunks={}",
        clear_elapsed,
        clear_report.deleted_records,
        clear_report.aggregated_hours,
        clear_report.chunks
    );
    assert!(
        clear_elapsed < CLEAR_BOUND,
        "clear took {clear_elapsed:?}, above the {CLEAR_BOUND:?} crash guard"
    );
    assert_eq!(
        u64::try_from(remaining).unwrap(),
        clear_report.deleted_records,
        "the clear must delete exactly the rows retention left"
    );
    assert_eq!(
        i64::try_from(clear_report.chunks).unwrap(),
        expected_clear_chunks,
        "the implementation's chunk counter must equal the per-hour 5,000-row \
         ceiling sum (expected {expected_clear_chunks}); the progress probe \
         above independently observed committed rollups mid-run"
    );
    assert_eq!(
        detailed_rows(&db).await,
        0,
        "the clear must empty query_log"
    );
    assert_eq!(
        rollup_totals(&db).await,
        (FIXTURE_ROWS, fixture.total_blocked, fixture.total_cached),
        "retention + clear must account for every fixture row exactly once \
         (no lost or doubled counters)"
    );

    // Complete the public clear path's maintenance step, as
    // `delete_query_logs_with_policy` does after >=1,000 deletions.
    let vacuum_started = Instant::now();
    db.vacuum().await.unwrap();
    let clear_vacuum_elapsed = vacuum_started.elapsed();
    let after_clear_size = db.db_size_bytes().await.unwrap();
    println!(
        "B6 clear vacuum: {:?}, DB {:.1} MiB (from {:.1} MiB); \
         VmHWM={:?} KiB",
        clear_vacuum_elapsed,
        after_clear_size as f64 / (1024.0 * 1024.0),
        after_retention_size as f64 / (1024.0 * 1024.0),
        rss_kib("VmHWM")
    );
    assert!(
        after_clear_size < after_retention_size,
        "clearing the remaining detailed rows must shrink the DB"
    );
    assert_bounded_memory("after clear");

    // ---- Backdated rows into an already-aggregated hour ------------------
    // The oldest two days were aggregated by retention, then the clear folded
    // the rest. Insert 1,000 new rows into an hour both already processed.
    let backdated_hour = fixture.base_hour_ms + 5 * HOUR_MS;
    let backdated_blocked = 250i64;
    let backdated_cached = 90i64;
    let hour_already_aggregated: i64 =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM stats_hourly WHERE hour = ?)")
            .bind(backdated_hour)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(
        hour_already_aggregated, 1,
        "the backdated target hour must already have a rollup row before the insert"
    );
    let before_backdated = rollup_totals(&db).await;
    let entries: Vec<QueryLogEntry> = (0..1_000i64)
        .map(|i| {
            let mut entry = QueryLogEntry::new(
                backdated_hour + i,
                format!("203.0.113.{}", i % 200 + 1),
                Some("backdated-device".into()),
                "backdated.example",
                1,
                Some(0),
                if i < backdated_blocked {
                    "blocked"
                } else {
                    "allowed"
                },
                "udp",
            );
            if i >= backdated_blocked && i < backdated_blocked + backdated_cached {
                entry.rule = Some("cache".into());
            }
            entry
        })
        .collect();
    db.insert_batch(&entries).await.unwrap();
    assert_eq!(detailed_rows(&db).await, 1_000);

    let backdated_started = Instant::now();
    let backdated_report = db
        .rollup_and_delete_range(i64::MIN, i64::MAX, false)
        .await
        .expect("backdated clear");
    let backdated_clear_elapsed = backdated_started.elapsed();
    // The public clear path vacuums after >=1,000 deleted rows. Mirror it so
    // the recorded wall time and DB size describe the public behavior, not
    // just the range helper.
    let backdated_vacuum_started = Instant::now();
    db.vacuum().await.unwrap();
    let backdated_vacuum_elapsed = backdated_vacuum_started.elapsed();
    let backdated_elapsed = backdated_clear_elapsed + backdated_vacuum_elapsed;
    println!(
        "B6 backdated clear: total {:?} (clear {:?}, vacuum {:?}), deleted={}, hours={}, \
         chunks={}",
        backdated_elapsed,
        backdated_clear_elapsed,
        backdated_vacuum_elapsed,
        backdated_report.deleted_records,
        backdated_report.aggregated_hours,
        backdated_report.chunks
    );
    assert_eq!(backdated_report.deleted_records, 1_000);
    assert_eq!(backdated_report.aggregated_hours, 1, "one old hour");
    assert_eq!(backdated_report.chunks, 1, "1,000 rows = one bounded chunk");
    assert_eq!(detailed_rows(&db).await, 0);
    assert_eq!(
        rollup_totals(&db).await,
        (
            before_backdated.0 + 1_000,
            before_backdated.1 + backdated_blocked,
            before_backdated.2 + backdated_cached,
        ),
        "backdated rows must be re-aggregated exactly once"
    );

    // Idempotent rerun: nothing to aggregate, totals unchanged.
    let rerun = db
        .rollup_and_delete_range(i64::MIN, i64::MAX, false)
        .await
        .unwrap();
    assert_eq!(rerun.deleted_records, 0);
    assert_eq!(rerun.chunks, 0);
    assert_eq!(
        rollup_totals(&db).await.0,
        FIXTURE_ROWS + 1_000,
        "a rerun must not double count"
    );

    // The watermark is a diagnostic: it records the highest processed ts and a
    // backdated insert must not lower it. (It is never read to skip rows; that
    // behavior is B7 and is asserted by the retention unit tests.)
    let (watermark_id, watermark_ts): (i64, i64) = sqlx::query_as(
        "SELECT last_id, last_ts FROM stats_watermark WHERE key = 'hourly_aggregation'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(watermark_id > 0);
    assert_eq!(
        watermark_ts, fixture.newest_ts,
        "the watermark must keep the highest processed timestamp, not the backdated one"
    );

    print_memory("after backdated clear");
    println!(
        "B6 final DB {:.1} MiB",
        db.db_size_bytes().await.unwrap() as f64 / (1024.0 * 1024.0)
    );
}

/// Gated full-backlog retention evidence: a 90-day/1M fixture drained by the
/// retention path itself.
///
/// The steady-state test above expires the oldest two days of a 90-day
/// deployment. This one models the other extreme: an operator lowers
/// `retention_days` (or the resolver was offline long enough that the whole
/// 90-day window is expired), so the sweep aggregates and prunes all 1M rows
/// through the same hour/chunk machinery. `retention_days = 1` is just the
/// deadline that makes the complete fixture expired; the path and chunking
/// under test are unchanged.
#[tokio::test]
#[ignore = "1M-row full-backlog retention evidence; run explicitly with --ignored --nocapture"]
async fn test_1m_rows_90_day_retention_full_backlog() {
    let dir = TempDbDir::new("1m-90d-backlog");
    let db = StatsDb::open(dir.db_path()).await.unwrap();
    let base_hour_ms = fixture_base_hour_ms();

    let seed_started = Instant::now();
    let fixture = seed_fixture(&db, FIXTURE_ROWS, base_hour_ms).await;
    let seed_elapsed = seed_started.elapsed();
    assert!(
        seed_elapsed < SEED_BOUND,
        "1M seed took {seed_elapsed:?}, above the {SEED_BOUND:?} crash guard"
    );
    let expected = expected_chunks(&db).await;
    db.vacuum().await.unwrap();
    let before_size = db.db_size_bytes().await.unwrap();
    println!(
        "B6 backlog fixture: {FIXTURE_ROWS} rows, {} hours, seed {:?}, \
         expected_chunks={expected}, DB {:.1} MiB",
        fixture.distinct_hours,
        seed_elapsed,
        before_size as f64 / (1024.0 * 1024.0)
    );
    assert_eq!(fixture.distinct_hours, FIXTURE_HOURS);

    // Newest fixture row is ~2 days old, so a 1-day deadline expires all rows.
    let (report, elapsed, progress) = run_with_progress(
        &db,
        "retention(full 90-day backlog)",
        db.cleanup_retention_with_policy(1, 365, false),
    )
    .await;
    let report = report.expect("full-backlog retention sweep");
    assert_incremental_commits(&progress, "retention(full 90-day backlog)", 50);
    let after_size = db.db_size_bytes().await.unwrap();
    println!(
        "B6 retention(1d deadline, 90-day backlog): {:?}, deleted={}, \
         aggregated_hours={}, chunks={}, DB {:.1} MiB",
        elapsed,
        report.deleted_records,
        report.aggregated_hours,
        report.chunks,
        after_size as f64 / (1024.0 * 1024.0)
    );
    assert!(
        elapsed < RETENTION_BOUND,
        "full-backlog retention took {elapsed:?}, above the {RETENTION_BOUND:?} crash guard"
    );
    assert_eq!(
        report.deleted_records,
        u64::try_from(FIXTURE_ROWS).unwrap(),
        "the 1-day deadline must expire the whole 90-day fixture"
    );
    assert_eq!(
        report.aggregated_hours,
        usize::try_from(FIXTURE_HOURS).unwrap(),
        "every fixture hour must be folded exactly once"
    );
    assert_eq!(
        i64::try_from(report.chunks).unwrap(),
        expected,
        "the implementation's chunk counter must equal the per-hour 5,000-row \
         ceiling sum (one per quiet hour, more for the heavy hour); the \
         progress probe above independently observed committed rollups mid-run"
    );
    assert_eq!(detailed_rows(&db).await, 0);
    assert_eq!(
        rollup_totals(&db).await,
        (FIXTURE_ROWS, fixture.total_blocked, fixture.total_cached),
        "the retention rollups must account for every row exactly once"
    );
    assert!(
        after_size < before_size,
        "the sweep must vacuum the cleared pages ({after_size} >= {before_size})"
    );
    assert_bounded_memory("after full-backlog retention");
    print_memory("after full-backlog retention");
}

/// Gated 100k-row retroactive anonymization evidence (B4 path).
#[tokio::test]
#[ignore = "100k-row anonymize capacity evidence; run explicitly with --ignored --nocapture"]
async fn test_100k_rows_anonymize_is_chunked_and_removes_pii() {
    const ROWS: i64 = 100_000;
    const CHUNK: usize = 1_000;

    let dir = TempDbDir::new("100k-anonymize");
    let db = StatsDb::open(dir.db_path()).await.unwrap();
    let base_hour_ms = fixture_base_hour_ms();

    let seed_started = Instant::now();
    seed_fixture(&db, ROWS, base_hour_ms).await;
    let seed_elapsed = seed_started.elapsed();
    db.vacuum().await.unwrap();
    let before_size = db.db_size_bytes().await.unwrap();
    let would_change: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM query_log \
         WHERE client_name IS NOT NULL OR client_ip NOT LIKE '%.0'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    println!(
        "B6 anonymize fixture: {ROWS} rows, seed {:?}, DB {:.1} MiB, would_change={would_change}",
        seed_elapsed,
        before_size as f64 / (1024.0 * 1024.0)
    );
    assert!(
        seed_elapsed < SEED_BOUND,
        "100k seed took {seed_elapsed:?}, above the {SEED_BOUND:?} crash guard"
    );
    assert!(would_change > 0, "the fixture must contain PII to rewrite");

    let (report, elapsed, progress) =
        run_with_progress(&db, "anonymize(100k)", db.anonymize_query_log(CHUNK)).await;
    let report = report.unwrap();
    // `stats_hourly` is not touched here, so there is no partial-rollup signal;
    // `data_version` changes still prove that the rewrite committed repeatedly
    // rather than in one transaction.
    assert_multiple_commits(&progress, "anonymize(100k)", 10);
    let after_size = db.db_size_bytes().await.unwrap();
    let chunk_i64 = i64::try_from(CHUNK).unwrap();
    let expected_chunks = (ROWS + chunk_i64 - 1) / chunk_i64;
    println!(
        "B6 anonymize: {:?}, processed={}, changed={}, already_anonymized={}, \
         unparseable={}, chunks={}, vacuumed={}, DB {:.1} MiB",
        elapsed,
        report.processed,
        report.changed,
        report.already_anonymized,
        report.unparseable,
        report.chunks,
        report.vacuumed,
        after_size as f64 / (1024.0 * 1024.0)
    );
    assert!(
        elapsed < ANONYMIZE_BOUND,
        "anonymize took {elapsed:?}, above the {ANONYMIZE_BOUND:?} crash guard"
    );
    assert_eq!(report.processed, u64::try_from(ROWS).unwrap());
    assert_eq!(report.changed, u64::try_from(would_change).unwrap());
    assert_eq!(report.unparseable, 0);
    assert_eq!(
        report.chunks,
        u64::try_from(expected_chunks).unwrap(),
        "the chunk counter must match ceil(rows / {CHUNK})"
    );
    assert!(report.vacuumed);

    // No PII remains: every IPv4 address is masked to /24 and every client
    // name is cleared. The raw last octet may already have been 0 for some
    // seeded rows, so the LIKE check is a necessary condition, and the name
    // check covers rows whose address was already masked.
    let remaining_pii: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM query_log \
         WHERE client_name IS NOT NULL OR client_ip NOT LIKE '%.0'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(remaining_pii, 0, "no raw address or client name may remain");
    assert_eq!(detailed_rows(&db).await, ROWS, "rows are never deleted");
    assert!(
        after_size <= before_size,
        "the anonymize vacuum must not grow the file ({after_size} > {before_size})"
    );

    // A rerun is cheap and changes nothing.
    let rerun = db.anonymize_query_log(CHUNK).await.unwrap();
    assert_eq!(rerun.changed, 0, "a rerun must change zero rows");
    assert!(!rerun.vacuumed, "a no-op rerun must not vacuum");

    assert_bounded_memory("after anonymize");
    print_memory("after anonymize");
}
