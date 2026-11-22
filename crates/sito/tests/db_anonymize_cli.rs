//! End-to-end tests for `sito db anonymize --all` (B4).
//!
//! These drive the real binary with a temporary data directory and a real
//! SQLite database created by the production `StatsDb`. The service lease and
//! the shared migration lock are held with the same advisory `flock` files the
//! server uses, so the refusal paths are exercised exactly as an operator would
//! see them.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sito_stats::{QueryLogEntry, StatsDb};
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    id: i64,
    ts: i64,
    client_ip: String,
    client_name: Option<String>,
    qname: String,
    qtype: i64,
    rcode: Option<i64>,
    verdict: String,
    rule: Option<String>,
    list_source: Option<String>,
    upstream: Option<String>,
    elapsed_us: Option<i64>,
    dnssec: Option<String>,
    proto: String,
}

fn fixture(label: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "sito_db_anonymize_{label}_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "config_version = 2\n[server]\ndata_dir = \"{}\"\n[upstream]\nservers = [\"1.1.1.1\"]\n",
            dir.display()
        ),
    )
    .unwrap();
    (dir, config_path)
}

fn sito() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sito"))
}

fn anonymize(config_path: &Path, extra: &[&str]) -> std::process::Output {
    sito()
        .args(["db", "anonymize", "--config"])
        .arg(config_path)
        .args(extra)
        .output()
        .unwrap()
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn entry(ts: i64, ip: &str, name: Option<&str>, qname: &str) -> QueryLogEntry {
    let mut entry = QueryLogEntry::new(
        ts,
        ip,
        name.map(ToString::to_string),
        qname,
        1,
        Some(0),
        "allowed",
        "udp",
    );
    entry.rule = Some("rule.example".to_string());
    entry.list_source = Some("test-list".to_string());
    entry.upstream = Some("1.1.1.1".to_string());
    entry.elapsed_us = Some(42);
    entry.dnssec = Some("secure".to_string());
    entry
}

async fn seed(db_path: &Path, entries: &[QueryLogEntry]) {
    let db = StatsDb::open(db_path).await.unwrap();
    db.insert_batch(entries).await.unwrap();
    db.pool().close().await;
}

async fn snapshot(db_path: &Path) -> Vec<Snapshot> {
    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .read_only(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let rows = sqlx::query(
        "SELECT id, ts, client_ip, client_name, qname, qtype, rcode, verdict, rule, \
         list_source, upstream, elapsed_us, dnssec, proto FROM query_log ORDER BY id ASC",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    pool.close().await;
    rows.into_iter()
        .map(|row| Snapshot {
            id: row.get("id"),
            ts: row.get("ts"),
            client_ip: row.get("client_ip"),
            client_name: row.get("client_name"),
            qname: row.get("qname"),
            qtype: row.get("qtype"),
            rcode: row.get("rcode"),
            verdict: row.get("verdict"),
            rule: row.get("rule"),
            list_source: row.get("list_source"),
            upstream: row.get("upstream"),
            elapsed_us: row.get("elapsed_us"),
            dnssec: row.get("dnssec"),
            proto: row.get("proto"),
        })
        .collect()
}

async fn raw_sql(db_path: &Path, sql: &'static str) {
    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::query(sql).execute(&pool).await.unwrap();
    pool.close().await;
}

fn assert_no_sidecars_or_staging(dir: &Path) {
    for sidecar in ["stats.db-wal", "stats.db-shm", "stats.db-journal"] {
        assert!(
            !dir.join(sidecar).exists(),
            "{sidecar} must not be created by a dry run/refusal"
        );
    }
    let leftovers: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".sito-db-inspect-") || name.ends_with(".backup-tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "private staging must be removed: {leftovers:?}"
    );
}

fn hold_service_lease(data_dir: &Path) -> File {
    let path = data_dir.join("sito.pid");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.lock().unwrap();
    file.set_len(0).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    writeln!(file, "{}", std::process::id()).unwrap();
    file.sync_all().unwrap();
    file
}

fn hold_migration_lock(data_dir: &Path) -> File {
    let path = data_dir.join("db-migrate.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.lock().unwrap();
    file
}

#[tokio::test]
async fn cli_db_anonymize_masks_ips_and_preserves_rows() {
    let (dir, config_path) = fixture("masks");
    let db_path = dir.join("stats.db");
    seed(
        &db_path,
        &[
            entry(1_000, "192.168.1.123", Some("laptop"), "a.test"),
            entry(
                1_001,
                "2001:db8:abcd:0012:3456:7890:1234:5678",
                Some("phone"),
                "b.test",
            ),
            entry(1_002, "::ffff:198.51.100.20", Some("mapped"), "c.test"),
            entry(1_003, "192.168.1.0", None, "already.test"),
        ],
    )
    .await;
    let before = snapshot(&db_path).await;
    assert_eq!(before.len(), 4);

    let output = anonymize(&config_path, &["--all"]);

    assert!(
        output.status.success(),
        "anonymize must succeed: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("Anonymized 3 of 4 query_log rows"),
        "must report changed/processed rows: {stdout}"
    );
    assert!(
        stdout.contains("Vacuumed the database and truncated the WAL"),
        "a full anonymize must vacuum: {stdout}"
    );
    assert!(
        stdout.contains("Stats database size:"),
        "must report the final size: {stdout}"
    );

    let after = snapshot(&db_path).await;
    assert_eq!(after.len(), before.len(), "row count must be unchanged");
    assert_eq!(after[0].client_ip, "192.168.1.0");
    assert_eq!(after[1].client_ip, "2001:db8:abcd::");
    assert_eq!(after[2].client_ip, "198.51.100.0");
    assert_eq!(after[3].client_ip, "192.168.1.0");
    for (before, after) in before.iter().zip(after.iter()) {
        assert_eq!(after.id, before.id, "id is preserved");
        assert_eq!(after.ts, before.ts, "ts is preserved");
        assert_eq!(after.qname, before.qname, "qname is preserved");
        assert_eq!(after.qtype, before.qtype, "qtype is preserved");
        assert_eq!(after.rcode, before.rcode, "rcode is preserved");
        assert_eq!(after.verdict, before.verdict, "verdict is preserved");
        assert_eq!(after.rule, before.rule, "rule is preserved");
        assert_eq!(
            after.list_source, before.list_source,
            "list_source is preserved"
        );
        assert_eq!(after.upstream, before.upstream, "upstream is preserved");
        assert_eq!(
            after.elapsed_us, before.elapsed_us,
            "elapsed_us is preserved"
        );
        assert_eq!(after.dnssec, before.dnssec, "dnssec is preserved");
        assert_eq!(after.proto, before.proto, "proto is preserved");
        assert_eq!(after.client_name, None, "client_name must be NULL");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_anonymize_second_run_changes_zero_rows() {
    let (dir, config_path) = fixture("idempotent");
    let db_path = dir.join("stats.db");
    seed(
        &db_path,
        &[
            entry(1_000, "10.1.2.3", Some("one"), "a.test"),
            entry(1_001, "10.1.2.4", Some("two"), "b.test"),
            entry(1_002, "10.1.2.5", Some("three"), "c.test"),
        ],
    )
    .await;

    let first = anonymize(&config_path, &["--all"]);
    assert!(first.status.success(), "{}", stderr_of(&first));
    let after_first = snapshot(&db_path).await;

    let second = anonymize(&config_path, &["--all"]);
    assert!(
        second.status.success(),
        "the second run must succeed: {}",
        stderr_of(&second)
    );
    let stdout = stdout_of(&second);
    assert!(
        stdout.contains("Nothing to do") && stdout.contains("0 changed"),
        "a rerun must report zero changes: {stdout}"
    );
    assert!(
        !stdout.contains("Vacuumed"),
        "a no-op run must not vacuum: {stdout}"
    );
    assert_eq!(
        snapshot(&db_path).await,
        after_first,
        "a rerun must not alter any row"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_anonymize_dry_run_reports_without_writing() {
    let (dir, config_path) = fixture("dry_run");
    let db_path = dir.join("stats.db");
    seed(
        &db_path,
        &[
            entry(1_000, "192.0.2.10", Some("one"), "a.test"),
            entry(1_001, "192.0.2.11", Some("two"), "b.test"),
            entry(1_002, "192.0.2.0", None, "already.test"),
        ],
    )
    .await;
    // `--dry-run` must never recreate a missing salt on the live path.
    let salt = dir.join("stats-salt");
    std::fs::remove_file(&salt).unwrap();
    let before = std::fs::read(&db_path).unwrap();

    let output = anonymize(&config_path, &["--all", "--dry-run"]);

    assert!(
        output.status.success(),
        "dry run must succeed: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("Would anonymize 2 of 3 query_log rows"),
        "dry run must report the candidate count: {stdout}"
    );
    assert!(
        stdout.contains("1 already anonymized"),
        "dry run must report skipped rows: {stdout}"
    );
    assert!(
        stdout.contains("Dry run: the live database"),
        "dry run must state that it wrote nothing: {stdout}"
    );
    assert_eq!(
        std::fs::read(&db_path).unwrap(),
        before,
        "dry run must not touch the database bytes"
    );
    assert!(!salt.exists(), "dry run must not create stats-salt");
    assert_no_sidecars_or_staging(&dir);

    // The real run then applies exactly the rows the dry run counted.
    let real = anonymize(&config_path, &["--all"]);
    assert!(real.status.success(), "{}", stderr_of(&real));
    assert!(
        stdout_of(&real).contains("Anonymized 2 of 3 query_log rows"),
        "real run must match the dry-run count: {}",
        stdout_of(&real)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_anonymize_dry_run_counts_committed_wal_without_touching_it() {
    let (dir, config_path) = fixture("dry_wal");
    let db_path = dir.join("stats.db");
    seed(
        &db_path,
        &[entry(1_000, "192.0.2.10", Some("base"), "base.test")],
    )
    .await;

    // Keep a connection open so this row stays in the `-wal` file: the dry run
    // must count it without modifying the live WAL or database.
    let options = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO query_log (ts, client_ip, client_name, qname, qtype, rcode, verdict, proto) \
         VALUES (2000, '203.0.113.9', 'wal-client', 'wal.test', 1, 0, 'allowed', 'udp')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let wal_path = PathBuf::from(format!("{}-wal", db_path.display()));
    assert!(wal_path.is_file(), "the fixture write must be in the WAL");
    let wal_before = std::fs::read(&wal_path).unwrap();
    let db_before = std::fs::read(&db_path).unwrap();

    let output = anonymize(&config_path, &["--all", "--dry-run"]);

    assert!(
        output.status.success(),
        "dry run over committed WAL content must succeed: {}",
        stderr_of(&output)
    );
    assert!(
        stdout_of(&output).contains("Would anonymize 2 of 2 query_log rows"),
        "dry run must include committed WAL rows: {}",
        stdout_of(&output)
    );
    assert_eq!(
        std::fs::read(&wal_path).unwrap(),
        wal_before,
        "dry run must not modify the live WAL"
    );
    assert_eq!(
        std::fs::read(&db_path).unwrap(),
        db_before,
        "dry run must not modify the live database"
    );

    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_anonymize_missing_database_errors_without_creating() {
    let (dir, config_path) = fixture("missing");
    let db_path = dir.join("stats.db");

    let output = anonymize(&config_path, &["--all"]);

    assert!(!output.status.success(), "missing DB must fail");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("does not exist") && stderr.contains("nothing to anonymize"),
        "clear missing-DB error: {stderr}"
    );
    assert!(!db_path.exists(), "the command must not create an empty DB");
    assert_no_sidecars_or_staging(&dir);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_anonymize_refuses_while_service_running() {
    let (dir, config_path) = fixture("running");
    let db_path = dir.join("stats.db");
    seed(
        &db_path,
        &[entry(1_000, "192.0.2.10", Some("one"), "a.test")],
    )
    .await;
    let before = snapshot(&db_path).await;
    let _lease = hold_service_lease(&dir);

    let output = anonymize(&config_path, &["--all"]);

    assert!(
        !output.status.success(),
        "anonymization must fail closed while the service runs"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("systemctl stop sito"),
        "error must tell the operator to stop the service: {stderr}"
    );
    assert!(
        stderr.contains("no --force override"),
        "anonymization must not advertise an override: {stderr}"
    );
    assert_eq!(
        snapshot(&db_path).await,
        before,
        "a refused run must not change rows"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_anonymize_refuses_when_the_migration_lock_is_held() {
    let (dir, config_path) = fixture("migration_lock");
    let db_path = dir.join("stats.db");
    seed(
        &db_path,
        &[entry(1_000, "192.0.2.10", Some("one"), "a.test")],
    )
    .await;
    let before = snapshot(&db_path).await;

    let lock_file = hold_migration_lock(&dir);
    let output = anonymize(&config_path, &["--all"]);

    assert!(
        !output.status.success(),
        "a held migration lock must refuse the command"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("another DB migration is in progress"),
        "the refusal must explain the shared migration lock: {stderr}"
    );
    assert_eq!(
        snapshot(&db_path).await,
        before,
        "a refused run must not change rows"
    );

    lock_file.unlock().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_anonymize_requires_all_flag() {
    let (dir, config_path) = fixture("require_all");
    let db_path = dir.join("stats.db");
    seed(
        &db_path,
        &[entry(1_000, "192.0.2.10", Some("one"), "a.test")],
    )
    .await;
    let before = snapshot(&db_path).await;

    let output = anonymize(&config_path, &[]);

    assert!(!output.status.success(), "`--all` must be required");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("--all"),
        "the parse error must name --all: {stderr}"
    );
    assert_eq!(
        snapshot(&db_path).await,
        before,
        "a parse refusal must not change rows"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_anonymize_refuses_a_legacy_schema_without_migrating() {
    let (dir, config_path) = fixture("legacy");
    let db_path = dir.join("stats.db");
    seed(
        &db_path,
        &[entry(1_000, "192.0.2.10", Some("one"), "a.test")],
    )
    .await;
    raw_sql(
        &db_path,
        "DELETE FROM stats_meta WHERE key = 'schema_version'",
    )
    .await;
    let before = snapshot(&db_path).await;
    // The read-only snapshot above can create an empty WAL sidecar for a WAL
    // database; start the command from a clean directory so the assertion
    // below only covers files the command itself might create.
    for sidecar in ["stats.db-wal", "stats.db-shm"] {
        let path = dir.join(sidecar);
        if path.exists() {
            std::fs::remove_file(path).unwrap();
        }
    }
    let db_bytes = std::fs::read(&db_path).unwrap();

    let output = anonymize(&config_path, &["--all"]);

    assert!(
        !output.status.success(),
        "an old schema must be refused, not migrated implicitly"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("schema version 1") && stderr.contains("sito db migrate"),
        "the refusal must name the explicit migration command: {stderr}"
    );
    assert_eq!(
        std::fs::read(&db_path).unwrap(),
        db_bytes,
        "a refused run must not migrate the database"
    );
    assert_no_sidecars_or_staging(&dir);
    assert_eq!(
        snapshot(&db_path).await,
        before,
        "a refused run must not change rows"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
