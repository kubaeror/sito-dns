//! End-to-end tests for `sito db migrate` (B2).
//!
//! These drive the real binary with a temporary data directory and a real
//! SQLite database. Fixtures are created with the production `StatsDb` (which
//! writes schema version 2) and then edited to simulate a legacy, newer, or
//! corrupt database. The service lease is simulated exactly as
//! `reset_service.rs` does: an advisory lock on `<data_dir>/sito.pid`.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sito_stats::StatsDb;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

fn fixture(label: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "sito_db_migrate_{label}_{}_{}",
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

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
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

async fn stored_marker(db_path: &Path) -> Option<String> {
    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .read_only(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let value: Option<String> =
        sqlx::query_scalar("SELECT value FROM stats_meta WHERE key = 'schema_version'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    pool.close().await;
    value
}

/// Creates a current (schema version 2) database and closes it cleanly.
async fn current_db(db_path: &Path) {
    let db = StatsDb::open(db_path).await.unwrap();
    db.pool().close().await;
}

/// A database written by 1.9.x-shaped code: the current schema but without
/// the `schema_version` marker, which reports legacy version 1.
async fn legacy_db(db_path: &Path) {
    current_db(db_path).await;
    raw_sql(
        db_path,
        "DELETE FROM stats_meta WHERE key = 'schema_version'",
    )
    .await;
}

async fn newer_db(db_path: &Path) {
    current_db(db_path).await;
    raw_sql(
        db_path,
        "INSERT INTO stats_meta (key, value) VALUES ('schema_version', '3') \
         ON CONFLICT(key) DO UPDATE SET value = '3'",
    )
    .await;
}

async fn corrupt_db(db_path: &Path) {
    current_db(db_path).await;
    raw_sql(
        db_path,
        "INSERT INTO stats_meta (key, value) VALUES ('schema_version', 'banana') \
         ON CONFLICT(key) DO UPDATE SET value = 'banana'",
    )
    .await;
}

fn backup_path(db_path: &Path, found: i64) -> PathBuf {
    let mut name = db_path.as_os_str().to_os_string();
    name.push(format!(".v{found}.bak"));
    PathBuf::from(name)
}

fn backups(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.to_string_lossy().contains(".bak"))
        .collect();
    found.sort();
    found
}

fn db_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

/// Acquires the lease a running server holds for `data_dir`.
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

fn migrate(config_path: &Path, extra: &[&str]) -> std::process::Output {
    sito()
        .args(["db", "migrate", "--config"])
        .arg(config_path)
        .args(extra)
        .output()
        .unwrap()
}

#[tokio::test]
async fn cli_db_migrate_missing_database_errors_without_creating() {
    let (dir, config_path) = fixture("missing");
    let db_path = dir.join("stats.db");

    let output = migrate(&config_path, &[]);

    assert!(!output.status.success(), "missing DB must fail");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("does not exist") && stderr.contains("nothing to migrate"),
        "clear missing-DB error: {stderr}"
    );
    assert!(!db_path.exists(), "migration must not create an empty DB");
    assert!(backups(&dir).is_empty(), "no backup may be created");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_migrate_current_is_idempotent_and_skips_backup() {
    let (dir, config_path) = fixture("current");
    let db_path = dir.join("stats.db");
    current_db(&db_path).await;
    let before = db_bytes(&db_path);

    let first = migrate(&config_path, &[]);
    assert!(
        first.status.success(),
        "current DB must be a no-op: {}",
        stderr_of(&first)
    );
    assert!(
        stdout_of(&first).contains("already at schema version 2"),
        "must report the current schema: {}",
        stdout_of(&first)
    );
    assert!(backups(&dir).is_empty(), "no backup for a current DB");

    let second = migrate(&config_path, &[]);
    assert!(second.status.success(), "second run must also succeed");
    assert!(backups(&dir).is_empty(), "second run must not add a backup");
    assert_eq!(
        db_bytes(&db_path),
        before,
        "already-current runs must not write to the database"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_migrate_dry_run_does_not_mutate_anything() {
    let (dir, config_path) = fixture("dry_run");
    let db_path = dir.join("stats.db");
    legacy_db(&db_path).await;
    for sidecar in ["stats.db-wal", "stats.db-shm"] {
        assert!(
            !dir.join(sidecar).exists(),
            "fixture must start without {sidecar}"
        );
    }
    let before = db_bytes(&db_path);

    let output = migrate(&config_path, &["--dry-run"]);

    assert!(
        output.status.success(),
        "dry run must succeed: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("schema version 1 found, 2 supported"),
        "dry run must print found/supported: {stdout}"
    );
    assert!(
        stdout.contains("Would migrate to schema version 2"),
        "dry run must explain the action: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "Backup would be written to '{}'",
            backup_path(&db_path, 1).display()
        )),
        "dry run must name the backup path: {stdout}"
    );
    assert!(
        stdout.contains("the database, WAL/SHM and backup were not created or modified"),
        "dry run must be explicit about side effects: {stdout}"
    );
    assert!(backups(&dir).is_empty(), "dry run must not create a backup");
    assert_eq!(db_bytes(&db_path), before, "dry run must not touch the DB");
    for sidecar in ["stats.db-wal", "stats.db-shm"] {
        assert!(
            !dir.join(sidecar).exists(),
            "dry run must not create {sidecar}"
        );
    }
    assert_eq!(stored_marker(&db_path).await, None, "marker stays legacy");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_migrate_upgrades_legacy_with_0600_backup() {
    let (dir, config_path) = fixture("upgrade");
    let db_path = dir.join("stats.db");
    legacy_db(&db_path).await;

    let output = migrate(&config_path, &[]);

    assert!(
        output.status.success(),
        "legacy migration must succeed: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("from schema version 1 to 2"),
        "must report the upgrade: {stdout}"
    );
    assert_eq!(stored_marker(&db_path).await.as_deref(), Some("2"));

    let backup = backup_path(&db_path, 1);
    assert!(
        backup.is_file(),
        "backup must exist at {}",
        backup.display()
    );
    let inspection = StatsDb::inspect_schema_version(&backup)
        .await
        .unwrap()
        .expect("backup is a database");
    assert_eq!(inspection.found, 1, "backup keeps the pre-migration schema");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the backup must be mode 0600");
    }
    assert_eq!(backups(&dir), vec![backup], "exactly one backup");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_migrate_second_real_run_is_idempotent() {
    let (dir, config_path) = fixture("idempotent");
    let db_path = dir.join("stats.db");
    legacy_db(&db_path).await;

    let first = migrate(&config_path, &[]);
    assert!(first.status.success(), "{}", stderr_of(&first));
    let backup = backup_path(&db_path, 1);
    assert!(backup.is_file());
    let upgraded = db_bytes(&db_path);

    let second = migrate(&config_path, &[]);

    assert!(
        second.status.success(),
        "second run must succeed: {}",
        stderr_of(&second)
    );
    assert!(
        stdout_of(&second).contains("already at schema version 2"),
        "second run must be a no-op: {}",
        stdout_of(&second)
    );
    assert_eq!(
        backups(&dir),
        vec![backup],
        "second run must not create a v2 backup"
    );
    assert_eq!(
        db_bytes(&db_path),
        upgraded,
        "second run must not rewrite the database"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_migrate_refuses_newer_schema_without_writes() {
    let (dir, config_path) = fixture("newer");
    let db_path = dir.join("stats.db");
    newer_db(&db_path).await;
    let before = db_bytes(&db_path);

    let output = migrate(&config_path, &[]);

    assert!(
        !output.status.success(),
        "a newer schema must be refused, not downgraded"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("schema version 3") && stderr.contains("at most 2"),
        "refusal must show both versions: {stderr}"
    );
    assert!(
        stderr.contains("Downgrading is not supported"),
        "refusal must be forward-only: {stderr}"
    );
    assert!(
        stderr.contains("No files were changed"),
        "refusal must state there were no writes: {stderr}"
    );
    assert!(backups(&dir).is_empty(), "no backup for a refused DB");
    assert_eq!(db_bytes(&db_path), before, "refusal must not touch the DB");
    assert_eq!(stored_marker(&db_path).await.as_deref(), Some("3"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_migrate_dry_run_reads_committed_wal_without_touching_it() {
    let (dir, config_path) = fixture("dry_wal");
    let db_path = dir.join("stats.db");
    current_db(&db_path).await;

    // Keep a connection open so this marker write stays in the `-wal` file:
    // the dry run must include committed WAL content without modifying it.
    let options = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::query("UPDATE stats_meta SET value = '3' WHERE key = 'schema_version'")
        .execute(&pool)
        .await
        .unwrap();
    let wal_path = PathBuf::from(format!("{}-wal", db_path.display()));
    assert!(wal_path.is_file(), "the fixture write must be in the WAL");
    let wal_before = std::fs::read(&wal_path).unwrap();

    let output = migrate(&config_path, &["--dry-run"]);

    assert!(
        !output.status.success(),
        "the newer version committed in the WAL must be seen and refused"
    );
    assert!(
        stderr_of(&output).contains("schema version 3"),
        "dry run must read the WAL marker: {}",
        stderr_of(&output)
    );
    assert_eq!(
        std::fs::read(&wal_path).unwrap(),
        wal_before,
        "dry run must not modify the live WAL"
    );
    assert!(backups(&dir).is_empty(), "dry run must not create a backup");

    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_migrate_refuses_to_overwrite_a_backup() {
    let (dir, config_path) = fixture("collision");
    let db_path = dir.join("stats.db");
    legacy_db(&db_path).await;
    let backup = backup_path(&db_path, 1);
    std::fs::write(&backup, b"operator's existing backup").unwrap();

    let output = migrate(&config_path, &[]);

    assert!(
        !output.status.success(),
        "an existing backup must be refused"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("Refusing to overwrite the existing backup"),
        "collision refusal must be explicit: {stderr}"
    );
    assert_eq!(
        std::fs::read(&backup).unwrap(),
        b"operator's existing backup",
        "the existing backup must not be overwritten"
    );
    assert_eq!(
        stored_marker(&db_path).await,
        None,
        "a refused run must not migrate"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_migrate_refuses_while_service_running() {
    let (dir, config_path) = fixture("running");
    let db_path = dir.join("stats.db");
    legacy_db(&db_path).await;
    let _lease = hold_service_lease(&dir);

    let output = migrate(&config_path, &[]);

    assert!(
        !output.status.success(),
        "migration must fail closed while the service runs"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("systemctl stop sito"),
        "error must tell the operator to stop the service: {stderr}"
    );
    assert!(
        stderr.contains("no --force override"),
        "migration must not advertise an override: {stderr}"
    );
    assert!(backups(&dir).is_empty(), "a refused run must not back up");
    assert_eq!(
        stored_marker(&db_path).await,
        None,
        "a refused run must not migrate"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_migrate_no_backup_migrates_without_a_file() {
    let (dir, config_path) = fixture("no_backup");
    let db_path = dir.join("stats.db");
    legacy_db(&db_path).await;

    let output = migrate(&config_path, &["--no-backup"]);

    assert!(
        output.status.success(),
        "--no-backup must still migrate: {}",
        stderr_of(&output)
    );
    assert!(
        stdout_of(&output).contains("Skipping the backup (--no-backup)"),
        "the risk must be printed: {}",
        stdout_of(&output)
    );
    assert_eq!(stored_marker(&db_path).await.as_deref(), Some("2"));
    assert!(
        backups(&dir).is_empty(),
        "--no-backup must not create a backup"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_db_migrate_corrupt_marker_fails_closed() {
    let (dir, config_path) = fixture("corrupt");
    let db_path = dir.join("stats.db");
    corrupt_db(&db_path).await;
    let before = db_bytes(&db_path);

    let output = migrate(&config_path, &[]);

    assert!(
        !output.status.success(),
        "a corrupt marker must fail closed"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("invalid") && stderr.contains("banana"),
        "error must identify the invalid marker: {stderr}"
    );
    assert!(backups(&dir).is_empty(), "no backup for a corrupt DB");
    assert_eq!(
        db_bytes(&db_path),
        before,
        "a corrupt marker must not be rewritten"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
