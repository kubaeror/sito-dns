//! End-to-end tests for the container entrypoint database migration (E1).
//!
//! The distroless image has no shell, so its `ENTRYPOINT` runs the same binary
//! with the hidden `--container-entrypoint` flag. These tests drive the real
//! binary against temporary data directories: a current database starts
//! normally, an old one is migrated with the B2 backup, `SITO_NO_MIGRATE=1`
//! leaves B3 fail-closed, and a failed migration exits before the server starts.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sito_stats::StatsDb;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

fn fixture(label: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "sito_container_entrypoint_{label}_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let port = free_port();
    let config_path = dir.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "config_version = 2\n\
             [server]\n\
             data_dir = \"{}\"\n\
             [dns]\n\
             bind = [\"127.0.0.1\"]\n\
             port = {port}\n\
             dot_port = 0\n\
             doh_port = 0\n\
             doq_port = 0\n\
             doh3_port = 0\n\
             [upstream]\n\
             servers = [\"1.1.1.1\"]\n\
             [filtering]\n\
             enabled = false\n\
             [web]\n\
             enabled = false\n",
            dir.display()
        ),
    )
    .unwrap();
    (dir, config_path)
}

/// Returns a currently free loopback port. The listener is dropped immediately,
/// which is enough to avoid collisions between the sequential tests here.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn sito() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sito"))
}

fn entrypoint(config_path: &Path) -> Command {
    let mut command = sito();
    command
        .args(["--config"])
        .arg(config_path)
        .arg("--container-entrypoint");
    command
}

fn output_of(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
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
    read_marker(db_path).await.unwrap()
}

/// Reads the schema marker, tolerating a database that the server is still
/// creating (the table or file may not exist yet).
async fn read_marker(db_path: &Path) -> Result<Option<String>, sqlx::Error> {
    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .read_only(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    let value: Option<String> =
        sqlx::query_scalar("SELECT value FROM stats_meta WHERE key = 'schema_version'")
            .fetch_optional(&pool)
            .await?;
    pool.close().await;
    Ok(value)
}

async fn current_db(db_path: &Path) {
    let db = StatsDb::open(db_path).await.unwrap();
    db.pool().close().await;
}

async fn legacy_db(db_path: &Path) {
    current_db(db_path).await;
    raw_sql(
        db_path,
        "DELETE FROM stats_meta WHERE key = 'schema_version'",
    )
    .await;
}

fn backup_path(db_path: &Path, found: i64) -> PathBuf {
    let mut name = db_path.as_os_str().to_os_string();
    name.push(format!(".v{found}.bak"));
    PathBuf::from(name)
}

fn assert_mode_0600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{} must be mode 0600", path.display());
    }
}

/// Spawns the entrypoint and waits (with a bounded timeout) for a stdout line
/// containing `needle`. A process that exits or stalls fails the test.
fn wait_for_line(child: &mut Child, needle: &str) {
    let stdout = child
        .stdout
        .take()
        .expect("entrypoint stdout must be piped");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    if sender.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut seen = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "timed out waiting for '{needle}'; lines seen: {seen:?}"
        );
        match receiver.recv_timeout(remaining) {
            Ok(line) => {
                seen.push(line.clone());
                if line.contains(needle) {
                    return;
                }
            }
            Err(error) => panic!(
                "entrypoint stopped before printing '{needle}' ({error}); lines seen: {seen:?}"
            ),
        }
    }
}

fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn test_container_entrypoint_current_database_starts_without_backup() {
    let (dir, config_path) = fixture("current");
    let db_path = dir.join("stats.db");
    current_db(&db_path).await;

    let mut child = entrypoint(&config_path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_line(&mut child, "already at schema version 2");
    stop(child);

    assert!(
        !backup_path(&db_path, 1).exists(),
        "a current database must not create a migration backup"
    );
    assert_eq!(stored_marker(&db_path).await.as_deref(), Some("2"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_container_entrypoint_migrates_old_database_with_0600_backup() {
    let (dir, config_path) = fixture("legacy");
    let db_path = dir.join("stats.db");
    legacy_db(&db_path).await;

    let mut child = entrypoint(&config_path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_line(&mut child, "Migrated stats database");
    stop(child);

    let backup = backup_path(&db_path, 1);
    assert!(backup.is_file(), "the migration must write stats.db.v1.bak");
    assert_mode_0600(&backup);
    assert_eq!(stored_marker(&db_path).await.as_deref(), Some("2"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_container_entrypoint_fresh_volume_creates_database_without_backup() {
    let (dir, config_path) = fixture("fresh");
    let db_path = dir.join("stats.db");
    assert!(!db_path.exists());
    // A fresh container with a mounted config still needs an admin account;
    // create one so the server reaches normal startup instead of refusing the
    // missing users file after the database is created.
    let reset = sito()
        .args(["--config"])
        .arg(&config_path)
        .args(["reset-admin", "--password", "entrypoint-test-password"])
        .output()
        .unwrap();
    assert!(
        reset.status.success(),
        "reset-admin failed: {}{}",
        String::from_utf8_lossy(&reset.stdout),
        String::from_utf8_lossy(&reset.stderr)
    );

    let mut child = entrypoint(&config_path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_line(&mut child, "Starting sito DNS server");

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut marker = None;
    while Instant::now() < deadline {
        if let Ok(Some(value)) = read_marker(&db_path).await {
            marker = Some(value);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    stop(child);

    assert!(
        db_path.is_file(),
        "the server must create stats.db on first start"
    );
    assert!(
        !backup_path(&db_path, 1).exists(),
        "a fresh database must not create a migration backup"
    );
    assert_eq!(marker.as_deref(), Some("2"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_container_entrypoint_no_migrate_leaves_fail_closed_b3_message() {
    let (dir, config_path) = fixture("no_migrate");
    let db_path = dir.join("stats.db");
    legacy_db(&db_path).await;
    let before = std::fs::read(&db_path).unwrap();

    let output = entrypoint(&config_path)
        .env("SITO_NO_MIGRATE", "1")
        .output()
        .unwrap();
    let text = output_of(&output);

    assert!(
        !output.status.success(),
        "SITO_NO_MIGRATE=1 on an old database must fail closed: {text}"
    );
    assert!(
        text.contains("SITO_NO_MIGRATE"),
        "the entrypoint must say it skipped the migration: {text}"
    );
    assert!(
        text.contains("SITO_DB_AUTO_MIGRATE=1") && text.contains("sito db migrate"),
        "the server must print the B3 upgrade guidance: {text}"
    );
    assert!(
        !backup_path(&db_path, 1).exists(),
        "SITO_NO_MIGRATE=1 must not create a backup"
    );
    assert_eq!(
        std::fs::read(&db_path).unwrap(),
        before,
        "SITO_NO_MIGRATE=1 must not modify the database"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_container_entrypoint_failed_migration_never_starts_server() {
    let (dir, config_path) = fixture("migration_failure");
    let db_path = dir.join("stats.db");
    legacy_db(&db_path).await;
    // Force a real post-backup migration failure: the pre-flight and schema
    // upgrade succeed, then the rollup PII backfill cannot run without the
    // dropped table.
    raw_sql(
        &db_path,
        "DELETE FROM stats_meta WHERE key = 'rollup_pii_v2'",
    )
    .await;
    raw_sql(&db_path, "DROP TABLE stats_hourly").await;

    let output = entrypoint(&config_path).output().unwrap();
    let text = output_of(&output);

    assert!(
        !output.status.success(),
        "a failed migration must make the container exit: {text}"
    );
    assert!(
        text.contains("Database migration failed before starting the server"),
        "the entrypoint error must explain why the container did not start: {text}"
    );
    assert!(
        text.contains("Failed to migrate stats database"),
        "the B2 migration error must be preserved: {text}"
    );
    assert!(
        !text.contains("Starting sito DNS server"),
        "the server must not start after a failed migration: {text}"
    );
    let backup = backup_path(&db_path, 1);
    assert!(
        backup.is_file(),
        "the pre-migration backup must remain after a failure"
    );
    assert_mode_0600(&backup);
    let _ = std::fs::remove_dir_all(&dir);
}
