//! Startup policy for the stats database schema.
//!
//! The server never migrates a database silently. By default an older database
//! is refused with a message that names both supported upgrade paths. Setting
//! `SITO_DB_AUTO_MIGRATE=1` (or `true`) opts into the safe startup sequence:
//! shared migration lock, 0600 backup, migrate, verify, and only then open the
//! runtime database for serving.

use std::path::Path;

use sito_stats::{MigrationMode, StatsDb, StatsOpenOptions};
use tracing::{info, warn};

use crate::db_maintenance::{
    DB_MIGRATE_LOCK_FILE, OwnershipGuard, acquire_db_migration_lock, file_owner,
    inspect_db_without_writes, migration_created_paths, restore_ownership, stats_backup_path,
};

/// Environment variable that allows startup to migrate an older stats database.
pub const DB_AUTO_MIGRATE_ENV: &str = "SITO_DB_AUTO_MIGRATE";

/// Parsed startup migration policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbAutoMigrate {
    /// Refuse to start when the database needs a migration.
    Disabled,
    /// Back up, migrate, verify and then open an older database.
    Enabled,
}

impl DbAutoMigrate {
    /// Parses the raw environment value.
    ///
    /// Unset, empty, `0` and `false` disable auto-migration; `1` and `true`
    /// enable it. Every other value is a startup error: a typo must not
    /// silently choose either policy.
    pub fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value {
            None | Some("" | "0" | "false") => Ok(Self::Disabled),
            Some("1" | "true") => Ok(Self::Enabled),
            Some(other) => Err(anyhow::anyhow!(
                "Invalid {DB_AUTO_MIGRATE_ENV} value '{other}'. Set it to '1' or 'true' to allow \
                 startup to back up and migrate an older stats database, or unset it (or set '0' \
                 or 'false') to refuse startup until `sito db migrate` has run."
            )),
        }
    }

    /// Reads [`DB_AUTO_MIGRATE_ENV`] once for this startup.
    pub fn from_env() -> anyhow::Result<Self> {
        match std::env::var_os(DB_AUTO_MIGRATE_ENV) {
            None => Ok(Self::Disabled),
            Some(value) => {
                let value = value.to_str().ok_or_else(|| {
                    anyhow::anyhow!(
                        "{DB_AUTO_MIGRATE_ENV} is not valid UTF-8. Set it to '1'/'true' or \
                         unset it to disable startup auto-migration."
                    )
                })?;
                Self::parse(Some(value))
            }
        }
    }

    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// Prepares the stats database for server startup under `policy`.
///
/// - A missing database is a first install: it is created with the current
///   schema and no backup.
/// - A current database opens normally without a backup.
/// - A newer or corrupt database is refused before any write.
/// - An older database is refused unless auto-migration is enabled; when it is,
///   a consistent 0600 backup is written first and startup aborts if the
///   migration or its verification fails.
///
/// The shared migration lock is held from before inspection through the runtime
/// open. No caller may open the database for serving before this function
/// returns `Ok`.
pub async fn prepare_stats_db(
    data_dir: &Path,
    rollup_client_names: bool,
    policy: DbAutoMigrate,
) -> anyhow::Result<StatsDb> {
    tokio::fs::create_dir_all(data_dir).await?;
    let db_path = data_dir.join("stats.db");

    // Capture the owner before the lock or any migration file is created. A
    // `sudo` startup must not leave root-owned files for the service user.
    let owner = file_owner(&db_path).or_else(|| file_owner(data_dir));

    let _lock = acquire_db_migration_lock(data_dir)?;
    // The lock file was created by this process; make it usable by the service
    // user if startup is running as root.
    restore_ownership(&[data_dir.join(DB_MIGRATE_LOCK_FILE)], owner)?;

    // First install: create the current schema. There is nothing to inspect,
    // back up or migrate.
    if !db_path.is_file() {
        let mut guard =
            OwnershipGuard::new(migration_created_paths(&db_path, data_dir, None), owner);
        let db = open_db(
            &db_path,
            rollup_client_names,
            MigrationMode::Auto,
            "create the first-install stats database",
        )
        .await?;
        guard.restore()?;
        info!(
            path = %db_path.display(),
            "Created a new stats database at the current schema version"
        );
        return Ok(db);
    }

    let inspection = inspect_db_without_writes(&db_path).await.map_err(|e| {
        anyhow::anyhow!(
            "Refusing to start: cannot determine the schema version of stats database '{}'. \
             {e} No database files were changed.",
            db_path.display()
        )
    })?;

    if inspection.is_too_new() {
        anyhow::bail!(
            "Refusing to start: stats database '{}' records schema version {} but this binary \
             supports at most {}. Downgrading is not supported; upgrade the sito binary instead. \
             No database files were changed.",
            db_path.display(),
            inspection.found,
            inspection.supported
        );
    }

    if inspection.is_current() {
        let mut guard =
            OwnershipGuard::new(migration_created_paths(&db_path, data_dir, None), owner);
        let db = open_db(
            &db_path,
            rollup_client_names,
            MigrationMode::RequireCurrent,
            "open the current stats database",
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Refusing to start: stats database '{}' did not open at schema version {}. {e}",
                db_path.display(),
                inspection.supported
            )
        })?;
        guard.restore()?;
        info!(
            path = %db_path.display(),
            schema_version = inspection.found,
            "Opened the stats database"
        );
        return Ok(db);
    }

    // Older schema. Being defensive here also keeps a future schema-version
    // change from silently taking the wrong branch.
    if !inspection.needs_migration() {
        anyhow::bail!(
            "Refusing to start: stats database '{}' reports an unrecognized schema version {} \
             (this binary supports {}). No database files were changed.",
            db_path.display(),
            inspection.found,
            inspection.supported
        );
    }

    if !policy.is_enabled() {
        anyhow::bail!(
            "Refusing to start: stats database '{}' is at schema version {} but this binary \
             requires schema version {}. Stop the service and run `sito db migrate --config \
             <config.toml>` to back it up and upgrade it, or start with \
             {DB_AUTO_MIGRATE_ENV}=1 to let startup migrate it. No database files were changed.",
            db_path.display(),
            inspection.found,
            inspection.supported
        );
    }

    let backup_path = stats_backup_path(&db_path, inspection.found);
    if backup_path.exists() {
        anyhow::bail!(
            "Refusing to start: auto-migration of stats database '{}' would overwrite the \
             existing backup '{}'. Move or remove that backup, then start again. No database \
             files were changed.",
            db_path.display(),
            backup_path.display()
        );
    }

    info!(
        path = %db_path.display(),
        backup = %backup_path.display(),
        found = inspection.found,
        supported = inspection.supported,
        "Backing up the stats database before startup auto-migration"
    );
    StatsDb::snapshot_to(&db_path, &backup_path)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Refusing to start: failed to write the 0600 backup '{}' before migrating stats \
                 database '{}': {e}. Startup aborted and the database was not migrated.",
                backup_path.display(),
                db_path.display()
            )
        })?;
    restore_ownership(std::slice::from_ref(&backup_path), owner)?;

    let mut guard = OwnershipGuard::new(
        migration_created_paths(&db_path, data_dir, Some(&backup_path)),
        owner,
    );

    let db = open_db(
        &db_path,
        rollup_client_names,
        MigrationMode::Auto,
        "migrate the stats database",
    )
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "Refusing to start: failed to migrate stats database '{}': {e}. Startup aborted and \
             no DNS/API listeners were started. The pre-migration backup is at '{}'; restore it \
             if the failed migration changed the live database.",
            db_path.display(),
            backup_path.display()
        )
    })?;

    match db.is_schema_current().await {
        Ok(true) => {}
        Ok(false) => {
            db.pool().close().await;
            anyhow::bail!(
                "Refusing to start: stats database '{}' was migrated but does not report the \
                 required schema version {}. Startup aborted and no DNS/API listeners were \
                 started. The pre-migration backup is at '{}'.",
                db_path.display(),
                inspection.supported,
                backup_path.display()
            );
        }
        Err(e) => {
            db.pool().close().await;
            anyhow::bail!(
                "Refusing to start: stats database '{}' was migrated but its schema version \
                 could not be verified: {e}. Startup aborted and no DNS/API listeners were \
                 started. The pre-migration backup is at '{}'.",
                db_path.display(),
                backup_path.display()
            );
        }
    }

    guard.restore()?;
    info!(
        path = %db_path.display(),
        backup = %backup_path.display(),
        found = inspection.found,
        supported = inspection.supported,
        "Migrated the stats database and verified the new schema version"
    );
    Ok(db)
}

async fn open_db(
    db_path: &Path,
    rollup_client_names: bool,
    migration_mode: MigrationMode,
    action: &str,
) -> anyhow::Result<StatsDb> {
    StatsDb::open_with_options(
        db_path,
        StatsOpenOptions {
            rollup_client_names,
            migration_mode,
        },
    )
    .await
    .map_err(|e| {
        warn!(
            path = %db_path.display(),
            error = %e,
            "Failed to {action}"
        );
        anyhow::anyhow!("Failed to {action} '{}': {e}", db_path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sito_db_startup_{label}_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn raw_sql(db_path: &Path, sql: &str) {
        let options = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(sql.to_string()))
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
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

    fn assert_no_sidecars_or_staging(dir: &Path) {
        for sidecar in ["stats.db-wal", "stats.db-shm", "stats.db-journal"] {
            assert!(
                !dir.join(sidecar).exists(),
                "{sidecar} must not be created by inspection/refusal"
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

    fn db_bytes(path: &Path) -> Vec<u8> {
        std::fs::read(path).unwrap()
    }

    #[test]
    fn env_policy_parses_all_documented_values() {
        assert_eq!(DbAutoMigrate::parse(None).unwrap(), DbAutoMigrate::Disabled);
        assert_eq!(
            DbAutoMigrate::parse(Some("")).unwrap(),
            DbAutoMigrate::Disabled
        );
        assert_eq!(
            DbAutoMigrate::parse(Some("0")).unwrap(),
            DbAutoMigrate::Disabled
        );
        assert_eq!(
            DbAutoMigrate::parse(Some("false")).unwrap(),
            DbAutoMigrate::Disabled
        );
        assert_eq!(
            DbAutoMigrate::parse(Some("1")).unwrap(),
            DbAutoMigrate::Enabled
        );
        assert_eq!(
            DbAutoMigrate::parse(Some("true")).unwrap(),
            DbAutoMigrate::Enabled
        );
        assert!(DbAutoMigrate::parse(Some("yes")).is_err());
        assert!(DbAutoMigrate::parse(Some("TRUE")).is_err());
        let error = DbAutoMigrate::parse(Some("2")).unwrap_err().to_string();
        assert!(
            error.contains(DB_AUTO_MIGRATE_ENV) && error.contains("'2'"),
            "the invalid-value error must name the variable and value: {error}"
        );
    }

    #[tokio::test]
    async fn missing_database_is_created_without_backup() {
        let dir = temp_dir("missing");
        let db_path = dir.join("stats.db");

        let db = prepare_stats_db(&dir, false, DbAutoMigrate::Disabled)
            .await
            .expect("a first install must create the database");
        assert!(db.is_schema_current().await.unwrap());
        db.pool().close().await;

        assert!(db_path.is_file());
        assert_eq!(
            backups(&dir),
            Vec::<PathBuf>::new(),
            "first install needs no backup"
        );
        assert!(
            !dir.join(DB_MIGRATE_LOCK_FILE).exists(),
            "the migration lock is released after startup preparation"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn current_database_opens_without_backup() {
        let dir = temp_dir("current");
        let db_path = dir.join("stats.db");
        current_db(&db_path).await;

        let db = prepare_stats_db(&dir, false, DbAutoMigrate::Disabled)
            .await
            .expect("a current database must open");
        assert!(db.is_schema_current().await.unwrap());
        db.pool().close().await;

        assert_eq!(
            backups(&dir),
            Vec::<PathBuf>::new(),
            "a current database needs no backup"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn older_database_without_opt_in_is_refused_without_writes() {
        let dir = temp_dir("older_disabled");
        let db_path = dir.join("stats.db");
        legacy_db(&db_path).await;
        let before = db_bytes(&db_path);

        let error = prepare_stats_db(&dir, false, DbAutoMigrate::Disabled)
            .await
            .map(|_| ())
            .expect_err("an older database must fail closed by default")
            .to_string();

        assert!(
            error.contains("sito db migrate") && error.contains("SITO_DB_AUTO_MIGRATE=1"),
            "the refusal must name both upgrade paths: {error}"
        );
        assert!(
            error.contains("No database files were changed"),
            "the refusal must state there were no writes: {error}"
        );
        assert_eq!(
            db_bytes(&db_path),
            before,
            "the database must not be written"
        );
        assert_eq!(backups(&dir), Vec::<PathBuf>::new());
        assert_no_sidecars_or_staging(&dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn older_database_with_opt_in_is_backed_up_and_migrated() {
        let dir = temp_dir("older_enabled");
        let db_path = dir.join("stats.db");
        legacy_db(&db_path).await;

        let db = prepare_stats_db(&dir, false, DbAutoMigrate::Enabled)
            .await
            .expect("auto-migration must upgrade the database");
        assert!(db.is_schema_current().await.unwrap());
        db.pool().close().await;

        let backup = stats_backup_path(&db_path, 1);
        assert!(backup.is_file(), "the backup must exist");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the backup must be owner-only");
        }
        assert_eq!(backups(&dir), vec![backup], "exactly one v1 backup");

        let reopened = StatsDb::open(&db_path).await.unwrap();
        assert!(reopened.is_schema_current().await.unwrap());
        reopened.pool().close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn newer_database_is_refused_without_writes() {
        let dir = temp_dir("newer");
        let db_path = dir.join("stats.db");
        newer_db(&db_path).await;
        let before = db_bytes(&db_path);

        let error = prepare_stats_db(&dir, false, DbAutoMigrate::Enabled)
            .await
            .map(|_| ())
            .expect_err("a newer database must never be downgraded")
            .to_string();
        assert!(
            error.contains("schema version 3") && error.contains("at most 2"),
            "the refusal must show both versions: {error}"
        );
        assert_eq!(db_bytes(&db_path), before);
        assert_eq!(backups(&dir), Vec::<PathBuf>::new());
        assert_no_sidecars_or_staging(&dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn corrupt_database_is_refused_without_writes() {
        let dir = temp_dir("corrupt");
        let db_path = dir.join("stats.db");
        corrupt_db(&db_path).await;
        let before = db_bytes(&db_path);

        let error = prepare_stats_db(&dir, false, DbAutoMigrate::Enabled)
            .await
            .map(|_| ())
            .expect_err("a corrupt schema marker must fail closed")
            .to_string();
        assert!(
            error.contains("banana"),
            "the refusal must identify the invalid marker: {error}"
        );
        assert_eq!(db_bytes(&db_path), before);
        assert_eq!(backups(&dir), Vec::<PathBuf>::new());
        assert_no_sidecars_or_staging(&dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn held_migration_lock_refuses_startup() {
        let dir = temp_dir("lock_held");
        let db_path = dir.join("stats.db");
        legacy_db(&db_path).await;
        let _held = crate::db_maintenance::DbMigrationLock::acquire(&dir).unwrap();

        let error = prepare_stats_db(&dir, false, DbAutoMigrate::Enabled)
            .await
            .map(|_| ())
            .expect_err("a held migration lock must refuse startup")
            .to_string();
        assert!(
            error.contains("another DB migration is in progress"),
            "the refusal must explain the lock: {error}"
        );
        assert_eq!(backups(&dir), Vec::<PathBuf>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn migration_failure_keeps_the_backup_and_aborts() {
        let dir = temp_dir("migration_failure");
        let db_path = dir.join("stats.db");
        legacy_db(&db_path).await;
        // The pre-flight and schema upgrade succeed, but the rollup PII
        // backfill then fails: a real post-backup open failure.
        raw_sql(
            &db_path,
            "DELETE FROM stats_meta WHERE key = 'rollup_pii_v2'",
        )
        .await;
        raw_sql(&db_path, "DROP TABLE stats_hourly").await;

        let error = prepare_stats_db(&dir, false, DbAutoMigrate::Enabled)
            .await
            .map(|_| ())
            .expect_err("a migration failure must abort startup")
            .to_string();
        assert!(
            error.contains("failed to migrate stats database")
                && error.contains("pre-migration backup is at"),
            "the error must explain the abort and name the backup: {error}"
        );

        let backup = stats_backup_path(&db_path, 1);
        assert!(
            backup.is_file(),
            "the pre-migration backup must remain after a failure"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn verification_mismatch_keeps_the_backup_and_aborts() {
        let dir = temp_dir("verification_mismatch");
        let db_path = dir.join("stats.db");
        current_db(&db_path).await;
        raw_sql(
            &db_path,
            "DELETE FROM stats_meta WHERE key = 'schema_version'",
        )
        .await;
        // Force the stored marker back to 1 after the migration write, so the
        // post-migration verification observes a mismatch.
        raw_sql(
            &db_path,
            "CREATE TRIGGER pin_old_schema AFTER INSERT ON stats_meta \
             WHEN NEW.key = 'schema_version' \
             BEGIN UPDATE stats_meta SET value = '1' WHERE key = 'schema_version'; END",
        )
        .await;

        let error = prepare_stats_db(&dir, false, DbAutoMigrate::Enabled)
            .await
            .map(|_| ())
            .expect_err("a failed verification must abort startup")
            .to_string();
        assert!(
            error.contains("does not report the required schema version")
                && error.contains("pre-migration backup is at"),
            "the error must explain the verification failure and name the backup: {error}"
        );

        let backup = stats_backup_path(&db_path, 1);
        assert!(
            backup.is_file(),
            "the pre-migration backup must remain after a verification failure"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn existing_backup_collision_refuses_auto_migration() {
        let dir = temp_dir("backup_collision");
        let db_path = dir.join("stats.db");
        legacy_db(&db_path).await;
        let backup = stats_backup_path(&db_path, 1);
        std::fs::write(&backup, b"operator backup").unwrap();
        let before = db_bytes(&db_path);

        let error = prepare_stats_db(&dir, false, DbAutoMigrate::Enabled)
            .await
            .map(|_| ())
            .expect_err("an existing backup must never be overwritten")
            .to_string();
        assert!(
            error.contains("would overwrite the existing backup"),
            "the refusal must name the collision: {error}"
        );
        assert_eq!(std::fs::read(&backup).unwrap(), b"operator backup");
        assert_eq!(db_bytes(&db_path), before);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
