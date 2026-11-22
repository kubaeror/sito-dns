//! Shared, side-effect-free stats database maintenance helpers.
//!
//! Both `sito db migrate` and server startup inspect and migrate the stats
//! database. They must agree on the private inspection copy, the backup path
//! and mode, ownership restoration, and the cross-process migration lock.
//! Keeping one implementation here prevents the two entry points from drifting.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sito_stats::{QueryLogAnonymizePlan, SchemaInspection, StatsDb};

/// Name of the cross-process database migration lock inside `server.data_dir`.
///
/// The lock is an advisory `flock` on this file. The file's existence is not
/// authoritative; a stale file left by a crash is harmless and the OS releases
/// the lock when the holding process exits.
pub const DB_MIGRATE_LOCK_FILE: &str = "db-migrate.lock";

/// Held while a process inspects, backs up, or migrates the stats database.
///
/// `sito db migrate` holds it from inspection through verification, and server
/// startup holds it through preparation and the runtime open. A second process
/// fails immediately instead of waiting: an unattended server start must not
/// block forever behind an operator's long-running migration.
#[derive(Debug)]
pub struct DbMigrationLock {
    file: File,
    path: PathBuf,
}

impl DbMigrationLock {
    /// Acquires the migration lock for `data_dir`.
    ///
    /// Returns [`io::ErrorKind::WouldBlock`] when another process already holds
    /// it. The lock file is created with mode 0600 (and tightened if it already
    /// existed with a looser mode).
    pub fn acquire(data_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(DB_MIGRATE_LOCK_FILE);

        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }

        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "another DB migration is in progress for data directory '{}'",
                        data_dir.display()
                    ),
                ));
            }
            Err(TryLockError::Error(e)) => return Err(e),
        }

        // Only write the PID after the lock is ours; a contender must never
        // replace the holder's diagnostics.
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        writeln!(file, "{}", std::process::id())?;
        file.flush()?;

        Ok(Self { file, path })
    }
}

impl Drop for DbMigrationLock {
    fn drop(&mut self) {
        // Remove the path while still holding the lock so a clean exit leaves no
        // stale file for the next start. The lock itself is released by dropping
        // the file handle.
        let _ = std::fs::remove_file(&self.path);
        let _ = self.file.unlock();
    }
}

/// Acquires [`DbMigrationLock`] with the operator-facing error message shared by
/// startup and `sito db migrate`.
pub fn acquire_db_migration_lock(data_dir: &Path) -> anyhow::Result<DbMigrationLock> {
    DbMigrationLock::acquire(data_dir).map_err(|e| {
        if e.kind() == io::ErrorKind::WouldBlock {
            anyhow::anyhow!(
                "Refusing to touch the stats database: another DB migration is in progress \
                 for data directory '{}'. Wait for it to finish and try again.",
                data_dir.display()
            )
        } else {
            anyhow::anyhow!(
                "Failed to acquire the database migration lock in '{}': {e}",
                data_dir.display()
            )
        }
    })
}

/// `<stats.db>.v<found>.bak`, matching the `<config>.v1.bak` convention.
pub fn stats_backup_path(db_path: &Path, found: i64) -> PathBuf {
    path_with_suffix(db_path, &format!(".v{found}.bak"))
}

/// Appends a literal suffix to the final path component (keeps non-UTF-8 paths).
pub fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Creates a 0700 staging directory so a database copy is unreadable to other
/// local users even before its own 0600 mode is applied.
fn create_private_directory(path: &Path) -> Result<(), anyhow::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir(path)?;
    Ok(())
}

/// Inspects the schema version without touching the data directory.
///
/// `StatsDb::inspect_schema_version` opens the database in place; SQLite
/// creates `-wal`/`-shm` sidecars for a WAL-mode database even through a
/// read-only connection. Inspection therefore uses a private copy (including
/// any committed `-wal` content) so refusals and the already-current no-op
/// leave no sidecars behind.
pub async fn inspect_db_without_writes(db_path: &Path) -> Result<SchemaInspection, anyhow::Error> {
    let copy = PrivateDbCopy::new(db_path)?;
    StatsDb::inspect_schema_version(copy.path())
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to inspect stats database '{}': {e}",
                db_path.display()
            )
        })?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Stats database '{}' disappeared before it could be inspected",
                db_path.display()
            )
        })
}

/// Read-only dry-run view of a retroactive anonymization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnonymizeInspection {
    pub schema: SchemaInspection,
    /// `None` unless the copied database is at the supported schema version.
    pub plan: Option<QueryLogAnonymizePlan>,
}

/// Inspects the schema and counts anonymization candidates on a private copy.
///
/// The live `stats.db` is never opened, so `--dry-run` cannot create
/// `-wal`/`-shm` sidecars or a `stats-salt` beside it. The copy lives in a 0700
/// staging directory under the data directory and is removed before returning.
/// It includes committed `-wal` content, so the count reflects rows the server
/// had already persisted before it was stopped.
pub async fn inspect_anonymize_without_writes(
    db_path: &Path,
) -> Result<AnonymizeInspection, anyhow::Error> {
    let copy = PrivateDbCopy::new(db_path)?;
    let schema = StatsDb::inspect_schema_version(copy.path())
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to inspect stats database '{}': {e}",
                db_path.display()
            )
        })?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Stats database '{}' disappeared before it could be inspected",
                db_path.display()
            )
        })?;

    let plan = if schema.is_current() {
        Some(
            StatsDb::inspect_anonymize_plan(copy.path())
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to count anonymization candidates in '{}': {e}",
                        db_path.display()
                    )
                })?,
        )
    } else {
        None
    };

    Ok(AnonymizeInspection { schema, plan })
}

/// A private 0700 copy of `stats.db` and its committed WAL content.
///
/// Dropping the copy removes the whole staging directory, including any
/// sidecars SQLite created while inspecting it.
struct PrivateDbCopy {
    staging: PathBuf,
    copy: PathBuf,
}

impl PrivateDbCopy {
    fn new(db_path: &Path) -> Result<Self, anyhow::Error> {
        let parent = db_path.parent().unwrap_or_else(|| Path::new("."));
        let staging = parent.join(format!(
            ".sito-db-inspect-{}-{:016x}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        create_private_directory(&staging)?;

        let copy = staging.join("stats.db");
        let result = (|| -> Result<(), anyhow::Error> {
            std::fs::copy(db_path, &copy).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to copy '{}' for the dry-run inspection: {e}",
                    db_path.display()
                )
            })?;
            let wal = path_with_suffix(db_path, "-wal");
            if wal.is_file() {
                std::fs::copy(&wal, path_with_suffix(&copy, "-wal")).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to copy '{}' for the dry-run inspection: {e}",
                        wal.display()
                    )
                })?;
            }
            Ok(())
        })();

        match result {
            Ok(()) => Ok(Self { staging, copy }),
            Err(e) => {
                let _ = std::fs::remove_dir_all(&staging);
                Err(e)
            }
        }
    }

    fn path(&self) -> &Path {
        &self.copy
    }
}

impl Drop for PrivateDbCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.staging);
    }
}

/// Ownership of a data-directory file, captured before the command writes
/// anything.
///
/// When `sito db migrate` is run with `sudo`, SQLite creates `-wal`/`-shm`
/// sidecars and `stats-salt` as root. The systemd unit runs the server as the
/// unprivileged `sito` user, which then cannot open or write those files. The
/// owner of the existing `stats.db` (or the data directory) is therefore
/// restored on every file the migration creates or modifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileOwner {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

pub fn file_owner(path: &Path) -> Option<FileOwner> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|meta| FileOwner {
            uid: meta.uid(),
            gid: meta.gid(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Restores `owner` on every existing path in `paths`.
///
/// Missing paths are skipped: not every candidate (for example `-shm`) exists
/// after a clean close. Files that already carry the expected owner are left
/// untouched, so a non-root invocation never attempts a privileged `chown`.
pub fn restore_ownership(paths: &[PathBuf], owner: Option<FileOwner>) -> Result<(), anyhow::Error> {
    let Some(owner) = owner else {
        return Ok(());
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for path in paths {
            let Ok(meta) = std::fs::symlink_metadata(path) else {
                continue;
            };
            if !meta.file_type().is_file() {
                continue;
            }
            if meta.uid() == owner.uid && meta.gid() == owner.gid {
                continue;
            }
            std::os::unix::fs::chown(path, Some(owner.uid), Some(owner.gid)).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to restore ownership of '{}' to {}:{}: {e}. Run this command as the \
                     service user, or fix the ownership manually.",
                    path.display(),
                    owner.uid,
                    owner.gid
                )
            })?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = paths;
    }
    Ok(())
}

/// Every path the migration can create or modify under `server.data_dir`.
pub fn migration_created_paths(
    db_path: &Path,
    data_dir: &Path,
    backup_path: Option<&Path>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for suffix in ["", "-wal", "-shm", "-journal"] {
        paths.push(path_with_suffix(db_path, suffix));
    }
    // `load_or_create_salt` creates `<data_dir>/stats-salt` during the open.
    paths.push(data_dir.join("stats-salt"));
    paths.push(data_dir.join(DB_MIGRATE_LOCK_FILE));
    if let Some(backup) = backup_path {
        paths.push(backup.to_path_buf());
    }
    paths
}

/// Restores ownership on drop as a backstop for panics/early returns.
pub struct OwnershipGuard {
    paths: Vec<PathBuf>,
    owner: Option<FileOwner>,
}

impl OwnershipGuard {
    pub fn new(paths: Vec<PathBuf>, owner: Option<FileOwner>) -> Self {
        Self { paths, owner }
    }

    /// Restores ownership now, propagating a failure. On success the guard no
    /// longer retries on drop.
    pub fn restore(&mut self) -> Result<(), anyhow::Error> {
        let result = restore_ownership(&self.paths, self.owner);
        if result.is_ok() {
            self.paths.clear();
        }
        result
    }
}

impl Drop for OwnershipGuard {
    fn drop(&mut self) {
        let _ = restore_ownership(&self.paths, self.owner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sito_db_maintenance_{label}_{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn migration_lock_is_exclusive_and_released_on_drop() {
        let dir = temp_dir("lock");
        let lock = DbMigrationLock::acquire(&dir).unwrap();
        let err = DbMigrationLock::acquire(&dir).expect_err("second lock must fail");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        drop(lock);
        let _relocked = DbMigrationLock::acquire(&dir).expect("the lock must be released");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn migration_lock_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("lock_mode");
        let _lock = DbMigrationLock::acquire(&dir).unwrap();
        let mode = std::fs::metadata(dir.join(DB_MIGRATE_LOCK_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
