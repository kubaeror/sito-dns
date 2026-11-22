//! Consistent, owner-only snapshots of the stats database.
//!
//! `sito db migrate` must be able to keep a rollback copy of a database that
//! may still have committed data in a `-wal` sidecar (for example after an
//! unclean shutdown). Copying `stats.db` byte-for-byte is therefore not
//! enough: SQLite's `VACUUM INTO` reads through a transaction and writes a
//! self-contained snapshot of the main file plus the committed WAL content.

#[allow(clippy::wildcard_imports, unused_imports)]
use super::*;

impl StatsDb {
    /// Writes a consistent snapshot of the database at `source` to `dest`.
    ///
    /// The snapshot is produced by `VACUUM INTO`, so committed WAL content is
    /// included without copying a live `-wal` file. `dest` must not exist.
    ///
    /// SQLite creates the output file with the process umask, so the snapshot
    /// is staged inside a private (0700) directory next to `dest`, then
    /// fsynced, made 0600, and hard-linked to `dest`. The final `hard_link`
    /// fails with [`std::io::ErrorKind::AlreadyExists`] instead of silently
    /// overwriting a backup that appeared concurrently.
    pub async fn snapshot_to(
        source: impl AsRef<Path>,
        dest: impl AsRef<Path>,
    ) -> Result<(), StatsError> {
        let source = source.as_ref();
        let dest = dest.as_ref();

        if !source.is_file() {
            return Err(StatsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("stats database '{}' does not exist", source.display()),
            )));
        }
        if dest.exists() {
            return Err(StatsError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("backup '{}' already exists", dest.display()),
            )));
        }

        let parent = dest.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let staging = parent.join(format!(
            ".{}.{}.{:016x}.backup-tmp",
            dest.file_name().map_or_else(
                || "stats.db".into(),
                |name| name.to_string_lossy().into_owned()
            ),
            std::process::id(),
            rand::random::<u64>()
        ));
        create_private_dir(&staging)?;

        let staged = staging.join("snapshot.db");
        let result = vacuum_into(source, &staged)
            .await
            .and_then(|()| -> Result<(), StatsError> {
                // Repair the mode even on Unix builds where `VACUUM INTO`
                // created the file with a permissive umask.
                set_private_permissions(&staged)?;
                sync_file(&staged)?;
                std::fs::hard_link(&staged, dest)?;
                fsync_dir(parent);
                Ok(())
            });

        let _ = std::fs::remove_dir_all(&staging);
        result
    }
}

/// Opens `source` without creating it and writes a `VACUUM INTO` snapshot.
async fn vacuum_into(source: &Path, dest: &Path) -> Result<(), StatsError> {
    let dest = dest.to_str().ok_or_else(|| {
        StatsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "backup staging path is not valid UTF-8",
        ))
    })?;

    let connection_options = SqliteConnectOptions::new()
        .filename(source)
        .create_if_missing(false)
        // Do not force a journal mode: the source may legitimately be in WAL
        // (a crashed server) or rollback-journal mode.
        .busy_timeout(Duration::from_secs(30));
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(connection_options)
        .await?;

    // SQLite treats the INTO argument as a string literal; double any quote.
    // The only dynamic part of the statement is that audited literal.
    let sql = format!("VACUUM INTO '{}'", dest.replace('\'', "''"));
    let result = sqlx::query(sqlx::AssertSqlSafe(sql)).execute(&pool).await;
    pool.close().await;
    result?;
    Ok(())
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<(), StatsError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> Result<(), StatsError> {
    std::fs::create_dir(path)?;
    Ok(())
}

fn sync_file(path: &Path) -> Result<(), StatsError> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

/// fsyncs the parent directory so the new backup name is durable.
fn fsync_dir(path: &Path) {
    if let Ok(dir) = std::fs::File::open(path) {
        let _ = dir.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sito-stats-backup-{label}-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A snapshot must be a self-contained database that includes committed
    /// WAL content, be owner-only, and never overwrite an existing file.
    #[tokio::test]
    async fn snapshot_includes_wal_and_refuses_overwrite() {
        let dir = temp_dir("wal");
        let source = dir.join("stats.db");
        let dest = dir.join("stats.db.v1.bak");

        // Keep the source handle open so the probe row lives in a WAL sidecar
        // at snapshot time: copying stats.db alone would lose it.
        let db = StatsDb::open(&source).await.unwrap();
        sqlx::query("CREATE TABLE snapshot_probe (value TEXT)")
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO snapshot_probe (value) VALUES ('present')")
            .execute(db.pool())
            .await
            .unwrap();
        assert!(
            PathBuf::from(format!("{}-wal", source.display())).exists(),
            "the probe write should still be in the WAL at this point"
        );

        StatsDb::snapshot_to(&source, &dest).await.unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "snapshot must be mode 0600");
        }

        let snapshot = StatsDb::open_with_options(
            &dest,
            StatsOpenOptions {
                migration_mode: MigrationMode::RequireCurrent,
                ..StatsOpenOptions::default()
            },
        )
        .await
        .expect("snapshot opens at the current schema");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM snapshot_probe")
            .fetch_one(snapshot.pool())
            .await
            .unwrap();
        assert_eq!(count, 1, "committed WAL rows must be in the snapshot");
        snapshot.pool().close().await;
        db.pool().close().await;

        let err = StatsDb::snapshot_to(&source, &dest)
            .await
            .expect_err("an existing backup must never be overwritten");
        match err {
            StatsError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists),
            other => panic!("expected an AlreadyExists IO error, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn snapshot_refuses_a_missing_source() {
        let dir = temp_dir("missing");
        let err = StatsDb::snapshot_to(dir.join("stats.db"), dir.join("stats.db.v1.bak"))
            .await
            .expect_err("a missing source must not be snapshotted");
        match err {
            StatsError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected a NotFound IO error, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
