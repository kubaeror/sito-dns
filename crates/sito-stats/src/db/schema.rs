//! Schema creation, additive migrations, and rollup PII backfill.

#[allow(clippy::wildcard_imports, unused_imports)]
use super::*;

impl StatsDb {
    /// Opens or creates an in-memory SQLite database (primarily for testing).
    pub async fn in_memory() -> Result<Self, StatsError> {
        Self::in_memory_with_rollup_client_names(false).await
    }

    /// In-memory database with an explicit rollup client-name policy.
    pub async fn in_memory_with_rollup_client_names(
        rollup_client_names: bool,
    ) -> Result<Self, StatsError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5))
            .pragma("secure_delete", "ON");

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        let db = Self {
            pool,
            db_path: None,
            salt: Arc::new(random_salt()),
            rollup_client_names,
            cache: Arc::new(StatsCache::default()),
        };
        db.run_migrations().await?;
        db.backfill_rollup_pii().await?;
        db.sync_rollup_name_policy().await?;
        Ok(db)
    }

    /// Opens or creates a SQLite database on disk in WAL mode.
    pub async fn open(db_path: impl AsRef<Path>) -> Result<Self, StatsError> {
        Self::open_with_rollup_client_names(db_path, false).await
    }

    /// Opens or creates a SQLite database on disk with an explicit rollup
    /// client-name policy. The per-install salt lives next to the database as
    /// `<data_dir>/stats-salt`.
    pub async fn open_with_rollup_client_names(
        db_path: impl AsRef<Path>,
        rollup_client_names: bool,
    ) -> Result<Self, StatsError> {
        let path = db_path.as_ref().to_path_buf();
        let directory = path
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        tokio::fs::create_dir_all(&directory).await?;
        let salt = load_or_create_salt(&directory)?;
        ensure_private_db_file(&path)?;

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            // A retention chunk can hold the writer lock on a slow disk. Give
            // the single-writer pipeline enough room to wait it out instead of
            // returning SQLITE_BUSY and dropping a query-log batch.
            .busy_timeout(Duration::from_secs(30))
            .pragma("secure_delete", "ON");

        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .connect_with(options)
            .await?;

        let db = Self {
            pool,
            db_path: Some(path),
            salt: Arc::new(salt),
            rollup_client_names,
            cache: Arc::new(StatsCache::default()),
        };
        db.run_migrations().await?;
        db.repair_permissions()?;
        db.backfill_rollup_pii().await?;
        db.sync_rollup_name_policy().await?;
        Ok(db)
    }

    /// Runs embedded SQL migrations followed by idempotent additive schema
    /// changes.
    pub async fn run_migrations(&self) -> Result<(), StatsError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(StatsError::Migration)?;
        self.ensure_additive_schema().await
    }

    /// Applies additive tables that old 1.9.3 binaries can ignore.
    ///
    /// This deliberately does **not** use a new sqlx migration file: an old
    /// binary's embedded migrator rejects `_sqlx_migrations` rows whose version
    /// it does not know (`VersionMissing`). Running idempotent DDL instead
    /// keeps the database openable by 1.9.3 while new code gets the table.
    pub(super) async fn ensure_additive_schema(&self) -> Result<(), StatsError> {
        sqlx::query(
            r"
            CREATE TABLE IF NOT EXISTS stats_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            ",
        )
        .execute(&self.pool)
        .await?;
        // Supports row-bounded retention chunk cursors `(ts, id)` without a
        // temp B-tree. Additive runtime DDL keeps old binaries compatible.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_ql_ts_id ON query_log(ts, id)")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Repairs permissions on the database file and WAL/SHM sidecars so a
    /// pre-existing loose `stats.db` cannot leak query history to other local
    /// users. No-op for in-memory databases.
    pub fn repair_permissions(&self) -> Result<(), StatsError> {
        let Some(ref path) = self.db_path else {
            return Ok(());
        };
        for suffix in ["", "-wal", "-shm"] {
            let mut candidate = path.as_os_str().to_os_string();
            candidate.push(suffix);
            set_private_permissions(Path::new(&candidate))?;
        }
        Ok(())
    }

    /// One-time backfill for rollups written by older versions: hash raw
    /// client identifiers and drop client names unless explicitly enabled.
    /// Idempotent via the `rollup_pii_v2` marker in `stats_meta`. v2 also
    /// re-runs over databases written by the unreleased base that may have
    /// marked v1 complete while skipping malformed payloads.
    pub(super) async fn backfill_rollup_pii(&self) -> Result<(), StatsError> {
        let done: Option<String> =
            sqlx::query_scalar("SELECT value FROM stats_meta WHERE key = 'rollup_pii_v2'")
                .fetch_optional(&self.pool)
                .await?;
        if done.as_deref() == Some("1") {
            return Ok(());
        }

        // Process in bounded batches so a large legacy rollup table does not
        // hold one long write transaction during startup. The operation is
        // idempotent, so a crash before the marker simply re-runs it.
        let mut last_hour = i64::MIN;
        loop {
            let rows = sqlx::query(
                "SELECT hour, top_clients FROM stats_hourly \
                 WHERE hour > ? AND top_clients IS NOT NULL AND top_clients != '[]' \
                 ORDER BY hour ASC LIMIT ?",
            )
            .bind(last_hour)
            .bind(ROLLUP_PII_BACKFILL_BATCH)
            .fetch_all(&self.pool)
            .await?;
            if rows.is_empty() {
                break;
            }

            let mut tx = self.pool.begin().await?;
            for row in &rows {
                let hour: i64 = row.get("hour");
                last_hour = last_hour.max(hour);
                let raw: Option<String> = row.get("top_clients");
                let Some(raw) = raw else { continue };
                let transformed: Vec<ClientTop> = match serde_json::from_str::<Vec<ClientTop>>(&raw)
                {
                    Ok(clients) => clients
                        .into_iter()
                        .map(|(client_ip, client_name, total, blocked, last_seen)| {
                            (
                                self.hash_client_ip(&client_ip),
                                if self.rollup_client_names {
                                    client_name
                                } else {
                                    None
                                },
                                total,
                                blocked,
                                last_seen,
                            )
                        })
                        .collect(),
                    Err(e) => {
                        // Never leave an unparseable legacy payload in place:
                        // it may contain raw identifiers and the marker below
                        // would prevent another attempt. Dropping only the
                        // bounded top-N list keeps the aggregate counts.
                        tracing::warn!(
                            hour,
                            error = %e,
                            "Discarding unparseable legacy stats_hourly.top_clients payload"
                        );
                        Vec::new()
                    }
                };
                sqlx::query("UPDATE stats_hourly SET top_clients = ? WHERE hour = ?")
                    .bind(encode_tops(&transformed))
                    .bind(hour)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
        }

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO stats_meta (key, value) VALUES ('rollup_pii_v2', '1') \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO stats_meta (key, value) VALUES ('rollup_client_names_policy', ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(if self.rollup_client_names {
            "true"
        } else {
            "false"
        })
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Enforces the current `rollup_client_names` policy on existing rollups.
    ///
    /// When the operator switches the setting from `true` to `false`, rewrite
    /// every stored `top_clients` list with names removed. A marker stores the
    /// last policy so this full scrub runs only on the transition (or once when
    /// upgrading from a build that had no policy marker).
    pub(super) async fn sync_rollup_name_policy(&self) -> Result<(), StatsError> {
        let stored: Option<String> = sqlx::query_scalar(
            "SELECT value FROM stats_meta WHERE key = 'rollup_client_names_policy'",
        )
        .fetch_optional(&self.pool)
        .await?;
        let current = if self.rollup_client_names {
            "true"
        } else {
            "false"
        };

        if !self.rollup_client_names && stored.as_deref() != Some("false") {
            self.scrub_rollup_client_names().await?;
        }

        sqlx::query(
            "INSERT INTO stats_meta (key, value) VALUES ('rollup_client_names_policy', ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(current)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Rewrites every rollup client list with names removed (and raw IPs
    /// hashed) in bounded batches.
    pub(super) async fn scrub_rollup_client_names(&self) -> Result<(), StatsError> {
        let mut last_hour = i64::MIN;
        loop {
            let rows = sqlx::query(
                "SELECT hour, top_clients FROM stats_hourly \
                 WHERE hour > ? AND top_clients IS NOT NULL AND top_clients != '[]' \
                 ORDER BY hour ASC LIMIT ?",
            )
            .bind(last_hour)
            .bind(ROLLUP_PII_BACKFILL_BATCH)
            .fetch_all(&self.pool)
            .await?;
            if rows.is_empty() {
                break;
            }

            let mut tx = self.pool.begin().await?;
            for row in &rows {
                let hour: i64 = row.get("hour");
                last_hour = last_hour.max(hour);
                let raw: Option<String> = row.get("top_clients");
                let Some(raw) = raw else { continue };
                let transformed: Vec<ClientTop> = match serde_json::from_str::<Vec<ClientTop>>(&raw)
                {
                    Ok(clients) => clients
                        .into_iter()
                        .map(|(client_ip, _name, total, blocked, last_seen)| {
                            (
                                self.hash_client_ip(&client_ip),
                                None,
                                total,
                                blocked,
                                last_seen,
                            )
                        })
                        .collect(),
                    Err(e) => {
                        tracing::warn!(
                            hour,
                            error = %e,
                            "Discarding unparseable stats_hourly.top_clients payload during name scrub"
                        );
                        Vec::new()
                    }
                };
                sqlx::query("UPDATE stats_hourly SET top_clients = ? WHERE hour = ?")
                    .bind(encode_tops(&transformed))
                    .bind(hour)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
        }
        Ok(())
    }

    /// Timestamp (unix millis) of the last successful retention sweep, if any.
    pub async fn retention_last_success_ms(&self) -> Result<Option<i64>, StatsError> {
        let value: Option<String> =
            sqlx::query_scalar("SELECT value FROM stats_meta WHERE key = 'retention_last_success'")
                .fetch_optional(&self.pool)
                .await?;
        Ok(value.and_then(|raw| raw.parse::<i64>().ok()))
    }

    pub(super) async fn record_retention_success(&self, now_ms: i64) -> Result<(), StatsError> {
        sqlx::query(
            "INSERT INTO stats_meta (key, value) VALUES ('retention_last_success', ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(now_ms.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
