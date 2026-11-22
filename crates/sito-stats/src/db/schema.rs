//! Schema creation, additive migrations, and rollup PII backfill.

#[allow(clippy::wildcard_imports, unused_imports)]
use super::*;

impl StatsDb {
    /// Opens or creates an in-memory SQLite database (primarily for testing).
    pub async fn in_memory() -> Result<Self, StatsError> {
        Self::in_memory_with_options(StatsOpenOptions::default()).await
    }

    /// In-memory database with an explicit rollup client-name policy.
    pub async fn in_memory_with_rollup_client_names(
        rollup_client_names: bool,
    ) -> Result<Self, StatsError> {
        Self::in_memory_with_options(StatsOpenOptions {
            rollup_client_names,
            ..StatsOpenOptions::default()
        })
        .await
    }

    /// In-memory database with explicit open options.
    pub async fn in_memory_with_options(options: StatsOpenOptions) -> Result<Self, StatsError> {
        let connection_options = SqliteConnectOptions::from_str("sqlite::memory:")?
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5))
            .pragma("secure_delete", "ON");

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(connection_options)
            .await?;

        let db = Self::new(pool, None, random_salt(), options);
        db.run_migrations_with_mode(options.migration_mode).await?;
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
        Self::open_with_options(
            db_path,
            StatsOpenOptions {
                rollup_client_names,
                ..StatsOpenOptions::default()
            },
        )
        .await
    }

    /// Opens or creates a SQLite database on disk with explicit options.
    ///
    /// With [`MigrationMode::RequireCurrent`] an older database is refused
    /// before any schema DDL runs, so its schema and data stay untouched.
    pub async fn open_with_options(
        db_path: impl AsRef<Path>,
        options: StatsOpenOptions,
    ) -> Result<Self, StatsError> {
        let path = db_path.as_ref().to_path_buf();
        let directory = path
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        tokio::fs::create_dir_all(&directory).await?;
        let salt = load_or_create_salt(&directory)?;
        ensure_private_db_file(&path)?;

        let connection_options = SqliteConnectOptions::new()
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
            .connect_with(connection_options)
            .await?;

        let db = Self::new(pool, Some(path), salt, options);
        db.run_migrations_with_mode(options.migration_mode).await?;
        db.repair_permissions()?;
        db.backfill_rollup_pii().await?;
        db.sync_rollup_name_policy().await?;
        Ok(db)
    }

    fn new(
        pool: Pool<Sqlite>,
        db_path: Option<PathBuf>,
        salt: [u8; 32],
        options: StatsOpenOptions,
    ) -> Self {
        Self {
            pool,
            db_path,
            salt: Arc::new(salt),
            rollup_client_names: Arc::new(AtomicBool::new(options.rollup_client_names)),
            maintenance_lock: Arc::new(tokio::sync::Mutex::new(())),
            cache: Arc::new(StatsCache::default()),
        }
    }

    /// Runs embedded SQL migrations followed by idempotent additive schema
    /// changes under the default [`MigrationMode::Auto`] policy.
    pub async fn run_migrations(&self) -> Result<(), StatsError> {
        self.run_migrations_with_mode(MigrationMode::Auto).await
    }

    /// Checks the stored schema version and, when allowed, upgrades the
    /// database to [`SCHEMA_VERSION`].
    ///
    /// A database written by a newer binary is always refused before any DDL
    /// runs. Under [`MigrationMode::RequireCurrent`] an older database is
    /// refused before any DDL runs as well. A current database is left
    /// untouched, which makes reopening idempotent.
    pub async fn run_migrations_with_mode(&self, mode: MigrationMode) -> Result<(), StatsError> {
        let found = self.schema_version().await?;
        if found > SCHEMA_VERSION {
            return Err(StatsError::SchemaTooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        if found == SCHEMA_VERSION {
            // The version marker is committed atomically with the additive
            // DDL, so a current database is already fully migrated.
            return Ok(());
        }
        if mode == MigrationMode::RequireCurrent {
            return Err(StatsError::MigrationRequired {
                found,
                supported: SCHEMA_VERSION,
            });
        }

        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(StatsError::Migration)?;
        self.ensure_additive_schema().await
    }

    /// Applies additive tables that old 1.9.3 binaries can ignore, then
    /// records the supported schema version in the same transaction.
    ///
    /// This deliberately does **not** use a new sqlx migration file: an old
    /// binary's embedded migrator rejects `_sqlx_migrations` rows whose version
    /// it does not know (`VersionMissing`). Running idempotent DDL instead
    /// keeps the database openable by 1.9.3 while new code gets the table.
    ///
    /// The version marker is re-read under the `BEGIN IMMEDIATE` write lock
    /// before any DDL. A newer binary may have migrated the database after the
    /// caller's pre-flight check, so this guard is what actually prevents an
    /// older binary from overwriting a newer marker. Every caller must go
    /// through this method (it is deliberately private) rather than writing
    /// the marker itself.
    async fn ensure_additive_schema(&self) -> Result<(), StatsError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

        let found = Self::read_stored_schema_version_conn(&mut tx).await?;
        if found > SCHEMA_VERSION {
            tx.rollback().await?;
            return Err(StatsError::SchemaTooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        if found == SCHEMA_VERSION {
            // Another current binary won the race between the pre-flight
            // check and this transaction. Its commit already included the
            // additive objects, so leave the database untouched.
            tx.rollback().await?;
            return Ok(());
        }

        sqlx::query(
            r"
            CREATE TABLE IF NOT EXISTS stats_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            ",
        )
        .execute(&mut *tx)
        .await?;
        // Supports row-bounded retention chunk cursors `(ts, id)` without a
        // temp B-tree. Additive runtime DDL keeps old binaries compatible.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_ql_ts_id ON query_log(ts, id)")
            .execute(&mut *tx)
            .await?;
        // Commit the marker with the additive objects: a crash cannot leave a
        // database that claims to be current without the runtime schema. The
        // `WHERE` clause is defense in depth: only an older/legacy value may
        // be advanced, never an equal or newer marker.
        sqlx::query(
            "INSERT INTO stats_meta (key, value) VALUES ('schema_version', ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value \
             WHERE CAST(stats_meta.value AS INTEGER) < CAST(excluded.value AS INTEGER)",
        )
        .bind(SCHEMA_VERSION.to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Schema version recorded in this database, or
    /// [`LEGACY_SCHEMA_VERSION`] when it predates the marker.
    pub async fn schema_version(&self) -> Result<i64, StatsError> {
        Self::read_stored_schema_version(&self.pool).await
    }

    /// Highest schema version this binary can operate on.
    #[must_use]
    pub const fn supported_schema_version() -> i64 {
        SCHEMA_VERSION
    }

    /// Whether this database is exactly at [`SCHEMA_VERSION`].
    pub async fn is_schema_current(&self) -> Result<bool, StatsError> {
        Ok(self.schema_version().await? == SCHEMA_VERSION)
    }

    /// Reads the schema version of a database file without creating,
    /// migrating, or otherwise writing to it.
    ///
    /// Returns `Ok(None)` when the file does not exist. Existing databases
    /// without a marker report [`LEGACY_SCHEMA_VERSION`]. This is the dry-run
    /// entry point for an explicit migration command.
    pub async fn inspect_schema_version(
        db_path: impl AsRef<Path>,
    ) -> Result<Option<SchemaInspection>, StatsError> {
        let path = db_path.as_ref();
        if !path.exists() {
            return Ok(None);
        }

        let connection_options = SqliteConnectOptions::new()
            .filename(path)
            .read_only(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(connection_options)
            .await?;
        let found = Self::read_stored_schema_version(&pool).await;
        pool.close().await;
        found.map(|found| {
            Some(SchemaInspection {
                found,
                supported: SCHEMA_VERSION,
            })
        })
    }

    async fn read_stored_schema_version(pool: &Pool<Sqlite>) -> Result<i64, StatsError> {
        let mut conn = pool.acquire().await?;
        Self::read_stored_schema_version_conn(&mut conn).await
    }

    /// Reads and validates the stored marker through an existing connection.
    ///
    /// Running this inside the additive `BEGIN IMMEDIATE` transaction is what
    /// makes the newer-version guard race-free: no other writer can commit
    /// between this read and the conditional marker write.
    async fn read_stored_schema_version_conn(
        conn: &mut SqliteConnection,
    ) -> Result<i64, StatsError> {
        // Do not create `stats_meta` here: a version check must not run DDL,
        // both so refusal is side-effect free and so a read-only connection
        // can perform the check.
        let has_meta: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'stats_meta'",
        )
        .fetch_one(&mut *conn)
        .await?;
        if has_meta == 0 {
            return Ok(LEGACY_SCHEMA_VERSION);
        }

        let value: Option<String> =
            sqlx::query_scalar("SELECT value FROM stats_meta WHERE key = 'schema_version'")
                .fetch_optional(&mut *conn)
                .await?;
        let Some(raw) = value else {
            return Ok(LEGACY_SCHEMA_VERSION);
        };
        parse_schema_version(&raw)
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
                                if self.rollup_client_names_enabled() {
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
        .bind(if self.rollup_client_names_enabled() {
            "true"
        } else {
            "false"
        })
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Re-applies a new `rollup_client_names` policy to the live database.
    ///
    /// Config apply calls this when the setting changes so the new policy takes
    /// effect without a restart. Turning names off scrubs every existing
    /// rollup (irreversible); turning them on only affects future rollups.
    pub async fn set_rollup_client_names(&self, enabled: bool) -> Result<(), StatsError> {
        self.rollup_client_names.store(enabled, Ordering::Relaxed);
        self.sync_rollup_name_policy().await
    }

    /// Enforces the current `rollup_client_names` policy on existing rollups.
    ///
    /// When the operator switches the setting from `true` to `false`, rewrite
    /// every stored `top_clients` list with names removed. A marker stores the
    /// last policy so this full scrub runs only on the transition (or once when
    /// upgrading from a build that had no policy marker).
    ///
    /// The whole check/scrub/marker sequence runs in one `BEGIN IMMEDIATE`
    /// transaction on a pooled write connection. That serializes it with
    /// in-flight retention chunks and keep-aggregates clears: the scrub waits
    /// for a writer already holding the lock, and a writer that starts after
    /// the scrub commits observes the live `false` policy and strips names.
    /// The marker is committed with the scrubbed rows, so a later startup
    /// cannot skip the scrub while a name-bearing row is still visible.
    pub(super) async fn sync_rollup_name_policy(&self) -> Result<(), StatsError> {
        // Take the write lock before the first read. An in-flight writer is
        // either included in this scan (it committed before we acquired the
        // lock) or blocked until the marker is committed.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let stored: Option<String> = sqlx::query_scalar(
            "SELECT value FROM stats_meta WHERE key = 'rollup_client_names_policy'",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let current = if self.rollup_client_names_enabled() {
            "true"
        } else {
            "false"
        };

        if !self.rollup_client_names_enabled() && stored.as_deref() != Some("false") {
            self.scrub_rollup_client_names(&mut tx).await?;
        }

        sqlx::query(
            "INSERT INTO stats_meta (key, value) VALUES ('rollup_client_names_policy', ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(current)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Rewrites every rollup client list with names removed (and raw IPs
    /// hashed), using the caller's transaction so the scrub and the policy
    /// marker are atomic with respect to concurrent rollup writers.
    async fn scrub_rollup_client_names(
        &self,
        conn: &mut SqliteConnection,
    ) -> Result<(), StatsError> {
        let mut last_hour = i64::MIN;
        loop {
            let rows = sqlx::query(
                "SELECT hour, top_clients FROM stats_hourly \
                 WHERE hour > ? AND top_clients IS NOT NULL AND top_clients != '[]' \
                 ORDER BY hour ASC LIMIT ?",
            )
            .bind(last_hour)
            .bind(ROLLUP_PII_BACKFILL_BATCH)
            .fetch_all(&mut *conn)
            .await?;
            if rows.is_empty() {
                break;
            }

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
                    .execute(&mut *conn)
                    .await?;
            }
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

/// Parses a stored `schema_version` marker. Anything that is not a positive
/// version number is rejected rather than guessed at, so a corrupt marker can
/// never silently downgrade a database or skip an upgrade.
fn parse_schema_version(raw: &str) -> Result<i64, StatsError> {
    match raw.trim().parse::<i64>() {
        Ok(version) if version >= LEGACY_SCHEMA_VERSION => Ok(version),
        _ => Err(StatsError::InvalidSchemaVersion {
            value: raw.to_string(),
        }),
    }
}

#[cfg(test)]
mod schema_version_tests {
    use super::*;

    fn temp_dir(prefix: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sito-stats-{prefix}-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Regression: a newer binary can commit a newer marker between the
    /// pre-flight check in `run_migrations_with_mode` and the additive
    /// transaction. The in-transaction guard must refuse it and must not
    /// rewrite the marker to the older supported version.
    #[tokio::test]
    async fn test_additive_pass_refuses_newer_marker_written_after_preflight() {
        let dir = temp_dir("schema-race-guard");
        let db_path = dir.join("stats.db");
        let db = StatsDb::open(&db_path).await.unwrap();

        let newer = SCHEMA_VERSION + 1;
        sqlx::query("UPDATE stats_meta SET value = ? WHERE key = 'schema_version'")
            .bind(newer.to_string())
            .execute(db.pool())
            .await
            .unwrap();

        // Bypass the pre-flight check exactly as a lost race would.
        let err = db.ensure_additive_schema().await.unwrap_err();
        assert!(
            matches!(
                err,
                StatsError::SchemaTooNew { found, supported }
                    if found == newer && supported == SCHEMA_VERSION
            ),
            "expected SchemaTooNew from the in-transaction guard, got {err}"
        );

        let stored: String =
            sqlx::query_scalar("SELECT value FROM stats_meta WHERE key = 'schema_version'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(
            stored,
            newer.to_string(),
            "a newer marker must never be overwritten"
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The guarded additive pass still advances a legacy/older marker to the
    /// supported version (the conditional upsert must not block real
    /// upgrades).
    #[tokio::test]
    async fn test_additive_pass_advances_legacy_marker() {
        let dir = temp_dir("schema-legacy-advance");
        let db_path = dir.join("stats.db");
        let db = StatsDb::open(&db_path).await.unwrap();

        sqlx::query("UPDATE stats_meta SET value = ? WHERE key = 'schema_version'")
            .bind(LEGACY_SCHEMA_VERSION.to_string())
            .execute(db.pool())
            .await
            .unwrap();

        db.ensure_additive_schema().await.unwrap();

        let stored: String =
            sqlx::query_scalar("SELECT value FROM stats_meta WHERE key = 'schema_version'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(stored, SCHEMA_VERSION.to_string());

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
