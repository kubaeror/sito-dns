//! Pool/secret helpers and database maintenance operations.

#[allow(clippy::wildcard_imports, unused_imports)]
use super::*;

impl StatsDb {
    /// Returns a reference to the underlying SQLite connection pool.
    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }

    /// Whether the pool has been closed (shutdown or unrecoverable failure).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.pool.is_closed()
    }

    /// Cheap readiness probe for the stats database.
    ///
    /// A single `SELECT 1` detects a locked/corrupt/unavailable database
    /// without touching query-log data. Callers bound the probe with a timeout
    /// so a wedged disk cannot stall a health endpoint.
    pub async fn health_check(&self) -> Result<(), StatsError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Whether `value` is a stored keyed digest (current or legacy prefix).
    ///
    /// Requiring exactly 64 hex characters avoids treating a real IPv6 address
    /// such as `b3::1` as already hashed and writing it raw.
    pub(super) fn is_hashed_client_id(value: &str) -> bool {
        [ROLLUP_HASH_PREFIX, LEGACY_ROLLUP_HASH_PREFIX]
            .iter()
            .any(|prefix| {
                value.strip_prefix(prefix).is_some_and(|hex| {
                    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())
                })
            })
    }

    /// Hashes a client identifier for storage in `stats_hourly`.
    ///
    /// Already-hashed values are returned unchanged so re-merging a rollup does
    /// not hash twice. The keyed BLAKE3 digest is not reversible without the
    /// per-install salt.
    pub(super) fn hash_client_ip(&self, client_ip: &str) -> String {
        if Self::is_hashed_client_id(client_ip) {
            return client_ip.to_string();
        }
        let mut hasher = blake3::Hasher::new_keyed(self.salt.as_ref());
        hasher.update(client_ip.as_bytes());
        format!("{ROLLUP_HASH_PREFIX}{}", hasher.finalize().to_hex())
    }

    /// Triggers SQLite `VACUUM` and truncates the WAL so the compacted file
    /// size is immediately visible on disk (WAL mode otherwise keeps the freed
    /// pages in the sidecar file).
    pub async fn vacuum(&self) -> Result<(), StatsError> {
        sqlx::query("VACUUM").execute(&self.pool).await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.pool)
            .await?;
        // SQLite may recreate the WAL/SHM sidecars during the checkpoint.
        self.repair_permissions()?;
        Ok(())
    }

    /// Returns the database file size in bytes if stored on disk.
    ///
    /// WAL mode keeps recent writes in `<db>-wal` and index metadata in
    /// `<db>-shm`; both count towards the on-disk footprint and are included.
    pub async fn db_size_bytes(&self) -> Result<u64, StatsError> {
        let Some(ref path) = self.db_path else {
            return Ok(0);
        };

        let mut total = 0u64;
        for suffix in ["", "-wal", "-shm"] {
            let mut candidate = path.as_os_str().to_os_string();
            candidate.push(suffix);
            match tokio::fs::metadata(PathBuf::from(candidate)).await {
                Ok(meta) => total = total.saturating_add(meta.len()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(StatsError::Io(e)),
            }
        }
        Ok(total)
    }

    /// Returns aggregated activity for the last N hours bucketed by hour.
    pub async fn get_hourly_activity(&self, hours: u32) -> Result<Vec<HourlyActivity>, StatsError> {
        let now_sec = chrono::Utc::now().timestamp();
        let current_hour_sec = (now_sec / 3600) * 3600;
        let hours_i64 = i64::from(hours.max(1));
        let start_hour_sec = current_hour_sec - (hours_i64 - 1) * 3600;
        let start_ms = start_hour_sec * 1000;

        let rows = sqlx::query(
            r"
            SELECT
                (ts / 3600000) * 3600 as hour_sec,
                COUNT(*) as total,
                SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) as blocked
            FROM query_log
            WHERE ts >= ?
            GROUP BY hour_sec
            ",
        )
        .bind(start_ms)
        .fetch_all(&self.pool)
        .await?;

        let mut map = std::collections::HashMap::new();
        for r in rows {
            let hour_sec: i64 = r.get("hour_sec");
            let total: i64 = r.get::<Option<i64>, _>("total").unwrap_or(0);
            let blocked: i64 = r.get::<Option<i64>, _>("blocked").unwrap_or(0);
            map.insert(hour_sec, (total, blocked));
        }

        // Also merge stats_hourly in case older logs were pruned by retention.
        // A live query and an archived rollup can legitimately cover the same
        // hour (retention prunes part of an hour), so the two are added
        // together rather than one silently replacing the other.
        let archived_rows = sqlx::query(
            r"
            SELECT
                (hour / 3600000) * 3600 as hour_sec,
                queries as total,
                blocked
            FROM stats_hourly
            WHERE hour >= ?
            ",
        )
        .bind(start_ms)
        .fetch_all(&self.pool)
        .await?;

        for r in archived_rows {
            let hour_sec: i64 = r.get("hour_sec");
            let total: i64 = r.get::<Option<i64>, _>("total").unwrap_or(0);
            let blocked: i64 = r.get::<Option<i64>, _>("blocked").unwrap_or(0);
            let entry = map.entry(hour_sec).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(total);
            entry.1 = entry.1.saturating_add(blocked);
        }

        let mut result = Vec::with_capacity(hours as usize);
        for h in 0..hours_i64 {
            let h_sec = start_hour_sec + h * 3600;
            let (total, blocked) = map.get(&h_sec).copied().unwrap_or((0, 0));
            result.push(HourlyActivity {
                timestamp_sec: h_sec,
                total_queries: total,
                blocked_queries: blocked,
            });
        }

        Ok(result)
    }
}
