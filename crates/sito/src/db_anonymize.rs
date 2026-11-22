//! `sito db anonymize --all`: bounded retroactive query-log anonymization.
//!
//! The implementation lives outside `cli.rs` so the dispatch module stays
//! within the production file-size budget. The CLI re-exports the options,
//! outcome and entry point, so `sito::cli::run_db_anonymize` remains the public
//! path used by `main`.

use crate::db_maintenance::{
    DB_MIGRATE_LOCK_FILE, FileOwner, OwnershipGuard, acquire_db_migration_lock, file_owner,
    inspect_anonymize_without_writes, inspect_db_without_writes, migration_created_paths,
    restore_ownership,
};
use sito_core::config::Config;
use sito_stats::{ANONYMIZE_QUERYLOG_CHUNK_ROWS, MigrationMode, StatsDb, StatsOpenOptions};
use std::path::Path;
use std::time::{Duration, Instant};

/// Operator-facing refusal text for a live service.
const DB_ANONYMIZE_FORCE_HINT: &str = "Anonymization needs exclusive access to the stats \
     database, so this command has no --force override; stop the service and run it again.";

/// Options for `sito db anonymize`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DbAnonymizeOptions {
    /// Required in 2.0: anonymize every `query_log` row.
    pub all: bool,
    /// Report how many rows would change without touching the live database.
    pub dry_run: bool,
}

/// Result of a successful `sito db anonymize --all` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbAnonymizeOutcome {
    pub dry_run: bool,
    /// Rows read (or, for a dry run, rows counted on the private copy).
    pub processed_rows: u64,
    /// Rows that were changed (or would be changed by a dry run).
    pub changed_rows: u64,
    pub already_anonymized_rows: u64,
    pub unparseable_rows: u64,
    /// Non-empty committed chunks. Zero for a dry run.
    pub chunks: u64,
    /// Whether the post-run `VACUUM`/WAL truncate ran. Always false for a dry
    /// run or a no-op run.
    pub vacuumed: bool,
    /// Size of `stats.db` plus WAL/SHM after the run (or before a dry run).
    pub db_size_bytes: u64,
    pub elapsed: Duration,
}

/// Refuses an older, newer or corrupt schema before anonymization writes.
fn ensure_anonymize_schema_current(
    db_path: &Path,
    found: i64,
    supported: i64,
) -> Result<(), anyhow::Error> {
    if found > supported {
        anyhow::bail!(
            "Refusing to anonymize '{}': it records schema version {} but this binary supports \
             at most {}. Upgrade the sito binary instead. No database files were changed.",
            db_path.display(),
            found,
            supported
        );
    }
    if found != supported {
        anyhow::bail!(
            "Refusing to anonymize '{}': it records schema version {} but this binary requires \
             version {}. Run `sito db migrate --config <path>` first. No database files were changed.",
            db_path.display(),
            found,
            supported
        );
    }
    Ok(())
}

/// `--dry-run`: count candidates on a private copy, never open the live DB.
async fn run_anonymize_dry_run(db_path: &Path) -> Result<DbAnonymizeOutcome, anyhow::Error> {
    let started = Instant::now();
    let inspection = inspect_anonymize_without_writes(db_path).await?;
    ensure_anonymize_schema_current(
        db_path,
        inspection.schema.found,
        inspection.schema.supported,
    )?;
    let plan = inspection
        .plan
        .expect("a current schema always produces an anonymization plan");

    println!(
        "Stats database '{}' is at schema version {}.",
        db_path.display(),
        inspection.schema.found
    );
    println!(
        "Would anonymize {} of {} query_log rows ({} already anonymized, {} unparseable client IPs).",
        plan.would_change, plan.scanned, plan.already_anonymized, plan.unparseable
    );
    println!(
        "Rows are preserved: client_ip is masked (IPv4 /24, IPv6 /56, IPv4-mapped as IPv4 /24) \
         and client_name is set to NULL. stats_hourly rollups are not touched."
    );
    println!(
        "Dry run: the live database, its WAL/SHM sidecars and stats-salt were not created or modified."
    );

    let db_size_bytes = std::fs::metadata(db_path).map_or(0, |m| m.len());
    Ok(DbAnonymizeOutcome {
        dry_run: true,
        processed_rows: plan.scanned,
        changed_rows: plan.would_change,
        already_anonymized_rows: plan.already_anonymized,
        unparseable_rows: plan.unparseable,
        chunks: 0,
        vacuumed: false,
        db_size_bytes,
        elapsed: started.elapsed(),
    })
}

/// The real run: open the live database read-write, rewrite it in chunks, and
/// report the result.
async fn run_anonymize_apply(
    db_path: &Path,
    data_dir: &Path,
    owner: Option<FileOwner>,
    rollup_client_names: bool,
) -> Result<DbAnonymizeOutcome, anyhow::Error> {
    // Inspect a private copy first so an old/newer/corrupt schema is refused
    // without creating WAL/SHM, a salt or any other file in the data directory.
    let inspection = inspect_db_without_writes(db_path).await?;
    ensure_anonymize_schema_current(db_path, inspection.found, inspection.supported)?;

    let owned_paths = migration_created_paths(db_path, data_dir, None);
    let _owner_guard = OwnershipGuard::new(owned_paths.clone(), owner);
    let open_result = StatsDb::open_with_options(
        db_path,
        StatsOpenOptions {
            // Never migrate implicitly here: the operator runs `db migrate`
            // explicitly. This also keeps `db anonymize` from writing before
            // the first chunk is committed.
            migration_mode: MigrationMode::RequireCurrent,
            rollup_client_names,
        },
    )
    .await;
    let ownership = restore_ownership(&owned_paths, owner);

    let db = match open_result {
        Ok(db) => {
            ownership?;
            db
        }
        Err(e) => {
            let ownership_note = match ownership {
                Ok(()) => String::new(),
                Err(ownership_error) => {
                    format!(" Restoring file ownership also failed: {ownership_error}")
                }
            };
            anyhow::bail!(
                "Failed to open stats database '{}' for anonymization: {e}.{ownership_note} \
                 No query_log rows were changed.",
                db_path.display()
            );
        }
    };

    let started = Instant::now();
    let report = match db.anonymize_query_log(ANONYMIZE_QUERYLOG_CHUNK_ROWS).await {
        Ok(report) => report,
        Err(e) => {
            db.pool().close().await;
            anyhow::bail!(
                "Anonymization of '{}' did not finish: {e}. Every committed chunk stays applied; \
                 run the command again to resume safely (already-anonymized rows are skipped).",
                db_path.display()
            );
        }
    };
    let elapsed = started.elapsed();
    let db_size_bytes = db.db_size_bytes().await.map_err(|e| {
        anyhow::anyhow!(
            "Anonymized '{}', but could not read the resulting database size: {e}",
            db_path.display()
        )
    })?;
    db.pool().close().await;

    if report.changed == 0 {
        println!(
            "Nothing to do: all {} query_log rows are already anonymized (0 changed).",
            report.processed
        );
    } else {
        println!(
            "Anonymized {} of {} query_log rows in {} chunk(s) ({} already anonymized, {} unparseable client IPs).",
            report.changed,
            report.processed,
            report.chunks,
            report.already_anonymized,
            report.unparseable
        );
        println!(
            "Rows were preserved: only client_ip and client_name changed; stats_hourly rollups were not touched."
        );
    }
    if report.unparseable > 0 {
        println!(
            "Warning: {} client IP value(s) could not be parsed and kept their stored address; \
             their client_name was cleared.",
            report.unparseable
        );
    }
    if report.vacuumed {
        println!(
            "Vacuumed the database and truncated the WAL so old unmasked values do not remain in free space."
        );
    }
    println!(
        "Finished in {:.2}s. Stats database size: {} bytes (stats.db + WAL/SHM).",
        elapsed.as_secs_f64(),
        db_size_bytes
    );

    Ok(DbAnonymizeOutcome {
        dry_run: false,
        processed_rows: report.processed,
        changed_rows: report.changed,
        already_anonymized_rows: report.already_anonymized,
        unparseable_rows: report.unparseable,
        chunks: report.chunks,
        vacuumed: report.vacuumed,
        db_size_bytes,
        elapsed,
    })
}

/// Executes the `db anonymize --all` subcommand (B4).
///
/// Retroactive anonymization is explicit and offline: it takes the service
/// lease, refuses a live server, shares the B2 migration lock, and has no
/// `--force` data-loss override. A real run masks every `client_ip` with the
/// writer's [`sito_stats::anonymize_ip`] and sets `client_name = NULL` in
/// bounded, independently committed chunks. A dry run inspects a private copy
/// and never opens the live database.
pub async fn run_db_anonymize(
    config_path: &Path,
    options: DbAnonymizeOptions,
) -> Result<DbAnonymizeOutcome, anyhow::Error> {
    if !options.all {
        anyhow::bail!(
            "`sito db anonymize` requires `--all` in 2.0: per-client and date-range \
             selection is not implemented yet. Nothing was changed."
        );
    }

    let content = std::fs::read_to_string(config_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read configuration file '{}': {}",
            config_path.display(),
            e
        )
    })?;
    let config = Config::from_toml_str(&content)
        .map_err(|e| anyhow::anyhow!("Configuration validation failed: {e}"))?;

    let data_dir = &config.server.data_dir;
    let db_path = data_dir.join("stats.db");
    if !db_path.is_file() {
        anyhow::bail!(
            "Stats database '{}' does not exist, so there is nothing to anonymize. \
             A first install creates it when the server starts; this command never creates an empty database.",
            db_path.display()
        );
    }

    // Capture the owner before anything is created: a `sudo` run must not
    // leave root-owned sidecars, salt or lock files for the service user.
    let owner = file_owner(&db_path).or_else(|| file_owner(data_dir));

    // Held through inspection and the whole chunked rewrite. There is no
    // `--force`: the running server holds SQLite connections and must stop.
    let _access = crate::cli::begin_reset(
        data_dir,
        "anonymize the stats database",
        false,
        DB_ANONYMIZE_FORCE_HINT,
    )?;
    restore_ownership(
        &[data_dir.join(crate::service_lock::SERVICE_LOCK_FILE)],
        owner,
    )?;

    let _migration_lock = acquire_db_migration_lock(data_dir)?;
    restore_ownership(&[data_dir.join(DB_MIGRATE_LOCK_FILE)], owner)?;

    if options.dry_run {
        run_anonymize_dry_run(&db_path).await
    } else {
        let stats = config.get_stats_config();
        run_anonymize_apply(&db_path, data_dir, owner, stats.rollup_client_names).await
    }
}
