//! Image entrypoint: migrate the stats database before the server starts.
//!
//! The published image runs on distroless and therefore has no shell. The
//! entrypoint is the `sito` binary itself in a hidden
//! `--container-entrypoint` mode: it applies the same explicit
//! [`run_db_migrate`](crate::cli::run_db_migrate) path as the CLI and only then
//! falls through to the normal server startup. This mirrors the installer,
//! which runs `sito db migrate` after stopping the old service and before
//! starting the new one.
//!
//! The migration is skipped when:
//! - there is no configuration file yet (first-boot wizard; the server creates
//!   a fresh database normally), or
//! - `<server.data_dir>/stats.db` does not exist yet (fresh volume), or
//! - [`NO_MIGRATE_ENV`] is set to `1`/`true`. The entrypoint then starts the
//!   server unchanged, so B3's fail-closed startup policy refuses an old
//!   database with the normal `SITO_DB_AUTO_MIGRATE=1` guidance.

use std::path::Path;

use sito_core::config::Config;

use crate::cli::{DbMigrateOptions, run_db_migrate};

/// Explicit opt-out from the image entrypoint's pre-start migration.
pub const NO_MIGRATE_ENV: &str = "SITO_NO_MIGRATE";

/// Parsed entrypoint migration policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoMigrate {
    /// Run the explicit database migration before starting the server.
    Disabled,
    /// Do not migrate; let the server's B3 fail-closed policy decide.
    Enabled,
}

impl NoMigrate {
    /// Parses the raw environment value.
    ///
    /// Unset, empty, `0` and `false` keep the default migration; `1` and
    /// `true` skip it. Every other value is a startup error: a typo must not
    /// silently disable or enable a database migration.
    pub fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value {
            None | Some("" | "0" | "false") => Ok(Self::Disabled),
            Some("1" | "true") => Ok(Self::Enabled),
            Some(other) => Err(anyhow::anyhow!(
                "Invalid {NO_MIGRATE_ENV} value '{other}'. Set it to '1' or 'true' to skip the \
                 pre-start database migration, or unset it (or set '0' or 'false') to let the \
                 container entrypoint run `sito db migrate` first."
            )),
        }
    }

    /// Reads [`NO_MIGRATE_ENV`] once for this start.
    pub fn from_env() -> anyhow::Result<Self> {
        match std::env::var_os(NO_MIGRATE_ENV) {
            None => Ok(Self::Disabled),
            Some(value) => {
                let value = value.to_str().ok_or_else(|| {
                    anyhow::anyhow!(
                        "{NO_MIGRATE_ENV} is not valid UTF-8. Set it to '1'/'true' to skip the \
                         pre-start database migration, or unset it to run it."
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

/// Runs the explicit stats database migration before the server starts.
///
/// Returns `Ok(())` when there is nothing to migrate or the migration
/// succeeded. Any migration error is returned with a message that names the
/// entrypoint decision, so the process exits without binding DNS/API ports.
pub async fn migrate_before_start(config_path: &Path) -> anyhow::Result<()> {
    if NoMigrate::from_env()?.is_enabled() {
        // `SITO_NO_MIGRATE` must win. Fail closed on the conflicting pair rather
        // than letting B3 auto-migrate the database the operator explicitly
        // asked the entrypoint not to migrate.
        if crate::db_startup::DbAutoMigrate::from_env()?.is_enabled() {
            anyhow::bail!(
                "Conflicting migration policy: {NO_MIGRATE_ENV} is set but \
                 {DB_AUTO_MIGRATE_ENV}=1 asks the server to auto-migrate. Remove or set \
                 {DB_AUTO_MIGRATE_ENV}=0 to keep the no-migrate opt-out, or unset \
                 {NO_MIGRATE_ENV} to let the entrypoint migrate first.",
                DB_AUTO_MIGRATE_ENV = crate::db_startup::DB_AUTO_MIGRATE_ENV
            );
        }
        eprintln!(
            "{NO_MIGRATE_ENV} is set: skipping the pre-start database migration. If \
             <server.data_dir>/stats.db still needs a migration, the server will refuse to start \
             until `sito db migrate` has run."
        );
        return Ok(());
    }

    // A missing configuration is the first-boot wizard path. The server
    // creates a fresh database when it starts; there is nothing to migrate.
    if !config_path.is_file() {
        return Ok(());
    }

    let content = std::fs::read_to_string(config_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read configuration file '{}' before the database migration: {}",
            config_path.display(),
            e
        )
    })?;
    let config = Config::from_toml_str(&content).map_err(|e| {
        anyhow::anyhow!("Configuration validation failed before the database migration: {e}")
    })?;

    // A fresh volume has no stats.db yet. The server creates the current schema
    // without a backup, exactly like a fresh systemd install.
    if !config.server.data_dir.join("stats.db").is_file() {
        return Ok(());
    }

    run_db_migrate(config_path, DbMigrateOptions::default())
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Database migration failed before starting the server, so the container will \
                 not start: {e}"
            )
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_entrypoint_no_migrate_policy_parsing() {
        for disabled in [None, Some(""), Some("0"), Some("false")] {
            assert_eq!(
                NoMigrate::parse(disabled).unwrap(),
                NoMigrate::Disabled,
                "value {disabled:?} must keep the migration enabled"
            );
        }
        for enabled in [Some("1"), Some("true")] {
            assert_eq!(
                NoMigrate::parse(enabled).unwrap(),
                NoMigrate::Enabled,
                "value {enabled:?} must skip the migration"
            );
        }
    }

    #[test]
    fn test_container_entrypoint_rejects_invalid_no_migrate_value() {
        for invalid in ["yes", "TRUE", "2", "on"] {
            let error = NoMigrate::parse(Some(invalid)).unwrap_err().to_string();
            assert!(
                error.contains(NO_MIGRATE_ENV) && error.contains(invalid),
                "the error must name the variable and the invalid value: {error}"
            );
        }
    }

    #[test]
    fn test_container_entrypoint_no_migrate_gate() {
        assert!(!NoMigrate::Disabled.is_enabled());
        assert!(NoMigrate::Enabled.is_enabled());
    }
}
