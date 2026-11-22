//! Error types for the statistics and query-logging subsystem.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StatsError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid cursor parameter: {0}")]
    InvalidCursor(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// The database records a schema version written by a newer binary. The
    /// open fails before any DDL runs so an old binary cannot corrupt a
    /// forward-migrated database.
    #[error(
        "Database schema version {found} is newer than the supported version {supported}; \
         upgrade the running sito binary"
    )]
    SchemaTooNew { found: i64, supported: i64 },

    /// The database is older than the running binary and the caller asked not
    /// to apply migrations.
    #[error(
        "Database schema version {found} requires migration to {supported}; \
         run the database migration command first"
    )]
    MigrationRequired { found: i64, supported: i64 },

    /// The `stats_meta.schema_version` marker is present but is not a valid
    /// version number. Treated as an error (never silently downgraded) because
    /// guessing could run an upgrade against an unknown layout.
    #[error("Database schema version marker is invalid: '{value}'")]
    InvalidSchemaVersion { value: String },
}
