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
}
