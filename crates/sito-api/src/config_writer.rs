//! Atomic configuration writer per ADR-0004.
//!
//! Enforces pre-commit validation, writing to `.tmp`, fsync, and atomic rename.

use crate::error::ProblemDetails;
use sito_core::config::Config;
use std::path::Path;
use tokio::io::AsyncWriteExt;

/// Atomically persists configuration to disk and guarantees durability.
pub async fn save_config_atomic(path: &Path, config: &Config) -> Result<(), ProblemDetails> {
    // 1. Pre-commit validation
    if let Err(e) = config.validate() {
        return Err(ProblemDetails::bad_request(format!(
            "Configuration validation failed: {e}"
        )));
    }

    // 2. Serialize to TOML
    let toml_str = toml::to_string_pretty(config)
        .map_err(|e| ProblemDetails::internal_error(format!("Serialization failed: {e}")))?;

    // 3. Write to temporary sibling file
    let tmp_path = path.with_extension("tmp");
    let mut file = tokio::fs::File::create(&tmp_path).await.map_err(|e| {
        ProblemDetails::internal_error(format!("Failed to create temporary config file: {e}"))
    })?;

    file.write_all(toml_str.as_bytes()).await.map_err(|e| {
        ProblemDetails::internal_error(format!("Failed to write temporary config file: {e}"))
    })?;

    // 4. fsync to guarantee persistence to disk
    file.sync_all().await.map_err(|e| {
        ProblemDetails::internal_error(format!("Failed to sync config to disk: {e}"))
    })?;

    drop(file);

    // 5. Atomic rename to target path
    tokio::fs::rename(&tmp_path, path).await.map_err(|e| {
        ProblemDetails::internal_error(format!("Failed to replace config file: {e}"))
    })?;

    Ok(())
}
