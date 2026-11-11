//! Atomic configuration writer per ADR-0004.
//!
//! Enforces pre-commit validation, writing to `.tmp`, fsync, and atomic rename.

use crate::error::ProblemDetails;
use rand::RngExt;
use sito_core::config::Config;
use std::path::Path;
use tokio::io::AsyncWriteExt;

/// Atomically persists an already-rendered configuration document.
///
/// Used by the HA slave apply path, which must keep the exact document built
/// from the pushed configuration plus node-local fields (`[ha]`, identity,
/// RouterOS credentials) instead of re-serializing the typed config. The
/// document is still validated before it is committed so a restart cannot
/// observe an unloadable file.
pub(crate) async fn save_config_document_atomic(
    path: &Path,
    document: &str,
    config: &Config,
) -> Result<(), ProblemDetails> {
    if let Err(e) = config.validate() {
        return Err(ProblemDetails::bad_request(format!(
            "Configuration validation failed: {e}"
        )));
    }
    // The persisted document must parse and validate as a full config: the
    // next process start reads exactly this text.
    if let Err(e) = Config::from_toml_str(document) {
        return Err(ProblemDetails::bad_request(format!(
            "Configuration document validation failed: {e}"
        )));
    }

    write_config_document_atomic(path, document).await
}

async fn write_config_document_atomic(path: &Path, document: &str) -> Result<(), ProblemDetails> {
    // 3. Write to a unique temporary sibling file (avoids concurrent-writer races)
    let suffix: u64 = rand::rng().random();
    let file_name = path.file_name().map_or_else(
        || "config.toml".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let tmp_path = path.with_file_name(format!("{file_name}.{suffix:016x}.tmp"));

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .await
        .map_err(|e| {
            ProblemDetails::internal_error(format!("Failed to create temporary config file: {e}"))
        })?;

    // Config may contain HA tokens: restrict permissions to the owner.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        file.set_permissions(perms).await.map_err(|e| {
            ProblemDetails::internal_error(format!("Failed to secure temporary config file: {e}"))
        })?;
    }

    file.write_all(document.as_bytes()).await.map_err(|e| {
        ProblemDetails::internal_error(format!("Failed to write temporary config file: {e}"))
    })?;

    // 4. fsync to guarantee persistence to disk
    file.sync_all().await.map_err(|e| {
        ProblemDetails::internal_error(format!("Failed to sync config to disk: {e}"))
    })?;

    drop(file);

    // 5. Atomic rename to target path
    if let Err(e) = tokio::fs::rename(&tmp_path, path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(ProblemDetails::internal_error(format!(
            "Failed to replace config file: {e}"
        )));
    }

    // 6. fsync the parent directory so the rename is durable
    if let Some(parent) = path.parent()
        && let Ok(dir) = tokio::fs::File::open(parent).await
    {
        let _ = dir.sync_all().await;
    }

    Ok(())
}
