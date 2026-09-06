//! Configuration management, atomic update, hot-reload, backup and restore handlers.

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use rand::RngExt;
use sito_core::config::Config;
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tar::{Archive, Builder, Header};

use crate::auth::rbac::RequireAdmin;
use crate::config_writer::save_config_atomic;
use crate::error::ProblemDetails;
use crate::models::{
    BackupMetadata, ConfigResponse, GenericMessageResponse, RestoreConfirmRequest,
    RestorePreparedResponse, UpdateConfigRequest,
};
use crate::state::ServerContext;

/// Mask sensitive values (e.g. key = "...", password = "...") with "***"
pub fn mask_sensitive_toml(toml_str: &str) -> String {
    let mut out = Vec::new();
    for line in toml_str.lines() {
        let trimmed = line.trim_start();
        if (trimmed.starts_with("key =")
            || trimmed.starts_with("password =")
            || trimmed.starts_with("secret =")
            || trimmed.starts_with("token =")
            || trimmed.starts_with("password_hash ="))
            && let Some(idx) = line.find('=')
        {
            let (prefix, _) = line.split_at(idx + 1);
            out.push(format!("{prefix} \"***\""));
            continue;
        }
        out.push(line.to_string());
    }
    out.join("\n")
}

/// Unmask sensitive values in new TOML if they are preserved as "***"
pub fn unmask_sensitive_toml(new_toml: &str, current_toml: &str) -> String {
    let current_lines: Vec<&str> = current_toml.lines().collect();
    let mut out = Vec::new();

    for new_line in new_toml.lines() {
        let trimmed = new_line.trim_start();
        if trimmed.contains("\"***\"") {
            let key_prefix = trimmed.split('=').next().unwrap_or("").trim();
            // Find matching key in current_toml
            let mut matched = false;
            for cur_line in &current_lines {
                let cur_trimmed = cur_line.trim_start();
                if cur_trimmed.starts_with(key_prefix) && cur_trimmed.contains('=') {
                    out.push((*cur_line).to_string());
                    matched = true;
                    break;
                }
            }
            if !matched {
                out.push(new_line.to_string());
            }
        } else {
            out.push(new_line.to_string());
        }
    }
    out.join("\n")
}

/// Get current full configuration with secrets masked.
#[utoipa::path(
    get,
    path = "/api/v1/config",
    responses(
        (status = 200, description = "Full configuration with masked secrets", body = ConfigResponse),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn get_config(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
) -> Result<Json<ConfigResponse>, ProblemDetails> {
    let raw = tokio::fs::read_to_string(&ctx.config_path)
        .await
        .unwrap_or_else(|_| toml::to_string_pretty(&*ctx.config.load()).unwrap_or_default());

    let masked = mask_sensitive_toml(&raw);
    Ok(Json(ConfigResponse {
        config_toml: masked,
    }))
}

/// Update full configuration atomically after pre-commit validation.
#[utoipa::path(
    put,
    path = "/api/v1/config",
    request_body = UpdateConfigRequest,
    responses(
        (status = 200, description = "Configuration updated successfully", body = GenericMessageResponse),
        (status = 400, description = "Invalid configuration", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn update_config(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    let current_toml = tokio::fs::read_to_string(&ctx.config_path)
        .await
        .unwrap_or_default();

    let unmasked_toml = unmask_sensitive_toml(&req.config_toml, &current_toml);

    // Pre-commit parse and validation
    let parsed: Config = Config::from_toml_str(&unmasked_toml)
        .map_err(|e| ProblemDetails::bad_request(format!("Configuration error: {e}")))?;

    // Atomic write
    save_config_atomic(&ctx.config_path, &parsed).await?;
    ctx.config.store(Arc::new(parsed));
    crate::publish_bundle(&ctx);

    Ok(Json(GenericMessageResponse {
        message: "Configuration successfully updated".to_string(),
    }))
}

/// Reload configuration from disk without server restart.
#[utoipa::path(
    post,
    path = "/api/v1/config/reload",
    responses(
        (status = 200, description = "Configuration reloaded", body = GenericMessageResponse),
        (status = 400, description = "Invalid configuration on disk", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn reload_config(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    let raw = tokio::fs::read_to_string(&ctx.config_path)
        .await
        .map_err(|e| ProblemDetails::internal_error(format!("Failed to read config file: {e}")))?;

    let parsed = Config::from_toml_str(&raw)
        .map_err(|e| ProblemDetails::bad_request(format!("Invalid configuration on disk: {e}")))?;

    ctx.config.store(Arc::new(parsed));
    crate::publish_bundle(&ctx);

    Ok(Json(GenericMessageResponse {
        message: "Configuration reloaded successfully from disk".to_string(),
    }))
}

/// Download a complete configuration backup archive (.tar.gz).
#[utoipa::path(
    get,
    path = "/api/v1/config/backup",
    responses(
        (status = 200, description = "Gzipped tar archive containing config and metadata", content_type = "application/gzip"),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
/// Create a compressed .tar.gz archive containing config.toml and metadata.json
pub fn create_backup_archive(config_toml: &str) -> anyhow::Result<Vec<u8>> {
    let metadata = BackupMetadata {
        version: "1.0".to_string(),
        timestamp: chrono::Utc::now().timestamp(),
        sito_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let meta_json = serde_json::to_vec_pretty(&metadata)?;

    let enc = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = Builder::new(enc);

    // Add config.toml
    let mut cfg_header = Header::new_gnu();
    cfg_header.set_size(config_toml.len() as u64);
    cfg_header.set_mode(0o644);
    cfg_header.set_cksum();
    tar.append_data(&mut cfg_header, "config.toml", config_toml.as_bytes())?;

    // Add metadata.json
    let mut meta_header = Header::new_gnu();
    meta_header.set_size(meta_json.len() as u64);
    meta_header.set_mode(0o644);
    meta_header.set_cksum();
    tar.append_data(&mut meta_header, "metadata.json", &meta_json[..])?;

    let enc = tar.into_inner()?;
    let compressed = enc.finish()?;
    Ok(compressed)
}

/// Extract and validate a compressed .tar.gz archive containing config.toml and metadata.json
pub fn extract_backup_archive(archive_bytes: &[u8]) -> anyhow::Result<(String, BackupMetadata)> {
    if archive_bytes.is_empty() {
        anyhow::bail!("Archive body is empty");
    }

    let gz = GzDecoder::new(archive_bytes);
    let mut archive = Archive::new(gz);

    let mut restored_config_toml = None;
    let mut restored_metadata = None;

    let entries = archive.entries()?;
    for entry_res in entries {
        let mut entry = entry_res?;
        let path = entry.path()?.to_string_lossy().to_string();

        if path == "config.toml" || path.ends_with("/config.toml") {
            let mut s = String::new();
            entry.read_to_string(&mut s)?;
            restored_config_toml = Some(s);
        } else if path == "metadata.json" || path.ends_with("/metadata.json") {
            let mut s = String::new();
            entry.read_to_string(&mut s)?;
            if let Ok(meta) = serde_json::from_str::<BackupMetadata>(&s) {
                restored_metadata = Some(meta);
            }
        }
    }

    let meta =
        restored_metadata.ok_or_else(|| anyhow::anyhow!("Archive is missing metadata.json"))?;
    let config_toml = restored_config_toml
        .ok_or_else(|| anyhow::anyhow!("Archive does not contain a valid config.toml"))?;

    // Pre-validation of restored configuration
    Config::from_toml_str(&config_toml)
        .map_err(|e| anyhow::anyhow!("Restored configuration validation failed: {e}"))?;

    Ok((config_toml, meta))
}

/// Download a complete configuration backup archive (.tar.gz).
#[utoipa::path(
    get,
    path = "/api/v1/config/backup",
    responses(
        (status = 200, description = "Gzipped tar archive containing config and metadata", content_type = "application/gzip"),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn download_backup(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
) -> Result<Response, ProblemDetails> {
    let config_content = tokio::fs::read_to_string(&ctx.config_path)
        .await
        .unwrap_or_else(|_| toml::to_string_pretty(&*ctx.config.load()).unwrap_or_default());

    let compressed = create_backup_archive(&config_content)
        .map_err(|e| ProblemDetails::internal_error(format!("Backup archiving failed: {e}")))?;

    let filename = format!(
        "sito-backup-{}.tar.gz",
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    );

    Ok((
        [
            (CONTENT_TYPE, "application/gzip"),
            (
                CONTENT_DISPOSITION,
                &format!("attachment; filename=\"{filename}\""),
            ),
        ],
        compressed,
    )
        .into_response())
}

/// Upload and validate a backup archive (.tar.gz), generating a confirmation token.
#[utoipa::path(
    post,
    path = "/api/v1/config/restore",
    request_body(content = String, description = "Gzipped tar archive", content_type = "application/gzip"),
    responses(
        (status = 200, description = "Backup validated and confirmation token issued", body = RestorePreparedResponse),
        (status = 400, description = "Corrupted or invalid backup", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn prepare_restore(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
    body: Bytes,
) -> Result<Json<RestorePreparedResponse>, ProblemDetails> {
    let (config_toml, _meta) =
        extract_backup_archive(&body).map_err(|e| ProblemDetails::bad_request(e.to_string()))?;

    let mut token_bytes = [0u8; 16];
    rand::rng().fill(&mut token_bytes);
    let token = hex::encode(token_bytes);

    // Save token with 5-minute expiry
    let expires_at = Instant::now() + Duration::from_secs(300);
    ctx.restore_tokens
        .lock()
        .unwrap()
        .insert(token.clone(), (config_toml.clone(), expires_at));

    Ok(Json(RestorePreparedResponse {
        confirmation_token: token,
        message: "Backup verified successfully. Submit confirmation token to apply restoration."
            .to_string(),
        config_preview: config_toml,
    }))
}

/// Confirm and apply configuration restoration using confirmation token.
#[utoipa::path(
    post,
    path = "/api/v1/config/restore/confirm",
    request_body = RestoreConfirmRequest,
    responses(
        (status = 200, description = "Restoration completed successfully", body = GenericMessageResponse),
        (status = 400, description = "Invalid or expired confirmation token", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn confirm_restore(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
    Json(req): Json<RestoreConfirmRequest>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    let pending = {
        let mut map = ctx.restore_tokens.lock().unwrap();
        map.remove(&req.confirmation_token)
    };

    let (config_toml, expires_at) = pending.ok_or_else(|| {
        ProblemDetails::bad_request("Invalid or expired restore confirmation token")
    })?;

    if Instant::now() > expires_at {
        return Err(ProblemDetails::bad_request(
            "Restore confirmation token has expired",
        ));
    }

    let parsed = Config::from_toml_str(&config_toml)
        .map_err(|e| ProblemDetails::bad_request(format!("Configuration error: {e}")))?;

    save_config_atomic(&ctx.config_path, &parsed).await?;
    ctx.config.store(Arc::new(parsed));
    crate::publish_bundle(&ctx);

    Ok(Json(GenericMessageResponse {
        message: "Configuration successfully restored from backup".to_string(),
    }))
}
