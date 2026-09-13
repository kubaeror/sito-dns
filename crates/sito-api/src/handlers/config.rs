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
use std::time::{Duration, Instant};
use tar::{Archive, Builder, Header};

use crate::auth::rbac::RequireAdmin;
use crate::config_writer::save_config_atomic;
use crate::error::ProblemDetails;
use crate::models::{
    BackupMetadata, ConfigResponse, ConfigUpdateResponse, GenericMessageResponse,
    RestoreConfirmRequest, RestorePreparedResponse, UpdateConfigRequest,
};
use crate::state::ServerContext;

/// Returns true when a TOML key holds a secret value.
fn is_sensitive_key(key: &str) -> bool {
    matches!(
        key,
        "key"
            | "password"
            | "password_hash"
            | "secret"
            | "token"
            | "api_key"
            | "slave_token"
            | "credential"
            | "credentials"
            | "psk"
            | "passphrase"
    ) || key.ends_with("_token")
        || key.ends_with("_password")
        || key.ends_with("_secret")
        || key.ends_with("_key")
}

/// Extracts the final key segment from a (possibly dotted/quoted) TOML key.
fn sensitive_key_of(lhs: &str) -> &str {
    let last = lhs.trim().rsplit('.').next().unwrap_or(lhs).trim();
    last.trim_matches('"').trim_matches('\'')
}

/// Masks sensitive values inside a single-line inline table.
fn mask_inline_table(value: &str) -> String {
    let trimmed = value.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return value.to_string();
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let masked: Vec<String> = inner
        .split(',')
        .map(|pair| {
            if let Some((key, _)) = pair.split_once('=')
                && is_sensitive_key(sensitive_key_of(key))
            {
                return format!("{} = \"***\"", key.trim());
            }
            pair.to_string()
        })
        .collect();
    format!("{{{}}}", masked.join(","))
}

fn bracket_delta(line: &str) -> i64 {
    let opens =
        i64::try_from(line.chars().filter(|c| matches!(c, '[' | '{')).count()).unwrap_or(i64::MAX);
    let closes =
        i64::try_from(line.chars().filter(|c| matches!(c, ']' | '}')).count()).unwrap_or(i64::MAX);
    opens - closes
}

/// Mask sensitive values (e.g. `key = "..."`, `slave_token = "..."`,
/// `secret = ["a"]`, `[tls] key = ...` or multi-line arrays/inline tables)
/// with `"***"`.
pub fn mask_sensitive_toml(toml_str: &str) -> String {
    let mut out = Vec::new();
    let mut masking_multiline = false;
    let mut depth = 0i64;

    for line in toml_str.lines() {
        if masking_multiline {
            out.push("***".to_string());
            depth += bracket_delta(line);
            if depth <= 0 {
                masking_multiline = false;
            }
            continue;
        }

        let trimmed = line.trim_start();
        let Some((lhs, rhs)) = trimmed.split_once('=') else {
            out.push(line.to_string());
            continue;
        };
        if !is_sensitive_key(sensitive_key_of(lhs)) {
            // Inline tables can contain nested secret keys (e.g. credentials).
            if rhs.trim_start().starts_with('{') && rhs.contains('=') {
                let (prefix, _) = match line.find('=') {
                    Some(idx) => line.split_at(idx + 1),
                    None => (line, ""),
                };
                out.push(format!("{prefix} {}", mask_inline_table(rhs)));
            } else {
                out.push(line.to_string());
            }
            continue;
        }

        let (prefix, _) = match line.find('=') {
            Some(idx) => line.split_at(idx + 1),
            None => (line, ""),
        };
        let value = rhs.trim();
        let opens_collection = (value.starts_with('[') && !value.ends_with(']'))
            || (value.starts_with('{') && !value.ends_with('}'));
        if opens_collection {
            masking_multiline = true;
            depth = bracket_delta(value);
        }
        out.push(format!("{prefix} \"***\""));
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
            // Find matching key in current_toml (exact key name match)
            let mut matched = false;
            for cur_line in &current_lines {
                let cur_trimmed = cur_line.trim_start();
                let cur_key = cur_trimmed.split('=').next().unwrap_or("").trim();
                if cur_key == key_prefix && cur_trimmed.contains('=') {
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
) -> Result<Json<ConfigUpdateResponse>, ProblemDetails> {
    let current_toml = tokio::fs::read_to_string(&ctx.config_path)
        .await
        .unwrap_or_default();

    let unmasked_toml = unmask_sensitive_toml(&req.config_toml, &current_toml);

    // Pre-commit parse and deep validation: never persist a configuration the
    // server cannot load (the watcher would reject it after we returned 200).
    let parsed: Config = Config::from_toml_str(&unmasked_toml)
        .map_err(|e| ProblemDetails::bad_request(format!("Configuration error: {e}")))?;
    crate::config_validation::validate_typed_sections(&parsed)
        .map_err(|e| ProblemDetails::bad_request(format!("Configuration error: {e}")))?;

    let restart_required = restart_required_fields(&ctx.config.load(), &parsed);

    // Atomic write
    save_config_atomic(&ctx.config_path, &parsed).await?;
    ctx.querylog_sender
        .set_anonymize(parsed.privacy.anonymize_querylog);
    ctx.set_config(parsed);
    crate::publish_bundle(&ctx);

    Ok(Json(ConfigUpdateResponse {
        message: "Configuration successfully updated".to_string(),
        restart_required,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restart_required_fields_marks_restart_only_sections() {
        let old = Config::default();
        let mut new = old.clone();

        // [auth] is read once at startup and must be reported as restart-only.
        let mut auth = toml::Table::new();
        auth.insert("session_ttl_hours".to_string(), toml::Value::Integer(1));
        new.auth = Some(toml::Value::Table(auth));
        let fields = restart_required_fields(&old, &new);
        assert!(fields.iter().any(|f| f == "auth"), "got {fields:?}");

        // Listener ports are rebound in-process by the watcher, not restart-only.
        new.dns.port = old.dns.port.saturating_add(1);
        let fields = restart_required_fields(&old, &new);
        assert!(
            !fields.iter().any(|f| f.starts_with("dns.")),
            "listener changes must not claim restart-required: {fields:?}"
        );
    }

    #[test]
    fn test_restore_archive_rejects_typed_section_errors() {
        let bad_config = "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n[clients]\nentries = \"not-an-array\"\n";
        let archive = create_backup_archive(bad_config).expect("archive builds");
        let err = extract_backup_archive(&archive).expect_err("must reject typed errors");
        assert!(err.to_string().contains("[clients]"), "got: {err}");
    }

    #[test]
    fn test_mask_sensitive_toml_covers_tokens_arrays_and_tables() {
        let toml_str = r#"[tls]
key = "super-secret-private-key"
cert = "public-cert.pem"

[server]
slave_token = "abc123"

[upstream]
servers = ["1.1.1.1", "9.9.9.9"]
api_key = ["first", "second"]

[web]
header = { api_token = "Bearer xyz", Accept = "text/html" }
"#;
        let masked = mask_sensitive_toml(toml_str);
        assert!(!masked.contains("super-secret-private-key"));
        assert!(!masked.contains("abc123"));
        assert!(!masked.contains("first"));
        assert!(!masked.contains("Bearer xyz"));
        assert!(masked.contains("cert = \"public-cert.pem\""));
        assert!(masked.contains("\"1.1.1.1\""));
        assert!(masked.contains("\"***\""));
    }

    #[test]
    fn test_mask_sensitive_toml_multiline_collection() {
        let toml_str = "slave_token = [\n  \"secret1\",\n  \"secret2\",\n]\nname = \"ok\"\n";
        let masked = mask_sensitive_toml(toml_str);
        assert!(!masked.contains("secret1"));
        assert!(!masked.contains("secret2"));
        assert!(masked.contains("name = \"ok\""));
    }
}

/// Settings that are only read at process start; changing them needs a restart.
fn restart_required_fields(old: &Config, new: &Config) -> Vec<String> {
    let mut fields = Vec::new();
    let mark = |changed: bool, name: &str, fields: &mut Vec<String>| {
        if changed {
            fields.push(name.to_string());
        }
    };

    mark(
        old.server.role != new.server.role,
        "server.role",
        &mut fields,
    );
    mark(
        old.server.instance_name != new.server.instance_name,
        "server.instance_name",
        &mut fields,
    );
    mark(
        old.server.data_dir != new.server.data_dir,
        "server.data_dir",
        &mut fields,
    );
    mark(
        old.server.log_format != new.server.log_format,
        "server.log_format",
        &mut fields,
    );
    // dns.bind/ports and dns.rate_limit_per_ip are rebound in-process by the
    // config watcher, so they are not restart-only.
    mark(
        old.dns.doh_dedicated_hostname != new.dns.doh_dedicated_hostname,
        "dns.doh_dedicated_hostname",
        &mut fields,
    );
    // [auth] sessions/token policy and [integrations] workers are read once at
    // startup; changes need a restart.
    mark(old.auth != new.auth, "auth", &mut fields);
    mark(
        old.integrations != new.integrations,
        "integrations",
        &mut fields,
    );
    mark(old.web != new.web, "web", &mut fields);
    mark(old.tls != new.tls, "tls", &mut fields);
    mark(old.acme != new.acme, "acme", &mut fields);
    mark(old.ha != new.ha, "ha", &mut fields);
    fields
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
) -> Result<Json<ConfigUpdateResponse>, ProblemDetails> {
    let raw = tokio::fs::read_to_string(&ctx.config_path)
        .await
        .map_err(|e| ProblemDetails::internal_error(format!("Failed to read config file: {e}")))?;

    let parsed = Config::from_toml_str(&raw)
        .map_err(|e| ProblemDetails::bad_request(format!("Invalid configuration on disk: {e}")))?;
    crate::config_validation::validate_typed_sections(&parsed)
        .map_err(|e| ProblemDetails::bad_request(format!("Invalid configuration on disk: {e}")))?;

    let restart_required = restart_required_fields(&ctx.config.load(), &parsed);

    ctx.querylog_sender
        .set_anonymize(parsed.privacy.anonymize_querylog);
    apply_hot_config(&ctx, parsed).await?;
    crate::publish_bundle(&ctx);

    Ok(Json(ConfigUpdateResponse {
        message: "Configuration reloaded from disk and applied".to_string(),
        restart_required,
    }))
}

/// Applies the hot-reloadable components of `cfg` to the live server.
///
/// Mirrors the config-watcher apply order: filter, upstreams, cache, then the
/// coherent runtime snapshot (config/clients/rewrites). Fails on the first
/// component error instead of reporting a successful reload that applied
/// nothing.
async fn apply_hot_config(ctx: &ServerContext, cfg: Config) -> Result<(), ProblemDetails> {
    ctx.filter
        .reload_with_config(&cfg.filtering)
        .await
        .map_err(|e| {
            ProblemDetails::internal_error(format!("Failed to apply filter configuration: {e}"))
        })?;

    let bootstrap = sito_upstream::BootstrapResolver::new(
        cfg.upstream.bootstrap.clone(),
        Duration::from_millis(cfg.upstream.timeout_ms),
    );
    ctx.upstream
        .reload(&cfg.upstream, &bootstrap)
        .await
        .map_err(|e| {
            ProblemDetails::internal_error(format!("Failed to apply upstream configuration: {e}"))
        })?;

    let clients: sito_clients::ClientsConfig = match cfg.clients.as_ref() {
        Some(value) => value.clone().try_into().map_err(|e| {
            ProblemDetails::bad_request(format!("invalid [clients] configuration: {e}"))
        })?,
        None => sito_clients::ClientsConfig::default(),
    };
    let rewrites: sito_rewrites::RewritesConfig = match cfg.rewrites.as_ref() {
        Some(value) => value.clone().try_into().map_err(|e| {
            ProblemDetails::bad_request(format!("invalid [rewrites] configuration: {e}"))
        })?,
        None => sito_rewrites::RewritesConfig::default(),
    };

    ctx.cache.update_config(cfg.dns.cache.clone()).await;
    ctx.runtime.replace(sito_runtime::RuntimeSnapshot {
        config: std::sync::Arc::new(cfg),
        clients: std::sync::Arc::new(sito_clients::ClientRegistry::new(clients)),
        rewrites: std::sync::Arc::new(sito_rewrites::RewriteTable::new(rewrites)),
    });
    Ok(())
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

    // Pre-validation of restored configuration (including typed sections)
    let restored = Config::from_toml_str(&config_toml)
        .map_err(|e| anyhow::anyhow!("Restored configuration validation failed: {e}"))?;
    crate::config_validation::validate_typed_sections(&restored)
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

    // Save token with 5-minute expiry, pruning expired entries and capping the
    // number of outstanding restorations.
    let expires_at = Instant::now() + Duration::from_secs(300);
    {
        let mut tokens = ctx
            .restore_tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        tokens.retain(|_, (_, expiry)| *expiry > now);
        while tokens.len() >= 32 {
            let Some(oldest) = tokens
                .iter()
                .min_by_key(|(_, (_, expiry))| *expiry)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            tokens.remove(&oldest);
        }
        tokens.insert(token.clone(), (config_toml.clone(), expires_at));
    }

    Ok(Json(RestorePreparedResponse {
        confirmation_token: token,
        message: "Backup verified successfully. Submit confirmation token to apply restoration."
            .to_string(),
        config_preview: mask_sensitive_toml(&config_toml),
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
        let mut map = ctx
            .restore_tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    ctx.querylog_sender
        .set_anonymize(parsed.privacy.anonymize_querylog);
    ctx.set_config(parsed);
    crate::publish_bundle(&ctx);

    Ok(Json(GenericMessageResponse {
        message: "Configuration successfully restored from backup".to_string(),
    }))
}
