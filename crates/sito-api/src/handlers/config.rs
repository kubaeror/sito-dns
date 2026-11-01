//! Configuration management, atomic update, hot-reload, backup and restore handlers.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, State};
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
use crate::config_apply::{ApplyHooks, FilterApply, apply_and_persist_config, apply_full_config};
use crate::error::ProblemDetails;
use crate::models::{
    BackupMetadata, ConfigResponse, ConfigUpdateResponse, GenericMessageResponse,
    RestoreConfirmRequest, RestorePreparedResponse, UpdateConfigRequest,
};
use crate::state::ServerContext;

/// Placeholder written in place of a secret value. Masked output is valid TOML
/// and round-trips through [`unmask_sensitive_toml`].
pub const SECRET_PLACEHOLDER: &str = "***";

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
        || key.ends_with("_secrets")
        || key.ends_with("_key")
}

/// True when the whole table at this path holds secrets (per-client shared
/// secrets are keyed by client name, so the key name alone is not sensitive).
fn is_sensitive_table_path(path: &[String]) -> bool {
    matches!(
        path.join(".").as_str(),
        "clients.client_id_secrets" | "clients.client_id_secrets.*"
    )
}

/// Walks a parsed TOML tree and replaces every secret value with the
/// placeholder. Secret detection is by key path, so nested tables, arrays of
/// tables and inline tables are all covered.
fn mask_value(value: &mut toml::Value, path: &mut Vec<String>) {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table.iter_mut() {
                path.push(key.clone());
                if is_sensitive_key(key) || is_sensitive_table_path(path) {
                    *child = toml::Value::String(SECRET_PLACEHOLDER.to_string());
                } else {
                    mask_value(child, path);
                }
                path.pop();
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                mask_value(item, path);
            }
        }
        _ => {}
    }
}

/// Line-based fallback used only when the input is not parseable TOML (the
/// server's own configuration always is). Prefer [`mask_sensitive_toml`].
fn mask_sensitive_toml_fallback(toml_str: &str) -> String {
    toml_str
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            match trimmed.split_once('=') {
                Some((lhs, _)) => {
                    let key = lhs.trim().rsplit('.').next().unwrap_or(lhs).trim();
                    let key = key.trim_matches('"').trim_matches('\'');
                    if is_sensitive_key(key) {
                        let (prefix, _) = line.split_at(line.find('=').map_or(0, |i| i + 1));
                        format!("{prefix} \"{SECRET_PLACEHOLDER}\"")
                    } else {
                        line.to_string()
                    }
                }
                None => line.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Masks sensitive values with a TOML-value walk keyed by path
/// (`clients.client_id_secrets.*`, `*.password`, `*.key`, `*.token`,
/// `slave_token`, `secret_key`, ...) and serializes the masked tree. The
/// output is always valid TOML, including for multi-line arrays/tables.
pub fn mask_sensitive_toml(toml_str: &str) -> String {
    let Ok(table) = toml::from_str::<toml::Table>(toml_str) else {
        return mask_sensitive_toml_fallback(toml_str);
    };
    let mut root = toml::Value::Table(table);
    mask_value(&mut root, &mut Vec::new());
    let toml::Value::Table(masked) = root else {
        return mask_sensitive_toml_fallback(toml_str);
    };
    toml::to_string_pretty(&masked).unwrap_or_else(|_| mask_sensitive_toml_fallback(toml_str))
}

/// Restores placeholder values in `new_toml` from `current_toml` by key path.
///
/// This replaces the old line-based matching, which restored the first line
/// with the same key name anywhere in the file and could not handle
/// multi-line values or nested tables.
pub fn unmask_sensitive_toml(new_toml: &str, current_toml: &str) -> String {
    let (Ok(mut new_table), Ok(current_table)) = (
        toml::from_str::<toml::Table>(new_toml),
        toml::from_str::<toml::Table>(current_toml),
    ) else {
        return new_toml.to_string();
    };

    restore_placeholders(&mut new_table, &current_table);
    toml::to_string_pretty(&new_table).unwrap_or_else(|_| new_toml.to_string())
}

fn restore_placeholders(new: &mut toml::Table, current: &toml::Table) {
    for (key, value) in new.iter_mut() {
        let current_child = current.get(key);
        if value.as_str() == Some(SECRET_PLACEHOLDER) {
            if let Some(current_child) = current_child {
                *value = current_child.clone();
            }
            continue;
        }
        match value {
            toml::Value::Table(table) => {
                if let Some(current_table) = current_child.and_then(toml::Value::as_table) {
                    restore_placeholders(table, current_table);
                }
            }
            toml::Value::Array(items) => {
                let Some(current_items) = current_child.and_then(toml::Value::as_array) else {
                    continue;
                };
                for (index, item) in items.iter_mut().enumerate() {
                    if let (toml::Value::Table(table), Some(current_table)) = (
                        item,
                        current_items.get(index).and_then(toml::Value::as_table),
                    ) {
                        restore_placeholders(table, current_table);
                    }
                }
            }
            _ => {}
        }
    }
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
    Extension(hooks): Extension<ApplyHooks>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<ConfigUpdateResponse>, ProblemDetails> {
    let current_toml = tokio::fs::read_to_string(&ctx.config_path)
        .await
        .unwrap_or_default();

    let unmasked_toml = unmask_sensitive_toml(&req.config_toml, &current_toml);

    // Parse, deep-validate, apply and only then persist: a configuration the
    // server cannot load must never reach the file.
    let parsed: Config = Config::from_toml_str(&unmasked_toml)
        .map_err(|e| ProblemDetails::bad_request(format!("Configuration error: {e}")))?;

    let report = apply_and_persist_config(&ctx, &parsed, FilterApply::Sync, hooks.as_dyn()).await?;

    Ok(Json(ConfigUpdateResponse {
        message: "Configuration successfully updated".to_string(),
        restart_required: report.restart_required,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restore_archive_rejects_decompression_bomb() {
        let enc = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = Builder::new(enc);
        let bomb = vec![b'a'; (MAX_RESTORE_CONFIG_BYTES + 1) as usize];
        let mut header = Header::new_gnu();
        header.set_size(bomb.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "config.toml", &bomb[..])
            .unwrap();
        let bytes = tar.into_inner().unwrap().finish().unwrap();

        let err = extract_backup_archive(&bytes).expect_err("bomb must be rejected");
        assert!(err.to_string().contains("exceeds"), "got: {err}");
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

[clients.client_id_secrets]
"phone" = "shared-secret-one"
"laptop" = "shared-secret-two"
"#;
        let masked = mask_sensitive_toml(toml_str);
        assert!(!masked.contains("super-secret-private-key"));
        assert!(!masked.contains("abc123"));
        assert!(!masked.contains("first"));
        assert!(!masked.contains("Bearer xyz"));
        assert!(!masked.contains("shared-secret-one"));
        assert!(!masked.contains("shared-secret-two"));
        assert!(masked.contains("cert = \"public-cert.pem\""));
        assert!(masked.contains("\"1.1.1.1\""));
        assert!(masked.contains(SECRET_PLACEHOLDER));

        // The masked output must always be parseable TOML.
        let parsed: toml::Table = toml::from_str(&masked).expect("masked TOML parses");
        assert_eq!(
            parsed["clients"]["client_id_secrets"].as_str(),
            Some(SECRET_PLACEHOLDER)
        );
    }

    #[test]
    fn test_mask_sensitive_toml_multiline_collection() {
        let toml_str = "slave_token = [\n  \"secret1\",\n  \"secret2\",\n]\nname = \"ok\"\n";
        let masked = mask_sensitive_toml(toml_str);
        assert!(!masked.contains("secret1"));
        assert!(!masked.contains("secret2"));
        assert!(masked.contains("name = \"ok\""));
        // Multi-line values are masked as a scalar placeholder, not a broken
        // multi-line fragment: the result parses.
        let parsed: toml::Table = toml::from_str(&masked).expect("masked TOML parses");
        assert_eq!(
            parsed["slave_token"].as_str(),
            Some(SECRET_PLACEHOLDER),
            "masked multi-line value must be valid TOML"
        );
    }

    #[test]
    fn test_mask_round_trip_restores_multiline_and_client_secrets() {
        let original = r#"[server]
slave_token = [
  "multi-line-secret-one",
  "multi-line-secret-two",
]

[clients.client_id_secrets]
"phone" = "phone-secret"
"laptop" = "laptop-secret"

[upstream]
servers = ["1.1.1.1"]
api_key = "upstream-api-key"
"#;
        let masked = mask_sensitive_toml(original);
        assert!(!masked.contains("multi-line-secret-one"));
        assert!(!masked.contains("phone-secret"));
        assert!(!masked.contains("upstream-api-key"));

        // Round-trip: the masked document parses and unmasks back to the
        // original values by key path.
        let _: toml::Table = toml::from_str(&masked).expect("masked output parses");
        let restored = unmask_sensitive_toml(&masked, original);
        let restored: toml::Table = toml::from_str(&restored).expect("unmasked output parses");
        assert_eq!(
            restored["server"]["slave_token"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            restored["clients"]["client_id_secrets"]["phone"].as_str(),
            Some("phone-secret")
        );
        assert_eq!(
            restored["clients"]["client_id_secrets"]["laptop"].as_str(),
            Some("laptop-secret")
        );
        assert_eq!(
            restored["upstream"]["api_key"].as_str(),
            Some("upstream-api-key")
        );
        // Non-secret values survive the round trip untouched.
        assert_eq!(
            restored["upstream"]["servers"].as_array().map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn test_unmask_is_path_aware_not_name_based() {
        // Two different tables use the same key name; the line-based matcher
        // used to restore the first occurrence in file order.
        let original = r#"[web]
token = "web-token"

[ha]
token = "ha-token"
"#;
        let masked = mask_sensitive_toml(original);
        let restored = unmask_sensitive_toml(&masked, original);
        let restored: toml::Table = toml::from_str(&restored).unwrap();
        assert_eq!(restored["web"]["token"].as_str(), Some("web-token"));
        assert_eq!(restored["ha"]["token"].as_str(), Some("ha-token"));
    }

    fn admin() -> RequireAdmin {
        RequireAdmin(crate::auth::AuthUser {
            username: "admin".to_string(),
            role: crate::auth::token::Role::Admin,
            token_id: None,
        })
    }

    /// WP-4.2: `PUT /config` with an unparseable/typo upstream must be rejected
    /// with 400 and the file must stay untouched.
    #[tokio::test]
    async fn test_update_config_rejects_invalid_upstream_and_keeps_file() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_put");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let original = "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n";
        tokio::fs::write(&ctx.config_path, original).await.unwrap();
        ctx.set_config(Config::from_toml_str(original).unwrap());

        let err = update_config(
            admin(),
            State(ctx.clone()),
            Extension(ApplyHooks::default()),
            Json(UpdateConfigRequest {
                config_toml: "config_version = 1\n[upstream]\nservers = [\"oops-typo\"]\n"
                    .to_string(),
            }),
        )
        .await
        .expect_err("invalid upstream must be rejected");
        assert_eq!(err.status, 400);
        assert_eq!(
            tokio::fs::read_to_string(&ctx.config_path).await.unwrap(),
            original,
            "the rejected configuration must not be persisted"
        );
        assert_eq!(ctx.config.load().upstream.servers, vec!["1.1.1.1"]);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// WP-4.2: reloading a file with an invalid `[clients]` section must return
    /// 400 and must not wipe the live clients/runtime snapshot.
    #[tokio::test]
    async fn test_reload_rejects_invalid_clients_without_wiping() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_reload");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let seed = "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n[clients]\n[[clients.entries]]\nname = \"phone\"\nids = [\"10.0.0.5\"]\n";
        let seed_cfg = Config::from_toml_str(seed).unwrap();
        ctx.set_config(seed_cfg.clone());
        let clients_cfg: sito_clients::ClientsConfig =
            seed_cfg.clients.clone().unwrap().try_into().unwrap();
        ctx.set_clients(sito_clients::ClientRegistry::new(clients_cfg));

        tokio::fs::write(
            &ctx.config_path,
            "config_version = 1\n[clients]\nentries = \"not-an-array\"\n",
        )
        .await
        .unwrap();

        let err = reload_config(
            admin(),
            State(ctx.clone()),
            Extension(ApplyHooks::default()),
        )
        .await
        .expect_err("invalid clients section must be rejected");
        assert_eq!(err.status, 400);

        let live = ctx.config.load();
        let clients = live
            .clients
            .as_ref()
            .and_then(|v| v.get("entries"))
            .and_then(|v| v.as_array())
            .expect("live clients section must survive the rejected reload");
        assert_eq!(clients.len(), 1);
        assert_eq!(
            ctx.runtime.snapshot().config.upstream.servers,
            vec!["1.1.1.1"],
            "runtime snapshot must be untouched"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// WP-4.2: a persist failure rolls the in-memory apply back.
    #[tokio::test]
    async fn test_persist_failure_rolls_back_in_memory_config() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_rollback");
        let mut ctx = crate::test_support::mock_context(&temp_dir).await;
        ctx.config_path = std::path::PathBuf::from("/proc/forbidden_cfg_test/config.toml");

        let original_ttl = ctx.config.load().dns.cache.min_ttl;
        let mut candidate = (**ctx.config.load()).clone();
        candidate.dns.cache.min_ttl = original_ttl.saturating_add(42);

        let err = crate::config_apply::apply_and_persist_config(
            &ctx,
            &candidate,
            FilterApply::Sync,
            None,
        )
        .await
        .expect_err("persist must fail");
        assert_eq!(err.status, 500);
        assert_eq!(
            ctx.config.load().dns.cache.min_ttl,
            original_ttl,
            "in-memory apply must be rolled back when the persist fails"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
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
    Extension(hooks): Extension<ApplyHooks>,
) -> Result<Json<ConfigUpdateResponse>, ProblemDetails> {
    let raw = tokio::fs::read_to_string(&ctx.config_path)
        .await
        .map_err(|e| ProblemDetails::internal_error(format!("Failed to read config file: {e}")))?;

    let parsed = Config::from_toml_str(&raw)
        .map_err(|e| ProblemDetails::bad_request(format!("Invalid configuration on disk: {e}")))?;

    // Same deep validation and apply routine as every other write path.
    let report = apply_full_config(&ctx, &parsed, FilterApply::Sync, hooks.as_dyn()).await?;
    ctx.publish_bundle().await;

    Ok(Json(ConfigUpdateResponse {
        message: "Configuration reloaded from disk and applied".to_string(),
        restart_required: report.restart_required,
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

/// Maximum decompressed size accepted for `config.toml` inside a restore archive.
const MAX_RESTORE_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum decompressed size accepted for `metadata.json` inside a restore archive.
const MAX_RESTORE_METADATA_BYTES: u64 = 64 * 1024;
/// Maximum combined decompressed size accepted for a restore archive. Caps
/// gzip bombs even when individual entries lie about their sizes.
const MAX_RESTORE_TOTAL_BYTES: u64 = 8 * 1024 * 1024;

/// Extract and validate a compressed .tar.gz archive containing config.toml and metadata.json
pub fn extract_backup_archive(archive_bytes: &[u8]) -> anyhow::Result<(String, BackupMetadata)> {
    if archive_bytes.is_empty() {
        anyhow::bail!("Archive body is empty");
    }

    let gz = GzDecoder::new(archive_bytes);
    let mut archive = Archive::new(gz);

    let mut restored_config_toml = None;
    let mut restored_metadata = None;
    let mut total_read: u64 = 0;

    let entries = archive.entries()?;
    for entry_res in entries {
        let entry = entry_res?;
        let path = entry.path()?.to_string_lossy().to_string();

        let cap = if path == "config.toml" || path.ends_with("/config.toml") {
            MAX_RESTORE_CONFIG_BYTES
        } else if path == "metadata.json" || path.ends_with("/metadata.json") {
            MAX_RESTORE_METADATA_BYTES
        } else {
            continue;
        };

        // Read at most cap+1 bytes so an oversized (or lying) entry is
        // rejected without buffering it in full.
        let mut limited = entry.take(cap + 1);
        let mut bytes = Vec::new();
        limited.read_to_end(&mut bytes)?;
        let read = bytes.len() as u64;
        if read > cap {
            anyhow::bail!("Restore archive entry '{path}' exceeds the {cap}-byte limit");
        }
        total_read = total_read.saturating_add(read);
        if total_read > MAX_RESTORE_TOTAL_BYTES {
            anyhow::bail!(
                "Restore archive expands beyond the {MAX_RESTORE_TOTAL_BYTES}-byte limit"
            );
        }

        let s = String::from_utf8(bytes)
            .map_err(|e| anyhow::anyhow!("Restore archive entry '{path}' is not UTF-8: {e}"))?;
        if path == "config.toml" || path.ends_with("/config.toml") {
            restored_config_toml = Some(s);
        } else if let Ok(meta) = serde_json::from_str::<BackupMetadata>(&s) {
            restored_metadata = Some(meta);
        }
    }

    let meta =
        restored_metadata.ok_or_else(|| anyhow::anyhow!("Archive is missing metadata.json"))?;
    let config_toml = restored_config_toml
        .ok_or_else(|| anyhow::anyhow!("Archive does not contain a valid config.toml"))?;

    // Pre-validation of restored configuration (including typed sections and
    // every upstream target, so a typo in `servers` cannot be restored).
    let restored = Config::from_toml_str(&config_toml)
        .map_err(|e| anyhow::anyhow!("Restored configuration validation failed: {e}"))?;
    crate::config_apply::validate_full_config_sync(&restored)
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
    Extension(hooks): Extension<ApplyHooks>,
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

    // Apply first, persist second: a restored config that cannot be applied is
    // rejected without touching the current file.
    apply_and_persist_config(&ctx, &parsed, FilterApply::Sync, hooks.as_dyn()).await?;

    Ok(Json(GenericMessageResponse {
        message: "Configuration successfully restored from backup".to_string(),
    }))
}
