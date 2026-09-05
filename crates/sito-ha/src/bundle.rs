//! Configuration bundle construction, secret masking, signing, and unpack verification.

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::crypto::{Ed25519SigningKey, verify_ed25519_signature};
use crate::error::HaError;
use crate::protocol::HaMessage;

/// Metadata for a filter list subscription included in the bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilterListMetadata {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_hours: Option<u64>,
}

/// A complete replicable configuration bundle.
///
/// Contains the complete state of the master node without [ha] and instance_name,
/// and with all secrets redacted with `${SECRET:name}` placeholders.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigBundle {
    pub version: u64,
    pub timestamp: u64,
    pub config_toml: String,
    #[serde(default)]
    pub custom_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrites: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clients: Option<toml::Value>,
    #[serde(default)]
    pub lists: Vec<FilterListMetadata>,
}

impl ConfigBundle {
    /// Serializes the bundle to a canonical JSON string.
    pub fn to_json(&self) -> Result<String, HaError> {
        serde_json::to_string(self)
            .map_err(|e| HaError::Serialization(format!("Failed to serialize bundle: {e}")))
    }

    /// Deserializes a bundle from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, HaError> {
        serde_json::from_str(s)
            .map_err(|e| HaError::Serialization(format!("Failed to parse bundle JSON: {e}")))
    }
}

/// Builds a sanitized TOML string from a master configuration TOML string.
///
/// Strips out:
/// - The entire `[ha]` section
/// - `server.instance_name` (so slaves preserve their own local instance names)
/// - Masks known secrets into `${SECRET:name}` placeholders
/// - Sets `server.role = "slave"` in the replicable configuration.
pub fn sanitize_config_for_bundle(master_toml: &str) -> Result<String, HaError> {
    let mut table: toml::Table = toml::from_str(master_toml).map_err(|e| HaError::Validation {
        field: "config_toml".to_string(),
        reason: format!("Failed to parse master TOML for sanitization: {e}"),
    })?;

    // 1. Remove [ha] section
    table.remove("ha");

    // 2. In [server], set role to "slave" and remove instance_name
    if let Some(toml::Value::Table(server_table)) = table.get_mut("server") {
        server_table.remove("instance_name");
        server_table.insert("role".to_string(), toml::Value::String("slave".to_string()));
    }

    // 3. Mask TLS keys if present
    if let Some(toml::Value::Table(tls_table)) = table.get_mut("tls")
        && tls_table.contains_key("key")
    {
        tls_table.insert(
            "key".to_string(),
            toml::Value::String("${SECRET:tls_key}".to_string()),
        );
    }

    // 4. Mask web secrets if present
    if let Some(toml::Value::Table(web_table)) = table.get_mut("web") {
        if web_table.contains_key("key") {
            web_table.insert(
                "key".to_string(),
                toml::Value::String("${SECRET:web_key}".to_string()),
            );
        }
        if web_table.contains_key("cert") {
            web_table.insert(
                "cert".to_string(),
                toml::Value::String("${SECRET:web_cert}".to_string()),
            );
        }
    }

    // 5. Mask auth secrets if present
    if let Some(toml::Value::Table(auth_table)) = table.get_mut("auth") {
        if auth_table.contains_key("admin_password_hash") {
            auth_table.insert(
                "admin_password_hash".to_string(),
                toml::Value::String("${SECRET:admin_password_hash}".to_string()),
            );
        }
        if auth_table.contains_key("tokens") {
            auth_table.insert(
                "tokens".to_string(),
                toml::Value::String("${SECRET:auth_tokens}".to_string()),
            );
        }
    }

    // 6. Mask integrations secrets if present
    if let Some(toml::Value::Table(integrations_table)) = table.get_mut("integrations")
        && let Some(toml::Value::Table(mikrotik)) = integrations_table.get_mut("mikrotik")
        && mikrotik.contains_key("token")
    {
        mikrotik.insert(
            "token".to_string(),
            toml::Value::String("${SECRET:mikrotik_token}".to_string()),
        );
    }

    toml::to_string_pretty(&table).map_err(|e| HaError::Serialization(e.to_string()))
}

/// Scans a serialized bundle or string for accidental plaintext secret leakage.
///
/// Asserts that none of `known_secrets` appear as substrings, and checks for PEM private key headers.
pub fn scan_for_secrets(bundle_str: &str, known_secrets: &[&str]) -> Result<(), HaError> {
    for secret in known_secrets {
        let trimmed = secret.trim();
        if trimmed.len() >= 4 && !trimmed.starts_with("${SECRET:") && bundle_str.contains(trimmed) {
            return Err(HaError::SecretLeak {
                secret_name: format!(
                    "detected secret content (length {}) in bundle payload",
                    trimmed.len()
                ),
            });
        }
    }

    // Check for raw private key PEM markers
    if bundle_str.contains("BEGIN PRIVATE KEY")
        || bundle_str.contains("BEGIN RSA PRIVATE KEY")
        || bundle_str.contains("BEGIN EC PRIVATE KEY")
        || bundle_str.contains("BEGIN OPENSSH PRIVATE KEY")
    {
        return Err(HaError::SecretLeak {
            secret_name: "detected raw PEM private key marker in bundle payload".to_string(),
        });
    }

    Ok(())
}

/// Substitutes `${SECRET:name}` placeholders in `template` using `local_secrets`.
///
/// If a placeholder has no matching secret in `local_secrets`, checks environment variables (`DNSD_SECRET_<NAME>` or `<NAME>`).
/// If still missing, leaves a warning or returns an error depending on `allow_missing`.
pub fn substitute_secrets<S: ::std::hash::BuildHasher>(
    template: &str,
    local_secrets: &HashMap<String, String, S>,
    allow_missing: bool,
) -> Result<String, HaError> {
    let mut result = template.to_string();
    let prefix = "${SECRET:";
    let suffix = "}";
    let mut search_from = 0;

    while let Some(rel_start) = result[search_from..].find(prefix) {
        let start = search_from + rel_start;
        let after_prefix = &result[start + prefix.len()..];
        if let Some(end) = after_prefix.find(suffix) {
            let secret_name = &after_prefix[..end];
            let full_placeholder_len = prefix.len() + end + suffix.len();

            let replacement = if let Some(val) = local_secrets.get(secret_name) {
                Some(val.clone())
            } else if let Ok(val) = std::env::var(format!("DNSD_SECRET_{secret_name}")) {
                Some(val)
            } else {
                std::env::var(secret_name).ok()
            };

            match replacement {
                Some(val) => {
                    let val_len = val.len();
                    result.replace_range(start..start + full_placeholder_len, &val);
                    search_from = start + val_len;
                }
                None => {
                    if allow_missing {
                        // Replace with empty to allow parse attempt
                        result.replace_range(start..start + full_placeholder_len, "");
                        search_from = start;
                    } else {
                        return Err(HaError::Validation {
                            field: secret_name.to_string(),
                            reason: format!(
                                "Missing required local secret substitution for '{secret_name}'"
                            ),
                        });
                    }
                }
            }
        } else {
            break;
        }
    }

    Ok(result)
}

/// Packages a `ConfigBundle` into a signed `HaMessage::ConfigPush`.
pub fn build_and_sign_push(
    bundle: &ConfigBundle,
    signing_key: &Ed25519SigningKey,
) -> Result<HaMessage, HaError> {
    let bundle_json = bundle.to_json()?;
    let payload_bytes = bundle_json.as_bytes();

    let hash = blake3::hash(payload_bytes);
    let hash_hex = hash.to_hex().to_string();

    let sig = signing_key.sign(hash.as_bytes());
    let sig_hex = hex::encode(sig);

    let payload_b64 = BASE64_STANDARD.encode(payload_bytes);

    Ok(HaMessage::ConfigPush {
        version: bundle.version,
        hash_blake3: hash_hex.clone(),
        signature_ed25519: sig_hex,
        payload_b64,
        payload_hash_blake3: hash_hex,
    })
}

/// Verifies and unpacks a received `HaMessage::ConfigPush`.
///
/// Performs:
/// 1. Monotonicity check: `version > have_version`.
/// 2. Base64 payload decoding.
/// 3. BLAKE3 payload checksum verification.
/// 4. Ed25519 cryptographic signature verification using `master_pubkey`.
/// 5. Deserialization into `ConfigBundle`.
pub fn verify_and_unpack_push(
    push: &HaMessage,
    have_version: u64,
    master_pubkey: &[u8],
) -> Result<ConfigBundle, HaError> {
    let (version, signature_ed25519, payload_b64, payload_hash_blake3) = match push {
        HaMessage::ConfigPush {
            version,
            signature_ed25519,
            payload_b64,
            payload_hash_blake3,
            ..
        } => (
            *version,
            signature_ed25519,
            payload_b64,
            payload_hash_blake3,
        ),
        other => {
            return Err(HaError::Protocol(format!(
                "Expected ConfigPush message, got: {other:?}"
            )));
        }
    };

    // 1. Monotonicity guard: strictly greater than current version
    if version <= have_version {
        return Err(HaError::Validation {
            field: "version".to_string(),
            reason: format!(
                "Push version {version} is not greater than currently synced version {have_version} (monotonicity violation/replay rejected)"
            ),
        });
    }

    // 2. Base64 payload decoding
    let payload_bytes = BASE64_STANDARD
        .decode(payload_b64)
        .map_err(|e| HaError::Protocol(format!("Invalid base64 payload in config push: {e}")))?;

    // 3. BLAKE3 payload checksum verification
    let computed_hash = blake3::hash(&payload_bytes);
    let computed_hash_hex = computed_hash.to_hex().to_string();

    let expected_hash = payload_hash_blake3.trim_start_matches("blake3:");
    if computed_hash_hex != expected_hash {
        return Err(HaError::Protocol(format!(
            "Payload BLAKE3 checksum mismatch: computed {computed_hash_hex}, expected {expected_hash}"
        )));
    }

    // 4. Ed25519 signature verification
    let sig_bytes = hex::decode(signature_ed25519)
        .or_else(|_| BASE64_STANDARD.decode(signature_ed25519))
        .map_err(|e| HaError::Crypto(format!("Invalid signature encoding: {e}")))?;

    // Verify over hash bytes
    verify_ed25519_signature(master_pubkey, computed_hash.as_bytes(), &sig_bytes)?;

    // 5. Deserialization
    let bundle_str = std::str::from_utf8(&payload_bytes)
        .map_err(|e| HaError::Serialization(format!("Bundle payload is not valid UTF-8: {e}")))?;

    ConfigBundle::from_json(bundle_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_sanitization_and_secret_redaction() {
        let master_toml = r#"
config_version = 1

[server]
role = "master"
instance_name = "master-prod"
data_dir = "/var/lib/sito"

[ha]
replication_port = 8953

[tls]
cert = "/etc/sito/cert.pem"
key = "super_secret_private_key_content"

[auth]
admin_password_hash = "$argon2id$v=19$m=65536,t=3,p=4$secret_hash"

[integrations.mikrotik]
token = "mikrotik_secret_token_12345"
"#;

        let sanitized = sanitize_config_for_bundle(master_toml).unwrap();

        // Check removals
        assert!(!sanitized.contains("[ha]"));
        assert!(!sanitized.contains("master-prod"));
        assert!(sanitized.contains("role = \"slave\""));

        // Check masking
        assert!(!sanitized.contains("super_secret_private_key_content"));
        assert!(!sanitized.contains("secret_hash"));
        assert!(!sanitized.contains("mikrotik_secret_token_12345"));

        assert!(sanitized.contains("${SECRET:tls_key}"));
        assert!(sanitized.contains("${SECRET:admin_password_hash}"));
        assert!(sanitized.contains("${SECRET:mikrotik_token}"));

        // Security scanner test
        let secrets = [
            "super_secret_private_key_content",
            "secret_hash",
            "mikrotik_secret_token_12345",
        ];
        assert!(scan_for_secrets(&sanitized, &secrets).is_ok());

        // Test scanner detects leaks
        let leaky = format!("{sanitized}\nleak = \"secret_hash\"");
        assert!(scan_for_secrets(&leaky, &secrets).is_err());
    }

    #[test]
    fn test_build_and_verify_push_roundtrip() {
        let signing_key = Ed25519SigningKey::generate().unwrap();

        let bundle = ConfigBundle {
            version: 10,
            timestamp: 123_456_789,
            config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
            custom_rules: vec!["||example.org^".to_string()],
            rewrites: None,
            clients: None,
            lists: vec![FilterListMetadata {
                name: "TestList".to_string(),
                url: "https://example.com/hosts.txt".to_string(),
                enabled: true,
                refresh_hours: Some(24),
            }],
        };

        let push_msg = build_and_sign_push(&bundle, &signing_key).unwrap();

        // Successful unpack
        let unpacked = verify_and_unpack_push(&push_msg, 9, &signing_key.public_key()).unwrap();
        assert_eq!(unpacked, bundle);

        // Monotonicity rejection: version 10 <= 10
        let mono_err = verify_and_unpack_push(&push_msg, 10, &signing_key.public_key());
        assert!(mono_err.is_err());

        // Signature rejection with different key
        let wrong_key = Ed25519SigningKey::generate().unwrap();
        let sig_err = verify_and_unpack_push(&push_msg, 9, &wrong_key.public_key());
        assert!(sig_err.is_err());
    }

    #[test]
    fn test_substitute_secrets_recursive_safety() {
        let mut secrets = HashMap::new();
        // Secret value itself contains placeholder syntax
        secrets.insert(
            "nested".to_string(),
            "val_${SECRET:nested}_safe".to_string(),
        );
        let template = "key = \"${SECRET:nested}\"";
        let res = substitute_secrets(template, &secrets, false).unwrap();
        assert_eq!(res, "key = \"val_${SECRET:nested}_safe\"");
    }
}
