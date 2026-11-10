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
    /// Cluster epoch/term that produced this bundle.
    ///
    /// Missing in bundles signed before terms existed, which are interpreted as
    /// term 0 for backwards compatibility. A term increase is an explicit
    /// operator promotion; a stale master from an older term can never
    /// overwrite a newer slave, regardless of its version counter.
    #[serde(default)]
    pub term: u64,
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

    /// Strips secret material from the structured fields in place.
    ///
    /// The `config_toml` string is sanitized by [`sanitize_config_for_bundle`],
    /// but the structured `clients` value travels alongside it and must be
    /// sanitized identically: per-client shared secrets (`client_id_secrets`)
    /// are node-local (DoH path / DoT SNI credentials) and must never be
    /// replicated.
    pub fn strip_structured_secrets(&mut self) {
        if let Some(ref mut clients) = self.clients {
            strip_client_id_secrets(clients);
        }
    }

    /// Returns a copy with all structured secret material stripped.
    #[must_use]
    pub fn sanitized(&self) -> Self {
        let mut bundle = self.clone();
        bundle.strip_structured_secrets();
        bundle
    }
}

/// Removes the `client_id_secrets` table from a structured `[clients]` value.
fn strip_client_id_secrets(clients: &mut toml::Value) {
    if let toml::Value::Table(table) = clients {
        table.remove("client_id_secrets");
    }
}

/// Builds a sanitized TOML string from a master configuration TOML string.
///
/// Strips out:
/// - The entire `[ha]` section
/// - `server.instance_name` (so slaves preserve their own local instance names)
/// - Secret material: legacy `[auth]` verifiers, RouterOS credentials and
///   per-client shared secrets (path-valued fields such as `tls.key` are kept;
///   they are node-local paths, not secret material)
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

    // 3. Mask genuine secret material only. Path-valued fields (`tls.key`,
    // `web.key`, `web.cert`) are NOT masked: replacing a path with
    // `${SECRET:...}` makes the slave fail substitution and permanently
    // rejects every push (slaves keep their own node-local TLS files).
    //
    // `[auth]` in the current schema only carries session/token policy
    // (optionally `users.toml`); legacy `admin_password_hash`/`tokens` values
    // are secret material and are stripped outright rather than replaced by a
    // placeholder the slave cannot resolve.
    if let Some(toml::Value::Table(auth_table)) = table.get_mut("auth") {
        auth_table.remove("admin_password_hash");
        auth_table.remove("tokens");
    }

    // 4. Strip integration secrets: these are provisioned per node (or
    // supplied via `${SECRET:...}` for the fields that support it) and must
    // never travel inside the replicated configuration.
    if let Some(toml::Value::Table(integrations_table)) = table.get_mut("integrations")
        && let Some(toml::Value::Table(mikrotik)) = integrations_table.get_mut("mikrotik")
    {
        mikrotik.remove("token");
        mikrotik.remove("password");
    }

    // 5. Strip per-client shared secrets (DoH path / DoT SNI identity). A
    // table cannot be replaced by a `${SECRET:...}` string placeholder without
    // breaking TOML, so slaves keep their local copy (see
    // `merge_local_replication_config`) and master-added secrets must be
    // provisioned per node.
    if let Some(toml::Value::Table(clients_table)) = table.get_mut("clients") {
        clients_table.remove("client_id_secrets");
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

/// Persisted applied-version watermark for a slave node.
///
/// Written atomically (0600) after a push has been applied and its
/// configuration persisted, before the slave acknowledges it. On startup the
/// slave restores this record so a restart cannot replay an older signed
/// bundle or overwrite the applied configuration with stale content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppliedWatermark {
    /// Configuration version of the last successfully applied bundle.
    pub version: u64,
    /// Cluster epoch/term of that bundle. Missing in watermark files written
    /// before terms existed, which are interpreted as term 0.
    #[serde(default)]
    pub term: u64,
    /// BLAKE3 hash of the signed bundle payload that produced `version`.
    pub payload_hash: String,
    /// Unix milliseconds at which the bundle was applied.
    pub timestamp: u64,
    /// Set when a same-version payload-hash mismatch proved that this node and
    /// its master are on different forks. All same-term pushes are rejected
    /// until an explicit higher-term promotion arrives.
    #[serde(default)]
    pub forked: bool,
    /// Version at which the fork was detected.
    #[serde(default)]
    pub forked_at_version: u64,
    /// BLAKE3 digest of the exact `config.toml` document this node persisted
    /// when it applied the bundle.
    ///
    /// On restart the digest is compared with the on-disk document. A mismatch
    /// means a local edit/revert changed the configuration while the process
    /// was stopped (or the file watcher applied one while running) and the
    /// slave must re-apply the master's bundle instead of early-ACKing
    /// `Synced`. Missing in watermarks written before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_config_digest: Option<String>,
}

impl AppliedWatermark {
    /// Returns the normalized (prefix-free) payload hash.
    #[must_use]
    pub fn normalized_hash(&self) -> &str {
        self.payload_hash.trim_start_matches("blake3:")
    }
}

/// Computes the BLAKE3 digest of a configuration document as normalized hex.
///
/// The digest is over the exact persisted document, so any local edit
/// (including whitespace) is detected. Node-local edits are also flagged until
/// the next successful replication apply re-establishes a matching digest;
/// this is deliberately fail-safe because the local file and the applied
/// bundle can otherwise diverge silently.
#[must_use]
pub fn config_digest(document: &str) -> String {
    blake3::hash(document.as_bytes()).to_hex().to_string()
}

/// Extracts the signed payload hash from a `ConfigPush` envelope.
pub fn push_payload_hash(push: &HaMessage) -> Result<String, HaError> {
    match push {
        HaMessage::ConfigPush {
            payload_hash_blake3,
            ..
        } => Ok(payload_hash_blake3
            .trim_start_matches("blake3:")
            .to_string()),
        other => Err(HaError::Protocol(format!(
            "Expected ConfigPush message, got: {other:?}"
        ))),
    }
}

/// Packages a `ConfigBundle` into a signed `HaMessage::ConfigPush`.
///
/// The bundle is sanitized before serialization (structured
/// `clients.client_id_secrets` stripped) so secret material can never reach
/// the wire, even when a caller built the bundle from a raw configuration.
pub fn build_and_sign_push(
    bundle: &ConfigBundle,
    signing_key: &Ed25519SigningKey,
) -> Result<HaMessage, HaError> {
    let bundle = bundle.sanitized();
    let bundle_json = bundle.to_json()?;
    let payload_bytes = bundle_json.as_bytes();

    let hash = blake3::hash(payload_bytes);
    let hash_hex = hash.to_hex().to_string();

    let sig = signing_key.sign(hash.as_bytes());
    let sig_hex = hex::encode(sig);

    let payload_b64 = BASE64_STANDARD.encode(payload_bytes);

    Ok(HaMessage::ConfigPush {
        version: bundle.version,
        term: bundle.term,
        hash_blake3: hash_hex.clone(),
        signature_ed25519: sig_hex,
        payload_b64,
        payload_hash_blake3: hash_hex,
    })
}

/// Verifies the envelope and returns the signed bundle plus the computed
/// normalized payload hash.
fn verify_and_unpack_push_inner(
    push: &HaMessage,
    master_pubkey: &[u8],
) -> Result<(ConfigBundle, String), HaError> {
    let (version, term, signature_ed25519, payload_b64, payload_hash_blake3, envelope_hash) =
        match push {
            HaMessage::ConfigPush {
                version,
                term,
                signature_ed25519,
                payload_b64,
                payload_hash_blake3,
                hash_blake3,
            } => (
                *version,
                *term,
                signature_ed25519,
                payload_b64,
                payload_hash_blake3,
                hash_blake3,
            ),
            other => {
                return Err(HaError::Protocol(format!(
                    "Expected ConfigPush message, got: {other:?}"
                )));
            }
        };

    if version == u64::MAX {
        return Err(HaError::Validation {
            field: "version".to_string(),
            reason: "Push version u64::MAX is implausible; the sequence could never advance again"
                .to_string(),
        });
    }
    if term == u64::MAX {
        return Err(HaError::Validation {
            field: "term".to_string(),
            reason: "Push term u64::MAX is implausible; the epoch could never advance again"
                .to_string(),
        });
    }

    // 1. Base64 payload decoding
    let payload_bytes = BASE64_STANDARD
        .decode(payload_b64)
        .map_err(|e| HaError::Protocol(format!("Invalid base64 payload in config push: {e}")))?;

    // 2. BLAKE3 payload checksum verification
    let computed_hash = blake3::hash(&payload_bytes);
    let computed_hash_hex = computed_hash.to_hex().to_string();

    let expected_hash = payload_hash_blake3.trim_start_matches("blake3:");
    if computed_hash_hex != expected_hash {
        return Err(HaError::Protocol(format!(
            "Payload BLAKE3 checksum mismatch: computed {computed_hash_hex}, expected {expected_hash}"
        )));
    }
    // The envelope hash must agree with the signed payload hash; a mismatch
    // indicates tampering with the outer message.
    if envelope_hash.trim_start_matches("blake3:") != computed_hash_hex {
        return Err(HaError::Protocol(
            "Envelope BLAKE3 hash does not match the signed payload hash".to_string(),
        ));
    }

    // 3. Ed25519 signature verification
    let sig_bytes = hex::decode(signature_ed25519)
        .or_else(|_| BASE64_STANDARD.decode(signature_ed25519))
        .map_err(|e| HaError::Crypto(format!("Invalid signature encoding: {e}")))?;

    // Verify over hash bytes
    verify_ed25519_signature(master_pubkey, computed_hash.as_bytes(), &sig_bytes)?;

    // 4. Deserialization
    let bundle_str = std::str::from_utf8(&payload_bytes)
        .map_err(|e| HaError::Serialization(format!("Bundle payload is not valid UTF-8: {e}")))?;

    let bundle = ConfigBundle::from_json(bundle_str)?;

    // 5. Envelope/payload version binding: the version the monotonicity guard
    // checked must be the same one actually carried inside the signed payload,
    // otherwise an attacker can replay an old signed bundle with a bumped
    // envelope version and roll the slave's configuration backward.
    if bundle.version != version {
        return Err(HaError::Validation {
            field: "version".to_string(),
            reason: format!(
                "Envelope version {version} does not match signed bundle version {} (replay/downgrade rejected)",
                bundle.version
            ),
        });
    }
    if bundle.term != term {
        return Err(HaError::Validation {
            field: "term".to_string(),
            reason: format!(
                "Envelope term {term} does not match signed bundle term {} (epoch tampering rejected)",
                bundle.term
            ),
        });
    }

    Ok((bundle, computed_hash_hex))
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
    let (bundle, _hash) = verify_and_unpack_push_inner(push, master_pubkey)?;

    // Monotonicity guard: strictly greater than current version
    if bundle.version <= have_version {
        return Err(HaError::Validation {
            field: "version".to_string(),
            reason: format!(
                "Push version {} is not greater than currently synced version {have_version} (monotonicity violation/replay rejected)",
                bundle.version
            ),
        });
    }

    Ok(bundle)
}

/// Verifies and unpacks a push against the persisted applied watermark.
///
/// A stale master from an older term is rejected even when its version counter
/// is higher, because a term increase is the explicit promotion signal. Within
/// the same term the version must advance; an equal version is accepted only
/// when it is the same signed payload (idempotent re-delivery). A higher term
/// is a new epoch, but it does **not** reset the sequence: the promoted version
/// must also be above the applied watermark, so an explicit promotion raises
/// both term and version.
pub fn verify_and_unpack_push_with_watermark(
    push: &HaMessage,
    watermark: Option<&AppliedWatermark>,
    master_pubkey: &[u8],
) -> Result<ConfigBundle, HaError> {
    let (bundle, payload_hash) = verify_and_unpack_push_inner(push, master_pubkey)?;

    if let Some(watermark) = watermark {
        if watermark.forked && bundle.term <= watermark.term {
            return Err(HaError::Validation {
                field: "term".to_string(),
                reason: format!(
                    "A same-version payload fork was latched at term {} version {}; refusing term {} version {} until a strictly higher-term promotion arrives",
                    watermark.term, watermark.forked_at_version, bundle.term, bundle.version
                ),
            });
        }
        if bundle.term < watermark.term {
            return Err(HaError::Validation {
                field: "term".to_string(),
                reason: format!(
                    "Push term {} is below the persisted applied term {} (stale master/epoch rejected)",
                    bundle.term, watermark.term
                ),
            });
        }
        if bundle.term > watermark.term {
            // A term increase is an explicit promotion, but it is not
            // permission to roll the version back: the promoted master must
            // continue above the cluster's applied high-water mark.
            if bundle.version <= watermark.version {
                return Err(HaError::Validation {
                    field: "version".to_string(),
                    reason: format!(
                        "Higher-term push (term {} version {}) must continue above the applied version {}; a term bump does not permit a version rollback (restore the promoted state or raise the version)",
                        bundle.term, bundle.version, watermark.version
                    ),
                });
            }
        }
        if bundle.term == watermark.term {
            if bundle.version < watermark.version {
                return Err(HaError::Validation {
                    field: "version".to_string(),
                    reason: format!(
                        "Push version {} is below the persisted applied watermark {} (restart/replay rejected)",
                        bundle.version, watermark.version
                    ),
                });
            }
            if bundle.version == watermark.version && payload_hash != watermark.normalized_hash() {
                return Err(HaError::Validation {
                    field: "version".to_string(),
                    reason: format!(
                        "Push version {} has payload hash {payload_hash} but the applied watermark records {} (same-version content replay rejected)",
                        bundle.version,
                        watermark.normalized_hash()
                    ),
                });
            }
        }
    }

    Ok(bundle)
}

/// Returns true when `watermark` already covers a push with `term`, `version`
/// and `payload_hash` (same epoch, same version, identical signed payload).
#[must_use]
pub fn watermark_covers(
    watermark: &AppliedWatermark,
    term: u64,
    version: u64,
    payload_hash: &str,
) -> bool {
    term == watermark.term
        && version == watermark.version
        && payload_hash.trim_start_matches("blake3:") == watermark.normalized_hash()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_bundle_without_term_verifies_as_term_zero() {
        let signing_key = Ed25519SigningKey::generate().unwrap();
        // A payload produced by a pre-term master: no `term` field.
        let payload = r#"{"version":7,"timestamp":1,"config_toml":"config_version = 1\n[server]\nrole = \"slave\"\n","custom_rules":[],"lists":[]}"#;
        let hash = blake3::hash(payload.as_bytes());
        let hash_hex = hash.to_hex().to_string();
        let sig = signing_key.sign(hash.as_bytes());
        let push = HaMessage::ConfigPush {
            version: 7,
            term: 0,
            hash_blake3: hash_hex.clone(),
            signature_ed25519: hex::encode(sig),
            payload_b64: BASE64_STANDARD.encode(payload.as_bytes()),
            payload_hash_blake3: hash_hex,
        };

        let bundle = verify_and_unpack_push(&push, 6, &signing_key.public_key())
            .expect("a legacy term-less bundle must remain verifiable");
        assert_eq!(bundle.term, 0, "missing term must default to epoch 0");

        let bundle =
            verify_and_unpack_push_with_watermark(&push, None, &signing_key.public_key()).unwrap();
        assert_eq!(bundle.term, 0);
    }

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
key = "/etc/sito/tls.key"

[web]
bind = "0.0.0.0"

[auth]
session_ttl_hours = 12
admin_password_hash = "$argon2id$v=19$m=65536,t=3,p=4$secret_hash"

[clients]
client_id_secrets = { "kids-tablet" = "client_shared_secret_9876" }

[integrations.mikrotik]
token = "mikrotik_secret_token_12345"
password = "mikrotik_secret_password"
"#;

        let sanitized = sanitize_config_for_bundle(master_toml).unwrap();

        // Check removals
        assert!(!sanitized.contains("[ha]"));
        assert!(!sanitized.contains("master-prod"));
        assert!(sanitized.contains("role = \"slave\""));
        assert!(sanitized.contains("session_ttl_hours = 12"));

        // Check secret stripping
        assert!(!sanitized.contains("super_secret_private_key_content"));
        assert!(!sanitized.contains("secret_hash"));
        assert!(!sanitized.contains("admin_password_hash"));
        assert!(!sanitized.contains("mikrotik_secret_token_12345"));
        assert!(!sanitized.contains("mikrotik_secret_password"));
        assert!(!sanitized.contains("client_shared_secret_9876"));
        assert!(!sanitized.contains("client_id_secrets"));

        // Path-valued fields must survive verbatim: they are node-local file
        // paths, not secrets, and a `${SECRET:tls_key}` placeholder would make
        // the slave reject every push.
        assert!(sanitized.contains("key = \"/etc/sito/tls.key\""));
        assert!(!sanitized.contains("${SECRET:tls_key}"));
        assert!(!sanitized.contains("${SECRET:"));

        // Security scanner test
        let secrets = [
            "super_secret_private_key_content",
            "secret_hash",
            "mikrotik_secret_token_12345",
            "mikrotik_secret_password",
            "client_shared_secret_9876",
        ];
        assert!(scan_for_secrets(&sanitized, &secrets).is_ok());

        // Test scanner detects leaks
        let leaky = format!("{sanitized}\nleak = \"secret_hash\"");
        assert!(scan_for_secrets(&leaky, &secrets).is_err());
    }

    #[test]
    fn test_serialized_bundle_strips_structured_client_secrets() {
        let signing_key = Ed25519SigningKey::generate().unwrap();

        let mut secrets = toml::Table::new();
        secrets.insert(
            "kids-tablet".to_string(),
            toml::Value::String("client_shared_secret_9876".to_string()),
        );
        let mut clients = toml::Table::new();
        clients.insert("client_id_secrets".to_string(), toml::Value::Table(secrets));
        clients.insert(
            "entries".to_string(),
            toml::Value::Array(vec![toml::Value::String("kids-tablet".to_string())]),
        );

        let bundle = ConfigBundle {
            version: 7,
            term: 0,
            timestamp: 123,
            config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
            custom_rules: vec![],
            rewrites: None,
            clients: Some(toml::Value::Table(clients)),
            lists: vec![],
        };

        let push = build_and_sign_push(&bundle, &signing_key).unwrap();
        let payload_b64 = match &push {
            HaMessage::ConfigPush { payload_b64, .. } => payload_b64.clone(),
            other => panic!("expected ConfigPush, got {other:?}"),
        };
        let payload = String::from_utf8(BASE64_STANDARD.decode(payload_b64).unwrap()).unwrap();
        assert!(
            !payload.contains("client_shared_secret_9876"),
            "serialized push payload must not contain the client secret: {payload}"
        );
        assert!(!payload.contains("client_id_secrets"));
        assert!(
            payload.contains("kids-tablet"),
            "non-secret client entries must be replicated"
        );

        // The unpacked bundle seen by the slave is sanitized as well.
        let unpacked = verify_and_unpack_push(&push, 6, &signing_key.public_key()).unwrap();
        let clients = unpacked
            .clients
            .expect("structured clients must be replicated");
        assert!(clients.get("client_id_secrets").is_none());
    }

    #[test]
    fn test_build_and_verify_push_roundtrip() {
        let signing_key = Ed25519SigningKey::generate().unwrap();

        let bundle = ConfigBundle {
            version: 10,
            term: 0,
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
    fn test_envelope_version_must_match_signed_payload() {
        let signing_key = Ed25519SigningKey::generate().unwrap();

        let bundle = ConfigBundle {
            version: 10,
            term: 0,
            timestamp: 123_456_789,
            config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
            custom_rules: vec![],
            rewrites: None,
            clients: None,
            lists: vec![],
        };

        let push_msg = build_and_sign_push(&bundle, &signing_key).unwrap();

        // Tamper with the unsigned envelope version (replay/downgrade attempt):
        // bumping it must not bypass the signed-payload version check.
        let tampered = match push_msg {
            HaMessage::ConfigPush {
                hash_blake3,
                signature_ed25519,
                payload_b64,
                payload_hash_blake3,
                ..
            } => HaMessage::ConfigPush {
                version: 11,
                term: 0,
                hash_blake3,
                signature_ed25519,
                payload_b64,
                payload_hash_blake3,
            },
            other => panic!("expected ConfigPush, got {other:?}"),
        };

        let err = verify_and_unpack_push(&tampered, 9, &signing_key.public_key());
        assert!(
            err.is_err(),
            "envelope version not bound to the signed payload must be rejected"
        );
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

    #[test]
    fn test_substitute_secrets_from_environment_and_missing_failure() {
        // There is no on-disk local secret store: placeholders resolve from
        // `DNSD_SECRET_<name>` (and then a bare `<name>`) environment
        // variables. Use a unique name so parallel tests cannot observe it.
        let suffix = format!("ha_test_{}", rand::random::<u64>());
        let var = format!("DNSD_SECRET_{suffix}");
        // SAFETY: the variable name is unique to this test; no other test or
        // thread reads it.
        unsafe { std::env::set_var(&var, "env-secret-value") };

        let template = format!("token = \"${{SECRET:{suffix}}}\"");
        let resolved = substitute_secrets(&template, &HashMap::new(), false).unwrap();
        assert_eq!(resolved, "token = \"env-secret-value\"");
        // SAFETY: see above.
        unsafe { std::env::remove_var(&var) };

        // A missing secret fails closed instead of silently substituting empty.
        let err = substitute_secrets(
            "token = \"${SECRET:definitely_missing_ha_secret}\"",
            &HashMap::new(),
            false,
        )
        .unwrap_err();
        assert!(matches!(err, HaError::Validation { .. }));
    }
}
