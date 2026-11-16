//! Configuration bundle types shared by master and slave.

use serde::{Deserialize, Serialize};

use crate::error::HaError;

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
    /// The `config_toml` string is sanitized by `sanitize_config_for_bundle`,
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

/// Watermark of the last successfully applied bundle.
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
