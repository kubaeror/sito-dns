//! Configuration bundle types shared by master and slave.

use serde::ser::SerializeStruct as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::HaError;
use crate::protocol::PROTOCOL_VERSION;

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
    /// HA protocol version that produced this bundle.
    ///
    /// Required: a v1 signed payload (which has no such field) fails to
    /// deserialize instead of being interpreted with v2 semantics. The field is
    /// signed as part of the bundle JSON.
    pub protocol_version: u32,
    /// BLAKE3 digest of `config_toml` (normalized hex, no prefix).
    ///
    /// Bound into the signed payload and recomputed by the slave before apply.
    /// The master fills it when signing; a manually built payload with a
    /// mismatched digest is refused.
    pub config_digest: String,
    /// BLAKE3 fingerprint of the master's Ed25519 signing public key.
    ///
    /// Bound into the signed payload and checked against the configured
    /// `master_pubkey` before apply. The master computes it when signing.
    pub signing_key_fingerprint: String,
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

impl Default for ConfigBundle {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            config_digest: String::new(),
            signing_key_fingerprint: String::new(),
            version: 0,
            term: 0,
            timestamp: 0,
            config_toml: String::new(),
            custom_rules: Vec::new(),
            rewrites: None,
            clients: None,
            lists: Vec::new(),
        }
    }
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedWatermark {
    /// HA protocol version that wrote this watermark.
    ///
    /// Required and checked on load. The on-disk shape is wrapped under
    /// `{"protocol_version": 2, "watermark": { ... }}` so a v1 binary cannot
    /// silently deserialize v2 state: v1 expects the fields at the top level
    /// and fails with a missing-field error instead.
    pub protocol_version: u32,
    /// Configuration version of the last successfully applied bundle.
    pub version: u64,
    /// Cluster epoch/term of that bundle. Always present in v2 watermarks.
    pub term: u64,
    /// BLAKE3 hash of the signed bundle payload that produced `version`.
    pub payload_hash: String,
    /// Ed25519 signing-key fingerprint that produced the applied bundle.
    ///
    /// Absent in watermarks written before identity binding existed; the next
    /// successful apply records it. A same-term push from a different key is
    /// rejected until an explicit higher-term promotion.
    pub signing_key_fingerprint: Option<String>,
    /// Unix milliseconds at which the bundle was applied.
    pub timestamp: u64,
    /// Set when a same-version payload-hash mismatch proved that this node and
    /// its master are on different forks. All same-term pushes are rejected
    /// until an explicit higher-term promotion arrives.
    pub forked: bool,
    /// Version at which the fork was detected.
    pub forked_at_version: u64,
    /// BLAKE3 digest of the exact `config.toml` document this node persisted
    /// when it applied the bundle.
    ///
    /// On restart the digest is compared with the on-disk document. A mismatch
    /// means a local edit/revert changed the configuration while the process
    /// was stopped (or the file watcher applied one while running) and the
    /// slave must re-apply the master's bundle instead of early-ACKing
    /// `Synced`. Always present when a digest was recorded.
    pub applied_config_digest: Option<String>,
}

impl Serialize for AppliedWatermark {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Body<'a> {
            version: u64,
            term: u64,
            payload_hash: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            signing_key_fingerprint: Option<&'a str>,
            timestamp: u64,
            forked: bool,
            forked_at_version: u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            applied_config_digest: Option<&'a str>,
        }

        let mut state = serializer.serialize_struct("AppliedWatermark", 2)?;
        state.serialize_field("protocol_version", &self.protocol_version)?;
        state.serialize_field(
            "watermark",
            &Body {
                version: self.version,
                term: self.term,
                payload_hash: &self.payload_hash,
                signing_key_fingerprint: self.signing_key_fingerprint.as_deref(),
                timestamp: self.timestamp,
                forked: self.forked,
                forked_at_version: self.forked_at_version,
                applied_config_digest: self.applied_config_digest.as_deref(),
            },
        )?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for AppliedWatermark {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Envelope {
            protocol_version: u32,
            watermark: Body,
        }

        #[derive(Deserialize)]
        struct Body {
            version: u64,
            #[serde(default)]
            term: u64,
            payload_hash: String,
            #[serde(default)]
            signing_key_fingerprint: Option<String>,
            timestamp: u64,
            #[serde(default)]
            forked: bool,
            #[serde(default)]
            forked_at_version: u64,
            #[serde(default)]
            applied_config_digest: Option<String>,
        }

        let envelope = Envelope::deserialize(deserializer)?;
        if envelope.protocol_version != PROTOCOL_VERSION {
            return Err(serde::de::Error::custom(format!(
                "protocol_mismatch: watermark was written by HA protocol v{} but this node requires v{}; restore a v2 watermark/backup or delete it to force a full resync",
                envelope.protocol_version, PROTOCOL_VERSION
            )));
        }
        Ok(Self {
            protocol_version: envelope.protocol_version,
            version: envelope.watermark.version,
            term: envelope.watermark.term,
            payload_hash: envelope.watermark.payload_hash,
            signing_key_fingerprint: envelope.watermark.signing_key_fingerprint,
            timestamp: envelope.watermark.timestamp,
            forked: envelope.watermark.forked,
            forked_at_version: envelope.watermark.forked_at_version,
            applied_config_digest: envelope.watermark.applied_config_digest,
        })
    }
}

impl AppliedWatermark {
    /// Returns the normalized (prefix-free) payload hash.
    #[must_use]
    pub fn normalized_hash(&self) -> &str {
        self.payload_hash.trim_start_matches("blake3:")
    }
}
