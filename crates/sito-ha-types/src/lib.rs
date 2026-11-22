//! Portable HA contract types.
//!
//! This crate deliberately has no runtime/server dependencies: the admin API,
//! CLI validation and any embedder can use the HA configuration, status and
//! wire types even when the `sito-ha` implementation is not compiled in.

pub mod bundle;
pub mod config;
pub mod error;
pub mod hash;
pub mod protocol;
pub mod readiness;
pub mod status;

pub use bundle::{AppliedWatermark, ConfigBundle, FilterListMetadata};
pub use config::HaConfig;
pub use error::HaError;
pub use hash::{
    BundleHashError, normalize_blake3_hash, normalize_bundle_hash, normalize_optional_hash,
};
pub use protocol::{AckConflict, HaMessage, PROTOCOL_VERSION, UpstreamReport};
pub use readiness::{HaReadiness, HaReadinessState};
pub use status::{PublishOutcome, ResyncOutcome, SlaveState, SlaveStatsSummary, SlaveSummary};

/// Parses a 32-byte Ed25519 public key from hex or standard base64.
///
/// This lives beside [`HaConfig`] so configuration validation does not depend
/// on the crypto/runtime crate.
pub fn parse_public_key(input: &str) -> Result<[u8; 32], HaError> {
    use base64::Engine as _;
    use base64::prelude::BASE64_STANDARD;

    let trimmed = input.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let decoded = hex::decode(trimmed)
            .map_err(|e| HaError::Crypto(format!("Invalid hex public key: {e}")))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        return Ok(out);
    }

    if let Ok(decoded) = BASE64_STANDARD.decode(trimmed)
        && decoded.len() == 32
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        return Ok(out);
    }

    Err(HaError::Crypto(format!(
        "Invalid Ed25519 public key format (expected 32-byte hex or base64): '{trimmed}'"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::collections::HashMap;

    #[test]
    fn contract_types_serialize_and_parse_without_runtime_dependencies() {
        let ping = HaMessage::Ping { ts: 42 };
        let json = ping.to_json().expect("serialize ping");
        assert_eq!(HaMessage::from_json(&json).expect("parse ping"), ping);

        let config = HaConfig::default();
        assert_eq!(config.replication_port, 8953);
        assert!(!config.allow_unpinned_tls);
        assert!(!config.allow_insecure_ws);

        let config_json = serde_json::to_string(&config).expect("serialize HaConfig");
        assert_eq!(
            serde_json::from_str::<HaConfig>(&config_json).expect("parse HaConfig"),
            config
        );

        let synced_json = serde_json::to_string(&SlaveState::Synced).expect("serialize state");
        assert_eq!(
            serde_json::from_str::<SlaveState>(&synced_json).expect("parse state"),
            SlaveState::Synced
        );

        let bundle = ConfigBundle {
            config_digest: String::new(),
            signing_key_fingerprint: String::new(),
            protocol_version: PROTOCOL_VERSION,
            version: 1,
            term: 2,
            timestamp: 3,
            config_toml: "config_version = 2\n".to_string(),
            custom_rules: vec![],
            rewrites: None,
            clients: None,
            lists: vec![FilterListMetadata {
                name: "ads".to_string(),
                url: "https://example.invalid/ads.txt".to_string(),
                enabled: true,
                refresh_hours: Some(24),
            }],
        };
        let bundle_json = bundle.to_json().expect("serialize bundle");
        assert_eq!(
            ConfigBundle::from_json(&bundle_json).expect("parse bundle"),
            bundle
        );

        let mut upstreams = HashMap::new();
        upstreams.insert(
            "tls://resolver".to_string(),
            UpstreamReport {
                rtt_ms: 1.5,
                errors: 0,
            },
        );
        let stats = HaMessage::StatsReport {
            window_s: 30,
            queries: 1,
            blocked: 0,
            upstreams,
        };
        assert_eq!(
            HaMessage::from_json(&stats.to_json().expect("stats json")).expect("stats parse"),
            stats
        );

        assert_eq!(SlaveState::Synced.to_string(), "synced");
        assert!(HaReadiness::ready().ready);
        assert_eq!(PROTOCOL_VERSION, 2);
    }

    #[test]
    fn protocol_v2_state_and_bundle_reject_v1_shapes() {
        let default_bundle = ConfigBundle::default();
        assert_eq!(default_bundle.protocol_version, PROTOCOL_VERSION);

        // v1 signed payloads have no protocol_version and must not deserialize
        // as a v2 bundle.
        let legacy_bundle = r#"{"version":7,"timestamp":1,"config_toml":"config_version = 2\n","custom_rules":[],"lists":[]}"#;
        assert!(ConfigBundle::from_json(legacy_bundle).is_err());

        let watermark = AppliedWatermark {
            signing_key_fingerprint: None,
            protocol_version: PROTOCOL_VERSION,
            version: 7,
            term: 1,
            payload_hash: "abc".to_string(),
            timestamp: 1,
            forked: false,
            forked_at_version: 0,
            applied_config_digest: None,
        };
        let json = serde_json::to_string(&watermark).expect("serialize watermark");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse json");
        assert_eq!(value["protocol_version"], 2);
        assert_eq!(
            value["watermark"]["version"], 7,
            "v2 watermarks are wrapped so v1 binaries fail instead of silently reading them"
        );
        assert_eq!(
            serde_json::from_str::<AppliedWatermark>(&json).expect("roundtrip"),
            watermark
        );

        // A v1 flat watermark (or a future protocol version) is rejected.
        let legacy_watermark = r#"{"version":7,"payload_hash":"abc","timestamp":1}"#;
        assert!(serde_json::from_str::<AppliedWatermark>(legacy_watermark).is_err());
        let other_version = json.replace(r#""protocol_version":2"#, r#""protocol_version":3"#);
        let err = serde_json::from_str::<AppliedWatermark>(&other_version)
            .expect_err("a mismatched watermark protocol version must be rejected");
        assert!(err.to_string().contains("protocol_mismatch"));
    }

    #[test]
    fn crate_manifest_does_not_depend_on_the_runtime_implementation() {
        let manifest: toml::Value =
            toml::from_str(include_str!("../Cargo.toml")).expect("valid crate manifest");
        for table in ["dependencies", "dev-dependencies", "build-dependencies"] {
            assert!(
                manifest
                    .get(table)
                    .and_then(toml::Value::as_table)
                    .is_none_or(|deps| !deps.contains_key("sito-ha")),
                "sito-ha-types must not depend on sito-ha in [{table}]"
            );
        }
    }

    #[test]
    fn public_key_parser_accepts_hex_and_base64() {
        let key = [7u8; 32];
        let hex_key = hex::encode(key);
        assert_eq!(parse_public_key(&hex_key).expect("hex"), key);

        let b64 = base64::prelude::BASE64_STANDARD.encode(key);
        assert_eq!(parse_public_key(&b64).expect("base64"), key);
        assert!(parse_public_key("not-a-key").is_err());
    }
}
