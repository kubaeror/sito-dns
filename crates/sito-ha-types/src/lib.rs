//! Portable HA contract types.
//!
//! This crate deliberately has no runtime/server dependencies: the admin API,
//! CLI validation and any embedder can use the HA configuration, status and
//! wire types even when the `sito-ha` implementation is not compiled in.

pub mod bundle;
pub mod config;
pub mod error;
pub mod protocol;
pub mod readiness;
pub mod status;

pub use bundle::{AppliedWatermark, ConfigBundle, FilterListMetadata};
pub use config::HaConfig;
pub use error::HaError;
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

        let bundle = ConfigBundle {
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
        assert_eq!(PROTOCOL_VERSION, 1);
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
