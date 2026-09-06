//! Configuration structures and validation for High Availability clustering.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::crypto::parse_public_key;
use crate::error::HaError;

fn default_replication_port() -> u16 {
    8953
}

fn default_listen_addr() -> String {
    "0.0.0.0".to_string()
}

fn default_stats_interval_secs() -> u64 {
    30
}

fn default_ping_interval_secs() -> u64 {
    15
}

/// High Availability clustering configuration section `[ha]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaConfig {
    /// Port on which the master node listens for WebSocket replication connections (default: 8953).
    #[serde(default = "default_replication_port")]
    pub replication_port: u16,

    /// Listening IP address for the replication listener (default: "0.0.0.0").
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// WebSocket URL to connect to the master (required on slave nodes, e.g. "wss://192.168.1.10:8953").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_url: Option<String>,

    /// Expected BLAKE3 certificate fingerprint of the master node for pinning (e.g. "blake3:...").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_fingerprint: Option<String>,

    /// Ed25519 public key (in hex or base64) of the master node used to verify signed state bundles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_pubkey: Option<String>,

    /// Path to mTLS certificate file (PEM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<PathBuf>,

    /// Path to mTLS private key file (PEM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<PathBuf>,

    /// Path to CA certificate file (PEM) for mTLS verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<PathBuf>,

    /// Pinned slave certificate BLAKE3 fingerprints accepted by the master.
    #[serde(default)]
    pub pinned_slave_fingerprints: Vec<String>,

    /// Pre-shared authentication token for slave authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slave_token: Option<String>,

    /// Allow unpinned TLS connections (insecure; default: false).
    #[serde(default)]
    pub allow_unpinned_tls: bool,

    /// Allow unencrypted plaintext WebSocket connections (ws://; insecure; default: false).
    #[serde(default)]
    pub allow_insecure_ws: bool,

    /// Interval in seconds for sending periodic statistics reports from slave to master (default: 30s).
    #[serde(default = "default_stats_interval_secs")]
    pub stats_interval_secs: u64,

    /// Interval in seconds for WebSocket heartbeat pings (default: 15s).
    #[serde(default = "default_ping_interval_secs")]
    pub ping_interval_secs: u64,
}

impl Default for HaConfig {
    fn default() -> Self {
        Self {
            replication_port: default_replication_port(),
            listen_addr: default_listen_addr(),
            master_url: None,
            master_fingerprint: None,
            master_pubkey: None,
            cert: None,
            key: None,
            ca: None,
            pinned_slave_fingerprints: Vec::new(),
            slave_token: None,
            allow_unpinned_tls: false,
            allow_insecure_ws: false,
            stats_interval_secs: default_stats_interval_secs(),
            ping_interval_secs: default_ping_interval_secs(),
        }
    }
}

impl HaConfig {
    /// Deserializes `HaConfig` from a `toml::Value`.
    pub fn from_toml_value(val: &toml::Value) -> Result<Self, HaError> {
        val.clone().try_into().map_err(|e| HaError::Validation {
            field: "ha".to_string(),
            reason: format!("Failed to parse [ha] configuration: {e}"),
        })
    }

    /// Validates fields based on the assigned node role ("master" or "slave").
    pub fn validate(&self, role: &str) -> Result<(), HaError> {
        if role == "master" {
            if self.replication_port > 0 {
                let has_token = self
                    .slave_token
                    .as_ref()
                    .is_some_and(|t| !t.trim().is_empty());
                let has_pins = !self.pinned_slave_fingerprints.is_empty();

                if !has_token && !has_pins {
                    return Err(HaError::Validation {
                        field: "slave_token".to_string(),
                        reason: "Master replication requires authentication: either slave_token or pinned_slave_fingerprints must be configured".to_string(),
                    });
                }

                let has_cert = self.cert.is_some();
                let has_key = self.key.is_some();

                if (has_cert && !has_key) || (!has_cert && has_key) {
                    return Err(HaError::Validation {
                        field: "key".to_string(),
                        reason: "Both cert and key must be provided for TLS replication"
                            .to_string(),
                    });
                }

                if (!has_cert || !has_key) && !self.allow_insecure_ws {
                    return Err(HaError::Validation {
                        field: "cert".to_string(),
                        reason: "Master replication requires TLS certificate and key unless allow_insecure_ws = true".to_string(),
                    });
                }
            }
        } else if role == "slave" {
            if self.replication_port == 0 {
                return Err(HaError::Validation {
                    field: "replication_port".to_string(),
                    reason: "Replication port must be greater than 0".to_string(),
                });
            }
            if let Some(ref pubkey_str) = self.master_pubkey {
                parse_public_key(pubkey_str)?;
            }
            if let Some(ref url) = self.master_url {
                if !url.starts_with("ws://") && !url.starts_with("wss://") {
                    return Err(HaError::Validation {
                        field: "master_url".to_string(),
                        reason: format!(
                            "Invalid master_url '{url}': must start with ws:// or wss://"
                        ),
                    });
                }
                if url.starts_with("ws://") && !self.allow_insecure_ws {
                    return Err(HaError::Validation {
                        field: "master_url".to_string(),
                        reason: "Plaintext ws:// replication is rejected by default. Use wss:// or explicitly set allow_insecure_ws = true".to_string(),
                    });
                }
                if url.starts_with("wss://")
                    && self.master_fingerprint.is_none()
                    && !self.allow_unpinned_tls
                {
                    return Err(HaError::Validation {
                        field: "master_fingerprint".to_string(),
                        reason: "WSS replication requires master_fingerprint for certificate pinning unless allow_unpinned_tls = true".to_string(),
                    });
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ha_config_defaults_and_parsing() {
        let toml_str = r#"
replication_port = 8953
master_url = "wss://127.0.0.1:8953"
master_fingerprint = "blake3:abcdef0123456789"
pinned_slave_fingerprints = ["blake3:11223344"]
"#;
        let val: toml::Value = toml::from_str(toml_str).unwrap();
        let cfg = HaConfig::from_toml_value(&val).unwrap();
        assert_eq!(cfg.replication_port, 8953);
        assert_eq!(cfg.master_url.as_deref(), Some("wss://127.0.0.1:8953"));
        assert_eq!(cfg.pinned_slave_fingerprints.len(), 1);
        assert!(cfg.validate("slave").is_ok());
    }

    #[test]
    fn test_master_validation_requires_auth_and_tls() {
        // Default config with replication_port > 0 fails without auth
        let mut cfg = HaConfig::default();
        assert!(cfg.validate("master").is_err());

        // Token provided, but no TLS and allow_insecure_ws is false -> fails
        cfg.slave_token = Some("secret".to_string());
        assert!(cfg.validate("master").is_err());

        // Explicit allow_insecure_ws with token -> passes
        cfg.allow_insecure_ws = true;
        assert!(cfg.validate("master").is_ok());

        // allow_insecure_ws true, but no auth -> fails
        cfg.slave_token = None;
        assert!(cfg.validate("master").is_err());

        // Pinned slave fingerprints satisfies auth
        cfg.pinned_slave_fingerprints = vec!["blake3:abc123".to_string()];
        assert!(cfg.validate("master").is_ok());

        // replication_port == 0 (disabled) always passes master validation
        let disabled_cfg = HaConfig {
            replication_port: 0,
            ..Default::default()
        };
        assert!(disabled_cfg.validate("master").is_ok());
    }
}
