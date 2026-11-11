//! MikroTik RouterOS DHCP lease configuration (M4.5).
//!
//! This crate keeps only the plain configuration/data types so the default
//! build does not link the RouterOS HTTP stack. The optional `sito-routeros`
//! crate implements the REST client and the background lease-sync task behind
//! the `routeros` feature.

use serde::{Deserialize, Serialize};

/// Configuration for MikroTik RouterOS integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterOsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Base URL of the RouterOS REST API.
    ///
    /// Only an `https://` URL with certificate verification enabled
    /// (`allow_invalid_certs = false`) authenticates the peer; a plaintext
    /// `http://` URL is allowed as a lab opt-out but its leases are
    /// display-only and never grant client identity.
    #[serde(default = "default_url")]
    pub url: String,
    pub token_env: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub password_env: Option<String>,
    #[serde(default = "default_interval_s")]
    pub interval_s: u64,
    /// Accept invalid/untrusted TLS certificates from the RouterOS API
    /// (default false; enable only for self-signed router certificates).
    #[serde(default)]
    pub allow_invalid_certs: bool,
}

fn default_url() -> String {
    "https://192.168.1.1".to_string()
}

fn default_interval_s() -> u64 {
    300
}

impl Default for RouterOsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_url(),
            token_env: Some("MIKROTIK_API_TOKEN".to_string()),
            username: None,
            password: None,
            password_env: None,
            interval_s: default_interval_s(),
            allow_invalid_certs: false,
        }
    }
}
