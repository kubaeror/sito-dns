//! Configuration structures and validation for High Availability clustering.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::error::HaError;
use crate::parse_public_key;

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

fn default_promotion_backend() -> String {
    "witness".to_string()
}

fn default_lease_ttl_secs() -> u64 {
    30
}

fn default_renew_interval_secs() -> u64 {
    10
}

fn default_reconcile_window_secs() -> u64 {
    10
}

/// Witness endpoint parsed from `ha.promotion.witness.url`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessUrl {
    /// Host without IPv6 brackets, exactly as it appears in the URL authority.
    pub host: String,
    /// Explicit port or the ADR default `8954`.
    pub port: u16,
}

/// Parses a `https://host[:port]` witness base URL.
///
/// ADR-0010 requires TLS, a host and no userinfo, path, query or fragment. The
/// default witness port is `8954`. IPv6 literals must be bracketed, as in
/// `https://[2001:db8::2]:8954`.
pub fn parse_witness_url(input: &str) -> Result<WitnessUrl, HaError> {
    let invalid = |reason: &str| HaError::Validation {
        field: "ha.promotion.witness.url".to_string(),
        reason: reason.to_string(),
    };

    let trimmed = input.trim();
    let Some((scheme, authority)) = trimmed.split_once("://") else {
        return Err(invalid(
            "must be an absolute https:// URL with a host, for example https://witness.lan:8954",
        ));
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(invalid(
            "must use https://; plaintext http:// is not supported for the witness",
        ));
    }
    if authority.is_empty() {
        return Err(invalid("must include a host"));
    }
    if authority.contains('@') {
        return Err(invalid("must not contain userinfo"));
    }
    if authority.contains('/') || authority.contains('?') || authority.contains('#') {
        return Err(invalid(
            "must not contain a path, query or fragment; the client appends /v1/...",
        ));
    }

    let (host, port_text, bracketed) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return Err(invalid("has an unterminated IPv6 host literal"));
        };
        let port_text = if after.is_empty() {
            None
        } else if let Some(port) = after.strip_prefix(':') {
            Some(port)
        } else {
            return Err(invalid("has an unexpected suffix after the IPv6 host"));
        };
        (host, port_text, true)
    } else if authority.matches(':').count() > 1 {
        return Err(invalid(
            "must bracket IPv6 host literals, for example https://[2001:db8::2]:8954",
        ));
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if port.bytes().all(|byte| byte.is_ascii_digit()) && !host.is_empty() {
            (host, Some(port), false)
        } else {
            (authority, None, false)
        }
    } else {
        (authority, None, false)
    };

    if host.is_empty() {
        return Err(invalid("must include a host"));
    }
    if !bracketed && host.contains(':') {
        return Err(invalid("has an invalid port or an unbracketed host"));
    }
    if host.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(invalid("host must not contain whitespace"));
    }

    let port = match port_text {
        None => 8954,
        Some(text) => {
            let port = text
                .parse::<u16>()
                .map_err(|_| invalid("has an invalid port"))?;
            if port == 0 {
                return Err(invalid("port must be greater than zero"));
            }
            port
        }
    };

    Ok(WitnessUrl {
        host: host.to_string(),
        port,
    })
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), HaError> {
    let valid_len = (1..=64).contains(&value.len());
    let valid_chars = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid_len && valid_chars {
        Ok(())
    } else {
        Err(HaError::Validation {
            field: field.to_string(),
            reason: format!("{field} must be 1-64 characters from [A-Za-z0-9._-]"),
        })
    }
}

/// Witness client configuration `[ha.promotion.witness]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WitnessClientConfig {
    /// Base URL of the witness, for example `https://witness.lan:8954`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// CA bundle used to verify the witness certificate (absolute path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<PathBuf>,

    /// TLS server name; defaults to the URL host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,

    /// Optional BLAKE3 pin of the DER witness certificate, in addition to CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,

    /// File containing the shared bearer token (absolute path, mode 0600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,
}

impl WitnessClientConfig {
    /// Returns the configured fingerprint in canonical lowercase hex form.
    ///
    /// Both `blake3:<hex>` and bare `<hex>` are accepted, matching the ADR's
    /// hash normalization rule.
    pub fn normalized_fingerprint(&self) -> Result<Option<String>, HaError> {
        self.fingerprint
            .as_deref()
            .map(|value| {
                crate::hash::normalize_blake3_hash(value).map_err(|error| HaError::Validation {
                    field: "ha.promotion.witness.fingerprint".to_string(),
                    reason: format!("must be blake3:<64 hex> (the DER certificate pin): {error}"),
                })
            })
            .transpose()
    }
}

/// Automatic promotion configuration `[ha.promotion]`.
///
/// The feature is opt-in and inert unless [`Self::enabled`] is true. Bounds are
/// only validated when enabled; `backend` is validated always so a typo cannot
/// be ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionConfig {
    /// Master gate. When false, every other field is inert.
    #[serde(default)]
    pub enabled: bool,

    /// This node may try to acquire the lease. Exactly one slave per cluster.
    #[serde(default)]
    pub candidate: bool,

    /// Stable cluster identifier shared with the witness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<String>,

    /// Stable per-node identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,

    /// Lease backend. Only `"witness"` is supported in 2.0.
    #[serde(default = "default_promotion_backend")]
    pub backend: String,

    /// Witness-side lease lifetime in seconds.
    #[serde(default = "default_lease_ttl_secs")]
    pub lease_ttl_secs: u64,

    /// Lease renewal period in seconds.
    #[serde(default = "default_renew_interval_secs")]
    pub renew_interval_secs: u64,

    /// Candidate wait after master loss. Omitted means
    /// `max(45, 3 * ha.ping_interval_secs)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_timeout_secs: Option<u64>,

    /// Require a local operator confirmation before acquiring the lease.
    #[serde(default)]
    pub require_manual_confirmation: bool,

    /// Window for slaves to report their applied term/version/after quiesce.
    #[serde(default = "default_reconcile_window_secs")]
    pub reconcile_window_secs: u64,

    /// Witness TLS/auth settings.
    #[serde(default)]
    pub witness: WitnessClientConfig,
}

impl Default for PromotionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            candidate: false,
            cluster_id: None,
            node_id: None,
            backend: default_promotion_backend(),
            lease_ttl_secs: default_lease_ttl_secs(),
            renew_interval_secs: default_renew_interval_secs(),
            heartbeat_timeout_secs: None,
            require_manual_confirmation: false,
            reconcile_window_secs: default_reconcile_window_secs(),
            witness: WitnessClientConfig::default(),
        }
    }
}

impl PromotionConfig {
    /// Effective candidate wait: the explicit value or `max(45, 3 * ping)`.
    #[must_use]
    pub fn effective_heartbeat_timeout_secs(&self, ping_interval_secs: u64) -> u64 {
        self.heartbeat_timeout_secs
            .unwrap_or_else(|| ping_interval_secs.saturating_mul(3).max(45))
    }

    /// Validates the promotion section for the configured node role.
    ///
    /// Only [`Self::backend`] is checked when `enabled = false`, so an existing
    /// HA configuration loads unchanged and a disabled `candidate = true` on a
    /// master remains inert (the operator-facing warning is emitted by the
    /// runtime, not here).
    pub fn validate(&self, role: &str, ping_interval_secs: u64) -> Result<(), HaError> {
        if self.backend != "witness" {
            return Err(HaError::Validation {
                field: "ha.promotion.backend".to_string(),
                reason: format!(
                    "unsupported_lease_backend: '{}' is not supported; only \"witness\" is available in 2.0",
                    self.backend
                ),
            });
        }

        if !self.enabled {
            return Ok(());
        }

        if self.candidate && role != "slave" {
            return Err(HaError::Validation {
                field: "ha.promotion.candidate".to_string(),
                reason: "candidate = true requires server.role = \"slave\" when ha.promotion.enabled = true"
                    .to_string(),
            });
        }

        let cluster_id = self
            .cluster_id
            .as_deref()
            .ok_or_else(|| HaError::Validation {
                field: "ha.promotion.cluster_id".to_string(),
                reason: "cluster_id is required when ha.promotion.enabled = true".to_string(),
            })?;
        validate_identifier("ha.promotion.cluster_id", cluster_id)?;

        let node_id = self.node_id.as_deref().ok_or_else(|| HaError::Validation {
            field: "ha.promotion.node_id".to_string(),
            reason: "node_id is required when ha.promotion.enabled = true".to_string(),
        })?;
        validate_identifier("ha.promotion.node_id", node_id)?;

        if !(5..=300).contains(&self.lease_ttl_secs) {
            return Err(HaError::Validation {
                field: "ha.promotion.lease_ttl_secs".to_string(),
                reason: "lease_ttl_secs must be between 5 and 300".to_string(),
            });
        }
        if self.renew_interval_secs == 0 || self.renew_interval_secs > self.lease_ttl_secs / 3 {
            return Err(HaError::Validation {
                field: "ha.promotion.renew_interval_secs".to_string(),
                reason: format!(
                    "renew_interval_secs must be between 1 and lease_ttl_secs / 3 ({})",
                    self.lease_ttl_secs / 3
                ),
            });
        }
        if self.lease_ttl_secs < self.renew_interval_secs.saturating_mul(3) {
            return Err(HaError::Validation {
                field: "ha.promotion.lease_ttl_secs".to_string(),
                reason: "lease_ttl_secs must be at least 3 * renew_interval_secs".to_string(),
            });
        }
        if self.heartbeat_timeout_secs.is_some_and(|heartbeat| {
            heartbeat == 0 || heartbeat < ping_interval_secs.saturating_mul(3)
        }) {
            return Err(HaError::Validation {
                field: "ha.promotion.heartbeat_timeout_secs".to_string(),
                reason: format!(
                    "heartbeat_timeout_secs must be at least 1 and at least 3 * ha.ping_interval_secs ({})",
                    ping_interval_secs.saturating_mul(3)
                ),
            });
        }
        if !(1..=60).contains(&self.reconcile_window_secs) {
            return Err(HaError::Validation {
                field: "ha.promotion.reconcile_window_secs".to_string(),
                reason: "reconcile_window_secs must be between 1 and 60".to_string(),
            });
        }

        let url = self
            .witness
            .url
            .as_deref()
            .ok_or_else(|| HaError::Validation {
                field: "ha.promotion.witness.url".to_string(),
                reason: "witness.url is required when ha.promotion.enabled = true".to_string(),
            })?;
        parse_witness_url(url)?;

        let ca = self
            .witness
            .ca
            .as_ref()
            .ok_or_else(|| HaError::Validation {
                field: "ha.promotion.witness.ca".to_string(),
                reason: "witness.ca is required when ha.promotion.enabled = true".to_string(),
            })?;
        if !ca.is_absolute() {
            return Err(HaError::Validation {
                field: "ha.promotion.witness.ca".to_string(),
                reason: "witness.ca must be an absolute path".to_string(),
            });
        }

        let token_file = self
            .witness
            .token_file
            .as_ref()
            .ok_or_else(|| HaError::Validation {
                field: "ha.promotion.witness.token_file".to_string(),
                reason: "witness.token_file is required when ha.promotion.enabled = true"
                    .to_string(),
            })?;
        if !token_file.is_absolute() {
            return Err(HaError::Validation {
                field: "ha.promotion.witness.token_file".to_string(),
                reason: "witness.token_file must be an absolute path".to_string(),
            });
        }

        if let Some(server_name) = self.witness.server_name.as_deref() {
            rustls_pki_types::ServerName::try_from(server_name.to_string()).map_err(|error| {
                HaError::Validation {
                    field: "ha.promotion.witness.server_name".to_string(),
                    reason: format!(
                        "witness.server_name '{server_name}' is not a valid TLS server name: {error}"
                    ),
                }
            })?;
        }

        self.witness.normalized_fingerprint()?;

        Ok(())
    }
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
    ///
    /// This only selects the explicit no-verification mode when neither
    /// `master_fingerprint` nor `ca` is configured. A configured `ca` is always
    /// enforced (chain/SAN/validity), and a configured pin is always enforced.
    #[serde(default)]
    pub allow_unpinned_tls: bool,

    /// Allow unencrypted plaintext WebSocket connections (ws://; insecure; default: false).
    ///
    /// This is an explicit opt-in with no silent fallback: a master without
    /// `cert`/`key` refuses to serve and a slave refuses a `ws://`
    /// `master_url` unless this is `true`. Plaintext requires a non-empty
    /// `slave_token` and is rejected when TLS-only material
    /// (`pinned_slave_fingerprints`, `ca`, `master_fingerprint`) is also
    /// configured, because none of it can be enforced without TLS.
    #[serde(default)]
    pub allow_insecure_ws: bool,

    /// Require at least one connected slave synced to the current configuration
    /// version before master readiness reports ready (default: false).
    ///
    /// Only gates the master role; slave readiness is unaffected.
    #[serde(default)]
    pub require_slaves: bool,

    /// Require every connected slave to be synced to the current configuration
    /// version before master readiness reports ready (default: false).
    ///
    /// This is stronger than [`Self::require_slaves`]: zero connected slaves is
    /// also not ready. Only gates the master role.
    #[serde(default)]
    pub require_all_slaves: bool,

    /// Interval in seconds for sending periodic statistics reports from slave to master (default: 30s).
    #[serde(default = "default_stats_interval_secs")]
    pub stats_interval_secs: u64,

    /// Interval in seconds for WebSocket heartbeat pings (default: 15s).
    #[serde(default = "default_ping_interval_secs")]
    pub ping_interval_secs: u64,

    /// Opt-in automatic promotion with a lease witness (default: disabled).
    #[serde(default)]
    pub promotion: PromotionConfig,
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
            require_slaves: false,
            require_all_slaves: false,
            stats_interval_secs: default_stats_interval_secs(),
            ping_interval_secs: default_ping_interval_secs(),
            promotion: PromotionConfig::default(),
        }
    }
}

impl HaConfig {
    /// Whether the node's role depends on a working HA replication path.
    ///
    /// Used by the healthcheck to fail closed only when replication is
    /// actually part of the deployment:
    /// - a master with `replication_port = 0` has explicitly disabled HA;
    /// - a slave with no `[ha]` section is not enrolled in a cluster;
    /// - any slave with an `[ha]` section is expected to replicate (a missing
    ///   `master_url` is then a misconfiguration, not a healthy idle node).
    #[must_use]
    pub fn readiness_required(role: &str, ha: Option<&toml::Value>) -> bool {
        let Some(ha) = ha else {
            return false;
        };
        match role {
            "master" => ha
                .get("replication_port")
                .and_then(toml::Value::as_integer)
                .is_none_or(|port| port > 0),
            "slave" => true,
            _ => false,
        }
    }

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

                let has_cert = self.cert.is_some();
                let has_key = self.key.is_some();
                let has_ca = self.ca.is_some();

                if (has_cert && !has_key) || (!has_cert && has_key) {
                    return Err(HaError::Validation {
                        field: "key".to_string(),
                        reason: "Both cert and key must be provided for TLS replication"
                            .to_string(),
                    });
                }

                if has_cert && has_key {
                    // TLS without either pinned client fingerprints or a client
                    // CA rejects every handshake at runtime, so fail validation
                    // instead of booting an unreachable master.
                    if !has_pins && !has_ca {
                        return Err(HaError::Validation {
                            field: "pinned_slave_fingerprints".to_string(),
                            reason: "TLS replication requires pinned_slave_fingerprints or ca; empty pins reject every client certificate".to_string(),
                        });
                    }
                } else {
                    if !self.allow_insecure_ws {
                        return Err(HaError::Validation {
                            field: "cert".to_string(),
                            reason: "Master replication requires TLS certificate and key unless allow_insecure_ws = true".to_string(),
                        });
                    }
                    // Certificate pins and a verification CA only exist in the
                    // TLS handshake. Accepting plaintext while either is
                    // configured would silently stop enforcing a control the
                    // operator asked for, so the combination is rejected
                    // instead of downgraded.
                    if has_pins {
                        return Err(HaError::Validation {
                            field: "pinned_slave_fingerprints".to_string(),
                            reason: "pinned_slave_fingerprints cannot be enforced over plaintext replication; configure cert/key or remove the pins".to_string(),
                        });
                    }
                    if has_ca {
                        return Err(HaError::Validation {
                            field: "ca".to_string(),
                            reason: "ha.ca requires TLS (cert/key); it cannot be used with plaintext (allow_insecure_ws) replication".to_string(),
                        });
                    }
                    // Certificate pins cannot be enforced without TLS, so
                    // plaintext replication must use a pre-shared token.
                    if !has_token {
                        return Err(HaError::Validation {
                            field: "slave_token".to_string(),
                            reason: "Plaintext (allow_insecure_ws) replication requires a non-empty slave_token".to_string(),
                        });
                    }
                }
            }
        } else if role == "slave" {
            if self.replication_port == 0 {
                return Err(HaError::Validation {
                    field: "replication_port".to_string(),
                    reason: "Replication port must be greater than 0".to_string(),
                });
            }
            if self.master_pubkey.is_none() {
                return Err(HaError::Validation {
                    field: "master_pubkey".to_string(),
                    reason: "Slave replication requires master_pubkey to verify signed configuration pushes".to_string(),
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
                if url.starts_with("ws://") && self.master_fingerprint.is_some() {
                    return Err(HaError::Validation {
                        field: "master_fingerprint".to_string(),
                        reason: "master_fingerprint cannot be enforced over plaintext ws:// replication; use wss:// or remove the pin".to_string(),
                    });
                }
                if url.starts_with("ws://") && self.ca.is_some() {
                    return Err(HaError::Validation {
                        field: "ca".to_string(),
                        reason: "ha.ca cannot be used with plaintext ws:// replication; use wss:// or remove ca".to_string(),
                    });
                }
                if url.starts_with("wss://")
                    && self.master_fingerprint.is_none()
                    && self.ca.is_none()
                    && !self.allow_unpinned_tls
                {
                    return Err(HaError::Validation {
                        field: "master_fingerprint".to_string(),
                        reason: "WSS replication requires master_fingerprint (pin) or ca (chain validation); set allow_unpinned_tls = true only to explicitly disable TLS verification".to_string(),
                    });
                }
            }
        }

        self.promotion.validate(role, self.ping_interval_secs)?;

        Ok(())
    }

    /// Returns operator-facing warnings for the explicit insecure plaintext
    /// WebSocket opt-in (`ha.allow_insecure_ws = true`).
    ///
    /// The policy itself is enforced by [`Self::validate`] and again by the
    /// master listener and slave session code; these warnings exist so
    /// `check-config` and startup can report a risk that is valid but
    /// easy to miss. They never contain secrets.
    ///
    /// A node only "uses" plaintext when its replication path would actually
    /// omit TLS: a master whose listener has no certificate/key pair, or a
    /// slave whose `master_url` is `ws://`. On every other node the flag is
    /// inert (TLS is used) and the warning says so, because a leftover
    /// opt-in must not look like a downgrade the operator is relying on.
    #[must_use]
    pub fn insecure_ws_warnings(&self, role: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        if !self.allow_insecure_ws {
            return warnings;
        }

        let plaintext_active = match role {
            "master" => self.replication_port > 0 && !(self.cert.is_some() && self.key.is_some()),
            "slave" => self
                .master_url
                .as_deref()
                .is_some_and(|url| url.starts_with("ws://")),
            _ => false,
        };

        if plaintext_active {
            warnings.push(
                "ha.allow_insecure_ws = true: HA replication is running over plaintext ws:// \
                 with no TLS. Configuration bundles, client definitions and the slave token \
                 are visible on the wire. Use wss:// unless both nodes are on a trusted, \
                 private or loopback link, and never across an untrusted network."
                    .to_string(),
            );
            if role == "slave" && self.master_fingerprint.is_some() {
                warnings.push(
                    "ha.master_fingerprint is ignored over plaintext ws://; remove the pin or \
                     switch master_url to wss://"
                        .to_string(),
                );
            }
            if self.allow_unpinned_tls {
                warnings.push(
                    "ha.allow_unpinned_tls has no effect while replication is plaintext; \
                     remove the flag or switch to wss://"
                        .to_string(),
                );
            }
            if self.promotion.enabled {
                warnings.push(
                    "ha.promotion.enabled = true reuses this replication transport: a promoted \
                     master inherits ha.allow_insecure_ws = true and will serve plaintext too"
                        .to_string(),
                );
            }
        } else {
            warnings.push(
                "ha.allow_insecure_ws = true is inert on this node because its replication path \
                 uses TLS (or has no master listener); remove it unless it is a deliberate \
                 leftover from a plaintext deployment"
                    .to_string(),
            );
        }

        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readiness_required_only_when_replication_is_expected() {
        assert!(!HaConfig::readiness_required("master", None));
        let enabled: toml::Value = toml::from_str("replication_port = 8953").unwrap();
        assert!(HaConfig::readiness_required("master", Some(&enabled)));
        let disabled: toml::Value = toml::from_str("replication_port = 0").unwrap();
        assert!(!HaConfig::readiness_required("master", Some(&disabled)));

        assert!(!HaConfig::readiness_required("slave", None));
        let slave: toml::Value = toml::from_str("master_url = \"wss://127.0.0.1:8953\"").unwrap();
        assert!(HaConfig::readiness_required("slave", Some(&slave)));
        // An [ha] section on a slave without master_url is a misconfiguration
        // and must still gate health instead of looking idle.
        let incomplete: toml::Value = toml::from_str("replication_port = 8953").unwrap();
        assert!(HaConfig::readiness_required("slave", Some(&incomplete)));
    }

    #[test]
    fn test_ha_config_defaults_and_parsing() {
        let toml_str = r#"
replication_port = 8953
master_url = "wss://127.0.0.1:8953"
master_fingerprint = "blake3:abcdef0123456789"
master_pubkey = "0000000000000000000000000000000000000000000000000000000000000000"
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
    fn test_slave_readiness_requirements_default_false_and_parse() {
        let defaults = HaConfig::default();
        assert!(!defaults.require_slaves);
        assert!(!defaults.require_all_slaves);

        // Absent keys preserve the pre-upgrade behavior.
        let absent: toml::Value = toml::from_str("replication_port = 8953").unwrap();
        let absent = HaConfig::from_toml_value(&absent).unwrap();
        assert!(!absent.require_slaves);
        assert!(!absent.require_all_slaves);

        let explicit: toml::Value = toml::from_str(
            "replication_port = 8953\nrequire_slaves = true\nrequire_all_slaves = true",
        )
        .unwrap();
        let explicit = HaConfig::from_toml_value(&explicit).unwrap();
        assert!(explicit.require_slaves);
        assert!(explicit.require_all_slaves);
    }

    #[test]
    fn test_slave_readiness_requirements_do_not_affect_slave_validation() {
        // The fields only gate master readiness; a slave with both set must
        // still validate (and start) normally.
        let cfg = HaConfig {
            master_url: Some("wss://127.0.0.1:8953".to_string()),
            master_fingerprint: Some("blake3:abcdef0123456789".to_string()),
            master_pubkey: Some("00".repeat(32)),
            require_slaves: true,
            require_all_slaves: true,
            ..Default::default()
        };
        assert!(cfg.validate("slave").is_ok());
    }

    #[test]
    fn test_wss_trust_policy_accepts_pin_ca_or_explicit_unpinned() {
        let base = HaConfig {
            master_url: Some("wss://127.0.0.1:8953".to_string()),
            master_pubkey: Some("00".repeat(32)),
            ..Default::default()
        };

        // No pin, no CA, no explicit opt-out: rejected.
        assert!(base.validate("slave").is_err());

        // A CA alone is a valid trust anchor (chain/SAN validation).
        let ca_only = HaConfig {
            ca: Some(std::path::PathBuf::from("/etc/sito/ca.crt")),
            ..base.clone()
        };
        assert!(ca_only.validate("slave").is_ok());

        // Explicit no-verification remains available without pin/CA.
        let unpinned = HaConfig {
            allow_unpinned_tls: true,
            ..base
        };
        assert!(unpinned.validate("slave").is_ok());
    }

    #[test]
    fn test_slave_validation_requires_master_pubkey() {
        let mut cfg = HaConfig {
            master_url: Some("wss://127.0.0.1:8953".to_string()),
            master_fingerprint: Some("blake3:abcdef0123456789".to_string()),
            ..Default::default()
        };
        assert!(
            cfg.validate("slave").is_err(),
            "slave without master_pubkey must be rejected (pushes cannot be verified)"
        );
        cfg.master_pubkey = Some("00".repeat(32));
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

        // Pins do not authenticate plaintext replication (no TLS to pin).
        cfg.pinned_slave_fingerprints = vec!["blake3:abc123".to_string()];
        assert!(cfg.validate("master").is_err());

        // Pins are sufficient auth when TLS is configured.
        cfg.cert = Some(std::path::PathBuf::from("/etc/sito/certs/master.crt"));
        cfg.key = Some(std::path::PathBuf::from("/etc/sito/certs/master.key"));
        assert!(cfg.validate("master").is_ok());

        // replication_port == 0 (disabled) always passes master validation
        let disabled_cfg = HaConfig {
            replication_port: 0,
            ..Default::default()
        };
        assert!(disabled_cfg.validate("master").is_ok());
    }

    #[test]
    fn test_plaintext_master_rejects_tls_only_material() {
        let base = HaConfig {
            allow_insecure_ws: true,
            slave_token: Some("secret".to_string()),
            ..Default::default()
        };
        assert!(base.validate("master").is_ok());

        // Pins are enforced only inside the TLS handshake; a plaintext
        // listener must not silently stop enforcing them.
        let pinned = HaConfig {
            pinned_slave_fingerprints: vec!["blake3:abc123".to_string()],
            ..base.clone()
        };
        let err = pinned
            .validate("master")
            .expect_err("pins with plaintext must be rejected");
        assert!(err.to_string().contains("pinned_slave_fingerprints"));

        // The same applies to a verification CA.
        let with_ca = HaConfig {
            ca: Some(PathBuf::from("/etc/sito/ca.crt")),
            ..base
        };
        let err = with_ca
            .validate("master")
            .expect_err("ca with plaintext must be rejected");
        assert!(err.to_string().contains("ca"));
    }

    #[test]
    fn test_plaintext_slave_rejects_pin_or_ca() {
        let base = HaConfig {
            master_url: Some("ws://127.0.0.1:8953".to_string()),
            master_pubkey: Some("00".repeat(32)),
            allow_insecure_ws: true,
            ..Default::default()
        };
        assert!(base.validate("slave").is_ok());

        let pinned = HaConfig {
            master_fingerprint: Some("blake3:abcdef0123456789".to_string()),
            ..base.clone()
        };
        let err = pinned
            .validate("slave")
            .expect_err("a pin cannot be enforced over ws://");
        assert!(err.to_string().contains("master_fingerprint"));

        let with_ca = HaConfig {
            ca: Some(PathBuf::from("/etc/sito/ca.crt")),
            ..base
        };
        let err = with_ca
            .validate("slave")
            .expect_err("a CA cannot be used over ws://");
        assert!(err.to_string().contains("ca"));
    }

    #[test]
    fn test_insecure_ws_warnings_report_active_and_inert_flag() {
        // Default is quiet.
        let warnings = HaConfig::default().insecure_ws_warnings("master");
        assert_eq!(warnings, Vec::<String>::new());

        // An explicit plaintext master warns about the wire exposure.
        let plaintext_master = HaConfig {
            allow_insecure_ws: true,
            slave_token: Some("secret".to_string()),
            ..Default::default()
        };
        let warnings = plaintext_master.insecure_ws_warnings("master");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("plaintext ws://"), "{warnings:?}");

        // With TLS material configured, the listener serves TLS: the flag is
        // inert and the warning says so instead of claiming a downgrade.
        let tls_master = HaConfig {
            cert: Some(PathBuf::from("/etc/sito/master.crt")),
            key: Some(PathBuf::from("/etc/sito/master.key")),
            pinned_slave_fingerprints: vec!["blake3:abc123".to_string()],
            ..plaintext_master.clone()
        };
        let warnings = tls_master.insecure_ws_warnings("master");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("inert"), "{warnings:?}");

        // A plaintext slave with promotion enabled warns that the promoted
        // master inherits the same policy.
        let plaintext_slave = HaConfig {
            master_url: Some("ws://127.0.0.1:8953".to_string()),
            master_pubkey: Some("00".repeat(32)),
            promotion: PromotionConfig {
                enabled: true,
                ..Default::default()
            },
            ..plaintext_master
        };
        let warnings = plaintext_slave.insecure_ws_warnings("slave");
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(
            warnings.iter().any(|warning| warning.contains("promoted")),
            "{warnings:?}"
        );

        // The warning text must never echo a token.
        let rendered = warnings.join("\n");
        assert!(!rendered.contains("secret"), "{rendered}");
    }

    fn valid_promotion() -> PromotionConfig {
        PromotionConfig {
            enabled: true,
            candidate: true,
            cluster_id: Some("home-dns".to_string()),
            node_id: Some("sito-node-a".to_string()),
            witness: WitnessClientConfig {
                url: Some("https://witness.lan:8954".to_string()),
                ca: Some(PathBuf::from("/etc/sito/certs/witness-ca.crt")),
                server_name: None,
                fingerprint: None,
                token_file: Some(PathBuf::from("/etc/sito/witness.token")),
            },
            ..Default::default()
        }
    }

    #[test]
    fn promotion_defaults_are_opt_in_and_inert() {
        let cfg = HaConfig::default();
        let promotion = &cfg.promotion;
        assert!(!promotion.enabled);
        assert!(!promotion.candidate);
        assert_eq!(promotion.cluster_id, None);
        assert_eq!(promotion.node_id, None);
        assert_eq!(promotion.backend, "witness");
        assert_eq!(promotion.lease_ttl_secs, 30);
        assert_eq!(promotion.renew_interval_secs, 10);
        assert_eq!(promotion.heartbeat_timeout_secs, None);
        assert!(!promotion.require_manual_confirmation);
        assert_eq!(promotion.reconcile_window_secs, 10);
        assert_eq!(promotion.witness.url, None);
        assert_eq!(promotion.witness.ca, None);
        assert_eq!(promotion.witness.server_name, None);
        assert_eq!(promotion.witness.fingerprint, None);
        assert_eq!(promotion.witness.token_file, None);

        // A disabled section is inert: no bounds are validated.
        let disabled = HaConfig {
            replication_port: 0,
            ping_interval_secs: 30,
            ..Default::default()
        };
        assert!(disabled.validate("master").is_ok());
    }

    #[test]
    fn promotion_accepts_the_full_adr_document() {
        let cfg = valid_promotion();
        cfg.validate("slave", 15).expect("full promotion config");

        let toml_value: toml::Value = toml::from_str(
            r#"
enabled = true
candidate = true
cluster_id = "home-dns"
node_id = "sito-node-a"
backend = "witness"
lease_ttl_secs = 30
renew_interval_secs = 10
heartbeat_timeout_secs = 90
require_manual_confirmation = false
reconcile_window_secs = 10

[witness]
url = "https://witness.lan:8954"
ca = "/etc/sito/certs/witness-ca.crt"
server_name = "witness.lan"
fingerprint = "blake3:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
token_file = "/etc/sito/witness.token"
"#,
        )
        .unwrap();
        let parsed = PromotionConfig::deserialize(toml_value).unwrap();
        assert_eq!(
            parsed.witness.normalized_fingerprint().unwrap().as_deref(),
            Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        );
        parsed.validate("slave", 15).unwrap();
    }

    #[test]
    fn heartbeat_default_derives_from_ping_only_when_enabled() {
        let mut cfg = valid_promotion();
        assert_eq!(cfg.effective_heartbeat_timeout_secs(15), 45);
        assert_eq!(cfg.effective_heartbeat_timeout_secs(30), 90);

        // An explicit 45 is valid with ping 15 and rejected with ping 30.
        cfg.heartbeat_timeout_secs = Some(45);
        cfg.validate("slave", 15).unwrap();
        let err = cfg.validate("slave", 30).unwrap_err();
        assert!(err.to_string().contains("heartbeat_timeout_secs"), "{err}");

        // Large ping values have no unsatisfiable upper bound.
        let large = PromotionConfig {
            heartbeat_timeout_secs: Some(10_000),
            ..valid_promotion()
        };
        large.validate("slave", 1201).unwrap();
    }

    #[test]
    fn enabled_promotion_requires_every_adr_field() {
        type Mutation = fn(&mut PromotionConfig);
        let cases: [(&str, Mutation); 5] = [
            ("cluster_id", |cfg: &mut PromotionConfig| {
                cfg.cluster_id = None;
            }),
            ("node_id", |cfg: &mut PromotionConfig| {
                cfg.node_id = None;
            }),
            ("witness.url", |cfg: &mut PromotionConfig| {
                cfg.witness.url = None;
            }),
            ("witness.ca", |cfg: &mut PromotionConfig| {
                cfg.witness.ca = None;
            }),
            ("witness.token_file", |cfg: &mut PromotionConfig| {
                cfg.witness.token_file = None;
            }),
        ];
        for (field, mutate) in cases {
            let mut cfg = valid_promotion();
            mutate(&mut cfg);
            let err = cfg.validate("slave", 15).unwrap_err();
            assert!(
                err.to_string().contains(field),
                "missing {field} must name the key, got: {err}"
            );
        }
    }

    #[test]
    fn backend_is_validated_even_when_disabled() {
        let mut cfg = PromotionConfig {
            backend: "etcd".to_string(),
            ..Default::default()
        };
        let err = cfg.validate("master", 15).unwrap_err();
        assert!(
            err.to_string().contains("unsupported_lease_backend"),
            "{err}"
        );
        assert!(err.to_string().contains("backend"), "{err}");

        cfg.backend = "witness".to_string();
        cfg.validate("master", 15).unwrap();
    }

    #[test]
    fn witness_url_requires_https_host_and_no_userinfo_or_path() {
        for url in [
            "http://witness.lan:8954",
            "https://user:pass@witness.lan:8954",
            "https://witness.lan:8954/v1",
            "https://witness.lan:8954/",
            "https://witness.lan?x=1",
            "https://witness.lan#frag",
            "https://",
            "https://:8954",
            "https://witness.lan:not-a-port",
        ] {
            let mut cfg = valid_promotion();
            cfg.witness.url = Some(url.to_string());
            let err = cfg.validate("slave", 15).unwrap_err();
            assert!(err.to_string().contains("witness.url"), "{url}: {err}");
        }

        parse_witness_url("https://witness.lan").unwrap();
        let endpoint = parse_witness_url("https://[2001:db8::2]:9954").unwrap();
        assert_eq!(endpoint.host, "2001:db8::2");
        assert_eq!(endpoint.port, 9954);
        assert_eq!(parse_witness_url("https://witness.lan").unwrap().port, 8954);
    }

    #[test]
    fn witness_paths_must_be_absolute_and_fingerprints_valid() {
        let mut relative_ca = valid_promotion();
        relative_ca.witness.ca = Some(PathBuf::from("certs/witness-ca.crt"));
        assert!(
            relative_ca
                .validate("slave", 15)
                .unwrap_err()
                .to_string()
                .contains("witness.ca")
        );

        let mut relative_token = valid_promotion();
        relative_token.witness.token_file = Some(PathBuf::from("witness.token"));
        assert!(
            relative_token
                .validate("slave", 15)
                .unwrap_err()
                .to_string()
                .contains("witness.token_file")
        );

        for server_name in ["  ", "bad name", "host:8954", "a/b"] {
            let mut invalid_name = valid_promotion();
            invalid_name.witness.server_name = Some(server_name.to_string());
            assert!(
                invalid_name
                    .validate("slave", 15)
                    .unwrap_err()
                    .to_string()
                    .contains("server_name"),
                "{server_name:?} must be rejected"
            );
        }

        for fingerprint in ["blake3:abc", "1234", "blake3:zz"] {
            let mut cfg = valid_promotion();
            cfg.witness.fingerprint = Some(fingerprint.to_string());
            let err = cfg.validate("slave", 15).unwrap_err();
            assert!(
                err.to_string().contains("fingerprint"),
                "{fingerprint}: {err}"
            );
        }

        // Bare lowercase and prefixed uppercase are both accepted.
        let mut cfg = valid_promotion();
        cfg.witness.fingerprint = Some(format!("BLAKE3:{}", "AB".repeat(32)));
        assert_eq!(
            cfg.validate("slave", 15)
                .and_then(|()| cfg.witness.normalized_fingerprint())
                .unwrap()
                .as_deref(),
            Some("ab".repeat(32).as_str())
        );
    }

    #[test]
    fn candidate_requires_slave_role_only_when_enabled() {
        let mut cfg = valid_promotion();
        let err = cfg.validate("master", 15).unwrap_err();
        assert!(err.to_string().contains("candidate"), "{err}");

        cfg.enabled = false;
        cfg.validate("master", 15).unwrap();
    }

    #[test]
    fn intervals_are_bounded_and_consistent() {
        let mut ttl = valid_promotion();
        ttl.lease_ttl_secs = 4;
        assert!(
            ttl.validate("slave", 15)
                .unwrap_err()
                .to_string()
                .contains("lease_ttl_secs")
        );
        ttl.lease_ttl_secs = 301;
        assert!(
            ttl.validate("slave", 15)
                .unwrap_err()
                .to_string()
                .contains("lease_ttl_secs")
        );

        let mut renew = valid_promotion();
        renew.renew_interval_secs = 0;
        assert!(
            renew
                .validate("slave", 15)
                .unwrap_err()
                .to_string()
                .contains("renew_interval_secs")
        );
        renew.renew_interval_secs = 11;
        assert!(
            renew
                .validate("slave", 15)
                .unwrap_err()
                .to_string()
                .contains("renew_interval_secs")
        );

        let mut reconcile = valid_promotion();
        reconcile.reconcile_window_secs = 0;
        assert!(
            reconcile
                .validate("slave", 15)
                .unwrap_err()
                .to_string()
                .contains("reconcile_window_secs")
        );
        reconcile.reconcile_window_secs = 61;
        assert!(
            reconcile
                .validate("slave", 15)
                .unwrap_err()
                .to_string()
                .contains("reconcile_window_secs")
        );
    }

    #[test]
    fn identifiers_are_bounded_and_restricted() {
        let mut cfg = valid_promotion();
        cfg.cluster_id = Some(String::new());
        assert!(
            cfg.validate("slave", 15)
                .unwrap_err()
                .to_string()
                .contains("cluster_id")
        );
        cfg.cluster_id = Some("x".repeat(65));
        assert!(
            cfg.validate("slave", 15)
                .unwrap_err()
                .to_string()
                .contains("cluster_id")
        );
        cfg.cluster_id = Some("bad cluster".to_string());
        assert!(
            cfg.validate("slave", 15)
                .unwrap_err()
                .to_string()
                .contains("cluster_id")
        );
    }
}
