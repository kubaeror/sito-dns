//! Built-in witness lease server for opt-in HA automatic promotion.
//!
//! The witness is a separate `sito ha lease-server` process that serializes
//! lease acquisition for an HA cluster over TLS and a shared bearer token. It
//! stores one durable record and implements the compare-and-swap rules in
//! [ADR-0010](../../../../docs/adr/0010-ha-automatic-promotion.md). This module
//! contains the witness backend only; the client promotion loop lives in
//! `sito-ha`'s promotion client (C3b2).
//!
//! Safety properties:
//! - one process holds `state_dir/lease.lock` for its lifetime;
//! - every operation runs under one mutex and persists with
//!   temp-file + `fsync` + `rename` + directory `fsync` before responding;
//! - `lease.json` is never silently reset: a missing/corrupt record with an
//!   `initialized` sentinel refuses startup;
//! - term/version/hash/expiry rules are enforced server-side.

pub mod admin;
pub mod clock;
pub mod record;
pub mod server;
pub mod store;

#[cfg(test)]
mod tests;

pub use admin::{
    LeaseAdminOutcome, lease_admin_set, lease_admin_set_term_only,
    lease_admin_set_term_only_with_clock, lease_admin_set_with_clock,
};
pub use clock::{Clock, ManualClock, SystemClock};
pub use record::{AcquireRequest, LEASE_PROTOCOL_VERSION, LeaseInfo, LeaseRecord, RenewRequest};
pub use server::{
    WitnessConfig, WitnessHandle, read_token_file, start_witness_server, validate_token_file,
};
pub use store::{LeaseOpError, LeaseStore};

use std::fmt;

/// Default witness listen address from the ADR.
pub const DEFAULT_LEASE_LISTEN: &str = "0.0.0.0:8954";

/// Maximum accepted JSON request body (16 KiB).
pub const MAX_REQUEST_BODY: usize = 16 * 1024;

/// On-disk record schema version.
pub const LEASE_SCHEMA: u32 = 1;

/// Maximum version lead over the witness record accepted on acquire/renew.
///
/// This mirrors the existing peer-lead limit: a version may not jump more than
/// one million above the last published baseline.
pub const MAX_VERSION_LEAD: u64 = 1_000_000;

/// Minimum TTL accepted by the witness, in seconds.
pub const MIN_TTL_SECS: u64 = 5;

/// Maximum TTL accepted by the witness, in seconds.
pub const MAX_TTL_SECS: u64 = 300;

const STATE_DIR_MODE: u32 = 0o700;
const STATE_FILE_MODE: u32 = 0o600;

/// A witness configuration/state error with a stable machine-readable code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessError {
    code: &'static str,
    message: String,
}

impl WitnessError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Stable error code (for example `state_missing`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Human-readable detail.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for WitnessError {}

impl From<std::io::Error> for WitnessError {
    fn from(value: std::io::Error) -> Self {
        Self::new("io_error", value.to_string())
    }
}

/// Normalizes a BLAKE3 hash to 64 lowercase hexadecimal characters.
///
/// A `blake3:` prefix is accepted and stripped. Anything else (wrong length,
/// non-hex characters, an empty value) is rejected.
pub fn normalize_hash(input: &str) -> Result<String, WitnessError> {
    sito_ha_types::hash::normalize_blake3_hash(input)
        .map_err(|error| WitnessError::new("invalid_bundle_hash", error.to_string()))
}

/// Normalizes the `(version, bundle_hash)` pair carried by a lease request.
///
/// `version == 0` requires exactly `"none"`; a positive version requires a
/// valid BLAKE3 hash and rejects `"none"`.
pub fn normalize_bundle_hash(version: u64, input: &str) -> Result<String, WitnessError> {
    sito_ha_types::hash::normalize_bundle_hash(version, input)
        .map_err(|error| WitnessError::new("invalid_bundle_hash", error.to_string()))
}

/// Validates a stable cluster identifier (`[A-Za-z0-9._-]{1,64}`).
pub fn validate_cluster_id(cluster_id: &str) -> Result<(), WitnessError> {
    validate_identifier("cluster_id", cluster_id)
}

/// Validates a stable node identifier (`[A-Za-z0-9._-]{1,64}`).
pub fn validate_node_id(node_id: &str) -> Result<(), WitnessError> {
    validate_identifier("node_id", node_id)
}

fn validate_identifier(field: &str, value: &str) -> Result<(), WitnessError> {
    let valid_len = (1..=64).contains(&value.len());
    let valid_chars = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid_len && valid_chars {
        Ok(())
    } else {
        Err(WitnessError::new(
            "invalid_identifier",
            format!("{field} must be 1-64 characters from [A-Za-z0-9._-]"),
        ))
    }
}

/// Validates that `holder` is exactly `node_id/<uuid>`.
pub fn validate_holder(holder: &str, node_id: &str) -> Result<(), WitnessError> {
    validate_holder_shape(holder)?;
    let (prefix, suffix) = holder
        .split_once('/')
        .expect("validate_holder_shape guarantees a slash");
    if prefix != node_id {
        return Err(WitnessError::new(
            "invalid_holder",
            format!("holder '{holder}' does not start with node_id '{node_id}/'"),
        ));
    }
    if suffix.is_empty() {
        return Err(WitnessError::new(
            "invalid_holder",
            "holder must be node_id/<non-empty boot uuid>",
        ));
    }
    Ok(())
}

/// Validates the generic `node_id/<boot uuid>` shape without a node id to
/// compare against (used by renew, where the record supplies the node id).
pub fn validate_holder_shape(holder: &str) -> Result<(), WitnessError> {
    let Some((node_id, boot)) = holder.split_once('/') else {
        return Err(WitnessError::new(
            "invalid_holder",
            "holder must be node_id/<boot uuid>",
        ));
    };
    if holder.len() > 129 {
        return Err(WitnessError::new(
            "invalid_holder",
            "holder is longer than 129 characters",
        ));
    }
    validate_node_id(node_id)?;
    let boot_valid = (1..=64).contains(&boot.len())
        && boot
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if boot_valid {
        Ok(())
    } else {
        Err(WitnessError::new(
            "invalid_holder",
            format!("holder '{holder}' has an invalid boot uuid"),
        ))
    }
}

/// Validates a lease TTL (5..=300 seconds).
pub fn validate_ttl(ttl_secs: u64) -> Result<(), WitnessError> {
    if (MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl_secs) {
        Ok(())
    } else {
        Err(WitnessError::new(
            "ttl_out_of_range",
            format!("ttl_secs must be {MIN_TTL_SECS}..={MAX_TTL_SECS}"),
        ))
    }
}

/// Sets Unix permissions when running on Unix; a no-op elsewhere.
pub(crate) fn set_mode(path: &std::path::Path, mode: u32) -> Result<(), WitnessError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(path)
            .map_err(WitnessError::from)?
            .permissions();
        if permissions.mode() & 0o777 != mode {
            permissions.set_mode(mode);
            std::fs::set_permissions(path, permissions).map_err(WitnessError::from)?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

/// Returns true when a path exists, without following a final symlink.
pub(crate) fn exists_no_follow(path: &std::path::Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

pub(crate) const STATE_DIR_MODE_VALUE: u32 = STATE_DIR_MODE;
pub(crate) const STATE_FILE_MODE_VALUE: u32 = STATE_FILE_MODE;
