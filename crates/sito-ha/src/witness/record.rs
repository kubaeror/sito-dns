//! Wire and persistence types for the witness lease protocol.

use serde::{Deserialize, Serialize};

use super::{
    LEASE_SCHEMA, WitnessError, normalize_bundle_hash, validate_holder_shape, validate_node_id,
};

/// Lease protocol version returned by `GET /v1/info`.
pub const LEASE_PROTOCOL_VERSION: u32 = 1;

/// The durable witness record.
///
/// `bundle_hash` is stored normalized: exactly `"none"` for version 0 and 64
/// lowercase hexadecimal characters otherwise. The `blake3:` prefix accepted on
/// input is not persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecord {
    pub schema: u32,
    pub cluster_id: String,
    pub holder: String,
    pub node_id: String,
    pub term: u64,
    pub revision: u64,
    pub version: u64,
    pub bundle_hash: String,
    pub acquired_unix_ms: i64,
    pub expires_unix_ms: i64,
}

impl LeaseRecord {
    /// Validates a record loaded from disk for `cluster_id`.
    pub fn validate_loaded(&self, cluster_id: &str) -> Result<(), WitnessError> {
        if self.schema != LEASE_SCHEMA {
            return Err(WitnessError::new(
                "state_corrupt",
                format!(
                    "unsupported lease record schema {} (expected {LEASE_SCHEMA})",
                    self.schema
                ),
            ));
        }
        if self.cluster_id != cluster_id {
            return Err(WitnessError::new(
                "state_cluster_mismatch",
                format!(
                    "lease record belongs to cluster '{}' but --cluster-id is '{}'",
                    self.cluster_id, cluster_id
                ),
            ));
        }
        validate_node_id(&self.node_id).map_err(|error| {
            WitnessError::new(
                "state_corrupt",
                format!("invalid node_id: {}", error.message()),
            )
        })?;
        validate_holder_shape(&self.holder).map_err(|error| {
            WitnessError::new(
                "state_corrupt",
                format!("invalid holder: {}", error.message()),
            )
        })?;
        if !self.holder.starts_with(&format!("{}/", self.node_id)) {
            return Err(WitnessError::new(
                "state_corrupt",
                "holder does not belong to node_id",
            ));
        }
        if self.term == 0 {
            return Err(WitnessError::new(
                "state_corrupt",
                "lease record term must be at least 1",
            ));
        }
        if self.revision == 0 {
            return Err(WitnessError::new(
                "state_corrupt",
                "lease record revision must be at least 1",
            ));
        }
        let expected_hash =
            normalize_bundle_hash(self.version, &self.bundle_hash).map_err(|error| {
                WitnessError::new(
                    "state_corrupt",
                    format!("invalid bundle_hash: {}", error.message()),
                )
            })?;
        if expected_hash != self.bundle_hash {
            return Err(WitnessError::new(
                "state_corrupt",
                "bundle_hash is not stored in normalized form",
            ));
        }
        if self.expires_unix_ms < self.acquired_unix_ms {
            return Err(WitnessError::new(
                "state_corrupt",
                "lease record expires before it was acquired",
            ));
        }
        Ok(())
    }

    /// Whether the record is expired at witness time `now_unix_ms`.
    #[must_use]
    pub const fn is_expired(&self, now_unix_ms: i64) -> bool {
        now_unix_ms >= self.expires_unix_ms
    }
}

/// `POST /v1/lease/acquire` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquireRequest {
    pub holder: String,
    pub node_id: String,
    #[serde(default)]
    pub expected_term: Option<u64>,
    #[serde(default)]
    pub expected_revision: Option<u64>,
    pub term: u64,
    pub version: u64,
    pub bundle_hash: String,
    pub ttl_secs: u64,
}

/// `POST /v1/lease/renew` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewRequest {
    pub holder: String,
    pub term: u64,
    pub expected_revision: u64,
    pub version: u64,
    pub bundle_hash: String,
    pub ttl_secs: u64,
}

/// `GET /v1/info` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseInfo {
    pub lease_protocol_version: u32,
    pub cluster_id: String,
    pub now_unix_ms: i64,
}
