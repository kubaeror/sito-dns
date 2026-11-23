//! Durable fence markers for ADR-0010 automatic promotion.
//!
//! A fenced node must never re-acquire the lease automatically, including
//! across restarts. The marker is written in two steps: an atomic
//! `ha_fence.pending` first, then the canonical `ha_fence.json`. If the final
//! write fails but the pending write succeeded the node is still durably
//! fenced. If both fail the caller must become read-only and exit non-zero; the
//! witness term remains the safety backstop because no durable distinction
//! could be recorded.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::HaError;

use super::state::{check_data_dir_integrity, write_atomic_private};

/// On-disk fence protocol version.
pub const FENCE_PROTOCOL_VERSION: u32 = 2;
/// Canonical marker path name.
pub const FENCE_FILE: &str = "ha_fence.json";
/// Pre-marker path name.
pub const FENCE_PENDING_FILE: &str = "ha_fence.pending";

/// Stable reasons recorded in a fence marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceReason {
    /// The lease expired, was lost, or the holder could not renew in time.
    LeaseLost,
    /// A renewal 409 showed the witness record above/beside our baseline.
    LeaseVersionRegression,
    /// The witness no longer has any record but this node held a term.
    LeaseRecordMissing,
    /// A wall-clock step or boot-id change made the deadline untrustworthy.
    ClockAnomaly,
    /// The local state write failed after acquisition.
    StateWriteFailed,
    /// The listener/role switch failed after acquisition.
    RoleSwitchFailed,
    /// The witness rejected authentication or TLS configuration.
    WitnessAuthFailed,
    /// The witness speaks an incompatible protocol.
    WitnessProtocolMismatch,
}

impl FenceReason {
    /// Stable status/audit code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LeaseLost => "lease_lost",
            Self::LeaseVersionRegression => "lease_version_regression",
            Self::LeaseRecordMissing => "lease_record_missing",
            Self::ClockAnomaly => "clock_step",
            Self::StateWriteFailed => "state_write_failed",
            Self::RoleSwitchFailed => "role_switch_failed",
            Self::WitnessAuthFailed => "witness_auth_failed",
            Self::WitnessProtocolMismatch => "witness_protocol_mismatch",
        }
    }
}

/// The durable marker payload from the ADR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceMarker {
    /// Marker protocol version (always 2).
    pub protocol_version: u32,
    /// Cluster the fence belongs to.
    pub cluster_id: String,
    /// Node the fence belongs to.
    pub node_id: String,
    /// Term this node held (or was trying to hold) when it fenced.
    pub fenced_term: u64,
    /// Stable reason code.
    pub reason: String,
    /// Unix milliseconds at which the fence was recorded.
    pub fenced_at_unix_ms: i64,
    /// Whether an operator has reconciled the node.
    pub reconciled: bool,
}

impl FenceMarker {
    /// Builds an unreconciled marker.
    #[must_use]
    pub fn new(
        cluster_id: impl Into<String>,
        node_id: impl Into<String>,
        fenced_term: u64,
        reason: FenceReason,
        fenced_at_unix_ms: i64,
    ) -> Self {
        Self {
            protocol_version: FENCE_PROTOCOL_VERSION,
            cluster_id: cluster_id.into(),
            node_id: node_id.into(),
            fenced_term,
            reason: reason.code().to_string(),
            fenced_at_unix_ms,
            reconciled: false,
        }
    }

    fn validate(&self, cluster_id: &str, node_id: &str) -> Result<(), HaError> {
        if self.protocol_version != FENCE_PROTOCOL_VERSION {
            return Err(HaError::Validation {
                field: "ha_fence".to_string(),
                reason: format!(
                    "fence marker protocol_version {} is not supported (expected {FENCE_PROTOCOL_VERSION})",
                    self.protocol_version
                ),
            });
        }
        if self.cluster_id != cluster_id || self.node_id != node_id {
            return Err(HaError::Validation {
                field: "ha_fence".to_string(),
                reason: format!(
                    "fence marker belongs to {}/{} but this node is {cluster_id}/{node_id}; refusing to start until the data-dir mix-up is resolved",
                    self.cluster_id, self.node_id
                ),
            });
        }
        Ok(())
    }
}

/// Result of a fence-marker persistence attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FencePersistOutcome {
    /// Both the pending and final markers are durable.
    Durable,
    /// `ha_fence.pending` is durable but the final marker failed. A restart is
    /// still fenced.
    PendingOnly,
    /// Neither marker could be written. The caller must exit non-zero.
    Undurable,
}

/// Paths owned by one node's durable fence.
#[derive(Debug, Clone)]
pub struct FenceStore {
    data_dir: PathBuf,
    cluster_id: String,
    node_id: String,
}

impl FenceStore {
    /// Creates a store for `data_dir` scoped to a stable cluster/node identity.
    #[must_use]
    pub fn new(
        data_dir: impl Into<PathBuf>,
        cluster_id: impl Into<String>,
        node_id: impl Into<String>,
    ) -> Self {
        Self {
            data_dir: data_dir.into(),
            cluster_id: cluster_id.into(),
            node_id: node_id.into(),
        }
    }

    /// The data directory.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The canonical marker path.
    #[must_use]
    pub fn marker_path(&self) -> PathBuf {
        self.data_dir.join(FENCE_FILE)
    }

    /// The pending marker path.
    #[must_use]
    pub fn pending_path(&self) -> PathBuf {
        self.data_dir.join(FENCE_PENDING_FILE)
    }

    /// Returns the unreconciled marker, if either file exists.
    ///
    /// A corrupt marker also fails closed: the caller must refuse to start.
    pub fn load(&self) -> Result<Option<FenceMarker>, HaError> {
        for path in [self.marker_path(), self.pending_path()] {
            let data = match std::fs::read_to_string(&path) {
                Ok(data) => data,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(HaError::Validation {
                        field: "ha_fence".to_string(),
                        reason: format!("cannot read fence marker {}: {error}", path.display()),
                    });
                }
            };
            let marker: FenceMarker =
                serde_json::from_str(&data).map_err(|error| HaError::Validation {
                    field: "ha_fence".to_string(),
                    reason: format!(
                        "corrupt fence marker {}: {error}; refusing to start until it is repaired or cleared",
                        path.display()
                    ),
                })?;
            marker.validate(&self.cluster_id, &self.node_id)?;
            if marker.reconciled {
                continue;
            }
            return Ok(Some(marker));
        }
        Ok(None)
    }

    /// Persists the marker: `ha_fence.pending`, then `ha_fence.json`.
    ///
    /// The caller must treat [`FencePersistOutcome::PendingOnly`] as durably
    /// fenced and [`FencePersistOutcome::Undurable`] as a critical failure.
    pub fn persist(&self, marker: &FenceMarker) -> FencePersistOutcome {
        if marker.validate(&self.cluster_id, &self.node_id).is_err() {
            return FencePersistOutcome::Undurable;
        }
        let Ok(payload) = serde_json::to_vec_pretty(marker) else {
            return FencePersistOutcome::Undurable;
        };
        if write_atomic_private(&self.pending_path(), &payload).is_err() {
            return FencePersistOutcome::Undurable;
        }
        if write_atomic_private(&self.marker_path(), &payload).is_err() {
            return FencePersistOutcome::PendingOnly;
        }
        FencePersistOutcome::Durable
    }

    /// Removes both markers after an operator has reconciled the node.
    pub fn clear(&self) -> Result<(), HaError> {
        for path in [self.marker_path(), self.pending_path()] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(HaError::Validation {
                        field: "ha_fence".to_string(),
                        reason: format!("cannot remove fence marker {}: {error}", path.display()),
                    });
                }
            }
        }
        Ok(())
    }

    /// Runs the post-failure data-directory integrity check.
    pub fn check_integrity(&self) -> Result<(), HaError> {
        check_data_dir_integrity(&self.data_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sito_fence_{label}_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn marker_roundtrips_pending_then_final_and_blocks_restart() {
        let dir = temp_dir("roundtrip");
        let store = FenceStore::new(&dir, "home-dns", "node-a");
        let marker = FenceMarker::new("home-dns", "node-a", 8, FenceReason::LeaseLost, 42);
        assert_eq!(store.persist(&marker), FencePersistOutcome::Durable);
        assert_eq!(store.load().unwrap(), Some(marker.clone()));
        assert!(store.marker_path().exists());
        assert!(store.pending_path().exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(store.marker_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        store.clear().unwrap();
        assert_eq!(store.load().unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_only_is_still_a_fence() {
        let dir = temp_dir("pending");
        let store = FenceStore::new(&dir, "home-dns", "node-a");
        let marker = FenceMarker::new("home-dns", "node-a", 3, FenceReason::LeaseLost, 1);
        std::fs::create_dir_all(&dir).unwrap();
        let payload = serde_json::to_vec_pretty(&marker).unwrap();
        write_atomic_private(&store.pending_path(), &payload).unwrap();
        assert_eq!(store.load().unwrap(), Some(marker));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_foreign_and_reconciled_markers_are_handled() {
        let dir = temp_dir("foreign");
        let store = FenceStore::new(&dir, "home-dns", "node-a");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(store.marker_path(), "not-json").unwrap();
        assert!(store.load().is_err());

        let foreign = FenceMarker::new("other", "node-a", 1, FenceReason::LeaseLost, 1);
        std::fs::write(
            store.marker_path(),
            serde_json::to_vec_pretty(&foreign).unwrap(),
        )
        .unwrap();
        assert!(store.load().is_err());

        let mut reconciled = FenceMarker::new("home-dns", "node-a", 1, FenceReason::LeaseLost, 1);
        reconciled.reconciled = true;
        std::fs::write(
            store.marker_path(),
            serde_json::to_vec_pretty(&reconciled).unwrap(),
        )
        .unwrap();
        assert_eq!(store.load().unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn undurable_write_is_reported() {
        // A file where the data directory should be makes both writes fail.
        let dir = temp_dir("undurable");
        std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
        std::fs::write(&dir, b"not a directory").unwrap();
        let store = FenceStore::new(&dir, "home-dns", "node-a");
        let marker = FenceMarker::new("home-dns", "node-a", 1, FenceReason::LeaseLost, 1);
        assert_eq!(store.persist(&marker), FencePersistOutcome::Undurable);
        assert!(store.check_integrity().is_err());
        let _ = std::fs::remove_file(&dir);
    }
}
