//! One-shot local manual-confirmation file for ADR-0010.
//!
//! `require_manual_confirmation = true` never bypasses the witness. The
//! operator writes `ha_promote.confirm` on the candidate; the candidate
//! consumes it exactly once, after master loss, verifies its identity and age,
//! removes it and authorizes one acquisition. A stale, foreign or old file is
//! ignored and removed.

use std::path::{Path, PathBuf};

use rand::Rng as _;
use serde::{Deserialize, Serialize};

use crate::error::HaError;

use super::state::write_atomic_private;

/// Confirmation file protocol version.
pub const CONFIRM_PROTOCOL_VERSION: u32 = 2;
/// Default file name inside the data directory.
pub const CONFIRM_FILE: &str = "ha_promote.confirm";

/// The confirmation payload written by `sito ha confirm-promotion`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationFile {
    /// Confirmation protocol version.
    pub protocol_version: u32,
    /// Cluster the operator confirmed.
    pub cluster_id: String,
    /// Node the operator confirmed.
    pub node_id: String,
    /// Unix milliseconds at which the operator requested confirmation.
    pub requested_at_unix_ms: i64,
    /// Random one-shot nonce (hex).
    pub nonce: String,
}

impl ConfirmationFile {
    /// Creates a confirmation payload with a fresh random nonce.
    #[must_use]
    pub fn new(
        cluster_id: impl Into<String>,
        node_id: impl Into<String>,
        requested_at_unix_ms: i64,
    ) -> Self {
        let mut nonce = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce);
        Self {
            protocol_version: CONFIRM_PROTOCOL_VERSION,
            cluster_id: cluster_id.into(),
            node_id: node_id.into(),
            requested_at_unix_ms,
            nonce: hex::encode(nonce),
        }
    }

    /// Creates a deterministic payload for tests.
    #[must_use]
    pub fn with_nonce(
        cluster_id: impl Into<String>,
        node_id: impl Into<String>,
        requested_at_unix_ms: i64,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: CONFIRM_PROTOCOL_VERSION,
            cluster_id: cluster_id.into(),
            node_id: node_id.into(),
            requested_at_unix_ms,
            nonce: nonce.into(),
        }
    }
}

/// Why a confirmation was not consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationError {
    /// No file exists.
    Missing,
    /// The file exists but is unreadable/corrupt; it was removed.
    Invalid,
    /// The file names another cluster or node; it was removed.
    WrongIdentity,
    /// The file is older than the heartbeat timeout; it was removed.
    Expired,
    /// The file is from the future by more than the allowed skew; it was
    /// removed and treated as invalid.
    NotYetValid,
}

/// Path-bound confirmation store.
#[derive(Debug, Clone)]
pub struct ConfirmationStore {
    path: PathBuf,
    cluster_id: String,
    node_id: String,
}

impl ConfirmationStore {
    /// Creates a store for `<data_dir>/ha_promote.confirm`.
    #[must_use]
    pub fn new(
        data_dir: impl Into<PathBuf>,
        cluster_id: impl Into<String>,
        node_id: impl Into<String>,
    ) -> Self {
        Self {
            path: data_dir.into().join(CONFIRM_FILE),
            cluster_id: cluster_id.into(),
            node_id: node_id.into(),
        }
    }

    /// Creates a store for an explicit path (tests and the C3b2c CLI).
    #[must_use]
    pub fn with_path(
        path: impl Into<PathBuf>,
        cluster_id: impl Into<String>,
        node_id: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            cluster_id: cluster_id.into(),
            node_id: node_id.into(),
        }
    }

    /// The file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes a new confirmation file atomically (0600).
    pub fn write(&self, confirmation: &ConfirmationFile) -> Result<(), HaError> {
        if confirmation.protocol_version != CONFIRM_PROTOCOL_VERSION {
            return Err(HaError::Validation {
                field: "ha_promote.confirm".to_string(),
                reason: format!(
                    "unsupported confirmation protocol version {}",
                    confirmation.protocol_version
                ),
            });
        }
        let payload = serde_json::to_vec_pretty(confirmation).map_err(|error| {
            HaError::Serialization(format!("failed to serialize confirmation: {error}"))
        })?;
        write_atomic_private(&self.path, &payload).map_err(HaError::Io)
    }

    /// Writes a confirmation for this store's cluster/node.
    pub fn confirm(&self, now_unix_ms: i64) -> Result<ConfirmationFile, HaError> {
        let confirmation =
            ConfirmationFile::new(self.cluster_id.clone(), self.node_id.clone(), now_unix_ms);
        self.write(&confirmation)?;
        Ok(confirmation)
    }

    /// Reads the file without consuming it.
    pub fn peek(&self) -> Result<Option<ConfirmationFile>, HaError> {
        let data = match std::fs::read_to_string(&self.path) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(HaError::Validation {
                    field: "ha_promote.confirm".to_string(),
                    reason: format!("cannot read {}: {error}", self.path.display()),
                });
            }
        };
        let confirmation: ConfirmationFile =
            serde_json::from_str(&data).map_err(|error| HaError::Validation {
                field: "ha_promote.confirm".to_string(),
                reason: format!("corrupt confirmation {}: {error}", self.path.display()),
            })?;
        Ok(Some(confirmation))
    }

    /// Atomically consumes a valid confirmation.
    ///
    /// The file is removed before the result is returned, including for an
    /// invalid/expired/foreign file: a stale confirmation must never be reused.
    /// `max_age_ms` is the effective heartbeat timeout; a file older than that
    /// (or more than `max_age_ms` in the future) is discarded.
    pub fn consume(
        &self,
        now_unix_ms: i64,
        max_age_ms: i64,
    ) -> Result<ConfirmationFile, ConfirmationError> {
        // Atomically take ownership of the file. `rename` succeeds for exactly
        // one consumer; a concurrent/racing attempt gets `NotFound` and can
        // never observe the same authorization twice.
        let mut nonce = [0u8; 8];
        rand::rng().fill_bytes(&mut nonce);
        let staged = self.path.with_extension(format!(
            "consume.{}.{}",
            std::process::id(),
            hex::encode(nonce)
        ));
        match std::fs::rename(&self.path, &staged) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ConfirmationError::Missing);
            }
            Err(_) => return Err(ConfirmationError::Invalid),
        }
        let Some(confirmation) = std::fs::read_to_string(&staged)
            .ok()
            .and_then(|data| serde_json::from_str::<ConfirmationFile>(&data).ok())
        else {
            let _ = std::fs::remove_file(&staged);
            return Err(ConfirmationError::Invalid);
        };
        let _ = std::fs::remove_file(&staged);

        if confirmation.protocol_version != CONFIRM_PROTOCOL_VERSION
            || confirmation.cluster_id != self.cluster_id
            || confirmation.node_id != self.node_id
        {
            return Err(ConfirmationError::WrongIdentity);
        }
        let age = now_unix_ms.saturating_sub(confirmation.requested_at_unix_ms);
        if age < -max_age_ms {
            return Err(ConfirmationError::NotYetValid);
        }
        if age > max_age_ms {
            return Err(ConfirmationError::Expired);
        }
        Ok(confirmation)
    }

    /// Removes the confirmation file, if present.
    pub fn discard(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(label: &str) -> (PathBuf, ConfirmationStore) {
        let dir = std::env::temp_dir().join(format!(
            "sito_confirm_{label}_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let store = ConfirmationStore::new(&dir, "home-dns", "node-a");
        (dir, store)
    }

    #[test]
    fn confirmation_roundtrips_and_is_consumed_once() {
        let (dir, store) = store("once");
        let confirmation = store.confirm(1_000).unwrap();
        assert_eq!(store.peek().unwrap(), Some(confirmation.clone()));
        assert_eq!(store.consume(1_100, 1_000).unwrap(), confirmation);
        assert_eq!(store.consume(1_100, 1_000), Err(ConfirmationError::Missing));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = store.confirm(1_000).unwrap();
            let mode = std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_foreign_and_corrupt_confirmations_are_discarded() {
        let (dir, store) = store("invalid");
        let stale = ConfirmationFile::with_nonce("home-dns", "node-a", 1_000, "aa");
        store.write(&stale).unwrap();
        assert_eq!(store.consume(5_000, 1_000), Err(ConfirmationError::Expired));
        assert_eq!(store.peek().unwrap(), None);

        let foreign = ConfirmationFile::with_nonce("other", "node-a", 1_000, "bb");
        store.write(&foreign).unwrap();
        assert_eq!(
            store.consume(1_100, 1_000),
            Err(ConfirmationError::WrongIdentity)
        );

        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(store.path(), "not-json").unwrap();
        assert_eq!(store.consume(1_100, 1_000), Err(ConfirmationError::Invalid));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn future_file_is_rejected_and_removed() {
        let (dir, store) = store("future");
        let future = ConfirmationFile::with_nonce("home-dns", "node-a", 10_000, "cc");
        store.write(&future).unwrap();
        assert_eq!(
            store.consume(1_000, 1_000),
            Err(ConfirmationError::NotYetValid)
        );
        assert_eq!(store.peek().unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
