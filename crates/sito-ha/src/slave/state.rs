//! High Availability slave state machine representation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::bundle::AppliedWatermark;
use crate::error::HaError;

/// Lifecycle states of a replica slave node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaveState {
    /// Actively attempting to connect to the master WebSocket endpoint.
    Connecting,
    /// Connected and waiting for synchronization response after sending `Hello`.
    HelloSent,
    /// Synchronized with master; operating normally.
    Synced,
    /// Staging and atomically applying a received configuration push.
    Applying,
    /// Operating with previous working configuration after an apply failure.
    Degraded,
}

impl std::fmt::Display for SlaveState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connecting => write!(f, "connecting"),
            Self::HelloSent => write!(f, "hello_sent"),
            Self::Synced => write!(f, "synced"),
            Self::Applying => write!(f, "applying"),
            Self::Degraded => write!(f, "degraded"),
        }
    }
}

/// Shared runtime state of the slave HA controller.
#[derive(Debug, Clone)]
pub struct SlaveStatusTracker {
    pub instance_name: String,
    pub current_version: Arc<AtomicU64>,
    /// Cluster epoch/term of the last applied configuration.
    pub current_term: Arc<AtomicU64>,
    pub state: Arc<Mutex<SlaveState>>,
    pub degraded_reason: Arc<Mutex<Option<String>>>,
    /// Last connection/handshake error. Kept separate from `degraded_reason`
    /// because a transport failure is not an apply failure.
    connection_error: Arc<Mutex<Option<String>>>,
    pub last_synced_at: Arc<Mutex<Option<DateTime<Utc>>>>,
    pub master_url: Option<String>,
    /// Last durably applied bundle watermark.
    watermark: Arc<Mutex<Option<AppliedWatermark>>>,
    /// Path of the on-disk watermark, when persistence is configured.
    watermark_path: Arc<Mutex<Option<PathBuf>>>,
}

impl SlaveStatusTracker {
    pub fn new(instance_name: String, initial_version: u64, master_url: Option<String>) -> Self {
        Self {
            instance_name,
            current_version: Arc::new(AtomicU64::new(initial_version)),
            current_term: Arc::new(AtomicU64::new(0)),
            state: Arc::new(Mutex::new(SlaveState::Connecting)),
            degraded_reason: Arc::new(Mutex::new(None)),
            connection_error: Arc::new(Mutex::new(None)),
            last_synced_at: Arc::new(Mutex::new(None)),
            master_url,
            watermark: Arc::new(Mutex::new(None)),
            watermark_path: Arc::new(Mutex::new(None)),
        }
    }

    /// Restores the applied-version watermark from `path` and enables
    /// persistence there.
    ///
    /// A missing file is a fresh node. A corrupt or implausible file is a hard
    /// error: silently starting at version 0 would let a stale master replay an
    /// older signed bundle after a restart.
    pub fn with_watermark_path(self, path: PathBuf) -> Result<Self, HaError> {
        let watermark = Self::load_watermark(&path)?;
        if let Some(ref watermark) = watermark {
            if watermark.version == u64::MAX {
                return Err(HaError::Validation {
                    field: "ha_watermark".to_string(),
                    reason: format!(
                        "Watermark {} records version u64::MAX and can never advance; delete it only after accepting a full resync",
                        path.display()
                    ),
                });
            }
            if watermark.term == u64::MAX {
                return Err(HaError::Validation {
                    field: "ha_watermark".to_string(),
                    reason: format!(
                        "Watermark {} records term u64::MAX and can never advance; delete it only after accepting a full resync",
                        path.display()
                    ),
                });
            }
            self.current_version
                .store(watermark.version, Ordering::SeqCst);
            self.current_term.store(watermark.term, Ordering::SeqCst);
        }
        *self.watermark.lock().unwrap() = watermark;
        *self.watermark_path.lock().unwrap() = Some(path);
        Ok(self)
    }

    fn load_watermark(path: &std::path::Path) -> Result<Option<AppliedWatermark>, HaError> {
        let data = match std::fs::read_to_string(path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(HaError::Validation {
                    field: "ha_watermark".to_string(),
                    reason: format!("Failed to read {}: {e}", path.display()),
                });
            }
        };
        serde_json::from_str(&data).map(Some).map_err(|e| HaError::Validation {
            field: "ha_watermark".to_string(),
            reason: format!(
                "Corrupt applied-version watermark {}: {e}. Refusing to start at version 0 because that would re-enable replay; restore the file from backup or delete it to force a full resync",
                path.display()
            ),
        })
    }

    /// Returns the last durably applied bundle watermark, if any.
    pub fn get_watermark(&self) -> Option<AppliedWatermark> {
        self.watermark.lock().unwrap().clone()
    }

    /// Returns true when a same-version payload fork has been latched.
    pub fn is_forked(&self) -> bool {
        self.watermark
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|watermark| watermark.forked)
    }

    /// Durably latches a same-version payload fork.
    ///
    /// The applied version/term/payload hash are preserved (they describe the
    /// configuration this node is still serving); only the fork marker is
    /// added. All same-term pushes are refused until a strictly higher-term
    /// promotion is applied.
    pub fn latch_fork(&self, version: u64, term: u64) -> Result<(), HaError> {
        #[allow(clippy::cast_sign_loss)]
        let timestamp = Utc::now().timestamp_millis() as u64;
        let mut watermark = self.get_watermark().unwrap_or(AppliedWatermark {
            version,
            term,
            payload_hash: String::new(),
            timestamp,
            forked: false,
            forked_at_version: 0,
        });
        watermark.forked = true;
        watermark.forked_at_version = version;

        // Fail closed: latch in memory before the durable write so a failed
        // write cannot let the next same-term push through. The caller still
        // receives the error and must not treat replication as recovered.
        *self.watermark.lock().unwrap() = Some(watermark.clone());

        if let Some(path) = self.watermark_path.lock().unwrap().clone() {
            let payload = serde_json::to_vec_pretty(&watermark).map_err(|e| {
                HaError::Serialization(format!("Failed to serialize HA watermark: {e}"))
            })?;
            Self::write_private_atomic(&path, &payload).map_err(|e| HaError::Validation {
                field: "ha_watermark".to_string(),
                reason: format!(
                    "Failed to persist the fork latch at {}: {e}",
                    path.display()
                ),
            })?;
        }

        Ok(())
    }

    /// Atomically persists `{version, term, payload_hash, timestamp}` (0600)
    /// and updates the in-memory watermark only after the write succeeds.
    ///
    /// Must be called after the pushed configuration has been applied and
    /// persisted, before the ACK is sent.
    pub fn persist_watermark(
        &self,
        version: u64,
        term: u64,
        payload_hash: &str,
    ) -> Result<(), HaError> {
        if version == u64::MAX {
            return Err(HaError::Validation {
                field: "ha_watermark".to_string(),
                reason: "Refusing to persist an applied watermark at version u64::MAX".to_string(),
            });
        }
        if term == u64::MAX {
            return Err(HaError::Validation {
                field: "ha_watermark".to_string(),
                reason: "Refusing to persist an applied watermark at term u64::MAX".to_string(),
            });
        }
        #[allow(clippy::cast_sign_loss)]
        let timestamp = Utc::now().timestamp_millis() as u64;
        let watermark = AppliedWatermark {
            version,
            term,
            payload_hash: payload_hash.trim_start_matches("blake3:").to_string(),
            timestamp,
            forked: false,
            forked_at_version: 0,
        };

        if let Some(path) = self.watermark_path.lock().unwrap().clone() {
            let payload = serde_json::to_vec_pretty(&watermark).map_err(|e| {
                HaError::Serialization(format!("Failed to serialize HA watermark: {e}"))
            })?;
            Self::write_private_atomic(&path, &payload).map_err(|e| HaError::Validation {
                field: "ha_watermark".to_string(),
                reason: format!(
                    "Failed to persist applied watermark {}: {e}",
                    path.display()
                ),
            })?;
        }

        *self.watermark.lock().unwrap() = Some(watermark);
        Ok(())
    }

    /// Writes `payload` to `path` atomically (0600 temp file, fsync, rename).
    fn write_private_atomic(path: &std::path::Path, payload: &[u8]) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(payload)?;
            file.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            file.write_all(payload)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }

    pub fn get_state(&self) -> SlaveState {
        *self.state.lock().unwrap()
    }

    pub fn set_state(&self, new_state: SlaveState) {
        *self.state.lock().unwrap() = new_state;
    }

    pub fn get_version(&self) -> u64 {
        self.current_version.load(Ordering::SeqCst)
    }

    /// Records or clears the last connection/handshake failure.
    pub fn set_connection_error(&self, reason: Option<String>) {
        *self.connection_error.lock().unwrap() = reason;
    }

    /// Readiness of the slave's replication path.
    ///
    /// The node is ready only after a successful sync and while its last
    /// connection attempt did not fail. DNS keeps serving either way, so this
    /// signal is what the healthcheck and `/ha/status` use to avoid masking a
    /// dead replication link.
    #[must_use]
    pub fn readiness(&self) -> crate::readiness::HaReadiness {
        if let Some(error) = self.connection_error.lock().unwrap().clone() {
            return crate::readiness::HaReadiness::not_ready(error);
        }
        let state = self.get_state();
        if state == SlaveState::Synced {
            return crate::readiness::HaReadiness::ready();
        }
        let reason = self
            .degraded_reason
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| match state {
                SlaveState::Degraded => "slave is degraded".to_string(),
                SlaveState::HelloSent => {
                    "connected to master; waiting for the initial sync".to_string()
                }
                SlaveState::Applying => "applying a pushed configuration".to_string(),
                SlaveState::Connecting | SlaveState::Synced => {
                    "connecting to the master replication endpoint".to_string()
                }
            });
        crate::readiness::HaReadiness::not_ready(reason)
    }

    pub fn get_term(&self) -> u64 {
        self.current_term.load(Ordering::SeqCst)
    }

    /// Records a successful apply (or an early ACK for the already-running
    /// version) and clears any previous degraded reason.
    pub fn mark_synced(&self, version: u64) {
        self.mark_synced_with_term(version, self.get_term());
    }

    /// Records a successful apply together with the bundle's cluster term.
    pub fn mark_synced_with_term(&self, version: u64, term: u64) {
        self.current_version.store(version, Ordering::SeqCst);
        self.current_term.store(term, Ordering::SeqCst);
        *self.state.lock().unwrap() = SlaveState::Synced;
        *self.degraded_reason.lock().unwrap() = None;
        *self.connection_error.lock().unwrap() = None;
        *self.last_synced_at.lock().unwrap() = Some(Utc::now());
    }

    pub fn mark_degraded(&self, reason: String) {
        *self.state.lock().unwrap() = SlaveState::Degraded;
        *self.degraded_reason.lock().unwrap() = Some(reason);
        // A degraded node is connected (the failure is in the apply path), so
        // do not let an earlier transport error mask the actual reason.
        *self.connection_error.lock().unwrap() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{ConfigBundle, build_and_sign_push, verify_and_unpack_push_with_watermark};
    use crate::crypto::Ed25519SigningKey;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "sito_ha_watermark_{label}_{}_{}",
                std::process::id(),
                rand::random::<u64>()
            ))
            .join("ha_watermark.toml")
    }

    fn bundle(version: u64) -> ConfigBundle {
        ConfigBundle {
            version,
            term: 0,
            timestamp: 1,
            config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
            custom_rules: vec![],
            rewrites: None,
            clients: None,
            lists: vec![],
        }
    }

    #[test]
    fn test_slave_readiness_requires_synced_state() {
        let tracker = SlaveStatusTracker::new(
            "slave-1".to_string(),
            0,
            Some("wss://127.0.0.1:8953".to_string()),
        );
        let readiness = tracker.readiness();
        assert!(!readiness.ready, "a fresh slave is not ready before sync");
        assert!(
            readiness.reason.unwrap_or_default().contains("connect"),
            "a connecting slave must explain its state"
        );

        tracker.set_connection_error(Some(
            "mTLS handshake failed with master '127.0.0.1:8953'".to_string(),
        ));
        let readiness = tracker.readiness();
        assert!(!readiness.ready);
        assert!(
            readiness
                .reason
                .unwrap_or_default()
                .contains("mTLS handshake failed"),
            "the handshake failure must be visible, not just the generic state"
        );

        tracker.mark_degraded("apply failed".to_string());
        let readiness = tracker.readiness();
        assert!(!readiness.ready);
        assert_eq!(readiness.reason.as_deref(), Some("apply failed"));

        tracker.mark_synced_with_term(7, 1);
        let readiness = tracker.readiness();
        assert!(readiness.ready, "a synced slave is ready");
        assert!(readiness.reason.is_none());

        // A later connection error after sync must immediately make the node
        // unready again instead of leaving a stale green signal.
        tracker.set_connection_error(Some("TCP connect error".to_string()));
        let readiness = tracker.readiness();
        assert!(!readiness.ready);
        assert_eq!(readiness.reason.as_deref(), Some("TCP connect error"));
    }

    #[test]
    fn test_watermark_persists_0600_and_loads_on_restart() {
        let path = temp_path("restart");
        let tracker = SlaveStatusTracker::new("slave-1".to_string(), 0, None)
            .with_watermark_path(path.clone())
            .unwrap();
        tracker.persist_watermark(5, 0, "abc123").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "watermark must be owner-only");
        }
        assert!(!path.with_extension("tmp").exists());

        // A restart must resume at the persisted watermark, not version 0.
        let restarted = SlaveStatusTracker::new("slave-1".to_string(), 0, None)
            .with_watermark_path(path.clone())
            .unwrap();
        assert_eq!(restarted.get_version(), 5);
        assert_eq!(restarted.get_term(), 0);
        let watermark = restarted.get_watermark().expect("watermark restored");
        assert_eq!(watermark.version, 5);
        assert_eq!(watermark.term, 0);
        assert_eq!(watermark.payload_hash, "abc123");
        assert!(watermark.timestamp > 0);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_stale_master_term_is_rejected_and_new_term_wins() {
        let path = temp_path("term");
        let signing_key = Ed25519SigningKey::generate().unwrap();
        let tracker = SlaveStatusTracker::new("slave-1".to_string(), 0, None)
            .with_watermark_path(path.clone())
            .unwrap();

        // The slave is at epoch 2, version 10.
        let current = ConfigBundle {
            term: 2,
            ..bundle(10)
        };
        let current_push = build_and_sign_push(&current, &signing_key).unwrap();
        let hash = crate::bundle::push_payload_hash(&current_push).unwrap();
        tracker.persist_watermark(10, 2, &hash).unwrap();

        // A stale master from epoch 1 with a higher version must not overwrite
        // the newer configuration.
        let stale = ConfigBundle {
            term: 1,
            ..bundle(11)
        };
        let stale_push = build_and_sign_push(&stale, &signing_key).unwrap();
        let err = verify_and_unpack_push_with_watermark(
            &stale_push,
            tracker.get_watermark().as_ref(),
            &signing_key.public_key(),
        )
        .expect_err("an older-term master must be rejected even with a higher version");
        assert!(matches!(err, HaError::Validation { ref field, .. } if field == "term"));

        // A term bump alone is not permission to roll the version back: a
        // promoted master with a stale state file is rejected.
        let stale_promotion = ConfigBundle {
            term: 3,
            ..bundle(1)
        };
        let stale_promotion_push = build_and_sign_push(&stale_promotion, &signing_key).unwrap();
        let err = verify_and_unpack_push_with_watermark(
            &stale_promotion_push,
            tracker.get_watermark().as_ref(),
            &signing_key.public_key(),
        )
        .expect_err("a higher term with a lower version must not roll the cluster back");
        assert!(matches!(err, HaError::Validation { ref field, .. } if field == "version"));

        // An explicit promotion must raise both term and version above the
        // applied high-water mark.
        let promoted = ConfigBundle {
            term: 3,
            ..bundle(11)
        };
        let promoted_push = build_and_sign_push(&promoted, &signing_key).unwrap();
        let accepted = verify_and_unpack_push_with_watermark(
            &promoted_push,
            tracker.get_watermark().as_ref(),
            &signing_key.public_key(),
        )
        .expect("a newer explicitly promoted epoch must be accepted");
        assert_eq!(accepted.term, 3);
        assert_eq!(accepted.version, 11);
        // The promotion is only complete once the new epoch is applied; record
        // its watermark before checking that the old epoch cannot come back.
        tracker
            .persist_watermark(
                11,
                3,
                &crate::bundle::push_payload_hash(&promoted_push).unwrap(),
            )
            .unwrap();

        // Old-epoch bundles can never be replayed after the promotion.
        let err = verify_and_unpack_push_with_watermark(
            &current_push,
            tracker.get_watermark().as_ref(),
            &signing_key.public_key(),
        )
        .expect_err("the previous epoch must be rejected after the watermark is at a newer term");
        assert!(matches!(err, HaError::Validation { ref field, .. } if field == "term"));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_restart_rejects_replayed_bundle_below_watermark() {
        let path = temp_path("replay");
        let signing_key = Ed25519SigningKey::generate().unwrap();
        let tracker = SlaveStatusTracker::new("slave-1".to_string(), 0, None)
            .with_watermark_path(path.clone())
            .unwrap();
        let old_push = build_and_sign_push(&bundle(4), &signing_key).unwrap();
        tracker.persist_watermark(5, 0, "abc123").unwrap();

        // Simulate a process restart: the in-memory counter is unknown, so the
        // persisted watermark is the only replay guard.
        let restarted = SlaveStatusTracker::new("slave-1".to_string(), 0, None)
            .with_watermark_path(path.clone())
            .unwrap();
        let err = verify_and_unpack_push_with_watermark(
            &old_push,
            restarted.get_watermark().as_ref(),
            &signing_key.public_key(),
        )
        .expect_err("an older signed bundle must be rejected after restart");
        assert!(matches!(err, HaError::Validation { ref field, .. } if field == "version"));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_same_version_with_different_hash_is_rejected() {
        let path = temp_path("hash");
        let signing_key = Ed25519SigningKey::generate().unwrap();
        let tracker = SlaveStatusTracker::new("slave-1".to_string(), 0, None)
            .with_watermark_path(path.clone())
            .unwrap();
        let push = build_and_sign_push(&bundle(5), &signing_key).unwrap();
        let hash = crate::bundle::push_payload_hash(&push).unwrap();
        tracker.persist_watermark(5, 0, &hash).unwrap();

        // Same version and identical payload: an idempotent re-delivery.
        verify_and_unpack_push_with_watermark(
            &push,
            tracker.get_watermark().as_ref(),
            &signing_key.public_key(),
        )
        .expect("identical same-version delivery must be accepted as idempotent");

        // Same version, different signed content: a content replay.
        let other = build_and_sign_push(
            &ConfigBundle {
                custom_rules: vec!["||evil.example^".to_string()],
                ..bundle(5)
            },
            &signing_key,
        )
        .unwrap();
        let err = verify_and_unpack_push_with_watermark(
            &other,
            tracker.get_watermark().as_ref(),
            &signing_key.public_key(),
        )
        .expect_err("same-version content replay must be rejected");
        assert!(matches!(err, HaError::Validation { ref field, .. } if field == "version"));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_legacy_watermark_without_term_loads_as_term_zero() {
        let path = temp_path("legacy");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"version":5,"payload_hash":"abc123","timestamp":1}"#,
        )
        .unwrap();

        let tracker = SlaveStatusTracker::new("slave-1".to_string(), 0, None)
            .with_watermark_path(path.clone())
            .expect("a pre-term watermark must remain loadable");
        assert_eq!(tracker.get_version(), 5);
        assert_eq!(tracker.get_term(), 0);
        assert_eq!(tracker.get_watermark().unwrap().term, 0);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_corrupt_watermark_fails_closed() {
        let path = temp_path("corrupt");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "not-json").unwrap();

        let err = SlaveStatusTracker::new("slave-1".to_string(), 0, None)
            .with_watermark_path(path.clone())
            .expect_err("a corrupt watermark must not silently reset to version 0");
        assert!(matches!(err, HaError::Validation { ref field, .. } if field == "ha_watermark"));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_watermark_refuses_u64_max() {
        let path = temp_path("max");
        let tracker = SlaveStatusTracker::new("slave-1".to_string(), 0, None)
            .with_watermark_path(path.clone())
            .unwrap();
        assert_eq!(tracker.get_version(), 0);
        assert!(tracker.persist_watermark(u64::MAX, 0, "hash").is_err());
        assert_eq!(
            tracker.get_version(),
            0,
            "a rejected watermark must not advance the counter"
        );

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
