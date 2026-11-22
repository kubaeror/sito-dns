//! Durable publish-baseline state for ADR-0010 automatic promotion.
//!
//! The promotion bookkeeping lives in the existing `ha_state.toml` master state
//! file so the bundle and the baseline are updated atomically. The file is
//! JSON (the historical name is retained) and is written with the same
//! temp-file + `fsync` + `rename` discipline as the rest of the HA state.
//!
//! The central rule is deliberately small and strict:
//!
//! * [`PromotionBookkeeping::published_version`] / `published_hash` are the last
//!   **published** baseline. They are the only values sent to the witness.
//! * The active bundle's `version` is a **pending** version while
//!   `publication_state` is `pending`/`publishing`. It is never a witness
//!   baseline.
//! * A crash can leave a pending bundle staged. Reconciliation or a witness
//!   record match decides whether it was published; the pending version is
//!   reused, never skipped.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use sito_ha_types::bundle::ConfigBundle;
use sito_ha_types::hash::normalize_bundle_hash;
use sito_ha_types::status::PublicationState;

use crate::error::HaError;

pub(crate) use crate::master::coordinator::PersistedMasterState;

/// A published `(version, hash)` baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationBaseline {
    /// Version of the last published bundle; `0` means no bundle yet.
    pub version: u64,
    /// Normalized hash, or `"none"` at version 0.
    pub hash: String,
}

impl PublicationBaseline {
    /// The empty baseline used before a first publish.
    #[must_use]
    pub fn none() -> Self {
        Self {
            version: 0,
            hash: "none".to_string(),
        }
    }

    /// Validates and normalizes `(version, hash)`.
    pub fn new(version: u64, hash: &str) -> Result<Self, HaError> {
        let hash = normalize_bundle_hash(version, hash).map_err(|error| HaError::Validation {
            field: "ha_state.published_hash".to_string(),
            reason: error.to_string(),
        })?;
        Ok(Self { version, hash })
    }

    /// Whether this baseline describes a real published bundle.
    #[must_use]
    pub const fn is_published(&self) -> bool {
        self.version > 0
    }
}

/// The promotion fields persisted next to the bundle in `ha_state.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionBookkeeping {
    /// State of the active bundle relative to the published baseline.
    pub publication_state: PublicationState,
    /// Version of the last published bundle.
    pub published_version: u64,
    /// Normalized hash of the last published signed payload.
    pub published_hash: String,
    /// Hash of the staged bundle, when one is pending/publishing.
    pub pending_hash: Option<String>,
    /// `"automatic"` or `"restart"`.
    pub promotion_origin: Option<String>,
    /// Witness holder (`node_id/boot_uuid`) that performed the promotion.
    pub lease_holder: Option<String>,
    /// Cluster identifier used by the promotion.
    pub cluster_id: Option<String>,
    /// Stable node identifier.
    pub node_id: Option<String>,
    /// Unix milliseconds at which the promotion started.
    pub promoted_at_unix_ms: Option<i64>,
    /// Last applied configuration version on this node (candidate baseline).
    pub last_applied_version: Option<u64>,
    /// Last applied signed-payload hash on this node.
    pub last_applied_hash: Option<String>,
}

impl PromotionBookkeeping {
    /// Bookkeeping for a node that has never staged a promotion.
    #[must_use]
    pub fn published(baseline: PublicationBaseline) -> Self {
        Self {
            publication_state: PublicationState::Published,
            published_version: baseline.version,
            published_hash: baseline.hash,
            pending_hash: None,
            promotion_origin: None,
            lease_holder: None,
            cluster_id: None,
            node_id: None,
            promoted_at_unix_ms: None,
            last_applied_version: None,
            last_applied_hash: None,
        }
    }

    /// The published baseline.
    #[must_use]
    pub fn baseline(&self) -> PublicationBaseline {
        PublicationBaseline {
            version: self.published_version,
            hash: self.published_hash.clone(),
        }
    }

    /// Whether the active bundle must be treated as staged, not published.
    #[must_use]
    pub const fn has_pending_bundle(&self) -> bool {
        self.publication_state.is_pending()
    }
}

/// Strict result of reading `ha_state.toml` for the promotion engine.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum LoadedState {
    /// The file does not exist. A fresh node may acquire term 1.
    Missing,
    /// A v2 state file with a bundle and (possibly) promotion fields.
    Present {
        /// The full on-disk state.
        state: Box<PersistedMasterState>,
        /// Promotion bookkeeping, if the file was written by a promotion-aware
        /// build. `None` means "unknown" and must be reconciled, never assumed
        /// published.
        bookkeeping: Option<PromotionBookkeeping>,
    },
}

impl LoadedState {
    /// The bundle version/term, if any.
    #[must_use]
    pub fn bundle(&self) -> Option<&ConfigBundle> {
        match self {
            Self::Missing => None,
            Self::Present { state, .. } => Some(&state.bundle),
        }
    }
}

/// A durable reader/writer for one `ha_state.toml` path.
///
/// `load` fails closed on a corrupt, v1 or foreign file. No backup-and-reset is
/// performed here: a promotion must not silently start a new sequence from a
/// state file it could not understand.
#[derive(Debug, Clone)]
pub struct HaStateStore {
    path: PathBuf,
    cluster_id: Option<String>,
    node_id: Option<String>,
}

impl HaStateStore {
    /// Creates a store for `path`.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            cluster_id: None,
            node_id: None,
        }
    }

    /// Binds the stable cluster/node identity. A state file naming another
    /// cluster or node is a data-dir mix-up and is refused.
    #[must_use]
    pub fn with_identity(
        mut self,
        cluster_id: impl Into<String>,
        node_id: impl Into<String>,
    ) -> Self {
        self.cluster_id = Some(cluster_id.into());
        self.node_id = Some(node_id.into());
        self
    }

    /// The state file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads and validates the state file.
    pub fn load(&self) -> Result<LoadedState, HaError> {
        let data = match std::fs::read_to_string(&self.path) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LoadedState::Missing);
            }
            Err(error) => {
                return Err(HaError::Validation {
                    field: "ha_state".to_string(),
                    reason: format!("cannot read {}: {error}", self.path.display()),
                });
            }
        };

        let state: PersistedMasterState = serde_json::from_str(&data).map_err(|error| {
            let detail = if data.contains("\"bundle\"") {
                "protocol_mismatch: ha_state.toml is missing the protocol v2 signed identity fields"
            } else if data.contains("\"config_toml\"") {
                "protocol_mismatch: ha_state.toml uses the v1 flat format"
            } else {
                "corrupt ha_state.toml; refusing to reset the configuration sequence"
            };
            HaError::Validation {
                field: "ha_state".to_string(),
                reason: format!("{detail} at {}: {error}", self.path.display()),
            }
        })?;

        if state.protocol_version != crate::protocol::PROTOCOL_VERSION {
            return Err(HaError::Validation {
                field: "ha_state".to_string(),
                reason: format!(
                    "protocol_mismatch: ha_state.toml was written by protocol v{} but this node requires v{}",
                    state.protocol_version,
                    crate::protocol::PROTOCOL_VERSION
                ),
            });
        }
        if state.bundle.protocol_version != state.protocol_version {
            return Err(HaError::Validation {
                field: "ha_state".to_string(),
                reason: format!(
                    "protocol_mismatch: ha_state.toml declares protocol v{} but its bundle declares v{}",
                    state.protocol_version, state.bundle.protocol_version
                ),
            });
        }
        if let Some(ref expected) = self.cluster_id
            && state
                .cluster_id
                .as_ref()
                .is_some_and(|actual| actual != expected)
        {
            return Err(HaError::Validation {
                field: "ha_state".to_string(),
                reason: format!(
                    "ha_state.toml belongs to cluster '{}' but this node is configured for '{expected}'",
                    state.cluster_id.as_deref().unwrap_or_default()
                ),
            });
        }
        if let Some(ref expected) = self.node_id
            && state
                .node_id
                .as_ref()
                .is_some_and(|actual| actual != expected)
        {
            return Err(HaError::Validation {
                field: "ha_state".to_string(),
                reason: format!(
                    "ha_state.toml belongs to node '{}' but this node is '{}'",
                    state.node_id.as_deref().unwrap_or_default(),
                    expected
                ),
            });
        }
        if state.bundle.term == u64::MAX || state.bundle.version == u64::MAX {
            return Err(HaError::Validation {
                field: "ha_state".to_string(),
                reason: "ha_state.toml uses u64::MAX for term or version and can never advance"
                    .to_string(),
            });
        }
        if let (Some(version), Some(hash)) =
            (state.published_version, state.published_hash.as_deref())
        {
            normalize_bundle_hash(version, hash).map_err(|error| HaError::Validation {
                field: "ha_state.published_hash".to_string(),
                reason: format!("invalid published baseline: {error}"),
            })?;
        }
        let bookkeeping = PromotionBookkeeping::from_state(&state)?;
        Ok(LoadedState::Present {
            state: Box::new(state),
            bookkeeping,
        })
    }

    /// Atomically writes the full state.
    pub fn save(&self, state: &PersistedMasterState) -> Result<(), HaError> {
        let payload = serde_json::to_vec_pretty(state).map_err(|error| {
            HaError::Serialization(format!("failed to serialize ha_state.toml: {error}"))
        })?;
        write_atomic_private(&self.path, &payload).map_err(HaError::Io)
    }

    /// Atomically updates only the promotion bookkeeping, preserving the
    /// bundle already on disk.
    ///
    /// A missing file is an error: a promotion never invents a bundle.
    pub fn save_bookkeeping(&self, bookkeeping: &PromotionBookkeeping) -> Result<(), HaError> {
        let loaded = self.load()?;
        let LoadedState::Present { mut state, .. } = loaded else {
            return Err(HaError::Validation {
                field: "ha_state".to_string(),
                reason: "cannot update promotion bookkeeping without an existing bundle"
                    .to_string(),
            });
        };
        bookkeeping.apply_to(&mut state);
        self.save(&state)
    }
}

impl PromotionBookkeeping {
    /// Reads bookkeeping from a parsed state file.
    ///
    /// An older binary wrote no `publication_state`: that is explicitly
    /// *unknown*, not `published`. It is represented as `None` so callers must
    /// infer from a witness record match instead of assuming publication.
    pub fn from_state(state: &PersistedMasterState) -> Result<Option<Self>, HaError> {
        let Some(publication_state) = state.publication_state else {
            return Ok(None);
        };
        let published_version = state.published_version.unwrap_or(0);
        let published_hash = state
            .published_hash
            .clone()
            .unwrap_or_else(|| "none".to_string());
        normalize_bundle_hash(published_version, &published_hash).map_err(|error| {
            HaError::Validation {
                field: "ha_state.published_hash".to_string(),
                reason: format!("invalid published baseline: {error}"),
            }
        })?;
        Ok(Some(Self {
            publication_state,
            published_version,
            published_hash,
            pending_hash: state.pending_hash.clone(),
            promotion_origin: state.promotion_origin.clone(),
            lease_holder: state.lease_holder.clone(),
            cluster_id: state.cluster_id.clone(),
            node_id: state.node_id.clone(),
            promoted_at_unix_ms: state.promoted_at_unix_ms,
            last_applied_version: state.last_applied_version,
            last_applied_hash: state.last_applied_hash.clone(),
        }))
    }

    /// Writes this bookkeeping into `state` without touching the bundle.
    pub fn apply_to(&self, state: &mut PersistedMasterState) {
        state.publication_state = Some(self.publication_state);
        state.published_version = Some(self.published_version);
        state.published_hash = Some(self.published_hash.clone());
        state.pending_hash.clone_from(&self.pending_hash);
        state.promotion_origin.clone_from(&self.promotion_origin);
        state.lease_holder.clone_from(&self.lease_holder);
        state.cluster_id.clone_from(&self.cluster_id);
        state.node_id.clone_from(&self.node_id);
        state.promoted_at_unix_ms = self.promoted_at_unix_ms;
        state.last_applied_version = self.last_applied_version;
        state.last_applied_hash.clone_from(&self.last_applied_hash);
    }
}

/// Writes `payload` to `path` atomically (0600 temp file, fsync, rename, and a
/// directory fsync when supported).
pub(crate) fn write_atomic_private(path: &Path, payload: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = tmp_path(path);
    #[cfg(unix)]
    {
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
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(payload)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        // Best effort: the rename is already atomic. A directory fsync keeps
        // the new name durable across a power loss on filesystems that need it.
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().into_owned())
        .unwrap_or_default();
    if extension.is_empty() {
        extension = "tmp".to_string();
    } else {
        extension.push_str(".tmp");
    }
    path.with_extension(extension)
}

/// Data-directory integrity check used after a fence-marker write failure.
///
/// The check is intentionally conservative: the directory must exist, be
/// writable, and contain no unreadable/foreign promotion state. A failure is
/// reported so the caller can exit non-zero instead of resuming a fenced term.
pub fn check_data_dir_integrity(data_dir: &Path) -> Result<(), HaError> {
    std::fs::create_dir_all(data_dir).map_err(HaError::Io)?;
    let probe = data_dir.join(format!(
        ".ha-integrity-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe);
    match result {
        Ok(file) => {
            drop(file);
            let _ = std::fs::remove_file(&probe);
        }
        Err(error) => {
            return Err(HaError::Validation {
                field: "data_dir".to_string(),
                reason: format!(
                    "data directory '{}' is not writable after a fence write failure: {error}",
                    data_dir.display()
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(version: u64, term: u64) -> ConfigBundle {
        ConfigBundle {
            version,
            term,
            config_toml: "config_version = 2\n[server]\nrole = \"slave\"\n".to_string(),
            ..ConfigBundle::default()
        }
    }

    fn state(version: u64, term: u64) -> PersistedMasterState {
        PersistedMasterState {
            protocol_version: crate::protocol::PROTOCOL_VERSION,
            bundle: bundle(version, term),
            signing_key_pubkey: None,
            publication_state: None,
            published_version: None,
            published_hash: None,
            pending_hash: None,
            promotion_origin: None,
            lease_holder: None,
            cluster_id: None,
            node_id: None,
            promoted_at_unix_ms: None,
            last_applied_version: None,
            last_applied_hash: None,
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sito_promotion_state_{label}_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn state_roundtrips_and_preserves_bookkeeping() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("ha_state.toml");
        let store = HaStateStore::new(path.clone()).with_identity("home-dns", "node-a");
        assert!(matches!(store.load().unwrap(), LoadedState::Missing));

        let mut state = state(4, 2);
        let bookkeeping = PromotionBookkeeping {
            publication_state: PublicationState::Pending,
            published_version: 3,
            published_hash: "ab".repeat(32),
            pending_hash: Some("cd".repeat(32)),
            promotion_origin: Some("automatic".to_string()),
            lease_holder: Some("node-a/boot".to_string()),
            cluster_id: Some("home-dns".to_string()),
            node_id: Some("node-a".to_string()),
            promoted_at_unix_ms: Some(42),
            last_applied_version: Some(3),
            last_applied_hash: Some("ab".repeat(32)),
        };
        bookkeeping.apply_to(&mut state);
        store.save(&state).unwrap();

        let LoadedState::Present {
            state: loaded,
            bookkeeping: loaded_bookkeeping,
        } = store.load().unwrap()
        else {
            panic!("state should exist");
        };
        assert_eq!(loaded.bundle.version, 4);
        assert_eq!(loaded_bookkeeping, Some(bookkeeping));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_publication_state_is_unknown_not_published() {
        let dir = temp_dir("legacy");
        let path = dir.join("ha_state.toml");
        let store = HaStateStore::new(path.clone());
        store.save(&state(7, 3)).unwrap();
        let LoadedState::Present { bookkeeping, .. } = store.load().unwrap() else {
            panic!("state should exist");
        };
        assert_eq!(bookkeeping, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_v1_and_foreign_state_fail_closed() {
        let dir = temp_dir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ha_state.toml");
        std::fs::write(&path, "not-json").unwrap();
        let store = HaStateStore::new(path.clone());
        assert!(store.load().is_err());

        // A v1 flat state must not be repaired into a fresh sequence.
        std::fs::write(&path, r#"{"version":4,"config_toml":"x"}"#).unwrap();
        let error = store.load().unwrap_err().to_string();
        assert!(error.contains("v1"), "{error}");

        // A foreign cluster/node is a data-dir mix-up.
        let mut foreign = state(3, 1);
        foreign.cluster_id = Some("other".to_string());
        store.save(&foreign).unwrap();
        let scoped = HaStateStore::new(path.clone()).with_identity("home-dns", "node-a");
        assert!(scoped.load().is_err());

        let mut other_node = state(3, 1);
        other_node.node_id = Some("node-b".to_string());
        store.save(&other_node).unwrap();
        assert!(scoped.load().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_bookkeeping_requires_an_existing_bundle_and_preserves_it() {
        let dir = temp_dir("save_bookkeeping");
        let path = dir.join("ha_state.toml");
        let store = HaStateStore::new(path.clone());
        let bookkeeping =
            PromotionBookkeeping::published(PublicationBaseline::new(5, &"ef".repeat(32)).unwrap());
        assert!(store.save_bookkeeping(&bookkeeping).is_err());

        store.save(&state(6, 2)).unwrap();
        store.save_bookkeeping(&bookkeeping).unwrap();
        let LoadedState::Present {
            state,
            bookkeeping: loaded,
        } = store.load().unwrap()
        else {
            panic!("state");
        };
        assert_eq!(state.bundle.version, 6);
        assert_eq!(loaded.unwrap().published_version, 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn baselines_normalize_hashes_and_none_is_only_version_zero() {
        assert_eq!(PublicationBaseline::new(0, "none").unwrap().hash, "none");
        assert!(
            PublicationBaseline::new(0, &"aa".repeat(32))
                .unwrap_err()
                .to_string()
                .contains("version 0")
        );
        assert!(
            PublicationBaseline::new(2, "none")
                .unwrap_err()
                .to_string()
                .contains("only valid for version 0")
        );
        assert_eq!(
            PublicationBaseline::new(2, &format!("blake3:{}", "AB".repeat(32)))
                .unwrap()
                .hash,
            "ab".repeat(32)
        );
    }

    #[test]
    fn data_dir_integrity_requires_a_writable_directory() {
        let dir = temp_dir("integrity");
        check_data_dir_integrity(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
