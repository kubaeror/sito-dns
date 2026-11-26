//! Durable single-record lease state with linearizable CAS operations.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::record::{AcquireRequest, LeaseRecord, RenewRequest};
use super::{
    Clock, LEASE_SCHEMA, MAX_VERSION_LEAD, STATE_FILE_MODE_VALUE, WitnessError, exists_no_follow,
    normalize_bundle_hash, set_mode, validate_cluster_id, validate_holder, validate_holder_shape,
    validate_node_id, validate_ttl,
};

/// Current record file.
pub const LEASE_FILE: &str = "lease.json";
/// Sentinel written after the first successful grant.
pub const INITIALIZED_FILE: &str = "initialized";
/// Lifetime advisory lock that keeps the offline admin tool out.
pub const LOCK_FILE: &str = "lease.lock";

/// Error returned by an acquire/renew operation.
#[derive(Debug, Clone)]
pub enum LeaseOpError {
    /// The request was structurally invalid (HTTP 400).
    Invalid {
        reason: &'static str,
        detail: String,
    },
    /// The compare-and-swap precondition failed (HTTP 409).
    Conflict {
        reason: &'static str,
        detail: String,
        current: Option<Box<LeaseRecord>>,
    },
    /// Durable persistence failed (HTTP 500).
    Storage(String),
}

impl LeaseOpError {
    fn invalid(reason: &'static str, detail: impl Into<String>) -> Self {
        Self::Invalid {
            reason,
            detail: detail.into(),
        }
    }

    fn conflict(
        reason: &'static str,
        detail: impl Into<String>,
        current: Option<LeaseRecord>,
    ) -> Self {
        Self::Conflict {
            reason,
            detail: detail.into(),
            current: current.map(Box::new),
        }
    }
}

impl From<LeaseOpError> for WitnessError {
    fn from(value: LeaseOpError) -> Self {
        match value {
            LeaseOpError::Invalid { reason, detail }
            | LeaseOpError::Conflict { reason, detail, .. } => WitnessError::new(reason, detail),
            LeaseOpError::Storage(detail) => WitnessError::new("storage_error", detail),
        }
    }
}

struct StoreInner {
    record: Option<LeaseRecord>,
    initialized: bool,
}

/// The witness' durable lease store.
///
/// Every mutating operation runs under one mutex, persists before it returns,
/// and only then updates the in-memory record. A failed write leaves the
/// previous record authoritative.
pub struct LeaseStore {
    dir: PathBuf,
    cluster_id: String,
    clock: Arc<dyn Clock>,
    inner: Mutex<StoreInner>,
    /// Holds the exclusive advisory lock for this process' lifetime.
    _lock: File,
}

impl std::fmt::Debug for LeaseStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseStore")
            .field("dir", &self.dir)
            .field("cluster_id", &self.cluster_id)
            .finish_non_exhaustive()
    }
}

impl LeaseStore {
    /// Opens (or creates) `state_dir`, takes the lifetime lock and loads state.
    ///
    /// Startup refuses on `state_missing`, `state_corrupt`,
    /// `state_cluster_mismatch` or a held `state_locked` instead of resetting
    /// the term.
    pub fn open(
        dir: &Path,
        cluster_id: &str,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, WitnessError> {
        validate_cluster_id(cluster_id)?;
        std::fs::create_dir_all(dir).map_err(WitnessError::from)?;
        set_mode(dir, super::STATE_DIR_MODE_VALUE)?;
        if !std::fs::metadata(dir).map_err(WitnessError::from)?.is_dir() {
            return Err(WitnessError::new(
                "state_corrupt",
                format!("state path '{}' is not a directory", dir.display()),
            ));
        }

        let lock_path = dir.join(LOCK_FILE);
        let mut lock_options = OpenOptions::new();
        lock_options
            .create(true)
            .truncate(false)
            .read(true)
            .write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            lock_options.mode(STATE_FILE_MODE_VALUE);
        }
        let lock = lock_options.open(&lock_path).map_err(WitnessError::from)?;
        set_mode(&lock_path, STATE_FILE_MODE_VALUE)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(WitnessError::new(
                    "state_locked",
                    format!(
                        "lease state lock '{}' is held by a running witness process",
                        lock_path.display()
                    ),
                ));
            }
            Err(TryLockError::Error(error)) => {
                return Err(WitnessError::new("state_locked", error.to_string()));
            }
        }

        let initialized = exists_no_follow(&dir.join(INITIALIZED_FILE));
        let record_path = dir.join(LEASE_FILE);
        let record = if exists_no_follow(&record_path) {
            let bytes = std::fs::read(&record_path).map_err(|error| {
                WitnessError::new(
                    "state_corrupt",
                    format!("failed to read '{}': {error}", record_path.display()),
                )
            })?;
            let record: LeaseRecord = serde_json::from_slice(&bytes).map_err(|error| {
                WitnessError::new(
                    "state_corrupt",
                    format!("failed to parse '{}': {error}", record_path.display()),
                )
            })?;
            record.validate_loaded(cluster_id)?;
            Some(record)
        } else if initialized {
            return Err(WitnessError::new(
                "state_missing",
                format!(
                    "witness is initialized but '{}' is missing; restore the state backup or perform an explicit manual reinitialization",
                    record_path.display()
                ),
            ));
        } else {
            None
        };

        // A record without the sentinel is recoverable: the record itself is
        // the term history. Write the sentinel rather than refusing a valid
        // grant that crashed between the two atomic writes.
        if record.is_some() && !initialized {
            write_atomic(dir, &dir.join(INITIALIZED_FILE), b"initialized\n")?;
        }
        if initialized {
            let initialized_path = dir.join(INITIALIZED_FILE);
            set_mode(&initialized_path, STATE_FILE_MODE_VALUE)?;
        }

        Ok(Arc::new(Self {
            dir: dir.to_path_buf(),
            cluster_id: cluster_id.to_string(),
            clock,
            inner: Mutex::new(StoreInner {
                record,
                initialized: initialized || record_present(dir),
            }),
            _lock: lock,
        }))
    }

    /// The configured cluster identifier.
    #[must_use]
    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    /// The state directory.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.dir
    }

    /// Current witness time in Unix milliseconds.
    #[must_use]
    pub fn now_unix_ms(&self) -> i64 {
        self.clock.now_unix_ms()
    }

    /// Returns the current record, including an expired one.
    #[must_use]
    pub fn snapshot(&self) -> Option<LeaseRecord> {
        self.lock_inner().record.clone()
    }

    /// Probes that the state directory is writable.
    #[must_use]
    pub fn is_writable(&self) -> bool {
        let probe = self.dir.join(format!(
            ".healthz-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let result = OpenOptions::new().write(true).create_new(true).open(&probe);
        match result {
            Ok(file) => {
                drop(file);
                let _ = std::fs::remove_file(&probe);
                true
            }
            Err(_) => false,
        }
    }

    /// Acquires the lease according to the ADR CAS rules.
    pub fn acquire(&self, request: &AcquireRequest) -> Result<LeaseRecord, LeaseOpError> {
        validate_node_id(&request.node_id)
            .map_err(|error| LeaseOpError::invalid(error.code(), error.message()))?;
        validate_holder(&request.holder, &request.node_id)
            .map_err(|error| LeaseOpError::invalid(error.code(), error.message()))?;
        validate_ttl(request.ttl_secs)
            .map_err(|error| LeaseOpError::invalid(error.code(), error.message()))?;
        let bundle_hash = normalize_bundle_hash(request.version, &request.bundle_hash)
            .map_err(|error| LeaseOpError::invalid(error.code(), error.message()))?;

        let mut inner = self.lock_inner();
        let now = self.clock.now_unix_ms();
        let current = inner.record.clone();

        match &current {
            None => {
                if request.expected_term.is_some() || request.expected_revision.is_some() {
                    return Err(LeaseOpError::conflict(
                        "expected_mismatch",
                        "an empty witness requires expected_term = null and expected_revision = null",
                        None,
                    ));
                }
                if request.term != 1 {
                    return Err(LeaseOpError::conflict(
                        "term_mismatch",
                        "the first acquired term must be 1",
                        None,
                    ));
                }
            }
            Some(record) => {
                if !record.is_expired(now) {
                    return Err(LeaseOpError::conflict(
                        "lease_held",
                        format!(
                            "lease is held by '{}' until {}",
                            record.holder, record.expires_unix_ms
                        ),
                        Some(record.clone()),
                    ));
                }
                let expected_ok = request.expected_term == Some(record.term)
                    && request.expected_revision == Some(record.revision);
                if !expected_ok {
                    return Err(LeaseOpError::conflict(
                        "expected_mismatch",
                        format!(
                            "expected (term {}, revision {}), got ({:?}, {:?})",
                            record.term,
                            record.revision,
                            request.expected_term,
                            request.expected_revision
                        ),
                        Some(record.clone()),
                    ));
                }
                let Some(next_term) = record.term.checked_add(1) else {
                    return Err(LeaseOpError::conflict(
                        "term_overflow",
                        "lease term overflow",
                        Some(record.clone()),
                    ));
                };
                if request.term != next_term {
                    return Err(LeaseOpError::conflict(
                        "term_mismatch",
                        format!(
                            "term must be exactly {} after term {}",
                            next_term, record.term
                        ),
                        Some(record.clone()),
                    ));
                }
            }
        }

        let (current_version, current_hash) = current.as_ref().map_or((0, "none"), |record| {
            (record.version, record.bundle_hash.as_str())
        });
        validate_version_rule(
            request.version,
            &bundle_hash,
            current_version,
            current_hash,
            current.as_ref(),
        )?;

        let revision = match current.as_ref() {
            None => 1,
            Some(record) => record.revision.checked_add(1).ok_or_else(|| {
                LeaseOpError::conflict(
                    "revision_overflow",
                    "lease revision overflow",
                    Some(record.clone()),
                )
            })?,
        };
        let record = LeaseRecord {
            schema: LEASE_SCHEMA,
            cluster_id: self.cluster_id.clone(),
            holder: request.holder.clone(),
            node_id: request.node_id.clone(),
            term: request.term,
            revision,
            version: request.version,
            bundle_hash,
            acquired_unix_ms: now,
            expires_unix_ms: now.saturating_add(
                i64::try_from(request.ttl_secs)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1000),
            ),
        };

        self.persist_record(&record)?;
        inner.record = Some(record.clone());
        self.ensure_initialized(&mut inner)?;
        Ok(record)
    }

    /// Renews the current lease according to the ADR CAS rules.
    pub fn renew(&self, request: &RenewRequest) -> Result<LeaseRecord, LeaseOpError> {
        validate_holder_shape(&request.holder)
            .map_err(|error| LeaseOpError::invalid(error.code(), error.message()))?;
        validate_ttl(request.ttl_secs)
            .map_err(|error| LeaseOpError::invalid(error.code(), error.message()))?;
        let bundle_hash = normalize_bundle_hash(request.version, &request.bundle_hash)
            .map_err(|error| LeaseOpError::invalid(error.code(), error.message()))?;

        let mut inner = self.lock_inner();
        let now = self.clock.now_unix_ms();
        let Some(current) = inner.record.clone() else {
            return Err(LeaseOpError::conflict(
                "lease_record_missing",
                "the witness has no lease record; acquire a new term",
                None,
            ));
        };
        if current.is_expired(now) {
            return Err(LeaseOpError::conflict(
                "lease_expired",
                format!(
                    "lease expired at {}; acquire term {}",
                    current.expires_unix_ms,
                    current.term.saturating_add(1)
                ),
                Some(current),
            ));
        }
        if current.holder != request.holder {
            return Err(LeaseOpError::conflict(
                "holder_mismatch",
                "the lease is held by a different holder",
                Some(current),
            ));
        }
        if current.term != request.term {
            return Err(LeaseOpError::conflict(
                "term_mismatch",
                format!("the lease term is {}", current.term),
                Some(current),
            ));
        }
        if current.revision != request.expected_revision {
            return Err(LeaseOpError::conflict(
                "revision_mismatch",
                format!("the lease revision is {}", current.revision),
                Some(current),
            ));
        }
        validate_version_rule(
            request.version,
            &bundle_hash,
            current.version,
            &current.bundle_hash,
            Some(&current),
        )?;

        let revision = current.revision.checked_add(1).ok_or_else(|| {
            LeaseOpError::conflict(
                "revision_overflow",
                "lease revision overflow",
                Some(current.clone()),
            )
        })?;
        let record = LeaseRecord {
            schema: LEASE_SCHEMA,
            cluster_id: self.cluster_id.clone(),
            holder: current.holder,
            node_id: current.node_id,
            term: current.term,
            revision,
            version: request.version,
            bundle_hash,
            acquired_unix_ms: current.acquired_unix_ms,
            expires_unix_ms: now.saturating_add(
                i64::try_from(request.ttl_secs)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1000),
            ),
        };

        self.persist_record(&record)?;
        inner.record = Some(record.clone());
        Ok(record)
    }

    /// Offline recovery: raise the record above the cluster high-water mark.
    ///
    /// The new record is immediately expired so the next acquire can take over.
    /// The old record is backed up first. Monotonic checks refuse an equal or
    /// lower term/version.
    pub fn set_high_water(
        &self,
        term: u64,
        version: u64,
        bundle_hash: &str,
    ) -> Result<(LeaseRecord, Option<PathBuf>), WitnessError> {
        self.set_high_water_inner(term, version, bundle_hash, false)
    }

    /// Term-only recovery: raise the term while keeping the current version
    /// and bundle hash.
    ///
    /// This is required after an offline signing-key rotation. The rotation
    /// keeps the witness's **published** version/hash but raises the master's
    /// state term, so a strict version raise would either fail
    /// `version_not_raised` (same version) or push the witness above the
    /// cluster's published baseline (`master_state_behind` on acquisition).
    ///
    /// An equal version is accepted only with the exact current bundle hash;
    /// a lower term/version is still refused, as is an equal version with a
    /// different hash.
    pub fn set_high_water_allow_equal_version(
        &self,
        term: u64,
        version: u64,
        bundle_hash: &str,
    ) -> Result<(LeaseRecord, Option<PathBuf>), WitnessError> {
        self.set_high_water_inner(term, version, bundle_hash, true)
    }

    fn set_high_water_inner(
        &self,
        term: u64,
        version: u64,
        bundle_hash: &str,
        allow_equal_version: bool,
    ) -> Result<(LeaseRecord, Option<PathBuf>), WitnessError> {
        let bundle_hash = normalize_bundle_hash(version, bundle_hash)?;
        let mut inner = self.lock_inner();
        let Some(old) = inner.record.clone() else {
            return Err(WitnessError::new(
                "state_missing",
                "cannot infer cluster_id without an existing lease record; restore the witness state backup first",
            ));
        };
        if term <= old.term {
            return Err(WitnessError::new(
                "term_not_raised",
                format!(
                    "--term {term} must be greater than the current term {}",
                    old.term
                ),
            ));
        }
        if version < old.version {
            return Err(WitnessError::new(
                "version_not_raised",
                format!(
                    "--version {version} must be greater than the current version {}",
                    old.version
                ),
            ));
        }
        if version == old.version {
            if !allow_equal_version {
                return Err(WitnessError::new(
                    "version_not_raised",
                    format!(
                        "--version {version} must be greater than the current version {} unless --allow-equal-version is used to raise only the term",
                        old.version
                    ),
                ));
            }
            let expected = normalize_bundle_hash(old.version, &old.bundle_hash)?;
            if bundle_hash != expected {
                return Err(WitnessError::new(
                    "bundle_hash_mismatch",
                    format!(
                        "--allow-equal-version requires the current bundle hash {expected} at version {version}, not {bundle_hash}"
                    ),
                ));
            }
        }

        let backup_path = self.backup_record()?;
        let revision = old
            .revision
            .checked_add(1)
            .ok_or_else(|| WitnessError::new("state_corrupt", "lease record revision overflow"))?;
        let record = LeaseRecord {
            schema: LEASE_SCHEMA,
            cluster_id: self.cluster_id.clone(),
            holder: format!("lease-admin/{}", random_boot_uuid()),
            node_id: "lease-admin".to_string(),
            term,
            revision,
            version,
            bundle_hash,
            // Timestamps are deliberately zero so the record is expired for
            // every non-negative witness clock, including after a backward
            // clock step between the offline tool and the witness start.
            acquired_unix_ms: 0,
            expires_unix_ms: 0,
        };
        self.persist_record(&record)?;
        inner.record = Some(record.clone());
        self.ensure_initialized(&mut inner)?;
        Ok((record, backup_path))
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, StoreInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn persist_record(&self, record: &LeaseRecord) -> Result<(), LeaseOpError> {
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|error| LeaseOpError::Storage(format!("serialize lease record: {error}")))?;
        let path = self.dir.join(LEASE_FILE);
        match write_atomic(&self.dir, &path, &bytes) {
            Ok(()) => Ok(()),
            Err(error) => Err(LeaseOpError::Storage(error.to_string())),
        }
    }

    fn ensure_initialized(&self, inner: &mut StoreInner) -> Result<(), LeaseOpError> {
        if inner.initialized {
            return Ok(());
        }
        let path = self.dir.join(INITIALIZED_FILE);
        match write_atomic(&self.dir, &path, b"initialized\n") {
            Ok(()) => {
                inner.initialized = true;
                Ok(())
            }
            Err(error) => Err(LeaseOpError::Storage(format!(
                "lease record was written but the initialized sentinel failed: {error}"
            ))),
        }
    }

    fn backup_record(&self) -> Result<Option<PathBuf>, WitnessError> {
        let path = self.dir.join(LEASE_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let mut backup = self.dir.join(format!("{LEASE_FILE}.bak"));
        if backup.exists() {
            backup = self
                .dir
                .join(format!("{LEASE_FILE}.bak.{}", self.clock.now_unix_ms()));
        }
        let bytes = std::fs::read(&path).map_err(WitnessError::from)?;
        write_atomic(&self.dir, &backup, &bytes)?;
        Ok(Some(backup))
    }
}

fn validate_version_rule(
    version: u64,
    bundle_hash: &str,
    current_version: u64,
    current_hash: &str,
    current: Option<&LeaseRecord>,
) -> Result<(), LeaseOpError> {
    if version < current_version {
        return Err(LeaseOpError::conflict(
            "version_regression",
            format!("version {version} is below the witness version {current_version}"),
            current.cloned(),
        ));
    }
    if version == current_version && bundle_hash != current_hash {
        return Err(LeaseOpError::conflict(
            "version_forked",
            format!("version {version} already exists with a different bundle hash"),
            current.cloned(),
        ));
    }
    if version > current_version.saturating_add(MAX_VERSION_LEAD) {
        return Err(LeaseOpError::conflict(
            "version_lead_too_large",
            format!("version may not exceed current + {MAX_VERSION_LEAD}"),
            current.cloned(),
        ));
    }
    Ok(())
}

fn random_boot_uuid() -> String {
    let bytes = rand::random::<u128>().to_be_bytes();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn record_present(dir: &Path) -> bool {
    dir.join(LEASE_FILE).exists()
}

/// Writes `bytes` atomically with mode 0600 and fsyncs the parent directory.
pub(crate) fn write_atomic(dir: &Path, path: &Path, bytes: &[u8]) -> Result<(), WitnessError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("lease");
    let tmp = dir.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        rand::random::<u64>()
    ));

    let write_result = (|| -> Result<(), std::io::Error> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(STATE_FILE_MODE_VALUE);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        let dir_file = File::open(dir)?;
        dir_file.sync_all()?;
        Ok(())
    })();

    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(WitnessError::new(
            "storage_error",
            format!("atomic write of '{}' failed: {error}", path.display()),
        ));
    }
    Ok(())
}
