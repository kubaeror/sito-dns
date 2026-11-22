//! Offline `sito ha lease-admin set` recovery tool.

use std::path::PathBuf;
use std::sync::Arc;

use super::WitnessError;
use super::clock::SystemClock;
use super::record::LeaseRecord;
use super::store::{LEASE_FILE, LeaseStore};

/// Result of an offline high-water update.
#[derive(Debug, Clone)]
pub struct LeaseAdminOutcome {
    /// The new, immediately expired record.
    pub record: LeaseRecord,
    /// Backup of the previous record, when one existed.
    pub backup_path: Option<PathBuf>,
}

/// Raises an offline witness record above the cluster high-water mark.
///
/// The witness must be stopped: the function takes the same lifetime
/// `lease.lock` and returns `state_locked` while a witness process is running.
/// The previous `lease.json` is copied to a 0600 backup first. The new record is
/// immediately expired so the next `acquire` takes over at `term + 1`.
///
/// `cluster_id` is read from the existing record; the tool never invents or
/// changes it.
pub fn lease_admin_set(
    state_dir: &std::path::Path,
    term: u64,
    version: u64,
    bundle_hash: &str,
) -> Result<LeaseAdminOutcome, WitnessError> {
    lease_admin_set_with_clock(
        state_dir,
        term,
        version,
        bundle_hash,
        Arc::new(SystemClock::new()),
    )
}

/// Like [`lease_admin_set`], with an explicit witness clock (tests).
pub fn lease_admin_set_with_clock(
    state_dir: &std::path::Path,
    term: u64,
    version: u64,
    bundle_hash: &str,
    clock: Arc<dyn super::clock::Clock>,
) -> Result<LeaseAdminOutcome, WitnessError> {
    let record_path = state_dir.join(LEASE_FILE);
    let bytes = std::fs::read(&record_path).map_err(|error| {
        WitnessError::new(
            "state_missing",
            format!(
                "cannot read '{}': {error}; restore the witness state backup first",
                record_path.display()
            ),
        )
    })?;
    let existing: LeaseRecord = serde_json::from_slice(&bytes).map_err(|error| {
        WitnessError::new(
            "state_corrupt",
            format!("cannot parse '{}': {error}", record_path.display()),
        )
    })?;
    let store = LeaseStore::open(state_dir, &existing.cluster_id, clock)?;
    let (record, backup_path) = store.set_high_water(term, version, bundle_hash)?;
    Ok(LeaseAdminOutcome {
        record,
        backup_path,
    })
}
