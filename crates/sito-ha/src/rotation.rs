//! Offline rotation of the HA master Ed25519 signing key.
//!
//! The normal startup path deliberately refuses to sign persisted state with a
//! key that does not match `ha_state.toml`'s `signing_key_pubkey`. Replacing the
//! key therefore needs an explicit operator action: this module implements the
//! safe subset used by `sito ha rotate-signing-key`.
//!
//! The operation is offline and local:
//!
//! * the service lease must not be held (the caller checks and holds it);
//! * the old key and `ha_state.toml` are copied to mode-`0600` backups before
//!   anything is mutated;
//! * a new Ed25519 key is generated at `<data_dir>/ha_signing.key` (mode `0600`);
//! * `ha_state.toml` is re-sealed with the new public key and a strictly higher
//!   term and version;
//! * no witness request, lease acquisition, publish or network I/O is performed.
//!
//! This is not a dual-key protocol. Slaves still trust exactly one
//! `master_pubkey`; the higher term is what tells an existing slave that a new
//! signing identity is intentional. Every slave must be reconfigured and
//! restarted before it can verify the next push.

use std::path::{Path, PathBuf};

use crate::bundle::{build_and_sign_push, push_payload_hash, seal_bundle_identity};
use crate::crypto::Ed25519SigningKey;
use crate::crypto::signing::write_private_exclusive;
use crate::error::HaError;
use crate::promotion::state::{HaStateStore, LoadedState, PublicationBaseline};

use sito_ha_types::status::PublicationState;

/// Name of the master Ed25519 key inside `server.data_dir`.
pub const SIGNING_KEY_FILE: &str = "ha_signing.key";
/// Name of the persisted master state inside `server.data_dir`.
pub const HA_STATE_FILE: &str = "ha_state.toml";

/// Result of a successful offline signing-key rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyRotation {
    /// Path of the replaced private key.
    pub key_path: PathBuf,
    /// Path of the re-sealed state file.
    pub state_path: PathBuf,
    /// Mode-`0600` backup of the previous private key.
    pub key_backup: PathBuf,
    /// Mode-`0600` backup of the previous `ha_state.toml`.
    pub state_backup: PathBuf,
    /// Hex public key that signed the previous state.
    pub previous_pubkey: String,
    /// New hex public key for every slave's `[ha] master_pubkey`.
    pub master_pubkey: String,
    /// New standard-Base64 public key (accepted by the same parser).
    pub master_pubkey_b64: String,
    /// Term recorded by the previous state.
    pub previous_term: u64,
    /// Version recorded by the previous state.
    pub previous_version: u64,
    /// Term written to the re-sealed state.
    pub term: u64,
    /// Version written to the re-sealed state.
    pub version: u64,
    /// Signed-payload hash of the staged rotated bundle, when the state file
    /// already carried promotion bookkeeping. `None` for a legacy state file
    /// that never had it.
    pub pending_hash: Option<String>,
    /// Published baseline preserved from the old state. `None` for a legacy
    /// state that never carried promotion bookkeeping. A promotion-enabled
    /// cluster must give these exact values to its offline witness update;
    /// they are never the rotated pending version/hash.
    pub published_baseline: Option<PublicationBaseline>,
}

/// Rotates the master signing key and re-seals `ha_state.toml` offline.
///
/// `requested_term`/`requested_version` are the operator's explicit values.
/// When omitted, the term is `current + 1` and the version is
/// `max(active bundle version, published baseline version) + 1`. Both values
/// must be strictly greater than those floors; equal or lower values are
/// refused so a slave's same-term key-change guard can never be bypassed.
///
/// # Caller contract
///
/// This library entry point does not inspect the service lease and does not
/// require a confirmation flag; those are operator-UX guards enforced by
/// `sito ha rotate-signing-key`. A direct caller must stop the HA master and
/// exclude every running server from `data_dir` for the whole call, and must
/// invoke it only after an explicit operator decision. The function performs
/// no witness or network I/O.
pub fn rotate_master_signing_key(
    data_dir: &Path,
    requested_term: Option<u64>,
    requested_version: Option<u64>,
) -> Result<SigningKeyRotation, HaError> {
    let key_path = data_dir.join(SIGNING_KEY_FILE);
    let state_path = data_dir.join(HA_STATE_FILE);

    let old_key_bytes = std::fs::read(&key_path).map_err(|error| {
        key_io_error(
            &key_path,
            &error,
            "cannot read the current signing key to back it up; restore it from backup or re-enroll every slave before rotating",
        )
    })?;
    let key_owner = capture_owner(&key_path, "ha_signing_key")?;
    let old_key = Ed25519SigningKey::from_pkcs8(&old_key_bytes).map_err(|error| {
        HaError::Validation {
            field: "ha_signing_key".to_string(),
            reason: format!(
                "signing key '{}' is corrupt ({error}); refusing to rotate. Restore the original key from backup",
                key_path.display()
            ),
        }
    })?;

    let store = HaStateStore::new(state_path.clone());
    let LoadedState::Present { state, bookkeeping } =
        store.load().map_err(|error| match error {
            HaError::Validation { field, reason } => HaError::Validation {
                field,
                reason: format!(
                    "refusing to rotate the signing key: {reason}. The state must be valid and match the current key before it can be re-sealed"
                ),
            },
            other => other,
        })?
    else {
        return Err(validation(
            "ha_state",
            format!(
                "no '{}' exists. Rotating a signing key requires a persisted master state to re-seal; start the current master once so it writes one (or follow the manual re-enrollment procedure), then stop it and retry",
                state_path.display()
            ),
        ));
    };
    let state_owner = capture_owner(&state_path, "ha_state")?;
    let mut state = *state;

    let recorded_pubkey = state.signing_key_pubkey.as_deref().ok_or_else(|| {
        validation(
            "ha_signing_key",
            format!(
                "'{}' does not record signing_key_pubkey, so the state cannot be bound to the current key. Start the current master once with this build (which records the identity), stop it, then retry",
                state_path.display()
            ),
        )
    })?;
    let recorded = crate::crypto::parse_public_key(recorded_pubkey).map_err(|error| {
        validation(
            "ha_signing_key",
            format!(
                "'{recorded_pubkey}' in '{}' is not a valid Ed25519 public key: {error}",
                state_path.display()
            ),
        )
    })?;
    let actual = old_key.public_key();
    if recorded != actual {
        return Err(validation(
            "ha_signing_key",
            format!(
                "key/state identity mismatch: '{}' records signing key {}, but '{}' contains {}. Restore the matching key/state backup (or follow the manual re-enrollment procedure); refusing to silently re-sign the state",
                state_path.display(),
                hex::encode(recorded),
                key_path.display(),
                hex::encode(actual)
            ),
        ));
    }
    let expected_fingerprint = crate::bundle::signing_key_fingerprint(&actual);
    if normalize_fingerprint(&state.bundle.signing_key_fingerprint)
        != normalize_fingerprint(&expected_fingerprint)
    {
        return Err(validation(
            "ha_signing_key",
            format!(
                "the active bundle in '{}' records signing_key_fingerprint '{}', but the loaded key is {}. The state is internally inconsistent and cannot be safely re-sealed; restore a matching state/key backup",
                state_path.display(),
                state.bundle.signing_key_fingerprint,
                expected_fingerprint
            ),
        ));
    }

    if bookkeeping
        .as_ref()
        .is_some_and(crate::promotion::PromotionBookkeeping::has_pending_bundle)
    {
        return Err(validation(
            "ha_state",
            format!(
                "'{}' carries a pending/publishing bundle (version {}). Reconciliation must decide whether it was published before a key rotation can re-seal it; start the master once, let it reconcile, stop it, then retry",
                state_path.display(),
                state.bundle.version
            ),
        ));
    }

    let previous_term = state.bundle.term;
    let previous_version = state.bundle.version;
    let published_baseline = bookkeeping.as_ref().map(|bookkeeping| PublicationBaseline {
        version: bookkeeping.published_version,
        hash: bookkeeping.published_hash.clone(),
    });
    // Never move the version below a published baseline that is ahead of the
    // active bundle. The witness/promotion baseline is part of the current
    // state even when a crash/recovery left the bundle behind it.
    let version_floor = previous_version.max(state.published_version.unwrap_or(0));
    let term = next_monotonic("term", previous_term, requested_term)?;
    let version = next_monotonic("version", version_floor, requested_version)?;

    // Assemble the new key/state completely before touching the data
    // directory. The signed push is built only to compute the staged payload
    // hash; it is never sent anywhere.
    let new_key = Ed25519SigningKey::generate()?;
    let new_pubkey = new_key.public_key_hex();
    let new_pubkey_b64 = new_key.public_key_b64();

    let mut bundle = state.bundle.clone();
    bundle.version = version;
    bundle.term = term;
    bundle.timestamp = now_unix_ms();
    seal_bundle_identity(&mut bundle, &new_key.public_key());
    let staged_push = build_and_sign_push(&bundle, &new_key)?;
    let staged_hash = push_payload_hash(&staged_push)?;

    let pending_hash = if bookkeeping.is_some() || state.publication_state.is_some() {
        // The published baseline stays exactly what the witness last saw. The
        // rotated bundle is staged, not published: no witness or slave was
        // contacted by this command.
        state.publication_state = Some(PublicationState::Pending);
        state.pending_hash = Some(staged_hash.clone());
        Some(staged_hash)
    } else {
        // A pre-promotion state has no publication bookkeeping. Do not invent
        // a baseline: the next promotion-enabled start must reconcile.
        state.pending_hash = None;
        None
    };
    state.bundle = bundle;
    state.signing_key_pubkey = Some(new_pubkey.clone());

    let backup_stamp = now_unix_ms();
    let key_backup = backup_private(
        &key_path,
        data_dir,
        backup_stamp,
        "ha_signing_key",
        key_owner,
    )?;
    let state_backup =
        backup_private(&state_path, data_dir, backup_stamp, "ha_state", state_owner)?;

    // From here on the old key/state are recoverable from the two backups.
    replace_private_atomic(&key_path, new_key.pkcs8_bytes(), key_owner).map_err(|error| {
        validation(
            "ha_signing_key",
            format!(
                "failed to write the new signing key '{}': {error}. The previous key is backed up at '{}' and was not changed",
                key_path.display(),
                key_backup.display()
            ),
        )
    })?;

    let save_result = if let Some(error) = take_injected_failure(FAILURE_STATE_WRITE) {
        Err(error)
    } else {
        match store.save(&state) {
            Ok(()) => match take_injected_failure(FAILURE_STATE_OWNER) {
                Some(error) => Err(error),
                None => apply_owner(&state_path, state_owner, "ha_state"),
            },
            Err(error) => Err(error),
        }
    };
    if let Err(error) = save_result {
        // The state file may already have been replaced by `store.save` even
        // when ownership transfer failed. Restore both files so the key and
        // state cannot be left as a mismatched pair.
        let key_rollback = restore_backup(&key_path, &key_backup, key_owner);
        let state_rollback = restore_backup(&state_path, &state_backup, state_owner);
        return Err(validation(
            "ha_state",
            if key_rollback.is_ok() && state_rollback.is_ok() {
                format!(
                    "failed to re-seal '{}': {error}. Both previous files were restored from '{}' and '{}'; no rotation was applied",
                    state_path.display(),
                    key_backup.display(),
                    state_backup.display()
                )
            } else {
                format!(
                    "failed to re-seal '{}': {error}. Automatic restore failed; restore '{}' over '{}' and '{}' over '{}' manually before restarting",
                    state_path.display(),
                    key_backup.display(),
                    key_path.display(),
                    state_backup.display(),
                    state_path.display()
                )
            },
        ));
    }

    // Read everything back from disk: the command must not report success for
    // a key/state pair that the next startup would reject.
    let verify = match take_injected_failure(FAILURE_VERIFY) {
        Some(error) => Err(error),
        None => verify_rotated_files(
            &key_path,
            &state_path,
            previous_version,
            key_owner,
            state_owner,
        ),
    };
    if let Err(error) = verify {
        let key_rollback = restore_backup(&key_path, &key_backup, key_owner);
        let state_rollback = restore_backup(&state_path, &state_backup, state_owner);
        return Err(validation(
            "ha_signing_key",
            if key_rollback.is_ok() && state_rollback.is_ok() {
                format!(
                    "post-rotation verification failed: {error}. Both files were restored from '{}' and '{}'",
                    key_backup.display(),
                    state_backup.display()
                )
            } else {
                format!(
                    "post-rotation verification failed: {error}. Automatic restore failed; restore '{}' and '{}' manually",
                    key_backup.display(),
                    state_backup.display()
                )
            },
        ));
    }

    Ok(SigningKeyRotation {
        key_path,
        state_path,
        key_backup,
        state_backup,
        previous_pubkey: hex::encode(actual),
        master_pubkey: new_pubkey,
        master_pubkey_b64: new_pubkey_b64,
        previous_term,
        previous_version,
        term,
        version,
        pending_hash,
        published_baseline,
    })
}

/// Returns `current + 1`, or the operator's value, refusing any value that is
/// not strictly greater than the current state or that consumes the ceiling.
fn next_monotonic(field: &str, current: u64, requested: Option<u64>) -> Result<u64, HaError> {
    let candidate = match requested {
        Some(value) => value,
        None => current.checked_add(1).ok_or_else(|| {
            validation(
                field,
                format!(
                    "current {field} {current} can never advance; restore the state from backup"
                ),
            )
        })?,
    };
    if candidate <= current {
        return Err(validation(
            field,
            format!(
                "requested {field} {candidate} must be strictly greater than the current {field} {current}; a same-term/same-version key change is refused by every slave"
            ),
        ));
    }
    if candidate == u64::MAX {
        return Err(validation(
            field,
            format!(
                "requested {field} u64::MAX can never advance again; choose a lower value above {current}"
            ),
        ));
    }
    Ok(candidate)
}

/// Verifies that the files on disk are exactly the key/state pair the startup
/// path expects, and that the rotated bundle verifies with the new public key.
fn verify_rotated_files(
    key_path: &Path,
    state_path: &Path,
    have_version: u64,
    key_owner: FileOwner,
    state_owner: FileOwner,
) -> Result<(), HaError> {
    // A root-run rotation must not leave a file the service user cannot read.
    apply_owner(key_path, key_owner, "ha_signing_key")?;
    apply_owner(state_path, state_owner, "ha_state")?;
    let key_bytes = std::fs::read(key_path).map_err(|error| {
        validation(
            "ha_signing_key",
            format!("cannot read back '{}': {error}", key_path.display()),
        )
    })?;
    let key = Ed25519SigningKey::from_pkcs8(&key_bytes).map_err(|error| {
        validation(
            "ha_signing_key",
            format!(
                "cannot parse the written key '{}': {error}",
                key_path.display()
            ),
        )
    })?;
    let LoadedState::Present { state, .. } = HaStateStore::new(state_path.to_path_buf()).load()?
    else {
        return Err(validation(
            "ha_state",
            format!("'{}' disappeared during rotation", state_path.display()),
        ));
    };
    let expected = key.public_key_hex();
    if state.signing_key_pubkey.as_deref() != Some(expected.as_str()) {
        return Err(validation(
            "ha_signing_key",
            format!(
                "'{}' records signing_key_pubkey '{}', but the written key is {expected}",
                state_path.display(),
                state.signing_key_pubkey.as_deref().unwrap_or("<none>")
            ),
        ));
    }
    let push = build_and_sign_push(&state.bundle, &key)?;
    // The next startup would refuse an oversized push. Fail the rotation now,
    // while both previous files are still recoverable from backup.
    crate::master::MasterCoordinator::ensure_push_fits(&push)?;
    crate::bundle::verify_and_unpack_push(&push, have_version, &key.public_key()).map_err(
        |error| {
            validation(
                "ha_signing_key",
                format!("the re-sealed bundle does not verify with the new key: {error}"),
            )
        },
    )?;
    Ok(())
}

fn normalize_fingerprint(value: &str) -> &str {
    value.trim().trim_start_matches("blake3:")
}

fn now_unix_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

fn validation(field: &str, reason: impl Into<String>) -> HaError {
    HaError::Validation {
        field: field.to_string(),
        reason: reason.into(),
    }
}

fn key_io_error(path: &Path, error: &std::io::Error, context: &str) -> HaError {
    if error.kind() == std::io::ErrorKind::NotFound {
        validation(
            "ha_signing_key",
            format!(
                "signing key '{}' is missing; {context}. A rotation never invents a key that has no matching state",
                path.display()
            ),
        )
    } else {
        HaError::Io(std::io::Error::new(
            error.kind(),
            format!("{context}: '{}': {error}", path.display()),
        ))
    }
}

/// Owner of an existing HA file, preserved across a root-run rotation.
///
/// The server usually runs as an unprivileged service user. Running the CLI
/// with `sudo` must not leave a root-owned key, state or backup that the
/// service can no longer read.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileOwner {
    uid: u32,
    gid: u32,
}

/// Owner placeholder for platforms without Unix ownership.
#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileOwner;

fn capture_owner(path: &Path, field: &str) -> Result<FileOwner, HaError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::metadata(path).map_err(|error| {
            validation(
                field,
                format!("cannot read the ownership of '{}': {error}", path.display()),
            )
        })?;
        Ok(FileOwner {
            uid: metadata.uid(),
            gid: metadata.gid(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, field);
        Ok(FileOwner)
    }
}

/// Applies `owner` to `path`, refusing a privileged mismatch.
fn apply_owner(path: &Path, owner: FileOwner, field: &str) -> Result<(), HaError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::metadata(path).map_err(|error| {
            validation(
                field,
                format!("cannot read the ownership of '{}': {error}", path.display()),
            )
        })?;
        if metadata.uid() == owner.uid && metadata.gid() == owner.gid {
            return Ok(());
        }
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            return Err(validation(
                field,
                format!(
                    "'{}' is owned by {}:{} but this command runs as uid {euid}; run it as root or as the service user so the server can still read its key/state",
                    path.display(),
                    owner.uid,
                    owner.gid
                ),
            ));
        }
        std::os::unix::fs::chown(path, Some(owner.uid), Some(owner.gid)).map_err(|error| {
            validation(
                field,
                format!(
                    "cannot restore ownership {}:{} on '{}': {error}",
                    owner.uid,
                    owner.gid,
                    path.display()
                ),
            )
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, owner, field);
        Ok(())
    }
}

/// Copies `source` to a new mode-`0600` backup next to the data directory.
///
/// `create_new` is used so an existing backup is never overwritten; a
/// timestamp collision gets a numeric suffix. A failed copy (including
/// ownership transfer) aborts the rotation before any source file is mutated.
fn backup_private(
    source: &Path,
    data_dir: &Path,
    stamp: u64,
    field: &str,
    owner: FileOwner,
) -> Result<PathBuf, HaError> {
    let bytes = std::fs::read(source).map_err(|error| {
        key_io_error(
            source,
            &error,
            "cannot read the file to back it up before rotation",
        )
    })?;
    let name = source.file_name().map_or_else(
        || "ha_backup".to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    for attempt in 0..1000u32 {
        let suffix = if attempt == 0 {
            format!("bak.{stamp}")
        } else {
            format!("bak.{stamp}.{attempt}")
        };
        let candidate = data_dir.join(format!("{name}.{suffix}"));
        match write_private_exclusive(&candidate, &bytes) {
            Ok(()) => {
                if let Err(error) = apply_owner(&candidate, owner, field) {
                    let _ = std::fs::remove_file(&candidate);
                    return Err(validation(
                        field,
                        format!(
                            "{error}. The rotation was aborted before any source file was changed"
                        ),
                    ));
                }
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(validation(
                    field,
                    format!(
                        "failed to write the backup '{}' before rotation: {error}. Nothing was changed",
                        candidate.display()
                    ),
                ));
            }
        }
    }
    Err(validation(
        field,
        format!(
            "could not allocate a unique backup name next to '{}'; remove stale backups and retry",
            source.display()
        ),
    ))
}

/// Replaces `path` with `bytes` using a mode-`0600` temporary file, fsync and
/// rename, so the key is never briefly world-readable or half-written.
fn replace_private_atomic(path: &Path, bytes: &[u8], owner: FileOwner) -> std::io::Result<()> {
    let tmp = match path.parent() {
        Some(parent) => parent.join(format!(
            "{}.new.{}.{}",
            path.file_name().map_or_else(
                || "ha_signing.key".to_string(),
                |name| name.to_string_lossy().into_owned()
            ),
            std::process::id(),
            rand::random::<u64>()
        )),
        None => path.with_extension("new"),
    };
    let result = (|| {
        write_private_exclusive(&tmp, bytes)?;
        apply_owner_io(&tmp, owner)?;
        std::fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent()
            && let Ok(dir) = std::fs::File::open(parent)
        {
            // Best effort: the rename is already atomic; a directory fsync
            // makes the new name durable across a power loss.
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Restores `path` from a previously written private backup.
fn restore_backup(path: &Path, backup: &Path, owner: FileOwner) -> std::io::Result<()> {
    let bytes = std::fs::read(backup)?;
    replace_private_atomic(path, &bytes, owner)
}

/// Unix implementation of [`apply_owner`] for the atomic-write path.
fn apply_owner_io(path: &Path, owner: FileOwner) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::metadata(path)?;
        if metadata.uid() == owner.uid && metadata.gid() == owner.gid {
            return Ok(());
        }
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "'{}' is owned by {}:{} but this command runs as uid {euid}",
                    path.display(),
                    owner.uid,
                    owner.gid
                ),
            ));
        }
        std::os::unix::fs::chown(path, Some(owner.uid), Some(owner.gid))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, owner);
        Ok(())
    }
}

const FAILURE_STATE_WRITE: u8 = 1;
const FAILURE_VERIFY: u8 = 2;
const FAILURE_STATE_OWNER: u8 = 3;

#[cfg(test)]
thread_local! {
    static INJECTED_FAILURE: std::cell::Cell<Option<u8>> = const { std::cell::Cell::new(None) };
}

/// Test-only fault injection at a named rotation step. Production builds
/// always return `None`.
fn take_injected_failure(point: u8) -> Option<HaError> {
    #[cfg(test)]
    {
        INJECTED_FAILURE.with(|cell| {
            if cell.get() == Some(point) {
                cell.set(None);
                Some(validation(
                    "ha_test_failure",
                    format!("injected rotation failure at step {point}"),
                ))
            } else {
                None
            }
        })
    }
    #[cfg(not(test))]
    {
        let _ = point;
        None
    }
}

#[cfg(test)]
fn inject_failure(point: u8) {
    INJECTED_FAILURE.with(|cell| cell.set(Some(point)));
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    use crate::bundle::{AppliedWatermark, build_and_sign_push, signing_key_fingerprint};
    use crate::master::coordinator::PersistedMasterState;
    use crate::protocol::PROTOCOL_VERSION;
    use sito_ha_types::status::PublicationState;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sito_ha_rotation_{label}_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn bundle(version: u64, term: u64) -> crate::bundle::ConfigBundle {
        crate::bundle::ConfigBundle {
            version,
            term,
            timestamp: 1,
            config_toml: "config_version = 2\n[server]\nrole = \"slave\"\n".to_string(),
            ..crate::bundle::ConfigBundle::default()
        }
    }

    struct Fixture {
        dir: PathBuf,
        key: Ed25519SigningKey,
        key_path: PathBuf,
        state_path: PathBuf,
        version: u64,
        term: u64,
        old_hash: String,
        old_watermark: AppliedWatermark,
    }

    fn fixture(label: &str) -> Fixture {
        let dir = temp_dir(label);
        let key_path = dir.join(SIGNING_KEY_FILE);
        let key = Ed25519SigningKey::load_or_create(&key_path).unwrap();
        let state_path = dir.join(HA_STATE_FILE);

        let version = 7;
        let term = 3;
        let mut bundle = bundle(version, term);
        seal_bundle_identity(&mut bundle, &key.public_key());
        let push = build_and_sign_push(&bundle, &key).unwrap();
        let hash = push_payload_hash(&push).unwrap();
        let state = PersistedMasterState {
            protocol_version: PROTOCOL_VERSION,
            bundle,
            signing_key_pubkey: Some(key.public_key_hex()),
            publication_state: Some(PublicationState::Published),
            published_version: Some(version),
            published_hash: Some(hash.clone()),
            pending_hash: None,
            promotion_origin: None,
            lease_holder: None,
            cluster_id: Some("home-dns".to_string()),
            node_id: Some("node-a".to_string()),
            promoted_at_unix_ms: None,
            last_applied_version: Some(version),
            last_applied_hash: Some(hash.clone()),
        };
        HaStateStore::new(state_path.clone()).save(&state).unwrap();
        let old_watermark = AppliedWatermark {
            protocol_version: PROTOCOL_VERSION,
            version,
            term,
            payload_hash: hash.clone(),
            signing_key_fingerprint: Some(signing_key_fingerprint(&key.public_key())),
            timestamp: 1,
            forked: false,
            forked_at_version: 0,
            applied_config_digest: None,
        };

        Fixture {
            dir,
            key,
            key_path,
            state_path,
            version,
            term,
            old_hash: hash,
            old_watermark,
        }
    }

    fn unix_mode(path: &Path) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            0o600
        }
    }

    #[test]
    fn test_rotation_writes_new_key_backs_up_and_reseals_state() {
        let fixture = fixture("happy");
        let old_key_bytes = std::fs::read(&fixture.key_path).unwrap();
        let old_state_bytes = std::fs::read(&fixture.state_path).unwrap();
        let old_key_owner = capture_owner(&fixture.key_path, "ha_signing_key").unwrap();
        let old_state_owner = capture_owner(&fixture.state_path, "ha_state").unwrap();

        let rotated = rotate_master_signing_key(&fixture.dir, None, None).expect("rotate the key");

        assert_ne!(rotated.master_pubkey, fixture.key.public_key_hex());
        assert_eq!(rotated.previous_pubkey, fixture.key.public_key_hex());
        assert_eq!(rotated.previous_version, fixture.version);
        assert_eq!(rotated.previous_term, fixture.term);
        assert_eq!(rotated.version, fixture.version + 1);
        assert_eq!(rotated.term, fixture.term + 1);
        assert!(rotated.pending_hash.is_some());
        assert_eq!(
            rotated.published_baseline,
            Some(PublicationBaseline {
                version: fixture.version,
                hash: fixture.old_hash.clone(),
            })
        );
        assert_ne!(
            rotated.published_baseline.as_ref().unwrap().hash,
            rotated.pending_hash.clone().unwrap(),
            "the witness baseline must stay the published hash, never the pending rotation hash"
        );

        // The old key/state are byte-for-byte recoverable from the backups.
        assert_eq!(std::fs::read(&rotated.key_backup).unwrap(), old_key_bytes);
        assert_eq!(
            std::fs::read(&rotated.state_backup).unwrap(),
            old_state_bytes
        );
        assert_eq!(unix_mode(&rotated.key_backup), 0o600);
        assert_eq!(unix_mode(&rotated.state_backup), 0o600);
        assert_eq!(
            capture_owner(&rotated.key_backup, "ha_signing_key").unwrap(),
            old_key_owner
        );
        assert_eq!(
            capture_owner(&rotated.state_backup, "ha_state").unwrap(),
            old_state_owner
        );
        assert_eq!(
            capture_owner(&rotated.key_path, "ha_signing_key").unwrap(),
            old_key_owner
        );
        assert_eq!(
            capture_owner(&rotated.state_path, "ha_state").unwrap(),
            old_state_owner
        );

        // The new key and re-sealed state are 0600, and the key is the only
        // private key at the canonical path.
        assert_eq!(unix_mode(&rotated.key_path), 0o600);
        assert_eq!(unix_mode(&rotated.state_path), 0o600);
        assert_ne!(std::fs::read(&rotated.key_path).unwrap(), old_key_bytes);
        let new_key =
            Ed25519SigningKey::from_pkcs8(&std::fs::read(&rotated.key_path).unwrap()).unwrap();
        assert_eq!(new_key.public_key_hex(), rotated.master_pubkey);
        assert_eq!(new_key.public_key_b64(), rotated.master_pubkey_b64);

        let LoadedState::Present { state, bookkeeping } =
            HaStateStore::new(rotated.state_path.clone())
                .load()
                .unwrap()
        else {
            panic!("state must exist");
        };
        assert_eq!(
            state.signing_key_pubkey.as_deref(),
            Some(rotated.master_pubkey.as_str())
        );
        assert_eq!(state.bundle.version, fixture.version + 1);
        assert_eq!(state.bundle.term, fixture.term + 1);
        assert_eq!(
            normalize_fingerprint(&state.bundle.signing_key_fingerprint),
            normalize_fingerprint(&signing_key_fingerprint(&new_key.public_key()))
        );
        let bookkeeping = bookkeeping.expect("promotion bookkeeping is preserved");
        assert_eq!(bookkeeping.publication_state, PublicationState::Pending);
        assert_eq!(bookkeeping.published_version, fixture.version);
        assert_eq!(bookkeeping.published_hash, fixture.old_hash);
        assert_eq!(
            bookkeeping.pending_hash.as_deref(),
            rotated.pending_hash.as_deref()
        );

        // Compatibility: the rotated bundle is a valid push for a slave whose
        // watermark is the old term/version.
        let push = build_and_sign_push(&state.bundle, &new_key).unwrap();
        crate::bundle::verify_and_unpack_push_with_watermark(
            &push,
            Some(&fixture.old_watermark),
            &new_key.public_key(),
        )
        .expect("a slave with the new master_pubkey accepts the higher-term push");

        // The old public key cannot verify the new signature.
        let error = crate::bundle::verify_and_unpack_push(
            &push,
            fixture.version,
            &fixture.key.public_key(),
        )
        .expect_err("the old master_pubkey must reject the rotated signature");
        assert!(
            matches!(error, HaError::SignatureVerification(_)),
            "unexpected error: {error:?}"
        );

        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn test_old_key_no_longer_matches_rotated_state() {
        let fixture = fixture("old_key_fails_closed");
        rotate_master_signing_key(&fixture.dir, None, None).unwrap();

        let metrics = sito_stats::MetricsRegistry::new("0.1.0", "test");
        let coordinator = crate::master::MasterCoordinator::new(
            "node-a".to_string(),
            0,
            std::sync::Arc::new(fixture.key),
            metrics,
        )
        .with_state_path(fixture.state_path.clone());

        let error = coordinator
            .restore_state()
            .expect_err("startup with the old key must fail closed");
        assert!(
            matches!(error, HaError::Validation { ref field, .. } if field == "ha_signing_key"),
            "unexpected error: {error:?}"
        );
        assert!(
            error.to_string().contains("was written by signing key"),
            "the error must be actionable: {error}"
        );

        // The matching new key restores successfully and resumes at the
        // re-sealed version.
        let new_key =
            Ed25519SigningKey::from_pkcs8(&std::fs::read(&fixture.key_path).unwrap()).unwrap();
        let metrics = sito_stats::MetricsRegistry::new("0.1.0", "test");
        let coordinator = crate::master::MasterCoordinator::new(
            "node-a".to_string(),
            0,
            std::sync::Arc::new(new_key),
            metrics,
        )
        .with_state_path(fixture.state_path.clone());
        assert_eq!(
            coordinator.restore_state().unwrap(),
            Some(fixture.version + 1)
        );

        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn test_new_key_push_is_accepted_after_the_higher_term_and_version() {
        let fixture = fixture("new_key_accepted");
        let rotated = rotate_master_signing_key(&fixture.dir, Some(10), Some(20)).unwrap();
        let new_key =
            Ed25519SigningKey::from_pkcs8(&std::fs::read(&fixture.key_path).unwrap()).unwrap();
        let LoadedState::Present { state, .. } = HaStateStore::new(rotated.state_path.clone())
            .load()
            .unwrap()
        else {
            panic!("state must exist");
        };
        let push = build_and_sign_push(&state.bundle, &new_key).unwrap();
        assert!(
            crate::bundle::verify_and_unpack_push_with_watermark(
                &push,
                Some(&fixture.old_watermark),
                &new_key.public_key(),
            )
            .is_ok()
        );
        let error = crate::bundle::verify_and_unpack_push_with_watermark(
            &push,
            Some(&fixture.old_watermark),
            &fixture.key.public_key(),
        )
        .expect_err("the old public key cannot verify the new push");
        assert!(
            matches!(error, HaError::SignatureVerification(_)),
            "unexpected error: {error:?}"
        );
        assert_eq!(rotated.term, 10);
        assert_eq!(rotated.version, 20);
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn test_rotation_refuses_non_monotonic_term_and_version() {
        for (term, version) in [
            (Some(3), None),
            (Some(2), None),
            (None, Some(7)),
            (None, Some(1)),
            (Some(u64::MAX), None),
            (None, Some(u64::MAX)),
        ] {
            let fixture = fixture("non_monotonic");
            let old_key = std::fs::read(&fixture.key_path).unwrap();
            let error = rotate_master_signing_key(&fixture.dir, term, version)
                .expect_err("non-monotonic values must be refused");
            assert!(
                matches!(error, HaError::Validation { ref field, .. } if field == "term" || field == "version"),
                "unexpected error: {error:?}"
            );
            assert_eq!(std::fs::read(&fixture.key_path).unwrap(), old_key);
            let backups: Vec<_> = std::fs::read_dir(&fixture.dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains(".bak."))
                .collect();
            assert!(
                backups.is_empty(),
                "a refused rotation must not write backups"
            );
            let _ = std::fs::remove_dir_all(&fixture.dir);
        }
    }

    #[test]
    fn test_rotation_refuses_missing_or_corrupt_state_and_key() {
        // Missing state.
        let state_fixture = fixture("missing_state");
        std::fs::remove_file(&state_fixture.state_path).unwrap();
        let error =
            rotate_master_signing_key(&state_fixture.dir, None, None).expect_err("missing state");
        assert!(error.to_string().contains("no '"), "{error}");

        // Corrupt state.
        std::fs::write(&state_fixture.state_path, "not-json").unwrap();
        let error =
            rotate_master_signing_key(&state_fixture.dir, None, None).expect_err("corrupt state");
        assert!(error.to_string().contains("refusing to rotate"), "{error}");

        let _ = std::fs::remove_dir_all(&state_fixture.dir);

        // Missing key.
        let key_fixture = fixture("missing_key");
        std::fs::remove_file(&key_fixture.key_path).unwrap();
        let error =
            rotate_master_signing_key(&key_fixture.dir, None, None).expect_err("missing key");
        assert!(error.to_string().contains("is missing"), "{error}");

        // Corrupt key.
        std::fs::write(&key_fixture.key_path, b"not-a-pkcs8-key").unwrap();
        let error =
            rotate_master_signing_key(&key_fixture.dir, None, None).expect_err("corrupt key");
        assert!(error.to_string().contains("is corrupt"), "{error}");

        let _ = std::fs::remove_dir_all(&key_fixture.dir);
    }

    #[test]
    fn test_rotation_refuses_key_state_identity_mismatch() {
        let fixture = fixture("identity_mismatch");
        let other = Ed25519SigningKey::generate().unwrap();
        std::fs::write(&fixture.key_path, other.pkcs8_bytes()).unwrap();
        let old_state = std::fs::read(&fixture.state_path).unwrap();

        let error = rotate_master_signing_key(&fixture.dir, None, None)
            .expect_err("mismatched key/state must be refused");
        assert!(error.to_string().contains("identity mismatch"), "{error}");
        assert_eq!(
            std::fs::read(&fixture.key_path).unwrap(),
            other.pkcs8_bytes()
        );
        assert_eq!(std::fs::read(&fixture.state_path).unwrap(), old_state);

        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn test_rotation_refuses_an_unreconciled_pending_bundle() {
        let fixture = fixture("pending_bundle");
        let store = HaStateStore::new(fixture.state_path.clone());
        let LoadedState::Present { mut state, .. } = store.load().unwrap() else {
            panic!("state must exist");
        };
        state.publication_state = Some(PublicationState::Publishing);
        state.pending_hash = Some("ab".repeat(32));
        store.save(&state).unwrap();
        let old_key = std::fs::read(&fixture.key_path).unwrap();

        let error = rotate_master_signing_key(&fixture.dir, None, None)
            .expect_err("an unresolved publish must refuse rotation");
        assert!(error.to_string().contains("pending/publishing"), "{error}");
        assert_eq!(std::fs::read(&fixture.key_path).unwrap(), old_key);
        let backups = std::fs::read_dir(&fixture.dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".bak."))
            .count();
        assert_eq!(backups, 0);
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn test_rotation_version_floor_includes_published_baseline() {
        let fixture = fixture("published_floor");
        let store = HaStateStore::new(fixture.state_path.clone());
        let LoadedState::Present { mut state, .. } = store.load().unwrap() else {
            panic!("state must exist");
        };
        state.published_version = Some(20);
        state.published_hash = Some("cd".repeat(32));
        store.save(&state).unwrap();

        let rotated =
            rotate_master_signing_key(&fixture.dir, None, None).expect("rotate above baseline");
        assert_eq!(
            rotated.version, 21,
            "the rotated version must stay above the published baseline"
        );
        assert_eq!(rotated.previous_version, fixture.version);
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn test_state_write_failure_restores_the_old_key_and_state() {
        let fixture = fixture("state_write_failure");
        let old_key = std::fs::read(&fixture.key_path).unwrap();
        let old_state = std::fs::read(&fixture.state_path).unwrap();

        inject_failure(FAILURE_STATE_WRITE);
        let error = rotate_master_signing_key(&fixture.dir, None, None)
            .expect_err("the injected state write must fail the rotation");
        assert!(error.to_string().contains("failed to re-seal"), "{error}");
        assert_eq!(std::fs::read(&fixture.key_path).unwrap(), old_key);
        assert_eq!(std::fs::read(&fixture.state_path).unwrap(), old_state);
        let entries: Vec<_> = std::fs::read_dir(&fixture.dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries
                .iter()
                .any(|name| name.starts_with("ha_signing.key.bak.")),
            "the key backup must remain available: {entries:?}"
        );
        assert!(
            entries
                .iter()
                .any(|name| name.starts_with("ha_state.toml.bak.")),
            "the state backup must remain available: {entries:?}"
        );
        assert!(
            !entries.iter().any(|name| name.contains(".new.")),
            "no temporary key may be left behind: {entries:?}"
        );
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn test_state_owner_failure_restores_both_files() {
        let fixture = fixture("state_owner_failure");
        let old_key = std::fs::read(&fixture.key_path).unwrap();
        let old_state = std::fs::read(&fixture.state_path).unwrap();

        // The state save succeeds, then ownership transfer fails. The rollback
        // must restore the state as well as the key, not leave the new state
        // paired with the old key.
        inject_failure(FAILURE_STATE_OWNER);
        let error = rotate_master_signing_key(&fixture.dir, None, None)
            .expect_err("the injected ownership failure must fail the rotation");
        assert!(error.to_string().contains("failed to re-seal"), "{error}");
        assert!(
            error
                .to_string()
                .contains("Both previous files were restored"),
            "{error}"
        );
        assert_eq!(std::fs::read(&fixture.key_path).unwrap(), old_key);
        assert_eq!(std::fs::read(&fixture.state_path).unwrap(), old_state);
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn test_verification_failure_restores_both_files() {
        let fixture = fixture("verify_failure");
        let old_key = std::fs::read(&fixture.key_path).unwrap();
        let old_state = std::fs::read(&fixture.state_path).unwrap();

        inject_failure(FAILURE_VERIFY);
        let error = rotate_master_signing_key(&fixture.dir, None, None)
            .expect_err("the injected verification failure must fail the rotation");
        assert!(
            error
                .to_string()
                .contains("post-rotation verification failed"),
            "{error}"
        );
        assert_eq!(std::fs::read(&fixture.key_path).unwrap(), old_key);
        assert_eq!(std::fs::read(&fixture.state_path).unwrap(), old_state);
        let entries: Vec<_> = std::fs::read_dir(&fixture.dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries
                .iter()
                .any(|name| name.starts_with("ha_signing.key.bak.")),
            "{entries:?}"
        );
        assert!(
            entries
                .iter()
                .any(|name| name.starts_with("ha_state.toml.bak.")),
            "{entries:?}"
        );
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn test_rotation_has_no_witness_or_lease_side_effects() {
        let fixture = fixture("no_side_effects");
        // A witness state canary must stay byte-for-byte untouched, and no
        // lease/promotion marker may appear.
        let witness_dir = fixture.dir.join("witness-state");
        std::fs::create_dir_all(&witness_dir).unwrap();
        std::fs::write(witness_dir.join("lease.json"), b"{\"term\":3}").unwrap();
        std::fs::write(fixture.dir.join("ha_watermark.toml"), b"canary").unwrap();

        let before: Vec<_> = std::fs::read_dir(&fixture.dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        rotate_master_signing_key(&fixture.dir, None, None).unwrap();
        let after: Vec<_> = std::fs::read_dir(&fixture.dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();

        assert_eq!(
            std::fs::read(witness_dir.join("lease.json")).unwrap(),
            b"{\"term\":3}"
        );
        for name in [
            "ha_promote.confirm",
            "ha_fence.json",
            "ha_fence.pending",
            "sito.pid",
        ] {
            assert!(
                !fixture.dir.join(name).exists(),
                "rotation must not create {name}"
            );
        }
        assert_eq!(
            std::fs::read(fixture.dir.join("ha_watermark.toml")).unwrap(),
            b"canary"
        );
        // Only the key, the state and their two backups were added/changed.
        let mut expected: std::collections::BTreeSet<_> = before.into_iter().collect();
        assert!(expected.len() >= 4);
        let rotated_backups: Vec<_> = after
            .iter()
            .filter(|name| name.to_string_lossy().contains(".bak."))
            .cloned()
            .collect();
        assert_eq!(rotated_backups.len(), 2);
        expected.extend(rotated_backups);
        let after: std::collections::BTreeSet<_> = after.into_iter().collect();
        assert_eq!(
            expected, after,
            "rotation must not create witness/lease/promotion files"
        );

        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn test_repeated_rotation_keeps_distinct_private_backups() {
        let fixture = fixture("repeat");
        let first = rotate_master_signing_key(&fixture.dir, None, None).unwrap();
        // Model the master publishing the rotated bundle before a second
        // rotation: a pending bundle deliberately refuses another rotation.
        let store = HaStateStore::new(fixture.state_path.clone());
        let LoadedState::Present { mut state, .. } = store.load().unwrap() else {
            panic!("state must exist");
        };
        state.publication_state = Some(PublicationState::Published);
        state.published_version = Some(first.version);
        state.published_hash = first.pending_hash.clone();
        state.pending_hash = None;
        store.save(&state).unwrap();

        let second = rotate_master_signing_key(&fixture.dir, None, None).unwrap();
        assert_ne!(first.key_backup, second.key_backup);
        assert_ne!(first.state_backup, second.state_backup);
        assert!(first.key_backup.exists());
        assert!(second.key_backup.exists());
        assert_eq!(unix_mode(&second.key_backup), 0o600);
        assert_eq!(unix_mode(&second.state_backup), 0o600);
        assert_eq!(second.previous_pubkey, first.master_pubkey);
        assert_eq!(second.version, fixture.version + 2);
        assert_eq!(second.term, fixture.term + 2);
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }
}
