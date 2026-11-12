//! Authentication, session, TOTP, and API-token manager.
//!
//! The facade keeps the public `AuthManager` surface and the shared data types;
//! each sibling module owns one credential lifecycle.

//! AuthManager coordinating passwords, TOTP, sessions, API tokens, and RBAC.

use crate::auth::lockout::LockoutTracker;
use crate::auth::password::{hash_password, verify_password};
use crate::auth::secret_store::TotpSecretStore;
use crate::auth::session::{DEFAULT_SESSION_TTL_SECS, Session};
use crate::auth::token::{ApiTokenMeta, CreateTokenResponse, Role, generate_token, hash_token};
use crate::auth::totp::{TotpConfig, TotpSetupResponse};
use crate::models::UserDto;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

/// Outcome of the first login phase (`POST /auth/login`).
#[derive(Debug, Clone)]
pub enum LoginResult {
    /// Login successful without TOTP.
    Success(Session),
    /// Password valid, but TOTP verification required (`202 Accepted`).
    TotpRequired { partial_token: String },
    /// Account or IP is locked out.
    LockedOut { remaining_seconds: u64 },
    /// Rate limit exceeded for this IP.
    RateLimited,
    /// Invalid credentials.
    InvalidCredentials { remaining_attempts: u32 },
    /// The account's credentials changed while the login was being verified.
    /// The password used is no longer current, so no session was issued.
    StaleCredentials,
}

#[derive(Debug, Clone)]
struct PartialAuth {
    username: String,
    /// Credential epoch observed when the password was verified. The second
    /// factor may only complete a login for the same credential state.
    credential_epoch: u64,
    expires_at: Instant,
    failed_attempts: u32,
}

/// Outcome of the second login phase (`POST /auth/totp/verify`).
#[derive(Debug, Clone)]
pub enum TotpVerifyResult {
    /// TOTP verified and a session was created.
    Success(Session),
    /// Invalid code (partial token remains valid until the attempt limit is hit).
    Invalid,
    /// Partial token is missing, expired, or was consumed.
    TokenExpired,
    /// Account is locked out.
    LockedOut { remaining_seconds: u64 },
    /// IP rate limit exceeded.
    RateLimited,
}

/// A short-lived proof that the caller re-authenticated for a sensitive
/// operation. Bound to the account, its credential epoch, and the session that
/// requested it.
#[derive(Debug, Clone)]
struct ReauthGrant {
    username: String,
    session_id: String,
    credential_epoch: u64,
    expires_at: Instant,
}

/// Successful re-authentication ticket.
#[derive(Debug, Clone)]
pub struct ReauthToken {
    pub token: String,
    /// Remaining lifetime in seconds.
    pub expires_in: u64,
}

/// Failure modes for [`AuthManager::reauth`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReauthError {
    /// Wrong password or second factor.
    InvalidCredentials,
    /// The account has TOTP enabled but no code was supplied.
    SecondFactorRequired,
    /// Too many attempts from this IP address.
    RateLimited,
    /// The account is currently locked out.
    LockedOut { remaining_seconds: u64 },
}

/// Result of validating a first-boot setup token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupTokenStatus {
    /// Token matched.
    Valid,
    /// Token did not match.
    Invalid,
    /// No token is provisioned (setup already completed) or none was supplied.
    Missing,
    /// Too many failed attempts from this client.
    RateLimited,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    /// Monotonic credential revision for this account. Password, role, TOTP,
    /// deletion/recreation and admin-reset changes advance it so a session or
    /// API token issued under the previous credential state is rejected.
    /// `0` deserializes from users files written before the field existed.
    #[serde(default)]
    pub credential_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpConfig>,
}

pub const MAX_SESSIONS: usize = 10_000;
pub const MAX_PENDING_TOTP: usize = 10_000;
pub const MAX_PARTIAL_TOKENS: usize = 10_000;
/// Maximum accepted login username length (bytes) before lockout/Argon2.
pub const MAX_LOGIN_USERNAME_BYTES: usize = 64;
/// Maximum accepted login password length (bytes) before lockout/Argon2.
pub const MAX_LOGIN_PASSWORD_BYTES: usize = 1024;

/// Digest key used for account lockout bookkeeping. Hashing bounds the key
/// size and prevents the raw (attacker-controlled) username from being stored.
pub(crate) fn lockout_key(username: &str) -> String {
    format!("user:{}", blake3::hash(username.as_bytes()).to_hex())
}

/// Records a failed re-authentication attempt and maps the lockout threshold
/// crossing to the same result login returns: the attempt that reaches the
/// limit reports `LockedOut`, not the next one.
fn record_reauth_failure(
    lockout: &LockoutTracker,
    key: &str,
    otherwise: ReauthError,
) -> ReauthError {
    let (locked, _remaining) = lockout.record_failure(key);
    if locked {
        // Mirrors `login`: the threshold-crossing attempt is the 429.
        ReauthError::LockedOut {
            remaining_seconds: crate::auth::lockout::LOCKOUT_DURATION_SECS,
        }
    } else {
        otherwise
    }
}
/// Maximum number of API tokens kept in memory/on disk.
pub const MAX_API_TOKENS: usize = 256;
/// Maximum number of API tokens a single owner may hold. When the limit is
/// reached, creating another token evicts that owner's oldest token; other
/// owners' tokens are never touched.
pub const MAX_API_TOKENS_PER_OWNER: usize = 16;
pub const PENDING_TOTP_TTL: Duration = Duration::from_secs(600); // 10 minutes
/// Lifetime of a re-authentication ticket for a sensitive operation.
pub const REAUTH_TOKEN_TTL: Duration = Duration::from_secs(300);
/// Maximum number of live re-authentication tickets.
pub const MAX_REAUTH_TOKENS: usize = 10_000;
/// Maximum wrong TOTP codes per partial token before it is invalidated.
pub const MAX_TOTP_ATTEMPTS: u32 = 5;
/// Maximum failed first-boot setup-token attempts per client within the window.
pub const MAX_SETUP_TOKEN_FAILURES: u32 = 10;
/// Rolling window for setup-token failure throttling.
pub const SETUP_TOKEN_RATE_WINDOW: Duration = Duration::from_secs(60);
/// Age at which a still-pending setup emits a one-time operator warning.
pub const SETUP_TOKEN_PENDING_WARN: Duration = Duration::from_hours(24);

/// Failure to create an API token at the global capacity limit when the
/// requesting account has no token of its own to evict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CreateTokenError {
    #[error(
        "API token capacity reached and this account has no revocable tokens; revoke a token and try again"
    )]
    CapacityReached,
}

/// Failure to apply a user mutation that must never leave the deployment
/// without an Admin account.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UserMutationError {
    #[error("user not found")]
    NotFound,
    #[error("operation would remove the last remaining admin account")]
    LastAdmin,
    #[error("failed to persist users file: {0}")]
    Persistence(String),
}

/// Failure of a TOTP enable/disable mutation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TotpMutationError {
    #[error("user not found")]
    NotFound,
    #[error("invalid or expired TOTP verification code")]
    InvalidCode,
    #[error("failed to persist users file: {0}")]
    Persistence(String),
}

#[derive(Debug, Clone)]
struct PendingTotp {
    config: TotpConfig,
    created_at: Instant,
}

/// Test-only latch that pauses a login after the password (or TOTP code) was
/// verified but before the session is inserted. It lets a regression test
/// deterministically interleave a credential mutation with an in-flight
/// login without adding timing sleeps.
#[cfg(test)]
#[derive(Clone)]
struct LoginGate {
    reached: Arc<tokio::sync::Notify>,
    resume: Arc<tokio::sync::Notify>,
}

#[derive(Debug, Clone)]
struct SetupToken {
    token: String,
    created_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct FailureWindow {
    window_start: Instant,
    failures: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthStorageError {
    #[error(
        "Corrupt users file '{path}': {source}. The corrupt file was not retained because it may contain plaintext TOTP secrets. Refusing to start to prevent unauthorized bootstrap; use `sito reset-admin` to recover."
    )]
    CorruptUsersFile {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error(
        "Users file '{path}' exists but contains no user accounts. Refusing to start to prevent unauthorized bootstrap; use `sito reset-admin` to recover."
    )]
    EmptyUsersFile { path: PathBuf },
    #[error(
        "Users file '{path}' is missing while a configuration file exists. Refusing to start to prevent unauthorized bootstrap; run `sito reset-admin` to recover, or remove the configuration to re-run the setup wizard."
    )]
    MissingUsersFile { path: PathBuf },
    #[error("I/O error accessing users file '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "TOTP key file '{key_path}' is missing but '{users_path}' contains encrypted TOTP secrets. Restore '{key_path}' from the same backup as 'users.toml'; restoring only one is a lockout. Refusing to start to avoid silently disabling 2FA."
    )]
    MissingTotpKey {
        key_path: PathBuf,
        users_path: PathBuf,
    },
    #[error(
        "TOTP key file '{key_path}' is invalid: {reason}. Refusing to start to avoid silently disabling 2FA."
    )]
    InvalidTotpKey { key_path: PathBuf, reason: String },
    #[error(
        "Failed to decrypt the TOTP secret for user '{username}' in '{users_path}' with key '{key_path}': {reason}. Refusing to start to avoid silently disabling 2FA; restore the matching 'totp.key' or use `sito reset-admin`."
    )]
    TotpSecretDecrypt {
        username: String,
        users_path: PathBuf,
        key_path: PathBuf,
        reason: String,
    },
    #[error("Failed to encrypt the TOTP secret for user '{username}': {reason}")]
    TotpSecretEncrypt { username: String, reason: String },
    #[error(
        "TOTP encryption key is unavailable while persisting '{path}'; refusing to write plaintext secrets"
    )]
    MissingSecretStore { path: PathBuf },
    #[error("Failed to serialize users file '{path}': {source}")]
    Serialize {
        path: PathBuf,
        #[source]
        source: Box<toml::ser::Error>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UsersFile {
    #[serde(default)]
    users: Vec<UserAccount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SessionsFile {
    #[serde(default)]
    sessions: Vec<Session>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TokensFile {
    #[serde(default)]
    tokens: Vec<ApiTokenMeta>,
}

/// Locks a mutex, recovering the guard when the lock was poisoned by a panic
/// in another task instead of propagating the panic.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    sito_core::sync::lock_or_recover(mutex)
}

/// A fixed Argon2 hash used to keep the unknown-username login path as
/// expensive as the wrong-password path (prevents user enumeration).
fn dummy_password_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        let secret = format!("sito-dummy-{}", rand::random::<u64>());
        hash_password(&secret).expect("valid dummy password hash")
    })
}

async fn hash_password_blocking(password: String) -> Result<(String, bool), String> {
    tokio::task::spawn_blocking(move || {
        let hash = hash_password(&password)?;
        let is_default = verify_password("adminadmin", &hash);
        Ok((hash, is_default))
    })
    .await
    .map_err(|e| format!("password hashing task failed: {e}"))?
}

async fn verify_password_blocking(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .unwrap_or(false)
}

/// Test-only record of `(path, thread)` for every secret-file write, used to
/// prove that auth persistence runs off the calling runtime thread.
#[cfg(test)]
pub(crate) static SECRET_WRITE_THREADS: Mutex<Vec<(PathBuf, std::thread::ThreadId)>> =
    Mutex::new(Vec::new());

/// Test-only one-shot delays for the next write of a matching path. Tests use
/// this to widen a real persistence interleaving (a slow filesystem) without
/// changing production behavior.
#[cfg(test)]
pub(crate) static SECRET_WRITE_DELAYS: Mutex<Vec<(PathBuf, std::time::Duration)>> =
    Mutex::new(Vec::new());

/// Test-only one-shot signals sent when a write for a matching path has
/// started. Kept separate from [`SECRET_WRITE_THREADS`] so a test never depends
/// on globally cleared state.
#[cfg(test)]
pub(crate) static SECRET_WRITE_START_SIGNALS: Mutex<
    Vec<(PathBuf, tokio::sync::oneshot::Sender<()>)>,
> = Mutex::new(Vec::new());

/// Test-only write failures: `(path, skip)` allows the next `skip` writes to
/// succeed and then fails the following write for that path exactly once.
#[cfg(test)]
pub(crate) static SECRET_WRITE_FAIL_AFTER: Mutex<Vec<(PathBuf, usize)>> = Mutex::new(Vec::new());

/// Atomically writes a secret file with owner-only permissions.
fn write_secret_file(path: &Path, content: &str) -> std::io::Result<()> {
    #[cfg(test)]
    {
        // Notify and delay before deciding to fail so a test can observe the
        // start of a write that is then rejected (and interleave another
        // mutation while it is still in flight).
        let signal = {
            let mut signals = sito_core::sync::lock_or_recover(&SECRET_WRITE_START_SIGNALS);
            signals
                .iter()
                .position(|(signal_path, _)| signal_path == path)
                .map(|index| signals.remove(index).1)
        };
        if let Some(sender) = signal {
            let _ = sender.send(());
        }
        let delay = {
            let mut delays = sito_core::sync::lock_or_recover(&SECRET_WRITE_DELAYS);
            delays
                .iter()
                .position(|(delayed_path, _)| delayed_path == path)
                .map(|index| delays.remove(index).1)
        };
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
        let should_fail = {
            let mut rules = sito_core::sync::lock_or_recover(&SECRET_WRITE_FAIL_AFTER);
            if let Some(index) = rules.iter().position(|(rule_path, _)| rule_path == path) {
                if rules[index].1 == 0 {
                    rules.remove(index);
                    true
                } else {
                    rules[index].1 -= 1;
                    false
                }
            } else {
                false
            }
        };
        if should_fail {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected users-file write failure",
            ));
        }
        sito_core::sync::lock_or_recover(&SECRET_WRITE_THREADS)
            .push((path.to_path_buf(), std::thread::current().id()));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension(format!("tmp.{}", rand::random::<u32>()));
    let write_res = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::File::create(&tmp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)?;
        }
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp_path, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(())
    })();

    if let Err(e) = &write_res {
        tracing::error!("Failed to persist {}: {e}", path.display());
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_res
}

/// Writes a sanitized copy of `users.toml` to `backup_path`.
///
/// Recovery copies must not reintroduce the plaintext-at-rest problem the
/// encrypted store fixes: legacy plaintext TOTP secrets are sealed before the
/// backup is written. An unparseable source is never copied raw; the function
/// logs a value-free warning and removes any pre-existing copy at
/// `backup_path`.
///
/// Returns `Ok(true)` when a sanitized backup was written, `Ok(false)` when the
/// source was unparseable and no backup was retained.
fn write_sanitized_users_backup(
    source: &Path,
    backup_path: &Path,
    store: &TotpSecretStore,
) -> Result<bool, AuthStorageError> {
    let content = std::fs::read_to_string(source).map_err(|e| AuthStorageError::Io {
        path: source.to_path_buf(),
        source: e,
    })?;

    let mut file: UsersFile = if let Ok(file) = toml::from_str(&content) {
        file
    } else {
        tracing::warn!(
            source = %source.display(),
            "Users file is unparseable; not retaining a backup because it may contain plaintext TOTP secrets"
        );
        // Never leave a raw copy from an earlier attempt behind.
        let _ = std::fs::remove_file(backup_path);
        return Ok(false);
    };

    for user in &mut file.users {
        let username = user.username.clone();
        let Some(totp) = user.totp.as_mut() else {
            continue;
        };
        if TotpSecretStore::is_encrypted(&totp.secret) {
            continue;
        }
        totp.secret = store.seal(&username, &totp.secret).map_err(|e| {
            AuthStorageError::TotpSecretEncrypt {
                username,
                reason: e.to_string(),
            }
        })?;
    }

    let toml_str = toml::to_string_pretty(&file).map_err(|e| AuthStorageError::Serialize {
        path: backup_path.to_path_buf(),
        source: Box::new(e),
    })?;
    write_secret_file(backup_path, &toml_str).map_err(|e| AuthStorageError::Io {
        path: backup_path.to_path_buf(),
        source: e,
    })?;
    Ok(true)
}

/// Path of the file holding the global user-secret generation counter.
fn auth_generation_path(data_dir: &Path) -> PathBuf {
    data_dir.join("auth_generation")
}

/// Path of the AES-256-GCM key that protects TOTP secrets in `users.toml`.
fn totp_key_path(users_path: &Path) -> PathBuf {
    users_path.parent().map_or_else(
        || users_path.with_file_name("totp.key"),
        |dir| dir.join("totp.key"),
    )
}

/// Reads the persisted user-secret generation (`0` when no file exists).
fn read_auth_generation(data_dir: &Path) -> u64 {
    std::fs::read_to_string(auth_generation_path(data_dir))
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Rotates the global user-secret generation so every session/token issued
/// before the rotation is rejected even if its file survives.
pub fn rotate_auth_generation(data_dir: &Path) -> std::io::Result<u64> {
    let next = read_auth_generation(data_dir).saturating_add(1);
    write_secret_file(&auth_generation_path(data_dir), &next.to_string())?;
    Ok(next)
}

/// Backs up a corrupt state file so operators can inspect it after recovery.
fn backup_corrupt_file(path: &Path, label: &str) {
    let timestamp = chrono::Utc::now().timestamp();
    let backup_name = format!(
        "{}.corrupt.{}.bak",
        path.file_name().unwrap_or_default().to_string_lossy(),
        timestamp
    );
    let backup_path = path.with_file_name(backup_name);
    match std::fs::copy(path, &backup_path) {
        Ok(_) => tracing::warn!(
            file = label,
            source = %path.display(),
            backup = %backup_path.display(),
            "Backed up corrupt state file"
        ),
        Err(copy_err) => tracing::error!(
            file = label,
            source = %path.display(),
            error = %copy_err,
            "Failed to back up corrupt state file"
        ),
    }
}

/// Central state manager for authentication and authorization.
#[derive(Clone)]
pub struct AuthManager {
    users: Arc<Mutex<HashMap<String, UserAccount>>>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    tokens: Arc<Mutex<HashMap<String, ApiTokenMeta>>>, // Keyed by token hash
    pending_totp_setups: Arc<Mutex<HashMap<String, PendingTotp>>>,
    partial_tokens: Arc<Mutex<HashMap<String, PartialAuth>>>,
    /// Short-lived re-authentication tickets for sensitive operations.
    reauth_tokens: Arc<Mutex<HashMap<String, ReauthGrant>>>,
    lockout: LockoutTracker,
    session_ttl_secs: i64,
    login_rate_limit: usize,
    setup_complete: Arc<AtomicBool>,
    /// True while the bootstrapped `admin` account still uses its default password.
    default_admin_active: Arc<AtomicBool>,
    /// One-time first-boot setup token (only provisioned until setup completes).
    setup_token: Arc<Mutex<Option<SetupToken>>>,
    /// Failed setup-token attempts keyed by client IP.
    setup_token_failures: Arc<Mutex<HashMap<String, FailureWindow>>>,
    /// Whether the one-time "setup still pending" warning was already emitted.
    setup_pending_warned: Arc<AtomicBool>,
    /// Serializes second-factor verification so a backup code cannot be
    /// consumed by two concurrent requests.
    totp_verification_lock: Arc<tokio::sync::Mutex<()>>,
    /// Serializes setup-wizard completion so token consumption, credential
    /// changes and `setup_complete` cannot race each other.
    setup_completion_lock: Arc<tokio::sync::Mutex<()>>,
    /// Serializes every users-table mutation from the in-memory change through
    /// its save/rollback. Without it, a mutation whose write fails can release
    /// `persist_lock`, let a second mutation snapshot and commit the first
    /// mutation's uncommitted state, and then roll the first mutation back over
    /// the second one (or resurrect a concurrently deleted account).
    ///
    /// Lock order: `totp_verification_lock` (if taken) then this lock. Never
    /// acquire the TOTP verification lock while holding this one.
    user_mutation_lock: Arc<tokio::sync::Mutex<()>>,
    /// Serializes snapshot + persist of the auth state files so a stale
    /// snapshot can never overwrite a newer revocation/creation on disk.
    /// Held only across the snapshot and its `spawn_blocking` write; callers
    /// must not nest `save_*_async` calls while it is held.
    persist_lock: Arc<tokio::sync::Mutex<()>>,
    users_path: Option<PathBuf>,
    sessions_path: Option<PathBuf>,
    tokens_path: Option<PathBuf>,
    tokens_dirty: Arc<AtomicBool>,
    sessions_dirty: Arc<AtomicBool>,
    /// Monotonic revision of every token mutation. A save captures it before
    /// snapshotting and only clears `tokens_dirty` when it is still unchanged,
    /// so a sync reader's removal/last-used update is never silently dropped.
    tokens_revision: Arc<AtomicU64>,
    /// Same contract as [`Self::tokens_revision`] for sessions.
    sessions_revision: Arc<AtomicU64>,
    token_default_ttl_days: u64,
    /// Global user-secret generation; sessions/tokens must match it to be valid.
    generation: u64,
    /// Monotonic source of per-user credential epochs. Seeded from the clock
    /// and the highest epoch found on load so a deleted-and-recreated account
    /// never receives an epoch an older session/token could still match.
    credential_epoch_cursor: Arc<AtomicU64>,
    /// AES-256-GCM key for TOTP secrets (`<data_dir>/totp.key`); `None` for
    /// memory-only managers.
    secret_store: Option<TotpSecretStore>,
    /// Test-only latch used to pause an in-flight login after credential
    /// verification. Always `None` outside tests.
    #[cfg(test)]
    login_gate: Arc<Mutex<Option<LoginGate>>>,
}

mod construction;
mod login;
mod prune;
mod sessions;
mod storage;
mod tokens;
mod totp;
mod users;

#[cfg(test)]
mod tests;
