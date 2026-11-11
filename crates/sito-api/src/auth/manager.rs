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
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
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
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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
            let mut signals = SECRET_WRITE_START_SIGNALS
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            signals
                .iter()
                .position(|(signal_path, _)| signal_path == path)
                .map(|index| signals.remove(index).1)
        };
        if let Some(sender) = signal {
            let _ = sender.send(());
        }
        let delay = {
            let mut delays = SECRET_WRITE_DELAYS
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            delays
                .iter()
                .position(|(delayed_path, _)| delayed_path == path)
                .map(|index| delays.remove(index).1)
        };
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
        let should_fail = {
            let mut rules = SECRET_WRITE_FAIL_AFTER
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
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
        SECRET_WRITE_THREADS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
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

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthManager {
    pub fn new() -> Self {
        Self::with_config_and_storage(None, 24, 5)
            .expect("in-memory auth initialization cannot fail")
    }

    pub fn with_config(session_ttl_hours: u64, login_rate_limit: usize) -> Self {
        Self::with_config_and_storage(None, session_ttl_hours, login_rate_limit)
            .expect("in-memory auth initialization cannot fail")
    }

    pub fn with_storage(
        data_dir: impl AsRef<Path>,
        session_ttl_hours: u64,
        login_rate_limit: usize,
    ) -> Result<Self, AuthStorageError> {
        Self::with_config_and_storage(
            Some(data_dir.as_ref().join("users.toml")),
            session_ttl_hours,
            login_rate_limit,
        )
    }

    /// Like [`with_storage`], but fails when the users file is missing and
    /// `bootstrap_allowed` is false. Used by the production server so that a
    /// deleted/lost `users.toml` cannot silently re-enable the default admin.
    pub fn with_storage_checked(
        data_dir: impl AsRef<Path>,
        session_ttl_hours: u64,
        login_rate_limit: usize,
        bootstrap_allowed: bool,
    ) -> Result<Self, AuthStorageError> {
        Self::with_config_and_storage_checked(
            Some(data_dir.as_ref().join("users.toml")),
            session_ttl_hours,
            login_rate_limit,
            bootstrap_allowed,
        )
    }

    /// Production constructor with persistence policy for sessions and tokens.
    pub fn with_storage_full(
        data_dir: impl AsRef<Path>,
        session_ttl_hours: u64,
        login_rate_limit: usize,
        bootstrap_allowed: bool,
        session_persist: bool,
        token_default_ttl_days: u64,
    ) -> Result<Self, AuthStorageError> {
        Self::with_config_and_storage_full(
            Some(data_dir.as_ref().join("users.toml")),
            session_ttl_hours,
            login_rate_limit,
            bootstrap_allowed,
            session_persist,
            token_default_ttl_days,
        )
    }

    pub fn with_config_and_storage(
        users_path: Option<PathBuf>,
        session_ttl_hours: u64,
        login_rate_limit: usize,
    ) -> Result<Self, AuthStorageError> {
        Self::with_config_and_storage_checked(users_path, session_ttl_hours, login_rate_limit, true)
    }

    pub fn with_config_and_storage_checked(
        users_path: Option<PathBuf>,
        session_ttl_hours: u64,
        login_rate_limit: usize,
        bootstrap_allowed: bool,
    ) -> Result<Self, AuthStorageError> {
        Self::with_config_and_storage_full(
            users_path,
            session_ttl_hours,
            login_rate_limit,
            bootstrap_allowed,
            true,
            0,
        )
    }

    pub fn with_config_and_storage_full(
        users_path: Option<PathBuf>,
        session_ttl_hours: u64,
        login_rate_limit: usize,
        bootstrap_allowed: bool,
        session_persist: bool,
        token_default_ttl_days: u64,
    ) -> Result<Self, AuthStorageError> {
        let secs = session_ttl_hours.saturating_mul(3600);
        let session_ttl_secs = i64::try_from(secs).unwrap_or(DEFAULT_SESSION_TTL_SECS);

        let data_dir = users_path.as_ref().and_then(|p| p.parent());
        let (sessions_path, tokens_path) = if session_persist {
            match data_dir {
                Some(dir) => (
                    Some(dir.join("sessions.toml")),
                    Some(dir.join("tokens.toml")),
                ),
                None => (None, None),
            }
        } else {
            (None, None)
        };

        let generation = data_dir.map_or(0, read_auth_generation);
        let mut mgr = Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            tokens: Arc::new(Mutex::new(HashMap::new())),
            pending_totp_setups: Arc::new(Mutex::new(HashMap::new())),
            partial_tokens: Arc::new(Mutex::new(HashMap::new())),
            reauth_tokens: Arc::new(Mutex::new(HashMap::new())),
            lockout: LockoutTracker::new(),
            session_ttl_secs,
            login_rate_limit,
            setup_complete: Arc::new(AtomicBool::new(false)),
            default_admin_active: Arc::new(AtomicBool::new(false)),
            setup_token: Arc::new(Mutex::new(None)),
            setup_token_failures: Arc::new(Mutex::new(HashMap::new())),
            setup_pending_warned: Arc::new(AtomicBool::new(false)),
            totp_verification_lock: Arc::new(tokio::sync::Mutex::new(())),
            setup_completion_lock: Arc::new(tokio::sync::Mutex::new(())),
            user_mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            persist_lock: Arc::new(tokio::sync::Mutex::new(())),
            users_path,
            sessions_path,
            tokens_path,
            tokens_dirty: Arc::new(AtomicBool::new(false)),
            sessions_dirty: Arc::new(AtomicBool::new(false)),
            tokens_revision: Arc::new(AtomicU64::new(0)),
            sessions_revision: Arc::new(AtomicU64::new(0)),
            token_default_ttl_days,
            generation,
            credential_epoch_cursor: Arc::new(AtomicU64::new(
                chrono::Utc::now().timestamp_millis().max(0) as u64,
            )),
            secret_store: None,
            #[cfg(test)]
            login_gate: Arc::new(Mutex::new(None)),
        };

        if let Some(ref path) = mgr.users_path {
            if path.exists() {
                let content = match std::fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(path = %path.display(), error = %e, "Failed to read users file");
                        return Err(AuthStorageError::Io {
                            path: path.clone(),
                            source: e,
                        });
                    }
                };

                let file: UsersFile = match toml::from_str(&content) {
                    Ok(f) => f,
                    Err(e) => {
                        // Do not retain a raw copy: an unparseable file may still
                        // contain legacy plaintext TOTP secrets.
                        tracing::warn!(
                            path = %path.display(),
                            "Corrupt users file detected; not retaining a backup because it may contain plaintext TOTP secrets"
                        );
                        tracing::error!(
                            path = %path.display(),
                            error = %e,
                            "Corrupt users file detected; refusing to start"
                        );

                        return Err(AuthStorageError::CorruptUsersFile {
                            path: path.clone(),
                            source: Box::new(e),
                        });
                    }
                };

                if file.users.is_empty() {
                    tracing::error!(
                        path = %path.display(),
                        "Users file exists but contains no accounts; refusing to start"
                    );
                    return Err(AuthStorageError::EmptyUsersFile { path: path.clone() });
                }

                // Resolve the TOTP encryption key before touching the users so
                // encrypted values can never be mistaken for plaintext.
                let key_path = totp_key_path(path);
                let has_encrypted_totp = file.users.iter().any(|u| {
                    u.totp
                        .as_ref()
                        .is_some_and(|totp| TotpSecretStore::is_encrypted(&totp.secret))
                });
                let store = if has_encrypted_totp {
                    // Encrypted secrets are useless without their key: never
                    // generate a replacement that would silently disable 2FA.
                    TotpSecretStore::load_existing(&key_path).map_err(|e| {
                        if e.kind() == std::io::ErrorKind::NotFound {
                            AuthStorageError::MissingTotpKey {
                                key_path: key_path.clone(),
                                users_path: path.clone(),
                            }
                        } else {
                            AuthStorageError::InvalidTotpKey {
                                key_path: key_path.clone(),
                                reason: e.to_string(),
                            }
                        }
                    })?
                } else {
                    TotpSecretStore::load_or_create(&key_path).map_err(|e| {
                        AuthStorageError::Io {
                            path: key_path.clone(),
                            source: e,
                        }
                    })?
                };
                mgr.secret_store = Some(store);

                let mut migrated_plaintext = Vec::new();
                let mut users = file.users;
                for user in &mut users {
                    let Some(totp) = user.totp.as_mut() else {
                        continue;
                    };
                    if TotpSecretStore::is_encrypted(&totp.secret) {
                        let store = mgr
                            .secret_store
                            .as_ref()
                            .expect("key resolved for encrypted secrets");
                        totp.secret = store.open(&user.username, &totp.secret).map_err(|e| {
                            AuthStorageError::TotpSecretDecrypt {
                                username: user.username.clone(),
                                users_path: path.clone(),
                                key_path: store.key_path().to_path_buf(),
                                reason: e.to_string(),
                            }
                        })?;
                    } else {
                        migrated_plaintext.push(user.username.clone());
                    }
                }

                let (has_usable_admin, admin_default_active) = {
                    let mut map = lock(&mgr.users);
                    for u in users {
                        map.insert(u.username.clone(), u);
                    }
                    let admin_default_active = map
                        .get("admin")
                        .is_some_and(|admin| verify_password("adminadmin", &admin.password_hash));
                    // Setup is complete when at least one Admin account has a
                    // non-bootstrap credential, regardless of its username.
                    // The bootstrap `admin` account only counts once its
                    // password has been rotated.
                    let has_usable_admin = map.values().any(|user| {
                        user.role == Role::Admin
                            && !(user.username == "admin" && admin_default_active)
                    });
                    (has_usable_admin, admin_default_active)
                };
                mgr.seed_epoch_cursor();

                // Legacy plaintext secrets are encrypted on this startup with
                // exactly one atomic rewrite. Warnings name the account only.
                if !migrated_plaintext.is_empty() {
                    let (save_path, toml_str) =
                        mgr.users_toml()?
                            .ok_or_else(|| AuthStorageError::MissingSecretStore {
                                path: path.clone(),
                            })?;
                    write_secret_file(&save_path, &toml_str).map_err(|e| AuthStorageError::Io {
                        path: save_path,
                        source: e,
                    })?;
                    for username in &migrated_plaintext {
                        tracing::warn!(
                            user = %username,
                            "migrated legacy plaintext TOTP secret"
                        );
                    }
                }
                mgr.default_admin_active
                    .store(admin_default_active, Ordering::SeqCst);
                mgr.setup_complete
                    .store(has_usable_admin && !admin_default_active, Ordering::SeqCst);
                mgr.load_sessions();
                mgr.load_tokens();
                mgr.provision_setup_token_if_needed();
                return Ok(mgr);
            }

            // If file does not exist, initialize bootstrap admin and persist —
            // but only while the deployment is still in first-run / setup mode.
            if !bootstrap_allowed {
                tracing::error!(
                    path = %path.display(),
                    "Users file is missing while a configuration exists; refusing to start"
                );
                return Err(AuthStorageError::MissingUsersFile { path: path.clone() });
            }
            let key_path = totp_key_path(path);
            mgr.secret_store = Some(TotpSecretStore::load_or_create(&key_path).map_err(|e| {
                AuthStorageError::Io {
                    path: key_path,
                    source: e,
                }
            })?);
            mgr.create_user_internal("admin", "adminadmin", Role::Admin);
            mgr.save_users_initial()?;
        } else {
            // Memory-only fallback for tests
            mgr.create_user_internal("admin", "adminadmin", Role::Admin);
        }

        mgr.load_sessions();
        mgr.load_tokens();
        mgr.provision_setup_token_if_needed();
        Ok(mgr)
    }

    /// Resets the administrative account credentials and preserves every
    /// non-admin account already present in `users.toml`. The file is backed up
    /// before being rewritten. Use [`Self::reset_admin_credentials_full`] when
    /// a full account-store replacement is explicitly intended.
    pub fn reset_admin_credentials(
        data_dir: impl AsRef<Path>,
        new_password: &str,
    ) -> std::io::Result<PathBuf> {
        Self::reset_admin_credentials_inner(data_dir.as_ref(), new_password, false)
    }

    /// Full `reset-admin --reset-all`: replaces the account store with only the
    /// `admin` account. Also the recovery path for an unparseable `users.toml`.
    pub fn reset_admin_credentials_full(
        data_dir: impl AsRef<Path>,
        new_password: &str,
    ) -> std::io::Result<PathBuf> {
        Self::reset_admin_credentials_inner(data_dir.as_ref(), new_password, true)
    }

    fn reset_admin_credentials_inner(
        data_dir: &Path,
        new_password: &str,
        reset_all_users: bool,
    ) -> std::io::Result<PathBuf> {
        let path = data_dir.join("users.toml");
        // Resolve the key before copying anything: a recovery backup must never
        // retain legacy plaintext TOTP secrets. `reset-admin` is the recovery
        // path, so a malformed key must not make recovery impossible: move it
        // aside and generate a fresh one (the reset rotates credentials and
        // invalidates existing sessions/tokens anyway).
        let key_path = totp_key_path(&path);
        let key_was_missing = !key_path.exists();
        let (secret_store, key_was_rotated) = match TotpSecretStore::load_or_create(&key_path) {
            Ok(store) => (store, false),
            Err(e) => {
                let backup =
                    key_path.with_extension(format!("corrupt.{}", chrono::Utc::now().timestamp()));
                tracing::warn!(
                    path = %key_path.display(),
                    backup = %backup.display(),
                    error = %e,
                    "Existing TOTP key is unusable; moving it aside and generating a fresh key for admin reset"
                );
                if key_path.exists() {
                    std::fs::rename(&key_path, &backup)?;
                }
                (TotpSecretStore::load_or_create(&key_path)?, true)
            }
        };
        if path.exists() {
            let timestamp = chrono::Utc::now().timestamp();
            let backup_name = format!(
                "{}.reset.{}.bak",
                path.file_name().unwrap_or_default().to_string_lossy(),
                timestamp
            );
            let backup_path = path.with_file_name(backup_name);
            match write_sanitized_users_backup(&path, &backup_path, &secret_store) {
                Ok(true) => tracing::warn!(
                    source = %path.display(),
                    backup = %backup_path.display(),
                    "Backed up users file with TOTP secrets sealed"
                ),
                Ok(false) => {}
                Err(e) => tracing::error!(
                    source = %path.display(),
                    error = %e,
                    "Failed to write sanitized users backup; no backup retained"
                ),
            }
        }
        let mut preserved_users = if path.exists() && !reset_all_users {
            let content = std::fs::read_to_string(&path)?;
            let mut file: UsersFile = toml::from_str(&content).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "users file '{}' is unparseable ({e}); refusing to delete non-admin accounts. Re-run with --reset-all to replace the account store.",
                        path.display()
                    ),
                )
            })?;
            file.users.retain(|user| user.username != "admin");
            // A newly generated/rotated key, or a valid file holding the
            // wrong 32-byte key, cannot decrypt existing TOTP secrets.
            // Preserve the accounts but drop the unusable second factor
            // instead of leaving the server unable to start later.
            let key_usable = !(key_was_missing || key_was_rotated);
            for user in &mut file.users {
                let Some(totp) = user.totp.as_ref() else {
                    continue;
                };
                if !TotpSecretStore::is_encrypted(&totp.secret) {
                    continue;
                }
                if !key_usable || secret_store.open(&user.username, &totp.secret).is_err() {
                    tracing::warn!(
                        user = %user.username,
                        "Dropping an existing TOTP secret that the current encryption key cannot decrypt during admin reset"
                    );
                    user.totp = None;
                }
            }
            file.users
        } else {
            Vec::new()
        };

        // Rotate the user-secret generation *before* installing the new
        // credentials so every live session and API token is rejected as soon
        // as the reset takes effect, and remove the persisted stores.
        let generation = rotate_auth_generation(data_dir)?;
        for name in ["sessions.toml", "tokens.toml"] {
            let store = data_dir.join(name);
            if store.exists() {
                std::fs::remove_file(&store)?;
                tracing::info!(path = %store.display(), "Removed persisted auth store on admin reset");
            }
        }

        let mgr = Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            tokens: Arc::new(Mutex::new(HashMap::new())),
            pending_totp_setups: Arc::new(Mutex::new(HashMap::new())),
            partial_tokens: Arc::new(Mutex::new(HashMap::new())),
            reauth_tokens: Arc::new(Mutex::new(HashMap::new())),
            lockout: LockoutTracker::new(),
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            login_rate_limit: 5,
            setup_complete: Arc::new(AtomicBool::new(false)),
            default_admin_active: Arc::new(AtomicBool::new(false)),
            setup_token: Arc::new(Mutex::new(None)),
            setup_token_failures: Arc::new(Mutex::new(HashMap::new())),
            setup_pending_warned: Arc::new(AtomicBool::new(false)),
            totp_verification_lock: Arc::new(tokio::sync::Mutex::new(())),
            setup_completion_lock: Arc::new(tokio::sync::Mutex::new(())),
            user_mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            persist_lock: Arc::new(tokio::sync::Mutex::new(())),
            users_path: Some(path.clone()),
            sessions_path: None,
            tokens_path: None,
            tokens_dirty: Arc::new(AtomicBool::new(false)),
            sessions_dirty: Arc::new(AtomicBool::new(false)),
            tokens_revision: Arc::new(AtomicU64::new(0)),
            sessions_revision: Arc::new(AtomicU64::new(0)),
            token_default_ttl_days: 0,
            generation,
            credential_epoch_cursor: Arc::new(AtomicU64::new(
                chrono::Utc::now().timestamp_millis().max(0) as u64,
            )),
            // A reset replaces the account store; reuse an existing key so
            // backups of the previous users file stay decryptable, or create
            // one when the key was lost (the reset is the documented recovery).
            secret_store: Some(secret_store),
            #[cfg(test)]
            login_gate: Arc::new(Mutex::new(None)),
        };
        {
            let mut users = lock(&mgr.users);
            for user in preserved_users.drain(..) {
                users.insert(user.username.clone(), user);
            }
        }
        mgr.seed_epoch_cursor();
        mgr.create_user_internal("admin", new_password, Role::Admin);
        mgr.save_users_initial().map_err(std::io::Error::other)?;
        Ok(path)
    }

    /// Serializes the current user accounts to TOML, returning the target path.
    ///
    /// TOTP secrets are sealed on cloned accounts, so the in-memory plaintext
    /// (needed to verify codes) never reaches the file. An encryption failure
    /// is returned instead of falling back to plaintext.
    fn users_toml(&self) -> Result<Option<(PathBuf, String)>, AuthStorageError> {
        let Some(path) = self.users_path.clone() else {
            return Ok(None);
        };
        let mut users_list: Vec<UserAccount> = {
            let users = lock(&self.users);
            users.values().cloned().collect()
        };
        for user in &mut users_list {
            let username = user.username.clone();
            let Some(totp) = user.totp.as_mut() else {
                continue;
            };
            if TotpSecretStore::is_encrypted(&totp.secret) {
                continue;
            }
            let store = self
                .secret_store
                .as_ref()
                .ok_or_else(|| AuthStorageError::MissingSecretStore { path: path.clone() })?;
            totp.secret = store.seal(&username, &totp.secret).map_err(|e| {
                AuthStorageError::TotpSecretEncrypt {
                    username: username.clone(),
                    reason: e.to_string(),
                }
            })?;
        }
        let file_content = UsersFile { users: users_list };
        let toml_str =
            toml::to_string_pretty(&file_content).map_err(|e| AuthStorageError::Serialize {
                path: path.clone(),
                source: Box::new(e),
            })?;
        Ok(Some((path, toml_str)))
    }

    /// Writes the users file synchronously. Constructor-only: the manager is
    /// not shared yet, so bypassing `persist_lock` cannot race a runtime save.
    /// Every runtime path must use [`Self::try_save_users_async`] instead.
    ///
    /// Returns the write failure so `reset-admin` cannot report success when
    /// the new credentials did not land.
    fn save_users_initial(&self) -> Result<(), AuthStorageError> {
        match self.users_toml()? {
            Some((path, toml_str)) => write_secret_file(&path, &toml_str)
                .map_err(|e| AuthStorageError::Io { path, source: e }),
            None => Ok(()),
        }
    }

    /// Returns the next credential epoch. Always strictly greater than every
    /// epoch already issued by this process and (after load) every epoch on
    /// disk.
    fn next_credential_epoch(&self) -> u64 {
        self.credential_epoch_cursor
            .fetch_add(1, Ordering::SeqCst)
            .max(1)
    }

    /// Raises the epoch cursor above the clock and every loaded account so a
    /// recreated account cannot reuse an epoch that a persisted credential
    /// could still match.
    fn seed_epoch_cursor(&self) {
        let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
        let highest = lock(&self.users)
            .values()
            .map(|user| user.credential_epoch)
            .max()
            .unwrap_or(0);
        self.credential_epoch_cursor
            .store(now.max(highest).saturating_add(1), Ordering::SeqCst);
    }

    /// Persists users on the blocking pool so async handlers never perform
    /// blocking file IO on the runtime worker.
    ///
    /// The snapshot is taken while holding `persist_lock` and the lock is held
    /// until the write finishes, so a stale snapshot cannot land after a newer
    /// one. The guard is owned by the blocking task, so cancelling the caller
    /// cannot release it before the write completes. Every caller must handle
    /// the error and roll its in-memory change back: a credential mutation must
    /// never report success when the write did not land.
    pub(crate) async fn try_save_users_async(&self) -> Result<(), AuthStorageError> {
        // Use an owned guard moved into the blocking closure: if the caller is
        // cancelled mid-write, the closure keeps the lock until the write
        // finishes so a newer save cannot complete (and be overwritten) first.
        let persist = self.persist_lock.clone().lock_owned().await;
        let Some((path, toml_str)) = self.users_toml()? else {
            return Ok(());
        };
        let write_path = path.clone();
        match tokio::task::spawn_blocking(move || {
            let _persist = persist;
            write_secret_file(&path, &toml_str)
        })
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(AuthStorageError::Io {
                path: write_path,
                source: e,
            }),
            Err(e) => Err(AuthStorageError::Io {
                path: write_path,
                source: std::io::Error::other(e.to_string()),
            }),
        }
    }

    /// Serializes the current sessions to TOML, returning the target path.
    ///
    /// The snapshot is taken before any blocking IO so no lock is held across
    /// an `.await` or a filesystem write.
    fn sessions_toml(&self) -> Option<(PathBuf, String)> {
        let path = self.sessions_path.clone()?;
        let sessions: Vec<Session> = lock(&self.sessions).values().cloned().collect();
        if let Ok(toml_str) = toml::to_string_pretty(&SessionsFile { sessions }) {
            Some((path, toml_str))
        } else {
            tracing::error!("Failed to serialize sessions to TOML");
            None
        }
    }

    /// Serializes the current API tokens to TOML, returning the target path.
    fn tokens_toml(&self) -> Option<(PathBuf, String)> {
        let path = self.tokens_path.clone()?;
        let tokens: Vec<ApiTokenMeta> = lock(&self.tokens).values().cloned().collect();
        if let Ok(toml_str) = toml::to_string_pretty(&TokensFile { tokens }) {
            Some((path, toml_str))
        } else {
            tracing::error!("Failed to serialize API tokens to TOML");
            None
        }
    }

    /// Persists sessions on the blocking pool so async handlers never perform
    /// blocking file IO on the runtime worker.
    async fn save_sessions_async(&self) {
        let persist = self.persist_lock.clone().lock_owned().await;
        // Capture the revision before snapshotting. A mutation that lands after
        // the snapshot must keep the store dirty so the pruner retries.
        let revision = self.sessions_revision.load(Ordering::SeqCst);
        let Some((path, toml_str)) = self.sessions_toml() else {
            // Only a memory-only manager has nothing to retry; keep the flag
            // set when serialization failed so the pruner tries again.
            if self.sessions_path.is_none() {
                self.sessions_dirty.store(false, Ordering::SeqCst);
            }
            return;
        };
        // Mark dirty before writing so a failed write is retried by the pruner
        // instead of being lost until the next explicit session mutation.
        self.sessions_dirty.store(true, Ordering::SeqCst);
        let sessions_dirty = self.sessions_dirty.clone();
        let sessions_revision = self.sessions_revision.clone();
        let sessions = self.sessions.clone();
        match tokio::task::spawn_blocking(move || {
            let _persist = persist;
            let result = write_secret_file(&path, &toml_str);
            if result.is_ok() {
                // Take the sessions lock so the revision check and clear cannot
                // interleave with a sync mutator such as `validate_session`,
                // which bumps the revision and sets the dirty flag under this
                // same lock. Clear while the persist guard is still held: a
                // newer save woken by its release must not be able to set the
                // flag again and then have this older caller clear it.
                let _sessions = lock(&sessions);
                if sessions_revision.load(Ordering::SeqCst) == revision {
                    sessions_dirty.store(false, Ordering::SeqCst);
                }
            }
            result
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!("Failed to persist sessions file: {e}"),
            Err(e) => tracing::error!("Sessions persistence task failed: {e}"),
        }
    }

    /// Persists API tokens on the blocking pool. The dirty flag is set before
    /// the write and cleared only after success, so a failed write is retried
    /// by the pruner.
    async fn save_tokens_async(&self) {
        let persist = self.persist_lock.clone().lock_owned().await;
        // Capture the revision before snapshotting. A mutation that lands after
        // the snapshot must keep the store dirty so the pruner retries.
        let revision = self.tokens_revision.load(Ordering::SeqCst);
        let Some((path, toml_str)) = self.tokens_toml() else {
            // Only a memory-only manager has nothing to retry; keep the flag
            // set when serialization failed so the pruner tries again.
            if self.tokens_path.is_none() {
                self.tokens_dirty.store(false, Ordering::SeqCst);
            }
            return;
        };
        self.tokens_dirty.store(true, Ordering::SeqCst);
        let tokens_dirty = self.tokens_dirty.clone();
        let tokens_revision = self.tokens_revision.clone();
        let tokens = self.tokens.clone();
        match tokio::task::spawn_blocking(move || {
            let _persist = persist;
            let result = write_secret_file(&path, &toml_str);
            if result.is_ok() {
                // Take the tokens lock so the revision check and clear cannot
                // interleave with a sync mutator such as `validate_token`,
                // which bumps the revision and sets the dirty flag under this
                // same lock. Clear while the persist guard is still held: a
                // newer save woken by its release must not be able to set the
                // flag again and then have this older caller clear it.
                let _tokens = lock(&tokens);
                if tokens_revision.load(Ordering::SeqCst) == revision {
                    tokens_dirty.store(false, Ordering::SeqCst);
                }
            }
            result
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!("Failed to persist API tokens file: {e}"),
            Err(e) => tracing::error!("API tokens persistence task failed: {e}"),
        }
    }

    fn load_sessions(&self) {
        let Some(ref path) = self.sessions_path else {
            return;
        };
        if !path.exists() {
            return;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            tracing::error!(path = %path.display(), "Failed to read sessions file");
            return;
        };
        match toml::from_str::<SessionsFile>(&content) {
            Ok(file) => {
                let users = lock(&self.users);
                let mut sessions = lock(&self.sessions);
                for mut session in file.sessions {
                    if session.generation != self.generation {
                        tracing::warn!(
                            session = %session.id,
                            "Rejecting persisted session issued under a previous auth generation"
                        );
                        continue;
                    }
                    if session.is_expired() {
                        continue;
                    }
                    let Some(epoch) = session.credential_epoch else {
                        tracing::warn!(
                            session = %session.id,
                            "Rejecting legacy persisted session without a credential epoch; re-login required"
                        );
                        continue;
                    };
                    let Some(user) = users.get(&session.username) else {
                        tracing::warn!(
                            session = %session.id,
                            "Rejecting persisted session for a removed account"
                        );
                        continue;
                    };
                    if user.credential_epoch != epoch || user.role != session.role {
                        tracing::warn!(
                            session = %session.id,
                            "Rejecting persisted session issued under stale credentials"
                        );
                        continue;
                    }
                    session.ensure_csrf_token();
                    sessions.insert(session.id.clone(), session);
                }
            }
            Err(e) => {
                backup_corrupt_file(path, "sessions");
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "Corrupt sessions file detected; starting with no active sessions"
                );
            }
        }
    }

    fn load_tokens(&self) {
        let Some(ref path) = self.tokens_path else {
            return;
        };
        if !path.exists() {
            return;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            tracing::error!(path = %path.display(), "Failed to read API tokens file");
            return;
        };
        match toml::from_str::<TokensFile>(&content) {
            Ok(file) => {
                let now = chrono::Utc::now().timestamp();
                let users = lock(&self.users);
                // Newest first so when the cap trims loaded tokens we keep the
                // most recently issued ones.
                let mut loaded: Vec<ApiTokenMeta> = file
                    .tokens
                    .into_iter()
                    .filter(|token| token.expires_at.is_none_or(|exp| now < exp))
                    .filter(|token| {
                        if token.generation != self.generation {
                            tracing::warn!(
                                token = %token.id,
                                "Rejecting persisted API token issued under a previous auth generation"
                            );
                            return false;
                        }
                        let Some(epoch) = token.credential_epoch else {
                            tracing::warn!(
                                token = %token.id,
                                "Rejecting legacy persisted API token without a credential epoch; re-issue required"
                            );
                            return false;
                        };
                        match token.owner.as_deref() {
                            // Ownerless tokens are Admin-managed and not tied
                            // to an account.
                            None => true,
                            Some(owner) => users.get(owner).is_some_and(|user| {
                                user.credential_epoch == epoch && user.role >= token.scope
                            }),
                        }
                    })
                    .collect();
                let mut tokens = lock(&self.tokens);
                loaded.sort_by_key(|t| std::cmp::Reverse(t.created_at));
                for token in loaded {
                    if tokens.len() >= MAX_API_TOKENS {
                        break;
                    }
                    tokens.insert(token.hash.clone(), token);
                }
            }
            Err(e) => {
                backup_corrupt_file(path, "tokens");
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "Corrupt API tokens file detected; starting with no active tokens"
                );
            }
        }
    }

    fn create_user_internal(&self, username: &str, password: &str, role: Role) {
        let hash = hash_password(password).expect("valid password hash");
        let is_default = username == "admin" && verify_password("adminadmin", &hash);
        if username == "admin" {
            self.default_admin_active
                .store(is_default, Ordering::SeqCst);
        }
        let user = UserAccount {
            username: username.to_string(),
            password_hash: hash,
            role,
            credential_epoch: self.next_credential_epoch(),
            totp: None,
        };
        lock(&self.users).insert(username.to_string(), user);
    }

    // ------------------------------------------------------------------
    // First-boot setup token
    // ------------------------------------------------------------------

    /// Generates the one-time setup token when the deployment is still in
    /// first-run state. The token is printed to stdout/logs exactly once.
    fn provision_setup_token_if_needed(&self) {
        if self.users_path.is_none() || self.setup_complete.load(Ordering::SeqCst) {
            return;
        }
        let mut guard = lock(&self.setup_token);
        if guard.is_some() {
            return;
        }
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        let token = hex::encode(bytes);
        *guard = Some(SetupToken {
            token: token.clone(),
            created_at: Instant::now(),
        });
        self.setup_pending_warned.store(false, Ordering::SeqCst);
        tracing::warn!(
            "First-boot setup token generated; required for /wizard, /ui/wizard/* and /ui/upstreams/test until setup completes"
        );
        eprintln!(
            "\n==================================================================\n \
             First-boot setup token: {token}\n \
             Open /wizard?setup_token={token} (or provide the X-Setup-Token header)\n\
             ==================================================================\n"
        );
    }

    /// Returns the active first-boot setup token, if any. Intended for setup
    /// tooling and tests; it is never rendered to unauthenticated web clients
    /// on its own.
    pub fn setup_token(&self) -> Option<String> {
        lock(&self.setup_token)
            .as_ref()
            .map(|entry| entry.token.clone())
    }

    /// Returns true while a first-boot setup token is active.
    pub fn setup_token_required(&self) -> bool {
        lock(&self.setup_token).is_some()
    }

    /// Invalidates the setup token (setup completed).
    pub fn consume_setup_token(&self) {
        *lock(&self.setup_token) = None;
    }

    fn setup_token_rate_limited(&self, client_ip: &str) -> bool {
        let mut windows = lock(&self.setup_token_failures);
        let now = Instant::now();
        windows.retain(|_, w| now.duration_since(w.window_start) <= SETUP_TOKEN_RATE_WINDOW);
        windows
            .get(client_ip)
            .is_some_and(|w| w.failures >= MAX_SETUP_TOKEN_FAILURES)
    }

    fn record_setup_token_failure(&self, client_ip: &str) {
        let mut windows = lock(&self.setup_token_failures);
        let now = Instant::now();
        let entry = windows
            .entry(client_ip.to_string())
            .or_insert(FailureWindow {
                window_start: now,
                failures: 0,
            });
        if now.duration_since(entry.window_start) > SETUP_TOKEN_RATE_WINDOW {
            entry.window_start = now;
            entry.failures = 0;
        }
        entry.failures = entry.failures.saturating_add(1);
    }

    /// Constant-time setup-token validation with per-client failure throttling.
    pub fn validate_setup_token(
        &self,
        candidate: Option<&str>,
        client_ip: &str,
    ) -> SetupTokenStatus {
        if self.setup_token_rate_limited(client_ip) {
            return SetupTokenStatus::RateLimited;
        }

        let guard = lock(&self.setup_token);
        let Some(ref entry) = *guard else {
            return SetupTokenStatus::Missing;
        };

        let Some(candidate) = candidate.filter(|c| !c.is_empty()) else {
            drop(guard);
            self.record_setup_token_failure(client_ip);
            return SetupTokenStatus::Missing;
        };

        let expected = entry.token.as_bytes();
        let supplied = candidate.as_bytes();
        let matches = expected.len() == supplied.len() && bool::from(expected.ct_eq(supplied));
        drop(guard);

        if matches {
            SetupTokenStatus::Valid
        } else {
            self.record_setup_token_failure(client_ip);
            SetupTokenStatus::Invalid
        }
    }

    // ------------------------------------------------------------------
    // Users
    // ------------------------------------------------------------------

    /// Returns true if the server is in first-run state (setup has not been completed and default credentials are active).
    pub fn is_first_run(&self) -> bool {
        !self.setup_complete.load(Ordering::SeqCst)
            && self.default_admin_active.load(Ordering::SeqCst)
    }

    /// Checks whether a user with the given username exists.
    pub fn has_user(&self, username: &str) -> bool {
        lock(&self.users).contains_key(username)
    }

    /// Lists user accounts (never includes password hashes or TOTP secrets).
    pub fn list_users(&self) -> Vec<UserDto> {
        let mut users: Vec<UserDto> = lock(&self.users)
            .values()
            .map(|u| UserDto {
                username: u.username.clone(),
                role: u.role.to_string(),
                totp_enabled: u.totp.as_ref().is_some_and(|t| t.enabled),
            })
            .collect();
        users.sort_by(|a, b| a.username.cmp(&b.username));
        users
    }

    /// Returns the role of a user, if the account exists.
    pub fn role_of(&self, username: &str) -> Option<Role> {
        lock(&self.users).get(username).map(|u| u.role)
    }

    /// Number of accounts with the Admin role.
    #[cfg(test)]
    fn admin_count(&self) -> usize {
        lock(&self.users)
            .values()
            .filter(|u| u.role == Role::Admin)
            .count()
    }

    /// Updates a user's role, revoking their sessions and owned API tokens (a
    /// role change must take effect immediately). Returns false when the user
    /// does not exist.
    ///
    /// This variant does not check the last-admin invariant; request handlers
    /// must use [`Self::set_user_role_checked`].
    pub async fn set_user_role(&self, username: &str, role: Role) -> bool {
        self.set_user_role_inner(username, role, false)
            .await
            .is_ok()
    }

    /// Atomically updates a user's role while protecting the last remaining
    /// Admin account.
    ///
    /// The last-admin check and the mutation happen under the same users lock,
    /// so two concurrent demotions cannot both pass. Returns whether the role
    /// actually changed, or a distinct [`UserMutationError`].
    pub async fn set_user_role_checked(
        &self,
        username: &str,
        role: Role,
    ) -> Result<bool, UserMutationError> {
        self.set_user_role_inner(username, role, true).await
    }

    async fn set_user_role_inner(
        &self,
        username: &str,
        role: Role,
        protect_last_admin: bool,
    ) -> Result<bool, UserMutationError> {
        // Serialize the whole mutation + save + rollback cycle.
        let _mutation = self.user_mutation_lock.lock().await;
        let (changed, previous_role, previous_epoch, mutated_epoch) = {
            let mut users = lock(&self.users);
            let admin_count = users.values().filter(|u| u.role == Role::Admin).count();
            let Some(user) = users.get_mut(username) else {
                return Err(UserMutationError::NotFound);
            };
            if protect_last_admin
                && user.role == Role::Admin
                && role != Role::Admin
                && admin_count <= 1
            {
                return Err(UserMutationError::LastAdmin);
            }
            let changed = user.role != role;
            if changed {
                let previous_role = user.role;
                let previous_epoch = user.credential_epoch;
                let mutated_epoch = self.next_credential_epoch();
                user.role = role;
                user.credential_epoch = mutated_epoch;
                (
                    true,
                    Some(previous_role),
                    Some(previous_epoch),
                    Some(mutated_epoch),
                )
            } else {
                (false, None, None, None)
            }
        };
        if changed {
            if let Err(e) = self.try_save_users_async().await {
                // Field-level, epoch-CAS rollback: only undo this mutation if
                // no newer credential state has replaced it.
                if let (Some(previous_role), Some(previous_epoch), Some(mutated_epoch)) =
                    (previous_role, previous_epoch, mutated_epoch)
                {
                    let mut users = lock(&self.users);
                    if let Some(current) = users.get_mut(username)
                        && current.credential_epoch == mutated_epoch
                    {
                        current.role = previous_role;
                        current.credential_epoch = previous_epoch;
                    }
                }
                return Err(UserMutationError::Persistence(e.to_string()));
            }
            self.purge_user_sessions(username).await;
            // An Admin-scoped token must not survive a demotion, and a
            // promotion changes the account's effective privileges too.
            self.revoke_tokens_for_owner(username).await;
        }
        Ok(changed)
    }

    /// Deletes a user account by username. Returns true if the user existed and was removed.
    ///
    /// This variant does not check the last-admin invariant; request handlers
    /// must use [`Self::delete_user_checked`].
    pub async fn delete_user(&self, username: &str) -> bool {
        self.delete_user_inner(username, false).await.is_ok()
    }

    /// Atomically deletes a user account while protecting the last remaining
    /// Admin account.
    ///
    /// The last-admin check and the removal happen under the same users lock,
    /// so concurrent deletions/demotions cannot both pass.
    pub async fn delete_user_checked(&self, username: &str) -> Result<(), UserMutationError> {
        self.delete_user_inner(username, true).await
    }

    async fn delete_user_inner(
        &self,
        username: &str,
        protect_last_admin: bool,
    ) -> Result<(), UserMutationError> {
        let _mutation = self.user_mutation_lock.lock().await;
        let (removed, previous_default_admin_active) = {
            let mut users = lock(&self.users);
            let Some(role) = users.get(username).map(|user| user.role) else {
                return Err(UserMutationError::NotFound);
            };
            if protect_last_admin
                && role == Role::Admin
                && users.values().filter(|u| u.role == Role::Admin).count() <= 1
            {
                return Err(UserMutationError::LastAdmin);
            }
            let removed = users.remove(username);
            (removed, self.default_admin_active.load(Ordering::SeqCst))
        };
        if username == "admin" {
            self.default_admin_active.store(false, Ordering::SeqCst);
        }
        if let Err(e) = self.try_save_users_async().await {
            // The account is still on disk: restore it (and the bootstrap
            // flag) so a failed write cannot look like a successful deletion.
            // Never overwrite an account that was recreated after this
            // deletion attempt removed the old one.
            if let Some(removed) = removed {
                let mut users = lock(&self.users);
                if !users.contains_key(username) {
                    users.insert(username.to_string(), removed);
                }
            }
            self.default_admin_active
                .store(previous_default_admin_active, Ordering::SeqCst);
            return Err(UserMutationError::Persistence(e.to_string()));
        }
        // A deleted account must lose access immediately: sessions are
        // not re-validated against the user table on every request.
        self.purge_user_sessions(username).await;
        // API tokens are credentials for the account too: never leave
        // them usable after the account is gone.
        self.revoke_tokens_for_owner(username).await;
        Ok(())
    }

    /// Returns true if the default bootstrapped admin user is still active with default password.
    pub fn is_default_admin_active(&self) -> bool {
        self.default_admin_active.load(Ordering::SeqCst)
    }

    /// Serializes setup-wizard completions. Hold this guard from before
    /// reading the setup state until the token has been consumed and setup has
    /// been marked complete.
    pub async fn lock_setup_completion(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.setup_completion_lock.clone().lock_owned().await
    }

    /// Returns true once setup has been completed.
    pub fn is_setup_complete(&self) -> bool {
        self.setup_complete.load(Ordering::SeqCst)
    }

    /// Marks initial setup as completed.
    pub fn mark_setup_complete(&self) {
        self.setup_complete.store(true, Ordering::SeqCst);
    }

    /// Creates or updates a user account. Hashing runs on the blocking pool.
    pub async fn create_user(&self, username: &str, password: &str, role: Role) {
        if let Err(e) = self.create_user_persisted(username, password, role).await {
            tracing::error!(user = username, error = %e, "Failed to create user");
        }
    }

    /// Creates or updates a user account and only reports success after the
    /// account store has been written. A failed write rolls the in-memory
    /// mutation back.
    pub(crate) async fn create_user_persisted(
        &self,
        username: &str,
        password: &str,
        role: Role,
    ) -> Result<(), String> {
        let _mutation = self.user_mutation_lock.lock().await;
        let (hash, is_default) = hash_password_blocking(password.to_string())
            .await
            .map_err(|e| format!("failed to hash password for '{username}': {e}"))?;
        let mutated_epoch = self.next_credential_epoch();
        let user = UserAccount {
            username: username.to_string(),
            password_hash: hash,
            role,
            // Always a fresh epoch: overwriting or recreating an account must
            // invalidate every credential issued for the previous identity.
            credential_epoch: mutated_epoch,
            totp: None,
        };
        let previous_user = {
            let mut users = lock(&self.users);
            if let Some(existing) = users.get(username)
                && existing.role == Role::Admin
                && role != Role::Admin
                && users.values().filter(|u| u.role == Role::Admin).count() <= 1
            {
                // The internal create path can overwrite an existing
                // account. Never let that remove the sole remaining Admin,
                // even though request handlers already reject duplicates.
                return Err(format!(
                    "refusing to overwrite the last remaining Admin '{username}' with a non-Admin role"
                ));
            }
            users.insert(username.to_string(), user)
        };
        if let Err(e) = self.try_save_users_async().await {
            let mut users = lock(&self.users);
            // Epoch-CAS: only undo this create/overwrite if the account still
            // carries the epoch this call installed.
            if users
                .get(username)
                .is_some_and(|current| current.credential_epoch == mutated_epoch)
            {
                match previous_user {
                    Some(previous) => {
                        users.insert(username.to_string(), previous);
                    }
                    None => {
                        users.remove(username);
                    }
                }
            }
            return Err(format!("failed to persist users file: {e}"));
        }
        if username == "admin" {
            self.default_admin_active
                .store(is_default, Ordering::SeqCst);
        }
        if previous_user.is_some() {
            // Overwriting an account (new password/role) revokes its sessions
            // and credentials so the previous identity cannot keep access.
            self.purge_user_sessions(username).await;
            self.revoke_tokens_for_owner(username).await;
        }
        Ok(())
    }

    /// Updates password for an existing user and invalidates their sessions.
    pub async fn update_user_password(&self, username: &str, password: &str) -> bool {
        self.update_user_password_tracked(username, password)
            .await
            .is_ok()
    }

    /// Updates a password and returns the previous hash only after the new
    /// hash has been persisted. Callers that must undo the change when a later
    /// step fails can pass the returned hash to
    /// [`Self::restore_user_password_hash`].
    pub(crate) async fn update_user_password_tracked(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<String>, UserMutationError> {
        let _mutation = self.user_mutation_lock.lock().await;
        let (hash, is_default) = hash_password_blocking(password.to_string())
            .await
            .map_err(UserMutationError::Persistence)?;

        let (previous_hash, previous_epoch, mutated_epoch) = {
            let mut users = lock(&self.users);
            let Some(user) = users.get_mut(username) else {
                return Err(UserMutationError::NotFound);
            };
            let previous_hash = user.password_hash.clone();
            let previous_epoch = user.credential_epoch;
            let mutated_epoch = self.next_credential_epoch();
            user.password_hash.clone_from(&hash);
            user.credential_epoch = mutated_epoch;
            (previous_hash, previous_epoch, mutated_epoch)
        };
        if let Err(e) = self.try_save_users_async().await {
            // Field-level, epoch-CAS rollback: never clobber a newer password
            // or another credential mutation.
            let mut users = lock(&self.users);
            if let Some(current) = users.get_mut(username)
                && current.credential_epoch == mutated_epoch
            {
                current.password_hash.clone_from(&previous_hash);
                current.credential_epoch = previous_epoch;
            }
            return Err(UserMutationError::Persistence(e.to_string()));
        }
        if username == "admin" {
            self.default_admin_active
                .store(is_default, Ordering::SeqCst);
        }
        self.purge_user_sessions(username).await;
        // A password change invalidates every credential derived from the old
        // password, including owned API tokens.
        self.revoke_tokens_for_owner(username).await;
        Ok(Some(previous_hash))
    }

    /// Password update for request handlers that must distinguish a missing
    /// account from a failed users-file write.
    pub(crate) async fn update_user_password_checked(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(), UserMutationError> {
        self.update_user_password_tracked(username, password)
            .await
            .map(|_| ())
    }

    /// Restores a password hash previously returned by
    /// [`Self::update_user_password_tracked`] and persists it.
    #[cfg_attr(not(feature = "embed-ui"), allow(dead_code))]
    pub(crate) async fn restore_user_password_hash(
        &self,
        username: &str,
        previous_hash: &str,
    ) -> Result<(), String> {
        let _mutation = self.user_mutation_lock.lock().await;
        let is_default = username == "admin"
            && verify_password_blocking("adminadmin".to_string(), previous_hash.to_string()).await;
        let (previous_current_hash, previous_epoch, mutated_epoch) = {
            let mut users = lock(&self.users);
            let Some(user) = users.get_mut(username) else {
                return Err(format!("user '{username}' does not exist"));
            };
            let previous_current_hash = user.password_hash.clone();
            let previous_epoch = user.credential_epoch;
            let mutated_epoch = self.next_credential_epoch();
            user.password_hash = previous_hash.to_string();
            user.credential_epoch = mutated_epoch;
            (previous_current_hash, previous_epoch, mutated_epoch)
        };
        if let Err(e) = self.try_save_users_async().await {
            let mut users = lock(&self.users);
            if let Some(current) = users.get_mut(username)
                && current.credential_epoch == mutated_epoch
            {
                current.password_hash = previous_current_hash;
                current.credential_epoch = previous_epoch;
            }
            return Err(format!("failed to persist users file: {e}"));
        }
        if username == "admin" {
            self.default_admin_active
                .store(is_default, Ordering::SeqCst);
        }
        self.purge_user_sessions(username).await;
        self.revoke_tokens_for_owner(username).await;
        Ok(())
    }

    /// Verifies a user's current password without holding the users lock
    /// across the Argon2 computation. Unknown users get a dummy verification
    /// to keep timing comparable.
    pub async fn verify_user_password(&self, username: &str, password: &str) -> bool {
        let stored = {
            let users = lock(&self.users);
            users.get(username).map(|u| u.password_hash.clone())
        };
        let (hash, exists) = match stored {
            Some(hash) => (hash, true),
            None => (dummy_password_hash().to_string(), false),
        };
        let verified = verify_password_blocking(password.to_string(), hash).await;
        exists && verified
    }

    /// Removes all active sessions belonging to a user (used after credential
    /// changes) and persists the revocation.
    pub async fn purge_user_sessions(&self, username: &str) {
        if self.purge_user_sessions_in_memory(username) {
            self.save_sessions_async().await;
        }
    }

    /// In-memory half of [`purge_user_sessions`]; returns whether anything was
    /// removed. Kept separate so callers can batch the persistence step.
    fn purge_user_sessions_in_memory(&self, username: &str) -> bool {
        let mut sessions = lock(&self.sessions);
        let before = sessions.len();
        sessions.retain(|_, session| session.username != username);
        let changed = sessions.len() != before;
        if changed {
            self.sessions_revision.fetch_add(1, Ordering::SeqCst);
        }
        changed
    }

    /// Inserts a session only if the account still exists with `expected_epoch`
    /// and the role observed when the password was verified. The users lock is
    /// held across the re-check and the insert so a concurrent credential
    /// mutation (which bumps the epoch under the same lock) cannot slip
    /// between them.
    async fn insert_session(&self, session: Session, expected_epoch: u64) -> Option<Session> {
        let session = {
            let users = lock(&self.users);
            let user = users.get(&session.username)?;
            if user.credential_epoch != expected_epoch {
                return None;
            }
            let session = session
                .with_generation(self.generation)
                .with_credential(user.role, user.credential_epoch);
            let mut sessions = lock(&self.sessions);
            if !sessions.contains_key(&session.id) && sessions.len() >= MAX_SESSIONS {
                sessions.retain(|_, s| !s.is_expired());
                // Deterministic eviction: oldest created_at first, then earliest
                // expiry, then id for total ordering.
                while sessions.len() >= MAX_SESSIONS {
                    let Some(oldest_key) = sessions
                        .values()
                        .min_by_key(|s| (s.created_at, s.expires_at, s.id.clone()))
                        .map(|s| s.id.clone())
                    else {
                        break;
                    };
                    sessions.remove(&oldest_key);
                }
            }
            sessions.insert(session.id.clone(), session.clone());
            self.sessions_revision.fetch_add(1, Ordering::SeqCst);
            session
        };
        self.save_sessions_async().await;
        Some(session)
    }

    // ------------------------------------------------------------------
    // Login / TOTP
    // ------------------------------------------------------------------

    /// Test-only pause between credential verification and session creation.
    #[cfg(test)]
    async fn await_login_test_gate(&self) {
        let gate = lock(&self.login_gate).take();
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.resume.notified().await;
        }
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_async)]
    async fn await_login_test_gate(&self) {}

    /// Primary login flow (`POST /auth/login`).
    pub async fn login(&self, username: &str, password: &str, client_ip: &str) -> LoginResult {
        // 1. IP rate limiting
        if !self
            .lockout
            .check_ip_rate_limit(client_ip, self.login_rate_limit)
        {
            return LoginResult::RateLimited;
        }

        // 2. Bound pre-auth input before it reaches lockout bookkeeping or the
        //    memory-hard password hash. Unbounded values are a cheap pre-auth
        //    DoS and were previously stored verbatim as lockout-map keys.
        if username.len() > MAX_LOGIN_USERNAME_BYTES || password.len() > MAX_LOGIN_PASSWORD_BYTES {
            return LoginResult::InvalidCredentials {
                remaining_attempts: crate::auth::lockout::MAX_FAILED_ATTEMPTS,
            };
        }

        let key = lockout_key(username);

        // 3. Check user lockout
        if let Some(secs) = self.lockout.check_lockout(&key) {
            return LoginResult::LockedOut {
                remaining_seconds: secs,
            };
        }

        // 3. Fetch the stored hash and TOTP state without holding the lock
        //    across the Argon2 verification.
        let stored = {
            let users = lock(&self.users);
            users.get(username).map(|u| {
                (
                    u.password_hash.clone(),
                    u.role,
                    u.credential_epoch,
                    u.totp.as_ref().is_some_and(|t| t.enabled),
                )
            })
        };

        // Unknown user: run a dummy verification so the response time does not
        // reveal whether the account exists.
        let Some((hash, role, credential_epoch, totp_enabled)) = stored else {
            let _ =
                verify_password_blocking(password.to_string(), dummy_password_hash().to_string())
                    .await;
            let (locked, rem) = self.lockout.record_failure(&key);
            return if locked {
                LoginResult::LockedOut {
                    remaining_seconds: crate::auth::lockout::LOCKOUT_DURATION_SECS,
                }
            } else {
                LoginResult::InvalidCredentials {
                    remaining_attempts: rem,
                }
            };
        };

        let password_valid = verify_password_blocking(password.to_string(), hash.clone()).await;
        if !password_valid {
            let (locked, rem) = self.lockout.record_failure(&key);
            return if locked {
                LoginResult::LockedOut {
                    remaining_seconds: crate::auth::lockout::LOCKOUT_DURATION_SECS,
                }
            } else {
                LoginResult::InvalidCredentials {
                    remaining_attempts: rem,
                }
            };
        }

        // Password valid. Pause here in tests so a credential mutation can be
        // interleaved before the session is created.
        self.await_login_test_gate().await;

        // Password valid: check if TOTP is enabled
        if totp_enabled {
            let mut bytes = [0u8; 32];
            rand::rng().fill(&mut bytes);
            let partial_token = hex::encode(bytes);

            let mut partials = lock(&self.partial_tokens);
            let now = Instant::now();
            if !partials.contains_key(&partial_token) && partials.len() >= MAX_PARTIAL_TOKENS {
                partials.retain(|_, auth| now < auth.expires_at);
                while partials.len() >= MAX_PARTIAL_TOKENS {
                    let Some(oldest_key) = partials
                        .iter()
                        .min_by_key(|(_, auth)| auth.expires_at)
                        .map(|(k, _)| k.clone())
                    else {
                        break;
                    };
                    partials.remove(&oldest_key);
                }
            }
            partials.insert(
                partial_token.clone(),
                PartialAuth {
                    username: username.to_string(),
                    credential_epoch,
                    expires_at: now + Duration::from_secs(300), // 5 minutes
                    failed_attempts: 0,
                },
            );

            return LoginResult::TotpRequired { partial_token };
        }

        // Authentication successful, provided the credential state did not
        // change while the password was being verified.
        let session = Session::new(username, role, self.session_ttl_secs);
        let Some(session) = self.insert_session(session, credential_epoch).await else {
            return LoginResult::StaleCredentials;
        };
        self.lockout.record_success(&key);
        LoginResult::Success(session)
    }

    /// Second login phase: verify TOTP code with partial token (`POST /auth/totp/verify`).
    pub async fn verify_totp(
        &self,
        partial_token: &str,
        code: &str,
        client_ip: &str,
    ) -> TotpVerifyResult {
        // 1. IP rate limiting (mirrors the first login phase)
        if !client_ip.is_empty()
            && !self
                .lockout
                .check_ip_rate_limit(client_ip, self.login_rate_limit)
        {
            return TotpVerifyResult::RateLimited;
        }

        // 2. Resolve and validate the partial token
        let (username, partial_epoch, is_expired) = {
            let partials = lock(&self.partial_tokens);
            let Some(auth) = partials.get(partial_token) else {
                return TotpVerifyResult::TokenExpired;
            };
            (
                auth.username.clone(),
                auth.credential_epoch,
                Instant::now() >= auth.expires_at,
            )
        };

        if is_expired {
            lock(&self.partial_tokens).remove(partial_token);
            return TotpVerifyResult::TokenExpired;
        }

        // 3. Account lockout check (digest key shared with the first phase).
        let key = lockout_key(&username);
        if let Some(secs) = self.lockout.check_lockout(&key) {
            return TotpVerifyResult::LockedOut {
                remaining_seconds: secs,
            };
        }

        // Serialize the read-verify-write cycle. Without this, two concurrent
        // requests with the same TOTP step both verify against the same
        // `last_used_step` and both succeed (code replay), and one backup code
        // can be consumed twice.
        let _verify_guard = self.totp_verification_lock.lock().await;

        let snapshot = {
            let users = lock(&self.users);
            users
                .get(&username)
                .map(|user| (user.role, user.credential_epoch, user.totp.clone()))
        };
        // The second factor must still belong to the credential state that
        // passed the password check. A password change, TOTP enable/disable or
        // role change while the code was entered invalidates the partial token.
        let Some((role, credential_epoch, Some(totp))) = snapshot else {
            lock(&self.partial_tokens).remove(partial_token);
            return TotpVerifyResult::TokenExpired;
        };
        if credential_epoch != partial_epoch || !totp.enabled {
            lock(&self.partial_tokens).remove(partial_token);
            return TotpVerifyResult::TokenExpired;
        }

        // 4. Verify off the async worker without holding the users lock.
        let code_owned = code.to_string();
        let username_for_verify = username.clone();
        let verified = tokio::task::spawn_blocking(move || {
            let mut config = totp;
            let ok = config.verify(&code_owned, &username_for_verify, "sito");
            (config, ok)
        })
        .await;

        let (updated_totp, valid) = match verified {
            Ok((config, ok)) => (Some(config), ok),
            Err(e) => {
                tracing::error!("TOTP verification task failed: {e}");
                (None, false)
            }
        };

        if let Some(updated_totp) = updated_totp
            && valid
        {
            // Test-only: allow a credential mutation to interleave after the
            // code was verified but before the session is created.
            self.await_login_test_gate().await;
            // Serialize the credential-state update with every other user
            // mutation. Lock order: TOTP verification lock, then mutation lock.
            let _mutation = self.user_mutation_lock.lock().await;
            // Success: consume the partial token first so it can never be
            // replayed, then re-check the credential epoch before writing the
            // TOTP state. A concurrent disable must win.
            lock(&self.partial_tokens).remove(partial_token);
            {
                let mut users = lock(&self.users);
                let Some(user) = users.get_mut(&username) else {
                    return TotpVerifyResult::TokenExpired;
                };
                if user.credential_epoch != credential_epoch {
                    return TotpVerifyResult::TokenExpired;
                }
                user.totp = Some(updated_totp);
            }
            if let Err(e) = self.try_save_users_async().await {
                tracing::error!(error = %e, "Failed to persist TOTP state after verification");
                return TotpVerifyResult::TokenExpired;
            }

            let session = Session::new(&username, role, self.session_ttl_secs);
            let Some(session) = self.insert_session(session, credential_epoch).await else {
                return TotpVerifyResult::TokenExpired;
            };
            self.lockout.record_success(&key);
            return TotpVerifyResult::Success(session);
        }

        // Failure: count it against both the partial token and the account lockout.
        let (locked, _rem) = self.lockout.record_failure(&key);
        let remaining_attempts = {
            let mut partials = lock(&self.partial_tokens);
            if let Some(auth) = partials.get_mut(partial_token) {
                auth.failed_attempts += 1;
                MAX_TOTP_ATTEMPTS.saturating_sub(auth.failed_attempts)
            } else {
                0
            }
        };
        if locked {
            // Account locked: consume the partial token as well.
            lock(&self.partial_tokens).remove(partial_token);
            return TotpVerifyResult::LockedOut {
                remaining_seconds: crate::auth::lockout::LOCKOUT_DURATION_SECS,
            };
        }
        if remaining_attempts == 0 {
            lock(&self.partial_tokens).remove(partial_token);
        }
        TotpVerifyResult::Invalid
    }

    /// Re-authenticates a live session for a sensitive operation and returns a
    /// short-lived ticket bound to that session and credential epoch.
    ///
    /// The current password is always required; when TOTP is enabled a current
    /// TOTP or backup code is required too. Failures share the login lockout
    /// so a stolen session cannot brute-force the password cheaply.
    pub async fn reauth(
        &self,
        username: &str,
        password: &str,
        code: Option<&str>,
        session_id: &str,
        client_ip: &str,
    ) -> Result<ReauthToken, ReauthError> {
        if !client_ip.is_empty()
            && !self
                .lockout
                .check_ip_rate_limit(client_ip, self.login_rate_limit)
        {
            return Err(ReauthError::RateLimited);
        }

        // Bound pre-auth input before lockout bookkeeping or Argon2, matching
        // `login` (and so an oversized value cannot grow the lockout map).
        if username.len() > MAX_LOGIN_USERNAME_BYTES || password.len() > MAX_LOGIN_PASSWORD_BYTES {
            return Err(ReauthError::InvalidCredentials);
        }

        let key = lockout_key(username);
        if let Some(remaining_seconds) = self.lockout.check_lockout(&key) {
            return Err(ReauthError::LockedOut { remaining_seconds });
        }

        if !self.verify_user_password(username, password).await {
            return Err(record_reauth_failure(
                &self.lockout,
                &key,
                ReauthError::InvalidCredentials,
            ));
        }

        let Some((credential_epoch, totp_enabled)) = lock(&self.users).get(username).map(|user| {
            (
                user.credential_epoch,
                user.totp.as_ref().is_some_and(|totp| totp.enabled),
            )
        }) else {
            return Err(record_reauth_failure(
                &self.lockout,
                &key,
                ReauthError::InvalidCredentials,
            ));
        };

        if totp_enabled {
            let Some(code) = code.map(str::trim).filter(|code| !code.is_empty()) else {
                return Err(record_reauth_failure(
                    &self.lockout,
                    &key,
                    ReauthError::SecondFactorRequired,
                ));
            };
            if !self.verify_second_factor(username, code).await {
                return Err(record_reauth_failure(
                    &self.lockout,
                    &key,
                    ReauthError::InvalidCredentials,
                ));
            }
        }

        self.lockout.record_success(&key);

        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        let token = hex::encode(bytes);
        let now = Instant::now();
        let expires_at = now + REAUTH_TOKEN_TTL;

        let mut tokens = lock(&self.reauth_tokens);
        if !tokens.contains_key(&token) && tokens.len() >= MAX_REAUTH_TOKENS {
            tokens.retain(|_, grant| now < grant.expires_at);
            while tokens.len() >= MAX_REAUTH_TOKENS {
                let Some(oldest_key) = tokens
                    .iter()
                    .min_by_key(|(_, grant)| grant.expires_at)
                    .map(|(key, _)| key.clone())
                else {
                    break;
                };
                tokens.remove(&oldest_key);
            }
        }
        tokens.insert(
            token.clone(),
            ReauthGrant {
                username: username.to_string(),
                session_id: session_id.to_string(),
                credential_epoch,
                expires_at,
            },
        );

        Ok(ReauthToken {
            token,
            expires_in: REAUTH_TOKEN_TTL.as_secs(),
        })
    }

    /// Returns true when `token` is a live re-authentication ticket for this
    /// account, session, and credential state.
    pub fn check_reauth_token(&self, token: &str, username: &str, session_id: &str) -> bool {
        let credential_epoch = lock(&self.users)
            .get(username)
            .map(|user| user.credential_epoch);
        let now = Instant::now();
        let mut tokens = lock(&self.reauth_tokens);
        tokens.retain(|_, grant| now < grant.expires_at);
        let Some(grant) = tokens.get(token) else {
            return false;
        };
        grant.username == username
            && grant.session_id == session_id
            && Some(grant.credential_epoch) == credential_epoch
    }

    /// Consumes a re-authentication ticket (single-use for an operation).
    ///
    /// The credential epoch is deliberately not re-checked here: the caller
    /// has already validated the ticket before performing the operation, and
    /// TOTP enable/disable bumps the epoch and revokes sessions as part of that
    /// operation. Matching the account and session is enough to retire it.
    pub fn consume_reauth_token(&self, token: &str, username: &str, session_id: &str) -> bool {
        let now = Instant::now();
        let mut tokens = lock(&self.reauth_tokens);
        tokens.retain(|_, grant| now < grant.expires_at);
        let matches = tokens
            .get(token)
            .is_some_and(|grant| grant.username == username && grant.session_id == session_id);
        if matches {
            tokens.remove(token);
        }
        matches
    }

    /// Starts a TOTP enrollment (secret + backup codes) for `username`.
    pub async fn begin_totp_enrollment(&self, username: &str) -> Option<TotpSetupResponse> {
        self.init_totp_setup(username).await
    }

    /// Initiates TOTP setup for a user (`GET /auth/totp/setup`). Backup-code
    /// hashing (Argon2) runs on the blocking pool.
    pub async fn init_totp_setup(&self, username: &str) -> Option<TotpSetupResponse> {
        let username_owned = username.to_string();
        let (config, resp) =
            tokio::task::spawn_blocking(move || TotpConfig::generate("sito", &username_owned))
                .await
                .ok()?;

        let now = Instant::now();
        let mut pending = lock(&self.pending_totp_setups);
        if !pending.contains_key(username) && pending.len() >= MAX_PENDING_TOTP {
            pending.retain(|_, p| now.duration_since(p.created_at) <= PENDING_TOTP_TTL);
            while pending.len() >= MAX_PENDING_TOTP {
                let Some(oldest_key) = pending
                    .iter()
                    .min_by_key(|(_, p)| p.created_at)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                pending.remove(&oldest_key);
            }
        }
        pending.insert(
            username.to_string(),
            PendingTotp {
                config,
                created_at: now,
            },
        );
        Some(resp)
    }

    /// Confirms and activates TOTP for a user using initial code verification.
    ///
    /// Returns false for an invalid code or a failed users-file write; request
    /// handlers use [`Self::try_confirm_totp_setup`] to report the difference.
    pub async fn confirm_totp_setup(&self, username: &str, code: &str) -> bool {
        self.try_confirm_totp_setup(username, code).await.is_ok()
    }

    /// Confirms and activates TOTP, failing closed when the users file cannot
    /// be written.
    pub(crate) async fn try_confirm_totp_setup(
        &self,
        username: &str,
        code: &str,
    ) -> Result<(), TotpMutationError> {
        let item = lock(&self.pending_totp_setups).remove(username);
        let Some(mut item) = item else {
            return Err(TotpMutationError::InvalidCode);
        };

        if Instant::now().duration_since(item.created_at) > PENDING_TOTP_TTL {
            return Err(TotpMutationError::InvalidCode);
        }

        let _totp_guard = self.totp_verification_lock.lock().await;
        // Lock order: TOTP verification lock, then user-mutation lock.
        let _mutation = self.user_mutation_lock.lock().await;
        let code_owned = code.to_string();
        let username_owned = username.to_string();
        let verified = tokio::task::spawn_blocking(move || {
            let ok = item.config.verify(&code_owned, &username_owned, "sito");
            (item.config, ok)
        })
        .await;

        let (mut config, ok) = verified.map_err(|_| TotpMutationError::InvalidCode)?;
        if !ok {
            return Err(TotpMutationError::InvalidCode);
        }

        config.enabled = true;
        let (previous_totp, previous_epoch, mutated_epoch) = {
            let mut users = lock(&self.users);
            let Some(user) = users.get_mut(username) else {
                return Err(TotpMutationError::NotFound);
            };
            let previous_totp = user.totp.clone();
            let previous_epoch = user.credential_epoch;
            let mutated_epoch = self.next_credential_epoch();
            user.totp = Some(config);
            user.credential_epoch = mutated_epoch;
            (previous_totp, previous_epoch, mutated_epoch)
        };
        if let Err(e) = self.try_save_users_async().await {
            // Field-level, epoch-CAS rollback: never discard a newer TOTP
            // enable/disable from another operation.
            let mut users = lock(&self.users);
            if let Some(current) = users.get_mut(username)
                && current.credential_epoch == mutated_epoch
            {
                current.totp = previous_totp;
                current.credential_epoch = previous_epoch;
            }
            return Err(TotpMutationError::Persistence(e.to_string()));
        }
        // Changing the second factor invalidates existing sessions and every
        // API token owned by the account, matching the disable lifecycle: a
        // credential must not outlive the factor it was issued under.
        self.purge_user_sessions(username).await;
        self.revoke_tokens_for_owner(username).await;
        Ok(())
    }

    /// Returns true when the user has TOTP enabled.
    pub fn totp_enabled(&self, username: &str) -> bool {
        lock(&self.users)
            .get(username)
            .and_then(|u| u.totp.as_ref())
            .is_some_and(|t| t.enabled)
    }

    /// Verifies a TOTP or backup code for a user (used for re-authentication),
    /// consuming a backup code on success.
    pub async fn verify_second_factor(&self, username: &str, code: &str) -> bool {
        let _totp_guard = self.totp_verification_lock.lock().await;
        // Lock order: TOTP verification lock, then user-mutation lock.
        let _mutation = self.user_mutation_lock.lock().await;
        let snapshot = lock(&self.users)
            .get(username)
            .map(|user| (user.credential_epoch, user.totp.clone()));
        let Some((credential_epoch, Some(previous_totp))) = snapshot else {
            return false;
        };
        if !previous_totp.enabled {
            return false;
        }
        let totp = previous_totp.clone();

        let code_owned = code.to_string();
        let username_owned = username.to_string();
        let verified = tokio::task::spawn_blocking(move || {
            let mut config = totp;
            let ok = config.verify(&code_owned, &username_owned, "sito");
            (config, ok)
        })
        .await;

        let Ok((updated, ok)) = verified else {
            return false;
        };
        if ok {
            {
                let mut users = lock(&self.users);
                let Some(user) = users.get_mut(username) else {
                    return false;
                };
                if user.credential_epoch != credential_epoch {
                    return false;
                }
                user.totp = Some(updated);
            }
            if let Err(e) = self.try_save_users_async().await {
                // A consumed backup code or advanced replay counter that did
                // not reach disk must not authorize a sensitive operation.
                tracing::error!(error = %e, "Failed to persist TOTP verification state");
                let mut users = lock(&self.users);
                if let Some(user) = users.get_mut(username)
                    && user.credential_epoch == credential_epoch
                {
                    user.totp = Some(previous_totp);
                }
                return false;
            }
        }
        ok
    }

    /// Disables TOTP 2FA for a user and invalidates their sessions.
    ///
    /// Returns false for a missing account or a failed users-file write;
    /// request handlers use [`Self::try_disable_totp`] to report the
    /// difference.
    pub async fn disable_totp(&self, username: &str) -> bool {
        self.try_disable_totp(username).await.is_ok()
    }

    /// Disables TOTP, failing closed when the users file cannot be written.
    pub(crate) async fn try_disable_totp(&self, username: &str) -> Result<(), TotpMutationError> {
        let _mutation = self.user_mutation_lock.lock().await;
        let (previous_totp, previous_epoch, mutated_epoch) = {
            let mut users = lock(&self.users);
            let Some(user) = users.get_mut(username) else {
                return Err(TotpMutationError::NotFound);
            };
            let Some(previous_totp) = user.totp.clone() else {
                return Ok(());
            };
            let previous_epoch = user.credential_epoch;
            let mutated_epoch = self.next_credential_epoch();
            user.totp = None;
            user.credential_epoch = mutated_epoch;
            (previous_totp, previous_epoch, mutated_epoch)
        };
        if let Err(e) = self.try_save_users_async().await {
            let mut users = lock(&self.users);
            if let Some(current) = users.get_mut(username)
                && current.credential_epoch == mutated_epoch
            {
                current.totp = Some(previous_totp);
                current.credential_epoch = previous_epoch;
            }
            return Err(TotpMutationError::Persistence(e.to_string()));
        }
        self.purge_user_sessions(username).await;
        // Disabling a second factor is a credential change: owned API tokens
        // must not outlive it.
        self.revoke_tokens_for_owner(username).await;
        Ok(())
    }

    /// Validates an active session from a cookie.
    ///
    /// Besides TTL and the global auth generation, the account must still
    /// exist with the same role and credential epoch the session was issued
    /// under. This makes password/role/TOTP/deletion revocations effective
    /// even when a session insert raced the mutation or a persisted session
    /// file outlived it.
    pub fn validate_session(&self, session_id: &str) -> Option<Session> {
        let session = {
            let sessions = lock(&self.sessions);
            sessions.get(session_id)?.clone()
        };
        let invalid = if session.generation != self.generation || session.is_expired() {
            true
        } else {
            match session.credential_epoch {
                // Prefix/legacy sessions have no epoch: force re-login.
                None => true,
                Some(epoch) => {
                    let users = lock(&self.users);
                    users.get(&session.username).is_none_or(|user| {
                        user.credential_epoch != epoch || user.role != session.role
                    })
                }
            }
        };
        if invalid {
            let mut sessions = lock(&self.sessions);
            if sessions.remove(session_id).is_some() {
                // Readers may prune as a side effect; the pruner persists this
                // removal within 60 seconds (revision guards the retry).
                self.sessions_revision.fetch_add(1, Ordering::SeqCst);
                self.sessions_dirty.store(true, Ordering::SeqCst);
            }
            return None;
        }
        // Re-read after the user-table check: a concurrent revocation may have
        // removed the session in the meantime. Never resurrect the old copy.
        lock(&self.sessions).get(session_id).cloned()
    }

    /// Logs out and destroys an active session.
    pub async fn logout(&self, session_id: &str) {
        let removed = {
            let mut sessions = lock(&self.sessions);
            let removed = sessions.remove(session_id).is_some();
            if removed {
                self.sessions_revision.fetch_add(1, Ordering::SeqCst);
            }
            removed
        };
        if removed {
            self.save_sessions_async().await;
        }
    }

    /// Revokes every API token owned by `username` and persists the change.
    ///
    /// Legacy ownerless tokens are intentionally not matched: they are not
    /// tied to an account and remain Admin-managed.
    pub async fn revoke_tokens_for_owner(&self, username: &str) {
        if self.revoke_tokens_for_owner_in_memory(username) {
            self.save_tokens_async().await;
        }
    }

    /// In-memory half of [`revoke_tokens_for_owner`]; returns whether anything
    /// was removed so callers can skip an unnecessary persistence write.
    fn revoke_tokens_for_owner_in_memory(&self, username: &str) -> bool {
        let mut tokens = lock(&self.tokens);
        let before = tokens.len();
        tokens.retain(|_, token| token.owner.as_deref() != Some(username));
        let changed = tokens.len() != before;
        if changed {
            self.tokens_revision.fetch_add(1, Ordering::SeqCst);
        }
        changed
    }

    /// Creates a new API token owned by `owner`.
    ///
    /// A single owner may hold at most [`MAX_API_TOKENS_PER_OWNER`] tokens;
    /// creating one more evicts that owner's oldest token. At the global
    /// capacity limit only a token owned by the same account is evicted
    /// (oldest first). If the owner has no token to evict, the create fails
    /// instead of silently deleting another account's credential.
    pub async fn create_token(
        &self,
        name: &str,
        scope: Role,
        owner: Option<&str>,
    ) -> Result<(ApiTokenMeta, CreateTokenResponse), CreateTokenError> {
        let (mut meta, resp) = generate_token(name, scope);
        meta.generation = self.generation;
        meta.credential_epoch = match owner {
            Some(owner) => lock(&self.users)
                .get(owner)
                .map(|user| user.credential_epoch),
            // Ownerless tokens are not tied to an account. `Some(0)` marks a
            // post-upgrade token so legacy epochless entries can be rejected.
            None => Some(0),
        };
        meta.owner = owner.map(str::to_string);
        if self.token_default_ttl_days > 0 {
            let ttl_secs = i64::try_from(self.token_default_ttl_days)
                .unwrap_or(i64::MAX / 86_400)
                .saturating_mul(86_400);
            meta.expires_at = Some(chrono::Utc::now().timestamp().saturating_add(ttl_secs));
        }
        {
            let mut tokens = lock(&self.tokens);
            let now = chrono::Utc::now().timestamp();
            tokens.retain(|_, t| t.expires_at.is_none_or(|exp| now < exp));

            // Per-owner quota. Legacy ownerless tokens are not an owner and
            // keep relying on the global cap below. The loop also trims state
            // persisted before the per-owner quota existed.
            if let Some(owner_name) = owner {
                loop {
                    let owner_count = tokens
                        .values()
                        .filter(|token| token.owner.as_deref() == Some(owner_name))
                        .count();
                    if owner_count < MAX_API_TOKENS_PER_OWNER {
                        break;
                    }
                    let oldest_key = tokens
                        .iter()
                        .filter(|(_, token)| token.owner.as_deref() == Some(owner_name))
                        .min_by_key(|(_, token)| (token.created_at, token.id.clone()))
                        .map(|(key, _)| key.clone());
                    let Some(key) = oldest_key else {
                        break;
                    };
                    tokens.remove(&key);
                }
            }

            if tokens.len() >= MAX_API_TOKENS {
                let oldest_same_owner = tokens
                    .iter()
                    .filter(|(_, t)| t.owner.as_deref() == owner)
                    .min_by_key(|(_, t)| (t.created_at, t.id.clone()))
                    .map(|(k, _)| k.clone());
                if let Some(key) = oldest_same_owner {
                    tokens.remove(&key);
                } else {
                    // Expired/over-quota trims above may already have mutated
                    // the store even though creation fails.
                    self.tokens_revision.fetch_add(1, Ordering::SeqCst);
                    return Err(CreateTokenError::CapacityReached);
                }
            }
            tokens.insert(meta.hash.clone(), meta.clone());
            self.tokens_revision.fetch_add(1, Ordering::SeqCst);
        }
        self.save_tokens_async().await;
        Ok((meta, resp))
    }

    /// Lists all active API tokens.
    pub fn list_tokens(&self) -> Vec<ApiTokenMeta> {
        lock(&self.tokens).values().cloned().collect()
    }

    /// Revokes an API token by ID.
    pub async fn delete_token(&self, id: &str) -> bool {
        let removed = {
            let mut tokens = lock(&self.tokens);
            if let Some(key) = tokens
                .iter()
                .find(|(_, m)| m.id == id)
                .map(|(k, _)| k.clone())
            {
                tokens.remove(&key);
                self.tokens_revision.fetch_add(1, Ordering::SeqCst);
                true
            } else {
                false
            }
        };
        if removed {
            self.save_tokens_async().await;
        }
        removed
    }

    /// Validates a bearer API token string against stored Blake3 hashes using constant-time comparison.
    ///
    /// This stays synchronous because it runs in the request extractor. A token
    /// that is expired or was issued under a previous auth generation is
    /// removed from memory and the store is marked dirty; the background
    /// pruner persists that removal within 60 seconds. Revocation is effective
    /// immediately on every replica (the in-memory entry is gone and the
    /// generation check rejects stale copies), only the on-disk snapshot lags.
    pub fn validate_token(&self, token: &str) -> Option<ApiTokenMeta> {
        let hash = hash_token(token);
        let hash_bytes = hash.as_bytes();
        let key = {
            let tokens = lock(&self.tokens);
            let mut matched_key: Option<String> = None;
            for stored_hash in tokens.keys() {
                let stored_bytes = stored_hash.as_bytes();
                if stored_bytes.len() == hash_bytes.len()
                    && bool::from(stored_bytes.ct_eq(hash_bytes))
                {
                    matched_key = Some(stored_hash.clone());
                }
            }
            matched_key?
        };

        let meta = {
            let tokens = lock(&self.tokens);
            tokens.get(&key)?.clone()
        };
        let now = chrono::Utc::now().timestamp();
        let invalid = if meta.generation != self.generation
            || meta.expires_at.is_some_and(|expires_at| now >= expires_at)
        {
            true
        } else {
            match meta.credential_epoch {
                // Legacy tokens have no epoch: re-issue after upgrade.
                None => true,
                Some(epoch) => match meta.owner.as_deref() {
                    // Ownerless tokens are Admin-managed and not tied to an
                    // account; the global generation still applies.
                    None => false,
                    Some(owner) => {
                        let users = lock(&self.users);
                        users.get(owner).is_none_or(|user| {
                            user.credential_epoch != epoch || user.role < meta.scope
                        })
                    }
                },
            }
        };
        let mut tokens = lock(&self.tokens);
        if invalid {
            if tokens.remove(&key).is_some() {
                self.tokens_revision.fetch_add(1, Ordering::SeqCst);
                self.tokens_dirty.store(true, Ordering::SeqCst);
            }
            return None;
        }
        let meta = tokens.get_mut(&key)?;
        meta.last_used = Some(chrono::Utc::now().timestamp_millis());
        self.tokens_revision.fetch_add(1, Ordering::SeqCst);
        self.tokens_dirty.store(true, Ordering::SeqCst);
        Some(meta.clone())
    }

    /// Prunes expired sessions, partial tokens, pending TOTP setups, API
    /// tokens and rate-limit state.
    pub async fn prune(&self) {
        self.lockout.prune();
        let sessions_changed = {
            let mut sessions = lock(&self.sessions);
            let before = sessions.len();
            sessions.retain(|_, s| !s.is_expired());
            let changed = sessions.len() != before;
            if changed {
                self.sessions_revision.fetch_add(1, Ordering::SeqCst);
            }
            changed
        };
        if sessions_changed || self.sessions_dirty.load(Ordering::SeqCst) {
            self.save_sessions_async().await;
        }
        let tokens_changed = {
            let now = chrono::Utc::now().timestamp();
            let mut tokens = lock(&self.tokens);
            let before = tokens.len();
            tokens.retain(|_, t| t.expires_at.is_none_or(|exp| now < exp));
            let changed = tokens.len() != before;
            if changed {
                self.tokens_revision.fetch_add(1, Ordering::SeqCst);
            }
            changed
        };
        if tokens_changed || self.tokens_dirty.load(Ordering::SeqCst) {
            self.save_tokens_async().await;
        }
        {
            let now = Instant::now();
            let mut pending = lock(&self.pending_totp_setups);
            pending.retain(|_, p| now.duration_since(p.created_at) <= PENDING_TOTP_TTL);
        }
        {
            let now = Instant::now();
            let mut partials = lock(&self.partial_tokens);
            partials.retain(|_, p| now < p.expires_at);
        }
        {
            let now = Instant::now();
            let mut reauth = lock(&self.reauth_tokens);
            reauth.retain(|_, grant| now < grant.expires_at);
        }
        {
            let now = Instant::now();
            let mut windows = lock(&self.setup_token_failures);
            windows.retain(|_, w| now.duration_since(w.window_start) <= SETUP_TOKEN_RATE_WINDOW);
        }
        // The setup token must never silently expire while the deployment is
        // still in first-run state: without it, `/ui/wizard/complete` would be
        // reachable unauthenticated and an attacker could claim the admin
        // account. It is consumed when setup completes; clear any leftover
        // once `setup_complete` is set by another path.
        let setup_complete = self.setup_complete.load(Ordering::SeqCst);
        let mut token = lock(&self.setup_token);
        if setup_complete {
            if token.take().is_some() {
                self.setup_pending_warned.store(false, Ordering::SeqCst);
            }
        } else if let Some(entry) = token.as_ref()
            && entry.created_at.elapsed() > SETUP_TOKEN_PENDING_WARN
            && !self.setup_pending_warned.swap(true, Ordering::SeqCst)
        {
            tracing::warn!(
                "Setup mode has been pending for over 24 hours; the first-boot setup token \
                 remains required until setup completes (see the token printed at startup)"
            );
        }
    }

    /// Ages the setup token for tests (no effect when no token is active).
    #[cfg(test)]
    pub fn age_setup_token_for_test(&self, age: Duration) {
        let mut token = lock(&self.setup_token);
        if let Some(entry) = token.as_mut() {
            entry.created_at = Instant::now()
                .checked_sub(age)
                .expect("test age must fit in Instant range");
        }
    }

    /// Spawns a background task to periodically prune expired sessions and entries until shutdown.
    pub fn spawn_pruner(
        self: &Arc<Self>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        mgr.prune().await;
                    }
                }
            }
        })
    }

    #[cfg(test)]
    pub fn sessions_len(&self) -> usize {
        lock(&self.sessions).len()
    }

    #[cfg(test)]
    pub fn partial_tokens_len(&self) -> usize {
        lock(&self.partial_tokens).len()
    }

    #[cfg(test)]
    pub fn pending_totp_len(&self) -> usize {
        lock(&self.pending_totp_setups).len()
    }

    #[cfg(test)]
    pub fn reauth_tokens_len(&self) -> usize {
        lock(&self.reauth_tokens).len()
    }

    #[cfg(test)]
    pub fn expire_session_for_test(&self, session_id: &str) {
        let mut sessions = lock(&self.sessions);
        if let Some(s) = sessions.get_mut(session_id) {
            s.expires_at = 0;
        }
    }

    #[cfg(test)]
    pub fn expire_partial_tokens_for_test(&self) {
        let mut partials = lock(&self.partial_tokens);
        for auth in partials.values_mut() {
            auth.expires_at = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
        }
    }

    #[cfg(test)]
    pub fn expire_pending_totp_for_test(&self) {
        let mut pending = lock(&self.pending_totp_setups);
        for p in pending.values_mut() {
            p.created_at = Instant::now()
                .checked_sub(Duration::from_secs(1000))
                .unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sito_auth_{label}_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn in_memory_totp_secret(mgr: &AuthManager, username: &str) -> String {
        lock(&mgr.users)
            .get(username)
            .and_then(|u| u.totp.as_ref())
            .map(|t| t.secret.clone())
            .expect("user has TOTP configured")
    }

    async fn enable_totp(mgr: &AuthManager, username: &str) -> TotpSetupResponse {
        let setup = mgr.init_totp_setup(username).await.expect("totp setup");
        assert!(
            mgr.confirm_totp_setup(username, &setup.backup_codes[0])
                .await,
            "TOTP setup must be confirmed"
        );
        setup
    }

    #[tokio::test]
    async fn test_auth_manager_login_and_session() {
        let mgr = AuthManager::new();
        // Login with default admin
        match mgr.login("admin", "adminadmin", "127.0.0.1").await {
            LoginResult::Success(session) => {
                assert_eq!(session.username, "admin");
                assert_eq!(session.role, Role::Admin);
                assert!(mgr.validate_session(&session.id).is_some());
                mgr.logout(&session.id).await;
                assert!(mgr.validate_session(&session.id).is_none());
            }
            _ => panic!("Expected successful login"),
        }
    }

    #[tokio::test]
    async fn test_unknown_user_and_wrong_password_are_rejected() {
        let mgr = AuthManager::new();
        assert!(matches!(
            mgr.login("ghost", "whatever", "127.0.0.1").await,
            LoginResult::InvalidCredentials { .. }
        ));
        assert!(matches!(
            mgr.login("admin", "wrongpassword", "127.0.0.1").await,
            LoginResult::InvalidCredentials { .. }
        ));
    }

    /// WP-0.7 (P1-20): pre-auth inputs are bounded before lockout bookkeeping
    /// and Argon2, and the lockout map never stores the raw username.
    #[tokio::test]
    async fn test_login_rejects_oversized_credentials_before_lockout() {
        let mgr = AuthManager::new();

        let long_username = "u".repeat(MAX_LOGIN_USERNAME_BYTES + 1);
        assert!(matches!(
            mgr.login(&long_username, "whatever", "127.0.0.1").await,
            LoginResult::InvalidCredentials { .. }
        ));
        assert_eq!(
            mgr.lockout.attempts_len(),
            0,
            "oversized usernames must not create lockout entries"
        );

        let long_password = "p".repeat(MAX_LOGIN_PASSWORD_BYTES + 1);
        assert!(matches!(
            mgr.login("admin", &long_password, "127.0.0.1").await,
            LoginResult::InvalidCredentials { .. }
        ));
        assert_eq!(
            mgr.lockout.attempts_len(),
            0,
            "oversized passwords must be rejected before the lockout/Argon2 path"
        );
    }

    #[tokio::test]
    async fn test_login_lockout_key_is_a_digest() {
        let mgr = AuthManager::new();
        for _ in 0..5 {
            let _ = mgr.login("admin", "wrongpassword", "127.0.0.1").await;
        }
        let keys = mgr.lockout.attempt_keys();
        assert_eq!(keys.len(), 1);
        assert!(
            !keys[0].contains("admin"),
            "the raw username must never be a lockout-map key: {keys:?}"
        );
        assert_eq!(keys[0], lockout_key("admin"));
    }

    /// Deferred D4b: re-auth must report the threshold-crossing failure as a
    /// lockout (matching login), not return 401 once more and 429 only on the
    /// following attempt.
    #[tokio::test]
    async fn test_reauth_lockout_triggers_on_the_fifth_failure() {
        let mgr = AuthManager::new();
        let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await
        else {
            panic!("login failed");
        };

        for attempt in 1..crate::auth::lockout::MAX_FAILED_ATTEMPTS {
            assert!(
                matches!(
                    mgr.reauth("admin", "wrongpassword", None, &session.id, "")
                        .await,
                    Err(ReauthError::InvalidCredentials)
                ),
                "attempt {attempt} must stay a 401"
            );
        }
        assert!(
            matches!(
                mgr.reauth("admin", "wrongpassword", None, &session.id, "")
                    .await,
                Err(ReauthError::LockedOut { .. })
            ),
            "the fifth failure must be the 429 lockout, like login"
        );
    }

    /// Deferred D4b: oversized re-auth credentials are rejected before the
    /// lockout check and Argon2 (matching login), including while locked out.
    #[tokio::test]
    async fn test_reauth_rejects_oversized_credentials_before_lockout() {
        let mgr = AuthManager::new();
        let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await
        else {
            panic!("login failed");
        };
        for _ in 0..crate::auth::lockout::MAX_FAILED_ATTEMPTS {
            let _ = mgr
                .reauth("admin", "wrongpassword", None, &session.id, "")
                .await;
        }
        assert!(mgr.lockout.check_lockout(&lockout_key("admin")).is_some());

        let long_username = "u".repeat(MAX_LOGIN_USERNAME_BYTES + 1);
        assert!(matches!(
            mgr.reauth(&long_username, "whatever", None, &session.id, "")
                .await,
            Err(ReauthError::InvalidCredentials)
        ));
        let long_password = "p".repeat(MAX_LOGIN_PASSWORD_BYTES + 1);
        assert!(matches!(
            mgr.reauth("admin", &long_password, None, &session.id, "")
                .await,
            Err(ReauthError::InvalidCredentials)
        ));
        assert_eq!(
            mgr.lockout.attempts_len(),
            1,
            "oversized inputs must not create or extend lockout entries"
        );
    }

    #[tokio::test]
    async fn test_auth_manager_totp_flow() {
        let mgr = AuthManager::new();
        let setup = mgr.init_totp_setup("admin").await.expect("setup");

        // Use backup code to confirm setup
        assert!(
            mgr.confirm_totp_setup("admin", &setup.backup_codes[0])
                .await
        );

        // Login now requires TOTP
        match mgr.login("admin", "adminadmin", "127.0.0.1").await {
            LoginResult::TotpRequired { partial_token } => {
                // Invalid code fails
                assert!(matches!(
                    mgr.verify_totp(&partial_token, "000000", "127.0.0.1").await,
                    TotpVerifyResult::Invalid
                ));
                // Valid backup code succeeds
                let session = match mgr
                    .verify_totp(&partial_token, &setup.backup_codes[1], "127.0.0.1")
                    .await
                {
                    TotpVerifyResult::Success(session) => session,
                    other => panic!("expected TOTP success, got {other:?}"),
                };
                assert_eq!(session.role, Role::Admin);
            }
            _ => panic!("Expected TOTP required"),
        }
    }

    #[tokio::test]
    async fn test_totp_bruteforce_attempt_limit() {
        // High IP rate limit so the per-account lockout/attempt cap is exercised.
        let mgr = AuthManager::with_config(24, 1000);
        let setup = mgr.init_totp_setup("admin").await.expect("setup");
        assert!(
            mgr.confirm_totp_setup("admin", &setup.backup_codes[0])
                .await
        );

        let LoginResult::TotpRequired { partial_token } =
            mgr.login("admin", "adminadmin", "127.0.0.1").await
        else {
            panic!("Expected TOTP required");
        };

        let mut saw_terminal = false;
        for _ in 0..MAX_TOTP_ATTEMPTS {
            match mgr.verify_totp(&partial_token, "000000", "127.0.0.1").await {
                TotpVerifyResult::Invalid => {}
                TotpVerifyResult::LockedOut { .. } => {
                    saw_terminal = true;
                    break;
                }
                other => panic!("unexpected TOTP result: {other:?}"),
            }
        }
        assert!(
            saw_terminal,
            "repeated wrong TOTP codes must eventually lock the account"
        );

        // The partial token is consumed and cannot be used with a valid code.
        assert!(matches!(
            mgr.verify_totp(&partial_token, &setup.backup_codes[1], "127.0.0.1")
                .await,
            TotpVerifyResult::TokenExpired | TotpVerifyResult::LockedOut { .. }
        ));
    }

    #[tokio::test]
    async fn test_totp_backup_code_is_single_use_under_concurrency() {
        let mgr = Arc::new(AuthManager::new());
        let setup = mgr.init_totp_setup("admin").await.expect("setup");
        assert!(
            mgr.confirm_totp_setup("admin", &setup.backup_codes[0])
                .await
        );

        let LoginResult::TotpRequired { partial_token: t1 } =
            mgr.login("admin", "adminadmin", "127.0.0.1").await
        else {
            panic!("Expected TOTP required");
        };
        let LoginResult::TotpRequired { partial_token: t2 } =
            mgr.login("admin", "adminadmin", "127.0.0.2").await
        else {
            panic!("Expected TOTP required");
        };

        // Both requests race on the same unused backup code.
        let code = setup.backup_codes[1].clone();
        let code_2 = code.clone();
        let mgr_2 = Arc::clone(&mgr);
        let (r1, r2) = tokio::join!(mgr.verify_totp(&t1, &code, "127.0.0.1"), async move {
            mgr_2.verify_totp(&t2, &code_2, "127.0.0.2").await
        },);

        let successes = [&r1, &r2]
            .iter()
            .filter(|r| matches!(r, TotpVerifyResult::Success(_)))
            .count();
        assert_eq!(
            successes, 1,
            "a backup code must be consumed exactly once: {r1:?} / {r2:?}"
        );
    }

    #[tokio::test]
    async fn test_delete_user_revokes_sessions() {
        let mgr = AuthManager::new();
        let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await
        else {
            panic!("expected direct login");
        };
        assert!(mgr.validate_session(&session.id).is_some());

        assert!(mgr.delete_user("admin").await);
        assert!(
            mgr.validate_session(&session.id).is_none(),
            "a deleted account's sessions must be invalidated"
        );
    }

    #[tokio::test]
    async fn test_auth_manager_api_tokens() {
        let mgr = AuthManager::new();
        let (meta, resp) = mgr
            .create_token("grafana", Role::Viewer, Some("admin"))
            .await
            .expect("token");

        assert_eq!(mgr.list_tokens().len(), 1);
        let validated = mgr.validate_token(&resp.token).expect("valid token");
        assert_eq!(validated.id, meta.id);
        assert_eq!(validated.scope, Role::Viewer);
        assert_eq!(validated.owner.as_deref(), Some("admin"));

        assert!(mgr.delete_token(&meta.id).await);
        assert!(mgr.validate_token(&resp.token).is_none());
        assert_eq!(mgr.list_tokens().len(), 0);
    }

    #[tokio::test]
    async fn test_api_token_cap_evicts() {
        let mgr = AuthManager::new();
        for i in 0..(MAX_API_TOKENS + 5) {
            mgr.create_token(&format!("tok-{i}"), Role::Viewer, None)
                .await
                .expect("token");
        }
        assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS);
    }

    #[tokio::test]
    async fn test_api_token_capacity_never_evicts_another_owners_token() {
        let mgr = AuthManager::new();
        // Fill the global store to MAX_API_TOKENS with owned tokens only:
        // 15 owners at the per-owner quota plus a 16th owner.
        for owner in 0..(MAX_API_TOKENS / MAX_API_TOKENS_PER_OWNER - 1) {
            let owner = format!("owner-{owner}");
            for i in 0..MAX_API_TOKENS_PER_OWNER {
                create_owned_token(&mgr, &owner, &format!("{owner}-{i}")).await;
            }
        }
        for i in 0..MAX_API_TOKENS_PER_OWNER {
            create_owned_token(&mgr, "admin", &format!("admin-{i}")).await;
        }
        assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS);

        let err = mgr
            .create_token("viewer-new", Role::Viewer, Some("viewer"))
            .await
            .expect_err("full store must not evict another owner's token");
        assert_eq!(err, CreateTokenError::CapacityReached);
        assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS);
        assert!(
            mgr.list_tokens().iter().all(|token| token.owner.is_some()),
            "the failed create must not have evicted another owner's token"
        );

        // The same owner can still rotate its oldest token at the global cap.
        mgr.create_token("admin-new", Role::Admin, Some("admin"))
            .await
            .expect("same-owner rotation");
        assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS);
        assert!(
            mgr.list_tokens()
                .iter()
                .any(|token| token.name == "admin-new")
        );
        assert_eq!(
            mgr.list_tokens()
                .iter()
                .filter(|token| token.owner.as_deref() == Some("owner-0"))
                .count(),
            MAX_API_TOKENS_PER_OWNER,
            "another owner's tokens must be untouched"
        );
    }

    #[tokio::test]
    async fn test_global_cap_evicts_only_same_owner_below_per_owner_quota() {
        let mgr = AuthManager::new();
        // 15 owners at the per-owner quota => 240 tokens.
        for owner in 0..(MAX_API_TOKENS / MAX_API_TOKENS_PER_OWNER - 1) {
            let owner = format!("owner-{owner}");
            for i in 0..MAX_API_TOKENS_PER_OWNER {
                create_owned_token(&mgr, &owner, &format!("{owner}-{i}")).await;
            }
        }
        // A 16th owner with 15 tokens => 255, leaving one free global slot.
        let partial_owner = "owner-partial";
        for i in 0..(MAX_API_TOKENS_PER_OWNER - 1) {
            create_owned_token(&mgr, partial_owner, &format!("partial-{i}")).await;
        }
        assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS - 1);

        // The requester owns exactly one token and is below the per-owner
        // quota, so only the global same-owner branch can make room.
        create_owned_token(&mgr, "solo", "solo-old").await;
        assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS);

        create_owned_token(&mgr, "solo", "solo-new").await;

        assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS);
        assert_eq!(
            owned_token_names(&mgr, "solo"),
            vec!["solo-new".to_string()],
            "the global cap must evict the requester's own oldest token"
        );
        assert_eq!(
            owned_token_names(&mgr, partial_owner).len(),
            MAX_API_TOKENS_PER_OWNER - 1,
            "other owners' tokens must survive the global same-owner eviction"
        );
        assert_eq!(
            owned_token_names(&mgr, "owner-0").len(),
            MAX_API_TOKENS_PER_OWNER,
            "other owners' tokens must survive the global same-owner eviction"
        );
    }

    #[tokio::test]
    async fn test_delete_user_revokes_owned_tokens() {
        let mgr = AuthManager::new();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        let (alice_token, _) = mgr
            .create_token("alice-token", Role::Operator, Some("alice"))
            .await
            .expect("alice token");
        let (admin_token, _) = mgr
            .create_token("admin-token", Role::Admin, Some("admin"))
            .await
            .expect("admin token");
        mgr.create_token("legacy", Role::Viewer, None)
            .await
            .expect("legacy token");

        assert!(mgr.delete_user("alice").await);

        let ids: Vec<String> = mgr
            .list_tokens()
            .into_iter()
            .map(|token| token.id)
            .collect();
        assert!(
            !ids.contains(&alice_token.id),
            "deleting a user must revoke their API tokens"
        );
        assert!(ids.contains(&admin_token.id));
        assert_eq!(ids.len(), 2, "admin-owned and legacy tokens must survive");
    }

    #[tokio::test]
    async fn test_token_owner_persists_and_delete_user_removes_it_from_disk() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito_token_owner_persist_{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();

        {
            let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
            mgr.create_user("alice", "AlicePassword1", Role::Operator)
                .await;
            mgr.create_token("alice-persisted", Role::Operator, Some("alice"))
                .await
                .expect("alice token");
        }

        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        let reloaded = mgr
            .list_tokens()
            .into_iter()
            .find(|token| token.name == "alice-persisted")
            .expect("token must survive reload");
        assert_eq!(reloaded.owner.as_deref(), Some("alice"));

        assert!(mgr.delete_user("alice").await);
        assert!(
            !mgr.list_tokens()
                .iter()
                .any(|token| token.name == "alice-persisted")
        );
        drop(mgr);

        let tokens_toml = std::fs::read_to_string(temp_dir.join("tokens.toml")).unwrap();
        assert!(
            !tokens_toml.contains("alice-persisted"),
            "deletion must rewrite tokens.toml without the owned token"
        );

        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        assert!(
            !mgr.list_tokens()
                .iter()
                .any(|token| token.name == "alice-persisted"),
            "the deletion must survive a reload"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    fn owned_token_names(mgr: &AuthManager, owner: &str) -> Vec<String> {
        let mut names: Vec<String> = mgr
            .list_tokens()
            .into_iter()
            .filter(|token| token.owner.as_deref() == Some(owner))
            .map(|token| token.name)
            .collect();
        names.sort();
        names
    }

    async fn create_owned_token(mgr: &AuthManager, owner: &str, name: &str) {
        mgr.create_token(name, Role::Viewer, Some(owner))
            .await
            .expect("owned token");
    }

    #[tokio::test]
    async fn test_password_change_revokes_owned_tokens() {
        let dir = auth_temp_dir("pw_revokes_tokens");
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            mgr.create_user("alice", "AlicePassword1", Role::Operator)
                .await;
            create_owned_token(&mgr, "alice", "alice-token").await;
            create_owned_token(&mgr, "admin", "admin-token").await;
            mgr.create_token("legacy", Role::Viewer, None)
                .await
                .expect("legacy token");

            assert!(mgr.update_user_password("alice", "AlicePassword2").await);
            assert!(
                owned_token_names(&mgr, "alice").is_empty(),
                "a password change must revoke the account's API tokens"
            );
            assert_eq!(
                owned_token_names(&mgr, "admin"),
                vec!["admin-token".to_string()]
            );
            assert!(
                mgr.list_tokens().iter().any(|token| token.name == "legacy"),
                "legacy ownerless tokens stay Admin-managed"
            );
        }

        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(
            owned_token_names(&mgr, "alice").is_empty(),
            "password-change token revocation must survive a reload"
        );
        assert!(
            mgr.list_tokens()
                .iter()
                .any(|token| token.name == "admin-token")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_disable_totp_revokes_owned_tokens() {
        let dir = auth_temp_dir("totp_revokes_tokens");
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            mgr.create_user("alice", "AlicePassword1", Role::Operator)
                .await;
            enable_totp(&mgr, "alice").await;
            create_owned_token(&mgr, "alice", "alice-token").await;
            create_owned_token(&mgr, "admin", "admin-token").await;

            assert!(mgr.disable_totp("alice").await);
            assert!(
                owned_token_names(&mgr, "alice").is_empty(),
                "disabling TOTP must revoke the account's API tokens"
            );
            assert_eq!(
                owned_token_names(&mgr, "admin"),
                vec!["admin-token".to_string()]
            );
        }

        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(
            owned_token_names(&mgr, "alice").is_empty(),
            "TOTP-disable token revocation must survive a reload"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_role_change_revokes_owned_tokens() {
        let dir = auth_temp_dir("role_revokes_tokens");
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            mgr.create_user("alice", "AlicePassword1", Role::Operator)
                .await;
            create_owned_token(&mgr, "alice", "before-demotion").await;
            create_owned_token(&mgr, "admin", "admin-token").await;
            mgr.create_token("legacy", Role::Viewer, None)
                .await
                .expect("legacy token");

            // Exercise the handler-facing checked path.
            assert_eq!(
                mgr.set_user_role_checked("alice", Role::Viewer).await,
                Ok(true)
            );
            assert!(
                owned_token_names(&mgr, "alice").is_empty(),
                "demotion must revoke existing tokens so the old scope cannot survive"
            );
            assert_eq!(
                owned_token_names(&mgr, "admin"),
                vec!["admin-token".to_string()]
            );
            assert!(mgr.list_tokens().iter().any(|token| token.name == "legacy"));
        }

        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(
            owned_token_names(&mgr, "alice").is_empty(),
            "demotion token revocation must survive a reload"
        );
        assert_eq!(
            owned_token_names(&mgr, "admin"),
            vec!["admin-token".to_string()]
        );
        assert!(mgr.list_tokens().iter().any(|token| token.name == "legacy"));

        // Promotion also revokes, and must persist.
        create_owned_token(&mgr, "alice", "before-promotion").await;
        assert_eq!(
            mgr.set_user_role_checked("alice", Role::Admin).await,
            Ok(true)
        );
        assert!(
            owned_token_names(&mgr, "alice").is_empty(),
            "promotion also revokes existing tokens"
        );
        drop(mgr);

        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(
            owned_token_names(&mgr, "alice").is_empty(),
            "promotion token revocation must survive a reload"
        );
        assert_eq!(
            owned_token_names(&mgr, "admin"),
            vec!["admin-token".to_string()]
        );
        assert!(mgr.list_tokens().iter().any(|token| token.name == "legacy"));

        // A no-op role update must not revoke anything, before or after reload.
        create_owned_token(&mgr, "alice", "unchanged-role").await;
        assert_eq!(
            mgr.set_user_role_checked("alice", Role::Admin).await,
            Ok(false)
        );
        assert!(
            mgr.list_tokens()
                .iter()
                .any(|token| token.name == "unchanged-role"),
            "setting the same role must not revoke tokens"
        );
        drop(mgr);

        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(
            mgr.list_tokens()
                .iter()
                .any(|token| token.name == "unchanged-role"),
            "a no-op role update must not revoke tokens across reload"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_overwriting_user_revokes_owned_tokens() {
        let dir = auth_temp_dir("overwrite_revokes_tokens");
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            mgr.create_user("alice", "AlicePassword1", Role::Operator)
                .await;
            create_owned_token(&mgr, "alice", "alice-old").await;
            create_owned_token(&mgr, "admin", "admin-token").await;
            mgr.create_token("legacy", Role::Viewer, None)
                .await
                .expect("legacy token");

            mgr.create_user("alice", "AlicePassword2", Role::Viewer)
                .await;
            assert!(
                owned_token_names(&mgr, "alice").is_empty(),
                "overwriting a user account must revoke its API tokens"
            );
            assert_eq!(
                owned_token_names(&mgr, "admin"),
                vec!["admin-token".to_string()]
            );
            assert!(mgr.list_tokens().iter().any(|token| token.name == "legacy"));
        }

        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(
            owned_token_names(&mgr, "alice").is_empty(),
            "overwrite token revocation must survive a reload"
        );
        assert_eq!(
            owned_token_names(&mgr, "admin"),
            vec!["admin-token".to_string()]
        );
        assert!(mgr.list_tokens().iter().any(|token| token.name == "legacy"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_per_owner_token_quota_evicts_only_that_owner() {
        let mgr = AuthManager::new();
        let (bob_token, _) = mgr
            .create_token("bob-keep", Role::Viewer, Some("bob"))
            .await
            .expect("bob token");

        for i in 0..MAX_API_TOKENS_PER_OWNER {
            create_owned_token(&mgr, "alice", &format!("alice-{i}")).await;
            // Keep created_at strictly increasing so "oldest" is unambiguous.
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let alice_before = owned_token_names(&mgr, "alice");
        assert_eq!(alice_before.len(), MAX_API_TOKENS_PER_OWNER);

        create_owned_token(&mgr, "alice", "alice-new").await;

        let alice_after = owned_token_names(&mgr, "alice");
        assert_eq!(
            alice_after.len(),
            MAX_API_TOKENS_PER_OWNER,
            "one owner must never exceed the per-owner quota"
        );
        assert!(
            !alice_after.iter().any(|name| name == "alice-0"),
            "the owner's oldest token must be evicted: {alice_after:?}"
        );
        assert!(alice_after.iter().any(|name| name == "alice-new"));
        assert!(
            mgr.list_tokens()
                .iter()
                .any(|token| token.id == bob_token.id),
            "another owner's token must never be evicted"
        );
    }

    #[tokio::test]
    async fn test_per_owner_token_quota_trims_persisted_overflow() {
        let mgr = AuthManager::new();
        // Simulate a tokens.toml written before the per-owner quota existed.
        {
            let mut tokens = lock(&mgr.tokens);
            for i in 0..20 {
                let (mut meta, _) = generate_token(&format!("legacy-{i}"), Role::Viewer);
                meta.owner = Some("alice".to_string());
                meta.created_at = i;
                tokens.insert(meta.hash.clone(), meta);
            }
        }

        create_owned_token(&mgr, "alice", "new").await;

        let names = owned_token_names(&mgr, "alice");
        assert_eq!(
            names.len(),
            MAX_API_TOKENS_PER_OWNER,
            "legacy overflow must be trimmed to the per-owner quota"
        );
        assert!(names.iter().any(|name| name == "new"));
        assert!(
            !names.iter().any(|name| name == "legacy-0"),
            "the oldest overflow token must be trimmed first"
        );
    }

    #[test]
    fn test_setup_token_lifecycle_and_rate_limit() {
        let mgr = AuthManager::with_storage(
            std::env::temp_dir().join(format!("sito_setup_tok_{}", rand::random::<u64>())),
            24,
            5,
        )
        .unwrap();
        assert!(mgr.setup_token_required());

        // Unknown tokens are rejected and throttled.
        assert_eq!(
            mgr.validate_setup_token(Some("wrong"), "198.51.100.7"),
            SetupTokenStatus::Invalid
        );
        for _ in 0..MAX_SETUP_TOKEN_FAILURES {
            let _ = mgr.validate_setup_token(Some("wrong"), "198.51.100.7");
        }
        assert_eq!(
            mgr.validate_setup_token(Some("wrong"), "198.51.100.7"),
            SetupTokenStatus::RateLimited
        );

        // The actual token is valid (need to read it from state in tests).
        let token = lock(&mgr.setup_token)
            .as_ref()
            .map(|t| t.token.clone())
            .expect("token provisioned");
        assert_eq!(
            mgr.validate_setup_token(Some(&token), "198.51.100.8"),
            SetupTokenStatus::Valid
        );

        // Consuming invalidates it.
        mgr.consume_setup_token();
        assert!(!mgr.setup_token_required());
        assert_eq!(
            mgr.validate_setup_token(Some(&token), "198.51.100.8"),
            SetupTokenStatus::Missing
        );
    }

    #[tokio::test]
    async fn test_setup_token_does_not_expire_before_setup_completes() {
        let mgr = AuthManager::with_storage(
            std::env::temp_dir().join(format!("sito_setup_tok_age_{}", rand::random::<u64>())),
            24,
            5,
        )
        .unwrap();
        let token = mgr.setup_token().expect("token provisioned");

        // Regression: a server left in setup mode longer than the old 24 h
        // expiry must still require the token; an expired token previously
        // enabled unauthenticated `/ui/wizard/complete`.
        mgr.age_setup_token_for_test(Duration::from_hours(72));
        mgr.prune().await;

        assert!(
            mgr.setup_token_required(),
            "setup token must survive while setup is pending"
        );
        assert_eq!(
            mgr.validate_setup_token(Some(&token), "198.51.100.9"),
            SetupTokenStatus::Valid
        );

        // Once setup is complete the residual token is cleared.
        mgr.mark_setup_complete();
        mgr.prune().await;
        assert!(!mgr.setup_token_required());
    }

    #[tokio::test]
    async fn test_user_persistence_across_restart() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_auth_test_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);

        {
            let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
            assert!(mgr.is_first_run());

            // Change admin password
            assert!(mgr.update_user_password("admin", "newsecret123").await);
            assert!(!mgr.is_first_run());

            // Create operator user
            mgr.create_user("operator1", "oppassword", Role::Operator)
                .await;

            // Setup TOTP for operator1
            let setup = mgr.init_totp_setup("operator1").await.expect("totp setup");
            assert!(
                mgr.confirm_totp_setup("operator1", &setup.backup_codes[0])
                    .await
            );
        }

        // Simulate server restart by creating a new AuthManager pointing to same directory
        {
            let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
            assert!(!mgr.is_first_run());

            // Old default credentials must FAIL
            match mgr.login("admin", "adminadmin", "127.0.0.1").await {
                LoginResult::InvalidCredentials { .. } => {}
                other => panic!("expected invalid credentials, got {other:?}"),
            }

            // New password must SUCCEED
            match mgr.login("admin", "newsecret123", "127.0.0.1").await {
                LoginResult::Success(session) => {
                    assert_eq!(session.username, "admin");
                    assert_eq!(session.role, Role::Admin);
                }
                other => panic!("expected success, got {other:?}"),
            }

            // Operator must exist and require TOTP
            match mgr.login("operator1", "oppassword", "127.0.0.1").await {
                LoginResult::TotpRequired { .. } => {}
                other => panic!("expected TotpRequired, got {other:?}"),
            }

            // Verify file permissions (0600 on Unix)
            let users_file = temp_dir.join("users.toml");
            assert!(users_file.exists());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::metadata(&users_file).unwrap().permissions();
                assert_eq!(perms.mode() & 0o777, 0o600);
            }
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_corrupt_users_file_is_not_backed_up_and_refuses_to_start() {
        let temp_dir = auth_temp_dir("corrupt");
        let users_file = temp_dir.join("users.toml");
        let plaintext = "JBSWY3DPEHPK3PXP";
        let corrupt_content = format!(
            "[[users]]\nusername = 'admin'\npassword_hash = invalid_syntax\n\
             [users.totp]\nenabled = true\nsecret = '{plaintext}'\n\
             backup_code_hashes = []\nbroken = [\n"
        );
        std::fs::write(&users_file, &corrupt_content).unwrap();

        match AuthManager::with_storage(&temp_dir, 24, 5) {
            Err(AuthStorageError::CorruptUsersFile { path, source: _ }) => {
                assert_eq!(path, users_file);
            }
            Ok(_) => panic!("Expected Err(CorruptUsersFile), got Ok"),
            Err(other) => panic!("Expected CorruptUsersFile, got {other:?}"),
        }

        // A corrupt file may still contain legacy plaintext TOTP secrets, so
        // it must never be retained as a raw backup.
        let backups: Vec<_> = std::fs::read_dir(&temp_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt."))
            .collect();
        assert!(
            backups.is_empty(),
            "corrupt users files must not be backed up raw"
        );
        for entry in std::fs::read_dir(&temp_dir).unwrap().filter_map(Result::ok) {
            if entry.path() == users_file {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                assert!(
                    !text.contains(plaintext),
                    "recovery file {} leaked the legacy TOTP secret",
                    entry.path().display()
                );
            }
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_reset_admin_backup_seals_legacy_plaintext() {
        let dir = auth_temp_dir("reset_backup_plaintext");
        let plaintext;
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            enable_totp(&mgr, "admin").await;
            plaintext = in_memory_totp_secret(&mgr, "admin");
        }

        // Restore a pre-1.9 plaintext secret without starting the manager, so
        // the reset itself is the first code path to see this file.
        let users_file = dir.join("users.toml");
        let raw = std::fs::read_to_string(&users_file).unwrap();
        let parsed: UsersFile = toml::from_str(&raw).unwrap();
        let sealed = parsed
            .users
            .iter()
            .find(|u| u.username == "admin")
            .and_then(|u| u.totp.as_ref())
            .expect("stored TOTP config")
            .secret
            .clone();
        let legacy = raw.replace(&sealed, &plaintext);
        assert!(legacy.contains(&plaintext));
        std::fs::write(&users_file, &legacy).unwrap();

        AuthManager::reset_admin_credentials(&dir, "resetpassword1").unwrap();

        let backups: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                let name = p.file_name().unwrap_or_default().to_string_lossy();
                name.starts_with("users.toml.reset.") && name.ends_with(".bak")
            })
            .collect();
        assert_eq!(backups.len(), 1, "reset must retain one sanitized backup");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&backups[0]).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "recovery backup must be owner-only");
        }
        let backup_raw = std::fs::read_to_string(&backups[0]).unwrap();
        assert!(
            !backup_raw.contains(&plaintext),
            "reset backup leaked the legacy plaintext TOTP secret"
        );
        let backup: UsersFile = toml::from_str(&backup_raw).unwrap();
        let backup_secret = backup
            .users
            .iter()
            .find(|u| u.username == "admin")
            .and_then(|u| u.totp.as_ref())
            .expect("backup keeps the TOTP config")
            .secret
            .clone();
        assert!(backup_secret.starts_with("enc:v1:"));

        // The live store is the freshly reset account and contains no TOTP.
        let current = std::fs::read_to_string(&users_file).unwrap();
        assert!(!current.contains(&plaintext));
        assert!(!current.contains("enc:v1:"));

        // No temporary files left by either atomic write.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("users.tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary files left behind");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reset_admin_skips_backup_for_unparseable_users_file() {
        let dir = auth_temp_dir("reset_backup_corrupt");
        let plaintext = "JBSWY3DPEHPK3PXP";
        let corrupt_content = format!(
            "[[users]]\nusername = 'admin'\npassword_hash = invalid_syntax\n\
             [users.totp]\nenabled = true\nsecret = '{plaintext}'\n\
             backup_code_hashes = []\nbroken = [\n"
        );
        std::fs::write(dir.join("users.toml"), corrupt_content).unwrap();

        // Replacing an unparseable store requires the explicit full reset.
        AuthManager::reset_admin_credentials_full(&dir, "resetpassword1").unwrap();

        let backups: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                let name = p.file_name().unwrap_or_default().to_string_lossy();
                name.starts_with("users.toml.reset.") && name.ends_with(".bak")
            })
            .collect();
        assert!(
            backups.is_empty(),
            "unparseable users file must not be retained as a backup"
        );
        let current = std::fs::read_to_string(dir.join("users.toml")).unwrap();
        assert!(!current.contains(plaintext));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_empty_users_file_refuses_to_start() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_auth_empty_test_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let users_file = temp_dir.join("users.toml");
        std::fs::write(&users_file, "users = []\n").unwrap();

        let res = AuthManager::with_storage(&temp_dir, 24, 5);
        match res {
            Err(AuthStorageError::EmptyUsersFile { path }) => {
                assert_eq!(path, users_file);
            }
            Ok(_) => panic!("Expected Err(EmptyUsersFile), got Ok"),
            Err(other) => panic!("Expected EmptyUsersFile, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Minor: `reset-admin` is the recovery path and must still work when the
    /// existing `totp.key` is malformed.
    #[tokio::test]
    async fn test_reset_admin_credentials_recovers_from_corrupt_totp_key() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito_auth_reset_corrupt_key_{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        {
            let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
            mgr.update_user_password("admin", "firstpassword").await;
        }
        let key_path = temp_dir.join("totp.key");
        std::fs::write(&key_path, b"not-a-valid-key").unwrap();

        let reset_path = AuthManager::reset_admin_credentials(&temp_dir, "newpassword_reset")
            .expect("admin reset must recover from a malformed TOTP key");
        assert_eq!(reset_path, temp_dir.join("users.toml"));
        let backups: Vec<_> = std::fs::read_dir(&temp_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("totp.corrupt.")
            })
            .collect();
        assert_eq!(backups.len(), 1, "the unusable key must be moved aside");
        assert!(
            AuthManager::with_storage(&temp_dir, 24, 5).is_ok(),
            "the fresh key and reset credentials must load"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_reset_admin_credentials() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_auth_reset_test_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);

        // First bootstrap
        {
            let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
            mgr.update_user_password("admin", "firstpassword").await;
        }

        // Corrupt the users file
        let users_file = temp_dir.join("users.toml");
        std::fs::write(&users_file, "corrupt garbage").unwrap();
        assert!(AuthManager::with_storage(&temp_dir, 24, 5).is_err());

        // Perform admin credentials reset (a corrupt store needs a full reset)
        let reset_path =
            AuthManager::reset_admin_credentials_full(&temp_dir, "newpassword_reset").unwrap();
        assert_eq!(reset_path, users_file);

        // Now loading with_storage must succeed
        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        match mgr.login("admin", "newpassword_reset", "127.0.0.1").await {
            LoginResult::Success(session) => {
                assert_eq!(session.username, "admin");
                assert_eq!(session.role, Role::Admin);
            }
            other => panic!("Expected login success after reset, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Regression: a custom-named Admin (or deletion of the literal `admin`
    /// while another Admin exists) must survive restart without re-entering
    /// setup-token mode.
    #[tokio::test]
    async fn test_custom_admin_survives_restart_without_setup_token() {
        let dir = auth_temp_dir("custom_admin_restart");
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            mgr.create_user("owner", "OwnerPassword123!", Role::Admin)
                .await;
            assert!(mgr.delete_user_checked("admin").await.is_ok());
        }

        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(mgr.has_user("owner"));
        assert!(!mgr.has_user("admin"));
        assert!(!mgr.setup_token_required());
        assert!(!mgr.is_default_admin_active());
        assert!(!mgr.is_first_run());
        assert!(matches!(
            mgr.login("owner", "OwnerPassword123!", "127.0.0.1").await,
            LoginResult::Success(_)
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A store with only non-admin accounts has no usable Admin, so it must
    /// stay recoverable through the setup token even though no default admin
    /// exists.
    #[tokio::test]
    async fn test_no_admin_account_still_provisions_setup_token() {
        let dir = auth_temp_dir("no_admin_token");
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            mgr.create_user("viewer", "ViewerPassword123!", Role::Viewer)
                .await;
            assert!(mgr.delete_user("admin").await);
        }

        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(!mgr.has_user("admin"));
        assert!(!mgr.is_first_run());
        assert!(mgr.setup_token_required());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: a valid but wrong 32-byte `totp.key` must not leave the
    /// server unable to start after `reset-admin` preserved TOTP accounts.
    #[tokio::test]
    async fn test_reset_admin_drops_totp_unreadable_by_current_key() {
        let dir = auth_temp_dir("reset_wrong_totp_key");
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            mgr.create_user("alice", "AlicePassword123!", Role::Operator)
                .await;
            let setup = mgr.init_totp_setup("alice").await.expect("totp setup");
            assert!(
                mgr.confirm_totp_setup("alice", &setup.backup_codes[0])
                    .await
            );
            assert!(mgr.totp_enabled("alice"));
        }
        // Replace the key with a structurally valid but different 32-byte key.
        std::fs::write(dir.join("totp.key"), [0x5Au8; 32]).unwrap();

        AuthManager::reset_admin_credentials(&dir, "NewAdminPassword123!").unwrap();

        let mgr = AuthManager::with_storage(&dir, 24, 5)
            .expect("preserved accounts must not make startup fail after reset");
        assert!(mgr.has_user("alice"));
        assert!(!mgr.totp_enabled("alice"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed users-file write during deletion must restore the account and
    /// surface an error instead of reporting a successful deletion.
    #[tokio::test]
    async fn test_delete_user_rolls_back_when_persistence_fails() {
        let dir = auth_temp_dir("delete_persist_failure");
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.create_user("owner", "OwnerPassword123!", Role::Admin)
            .await;
        let users_path = dir.join("users.toml");
        SECRET_WRITE_FAIL_AFTER
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((users_path.clone(), 0));

        let err = mgr
            .delete_user_checked("admin")
            .await
            .expect_err("failed users write must not report success");
        assert!(matches!(err, UserMutationError::Persistence(_)));
        assert!(mgr.has_user("admin"));
        assert!(mgr.has_user("owner"));
        assert!(mgr.is_default_admin_active());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_prune_expired_entries() {
        let mgr = Arc::new(AuthManager::new());
        // 1. Create a session and expire it
        let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await
        else {
            panic!("login failed");
        };
        assert_eq!(mgr.sessions_len(), 1);
        mgr.expire_session_for_test(&session.id);

        // 2. Create pending totp and expire it
        mgr.init_totp_setup("admin").await;
        assert_eq!(mgr.pending_totp_len(), 1);
        mgr.expire_pending_totp_for_test();

        // 3. Prune
        mgr.prune().await;
        assert_eq!(mgr.sessions_len(), 0);
        assert_eq!(mgr.pending_totp_len(), 0);

        // Test pruner task shutdown
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = mgr.spawn_pruner(shutdown_rx);
        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_millis(500), handle)
            .await
            .expect("pruner should shutdown cleanly")
            .unwrap();
    }

    #[tokio::test]
    async fn test_session_persistence_across_restart() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_sess_test_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let session_id = {
            let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
            let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await
            else {
                panic!("login failed");
            };
            session.id
        };

        // Restart: session must still validate and the file must be 0600.
        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        let restored = mgr.validate_session(&session_id).expect("session restored");
        assert!(
            !restored.csrf_token.is_empty(),
            "legacy sessions get a CSRF token on load"
        );

        let sessions_file = temp_dir.join("sessions.toml");
        assert!(sessions_file.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&sessions_file).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        // Logout must persist the revocation across another restart.
        mgr.logout(&session_id).await;
        let mgr2 = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        assert!(mgr2.validate_session(&session_id).is_none());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_token_persistence_and_expiry() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_tok_test_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let plaintext = {
            let mgr = AuthManager::with_config_and_storage_full(
                Some(temp_dir.join("users.toml")),
                24,
                5,
                true,
                true,
                30, // 30-day token TTL
            )
            .unwrap();
            let (meta, resp) = mgr
                .create_token("ci", Role::Operator, None)
                .await
                .expect("token");
            assert!(meta.expires_at.is_some(), "default TTL must be applied");
            resp.token
        };

        // Restart: the token still authenticates and the hash is persisted.
        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        let meta = mgr
            .validate_token(&plaintext)
            .expect("token survives restart");
        assert_eq!(meta.scope, Role::Operator);

        let tokens_file = temp_dir.join("tokens.toml");
        assert!(tokens_file.exists());
        let content = std::fs::read_to_string(&tokens_file).unwrap();
        assert!(
            !content.contains(&plaintext),
            "plaintext token must never be persisted"
        );

        // Revocation persists.
        assert!(mgr.delete_token(&meta.id).await);
        let mgr2 = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        assert!(mgr2.validate_token(&plaintext).is_none());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_expired_token_rejected_on_load() {
        let temp_dir = std::env::temp_dir().join(format!("sito_tokexp_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        let (mut meta, resp) = mgr
            .create_token("expired", Role::Viewer, None)
            .await
            .expect("token");
        meta.expires_at = Some(chrono::Utc::now().timestamp() - 10);
        lock(&mgr.tokens).insert(meta.hash.clone(), meta);
        mgr.save_tokens_async().await;
        drop(mgr);

        let mgr2 = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        assert!(mgr2.validate_token(&resp.token).is_none());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_corrupt_session_store_backed_up_and_empty() {
        let temp_dir = std::env::temp_dir().join(format!("sito_sesscor_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);

        // Bootstrap a valid manager, then corrupt the sessions file.
        {
            let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
            drop(mgr);
        }
        std::fs::write(temp_dir.join("sessions.toml"), "not = [valid toml").unwrap();

        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        assert_eq!(mgr.sessions_len(), 0, "corrupt store starts empty");
        let backups: Vec<_> = std::fs::read_dir(&temp_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt."))
            .collect();
        assert_eq!(backups.len(), 1, "corrupt file must be backed up");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_session_persistence_can_be_disabled() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_nopersist_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let mgr = AuthManager::with_config_and_storage_full(
            Some(temp_dir.join("users.toml")),
            24,
            5,
            true,
            false, // session_persist disabled
            0,
        )
        .unwrap();
        assert!(!temp_dir.join("sessions.toml").exists());
        drop(mgr);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_lock_recovery_after_poisoning() {
        let mgr = AuthManager::new();
        let users = mgr.users.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = users.lock().unwrap();
            panic!("poison the users lock");
        }));
        // The manager must keep working instead of panicking.
        assert!(mgr.has_user("admin"));
        let (meta, resp) = mgr
            .create_token("post-poison", Role::Viewer, None)
            .await
            .expect("token");
        assert!(mgr.validate_token(&resp.token).is_some());
        assert!(mgr.delete_token(&meta.id).await);
    }

    /// WP-4.4: `reset-admin` must invalidate every live session and API token,
    /// not just replace the password.
    #[tokio::test]
    async fn test_reset_admin_credentials_invalidates_sessions_and_tokens() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_auth_reset_revoke_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let (session_id, token_plaintext, token_hash) = {
            let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
            let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await
            else {
                panic!("login failed");
            };
            let (_meta, resp) = mgr
                .create_token("ci", Role::Operator, None)
                .await
                .expect("token");
            assert!(mgr.validate_session(&session.id).is_some());
            assert!(mgr.validate_token(&resp.token).is_some());
            let token_hash = hash_token(&resp.token);
            (session.id, resp.token, token_hash)
        };

        AuthManager::reset_admin_credentials(&temp_dir, "resetpassword1").unwrap();

        // The persisted stores are removed on reset.
        assert!(!temp_dir.join("sessions.toml").exists());
        assert!(!temp_dir.join("tokens.toml").exists());

        // Even if an attacker restores stale stores, the rotated generation
        // rejects them.
        std::fs::write(
            temp_dir.join("sessions.toml"),
            format!(
                "[[sessions]]\nid = \"{session_id}\"\nusername = \"admin\"\nrole = \"admin\"\ncreated_at = 0\nexpires_at = {}\ncsrf_token = \"deadbeef\"\ngeneration = 0\n",
                i64::MAX
            ),
        )
        .unwrap();
        std::fs::write(
            temp_dir.join("tokens.toml"),
            format!(
                "[[tokens]]\nid = \"tok_stale\"\nname = \"ci\"\nhash = \"{token_hash}\"\nscope = \"operator\"\ncreated_at = 0\ngeneration = 0\n"
            ),
        )
        .unwrap();

        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        assert!(
            mgr.validate_session(&session_id).is_none(),
            "a session from the previous generation must be rejected"
        );
        assert!(
            mgr.validate_token(&token_plaintext).is_none(),
            "a token from the previous generation must be rejected"
        );
        // The new credentials work.
        assert!(matches!(
            mgr.login("admin", "resetpassword1", "127.0.0.1").await,
            LoginResult::Success(_)
        ));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// WP-4.4: changing a password revokes that user's sessions (already) and
    /// role changes take effect immediately.
    #[tokio::test]
    async fn test_role_change_and_admin_guards() {
        let mgr = AuthManager::new();
        mgr.create_user("ops", "OperatorPass1", Role::Operator)
            .await;
        assert_eq!(mgr.admin_count(), 1);
        assert_eq!(mgr.role_of("ops"), Some(Role::Operator));

        let LoginResult::Success(session) = mgr.login("ops", "OperatorPass1", "127.0.0.1").await
        else {
            panic!("login failed");
        };
        assert!(mgr.set_user_role("ops", Role::Viewer).await);
        assert_eq!(mgr.role_of("ops"), Some(Role::Viewer));
        assert!(
            mgr.validate_session(&session.id).is_none(),
            "a role change must revoke existing sessions"
        );

        // Unknown user.
        assert!(!mgr.set_user_role("ghost", Role::Admin).await);
        assert_eq!(
            mgr.set_user_role_checked("ghost", Role::Admin).await,
            Err(UserMutationError::NotFound)
        );
        assert_eq!(
            mgr.delete_user_checked("ghost").await,
            Err(UserMutationError::NotFound)
        );
        assert_eq!(mgr.list_users().len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_concurrent_demotions_keep_at_least_one_admin() {
        let mgr = AuthManager::new();
        mgr.create_user("admin2", "Admin2Password1", Role::Admin)
            .await;
        assert_eq!(mgr.admin_count(), 2);

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let demote = |username: &'static str| {
            let mgr = mgr.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                mgr.set_user_role_checked(username, Role::Viewer).await
            })
        };
        let (first, second) = tokio::join!(demote("admin"), demote("admin2"));
        let first = first.expect("demotion task");
        let second = second.expect("demotion task");

        let successes = [&first, &second]
            .iter()
            .filter(|result| matches!(result, Ok(true)))
            .count();
        let blocked = [&first, &second]
            .iter()
            .filter(|result| matches!(result, Err(UserMutationError::LastAdmin)))
            .count();
        assert_eq!(
            successes, 1,
            "exactly one concurrent demotion may succeed: {first:?} / {second:?}"
        );
        assert_eq!(
            blocked, 1,
            "the losing demotion must return LastAdmin: {first:?} / {second:?}"
        );
        assert_eq!(
            mgr.admin_count(),
            1,
            "concurrent demotions must leave at least one Admin"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_concurrent_demote_and_delete_keep_at_least_one_admin() {
        let mgr = AuthManager::new();
        mgr.create_user("admin2", "Admin2Password1", Role::Admin)
            .await;
        assert_eq!(mgr.admin_count(), 2);

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let demote = {
            let mgr = mgr.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                mgr.set_user_role_checked("admin", Role::Viewer).await
            })
        };
        let delete = {
            let mgr = mgr.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                mgr.delete_user_checked("admin2").await
            })
        };
        let (demote, delete) = tokio::join!(demote, delete);
        let demote = demote.expect("demotion task");
        let delete = delete.expect("deletion task");

        match (&demote, &delete) {
            (Ok(true), Ok(())) => panic!("both operations removed an Admin"),
            (Ok(true), Err(UserMutationError::LastAdmin))
            | (Err(UserMutationError::LastAdmin), Ok(())) => {}
            other => panic!("unexpected concurrent results: {other:?}"),
        }
        assert_eq!(
            mgr.admin_count(),
            1,
            "concurrent demote/delete must leave at least one Admin"
        );
    }

    /// Overwriting an existing account must not be able to remove the sole
    /// remaining Admin, even through the internal (non-handler) path.
    #[tokio::test]
    async fn test_create_user_cannot_overwrite_sole_admin_with_non_admin_role() {
        for role in [Role::Viewer, Role::Operator] {
            let mgr = AuthManager::new();
            assert_eq!(mgr.admin_count(), 1);
            assert!(mgr.is_default_admin_active());

            mgr.create_user("admin", "ReplacementPass1", role).await;

            assert_eq!(
                mgr.role_of("admin"),
                Some(Role::Admin),
                "a blocked overwrite must leave the Admin role unchanged ({role:?})"
            );
            assert_eq!(
                mgr.admin_count(),
                1,
                "a blocked overwrite must leave exactly one Admin ({role:?})"
            );
            assert!(
                mgr.is_default_admin_active(),
                "a blocked overwrite must not change the default-admin flag ({role:?})"
            );
            assert!(
                matches!(
                    mgr.login("admin", "adminadmin", "127.0.0.1").await,
                    LoginResult::Success(_)
                ),
                "a blocked overwrite must not change the password ({role:?})"
            );
        }
    }

    /// Concurrent create/delete writes must not let an older snapshot land
    /// after a newer one: the persisted file must match the final in-memory
    /// state (no resurrected deletions, no lost creations).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_token_mutations_persist_final_state() {
        const MUTATIONS: usize = 30;
        let dir = auth_temp_dir("concurrent_token_persist");
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();

        let mut seeded = Vec::with_capacity(MUTATIONS);
        for i in 0..MUTATIONS {
            let (meta, _resp) = mgr
                .create_token(&format!("seed-{i}"), Role::Viewer, None)
                .await
                .expect("seed token");
            seeded.push(meta.id);
        }

        let barrier = Arc::new(tokio::sync::Barrier::new(MUTATIONS * 2));
        // Model a slow disk for the first concurrent write so an older
        // snapshot can complete after newer ones if writes are not serialized.
        SECRET_WRITE_DELAYS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((dir.join("tokens.toml"), Duration::from_millis(300)));
        let mut tasks = Vec::with_capacity(MUTATIONS * 2);
        for id in seeded {
            let mgr = mgr.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                assert!(mgr.delete_token(&id).await, "seeded token must be deleted");
            }));
        }
        for i in 0..MUTATIONS {
            let mgr = mgr.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                mgr.create_token(&format!("new-{i}"), Role::Viewer, None)
                    .await
                    .expect("new token");
            }));
        }
        for task in tasks {
            task.await.expect("token mutation task");
        }

        let mut expected: Vec<(String, String)> = mgr
            .list_tokens()
            .into_iter()
            .map(|token| (token.id, token.name))
            .collect();
        expected.sort();
        assert_eq!(
            expected.len(),
            MUTATIONS,
            "only the newly created tokens should remain"
        );
        assert!(
            expected.iter().all(|(_, name)| name.starts_with("new-")),
            "no deleted seed token may remain in memory: {expected:?}"
        );

        // Read the file directly instead of relying on a reload's filtering.
        let raw = std::fs::read_to_string(dir.join("tokens.toml")).unwrap();
        let persisted_file: TokensFile = toml::from_str(&raw).unwrap();
        let mut persisted: Vec<(String, String)> = persisted_file
            .tokens
            .into_iter()
            .map(|token| (token.id, token.name))
            .collect();
        persisted.sort();
        assert_eq!(
            persisted, expected,
            "tokens.toml must reflect the final in-memory state after concurrent mutations"
        );

        drop(mgr);
        let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
        let mut after_reload: Vec<(String, String)> = reloaded
            .list_tokens()
            .into_iter()
            .map(|token| (token.id, token.name))
            .collect();
        after_reload.sort();
        assert_eq!(
            after_reload, expected,
            "a reload must reproduce the final in-memory token state"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cancelling the future that awaits a persistence write must not release
    /// the persist lock early: the detached blocking write owns the lock until
    /// it finishes, so a newer save cannot be overwritten by the orphan.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_cancelled_token_save_keeps_lock_until_write_finishes() {
        let dir = auth_temp_dir("cancelled_token_save");
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        let (meta, _resp) = mgr
            .create_token("doomed", Role::Viewer, None)
            .await
            .expect("token");
        let tokens_path = dir.join("tokens.toml");

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        SECRET_WRITE_START_SIGNALS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((tokens_path.clone(), started_tx));
        SECRET_WRITE_DELAYS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((tokens_path.clone(), Duration::from_millis(500)));

        let save_mgr = mgr.clone();
        let save = tokio::spawn(async move {
            save_mgr.save_tokens_async().await;
        });

        // Wait until the blocking write has started and is sleeping. The signal
        // is path-scoped and one-shot, so parallel tests cannot consume it.
        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .expect("timed out waiting for the delayed write to start")
            .expect("write-start signal was dropped");

        // Cancel the caller while the orphaned blocking write is still running.
        save.abort();
        let _ = save.await;

        // The newer revocation must persist after (not before) the orphan write.
        assert!(mgr.delete_token(&meta.id).await);
        // Give a broken implementation time to let the orphan land afterwards.
        tokio::time::sleep(Duration::from_millis(700)).await;

        let raw = std::fs::read_to_string(&tokens_path).unwrap();
        let persisted: TokensFile = toml::from_str(&raw).unwrap();
        assert!(
            !persisted.tokens.iter().any(|token| token.id == meta.id),
            "a cancelled stale write must not resurrect a deleted token: {raw}"
        );

        drop(mgr);
        let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(
            !reloaded
                .list_tokens()
                .iter()
                .any(|token| token.id == meta.id),
            "a reload must not resurrect a deleted token"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A sync reader (`validate_token`) that removes an expired token while a
    /// save is in flight must leave the token store dirty: the old snapshot on
    /// disk still contains the removal, and the next prune must rewrite it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_validate_token_expiry_retries_persist() {
        let dir = auth_temp_dir("validate_token_retry");
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        let (meta, resp) = mgr
            .create_token("expiring-retry", Role::Viewer, None)
            .await
            .expect("token");
        // Expire the token in memory only: the next snapshot will include it.
        lock(&mgr.tokens)
            .get_mut(&meta.hash)
            .expect("token in memory")
            .expires_at = Some(chrono::Utc::now().timestamp() - 10);

        let tokens_path = dir.join("tokens.toml");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        SECRET_WRITE_START_SIGNALS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((tokens_path.clone(), started_tx));
        SECRET_WRITE_DELAYS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((tokens_path.clone(), Duration::from_millis(400)));

        let save_mgr = mgr.clone();
        let save = tokio::spawn(async move { save_mgr.save_tokens_async().await });
        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .expect("timed out waiting for the delayed token write to start")
            .expect("write-start signal was dropped");

        // Remove the expired token while the snapshot write is in flight.
        assert!(mgr.validate_token(&resp.token).is_none());
        save.await.expect("token save task");

        // Without the dirty flag the prune below would see no in-memory change
        // and skip rewriting, leaving the removed token on disk.
        mgr.prune().await;

        let raw = std::fs::read_to_string(&tokens_path).unwrap();
        assert!(
            !raw.contains("expiring-retry"),
            "prune must persist a removal made by validate_token: {raw}"
        );

        drop(mgr);
        let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(
            !reloaded
                .list_tokens()
                .iter()
                .any(|token| token.id == meta.id),
            "a reload must not resurrect a token removed by validate_token"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Same contract as [`test_validate_token_expiry_retries_persist`] for
    /// sessions: a sync `validate_session` removal must mark the store dirty so
    /// the pruner rewrites the stale snapshot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_validate_session_expiry_retries_persist() {
        let dir = auth_temp_dir("validate_session_retry");
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await
        else {
            panic!("login failed");
        };
        mgr.expire_session_for_test(&session.id);

        let sessions_path = dir.join("sessions.toml");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        SECRET_WRITE_START_SIGNALS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((sessions_path.clone(), started_tx));
        SECRET_WRITE_DELAYS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((sessions_path.clone(), Duration::from_millis(400)));

        let save_mgr = mgr.clone();
        let save = tokio::spawn(async move { save_mgr.save_sessions_async().await });
        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .expect("timed out waiting for the delayed session write to start")
            .expect("write-start signal was dropped");

        assert!(mgr.validate_session(&session.id).is_none());
        save.await.expect("session save task");

        mgr.prune().await;

        let raw = std::fs::read_to_string(&sessions_path).unwrap();
        assert!(
            !raw.contains(&session.id),
            "prune must persist a removal made by validate_session: {raw}"
        );

        drop(mgr);
        let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(reloaded.validate_session(&session.id).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Enabling TOTP is a credential change exactly like disabling it: tokens
    /// owned by the account must not outlive the new second factor.
    #[tokio::test]
    async fn test_totp_enable_revokes_owned_tokens() {
        let dir = auth_temp_dir("totp_enable_revokes");
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        let (admin_token, admin_resp) = mgr
            .create_token("admin-before-totp", Role::Operator, Some("admin"))
            .await
            .expect("admin token");
        let (alice_token, _) = mgr
            .create_token("alice-unaffected", Role::Operator, Some("alice"))
            .await
            .expect("alice token");

        enable_totp(&mgr, "admin").await;

        assert!(
            mgr.validate_token(&admin_resp.token).is_none(),
            "enabling TOTP must revoke owned tokens in memory"
        );
        assert!(
            !mgr.list_tokens()
                .iter()
                .any(|token| token.id == admin_token.id)
        );
        assert!(
            mgr.list_tokens()
                .iter()
                .any(|token| token.id == alice_token.id),
            "another account's tokens must survive"
        );

        let raw = std::fs::read_to_string(dir.join("tokens.toml")).unwrap();
        assert!(
            !raw.contains("admin-before-totp"),
            "the revocation must be persisted: {raw}"
        );
        assert!(raw.contains("alice-unaffected"));

        drop(mgr);
        let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(
            !reloaded
                .list_tokens()
                .iter()
                .any(|token| token.id == admin_token.id),
            "a reload must not resurrect a token revoked by TOTP enable"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `save_users_initial` bypasses `persist_lock` and is only safe from the
    /// constructors. Runtime mutations must go through `save_users_async`.
    #[test]
    fn test_save_users_is_constructor_only() {
        let source = include_str!("manager.rs");
        // Build needles at runtime so this test's own source cannot match them.
        let private_initial_fn = format!(
            "{}{}",
            "fn save_users", "_initial(&self) -> Result<(), AuthStorageError> {"
        );
        assert!(
            source.lines().any(|line| line.trim() == private_initial_fn),
            "the synchronous constructor-only writer must exist as a private fallible fn"
        );
        let public_initial_fn = format!("pub {private_initial_fn}");
        assert!(
            !source
                .lines()
                .any(|line| line.trim_start().starts_with(&public_initial_fn)),
            "save_users_initial must stay private"
        );
        let constructor_calls = format!("{}{}", "mgr.save_users", "_initial()");
        assert_eq!(
            source.matches(&constructor_calls).count(),
            2,
            "only the two constructors may call save_users_initial"
        );
    }

    #[tokio::test]
    async fn test_user_mutations_persist_across_restart() {
        // Each mutation is the last write in its own store so a missing async
        // save cannot be masked by a later unrelated save.
        let role_dir = auth_temp_dir("async_role");
        {
            let mgr = AuthManager::with_storage(&role_dir, 24, 5).unwrap();
            mgr.create_user("alice", "AlicePassword1", Role::Operator)
                .await;
            assert!(mgr.set_user_role("alice", Role::Viewer).await);
        }
        let mgr = AuthManager::with_storage(&role_dir, 24, 5).unwrap();
        assert_eq!(
            mgr.role_of("alice"),
            Some(Role::Viewer),
            "a role change must be persisted"
        );
        drop(mgr);
        let _ = std::fs::remove_dir_all(&role_dir);

        let totp_dir = auth_temp_dir("async_totp");
        {
            let mgr = AuthManager::with_storage(&totp_dir, 24, 5).unwrap();
            mgr.create_user("alice", "AlicePassword1", Role::Operator)
                .await;
            enable_totp(&mgr, "alice").await;
            assert!(mgr.disable_totp("alice").await);
        }
        let mgr = AuthManager::with_storage(&totp_dir, 24, 5).unwrap();
        assert!(
            !mgr.totp_enabled("alice"),
            "disabling TOTP must be persisted"
        );
        drop(mgr);
        let _ = std::fs::remove_dir_all(&totp_dir);

        let delete_dir = auth_temp_dir("async_delete");
        {
            let mgr = AuthManager::with_storage(&delete_dir, 24, 5).unwrap();
            mgr.create_user("bob", "BobPassword01", Role::Operator)
                .await;
            assert!(mgr.delete_user("bob").await);
        }
        let mgr = AuthManager::with_storage(&delete_dir, 24, 5).unwrap();
        assert!(!mgr.has_user("bob"), "deleting a user must be persisted");
        drop(mgr);
        let _ = std::fs::remove_dir_all(&delete_dir);
    }

    /// Blocking persistence (users, sessions, tokens) must run on the blocking
    /// pool, never inline on the async runtime thread.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_auth_writes_run_off_runtime_thread() {
        let dir = auth_temp_dir("off_runtime");
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();

        // Ignore the synchronous bootstrap write performed by the constructor.
        SECRET_WRITE_THREADS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();

        let caller_thread = std::thread::current().id();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        let (meta, _resp) = mgr
            .create_token("ci", Role::Viewer, None)
            .await
            .expect("token");
        let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await
        else {
            panic!("expected direct login");
        };
        mgr.logout(&session.id).await;
        assert!(mgr.delete_token(&meta.id).await);

        let writes: Vec<(PathBuf, std::thread::ThreadId)> = SECRET_WRITE_THREADS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(path, _)| path.starts_with(&dir))
            .cloned()
            .collect();
        for name in ["users.toml", "sessions.toml", "tokens.toml"] {
            let matching: Vec<_> = writes
                .iter()
                .filter(|(path, _)| path.ends_with(name))
                .collect();
            assert!(
                !matching.is_empty(),
                "expected a persisted {name} write from the async path"
            );
            assert!(
                matching.iter().all(|(_, tid)| *tid != caller_thread),
                "{name} persistence must not run on the calling async thread"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_users_file_encrypts_totp_secret() {
        let dir = auth_temp_dir("totp_encrypt");
        let plaintext;
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            let _setup = enable_totp(&mgr, "admin").await;
            plaintext = in_memory_totp_secret(&mgr, "admin");
            assert_ne!(plaintext, "");
        }

        let users_file = dir.join("users.toml");
        let raw = std::fs::read_to_string(&users_file).unwrap();
        assert!(
            raw.contains("enc:v1:"),
            "TOTP secret must be sealed in users.toml: {raw}"
        );
        assert!(
            !raw.contains(&plaintext),
            "users.toml must not contain the recoverable TOTP secret: {raw}"
        );

        let parsed: UsersFile = toml::from_str(&raw).unwrap();
        let stored = parsed
            .users
            .iter()
            .find(|u| u.username == "admin")
            .and_then(|u| u.totp.as_ref())
            .expect("stored TOTP config");
        assert!(stored.secret.starts_with("enc:v1:"));
        assert_ne!(stored.secret, plaintext);

        // The atomic rewrite must not leave temporary files behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("users.tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary files left behind");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_plaintext_totp_secret_migrates_on_load() {
        let dir = auth_temp_dir("totp_migrate");
        let plaintext;
        let backup_code;
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            let setup = enable_totp(&mgr, "admin").await;
            plaintext = in_memory_totp_secret(&mgr, "admin");
            backup_code = setup.backup_codes[1].clone();
        }

        // Rewrite the file as a pre-1.9 plaintext store.
        let users_file = dir.join("users.toml");
        let raw = std::fs::read_to_string(&users_file).unwrap();
        let parsed: UsersFile = toml::from_str(&raw).unwrap();
        let sealed = parsed
            .users
            .iter()
            .find(|u| u.username == "admin")
            .and_then(|u| u.totp.as_ref())
            .expect("stored TOTP config")
            .secret
            .clone();
        assert!(sealed.starts_with("enc:v1:"));
        let legacy = raw.replace(&sealed, &plaintext);
        assert_ne!(legacy, raw);
        assert!(legacy.contains(&plaintext));
        std::fs::write(&users_file, &legacy).unwrap();

        // Startup migrates the legacy value and rewrites the file once.
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        let migrated = std::fs::read_to_string(&users_file).unwrap();
        assert!(
            migrated.contains("enc:v1:"),
            "migration must seal the plaintext secret"
        );
        assert!(
            !migrated.contains(&plaintext),
            "migration must not leave the plaintext secret behind"
        );

        // The migration's atomic rewrite must not leave a temp file behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("users.tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "migration left temporary files behind"
        );

        // The account still logs in with its remaining backup code.
        let LoginResult::TotpRequired { partial_token } =
            mgr.login("admin", "adminadmin", "127.0.0.1").await
        else {
            panic!("expected TOTP required after migration");
        };
        match mgr
            .verify_totp(&partial_token, &backup_code, "127.0.0.1")
            .await
        {
            TotpVerifyResult::Success(session) => assert_eq!(session.username, "admin"),
            other => panic!("expected successful login after migration, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_encrypted_totp_login_survives_restart() {
        let dir = auth_temp_dir("totp_restart");
        let backup_code;
        let plaintext;
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            let setup = enable_totp(&mgr, "admin").await;
            backup_code = setup.backup_codes[1].clone();
            plaintext = in_memory_totp_secret(&mgr, "admin");
        }

        let raw = std::fs::read_to_string(dir.join("users.toml")).unwrap();
        assert!(raw.contains("enc:v1:"));
        assert!(!raw.contains(&plaintext));

        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        let LoginResult::TotpRequired { partial_token } =
            mgr.login("admin", "adminadmin", "127.0.0.1").await
        else {
            panic!("expected TOTP required after restart");
        };
        match mgr
            .verify_totp(&partial_token, &backup_code, "127.0.0.1")
            .await
        {
            TotpVerifyResult::Success(session) => assert_eq!(session.username, "admin"),
            other => panic!("expected successful login after restart, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_missing_totp_key_refuses_start() {
        let dir = auth_temp_dir("totp_missing_key");
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            enable_totp(&mgr, "admin").await;
        }

        let key_path = dir.join("totp.key");
        let users_path = dir.join("users.toml");
        std::fs::remove_file(&key_path).unwrap();

        match AuthManager::with_storage(&dir, 24, 5) {
            Err(AuthStorageError::MissingTotpKey {
                key_path: actual_key,
                users_path: actual_users,
            }) => {
                assert_eq!(actual_key, key_path);
                assert_eq!(actual_users, users_path);
            }
            Ok(_) => panic!("startup must fail closed when the TOTP key is missing"),
            Err(other) => panic!("expected MissingTotpKey, got {other:?}"),
        }
        assert!(users_path.exists(), "the users file must not be rewritten");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_wrong_totp_key_refuses_start() {
        let dir = auth_temp_dir("totp_wrong_key");
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            enable_totp(&mgr, "admin").await;
        }

        std::fs::write(dir.join("totp.key"), [0x5au8; 32]).unwrap();

        match AuthManager::with_storage(&dir, 24, 5) {
            Err(AuthStorageError::TotpSecretDecrypt { username, .. }) => {
                assert_eq!(username, "admin");
            }
            Ok(_) => panic!("startup must fail closed with the wrong TOTP key"),
            Err(other) => panic!("expected TotpSecretDecrypt, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_totp_key_file_is_0600() {
        let dir = auth_temp_dir("totp_key_0600");
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        enable_totp(&mgr, "admin").await;
        drop(mgr);

        let key_path = dir.join("totp.key");
        assert!(key_path.exists());
        assert_eq!(std::fs::metadata(&key_path).unwrap().len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_totp_secret_not_in_list_users_or_debug() {
        let mgr = AuthManager::new();
        enable_totp(&mgr, "admin").await;
        let secret = in_memory_totp_secret(&mgr, "admin");
        assert_ne!(secret, "");

        let json = serde_json::to_string(&mgr.list_users()).unwrap();
        assert!(!json.contains(&secret), "list_users leaked the TOTP secret");
        assert!(!json.contains("secret"));

        let user_debug = {
            let users = lock(&mgr.users);
            format!("{:?}", users.get("admin").unwrap())
        };
        assert!(!user_debug.contains(&secret));
        assert!(user_debug.contains("<redacted>"));

        let totp_debug = {
            let users = lock(&mgr.users);
            format!("{:?}", users.get("admin").unwrap().totp.as_ref().unwrap())
        };
        assert!(!totp_debug.contains(&secret));
        assert!(totp_debug.contains("<redacted>"));
    }

    // ------------------------------------------------------------------
    // Credential epoch / revocation races
    // ------------------------------------------------------------------

    fn install_login_gate(
        mgr: &AuthManager,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let reached = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        *lock(&mgr.login_gate) = Some(LoginGate {
            reached: reached.clone(),
            resume: resume.clone(),
        });
        (reached, resume)
    }

    /// A password change that lands after the password was verified but before
    /// the session insert must invalidate the in-flight login.
    #[tokio::test]
    async fn test_password_change_during_login_cannot_create_session() {
        let mgr = AuthManager::new();
        let (reached, resume) = install_login_gate(&mgr);
        let login_mgr = mgr.clone();
        let login =
            tokio::spawn(async move { login_mgr.login("admin", "adminadmin", "127.0.0.1").await });

        reached.notified().await;
        assert!(mgr.update_user_password("admin", "NewAdminPassword1").await);
        resume.notify_one();

        let result = login.await.expect("login task");
        assert!(
            !matches!(result, LoginResult::Success(_)),
            "an in-flight login must not outlive the password it verified: {result:?}"
        );
        assert_eq!(mgr.sessions_len(), 0);
    }

    /// Demoting an account while its login is in flight must not issue a
    /// session carrying the old (higher) role.
    #[tokio::test]
    async fn test_demotion_during_login_cannot_create_session() {
        let mgr = AuthManager::new();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        let (reached, resume) = install_login_gate(&mgr);
        let login_mgr = mgr.clone();
        let login = tokio::spawn(async move {
            login_mgr
                .login("alice", "AlicePassword1", "127.0.0.1")
                .await
        });

        reached.notified().await;
        assert!(mgr.set_user_role("alice", Role::Viewer).await);
        resume.notify_one();

        let result = login.await.expect("login task");
        assert!(
            !matches!(result, LoginResult::Success(_)),
            "a demoted account must not receive a session with its old role: {result:?}"
        );
        assert_eq!(mgr.sessions_len(), 0);
    }

    /// Deleting an account while its login is in flight must not create a
    /// session for the removed account.
    #[tokio::test]
    async fn test_deletion_during_login_cannot_create_session() {
        let mgr = AuthManager::new();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        let (reached, resume) = install_login_gate(&mgr);
        let login_mgr = mgr.clone();
        let login = tokio::spawn(async move {
            login_mgr
                .login("alice", "AlicePassword1", "127.0.0.1")
                .await
        });

        reached.notified().await;
        assert!(mgr.delete_user("alice").await);
        resume.notify_one();

        let result = login.await.expect("login task");
        assert!(
            !matches!(result, LoginResult::Success(_)),
            "a deleted account must not receive a session: {result:?}"
        );
        assert_eq!(mgr.sessions_len(), 0);
    }

    /// Enabling TOTP while a password-only login is in flight must force the
    /// second factor instead of issuing a session that bypasses it.
    #[tokio::test]
    async fn test_totp_enable_during_login_cannot_bypass_second_factor() {
        let mgr = AuthManager::new();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        let (reached, resume) = install_login_gate(&mgr);
        let login_mgr = mgr.clone();
        let login = tokio::spawn(async move {
            login_mgr
                .login("alice", "AlicePassword1", "127.0.0.1")
                .await
        });

        reached.notified().await;
        enable_totp(&mgr, "alice").await;
        resume.notify_one();

        let result = login.await.expect("login task");
        assert!(
            !matches!(result, LoginResult::Success(_)),
            "TOTP enablement must not be bypassed by an in-flight login: {result:?}"
        );
        assert_eq!(mgr.sessions_len(), 0);
    }

    /// Disabling TOTP while the second factor is being verified must not let
    /// the in-flight verification re-enable the factor or issue a session.
    #[tokio::test]
    async fn test_totp_disable_during_verification_cannot_create_session() {
        let mgr = AuthManager::new();
        let setup = enable_totp(&mgr, "admin").await;
        let LoginResult::TotpRequired { partial_token } =
            mgr.login("admin", "adminadmin", "127.0.0.1").await
        else {
            panic!("expected TOTP challenge");
        };
        let code = setup.backup_codes[1].clone();

        let (reached, resume) = install_login_gate(&mgr);
        let verify_mgr = mgr.clone();
        let verify = tokio::spawn(async move {
            verify_mgr
                .verify_totp(&partial_token, &code, "127.0.0.1")
                .await
        });

        reached.notified().await;
        assert!(mgr.disable_totp("admin").await);
        resume.notify_one();

        let result = verify.await.expect("verify task");
        assert!(
            !matches!(result, TotpVerifyResult::Success(_)),
            "a disabled second factor must not authenticate an in-flight verification: {result:?}"
        );
        assert!(!mgr.totp_enabled("admin"), "disable must win the race");
        assert_eq!(mgr.sessions_len(), 0);
    }

    /// Even when the session/token revocation writes fail, a restart must not
    /// resurrect credentials issued before a password change.
    #[tokio::test]
    async fn test_restart_rejects_credentials_older_than_password_change() {
        let dir = auth_temp_dir("epoch_restart");
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        let LoginResult::Success(session) = mgr.login("alice", "AlicePassword1", "127.0.0.1").await
        else {
            panic!("login failed");
        };
        let (_meta, token) = mgr
            .create_token("stale", Role::Viewer, Some("alice"))
            .await
            .expect("token");
        assert!(dir.join("sessions.toml").exists());
        assert!(dir.join("tokens.toml").exists());

        // The users write succeeds, but the revocation writes fail: this is
        // the crash window where the old session/token files survive.
        {
            let mut rules = SECRET_WRITE_FAIL_AFTER
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            rules.push((dir.join("sessions.toml"), 0));
            rules.push((dir.join("tokens.toml"), 0));
        }
        assert!(mgr.update_user_password("alice", "AlicePassword2").await);
        drop(mgr);

        let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(
            reloaded.validate_session(&session.id).is_none(),
            "a persisted session must not survive a password change"
        );
        assert!(
            reloaded.validate_token(&token.token).is_none(),
            "a persisted API token must not survive a password change"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Sessions and tokens written before the credential epoch existed must be
    /// rejected after upgrade (forced re-login / re-issue).
    #[tokio::test]
    async fn test_epochless_persisted_credentials_are_rejected() {
        let dir = auth_temp_dir("epoch_legacy");
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            drop(mgr);
        }

        let legacy_session = r#"
[[sessions]]
id = "legacy-session"
username = "admin"
role = "admin"
created_at = 0
expires_at = 9999999999
csrf_token = ""
generation = 0
"#;
        std::fs::write(dir.join("sessions.toml"), legacy_session).unwrap();

        let plaintext = "sito_legacy_epochless_token";
        let legacy_token = format!(
            r#"
[[tokens]]
id = "tok_legacy"
name = "legacy"
hash = "{}"
scope = "viewer"
created_at = 1
generation = 0
owner = "admin"
"#,
            hash_token(plaintext)
        );
        std::fs::write(dir.join("tokens.toml"), legacy_token).unwrap();

        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(
            mgr.validate_session("legacy-session").is_none(),
            "an epochless persisted session must force re-login after upgrade"
        );
        assert!(
            mgr.validate_token(plaintext).is_none(),
            "an epochless persisted token must be rejected after upgrade"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ------------------------------------------------------------------
    // Fail-closed user persistence
    // ------------------------------------------------------------------

    /// A failed role write must roll the role back and leave existing sessions
    /// valid instead of reporting success.
    #[tokio::test]
    async fn test_role_change_rolls_back_when_persistence_fails() {
        let dir = auth_temp_dir("role_persist_failure");
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        let LoginResult::Success(session) = mgr.login("alice", "AlicePassword1", "127.0.0.1").await
        else {
            panic!("login failed");
        };
        SECRET_WRITE_FAIL_AFTER
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((dir.join("users.toml"), 0));

        let err = mgr
            .set_user_role_checked("alice", Role::Viewer)
            .await
            .expect_err("a failed users write must not report success");
        assert!(matches!(err, UserMutationError::Persistence(_)));
        assert_eq!(mgr.role_of("alice"), Some(Role::Operator));
        assert!(
            mgr.validate_session(&session.id).is_some(),
            "a rolled-back role change must not revoke the account's session"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed mutation's rollback must not clobber a concurrent mutation
    /// that committed while the first write was in flight.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_failed_rollback_does_not_clobber_concurrent_role_change() {
        let dir = auth_temp_dir("mutation_rollback_role");
        let mgr = Arc::new(AuthManager::with_storage(&dir, 24, 5).unwrap());
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;

        let users_path = dir.join("users.toml");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        SECRET_WRITE_START_SIGNALS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((users_path.clone(), started_tx));
        SECRET_WRITE_DELAYS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((users_path.clone(), Duration::from_millis(500)));
        SECRET_WRITE_FAIL_AFTER
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((users_path, 0));

        // First mutation: role change whose users write fails.
        let first_mgr = mgr.clone();
        let first =
            tokio::spawn(
                async move { first_mgr.set_user_role_checked("alice", Role::Viewer).await },
            );
        started_rx.await.expect("first users write started");

        // Second mutation: promote while the first write is still sleeping.
        // Without a mutation lock it changes memory before the first rollback.
        let second_mgr = mgr.clone();
        let second =
            tokio::spawn(
                async move { second_mgr.set_user_role_checked("alice", Role::Admin).await },
            );

        let first_result = first.await.expect("first task");
        assert!(
            matches!(first_result, Err(UserMutationError::Persistence(_))),
            "the first mutation must fail: {first_result:?}"
        );
        let second_result = second
            .await
            .expect("second task")
            .expect("the second mutation must succeed");
        assert!(second_result, "the promotion must report a change");
        assert_eq!(
            mgr.role_of("alice"),
            Some(Role::Admin),
            "the failed mutation's rollback must not clobber the committed promotion"
        );

        drop(mgr);
        let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert_eq!(
            reloaded.role_of("alice"),
            Some(Role::Admin),
            "the committed promotion must be the persisted state"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed mutation's rollback must not resurrect an account that a
    /// concurrent mutation deleted successfully.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_failed_rollback_does_not_resurrect_deleted_account() {
        let dir = auth_temp_dir("mutation_rollback_delete");
        let mgr = Arc::new(AuthManager::with_storage(&dir, 24, 5).unwrap());
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;

        let users_path = dir.join("users.toml");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        SECRET_WRITE_START_SIGNALS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((users_path.clone(), started_tx));
        SECRET_WRITE_DELAYS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((users_path.clone(), Duration::from_millis(500)));
        SECRET_WRITE_FAIL_AFTER
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((users_path, 0));

        // First mutation: role change whose users write fails.
        let first_mgr = mgr.clone();
        let first =
            tokio::spawn(
                async move { first_mgr.set_user_role_checked("alice", Role::Viewer).await },
            );
        started_rx.await.expect("first users write started");

        // Second mutation: delete the account while the first write sleeps.
        let second_mgr = mgr.clone();
        let second = tokio::spawn(async move { second_mgr.delete_user_checked("alice").await });

        let first_result = first.await.expect("first task");
        assert!(
            matches!(first_result, Err(UserMutationError::Persistence(_))),
            "the first mutation must fail: {first_result:?}"
        );
        second
            .await
            .expect("second task")
            .expect("the deletion must succeed");
        assert!(
            !mgr.has_user("alice"),
            "the failed mutation's rollback must not resurrect the deleted account"
        );

        drop(mgr);
        let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(
            !reloaded.has_user("alice"),
            "the deletion must be the persisted state"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed TOTP enable write must not report success or leave the factor
    /// enabled in memory.
    #[tokio::test]
    async fn test_totp_enable_rolls_back_when_persistence_fails() {
        let dir = auth_temp_dir("totp_enable_persist_failure");
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        let setup = mgr.init_totp_setup("alice").await.expect("setup");
        SECRET_WRITE_FAIL_AFTER
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((dir.join("users.toml"), 0));

        assert!(
            !mgr.confirm_totp_setup("alice", &setup.backup_codes[0])
                .await,
            "a failed write must not report TOTP enabled"
        );
        assert!(!mgr.totp_enabled("alice"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed TOTP disable write must leave the factor enabled and report a
    /// failure.
    #[tokio::test]
    async fn test_totp_disable_rolls_back_when_persistence_fails() {
        let dir = auth_temp_dir("totp_disable_persist_failure");
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        enable_totp(&mgr, "alice").await;
        SECRET_WRITE_FAIL_AFTER
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((dir.join("users.toml"), 0));

        assert!(
            !mgr.disable_totp("alice").await,
            "a failed write must not report TOTP disabled"
        );
        assert!(
            mgr.totp_enabled("alice"),
            "the second factor must remain enabled when its removal did not land"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `reset-admin` must report a users-file write failure instead of
    /// claiming the new credentials are installed.
    #[tokio::test]
    async fn test_reset_admin_reports_users_write_failure() {
        let dir = auth_temp_dir("reset_persist_failure");
        {
            let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
            assert!(mgr.update_user_password("admin", "OldAdminPassword1").await);
        }
        SECRET_WRITE_FAIL_AFTER
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((dir.join("users.toml"), 0));

        let result = AuthManager::reset_admin_credentials(&dir, "NewAdminPassword1");
        assert!(
            result.is_err(),
            "reset-admin must not report success when users.toml was not written"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod send_checks {
    use super::*;

    #[test]
    fn test_auth_futures_are_send() {
        fn assert_send<F: std::future::Future + Send>(_f: F) {}
        let mgr = AuthManager::new();
        assert_send(mgr.update_user_password("admin", "x"));
        assert_send(mgr.verify_second_factor("admin", "x"));
        assert_send(mgr.confirm_totp_setup("admin", "x"));
        assert_send(mgr.create_user("a", "b", Role::Viewer));
        assert_send(mgr.login("a", "b", "c"));
        assert_send(mgr.verify_totp("a", "b", "c"));
        assert_send(mgr.set_user_role("a", Role::Viewer));
        assert_send(mgr.delete_user("a"));
        assert_send(mgr.disable_totp("a"));
        assert_send(mgr.logout("a"));
        assert_send(mgr.create_token("a", Role::Viewer, None));
        assert_send(mgr.delete_token("a"));
        assert_send(mgr.prune());
    }
}
