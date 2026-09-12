//! AuthManager coordinating passwords, TOTP, sessions, API tokens, and RBAC.

use crate::auth::lockout::LockoutTracker;
use crate::auth::password::{hash_password, verify_password};
use crate::auth::session::{DEFAULT_SESSION_TTL_SECS, Session};
use crate::auth::token::{ApiTokenMeta, CreateTokenResponse, Role, generate_token, hash_token};
use crate::auth::totp::{TotpConfig, TotpSetupResponse};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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
}

#[derive(Debug, Clone)]
struct PartialAuth {
    username: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpConfig>,
}

pub const MAX_SESSIONS: usize = 10_000;
pub const MAX_PENDING_TOTP: usize = 10_000;
pub const MAX_PARTIAL_TOKENS: usize = 10_000;
pub const PENDING_TOTP_TTL: Duration = Duration::from_secs(600); // 10 minutes
/// Maximum wrong TOTP codes per partial token before it is invalidated.
pub const MAX_TOTP_ATTEMPTS: u32 = 5;

#[derive(Debug, Clone)]
struct PendingTotp {
    config: TotpConfig,
    created_at: Instant,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthStorageError {
    #[error(
        "Corrupt users file '{path}': {source}. Corrupt file backed up to '{backup_path}'. Refusing to start to prevent unauthorized bootstrap; use `sito reset-admin` to recover."
    )]
    CorruptUsersFile {
        path: PathBuf,
        backup_path: PathBuf,
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

/// Atomically writes a secret file with owner-only permissions.
fn atomic_write_secret(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
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

    if let Err(e) = write_res {
        tracing::error!("Failed to persist {}: {e}", path.display());
        let _ = std::fs::remove_file(&tmp_path);
    }
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
    lockout: LockoutTracker,
    session_ttl_secs: i64,
    login_rate_limit: usize,
    setup_complete: Arc<AtomicBool>,
    users_path: Option<PathBuf>,
    sessions_path: Option<PathBuf>,
    tokens_path: Option<PathBuf>,
    tokens_dirty: Arc<AtomicBool>,
    token_default_ttl_days: u64,
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

        let mgr = Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            tokens: Arc::new(Mutex::new(HashMap::new())),
            pending_totp_setups: Arc::new(Mutex::new(HashMap::new())),
            partial_tokens: Arc::new(Mutex::new(HashMap::new())),
            lockout: LockoutTracker::new(),
            session_ttl_secs,
            login_rate_limit,
            setup_complete: Arc::new(AtomicBool::new(false)),
            users_path,
            sessions_path,
            tokens_path,
            tokens_dirty: Arc::new(AtomicBool::new(false)),
            token_default_ttl_days,
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
                        let timestamp = chrono::Utc::now().timestamp();
                        let backup_name = format!(
                            "{}.corrupt.{}.bak",
                            path.file_name().unwrap_or_default().to_string_lossy(),
                            timestamp
                        );
                        let backup_path = path.with_file_name(backup_name);
                        if let Err(copy_err) = std::fs::copy(path, &backup_path) {
                            tracing::error!(
                                source = %path.display(),
                                dest = %backup_path.display(),
                                error = %copy_err,
                                "Failed to back up corrupt users file"
                            );
                        } else {
                            tracing::warn!(
                                source = %path.display(),
                                backup = %backup_path.display(),
                                "Backed up corrupt users file"
                            );
                        }

                        tracing::error!(
                            path = %path.display(),
                            backup = %backup_path.display(),
                            error = %e,
                            "Corrupt users file detected; refusing to start"
                        );

                        return Err(AuthStorageError::CorruptUsersFile {
                            path: path.clone(),
                            backup_path,
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

                let (has_admin, admin_password_changed) = {
                    let mut map = mgr.users.lock().unwrap();
                    for u in file.users {
                        map.insert(u.username.clone(), u);
                    }
                    if let Some(admin) = map.get("admin") {
                        (true, !verify_password("adminadmin", &admin.password_hash))
                    } else {
                        (false, false)
                    }
                };
                if !has_admin || admin_password_changed {
                    mgr.setup_complete.store(true, Ordering::SeqCst);
                }
                mgr.load_sessions();
                mgr.load_tokens();
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
            mgr.create_user_internal("admin", "adminadmin", Role::Admin);
            mgr.save_users();
        } else {
            // Memory-only fallback for tests
            mgr.create_user_internal("admin", "adminadmin", Role::Admin);
        }

        mgr.load_sessions();
        mgr.load_tokens();
        Ok(mgr)
    }

    /// Resets the administrative account credentials and persists to users.toml.
    /// If an existing users.toml exists, it will be backed up before being overwritten.
    pub fn reset_admin_credentials(
        data_dir: impl AsRef<Path>,
        new_password: &str,
    ) -> std::io::Result<PathBuf> {
        let path = data_dir.as_ref().join("users.toml");
        if path.exists() {
            let timestamp = chrono::Utc::now().timestamp();
            let backup_name = format!(
                "{}.reset.{}.bak",
                path.file_name().unwrap_or_default().to_string_lossy(),
                timestamp
            );
            let backup_path = path.with_file_name(backup_name);
            let _ = std::fs::copy(&path, &backup_path);
        }
        let mgr = Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            tokens: Arc::new(Mutex::new(HashMap::new())),
            pending_totp_setups: Arc::new(Mutex::new(HashMap::new())),
            partial_tokens: Arc::new(Mutex::new(HashMap::new())),
            lockout: LockoutTracker::new(),
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            login_rate_limit: 5,
            setup_complete: Arc::new(AtomicBool::new(false)),
            users_path: Some(path.clone()),
            sessions_path: None,
            tokens_path: None,
            tokens_dirty: Arc::new(AtomicBool::new(false)),
            token_default_ttl_days: 0,
        };
        mgr.create_user_internal("admin", new_password, Role::Admin);
        mgr.save_users();
        Ok(path)
    }

    fn save_users(&self) {
        let Some(ref path) = self.users_path else {
            return;
        };
        let users_list: Vec<UserAccount> = {
            let users = self.users.lock().unwrap();
            users.values().cloned().collect()
        };
        let file_content = UsersFile { users: users_list };
        let Ok(toml_str) = toml::to_string_pretty(&file_content) else {
            tracing::error!("Failed to serialize users to TOML");
            return;
        };
        atomic_write_secret(path, &toml_str);
    }

    fn save_sessions(&self) {
        let Some(ref path) = self.sessions_path else {
            return;
        };
        let sessions: Vec<Session> = self.sessions.lock().unwrap().values().cloned().collect();
        let Ok(toml_str) = toml::to_string_pretty(&SessionsFile { sessions }) else {
            tracing::error!("Failed to serialize sessions to TOML");
            return;
        };
        atomic_write_secret(path, &toml_str);
    }

    fn save_tokens(&self) {
        let Some(ref path) = self.tokens_path else {
            return;
        };
        let tokens: Vec<ApiTokenMeta> = self.tokens.lock().unwrap().values().cloned().collect();
        let Ok(toml_str) = toml::to_string_pretty(&TokensFile { tokens }) else {
            tracing::error!("Failed to serialize API tokens to TOML");
            return;
        };
        atomic_write_secret(path, &toml_str);
        self.tokens_dirty.store(false, Ordering::SeqCst);
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
                let mut sessions = self.sessions.lock().unwrap();
                for session in file.sessions {
                    if !session.is_expired() {
                        sessions.insert(session.id.clone(), session);
                    }
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
                let mut tokens = self.tokens.lock().unwrap();
                for token in file.tokens {
                    if token.expires_at.is_none_or(|exp| now < exp) {
                        tokens.insert(token.hash.clone(), token);
                    }
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
        let user = UserAccount {
            username: username.to_string(),
            password_hash: hash,
            role,
            totp: None,
        };
        self.users
            .lock()
            .unwrap()
            .insert(username.to_string(), user);
    }

    /// Returns true if the server is in first-run state (setup has not been completed and default credentials are active).
    pub fn is_first_run(&self) -> bool {
        if self.setup_complete.load(Ordering::SeqCst) {
            return false;
        }
        let users = self.users.lock().unwrap();
        if let Some(admin) = users.get("admin") {
            verify_password("adminadmin", &admin.password_hash)
        } else {
            false
        }
    }

    /// Checks whether a user with the given username exists.
    pub fn has_user(&self, username: &str) -> bool {
        self.users.lock().unwrap().contains_key(username)
    }

    /// Deletes a user account by username. Returns true if the user existed and was removed.
    pub fn delete_user(&self, username: &str) -> bool {
        let removed = self.users.lock().unwrap().remove(username).is_some();
        if removed {
            self.save_users();
        }
        removed
    }

    /// Returns true if the default bootstrapped admin user is still active with default password.
    pub fn is_default_admin_active(&self) -> bool {
        let users = self.users.lock().unwrap();
        if let Some(admin) = users.get("admin") {
            verify_password("adminadmin", &admin.password_hash)
        } else {
            false
        }
    }

    /// Marks initial setup as completed.
    pub fn mark_setup_complete(&self) {
        self.setup_complete.store(true, Ordering::SeqCst);
    }

    /// Creates or updates a user account.
    pub fn create_user(&self, username: &str, password: &str, role: Role) {
        let hash = hash_password(password).expect("valid password hash");
        let user = UserAccount {
            username: username.to_string(),
            password_hash: hash,
            role,
            totp: None,
        };
        self.users
            .lock()
            .unwrap()
            .insert(username.to_string(), user);
        self.save_users();
    }

    /// Updates password for an existing user and invalidates their sessions.
    pub fn update_user_password(&self, username: &str, password: &str) -> bool {
        if let Ok(hash) = hash_password(password) {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.get_mut(username) {
                user.password_hash = hash;
                drop(users);
                self.save_users();
                self.purge_user_sessions(username);
                return true;
            }
        }
        false
    }

    /// Removes all active sessions belonging to a user (used after credential changes).
    pub fn purge_user_sessions(&self, username: &str) {
        let removed = {
            let mut sessions = self.sessions.lock().unwrap();
            let before = sessions.len();
            sessions.retain(|_, session| session.username != username);
            sessions.len() != before
        };
        if removed {
            self.save_sessions();
        }
    }

    fn insert_session(&self, session: Session) {
        let mut sessions = self.sessions.lock().unwrap();
        if !sessions.contains_key(&session.id) && sessions.len() >= MAX_SESSIONS {
            sessions.retain(|_, s| !s.is_expired());
            if sessions.len() >= MAX_SESSIONS
                && let Some(oldest_key) = sessions.keys().next().cloned()
            {
                sessions.remove(&oldest_key);
            }
        }
        sessions.insert(session.id.clone(), session);
        drop(sessions);
        self.save_sessions();
    }

    /// Primary login flow (`POST /auth/login`).
    pub fn login(&self, username: &str, password: &str, client_ip: &str) -> LoginResult {
        // 1. IP rate limiting
        if !self
            .lockout
            .check_ip_rate_limit(client_ip, self.login_rate_limit)
        {
            return LoginResult::RateLimited;
        }

        // 2. Check user lockout
        if let Some(secs) = self.lockout.check_lockout(username) {
            return LoginResult::LockedOut {
                remaining_seconds: secs,
            };
        }

        let users = self.users.lock().unwrap();
        let Some(user) = users.get(username) else {
            let (locked, rem) = self.lockout.record_failure(username);
            return if locked {
                LoginResult::LockedOut {
                    remaining_seconds: 15 * 60,
                }
            } else {
                LoginResult::InvalidCredentials {
                    remaining_attempts: rem,
                }
            };
        };

        // 3. Verify password
        if !verify_password(password, &user.password_hash) {
            let (locked, rem) = self.lockout.record_failure(username);
            return if locked {
                LoginResult::LockedOut {
                    remaining_seconds: 15 * 60,
                }
            } else {
                LoginResult::InvalidCredentials {
                    remaining_attempts: rem,
                }
            };
        }

        // Password valid: check if TOTP is enabled
        if let Some(ref totp) = user.totp
            && totp.enabled
        {
            let mut bytes = [0u8; 32];
            rand::rng().fill(&mut bytes);
            let partial_token = hex::encode(bytes);

            let mut partials = self.partial_tokens.lock().unwrap();
            let now = Instant::now();
            if !partials.contains_key(&partial_token) && partials.len() >= MAX_PARTIAL_TOKENS {
                partials.retain(|_, auth| now < auth.expires_at);
                if partials.len() >= MAX_PARTIAL_TOKENS
                    && let Some(oldest_key) = partials.keys().next().cloned()
                {
                    partials.remove(&oldest_key);
                }
            }
            partials.insert(
                partial_token.clone(),
                PartialAuth {
                    username: username.to_string(),
                    expires_at: now + Duration::from_secs(300), // 5 minutes
                    failed_attempts: 0,
                },
            );

            return LoginResult::TotpRequired { partial_token };
        }

        // Authentication successful
        self.lockout.record_success(username);
        let session = Session::new(username, user.role, self.session_ttl_secs);
        self.insert_session(session.clone());
        LoginResult::Success(session)
    }

    /// Second login phase: verify TOTP code with partial token (`POST /auth/totp/verify`).
    pub fn verify_totp(
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
        let (username, is_expired) = {
            let partials = self.partial_tokens.lock().unwrap();
            let Some(auth) = partials.get(partial_token) else {
                return TotpVerifyResult::TokenExpired;
            };
            (auth.username.clone(), Instant::now() >= auth.expires_at)
        };

        if is_expired {
            self.partial_tokens.lock().unwrap().remove(partial_token);
            return TotpVerifyResult::TokenExpired;
        }

        // 3. Account lockout check
        if let Some(secs) = self.lockout.check_lockout(&username) {
            return TotpVerifyResult::LockedOut {
                remaining_seconds: secs,
            };
        }

        let mut users = self.users.lock().unwrap();
        let Some(user) = users.get_mut(&username) else {
            self.partial_tokens.lock().unwrap().remove(partial_token);
            return TotpVerifyResult::TokenExpired;
        };
        let Some(totp) = user.totp.as_mut() else {
            return TotpVerifyResult::Invalid;
        };

        if totp.verify(code, &username, "sito") {
            // Success: consume partial token, reset lockout, generate session
            self.partial_tokens.lock().unwrap().remove(partial_token);
            self.lockout.record_success(&username);

            let role = user.role;
            drop(users);
            self.save_users();

            let session = Session::new(&username, role, self.session_ttl_secs);
            self.insert_session(session.clone());
            TotpVerifyResult::Success(session)
        } else {
            // Failure: count it against both the partial token and the account lockout.
            let (locked, _rem) = self.lockout.record_failure(&username);
            let remaining_attempts = {
                let mut partials = self.partial_tokens.lock().unwrap();
                if let Some(auth) = partials.get_mut(partial_token) {
                    auth.failed_attempts += 1;
                    MAX_TOTP_ATTEMPTS.saturating_sub(auth.failed_attempts)
                } else {
                    0
                }
            };
            if locked {
                // Account locked: consume the partial token as well.
                self.partial_tokens.lock().unwrap().remove(partial_token);
                return TotpVerifyResult::LockedOut {
                    remaining_seconds: 15 * 60,
                };
            }
            if remaining_attempts == 0 {
                self.partial_tokens.lock().unwrap().remove(partial_token);
            }
            TotpVerifyResult::Invalid
        }
    }

    /// Initiates TOTP setup for a user (`GET /auth/totp/setup`).
    pub fn init_totp_setup(&self, username: &str) -> Option<TotpSetupResponse> {
        let (config, resp) = TotpConfig::generate("sito", username);
        let now = Instant::now();
        let mut pending = self.pending_totp_setups.lock().unwrap();
        if !pending.contains_key(username) && pending.len() >= MAX_PENDING_TOTP {
            pending.retain(|_, p| now.duration_since(p.created_at) <= PENDING_TOTP_TTL);
            if pending.len() >= MAX_PENDING_TOTP
                && let Some(oldest_key) = pending.keys().next().cloned()
            {
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
    pub fn confirm_totp_setup(&self, username: &str, code: &str) -> bool {
        let mut pending = self.pending_totp_setups.lock().unwrap();
        let Some(mut item) = pending.remove(username) else {
            return false;
        };

        if Instant::now().duration_since(item.created_at) > PENDING_TOTP_TTL {
            return false;
        }

        if item.config.verify(code, username, "sito") {
            item.config.enabled = true;
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.get_mut(username) {
                user.totp = Some(item.config);
                drop(users);
                self.save_users();
                // Changing the second factor invalidates existing sessions.
                self.purge_user_sessions(username);
                return true;
            }
        }
        false
    }

    /// Disables TOTP 2FA for a user and invalidates their sessions.
    pub fn disable_totp(&self, username: &str) -> bool {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.get_mut(username) {
            user.totp = None;
            drop(users);
            self.save_users();
            self.purge_user_sessions(username);
            true
        } else {
            false
        }
    }

    /// Validates an active session from a cookie.
    pub fn validate_session(&self, session_id: &str) -> Option<Session> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get(session_id) {
            if session.is_expired() {
                sessions.remove(session_id);
                None
            } else {
                Some(session.clone())
            }
        } else {
            None
        }
    }

    /// Logs out and destroys an active session.
    pub fn logout(&self, session_id: &str) {
        let removed = self.sessions.lock().unwrap().remove(session_id).is_some();
        if removed {
            self.save_sessions();
        }
    }

    /// Creates a new API token with the specified scope.
    pub fn create_token(&self, name: &str, scope: Role) -> (ApiTokenMeta, CreateTokenResponse) {
        let (mut meta, resp) = generate_token(name, scope);
        if self.token_default_ttl_days > 0 {
            let ttl_secs = i64::try_from(self.token_default_ttl_days)
                .unwrap_or(i64::MAX / 86_400)
                .saturating_mul(86_400);
            meta.expires_at = Some(chrono::Utc::now().timestamp().saturating_add(ttl_secs));
        }
        self.tokens
            .lock()
            .unwrap()
            .insert(meta.hash.clone(), meta.clone());
        self.save_tokens();
        (meta, resp)
    }

    /// Lists all active API tokens.
    pub fn list_tokens(&self) -> Vec<ApiTokenMeta> {
        self.tokens.lock().unwrap().values().cloned().collect()
    }

    /// Revokes an API token by ID.
    pub fn delete_token(&self, id: &str) -> bool {
        let mut tokens = self.tokens.lock().unwrap();
        if let Some(key) = tokens
            .iter()
            .find(|(_, m)| m.id == id)
            .map(|(k, _)| k.clone())
        {
            tokens.remove(&key);
            drop(tokens);
            self.save_tokens();
            true
        } else {
            false
        }
    }

    /// Validates a bearer API token string against stored Blake3 hashes using constant-time comparison.
    pub fn validate_token(&self, token: &str) -> Option<ApiTokenMeta> {
        let hash = hash_token(token);
        let hash_bytes = hash.as_bytes();
        let mut tokens = self.tokens.lock().unwrap();
        let now = chrono::Utc::now().timestamp();

        let mut matched_key: Option<String> = None;
        for stored_hash in tokens.keys() {
            let stored_bytes = stored_hash.as_bytes();
            if stored_bytes.len() == hash_bytes.len() && bool::from(stored_bytes.ct_eq(hash_bytes))
            {
                matched_key = Some(stored_hash.clone());
            }
        }

        if let Some(key) = matched_key {
            if tokens
                .get(&key)
                .and_then(|meta| meta.expires_at)
                .is_some_and(|expires_at| now >= expires_at)
            {
                tokens.remove(&key);
                drop(tokens);
                self.save_tokens();
                return None;
            }
            if let Some(meta) = tokens.get_mut(&key) {
                meta.last_used = Some(chrono::Utc::now().timestamp_millis());
                self.tokens_dirty.store(true, Ordering::SeqCst);
                return Some(meta.clone());
            }
        }
        None
    }

    /// Prunes expired sessions, partial tokens, pending TOTP setups, and lockout/rate limits.
    pub fn prune(&self) {
        self.lockout.prune();
        let sessions_changed = {
            let mut sessions = self.sessions.lock().unwrap();
            let before = sessions.len();
            sessions.retain(|_, s| !s.is_expired());
            sessions.len() != before
        };
        if sessions_changed {
            self.save_sessions();
        }
        let tokens_changed = {
            let now = chrono::Utc::now().timestamp();
            let mut tokens = self.tokens.lock().unwrap();
            let before = tokens.len();
            tokens.retain(|_, t| t.expires_at.is_none_or(|exp| now < exp));
            tokens.len() != before
        };
        if tokens_changed || self.tokens_dirty.load(Ordering::SeqCst) {
            self.save_tokens();
        }
        {
            let now = Instant::now();
            let mut pending = self.pending_totp_setups.lock().unwrap();
            pending.retain(|_, p| now.duration_since(p.created_at) <= PENDING_TOTP_TTL);
        }
        {
            let now = Instant::now();
            let mut partials = self.partial_tokens.lock().unwrap();
            partials.retain(|_, p| now < p.expires_at);
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
                        mgr.prune();
                    }
                }
            }
        })
    }

    #[cfg(test)]
    pub fn sessions_len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    #[cfg(test)]
    pub fn partial_tokens_len(&self) -> usize {
        self.partial_tokens.lock().unwrap().len()
    }

    #[cfg(test)]
    pub fn pending_totp_len(&self) -> usize {
        self.pending_totp_setups.lock().unwrap().len()
    }

    #[cfg(test)]
    pub fn expire_session_for_test(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(s) = sessions.get_mut(session_id) {
            s.expires_at = 0;
        }
    }

    #[cfg(test)]
    pub fn expire_partial_tokens_for_test(&self) {
        let mut partials = self.partial_tokens.lock().unwrap();
        for auth in partials.values_mut() {
            auth.expires_at = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
        }
    }

    #[cfg(test)]
    pub fn expire_pending_totp_for_test(&self) {
        let mut pending = self.pending_totp_setups.lock().unwrap();
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

    #[test]
    fn test_auth_manager_login_and_session() {
        let mgr = AuthManager::new();
        // Login with default admin
        match mgr.login("admin", "adminadmin", "127.0.0.1") {
            LoginResult::Success(session) => {
                assert_eq!(session.username, "admin");
                assert_eq!(session.role, Role::Admin);
                assert!(mgr.validate_session(&session.id).is_some());
                mgr.logout(&session.id);
                assert!(mgr.validate_session(&session.id).is_none());
            }
            _ => panic!("Expected successful login"),
        }
    }

    #[test]
    fn test_auth_manager_totp_flow() {
        let mgr = AuthManager::new();
        let setup = mgr.init_totp_setup("admin").expect("setup");

        // Use backup code to confirm setup
        assert!(mgr.confirm_totp_setup("admin", &setup.backup_codes[0]));

        // Login now requires TOTP
        match mgr.login("admin", "adminadmin", "127.0.0.1") {
            LoginResult::TotpRequired { partial_token } => {
                // Invalid code fails
                assert!(matches!(
                    mgr.verify_totp(&partial_token, "000000", "127.0.0.1"),
                    TotpVerifyResult::Invalid
                ));
                // Valid backup code succeeds
                let session =
                    match mgr.verify_totp(&partial_token, &setup.backup_codes[1], "127.0.0.1") {
                        TotpVerifyResult::Success(session) => session,
                        other => panic!("expected TOTP success, got {other:?}"),
                    };
                assert_eq!(session.role, Role::Admin);
            }
            _ => panic!("Expected TOTP required"),
        }
    }

    #[test]
    fn test_totp_bruteforce_attempt_limit() {
        // High IP rate limit so the per-account lockout/attempt cap is exercised.
        let mgr = AuthManager::with_config(24, 1000);
        let setup = mgr.init_totp_setup("admin").expect("setup");
        assert!(mgr.confirm_totp_setup("admin", &setup.backup_codes[0]));

        let LoginResult::TotpRequired { partial_token } =
            mgr.login("admin", "adminadmin", "127.0.0.1")
        else {
            panic!("Expected TOTP required");
        };

        let mut saw_terminal = false;
        for _ in 0..MAX_TOTP_ATTEMPTS {
            match mgr.verify_totp(&partial_token, "000000", "127.0.0.1") {
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
            mgr.verify_totp(&partial_token, &setup.backup_codes[1], "127.0.0.1"),
            TotpVerifyResult::TokenExpired | TotpVerifyResult::LockedOut { .. }
        ));
    }

    #[test]
    fn test_auth_manager_api_tokens() {
        let mgr = AuthManager::new();
        let (meta, resp) = mgr.create_token("grafana", Role::Viewer);

        assert_eq!(mgr.list_tokens().len(), 1);
        let validated = mgr.validate_token(&resp.token).expect("valid token");
        assert_eq!(validated.id, meta.id);
        assert_eq!(validated.scope, Role::Viewer);

        assert!(mgr.delete_token(&meta.id));
        assert!(mgr.validate_token(&resp.token).is_none());
        assert_eq!(mgr.list_tokens().len(), 0);
    }

    #[test]
    fn test_user_persistence_across_restart() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_auth_test_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);

        {
            let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
            assert!(mgr.is_first_run());

            // Change admin password
            assert!(mgr.update_user_password("admin", "newsecret123"));
            assert!(!mgr.is_first_run());

            // Create operator user
            mgr.create_user("operator1", "oppassword", Role::Operator);

            // Setup TOTP for operator1
            let setup = mgr.init_totp_setup("operator1").expect("totp setup");
            assert!(mgr.confirm_totp_setup("operator1", &setup.backup_codes[0]));
        }

        // Simulate server restart by creating a new AuthManager pointing to same directory
        {
            let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
            assert!(!mgr.is_first_run());

            // Old default credentials must FAIL
            match mgr.login("admin", "adminadmin", "127.0.0.1") {
                LoginResult::InvalidCredentials { .. } => {}
                other => panic!("expected invalid credentials, got {other:?}"),
            }

            // New password must SUCCEED
            match mgr.login("admin", "newsecret123", "127.0.0.1") {
                LoginResult::Success(session) => {
                    assert_eq!(session.username, "admin");
                    assert_eq!(session.role, Role::Admin);
                }
                other => panic!("expected success, got {other:?}"),
            }

            // Operator must exist and require TOTP
            match mgr.login("operator1", "oppassword", "127.0.0.1") {
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
    fn test_corrupt_users_file_creates_backup_and_refuses_to_start() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_auth_corrupt_test_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let users_file = temp_dir.join("users.toml");
        let corrupt_content = "[[users]]\nusername = 'admin'\npassword_hash = invalid_syntax\n";
        std::fs::write(&users_file, corrupt_content).unwrap();

        let res = AuthManager::with_storage(&temp_dir, 24, 5);
        match res {
            Err(AuthStorageError::CorruptUsersFile {
                path,
                backup_path,
                source: _,
            }) => {
                assert_eq!(path, users_file);
                assert!(backup_path.exists());
                let backup_content = std::fs::read_to_string(&backup_path).unwrap();
                assert_eq!(backup_content, corrupt_content);
            }
            Ok(_) => panic!("Expected Err(CorruptUsersFile), got Ok"),
            Err(other) => panic!("Expected CorruptUsersFile, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
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

    #[test]
    fn test_reset_admin_credentials() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_auth_reset_test_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);

        // First bootstrap
        {
            let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
            mgr.update_user_password("admin", "firstpassword");
        }

        // Corrupt the users file
        let users_file = temp_dir.join("users.toml");
        std::fs::write(&users_file, "corrupt garbage").unwrap();
        assert!(AuthManager::with_storage(&temp_dir, 24, 5).is_err());

        // Perform admin credentials reset
        let reset_path =
            AuthManager::reset_admin_credentials(&temp_dir, "newpassword_reset").unwrap();
        assert_eq!(reset_path, users_file);

        // Now loading with_storage must succeed
        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        match mgr.login("admin", "newpassword_reset", "127.0.0.1") {
            LoginResult::Success(session) => {
                assert_eq!(session.username, "admin");
                assert_eq!(session.role, Role::Admin);
            }
            other => panic!("Expected login success after reset, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_prune_expired_entries() {
        let mgr = Arc::new(AuthManager::new());
        // 1. Create a session and expire it
        let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1") else {
            panic!("login failed");
        };
        assert_eq!(mgr.sessions_len(), 1);
        mgr.expire_session_for_test(&session.id);

        // 2. Create pending totp and expire it
        mgr.init_totp_setup("admin");
        assert_eq!(mgr.pending_totp_len(), 1);
        mgr.expire_pending_totp_for_test();

        // 3. Prune
        mgr.prune();
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

    #[test]
    fn test_session_persistence_across_restart() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_sess_test_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let session_id = {
            let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
            let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1")
            else {
                panic!("login failed");
            };
            session.id
        };

        // Restart: session must still validate and the file must be 0600.
        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        assert!(mgr.validate_session(&session_id).is_some());

        let sessions_file = temp_dir.join("sessions.toml");
        assert!(sessions_file.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&sessions_file).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        // Logout must persist the revocation across another restart.
        mgr.logout(&session_id);
        let mgr2 = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        assert!(mgr2.validate_session(&session_id).is_none());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_token_persistence_and_expiry() {
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
            let (meta, resp) = mgr.create_token("ci", Role::Operator);
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
        assert!(mgr.delete_token(&meta.id));
        let mgr2 = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        assert!(mgr2.validate_token(&plaintext).is_none());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_expired_token_rejected_on_load() {
        let temp_dir = std::env::temp_dir().join(format!("sito_tokexp_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        let (mut meta, resp) = mgr.create_token("expired", Role::Viewer);
        meta.expires_at = Some(chrono::Utc::now().timestamp() - 10);
        mgr.tokens.lock().unwrap().insert(meta.hash.clone(), meta);
        mgr.save_tokens();
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
            let _ = mgr.login("admin", "adminadmin", "127.0.0.1");
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
        let LoginResult::Success(_session) = mgr.login("admin", "adminadmin", "127.0.0.1") else {
            panic!("login failed");
        };
        assert!(!temp_dir.join("sessions.toml").exists());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
