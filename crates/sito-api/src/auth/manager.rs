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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UsersFile {
    #[serde(default)]
    users: Vec<UserAccount>,
}

/// Central state manager for authentication and authorization.
#[derive(Clone)]
pub struct AuthManager {
    users: Arc<Mutex<HashMap<String, UserAccount>>>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    tokens: Arc<Mutex<HashMap<String, ApiTokenMeta>>>, // Keyed by token hash
    pending_totp_setups: Arc<Mutex<HashMap<String, TotpConfig>>>,
    partial_tokens: Arc<Mutex<HashMap<String, PartialAuth>>>,
    lockout: LockoutTracker,
    session_ttl_secs: i64,
    login_rate_limit: usize,
    setup_complete: Arc<AtomicBool>,
    users_path: Option<PathBuf>,
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthManager {
    pub fn new() -> Self {
        Self::with_config_and_storage(None, 24, 5)
    }

    pub fn with_config(session_ttl_hours: u64, login_rate_limit: usize) -> Self {
        Self::with_config_and_storage(None, session_ttl_hours, login_rate_limit)
    }

    pub fn with_storage(
        data_dir: impl AsRef<Path>,
        session_ttl_hours: u64,
        login_rate_limit: usize,
    ) -> Self {
        Self::with_config_and_storage(
            Some(data_dir.as_ref().join("users.toml")),
            session_ttl_hours,
            login_rate_limit,
        )
    }

    pub fn with_config_and_storage(
        users_path: Option<PathBuf>,
        session_ttl_hours: u64,
        login_rate_limit: usize,
    ) -> Self {
        let secs = session_ttl_hours.saturating_mul(3600);
        let session_ttl_secs = i64::try_from(secs).unwrap_or(DEFAULT_SESSION_TTL_SECS);

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
        };

        if let Some(ref path) = mgr.users_path {
            if path.exists()
                && let Ok(content) = std::fs::read_to_string(path)
                && let Ok(file) = toml::from_str::<UsersFile>(&content)
                && !file.users.is_empty()
            {
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
                return mgr;
            }
            // If file does not exist or empty, initialize bootstrap admin and persist
            mgr.create_user_internal("admin", "adminadmin", Role::Admin);
            mgr.save_users();
        } else {
            // Memory-only fallback for tests
            mgr.create_user_internal("admin", "adminadmin", Role::Admin);
        }

        mgr
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
            file.write_all(toml_str.as_bytes())?;
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
            tracing::error!("Failed to persist users to {}: {e}", path.display());
            let _ = std::fs::remove_file(&tmp_path);
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

    /// Marks initial setup as completed.
    pub fn mark_setup_complete(&self) {
        self.setup_complete.store(true, Ordering::SeqCst);
    }

    /// Creates or updates a user account.
    pub fn create_user(&mut self, username: &str, password: &str, role: Role) {
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

    /// Updates password for an existing user.
    pub fn update_user_password(&self, username: &str, password: &str) -> bool {
        if let Ok(hash) = hash_password(password) {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.get_mut(username) {
                user.password_hash = hash;
                drop(users);
                self.save_users();
                return true;
            }
        }
        false
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
            partials.insert(
                partial_token.clone(),
                PartialAuth {
                    username: username.to_string(),
                    expires_at: Instant::now() + Duration::from_secs(300), // 5 minutes
                },
            );

            return LoginResult::TotpRequired { partial_token };
        }

        // Authentication successful
        self.lockout.record_success(username);
        let session = Session::new(username, user.role, self.session_ttl_secs);
        self.sessions
            .lock()
            .unwrap()
            .insert(session.id.clone(), session.clone());
        LoginResult::Success(session)
    }

    /// Second login phase: verify TOTP code with partial token (`POST /auth/totp/verify`).
    pub fn verify_totp(&self, partial_token: &str, code: &str) -> Option<Session> {
        let (username, is_expired) = {
            let partials = self.partial_tokens.lock().unwrap();
            let auth = partials.get(partial_token)?;
            (auth.username.clone(), Instant::now() >= auth.expires_at)
        };

        if is_expired {
            self.partial_tokens.lock().unwrap().remove(partial_token);
            return None;
        }

        let mut users = self.users.lock().unwrap();
        let user = users.get_mut(&username)?;
        let totp = user.totp.as_mut()?;

        if totp.verify(code, &username, "sito") {
            // Success: consume partial token, reset lockout, generate session
            self.partial_tokens.lock().unwrap().remove(partial_token);
            self.lockout.record_success(&username);

            let role = user.role;
            drop(users);
            self.save_users();

            let session = Session::new(&username, role, self.session_ttl_secs);
            self.sessions
                .lock()
                .unwrap()
                .insert(session.id.clone(), session.clone());
            Some(session)
        } else {
            self.lockout.record_failure(&username);
            None
        }
    }

    /// Initiates TOTP setup for a user (`GET /auth/totp/setup`).
    pub fn init_totp_setup(&self, username: &str) -> Option<TotpSetupResponse> {
        let (config, resp) = TotpConfig::generate("sito", username);
        self.pending_totp_setups
            .lock()
            .unwrap()
            .insert(username.to_string(), config);
        Some(resp)
    }

    /// Confirms and activates TOTP for a user using initial code verification.
    pub fn confirm_totp_setup(&self, username: &str, code: &str) -> bool {
        let mut pending = self.pending_totp_setups.lock().unwrap();
        let Some(mut config) = pending.remove(username) else {
            return false;
        };

        if config.verify(code, username, "sito") {
            config.enabled = true;
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.get_mut(username) {
                user.totp = Some(config);
                drop(users);
                self.save_users();
                return true;
            }
        }
        false
    }

    /// Disables TOTP 2FA for a user.
    pub fn disable_totp(&self, username: &str) -> bool {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.get_mut(username) {
            user.totp = None;
            drop(users);
            self.save_users();
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
        self.sessions.lock().unwrap().remove(session_id);
    }

    /// Creates a new API token with the specified scope.
    pub fn create_token(&self, name: &str, scope: Role) -> (ApiTokenMeta, CreateTokenResponse) {
        let (meta, resp) = generate_token(name, scope);
        self.tokens
            .lock()
            .unwrap()
            .insert(meta.hash.clone(), meta.clone());
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

        let mut matched_key: Option<String> = None;
        for stored_hash in tokens.keys() {
            let stored_bytes = stored_hash.as_bytes();
            if stored_bytes.len() == hash_bytes.len() && bool::from(stored_bytes.ct_eq(hash_bytes))
            {
                matched_key = Some(stored_hash.clone());
            }
        }

        if let Some(key) = matched_key
            && let Some(meta) = tokens.get_mut(&key)
        {
            meta.last_used = Some(chrono::Utc::now().timestamp_millis());
            return Some(meta.clone());
        }
        None
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
                assert!(mgr.verify_totp(&partial_token, "000000").is_none());
                // Valid backup code succeeds
                let session = mgr.verify_totp(&partial_token, &setup.backup_codes[1]);
                assert!(session.is_some());
                assert_eq!(session.unwrap().role, Role::Admin);
            }
            _ => panic!("Expected TOTP required"),
        }
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
            let mut mgr = AuthManager::with_storage(&temp_dir, 24, 5);
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
            let mgr = AuthManager::with_storage(&temp_dir, 24, 5);
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
}
