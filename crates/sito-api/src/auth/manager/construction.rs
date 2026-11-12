//! Constructors, persistence wiring, and configuration.

#[allow(clippy::wildcard_imports)]
use super::*;

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
}
