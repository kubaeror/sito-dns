//! users.toml, sessions.toml, and tokens.toml persistence.

#[allow(clippy::wildcard_imports)]
use super::*;

impl AuthManager {
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

    pub(super) fn reset_admin_credentials_inner(
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
}

impl AuthManager {
    /// Serializes the current user accounts to TOML, returning the target path.
    ///
    /// TOTP secrets are sealed on cloned accounts, so the in-memory plaintext
    /// (needed to verify codes) never reaches the file. An encryption failure
    /// is returned instead of falling back to plaintext.
    pub(super) fn users_toml(&self) -> Result<Option<(PathBuf, String)>, AuthStorageError> {
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
    pub(super) fn save_users_initial(&self) -> Result<(), AuthStorageError> {
        match self.users_toml()? {
            Some((path, toml_str)) => write_secret_file(&path, &toml_str)
                .map_err(|e| AuthStorageError::Io { path, source: e }),
            None => Ok(()),
        }
    }

    /// Returns the next credential epoch. Always strictly greater than every
    /// epoch already issued by this process and (after load) every epoch on
    /// disk.
    pub(super) fn next_credential_epoch(&self) -> u64 {
        self.credential_epoch_cursor
            .fetch_add(1, Ordering::SeqCst)
            .max(1)
    }

    /// Raises the epoch cursor above the clock and every loaded account so a
    /// recreated account cannot reuse an epoch that a persisted credential
    /// could still match.
    pub(super) fn seed_epoch_cursor(&self) {
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
    pub(super) fn sessions_toml(&self) -> Option<(PathBuf, String)> {
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
    pub(super) fn tokens_toml(&self) -> Option<(PathBuf, String)> {
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
    pub(super) async fn save_sessions_async(&self) {
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
    pub(super) async fn save_tokens_async(&self) {
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

    pub(super) fn load_sessions(&self) {
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

    pub(super) fn load_tokens(&self) {
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
}
