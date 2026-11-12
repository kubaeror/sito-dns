//! Password verification, login, session insertion, and lockout.

#[allow(clippy::wildcard_imports)]
use super::*;

impl AuthManager {
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
    pub(super) fn purge_user_sessions_in_memory(&self, username: &str) -> bool {
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
    pub(super) async fn insert_session(
        &self,
        session: Session,
        expected_epoch: u64,
    ) -> Option<Session> {
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
    pub(super) async fn await_login_test_gate(&self) {
        let gate = lock(&self.login_gate).take();
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.resume.notified().await;
        }
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_async)]
    pub(super) async fn await_login_test_gate(&self) {}

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
}
