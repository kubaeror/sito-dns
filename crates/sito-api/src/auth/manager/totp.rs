//! TOTP verification, re-authentication, enrollment, and second factor.

#[allow(clippy::wildcard_imports)]
use super::*;

impl AuthManager {
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
}
