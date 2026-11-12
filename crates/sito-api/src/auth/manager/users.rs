//! Setup-token lifecycle, accounts, roles, and credential recovery.

#[allow(clippy::wildcard_imports)]
use super::*;

impl AuthManager {
    pub(super) fn create_user_internal(&self, username: &str, password: &str, role: Role) {
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
    pub(super) fn provision_setup_token_if_needed(&self) {
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

    pub(super) fn setup_token_rate_limited(&self, client_ip: &str) -> bool {
        let mut windows = lock(&self.setup_token_failures);
        let now = Instant::now();
        windows.retain(|_, w| now.duration_since(w.window_start) <= SETUP_TOKEN_RATE_WINDOW);
        windows
            .get(client_ip)
            .is_some_and(|w| w.failures >= MAX_SETUP_TOKEN_FAILURES)
    }

    pub(super) fn record_setup_token_failure(&self, client_ip: &str) {
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
    pub(super) fn admin_count(&self) -> usize {
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

    pub(super) async fn set_user_role_inner(
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

    pub(super) async fn delete_user_inner(
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
}
