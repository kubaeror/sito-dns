//! API token creation, validation, revocation, and persistence.

#[allow(clippy::wildcard_imports)]
use super::*;

impl AuthManager {
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
    pub(super) fn revoke_tokens_for_owner_in_memory(&self, username: &str) -> bool {
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
}
