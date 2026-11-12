//! Periodic expiry pruning and test-only state helpers.

#[allow(clippy::wildcard_imports)]
use super::*;

impl AuthManager {
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
