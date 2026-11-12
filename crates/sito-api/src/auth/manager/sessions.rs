//! Session validation, logout, and in-memory purge.

#[allow(clippy::wildcard_imports)]
use super::*;

impl AuthManager {
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
}
