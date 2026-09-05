//! Session management and secure cookie handling per section 12.2.
//!
//! Cookies configured with: `HttpOnly; Secure; SameSite=Strict; Path=/`.
//! Rotated upon login.

use crate::auth::token::Role;
use rand::RngCore;
use serde::{Deserialize, Serialize};

pub const DEFAULT_SESSION_TTL_SECS: i64 = 86400; // 24 hours

/// Active user session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub created_at: i64,
    pub expires_at: i64,
}

impl Session {
    pub fn new(username: &str, role: Role, ttl_secs: i64) -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let id = hex::encode(bytes);
        let now = chrono::Utc::now().timestamp();

        Self {
            id,
            username: username.to_string(),
            role,
            created_at: now,
            expires_at: now + ttl_secs,
        }
    }

    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp() >= self.expires_at
    }
}

/// Generates a Set-Cookie header value conforming to `HttpOnly; Secure; SameSite=Strict; Path=/`.
pub fn build_session_cookie(session_id: &str, max_age_secs: i64) -> String {
    format!(
        "sito_session={session_id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age_secs}"
    )
}

/// Generates a Set-Cookie header value to clear the session cookie.
pub fn build_clear_session_cookie() -> String {
    "sito_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0".to_string()
}

/// Extracts the session ID from a Cookie header string.
pub fn extract_session_cookie(cookie_header: &str) -> Option<String> {
    for piece in cookie_header.split(';') {
        let trimmed = piece.trim();
        if let Some(val) = trimmed.strip_prefix("sito_session=") {
            let session_id = val.trim();
            if !session_id.is_empty() {
                return Some(session_id.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle_and_cookies() {
        let session = Session::new("admin", Role::Admin, 3600);
        assert_eq!(session.id.len(), 64);
        assert!(!session.is_expired());

        let cookie = build_session_cookie(&session.id, 3600);
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains(&session.id));

        let extracted = extract_session_cookie(&format!("theme=dark; {}; lang=en", cookie));
        assert_eq!(extracted, Some(session.id));

        let clear = build_clear_session_cookie();
        assert!(clear.contains("Max-Age=0"));
    }
}
