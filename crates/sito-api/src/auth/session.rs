//! Session management and secure cookie handling per section 12.2.
//!
//! Cookies configured with: `HttpOnly; Secure; SameSite=Strict; Path=/`.
//! Rotated upon login. When TLS is active the session cookie uses the
//! `__Host-` prefix so a network attacker cannot shadow it from a sibling
//! subdomain; readers accept both the prefixed and the legacy name.

use crate::auth::token::Role;
use rand::RngExt;
use serde::{Deserialize, Serialize};

pub const SESSION_COOKIE_NAME: &str = "sito_session";
/// `__Host-`-prefixed session cookie name (only valid over Secure connections).
pub const SESSION_COOKIE_NAME_SECURE: &str = "__Host-sito_session";
/// Double-submit/browser CSRF cookie name. Not HttpOnly so the UI can read it.
pub const CSRF_COOKIE_NAME: &str = "sito_csrf";
pub const DEFAULT_SESSION_TTL_SECS: i64 = 86400; // 24 hours

/// Active user session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub created_at: i64,
    pub expires_at: i64,
    /// Session-bound CSRF token. Defaulted for sessions persisted before the
    /// token was introduced; such sessions receive a fresh token on load.
    #[serde(default)]
    pub csrf_token: String,
}

fn random_token_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

impl Session {
    pub fn new(username: &str, role: Role, ttl_secs: i64) -> Self {
        let id = random_token_hex();
        let now = chrono::Utc::now().timestamp();

        Self {
            id,
            username: username.to_string(),
            role,
            created_at: now,
            expires_at: now + ttl_secs,
            csrf_token: random_token_hex(),
        }
    }

    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp() >= self.expires_at
    }

    /// Regenerates the CSRF token (e.g. for sessions persisted before the
    /// field existed).
    pub fn ensure_csrf_token(&mut self) {
        if self.csrf_token.is_empty() {
            self.csrf_token = random_token_hex();
        }
    }

    pub fn to_cookie_header(&self) -> String {
        self.to_cookie_header_secure(true)
    }

    pub fn to_cookie_header_secure(&self, secure: bool) -> String {
        let max_age = self.expires_at - chrono::Utc::now().timestamp();
        build_session_cookie(&self.id, max_age.max(0), secure)
    }
}

/// Generates a `Set-Cookie` header value conforming to `HttpOnly; SameSite=Strict; Path=/`,
/// conditionally including `Secure` if `secure` is true. When `secure` is set
/// the `__Host-` name prefix is used.
pub fn build_session_cookie(session_id: &str, max_age_secs: i64, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    let name = session_cookie_name(secure);
    format!(
        "{name}={session_id}; Path=/; HttpOnly{secure_attr}; SameSite=Strict; Max-Age={max_age_secs}"
    )
}

/// Generates a `Set-Cookie` header value to clear the session cookie.
pub fn build_clear_session_cookie(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    let name = session_cookie_name(secure);
    format!("{name}=; Path=/; HttpOnly{secure_attr}; SameSite=Strict; Max-Age=0")
}

/// Generates the CSRF double-submit cookie. It is intentionally *not*
/// HttpOnly so the web UI can echo it back, but it is SameSite=Strict and
/// host-scoped.
pub fn build_csrf_cookie(token: &str, max_age_secs: i64, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{CSRF_COOKIE_NAME}={token}; Path=/{secure_attr}; SameSite=Strict; Max-Age={max_age_secs}"
    )
}

/// Generates a `Set-Cookie` header value clearing the CSRF cookie.
pub fn build_clear_csrf_cookie(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{CSRF_COOKIE_NAME}=; Path=/{secure_attr}; SameSite=Strict; Max-Age=0")
}

fn session_cookie_name(secure: bool) -> &'static str {
    if secure {
        SESSION_COOKIE_NAME_SECURE
    } else {
        SESSION_COOKIE_NAME
    }
}

/// Extracts the session ID from a Cookie header string, accepting both the
/// `__Host-`-prefixed and legacy cookie names.
pub fn extract_session_cookie(cookie_header: &str) -> Option<String> {
    for piece in cookie_header.split(';') {
        let trimmed = piece.trim();
        let value = trimmed
            .strip_prefix("sito_session=")
            .or_else(|| trimmed.strip_prefix("__Host-sito_session="));
        if let Some(val) = value {
            let session_id = val.trim();
            if !session_id.is_empty() {
                return Some(session_id.to_string());
            }
        }
    }
    None
}

/// Extracts the CSRF cookie value from a Cookie header string.
pub fn extract_csrf_cookie(cookie_header: &str) -> Option<String> {
    for piece in cookie_header.split(';') {
        let trimmed = piece.trim();
        if let Some(val) = trimmed.strip_prefix("sito_csrf=") {
            let token = val.trim();
            if !token.is_empty() {
                return Some(token.to_string());
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
        assert_eq!(session.csrf_token.len(), 64);
        assert_ne!(session.id, session.csrf_token);
        assert!(!session.is_expired());

        // Secure cookies use the __Host- prefix.
        let cookie = build_session_cookie(&session.id, 3600, true);
        assert!(cookie.starts_with("__Host-sito_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains(&session.id));

        let plain_cookie = build_session_cookie(&session.id, 3600, false);
        assert!(plain_cookie.starts_with("sito_session="));
        assert!(plain_cookie.contains("HttpOnly"));
        assert!(!plain_cookie.contains("Secure"));
        assert!(!plain_cookie.contains("__Host-"));

        // Reader accepts both names.
        let extracted = extract_session_cookie(&format!("theme=dark; {cookie}; lang=en"));
        assert_eq!(extracted, Some(session.id.clone()));
        let extracted_legacy =
            extract_session_cookie(&format!("theme=dark; {plain_cookie}; lang=en"));
        assert_eq!(extracted_legacy, Some(session.id));

        let clear = build_clear_session_cookie(true);
        assert!(clear.starts_with("__Host-sito_session="));
        assert!(clear.contains("Max-Age=0"));
        assert!(clear.contains("Secure"));

        let clear_plain = build_clear_session_cookie(false);
        assert!(clear_plain.starts_with("sito_session="));
        assert!(clear.contains("Max-Age=0"));
        assert!(!clear_plain.contains("Secure"));

        // CSRF cookie is not HttpOnly and is SameSite=Strict.
        let csrf = build_csrf_cookie(&session.csrf_token, 3600, true);
        assert!(csrf.starts_with("sito_csrf="));
        assert!(!csrf.contains("HttpOnly"));
        assert!(csrf.contains("SameSite=Strict"));
        assert!(csrf.contains("Secure"));
        assert_eq!(
            extract_csrf_cookie(&format!("a=b; {csrf}")),
            Some(session.csrf_token.clone())
        );
    }

    #[test]
    fn test_legacy_session_without_csrf_token_gets_one() {
        let mut session = Session {
            id: "abc".to_string(),
            username: "admin".to_string(),
            role: Role::Admin,
            created_at: 0,
            expires_at: i64::MAX,
            csrf_token: String::new(),
        };
        session.ensure_csrf_token();
        assert_eq!(session.csrf_token.len(), 64);
    }
}
