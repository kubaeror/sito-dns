//! `sito-api`
//!
//! Administrative REST API, OpenAPI documentation, and administration server for sito:
//! - Fast async HTTP endpoints built on `axum`
//! - Auto-generated OpenAPI 3.0 schema and Swagger UI via `utoipa`
//! - Authentication, session tokens, Argon2 password hashing, and TOTP 2FA
//! - Role-Based Access Control (RBAC) with Axum extractors
//! - Real-time query log streaming over WebSockets

pub mod auth;
pub mod error;

pub use auth::*;
pub use error::ProblemDetails;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_initialization() {
        let auth = AuthManager::new();
        let tokens = auth.list_tokens();
        assert_eq!(tokens.len(), 0);
    }
}
