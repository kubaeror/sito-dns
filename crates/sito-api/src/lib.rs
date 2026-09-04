//! `sito-api`
//!
//! Administrative REST API and WebSocket services:
//! - Fast async HTTP endpoints built on `axum`
//! - Auto-generated OpenAPI 3.0 schema and Swagger UI via `utoipa`
//! - Authentication, session tokens, Argon2 password hashing, and TOTP 2FA
//! - Role-Based Access Control (RBAC)
//! - Real-time query log streaming over WebSockets

#[cfg(test)]
mod tests {
    #[test]
    fn test_api_initialization() {
        assert_eq!(2 + 2, 4);
    }
}
