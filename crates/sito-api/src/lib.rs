//! `sito-api`
//!
//! Administrative REST API, OpenAPI documentation, and administration server for sito:
//! - Fast async HTTP endpoints built on `axum`
//! - Auto-generated OpenAPI 3.0 schema and Swagger UI via `utoipa`
//! - Authentication, session tokens, Argon2 password hashing, and TOTP 2FA
//! - Role-Based Access Control (RBAC) with Axum extractors
//! - Real-time query log streaming over WebSockets

pub mod auth;
pub mod config_writer;
pub mod error;
pub mod handlers;
pub mod models;
pub mod openapi;
pub mod router;
pub mod state;

#[cfg(feature = "embed-ui")]
pub mod ui;

pub use auth::*;
pub use error::ProblemDetails;
pub use openapi::ApiDoc;
pub use router::create_router;
pub use state::ServerContext;

#[cfg(test)]
mod tests {
    use super::*;
    use utoipa::OpenApi;

    #[test]
    fn test_api_initialization() {
        let auth = AuthManager::new();
        let tokens = auth.list_tokens();
        assert_eq!(tokens.len(), 0);
    }

    #[test]
    fn test_export_openapi_json() {
        let openapi = ApiDoc::openapi();
        let json_str = openapi.to_pretty_json().expect("valid JSON");
        assert!(!json_str.is_empty());
        // Write out docs/openapi.json relative to crate root or workspace
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("docs")
            .join("openapi.json");
        std::fs::write(&path, json_str).expect("write openapi.json");
        assert!(path.exists());
    }
}
