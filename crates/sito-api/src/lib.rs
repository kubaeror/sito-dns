//! `sito-api`
//!
//! Administrative REST API, OpenAPI documentation, and administration server for sito:
//! - Fast async HTTP endpoints built on `axum`
//! - Auto-generated OpenAPI 3.0 schema and Swagger UI via `utoipa`
//! - Authentication, session tokens, Argon2 password hashing, and TOTP 2FA
//! - Role-Based Access Control (RBAC) with Axum extractors
//! - Real-time query log streaming over WebSockets

pub mod auth;
pub mod config_apply;
pub mod config_validation;
pub mod config_writer;
pub mod error;
pub mod handlers;
pub mod models;
pub mod openapi;
pub mod probe;
pub mod readiness;
pub mod router;
pub mod security;
pub mod state;
pub mod updater;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(feature = "embed-ui")]
pub mod ui;

pub use auth::*;
pub use error::ProblemDetails;
pub use openapi::ApiDoc;
pub use readiness::{
    ComponentReadiness, ReadinessInputs, ReadinessReason, ReadinessReport, ReadinessState,
};
pub use router::{create_router, create_router_with_hooks};
pub use state::{
    ServerContext, publish_bundle, refresh_tls_certificate_readiness, tls_certificate_readiness,
};

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

    /// Verifies the generated OpenAPI spec and its committed snapshot.
    ///
    /// A plain `cargo test` must never modify the working tree: the snapshot
    /// is only written when `SITO_UPDATE_OPENAPI=1` is explicitly set (CI
    /// does this before running the tests and then gates on
    /// `git diff --exit-code docs/openapi.json`). Without the variable the
    /// test still guards drift by comparing the generated specification with
    /// the committed file.
    #[test]
    fn test_export_openapi_json() {
        let openapi = ApiDoc::openapi();
        let json_str = openapi.to_pretty_json().expect("valid JSON");
        assert!(
            !json_str.is_empty(),
            "OpenAPI document must not serialize to an empty string"
        );
        // Keep the exposed spec version in lockstep with the crate version.
        assert_eq!(
            openapi.info.version,
            env!("CARGO_PKG_VERSION"),
            "OpenAPI info.version must match the crate version"
        );
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("docs")
            .join("openapi.json");

        if std::env::var("SITO_UPDATE_OPENAPI").as_deref() == Ok("1") {
            // Explicit refresh path, used by CI; drift is then reported by
            // `git diff --exit-code docs/openapi.json`.
            std::fs::write(&path, json_str).expect("write openapi.json");
            assert!(path.exists());
        } else {
            // Default path: verify the committed snapshot without touching it.
            let committed = std::fs::read_to_string(&path).expect(
                "docs/openapi.json is missing; regenerate with \
                 `SITO_UPDATE_OPENAPI=1 cargo test -p sito-api`",
            );
            assert_eq!(
                committed, json_str,
                "docs/openapi.json is stale; regenerate with \
                 `SITO_UPDATE_OPENAPI=1 cargo test -p sito-api`"
            );
        }
    }

    #[test]
    fn test_openapi_documents_total_count_header() {
        let openapi = serde_json::to_value(ApiDoc::openapi()).expect("valid OpenAPI JSON");
        for path in ["/api/v1/stats/clients", "/api/v1/stats/upstreams"] {
            let headers = &openapi["paths"][path]["get"]["responses"]["200"]["headers"];
            assert_eq!(
                headers["X-Total-Count"]["description"],
                "Number of distinct matching rows before the response limit",
                "{path} must document the X-Total-Count response header"
            );
            assert_eq!(
                headers["X-Total-Count"]["schema"]["type"], "string",
                "{path} X-Total-Count header must be a string"
            );
        }
    }
}
