//! `/api/v1/ha/*` placeholders for builds compiled without the `ha` feature.
//!
//! The routes stay mounted so HA is discoverable and clients get a stable
//! answer instead of a 404, but replication is genuinely unavailable. The
//! handlers keep the same `RequireAdmin` extractor as the real implementation,
//! so unauthenticated and non-admin callers still receive 401/403.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use crate::auth::rbac::RequireAdmin;
use crate::error::ProblemDetails;
use crate::models::{HaResyncResponse, HaSlaveSummary, HaStatusResponse};
use crate::state::ServerContext;

/// Stable machine-readable reason for a build without HA support.
pub const HA_NOT_SUPPORTED: &str = "ha_not_supported";

fn ha_not_supported() -> ProblemDetails {
    let mut problem = ProblemDetails::new(
        StatusCode::NOT_IMPLEMENTED,
        "Not Implemented",
        format!(
            "{HA_NOT_SUPPORTED}: this build of sito was compiled without high-availability \
             support; rebuild with `cargo build -p sito --features ha` to enable replication"
        ),
    );
    problem.error_type = "urn:sito:ha:not-supported".to_string();
    problem
}

/// Get HA cluster status (unsupported without the `ha` feature).
pub async fn get_ha_status(
    _admin: RequireAdmin,
    State(_ctx): State<ServerContext>,
) -> Result<Json<HaStatusResponse>, ProblemDetails> {
    Err(ha_not_supported())
}

/// List connected HA replica secondary nodes (unsupported without `ha`).
pub async fn get_ha_slaves(
    _admin: RequireAdmin,
    State(_ctx): State<ServerContext>,
) -> Result<Json<Vec<HaSlaveSummary>>, ProblemDetails> {
    Err(ha_not_supported())
}

/// Trigger manual HA resynchronization (unsupported without `ha`).
pub async fn trigger_ha_resync(
    _admin: RequireAdmin,
    State(_ctx): State<ServerContext>,
) -> Result<Json<HaResyncResponse>, ProblemDetails> {
    Err(ha_not_supported())
}
