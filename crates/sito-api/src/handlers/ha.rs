//! High Availability endpoints (stubbed with 501 Not Implemented per M5 specification).

use axum::Json;

use crate::auth::rbac::RequireAdmin;
use crate::error::ProblemDetails;
use crate::models::HaStubResponse;

/// Get HA cluster status (Deferred to Phase M8).
#[utoipa::path(
    get,
    path = "/api/v1/ha/status",
    responses(
        (status = 501, description = "HA replication will be delivered in Phase M8", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn get_ha_status(_admin: RequireAdmin) -> Result<Json<HaStubResponse>, ProblemDetails> {
    Err(ProblemDetails::not_implemented(
        "HA replication will be delivered in Phase M8",
    ))
}

/// List connected HA secondary nodes (Deferred to Phase M8).
#[utoipa::path(
    get,
    path = "/api/v1/ha/slaves",
    responses(
        (status = 501, description = "HA replication will be delivered in Phase M8", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn get_ha_slaves(_admin: RequireAdmin) -> Result<Json<HaStubResponse>, ProblemDetails> {
    Err(ProblemDetails::not_implemented(
        "HA replication will be delivered in Phase M8",
    ))
}

/// Trigger manual HA resynchronization (Deferred to Phase M8).
#[utoipa::path(
    post,
    path = "/api/v1/ha/resync",
    responses(
        (status = 501, description = "HA replication will be delivered in Phase M8", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn trigger_ha_resync(
    _admin: RequireAdmin,
) -> Result<Json<HaStubResponse>, ProblemDetails> {
    Err(ProblemDetails::not_implemented(
        "HA replication will be delivered in Phase M8",
    ))
}
