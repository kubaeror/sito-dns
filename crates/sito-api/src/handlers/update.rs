//! System update endpoints for checking and applying software updates.

use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::auth::rbac::RequireAdmin;
use crate::error::ProblemDetails;
use crate::updater::{self, UpdateInfo};

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct CheckUpdateQuery {
    pub repo: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ApplyUpdatePayload {
    pub repo: Option<String>,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApplyUpdateResponse {
    pub message: String,
    pub status: String,
}

/// Check for software updates via GitHub Releases.
#[utoipa::path(
    get,
    path = "/api/v1/system/update/check",
    tag = "system",
    params(CheckUpdateQuery),
    responses(
        (status = 200, description = "Update information retrieved successfully", body = UpdateInfo),
        (status = 500, description = "Failed to query release info", body = ProblemDetails)
    )
)]
pub async fn check_update(
    Query(params): Query<CheckUpdateQuery>,
) -> Result<Json<UpdateInfo>, ProblemDetails> {
    match updater::check_for_update(params.repo.as_deref()).await {
        Ok(info) => Ok(Json(info)),
        Err(e) => Err(ProblemDetails::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Update Check Failed",
            e.to_string(),
        )),
    }
}

/// Download and apply software update.
#[utoipa::path(
    post,
    path = "/api/v1/system/update/apply",
    tag = "system",
    request_body(content = Option<ApplyUpdatePayload>, description = "Optional update configuration"),
    responses(
        (status = 200, description = "Update applied successfully", body = ApplyUpdateResponse),
        (status = 400, description = "Invalid request or running in Docker", body = ProblemDetails),
        (status = 500, description = "Update process failed", body = ProblemDetails)
    )
)]
pub async fn apply_update(
    _admin: RequireAdmin,
    payload: Option<Json<ApplyUpdatePayload>>,
) -> Result<Json<ApplyUpdateResponse>, ProblemDetails> {
    let (repo, force) = if let Some(Json(p)) = payload {
        (p.repo, p.force)
    } else {
        (None, false)
    };

    match updater::apply_update(repo.as_deref(), force).await {
        Ok(message) => Ok(Json(ApplyUpdateResponse {
            message,
            status: "success".to_string(),
        })),
        Err(updater::UpdateError::DockerEnvironment(msg)) => Err(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "Docker Environment Cannot Self-Update",
            msg,
        )),
        Err(e) => Err(ProblemDetails::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Update Application Failed",
            e.to_string(),
        )),
    }
}
