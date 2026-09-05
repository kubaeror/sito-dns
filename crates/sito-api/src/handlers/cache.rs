//! DNS cache management endpoints.

use axum::Json;
use axum::extract::{Query, State};

use crate::auth::rbac::RequireOperator;
use crate::error::ProblemDetails;
use crate::models::{GenericMessageResponse, InvalidateCacheQuery};
use crate::state::ServerContext;

/// Flush entire DNS response cache.
#[utoipa::path(
    post,
    path = "/api/v1/cache/flush",
    responses(
        (status = 200, description = "Cache flushed successfully", body = GenericMessageResponse),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn flush_cache(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
) -> Json<GenericMessageResponse> {
    ctx.cache.flush();
    Json(GenericMessageResponse {
        message: "DNS cache flushed successfully".to_string(),
    })
}

/// Invalidate cache entries matching a domain.
#[utoipa::path(
    post,
    path = "/api/v1/cache/invalidate",
    params(InvalidateCacheQuery),
    responses(
        (status = 200, description = "Cache entries invalidated", body = GenericMessageResponse),
        (status = 400, description = "Bad request", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn invalidate_cache(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Query(query): Query<InvalidateCacheQuery>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    if query.domain.trim().is_empty() {
        return Err(ProblemDetails::bad_request(
            "domain parameter must not be empty",
        ));
    }

    ctx.cache.invalidate_domain(&query.domain);

    Ok(Json(GenericMessageResponse {
        message: format!("Invalidated cache entries matching '{}'", query.domain),
    }))
}
