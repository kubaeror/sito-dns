//! Statistics endpoint handlers.

use crate::auth::RequireViewer;
use crate::error::ProblemDetails;
use crate::models::StatsQuery;
use crate::state::ServerContext;
use axum::Json;
use axum::extract::{Query, State};
use sito_stats::{ClientStats, GlobalStats, UpstreamStats};

fn parse_window_ms(window: Option<&str>) -> i64 {
    match window {
        Some("1h") => 3600 * 1000,
        Some("24h") | None => 24 * 3600 * 1000,
        Some("7d") => 7 * 24 * 3600 * 1000,
        Some("30d") => 30 * 24 * 3600 * 1000,
        Some(other) => {
            if let Ok(hours) = other.trim_end_matches('h').parse::<i64>() {
                hours * 3600 * 1000
            } else {
                24 * 3600 * 1000
            }
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/stats",
    params(StatsQuery),
    responses(
        (status = 200, description = "Global statistics retrieved", body = GlobalStats),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Stats"
)]
pub async fn get_stats(
    _viewer: RequireViewer,
    State(ctx): State<ServerContext>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<GlobalStats>, ProblemDetails> {
    let window_ms = parse_window_ms(query.window.as_deref());
    let stats = ctx
        .stats_db
        .get_global_stats(window_ms)
        .await
        .map_err(|e| ProblemDetails::internal_error(e.to_string()))?;
    Ok(Json(stats))
}

#[utoipa::path(
    get,
    path = "/api/v1/stats/clients",
    params(StatsQuery),
    responses(
        (status = 200, description = "Per-client statistics retrieved", body = Vec<ClientStats>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Stats"
)]
pub async fn get_client_stats(
    _viewer: RequireViewer,
    State(ctx): State<ServerContext>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<Vec<ClientStats>>, ProblemDetails> {
    let window_ms = parse_window_ms(query.window.as_deref());
    let stats = ctx
        .stats_db
        .get_client_stats(window_ms)
        .await
        .map_err(|e| ProblemDetails::internal_error(e.to_string()))?;
    Ok(Json(stats))
}

#[utoipa::path(
    get,
    path = "/api/v1/stats/upstreams",
    params(StatsQuery),
    responses(
        (status = 200, description = "Per-upstream statistics retrieved", body = Vec<UpstreamStats>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Stats"
)]
pub async fn get_upstream_stats(
    _viewer: RequireViewer,
    State(ctx): State<ServerContext>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<Vec<UpstreamStats>>, ProblemDetails> {
    let window_ms = parse_window_ms(query.window.as_deref());
    let stats = ctx
        .stats_db
        .get_upstream_stats(window_ms)
        .await
        .map_err(|e| ProblemDetails::internal_error(e.to_string()))?;
    Ok(Json(stats))
}
