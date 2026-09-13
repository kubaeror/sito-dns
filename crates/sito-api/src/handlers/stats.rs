//! Statistics endpoint handlers.

use crate::auth::RequireViewer;
use crate::error::ProblemDetails;
use crate::models::StatsQuery;
use crate::state::ServerContext;
use axum::Json;
use axum::extract::{Query, State};
use sito_stats::{ClientStats, GlobalStats, UpstreamStats};

/// Longest accepted statistics window (5 years) — prevents absurd inputs from
/// overflowing the millisecond conversion.
pub const MAX_WINDOW_HOURS: i64 = 24 * 366 * 5;

/// Parses the `window` query parameter into milliseconds, clamping the result
/// and rejecting absurd values with `400 Bad Request`.
pub fn parse_window_ms(window: Option<&str>) -> Result<i64, ProblemDetails> {
    let hours = match window {
        None | Some("" | "24h") => 24,
        Some("1h") => 1,
        Some("7d") => 7 * 24,
        Some("30d") => 30 * 24,
        Some("90d") => 90 * 24,
        Some(other) => {
            let trimmed = other.trim();
            let Some(raw_hours) = trimmed.strip_suffix('h') else {
                return Err(ProblemDetails::bad_request(format!(
                    "Invalid window '{other}'. Use 1h, 24h, 7d or 30d."
                )));
            };
            match raw_hours.parse::<i64>() {
                Ok(hours) if (1..=MAX_WINDOW_HOURS).contains(&hours) => hours,
                Ok(_) => {
                    return Err(ProblemDetails::bad_request(format!(
                        "Window '{other}' is out of range (max {MAX_WINDOW_HOURS}h)."
                    )));
                }
                Err(_) => {
                    return Err(ProblemDetails::bad_request(format!(
                        "Invalid window '{other}'. Use 1h, 24h, 7d or 30d."
                    )));
                }
            }
        }
    };

    hours
        .checked_mul(3600)
        .and_then(|secs| secs.checked_mul(1000))
        .ok_or_else(|| ProblemDetails::bad_request("Statistics window is too large."))
}

#[utoipa::path(
    get,
    path = "/api/v1/stats",
    params(StatsQuery),
    responses(
        (status = 200, description = "Global statistics retrieved", body = GlobalStats),
        (status = 400, description = "Invalid window", body = ProblemDetails),
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
    let window_ms = parse_window_ms(query.window.as_deref())?;
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
        (status = 400, description = "Invalid window", body = ProblemDetails),
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
    let window_ms = parse_window_ms(query.window.as_deref())?;
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
        (status = 400, description = "Invalid window", body = ProblemDetails),
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
    let window_ms = parse_window_ms(query.window.as_deref())?;
    let stats = ctx
        .stats_db
        .get_upstream_stats(window_ms)
        .await
        .map_err(|e| ProblemDetails::internal_error(e.to_string()))?;
    Ok(Json(stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_parsing_and_clamping() {
        assert_eq!(parse_window_ms(None).unwrap(), 24 * 3600 * 1000);
        assert_eq!(parse_window_ms(Some("1h")).unwrap(), 3600 * 1000);
        assert_eq!(parse_window_ms(Some("7d")).unwrap(), 7 * 24 * 3600 * 1000);
        assert_eq!(parse_window_ms(Some("48h")).unwrap(), 48 * 3600 * 1000);

        // Absurd inputs are rejected instead of overflowing.
        assert!(parse_window_ms(Some("999999999999999999h")).is_err());
        assert!(parse_window_ms(Some("99999999999999999999")).is_err());
        assert!(parse_window_ms(Some("not-a-window")).is_err());
        assert!(parse_window_ms(Some("0h")).is_err());
    }
}
