//! Query log endpoints and WebSocket streaming per section 12.1.

use crate::auth::client_ip::resolve_client_ip;
use crate::auth::{MaybeConnectInfo, RequireOperator, RequireViewer};
use crate::error::ProblemDetails;
use crate::models::GenericMessageResponse;
use crate::state::ServerContext;
use axum::Json;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use sito_stats::{QueryLogFilter, QueryLogPage};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use utoipa::IntoParams;

/// Hard cap on the number of query-log rows returned by a REST request.
pub const MAX_QUERYLOG_LIMIT: usize = 1_000;
/// Default number of rows when no `limit` is supplied.
pub const DEFAULT_QUERYLOG_LIMIT: usize = 100;
/// Maximum REST query-log requests per client IP within `REST_RATE_WINDOW`.
const REST_RATE_LIMIT: u32 = 120;
const REST_RATE_WINDOW: Duration = Duration::from_secs(60);
/// Maximum tracked client IPs in the REST rate limiter. Bounds memory when
/// many distinct (possibly spoofed) addresses hit the endpoint.
const MAX_REST_RATE_BUCKETS: usize = 8_192;
/// Maximum WebSocket entries forwarded per second (excess entries are dropped
/// to keep one slow viewer from pinning a CPU).
const WS_MAX_ENTRIES_PER_SECOND: u32 = 200;

#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct QueryLogQueryParams {
    pub client: Option<String>,
    pub domain: Option<String>,
    pub status: Option<String>,
    pub qtype: Option<u16>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub cursor: Option<i64>,
    pub limit: Option<usize>,
    /// Defaults to `true` for API compatibility. The live UI refresh passes
    /// `false` so the 3 s poll does not run a whole-table `COUNT(*)`.
    pub include_total: Option<bool>,
}

/// Query parameters for clearing the log.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ClearQueryLogParams {
    /// Preserve `stats_hourly` rollups (the old “fold into aggregates”
    /// behavior). Defaults to `false`: both detailed rows and rollups are
    /// erased.
    #[serde(default)]
    pub keep_aggregates: bool,
}

fn rest_rate_limiter() -> &'static Mutex<HashMap<String, (Instant, u32)>> {
    static LIMITER: OnceLock<Mutex<HashMap<String, (Instant, u32)>>> = OnceLock::new();
    LIMITER.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns true when the client exceeded the REST query-log rate limit.
fn rest_rate_limited(client_ip: &str) -> bool {
    let mut buckets = rest_rate_limiter()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    buckets.retain(|_, (start, _)| now.duration_since(*start) <= REST_RATE_WINDOW);
    if buckets.len() >= MAX_REST_RATE_BUCKETS && !buckets.contains_key(client_ip) {
        // Evict one (typically stale) bucket to keep the table bounded.
        if let Some(victim) = buckets.keys().next().cloned() {
            buckets.remove(&victim);
        }
    }
    let entry = buckets.entry(client_ip.to_string()).or_insert((now, 0));
    if now.duration_since(entry.0) > REST_RATE_WINDOW {
        *entry = (now, 0);
    }
    entry.1 = entry.1.saturating_add(1);
    entry.1 > REST_RATE_LIMIT
}

/// Error type for the query-log REST handler.
///
/// Rate-limit responses carry `Retry-After` so a polling UI backs off instead
/// of immediately retrying the paginated query. Other failures remain plain
/// RFC 7807 problem details.
#[derive(Debug)]
pub enum QueryLogHandlerError {
    Problem(ProblemDetails),
    RateLimited(ProblemDetails),
}

impl IntoResponse for QueryLogHandlerError {
    fn into_response(self) -> Response {
        match self {
            Self::Problem(problem) => problem.into_response(),
            Self::RateLimited(problem) => {
                let mut response = problem.into_response();
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                response
            }
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/querylog",
    params(QueryLogQueryParams),
    responses(
        (status = 200, description = "Query logs retrieved with cursor pagination", body = QueryLogPage),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 429, description = "Rate limited", body = ProblemDetails,
            headers(("Retry-After", description = "Seconds to wait before retrying")))
    ),
    tag = "QueryLog"
)]
pub async fn get_querylog(
    _viewer: RequireViewer,
    State(ctx): State<ServerContext>,
    MaybeConnectInfo(peer_addr): MaybeConnectInfo,
    headers: HeaderMap,
    Query(params): Query<QueryLogQueryParams>,
) -> Result<Json<QueryLogPage>, QueryLogHandlerError> {
    let config = ctx.config.load();
    let trusted_proxies = config.get_web_config().trusted_proxies.clone();
    drop(config);
    let client_ip = resolve_client_ip(peer_addr, &headers, &trusted_proxies);
    if rest_rate_limited(&client_ip) {
        return Err(QueryLogHandlerError::RateLimited(
            ProblemDetails::too_many_requests("Too many query-log requests. Please slow down."),
        ));
    }

    let limit = params
        .limit
        .unwrap_or(DEFAULT_QUERYLOG_LIMIT)
        .clamp(1, MAX_QUERYLOG_LIMIT);
    let filter = QueryLogFilter {
        client: params.client,
        domain: params.domain,
        status: params.status,
        qtype: params.qtype,
        from: params.from,
        to: params.to,
        cursor: params.cursor,
        limit: Some(limit),
        include_total: params.include_total,
    };

    let page = ctx.stats_db.query_logs(&filter).await.map_err(|e| {
        QueryLogHandlerError::Problem(ProblemDetails::internal_error(e.to_string()))
    })?;
    Ok(Json(page))
}

#[utoipa::path(
    delete,
    path = "/api/v1/querylog",
    params(ClearQueryLogParams),
    responses(
        (status = 200, description = "Query log cleared successfully", body = GenericMessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "QueryLog"
)]
pub async fn delete_querylog(
    _operator: RequireOperator,
    headers: HeaderMap,
    State(ctx): State<ServerContext>,
    Query(params): Query<ClearQueryLogParams>,
) -> Result<Response, ProblemDetails> {
    let rollup_client_names = ctx.config.load().get_stats_config().rollup_client_names;
    let affected = ctx
        .stats_db
        .delete_query_logs_with_policy(params.keep_aggregates, rollup_client_names)
        .await
        .map_err(|e| ProblemDetails::internal_error(e.to_string()))?;

    if headers.contains_key("hx-request") {
        return Ok(axum::response::Html(
            "<tr><td colspan='6' class='text-muted text-center py-4'>No queries recorded yet</td></tr>",
        )
        .into_response());
    }

    Ok(Json(GenericMessageResponse {
        message: format!("Successfully deleted {affected} query log entries"),
    })
    .into_response())
}

/// WebSocket live tail endpoint streaming query log entries in real-time.
pub async fn stream_querylog(
    ws: WebSocketUpgrade,
    _viewer: RequireViewer,
    State(ctx): State<ServerContext>,
) -> Response {
    ws.on_upgrade(move |socket| handle_live_tail(socket, ctx))
}

async fn handle_live_tail(mut socket: WebSocket, ctx: ServerContext) {
    let mut rx = ctx.querylog_sender.subscribe();
    let mut window_start = Instant::now();
    let mut window_count: u32 = 0;
    loop {
        tokio::select! {
            entry = rx.recv() => {
                match entry {
                    Ok(entry) => {
                        let now = Instant::now();
                        if now.duration_since(window_start) >= Duration::from_secs(1) {
                            window_start = now;
                            window_count = 0;
                        }
                        if window_count >= WS_MAX_ENTRIES_PER_SECOND {
                            // Drop excess entries instead of stalling the sender.
                            continue;
                        }
                        window_count += 1;
                        if let Ok(json) = serde_json::to_string(&entry)
                            && socket.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => break,
                }
            }
            msg = socket.recv() => {
                if msg.is_none() {
                    break;
                }
            }
        }
    }
    let _ = socket.send(Message::Close(None)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rest_rate_limiter_blocks_after_budget() {
        let ip = "203.0.113.201";
        for _ in 0..REST_RATE_LIMIT {
            assert!(!rest_rate_limited(ip));
        }
        assert!(rest_rate_limited(ip));
        // A different client is unaffected.
        assert!(!rest_rate_limited("198.51.100.201"));
    }

    #[test]
    fn test_limit_clamping() {
        assert_eq!(0usize.clamp(1, MAX_QUERYLOG_LIMIT), 1);
        assert_eq!(usize::MAX.clamp(1, MAX_QUERYLOG_LIMIT), MAX_QUERYLOG_LIMIT);
    }

    /// Deferred D4a: the query-log 429 must carry `Retry-After` like the stats
    /// endpoints, so a polling UI backs off instead of retrying immediately.
    #[tokio::test]
    async fn test_querylog_rate_limit_response_has_retry_after() {
        use crate::auth::token::Role;
        use crate::auth::{AuthUser, MaybeConnectInfo, RequireViewer};

        let temp_dir = crate::test_support::temp_dir("sito_querylog_429");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let octet = rand::random::<u8>();
        let client_ip = format!("198.51.100.{octet}");
        for _ in 0..REST_RATE_LIMIT {
            assert!(!rest_rate_limited(&client_ip));
        }

        let viewer = RequireViewer(AuthUser {
            username: "viewer".to_string(),
            role: Role::Viewer,
            token_id: None,
        });
        let peer = std::net::SocketAddr::from(([198, 51, 100, octet], 12_345));
        let Err(error) = get_querylog(
            viewer,
            State(ctx),
            MaybeConnectInfo(Some(peer)),
            HeaderMap::new(),
            Query(QueryLogQueryParams::default()),
        )
        .await
        else {
            panic!("the exhausted query-log budget must return 429");
        };

        let response = error.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .unwrap(),
            "1",
            "query-log 429 responses must advertise the retry window"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
