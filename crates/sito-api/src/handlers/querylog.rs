//! Query log endpoints and WebSocket streaming per section 12.1.

use crate::auth::{RequireOperator, RequireViewer};
use crate::error::ProblemDetails;
use crate::models::GenericMessageResponse;
use crate::state::ServerContext;
use axum::Json;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use sito_stats::{QueryLogFilter, QueryLogPage};
use utoipa::IntoParams;

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
}

#[utoipa::path(
    get,
    path = "/api/v1/querylog",
    params(QueryLogQueryParams),
    responses(
        (status = 200, description = "Query logs retrieved with cursor pagination", body = QueryLogPage),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "QueryLog"
)]
pub async fn get_querylog(
    _viewer: RequireViewer,
    State(ctx): State<ServerContext>,
    Query(params): Query<QueryLogQueryParams>,
) -> Result<Json<QueryLogPage>, ProblemDetails> {
    let filter = QueryLogFilter {
        client: params.client,
        domain: params.domain,
        status: params.status,
        qtype: params.qtype,
        from: params.from,
        to: params.to,
        cursor: params.cursor,
        limit: params.limit,
    };

    let page = ctx
        .stats_db
        .query_logs(&filter)
        .await
        .map_err(|e| ProblemDetails::internal_error(e.to_string()))?;
    Ok(Json(page))
}

#[utoipa::path(
    delete,
    path = "/api/v1/querylog",
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
) -> Result<Response, ProblemDetails> {
    let affected = ctx
        .stats_db
        .delete_query_logs()
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
    loop {
        tokio::select! {
            entry = rx.recv() => {
                match entry {
                    Ok(entry) => {
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
}
