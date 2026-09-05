//! Prometheus metrics exposition endpoint.

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};

use crate::state::ServerContext;

/// Expose all Prometheus metrics in text format per Table 14.2.
pub async fn get_metrics(State(ctx): State<ServerContext>) -> Response {
    let body = ctx.metrics.render_prometheus();
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}
