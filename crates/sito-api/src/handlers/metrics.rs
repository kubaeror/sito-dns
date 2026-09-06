//! Prometheus metrics exposition endpoint.

use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE};
use axum::response::{IntoResponse, Response};

use crate::auth::rbac::authenticate_request;
use crate::auth::token::Role;
use crate::error::ProblemDetails;
use crate::state::ServerContext;

/// Expose all Prometheus metrics in text format per Table 14.2.
pub async fn get_metrics(
    State(ctx): State<ServerContext>,
    request: axum::extract::Request,
) -> Result<Response, ProblemDetails> {
    let (parts, _) = request.into_parts();
    let config = ctx.config.load();
    let web_cfg = config.get_web_config();

    let has_auth = parts.headers.contains_key(AUTHORIZATION)
        || parts.headers.contains_key(COOKIE)
        || parts.uri.query().is_some_and(|q| q.contains("token="));

    if web_cfg.metrics_auth || has_auth {
        let auth_user = authenticate_request(&parts, &ctx.auth_mgr)?;
        if auth_user.role < Role::Viewer {
            return Err(ProblemDetails::forbidden(
                "Insufficient privileges: requires at least Viewer role",
            ));
        }
    }

    let body = ctx.metrics.render_prometheus();
    Ok((
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response())
}
