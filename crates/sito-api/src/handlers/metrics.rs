//! Prometheus metrics exposition endpoint.

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};

use crate::auth::rbac::authenticate_request;
use crate::auth::token::Role;
use crate::error::ProblemDetails;
use crate::state::ServerContext;

/// Expose all Prometheus metrics in text format per Table 14.2.
///
/// When `web.metrics_auth` is enabled a real bearer-token or session
/// authentication is required. Query-string tokens are not accepted here
/// (they are only tolerated on WebSocket upgrades).
pub async fn get_metrics(
    State(ctx): State<ServerContext>,
    request: axum::extract::Request,
) -> Result<Response, ProblemDetails> {
    let (parts, _) = request.into_parts();
    let config = ctx.config.load();
    let web_cfg = config.get_web_config();
    drop(config);

    if web_cfg.metrics_auth {
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
