//! Status endpoint handler.

use crate::auth::RequireViewer;
use crate::models::StatusResponse;
use crate::state::ServerContext;
use axum::Json;
use axum::extract::State;

#[utoipa::path(
    get,
    path = "/api/v1/status",
    responses(
        (status = 200, description = "Server status retrieved successfully", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "System"
)]
#[allow(clippy::unused_async)]
pub async fn get_status(
    _viewer: RequireViewer,
    State(ctx): State<ServerContext>,
) -> Json<StatusResponse> {
    let cfg = ctx.config.load();
    let uptime = ctx.start_time.elapsed().as_secs();

    let mut listeners = Vec::new();
    for bind in &cfg.dns.bind {
        listeners.push(format!("{bind}:{} (UDP/TCP)", cfg.dns.port));
        if cfg.dns.dot_port > 0 {
            listeners.push(format!("{bind}:{} (DoT)", cfg.dns.dot_port));
        }
        if cfg.dns.doh_port > 0 {
            listeners.push(format!("{bind}:{} (DoH)", cfg.dns.doh_port));
        }
    }

    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        role: cfg.server.role.clone(),
        listeners,
    })
}
