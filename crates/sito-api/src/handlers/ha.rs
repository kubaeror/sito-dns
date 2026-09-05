//! High Availability endpoints implementing cluster status, replica listing, and resync.

use axum::Json;
use axum::extract::State;

use crate::auth::rbac::RequireAdmin;
use crate::error::ProblemDetails;
use crate::models::{HaResyncResponse, HaSlaveSummary, HaStatusResponse};
use crate::state::ServerContext;

/// Get HA cluster status.
#[utoipa::path(
    get,
    path = "/api/v1/ha/status",
    responses(
        (status = 200, description = "HA cluster status", body = HaStatusResponse),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn get_ha_status(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
) -> Result<Json<HaStatusResponse>, ProblemDetails> {
    let cfg = ctx.config.load();
    let role = cfg.server.role.clone();
    let instance_name = cfg.server.instance_name.clone();

    if role == "master" {
        let (version, slaves_connected) = if let Some(ref coord) = ctx.master_coordinator {
            (coord.get_current_version(), coord.connected_slave_count())
        } else {
            (1, 0)
        };

        Ok(Json(HaStatusResponse {
            role,
            instance_name,
            version,
            state: "active".to_string(),
            master_url: None,
            slaves_connected,
            last_synced_at: None,
            degraded_reason: None,
        }))
    } else {
        let (version, state, last_synced_at, degraded_reason, master_url) =
            if let Some(ref tracker) = ctx.slave_tracker {
                (
                    tracker.get_version(),
                    tracker.get_state().to_string(),
                    tracker
                        .last_synced_at
                        .lock()
                        .unwrap()
                        .map(|t| t.to_rfc3339()),
                    tracker.degraded_reason.lock().unwrap().clone(),
                    tracker.master_url.clone(),
                )
            } else {
                (
                    0,
                    "disconnected".to_string(),
                    None,
                    None,
                    Some(ctx.resolve_master_url()),
                )
            };

        Ok(Json(HaStatusResponse {
            role,
            instance_name,
            version,
            state,
            master_url,
            slaves_connected: 0,
            last_synced_at,
            degraded_reason,
        }))
    }
}

/// List connected HA replica secondary nodes.
#[utoipa::path(
    get,
    path = "/api/v1/ha/slaves",
    responses(
        (status = 200, description = "List connected replica slaves", body = Vec<HaSlaveSummary>),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn get_ha_slaves(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
) -> Result<Json<Vec<HaSlaveSummary>>, ProblemDetails> {
    if let Some(ref coord) = ctx.master_coordinator {
        let summaries = coord
            .list_slaves()
            .into_iter()
            .map(HaSlaveSummary::from)
            .collect();
        Ok(Json(summaries))
    } else {
        Ok(Json(Vec::new()))
    }
}

/// Trigger manual HA resynchronization.
#[utoipa::path(
    post,
    path = "/api/v1/ha/resync",
    responses(
        (status = 200, description = "Triggered HA synchronization", body = HaResyncResponse),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn trigger_ha_resync(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
) -> Result<Json<HaResyncResponse>, ProblemDetails> {
    let role = ctx.config.load().server.role.clone();

    if role == "master" {
        let version = if let Some(ref coord) = ctx.master_coordinator {
            coord.trigger_resync()
        } else {
            1
        };
        Ok(Json(HaResyncResponse {
            status: "resync_triggered".to_string(),
            role,
            version,
        }))
    } else {
        let version = if let Some(ref tracker) = ctx.slave_tracker {
            if let Some(ref tx) = ctx.resync_sender {
                let _ = tx.try_send(());
            }
            tracker.get_version()
        } else {
            0
        };
        Ok(Json(HaResyncResponse {
            status: "resync_triggered".to_string(),
            role,
            version,
        }))
    }
}
