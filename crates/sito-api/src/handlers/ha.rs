//! High Availability endpoints implementing cluster status, replica listing, and resync.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use tokio::sync::mpsc;

use crate::auth::rbac::RequireAdmin;
use crate::error::ProblemDetails;
use crate::models::{HaResyncResponse, HaSlaveSummary, HaStatusResponse};
use crate::state::ServerContext;

fn unavailable(detail: impl Into<String>) -> ProblemDetails {
    ProblemDetails::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "Service Unavailable",
        detail,
    )
}

/// Handles a resync request on a master node: a coordinator must exist and the
/// push must actually be queued for at least one connected slave.
fn resync_master(
    coordinator: Option<&sito_ha::MasterCoordinator>,
    role: &str,
) -> Result<HaResyncResponse, ProblemDetails> {
    let coordinator = coordinator.ok_or_else(|| {
        unavailable("HA replication is not active on this node (no master coordinator)")
    })?;
    let outcome = coordinator.trigger_resync();
    let connected = coordinator.connected_slave_count();
    if outcome.active_bundle && connected > 0 && outcome.slaves_notified == 0 {
        return Err(unavailable(format!(
            "Resync push could not be queued for any of the {connected} connected slave(s)"
        )));
    }
    Ok(HaResyncResponse {
        status: "resync_triggered".to_string(),
        role: role.to_string(),
        version: outcome.version,
        active_bundle: Some(outcome.active_bundle),
        slaves_notified: Some(outcome.slaves_notified),
    })
}

/// Handles a resync request on a slave node: the replication worker must be
/// running and its resync queue must accept the request.
fn resync_slave(
    tracker: Option<&sito_ha::SlaveStatusTracker>,
    sender: Option<&mpsc::Sender<()>>,
    role: &str,
) -> Result<HaResyncResponse, ProblemDetails> {
    let tracker = tracker.ok_or_else(|| {
        unavailable("HA replication is not active on this node (no slave tracker)")
    })?;
    let sender = sender.ok_or_else(|| {
        unavailable("Slave replication worker is not running; resync cannot be queued")
    })?;

    match sender.try_send(()) {
        Ok(()) => Ok(HaResyncResponse {
            status: "resync_triggered".to_string(),
            role: role.to_string(),
            version: tracker.get_version(),
            active_bundle: None,
            slaves_notified: None,
        }),
        Err(mpsc::error::TrySendError::Full(())) => Err(ProblemDetails::too_many_requests(
            "A resynchronization request is already queued; retry shortly",
        )),
        Err(mpsc::error::TrySendError::Closed(())) => Err(unavailable(
            "Slave replication worker has stopped; resync cannot be queued",
        )),
    }
}

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
        let (version, slaves_connected, diverged, diverged_reason, master_pubkey) =
            if let Some(ref coord) = ctx.master_coordinator {
                (
                    coord.get_current_version(),
                    coord.connected_slave_count(),
                    coord.is_diverged(),
                    coord.diverged_reason(),
                    Some(coord.signing_key.public_key_hex()),
                )
            } else {
                (1, 0, false, None, None)
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
            diverged,
            diverged_reason,
            master_pubkey,
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
            diverged: false,
            diverged_reason: None,
            master_pubkey: None,
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
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 429, description = "A resync is already queued", body = ProblemDetails),
        (status = 503, description = "HA replication is not active or the resync could not be queued", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn trigger_ha_resync(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
) -> Result<Json<HaResyncResponse>, ProblemDetails> {
    let role = ctx.config.load().server.role.clone();

    let response = if role == "master" {
        resync_master(ctx.master_coordinator.as_ref(), &role)?
    } else {
        resync_slave(
            ctx.slave_tracker.as_ref(),
            ctx.resync_sender.as_ref(),
            &role,
        )?
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sito_ha::master::ActiveSlave;
    use sito_stats::MetricsRegistry;
    use std::sync::Arc;
    use std::time::Instant;

    fn test_coordinator() -> sito_ha::MasterCoordinator {
        let key = Arc::new(sito_ha::Ed25519SigningKey::generate().unwrap());
        sito_ha::MasterCoordinator::new(
            "test-master".to_string(),
            1,
            key,
            MetricsRegistry::new("test", "test"),
        )
    }

    fn test_bundle(version: u64) -> sito_ha::ConfigBundle {
        sito_ha::ConfigBundle {
            version,
            term: 0,
            timestamp: 1,
            config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
            custom_rules: vec![],
            rewrites: None,
            clients: None,
            lists: vec![],
        }
    }

    fn register_closed_slave(coordinator: &sito_ha::MasterCoordinator, instance: &str) {
        let (tx, rx) = mpsc::channel(1);
        coordinator.slaves.lock().unwrap().insert(
            instance.to_string(),
            ActiveSlave {
                instance: instance.to_string(),
                remote_addr: "127.0.0.1:12345".parse().unwrap(),
                synced_version: 0,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 1,
            },
        );
        // The receiver is gone: every delivery attempt fails.
        drop(rx);
    }

    #[test]
    fn test_status_response_exposes_divergence_and_master_pubkey() {
        let response = HaStatusResponse {
            role: "master".to_string(),
            instance_name: "master-1".to_string(),
            version: 11,
            state: "active".to_string(),
            master_url: None,
            slaves_connected: 1,
            last_synced_at: None,
            degraded_reason: None,
            diverged: true,
            diverged_reason: Some("continuity is broken".to_string()),
            master_pubkey: Some("ab".repeat(32)),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["diverged"], true);
        assert_eq!(json["diverged_reason"], "continuity is broken");
        assert_eq!(json["master_pubkey"], "ab".repeat(32));

        // A slave summary flags the diverged slave instead of showing lag 0 as
        // "in sync".
        let summary = HaSlaveSummary {
            instance: "slave-1".to_string(),
            remote_addr: "127.0.0.1:1".to_string(),
            synced_version: 50,
            lag: 0,
            diverged: true,
            last_ping_secs_ago: 0,
            connected_at: "2026-01-01T00:00:00Z".to_string(),
            last_stats: None,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["diverged"], true);
    }

    #[test]
    fn test_resync_without_coordinator_or_worker_is_unavailable() {
        let err = resync_master(None, "master").expect_err("no coordinator must fail");
        assert_eq!(err.status, 503);

        let err = resync_slave(None, None, "slave").expect_err("no tracker must fail");
        assert_eq!(err.status, 503);

        let tracker = sito_ha::SlaveStatusTracker::new("slave-1".to_string(), 7, None);
        let err = resync_slave(Some(&tracker), None, "slave").expect_err("no worker must fail");
        assert_eq!(err.status, 503);
        assert!(err.detail.contains("worker"));
    }

    #[test]
    fn test_resync_slave_reports_queue_state() {
        let tracker = sito_ha::SlaveStatusTracker::new("slave-1".to_string(), 7, None);
        let (tx, mut rx) = mpsc::channel(1);

        let response = resync_slave(Some(&tracker), Some(&tx), "slave").unwrap();
        assert_eq!(response.status, "resync_triggered");
        assert_eq!(response.version, 7);
        assert!(rx.try_recv().is_ok());

        // Queue full: the request is rejected instead of pretending success.
        tx.try_send(()).unwrap();
        let err = resync_slave(Some(&tracker), Some(&tx), "slave")
            .expect_err("a full queue must not report success");
        assert_eq!(err.status, 429);

        // Worker gone (receiver dropped): closed channel is an error.
        drop(rx);
        let err = resync_slave(Some(&tracker), Some(&tx), "slave")
            .expect_err("a closed queue must not report success");
        assert_eq!(err.status, 503);
    }

    #[test]
    fn test_resync_master_reports_delivery_honestly() {
        let coordinator = test_coordinator();

        // No active bundle yet: accepted, but nothing to push.
        let response = resync_master(Some(&coordinator), "master").unwrap();
        assert_eq!(response.status, "resync_triggered");
        assert_eq!(response.active_bundle, Some(false));
        assert_eq!(response.slaves_notified, Some(0));

        coordinator.update_bundle(test_bundle(2)).unwrap();

        // Connected but unreachable slave: delivery failed, do not claim success.
        register_closed_slave(&coordinator, "slave-dead");
        let err = resync_master(Some(&coordinator), "master")
            .expect_err("an undeliverable resync must not report success");
        assert_eq!(err.status, 503);

        // Reachable slave: queued and reported.
        let (tx, mut rx) = mpsc::channel(4);
        coordinator.slaves.lock().unwrap().insert(
            "slave-live".to_string(),
            ActiveSlave {
                instance: "slave-live".to_string(),
                remote_addr: "127.0.0.1:23456".parse().unwrap(),
                synced_version: 2,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id: 2,
            },
        );
        let response = resync_master(Some(&coordinator), "master").unwrap();
        assert_eq!(response.active_bundle, Some(true));
        assert_eq!(response.slaves_notified, Some(1));
        assert!(rx.try_recv().is_ok(), "the live slave receives the push");
        assert!(
            rx.try_recv().is_err(),
            "each slave must receive exactly one push"
        );
    }
}
