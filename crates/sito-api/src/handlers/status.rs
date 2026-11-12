//! Status endpoint handler.

use crate::auth::RequireViewer;
use crate::models::{AcmeStatus, StatusResponse};
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

    let acme_readiness = ctx.acme_readiness(&cfg);
    let acme = acme_readiness.enabled.then(|| AcmeStatus {
        enabled: acme_readiness.enabled,
        ready: acme_readiness.ready,
        http01_available: acme_readiness.http01_available,
        tls_alpn_available: acme_readiness.tls_alpn_available,
        reason: acme_readiness.reason.map(str::to_string),
        last_error: acme_readiness.last_error,
    });
    let readiness = ctx.readiness_report().await;

    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        role: cfg.server.role.clone(),
        listeners,
        ready: readiness.ready,
        reasons: readiness.reasons,
        acme,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::rbac::AuthUser;
    use crate::auth::token::Role;

    fn viewer() -> RequireViewer {
        RequireViewer(AuthUser {
            username: "viewer".to_string(),
            role: Role::Viewer,
            token_id: None,
        })
    }

    /// WP-1.7: `/status` is the detailed admin view. It must carry the
    /// aggregate verdict and per-component reasons while staying additive to
    /// the existing version/uptime/role/listeners/acme fields.
    #[tokio::test]
    async fn test_status_includes_ready_and_component_reasons() {
        let temp_dir = crate::test_support::temp_dir("sito_status_ready");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        ctx.readiness
            .set_listeners_unavailable("listener_bind_failed", "no DNS listener is bound");
        ctx.readiness
            .set_tls_unavailable("tls_acceptor_unavailable", "configured TLS is not serving");

        let Json(status) = get_status(viewer(), State(ctx.clone())).await;

        assert!(!status.ready);
        assert_eq!(status.role, "master");
        assert_ne!(status.listeners, Vec::<String>::new());
        let components: Vec<&str> = status
            .reasons
            .iter()
            .map(|reason| reason.component.as_str())
            .collect();
        assert!(components.contains(&"listeners"), "{components:?}");
        assert!(components.contains(&"tls"), "{components:?}");
        let listener_reason = status
            .reasons
            .iter()
            .find(|reason| reason.component == "listeners")
            .expect("listener reason");
        assert_eq!(listener_reason.code, "listener_bind_failed");
        assert!(listener_reason.message.contains("no DNS listener"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// A healthy mock context (no HA, disabled filtering, healthy stats) is
    /// ready and has no reasons.
    #[tokio::test]
    async fn test_status_reports_ready_without_reasons() {
        let temp_dir = crate::test_support::temp_dir("sito_status_ok");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        let Json(status) = get_status(viewer(), State(ctx.clone())).await;

        assert!(status.ready, "unexpected reasons: {:?}", status.reasons);
        assert!(status.reasons.is_empty(), "{:?}", status.reasons);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
