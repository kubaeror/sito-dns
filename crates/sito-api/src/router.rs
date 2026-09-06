//! Axum router configuration binding handlers, middleware, and documentation.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::error::ProblemDetails;
use crate::handlers::{
    auth_handlers, cache, clients, config, filtering, ha, metrics, querylog, rewrites, stats,
    status, update, upstream,
};
use crate::openapi::ApiDoc;
use crate::state::ServerContext;

/// Middleware that enforces read-only access on replica slave nodes.
/// Mutating methods (POST, PUT, DELETE, PATCH) outside auth and resync return 409 Conflict with X-Dnsd-Master header.
pub async fn slave_read_only_middleware(
    axum::extract::State(ctx): axum::extract::State<ServerContext>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method();
    let is_mutating = matches!(
        *method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    );

    let is_slave = ctx.config.load().server.role == "slave";

    if is_slave && is_mutating {
        let path = request.uri().path();
        let is_allowed = path.starts_with("/api/v1/auth")
            || path == "/api/v1/ha/resync"
            || path == "/ha/resync"
            || path.starts_with("/auth");

        if !is_allowed {
            let master_url = ctx.resolve_master_url();
            let mut problem = ProblemDetails::conflict(
                "Modifications are disabled on HA replica slaves. Submit configuration changes directly to the master node.",
            );
            problem.error_type = "urn:sito:ha:read-only".to_string();
            problem.title = "Read-Only Replica".to_string();
            problem.instance = Some(path.to_string());

            let mut resp = (StatusCode::CONFLICT, Json(problem)).into_response();
            if let Ok(val) = HeaderValue::from_str(&master_url) {
                resp.headers_mut()
                    .insert(HeaderName::from_static("x-dnsd-master"), val);
            }
            return resp;
        }
    }

    next.run(request).await
}

async fn not_found_handler() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ProblemDetails::not_found(
            "The requested endpoint does not exist",
        )),
    )
}

/// Constructs the complete administrative HTTP router.
pub fn create_router(ctx: ServerContext) -> Router {
    let api_v1 = Router::new()
        // System status
        .route("/status", get(status::get_status))
        // Stats
        .route("/stats", get(stats::get_stats))
        .route("/stats/clients", get(stats::get_client_stats))
        .route("/stats/upstreams", get(stats::get_upstream_stats))
        // Query log
        .route(
            "/querylog",
            get(querylog::get_querylog).delete(querylog::delete_querylog),
        )
        .route("/querylog/clear", post(querylog::delete_querylog))
        .route("/querylog/stream", get(querylog::stream_querylog))
        // Filtering
        .route(
            "/filtering/lists",
            get(filtering::get_filter_lists).post(filtering::add_filter_list),
        )
        .route(
            "/filtering/lists/{id}",
            put(filtering::update_filter_list).delete(filtering::delete_filter_list),
        )
        .route("/filtering/refresh", post(filtering::refresh_filtering))
        .route(
            "/filtering/rules",
            get(filtering::get_filtering_rules).put(filtering::set_filtering_rules),
        )
        .route("/filtering/check", post(filtering::check_filtering))
        // Clients
        .route(
            "/clients",
            get(clients::get_clients).post(clients::create_client),
        )
        .route(
            "/clients/{name}",
            get(clients::get_client_by_name)
                .put(clients::update_client)
                .delete(clients::delete_client),
        )
        .route(
            "/clients/groups",
            get(clients::get_client_groups).post(clients::add_client_group),
        )
        .route(
            "/clients/groups/{name}",
            get(clients::get_client_group_by_name)
                .put(clients::update_client_group)
                .delete(clients::delete_client_group),
        )
        // Rewrites
        .route(
            "/rewrites",
            get(rewrites::get_rewrites).post(rewrites::add_rewrite),
        )
        .route(
            "/rewrites/{id}",
            put(rewrites::update_rewrite).delete(rewrites::delete_rewrite),
        )
        // Upstream
        .route(
            "/upstream",
            get(upstream::get_upstream_config).put(upstream::update_upstream_config),
        )
        .route(
            "/upstream/config",
            get(upstream::get_upstream_config).put(upstream::update_upstream_config),
        )
        .route("/upstream/test", post(upstream::test_upstream_servers))
        // Cache
        .route("/cache/flush", post(cache::flush_cache))
        .route("/cache/invalidate", post(cache::invalidate_cache))
        // High Availability (M8 stubs)
        .route("/ha/status", get(ha::get_ha_status))
        .route("/ha/slaves", get(ha::get_ha_slaves))
        .route("/ha/resync", post(ha::trigger_ha_resync))
        // Authentication
        .route("/auth/login", post(auth_handlers::login))
        .route("/auth/totp/verify", post(auth_handlers::verify_totp))
        .route("/auth/logout", post(auth_handlers::logout))
        .route("/auth/totp/setup", get(auth_handlers::get_totp_setup))
        .route("/auth/totp/enable", post(auth_handlers::enable_totp))
        .route("/auth/totp/disable", post(auth_handlers::disable_totp))
        .route(
            "/auth/tokens",
            get(auth_handlers::list_tokens).post(auth_handlers::create_token),
        )
        .route("/auth/tokens/{id}", delete(auth_handlers::delete_token))
        // Configuration
        .route(
            "/config",
            get(config::get_config).put(config::update_config),
        )
        .route("/config/reload", post(config::reload_config))
        .route("/config/backup", get(config::download_backup))
        .route("/config/restore", post(config::prepare_restore))
        .route("/config/restore/confirm", post(config::confirm_restore))
        // Software Update
        .route("/system/update/check", get(update::check_update))
        .route("/system/update/apply", post(update::apply_update))
        .layer(axum::middleware::from_fn_with_state(
            ctx.clone(),
            slave_read_only_middleware,
        ));

    // Note: Swagger UI at /api/docs and OpenAPI JSON are intentionally unauthenticated
    // to enable client generation and documentation discovery. Restrict via reverse proxy if needed.
    #[cfg(feature = "embed-ui")]
    let app = Router::new()
        .nest("/api/v1", api_v1)
        .route("/metrics", get(metrics::get_metrics))
        .merge(SwaggerUi::new("/api/docs").url("/api/docs/openapi.json", ApiDoc::openapi()))
        .merge(crate::ui::ui_router())
        .fallback(not_found_handler)
        .with_state(ctx);

    #[cfg(not(feature = "embed-ui"))]
    let app = Router::new()
        .nest("/api/v1", api_v1)
        .route("/metrics", get(metrics::get_metrics))
        .merge(SwaggerUi::new("/api/docs").url("/api/docs/openapi.json", ApiDoc::openapi()))
        .fallback(not_found_handler)
        .with_state(ctx);

    app
}
