//! Axum router configuration binding handlers, middleware, and documentation.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::error::ProblemDetails;
use crate::handlers::{
    auth_handlers, cache, clients, config, filtering, ha, metrics, querylog, rewrites, stats,
    status, upstream,
};
use crate::openapi::ApiDoc;
use crate::state::ServerContext;

#[cfg(feature = "embed-ui")]
use axum::http::header::CONTENT_TYPE;
#[cfg(feature = "embed-ui")]
use axum::response::Response;

#[cfg(not(feature = "embed-ui"))]
async fn not_found_handler() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ProblemDetails::not_found(
            "The requested endpoint does not exist",
        )),
    )
}

#[cfg(feature = "embed-ui")]
#[derive(rust_embed::RustEmbed)]
#[folder = "../../web/dist"]
struct WebDist;

#[cfg(feature = "embed-ui")]
async fn ui_handler(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    if path.starts_with("api/") || path == "api" || path == "metrics" {
        return (
            StatusCode::NOT_FOUND,
            Json(ProblemDetails::not_found(
                "The requested endpoint does not exist",
            )),
        )
            .into_response();
    }

    let file_path = if path.is_empty() { "index.html" } else { path };

    if let Some(file) = WebDist::get(file_path) {
        let mime = mime_guess::from_path(file_path).first_or_octet_stream();
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, mime.as_ref())
            .body(axum::body::Body::from(file.data))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    } else {
        // SPA fallback: non-file paths serve index.html for client-side routing
        if file_path.contains('.') {
            return (
                StatusCode::NOT_FOUND,
                Json(ProblemDetails::not_found("Asset not found")),
            )
                .into_response();
        }

        if let Some(index) = WebDist::get("index.html") {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/html; charset=utf-8")
                .body(axum::body::Body::from(index.data))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        } else {
            (
                StatusCode::NOT_FOUND,
                Json(ProblemDetails::not_found("UI index.html not found")),
            )
                .into_response()
        }
    }
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
            put(clients::update_client).delete(clients::delete_client),
        )
        .route(
            "/clients/groups",
            get(clients::get_client_groups).post(clients::add_client_group),
        )
        .route(
            "/clients/groups/{name}",
            put(clients::update_client_group).delete(clients::delete_client_group),
        )
        // Rewrites
        .route(
            "/rewrites",
            get(rewrites::get_rewrites).post(rewrites::add_rewrite),
        )
        .route("/rewrites/{id}", delete(rewrites::delete_rewrite))
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
        .route("/config/restore/confirm", post(config::confirm_restore));

    #[cfg(feature = "embed-ui")]
    let app = Router::new()
        .nest("/api/v1", api_v1)
        .route("/metrics", get(metrics::get_metrics))
        .merge(SwaggerUi::new("/api/docs").url("/api/docs/openapi.json", ApiDoc::openapi()))
        .fallback(ui_handler)
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
