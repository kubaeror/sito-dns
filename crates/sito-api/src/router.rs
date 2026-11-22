//! Axum router configuration binding handlers, middleware, and documentation.

use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::auth::client_ip::resolve_client_ip;
use crate::auth::rbac::RequireOperator;
use crate::auth::session::extract_session_cookie;
use crate::auth::token::Role;
use crate::error::ProblemDetails;
#[cfg(feature = "ha")]
use crate::handlers::ha;
#[cfg(not(feature = "ha"))]
use crate::handlers::ha_stub as ha;
use crate::handlers::{
    auth_handlers, cache, clients, config, filtering, metrics, querylog, rewrites, stats, status,
    update, upstream,
};
use crate::openapi::ApiDoc;
use crate::state::ServerContext;

/// Header accepted for first-boot setup authorization.
pub const SETUP_TOKEN_HEADER: &str = "x-setup-token";

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

    let is_slave =
        ctx.config.load().server.role == "slave" && !ctx.ha_write_gate.is_effective_master();
    let path = request.uri().path();
    // Login/logout/reauth must stay reachable on a read-only node; account,
    // token, TOTP-enable and password mutations are gated like config writes.
    let auth_allowed = matches!(
        path,
        "/api/v2/auth/login"
            | "/api/v2/auth/totp/verify"
            | "/api/v2/auth/logout"
            | "/api/v2/auth/reauth"
            | "/auth/login"
            | "/auth/totp/verify"
            | "/auth/logout"
            | "/auth/reauth"
            | "/ui/login"
            | "/ui/logout"
    );
    // `/ha/resync` stays reachable to report a precise 409/503; the handler
    // itself refuses to broadcast on a gated effective/configured master.
    let gate_allowed = auth_allowed || path == "/api/v2/ha/resync" || path == "/ha/resync";
    let slave_allowed = path.starts_with("/api/v2/auth")
        || path == "/api/v2/ha/resync"
        || path == "/ha/resync"
        || path == "/ui/login"
        || path == "/ui/logout"
        || path.starts_with("/auth");

    if is_mutating
        && !gate_allowed
        && let Some((reason, fenced)) = ctx.ha_write_gate.blocked()
    {
        let mut problem = ProblemDetails::conflict(if fenced {
            "This node is fenced for HA automatic promotion. Reconcile the cluster and clear the fence before submitting changes."
        } else {
            "HA automatic promotion is not writable yet. Configuration changes are disabled until the node holds the lease and has published."
        });
        problem.error_type = if fenced {
            "urn:sito:ha:promotion_fenced".to_string()
        } else {
            "urn:sito:ha:promotion_read_only".to_string()
        };
        problem.title = "HA Promotion Read-Only".to_string();
        problem.detail = reason;
        problem.instance = Some(path.to_string());
        return (StatusCode::CONFLICT, Json(problem)).into_response();
    }

    if is_slave && is_mutating && !slave_allowed {
        {
            let master_url = ctx.resolve_master_url();
            let mut problem = ProblemDetails::conflict(
                "Modifications are disabled on HA replica slaves. Submit configuration changes directly to the master node.",
            );
            problem.error_type = "urn:sito:ha:read-only".to_string();
            problem.title = "Read-Only Replica".to_string();
            problem.instance = Some(path.to_string());

            let mut resp = (StatusCode::CONFLICT, Json(problem)).into_response();
            if !master_url.is_empty()
                && let Ok(val) = HeaderValue::from_str(&master_url)
            {
                resp.headers_mut()
                    .insert(HeaderName::from_static("x-dnsd-master"), val);
            }
            return resp;
        }
    }

    next.run(request).await
}

/// Extracts the setup token from the `X-Setup-Token` header or the
/// `setup_token` query parameter.
fn setup_token_from_request(request: &Request) -> Option<String> {
    if let Some(value) = request
        .headers()
        .get(SETUP_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return Some(value.to_string());
    }
    let query = request.uri().query()?;
    for param in query.split('&') {
        let (key, value) = param.split_once('=').unwrap_or((param, ""));
        if key == "setup_token" && !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// Middleware that gates setup-only routes.
///
/// While a first-boot setup token is active (or the bootstrap
/// `admin/adminadmin` account is still active), `/wizard`, `/ui/wizard/*` and
/// `/ui/upstreams/test` require either an authenticated session with
/// sufficient privileges or the one-time setup token. During that window:
/// - Allows: `/wizard`, `/ui/wizard/*`, `/static/*`, `/assets/*`, `/health`,
///   `/status` and the setup-token-protected endpoints.
/// - Returns 403 for `/api/v2/auth/*` (login and credential management).
/// - Returns 503 for the remaining `/api/v2/*` routes.
/// - Redirects all other UI routes to `/wizard` (or `/login` once user
///   accounts exist and no setup token is required).
///
/// `setup_pending` alone only tracks a missing `config.toml`; the setup token
/// and default-admin checks are what make this fail closed when a configuration
/// file exists but the bootstrap credentials were never rotated.
pub async fn setup_pending_middleware(
    State(ctx): State<ServerContext>,
    request: Request,
    next: Next,
) -> Response {
    let setup_pending = ctx.is_setup_pending();
    let token_required = ctx.auth_mgr.setup_token_required();
    let default_admin_active = ctx.auth_mgr.is_default_admin_active();

    if !setup_pending && !token_required && !default_admin_active {
        return next.run(request).await;
    }

    let path = request.uri().path();
    let is_wizard = path == "/wizard" || path.starts_with("/ui/wizard");
    let is_probe = path == "/ui/upstreams/test";
    if is_wizard || is_probe {
        let authenticated_role = request
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(extract_session_cookie)
            .and_then(|id| ctx.auth_mgr.validate_session(&id))
            .map(|session| session.role);
        let privileged = if is_probe {
            authenticated_role.is_some_and(|role| role >= Role::Operator)
        } else {
            authenticated_role == Some(Role::Admin)
        };

        if !privileged {
            // The wizard completion form carries the token in its body, which
            // would require buffering the request here; the handler performs
            // the same constant-time validation and rate limiting instead.
            if path == "/ui/wizard/complete" {
                return next.run(request).await;
            }
            if token_required {
                let config = ctx.config.load();
                let trusted_proxies = config.get_web_config().trusted_proxies.clone();
                let peer = request
                    .extensions()
                    .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                    .map(|ci| ci.0);
                let client_ip = resolve_client_ip(peer, request.headers(), &trusted_proxies);
                drop(config);
                let candidate = setup_token_from_request(&request);
                match ctx
                    .auth_mgr
                    .validate_setup_token(candidate.as_deref(), &client_ip)
                {
                    crate::auth::SetupTokenStatus::Valid => {}
                    crate::auth::SetupTokenStatus::RateLimited => {
                        return ProblemDetails::too_many_requests(
                            "Too many invalid setup token attempts. Try again later.",
                        )
                        .into_response();
                    }
                    _ => {
                        return ProblemDetails::forbidden(
                            "First-boot setup token required (see server logs).",
                        )
                        .into_response();
                    }
                }
            } else if !setup_pending && !ctx.auth_mgr.is_first_run() {
                // No token provisioned and not in a bootstrap state: let the
                // normal auth layer decide.
                return next.run(request).await;
            } else if !ctx.auth_mgr.is_first_run() {
                // Setup-pending with an already-configured admin account but
                // no setup token: require an authenticated admin session.
                return ProblemDetails::forbidden(
                    "Setup wizard is disabled. Admin session required.",
                )
                .into_response();
            }
        }
    }

    // The setup gate applies whenever the deployment is still bootstrapping:
    // missing configuration, an unconsumed setup token, or the bootstrap
    // default password. A missing `config.toml` is not the only signal.
    // When user accounts already exist (missing `config.toml` but a valid
    // `users.toml` with a rotated password), the deployment is not in
    // first-boot state: allow the operator to log in instead of forcing the
    // wizard on every route.
    let first_run = ctx.auth_mgr.is_first_run();
    // A custom Admin may exist while the literal bootstrap `admin` credential
    // is still `adminadmin`; never reopen login in that state.
    let login_allowed = !first_run && !token_required && !default_admin_active;

    let login_path = path == "/login" || path == "/ui/login";
    let auth_api = path.starts_with("/api/v2/auth");
    if path.starts_with("/wizard")
        || path.starts_with("/ui/wizard")
        || path.starts_with("/static/")
        || path.starts_with("/assets/")
        || path == "/ui/upstreams/test"
        || path == "/health"
        || path == "/status"
        || (login_allowed && (login_path || auth_api))
    {
        return next.run(request).await;
    }

    // Fail closed on authentication while bootstrap credentials are live: a
    // remote client must not obtain a session with `admin/adminadmin` (or any
    // other account) before setup completes.
    if auth_api {
        return ProblemDetails::forbidden(
            "Authentication is disabled until first-boot setup is completed.",
        )
        .into_response();
    }

    if path.starts_with("/api/v2/") || path == "/api/v2" {
        return (StatusCode::SERVICE_UNAVAILABLE, "Setup not completed").into_response();
    }

    let target = if login_allowed { "/login" } else { "/wizard" };
    (StatusCode::FOUND, [(axum::http::header::LOCATION, target)]).into_response()
}

/// Generic readiness probe.
///
/// Unauthenticated and intentionally opaque: it reports only `ok` or
/// `unavailable`. Component details, reason codes, error text and configuration
/// values stay on the authenticated `/status` endpoint and in the logs
/// (P2-89/P2-87).
pub(crate) async fn health_handler(State(ctx): State<ServerContext>) -> impl IntoResponse {
    // Blocking-only report: no stats DB probe on the unauthenticated probe.
    let report = ctx.health_report();
    if report.ready {
        (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "unavailable" })),
        )
    }
}

async fn not_found_handler() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ProblemDetails::not_found(
            "The requested endpoint does not exist",
        )),
    )
}

/// Legacy alias for `GET|PUT /api/v2/upstream`; kept as a permanent redirect.
fn redirect_upstream_config() -> Response {
    (
        StatusCode::PERMANENT_REDIRECT,
        [(axum::http::header::LOCATION, "/api/v2/upstream")],
    )
        .into_response()
}

/// Documented GET alias for `/api/v2/upstream`.
#[utoipa::path(
    get,
    path = "/api/v2/upstream/config",
    responses(
        (status = 308, description = "Permanent redirect to /api/v2/upstream", headers(("Location", description = "Canonical upstream-config path"))),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    tag = "Upstream",
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
#[allow(clippy::unused_async)]
pub(crate) async fn redirect_upstream_config_get(_operator: RequireOperator) -> Response {
    redirect_upstream_config()
}

/// Documented PUT alias for `/api/v2/upstream`.
#[utoipa::path(
    put,
    path = "/api/v2/upstream/config",
    responses(
        (status = 308, description = "Permanent redirect to /api/v2/upstream", headers(("Location", description = "Canonical upstream-config path"))),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    tag = "Upstream",
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
#[allow(clippy::unused_async)]
pub(crate) async fn redirect_upstream_config_put(_operator: RequireOperator) -> Response {
    redirect_upstream_config()
}

/// Constructs the complete administrative HTTP router.
pub fn create_router(ctx: ServerContext) -> Router {
    create_router_inner(ctx, crate::config_apply::ApplyHooks::default())
}

/// Constructs the router with [`crate::config_apply::ConfigApplyHooks`] so the
/// configuration write paths can apply the components owned by the server
/// binary (DNSSEC, scoped upstreams, rate limiters, listeners, log level).
pub fn create_router_with_hooks(
    ctx: ServerContext,
    hooks: crate::config_apply::ApplyHooks,
) -> Router {
    create_router_inner(ctx, hooks)
}

fn create_router_inner(ctx: ServerContext, hooks: crate::config_apply::ApplyHooks) -> Router {
    let api_v2 = Router::new()
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
        .route("/querylog/clear", post(querylog::clear_querylog))
        .route("/querylog/stream", get(querylog::stream_querylog))
        // Filtering
        .route("/filtering/status", get(filtering::get_filtering_status))
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
        // Curated runtime lists
        .route(
            "/integrations/lists",
            get(filtering::get_integration_lists),
        )
        .route(
            "/integrations/lists/{category}/refresh",
            post(filtering::refresh_integration_list),
        )
        // Clients
        .route(
            "/clients",
            get(clients::get_clients).post(clients::create_client),
        )
        .route(
            "/clients/unidentified",
            get(clients::get_unidentified_clients),
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
        // Upstream: `/upstream` is canonical, `/upstream/config` redirects to it.
        .route(
            "/upstream",
            get(upstream::get_upstream_config).put(upstream::update_upstream_config),
        )
        .route(
            "/upstream/config",
            get(redirect_upstream_config_get).put(redirect_upstream_config_put),
        )
        .route("/upstream/test", post(upstream::test_upstream_servers))
        // Cache
        .route("/cache/flush", post(cache::flush_cache))
        .route("/cache/invalidate", post(cache::invalidate_cache))
        // High Availability (real handlers; 501 stubs in no-HA builds)
        .route("/ha/status", get(ha::get_ha_status))
        .route("/ha/slaves", get(ha::get_ha_slaves))
        .route("/ha/resync", post(ha::trigger_ha_resync))
        // Authentication
        .route("/auth/login", post(auth_handlers::login))
        .route("/auth/totp/verify", post(auth_handlers::verify_totp))
        .route("/auth/logout", post(auth_handlers::logout))
        .route("/auth/reauth", post(auth_handlers::reauth))
        .route("/auth/totp/setup", get(auth_handlers::get_totp_setup))
        .route("/auth/totp/enable", post(auth_handlers::enable_totp))
        .route("/auth/totp/disable", post(auth_handlers::disable_totp))
        .route(
            "/auth/tokens",
            get(auth_handlers::list_tokens).post(auth_handlers::create_token),
        )
        .route("/auth/tokens/{id}", delete(auth_handlers::delete_token))
        .route(
            "/auth/users",
            get(auth_handlers::list_users).post(auth_handlers::create_user),
        )
        .route(
            "/auth/users/{username}",
            put(auth_handlers::update_user).delete(auth_handlers::delete_user),
        )
        .route(
            "/auth/change-password",
            post(auth_handlers::change_password),
        )
        // Configuration
        .route(
            "/config",
            get(config::get_config).put(config::update_config),
        )
        .route("/config/reload", post(config::reload_config))
        .route(
            "/config/restart-required",
            get(config::get_restart_required),
        )
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
        .nest("/api/v2", api_v2)
        .route("/metrics", get(metrics::get_metrics))
        .route("/health", get(health_handler))
        .merge(SwaggerUi::new("/api/docs").url("/api/docs/openapi.json", ApiDoc::openapi()))
        .merge(
            crate::ui::ui_router().layer(axum::middleware::from_fn_with_state(
                ctx.clone(),
                slave_read_only_middleware,
            )),
        )
        .fallback(not_found_handler)
        .layer(axum::middleware::from_fn_with_state(
            ctx.clone(),
            setup_pending_middleware,
        ))
        .with_state(ctx.clone());

    #[cfg(not(feature = "embed-ui"))]
    let app = Router::new()
        .nest("/api/v2", api_v2)
        .route("/metrics", get(metrics::get_metrics))
        .route("/health", get(health_handler))
        .merge(SwaggerUi::new("/api/docs").url("/api/docs/openapi.json", ApiDoc::openapi()))
        .fallback(not_found_handler)
        .layer(axum::middleware::from_fn_with_state(
            ctx.clone(),
            setup_pending_middleware,
        ))
        .with_state(ctx.clone());

    app.layer(axum::Extension(hooks))
        .layer(axum::middleware::from_fn_with_state(
            ctx.clone(),
            crate::security::csrf_protection_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            ctx,
            crate::security::security_headers_middleware,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    #[cfg(feature = "ha")]
    use std::sync::Arc;

    async fn health_body(ctx: ServerContext) -> (StatusCode, serde_json::Value) {
        let response = health_handler(State(ctx)).await.into_response();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read health body");
        let body = serde_json::from_slice(&bytes).expect("health body must be JSON");
        (status, body)
    }

    #[tokio::test]
    async fn test_health_is_generic_and_opaque_when_ready() {
        let temp_dir = crate::test_support::temp_dir("sito_health_ready");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        let (status, body) = health_body(ctx).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({ "status": "ok" }));
        assert!(
            body.get("ha").is_none() && body.get("acme").is_none(),
            "/health must not expose component details: {body}"
        );
        assert!(
            body.get("setup_pending").is_none(),
            "/health must stay the generic liveness/readiness probe: {body}"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_promoted_effective_master_is_healthy() {
        let temp_dir = crate::test_support::temp_dir("sito_health_promoted_master");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        let key = std::sync::Arc::new(sito_ha::Ed25519SigningKey::generate().unwrap());
        let coordinator = sito_ha::MasterCoordinator::new(
            "promoted".to_string(),
            1,
            key,
            sito_stats::MetricsRegistry::new("2.0.0", "test"),
        );
        coordinator.mark_replication_ready();
        ctx.promoted_master_coordinator
            .lock()
            .unwrap()
            .replace(coordinator);
        ctx.ha_write_gate.mark_effective_master();
        ctx.ha_write_gate.allow();

        let (status, _) = health_body(ctx).await;
        assert_eq!(status, StatusCode::OK);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_health_not_ready_while_promotion_gate_is_blocked() {
        let temp_dir = crate::test_support::temp_dir("sito_health_promotion_gate");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        ctx.ha_write_gate.block("ha_promotion_witness_unavailable");

        let config = ctx.config.load_full();
        let readiness = ctx.ha_readiness(&config);
        assert!(!readiness.ready);
        assert_eq!(
            readiness.reason.as_deref(),
            Some("ha_promotion_witness_unavailable")
        );

        let (status, _) = health_body(ctx).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_health_unavailable_when_listeners_are_broken() {
        let temp_dir = crate::test_support::temp_dir("sito_health_listeners");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        ctx.readiness
            .set_listeners_unavailable("listener_bind_failed", "no DNS listener is bound");

        let (status, body) = health_body(ctx).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, serde_json::json!({ "status": "unavailable" }));
        assert!(
            !body.to_string().contains("listener_bind_failed"),
            "the public probe must not leak readiness reasons: {body}"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// The documented `/upstream/config` redirect alias must require the same
    /// authentication as the canonical upstream operations it points at.
    #[tokio::test]
    async fn test_upstream_config_alias_requires_operator_authentication() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let temp_dir = crate::test_support::temp_dir("sito_upstream_alias_auth");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        ctx.auth_mgr
            .update_user_password("admin", "TestPassword123!")
            .await;
        ctx.set_setup_pending(false);
        let token = ctx
            .auth_mgr
            .create_token("operator", Role::Operator, None)
            .await
            .expect("token")
            .1
            .token;
        let app = create_router(ctx);

        let unauthenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v2/upstream/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let authenticated = app
            .oneshot(
                Request::builder()
                    .uri("/api/v2/upstream/config")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            authenticated
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            "/api/v2/upstream"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// 2.0 mounts `/api/v2` as the only administrative API. `/api/v1` was
    /// removed and returns 404 with no alias or redirect; `/api/v2/status`
    /// keeps the canonical authentication behavior, and the OpenAPI document
    /// advertises only v2 paths.
    #[tokio::test]
    async fn test_api_surface_uses_only_v2_and_removes_v1() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        use utoipa::OpenApi;

        let temp_dir = crate::test_support::temp_dir("sito_api_surface_v2");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        ctx.auth_mgr
            .update_user_password("admin", "TestPassword123!")
            .await;
        ctx.set_setup_pending(false);
        let token = ctx
            .auth_mgr
            .create_token("viewer", Role::Viewer, None)
            .await
            .expect("token")
            .1
            .token;
        let app = create_router(ctx);

        for path in ["/api/v1", "/api/v1/status", "/api/v1/stats"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{path} must not be mounted"
            );
        }

        let unauthenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v2/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let authenticated = app
            .oneshot(
                Request::builder()
                    .uri("/api/v2/status")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated.status(), StatusCode::OK);

        let openapi = serde_json::to_value(ApiDoc::openapi()).expect("valid OpenAPI JSON");
        let paths = openapi["paths"].as_object().expect("paths object");
        assert!(!paths.is_empty(), "the OpenAPI document must document v2");
        assert!(
            paths.keys().all(|path| path.starts_with("/api/v2")),
            "every OpenAPI path must be under /api/v2"
        );
        assert!(
            paths.keys().all(|path| !path.starts_with("/api/v1")),
            "the OpenAPI document must not advertise the removed API v1"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[cfg(feature = "ha")]
    #[tokio::test]
    async fn test_health_unavailable_when_ha_is_broken() {
        let temp_dir = crate::test_support::temp_dir("sito_health_ha");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        let mut config = (*ctx.config.load_full()).clone();
        config.ha = Some(toml::from_str("replication_port = 8953").expect("valid ha table"));
        ctx.config.store(Arc::new(config));

        let (status, body) = health_body(ctx).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a master with a configured replication listener but no coordinator is not ready"
        );
        assert_eq!(body, serde_json::json!({ "status": "unavailable" }));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
    /// ADR-0010: a promoted slave keeps `role = "slave"` in `config.toml` but
    /// the in-memory effective role is master; the slave middleware must stop
    /// rejecting its mutations.
    #[tokio::test]
    async fn test_promoted_effective_master_is_not_slave_read_only() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let temp_dir = crate::test_support::temp_dir("sito_promoted_master");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        let mut config = (*ctx.config.load_full()).clone();
        config.server.role = "slave".to_string();
        ctx.config.store(Arc::new(config));
        ctx.auth_mgr
            .update_user_password("admin", "TestPassword123!")
            .await;
        ctx.set_setup_pending(false);
        let token = ctx
            .auth_mgr
            .create_token("operator", Role::Operator, None)
            .await
            .expect("token")
            .1
            .token;
        ctx.ha_write_gate.mark_effective_master();
        ctx.ha_write_gate.allow();
        let app = create_router(ctx);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/config/reload")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            response.status(),
            StatusCode::CONFLICT,
            "a promoted effective master must not be rejected as a replica slave"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// ADR-0010: the gate must not be bypassed through auth mutations, while
    /// login/logout/reauth remain reachable so the operator can authenticate.
    #[tokio::test]
    async fn test_promotion_gate_allowlist_blocks_auth_mutations_but_allows_login() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let temp_dir = crate::test_support::temp_dir("sito_promotion_gate_auth");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        ctx.auth_mgr
            .update_user_password("admin", "TestPassword123!")
            .await;
        ctx.set_setup_pending(false);
        let token = ctx
            .auth_mgr
            .create_token("operator", Role::Operator, None)
            .await
            .expect("token")
            .1
            .token;
        ctx.ha_write_gate.fence("ha_promotion_fenced");
        let app = create_router(ctx);

        let token_mutation = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/auth/tokens")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(token_mutation.status(), StatusCode::CONFLICT);

        let login = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/auth/login")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"username":"admin","password":"wrong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let login_status = login.status();
        let login_body = axum::body::to_bytes(login.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_ne!(
            login_status,
            StatusCode::CONFLICT,
            "login must remain reachable on a read-only node: {}",
            String::from_utf8_lossy(&login_body)
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// ADR-0010: witness-unavailable/read-only is distinct from fenced.
    #[tokio::test]
    async fn test_promotion_gate_reports_distinct_read_only_reason() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let temp_dir = crate::test_support::temp_dir("sito_promotion_gate_reason");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        ctx.auth_mgr
            .update_user_password("admin", "TestPassword123!")
            .await;
        ctx.set_setup_pending(false);
        let token = ctx
            .auth_mgr
            .create_token("operator", Role::Operator, None)
            .await
            .expect("token")
            .1
            .token;
        ctx.ha_write_gate.block("ha_promotion_witness_unavailable");
        let app = create_router(ctx);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/config/reload")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["type"], "urn:sito:ha:promotion_read_only");
        assert_eq!(problem["detail"], "ha_promotion_witness_unavailable");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// ADR-0010: an enabled promotion node is read-only until it holds the
    /// lease and has published; a fenced node returns `409` with the stable
    /// `ha_promotion_fenced` problem type for every mutating request.
    #[tokio::test]
    async fn test_promotion_gate_rejects_mutations_with_409() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let temp_dir = crate::test_support::temp_dir("sito_promotion_gate");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        ctx.auth_mgr
            .update_user_password("admin", "TestPassword123!")
            .await;
        ctx.set_setup_pending(false);
        let token = ctx
            .auth_mgr
            .create_token("operator", Role::Operator, None)
            .await
            .expect("token")
            .1
            .token;
        ctx.ha_write_gate.fence("ha_promotion_fenced");
        let app = create_router(ctx);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/config/reload")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["type"], "urn:sito:ha:promotion_fenced");
        assert_eq!(problem["detail"], "ha_promotion_fenced");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

/// A build without `sito-ha` still mounts `/api/v2/ha/*` for discoverability,
/// but every handler reports the stable `501 ha_not_supported` response behind
/// the same admin authorization as a feature-enabled build.
#[cfg(all(test, not(feature = "ha")))]
mod no_ha_tests {
    use super::*;
    use crate::auth::rbac::RequireAdmin;

    fn admin() -> RequireAdmin {
        RequireAdmin(crate::auth::AuthUser {
            username: "admin".to_string(),
            role: Role::Admin,
            token_id: None,
            owner: None,
        })
    }

    fn assert_ha_not_supported(problem: &ProblemDetails) {
        assert_eq!(problem.status, StatusCode::NOT_IMPLEMENTED.as_u16());
        assert!(
            problem.detail.contains("ha_not_supported"),
            "the response must carry the stable reason code: {problem:?}"
        );
        assert!(
            problem.detail.contains("--features ha"),
            "the response must tell the operator how to enable HA: {problem:?}"
        );
    }

    #[tokio::test]
    async fn test_ha_routes_return_501_without_ha_support() {
        let temp_dir = crate::test_support::temp_dir("sito_no_ha_routes");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let status = ha::get_ha_status(admin(), State(ctx.clone()))
            .await
            .expect_err("HA status must be unsupported without the feature");
        assert_ha_not_supported(&status);

        let slaves = ha::get_ha_slaves(admin(), State(ctx.clone()))
            .await
            .expect_err("HA slaves must be unsupported without the feature");
        assert_ha_not_supported(&slaves);

        let resync = ha::trigger_ha_resync(admin(), State(ctx.clone()))
            .await
            .expect_err("HA resync must be unsupported without the feature");
        assert_ha_not_supported(&resync);

        // The stubs are wired into the same full router as the HA build.
        let _router = create_router(ctx);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
