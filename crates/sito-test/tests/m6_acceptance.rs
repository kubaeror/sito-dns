//! Acceptance tests for Phase M6: Web Panel & Embedded UI.

#![allow(clippy::pedantic)]
#![cfg(feature = "embed-ui")]

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use sito_api::auth::AuthManager;
use sito_api::router::create_router;
use sito_api::state::ServerContext;
use sito_cache::DnsCache;
use sito_core::config::Config;
use sito_filter::HostsFilterEngine;
use sito_stats::{MetricsRegistry, QueryLogWriter, StatsDb};
use sito_upstream::UpstreamManager;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower::ServiceExt;

/// Non-default password used by router tests so the bootstrap-admin gate does
/// not close the login path the tests are exercising.
const TEST_ADMIN_PASSWORD: &str = "TestAdminPassword123!";

async fn create_test_context() -> (ServerContext, PathBuf) {
    let temp_dir = std::env::temp_dir().join(format!("sito_m6_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let db_path = temp_dir.join("test_stats.db");
    let stats_db = StatsDb::open(&db_path).await.unwrap();
    let querylog_writer = QueryLogWriter::spawn(stats_db.clone(), 100);
    let querylog_sender = querylog_writer.sender();
    let metrics = MetricsRegistry::new("0.1.0", "test-commit");

    let config_path = temp_dir.join("config.toml");
    let mut config = Config::default();
    config.server.data_dir = temp_dir.clone();
    // Self-contained filtering source: the wizard and background refresh must
    // never depend on a network blocklist (`big.oisd.nl`) in tests.
    let local_list = temp_dir.join("local-list.txt");
    tokio::fs::write(&local_list, "||ads.example^\n||tracker.example^\n")
        .await
        .unwrap();
    config.filtering.lists = vec![sito_core::config::FilterListConfig {
        name: "Local".to_string(),
        url: format!("file://{}", local_list.display()),
        enabled: true,
        refresh_hours: None,
    }];
    let config_toml = toml::to_string_pretty(&config).unwrap();
    tokio::fs::write(&config_path, &config_toml).await.unwrap();

    let config_arc = Arc::new(ArcSwap::new(Arc::new(config.clone())));
    let cache = Arc::new(DnsCache::new(config.dns.cache.clone()));
    let filter =
        Arc::new(HostsFilterEngine::init(config.filtering.clone(), temp_dir.clone()).await);
    let bootstrap = sito_upstream::BootstrapResolver::new(
        vec!["127.0.0.1".parse().unwrap()],
        Duration::from_secs(1),
    );
    let upstream = Arc::new(
        UpstreamManager::from_config(&config.upstream, &bootstrap)
            .await
            .unwrap(),
    );
    let clients = Arc::new(ArcSwap::new(Arc::new(sito_clients::ClientRegistry::new(
        Default::default(),
    ))));
    let rewrites = Arc::new(ArcSwap::new(Arc::new(sito_rewrites::RewriteTable::new(
        Default::default(),
    ))));
    let auth_mgr = Arc::new(AuthManager::new());
    // Router tests run against a configured deployment, not the bootstrap
    // state: use a non-default password so the setup gate stays out of the way.
    auth_mgr
        .update_user_password("admin", TEST_ADMIN_PASSWORD)
        .await;

    let runtime = Arc::new(sito_runtime::RuntimeState::new(
        config_arc.clone(),
        clients.clone(),
        rewrites.clone(),
    ));
    let runtime_lists = Arc::new(sito_clients::RuntimeLists::from_arcs(
        Arc::new(
            sito_clients::ParentalRegistry::try_bundled()
                .expect("bundled parental lists must load"),
        ),
        Arc::new(sito_clients::ServiceRegistry::try_bundled().expect("bundled services must load")),
    ));
    let ctx = ServerContext {
        config: config_arc,
        runtime,
        runtime_lists,
        config_path,
        auth_mgr,
        stats_db,
        querylog_sender,
        metrics,
        filter,
        cache,
        upstream,
        clients,
        rewrites,
        start_time: Instant::now(),
        restore_tokens: Arc::new(Mutex::new(HashMap::new())),
        apply_lock: Arc::new(tokio::sync::Mutex::new(())),
        master_coordinator: None,
        slave_tracker: None,
        resync_sender: None,
        setup_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        acme_challenges: None,
        dns_starter: None,
    };

    (ctx, temp_dir)
}

#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_embedded_ui_serves_root_and_index() {
    let (ctx, temp_dir) = create_test_context().await;
    let app = create_router(ctx.clone());

    // Unauthenticated GET / redirects to /login with 303 See Other
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
        "/login"
    );

    // GET /login returns 200 OK HTML
    let app2 = create_router(ctx);
    let req2 = Request::builder()
        .uri("/login")
        .body(Body::empty())
        .unwrap();
    let resp2 = app2.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let ct = resp2
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/html"));

    let body = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("sito DNS"));

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_embedded_ui_spa_routing_fallback() {
    let (ctx, temp_dir) = create_test_context().await;

    // Login with the configured admin credentials to obtain a real session cookie
    let login_res = ctx
        .auth_mgr
        .login("admin", TEST_ADMIN_PASSWORD, "127.0.0.1")
        .await;
    let cookie_val = match login_res {
        sito_api::auth::LoginResult::Success(session) => session.to_cookie_header(),
        other => panic!("expected login success, got {other:?}"),
    };

    for ui_path in ["/dashboard", "/querylog", "/filtering", "/wizard", "/login"] {
        let app = create_router(ctx.clone());
        let req = Request::builder()
            .uri(ui_path)
            .header(header::COOKIE, &cookie_val)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        // /login when authenticated redirects to /dashboard; the bootstrap
        // wizard is closed after setup; other pages return 200 OK.
        if ui_path == "/login" {
            assert_eq!(resp.status(), StatusCode::SEE_OTHER, "Failed for {ui_path}");
        } else if ui_path == "/wizard" {
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "the wizard must be bootstrap-only after setup"
            );
        } else {
            assert_eq!(resp.status(), StatusCode::OK, "Failed for {ui_path}");
            let ct = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap();
            assert!(ct.contains("text/html"));

            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let body_str = String::from_utf8_lossy(&body);
            assert!(body_str.contains("sito"));
        }
    }

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_embedded_ui_missing_asset_returns_404() {
    let (ctx, temp_dir) = create_test_context().await;
    let app = create_router(ctx);

    let req = Request::builder()
        .uri("/assets/missing-file.js")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_embedded_ui_api_route_not_found_returns_problem_details() {
    let (ctx, temp_dir) = create_test_context().await;
    let app = create_router(ctx);

    let req = Request::builder()
        .uri("/api/v1/nonexistent-endpoint")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], 404);
    assert_eq!(json["detail"], "The requested endpoint does not exist");

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_wizard_gate_forbidden_after_setup() {
    let (mut ctx, temp_dir) = create_test_context().await;
    // Simulate the genuine first-run bootstrap regardless of the configured
    // password used by the router test helper.
    ctx.auth_mgr = Arc::new(AuthManager::new());

    // 1. In first-run, unauthenticated POST /ui/wizard/complete succeeds.
    //    `filtering_enabled=on` keeps the seeded local `file://` list instead
    //    of pulling the OISD default, so the test never touches the network.
    let app = create_router(ctx.clone());
    let form_body =
        "admin_user=admin&admin_password=newpassword123&upstream=1.1.1.1&filtering_enabled=on";
    let req = Request::builder()
        .method("POST")
        .uri("/ui/wizard/complete")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // The wizard persisted the self-contained local list and the background
    // refresh compiled it (no synchronous download in the request).
    let persisted = tokio::fs::read_to_string(&ctx.config_path).await.unwrap();
    assert!(
        persisted.contains("file://"),
        "wizard must preserve the seeded local list: {persisted}"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if ctx.filter.rule_count() >= 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "background filter refresh did not compile the local list in time"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 2. After setup is complete, unauthenticated POST /ui/wizard/complete is rejected with 403
    let app2 = create_router(ctx.clone());
    let req2 = Request::builder()
        .method("POST")
        .uri("/ui/wizard/complete")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(
            "admin_user=admin&admin_password=hacked123&upstream=8.8.8.8",
        ))
        .unwrap();

    let resp2 = app2.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::FORBIDDEN);

    // 3. The wizard surface itself is bootstrap-only after setup
    let app3 = create_router(ctx.clone());
    let req3 = Request::builder()
        .uri("/wizard")
        .body(Body::empty())
        .unwrap();
    let resp3 = app3.oneshot(req3).await.unwrap();
    assert_eq!(
        resp3.status(),
        StatusCode::FORBIDDEN,
        "the wizard must not be reachable after setup"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_setup_pending_route_gating_and_wizard_flow() {
    let (mut ctx, temp_dir) = create_test_context().await;
    // Missing config plus the bootstrap admin is the canonical first-run state.
    ctx.auth_mgr = Arc::new(AuthManager::new());
    ctx.set_setup_pending(true);

    let app = create_router(ctx.clone());

    // 1. UI routes redirect to /wizard (302 Found)
    for path in [
        "/",
        "/login",
        "/dashboard",
        "/settings",
        "/querylog",
        "/filtering",
    ] {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FOUND,
            "Path {path} should return 302 FOUND"
        );
        assert_eq!(
            resp.headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
            "/wizard",
            "Path {path} should redirect to /wizard"
        );
    }

    // 2. API v1 endpoints return 503 Service Unavailable with "Setup not completed"
    for path in [
        "/api/v1/status",
        "/api/v1/config",
        "/api/v1/clients",
        "/api/v1/rewrites",
    ] {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "API path {path} should return 503"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "Setup not completed");
    }

    // 3. Allowed endpoints: /wizard, /ui/upstreams/test
    let req = Request::builder()
        .uri("/wizard")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let test_upstream_req = Request::builder()
        .method("POST")
        .uri("/ui/upstreams/test")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("address=1.1.1.1"))
        .unwrap();
    let resp = app.clone().oneshot(test_upstream_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 4. Complete setup wizard via POST /ui/wizard/complete
    let complete_req = Request::builder()
        .method("POST")
        .uri("/ui/wizard/complete")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(
            "admin_user=setupadmin&admin_password=Setuppassword123!&confirm_password=Setuppassword123!&bind_ipv4=on&port=5353&upstreams=1.1.1.1"
        ))
        .unwrap();
    let resp = app.clone().oneshot(complete_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
        "/login"
    );

    // 5. Setup pending is now flipped to false
    assert!(!ctx.is_setup_pending());

    // 6. UI routes no longer redirect to /wizard
    let req = Request::builder()
        .uri("/login")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 7. API v1 endpoints no longer return 503
    let req = Request::builder()
        .uri("/api/v1/status")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[cfg(feature = "embed-ui")]
fn cookie_value(response: &axum::http::Response<Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|cookie| {
            cookie
                .split(';')
                .next()
                .and_then(|pair| pair.strip_prefix(&format!("{name}=")))
                .map(str::to_string)
        })
}

/// WP-4.4: the double-submit CSRF cookie is enforced for session-authenticated
/// mutations instead of being written and ignored.
#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_csrf_cookie_enforced_for_session_mutations() {
    let (ctx, temp_dir) = create_test_context().await;
    let app = create_router(ctx.clone());

    let login = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header(header::HOST, "localhost")
        .header(header::ORIGIN, "http://localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({"user": "admin", "pass": TEST_ADMIN_PASSWORD}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(login).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let session = cookie_value(&resp, "sito_session").expect("session cookie");
    let csrf = cookie_value(&resp, "sito_csrf").expect("csrf cookie");

    // Session cookie + matching header token but no CSRF cookie: rejected.
    // (Before WP-4.4 the cookie was written but never validated, so this
    // request succeeded.)
    let missing_csrf = Request::builder()
        .method("POST")
        .uri("/api/v1/cache/flush")
        .header(header::HOST, "localhost")
        .header(header::ORIGIN, "http://localhost")
        .header(header::COOKIE, format!("sito_session={session}"))
        .header("x-csrf-token", &csrf)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(missing_csrf).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Cookie + matching header token: accepted.
    let valid = Request::builder()
        .method("POST")
        .uri("/api/v1/cache/flush")
        .header(header::HOST, "localhost")
        .header(header::ORIGIN, "http://localhost")
        .header(
            header::COOKIE,
            format!("sito_session={session}; sito_csrf={csrf}"),
        )
        .header("x-csrf-token", &csrf)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(valid).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// WP-4.4: when `users.toml` exists but `config.toml` is missing the
/// deployment must not force the wizard over an authenticated login, and the
/// wizard must not be an unauthenticated admin-password reset.
#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_setup_pending_with_existing_users_requires_admin() {
    let (mut ctx, temp_dir) = create_test_context().await;
    {
        // Simulate a first boot that created users.toml, then a restart with
        // `config.toml` missing: the manager must load the configured users
        // and consider setup complete (no first-boot token).
        let seed = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        assert!(
            seed.update_user_password("admin", "ConfiguredPassword1")
                .await
        );
    }
    let mgr = Arc::new(AuthManager::with_storage(&temp_dir, 24, 5).unwrap());
    assert!(!mgr.is_first_run());
    assert!(!mgr.setup_token_required());
    ctx.auth_mgr = mgr;
    ctx.set_setup_pending(true);

    let app = create_router(ctx.clone());

    // Login page is reachable instead of being redirected to the wizard.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Unauthenticated wizard completion is rejected.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/wizard/complete")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "admin_user=admin&admin_password=HackedPassword1",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // The configured credentials still work.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::HOST, "localhost")
                .header(header::ORIGIN, "http://localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"user":"admin","pass":"ConfiguredPassword1"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // DNS listeners stay gated while no configuration exists.
    assert!(ctx.is_setup_pending());

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Regression (1.9.2): `config.toml` existing was treated as "setup done" even
/// while `users.toml` still contained the bootstrap `admin/adminadmin`. The
/// setup token was active, but `setup_pending` was false, so the middleware
/// let the default password log in over the network.
#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_default_admin_with_existing_config_is_gated_by_setup_token() {
    let (mut ctx, temp_dir) = create_test_context().await;
    ctx.auth_mgr = Arc::new(AuthManager::with_storage(&temp_dir, 24, 5).unwrap());
    ctx.set_setup_pending(false);

    assert!(ctx.auth_mgr.setup_token_required());
    assert!(ctx.auth_mgr.is_default_admin_active());
    let token = ctx.auth_mgr.setup_token().expect("setup token provisioned");
    let app = create_router(ctx.clone());

    // 1. The bootstrap password must not authenticate while the token is active.
    let login = |user: &'static str, pass: String| {
        let app = app.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "http://localhost")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"user": user, "pass": pass}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    let resp = login("admin", "adminadmin".to_string()).await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "default admin login must be blocked while setup is pending"
    );
    assert!(
        cookie_value(&resp, "sito_session").is_none(),
        "no session may be issued for the bootstrap password"
    );

    // 2. Every non-wizard API is setup-gated.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    // 3. The wizard itself still requires the token.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/wizard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/wizard?setup_token={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a valid setup token opens the wizard"
    );

    // 4. An authenticated Admin may always reach the wizard.
    let sito_api::auth::LoginResult::Success(admin_session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("direct admin login failed");
    };
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/wizard")
                .header(header::COOKIE, admin_session.to_cookie_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. Completing the wizard with a strong password consumes the token and
    // rotates the bootstrap credential.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/wizard/complete")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "setup_token={token}&admin_user=admin&admin_password=Recovered-Password-1!&confirm_password=Recovered-Password-1!"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(!ctx.auth_mgr.setup_token_required());
    assert!(!ctx.auth_mgr.is_default_admin_active());

    let resp = login("admin", "adminadmin".to_string()).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = login("admin", "Recovered-Password-1!".to_string()).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Regression (1.9.2 review): a restart with a custom-named Admin and no
/// literal `admin` account must not re-enter setup-token mode or lock out
/// login, the wizard (for Admins) or the API.
#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_custom_admin_restart_does_not_reengage_setup_gate() {
    let (mut ctx, temp_dir) = create_test_context().await;
    {
        let seed = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        seed.create_user("owner", "OwnerPassword123!", sito_api::auth::Role::Admin)
            .await;
        seed.delete_user_checked("admin")
            .await
            .expect("delete bootstrap admin");
    }

    let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    assert!(!mgr.has_user("admin"));
    assert!(!mgr.setup_token_required());
    assert!(!mgr.is_first_run());
    ctx.auth_mgr = Arc::new(mgr);
    let app = create_router(ctx.clone());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::HOST, "localhost")
                .header(header::ORIGIN, "http://localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"user": "owner", "pass": "OwnerPassword123!"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "custom Admin must log in after restart"
    );
    let session = cookie_value(&resp, "sito_session").expect("session cookie");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/wizard")
                .header(header::COOKIE, format!("sito_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "the bootstrap wizard must stay closed after setup, even for an Admin"
    );

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .header(header::COOKIE, format!("sito_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a configured custom-admin deployment must not stay API-gated"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Regression (1.9.2 review): a users file with no usable Admin must keep the
/// token-protected wizard reachable so the deployment can be recovered without
/// shell access.
#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_setup_token_wizard_works_without_any_admin_account() {
    let (mut ctx, temp_dir) = create_test_context().await;
    {
        let seed = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        seed.create_user("viewer", "ViewerPassword123!", sito_api::auth::Role::Viewer)
            .await;
        assert!(
            seed.delete_user("admin").await,
            "remove the bootstrap admin"
        );
    }

    let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    assert!(mgr.setup_token_required());
    assert!(!mgr.is_first_run());
    let token = mgr.setup_token().expect("setup token provisioned");
    ctx.auth_mgr = Arc::new(mgr);
    ctx.set_setup_pending(false);
    let app = create_router(ctx.clone());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/wizard?setup_token={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "token holder must reach the wizard even without an Admin account"
    );

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/wizard/complete")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "setup_token={token}&admin_user=admin&admin_password=RecoveredPassword123!&confirm_password=RecoveredPassword123!"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(!ctx.auth_mgr.setup_token_required());
    assert!(ctx.auth_mgr.has_user("admin"));
    assert!(ctx.auth_mgr.has_user("viewer"));
    assert!(matches!(
        ctx.auth_mgr
            .login("admin", "RecoveredPassword123!", "127.0.0.1")
            .await,
        sito_api::auth::LoginResult::Success(_)
    ));

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Regression (1.9.2): the documented recovery path must restore remote login
/// with the new password and leave no active setup token behind.
#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_reset_admin_custom_password_restores_login() {
    let (mut ctx, temp_dir) = create_test_context().await;
    {
        let _ = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    }
    AuthManager::reset_admin_credentials(&temp_dir, "RecoveredPassword123!").unwrap();

    let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    assert!(!mgr.setup_token_required());
    assert!(!mgr.is_default_admin_active());
    ctx.auth_mgr = Arc::new(mgr);
    let app = create_router(ctx.clone());

    let login = |pass: &'static str| {
        let app = app.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "http://localhost")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"user": "admin", "pass": pass}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    let resp = login("adminadmin").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = login("RecoveredPassword123!").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// WP-4.5: authenticated API surfaces must not be cacheable and must vary on
/// the caller's cookie.
#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_sensitive_responses_have_no_store_and_vary_cookie() {
    let (ctx, temp_dir) = create_test_context().await;
    let app = create_router(ctx);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/clients")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        resp.headers()
            .get(header::VARY)
            .and_then(|v| v.to_str().ok()),
        Some("Cookie")
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}
