//! Acceptance integration tests for the Audit-4 API security hardening
//! (WP-3 setup tokens, WP-4 CSRF/headers, WP-5 auth, WP-12 data integrity).

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use sito_api::auth::{AuthManager, Role};
use sito_api::state::ServerContext;
use sito_cache::DnsCache;
use sito_core::config::Config;
use sito_filter::HostsFilterEngine;
use sito_stats::{MetricsRegistry, QueryLogWriter, StatsDb};
use sito_upstream::UpstreamManager;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower::ServiceExt;

async fn create_test_context(temp_dir: &Path, setup_pending: bool) -> ServerContext {
    let db_path = temp_dir.join("test_stats.db");
    let stats_db = StatsDb::open(&db_path).await.unwrap();
    let querylog_writer = QueryLogWriter::spawn(stats_db.clone(), 1000);
    let querylog_sender = querylog_writer.sender();
    let metrics = MetricsRegistry::new("0.1.0", "test-commit");

    let config_path = temp_dir.join("config.toml");
    let mut config = Config::default();
    config.server.data_dir = temp_dir.to_path_buf();
    let config_toml = toml::to_string_pretty(&config).unwrap();
    tokio::fs::write(&config_path, &config_toml).await.unwrap();

    let config_arc = Arc::new(ArcSwap::new(Arc::new(config.clone())));
    let cache = Arc::new(DnsCache::new(config.dns.cache.clone()));
    let filter =
        Arc::new(HostsFilterEngine::init(config.filtering.clone(), temp_dir.to_path_buf()).await);
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

    let runtime = Arc::new(sito_runtime::RuntimeState::new(
        config_arc.clone(),
        clients.clone(),
        rewrites.clone(),
    ));
    let runtime_lists = Arc::new(sito_clients::RuntimeLists::from_arcs(
        Arc::new(sito_clients::ParentalRegistry::bundled()),
        Arc::new(sito_clients::ServiceRegistry::bundled()),
    ));
    ServerContext {
        config: config_arc,
        runtime,
        runtime_lists,
        config_path: config_path.clone(),
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
        master_coordinator: None,
        slave_tracker: None,
        resync_sender: None,
        setup_pending: Arc::new(std::sync::atomic::AtomicBool::new(setup_pending)),
        dns_starter: None,
    }
}

fn cookie_from_response(res: &axum::http::Response<Body>, name: &str) -> Option<String> {
    for value in &res.headers().get_all(header::SET_COOKIE) {
        let raw = value.to_str().ok()?;
        for part in raw.split(';') {
            let trimmed = part.trim();
            if let Some(v) = trimmed.strip_prefix(&format!("{name}="))
                && !v.is_empty()
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

async fn body_string(res: axum::http::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

/// WP-4: session-cookie mutations require a matching CSRF token and a strict
/// Origin; `Origin: null` is always rejected.
#[tokio::test]
async fn test_acceptance_m10_csrf_and_origin_enforcement() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m10_csrf_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let ctx = create_test_context(&temp_dir, false).await;
    let app = sito_api::create_router(ctx.clone());

    // Log in over the API to obtain a real session + CSRF cookie pair.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({"user": "admin", "pass": "adminadmin"}).to_string(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let session_id = cookie_from_response(&res, "sito_session").expect("session cookie");
    let csrf_token = cookie_from_response(&res, "sito_csrf").expect("csrf cookie");

    // 1. Session-cookie POST without Origin/CSRF -> 403.
    let req = Request::builder()
        .method("POST")
        .uri("/ui/logout")
        .header(header::HOST, "localhost")
        .header(
            header::COOKIE,
            format!("sito_session={session_id}; sito_csrf={csrf_token}"),
        )
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // 2. Origin: null -> 403.
    let req = Request::builder()
        .method("POST")
        .uri("/ui/logout")
        .header(header::HOST, "localhost")
        .header(header::ORIGIN, "null")
        .header(
            header::COOKIE,
            format!("sito_session={session_id}; sito_csrf={csrf_token}"),
        )
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("csrf_token={csrf_token}")))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // 3. Session-cookie POST with wrong CSRF token -> 403.
    let req = Request::builder()
        .method("POST")
        .uri("/ui/logout")
        .header(header::HOST, "localhost")
        .header(header::ORIGIN, "http://localhost")
        .header(
            header::COOKIE,
            format!("sito_session={session_id}; sito_csrf={csrf_token}"),
        )
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("csrf_token=deadbeef"))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // 4. Same-origin + matching CSRF token -> the mutation goes through. Use
    // an API route so this holds with and without the optional `embed-ui`
    // feature (the `/ui/*` routes are feature-gated).
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/cache/flush")
        .header(header::HOST, "localhost")
        .header(header::ORIGIN, "http://localhost")
        .header(
            header::COOKIE,
            format!("sito_session={session_id}; sito_csrf={csrf_token}"),
        )
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("csrf_token={csrf_token}")))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 5. Bearer-token mutation is exempt from the double submit.
    let admin_tok = ctx.auth_mgr.create_token("csrf-test", Role::Admin).1.token;
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/cache/flush")
        .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// WP-4: login sets HttpOnly/SameSite=Strict cookies, `no-store`, and the
/// hardened header set (no `unsafe-inline` in script-src).
#[tokio::test]
async fn test_acceptance_m10_security_headers_and_cookies() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m10_hdr_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let ctx = create_test_context(&temp_dir, false).await;
    let app = sito_api::create_router(ctx);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({"user": "admin", "pass": "adminadmin"}).to_string(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let cookies: Vec<String> = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(ToString::to_string))
        .collect();
    assert!(
        cookies.iter().any(|c| c.contains("HttpOnly")
            && c.contains("SameSite=Strict")
            && c.starts_with("sito_session=")),
        "session cookie flags missing: {cookies:?}"
    );
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("sito_csrf=") && !c.contains("HttpOnly")),
        "CSRF cookie missing or wrongly HttpOnly: {cookies:?}"
    );

    assert_eq!(
        res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        res.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(res.headers().get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(res.headers().get("x-frame-options").unwrap(), "DENY");
    let csp = res
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        csp.contains("script-src 'self' 'unsafe-eval'"),
        "csp: {csp}"
    );
    assert!(
        !csp.contains("script-src 'self' 'unsafe-inline'"),
        "script-src must not allow unsafe-inline: {csp}"
    );
    assert!(csp.contains("frame-ancestors 'none'"), "csp: {csp}");
    // HSTS is only emitted for genuine TLS (no ConnectInfo here -> absent).
    assert!(
        res.headers()
            .get(header::STRICT_TRANSPORT_SECURITY)
            .is_none()
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// WP-3: while setup is pending, wizard/probe routes require the one-time
/// setup token; failures are rate limited and completion consumes it.
#[cfg(feature = "embed-ui")]
#[tokio::test]
async fn test_acceptance_m10_setup_token_gate() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m10_setup_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let mut ctx = create_test_context(&temp_dir, true).await;
    // Use a persisted manager so a first-boot setup token is provisioned.
    ctx.auth_mgr = Arc::new(AuthManager::with_storage(&temp_dir, 24, 5).unwrap());
    assert!(ctx.auth_mgr.setup_token_required());
    let token = ctx.auth_mgr.setup_token().expect("setup token");
    let app = sito_api::create_router(ctx.clone());

    // 1. /wizard without a token -> 403.
    let req = Request::builder()
        .uri("/wizard")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // 2. /wizard with the token in the query -> 200.
    let req = Request::builder()
        .uri(format!("/wizard?setup_token={token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_string(res).await;
    assert!(html.contains("One-time setup token required"));

    // 3. Wizard completion without the token is rejected by the handler.
    let req = Request::builder()
        .method("POST")
        .uri("/ui/wizard/complete")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(
            "admin_user=admin&admin_password=Str0ngPassword%21",
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // 4. /ui/upstreams/test without auth or token -> 403 (middleware).
    let req = Request::builder()
        .method("POST")
        .uri("/ui/upstreams/test")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("address=1.1.1.1"))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // 5. Repeated bad tokens are rate limited (429).
    let mut saw_rate_limited = false;
    for _ in 0..20 {
        let req = Request::builder()
            .uri("/wizard?setup_token=wrong-token")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        if res.status() == StatusCode::TOO_MANY_REQUESTS {
            saw_rate_limited = true;
            break;
        }
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }
    assert!(
        saw_rate_limited,
        "setup token failures must be rate limited"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// WP-12/24: metrics accept a real bearer token, and deprecated query tokens
/// do not authenticate non-WebSocket endpoints.
#[tokio::test]
async fn test_acceptance_m10_metrics_token_auth() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m10_metrics_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let ctx = create_test_context(&temp_dir, false).await;
    let app = sito_api::create_router(ctx.clone());

    // Default config requires authentication.
    let req = Request::builder()
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Query token is not accepted outside WebSocket upgrades.
    let tok = ctx.auth_mgr.create_token("metrics", Role::Viewer).1.token;
    let req = Request::builder()
        .uri(format!("/metrics?token={tok}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Real bearer token works.
    let req = Request::builder()
        .uri("/metrics")
        .header(header::AUTHORIZATION, format!("Bearer {tok}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// WP-12: restore previews mask secrets (tokens, arrays and inline tables).
#[tokio::test]
async fn test_acceptance_m10_restore_preview_is_masked() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m10_mask_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let ctx = create_test_context(&temp_dir, false).await;
    let app = sito_api::create_router(ctx.clone());
    let admin_tok = ctx.auth_mgr.create_token("mask", Role::Admin).1.token;

    let secret_toml = r#"
[server]
slave_token = "supersecret-token-value"

[tls]
key = "private-key-material"
cert = "public-cert.pem"

[web]
headers = { api_token = "inline-secret-token", accept = "text/html" }
"#;
    let archive = sito_api::handlers::config::create_backup_archive(secret_toml).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/restore")
        .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
        .header(header::CONTENT_TYPE, "application/gzip")
        .body(Body::from(archive))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_string(res).await;
    assert!(
        !body.contains("supersecret-token-value"),
        "slave token leaked: {body}"
    );
    assert!(
        !body.contains("private-key-material"),
        "private key leaked: {body}"
    );
    assert!(
        !body.contains("inline-secret-token"),
        "inline table secret leaked: {body}"
    );
    assert!(
        body.contains("\"***\"") || body.contains("***"),
        "no mask marker in {body}"
    );
    assert!(
        body.contains("public-cert.pem"),
        "non-secret value over-masked"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}
