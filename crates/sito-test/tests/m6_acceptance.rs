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

    let ctx = ServerContext {
        config: config_arc,
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
        master_coordinator: None,
        slave_tracker: None,
        resync_sender: None,
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

    // Login with default admin credentials to obtain real session cookie
    let login_res = ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1");
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
        // /login when authenticated redirects to /dashboard, other pages return 200 OK
        if ui_path == "/login" {
            assert_eq!(resp.status(), StatusCode::SEE_OTHER, "Failed for {ui_path}");
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
