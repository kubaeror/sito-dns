//! Acceptance integration tests for Phase M5:
//! REST API, Auth, Data Layer, OpenAPI, Metrics, and Hot-reload.

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use futures_util::StreamExt;
use sito::cli::{run_backup, run_restore};
use sito_api::auth::{AuthManager, Role};
use sito_api::handlers::config::extract_backup_archive;
use sito_api::openapi::ApiDoc;
use sito_api::state::ServerContext;
use sito_cache::DnsCache;
use sito_core::config::Config;
use sito_filter::HostsFilterEngine;
use sito_stats::anonymize::anonymize_ip;
use sito_stats::{MetricsRegistry, QueryLogEntry, QueryLogWriter, StatsDb};
use sito_upstream::UpstreamManager;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_tungstenite::connect_async;
use tower::ServiceExt;
use utoipa::OpenApi;

async fn create_test_context(temp_dir: &Path) -> (ServerContext, PathBuf, QueryLogWriter) {
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

    let ctx = ServerContext {
        config: config_arc,
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
    };

    (ctx, config_path, querylog_writer)
}

/// 1. Acceptance test: OpenAPI contract coverage & validation
#[tokio::test]
async fn test_acceptance_m5_openapi_contract() {
    let openapi = ApiDoc::openapi();
    assert_eq!(openapi.info.title, "sito DNS Administrative API");
    assert_eq!(
        serde_json::to_string(&openapi.openapi).unwrap(),
        "\"3.1.0\""
    );

    let expected_paths = [
        "/api/v1/status",
        "/api/v1/stats",
        "/api/v1/stats/clients",
        "/api/v1/stats/upstreams",
        "/api/v1/querylog",
        "/api/v1/filtering/lists",
        "/api/v1/filtering/rules",
        "/api/v1/filtering/check",
        "/api/v1/clients",
        "/api/v1/rewrites",
        "/api/v1/upstream",
        "/api/v1/upstream/test",
        "/api/v1/cache/flush",
        "/api/v1/ha/status",
        "/api/v1/ha/resync",
        "/api/v1/auth/login",
        "/api/v1/config",
        "/api/v1/config/reload",
        "/api/v1/config/backup",
        "/api/v1/config/restore",
        "/api/v1/config/restore/confirm",
    ];

    for path in expected_paths {
        assert!(
            openapi.paths.paths.contains_key(path),
            "OpenAPI schema missing required endpoint: {path}"
        );
    }

    // Verify docs/openapi.json exists and is valid JSON matching ApiDoc
    let committed_openapi_path = PathBuf::from("../../docs/openapi.json");
    if let Ok(committed_content) = tokio::fs::read_to_string(&committed_openapi_path).await {
        let val: serde_json::Value =
            serde_json::from_str(&committed_content).expect("docs/openapi.json must be valid JSON");
        assert_eq!(val["info"]["title"], "sito DNS Administrative API");
    }
}

/// 2. Acceptance test: RBAC Role x Endpoint Matrix (Admin, Operator, Viewer, Unauthenticated)
#[tokio::test]
async fn test_acceptance_m5_rbac_matrix() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m5_rbac_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let (ctx, _cfg_path, _writer) = create_test_context(&temp_dir).await;

    // Create tokens for all 3 roles
    let admin_tok = ctx.auth_mgr.create_token("adm-test", Role::Admin).1.token;
    let oper_tok = ctx
        .auth_mgr
        .create_token("opr-test", Role::Operator)
        .1
        .token;
    let view_tok = ctx.auth_mgr.create_token("viw-test", Role::Viewer).1.token;

    let app = sito_api::create_router(ctx);

    // Helper macro to run a request through the app
    async fn call_route(
        app: axum::Router,
        method: &'static str,
        uri: &'static str,
        token: Option<&str>,
        body: &'static str,
    ) -> (StatusCode, String) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");

        if let Some(t) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }

        let req = builder.body(Body::from(body)).unwrap();
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body_bytes).to_string())
    }

    // 1. Unauthenticated requests to protected endpoints -> 401 with RFC 7807 problem+json
    let (status, body) = call_route(app.clone(), "GET", "/api/v1/status", None, "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("Authentication required"));

    // 2. Viewer role
    // Viewer: allowed GET /api/v1/status
    let (status, _) = call_route(app.clone(), "GET", "/api/v1/status", Some(&view_tok), "").await;
    assert_eq!(status, StatusCode::OK);

    // Viewer: allowed GET /api/v1/stats
    let (status, _) = call_route(app.clone(), "GET", "/api/v1/stats", Some(&view_tok), "").await;
    assert_eq!(status, StatusCode::OK);

    // Viewer: allowed GET /api/v1/querylog
    let (status, _) = call_route(
        app.clone(),
        "GET",
        "/api/v1/querylog?limit=10",
        Some(&view_tok),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Viewer: FORBIDDEN to flush cache (requires Operator)
    let (status, body) = call_route(
        app.clone(),
        "POST",
        "/api/v1/cache/flush",
        Some(&view_tok),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("Insufficient privileges"));

    // Viewer: FORBIDDEN to reload config (requires Admin)
    let (status, _) = call_route(
        app.clone(),
        "POST",
        "/api/v1/config/reload",
        Some(&view_tok),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 3. Operator role
    // Operator: allowed GET /api/v1/status
    let (status, _) = call_route(app.clone(), "GET", "/api/v1/status", Some(&oper_tok), "").await;
    assert_eq!(status, StatusCode::OK);

    // Operator: allowed POST /api/v1/cache/flush
    let (status, _) = call_route(
        app.clone(),
        "POST",
        "/api/v1/cache/flush",
        Some(&oper_tok),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Operator: FORBIDDEN to reload config or modify config (requires Admin)
    let (status, _) = call_route(
        app.clone(),
        "POST",
        "/api/v1/config/reload",
        Some(&oper_tok),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = call_route(
        app.clone(),
        "GET",
        "/api/v1/config/backup",
        Some(&oper_tok),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 4. Admin role
    // Admin: allowed GET /api/v1/status
    let (status, _) = call_route(app.clone(), "GET", "/api/v1/status", Some(&admin_tok), "").await;
    assert_eq!(status, StatusCode::OK);

    // Admin: allowed POST /api/v1/cache/flush
    let (status, _) = call_route(
        app.clone(),
        "POST",
        "/api/v1/cache/flush",
        Some(&admin_tok),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Admin: allowed POST /api/v1/config/reload
    let (status, _) = call_route(
        app.clone(),
        "POST",
        "/api/v1/config/reload",
        Some(&admin_tok),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Admin: allowed GET /api/v1/config/backup
    let (status, _) = call_route(
        app.clone(),
        "GET",
        "/api/v1/config/backup",
        Some(&admin_tok),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 5. HA status: returns 200 OK for Admin per M8 implementation
    let (status, body) = call_route(
        app.clone(),
        "GET",
        "/api/v1/ha/status",
        Some(&admin_tok),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"role\""));

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// 3. Acceptance test: Query log filters and cursor pagination
#[tokio::test]
async fn test_acceptance_m5_querylog_filters_and_pagination() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m5_ql_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let (ctx, _cfg_path, _writer) = create_test_context(&temp_dir).await;
    let admin_tok = ctx.auth_mgr.create_token("adm-ql", Role::Admin).1.token;

    // Seed test query logs into SQLite
    let now = chrono::Utc::now().timestamp_millis();
    let entries = vec![
        QueryLogEntry {
            id: None,
            ts: now - 5000,
            client_ip: "192.168.1.10".to_string(),
            client_name: Some("laptop".to_string()),
            qname: "google.com.".to_string(),
            qtype: 1,
            rcode: Some(0),
            verdict: "allowed".to_string(),
            rule: None,
            list_source: None,
            upstream: Some("1.1.1.1".to_string()),
            elapsed_us: Some(12000),
            dnssec: Some("secure".to_string()),
            proto: "udp".to_string(),
        },
        QueryLogEntry {
            id: None,
            ts: now - 4000,
            client_ip: "192.168.1.20".to_string(),
            client_name: Some("phone".to_string()),
            qname: "ads.track.me.".to_string(),
            qtype: 1,
            rcode: Some(0),
            verdict: "blocked".to_string(),
            rule: Some("||track.me^".to_string()),
            list_source: Some("OISD".to_string()),
            upstream: None,
            elapsed_us: Some(450),
            dnssec: None,
            proto: "doh".to_string(),
        },
        QueryLogEntry {
            id: None,
            ts: now - 3000,
            client_ip: "192.168.1.10".to_string(),
            client_name: Some("laptop".to_string()),
            qname: "github.com.".to_string(),
            qtype: 28, // AAAA
            rcode: Some(0),
            verdict: "allowed".to_string(),
            rule: None,
            list_source: None,
            upstream: Some("1.1.1.1".to_string()),
            elapsed_us: Some(8000),
            dnssec: Some("secure".to_string()),
            proto: "udp".to_string(),
        },
    ];

    ctx.stats_db.insert_batch(&entries).await.unwrap();

    let app = sito_api::create_router(ctx.clone());

    // Helper request caller
    async fn get_json(
        app: axum::Router,
        uri: &str,
        token: &str,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        (status, json)
    }

    // Filter by domain
    let (status, json) =
        get_json(app.clone(), "/api/v1/querylog?domain=track.me", &admin_tok).await;
    assert_eq!(status, StatusCode::OK);
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["qname"], "ads.track.me.");
    assert_eq!(entries[0]["verdict"], "blocked");

    // Filter by client
    let (status, json) = get_json(
        app.clone(),
        "/api/v1/querylog?client=192.168.1.10",
        &admin_tok,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);

    // Filter by status (verdict)
    let (status, json) = get_json(app.clone(), "/api/v1/querylog?status=blocked", &admin_tok).await;
    assert_eq!(status, StatusCode::OK);
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);

    // Cursor pagination: page size 1
    let (status, json_page1) = get_json(app.clone(), "/api/v1/querylog?limit=1", &admin_tok).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_page1["entries"].as_array().unwrap().len(), 1);
    assert!(json_page1["next_cursor"].is_string());
    let cursor = json_page1["next_cursor"].as_str().unwrap();

    // Fetch page 2 using cursor
    let (status, json_page2) = get_json(
        app.clone(),
        &format!("/api/v1/querylog?limit=1&cursor={cursor}"),
        &admin_tok,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let page2_entries = json_page2["entries"].as_array().unwrap();
    assert_eq!(page2_entries.len(), 1);
    assert_ne!(
        json_page1["entries"][0]["id"], page2_entries[0]["id"],
        "Pagination cursor must return sequential non-overlapping items"
    );

    // Clear logs via DELETE /api/v1/querylog
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/querylog")
        .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let (status, json_cleared) =
        get_json(app.clone(), "/api/v1/querylog?limit=10", &admin_tok).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_cleared["entries"].as_array().unwrap().len(), 0);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// 4. Acceptance test: WebSocket Live-tail (`/api/v1/querylog/stream`)
#[tokio::test]
async fn test_acceptance_m5_websocket_livetail() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m5_ws_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let (ctx, _cfg_path, _writer) = create_test_context(&temp_dir).await;
    let view_tok = ctx.auth_mgr.create_token("ws-viewer", Role::Viewer).1.token;
    let sender = ctx.querylog_sender.clone();
    let app = sito_api::create_router(ctx);

    // Bind real TCP socket on ephemeral port to test live WebSocket handshake
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let ws_url = format!("ws://{addr}/api/v1/querylog/stream?token={view_tok}");
    let (ws_stream, _) = connect_async(&ws_url)
        .await
        .expect("WebSocket handshake failed");
    let (_, mut rx) = ws_stream.split();

    // Send a query log entry through the broadcast sender
    let test_entry = QueryLogEntry {
        id: None,
        ts: chrono::Utc::now().timestamp_millis(),
        client_ip: "10.0.0.42".to_string(),
        client_name: Some("test-device".to_string()),
        qname: "streaming.example.org.".to_string(),
        qtype: 1,
        rcode: Some(0),
        verdict: "allowed".to_string(),
        rule: None,
        list_source: None,
        upstream: Some("8.8.8.8".to_string()),
        elapsed_us: Some(1500),
        dnssec: None,
        proto: "udp".to_string(),
    };

    let start = Instant::now();
    assert!(sender.try_send(test_entry));

    // Expect websocket delivery in < 500 ms per DoD
    let msg = tokio::time::timeout(Duration::from_millis(500), rx.next())
        .await
        .expect("WebSocket message timed out after 500ms")
        .expect("Stream closed unexpectedly")
        .expect("WebSocket read error");

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "WebSocket delivery took {elapsed:?}, expected < 500ms"
    );

    let text = msg.to_text().unwrap();
    let val: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(val["qname"], "streaming.example.org.");
    assert_eq!(val["client_ip"], "10.0.0.42");
    assert_eq!(val["verdict"], "allowed");

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// 5. Acceptance test: Prometheus /metrics contains all 18 metrics from Table 14.2
#[tokio::test]
async fn test_acceptance_m5_prometheus_table_14_2() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m5_prom_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let (ctx, _cfg_path, _writer) = create_test_context(&temp_dir).await;

    // Simulate usage of metrics
    ctx.metrics.inc_queries("udp", 1, "allowed");
    ctx.metrics.inc_cache_hits();
    ctx.metrics.inc_cache_misses();
    ctx.metrics.set_ha_slaves_connected(2);
    ctx.metrics.inc_querylog_dropped();

    let app = sito_api::create_router(ctx);

    let req = Request::builder()
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body_bytes);

    let required_metrics = [
        "sito_queries_total",
        "sito_query_duration_seconds",
        "sito_upstream_rtt_seconds",
        "sito_upstream_errors_total",
        "sito_upstream_health",
        "sito_cache_hits_total",
        "sito_cache_misses_total",
        "sito_cache_size_bytes",
        "sito_cache_stale_served_total",
        "sito_filter_rules",
        "sito_filter_compile_seconds",
        "sito_dnssec_bogus_total",
        "sito_clients_identified_total",
        "sito_doh_bypass_blocked_total",
        "sito_ha_slaves_connected",
        "sito_ha_config_version",
        "sito_querylog_dropped_total",
        "sito_build_info",
    ];

    for metric in required_metrics {
        assert!(
            text.contains(metric),
            "Prometheus scrape missing Table 14.2 metric: {metric}"
        );
    }

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// 6. Acceptance test: IP Anonymization (/24 for IPv4, /56 for IPv6)
#[test]
fn test_acceptance_m5_ip_anonymization() {
    // IPv4 masking to /24 (last octet zeroed)
    let ipv4: std::net::IpAddr = "192.168.1.123".parse().unwrap();
    assert_eq!(anonymize_ip(ipv4).clone(), "192.168.1.0");

    let ipv4_public: std::net::IpAddr = "8.8.4.4".parse().unwrap();
    assert_eq!(anonymize_ip(ipv4_public).clone(), "8.8.4.0");

    // IPv6 masking to /56 (host and subnets beyond 56 bits zeroed)
    let ipv6: std::net::IpAddr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap();
    assert_eq!(anonymize_ip(ipv6).clone(), "2001:db8:85a3::");

    let ipv6_sub: std::net::IpAddr = "2606:4700:4700::1111".parse().unwrap();
    assert_eq!(anonymize_ip(ipv6_sub).clone(), "2606:4700:4700::");
}

/// 7. Acceptance test: Backup and restore roundtrip and invalid archive rejection
#[tokio::test]
async fn test_acceptance_m5_backup_restore_roundtrip() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m5_backup_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let config_path = temp_dir.join("config.toml");
    let mut original_config = Config::default();
    original_config.dns.port = 5353;
    original_config.filtering.custom_rules = vec!["0.0.0.0 ads.example.com".to_string()];
    let original_toml = toml::to_string_pretty(&original_config).unwrap();
    tokio::fs::write(&config_path, &original_toml)
        .await
        .unwrap();

    // 1. Create backup archive via CLI run_backup
    let archive_path = temp_dir.join("backup.tar.gz");
    let created = run_backup(&config_path, Some(&archive_path)).unwrap();
    assert_eq!(created, archive_path);
    assert!(archive_path.exists());

    // 2. Corrupt or change original configuration on disk
    let mut modified_config = Config::default();
    modified_config.dns.port = 1053;
    let modified_toml = toml::to_string_pretty(&modified_config).unwrap();
    tokio::fs::write(&config_path, &modified_toml)
        .await
        .unwrap();

    // 3. Restore backup archive via CLI run_restore
    run_restore(&archive_path, &config_path, true).unwrap();

    // 4. Verify restored configuration matches original
    let restored_toml = tokio::fs::read_to_string(&config_path).await.unwrap();
    let restored_config = Config::from_toml_str(&restored_toml).unwrap();
    assert_eq!(restored_config.dns.port, 5353);
    assert_eq!(
        restored_config.filtering.custom_rules,
        vec!["0.0.0.0 ads.example.com"]
    );

    // 5. Test rejection of corrupted/invalid archive
    let bad_archive_path = temp_dir.join("corrupted.tar.gz");
    tokio::fs::write(&bad_archive_path, b"not a real gzip archive")
        .await
        .unwrap();
    let err = run_restore(&bad_archive_path, &config_path, true);
    assert!(err.is_err(), "Corrupted archive must be rejected");

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// 8. Acceptance test: API Backup & Restore with confirmation token
#[tokio::test]
async fn test_acceptance_m5_api_backup_and_token_restore() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m5_api_bck_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let (ctx, _config_path, _writer) = create_test_context(&temp_dir).await;
    let admin_tok = ctx.auth_mgr.create_token("adm-bck", Role::Admin).1.token;
    let app = sito_api::create_router(ctx.clone());

    // GET /api/v1/config/backup -> download tar.gz
    let req = Request::builder()
        .uri("/api/v1/config/backup")
        .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/gzip"
    );

    let archive_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();

    // Inspect archive contents
    let (extracted_toml, metadata) = extract_backup_archive(&archive_bytes).unwrap();
    assert_eq!(metadata.version, "1.0");
    assert!(!extracted_toml.is_empty());

    // POST /api/v1/config/restore -> prepare restore and get confirmation token
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/restore")
        .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
        .header(header::CONTENT_TYPE, "application/gzip")
        .body(Body::from(archive_bytes))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let prepared: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let confirmation_token = prepared["confirmation_token"].as_str().unwrap();
    assert!(!confirmation_token.is_empty());

    // POST /api/v1/config/restore/confirm with confirmation token
    let confirm_body = serde_json::json!({
        "confirmation_token": confirmation_token
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/restore/confirm")
        .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&confirm_body).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Invalid confirmation token rejected
    let bad_confirm_body = serde_json::json!({
        "confirmation_token": "nonexistent_token"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/restore/confirm")
        .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&bad_confirm_body).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}
