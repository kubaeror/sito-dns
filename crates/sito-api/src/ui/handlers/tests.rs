#![cfg(test)]

use super::*;
use arc_swap::ArcSwap;
use axum::extract::State;
use axum::http::header::COOKIE;
use axum::http::{HeaderMap, StatusCode};
use sito_core::config::Config;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

#[test]
fn test_update_install_form_carries_csrf_token_and_uses_htmx() {
    let info = crate::updater::UpdateInfo {
        current_version: "1.9.1".to_string(),
        latest_version: "1.9.2".to_string(),
        update_available: true,
        release_url: "https://github.com/kubaeror/sito-dns/releases/tag/v1.9.2".to_string(),
        release_notes: "notes".to_string(),
        published_at: None,
        is_docker: false,
        is_systemd: false,
        in_app_update_disabled: false,
        instructions: None,
        version_comparison_unknown: false,
    };
    let html = update_action_html(&info, "csrf-token-123");
    assert!(
        html.contains(r#"name="csrf_token" value="csrf-token-123""#),
        "update form must carry the session CSRF token: {html}"
    );
    assert!(
        html.contains(r#"hx-post="/ui/system/update/apply""#),
        "update form must remain an htmx post: {html}"
    );
    assert!(
        !html.contains("this.form.submit()"),
        "native form submission bypasses htmx and would omit the CSRF header: {html}"
    );
    // A submit button disabled during its click handler returns from the
    // activation behavior without firing the form's submit event, so htmx
    // must own the disabled state after the event has started.
    assert!(
        html.contains(r#"hx-disabled-elt="button""#),
        "htmx must disable the button after submit: {html}"
    );
    assert!(
        !html.contains("this.disabled"),
        "the click handler must not disable the submit button before htmx sees submit: {html}"
    );

    let docker = crate::updater::UpdateInfo {
        is_docker: true,
        in_app_update_disabled: true,
        ..info.clone()
    };
    let docker_html = update_action_html(&docker, "csrf-token-123");
    assert!(!docker_html.contains("<form"), "{docker_html}");
    assert!(docker_html.contains("docker compose pull"), "{docker_html}");

    let unknown = crate::updater::UpdateInfo {
        version_comparison_unknown: true,
        update_available: false,
        ..info.clone()
    };
    let unknown_html = update_check_html(&unknown, "csrf-token-123");
    assert!(
        !unknown_html.to_ascii_lowercase().contains("up to date"),
        "unknown comparison must not render an up-to-date badge: {unknown_html}"
    );
    assert!(unknown_html.contains("Version comparison unknown"));
    assert!(unknown_html.contains("--force"));

    let systemd = crate::updater::UpdateInfo {
        is_systemd: true,
        in_app_update_disabled: true,
        ..info
    };
    let systemd_html = update_action_html(&systemd, "csrf-token-123");
    assert!(!systemd_html.contains("<form"), "{systemd_html}");
    assert!(
        systemd_html.contains("systemctl stop sito"),
        "{systemd_html}"
    );
    assert!(systemd_html.contains("sito update"), "{systemd_html}");
}

async fn mock_context(temp_dir: &std::path::Path) -> ServerContext {
    let db_path = temp_dir.join("test.db");
    let stats_db = sito_stats::StatsDb::open(&db_path).await.unwrap();
    let querylog_writer = sito_stats::QueryLogWriter::spawn(stats_db.clone(), 100);
    let querylog_sender = querylog_writer.sender();
    let metrics = sito_stats::MetricsRegistry::new("1.2.1", "test");
    let auth_mgr = Arc::new(crate::auth::AuthManager::new());
    // Filtering is disabled: `Config::default()` has no sources and an
    // enabled-with-zero-sources engine now fails closed.
    let mut config = Config::default();
    config.filtering.enabled = false;
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config.clone())));
    let filter = Arc::new(
        sito_filter::HostsFilterEngine::init(config.filtering, temp_dir.to_path_buf()).await,
    );
    let cache = Arc::new(sito_cache::DnsCache::new(Default::default()));
    let bootstrap = sito_upstream::BootstrapResolver::new(
        vec!["127.0.0.1".parse().unwrap()],
        std::time::Duration::from_secs(1),
    );
    let upstream = Arc::new(
        sito_upstream::UpstreamManager::from_config(&Default::default(), &bootstrap)
            .await
            .unwrap(),
    );
    let clients = Arc::new(ArcSwap::new(Arc::new(sito_clients::ClientRegistry::new(
        Default::default(),
    ))));
    let rewrites = Arc::new(ArcSwap::new(Arc::new(sito_rewrites::RewriteTable::new(
        Default::default(),
    ))));

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

    ServerContext {
        config: config_arc,
        runtime,
        runtime_lists,
        config_path: temp_dir.join("config.toml"),
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
        readiness: Arc::new(crate::readiness::ReadinessState::default()),
        cert_validity_cache: Arc::new(sito_transport::CertificateValidityCache::new()),
        acme_challenges: None,
        dns_starter: None,
    }
}

#[test]
fn test_bundled_list_views_corrupt_manifest_returns_runtime_rows_without_panic() {
    let corrupt = serde_json::from_str::<sito_clients::BundledManifest>("{ not json")
        .expect_err("fixture must be invalid JSON");
    let statuses = vec![sito_clients::RuntimeListStatus {
        category: "adult".to_string(),
        source_url: Some("https://lists.example/adult.txt".to_string()),
        last_refresh_unix: Some(1_700_000_000),
        last_attempt_unix: Some(1_700_000_100),
        last_error: Some("previous fetch failed".to_string()),
        entries: 42,
        bundled: false,
    }];

    let views = bundled_list_views(Err(corrupt), &statuses, true);
    assert_eq!(
        views.len(),
        1,
        "runtime rows must survive a corrupt manifest"
    );
    assert_eq!(views[0].id, "adult");
    assert_eq!(views[0].kind, "custom");
    assert_eq!(views[0].entries, 42);
    assert_eq!(views[0].state, "runtime refresh");
    assert!(views[0].last_refresh.contains("2023-11-14"));
    assert!(views[0].last_attempt.contains("2023-11-14"));
    assert_eq!(
        views[0].last_error.as_deref(),
        Some("previous fetch failed"),
        "the UI must surface the recorded refresh error"
    );

    // The healthy path still merges bundled metadata with runtime status.
    let manifest =
        sito_clients::BundledManifest::try_bundled().expect("bundled manifest must parse");
    let views = bundled_list_views(Ok(manifest), &[], true);
    assert!(views.iter().any(|view| view.id == "adult"));
    assert!(
        views.iter().all(|view| view.kind != "custom"),
        "a healthy manifest must not invent custom rows"
    );
}

/// P1-23: the live 3 s paths must stay cheap. The query-log route always reads
/// a bounded page (there is no total count on the read path at all), and the
/// dashboard route serves the cached aggregate instead of rescanning on every
/// poll.
#[tokio::test]
async fn test_live_routes_skip_query_log_total_and_use_cached_dashboard() {
    use axum::body::to_bytes;

    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_live_paths_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("live_admin", "pass", Role::Admin)
        .await;
    let LoginResult::Success(session) = ctx.auth_mgr.login("live_admin", "pass", "127.0.0.1").await
    else {
        panic!("login failed");
    };
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, session.to_cookie_header().parse().unwrap());

    // The route's live filter is the first page only: no cursor, bounded size.
    let filter = live_query_log_filter(&QueryLogParams::default());
    assert_eq!(
        filter.limit,
        Some(50),
        "the live query-log refresh must stay a bounded page"
    );
    assert!(
        filter.cursor.is_none(),
        "the live refresh must not carry a pagination cursor"
    );

    let now = chrono::Utc::now().timestamp_millis();
    let entry = sito_stats::QueryLogEntry::new(
        now,
        "192.0.2.50",
        None,
        "dashboard-cache.example",
        1,
        Some(0),
        "allowed",
        "udp",
    );
    ctx.stats_db.insert_batch(&[entry]).await.unwrap();

    let first = dashboard_stats_partial(State(ctx.clone()), headers.clone()).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = to_bytes(first.into_body(), usize::MAX).await.unwrap();
    assert!(
        String::from_utf8_lossy(&first_body).contains(">1</div>"),
        "the first dashboard render must show the current aggregate"
    );

    // A write inside the TTL must not be observed: the route used the cached
    // accessor rather than rescanning query_log.
    let second_entry = sito_stats::QueryLogEntry::new(
        now + 1,
        "192.0.2.50",
        None,
        "dashboard-cache.example",
        1,
        Some(0),
        "allowed",
        "udp",
    );
    ctx.stats_db.insert_batch(&[second_entry]).await.unwrap();
    let second = dashboard_stats_partial(State(ctx.clone()), headers).await;
    assert_eq!(second.status(), StatusCode::OK);
    let second_body = to_bytes(second.into_body(), usize::MAX).await.unwrap();
    let second_body = String::from_utf8_lossy(&second_body);
    assert!(
        second_body.contains(">1</div>"),
        "the dashboard must serve the cached aggregate within the TTL"
    );
    assert!(
        !second_body.contains(">2</div>"),
        "the dashboard route must not bypass the cached accessor"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// A5: the UI cursor is opt-in. Filter/refresh requests never send one, so they
/// reset pagination to the newest page instead of continuing a history walk.
#[test]
fn test_querylog_cursor_is_opt_in_and_cleared_for_live_requests() {
    let history = QueryLogParams {
        cursor: Some("opaque-cursor".to_string()),
        ..Default::default()
    };
    let filter = query_log_filter(&history);
    assert_eq!(filter.cursor.as_deref(), Some("opaque-cursor"));
    assert_eq!(filter.limit, Some(50));
    assert!(
        live_query_log_filter(&history).cursor.is_none(),
        "the live refresh filter must never carry a history cursor"
    );

    // A filter change or refresh sends no cursor (or an empty field); either
    // way the page starts again at the newest row.
    for cursor in [None, Some(String::new())] {
        let params = QueryLogParams {
            cursor,
            ..Default::default()
        };
        assert!(
            query_log_filter(&params).cursor.is_none(),
            "filter changes and refreshes must clear the cursor"
        );
    }
}

/// A5: following the cursor returns older rows and keeps row keys disjoint, so
/// appended pages cannot duplicate a previously loaded row.
#[tokio::test]
async fn test_querylog_history_pages_append_without_duplicate_keys() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_querylog_history_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let base = 1_700_000_000_000;
    let entries: Vec<_> = (0..60)
        .map(|index| {
            sito_stats::QueryLogEntry::new(
                base + index,
                "192.0.2.60",
                None,
                format!("history-{index}.example"),
                1,
                Some(5),
                "allowed",
                "udp",
            )
        })
        .collect();
    ctx.stats_db.insert_batch(&entries).await.unwrap();

    let first = fetch_query_rows(&ctx, &QueryLogParams::default()).await;
    assert_eq!(first.entries.len(), 50, "the first page stays bounded");
    let cursor = first
        .next_cursor
        .clone()
        .expect("60 rows need a second page");

    let second = fetch_query_rows(
        &ctx,
        &QueryLogParams {
            cursor: Some(cursor),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(second.entries.len(), 10, "only the older rows remain");
    assert!(
        second.next_cursor.is_none(),
        "the last page must exhaust the cursor"
    );

    let first_keys: std::collections::HashSet<&str> = first
        .entries
        .iter()
        .map(|row| row.row_key.as_str())
        .collect();
    assert!(
        second
            .entries
            .iter()
            .all(|row| !first_keys.contains(row.row_key.as_str())),
        "an appended page must not repeat a row key from the page above"
    );
    let newest_ts = first.entries.iter().map(|row| row.ts).min().unwrap();
    assert!(
        second.entries.iter().all(|row| row.ts < newest_ts),
        "continued pages must contain older rows only"
    );
    assert!(
        second
            .entries
            .iter()
            .any(|row| row.qname == "history-0.example"),
        "the oldest row must be reachable through the cursor"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// A5: the page/partial handlers pass `next_cursor` to the templates; the
/// partial marks an explicit history request and returns OOB controls.
#[tokio::test]
async fn test_querylog_ui_templates_receive_cursor_and_history_mode() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_querylog_markup_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("query_user", "pass", Role::Operator)
        .await;
    let LoginResult::Success(session) = ctx.auth_mgr.login("query_user", "pass", "127.0.0.1").await
    else {
        panic!("login failed");
    };
    let headers = session_headers(&session);

    let base = 1_700_000_000_000;
    let entries: Vec<_> = (0..120)
        .map(|index| {
            sito_stats::QueryLogEntry::new(
                base + index,
                "192.0.2.61",
                None,
                format!("markup-{index}.example"),
                1,
                Some(5),
                "allowed",
                "udp",
            )
        })
        .collect();
    ctx.stats_db.insert_batch(&entries).await.unwrap();

    // A full page load starts live and offers Load older when a cursor exists.
    let page = querylog_page(
        State(ctx.clone()),
        headers.clone(),
        Query(QueryLogParams::default()),
    )
    .await;
    assert_eq!(page.status(), StatusCode::OK);
    let page_html = response_body(page).await;
    assert!(
        page_html.contains("data-querylog-load-older"),
        "{page_html}"
    );
    assert!(
        page_html.contains("data-history-mode=\"false\""),
        "a full page load starts in live mode: {page_html}"
    );
    assert!(
        !page_html.contains("hx-swap-oob=\"true\""),
        "the full page must not mark its controls as an OOB swap"
    );

    let first = fetch_query_rows(&ctx, &QueryLogParams::default()).await;
    let cursor = first
        .next_cursor
        .clone()
        .expect("120 rows need a second page");

    // A full page load must ignore a stale cursor and show the live page.
    let stale = querylog_page(
        State(ctx.clone()),
        headers.clone(),
        Query(QueryLogParams {
            cursor: Some(cursor.clone()),
            ..Default::default()
        }),
    )
    .await;
    let stale_html = response_body(stale).await;
    assert!(
        stale_html.contains("markup-119.example")
            && stale_html.contains("data-history-mode=\"false\""),
        "a full page load must always start live at the newest page: {stale_html}"
    );

    // Following the cursor is history mode: pause polling, keep the new cursor.
    let history = querylog_rows_partial(
        State(ctx.clone()),
        headers.clone(),
        Query(QueryLogParams {
            cursor: Some(cursor),
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(history.status(), StatusCode::OK);
    let history_html = response_body(history).await;
    assert!(
        history_html.contains("hx-swap-oob=\"true\""),
        "history responses update the controls out of band: {history_html}"
    );
    assert!(
        history_html.contains("data-history-mode=\"true\""),
        "history mode must pause the live poll: {history_html}"
    );
    assert!(
        history_html.contains("data-querylog-back-live"),
        "history mode needs a Back to live control: {history_html}"
    );
    assert!(
        history_html.contains("data-querylog-load-older"),
        "a middle page keeps offering Load older: {history_html}"
    );
    assert!(
        !history_html.contains("markup-119.example"),
        "history pages must not repeat the newest page: {history_html}"
    );
    assert!(
        history_html.contains("markup-69.example") && history_html.contains("markup-20.example"),
        "the second page must contain the rows below the first page: {history_html}"
    );

    // A cursor-less request is a filter/refresh: live mode again, newest page.
    let live = querylog_rows_partial(
        State(ctx.clone()),
        headers,
        Query(QueryLogParams::default()),
    )
    .await;
    let live_html = response_body(live).await;
    assert!(
        live_html.contains("data-history-mode=\"false\""),
        "filter changes and refreshes must return to live mode: {live_html}"
    );
    assert!(
        !live_html.contains("data-querylog-back-live"),
        "live mode must not show Back to live: {live_html}"
    );
    assert!(
        live_html.contains("markup-119.example"),
        "the newest page must be restored after a filter change: {live_html}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_ui_rbac_checks() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_rbac_test_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let ctx = mock_context(&temp_dir).await;

    // 1. filtering_simulate_handler rejects unauthenticated
    let resp = filtering_simulate_handler(
        State(ctx.clone()),
        HeaderMap::new(),
        Form(SimulateForm {
            domain: "example.com".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Create Viewer and Operator users
    ctx.auth_mgr
        .create_user("view_user", "pass", Role::Viewer)
        .await;
    ctx.auth_mgr
        .create_user("oper_user", "pass", Role::Operator)
        .await;

    let LoginResult::Success(view_session) =
        ctx.auth_mgr.login("view_user", "pass", "127.0.0.1").await
    else {
        panic!("login failed");
    };
    let LoginResult::Success(oper_session) =
        ctx.auth_mgr.login("oper_user", "pass", "127.0.0.1").await
    else {
        panic!("login failed");
    };

    let mut view_headers = HeaderMap::new();
    view_headers.insert(COOKIE, view_session.to_cookie_header().parse().unwrap());

    let mut oper_headers = HeaderMap::new();
    oper_headers.insert(COOKIE, oper_session.to_cookie_header().parse().unwrap());

    // 2. filtering_simulate_handler succeeds with authenticated Viewer
    let resp = filtering_simulate_handler(
        State(ctx.clone()),
        view_headers.clone(),
        Form(SimulateForm {
            domain: "example.com".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. rewrites_add_handler forbidden for Viewer
    let resp = rewrites_add_handler(
        State(ctx.clone()),
        view_headers.clone(),
        Form(AddRewriteForm {
            domain: "test.lan".to_string(),
            record_type: "A".to_string(),
            answer: "1.2.3.4".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 4. rewrites_add_handler allowed for Operator (redirects to /rewrites)
    let resp = rewrites_add_handler(
        State(ctx.clone()),
        oper_headers.clone(),
        Form(AddRewriteForm {
            domain: "test.lan".to_string(),
            record_type: "A".to_string(),
            answer: "1.2.3.4".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // 5. settings_save_handler forbidden for Operator (requires Admin)
    let resp = settings_save_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        oper_headers.clone(),
        Form(SaveSettingsForm {
            cache_size_mb: 64,
            min_ttl: 60,
            dnssec: None,
            rate_limit: 10,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_ui_rewrite_add_rejects_invalid_entry_without_persisting() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_rewrite_validation_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("oper_user", "pass", Role::Operator)
        .await;
    let LoginResult::Success(session) = ctx.auth_mgr.login("oper_user", "pass", "127.0.0.1").await
    else {
        panic!("login failed");
    };
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, session.to_cookie_header().parse().unwrap());

    let resp = rewrites_add_handler(
        State(ctx.clone()),
        headers.clone(),
        Form(AddRewriteForm {
            domain: "bad..name".to_string(),
            record_type: "A".to_string(),
            answer: "10.0.0.1".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        crate::handlers::rewrites::load_rewrite_store(&ctx)
            .cfg
            .entries,
        Vec::new(),
        "an invalid UI rewrite add must not persist an entry"
    );
    assert!(
        ctx.config.load().rewrites.is_none(),
        "an invalid UI rewrite add must not write configuration"
    );

    // A valid entry still goes through the same gate.
    let resp = rewrites_add_handler(
        State(ctx.clone()),
        headers,
        Form(AddRewriteForm {
            domain: "printer.lan".to_string(),
            record_type: "A".to_string(),
            answer: "10.0.0.1".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        crate::handlers::rewrites::load_rewrite_store(&ctx)
            .cfg
            .entries
            .len(),
        1
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_wizard_validation_and_user_creation() {
    let temp_dir = std::env::temp_dir().join(format!("sito_ui_wiz_test_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    assert!(ctx.auth_mgr.is_first_run());

    // 1. Wrong username (empty) -> 400 Bad Request, first_run stays true
    let empty_user_form = WizardCompleteForm {
        admin_user: Some(String::new()),
        admin_password: Some("ValidPassword123!".to_string()),
        upstream: Some("1.1.1.1:53".to_string()),
        ..Default::default()
    };
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(empty_user_form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(ctx.auth_mgr.is_first_run());

    // 2. Wrong username (whitespace) -> 400 Bad Request, first_run stays true
    let space_user_form = WizardCompleteForm {
        admin_user: Some("admin user".to_string()),
        admin_password: Some("ValidPassword123!".to_string()),
        upstream: Some("1.1.1.1:53".to_string()),
        ..Default::default()
    };
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(space_user_form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(ctx.auth_mgr.is_first_run());

    // 3. Short password -> 400 Bad Request, first_run stays true
    let short_pass_form = WizardCompleteForm {
        admin_user: Some("admin".to_string()),
        admin_password: Some("short".to_string()),
        upstream: Some("1.1.1.1:53".to_string()),
        ..Default::default()
    };
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(short_pass_form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(ctx.auth_mgr.is_first_run());

    // 4. Nonexistent user -> created as admin, first_run becomes false, default admin purged
    let nonexistent_user_form = WizardCompleteForm {
        admin_user: Some("superadmin".to_string()),
        admin_password: Some("SuperSecretPassword123!".to_string()),
        upstream: Some("1.1.1.1:53".to_string()),
        enable_adblock: Some("on".to_string()),
        ..Default::default()
    };
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(nonexistent_user_form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(!ctx.auth_mgr.is_first_run());
    assert!(ctx.auth_mgr.has_user("superadmin"));
    assert!(!ctx.auth_mgr.has_user("admin"));

    // Login as new admin succeeds
    let login_res = ctx
        .auth_mgr
        .login("superadmin", "SuperSecretPassword123!", "127.0.0.1")
        .await;
    assert!(matches!(login_res, crate::auth::LoginResult::Success(_)));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_wizard_rejects_empty_and_default_password() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_wiz_defaults_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    // Empty password must not complete setup with bootstrap credentials.
    let empty_form = WizardCompleteForm::default();
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(empty_form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(ctx.auth_mgr.is_first_run());
    assert!(!ctx.auth_mgr.has_user("admin") || ctx.auth_mgr.is_default_admin_active());

    // The literal default password is rejected as well.
    let default_pass_form = WizardCompleteForm {
        admin_user: Some("admin".to_string()),
        admin_password: Some("adminadmin".to_string()),
        ..Default::default()
    };
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(default_pass_form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(ctx.auth_mgr.is_first_run());

    // Wizard-rejected attempts must not have modified the config.
    let cfg = ctx.config.load();
    assert_eq!(cfg.dns.port, 53);
    assert_eq!(cfg.dns.dot_port, 853);
    assert_eq!(cfg.dns.doq_port, 0);
    assert_eq!(
        cfg.dns.bind,
        vec![
            IpAddr::from_str("0.0.0.0").unwrap(),
            IpAddr::from_str("::").unwrap()
        ]
    );
    assert_eq!(cfg.get_web_config().port, 8080);
    assert_eq!(cfg.get_stats_config().retention_days, 90);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_wizard_password_mismatch() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_wiz_mismatch_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let mismatch_form = WizardCompleteForm {
        admin_user: Some("admin".to_string()),
        admin_password: Some("Password123!".to_string()),
        confirm_password: Some("Mismatch123!".to_string()),
        ..Default::default()
    };
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(mismatch_form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_wizard_rejects_existing_non_admin_target() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_wiz_nonadmin_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    ctx.auth_mgr
        .create_user("bob", "BobPassword123!", Role::Viewer)
        .await;
    assert!(ctx.auth_mgr.is_default_admin_active());

    let form = WizardCompleteForm {
        admin_user: Some("bob".to_string()),
        admin_password: Some("NewBobPassword123!".to_string()),
        upstream: Some("1.1.1.1:53".to_string()),
        ..Default::default()
    };
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(ctx.auth_mgr.role_of("bob"), Some(Role::Viewer));
    assert!(ctx.auth_mgr.is_default_admin_active());
    assert!(ctx.auth_mgr.is_first_run());
    // The rejected target's password must not have changed either.
    assert!(
        ctx.auth_mgr
            .verify_user_password("bob", "BobPassword123!")
            .await
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// Ordering regression: the configuration file must not be written when
/// the administrator password cannot be persisted.
#[cfg(unix)]
#[tokio::test]
async fn test_wizard_password_persist_failure_does_not_persist_config() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_wiz_pwfail_{}", rand::random::<u64>()));
    let auth_dir = temp_dir.join("auth");
    let _ = std::fs::create_dir_all(&auth_dir);
    let mut ctx = mock_context(&temp_dir).await;
    ctx.auth_mgr = Arc::new(crate::auth::AuthManager::with_storage(&auth_dir, 24, 5).unwrap());
    ctx.set_setup_pending(true);
    let token = ctx.auth_mgr.setup_token().expect("setup token provisioned");
    let config_path = ctx.config_path.clone();
    assert!(!config_path.exists());

    // Make the account store unwritable while the configuration directory
    // stays writable: a pre-fix wizard would persist config first.
    std::fs::set_permissions(&auth_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    let form = WizardCompleteForm {
        setup_token: Some(token),
        admin_user: Some("admin".to_string()),
        admin_password: Some("StrongPassword123!".to_string()),
        upstream: Some("1.1.1.1:53".to_string()),
        ..Default::default()
    };
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(form),
    )
    .await;
    assert_ne!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        !config_path.exists(),
        "config must not be persisted before the admin password is persisted"
    );
    assert!(ctx.is_setup_pending());
    assert!(ctx.auth_mgr.setup_token_required());
    assert!(ctx.auth_mgr.is_first_run());

    std::fs::set_permissions(&auth_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// Regression (1.9.2 review): concurrent completions are serialized, so a
/// request that re-reads the token state after another completion cannot
/// skip token validation and overwrite the new password.
#[tokio::test]
async fn test_concurrent_wizard_completion_only_one_succeeds() {
    let temp_dir = std::env::temp_dir().join(format!("sito_ui_wiz_race_{}", rand::random::<u64>()));
    let auth_dir = temp_dir.join("auth");
    let _ = std::fs::create_dir_all(&auth_dir);
    let mut ctx = mock_context(&temp_dir).await;
    ctx.auth_mgr = Arc::new(crate::auth::AuthManager::with_storage(&auth_dir, 24, 5).unwrap());
    let token = ctx.auth_mgr.setup_token().expect("setup token provisioned");
    let form = || WizardCompleteForm {
        setup_token: Some(token.clone()),
        admin_user: Some("admin".to_string()),
        admin_password: Some("RacedPassword123!".to_string()),
        confirm_password: Some("RacedPassword123!".to_string()),
        upstream: Some("1.1.1.1:53".to_string()),
        ..Default::default()
    };

    let first = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(form()),
    );
    let second = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(form()),
    );
    let (first, second) = tokio::join!(first, second);
    let statuses = [first.status(), second.status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::SEE_OTHER)
            .count(),
        1,
        "exactly one completion may win: {statuses:?}"
    );
    assert!(
        statuses.iter().all(|status| !status.is_success()),
        "no completion may report a body success: {statuses:?}"
    );
    assert!(!ctx.auth_mgr.setup_token_required());
    assert!(ctx.auth_mgr.has_user("admin"));
    assert!(matches!(
        ctx.auth_mgr
            .login("admin", "RacedPassword123!", "127.0.0.1")
            .await,
        crate::auth::LoginResult::Success(_)
    ));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// Regression (1.9.2 review): a failed write while deleting the bootstrap
/// `admin` must not be reported as a successful setup.
#[tokio::test]
async fn test_wizard_bootstrap_delete_persist_failure_keeps_setup_pending() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_wiz_delfail_{}", rand::random::<u64>()));
    let auth_dir = temp_dir.join("auth");
    let _ = std::fs::create_dir_all(&auth_dir);
    let mut ctx = mock_context(&temp_dir).await;
    ctx.auth_mgr = Arc::new(crate::auth::AuthManager::with_storage(&auth_dir, 24, 5).unwrap());
    ctx.set_setup_pending(true);
    let token = ctx.auth_mgr.setup_token().expect("setup token provisioned");
    ctx.auth_mgr
        .create_user("owner", "OwnerPassword123!", Role::Admin)
        .await;

    // The credential update write succeeds; the following delete write
    // fails.
    crate::auth::manager::SECRET_WRITE_FAIL_AFTER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((auth_dir.join("users.toml"), 1));

    let form = WizardCompleteForm {
        setup_token: Some(token),
        admin_user: Some("owner".to_string()),
        admin_password: Some("NewOwnerPassword123!".to_string()),
        confirm_password: Some("NewOwnerPassword123!".to_string()),
        upstream: Some("1.1.1.1:53".to_string()),
        ..Default::default()
    };
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(ctx.is_setup_pending());
    assert!(ctx.auth_mgr.setup_token_required());
    assert!(ctx.auth_mgr.has_user("admin"));
    assert!(ctx.auth_mgr.has_user("owner"));
    assert!(ctx.auth_mgr.is_default_admin_active());
    assert!(ctx.auth_mgr.is_first_run());
    assert!(
        ctx.auth_mgr
            .verify_user_password("owner", "OwnerPassword123!")
            .await,
        "the credential change must be rolled back"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// A configuration persistence failure must restore the previous admin
/// password so setup stays pending with the bootstrap credential.
#[cfg(unix)]
#[tokio::test]
async fn test_wizard_config_persist_failure_rolls_back_admin_password() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_wiz_cfgfail_{}", rand::random::<u64>()));
    let readonly = temp_dir.join("readonly");
    let _ = std::fs::create_dir_all(&readonly);
    let mut ctx = mock_context(&temp_dir).await;
    ctx.set_setup_pending(true);
    ctx.config_path = readonly.join("config.toml");
    std::fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o555)).unwrap();

    let form = WizardCompleteForm {
        admin_user: Some("admin".to_string()),
        admin_password: Some("StrongPassword123!".to_string()),
        upstream: Some("1.1.1.1:53".to_string()),
        ..Default::default()
    };
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(form),
    )
    .await;
    assert_ne!(resp.status(), StatusCode::SEE_OTHER);
    assert!(ctx.is_setup_pending());
    assert!(ctx.auth_mgr.is_first_run());
    assert!(ctx.auth_mgr.is_default_admin_active());
    assert!(
        ctx.auth_mgr
            .verify_user_password("admin", "adminadmin")
            .await,
        "the bootstrap password must be restored after the config persist failure"
    );
    assert!(
        !ctx.auth_mgr
            .verify_user_password("admin", "StrongPassword123!")
            .await
    );

    std::fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o755)).unwrap();
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_wizard_custom_config_and_presets() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_wiz_custom_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let custom_form = WizardCompleteForm {
        setup_token: None,
        reauth_token: None,
        admin_user: Some("customadmin".to_string()),
        admin_password: Some("custompassword123".to_string()),
        confirm_password: Some("custompassword123".to_string()),
        bind_ipv4: Some("on".to_string()),
        bind_ipv6: None,
        port: Some("5353".to_string()),
        dot_port: Some("8853".to_string()),
        doh_port: Some("8443".to_string()),
        doq_port: Some("0".to_string()),
        upstreams: Some("9.9.9.9\n149.112.112.112".to_string()),
        upstream: None,
        upstream_strategy: Some("parallel".to_string()),
        bootstrap: Some("1.1.1.1, 8.8.8.8".to_string()),
        timeout_ms: Some("3000".to_string()),
        cache_enabled_present: Some("1".to_string()),
        cache_enabled: Some("on".to_string()),
        cache_size_mb: Some("128".to_string()),
        dnssec_mode: Some("strict".to_string()),
        dnssec_validate_present: Some("1".to_string()),
        dnssec_validate: Some("on".to_string()),
        filtering_enabled_present: Some("1".to_string()),
        filtering_enabled: Some("on".to_string()),
        enable_adblock: None,
        blocking_mode: Some("nxdomain".to_string()),
        cname_cloaking_present: Some("1".to_string()),
        cname_cloaking: Some("on".to_string()),
        list_oisd_big: Some("on".to_string()),
        list_oisd_small: None,
        list_stevenblack: None,
        list_hagezi: Some("on".to_string()),
        web_bind: Some("127.0.0.1".to_string()),
        web_port: Some("9090".to_string()),
        retention_days: Some("30".to_string()),
    };

    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(custom_form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let cfg = ctx.config.load();
    assert_eq!(cfg.dns.port, 5353);
    assert_eq!(cfg.dns.dot_port, 8853);
    assert_eq!(cfg.dns.doh_port, 8443);
    assert_eq!(cfg.dns.bind, vec![IpAddr::from_str("0.0.0.0").unwrap()]);
    assert_eq!(cfg.upstream.servers, vec!["9.9.9.9", "149.112.112.112"]);
    assert_eq!(cfg.upstream.strategy, UpstreamStrategy::Parallel);
    assert_eq!(
        cfg.upstream.bootstrap,
        vec![
            IpAddr::from_str("1.1.1.1").unwrap(),
            IpAddr::from_str("8.8.8.8").unwrap()
        ]
    );
    assert_eq!(cfg.upstream.timeout_ms, 3000);
    assert_eq!(cfg.dns.cache.size_mb, 128);
    assert_eq!(cfg.dns.dnssec.mode, "strict");
    assert!(cfg.dns.dnssec.validate);
    assert_eq!(cfg.filtering.blocking_mode, BlockingMode::Nxdomain);
    assert_eq!(cfg.filtering.lists.len(), 2);
    assert_eq!(cfg.filtering.lists[0].name, "OISD Big");
    assert_eq!(cfg.filtering.lists[1].name, "Hagezi Pro");
    assert_eq!(
        cfg.get_web_config().bind,
        IpAddr::from_str("127.0.0.1").unwrap()
    );
    assert_eq!(cfg.get_web_config().port, 9090);
    assert_eq!(cfg.get_stats_config().retention_days, 30);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_wizard_invalid_ports_and_ips() {
    let temp_dir = std::env::temp_dir().join(format!("sito_ui_wiz_inv_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    // Invalid port
    let bad_port_form = WizardCompleteForm {
        admin_user: Some("admin".to_string()),
        admin_password: Some("ValidPassword123!".to_string()),
        port: Some("not_a_port".to_string()),
        ..Default::default()
    };
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(bad_port_form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Invalid web bind IP
    let bad_ip_form = WizardCompleteForm {
        admin_user: Some("admin".to_string()),
        admin_password: Some("ValidPassword123!".to_string()),
        web_bind: Some("not_an_ip".to_string()),
        ..Default::default()
    };
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(bad_ip_form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// P2-41/viewer: the filtering page shows only scheme+host to Viewers while
/// Operators keep the full subscription URL.
#[test]
fn test_redact_text_urls_preserves_punctuation_and_hides_credentials() {
    assert_eq!(
        redact_text_urls("failed (https://user:pass@lists.example/private?token=x); retry"),
        "failed (https://lists.example); retry"
    );
    assert_eq!(redact_text_urls("plain error"), "plain error");
}

#[tokio::test]
async fn test_filtering_page_redacts_subscription_urls_below_operator() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_filter_urls_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let mut config = (**ctx.config.load()).clone();
    config.filtering.lists = vec![sito_core::config::FilterListConfig {
        name: "Private".to_string(),
        url: "https://lists.example.net/subscriptions/private-token.txt".to_string(),
        enabled: false,
        refresh_hours: None,
    }];
    ctx.set_config(config);
    ctx.runtime_lists.mark_refreshed(
        "adult",
        "https://bundled.example.net/source/runtime-secret-token.txt",
    );
    ctx.runtime_lists.record_attempt(
        "adult",
        Some(
            "fetch failed for https://bundled.example.net/source/runtime-secret-token.txt"
                .to_string(),
        ),
    );

    ctx.auth_mgr
        .create_user("view_user", "pass", Role::Viewer)
        .await;
    ctx.auth_mgr
        .create_user("oper_user", "pass", Role::Operator)
        .await;

    let render = |session: crate::auth::session::Session| {
        let ctx = ctx.clone();
        async move {
            let mut headers = HeaderMap::new();
            headers.insert(COOKIE, session.to_cookie_header().parse().unwrap());
            let response = filtering_page(State(ctx), headers).await;
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
        }
    };

    let LoginResult::Success(viewer_session) =
        ctx.auth_mgr.login("view_user", "pass", "127.0.0.1").await
    else {
        panic!("viewer login failed");
    };
    let viewer_html = String::from_utf8(render(viewer_session).await.to_vec()).unwrap();
    assert!(
        viewer_html.contains("https://lists.example.net"),
        "a Viewer may see the source host"
    );
    assert!(
        !viewer_html.contains("private-token"),
        "a Viewer must not see the full subscription URL: {viewer_html}"
    );
    assert!(
        viewer_html.contains("https://bundled.example.net"),
        "a Viewer may see the runtime source host"
    );
    assert!(
        !viewer_html.contains("runtime-secret-token"),
        "a Viewer must not see the runtime source URL or error URL: {viewer_html}"
    );

    let LoginResult::Success(oper_session) =
        ctx.auth_mgr.login("oper_user", "pass", "127.0.0.1").await
    else {
        panic!("operator login failed");
    };
    let operator_html = String::from_utf8(render(oper_session).await.to_vec()).unwrap();
    assert!(
        operator_html.contains("https://lists.example.net/subscriptions/private-token.txt"),
        "an Operator must see the full subscription URL"
    );
    assert!(
        operator_html.contains("https://bundled.example.net/source/runtime-secret-token.txt"),
        "an Operator must see the full runtime source URL"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_catalog_page_views_sorted_and_already_added_flags() {
    let catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");
    let first = &catalog.filters[0];
    let second = &catalog.filters[1];
    let third = &catalog.filters[2];
    let fourth = &catalog.filters[3];

    let lists = vec![
        sito_core::config::FilterListConfig {
            name: catalog_list_name(first).to_uppercase(),
            url: "https://custom.example/one.txt".to_string(),
            enabled: true,
            refresh_hours: None,
        },
        sito_core::config::FilterListConfig {
            name: "Custom source".to_string(),
            url: second.download_url.to_uppercase(),
            enabled: true,
            refresh_hours: None,
        },
        sito_core::config::FilterListConfig {
            name: "Subscription source".to_string(),
            url: fourth.subscription_url.clone(),
            enabled: true,
            refresh_hours: None,
        },
    ];

    let (categories, filters) = catalog_page_views(Ok(catalog.clone()), &lists);

    assert_eq!(filters.len(), catalog.filters.len());
    let display_numbers: Vec<u32> = categories.iter().map(|c| c.display_number).collect();
    let mut sorted_numbers = display_numbers.clone();
    sorted_numbers.sort_unstable();
    assert_eq!(
        display_numbers, sorted_numbers,
        "categories need stable order"
    );
    assert_eq!(
        categories.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        vec!["general", "other", "regional", "security"]
    );
    assert_eq!(
        categories.iter().map(|c| c.filter_count).sum::<usize>(),
        catalog.filters.len()
    );
    let mut category_order: Vec<&str> = filters.iter().map(|f| f.category.as_str()).collect();
    category_order.dedup();
    assert_eq!(
        category_order,
        categories.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        "filters must be grouped in category display order"
    );

    let view = |id: &str| filters.iter().find(|f| f.id == id).expect("catalog filter");
    let first_view = view(&first.id);
    assert_eq!(first_view.name, first.name);
    assert_eq!(first_view.source_url, first.download_url);
    assert_eq!(first_view.category_name, "General");
    assert_eq!(first_view.version, first.version);
    assert_eq!(first_view.stored_name, catalog_list_name(first));
    assert!(
        !first_view.name_sanitized,
        "a routing-safe upstream name must not be marked as renamed"
    );
    assert!(first_view.already_added, "case-insensitive name match");

    // The UI gets the effective stored name from the view model, not by
    // re-running sanitization in the template.
    let slashed = catalog
        .filter_by_id("hagezi_windows_office_tracker_blocklist")
        .expect("catalog entry");
    let slashed_view = view(&slashed.id);
    assert!(slashed_view.name.contains('/'));
    assert!(slashed_view.name_sanitized);
    assert_eq!(slashed_view.stored_name, catalog_list_name(slashed));
    assert!(!slashed_view.stored_name.contains('/'));
    assert!(
        view(&second.id).already_added,
        "case-insensitive download URL match"
    );
    assert!(
        view(&fourth.id).already_added,
        "subscription URL match counts as already added"
    );
    assert!(!view(&third.id).already_added);

    // A corrupt catalog degrades to an empty section, not a page failure.
    let corrupt =
        sito_clients::Catalog::parse("{ not json").expect_err("fixture must be invalid JSON");
    let (categories, filters) = catalog_page_views(Err(corrupt), &lists);
    assert!(categories.is_empty());
    assert!(filters.is_empty());
}

#[test]
fn test_catalog_lists_to_add_maps_dedupes_and_skips_existing() {
    let catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");
    let first = &catalog.filters[0];
    let second = &catalog.filters[1];
    let third = &catalog.filters[2];
    let fourth = &catalog.filters[3];

    let existing = vec![
        sito_core::config::FilterListConfig {
            name: catalog_list_name(first).to_lowercase(),
            url: "https://custom.example/one.txt".to_string(),
            enabled: true,
            refresh_hours: None,
        },
        sito_core::config::FilterListConfig {
            name: "Custom source".to_string(),
            url: second.download_url.to_lowercase(),
            enabled: true,
            refresh_hours: None,
        },
        sito_core::config::FilterListConfig {
            name: "Subscription source".to_string(),
            url: fourth.subscription_url.clone(),
            enabled: true,
            refresh_hours: None,
        },
    ];

    let selected = vec![
        first.id.clone(),
        second.id.clone(),
        third.id.clone(),
        third.id.clone(),
    ];
    let additions = catalog_lists_to_add(&catalog, &existing, &selected).expect("valid selection");
    assert_eq!(
        additions.len(),
        1,
        "already-added and repeated ids are skipped"
    );
    assert_eq!(additions[0].name, catalog_list_name(third));
    assert_eq!(additions[0].url, catalog_filter_url(third));
    assert!(additions[0].enabled);
    assert_eq!(additions[0].refresh_hours, None);

    let all_present = vec![first.id.clone(), second.id.clone(), fourth.id.clone()];
    assert!(
        catalog_lists_to_add(&catalog, &existing, &all_present)
            .expect("valid selection")
            .is_empty(),
        "selecting only already-added entries must add nothing"
    );

    // Catalog names containing `/` are stored under a routing-safe name.
    let slashed = catalog
        .filter_by_id("hagezi_windows_office_tracker_blocklist")
        .expect("catalog entry");
    assert!(slashed.name.contains('/'));
    let stored = catalog_list_name(slashed);
    assert!(!stored.contains('/'));
    assert!(crate::handlers::filtering::valid_filter_list_name(&stored));
    let additions = catalog_lists_to_add(&catalog, &[], std::slice::from_ref(&slashed.id))
        .expect("valid selection");
    assert_eq!(additions[0].name, stored);
}

#[test]
fn test_catalog_lists_to_add_rejects_unknown_deprecated_and_oversize() {
    let catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");

    let unknown = catalog_lists_to_add(&catalog, &[], &["not_a_catalog_filter".to_string()]);
    assert!(matches!(
        unknown,
        Err(CatalogSelectionError::Unknown(id)) if id == "not_a_catalog_filter"
    ));

    let mut deprecated_catalog = catalog.clone();
    deprecated_catalog.filters[0].deprecated = true;
    let deprecated = catalog_lists_to_add(
        &deprecated_catalog,
        &[],
        &[deprecated_catalog.filters[0].id.clone()],
    );
    assert!(matches!(
        deprecated,
        Err(CatalogSelectionError::Deprecated(id)) if id == deprecated_catalog.filters[0].id
    ));

    let over_limit: Vec<String> = catalog
        .filters
        .iter()
        .take(MAX_CATALOG_SELECTION + 1)
        .map(|filter| filter.id.clone())
        .collect();
    assert!(matches!(
        catalog_lists_to_add(&catalog, &[], &over_limit),
        Err(CatalogSelectionError::TooMany)
    ));

    // Repeating an id does not consume the cap twice.
    let mut at_limit: Vec<String> = catalog
        .filters
        .iter()
        .take(MAX_CATALOG_SELECTION)
        .map(|filter| filter.id.clone())
        .collect();
    at_limit.extend(at_limit.clone());
    assert_eq!(
        catalog_lists_to_add(&catalog, &[], &at_limit)
            .expect("selection at the cap")
            .len(),
        MAX_CATALOG_SELECTION
    );
}

#[test]
fn test_selected_catalog_ids_reads_only_selected_field() {
    let pairs = vec![
        ("csrf_token".to_string(), "csrf-value".to_string()),
        ("selected".to_string(), " first ".to_string()),
        ("other".to_string(), "ignored".to_string()),
        ("selected".to_string(), String::new()),
        ("selected".to_string(), "second".to_string()),
    ];
    assert_eq!(selected_catalog_ids(&pairs), vec!["first", "second"]);
}

#[tokio::test]
async fn test_filtering_add_catalog_handler_adds_multiple_lists_once() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_catalog_add_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("oper_user", "pass", Role::Operator)
        .await;
    let LoginResult::Success(session) = ctx.auth_mgr.login("oper_user", "pass", "127.0.0.1").await
    else {
        panic!("login failed");
    };
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, session.to_cookie_header().parse().unwrap());

    let catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");
    let first = &catalog.filters[0];
    let second = &catalog.filters[1];
    let pairs = vec![
        ("csrf_token".to_string(), "ignored".to_string()),
        ("selected".to_string(), first.id.clone()),
        ("selected".to_string(), second.id.clone()),
        // A repeated id must not add a second copy.
        ("selected".to_string(), first.id.clone()),
    ];

    let resp =
        filtering_add_catalog_handler(State(ctx.clone()), headers.clone(), Form(pairs.clone()))
            .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let lists = ctx.config.load().filtering.lists.clone();
    assert_eq!(lists.len(), 2);
    assert_eq!(lists[0].name, catalog_list_name(first));
    assert_eq!(lists[0].url, catalog_filter_url(first));
    assert!(lists[0].enabled);
    assert_eq!(lists[0].refresh_hours, None);
    assert_eq!(lists[1].name, catalog_list_name(second));
    assert_eq!(lists[1].url, catalog_filter_url(second));

    // Selecting the same entries again is a no-op, not a conflict.
    let resp = filtering_add_catalog_handler(State(ctx.clone()), headers, Form(pairs)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        ctx.config.load().filtering.lists.len(),
        2,
        "already-added catalog lists must not be duplicated"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// The global CSRF middleware buffers a form-encoded body to read the token
/// and restores it for the handler. This route-level test proves repeated
/// `selected` fields survive that buffering and reach the `Form<Vec<_>>`
/// extractor as separate catalog ids.
#[tokio::test]
async fn test_add_catalog_route_preserves_repeated_selected_fields_through_csrf() {
    use axum::body::Body;
    use axum::http::{Request, header};
    use tower::ServiceExt;

    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_catalog_route_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    // Clear the bootstrap state so the setup middleware lets the request
    // reach the normal UI route and CSRF layer.
    ctx.auth_mgr
        .update_user_password("admin", "TestPassword123!")
        .await;
    ctx.set_setup_pending(false);

    ctx.auth_mgr
        .create_user("oper_user", "pass", Role::Operator)
        .await;
    let LoginResult::Success(session) = ctx.auth_mgr.login("oper_user", "pass", "127.0.0.1").await
    else {
        panic!("login failed");
    };

    let catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");
    let first = &catalog.filters[0];
    let second = &catalog.filters[1];
    let cookie = format!(
        "{}; {}",
        session.to_cookie_header_secure(false),
        crate::auth::session::build_csrf_cookie(&session.csrf_token, 3600, false)
    );
    let body = format!(
        "csrf_token={}&selected={}&selected={}&selected={}",
        session.csrf_token, first.id, second.id, first.id
    );
    let app = crate::create_router(ctx.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/filtering/add-catalog")
                .header(header::HOST, "localhost")
                .header(header::ORIGIN, "http://localhost")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let lists = ctx.config.load().filtering.lists.clone();
    assert_eq!(
        lists.len(),
        2,
        "both repeated selected fields must reach the handler, and the duplicate must dedupe"
    );
    assert_eq!(lists[0].name, catalog_list_name(first));
    assert_eq!(lists[1].name, catalog_list_name(second));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_filtering_add_catalog_handler_rejects_invalid_selection_without_partial_write() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_catalog_reject_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("oper_user", "pass", Role::Operator)
        .await;
    let LoginResult::Success(session) = ctx.auth_mgr.login("oper_user", "pass", "127.0.0.1").await
    else {
        panic!("login failed");
    };
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, session.to_cookie_header().parse().unwrap());

    let catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");
    let valid = catalog.filters[0].id.clone();

    // One unknown id invalidates the whole batch.
    let unknown = vec![
        ("selected".to_string(), valid.clone()),
        ("selected".to_string(), "not_a_catalog_filter".to_string()),
    ];
    let resp =
        filtering_add_catalog_handler(State(ctx.clone()), headers.clone(), Form(unknown)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        ctx.config.load().filtering.lists.is_empty(),
        "an unknown id must not partially write the selection"
    );

    // The selection cap is enforced at the handler boundary too.
    let over_limit: Vec<(String, String)> = catalog
        .filters
        .iter()
        .take(MAX_CATALOG_SELECTION + 1)
        .map(|filter| ("selected".to_string(), filter.id.clone()))
        .collect();
    let resp =
        filtering_add_catalog_handler(State(ctx.clone()), headers.clone(), Form(over_limit)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        ctx.config.load().filtering.lists.is_empty(),
        "an oversized selection must not write configuration"
    );

    // Deprecated entries are rejected even when the id is otherwise valid.
    let mut deprecated_catalog = catalog.clone();
    deprecated_catalog.filters[0].deprecated = true;
    let resp = apply_catalog_selection(
        &ctx,
        &deprecated_catalog,
        &[deprecated_catalog.filters[0].id.clone()],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        ctx.config.load().filtering.lists.is_empty(),
        "a deprecated selection must not write configuration"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_filtering_add_catalog_handler_rbac_and_empty_selection() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_catalog_rbac_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    // Unauthenticated callers are redirected to the login page.
    let resp =
        filtering_add_catalog_handler(State(ctx.clone()), HeaderMap::new(), Form(vec![])).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(axum::http::header::LOCATION).unwrap(),
        "/login"
    );

    ctx.auth_mgr
        .create_user("view_user", "pass", Role::Viewer)
        .await;
    ctx.auth_mgr
        .create_user("oper_user", "pass", Role::Operator)
        .await;
    let LoginResult::Success(view_session) =
        ctx.auth_mgr.login("view_user", "pass", "127.0.0.1").await
    else {
        panic!("viewer login failed");
    };
    let LoginResult::Success(oper_session) =
        ctx.auth_mgr.login("oper_user", "pass", "127.0.0.1").await
    else {
        panic!("operator login failed");
    };
    let mut view_headers = HeaderMap::new();
    view_headers.insert(COOKIE, view_session.to_cookie_header().parse().unwrap());
    let mut oper_headers = HeaderMap::new();
    oper_headers.insert(COOKIE, oper_session.to_cookie_header().parse().unwrap());

    let resp = filtering_add_catalog_handler(State(ctx.clone()), view_headers, Form(vec![])).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = filtering_add_catalog_handler(State(ctx.clone()), oper_headers, Form(vec![])).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        ctx.config.load().filtering.lists.is_empty(),
        "an empty selection must not change configuration"
    );
    assert!(
        !ctx.config_path.exists(),
        "an empty selection must not persist configuration"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_filtering_add_catalog_apply_failure_persists_nothing() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_catalog_persist_err_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let mut ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("oper_user", "pass", Role::Operator)
        .await;
    let LoginResult::Success(session) = ctx.auth_mgr.login("oper_user", "pass", "127.0.0.1").await
    else {
        panic!("login failed");
    };
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, session.to_cookie_header().parse().unwrap());
    ctx.config_path = std::path::PathBuf::from("/proc/forbidden_ui_test/config.toml");

    let catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");
    let selected: Vec<(String, String)> = catalog
        .filters
        .iter()
        .take(2)
        .map(|filter| ("selected".to_string(), filter.id.clone()))
        .collect();
    let resp = filtering_add_catalog_handler(State(ctx.clone()), headers, Form(selected)).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        ctx.config.load().filtering.lists.is_empty(),
        "a failed catalog apply must persist nothing: {:?}",
        ctx.config.load().filtering.lists
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_ui_handlers_persist_failure_returns_500_and_preserves_in_memory_state() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_persist_err_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let mut ctx = mock_context(&temp_dir).await;

    let login_res = ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await;
    let crate::auth::LoginResult::Success(session) = login_res else {
        panic!("admin login failed");
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        format!("sito_session={}", session.id).parse().unwrap(),
    );

    // Break config_path to point to a non-writable/non-existent directory to simulate disk write failure
    ctx.config_path = std::path::PathBuf::from("/proc/forbidden_ui_test/config.toml");

    let orig_cache_size = ctx.config.load().dns.cache.size_mb;
    let settings_resp = settings_save_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        headers.clone(),
        Form(SaveSettingsForm {
            cache_size_mb: 9999,
            min_ttl: 100,
            dnssec: None,
            rate_limit: 50,
        }),
    )
    .await;
    assert_eq!(settings_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    // Verify in-memory config was NOT mutated
    assert_eq!(ctx.config.load().dns.cache.size_mb, orig_cache_size);

    let filter_resp = filtering_add_handler(
        State(ctx.clone()),
        headers.clone(),
        Form(AddFilterListForm {
            name: "blocked-list".to_string(),
            url: "http://example.com/hosts".to_string(),
            refresh_hours: None,
        }),
    )
    .await;
    assert_eq!(filter_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    // Verify in-memory filter lists was NOT mutated
    assert!(
        ctx.config.load().filtering.lists.is_empty(),
        "failed apply must not mutate filter lists: {:?}",
        ctx.config.load().filtering.lists
    );

    let rewrite_resp = rewrites_add_handler(
        State(ctx.clone()),
        headers.clone(),
        Form(AddRewriteForm {
            domain: "bad.internal".to_string(),
            record_type: "A".to_string(),
            answer: "1.2.3.4".to_string(),
        }),
    )
    .await;
    assert_eq!(rewrite_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    // Verify in-memory rewrites table was NOT mutated
    let rewrites = crate::handlers::rewrites::load_rewrite_store(&ctx);
    assert!(
        rewrites.cfg.entries.is_empty(),
        "failed apply must not mutate rewrites: {:?}",
        rewrites.cfg.entries
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// WP-0.7 (P1-15): disabling 2FA requires a fresh re-authentication ticket.
/// The ticket proves the current password and second factor; a stolen
/// session alone cannot turn the factor off.
#[tokio::test]
async fn test_disable_totp_requires_reauth_token() {
    use crate::auth::rbac::RequireViewer;
    use crate::handlers::auth_handlers::{REAUTH_TOKEN_HEADER, disable_totp, reauth};
    use crate::models::{DisableTotpRequest, ReauthRequest};

    let temp_dir = std::env::temp_dir().join(format!("sito_ui_totp_off_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let setup = ctx.auth_mgr.init_totp_setup("admin").await.expect("setup");
    assert!(
        ctx.auth_mgr
            .confirm_totp_setup("admin", &setup.backup_codes[0])
            .await
    );
    assert!(ctx.auth_mgr.totp_enabled("admin"));

    let LoginResult::TotpRequired { partial_token } =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("TOTP login should require a second factor");
    };
    let crate::auth::manager::TotpVerifyResult::Success(session) = ctx
        .auth_mgr
        .verify_totp(&partial_token, &setup.backup_codes[1], "127.0.0.1")
        .await
    else {
        panic!("TOTP verification failed");
    };
    let headers = session_headers(&session);
    let admin = RequireViewer(session_to_user(&session));
    let body = || {
        axum::Json(DisableTotpRequest {
            password: "adminadmin".to_string(),
            code: Some(setup.backup_codes[2].clone()),
        })
    };

    // A stolen session without a re-auth ticket cannot disable 2FA.
    let err = disable_totp(admin.clone(), State(ctx.clone()), headers.clone(), body())
        .await
        .unwrap_err();
    assert_eq!(err.status, 401);
    assert!(ctx.auth_mgr.totp_enabled("admin"));

    // An invalid ticket is rejected too.
    let mut invalid_headers = headers.clone();
    invalid_headers.insert(
        REAUTH_TOKEN_HEADER,
        axum::http::HeaderValue::from_static("not-a-real-ticket"),
    );
    let err = disable_totp(admin.clone(), State(ctx.clone()), invalid_headers, body())
        .await
        .unwrap_err();
    assert_eq!(err.status, 401);
    assert!(ctx.auth_mgr.totp_enabled("admin"));

    // Re-authenticate with the current backup code, then disable with the
    // session-bound ticket. The ticket, not the request body, authorizes
    // the operation, so the same backup code is not consumed twice.
    let ticket = reauth(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        admin.clone(),
        headers.clone(),
        axum::Json(ReauthRequest {
            password: "adminadmin".to_string(),
            code: Some(setup.backup_codes[2].clone()),
        }),
    )
    .await
    .expect("re-authentication succeeds")
    .0;
    let mut ticket_headers = headers;
    ticket_headers.insert(
        REAUTH_TOKEN_HEADER,
        axum::http::HeaderValue::from_str(&ticket.reauth_token).unwrap(),
    );
    let ok = disable_totp(admin, State(ctx.clone()), ticket_headers, body()).await;
    assert!(ok.is_ok());
    assert!(!ctx.auth_mgr.totp_enabled("admin"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

fn session_to_user(session: &crate::auth::session::Session) -> crate::auth::AuthUser {
    crate::auth::AuthUser {
        username: session.username.clone(),
        role: session.role,
        token_id: None,
        owner: None,
    }
}

#[tokio::test]
async fn test_wizard_completion_requires_setup_token_when_provisioned() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_setup_tok_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let mut ctx = mock_context(&temp_dir).await;
    ctx.auth_mgr = Arc::new(crate::auth::AuthManager::with_storage(&temp_dir, 24, 5).unwrap());
    assert!(ctx.auth_mgr.setup_token_required());
    let token = ctx.auth_mgr.setup_token().expect("token provisioned");

    let form = || WizardCompleteForm {
        setup_token: None,
        admin_user: Some("admin".to_string()),
        admin_password: Some("Str0ngPassword!".to_string()),
        ..Default::default()
    };

    // Without the token -> 403 and setup stays pending.
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(form()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(ctx.auth_mgr.setup_token_required());

    // With the token -> completes and the token is consumed.
    let mut with_token = form();
    with_token.setup_token = Some(token);
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(with_token),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(!ctx.auth_mgr.setup_token_required());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// WP-2.10: when the printed setup token is required, an Admin session is no
/// longer exempt; it must present the token or a fresh reauth ticket.
#[tokio::test]
async fn test_wizard_admin_recovery_requires_setup_token_or_reauth() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_wizard_recovery_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let mut ctx = mock_context(&temp_dir).await;
    ctx.auth_mgr = Arc::new(crate::auth::AuthManager::with_storage(&temp_dir, 24, 5).unwrap());
    assert!(ctx.auth_mgr.setup_token_required());

    let LoginResult::Success(session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("bootstrap admin login failed");
    };
    let headers = session_headers(&session);

    let base_form = || WizardCompleteForm {
        setup_token: None,
        reauth_token: None,
        admin_user: Some("admin".to_string()),
        admin_password: Some("Str0ngPassword!".to_string()),
        ..Default::default()
    };

    // An Admin session alone is not enough while the setup token is pending.
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(base_form()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(ctx.auth_mgr.setup_token_required());

    // A fresh ticket bound to the Admin session is accepted instead.
    let ticket = ctx
        .auth_mgr
        .reauth("admin", "adminadmin", None, &session.id, "")
        .await
        .expect("reauth ticket");
    let mut form = base_form();
    form.reauth_token = Some(ticket.token);
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        headers,
        Form(form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(!ctx.auth_mgr.setup_token_required());
    assert!(matches!(
        ctx.auth_mgr
            .login("admin", "Str0ngPassword!", "127.0.0.2")
            .await,
        LoginResult::Success(_)
    ));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// WP-0.7 (P1-16): after first boot the wizard is closed to everyone,
/// including an Admin session, so it cannot reset the password.
#[tokio::test]
async fn test_wizard_forbidden_after_setup_even_for_admin() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_wiz_closed_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    assert!(
        ctx.auth_mgr
            .update_user_password("admin", "NewAdminPassword1")
            .await
    );
    assert!(!ctx.auth_mgr.is_first_run());
    assert!(!ctx.auth_mgr.setup_token_required());

    let LoginResult::Success(session) = ctx
        .auth_mgr
        .login("admin", "NewAdminPassword1", "127.0.0.1")
        .await
    else {
        panic!("admin login failed");
    };
    let headers = session_headers(&session);

    let resp = wizard_page(
        State(ctx.clone()),
        headers.clone(),
        Query(SetupTokenQuery::default()),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "the wizard page must be bootstrap-only"
    );

    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        headers,
        Form(WizardCompleteForm {
            admin_user: Some("admin".to_string()),
            admin_password: Some("AttackerKnownPassword1".to_string()),
            confirm_password: Some("AttackerKnownPassword1".to_string()),
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "an Admin must not reset the password through the closed wizard"
    );
    assert!(
        ctx.auth_mgr
            .verify_user_password("admin", "NewAdminPassword1")
            .await,
        "the wizard must not have changed the password"
    );
    assert!(
        !ctx.auth_mgr
            .verify_user_password("admin", "AttackerKnownPassword1")
            .await,
        "the attacker-supplied password must not be active"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// WP-4.3: deleting a client from the UI must also drop its shared secret.
#[tokio::test]
async fn test_ui_client_delete_removes_shared_secret() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_client_secret_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    // Seed a client with a shared secret in the in-memory config.
    let mut clients_cfg = load_clients_config(&ctx);
    clients_cfg.entries.push(sito_clients::ClientEntryConfig {
        name: "phone".to_string(),
        ids: vec!["10.0.0.5".to_string()],
        group: "default".to_string(),
        ignore_query_log: false,
        ignore_stats: false,
        use_global_upstreams: true,
        upstreams: None,
        trusted: false,
    });
    clients_cfg
        .client_id_secrets
        .insert("phone".to_string(), "shared-secret".to_string());
    let mut new_cfg = (**ctx.config.load()).clone();
    new_cfg.clients = Some(toml::Value::try_from(&clients_cfg).unwrap());
    ctx.set_config(new_cfg);

    let LoginResult::Success(session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("login failed");
    };
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, session.to_cookie_header().parse().unwrap());

    let resp = clients_delete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        headers,
        Form(DeleteClientForm {
            name: "phone".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let after = load_clients_config(&ctx);
    assert!(
        after.entries.is_empty(),
        "failed apply must not persist client entries: {:?}",
        after.entries
    );
    assert!(
        !after.client_id_secrets.contains_key("phone"),
        "the UI delete must remove the client's shared secret: {:?}",
        after.client_id_secrets
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// WP-4.4: the UI upstream probe requires Operator; a Viewer is rejected
/// (the setup-token path stays for first boot).
#[tokio::test]
async fn test_ui_probe_requires_operator() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_probe_rbac_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("view_user", "ViewerPass1", Role::Viewer)
        .await;
    ctx.auth_mgr
        .create_user("oper_user", "OperPass1", Role::Operator)
        .await;

    let LoginResult::Success(view_session) = ctx
        .auth_mgr
        .login("view_user", "ViewerPass1", "127.0.0.1")
        .await
    else {
        panic!("login failed");
    };
    let mut view_headers = HeaderMap::new();
    view_headers.insert(COOKIE, view_session.to_cookie_header().parse().unwrap());

    let resp = upstreams_test_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        view_headers,
        Form(TestUpstreamForm {
            address: String::new(),
            setup_token: None,
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a Viewer must not run the upstream probe"
    );

    let LoginResult::Success(oper_session) = ctx
        .auth_mgr
        .login("oper_user", "OperPass1", "127.0.0.1")
        .await
    else {
        panic!("login failed");
    };
    let mut oper_headers = HeaderMap::new();
    oper_headers.insert(COOKIE, oper_session.to_cookie_header().parse().unwrap());

    // Empty address short-circuits before any network probe.
    let resp = upstreams_test_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        oper_headers,
        Form(TestUpstreamForm {
            address: String::new(),
            setup_token: None,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

fn session_headers(session: &crate::auth::session::Session) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, session.to_cookie_header().parse().unwrap());
    headers
}

async fn response_body(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Records discovered clients through the same resolve path the DNS
/// listener uses, so the UI sees production-shaped registry entries.
type SeedDiscovery<'a> = (
    std::net::IpAddr,
    Option<&'a str>,
    Option<&'a str>,
    chrono::DateTime<chrono::Utc>,
);

fn seed_discovered(ctx: &ServerContext, entries: &[SeedDiscovery<'_>]) {
    let registry = ctx.clients.load();
    for (ip, mac, hostname, last_seen) in entries {
        let Some(mac) = mac else {
            // The resolve path only records a discovery when a lease is
            // present. Seed the no-identifier case directly so the UI
            // fallback (`-`) is exercised.
            registry.unidentified_store().write().unwrap().insert(
                *ip,
                sito_clients::UnidentifiedClient {
                    ip: *ip,
                    mac: None,
                    hostname: hostname.map(str::to_string),
                    comment: None,
                    last_seen: *last_seen,
                },
            );
            continue;
        };
        registry.update_routeros_leases(vec![sito_clients::RouterOsLease {
            mac: (*mac).to_string(),
            ip: Some(*ip),
            hostname: hostname.map(str::to_string),
            comment: None,
            verified: true,
        }]);
        let mut client = sito_core::client::ClientContext::new(*ip);
        let _ = registry.resolve(&mut client, registry.timezone().at_utc(*last_seen));
    }
}

/// Seeds `count` discoveries under `10.44.0.x` (index 0 is newest).
/// `hostname_prefix` adds a hostname to each entry so PII-leak assertions
/// have something distinctive to look for.
fn seed_discovered_page(ctx: &ServerContext, count: i64, hostname_prefix: Option<&str>) {
    let base = midday();
    for index in 0..count {
        let ip: std::net::IpAddr = format!("10.44.0.{}", index + 1).parse().unwrap();
        let mac = format!("aa:bb:cc:dd:ef:{index:02x}");
        let hostname = hostname_prefix.map(|prefix| format!("{prefix}-{index}"));
        let seen = base - chrono::TimeDelta::minutes(index);
        seed_discovered(ctx, &[(ip, Some(mac.as_str()), hostname.as_deref(), seen)]);
    }
}

/// A fixed midday UTC instant: deterministic formatting with no risk of
/// crossing a day (or UTC midnight) while the test runs.
fn midday() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
        .date_naive()
        .and_hms_opt(12, 0, 0)
        .expect("midday is a valid time")
        .and_utc()
}

#[tokio::test]
async fn test_clients_page_shows_unidentified_for_operator() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_clients_discovered_operator_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("oper_user", "OperPass1", Role::Operator)
        .await;

    let base = midday();
    let older_seen = base - chrono::TimeDelta::minutes(5);
    let newer_seen = base - chrono::TimeDelta::minutes(1);
    let no_id_seen = base - chrono::TimeDelta::minutes(3);
    let older: std::net::IpAddr = "10.42.0.10".parse().unwrap();
    let newer: std::net::IpAddr = "10.42.0.11".parse().unwrap();
    let no_id: std::net::IpAddr = "10.42.0.12".parse().unwrap();
    seed_discovered(
        &ctx,
        &[
            (
                older,
                Some("aa:bb:cc:dd:ee:01"),
                Some("older-host"),
                older_seen,
            ),
            (
                newer,
                Some("aa:bb:cc:dd:ee:02"),
                Some("newer-host"),
                newer_seen,
            ),
            (no_id, None, None, no_id_seen),
        ],
    );

    let LoginResult::Success(session) = ctx
        .auth_mgr
        .login("oper_user", "OperPass1", "127.0.0.1")
        .await
    else {
        panic!("operator login failed");
    };
    let resp = clients_page(
        State(ctx.clone()),
        session_headers(&session),
        Query(ClientsPageQuery::default()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body(resp).await;

    assert!(
        body.contains("Discovered but unidentified"),
        "operators must see the discovered card: {body}"
    );
    assert!(body.contains("10.42.0.10"), "{body}");
    assert!(body.contains("10.42.0.11"), "{body}");
    assert!(body.contains("aa:bb:cc:dd:ee:01"), "{body}");
    assert!(body.contains("aa:bb:cc:dd:ee:02"), "{body}");
    assert!(body.contains("older-host"), "{body}");
    assert!(body.contains("newer-host"), "{body}");
    assert!(body.contains("Last Seen"), "{body}");
    for seen in [older_seen, newer_seen, no_id_seen] {
        let rendered = seen.format("%Y-%m-%d %H:%M UTC").to_string();
        assert!(
            body.contains(&rendered),
            "last-seen timestamp {rendered:?} must render exactly: {body}"
        );
    }

    // A discovery with neither a MAC nor a hostname must render the `-`
    // fallback instead of an empty cell.
    let no_id_pos = body.find("10.42.0.12").expect("no-identifier row");
    let no_id_row_end = body[no_id_pos..].find("</tr>").expect("row terminator") + no_id_pos;
    assert!(
        body[no_id_pos..no_id_row_end].contains("<div>-</div>"),
        "missing MAC and hostname must render '-': {body}"
    );
    assert!(
        body.contains(&format!(
            "capped at {} entries",
            sito_clients::MAX_UNIDENTIFIED_CLIENTS
        )),
        "the entry bound must be visible: {body}"
    );
    assert!(
        body.contains(&format!(
            "pruned after {} hours",
            sito_clients::UNIDENTIFIED_CLIENT_TTL_HOURS
        )),
        "the retention window must be visible: {body}"
    );

    let newer_pos = body.find("10.42.0.11").expect("newer row");
    let older_pos = body.find("10.42.0.10").expect("older row");
    assert!(
        newer_pos < older_pos,
        "discovered rows must be newest first"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_clients_page_caps_discovered_rows_at_api_default() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_clients_discovered_cap_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("oper_user", "OperPass1", Role::Operator)
        .await;

    // 105 discoveries: the newest 100 render, the 5 oldest are omitted
    // even though the registry hard cap (1024) is not reached.
    let base = midday();
    let entries: Vec<(
        std::net::IpAddr,
        String,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
    )> = (0..105)
        .map(|index: i64| {
            let ip = format!("10.44.0.{}", index + 1).parse().unwrap();
            let mac = format!("aa:bb:cc:dd:ef:{index:02x}");
            (ip, mac, None, base - chrono::TimeDelta::minutes(index))
        })
        .collect();
    for (ip, mac, hostname, seen) in &entries {
        seed_discovered(
            &ctx,
            &[(*ip, Some(mac.as_str()), hostname.as_deref(), *seen)],
        );
    }

    let LoginResult::Success(session) = ctx
        .auth_mgr
        .login("oper_user", "OperPass1", "127.0.0.1")
        .await
    else {
        panic!("operator login failed");
    };
    let resp = clients_page(
        State(ctx.clone()),
        session_headers(&session),
        Query(ClientsPageQuery::default()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body(resp).await;

    assert!(
        body.contains("Showing 100 of 105 discovered clients"),
        "the truncated count must be accurate: {body}"
    );
    let rendered_rows = body
        .matches("<td class=\"td-strong mono\">10.44.0.")
        .count();
    assert_eq!(rendered_rows, 100, "at most 100 discovered rows may render");
    assert!(body.contains("10.44.0.1<"), "the newest row must render");
    assert!(body.contains("10.44.0.100<"), "row 100 must render");
    for index in 101..=105 {
        assert!(
            !body.contains(&format!("10.44.0.{index}<")),
            "row {index} is outside the 100-row window: {body}"
        );
    }
    assert!(
        body.contains(&format!(
            "capped at {} entries",
            sito_clients::MAX_UNIDENTIFIED_CLIENTS
        )),
        "the registry hard cap must stay visible: {body}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_clients_page_hides_unidentified_for_viewer() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_clients_discovered_viewer_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("view_user", "ViewerPass1", Role::Viewer)
        .await;

    // Viewers still see explicitly configured clients; only the
    // discovered (DHCP PII) section is hidden.
    let mut clients_cfg = load_clients_config(&ctx);
    clients_cfg.entries.push(sito_clients::ClientEntryConfig {
        name: "Viewer Laptop".to_string(),
        ids: vec!["10.43.0.99".to_string()],
        group: "default".to_string(),
        ignore_query_log: false,
        ignore_stats: false,
        use_global_upstreams: true,
        upstreams: None,
        trusted: false,
    });
    let mut new_cfg = (**ctx.config.load()).clone();
    new_cfg.clients = Some(toml::Value::try_from(&clients_cfg).unwrap());
    ctx.set_config(new_cfg);

    let ip: std::net::IpAddr = "10.43.0.20".parse().unwrap();
    seed_discovered(
        &ctx,
        &[(ip, Some("aa:bb:cc:dd:ee:03"), Some("secret-host"), midday())],
    );

    let LoginResult::Success(session) = ctx
        .auth_mgr
        .login("view_user", "ViewerPass1", "127.0.0.1")
        .await
    else {
        panic!("viewer login failed");
    };
    let resp = clients_page(
        State(ctx.clone()),
        session_headers(&session),
        Query(ClientsPageQuery::default()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body(resp).await;

    assert!(
        body.contains("Identified Clients & Device Policies"),
        "viewers still see configured clients: {body}"
    );
    assert!(
        body.contains("Viewer Laptop") && body.contains("10.43.0.99"),
        "the configured client row must remain visible: {body}"
    );
    assert!(
        !body.contains("Discovered but unidentified"),
        "the discovered section must be operator-only: {body}"
    );
    assert!(
        !body.contains("No unidentified clients discovered yet"),
        "the empty state must not leak the section: {body}"
    );
    assert!(!body.contains("10.43.0.20"), "discovered IP leaked: {body}");
    assert!(
        !body.contains("aa:bb:cc:dd:ee:03"),
        "discovered MAC leaked: {body}"
    );
    assert!(
        !body.contains("secret-host"),
        "discovered hostname leaked: {body}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_clients_page_renders_blocked_services_picker() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_clients_group_services_page_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let mut clients = sito_clients::ClientsConfig::default();
    clients.groups.insert(
        "kids".to_string(),
        clients_group_with_services(vec![sito_clients::BlockedServiceConfig {
            service: "tiktok".to_string(),
            schedule: Some(sito_clients::Schedule::parse("0 8 * * *").unwrap()),
        }]),
    );
    seed_clients_config(&ctx, &clients);

    let headers = operator_form_headers(&ctx).await;
    let resp = clients_page(
        State(ctx.clone()),
        headers,
        Query(ClientsPageQuery::default()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body(resp).await;

    assert!(body.contains("Blocked services by group"), "{body}");
    assert!(body.contains("kids"), "{body}");
    assert!(body.contains("tiktok"), "{body}");
    assert!(body.contains("schedule: 0 8 * * *"), "{body}");
    assert!(
        body.contains("action=\"/ui/clients/group-services\""),
        "the picker form must be wired to the handler: {body}"
    );
    assert!(body.contains("name=\"csrf_token\" value=\""), "{body}");
    assert!(body.contains("name=\"group\" value=\"kids\""), "{body}");
    assert!(body.contains("name=\"selected\""), "{body}");
    assert!(
        body.contains("1 selected"),
        "the group summary count must render: {body}"
    );

    // Groups sort default-first, so kids is the second picker. Its configured
    // TikTok entry must be prechecked without client-side JavaScript.
    let marker = "id=\"group-services-2-tiktok\"";
    let start = body.find(marker).expect("kids tiktok checkbox");
    let end = body[start..].find('>').expect("checkbox close") + start;
    assert!(
        body[start..=end].contains("checked"),
        "configured services must be prechecked: {}",
        &body[start..=end]
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_clients_page_empty_unidentified_state() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_clients_discovered_empty_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("oper_user", "OperPass1", Role::Operator)
        .await;

    let LoginResult::Success(session) = ctx
        .auth_mgr
        .login("oper_user", "OperPass1", "127.0.0.1")
        .await
    else {
        panic!("operator login failed");
    };
    let resp = clients_page(
        State(ctx.clone()),
        session_headers(&session),
        Query(ClientsPageQuery::default()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body(resp).await;

    assert!(body.contains("Discovered but unidentified"), "{body}");
    assert!(
        body.contains("No unidentified clients discovered yet."),
        "the empty state must render for operators: {body}"
    );
    assert!(
        body.contains(&format!(
            "capped at {} entries",
            sito_clients::MAX_UNIDENTIFIED_CLIENTS
        )),
        "the bound must stay visible when the list is empty: {body}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

fn discovered_row_count(body: &str) -> usize {
    body.matches("<td class=\"td-strong mono\">10.44.0.")
        .count()
}

#[tokio::test]
async fn test_clients_page_paginates_discovered_clients() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_clients_discovered_paginate_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("oper_user", "OperPass1", Role::Operator)
        .await;
    seed_discovered_page(&ctx, 105, None);

    let LoginResult::Success(session) = ctx
        .auth_mgr
        .login("oper_user", "OperPass1", "127.0.0.1")
        .await
    else {
        panic!("operator login failed");
    };

    let page1 = clients_page(
        State(ctx.clone()),
        session_headers(&session),
        Query(ClientsPageQuery {
            discovered_page: Some(1),
        }),
    )
    .await;
    assert_eq!(page1.status(), StatusCode::OK);
    let body1 = response_body(page1).await;
    assert!(body1.contains("Page 1 of 2"), "{body1}");
    assert_eq!(
        discovered_row_count(&body1),
        crate::handlers::clients::DEFAULT_UNIDENTIFIED_LIMIT,
        "page 1 must render exactly one page of rows: {body1}"
    );
    assert!(
        body1.contains("Showing 100 of 105 discovered clients"),
        "the page count must stay accurate: {body1}"
    );
    assert!(body1.contains("10.44.0.1<"), "newest row must render");
    assert!(body1.contains("10.44.0.100<"), "row 100 must render");
    for index in 101..=105 {
        assert!(
            !body1.contains(&format!("10.44.0.{index}<")),
            "row {index} belongs on page 2: {body1}"
        );
    }

    let page2 = clients_page(
        State(ctx.clone()),
        session_headers(&session),
        Query(ClientsPageQuery {
            discovered_page: Some(2),
        }),
    )
    .await;
    assert_eq!(page2.status(), StatusCode::OK);
    let body2 = response_body(page2).await;
    assert!(body2.contains("Page 2 of 2"), "{body2}");
    assert_eq!(discovered_row_count(&body2), 5, "{body2}");
    assert!(
        body2.contains("Showing 5 of 105 discovered clients"),
        "the page count must stay accurate on the last page: {body2}"
    );
    for index in 101..=105 {
        assert!(
            body2.contains(&format!("10.44.0.{index}<")),
            "row {index} must render on page 2: {body2}"
        );
    }
    assert!(
        !body2.contains("10.44.0.100<"),
        "row 100 belongs on page 1: {body2}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_clients_page_clamps_out_of_range_page() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_clients_discovered_clamp_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("oper_user", "OperPass1", Role::Operator)
        .await;
    seed_discovered_page(&ctx, 105, None);

    let LoginResult::Success(session) = ctx
        .auth_mgr
        .login("oper_user", "OperPass1", "127.0.0.1")
        .await
    else {
        panic!("operator login failed");
    };

    // A page far past the end clamps to the last page.
    let high = clients_page(
        State(ctx.clone()),
        session_headers(&session),
        Query(ClientsPageQuery {
            discovered_page: Some(99),
        }),
    )
    .await;
    assert_eq!(high.status(), StatusCode::OK);
    let high_body = response_body(high).await;
    assert!(
        high_body.contains("Page 2 of 2"),
        "an out-of-range page must clamp to the last page: {high_body}"
    );
    assert_eq!(discovered_row_count(&high_body), 5, "{high_body}");
    assert!(high_body.contains("10.44.0.105<"), "{high_body}");

    // Page zero clamps to the first page.
    let zero = clients_page(
        State(ctx.clone()),
        session_headers(&session),
        Query(ClientsPageQuery {
            discovered_page: Some(0),
        }),
    )
    .await;
    assert_eq!(zero.status(), StatusCode::OK);
    let zero_body = response_body(zero).await;
    assert!(
        zero_body.contains("Page 1 of 2"),
        "page zero must clamp to the first page: {zero_body}"
    );
    assert_eq!(
        discovered_row_count(&zero_body),
        crate::handlers::clients::DEFAULT_UNIDENTIFIED_LIMIT,
        "{zero_body}"
    );
    assert!(zero_body.contains("10.44.0.1<"), "{zero_body}");

    // No query parameter at all defaults to the first page.
    let default_page = clients_page(
        State(ctx.clone()),
        session_headers(&session),
        Query(ClientsPageQuery::default()),
    )
    .await;
    let default_body = response_body(default_page).await;
    assert!(default_body.contains("Page 1 of 2"), "{default_body}");
    assert_eq!(
        discovered_row_count(&default_body),
        crate::handlers::clients::DEFAULT_UNIDENTIFIED_LIMIT,
        "{default_body}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_viewer_pagination_never_exposes_pii() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_clients_discovered_viewer_page_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    ctx.auth_mgr
        .create_user("view_user", "ViewerPass1", Role::Viewer)
        .await;
    seed_discovered_page(&ctx, 105, Some("pii-host"));

    let LoginResult::Success(session) = ctx
        .auth_mgr
        .login("view_user", "ViewerPass1", "127.0.0.1")
        .await
    else {
        panic!("viewer login failed");
    };
    let resp = clients_page(
        State(ctx.clone()),
        session_headers(&session),
        Query(ClientsPageQuery {
            discovered_page: Some(2),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body(resp).await;

    assert!(
        !body.contains("Discovered but unidentified"),
        "the discovered section must stay operator-only: {body}"
    );
    assert!(
        !body.contains("Page 1 of 2") && !body.contains("Page 2 of 2"),
        "pagination controls must not leak the section: {body}"
    );
    assert!(
        !body.contains("No unidentified clients discovered yet"),
        "the empty state must not leak the section: {body}"
    );
    // Page 2 would contain rows 101-105; none of them (nor their PII) may
    // appear for a Viewer.
    for index in 1..=105 {
        assert!(
            !body.contains(&format!("10.44.0.{index}<")),
            "discovered IP {index} leaked: {body}"
        );
    }
    assert!(
        !body.contains("pii-host-"),
        "discovered hostname leaked: {body}"
    );
    assert!(
        !body.contains("aa:bb:cc:dd:ef:"),
        "discovered MAC leaked: {body}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_users_page_requires_admin() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_users_rbac_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    // Anonymous visitors are sent to the login page.
    let resp = users_page(State(ctx.clone()), HeaderMap::new()).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/login")
    );

    ctx.auth_mgr
        .create_user("view_user", "ViewerPass1", Role::Viewer)
        .await;
    ctx.auth_mgr
        .create_user("oper_user", "OperPass1", Role::Operator)
        .await;

    let LoginResult::Success(view_session) = ctx
        .auth_mgr
        .login("view_user", "ViewerPass1", "127.0.0.1")
        .await
    else {
        panic!("viewer login failed");
    };
    let view_headers = session_headers(&view_session);

    let resp = users_page(State(ctx.clone()), view_headers.clone()).await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a Viewer must not list user accounts"
    );

    let LoginResult::Success(oper_session) = ctx
        .auth_mgr
        .login("oper_user", "OperPass1", "127.0.0.1")
        .await
    else {
        panic!("operator login failed");
    };
    let resp = users_page(State(ctx.clone()), session_headers(&oper_session)).await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "an Operator must not list user accounts"
    );

    // /account is available to every authenticated role.
    let resp = account_page(State(ctx.clone()), view_headers).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let LoginResult::Success(admin_session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("admin login failed");
    };
    let resp = users_page(State(ctx.clone()), session_headers(&admin_session)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_users_create_role_delete_flow() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_users_flow_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let LoginResult::Success(session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("admin login failed");
    };
    let headers = session_headers(&session);

    // Weak passwords and invalid roles are rejected by the shared policy.
    let resp = users_create_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(CreateUserForm {
            username: "bob".to_string(),
            password: "short".to_string(),
            role: "viewer".to_string(),
            reauth_password: None,
            reauth_code: None,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(!ctx.auth_mgr.has_user("bob"));

    let resp = users_create_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(CreateUserForm {
            username: "  alice  ".to_string(),
            password: "AlicePassword1".to_string(),
            role: "operator".to_string(),
            reauth_password: None,
            reauth_code: None,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/users")
    );
    assert!(ctx.auth_mgr.has_user("alice"));
    assert_eq!(ctx.auth_mgr.role_of("alice"), Some(Role::Operator));

    // Duplicate creation is a conflict and does not overwrite the account.
    let resp = users_create_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(CreateUserForm {
            username: "alice".to_string(),
            password: "OtherPassword1".to_string(),
            role: "viewer".to_string(),
            reauth_password: None,
            reauth_code: None,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(ctx.auth_mgr.role_of("alice"), Some(Role::Operator));

    let resp = users_role_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Path("alice".to_string()),
        Form(UpdateUserRoleForm {
            role: "viewer".to_string(),
            reauth_password: Some("adminadmin".to_string()),
            reauth_code: None,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(ctx.auth_mgr.role_of("alice"), Some(Role::Viewer));

    let resp = users_delete_handler(
        State(ctx.clone()),
        headers.clone(),
        Path("alice".to_string()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(!ctx.auth_mgr.has_user("alice"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_users_last_admin_protected() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_users_last_admin_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let LoginResult::Success(session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("admin login failed");
    };
    let headers = session_headers(&session);

    let resp = users_role_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Path("admin".to_string()),
        Form(UpdateUserRoleForm {
            role: "viewer".to_string(),
            reauth_password: Some("adminadmin".to_string()),
            reauth_code: None,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_body(resp).await;
    assert!(
        body.contains("last remaining admin"),
        "visible error missing: {body}"
    );
    assert_eq!(ctx.auth_mgr.role_of("admin"), Some(Role::Admin));

    let resp = users_delete_handler(State(ctx.clone()), headers, Path("admin".to_string())).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_body(resp).await;
    assert!(
        body.contains("last remaining admin"),
        "visible error missing: {body}"
    );
    assert!(ctx.auth_mgr.has_user("admin"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_account_password_change() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_account_pw_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let LoginResult::Success(session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("admin login failed");
    };
    let headers = session_headers(&session);

    let resp = account_password_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(AccountPasswordForm {
            current_password: "wrong-password".to_string(),
            code: None,
            new_password: "NewAdminPassword1".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_body(resp).await;
    assert!(
        body.contains("Re-authentication failed: invalid password or second factor"),
        "{body}"
    );
    assert!(
        ctx.auth_mgr
            .verify_user_password("admin", "adminadmin")
            .await,
        "wrong current password must not change the password"
    );

    // WP-2.10: an oversized current password is rejected before Argon2 with a
    // visible validation error, matching the login/reauth length cap.
    let resp = account_password_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(AccountPasswordForm {
            current_password: "p".repeat(MAX_LOGIN_PASSWORD_BYTES + 1),
            code: None,
            new_password: "NewAdminPassword1".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_body(resp).await;
    assert!(
        body.contains("Current password must be at most"),
        "visible error missing: {body}"
    );
    assert!(
        ctx.auth_mgr
            .verify_user_password("admin", "adminadmin")
            .await,
        "an oversized current password must not change the password"
    );

    // Oversized TOTP/backup codes are rejected before the verifier.
    let resp = account_password_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(AccountPasswordForm {
            current_password: "adminadmin".to_string(),
            code: Some("1".repeat(MAX_TOTP_CODE_BYTES + 1)),
            new_password: "NewAdminPassword1".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_body(resp).await;
    assert!(body.contains("TOTP code must be at most"), "{body}");

    let resp = account_password_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers,
        Form(AccountPasswordForm {
            current_password: "  adminadmin  ".to_string(),
            code: None,
            new_password: "NewAdminPassword1".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(matches!(
        ctx.auth_mgr
            .login("admin", "NewAdminPassword1", "127.0.0.1")
            .await,
        LoginResult::Success(_)
    ));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// WP-2.10 review: the account-page password form goes through the shared
/// re-authentication lockout, so a stolen session cannot brute-force the
/// current password.
#[tokio::test]
async fn test_account_password_change_hits_lockout() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_account_pw_lockout_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    let LoginResult::Success(session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("admin login failed");
    };
    let headers = session_headers(&session);

    for attempt in 1..=crate::auth::lockout::MAX_FAILED_ATTEMPTS {
        let peer = Some(std::net::SocketAddr::from((
            [127, 0, 3, attempt as u8],
            7000 + attempt as u16,
        )));
        let resp = account_password_handler(
            State(ctx.clone()),
            crate::auth::MaybeConnectInfo(peer),
            headers.clone(),
            Form(AccountPasswordForm {
                current_password: "wrong-password".to_string(),
                code: None,
                new_password: format!("NewAdminPassword{}", attempt + 1),
            }),
        )
        .await;
        if attempt < crate::auth::lockout::MAX_FAILED_ATTEMPTS {
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        } else {
            assert_eq!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "the threshold-crossing attempt must be the lockout"
            );
        }
    }

    let resp = account_password_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(Some(std::net::SocketAddr::from(([127, 0, 4, 1], 8000)))),
        headers,
        Form(AccountPasswordForm {
            current_password: "adminadmin".to_string(),
            code: None,
            new_password: "NewAdminPassword1".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        ctx.auth_mgr
            .verify_user_password("admin", "adminadmin")
            .await,
        "the locked account password must remain unchanged"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// WP-2.10: a TOTP-enrolled account must supply a current code to change its
/// password from the account page.
#[tokio::test]
async fn test_account_password_change_requires_totp_code() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_account_pw_totp_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    ctx.auth_mgr
        .create_user("alice", "AlicePassword1", Role::Operator)
        .await;
    let setup = ctx.auth_mgr.init_totp_setup("alice").await.expect("setup");
    assert!(
        ctx.auth_mgr
            .confirm_totp_setup("alice", &setup.backup_codes[0])
            .await
    );

    let LoginResult::TotpRequired { partial_token } = ctx
        .auth_mgr
        .login("alice", "AlicePassword1", "127.0.0.1")
        .await
    else {
        panic!("TOTP challenge expected");
    };
    let crate::auth::manager::TotpVerifyResult::Success(session) = ctx
        .auth_mgr
        .verify_totp(&partial_token, &setup.backup_codes[1], "127.0.0.1")
        .await
    else {
        panic!("TOTP verification failed");
    };
    let headers = session_headers(&session);

    let missing = account_password_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(AccountPasswordForm {
            current_password: "AlicePassword1".to_string(),
            code: None,
            new_password: "AlicePassword2".to_string(),
        }),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

    let wrong = account_password_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(AccountPasswordForm {
            current_password: "AlicePassword1".to_string(),
            code: Some("000000".to_string()),
            new_password: "AlicePassword2".to_string(),
        }),
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    assert!(
        ctx.auth_mgr
            .verify_user_password("alice", "AlicePassword1")
            .await
    );

    let changed = account_password_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers,
        Form(AccountPasswordForm {
            current_password: "AlicePassword1".to_string(),
            code: Some(setup.backup_codes[2].clone()),
            new_password: "AlicePassword2".to_string(),
        }),
    )
    .await;
    assert_eq!(changed.status(), StatusCode::SEE_OTHER);
    assert!(
        ctx.auth_mgr
            .verify_user_password("alice", "AlicePassword2")
            .await
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// WP-2.10: role changes and Admin creation from the users page require the
/// caller's password (and TOTP code when enabled).
#[tokio::test]
async fn test_users_role_change_requires_reauth() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_users_reauth_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    ctx.auth_mgr
        .create_user("alice", "AlicePassword1", Role::Viewer)
        .await;

    let LoginResult::Success(session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("admin login failed");
    };
    let headers = session_headers(&session);

    let no_proof = users_role_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Path("alice".to_string()),
        Form(UpdateUserRoleForm {
            role: "operator".to_string(),
            reauth_password: None,
            reauth_code: None,
        }),
    )
    .await;
    assert_eq!(no_proof.status(), StatusCode::BAD_REQUEST);
    assert_eq!(ctx.auth_mgr.role_of("alice"), Some(Role::Viewer));

    let changed = users_role_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Path("alice".to_string()),
        Form(UpdateUserRoleForm {
            role: "operator".to_string(),
            reauth_password: Some("adminadmin".to_string()),
            reauth_code: None,
        }),
    )
    .await;
    assert_eq!(changed.status(), StatusCode::SEE_OTHER);
    assert_eq!(ctx.auth_mgr.role_of("alice"), Some(Role::Operator));

    // Creating an Admin account requires the same proof.
    let no_proof = users_create_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(CreateUserForm {
            username: "newadmin".to_string(),
            password: "NewAdminPass1".to_string(),
            role: "admin".to_string(),
            reauth_password: None,
            reauth_code: None,
        }),
    )
    .await;
    assert_eq!(no_proof.status(), StatusCode::BAD_REQUEST);
    assert!(!ctx.auth_mgr.has_user("newadmin"));

    let created = users_create_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers,
        Form(CreateUserForm {
            username: "newadmin".to_string(),
            password: "NewAdminPass1".to_string(),
            role: "admin".to_string(),
            reauth_password: Some("adminadmin".to_string()),
            reauth_code: None,
        }),
    )
    .await;
    assert_eq!(created.status(), StatusCode::SEE_OTHER);
    assert_eq!(ctx.auth_mgr.role_of("newadmin"), Some(Role::Admin));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// WP-2.10: minting an Admin-scoped token from the account page requires
/// re-authentication; lower scopes do not.
#[tokio::test]
async fn test_account_admin_token_requires_reauth() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_admin_token_reauth_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    let LoginResult::Success(session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("admin login failed");
    };
    let headers = session_headers(&session);

    let no_proof = account_token_create_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(CreateAccountTokenForm {
            name: "admin-scoped".to_string(),
            scope: "admin".to_string(),
            reauth_password: None,
            reauth_code: None,
            expires_in_days: None,
        }),
    )
    .await;
    assert_eq!(no_proof.status(), StatusCode::BAD_REQUEST);
    assert!(ctx.auth_mgr.list_tokens().is_empty());

    let created = account_token_create_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers,
        Form(CreateAccountTokenForm {
            name: "admin-scoped".to_string(),
            scope: "admin".to_string(),
            reauth_password: Some("adminadmin".to_string()),
            reauth_code: None,
            expires_in_days: None,
        }),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    assert_eq!(ctx.auth_mgr.list_tokens().len(), 1);
    assert_eq!(ctx.auth_mgr.list_tokens()[0].scope, Role::Admin);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_account_tokens_create_and_revoke() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_account_tokens_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let LoginResult::Success(session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("admin login failed");
    };
    let headers = session_headers(&session);

    let resp = account_token_create_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(CreateAccountTokenForm {
            name: "  ci-deploy  ".to_string(),
            scope: "viewer".to_string(),
            reauth_password: None,
            reauth_code: None,
            expires_in_days: None,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body(resp).await;
    let plaintext = body
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .find(|part| part.starts_with("sito_") && part.len() == 69)
        .expect("plaintext token must be rendered")
        .to_string();
    assert!(body.contains("ci-deploy"));
    assert!(
        body.contains("only time"),
        "one-time warning missing: {body}"
    );

    let tokens = ctx.auth_mgr.list_tokens();
    assert_eq!(tokens.len(), 1);
    assert_eq!(
        tokens[0].name, "ci-deploy",
        "the token name must be stored exactly as trimmed"
    );
    let token_id = tokens[0].id.clone();
    assert!(
        !body.contains(&tokens[0].hash),
        "the stored token hash must never be rendered"
    );

    // Reloading the account page lists metadata only, not the plaintext.
    let resp = account_page(State(ctx.clone()), headers.clone()).await;
    let reloaded = response_body(resp).await;
    assert!(
        !reloaded.contains(&plaintext),
        "plaintext token must not survive the one-time response: {reloaded}"
    );
    assert!(reloaded.contains("ci-deploy"));

    let resp = account_token_delete_handler(State(ctx.clone()), headers, Path(token_id)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(ctx.auth_mgr.list_tokens().is_empty());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_account_token_create_form_applies_expiry() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_token_expiry_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let LoginResult::Success(session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("admin login failed");
    };
    let headers = session_headers(&session);

    // The rendered form exposes the optional lifetime field.
    let page = response_body(account_page(State(ctx.clone()), headers.clone()).await).await;
    assert!(page.contains("name=\"expires_in_days\""));
    assert!(page.contains("Expires In (days)"));

    // An explicit lifetime is applied and the token stays owned by the user.
    let resp = account_token_create_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(CreateAccountTokenForm {
            name: "seven-days".to_string(),
            scope: "viewer".to_string(),
            reauth_password: None,
            reauth_code: None,
            expires_in_days: Some("7".to_string()),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let token = ctx
        .auth_mgr
        .list_tokens()
        .into_iter()
        .find(|token| token.name == "seven-days")
        .expect("token listed");
    assert_eq!(token.owner.as_deref(), Some("admin"));
    let remaining_days =
        (token.expires_at.expect("expiry") - chrono::Utc::now().timestamp()) / 86_400;
    assert_eq!(remaining_days, 7);

    // A malformed value is a 400 and creates nothing.
    let resp = account_token_create_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(CreateAccountTokenForm {
            name: "typo".to_string(),
            scope: "viewer".to_string(),
            reauth_password: None,
            reauth_code: None,
            expires_in_days: Some("next-week".to_string()),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        !ctx.auth_mgr
            .list_tokens()
            .iter()
            .any(|token| token.name == "typo")
    );

    // With no configured maximum (`0` in the mock manager), `0` means no
    // expiry.
    let resp = account_token_create_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers,
        Form(CreateAccountTokenForm {
            name: "forever".to_string(),
            scope: "viewer".to_string(),
            reauth_password: None,
            reauth_code: None,
            expires_in_days: Some("0".to_string()),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let forever = ctx
        .auth_mgr
        .list_tokens()
        .into_iter()
        .find(|token| token.name == "forever")
        .expect("token listed");
    assert!(forever.expires_at.is_none());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_account_token_empty_table_colspan_matches_role() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_token_colspan_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    ctx.auth_mgr
        .create_user("view_user", "ViewerPass1", Role::Viewer)
        .await;

    let LoginResult::Success(view_session) = ctx
        .auth_mgr
        .login("view_user", "ViewerPass1", "127.0.0.1")
        .await
    else {
        panic!("viewer login failed");
    };
    let body =
        response_body(account_page(State(ctx.clone()), session_headers(&view_session)).await).await;
    assert!(
        body.contains("colspan=\"6\""),
        "non-Admins have six token columns: {body}"
    );
    assert!(
        !body.contains("colspan=\"7\""),
        "the empty-state span must not count the hidden Owner column: {body}"
    );

    let LoginResult::Success(admin_session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("admin login failed");
    };
    let body =
        response_body(account_page(State(ctx.clone()), session_headers(&admin_session)).await)
            .await;
    assert!(
        body.contains("colspan=\"7\""),
        "Admins have seven token columns: {body}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_account_token_scope_capped_at_user_role() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_token_scope_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    ctx.auth_mgr
        .create_user("view_user", "ViewerPass1", Role::Viewer)
        .await;
    let LoginResult::Success(session) = ctx
        .auth_mgr
        .login("view_user", "ViewerPass1", "127.0.0.1")
        .await
    else {
        panic!("viewer login failed");
    };
    let headers = session_headers(&session);

    let resp = account_token_create_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(CreateAccountTokenForm {
            name: "escalation".to_string(),
            scope: "admin".to_string(),
            reauth_password: Some("adminadmin".to_string()),
            reauth_code: None,
            expires_in_days: None,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        ctx.auth_mgr.list_tokens().is_empty(),
        "a Viewer must not mint an Admin token"
    );

    let resp = account_token_create_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers,
        Form(CreateAccountTokenForm {
            name: "read-only".to_string(),
            scope: "viewer".to_string(),
            reauth_password: None,
            reauth_code: None,
            expires_in_days: None,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(ctx.auth_mgr.list_tokens().len(), 1);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_account_tokens_are_per_owner() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_token_owner_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    ctx.auth_mgr
        .create_user("oper_user", "OperPass1", Role::Operator)
        .await;
    ctx.auth_mgr
        .create_user("view_user", "ViewerPass1", Role::Viewer)
        .await;

    let (oper_token, _) = ctx
        .auth_mgr
        .create_token("oper-token", Role::Operator, Some("oper_user"))
        .await
        .expect("operator token");
    let (admin_token, _) = ctx
        .auth_mgr
        .create_token("admin-token", Role::Admin, Some("admin"))
        .await
        .expect("admin token");
    let (legacy_token, _) = ctx
        .auth_mgr
        .create_token("legacy-token", Role::Viewer, None)
        .await
        .expect("legacy token");
    let (viewer_token, _) = ctx
        .auth_mgr
        .create_token("viewer-token", Role::Viewer, Some("view_user"))
        .await
        .expect("viewer token");

    let LoginResult::Success(view_session) = ctx
        .auth_mgr
        .login("view_user", "ViewerPass1", "127.0.0.1")
        .await
    else {
        panic!("viewer login failed");
    };
    let view_headers = session_headers(&view_session);

    let resp = account_page(State(ctx.clone()), view_headers.clone()).await;
    let body = response_body(resp).await;
    assert!(body.contains("viewer-token"));
    assert!(!body.contains("oper-token"));
    assert!(!body.contains("admin-token"));
    assert!(!body.contains("legacy-token"));
    assert!(
        !body.contains("<th>Owner</th>"),
        "non-admins must not see the owner column"
    );

    // Viewer cannot revoke an Operator, Admin, or legacy token, and the
    // response is indistinguishable from a missing token.
    for foreign_id in [&oper_token.id, &admin_token.id, &legacy_token.id] {
        let resp = account_token_delete_handler(
            State(ctx.clone()),
            view_headers.clone(),
            Path(foreign_id.clone()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(
            ctx.auth_mgr
                .list_tokens()
                .iter()
                .any(|token| &token.id == foreign_id),
            "a foreign token must survive a Viewer revoke attempt"
        );
    }

    let resp = account_token_delete_handler(
        State(ctx.clone()),
        view_headers,
        Path(viewer_token.id.clone()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        !ctx.auth_mgr
            .list_tokens()
            .iter()
            .any(|token| token.id == viewer_token.id)
    );

    // An Operator also cannot revoke an Admin token or a legacy token.
    let LoginResult::Success(oper_session) = ctx
        .auth_mgr
        .login("oper_user", "OperPass1", "127.0.0.1")
        .await
    else {
        panic!("operator login failed");
    };
    let oper_headers = session_headers(&oper_session);
    for foreign_id in [&admin_token.id, &legacy_token.id] {
        let resp = account_token_delete_handler(
            State(ctx.clone()),
            oper_headers.clone(),
            Path(foreign_id.clone()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(
            ctx.auth_mgr
                .list_tokens()
                .iter()
                .any(|token| &token.id == foreign_id)
        );
    }
    let resp = account_page(State(ctx.clone()), oper_headers).await;
    let body = response_body(resp).await;
    assert!(body.contains("oper-token"));
    assert!(!body.contains("admin-token"));
    assert!(!body.contains("legacy-token"));

    // The Admin sees their own tokens plus legacy ownerless tokens, never
    // another account's tokens, and may revoke the legacy ones.
    let LoginResult::Success(admin_session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("admin login failed");
    };
    let admin_headers = session_headers(&admin_session);
    let resp = account_page(State(ctx.clone()), admin_headers.clone()).await;
    let body = response_body(resp).await;
    assert!(body.contains("admin-token"));
    assert!(body.contains("legacy-token"));
    assert!(!body.contains("oper-token"));
    assert!(body.contains("<th>Owner</th>"));

    // Admin privilege does not extend to another account's owned token:
    // the response is indistinguishable from a missing token and the
    // token survives.
    let resp = account_token_delete_handler(
        State(ctx.clone()),
        admin_headers.clone(),
        Path(oper_token.id.clone()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(
        ctx.auth_mgr
            .list_tokens()
            .iter()
            .any(|token| token.id == oper_token.id),
        "an Admin must not revoke another user's owned token"
    );

    let resp = account_token_delete_handler(
        State(ctx.clone()),
        admin_headers,
        Path(legacy_token.id.clone()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        !ctx.auth_mgr
            .list_tokens()
            .iter()
            .any(|token| token.id == legacy_token.id)
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_format_token_expiry_uses_seconds() {
    assert_eq!(
        format_token_expiry_timestamp(Some(1_800_000_000)),
        "2027-01-15 08:00 UTC"
    );
    assert_eq!(format_token_expiry_timestamp(None), "—");
}

#[tokio::test]
async fn test_account_totp_disable() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_ui_account_totp_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let setup = ctx.auth_mgr.init_totp_setup("admin").await.expect("setup");
    assert!(
        ctx.auth_mgr
            .confirm_totp_setup("admin", &setup.backup_codes[0])
            .await
    );
    assert!(ctx.auth_mgr.totp_enabled("admin"));

    // Enabling TOTP revokes the old session, and logging in now needs a
    // second factor. Use a backup code to obtain a real session.
    let LoginResult::TotpRequired { partial_token } =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("TOTP login should require a second factor");
    };
    let crate::auth::manager::TotpVerifyResult::Success(session) = ctx
        .auth_mgr
        .verify_totp(&partial_token, &setup.backup_codes[1], "127.0.0.1")
        .await
    else {
        panic!("TOTP verification failed");
    };
    let headers = session_headers(&session);

    let resp = account_totp_disable_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(DisableAccountTotpForm {
            password: "wrong-password".to_string(),
            code: Some(setup.backup_codes[2].clone()),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(ctx.auth_mgr.totp_enabled("admin"));

    let resp = account_totp_disable_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers.clone(),
        Form(DisableAccountTotpForm {
            password: "adminadmin".to_string(),
            code: None,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_body(resp).await;
    assert!(body.contains("TOTP or backup code is required"), "{body}");
    assert!(ctx.auth_mgr.totp_enabled("admin"));

    let resp = account_totp_disable_handler(
        State(ctx.clone()),
        crate::auth::MaybeConnectInfo(None),
        headers,
        Form(DisableAccountTotpForm {
            password: "adminadmin".to_string(),
            code: Some(setup.backup_codes[2].clone()),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        !ctx.auth_mgr.totp_enabled("admin"),
        "TOTP status must flip to disabled"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

fn extract_attr(body: &str, needle: &str) -> String {
    let start = body
        .find(needle)
        .unwrap_or_else(|| panic!("missing {needle} in {body}"))
        + needle.len();
    let end = body[start..].find('"').expect("attribute terminator");
    body[start..start + end].to_string()
}

fn extract_first_backup_code(body: &str) -> String {
    let marker = "class=\"totp-backup-code\"";
    let start = body.find(marker).expect("backup code marker") + marker.len();
    let start = body[start..].find('>').expect("backup code start") + start + 1;
    let end = body[start..].find("</code>").expect("backup code end") + start;
    body[start..end].trim().to_string()
}

/// WP-0.7 (P2-52): TOTP enrollment works in the Account UI for Viewer,
/// Operator, and Admin, and requires the current password.
#[tokio::test]
async fn test_self_service_totp_enrollment_for_all_roles() {
    for (username, role, password) in [
        ("admin", Role::Admin, "adminadmin"),
        ("oper_user", Role::Operator, "OperPass1"),
        ("view_user", Role::Viewer, "ViewPass1"),
    ] {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito_ui_totp_enroll_{}_{}",
            username,
            rand::random::<u64>()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ctx = mock_context(&temp_dir).await;
        if role != Role::Admin {
            ctx.auth_mgr.create_user(username, password, role).await;
        }
        let LoginResult::Success(session) =
            ctx.auth_mgr.login(username, password, "127.0.0.1").await
        else {
            panic!("{username} login failed");
        };
        let headers = session_headers(&session);

        // Negative counterpart: a fresh user's account page still offers
        // the enrollment starter form.
        let resp = account_page(State(ctx.clone()), headers.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body(resp).await;
        assert!(
            body.contains("Begin TOTP Setup"),
            "{username} must see the starter form before enrolling: {body}"
        );
        assert!(
            body.contains("action=\"/ui/account/totp/setup\""),
            "{username} must be able to start enrollment: {body}"
        );

        // A stolen session without the password cannot enroll.
        let resp = account_totp_setup_handler(
            State(ctx.clone()),
            crate::auth::MaybeConnectInfo(None),
            headers.clone(),
            Form(AccountTotpSetupForm {
                password: "wrong-password".to_string(),
                code: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(!ctx.auth_mgr.totp_enabled(username));

        let resp = account_totp_setup_handler(
            State(ctx.clone()),
            crate::auth::MaybeConnectInfo(None),
            headers.clone(),
            Form(AccountTotpSetupForm {
                password: password.to_string(),
                code: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_body(resp).await;
        assert!(
            body.contains("Confirm TOTP Enrollment"),
            "{username} must see the enrollment form: {body}"
        );
        // Deferred D5: the pending enrollment replaces the starter form.
        // Rendering both lets the user POST /ui/account/totp/setup again,
        // which invalidates the secret already displayed above.
        assert!(
            !body.contains("Begin TOTP Setup"),
            "{username} must not see the starter form during pending enrollment: {body}"
        );
        assert!(
            !body.contains("action=\"/ui/account/totp/setup\""),
            "the starter setup form must be suppressed while enrollment is pending"
        );
        let reauth_token = extract_attr(&body, "name=\"reauth_token\" value=\"");
        let backup_code = extract_first_backup_code(&body);

        let resp = account_totp_enable_handler(
            State(ctx.clone()),
            headers,
            Form(AccountTotpEnableForm {
                reauth_token,
                code: backup_code,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(
            ctx.auth_mgr.totp_enabled(username),
            "{username} must be able to enable TOTP self-service"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

/// WP-2.10: an unchecked wizard checkbox must actively disable a feature
/// that was already enabled, not leave the old value in place.
#[tokio::test]
async fn test_wizard_unchecked_flags_disable_existing_features() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_wizard_unchecked_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let mut cfg = (**ctx.config.load()).clone();
    cfg.dns.cache.enabled = true;
    cfg.dns.dnssec.validate = true;
    cfg.filtering.enabled = true;
    cfg.filtering.cname_cloaking = true;
    ctx.set_config(cfg);

    // The hidden sentinels are present while the checkboxes themselves are
    // absent, exactly as a browser submits an unchecked checkbox.
    let form = WizardCompleteForm {
        admin_user: Some("admin".to_string()),
        admin_password: Some("Str0ngPassword!".to_string()),
        cache_enabled_present: Some("1".to_string()),
        filtering_enabled_present: Some("1".to_string()),
        dnssec_validate_present: Some("1".to_string()),
        cname_cloaking_present: Some("1".to_string()),
        ..Default::default()
    };
    let resp = wizard_complete_handler(
        State(ctx.clone()),
        Extension(ApplyHooks::default()),
        crate::auth::MaybeConnectInfo(None),
        HeaderMap::new(),
        Form(form),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let cfg = ctx.config.load();
    assert!(!cfg.dns.cache.enabled, "unchecked cache must disable it");
    assert!(
        !cfg.filtering.enabled,
        "unchecked filtering must disable it"
    );
    assert!(
        !cfg.dns.dnssec.validate,
        "unchecked DNSSEC validation must disable it"
    );
    assert!(
        !cfg.filtering.cname_cloaking,
        "unchecked CNAME cloaking must disable it"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// WP-2.10: weighted upstream balancing is not implemented yet (WP-2.11),
/// so the upstream page must not offer a weight control or column.
#[tokio::test]
async fn test_upstreams_page_has_no_unsupported_weight_control() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_upstreams_weight_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    let LoginResult::Success(session) =
        ctx.auth_mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("admin login failed");
    };
    let body =
        response_body(upstreams_page(State(ctx.clone()), session_headers(&session)).await).await;
    assert!(
        !body.contains("Load Balancing Weight"),
        "the unimplemented weight input must not be offered: {body}"
    );
    assert!(
        !body.contains("name=\"weight\""),
        "no weight field may be submitted: {body}"
    );
    assert!(
        !body.contains("id=\"up-weight\""),
        "the old weight control id must be gone: {body}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ---------------------------------------------------------------------------
// Blocked services per client group (F2c1)
// ---------------------------------------------------------------------------

fn clients_group_with_services(
    services: Vec<sito_clients::BlockedServiceConfig>,
) -> sito_clients::ClientGroupConfig {
    sito_clients::ClientGroupConfig {
        description: Some("Kids devices".to_string()),
        custom_rules: vec!["||custom.example^".to_string()],
        safe_search: true,
        parental: true,
        parental_categories: vec!["adult".to_string()],
        blocked_services: services,
        ..Default::default()
    }
}

fn seed_clients_config(ctx: &ServerContext, clients: &sito_clients::ClientsConfig) {
    let mut cfg = (**ctx.config.load()).clone();
    cfg.clients = Some(toml::Value::try_from(clients).unwrap());
    ctx.set_config(cfg);
}

fn blocked_service_ids(group: &sito_clients::ClientGroupConfig) -> Vec<&str> {
    group
        .blocked_services
        .iter()
        .map(|blocked| blocked.service.as_str())
        .collect()
}

async fn operator_form_headers(ctx: &ServerContext) -> HeaderMap {
    ctx.auth_mgr
        .create_user("oper_user", "pass", Role::Operator)
        .await;
    let LoginResult::Success(session) = ctx.auth_mgr.login("oper_user", "pass", "127.0.0.1").await
    else {
        panic!("operator login failed");
    };
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, session.to_cookie_header().parse().unwrap());
    headers
}

#[test]
fn test_clients_service_views_groups_and_catalog() {
    let mut clients = sito_clients::ClientsConfig::default();
    clients.groups.insert(
        "kids".to_string(),
        clients_group_with_services(vec![
            sito_clients::BlockedServiceConfig {
                service: "tiktok".to_string(),
                schedule: Some(sito_clients::Schedule::parse("0 8 * * *").unwrap()),
            },
            sito_clients::BlockedServiceConfig {
                service: "netflix".to_string(),
                schedule: None,
            },
            // A duplicate configured entry must render once.
            sito_clients::BlockedServiceConfig {
                service: "tiktok".to_string(),
                schedule: None,
            },
        ]),
    );
    clients.groups.insert(
        "adults".to_string(),
        clients_group_with_services(Vec::new()),
    );

    let catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");
    let registry =
        sito_clients::ServiceRegistry::try_bundled().expect("bundled registry must be valid");
    let views = clients_service_views_from(&clients, Ok(catalog.clone()), Some(&registry));

    assert_eq!(
        views
            .groups
            .iter()
            .map(|group| group.name.as_str())
            .collect::<Vec<_>>(),
        vec!["default", "adults", "kids"],
        "the implied default must sort first, then group names"
    );
    assert!(views.groups[0].is_default);
    assert!(
        views.groups[0].blocked_services.is_empty(),
        "the implied default has no configured services"
    );
    let kids = views
        .groups
        .iter()
        .find(|group| group.name == "kids")
        .expect("kids group must render");
    assert_eq!(
        kids.blocked_services
            .iter()
            .map(|blocked| blocked.service.as_str())
            .collect::<Vec<_>>(),
        vec!["tiktok", "netflix"],
        "configured order is kept and duplicates are collapsed"
    );
    assert_eq!(
        kids.blocked_services[0].schedule.as_deref(),
        Some("0 8 * * *")
    );
    assert_eq!(kids.blocked_services[1].schedule, None);

    assert_eq!(views.catalog_service_count, catalog.services.len());
    assert_ne!(views.catalog_groups.len(), 0);
    let mut previous_group = "";
    let mut service_count = 0;
    for group in &views.catalog_groups {
        assert!(
            group.id.as_str() > previous_group,
            "catalog groups must be in stable sorted order"
        );
        previous_group = &group.id;
        let mut previous_name = String::new();
        for service in &group.services {
            assert_eq!(service.group, group.id, "a service stays in its group");
            assert!(
                service.available,
                "every embedded catalog service must be selectable: {}",
                service.id
            );
            let sort_key = service.name.to_lowercase();
            assert!(
                sort_key >= previous_name,
                "services must be sorted by display name within a group"
            );
            previous_name = sort_key;
            service_count += 1;
        }
    }
    assert_eq!(service_count, catalog.services.len());

    let tiktok = views
        .catalog_groups
        .iter()
        .flat_map(|group| &group.services)
        .find(|service| service.id == "tiktok")
        .expect("tiktok must be in the catalog");
    let tiktok_catalog = catalog.service_by_id("tiktok").expect("tiktok metadata");
    assert_eq!(tiktok.name, tiktok_catalog.name);
    assert_eq!(tiktok.rule_count, tiktok_catalog.rules.len());
    assert!(tiktok.available);

    // A catalog-only id (not in the minimal bundled services.json) is offered.
    let catalog_only = views
        .catalog_groups
        .iter()
        .flat_map(|group| &group.services)
        .find(|service| service.id == "4chan")
        .expect("catalog-only services must render");
    assert!(
        catalog_only.available,
        "catalog-only services must be selectable: {catalog_only:?}"
    );

    // The iCloud Private Relay service uses `$dnsrewrite=NXDOMAIN` rules; it
    // must still be available with all three literal domains.
    let icloud = views
        .catalog_groups
        .iter()
        .flat_map(|group| &group.services)
        .find(|service| service.id == "icloud_private_relay")
        .expect("icloud_private_relay must be in the catalog");
    assert!(icloud.available);
    assert_eq!(icloud.rule_count, 3);
}

#[test]
fn test_clients_service_views_marks_zero_rule_catalog_service_unavailable() {
    let mut catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");
    let group = catalog.service_groups[0].clone();
    catalog.services.push(sito_clients::CatalogService {
        id: "zero_rule_candidate".to_string(),
        name: "Zero rule candidate".to_string(),
        group,
        rules: vec![
            "/regex-only/".to_string(),
            "*.wild.example".to_string(),
            "||mask.example^$dnsrewrite=NOERROR;;".to_string(),
        ],
    });

    let registry =
        sito_clients::ServiceRegistry::try_bundled().expect("bundled registry must be valid");
    let views = clients_service_views_from(
        &sito_clients::ClientsConfig::default(),
        Ok(catalog),
        Some(&registry),
    );

    let zero = views
        .catalog_groups
        .iter()
        .flat_map(|group| &group.services)
        .find(|service| service.id == "zero_rule_candidate")
        .expect("the synthetic catalog service must render");
    assert!(
        !zero.available,
        "a catalog service with zero usable rules must be unavailable"
    );
    assert!(
        views
            .catalog_groups
            .iter()
            .flat_map(|group| &group.services)
            .filter(|service| service.id != "zero_rule_candidate")
            .all(|service| service.available),
        "real catalog services with usable rules stay available"
    );
}

#[test]
fn test_clients_service_views_corrupt_catalog_degrades() {
    let mut clients = sito_clients::ClientsConfig::default();
    clients.groups.insert(
        "kids".to_string(),
        clients_group_with_services(vec![sito_clients::BlockedServiceConfig {
            service: "tiktok".to_string(),
            schedule: None,
        }]),
    );
    let corrupt = sito_clients::Catalog::parse("{ not json")
        .expect_err("fixture must be invalid catalog JSON");

    let views = clients_service_views_from(&clients, Err(corrupt), None);
    assert_eq!(
        views
            .groups
            .iter()
            .map(|group| group.name.as_str())
            .collect::<Vec<_>>(),
        vec!["default", "kids"],
        "configured groups still render when the catalog is corrupt"
    );
    assert_eq!(views.catalog_groups.len(), 0);
    assert_eq!(views.catalog_service_count, 0);
}

#[test]
fn test_parse_group_services_form_reads_only_group_and_selected() {
    let pairs = vec![
        ("csrf_token".to_string(), "ignored".to_string()),
        ("group".to_string(), " kids ".to_string()),
        ("selected".to_string(), " tiktok ".to_string()),
        ("selected".to_string(), String::new()),
        ("selected".to_string(), "netflix".to_string()),
        ("name".to_string(), "client-supplied-name".to_string()),
        ("rules".to_string(), "||evil.example^".to_string()),
    ];
    let parsed = parse_group_services_form(&pairs).expect("valid form");
    assert_eq!(parsed.group, "kids");
    assert_eq!(parsed.selected, vec!["tiktok", "netflix"]);
    assert_eq!(
        parse_group_services_form(&[("selected".to_string(), "tiktok".to_string())]),
        Err(GroupServicesError::MissingGroup)
    );
    assert_eq!(
        parse_group_services_form(&[
            ("group".to_string(), "kids".to_string()),
            ("group".to_string(), "adults".to_string()),
        ]),
        Err(GroupServicesError::ConflictingGroup)
    );
}

#[tokio::test]
async fn test_clients_group_services_handler_adds_and_removes() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_group_services_add_remove_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let mut clients = sito_clients::ClientsConfig::default();
    clients.groups.insert(
        "kids".to_string(),
        clients_group_with_services(vec![
            sito_clients::BlockedServiceConfig {
                service: "tiktok".to_string(),
                schedule: None,
            },
            sito_clients::BlockedServiceConfig {
                service: "netflix".to_string(),
                schedule: None,
            },
            sito_clients::BlockedServiceConfig {
                service: "youtube".to_string(),
                schedule: None,
            },
        ]),
    );
    seed_clients_config(&ctx, &clients);
    let headers = operator_form_headers(&ctx).await;

    let pairs = vec![
        ("csrf_token".to_string(), "ignored".to_string()),
        ("group".to_string(), "kids".to_string()),
        ("selected".to_string(), "tiktok".to_string()),
        // A catalog-only service (not in bundled services.json) must be
        // accepted and persisted.
        ("selected".to_string(), "4chan".to_string()),
    ];
    let resp = clients_group_services_handler(State(ctx.clone()), headers, Form(pairs)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let after = load_clients_config(&ctx);
    let kids = after.groups.get("kids").expect("kids group must remain");
    assert_eq!(
        blocked_service_ids(kids),
        vec!["tiktok", "4chan"],
        "deselected services are removed and new catalog-only services appended"
    );
    assert!(
        kids.blocked_services
            .iter()
            .all(|blocked| blocked.schedule.is_none()),
        "new services start without a schedule"
    );
    // Every other group field is untouched.
    assert_eq!(kids.description.as_deref(), Some("Kids devices"));
    assert_eq!(kids.custom_rules, vec!["||custom.example^".to_string()]);
    assert!(kids.safe_search);
    assert!(kids.parental);
    assert_eq!(kids.parental_categories, vec!["adult".to_string()]);
    assert!(
        ctx.config_path.exists(),
        "a successful selection must persist config.toml"
    );
    let persisted = std::fs::read_to_string(&ctx.config_path).expect("persisted config.toml");
    assert!(
        persisted.contains("service = \"4chan\""),
        "the selected catalog-only service must be persisted in blocked_services: {persisted}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_group_services_route_preserves_repeated_selected_fields_through_csrf() {
    use axum::body::Body;
    use axum::http::{Request, header};
    use tower::ServiceExt;

    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_group_services_route_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    // Clear the bootstrap state so the setup middleware lets the request
    // reach the normal UI route and CSRF layer.
    ctx.auth_mgr
        .update_user_password("admin", "TestPassword123!")
        .await;
    ctx.set_setup_pending(false);

    let mut clients = sito_clients::ClientsConfig::default();
    clients.groups.insert(
        "kids".to_string(),
        clients_group_with_services(vec![sito_clients::BlockedServiceConfig {
            service: "tiktok".to_string(),
            schedule: None,
        }]),
    );
    seed_clients_config(&ctx, &clients);

    ctx.auth_mgr
        .create_user("oper_user", "pass", Role::Operator)
        .await;
    let LoginResult::Success(session) = ctx.auth_mgr.login("oper_user", "pass", "127.0.0.1").await
    else {
        panic!("operator login failed");
    };
    let cookie = format!(
        "{}; {}",
        session.to_cookie_header_secure(false),
        crate::auth::session::build_csrf_cookie(&session.csrf_token, 3600, false)
    );
    let body = format!(
        "csrf_token={}&group=kids&selected=tiktok&selected=netflix",
        session.csrf_token
    );
    let app = crate::create_router(ctx.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/clients/group-services")
                .header(header::HOST, "localhost")
                .header(header::ORIGIN, "http://localhost")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let after = load_clients_config(&ctx);
    let kids = after.groups.get("kids").expect("kids group must remain");
    assert_eq!(
        blocked_service_ids(kids),
        vec!["tiktok", "netflix"],
        "both repeated selected fields must survive the CSRF body buffering"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_clients_group_services_handler_preserves_schedules() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_group_services_schedule_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let mut clients = sito_clients::ClientsConfig::default();
    clients.groups.insert(
        "kids".to_string(),
        clients_group_with_services(vec![
            sito_clients::BlockedServiceConfig {
                service: "tiktok".to_string(),
                schedule: Some(sito_clients::Schedule::parse("0 8 * * *").unwrap()),
            },
            sito_clients::BlockedServiceConfig {
                service: "netflix".to_string(),
                schedule: Some(sito_clients::Schedule::parse("0 9 * * *").unwrap()),
            },
        ]),
    );
    seed_clients_config(&ctx, &clients);
    let headers = operator_form_headers(&ctx).await;

    let pairs = vec![
        ("group".to_string(), "kids".to_string()),
        ("selected".to_string(), "tiktok".to_string()),
        ("selected".to_string(), "netflix".to_string()),
        ("selected".to_string(), "youtube".to_string()),
    ];
    let resp = clients_group_services_handler(State(ctx.clone()), headers, Form(pairs)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let after = load_clients_config(&ctx);
    let kids = after.groups.get("kids").expect("kids group must remain");
    assert_eq!(
        blocked_service_ids(kids),
        vec!["tiktok", "netflix", "youtube"],
        "retained services keep their configured order; new ones append"
    );
    assert_eq!(
        kids.blocked_services[0]
            .schedule
            .as_ref()
            .map(sito_clients::Schedule::as_str),
        Some("0 8 * * *"),
        "a retained service must keep its schedule"
    );
    assert_eq!(
        kids.blocked_services[1]
            .schedule
            .as_ref()
            .map(sito_clients::Schedule::as_str),
        Some("0 9 * * *"),
        "every retained service keeps its own schedule"
    );
    assert!(
        kids.blocked_services[2].schedule.is_none(),
        "a newly selected service must not inherit a schedule"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_group_blocked_services_matches_ids_case_insensitively() {
    let catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");
    let registry =
        sito_clients::ServiceRegistry::try_bundled().expect("bundled registry must be valid");
    let existing = vec![sito_clients::BlockedServiceConfig {
        service: "TikTok".to_string(),
        schedule: Some(sito_clients::Schedule::parse("0 8 * * *").unwrap()),
    }];

    let merged = group_blocked_services(&existing, &["tiktok".to_string()], &catalog, &registry)
        .expect("a case variant of a configured service must be accepted");
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].service, "TikTok");
    assert_eq!(
        merged[0]
            .schedule
            .as_ref()
            .map(sito_clients::Schedule::as_str),
        Some("0 8 * * *"),
        "a retained entry keeps its schedule even when the form id differs in case"
    );

    // Case variants of the same id are duplicates, not two selections.
    assert_eq!(
        group_blocked_services(
            &existing,
            &["tiktok".to_string(), "TikTok".to_string()],
            &catalog,
            &registry,
        ),
        Err(GroupServicesError::DuplicateService("TikTok".to_string()))
    );
}

#[tokio::test]
async fn test_clients_group_services_handler_creates_implied_default_group() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_group_services_default_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    let headers = operator_form_headers(&ctx).await;

    let resp = clients_group_services_handler(
        State(ctx.clone()),
        headers,
        Form(vec![
            ("group".to_string(), "default".to_string()),
            ("selected".to_string(), "tiktok".to_string()),
        ]),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "the implied default group must be accepted even when it has no explicit configuration"
    );

    let after = load_clients_config(&ctx);
    let default_group = after
        .groups
        .get("default")
        .expect("selecting for the implied default must create it");
    assert_eq!(blocked_service_ids(default_group), vec!["tiktok"]);
    assert!(
        default_group.filtering,
        "an implied default keeps the normal group defaults"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_clients_group_services_handler_rejects_unknown_group_and_service() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_group_services_unknown_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let mut clients = sito_clients::ClientsConfig::default();
    clients.groups.insert(
        "kids".to_string(),
        clients_group_with_services(vec![sito_clients::BlockedServiceConfig {
            service: "tiktok".to_string(),
            schedule: None,
        }]),
    );
    seed_clients_config(&ctx, &clients);
    let headers = operator_form_headers(&ctx).await;

    // Unknown group.
    let resp = clients_group_services_handler(
        State(ctx.clone()),
        headers.clone(),
        Form(vec![
            ("group".to_string(), "missing".to_string()),
            ("selected".to_string(), "tiktok".to_string()),
        ]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Unknown catalog id.
    let resp = clients_group_services_handler(
        State(ctx.clone()),
        headers.clone(),
        Form(vec![
            ("group".to_string(), "kids".to_string()),
            ("selected".to_string(), "tiktok".to_string()),
            ("selected".to_string(), "not_a_catalog_service".to_string()),
        ]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Every failed request leaves the previous selection intact.
    let after = load_clients_config(&ctx);
    let kids = after.groups.get("kids").expect("kids group must remain");
    assert_eq!(blocked_service_ids(kids), vec!["tiktok"]);
    assert!(
        !ctx.config_path.exists(),
        "validation failures must not persist configuration"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_group_blocked_services_accepts_every_catalog_service() {
    let catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");
    let selected: Vec<String> = catalog
        .services()
        .map(|service| service.id.clone())
        .collect();
    assert_eq!(
        selected.len(),
        142,
        "the pinned catalog currently has 142 services"
    );

    let merged = group_blocked_services(
        &[],
        &selected,
        &catalog,
        &sito_clients::ServiceRegistry::try_bundled().expect("bundled registry must be valid"),
    )
    .expect("every embedded catalog service must be accepted");
    assert_eq!(merged.len(), catalog.services.len());
    assert_eq!(
        merged
            .iter()
            .map(|blocked| blocked.service.as_str())
            .collect::<Vec<_>>(),
        selected,
        "new selections keep the submitted catalog order"
    );
    assert!(
        merged.iter().all(|blocked| blocked.schedule.is_none()),
        "new catalog services start without a schedule"
    );
}

#[test]
fn test_group_blocked_services_rejects_zero_rule_catalog_service() {
    let mut catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");
    let group = catalog.service_groups[0].clone();
    catalog.services.push(sito_clients::CatalogService {
        id: "zero_rule_candidate".to_string(),
        name: "Zero rule candidate".to_string(),
        group,
        rules: vec![
            "/regex-only/".to_string(),
            "*.wild.example".to_string(),
            "||mask.example^$dnsrewrite=NOERROR;;".to_string(),
        ],
    });
    let registry =
        sito_clients::ServiceRegistry::try_bundled().expect("bundled registry must be valid");

    let err = group_blocked_services(
        &[],
        &["zero_rule_candidate".to_string()],
        &catalog,
        &registry,
    )
    .expect_err("a zero-rule catalog service must be rejected");
    assert_eq!(
        err,
        GroupServicesError::UnavailableService("zero_rule_candidate".to_string())
    );
    assert!(
        err.to_string().contains("no usable blocking rules"),
        "the rejection must explain the zero-rule guard: {err}"
    );
}

#[tokio::test]
async fn test_clients_group_services_handler_accepts_every_catalog_service() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_group_services_all_catalog_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;
    let headers = operator_form_headers(&ctx).await;

    let catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");
    let mut pairs = vec![("group".to_string(), "default".to_string())];
    pairs.extend(
        catalog
            .services()
            .map(|service| ("selected".to_string(), service.id.clone())),
    );
    let selected_count = catalog.services.len();

    let resp = clients_group_services_handler(State(ctx.clone()), headers, Form(pairs)).await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "every embedded catalog service must be accepted in one selection"
    );

    let after = load_clients_config(&ctx);
    let default_group = after
        .groups
        .get("default")
        .expect("the implied default must be created");
    assert_eq!(default_group.blocked_services.len(), selected_count);
    assert_eq!(
        default_group
            .blocked_services
            .iter()
            .map(|blocked| blocked.service.as_str())
            .collect::<Vec<_>>(),
        catalog
            .services()
            .map(|service| service.id.as_str())
            .collect::<Vec<_>>(),
        "all catalog ids must be persisted in catalog order"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_clients_group_services_handler_rejects_duplicates() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_group_services_dupes_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let mut clients = sito_clients::ClientsConfig::default();
    clients.groups.insert(
        "kids".to_string(),
        clients_group_with_services(vec![sito_clients::BlockedServiceConfig {
            service: "tiktok".to_string(),
            schedule: None,
        }]),
    );
    seed_clients_config(&ctx, &clients);
    let headers = operator_form_headers(&ctx).await;

    let resp = clients_group_services_handler(
        State(ctx.clone()),
        headers,
        Form(vec![
            ("group".to_string(), "kids".to_string()),
            ("selected".to_string(), "tiktok".to_string()),
            ("selected".to_string(), "tiktok".to_string()),
        ]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let after = load_clients_config(&ctx);
    let kids = after.groups.get("kids").expect("kids group must remain");
    assert_eq!(blocked_service_ids(kids), vec!["tiktok"]);
    assert!(!ctx.config_path.exists());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_clients_group_services_handler_rejects_oversized_selection() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_group_services_cap_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let mut clients = sito_clients::ClientsConfig::default();
    clients.groups.insert(
        "kids".to_string(),
        clients_group_with_services(vec![sito_clients::BlockedServiceConfig {
            service: "tiktok".to_string(),
            schedule: None,
        }]),
    );
    seed_clients_config(&ctx, &clients);
    let headers = operator_form_headers(&ctx).await;

    let catalog = sito_clients::Catalog::embedded().expect("embedded catalog must be valid");
    let selected: Vec<String> = (0..=catalog.services.len())
        .map(|index| format!("service_{index}"))
        .collect();
    let registry =
        sito_clients::ServiceRegistry::try_bundled().expect("bundled registry must be valid");
    assert_eq!(
        group_blocked_services(&[], &selected, &catalog, &registry),
        Err(GroupServicesError::TooMany(
            MAX_GROUP_SERVICES_SELECTION.min(catalog.services.len())
        )),
        "the cap is checked before catalog membership"
    );

    let mut pairs = vec![("group".to_string(), "kids".to_string())];
    pairs.extend(selected.into_iter().map(|id| ("selected".to_string(), id)));

    let resp = clients_group_services_handler(State(ctx.clone()), headers, Form(pairs)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let after = load_clients_config(&ctx);
    let kids = after.groups.get("kids").expect("kids group must remain");
    assert_eq!(blocked_service_ids(kids), vec!["tiktok"]);
    assert!(!ctx.config_path.exists());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_clients_group_services_handler_rbac() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_group_services_rbac_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let ctx = mock_context(&temp_dir).await;

    let mut clients = sito_clients::ClientsConfig::default();
    clients.groups.insert(
        "kids".to_string(),
        clients_group_with_services(vec![sito_clients::BlockedServiceConfig {
            service: "tiktok".to_string(),
            schedule: None,
        }]),
    );
    seed_clients_config(&ctx, &clients);

    // Unauthenticated callers are redirected to the login page.
    let resp = clients_group_services_handler(
        State(ctx.clone()),
        HeaderMap::new(),
        Form(vec![("group".to_string(), "kids".to_string())]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get(axum::http::header::LOCATION).unwrap(),
        "/login"
    );

    // Viewers cannot change group policy.
    ctx.auth_mgr
        .create_user("view_user", "pass", Role::Viewer)
        .await;
    let LoginResult::Success(view_session) =
        ctx.auth_mgr.login("view_user", "pass", "127.0.0.1").await
    else {
        panic!("viewer login failed");
    };
    let mut view_headers = HeaderMap::new();
    view_headers.insert(COOKIE, view_session.to_cookie_header().parse().unwrap());
    let resp = clients_group_services_handler(
        State(ctx.clone()),
        view_headers,
        Form(vec![
            ("group".to_string(), "kids".to_string()),
            ("selected".to_string(), "netflix".to_string()),
        ]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let after = load_clients_config(&ctx);
    let kids = after.groups.get("kids").expect("kids group must remain");
    assert_eq!(
        blocked_service_ids(kids),
        vec!["tiktok"],
        "a forbidden caller must not change the selection"
    );

    // Operators may change it.
    let headers = operator_form_headers(&ctx).await;
    let resp = clients_group_services_handler(
        State(ctx.clone()),
        headers,
        Form(vec![
            ("group".to_string(), "kids".to_string()),
            ("selected".to_string(), "netflix".to_string()),
        ]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_clients_group_services_apply_failure_persists_nothing() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_ui_group_services_persist_err_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let mut ctx = mock_context(&temp_dir).await;

    let mut clients = sito_clients::ClientsConfig::default();
    clients.groups.insert(
        "kids".to_string(),
        clients_group_with_services(vec![sito_clients::BlockedServiceConfig {
            service: "tiktok".to_string(),
            schedule: None,
        }]),
    );
    seed_clients_config(&ctx, &clients);
    let headers = operator_form_headers(&ctx).await;
    ctx.config_path = std::path::PathBuf::from("/proc/forbidden_ui_test/config.toml");

    let resp = clients_group_services_handler(
        State(ctx.clone()),
        headers,
        Form(vec![
            ("group".to_string(), "kids".to_string()),
            ("selected".to_string(), "tiktok".to_string()),
            ("selected".to_string(), "netflix".to_string()),
        ]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let after = load_clients_config(&ctx);
    let kids = after.groups.get("kids").expect("kids group must remain");
    assert_eq!(
        blocked_service_ids(kids),
        vec!["tiktok"],
        "a failed apply must roll the in-memory selection back: {:?}",
        kids.blocked_services
    );
    assert!(!ctx.config_path.exists());

    let _ = std::fs::remove_dir_all(&temp_dir);
}
