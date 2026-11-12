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
        ..info
    };
    let docker_html = update_action_html(&docker, "csrf-token-123");
    assert!(!docker_html.contains("<form"), "{docker_html}");
    assert!(docker_html.contains("docker compose pull"), "{docker_html}");
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
        entries: 42,
        bundled: false,
    }];

    let views = bundled_list_views(Err(corrupt), &statuses);
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

    // The healthy path still merges bundled metadata with runtime status.
    let manifest =
        sito_clients::BundledManifest::try_bundled().expect("bundled manifest must parse");
    let views = bundled_list_views(Ok(manifest), &[]);
    assert!(views.iter().any(|view| view.id == "adult"));
    assert!(
        views.iter().all(|view| view.kind != "custom"),
        "a healthy manifest must not invent custom rows"
    );
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
        cache_enabled: Some("on".to_string()),
        cache_size_mb: Some("128".to_string()),
        dnssec_mode: Some("strict".to_string()),
        dnssec_validate: Some("on".to_string()),
        filtering_enabled: Some("on".to_string()),
        enable_adblock: None,
        blocking_mode: Some("nxdomain".to_string()),
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
        headers.clone(),
        Form(CreateUserForm {
            username: "bob".to_string(),
            password: "short".to_string(),
            role: "viewer".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(!ctx.auth_mgr.has_user("bob"));

    let resp = users_create_handler(
        State(ctx.clone()),
        headers.clone(),
        Form(CreateUserForm {
            username: "  alice  ".to_string(),
            password: "AlicePassword1".to_string(),
            role: "operator".to_string(),
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
        headers.clone(),
        Form(CreateUserForm {
            username: "alice".to_string(),
            password: "OtherPassword1".to_string(),
            role: "viewer".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(ctx.auth_mgr.role_of("alice"), Some(Role::Operator));

    let resp = users_role_handler(
        State(ctx.clone()),
        headers.clone(),
        Path("alice".to_string()),
        Form(UpdateUserRoleForm {
            role: "viewer".to_string(),
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
        headers.clone(),
        Path("admin".to_string()),
        Form(UpdateUserRoleForm {
            role: "viewer".to_string(),
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
        headers.clone(),
        Form(AccountPasswordForm {
            current_password: "wrong-password".to_string(),
            new_password: "NewAdminPassword1".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_body(resp).await;
    assert!(body.contains("Current password is incorrect"), "{body}");
    assert!(
        ctx.auth_mgr
            .verify_user_password("admin", "adminadmin")
            .await,
        "wrong current password must not change the password"
    );

    let resp = account_password_handler(
        State(ctx.clone()),
        headers,
        Form(AccountPasswordForm {
            current_password: "  adminadmin  ".to_string(),
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
        headers.clone(),
        Form(CreateAccountTokenForm {
            name: "  ci-deploy  ".to_string(),
            scope: "viewer".to_string(),
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
        headers.clone(),
        Form(CreateAccountTokenForm {
            name: "escalation".to_string(),
            scope: "admin".to_string(),
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
        headers,
        Form(CreateAccountTokenForm {
            name: "read-only".to_string(),
            scope: "viewer".to_string(),
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
    assert!(body.contains("A TOTP or backup code is required"), "{body}");
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
