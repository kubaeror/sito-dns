//! Web UI administration module powered by Askama templates, HTMX, and Alpine.js.

pub mod handlers;
pub mod static_files;
pub mod templates;

use crate::state::ServerContext;
use axum::Router;
use axum::routing::{get, post};

pub fn ui_router() -> Router<ServerContext> {
    Router::new()
        .route("/", get(handlers::root_handler))
        .route("/login", get(handlers::login_page))
        .route("/dashboard", get(handlers::dashboard_page))
        .route("/querylog", get(handlers::querylog_page))
        .route("/filtering", get(handlers::filtering_page))
        .route("/clients", get(handlers::clients_page))
        .route("/rewrites", get(handlers::rewrites_page))
        .route("/upstreams", get(handlers::upstreams_page))
        .route("/settings", get(handlers::settings_page))
        .route("/system", get(handlers::system_page))
        .route("/wizard", get(handlers::wizard_page))
        .route("/users", get(handlers::users_page))
        .route("/account", get(handlers::account_page))
        // Static assets
        .route("/static/{*path}", get(static_files::static_handler))
        // UI Actions & Partials
        .route("/ui/login", post(handlers::login_submit))
        .route("/ui/logout", post(handlers::logout_handler))
        .route("/ui/users/create", post(handlers::users_create_handler))
        .route("/ui/users/{username}/role", post(handlers::users_role_handler))
        .route(
            "/ui/users/{username}/delete",
            post(handlers::users_delete_handler),
        )
        .route(
            "/ui/account/password",
            post(handlers::account_password_handler),
        )
        .route(
            "/ui/account/tokens",
            post(handlers::account_token_create_handler),
        )
        .route(
            "/ui/account/tokens/{id}/delete",
            post(handlers::account_token_delete_handler),
        )
        .route(
            "/ui/account/totp/setup",
            post(handlers::account_totp_setup_handler),
        )
        .route(
            "/ui/account/totp/enable",
            post(handlers::account_totp_enable_handler),
        )
        .route(
            "/ui/account/totp/disable",
            post(handlers::account_totp_disable_handler),
        )
        .route("/ui/partials/dashboard-stats", get(handlers::dashboard_stats_partial))
        .route("/ui/partials/querylog-rows", get(handlers::querylog_rows_partial))
        .route("/ui/filtering/toggle/{id}", post(handlers::filtering_toggle_handler))
        .route("/ui/filtering/add", post(handlers::filtering_add_handler))
        .route("/ui/filtering/delete/{id}", post(handlers::filtering_delete_handler))
        .route("/ui/filtering/custom-rules", post(handlers::filtering_custom_rules_handler))
        .route("/ui/filtering/simulate", post(handlers::filtering_simulate_handler))
        .route("/ui/filtering/update-all", post(handlers::filtering_update_all_handler))
        .route("/ui/rewrites/add", post(handlers::rewrites_add_handler))
        .route("/ui/rewrites/delete", post(handlers::rewrites_delete_handler))
        .route("/ui/clients/add", post(handlers::clients_add_handler))
        .route("/ui/clients/delete", post(handlers::clients_delete_handler))
        .route("/ui/upstreams/add", post(handlers::upstreams_add_handler))
        .route("/ui/upstreams/test", post(handlers::upstreams_test_handler))
        .route("/ui/settings/save", post(handlers::settings_save_handler))
        .route("/ui/system/reload", post(handlers::system_reload_handler))
        .route("/ui/system/update/check", get(handlers::system_update_check_handler))
        .route("/ui/system/update/apply", post(handlers::system_update_apply_handler))
        .route("/ui/wizard/complete", post(handlers::wizard_complete_handler))
}

#[cfg(test)]
mod tests {
    use askama::Template;

    use crate::models::StatusResponse;
    use crate::ui::static_files::StaticAssets;
    use crate::ui::templates::{
        AccountTemplate, ClientDiscoveryViewItem, ClientViewItem, ClientsTemplate,
        DashboardStatsPartialTemplate, DashboardTemplate, FilteringTemplate, LoginTemplate,
        QueryLogRowItem, QueryLogRowsPartialTemplate, QueryLogTemplate, RewriteViewItem,
        RewritesTemplate, SettingsTemplate, SystemTemplate, TokenViewItem, TotpSetupView,
        UpstreamViewItem, UpstreamsTemplate, UserViewItem, UsersTemplate, WizardTemplate,
    };
    use sito_stats::GlobalStats;

    #[test]
    fn test_embedded_static_assets() {
        assert!(StaticAssets::get("htmx.min.js").is_some());
        assert!(StaticAssets::get("htmx-ws.js").is_some());
        assert!(StaticAssets::get("alpine.min.js").is_some());
        assert!(StaticAssets::get("uplot.min.js").is_some());
        assert!(StaticAssets::get("uplot.min.css").is_some());
        assert!(StaticAssets::get("app.css").is_some());
        assert!(StaticAssets::get("app.js").is_some());
        assert!(StaticAssets::get("logo.svg").is_some());
    }

    #[test]
    fn test_render_login_template() {
        let tmpl = LoginTemplate {
            is_authenticated: false,
            username: "admin",
            user_role: "",
            active_tab: "login",
            version: "1.2.1",
            error_message: "Invalid credentials test",
            csrf_token: "",
        };
        let html = tmpl.render().expect("render login template");
        assert!(html.contains("sito DNS"));
        assert!(html.contains("Invalid credentials test"));
        assert!(html.contains("Sign In"));
        assert!(html.contains("name=\"password\""));
    }

    #[test]
    fn test_render_dashboard_and_partial() {
        let stats = GlobalStats {
            total_queries: 1234,
            blocked_queries: 123,
            cached_queries: 456,
            blocked_percentage: 10.0,
            top_domains: vec![("example.com".to_string(), 50)],
            top_blocked_domains: vec![("ads.bad.com".to_string(), 25)],
            top_clients: vec![("192.168.1.10".to_string(), 100)],
        };
        let status = StatusResponse {
            version: "1.2.1".to_string(),
            uptime_seconds: 3661,
            role: "master".to_string(),
            listeners: vec!["0.0.0.0:53 (UDP/TCP)".to_string()],
            acme: None,
        };

        // Partial
        let partial = DashboardStatsPartialTemplate {
            stats: &stats,
            status: &status,
            uptime_str: "1h 1m 1s".to_string(),
            blocked_pct_str: "10.0".to_string(),
        };
        let partial_html = partial.render().expect("render dashboard stats partial");
        assert!(partial_html.contains("1234"));
        assert!(partial_html.contains("10.0%"));
        assert!(partial_html.contains("example.com"));
        assert!(partial_html.contains("ads.bad.com"));

        // Full Dashboard
        let dash = DashboardTemplate {
            csrf_token: "",
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "dashboard",
            version: "1.2.1",
            stats: &stats,
            status: &status,
            uptime_str: "1h 1m 1s".to_string(),
            blocked_pct_str: "10.0".to_string(),
            upstreams: vec![UpstreamViewItem {
                address: "tls://1.1.1.1:853".to_string(),
                protocol: "DoT (TLS)".to_string(),
                is_healthy: true,
                weight: 100,
                total_queries: 500,
                avg_latency_ms: 15.2,
            }],
            hourly_times_json: "[0, 1, 2]".to_string(),
            hourly_totals_json: "[10, 20, 30]".to_string(),
            hourly_blocked_json: "[1, 2, 3]".to_string(),
        };
        let dash_html = dash.render().expect("render dashboard template");
        assert!(dash_html.contains("Operational Dashboard"));
        assert!(dash_html.contains("tls://1.1.1.1:853"));
        assert!(dash_html.contains("Query Activity (24h Window)"));
    }

    #[test]
    fn test_render_querylog_and_rows() {
        let rows = vec![QueryLogRowItem {
            ts: 1_700_000_000_000,
            time_str: "12:34:56".to_string(),
            client_ip: "192.168.1.5".to_string(),
            client_name: Some("Laptop".to_string()),
            qname: "google.com".to_string(),
            qtype_str: "A".to_string(),
            verdict: "allowed".to_string(),
            latency_str: "1.2 ms".to_string(),
            rule: None,
            upstream: Some("1.1.1.1".to_string()),
        }];

        let partial = QueryLogRowsPartialTemplate { entries: &rows };
        let partial_html = partial.render().expect("render querylog rows partial");
        assert!(partial_html.contains("google.com"));
        assert!(partial_html.contains("Allowed"));
        assert!(partial_html.contains("1.2 ms"));

        let full = QueryLogTemplate {
            csrf_token: "",
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "querylog",
            version: "1.2.1",
            entries: &rows,
        };
        let full_html = full.render().expect("render querylog page");
        assert!(full_html.contains("Real-time DNS Query Log"));
        assert!(full_html.contains("Search Domain"));
    }

    #[test]
    fn test_render_all_views() {
        let filter_tmpl = FilteringTemplate {
            csrf_token: "",
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "filtering",
            version: "1.2.1",
            lists: &[],
            custom_rules: "||ad.com^",
            bundled_lists: vec![crate::ui::templates::BundledListView {
                id: "adult".to_string(),
                kind: "domains".to_string(),
                version: "2026.09.2".to_string(),
                source: "https://example.com/adult.txt".to_string(),
                license: "CC0-1.0".to_string(),
                entries: 40,
                state: "built-in (minimal)".to_string(),
                last_refresh: "—".to_string(),
            }],
        };
        let filtering_html = filter_tmpl.render().expect("render filtering page");
        assert!(filtering_html.contains("built-in (minimal)"));
        assert!(filtering_html.contains("adult"));
        assert!(filtering_html.contains("CC0-1.0"));

        let rewrites_tmpl = RewritesTemplate {
            csrf_token: "",
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "rewrites",
            version: "1.2.1",
            rewrites: vec![RewriteViewItem {
                id: "rw_test".to_string(),
                domain: "nas.lan".to_string(),
                record_type: "A".to_string(),
                answer: "192.168.1.50".to_string(),
            }],
        };
        assert!(rewrites_tmpl.render().unwrap().contains("nas.lan"));

        let clients_tmpl = ClientsTemplate {
            csrf_token: "",
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "clients",
            version: "1.2.1",
            clients: vec![ClientViewItem {
                name: "Work PC".to_string(),
                ids: vec!["192.168.1.100".to_string()],
                group: "default".to_string(),
            }],
            discovered: vec![ClientDiscoveryViewItem {
                ip: "192.168.1.101".to_string(),
                mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
                hostname: Some("laptop <b>&".to_string()),
                last_seen: "2026-01-02 03:04 UTC".to_string(),
            }],
            discovered_total: 1,
            can_view_discovered: true,
            discovered_page: 1,
            discovered_pages: 1,
            max_entries: sito_clients::MAX_UNIDENTIFIED_CLIENTS,
            retention_hours: sito_clients::UNIDENTIFIED_CLIENT_TTL_HOURS,
        };
        let clients_html = clients_tmpl.render().unwrap();
        assert!(clients_html.contains("Work PC"));
        assert!(clients_html.contains("Discovered but unidentified"));
        assert!(clients_html.contains("192.168.1.101"));
        assert!(clients_html.contains("2026-01-02 03:04 UTC"));
        assert!(
            clients_html.contains("laptop &#60;b&#62;&#38;"),
            "discovered hostnames must stay HTML-escaped: {clients_html}"
        );
        assert!(
            !clients_html.contains("laptop <b>"),
            "raw markup from a discovered hostname must never render"
        );

        let upstreams_tmpl = UpstreamsTemplate {
            csrf_token: "",
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "upstreams",
            version: "1.2.1",
            upstreams: vec![],
        };
        assert!(upstreams_tmpl.render().is_ok());

        let settings_tmpl = SettingsTemplate {
            csrf_token: "",
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "settings",
            version: "1.2.1",
            cache_size_mb: 64,
            min_ttl: 60,
            dnssec_enabled: true,
            rate_limit: 20,
        };
        assert!(settings_tmpl.render().is_ok());

        let status = StatusResponse {
            version: "1.2.1".to_string(),
            uptime_seconds: 120,
            role: "master".to_string(),
            listeners: vec![],
            acme: None,
        };
        let sys_tmpl = SystemTemplate {
            csrf_token: "",
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "system",
            version: "1.2.1",
            status: &status,
            uptime_str: "2m 0s".to_string(),
        };
        assert!(
            sys_tmpl
                .render()
                .unwrap()
                .contains("HTMX + Askama + Alpine.js")
        );

        let wiz_tmpl = WizardTemplate {
            is_authenticated: false,
            username: "admin",
            user_role: "",
            active_tab: "wizard",
            version: "1.2.1",
            csrf_token: "",
            setup_required: true,
            setup_token: "test-token",
        };
        assert!(wiz_tmpl.render().unwrap().contains("Welcome to sito DNS"));
    }

    #[test]
    fn test_render_users_and_account_templates() {
        let users_tmpl = UsersTemplate {
            csrf_token: "csrf-token",
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "users",
            version: "1.2.1",
            users: vec![
                UserViewItem {
                    username: "admin".to_string(),
                    role: "admin".to_string(),
                    totp_enabled: false,
                    role_action: "/ui/users/admin/role".to_string(),
                    delete_action: "/ui/users/admin/delete".to_string(),
                    is_current: true,
                },
                UserViewItem {
                    username: "alice".to_string(),
                    role: "operator".to_string(),
                    totp_enabled: true,
                    role_action: "/ui/users/alice/role".to_string(),
                    delete_action: "/ui/users/alice/delete".to_string(),
                    is_current: false,
                },
            ],
            error_message: "Duplicate user",
        };
        let html = users_tmpl.render().expect("render users template");
        assert!(html.contains("alice"));
        assert!(html.contains("/ui/users/alice/role"));
        assert!(html.contains("Duplicate user"));
        assert!(html.contains("href=\"/users\""), "admin nav link missing");

        // The Users nav link is admin-only.
        let viewer_tmpl = UsersTemplate {
            csrf_token: "csrf-token",
            is_authenticated: true,
            username: "alice",
            user_role: "viewer",
            active_tab: "users",
            version: "1.2.1",
            users: Vec::new(),
            error_message: "",
        };
        let viewer_html = viewer_tmpl.render().expect("render viewer users template");
        assert!(
            !viewer_html.contains("href=\"/users\""),
            "Viewers must not see the Users nav link"
        );
        assert!(viewer_html.contains("href=\"/account\""));

        let account_tmpl = AccountTemplate {
            csrf_token: "csrf-token",
            is_authenticated: true,
            username: "alice",
            user_role: "viewer",
            active_tab: "account",
            version: "1.2.1",
            tokens: vec![TokenViewItem {
                id: "tok_abc".to_string(),
                name: "ci-deploy".to_string(),
                scope: "viewer".to_string(),
                owner: "alice".to_string(),
                created_at: "2026-01-01 00:00 UTC".to_string(),
                last_used: "—".to_string(),
                expires_at: "—".to_string(),
            }],
            totp_enabled: true,
            totp_setup: None,
            can_create_operator_token: false,
            can_create_admin_token: false,
            error_message: "",
            notice_message: "",
            new_token: Some("sito_plaintext_once"),
            new_token_name: "ci-deploy",
            new_token_scope: "viewer",
        };
        let account_html = account_tmpl.render().expect("render account template");
        assert!(account_html.contains("sito_plaintext_once"));
        assert!(account_html.contains("ci-deploy"));
        assert!(account_html.contains("Disable TOTP"));
        assert!(account_html.contains("/ui/account/tokens/tok_abc/delete"));
    }

    fn account_template(
        totp_enabled: bool,
        totp_setup: Option<TotpSetupView>,
    ) -> AccountTemplate<'static> {
        AccountTemplate {
            csrf_token: "csrf-token",
            is_authenticated: true,
            username: "alice",
            user_role: "viewer",
            active_tab: "account",
            version: "1.2.1",
            tokens: Vec::new(),
            totp_enabled,
            totp_setup,
            can_create_operator_token: false,
            can_create_admin_token: false,
            error_message: "",
            notice_message: "",
            new_token: None,
            new_token_name: "",
            new_token_scope: "",
        }
    }

    fn pending_totp_setup() -> TotpSetupView {
        TotpSetupView {
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            otpauth_url: "otpauth://totp/sito:alice?secret=JBSWY3DPEHPK3PXP".to_string(),
            qr_code: String::new(),
            backup_codes: vec!["AAAA-BBBB".to_string()],
            reauth_token: "reauth-ticket".to_string(),
        }
    }

    /// Deferred D5: a pending TOTP enrollment must replace the starter form,
    /// not render beside it. Submitting the starter form again would issue a
    /// new secret and invalidate the one already displayed in the confirm card.
    #[test]
    fn test_account_template_suppresses_starter_form_during_pending_enrollment() {
        let html = account_template(false, Some(pending_totp_setup()))
            .render()
            .expect("render account template");
        assert!(html.contains("Confirm TOTP Enrollment"));
        assert!(
            !html.contains("Begin TOTP Setup"),
            "the starter form must be hidden while enrollment is pending"
        );
        assert!(
            !html.contains("action=\"/ui/account/totp/setup\""),
            "the starter setup form must be suppressed while enrollment is pending"
        );
    }

    /// Deferred D5 review: the same invalidation exists in the replace flow.
    /// An enabled user with a pending replacement must not see the replace
    /// form, because submitting it overwrites the pending secret.
    #[test]
    fn test_account_template_suppresses_replace_form_during_pending_enrollment() {
        let html = account_template(true, Some(pending_totp_setup()))
            .render()
            .expect("render account template");
        assert!(html.contains("Confirm TOTP Enrollment"));
        assert!(
            !html.contains("Replace TOTP 2FA"),
            "the replace form must be hidden while a replacement is pending"
        );
        assert!(
            !html.contains("action=\"/ui/account/totp/setup\""),
            "no enrollment-start form may be shown while enrollment is pending"
        );
        // Disabling is not an enrollment-start form and stays available.
        assert!(html.contains("Disable TOTP 2FA"));
    }

    /// Negative counterpart: without a pending setup, the starter form appears
    /// for a fresh user and the replace form appears for an enabled user.
    #[test]
    fn test_account_template_shows_enrollment_forms_without_pending_setup() {
        let starter = account_template(false, None)
            .render()
            .expect("render account template");
        assert!(!starter.contains("Confirm TOTP Enrollment"));
        assert!(starter.contains("Begin TOTP Setup"));
        assert!(starter.contains("action=\"/ui/account/totp/setup\""));

        let replace = account_template(true, None)
            .render()
            .expect("render account template");
        assert!(!replace.contains("Confirm TOTP Enrollment"));
        assert!(replace.contains("Replace TOTP 2FA"));
        assert!(replace.contains("action=\"/ui/account/totp/setup\""));
        assert!(!replace.contains("Begin TOTP Setup"));
    }
}
