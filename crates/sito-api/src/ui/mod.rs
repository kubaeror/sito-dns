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
        // Static assets
        .route("/static/{*path}", get(static_files::static_handler))
        // UI Actions & Partials
        .route("/ui/login", post(handlers::login_submit))
        .route("/ui/logout", post(handlers::logout_handler))
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
        .route("/ui/wizard/complete", post(handlers::wizard_complete_handler))
}

#[cfg(test)]
mod tests {
    use askama::Template;

    use crate::models::StatusResponse;
    use crate::ui::static_files::StaticAssets;
    use crate::ui::templates::{
        ClientViewItem, ClientsTemplate, DashboardStatsPartialTemplate, DashboardTemplate,
        FilteringTemplate, LoginTemplate, QueryLogRowItem, QueryLogRowsPartialTemplate,
        QueryLogTemplate, RewriteViewItem, RewritesTemplate, SettingsTemplate, SystemTemplate,
        UpstreamViewItem, UpstreamsTemplate, WizardTemplate,
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
        assert!(StaticAssets::get("logo.svg").is_some());
    }

    #[test]
    fn test_render_login_template() {
        let tmpl = LoginTemplate {
            is_authenticated: false,
            username: "admin",
            user_role: "",
            active_tab: "login",
            version: "1.1.0",
            error_message: "Invalid credentials test",
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
            version: "1.1.0".to_string(),
            uptime_seconds: 3661,
            role: "master".to_string(),
            listeners: vec!["0.0.0.0:53 (UDP/TCP)".to_string()],
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
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "dashboard",
            version: "1.1.0",
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
        };
        let dash_html = dash.render().expect("render dashboard template");
        assert!(dash_html.contains("Operational Dashboard"));
        assert!(dash_html.contains("tls://1.1.1.1:853"));
        assert!(dash_html.contains("Query Activity (24h Window)"));
    }

    #[test]
    fn test_render_querylog_and_rows() {
        let rows = vec![QueryLogRowItem {
            ts: 1700000000000,
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
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "querylog",
            version: "1.1.0",
            entries: &rows,
        };
        let full_html = full.render().expect("render querylog page");
        assert!(full_html.contains("Real-time DNS Query Log"));
        assert!(full_html.contains("Search Domain"));
    }

    #[test]
    fn test_render_all_views() {
        let filter_tmpl = FilteringTemplate {
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "filtering",
            version: "1.1.0",
            lists: &[],
            custom_rules: "||ad.com^",
        };
        assert!(filter_tmpl.render().is_ok());

        let rewrites_tmpl = RewritesTemplate {
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "rewrites",
            version: "1.1.0",
            rewrites: vec![RewriteViewItem {
                domain: "nas.lan".to_string(),
                record_type: "A".to_string(),
                answer: "192.168.1.50".to_string(),
            }],
        };
        assert!(rewrites_tmpl.render().unwrap().contains("nas.lan"));

        let clients_tmpl = ClientsTemplate {
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "clients",
            version: "1.1.0",
            clients: vec![ClientViewItem {
                name: "Work PC".to_string(),
                ids: vec!["192.168.1.100".to_string()],
                group: "default".to_string(),
            }],
        };
        assert!(clients_tmpl.render().unwrap().contains("Work PC"));

        let upstreams_tmpl = UpstreamsTemplate {
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "upstreams",
            version: "1.1.0",
            upstreams: vec![],
        };
        assert!(upstreams_tmpl.render().is_ok());

        let settings_tmpl = SettingsTemplate {
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "settings",
            version: "1.1.0",
            cache_size_mb: 64,
            min_ttl: 60,
            dnssec_enabled: true,
            rate_limit: 20,
        };
        assert!(settings_tmpl.render().is_ok());

        let status = StatusResponse {
            version: "1.1.0".to_string(),
            uptime_seconds: 120,
            role: "master".to_string(),
            listeners: vec![],
        };
        let sys_tmpl = SystemTemplate {
            is_authenticated: true,
            username: "admin",
            user_role: "admin",
            active_tab: "system",
            version: "1.1.0",
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
            version: "1.1.0",
        };
        assert!(wiz_tmpl.render().unwrap().contains("Welcome to sito DNS"));
    }
}
