//! Askama template structs and HTML response adapter.

use crate::models::{FilterListDto, StatusResponse};
use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use sito_stats::GlobalStats;

/// Wrapper to convert any Askama `Template` into an Axum HTML `Response`.
pub struct HtmlTemplate<T>(pub T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template: {err}"),
            )
                .into_response(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamViewItem {
    pub address: String,
    pub protocol: String,
    pub is_healthy: bool,
    pub weight: u32,
    pub total_queries: u64,
    pub avg_latency_ms: f64,
}

#[derive(Debug, Clone)]
pub struct RewriteViewItem {
    pub domain: String,
    pub record_type: String,
    pub answer: String,
}

#[derive(Debug, Clone)]
pub struct ClientViewItem {
    pub name: String,
    pub ids: Vec<String>,
    pub group: String,
}

#[derive(Debug, Clone)]
pub struct QueryLogRowItem {
    pub ts: i64,
    pub time_str: String,
    pub client_ip: String,
    pub client_name: Option<String>,
    pub qname: String,
    pub qtype_str: String,
    pub verdict: String,
    pub latency_str: String,
    pub rule: Option<String>,
    pub upstream: Option<String>,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate<'a> {
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub error_message: &'a str,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate<'a> {
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub stats: &'a GlobalStats,
    pub status: &'a StatusResponse,
    pub uptime_str: String,
    pub blocked_pct_str: String,
    pub upstreams: Vec<UpstreamViewItem>,
}

#[derive(Template)]
#[template(path = "partials/dashboard_stats.html")]
pub struct DashboardStatsPartialTemplate<'a> {
    pub stats: &'a GlobalStats,
    pub status: &'a StatusResponse,
    pub uptime_str: String,
    pub blocked_pct_str: String,
}

#[derive(Template)]
#[template(path = "querylog.html")]
pub struct QueryLogTemplate<'a> {
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub entries: &'a [QueryLogRowItem],
}

#[derive(Template)]
#[template(path = "partials/querylog_rows.html")]
pub struct QueryLogRowsPartialTemplate<'a> {
    pub entries: &'a [QueryLogRowItem],
}

#[derive(Template)]
#[template(path = "filtering.html")]
pub struct FilteringTemplate<'a> {
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub lists: &'a [FilterListDto],
    pub custom_rules: &'a str,
}

#[derive(Template)]
#[template(path = "rewrites.html")]
pub struct RewritesTemplate<'a> {
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub rewrites: Vec<RewriteViewItem>,
}

#[derive(Template)]
#[template(path = "clients.html")]
pub struct ClientsTemplate<'a> {
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub clients: Vec<ClientViewItem>,
}

#[derive(Template)]
#[template(path = "upstreams.html")]
pub struct UpstreamsTemplate<'a> {
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub upstreams: Vec<UpstreamViewItem>,
}

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate<'a> {
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub cache_size_mb: usize,
    pub min_ttl: u32,
    pub dnssec_enabled: bool,
    pub rate_limit: u32,
}

#[derive(Template)]
#[template(path = "system.html")]
pub struct SystemTemplate<'a> {
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub status: &'a StatusResponse,
    pub uptime_str: String,
}

#[derive(Template)]
#[template(path = "wizard.html")]
pub struct WizardTemplate<'a> {
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
}
