//! UI routes, HTMX partial endpoints, and form handlers.

use axum::extract::{Form, Path, Query, State};
use axum::http::StatusCode;
use axum::http::header::{HeaderMap, SET_COOKIE};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::net::IpAddr;
use std::str::FromStr;

use crate::auth::manager::LoginResult;
use crate::auth::rbac::AuthUser;
use crate::auth::resolve_client_ip;
use crate::auth::session::{
    build_clear_csrf_cookie, build_clear_session_cookie, build_csrf_cookie, extract_session_cookie,
};
use crate::auth::token::Role;
use crate::config_writer::save_config_atomic;
use crate::models::{FilterListDto, StatusResponse};
use crate::probe::probe_upstream_target;
use crate::state::ServerContext;
use crate::ui::templates::{
    ClientViewItem, ClientsTemplate, DashboardStatsPartialTemplate, DashboardTemplate,
    FilteringTemplate, HtmlTemplate, LoginTemplate, QueryLogRowItem, QueryLogRowsPartialTemplate,
    QueryLogTemplate, RewriteViewItem, RewritesTemplate, SettingsTemplate, SystemTemplate,
    UpstreamViewItem, UpstreamsTemplate, WizardTemplate,
};
use sito_core::FilterEngine;
use sito_core::config::{BlockingMode, Config, FilterListConfig, UpstreamStrategy};
use sito_stats::QueryLogFilter;

pub fn format_duration(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else {
        format!("{minutes}m {seconds}s")
    }
}

pub fn qtype_to_str(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        28 => "AAAA",
        5 => "CNAME",
        65 => "HTTPS",
        16 => "TXT",
        12 => "PTR",
        15 => "MX",
        2 => "NS",
        6 => "SOA",
        257 => "CAA",
        _ => "OTHER",
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

pub fn get_session_user(ctx: &ServerContext, headers: &HeaderMap) -> Option<AuthUser> {
    if let Some(cookie_hdr) = headers.get("cookie")
        && let Ok(cookie_str) = cookie_hdr.to_str()
        && let Some(session_id) = extract_session_cookie(cookie_str)
        && let Some(session) = ctx.auth_mgr.validate_session(&session_id)
    {
        return Some(AuthUser {
            username: session.username,
            role: session.role,
            token_id: None,
        });
    }
    None
}

/// Returns the CSRF token bound to the caller's session (empty when not
/// authenticated) for embedding in Askama forms.
pub fn get_csrf_token(ctx: &ServerContext, headers: &HeaderMap) -> String {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_session_cookie)
        .and_then(|id| ctx.auth_mgr.validate_session(&id))
        .map(|session| session.csrf_token)
        .unwrap_or_default()
}

/// Appends a `Set-Cookie` header without clobbering an existing one.
fn append_cookie(response: &mut Response, value: &str) {
    if let Ok(cookie_val) = value.parse() {
        response.headers_mut().append(SET_COOKIE, cookie_val);
    }
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, message.to_string()).into_response()
}

// ---------------------------------------------------------------------------
// Root, Login & Logout
// ---------------------------------------------------------------------------

pub async fn root_handler(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    if get_session_user(&ctx, &headers).is_some() {
        Redirect::to("/dashboard").into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

pub async fn login_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    if get_session_user(&ctx, &headers).is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    HtmlTemplate(LoginTemplate {
        is_authenticated: false,
        username: "",
        user_role: "",
        active_tab: "login",
        version: env!("CARGO_PKG_VERSION"),
        error_message: "",
        csrf_token: "",
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
}

pub async fn login_submit(
    State(ctx): State<ServerContext>,
    crate::auth::MaybeConnectInfo(peer_addr): crate::auth::MaybeConnectInfo,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let config = ctx.config.load();
    let trusted_proxies = config.get_web_config().trusted_proxies;
    let tls_enabled = config.get_tls_config().is_some();
    let is_secure =
        crate::auth::is_https_request(peer_addr, &headers, &trusted_proxies, tls_enabled);
    let client_ip = resolve_client_ip(peer_addr, &headers, &trusted_proxies);
    let result = ctx
        .auth_mgr
        .login(&form.username, &form.password, &client_ip)
        .await;

    match result {
        LoginResult::Success(session) => {
            let mut resp = Redirect::to("/dashboard").into_response();
            let max_age = (session.expires_at - Utc::now().timestamp()).max(0);
            append_cookie(
                &mut resp,
                &crate::auth::session::build_session_cookie(&session.id, max_age, is_secure),
            );
            append_cookie(
                &mut resp,
                &build_csrf_cookie(&session.csrf_token, max_age, is_secure),
            );
            resp
        }
        LoginResult::TotpRequired { partial_token } => {
            if let Some(ref code) = form.totp
                && !code.trim().is_empty()
            {
                match ctx
                    .auth_mgr
                    .verify_totp(&partial_token, code.trim(), &client_ip)
                    .await
                {
                    crate::auth::manager::TotpVerifyResult::Success(session) => {
                        let mut resp = Redirect::to("/dashboard").into_response();
                        let max_age = (session.expires_at - Utc::now().timestamp()).max(0);
                        append_cookie(
                            &mut resp,
                            &crate::auth::session::build_session_cookie(
                                &session.id,
                                max_age,
                                is_secure,
                            ),
                        );
                        append_cookie(
                            &mut resp,
                            &build_csrf_cookie(&session.csrf_token, max_age, is_secure),
                        );
                        return resp;
                    }
                    crate::auth::manager::TotpVerifyResult::LockedOut { .. } => {
                        return HtmlTemplate(LoginTemplate {
                            is_authenticated: false,
                            username: &form.username,
                            user_role: "",
                            active_tab: "login",
                            version: env!("CARGO_PKG_VERSION"),
                            error_message: "Account locked out due to failed attempts. Try again later.",
                            csrf_token: "",
                        })
                        .into_response();
                    }
                    crate::auth::manager::TotpVerifyResult::RateLimited => {
                        return HtmlTemplate(LoginTemplate {
                            is_authenticated: false,
                            username: &form.username,
                            user_role: "",
                            active_tab: "login",
                            version: env!("CARGO_PKG_VERSION"),
                            error_message: "Too many attempts. Please wait and try again.",
                            csrf_token: "",
                        })
                        .into_response();
                    }
                    crate::auth::manager::TotpVerifyResult::Invalid
                    | crate::auth::manager::TotpVerifyResult::TokenExpired => {}
                }
            }
            HtmlTemplate(LoginTemplate {
                is_authenticated: false,
                username: &form.username,
                user_role: "",
                active_tab: "login",
                version: env!("CARGO_PKG_VERSION"),
                error_message: "2FA TOTP code required or code is invalid.",
                csrf_token: "",
            })
            .into_response()
        }
        LoginResult::LockedOut { .. } => HtmlTemplate(LoginTemplate {
            is_authenticated: false,
            username: &form.username,
            user_role: "",
            active_tab: "login",
            version: env!("CARGO_PKG_VERSION"),
            error_message: "Account locked out due to failed attempts. Try again later.",
            csrf_token: "",
        })
        .into_response(),
        LoginResult::RateLimited => HtmlTemplate(LoginTemplate {
            is_authenticated: false,
            username: &form.username,
            user_role: "",
            active_tab: "login",
            version: env!("CARGO_PKG_VERSION"),
            error_message: "Too many attempts from this IP address. Please wait.",
            csrf_token: "",
        })
        .into_response(),
        LoginResult::InvalidCredentials { .. } => HtmlTemplate(LoginTemplate {
            is_authenticated: false,
            username: &form.username,
            user_role: "",
            active_tab: "login",
            version: env!("CARGO_PKG_VERSION"),
            error_message: "Invalid username or password.",
            csrf_token: "",
        })
        .into_response(),
    }
}

pub async fn logout_handler(
    State(ctx): State<ServerContext>,
    crate::auth::MaybeConnectInfo(peer_addr): crate::auth::MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    if let Some(cookie_hdr) = headers.get("cookie")
        && let Ok(s) = cookie_hdr.to_str()
        && let Some(session_id) = extract_session_cookie(s)
    {
        ctx.auth_mgr.logout(&session_id);
    }
    let config = ctx.config.load();
    let trusted_proxies = config.get_web_config().trusted_proxies;
    let tls_enabled = config.get_tls_config().is_some();
    let is_secure =
        crate::auth::is_https_request(peer_addr, &headers, &trusted_proxies, tls_enabled);
    let mut resp = Redirect::to("/login").into_response();
    append_cookie(&mut resp, &build_clear_session_cookie(is_secure));
    append_cookie(&mut resp, &build_clear_csrf_cookie(is_secure));
    resp
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

fn get_status_response(ctx: &ServerContext) -> StatusResponse {
    let cfg = ctx.config.load();
    let uptime = ctx.start_time.elapsed().as_secs();
    let mut listeners = Vec::new();
    for bind in &cfg.dns.bind {
        listeners.push(format!("{bind}:{} (UDP/TCP)", cfg.dns.port));
        if cfg.dns.dot_port > 0 {
            listeners.push(format!("{bind}:{} (DoT)", cfg.dns.dot_port));
        }
        if cfg.dns.doh_port > 0 {
            listeners.push(format!("{bind}:{} (DoH)", cfg.dns.doh_port));
        }
    }
    StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        role: cfg.server.role.clone(),
        listeners,
    }
}

async fn get_upstreams_list(ctx: &ServerContext) -> Vec<UpstreamViewItem> {
    let cfg = ctx.config.load();
    let statuses = ctx.upstream.statuses().await;
    let stats = ctx
        .stats_db
        .get_upstream_stats(86_400_000)
        .await
        .unwrap_or_default();

    let mut res = Vec::new();
    for addr_str in &cfg.upstream.servers {
        let proto = if addr_str.starts_with("tls://") {
            "DoT (TLS)"
        } else if addr_str.starts_with("udp://")
            || addr_str.contains(":53")
            || !addr_str.contains(':')
        {
            "UDP"
        } else {
            "DNS"
        };

        let is_healthy = statuses
            .iter()
            .find(|(name, _)| name == addr_str)
            .is_none_or(|(_, status)| *status != sito_upstream::HealthStatus::Down);

        let (total_queries, avg_latency_ms) = stats
            .iter()
            .find(|s| &s.upstream == addr_str || addr_str.contains(&s.upstream))
            .map_or((0, 0.0), |s| {
                (s.total_queries, (s.avg_elapsed_us as f64) / 1000.0)
            });

        res.push(UpstreamViewItem {
            address: addr_str.clone(),
            protocol: proto.to_string(),
            is_healthy,
            weight: 100,
            total_queries: total_queries.max(0) as u64,
            avg_latency_ms,
        });
    }
    res
}

pub async fn dashboard_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let csrf = get_csrf_token(&ctx, &headers);

    let stats = ctx
        .stats_db
        .get_global_stats(86_400_000)
        .await
        .unwrap_or_default();
    let status = get_status_response(&ctx);
    let uptime_str = format_duration(status.uptime_seconds);
    let blocked_pct_str = format!("{:.1}", stats.blocked_percentage);
    let upstreams = get_upstreams_list(&ctx).await;

    let hourly = ctx
        .stats_db
        .get_hourly_activity(24)
        .await
        .unwrap_or_default();
    let times: Vec<i64> = hourly.iter().map(|h| h.timestamp_sec).collect();
    let totals: Vec<i64> = hourly.iter().map(|h| h.total_queries).collect();
    let blocked: Vec<i64> = hourly.iter().map(|h| h.blocked_queries).collect();

    let hourly_times_json = serde_json::to_string(&times).unwrap_or_else(|_| "[]".to_string());
    let hourly_totals_json = serde_json::to_string(&totals).unwrap_or_else(|_| "[]".to_string());
    let hourly_blocked_json = serde_json::to_string(&blocked).unwrap_or_else(|_| "[]".to_string());

    HtmlTemplate(DashboardTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "dashboard",
        version: env!("CARGO_PKG_VERSION"),
        stats: &stats,
        status: &status,
        uptime_str,
        blocked_pct_str,
        upstreams,
        hourly_times_json,
        hourly_totals_json,
        hourly_blocked_json,
    })
    .into_response()
}

pub async fn dashboard_stats_partial(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
) -> Response {
    if get_session_user(&ctx, &headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let stats = ctx
        .stats_db
        .get_global_stats(86_400_000)
        .await
        .unwrap_or_default();
    let status = get_status_response(&ctx);
    let uptime_str = format_duration(status.uptime_seconds);
    let blocked_pct_str = format!("{:.1}", stats.blocked_percentage);

    HtmlTemplate(DashboardStatsPartialTemplate {
        stats: &stats,
        status: &status,
        uptime_str,
        blocked_pct_str,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// Query Log
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct QueryLogParams {
    pub domain: Option<String>,
    pub client: Option<String>,
    pub status: Option<String>,
    pub qtype: Option<String>,
}

async fn fetch_query_rows(ctx: &ServerContext, p: &QueryLogParams) -> Vec<QueryLogRowItem> {
    let qtype_num = p.qtype.as_deref().and_then(|s| {
        if s == "all" || s.is_empty() {
            None
        } else {
            s.parse::<u16>().ok()
        }
    });

    let status_filter = p.status.as_deref().and_then(|s| {
        if s == "all" || s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    });

    let filter = QueryLogFilter {
        client: p.client.clone().filter(|s| !s.is_empty()),
        domain: p.domain.clone().filter(|s| !s.is_empty()),
        status: status_filter,
        qtype: qtype_num,
        from: None,
        to: None,
        cursor: None,
        limit: Some(50),
    };

    let page_res = ctx.stats_db.query_logs(&filter).await;
    let entries = match page_res {
        Ok(p) => p.entries,
        Err(_) => Vec::new(),
    };

    entries
        .into_iter()
        .map(|e| {
            let dt = DateTime::<Utc>::from_timestamp_millis(e.ts).unwrap_or_default();
            let time_str = dt.format("%H:%M:%S").to_string();
            let latency_str = if let Some(us) = e.elapsed_us {
                format!("{:.1} ms", (us as f64) / 1000.0)
            } else {
                "<1 ms".to_string()
            };
            QueryLogRowItem {
                ts: e.ts,
                time_str,
                client_ip: e.client_ip,
                client_name: e.client_name,
                qname: e.qname,
                qtype_str: qtype_to_str(e.qtype).to_string(),
                verdict: e.verdict,
                latency_str,
                rule: e.rule,
                upstream: e.upstream,
            }
        })
        .collect()
}

pub async fn querylog_page(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Query(params): Query<QueryLogParams>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };

    let entries = fetch_query_rows(&ctx, &params).await;
    let csrf = get_csrf_token(&ctx, &headers);

    HtmlTemplate(QueryLogTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "querylog",
        version: env!("CARGO_PKG_VERSION"),
        entries: &entries,
    })
    .into_response()
}

pub async fn querylog_rows_partial(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Query(params): Query<QueryLogParams>,
) -> Response {
    if get_session_user(&ctx, &headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let entries = fetch_query_rows(&ctx, &params).await;
    HtmlTemplate(QueryLogRowsPartialTemplate { entries: &entries }).into_response()
}

// ---------------------------------------------------------------------------
// Filtering & Blocklists
// ---------------------------------------------------------------------------

pub async fn filtering_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let csrf = get_csrf_token(&ctx, &headers);

    let cfg = ctx.config.load();
    let snapshot = ctx.filter.snapshot();
    let lists: Vec<FilterListDto> = cfg
        .filtering
        .lists
        .iter()
        .map(|list| {
            let count = if list.enabled {
                snapshot
                    .rules
                    .iter()
                    .filter(|r| r.source == list.name)
                    .count()
            } else {
                0
            };
            FilterListDto {
                id: list.name.clone(),
                name: list.name.clone(),
                url: list.url.clone(),
                enabled: list.enabled,
                refresh_hours: list.refresh_hours.unwrap_or(24) as u32,
                rule_count: count,
                last_updated: None,
            }
        })
        .collect();

    let custom_rules = cfg.filtering.custom_rules.join("\n");

    // Curated lists bundled into the binary plus any runtime refresh state.
    let manifest = sito_clients::BundledManifest::bundled();
    let statuses: std::collections::HashMap<String, sito_clients::RuntimeListStatus> = ctx
        .runtime_lists
        .statuses()
        .into_iter()
        .map(|status| (status.category.clone(), status))
        .collect();
    let format_refresh = |ts: Option<u64>| {
        ts.and_then(|ts| chrono::DateTime::from_timestamp(ts.cast_signed(), 0))
            .map_or_else(
                || "—".to_string(),
                |dt| dt.format("%Y-%m-%d %H:%M UTC").to_string(),
            )
    };

    let mut bundled_lists: Vec<crate::ui::templates::BundledListView> = manifest
        .lists
        .iter()
        .map(|list| {
            let status = statuses.get(&list.id);
            crate::ui::templates::BundledListView {
                id: list.id.clone(),
                kind: list.kind.clone(),
                version: list.version.clone(),
                source: status
                    .and_then(|status| status.source_url.clone())
                    .unwrap_or_else(|| list.source.clone()),
                license: list.license.clone(),
                entries: status.map_or(list.entries, |status| status.entries),
                state: if status.is_some_and(|status| !status.bundled) {
                    "runtime refresh".to_string()
                } else {
                    "built-in (minimal)".to_string()
                },
                last_refresh: format_refresh(status.and_then(|status| status.last_refresh_unix)),
            }
        })
        .collect();
    for status in ctx.runtime_lists.statuses() {
        if manifest.list(&status.category).is_some() {
            continue;
        }
        bundled_lists.push(crate::ui::templates::BundledListView {
            id: status.category.clone(),
            kind: "custom".to_string(),
            version: "—".to_string(),
            source: status.source_url.clone().unwrap_or_default(),
            license: "—".to_string(),
            entries: status.entries,
            state: if status.bundled {
                "built-in".to_string()
            } else {
                "runtime refresh".to_string()
            },
            last_refresh: format_refresh(status.last_refresh_unix),
        });
    }
    bundled_lists.sort_by(|a, b| a.id.cmp(&b.id));

    HtmlTemplate(FilteringTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "filtering",
        version: env!("CARGO_PKG_VERSION"),
        lists: &lists,
        custom_rules: &custom_rules,
        bundled_lists,
    })
    .into_response()
}

/// Resolves a filter-list id: preferred key is the (unique) list name;
/// numeric indices from older clients keep working.
fn find_filter_list_index(cfg: &Config, id: &str) -> Option<usize> {
    if let Some(idx) = cfg.filtering.lists.iter().position(|list| list.name == id) {
        return Some(idx);
    }
    id.parse::<usize>()
        .ok()
        .filter(|idx| *idx < cfg.filtering.lists.len())
}

pub async fn filtering_toggle_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut new_cfg = (**ctx.config.load()).clone();
    let Some(idx) = find_filter_list_index(&new_cfg, &id) else {
        return error_response(StatusCode::NOT_FOUND, "Filter list not found");
    };
    new_cfg.filtering.lists[idx].enabled = !new_cfg.filtering.lists[idx].enabled;
    if let Err(e) = ctx.filter.reload_with_config(&new_cfg.filtering).await {
        tracing::error!("Failed to apply filter configuration: {e}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to apply filter configuration: {e}"),
        );
    }
    if let Err(e) = save_config_atomic(&ctx.config_path, &new_cfg).await {
        tracing::error!("Failed to persist configuration to disk: {e:?}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to persist configuration",
        );
    }
    ctx.set_config(new_cfg.clone());
    crate::publish_bundle(&ctx);
    Redirect::to("/filtering").into_response()
}

#[derive(Deserialize)]
pub struct AddFilterListForm {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub refresh_hours: Option<u32>,
}

pub async fn filtering_add_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<AddFilterListForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let name = form.name.trim().to_string();
    let url = form.url.trim().to_string();
    if !crate::handlers::filtering::valid_filter_list_name(&name) || url.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "List name must be non-empty and must not contain /, ?, # or % (URL is required)",
        );
    }

    let mut new_cfg = (**ctx.config.load()).clone();
    if new_cfg.filtering.lists.iter().any(|list| list.name == name) {
        return error_response(StatusCode::CONFLICT, "A list with that name already exists");
    }
    new_cfg.filtering.lists.push(FilterListConfig {
        name,
        url,
        enabled: true,
        refresh_hours: form.refresh_hours.map(u64::from),
    });
    if let Err(e) = ctx.filter.reload_with_config(&new_cfg.filtering).await {
        tracing::error!("Failed to apply filter configuration: {e}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to apply filter configuration: {e}"),
        );
    }
    if let Err(e) = save_config_atomic(&ctx.config_path, &new_cfg).await {
        tracing::error!("Failed to persist configuration to disk: {e:?}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to persist configuration",
        );
    }
    ctx.set_config(new_cfg.clone());
    crate::publish_bundle(&ctx);

    Redirect::to("/filtering").into_response()
}

pub async fn filtering_delete_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut new_cfg = (**ctx.config.load()).clone();
    let Some(idx) = find_filter_list_index(&new_cfg, &id) else {
        return error_response(StatusCode::NOT_FOUND, "Filter list not found");
    };
    new_cfg.filtering.lists.remove(idx);
    if let Err(e) = ctx.filter.reload_with_config(&new_cfg.filtering).await {
        tracing::error!("Failed to apply filter configuration: {e}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to apply filter configuration: {e}"),
        );
    }
    if let Err(e) = save_config_atomic(&ctx.config_path, &new_cfg).await {
        tracing::error!("Failed to persist configuration to disk: {e:?}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to persist configuration",
        );
    }
    ctx.set_config(new_cfg.clone());
    crate::publish_bundle(&ctx);
    Redirect::to("/filtering").into_response()
}

#[derive(Deserialize)]
pub struct CustomRulesForm {
    pub rules: String,
}

pub async fn filtering_custom_rules_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<CustomRulesForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut new_cfg = (**ctx.config.load()).clone();
    new_cfg.filtering.custom_rules = form
        .rules
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    if let Err(e) = ctx.filter.reload_with_config(&new_cfg.filtering).await {
        tracing::error!("Failed to apply filter configuration: {e}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to apply filter configuration: {e}"),
        );
    }
    if let Err(e) = save_config_atomic(&ctx.config_path, &new_cfg).await {
        tracing::error!("Failed to persist configuration to disk: {e:?}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to persist configuration",
        );
    }
    ctx.set_config(new_cfg.clone());
    crate::publish_bundle(&ctx);

    Redirect::to("/filtering").into_response()
}

#[derive(Deserialize)]
pub struct SimulateForm {
    pub domain: String,
}

pub async fn filtering_simulate_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<SimulateForm>,
) -> Response {
    if get_session_user(&ctx, &headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let clean = form.domain.trim();
    if clean.is_empty() {
        return axum::response::Html("<span class='badge badge-neutral'>Enter a domain</span>")
            .into_response();
    }

    let dummy_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let client_ctx = sito_core::client::ClientContext::new(dummy_ip);
    if let Ok(name) = sito_proto::Name::from_str(clean) {
        let verdict = ctx
            .filter
            .evaluate(&name, sito_proto::RecordType::A, &client_ctx);
        match verdict {
            sito_core::verdict::Verdict::Block(reason) => {
                let reason_str = match reason {
                    sito_core::verdict::BlockReason::Rule(rf) => rf.rule_text,
                    sito_core::verdict::BlockReason::Parental => "parental filter".to_string(),
                    sito_core::verdict::BlockReason::Service(s) => format!("blocked service: {s}"),
                    sito_core::verdict::BlockReason::AntiDohBypass => "Anti-DoH bypass".to_string(),
                    sito_core::verdict::BlockReason::FilterUnavailable => {
                        "filter rules unavailable (fail-closed)".to_string()
                    }
                };
                axum::response::Html(format!(
                    "<div class='badge badge-danger' style='font-size:0.9rem; padding: 6px 12px;'>BLOCKED ({})</div>",
                    escape_html(&reason_str)
                ))
                .into_response()
            }
            sito_core::verdict::Verdict::Allow(_) => {
                axum::response::Html(
                    "<div class='badge badge-success' style='font-size:0.9rem; padding: 6px 12px;'>ALLOWED (No matching block rule)</div>"
                )
                .into_response()
            }
            sito_core::verdict::Verdict::Rewrite(_) => {
                axum::response::Html(
                    "<div class='badge badge-info' style='font-size:0.9rem; padding: 6px 12px;'>REWRITTEN</div>"
                )
                .into_response()
            }
        }
    } else {
        axum::response::Html("<span class='badge badge-danger'>Invalid domain format</span>")
            .into_response()
    }
}

pub async fn filtering_update_all_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }
    let cfg = ctx.config.load();
    if let Err(e) = ctx.filter.reload_with_config(&cfg.filtering).await {
        tracing::error!("Failed to refresh filter lists: {e}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to refresh filter lists: {e}"),
        );
    }
    Redirect::to("/filtering").into_response()
}

// ---------------------------------------------------------------------------
// DNS Rewrites
// ---------------------------------------------------------------------------

pub async fn rewrites_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let csrf = get_csrf_token(&ctx, &headers);

    let store = crate::handlers::rewrites::load_rewrite_store(&ctx);
    let rewrites: Vec<RewriteViewItem> = store
        .ids
        .into_iter()
        .zip(store.cfg.entries)
        .map(|(id, r)| RewriteViewItem {
            id,
            domain: r.domain,
            record_type: r.r#type,
            answer: r.answer,
        })
        .collect();

    HtmlTemplate(RewritesTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "rewrites",
        version: env!("CARGO_PKG_VERSION"),
        rewrites,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct AddRewriteForm {
    pub domain: String,
    pub record_type: String,
    pub answer: String,
}

pub async fn rewrites_add_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<AddRewriteForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut store = crate::handlers::rewrites::load_rewrite_store(&ctx);
    store.cfg.entries.push(sito_rewrites::RewriteEntryConfig {
        domain: form.domain,
        r#type: form.record_type,
        answer: form.answer,
        exception_clients: Vec::new(),
    });
    store.ids.push(crate::handlers::rewrites::new_rewrite_id());

    if let Err(e) = crate::handlers::rewrites::save_rewrite_store(&ctx, &store).await {
        tracing::error!("Failed to persist rewrites: {e:?}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to persist rewrites: {}", e.detail),
        );
    }

    Redirect::to("/rewrites").into_response()
}

#[derive(Deserialize)]
pub struct DeleteRewriteForm {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub record_type: Option<String>,
    #[serde(default)]
    pub answer: Option<String>,
}

pub async fn rewrites_delete_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<DeleteRewriteForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut store = crate::handlers::rewrites::load_rewrite_store(&ctx);
    let idx = if let Some(ref id) = form.id {
        crate::handlers::rewrites::resolve_rewrite_index(&store, id)
    } else {
        store.cfg.entries.iter().position(|e| {
            form.domain.as_deref().is_none_or(|d| e.domain == d)
                && form.record_type.as_deref().is_none_or(|t| e.r#type == t)
                && form.answer.as_deref().is_none_or(|a| e.answer == a)
        })
    };
    let Some(idx) = idx else {
        return error_response(StatusCode::NOT_FOUND, "Rewrite not found");
    };
    store.cfg.entries.remove(idx);
    store.ids.remove(idx);

    if let Err(e) = crate::handlers::rewrites::save_rewrite_store(&ctx, &store).await {
        tracing::error!("Failed to persist rewrites: {e:?}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to persist rewrites: {}", e.detail),
        );
    }

    Redirect::to("/rewrites").into_response()
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

fn load_clients_config(ctx: &ServerContext) -> sito_clients::ClientsConfig {
    ctx.config
        .load()
        .clients
        .as_ref()
        .and_then(|v| v.clone().try_into().ok())
        .unwrap_or_default()
}

pub async fn clients_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let csrf = get_csrf_token(&ctx, &headers);

    let clients_cfg = load_clients_config(&ctx);
    let clients: Vec<ClientViewItem> = clients_cfg
        .entries
        .into_iter()
        .map(|c| ClientViewItem {
            name: c.name,
            ids: c.ids,
            group: c.group,
        })
        .collect();

    HtmlTemplate(ClientsTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "clients",
        version: env!("CARGO_PKG_VERSION"),
        clients,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct AddClientForm {
    pub name: String,
    pub ids: String,
    pub group: String,
}

pub async fn clients_add_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<AddClientForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut clients_cfg = load_clients_config(&ctx);
    if clients_cfg.entries.iter().any(|c| c.name == form.name) {
        return error_response(
            StatusCode::CONFLICT,
            "A client with that name already exists",
        );
    }
    let ids: Vec<String> = form
        .ids
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    clients_cfg.entries.push(sito_clients::ClientEntryConfig {
        name: form.name,
        ids,
        group: if form.group.trim().is_empty() {
            "default".to_string()
        } else {
            form.group
        },
        ignore_query_log: false,
        ignore_stats: false,
        use_global_upstreams: true,
        upstreams: None,
        trusted: false,
    });

    let val = match toml::Value::try_from(&clients_cfg) {
        Ok(val) => val,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to serialize clients: {e}"),
            );
        }
    };
    let mut new_cfg = (**ctx.config.load()).clone();
    new_cfg.clients = Some(val);
    if let Err(e) = save_config_atomic(&ctx.config_path, &new_cfg).await {
        tracing::error!("Failed to persist configuration to disk: {e:?}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to persist clients",
        );
    }
    ctx.set_config(new_cfg);
    let new_reg = sito_clients::ClientRegistry::new(clients_cfg);
    ctx.set_clients(new_reg);
    crate::publish_bundle(&ctx);

    Redirect::to("/clients").into_response()
}

#[derive(Deserialize)]
pub struct DeleteClientForm {
    pub name: String,
}

pub async fn clients_delete_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<DeleteClientForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut clients_cfg = load_clients_config(&ctx);
    let before = clients_cfg.entries.len();
    clients_cfg.entries.retain(|c| c.name != form.name);
    if clients_cfg.entries.len() == before {
        return error_response(StatusCode::NOT_FOUND, "Client not found");
    }

    let val = match toml::Value::try_from(&clients_cfg) {
        Ok(val) => val,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to serialize clients: {e}"),
            );
        }
    };
    let mut new_cfg = (**ctx.config.load()).clone();
    new_cfg.clients = Some(val);
    if let Err(e) = save_config_atomic(&ctx.config_path, &new_cfg).await {
        tracing::error!("Failed to persist configuration to disk: {e:?}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to persist clients",
        );
    }
    ctx.set_config(new_cfg);
    let new_reg = sito_clients::ClientRegistry::new(clients_cfg);
    ctx.set_clients(new_reg);
    crate::publish_bundle(&ctx);

    Redirect::to("/clients").into_response()
}

// ---------------------------------------------------------------------------
// Upstreams
// ---------------------------------------------------------------------------

pub async fn upstreams_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let csrf = get_csrf_token(&ctx, &headers);

    let upstreams = get_upstreams_list(&ctx).await;

    HtmlTemplate(UpstreamsTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "upstreams",
        version: env!("CARGO_PKG_VERSION"),
        upstreams,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct AddUpstreamForm {
    pub address: String,
    pub weight: u32,
}

pub async fn upstreams_add_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<AddUpstreamForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut new_cfg = (**ctx.config.load()).clone();
    let clean = form.address.trim().to_string();
    if clean.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Upstream address is required");
    }
    if new_cfg.upstream.servers.contains(&clean) {
        return error_response(StatusCode::CONFLICT, "Upstream is already configured");
    }
    new_cfg.upstream.servers.push(clean);
    let bootstrap = sito_upstream::BootstrapResolver::new(
        new_cfg.upstream.bootstrap.clone(),
        std::time::Duration::from_millis(new_cfg.upstream.timeout_ms),
    );
    if let Err(e) = ctx.upstream.reload(&new_cfg.upstream, &bootstrap).await {
        tracing::error!("Failed to reload upstream manager: {e:?}");
        return error_response(
            StatusCode::BAD_REQUEST,
            &format!("Invalid upstream configuration: {e}"),
        );
    }
    if let Err(e) = save_config_atomic(&ctx.config_path, &new_cfg).await {
        tracing::error!("Failed to persist configuration to disk: {e:?}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to persist configuration",
        );
    }
    ctx.set_config(new_cfg.clone());
    crate::publish_bundle(&ctx);

    Redirect::to("/upstreams").into_response()
}

#[derive(Deserialize)]
pub struct TestUpstreamForm {
    pub address: String,
    /// Accepted for first-boot setup requests (the wizard embeds it as a
    /// hidden form field in addition to the `X-Setup-Token` header).
    #[serde(default)]
    pub setup_token: Option<String>,
}

pub async fn upstreams_test_handler(
    State(ctx): State<ServerContext>,
    crate::auth::MaybeConnectInfo(peer_addr): crate::auth::MaybeConnectInfo,
    headers: HeaderMap,
    Form(form): Form<TestUpstreamForm>,
) -> Response {
    // Auth: a valid session wins; otherwise first-boot setup requires the
    // one-time setup token (or legacy setup-pending mode for in-memory tests).
    if get_session_user(&ctx, &headers).is_none() {
        let config = ctx.config.load();
        let trusted_proxies = config.get_web_config().trusted_proxies.clone();
        let probe_domain = config.upstream.probe_domain.clone();
        drop(config);
        let client_ip = resolve_client_ip(peer_addr, &headers, &trusted_proxies);

        if ctx.auth_mgr.setup_token_required() {
            let candidate = headers
                .get(crate::router::SETUP_TOKEN_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .or(form.setup_token.as_deref().map(str::trim));
            match ctx.auth_mgr.validate_setup_token(candidate, &client_ip) {
                crate::auth::SetupTokenStatus::Valid => {}
                crate::auth::SetupTokenStatus::RateLimited => {
                    return error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        "Too many invalid setup token attempts. Try again later.",
                    );
                }
                _ => {
                    return error_response(
                        StatusCode::FORBIDDEN,
                        "First-boot setup token required (see server logs).",
                    );
                }
            }
        } else if !ctx.is_setup_pending() && !ctx.auth_mgr.is_first_run() {
            return StatusCode::UNAUTHORIZED.into_response();
        }

        return run_upstream_probe(clean_address(&form.address), &probe_domain).await;
    }

    let probe_domain = ctx.config.load().upstream.probe_domain.clone();
    run_upstream_probe(clean_address(&form.address), &probe_domain).await
}

fn clean_address(address: &str) -> &str {
    address.trim()
}

async fn run_upstream_probe(clean: &str, probe_domain: &str) -> Response {
    if clean.is_empty() {
        return axum::response::Html(
            "<div class='badge badge-danger' style='font-size:0.9rem; padding: 6px 12px;'>Invalid upstream address</div>",
        )
        .into_response();
    }

    let result = tokio::time::timeout(
        crate::probe::PROBE_TIMEOUT,
        probe_upstream_target(clean, probe_domain),
    )
    .await;
    match result {
        Ok(Ok(elapsed)) => axum::response::Html(format!(
            "<div class='badge badge-success' style='font-size:0.9rem; padding: 6px 12px;'>Resolver {} is reachable (RTT: {:.1} ms)</div>",
            escape_html(clean),
            elapsed
        ))
        .into_response(),
        Ok(Err(e)) => axum::response::Html(format!(
            "<div class='badge badge-danger' style='font-size:0.9rem; padding: 6px 12px;'>Resolver {} error: {}</div>",
            escape_html(clean),
            escape_html(&e)
        ))
        .into_response(),
        Err(_) => axum::response::Html(format!(
            "<div class='badge badge-danger' style='font-size:0.9rem; padding: 6px 12px;'>Resolver {} error: probe timed out</div>",
            escape_html(clean)
        ))
        .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

pub async fn settings_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let csrf = get_csrf_token(&ctx, &headers);

    let cfg = ctx.config.load();

    HtmlTemplate(SettingsTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "settings",
        version: env!("CARGO_PKG_VERSION"),
        cache_size_mb: cfg.dns.cache.size_mb,
        min_ttl: cfg.dns.cache.min_ttl,
        dnssec_enabled: cfg.dns.dnssec.validate,
        rate_limit: cfg.dns.rate_limit_per_ip,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct SaveSettingsForm {
    pub cache_size_mb: usize,
    pub min_ttl: u32,
    pub dnssec: Option<String>,
    pub rate_limit: u32,
}

pub async fn settings_save_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<SaveSettingsForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Admin {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut new_cfg = (**ctx.config.load()).clone();
    new_cfg.dns.cache.size_mb = form.cache_size_mb;
    new_cfg.dns.cache.min_ttl = form.min_ttl;
    new_cfg.dns.dnssec.validate = form.dnssec.is_some();
    new_cfg.dns.rate_limit_per_ip = form.rate_limit;

    if let Err(e) = save_config_atomic(&ctx.config_path, &new_cfg).await {
        tracing::error!("Failed to persist configuration to disk: {e:?}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    ctx.set_config(new_cfg);
    crate::publish_bundle(&ctx);

    Redirect::to("/settings").into_response()
}

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

pub async fn system_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let csrf = get_csrf_token(&ctx, &headers);

    let status = get_status_response(&ctx);
    let uptime_str = format_duration(status.uptime_seconds);

    HtmlTemplate(SystemTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "system",
        version: env!("CARGO_PKG_VERSION"),
        status: &status,
        uptime_str,
    })
    .into_response()
}

pub async fn system_reload_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Admin {
        return StatusCode::FORBIDDEN.into_response();
    }

    let toml_str = match tokio::fs::read_to_string(&ctx.config_path).await {
        Ok(content) => content,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to read configuration file: {e}"),
            );
        }
    };
    let cfg = match sito_core::config::Config::from_toml_str(&toml_str) {
        Ok(cfg) => cfg,
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("Invalid configuration on disk: {e}"),
            );
        }
    };
    if let Err(e) = ctx.filter.reload_with_config(&cfg.filtering).await {
        tracing::error!("Failed to apply filter configuration: {e}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to apply filter configuration: {e}"),
        );
    }
    let bootstrap = sito_upstream::BootstrapResolver::new(
        cfg.upstream.bootstrap.clone(),
        std::time::Duration::from_millis(cfg.upstream.timeout_ms),
    );
    if let Err(e) = ctx.upstream.reload(&cfg.upstream, &bootstrap).await {
        tracing::error!("Failed to apply upstream configuration: {e}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to apply upstream configuration: {e}"),
        );
    }
    ctx.set_config(cfg);
    crate::publish_bundle(&ctx);
    Redirect::to("/system").into_response()
}

pub async fn system_update_check_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
) -> Response {
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }

    match crate::updater::check_for_update(None).await {
        Ok(info) => {
            if info.update_available {
                let install_or_docker = if info.is_docker {
                    r#"<div style="margin-top: 14px; padding: 12px; background: rgba(56, 189, 248, 0.1); border: 1px solid var(--accent); border-radius: 6px;">
                            <div style="font-weight: 600; color: var(--accent); margin-bottom: 4px;">Docker Environment Detected</div>
                            <div style="font-size: 0.85rem; color: var(--text-secondary);">
                                In-app binary updates are disabled in containers. Upgrade by running:
                                <pre style="margin-top: 6px; padding: 6px 10px; background: var(--bg-surface); border-radius: 4px;"><code>docker compose pull && docker compose up -d</code></pre>
                            </div>
                        </div>"#.to_string()
                } else {
                    format!(
                        r##"<form hx-post="/ui/system/update/apply" hx-target="#update-container" hx-swap="innerHTML" style="margin-top: 14px;">
                            <button type="submit" class="btn btn-primary" @click="this.disabled=true; this.innerText='Updating...'; this.form.submit();">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>
                                Download & Install v{}
                            </button>
                        </form>"##,
                        escape_html(&info.latest_version)
                    )
                };

                axum::response::Html(format!(
                    r#"<div>
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
                            <div>
                                <span class="badge badge-warning" style="font-size: 0.85rem;">New version available: v{}</span>
                                <span style="font-size: 0.85rem; color: var(--text-secondary); margin-left: 8px;">(Current: v{})</span>
                            </div>
                            <a href="{}" target="_blank" rel="noopener" class="btn btn-outline" style="font-size: 0.8rem; padding: 4px 10px;">View on GitHub</a>
                        </div>
                        <div style="background: var(--bg-base); padding: 12px; border-radius: 6px; font-size: 0.85rem; max-height: 150px; overflow-y: auto; white-space: pre-wrap; font-family: monospace;">{}</div>
                        {}
                    </div>"#,
                    escape_html(&info.latest_version),
                    escape_html(&info.current_version),
                    escape_html(&info.release_url),
                    escape_html(&info.release_notes),
                    install_or_docker
                )).into_response()
            } else {
                axum::response::Html(format!(
                    r##"<div>
                        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
                            <span class="badge badge-success" style="font-size: 0.85rem;">Up to date</span>
                            <span style="font-size: 0.875rem; color: var(--text-secondary);">sito is running the latest release (v{})</span>
                        </div>
                        <button hx-get="/ui/system/update/check" hx-target="#update-container" hx-swap="innerHTML" class="btn btn-outline" style="font-size: 0.8rem; padding: 4px 10px;">
                            Check Again
                        </button>
                    </div>"##,
                    escape_html(&info.current_version)
                )).into_response()
            }
        }
        Err(e) => {
            axum::response::Html(format!(
                r##"<div>
                    <div style="padding: 10px 14px; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); border-radius: 6px; color: var(--danger); font-size: 0.875rem; margin-bottom: 12px;">
                        Failed to check for updates: {}
                    </div>
                    <button hx-get="/ui/system/update/check" hx-target="#update-container" hx-swap="innerHTML" class="btn btn-outline" style="font-size: 0.8rem; padding: 4px 10px;">
                        Retry
                    </button>
                </div>"##,
                escape_html(&e.to_string())
            )).into_response()
        }
    }
}

pub async fn system_update_apply_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };

    if user.role != crate::auth::token::Role::Admin {
        return axum::response::Html(
            r#"<div style="padding: 12px; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); border-radius: 6px; color: var(--danger); font-size: 0.875rem;">
                Permission denied: Only administrators can install updates.
            </div>"#,
        ).into_response();
    }

    let require_signature = ctx.config.load().server.update_require_signature;
    match crate::updater::apply_update(None, false, require_signature).await {
        Ok(msg) => axum::response::Html(format!(
            r#"<div style="padding: 14px; background: rgba(34, 197, 94, 0.1); border: 1px solid var(--success); border-radius: 6px;">
                <div style="font-weight: 600; color: var(--success); margin-bottom: 4px;">Update Successful!</div>
                <div style="font-size: 0.875rem; color: var(--text-primary);">{}</div>
            </div>"#,
            escape_html(&msg)
        )).into_response(),
        Err(e) => axum::response::Html(format!(
            r##"<div>
                <div style="padding: 14px; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); border-radius: 6px; color: var(--danger); font-size: 0.875rem; margin-bottom: 12px;">
                    <strong>Update Failed:</strong> {}
                </div>
                <button hx-get="/ui/system/update/check" hx-target="#update-container" hx-swap="innerHTML" class="btn btn-outline" style="font-size: 0.8rem; padding: 4px 10px;">
                    Back to Update Status
                </button>
            </div>"##,
            escape_html(&e.to_string())
        )).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Setup Wizard
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct SetupTokenQuery {
    #[serde(default)]
    pub setup_token: Option<String>,
}

pub async fn wizard_page(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Query(params): Query<SetupTokenQuery>,
) -> Response {
    let auth_user = get_session_user(&ctx, &headers);
    let is_admin = auth_user.as_ref().is_some_and(|u| u.role == Role::Admin);

    if !ctx.is_setup_pending() && !ctx.auth_mgr.is_first_run() && !is_admin {
        return Redirect::to("/login").into_response();
    }

    let csrf = get_csrf_token(&ctx, &headers);
    let setup_required = ctx.auth_mgr.setup_token_required();
    // Only echo a token the requester already supplied; never reveal the
    // stored setup token in the rendered page on its own.
    let setup_token = params.setup_token.unwrap_or_default();

    HtmlTemplate(WizardTemplate {
        is_authenticated: auth_user.is_some(),
        username: auth_user.as_ref().map_or("admin", |u| &u.username),
        user_role: auth_user.as_ref().map_or("", |u| u.role.as_str()),
        active_tab: "wizard",
        version: env!("CARGO_PKG_VERSION"),
        csrf_token: &csrf,
        setup_required,
        setup_token: &setup_token,
    })
    .into_response()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WizardCompleteForm {
    /// One-time first-boot setup token (required while setup is pending).
    pub setup_token: Option<String>,

    // 1. Administrator account
    pub admin_user: Option<String>,
    pub admin_password: Option<String>,
    pub confirm_password: Option<String>,

    // 2. DNS listeners
    pub bind_ipv4: Option<String>,
    pub bind_ipv6: Option<String>,
    pub port: Option<String>,
    pub dot_port: Option<String>,
    pub doh_port: Option<String>,
    pub doq_port: Option<String>,

    // 3. Upstreams
    pub upstreams: Option<String>,
    pub upstream: Option<String>,
    pub upstream_strategy: Option<String>,
    pub bootstrap: Option<String>,
    pub timeout_ms: Option<String>,

    // 4. Cache & DNSSEC
    pub cache_enabled: Option<String>,
    pub cache_size_mb: Option<String>,
    pub dnssec_mode: Option<String>,
    pub dnssec_validate: Option<String>,

    // 5. Filtering
    pub filtering_enabled: Option<String>,
    pub enable_adblock: Option<String>,
    pub blocking_mode: Option<String>,
    pub cname_cloaking: Option<String>,
    pub list_oisd_big: Option<String>,
    pub list_oisd_small: Option<String>,
    pub list_stevenblack: Option<String>,
    pub list_hagezi: Option<String>,

    // 6. Web panel & stats
    pub web_bind: Option<String>,
    pub web_port: Option<String>,
    pub retention_days: Option<String>,
}

impl WizardCompleteForm {
    fn is_checkbox_checked(val: Option<&str>) -> bool {
        match val {
            Some(v) => {
                let v = v.trim();
                v == "on" || v == "true" || v == "yes" || v == "1"
            }
            None => false,
        }
    }

    pub fn build_config(&self, base: &Config) -> Result<Config, String> {
        let mut cfg = base.clone();

        // 2. DNS Listeners
        let v4_present = self.bind_ipv4.is_some();
        let v6_present = self.bind_ipv6.is_some();
        if v4_present || v6_present {
            let mut binds = Vec::new();
            if Self::is_checkbox_checked(self.bind_ipv4.as_deref()) {
                binds.push(IpAddr::from_str("0.0.0.0").unwrap());
            }
            if Self::is_checkbox_checked(self.bind_ipv6.as_deref()) {
                binds.push(IpAddr::from_str("::").unwrap());
            }
            if binds.is_empty() {
                return Err(
                    "At least one DNS bind address (IPv4 or IPv6) must be selected".to_string(),
                );
            }
            cfg.dns.bind = binds;
        }

        if let Some(s) = self
            .port
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.dns.port = s
                .parse::<u16>()
                .map_err(|_| format!("Invalid DNS port: '{s}'"))?;
        }
        if let Some(s) = self
            .dot_port
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.dns.dot_port = s
                .parse::<u16>()
                .map_err(|_| format!("Invalid DoT port: '{s}'"))?;
        }
        if let Some(s) = self
            .doh_port
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.dns.doh_port = s
                .parse::<u16>()
                .map_err(|_| format!("Invalid DoH port: '{s}'"))?;
        }
        if let Some(s) = self
            .doq_port
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.dns.doq_port = s
                .parse::<u16>()
                .map_err(|_| format!("Invalid DoQ port: '{s}'"))?;
        }

        // 3. Upstream Resolvers
        let mut servers = Vec::new();
        if let Some(s) = self
            .upstreams
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            for line in s.lines() {
                for part in line.split(',') {
                    let clean = part.trim();
                    if !clean.is_empty() {
                        servers.push(clean.to_string());
                    }
                }
            }
        }
        if servers.is_empty()
            && let Some(single) = self
                .upstream
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            servers.push(single.to_string());
        }
        if !servers.is_empty() {
            cfg.upstream.servers = servers;
        }

        if let Some(s) = self
            .upstream_strategy
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            match s.to_ascii_lowercase().as_str() {
                "failover" => cfg.upstream.strategy = UpstreamStrategy::Failover,
                "parallel" => cfg.upstream.strategy = UpstreamStrategy::Parallel,
                "load_balance" | "loadbalance" => {
                    cfg.upstream.strategy = UpstreamStrategy::LoadBalance;
                }
                other => return Err(format!("Invalid upstream strategy: '{other}'")),
            }
        }

        if let Some(s) = self
            .bootstrap
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let mut boots = Vec::new();
            for part in s.split([',', ' ', '\n']) {
                let clean = part.trim();
                if !clean.is_empty() {
                    let ip = IpAddr::from_str(clean)
                        .map_err(|_| format!("Invalid bootstrap IP: '{clean}'"))?;
                    boots.push(ip);
                }
            }
            if !boots.is_empty() {
                cfg.upstream.bootstrap = boots;
            }
        }

        if let Some(s) = self
            .timeout_ms
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.upstream.timeout_ms = s
                .parse::<u64>()
                .map_err(|_| format!("Invalid timeout_ms: '{s}'"))?;
        }

        // 4. Cache & DNSSEC
        if self.cache_enabled.is_some() {
            cfg.dns.cache.enabled = Self::is_checkbox_checked(self.cache_enabled.as_deref());
        }
        if let Some(s) = self
            .cache_size_mb
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.dns.cache.size_mb = s
                .parse::<usize>()
                .map_err(|_| format!("Invalid cache_size_mb: '{s}'"))?;
        }
        if let Some(s) = self
            .dnssec_mode
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.dns.dnssec.mode = s.to_string();
        }
        if self.dnssec_validate.is_some() {
            cfg.dns.dnssec.validate = Self::is_checkbox_checked(self.dnssec_validate.as_deref());
        }

        // 5. Filtering & Protection
        if self.filtering_enabled.is_some() {
            cfg.filtering.enabled = Self::is_checkbox_checked(self.filtering_enabled.as_deref());
        } else if self.enable_adblock.is_some() {
            cfg.filtering.enabled = Self::is_checkbox_checked(self.enable_adblock.as_deref());
        }

        if let Some(s) = self
            .blocking_mode
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            match s.to_ascii_lowercase().as_str() {
                "zero_ip" => cfg.filtering.blocking_mode = BlockingMode::ZeroIp,
                "nxdomain" => cfg.filtering.blocking_mode = BlockingMode::Nxdomain,
                "refused" => cfg.filtering.blocking_mode = BlockingMode::Refused,
                "null_rdata" => cfg.filtering.blocking_mode = BlockingMode::NullRdata,
                other => {
                    if let Ok(ip) = IpAddr::from_str(other) {
                        cfg.filtering.blocking_mode = BlockingMode::CustomIp(ip);
                    } else {
                        return Err(format!("Invalid blocking mode: '{other}'"));
                    }
                }
            }
        }

        if self.cname_cloaking.is_some() {
            cfg.filtering.cname_cloaking =
                Self::is_checkbox_checked(self.cname_cloaking.as_deref());
        }

        let mut lists = Vec::new();
        if Self::is_checkbox_checked(self.list_oisd_big.as_deref()) {
            lists.push(FilterListConfig {
                name: "OISD Big".to_string(),
                url: "https://big.oisd.nl".to_string(),
                enabled: true,
                refresh_hours: None,
            });
        }
        if Self::is_checkbox_checked(self.list_oisd_small.as_deref()) {
            lists.push(FilterListConfig {
                name: "OISD Small".to_string(),
                url: "https://small.oisd.nl".to_string(),
                enabled: true,
                refresh_hours: None,
            });
        }
        if Self::is_checkbox_checked(self.list_stevenblack.as_deref()) {
            lists.push(FilterListConfig {
                name: "StevenBlack Hosts".to_string(),
                url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
                enabled: true,
                refresh_hours: None,
            });
        }
        if Self::is_checkbox_checked(self.list_hagezi.as_deref()) {
            lists.push(FilterListConfig {
                name: "Hagezi Pro".to_string(),
                url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"
                    .to_string(),
                enabled: true,
                refresh_hours: None,
            });
        }

        // If filtering is enabled and no preset lists were specifically checked,
        // preserve existing lists if any, or provide default OISD Big
        if lists.is_empty()
            && cfg.filtering.enabled
            && (self.enable_adblock.is_some() || self.filtering_enabled.is_some())
        {
            if cfg.filtering.lists.is_empty() {
                lists.push(FilterListConfig {
                    name: "OISD Big".to_string(),
                    url: "https://big.oisd.nl".to_string(),
                    enabled: true,
                    refresh_hours: None,
                });
            } else {
                lists.clone_from(&cfg.filtering.lists);
            }
        }
        if !lists.is_empty() {
            cfg.filtering.lists = lists;
        }

        // 6. Web Panel & Stats
        let mut web = cfg.get_web_config();
        if let Some(s) = self
            .web_bind
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            web.bind = IpAddr::from_str(s).map_err(|_| format!("Invalid web bind IP: '{s}'"))?;
        }
        if let Some(s) = self
            .web_port
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            web.port = s
                .parse::<u16>()
                .map_err(|_| format!("Invalid web port: '{s}'"))?;
        }
        cfg.set_web_config(web);

        let mut stats = cfg.get_stats_config();
        if let Some(s) = self
            .retention_days
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            stats.retention_days = s
                .parse::<u32>()
                .map_err(|_| format!("Invalid retention_days: '{s}'"))?;
        }
        let stats_value = toml::Value::try_from(stats)
            .map_err(|e| format!("Failed to serialize stats configuration: {e}"))?;
        cfg.stats = Some(stats_value);

        // Validate final configuration
        cfg.validate()
            .map_err(|e| format!("Configuration validation failed: {e}"))?;

        Ok(cfg)
    }
}

pub async fn wizard_complete_handler(
    State(ctx): State<ServerContext>,
    crate::auth::MaybeConnectInfo(peer_addr): crate::auth::MaybeConnectInfo,
    headers: HeaderMap,
    Form(form): Form<WizardCompleteForm>,
) -> Response {
    let first_run = ctx.auth_mgr.is_first_run();
    let is_first_run = ctx.is_setup_pending() || first_run;
    let auth_user = get_session_user(&ctx, &headers);
    let is_admin = auth_user.as_ref().is_some_and(|u| u.role == Role::Admin);

    if !is_first_run && !is_admin {
        return error_response(
            StatusCode::FORBIDDEN,
            "Setup wizard is disabled. Admin session required.",
        );
    }

    // Setup-pending with an already-configured admin account but no setup
    // token: an authenticated admin is required to change credentials.
    if !first_run && !is_admin && !ctx.auth_mgr.setup_token_required() {
        return error_response(
            StatusCode::FORBIDDEN,
            "Setup wizard is disabled. Admin session required.",
        );
    }

    // First-boot completion requires the one-time setup token (authenticated
    // admins and in-memory test managers without a provisioned token are
    // exempt).
    if ctx.auth_mgr.setup_token_required() && !is_admin {
        let config = ctx.config.load();
        let trusted_proxies = config.get_web_config().trusted_proxies.clone();
        drop(config);
        let client_ip = resolve_client_ip(peer_addr, &headers, &trusted_proxies);
        let candidate = form
            .setup_token
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty());
        match ctx.auth_mgr.validate_setup_token(candidate, &client_ip) {
            crate::auth::SetupTokenStatus::Valid => {}
            crate::auth::SetupTokenStatus::RateLimited => {
                return error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many invalid setup token attempts. Try again later.",
                );
            }
            _ => {
                return error_response(
                    StatusCode::FORBIDDEN,
                    "First-boot setup token required (see server logs).",
                );
            }
        }
    }

    let admin_user = match form.admin_user.as_deref().map(str::trim) {
        Some("") => {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid username: cannot be empty.",
            )
                .into_response();
        }
        Some(u) => u,
        None => "admin",
    };

    if admin_user.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid username: cannot contain whitespace or control characters.",
        )
            .into_response();
    }

    let admin_pass_input = form.admin_password.as_deref().map_or("", str::trim);
    let confirm_pass_input = form.confirm_password.as_deref().map_or("", str::trim);

    let effective_password = if admin_pass_input.is_empty() {
        // Never allow completing setup with the default bootstrap password.
        return (
            StatusCode::BAD_REQUEST,
            "Invalid password: a non-default administrator password is required.",
        )
            .into_response();
    } else {
        if admin_pass_input.len() < 8 {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid username or password: password must be at least 8 characters long.",
            )
                .into_response();
        }
        if !confirm_pass_input.is_empty() && confirm_pass_input != admin_pass_input {
            return (StatusCode::BAD_REQUEST, "Passwords do not match.").into_response();
        }
        if admin_pass_input.contains(|c: char| c.is_whitespace() || c.is_control()) {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid password: cannot contain whitespace or control characters.",
            )
                .into_response();
        }
        if admin_pass_input.eq_ignore_ascii_case("adminadmin") {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid password: the default password is not allowed.",
            )
                .into_response();
        }
        admin_pass_input
    };

    let base_cfg = (**ctx.config.load()).clone();
    let new_cfg = match form.build_config(&base_cfg) {
        Ok(cfg) => cfg,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid configuration: {e}"),
            )
                .into_response();
        }
    };

    // Persist the configuration before applying it so a failed apply does not
    // leave an unapplied file behind silently.
    if let Err(e) = save_config_atomic(&ctx.config_path, &new_cfg).await {
        tracing::error!("Failed to save config in wizard: {e:?}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to save configuration",
        );
    }

    if is_first_run {
        if ctx.auth_mgr.has_user(admin_user) {
            if !ctx
                .auth_mgr
                .update_user_password(admin_user, effective_password)
                .await
            {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "Failed to update administrator password.",
                );
            }
        } else {
            // Nonexistent user: create as admin
            ctx.auth_mgr
                .create_user(admin_user, effective_password, Role::Admin)
                .await;
            // If custom admin username chosen, remove default 'admin' account if still on bootstrap password
            if admin_user != "admin" && ctx.auth_mgr.is_default_admin_active() {
                ctx.auth_mgr.delete_user("admin");
            }
        }
        ctx.auth_mgr.mark_setup_complete();
    } else {
        // Not first run: must be authenticated admin updating existing admin credentials
        if !ctx.auth_mgr.has_user(admin_user) {
            return error_response(StatusCode::BAD_REQUEST, "Username does not exist.");
        }
        if !ctx
            .auth_mgr
            .update_user_password(admin_user, effective_password)
            .await
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                "Failed to update administrator password.",
            );
        }
    }

    if let Err(e) = ctx.filter.reload_with_config(&new_cfg.filtering).await {
        tracing::error!("Failed to apply filter configuration in wizard: {e}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to apply filter configuration: {e}"),
        );
    }
    let bootstrap = sito_upstream::BootstrapResolver::new(
        new_cfg.upstream.bootstrap.clone(),
        std::time::Duration::from_millis(new_cfg.upstream.timeout_ms),
    );
    if let Err(e) = ctx.upstream.reload(&new_cfg.upstream, &bootstrap).await {
        tracing::error!("Failed to apply upstream configuration in wizard: {e}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to apply upstream configuration: {e}"),
        );
    }

    ctx.set_config(new_cfg.clone());
    crate::publish_bundle(&ctx);

    ctx.auth_mgr.consume_setup_token();
    ctx.set_setup_pending(false);
    if let Some(ref starter) = ctx.dns_starter
        && let Err(e) = starter.send(())
    {
        tracing::warn!("Failed to notify DNS listener starter after setup: {e}");
    }

    Redirect::to("/login").into_response()
}

#[cfg(test)]
mod tests {
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

    async fn mock_context(temp_dir: &std::path::Path) -> ServerContext {
        let db_path = temp_dir.join("test.db");
        let stats_db = sito_stats::StatsDb::open(&db_path).await.unwrap();
        let querylog_writer = sito_stats::QueryLogWriter::spawn(stats_db.clone(), 100);
        let querylog_sender = querylog_writer.sender();
        let metrics = sito_stats::MetricsRegistry::new("1.2.1", "test");
        let auth_mgr = Arc::new(crate::auth::AuthManager::new());
        let config = Config::default();
        let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
        let filter = Arc::new(
            sito_filter::HostsFilterEngine::init(Default::default(), temp_dir.to_path_buf()).await,
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
            Arc::new(sito_clients::ParentalRegistry::bundled()),
            Arc::new(sito_clients::ServiceRegistry::bundled()),
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
            master_coordinator: None,
            slave_tracker: None,
            resync_sender: None,
            setup_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            dns_starter: None,
        }
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
        let temp_dir =
            std::env::temp_dir().join(format!("sito_ui_wiz_test_{}", rand::random::<u64>()));
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
            crate::auth::MaybeConnectInfo(None),
            HeaderMap::new(),
            Form(mismatch_form),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

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
        let temp_dir =
            std::env::temp_dir().join(format!("sito_ui_wiz_inv_{}", rand::random::<u64>()));
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
        assert!(ctx.config.load().filtering.lists.is_empty());

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
        assert!(
            crate::handlers::rewrites::load_rewrite_store(&ctx)
                .cfg
                .entries
                .is_empty()
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_disable_totp_requires_password_and_second_factor() {
        use crate::auth::rbac::RequireAdmin;
        use crate::handlers::auth_handlers::disable_totp;
        use crate::models::DisableTotpRequest;

        let temp_dir =
            std::env::temp_dir().join(format!("sito_ui_totp_off_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ctx = mock_context(&temp_dir).await;

        let setup = ctx.auth_mgr.init_totp_setup("admin").await.expect("setup");
        assert!(
            ctx.auth_mgr
                .confirm_totp_setup("admin", &setup.backup_codes[0])
                .await
        );
        assert!(ctx.auth_mgr.totp_enabled("admin"));

        let admin = RequireAdmin(crate::auth::AuthUser {
            username: "admin".to_string(),
            role: Role::Admin,
            token_id: None,
        });

        // Wrong password rejected even with a valid code.
        let err = disable_totp(
            admin.clone(),
            State(ctx.clone()),
            axum::Json(DisableTotpRequest {
                password: "wrong-password".to_string(),
                code: Some(setup.backup_codes[1].clone()),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, 401);
        assert!(ctx.auth_mgr.totp_enabled("admin"));

        // Correct password but missing second factor rejected.
        let err = disable_totp(
            admin.clone(),
            State(ctx.clone()),
            axum::Json(DisableTotpRequest {
                password: "adminadmin".to_string(),
                code: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, 400);
        assert!(ctx.auth_mgr.totp_enabled("admin"));

        // Correct password + valid backup code disables 2FA.
        let ok = disable_totp(
            admin,
            State(ctx.clone()),
            axum::Json(DisableTotpRequest {
                password: "adminadmin".to_string(),
                code: Some(setup.backup_codes[1].clone()),
            }),
        )
        .await;
        assert!(ok.is_ok());
        assert!(!ctx.auth_mgr.totp_enabled("admin"));

        let _ = std::fs::remove_dir_all(&temp_dir);
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
            crate::auth::MaybeConnectInfo(None),
            HeaderMap::new(),
            Form(with_token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(!ctx.auth_mgr.setup_token_required());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
