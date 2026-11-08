//! UI routes, HTMX partial endpoints, and form handlers.

use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::StatusCode;
use axum::http::header::{HeaderMap, SET_COOKIE};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::net::IpAddr;
use std::str::FromStr;

use crate::auth::manager::{LoginResult, TotpMutationError, UserMutationError};
use crate::auth::rbac::AuthUser;
use crate::auth::resolve_client_ip;
use crate::auth::session::{
    build_clear_csrf_cookie, build_clear_session_cookie, build_csrf_cookie, extract_session_cookie,
};
use crate::auth::token::Role;
use crate::config_apply::{
    ApplyHooks, ConfigFileApplyOutcome, FilterApply, apply_and_persist_config_locked,
    apply_config_document_event,
};
use crate::error::ProblemDetails;
use crate::handlers::auth_handlers::{
    user_mutation_problem, validate_password_policy, validate_username,
};
use crate::models::{FilterListDto, StatusResponse};
use crate::probe::probe_upstream_target;
use crate::state::ServerContext;
use crate::ui::templates::{
    AccountTemplate, ClientDiscoveryViewItem, ClientViewItem, ClientsTemplate,
    DashboardStatsPartialTemplate, DashboardTemplate, FilteringTemplate, HtmlTemplate,
    LoginTemplate, QueryLogRowItem, QueryLogRowsPartialTemplate, QueryLogTemplate, RewriteViewItem,
    RewritesTemplate, SettingsTemplate, SystemTemplate, TokenViewItem, UpstreamViewItem,
    UpstreamsTemplate, UserViewItem, UsersTemplate, WizardTemplate,
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
    let (trusted_proxies, is_secure) = {
        let config = ctx.config.load();
        let trusted_proxies = config.get_web_config().trusted_proxies;
        let scheme = crate::auth::admin_scheme_config(config.web.as_ref());
        let is_secure =
            crate::auth::is_https_request(peer_addr, &headers, &trusted_proxies, &scheme);
        (trusted_proxies, is_secure)
    };
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
        LoginResult::InvalidCredentials { .. } | LoginResult::StaleCredentials => {
            HtmlTemplate(LoginTemplate {
                is_authenticated: false,
                username: &form.username,
                user_role: "",
                active_tab: "login",
                version: env!("CARGO_PKG_VERSION"),
                error_message: "Invalid username or password.",
                csrf_token: "",
            })
            .into_response()
        }
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
        ctx.auth_mgr.logout(&session_id).await;
    }
    let is_secure = {
        let config = ctx.config.load();
        let trusted_proxies = config.get_web_config().trusted_proxies;
        let scheme = crate::auth::admin_scheme_config(config.web.as_ref());
        crate::auth::is_https_request(peer_addr, &headers, &trusted_proxies, &scheme)
    };
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

/// Builds the bundled-list rows shown on the filtering page.
///
/// `manifest` may be an error (corrupt embedded JSON): the error is logged and
/// the function degrades to the runtime-refresh rows only, so rendering the
/// page never panics.
fn bundled_list_views(
    manifest: Result<sito_clients::BundledManifest, serde_json::Error>,
    statuses: &[sito_clients::RuntimeListStatus],
) -> Vec<crate::ui::templates::BundledListView> {
    let manifest = match manifest {
        Ok(manifest) => manifest,
        Err(e) => {
            tracing::error!(
                error = %e,
                "Embedded bundled-list manifest is invalid; showing runtime refresh state only"
            );
            sito_clients::BundledManifest::empty()
        }
    };
    let statuses: std::collections::HashMap<&str, &sito_clients::RuntimeListStatus> = statuses
        .iter()
        .map(|status| (status.category.as_str(), status))
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
            let status = statuses.get(list.id.as_str()).copied();
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
    for status in statuses.values().copied() {
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
    bundled_lists
}

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
    let manifest = sito_clients::BundledManifest::try_bundled();
    let bundled_lists = bundled_list_views(manifest, &ctx.runtime_lists.statuses());

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

    let _apply_guard = ctx.lock_config_apply().await;
    let mut new_cfg = (**ctx.config.load()).clone();
    let Some(idx) = find_filter_list_index(&new_cfg, &id) else {
        return error_response(StatusCode::NOT_FOUND, "Filter list not found");
    };
    new_cfg.filtering.lists[idx].enabled = !new_cfg.filtering.lists[idx].enabled;
    if let Err(e) = apply_and_persist_config_locked(&ctx, &new_cfg, FilterApply::Sync, None).await {
        tracing::error!("Failed to apply filter configuration: {e:?}");
        return error_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &format!("Failed to apply filter configuration: {}", e.detail),
        );
    }
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

    let _apply_guard = ctx.lock_config_apply().await;
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
    if let Err(e) = apply_and_persist_config_locked(&ctx, &new_cfg, FilterApply::Sync, None).await {
        tracing::error!("Failed to apply filter configuration: {e:?}");
        return error_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &format!("Failed to apply filter configuration: {}", e.detail),
        );
    }

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

    let _apply_guard = ctx.lock_config_apply().await;
    let mut new_cfg = (**ctx.config.load()).clone();
    let Some(idx) = find_filter_list_index(&new_cfg, &id) else {
        return error_response(StatusCode::NOT_FOUND, "Filter list not found");
    };
    new_cfg.filtering.lists.remove(idx);
    if let Err(e) = apply_and_persist_config_locked(&ctx, &new_cfg, FilterApply::Sync, None).await {
        tracing::error!("Failed to apply filter configuration: {e:?}");
        return error_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &format!("Failed to apply filter configuration: {}", e.detail),
        );
    }
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

    let _apply_guard = ctx.lock_config_apply().await;
    let mut new_cfg = (**ctx.config.load()).clone();
    new_cfg.filtering.custom_rules = form
        .rules
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    if let Err(e) = apply_and_persist_config_locked(&ctx, &new_cfg, FilterApply::Sync, None).await {
        tracing::error!("Failed to apply filter configuration: {e:?}");
        return error_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &format!("Failed to apply filter configuration: {}", e.detail),
        );
    }

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
    ctx.cache.flush();
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

    let _apply_guard = ctx.lock_config_apply().await;
    let mut store = crate::handlers::rewrites::load_rewrite_store(&ctx);
    store.cfg.entries.push(sito_rewrites::RewriteEntryConfig {
        domain: form.domain,
        r#type: form.record_type,
        answer: form.answer,
        exception_clients: Vec::new(),
    });
    store.ids.push(crate::handlers::rewrites::new_rewrite_id());

    if let Err(e) = crate::handlers::rewrites::save_rewrite_store_locked(&ctx, &store).await {
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

    let _apply_guard = ctx.lock_config_apply().await;
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

    if let Err(e) = crate::handlers::rewrites::save_rewrite_store_locked(&ctx, &store).await {
        tracing::error!("Failed to persist rewrites: {e:?}");
        return error_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
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

/// Query parameters for the clients page.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ClientsPageQuery {
    /// 1-based page of the discovered-but-unidentified list.
    pub discovered_page: Option<usize>,
}

pub async fn clients_page(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Query(query): Query<ClientsPageQuery>,
) -> Response {
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

    // Discovered-client rows carry DHCP PII (IP/MAC/hostname), so they are
    // loaded and rendered for Operators and above only. The list is paginated
    // at the API's default page size; the registry itself keeps its hard cap.
    let can_view_discovered = user.role >= Role::Operator;
    let (discovered, discovered_total, discovered_page, discovered_pages): (
        Vec<ClientDiscoveryViewItem>,
        usize,
        usize,
        usize,
    ) = if can_view_discovered {
        let all = ctx.clients.load().unidentified_clients();
        let total = all.len();
        let page_size = crate::handlers::clients::DEFAULT_UNIDENTIFIED_LIMIT;
        let pages = total.div_ceil(page_size).max(1);
        let page = query.discovered_page.unwrap_or(1).clamp(1, pages);
        let rows = all
            .into_iter()
            .skip((page - 1) * page_size)
            .take(page_size)
            .map(|client| ClientDiscoveryViewItem {
                ip: client.ip.to_string(),
                mac: client.mac,
                hostname: client.hostname,
                last_seen: client.last_seen.format("%Y-%m-%d %H:%M UTC").to_string(),
            })
            .collect();
        (rows, total, page, pages)
    } else {
        (Vec::new(), 0, 1, 1)
    };

    HtmlTemplate(ClientsTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "clients",
        version: env!("CARGO_PKG_VERSION"),
        clients,
        discovered,
        discovered_total,
        can_view_discovered,
        discovered_page,
        discovered_pages,
        max_entries: sito_clients::MAX_UNIDENTIFIED_CLIENTS,
        retention_hours: sito_clients::UNIDENTIFIED_CLIENT_TTL_HOURS,
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
    Extension(hooks): Extension<ApplyHooks>,
    headers: HeaderMap,
    Form(form): Form<AddClientForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let _apply_guard = ctx.lock_config_apply().await;
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
    if let Err(e) =
        apply_and_persist_config_locked(&ctx, &new_cfg, FilterApply::Deferred, hooks.as_dyn()).await
    {
        tracing::error!("Failed to apply clients: {e:?}");
        return error_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &format!("Failed to persist clients: {}", e.detail),
        );
    }

    Redirect::to("/clients").into_response()
}

#[derive(Deserialize)]
pub struct DeleteClientForm {
    pub name: String,
}

pub async fn clients_delete_handler(
    State(ctx): State<ServerContext>,
    Extension(hooks): Extension<ApplyHooks>,
    headers: HeaderMap,
    Form(form): Form<DeleteClientForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let _apply_guard = ctx.lock_config_apply().await;
    let mut clients_cfg = load_clients_config(&ctx);
    let before = clients_cfg.entries.len();
    clients_cfg.entries.retain(|c| c.name != form.name);
    if clients_cfg.entries.len() == before {
        return error_response(StatusCode::NOT_FOUND, "Client not found");
    }
    // The shared DoH-path/DoT-SNI secret must not outlive its client entry.
    clients_cfg.client_id_secrets.remove(&form.name);

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
    if let Err(e) =
        apply_and_persist_config_locked(&ctx, &new_cfg, FilterApply::Deferred, hooks.as_dyn()).await
    {
        tracing::error!("Failed to apply clients: {e:?}");
        return error_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &format!("Failed to persist clients: {}", e.detail),
        );
    }

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
    Extension(hooks): Extension<ApplyHooks>,
    headers: HeaderMap,
    Form(form): Form<AddUpstreamForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let clean = form.address.trim().to_string();
    if clean.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Upstream address is required");
    }

    let _apply_guard = ctx.lock_config_apply().await;
    let mut new_cfg = (**ctx.config.load()).clone();
    if new_cfg.upstream.servers.contains(&clean) {
        return error_response(StatusCode::CONFLICT, "Upstream is already configured");
    }
    new_cfg.upstream.servers.push(clean);
    if let Err(e) =
        apply_and_persist_config_locked(&ctx, &new_cfg, FilterApply::Deferred, hooks.as_dyn()).await
    {
        tracing::error!("Failed to apply upstream configuration: {e:?}");
        return error_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &format!("Failed to apply upstream configuration: {}", e.detail),
        );
    }

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
    // Authenticated sessions must have at least the Operator role, mirroring
    // the REST probe endpoint. The first-boot path (setup token) stays
    // available for the wizard.
    if let Some(user) = get_session_user(&ctx, &headers) {
        if user.role < Role::Operator {
            return StatusCode::FORBIDDEN.into_response();
        }
        let probe_domain = ctx.config.load().upstream.probe_domain.clone();
        return run_upstream_probe(clean_address(&form.address), &probe_domain).await;
    }

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
    Extension(hooks): Extension<ApplyHooks>,
    headers: HeaderMap,
    Form(form): Form<SaveSettingsForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Admin {
        return StatusCode::FORBIDDEN.into_response();
    }

    // Read the current config only after taking the apply lock so a concurrent
    // clients/filter write cannot be overwritten by a stale settings snapshot.
    let _apply_guard = ctx.lock_config_apply().await;
    let mut new_cfg = (**ctx.config.load()).clone();
    new_cfg.dns.cache.size_mb = form.cache_size_mb;
    new_cfg.dns.cache.min_ttl = form.min_ttl;
    new_cfg.dns.dnssec.validate = form.dnssec.is_some();
    new_cfg.dns.rate_limit_per_ip = form.rate_limit;

    // Same apply-then-persist pipeline as the REST API: the settings take
    // effect (and are validated) before the file is written, and a failed
    // write rolls the in-memory apply back.
    if let Err(e) =
        apply_and_persist_config_locked(&ctx, &new_cfg, FilterApply::Sync, hooks.as_dyn()).await
    {
        tracing::error!("Failed to apply settings: {e:?}");
        return StatusCode::from_u16(e.status)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            .into_response();
    }

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
    Extension(hooks): Extension<ApplyHooks>,
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
    // One shared apply/publish path with the REST reload and file watcher:
    // deep validation, rollback on failure, D8 HA semantics, and oversized
    // bundle rollback all behave identically here.
    match apply_config_document_event(&ctx, &toml_str, FilterApply::Sync, hooks.as_dyn()).await {
        ConfigFileApplyOutcome::SelfWriteIgnored | ConfigFileApplyOutcome::Applied(_) => {
            Redirect::to("/system").into_response()
        }
        ConfigFileApplyOutcome::Rejected(e) => {
            tracing::error!("Failed to apply configuration on reload: {e:?}");
            error_response(
                StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                &format!("Failed to apply configuration: {}", e.detail),
            )
        }
    }
}

/// Renders the update action row for the system page.
///
/// Session-authenticated HTMX posts must carry the session CSRF token. The
/// form includes it as a hidden field (matching the Askama forms) and lets
/// htmx perform the submission; calling `form.submit()` natively would bypass
/// htmx and still lack the token.
fn update_action_html(info: &crate::updater::UpdateInfo, csrf_token: &str) -> String {
    if info.is_docker {
        return r#"<div style="margin-top: 14px; padding: 12px; background: rgba(56, 189, 248, 0.1); border: 1px solid var(--accent); border-radius: 6px;">
                <div style="font-weight: 600; color: var(--accent); margin-bottom: 4px;">Docker Environment Detected</div>
                <div style="font-size: 0.85rem; color: var(--text-secondary);">
                    In-app binary updates are disabled in containers. Upgrade by running:
                    <pre style="margin-top: 6px; padding: 6px 10px; background: var(--bg-surface); border-radius: 4px;"><code>docker compose pull && docker compose up -d</code></pre>
                </div>
            </div>"#
            .to_string();
    }

    format!(
        r##"<form hx-post="/ui/system/update/apply" hx-target="#update-container" hx-swap="innerHTML" hx-disabled-elt="button" style="margin-top: 14px;">
            <input type="hidden" name="csrf_token" value="{}">
            <button type="submit" class="btn btn-primary" @click="this.innerText='Updating...';">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>
                Download & Install v{}
            </button>
        </form>"##,
        escape_html(csrf_token),
        escape_html(&info.latest_version)
    )
}

pub async fn system_update_check_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
) -> Response {
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }
    let csrf = get_csrf_token(&ctx, &headers);

    match crate::updater::check_for_update(None).await {
        Ok(info) => {
            if info.update_available {
                let install_or_docker = update_action_html(&info, &csrf);

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
    let setup_required = ctx.auth_mgr.setup_token_required();

    // Once user accounts exist (even if `config.toml` is missing) the wizard
    // is an admin-only configuration surface, not an unauthenticated bootstrap.
    // A deployment with no usable Admin (for example only non-admin accounts)
    // is still recoverable with the provisioned setup token.
    if !ctx.auth_mgr.is_first_run() && !setup_required && !is_admin {
        return Redirect::to("/login").into_response();
    }

    let csrf = get_csrf_token(&ctx, &headers);
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

/// Credential mutations made by the wizard, kept so a later configuration
/// persistence failure can restore the previous account state.
#[derive(Default)]
struct WizardCredentialUndo {
    restore_password: Option<(String, String)>,
    remove_created_user: Option<String>,
}

impl WizardCredentialUndo {
    async fn rollback(self, ctx: &ServerContext) {
        if let Some((username, previous_hash)) = self.restore_password
            && let Err(e) = ctx
                .auth_mgr
                .restore_user_password_hash(&username, &previous_hash)
                .await
        {
            tracing::error!(
                user = %username,
                error = %e,
                "Failed to roll back the administrator password after a wizard persistence failure"
            );
        }
        if let Some(username) = self.remove_created_user
            && !ctx.auth_mgr.delete_user(&username).await
        {
            tracing::error!(
                user = %username,
                "Failed to remove the wizard-created administrator during rollback"
            );
        }
    }
}

pub async fn wizard_complete_handler(
    State(ctx): State<ServerContext>,
    Extension(hooks): Extension<ApplyHooks>,
    crate::auth::MaybeConnectInfo(peer_addr): crate::auth::MaybeConnectInfo,
    headers: HeaderMap,
    Form(form): Form<WizardCompleteForm>,
) -> Response {
    // Serialize the whole completion. Capturing the token requirement once
    // prevents a request that entered before a concurrent completion from
    // re-reading it as `false` and skipping token validation.
    let _setup_guard = ctx.auth_mgr.lock_setup_completion().await;
    let is_first_run = ctx.auth_mgr.is_first_run();
    let setup_token_required = ctx.auth_mgr.setup_token_required();
    // Bootstrap mode covers both the default-admin first run and deployments
    // with no usable Admin yet (for example only non-admin accounts), which
    // are recoverable only with the setup token.
    let bootstrapping = is_first_run || setup_token_required;
    let auth_user = get_session_user(&ctx, &headers);
    let is_admin = auth_user.as_ref().is_some_and(|u| u.role == Role::Admin);

    if !bootstrapping && !is_admin {
        return error_response(
            StatusCode::FORBIDDEN,
            "Setup wizard is disabled. Admin session required.",
        );
    }

    // Bootstrap completion requires the one-time setup token (authenticated
    // admins and in-memory test managers without a provisioned token are
    // exempt). The requirement was captured under the completion lock.
    if setup_token_required && !is_admin {
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

    // A wizard completion may only target an Admin account. Updating the
    // password of an existing non-Admin would let setup finish with a
    // non-privileged account (and could leave `adminadmin` active).
    if ctx.auth_mgr.has_user(admin_user) && ctx.auth_mgr.role_of(admin_user) != Some(Role::Admin) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "The selected account exists but is not an administrator.",
        );
    }
    if !bootstrapping && !ctx.auth_mgr.has_user(admin_user) {
        return error_response(StatusCode::BAD_REQUEST, "Username does not exist.");
    }

    // Read the base config only after taking the apply lock so a concurrent
    // writer cannot be overwritten by a stale wizard snapshot. The guard is
    // scoped to the apply/persist section.
    let mut credential_undo = WizardCredentialUndo::default();
    let (report, filtering) = {
        let _apply_guard = ctx.lock_config_apply().await;
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

        // Defense in depth: if another writer completed setup while this
        // request waited, do not mutate credentials with a stale bootstrap
        // snapshot. The completion lock should already have prevented this.
        if bootstrapping && ctx.auth_mgr.is_setup_complete() && !ctx.auth_mgr.setup_token_required()
        {
            return error_response(StatusCode::CONFLICT, "Setup has already been completed.");
        }

        // Change and persist the administrator credential before the
        // configuration file. Setup must never be persisted with the bootstrap
        // password still active.
        if bootstrapping && !ctx.auth_mgr.has_user(admin_user) {
            if let Err(e) = ctx
                .auth_mgr
                .create_user_persisted(admin_user, effective_password, Role::Admin)
                .await
            {
                tracing::error!(user = %admin_user, error = %e, "Wizard failed to create the administrator");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to persist the administrator password. Setup was not completed.",
                );
            }
            credential_undo.remove_created_user = Some(admin_user.to_string());
        } else {
            match ctx
                .auth_mgr
                .update_user_password_tracked(admin_user, effective_password)
                .await
            {
                Ok(previous_hash) => {
                    credential_undo.restore_password =
                        previous_hash.map(|hash| (admin_user.to_string(), hash));
                }
                Err(e) => {
                    tracing::error!(user = %admin_user, error = %e, "Wizard failed to update the administrator password");
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to persist the administrator password. Setup was not completed.",
                    );
                }
            }
        }

        // Apply first, persist second (WP-4.2): a configuration that cannot be
        // applied never reaches the file. The blocklist fetch is deferred to a
        // background refresh so the wizard request does not download lists
        // synchronously; the DNS listeners are only started after the refresh
        // finished.
        let report = match apply_and_persist_config_locked(
            &ctx,
            &new_cfg,
            FilterApply::Deferred,
            hooks.as_dyn(),
        )
        .await
        {
            Ok(report) => report,
            Err(e) => {
                tracing::error!("Failed to apply wizard configuration: {e:?}");
                credential_undo.rollback(&ctx).await;
                return error_response(
                    StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    &format!(
                        "Failed to apply configuration: {}. Setup was not completed.",
                        e.detail
                    ),
                );
            }
        };
        (report, new_cfg.filtering.clone())
    };
    if !report.restart_required.is_empty() {
        tracing::warn!(
            fields = ?report.restart_required,
            "Wizard configuration saved; these settings need a restart to take effect"
        );
    }

    if bootstrapping {
        // Never leave the bootstrap `admin` account active after setup
        // completes. Removing it only after the configuration persist means a
        // failure leaves setup pending instead of half-applied.
        if admin_user != "admin"
            && ctx.auth_mgr.is_default_admin_active()
            && let Err(err) = ctx.auth_mgr.delete_user_checked("admin").await
        {
            tracing::error!(
                error = %err,
                "Wizard could not remove the bootstrap admin account; setup remains pending"
            );
            credential_undo.rollback(&ctx).await;
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to remove the bootstrap administrator. Setup was not completed.",
            );
        }
        ctx.auth_mgr.mark_setup_complete();
    }

    // All credential and configuration writes succeeded: only now retire the
    // setup token and let the server leave setup mode.
    ctx.auth_mgr.consume_setup_token();
    ctx.set_setup_pending(false);

    // Queue the blocklist fetch/compile off the request path. When the DNS
    // listeners are still gated (first boot), start them only after the
    // filter engine has the new rules.
    let filter_handle = crate::config_apply::queue_filter_refresh(&ctx, filtering);
    match ctx.dns_starter.clone() {
        Some(starter) => {
            tokio::spawn(async move {
                let _ = filter_handle.await;
                if let Err(e) = starter.send(()) {
                    tracing::warn!("Failed to notify DNS listener starter after setup: {e}");
                }
            });
        }
        None => drop(filter_handle),
    }

    Redirect::to("/login").into_response()
}

// ---------------------------------------------------------------------------
// User Management & Account (D-17b)
// ---------------------------------------------------------------------------

fn percent_encode_path_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

fn format_token_timestamp(ts: Option<i64>) -> String {
    ts.and_then(chrono::DateTime::from_timestamp_millis)
        .map_or_else(
            || "—".to_string(),
            |dt| dt.format("%Y-%m-%d %H:%M UTC").to_string(),
        )
}

/// `expires_at` is persisted as Unix seconds (unlike millisecond audit
/// timestamps), so format it through the seconds constructor.
fn format_token_expiry_timestamp(ts: Option<i64>) -> String {
    ts.and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
        .map_or_else(
            || "—".to_string(),
            |dt| dt.format("%Y-%m-%d %H:%M UTC").to_string(),
        )
}

fn user_view_items(ctx: &ServerContext, current_username: &str) -> Vec<UserViewItem> {
    ctx.auth_mgr
        .list_users()
        .into_iter()
        .map(|user| {
            let encoded = percent_encode_path_segment(&user.username);
            UserViewItem {
                is_current: user.username == current_username,
                username: user.username,
                role: user.role,
                totp_enabled: user.totp_enabled,
                role_action: format!("/ui/users/{encoded}/role"),
                delete_action: format!("/ui/users/{encoded}/delete"),
            }
        })
        .collect()
}

fn token_view_items(ctx: &ServerContext, user: &AuthUser) -> Vec<TokenViewItem> {
    let is_admin = user.role == Role::Admin;
    ctx.auth_mgr
        .list_tokens()
        .iter()
        .filter(|token| {
            token.owner.as_deref() == Some(user.username.as_str())
                || (is_admin && token.owner.is_none())
        })
        .map(|token| TokenViewItem {
            id: token.id.clone(),
            name: token.name.clone(),
            scope: token.scope.to_string(),
            owner: token
                .owner
                .clone()
                .unwrap_or_else(|| "(legacy / ownerless)".to_string()),
            created_at: format_token_timestamp(Some(token.created_at)),
            last_used: format_token_timestamp(token.last_used),
            expires_at: format_token_expiry_timestamp(token.expires_at),
        })
        .collect()
}

fn render_users_page(
    ctx: &ServerContext,
    user: &AuthUser,
    csrf: &str,
    error_message: &str,
    status: StatusCode,
) -> Response {
    let users = user_view_items(ctx, &user.username);
    let mut response = HtmlTemplate(UsersTemplate {
        csrf_token: csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: user.role.as_str(),
        active_tab: "users",
        version: env!("CARGO_PKG_VERSION"),
        users,
        error_message,
    })
    .into_response();
    *response.status_mut() = status;
    response
}

fn render_account_page(
    ctx: &ServerContext,
    user: &AuthUser,
    csrf: &str,
    error_message: &str,
    notice_message: &str,
    new_token: Option<&crate::auth::token::CreateTokenResponse>,
    status: StatusCode,
) -> Response {
    let tokens = token_view_items(ctx, user);
    let totp_enabled = ctx.auth_mgr.totp_enabled(&user.username);
    let (token_value, token_name, token_scope) = match new_token {
        Some(token) => (
            Some(token.token.as_str()),
            token.name.as_str(),
            token.scope.to_string(),
        ),
        None => (None, "", String::new()),
    };
    let mut response = HtmlTemplate(AccountTemplate {
        csrf_token: csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: user.role.as_str(),
        active_tab: "account",
        version: env!("CARGO_PKG_VERSION"),
        tokens,
        totp_enabled,
        can_create_operator_token: user.role >= Role::Operator,
        can_create_admin_token: user.role >= Role::Admin,
        error_message,
        notice_message,
        new_token: token_value,
        new_token_name: token_name,
        new_token_scope: &token_scope,
    })
    .into_response();
    *response.status_mut() = status;
    response
}

fn session_or_redirect(
    ctx: &ServerContext,
    headers: &HeaderMap,
) -> Result<(AuthUser, String), Box<Response>> {
    match get_session_user(ctx, headers) {
        Some(user) => Ok((user, get_csrf_token(ctx, headers))),
        None => Err(Box::new(Redirect::to("/login").into_response())),
    }
}

fn admin_or_forbidden(
    ctx: &ServerContext,
    headers: &HeaderMap,
) -> Result<(AuthUser, String), Box<Response>> {
    let (user, csrf) = session_or_redirect(ctx, headers)?;
    if user.role < Role::Admin {
        return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
    }
    Ok((user, csrf))
}

fn users_problem_page(
    ctx: &ServerContext,
    user: &AuthUser,
    csrf: &str,
    problem: ProblemDetails,
) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::BAD_REQUEST);
    let detail = problem.detail;
    render_users_page(ctx, user, csrf, &detail, status)
}

fn account_problem_page(
    ctx: &ServerContext,
    user: &AuthUser,
    csrf: &str,
    problem: ProblemDetails,
) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::BAD_REQUEST);
    let detail = problem.detail;
    render_account_page(ctx, user, csrf, &detail, "", None, status)
}

pub async fn users_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let (user, csrf) = match admin_or_forbidden(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    render_users_page(&ctx, &user, &csrf, "", StatusCode::OK)
}

#[derive(Deserialize)]
pub struct CreateUserForm {
    pub username: String,
    pub password: String,
    pub role: String,
}

pub async fn users_create_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<CreateUserForm>,
) -> Response {
    let (user, csrf) = match admin_or_forbidden(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    let username = form.username.trim();
    let role = match validate_username(username)
        .and_then(|()| validate_password_policy(&form.password))
        .and_then(|()| {
            Role::from_str(form.role.trim())
                .map_err(|e| ProblemDetails::bad_request(format!("Invalid role: {e}")))
        }) {
        Ok(role) => role,
        Err(problem) => return users_problem_page(&ctx, &user, &csrf, problem),
    };

    if ctx.auth_mgr.has_user(username) {
        return users_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::conflict(format!("User '{username}' already exists")),
        );
    }

    if let Err(e) = ctx
        .auth_mgr
        .create_user_persisted(username, &form.password, role)
        .await
    {
        return users_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::internal_error(format!("Failed to persist the user store: {e}")),
        );
    }
    tracing::info!(
        actor = %user.username,
        target = %username,
        role = %role,
        "Administrator created a user account"
    );
    Redirect::to("/users").into_response()
}

#[derive(Deserialize)]
pub struct UpdateUserRoleForm {
    pub role: String,
}

pub async fn users_role_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Form(form): Form<UpdateUserRoleForm>,
) -> Response {
    let (user, csrf) = match admin_or_forbidden(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    let role = match Role::from_str(form.role.trim()) {
        Ok(role) => role,
        Err(e) => {
            return users_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::bad_request(format!("Invalid role: {e}")),
            );
        }
    };
    if let Err(err) = ctx.auth_mgr.set_user_role_checked(&username, role).await {
        let problem = user_mutation_problem(&username, "demote", err);
        return users_problem_page(&ctx, &user, &csrf, problem);
    }
    tracing::info!(
        actor = %user.username,
        target = %username,
        role = %role,
        "Administrator changed a user role"
    );
    Redirect::to("/users").into_response()
}

pub async fn users_delete_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Response {
    let (user, csrf) = match admin_or_forbidden(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    if let Err(err) = ctx.auth_mgr.delete_user_checked(&username).await {
        let problem = user_mutation_problem(&username, "delete", err);
        return users_problem_page(&ctx, &user, &csrf, problem);
    }
    tracing::info!(
        actor = %user.username,
        target = %username,
        "Administrator deleted a user account"
    );
    Redirect::to("/users").into_response()
}

pub async fn account_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let (user, csrf) = match session_or_redirect(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    render_account_page(&ctx, &user, &csrf, "", "", None, StatusCode::OK)
}

#[derive(Deserialize)]
pub struct AccountPasswordForm {
    pub current_password: String,
    pub new_password: String,
}

pub async fn account_password_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<AccountPasswordForm>,
) -> Response {
    let (user, csrf) = match session_or_redirect(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    if let Err(problem) = validate_password_policy(&form.new_password) {
        return account_problem_page(&ctx, &user, &csrf, problem);
    }
    if form.current_password.is_empty() {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::bad_request("Current password is required"),
        );
    }
    if !ctx
        .auth_mgr
        .verify_user_password(&user.username, form.current_password.trim())
        .await
    {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::bad_request("Current password is incorrect"),
        );
    }
    if let Err(err) = ctx
        .auth_mgr
        .update_user_password_checked(&user.username, &form.new_password)
        .await
    {
        let problem = match err {
            UserMutationError::NotFound => ProblemDetails::not_found("User account not found"),
            UserMutationError::LastAdmin => {
                ProblemDetails::bad_request("Cannot remove the last remaining admin account")
            }
            UserMutationError::Persistence(detail) => ProblemDetails::internal_error(format!(
                "Failed to persist the user store while changing the password: {detail}"
            )),
        };
        return account_problem_page(&ctx, &user, &csrf, problem);
    }
    tracing::info!(user = %user.username, "User changed their password from the web UI");
    // Password changes revoke every session for the account, including this
    // one, so send the browser back to the login page.
    Redirect::to("/login").into_response()
}

#[derive(Deserialize)]
pub struct CreateAccountTokenForm {
    pub name: String,
    pub scope: String,
}

pub async fn account_token_create_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<CreateAccountTokenForm>,
) -> Response {
    let (user, csrf) = match session_or_redirect(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    let name = form.name.trim();
    if name.is_empty() {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::bad_request("Token name is required"),
        );
    }
    if name.len() > 128 {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::bad_request("Token name must be at most 128 characters"),
        );
    }
    let scope = match Role::from_str(form.scope.trim()) {
        Ok(scope) => scope,
        Err(e) => {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::bad_request(format!("Invalid token scope: {e}")),
            );
        }
    };
    // Tokens are owned per account, and a token must never outrank its owner.
    if scope > user.role {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::forbidden("A token scope may not exceed your own role"),
        );
    }

    let (_meta, token) = match ctx
        .auth_mgr
        .create_token(name, scope, Some(&user.username))
        .await
    {
        Ok(token) => token,
        Err(e) => {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::bad_request(e.to_string()),
            );
        }
    };
    tracing::info!(user = %user.username, token = %token.id, "User created an API token from the web UI");
    // The plaintext token is shown only in this response and is never stored
    // or logged; reloading the page lists metadata only.
    render_account_page(&ctx, &user, &csrf, "", "", Some(&token), StatusCode::OK)
}

pub async fn account_token_delete_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (user, csrf) = match session_or_redirect(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    let Some(token) = ctx
        .auth_mgr
        .list_tokens()
        .into_iter()
        .find(|token| token.id == id)
    else {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::not_found(format!("Token '{id}' not found")),
        );
    };
    // Only the owner may revoke a token. Admins additionally manage legacy
    // ownerless tokens created before ownership was tracked. Another user's
    // token ID must look indistinguishable from a missing token.
    let is_own = token.owner.as_deref() == Some(user.username.as_str());
    let is_admin_legacy = user.role == Role::Admin && token.owner.is_none();
    if !is_own && !is_admin_legacy {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::not_found(format!("Token '{id}' not found")),
        );
    }

    if !ctx.auth_mgr.delete_token(&id).await {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::not_found(format!("Token '{id}' not found")),
        );
    }
    tracing::info!(user = %user.username, token = %id, "User revoked an API token from the web UI");
    Redirect::to("/account").into_response()
}

#[derive(Deserialize)]
pub struct DisableAccountTotpForm {
    pub password: String,
    #[serde(default)]
    pub code: Option<String>,
}

pub async fn account_totp_disable_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<DisableAccountTotpForm>,
) -> Response {
    let (user, csrf) = match session_or_redirect(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    // Mirror the REST disable handler: the current password is always
    // required, and when TOTP is enabled a valid TOTP or backup code must
    // accompany it.
    if !ctx
        .auth_mgr
        .verify_user_password(&user.username, &form.password)
        .await
    {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::bad_request("Re-authentication failed: invalid password"),
        );
    }
    if ctx.auth_mgr.totp_enabled(&user.username) {
        let Some(code) = form
            .code
            .as_deref()
            .map(str::trim)
            .filter(|code| !code.is_empty())
        else {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::bad_request("A TOTP or backup code is required to disable 2FA"),
            );
        };
        if !ctx
            .auth_mgr
            .verify_second_factor(&user.username, code)
            .await
        {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::bad_request(
                    "Re-authentication failed: invalid TOTP or backup code",
                ),
            );
        }
    }

    if let Err(err) = ctx.auth_mgr.try_disable_totp(&user.username).await {
        let problem = match err {
            TotpMutationError::NotFound => ProblemDetails::not_found("User account not found"),
            TotpMutationError::InvalidCode => {
                ProblemDetails::bad_request("Invalid TOTP verification code")
            }
            TotpMutationError::Persistence(detail) => ProblemDetails::internal_error(format!(
                "Failed to persist the user store while disabling TOTP: {detail}"
            )),
        };
        return account_problem_page(&ctx, &user, &csrf, problem);
    }
    tracing::info!(user = %user.username, "User disabled TOTP 2FA from the web UI");
    // Disabling 2FA revokes every session for the account by design.
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
            Arc::new(
                sito_clients::ServiceRegistry::try_bundled().expect("bundled services must load"),
            ),
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
        let temp_dir =
            std::env::temp_dir().join(format!("sito_ui_wiz_race_{}", rand::random::<u64>()));
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

        let resp =
            users_delete_handler(State(ctx.clone()), headers, Path("admin".to_string())).await;
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
            response_body(account_page(State(ctx.clone()), session_headers(&view_session)).await)
                .await;
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
}
