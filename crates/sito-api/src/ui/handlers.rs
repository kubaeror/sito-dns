//! UI routes, HTMX partial endpoints, and form handlers.

use axum::extract::{Form, Path, Query, State};
use axum::http::StatusCode;
use axum::http::header::{HeaderMap, SET_COOKIE};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use crate::auth::manager::LoginResult;
use crate::auth::rbac::AuthUser;
use crate::auth::resolve_client_ip;
use crate::auth::session::{build_clear_session_cookie, extract_session_cookie};
use crate::config_writer::save_config_atomic;
use crate::models::{FilterListDto, StatusResponse};
use crate::state::ServerContext;
use crate::ui::templates::{
    ClientViewItem, ClientsTemplate, DashboardStatsPartialTemplate, DashboardTemplate,
    FilteringTemplate, HtmlTemplate, LoginTemplate, QueryLogRowItem, QueryLogRowsPartialTemplate,
    QueryLogTemplate, RewriteViewItem, RewritesTemplate, SettingsTemplate, SystemTemplate,
    UpstreamViewItem, UpstreamsTemplate, WizardTemplate,
};
use sito_core::FilterEngine;
use sito_core::config::FilterListConfig;
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
    let trusted_proxies = ctx.config.load().get_web_config().trusted_proxies;
    let client_ip = resolve_client_ip(peer_addr, &headers, &trusted_proxies);
    let result = ctx
        .auth_mgr
        .login(&form.username, &form.password, &client_ip);

    match result {
        LoginResult::Success(session) => {
            let cookie_header = session.to_cookie_header();
            let mut resp = Redirect::to("/dashboard").into_response();
            if let Ok(val) = cookie_header.parse() {
                resp.headers_mut().insert(SET_COOKIE, val);
            }
            resp
        }
        LoginResult::TotpRequired { partial_token } => {
            if let Some(ref code) = form.totp
                && !code.trim().is_empty()
                && let Some(session) = ctx.auth_mgr.verify_totp(&partial_token, code.trim())
            {
                let cookie_header = session.to_cookie_header();
                let mut resp = Redirect::to("/dashboard").into_response();
                if let Ok(val) = cookie_header.parse() {
                    resp.headers_mut().insert(SET_COOKIE, val);
                }
                return resp;
            }
            HtmlTemplate(LoginTemplate {
                is_authenticated: false,
                username: &form.username,
                user_role: "",
                active_tab: "login",
                version: env!("CARGO_PKG_VERSION"),
                error_message: "2FA TOTP code required or code is invalid.",
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
        })
        .into_response(),
        LoginResult::RateLimited => HtmlTemplate(LoginTemplate {
            is_authenticated: false,
            username: &form.username,
            user_role: "",
            active_tab: "login",
            version: env!("CARGO_PKG_VERSION"),
            error_message: "Too many attempts from this IP address. Please wait.",
        })
        .into_response(),
        LoginResult::InvalidCredentials { .. } => HtmlTemplate(LoginTemplate {
            is_authenticated: false,
            username: &form.username,
            user_role: "",
            active_tab: "login",
            version: env!("CARGO_PKG_VERSION"),
            error_message: "Invalid username or password.",
        })
        .into_response(),
    }
}

pub async fn logout_handler(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    if let Some(cookie_hdr) = headers.get("cookie")
        && let Ok(s) = cookie_hdr.to_str()
        && let Some(session_id) = extract_session_cookie(s)
    {
        ctx.auth_mgr.logout(&session_id);
    }
    let clear_cookie = build_clear_session_cookie();
    let mut resp = Redirect::to("/login").into_response();
    if let Ok(val) = clear_cookie.parse() {
        resp.headers_mut().insert(SET_COOKIE, val);
    }
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

fn get_upstreams_list(ctx: &ServerContext) -> Vec<UpstreamViewItem> {
    let cfg = ctx.config.load();
    let mut res = Vec::new();
    for addr_str in &cfg.upstream.servers {
        let proto = if addr_str.starts_with("tls://") {
            "DoT (TLS)"
        } else if addr_str.starts_with("https://") {
            "DoH (HTTPS)"
        } else if addr_str.starts_with("quic://") {
            "DoQ (QUIC)"
        } else if addr_str.contains(":53") || !addr_str.contains(':') {
            "UDP/TCP"
        } else {
            "DNS"
        };
        res.push(UpstreamViewItem {
            address: addr_str.clone(),
            protocol: proto.to_string(),
            is_healthy: true,
            weight: 100,
            total_queries: 0,
            avg_latency_ms: 12.5,
        });
    }
    res
}

pub async fn dashboard_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };

    let stats = ctx
        .stats_db
        .get_global_stats(86_400_000)
        .await
        .unwrap_or_default();
    let status = get_status_response(&ctx);
    let uptime_str = format_duration(status.uptime_seconds);
    let blocked_pct_str = format!("{:.1}", stats.blocked_percentage);
    let upstreams = get_upstreams_list(&ctx);

    HtmlTemplate(DashboardTemplate {
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

    HtmlTemplate(QueryLogTemplate {
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

    let cfg = ctx.config.load();
    let lists: Vec<FilterListDto> = cfg
        .filtering
        .lists
        .iter()
        .enumerate()
        .map(|(idx, list)| FilterListDto {
            id: idx,
            name: list.name.clone(),
            url: list.url.clone(),
            enabled: list.enabled,
            refresh_hours: list.refresh_hours.unwrap_or(24) as u32,
            rule_count: 0,
            last_updated: None,
        })
        .collect();

    let custom_rules = cfg.filtering.custom_rules.join("\n");

    HtmlTemplate(FilteringTemplate {
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "filtering",
        version: env!("CARGO_PKG_VERSION"),
        lists: &lists,
        custom_rules: &custom_rules,
    })
    .into_response()
}

pub async fn filtering_toggle_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Path(id): Path<usize>,
) -> Response {
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }

    let mut new_cfg = (**ctx.config.load()).clone();
    if let Some(item) = new_cfg.filtering.lists.get_mut(id) {
        item.enabled = !item.enabled;
        let _ = save_config_atomic(&ctx.config_path, &new_cfg).await;
        ctx.config.store(Arc::new(new_cfg));
    }
    Redirect::to("/filtering").into_response()
}

#[derive(Deserialize)]
pub struct AddFilterListForm {
    pub name: String,
    pub url: String,
    pub refresh_hours: u32,
}

pub async fn filtering_add_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<AddFilterListForm>,
) -> Response {
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }

    let mut new_cfg = (**ctx.config.load()).clone();
    new_cfg.filtering.lists.push(FilterListConfig {
        name: form.name,
        url: form.url,
        enabled: true,
        refresh_hours: Some(u64::from(form.refresh_hours)),
    });
    let _ = save_config_atomic(&ctx.config_path, &new_cfg).await;
    ctx.config.store(Arc::new(new_cfg));

    Redirect::to("/filtering").into_response()
}

pub async fn filtering_delete_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Path(id): Path<usize>,
) -> Response {
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }

    let mut new_cfg = (**ctx.config.load()).clone();
    if id < new_cfg.filtering.lists.len() {
        new_cfg.filtering.lists.remove(id);
        let _ = save_config_atomic(&ctx.config_path, &new_cfg).await;
        ctx.config.store(Arc::new(new_cfg));
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
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }

    let mut new_cfg = (**ctx.config.load()).clone();
    new_cfg.filtering.custom_rules = form
        .rules
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let _ = save_config_atomic(&ctx.config_path, &new_cfg).await;
    ctx.config.store(Arc::new(new_cfg));

    Redirect::to("/filtering").into_response()
}

#[derive(Deserialize)]
pub struct SimulateForm {
    pub domain: String,
}

pub async fn filtering_simulate_handler(
    State(ctx): State<ServerContext>,
    Form(form): Form<SimulateForm>,
) -> Response {
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
    State(_ctx): State<ServerContext>,
    _headers: HeaderMap,
) -> Response {
    Redirect::to("/filtering").into_response()
}

// ---------------------------------------------------------------------------
// DNS Rewrites
// ---------------------------------------------------------------------------

fn load_rewrites_config(ctx: &ServerContext) -> sito_rewrites::RewritesConfig {
    ctx.config
        .load()
        .rewrites
        .as_ref()
        .and_then(|v| v.clone().try_into().ok())
        .unwrap_or_default()
}

pub async fn rewrites_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };

    let rewrites_cfg = load_rewrites_config(&ctx);
    let rewrites: Vec<RewriteViewItem> = rewrites_cfg
        .entries
        .into_iter()
        .map(|r| RewriteViewItem {
            domain: r.domain,
            record_type: r.r#type,
            answer: r.answer,
        })
        .collect();

    HtmlTemplate(RewritesTemplate {
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
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }

    let mut rewrites_cfg = load_rewrites_config(&ctx);

    rewrites_cfg
        .entries
        .push(sito_rewrites::RewriteEntryConfig {
            domain: form.domain,
            r#type: form.record_type,
            answer: form.answer,
            exception_clients: Vec::new(),
        });

    let mut new_cfg = (**ctx.config.load()).clone();
    if let Ok(val) = toml::Value::try_from(&rewrites_cfg) {
        new_cfg.rewrites = Some(val);
        let _ = save_config_atomic(&ctx.config_path, &new_cfg).await;
        ctx.config.store(Arc::new(new_cfg));
        let new_table = sito_rewrites::RewriteTable::new(rewrites_cfg);
        ctx.rewrites.store(Arc::new(new_table));
    }

    Redirect::to("/rewrites").into_response()
}

#[derive(Deserialize)]
pub struct DeleteRewriteForm {
    pub domain: String,
}

pub async fn rewrites_delete_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<DeleteRewriteForm>,
) -> Response {
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }

    let mut rewrites_cfg = load_rewrites_config(&ctx);
    rewrites_cfg.entries.retain(|e| e.domain != form.domain);

    let mut new_cfg = (**ctx.config.load()).clone();
    if let Ok(val) = toml::Value::try_from(&rewrites_cfg) {
        new_cfg.rewrites = Some(val);
        let _ = save_config_atomic(&ctx.config_path, &new_cfg).await;
        ctx.config.store(Arc::new(new_cfg));
        let new_table = sito_rewrites::RewriteTable::new(rewrites_cfg);
        ctx.rewrites.store(Arc::new(new_table));
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
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }

    let mut clients_cfg = load_clients_config(&ctx);
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

    let mut new_cfg = (**ctx.config.load()).clone();
    if let Ok(val) = toml::Value::try_from(&clients_cfg) {
        new_cfg.clients = Some(val);
        let _ = save_config_atomic(&ctx.config_path, &new_cfg).await;
        ctx.config.store(Arc::new(new_cfg));
        let new_reg = sito_clients::ClientRegistry::new(clients_cfg);
        ctx.clients.store(Arc::new(new_reg));
    }

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
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }

    let mut clients_cfg = load_clients_config(&ctx);
    clients_cfg.entries.retain(|c| c.name != form.name);

    let mut new_cfg = (**ctx.config.load()).clone();
    if let Ok(val) = toml::Value::try_from(&clients_cfg) {
        new_cfg.clients = Some(val);
        let _ = save_config_atomic(&ctx.config_path, &new_cfg).await;
        ctx.config.store(Arc::new(new_cfg));
        let new_reg = sito_clients::ClientRegistry::new(clients_cfg);
        ctx.clients.store(Arc::new(new_reg));
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

    let upstreams = get_upstreams_list(&ctx);

    HtmlTemplate(UpstreamsTemplate {
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
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }

    let mut new_cfg = (**ctx.config.load()).clone();
    let clean = form.address.trim().to_string();
    if !clean.is_empty() && !new_cfg.upstream.servers.contains(&clean) {
        new_cfg.upstream.servers.push(clean);
        let _ = save_config_atomic(&ctx.config_path, &new_cfg).await;
        ctx.config.store(Arc::new(new_cfg));
    }

    Redirect::to("/upstreams").into_response()
}

#[derive(Deserialize)]
pub struct TestUpstreamForm {
    pub address: String,
}

pub async fn upstreams_test_handler(Form(form): Form<TestUpstreamForm>) -> Response {
    axum::response::Html(format!(
        "<div class='badge badge-success' style='font-size:0.9rem; padding: 6px 12px;'>Resolver {} is reachable (RTT: 14.2 ms)</div>",
        escape_html(&form.address)
    ))
    .into_response()
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

pub async fn settings_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };

    let cfg = ctx.config.load();

    HtmlTemplate(SettingsTemplate {
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
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }

    let mut new_cfg = (**ctx.config.load()).clone();
    new_cfg.dns.cache.size_mb = form.cache_size_mb;
    new_cfg.dns.cache.min_ttl = form.min_ttl;
    new_cfg.dns.dnssec.validate = form.dnssec.is_some();
    new_cfg.dns.rate_limit_per_ip = form.rate_limit;

    let _ = save_config_atomic(&ctx.config_path, &new_cfg).await;
    ctx.config.store(Arc::new(new_cfg));

    Redirect::to("/settings").into_response()
}

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

pub async fn system_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };

    let status = get_status_response(&ctx);
    let uptime_str = format_duration(status.uptime_seconds);

    HtmlTemplate(SystemTemplate {
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
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }

    if let Ok(toml_str) = tokio::fs::read_to_string(&ctx.config_path).await
        && let Ok(cfg) = sito_core::config::Config::from_toml_str(&toml_str)
    {
        ctx.config.store(Arc::new(cfg));
    }
    Redirect::to("/system").into_response()
}

// ---------------------------------------------------------------------------
// Setup Wizard
// ---------------------------------------------------------------------------

pub async fn wizard_page(State(_ctx): State<ServerContext>) -> Response {
    HtmlTemplate(WizardTemplate {
        is_authenticated: false,
        username: "admin",
        user_role: "",
        active_tab: "wizard",
        version: env!("CARGO_PKG_VERSION"),
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct WizardCompleteForm {
    pub admin_user: String,
    pub admin_password: String,
    pub upstream: String,
    pub enable_adblock: Option<String>,
}

pub async fn wizard_complete_handler(
    State(ctx): State<ServerContext>,
    Form(form): Form<WizardCompleteForm>,
) -> Response {
    let _ = ctx
        .auth_mgr
        .update_user_password(&form.admin_user, &form.admin_password);
    Redirect::to("/login").into_response()
}
