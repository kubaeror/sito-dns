//! Shared UI helpers: formatting, session/CSRF, and error responses.

#[allow(clippy::wildcard_imports)]
use super::*;

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

pub(crate) fn escape_html(s: &str) -> String {
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
pub(crate) fn append_cookie(response: &mut Response, value: &str) {
    if let Ok(cookie_val) = value.parse() {
        response.headers_mut().append(SET_COOKIE, cookie_val);
    }
}

pub(crate) fn error_response(status: StatusCode, message: &str) -> Response {
    (status, message.to_string()).into_response()
}

// ---------------------------------------------------------------------------

pub(crate) fn get_status_response(ctx: &ServerContext) -> StatusResponse {
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
    let acme_readiness = ctx.acme_readiness(&cfg);
    let acme = acme_readiness.enabled.then(|| AcmeStatus {
        enabled: acme_readiness.enabled,
        ready: acme_readiness.ready,
        http01_available: acme_readiness.http01_available,
        tls_alpn_available: acme_readiness.tls_alpn_available,
        reason: acme_readiness.reason.map(str::to_string),
        last_error: acme_readiness.last_error,
    });
    StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        role: cfg.server.role.clone(),
        listeners,
        acme,
    }
}

pub(crate) fn load_clients_config(ctx: &ServerContext) -> sito_clients::ClientsConfig {
    ctx.config
        .load()
        .clients
        .as_ref()
        .and_then(|v| v.clone().try_into().ok())
        .unwrap_or_default()
}

pub(crate) fn percent_encode_path_segment(value: &str) -> String {
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

pub(crate) fn format_token_timestamp(ts: Option<i64>) -> String {
    ts.and_then(chrono::DateTime::from_timestamp_millis)
        .map_or_else(
            || "—".to_string(),
            |dt| dt.format("%Y-%m-%d %H:%M UTC").to_string(),
        )
}

/// `expires_at` is persisted as Unix seconds (unlike millisecond audit
/// timestamps), so format it through the seconds constructor.
pub(crate) fn format_token_expiry_timestamp(ts: Option<i64>) -> String {
    ts.and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
        .map_or_else(
            || "—".to_string(),
            |dt| dt.format("%Y-%m-%d %H:%M UTC").to_string(),
        )
}

pub(crate) fn session_or_redirect(
    ctx: &ServerContext,
    headers: &HeaderMap,
) -> Result<(AuthUser, String), Box<Response>> {
    match get_session_user(ctx, headers) {
        Some(user) => Ok((user, get_csrf_token(ctx, headers))),
        None => Err(Box::new(Redirect::to("/login").into_response())),
    }
}

/// Session id backing the request cookie, validated against the manager.
pub(crate) fn current_session_id(ctx: &ServerContext, headers: &HeaderMap) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|value| value.to_str().ok())
        .and_then(extract_session_cookie)
        .filter(|session_id| ctx.auth_mgr.validate_session(session_id).is_some())
}

pub(crate) fn admin_or_forbidden(
    ctx: &ServerContext,
    headers: &HeaderMap,
) -> Result<(AuthUser, String), Box<Response>> {
    let (user, csrf) = session_or_redirect(ctx, headers)?;
    if user.role < Role::Admin {
        return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
    }
    Ok((user, csrf))
}
