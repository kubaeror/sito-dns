//! Upstream page, add, and connectivity test handlers.

#[allow(clippy::wildcard_imports)]
use super::*;

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

pub(crate) fn clean_address(address: &str) -> &str {
    address.trim()
}

pub(crate) async fn run_upstream_probe(clean: &str, probe_domain: &str) -> Response {
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
