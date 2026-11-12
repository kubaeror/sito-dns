//! Settings page and save handler.

#[allow(clippy::wildcard_imports)]
use super::*;

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
