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

    let (cache_size_mb, min_ttl, dnssec_enabled, rate_limit, configured_role) = {
        let cfg = ctx.config.load();
        (
            cfg.dns.cache.size_mb,
            cfg.dns.cache.min_ttl,
            cfg.dns.dnssec.validate,
            cfg.dns.rate_limit_per_ip,
            cfg.server.role.clone(),
        )
    };
    // On a replica slave every field on this page is shared, master-managed
    // policy. Render the form read-only instead of letting the POST bounce off
    // the slave middleware with a JSON 409.
    let ha_replica = configured_role == "slave" && !ctx.ha_write_gate.is_effective_master();
    let ha_master_url = if ha_replica {
        ctx.resolve_master_url()
    } else {
        String::new()
    };

    HtmlTemplate(SettingsTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "settings",
        version: env!("CARGO_PKG_VERSION"),
        cache_size_mb,
        min_ttl,
        dnssec_enabled,
        rate_limit,
        ha_replica,
        ha_master_url,
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
    // write rolls the in-memory apply back. `[filtering]` is untouched, so
    // the already-loaded rules are reused instead of refetching blocklists.
    let filter_apply = filter_apply_for(&ctx.config.load(), &new_cfg);
    if let Err(e) =
        apply_and_persist_config_locked(&ctx, &new_cfg, filter_apply, hooks.as_dyn()).await
    {
        tracing::error!("Failed to apply settings: {e:?}");
        return StatusCode::from_u16(e.status)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            .into_response();
    }

    Redirect::to("/settings").into_response()
}
