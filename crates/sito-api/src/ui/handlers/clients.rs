//! Clients page and client/group management.

#[allow(clippy::wildcard_imports)]
use super::*;

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
