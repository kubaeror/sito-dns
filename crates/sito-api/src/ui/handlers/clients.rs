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
    // Blocked-service picker data. A corrupt embedded catalog or registry is
    // logged and degrades the service section instead of failing the page.
    let service_views = clients_service_views(&clients_cfg);
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
        group_services: service_views.groups,
        catalog_service_groups: service_views.catalog_groups,
        catalog_service_count: service_views.catalog_service_count,
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

/// Maximum number of blocked services an operator may select for one group.
pub(crate) const MAX_GROUP_SERVICES_SELECTION: usize = 256;

/// Page data for the blocked-services picker.
#[derive(Debug, Clone)]
pub(crate) struct ClientsServiceViews {
    pub groups: Vec<ClientGroupServicesViewItem>,
    pub catalog_groups: Vec<CatalogServiceGroupViewItem>,
    pub catalog_service_count: usize,
}

/// Builds blocked-service picker data from the embedded catalog.
pub(crate) fn clients_service_views(clients: &sito_clients::ClientsConfig) -> ClientsServiceViews {
    let registry = match sito_clients::ServiceRegistry::try_bundled() {
        Ok(registry) => Some(registry),
        Err(e) => {
            tracing::error!(
                error = %e,
                "Bundled service registry is invalid; catalog services are unavailable"
            );
            None
        }
    };
    clients_service_views_from(
        clients,
        sito_clients::Catalog::embedded(),
        registry.as_ref(),
    )
}

/// Testable core of [`clients_service_views`].
///
/// Configured groups are always rendered. A corrupt embedded catalog is logged
/// and degrades to an empty service picker instead of failing the whole page.
/// `registry` decides availability: the runtime registry includes every
/// catalog service with at least one usable blocking rule, while a catalog
/// service with zero usable rules is marked unavailable instead of being
/// offered as a silent no-op.
pub(crate) fn clients_service_views_from(
    clients: &sito_clients::ClientsConfig,
    catalog: Result<sito_clients::Catalog, sito_clients::CatalogError>,
    registry: Option<&sito_clients::ServiceRegistry>,
) -> ClientsServiceViews {
    let mut group_names: Vec<String> = clients.groups.keys().cloned().collect();
    // `default` is implied even when it has no explicit configuration.
    if !group_names.iter().any(|name| name == "default") {
        group_names.push("default".to_string());
    }
    group_names.sort_by(|a, b| {
        let a_default = a == "default";
        let b_default = b == "default";
        b_default.cmp(&a_default).then_with(|| a.cmp(b))
    });

    let catalog_lower_ids: Option<std::collections::HashSet<String>> =
        catalog.as_ref().ok().map(|catalog| {
            catalog
                .services()
                .map(|service| service.id.to_ascii_lowercase())
                .collect()
        });

    let groups = group_names
        .into_iter()
        .map(|name| {
            let mut seen = std::collections::HashSet::new();
            let blocked_services: Vec<BlockedServiceViewItem> = clients
                .groups
                .get(&name)
                .map(|group| {
                    group
                        .blocked_services
                        .iter()
                        .filter(|blocked| !blocked.service.trim().is_empty())
                        .filter(|blocked| seen.insert(blocked.service.to_ascii_lowercase()))
                        .map(|blocked| BlockedServiceViewItem {
                            service: blocked.service.clone(),
                            schedule: blocked
                                .schedule
                                .as_ref()
                                .map(|schedule| schedule.as_str().to_string()),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let unlisted_services = blocked_services
                .iter()
                .filter(|blocked| {
                    catalog_lower_ids
                        .as_ref()
                        .is_none_or(|ids| !ids.contains(&blocked.service.to_ascii_lowercase()))
                })
                .cloned()
                .collect();
            ClientGroupServicesViewItem {
                is_default: name == "default",
                name,
                blocked_services,
                unlisted_services,
            }
        })
        .collect();

    let (catalog_groups, catalog_service_count) = match catalog {
        Ok(catalog) => {
            let catalog_service_count = catalog.services.len();
            let mut by_group: std::collections::BTreeMap<String, Vec<CatalogServiceViewItem>> =
                std::collections::BTreeMap::new();
            for group in catalog.service_groups() {
                by_group.entry(group.to_string()).or_default();
            }
            for service in catalog.services() {
                by_group
                    .entry(service.group.clone())
                    .or_default()
                    .push(CatalogServiceViewItem {
                        id: service.id.clone(),
                        name: service.name.clone(),
                        group: service.group.clone(),
                        rule_count: service.rules.len(),
                        available: registry
                            .is_some_and(|registry| registry.contains_service(&service.id)),
                    });
            }
            let mut groups = Vec::with_capacity(by_group.len());
            for (id, mut services) in by_group {
                services.sort_by(|a, b| {
                    a.name
                        .to_lowercase()
                        .cmp(&b.name.to_lowercase())
                        .then_with(|| a.id.cmp(&b.id))
                });
                groups.push(CatalogServiceGroupViewItem { id, services });
            }
            (groups, catalog_service_count)
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "Embedded service catalog is invalid; rendering an empty service section"
            );
            (Vec::new(), 0)
        }
    };

    ClientsServiceViews {
        groups,
        catalog_groups,
        catalog_service_count,
    }
}

/// A parsed `POST /ui/clients/group-services` submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupServicesSubmission {
    pub group: String,
    pub selected: Vec<String>,
}

/// Why a blocked-services selection could not be parsed or applied.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum GroupServicesError {
    #[error("group is required")]
    MissingGroup,
    #[error("group must be submitted once")]
    ConflictingGroup,
    #[error("duplicate selected service id '{0}'")]
    DuplicateService(String),
    #[error("select at most {0} services at a time")]
    TooMany(usize),
    #[error("unknown catalog service id '{0}'")]
    UnknownService(String),
    #[error("catalog service '{0}' has no usable blocking rules and cannot be selected")]
    UnavailableService(String),
}

/// Reads `group` and the repeated `selected` fields from a form body.
///
/// Only catalog ids are collected; a client-supplied name or rule is never
/// accepted. Other fields (including `csrf_token`) are ignored: CSRF is
/// enforced by the UI middleware before the handler runs.
pub(crate) fn parse_group_services_form(
    pairs: &[(String, String)],
) -> Result<GroupServicesSubmission, GroupServicesError> {
    let mut group: Option<String> = None;
    let mut selected = Vec::new();
    for (key, value) in pairs {
        match key.as_str() {
            "group" => {
                let value = value.trim();
                if value.is_empty() {
                    return Err(GroupServicesError::MissingGroup);
                }
                match &group {
                    Some(existing) if existing != value => {
                        return Err(GroupServicesError::ConflictingGroup);
                    }
                    Some(_) => {}
                    None => group = Some(value.to_string()),
                }
            }
            "selected" => {
                let value = value.trim();
                if !value.is_empty() {
                    selected.push(value.to_string());
                }
            }
            _ => {}
        }
    }
    Ok(GroupServicesSubmission {
        group: group.ok_or(GroupServicesError::MissingGroup)?,
        selected,
    })
}

/// Merges a validated selection with the existing blocked-service entries.
///
/// Retained services keep their configured order and existing `schedule`;
/// removed services disappear; new services are appended in submitted order
/// with `schedule: None`. Duplicate ids are rejected rather than silently
/// deduplicated.
///
/// Catalog ids are canonicalized and must have at least one usable registry
/// rule. An id that is not in the embedded catalog is accepted only when this
/// group already configures it (for example bundled-only services such as
/// `ads` or a legacy custom id); retaining it keeps its original spelling and
/// schedule, and omitting it removes it. This prevents editing a group from
/// silently dropping configured services the catalog cannot represent.
/// Ids are matched case-insensitively because the service registry is
/// case-insensitive.
pub(crate) fn group_blocked_services(
    existing: &[sito_clients::BlockedServiceConfig],
    selected: &[String],
    catalog: &sito_clients::Catalog,
    registry: &sito_clients::ServiceRegistry,
) -> Result<Vec<sito_clients::BlockedServiceConfig>, GroupServicesError> {
    let by_lower: std::collections::HashMap<String, &str> = catalog
        .services()
        .map(|service| (service.id.to_ascii_lowercase(), service.id.as_str()))
        .collect();
    let existing_by_lower: std::collections::HashMap<String, &sito_clients::BlockedServiceConfig> =
        existing
            .iter()
            .map(|blocked| (blocked.service.to_ascii_lowercase(), blocked))
            .collect();

    let mut trimmed: Vec<&str> = Vec::with_capacity(selected.len());
    let mut seen_selected = std::collections::HashSet::new();
    for id in selected {
        let id = id.trim();
        if id.is_empty() {
            continue;
        }
        let lower = id.to_ascii_lowercase();
        if !seen_selected.insert(lower) {
            return Err(GroupServicesError::DuplicateService(id.to_string()));
        }
        trimmed.push(id);
    }

    if trimmed.len() > MAX_GROUP_SERVICES_SELECTION {
        return Err(GroupServicesError::TooMany(MAX_GROUP_SERVICES_SELECTION));
    }

    let mut selected_ids: Vec<&str> = Vec::with_capacity(trimmed.len());
    for id in trimmed {
        let lower = id.to_ascii_lowercase();
        if let Some(canonical) = by_lower.get(&lower).copied() {
            selected_ids.push(canonical);
        } else if let Some(configured) = existing_by_lower.get(&lower) {
            // Bundled-only or legacy configured service: retain its configured
            // spelling so a catalog edit cannot silently drop it.
            selected_ids.push(configured.service.as_str());
        } else {
            return Err(GroupServicesError::UnknownService(id.to_string()));
        }
    }

    for id in &selected_ids {
        if catalog.service_by_id(id).is_some() && !registry.contains_service(id) {
            return Err(GroupServicesError::UnavailableService((*id).to_string()));
        }
    }

    let selected_set: std::collections::HashSet<String> = selected_ids
        .iter()
        .map(|id| id.to_ascii_lowercase())
        .collect();
    let mut emitted = std::collections::HashSet::new();
    let mut merged = Vec::with_capacity(selected_ids.len());
    for blocked in existing {
        if selected_set.contains(&blocked.service.to_ascii_lowercase())
            && emitted.insert(blocked.service.to_ascii_lowercase())
        {
            merged.push(blocked.clone());
        }
    }
    for id in selected_ids {
        if emitted.insert(id.to_string()) {
            merged.push(sito_clients::BlockedServiceConfig {
                service: id.to_string(),
                schedule: None,
            });
        }
    }
    Ok(merged)
}

/// Operator-only blocked-services selection for one client group.
///
/// The form supplies `group` and repeated `selected` service ids. The embedded
/// catalog decides which new ids exist; configured ids missing from the
/// catalog (bundled-only or legacy entries) can be retained or removed
/// explicitly. The bundled registry decides what is enforceable. Retained
/// entries keep their schedules. Everything is applied in one configuration
/// clone and one synchronous apply, so an invalid selection or a failed apply
/// persists nothing.
pub async fn clients_group_services_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let submission = match parse_group_services_form(&pairs) {
        Ok(submission) => submission,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    };

    let catalog = match sito_clients::Catalog::embedded() {
        Ok(catalog) => catalog,
        Err(e) => {
            tracing::error!(
                error = %e,
                "Embedded service catalog is invalid; group service selection is unavailable"
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Embedded service catalog is unavailable",
            );
        }
    };
    let registry = match sito_clients::ServiceRegistry::try_bundled() {
        Ok(registry) => registry,
        Err(e) => {
            tracing::error!(
                error = %e,
                "Bundled service registry is invalid; group service selection is unavailable"
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Bundled service registry is unavailable",
            );
        }
    };

    let _apply_guard = ctx.lock_config_apply().await;
    let mut clients_cfg = load_clients_config(&ctx);
    if submission.group != "default" && !clients_cfg.groups.contains_key(&submission.group) {
        return error_response(StatusCode::BAD_REQUEST, "Unknown client group");
    }

    let existing = clients_cfg
        .groups
        .get(&submission.group)
        .map(|group| group.blocked_services.clone())
        .unwrap_or_default();
    let blocked_services =
        match group_blocked_services(&existing, &submission.selected, &catalog, &registry) {
            Ok(blocked_services) => blocked_services,
            Err(e) => return error_response(StatusCode::BAD_REQUEST, &e.to_string()),
        };

    // Replace only this group's blocked services (creating the implied
    // `default` group when needed); every other group field is preserved.
    clients_cfg
        .groups
        .entry(submission.group)
        .or_default()
        .blocked_services = blocked_services;

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
    if let Err(e) = apply_and_persist_config_locked(&ctx, &new_cfg, FilterApply::Sync, None).await {
        tracing::error!("Failed to apply group services: {e:?}");
        return error_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &format!("Failed to persist group services: {}", e.detail),
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
