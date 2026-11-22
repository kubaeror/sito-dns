//! Filtering page, list management, custom rules, and simulation.

#[allow(clippy::wildcard_imports)]
use super::*;

// ---------------------------------------------------------------------------
// Filtering & Blocklists
// ---------------------------------------------------------------------------

/// Builds the bundled-list rows shown on the filtering page.
///
/// `manifest` may be an error (corrupt embedded JSON): the error is logged and
/// the function degrades to the runtime-refresh rows only, so rendering the
/// page never panics.
pub(crate) fn bundled_list_views(
    manifest: Result<sito_clients::BundledManifest, serde_json::Error>,
    statuses: &[sito_clients::RuntimeListStatus],
    can_view_urls: bool,
) -> Vec<crate::ui::templates::BundledListView> {
    let redact_source = |source: String| -> String {
        if can_view_urls {
            source
        } else {
            redact_subscription_url(&source)
        }
    };
    let redact_error = |error: String| -> String {
        if can_view_urls {
            error
        } else {
            redact_text_urls(&error)
        }
    };
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
                source: redact_source(
                    status
                        .and_then(|status| status.source_url.clone())
                        .unwrap_or_else(|| list.source.clone()),
                ),
                license: list.license.clone(),
                entries: status.map_or(list.entries, |status| status.entries),
                state: if status.is_some_and(|status| !status.bundled) {
                    "runtime refresh".to_string()
                } else {
                    "built-in (minimal)".to_string()
                },
                last_refresh: format_refresh(status.and_then(|status| status.last_refresh_unix)),
                last_attempt: format_refresh(status.and_then(|status| status.last_attempt_unix)),
                last_error: status
                    .and_then(|status| status.last_error.clone())
                    .map(redact_error),
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
            source: redact_source(status.source_url.clone().unwrap_or_default()),
            license: "—".to_string(),
            entries: status.entries,
            state: if status.bundled {
                "built-in".to_string()
            } else {
                "runtime refresh".to_string()
            },
            last_refresh: format_refresh(status.last_refresh_unix),
            last_attempt: format_refresh(status.last_attempt_unix),
            last_error: status.last_error.clone().map(redact_error),
        });
    }
    bundled_lists.sort_by(|a, b| a.id.cmp(&b.id));
    bundled_lists
}

/// Reduces a subscription URL to its scheme and host for roles that may see
/// that a source exists but not its full (often tokenised) URL.
pub(crate) fn redact_subscription_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "***".to_string();
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if scheme.is_empty() || host.is_empty() {
        "***".to_string()
    } else {
        format!("{scheme}://{host}")
    }
}

/// Redacts scheme URLs embedded in a free-form error string. Runtime-list
/// errors can include the failing source; Viewers must not receive its path or
/// credentials, so each URL is reduced to scheme+host.
pub(crate) fn redact_text_urls(text: &str) -> String {
    text.split_whitespace()
        .map(|token| {
            let Some(start) = ["http://", "https://", "file://"]
                .iter()
                .filter_map(|scheme| token.find(scheme))
                .min()
            else {
                return token.to_string();
            };
            let (prefix, rest) = token.split_at(start);
            let suffix_start = rest
                .find([',', ';', ')', ']', '}', '"', '\''])
                .unwrap_or(rest.len());
            let (url, suffix) = rest.split_at(suffix_start);
            format!("{prefix}{}{suffix}", redact_subscription_url(url))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Maximum number of catalog filters an operator may add in one request.
pub(crate) const MAX_CATALOG_SELECTION: usize = 20;

/// Returns the effective filter-list name for a catalog entry.
///
/// `FilterListConfig::name` doubles as the list id in UI routes, so it must
/// pass [`crate::handlers::filtering::valid_filter_list_name`]. Most catalog
/// names already qualify; a few contain `/` (for example
/// `HaGeZi's Windows/Office Tracker Blocklist`), which would break routing, so
/// those characters become `-` and control characters are removed. Valid
/// names are returned unchanged.
pub(crate) fn catalog_list_name(filter: &sito_clients::CatalogFilter) -> String {
    let sanitized: String = filter
        .name
        .chars()
        .map(|c| {
            if matches!(c, '/' | '?' | '#' | '%') {
                '-'
            } else {
                c
            }
        })
        .filter(|c| !c.is_control())
        .collect();
    let sanitized = sanitized.trim();
    if sanitized.is_empty() {
        filter.id.clone()
    } else {
        sanitized.to_string()
    }
}

/// The URL stored when a catalog filter is selected: `download_url`, with the
/// upstream `subscription_url` as a fallback.
pub(crate) fn catalog_filter_url(filter: &sito_clients::CatalogFilter) -> &str {
    if filter.download_url.trim().is_empty() {
        &filter.subscription_url
    } else {
        &filter.download_url
    }
}

fn catalog_list_is_present(
    filter: &sito_clients::CatalogFilter,
    names: &std::collections::HashSet<String>,
    urls: &std::collections::HashSet<String>,
) -> bool {
    names.contains(&catalog_list_name(filter).to_lowercase())
        || urls.contains(&catalog_filter_url(filter).to_lowercase())
        || urls.contains(&filter.subscription_url.to_lowercase())
}

/// Builds the catalog picker data for the filtering page.
///
/// A corrupt embedded catalog is logged and degrades to an empty catalog
/// section instead of failing the whole page. Categories and filters are
/// sorted explicitly so the rendered order does not depend on the JSON order.
pub(crate) fn catalog_page_views(
    catalog: Result<sito_clients::Catalog, sito_clients::CatalogError>,
    lists: &[FilterListConfig],
) -> (
    Vec<crate::ui::templates::CatalogCategoryView>,
    Vec<crate::ui::templates::CatalogFilterView>,
) {
    let catalog = match catalog {
        Ok(catalog) => catalog,
        Err(e) => {
            tracing::error!(
                error = %e,
                "Embedded filter catalog is invalid; rendering an empty catalog section"
            );
            return (Vec::new(), Vec::new());
        }
    };

    let existing_names: std::collections::HashSet<String> =
        lists.iter().map(|list| list.name.to_lowercase()).collect();
    let existing_urls: std::collections::HashSet<String> =
        lists.iter().map(|list| list.url.to_lowercase()).collect();

    let mut categories: Vec<&sito_clients::CatalogCategory> = catalog.categories().collect();
    categories.sort_by(|a, b| {
        a.display_number
            .cmp(&b.display_number)
            .then_with(|| a.id.cmp(&b.id))
    });
    let category_views: Vec<crate::ui::templates::CatalogCategoryView> = categories
        .iter()
        .map(|category| crate::ui::templates::CatalogCategoryView {
            id: category.id.clone(),
            name: category.name.clone(),
            display_number: category.display_number,
            filter_count: catalog.filter_count_in_category(&category.id),
        })
        .collect();

    let mut filter_views = Vec::with_capacity(catalog.filters.len());
    for category in &categories {
        let mut filters: Vec<&sito_clients::CatalogFilter> =
            catalog.filters_in_category(&category.id).collect();
        filters.sort_by(|a, b| {
            a.display_number
                .cmp(&b.display_number)
                .then_with(|| a.id.cmp(&b.id))
        });
        for filter in filters {
            let stored_name = catalog_list_name(filter);
            let name_sanitized = stored_name != filter.name;
            filter_views.push(crate::ui::templates::CatalogFilterView {
                id: filter.id.clone(),
                name: filter.name.clone(),
                category: filter.category.clone(),
                category_name: category.name.clone(),
                description: filter.description.clone(),
                homepage: filter.homepage.clone(),
                source_url: catalog_filter_url(filter).to_string(),
                version: filter.version.clone(),
                stored_name,
                name_sanitized,
                deprecated: filter.deprecated,
                already_added: catalog_list_is_present(filter, &existing_names, &existing_urls),
            });
        }
    }

    (category_views, filter_views)
}

/// Collects the repeated `selected` form field into catalog filter ids.
///
/// The form only ever contributes catalog ids; names and URLs always come from
/// the embedded catalog. Blank values are ignored and the order is preserved.
pub(crate) fn selected_catalog_ids(pairs: &[(String, String)]) -> Vec<String> {
    pairs
        .iter()
        .filter(|(key, _)| key == "selected")
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

/// Why a catalog selection could not be turned into filter lists.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CatalogSelectionError {
    #[error("select at most {MAX_CATALOG_SELECTION} catalog lists at a time")]
    TooMany,
    #[error("unknown catalog filter id '{0}'")]
    Unknown(String),
    #[error("catalog filter '{0}' is deprecated and cannot be added")]
    Deprecated(String),
    #[error("catalog filter '{0}' has a name that cannot be stored as a filter list")]
    InvalidName(String),
}

/// Resolves selected catalog ids into the filter lists to append.
///
/// Every id is validated against the embedded catalog before anything is
/// mutated, so callers can treat a returned error as "nothing was added".
/// Already-configured lists (case-insensitive name or URL, including the
/// catalog subscription URL) are skipped; the selection itself is deduped and
/// capped at [`MAX_CATALOG_SELECTION`]. Deprecated entries are rejected rather
/// than silently added.
pub(crate) fn catalog_lists_to_add(
    catalog: &sito_clients::Catalog,
    existing: &[FilterListConfig],
    selected: &[String],
) -> Result<Vec<FilterListConfig>, CatalogSelectionError> {
    let mut ids: Vec<&str> = Vec::new();
    let mut seen_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for id in selected {
        let id = id.trim();
        if id.is_empty() || !seen_ids.insert(id) {
            continue;
        }
        ids.push(id);
    }
    if ids.len() > MAX_CATALOG_SELECTION {
        return Err(CatalogSelectionError::TooMany);
    }

    let mut filters = Vec::with_capacity(ids.len());
    for id in &ids {
        let Some(filter) = catalog.filter_by_id(id) else {
            return Err(CatalogSelectionError::Unknown((*id).to_string()));
        };
        if filter.deprecated {
            return Err(CatalogSelectionError::Deprecated((*id).to_string()));
        }
        filters.push(filter);
    }

    let mut names: std::collections::HashSet<String> = existing
        .iter()
        .map(|list| list.name.to_lowercase())
        .collect();
    let mut urls: std::collections::HashSet<String> = existing
        .iter()
        .map(|list| list.url.to_lowercase())
        .collect();

    let mut additions = Vec::with_capacity(filters.len());
    for filter in filters {
        if catalog_list_is_present(filter, &names, &urls) {
            continue;
        }
        let name = catalog_list_name(filter);
        if !crate::handlers::filtering::valid_filter_list_name(&name) {
            return Err(CatalogSelectionError::InvalidName(filter.id.clone()));
        }
        names.insert(name.to_lowercase());
        urls.insert(catalog_filter_url(filter).to_lowercase());
        additions.push(FilterListConfig {
            name,
            url: catalog_filter_url(filter).to_string(),
            enabled: true,
            refresh_hours: None,
        });
    }
    Ok(additions)
}

/// Applies a validated catalog selection in one config clone and one sync
/// apply, so a validation or persist failure leaves both the live config and
/// `config.toml` untouched.
pub(crate) async fn apply_catalog_selection(
    ctx: &ServerContext,
    catalog: &sito_clients::Catalog,
    selected: &[String],
) -> Response {
    let _apply_guard = ctx.lock_config_apply().await;
    let mut new_cfg = (**ctx.config.load()).clone();
    let additions = match catalog_lists_to_add(catalog, &new_cfg.filtering.lists, selected) {
        Ok(additions) => additions,
        Err(error) => {
            return error_response(StatusCode::BAD_REQUEST, &error.to_string());
        }
    };
    if additions.is_empty() {
        return Redirect::to("/filtering").into_response();
    }
    new_cfg.filtering.lists.extend(additions);
    if let Err(e) = apply_and_persist_config_locked(ctx, &new_cfg, FilterApply::Sync, None).await {
        tracing::error!("Failed to apply filter configuration: {e:?}");
        return error_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &format!("Failed to apply filter configuration: {}", e.detail),
        );
    }
    Redirect::to("/filtering").into_response()
}

pub async fn filtering_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let csrf = get_csrf_token(&ctx, &headers);
    let can_view_urls = user.role >= Role::Operator;

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
                url: if can_view_urls {
                    list.url.clone()
                } else {
                    redact_subscription_url(&list.url)
                },
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
    let bundled_lists = bundled_list_views(manifest, &ctx.runtime_lists.statuses(), can_view_urls);
    let (catalog_categories, catalog_filters) =
        catalog_page_views(sito_clients::Catalog::embedded(), &cfg.filtering.lists);
    let catalog_filter_count = catalog_filters.len();

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
        catalog_categories,
        catalog_filters,
        catalog_filter_count,
    })
    .into_response()
}

/// Resolves a filter-list id: preferred key is the (unique) list name;
/// numeric indices from older clients keep working.
pub(crate) fn find_filter_list_index(cfg: &Config, id: &str) -> Option<usize> {
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

/// Operator-only catalog selection: adds one or more embedded-catalog filter
/// lists to `[filtering].lists`.
///
/// The form supplies only repeated `selected` catalog ids (never names or
/// URLs); the catalog metadata decides what is persisted. All selected lists
/// are applied in a single configuration transaction.
pub async fn filtering_add_catalog_handler(
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

    let selected = selected_catalog_ids(&pairs);
    let catalog = match sito_clients::Catalog::embedded() {
        Ok(catalog) => catalog,
        Err(e) => {
            tracing::error!(
                error = %e,
                "Embedded filter catalog is invalid; catalog selection is unavailable"
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Embedded filter catalog is unavailable",
            );
        }
    };

    apply_catalog_selection(&ctx, &catalog, &selected).await
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
    let list_name = new_cfg.filtering.lists[idx].name.clone();
    let groups = crate::handlers::filtering::groups_referencing_filter_list(&new_cfg, &list_name);
    if !groups.is_empty() {
        return error_response(
            StatusCode::CONFLICT,
            &format!(
                "Filter list '{list_name}' is referenced by client group(s) {}; update the groups before deleting it",
                groups.join(", ")
            ),
        );
    }
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
    // Hold the apply lock and the prepared filter guard across both publishes.
    let _apply_guard = ctx.lock_config_apply().await;
    let cfg = ctx.config.load_full();
    let prepared = ctx.filter.prepare(&cfg.filtering).await;
    if let Some(error) = prepared.error.as_ref() {
        let error = error.to_string();
        if ctx.filter.publish_prepared(prepared).is_ok() {
            tracing::error!(
                "Filter refresh publish unexpectedly succeeded after a staged load failure"
            );
        }
        tracing::error!("Failed to refresh filter lists: {error}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to refresh filter lists: {error}"),
        );
    }
    let expected = ctx.runtime.generation();
    let snapshot = prepared.snapshot.clone();
    let groups = prepared.group_snapshots.clone();
    if let Err(error) = ctx.runtime.publish_filter(Some(snapshot), groups, expected) {
        tracing::error!("Failed to refresh filter lists: {error}");
        return error_response(
            StatusCode::CONFLICT,
            &format!("Failed to refresh filter lists: {error}"),
        );
    }
    if let Err(e) = ctx.filter.publish_prepared(prepared) {
        tracing::error!("Failed to refresh filter lists: {e}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to refresh filter lists: {e}"),
        );
    }
    ctx.metrics.set_filter_rules(ctx.filter.rule_count());
    ctx.cache.flush();
    ctx.publish_cache_size();
    Redirect::to("/filtering").into_response()
}
