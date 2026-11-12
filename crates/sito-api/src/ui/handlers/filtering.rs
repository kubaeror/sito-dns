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
    // Hold the apply lock and the prepared filter guard across both publishes.
    let _apply_guard = ctx.lock_config_apply().await;
    let cfg = ctx.config.load_full();
    let prepared = ctx.filter.prepare(&cfg.filtering).await;
    if let Some(error) = prepared.error.as_ref() {
        let error = error.to_string();
        let _ = ctx.filter.publish_prepared(prepared);
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
    Redirect::to("/filtering").into_response()
}
