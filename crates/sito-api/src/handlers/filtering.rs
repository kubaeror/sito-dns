//! Filtering management and simulation endpoints per section 12.1.

use crate::auth::{RequireOperator, RequireViewer};
use crate::config_apply::{FilterApply, apply_and_persist_config_locked};
use crate::error::ProblemDetails;
use crate::models::{
    AddFilterListRequest, CustomRulesDto, FilterCheckRequest, FilterCheckResponse, FilterListDto,
    FilterStatusDto, GenericMessageResponse, IntegrationListStatusDto, UpdateFilterListRequest,
};
use crate::state::ServerContext;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use sito_core::client::ClientContext;
use sito_core::config::{Config, FilterListConfig};
use sito_core::engine::FilterEngine;
use sito_proto::{Name, RecordType};
use std::net::IpAddr;
use std::str::FromStr;

/// True when a filter-list name is safe to use as a URL path segment/key.
pub(crate) fn valid_filter_list_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(['/', '?', '#', '%']) && !name.chars().any(char::is_control)
}

/// Client groups that reference `list_name` in their `lists` array.
///
/// Renaming or deleting a referenced list would leave the group pointing at a
/// source the engine cannot resolve, so the admin endpoints reject the change
/// with 409 until the groups are updated first.
pub(crate) fn groups_referencing_filter_list(cfg: &Config, list_name: &str) -> Vec<String> {
    let Some(clients) = cfg
        .clients
        .as_ref()
        .and_then(|value| value.clone().try_into::<sito_clients::ClientsConfig>().ok())
    else {
        return Vec::new();
    };
    clients
        .groups
        .into_iter()
        .filter(|(_, group)| group.lists.iter().any(|name| name == list_name))
        .map(|(name, _)| name)
        .collect()
}

/// Resolves a filter-list id: the stable key is the (unique) list name, while
/// numeric indices from older clients keep working.
fn resolve_filter_list_index(cfg: &sito_core::config::Config, id: &str) -> Option<usize> {
    if let Some(idx) = cfg.filtering.lists.iter().position(|list| list.name == id) {
        return Some(idx);
    }
    id.parse::<usize>()
        .ok()
        .filter(|idx| *idx < cfg.filtering.lists.len())
}

/// Real per-list statistics from the live filter snapshot and the on-disk list
/// metadata (the previous implementation always returned `0`/`None`).
async fn filter_list_stats(ctx: &ServerContext, list_name: &str) -> (usize, Option<i64>) {
    let rule_count = {
        let snapshot = ctx.filter.snapshot();
        snapshot
            .rules
            .iter()
            .filter(|rule| rule.source == list_name)
            .count()
    };
    let data_dir = ctx.config.load().server.data_dir.clone();
    let meta_path = sito_filter::subscription::meta_path_for_list(&data_dir, list_name);
    let last_updated = sito_filter::subscription::read_metadata(&meta_path)
        .await
        .and_then(|meta| i64::try_from(meta.updated_at_secs).ok());
    (rule_count, last_updated)
}

/// Builds a list DTO with real statistics.
async fn filter_list_dto(ctx: &ServerContext, list: &FilterListConfig) -> FilterListDto {
    let (rule_count, last_updated) = filter_list_stats(ctx, &list.name).await;
    FilterListDto {
        id: list.name.clone(),
        name: list.name.clone(),
        url: list.url.clone(),
        enabled: list.enabled,
        refresh_hours: list.refresh_hours.unwrap_or(24) as u32,
        rule_count,
        last_updated,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/filtering/status",
    responses(
        (status = 200, description = "Filter engine lifecycle and per-list health", body = FilterStatusDto),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Filtering",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
)]
#[allow(clippy::unused_async)]
pub async fn get_filtering_status(
    _viewer: RequireViewer,
    State(ctx): State<ServerContext>,
) -> Json<FilterStatusDto> {
    let status = ctx.filter.status();
    Json(FilterStatusDto {
        state: match status.state {
            sito_filter::FilterState::Disabled => "disabled",
            sito_filter::FilterState::Loading => "loading",
            sito_filter::FilterState::Ready => "ready",
            sito_filter::FilterState::Failed => "failed",
        }
        .to_string(),
        rule_count: status.rule_count,
        loaded_lists: status.loaded_lists,
        failed_lists: status.failed_lists,
        degraded_lists: status.degraded_lists,
        degraded_groups: status.degraded_groups,
        dropped_regex_patterns: status.dropped_regex_patterns,
        unavailable: status.unavailable,
        last_error: status.last_error,
        last_compile_ms: status.last_compile_ms,
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/filtering/lists",
    responses(
        (status = 200, description = "Subscription lists retrieved with real rule counts", body = Vec<FilterListDto>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Filtering",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
)]
pub async fn get_filter_lists(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
) -> Json<Vec<FilterListDto>> {
    let lists = ctx.config.load().filtering.lists.clone();
    let mut dtos = Vec::with_capacity(lists.len());
    for list in &lists {
        dtos.push(filter_list_dto(&ctx, list).await);
    }
    Json(dtos)
}

#[utoipa::path(
    get,
    path = "/api/v1/integrations/lists",
    responses(
        (status = 200, description = "Runtime state of every curated parental/service category", body = Vec<IntegrationListStatusDto>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Integrations",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
)]
#[allow(clippy::unused_async)]
pub async fn get_integration_lists(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
) -> Json<Vec<IntegrationListStatusDto>> {
    Json(
        ctx.runtime_lists
            .statuses()
            .into_iter()
            .map(IntegrationListStatusDto::from)
            .collect(),
    )
}

#[utoipa::path(
    post,
    path = "/api/v1/integrations/lists/{category}/refresh",
    params(("category" = String, Path, description = "Curated category id (case-insensitive)")),
    responses(
        (status = 200, description = "Category force-refreshed; the >50% shrink guard is bypassed", body = IntegrationListStatusDto),
        (status = 400, description = "Downloaded content could not be applied"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Category is not configured in [integrations.lists]"),
        (status = 502, description = "Source could not be fetched")
    ),
    tag = "Integrations",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
)]
pub async fn refresh_integration_list(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(category): Path<String>,
) -> Result<Json<IntegrationListStatusDto>, ProblemDetails> {
    // Resolve against the current typed config so a renamed/uppercase request
    // targets the configured source. Only configured categories can refresh;
    // bundled-only rows still have no upstream URL.
    let (category_name, url, data_dir) = {
        let cfg = ctx.config.load();
        let integrations: sito_clients::IntegrationsConfig = cfg
            .integrations
            .as_ref()
            .ok_or_else(|| {
                ProblemDetails::not_found(format!(
                    "Curated list category '{category}' is not configured"
                ))
            })?
            .clone()
            .try_into()
            .map_err(|e| {
                ProblemDetails::internal_error(format!("invalid [integrations] configuration: {e}"))
            })?;
        let lists = integrations.lists.ok_or_else(|| {
            ProblemDetails::not_found(format!(
                "Curated list category '{category}' is not configured"
            ))
        })?;
        let (name, source) = lists
            .categories
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(&category))
            .ok_or_else(|| {
                ProblemDetails::not_found(format!(
                    "Curated list category '{category}' is not configured in [integrations.lists]"
                ))
            })?;
        (
            name.clone(),
            source.url.clone(),
            cfg.server.data_dir.clone(),
        )
    };

    // Same downloader policy as the startup refresh task: default timeout and
    // size cap, with `file://` reads restricted to the data directory.
    let fetcher =
        sito_filter::subscription::SubscriptionFetcher::default().with_file_root(data_dir.clone());
    let cache_name = format!("integration-{category_name}");
    ctx.runtime_lists.record_attempt(&category_name, None);

    let content = match fetcher.fetch_or_cached(&cache_name, &url, &data_dir).await {
        Ok(content) => content,
        Err(e) => {
            let detail = format!("Failed to fetch curated list '{category_name}': {e}");
            ctx.runtime_lists
                .record_attempt(&category_name, Some(detail.clone()));
            return Err(ProblemDetails::new(
                StatusCode::BAD_GATEWAY,
                "Bad Gateway",
                detail,
            ));
        }
    };

    // Operator-initiated refresh: an intentional shrink must be allowed to
    // replace the active content. The periodic task keeps using the guarded
    // `apply_content`.
    if let Err(e) = ctx
        .runtime_lists
        .apply_content_forced(&category_name, &content)
    {
        let detail = format!("Failed to apply curated list '{category_name}': {e}");
        ctx.runtime_lists
            .record_attempt(&category_name, Some(detail.clone()));
        return Err(ProblemDetails::bad_request(detail));
    }
    ctx.runtime_lists.mark_refreshed(&category_name, &url);

    let key = category_name.to_ascii_lowercase();
    let status = ctx
        .runtime_lists
        .statuses()
        .into_iter()
        .find(|status| status.category == key)
        .ok_or_else(|| {
            ProblemDetails::internal_error(format!(
                "Curated list category '{category_name}' disappeared after refresh"
            ))
        })?;
    Ok(Json(status.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/filtering/lists",
    request_body = AddFilterListRequest,
    responses(
        (status = 201, description = "Filter list added", body = FilterListDto),
        (status = 400, description = "Bad Request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Filtering",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
)]
pub async fn add_filter_list(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Json(payload): Json<AddFilterListRequest>,
) -> Result<(StatusCode, Json<FilterListDto>), ProblemDetails> {
    let _apply_guard = ctx.lock_config_apply().await;
    let mut new_cfg = (**ctx.config.load()).clone();
    let name = payload.name.trim().to_string();
    if !valid_filter_list_name(&name) || payload.url.trim().is_empty() {
        return Err(ProblemDetails::bad_request(
            "Filter list name must be non-empty and must not contain /, ?, # or % (URL is required)",
        ));
    }
    if new_cfg.filtering.lists.iter().any(|list| list.name == name) {
        return Err(ProblemDetails::conflict(format!(
            "Filter list '{name}' already exists"
        )));
    }
    let new_list = FilterListConfig {
        name: name.clone(),
        url: payload.url.clone(),
        enabled: payload.enabled,
        refresh_hours: Some(u64::from(payload.refresh_hours)),
    };

    new_cfg.filtering.lists.push(new_list.clone());

    // Compile before persisting so a broken list does not get written as
    // successfully applied; a persist failure also rolls the filter snapshot
    // and the rest of the live apply back.
    apply_and_persist_config_locked(&ctx, &new_cfg, FilterApply::Sync, None).await?;

    let mut dto = filter_list_dto(&ctx, &new_list).await;
    dto.id = name;
    Ok((StatusCode::CREATED, Json(dto)))
}

#[utoipa::path(
    put,
    path = "/api/v1/filtering/lists/{id}",
    request_body = UpdateFilterListRequest,
    params(("id" = usize, Path, description = "Filter list index ID")),
    responses(
        (status = 200, description = "Filter list updated", body = FilterListDto),
        (status = 404, description = "Not Found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Filtering",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
)]
pub async fn update_filter_list(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateFilterListRequest>,
) -> Result<Json<FilterListDto>, ProblemDetails> {
    let _apply_guard = ctx.lock_config_apply().await;
    let mut new_cfg = (**ctx.config.load()).clone();
    let idx = resolve_filter_list_index(&new_cfg, &id)
        .ok_or_else(|| ProblemDetails::not_found(format!("Filter list with ID {id} not found")))?;

    let old_name = new_cfg.filtering.lists[idx].name.clone();
    if let Some(ref new_name) = payload.name {
        if !valid_filter_list_name(new_name.trim()) {
            return Err(ProblemDetails::bad_request(
                "Filter list name must be non-empty and must not contain /, ?, # or %",
            ));
        }
        if new_cfg
            .filtering
            .lists
            .iter()
            .enumerate()
            .any(|(i, list)| i != idx && list.name == *new_name)
        {
            return Err(ProblemDetails::conflict(format!(
                "Filter list '{new_name}' already exists"
            )));
        }
        if *new_name != old_name {
            let groups = groups_referencing_filter_list(&new_cfg, &old_name);
            if !groups.is_empty() {
                return Err(ProblemDetails::conflict(format!(
                    "Filter list '{old_name}' is referenced by client group(s) {}; update the groups before renaming it",
                    groups.join(", ")
                )));
            }
        }
    }

    let list = &mut new_cfg.filtering.lists[idx];
    if let Some(name) = payload.name {
        list.name = name;
    }
    if let Some(url) = payload.url {
        list.url = url;
    }
    if let Some(enabled) = payload.enabled {
        list.enabled = enabled;
    }
    if let Some(rh) = payload.refresh_hours {
        list.refresh_hours = Some(u64::from(rh));
    }

    let updated = new_cfg.filtering.lists[idx].clone();
    apply_and_persist_config_locked(&ctx, &new_cfg, FilterApply::Sync, None).await?;

    Ok(Json(filter_list_dto(&ctx, &updated).await))
}

#[utoipa::path(
    delete,
    path = "/api/v1/filtering/lists/{id}",
    params(("id" = usize, Path, description = "Filter list index ID")),
    responses(
        (status = 200, description = "Filter list deleted", body = GenericMessageResponse),
        (status = 404, description = "Not Found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Filtering",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
)]
pub async fn delete_filter_list(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(id): Path<String>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    let _apply_guard = ctx.lock_config_apply().await;
    let mut new_cfg = (**ctx.config.load()).clone();
    let idx = resolve_filter_list_index(&new_cfg, &id)
        .ok_or_else(|| ProblemDetails::not_found(format!("Filter list with ID {id} not found")))?;

    let list_name = new_cfg.filtering.lists[idx].name.clone();
    let groups = groups_referencing_filter_list(&new_cfg, &list_name);
    if !groups.is_empty() {
        return Err(ProblemDetails::conflict(format!(
            "Filter list '{list_name}' is referenced by client group(s) {}; update the groups before deleting it",
            groups.join(", ")
        )));
    }

    let removed = new_cfg.filtering.lists.remove(idx);
    apply_and_persist_config_locked(&ctx, &new_cfg, FilterApply::Sync, None).await?;

    Ok(Json(GenericMessageResponse {
        message: format!("Filter list '{}' deleted successfully", removed.name),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/filtering/refresh",
    responses(
        (status = 200, description = "Filter lists refreshed", body = GenericMessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Filtering",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
)]
pub async fn refresh_filtering(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    // Serialize with config applies and keep the prepared engine guard until
    // both the runtime snapshot and the engine state are published. A refresh
    // compiled for an older config generation is rejected instead of
    // overwriting the newer generation's filter.
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
        return Err(ProblemDetails::internal_error(format!(
            "Refresh failed: {error}"
        )));
    }
    let expected = ctx.runtime.generation();
    let snapshot = prepared.snapshot.clone();
    let groups = prepared.group_snapshots.clone();
    ctx.runtime
        .publish_filter(Some(snapshot), groups, expected)
        .map_err(crate::config_apply::problem_from_apply)?;
    let count = ctx
        .filter
        .publish_prepared(prepared)
        .map_err(|e| ProblemDetails::internal_error(format!("Refresh failed: {e}")))?;
    ctx.metrics.set_filter_rules(count);
    ctx.cache.flush();
    ctx.publish_cache_size();
    Ok(Json(GenericMessageResponse {
        message: format!("Successfully refreshed filter lists ({count} active rules compiled)"),
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/filtering/rules",
    responses(
        (status = 200, description = "Custom rules retrieved", body = CustomRulesDto),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Filtering",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
)]
pub async fn get_filtering_rules(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
) -> Json<CustomRulesDto> {
    let cfg = ctx.config.load();
    Json(CustomRulesDto {
        rules: cfg.filtering.custom_rules.clone(),
    })
}

#[utoipa::path(
    put,
    path = "/api/v1/filtering/rules",
    request_body = CustomRulesDto,
    responses(
        (status = 200, description = "Custom rules updated", body = CustomRulesDto),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Filtering",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
)]
pub async fn set_filtering_rules(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Json(payload): Json<CustomRulesDto>,
) -> Result<Json<CustomRulesDto>, ProblemDetails> {
    let _apply_guard = ctx.lock_config_apply().await;
    let mut new_cfg = (**ctx.config.load()).clone();
    new_cfg.filtering.custom_rules = payload.rules.clone();

    apply_and_persist_config_locked(&ctx, &new_cfg, FilterApply::Sync, None).await?;

    Ok(Json(CustomRulesDto {
        rules: payload.rules,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/filtering/check",
    request_body = FilterCheckRequest,
    responses(
        (status = 200, description = "Filtering check result simulated", body = FilterCheckResponse),
        (status = 400, description = "Bad Request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Filtering",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
)]
pub async fn check_filtering(
    _viewer: RequireViewer,
    State(ctx): State<ServerContext>,
    Json(payload): Json<FilterCheckRequest>,
) -> Result<Json<FilterCheckResponse>, ProblemDetails> {
    let domain_name = Name::from_str(&payload.domain)
        .map_err(|e| ProblemDetails::bad_request(format!("Invalid domain name: {e}")))?;

    let client_ip: IpAddr = payload
        .client
        .as_deref()
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap());

    let mut client = ClientContext::new(client_ip);
    if let Some(ref name) = payload.client {
        client.client_name = Some(name.clone());
    }

    let qtype = payload.qtype.map_or(RecordType::A, RecordType::from);

    let verdict = ctx.filter.evaluate(&domain_name, qtype, &client);

    let (v_str, rule_text, source, cat) = match verdict {
        sito_core::verdict::Verdict::Allow(rule_ref) => {
            let (r, s) = rule_ref.as_ref().map_or((None, None), |rf| {
                (Some(rf.rule_text.clone()), rf.list_name.clone())
            });
            ("allowed".to_string(), r, s, None)
        }
        sito_core::verdict::Verdict::Block(reason) => match reason {
            sito_core::verdict::BlockReason::Rule(rf) => (
                "blocked".to_string(),
                Some(rf.rule_text),
                rf.list_name,
                None,
            ),
            sito_core::verdict::BlockReason::Parental => (
                "blocked".to_string(),
                None,
                None,
                Some("parental".to_string()),
            ),
            sito_core::verdict::BlockReason::Service(svc) => (
                "blocked".to_string(),
                None,
                None,
                Some(format!("service:{svc}")),
            ),
            sito_core::verdict::BlockReason::AntiDohBypass => (
                "blocked".to_string(),
                Some("anti_doh_bypass".to_string()),
                Some("anti_doh_bypass".to_string()),
                Some("anti_doh_bypass".to_string()),
            ),
            sito_core::verdict::BlockReason::FilterUnavailable => (
                "blocked".to_string(),
                Some("filter_unavailable".to_string()),
                Some("fail_closed".to_string()),
                Some("fail_closed".to_string()),
            ),
        },
        sito_core::verdict::Verdict::Rewrite(_) => ("rewritten".to_string(), None, None, None),
    };

    Ok(Json(FilterCheckResponse {
        domain: payload.domain,
        verdict: v_str,
        rule: rule_text,
        list_source: source,
        category: cat,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::rbac::AuthUser;
    use crate::auth::token::Role;

    fn operator() -> RequireOperator {
        RequireOperator(AuthUser {
            username: "operator".to_string(),
            role: Role::Operator,
            token_id: None,
        })
    }

    /// WP-4.5: `GET /filtering/lists` must report the real compiled rule count
    /// (the placeholder `0` made a loaded list indistinguishable from a dead
    /// one).
    #[tokio::test]
    async fn test_filter_lists_expose_real_rule_counts() {
        let temp_dir = crate::test_support::temp_dir("sito_filter_counts");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let list_path = temp_dir.join("local-list.txt");
        std::fs::write(
            &list_path,
            "||ads.example^\n||tracker.example^\n0.0.0.0 banner.example\n",
        )
        .unwrap();

        let mut config = (**ctx.config.load()).clone();
        config.filtering.enabled = true;
        config.filtering.lists = vec![FilterListConfig {
            name: "Local".to_string(),
            url: format!("file://{}", list_path.display()),
            enabled: true,
            refresh_hours: None,
        }];
        ctx.filter
            .reload_with_config(&config.filtering)
            .await
            .expect("local list loads");
        ctx.set_config(config);

        let Json(dtos) = get_filter_lists(operator(), State(ctx.clone())).await;
        assert_eq!(dtos.len(), 1);
        assert_eq!(
            dtos[0].rule_count, 3,
            "rule_count must reflect the compiled rules for the list"
        );

        // A list whose source does not exist reports zero rules while the
        // healthy list keeps its real count.
        let mut config = (**ctx.config.load()).clone();
        config.filtering.lists.push(FilterListConfig {
            name: "Missing".to_string(),
            url: format!("file://{}", temp_dir.join("missing.txt").display()),
            enabled: true,
            refresh_hours: None,
        });
        let _ = ctx.filter.reload_with_config(&config.filtering).await;
        ctx.set_config(config);
        let Json(dtos) = get_filter_lists(operator(), State(ctx.clone())).await;
        assert_eq!(dtos.len(), 2);
        let local = dtos.iter().find(|d| d.name == "Local").unwrap();
        let missing = dtos.iter().find(|d| d.name == "Missing").unwrap();
        assert_eq!(local.rule_count, 3);
        assert_eq!(missing.rule_count, 0);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// P2-41: renaming or deleting a list still referenced by a client group
    /// is a 409 and changes neither the live config nor the persisted file.
    #[tokio::test]
    async fn test_referenced_filter_list_rename_and_delete_return_conflict() {
        let temp_dir = crate::test_support::temp_dir("sito_filter_references");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let list_path = temp_dir.join("referenced-list.txt");
        std::fs::write(&list_path, "||ads.example^\n").unwrap();
        let mut seed = (**ctx.config.load()).clone();
        seed.filtering.enabled = true;
        seed.filtering.lists = vec![FilterListConfig {
            name: "Local".to_string(),
            url: format!("file://{}", list_path.display()),
            enabled: true,
            refresh_hours: None,
        }];
        let mut clients = sito_clients::ClientsConfig::default();
        clients.groups.insert(
            "kids".to_string(),
            sito_clients::ClientGroupConfig {
                lists: vec!["Local".to_string()],
                ..Default::default()
            },
        );
        seed.clients = Some(toml::Value::try_from(&clients).unwrap());
        crate::config_apply::apply_and_persist_config(
            &ctx,
            &seed,
            crate::config_apply::FilterApply::Sync,
            None,
        )
        .await
        .expect("seed with a referenced list");
        let persisted_before = tokio::fs::read_to_string(&ctx.config_path).await.unwrap();

        let err = update_filter_list(
            operator(),
            State(ctx.clone()),
            Path("Local".to_string()),
            Json(UpdateFilterListRequest {
                name: Some("Renamed".to_string()),
                url: None,
                enabled: None,
                refresh_hours: None,
            }),
        )
        .await
        .expect_err("renaming a referenced list must conflict");
        assert_eq!(err.status, 409);
        assert!(err.detail.contains("kids"), "got: {}", err.detail);

        let err = delete_filter_list(operator(), State(ctx.clone()), Path("Local".to_string()))
            .await
            .expect_err("deleting a referenced list must conflict");
        assert_eq!(err.status, 409);
        assert!(err.detail.contains("kids"), "got: {}", err.detail);

        assert_eq!(ctx.config.load().filtering.lists.len(), 1);
        assert_eq!(ctx.config.load().filtering.lists[0].name, "Local");
        assert_eq!(
            tokio::fs::read_to_string(&ctx.config_path).await.unwrap(),
            persisted_before,
            "a conflicting rename/delete must not persist anything"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// WP-2.10: creating a filter list returns 201 (not 200) with the created
    /// DTO, matching the other create endpoints.
    #[tokio::test]
    async fn test_add_filter_list_returns_201_with_body() {
        let temp_dir = crate::test_support::temp_dir("sito_filter_add_status");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        let list_path = temp_dir.join("add-list.txt");
        std::fs::write(&list_path, "||ads.example^\n").unwrap();

        let response = add_filter_list(
            operator(),
            State(ctx.clone()),
            Json(AddFilterListRequest {
                name: "Local".to_string(),
                url: format!("file://{}", list_path.display()),
                enabled: true,
                refresh_hours: 24,
            }),
        )
        .await
        .expect("filter list added");

        let (status, Json(dto)) = response;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(dto.id, "Local");
        assert_eq!(dto.name, "Local");
        assert!(
            ctx.config
                .load()
                .filtering
                .lists
                .iter()
                .any(|list| list.name == "Local"),
            "the created list must be persisted"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// The curated-list API exposes status, resolves categories
    /// case-insensitively, reports unknown/unfetchable categories, and is
    /// Operator-only.
    #[tokio::test]
    async fn test_integration_lists_api_status_refresh_and_auth() {
        use axum::body::{Body, to_bytes};
        use axum::http::{Request, header};
        use tower::ServiceExt;

        let temp_dir = crate::test_support::temp_dir("sito_integration_lists_api");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        // Rotate the bootstrap password so the setup gate lets API requests
        // reach the normal auth layer (which is what this test exercises).
        ctx.auth_mgr
            .update_user_password("admin", "TestPassword123!")
            .await;
        let source_path = temp_dir.join("adult.txt");
        std::fs::write(&source_path, "a.example\nb.example\n").unwrap();
        let missing_path = temp_dir.join("missing.txt");
        let invalid_services_path = temp_dir.join("services.json");
        std::fs::write(&invalid_services_path, "not service json").unwrap();

        let mut config = (**ctx.config.load()).clone();
        config.server.data_dir = temp_dir.clone();
        config.integrations = Some(
            toml::from_str(&format!(
                r#"
                [lists]
                refresh_hours = 24
                [lists.categories.adult]
                url = "file://{}"
                [lists.categories.gambling]
                url = "file://{}"
                [lists.categories.services]
                url = "file://{}"
                "#,
                source_path.display(),
                missing_path.display(),
                invalid_services_path.display()
            ))
            .expect("valid integrations fixture"),
        );
        ctx.set_config(config);

        let token = ctx
            .auth_mgr
            .create_token("lists-test", Role::Operator, None)
            .await
            .expect("create operator token")
            .1
            .token;
        let app = crate::create_router(ctx.clone());

        // Unauthenticated reads are rejected.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/integrations/lists")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Mutating force refresh is Operator-only too.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/integrations/lists/adult/refresh")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let get_rows = |app: axum::Router, token: String| async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/integrations/lists")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            serde_json::from_slice::<Vec<serde_json::Value>>(&bytes).unwrap()
        };

        let rows = get_rows(app.clone(), token.clone()).await;
        let adult = rows
            .iter()
            .find(|row| row["category"] == "adult")
            .expect("adult status row");
        assert_eq!(adult["bundled"], true);
        assert!(adult.get("last_error").is_none());

        // Uppercase request resolves the configured lowercase key.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/integrations/lists/Adult/refresh")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let refreshed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(refreshed["category"], "adult");
        assert_eq!(refreshed["bundled"], false);
        assert_eq!(refreshed["entries"], 2);
        assert!(refreshed.get("last_error").is_none());
        assert!(refreshed["last_refresh_unix"].is_number());
        assert!(refreshed["last_attempt_unix"].is_number());

        // Unknown categories are 404, not a silent bundled-only refresh.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/integrations/lists/unknown/refresh")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // A fetch failure is a 502 and records the error for status consumers.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/integrations/lists/gambling/refresh")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let problem: crate::error::ProblemDetails = serde_json::from_slice(&bytes).unwrap();
        assert!(
            problem.detail.contains("Failed to fetch"),
            "unexpected problem: {problem:?}"
        );

        // Invalid downloaded content is a 400 and also records the error.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/integrations/lists/services/refresh")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let rows = get_rows(app, token).await;
        let gambling = rows
            .iter()
            .find(|row| row["category"] == "gambling")
            .expect("gambling status row");
        assert!(
            gambling["last_error"]
                .as_str()
                .is_some_and(|error| error.contains("Failed to fetch")),
            "the 502 must leave last_error visible: {gambling}"
        );
        assert!(gambling["last_attempt_unix"].is_number());
        let services = rows
            .iter()
            .find(|row| row["category"] == "services")
            .expect("services status row");
        assert!(
            services["last_error"]
                .as_str()
                .is_some_and(|error| error.contains("Failed to apply")),
            "the 400 must leave last_error visible: {services}"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// WP-0.5: the engine's loaded/failed/degraded state is exposed via the
    /// API instead of being log-only.
    #[tokio::test]
    async fn test_filtering_status_is_exposed() {
        let temp_dir = crate::test_support::temp_dir("sito_filter_status_api");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        let Json(status) = get_filtering_status(
            crate::auth::rbac::RequireViewer(AuthUser {
                username: "viewer".to_string(),
                role: Role::Viewer,
                token_id: None,
            }),
            State(ctx.clone()),
        )
        .await;

        assert_eq!(status.state, "disabled");
        assert_eq!(status.rule_count, 0);
        assert!(!status.unavailable);
        assert_eq!(status.failed_lists.len(), 0);
        assert_eq!(status.degraded_groups.len(), 0);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
