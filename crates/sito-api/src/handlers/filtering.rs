//! Filtering management and simulation endpoints per section 12.1.

use crate::auth::{RequireOperator, RequireViewer};
use crate::config_apply::{FilterApply, apply_and_persist_config_locked};
use crate::error::ProblemDetails;
use crate::models::{
    AddFilterListRequest, CustomRulesDto, FilterCheckRequest, FilterCheckResponse, FilterListDto,
    FilterStatusDto, GenericMessageResponse, UpdateFilterListRequest,
};
use crate::state::ServerContext;
use axum::Json;
use axum::extract::{Path, State};
use sito_core::client::ClientContext;
use sito_core::config::FilterListConfig;
use sito_core::engine::FilterEngine;
use sito_proto::{Name, RecordType};
use std::net::IpAddr;
use std::str::FromStr;

/// True when a filter-list name is safe to use as a URL path segment/key.
pub(crate) fn valid_filter_list_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(['/', '?', '#', '%']) && !name.chars().any(char::is_control)
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
    tag = "Filtering"
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
    tag = "Filtering"
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
    post,
    path = "/api/v1/filtering/lists",
    request_body = AddFilterListRequest,
    responses(
        (status = 200, description = "Filter list added", body = FilterListDto),
        (status = 400, description = "Bad Request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Filtering"
)]
pub async fn add_filter_list(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Json(payload): Json<AddFilterListRequest>,
) -> Result<Json<FilterListDto>, ProblemDetails> {
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
    Ok(Json(dto))
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
    tag = "Filtering"
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
    tag = "Filtering"
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
    tag = "Filtering"
)]
pub async fn refresh_filtering(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    let cfg = ctx.config.load();
    let count = ctx
        .filter
        .reload_with_config(&cfg.filtering)
        .await
        .map_err(|e| ProblemDetails::internal_error(format!("Refresh failed: {e}")))?;
    ctx.cache.flush();
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
    tag = "Filtering"
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
    tag = "Filtering"
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
    tag = "Filtering"
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
