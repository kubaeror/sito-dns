//! Filtering management and simulation endpoints per section 12.1.

use crate::auth::{RequireOperator, RequireViewer};
use crate::config_writer::save_config_atomic;
use crate::error::ProblemDetails;
use crate::models::{
    AddFilterListRequest, CustomRulesDto, FilterCheckRequest, FilterCheckResponse, FilterListDto,
    GenericMessageResponse, UpdateFilterListRequest,
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

#[utoipa::path(
    get,
    path = "/api/v1/filtering/lists",
    responses(
        (status = 200, description = "Subscription lists retrieved", body = Vec<FilterListDto>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Filtering"
)]
pub async fn get_filter_lists(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
) -> Json<Vec<FilterListDto>> {
    let cfg = ctx.config.load();
    let dtos = cfg
        .filtering
        .lists
        .iter()
        .map(|list| FilterListDto {
            id: list.name.clone(),
            name: list.name.clone(),
            url: list.url.clone(),
            enabled: list.enabled,
            refresh_hours: list.refresh_hours.unwrap_or(24) as u32,
            rule_count: 0,
            last_updated: None,
        })
        .collect();
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
    // successfully applied.
    ctx.filter
        .reload_with_config(&new_cfg.filtering)
        .await
        .map_err(|e| {
            ProblemDetails::internal_error(format!("Failed to apply filter configuration: {e}"))
        })?;
    save_config_atomic(&ctx.config_path, &new_cfg).await?;
    ctx.set_config(new_cfg);
    crate::publish_bundle(&ctx);

    Ok(Json(FilterListDto {
        id: name,
        name: new_list.name,
        url: new_list.url,
        enabled: new_list.enabled,
        refresh_hours: new_list.refresh_hours.unwrap_or(24) as u32,
        rule_count: 0,
        last_updated: None,
    }))
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

    let updated_dto = FilterListDto {
        id: list.name.clone(),
        name: list.name.clone(),
        url: list.url.clone(),
        enabled: list.enabled,
        refresh_hours: list.refresh_hours.unwrap_or(24) as u32,
        rule_count: 0,
        last_updated: None,
    };

    ctx.filter
        .reload_with_config(&new_cfg.filtering)
        .await
        .map_err(|e| {
            ProblemDetails::internal_error(format!("Failed to apply filter configuration: {e}"))
        })?;
    save_config_atomic(&ctx.config_path, &new_cfg).await?;
    ctx.set_config(new_cfg);
    crate::publish_bundle(&ctx);

    Ok(Json(updated_dto))
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
    let mut new_cfg = (**ctx.config.load()).clone();
    let idx = resolve_filter_list_index(&new_cfg, &id)
        .ok_or_else(|| ProblemDetails::not_found(format!("Filter list with ID {id} not found")))?;

    let removed = new_cfg.filtering.lists.remove(idx);
    ctx.filter
        .reload_with_config(&new_cfg.filtering)
        .await
        .map_err(|e| {
            ProblemDetails::internal_error(format!("Failed to apply filter configuration: {e}"))
        })?;
    save_config_atomic(&ctx.config_path, &new_cfg).await?;
    ctx.set_config(new_cfg);
    crate::publish_bundle(&ctx);

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
    let mut new_cfg = (**ctx.config.load()).clone();
    new_cfg.filtering.custom_rules = payload.rules.clone();

    ctx.filter
        .reload_with_config(&new_cfg.filtering)
        .await
        .map_err(|e| {
            ProblemDetails::internal_error(format!("Failed to apply filter configuration: {e}"))
        })?;
    save_config_atomic(&ctx.config_path, &new_cfg).await?;
    ctx.set_config(new_cfg);
    crate::publish_bundle(&ctx);

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
