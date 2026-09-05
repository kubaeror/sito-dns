//! Local DNS rewrite management endpoints per section 12.1.

use crate::auth::RequireOperator;
use crate::config_writer::save_config_atomic;
use crate::error::ProblemDetails;
use crate::models::{AddRewriteRequest, GenericMessageResponse, RewriteDto};
use crate::state::ServerContext;
use axum::Json;
use axum::extract::{Path, State};
use sito_rewrites::{RewriteEntryConfig, RewritesConfig};
use std::sync::Arc;

fn load_rewrites_config(ctx: &ServerContext) -> RewritesConfig {
    ctx.config
        .load()
        .rewrites
        .as_ref()
        .and_then(|v| v.clone().try_into().ok())
        .unwrap_or_default()
}

async fn save_rewrites_config(
    ctx: &ServerContext,
    rewrites_cfg: &RewritesConfig,
) -> Result<(), ProblemDetails> {
    let mut new_cfg = (**ctx.config.load()).clone();
    let val = toml::Value::try_from(rewrites_cfg).map_err(|e| {
        ProblemDetails::internal_error(format!("Failed to serialize rewrites: {e}"))
    })?;
    new_cfg.rewrites = Some(val);

    save_config_atomic(&ctx.config_path, &new_cfg).await?;
    ctx.config.store(Arc::new(new_cfg));

    // Update active rewrite table
    let new_table = sito_rewrites::RewriteTable::new(rewrites_cfg.clone());
    ctx.rewrites.store(Arc::new(new_table));
    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/v1/rewrites",
    responses(
        (status = 200, description = "DNS rewrites retrieved", body = Vec<RewriteDto>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Rewrites"
)]
pub async fn get_rewrites(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
) -> Json<Vec<RewriteDto>> {
    let cfg = load_rewrites_config(&ctx);
    let dtos = cfg
        .entries
        .into_iter()
        .enumerate()
        .map(|(idx, e)| RewriteDto {
            id: idx.to_string(),
            domain: e.domain,
            record_type: e.r#type,
            answer: e.answer,
            exception_clients: e.exception_clients,
        })
        .collect();
    Json(dtos)
}

#[utoipa::path(
    post,
    path = "/api/v1/rewrites",
    request_body = AddRewriteRequest,
    responses(
        (status = 200, description = "DNS rewrite created", body = RewriteDto),
        (status = 400, description = "Bad Request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Rewrites"
)]
pub async fn add_rewrite(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Json(payload): Json<AddRewriteRequest>,
) -> Result<Json<RewriteDto>, ProblemDetails> {
    let mut cfg = load_rewrites_config(&ctx);

    let id = cfg.entries.len().to_string();
    let entry = RewriteEntryConfig {
        domain: payload.domain.clone(),
        r#type: payload.record_type.clone(),
        answer: payload.answer.clone(),
        exception_clients: payload.exception_clients.clone(),
    };

    cfg.entries.push(entry);
    save_rewrites_config(&ctx, &cfg).await?;

    Ok(Json(RewriteDto {
        id,
        domain: payload.domain,
        record_type: payload.record_type,
        answer: payload.answer,
        exception_clients: payload.exception_clients,
    }))
}

#[utoipa::path(
    put,
    path = "/api/v1/rewrites/{id}",
    request_body = AddRewriteRequest,
    params(("id" = String, Path, description = "Rewrite index ID")),
    responses(
        (status = 200, description = "DNS rewrite updated", body = RewriteDto),
        (status = 404, description = "Not Found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Rewrites"
)]
pub async fn update_rewrite(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(id): Path<String>,
    Json(payload): Json<AddRewriteRequest>,
) -> Result<Json<RewriteDto>, ProblemDetails> {
    let idx: usize = id
        .parse()
        .map_err(|_| ProblemDetails::bad_request("Rewrite ID must be a numeric index"))?;

    let mut cfg = load_rewrites_config(&ctx);
    if idx >= cfg.entries.len() {
        return Err(ProblemDetails::not_found(format!(
            "Rewrite with ID {id} not found"
        )));
    }

    cfg.entries[idx] = RewriteEntryConfig {
        domain: payload.domain.clone(),
        r#type: payload.record_type.clone(),
        answer: payload.answer.clone(),
        exception_clients: payload.exception_clients.clone(),
    };

    save_rewrites_config(&ctx, &cfg).await?;

    Ok(Json(RewriteDto {
        id,
        domain: payload.domain,
        record_type: payload.record_type,
        answer: payload.answer,
        exception_clients: payload.exception_clients,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/rewrites/{id}",
    params(("id" = String, Path, description = "Rewrite index ID")),
    responses(
        (status = 200, description = "DNS rewrite deleted", body = GenericMessageResponse),
        (status = 404, description = "Not Found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Rewrites"
)]
pub async fn delete_rewrite(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(id): Path<String>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    let idx: usize = id
        .parse()
        .map_err(|_| ProblemDetails::bad_request("Rewrite ID must be a numeric index"))?;

    let mut cfg = load_rewrites_config(&ctx);
    if idx >= cfg.entries.len() {
        return Err(ProblemDetails::not_found(format!(
            "Rewrite with ID {id} not found"
        )));
    }

    let removed = cfg.entries.remove(idx);
    save_rewrites_config(&ctx, &cfg).await?;

    Ok(Json(GenericMessageResponse {
        message: format!("Rewrite for '{}' deleted successfully", removed.domain),
    }))
}
