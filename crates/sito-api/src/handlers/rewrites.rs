//! Local DNS rewrite management endpoints per section 12.1.
//!
//! Entries carry a stable, persisted `id` (stored next to the entry in the
//! raw TOML so the `sito-rewrites` config struct stays unchanged). Clients that
//! still send legacy numeric indices are supported: an unknown id that parses
//! as an index resolves positionally, and `legacy-N` ids map to index `N`.

use crate::auth::RequireOperator;
use crate::config_writer::save_config_atomic;
use crate::error::ProblemDetails;
use crate::models::{AddRewriteRequest, GenericMessageResponse, RewriteDto};
use crate::state::ServerContext;
use axum::Json;
use axum::extract::{Path, State};
use rand::RngExt;
use sito_rewrites::{RewriteEntryConfig, RewritesConfig};

/// Rewrite configuration plus the stable ids of its entries (same order).
#[derive(Debug, Clone)]
pub(crate) struct RewriteStore {
    pub cfg: RewritesConfig,
    pub ids: Vec<String>,
}

pub(crate) fn new_rewrite_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    format!("rw_{}", hex::encode(bytes))
}

/// Loads the rewrite configuration, recovering persisted ids from the raw
/// TOML table and synthesizing deterministic legacy ids for entries that
/// predate stable ids.
pub(crate) fn load_rewrite_store(ctx: &ServerContext) -> RewriteStore {
    let raw = ctx.config.load().rewrites.clone();
    let cfg: RewritesConfig = raw
        .as_ref()
        .and_then(|v| v.clone().try_into().ok())
        .unwrap_or_default();

    let mut ids: Vec<String> = Vec::with_capacity(cfg.entries.len());
    if let Some(entries) = raw
        .as_ref()
        .and_then(|v| v.get("entries"))
        .and_then(|v| v.as_array())
        && entries.len() == cfg.entries.len()
    {
        for (idx, entry) in entries.iter().enumerate() {
            ids.push(
                entry
                    .get("id")
                    .and_then(|v| v.as_str())
                    .filter(|id| !id.is_empty())
                    .map_or_else(|| format!("legacy-{idx}"), ToString::to_string),
            );
        }
    }
    if ids.len() != cfg.entries.len() {
        ids = (0..cfg.entries.len())
            .map(|i| format!("legacy-{i}"))
            .collect();
    }

    RewriteStore { cfg, ids }
}

/// Persists rewrites with their stable ids embedded in the raw TOML value.
pub(crate) async fn save_rewrite_store(
    ctx: &ServerContext,
    store: &RewriteStore,
) -> Result<(), ProblemDetails> {
    let mut new_cfg = (**ctx.config.load()).clone();
    let mut value = toml::Value::try_from(&store.cfg).map_err(|e| {
        ProblemDetails::internal_error(format!("Failed to serialize rewrites: {e}"))
    })?;
    if let Some(entries) = value.get_mut("entries").and_then(|v| v.as_array_mut()) {
        for (entry, id) in entries.iter_mut().zip(store.ids.iter()) {
            if let Some(table) = entry.as_table_mut() {
                table.insert("id".to_string(), toml::Value::String(id.clone()));
            }
        }
    }
    new_cfg.rewrites = Some(value);

    save_config_atomic(&ctx.config_path, &new_cfg).await?;
    ctx.set_config(new_cfg);

    // Update active rewrite table
    let new_table = sito_rewrites::RewriteTable::new(store.cfg.clone());
    ctx.set_rewrites(new_table);
    crate::publish_bundle(ctx);
    Ok(())
}

/// Resolves a rewrite id to an index, accepting persisted ids, legacy
/// `legacy-N` ids and (for backward compatibility) plain numeric indices.
pub(crate) fn resolve_rewrite_index(store: &RewriteStore, id: &str) -> Option<usize> {
    if let Some(idx) = store.ids.iter().position(|candidate| candidate == id) {
        return Some(idx);
    }
    let index = id
        .parse::<usize>()
        .ok()
        .or_else(|| id.strip_prefix("legacy-").and_then(|n| n.parse().ok()))?;
    (index < store.cfg.entries.len()).then_some(index)
}

fn to_dto(id: String, entry: RewriteEntryConfig) -> RewriteDto {
    RewriteDto {
        id,
        domain: entry.domain,
        record_type: entry.r#type,
        answer: entry.answer,
        exception_clients: entry.exception_clients,
    }
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
    let store = load_rewrite_store(&ctx);
    let dtos = store
        .ids
        .into_iter()
        .zip(store.cfg.entries)
        .map(|(id, e)| to_dto(id, e))
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
    let mut store = load_rewrite_store(&ctx);

    let id = new_rewrite_id();
    let entry = RewriteEntryConfig {
        domain: payload.domain.clone(),
        r#type: payload.record_type.clone(),
        answer: payload.answer.clone(),
        exception_clients: payload.exception_clients.clone(),
    };

    store.cfg.entries.push(entry);
    store.ids.push(id.clone());
    save_rewrite_store(&ctx, &store).await?;

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
    params(("id" = String, Path, description = "Stable rewrite ID")),
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
    let mut store = load_rewrite_store(&ctx);
    let idx = resolve_rewrite_index(&store, &id)
        .ok_or_else(|| ProblemDetails::not_found(format!("Rewrite with ID {id} not found")))?;

    store.cfg.entries[idx] = RewriteEntryConfig {
        domain: payload.domain.clone(),
        r#type: payload.record_type.clone(),
        answer: payload.answer.clone(),
        exception_clients: payload.exception_clients.clone(),
    };

    save_rewrite_store(&ctx, &store).await?;

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
    params(("id" = String, Path, description = "Stable rewrite ID")),
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
    let mut store = load_rewrite_store(&ctx);
    let idx = resolve_rewrite_index(&store, &id)
        .ok_or_else(|| ProblemDetails::not_found(format!("Rewrite with ID {id} not found")))?;

    let removed = store.cfg.entries.remove(idx);
    store.ids.remove(idx);
    save_rewrite_store(&ctx, &store).await?;

    Ok(Json(GenericMessageResponse {
        message: format!("Rewrite for '{}' deleted successfully", removed.domain),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthUser;
    use crate::auth::token::Role;
    use crate::models::AddRewriteRequest;
    use arc_swap::ArcSwap;
    use axum::extract::State;
    use sito_core::config::Config;
    use std::sync::{Arc, Mutex};

    async fn mock_context(temp_dir: &std::path::Path) -> ServerContext {
        let db_path = temp_dir.join("test.db");
        let stats_db = sito_stats::StatsDb::open(&db_path).await.unwrap();
        let querylog_writer = sito_stats::QueryLogWriter::spawn(stats_db.clone(), 100);
        let querylog_sender = querylog_writer.sender();
        let metrics = sito_stats::MetricsRegistry::new("1.2.1", "test");
        let auth_mgr = Arc::new(crate::auth::AuthManager::new());
        let config = Config::default();
        let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
        let filter = Arc::new(
            sito_filter::HostsFilterEngine::init(Default::default(), temp_dir.to_path_buf()).await,
        );
        let cache = Arc::new(sito_cache::DnsCache::new(Default::default()));
        let bootstrap = sito_upstream::BootstrapResolver::new(
            vec!["127.0.0.1".parse().unwrap()],
            std::time::Duration::from_secs(1),
        );
        let upstream = Arc::new(
            sito_upstream::UpstreamManager::from_config(&Default::default(), &bootstrap)
                .await
                .unwrap(),
        );
        let clients = Arc::new(ArcSwap::new(Arc::new(sito_clients::ClientRegistry::new(
            Default::default(),
        ))));
        let rewrites = Arc::new(ArcSwap::new(Arc::new(sito_rewrites::RewriteTable::new(
            Default::default(),
        ))));
        let runtime = Arc::new(sito_runtime::RuntimeState::new(
            config_arc.clone(),
            clients.clone(),
            rewrites.clone(),
        ));
        let runtime_lists = Arc::new(sito_clients::RuntimeLists::from_arcs(
            Arc::new(sito_clients::ParentalRegistry::bundled()),
            Arc::new(sito_clients::ServiceRegistry::bundled()),
        ));

        ServerContext {
            config: config_arc,
            runtime,
            runtime_lists,
            config_path: temp_dir.join("config.toml"),
            auth_mgr,
            stats_db,
            querylog_sender,
            metrics,
            filter,
            cache,
            upstream,
            clients,
            rewrites,
            start_time: std::time::Instant::now(),
            restore_tokens: Arc::new(Mutex::new(std::collections::HashMap::new())),
            master_coordinator: None,
            slave_tracker: None,
            resync_sender: None,
            setup_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            dns_starter: None,
        }
    }

    fn operator() -> RequireOperator {
        RequireOperator(AuthUser {
            username: "operator".to_string(),
            role: Role::Operator,
            token_id: None,
        })
    }

    #[tokio::test]
    async fn test_stable_ids_survive_delete_and_update() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_rewrite_ids_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ctx = mock_context(&temp_dir).await;

        let a = add_rewrite(
            operator(),
            State(ctx.clone()),
            Json(AddRewriteRequest {
                domain: "a.lan".to_string(),
                record_type: "A".to_string(),
                answer: "10.0.0.1".to_string(),
                exception_clients: Vec::new(),
            }),
        )
        .await
        .unwrap()
        .0;
        let b = add_rewrite(
            operator(),
            State(ctx.clone()),
            Json(AddRewriteRequest {
                domain: "b.lan".to_string(),
                record_type: "A".to_string(),
                answer: "10.0.0.2".to_string(),
                exception_clients: Vec::new(),
            }),
        )
        .await
        .unwrap()
        .0;

        // Delete the first entry: the second entry's id must keep working.
        let _removed = delete_rewrite(operator(), State(ctx.clone()), Path(a.id.clone()))
            .await
            .unwrap();

        let updated = update_rewrite(
            operator(),
            State(ctx.clone()),
            Path(b.id.clone()),
            Json(AddRewriteRequest {
                domain: "b.lan".to_string(),
                record_type: "A".to_string(),
                answer: "10.0.0.99".to_string(),
                exception_clients: Vec::new(),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(updated.id, b.id);
        assert_eq!(updated.answer, "10.0.0.99");

        let list = get_rewrites(operator(), State(ctx.clone())).await.0;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].domain, "b.lan");
        assert_eq!(list[0].answer, "10.0.0.99");
        assert_eq!(list[0].id, b.id);

        // Stable ids persist across a fresh load (and thus across restarts).
        let reloaded = load_rewrite_store(&ctx);
        assert_eq!(reloaded.ids, vec![b.id.clone()]);

        // Legacy numeric index still resolves.
        assert_eq!(resolve_rewrite_index(&reloaded, "0"), Some(0));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
