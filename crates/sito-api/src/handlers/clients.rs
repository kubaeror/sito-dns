//! Client and group management endpoints per section 12.1.
//!
//! Updates are partial: fields that are absent from the JSON body retain their
//! current values. Identifier lists are only replaced when at least one of the
//! `ip`/`mac`/`subnet`/`doh_path`/`dot_sni` fields is supplied.

use crate::auth::RequireOperator;
use crate::config_writer::save_config_atomic;
use crate::error::ProblemDetails;
use crate::models::{
    ClientDto, ClientGroupDto, GenericMessageResponse, UpdateClientGroupRequest,
    UpdateClientRequest,
};
use crate::state::ServerContext;
use axum::Json;
use axum::extract::{Path, State};
use sito_clients::{BlockedServiceConfig, ClientEntryConfig, ClientGroupConfig, ClientsConfig};

fn load_clients_config(ctx: &ServerContext) -> ClientsConfig {
    ctx.config
        .load()
        .clients
        .as_ref()
        .and_then(|v| v.clone().try_into().ok())
        .unwrap_or_default()
}

async fn save_clients_config(
    ctx: &ServerContext,
    clients_cfg: &ClientsConfig,
) -> Result<(), ProblemDetails> {
    let mut new_cfg = (**ctx.config.load()).clone();
    let val = toml::Value::try_from(clients_cfg).map_err(|e| {
        ProblemDetails::internal_error(format!("Failed to serialize clients config: {e}"))
    })?;
    new_cfg.clients = Some(val);

    save_config_atomic(&ctx.config_path, &new_cfg).await?;
    ctx.set_config(new_cfg);

    // Update active registry
    let new_reg = sito_clients::ClientRegistry::new(clients_cfg.clone());
    ctx.set_clients(new_reg);
    crate::publish_bundle(ctx);
    Ok(())
}

/// Identifier buckets returned by [`classify_ids`]: ip, mac, subnet, DoH
/// path and DoT SNI.
type ClassifiedIds = (
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Option<String>,
    Option<String>,
);

/// Splits stored identifiers into their DTO buckets. The DoH path is checked
/// before generic subnets so `/dns-query` is not misclassified.
fn classify_ids(ids: Vec<String>) -> ClassifiedIds {
    let mut ip = Vec::new();
    let mut mac = Vec::new();
    let mut subnet = Vec::new();
    let mut doh_path = None;
    let mut dot_sni = None;

    for id in ids {
        if id.starts_with('/') {
            doh_path = Some(id);
        } else if id.contains('/') {
            subnet.push(id);
        } else if id.contains(':') && id.len() == 17 {
            mac.push(id);
        } else if id.contains('.') && id.chars().any(char::is_alphabetic) {
            dot_sni = Some(id);
        } else {
            ip.push(id);
        }
    }

    (ip, mac, subnet, doh_path, dot_sni)
}

fn build_ids(
    ip: &[String],
    mac: &[String],
    subnet: &[String],
    doh_path: Option<&String>,
    dot_sni: Option<&String>,
) -> Vec<String> {
    let mut ids = Vec::new();
    ids.extend(ip.iter().cloned());
    ids.extend(mac.iter().cloned());
    ids.extend(subnet.iter().cloned());
    if let Some(path) = doh_path {
        ids.push(path.clone());
    }
    if let Some(sni) = dot_sni {
        ids.push(sni.clone());
    }
    ids
}

fn client_to_dto(entry: &ClientEntryConfig, secret: Option<&String>) -> ClientDto {
    let (ip, mac, subnet, legacy_doh_path, dot_sni) = classify_ids(entry.ids.clone());
    ClientDto {
        name: entry.name.clone(),
        ip,
        mac,
        subnet,
        group: entry.group.clone(),
        // The shared secret is the only path/SNI identity accepted by the
        // registry; legacy path identifiers stored in `ids` are only shown.
        doh_path: secret.cloned().or(legacy_doh_path),
        dot_sni,
        ignore_query_log: entry.ignore_query_log,
        ignore_stats: entry.ignore_stats,
        use_global_upstreams: Some(entry.use_global_upstreams),
        upstreams: entry.upstreams.clone(),
        trusted: Some(entry.trusted),
    }
}

/// Rejects a shared secret already assigned to another client entry.
fn ensure_secret_available(
    cfg: &sito_clients::ClientsConfig,
    entry_name: &str,
    secret: &str,
) -> Result<(), ProblemDetails> {
    for (name, existing) in &cfg.client_id_secrets {
        if name != entry_name && existing == secret {
            return Err(ProblemDetails::conflict(format!(
                "Client ID secret is already used by client '{name}'"
            )));
        }
    }
    Ok(())
}

/// Extracts the shared secret from the DTO's `doh_path`/`dot_sni` inputs.
fn payload_secret(doh_path: Option<&String>, dot_sni: Option<&String>) -> Option<String> {
    doh_path
        .or(dot_sni)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn group_to_dto(name: &str, group: &ClientGroupConfig) -> ClientGroupDto {
    ClientGroupDto {
        name: name.to_string(),
        description: group.description.clone(),
        filtering_enabled: group.filtering,
        parental_control: group.parental,
        safe_search: group.safe_search,
        blocked_services: group
            .blocked_services
            .iter()
            .map(|b| b.service.clone())
            .collect(),
        parental_categories: group.parental_categories.clone(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/clients",
    responses(
        (status = 200, description = "Clients list retrieved", body = Vec<ClientDto>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
pub async fn get_clients(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
) -> Json<Vec<ClientDto>> {
    let cfg = load_clients_config(&ctx);
    Json(
        cfg.entries
            .iter()
            .map(|entry| client_to_dto(entry, cfg.client_id_secrets.get(&entry.name)))
            .collect(),
    )
}

#[utoipa::path(
    post,
    path = "/api/v1/clients",
    request_body = ClientDto,
    responses(
        (status = 200, description = "Client created", body = ClientDto),
        (status = 400, description = "Bad Request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
pub async fn create_client(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Json(payload): Json<ClientDto>,
) -> Result<Json<ClientDto>, ProblemDetails> {
    let mut cfg = load_clients_config(&ctx);
    if cfg.entries.iter().any(|c| c.name == payload.name) {
        return Err(ProblemDetails::conflict(format!(
            "Client '{}' already exists",
            payload.name
        )));
    }

    let secret = payload_secret(payload.doh_path.as_ref(), payload.dot_sni.as_ref());
    let ids = build_ids(&payload.ip, &payload.mac, &payload.subnet, None, None);

    let entry = ClientEntryConfig {
        name: payload.name.clone(),
        ids,
        group: payload.group.clone(),
        ignore_query_log: payload.ignore_query_log,
        ignore_stats: payload.ignore_stats,
        use_global_upstreams: payload.use_global_upstreams.unwrap_or(true),
        upstreams: payload.upstreams.clone(),
        trusted: payload.trusted.unwrap_or(false),
    };

    if let Some(ref secret) = secret {
        ensure_secret_available(&cfg, &entry.name, secret)?;
        cfg.client_id_secrets
            .insert(entry.name.clone(), secret.clone());
    }

    cfg.entries.push(entry.clone());
    save_clients_config(&ctx, &cfg).await?;
    Ok(Json(client_to_dto(
        &entry,
        cfg.client_id_secrets.get(&entry.name),
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/clients/{name}",
    params(("name" = String, Path, description = "Client name")),
    responses(
        (status = 200, description = "Client details retrieved", body = ClientDto),
        (status = 404, description = "Not Found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
#[allow(clippy::unused_async)]
pub async fn get_client_by_name(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(name): Path<String>,
) -> Result<Json<ClientDto>, ProblemDetails> {
    let cfg = load_clients_config(&ctx);
    let Some(c) = cfg.entries.iter().find(|e| e.name == name) else {
        return Err(ProblemDetails::not_found(format!(
            "Client '{name}' not found"
        )));
    };

    Ok(Json(client_to_dto(c, cfg.client_id_secrets.get(&c.name))))
}

#[utoipa::path(
    put,
    path = "/api/v1/clients/{name}",
    request_body = UpdateClientRequest,
    params(("name" = String, Path, description = "Client name")),
    responses(
        (status = 200, description = "Client updated (partial merge)", body = ClientDto),
        (status = 404, description = "Not Found"),
        (status = 409, description = "Renaming onto an existing client name"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
pub async fn update_client(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(name): Path<String>,
    Json(payload): Json<UpdateClientRequest>,
) -> Result<Json<ClientDto>, ProblemDetails> {
    let mut cfg = load_clients_config(&ctx);
    let Some(pos) = cfg.entries.iter().position(|e| e.name == name) else {
        return Err(ProblemDetails::not_found(format!(
            "Client '{name}' not found"
        )));
    };
    let existing = cfg.entries[pos].clone();

    let new_name = payload
        .name
        .clone()
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| existing.name.clone());
    if new_name != name && cfg.entries.iter().any(|c| c.name == new_name) {
        return Err(ProblemDetails::conflict(format!(
            "Client '{new_name}' already exists"
        )));
    }

    let replace_ids = !payload.ip.is_empty()
        || !payload.mac.is_empty()
        || !payload.subnet.is_empty()
        || payload.doh_path.is_some()
        || payload.dot_sni.is_some();
    let secret_input = payload_secret(payload.doh_path.as_ref(), payload.dot_sni.as_ref());
    let ids = if replace_ids {
        build_ids(&payload.ip, &payload.mac, &payload.subnet, None, None)
    } else {
        existing.ids.clone()
    };

    let entry = ClientEntryConfig {
        name: new_name.clone(),
        ids,
        group: payload
            .group
            .clone()
            .unwrap_or_else(|| existing.group.clone()),
        ignore_query_log: payload
            .ignore_query_log
            .unwrap_or(existing.ignore_query_log),
        ignore_stats: payload.ignore_stats.unwrap_or(existing.ignore_stats),
        use_global_upstreams: payload
            .use_global_upstreams
            .unwrap_or(existing.use_global_upstreams),
        upstreams: payload.upstreams.clone().or(existing.upstreams.clone()),
        trusted: payload.trusted.unwrap_or(existing.trusted),
    };

    // Keep the shared secret in sync: renames carry it over, replacing the
    // identifier lists sets or clears it, partial updates leave it untouched.
    let mut secret = cfg.client_id_secrets.remove(&name);
    if replace_ids {
        secret = secret_input;
    }
    if let Some(secret) = secret {
        ensure_secret_available(&cfg, &new_name, &secret)?;
        cfg.client_id_secrets.insert(new_name.clone(), secret);
    }

    cfg.entries[pos] = entry.clone();
    save_clients_config(&ctx, &cfg).await?;
    Ok(Json(client_to_dto(
        &entry,
        cfg.client_id_secrets.get(&entry.name),
    )))
}

#[utoipa::path(
    delete,
    path = "/api/v1/clients/{name}",
    params(("name" = String, Path, description = "Client name")),
    responses(
        (status = 200, description = "Client deleted", body = GenericMessageResponse),
        (status = 404, description = "Not Found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
pub async fn delete_client(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(name): Path<String>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    let mut cfg = load_clients_config(&ctx);
    let Some(pos) = cfg.entries.iter().position(|e| e.name == name) else {
        return Err(ProblemDetails::not_found(format!(
            "Client '{name}' not found"
        )));
    };

    cfg.entries.remove(pos);
    cfg.client_id_secrets.remove(&name);
    save_clients_config(&ctx, &cfg).await?;
    Ok(Json(GenericMessageResponse {
        message: format!("Client '{name}' deleted successfully"),
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/clients/groups",
    responses(
        (status = 200, description = "Client groups retrieved", body = Vec<ClientGroupDto>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
pub async fn get_client_groups(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
) -> Json<Vec<ClientGroupDto>> {
    let cfg = load_clients_config(&ctx);
    let mut groups = Vec::new();

    // Always include default group if not explicitly defined
    if !cfg.groups.contains_key("default") {
        groups.push(ClientGroupDto {
            name: "default".to_string(),
            description: Some("Default policy group".to_string()),
            filtering_enabled: true,
            parental_control: false,
            safe_search: false,
            blocked_services: Vec::new(),
            parental_categories: Vec::new(),
        });
    }

    for (name, g) in cfg.groups {
        groups.push(group_to_dto(&name, &g));
    }

    Json(groups)
}

#[utoipa::path(
    get,
    path = "/api/v1/clients/groups/{name}",
    params(("name" = String, Path, description = "Group name")),
    responses(
        (status = 200, description = "Client group retrieved", body = ClientGroupDto),
        (status = 404, description = "Not Found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
#[allow(clippy::unused_async)]
pub async fn get_client_group_by_name(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(name): Path<String>,
) -> Result<Json<ClientGroupDto>, ProblemDetails> {
    let cfg = load_clients_config(&ctx);
    if name == "default" && !cfg.groups.contains_key("default") {
        return Ok(Json(ClientGroupDto {
            name: "default".to_string(),
            description: Some("Default policy group".to_string()),
            filtering_enabled: true,
            parental_control: false,
            safe_search: false,
            blocked_services: Vec::new(),
            parental_categories: Vec::new(),
        }));
    }

    let Some(g) = cfg.groups.get(&name) else {
        return Err(ProblemDetails::not_found(format!(
            "Group '{name}' not found"
        )));
    };

    Ok(Json(group_to_dto(&name, g)))
}

#[utoipa::path(
    put,
    path = "/api/v1/clients/groups/{name}",
    request_body = UpdateClientGroupRequest,
    params(("name" = String, Path, description = "Group name")),
    responses(
        (status = 200, description = "Client group updated (partial merge; fields absent keep current values)", body = ClientGroupDto),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
pub async fn update_client_group(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(name): Path<String>,
    Json(payload): Json<UpdateClientGroupRequest>,
) -> Result<Json<ClientGroupDto>, ProblemDetails> {
    let mut cfg = load_clients_config(&ctx);
    let existing = cfg.groups.get(&name).cloned().unwrap_or_default();

    let blocked_services = match payload.blocked_services {
        Some(services) => services
            .iter()
            .map(|service| {
                // Preserve an existing per-service schedule when the service
                // remains in the list.
                let schedule = existing
                    .blocked_services
                    .iter()
                    .find(|b| &b.service == service)
                    .and_then(|b| b.schedule.clone());
                BlockedServiceConfig {
                    service: service.clone(),
                    schedule,
                }
            })
            .collect(),
        None => existing.blocked_services.clone(),
    };

    let group = ClientGroupConfig {
        description: payload.description.or_else(|| existing.description.clone()),
        filtering: payload.filtering_enabled.unwrap_or(existing.filtering),
        lists: payload.lists.unwrap_or_else(|| existing.lists.clone()),
        custom_rules: payload
            .custom_rules
            .unwrap_or_else(|| existing.custom_rules.clone()),
        safe_search: payload.safe_search.unwrap_or(existing.safe_search),
        // Not exposed in the partial-update DTO: always preserved.
        safe_search_youtube: existing.safe_search_youtube,
        parental: payload.parental_control.unwrap_or(existing.parental),
        parental_categories: payload
            .parental_categories
            .unwrap_or_else(|| existing.parental_categories.clone()),
        schedule_enabled: payload
            .schedule_enabled
            .unwrap_or(existing.schedule_enabled),
        // Not exposed in the partial-update DTO: always preserved.
        schedule: existing.schedule.clone(),
        blocked_services,
    };

    cfg.groups.insert(name.clone(), group.clone());
    save_clients_config(&ctx, &cfg).await?;
    Ok(Json(group_to_dto(&name, &group)))
}

#[utoipa::path(
    post,
    path = "/api/v1/clients/groups",
    request_body = ClientGroupDto,
    responses(
        (status = 200, description = "Client group added", body = ClientGroupDto),
        (status = 400, description = "Group already exists"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
pub async fn add_client_group(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Json(payload): Json<ClientGroupDto>,
) -> Result<Json<ClientGroupDto>, ProblemDetails> {
    let mut cfg = load_clients_config(&ctx);
    if cfg.groups.contains_key(&payload.name) {
        return Err(ProblemDetails::bad_request(format!(
            "Group '{}' already exists",
            payload.name
        )));
    }
    let group = ClientGroupConfig {
        description: payload.description.clone(),
        filtering: payload.filtering_enabled,
        lists: Vec::new(),
        custom_rules: Vec::new(),
        safe_search: payload.safe_search,
        safe_search_youtube: None,
        parental: payload.parental_control,
        parental_categories: payload.parental_categories.clone(),
        schedule_enabled: false,
        schedule: None,
        blocked_services: payload
            .blocked_services
            .iter()
            .map(|s| BlockedServiceConfig {
                service: s.clone(),
                schedule: None,
            })
            .collect(),
    };
    cfg.groups.insert(payload.name.clone(), group.clone());
    save_clients_config(&ctx, &cfg).await?;
    Ok(Json(group_to_dto(&payload.name, &group)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/clients/groups/{name}",
    params(("name" = String, Path, description = "Group name")),
    responses(
        (status = 200, description = "Client group deleted", body = crate::models::GenericMessageResponse),
        (status = 404, description = "Group not found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
pub async fn delete_client_group(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(name): Path<String>,
) -> Result<Json<crate::models::GenericMessageResponse>, ProblemDetails> {
    if name == "default" {
        return Err(ProblemDetails::bad_request(
            "Cannot delete the default group",
        ));
    }
    let mut cfg = load_clients_config(&ctx);
    if cfg.groups.remove(&name).is_some() {
        save_clients_config(&ctx, &cfg).await?;
        Ok(Json(crate::models::GenericMessageResponse {
            message: format!("Group '{name}' deleted successfully"),
        }))
    } else {
        Err(ProblemDetails::not_found(format!(
            "Group '{name}' not found"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthUser;
    use crate::auth::token::Role;
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
    async fn test_partial_update_preserves_fields_and_rejects_duplicate_rename() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_clients_partial_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ctx = mock_context(&temp_dir).await;

        // Seed two clients directly in the config.
        let mut cfg = load_clients_config(&ctx);
        cfg.entries.push(ClientEntryConfig {
            name: "alpha".to_string(),
            ids: vec!["10.0.0.5".to_string(), "/dns-query".to_string()],
            group: "kids".to_string(),
            ignore_query_log: true,
            ignore_stats: false,
            use_global_upstreams: false,
            upstreams: Some(vec!["9.9.9.9".to_string()]),
            trusted: true,
        });
        cfg.entries.push(ClientEntryConfig {
            name: "beta".to_string(),
            ids: vec!["10.0.0.6".to_string()],
            group: "default".to_string(),
            ignore_query_log: false,
            ignore_stats: false,
            use_global_upstreams: true,
            upstreams: None,
            trusted: false,
        });
        save_clients_config(&ctx, &cfg).await.unwrap();

        // Partial update that only toggles ignore_stats: everything else kept.
        let updated = update_client(
            operator(),
            State(ctx.clone()),
            Path("alpha".to_string()),
            Json(UpdateClientRequest {
                ignore_stats: Some(true),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .0;
        assert!(updated.ignore_stats);
        assert!(updated.ignore_query_log);
        assert_eq!(updated.group, "kids");
        assert_eq!(updated.use_global_upstreams, Some(false));
        assert_eq!(updated.upstreams, Some(vec!["9.9.9.9".to_string()]));
        assert_eq!(updated.trusted, Some(true));
        assert_eq!(updated.ip, vec!["10.0.0.5"]);
        // DoH path is classified correctly (previously unreachable).
        assert_eq!(updated.doh_path, Some("/dns-query".to_string()));
        assert!(updated.subnet.is_empty());

        // Renaming onto an existing name is rejected.
        let conflict = update_client(
            operator(),
            State(ctx.clone()),
            Path("alpha".to_string()),
            Json(UpdateClientRequest {
                name: Some("beta".to_string()),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(conflict.status, 409);
    }

    #[tokio::test]
    async fn test_client_id_secrets_are_written_and_enforced() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_clients_secret_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ctx = mock_context(&temp_dir).await;

        let dto = |name: &str, secret: Option<&str>| ClientDto {
            name: name.to_string(),
            ip: vec!["10.0.0.9".to_string()],
            mac: Vec::new(),
            subnet: Vec::new(),
            group: "default".to_string(),
            doh_path: secret.map(str::to_string),
            dot_sni: None,
            ignore_query_log: false,
            ignore_stats: false,
            use_global_upstreams: None,
            upstreams: None,
            trusted: None,
        };

        // The secret is trimmed, stored in client_id_secrets and never in ids.
        let created = create_client(
            operator(),
            State(ctx.clone()),
            Json(dto("phone", Some("  super-secret  "))),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(created.doh_path.as_deref(), Some("super-secret"));
        let cfg = load_clients_config(&ctx);
        assert_eq!(
            cfg.client_id_secrets.get("phone").map(String::as_str),
            Some("super-secret")
        );
        assert!(!cfg.entries[0].ids.iter().any(|id| id.contains("secret")));

        // Reusing a secret for another entry is rejected.
        let conflict = create_client(
            operator(),
            State(ctx.clone()),
            Json(dto("other", Some("super-secret"))),
        )
        .await
        .unwrap_err();
        assert_eq!(conflict.status, 409);

        // Replacing identifiers without a secret clears it.
        let _ = update_client(
            operator(),
            State(ctx.clone()),
            Path("phone".to_string()),
            Json(UpdateClientRequest {
                ip: vec!["10.0.0.10".to_string()],
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert!(
            !load_clients_config(&ctx)
                .client_id_secrets
                .contains_key("phone")
        );

        // Setting it again and deleting removes the secret.
        let _ = update_client(
            operator(),
            State(ctx.clone()),
            Path("phone".to_string()),
            Json(UpdateClientRequest {
                doh_path: Some("second-secret".to_string()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert!(
            load_clients_config(&ctx)
                .client_id_secrets
                .contains_key("phone")
        );
        let _ = delete_client(operator(), State(ctx.clone()), Path("phone".to_string()))
            .await
            .unwrap();
        assert!(
            !load_clients_config(&ctx)
                .client_id_secrets
                .contains_key("phone")
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_group_update_preserves_unset_fields() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_group_partial_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ctx = mock_context(&temp_dir).await;

        let mut cfg = load_clients_config(&ctx);
        cfg.groups.insert(
            "kids".to_string(),
            ClientGroupConfig {
                description: Some("kids policy".to_string()),
                filtering: true,
                lists: vec!["OISD".to_string()],
                custom_rules: vec!["||x^".to_string()],
                safe_search: true,
                safe_search_youtube: None,
                parental: true,
                parental_categories: vec!["adult".to_string()],
                schedule_enabled: true,
                schedule: None,
                blocked_services: vec![BlockedServiceConfig {
                    service: "tiktok".to_string(),
                    schedule: None,
                }],
            },
        );
        save_clients_config(&ctx, &cfg).await.unwrap();

        // Only disable filtering; lists/rules/schedules must survive.
        let _unused = update_client_group(
            operator(),
            State(ctx.clone()),
            Path("kids".to_string()),
            Json(UpdateClientGroupRequest {
                filtering_enabled: Some(false),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let cfg = load_clients_config(&ctx);
        let group = cfg.groups.get("kids").unwrap();
        assert!(!group.filtering);
        assert_eq!(group.lists, vec!["OISD"]);
        assert_eq!(group.custom_rules, vec!["||x^"]);
        assert!(group.safe_search);
        assert!(group.parental);
        assert_eq!(group.parental_categories, vec!["adult"]);
        assert!(group.schedule_enabled);
        assert_eq!(
            group.description.as_deref(),
            Some("kids policy"),
            "description must survive a partial update"
        );
        assert_eq!(group.blocked_services.len(), 1);
        assert_eq!(group.blocked_services[0].service, "tiktok");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_classify_ids_prioritizes_doh_path() {
        let (ip, mac, subnet, doh_path, dot_sni) = classify_ids(vec![
            "10.0.0.1".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            "10.0.0.0/24".to_string(),
            "/dns-query".to_string(),
            "resolver.example".to_string(),
        ]);
        assert_eq!(ip, vec!["10.0.0.1"]);
        assert_eq!(mac, vec!["AA:BB:CC:DD:EE:FF"]);
        assert_eq!(subnet, vec!["10.0.0.0/24"]);
        assert_eq!(doh_path, Some("/dns-query".to_string()));
        assert_eq!(dot_sni, Some("resolver.example".to_string()));
    }
}
