//! Client and group management endpoints per section 12.1.

use crate::auth::RequireOperator;
use crate::config_writer::save_config_atomic;
use crate::error::ProblemDetails;
use crate::models::{ClientDto, ClientGroupDto, GenericMessageResponse};
use crate::state::ServerContext;
use axum::Json;
use axum::extract::{Path, State};
use sito_clients::{ClientEntryConfig, ClientGroupConfig, ClientsConfig};
use std::sync::Arc;

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
    ctx.config.store(Arc::new(new_cfg));

    // Update active registry
    let new_registry = sito_clients::ClientRegistry::new(clients_cfg.clone());
    ctx.clients.store(Arc::new(new_registry));
    Ok(())
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
    let dtos = cfg
        .entries
        .into_iter()
        .map(|c| {
            let mut ip = Vec::new();
            let mut mac = Vec::new();
            let mut subnet = Vec::new();
            let mut doh_path = None;
            let mut dot_sni = None;

            for id in c.ids {
                if id.contains('/') {
                    subnet.push(id);
                } else if id.contains(':') && id.len() == 17 {
                    mac.push(id);
                } else if id.starts_with('/') {
                    doh_path = Some(id);
                } else if id.contains('.') && id.chars().any(char::is_alphabetic) {
                    dot_sni = Some(id);
                } else {
                    ip.push(id);
                }
            }

            ClientDto {
                name: c.name,
                ip,
                mac,
                subnet,
                group: c.group,
                doh_path,
                dot_sni,
                ignore_query_log: c.ignore_query_log,
                ignore_stats: c.ignore_stats,
            }
        })
        .collect();
    Json(dtos)
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

    let mut ids = Vec::new();
    ids.extend(payload.ip.clone());
    ids.extend(payload.mac.clone());
    ids.extend(payload.subnet.clone());
    if let Some(ref p) = payload.doh_path {
        ids.push(p.clone());
    }
    if let Some(ref s) = payload.dot_sni {
        ids.push(s.clone());
    }

    let entry = ClientEntryConfig {
        name: payload.name.clone(),
        ids,
        group: payload.group.clone(),
        ignore_query_log: payload.ignore_query_log,
        ignore_stats: payload.ignore_stats,
        use_global_upstreams: true,
        upstreams: None,
        trusted: false,
    };

    cfg.entries.push(entry);
    save_clients_config(&ctx, &cfg).await?;
    Ok(Json(payload))
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
    let Some(c) = cfg.entries.into_iter().find(|e| e.name == name) else {
        return Err(ProblemDetails::not_found(format!(
            "Client '{name}' not found"
        )));
    };

    let mut ip = Vec::new();
    let mut mac = Vec::new();
    let mut subnet = Vec::new();
    let mut doh_path = None;
    let mut dot_sni = None;

    for id in c.ids {
        if id.contains('/') {
            subnet.push(id);
        } else if id.contains(':') && id.len() == 17 {
            mac.push(id);
        } else if id.starts_with('/') {
            doh_path = Some(id);
        } else if id.contains('.') && id.chars().any(char::is_alphabetic) {
            dot_sni = Some(id);
        } else {
            ip.push(id);
        }
    }

    Ok(Json(ClientDto {
        name: c.name,
        ip,
        mac,
        subnet,
        group: c.group,
        doh_path,
        dot_sni,
        ignore_query_log: c.ignore_query_log,
        ignore_stats: c.ignore_stats,
    }))
}

#[utoipa::path(
    put,
    path = "/api/v1/clients/{name}",
    request_body = ClientDto,
    params(("name" = String, Path, description = "Client name")),
    responses(
        (status = 200, description = "Client updated", body = ClientDto),
        (status = 404, description = "Not Found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
pub async fn update_client(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(name): Path<String>,
    Json(payload): Json<ClientDto>,
) -> Result<Json<ClientDto>, ProblemDetails> {
    let mut cfg = load_clients_config(&ctx);
    let Some(pos) = cfg.entries.iter().position(|e| e.name == name) else {
        return Err(ProblemDetails::not_found(format!(
            "Client '{name}' not found"
        )));
    };

    let mut ids = Vec::new();
    ids.extend(payload.ip.clone());
    ids.extend(payload.mac.clone());
    ids.extend(payload.subnet.clone());
    if let Some(ref p) = payload.doh_path {
        ids.push(p.clone());
    }
    if let Some(ref s) = payload.dot_sni {
        ids.push(s.clone());
    }

    cfg.entries[pos] = ClientEntryConfig {
        name: payload.name.clone(),
        ids,
        group: payload.group.clone(),
        ignore_query_log: payload.ignore_query_log,
        ignore_stats: payload.ignore_stats,
        use_global_upstreams: true,
        upstreams: None,
        trusted: false,
    };

    save_clients_config(&ctx, &cfg).await?;
    Ok(Json(payload))
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
        groups.push(ClientGroupDto {
            name,
            description: None,
            filtering_enabled: g.filtering,
            parental_control: g.parental,
            safe_search: g.safe_search,
            blocked_services: g.blocked_services.into_iter().map(|b| b.service).collect(),
            parental_categories: g.parental_categories,
        });
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

    Ok(Json(ClientGroupDto {
        name,
        description: None,
        filtering_enabled: g.filtering,
        parental_control: g.parental,
        safe_search: g.safe_search,
        blocked_services: g
            .blocked_services
            .iter()
            .map(|b| b.service.clone())
            .collect(),
        parental_categories: g.parental_categories.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/v1/clients/groups/{name}",
    request_body = ClientGroupDto,
    params(("name" = String, Path, description = "Group name")),
    responses(
        (status = 200, description = "Client group updated", body = ClientGroupDto),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
pub async fn update_client_group(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(name): Path<String>,
    Json(payload): Json<ClientGroupDto>,
) -> Result<Json<ClientGroupDto>, ProblemDetails> {
    let mut cfg = load_clients_config(&ctx);

    let group = ClientGroupConfig {
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
            .map(|s| sito_clients::BlockedServiceConfig {
                service: s.clone(),
                schedule: None,
            })
            .collect(),
    };

    cfg.groups.insert(name, group);
    save_clients_config(&ctx, &cfg).await?;
    Ok(Json(payload))
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
            .map(|s| sito_clients::BlockedServiceConfig {
                service: s.clone(),
                schedule: None,
            })
            .collect(),
    };
    cfg.groups.insert(payload.name.clone(), group);
    save_clients_config(&ctx, &cfg).await?;
    Ok(Json(payload))
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
