//! Client and group management endpoints per section 12.1.
//!
//! Updates are partial: fields that are absent from the JSON body retain their
//! current values. Identifier lists are only replaced when at least one of the
//! `ip`/`mac`/`subnet`/`doh_path`/`dot_sni` fields is supplied.

use crate::auth::RequireOperator;
use crate::auth::token::Role;
use crate::config_apply::{
    ApplyHooks, ConfigApplyHooks, FilterApply, apply_and_persist_config_locked,
};
use crate::error::ProblemDetails;
use crate::models::{
    ClientDto, ClientGroupDto, GenericMessageResponse, UnidentifiedClientDto,
    UnidentifiedClientsResponse, UpdateClientGroupRequest, UpdateClientRequest,
};
use crate::state::ServerContext;
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use serde::Deserialize;
use sito_clients::{BlockedServiceConfig, ClientEntryConfig, ClientGroupConfig, ClientsConfig};

/// Query parameters for the client detail endpoint.
#[derive(Debug, Clone, Default, Deserialize, utoipa::IntoParams)]
pub struct ClientRevealQuery {
    /// `1`/`true` reveals the stored shared secret. Admin-only and audited.
    #[serde(default)]
    pub reveal: Option<String>,
}

impl ClientRevealQuery {
    fn wants_reveal(&self) -> bool {
        self.reveal.as_deref().is_some_and(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
        })
    }
}

/// Query parameters for the discovered-client list.
#[derive(Debug, Clone, Default, Deserialize, utoipa::IntoParams)]
pub struct UnidentifiedClientsQuery {
    /// Maximum number of newest entries to return (default 100, clamped to
    /// the registry bound).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Default page size for the discovered-client list (also the web UI cap).
pub(crate) const DEFAULT_UNIDENTIFIED_LIMIT: usize = 100;

fn load_clients_config(ctx: &ServerContext) -> ClientsConfig {
    ctx.config
        .load()
        .clients
        .as_ref()
        .and_then(|v| v.clone().try_into().ok())
        .unwrap_or_default()
}

/// Applies and persists a clients update. The caller **must** hold
/// [`ServerContext::apply_lock`] (see [`ServerContext::lock_config_apply`]) and
/// must have read the current config after acquiring it.
async fn save_clients_config_locked(
    ctx: &ServerContext,
    clients_cfg: &ClientsConfig,
    hooks: Option<&dyn ConfigApplyHooks>,
) -> Result<(), ProblemDetails> {
    let mut new_cfg = (**ctx.config.load()).clone();
    let val = toml::Value::try_from(clients_cfg).map_err(|e| {
        ProblemDetails::internal_error(format!("Failed to serialize clients config: {e}"))
    })?;
    new_cfg.clients = Some(val);

    // `apply_inner` rebuilds the registry with the shared RouterOS lease and
    // discovered-client stores, so unidentified clients survive the save.
    apply_and_persist_config_locked(ctx, &new_cfg, FilterApply::Deferred, hooks).await?;
    Ok(())
}

/// Test-only convenience wrapper that acquires the apply lock itself.
#[cfg(test)]
async fn save_clients_config(
    ctx: &ServerContext,
    clients_cfg: &ClientsConfig,
) -> Result<(), ProblemDetails> {
    let _apply_guard = ctx.lock_config_apply().await;
    save_clients_config_locked(ctx, clients_cfg, None).await
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

/// Marker returned in place of a stored shared secret.
pub const SECRET_MASK: &str = "***";

/// True when a value is the masked marker (optionally followed by a hint).
fn is_secret_mask(value: &str) -> bool {
    value.trim_start().starts_with(SECRET_MASK)
}

/// Masked hint for a stored secret: marker plus its last four characters.
fn secret_hint(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 4 {
        SECRET_MASK.to_string()
    } else {
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("{SECRET_MASK}{tail}")
    }
}

fn client_to_dto(entry: &ClientEntryConfig, secret: Option<&String>, reveal: bool) -> ClientDto {
    let (ip, mac, subnet, legacy_doh_path, dot_sni) = classify_ids(entry.ids.clone());
    let (doh_path, has_secret, secret_hint) = match secret {
        Some(secret) if reveal => (Some(secret.clone()), true, None),
        Some(secret) => (None, true, Some(secret_hint(secret))),
        // Legacy path identifiers stored in `ids` are only shown; the shared
        // secret is the only path/SNI identity accepted by the registry.
        None => (legacy_doh_path, false, None),
    };
    ClientDto {
        name: entry.name.clone(),
        ip,
        mac,
        subnet,
        group: entry.group.clone(),
        doh_path,
        dot_sni,
        ignore_query_log: entry.ignore_query_log,
        ignore_stats: entry.ignore_stats,
        use_global_upstreams: Some(entry.use_global_upstreams),
        upstreams: entry.upstreams.clone(),
        trusted: Some(entry.trusted),
        has_secret,
        secret_hint,
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
/// Masked values (`***...`) are treated as "not supplied" so a GET→PUT
/// round-trip cannot overwrite the stored secret with a marker.
fn payload_secret(doh_path: Option<&String>, dot_sni: Option<&String>) -> Option<String> {
    doh_path
        .or(dot_sni)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !is_secret_mask(s))
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
            .map(|entry| client_to_dto(entry, cfg.client_id_secrets.get(&entry.name), false))
            .collect(),
    )
}

#[utoipa::path(
    get,
    path = "/api/v1/clients/unidentified",
    params(UnidentifiedClientsQuery),
    responses(
        (status = 200, description = "Discovered but unconfigured clients, newest first", body = UnidentifiedClientsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
pub async fn get_unidentified_clients(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Query(query): Query<UnidentifiedClientsQuery>,
) -> Json<UnidentifiedClientsResponse> {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_UNIDENTIFIED_LIMIT)
        .clamp(1, sito_clients::MAX_UNIDENTIFIED_CLIENTS);
    let clients = ctx
        .clients
        .load()
        .unidentified_clients()
        .into_iter()
        .take(limit)
        .map(|client| UnidentifiedClientDto {
            ip: client.ip.to_string(),
            mac: client.mac,
            hostname: client.hostname,
            comment: client.comment,
            last_seen: client.last_seen.to_rfc3339(),
        })
        .collect();

    Json(UnidentifiedClientsResponse {
        clients,
        max_entries: sito_clients::MAX_UNIDENTIFIED_CLIENTS,
        retention_hours: sito_clients::UNIDENTIFIED_CLIENT_TTL_HOURS,
    })
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
    Extension(hooks): Extension<ApplyHooks>,
    Json(payload): Json<ClientDto>,
) -> Result<Json<ClientDto>, ProblemDetails> {
    let _apply_guard = ctx.lock_config_apply().await;
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
    save_clients_config_locked(&ctx, &cfg, hooks.as_dyn()).await?;
    Ok(Json(client_to_dto(
        &entry,
        cfg.client_id_secrets.get(&entry.name),
        false,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/clients/{name}",
    params(("name" = String, Path, description = "Client name"), ClientRevealQuery),
    responses(
        (status = 200, description = "Client details retrieved (shared secret replaced by a marker unless ?reveal=1)", body = ClientDto),
        (status = 403, description = "Revealing a secret requires the Admin role"),
        (status = 404, description = "Not Found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
#[allow(clippy::unused_async)]
pub async fn get_client_by_name(
    operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Path(name): Path<String>,
    Query(query): Query<ClientRevealQuery>,
) -> Result<Json<ClientDto>, ProblemDetails> {
    let reveal = query.wants_reveal();
    if reveal && operator.role < Role::Admin {
        return Err(ProblemDetails::forbidden(
            "Revealing a client shared secret requires the Admin role",
        ));
    }
    if reveal {
        tracing::warn!(
            actor = %operator.username,
            client = %name,
            "Client shared secret revealed via API"
        );
    }

    let cfg = load_clients_config(&ctx);
    let Some(c) = cfg.entries.iter().find(|e| e.name == name) else {
        return Err(ProblemDetails::not_found(format!(
            "Client '{name}' not found"
        )));
    };

    Ok(Json(client_to_dto(
        c,
        cfg.client_id_secrets.get(&c.name),
        reveal,
    )))
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
    Extension(hooks): Extension<ApplyHooks>,
    Path(name): Path<String>,
    Json(payload): Json<UpdateClientRequest>,
) -> Result<Json<ClientDto>, ProblemDetails> {
    let _apply_guard = ctx.lock_config_apply().await;
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

    let mask_echoed = |value: &Option<String>| value.as_deref().is_some_and(is_secret_mask);
    let doh_supplied = payload.doh_path.is_some() && !mask_echoed(&payload.doh_path);
    let sni_supplied = payload.dot_sni.is_some() && !mask_echoed(&payload.dot_sni);
    let replace_ids = !payload.ip.is_empty()
        || !payload.mac.is_empty()
        || !payload.subnet.is_empty()
        || doh_supplied
        || sni_supplied;
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
    save_clients_config_locked(&ctx, &cfg, hooks.as_dyn()).await?;
    Ok(Json(client_to_dto(
        &entry,
        cfg.client_id_secrets.get(&entry.name),
        false,
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
    Extension(hooks): Extension<ApplyHooks>,
    Path(name): Path<String>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    let _apply_guard = ctx.lock_config_apply().await;
    let mut cfg = load_clients_config(&ctx);
    let Some(pos) = cfg.entries.iter().position(|e| e.name == name) else {
        return Err(ProblemDetails::not_found(format!(
            "Client '{name}' not found"
        )));
    };

    cfg.entries.remove(pos);
    cfg.client_id_secrets.remove(&name);
    save_clients_config_locked(&ctx, &cfg, hooks.as_dyn()).await?;
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
    Extension(hooks): Extension<ApplyHooks>,
    Path(name): Path<String>,
    Json(payload): Json<UpdateClientGroupRequest>,
) -> Result<Json<ClientGroupDto>, ProblemDetails> {
    let _apply_guard = ctx.lock_config_apply().await;
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
    save_clients_config_locked(&ctx, &cfg, hooks.as_dyn()).await?;
    Ok(Json(group_to_dto(&name, &group)))
}

#[utoipa::path(
    post,
    path = "/api/v1/clients/groups",
    request_body = ClientGroupDto,
    responses(
        (status = 200, description = "Client group added", body = ClientGroupDto),
        (status = 409, description = "Group already exists", body = ProblemDetails),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Clients"
)]
pub async fn add_client_group(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Extension(hooks): Extension<ApplyHooks>,
    Json(payload): Json<ClientGroupDto>,
) -> Result<Json<ClientGroupDto>, ProblemDetails> {
    let _apply_guard = ctx.lock_config_apply().await;
    let mut cfg = load_clients_config(&ctx);
    if cfg.groups.contains_key(&payload.name) {
        return Err(ProblemDetails::conflict(format!(
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
    save_clients_config_locked(&ctx, &cfg, hooks.as_dyn()).await?;
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
    Extension(hooks): Extension<ApplyHooks>,
    Path(name): Path<String>,
) -> Result<Json<crate::models::GenericMessageResponse>, ProblemDetails> {
    if name == "default" {
        return Err(ProblemDetails::bad_request(
            "Cannot delete the default group",
        ));
    }
    let _apply_guard = ctx.lock_config_apply().await;
    let mut cfg = load_clients_config(&ctx);
    if cfg.groups.remove(&name).is_some() {
        save_clients_config_locked(&ctx, &cfg, hooks.as_dyn()).await?;
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
        let mut config = Config::default();
        config.filtering.enabled = false;
        let config_arc = Arc::new(ArcSwap::new(Arc::new(config.clone())));
        let filter = Arc::new(
            sito_filter::HostsFilterEngine::init(config.filtering, temp_dir.to_path_buf()).await,
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
            Arc::new(
                sito_clients::ParentalRegistry::try_bundled()
                    .expect("bundled parental lists must load"),
            ),
            Arc::new(
                sito_clients::ServiceRegistry::try_bundled().expect("bundled services must load"),
            ),
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
            apply_lock: Arc::new(tokio::sync::Mutex::new(())),
            master_coordinator: None,
            slave_tracker: None,
            resync_sender: None,
            setup_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            acme_challenges: None,
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

    /// An Operator extractor carrying the Admin role (the client-detail
    /// handler admits Operators and gates `?reveal=1` on `role >= Admin`).
    fn admin() -> RequireOperator {
        RequireOperator(AuthUser {
            username: "admin".to_string(),
            role: Role::Admin,
            token_id: None,
        })
    }

    fn seed_unidentified(
        ctx: &ServerContext,
        entries: &[(std::net::IpAddr, chrono::DateTime<chrono::Utc>)],
    ) {
        let registry = ctx.clients.load();
        for (ip, last_seen) in entries {
            registry.update_routeros_leases(vec![sito_clients::RouterOsLease {
                mac: "11:22:33:44:55:66".to_string(),
                ip: Some(*ip),
                hostname: Some(format!("host-{ip}")),
                comment: None,
            }]);
            let mut client = sito_core::client::ClientContext::new(*ip);
            let _ = registry.resolve(&mut client, registry.timezone().at_utc(*last_seen));
        }
    }

    #[tokio::test]
    async fn test_unidentified_clients_endpoint_newest_first_and_bounded() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito_clients_unidentified_{}",
            rand::random::<u64>()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ctx = mock_context(&temp_dir).await;

        let now = chrono::Utc::now();
        let older: std::net::IpAddr = "10.20.0.1".parse().unwrap();
        let newer: std::net::IpAddr = "10.20.0.2".parse().unwrap();
        seed_unidentified(
            &ctx,
            &[
                (older, now - chrono::TimeDelta::minutes(5)),
                (newer, now - chrono::TimeDelta::minutes(1)),
            ],
        );

        let response = get_unidentified_clients(
            operator(),
            State(ctx.clone()),
            Query(UnidentifiedClientsQuery { limit: Some(1) }),
        )
        .await
        .0;
        assert_eq!(response.clients.len(), 1, "the limit must bound the page");
        assert_eq!(response.clients[0].ip, newer.to_string());
        let expected_host = format!("host-{newer}");
        assert_eq!(
            response.clients[0].hostname.as_deref(),
            Some(expected_host.as_str())
        );

        // Newest-first when both are requested.
        let response = get_unidentified_clients(
            operator(),
            State(ctx.clone()),
            Query(UnidentifiedClientsQuery { limit: Some(10) }),
        )
        .await
        .0;
        assert_eq!(response.clients.len(), 2);
        assert_eq!(response.clients[0].ip, newer.to_string());
        assert_eq!(response.clients[1].ip, older.to_string());

        // An oversized limit is clamped instead of allocating the request.
        let response = get_unidentified_clients(
            operator(),
            State(ctx.clone()),
            Query(UnidentifiedClientsQuery {
                limit: Some(usize::MAX),
            }),
        )
        .await
        .0;
        assert_eq!(response.clients.len(), 2);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_unidentified_clients_response_reports_limits() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_clients_limits_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ctx = mock_context(&temp_dir).await;

        let response = get_unidentified_clients(
            operator(),
            State(ctx.clone()),
            Query(UnidentifiedClientsQuery::default()),
        )
        .await
        .0;
        assert_eq!(response.max_entries, sito_clients::MAX_UNIDENTIFIED_CLIENTS);
        assert_eq!(
            response.retention_hours,
            sito_clients::UNIDENTIFIED_CLIENT_TTL_HOURS
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_unidentified_clients_requires_operator() {
        use axum::extract::FromRequestParts;

        let temp_dir =
            std::env::temp_dir().join(format!("sito_clients_rbac_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ctx = mock_context(&temp_dir).await;
        let (_, token) = ctx
            .auth_mgr
            .create_token("viewer", Role::Viewer, None)
            .await
            .expect("token");

        let request = axum::http::Request::builder()
            .uri("/api/v1/clients/unidentified")
            .header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {}", token.token),
            )
            .body(())
            .unwrap();
        let (mut parts, ()) = request.into_parts();
        let err = <RequireOperator as FromRequestParts<ServerContext>>::from_request_parts(
            &mut parts, &ctx,
        )
        .await
        .expect_err("a Viewer must not list discovered clients");
        assert_eq!(err.status, 403);

        // Operators pass the same extractor.
        let (_, token) = ctx
            .auth_mgr
            .create_token("operator", Role::Operator, None)
            .await
            .expect("token");
        let request = axum::http::Request::builder()
            .uri("/api/v1/clients/unidentified")
            .header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {}", token.token),
            )
            .body(())
            .unwrap();
        let (mut parts, ()) = request.into_parts();
        assert!(
            <RequireOperator as FromRequestParts<ServerContext>>::from_request_parts(
                &mut parts, &ctx,
            )
            .await
            .is_ok()
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_client_reload_preserves_unidentified_clients() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_clients_reload_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ctx = mock_context(&temp_dir).await;

        let ip: std::net::IpAddr = "10.30.0.7".parse().unwrap();
        seed_unidentified(&ctx, &[(ip, chrono::Utc::now())]);
        assert_eq!(ctx.clients.load().unidentified_clients().len(), 1);

        // Saving clients replaces the registry; discovery must survive.
        let cfg = load_clients_config(&ctx);
        save_clients_config(&ctx, &cfg).await.unwrap();

        let list = ctx.clients.load().unidentified_clients();
        assert_eq!(list.len(), 1, "a clients reload must keep discovery data");
        assert_eq!(list[0].ip, ip);

        let _ = std::fs::remove_dir_all(&temp_dir);
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
            Extension(ApplyHooks::default()),
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
        assert!(
            updated.subnet.is_empty(),
            "DoH client must not carry a subnet: {:?}",
            updated.subnet
        );

        // Renaming onto an existing name is rejected.
        let conflict = update_client(
            operator(),
            State(ctx.clone()),
            Extension(ApplyHooks::default()),
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
            has_secret: false,
            secret_hint: None,
        };

        // The secret is trimmed, stored in client_id_secrets and never in ids.
        let created = create_client(
            operator(),
            State(ctx.clone()),
            Extension(ApplyHooks::default()),
            Json(dto("phone", Some("  super-secret  "))),
        )
        .await
        .unwrap()
        .0;
        // The response must not echo the plaintext secret.
        assert_eq!(created.doh_path, None);
        assert!(created.has_secret);
        assert_eq!(created.secret_hint.as_deref(), Some("***cret"));
        let cfg = load_clients_config(&ctx);
        assert_eq!(
            cfg.client_id_secrets.get("phone").map(String::as_str),
            Some("super-secret")
        );
        assert!(!cfg.entries[0].ids.iter().any(|id| id.contains("secret")));

        // GET must not leak the plaintext either; ?reveal=1 is Admin-only.
        let listed = get_clients(operator(), State(ctx.clone())).await.0;
        assert_eq!(listed[0].doh_path, None);
        assert!(listed[0].has_secret);
        let revealed = get_client_by_name(
            operator(),
            State(ctx.clone()),
            Path("phone".to_string()),
            Query(ClientRevealQuery {
                reveal: Some("1".to_string()),
            }),
        )
        .await
        .expect_err("Operator must not be able to reveal a secret");
        assert_eq!(revealed.status, 403);
        let revealed = get_client_by_name(
            admin(),
            State(ctx.clone()),
            Path("phone".to_string()),
            Query(ClientRevealQuery {
                reveal: Some("1".to_string()),
            }),
        )
        .await
        .expect("Admin can reveal the secret")
        .0;
        assert_eq!(revealed.doh_path.as_deref(), Some("super-secret"));

        // Reusing a secret for another entry is rejected.
        let conflict = create_client(
            operator(),
            State(ctx.clone()),
            Extension(ApplyHooks::default()),
            Json(dto("other", Some("super-secret"))),
        )
        .await
        .unwrap_err();
        assert_eq!(conflict.status, 409);

        // Replacing identifiers without a secret clears it.
        let _ = update_client(
            operator(),
            State(ctx.clone()),
            Extension(ApplyHooks::default()),
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
            Extension(ApplyHooks::default()),
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

        // A masked echo in an update must preserve the stored secret.
        let updated = update_client(
            operator(),
            State(ctx.clone()),
            Extension(ApplyHooks::default()),
            Path("phone".to_string()),
            Json(UpdateClientRequest {
                doh_path: Some("***cret".to_string()),
                group: Some("kids".to_string()),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(updated.group, "kids");
        assert!(updated.has_secret);
        assert_eq!(
            load_clients_config(&ctx)
                .client_id_secrets
                .get("phone")
                .map(String::as_str),
            Some("second-secret"),
            "a masked value must never overwrite the stored secret"
        );

        let _ = delete_client(
            operator(),
            State(ctx.clone()),
            Extension(ApplyHooks::default()),
            Path("phone".to_string()),
        )
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
            Extension(ApplyHooks::default()),
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

    /// WP-0.7 (P2-54): re-creating an existing group is a conflict, not a
    /// malformed request.
    #[tokio::test]
    async fn test_add_duplicate_client_group_returns_conflict() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_group_dup_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ctx = mock_context(&temp_dir).await;
        let group = ClientGroupDto {
            name: "kids".to_string(),
            description: None,
            filtering_enabled: true,
            parental_control: false,
            safe_search: false,
            blocked_services: Vec::new(),
            parental_categories: Vec::new(),
        };

        let _ = add_client_group(
            operator(),
            State(ctx.clone()),
            Extension(ApplyHooks::default()),
            Json(group.clone()),
        )
        .await
        .expect("first group creation succeeds");

        let err = add_client_group(
            operator(),
            State(ctx.clone()),
            Extension(ApplyHooks::default()),
            Json(group),
        )
        .await
        .expect_err("duplicate group must be rejected");
        assert_eq!(err.status, 409);
        assert_eq!(
            load_clients_config(&ctx).groups.len(),
            1,
            "the duplicate must not alter the stored groups"
        );

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
