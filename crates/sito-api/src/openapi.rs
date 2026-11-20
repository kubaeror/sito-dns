//! OpenAPI specification generator via utoipa.

use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

/// Declares the two authentication schemes used by every protected operation.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.security_schemes.insert(
            "bearer_auth".to_string(),
            utoipa::openapi::RefOr::T(SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some("API token in `Authorization: Bearer <token>`"))
                    .build(),
            )),
        );
        components.security_schemes.insert(
            "cookie_auth".to_string(),
            utoipa::openapi::RefOr::T(SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new(
                "sito_session",
            )))),
        );
    }
}

/// Documentation shared by every build.
#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
    paths(
        crate::handlers::status::get_status,
        crate::handlers::stats::get_stats,
        crate::handlers::stats::get_client_stats,
        crate::handlers::stats::get_upstream_stats,
        crate::handlers::querylog::get_querylog,
        crate::handlers::querylog::delete_querylog,
        crate::handlers::querylog::clear_querylog,
        crate::handlers::querylog::stream_querylog,
        crate::handlers::filtering::get_filtering_status,
        crate::handlers::filtering::get_filter_lists,
        crate::handlers::filtering::add_filter_list,
        crate::handlers::filtering::update_filter_list,
        crate::handlers::filtering::delete_filter_list,
        crate::handlers::filtering::refresh_filtering,
        crate::handlers::filtering::get_filtering_rules,
        crate::handlers::filtering::set_filtering_rules,
        crate::handlers::filtering::check_filtering,
        crate::handlers::filtering::get_integration_lists,
        crate::handlers::filtering::refresh_integration_list,
        crate::handlers::clients::get_clients,
        crate::handlers::clients::get_unidentified_clients,
        crate::handlers::clients::get_client_by_name,
        crate::handlers::clients::create_client,
        crate::handlers::clients::update_client,
        crate::handlers::clients::delete_client,
        crate::handlers::clients::get_client_groups,
        crate::handlers::clients::get_client_group_by_name,
        crate::handlers::clients::add_client_group,
        crate::handlers::clients::update_client_group,
        crate::handlers::clients::delete_client_group,
        crate::handlers::rewrites::get_rewrites,
        crate::handlers::rewrites::add_rewrite,
        crate::handlers::rewrites::update_rewrite,
        crate::handlers::rewrites::delete_rewrite,
        crate::handlers::upstream::get_upstream_config,
        crate::handlers::upstream::update_upstream_config,
        crate::router::redirect_upstream_config_get,
        crate::router::redirect_upstream_config_put,
        crate::handlers::upstream::test_upstream_servers,
        crate::handlers::cache::flush_cache,
        crate::handlers::cache::invalidate_cache,
        crate::handlers::auth_handlers::login,
        crate::handlers::auth_handlers::verify_totp,
        crate::handlers::auth_handlers::logout,
        crate::handlers::auth_handlers::reauth,
        crate::handlers::auth_handlers::get_totp_setup,
        crate::handlers::auth_handlers::enable_totp,
        crate::handlers::auth_handlers::disable_totp,
        crate::handlers::auth_handlers::list_tokens,
        crate::handlers::auth_handlers::create_token,
        crate::handlers::auth_handlers::delete_token,
        crate::handlers::auth_handlers::list_users,
        crate::handlers::auth_handlers::create_user,
        crate::handlers::auth_handlers::update_user,
        crate::handlers::auth_handlers::delete_user,
        crate::handlers::auth_handlers::change_password,
        crate::handlers::config::get_config,
        crate::handlers::config::get_restart_required,
        crate::handlers::config::update_config,
        crate::handlers::config::reload_config,
        crate::handlers::config::download_backup,
        crate::handlers::config::prepare_restore,
        crate::handlers::config::confirm_restore,
        crate::handlers::update::check_update,
        crate::handlers::update::apply_update,
    ),
    components(
        schemas(
            crate::updater::UpdateInfo,
            crate::handlers::update::ApplyUpdateResponse,
            crate::handlers::update::ApplyUpdatePayload,
            crate::models::StatusResponse,
            crate::models::AcmeStatus,
            crate::readiness::ReadinessReason,
            crate::models::StatsQuery,
            crate::models::FilterStatusDto,
            crate::models::FilterListDto,
            crate::models::AddFilterListRequest,
            crate::models::UpdateFilterListRequest,
            crate::models::CustomRulesDto,
            crate::models::FilterCheckRequest,
            crate::models::FilterCheckResponse,
            crate::models::IntegrationListStatusDto,
            crate::models::ClientDto,
            crate::models::UnidentifiedClientDto,
            crate::models::UnidentifiedClientsResponse,
            crate::models::ClientGroupDto,
            crate::models::UpdateClientRequest,
            crate::models::UpdateClientGroupRequest,
            crate::models::RewriteDto,
            crate::models::AddRewriteRequest,
            crate::models::UpstreamConfigDto,
            crate::models::UpstreamTestRequest,
            crate::models::UpstreamTestItem,
            crate::models::UpstreamTestResponse,
            crate::models::InvalidateCacheQuery,
            crate::models::ConfigUpdateResponse,
            crate::models::GenericMessageResponse,
            crate::models::ConfigResponse,
            crate::models::RestartRequiredResponse,
            crate::models::UpdateConfigRequest,
            crate::models::BackupMetadata,
            crate::models::RestorePreparedResponse,
            crate::models::RestoreConfirmRequest,
            crate::models::LoginRequest,
            crate::models::LoginResponse,
            crate::models::ReauthRequest,
            crate::models::ReauthResponse,
            crate::models::TotpVerifyRequest,
            crate::models::TotpConfirmRequest,
            crate::models::DisableTotpRequest,
            crate::models::CreateTokenRequest,
            crate::models::ApiTokenDto,
            crate::models::UserDto,
            crate::models::CreateUserRequest,
            crate::models::UpdateUserRequest,
            crate::models::ChangePasswordRequest,
            crate::auth::token::Role,
            crate::auth::token::CreateTokenResponse,
            crate::auth::totp::TotpSetupResponse,
            crate::error::ProblemDetails,
            sito_stats::GlobalStats,
            sito_stats::ClientStats,
            sito_stats::UpstreamStats,
            sito_stats::QueryLogEntry,
            sito_stats::QueryLogPage,
            sito_stats::QueryLogFilter,
        )
    ),
    tags(
        (name = "System", description = "System status and health"),
        (name = "Stats", description = "Query statistics and metrics"),
        (name = "QueryLog", description = "Historical query logs and live streaming"),
        (name = "Filtering", description = "Blocklists, allowlists, and custom rules"),
        (name = "Integrations", description = "Curated runtime list status and refresh"),
        (name = "Clients", description = "Client mapping and policy groups"),
        (name = "Rewrites", description = "Custom DNS rewrites"),
        (name = "Upstream", description = "Upstream DNS resolvers and latency probing"),
        (name = "Cache", description = "Response cache operations"),
        (name = "Config", description = "Configuration persistence, hot-reload, backup and restore"),
        (name = "Auth", description = "Authentication, sessions, TOTP 2FA, and API tokens")
    ),
    info(
        title = "sito DNS Administrative API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Administrative REST API and OpenAPI 3.1 specification for the sito DNS server. Account, role, API-token management, and self-service TOTP enrollment are available in the web UI (/users and /account); sensitive TOTP changes require a fresh re-authentication ticket from POST /api/v1/auth/reauth. See docs/user-management.md (https://github.com/kubaeror/sito-dns/blob/main/docs/user-management.md).",
        license(name = "GPL-3.0-only")
    )
)]
struct BaseApiDoc;

/// HA paths and schemas, compiled only when replication support is present.
#[cfg(feature = "ha")]
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::ha::get_ha_status,
        crate::handlers::ha::get_ha_slaves,
        crate::handlers::ha::trigger_ha_resync,
    ),
    components(
        schemas(
            crate::models::HaStatusResponse,
            crate::models::HaSlaveSummary,
            crate::models::HaSlaveStatsSummary,
            crate::models::HaResyncResponse,
        )
    ),
    tags(
        (name = "HA", description = "High Availability replication (Phase M8)")
    )
)]
struct HaApiDoc;

/// Root OpenAPI documentation specification for the sito administration API.
pub struct ApiDoc;

impl OpenApi for ApiDoc {
    fn openapi() -> utoipa::openapi::OpenApi {
        let document = BaseApiDoc::openapi();
        #[cfg(feature = "ha")]
        let document = document.merge_from(HaApiDoc::openapi());
        document
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    const HTTP_METHODS: &[&str] = &["get", "post", "put", "delete", "patch"];

    fn document() -> serde_json::Value {
        serde_json::to_value(ApiDoc::openapi()).expect("OpenAPI serializes")
    }

    fn operations(document: &serde_json::Value) -> BTreeMap<(String, String), serde_json::Value> {
        let mut operations = BTreeMap::new();
        for (path, item) in document["paths"].as_object().expect("paths object") {
            for method in HTTP_METHODS {
                if let Some(operation) = item.get(method) {
                    operations.insert((path.clone(), method.to_string()), operation.clone());
                }
            }
        }
        operations
    }

    fn security_names(operation: &serde_json::Value) -> BTreeSet<String> {
        operation["security"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_object)
            .flat_map(|requirement| requirement.keys().cloned())
            .collect()
    }

    #[test]
    fn test_openapi_security_schemes_and_operation_security() {
        let document = document();
        let schemes = &document["components"]["securitySchemes"];
        assert_eq!(schemes["bearer_auth"]["type"], "http");
        assert_eq!(schemes["bearer_auth"]["scheme"], "bearer");
        assert_eq!(schemes["cookie_auth"]["type"], "apiKey");
        assert_eq!(schemes["cookie_auth"]["in"], "cookie");
        assert_eq!(schemes["cookie_auth"]["name"], "sito_session");

        let public: BTreeSet<(String, String)> = [
            ("/api/v1/auth/login", "post"),
            ("/api/v1/auth/totp/verify", "post"),
            ("/api/v1/auth/logout", "post"),
        ]
        .into_iter()
        .map(|(path, method)| (path.to_string(), method.to_string()))
        .collect();

        for (key, operation) in operations(&document) {
            let names = security_names(&operation);
            if public.contains(&key) {
                assert!(
                    names.is_empty(),
                    "{} {} must stay public, got {names:?}",
                    key.1,
                    key.0
                );
            } else {
                assert!(
                    names.contains("bearer_auth") && names.contains("cookie_auth"),
                    "{} {} must declare bearer_auth and cookie_auth, got {names:?}",
                    key.1,
                    key.0
                );
            }
        }
    }

    #[test]
    fn test_openapi_operations_use_declared_tags() {
        let document = document();
        let declared: BTreeSet<String> = document["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .filter_map(|tag| tag["name"].as_str().map(ToString::to_string))
            .collect();
        assert!(!declared.is_empty());

        for (key, operation) in operations(&document) {
            let tags: Vec<&str> = operation["tags"]
                .as_array()
                .expect("operation tags")
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect();
            assert!(!tags.is_empty(), "{} {} has no tag", key.1, key.0);
            for tag in tags {
                assert!(
                    !tag.starts_with("crate::"),
                    "{} {} uses a module-path tag '{tag}'",
                    key.1,
                    key.0
                );
                assert_ne!(tag, "system", "{} {} uses lowercase 'system'", key.1, key.0);
                assert!(
                    declared.contains(tag),
                    "{} {} uses undeclared tag '{tag}'",
                    key.1,
                    key.0
                );
            }
        }
    }

    /// Extracts `.route("<path>", <chain>)` paths and methods from the router
    /// source. Axum's `Router` is opaque after construction, so the route table
    /// is the source of truth for structural drift.
    fn router_operations() -> BTreeMap<String, BTreeSet<String>> {
        let source = include_str!("router.rs");
        let start = source
            .find("fn create_router_inner")
            .expect("router constructor");
        let source = &source[start..];
        let mut occurrences = Vec::new();
        let mut search = 0;
        while let Some(found) = source[search..].find(".route(") {
            let position = search + found;
            occurrences.push(position);
            search = position + ".route(".len();
        }

        let mut routes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (index, position) in occurrences.iter().enumerate() {
            let position = *position;
            let end = occurrences.get(index + 1).copied().unwrap_or(source.len());
            let segment = &source[position..end];
            let after = segment[".route(".len()..].trim_start();
            let Some(rest) = after.strip_prefix('"') else {
                continue;
            };
            let Some(quote) = rest.find('"') else {
                continue;
            };
            let route = &rest[..quote];
            let path = match route {
                "/health" | "/metrics" => continue,
                _ => format!("/api/v1{route}"),
            };
            let methods = routes.entry(path).or_default();
            for method in HTTP_METHODS {
                if segment.contains(&format!("{method}(")) {
                    methods.insert((*method).to_string());
                }
            }
        }
        routes
    }

    #[test]
    fn test_openapi_paths_match_router() {
        let document = document();
        let mut documented: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (path, method) in operations(&document).keys() {
            documented
                .entry(path.clone())
                .or_default()
                .insert(method.clone());
        }

        #[allow(unused_mut)]
        let mut routed = router_operations();
        // A no-HA build intentionally omits the HA operations from the spec
        // while keeping the routes mounted as 501 stubs.
        #[cfg(not(feature = "ha"))]
        routed.retain(|path, _| !path.starts_with("/api/v1/ha/"));

        assert_eq!(
            documented.keys().collect::<Vec<_>>(),
            routed.keys().collect::<Vec<_>>(),
            "OpenAPI paths and router paths must match"
        );
        for (path, methods) in routed {
            assert_eq!(
                documented.get(&path),
                Some(&methods),
                "method drift for {path}"
            );
        }
    }
}
