//! OpenAPI specification generator via utoipa.

use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::auth::session::{SESSION_COOKIE_NAME, SESSION_COOKIE_NAME_SECURE};

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
                    .bearer_format("API token")
                    .description(Some(
                        "API token in `Authorization: Bearer <token>`. API-token callers are \
                         exempt from `X-Reauth-Token` on sensitive mutations.",
                    ))
                    .build(),
            )),
        );
        let mut cookie = ApiKeyValue::new(SESSION_COOKIE_NAME_SECURE);
        cookie.description = Some(format!(
            "Browser session cookie. The canonical secure cookie is \
             `{SESSION_COOKIE_NAME_SECURE}`; `{SESSION_COOKIE_NAME}` is only the \
             plaintext/loopback fallback used when TLS is not active. Session \
             callers need a fresh `X-Reauth-Token` for sensitive mutations."
        ));
        components.security_schemes.insert(
            "cookie_auth".to_string(),
            utoipa::openapi::RefOr::T(SecurityScheme::ApiKey(ApiKey::Cookie(cookie))),
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
        description = "Administrative REST API and OpenAPI 3.1 specification for the sito DNS server. Account, role, API-token management, and self-service TOTP enrollment are available in the web UI (/users and /account); sensitive TOTP changes require a fresh re-authentication ticket from POST /api/v2/auth/reauth. See docs/user-management.md (https://github.com/kubaeror/sito-dns/blob/main/docs/user-management.md).",
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

    fn parameters(operation: &serde_json::Value) -> Vec<serde_json::Value> {
        operation["parameters"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    fn header_parameter<'a>(
        operation: &'a serde_json::Value,
        name: &str,
    ) -> Option<&'a serde_json::Value> {
        operation["parameters"]
            .as_array()?
            .iter()
            .find(|parameter| {
                parameter["in"] == "header"
                    && parameter["name"]
                        .as_str()
                        .is_some_and(|actual| actual.eq_ignore_ascii_case(name))
            })
    }

    #[test]
    fn test_openapi_security_schemes_and_operation_security() {
        let document = document();
        let schemes = &document["components"]["securitySchemes"];
        assert_eq!(schemes["bearer_auth"]["type"], "http");
        assert_eq!(schemes["bearer_auth"]["scheme"], "bearer");
        assert_eq!(schemes["cookie_auth"]["type"], "apiKey");
        assert_eq!(schemes["cookie_auth"]["in"], "cookie");
        assert_eq!(schemes["cookie_auth"]["name"], "__Host-sito_session");

        let cookie_description = schemes["cookie_auth"]["description"]
            .as_str()
            .expect("cookie scheme description");
        assert!(
            cookie_description.contains("sito_session"),
            "the cookie description must name the plaintext/loopback fallback: {cookie_description}"
        );
        assert!(
            cookie_description.contains("plaintext") && cookie_description.contains("loopback"),
            "the cookie description must explain the fallback: {cookie_description}"
        );

        let public: BTreeSet<(String, String)> = [
            ("/api/v2/auth/login", "post"),
            ("/api/v2/auth/totp/verify", "post"),
            ("/api/v2/auth/logout", "post"),
        ]
        .into_iter()
        .map(|(path, method)| (path.to_string(), method.to_string()))
        .collect();

        let operations = operations(&document);
        let documented_public: BTreeSet<(String, String)> = operations
            .iter()
            .filter(|(_, operation)| security_names(operation).is_empty())
            .map(|(key, _)| key.clone())
            .collect();
        assert_eq!(
            documented_public, public,
            "the only public operations may be login, TOTP verify, and logout"
        );

        for (key, operation) in operations {
            let names = security_names(&operation);
            if public.contains(&key) {
                assert!(
                    names.is_empty(),
                    "{} {} must stay public, got {names:?}",
                    key.1,
                    key.0
                );
            } else {
                assert_eq!(
                    names,
                    BTreeSet::from(["bearer_auth".to_string(), "cookie_auth".to_string()]),
                    "{} {} must declare exactly bearer_auth and cookie_auth",
                    key.1,
                    key.0
                );
            }
        }
    }

    #[test]
    fn test_openapi_reauth_header_is_documented_as_session_only() {
        let document = document();
        let sensitive: BTreeSet<(String, String)> = [
            ("/api/v2/auth/totp/setup", "get"),
            ("/api/v2/auth/totp/enable", "post"),
            ("/api/v2/auth/totp/disable", "post"),
            ("/api/v2/auth/tokens", "post"),
            ("/api/v2/auth/users", "post"),
            ("/api/v2/auth/users/{username}", "put"),
            ("/api/v2/auth/users/{username}", "delete"),
            ("/api/v2/auth/tokens/{id}", "delete"),
            ("/api/v2/auth/change-password", "post"),
        ]
        .into_iter()
        .map(|(path, method)| (path.to_string(), method.to_string()))
        .collect();

        let operations = operations(&document);
        for key in &sensitive {
            let operation = operations
                .get(key)
                .unwrap_or_else(|| panic!("{} {} is missing", key.1, key.0));
            let header = header_parameter(operation, "X-Reauth-Token").unwrap_or_else(|| {
                panic!(
                    "{} {} must document the X-Reauth-Token header",
                    key.1, key.0
                )
            });
            assert_eq!(
                header["required"], false,
                "{} {} must document X-Reauth-Token as optional, not globally required",
                key.1, key.0
            );
            let description = header["description"]
                .as_str()
                .expect("reauth header description")
                .to_ascii_lowercase();
            assert!(
                description.contains("session") || description.contains("cookie"),
                "{} {} must describe the header as session-scoped: {description}",
                key.1,
                key.0
            );
            assert!(
                description.contains("api-token") || description.contains("api token"),
                "{} {} must state that API-token callers are exempt: {description}",
                key.1,
                key.0
            );
        }

        for (key, operation) in operations {
            if header_parameter(&operation, "X-Reauth-Token").is_some() {
                assert!(
                    sensitive.contains(&key),
                    "{} {} must not advertise X-Reauth-Token; it is not required by the handler",
                    key.1,
                    key.0
                );
            }
        }
    }

    #[test]
    fn test_openapi_never_advertises_a_query_token() {
        let document = document();
        for (key, operation) in operations(&document) {
            for parameter in parameters(&operation) {
                let location = parameter["in"].as_str().unwrap_or_default();
                let name = parameter["name"].as_str().unwrap_or_default();
                if location.eq_ignore_ascii_case("query") {
                    assert!(
                        !name.eq_ignore_ascii_case("token"),
                        "{} {} must not advertise a query token credential",
                        key.1,
                        key.0
                    );
                }
            }
        }

        let stream = &document["paths"]["/api/v2/querylog/stream"]["get"];
        assert!(
            stream.get("parameters").is_none(),
            "the query-log stream must not advertise query parameters"
        );
        let description = stream["description"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(
            description.contains("token"),
            "the query-log stream contract must rule out the legacy ?token= credential"
        );
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
        #[cfg(feature = "ha")]
        assert!(
            declared.contains("HA"),
            "the HA tag is declared when the ha feature is enabled"
        );
        #[cfg(not(feature = "ha"))]
        assert!(
            !declared.contains("HA"),
            "the HA tag must not be declared without the ha feature"
        );

        for (key, operation) in operations(&document) {
            let tags: Vec<&str> = operation["tags"]
                .as_array()
                .expect("operation tags")
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect();
            assert!(!tags.is_empty(), "{} {} has no tag", key.1, key.0);
            for tag in &tags {
                assert!(
                    !tag.starts_with("crate::"),
                    "{} {} uses a module-path tag '{tag}'",
                    key.1,
                    key.0
                );
                assert_ne!(
                    *tag, "system",
                    "{} {} uses lowercase 'system'",
                    key.1, key.0
                );
                assert!(
                    declared.contains(*tag),
                    "{} {} uses undeclared tag '{tag}'",
                    key.1,
                    key.0
                );
            }
            if key.0.starts_with("/api/v2/ha/") {
                assert_eq!(
                    tags,
                    vec!["HA"],
                    "{} {} must use only the HA tag",
                    key.1,
                    key.0
                );
            }
        }
    }

    fn response_statuses(operation: &serde_json::Value) -> BTreeSet<String> {
        operation["responses"]
            .as_object()
            .map(|responses| responses.keys().cloned().collect())
            .unwrap_or_default()
    }

    #[test]
    fn test_openapi_documents_handler_error_responses() {
        let document = document();
        let expectations: &[(&str, &str, &[&str])] = &[
            ("/api/v2/config", "put", &["400", "409", "500"]),
            ("/api/v2/config", "get", &["500"]),
            ("/api/v2/config/reload", "post", &["400", "500"]),
            ("/api/v2/config/backup", "get", &["500"]),
            (
                "/api/v2/config/restore/confirm",
                "post",
                &["400", "409", "500"],
            ),
            ("/api/v2/clients", "post", &["400", "409", "500"]),
            (
                "/api/v2/clients/{name}",
                "put",
                &["400", "409", "404", "500"],
            ),
            ("/api/v2/clients/{name}", "delete", &["404", "500"]),
            (
                "/api/v2/clients/groups/{name}",
                "delete",
                &["400", "409", "404", "500"],
            ),
            ("/api/v2/filtering/lists", "post", &["400", "409", "500"]),
            (
                "/api/v2/filtering/lists/{id}",
                "put",
                &["400", "409", "404", "500"],
            ),
            (
                "/api/v2/filtering/lists/{id}",
                "delete",
                &["409", "404", "500"],
            ),
            ("/api/v2/filtering/refresh", "post", &["500"]),
            ("/api/v2/filtering/rules", "put", &["400", "500"]),
            (
                "/api/v2/integrations/lists/{category}/refresh",
                "post",
                &["400", "404", "500", "502"],
            ),
            ("/api/v2/querylog", "get", &["429", "500"]),
            ("/api/v2/querylog", "delete", &["500"]),
            ("/api/v2/stats", "get", &["400", "429", "500"]),
            ("/api/v2/stats/clients", "get", &["400", "429", "500"]),
            ("/api/v2/stats/upstreams", "get", &["400", "429", "500"]),
            ("/api/v2/rewrites", "post", &["400", "500"]),
            ("/api/v2/rewrites/{id}", "put", &["400", "404", "500"]),
            ("/api/v2/rewrites/{id}", "delete", &["404", "500"]),
            ("/api/v2/upstream", "put", &["400", "500"]),
            ("/api/v2/upstream/test", "post", &["400"]),
            ("/api/v2/auth/totp/verify", "post", &["401", "429"]),
            ("/api/v2/auth/totp/setup", "get", &["401", "403", "500"]),
            ("/api/v2/auth/totp/enable", "post", &["400", "404", "500"]),
            ("/api/v2/auth/totp/disable", "post", &["400", "404", "500"]),
            ("/api/v2/auth/users", "post", &["400", "409", "500"]),
            (
                "/api/v2/auth/users/{username}",
                "put",
                &["400", "404", "500"],
            ),
            (
                "/api/v2/auth/users/{username}",
                "delete",
                &["400", "404", "500"],
            ),
            (
                "/api/v2/auth/change-password",
                "post",
                &["400", "404", "500"],
            ),
        ];

        for (path, method, expected) in expectations {
            let operation = document["paths"]
                .get(*path)
                .and_then(|item| item.get(*method))
                .unwrap_or_else(|| panic!("{method} {path} is missing"));
            let statuses = response_statuses(operation);
            for status in *expected {
                assert!(
                    statuses.contains(*status),
                    "{method} {path} must document {status}, got {statuses:?}"
                );
            }
        }

        // These operations take the config-apply lock before they capture the
        // runtime generation, so `ApplyError::GenerationConflict` cannot occur.
        // They also use the locked/full apply variants, which skip the
        // restart-only gate. Advertising 409 here would be inventing a status
        // the handler can never return.
        let unreachable: &[(&str, &str, &[&str])] = &[
            ("/api/v2/clients/{name}", "delete", &["400", "409"]),
            ("/api/v2/clients/groups/{name}", "put", &["409"]),
            ("/api/v2/filtering/lists/{id}", "delete", &["400"]),
            ("/api/v2/filtering/refresh", "post", &["400", "409"]),
            ("/api/v2/filtering/rules", "put", &["409"]),
            ("/api/v2/rewrites", "post", &["409"]),
            ("/api/v2/rewrites/{id}", "put", &["409"]),
            ("/api/v2/rewrites/{id}", "delete", &["400", "409"]),
            ("/api/v2/upstream", "put", &["409"]),
            ("/api/v2/config/reload", "post", &["409"]),
        ];
        for (path, method, absent) in unreachable {
            let operation = &document["paths"][*path][*method];
            let statuses = response_statuses(operation);
            for status in *absent {
                assert!(
                    !statuses.contains(*status),
                    "{method} {path} must not document unreachable {status}, got {statuses:?}"
                );
            }
        }

        // `PUT /filtering/rules` can still return 400: the shared locked apply
        // pipeline rejects a configuration whose HA replication bundle exceeds
        // the push limit, even with no slaves connected. The response must
        // carry the ProblemDetails envelope.
        let rules_400 = &document["paths"]["/api/v2/filtering/rules"]["put"]["responses"]["400"];
        assert_eq!(
            rules_400["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ProblemDetails",
            "the oversized-HA-bundle 400 must document the ProblemDetails envelope"
        );
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
                _ => format!("/api/v2{route}"),
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
            assert!(path.starts_with("/api/v2"), "{path} must be under /api/v2");
            assert!(
                !path.starts_with("/api/v1"),
                "{path} is a removed API v1 path"
            );
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
        routed.retain(|path, _| !path.starts_with("/api/v2/ha/"));

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

        // `/upstream/config` is the documented 308 alias for `/upstream`.
        for method in ["get", "put"] {
            let alias = &document["paths"]["/api/v2/upstream/config"][method];
            assert!(
                alias["responses"]["308"].is_object(),
                "the upstream alias {method} must document its 308 redirect"
            );
            assert!(
                document["paths"]["/api/v2/upstream"][method].is_object(),
                "the canonical upstream {method} operation must remain documented"
            );
        }
    }
}
