//! REST API request and response data transfer objects with OpenAPI schema annotations.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// System status response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StatusResponse {
    pub version: String,
    pub uptime_seconds: u64,
    pub role: String,
    pub listeners: Vec<String>,
}

/// Query parameters for statistics window.
#[derive(Debug, Clone, Default, Deserialize, IntoParams, ToSchema)]
pub struct StatsQuery {
    /// Time window: "1h", "24h", "7d", "30d" (default: "24h").
    pub window: Option<String>,
}

/// Observable filter-engine status (additive, read-only).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FilterStatusDto {
    /// `disabled`, `loading`, `ready` or `failed`.
    pub state: String,
    /// Active compiled rules.
    pub rule_count: usize,
    /// Configured lists that loaded in the last reload.
    pub loaded_lists: usize,
    /// Configured lists that failed (fetch, parse, empty/zero-yield, limits).
    pub failed_lists: Vec<String>,
    /// Lists whose newest content was rejected while an older snapshot stayed.
    pub degraded_lists: Vec<String>,
    /// Groups published without their regex/wildcard (or substring/prefix)
    /// class after a budget/limit failure.
    pub degraded_groups: Vec<String>,
    /// Regex/wildcard patterns dropped from the active snapshot.
    pub dropped_regex_patterns: usize,
    /// True when no usable snapshot is active and fail-closed answers SERVFAIL.
    pub unavailable: bool,
    /// Most recent reload error.
    pub last_error: Option<String>,
    /// Wall-clock milliseconds of the last parse+compile attempt.
    pub last_compile_ms: Option<u64>,
}

/// Filter list subscription details. `id` is the stable list name (numeric
/// indices from older clients are still accepted on update/delete).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FilterListDto {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub refresh_hours: u32,
    pub rule_count: usize,
    pub last_updated: Option<i64>,
}

/// Request to create a new filter list.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AddFilterListRequest {
    pub name: String,
    pub url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_refresh_hours")]
    pub refresh_hours: u32,
}

fn default_true() -> bool {
    true
}

fn default_refresh_hours() -> u32 {
    24
}

/// Request to update an existing filter list.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateFilterListRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub enabled: Option<bool>,
    pub refresh_hours: Option<u32>,
}

/// Custom rules collection.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CustomRulesDto {
    pub rules: Vec<String>,
}

/// Request to test/simulate a filtering verdict without contacting upstreams.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FilterCheckRequest {
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qtype: Option<u16>,
}

/// Simulated filtering verdict response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FilterCheckResponse {
    pub domain: String,
    pub verdict: String,
    pub rule: Option<String>,
    pub list_source: Option<String>,
    pub category: Option<String>,
}

/// Discovered client that is not explicitly configured.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UnidentifiedClientDto {
    /// Client IP address.
    pub ip: String,
    /// MAC address reported by the DHCP lease, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// DHCP hostname, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// DHCP lease comment, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// RFC 3339 timestamp of the last query from this client.
    pub last_seen: String,
}

/// Bounded, newest-first list of discovered but unconfigured clients.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UnidentifiedClientsResponse {
    pub clients: Vec<UnidentifiedClientDto>,
    /// Maximum number of entries the registry retains.
    pub max_entries: usize,
    /// Age after which entries are pruned.
    pub retention_hours: u64,
}

/// Client configuration record.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClientDto {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mac: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subnet: Vec<String>,
    #[serde(default = "default_group")]
    pub group: String,
    /// Shared DoH-path/DoT-SNI secret. On `GET` responses this is only ever
    /// populated when the caller explicitly requested a reveal; otherwise it
    /// is `None` and `has_secret`/`secret_hint` describe the stored value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dot_sni: Option<String>,
    #[serde(default)]
    pub ignore_query_log: bool,
    #[serde(default)]
    pub ignore_stats: bool,
    /// Per-client upstream toggle; only changed when present in an update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_global_upstreams: Option<bool>,
    /// Per-client upstream server list; only changed when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstreams: Option<Vec<String>>,
    /// Whether the client is a trusted resolver; only changed when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    /// Response only: a shared secret is stored for this client.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub has_secret: bool,
    /// Response only: masked hint (`last4`) for the stored shared secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_hint: Option<String>,
}

/// Partial update for a client. Fields that are absent keep their current
/// values; identifier lists are only replaced when at least one is supplied.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct UpdateClientRequest {
    /// New client name. Renaming onto an existing client name is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mac: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subnet: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dot_sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignore_query_log: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignore_stats: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_global_upstreams: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstreams: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
}

fn default_group() -> String {
    "default".to_string()
}

/// Partial update for a client policy group. Fields that are absent keep their
/// current values (lists, custom rules, YouTube safe search, schedules and
/// per-service schedules are always preserved).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct UpdateClientGroupRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filtering_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parental_control: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_search: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_services: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parental_categories: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lists: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_search_youtube: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_enabled: Option<bool>,
}

/// Client policy group.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClientGroupDto {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub filtering_enabled: bool,
    #[serde(default)]
    pub parental_control: bool,
    #[serde(default)]
    pub safe_search: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_services: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parental_categories: Vec<String>,
}

/// Local DNS rewrite record.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RewriteDto {
    pub id: String,
    pub domain: String,
    pub record_type: String,
    pub answer: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exception_clients: Vec<String>,
}

/// Request to create a new DNS rewrite.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AddRewriteRequest {
    pub domain: String,
    #[serde(default = "default_a_record")]
    pub record_type: String,
    pub answer: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exception_clients: Vec<String>,
}

fn default_a_record() -> String {
    "A".to_string()
}

/// Upstream DNS configuration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpstreamConfigDto {
    pub servers: Vec<String>,
    pub bootstrap: Vec<String>,
    pub strategy: String,
    pub timeout_ms: u64,
    pub probe_domain: String,
    pub pool_size: usize,
}

/// Upstream latency test request.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpstreamTestRequest {
    pub servers: Vec<String>,
}

/// Upstream latency test individual result.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpstreamTestItem {
    pub server: String,
    pub rtt_ms: Option<u64>,
    pub healthy: bool,
    pub error: Option<String>,
}

/// Upstream latency test result response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpstreamTestResponse {
    pub results: Vec<UpstreamTestItem>,
}

/// Query parameters for cache invalidation.
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
pub struct InvalidateCacheQuery {
    pub domain: String,
}

/// Generic success message response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GenericMessageResponse {
    pub message: String,
}

/// Result of a configuration update, including restart requirements.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfigUpdateResponse {
    pub message: String,
    /// Settings that changed but only take effect after a process restart.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restart_required: Vec<String>,
    /// HA publication result when this node is a cluster master. Omitted for
    /// non-HA nodes and slaves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ha_publish: Option<HaPublishStatus>,
}

/// Outcome of publishing a configuration to HA replica slaves.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct HaPublishStatus {
    /// `published`, `no_slaves` or `failed`.
    pub status: String,
    /// Human-readable failure reason. Never contains secret material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// RFC3339 timestamp of the first background retry, when one is scheduled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<String>,
}

/// Full configuration response with secrets masked.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfigResponse {
    pub config_toml: String,
}

/// Request to replace full configuration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateConfigRequest {
    pub config_toml: String,
}

/// Backup creation metadata.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BackupMetadata {
    pub version: String,
    pub timestamp: i64,
    pub sito_version: String,
}

/// Restore preparation response with confirmation token.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RestorePreparedResponse {
    pub confirmation_token: String,
    pub message: String,
    pub config_preview: String,
}

/// Request to confirm restoration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RestoreConfirmRequest {
    pub confirmation_token: String,
}

/// Login request.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub user: String,
    pub pass: String,
}

/// Login response.
///
/// The session itself is delivered as an HttpOnly `Set-Cookie` header; it is
/// deliberately never echoed in the JSON body. The TOTP `partial_token` is
/// returned only to clients that opt in with `X-Sito-Token-Delivery: body`
/// (CLI/API consumers); browser clients receive it as an HttpOnly cookie.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LoginResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default)]
    pub totp_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_token: Option<String>,
}

/// Re-authentication request for a sensitive operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReauthRequest {
    pub password: String,
    /// Current TOTP or backup code; required when TOTP is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Short-lived, session-bound re-authentication ticket.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReauthResponse {
    pub reauth_token: String,
    /// Remaining lifetime in seconds.
    pub expires_in: u64,
}

/// TOTP verification request.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TotpVerifyRequest {
    pub partial_token: String,
    pub code: String,
}

/// Request to confirm and enable TOTP.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TotpConfirmRequest {
    pub code: String,
}

/// Request to disable TOTP. Requires the current password and, when 2FA is
/// enabled, a valid TOTP or backup code.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DisableTotpRequest {
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Request to create or update an API token.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateTokenRequest {
    pub name: String,
    pub scope: String,
}

/// API token metadata safe for API/UI responses (never includes the hash).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiTokenDto {
    pub id: String,
    pub name: String,
    pub scope: String,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl From<&crate::auth::token::ApiTokenMeta> for ApiTokenDto {
    fn from(meta: &crate::auth::token::ApiTokenMeta) -> Self {
        Self {
            id: meta.id.clone(),
            name: meta.name.clone(),
            scope: meta.scope.to_string(),
            created_at: meta.created_at,
            last_used: meta.last_used,
            expires_at: meta.expires_at,
        }
    }
}

/// User account record (never includes password hashes or TOTP secrets).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserDto {
    pub username: String,
    pub role: String,
    pub totp_enabled: bool,
}

/// Request to create a local user account.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: String,
}

/// Request to change a user's role.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub role: String,
}

/// Request to change a password. The caller must either prove knowledge of the
/// current password (self-service) or be an Admin overriding another account
/// (`username` set, audited).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_password: Option<String>,
    pub new_password: String,
}

/// HA cluster status response for `GET /api/v1/ha/status`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HaStatusResponse {
    pub role: String,
    pub instance_name: String,
    pub version: u64,
    pub state: String,
    /// Whether the node's HA role is actually operational. A master with a
    /// failed mTLS listener or a slave that has not reached `synced` reports
    /// `false` even though DNS keeps answering.
    #[serde(default)]
    pub ready: bool,
    /// Why `ready` is false (unreadable key, bind failure, handshake failure,
    /// not yet synced, ...), or an explanatory note for a deliberately
    /// disabled replication listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_url: Option<String>,
    pub slaves_connected: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded_reason: Option<String>,
    /// True when the master detected a version-continuity violation: a slave
    /// acknowledged a version above the master's current version, meaning
    /// every push below the slave's version is silently ignored.
    #[serde(default)]
    pub diverged: bool,
    /// Human-readable reason for `diverged`, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diverged_reason: Option<String>,
    /// Master only: the Ed25519 public key (hex) that signs replicated
    /// bundles. Slaves must list it as `master_pubkey`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_pubkey: Option<String>,
}

/// Statistics reported by a replica slave.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HaSlaveStatsSummary {
    pub window_s: u64,
    pub queries: u64,
    pub blocked: u64,
    pub upstreams_count: usize,
}

/// Summary of a connected replica slave node for `GET /api/v1/ha/slaves`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HaSlaveSummary {
    pub instance: String,
    pub remote_addr: String,
    pub synced_version: u64,
    pub lag: u64,
    /// True when this slave reported a version above the master's current one.
    /// `lag` is pinned to 0 in that case and must not be read as "in sync".
    #[serde(default)]
    pub diverged: bool,
    pub last_ping_secs_ago: u64,
    pub connected_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_stats: Option<HaSlaveStatsSummary>,
}

impl From<sito_ha::SlaveSummary> for HaSlaveSummary {
    fn from(s: sito_ha::SlaveSummary) -> Self {
        Self {
            instance: s.instance,
            remote_addr: s.remote_addr,
            synced_version: s.synced_version,
            lag: s.lag,
            diverged: s.diverged,
            last_ping_secs_ago: s.last_ping_secs_ago,
            connected_at: s.connected_at,
            last_stats: s.last_stats.map(|st| HaSlaveStatsSummary {
                window_s: st.window_s,
                queries: st.queries,
                blocked: st.blocked,
                upstreams_count: st.upstreams_count,
            }),
        }
    }
}

/// Response for `POST /api/v1/ha/resync`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HaResyncResponse {
    pub status: String,
    pub role: String,
    pub version: u64,
    /// Master only: whether an active bundle exists to re-push. `false` means
    /// the request was accepted but there is nothing to replicate yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_bundle: Option<bool>,
    /// Master only: connected slaves for which a push was queued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slaves_notified: Option<usize>,
}
