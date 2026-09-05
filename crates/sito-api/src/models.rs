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

/// Filter list subscription details.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FilterListDto {
    pub id: usize,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dot_sni: Option<String>,
    #[serde(default)]
    pub ignore_query_log: bool,
    #[serde(default)]
    pub ignore_stats: bool,
}

fn default_group() -> String {
    "default".to_string()
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LoginResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default)]
    pub totp_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_token: Option<String>,
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

/// Request to create an API token.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateTokenRequest {
    pub name: String,
    pub scope: String,
}

/// Stub response for HA endpoints returning 501 Not Implemented.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HaStubResponse {
    pub message: String,
}

/// HA cluster status response for `GET /api/v1/ha/status`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HaStatusResponse {
    pub role: String,
    pub instance_name: String,
    pub version: u64,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_url: Option<String>,
    pub slaves_connected: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded_reason: Option<String>,
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
}
