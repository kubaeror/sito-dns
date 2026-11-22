//! Askama template structs and HTML response adapter.

use crate::models::{FilterListDto, StatusResponse};
use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use sito_stats::GlobalStats;

/// Wrapper to convert any Askama `Template` into an Axum HTML `Response`.
pub struct HtmlTemplate<T>(pub T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template: {err}"),
            )
                .into_response(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamViewItem {
    pub address: String,
    pub protocol: String,
    pub is_healthy: bool,
    pub total_queries: u64,
    pub avg_latency_ms: f64,
}

#[derive(Debug, Clone)]
pub struct RewriteViewItem {
    pub id: String,
    pub domain: String,
    pub record_type: String,
    pub answer: String,
}

#[derive(Debug, Clone)]
pub struct ClientViewItem {
    pub name: String,
    pub ids: Vec<String>,
    pub group: String,
}

/// One discovered-but-unconfigured client row.
#[derive(Debug, Clone)]
pub struct ClientDiscoveryViewItem {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    /// Pre-formatted UTC timestamp for display.
    pub last_seen: String,
}

/// One blocked-service entry configured for a client group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedServiceViewItem {
    pub service: String,
    /// Cron expression when the entry is schedule-limited, for display.
    pub schedule: Option<String>,
}

/// One client group with its configured blocked services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGroupServicesViewItem {
    pub name: String,
    /// True for the implicit `default` group when no explicit group exists.
    pub is_default: bool,
    /// Configured entries in configuration order, deduplicated by service id.
    pub blocked_services: Vec<BlockedServiceViewItem>,
    /// Configured entries whose ids are absent from the embedded catalog
    /// (bundled-only or legacy ids). The picker shows these as an editable
    /// "Other configured services" section so saving cannot drop them
    /// silently.
    pub unlisted_services: Vec<BlockedServiceViewItem>,
}

/// One catalog service offered by the blocked-service picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogServiceViewItem {
    pub id: String,
    pub name: String,
    /// Catalog service group id (`social_network`, `streaming`, ...).
    pub group: String,
    /// Number of embedded `||domain^` rules for this service.
    pub rule_count: usize,
    /// True when the id has at least one usable catalog rule and was merged
    /// into the runtime service registry. Every usable catalog service is
    /// available; a zero-rule catalog service is marked unavailable instead of
    /// being offered as a silent no-op.
    pub available: bool,
}

/// One catalog service group with its services in stable display order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogServiceGroupViewItem {
    pub id: String,
    pub services: Vec<CatalogServiceViewItem>,
}

/// One row on the user-management page.
#[derive(Debug, Clone)]
pub struct UserViewItem {
    pub username: String,
    pub role: String,
    pub totp_enabled: bool,
    /// Percent-encoded action URLs so usernames cannot break out of the path.
    pub role_action: String,
    pub delete_action: String,
    /// True for the authenticated account viewing the page.
    pub is_current: bool,
}

/// Pending TOTP enrollment material shown once on the account page.
///
/// The fields are intentionally secret-bearing. `Debug` is redacted (like
/// `TotpSetupResponse`) so enrollment material cannot leak through logging or
/// error formatting.
#[derive(Clone)]
pub struct TotpSetupView {
    pub secret: String,
    pub otpauth_url: String,
    /// Base64 PNG (without the data-URI prefix), empty when generation failed.
    pub qr_code: String,
    pub backup_codes: Vec<String>,
    /// Short-lived, session-bound ticket required to confirm the enrollment.
    pub reauth_token: String,
}

impl std::fmt::Debug for TotpSetupView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSetupView")
            .field("secret", &"<redacted>")
            .field("otpauth_url", &"<redacted>")
            .field("qr_code", &"<redacted>")
            .field(
                "backup_codes",
                &format_args!("<{} redacted>", self.backup_codes.len()),
            )
            .field("reauth_token", &"<redacted>")
            .finish()
    }
}

/// One API-token row on the account page.
#[derive(Debug, Clone)]
pub struct TokenViewItem {
    pub id: String,
    pub name: String,
    pub scope: String,
    /// Display label for Admins; ordinary users only see their own tokens.
    pub owner: String,
    pub created_at: String,
    pub last_used: String,
    pub expires_at: String,
}

#[derive(Debug, Clone)]
pub struct QueryLogRowItem {
    /// Stable, unique key for this DB row (`id-<rowid>` when available).
    pub row_key: String,
    pub ts: i64,
    pub time_str: String,
    pub client_ip: String,
    pub client_name: Option<String>,
    pub qname: String,
    pub qtype_str: String,
    pub verdict: String,
    pub latency_str: String,
    pub rule: Option<String>,
    pub upstream: Option<String>,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate<'a> {
    pub csrf_token: &'a str,
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub error_message: &'a str,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate<'a> {
    pub csrf_token: &'a str,
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub stats: &'a GlobalStats,
    pub status: &'a StatusResponse,
    pub uptime_str: String,
    pub blocked_pct_str: String,
    pub upstreams: Vec<UpstreamViewItem>,
    pub hourly_times_json: String,
    pub hourly_totals_json: String,
    pub hourly_blocked_json: String,
}

#[derive(Template)]
#[template(path = "partials/dashboard_stats.html")]
pub struct DashboardStatsPartialTemplate<'a> {
    pub stats: &'a GlobalStats,
    pub status: &'a StatusResponse,
    pub uptime_str: String,
    pub blocked_pct_str: String,
}

#[derive(Template)]
#[template(path = "querylog.html")]
pub struct QueryLogTemplate<'a> {
    pub csrf_token: &'a str,
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub entries: &'a [QueryLogRowItem],
    /// Cursor for the page below this one, or `None` on the last page.
    pub next_cursor: Option<&'a str>,
    /// History mode pauses the 3 s live poll.
    pub history_mode: bool,
    /// True when the history controls are returned as an HTMX OOB swap.
    pub controls_oob: bool,
}

#[derive(Template)]
#[template(path = "partials/querylog_rows_response.html")]
pub struct QueryLogRowsPartialTemplate<'a> {
    pub entries: &'a [QueryLogRowItem],
    /// Cursor for the page below this one, or `None` on the last page.
    pub next_cursor: Option<&'a str>,
    /// True while the operator browses older pages.
    pub history_mode: bool,
    /// Response fragments always carry the controls as an OOB swap.
    pub controls_oob: bool,
}

/// One curated list row on the filtering page.
#[derive(Debug, Clone)]
pub struct BundledListView {
    pub id: String,
    pub kind: String,
    pub version: String,
    pub source: String,
    pub license: String,
    pub entries: u64,
    /// `built-in (minimal)` until the category is refreshed from a configured source.
    pub state: String,
    pub last_refresh: String,
    /// Last fetch/apply attempt, successful or not (`—` before any attempt).
    pub last_attempt: String,
    /// Most recent fetch/apply error, when the last attempt failed.
    pub last_error: Option<String>,
}

/// One catalog category shown in the filtering page catalog picker.
#[derive(Debug, Clone)]
pub struct CatalogCategoryView {
    pub id: String,
    pub name: String,
    /// Upstream display order; categories are sorted by this value.
    pub display_number: u32,
    /// Number of filters in the category.
    pub filter_count: usize,
}

/// One selectable filter from the embedded, release-bound catalog.
///
/// Only metadata is exposed; the filter-list body is downloaded at runtime by
/// the existing filter scheduler after the operator selects it.
#[derive(Debug, Clone)]
pub struct CatalogFilterView {
    pub id: String,
    pub name: String,
    pub category: String,
    pub category_name: String,
    pub description: String,
    pub homepage: String,
    /// `download_url`, falling back to `subscription_url` when needed.
    pub source_url: String,
    pub version: String,
    /// Effective name persisted when this entry is added. It can differ from
    /// [`Self::name`] when the upstream name contains characters that are not
    /// valid in a filter-list id (for example `/`).
    pub stored_name: String,
    /// True when [`Self::stored_name`] differs from [`Self::name`], so the UI
    /// can tell the operator which name will be saved.
    pub name_sanitized: bool,
    pub deprecated: bool,
    /// True when a configured list already matches this catalog entry by
    /// case-insensitive name or URL.
    pub already_added: bool,
}

#[derive(Template)]
#[template(path = "filtering.html")]
pub struct FilteringTemplate<'a> {
    pub csrf_token: &'a str,
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub lists: &'a [FilterListDto],
    pub custom_rules: &'a str,
    /// Metadata of the curated lists bundled into the binary plus runtime state.
    pub bundled_lists: Vec<BundledListView>,
    /// Catalog categories in stable display order.
    pub catalog_categories: Vec<CatalogCategoryView>,
    /// Catalog filters in stable category/display order.
    pub catalog_filters: Vec<CatalogFilterView>,
    /// Total number of catalog filters, for rendering stable counts.
    pub catalog_filter_count: usize,
}

#[derive(Template)]
#[template(path = "rewrites.html")]
pub struct RewritesTemplate<'a> {
    pub csrf_token: &'a str,
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub rewrites: Vec<RewriteViewItem>,
}

#[derive(Template)]
#[template(path = "clients.html")]
pub struct ClientsTemplate<'a> {
    pub csrf_token: &'a str,
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub clients: Vec<ClientViewItem>,
    /// Newest-first discovered clients; empty for roles below Operator.
    pub discovered: Vec<ClientDiscoveryViewItem>,
    /// Total discoveries before the UI row cap, used for the truncation count.
    pub discovered_total: usize,
    /// True when the signed-in role may see discovered-client PII.
    pub can_view_discovered: bool,
    /// 1-based page of the discovered-client list currently rendered.
    pub discovered_page: usize,
    /// Total number of discovered-client pages (always at least one).
    pub discovered_pages: usize,
    /// Maximum number of entries the registry retains.
    pub max_entries: usize,
    /// Age after which discovered entries are pruned.
    pub retention_hours: u64,
    /// Client groups (including the implied `default`) with their blocked
    /// services; consumed by the blocked-services picker (F2c2).
    pub group_services: Vec<ClientGroupServicesViewItem>,
    /// Embedded catalog services grouped for the picker; empty when the
    /// catalog is corrupt (the page still renders).
    pub catalog_service_groups: Vec<CatalogServiceGroupViewItem>,
    /// Total catalog services available to the picker.
    pub catalog_service_count: usize,
}

#[derive(Template)]
#[template(path = "upstreams.html")]
pub struct UpstreamsTemplate<'a> {
    pub csrf_token: &'a str,
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub upstreams: Vec<UpstreamViewItem>,
}

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate<'a> {
    pub csrf_token: &'a str,
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub cache_size_mb: usize,
    pub min_ttl: u32,
    pub dnssec_enabled: bool,
    pub rate_limit: u32,
}

#[derive(Template)]
#[template(path = "system.html")]
pub struct SystemTemplate<'a> {
    pub csrf_token: &'a str,
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub status: &'a StatusResponse,
    pub uptime_str: String,
}

#[derive(Template)]
#[template(path = "users.html")]
pub struct UsersTemplate<'a> {
    pub csrf_token: &'a str,
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub users: Vec<UserViewItem>,
    /// Whether the signed-in caller (not the target row) has TOTP enabled;
    /// role changes require the caller's TOTP code, not the target's.
    pub caller_totp_enabled: bool,
    pub error_message: &'a str,
}

#[derive(Template)]
#[template(path = "account.html")]
pub struct AccountTemplate<'a> {
    pub csrf_token: &'a str,
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub tokens: Vec<TokenViewItem>,
    pub totp_enabled: bool,
    /// Pending enrollment to render once, with its re-auth ticket.
    pub totp_setup: Option<TotpSetupView>,
    /// Scope options the signed-in role is allowed to mint. Tokens are global
    /// in the current auth model, so a role must never create a token above
    /// its own privilege level.
    pub can_create_operator_token: bool,
    pub can_create_admin_token: bool,
    /// Configured default token lifetime in days (`0` = no expiry), shown in
    /// the create-token form help.
    pub token_default_ttl_days: u64,
    /// Configured maximum token lifetime in days (`0` = no maximum), shown in
    /// the create-token form help and used as the input's `max` bound.
    pub token_max_ttl_days: u64,
    pub error_message: &'a str,
    pub notice_message: &'a str,
    /// Plaintext token from the request that just created it. Rendered exactly
    /// once and never stored or re-listed.
    pub new_token: Option<&'a str>,
    pub new_token_name: &'a str,
    pub new_token_scope: &'a str,
}

/// One client-network candidate rendered by the first-boot ACL step.
#[derive(Debug, Clone)]
pub struct AclCandidateView {
    pub id: String,
    pub interface: String,
    pub address: String,
    pub prefix: u8,
    pub family: &'static str,
    pub class: &'static str,
    pub class_label: &'static str,
    pub source_label: &'static str,
    /// True for loopback (fixed) and prefixes the base template already allows.
    pub selected: bool,
    pub is_loopback: bool,
    pub is_public: bool,
    pub is_bridge_or_tunnel: bool,
}

#[derive(Template)]
#[template(path = "wizard.html")]
pub struct WizardTemplate<'a> {
    pub is_authenticated: bool,
    pub username: &'a str,
    pub user_role: &'a str,
    pub active_tab: &'a str,
    pub version: &'a str,
    pub csrf_token: &'a str,
    /// True while a one-time setup token is active.
    pub setup_required: bool,
    /// Setup token supplied by the requester (never revealed on its own).
    pub setup_token: &'a str,
    /// Optional re-authentication ticket supplied by an Admin.
    pub reauth_token: &'a str,
    /// True only for a genuine fresh install
    /// (`is_first_run && !is_setup_complete()`). Recovery runs never render
    /// the ACL step, so an existing `[clients.acl]` is never rewritten.
    pub fresh_install_acl: bool,
    /// Detected interface candidates plus loopback; only loopback/prefilled
    /// entries are selected.
    pub acl_candidates: Vec<AclCandidateView>,
    /// Detected network candidates that are already allowed by the base
    /// template but not exposed by a live interface.
    pub acl_prefilled: Vec<AclCandidateView>,
    /// The base template explicitly sets `default_policy = "allow"`.
    pub acl_template_explicit_allow: bool,
    /// The base template has `clients.acl.allow_entry_ids = true`, which the
    /// fresh-install step deliberately does not carry through silently.
    pub acl_base_allow_entry_ids: bool,
    pub acl_manual: &'a str,
}

#[cfg(test)]
mod tests {
    use super::TotpSetupView;

    /// Regression (deferred D2): the view used to derive `Debug` over the TOTP
    /// secret, otpauth URL, QR payload, backup codes and re-auth ticket.
    #[test]
    fn test_totp_setup_view_debug_redacts_enrollment_material() {
        let view = TotpSetupView {
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            otpauth_url: "otpauth://totp/sito:admin?secret=JBSWY3DPEHPK3PXP".to_string(),
            qr_code: "iVBORw0KGgoAAAANSUhEUg".to_string(),
            backup_codes: vec!["AAAA-BBBB".to_string(), "CCCC-DDDD".to_string()],
            reauth_token: "reauth-ticket-secret".to_string(),
        };

        let rendered = format!("{view:?}");
        for secret in [
            "JBSWY3DPEHPK3PXP",
            "otpauth://",
            "iVBORw0KGgoAAAANSUhEUg",
            "AAAA-BBBB",
            "CCCC-DDDD",
            "reauth-ticket-secret",
        ] {
            assert!(
                !rendered.contains(secret),
                "Debug output leaked enrollment material '{secret}': {rendered}"
            );
        }
        assert!(
            rendered.contains("2 redacted"),
            "the backup-code count may be shown but not the codes: {rendered}"
        );
    }
}
