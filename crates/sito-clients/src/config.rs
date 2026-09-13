//! Client and group policy configuration structures per section 9.1.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::safe_search::YouTubeSafeSearchMode;
use crate::schedule::Schedule;

/// Clients configuration section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClientsConfig {
    #[serde(default)]
    pub entries: Vec<ClientEntryConfig>,
    #[serde(default)]
    pub groups: HashMap<String, ClientGroupConfig>,
    /// Shared secrets enabling DoH path / DoT SNI client authentication,
    /// keyed by the client entry `name`.
    ///
    /// Empty by default ("off"): DoH path and DoT SNI values never grant a
    /// client entry's group/upstreams/trusted policy on their own, because
    /// those values are attacker-controlled (any client may present
    /// `/dns-query/<name>` or `<name>.dns.example.com`) and usually guessable.
    /// When an entry is listed here, a client presenting the exact secret as
    /// its DoH path segment or as the first label of the DoT/DoQ SNI is
    /// identified as that entry. Secrets are compared byte-for-byte; use
    /// lowercase values for SNI authentication (DNS names are lowercased).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub client_id_secrets: HashMap<String, String>,
    /// Trust RouterOS DHCP lease `host-name`/`comment` values as client
    /// identity (default `false`).
    ///
    /// Lease names are client-controlled (a DHCP client picks its own
    /// hostname), so by default they are informational only and never map to
    /// a client entry's group/trusted policy. Enable only on a trusted LAN
    /// where DHCP leases are managed by the operator.
    #[serde(default)]
    pub trust_routeros_lease_names: bool,
}

/// Optional `[integrations]` section: RouterOS DHCP lease sync and curated
/// runtime-updatable list categories.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntegrationsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mikrotik: Option<crate::routeros::RouterOsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lists: Option<crate::runtime_lists::ListCategoriesConfig>,
}

fn default_group() -> String {
    "default".to_string()
}

fn default_true() -> bool {
    true
}

/// A specific client configuration entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientEntryConfig {
    pub name: String,
    #[serde(default)]
    pub ids: Vec<String>,
    #[serde(default = "default_group")]
    pub group: String,
    #[serde(default)]
    pub ignore_query_log: bool,
    #[serde(default)]
    pub ignore_stats: bool,
    #[serde(default = "default_true")]
    pub use_global_upstreams: bool,
    #[serde(default)]
    pub upstreams: Option<Vec<String>>,
    #[serde(default)]
    pub trusted: bool,
}

/// A policy group configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientGroupConfig {
    #[serde(default = "default_true")]
    pub filtering: bool,
    #[serde(default)]
    pub lists: Vec<String>,
    #[serde(default)]
    pub custom_rules: Vec<String>,
    #[serde(default)]
    pub safe_search: bool,
    #[serde(default)]
    pub safe_search_youtube: Option<YouTubeSafeSearchMode>,
    #[serde(default)]
    pub parental: bool,
    #[serde(default)]
    pub parental_categories: Vec<String>,
    #[serde(default)]
    pub schedule_enabled: bool,
    #[serde(default)]
    pub schedule: Option<Schedule>,
    #[serde(default)]
    pub blocked_services: Vec<BlockedServiceConfig>,
}

impl Default for ClientGroupConfig {
    fn default() -> Self {
        Self {
            filtering: true,
            lists: Vec::new(),
            custom_rules: Vec::new(),
            safe_search: false,
            safe_search_youtube: None,
            parental: false,
            parental_categories: Vec::new(),
            schedule_enabled: false,
            schedule: None,
            blocked_services: Vec::new(),
        }
    }
}

/// Blocked service specification with optional cron schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedServiceConfig {
    pub service: String,
    #[serde(default)]
    pub schedule: Option<Schedule>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_section_9_1_toml() {
        let toml_str = r#"
[[entries]]
name = "Jane's Phone"
ids = ["192.168.1.20", "janes-phone", "AA:BB:CC:DD:EE:FF"]
group = "kids"
ignore_query_log = false
use_global_upstreams = true

[groups.kids]
lists = ["OISD", "StevenBlack", "school-list"]
custom_rules = ["||fortnite.com^$important"]
safe_search = true
parental = true
schedule_enabled = true
schedule = "0 0 15-21 * * MON-FRI"

[[groups.kids.blocked_services]]
service = "tiktok"
schedule = "0 0 15-21 * * MON-FRI"
"#;

        let cfg: ClientsConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.entries.len(), 1);
        assert_eq!(cfg.entries[0].name, "Jane's Phone");
        assert_eq!(cfg.entries[0].group, "kids");
        assert_eq!(cfg.entries[0].ids.len(), 3);

        let kids_group = cfg.groups.get("kids").unwrap();
        assert_eq!(kids_group.lists, vec!["OISD", "StevenBlack", "school-list"]);
        assert!(kids_group.safe_search);
        assert!(kids_group.parental);
        assert!(kids_group.schedule_enabled);
        assert_eq!(kids_group.blocked_services.len(), 1);
        assert_eq!(kids_group.blocked_services[0].service, "tiktok");
    }

    #[test]
    fn test_client_id_secrets_and_routeros_trust_default_off() {
        let toml_str = r#"
            client_id_secrets = { "Jane's Phone" = "jane-shared-secret" }
            trust_routeros_lease_names = true

            [[entries]]
            name = "Jane's Phone"
            ids = ["192.168.1.20"]
        "#;
        let cfg: ClientsConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            cfg.client_id_secrets
                .get("Jane's Phone")
                .map(String::as_str),
            Some("jane-shared-secret")
        );
        assert!(cfg.trust_routeros_lease_names);

        // Both settings are opt-in: absent means path/SNI identity off and
        // RouterOS lease names untrusted.
        let defaults: ClientsConfig = toml::from_str("").unwrap();
        assert!(defaults.client_id_secrets.is_empty());
        assert!(!defaults.trust_routeros_lease_names);
    }
}
