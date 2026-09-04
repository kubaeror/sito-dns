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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClientGroupConfig {
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
}
