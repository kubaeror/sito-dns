//! Effective policy representation for resolved client requests.

use crate::safe_search::YouTubeSafeSearchMode;
use std::collections::HashSet;

/// Merged policy resolving client flags, group rules, schedules, and active blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePolicy {
    pub client_name: Option<String>,
    pub group_name: String,
    pub ids: Vec<String>,
    pub ignore_query_log: bool,
    pub ignore_stats: bool,
    pub use_global_upstreams: bool,
    pub upstreams: Option<Vec<String>>,
    pub trusted: bool,
    pub lists: Vec<String>,
    pub custom_rules: Vec<String>,
    pub safe_search: bool,
    pub safe_search_youtube: YouTubeSafeSearchMode,
    pub parental: bool,
    pub parental_categories: HashSet<String>,
    pub is_filtering_enabled: bool,
    pub active_blocked_services: HashSet<String>,
}

impl Default for EffectivePolicy {
    fn default() -> Self {
        Self {
            client_name: None,
            group_name: "default".to_string(),
            ids: Vec::new(),
            ignore_query_log: false,
            ignore_stats: false,
            use_global_upstreams: true,
            upstreams: None,
            trusted: false,
            lists: Vec::new(),
            custom_rules: Vec::new(),
            safe_search: false,
            safe_search_youtube: YouTubeSafeSearchMode::Strict,
            parental: false,
            parental_categories: HashSet::new(),
            is_filtering_enabled: true,
            active_blocked_services: HashSet::new(),
        }
    }
}
