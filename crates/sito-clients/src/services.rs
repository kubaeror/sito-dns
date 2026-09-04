//! Service blocking engine using bundled `services.json` (compatible with AdGuard format).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const BUNDLED_SERVICES_JSON: &str = include_str!("bundled/services.json");

/// Service blocking database mapping service IDs to domain patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRegistry {
    services: HashMap<String, Vec<String>>,
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::bundled()
    }
}

#[derive(Deserialize)]
struct ServiceEntry {
    id: String,
    #[serde(default)]
    rules: Vec<String>,
}

impl ServiceRegistry {
    /// Load the bundled service definitions.
    pub fn bundled() -> Self {
        Self::from_json(BUNDLED_SERVICES_JSON)
            .unwrap_or_else(|e| panic!("invalid bundled services.json: {e}"))
    }

    /// Parse service definitions from a JSON string.
    ///
    /// Supports both map format `{"service": ["domain1", "domain2"]}` and
    /// list format `[{"id": "service", "rules": ["domain1"]}]`.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        // Try map format first
        if let Ok(map) = serde_json::from_str::<HashMap<String, Vec<String>>>(json_str) {
            let mut normalized = HashMap::with_capacity(map.len());
            for (svc, domains) in map {
                let cleaned_domains = domains.into_iter().map(|d| clean_domain_rule(&d)).collect();
                normalized.insert(svc.to_ascii_lowercase(), cleaned_domains);
            }
            return Ok(Self {
                services: normalized,
            });
        }

        let list: Vec<ServiceEntry> = serde_json::from_str(json_str)?;
        let mut services = HashMap::with_capacity(list.len());
        for entry in list {
            let cleaned = entry
                .rules
                .into_iter()
                .map(|r| clean_domain_rule(&r))
                .collect();
            services.insert(entry.id.to_ascii_lowercase(), cleaned);
        }

        Ok(Self { services })
    }

    /// Check if a domain belongs to the given service.
    pub fn is_service_domain(&self, service: &str, query_domain: &str) -> bool {
        let svc_key = service.to_ascii_lowercase();
        let Some(rules) = self.services.get(&svc_key) else {
            return false;
        };

        let q = query_domain.trim_end_matches('.').to_ascii_lowercase();

        for rule in rules {
            if q == *rule || q.ends_with(&format!(".{rule}")) {
                return true;
            }
        }

        false
    }

    /// Check if any of the given services match the queried domain.
    pub fn matches_any_service<'a>(
        &self,
        services: impl IntoIterator<Item = &'a str>,
        query_domain: &str,
    ) -> Option<&'a str> {
        services
            .into_iter()
            .find(|&svc| self.is_service_domain(svc, query_domain))
    }

    /// Returns list of available service identifiers.
    pub fn available_services(&self) -> Vec<&str> {
        let mut list: Vec<&str> = self.services.keys().map(String::as_str).collect();
        list.sort_unstable();
        list
    }
}

fn clean_domain_rule(rule: &str) -> String {
    let mut s = rule.trim();
    if let Some(stripped) = s.strip_prefix("||") {
        s = stripped;
    }
    if let Some(stripped) = s.strip_suffix('^') {
        s = stripped;
    }
    s.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundled_services_loaded() {
        let reg = ServiceRegistry::bundled();
        assert!(reg.is_service_domain("tiktok", "tiktok.com"));
        assert!(reg.is_service_domain("tiktok", "p16-sign.tiktokcdn.com"));
        assert!(reg.is_service_domain("tiktok", "www.musical.ly"));
        assert!(!reg.is_service_domain("tiktok", "google.com"));

        assert!(reg.is_service_domain("youtube", "youtube.com"));
        assert!(reg.is_service_domain("youtube", "googlevideo.com"));
        assert!(reg.is_service_domain("youtube", "r1---sn-4g5edn7k.googlevideo.com"));

        assert!(reg.is_service_domain("steam", "steampowered.com"));
        assert!(reg.is_service_domain("discord", "discord.gg"));
    }

    #[test]
    fn test_matches_any_service() {
        let reg = ServiceRegistry::bundled();
        let blocked = vec!["tiktok", "steam"];

        assert_eq!(
            reg.matches_any_service(blocked.iter().copied(), "api.tiktokv.com"),
            Some("tiktok")
        );
        assert_eq!(
            reg.matches_any_service(blocked.iter().copied(), "store.steampowered.com"),
            Some("steam")
        );
        assert_eq!(
            reg.matches_any_service(blocked.iter().copied(), "netflix.com"),
            None
        );
    }

    #[test]
    fn test_adguard_list_format() {
        let json_data = r#"[
            { "id": "custom_app", "rules": ["||custom-app.com^", "cdn.custom.net"] }
        ]"#;
        let reg = ServiceRegistry::from_json(json_data).unwrap();
        assert!(reg.is_service_domain("custom_app", "custom-app.com"));
        assert!(reg.is_service_domain("custom_app", "sub.custom-app.com"));
        assert!(reg.is_service_domain("custom_app", "cdn.custom.net"));
        assert!(!reg.is_service_domain("custom_app", "other.custom.net"));
    }
}
