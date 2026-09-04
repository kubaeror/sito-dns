//! DNS rewrite configuration per section 10 and 15.

use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

/// Rewrites configuration table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RewritesConfig {
    #[serde(default = "default_true")]
    pub auto_ptr: bool,
    #[serde(default)]
    pub entries: Vec<RewriteEntryConfig>,
}

/// A single local DNS rewrite rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteEntryConfig {
    pub domain: String,
    pub r#type: String, // "A", "AAAA", "CNAME", "PTR", "TXT"
    pub answer: String,
    #[serde(default)]
    pub exception_clients: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rewrites_toml() {
        let toml_str = r#"
auto_ptr = true
entries = [
    { domain = "*.home.arpa", type = "A", answer = "192.168.1.10", exception_clients = ["admin-laptop"] },
    { domain = "printer.lan", type = "A", answer = "192.168.1.50" },
    { domain = "router.lan", type = "CNAME", answer = "gateway.lan" }
]
"#;
        let cfg: RewritesConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.auto_ptr);
        assert_eq!(cfg.entries.len(), 3);
        assert_eq!(cfg.entries[0].domain, "*.home.arpa");
        assert_eq!(cfg.entries[0].r#type, "A");
        assert_eq!(cfg.entries[0].exception_clients, vec!["admin-laptop"]);
    }
}
