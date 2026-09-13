//! DNS rewrite configuration per section 10 and 15.

use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn default_ttl() -> u32 {
    60
}

/// Rewrites configuration table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewritesConfig {
    #[serde(default = "default_true")]
    pub auto_ptr: bool,
    /// TTL (seconds) applied to synthesized local rewrite records.
    ///
    /// Defaults to 60. Values are passed through to clients as-is; the local
    /// records are not cached by this resolver.
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    #[serde(default)]
    pub entries: Vec<RewriteEntryConfig>,
}

impl Default for RewritesConfig {
    fn default() -> Self {
        Self {
            auto_ptr: false,
            ttl: default_ttl(),
            entries: Vec::new(),
        }
    }
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
