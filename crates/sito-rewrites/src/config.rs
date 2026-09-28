//! DNS rewrite configuration per section 10 and 15.

use serde::{Deserialize, Serialize};

/// Single source of truth for [`RewritesConfig::auto_ptr`].
///
/// The serde field default and the section-level `impl Default` must agree so
/// that an absent `[rewrites]` section (`RewritesConfig::default()`, used by
/// `crates/sito/src/server.rs`) behaves exactly like a present section that
/// omits the key. Auto-PTR is opt-in: it is `false` by default in both paths.
fn default_auto_ptr() -> bool {
    false
}

fn default_ttl() -> u32 {
    60
}

/// Rewrites configuration table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewritesConfig {
    /// Automatically synthesize reverse PTR records (`in-addr.arpa` /
    /// `ip6.arpa`) for local A/AAAA rewrites in RFC 1918 / ULA ranges.
    ///
    /// Opt-in; defaults to `false`, both when the `[rewrites]` section is
    /// absent and when the section omits this key.
    #[serde(default = "default_auto_ptr")]
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
            auto_ptr: default_auto_ptr(),
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

    /// Audit 6 / WP-6.5: an absent `[rewrites]` section used to default
    /// `auto_ptr` to `false` while a present section that omitted the key
    /// defaulted it to `true`. Both paths must agree (opt-in, `false`).
    #[test]
    fn test_auto_ptr_default_agrees_between_serde_and_default() {
        assert!(
            !RewritesConfig::default().auto_ptr,
            "section default must be auto_ptr = false"
        );

        let omitted: RewritesConfig = toml::from_str("ttl = 60\nentries = []\n").unwrap();
        assert_eq!(
            omitted.auto_ptr,
            RewritesConfig::default().auto_ptr,
            "a present section that omits auto_ptr must match the section default"
        );

        let explicit_true: RewritesConfig = toml::from_str("auto_ptr = true\n").unwrap();
        assert!(explicit_true.auto_ptr);
        let explicit_false: RewritesConfig = toml::from_str("auto_ptr = false\n").unwrap();
        assert!(!explicit_false.auto_ptr);
    }

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
