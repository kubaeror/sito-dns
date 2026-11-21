//! DNS rewrite configuration per section 10 and 15.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sito_core::domain::NormalizedDomain;
use sito_core::net::IpNetwork;

use crate::table::{normalize_domain_key, parse_entry_record};

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

impl RewritesConfig {
    /// Validates every configured rewrite entry.
    ///
    /// The error names the offending entry by index so an operator can locate
    /// it in the configuration file.
    ///
    /// # Errors
    ///
    /// Returns the first entry error, prefixed with `entry <index>:`.
    pub fn validate(&self) -> Result<(), String> {
        for (index, entry) in self.entries.iter().enumerate() {
            entry
                .validate()
                .map_err(|error| format!("entry {index}: {error}"))?;
        }
        Ok(())
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

impl RewriteEntryConfig {
    /// Validates one rewrite entry before it is persisted or loaded.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error naming the rejected domain, type, answer
    /// or `exception_clients` value.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_domain()?;
        self.validate_type_and_answer()?;
        for exception in &self.exception_clients {
            validate_exception_client(exception)?;
        }
        Ok(())
    }

    fn validate_domain(&self) -> Result<(), String> {
        let Some(normalized) = normalize_domain_key(&self.domain) else {
            return Err(format!(
                "invalid domain '{}': not a valid DNS name",
                self.domain.trim()
            ));
        };
        if normalized.is_root() {
            return Err("invalid domain '.': the DNS root cannot be a rewrite owner".to_string());
        }
        if let Some(suffix) = normalized.as_str().strip_prefix("*.") {
            let valid_suffix =
                NormalizedDomain::parse(suffix).is_ok_and(|suffix| !suffix.has_wildcard_labels());
            if !valid_suffix {
                return Err(format!(
                    "invalid wildcard domain '{}': only a single leading '*.' wildcard is allowed",
                    self.domain.trim()
                ));
            }
        } else if normalized.has_wildcard_labels() {
            return Err(format!(
                "invalid domain '{}': '*' is only allowed as a leading '*.' wildcard label",
                self.domain.trim()
            ));
        }
        Ok(())
    }

    fn validate_type_and_answer(&self) -> Result<(), String> {
        let record_type = self.r#type.to_ascii_uppercase();
        if !matches!(record_type.as_str(), "A" | "AAAA" | "CNAME" | "PTR" | "TXT") {
            return Err(format!(
                "invalid type '{}': expected one of A, AAAA, CNAME, PTR, TXT",
                self.r#type
            ));
        }

        if record_type == "TXT" {
            if self.answer.is_empty() {
                return Err("invalid answer for TXT rewrite: must not be empty".to_string());
            }
            if self.answer.len() > 65_535 {
                return Err(format!(
                    "invalid answer for TXT rewrite: {} bytes exceeds the 65535-byte maximum",
                    self.answer.len()
                ));
            }
        } else if self.answer.trim().is_empty() {
            return Err(format!(
                "invalid answer for type {record_type}: must not be empty"
            ));
        }
        if parse_entry_record(&self.r#type, &self.answer).is_none() {
            return Err(format!(
                "invalid answer '{}' for type {record_type}",
                self.answer
            ));
        }
        Ok(())
    }
}

/// Validates one `exception_clients` value.
///
/// Accepted forms are an IP address, an IP network in CIDR notation, a MAC
/// address with `:` or `-` separators, or a non-empty client/group name. Names
/// are not required to exist in the client registry: they may be resolved
/// later by an identity integration, and may contain internal spaces and
/// apostrophes. A name containing `/` is not supported: any value with a slash
/// must be a valid CIDR network. Values with leading or trailing whitespace
/// are rejected because matching uses the raw value and a padded value would
/// never match.
fn validate_exception_client(value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err("invalid exception_clients value: must not be empty".to_string());
    }
    if value != value.trim() {
        return Err(format!(
            "invalid exception_clients value '{value}': must not have leading or trailing whitespace"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(format!(
            "invalid exception_clients value '{value}': must not contain control characters"
        ));
    }

    if value.contains('/') {
        return IpNetwork::parse(value)
            .map(|_| ())
            .map_err(|error| format!("invalid exception_clients CIDR '{value}': {error}"));
    }
    if value.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if let Some(groups) = mac_groups(value) {
        if groups.iter().any(|group| group.len() != 2) {
            return Err(format!(
                "invalid exception_clients MAC address '{value}': expected six two-digit hex groups"
            ));
        }
        return Ok(());
    }
    // Anything else is a client or group name (internal spaces are allowed).
    Ok(())
}

/// Returns the six hex groups of a MAC-shaped value, if it has that shape.
///
/// A MAC-shaped value uses exactly one separator kind (`:` or `-`), six
/// non-empty groups and hex digits only. Callers still enforce two digits per
/// group; this only classifies the value as an attempted MAC address.
fn mac_groups(value: &str) -> Option<Vec<&str>> {
    let separator = match (value.contains(':'), value.contains('-')) {
        (true, false) => ':',
        (false, true) => '-',
        _ => return None,
    };
    let groups: Vec<&str> = value.split(separator).collect();
    if groups.len() == 6
        && groups
            .iter()
            .all(|group| !group.is_empty() && group.chars().all(|c| c.is_ascii_hexdigit()))
    {
        Some(groups)
    } else {
        None
    }
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

    fn entry(domain: &str, r#type: &str, answer: &str) -> RewriteEntryConfig {
        RewriteEntryConfig {
            domain: domain.to_string(),
            r#type: r#type.to_string(),
            answer: answer.to_string(),
            exception_clients: Vec::new(),
        }
    }

    #[test]
    fn test_valid_entries_validate() {
        for entry in [
            entry("printer.lan", "A", "192.168.1.50"),
            entry("printer-v6.lan", "AAAA", "fd00::50"),
            entry("router.lan", "CNAME", "gateway.lan"),
            entry("1.0.0.10.in-addr.arpa", "PTR", "printer.lan"),
            entry("text.lan", "TXT", "hello world"),
            entry("lower.lan", "a", "192.168.1.51"),
        ] {
            entry
                .validate()
                .unwrap_or_else(|error| panic!("{entry:?} must validate: {error}"));
        }
    }

    #[test]
    fn test_valid_wildcard_and_exception_clients_validate() {
        let mut wildcard = entry("*.home.arpa", "A", "192.168.1.10");
        wildcard.exception_clients = vec![
            "192.168.1.20".to_string(),
            "10.0.0.0/8".to_string(),
            "fd00::/8".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            "aa-bb-cc-dd-ee-ff".to_string(),
            "admin-laptop".to_string(),
            "admins".to_string(),
            "Admin Laptop".to_string(),
            "Jane's Phone".to_string(),
        ];
        wildcard
            .validate()
            .expect("wildcard with IP/CIDR/MAC/name exceptions must validate");
    }

    #[test]
    fn test_valid_domains_include_idn_and_trailing_dot() {
        for domain in [
            "printer.lan.",
            "MÜNCHEN.de.",
            "*.BÜCHER.example.",
            "xn--mnchen-3ya.de",
        ] {
            entry(domain, "A", "192.168.1.1")
                .validate()
                .unwrap_or_else(|error| panic!("{domain:?} must validate: {error}"));
        }
    }

    #[test]
    fn test_rejects_nested_wildcards() {
        for domain in ["*.*.example.com", "*.foo.*.bar", "*.*"] {
            let err = entry(domain, "A", "192.168.1.1")
                .validate()
                .expect_err("nested wildcard must be rejected");
            assert!(
                err.contains("wildcard") || err.contains("domain"),
                "error for {domain:?} must name the wildcard/domain: {err}"
            );
        }
    }

    #[test]
    fn test_rejects_invalid_domains() {
        for domain in ["bad..name", "*", "foo.*.bar", "*.", "", "   ", "."] {
            let err = entry(domain, "A", "192.168.1.1")
                .validate()
                .expect_err("invalid domain must be rejected");
            assert!(
                err.contains("domain"),
                "error for {domain:?} must name the domain: {err}"
            );
        }
    }

    #[test]
    fn test_rejects_invalid_type_and_answers() {
        let err = entry("host.lan", "MX", "mx.lan")
            .validate()
            .expect_err("unsupported type must be rejected");
        assert!(err.contains("type"), "got: {err}");

        for (r#type, answer) in [
            ("A", "192.168.1.256"),
            ("AAAA", "gggg::1"),
            ("CNAME", "bad name"),
            ("CNAME", ""),
            ("PTR", "bad name"),
            ("PTR", "   "),
        ] {
            let err = entry("host.lan", r#type, answer).validate().unwrap_err();
            assert!(
                err.contains("answer"),
                "{type} answer {answer:?} must be named in: {err}"
            );
        }
    }

    #[test]
    fn test_rejects_invalid_txt_answers() {
        let err = entry("txt.lan", "TXT", "")
            .validate()
            .expect_err("empty TXT must be rejected");
        assert!(err.contains("TXT"), "got: {err}");

        let too_long = "a".repeat(65_536);
        let err = entry("txt.lan", "TXT", &too_long)
            .validate()
            .expect_err("over-65535-byte TXT must be rejected");
        assert!(err.contains("65535"), "got: {err}");

        // The exact limit is accepted, as is a whitespace-only value (a valid
        // non-empty TXT character-string).
        entry("txt.lan", "TXT", &"a".repeat(65_535))
            .validate()
            .expect("65535-byte TXT must validate");
        entry("txt.lan", "TXT", "   ")
            .validate()
            .expect("whitespace-only TXT must validate");
    }

    #[test]
    fn test_rejects_invalid_exception_clients() {
        for exception in [
            "",
            "   ",
            " admin-laptop",
            "admin-laptop ",
            "admin\tlaptop",
            "10.0.0.0/99",
            "not/a/cidr",
            "aa:bb:cc:dd:ee:fff",
            "aa:bb:cc:dd:ee:1234",
        ] {
            let mut candidate = entry("host.lan", "A", "192.168.1.1");
            candidate.exception_clients = vec![exception.to_string()];
            let err = candidate
                .validate()
                .expect_err(&format!("{exception:?} must be rejected"));
            assert!(
                err.contains("exception"),
                "error for {exception:?} must name the exception: {err}"
            );
        }
    }

    #[test]
    fn test_config_validate_prefixes_entry_index() {
        let config = RewritesConfig {
            auto_ptr: false,
            ttl: 60,
            entries: vec![
                entry("printer.lan", "A", "192.168.1.50"),
                entry("bad..name", "A", "192.168.1.51"),
            ],
        };
        let err = config.validate().expect_err("invalid entry must fail");
        assert!(err.contains("entry 1"), "got: {err}");

        RewritesConfig {
            auto_ptr: false,
            ttl: 60,
            entries: vec![entry("printer.lan", "A", "192.168.1.50")],
        }
        .validate()
        .expect("valid config");
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
