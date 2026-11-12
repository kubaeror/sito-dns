//! DNSSEC policy types shared by the validator and response shaping.
//!
//! The mode lives in `sito-core` so `sito-proto` can make response-shaping
//! decisions without depending on the validator crate (which depends on
//! `sito-proto`). `sito-dnssec` re-exports it as its historical
//! `sito_dnssec::DnssecMode` path.

/// DNSSEC validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnssecMode {
    /// Strict validation: bogus queries result in SERVFAIL with EDE.
    #[default]
    Validate,
    /// Permissive validation: log bogus queries and clear AD bit, but return response.
    LogOnly,
    /// DNSSEC validation disabled.
    Disabled,
}

impl From<&str> for DnssecMode {
    fn from(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "log-only" | "log_only" | "log_fail" | "permissive" => Self::LogOnly,
            "disabled" | "off" => Self::Disabled,
            _ => Self::Validate,
        }
    }
}
