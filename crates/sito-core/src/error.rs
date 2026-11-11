//! Error definitions for sito-core and upstream interactions.

use thiserror::Error;

/// Errors that can occur when querying an upstream DNS server.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UpstreamError {
    #[error("Upstream timeout")]
    Timeout,

    #[error("Upstream connection refused")]
    Refused,

    #[error("Upstream TLS error: {0}")]
    Tls(String),

    #[error("Bad or invalid upstream response: {0}")]
    BadResponse(String),

    #[error("Upstream does not support the requested operation")]
    Unsupported,

    #[error("All configured upstream servers are unavailable")]
    AllDown,

    #[error("Upstream IO error: {0}")]
    Io(String),
}

impl UpstreamError {
    /// Stable, low-cardinality kind label for metrics.
    ///
    /// Never returns the error text itself: metrics labels must not grow with
    /// arbitrary upstream payloads.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Refused => "refused",
            Self::Tls(_) => "tls",
            Self::BadResponse(_) => "bad_response",
            Self::Unsupported => "unsupported",
            Self::AllDown => "all_down",
            Self::Io(_) => "io",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upstream_error_kinds_are_bounded() {
        let kinds: std::collections::HashSet<&str> = [
            UpstreamError::Timeout,
            UpstreamError::Refused,
            UpstreamError::Tls("x".repeat(1000)),
            UpstreamError::BadResponse("y".repeat(1000)),
            UpstreamError::Unsupported,
            UpstreamError::AllDown,
            UpstreamError::Io("z".repeat(1000)),
        ]
        .iter()
        .map(UpstreamError::kind)
        .collect();
        assert_eq!(kinds.len(), 7);
        for kind in kinds {
            assert!(kind.len() < 32, "kind labels must stay short: {kind}");
        }
    }
}

/// Errors that can occur when parsing or validating configuration.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    #[error("Configuration parse error: {0}")]
    Parse(String),

    #[error("Configuration validation error on field '{field}': {message}")]
    Validation { field: String, message: String },

    /// A key or table that is not part of the config v2 schema (D5).
    #[error(
        "unknown configuration key '{key}' in [{section}]: this key is not part of config v2 \
         and was rejected instead of being silently ignored. Remove it, or run \
         `sito config migrate --from v1 --to v2 --backup --ignore-unknown-keys` for a v1 document"
    )]
    UnknownKey { section: String, key: String },

    /// A v1 key that config v2 removed. Unlike an unknown typo this key used
    /// to be meaningful, so the error names the replacement when there is one.
    #[error(
        "configuration key '{key}' was removed in config v2{replacement}; delete it. \
         Run `sito config migrate --from v1 --to v2 --backup` to rewrite a v1 document",
        replacement = removed_replacement(.replaced_by.as_deref())
    )]
    RemovedKey {
        key: String,
        replaced_by: Option<String>,
    },

    /// A document that is not config v2 and must be migrated first.
    #[error(
        "unsupported config_version {found}: this build requires config_version = {supported}. \
         Migrate the document with `sito config migrate --from v1 --to v2 --backup` \
         (add `--ignore-unknown-keys` only after reviewing the unknown-key report)"
    )]
    UnsupportedVersion { found: u32, supported: u32 },

    /// A constraint that spans two sections (duplicate binds, listener port
    /// conflicts, an invalid cross-section reference).
    #[error("Configuration cross-section error on '{field}': {message}")]
    CrossSection { field: String, message: String },

    /// The v1→v2 migration itself failed (for example, the migrated document
    /// still does not validate).
    #[error("Configuration migration failed: {0}")]
    Migration(String),

    #[error("IO error reading configuration: {0}")]
    Io(String),
}

fn removed_replacement(replaced_by: Option<&str>) -> String {
    replaced_by.map_or_else(String::new, |replacement| {
        format!(" (use '{replacement}' instead)")
    })
}

impl ConfigError {
    pub fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            field: field.into(),
            message: message.into(),
        }
    }

    pub fn cross_section(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::CrossSection {
            field: field.into(),
            message: message.into(),
        }
    }

    /// The machine-readable kind used by migration reports and API errors.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Parse(_) => "parse",
            Self::Validation { .. } => "validation",
            Self::UnknownKey { .. } => "unknown_key",
            Self::RemovedKey { .. } => "removed_key",
            Self::UnsupportedVersion { .. } => "unsupported_version",
            Self::CrossSection { .. } => "cross_section",
            Self::Migration(_) => "migration",
            Self::Io(_) => "io",
        }
    }
}
