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

    #[error("DNSSEC validation failure (bogus response)")]
    DnssecBogus,

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
            Self::DnssecBogus => "dnssec_bogus",
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
            UpstreamError::DnssecBogus,
            UpstreamError::AllDown,
            UpstreamError::Io("z".repeat(1000)),
        ]
        .iter()
        .map(UpstreamError::kind)
        .collect();
        assert_eq!(kinds.len(), 8);
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

    #[error("IO error reading configuration: {0}")]
    Io(String),
}

impl ConfigError {
    pub fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            field: field.into(),
            message: message.into(),
        }
    }
}
