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

    #[error("DNSSEC validation failure (bogus response)")]
    DnssecBogus,

    #[error("All configured upstream servers are unavailable")]
    AllDown,

    #[error("Upstream IO error: {0}")]
    Io(String),
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
