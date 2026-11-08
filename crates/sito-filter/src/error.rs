//! Error types for the filter engine and list management.

use std::path::PathBuf;
use thiserror::Error;

/// Errors produced during blocklist download, caching, and parsing.
#[derive(Debug, Error)]
pub enum FilterError {
    #[error("Failed to download blocklist '{list}' from '{url}': {source}")]
    DownloadFailed {
        list: String,
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("Blocklist '{list}' exceeded size limit of {limit} bytes (actual: {size} bytes)")]
    ListTooLarge {
        list: String,
        size: usize,
        limit: usize,
    },

    #[error("I/O error for path '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Invalid URL '{url}': {reason}")]
    InvalidUrl { url: String, reason: String },

    #[error("Cached blocklist '{path}' failed its integrity check: {reason}")]
    CacheCorrupted { path: PathBuf, reason: String },

    #[error("Rule compilation task failed: {0}")]
    CompileTaskFailed(String),

    #[error("No filter list sources could be loaded ({failed} failed): {details}")]
    NoSourcesLoaded { failed: usize, details: String },

    #[error("Filtering is enabled but no filter sources are configured")]
    NoSourcesConfigured,

    #[error("Configured filter sources yielded no usable rules: {details}")]
    NoUsableRules { details: String },

    #[error("Blocklist '{list}' returned an empty response")]
    EmptyList { list: String },

    #[error("Blocklist '{list}' returned an HTML/XML document instead of a rule list")]
    HtmlResponse { list: String },

    #[error("Blocklist '{list}' yielded no rules after parsing")]
    NoRulesYielded { list: String },

    #[error("Filter rule set exceeds the configured limit of {limit} rules (parsed: {count})")]
    TooManyRules { count: usize, limit: usize },

    #[error(
        "Regex compilation exceeded the configured budget of {limit_ms} ms (elapsed: {elapsed_ms} ms); previous snapshot retained"
    )]
    CompileBudgetExceeded { elapsed_ms: u64, limit_ms: u64 },
}
