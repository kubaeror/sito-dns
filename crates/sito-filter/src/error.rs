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

    #[error("Rule compilation task failed: {0}")]
    CompileTaskFailed(String),
}
