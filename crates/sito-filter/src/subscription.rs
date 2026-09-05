//! Subscription management with conditional HTTP updates, retries, and disk caching.

use crate::downloader::{
    DEFAULT_DOWNLOAD_TIMEOUT, DEFAULT_MAX_LIST_BYTES, cache_path_for_list, read_from_cache,
    save_to_cache,
};
use crate::error::FilterError;
use reqwest::StatusCode;
use reqwest::header::{IF_MODIFIED_SINCE, IF_NONE_MATCH};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Cached metadata for a downloaded blocklist to support conditional HTTP updates.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ListMetadata {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub updated_at_secs: u64,
}

/// Generates the file path for storing subscription metadata.
pub fn meta_path_for_list(data_dir: &Path, list_name: &str) -> PathBuf {
    let sanitized: String = list_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    data_dir
        .join("lists")
        .join(format!("{sanitized}.meta.json"))
}

/// Reads list metadata from disk cache.
pub async fn read_metadata(path: &Path) -> Option<ListMetadata> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    serde_json::from_str(&content).ok()
}

/// Saves list metadata to disk cache.
pub async fn save_metadata(path: &Path, meta: &ListMetadata) -> Result<(), FilterError> {
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let content = serde_json::to_string(meta).unwrap_or_default();
    tokio::fs::write(path, content)
        .await
        .map_err(|e| FilterError::Io {
            path: path.to_path_buf(),
            source: e,
        })
}

/// Manages fetching blocklists with ETag/If-Modified-Since caching and retries.
#[derive(Clone, Debug)]
pub struct SubscriptionFetcher {
    client: reqwest::Client,
    max_bytes: usize,
    timeout: Duration,
    max_retries: usize,
    initial_backoff: Duration,
}

impl Default for SubscriptionFetcher {
    fn default() -> Self {
        Self::new(
            DEFAULT_DOWNLOAD_TIMEOUT,
            DEFAULT_MAX_LIST_BYTES,
            3,
            Duration::from_millis(100),
        )
    }
}

impl SubscriptionFetcher {
    /// Creates a new `SubscriptionFetcher`.
    pub fn new(
        timeout: Duration,
        max_bytes: usize,
        max_retries: usize,
        initial_backoff: Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("sito-dns/0.1.0")
            .build()
            .unwrap_or_default();

        Self {
            client,
            max_bytes,
            timeout,
            max_retries,
            initial_backoff,
        }
    }

    /// Returns the configured download timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Fetches blocklist content, honoring HTTP conditional caching (`ETag`, `If-Modified-Since`),
    /// retrying transient failures up to `max_retries` with exponential backoff,
    /// and falling back to disk cache if available.
    pub async fn fetch_or_cached(
        &self,
        list_name: &str,
        url: &str,
        data_dir: &Path,
    ) -> Result<String, FilterError> {
        let cache_path = cache_path_for_list(data_dir, list_name);
        let meta_path = meta_path_for_list(data_dir, list_name);

        // Handle file:// URI scheme directly
        if let Some(file_path) = url.strip_prefix("file://") {
            debug!(list = %list_name, path = %file_path, "Reading blocklist from local file");
            return tokio::fs::read_to_string(file_path)
                .await
                .map_err(|e| FilterError::Io {
                    path: PathBuf::from(file_path),
                    source: e,
                });
        }

        // Restrict HTTP list download schemes to http and https (SSRF protection)
        let url_lower = url.trim().to_ascii_lowercase();
        if !url_lower.starts_with("http://") && !url_lower.starts_with("https://") {
            return Err(FilterError::InvalidUrl {
                url: url.to_string(),
                reason: "unsupported scheme: only http, https, and file schemes are permitted"
                    .to_string(),
            });
        }

        let existing_meta = read_metadata(&meta_path).await;
        let mut last_error = None;
        let mut backoff = self.initial_backoff;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                debug!(list = %list_name, attempt, backoff_ms = backoff.as_millis(), "Retrying list download with backoff");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(10));
            }

            let mut req = self.client.get(url);
            if let Some(meta) = &existing_meta {
                if let Some(etag) = &meta.etag {
                    req = req.header(IF_NONE_MATCH, etag);
                }
                if let Some(lm) = &meta.last_modified {
                    req = req.header(IF_MODIFIED_SINCE, lm);
                }
            }

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status == StatusCode::NOT_MODIFIED {
                        info!(list = %list_name, "Blocklist unchanged (HTTP 304 Not Modified), serving disk cache");
                        match read_from_cache(&cache_path).await {
                            Ok(content) => return Ok(content),
                            Err(e) => {
                                warn!(list = %list_name, error = %e, "Cache missing despite 304; continuing to fallback");
                                last_error = Some(e);
                                break;
                            }
                        }
                    }

                    if !status.is_success() {
                        let is_server_err = status.is_server_error();
                        let req_err = resp.error_for_status().unwrap_err();
                        last_error = Some(FilterError::DownloadFailed {
                            list: list_name.to_string(),
                            url: url.to_string(),
                            source: req_err,
                        });
                        if is_server_err && attempt < self.max_retries {
                            continue;
                        }
                        break;
                    }

                    if let Some(len) = resp.content_length() {
                        if len as usize > self.max_bytes {
                            return Err(FilterError::ListTooLarge {
                                list: list_name.to_string(),
                                size: len as usize,
                                limit: self.max_bytes,
                            });
                        }
                    }

                    // Extract ETag and Last-Modified headers before consuming body
                    let new_etag = resp
                        .headers()
                        .get("etag")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                    let new_last_modified = resp
                        .headers()
                        .get("last-modified")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);

                    let bytes = match resp.bytes().await {
                        Ok(b) => b,
                        Err(e) => {
                            last_error = Some(FilterError::DownloadFailed {
                                list: list_name.to_string(),
                                url: url.to_string(),
                                source: e,
                            });
                            if attempt < self.max_retries {
                                continue;
                            }
                            break;
                        }
                    };

                    if bytes.len() > self.max_bytes {
                        return Err(FilterError::ListTooLarge {
                            list: list_name.to_string(),
                            size: bytes.len(),
                            limit: self.max_bytes,
                        });
                    }

                    let Ok(content) = String::from_utf8(bytes.to_vec()) else {
                        return Err(FilterError::InvalidUrl {
                            url: url.to_string(),
                            reason: "Blocklist content is not valid UTF-8".to_string(),
                        });
                    };

                    // Save to disk cache
                    if let Err(e) = save_to_cache(&cache_path, &content).await {
                        warn!(list = %list_name, error = %e, "Failed to save blocklist to disk cache");
                    }

                    // Save metadata
                    let updated_secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    let meta = ListMetadata {
                        etag: new_etag,
                        last_modified: new_last_modified,
                        updated_at_secs: updated_secs,
                    };
                    let _ = save_metadata(&meta_path, &meta).await;

                    info!(list = %list_name, bytes = content.len(), "Successfully fetched blocklist");
                    return Ok(content);
                }
                Err(e) => {
                    last_error = Some(FilterError::DownloadFailed {
                        list: list_name.to_string(),
                        url: url.to_string(),
                        source: e,
                    });
                    if attempt < self.max_retries {
                        continue;
                    }
                    break;
                }
            }
        }

        // All download attempts failed: attempt disk cache fallback
        warn!(
            list = %list_name,
            url = %url,
            "Blocklist download failed; attempting disk cache fallback"
        );
        match read_from_cache(&cache_path).await {
            Ok(cached) => {
                info!(
                    list = %list_name,
                    path = %cache_path.display(),
                    bytes = cached.len(),
                    "Loaded blocklist from disk cache fallback"
                );
                Ok(cached)
            }
            Err(cache_err) => {
                warn!(
                    list = %list_name,
                    cache_error = %cache_err,
                    "Disk cache fallback unavailable"
                );
                Err(last_error.unwrap_or(cache_err))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metadata_save_and_read() {
        let temp_dir = std::env::temp_dir().join(format!("sito_meta_test_{}", std::process::id()));
        let meta_file = meta_path_for_list(&temp_dir, "test_list");

        let meta = ListMetadata {
            etag: Some("\"abc123etag\"".to_string()),
            last_modified: Some("Fri, 05 Sep 2026 00:00:00 GMT".to_string()),
            updated_at_secs: 123_456_789,
        };

        save_metadata(&meta_file, &meta).await.unwrap();
        let loaded = read_metadata(&meta_file).await.unwrap();
        assert_eq!(meta, loaded);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_fetch_file_uri_with_fetcher() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_fetcher_file_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let list_file = temp_dir.join("hosts.txt");
        tokio::fs::write(&list_file, "||test-fetcher.com^\n")
            .await
            .unwrap();

        let fetcher = SubscriptionFetcher::default();
        let uri = format!("file://{}", list_file.display());
        let content = fetcher
            .fetch_or_cached("local", &uri, &temp_dir)
            .await
            .unwrap();

        assert_eq!(content, "||test-fetcher.com^\n");

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
