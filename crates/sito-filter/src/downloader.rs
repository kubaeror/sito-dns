//! Downloader and disk-cache manager for blocklists.

use crate::error::FilterError;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_MAX_LIST_BYTES: usize = 64 * 1024 * 1024; // 64 MB
pub const DEFAULT_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// Manages fetching blocklists over HTTP(S) and falling back to disk cache.
#[derive(Clone, Debug)]
pub struct ListDownloader {
    client: reqwest::Client,
    max_bytes: usize,
}

impl Default for ListDownloader {
    fn default() -> Self {
        Self::new(DEFAULT_DOWNLOAD_TIMEOUT, DEFAULT_MAX_LIST_BYTES)
    }
}

impl ListDownloader {
    /// Creates a new `ListDownloader` with specified timeout and byte limit.
    pub fn new(timeout: Duration, max_bytes: usize) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("sito-dns/0.1.0")
            .build()
            .unwrap_or_default();

        Self { client, max_bytes }
    }

    /// Fetches a list from URL or file:// URI, falling back to disk cache if download fails.
    /// Honors HTTP ETag and If-Modified-Since caching headers and retries with backoff.
    pub async fn fetch_or_cached(
        &self,
        list_name: &str,
        url: &str,
        data_dir: &Path,
    ) -> Result<String, FilterError> {
        let fetcher = crate::subscription::SubscriptionFetcher::new(
            Duration::from_secs(60),
            self.max_bytes,
            3,
            Duration::from_millis(50),
        );
        fetcher.fetch_or_cached(list_name, url, data_dir).await
    }

    /// Downloads a blocklist over HTTP/HTTPS with size checking.
    pub async fn download(&self, list_name: &str, url: &str) -> Result<String, FilterError> {
        let url_lower = url.trim().to_ascii_lowercase();
        if !url_lower.starts_with("http://") && !url_lower.starts_with("https://") {
            return Err(FilterError::InvalidUrl {
                url: url.to_string(),
                reason:
                    "unsupported scheme: only http and https are permitted for network downloads"
                        .to_string(),
            });
        }

        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| FilterError::DownloadFailed {
                list: list_name.to_string(),
                url: url.to_string(),
                source: e,
            })?;

        let status = resp.status();
        if !status.is_success() {
            let req_err = resp.error_for_status().unwrap_err();
            return Err(FilterError::DownloadFailed {
                list: list_name.to_string(),
                url: url.to_string(),
                source: req_err,
            });
        }

        if let Some(content_length) = resp.content_length() {
            if content_length as usize > self.max_bytes {
                return Err(FilterError::ListTooLarge {
                    list: list_name.to_string(),
                    size: content_length as usize,
                    limit: self.max_bytes,
                });
            }
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| FilterError::DownloadFailed {
                list: list_name.to_string(),
                url: url.to_string(),
                source: e,
            })?;

        if bytes.len() > self.max_bytes {
            return Err(FilterError::ListTooLarge {
                list: list_name.to_string(),
                size: bytes.len(),
                limit: self.max_bytes,
            });
        }

        String::from_utf8(bytes.to_vec()).map_err(|_| FilterError::InvalidUrl {
            url: url.to_string(),
            reason: "Blocklist content is not valid UTF-8".to_string(),
        })
    }
}

/// Generates a sanitized file path for caching a list on disk.
pub fn cache_path_for_list(data_dir: &Path, list_name: &str) -> PathBuf {
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
    data_dir.join("lists").join(format!("{sanitized}.txt"))
}

/// Reads list content from disk cache.
pub async fn read_from_cache(path: &Path) -> Result<String, FilterError> {
    tokio::fs::read_to_string(path)
        .await
        .map_err(|e| FilterError::Io {
            path: path.to_path_buf(),
            source: e,
        })
}

/// Saves list content to disk cache, creating parent directories if needed.
pub async fn save_to_cache(path: &Path, content: &str) -> Result<(), FilterError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| FilterError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
    }

    tokio::fs::write(path, content)
        .await
        .map_err(|e| FilterError::Io {
            path: path.to_path_buf(),
            source: e,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_save_and_read() {
        let temp_dir = std::env::temp_dir().join(format!("sito_cache_test_{}", std::process::id()));
        let cache_file = cache_path_for_list(&temp_dir, "My Test List");

        let content = "0.0.0.0 blocked.test\n";
        save_to_cache(&cache_file, content).await.unwrap();

        let read_back = read_from_cache(&cache_file).await.unwrap();
        assert_eq!(read_back, content);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_fetch_file_uri() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_file_uri_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let file_path = temp_dir.join("hosts.txt");
        tokio::fs::write(&file_path, "0.0.0.0 file-blocked.com\n")
            .await
            .unwrap();

        let downloader = ListDownloader::default();
        let uri = format!("file://{}", file_path.display());
        let res = downloader
            .fetch_or_cached("local", &uri, &temp_dir)
            .await
            .unwrap();
        assert!(res.contains("file-blocked.com"));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
