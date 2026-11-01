//! Downloader and disk-cache manager for blocklists.
//!
//! The actual fetch logic (schemes, SSRF guards, conditional HTTP, retries,
//! streaming size cap, disk fallback) lives in [`crate::subscription::SubscriptionFetcher`];
//! [`ListDownloader`] is a thin configuration holder that delegates to it so
//! there is a single downloader implementation.

use crate::error::FilterError;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_MAX_LIST_BYTES: usize = 64 * 1024 * 1024; // 64 MB
pub const DEFAULT_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// Manages fetching blocklists over HTTP(S) and falling back to disk cache.
#[derive(Clone, Debug)]
pub struct ListDownloader {
    timeout: Duration,
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
        Self { timeout, max_bytes }
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
            self.timeout,
            self.max_bytes,
            3,
            Duration::from_millis(50),
        )
        .with_file_root(data_dir);
        fetcher.fetch_or_cached(list_name, url, data_dir).await
    }
}

/// Builds the deterministic disk-cache key for a list name.
///
/// The sanitized name is kept as a readable prefix, while a stable FNV-1a hash
/// suffix guarantees that distinct list names mapping to the same sanitized
/// form (e.g. `a/b` and `a_b`) never collide on one cache file.
pub(crate) fn cache_key_for_list(list_name: &str) -> String {
    let mut hasher = fnv::FnvHasher::default();
    list_name.hash(&mut hasher);
    let digest = hasher.finish();
    let sanitized: String = list_name
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        format!("{digest:016x}")
    } else {
        format!("{sanitized}-{digest:016x}")
    }
}

/// Generates a sanitized file path for caching a list on disk.
pub fn cache_path_for_list(data_dir: &Path, list_name: &str) -> PathBuf {
    data_dir
        .join("lists")
        .join(format!("{}.txt", cache_key_for_list(list_name)))
}

/// Reads list content from disk cache, applying the default size cap.
pub async fn read_from_cache(path: &Path) -> Result<String, FilterError> {
    read_from_cache_capped(path, DEFAULT_MAX_LIST_BYTES).await
}

/// Reads list content from disk cache, rejecting files larger than
/// `max_bytes` before reading them into memory.
pub async fn read_from_cache_capped(path: &Path, max_bytes: usize) -> Result<String, FilterError> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|e| FilterError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    if metadata.len() > max_bytes as u64 {
        return Err(FilterError::ListTooLarge {
            list: path.display().to_string(),
            size: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
            limit: max_bytes,
        });
    }
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
    async fn test_cache_read_rejects_oversized_file() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_cache_cap_test_{}", std::process::id()));
        let cache_file = cache_path_for_list(&temp_dir, "Oversized");
        save_to_cache(&cache_file, "0123456789").await.unwrap();

        let err = read_from_cache_capped(&cache_file, 4)
            .await
            .expect_err("files over the cap must be rejected");
        assert!(
            matches!(err, FilterError::ListTooLarge { limit: 4, .. }),
            "unexpected error: {err}"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[test]
    fn test_cache_paths_do_not_collide_for_similar_names() {
        // These previously sanitized to the same file name.
        let a = cache_path_for_list(Path::new("/tmp/sito"), "a/b");
        let b = cache_path_for_list(Path::new("/tmp/sito"), "a_b");
        assert_ne!(a, b);
        assert_ne!(a.file_name(), b.file_name());

        // The same name always maps to the same path (stable across calls).
        assert_eq!(
            cache_path_for_list(Path::new("/tmp/sito"), "same"),
            cache_path_for_list(Path::new("/tmp/sito"), "same")
        );
    }

    #[tokio::test]
    async fn test_fetch_file_uri_inside_data_dir() {
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
