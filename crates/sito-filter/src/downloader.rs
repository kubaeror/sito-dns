//! Downloader and disk-cache manager for blocklists.
//!
//! The actual fetch logic (schemes, SSRF guards, conditional HTTP, retries,
//! streaming size cap, disk fallback) lives in [`crate::subscription::SubscriptionFetcher`];
//! [`ListDownloader`] is a thin configuration holder that delegates to it so
//! there is a single downloader implementation.

use crate::error::FilterError;
use crate::subscription::read_metadata;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

pub const DEFAULT_MAX_LIST_BYTES: usize = 64 * 1024 * 1024; // 64 MB
pub const DEFAULT_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum size of a list metadata file accepted by the cache readers.
pub const MAX_METADATA_BYTES: usize = 16 * 1024;

/// Monotonic suffix keeping concurrent temporary cache files distinct.
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Returns a unique temporary path next to `path` (same directory, hence the
/// same filesystem) so the final rename is atomic.
fn temp_path_for(path: &Path) -> PathBuf {
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = path.file_name().map_or_else(
        || "cache".into(),
        |name| name.to_string_lossy().into_owned(),
    );
    path.with_file_name(format!(".{file_name}.tmp-{}-{counter}", std::process::id()))
}

/// Writes `contents` to `path` through a temporary file and an atomic rename.
///
/// Readers can therefore never observe a truncated cache file: the previous
/// contents remain in place until the new file is complete and fsynced.
pub(crate) async fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), FilterError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| FilterError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
    }

    let tmp = temp_path_for(path);
    let written = async {
        let mut file = tokio::fs::File::create(&tmp).await?;
        file.write_all(contents).await?;
        file.sync_all().await?;
        Ok::<(), std::io::Error>(())
    }
    .await;
    if let Err(e) = written {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(FilterError::Io {
            path: tmp,
            source: e,
        });
    }

    if let Err(e) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(FilterError::Io {
            path: path.to_path_buf(),
            source: e,
        });
    }
    Ok(())
}

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
///
/// The write is atomic (temp file + rename): a crash or a full disk can no
/// longer leave a truncated cache file behind that the reader would trust.
pub async fn save_to_cache(path: &Path, content: &str) -> Result<(), FilterError> {
    write_atomic(path, content.as_bytes()).await
}

/// Reads a cached list and rejects it unless its metadata records matching
/// integrity signals (byte length and line count).
///
/// A cache file is trusted only when it is accompanied by metadata written
/// after the same fetch. Truncated, partially replaced or unverifiable
/// (legacy, metadata-less) caches are refused so the caller re-downloads the
/// list instead of serving partial or stale content.
pub(crate) async fn read_cache_verified(
    cache_path: &Path,
    meta_path: &Path,
    list_name: &str,
    max_bytes: usize,
) -> Result<String, FilterError> {
    let content = read_from_cache_capped(cache_path, max_bytes).await?;
    let Some(meta) = read_metadata(meta_path).await else {
        return Err(FilterError::CacheCorrupted {
            path: cache_path.to_path_buf(),
            reason: format!("list '{list_name}' cache has no readable metadata"),
        });
    };
    let (Some(expected_len), Some(expected_lines)) = (meta.content_len, meta.line_count) else {
        return Err(FilterError::CacheCorrupted {
            path: cache_path.to_path_buf(),
            reason: format!("list '{list_name}' cache metadata has no integrity fields"),
        });
    };
    let actual_len = content.len() as u64;
    if actual_len != expected_len {
        return Err(FilterError::CacheCorrupted {
            path: cache_path.to_path_buf(),
            reason: format!(
                "list '{list_name}' cache is {actual_len} bytes but {expected_len} bytes were recorded"
            ),
        });
    }
    let actual_lines = content.lines().count();
    if actual_lines != expected_lines {
        return Err(FilterError::CacheCorrupted {
            path: cache_path.to_path_buf(),
            reason: format!(
                "list '{list_name}' cache has {actual_lines} lines but {expected_lines} were recorded"
            ),
        });
    }
    Ok(content)
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

    /// Regression (audit 6, WP-3.9): cache writes used to truncate the live
    /// file in place, so a crash mid-write left a partially written list that
    /// the next start trusted. Writes must replace the file atomically.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_cache_save_replaces_file_atomically() {
        use std::os::unix::fs::MetadataExt;

        let temp_dir =
            std::env::temp_dir().join(format!("sito_cache_atomic_{}", std::process::id()));
        let cache_file = cache_path_for_list(&temp_dir, "Atomic");
        save_to_cache(&cache_file, "0.0.0.0 one.example\n")
            .await
            .unwrap();
        let inode_before = std::fs::metadata(&cache_file).unwrap().ino();

        save_to_cache(&cache_file, "0.0.0.0 two.example\n")
            .await
            .unwrap();

        let inode_after = std::fs::metadata(&cache_file).unwrap().ino();
        assert_ne!(
            inode_before, inode_after,
            "the cache file must be replaced by rename, not truncated in place"
        );
        assert_eq!(
            tokio::fs::read_to_string(&cache_file).await.unwrap(),
            "0.0.0.0 two.example\n"
        );

        // No temporary files may be left behind.
        let mut entries = tokio::fs::read_dir(cache_file.parent().unwrap())
            .await
            .unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            assert!(
                !entry.file_name().to_string_lossy().contains(".tmp-"),
                "leftover temporary file: {:?}",
                entry.file_name()
            );
        }

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// Regression (audit 6, WP-3.9): a truncated cache file (or one whose
    /// line structure changed) must be rejected instead of served as rules.
    #[tokio::test]
    async fn test_truncated_cache_is_rejected() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_cache_trunc_{}", std::process::id()));
        let cache_file = cache_path_for_list(&temp_dir, "Truncated");
        let meta_file = crate::subscription::meta_path_for_list(&temp_dir, "Truncated");
        let content = "0.0.0.0 one.example\n0.0.0.0 two.example\n";
        save_to_cache(&cache_file, content).await.unwrap();
        crate::subscription::save_metadata(
            &meta_file,
            &crate::subscription::ListMetadata {
                content_len: Some(content.len() as u64),
                line_count: Some(content.lines().count()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // The intact cache verifies.
        let verified =
            read_cache_verified(&cache_file, &meta_file, "Truncated", DEFAULT_MAX_LIST_BYTES)
                .await
                .unwrap();
        assert_eq!(verified, content);

        // A truncated file (crash mid-write) is refused.
        tokio::fs::write(&cache_file, &content[..10]).await.unwrap();
        let err = read_cache_verified(&cache_file, &meta_file, "Truncated", DEFAULT_MAX_LIST_BYTES)
            .await
            .expect_err("truncated cache must be rejected");
        assert!(
            matches!(err, FilterError::CacheCorrupted { .. }),
            "unexpected error: {err}"
        );

        // Same byte length but different line structure is refused too, so a
        // byte-count-only check cannot be bypassed by equal-length damage.
        let same_len = format!("{}  ", content.replace('\n', ""));
        assert_eq!(same_len.len(), content.len(), "test precondition");
        assert_eq!(same_len.lines().count(), 1, "test precondition");
        tokio::fs::write(&cache_file, same_len).await.unwrap();
        let err = read_cache_verified(&cache_file, &meta_file, "Truncated", DEFAULT_MAX_LIST_BYTES)
            .await
            .expect_err("line-structure mismatch must be rejected");
        assert!(
            matches!(err, FilterError::CacheCorrupted { .. }),
            "unexpected error: {err}"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// A cache file without metadata is unverifiable and must not be trusted.
    #[tokio::test]
    async fn test_cache_without_metadata_is_rejected() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_cache_nometa_{}", std::process::id()));
        let cache_file = cache_path_for_list(&temp_dir, "NoMeta");
        let meta_file = crate::subscription::meta_path_for_list(&temp_dir, "NoMeta");
        save_to_cache(&cache_file, "0.0.0.0 orphan.example\n")
            .await
            .unwrap();

        let err = read_cache_verified(&cache_file, &meta_file, "NoMeta", DEFAULT_MAX_LIST_BYTES)
            .await
            .expect_err("metadata-less cache must be rejected");
        assert!(
            matches!(err, FilterError::CacheCorrupted { .. }),
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

    /// D-07: the byte cap passed to `ListDownloader::new` must be enforced for
    /// `file://` lists, not just for HTTP responses.
    #[tokio::test]
    async fn test_downloader_enforces_configured_cap_for_file_lists() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_downloader_cap_{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let file_path = temp_dir.join("ten-bytes.txt");
        tokio::fs::write(&file_path, "0123456789").await.unwrap();

        let downloader = ListDownloader::new(DEFAULT_DOWNLOAD_TIMEOUT, 4);
        let err = downloader
            .fetch_or_cached(
                "capped",
                &format!("file://{}", file_path.display()),
                &temp_dir,
            )
            .await
            .expect_err("a 10-byte list must exceed a 4-byte cap");
        assert!(
            matches!(err, FilterError::ListTooLarge { limit: 4, .. }),
            "unexpected error: {err}"
        );

        // A cap of usize::MAX must not overflow the internal take() bound.
        let huge = ListDownloader::new(DEFAULT_DOWNLOAD_TIMEOUT, usize::MAX);
        let content = huge
            .fetch_or_cached(
                "huge-cap",
                &format!("file://{}", file_path.display()),
                &temp_dir,
            )
            .await
            .expect("usize::MAX must not overflow the read cap");
        assert_eq!(content, "0123456789");

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
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
