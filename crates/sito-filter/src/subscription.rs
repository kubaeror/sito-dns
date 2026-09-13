//! Subscription management with conditional HTTP updates, retries, and disk caching.
//!
//! Network list fetches are guarded against SSRF: only http/https URLs are
//! accepted, redirects are disabled, and the target host is resolved and
//! rejected when any address is loopback, private, link-local, CGNAT,
//! multicast, reserved or documentation space. `file://` lists are denied by
//! default and only readable from the server data directory or explicitly
//! allowed roots, never from `/proc`, `/sys`, `/dev` or non-regular files.

use crate::downloader::{
    DEFAULT_DOWNLOAD_TIMEOUT, DEFAULT_MAX_LIST_BYTES, cache_key_for_list, cache_path_for_list,
    read_from_cache_capped, save_to_cache,
};
use crate::error::FilterError;
use reqwest::StatusCode;
use reqwest::header::{IF_MODIFIED_SINCE, IF_NONE_MATCH};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
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
    data_dir
        .join("lists")
        .join(format!("{}.meta.json", cache_key_for_list(list_name)))
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

/// Returns true for IPs that must never be fetched as blocklist sources:
/// loopback, private, link-local (including cloud metadata), CGNAT,
/// unspecified, multicast, reserved and documentation ranges.
pub(crate) fn is_denied_target_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 (CGNAT)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_denied_target_ip(IpAddr::V4(v4));
            }
            // Translation/encapsulation prefixes that embed an IPv4 address:
            // without unwrapping these, a NAT64/6to4/Teredo literal could
            // reach a private v4 target through a v6-only denylist.
            let o = v6.octets();
            let embedded = if o[0] == 0x00
                && o[1] == 0x64
                && o[2] == 0xff
                && o[3] == 0x9b
                && o[4..12].iter().all(|b| *b == 0)
            {
                // NAT64 64:ff9b::/96
                Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
            } else if o[0] == 0x20 && o[1] == 0x02 {
                // 6to4 2002::/16
                Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]))
            } else if o[0] == 0x20 && o[1] == 0x01 && o[2] == 0 && o[3] == 0 {
                // Teredo 2001:0000::/32: client IPv4 is bitwise-inverted.
                Some(Ipv4Addr::new(!o[12], !o[13], !o[14], !o[15]))
            } else {
                None
            };
            if let Some(v4) = embedded {
                return is_denied_target_ip(IpAddr::V4(v4));
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
                || (seg[0] == 0x2001 && seg[1] == 0x0db8) // 2001:db8::/32 documentation
                || (seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0) // 100::/64 discard
        }
    }
}

/// Returns true when `path` (canonical) is inside `root`.
fn path_is_within(path: &Path, root: &Path) -> bool {
    let absolute_root = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| root.to_path_buf(), |cwd| cwd.join(root))
    };
    let root = std::fs::canonicalize(&absolute_root).unwrap_or(absolute_root);
    path.starts_with(root)
}

fn build_client(
    timeout: Duration,
    pinned: Option<(&str, &[SocketAddr])>,
) -> Result<reqwest::Client, FilterError> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("sito-dns/", env!("CARGO_PKG_VERSION")))
        // Redirects could otherwise bounce a checked public URL to an
        // internal target (SSRF).
        .redirect(reqwest::redirect::Policy::none())
        // Environment proxies would bypass the resolved-address SSRF guard
        // (the request leaves the process for a proxy that can reach
        // private ranges), so list downloads never use a proxy.
        .no_proxy();
    if let Some((host, addrs)) = pinned {
        builder = builder.resolve_to_addrs(host, addrs);
    }
    builder.build().map_err(|e| FilterError::InvalidUrl {
        url: String::new(),
        reason: format!("failed to build HTTP client: {e}"),
    })
}

/// Reads a blocklist from disk cache, returning `error` when unavailable.
async fn load_cache_or(
    cache_path: &Path,
    list_name: &str,
    max_bytes: usize,
    error: FilterError,
) -> Result<String, FilterError> {
    match read_from_cache_capped(cache_path, max_bytes).await {
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
            Err(error)
        }
    }
}

/// Manages fetching blocklists with ETag/If-Modified-Since caching and retries.
#[derive(Clone, Debug)]
pub struct SubscriptionFetcher {
    /// Base HTTP client; `None` when the TLS backend failed to initialize.
    client: Option<reqwest::Client>,
    max_bytes: usize,
    timeout: Duration,
    max_retries: usize,
    initial_backoff: Duration,
    /// Extra directories (beyond the server data directory) from which
    /// `file://` lists may be read.
    file_allowlist: Vec<PathBuf>,
    /// Unit-test hook enabling loopback targets for local mock servers.
    /// Always `false` in production builds.
    #[cfg(test)]
    allow_private_targets: bool,
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
        let client = build_client(timeout, None).ok();

        Self {
            client,
            max_bytes,
            timeout,
            max_retries,
            initial_backoff,
            file_allowlist: Vec::new(),
            #[cfg(test)]
            allow_private_targets: false,
        }
    }

    /// Adds a directory root from which `file://` lists may be read.
    #[must_use]
    pub fn with_file_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.file_allowlist.push(root.into());
        self
    }

    /// Adds a directory root from which `file://` lists may be read.
    pub fn add_file_root(&mut self, root: impl Into<PathBuf>) {
        self.file_allowlist.push(root.into());
    }

    /// Returns the configured download timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    #[cfg(test)]
    fn private_targets_allowed(&self) -> bool {
        self.allow_private_targets
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)] // `self` is only read by the test-only variant
    fn private_targets_allowed(&self) -> bool {
        false
    }

    /// Validates an http(s) target against the SSRF denylist.
    ///
    /// Returns the pre-resolved addresses for hostnames so the request client
    /// can pin DNS and defeat re-resolution (DNS rebinding) between the check
    /// and the actual connection.
    async fn validate_target(
        &self,
        url: &str,
    ) -> Result<Option<(String, Vec<SocketAddr>)>, FilterError> {
        let parsed = reqwest::Url::parse(url).map_err(|e| FilterError::InvalidUrl {
            url: url.to_string(),
            reason: format!("invalid URL: {e}"),
        })?;
        let host = parsed.host_str().ok_or_else(|| FilterError::InvalidUrl {
            url: url.to_string(),
            reason: "URL is missing a host".to_string(),
        })?;
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = parsed
            .port_or_known_default()
            .unwrap_or_else(|| if parsed.scheme() == "https" { 443 } else { 80 });

        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_denied_target_ip(ip) && !self.private_targets_allowed() {
                return Err(FilterError::InvalidUrl {
                    url: url.to_string(),
                    reason: format!("target address '{ip}' is not a permitted list host"),
                });
            }
            return Ok(None);
        }

        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| FilterError::InvalidUrl {
                url: url.to_string(),
                reason: format!("cannot resolve list host '{host}': {e}"),
            })?
            .collect();
        if addrs.is_empty() {
            return Err(FilterError::InvalidUrl {
                url: url.to_string(),
                reason: format!("list host '{host}' did not resolve to any address"),
            });
        }
        if !self.private_targets_allowed()
            && addrs.iter().any(|addr| is_denied_target_ip(addr.ip()))
        {
            return Err(FilterError::InvalidUrl {
                url: url.to_string(),
                reason: format!(
                    "list host '{host}' resolves to a private, loopback, link-local or reserved address"
                ),
            });
        }
        Ok(Some((host, addrs)))
    }

    /// Reads a `file://` list after allowlist, pseudo-filesystem and
    /// regular-file checks, with a hard size cap.
    async fn read_file_list(
        &self,
        list_name: &str,
        url: &str,
        data_dir: &Path,
    ) -> Result<String, FilterError> {
        let raw_path = url.trim().strip_prefix("file://").unwrap_or_default();
        if raw_path.is_empty() {
            return Err(FilterError::InvalidUrl {
                url: url.to_string(),
                reason: "file:// URL is missing a path".to_string(),
            });
        }
        let path = Path::new(raw_path);
        if !path.is_absolute() {
            return Err(FilterError::InvalidUrl {
                url: url.to_string(),
                reason: "file:// URLs must use an absolute path".to_string(),
            });
        }
        let canonical = tokio::fs::canonicalize(path)
            .await
            .map_err(|e| FilterError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;

        // Never read kernel pseudo-filesystems, even if an operator adds them
        // to the allowlist.
        if ["/proc", "/sys", "/dev"]
            .iter()
            .any(|prefix| canonical.starts_with(prefix))
        {
            return Err(FilterError::InvalidUrl {
                url: url.to_string(),
                reason: format!(
                    "file:// path '{}' is not a permitted list location",
                    canonical.display()
                ),
            });
        }

        let allowed = path_is_within(&canonical, data_dir)
            || self
                .file_allowlist
                .iter()
                .any(|root| path_is_within(&canonical, root));
        if !allowed {
            return Err(FilterError::InvalidUrl {
                url: url.to_string(),
                reason:
                    "file:// lists are restricted to the server data directory or an explicitly allowed directory"
                        .to_string(),
            });
        }

        let file = tokio::fs::File::open(&canonical)
            .await
            .map_err(|e| FilterError::Io {
                path: canonical.clone(),
                source: e,
            })?;
        let metadata = file.metadata().await.map_err(|e| FilterError::Io {
            path: canonical.clone(),
            source: e,
        })?;
        // Rejects directories, character devices (/dev/zero), block devices,
        // FIFOs and sockets.
        if !metadata.is_file() {
            return Err(FilterError::InvalidUrl {
                url: url.to_string(),
                reason: "file:// path is not a regular file".to_string(),
            });
        }
        if metadata.len() > self.max_bytes as u64 {
            return Err(FilterError::ListTooLarge {
                list: list_name.to_string(),
                size: metadata.len() as usize,
                limit: self.max_bytes,
            });
        }

        let mut limited = file.take(self.max_bytes as u64 + 1);
        let mut bytes = Vec::new();
        limited
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| FilterError::Io {
                path: canonical.clone(),
                source: e,
            })?;
        if bytes.len() > self.max_bytes {
            return Err(FilterError::ListTooLarge {
                list: list_name.to_string(),
                size: bytes.len(),
                limit: self.max_bytes,
            });
        }
        String::from_utf8(bytes).map_err(|_| FilterError::InvalidUrl {
            url: url.to_string(),
            reason: "Blocklist content is not valid UTF-8".to_string(),
        })
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

        // Handle file:// URI scheme through the allowlisted local reader.
        if url.trim().to_ascii_lowercase().starts_with("file://") {
            debug!(list = %list_name, url = %url, "Reading blocklist from local file");
            return match self.read_file_list(list_name, url, data_dir).await {
                Ok(content) => Ok(content),
                Err(e) => {
                    warn!(
                        list = %list_name,
                        url = %url,
                        error = %e,
                        "Refusing local blocklist; attempting disk cache fallback"
                    );
                    load_cache_or(&cache_path, list_name, self.max_bytes, e).await
                }
            };
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

        // SSRF guard before any request; pinned resolution also closes the
        // check-then-resolve (DNS rebinding) time-of-check window.
        let pinned = match self.validate_target(url).await {
            Ok(pinned) => pinned,
            Err(e) => {
                warn!(
                    list = %list_name,
                    url = %url,
                    error = %e,
                    "Refusing blocklist URL target; attempting disk cache fallback"
                );
                return load_cache_or(&cache_path, list_name, self.max_bytes, e).await;
            }
        };
        let client = match pinned.as_ref() {
            Some((host, addrs)) => build_client(self.timeout, Some((host.as_str(), addrs)))?,
            None => self.client.clone().ok_or_else(|| FilterError::InvalidUrl {
                url: url.to_string(),
                reason: "HTTP client is unavailable on this build".to_string(),
            })?,
        };

        let mut conditional = read_metadata(&meta_path).await;
        let mut last_error = None;
        let mut backoff = self.initial_backoff;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                debug!(list = %list_name, attempt, backoff_ms = backoff.as_millis(), "Retrying list download with backoff");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(10));
            }

            let mut req = client.get(url);
            if let Some(meta) = &conditional {
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
                        match read_from_cache_capped(&cache_path, self.max_bytes).await {
                            Ok(content) => return Ok(content),
                            Err(e) => {
                                // The server claims "not modified" but we have
                                // no local copy. Retry unconditionally so the
                                // full content is downloaded instead of
                                // aborting the whole source.
                                warn!(
                                    list = %list_name,
                                    error = %e,
                                    "Cache missing despite HTTP 304; retrying without conditional headers"
                                );
                                last_error = Some(e);
                                conditional = None;
                                if attempt < self.max_retries {
                                    continue;
                                }
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

                    if let Some(len) = resp.content_length()
                        && len as usize > self.max_bytes
                    {
                        return Err(FilterError::ListTooLarge {
                            list: list_name.to_string(),
                            size: len as usize,
                            limit: self.max_bytes,
                        });
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

                    // Stream the body with a hard size cap so a chunked
                    // response without Content-Length cannot exhaust memory.
                    let mut resp = resp;
                    let mut body: Vec<u8> = Vec::new();
                    let mut too_large = false;
                    let mut body_error = None;
                    loop {
                        match resp.chunk().await {
                            Ok(Some(chunk)) => {
                                if body.len().saturating_add(chunk.len()) > self.max_bytes {
                                    too_large = true;
                                    break;
                                }
                                body.extend_from_slice(&chunk);
                            }
                            Ok(None) => break,
                            Err(e) => {
                                body_error = Some(FilterError::DownloadFailed {
                                    list: list_name.to_string(),
                                    url: url.to_string(),
                                    source: e,
                                });
                                break;
                            }
                        }
                    }
                    if too_large {
                        return Err(FilterError::ListTooLarge {
                            list: list_name.to_string(),
                            size: body.len(),
                            limit: self.max_bytes,
                        });
                    }
                    if let Some(e) = body_error {
                        last_error = Some(e);
                        if attempt < self.max_retries {
                            continue;
                        }
                        break;
                    }
                    let bytes = body;

                    let Ok(content) = String::from_utf8(bytes) else {
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
        let fallback_error = last_error.unwrap_or_else(|| FilterError::InvalidUrl {
            url: url.to_string(),
            reason: "blocklist download failed".to_string(),
        });
        load_cache_or(&cache_path, list_name, self.max_bytes, fallback_error).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;

    fn temp_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{prefix}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Minimal single-threaded HTTP server returning canned responses in order
    /// while capturing the raw requests.
    async fn spawn_http_server(
        responses: Vec<String>,
    ) -> (
        SocketAddr,
        Arc<Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_for_task = captured.clone();
        let handle = tokio::spawn(async move {
            for response in responses {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    request.extend_from_slice(&buf[..n]);
                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                captured_for_task
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request).to_string());
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        (addr, captured, handle)
    }

    #[tokio::test]
    async fn test_metadata_save_and_read() {
        let temp_dir = temp_dir("sito_meta_test");
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
    async fn test_fetch_file_uri_inside_data_dir() {
        let temp_dir = temp_dir("sito_fetcher_file");
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

    #[tokio::test]
    async fn test_file_uri_outside_allowlist_is_rejected() {
        let data_dir = temp_dir("sito_file_deny");
        let outside = temp_dir("sito_file_outside");
        let outside_file = outside.join("hosts.txt");
        tokio::fs::write(&outside_file, "0.0.0.0 evil.example\n")
            .await
            .unwrap();

        let fetcher = SubscriptionFetcher::default();

        // Arbitrary absolute path outside the data dir.
        let err = fetcher
            .fetch_or_cached(
                "outside",
                &format!("file://{}", outside_file.display()),
                &data_dir,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("restricted"),
            "unexpected error: {err}"
        );

        // System credential files.
        let err = fetcher
            .fetch_or_cached("passwd", "file:///etc/passwd", &data_dir)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("restricted"), "unexpected: {err}");

        // Character devices are never regular files.
        let err = fetcher
            .fetch_or_cached("zero", "file:///dev/zero", &data_dir)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("not a permitted"),
            "unexpected: {err}"
        );

        // Traversal escaping the allowlisted root.
        let escape = std::env::temp_dir().join(format!("sito_escape_{}", std::process::id()));
        tokio::fs::write(&escape, "0.0.0.0 escape.example\n")
            .await
            .unwrap();
        let traversal = format!(
            "file://{}/../sito_escape_{}",
            data_dir.display(),
            std::process::id()
        );
        let err = fetcher
            .fetch_or_cached("traversal", &traversal, &data_dir)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("restricted"), "unexpected: {err}");

        let _ = tokio::fs::remove_file(&escape).await;
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
        let _ = tokio::fs::remove_dir_all(&outside).await;
    }

    #[tokio::test]
    async fn test_explicit_file_root_is_allowed() {
        let data_dir = temp_dir("sito_file_root_data");
        let allowed = temp_dir("sito_file_root_allowed");
        let list_file = allowed.join("hosts.txt");
        tokio::fs::write(&list_file, "0.0.0.0 allowed-root.example\n")
            .await
            .unwrap();

        let mut fetcher = SubscriptionFetcher::default();
        fetcher.add_file_root(&allowed);
        let content = fetcher
            .fetch_or_cached(
                "allowed",
                &format!("file://{}", list_file.display()),
                &data_dir,
            )
            .await
            .unwrap();
        assert!(content.contains("allowed-root.example"));

        let _ = tokio::fs::remove_dir_all(&data_dir).await;
        let _ = tokio::fs::remove_dir_all(&allowed).await;
    }

    #[test]
    fn test_denied_target_ip_ranges() {
        for denied in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "ff02::1",
            // IPv4-embedding translation prefixes.
            "64:ff9b::7f00:1",                      // NAT64 -> 127.0.0.1
            "64:ff9b::a9fe:a9fe",                   // NAT64 -> 169.254.169.254 (metadata)
            "2002:7f00:1::",                        // 6to4 -> 127.0.0.1
            "2002:a9fe:a9fe::",                     // 6to4 -> 169.254.169.254
            "2001:0:4136:e378:8000:63bf:80ff:fffe", // Teredo -> 127.0.0.1
        ] {
            let ip: IpAddr = denied.parse().unwrap();
            assert!(is_denied_target_ip(ip), "{denied} must be denied");
        }
        for allowed in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            let ip: IpAddr = allowed.parse().unwrap();
            assert!(!is_denied_target_ip(ip), "{allowed} must be allowed");
        }
    }

    #[tokio::test]
    async fn test_private_targets_are_rejected_without_network_access() {
        let data_dir = temp_dir("sito_ssrf_deny");
        let fetcher = SubscriptionFetcher::new(
            Duration::from_secs(5),
            1024 * 1024,
            0,
            Duration::from_millis(10),
        );

        for url in [
            "http://127.0.0.1:8099/list.txt",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:8099/list.txt",
            "http://192.168.0.1/list.txt",
        ] {
            let err = fetcher
                .fetch_or_cached("ssrf", url, &data_dir)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("not a permitted list host"),
                "{url}: unexpected error {err}"
            );
        }

        let _ = tokio::fs::remove_dir_all(&data_dir).await;
    }

    #[tokio::test]
    async fn test_304_with_missing_cache_retries_unconditionally() {
        let data_dir = temp_dir("sito_304_test");
        let meta_path = meta_path_for_list(&data_dir, "etag-list");
        let cache_path = cache_path_for_list(&data_dir, "etag-list");

        save_metadata(
            &meta_path,
            &ListMetadata {
                etag: Some("\"v1\"".to_string()),
                last_modified: None,
                updated_at_secs: 1,
            },
        )
        .await
        .unwrap();
        assert!(!cache_path.exists());

        let responses = vec![
            "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
            "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n||fresh.example^".to_string(),
        ];
        let (addr, captured, server) = spawn_http_server(responses).await;

        let mut fetcher = SubscriptionFetcher::new(
            Duration::from_secs(5),
            1024 * 1024,
            1,
            Duration::from_millis(10),
        );
        fetcher.allow_private_targets = true;

        let url = format!("http://{addr}/list.txt");
        let content = fetcher
            .fetch_or_cached("etag-list", &url, &data_dir)
            .await
            .unwrap();
        assert_eq!(content, "||fresh.example^");

        server.await.unwrap();
        let requests = captured.lock().unwrap().clone();
        assert_eq!(requests.len(), 2, "expected a conditional retry");
        assert!(
            requests[0].to_ascii_lowercase().contains("if-none-match"),
            "first request should be conditional: {}",
            requests[0]
        );
        assert!(
            !requests[1].to_ascii_lowercase().contains("if-none-match"),
            "retry must drop conditional headers: {}",
            requests[1]
        );

        let _ = tokio::fs::remove_dir_all(&data_dir).await;
    }
}
