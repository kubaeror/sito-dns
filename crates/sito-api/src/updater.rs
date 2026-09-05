//! In-app software update subsystem for sito.
//!
//! Provides GitHub Releases querying, semver comparison, Docker environment detection,
//! archive downloading with SHA256 checksum verification, and atomic self-replacement.

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

pub const DEFAULT_GITHUB_REPO: &str = "kubaeror/sito-dns";

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("Network request failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Failed to parse release information: {0}")]
    Parse(String),
    #[error("In-app update is disabled inside Docker containers: {0}")]
    DockerEnvironment(String),
    #[error("No compatible release asset found for architecture {0}")]
    NoCompatibleAsset(String),
    #[error("Checksum verification failed: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("Checksum file not found in release assets")]
    ChecksumNotFound,
    #[error("I/O error during update: {0}")]
    Io(#[from] std::io::Error),
    #[error("Archive extraction error: {0}")]
    Archive(String),
    #[error("Update error: {0}")]
    Other(String),
}

/// Release asset information from GitHub API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

/// Information about version and available updates.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateInfo {
    /// Currently running version of sito.
    pub current_version: String,
    /// Latest version available upstream.
    pub latest_version: String,
    /// Whether an update is available.
    pub update_available: bool,
    /// HTML URL to the release page on GitHub.
    pub release_url: String,
    /// Markdown release notes for the latest version.
    pub release_notes: String,
    /// Release publication timestamp.
    pub published_at: Option<String>,
    /// Whether the server is running inside a Docker/OCI container.
    pub is_docker: bool,
    /// Environment-specific upgrade instructions (e.g. docker compose command).
    pub instructions: Option<String>,
}

/// Detects whether the current process is running inside a Docker or OCI container.
pub fn is_running_in_docker() -> bool {
    if Path::new("/.dockerenv").exists() {
        return true;
    }

    if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup")
        && (cgroup.contains("docker")
            || cgroup.contains("containerd")
            || cgroup.contains("kubepods"))
    {
        return true;
    }

    // Check container environment variable
    if std::env::var("container").is_ok() || std::env::var("DOCKER_CONTAINER").is_ok() {
        return true;
    }

    false
}

/// Maps the current host CPU architecture to the release target triple.
pub fn current_target_triple() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        "arm" => "armv7-unknown-linux-gnueabihf",
        other => other,
    }
}

/// Parses a version string into a (major, minor, patch) tuple.
pub fn parse_version_tuple(v: &str) -> Option<(u64, u64, u64)> {
    let clean = v.trim().trim_start_matches('v');
    let parts: Vec<&str> = clean.split('.').collect();
    if parts.is_empty() {
        return None;
    }

    let major = parts[0].parse::<u64>().ok()?;
    let minor = parts
        .get(1)
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(0);
    let patch_raw = parts.get(2).copied().unwrap_or("0");
    let patch_clean = patch_raw
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap_or("0");
    let patch = patch_clean.parse::<u64>().unwrap_or(0);

    Some((major, minor, patch))
}

/// Returns true if `latest` is strictly newer than `current`.
pub fn is_version_newer(latest: &str, current: &str) -> bool {
    match (parse_version_tuple(latest), parse_version_tuple(current)) {
        (Some(l), Some(c)) => l > c,
        _ => latest.trim_start_matches('v') != current.trim_start_matches('v'),
    }
}

/// Queries GitHub Releases for the latest release information.
pub async fn check_for_update(repo: Option<&str>) -> Result<UpdateInfo, UpdateError> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let repo_name = repo.unwrap_or(DEFAULT_GITHUB_REPO);
    let url = format!("https://api.github.com/repos/{repo_name}/releases/latest");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(format!("sito/{current_version}"))
        .build()?;

    let response = client.get(&url).send().await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        // No releases published yet
        let is_docker = is_running_in_docker();
        return Ok(UpdateInfo {
            current_version: current_version.clone(),
            latest_version: current_version,
            update_available: false,
            release_url: format!("https://github.com/{repo_name}"),
            release_notes: "No releases found on GitHub.".to_string(),
            published_at: None,
            is_docker,
            instructions: None,
        });
    }

    let text = response.text().await?;
    let release: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| UpdateError::Parse(e.to_string()))?;

    let tag_name = release["tag_name"]
        .as_str()
        .ok_or_else(|| UpdateError::Parse("Missing tag_name in release payload".to_string()))?;
    let latest_version = tag_name.trim_start_matches('v').to_string();

    let release_url = release["html_url"]
        .as_str()
        .unwrap_or(&format!("https://github.com/{repo_name}/releases/latest"))
        .to_string();

    let release_notes = release["body"]
        .as_str()
        .unwrap_or("No release notes provided.")
        .to_string();

    let published_at = release["published_at"].as_str().map(ToString::to_string);

    let is_docker = is_running_in_docker();
    let update_available = is_version_newer(&latest_version, &current_version);

    let instructions = if is_docker {
        Some(
            "Running inside a Docker container. In-app binary replacement is disabled.\n\
             Upgrade by pulling the latest image on your Docker host:\n\
             docker compose pull && docker compose up -d"
                .to_string(),
        )
    } else {
        None
    };

    Ok(UpdateInfo {
        current_version,
        latest_version,
        update_available,
        release_url,
        release_notes,
        published_at,
        is_docker,
        instructions,
    })
}

/// Parses expected SHA256 checksum for a specific archive from SHA256SUMS file content.
pub fn parse_checksum_from_sums(sums_content: &str, archive_name: &str) -> Option<String> {
    for line in sums_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Format is typically: "<sha256>  <filename>" or "<sha256> *<filename>"
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            let hash = parts[0];
            let filename = parts[1].trim_start_matches('*');
            if filename == archive_name && hash.len() == 64 {
                return Some(hash.to_lowercase());
            }
        }
    }

    // Fallback: if sums_content is just a raw 64-char hash
    let clean = sums_content.trim();
    if clean.len() == 64 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(clean.to_lowercase());
    }

    None
}

/// Downloads latest release asset, verifies SHA256, and replaces running executable.
pub async fn apply_update(repo: Option<&str>, force: bool) -> Result<String, UpdateError> {
    if is_running_in_docker() {
        return Err(UpdateError::DockerEnvironment(
            "Self-updating is not supported inside Docker containers. Run 'docker compose pull && docker compose up -d' instead.".to_string()
        ));
    }

    let repo_name = repo.unwrap_or(DEFAULT_GITHUB_REPO);
    let update_info = check_for_update(Some(repo_name)).await?;

    if !update_info.update_available && !force {
        return Ok(format!(
            "sito is already on the latest version (v{}). Use force to reinstall.",
            update_info.current_version
        ));
    }

    let current_version = env!("CARGO_PKG_VERSION");
    let url = format!("https://api.github.com/repos/{repo_name}/releases/latest");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(format!("sito/{current_version}"))
        .build()?;

    let release_resp = client.get(&url).send().await?;
    let release_text = release_resp.text().await?;
    let release: serde_json::Value =
        serde_json::from_str(&release_text).map_err(|e| UpdateError::Parse(e.to_string()))?;
    let assets_arr = release["assets"]
        .as_array()
        .ok_or_else(|| UpdateError::Parse("Release payload has no assets".to_string()))?;

    let target = current_target_triple();

    // 1. Locate binary archive asset
    let mut archive_asset: Option<ReleaseAsset> = None;
    let mut sha256_asset: Option<ReleaseAsset> = None;

    for asset in assets_arr {
        let name = asset["name"].as_str().unwrap_or("");
        let download_url = asset["browser_download_url"].as_str().unwrap_or("");
        let size = asset["size"].as_u64().unwrap_or(0);

        if (name.contains(target) || name.ends_with(&format!("{target}.tar.gz")))
            && name.ends_with(".tar.gz")
        {
            archive_asset = Some(ReleaseAsset {
                name: name.to_string(),
                browser_download_url: download_url.to_string(),
                size,
            });
        }

        if name == "SHA256SUMS" || name.ends_with(".tar.gz.sha256") {
            sha256_asset = Some(ReleaseAsset {
                name: name.to_string(),
                browser_download_url: download_url.to_string(),
                size,
            });
        }
    }

    let archive =
        archive_asset.ok_or_else(|| UpdateError::NoCompatibleAsset(target.to_string()))?;

    info!(asset = %archive.name, url = %archive.browser_download_url, "Downloading release archive");
    let archive_bytes = client
        .get(&archive.browser_download_url)
        .send()
        .await?
        .bytes()
        .await?;

    // 2. Compute SHA256 of downloaded archive
    let computed_hash =
        hex::encode(ring::digest::digest(&ring::digest::SHA256, &archive_bytes).as_ref());

    // 3. Verify checksum if SHA256SUMS asset exists
    if let Some(sha_asset) = sha256_asset {
        debug!(asset = %sha_asset.name, "Fetching checksum manifest");
        let sums_content = client
            .get(&sha_asset.browser_download_url)
            .send()
            .await?
            .text()
            .await?;

        if let Some(expected_hash) = parse_checksum_from_sums(&sums_content, &archive.name) {
            if !computed_hash.eq_ignore_ascii_case(&expected_hash) {
                return Err(UpdateError::ChecksumMismatch {
                    expected: expected_hash,
                    actual: computed_hash,
                });
            }
            info!(checksum = %computed_hash, "SHA256 checksum verified successfully");
        } else {
            warn!(
                "Could not find checksum for {} in checksums file; continuing",
                archive.name
            );
        }
    }

    // 4. Extract 'sito' executable from tarball
    let gz = GzDecoder::new(&archive_bytes[..]);
    let mut tar = tar::Archive::new(gz);
    let mut binary_content = Vec::new();
    let mut found = false;

    let entries = tar
        .entries()
        .map_err(|e| UpdateError::Archive(format!("Failed to read tar entries: {e}")))?;

    for entry in entries {
        let mut entry = entry.map_err(|e| UpdateError::Archive(format!("Failed entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| UpdateError::Archive(format!("Invalid path: {e}")))?;

        if let Some(file_name) = path.file_name()
            && file_name == "sito"
        {
            entry
                .read_to_end(&mut binary_content)
                .map_err(|e| UpdateError::Archive(format!("Failed to read binary: {e}")))?;
            found = true;
            break;
        }
    }

    if !found || binary_content.is_empty() {
        return Err(UpdateError::Archive(
            "Could not find executable binary 'sito' in the downloaded release archive".to_string(),
        ));
    }

    // 5. Replace current executable atomically
    let current_exe = std::env::current_exe()?;
    let parent_dir = current_exe.parent().ok_or_else(|| {
        UpdateError::Other("Could not resolve parent directory of executable".to_string())
    })?;

    let temp_exe = parent_dir.join(format!(".sito_update_{}", rand::random::<u32>()));

    tokio::fs::write(&temp_exe, &binary_content).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        tokio::fs::set_permissions(&temp_exe, perms).await?;
    }

    tokio::fs::rename(&temp_exe, &current_exe).await?;

    info!(
        version = %update_info.latest_version,
        path = %current_exe.display(),
        "sito binary updated successfully"
    );

    Ok(format!(
        "Successfully updated sito to version v{}. Restart the service (e.g. 'systemctl restart sito') to activate.",
        update_info.latest_version
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_version_newer() {
        assert!(is_version_newer("1.2.0", "1.1.1"));
        assert!(is_version_newer("v2.0.0", "1.9.9"));
        assert!(is_version_newer("1.1.2", "1.1.1"));
        assert!(!is_version_newer("1.1.1", "1.1.1"));
        assert!(!is_version_newer("1.0.0", "1.1.1"));
        assert!(!is_version_newer("v1.1.1", "1.1.1"));
    }

    #[test]
    fn test_parse_checksum_from_sums() {
        let content = "\
d5a3...fakehash...88  sito-v1.2.0-x86_64-unknown-linux-gnu.tar.gz\n\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  sito-v1.2.0-aarch64-unknown-linux-gnu.tar.gz\n";

        let hash =
            parse_checksum_from_sums(content, "sito-v1.2.0-aarch64-unknown-linux-gnu.tar.gz");
        assert_eq!(
            hash,
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string())
        );

        let not_found = parse_checksum_from_sums(content, "nonexistent.tar.gz");
        assert_eq!(not_found, None);
    }

    #[test]
    fn test_current_target_triple() {
        let target = current_target_triple();
        assert!(!target.is_empty());
    }
}
