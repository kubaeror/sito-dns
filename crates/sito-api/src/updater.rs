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
use tracing::{debug, info};

pub const DEFAULT_GITHUB_REPO: &str = "kubaeror/sito-dns";

/// Allowed repositories for fetching release binaries (SSRF protection).
pub const ALLOWED_UPDATE_REPOS: &[&str] = &["kubaeror/sito-dns"];

/// Returns true if the specified repository slug is allowed for updates.
pub fn is_allowed_repo(repo: &str) -> bool {
    ALLOWED_UPDATE_REPOS.contains(&repo)
}

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
    #[error("Release signature is required but no .sig/.pem assets were found")]
    SignatureMissing,
    #[error("Release signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error("Release signature is required but no verifier is available: {0}")]
    SignatureVerifierUnavailable(String),
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
    /// True when the version comparison could not be performed because one of
    /// the version strings is not valid semver. Callers must not interpret
    /// `update_available = false` as "up to date" in that case.
    #[serde(default)]
    pub version_comparison_unknown: bool,
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

/// Parses a strict `major.minor.patch` semver core (optionally `v`-prefixed,
/// optional pre-release/build metadata after `-`/`+`). Returns `None` for any
/// other shape so callers never claim "newer" based on a loose comparison.
pub fn parse_version_tuple(v: &str) -> Option<(u64, u64, u64)> {
    let clean = v.trim().trim_start_matches('v');
    let core = clean.split(['-', '+']).next().unwrap_or(clean);
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Compares two versions. `None` means at least one side is unparseable
/// (unknown outcome) and no ordering can be asserted.
pub fn compare_versions(latest: &str, current: &str) -> Option<std::cmp::Ordering> {
    let latest = parse_version_tuple(latest)?;
    let current = parse_version_tuple(current)?;
    Some(latest.cmp(&current))
}

/// Returns true only when both versions parse and `latest` is strictly newer
/// than `current`. Unparseable versions are never reported as newer.
pub fn is_version_newer(latest: &str, current: &str) -> bool {
    compare_versions(latest, current) == Some(std::cmp::Ordering::Greater)
}

/// True when both versions parse as semver.
pub fn versions_comparable(latest: &str, current: &str) -> bool {
    parse_version_tuple(latest).is_some() && parse_version_tuple(current).is_some()
}

/// Queries GitHub Releases for the latest release information.
pub async fn check_for_update(repo: Option<&str>) -> Result<UpdateInfo, UpdateError> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let repo_name = repo.unwrap_or(DEFAULT_GITHUB_REPO);
    if !is_allowed_repo(repo_name) {
        return Err(UpdateError::Other(format!(
            "Repository '{repo_name}' is not in the allowed repositories list"
        )));
    }
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
            version_comparison_unknown: false,
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
    let version_comparison_unknown = !versions_comparable(&latest_version, &current_version);
    if version_comparison_unknown {
        tracing::warn!(
            latest = %latest_version,
            current = %current_version,
            "Release tag is not strict semver; update availability is unknown"
        );
    }
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
        version_comparison_unknown,
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

/// Verifies that archive checksum matches expected hash from sums manifest.
pub fn verify_archive_checksum(
    archive_bytes: &[u8],
    archive_name: &str,
    sums_content: Option<&str>,
) -> Result<(), UpdateError> {
    let sums = sums_content.ok_or(UpdateError::ChecksumNotFound)?;
    let computed_hash =
        hex::encode(ring::digest::digest(&ring::digest::SHA256, archive_bytes).as_ref());
    let expected_hash =
        parse_checksum_from_sums(sums, archive_name).ok_or(UpdateError::ChecksumNotFound)?;

    if !computed_hash.eq_ignore_ascii_case(&expected_hash) {
        return Err(UpdateError::ChecksumMismatch {
            expected: expected_hash,
            actual: computed_hash,
        });
    }
    Ok(())
}

/// Maximum accepted release archive size (defense against oversized downloads).
const MAX_UPDATE_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum accepted signature/certificate asset size.
const MAX_SIGNATURE_ASSET_BYTES: u64 = 1024 * 1024;

/// Maximum decompressed size accepted for the extracted executable entry.
const MAX_EXTRACTED_BINARY_BYTES: u64 = 256 * 1024 * 1024;

/// Outcome of release signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureOutcome {
    /// A signature was present and verified successfully.
    Verified,
    /// No signature was present (or no verifier is installed) and the policy
    /// does not require one; checksum verification still applies.
    UnsignedAllowed,
}

/// Verifies detached release signatures.
#[async_trait::async_trait]
pub trait SignatureVerifier: Send + Sync {
    /// Returns true when the underlying verification tooling is available.
    fn is_available(&self) -> bool;

    /// Verifies `artifact` against a detached `signature` and `certificate`.
    async fn verify(
        &self,
        artifact: &Path,
        signature: &Path,
        certificate: &Path,
    ) -> Result<(), UpdateError>;
}

/// Cosign keyless signature verifier shelling out to the `cosign` binary.
pub struct CosignVerifier {
    identity_regexp: String,
}

impl CosignVerifier {
    /// Creates a verifier that requires the signature identity to belong to the
    /// given GitHub repository's release workflow.
    pub fn new(repo: &str) -> Self {
        Self {
            identity_regexp: format!("https://github.com/{repo}/.*"),
        }
    }

    fn binary() -> Option<std::path::PathBuf> {
        for candidate in ["/usr/bin/cosign", "/usr/local/bin/cosign"] {
            let path = std::path::PathBuf::from(candidate);
            if path.is_file() {
                return Some(path);
            }
        }
        // Fall back to PATH lookup.
        let path_var = std::env::var_os("PATH")?;
        std::env::split_paths(&path_var)
            .map(|dir| dir.join("cosign"))
            .find(|p| p.is_file())
    }
}

#[async_trait::async_trait]
impl SignatureVerifier for CosignVerifier {
    fn is_available(&self) -> bool {
        Self::binary().is_some()
    }

    async fn verify(
        &self,
        artifact: &Path,
        signature: &Path,
        certificate: &Path,
    ) -> Result<(), UpdateError> {
        let binary = Self::binary().ok_or_else(|| {
            UpdateError::SignatureVerifierUnavailable(
                "cosign binary not found in /usr/bin, /usr/local/bin or PATH".to_string(),
            )
        })?;

        let output = tokio::process::Command::new(binary)
            .arg("verify-blob")
            .arg("--certificate")
            .arg(certificate)
            .arg("--signature")
            .arg(signature)
            .arg("--certificate-identity-regexp")
            .arg(&self.identity_regexp)
            .arg("--certificate-oidc-issuer")
            .arg("https://token.actions.githubusercontent.com")
            .arg(artifact)
            .output()
            .await
            .map_err(|e| UpdateError::SignatureInvalid(format!("failed to execute cosign: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = stderr.lines().last().unwrap_or("unknown error");
            return Err(UpdateError::SignatureInvalid(detail.to_string()));
        }
        Ok(())
    }
}

/// Locates the detached signature and certificate assets for an archive.
pub fn find_signature_assets(
    assets: &[ReleaseAsset],
    archive_name: &str,
) -> (Option<ReleaseAsset>, Option<ReleaseAsset>) {
    let sig_name = format!("{archive_name}.sig");
    let cert_name = format!("{archive_name}.pem");
    let signature = assets.iter().find(|a| a.name == sig_name).cloned();
    let certificate = assets.iter().find(|a| a.name == cert_name).cloned();
    (signature, certificate)
}

/// Applies the release signature policy.
///
/// * A signature that is present must verify, regardless of `required`.
/// * If no signature is present (or no verifier is installed), verification is
///   only skipped when `required` is false; otherwise an error is returned.
pub async fn verify_release_signature(
    artifact: &Path,
    signature: Option<&Path>,
    certificate: Option<&Path>,
    required: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<SignatureOutcome, UpdateError> {
    if let (Some(sig), Some(cert)) = (signature, certificate) {
        if !verifier.is_available() {
            if required {
                return Err(UpdateError::SignatureVerifierUnavailable(
                    "release ships a signature but no verifier is installed".to_string(),
                ));
            }
            tracing::warn!(
                "Release ships a signature but no verifier is available; relying on SHA-256 checksum only"
            );
            return Ok(SignatureOutcome::UnsignedAllowed);
        }
        verifier.verify(artifact, sig, cert).await?;
        tracing::info!("Release signature verified successfully");
        return Ok(SignatureOutcome::Verified);
    }

    if required {
        return Err(UpdateError::SignatureMissing);
    }
    tracing::warn!("Release does not ship signature assets; relying on SHA-256 checksum only");
    Ok(SignatureOutcome::UnsignedAllowed)
}

fn is_allowed_download_host(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or("");
    host == "github.com"
        || host == "api.github.com"
        || host == "objects.githubusercontent.com"
        || host.ends_with(".githubusercontent.com")
}

/// Downloads release signature assets (when present) and applies the configured
/// signature policy to the archive bytes.
#[allow(clippy::too_many_arguments)]
async fn apply_signature_policy(
    client: &reqwest::Client,
    repo_name: &str,
    archive: &ReleaseAsset,
    archive_bytes: &[u8],
    sig_asset: Option<&ReleaseAsset>,
    cert_asset: Option<&ReleaseAsset>,
    required: bool,
) -> Result<SignatureOutcome, UpdateError> {
    let verifier = CosignVerifier::new(repo_name);

    let (Some(sig), Some(cert)) = (sig_asset, cert_asset) else {
        return verify_release_signature(Path::new(&archive.name), None, None, required, &verifier)
            .await;
    };

    for asset in [sig, cert] {
        if asset.size > MAX_SIGNATURE_ASSET_BYTES {
            return Err(UpdateError::Other(format!(
                "Signature asset '{}' is unexpectedly large ({} bytes)",
                asset.name, asset.size
            )));
        }
        if !is_allowed_download_host(&asset.browser_download_url) {
            return Err(UpdateError::Other(format!(
                "Signature asset URL '{}' does not point at an allowed GitHub host",
                asset.browser_download_url
            )));
        }
    }

    debug!(asset = %sig.name, "Downloading release signature");
    let sig_bytes = client
        .get(&sig.browser_download_url)
        .send()
        .await?
        .bytes()
        .await?;
    let cert_bytes = client
        .get(&cert.browser_download_url)
        .send()
        .await?
        .bytes()
        .await?;
    if sig_bytes.len() as u64 > MAX_SIGNATURE_ASSET_BYTES
        || cert_bytes.len() as u64 > MAX_SIGNATURE_ASSET_BYTES
    {
        return Err(UpdateError::Other(
            "Signature/certificate asset exceeded the maximum size".to_string(),
        ));
    }

    // cosign needs real files; use a unique temporary directory and always clean up.
    let temp_dir =
        std::env::temp_dir().join(format!("sito-update-verify-{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await?;
    let artifact_path = temp_dir.join(&archive.name);
    let sig_path = temp_dir.join(format!("{}.sig", archive.name));
    let cert_path = temp_dir.join(format!("{}.pem", archive.name));

    tokio::fs::write(&artifact_path, archive_bytes).await?;
    tokio::fs::write(&sig_path, &sig_bytes).await?;
    tokio::fs::write(&cert_path, &cert_bytes).await?;

    let result = verify_release_signature(
        &artifact_path,
        Some(&sig_path),
        Some(&cert_path),
        required,
        &verifier,
    )
    .await;

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    result
}

/// Extracts the `sito` executable from a gzipped release tarball, enforcing a
/// per-entry decompression cap so a tar bomb cannot exhaust memory even when
/// the compressed archive passed the download-size check.
pub fn extract_binary_from_archive(archive_bytes: &[u8]) -> Result<Vec<u8>, UpdateError> {
    let gz = GzDecoder::new(archive_bytes);
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
            if entry.size() > MAX_EXTRACTED_BINARY_BYTES {
                return Err(UpdateError::Archive(format!(
                    "Binary entry 'sito' is too large ({} bytes)",
                    entry.size()
                )));
            }
            let mut limited = (&mut entry).take(MAX_EXTRACTED_BINARY_BYTES + 1);
            limited
                .read_to_end(&mut binary_content)
                .map_err(|e| UpdateError::Archive(format!("Failed to read binary: {e}")))?;
            if binary_content.len() as u64 > MAX_EXTRACTED_BINARY_BYTES {
                return Err(UpdateError::Archive(
                    "Binary entry exceeded the decompression cap".to_string(),
                ));
            }
            found = true;
            break;
        }
    }

    if !found || binary_content.is_empty() {
        return Err(UpdateError::Archive(
            "Could not find executable binary 'sito' in the downloaded release archive".to_string(),
        ));
    }
    Ok(binary_content)
}

/// Downloads the latest release archive, verifies the release signature (when
/// present) and SHA-256 checksum, extracts the binary, and replaces the running
/// executable.
pub async fn apply_update(
    repo: Option<&str>,
    force: bool,
    require_signature: bool,
) -> Result<String, UpdateError> {
    if is_running_in_docker() {
        return Err(UpdateError::DockerEnvironment(
            "In-app binary update is disabled inside Docker. Use container image management."
                .to_string(),
        ));
    }

    let repo_name = repo.unwrap_or(DEFAULT_GITHUB_REPO);
    if !is_allowed_repo(repo_name) {
        return Err(UpdateError::Other(format!(
            "Repository '{repo_name}' is not in the allowed repositories list"
        )));
    }
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
    let assets: Vec<ReleaseAsset> = assets_arr
        .iter()
        .filter_map(|asset| {
            Some(ReleaseAsset {
                name: asset["name"].as_str()?.to_string(),
                browser_download_url: asset["browser_download_url"].as_str()?.to_string(),
                size: asset["size"].as_u64().unwrap_or(0),
            })
        })
        .collect();

    // 1. Locate binary archive asset
    let archive = assets
        .iter()
        .find(|a| {
            (a.name.contains(target) || a.name.ends_with(&format!("{target}.tar.gz")))
                && a.name.ends_with(".tar.gz")
        })
        .cloned()
        .ok_or_else(|| UpdateError::NoCompatibleAsset(target.to_string()))?;

    let sha_asset = assets
        .iter()
        .find(|a| a.name == "SHA256SUMS" || a.name.ends_with(".tar.gz.sha256"))
        .cloned()
        .ok_or(UpdateError::ChecksumNotFound)?;

    if archive.size > MAX_UPDATE_ARCHIVE_BYTES {
        return Err(UpdateError::Other(format!(
            "Release archive '{}' is unexpectedly large ({} bytes); refusing to download",
            archive.name, archive.size
        )));
    }
    if !is_allowed_download_host(&archive.browser_download_url) {
        return Err(UpdateError::Other(format!(
            "Release asset URL '{}' does not point at an allowed GitHub host",
            archive.browser_download_url
        )));
    }
    if !is_allowed_download_host(&sha_asset.browser_download_url) {
        return Err(UpdateError::Other(format!(
            "Checksum asset URL '{}' does not point at an allowed GitHub host",
            sha_asset.browser_download_url
        )));
    }

    info!(asset = %archive.name, url = %archive.browser_download_url, "Downloading release archive");
    let archive_bytes = client
        .get(&archive.browser_download_url)
        .send()
        .await?
        .bytes()
        .await?;

    if archive_bytes.len() as u64 > MAX_UPDATE_ARCHIVE_BYTES {
        return Err(UpdateError::Other(
            "Release archive exceeded the maximum download size".to_string(),
        ));
    }

    // 2. Release signature policy (present signatures must always verify)
    let (sig_asset, cert_asset) = find_signature_assets(&assets, &archive.name);
    apply_signature_policy(
        &client,
        repo_name,
        &archive,
        archive_bytes.as_ref(),
        sig_asset.as_ref(),
        cert_asset.as_ref(),
        require_signature,
    )
    .await?;

    // 3. Verify SHA-256 checksum
    debug!(asset = %sha_asset.name, "Fetching checksum manifest");
    let sums_content = client
        .get(&sha_asset.browser_download_url)
        .send()
        .await?
        .text()
        .await?;

    verify_archive_checksum(&archive_bytes, &archive.name, Some(&sums_content))?;
    info!(asset = %archive.name, "SHA256 checksum verified successfully");

    // 4. Extract 'sito' executable from tarball
    let binary_content = extract_binary_from_archive(archive_bytes.as_ref())?;

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
        assert!(is_version_newer("1.1.2-rc.1", "1.1.1"));
        assert!(!is_version_newer("1.1.1", "1.1.1"));
        assert!(!is_version_newer("1.0.0", "1.1.1"));
        assert!(!is_version_newer("v1.1.1", "1.1.1"));
        // Unparseable versions must never be claimed as newer.
        assert!(!is_version_newer("garbage", "1.0.0"));
        assert!(!is_version_newer("1.0.0", "garbage"));
        assert!(!is_version_newer("1.0", "0.9"));
        assert!(versions_comparable("1.6.0", "1.5.0"));
        assert!(!versions_comparable("nightly", "1.5.0"));
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

    #[test]
    fn test_updater_aborts_without_checksum() {
        let fake_archive = b"dummy archive payload";
        let fake_name = "sito-v1.2.1-x86_64-unknown-linux-gnu.tar.gz";

        // 1. None sums content -> ChecksumNotFound
        let err = verify_archive_checksum(fake_archive, fake_name, None).unwrap_err();
        assert!(matches!(err, UpdateError::ChecksumNotFound));

        // 2. Archive not in sums content -> ChecksumNotFound
        let sums_other =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  other.tar.gz\n";
        let err = verify_archive_checksum(fake_archive, fake_name, Some(sums_other)).unwrap_err();
        assert!(matches!(err, UpdateError::ChecksumNotFound));

        // 3. Mismatched checksum -> ChecksumMismatch
        let sums_mismatch = format!(
            "0000000000000000000000000000000000000000000000000000000000000000  {fake_name}\n"
        );
        let err =
            verify_archive_checksum(fake_archive, fake_name, Some(&sums_mismatch)).unwrap_err();
        assert!(matches!(err, UpdateError::ChecksumMismatch { .. }));

        // 4. Valid checksum -> Ok(())
        let valid_hash =
            hex::encode(ring::digest::digest(&ring::digest::SHA256, fake_archive).as_ref());
        let sums_valid = format!("{valid_hash}  {fake_name}\n");
        assert!(verify_archive_checksum(fake_archive, fake_name, Some(&sums_valid)).is_ok());
    }

    fn build_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, *name, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn test_extract_binary_from_archive() {
        let archive = build_tar_gz(&[("README.md", b"docs"), ("sito", b"binary-bytes")]);
        assert_eq!(
            extract_binary_from_archive(&archive).unwrap(),
            b"binary-bytes"
        );

        // A tar bomb whose declared entry size exceeds the cap must be rejected
        // before decompression.
        let enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
        header.set_size(MAX_EXTRACTED_BINARY_BYTES + 1);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "sito", std::io::empty())
            .unwrap();
        let bomb = builder.into_inner().unwrap().finish().unwrap();
        let err = extract_binary_from_archive(&bomb).unwrap_err();
        assert!(matches!(err, UpdateError::Archive(_)));
    }

    #[test]
    fn test_allowed_repos() {
        assert!(is_allowed_repo("kubaeror/sito-dns"));
        assert!(!is_allowed_repo("evil/attacker-repo"));
        assert!(!is_allowed_repo("kubaeror/other-repo"));
    }

    #[test]
    fn test_allowed_download_hosts() {
        assert!(is_allowed_download_host(
            "https://github.com/kubaeror/sito-dns/releases/download/v1.4.0/sito.tar.gz"
        ));
        assert!(is_allowed_download_host(
            "https://objects.githubusercontent.com/github-production-release-asset/file"
        ));
        assert!(!is_allowed_download_host("http://github.com/file"));
        assert!(!is_allowed_download_host("https://evil.example.com/file"));
        assert!(!is_allowed_download_host(
            "https://github.com.evil.example.com/file"
        ));
    }

    fn asset(name: &str) -> ReleaseAsset {
        ReleaseAsset {
            name: name.to_string(),
            browser_download_url: format!("https://github.com/kubaeror/sito-dns/releases/{name}"),
            size: 100,
        }
    }

    #[test]
    fn test_find_signature_assets() {
        let assets = vec![
            asset("sito-v1.4.0-x86_64-unknown-linux-gnu.tar.gz"),
            asset("sito-v1.4.0-x86_64-unknown-linux-gnu.tar.gz.sig"),
            asset("sito-v1.4.0-x86_64-unknown-linux-gnu.tar.gz.pem"),
            asset("SHA256SUMS"),
        ];
        let (sig, cert) =
            find_signature_assets(&assets, "sito-v1.4.0-x86_64-unknown-linux-gnu.tar.gz");
        assert_eq!(
            sig.expect("sig asset").name,
            "sito-v1.4.0-x86_64-unknown-linux-gnu.tar.gz.sig"
        );
        assert_eq!(
            cert.expect("cert asset").name,
            "sito-v1.4.0-x86_64-unknown-linux-gnu.tar.gz.pem"
        );

        let (sig, cert) = find_signature_assets(&assets, "other.tar.gz");
        assert!(sig.is_none());
        assert!(cert.is_none());
    }

    struct MockVerifier {
        available: bool,
        result: Result<(), UpdateError>,
    }

    #[async_trait::async_trait]
    impl SignatureVerifier for MockVerifier {
        fn is_available(&self) -> bool {
            self.available
        }

        async fn verify(
            &self,
            _artifact: &Path,
            _signature: &Path,
            _certificate: &Path,
        ) -> Result<(), UpdateError> {
            match &self.result {
                Ok(()) => Ok(()),
                Err(UpdateError::SignatureInvalid(msg)) => {
                    Err(UpdateError::SignatureInvalid(msg.clone()))
                }
                Err(_) => Err(UpdateError::SignatureInvalid("mock failure".to_string())),
            }
        }
    }

    #[tokio::test]
    async fn test_signature_policy_present_and_valid() {
        let verifier = MockVerifier {
            available: true,
            result: Ok(()),
        };
        let outcome = verify_release_signature(
            Path::new("archive.tar.gz"),
            Some(Path::new("archive.tar.gz.sig")),
            Some(Path::new("archive.tar.gz.pem")),
            true,
            &verifier,
        )
        .await
        .unwrap();
        assert_eq!(outcome, SignatureOutcome::Verified);
    }

    #[tokio::test]
    async fn test_signature_policy_present_but_invalid_always_fails() {
        let verifier = MockVerifier {
            available: true,
            result: Err(UpdateError::SignatureInvalid("bad sig".to_string())),
        };
        let err = verify_release_signature(
            Path::new("archive.tar.gz"),
            Some(Path::new("archive.tar.gz.sig")),
            Some(Path::new("archive.tar.gz.pem")),
            false, // not required, but a present signature must still verify
            &verifier,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, UpdateError::SignatureInvalid(_)));
    }

    #[tokio::test]
    async fn test_signature_policy_missing_required_fails() {
        let verifier = MockVerifier {
            available: true,
            result: Ok(()),
        };
        let err =
            verify_release_signature(Path::new("archive.tar.gz"), None, None, true, &verifier)
                .await
                .unwrap_err();
        assert!(matches!(err, UpdateError::SignatureMissing));
    }

    #[tokio::test]
    async fn test_signature_policy_missing_optional_allowed() {
        let verifier = MockVerifier {
            available: true,
            result: Ok(()),
        };
        let outcome =
            verify_release_signature(Path::new("archive.tar.gz"), None, None, false, &verifier)
                .await
                .unwrap();
        assert_eq!(outcome, SignatureOutcome::UnsignedAllowed);
    }

    #[tokio::test]
    async fn test_signature_policy_required_without_verifier_fails() {
        let verifier = MockVerifier {
            available: false,
            result: Ok(()),
        };
        let err = verify_release_signature(
            Path::new("archive.tar.gz"),
            Some(Path::new("archive.tar.gz.sig")),
            Some(Path::new("archive.tar.gz.pem")),
            true,
            &verifier,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, UpdateError::SignatureVerifierUnavailable(_)));
    }
}
