//! In-app software update subsystem for sito.
//!
//! Provides GitHub Releases querying, semver comparison, Docker environment detection,
//! archive downloading with SHA256 checksum verification, and atomic self-replacement.

use flate2::read::GzDecoder;
use futures_util::StreamExt;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info};

pub const DEFAULT_GITHUB_REPO: &str = "kubaeror/sito-dns";

/// Allowed repositories for fetching release binaries (SSRF protection).
pub const ALLOWED_UPDATE_REPOS: &[&str] = &["kubaeror/sito-dns"];

/// Returns true if the specified repository slug is allowed for updates.
pub fn is_allowed_repo(repo: &str) -> bool {
    ALLOWED_UPDATE_REPOS.contains(&repo)
}

/// Maximum number of redirect hops the updater will follow.
///
/// GitHub release assets redirect from `github.com` to
/// `objects.githubusercontent.com` (and occasionally other
/// `*.githubusercontent.com` hosts); a small fixed cap keeps a hostile or
/// misconfigured endpoint from turning an update into an unbounded request
/// chain.
const MAX_UPDATE_REDIRECTS: usize = 5;

/// Why a redirect target was rejected by the updater HTTP policy.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RedirectRejection {
    InsecureScheme { url: String },
    DisallowedHost { url: String },
    Loop { url: String },
    TooManyRedirects { max: usize },
}

impl fmt::Display for RedirectRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecureScheme { url } => {
                write!(f, "update redirect to non-HTTPS URL rejected: '{url}'")
            }
            Self::DisallowedHost { url } => {
                write!(
                    f,
                    "update redirect to non-allowlisted host rejected: '{url}'"
                )
            }
            Self::Loop { url } => write!(f, "update redirect loop detected at '{url}'"),
            Self::TooManyRedirects { max } => {
                write!(f, "update redirect chain exceeded {max} hops")
            }
        }
    }
}

impl std::error::Error for RedirectRejection {}

/// Validates one redirect hop against the updater's download policy.
///
/// `previous` is the chain of URLs already requested (including the initial
/// request), matching `reqwest::redirect::Attempt::previous()`.
fn validate_redirect(previous: &[Url], next: &Url) -> Result<(), RedirectRejection> {
    if next.scheme() != "https" {
        return Err(RedirectRejection::InsecureScheme {
            url: next.to_string(),
        });
    }
    if !is_allowed_download_host(next.as_str()) {
        return Err(RedirectRejection::DisallowedHost {
            url: next.to_string(),
        });
    }
    if previous.iter().any(|visited| visited == next) {
        return Err(RedirectRejection::Loop {
            url: next.to_string(),
        });
    }
    // `previous` includes the initial URL, so allow at most
    // `MAX_UPDATE_REDIRECTS` followed hops before refusing the next one.
    if previous.len() > MAX_UPDATE_REDIRECTS {
        return Err(RedirectRejection::TooManyRedirects {
            max: MAX_UPDATE_REDIRECTS,
        });
    }
    Ok(())
}

/// Builds a reqwest redirect policy that revalidates every hop.
fn updater_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        match validate_redirect(attempt.previous(), attempt.url()) {
            Ok(()) => attempt.follow(),
            Err(rejection) => attempt.error(rejection),
        }
    })
}

/// Builds the HTTP client used for every updater request.
///
/// The client carries no credentials or authorization headers: GitHub release
/// assets are public, and keeping the request header set uniform avoids
/// leaking anything across a redirect to another allowlisted host.
fn updater_http_client(timeout: Duration) -> Result<reqwest::Client, UpdateError> {
    let current_version = env!("CARGO_PKG_VERSION");
    Ok(reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(format!("sito/{current_version}"))
        .redirect(updater_redirect_policy())
        .build()?)
}

/// Validates a URL before the updater's first request. Redirect hops are
/// checked separately by [`validate_redirect`].
fn ensure_allowed_download_url(url: &str, asset_kind: &str) -> Result<(), UpdateError> {
    if is_allowed_download_host(url) {
        return Ok(());
    }
    Err(UpdateError::Other(format!(
        "{asset_kind} URL '{url}' does not point at an allowed GitHub host"
    )))
}

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("Network request failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Failed to parse release information: {0}")]
    Parse(String),
    #[error("In-app update is disabled inside Docker containers: {0}")]
    DockerEnvironment(String),
    #[error("In-app update is disabled while running as a systemd service: {0}")]
    SystemdEnvironment(String),
    #[error("Another in-app update is already in progress")]
    UpdateInProgress,
    #[error(
        "Cannot order the current version and latest tag (current {current}, latest {latest}); re-run with force to reinstall"
    )]
    VersionComparisonUnknown { current: String, latest: String },
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
    #[error("Release ships an incomplete signature pair: {0}")]
    SignatureIncomplete(String),
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
    /// Whether the server is running as a systemd service.
    pub is_systemd: bool,
    /// True when this deployment must not replace its own binary in place.
    /// `--check` and the CLI after `systemctl stop` still work.
    pub in_app_update_disabled: bool,
    /// Environment-specific upgrade instructions (e.g. docker compose or
    /// systemctl commands).
    pub instructions: Option<String>,
    /// True when the version comparison could not be performed because one of
    /// the version strings is not valid semver. Callers must not interpret
    /// `update_available = false` as "up to date" in that case.
    #[serde(default)]
    pub version_comparison_unknown: bool,
}

/// Detects whether the current process is running inside a Docker or OCI container.
fn is_running_in_docker() -> bool {
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

/// True when systemd sets one of its service-scoped environment variables.
/// Kept pure so tests do not mutate the process environment.
fn systemd_service_env(
    invocation_id: Option<&std::ffi::OsStr>,
    journal_stream: Option<&std::ffi::OsStr>,
) -> bool {
    invocation_id.is_some() || journal_stream.is_some()
}

/// Detects a process started by a systemd unit. The unit hardening
/// (`ProtectSystem=strict`) makes the installed binary read-only, so in-app
/// replacement cannot work even though `sito update --check` can.
fn is_running_under_systemd() -> bool {
    systemd_service_env(
        std::env::var_os("INVOCATION_ID").as_deref(),
        std::env::var_os("JOURNAL_STREAM").as_deref(),
    )
}

/// Environment restrictions that decide whether in-app replacement is allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateEnvironment {
    /// True when the process runs inside a Docker/OCI container.
    pub is_docker: bool,
    /// True when the process was started by a systemd unit.
    pub is_systemd: bool,
    /// True when this process cannot replace its own binary.
    pub in_app_update_disabled: bool,
    /// Operator guidance for the detected environment.
    pub instructions: Option<String>,
}

/// Detects the update environment without performing any network or disk work.
///
/// CLI callers use this before acquiring the update lock so a Docker or
/// systemd-hosted process reports the actionable notice instead of a
/// permission error from a data directory it cannot use.
pub fn update_environment() -> UpdateEnvironment {
    let is_docker = is_running_in_docker();
    let is_systemd = is_running_under_systemd();
    UpdateEnvironment {
        is_docker,
        is_systemd,
        in_app_update_disabled: is_docker || is_systemd,
        instructions: update_instructions(is_docker, is_systemd),
    }
}

/// Operator guidance for environments that cannot replace their own binary.
fn update_instructions(is_docker: bool, is_systemd: bool) -> Option<String> {
    if is_docker {
        return Some(
            "Running inside a Docker container. In-app binary replacement is disabled.\n\
             Upgrade by pulling the latest image on your Docker host:\n\
             docker compose pull && docker compose up -d"
                .to_string(),
        );
    }
    if is_systemd {
        return Some(
            "Running as a systemd service. In-app binary replacement is disabled.\n\
             Upgrade from a shell after stopping the service:\n\
             sudo systemctl stop sito\n\
             sudo sito update\n\
             sudo systemctl start sito"
                .to_string(),
        );
    }
    None
}

/// Maps the current host CPU architecture to the release target triple.
fn current_target_triple() -> &'static str {
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
fn parse_version_tuple(v: &str) -> Option<(u64, u64, u64)> {
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
fn compare_versions(latest: &str, current: &str) -> Option<std::cmp::Ordering> {
    let latest = parse_version_tuple(latest)?;
    let current = parse_version_tuple(current)?;
    Some(latest.cmp(&current))
}

/// Returns true only when both versions parse and `latest` is strictly newer
/// than `current`. Unparseable versions are never reported as newer.
fn is_version_newer(latest: &str, current: &str) -> bool {
    compare_versions(latest, current) == Some(std::cmp::Ordering::Greater)
}

/// True when both versions parse as semver.
fn versions_comparable(latest: &str, current: &str) -> bool {
    parse_version_tuple(latest).is_some() && parse_version_tuple(current).is_some()
}

/// Queries GitHub Releases for the latest release information.
///
/// The call is serialized with every other update check/apply through the
/// cross-process lock in `data_dir` so the CLI and a running server cannot
/// query or download a release at the same time.
pub async fn check_for_update(
    repo: Option<&str>,
    data_dir: &Path,
) -> Result<UpdateInfo, UpdateError> {
    let _guard = try_acquire_update_operation(data_dir)?;
    check_for_update_locked(repo).await
}

/// Performs the release query assuming the caller already holds the update
/// lock.
async fn check_for_update_locked(repo: Option<&str>) -> Result<UpdateInfo, UpdateError> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let repo_name = repo.unwrap_or(DEFAULT_GITHUB_REPO);
    if !is_allowed_repo(repo_name) {
        return Err(UpdateError::Other(format!(
            "Repository '{repo_name}' is not in the allowed repositories list"
        )));
    }
    let url = format!("https://api.github.com/repos/{repo_name}/releases/latest");
    ensure_allowed_download_url(&url, "Update check")?;

    let client = updater_http_client(Duration::from_secs(10))?;

    let response = client.get(&url).send().await?;
    let environment = update_environment();

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        // No releases published yet
        return Ok(UpdateInfo {
            current_version: current_version.clone(),
            latest_version: current_version,
            update_available: false,
            release_url: format!("https://github.com/{repo_name}"),
            release_notes: "No releases found on GitHub.".to_string(),
            published_at: None,
            is_docker: environment.is_docker,
            is_systemd: environment.is_systemd,
            in_app_update_disabled: environment.in_app_update_disabled,
            instructions: environment.instructions,
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

    let version_comparison_unknown = !versions_comparable(&latest_version, &current_version);
    if version_comparison_unknown {
        tracing::warn!(
            latest = %latest_version,
            current = %current_version,
            "Release tag is not strict semver; update availability is unknown"
        );
    }
    let update_available = is_version_newer(&latest_version, &current_version);

    Ok(UpdateInfo {
        current_version,
        latest_version,
        update_available,
        release_url,
        release_notes,
        published_at,
        is_docker: environment.is_docker,
        is_systemd: environment.is_systemd,
        in_app_update_disabled: environment.in_app_update_disabled,
        instructions: environment.instructions,
        version_comparison_unknown,
    })
}

/// Parses expected SHA256 checksum for a specific archive from SHA256SUMS file content.
fn parse_checksum_from_sums(sums_content: &str, archive_name: &str) -> Option<String> {
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

/// Returns the expected checksum for `archive_name` from the sums manifest.
fn expected_checksum_from_sums(
    sums_content: Option<&str>,
    archive_name: &str,
) -> Result<String, UpdateError> {
    let sums = sums_content.ok_or(UpdateError::ChecksumNotFound)?;
    parse_checksum_from_sums(sums, archive_name).ok_or(UpdateError::ChecksumNotFound)
}

fn compare_checksum(computed_hash: &str, expected_hash: &str) -> Result<(), UpdateError> {
    if !computed_hash.eq_ignore_ascii_case(expected_hash) {
        return Err(UpdateError::ChecksumMismatch {
            expected: expected_hash.to_string(),
            actual: computed_hash.to_string(),
        });
    }
    Ok(())
}

/// Hashes a reader with SHA-256 in fixed-size chunks so the input is never
/// buffered in memory as a whole.
fn hash_reader_sha256<R: Read>(reader: &mut R) -> std::io::Result<String> {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
    }
    Ok(hex::encode(context.finish().as_ref()))
}

/// Verifies that archive checksum matches expected hash from sums manifest.
///
/// This retains the in-memory API for callers that already hold the bytes;
/// [`verify_archive_checksum_file`] is the streaming variant used by the
/// updater.
#[cfg(test)]
fn verify_archive_checksum(
    archive_bytes: &[u8],
    archive_name: &str,
    sums_content: Option<&str>,
) -> Result<(), UpdateError> {
    let expected_hash = expected_checksum_from_sums(sums_content, archive_name)?;
    let mut cursor = std::io::Cursor::new(archive_bytes);
    let computed_hash = hash_reader_sha256(&mut cursor)?;
    compare_checksum(&computed_hash, &expected_hash)
}

/// Verifies an archive on disk without reading it into memory.
async fn verify_archive_checksum_file(
    archive_path: &Path,
    archive_name: &str,
    sums_content: Option<&str>,
) -> Result<(), UpdateError> {
    let expected_hash = expected_checksum_from_sums(sums_content, archive_name)?;
    let path = archive_path.to_path_buf();
    let computed_hash = tokio::task::spawn_blocking(move || -> Result<String, UpdateError> {
        let mut file = std::fs::File::open(&path)?;
        Ok(hash_reader_sha256(&mut file)?)
    })
    .await
    .map_err(|e| UpdateError::Other(format!("Checksum verification task failed: {e}")))??;
    compare_checksum(&computed_hash, &expected_hash)
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
    /// No signature assets were present and the policy does not require one;
    /// SHA-256 checksum verification still applies.
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
    /// Creates a verifier that requires the signature identity to be this
    /// repository's release workflow on a tag ref. A repo-wide `.*` pattern
    /// would also accept signatures minted by any other (or future) workflow
    /// with OIDC access.
    pub fn new(repo: &str) -> Self {
        Self {
            identity_regexp: format!(
                "^https://github.com/{repo}/\\.github/workflows/release\\.yml@refs/tags/.*$"
            ),
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

/// Returns true when the `cosign` binary is available to the updater.
///
/// Callers use this for an actionable preflight before downloading a release.
pub fn cosign_available() -> bool {
    CosignVerifier::binary().is_some()
}

/// Actionable guidance for a host that requires signatures but has no cosign.
pub const COSIGN_MISSING_GUIDANCE: &str = "install cosign (the installer does this by default; \
     otherwise re-run contrib/install.sh or see docs/installation.md \"Updating sito\") or set \
     server.update_require_signature = false only if you accept SHA-256-only integrity";

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
            UpdateError::SignatureVerifierUnavailable(format!(
                "cosign binary not found in /usr/bin, /usr/local/bin or PATH; {COSIGN_MISSING_GUIDANCE}"
            ))
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
fn find_signature_assets(
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
/// * A signature that is present must verify, regardless of `required`; a
///   present signature without an installed verifier is an error.
/// * Only when no signature assets are present may `required = false` skip
///   verification (SHA-256 checksum verification still applies).
async fn verify_release_signature(
    artifact: &Path,
    signature: Option<&Path>,
    certificate: Option<&Path>,
    required: bool,
    verifier: &dyn SignatureVerifier,
) -> Result<SignatureOutcome, UpdateError> {
    if let (Some(sig), Some(cert)) = (signature, certificate) {
        if !verifier.is_available() {
            // A present signature is never silently ignored, even when the
            // policy does not require signatures: that would let an attacker
            // downgrade verification by shipping unverifiable assets.
            return Err(UpdateError::SignatureVerifierUnavailable(format!(
                "release ships a signature but no verifier is installed; {COSIGN_MISSING_GUIDANCE}"
            )));
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

/// Removes a temporary file or directory when it goes out of scope, so every
/// error path cleans up after itself without explicit `remove_*` calls.
struct TempFileGuard {
    path: PathBuf,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.path.is_dir() {
            let _ = std::fs::remove_dir_all(&self.path);
        } else {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Downloads an allowlisted updater asset with a size cap.
async fn download_capped(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    cap: u64,
) -> Result<(), UpdateError> {
    ensure_allowed_download_url(url, "Download")?;
    download_capped_raw(client, url, dest, cap).await
}

/// Streams a download into `dest`, aborting as soon as the response exceeds
/// `cap` bytes. A declared `Content-Length` above the cap is rejected before
/// the file is created; chunked responses are covered by the running total.
///
/// This variant does not validate the initial URL so loopback test servers can
/// exercise the redirect policy; production callers use [`download_capped`].
async fn download_capped_raw(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    cap: u64,
) -> Result<(), UpdateError> {
    let response = client.get(url).send().await?;

    if let Some(declared) = response.content_length()
        && declared > cap
    {
        return Err(UpdateError::Other(format!(
            "Download from '{url}' declares {declared} bytes, exceeding the {cap}-byte limit"
        )));
    }

    let result = write_capped_stream(response, dest, cap).await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(dest).await;
    }
    result
}

async fn write_capped_stream(
    response: reqwest::Response,
    dest: &Path,
    cap: u64,
) -> Result<(), UpdateError> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(dest).await?;
    let mut stream = response.bytes_stream();
    let mut total: u64 = 0;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        total = total.saturating_add(chunk.len() as u64);
        if total > cap {
            drop(file);
            return Err(UpdateError::Other(format!(
                "Download exceeded the {cap}-byte limit; aborting"
            )));
        }
        file.write_all(&chunk).await?;
    }

    file.flush().await?;
    file.sync_all().await?;
    Ok(())
}

/// Creates a private scratch directory for downloaded signature assets.
async fn create_private_dir(path: &Path) -> Result<(), UpdateError> {
    tokio::fs::create_dir_all(path).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    }
    Ok(())
}

/// Rejects release asset names that could escape the scratch directory when
/// joined into a temporary path.
fn safe_asset_name(name: &str) -> Result<&str, UpdateError> {
    if name.is_empty()
        || name.contains(['/', '\\'])
        || Path::new(name)
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            != Some(name)
    {
        return Err(UpdateError::Other(format!(
            "Release asset name '{name}' is not a plain file name"
        )));
    }
    Ok(name)
}

/// Downloads release signature assets (when present) and applies the configured
/// signature policy to the archive on disk.
#[allow(clippy::too_many_arguments)]
async fn apply_signature_policy(
    client: &reqwest::Client,
    repo_name: &str,
    archive: &ReleaseAsset,
    archive_path: &Path,
    sig_asset: Option<&ReleaseAsset>,
    cert_asset: Option<&ReleaseAsset>,
    required: bool,
) -> Result<SignatureOutcome, UpdateError> {
    let verifier = CosignVerifier::new(repo_name);

    let (sig, cert) = match (sig_asset, cert_asset) {
        (None, None) => {
            return verify_release_signature(archive_path, None, None, required, &verifier).await;
        }
        (Some(sig), Some(cert)) => (sig, cert),
        (Some(sig), None) => {
            return Err(UpdateError::SignatureIncomplete(format!(
                "release ships '{}' without the matching .pem certificate",
                sig.name
            )));
        }
        (None, Some(cert)) => {
            return Err(UpdateError::SignatureIncomplete(format!(
                "release ships '{}' without the matching .sig signature",
                cert.name
            )));
        }
    };

    for asset in [sig, cert] {
        if asset.size > MAX_SIGNATURE_ASSET_BYTES {
            return Err(UpdateError::Other(format!(
                "Signature asset '{}' is unexpectedly large ({} bytes)",
                asset.name, asset.size
            )));
        }
        ensure_allowed_download_url(&asset.browser_download_url, "Signature asset")?;
    }

    // cosign needs real files; use a unique temporary directory and always clean up.
    let temp_dir =
        std::env::temp_dir().join(format!("sito-update-verify-{}", rand::random::<u64>()));
    let _temp_guard = TempFileGuard::new(temp_dir.clone());
    create_private_dir(&temp_dir).await?;
    let archive_name = safe_asset_name(&archive.name)?;
    safe_asset_name(&sig.name)?;
    safe_asset_name(&cert.name)?;
    let sig_path = temp_dir.join(format!("{archive_name}.sig"));
    let cert_path = temp_dir.join(format!("{archive_name}.pem"));

    debug!(asset = %sig.name, "Downloading release signature");
    download_capped(
        client,
        &sig.browser_download_url,
        &sig_path,
        MAX_SIGNATURE_ASSET_BYTES,
    )
    .await?;
    download_capped(
        client,
        &cert.browser_download_url,
        &cert_path,
        MAX_SIGNATURE_ASSET_BYTES,
    )
    .await?;

    verify_release_signature(
        archive_path,
        Some(&sig_path),
        Some(&cert_path),
        required,
        &verifier,
    )
    .await
}

/// Extracts the `sito` executable from a gzipped release tarball read from
/// `reader`, enforcing a per-entry decompression cap so a tar bomb cannot
/// exhaust memory even when the compressed archive passed the download-size
/// check.
fn extract_binary_from_reader<R: Read>(reader: R) -> Result<Vec<u8>, UpdateError> {
    let gz = GzDecoder::new(reader);
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

/// In-memory compatibility wrapper around [`extract_binary_from_reader`].
#[cfg(test)]
fn extract_binary_from_archive(archive_bytes: &[u8]) -> Result<Vec<u8>, UpdateError> {
    extract_binary_from_reader(archive_bytes)
}

/// Extracts the binary from an archive on disk without buffering the archive.
async fn extract_binary_from_file(archive_path: &Path) -> Result<Vec<u8>, UpdateError> {
    let path = archive_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&path)?;
        extract_binary_from_reader(file)
    })
    .await
    .map_err(|e| UpdateError::Other(format!("Archive extraction task failed: {e}")))?
}

/// Lists every extended attribute name on `path`.
#[cfg(unix)]
fn list_xattr_names(path: &Path) -> std::io::Result<Vec<Vec<u8>>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "executable path contains a NUL byte",
        )
    })?;

    loop {
        // SAFETY: `c_path` is a valid NUL-terminated path and a null buffer with
        // length 0 is the documented way to query the required size.
        let size = unsafe { libc::listxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            let err = std::io::Error::last_os_error();
            // Filesystems without xattr support have nothing to preserve.
            if err.raw_os_error() == Some(libc::ENOTSUP) {
                return Ok(Vec::new());
            }
            return Err(err);
        }
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u8; size as usize];
        // SAFETY: the buffer is valid for `buffer.len()` bytes and the path is
        // NUL-terminated.
        let written = unsafe {
            libc::listxattr(
                c_path.as_ptr(),
                buffer.as_mut_ptr().cast::<libc::c_char>(),
                buffer.len(),
            )
        };
        if written < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ERANGE) {
                // Attributes grew between the size query and the read; retry.
                continue;
            }
            return Err(err);
        }
        buffer.truncate(written as usize);
        return Ok(buffer
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
            .map(<[u8]>::to_vec)
            .collect());
    }
}

/// Reads one extended attribute value from `path`.
#[cfg(unix)]
fn get_xattr(path: &Path, name: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "executable path contains a NUL byte",
        )
    })?;
    let c_name = CString::new(name).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "extended attribute name contains a NUL byte",
        )
    })?;

    loop {
        // SAFETY: valid path and name pointers; a null buffer queries the size.
        let size =
            unsafe { libc::getxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u8; size as usize];
        // SAFETY: buffer is valid for `buffer.len()` bytes.
        let written = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
            )
        };
        if written < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            return Err(err);
        }
        buffer.truncate(written as usize);
        return Ok(buffer);
    }
}

/// Copies every extended attribute (including `security.capability`) from
/// `source` to `destination`.
#[cfg(unix)]
fn copy_xattrs(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_dest = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination path contains a NUL byte",
        )
    })?;

    for name in list_xattr_names(source)? {
        let value = get_xattr(source, &name)?;
        let c_name = CString::new(name).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "extended attribute name contains a NUL byte",
            )
        })?;
        // SAFETY: valid NUL-terminated path/name and a value buffer valid for
        // `value.len()` bytes.
        let rc = unsafe {
            libc::setxattr(
                c_dest.as_ptr(),
                c_name.as_ptr(),
                value.as_ptr().cast::<libc::c_void>(),
                value.len(),
                0,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Writes an executable with a private initial mode, then makes it executable.
async fn write_private_executable(path: &Path, content: &[u8]) -> Result<(), UpdateError> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(path).await?;
    file.write_all(content).await?;
    file.flush().await?;
    file.sync_all().await?;
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).await?;
    }
    Ok(())
}

/// Reads at most `cap` bytes while still draining the pipe, so a noisy staged
/// binary cannot exhaust memory or block on a full pipe.
async fn read_capped_output<R: tokio::io::AsyncRead + Unpin>(mut reader: R, cap: usize) -> Vec<u8> {
    use tokio::io::AsyncReadExt;

    let mut output = Vec::with_capacity(cap.min(4096));
    let mut buffer = [0_u8; 4096];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        if output.len() < cap {
            let take = (cap - output.len()).min(read);
            output.extend_from_slice(&buffer[..take]);
        }
    }
    output
}

/// Runs the staged binary once to prove it is executable before replacing the
/// running server binary. Output is captured with a hard cap and the child is
/// killed if the verification future is cancelled by the timeout.
async fn verify_executable_version(path: &Path) -> Result<(), UpdateError> {
    const MAX_OUTPUT_BYTES: usize = 4096;

    let (status, stderr) = tokio::time::timeout(Duration::from_secs(10), async {
        let mut child = tokio::process::Command::new(path)
            .arg("--version")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let read_stdout = async {
            match stdout {
                Some(stdout) => read_capped_output(stdout, MAX_OUTPUT_BYTES).await,
                None => Vec::new(),
            }
        };
        let read_stderr = async {
            match stderr {
                Some(stderr) => read_capped_output(stderr, MAX_OUTPUT_BYTES).await,
                None => Vec::new(),
            }
        };
        let (_, stderr) = tokio::join!(read_stdout, read_stderr);
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status, stderr))
    })
    .await
    .map_err(|_| {
        UpdateError::Other(
            "The downloaded executable did not respond to --version within 10 seconds".to_string(),
        )
    })?
    .map_err(|e| {
        UpdateError::Other(format!(
            "The downloaded executable could not be run for verification: {e}"
        ))
    })?;
    if !status.success() {
        let detail = String::from_utf8_lossy(&stderr);
        return Err(UpdateError::Other(format!(
            "The downloaded executable failed --version verification with status {status}: {}",
            detail.lines().last().unwrap_or("no stderr")
        )));
    }
    Ok(())
}

/// Replaces `current_exe` with `new_exe`, keeping a backup until the rename
/// succeeds. A failed rename restores the backup.
async fn replace_with_backup(new_exe: &Path, current_exe: &Path) -> Result<(), UpdateError> {
    let parent_dir = current_exe.parent().ok_or_else(|| {
        UpdateError::Other("Could not resolve parent directory of executable".to_string())
    })?;

    // A fresh install has nothing to back up or roll back to.
    match tokio::fs::metadata(current_exe).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            tokio::fs::rename(new_exe, current_exe).await?;
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    }

    let backup = parent_dir.join(format!(".sito_backup_{}", rand::random::<u32>()));
    let _backup_guard = TempFileGuard::new(backup.clone());

    tokio::fs::copy(current_exe, &backup).await?;
    #[cfg(unix)]
    if let Ok(metadata) = std::fs::metadata(current_exe) {
        let _ = tokio::fs::set_permissions(&backup, metadata.permissions()).await;
    }

    match tokio::fs::rename(new_exe, current_exe).await {
        Ok(()) => {
            let _ = tokio::fs::remove_file(&backup).await;
            Ok(())
        }
        Err(error) => {
            if let Err(restore_error) = tokio::fs::rename(&backup, current_exe).await {
                tracing::error!(
                    %error,
                    %restore_error,
                    "Failed to install the new executable and could not restore the backup"
                );
                return Err(UpdateError::Other(format!(
                    "Failed to install the new executable ({error}); restoring the backup also failed ({restore_error})"
                )));
            }
            Err(UpdateError::Io(error))
        }
    }
}

/// Writes the extracted binary next to the running executable, verifies it
/// with `--version`, then atomically replaces the old binary while keeping a
/// backup for rollback.
///
/// When the target already exists its permission bits and extended attributes
/// (notably `security.capability`, which grants `CAP_NET_BIND_SERVICE`) are
/// copied onto the replacement before the rename, so an update cannot silently
/// strip the capability the service needs to bind privileged DNS ports. A
/// missing target is installed mode 0755.
async fn install_binary_atomically(
    binary_content: &[u8],
    current_exe: &Path,
) -> Result<(), UpdateError> {
    let parent_dir = current_exe.parent().ok_or_else(|| {
        UpdateError::Other("Could not resolve parent directory of executable".to_string())
    })?;

    #[cfg(unix)]
    let existing_metadata = match tokio::fs::metadata(current_exe).await {
        Ok(metadata) if metadata.is_file() => Some(metadata),
        Ok(_) => None,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err.into()),
    };

    let temp_exe = parent_dir.join(format!(".sito_update_{}", rand::random::<u32>()));
    let _temp_guard = TempFileGuard::new(temp_exe.clone());

    write_private_executable(&temp_exe, binary_content).await?;
    verify_executable_version(&temp_exe).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = existing_metadata
            .as_ref()
            .map_or(0o755, |metadata| metadata.permissions().mode() & 0o7777);
        let perms = std::fs::Permissions::from_mode(mode);
        tokio::fs::set_permissions(&temp_exe, perms).await?;

        if existing_metadata.is_some() {
            let source = current_exe.to_path_buf();
            let destination = temp_exe.clone();
            tokio::task::spawn_blocking(move || copy_xattrs(&source, &destination))
                .await
                .map_err(|err| {
                    UpdateError::Other(format!("Extended-attribute copy task failed: {err}"))
                })??;
        }
    }

    replace_with_backup(&temp_exe, current_exe).await
}

/// Name of the cross-process update lock inside `server.data_dir`.
pub const UPDATE_LOCK_FILE: &str = "update.lock";

/// Returns the shared update lock path for a configured data directory.
pub fn update_lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join(UPDATE_LOCK_FILE)
}

/// Cross-process exclusive update lease backed by `flock`.
///
/// The file's existence is not authoritative; the advisory lock is. A stale
/// lock file left behind by a crash is harmless because the kernel releases
/// the lock when the last descriptor closes. The file is intentionally never
/// removed and carries no meaningful content, so a waiter can never be fooled
/// by a leftover path or read a stale PID.
///
/// On Unix this uses `flock(LOCK_EX | LOCK_NB)`. On non-Unix platforms the
/// standard library's per-handle file lock is used as a best-effort fallback;
/// only Unix is supported for coordinated CLI/server updates.
#[derive(Debug)]
pub struct UpdateLock {
    _file: File,
    path: PathBuf,
}

impl UpdateLock {
    /// Acquires the update lock for `data_dir`, creating the directory and the
    /// 0600 lock file when needed.
    ///
    /// Returns [`UpdateError::UpdateInProgress`] immediately when another
    /// process (or another independently opened descriptor) holds the lock.
    pub fn acquire(data_dir: &Path) -> Result<Self, UpdateError> {
        std::fs::create_dir_all(data_dir)?;
        let path = update_lock_path(data_dir);

        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
            // Refuse a symlink planted at the lock path; the lock is a plain
            // file owned by the data directory's owner.
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(&path)?;

        try_lock_file(&file)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // A root CLI run must leave a lock the unprivileged server can
            // open. Match the data directory's owner before narrowing the mode.
            normalize_lock_ownership(&file, data_dir)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }

        // Drop any stale content from an earlier writer: the path must never
        // communicate update state, only the advisory lock does.
        file.set_len(0)?;
        debug!(path = %path.display(), "Acquired cross-process update lock");
        Ok(Self { _file: file, path })
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        // `flock` is released when the descriptor is closed after this method
        // returns. The path is deliberately left in place for the next owner.
        debug!(path = %self.path.display(), "Releasing cross-process update lock");
    }
}

/// Makes a lock file created by a privileged CLI usable by the data
/// directory's owner.
///
/// The documented update flow is `sudo sito update` while the service runs as
/// an unprivileged user. Without this, the root-created 0600 lock would later
/// be unopenable by the server and every API/UI update check would fail. Only
/// a root process changes ownership; an unprivileged caller already owns the
/// file it can create, so it is left untouched.
#[cfg(unix)]
fn normalize_lock_ownership(file: &File, data_dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;

    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }

    let dir_meta = std::fs::metadata(data_dir)?;
    let file_meta = file.metadata()?;
    if file_meta.uid() == dir_meta.uid() && file_meta.gid() == dir_meta.gid() {
        return Ok(());
    }

    // SAFETY: `file` owns a valid descriptor and the ids come from a directory
    // metadata lookup.
    let rc = unsafe {
        libc::fchown(
            file.as_raw_fd(),
            dir_meta.uid() as libc::uid_t,
            dir_meta.gid() as libc::gid_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Attempts a non-blocking exclusive lock on `file`.
#[cfg(unix)]
fn try_lock_file(file: &File) -> Result<(), UpdateError> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: `file` owns a valid descriptor for the lifetime of the call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.kind() == std::io::ErrorKind::WouldBlock {
        return Err(UpdateError::UpdateInProgress);
    }
    Err(err.into())
}

/// Attempts a non-blocking exclusive lock on `file` (non-Unix fallback).
#[cfg(not(unix))]
fn try_lock_file(file: &File) -> Result<(), UpdateError> {
    use std::fs::TryLockError;

    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(UpdateError::UpdateInProgress),
        Err(TryLockError::Error(err)) => Err(err.into()),
    }
}

/// The in-process update lock prevents two admin requests (or an admin and a
/// CLI invocation in the same process) from replacing the binary concurrently.
fn update_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn try_acquire_update_lock() -> Result<tokio::sync::MutexGuard<'static, ()>, UpdateError> {
    update_lock()
        .try_lock()
        .map_err(|_| UpdateError::UpdateInProgress)
}

/// Serializes an update operation across threads (the in-process mutex) and
/// across processes (the `flock` lease in `data_dir`).
///
/// `_process` is declared first so the file lock is released before the
/// in-process mutex; a competing thread cannot observe a free mutex while the
/// kernel lock is still held.
struct UpdateOperationGuard {
    _process: UpdateLock,
    _threads: tokio::sync::MutexGuard<'static, ()>,
}

fn try_acquire_update_operation(data_dir: &Path) -> Result<UpdateOperationGuard, UpdateError> {
    let threads = try_acquire_update_lock()?;
    let process = UpdateLock::acquire(data_dir)?;
    Ok(UpdateOperationGuard {
        _process: process,
        _threads: threads,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateDecision {
    Install,
    UpToDate,
}

/// Decides whether an explicit apply may proceed.
///
/// `update_available = false` is only "up to date" when both versions parsed.
/// An unknown comparison requires `force`, so a non-semver tag can never make
/// the updater claim the server is current when it is not.
fn update_decision(info: &UpdateInfo, force: bool) -> Result<UpdateDecision, UpdateError> {
    if info.version_comparison_unknown && !force {
        return Err(UpdateError::VersionComparisonUnknown {
            current: info.current_version.clone(),
            latest: info.latest_version.clone(),
        });
    }
    if !info.update_available && !force {
        return Ok(UpdateDecision::UpToDate);
    }
    Ok(UpdateDecision::Install)
}

/// Downloads the latest release archive, verifies the release signature (when
/// present) and SHA-256 checksum, extracts the binary, and replaces the running
/// executable.
pub async fn apply_update(
    repo: Option<&str>,
    force: bool,
    require_signature: bool,
    data_dir: &Path,
) -> Result<String, UpdateError> {
    let environment = update_environment();
    if environment.is_docker {
        return Err(UpdateError::DockerEnvironment(
            "In-app binary update is disabled inside Docker. Use container image management."
                .to_string(),
        ));
    }
    if environment.is_systemd {
        return Err(UpdateError::SystemdEnvironment(
            "In-app binary update is disabled for a systemd service. Stop the service and run \
             'sudo sito update', then start it again."
                .to_string(),
        ));
    }

    // Acquire before any network work so a second request fails fast with a
    // conflict instead of racing the download/verification/replace sequence.
    let _update_guard = try_acquire_update_operation(data_dir)?;

    let repo_name = repo.unwrap_or(DEFAULT_GITHUB_REPO);
    if !is_allowed_repo(repo_name) {
        return Err(UpdateError::Other(format!(
            "Repository '{repo_name}' is not in the allowed repositories list"
        )));
    }
    let update_info = check_for_update_locked(Some(repo_name)).await?;

    if update_decision(&update_info, force)? == UpdateDecision::UpToDate {
        return Ok(format!(
            "sito is already on the latest version (v{}). Use force to reinstall.",
            update_info.current_version
        ));
    }

    let url = format!("https://api.github.com/repos/{repo_name}/releases/latest");
    ensure_allowed_download_url(&url, "Release metadata")?;
    let client = updater_http_client(Duration::from_secs(60))?;

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
    ensure_allowed_download_url(&archive.browser_download_url, "Release asset")?;
    ensure_allowed_download_url(&sha_asset.browser_download_url, "Checksum asset")?;

    info!(asset = %archive.name, url = %archive.browser_download_url, "Downloading release archive");
    let archive_path =
        std::env::temp_dir().join(format!("sito-update-archive-{}", rand::random::<u64>()));
    let _archive_guard = TempFileGuard::new(archive_path.clone());
    download_capped(
        &client,
        &archive.browser_download_url,
        &archive_path,
        MAX_UPDATE_ARCHIVE_BYTES,
    )
    .await?;

    // 2. Release signature policy (present signatures must always verify)
    let (sig_asset, cert_asset) = find_signature_assets(&assets, &archive.name);
    apply_signature_policy(
        &client,
        repo_name,
        &archive,
        &archive_path,
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

    verify_archive_checksum_file(&archive_path, &archive.name, Some(&sums_content)).await?;
    info!(asset = %archive.name, "SHA256 checksum verified successfully");

    // 4. Extract 'sito' executable from tarball
    let binary_content = extract_binary_from_file(&archive_path).await?;

    // 5. Replace current executable atomically
    let current_exe = std::env::current_exe()?;
    install_binary_atomically(&binary_content, &current_exe).await?;

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

    fn update_info(unknown: bool) -> UpdateInfo {
        UpdateInfo {
            current_version: "2.0.0-alpha.1".to_string(),
            latest_version: if unknown {
                "nightly".to_string()
            } else {
                "2.0.0".to_string()
            },
            update_available: !unknown,
            release_url: "https://github.com/kubaeror/sito-dns/releases".to_string(),
            release_notes: String::new(),
            published_at: None,
            is_docker: false,
            is_systemd: false,
            in_app_update_disabled: false,
            instructions: None,
            version_comparison_unknown: unknown,
        }
    }

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
    fn test_systemd_service_detection() {
        let id = std::ffi::OsStr::new("abc");
        let journal = std::ffi::OsStr::new("1:2");
        assert!(!systemd_service_env(None, None));
        assert!(systemd_service_env(Some(id), None));
        assert!(systemd_service_env(None, Some(journal)));
        assert!(systemd_service_env(Some(id), Some(journal)));
    }

    #[test]
    fn test_unknown_version_requires_force_never_up_to_date() {
        let unknown = update_info(true);
        let err = update_decision(&unknown, false).unwrap_err();
        assert!(matches!(err, UpdateError::VersionComparisonUnknown { .. }));
        assert_eq!(
            update_decision(&unknown, true).unwrap(),
            UpdateDecision::Install,
            "force must allow an explicit reinstall"
        );

        let known = update_info(false);
        // Make the known release look older so it is genuinely up to date.
        let mut up_to_date = known.clone();
        up_to_date.update_available = false;
        up_to_date.latest_version = up_to_date.current_version.clone();
        assert_eq!(
            update_decision(&up_to_date, false).unwrap(),
            UpdateDecision::UpToDate
        );
        assert_eq!(
            update_decision(&up_to_date, true).unwrap(),
            UpdateDecision::Install
        );
    }

    #[tokio::test]
    async fn test_update_lock_serializes_applies() {
        let first = match try_acquire_update_lock() {
            Ok(guard) => guard,
            Err(e) => panic!("first lock acquisition failed: {e}"),
        };
        match try_acquire_update_lock() {
            Ok(_) => panic!("a concurrent update must not acquire the lock"),
            Err(UpdateError::UpdateInProgress) => {}
            Err(e) => panic!("unexpected lock error: {e}"),
        }
        drop(first);
        assert!(try_acquire_update_lock().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_cross_process_update_lock_is_exclusive_and_reusable() {
        use std::os::unix::io::AsRawFd;

        let dir = test_scratch_dir("update-lock");
        let path = update_lock_path(&dir);
        // Stale content from a crashed/old writer must be ignored and wiped.
        std::fs::write(&path, b"stale-pid 1234").unwrap();
        let lock = UpdateLock::acquire(&dir).unwrap();
        assert_eq!(path, dir.join(UPDATE_LOCK_FILE));
        assert!(path.is_file(), "the lock file must be created");
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            0,
            "lock file content must not be meaningful"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the update lock must be mode 0600");
        }

        // Simulate another process: a separately opened descriptor is an
        // independent lock owner even inside the same process.
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        // SAFETY: `contender` owns a valid descriptor.
        let rc = unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, -1, "an independent descriptor must not lock");
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock
        );

        let err = UpdateLock::acquire(&dir).expect_err("second acquisition must fail");
        assert!(matches!(err, UpdateError::UpdateInProgress), "got {err:?}");

        drop(lock);
        // The stale file is harmless; the released advisory lock allows reuse.
        assert!(path.is_file(), "the lock file must not be deleted");
        let reacquired = UpdateLock::acquire(&dir).expect("lock must be reusable");
        drop(reacquired);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_update_lock_creates_missing_parent_directory() {
        let dir = test_scratch_dir("update-lock-parent");
        let nested = dir.join("nested").join("data");
        assert!(!nested.exists());

        let lock = UpdateLock::acquire(&nested).expect("missing parents must be created");
        assert!(nested.is_dir());
        assert!(update_lock_path(&nested).is_file());
        drop(lock);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Root CI runs `sudo sito update` against a data dir owned by the
    /// unprivileged service user. The lock it leaves behind must be openable by
    /// that user, otherwise the server's update API breaks after one CLI run.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_update_lock_is_owned_like_data_dir_and_openable_by_owner() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::os::unix::process::CommandExt;

        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("not running as root; skipped cross-user update lock test");
            return;
        }

        let dir = test_scratch_dir("update-lock-owner");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let service_uid = 65_534_u32;
        let service_gid = 65_534_u32;
        let c_path = CString::new(dir.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid NUL-terminated path.
        let rc = unsafe {
            libc::chown(
                c_path.as_ptr(),
                service_uid as libc::uid_t,
                service_gid as libc::gid_t,
            )
        };
        if rc != 0 {
            eprintln!(
                "could not chown test data dir; skipped cross-user update lock test: {}",
                std::io::Error::last_os_error()
            );
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        // Root CLI acquires and releases the lock (the update command exits).
        let lock = UpdateLock::acquire(&dir).unwrap();
        let path = update_lock_path(&dir);
        let file_meta = std::fs::metadata(&path).unwrap();
        assert_eq!(
            file_meta.uid(),
            service_uid,
            "lock owner must match data dir"
        );
        assert_eq!(
            file_meta.gid(),
            service_gid,
            "lock group must match data dir"
        );
        assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);
        drop(lock);

        // The unprivileged server/user must be able to open the remaining file.
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exec 3<>\"$1\"")
            .arg("sh")
            .arg(&path)
            .uid(service_uid)
            .gid(service_gid)
            .status()
            .expect("spawn unprivileged opener");
        assert!(
            status.success(),
            "the configured data-dir owner must be able to open the update lock"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn parsed(url: &str) -> Url {
        Url::parse(url).unwrap()
    }

    #[test]
    fn test_redirect_allows_github_release_asset_hosts() {
        let previous = [parsed(
            "https://github.com/kubaeror/sito-dns/releases/download/v2.0.0/sito.tar.gz",
        )];
        for target in [
            "https://objects.githubusercontent.com/github-production-release-asset/file",
            "https://release-assets.githubusercontent.com/github-production-release-asset/file",
        ] {
            assert_eq!(
                validate_redirect(&previous, &parsed(target)),
                Ok(()),
                "legitimate GitHub asset redirect {target} must be allowed"
            );
        }
    }

    #[test]
    fn test_redirect_rejects_cross_host_target() {
        let previous = [parsed("https://github.com/kubaeror/sito-dns/releases")];
        let rejection =
            validate_redirect(&previous, &parsed("https://evil.example/asset")).unwrap_err();
        assert!(matches!(
            rejection,
            RedirectRejection::DisallowedHost { .. }
        ));
    }

    #[test]
    fn test_redirect_rejects_https_downgrade() {
        let previous = [parsed("https://github.com/kubaeror/sito-dns/releases")];
        for target in [
            "http://github.com/kubaeror/sito-dns/releases",
            "http://objects.githubusercontent.com/file",
        ] {
            let rejection = validate_redirect(&previous, &parsed(target)).unwrap_err();
            assert!(
                matches!(rejection, RedirectRejection::InsecureScheme { .. }),
                "downgrade to {target} must be rejected"
            );
        }
    }

    #[test]
    fn test_redirect_rejects_loops_and_excess_hops() {
        let github = parsed("https://github.com/kubaeror/sito-dns/releases");
        let objects = parsed("https://objects.githubusercontent.com/file");
        let rejection = validate_redirect(&[github.clone(), objects.clone()], &github).unwrap_err();
        assert!(matches!(rejection, RedirectRejection::Loop { .. }));

        let mut previous: Vec<Url> = (0..=MAX_UPDATE_REDIRECTS)
            .map(|i| parsed(&format!("https://github.com/hop/{i}")))
            .collect();
        let too_many = parsed("https://github.com/hop/final");
        let rejection = validate_redirect(&previous, &too_many).unwrap_err();
        assert!(matches!(
            rejection,
            RedirectRejection::TooManyRedirects { .. }
        ));

        // A chain exactly at the cap is still accepted.
        previous.pop();
        assert_eq!(validate_redirect(&previous, &too_many), Ok(()));
    }

    #[test]
    fn test_initial_update_url_is_validated_before_request() {
        assert!(
            ensure_allowed_download_url(
                "https://api.github.com/repos/kubaeror/sito-dns/releases/latest",
                "Update check"
            )
            .is_ok()
        );
        for url in [
            "http://api.github.com/repos/kubaeror/sito-dns/releases/latest",
            "https://evil.example/asset",
            "https://github.com.evil.example/asset",
        ] {
            assert!(
                ensure_allowed_download_url(url, "Release asset").is_err(),
                "initial URL {url} must be rejected"
            );
        }
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
        assert!(
            !target.is_empty(),
            "current target triple must not be empty"
        );
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
    fn test_asset_names_cannot_escape_the_scratch_directory() {
        assert_eq!(
            safe_asset_name("sito-v1.2.3-x86_64-unknown-linux-gnu.tar.gz").unwrap(),
            "sito-v1.2.3-x86_64-unknown-linux-gnu.tar.gz"
        );
        for name in [
            "",
            "../escape",
            "dir/asset.tar.gz",
            "dir\\asset.tar.gz",
            "/etc/passwd",
        ] {
            assert!(
                safe_asset_name(name).is_err(),
                "asset name {name:?} must be rejected"
            );
        }
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

    #[test]
    fn test_cosign_identity_is_pinned_to_release_workflow_tags() {
        let verifier = CosignVerifier::new("kubaeror/sito-dns");
        // Must not accept signatures from arbitrary repo workflows/branches.
        assert!(
            verifier
                .identity_regexp
                .contains("\\.github/workflows/release\\.yml@refs/tags/"),
            "identity regexp must pin the release workflow and tag refs: {}",
            verifier.identity_regexp
        );
        assert!(verifier.identity_regexp.starts_with('^'));
        assert!(verifier.identity_regexp.ends_with('$'));
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
    async fn test_signature_policy_present_without_verifier_optional_fails() {
        let verifier = MockVerifier {
            available: false,
            result: Ok(()),
        };
        let err = verify_release_signature(
            Path::new("archive.tar.gz"),
            Some(Path::new("archive.tar.gz.sig")),
            Some(Path::new("archive.tar.gz.pem")),
            false, // optional policy must not silently skip present assets
            &verifier,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, UpdateError::SignatureVerifierUnavailable(_)));
    }

    #[tokio::test]
    async fn test_signature_policy_incomplete_pair_fails() {
        let archive = asset("sito-v1.4.0-x86_64-unknown-linux-gnu.tar.gz");
        let sig = asset("sito-v1.4.0-x86_64-unknown-linux-gnu.tar.gz.sig");
        let client = reqwest::Client::new();

        let err = apply_signature_policy(
            &client,
            "kubaeror/sito-dns",
            &archive,
            Path::new("/nonexistent/archive.tar.gz"),
            Some(&sig),
            None,
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, UpdateError::SignatureIncomplete(_)));

        let cert = asset("sito-v1.4.0-x86_64-unknown-linux-gnu.tar.gz.pem");
        let err = apply_signature_policy(
            &client,
            "kubaeror/sito-dns",
            &archive,
            Path::new("/nonexistent/archive.tar.gz"),
            None,
            Some(&cert),
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, UpdateError::SignatureIncomplete(_)));
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
        // The error must tell the operator how to fix the host, not just
        // report that verification failed.
        let msg = err.to_string();
        assert!(msg.contains("cosign"), "unexpected error: {msg}");
        assert!(msg.contains("install cosign"), "unexpected error: {msg}");
        assert!(
            msg.contains("update_require_signature"),
            "unexpected error: {msg}"
        );
    }

    fn test_scratch_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sito-update-test-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Serves exactly one HTTP/1.1 response on a loopback listener.
    async fn serve_http_once(response: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 8192];
            let _ = socket.read(&mut request).await;
            let _ = socket.write_all(&response).await;
            let _ = socket.shutdown().await;
        });
        (format!("http://{addr}/asset"), handle)
    }

    fn http_response_with_content_length(body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    fn http_chunked_response(chunks: &[&[u8]]) -> Vec<u8> {
        let mut response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        for chunk in chunks {
            response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            response.extend_from_slice(chunk);
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(b"0\r\n\r\n");
        response
    }

    fn http_redirect_response(location: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    }

    fn error_chain_contains(err: &dyn std::error::Error, needle: &str) -> bool {
        let mut current = Some(err);
        while let Some(error) = current {
            if error.to_string().contains(needle) {
                return true;
            }
            current = error.source();
        }
        false
    }

    #[tokio::test]
    async fn test_download_redirect_policy_blocks_before_contacting_target() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::net::TcpListener;

        // A default reqwest client would follow this HTTP redirect and contact
        // the second listener. The updater policy must reject it first.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();
        let contacted = Arc::new(AtomicBool::new(false));
        let contacted_probe = Arc::clone(&contacted);
        let probe = tokio::spawn(async move {
            if let Ok(Ok(_)) =
                tokio::time::timeout(Duration::from_millis(300), listener.accept()).await
            {
                contacted_probe.store(true, Ordering::SeqCst);
            }
        });

        let response = http_redirect_response(&format!("http://{target_addr}/asset"));
        let (url, server) = serve_http_once(response).await;

        let dir = test_scratch_dir("redirect-contact");
        let dest = dir.join("archive.tar.gz");
        let client = updater_http_client(Duration::from_secs(5)).unwrap();

        let err = download_capped_raw(&client, &url, &dest, MAX_UPDATE_ARCHIVE_BYTES)
            .await
            .unwrap_err();
        server.await.unwrap();
        probe.await.unwrap();

        assert!(
            error_chain_contains(&err, "non-HTTPS"),
            "the policy rejection must be visible in the error chain: {err:?}"
        );
        assert!(
            !contacted.load(Ordering::SeqCst),
            "the redirect target must never be contacted"
        );
        assert!(
            !dest.exists(),
            "a rejected redirect must not create or write the destination"
        );
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            0,
            "no download residue after a rejected redirect"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_download_redirect_policy_rejects_cross_host_target() {
        let response = http_redirect_response("https://evil.example/asset");
        let (url, server) = serve_http_once(response).await;

        let dir = test_scratch_dir("redirect-host");
        let dest = dir.join("archive.tar.gz");
        let client = updater_http_client(Duration::from_secs(5)).unwrap();

        let err = download_capped_raw(&client, &url, &dest, MAX_UPDATE_ARCHIVE_BYTES)
            .await
            .unwrap_err();
        server.await.unwrap();

        assert!(
            error_chain_contains(&err, "non-allowlisted host"),
            "the policy host rejection must be visible in the error chain: {err:?}"
        );
        assert!(!dest.exists(), "rejected redirect must not create dest");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_stream_download_aborts_over_cap_without_residue() {
        // Use a small cap so the test does not need to move 256 MiB.
        let cap = 64 * 1024;
        let payload = vec![0x5a_u8; cap as usize + 1];
        let split = payload.len() / 2;
        let response = http_chunked_response(&[&payload[..split], &payload[split..]]);
        let (url, server) = serve_http_once(response).await;

        let dir = test_scratch_dir("cap");
        let dest = dir.join("archive.tar.gz");
        let client = reqwest::Client::new();

        let err = download_capped_raw(&client, &url, &dest, cap)
            .await
            .unwrap_err();
        server.await.unwrap();

        assert!(matches!(err, UpdateError::Other(_)), "got {err:?}");
        assert!(!dest.exists(), "partial destination must be removed");
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            0,
            "no temp residue after an over-cap download"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_stream_download_content_length_over_cap_rejected_early() {
        let cap = 1024;
        // Declare more than the cap without sending a body: the reject must
        // happen from the Content-Length header alone.
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            cap + 1
        )
        .into_bytes();
        let (url, server) = serve_http_once(response).await;

        let dir = test_scratch_dir("content-length");
        let dest = dir.join("archive.tar.gz");
        let client = reqwest::Client::new();

        let err = download_capped_raw(&client, &url, &dest, cap)
            .await
            .unwrap_err();
        server.await.unwrap();

        assert!(matches!(err, UpdateError::Other(_)), "got {err:?}");
        assert!(!dest.exists(), "rejected download must not create dest");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_stream_download_then_checksum_and_extract() {
        let archive = build_tar_gz(&[("README.md", b"docs"), ("sito", b"streamed-binary-bytes")]);
        let response = http_response_with_content_length(&archive);
        let (url, server) = serve_http_once(response).await;

        let dir = test_scratch_dir("checksum-extract");
        let dest = dir.join("sito-v1.9.0-x86_64-unknown-linux-gnu.tar.gz");
        let client = reqwest::Client::new();

        download_capped_raw(&client, &url, &dest, MAX_UPDATE_ARCHIVE_BYTES)
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), archive);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "downloaded update assets must be 0600");
        }

        let archive_name = "sito-v1.9.0-x86_64-unknown-linux-gnu.tar.gz";
        let valid_hash =
            hex::encode(ring::digest::digest(&ring::digest::SHA256, &archive).as_ref());
        let sums_valid = format!("{valid_hash}  {archive_name}\n");
        verify_archive_checksum_file(&dest, archive_name, Some(&sums_valid))
            .await
            .unwrap();

        let sums_mismatch = format!("{}  {archive_name}\n", "0".repeat(64));
        let err = verify_archive_checksum_file(&dest, archive_name, Some(&sums_mismatch))
            .await
            .unwrap_err();
        assert!(matches!(err, UpdateError::ChecksumMismatch { .. }));

        let extracted = extract_binary_from_file(&dest).await.unwrap();
        assert_eq!(extracted, b"streamed-binary-bytes");
        assert_eq!(extract_binary_from_archive(&archive).unwrap(), extracted);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_private_signature_dir_is_0700() {
        let dir = test_scratch_dir("sig-dir");
        let path = dir.join("nested").join("signatures");
        create_private_dir(&path).await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "signature scratch dir must be 0700");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn no_leaked_files(dir: &Path, prefixes: &[&str]) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| prefixes.iter().any(|prefix| name.starts_with(prefix)))
            .collect()
    }

    #[tokio::test]
    async fn test_install_verifies_new_binary_and_keeps_backup_only_on_success() {
        let dir = test_scratch_dir("install-ok");
        let target = dir.join("sito");
        std::fs::write(&target, b"#!/bin/sh\nexit 1\n").unwrap();

        let new_binary = b"#!/bin/sh\necho 'sito 9.9.9'\n";
        install_binary_atomically(new_binary, &target)
            .await
            .unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), new_binary);
        let leaked = no_leaked_files(&dir, &[".sito_update_", ".sito_backup_"]);
        assert!(
            leaked.is_empty(),
            "temporary update files leaked: {leaked:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_install_rejects_unverified_binary_and_leaves_current_in_place() {
        let dir = test_scratch_dir("install-invalid");
        let target = dir.join("sito");
        let original = b"#!/bin/sh\necho old\n";
        std::fs::write(&target, original).unwrap();

        let err = install_binary_atomically(b"not an executable", &target)
            .await
            .unwrap_err();
        assert!(matches!(err, UpdateError::Other(_)), "got {err:?}");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            original,
            "a binary that fails --version must not replace the running executable"
        );
        let leaked = no_leaked_files(&dir, &[".sito_update_", ".sito_backup_"]);
        assert!(
            leaked.is_empty(),
            "temporary update files leaked: {leaked:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_replace_restores_backup_when_rename_fails() {
        let dir = test_scratch_dir("install-rollback");
        let target = dir.join("sito");
        let original = b"old-binary";
        std::fs::write(&target, original).unwrap();
        let missing_new = dir.join("missing-new-binary");

        let err = replace_with_backup(&missing_new, &target)
            .await
            .unwrap_err();
        assert!(matches!(err, UpdateError::Io(_)), "got {err:?}");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            original,
            "the backup must be restored when replacement fails"
        );
        let leaked = no_leaked_files(&dir, &[".sito_update_", ".sito_backup_"]);
        assert!(leaked.is_empty(), "backup/temp files leaked: {leaked:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_install_preserves_existing_mode_and_xattrs() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_scratch_dir("metadata");
        let target = dir.join("sito");
        std::fs::write(&target, b"#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o751)).unwrap();

        let attr_name = b"user.sito.test";
        let attr_value = b"preserve-me";
        let xattr_supported = set_test_xattr(&target, attr_name, attr_value);

        let new_binary = b"#!/bin/sh\necho 'sito 9.9.9'\n";
        install_binary_atomically(new_binary, &target)
            .await
            .unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), new_binary);
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o751,
            "the existing executable mode must be preserved"
        );
        if xattr_supported {
            assert_eq!(
                get_xattr(&target, attr_name).unwrap(),
                attr_value,
                "extended attributes must survive the rename"
            );
        } else {
            eprintln!("filesystem does not support user xattrs; skipped xattr assertion");
        }

        let leaked = no_leaked_files(&dir, &[".sito_update_", ".sito_backup_"]);
        assert!(
            leaked.is_empty(),
            "temporary update files leaked: {leaked:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_install_uses_0755_when_target_is_absent() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_scratch_dir("fresh-mode");
        let target = dir.join("sito");

        let new_binary = b"#!/bin/sh\necho 'sito 9.9.9'\n";
        install_binary_atomically(new_binary, &target)
            .await
            .unwrap();

        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o755,
            "a fresh install must be executable mode 0755"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_install_preserves_security_capability_when_root() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("not running as root; skipped security.capability preservation test");
            return;
        }

        let dir = test_scratch_dir("capability");
        let target = dir.join("sito");
        std::fs::write(&target, b"#!/bin/sh\nexit 1\n").unwrap();
        let status = std::process::Command::new("setcap")
            .args(["cap_net_bind_service=+ep"])
            .arg(&target)
            .status();
        if !status.is_ok_and(|status| status.success()) {
            eprintln!("setcap unavailable or failed; skipped capability test");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let before = get_xattr(&target, b"security.capability").unwrap();
        assert_ne!(before, Vec::<u8>::new());

        let new_binary = b"#!/bin/sh\necho 'sito 9.9.9'\n";
        install_binary_atomically(new_binary, &target)
            .await
            .unwrap();

        let after = get_xattr(&target, b"security.capability").unwrap();
        assert_eq!(
            before, after,
            "security.capability must survive the atomic replacement"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn set_test_xattr(path: &Path, name: &[u8], value: &[u8]) -> bool {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let c_name = CString::new(name).unwrap();
        // SAFETY: valid path/name/value pointers for the given lengths.
        let rc = unsafe {
            libc::setxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                value.as_ptr().cast::<libc::c_void>(),
                value.len(),
                0,
            )
        };
        if rc == 0 {
            return true;
        }
        let err = std::io::Error::last_os_error();
        matches!(err.raw_os_error(), Some(libc::ENOTSUP | libc::EPERM))
    }
}
