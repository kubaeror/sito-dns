//! ACME (RFC 8555) automatic TLS certificate management for sito.
//!
//! Provides automatic certificate issuance and renewal via Let's Encrypt
//! (or custom/staging ACME directories), supporting:
//! - TLS-ALPN-01 (RFC 8737) challenges directly via `DynamicCertResolver` on port 443
//! - HTTP-01 fallback challenges via `DohConfig::http01_challenges`
//! - Account and certificate persistence in `<data_dir>/acme/`
//! - Background renewal ticker (renewing 30 days before expiration)
//! - Zero-downtime certificate reloading via `TlsAcceptorManager`

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    RetryPolicy,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::{debug, info, warn};

use crate::tls::{TlsAcceptorManager, TlsManagerSet, create_certified_key};

/// Enforce owner-only permissions (0600) on an existing secret file.
///
/// `OpenOptions::mode` only applies when a file is created, so files that
/// already exist (e.g. account credentials written by an older version) need
/// this explicit fix-up.
fn enforce_secret_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        warn!(
            "Failed to restrict permissions on secret file {}: {e}",
            path.display()
        );
    }
}

/// Writes a file containing key material with owner-only permissions (0600).
///
/// `mode` only applies when the file is created; existing files are re-chmodded
/// and a failure to restrict permissions is returned as an error (fail closed).
pub fn write_secret_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    // `mode` only applies at creation; fail closed if existing perms cannot
    // be restricted. The crate is Unix-only (see lib.rs `compile_error!`).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Configuration for ACME certificate management.
#[derive(Clone, Debug)]
pub struct AcmeServiceConfig {
    pub enabled: bool,
    pub email: String,
    pub domains: Vec<String>,
    pub staging: bool,
    pub directory_url: Option<String>,
    pub renew_before_days: u32,
    pub storage_dir: PathBuf,
    /// Optional PEM root certificate used to trust a private/test ACME
    /// directory. Public Let's Encrypt directories leave this unset.
    root_certificate: Option<PathBuf>,
}

impl AcmeServiceConfig {
    pub fn new(email: String, domains: Vec<String>, storage_dir: PathBuf) -> Self {
        Self {
            enabled: true,
            email,
            domains,
            staging: false,
            directory_url: None,
            renew_before_days: 30,
            storage_dir,
            root_certificate: None,
        }
    }

    #[must_use]
    pub fn with_staging(mut self, staging: bool) -> Self {
        self.staging = staging;
        self
    }

    #[must_use]
    pub fn with_directory_url(mut self, url: impl Into<String>) -> Self {
        self.directory_url = Some(url.into());
        self
    }

    #[must_use]
    pub fn with_renew_before_days(mut self, days: u32) -> Self {
        self.renew_before_days = days;
        self
    }

    /// Trust a private ACME directory whose TLS certificate chains to the
    /// given root PEM file (for private CAs and integration tests).
    #[must_use]
    pub fn with_root_certificate(mut self, root: impl Into<PathBuf>) -> Self {
        self.root_certificate = Some(root.into());
        self
    }

    /// Whether the certificate currently stored for ACME is a bootstrap
    /// placeholder rather than a CA-issued certificate.
    ///
    /// Bootstrap certificates are detected by an explicit marker or by being
    /// self-signed. The self-signed check also recovers installations upgraded
    /// from versions that wrote a year-4096 bootstrap certificate without a
    /// marker.
    ///
    /// Total lifetime is deliberately not used: short-lived CA-issued
    /// certificates exist, and a CA-issued certificate must never be replaced
    /// by a self-signed placeholder.
    ///
    /// Missing, unreadable or unparseable material is treated as a bootstrap
    /// placeholder. Such material cannot be a usable CA-issued certificate,
    /// and reporting it as "not bootstrap" would let startup select it and
    /// abort in the TLS builder even when a valid static pair exists.
    pub fn is_bootstrap_cert(&self) -> bool {
        if bootstrap_marker_path(&self.storage_dir).exists() {
            return true;
        }
        let Ok(cert_bytes) = std::fs::read(self.storage_dir.join("cert.pem")) else {
            return true;
        };
        // `is_self_signed` returns `None` for unparseable PEM/X.509 input;
        // treat that as unusable rather than as a CA-issued certificate.
        is_self_signed(&cert_bytes).unwrap_or(true)
    }

    /// Whether the certificate currently stored for ACME is already expired
    /// or otherwise cannot be proven valid.
    ///
    /// An expired CA certificate must not be served, but it also must not be
    /// silently overwritten by a bootstrap certificate unless the operator
    /// explicitly opted in. Missing, unreadable or unparseable material is
    /// reported as expired for the same reason: it must never be served.
    pub fn stored_cert_is_expired(&self) -> bool {
        let Ok(cert_bytes) = std::fs::read(self.storage_dir.join("cert.pem")) else {
            return true;
        };
        // Compare seconds, not whole days: `days_until_expiration` truncates
        // toward zero, so a certificate that expired one hour ago still has a
        // day count of 0.
        match seconds_until_expiration(&cert_bytes) {
            Ok(seconds) => seconds <= 0,
            Err(_) => true,
        }
    }

    /// Whether the stored ACME certificate/key pair can actually be served.
    ///
    /// Startup must never hand an unusable pair to the TLS builder: a single
    /// truncated `cert.pem` or a malformed `key.pem` would otherwise abort the
    /// whole process even when valid static `[tls]` material exists. This is
    /// stricter than [`Self::is_bootstrap_cert`]/[`Self::stored_cert_is_expired`]
    /// because it also parses the private key and verifies that the key belongs
    /// to the certificate.
    #[must_use]
    pub fn stored_pair_is_usable(&self) -> bool {
        let cert_path = self.storage_dir.join("cert.pem");
        let key_path = self.storage_dir.join("key.pem");
        if self.is_bootstrap_cert() || self.stored_cert_is_expired() {
            return false;
        }
        let Ok(certs) = crate::tls::load_certificates(&cert_path) else {
            warn!(
                path = %cert_path.display(),
                "Stored ACME certificate is unreadable or invalid; falling back to other TLS material"
            );
            return false;
        };
        let Ok(key) = crate::tls::load_private_key(&key_path) else {
            warn!(
                path = %key_path.display(),
                "Stored ACME private key is unreadable or invalid; falling back to other TLS material"
            );
            return false;
        };
        match crate::tls::create_certified_key(certs, &key) {
            Ok(_) => true,
            Err(e) => {
                warn!(
                    cert = %cert_path.display(),
                    key = %key_path.display(),
                    error = %e,
                    "Stored ACME certificate/key pair is unusable; falling back to other TLS material"
                );
                false
            }
        }
    }

    /// Determine the directory URL to use.
    pub fn get_directory_url(&self) -> String {
        if let Some(ref url) = self.directory_url {
            url.clone()
        } else if self.staging {
            LetsEncrypt::Staging.url().to_string()
        } else {
            LetsEncrypt::Production.url().to_string()
        }
    }
}

/// Warning window for an expiring certificate (D12).
pub const CERTIFICATE_EXPIRY_WARNING_DAYS: i64 = 30;

/// Validity of a certificate file for readiness decisions (D12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateValidity {
    /// No certificate file exists (first boot or ACME issuance pending).
    Missing,
    /// The self-signed bootstrap placeholder is the only material available.
    Bootstrap,
    /// The certificate is expired or cannot be parsed.
    Expired,
    /// The certificate is valid but expires within the warning window.
    Expiring { days_remaining: i64 },
    /// The certificate is valid beyond the warning window.
    Valid { days_remaining: i64 },
}

/// Classifies a certificate file for readiness.
///
/// Missing and unparseable material is not silently treated as valid. A
/// certificate that cannot be parsed is reported as expired because it cannot
/// be served.
#[must_use]
pub fn certificate_validity(cert_path: &std::path::Path) -> CertificateValidity {
    let Ok(bytes) = std::fs::read(cert_path) else {
        return CertificateValidity::Missing;
    };
    match days_until_expiration(&bytes) {
        Ok(days) if days <= 0 => CertificateValidity::Expired,
        Ok(days) if days <= CERTIFICATE_EXPIRY_WARNING_DAYS => CertificateValidity::Expiring {
            days_remaining: days,
        },
        Ok(days) => CertificateValidity::Valid {
            days_remaining: days,
        },
        Err(_) => CertificateValidity::Expired,
    }
}

impl AcmeServiceConfig {
    /// Classifies the stored ACME certificate for readiness.
    #[must_use]
    pub fn certificate_validity(&self) -> CertificateValidity {
        let cert_path = self.storage_dir.join("cert.pem");
        if !cert_path.exists() {
            return CertificateValidity::Missing;
        }
        if self.is_bootstrap_cert() {
            return CertificateValidity::Bootstrap;
        }
        certificate_validity(&cert_path)
    }
}

/// Seconds remaining until the first certificate in `cert_pem` expires.
///
/// Negative values mean the certificate is already expired. This is the
/// precise form used for expiry decisions; [`days_until_expiration`] truncates
/// the remainder into whole days for display/threshold comparisons.
pub fn seconds_until_expiration(cert_pem: &[u8]) -> Result<i64, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse PEM certificate: {e}"))?;

    let first = certs
        .first()
        .ok_or_else(|| "Certificate chain is empty".to_string())?;

    let (_, x509) = x509_parser::parse_x509_certificate(first.as_ref())
        .map_err(|e| format!("Failed to parse X.509 DER certificate: {e}"))?;

    let not_after = x509.validity().not_after.timestamp();
    #[allow(clippy::cast_possible_wrap)]
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    Ok(not_after - now)
}

/// Calculate the number of days remaining until an X.509 certificate expires.
pub fn days_until_expiration(cert_pem: &[u8]) -> Result<i64, String> {
    Ok(seconds_until_expiration(cert_pem)? / 86400)
}

/// Total lifetime of the first certificate in `cert_pem`, in whole days
/// (`not_after - not_before`).
///
/// Unlike [`days_until_expiration`], this is stable for the lifetime of the
/// certificate. It is diagnostics/test signal only: bootstrap classification
/// uses the explicit marker or a self-signed issuer so short-lived CA-issued
/// certificates are never misclassified.
pub fn certificate_lifetime_days(cert_pem: &[u8]) -> Result<i64, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse PEM certificate: {e}"))?;
    let first = certs
        .first()
        .ok_or_else(|| "Certificate chain is empty".to_string())?;
    let (_, x509) = x509_parser::parse_x509_certificate(first.as_ref())
        .map_err(|e| format!("Failed to parse X.509 DER certificate: {e}"))?;
    let not_before = x509.validity().not_before.timestamp();
    let not_after = x509.validity().not_after.timestamp();
    Ok((not_after - not_before) / 86400)
}

/// Generate a TLS-ALPN-01 (RFC 8737) challenge certificate.
pub fn generate_tls_alpn_01_cert(
    domain: &str,
    key_authorization: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), String> {
    let digest = ring::digest::digest(&ring::digest::SHA256, key_authorization.as_bytes());

    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| format!("Failed to initialize CertificateParams: {e}"))?;

    let acme_ext = rcgen::CustomExtension::new_acme_identifier(digest.as_ref());
    params.custom_extensions.push(acme_ext);

    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| format!("Failed to generate challenge key pair: {e}"))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("Failed to self-sign challenge certificate: {e}"))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let priv_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok((cert_der, priv_der))
}

/// Build an ACME account client, optionally trusting a private root.
fn account_builder(config: &AcmeServiceConfig) -> Result<instant_acme::AccountBuilder, String> {
    match config.root_certificate.as_ref() {
        Some(root) => Account::builder_with_root(root).map_err(|e| {
            format!(
                "Failed to build account client with root {}: {e}",
                root.display()
            )
        }),
        None => Account::builder().map_err(|e| format!("Failed to build account client: {e}")),
    }
}

/// Move unusable account credentials aside so a failed parse or a directory
/// change cannot block all future renewals.
fn set_account_credentials_aside(creds_file: &Path, suffix: &str) -> Result<PathBuf, String> {
    let backup = creds_file.with_extension(format!("json.{suffix}"));
    let _ = std::fs::remove_file(&backup);
    std::fs::rename(creds_file, &backup).map_err(|e| {
        format!(
            "Failed to move unusable account credentials {} to {}: {e}",
            creds_file.display(),
            backup.display()
        )
    })?;
    warn!(
        "Moved ACME account credentials from {} to {}",
        creds_file.display(),
        backup.display()
    );
    Ok(backup)
}

/// Directory URL recorded inside serialized account credentials.
fn account_credentials_directory(data: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(data)
        .ok()?
        .get("directory")?
        .as_str()
        .map(str::to_owned)
}

/// Register a new ACME account and persist its credentials atomically.
async fn register_account(
    config: &AcmeServiceConfig,
    directory_url: &str,
    creds_file: &Path,
) -> Result<Account, String> {
    info!(
        "Registering new ACME account for {} at {}",
        config.email, directory_url
    );
    let new_account = NewAccount {
        contact: &[&format!("mailto:{}", config.email)],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    let (account, creds) = account_builder(config)?
        .create(&new_account, directory_url.to_string(), None)
        .await
        .map_err(|e| format!("Failed to create ACME account: {e}"))?;

    let serialized = serde_json::to_vec_pretty(&creds)
        .map_err(|e| format!("Failed to serialize account credentials: {e}"))?;

    std::fs::create_dir_all(&config.storage_dir).map_err(|e| {
        format!(
            "Failed to create ACME storage directory {}: {e}",
            config.storage_dir.display()
        )
    })?;
    // Atomic replace: a crash can never leave a half-written account.json that
    // blocks the next renewal.
    write_atomic(creds_file, &serialized, 0o600).map_err(|e| {
        format!(
            "Failed to persist account credentials to {}: {e}",
            creds_file.display()
        )
    })?;

    info!(
        "ACME account successfully created and saved to {:?}",
        creds_file
    );
    Ok(account)
}

/// Load or create an ACME account from the storage directory.
async fn load_or_create_account(
    config: &AcmeServiceConfig,
    directory_url: &str,
) -> Result<Account, String> {
    let creds_file = config.storage_dir.join("account.json");

    if creds_file.exists() {
        debug!(
            "Loading existing ACME account credentials from {:?}",
            creds_file
        );
        // Existing credentials may predate the 0600 creation mode; fix in place.
        enforce_secret_file_permissions(&creds_file);
        let creds_data = std::fs::read_to_string(&creds_file)
            .map_err(|e| format!("Failed to read account credentials file: {e}"))?;

        let creds: AccountCredentials = match serde_json::from_str(&creds_data) {
            Ok(creds) => creds,
            Err(e) => {
                warn!(
                    "ACME account credentials at {} are corrupt ({e}); \
                     backing them up and registering again",
                    creds_file.display()
                );
                set_account_credentials_aside(&creds_file, "corrupt")?;
                return register_account(config, directory_url, &creds_file).await;
            }
        };

        // `from_credentials` would use the directory stored in the file and
        // silently ignore a staging/production switch (or a custom directory).
        // Credentials without a directory URL (pre-0.4 format) cannot be
        // verified against the configured directory either.
        match account_credentials_directory(&creds_data) {
            Some(stored_directory) if stored_directory == directory_url => {}
            Some(stored_directory) => {
                warn!(
                    "ACME account credentials were registered with directory {stored_directory} \
                     but {directory_url} is configured; backing them up and registering again"
                );
                set_account_credentials_aside(&creds_file, "bak")?;
                return register_account(config, directory_url, &creds_file).await;
            }
            None => {
                warn!(
                    "ACME account credentials do not record a directory URL; \
                     registering again for {directory_url}"
                );
                set_account_credentials_aside(&creds_file, "bak")?;
                return register_account(config, directory_url, &creds_file).await;
            }
        }

        let account = account_builder(config)?
            .from_credentials(creds)
            .await
            .map_err(|e| format!("Failed to restore account from credentials: {e}"))?;
        return Ok(account);
    }

    register_account(config, directory_url, &creds_file).await
}

/// Writes `contents` to `path` atomically: a temp file in the same directory
/// is written, fsynced and renamed over the target, then the directory is
/// fsynced. A crash can therefore never leave a half-written certificate or
/// key file behind.
fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = path.with_extension("tmp");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, path)?;
    if let Ok(dir_file) = std::fs::File::open(dir) {
        let _ = dir_file.sync_all();
    }
    Ok(())
}

/// SHA-256 of a file's contents, hex encoded.
fn file_sha256(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
    Some(
        digest
            .as_ref()
            .iter()
            .fold(String::with_capacity(64), |mut acc, byte| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{byte:02x}");
                acc
            }),
    )
}

/// Path of the cert/key pair fingerprint marker written after every rotation.
fn pair_metadata_path(storage_dir: &Path) -> std::path::PathBuf {
    storage_dir.join("pair.sha256")
}

/// Path of the marker identifying a self-signed bootstrap placeholder pair.
fn bootstrap_marker_path(storage_dir: &Path) -> std::path::PathBuf {
    storage_dir.join("bootstrap")
}

/// Record that the pair currently in `storage_dir` is the bootstrap
/// placeholder. Also writes the normal pair fingerprint so a later rotation is
/// detectable, and so an interrupted bootstrap write is not mistaken for a
/// complete pair.
pub fn record_bootstrap_cert(storage_dir: &Path) -> std::io::Result<()> {
    write_pair_metadata(storage_dir)?;
    write_atomic(&bootstrap_marker_path(storage_dir), b"1\n", 0o644)
}

/// Write the certificate/key pair fingerprint marker for `storage_dir`.
fn write_pair_metadata(storage_dir: &Path) -> std::io::Result<()> {
    let cert_path = storage_dir.join("cert.pem");
    let key_path = storage_dir.join("key.pem");
    let (Some(cert_hash), Some(key_hash)) = (file_sha256(&cert_path), file_sha256(&key_path))
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "certificate or key is missing",
        ));
    };
    write_atomic(
        &pair_metadata_path(storage_dir),
        format!("{cert_hash} {key_hash}\n").as_bytes(),
        0o644,
    )
}

/// Remove the bootstrap marker after a CA-issued certificate is installed.
fn clear_bootstrap_marker(storage_dir: &Path) {
    match std::fs::remove_file(bootstrap_marker_path(storage_dir)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            "Failed to remove bootstrap certificate marker in {:?}: {e}",
            storage_dir.display()
        ),
    }
}

/// Whether the first certificate in `cert_pem` is self-signed.
///
/// Returns `None` when the PEM or X.509 material cannot be parsed: callers
/// must treat unparseable material as unusable, never as a trusted
/// certificate.
fn is_self_signed(cert_pem: &[u8]) -> Option<bool> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let first = certs.first()?;
    let (_, x509) = x509_parser::parse_x509_certificate(first.as_ref()).ok()?;
    Some(x509.tbs_certificate.subject == x509.tbs_certificate.issuer)
}

/// Whether the stored pair fingerprint matches the certificate and key files.
///
/// A missing marker is treated as unknown (older installs, manual certs) so
/// existing deployments are not thrown into a renewal loop; a marker that does
/// not match means a rotation only completed partially and the material must
/// be re-obtained before the next handshake.
fn pair_metadata_matches(cert_path: &Path, key_path: &Path, metadata_path: &Path) -> bool {
    let Ok(stored) = std::fs::read_to_string(metadata_path) else {
        return true;
    };
    let (Some(cert_hash), Some(key_hash)) = (file_sha256(cert_path), file_sha256(key_path)) else {
        return false;
    };
    let mut parts = stored.split_whitespace();
    parts.next() == Some(cert_hash.as_str()) && parts.next() == Some(key_hash.as_str())
}

/// Names covered by the first certificate in `cert_pem`.
///
/// Only DNS SANs are returned; a certificate without a SAN extension covers
/// nothing here (ACME always issues SAN certificates, so this is a safe
/// renewal trigger rather than a compatibility fallback).
fn certificate_dns_names(cert_pem: &[u8]) -> Result<Vec<String>, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse PEM certificate: {e}"))?;
    let first = certs
        .first()
        .ok_or_else(|| "Certificate chain is empty".to_string())?;
    let (_, x509) = x509_parser::parse_x509_certificate(first.as_ref())
        .map_err(|e| format!("Failed to parse X.509 DER certificate: {e}"))?;
    let san = x509
        .subject_alternative_name()
        .map_err(|e| format!("Failed to parse certificate SAN extension: {e}"))?
        .ok_or_else(|| "Certificate has no Subject Alternative Name extension".to_string())?;
    Ok(san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::DNSName(name) => {
                Some(name.trim_end_matches('.').to_ascii_lowercase())
            }
            _ => None,
        })
        .collect())
}

/// Whether the stored certificate's SAN set matches the configured domains.
///
/// Any added or removed domain requires a new order. Comparison is
/// order-insensitive and normalizes case/trailing dots.
fn certificate_covers_domains(cert_pem: &[u8], domains: &[String]) -> Result<bool, String> {
    if domains.is_empty() {
        return Ok(true);
    }
    let mut expected: Vec<String> = domains
        .iter()
        .map(|domain| domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .collect();
    expected.sort_unstable();
    expected.dedup();

    let mut actual = certificate_dns_names(cert_pem)?;
    actual.sort_unstable();
    actual.dedup();
    Ok(actual == expected)
}

/// Check whether the current certificate on disk needs to be acquired or renewed.
pub fn certificate_needs_renewal(config: &AcmeServiceConfig) -> bool {
    let cert_path = config.storage_dir.join("cert.pem");
    let key_path = config.storage_dir.join("key.pem");

    if !cert_path.exists() || !key_path.exists() {
        return true;
    }

    if config.is_bootstrap_cert() {
        info!("ACME storage contains a bootstrap certificate; issuance needed");
        return true;
    }

    if !pair_metadata_matches(
        &cert_path,
        &key_path,
        &pair_metadata_path(&config.storage_dir),
    ) {
        warn!(
            "ACME certificate and key do not match the last completed rotation \
             (partial write); renewal needed"
        );
        return true;
    }

    let Ok(cert_bytes) = std::fs::read(&cert_path) else {
        return true;
    };

    match certificate_covers_domains(&cert_bytes, &config.domains) {
        Ok(true) => {}
        Ok(false) => {
            info!(
                "Stored ACME certificate SANs do not match acme.domains {:?}; renewal needed",
                config.domains
            );
            return true;
        }
        Err(e) => {
            warn!("Failed to compare ACME certificate SANs with acme.domains (will renew): {e}");
            return true;
        }
    }

    match days_until_expiration(&cert_bytes) {
        Ok(days) => {
            if days <= i64::from(config.renew_before_days) {
                info!(
                    "Certificate expires in {} days (threshold: {} days); renewal needed",
                    days, config.renew_before_days
                );
                true
            } else {
                debug!(
                    "Certificate valid for {} more days (threshold: {} days); no renewal needed",
                    days, config.renew_before_days
                );
                false
            }
        }
        Err(e) => {
            warn!("Failed to check certificate expiration (will renew): {e}");
            true
        }
    }
}

/// Which challenge types the running server can actually answer.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcmeChallengeOptions {
    /// A TCP listener serving port 443 with the `acme-tls/1` ALPN is bound.
    pub tls_alpn_available: bool,
    /// The dedicated HTTP-01 listener is bound and reachable.
    pub http01_available: bool,
}

/// Live challenge-listener state shared by the DNS listener manager and the
/// ACME background manager.
///
/// Listener bindings start before ACME attempts and can change on a hot
/// rebind, so the ACME manager reads this at every attempt instead of capturing
/// a configuration-derived snapshot. The default (nothing bound) is fail-safe:
/// only HTTP-01 can be selected.
#[derive(Clone, Debug, Default)]
pub struct AcmeChallengeAvailability {
    tls_alpn_available: Arc<AtomicBool>,
    http01_available: Arc<AtomicBool>,
    /// Whether ACME is enabled for this process (false makes readiness moot).
    enabled: Arc<AtomicBool>,
    /// Most recent issuance/renewal error, cleared on a successful check.
    last_error: Arc<std::sync::Mutex<Option<String>>>,
}

impl AcmeChallengeAvailability {
    pub fn new(tls_alpn_available: bool, http01_available: bool) -> Self {
        Self {
            tls_alpn_available: Arc::new(AtomicBool::new(tls_alpn_available)),
            http01_available: Arc::new(AtomicBool::new(http01_available)),
            enabled: Arc::new(AtomicBool::new(false)),
            last_error: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_tls_alpn_available(&self, available: bool) {
        self.tls_alpn_available.store(available, Ordering::Relaxed);
    }

    pub fn set_http01_available(&self, available: bool) {
        self.http01_available.store(available, Ordering::Relaxed);
    }

    pub fn options(&self) -> AcmeChallengeOptions {
        AcmeChallengeOptions {
            tls_alpn_available: self.tls_alpn_available.load(Ordering::Relaxed),
            http01_available: self.http01_available.load(Ordering::Relaxed),
        }
    }

    /// No configured challenge listener can answer either ACME challenge.
    pub fn challenge_unavailable(&self) -> bool {
        let options = self.options();
        !options.tls_alpn_available && !options.http01_available
    }

    /// Record a failed issuance/renewal attempt for readiness reporting.
    pub fn record_error(&self, error: impl Into<String>) {
        *sito_core::sync::lock_or_recover(&self.last_error) = Some(error.into());
    }

    /// Clear the last error after a successful issuance check.
    pub fn record_success(&self) {
        *sito_core::sync::lock_or_recover(&self.last_error) = None;
    }

    pub fn last_error(&self) -> Option<String> {
        sito_core::sync::lock_or_recover(&self.last_error).clone()
    }
}

/// Select a challenge type the CA offers and this deployment can answer.
///
/// TLS-ALPN-01 is only usable when a TCP listener on port 443 answers the
/// `acme-tls/1` ALPN; a DoT-only or custom-DoH-port deployment must fall back
/// to HTTP-01 instead of retrying an impossible challenge forever.
fn select_challenge_type(
    offers_tls_alpn: bool,
    offers_http01: bool,
    options: AcmeChallengeOptions,
) -> Option<ChallengeType> {
    if options.tls_alpn_available && offers_tls_alpn {
        Some(ChallengeType::TlsAlpn01)
    } else if options.http01_available && offers_http01 {
        Some(ChallengeType::Http01)
    } else {
        None
    }
}

/// RAII cleanup for challenge state registered during an ACME order.
///
/// Ensures TLS-ALPN-01 and HTTP-01 challenge material is removed even when
/// order processing fails early (previously challenges remained registered
/// until the next successful renewal).
struct ChallengeCleanup<'a> {
    mgr: Option<&'a TlsAcceptorManager>,
    alpn_domains: Vec<String>,
    http01: Option<&'a Arc<dashmap::DashMap<String, String>>>,
    http_tokens: Vec<String>,
}

impl ChallengeCleanup<'_> {
    fn register_alpn(&mut self, domain: &str) {
        self.alpn_domains.push(domain.to_string());
    }

    fn register_http(&mut self, token: &str) {
        self.http_tokens.push(token.to_string());
    }
}

impl Drop for ChallengeCleanup<'_> {
    fn drop(&mut self) {
        if let Some(mgr) = self.mgr {
            for domain in &self.alpn_domains {
                mgr.unregister_challenge(domain);
            }
        }
        if let Some(challenges_map) = self.http01 {
            for token in &self.http_tokens {
                challenges_map.remove(token);
            }
        }
    }
}

/// Obtain a new certificate or renew an existing certificate via ACME protocol.
///
/// Returns `Ok(true)` if a certificate was issued/renewed and reloaded,
/// or `Ok(false)` if the current certificate is already valid and not expiring soon.
pub async fn obtain_or_renew_certificate(
    config: &AcmeServiceConfig,
    acceptor_mgr: Option<&TlsAcceptorManager>,
    http01_challenges: Option<&Arc<dashmap::DashMap<String, String>>>,
    _alpn_protocols: &[Vec<u8>],
) -> Result<bool, String> {
    let managers = TlsManagerSet::from_doh(acceptor_mgr.cloned());
    let challenge_options = AcmeChallengeOptions {
        // Preserve the historical API contract for direct callers: an
        // acceptor is assumed to answer TLS-ALPN-01. Server startup uses the
        // explicit port-aware entry point below.
        tls_alpn_available: acceptor_mgr.is_some(),
        http01_available: http01_challenges.is_some(),
    };
    obtain_or_renew_certificate_for_transports(
        config,
        &managers,
        http01_challenges,
        challenge_options,
    )
    .await
}

/// Obtain or renew a certificate and reload every encrypted transport.
///
/// `challenge_options` describes the listeners that are actually bound; the
/// server passes the port-aware result so an unusable TLS-ALPN-01 challenge is
/// never selected.
pub async fn obtain_or_renew_certificate_for_transports(
    config: &AcmeServiceConfig,
    managers: &TlsManagerSet,
    http01_challenges: Option<&Arc<dashmap::DashMap<String, String>>>,
    challenge_options: AcmeChallengeOptions,
) -> Result<bool, String> {
    let cert_path = config.storage_dir.join("cert.pem");
    let key_path = config.storage_dir.join("key.pem");

    if !certificate_needs_renewal(config) {
        // Best effort: make sure every transport serves the persisted pair.
        // This heals a restart that selected static material and a previous
        // reload that failed after issuance.
        if cert_path.exists() && key_path.exists() {
            managers.reload_all(&cert_path, &key_path).map_err(|e| {
                format!("Failed to reload transports from persisted ACME certificate: {e}")
            })?;
        }
        return Ok(false);
    }

    info!(
        "Beginning ACME certificate acquisition/renewal for domains: {:?}",
        config.domains
    );

    let directory_url = config.get_directory_url();
    let account = load_or_create_account(config, &directory_url).await?;

    let identifiers: Vec<Identifier> = config
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();

    let new_order = NewOrder::new(&identifiers);
    let mut order = account
        .new_order(&new_order)
        .await
        .map_err(|e| format!("Failed to create ACME order: {e}"))?;

    // Challenge registrations are cleaned up on every exit path (including
    // early errors) by this RAII guard.
    let mut challenges = ChallengeCleanup {
        mgr: managers.doh.as_ref(),
        alpn_domains: Vec::new(),
        http01: http01_challenges,
        http_tokens: Vec::new(),
    };

    // Process authorizations and set up challenge responses
    {
        let mut authorizations = order.authorizations();
        while let Some(auth_res) = authorizations.next().await {
            let mut auth = auth_res.map_err(|e| format!("Failed to fetch authorization: {e}"))?;
            let domain = match auth.identifier().identifier {
                Identifier::Dns(d) => d.clone(),
                _ => auth.identifier().to_string(),
            };

            // Prefer TLS-ALPN-01 only when the running server actually has a
            // TCP 443 listener; otherwise fall back to HTTP-01.
            let offers_tls_alpn = auth
                .challenges
                .iter()
                .any(|c| c.r#type == ChallengeType::TlsAlpn01);
            let offers_http01 = auth
                .challenges
                .iter()
                .any(|c| c.r#type == ChallengeType::Http01);
            let selected_challenge =
                select_challenge_type(offers_tls_alpn, offers_http01, challenge_options)
                    .ok_or_else(|| {
                        format!("No supported challenge type available for domain '{domain}'")
                    })?;

            match selected_challenge {
                ChallengeType::TlsAlpn01 => {
                    let mgr = managers.doh.as_ref().ok_or_else(|| {
                        "TLS-ALPN-01 selected but no DoH TLS manager is available".to_string()
                    })?;
                    let mut challenge = auth
                        .challenge(ChallengeType::TlsAlpn01)
                        .ok_or_else(|| format!("TLS-ALPN-01 challenge missing for {domain}"))?;

                    let key_auth = challenge.key_authorization();
                    let (cert_der, priv_der) =
                        generate_tls_alpn_01_cert(&domain, key_auth.as_str())?;

                    let certified_key = create_certified_key(vec![cert_der], &priv_der)
                        .map_err(|e| format!("Failed to create challenge CertifiedKey: {e}"))?;

                    mgr.register_challenge(&domain, certified_key);
                    challenges.register_alpn(&domain);

                    challenge
                        .set_ready()
                        .await
                        .map_err(|e| format!("Failed to set TLS-ALPN-01 challenge ready: {e}"))?;
                    debug!("Registered TLS-ALPN-01 challenge for {}", domain);
                }
                ChallengeType::Http01 => {
                    let challenges_map = http01_challenges.ok_or_else(|| {
                        "HTTP-01 selected but no challenge store is available".to_string()
                    })?;
                    let mut challenge = auth
                        .challenge(ChallengeType::Http01)
                        .ok_or_else(|| format!("HTTP-01 challenge missing for {domain}"))?;

                    let key_auth = challenge.key_authorization();
                    let token = challenge.token.clone();

                    challenges_map.insert(token.clone(), key_auth.as_str().to_string());
                    challenges.register_http(&token);

                    challenge
                        .set_ready()
                        .await
                        .map_err(|e| format!("Failed to set HTTP-01 challenge ready: {e}"))?;
                    debug!("Registered HTTP-01 challenge for {}", domain);
                }
                _ => unreachable!(),
            }
        }
    }

    // Wait for the order to transition to Ready. `poll_ready` drives the CA
    // validations, so challenge state must stay registered until it returns;
    // dropping the guard releases it on success and on error alike.
    let retry_policy = RetryPolicy::default().timeout(Duration::from_secs(90));
    let order_status = order
        .poll_ready(&retry_policy)
        .await
        .map_err(|e| format!("Error waiting for ACME order to become ready: {e}"))?;
    drop(challenges);

    if order_status != instant_acme::OrderStatus::Ready {
        return Err(format!(
            "ACME order did not become ready, status: {order_status:?}"
        ));
    }

    info!("ACME challenges validated, finalizing order...");

    // Finalize order (generates CSR and returns PEM private key)
    let private_key_pem = order
        .finalize()
        .await
        .map_err(|e| format!("Failed to finalize ACME order: {e}"))?;

    // Poll for the issued certificate chain
    let cert_chain_pem = order
        .poll_certificate(&retry_policy)
        .await
        .map_err(|e| format!("Failed to retrieve issued certificate: {e}"))?;

    // Persist certificates to disk
    std::fs::create_dir_all(&config.storage_dir).map_err(|e| {
        format!(
            "Failed to create ACME storage directory {}: {e}",
            config.storage_dir.display()
        )
    })?;

    // Write the key first, then the certificate, each atomically. On any
    // failure remove the certificate so `certificate_needs_renewal` retries
    // instead of serving a mismatched pair.
    if let Err(e) = write_atomic(&key_path, private_key_pem.as_bytes(), 0o600) {
        let _ = std::fs::remove_file(&cert_path);
        return Err(format!(
            "Failed to write key.pem to {}: {e}",
            key_path.display()
        ));
    }
    if let Err(e) = write_atomic(&cert_path, cert_chain_pem.as_bytes(), 0o644) {
        let _ = std::fs::remove_file(&cert_path);
        return Err(format!(
            "Failed to write cert.pem to {}: {e}",
            cert_path.display()
        ));
    }
    // Record the completed pair so a partially finished rotation is detected
    // even after a crash (rustls does not verify that cert and key match).
    if let Err(e) = write_pair_metadata(&config.storage_dir) {
        let _ = std::fs::remove_file(&cert_path);
        return Err(format!("Failed to record the certificate/key pair: {e}"));
    }

    // The real certificate is installed: the placeholder must no longer force
    // a fresh order on every renewal check.
    clear_bootstrap_marker(&config.storage_dir);

    info!(
        "ACME certificate and private key saved to {:?}",
        config.storage_dir
    );

    // Reload every encrypted transport from the issued pair. Each manager
    // reloads with its own ALPN list and keeps its shared challenge keys and
    // SNI virtual-host certificates.
    //
    // A failure must surface to the caller: reporting success would make the
    // manager wait the full steady-state interval while transports keep
    // serving the bootstrap certificate. The retry path calls `reload_all`
    // again even when the persisted certificate no longer needs renewal.
    managers
        .reload_all(&cert_path, &key_path)
        .map_err(|e| format!("Certificate issued but failed to reload TLS transports: {e}"))?;
    info!("All TLS transports reloaded with the ACME certificate");

    Ok(true)
}

/// Spawns the ACME manager background task for initial acquisition and periodic renewal.
///
/// Kept as a compatibility wrapper around
/// [`start_acme_manager_for_transports`] for callers that only have a DoH
/// manager.
pub fn start_acme_manager(
    config: AcmeServiceConfig,
    acceptor_mgr: Option<TlsAcceptorManager>,
    http01_challenges: Option<Arc<dashmap::DashMap<String, String>>>,
    _alpn_protocols: Vec<Vec<u8>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let managers = TlsManagerSet::from_doh(acceptor_mgr);
    let challenge_availability =
        AcmeChallengeAvailability::new(!managers.is_empty(), http01_challenges.is_some());
    challenge_availability.set_enabled(true);
    start_acme_manager_for_transports(
        config,
        managers,
        http01_challenges,
        challenge_availability,
        shutdown_rx,
    )
}

/// Spawns the ACME manager with an explicit set of transport managers and a
/// live view of which challenge listeners are actually bound.
pub fn start_acme_manager_for_transports(
    config: AcmeServiceConfig,
    managers: TlsManagerSet,
    http01_challenges: Option<Arc<dashmap::DashMap<String, String>>>,
    challenge_availability: AcmeChallengeAvailability,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    /// Steady-state check cadence once renewal is not immediately required.
    const ACME_CHECK_INTERVAL: Duration = Duration::from_hours(12);
    /// First retry delay after a failed attempt.
    const ACME_RETRY_INITIAL: Duration = Duration::from_secs(300);
    /// Upper bound for the failure backoff.
    const ACME_RETRY_MAX: Duration = Duration::from_hours(6);

    tokio::spawn(async move {
        info!(
            "ACME background manager started for domains: {:?}",
            config.domains
        );

        // Initial acquisition/renewal check on startup. Failures retry with a
        // bounded backoff instead of waiting the full steady-state interval.
        let initial_ok = match obtain_or_renew_certificate_for_transports(
            &config,
            &managers,
            http01_challenges.as_ref(),
            challenge_availability.options(),
        )
        .await
        {
            Ok(_) => {
                challenge_availability.record_success();
                true
            }
            Err(e) => {
                warn!("Initial ACME certificate check failed: {e}");
                challenge_availability.record_error(e.clone());
                false
            }
        };
        let mut next_delay = if initial_ok {
            ACME_CHECK_INTERVAL
        } else {
            ACME_RETRY_INITIAL
        };
        let mut retry_delay = if initial_ok {
            ACME_RETRY_INITIAL
        } else {
            ACME_RETRY_INITIAL * 2
        };

        loop {
            tokio::select! {
                res = shutdown_rx.changed() => {
                    if res.is_err() || *shutdown_rx.borrow() {
                        debug!("ACME manager shutting down");
                        break;
                    }
                }
                () = tokio::time::sleep(next_delay) => {
                    debug!("Running periodic ACME renewal check...");
                    match obtain_or_renew_certificate_for_transports(
                        &config,
                        &managers,
                        http01_challenges.as_ref(),
                        challenge_availability.options(),
                    ).await {
                        Ok(_) => {
                            challenge_availability.record_success();
                            next_delay = ACME_CHECK_INTERVAL;
                            retry_delay = ACME_RETRY_INITIAL;
                        }
                        Err(e) => {
                            warn!("Periodic ACME renewal failed: {e}; retrying in {:?}", retry_delay);
                            challenge_availability.record_error(e.clone());
                            next_delay = retry_delay;
                            retry_delay = (retry_delay * 2).min(ACME_RETRY_MAX);
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::generate_test_cert;
    use std::os::unix::fs::PermissionsExt;

    fn rand_suffix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }

    #[test]
    fn test_days_until_expiration() {
        let (cert_pem, _) = generate_test_cert(&["localhost"]);
        let days = days_until_expiration(cert_pem.as_bytes()).unwrap();
        // Generated test certs are typically valid for 30-365 days
        assert!(
            days >= 0,
            "Test cert should be valid for non-negative days: {days}"
        );
    }

    /// D12 ladder: a certificate's remaining lifetime determines whether
    /// readiness should be valid, degraded, or not-ready.
    #[test]
    fn test_certificate_validity_ladder() {
        let now = time::OffsetDateTime::now_utc();
        let dir = std::env::temp_dir().join(format!(
            "sito_cert_validity_{}_{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&dir).expect("create dir");

        let missing = certificate_validity(&dir.join("missing.pem"));
        assert_eq!(missing, CertificateValidity::Missing);

        let valid_path = dir.join("valid.pem");
        let (valid_pem, _) = generate_ca_signed_cert_with_window(
            "valid.example",
            now,
            now + time::Duration::days(90),
        );
        std::fs::write(&valid_path, valid_pem).expect("write valid cert");
        assert!(matches!(
            certificate_validity(&valid_path),
            CertificateValidity::Valid { .. }
        ));

        let expiring_path = dir.join("expiring.pem");
        let (expiring_pem, _) = generate_ca_signed_cert_with_window(
            "expiring.example",
            now - time::Duration::days(60),
            now + time::Duration::days(10),
        );
        std::fs::write(&expiring_path, expiring_pem).expect("write expiring cert");
        assert!(matches!(
            certificate_validity(&expiring_path),
            CertificateValidity::Expiring { .. }
        ));

        let expired_path = dir.join("expired.pem");
        let (expired_pem, _) = generate_ca_signed_cert_with_window(
            "expired.example",
            now - time::Duration::days(90),
            now - time::Duration::hours(1),
        );
        std::fs::write(&expired_path, expired_pem).expect("write expired cert");
        assert_eq!(
            certificate_validity(&expired_path),
            CertificateValidity::Expired
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The default availability (nothing bound yet) must not select
    /// TLS-ALPN-01; a successful 443 bind flips it dynamically.
    #[test]
    fn test_challenge_availability_defaults_to_http01() {
        let availability = AcmeChallengeAvailability::default();
        assert!(!availability.options().tls_alpn_available);
        assert!(!availability.options().http01_available);

        availability.set_http01_available(true);
        assert_eq!(
            select_challenge_type(true, true, availability.options()),
            Some(ChallengeType::Http01)
        );

        availability.set_tls_alpn_available(true);
        assert_eq!(
            select_challenge_type(true, true, availability.options()),
            Some(ChallengeType::TlsAlpn01)
        );

        availability.set_tls_alpn_available(false);
        assert_eq!(
            select_challenge_type(true, true, availability.options()),
            Some(ChallengeType::Http01)
        );
    }

    /// Regression (P1-12): TLS-ALPN-01 must only be chosen when a TCP 443
    /// listener is available. A deployment without one must use HTTP-01.
    #[test]
    fn test_challenge_selection_requires_tls_alpn_listener() {
        let http_only = AcmeChallengeOptions {
            tls_alpn_available: false,
            http01_available: true,
        };
        assert_eq!(
            select_challenge_type(true, true, http_only),
            Some(ChallengeType::Http01),
            "TLS-ALPN-01 must not be selected without a bound 443 listener"
        );

        let tls_available = AcmeChallengeOptions {
            tls_alpn_available: true,
            http01_available: true,
        };
        assert_eq!(
            select_challenge_type(true, true, tls_available),
            Some(ChallengeType::TlsAlpn01)
        );

        // If TLS-ALPN-01 is unavailable and the CA does not offer HTTP-01,
        // there is no usable challenge.
        assert_eq!(select_challenge_type(true, false, http_only), None);
        // HTTP-01 availability is also required to select HTTP-01.
        assert_eq!(
            select_challenge_type(false, true, AcmeChallengeOptions::default()),
            None
        );
    }

    /// Generates a CA-signed (non-bootstrap) certificate chain for the given
    /// domain. Returns `(cert_pem, key_pem)`.
    fn generate_ca_signed_cert(domain: &str) -> (String, String) {
        let now = time::OffsetDateTime::now_utc();
        generate_ca_signed_cert_with_window(domain, now, now + time::Duration::days(90))
    }

    fn generate_ca_signed_cert_with_window(
        domain: &str,
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) -> (String, String) {
        generate_ca_signed_cert_with_domains(&[domain], not_before, not_after)
    }

    fn generate_ca_signed_cert_with_domains(
        domains: &[&str],
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) -> (String, String) {
        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "sito test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA cert");

        let key = rcgen::KeyPair::generate().expect("leaf key");
        let mut params = rcgen::CertificateParams::new(
            domains
                .iter()
                .map(|domain| (*domain).to_string())
                .collect::<Vec<_>>(),
        )
        .expect("leaf params");
        params.not_before = not_before;
        params.not_after = not_after;
        let cert = params
            .signed_by(&key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .expect("leaf cert");
        (
            format!("{}{}", cert.pem(), ca_cert.pem()),
            key.serialize_pem(),
        )
    }

    /// Changing `acme.domains` must force a new order instead of waiting for
    /// the old certificate's renewal window. Removing or adding a SAN both
    /// count; reordering is not a change.
    #[test]
    fn test_certificate_needs_renewal_when_domains_change() {
        let dir = std::env::temp_dir().join(format!(
            "sito_acme_domain_change_{}_{}",
            std::process::id(),
            rand_suffix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");

        let now = time::OffsetDateTime::now_utc();
        let (cert_pem, key_pem) = generate_ca_signed_cert_with_domains(
            &["a.example.com", "b.example.com"],
            now,
            now + time::Duration::days(90),
        );
        std::fs::write(dir.join("cert.pem"), &cert_pem).expect("write cert");
        write_secret_file(&dir.join("key.pem"), key_pem.as_bytes()).expect("write key");
        write_pair_metadata(&dir).expect("pair metadata");

        let config = |domains: &[&str]| {
            AcmeServiceConfig::new(
                "admin@example.com".into(),
                domains.iter().map(|domain| (*domain).to_string()).collect(),
                dir.clone(),
            )
        };

        assert!(
            !certificate_needs_renewal(&config(&["b.example.com", "a.example.com"])),
            "the same SAN set in a different order must not renew"
        );
        assert!(
            certificate_needs_renewal(&config(&["a.example.com"])),
            "removing a configured domain must trigger renewal"
        );
        assert!(
            certificate_needs_renewal(&config(&[
                "a.example.com",
                "b.example.com",
                "c.example.com"
            ])),
            "adding a configured domain must trigger renewal"
        );
        assert!(
            certificate_needs_renewal(&config(&["other.example.com", "b.example.com"])),
            "replacing a domain must trigger renewal"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Bootstrap detection must not flag a genuine CA-issued certificate.
    #[test]
    fn test_is_bootstrap_cert_distinguishes_real_certificate() {
        let dir = std::env::temp_dir().join(format!(
            "sito_acme_is_bootstrap_{}_{}",
            std::process::id(),
            rand_suffix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");

        let config = AcmeServiceConfig::new(
            "admin@example.com".into(),
            vec!["acme.example.com".into()],
            dir.clone(),
        );

        let (bootstrap_cert, bootstrap_key) =
            crate::tls::generate_self_signed_cert(&["acme.example.com".into()])
                .expect("bootstrap cert");
        std::fs::write(dir.join("cert.pem"), bootstrap_cert).expect("write cert");
        write_secret_file(&dir.join("key.pem"), bootstrap_key.as_bytes()).expect("write key");
        assert!(
            config.is_bootstrap_cert(),
            "a self-signed placeholder must be detected as bootstrap"
        );

        let (real_cert, real_key) = generate_ca_signed_cert("acme.example.com");
        std::fs::write(dir.join("cert.pem"), real_cert).expect("write cert");
        write_secret_file(&dir.join("key.pem"), real_key.as_bytes()).expect("write key");
        assert!(
            !config.is_bootstrap_cert(),
            "a CA-issued certificate must not be treated as a bootstrap placeholder"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression (deferred D2): truncated ACME material used to be reported
    /// as neither bootstrap nor expired, so startup selected it and the TLS
    /// builder aborted even when a valid static pair existed. Unreadable or
    /// unparseable material must be unusable.
    #[test]
    fn test_truncated_certificate_is_treated_as_unusable() {
        let dir = std::env::temp_dir().join(format!(
            "sito_acme_truncated_{}_{}",
            std::process::id(),
            rand_suffix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");

        let (_, key_pem) = generate_ca_signed_cert("acme.example.com");
        write_secret_file(&dir.join("key.pem"), key_pem.as_bytes()).expect("write key");
        std::fs::write(
            dir.join("cert.pem"),
            b"-----BEGIN CERTIFICATE-----\nnot a certificate\n",
        )
        .expect("write truncated cert");

        let config = AcmeServiceConfig::new(
            "admin@example.com".into(),
            vec!["acme.example.com".into()],
            dir.clone(),
        );
        assert!(
            config.is_bootstrap_cert(),
            "unparseable material must never be treated as a CA-issued certificate"
        );
        assert!(
            config.stored_cert_is_expired(),
            "unparseable material must be treated as unusable, not valid"
        );
        assert!(
            !config.stored_pair_is_usable(),
            "the startup path must reject an unparseable pair"
        );
        assert!(
            certificate_needs_renewal(&config),
            "unparseable material must still trigger ACME issuance"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A valid certificate with an unparseable key must not be selected for
    /// serving either: the TLS builder rejects the pair and startup would
    /// abort.
    #[test]
    fn test_unparseable_key_is_not_usable() {
        let dir = std::env::temp_dir().join(format!(
            "sito_acme_badkey_{}_{}",
            std::process::id(),
            rand_suffix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");

        let (cert_pem, _) = generate_ca_signed_cert("acme.example.com");
        std::fs::write(dir.join("cert.pem"), cert_pem).expect("write cert");
        write_secret_file(&dir.join("key.pem"), b"not a private key").expect("write key");

        let config = AcmeServiceConfig::new(
            "admin@example.com".into(),
            vec!["acme.example.com".into()],
            dir.clone(),
        );
        assert!(
            !config.is_bootstrap_cert(),
            "a valid CA certificate is not a bootstrap placeholder"
        );
        assert!(
            !config.stored_cert_is_expired(),
            "a valid CA certificate is not expired"
        );
        assert!(
            !config.stored_pair_is_usable(),
            "an unparseable private key makes the pair unusable"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A legitimate CA certificate that is merely close
    /// to expiry must still be treated as a real certificate. Its total
    /// lifetime is 90 days even though only 5 days remain.
    #[test]
    fn test_certificate_in_last_week_is_not_bootstrap() {
        let dir = std::env::temp_dir().join(format!(
            "sito_acme_short_remaining_{}_{}",
            std::process::id(),
            rand_suffix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");

        let now = time::OffsetDateTime::now_utc();
        let (cert_pem, key_pem) = generate_ca_signed_cert_with_window(
            "acme.example.com",
            now - time::Duration::days(85),
            now + time::Duration::days(5),
        );
        std::fs::write(dir.join("cert.pem"), &cert_pem).expect("write cert");
        write_secret_file(&dir.join("key.pem"), key_pem.as_bytes()).expect("write key");

        let config = AcmeServiceConfig::new(
            "admin@example.com".into(),
            vec!["acme.example.com".into()],
            dir.clone(),
        )
        .with_renew_before_days(30);

        assert!(
            !config.is_bootstrap_cert(),
            "remaining validity must not classify a CA certificate as bootstrap"
        );
        let lifetime =
            certificate_lifetime_days(cert_pem.as_bytes()).expect("certificate lifetime");
        assert!(
            (89..=91).contains(&lifetime),
            "expected a ~90-day certificate lifetime, got {lifetime}"
        );
        assert!(
            certificate_needs_renewal(&config),
            "a certificate with 5 days left must still be renewed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: a certificate expired by less than a day still has a
    /// truncated day count of 0. Expiry must be decided from seconds so
    /// startup does not pass the pair to TLS validation and abort.
    #[test]
    fn test_certificate_expired_one_hour_ago_is_expired() {
        let dir = std::env::temp_dir().join(format!(
            "sito_acme_expired_hour_{}_{}",
            std::process::id(),
            rand_suffix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");

        let now = time::OffsetDateTime::now_utc();
        let (cert_pem, key_pem) = generate_ca_signed_cert_with_window(
            "acme.example.com",
            now - time::Duration::days(90),
            now - time::Duration::hours(1),
        );
        std::fs::write(dir.join("cert.pem"), &cert_pem).expect("write cert");
        write_secret_file(&dir.join("key.pem"), key_pem.as_bytes()).expect("write key");

        let config = AcmeServiceConfig::new(
            "admin@example.com".into(),
            vec!["acme.example.com".into()],
            dir.clone(),
        );
        assert!(
            !config.is_bootstrap_cert(),
            "a CA-issued certificate is never a bootstrap placeholder"
        );
        assert!(
            config.stored_cert_is_expired(),
            "an hour-old expiry must be detected (days_until_expiration returns 0)"
        );

        let seconds = seconds_until_expiration(cert_pem.as_bytes()).expect("seconds remaining");
        assert!(
            (-3600..=-3590).contains(&seconds),
            "expected ~1 hour past expiry, got {seconds}s"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A CA-issued short-lived certificate (<= 7 days total) must not be
    /// classified as a bootstrap placeholder just because of its lifetime.
    #[test]
    fn test_short_lived_ca_certificate_is_not_bootstrap() {
        let dir = std::env::temp_dir().join(format!(
            "sito_acme_short_lived_ca_{}_{}",
            std::process::id(),
            rand_suffix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");

        let now = time::OffsetDateTime::now_utc();
        let (cert_pem, key_pem) = generate_ca_signed_cert_with_window(
            "acme.example.com",
            now - time::Duration::days(1),
            now + time::Duration::days(4),
        );
        std::fs::write(dir.join("cert.pem"), &cert_pem).expect("write cert");
        write_secret_file(&dir.join("key.pem"), key_pem.as_bytes()).expect("write key");

        let config = AcmeServiceConfig::new(
            "admin@example.com".into(),
            vec!["acme.example.com".into()],
            dir.clone(),
        );
        let lifetime =
            certificate_lifetime_days(cert_pem.as_bytes()).expect("certificate lifetime");
        assert!(
            (4..=5).contains(&lifetime),
            "expected a ~5-day certificate lifetime, got {lifetime}"
        );
        assert!(
            !config.is_bootstrap_cert(),
            "a short-lived CA certificate must not be treated as bootstrap"
        );
        assert!(!config.stored_cert_is_expired());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An explicit marker marks a legacy bootstrap pair even when its validity
    /// has not yet expired.
    #[test]
    fn test_bootstrap_marker_forces_detection() {
        let dir = std::env::temp_dir().join(format!(
            "sito_acme_bootstrap_marker_{}_{}",
            std::process::id(),
            rand_suffix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");

        let (cert_pem, key_pem) = generate_ca_signed_cert("acme.example.com");
        std::fs::write(dir.join("cert.pem"), cert_pem).expect("write cert");
        write_secret_file(&dir.join("key.pem"), key_pem.as_bytes()).expect("write key");
        let config = AcmeServiceConfig::new(
            "admin@example.com".into(),
            vec!["acme.example.com".into()],
            dir.clone(),
        );
        assert!(!config.is_bootstrap_cert());

        record_bootstrap_cert(&dir).expect("record bootstrap marker");
        assert!(config.is_bootstrap_cert());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tls_alpn_01_challenge_cert_generation() {
        let domain = "acme.example.com";
        let key_auth = "sample_key_auth_token_value_1234567890";
        let (cert_der, priv_der) = generate_tls_alpn_01_cert(domain, key_auth).unwrap();

        assert!(
            !cert_der.is_empty(),
            "generated TLS-ALPN-01 certificate must not be empty"
        );
        let certified = create_certified_key(vec![cert_der], &priv_der).unwrap();
        assert_eq!(certified.cert.len(), 1);
    }

    /// Regression (P0-1): a bootstrap self-signed certificate written by the
    /// startup path carries no `pair.sha256` marker and used to be valid until
    /// year 4096, so `certificate_needs_renewal` skipped ACME forever.
    #[test]
    fn test_fresh_bootstrap_certificate_requires_renewal() {
        let dir = std::env::temp_dir().join(format!(
            "sito_acme_bootstrap_renew_{}_{}",
            std::process::id(),
            rand_suffix()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");

        let (cert_pem, key_pem) =
            crate::tls::generate_self_signed_cert(&["acme.example.com".into()])
                .expect("bootstrap cert");
        std::fs::write(dir.join("cert.pem"), cert_pem).expect("write cert");
        write_secret_file(&dir.join("key.pem"), key_pem.as_bytes()).expect("write key");

        let config = AcmeServiceConfig::new(
            "admin@example.com".into(),
            vec!["acme.example.com".into()],
            dir.clone(),
        );
        assert!(
            certificate_needs_renewal(&config),
            "a fresh bootstrap certificate must never suppress ACME issuance"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression (P0-1): the bootstrap certificate must be short-lived (or
    /// explicitly marked bootstrap) so operators never keep serving it for
    /// centuries when issuance fails.
    #[test]
    fn test_bootstrap_certificate_is_short_lived() {
        let (cert_pem, _) = crate::tls::generate_self_signed_cert(&["acme.example.com".into()])
            .expect("bootstrap cert");
        let days = days_until_expiration(cert_pem.as_bytes()).expect("parse bootstrap cert");
        assert!(
            (0..=7).contains(&days),
            "bootstrap certificate validity must not exceed 7 days, got {days}"
        );
    }

    #[test]
    fn test_certificate_needs_renewal_missing_files() {
        let temp_dir = std::env::temp_dir().join(format!("sito_acme_check_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let config = AcmeServiceConfig::new(
            "admin@example.com".into(),
            vec!["test.com".into()],
            temp_dir.clone(),
        );
        assert!(certificate_needs_renewal(&config));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_pair_metadata_detects_partial_rotation() {
        let dir = std::env::temp_dir().join(format!("sito_acme_pair_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let meta = pair_metadata_path(&dir);

        // Missing marker: unknown (older/manual installs) must not force a
        // renewal loop.
        std::fs::write(&cert, b"cert").expect("write cert");
        std::fs::write(&key, b"key").expect("write key");
        assert!(pair_metadata_matches(&cert, &key, &meta));

        // A completed rotation records the pair and matches.
        let cert_hash = file_sha256(&cert).expect("cert hash");
        let key_hash = file_sha256(&key).expect("key hash");
        std::fs::write(&meta, format!("{cert_hash} {key_hash}\n")).expect("write marker");
        assert!(pair_metadata_matches(&cert, &key, &meta));

        // A new certificate with the old key is a partial rotation.
        std::fs::write(&cert, b"new-cert").expect("write new cert");
        assert!(
            !pair_metadata_matches(&cert, &key, &meta),
            "a mismatched pair must force renewal"
        );

        // Atomic writes replace the file and apply the requested mode.
        write_atomic(&cert, b"atomic", 0o600).expect("atomic write");
        assert_eq!(std::fs::read(&cert).expect("read"), b"atomic");
        let mode = std::fs::metadata(&cert)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
