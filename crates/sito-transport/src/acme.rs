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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    RetryPolicy,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::{debug, error, info, warn};

use crate::tls::{TlsAcceptorManager, TlsManagerSet, create_certified_key};

/// Enforce owner-only permissions (0600) on an existing secret file.
///
/// `OpenOptions::mode` only applies when a file is created, so files that
/// already exist (e.g. account credentials written by an older version) need
/// this explicit fix-up.
#[cfg(unix)]
fn enforce_secret_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        warn!(
            "Failed to restrict permissions on secret file {}: {e}",
            path.display()
        );
    }
}

#[cfg(not(unix))]
fn enforce_secret_file_permissions(_path: &Path) {}

/// Writes a file containing key material with owner-only permissions (0600).
///
/// `mode` only applies when the file is created; existing files are re-chmodded
/// and a failure to restrict permissions is returned as an error (fail closed).
pub fn write_secret_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
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
        // `mode` only applies at creation; fail closed if existing perms
        // cannot be restricted.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
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
    /// Bootstrap certificates are detected by an explicit marker, a short
    /// validity, or being self-signed. The self-signed check also recovers
    /// installations upgraded from versions that wrote a year-4096 bootstrap
    /// certificate without a marker.
    pub fn is_bootstrap_cert(&self) -> bool {
        if bootstrap_marker_path(&self.storage_dir).exists() {
            return true;
        }
        let Ok(cert_bytes) = std::fs::read(self.storage_dir.join("cert.pem")) else {
            return false;
        };
        if is_self_signed(&cert_bytes) {
            return true;
        }
        days_until_expiration(&cert_bytes)
            .is_ok_and(|days| days <= crate::tls::BOOTSTRAP_CERT_VALIDITY_DAYS)
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

/// Calculate the number of days remaining until an X.509 certificate expires.
pub fn days_until_expiration(cert_pem: &[u8]) -> Result<i64, String> {
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

    let seconds_left = not_after - now;
    let days_left = seconds_left / 86400;
    Ok(days_left)
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
fn is_self_signed(cert_pem: &[u8]) -> bool {
    let Ok(certs) = CertificateDer::pem_slice_iter(cert_pem).collect::<Result<Vec<_>, _>>() else {
        return false;
    };
    let Some(first) = certs.first() else {
        return false;
    };
    let Ok((_, x509)) = x509_parser::parse_x509_certificate(first.as_ref()) else {
        return false;
    };
    x509.tbs_certificate.subject == x509.tbs_certificate.issuer
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
        if cert_path.exists()
            && key_path.exists()
            && let Err(e) = managers.reload_all(&cert_path, &key_path)
        {
            warn!("Failed to reload transports from persisted ACME certificate: {e}");
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
    match managers.reload_all(&cert_path, &key_path) {
        Ok(()) => info!("All TLS transports reloaded with the ACME certificate"),
        Err(e) => error!("Failed to reload one or more TLS transports with new ACME cert: {e}"),
    }

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
    let challenge_options = AcmeChallengeOptions {
        tls_alpn_available: !managers.is_empty(),
        http01_available: http01_challenges.is_some(),
    };
    start_acme_manager_for_transports(
        config,
        managers,
        http01_challenges,
        challenge_options,
        shutdown_rx,
    )
}

/// Spawns the ACME manager with an explicit set of transport managers and a
/// port-aware challenge selection.
pub fn start_acme_manager_for_transports(
    config: AcmeServiceConfig,
    managers: TlsManagerSet,
    http01_challenges: Option<Arc<dashmap::DashMap<String, String>>>,
    challenge_options: AcmeChallengeOptions,
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
            challenge_options,
        )
        .await
        {
            Ok(_) => true,
            Err(e) => {
                warn!("Initial ACME certificate check failed: {e}");
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
                        challenge_options,
                    ).await {
                        Ok(_) => {
                            next_delay = ACME_CHECK_INTERVAL;
                            retry_delay = ACME_RETRY_INITIAL;
                        }
                        Err(e) => {
                            warn!("Periodic ACME renewal failed: {e}; retrying in {:?}", retry_delay);
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
        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "sito test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA cert");

        let key = rcgen::KeyPair::generate().expect("leaf key");
        let params = rcgen::CertificateParams::new(vec![domain.to_string()]).expect("leaf params");
        let cert = params
            .signed_by(&key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .expect("leaf cert");
        (
            format!("{}{}", cert.pem(), ca_cert.pem()),
            key.serialize_pem(),
        )
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
