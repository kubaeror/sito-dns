//! TLS infrastructure for encrypted DNS transports (DoT, DoH).
//!
//! Provides `rustls::ServerConfig` loading from PEM files, certificate validity
//! (expiration and not-before) checking, SNI-based certificate resolution,
//! zero-downtime certificate reloading via `ArcSwap`, and filesystem monitoring.

use arc_swap::ArcSwap;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

/// TLS configuration and certificate loading errors.
#[derive(Debug, Error)]
pub enum TlsError {
    #[error("I/O error reading TLS material from '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse PEM certificate from '{path}': {reason}")]
    CertParse { path: PathBuf, reason: String },

    #[error("Failed to parse PEM private key from '{path}': {reason}")]
    KeyParse { path: PathBuf, reason: String },

    #[error("Certificate file '{path}' contains no valid certificates")]
    EmptyCertificateChain { path: PathBuf },

    #[error("Certificate '{path}' is expired (not_after: {not_after})")]
    CertificateExpired { path: PathBuf, not_after: String },

    #[error("Certificate '{path}' is not yet valid (not_before: {not_before})")]
    CertificateNotYetValid { path: PathBuf, not_before: String },

    #[error("TLS certificate and private key do not contain the same public key")]
    CertKeyMismatch,

    #[error("TLS configuration error: {0}")]
    Config(String),

    #[error("Filesystem watch error: {0}")]
    Watch(String),
}

/// Load and validate a certificate chain from a PEM file.
pub fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let bytes = std::fs::read(path).map_err(|e| TlsError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertParse {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;

    if certs.is_empty() {
        return Err(TlsError::EmptyCertificateChain {
            path: path.to_path_buf(),
        });
    }

    // Verify validity (not expired, not before) of the certificates
    for cert in &certs {
        validate_certificate_validity(cert.as_ref(), path)?;
    }

    Ok(certs)
}

/// Validate that an X.509 DER certificate is currently within its validity period.
pub fn validate_certificate_validity(der_bytes: &[u8], path: &Path) -> Result<(), TlsError> {
    let (_, x509) =
        x509_parser::parse_x509_certificate(der_bytes).map_err(|e| TlsError::CertParse {
            path: path.to_path_buf(),
            reason: format!("X.509 parse failure: {e}"),
        })?;

    #[allow(clippy::cast_possible_wrap)]
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let validity = x509.validity();
    if now > validity.not_after.timestamp() {
        return Err(TlsError::CertificateExpired {
            path: path.to_path_buf(),
            not_after: validity.not_after.to_string(),
        });
    }

    if now < validity.not_before.timestamp() {
        return Err(TlsError::CertificateNotYetValid {
            path: path.to_path_buf(),
            not_before: validity.not_before.to_string(),
        });
    }

    Ok(())
}

/// Load a private key from a PEM file.
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let bytes = std::fs::read(path).map_err(|e| TlsError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    PrivateKeyDer::from_pem_slice(&bytes).map_err(|e| TlsError::KeyParse {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}

/// Validity of the self-signed bootstrap certificate generated while ACME is
/// still ordering a real certificate.
///
/// This is deliberately short: the bootstrap certificate is only a placeholder
/// so encrypted listeners can start before issuance completes. It must never be
/// mistaken for a usable long-lived certificate.
pub const BOOTSTRAP_CERT_VALIDITY_DAYS: i64 = 7;

/// Generates a self-signed certificate and private key pair for the given domain names.
///
/// The returned certificate is short-lived ([`BOOTSTRAP_CERT_VALIDITY_DAYS`])
/// because this helper is used for the ACME bootstrap placeholder. Callers that
/// need a longer-lived test certificate should build one explicitly.
pub fn generate_self_signed_cert(domains: &[String]) -> Result<(String, String), TlsError> {
    let mut params = rcgen::CertificateParams::new(domains.to_vec())
        .map_err(|e| TlsError::Config(format!("Failed to build certificate params: {e}")))?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(BOOTSTRAP_CERT_VALIDITY_DAYS);
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| TlsError::Config(format!("Failed to generate key pair: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TlsError::Config(format!("Failed to sign certificate: {e}")))?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// Dynamic SNI certificate resolver supporting a default fallback, virtual host mapping,
/// and in-memory ACME challenge keys (RFC 8737 TLS-ALPN-01).
pub struct DynamicCertResolver {
    default_key: Arc<CertifiedKey>,
    sni_keys: HashMap<String, Arc<CertifiedKey>>,
    allowed_alpn: Vec<Vec<u8>>,
    challenge_keys: Arc<dashmap::DashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertResolver")
            .field("default_key", &self.default_key)
            .field("sni_keys", &self.sni_keys)
            .field("allowed_alpn", &self.allowed_alpn)
            .field("challenge_count", &self.challenge_keys.len())
            .finish()
    }
}

impl DynamicCertResolver {
    pub fn new(
        default_key: Arc<CertifiedKey>,
        sni_keys: HashMap<String, Arc<CertifiedKey>>,
    ) -> Self {
        Self {
            default_key,
            sni_keys,
            allowed_alpn: Vec::new(),
            challenge_keys: Arc::new(dashmap::DashMap::new()),
        }
    }

    #[must_use]
    pub fn with_challenge_keys(
        mut self,
        challenge_keys: Arc<dashmap::DashMap<String, Arc<CertifiedKey>>>,
    ) -> Self {
        self.challenge_keys = challenge_keys;
        self
    }

    pub fn challenge_keys(&self) -> Arc<dashmap::DashMap<String, Arc<CertifiedKey>>> {
        Arc::clone(&self.challenge_keys)
    }

    pub fn register_challenge(&self, domain: &str, key: Arc<CertifiedKey>) {
        self.challenge_keys.insert(domain.to_ascii_lowercase(), key);
    }

    pub fn unregister_challenge(&self, domain: &str) {
        self.challenge_keys.remove(&domain.to_ascii_lowercase());
    }

    #[must_use]
    pub fn with_allowed_alpn(mut self, allowed_alpn: Vec<Vec<u8>>) -> Self {
        self.allowed_alpn = allowed_alpn;
        self
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // Check for ACME TLS-ALPN-01 challenge first (ALPN = "acme-tls/1")
        if let Some(mut alpn) = client_hello.alpn()
            && alpn.any(|proto| proto == b"acme-tls/1")
            && let Some(sni) = client_hello.server_name()
        {
            let sni_lower = sni.to_ascii_lowercase();
            if let Some(key) = self.challenge_keys.get(&sni_lower) {
                return Some(Arc::clone(&*key));
            }
        }

        // Enforce ALPN if configured and client provided ALPN offers
        if !self.allowed_alpn.is_empty()
            && let Some(mut alpn) = client_hello.alpn()
            && !alpn.any(|client_proto| {
                self.allowed_alpn
                    .iter()
                    .any(|p| p.as_slice() == client_proto)
            })
        {
            return None;
        }

        if let Some(sni) = client_hello.server_name() {
            let sni_lower = sni.to_ascii_lowercase();
            if let Some(key) = self.sni_keys.get(&sni_lower) {
                return Some(Arc::clone(key));
            }
            if let Some(dot_idx) = sni_lower.find('.') {
                let wildcard = format!("*{}", &sni_lower[dot_idx..]);
                if let Some(key) = self.sni_keys.get(&wildcard) {
                    return Some(Arc::clone(key));
                }
            }
        }
        Some(Arc::clone(&self.default_key))
    }
}

/// Build a `CertifiedKey` from a certificate chain and private key.
pub fn create_certified_key(
    certs: Vec<CertificateDer<'static>>,
    key: &PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>, TlsError> {
    let signing_key = rustls::crypto::ring::sign::any_supported_type(key)
        .map_err(|e| TlsError::Config(format!("unsupported private key format: {e}")))?;

    // rustls does not check that the private key belongs to the leaf
    // certificate; it only fails later, during the handshake. ACME writes the
    // key before the certificate, so a watcher can observe exactly that mixed
    // pair. Compare the certificate SPKI with the signing key's SPKI and refuse
    // to install an unusable pair.
    if let Some(key_spki) = signing_key.public_key()
        && let Some(cert) = certs.first()
    {
        let (_, x509) = x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|e| {
            TlsError::Config(format!(
                "Failed to parse certificate while verifying the certificate/key pair: {e}"
            ))
        })?;
        if x509.tbs_certificate.subject_pki.raw != key_spki.as_ref() {
            return Err(TlsError::CertKeyMismatch);
        }
    }

    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Build a `rustls::ServerConfig` with modern TLS (1.3 + 1.2), session resumption enabled,
/// and configured ALPN protocols.
pub fn build_server_config(
    cert_resolver: Arc<dyn ResolvesServerCert>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ServerConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    config.alpn_protocols = alpn_protocols;
    Ok(config)
}

/// Build `ServerConfig` from primary cert/key paths and optional SNI pairs.
pub fn load_server_config(
    cert_path: &Path,
    key_path: &Path,
    sni_certs: &[(String, PathBuf, PathBuf)],
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ServerConfig, TlsError> {
    load_server_config_with_challenges(
        cert_path,
        key_path,
        sni_certs,
        alpn_protocols,
        Arc::new(dashmap::DashMap::new()),
    )
}

/// Build `ServerConfig` from primary cert/key paths, optional SNI pairs, and shared challenge keys.
pub fn load_server_config_with_challenges(
    cert_path: &Path,
    key_path: &Path,
    sni_certs: &[(String, PathBuf, PathBuf)],
    alpn_protocols: Vec<Vec<u8>>,
    challenge_keys: Arc<dashmap::DashMap<String, Arc<CertifiedKey>>>,
) -> Result<ServerConfig, TlsError> {
    let default_certs = load_certificates(cert_path)?;
    let default_key = load_private_key(key_path)?;
    let default_certified = create_certified_key(default_certs, &default_key)?;

    let mut sni_keys = HashMap::new();
    for (domain, sni_cert_path, sni_key_path) in sni_certs {
        let certs = load_certificates(sni_cert_path)?;
        let key = load_private_key(sni_key_path)?;
        let certified = create_certified_key(certs, &key)?;
        sni_keys.insert(domain.to_ascii_lowercase(), certified);
    }

    let resolver = Arc::new(
        DynamicCertResolver::new(default_certified, sni_keys)
            .with_challenge_keys(challenge_keys)
            .with_allowed_alpn(alpn_protocols.clone()),
    );
    build_server_config(resolver, alpn_protocols)
}

/// Manages dynamic `ServerConfig` swapping without dropping in-flight connections.
#[derive(Clone)]
pub struct TlsAcceptorManager {
    server_config: Arc<ArcSwap<ServerConfig>>,
    challenge_keys: Arc<dashmap::DashMap<String, Arc<CertifiedKey>>>,
    sni_certs: Arc<ArcSwap<Vec<(String, PathBuf, PathBuf)>>>,
}

impl TlsAcceptorManager {
    /// Create a new manager initialized with a `ServerConfig`.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            server_config: Arc::new(ArcSwap::from_pointee(config)),
            challenge_keys: Arc::new(dashmap::DashMap::new()),
            sni_certs: Arc::new(ArcSwap::from_pointee(Vec::new())),
        }
    }

    /// Create a new manager with shared challenge keys.
    pub fn with_challenge_keys(
        config: ServerConfig,
        challenge_keys: Arc<dashmap::DashMap<String, Arc<CertifiedKey>>>,
    ) -> Self {
        Self {
            server_config: Arc::new(ArcSwap::from_pointee(config)),
            challenge_keys,
            sni_certs: Arc::new(ArcSwap::from_pointee(Vec::new())),
        }
    }

    /// Record the SNI certificate pairs this manager was built with so later
    /// in-process reloads (ACME rotation, config changes) can preserve them.
    pub fn set_sni_certs(&self, sni_certs: Vec<(String, PathBuf, PathBuf)>) {
        self.sni_certs.store(Arc::new(sni_certs));
    }

    /// Snapshot of the SNI certificate pairs associated with this manager.
    pub fn sni_certs(&self) -> Arc<Vec<(String, PathBuf, PathBuf)>> {
        self.sni_certs.load_full()
    }

    /// Access the shared challenge keys map.
    pub fn challenge_keys(&self) -> Arc<dashmap::DashMap<String, Arc<CertifiedKey>>> {
        Arc::clone(&self.challenge_keys)
    }

    /// Register a challenge certificate for TLS-ALPN-01 validation.
    pub fn register_challenge(&self, domain: &str, key: Arc<CertifiedKey>) {
        self.challenge_keys.insert(domain.to_ascii_lowercase(), key);
    }

    /// Unregister a challenge certificate.
    pub fn unregister_challenge(&self, domain: &str) {
        self.challenge_keys.remove(&domain.to_ascii_lowercase());
    }

    /// Load the current active `ServerConfig`.
    pub fn current_config(&self) -> Arc<ServerConfig> {
        self.server_config.load_full()
    }

    /// ALPN protocols currently advertised by this manager.
    pub fn alpn_protocols(&self) -> Vec<Vec<u8>> {
        self.current_config().alpn_protocols.clone()
    }

    /// Obtain a `TlsAcceptor` configured with the latest `ServerConfig`.
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.current_config())
    }

    /// Atomically replace the running `ServerConfig` without interrupting active connections.
    pub fn reload(&self, new_config: ServerConfig) {
        self.server_config.store(Arc::new(new_config));
        info!("TLS server configuration reloaded successfully");
    }

    /// Reload this manager from certificate/key files while preserving the
    /// manager's ALPN protocols, virtual-host certificates and in-flight ACME
    /// challenge keys.
    ///
    /// The new pair is validated (including the certificate/key public-key
    /// match) before it replaces the running configuration, so a failed reload
    /// leaves the previous pair active.
    pub fn reload_from_files(&self, cert_path: &Path, key_path: &Path) -> Result<(), TlsError> {
        let new_config = load_server_config_with_challenges(
            cert_path,
            key_path,
            self.sni_certs().as_slice(),
            self.alpn_protocols(),
            self.challenge_keys(),
        )?;
        self.reload(new_config);
        Ok(())
    }
}

/// The TLS managers used by every encrypted DNS transport.
///
/// ACME issuance used to reload only the DoH manager, leaving DoT/DoQ/DoH3 on
/// stale certificates until the next restart. `reload_all` updates every
/// configured listener from the same persisted pair.
#[derive(Clone, Default)]
pub struct TlsManagerSet {
    pub dot: Option<TlsAcceptorManager>,
    pub doh: Option<TlsAcceptorManager>,
    pub doq: Option<TlsAcceptorManager>,
    pub doh3: Option<TlsAcceptorManager>,
}

impl TlsManagerSet {
    /// Build a set containing only the DoH manager (the pre-existing API shape).
    pub fn from_doh(doh: Option<TlsAcceptorManager>) -> Self {
        Self {
            doh,
            ..Self::default()
        }
    }

    /// Whether no encrypted listener has a TLS manager.
    pub fn is_empty(&self) -> bool {
        self.dot.is_none() && self.doh.is_none() && self.doq.is_none() && self.doh3.is_none()
    }

    /// Reload every configured transport from `cert`/`key`.
    ///
    /// All managers are attempted even if one fails; the collected errors are
    /// returned so the caller can log every transport that did not pick up the
    /// new certificate.
    pub fn reload_all(&self, cert: &Path, key: &Path) -> Result<(), TlsError> {
        let mut first_error = None;
        for (protocol, manager) in [
            ("dot", self.dot.as_ref()),
            ("doh", self.doh.as_ref()),
            ("doq", self.doq.as_ref()),
            ("doh3", self.doh3.as_ref()),
        ] {
            let Some(manager) = manager else {
                continue;
            };
            if let Err(e) = manager.reload_from_files(cert, key) {
                error!(protocol, error = %e, "Failed to reload TLS certificate");
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// Filesystem watcher that automatically reloads TLS certificates on modification.
pub struct CertWatcher {
    _watcher: Arc<Mutex<RecommendedWatcher>>,
}

/// Makes `path` absolute without resolving symlinks: notify reports event
/// paths in the form they were watched, and a symlinked certificate path must
/// still match its own events.
fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
    }
}

/// Registers a direct watch on each file (in-place rewrites) plus a
/// non-recursive watch on its parent directory (atomic replacements via
/// rename, which destroy the direct file watch on Linux).
///
/// Every failure is logged at `error` level and does not abort the remaining
/// watches: a silently disabled certificate reload is worse than a noisy log.
fn register_watches(watcher: &mut RecommendedWatcher, files: &[PathBuf]) -> usize {
    let mut registered = 0usize;
    let mut dirs_done: Vec<PathBuf> = Vec::new();

    for file in files {
        if file.exists() {
            match watcher.watch(file, RecursiveMode::NonRecursive) {
                Ok(()) => registered += 1,
                Err(e) => error!(
                    path = %file.display(),
                    error = %e,
                    "Failed to watch TLS certificate/key file; automatic reload \
                     will not see in-place changes to it"
                ),
            }
        }

        let Some(parent) = file.parent() else {
            continue;
        };
        if dirs_done.iter().any(|dir| dir == parent) {
            continue;
        }
        match watcher.watch(parent, RecursiveMode::NonRecursive) {
            Ok(()) => registered += 1,
            Err(e) => error!(
                path = %parent.display(),
                error = %e,
                "Failed to watch TLS certificate directory; automatic reload \
                 will not see atomic certificate replacements"
            ),
        }
        dirs_done.push(parent.to_path_buf());
    }

    registered
}

impl CertWatcher {
    /// Start watching certificate and key files for changes and automatically reload the acceptor.
    ///
    /// The configured files are watched directly (in-place rewrites) and their
    /// parent directories are watched for rename/create events (atomic
    /// replacements), with events filtered to the configured paths so
    /// unrelated directory activity does not trigger reloads. Watch setup and
    /// runtime errors are logged at `error` level.
    pub fn start(
        cert_path: &Path,
        key_path: &Path,
        sni_certs: &[(String, PathBuf, PathBuf)],
        alpn_protocols: &[Vec<u8>],
        acceptor_mgr: TlsAcceptorManager,
        on_reload: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Result<Self, TlsError> {
        // Remember the SNI pairs so reloads triggered by other components
        // (e.g. ACME renewal) do not silently drop virtual-host certificates.
        acceptor_mgr.set_sni_certs(sni_certs.to_vec());

        // Every file whose change must trigger a reload (primary cert/key plus
        // virtual-host pairs), as absolute paths so they compare equal to
        // notify's event paths.
        let mut watched_files: Vec<PathBuf> = Vec::with_capacity(2 + sni_certs.len() * 2);
        for path in std::iter::once(cert_path)
            .chain(std::iter::once(key_path))
            .chain(
                sni_certs
                    .iter()
                    .flat_map(|(_, cert, key)| [cert.as_path(), key.as_path()]),
            )
        {
            let absolute = absolute_path(path);
            if !watched_files.contains(&absolute) {
                watched_files.push(absolute);
            }
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);
        let event_paths = watched_files.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| match res {
                Ok(event) => {
                    // Only changes to the configured files matter; a directory
                    // watch would otherwise reload on every unrelated file.
                    let relevant = event.paths.iter().any(|path| event_paths.contains(path));
                    if relevant
                        && (event.kind.is_modify()
                            || event.kind.is_create()
                            || event.kind.is_remove())
                    {
                        // Never block the notify event loop: a full channel
                        // means the reload task already has pending wake-ups,
                        // and it re-reads the current files when it runs.
                        let _ = tx.try_send(());
                    }
                }
                Err(e) => error!(
                    error = %e,
                    "TLS certificate watcher reported an error; certificate \
                     reload may be disabled"
                ),
            },
            notify::Config::default(),
        )
        .map_err(|e| TlsError::Watch(e.to_string()))?;

        register_watches(&mut watcher, &watched_files);

        let watcher = Arc::new(Mutex::new(watcher));
        // The reload task only borrows the watcher: holding an `Arc` there
        // would keep the watcher (and its inotify event loop) alive after the
        // `CertWatcher` is dropped.
        let task_watcher = Arc::downgrade(&watcher);

        let cert_path_clone = cert_path.to_path_buf();
        let key_path_clone = key_path.to_path_buf();
        let sni_certs_clone = sni_certs.to_vec();
        let alpn_clone = alpn_protocols.to_vec();
        let task_files = watched_files.clone();

        tokio::spawn(async move {
            while (rx.recv().await).is_some() {
                // Debounce rapid filesystem updates
                tokio::time::sleep(Duration::from_millis(200)).await;
                while rx.try_recv().is_ok() {}

                info!(
                    cert = %cert_path_clone.display(),
                    key = %key_path_clone.display(),
                    "Detected change in TLS certificate/key files; reloading..."
                );

                // An atomic replacement removes the direct file watch on
                // Linux; re-register it so later in-place changes are still
                // noticed.
                if let Some(watcher) = task_watcher.upgrade() {
                    let mut watcher = sito_core::sync::lock_or_recover(&watcher);
                    register_watches(&mut watcher, &task_files);
                }

                match load_server_config_with_challenges(
                    &cert_path_clone,
                    &key_path_clone,
                    &sni_certs_clone,
                    alpn_clone.clone(),
                    acceptor_mgr.challenge_keys(),
                ) {
                    Ok(new_config) => {
                        acceptor_mgr.reload(new_config);
                        if let Some(on_reload) = &on_reload {
                            // Republish readiness immediately on reload so a
                            // replaced certificate clears (or sets) the TLS
                            // reason without waiting for the next probe.
                            on_reload();
                        }
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            "Failed to reload TLS certificates (keeping existing configuration active)"
                        );
                    }
                }
            }
        });

        Ok(Self { _watcher: watcher })
    }
}

/// Generates a valid self-signed certificate and private key in PEM format using rcgen.
#[cfg(test)]
pub fn generate_test_cert(san_domains: &[&str]) -> (String, String) {
    let key_pair = rcgen::KeyPair::generate().expect("key pair generation");
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "sito-test.local");
    params.distinguished_name = dn;
    for san in san_domains {
        params.subject_alt_names.push(rcgen::SanType::DnsName(
            (*san).to_string().try_into().unwrap(),
        ));
    }

    let cert = params.self_signed(&key_pair).expect("self signed cert");
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem, key_pem)
}

/// Generates an expired self-signed certificate and private key in PEM format using rcgen.
#[cfg(test)]
pub fn generate_expired_test_cert(san_domains: &[&str]) -> (String, String) {
    let key_pair = rcgen::KeyPair::generate().expect("key pair generation");
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "sito-expired.local");
    params.distinguished_name = dn;
    for san in san_domains {
        params.subject_alt_names.push(rcgen::SanType::DnsName(
            (*san).to_string().try_into().unwrap(),
        ));
    }
    // Set validity in the past (year 2020)
    params.not_before = time::OffsetDateTime::from_unix_timestamp(1_577_836_800).unwrap(); // 2020-01-01
    params.not_after = time::OffsetDateTime::from_unix_timestamp(1_577_923_200).unwrap(); // 2020-01-02

    let cert = params.self_signed(&key_pair).expect("self signed cert");
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem, key_pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sito_tls_test_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn test_load_valid_certificates_and_key() {
        let temp_dir = create_test_dir("valid");
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");

        let (cert_pem, key_pem) = generate_test_cert(&["localhost", "dns.example.com"]);
        std::fs::write(&cert_file, cert_pem).unwrap();
        std::fs::write(&key_file, key_pem).unwrap();

        let certs = load_certificates(&cert_file).unwrap();
        assert_eq!(certs.len(), 1);

        let key = load_private_key(&key_file).unwrap();
        let certified = create_certified_key(certs, &key);
        assert!(certified.is_ok());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Regression (P2-14): ACME writes the key before the certificate, so the
    /// certificate watcher can observe a mismatched pair. Loading it must fail
    /// instead of installing a pair that cannot complete a handshake.
    #[tokio::test]
    async fn test_reject_mismatched_certificate_and_key() {
        let temp_dir = create_test_dir("mismatch");
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");

        let (cert_pem, _) = generate_test_cert(&["mismatch.example.com"]);
        let (_, other_key_pem) = generate_test_cert(&["other.example.com"]);
        std::fs::write(&cert_file, cert_pem).unwrap();
        std::fs::write(&key_file, other_key_pem).unwrap();

        let err = load_server_config(&cert_file, &key_file, &[], vec![b"dot".to_vec()])
            .expect_err("a certificate/key mismatch must be rejected");
        assert!(
            matches!(err, TlsError::CertKeyMismatch),
            "expected CertKeyMismatch, got {err:?}"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_reject_expired_certificate() {
        let temp_dir = create_test_dir("expired");
        let cert_file = temp_dir.join("expired_cert.pem");

        let (cert_pem, _) = generate_expired_test_cert(&["localhost"]);
        std::fs::write(&cert_file, cert_pem).unwrap();

        let err = load_certificates(&cert_file).unwrap_err();
        match err {
            TlsError::CertificateExpired { .. } => {}
            other => panic!("expected CertificateExpired, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_sni_certificate_resolver() {
        let (default_cert_pem, default_key_pem) = generate_test_cert(&["default.local"]);
        let (vhost_cert_pem, vhost_key_pem) = generate_test_cert(&["vhost.example.com"]);

        let temp_dir = create_test_dir("sni");
        let def_c = temp_dir.join("def_c.pem");
        let def_k = temp_dir.join("def_k.pem");
        let vhost_c = temp_dir.join("vhost_c.pem");
        let vhost_k = temp_dir.join("vhost_k.pem");

        std::fs::write(&def_c, default_cert_pem).unwrap();
        std::fs::write(&def_k, default_key_pem).unwrap();
        std::fs::write(&vhost_c, vhost_cert_pem).unwrap();
        std::fs::write(&vhost_k, vhost_key_pem).unwrap();

        let sni_list = vec![(
            "vhost.example.com".to_string(),
            vhost_c.clone(),
            vhost_k.clone(),
        )];

        let server_config =
            load_server_config(&def_c, &def_k, &sni_list, vec![b"dot".to_vec()]).unwrap();

        let acceptor_mgr = TlsAcceptorManager::new(server_config);
        assert!(
            !acceptor_mgr.current_config().alpn_protocols.is_empty(),
            "TLS acceptor must advertise ALPN protocols: {:?}",
            acceptor_mgr.current_config().alpn_protocols
        );
        assert_eq!(acceptor_mgr.current_config().alpn_protocols[0], b"dot");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_atomic_reload_without_dropping_active() {
        let temp_dir = create_test_dir("reload");
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");

        let (c1, k1) = generate_test_cert(&["initial.local"]);
        std::fs::write(&cert_file, c1).unwrap();
        std::fs::write(&key_file, k1).unwrap();

        let config1 =
            load_server_config(&cert_file, &key_file, &[], vec![b"dot".to_vec()]).unwrap();

        let mgr = TlsAcceptorManager::new(config1);
        let initial_config_ref = mgr.current_config();

        // Write new cert
        let (c2, k2) = generate_test_cert(&["reloaded.local"]);
        std::fs::write(&cert_file, c2).unwrap();
        std::fs::write(&key_file, k2).unwrap();

        let config2 =
            load_server_config(&cert_file, &key_file, &[], vec![b"dot".to_vec()]).unwrap();

        mgr.reload(config2);

        // Active connection reference still valid and distinct
        let new_config_ref = mgr.current_config();
        assert!(!Arc::ptr_eq(&initial_config_ref, &new_config_ref));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Minimal `tracing::Subscriber` that records error-level events, so the
    /// watcher's loud failure logging can be asserted without adding a logging
    /// test dependency.
    #[derive(Clone, Default)]
    struct ErrorLog {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl ErrorLog {
        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    /// Renders all of an event's fields into a string.
    struct FieldCollector<'a>(&'a mut String);

    impl tracing::field::Visit for FieldCollector<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            let _ = write!(self.0, "{field}={value:?}");
        }
    }

    impl tracing::subscriber::Subscriber for ErrorLog {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() == tracing::Level::ERROR
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() != tracing::Level::ERROR {
                return;
            }
            let mut fields = String::new();
            event.record(&mut FieldCollector(&mut fields));
            self.events
                .lock()
                .unwrap()
                .push(format!("{}: {fields}", event.metadata().target()));
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// Waits until the manager's config `Arc` is replaced, failing the test
    /// after a bounded timeout.
    async fn wait_for_reload(
        mgr: &TlsAcceptorManager,
        previous: &Arc<ServerConfig>,
    ) -> Arc<ServerConfig> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let current = mgr.current_config();
            if !Arc::ptr_eq(previous, &current) {
                return current;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "TLS certificate reload did not happen within 5s"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn start_test_watcher(
        name: &str,
    ) -> (PathBuf, PathBuf, PathBuf, TlsAcceptorManager, CertWatcher) {
        let temp_dir = create_test_dir(name);
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");
        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);
        std::fs::write(&cert_file, cert_pem).unwrap();
        std::fs::write(&key_file, key_pem).unwrap();

        let config = load_server_config(&cert_file, &key_file, &[], vec![b"dot".to_vec()]).unwrap();
        let mgr = TlsAcceptorManager::new(config);
        let watcher = CertWatcher::start(
            &cert_file,
            &key_file,
            &[],
            &[b"dot".to_vec()],
            mgr.clone(),
            None,
        )
        .unwrap();
        (temp_dir, cert_file, key_file, mgr, watcher)
    }

    /// A successful certificate reload must notify readiness immediately, not
    /// only on the next health probe. The server passes a callback that
    /// refreshes the TLS reason after a hot-reloaded replacement.
    #[tokio::test]
    async fn test_cert_watcher_invokes_reload_callback() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let temp_dir = create_test_dir("watch_callback");
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");
        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);
        std::fs::write(&cert_file, cert_pem).unwrap();
        std::fs::write(&key_file, key_pem).unwrap();

        let config = load_server_config(&cert_file, &key_file, &[], vec![b"dot".to_vec()]).unwrap();
        let mgr = TlsAcceptorManager::new(config);
        let reloads = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reloads);
        let _watcher = CertWatcher::start(
            &cert_file,
            &key_file,
            &[],
            &[b"dot".to_vec()],
            mgr,
            Some(Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            })),
        )
        .unwrap();

        let (replacement_cert, replacement_key) = generate_test_cert(&["replaced.local"]);
        std::fs::write(&cert_file, replacement_cert).unwrap();
        std::fs::write(&key_file, replacement_key).unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while reloads.load(Ordering::SeqCst) == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the watcher did not invoke its reload callback within 5s"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Regression: the watcher must only react to the configured certificate
    /// files. The previous implementation watched the whole parent directory
    /// and reloaded when any file there was created or modified.
    #[tokio::test]
    async fn test_cert_watcher_ignores_unrelated_directory_changes() {
        let (temp_dir, _cert_file, _key_file, mgr, _watcher) =
            start_test_watcher("watch_unrelated");

        let before = mgr.current_config();
        std::fs::write(temp_dir.join("unrelated.txt"), b"hello").unwrap();
        std::fs::write(temp_dir.join("unrelated.pem"), b"world").unwrap();

        // Longer than the 200 ms reload debounce.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(
            Arc::ptr_eq(&before, &mgr.current_config()),
            "unrelated files in the certificate directory must not trigger a reload"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Behavior preserved from the previous watcher: an atomic replacement
    /// (temp file + rename) must trigger a reload, and a later in-place edit
    /// must too. On Linux the directory watch also reports child events, so
    /// this test passes with the old directory-only logic as well; the
    /// regression tests for the rework are the path-filtering and
    /// error-logging ones above/below.
    #[tokio::test]
    async fn test_cert_watcher_reloads_on_atomic_rename_and_later_in_place_edit() {
        let (temp_dir, cert_file, key_file, mgr, _watcher) = start_test_watcher("watch_rename");

        let before = mgr.current_config();

        let (c2, k2) = generate_test_cert(&["replaced.local"]);
        std::fs::write(temp_dir.join("cert.pem.tmp"), c2).unwrap();
        std::fs::write(temp_dir.join("key.pem.tmp"), k2).unwrap();
        std::fs::rename(temp_dir.join("cert.pem.tmp"), &cert_file).unwrap();
        std::fs::rename(temp_dir.join("key.pem.tmp"), &key_file).unwrap();

        let after_rename = wait_for_reload(&mgr, &before).await;

        let (c3, k3) = generate_test_cert(&["in-place.local"]);
        std::fs::write(&cert_file, c3).unwrap();
        std::fs::write(&key_file, k3).unwrap();

        let after_edit = wait_for_reload(&mgr, &after_rename).await;
        assert!(!Arc::ptr_eq(&after_rename, &after_edit));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Regression: a failed `watch()` used to be silently ignored, so a
    /// disabled certificate reload was invisible. It must be logged at `error`
    /// level; startup still succeeds and the previous config stays active.
    #[tokio::test]
    async fn test_cert_watcher_logs_setup_errors() {
        let logs = ErrorLog::default();
        let _guard = tracing::subscriber::set_default(logs.clone());

        let temp_dir = create_test_dir("watch_log");
        let cert_file = temp_dir.join("cert.pem");
        let key_file = temp_dir.join("key.pem");
        let (cert_pem, key_pem) = generate_test_cert(&["localhost"]);
        std::fs::write(&cert_file, cert_pem).unwrap();
        std::fs::write(&key_file, key_pem).unwrap();
        let config = load_server_config(&cert_file, &key_file, &[], vec![b"dot".to_vec()]).unwrap();
        let mgr = TlsAcceptorManager::new(config);

        // Point the watcher at a directory that does not exist: every watch
        // registration fails.
        let missing = temp_dir.join("missing");
        let watcher = CertWatcher::start(
            &missing.join("cert.pem"),
            &missing.join("key.pem"),
            &[],
            &[b"dot".to_vec()],
            mgr,
            None,
        );
        assert!(
            watcher.is_ok(),
            "watcher startup must not fail when watches cannot be registered"
        );
        drop(watcher);

        let errors = logs.events();
        assert!(
            errors.iter().any(|e| e.starts_with("sito_transport::tls")),
            "expected an error-level log for the failed watch, got {errors:?}"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
