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
use std::sync::Arc;
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

/// Generates a self-signed certificate and private key pair for the given domain names.
pub fn generate_self_signed_cert(domains: &[String]) -> Result<(String, String), TlsError> {
    let params = rcgen::CertificateParams::new(domains.to_vec())
        .map_err(|e| TlsError::Config(format!("Failed to build certificate params: {e}")))?;
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
}

impl TlsAcceptorManager {
    /// Create a new manager initialized with a `ServerConfig`.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            server_config: Arc::new(ArcSwap::from_pointee(config)),
            challenge_keys: Arc::new(dashmap::DashMap::new()),
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
        }
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

    /// Obtain a `TlsAcceptor` configured with the latest `ServerConfig`.
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.current_config())
    }

    /// Atomically replace the running `ServerConfig` without interrupting active connections.
    pub fn reload(&self, new_config: ServerConfig) {
        self.server_config.store(Arc::new(new_config));
        info!("TLS server configuration reloaded successfully");
    }
}

/// Filesystem watcher that automatically reloads TLS certificates on modification.
pub struct CertWatcher {
    _watcher: RecommendedWatcher,
}

impl CertWatcher {
    /// Start watching certificate and key files for changes and automatically reload the acceptor.
    pub fn start(
        cert_path: &Path,
        key_path: &Path,
        sni_certs: &[(String, PathBuf, PathBuf)],
        alpn_protocols: &[Vec<u8>],
        acceptor_mgr: TlsAcceptorManager,
    ) -> Result<Self, TlsError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res
                    && (event.kind.is_modify() || event.kind.is_create())
                {
                    let _ = tx.blocking_send(());
                }
            },
            notify::Config::default(),
        )
        .map_err(|e| TlsError::Watch(e.to_string()))?;

        // Watch parent directory of cert and key
        if let Some(parent) = cert_path.parent() {
            let _ = watcher.watch(parent, RecursiveMode::NonRecursive);
        } else {
            let _ = watcher.watch(cert_path, RecursiveMode::NonRecursive);
        }
        if let Some(parent) = key_path.parent() {
            let _ = watcher.watch(parent, RecursiveMode::NonRecursive);
        } else {
            let _ = watcher.watch(key_path, RecursiveMode::NonRecursive);
        }

        for (_, sni_cert, sni_key) in sni_certs {
            if let Some(parent) = sni_cert.parent() {
                let _ = watcher.watch(parent, RecursiveMode::NonRecursive);
            }
            if let Some(parent) = sni_key.parent() {
                let _ = watcher.watch(parent, RecursiveMode::NonRecursive);
            }
        }

        let cert_path_clone = cert_path.to_path_buf();
        let key_path_clone = key_path.to_path_buf();
        let sni_certs_clone = sni_certs.to_vec();
        let alpn_clone = alpn_protocols.to_vec();

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

                match load_server_config(
                    &cert_path_clone,
                    &key_path_clone,
                    &sni_certs_clone,
                    alpn_clone.clone(),
                ) {
                    Ok(new_config) => {
                        acceptor_mgr.reload(new_config);
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
        assert!(!acceptor_mgr.current_config().alpn_protocols.is_empty());
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
}
