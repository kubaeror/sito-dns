//! Shared TLS certificate fixtures for tests.
//!
//! These are test-only (they live in `sito-test`); nothing here is linked into
//! the production binary. Use [`CertificateFiles`] when a listener needs cert
//! and key files on disk, or [`TestCertificate`] when the PEM strings are
//! enough.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// A generated self-signed certificate and key pair in PEM form.
#[derive(Debug, Clone)]
pub struct TestCertificate {
    /// Certificate chain PEM.
    pub cert_pem: String,
    /// Private key PEM.
    pub key_pem: String,
}

impl TestCertificate {
    /// The PEM pair as `(cert, key)`, matching the historical
    /// `generate_test_cert` return value.
    #[must_use]
    pub fn into_pair(self) -> (String, String) {
        (self.cert_pem, self.key_pem)
    }
}

/// Generates a currently-valid self-signed certificate for `san_domains`.
#[must_use]
pub fn test_certificate(san_domains: &[&str]) -> TestCertificate {
    generate(san_domains, Validity::Valid)
}

/// Generates a certificate that expired in 2020.
#[must_use]
pub fn expired_certificate(san_domains: &[&str]) -> TestCertificate {
    generate(san_domains, Validity::Expired)
}

/// Generates a certificate that expires in `days` days (rounded down).
///
/// Use it for renewal/degraded-readiness tests that must not wait for a real
/// certificate lifetime.
#[must_use]
pub fn soon_to_expire_certificate(san_domains: &[&str], days: i64) -> TestCertificate {
    generate(san_domains, Validity::SoonToExpire(days))
}

#[derive(Debug, Clone, Copy)]
enum Validity {
    Valid,
    Expired,
    SoonToExpire(i64),
}

fn generate(san_domains: &[&str], validity: Validity) -> TestCertificate {
    let key_pair = rcgen::KeyPair::generate().expect("key pair generation");
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(
        rcgen::DnType::CommonName,
        match validity {
            Validity::Expired => "sito-expired.local",
            _ => "sito-test.local",
        },
    );
    params.distinguished_name = dn;
    for san in san_domains {
        params.subject_alt_names.push(rcgen::SanType::DnsName(
            (*san).to_string().try_into().unwrap(),
        ));
    }

    let (not_before, not_after) = match validity {
        Validity::Valid => (
            time::OffsetDateTime::now_utc() - time::Duration::hours(1),
            time::OffsetDateTime::now_utc() + time::Duration::days(365),
        ),
        // 2020-01-01 .. 2020-01-02, matching the historical fixture.
        Validity::Expired => (
            time::OffsetDateTime::from_unix_timestamp(1_577_836_800).unwrap(),
            time::OffsetDateTime::from_unix_timestamp(1_577_923_200).unwrap(),
        ),
        Validity::SoonToExpire(days) => (
            time::OffsetDateTime::now_utc() - time::Duration::hours(1),
            // Keep at least a few minutes so slow CI machines still observe a
            // valid (but soon-to-expire) certificate.
            time::OffsetDateTime::now_utc() + time::Duration::days(days) + time::Duration::hours(1),
        ),
    };
    params.not_before = not_before;
    params.not_after = not_after;

    let cert = params.self_signed(&key_pair).expect("self signed cert");
    TestCertificate {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

/// A temporary directory containing `cert.pem` and `key.pem`.
///
/// The directory is removed on drop. Keep the fixture alive for as long as the
/// listener needs the files.
#[derive(Debug)]
pub struct CertificateFiles {
    dir: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

impl CertificateFiles {
    /// Writes a valid certificate pair for `san_domains` into a fresh
    /// temporary directory.
    pub fn create(label: &str, san_domains: &[&str]) -> std::io::Result<Self> {
        Self::from_certificate(label, test_certificate(san_domains))
    }

    /// Writes an already-expired certificate pair.
    pub fn expired(label: &str, san_domains: &[&str]) -> std::io::Result<Self> {
        Self::from_certificate(label, expired_certificate(san_domains))
    }

    /// Writes a certificate that expires in `days` days.
    pub fn soon_to_expire(label: &str, san_domains: &[&str], days: i64) -> std::io::Result<Self> {
        Self::from_certificate(label, soon_to_expire_certificate(san_domains, days))
    }

    fn from_certificate(label: &str, certificate: TestCertificate) -> std::io::Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "sito_cert_{label}_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir)?;
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, certificate.cert_pem)?;
        std::fs::write(&key, certificate.key_pem)?;
        Ok(Self { dir, cert, key })
    }

    /// Certificate path.
    #[must_use]
    pub fn cert_path(&self) -> &Path {
        &self.cert
    }

    /// Private-key path.
    #[must_use]
    pub fn key_path(&self) -> &Path {
        &self.key
    }

    /// Containing temporary directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Rewrites both files with a new certificate pair.
    pub fn replace(&self, certificate: &TestCertificate) -> std::io::Result<()> {
        std::fs::write(&self.cert, &certificate.cert_pem)?;
        std::fs::write(&self.key, &certificate.key_pem)
    }
}

impl Drop for CertificateFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Returns the certificate readiness in whole days.
///
/// Thin wrapper over the production parser so fixtures assert the same way the
/// runtime classifies renewal.
pub fn days_until_expiration(cert_pem: &str) -> i64 {
    sito_transport::days_until_expiration(cert_pem.as_bytes()).expect("parse fixture certificate")
}

/// Returns the first certificate in a PEM chain as DER bytes.
pub fn first_certificate_der(pem: &[u8]) -> Vec<u8> {
    use rustls::pki_types::pem::PemObject as _;
    rustls::pki_types::CertificateDer::pem_slice_iter(pem)
        .next()
        .expect("certificate in PEM")
        .expect("valid certificate")
        .as_ref()
        .to_vec()
}

/// Builds a [`sito_transport::TlsAcceptorManager`] for tests that need to
/// verify which certificate a transport serves.
///
/// Pass `challenge_keys` to install a TLS-ALPN-01 challenge key map on the
/// manager (the m11 ACME test does this for its DoH manager).
pub fn tls_acceptor_manager(
    cert: &Path,
    key: &Path,
    alpn: &[u8],
    challenge_keys: Option<Arc<dashmap::DashMap<String, Arc<rustls::sign::CertifiedKey>>>>,
) -> sito_transport::TlsAcceptorManager {
    match challenge_keys {
        Some(keys) => sito_transport::TlsAcceptorManager::with_challenge_keys(
            sito_transport::load_server_config_with_challenges(
                cert,
                key,
                &[],
                vec![alpn.to_vec()],
                Arc::clone(&keys),
            )
            .expect("TLS config with challenges"),
            keys,
        ),
        None => sito_transport::TlsAcceptorManager::new(
            sito_transport::load_server_config(cert, key, &[], vec![alpn.to_vec()])
                .expect("TLS config"),
        ),
    }
}

/// Performs a TLS handshake against `manager` and returns the leaf DER
/// certificate it actually served.
pub async fn served_certificate(manager: &sito_transport::TlsAcceptorManager) -> Vec<u8> {
    let (listener, _claim) = crate::fixtures::net::bind_claimed_tcp()
        .await
        .expect("bind handshake listener");
    let addr = listener.local_addr().expect("handshake addr");
    let acceptor = manager.acceptor();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept handshake");
        let _ = acceptor.accept(stream).await;
    });

    let captured = Arc::new(std::sync::Mutex::new(None));
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("safe protocol versions")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(CapturingVerifier(Arc::clone(&captured))))
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect handshake");
    let domain = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let _ = connector.connect(domain, tcp).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;

    captured
        .lock()
        .expect("capture lock")
        .clone()
        .expect("server presented a certificate")
}

#[derive(Debug)]
struct CapturingVerifier(Arc<std::sync::Mutex<Option<Vec<u8>>>>);

impl rustls::client::danger::ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self.0.lock().expect("capture lock") = Some(end_entity.as_ref().to_vec());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
