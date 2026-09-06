//! Mutual TLS (mTLS) configuration and certificate pinning verifiers.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as RustlsError, SignatureScheme};
use std::path::Path;
use std::sync::Arc;

use crate::error::HaError;

/// Load certificates from a PEM file.
pub fn load_certs_pem(path: &Path) -> Result<Vec<CertificateDer<'static>>, HaError> {
    let bytes = std::fs::read(path).map_err(|e| {
        HaError::Tls(format!(
            "Failed to read certificate file '{}': {e}",
            path.display()
        ))
    })?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            HaError::Tls(format!(
                "Failed to parse PEM certificate '{}': {e}",
                path.display()
            ))
        })?;
    if certs.is_empty() {
        return Err(HaError::Tls(format!(
            "Certificate file '{}' contains no valid certificates",
            path.display()
        )));
    }
    Ok(certs)
}

/// Load private key from a PEM file.
pub fn load_key_pem(path: &Path) -> Result<PrivateKeyDer<'static>, HaError> {
    let bytes = std::fs::read(path).map_err(|e| {
        HaError::Tls(format!(
            "Failed to read private key file '{}': {e}",
            path.display()
        ))
    })?;
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|e| {
        HaError::Tls(format!(
            "Failed to parse private key '{}': {e}",
            path.display()
        ))
    })
}

fn normalize_fingerprint(fp: &str) -> String {
    fp.trim().trim_start_matches("blake3:").to_lowercase()
}

/// A server-side client certificate verifier enforcing BLAKE3 fingerprint pinning.
#[derive(Debug)]
pub struct PinnedClientCertVerifier {
    pinned_fingerprints: Vec<String>,
}

impl PinnedClientCertVerifier {
    pub fn new(pinned: &[String]) -> Self {
        Self {
            pinned_fingerprints: pinned.iter().map(|s| normalize_fingerprint(s)).collect(),
        }
    }
}

impl ClientCertVerifier for PinnedClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        if self.pinned_fingerprints.is_empty() {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

        let cert_fp = blake3::hash(end_entity.as_ref())
            .to_hex()
            .to_string()
            .to_lowercase();

        if !self.pinned_fingerprints.contains(&cert_fp) {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A client-side server certificate verifier enforcing BLAKE3 fingerprint pinning of the master node.
#[derive(Debug)]
pub struct PinnedServerCertVerifier {
    pinned_fingerprint: Option<String>,
    allow_unpinned: bool,
}

impl PinnedServerCertVerifier {
    pub fn new(pinned: Option<&str>, allow_unpinned: bool) -> Self {
        Self {
            pinned_fingerprint: pinned.map(normalize_fingerprint),
            allow_unpinned,
        }
    }
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let cert_fp = blake3::hash(end_entity.as_ref())
            .to_hex()
            .to_string()
            .to_lowercase();

        if let Some(ref expected_fp) = self.pinned_fingerprint {
            if &cert_fp != expected_fp {
                return Err(RustlsError::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
        } else if !self.allow_unpinned {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Constructs a `rustls::ServerConfig` for the master WebSocket replication listener.
pub fn build_server_tls_config(
    cert_path: &Path,
    key_path: &Path,
    pinned_slave_fingerprints: &[String],
) -> Result<Arc<rustls::ServerConfig>, HaError> {
    let certs = load_certs_pem(cert_path)?;
    let key = load_key_pem(key_path)?;

    let client_verifier = Arc::new(PinnedClientCertVerifier::new(pinned_slave_fingerprints));

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|e| HaError::Tls(format!("Failed to configure TLS versions: {e}")))?
    .with_client_cert_verifier(client_verifier)
    .with_single_cert(certs, key)
    .map_err(|e| HaError::Tls(format!("Failed to set master certificate and key: {e}")))?;

    Ok(Arc::new(config))
}

/// Constructs a `rustls::ClientConfig` for the slave connecting to the master WebSocket endpoint.
pub fn build_client_tls_config(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    master_fingerprint: Option<&str>,
    allow_unpinned_tls: bool,
) -> Result<Arc<rustls::ClientConfig>, HaError> {
    if master_fingerprint.is_none() && !allow_unpinned_tls {
        return Err(HaError::Tls(
            "TLS connection requires master_fingerprint for certificate pinning unless allow_unpinned_tls = true".to_string(),
        ));
    }

    let server_verifier = Arc::new(PinnedServerCertVerifier::new(
        master_fingerprint,
        allow_unpinned_tls,
    ));

    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|e| HaError::Tls(format!("Failed to configure TLS versions: {e}")))?
    .dangerous()
    .with_custom_certificate_verifier(server_verifier);

    let config = if let (Some(cp), Some(kp)) = (cert_path, key_path) {
        let certs = load_certs_pem(cp)?;
        let key = load_key_pem(kp)?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| HaError::Tls(format!("Failed to set client certificate: {e}")))?
    } else {
        builder.with_no_client_auth()
    };

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_client_cert_verifier_rejects_empty_pins() {
        let verifier = PinnedClientCertVerifier::new(&[]);
        let dummy_cert = CertificateDer::from(vec![1, 2, 3, 4]);
        let now = rustls::pki_types::UnixTime::now();
        let res = verifier.verify_client_cert(&dummy_cert, &[], now);
        assert!(res.is_err());
    }

    #[test]
    fn test_pinned_client_cert_verifier_matching_and_mismatch() {
        let dummy_cert = CertificateDer::from(vec![1, 2, 3, 4]);
        let fp = blake3::hash(dummy_cert.as_ref()).to_hex().to_string();
        let now = rustls::pki_types::UnixTime::now();

        // Matching pin
        let verifier = PinnedClientCertVerifier::new(&[fp]);
        assert!(verifier.verify_client_cert(&dummy_cert, &[], now).is_ok());

        // Mismatch pin
        let verifier_mismatch = PinnedClientCertVerifier::new(&["blake3:99999999".to_string()]);
        assert!(
            verifier_mismatch
                .verify_client_cert(&dummy_cert, &[], now)
                .is_err()
        );
    }
}
