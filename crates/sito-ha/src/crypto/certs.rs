//! Certificate generation for High Availability (HA) mutual TLS.
//!
//! Generates self-signed CA, master server cert/key, and slave client cert/key
//! using `rcgen`, and computes BLAKE3 fingerprints for certificate pinning.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use crate::error::HaError;

/// Information about generated certificates and their BLAKE3 pinning fingerprints.
#[derive(Debug, Clone)]
pub struct GeneratedCerts {
    pub ca_cert_path: PathBuf,
    pub ca_cert_pem: String,
    pub ca_key_path: PathBuf,
    pub ca_key_pem: String,
    pub master_cert_path: Option<PathBuf>,
    pub master_cert_pem: Option<String>,
    pub master_fingerprint: Option<String>,
    pub master_key_path: Option<PathBuf>,
    pub master_key_pem: Option<String>,
    pub slave_cert_path: Option<PathBuf>,
    pub slave_cert_pem: Option<String>,
    pub slave_fingerprint: Option<String>,
    pub slave_key_path: Option<PathBuf>,
    pub slave_key_pem: Option<String>,
}

impl GeneratedCerts {
    /// Generates human-readable setup instructions showing config snippets with fingerprints.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "=== sito HA mTLS Certificates Generated Successfully ===\n"
        );
        let _ = writeln!(out, "CA Certificate: {}", self.ca_cert_path.display());
        let _ = writeln!(out, "CA Private Key: {}\n", self.ca_key_path.display());

        if let (Some(cert), Some(fp)) = (&self.master_cert_path, &self.master_fingerprint) {
            let _ = writeln!(out, "--- Master Node Configuration ---");
            let _ = writeln!(out, "Certificate: {}", cert.display());
            let _ = writeln!(
                out,
                "Key:         {}",
                self.master_key_path.as_ref().unwrap().display()
            );
            let _ = writeln!(out, "Fingerprint: {fp}\n");
            let _ = writeln!(out, "Paste into master config.toml:");
            let _ = writeln!(out, "[ha]");
            let _ = writeln!(out, "replication_port = 8953");
            let _ = writeln!(out, "cert = \"{}\"", cert.display());
            let _ = writeln!(
                out,
                "key = \"{}\"",
                self.master_key_path.as_ref().unwrap().display()
            );
            let _ = writeln!(out, "ca = \"{}\"\n", self.ca_cert_path.display());
        }

        if let (Some(cert), Some(fp)) = (&self.slave_cert_path, &self.slave_fingerprint) {
            let _ = writeln!(out, "--- Slave Node Configuration ---");
            let _ = writeln!(out, "Certificate: {}", cert.display());
            let _ = writeln!(
                out,
                "Key:         {}",
                self.slave_key_path.as_ref().unwrap().display()
            );
            let _ = writeln!(out, "Fingerprint: {fp}\n");
            let _ = writeln!(out, "Paste into slave config.toml:");
            let _ = writeln!(out, "[ha]");
            let _ = writeln!(out, "master_url = \"wss://<MASTER_IP>:8953\"");
            if let Some(mfp) = &self.master_fingerprint {
                let _ = writeln!(out, "master_fingerprint = \"{mfp}\"");
            }
            let _ = writeln!(out, "cert = \"{}\"", cert.display());
            let _ = writeln!(
                out,
                "key = \"{}\"",
                self.slave_key_path.as_ref().unwrap().display()
            );
            let _ = writeln!(out, "ca = \"{}\"", self.ca_cert_path.display());
        }

        out
    }
}

/// Computes the BLAKE3 fingerprint of a DER-encoded certificate, prefixed with `blake3:`.
pub fn compute_blake3_fingerprint(cert_der: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(cert_der).to_hex())
}

/// Computes the raw hex BLAKE3 fingerprint of a DER-encoded certificate.
pub fn compute_blake3_raw_hex(cert_der: &[u8]) -> String {
    blake3::hash(cert_der).to_hex().to_string()
}

/// Generates self-signed CA, master and/or slave certificates, writing them to `dir`.
/// If both `gen_master` and `gen_slave` are false, generates the complete set (both).
pub fn generate_ha_certs(
    dir: &Path,
    mut gen_master: bool,
    mut gen_slave: bool,
) -> Result<GeneratedCerts, HaError> {
    if !gen_master && !gen_slave {
        gen_master = true;
        gen_slave = true;
    }

    std::fs::create_dir_all(dir)?;

    let ca_cert_path = dir.join("ca.crt");
    let ca_key_path = dir.join("ca.key");

    // Check if CA already exists; if not, create new CA
    let (ca_cert_pem, ca_key_pem, ca_params, ca_key) =
        if ca_cert_path.exists() && ca_key_path.exists() {
            let cert_pem = std::fs::read_to_string(&ca_cert_path)?;
            let key_pem = std::fs::read_to_string(&ca_key_path)?;
            let ca_key = KeyPair::from_pem(&key_pem).map_err(|e| {
                HaError::Crypto(format!("Failed to parse existing CA private key: {e}"))
            })?;
            let mut ca_params = CertificateParams::default();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "sito-ha-ca");
            ca_params.distinguished_name = dn;
            (cert_pem, key_pem, ca_params, ca_key)
        } else {
            let mut ca_params = CertificateParams::default();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "sito-ha-ca");
            ca_params.distinguished_name = dn;

            let ca_key = KeyPair::generate()
                .map_err(|e| HaError::Crypto(format!("Failed to generate CA keypair: {e}")))?;
            let ca_cert = ca_params.self_signed(&ca_key).map_err(|e| {
                HaError::Crypto(format!("Failed to generate self-signed CA cert: {e}"))
            })?;

            let cert_pem = ca_cert.pem();
            let key_pem = ca_key.serialize_pem();

            std::fs::write(&ca_cert_path, &cert_pem)?;
            write_private_key_file(&ca_key_path, &key_pem)?;

            (cert_pem, key_pem, ca_params, ca_key)
        };

    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let (master_cert_path, master_cert_pem, master_fingerprint, master_key_path, master_key_pem) =
        if gen_master {
            let mut master_params =
                CertificateParams::new(vec!["localhost".to_string(), "sito-master".to_string()])
                    .map_err(|e| HaError::Crypto(format!("Master cert params error: {e}")))?;

            master_params
                .subject_alt_names
                .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
            master_params
                .subject_alt_names
                .push(SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)));

            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "sito-master");
            master_params.distinguished_name = dn;
            master_params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            master_params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];

            let master_key = KeyPair::generate()
                .map_err(|e| HaError::Crypto(format!("Failed to generate master keypair: {e}")))?;
            let master_cert = master_params
                .signed_by(&master_key, &issuer)
                .map_err(|e| HaError::Crypto(format!("Failed to sign master certificate: {e}")))?;

            let cert_path = dir.join("master.crt");
            let key_path = dir.join("master.key");
            let cert_pem = master_cert.pem();
            let key_pem = master_key.serialize_pem();
            let fp = compute_blake3_fingerprint(master_cert.der());

            std::fs::write(&cert_path, &cert_pem)?;
            write_private_key_file(&key_path, &key_pem)?;

            (
                Some(cert_path),
                Some(cert_pem),
                Some(fp),
                Some(key_path),
                Some(key_pem),
            )
        } else {
            (None, None, None, None, None)
        };

    let (slave_cert_path, slave_cert_pem, slave_fingerprint, slave_key_path, slave_key_pem) =
        if gen_slave {
            let mut slave_params =
                CertificateParams::new(vec!["localhost".to_string(), "sito-slave".to_string()])
                    .map_err(|e| HaError::Crypto(format!("Slave cert params error: {e}")))?;

            slave_params
                .subject_alt_names
                .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
            slave_params
                .subject_alt_names
                .push(SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)));

            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "sito-slave");
            slave_params.distinguished_name = dn;
            slave_params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            slave_params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ClientAuth,
                ExtendedKeyUsagePurpose::ServerAuth,
            ];

            let slave_key = KeyPair::generate()
                .map_err(|e| HaError::Crypto(format!("Failed to generate slave keypair: {e}")))?;
            let slave_cert = slave_params
                .signed_by(&slave_key, &issuer)
                .map_err(|e| HaError::Crypto(format!("Failed to sign slave certificate: {e}")))?;

            let cert_path = dir.join("slave.crt");
            let key_path = dir.join("slave.key");
            let cert_pem = slave_cert.pem();
            let key_pem = slave_key.serialize_pem();
            let fp = compute_blake3_fingerprint(slave_cert.der());

            std::fs::write(&cert_path, &cert_pem)?;
            write_private_key_file(&key_path, &key_pem)?;

            (
                Some(cert_path),
                Some(cert_pem),
                Some(fp),
                Some(key_path),
                Some(key_pem),
            )
        } else {
            (None, None, None, None, None)
        };

    Ok(GeneratedCerts {
        ca_cert_path,
        ca_cert_pem,
        ca_key_path,
        ca_key_pem,
        master_cert_path,
        master_cert_pem,
        master_fingerprint,
        master_key_path,
        master_key_pem,
        slave_cert_path,
        slave_cert_pem,
        slave_fingerprint,
        slave_key_path,
        slave_key_pem,
    })
}

fn write_private_key_file(path: &Path, content: &str) -> Result<(), HaError> {
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_complete_ha_certs_set() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito_ha_certs_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let certs = generate_ha_certs(&temp_dir, false, false).unwrap();

        assert!(certs.ca_cert_path.exists());
        assert!(certs.ca_key_path.exists());
        assert!(certs.master_cert_path.as_ref().unwrap().exists());
        assert!(certs.master_key_path.as_ref().unwrap().exists());
        assert!(certs.slave_cert_path.as_ref().unwrap().exists());
        assert!(certs.slave_key_path.as_ref().unwrap().exists());

        assert!(
            certs
                .master_fingerprint
                .as_ref()
                .unwrap()
                .starts_with("blake3:")
        );
        assert!(
            certs
                .slave_fingerprint
                .as_ref()
                .unwrap()
                .starts_with("blake3:")
        );

        let summary = certs.summary();
        assert!(summary.contains("sito HA mTLS Certificates"));
        assert!(summary.contains("master_fingerprint"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
