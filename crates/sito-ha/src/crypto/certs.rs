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

/// Ownership applied to generated certificate and private-key files.
///
/// HA runtimes are unprivileged (`sito` under systemd, uid/gid `65532` in the
/// container image). Generating the keys as root without transferring them
/// leaves them unreadable by the runtime, which disables the replication
/// listener without affecting DNS health. `--uid/--gid` makes the handover
/// explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertOwnership {
    pub uid: u32,
    pub gid: u32,
}

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

/// Appends user-provided SANs (IP addresses or DNS names) to certificate params.
fn append_extra_sans(
    params: &mut CertificateParams,
    extra_sans: &[String],
    role: &str,
) -> Result<(), HaError> {
    for san in extra_sans {
        let trimmed = san.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            params.subject_alt_names.push(SanType::IpAddress(ip));
        } else {
            let dns: rcgen::string::Ia5String = trimmed.try_into().map_err(|e| {
                HaError::Crypto(format!("Invalid {role} certificate SAN '{trimmed}': {e}"))
            })?;
            params.subject_alt_names.push(SanType::DnsName(dns));
        }
    }
    Ok(())
}

/// Generates self-signed CA, master and/or slave certificates, writing them to `dir`.
/// If both `gen_master` and `gen_slave` are false, generates the complete set (both).
pub fn generate_ha_certs(
    dir: &Path,
    gen_master: bool,
    gen_slave: bool,
) -> Result<GeneratedCerts, HaError> {
    generate_ha_certs_with_options(dir, gen_master, gen_slave, &[], None)
}

/// Like [`generate_ha_certs`], with additional subject alternative names
/// applied to both the master and slave certificates. Each entry is parsed as
/// an IP address first and otherwise added as a DNS name.
pub fn generate_ha_certs_with_sans(
    dir: &Path,
    gen_master: bool,
    gen_slave: bool,
    extra_sans: &[String],
) -> Result<GeneratedCerts, HaError> {
    generate_ha_certs_with_options(dir, gen_master, gen_slave, extra_sans, None)
}

/// Like [`generate_ha_certs_with_sans`], additionally transferring every
/// generated file (certificates and private keys) to `ownership`.
///
/// The chown happens only after all files are written, so a failed ownership
/// transfer leaves the keys owner-only under the invoking user and returns an
/// error instead of starting a node with unreadable keys.
pub fn generate_ha_certs_with_options(
    dir: &Path,
    mut gen_master: bool,
    mut gen_slave: bool,
    extra_sans: &[String],
    ownership: Option<CertOwnership>,
) -> Result<GeneratedCerts, HaError> {
    if ownership.is_some() && !cfg!(unix) {
        return Err(HaError::Validation {
            field: "uid".to_string(),
            reason: "certificate ownership transfer is only supported on Unix".to_string(),
        });
    }
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
            append_extra_sans(&mut master_params, extra_sans, "master")?;

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
            append_extra_sans(&mut slave_params, extra_sans, "slave")?;

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

    let certs = GeneratedCerts {
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
    };

    if let Some(owner) = ownership {
        transfer_ownership(&certs, owner)?;
    }

    Ok(certs)
}

/// Transfers every generated certificate and key file to `ownership`.
///
/// Certificates are included so a restrictive umask cannot leave the public
/// certificate unreadable by the runtime user either. Failure is fatal: a
/// silently skipped chown would recreate the original bug.
#[cfg(unix)]
fn transfer_ownership(certs: &GeneratedCerts, owner: CertOwnership) -> Result<(), HaError> {
    use std::os::unix::fs::chown;

    let mut paths: Vec<&Path> = vec![&certs.ca_cert_path, &certs.ca_key_path];
    for path in [
        certs.master_cert_path.as_deref(),
        certs.master_key_path.as_deref(),
        certs.slave_cert_path.as_deref(),
        certs.slave_key_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        paths.push(path);
    }

    for path in paths {
        chown(path, Some(owner.uid), Some(owner.gid)).map_err(|e| {
            HaError::Crypto(format!(
                "Failed to chown '{}' to {}:{}: {e}. Run gen-certs as root (or the file owner) to transfer certificate ownership to the runtime user",
                path.display(),
                owner.uid,
                owner.gid
            ))
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn transfer_ownership(_certs: &GeneratedCerts, _owner: CertOwnership) -> Result<(), HaError> {
    Err(HaError::Validation {
        field: "uid".to_string(),
        reason: "certificate ownership transfer is only supported on Unix".to_string(),
    })
}

fn write_private_key_file(path: &Path, content: &str) -> Result<(), HaError> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        // The mode is applied at creation time so the private key is never
        // observable with wider permissions (no write-then-chmod window).
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content)?;
    }

    // Repair a pre-existing file created outside this code path.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        if perms.mode() & 0o777 != 0o600 {
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
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

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for key_path in [
                certs.ca_key_path.as_path(),
                certs.master_key_path.as_ref().unwrap().as_path(),
                certs.slave_key_path.as_ref().unwrap().as_path(),
            ] {
                let mode = std::fs::metadata(key_path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{} must be 0600", key_path.display());
            }
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// `gen-certs --uid/--gid` must hand the generated files to the runtime
    /// user. The test runs as either root (chown succeeds) or an unprivileged
    /// user (chown to another uid must fail loudly instead of being ignored).
    #[cfg(unix)]
    #[test]
    fn test_generate_ha_certs_applies_requested_ownership() {
        use std::os::unix::fs::MetadataExt as _;

        let temp_dir = std::env::temp_dir().join(format!(
            "sito_ha_owner_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));

        // Discover the invoking uid/gid from a file we own.
        std::fs::create_dir_all(&temp_dir).unwrap();
        let probe = temp_dir.join("probe");
        std::fs::write(&probe, b"x").unwrap();
        let probe_meta = std::fs::metadata(&probe).unwrap();
        let euid = probe_meta.uid();
        let egid = probe_meta.gid();

        // Own uid/gid always succeeds and must be reflected on every file.
        let certs = generate_ha_certs_with_options(
            &temp_dir,
            true,
            true,
            &[],
            Some(CertOwnership {
                uid: euid,
                gid: egid,
            }),
        )
        .expect("owning generated files to the invoking user must succeed");
        for path in [
            certs.ca_cert_path.as_path(),
            certs.ca_key_path.as_path(),
            certs.master_cert_path.as_ref().unwrap().as_path(),
            certs.master_key_path.as_ref().unwrap().as_path(),
            certs.slave_cert_path.as_ref().unwrap().as_path(),
            certs.slave_key_path.as_ref().unwrap().as_path(),
        ] {
            let meta = std::fs::metadata(path).unwrap();
            assert_eq!(meta.uid(), euid, "{} uid", path.display());
            assert_eq!(meta.gid(), egid, "{} gid", path.display());
        }

        let _ = std::fs::remove_dir_all(&temp_dir);

        // A different owner is only possible for a privileged caller. Either
        // way the request must be honored or rejected; it must never be
        // silently ignored.
        let foreign_dir = std::env::temp_dir().join(format!(
            "sito_ha_owner_foreign_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let result = generate_ha_certs_with_options(
            &foreign_dir,
            true,
            true,
            &[],
            Some(CertOwnership {
                uid: 65532,
                gid: 65532,
            }),
        );
        if euid == 0 {
            let certs = result.expect("root must be able to chown generated keys");
            let meta = std::fs::metadata(certs.master_key_path.as_ref().unwrap()).unwrap();
            assert_eq!(meta.uid(), 65532);
            assert_eq!(meta.gid(), 65532);
        } else {
            let err = result.expect_err("unprivileged chown to another uid must fail");
            assert!(
                err.to_string().contains("chown"),
                "error must name the failed chown: {err}"
            );
        }
        let _ = std::fs::remove_dir_all(&foreign_dir);
    }

    #[test]
    fn test_generate_ha_certs_without_ownership_keeps_invoking_owner() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            let temp_dir = std::env::temp_dir().join(format!(
                "sito_ha_no_owner_test_{}_{}",
                std::process::id(),
                rand::random::<u32>()
            ));
            let certs = generate_ha_certs_with_options(&temp_dir, true, true, &[], None).unwrap();
            let probe = temp_dir.join("probe");
            std::fs::write(&probe, b"x").unwrap();
            let euid = std::fs::metadata(&probe).unwrap().uid();
            assert_eq!(
                std::fs::metadata(certs.master_key_path.as_ref().unwrap())
                    .unwrap()
                    .uid(),
                euid,
                "omitting --uid must not change ownership"
            );
            let _ = std::fs::remove_dir_all(&temp_dir);
        }
    }

    #[test]
    fn test_generate_ha_certs_with_extra_sans() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito_ha_san_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let sans = vec!["10.20.30.40".to_string(), "dns.example.lan".to_string()];
        let certs = generate_ha_certs_with_sans(&temp_dir, true, true, &sans).unwrap();
        assert!(certs.master_cert_path.as_ref().unwrap().exists());
        assert!(certs.slave_cert_path.as_ref().unwrap().exists());

        // Blank entries are ignored rather than failing generation.
        generate_ha_certs_with_sans(&temp_dir, true, false, &["  ".to_string()]).unwrap();

        // Non-ASCII DNS names cannot be encoded and must be rejected.
        let bad = generate_ha_certs_with_sans(&temp_dir, true, false, &["münchen.de".to_string()]);
        assert!(bad.is_err(), "invalid SAN must fail certificate generation");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
