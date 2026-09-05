//! ACME (RFC 8555) automatic TLS certificate management for sito.
//!
//! Provides automatic certificate issuance and renewal via Let's Encrypt
//! (or custom/staging ACME directories), supporting:
//! - TLS-ALPN-01 (RFC 8737) challenges directly via `DynamicCertResolver` on port 443
//! - HTTP-01 fallback challenges via `DohConfig::http01_challenges`
//! - Account and certificate persistence in `<data_dir>/acme/`
//! - Background renewal ticker (renewing 30 days before expiration)
//! - Zero-downtime certificate reloading via `TlsAcceptorManager`

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    RetryPolicy,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::{debug, error, info, warn};

use crate::tls::{TlsAcceptorManager, create_certified_key, load_server_config};

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
        let creds_data = std::fs::read_to_string(&creds_file)
            .map_err(|e| format!("Failed to read account credentials file: {e}"))?;
        let creds: AccountCredentials = serde_json::from_str(&creds_data)
            .map_err(|e| format!("Failed to deserialize account credentials: {e}"))?;
        let account = Account::builder()
            .map_err(|e| format!("Failed to build account client: {e}"))?
            .from_credentials(creds)
            .await
            .map_err(|e| format!("Failed to restore account from credentials: {e}"))?;
        return Ok(account);
    }

    info!(
        "Registering new ACME account for {} at {}",
        config.email, directory_url
    );
    let new_account = NewAccount {
        contact: &[&format!("mailto:{}", config.email)],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    let (account, creds) = Account::builder()
        .map_err(|e| format!("Failed to build account client: {e}"))?
        .create(&new_account, directory_url.to_string(), None)
        .await
        .map_err(|e| format!("Failed to create ACME account: {e}"))?;

    let serialized = serde_json::to_string_pretty(&creds)
        .map_err(|e| format!("Failed to serialize account credentials: {e}"))?;

    let _ = std::fs::create_dir_all(&config.storage_dir);
    std::fs::write(&creds_file, serialized).map_err(|e| {
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

/// Check whether the current certificate on disk needs to be acquired or renewed.
pub fn certificate_needs_renewal(config: &AcmeServiceConfig) -> bool {
    let cert_path = config.storage_dir.join("cert.pem");
    let key_path = config.storage_dir.join("key.pem");

    if !cert_path.exists() || !key_path.exists() {
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

/// Obtain a new certificate or renew an existing certificate via ACME protocol.
///
/// Returns `Ok(true)` if a certificate was issued/renewed and reloaded,
/// or `Ok(false)` if the current certificate is already valid and not expiring soon.
pub async fn obtain_or_renew_certificate(
    config: &AcmeServiceConfig,
    acceptor_mgr: Option<&TlsAcceptorManager>,
    http01_challenges: Option<&Arc<dashmap::DashMap<String, String>>>,
    alpn_protocols: &[Vec<u8>],
) -> Result<bool, String> {
    if !certificate_needs_renewal(config) {
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

    let mut registered_alpn_challenges = Vec::new();
    let mut registered_http_challenges = Vec::new();

    // Process authorizations and set up challenge responses
    {
        let mut authorizations = order.authorizations();
        while let Some(auth_res) = authorizations.next().await {
            let mut auth = auth_res.map_err(|e| format!("Failed to fetch authorization: {e}"))?;
            let domain = match auth.identifier().identifier {
                Identifier::Dns(d) => d.clone(),
                _ => auth.identifier().to_string(),
            };

            // Select challenge type (prefer TLS-ALPN-01 if acceptor_mgr is available, fallback to HTTP-01)
            let selected_challenge = if acceptor_mgr.is_some()
                && auth
                    .challenges
                    .iter()
                    .any(|c| c.r#type == ChallengeType::TlsAlpn01)
            {
                ChallengeType::TlsAlpn01
            } else if http01_challenges.is_some()
                && auth
                    .challenges
                    .iter()
                    .any(|c| c.r#type == ChallengeType::Http01)
            {
                ChallengeType::Http01
            } else {
                return Err(format!(
                    "No supported challenge type available for domain '{domain}'"
                ));
            };

            match selected_challenge {
                ChallengeType::TlsAlpn01 => {
                    let mgr = acceptor_mgr.unwrap();
                    let mut challenge = auth
                        .challenge(ChallengeType::TlsAlpn01)
                        .ok_or_else(|| format!("TLS-ALPN-01 challenge missing for {domain}"))?;

                    let key_auth = challenge.key_authorization();
                    let (cert_der, priv_der) =
                        generate_tls_alpn_01_cert(&domain, key_auth.as_str())?;

                    let certified_key = create_certified_key(vec![cert_der], &priv_der)
                        .map_err(|e| format!("Failed to create challenge CertifiedKey: {e}"))?;

                    mgr.register_challenge(&domain, certified_key);
                    registered_alpn_challenges.push(domain.clone());

                    challenge
                        .set_ready()
                        .await
                        .map_err(|e| format!("Failed to set TLS-ALPN-01 challenge ready: {e}"))?;
                    debug!("Registered TLS-ALPN-01 challenge for {}", domain);
                }
                ChallengeType::Http01 => {
                    let challenges_map = http01_challenges.unwrap();
                    let mut challenge = auth
                        .challenge(ChallengeType::Http01)
                        .ok_or_else(|| format!("HTTP-01 challenge missing for {domain}"))?;

                    let key_auth = challenge.key_authorization();
                    let token = challenge.token.clone();

                    challenges_map.insert(token.clone(), key_auth.as_str().to_string());
                    registered_http_challenges.push(token);

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

    // Wait for the order to transition to Ready
    let retry_policy = RetryPolicy::default().timeout(Duration::from_secs(90));
    let order_status = order
        .poll_ready(&retry_policy)
        .await
        .map_err(|e| format!("Error waiting for ACME order to become ready: {e}"))?;

    // Cleanup challenge state
    if let Some(mgr) = acceptor_mgr {
        for domain in &registered_alpn_challenges {
            mgr.unregister_challenge(domain);
        }
    }
    if let Some(challenges_map) = http01_challenges {
        for token in &registered_http_challenges {
            challenges_map.remove(token);
        }
    }

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
    let _ = std::fs::create_dir_all(&config.storage_dir);
    let cert_path = config.storage_dir.join("cert.pem");
    let key_path = config.storage_dir.join("key.pem");

    std::fs::write(&cert_path, &cert_chain_pem)
        .map_err(|e| format!("Failed to write cert.pem to {}: {e}", cert_path.display()))?;
    std::fs::write(&key_path, &private_key_pem)
        .map_err(|e| format!("Failed to write key.pem to {}: {e}", key_path.display()))?;

    info!(
        "ACME certificate and private key saved to {:?}",
        config.storage_dir
    );

    // Reload the running server TLS config if acceptor_mgr is provided
    if let Some(mgr) = acceptor_mgr {
        match load_server_config(&cert_path, &key_path, &[], alpn_protocols.to_vec()) {
            Ok(new_config) => {
                mgr.reload(new_config);
                info!("TlsAcceptorManager successfully reloaded with ACME certificate");
            }
            Err(e) => {
                error!("Failed to reload server TLS config with new ACME cert: {e}");
            }
        }
    }

    Ok(true)
}

/// Spawns the ACME manager background task for initial acquisition and periodic renewal.
pub fn start_acme_manager(
    config: AcmeServiceConfig,
    acceptor_mgr: Option<TlsAcceptorManager>,
    http01_challenges: Option<Arc<dashmap::DashMap<String, String>>>,
    alpn_protocols: Vec<Vec<u8>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            "ACME background manager started for domains: {:?}",
            config.domains
        );

        // Initial acquisition/renewal check on startup
        if let Err(e) = obtain_or_renew_certificate(
            &config,
            acceptor_mgr.as_ref(),
            http01_challenges.as_ref(),
            &alpn_protocols,
        )
        .await
        {
            warn!("Initial ACME certificate check failed: {e}");
        }

        // Periodic renewal loop (check every 12 hours)
        let check_interval = Duration::from_hours(12);
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        debug!("ACME manager shutting down");
                        break;
                    }
                }
                () = tokio::time::sleep(check_interval) => {
                    debug!("Running periodic ACME renewal check...");
                    if let Err(e) = obtain_or_renew_certificate(
                        &config,
                        acceptor_mgr.as_ref(),
                        http01_challenges.as_ref(),
                        &alpn_protocols,
                    ).await {
                        warn!("Periodic ACME renewal failed: {e}");
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

    #[test]
    fn test_tls_alpn_01_challenge_cert_generation() {
        let domain = "acme.example.com";
        let key_auth = "sample_key_auth_token_value_1234567890";
        let (cert_der, priv_der) = generate_tls_alpn_01_cert(domain, key_auth).unwrap();

        assert!(!cert_der.is_empty());
        let certified = create_certified_key(vec![cert_der], &priv_der).unwrap();
        assert_eq!(certified.cert.len(), 1);
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
}
