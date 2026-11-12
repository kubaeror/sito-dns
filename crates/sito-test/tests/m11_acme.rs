//! WP-0.2 acceptance: ACME bootstrap, issuance, renewal and all-transport
//! reload against a deterministic local ACME CA.
//!
//! The shared mock CA fixture implements the RFC 8555 directory/account/order/
//! authorization/challenge/finalize/certificate flow over HTTPS. It
//! intentionally does not perform challenge validation, does not verify JWS
//! signatures, and always issues a certificate for the CSR it receives. That is
//! enough to exercise sito's renewal scheduling, challenge selection,
//! persistence, and TLS manager reloads; it is not a conformance test of the
//! ACME client itself.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use sito_test::fixtures::acme::{DEFAULT_DOMAIN as DOMAIN, MockAcme};
use sito_test::fixtures::tls::{
    first_certificate_der as first_cert_der, served_certificate as served_cert,
    tls_acceptor_manager as build_manager,
};
use sito_transport::{
    AcmeChallengeAvailability, AcmeChallengeOptions, AcmeServiceConfig, TlsManagerSet,
    certificate_needs_renewal, days_until_expiration, generate_self_signed_cert,
    obtain_or_renew_certificate_for_transports, record_bootstrap_cert,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn rand_suffix() -> u64 {
    rand::random()
}

fn test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sito_m11_acme_{name}_{}_{}",
        std::process::id(),
        rand_suffix()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create test dir");
    dir
}

fn write_bootstrap(storage: &std::path::Path) -> (String, String) {
    let (cert_pem, key_pem) =
        generate_self_signed_cert(&[DOMAIN.to_string()]).expect("bootstrap cert");
    std::fs::write(storage.join("cert.pem"), &cert_pem).expect("write bootstrap cert");
    sito_transport::write_secret_file(&storage.join("key.pem"), key_pem.as_bytes())
        .expect("write bootstrap key");
    record_bootstrap_cert(storage).expect("record bootstrap marker");
    (cert_pem, key_pem)
}

fn config_for(storage: &std::path::Path, mock: &MockAcme) -> AcmeServiceConfig {
    AcmeServiceConfig::new(
        "admin@example.test".to_string(),
        vec![DOMAIN.to_string()],
        storage.to_path_buf(),
    )
    .with_directory_url(mock.directory_url().to_string())
    .with_root_certificate(mock.root_certificate_path().to_path_buf())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Acceptance: a fresh ACME-only install (only a bootstrap certificate on
/// disk) orders a real certificate, all four transports pick it up, renewal
/// issues a new certificate, and the account file survives corruption and a
/// directory change.
#[tokio::test(flavor = "multi_thread")]
async fn test_acme_bootstrap_issuance_all_transports_and_renewal() {
    let mock = MockAcme::start().await;
    let storage = test_dir("all_transports");
    write_bootstrap(&storage);

    let config = config_for(&storage, &mock);
    assert!(
        certificate_needs_renewal(&config),
        "bootstrap storage must request issuance"
    );
    assert!(config.is_bootstrap_cert());

    let challenge_keys = Arc::new(dashmap::DashMap::new());
    let dot = build_manager(
        &storage.join("cert.pem"),
        &storage.join("key.pem"),
        b"dot",
        None,
    );
    let doh = build_manager(
        &storage.join("cert.pem"),
        &storage.join("key.pem"),
        b"h2",
        Some(Arc::clone(&challenge_keys)),
    );
    let doq = build_manager(
        &storage.join("cert.pem"),
        &storage.join("key.pem"),
        b"doq",
        None,
    );
    let doh3 = build_manager(
        &storage.join("cert.pem"),
        &storage.join("key.pem"),
        b"h3",
        None,
    );
    let managers = TlsManagerSet {
        dot: Some(dot.clone()),
        doh: Some(doh.clone()),
        doq: Some(doq.clone()),
        doh3: Some(doh3.clone()),
    };
    let http01 = Arc::new(dashmap::DashMap::new());
    let options = AcmeChallengeOptions {
        tls_alpn_available: true,
        http01_available: true,
    };

    let issued =
        obtain_or_renew_certificate_for_transports(&config, &managers, Some(&http01), options)
            .await
            .expect("ACME issuance against the mock CA");
    assert!(issued, "a bootstrap certificate must trigger issuance");

    let issued_pem = std::fs::read(storage.join("cert.pem")).expect("issued cert");
    let issued_der = first_cert_der(&issued_pem);
    assert!(
        !config.is_bootstrap_cert(),
        "after issuance the stored certificate must no longer be a bootstrap placeholder"
    );
    assert!(
        days_until_expiration(&issued_pem).expect("issued validity") > 7,
        "the CA-issued certificate must not look like the short-lived bootstrap cert"
    );
    assert!(
        !storage.join("bootstrap").exists(),
        "the bootstrap marker must be removed after issuance"
    );
    assert!(
        storage.join("pair.sha256").exists(),
        "a completed rotation must record the certificate/key pair"
    );
    assert!(
        !certificate_needs_renewal(&config),
        "a freshly issued 90-day certificate must not trigger a renewal loop"
    );

    {
        assert_eq!(
            mock.selected_challenges().last().map(String::as_str),
            Some("tls-alpn-01"),
            "a 443-capable deployment must use TLS-ALPN-01"
        );
    }

    for (name, manager) in [("dot", &dot), ("doh", &doh), ("doq", &doq), ("doh3", &doh3)] {
        assert_eq!(
            served_cert(manager).await,
            issued_der,
            "{name} must serve the ACME certificate, not the bootstrap pair"
        );
    }

    // Renewal: force the threshold above the issued lifetime and ensure a new
    // certificate is ordered, persisted, and reloaded everywhere.
    let renew_config = config.clone().with_renew_before_days(180);
    assert!(certificate_needs_renewal(&renew_config));
    assert!(
        obtain_or_renew_certificate_for_transports(
            &renew_config,
            &managers,
            Some(&http01),
            options,
        )
        .await
        .expect("ACME renewal against the mock CA")
    );
    let renewed_pem = std::fs::read(storage.join("cert.pem")).expect("renewed cert");
    let renewed_der = first_cert_der(&renewed_pem);
    assert_ne!(
        issued_der, renewed_der,
        "renewal must install a freshly issued certificate"
    );
    for manager in [&dot, &doh, &doq, &doh3] {
        assert_eq!(
            served_cert(manager).await,
            renewed_der,
            "all transports must reload the renewed certificate"
        );
    }

    // Account credentials are written atomically with owner-only permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(storage.join("account.json"))
            .expect("account metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "account credentials must be owner-only");
    }
    assert!(
        !storage.join("account.tmp").exists(),
        "atomic account writes must not leave a temp file behind"
    );

    // Corrupt credentials: back up and re-register instead of blocking renewal.
    std::fs::write(storage.join("account.json"), b"{not json").expect("corrupt account");
    obtain_or_renew_certificate_for_transports(&renew_config, &managers, Some(&http01), options)
        .await
        .expect("issuance must recover from corrupt account credentials");
    assert!(
        storage.join("account.json.corrupt").exists(),
        "corrupt account credentials must be backed up"
    );
    let recovered: Value = serde_json::from_slice(
        &std::fs::read(storage.join("account.json")).expect("recovered account"),
    )
    .expect("recovered account must be valid JSON");
    assert_eq!(
        recovered.get("directory").and_then(Value::as_str),
        Some(mock.directory_url())
    );

    // Directory change: the configured directory wins over the stored one.
    let mut changed = recovered;
    changed["directory"] = Value::String("https://old-ca.invalid/directory".to_string());
    std::fs::write(
        storage.join("account.json"),
        serde_json::to_vec(&changed).expect("serialize changed account"),
    )
    .expect("write changed account");
    obtain_or_renew_certificate_for_transports(&renew_config, &managers, Some(&http01), options)
        .await
        .expect("issuance must recover from a directory change");
    assert!(
        storage.join("account.json.bak").exists(),
        "credentials from another directory must be backed up"
    );
    let re_registered: Value = serde_json::from_slice(
        &std::fs::read(storage.join("account.json")).expect("re-registered account"),
    )
    .expect("re-registered account must be valid JSON");
    assert_eq!(
        re_registered.get("directory").and_then(Value::as_str),
        Some(mock.directory_url())
    );

    let _ = std::fs::remove_dir_all(&storage);
}

/// Regression (P1-12): without a TCP 443 listener the client must select
/// HTTP-01 even when the CA also offers TLS-ALPN-01.
#[tokio::test(flavor = "multi_thread")]
async fn test_acme_without_443_listener_falls_back_to_http01() {
    let mock = MockAcme::start().await;
    let storage = test_dir("http01_fallback");
    write_bootstrap(&storage);

    let config = config_for(&storage, &mock);
    // A DoH TLS manager exists, but it is not bound to TCP 443, so TLS-ALPN-01
    // is not answerable; the previous behaviour selected it anyway.
    let challenge_keys = Arc::new(dashmap::DashMap::new());
    let doh = build_manager(
        &storage.join("cert.pem"),
        &storage.join("key.pem"),
        b"h2",
        Some(challenge_keys),
    );
    let managers = TlsManagerSet {
        doh: Some(doh),
        ..TlsManagerSet::default()
    };
    let http01 = Arc::new(dashmap::DashMap::new());
    // This is the ACME manager's state before any 443 listener binds; it is
    // also what `record_doh_listener_binding` leaves after a failed 443 bind.
    let availability = AcmeChallengeAvailability::default();
    availability.set_http01_available(true);
    let options = availability.options();

    let issued =
        obtain_or_renew_certificate_for_transports(&config, &managers, Some(&http01), options)
            .await
            .expect("HTTP-01 issuance against the mock CA");
    assert!(issued);

    assert_eq!(
        mock.selected_challenges().last().map(String::as_str),
        Some("http-01"),
        "a deployment without a bound TCP 443 listener must fall back to HTTP-01"
    );

    let _ = std::fs::remove_dir_all(&storage);
}

/// Important 3 regression: if the certificate is issued but a transport fails
/// to reload it, the caller must see an error so the retry/backoff path runs
/// instead of reporting success and waiting 12 hours.
#[tokio::test(flavor = "multi_thread")]
async fn test_failed_post_issuance_reload_is_reported() {
    let mock = MockAcme::start().await;
    let storage = test_dir("reload_failure");
    write_bootstrap(&storage);

    let config = config_for(&storage, &mock);
    let challenge_keys = Arc::new(dashmap::DashMap::new());
    let doh = build_manager(
        &storage.join("cert.pem"),
        &storage.join("key.pem"),
        b"h2",
        Some(challenge_keys),
    );
    // A missing SNI pair makes every reload attempt fail after issuance.
    doh.set_sni_certs(vec![(
        "broken.example.test".to_string(),
        storage.join("missing-sni-cert.pem"),
        storage.join("missing-sni-key.pem"),
    )]);
    let managers = TlsManagerSet {
        doh: Some(doh),
        ..TlsManagerSet::default()
    };
    let http01 = Arc::new(dashmap::DashMap::new());
    let options = AcmeChallengeOptions {
        tls_alpn_available: true,
        http01_available: true,
    };

    let error =
        obtain_or_renew_certificate_for_transports(&config, &managers, Some(&http01), options)
            .await
            .expect_err("a failed post-issuance reload must be reported");
    assert!(
        error.contains("failed to reload TLS transports"),
        "unexpected error: {error}"
    );
    assert!(
        storage.join("cert.pem").exists(),
        "the issued certificate must still be persisted for the retry path"
    );
    assert!(
        !config.is_bootstrap_cert(),
        "the persisted certificate must be the CA-issued one"
    );

    // The no-renewal branch must also surface a persistent reload failure so
    // the manager keeps retrying instead of waiting for the steady-state tick.
    let retry_error =
        obtain_or_renew_certificate_for_transports(&config, &managers, Some(&http01), options)
            .await
            .expect_err("a persistent reload failure must be reported on the no-renewal path");
    assert!(
        retry_error.contains("persisted ACME certificate"),
        "unexpected error: {retry_error}"
    );

    let _ = std::fs::remove_dir_all(&storage);
}

/// Regression (P0-1): a fresh bootstrap certificate with no marker, no short
/// validity, but self-signed by an older version is still recognised as a
/// placeholder and renewed.
#[test]
fn test_legacy_self_signed_bootstrap_requires_renewal() {
    let storage = test_dir("legacy_bootstrap");
    let (cert_pem, key_pem) =
        generate_self_signed_cert(&[DOMAIN.to_string()]).expect("bootstrap cert");
    std::fs::write(storage.join("cert.pem"), cert_pem).expect("write cert");
    sito_transport::write_secret_file(&storage.join("key.pem"), key_pem.as_bytes())
        .expect("write key");
    // No bootstrap marker and no pair marker: exactly what 1.9.3 wrote.
    let config = AcmeServiceConfig::new(
        "admin@example.test".to_string(),
        vec![DOMAIN.to_string()],
        storage.clone(),
    );
    assert!(
        certificate_needs_renewal(&config),
        "a self-signed bootstrap certificate must never suppress ACME issuance"
    );
    let _ = std::fs::remove_dir_all(&storage);
}
