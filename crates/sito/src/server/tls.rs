//! TLS/ACME material selection, listener binding, and renewal bootstrap.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Builds one protocol's hot-reloadable TLS acceptor and starts its certificate
/// watcher.
///
/// Errors are fatal: a configured encrypted listener must never silently fall
/// back to "not running" because its certificate material is unreadable,
/// expired, or does not match the key.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_tls_acceptor(
    protocol: &str,
    cert: &Path,
    key: &Path,
    sni_tuples: &[(String, PathBuf, PathBuf)],
    alpn: &[Vec<u8>],
    challenge_keys: Option<Arc<dashmap::DashMap<String, Arc<rustls::sign::CertifiedKey>>>>,
    cert_watchers: &mut Vec<sito_transport::CertWatcher>,
) -> anyhow::Result<TlsAcceptorManager> {
    let config = match challenge_keys.clone() {
        Some(keys) => {
            load_server_config_with_challenges(cert, key, sni_tuples, alpn.to_vec(), keys)
        }
        None => load_server_config(cert, key, sni_tuples, alpn.to_vec()),
    }
    .map_err(|e| anyhow::anyhow!("Failed to initialize {protocol} TLS configuration: {e}"))?;

    let manager = match challenge_keys {
        Some(keys) => TlsAcceptorManager::with_challenge_keys(config, keys),
        None => TlsAcceptorManager::new(config),
    };
    match CertWatcher::start(cert, key, sni_tuples, alpn, manager.clone()) {
        Ok(watcher) => cert_watchers.push(watcher),
        Err(e) => warn!(protocol, "Certificate watcher failed to start: {e}"),
    }
    Ok(manager)
}

/// What encrypted listeners should do with the material found at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TlsStartupMaterial {
    /// Serve this certificate/key pair.
    Pair(PathBuf, PathBuf),
    /// No usable pair exists; write a short-lived bootstrap pair.
    GenerateBootstrap,
    /// No trusted pair and bootstrap serving is not opted in.
    Disabled,
}

/// Selects the startup action for encrypted listeners.
///
/// When ACME is enabled, a usable CA-issued certificate stored on disk takes
/// precedence over static `[tls]` files so a restart cannot silently revert
/// DoH/DoT/DoQ/DoH3 to stale static material. A bootstrap placeholder never
/// wins over a real static pair. If no trusted pair exists, a bootstrap is
/// generated only when the operator opted in with
/// `acme.allow_bootstrap_cert = true`; otherwise encrypted listeners stay
/// disabled until a real certificate is available.
pub(super) fn choose_tls_material(
    static_pair: Option<(PathBuf, PathBuf)>,
    acme_pair: Option<(PathBuf, PathBuf)>,
    acme_pair_usable: bool,
    acme_enabled: bool,
    allow_bootstrap_cert: bool,
) -> TlsStartupMaterial {
    if !acme_enabled {
        return static_pair.map_or(TlsStartupMaterial::Disabled, |(cert, key)| {
            TlsStartupMaterial::Pair(cert, key)
        });
    }

    if let Some((cert, key)) = acme_pair
        && acme_pair_usable
    {
        return TlsStartupMaterial::Pair(cert, key);
    }
    if let Some((cert, key)) = static_pair {
        return TlsStartupMaterial::Pair(cert, key);
    }
    if allow_bootstrap_cert {
        TlsStartupMaterial::GenerateBootstrap
    } else {
        TlsStartupMaterial::Disabled
    }
}

/// Whether the stored ACME certificate/key pair should be selected at startup.
///
/// Factored out of [`init_tls_and_acme`] so the wiring (`pair.is_some()` AND
/// `stored_pair_is_usable()`) is testable without binding listeners.
pub(super) fn acme_startup_pair_usable(pair_exists: bool, config: &AcmeServiceConfig) -> bool {
    pair_exists && config.stored_pair_is_usable()
}

/// Record whether a TCP DoH listener actually bound port 443 with the
/// `acme-tls/1` ALPN. Called after every bind/rebind so ACME challenge
/// selection reflects reality rather than configuration intent.
pub(super) fn record_doh_listener_binding(
    availability: &AcmeChallengeAvailability,
    config: &Config,
    doh_manager: Option<&TlsAcceptorManager>,
    doh_bound: bool,
) {
    let advertises_acme_alpn = doh_manager.is_some_and(|manager| {
        manager
            .alpn_protocols()
            .iter()
            .any(|protocol| protocol.as_slice() == b"acme-tls/1")
    });
    availability
        .set_tls_alpn_available(doh_bound && config.dns.doh_port == 443 && advertises_acme_alpn);
}

use sito_transport::CertificateValidity;

/// Maps a static certificate's validity to the TLS component readiness.
///
/// D12: a valid certificate is ready, one expiring inside the warning window is
/// degraded (still serving), and an expired/unparseable certificate is
/// not-ready.
pub(super) fn tls_certificate_readiness(
    validity: CertificateValidity,
) -> sito_api::ComponentReadiness {
    match validity {
        CertificateValidity::Expired => sito_api::ComponentReadiness::unavailable(
            "tls_cert_expired",
            "configured static TLS certificate is expired; encrypted listeners cannot serve",
        ),
        CertificateValidity::Expiring { days_remaining } => sito_api::ComponentReadiness::degraded(
            "tls_cert_expiring",
            format!("configured static TLS certificate expires in {days_remaining} day(s)"),
        ),
        CertificateValidity::Valid { .. }
        | CertificateValidity::Missing
        | CertificateValidity::Bootstrap => sito_api::ComponentReadiness::ready(),
    }
}

/// Whether an enabled ACME deployment has a usable current certificate that
/// takes precedence over the static pair (D12 ACME + static matrix).
fn acme_has_serving_certificate(config: &Config) -> bool {
    let Some(acme) = config.get_acme_config().filter(|acme| acme.enabled) else {
        return false;
    };
    let storage_dir = acme
        .cache_dir
        .clone()
        .unwrap_or_else(|| config.server.data_dir.join("acme"));
    let service = sito_transport::AcmeServiceConfig::new(
        acme.email
            .clone()
            .unwrap_or_else(|| "admin@example.com".to_string()),
        acme.domains.clone(),
        storage_dir,
    );
    matches!(
        service.certificate_validity(),
        CertificateValidity::Valid { .. } | CertificateValidity::Expiring { .. }
    )
}

/// Publishes TLS readiness for the acceptors installed by [`init_tls_and_acme`].
///
/// A configured static `[dns.tls]`/`[tls]` pair with no acceptor is a broken
/// configured listener (P2-87), not a silently disabled one: readiness must be
/// false. ACME-only deployments that intentionally wait for a real certificate
/// (`acme.allow_bootstrap_cert = false`) are covered by ACME readiness instead.
pub(super) fn publish_tls_readiness(
    readiness: &sito_api::ReadinessState,
    config: &Config,
    acceptors: Option<&ListenerAcceptors>,
    init_error: Option<&anyhow::Error>,
) {
    if let Some(error) = init_error {
        warn!(error = %error, "TLS initialization failed; encrypted listeners are not serving");
        readiness.set_tls_unavailable(
            "tls_init_failed",
            "TLS initialization failed; configured encrypted listeners are not serving",
        );
        return;
    }

    let static_tls_configured = config
        .get_tls_config()
        .is_some_and(|tls| tls.cert.is_some() && tls.key.is_some());
    let has_acceptor = acceptors.is_some_and(|acceptors| {
        acceptors.dot.is_some()
            || acceptors.doh.is_some()
            || acceptors.doq.is_some()
            || acceptors.doh3.is_some()
    });

    // P2-87: configured TLS material that produced no acceptor used to
    // disappear silently. Ports alone are not a TLS configuration: the default
    // DoT/DoH ports exist in every config, so only explicit `[dns.tls]`/`[tls]`
    // material (or an initialization error) marks the TLS component broken.
    if static_tls_configured && !has_acceptor {
        readiness.set_tls_unavailable(
            "tls_acceptor_unavailable",
            "configured TLS material has no usable acceptor; encrypted listeners are not serving",
        );
    } else if static_tls_configured && !acme_has_serving_certificate(config) {
        // D12 static-certificate ladder: expiry at runtime is a readiness
        // signal, not just an acceptor-presence check. An ACME certificate
        // that is currently valid takes precedence over the static pair.
        let validity = config
            .get_tls_config()
            .and_then(|tls| tls.cert.as_deref())
            .map_or(CertificateValidity::Missing, |path| {
                sito_transport::certificate_validity(path)
            });
        match tls_certificate_readiness(validity) {
            readiness_state if !readiness_state.ready => {
                readiness.set_tls_unavailable(
                    readiness_state.code.unwrap_or("tls_cert_expired"),
                    readiness_state
                        .message
                        .unwrap_or_else(|| "static TLS certificate is expired".to_string()),
                );
            }
            readiness_state if readiness_state.code.is_some() => {
                readiness.set_tls_degraded(
                    readiness_state.code.unwrap_or("tls_cert_expiring"),
                    readiness_state
                        .message
                        .unwrap_or_else(|| "static TLS certificate is expiring".to_string()),
                );
            }
            _ => readiness.set_tls_ready(),
        }
    } else {
        readiness.set_tls_ready();
    }
}

/// Loads certificates and ACME configuration, builds the per-protocol TLS
/// acceptors, publishes them for in-process listener rebinds, starts the ACME
/// renewal manager and returns the certificate watchers that must stay alive.
pub(super) async fn init_tls_and_acme(
    config: &Config,
    shutdown_rx: &watch::Receiver<bool>,
    listener_acceptors: &tokio::sync::Mutex<Option<ListenerAcceptors>>,
    acme_challenges: &sito_transport::AcmeChallengeAvailability,
) -> anyhow::Result<Vec<sito_transport::CertWatcher>> {
    // ACME and TLS setup
    let acme_cfg = config.get_acme_config();
    let is_acme_enabled = acme_cfg
        .as_ref()
        .is_some_and(|a| a.enabled && !a.domains.is_empty());
    acme_challenges.set_enabled(is_acme_enabled);

    let (cert_file, key_file, sni_tuples) = if let Some(tls_cfg) = config.get_tls_config() {
        if let (Some(cert), Some(key)) = (&tls_cfg.cert, &tls_cfg.key) {
            (Some(cert.clone()), Some(key.clone()), tls_cfg.sni_tuples())
        } else {
            (None, None, Vec::new())
        }
    } else {
        (None, None, Vec::new())
    };
    let static_pair = match (cert_file, key_file) {
        (Some(cert), Some(key)) => Some((cert, key)),
        _ => None,
    };

    // Build the ACME service configuration once; it is also used to decide
    // whether an existing stored certificate should take precedence over
    // static `[tls]` material at startup.
    let acme_service_cfg = if is_acme_enabled {
        let Some(acme) = acme_cfg.as_ref() else {
            // `is_acme_enabled` is derived from `acme_cfg`; this guard
            // keeps the startup path panic-free even if that changes.
            anyhow::bail!("ACME is enabled but the ACME configuration is missing");
        };
        let email = if let Some(email) = acme.email.clone() {
            email
        } else {
            warn!(
                "[acme] enabled without an account email; using admin@example.com. Set acme.email to receive expiry notices."
            );
            "admin@example.com".to_string()
        };
        let storage_dir = acme
            .cache_dir
            .clone()
            .unwrap_or_else(|| config.server.data_dir.join("acme"));
        Some(
            AcmeServiceConfig::new(email, acme.domains.clone(), storage_dir)
                .with_staging(acme.staging),
        )
    } else {
        None
    };

    let (acme_pair, acme_pair_usable) = if let Some(service_cfg) = &acme_service_cfg {
        let cert_path = service_cfg.storage_dir.join("cert.pem");
        let key_path = service_cfg.storage_dir.join("key.pem");
        let pair = (cert_path.exists() && key_path.exists()).then_some((cert_path, key_path));
        // Fail closed on unreadable/unparseable material: a truncated
        // certificate or key must never be selected and then abort startup in
        // the TLS builder while a valid static pair is available.
        let usable = acme_startup_pair_usable(pair.is_some(), service_cfg);
        (pair, usable)
    } else {
        (None, false)
    };

    // D12: bootstrap serving is opt-in and defaults to fail-closed.
    let allow_bootstrap_cert = acme_cfg
        .as_ref()
        .is_some_and(|acme| acme.enabled && acme.allow_bootstrap_cert);
    let material = match choose_tls_material(
        static_pair,
        acme_pair,
        acme_pair_usable,
        is_acme_enabled,
        allow_bootstrap_cert,
    ) {
        TlsStartupMaterial::Pair(cert, key) => Some((cert, key)),
        TlsStartupMaterial::Disabled => None,
        TlsStartupMaterial::GenerateBootstrap => {
            let Some(service_cfg) = &acme_service_cfg else {
                anyhow::bail!(
                    "Bootstrap certificate was requested but ACME configuration is missing"
                );
            };
            std::fs::create_dir_all(&service_cfg.storage_dir).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to create ACME storage directory {}: {e}",
                    service_cfg.storage_dir.display()
                )
            })?;
            let (cert_pem, key_pem) = generate_self_signed_cert(&service_cfg.domains)
                .map_err(|e| anyhow::anyhow!("Failed to generate bootstrap certificate: {e}"))?;
            let cert_path = service_cfg.storage_dir.join("cert.pem");
            let key_path = service_cfg.storage_dir.join("key.pem");
            std::fs::write(&cert_path, cert_pem).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to write bootstrap certificate to {}: {e}",
                    cert_path.display()
                )
            })?;
            // The bootstrap private key must be 0600: local users must not
            // read it before ACME replaces it.
            write_secret_file(&key_path, key_pem.as_bytes()).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to write bootstrap key to {}: {e}",
                    key_path.display()
                )
            })?;
            record_bootstrap_cert(&service_cfg.storage_dir).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to record bootstrap certificate in {}: {e}",
                    service_cfg.storage_dir.display()
                )
            })?;
            info!(
                "Generated bootstrap self-signed certificate in {:?} (allow_bootstrap_cert = true)",
                service_cfg.storage_dir
            );
            Some((cert_path, key_path))
        }
    };

    if material.is_none() && is_acme_enabled {
        warn!(
            "ACME is enabled but no trusted certificate is available and \
             acme.allow_bootstrap_cert is false; encrypted listeners are disabled \
             until ACME issuance completes and the server is restarted"
        );
    }

    let http01_challenges = Arc::new(dashmap::DashMap::<String, String>::new());
    let challenge_keys = Arc::new(dashmap::DashMap::new());
    // Kept alive for the lifetime of the server so certificate hot-reload works.
    let mut cert_watchers: Vec<sito_transport::CertWatcher> = Vec::new();

    let (dot_acceptor_mgr, doh_acceptor_mgr, doq_acceptor_mgr, doh3_acceptor_mgr) =
        if let Some((cert, key)) = &material {
            let doh_mgr = build_tls_acceptor(
                "doh",
                cert,
                key,
                &sni_tuples,
                &[b"h2".to_vec(), b"http/1.1".to_vec(), b"acme-tls/1".to_vec()],
                Some(challenge_keys.clone()),
                &mut cert_watchers,
            )?;
            let dot_mgr = build_tls_acceptor(
                "dot",
                cert,
                key,
                &sni_tuples,
                &[b"dot".to_vec()],
                None,
                &mut cert_watchers,
            )?;
            let doq_mgr = build_tls_acceptor(
                "doq",
                cert,
                key,
                &sni_tuples,
                &[b"doq".to_vec()],
                None,
                &mut cert_watchers,
            )?;
            let doh3_mgr = build_tls_acceptor(
                "doh3",
                cert,
                key,
                &sni_tuples,
                &[b"h3".to_vec()],
                None,
                &mut cert_watchers,
            )?;
            (Some(dot_mgr), Some(doh_mgr), Some(doq_mgr), Some(doh3_mgr))
        } else {
            (None, None, None, None)
        };

    // Live challenge state starts fail-safe: no TLS-ALPN-01 until a 443 DoH
    // listener actually binds (done later by `start_dns_listeners`). The
    // caller owns the shared object so readiness can read it.

    // If ACME is enabled, start ACME renewal background manager
    if let (Some(service_cfg), Some(acme)) = (acme_service_cfg, acme_cfg.as_ref()) {
        // Dedicated plaintext HTTP-01 listener (ACME validators always use port 80).
        let mut http01_available = false;
        if acme.http_port > 0 {
            let acme_http_addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                acme.http_port,
            );
            match sito_transport::start_acme_http01_listener(
                acme_http_addr,
                http01_challenges.clone(),
                shutdown_rx.clone(),
            )
            .await
            {
                Ok(_handle) => {
                    http01_available = true;
                    info!(
                        port = acme.http_port,
                        "ACME HTTP-01 challenge listener active"
                    );
                }
                Err(e) => warn!(
                    port = acme.http_port,
                    error = %e,
                    "Failed to bind ACME HTTP-01 listener; HTTP-01 validation will not be available"
                ),
            }
        }

        acme_challenges.set_http01_available(http01_available);
        let managers = TlsManagerSet {
            dot: dot_acceptor_mgr.clone(),
            doh: doh_acceptor_mgr.clone(),
            doq: doq_acceptor_mgr.clone(),
            doh3: doh3_acceptor_mgr.clone(),
        };
        let _acme_handle = start_acme_manager_for_transports(
            service_cfg,
            managers,
            Some(http01_challenges.clone()),
            acme_challenges.clone(),
            shutdown_rx.clone(),
        );
    }

    // Share TLS acceptors with the config watcher for in-process listener rebinds.
    *listener_acceptors.lock().await = Some(ListenerAcceptors {
        dot: dot_acceptor_mgr,
        doh: doh_acceptor_mgr,
        doq: doq_acceptor_mgr,
        doh3: doh3_acceptor_mgr,
        acme_challenges: acme_challenges.clone(),
    });

    Ok(cert_watchers)
}
