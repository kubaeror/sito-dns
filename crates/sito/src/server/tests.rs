#![cfg(test)]

use super::canonical_config_path;
use super::*;
use std::path::Path;

#[test]
fn test_retention_startup_delay_schedules_recent_success() {
    let interval_ms = 24 * 3600 * 1000;
    let now = 1_700_000_000_000i64;

    // No prior success: run immediately.
    assert_eq!(retention_startup_delay_ms(None, now, interval_ms), 0);

    // Recent success: normally wait until last_success + interval, but cap
    // the delay so a process restarting more often still runs retention.
    let recent = now - 12 * 3600 * 1000;
    let delay = retention_startup_delay_ms(Some(recent), now, interval_ms);
    assert_eq!(delay, RETENTION_STARTUP_CATCHUP_MAX_DELAY_MS);

    // Success older than the interval: run immediately.
    let old = now - interval_ms - 1;
    assert_eq!(retention_startup_delay_ms(Some(old), now, interval_ms), 0);

    // A recent success schedules a sweep (delay is not "skip forever").
    assert!(delay > 0);
}

#[test]
fn test_canonical_config_path_for_relative_default() {
    let resolved = canonical_config_path(Path::new("config.toml"));
    assert!(
        resolved.is_absolute(),
        "relative paths must become absolute: {resolved:?}"
    );
    assert_eq!(
        resolved.file_name(),
        Some(std::ffi::OsStr::new("config.toml"))
    );
    assert!(
        resolved.parent().is_some_and(|p| !p.as_os_str().is_empty()),
        "the watcher needs a watchable parent directory"
    );
}

#[test]
fn test_canonical_config_path_existing_file() {
    let dir = std::env::temp_dir().join(format!("sito_cfg_path_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("config.toml");
    std::fs::write(&file, "config_version = 2\n").unwrap();
    let resolved = canonical_config_path(&file);
    assert!(resolved.is_absolute());
    assert_eq!(
        resolved.file_name(),
        Some(std::ffi::OsStr::new("config.toml"))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn scoped_clients(servers: &[&str]) -> sito_clients::ClientsConfig {
    let mut clients = sito_clients::ClientsConfig::default();
    clients.entries.push(sito_clients::ClientEntryConfig {
        name: "corp".to_string(),
        ids: Vec::new(),
        group: "default".to_string(),
        ignore_query_log: false,
        ignore_stats: false,
        use_global_upstreams: false,
        upstreams: Some(servers.iter().map(|server| (*server).to_string()).collect()),
        trusted: false,
    });
    clients
}

/// Important 3: changing a global upstream setting such as
/// `allow_private_targets` must rebuild per-client scoped managers on a hot
/// reload instead of reusing the old SSRF policy.
#[tokio::test]
async fn test_scoped_upstream_reload_rebuilds_on_allow_private_targets_change() {
    let mut config = Config::default();
    config.upstream.servers = vec!["1.1.1.1".to_string()];
    let clients = scoped_clients(&["udp://127.0.0.1:53"]);

    let first = build_scoped_upstreams(&config, &clients, &HashMap::new())
        .await
        .expect("first scope must build");
    assert_eq!(first.len(), 1);
    let first_key = first.keys().next().unwrap().clone();
    let first_manager = first.values().next().unwrap().clone();

    config.upstream.allow_private_targets = true;
    let second = build_scoped_upstreams(&config, &clients, &first)
        .await
        .expect("reloaded scope must build");
    assert_eq!(second.len(), 1);
    let second_key = second.keys().next().unwrap().clone();
    let second_manager = second.values().next().unwrap().clone();

    assert_ne!(
        first_key, second_key,
        "the reuse key must include allow_private_targets"
    );
    assert!(
        !Arc::ptr_eq(&first_manager, &second_manager),
        "a changed SSRF policy must not reuse the stale scoped manager"
    );
}

/// The reuse key must also change when inherited connection settings change,
/// not only when the server list changes.
#[test]
fn test_scoped_upstream_key_includes_inherited_settings() {
    use sito_runtime::scoped_upstream_key;

    let mut config = Config::default();
    let servers = vec!["tls://dns.example".to_string()];
    let base = scoped_upstream_key(&config, &servers);

    config.upstream.bootstrap = vec!["1.1.1.1".parse().unwrap()];
    assert_ne!(base, scoped_upstream_key(&config, &servers));

    let mut config = Config::default();
    config.upstream.timeout_ms += 1;
    assert_ne!(base, scoped_upstream_key(&config, &servers));

    let mut config = Config::default();
    config.upstream.strategy = sito_core::config::UpstreamStrategy::Parallel;
    assert_ne!(base, scoped_upstream_key(&config, &servers));

    let mut config = Config::default();
    config.upstream.pool_size += 1;
    assert_ne!(base, scoped_upstream_key(&config, &servers));

    let mut config = Config::default();
    config.upstream.allow_private_targets = true;
    assert_ne!(base, scoped_upstream_key(&config, &servers));
}

/// I5 regression: the production `init_ha` call site records the
/// `replication_disabled` no-op for a master with a zero replication port.
#[tokio::test]
async fn test_init_ha_records_master_replication_disabled_noop() {
    let dir = std::env::temp_dir().join(format!("sito_init_ha_{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut config = Config::default();
    config.server.role = "master".to_string();
    config.server.data_dir = dir.clone();
    config.ha = None;

    let metrics = sito_stats::MetricsRegistry::new("1.9.0", "test");
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let runtime = init_ha(&config, &dir.join("config.toml"), &metrics, &shutdown_rx)
        .expect("init_ha must succeed for a master with replication disabled");
    assert!(runtime.coordinator.is_some());

    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains(
            r#"sito_ha_startup_noop_total{role="master",reason="replication_disabled"} 1"#
        ),
        "the production startup path must expose the no-op: {rendered}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression: a master restart with a persisted `ha_state.toml` used to
/// resume the old bundle and never compare it with `config.toml`, leaving
/// every slave on stale configuration. A changed config must republish at
/// `N + 1`; an unchanged config must resume the existing sequence.
#[tokio::test]
async fn test_master_restart_republishes_changed_config() {
    let dir =
        std::env::temp_dir().join(format!("sito_init_ha_reconcile_{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.toml");

    let mut config = Config::default();
    config.server.role = "master".to_string();
    config.server.instance_name = "master-reconcile".to_string();
    config.server.data_dir = dir.clone();
    config.ha = None;
    config.upstream.servers = vec!["1.1.1.1".to_string()];
    std::fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();

    let metrics = sito_stats::MetricsRegistry::new("1.9.0", "test");
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    let first = init_ha(&config, &config_path, &metrics, &shutdown_rx)
        .expect("first master startup must publish v1");
    let first_coordinator = first.coordinator.expect("master coordinator");
    assert_eq!(
        first_coordinator.current_version.load(Ordering::SeqCst),
        1,
        "a fresh master must start at version 1"
    );
    drop(first_coordinator);

    // Restarting with an unchanged config must not churn the sequence.
    let unchanged = init_ha(&config, &config_path, &metrics, &shutdown_rx)
        .expect("unchanged restart must succeed");
    let unchanged_coordinator = unchanged.coordinator.expect("master coordinator");
    assert_eq!(
        unchanged_coordinator.current_version.load(Ordering::SeqCst),
        1,
        "an unchanged config must resume the persisted version"
    );
    let unchanged_bundle = unchanged_coordinator
        .active_bundle
        .lock()
        .unwrap()
        .clone()
        .expect("restored bundle");
    assert!(
        unchanged_bundle.config_toml.contains("1.1.1.1"),
        "an unchanged restart must keep the persisted bundle"
    );
    drop(unchanged_coordinator);

    // Editing the master config and restarting must publish N + 1 so
    // connected slaves pick up the new shared configuration.
    config.upstream.servers = vec!["9.9.9.9".to_string()];
    std::fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();
    let changed = init_ha(&config, &config_path, &metrics, &shutdown_rx)
        .expect("changed restart must republish the bundle");
    let changed_coordinator = changed.coordinator.expect("master coordinator");
    assert_eq!(
        changed_coordinator.current_version.load(Ordering::SeqCst),
        2,
        "a changed config must republish at N + 1"
    );
    let changed_bundle = changed_coordinator
        .active_bundle
        .lock()
        .unwrap()
        .clone()
        .expect("republished bundle");
    assert!(
        changed_bundle.config_toml.contains("9.9.9.9"),
        "the republished bundle must carry the current config: {}",
        changed_bundle.config_toml
    );
    assert!(
        !changed_bundle.config_toml.contains("1.1.1.1"),
        "the republished bundle must not carry the stale config: {}",
        changed_bundle.config_toml
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_bundled_registries_load_without_panicking() {
    // Startup must use the fallible loaders: corrupt embedded data has to
    // surface as a startup error, not a panic. This pins that the shipped
    // bundled data loads cleanly through that path.
    let (parental, services) = load_bundled_registries().expect("embedded bundled lists must load");
    assert!(
        !parental.lists().is_empty(),
        "parental lists must be present"
    );
    assert!(
        services.service_count() > 0,
        "service rules must be present"
    );
}

/// Regression (P1-12/Important 2): TLS-ALPN-01 must only be offered when
/// DoH actually bound TCP 443. A failed/absent bind or a custom DoH port
/// must fall back to HTTP-01.
#[test]
fn test_acme_challenge_availability_requires_bound_443() {
    let dir = std::env::temp_dir().join(format!(
        "sito_acme_bind_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let (cert_pem, key_pem) =
        generate_self_signed_cert(&["localhost".to_string()]).expect("self-signed cert");
    std::fs::write(&cert, cert_pem).unwrap();
    std::fs::write(&key, key_pem).unwrap();
    let manager = TlsAcceptorManager::new(
        load_server_config(&cert, &key, &[], vec![b"acme-tls/1".to_vec()]).expect("TLS config"),
    );

    let mut config = Config::default();
    config.dns.doh_port = 443;
    let availability = AcmeChallengeAvailability::default();

    // The ACME manager starts before the DNS bind: nothing is available.
    assert!(!availability.options().tls_alpn_available);

    record_doh_listener_binding(&availability, &config, Some(&manager), false);
    assert!(
        !availability.options().tls_alpn_available,
        "a failed/absent 443 bind must not enable TLS-ALPN-01"
    );

    config.dns.doh_port = 8443;
    record_doh_listener_binding(&availability, &config, Some(&manager), true);
    assert!(
        !availability.options().tls_alpn_available,
        "TLS-ALPN-01 needs port 443, not just any bound TLS listener"
    );

    config.dns.doh_port = 443;
    record_doh_listener_binding(&availability, &config, Some(&manager), true);
    assert!(
        availability.options().tls_alpn_available,
        "a bound 443 DoH listener with acme-tls/1 enables TLS-ALPN-01"
    );

    record_doh_listener_binding(&availability, &config, None, true);
    assert!(!availability.options().tls_alpn_available);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression (P1-12/P2-13): a restart must prefer the stored ACME
/// certificate over static `[tls]` files, but a bootstrap placeholder must
/// not displace a real static pair.
#[test]
fn test_choose_tls_material_prefers_acme_certificate_on_restart() {
    let static_pair = Some((
        PathBuf::from("/etc/sito/static-cert.pem"),
        PathBuf::from("/etc/sito/static-key.pem"),
    ));
    let acme_pair = Some((
        PathBuf::from("/var/lib/sito/acme/cert.pem"),
        PathBuf::from("/var/lib/sito/acme/key.pem"),
    ));
    let static_pair_value = static_pair.clone().expect("static pair");
    let acme_pair_value = acme_pair.clone().expect("acme pair");

    assert_eq!(
        choose_tls_material(static_pair.clone(), acme_pair.clone(), true, true, false),
        TlsStartupMaterial::Pair(acme_pair_value.0.clone(), acme_pair_value.1.clone()),
        "a usable ACME certificate must win over static material after restart"
    );
    assert_eq!(
        choose_tls_material(static_pair.clone(), acme_pair.clone(), false, true, true),
        TlsStartupMaterial::Pair(static_pair_value.0.clone(), static_pair_value.1.clone()),
        "a bootstrap placeholder must not displace a real static pair"
    );
    assert_eq!(
        choose_tls_material(None, acme_pair.clone(), false, true, false),
        TlsStartupMaterial::Disabled,
        "D12: bootstrap must not be served by default"
    );
    assert_eq!(
        choose_tls_material(None, acme_pair.clone(), false, true, true),
        TlsStartupMaterial::GenerateBootstrap,
        "opting in allows a fresh bootstrap while ACME issues"
    );
    assert_eq!(
        choose_tls_material(None, None, false, true, false),
        TlsStartupMaterial::Disabled,
        "ACME-only with no certificate is fail-closed by default"
    );
    assert_eq!(
        choose_tls_material(None, None, false, true, true),
        TlsStartupMaterial::GenerateBootstrap,
        "ACME-only with the opt-in generates a bootstrap certificate"
    );
    assert_eq!(
        choose_tls_material(static_pair.clone(), None, false, true, false),
        TlsStartupMaterial::Pair(static_pair_value.0.clone(), static_pair_value.1.clone()),
        "without ACME material the static pair is used while issuance runs"
    );
    assert_eq!(
        choose_tls_material(static_pair.clone(), acme_pair.clone(), false, false, false),
        TlsStartupMaterial::Pair(static_pair_value.0.clone(), static_pair_value.1.clone()),
        "with ACME disabled only static material is used"
    );
}

/// Regression (deferred D2): unparseable ACME material must not be
/// selected at startup. It must fall back to a valid static pair when one
/// exists, and otherwise take the bootstrap/renewal path instead of
/// passing the pair to the TLS builder (which would abort startup).
#[test]
fn test_unparseable_acme_material_falls_back_to_static_pair() {
    let dir = std::env::temp_dir().join(format!(
        "sito_acme_truncated_startup_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
    let acme_cert = dir.join("cert.pem");
    let acme_key = dir.join("key.pem");
    std::fs::write(&acme_cert, b"-----BEGIN CERTIFICATE-----\ntruncated\n")
        .expect("write truncated cert");
    write_secret_file(&acme_key, b"not a private key").expect("write bad key");

    let config = AcmeServiceConfig::new(
        "admin@example.test".to_string(),
        vec!["dns.example.test".to_string()],
        dir.clone(),
    );
    assert!(
        !config.stored_pair_is_usable(),
        "truncated ACME material must never be considered usable"
    );
    assert!(
        !acme_startup_pair_usable(false, &config),
        "a missing pair must not be selected"
    );
    assert!(
        !acme_startup_pair_usable(true, &config),
        "an existing but unusable pair must not be selected"
    );
    assert!(
        sito_transport::certificate_needs_renewal(&config),
        "the renewal path must still run for truncated material"
    );

    let acme_pair = Some((acme_cert, acme_key));
    let static_pair = Some((
        PathBuf::from("/etc/sito/static-cert.pem"),
        PathBuf::from("/etc/sito/static-key.pem"),
    ));
    let static_value = static_pair.clone().expect("static pair");
    assert_eq!(
        choose_tls_material(
            static_pair.clone(),
            acme_pair.clone(),
            config.stored_pair_is_usable(),
            true,
            false
        ),
        TlsStartupMaterial::Pair(static_value.0.clone(), static_value.1.clone()),
        "unparseable ACME material must not displace a valid static pair"
    );
    assert_eq!(
        choose_tls_material(None, acme_pair.clone(), false, true, false),
        TlsStartupMaterial::Disabled,
        "ACME-only with unusable material is fail-closed without the opt-in"
    );
    assert_eq!(
        choose_tls_material(None, acme_pair, false, true, true),
        TlsStartupMaterial::GenerateBootstrap,
        "the opt-in replaces unusable material with a fresh bootstrap pair"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Critical 1 regression: a CA-issued certificate with only ~5 days left
/// has a ~90-day lifetime. It must not be classified as a bootstrap
/// placeholder and must not be overwritten during startup selection.
#[test]
fn test_short_remaining_validity_does_not_trigger_bootstrap_replacement() {
    let dir = std::env::temp_dir().join(format!(
        "sito_acme_short_remaining_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");

    let ca_key = rcgen::KeyPair::generate().expect("CA key");
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "sito test CA");
    let now = time::OffsetDateTime::now_utc();
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let mut leaf_params =
        rcgen::CertificateParams::new(vec!["dns.example.test".to_string()]).expect("leaf params");
    leaf_params.not_before = now - time::Duration::days(85);
    leaf_params.not_after = now + time::Duration::days(5);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
        .expect("leaf cert");

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, leaf_cert.pem()).expect("write cert");
    write_secret_file(&key_path, leaf_key.serialize_pem().as_bytes()).expect("write key");

    let config = AcmeServiceConfig::new(
        "admin@example.test".to_string(),
        vec!["dns.example.test".to_string()],
        dir.clone(),
    )
    .with_renew_before_days(30);
    assert!(
        !config.is_bootstrap_cert(),
        "remaining validity must not classify a CA certificate as bootstrap"
    );

    let acme_pair = Some((cert_path.clone(), key_path.clone()));
    let acme_pair_value = acme_pair.clone().expect("acme pair");
    assert!(
        acme_startup_pair_usable(true, &config),
        "a still-valid CA-issued pair must be selected at startup"
    );
    let acme_pair_usable = acme_startup_pair_usable(true, &config);
    assert_eq!(
        choose_tls_material(None, acme_pair.clone(), acme_pair_usable, true, false),
        TlsStartupMaterial::Pair(acme_pair_value.0.clone(), acme_pair_value.1.clone()),
        "a still-valid CA certificate must be retained even though renewal is due"
    );

    // An actually expired CA certificate is not served, but is not
    // overwritten either: encrypted listeners are disabled by default.
    let expired_key = rcgen::KeyPair::generate().expect("expired leaf key");
    let mut expired_params = rcgen::CertificateParams::new(vec!["dns.example.test".to_string()])
        .expect("expired leaf params");
    expired_params.not_before = now - time::Duration::days(90);
    expired_params.not_after = now - time::Duration::hours(1);
    let expired_cert = expired_params
        .signed_by(
            &expired_key,
            &rcgen::Issuer::from_params(&ca_params, &ca_key),
        )
        .expect("expired leaf cert");
    std::fs::write(&cert_path, expired_cert.pem()).expect("write expired cert");
    write_secret_file(&key_path, expired_key.serialize_pem().as_bytes())
        .expect("write expired key");
    assert!(
        config.stored_cert_is_expired(),
        "the expired certificate must be detected"
    );
    assert_eq!(
        choose_tls_material(None, acme_pair, false, true, false),
        TlsStartupMaterial::Disabled,
        "an expired CA certificate must not be replaced or served without opt-in"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression (P0-1): invalid configured certificate material must abort
/// startup for the encrypted listeners instead of silently running without
/// them.
#[tokio::test]
async fn test_invalid_tls_material_is_fatal() {
    let dir = std::env::temp_dir().join(format!(
        "sito_tls_fatal_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let mut config = Config::default();
    config.tls = Some(sito_core::config::TlsConfig {
        cert: Some(dir.join("missing-cert.pem")),
        key: Some(dir.join("missing-key.pem")),
        sni_certs: Vec::new(),
    });

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let acceptors = tokio::sync::Mutex::new(None);
    let challenges = AcmeChallengeAvailability::default();
    let readiness = sito_api::ReadinessState::default();
    let cert_validity_cache = Arc::new(sito_transport::CertificateValidityCache::new());
    let result = init_tls_and_acme(
        &config,
        &shutdown_rx,
        &acceptors,
        &challenges,
        &readiness,
        &cert_validity_cache,
    )
    .await;
    assert!(
        result.is_err(),
        "unreadable certificate material must fail startup, not disable encrypted listeners"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_tls_acceptors_rebuilt_from_updated_config() {
    // The setup wizard can configure TLS after startup; re-initializing
    // must populate the acceptors so encrypted listeners bind immediately.
    let (cert_pem, key_pem) =
        generate_self_signed_cert(&["localhost".to_string()]).expect("self-signed cert");
    let dir = std::env::temp_dir().join(format!("sito_tls_reinit_{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();

    let mut config = Config::default();
    config.tls = Some(sito_core::config::TlsConfig {
        cert: Some(cert_path),
        key: Some(key_path),
        sni_certs: Vec::new(),
    });

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let acceptors = tokio::sync::Mutex::new(None);
    let challenges = AcmeChallengeAvailability::default();
    let readiness = sito_api::ReadinessState::default();
    let cert_validity_cache = Arc::new(sito_transport::CertificateValidityCache::new());
    let watchers = init_tls_and_acme(
        &config,
        &shutdown_rx,
        &acceptors,
        &challenges,
        &readiness,
        &cert_validity_cache,
    )
    .await
    .expect("TLS initialization");

    let snapshot = acceptors
        .lock()
        .await
        .clone()
        .expect("acceptors must be stored");
    assert!(snapshot.dot.is_some(), "DoT acceptor must exist");
    assert!(snapshot.doh.is_some(), "DoH acceptor must exist");
    assert!(snapshot.doq.is_some(), "DoQ acceptor must exist");
    assert!(snapshot.doh3.is_some(), "DoH3 acceptor must exist");

    drop(watchers);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression: the DNS warning must not claim listeners exist during
/// setup-pending mode, and the post-wizard transition must use the
/// configuration the wizard actually wrote.
#[test]
fn test_exposure_warning_phases_suppress_dns_while_setup_pending() {
    // 2.0 safe default binds the admin UI loopback; explicitly expose it
    // here so the phase separation is still exercised.
    let mut default = Config::default();
    let mut web = default.get_web_config();
    web.bind = "0.0.0.0".parse().expect("valid wildcard");
    default.set_web_config(web);
    let startup = exposure_warnings_for_phase(&default, ExposurePhase::Startup);
    assert_eq!(
        startup.len(),
        1,
        "setup-pending startup must warn only for the admin UI: {startup:?}"
    );
    assert!(startup[0].contains("admin web UI"));
    assert!(
        !startup.iter().any(|w| w.contains("DNS listeners")),
        "DNS is not bound during setup-pending mode: {startup:?}"
    );

    let dns_starting = exposure_warnings_for_phase(&default, ExposurePhase::DnsListeners);
    assert_eq!(
        dns_starting.len(),
        1,
        "the DNS transition must emit exactly the DNS warning: {dns_starting:?}"
    );
    assert!(dns_starting[0].contains("DNS listeners"));

    // The wizard may change dns.bind to loopback; the transition warning
    // must use the then-current configuration, not the startup defaults.
    let mut completed = Config::default();
    completed.dns.bind = vec!["127.0.0.1".parse().expect("valid loopback")];
    assert!(
        exposure_warnings_for_phase(&completed, ExposurePhase::DnsListeners).is_empty(),
        "a loopback DNS bind must not warn after setup completes"
    );
}

fn no_acceptors() -> ListenerAcceptors {
    ListenerAcceptors {
        dot: None,
        doh: None,
        doq: None,
        doh3: None,
        acme_challenges: AcmeChallengeAvailability::default(),
    }
}

/// P2-87: configured TLS material without an acceptor must make TLS readiness
/// false instead of silently serving plain DNS only.
#[test]
fn test_publish_tls_readiness_marks_configured_material_without_acceptor_unavailable() {
    let readiness = sito_api::ReadinessState::default();

    let mut config = Config::default();
    config.dns.tls = Some(sito_core::config::TlsConfig {
        cert: Some(Path::new("/etc/sito/certs/dns.crt").to_path_buf()),
        key: Some(Path::new("/etc/sito/certs/dns.key").to_path_buf()),
        sni_certs: Vec::new(),
    });
    publish_tls_readiness(
        &readiness,
        &config,
        Some(&no_acceptors()),
        None,
        &sito_transport::CertificateValidityCache::new(),
    );
    let tls = readiness.tls();
    assert!(
        !tls.ready,
        "configured TLS material without an acceptor is not ready"
    );
    assert_eq!(tls.code, Some("tls_acceptor_unavailable"));

    // No explicit TLS material: the TLS component is not applicable even
    // though the default config lists encrypted listener ports.
    let config = Config::default();
    publish_tls_readiness(
        &readiness,
        &config,
        Some(&no_acceptors()),
        None,
        &sito_transport::CertificateValidityCache::new(),
    );
    assert!(readiness.tls().ready);
}

/// An ACME-only deployment that intentionally waits for its first real
/// certificate is covered by ACME readiness, not by a broken-TLS reason.
#[test]
fn test_publish_tls_readiness_allows_acme_without_static_material() {
    let readiness = sito_api::ReadinessState::default();
    let mut config = Config::default();
    config.acme = Some(sito_core::config::AcmeConfig {
        enabled: true,
        email: Some("admin@example.com".to_string()),
        domains: vec!["dns.example.com".to_string()],
        allow_bootstrap_cert: false,
        ..Default::default()
    });
    publish_tls_readiness(
        &readiness,
        &config,
        Some(&no_acceptors()),
        None,
        &sito_transport::CertificateValidityCache::new(),
    );
    assert!(
        readiness.tls().ready,
        "ACME issuance readiness owns the waiting state"
    );

    // A TLS initialization failure always makes the TLS component unavailable,
    // even in an ACME deployment.
    let error = anyhow::anyhow!("certificate parse failure");
    publish_tls_readiness(
        &readiness,
        &config,
        Some(&no_acceptors()),
        Some(&error),
        &sito_transport::CertificateValidityCache::new(),
    );
    let tls = readiness.tls();
    assert!(!tls.ready);
    assert_eq!(tls.code, Some("tls_init_failed"));
}

/// D12 static TLS ladder: valid serves, expiring is degraded, expired is
/// not-ready.
#[test]
fn test_static_tls_certificate_readiness_ladder() {
    let ready = tls_certificate_readiness(sito_transport::CertificateValidity::Valid {
        days_remaining: 90,
    });
    assert!(ready.ready);
    assert!(ready.code.is_none());

    let expiring = tls_certificate_readiness(sito_transport::CertificateValidity::Expiring {
        days_remaining: 10,
    });
    assert!(expiring.ready, "an expiring certificate still serves");
    assert_eq!(expiring.code, Some("tls_cert_expiring"));

    let expired = tls_certificate_readiness(sito_transport::CertificateValidity::Expired);
    assert!(!expired.ready);
    assert_eq!(expired.code, Some("tls_cert_expired"));

    let missing = tls_certificate_readiness(sito_transport::CertificateValidity::Missing);
    assert!(
        missing.ready,
        "a live acceptor still serves after the file disappears"
    );
}

/// A scoped-upstream construction failure must fail the staged apply in
/// `ConfigApplyHooks::prepare`, before anything is published. It must never
/// log a warning and let the client fall back to the global upstreams.
#[tokio::test]
async fn test_scoped_upstream_construction_failure_aborts_prepare() {
    use sito_api::config_apply::ConfigApplyHooks;
    use sito_clients::{ClientRegistry, ParentalRegistry, ServiceRegistry};
    use sito_filter::HostsFilterEngine;
    use sito_rewrites::{RewriteTable, RewritesConfig};
    use std::sync::atomic::AtomicUsize;

    let temp_dir = std::env::temp_dir().join(format!(
        "sito_scoped_prepare_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let mut config = Config::default();
    config.server.data_dir = temp_dir.clone();
    config.upstream.servers = vec!["1.1.1.1".to_string()];
    config.filtering.enabled = false;
    config.dns.dnssec.validate = false;

    let bootstrap = BootstrapResolver::new(vec![], Duration::from_millis(100));
    let upstream = Arc::new(
        UpstreamManager::from_config(&config.upstream, &bootstrap)
            .await
            .unwrap(),
    );
    let filter =
        Arc::new(HostsFilterEngine::init(config.filtering.clone(), temp_dir.clone()).await);
    let pipeline = Arc::new(DnsPipeline::new(
        Arc::new(ArcSwap::new(Arc::new(config.clone()))),
        filter,
        Arc::new(DnsCache::new(config.dns.cache.clone())),
        upstream,
        Arc::new(DnssecValidator::from_config(&config.dns.dnssec)),
        Arc::new(ArcSwap::new(Arc::new(ClientRegistry::new(
            sito_clients::ClientsConfig::default(),
        )))),
        Arc::new(ParentalRegistry::try_bundled().expect("bundled parental lists must load")),
        Arc::new(ServiceRegistry::try_bundled().expect("bundled services must load")),
        Arc::new(ArcSwap::new(Arc::new(RewriteTable::new(
            RewritesConfig::default(),
        )))),
        Arc::new(AtomicUsize::new(0)),
    ));
    let hooks = ServerApplyHooks {
        dnssec: Arc::new(ArcSwap::new(Arc::new(DnssecValidator::from_config(
            &config.dns.dnssec,
        )))),
        dnssec_chain_cache: Arc::new(sito_dnssec::ChainCache::new(None)),
        scoped_upstreams: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        rate_limiters: Arc::new(Mutex::new(Vec::new())),
        listener_manager: Arc::new(tokio::sync::Mutex::new(None)),
        listener_acceptors: Arc::new(tokio::sync::Mutex::new(None)),
        pipeline,
        readiness: Arc::new(sito_api::ReadinessState::default()),
        cert_validity_cache: Arc::new(sito_transport::CertificateValidityCache::new()),
    };

    for upstreams in [None, Some(vec!["ftp://unsupported.example".to_string()])] {
        let clients = sito_clients::ClientsConfig {
            entries: vec![sito_clients::ClientEntryConfig {
                name: "scoped-client".to_string(),
                ids: vec!["10.0.0.1".to_string()],
                group: "default".to_string(),
                ignore_query_log: false,
                ignore_stats: false,
                use_global_upstreams: false,
                upstreams,
                trusted: false,
            }],
            ..Default::default()
        };
        let error = hooks
            .prepare(&config, &clients)
            .await
            .expect_err("an unbuildable scope must abort the staged apply");
        let rendered = error.to_string();
        assert!(
            rendered.contains("scoped-client"),
            "the apply error must name the offending client: {rendered}"
        );
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// D12 runtime ladder: a static certificate that expires while the process is
/// running must make `/health` not-ready, and a replacement must clear the
/// reason without a rebind or restart. The health path re-evaluates the file
/// through the mtime/size cache, so this uses the same helper `/health` calls.
#[test]
fn test_static_tls_readiness_follows_runtime_certificate_changes() {
    fn write_cert(cert_path: &Path, key_path: &Path, not_before_days: i64, not_after_days: i64) {
        let now = time::OffsetDateTime::now_utc();
        let key = rcgen::KeyPair::generate().expect("key pair");
        let mut params = rcgen::CertificateParams::new(vec!["dns.example.com".to_string()])
            .expect("certificate params");
        params.not_before = now + time::Duration::days(not_before_days);
        params.not_after = now + time::Duration::days(not_after_days);
        let cert = params.self_signed(&key).expect("self-signed cert");
        std::fs::write(cert_path, cert.pem()).expect("write cert");
        std::fs::write(key_path, key.serialize_pem()).expect("write key");
    }

    let dir = std::env::temp_dir().join(format!(
        "sito_tls_runtime_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    let mut config = Config::default();
    config.dns.tls = Some(sito_core::config::TlsConfig {
        cert: Some(cert_path.clone()),
        key: Some(key_path.clone()),
        sni_certs: Vec::new(),
    });
    let readiness = sito_api::ReadinessState::default();
    readiness.set_tls_ready();
    let cache = sito_transport::CertificateValidityCache::new();

    write_cert(&cert_path, &key_path, -1, 90);
    sito_api::refresh_tls_certificate_readiness(&readiness, &config, &cache);
    assert!(readiness.tls().ready);
    assert!(readiness.tls().code.is_none());

    write_cert(&cert_path, &key_path, -2, 10);
    std::thread::sleep(Duration::from_millis(20));
    sito_api::refresh_tls_certificate_readiness(&readiness, &config, &cache);
    assert!(
        readiness.tls().ready,
        "an expiring certificate still serves"
    );
    assert_eq!(readiness.tls().code, Some("tls_cert_expiring"));

    write_cert(&cert_path, &key_path, -2, -1);
    std::thread::sleep(Duration::from_millis(20));
    sito_api::refresh_tls_certificate_readiness(&readiness, &config, &cache);
    assert!(
        !readiness.tls().ready,
        "an expired certificate is not ready"
    );
    assert_eq!(readiness.tls().code, Some("tls_cert_expired"));

    // A watcher reload replaces the file; readiness must recover immediately.
    write_cert(&cert_path, &key_path, -1, 90);
    std::thread::sleep(Duration::from_millis(20));
    sito_api::refresh_tls_certificate_readiness(&readiness, &config, &cache);
    assert!(readiness.tls().ready);
    assert!(
        readiness.tls().code.is_none(),
        "a replaced valid certificate must clear the stale reason"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Removing `[tls]` material (or leaving only half of the pair) must clear a
/// stale certificate reason from the previous configuration. Returning early
/// used to leave `/health` not-ready forever after the operator removed TLS.
#[test]
fn test_refresh_tls_readiness_clears_stale_cert_reason_when_material_removed() {
    let readiness = sito_api::ReadinessState::default();
    let cache = sito_transport::CertificateValidityCache::new();

    readiness.set_tls_unavailable("tls_cert_expired", "previously expired");
    let config = Config::default();
    sito_api::refresh_tls_certificate_readiness(&readiness, &config, &cache);
    assert!(readiness.tls().ready);
    assert!(readiness.tls().code.is_none());

    readiness.set_tls_degraded("tls_cert_expiring", "previously expiring");
    let mut incomplete = Config::default();
    incomplete.dns.tls = Some(sito_core::config::TlsConfig {
        cert: Some(Path::new("/etc/sito/certs/dns.crt").to_path_buf()),
        key: None,
        sni_certs: Vec::new(),
    });
    sito_api::refresh_tls_certificate_readiness(&readiness, &incomplete, &cache);
    assert!(readiness.tls().ready);
    assert!(
        readiness.tls().code.is_none(),
        "an incomplete pair must not retain a certificate reason"
    );
}
