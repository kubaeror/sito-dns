#![cfg(test)]

use super::*;

/// Test-only aggregation of the two startup warnings. The production code
/// emits them separately per startup phase, so the combined helper lives
/// here instead of the public API.
fn network_exposure_warnings(config: &Config) -> Vec<String> {
    config
        .web_exposure_warning()
        .into_iter()
        .chain(config.dns_exposure_warning())
        .collect()
}

#[test]
fn test_parse_section_15_example() {
    let toml_str = r#"
config_version = 2

[server]
role = "master"
instance_name = "sito-main"
data_dir = "/var/lib/sito"
log_level = "info"
log_format = "json"

[dns]
bind = ["0.0.0.0", "::"]
port = 53
dot_port = 853
doh_port = 443
doq_port = 853
doh_dedicated_hostname = ""
edns_udp_size = 1232
rate_limit_per_ip = 20
max_tcp_connections = 256

[dns.cache]
enabled = true
size_mb = 64
min_ttl = 60
max_ttl = 86400
negative_ttl_max = 3600
prefetch = true
serve_stale_hours = 12

[dns.dnssec]
validate = true
ntp = []

[upstream]
servers = ["tls://dns1.example", "https://dns2.example/dns-query"]
bootstrap = ["9.9.9.9", "149.112.112.112"]
strategy = "parallel"
timeout_ms = 5000
probe_domain = "example.com"
pool_size = 4

[[upstream.per_domain]]
domains = ["*.lan", "168.192.in-addr.arpa"]
servers = ["192.168.1.1"]

[filtering]
enabled = true
refresh_interval_hours = 24
blocking_mode = "zero_ip"
blocking_ttl = 10
cname_cloaking = true
anti_doh_bypass = "off"
lists = [ { name = "OISD", url = "https://example.com/hosts.txt", enabled = true, refresh_hours = 24 } ]
custom_rules = []

[clients]
entries = []

[rewrites]
auto_ptr = true
entries = []

[web]
port = 8080
bind = "0.0.0.0"

[auth]
session_ttl_hours = 24

[stats]
retention_days = 90

[ha]
replication_port = 8953

[integrations.mikrotik]
enabled = false
"#;
    let config = Config::from_toml_str(toml_str).expect("section 15 config should parse cleanly");
    assert_eq!(config.config_version, 2);
    assert_eq!(config.server.role, "master");
    assert_eq!(config.dns.port, 53);
    assert_eq!(config.dns.cache.size_mb, 64);
    assert_eq!(config.upstream.strategy, UpstreamStrategy::Parallel);
    assert_eq!(config.filtering.blocking_mode, BlockingMode::ZeroIp);
    assert_eq!(config.filtering.lists.len(), 1);
    assert_eq!(config.filtering.lists[0].name, "OISD");
}

#[test]
fn test_ha_slave_readiness_requirements_load_from_config() {
    // These keys must be in the v2 schema map as well as `HaConfig`; without
    // the map entries, startup/check-config rejects them as unknown keys.
    let toml_str = format!(
        "{TEST_BASE}[ha]\nreplication_port = 8953\nrequire_slaves = true\nrequire_all_slaves = true\n"
    );
    let config = Config::from_toml_str(&toml_str)
        .expect("ha.require_slaves/require_all_slaves must be accepted in v2");
    let ha = config.ha.expect("[ha] section");
    assert_eq!(
        ha.get("require_slaves").and_then(toml::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        ha.get("require_all_slaves").and_then(toml::Value::as_bool),
        Some(true)
    );

    // Absent keys keep the documented default (`false`) and remain valid.
    let without = Config::from_toml_str(&format!("{TEST_BASE}[ha]\nreplication_port = 8953\n"))
        .expect("omitting the opt-in keys must stay valid");
    let ha = without.ha.expect("[ha] section");
    assert!(ha.get("require_slaves").is_none());
    assert!(ha.get("require_all_slaves").is_none());
}

#[test]
fn test_ha_promotion_keys_load_through_the_v2_loader() {
    // The full ADR-0010 table must be accepted by the real v2 loader (map +
    // serde), not only by the typed `HaConfig` struct.
    let toml_str = format!(
        "{TEST_BASE}[ha]\n\
         replication_port = 8953\n\
         ping_interval_secs = 30\n\
         \n\
         [ha.promotion]\n\
         enabled = true\n\
         candidate = true\n\
         cluster_id = \"home-dns\"\n\
         node_id = \"sito-node-a\"\n\
         backend = \"witness\"\n\
         lease_ttl_secs = 30\n\
         renew_interval_secs = 10\n\
         heartbeat_timeout_secs = 90\n\
         require_manual_confirmation = false\n\
         reconcile_window_secs = 10\n\
         \n\
         [ha.promotion.witness]\n\
         url = \"https://witness.lan:8954\"\n\
         ca = \"/etc/sito/certs/witness-ca.crt\"\n\
         server_name = \"witness.lan\"\n\
         fingerprint = \"blake3:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\n\
         token_file = \"/etc/sito/witness.token\"\n"
    );
    let config = Config::from_toml_str(&toml_str).expect("promotion table must load");
    let ha = config.ha.expect("[ha] section");
    let promotion = ha.get("promotion").expect("promotion table");
    assert_eq!(
        promotion.get("enabled").and_then(toml::Value::as_bool),
        Some(true)
    );
    let witness = promotion.get("witness").expect("witness table");
    assert_eq!(
        witness.get("url").and_then(toml::Value::as_str),
        Some("https://witness.lan:8954")
    );

    // Disabled promotion with a large ping and no heartbeat key still loads:
    // bounds are only validated by the typed promotion validator.
    let disabled = Config::from_toml_str(&format!(
        "{TEST_BASE}[ha]\nreplication_port = 8953\nping_interval_secs = 30\n[ha.promotion]\nenabled = false\n"
    ))
    .expect("a disabled promotion section must stay inert");
    let promotion = disabled
        .ha
        .expect("[ha]")
        .get("promotion")
        .cloned()
        .expect("promotion table");
    assert_eq!(
        promotion.get("enabled").and_then(toml::Value::as_bool),
        Some(false)
    );

    // Unknown nested promotion keys are rejected by the v2 unknown-key policy.
    let err = Config::from_toml_str(&format!(
        "{TEST_BASE}[ha]\nreplication_port = 8953\n[ha.promotion]\nenabled = false\nbogus = 1\n"
    ))
    .unwrap_err();
    assert!(err.to_string().contains("bogus"), "got: {err}");
    let err = Config::from_toml_str(&format!(
        "{TEST_BASE}[ha]\nreplication_port = 8953\n[ha.promotion.witness]\nbogus = 1\n"
    ))
    .unwrap_err();
    assert!(err.to_string().contains("bogus"), "got: {err}");
}

#[test]
fn test_reject_invalid_config() {
    // Bad config version: v1 must be rejected with the migration hint.
    let bad_ver = "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]";
    let err = Config::from_toml_str(bad_ver).unwrap_err();
    match err {
        ConfigError::UnsupportedVersion {
            found: 1,
            supported: 2,
        } => {}
        other => panic!("expected unsupported config_version, got: {other:?}"),
    }

    // Empty upstream servers
    let empty_up = "config_version = 2\n[upstream]\nservers = []";
    let err = Config::from_toml_str(empty_up).unwrap_err();
    match err {
        ConfigError::Validation { field, .. } => assert_eq!(field, "upstream.servers"),
        other => panic!("expected validation error on upstream.servers, got: {other:?}"),
    }

    // Bad min/max ttl
    let bad_ttl = "config_version = 2\n[dns.cache]\nmin_ttl = 500\nmax_ttl = 100\n[upstream]\nservers = [\"1.1.1.1\"]";
    let err = Config::from_toml_str(bad_ttl).unwrap_err();
    match err {
        ConfigError::Validation { field, .. } => assert_eq!(field, "dns.cache.min_ttl"),
        other => panic!("expected validation error on dns.cache.min_ttl, got: {other:?}"),
    }
}

#[test]
fn test_upstream_ecs_policy_defaults_off_and_parses_forward() {
    let base = "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n";
    let default = Config::from_toml_str(base).expect("default config");
    assert_eq!(default.upstream.ecs, UpstreamEcs::Off);

    let forward =
        Config::from_toml_str(&format!("{base}ecs = \"forward\"\n")).expect("forward config");
    assert_eq!(forward.upstream.ecs, UpstreamEcs::Forward);

    let invalid = Config::from_toml_str(&format!("{base}ecs = \"sometimes\"\n"));
    assert!(invalid.is_err(), "unknown ECS policy must be rejected");
}

/// Regression (audit 6, WP-3.9): two lists with the same `name` silently
/// overwrote each other in the engine; the config must reject them.
#[test]
fn test_filtering_rejects_duplicate_list_names() {
    let toml_str = r#"
config_version = 2
[upstream]
servers = ["1.1.1.1"]

[filtering]
lists = [
    { name = "ads", url = "https://example.com/a.txt" },
    { name = "ads", url = "https://example.com/b.txt" },
]
"#;
    let err = Config::from_toml_str(toml_str).unwrap_err();
    match err {
        ConfigError::Validation { field, .. } => {
            assert_eq!(field, "filtering.lists[1].name");
        }
        other => panic!("expected validation error on filtering.lists[1].name, got: {other:?}"),
    }

    // Distinct names in the same positions stay accepted.
    let ok = r#"
config_version = 2
[upstream]
servers = ["1.1.1.1"]

[filtering]
lists = [
    { name = "ads", url = "https://example.com/a.txt" },
    { name = "trackers", url = "https://example.com/b.txt" },
]
"#;
    Config::from_toml_str(ok).expect("distinct list names must parse");
}

/// P2-41: a client group may only reference configured filter lists. An
/// unknown name would be silently ignored by the engine and disable the
/// category the operator thought they selected.
#[test]
fn test_client_group_lists_must_reference_configured_filter_lists() {
    let toml_str = r#"
config_version = 2
[upstream]
servers = ["1.1.1.1"]

[filtering]
[[filtering.lists]]
name = "ads"
url = "https://example.com/a.txt"

[clients.groups.kids]
lists = ["missing"]
"#;
    let err = Config::from_toml_str(toml_str).expect_err("unknown group list must be rejected");
    match err {
        ConfigError::CrossSection { field, message } => {
            assert_eq!(field, "clients.groups.kids.lists[0]");
            assert!(
                message.contains("unknown filter list 'missing'"),
                "{message}"
            );
        }
        other => panic!("expected cross-section error for the group list, got: {other:?}"),
    }

    let accepted = toml_str.replace("[\"missing\"]", "[\"ads\"]");
    Config::from_toml_str(&accepted).expect("a configured list name must be accepted");
}

#[test]
fn test_blocking_mode_deserialization() {
    let toml_null = "config_version = 2\n[filtering]\nblocking_mode = \"null_rdata\"\n[upstream]\nservers = [\"1.1.1.1\"]";
    let cfg = Config::from_toml_str(toml_null).unwrap();
    assert_eq!(cfg.filtering.blocking_mode, BlockingMode::NullRdata);

    let toml_custom = "config_version = 2\n[filtering]\nblocking_mode = \"custom_ip:192.168.1.50\"\n[upstream]\nservers = [\"1.1.1.1\"]";
    let cfg = Config::from_toml_str(toml_custom).unwrap();
    assert_eq!(
        cfg.filtering.blocking_mode,
        BlockingMode::CustomIp("192.168.1.50".parse().unwrap())
    );

    let toml_refused = "config_version = 2\n[filtering]\nblocking_mode = \"refused\"\n[upstream]\nservers = [\"1.1.1.1\"]";
    let cfg = Config::from_toml_str(toml_refused).unwrap();
    assert_eq!(cfg.filtering.blocking_mode, BlockingMode::Refused);

    let toml_nxdomain = "config_version = 2\n[filtering]\nblocking_mode = \"nxdomain\"\n[upstream]\nservers = [\"1.1.1.1\"]";
    let cfg = Config::from_toml_str(toml_nxdomain).unwrap();
    assert_eq!(cfg.filtering.blocking_mode, BlockingMode::Nxdomain);
}

#[test]
fn test_dnssec_nta_matching() {
    let mut dnssec = DnssecConfig::default();
    dnssec.ntp.push("known-broken.example".to_string());
    dnssec.nta.push("corp.internal.".to_string());

    assert!(dnssec.is_nta("known-broken.example"));
    assert!(dnssec.is_nta("sub.known-broken.example"));
    assert!(dnssec.is_nta("sub.known-broken.example."));
    assert!(dnssec.is_nta("corp.internal"));
    assert!(dnssec.is_nta("host.corp.internal."));
    assert!(!dnssec.is_nta("example.com"));
}

#[test]
fn test_tls_config_validation() {
    let toml_missing_key = r#"
config_version = 2
[upstream]
servers = ["1.1.1.1"]
[tls]
cert = "/path/to/cert.pem"
"#;
    let err = Config::from_toml_str(toml_missing_key).unwrap_err();
    match err {
        ConfigError::Validation { field, .. } => assert_eq!(field, "tls.key"),
        other => panic!("expected tls.key error, got {other:?}"),
    }

    let toml_valid_tls = r#"
config_version = 2
[upstream]
servers = ["1.1.1.1"]
[dns.tls]
cert = "/path/to/cert.pem"
key = "/path/to/key.pem"
"#;
    let cfg = Config::from_toml_str(toml_valid_tls).unwrap();
    assert!(cfg.get_tls_config().is_some());
    assert_eq!(
        cfg.get_tls_config().unwrap().cert.as_deref(),
        Some(std::path::Path::new("/path/to/cert.pem"))
    );
}

#[test]
fn test_cache_config_negative_ttl_validation() {
    let cfg = CacheConfig {
        min_ttl: 300,
        negative_ttl_max: 60, // min_ttl > negative_ttl_max should fail validation
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    match err {
        ConfigError::Validation { field, .. } => {
            assert_eq!(field, "dns.cache.negative_ttl_max");
        }
        other => panic!("expected dns.cache.negative_ttl_max error, got {other:?}"),
    }
}

#[test]
fn test_default_api_token_ttl_is_bounded() {
    let auth = AuthConfig::default();
    assert_eq!(
        auth.token_default_ttl_days, 90,
        "API tokens must expire by default instead of living forever"
    );
    // Explicit opt-out (no expiry) still parses.
    let cfg =
        Config::from_toml_str("config_version = 2\n[auth]\ntoken_default_ttl_days = 0\n").unwrap();
    let parsed: AuthConfig = cfg.auth.unwrap().try_into().unwrap();
    assert_eq!(parsed.token_default_ttl_days, 0);
}

#[test]
fn test_api_token_max_ttl_defaults_and_validation() {
    let auth = AuthConfig::default();
    assert_eq!(
        auth.token_max_ttl_days, 365,
        "new API tokens must be capped at one year by default"
    );
    assert_eq!(auth.token_default_ttl_days, 90);
    auth.validate()
        .expect("the defaults must satisfy the policy");

    // An explicit maximum is accepted up to the documented bound.
    let cfg = Config::from_toml_str(
        "config_version = 2\n[auth]\ntoken_max_ttl_days = 30\ntoken_default_ttl_days = 20\n",
    )
    .expect("a bounded maximum must parse");
    let parsed: AuthConfig = cfg.auth.unwrap().try_into().unwrap();
    assert_eq!(parsed.token_max_ttl_days, 30);
    parsed.validate().expect("default <= max is valid");

    // The default lifetime may not exceed the maximum.
    let err = Config::from_toml_str(
        "config_version = 2\n[auth]\ntoken_max_ttl_days = 30\ntoken_default_ttl_days = 31\n",
    )
    .expect_err("default > max must be rejected");
    assert!(
        err.to_string().contains("auth.token_default_ttl_days"),
        "the error must name the offending default: {err}"
    );

    // `token_max_ttl_days = 0` is the explicit no-maximum opt-out and permits
    // a longer default (including the historical `0` = no expiry).
    for default in [0, 90, 10_000] {
        let parsed = AuthConfig {
            token_max_ttl_days: 0,
            token_default_ttl_days: default,
            ..AuthConfig::default()
        };
        parsed
            .validate()
            .expect("max = 0 must disable the cap entirely");
    }

    // Values above the documented cap are rejected even though 0 is allowed.
    let err = Config::from_toml_str(&format!(
        "config_version = 2\n[auth]\ntoken_max_ttl_days = {}\n",
        MAX_TOKEN_MAX_TTL_DAYS + 1
    ))
    .expect_err("over-cap max must be rejected");
    assert!(
        err.to_string().contains("auth.token_max_ttl_days"),
        "the error must name the field: {err}"
    );
}

#[test]
fn test_api_rate_limit_defaults_parses_and_is_bounded() {
    let auth = AuthConfig::default();
    assert_eq!(
        auth.api_rate_limit_per_minute, 600,
        "the per-account API rate limit must default to 600 requests/minute"
    );

    let cfg = Config::from_toml_str("config_version = 2\n[auth]\napi_rate_limit_per_minute = 10\n")
        .expect("a bounded auth.api_rate_limit_per_minute must parse");
    let parsed: AuthConfig = cfg.auth.unwrap().try_into().unwrap();
    assert_eq!(parsed.api_rate_limit_per_minute, 10);
    parsed.validate().expect("10 requests/minute is valid");

    let disabled =
        Config::from_toml_str("config_version = 2\n[auth]\napi_rate_limit_per_minute = 0\n")
            .expect("0 disables the limit");
    let parsed: AuthConfig = disabled.auth.unwrap().try_into().unwrap();
    assert_eq!(parsed.api_rate_limit_per_minute, 0);
    parsed.validate().expect("0 is an explicit opt-out");

    let too_high = Config::from_toml_str(&format!(
        "config_version = 2\n[auth]\napi_rate_limit_per_minute = {}\n",
        MAX_API_RATE_LIMIT_PER_MINUTE + 1
    ))
    .expect_err("values above the documented cap must be rejected");
    assert!(
        too_high
            .to_string()
            .contains("auth.api_rate_limit_per_minute"),
        "the error must name the field: {too_high}"
    );
}

#[test]
fn test_default_config_doq_port_disabled_and_conflict_free() {
    let cfg = Config::default();
    assert_eq!(cfg.dns.dot_port, 853);
    assert_eq!(
        cfg.dns.doq_port, 0,
        "DoQ must be disabled (port 0) by default to avoid port conflict with DoT"
    );
    assert_ne!(cfg.dns.dot_port, cfg.dns.doq_port);
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_trust_anchor_validation_rejects_malformed_entries() {
    let base = "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n";

    for (anchor, needle) in [
        ("", "must be 'zone:algorithm:base64'"),
        ("com:not-a-number:AQID", "unparsable algorithm"),
        ("com:99:AQID", "unsupported DNSSEC algorithm 99"),
        ("com:13:!!!not-base64!!!", "invalid base64"),
        ("com:13:", "empty key material"),
        ("bad..name:13:AQID", "invalid zone name"),
    ] {
        let toml = format!("{base}[dns.dnssec]\ntrust_anchors = [\"{anchor}\"]\n");
        // `from_toml_str` validates eagerly, so accept the error from
        // either stage.
        let message = match Config::from_toml_str(&toml) {
            Ok(config) => config
                .validate()
                .expect_err(&format!("'{anchor}' must be rejected"))
                .to_string(),
            Err(err) => err.to_string(),
        };
        assert!(
            message.contains(needle),
            "unexpected error for '{anchor}': {message}"
        );
    }

    // A well-formed anchor is accepted.
    let toml = format!("{base}[dns.dnssec]\ntrust_anchors = [\"com:13:AQIDBA==\"]\n");
    let config = Config::from_toml_str(&toml).expect("parses");
    config.validate().expect("valid anchor");
}

/// Base TOML with the required upstream section.
const TEST_BASE: &str = "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n";

fn expect_validation_field(toml: &str, expected: &str) {
    let err = Config::from_toml_str(toml)
        .expect_err(&format!("config must be rejected (expected {expected})"));
    match err {
        ConfigError::Validation { field, .. } => assert_eq!(field, expected),
        other => panic!("expected validation error on {expected}, got {other:?}"),
    }
}

fn expect_cross_section_field(toml: &str, expected: &str) {
    let err = Config::from_toml_str(toml)
        .expect_err(&format!("config must be rejected (expected {expected})"));
    match err {
        ConfigError::CrossSection { field, .. } => assert_eq!(field, expected),
        other => panic!("expected cross-section error on {expected}, got {other:?}"),
    }
}

/// Audit 6 / WP-6.5: the transports size the token-bucket burst as
/// `rate_limit_per_ip * 2`, so the value must be bounded.
#[test]
fn test_rate_limit_per_ip_upper_bound() {
    let over = format!(
        "{TEST_BASE}[dns]\nrate_limit_per_ip = {}\n",
        MAX_RATE_LIMIT_PER_IP + 1
    );
    expect_validation_field(&over, "dns.rate_limit_per_ip");

    let at_bound = format!("{TEST_BASE}[dns]\nrate_limit_per_ip = {MAX_RATE_LIMIT_PER_IP}\n");
    Config::from_toml_str(&at_bound).expect("the documented bound must be accepted");

    let disabled = format!("{TEST_BASE}[dns]\nrate_limit_per_ip = 0\n");
    Config::from_toml_str(&disabled).expect("0 disables rate limiting");
}

/// Audit 6 / WP-6.5: `retention_days = 0` deleted every query-log row on
/// the next sweep instead of being rejected.
#[test]
fn test_stats_retention_days_zero_rejected() {
    expect_validation_field(
        &format!("{TEST_BASE}[stats]\nretention_days = 0\n"),
        "stats.retention_days",
    );
    // The legacy alias is validated through the same path.
    expect_validation_field(
        &format!("{TEST_BASE}[stats]\nquery_log_retention_days = 0\n"),
        "stats.retention_days",
    );
    Config::from_toml_str(&format!("{TEST_BASE}[stats]\nretention_days = 1\n"))
        .expect("retention_days = 1 must be accepted");
}

/// P1-19: rollup retention/client-name keys are optional and safe by
/// default, and a zero rollup retention is rejected.
#[test]
fn test_stats_rollup_retention_defaults_and_validation() {
    let default = Config::from_toml_str(&format!("{TEST_BASE}[stats]\nretention_days = 90\n"))
        .expect("stats defaults must parse");
    let stats = default.get_stats_config();
    assert_eq!(stats.rollup_retention_days, 365);
    assert!(!stats.rollup_client_names);

    expect_validation_field(
        &format!("{TEST_BASE}[stats]\nrollup_retention_days = 0\n"),
        "stats.rollup_retention_days",
    );
    let configured = Config::from_toml_str(&format!(
        "{TEST_BASE}[stats]\nrollup_retention_days = 30\nrollup_client_names = true\n"
    ))
    .expect("explicit rollup settings must parse");
    let stats = configured.get_stats_config();
    assert_eq!(stats.rollup_retention_days, 30);
    assert!(stats.rollup_client_names);
}

/// Audit 6 / WP-6.5: `web.port = 0` requested an ephemeral port that
/// clients cannot discover; it must be rejected.
#[test]
fn test_web_port_zero_rejected() {
    expect_validation_field(&format!("{TEST_BASE}[web]\nport = 0\n"), "web.port");
    Config::from_toml_str(&format!("{TEST_BASE}[web]\nport = 8080\n"))
        .expect("a non-zero web port must be accepted");
}

/// Audit 6 / WP-6.5: two TCP listeners on one port cannot both bind.
#[test]
fn test_dns_rejects_tcp_port_collisions() {
    for (ports, field) in [
        ("dot_port = 9443\ndoh_port = 9443", "dns.doh_port"),
        ("port = 8853\ndot_port = 8853", "dns.dot_port"),
        ("port = 8443\ndoh_port = 8443", "dns.doh_port"),
    ] {
        expect_validation_field(&format!("{TEST_BASE}[dns]\n{ports}\n"), field);
    }
}

/// Audit 6 / WP-6.5: two UDP listeners on one port cannot both bind.
#[test]
fn test_dns_rejects_udp_port_collisions() {
    for (ports, field) in [
        ("doq_port = 8853\ndoh3_port = 8853", "dns.doh3_port"),
        ("port = 8853\ndoq_port = 8853", "dns.doq_port"),
        ("port = 8443\ndoh3_port = 8443", "dns.doh3_port"),
    ] {
        expect_validation_field(&format!("{TEST_BASE}[dns]\n{ports}\n"), field);
    }
}

/// Different transports may share a port number (TCP vs UDP).
#[test]
fn test_dns_allows_cross_transport_port_sharing() {
    let toml = format!(
        "{TEST_BASE}[dns]\ndot_port = 853\ndoq_port = 853\ndoh_port = 443\ndoh3_port = 443\n"
    );
    Config::from_toml_str(&toml)
        .expect("DoT/DoQ and DoH/DoH3 may share a port number across transports");
}

/// Audit 6 / WP-6.5: a zero session TTL creates sessions that are already
/// expired.
#[test]
fn test_auth_session_ttl_zero_rejected() {
    expect_validation_field(
        &format!("{TEST_BASE}[auth]\nsession_ttl_hours = 0\n"),
        "auth.session_ttl_hours",
    );
    Config::from_toml_str(&format!("{TEST_BASE}[auth]\nsession_ttl_hours = 1\n"))
        .expect("a one-hour session TTL must be accepted");
}

/// Audit 6 / WP-6.5: a per-list `refresh_hours = 0` was silently clamped
/// to one hour by the scheduler.
#[test]
fn test_filtering_list_refresh_hours_zero_rejected() {
    let zero = format!(
        "{TEST_BASE}[filtering]\nlists = [{{ name = \"ads\", url = \"https://example.com/a.txt\", refresh_hours = 0 }}]\n"
    );
    expect_validation_field(&zero, "filtering.lists[0].refresh_hours");

    let omitted = format!(
        "{TEST_BASE}[filtering]\nlists = [{{ name = \"ads\", url = \"https://example.com/a.txt\" }}]\n"
    );
    Config::from_toml_str(&omitted).expect("omitting refresh_hours must use the global interval");

    let positive = format!(
        "{TEST_BASE}[filtering]\nlists = [{{ name = \"ads\", url = \"https://example.com/a.txt\", refresh_hours = 24 }}]\n"
    );
    Config::from_toml_str(&positive).expect("a positive refresh_hours must be accepted");
}

/// WP-2.3: refresh intervals are capped at one year so the scheduler's
/// `Instant + Duration` arithmetic cannot panic on an enormous value.
#[test]
fn test_filtering_refresh_hours_capped_at_one_year() {
    let over_global = format!(
        "{TEST_BASE}[filtering]\nrefresh_interval_hours = {}\n",
        MAX_REFRESH_HOURS + 1
    );
    expect_validation_field(&over_global, "filtering.refresh_interval_hours");

    let over_list = format!(
        "{TEST_BASE}[filtering]\nlists = [{{ name = \"ads\", url = \"https://example.com/a.txt\", refresh_hours = {} }}]\n",
        MAX_REFRESH_HOURS + 1
    );
    expect_validation_field(&over_list, "filtering.lists[0].refresh_hours");

    // TOML integers are i64, so exercise the extreme u64 value on the typed
    // struct to prove validation does not overflow in either path.
    let extreme = FilteringConfig {
        refresh_interval_hours: u64::MAX,
        ..Default::default()
    };
    match extreme.validate() {
        Err(ConfigError::Validation { field, .. }) => {
            assert_eq!(field, "filtering.refresh_interval_hours");
        }
        other => panic!("expected validation error on the global interval, got {other:?}"),
    }
    let extreme_list = FilteringConfig {
        lists: vec![FilterListConfig {
            name: "ads".to_string(),
            url: "https://example.com/a.txt".to_string(),
            enabled: true,
            refresh_hours: Some(u64::MAX),
        }],
        ..Default::default()
    };
    match extreme_list.validate() {
        Err(ConfigError::Validation { field, .. }) => {
            assert_eq!(field, "filtering.lists[0].refresh_hours");
        }
        other => panic!("expected validation error on the per-list interval, got {other:?}"),
    }

    let at_cap = format!(
        "{TEST_BASE}[filtering]\nrefresh_interval_hours = {MAX_REFRESH_HOURS}\nlists = [{{ name = \"ads\", url = \"https://example.com/a.txt\", refresh_hours = {MAX_REFRESH_HOURS} }}]\n"
    );
    let accepted = Config::from_toml_str(&at_cap).expect("the one-year cap must be accepted");
    assert_eq!(accepted.filtering.refresh_interval_hours, MAX_REFRESH_HOURS);
    assert_eq!(
        accepted.filtering.lists[0].refresh_hours,
        Some(MAX_REFRESH_HOURS)
    );
}

/// D-07: the per-list download cap is configurable and must stay positive.
#[test]
fn test_filtering_max_list_bytes_default_and_validation() {
    let default = Config::from_toml_str(TEST_BASE).expect("minimal config must parse");
    assert_eq!(
        default.filtering.max_list_bytes,
        64 * 1024 * 1024,
        "the default per-list cap must stay at 64 MiB"
    );

    expect_validation_field(
        &format!("{TEST_BASE}[filtering]\nmax_list_bytes = 0\n"),
        "filtering.max_list_bytes",
    );

    let custom = Config::from_toml_str(&format!("{TEST_BASE}[filtering]\nmax_list_bytes = 1024\n"))
        .expect("a positive max_list_bytes must be accepted");
    assert_eq!(custom.filtering.max_list_bytes, 1024);
}

/// D-11: the regex compile budget is optional but must stay positive.
#[test]
fn test_filtering_regex_compile_budget_default_and_validation() {
    let default = Config::from_toml_str(TEST_BASE).expect("minimal config must parse");
    assert_eq!(
        default.filtering.regex_compile_budget_ms, None,
        "the compile budget must be disabled by default"
    );

    expect_validation_field(
        &format!("{TEST_BASE}[filtering]\nregex_compile_budget_ms = 0\n"),
        "filtering.regex_compile_budget_ms",
    );

    let custom = Config::from_toml_str(&format!(
        "{TEST_BASE}[filtering]\nregex_compile_budget_ms = 250\n"
    ))
    .expect("a positive compile budget must be accepted");
    assert_eq!(custom.filtering.regex_compile_budget_ms, Some(250));
}

/// P1-25: private bootstrap targets are opt-in and default to false.
#[test]
fn test_upstream_allow_private_targets_defaults_false_and_parses() {
    let default = Config::from_toml_str(TEST_BASE).expect("minimal config must parse");
    assert!(
        !default.upstream.allow_private_targets,
        "private bootstrap targets must be denied by default"
    );

    let opted_in =
        Config::from_toml_str("config_version = 2\n[upstream]\nallow_private_targets = true\n")
            .expect("the additive opt-in must parse");
    assert!(opted_in.upstream.allow_private_targets);
}

/// Audit 6 / WP-6.5: an empty or malformed probe domain made every
/// upstream health probe fail at runtime.
#[test]
fn test_upstream_probe_domain_validated() {
    expect_validation_field(
        "config_version = 2\n[upstream]\nprobe_domain = \"\"\n",
        "upstream.probe_domain",
    );
    expect_validation_field(
        "config_version = 2\n[upstream]\nprobe_domain = \"bad..name\"\n",
        "upstream.probe_domain",
    );
    Config::from_toml_str("config_version = 2\n[upstream]\nprobe_domain = \"example.com\"\n")
        .expect("a valid probe domain must be accepted");
}

/// Audit 6 / WP-6.5: per-domain rules without domains can never match and
/// rules without servers fail closed with SERVFAIL.
#[test]
fn test_upstream_per_domain_requires_domains_and_servers() {
    expect_validation_field(
        &format!("{TEST_BASE}[[upstream.per_domain]]\ndomains = []\nservers = [\"192.168.1.1\"]\n"),
        "upstream.per_domain[0].domains",
    );
    expect_validation_field(
        &format!("{TEST_BASE}[[upstream.per_domain]]\ndomains = [\"lan\"]\nservers = []\n"),
        "upstream.per_domain[0].servers",
    );
    Config::from_toml_str(&format!(
        "{TEST_BASE}[[upstream.per_domain]]\ndomains = [\"lan\"]\nservers = [\"192.168.1.1\"]\n"
    ))
    .expect("a complete per-domain rule must be accepted");
}

/// WP-2.7: an unbounded timeout or pool size is a resource-exhaustion foot-gun,
/// so both values are capped while still accepting the documented maxima.
#[test]
fn test_upstream_timeout_and_pool_bounds() {
    for timeout in ["0".to_string(), (MAX_UPSTREAM_TIMEOUT_MS + 1).to_string()] {
        expect_validation_field(
            &format!("{TEST_BASE}timeout_ms = {timeout}\n"),
            "upstream.timeout_ms",
        );
    }
    Config::from_toml_str(&format!(
        "{TEST_BASE}timeout_ms = {MAX_UPSTREAM_TIMEOUT_MS}\n"
    ))
    .expect("the documented timeout maximum must be accepted");

    for pool_size in ["0".to_string(), (MAX_UPSTREAM_POOL_SIZE + 1).to_string()] {
        expect_validation_field(
            &format!("{TEST_BASE}pool_size = {pool_size}\n"),
            "upstream.pool_size",
        );
    }
    Config::from_toml_str(&format!(
        "{TEST_BASE}pool_size = {MAX_UPSTREAM_POOL_SIZE}\n"
    ))
    .expect("the documented pool maximum must be accepted");
}

/// WP-2.7: validation and the manager agree on schemes and paths. Uppercase
/// schemes are accepted (the manager normalizes them), while a path on
/// `udp://`, `tls://` or a bare target is rejected instead of failing startup.
#[test]
fn test_upstream_target_schemes_and_paths() {
    for target in [
        "UDP://1.1.1.1",
        "TLS://1.1.1.1",
        "HTTPS://cloudflare-dns.com/dns-query",
        "QUIC://dns.adguard.com",
    ] {
        Config::from_toml_str(&format!(
            "config_version = 2\n[upstream]\nservers = [\"{target}\"]\n"
        ))
        .unwrap_or_else(|e| panic!("uppercase target '{target}' must be accepted: {e}"));
    }

    for target in [
        "udp://1.1.1.1/dns-query",
        "UDP://1.1.1.1/dns-query",
        "tls://dns.quad9.net/dns-query",
        "1.1.1.1:53/dns-query",
    ] {
        expect_cross_section_field(
            &format!("config_version = 2\n[upstream]\nservers = [\"{target}\"]\n"),
            "upstream.servers[0]",
        );
    }
}

/// WP-2.7: hostname targets need a bootstrap resolver; IP literals do not.
#[test]
fn test_upstream_hostname_target_requires_bootstrap() {
    expect_validation_field(
        "config_version = 2\n[upstream]\nservers = [\"dns.quad9.net\"]\nbootstrap = []\n",
        "upstream.bootstrap",
    );
    expect_validation_field(
        "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\nbootstrap = []\n[[upstream.per_domain]]\ndomains = [\"lan\"]\nservers = [\"dns.internal.example\"]\n",
        "upstream.bootstrap",
    );
    Config::from_toml_str(
        "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\", \"tls://1.0.0.1\"]\nbootstrap = []\n",
    )
    .expect("IP-literal targets must not require a bootstrap resolver");

    expect_validation_field(
        "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\nbootstrap = []\n[clients]\n[[clients.entries]]\nname = \"phone\"\nuse_global_upstreams = false\nupstreams = [\"dns.quad9.net\"]\n",
        "upstream.bootstrap",
    );
}

/// WP-2.7: `UpstreamConfig::validate` itself rejects bad targets so direct
/// callers (API DTO handling, restore) cannot bypass the configuration path.
#[test]
fn test_acl_config_real_loader() {
    let document = format!(
        "{TEST_BASE}\
         [clients]\n\
         default_policy = \"deny\"\n\
         [clients.acl]\n\
         allow = [\"192.168.1.7/24\", \"2001:db8::/64\"]\n\
         deny = [\"192.168.1.128/25\"]\n\
         allow_entry_ids = true\n\
         deny_response = \"drop\"\n"
    );
    let config = Config::from_toml_str(&document).expect("ACL fixture is valid v2");
    let clients = config
        .clients
        .as_ref()
        .and_then(toml::Value::as_table)
        .expect("clients section");
    assert_eq!(
        clients.get("default_policy").and_then(toml::Value::as_str),
        Some("deny")
    );
    let acl = clients
        .get("acl")
        .and_then(toml::Value::as_table)
        .expect("acl table");
    let allow: Vec<&str> = acl
        .get("allow")
        .and_then(toml::Value::as_array)
        .expect("allow array")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    assert_eq!(allow, vec!["192.168.1.7/24", "2001:db8::/64"]);
    assert_eq!(
        acl.get("allow_entry_ids").and_then(toml::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        acl.get("deny_response").and_then(toml::Value::as_str),
        Some("drop")
    );

    // The raw document is what the API/HA sanitizer carries; the loader must
    // retain every key.
    let rendered = toml::to_string_pretty(&config).expect("serialize");
    for expected in [
        "default_policy = \"deny\"",
        "\"192.168.1.7/24\"",
        "\"2001:db8::/64\"",
        "\"192.168.1.128/25\"",
        "allow_entry_ids = true",
        "deny_response = \"drop\"",
    ] {
        assert!(
            rendered.contains(expected),
            "missing {expected} in {rendered}"
        );
    }
}

#[test]
fn test_acl_defaults_are_compatibility_first_through_loader() {
    for document in [
        TEST_BASE.to_string(),
        format!("{TEST_BASE}[clients]\n"),
        format!("{TEST_BASE}[clients]\nentries = []\n"),
    ] {
        let config = Config::from_toml_str(&document).expect("omitted ACL is valid");
        let clients = config.clients.as_ref().and_then(toml::Value::as_table);
        // Omitted keys use their typed defaults; the loader must not write
        // them and must not treat the document as ACL-configured.
        assert!(
            clients.is_none_or(|table| !table.contains_key("default_policy")),
            "the loader must not materialize default_policy"
        );
        assert!(
            clients.is_none_or(|table| !table.contains_key("acl")),
            "the loader must not materialize [clients.acl]"
        );
    }
}

#[test]
fn test_acl_config_rejections() {
    for (document, expected_key, expected_value) in [
        (
            "[clients]\ndefault_policy = \"block\"\n".to_string(),
            "clients.default_policy",
            "block",
        ),
        (
            "[clients]\ndefault_policy = true\n".to_string(),
            "clients.default_policy",
            "allow",
        ),
        (
            "[clients.acl]\ndeny_response = \"silent\"\n".to_string(),
            "clients.acl.deny_response",
            "silent",
        ),
        (
            "[clients.acl]\nallow_entry_ids = \"yes\"\n".to_string(),
            "clients.acl.allow_entry_ids",
            "boolean",
        ),
        (
            "[clients.acl]\nallow = [\"192.0.2.0/33\"]\n".to_string(),
            "clients.acl.allow[0]",
            "192.0.2.0/33",
        ),
        (
            "[clients.acl]\nallow = [\"2001:db8::/129\"]\n".to_string(),
            "clients.acl.allow[0]",
            "2001:db8::/129",
        ),
        (
            "[clients.acl]\nallow = [\"192.168.1.7/24\", \"192.168.1.0/24\"]\n".to_string(),
            "clients.acl.allow[1]",
            "192.168.1.0/24",
        ),
        (
            "[clients.acl]\nallow = [\"192.0.2.0/24\"]\ndeny = [\"192.0.2.0/24\"]\n".to_string(),
            "clients.acl.deny",
            "192.0.2.0/24",
        ),
        (
            "[clients]\n[[clients.entries]]\nname = \"broken\"\nids = [\"192.0.2.5/\"]\n"
                .to_string(),
            "clients.entries[0].ids[0]",
            "192.0.2.5/",
        ),
    ] {
        let toml = format!("{TEST_BASE}{document}");
        let err = Config::from_toml_str(&toml).expect_err("must be rejected");
        let text = err.to_string();
        assert!(
            text.contains(expected_key),
            "error must name {expected_key}: {text}"
        );
        assert!(
            text.contains(expected_value),
            "error must name {expected_value}: {text}"
        );
    }

    let too_many: Vec<String> = (0..=1024)
        .map(|i| format!("\"198.51.{}.{}/32\"", 100 + i / 256, i % 256))
        .collect();
    let document = format!(
        "{TEST_BASE}[clients.acl]\nallow = [{}]\n",
        too_many.join(", ")
    );
    let err = Config::from_toml_str(&document).expect_err("cap is enforced");
    assert!(err.to_string().contains("clients.acl.allow"), "{err}");
    assert!(err.to_string().contains("1024"), "{err}");
}

#[test]
fn test_acl_config_save_does_not_materialize_default_policy() {
    // The API persists the raw `Config`; a save that did not explicitly build
    // the ACL must not add `default_policy` merely because the typed default
    // is allow.
    let document = format!("{TEST_BASE}[clients]\nentries = []\n");
    let config = Config::from_toml_str(&document).expect("valid");
    let rendered = toml::to_string_pretty(&config).expect("serialize");
    assert!(
        !rendered.contains("default_policy"),
        "an ordinary save must not materialize the key: {rendered}"
    );
    assert!(
        !rendered.contains("[clients.acl]"),
        "an ordinary save must not materialize [clients.acl]: {rendered}"
    );

    // Explicit values are preserved byte-for-byte at the value level.
    let explicit = format!(
        "{TEST_BASE}[clients]\ndefault_policy = \"deny\"\n[clients.acl]\nallow = [\"192.0.2.0/24\"]\n"
    );
    let config = Config::from_toml_str(&explicit).expect("valid");
    let rendered = toml::to_string_pretty(&config).expect("serialize");
    assert!(rendered.contains("default_policy = \"deny\""));
    assert!(rendered.contains("\"192.0.2.0/24\""));
}

#[test]
fn test_acl_config_load_full_fixture() {
    let dir = std::env::temp_dir().join(format!("sito-acl-load-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        format!(
            "{TEST_BASE}\
             [clients]\n\
             default_policy = \"deny\"\n\
             [clients.acl]\n\
             allow = [\"127.0.0.1/32\", \"::1/128\", \"192.168.1.0/24\"]\n\
             deny = [\"192.168.1.128/25\"]\n\
             allow_entry_ids = false\n\
             deny_response = \"refused\"\n"
        ),
    )
    .unwrap();

    let config = Config::load(&path).expect("Config::load accepts the full ACL fixture");
    let clients = config
        .clients
        .as_ref()
        .and_then(toml::Value::as_table)
        .expect("clients table");
    assert_eq!(
        clients.get("default_policy").and_then(toml::Value::as_str),
        Some("deny")
    );
    let acl = clients
        .get("acl")
        .and_then(toml::Value::as_table)
        .expect("acl table");
    assert_eq!(
        acl.get("deny_response").and_then(toml::Value::as_str),
        Some("refused")
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_acl_rollback_without_keys_preserves_allow() {
    // A pre-ACL document (or a rollback that removes the additive keys) must
    // load with the compatibility default and no ACL warnings.
    let rollback = format!("{TEST_BASE}[clients]\nentries = []\n");
    let config = Config::from_toml_str(&rollback).expect("pre-ACL document is valid");
    let clients = config.clients.as_ref().and_then(toml::Value::as_table);
    assert!(
        clients.is_none_or(|table| !table.contains_key("default_policy")),
        "rollback must not synthesize a policy"
    );
    assert!(clients.is_none_or(|table| !table.contains_key("acl")));

    let mut wildcard = config;
    wildcard.dns.bind = vec!["0.0.0.0".parse().unwrap()];
    let warning = wildcard.dns_exposure_warning().expect("wildcard warns");
    assert!(
        warning.contains("clients.default_policy is \"allow\""),
        "{warning}"
    );
    assert!(!warning.contains("catch-all allow"), "{warning}");
}

#[test]
fn test_acl_deny_catch_all_allow_is_reported_as_open() {
    for extra in [
        "[clients]\ndefault_policy = \"deny\"\n[clients.acl]\nallow = [\"0.0.0.0/0\"]\n",
        "[clients]\ndefault_policy = \"deny\"\n[clients.acl]\nallow_entry_ids = true\n[[clients.entries]]\nname = \"all\"\nids = [\"::/0\"]\n",
    ] {
        let config = Config::from_toml_str(&format!("{TEST_BASE}{extra}")).unwrap();
        let mut config = config;
        config.dns.bind = vec!["0.0.0.0".parse().unwrap()];
        let warning = config.dns_exposure_warning().expect("wildcard warns");
        assert!(
            warning.contains("catch-all allow"),
            "a deny policy with a catch-all allow is still open: {warning}"
        );
    }
}

#[test]
fn test_acl_deny_effective_exposure_warning_names_acl() {
    let mut config = Config::default();
    config.dns.bind = vec!["0.0.0.0".parse().unwrap(), "::".parse().unwrap()];
    let allow = config.dns_exposure_warning().expect("wildcard bind warns");
    assert!(allow.contains("any source not matched"), "{allow}");

    config.clients = Some(toml::from_str("default_policy = \"deny\"\n").unwrap());
    let deny = config
        .dns_exposure_warning()
        .expect("wildcard bind still warns");
    assert!(
        deny.contains("active DNS client admission control"),
        "{deny}"
    );
    assert!(!deny.contains("accept queries from any source"), "{deny}");
}

#[test]
fn test_upstream_config_validate_checks_targets_directly() {
    let mut config = UpstreamConfig {
        servers: vec!["udp://1.1.1.1/dns-query".to_string()],
        ..UpstreamConfig::default()
    };
    assert!(
        config.validate().is_err(),
        "a path on a UDP target must be rejected by UpstreamConfig::validate"
    );

    config.servers = vec!["TLS://1.1.1.1".to_string()];
    config.validate().expect("uppercase schemes must validate");

    config.servers = vec!["dns.quad9.net".to_string()];
    config.bootstrap.clear();
    assert!(
        config.validate().is_err(),
        "a hostname target without a bootstrap resolver must be rejected"
    );

    config.servers = vec!["1.1.1.1".to_string()];
    config
        .validate()
        .expect("an IP literal does not need a bootstrap resolver");
}

/// F1: an absent weight list means one unit of weight per server, and the
/// default configuration must keep its pre-weight on-disk bytes.
#[test]
fn test_upstream_weights_default_to_one_without_changing_config_bytes() {
    let config = Config::default();
    assert_eq!(config.upstream.weights, Vec::<u32>::new());
    assert_eq!(
        config.upstream.effective_weights(),
        vec![DEFAULT_UPSTREAM_WEIGHT; config.upstream.servers.len()]
    );
    assert_eq!(config.upstream.effective_weight(0), DEFAULT_UPSTREAM_WEIGHT);

    let rendered = toml::to_string_pretty(&config).expect("serialize default config");
    assert!(
        !rendered.contains("weights"),
        "a default configuration must not materialize the weights key:\n{rendered}"
    );

    // Explicitly re-serializing a parsed weight-less document is also stable.
    let parsed = Config::from_toml_str(TEST_BASE).expect("weight-less config is valid");
    let rendered = toml::to_string_pretty(&parsed).expect("serialize parsed config");
    assert!(!rendered.contains("weights"), "{rendered}");
}

/// F1: weights are index-aligned with `servers`, bounded 1..=100, and a weight
/// of 0 is rejected rather than silently disabling the upstream.
#[test]
fn test_upstream_weights_validate_alignment_and_bounds() {
    let weighted =
        "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\", \"1.0.0.1\"]\nweights = [3, 1]\n";
    let config = Config::from_toml_str(weighted).expect("valid weights");
    assert_eq!(config.upstream.weights, vec![3, 1]);
    assert_eq!(config.upstream.effective_weights(), vec![3, 1]);

    expect_validation_field(
        "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\nweights = [0]\n",
        "upstream.weights[0]",
    );
    expect_validation_field(
        "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\nweights = [101]\n",
        "upstream.weights[0]",
    );
    expect_validation_field(
        "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\", \"1.0.0.1\"]\nweights = [2]\n",
        "upstream.weights",
    );
    expect_validation_field(
        "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\", \"1.0.0.1\"]\nweights = [1, 2, 3]\n",
        "upstream.weights",
    );

    // The error must name the offending value so a typo is actionable.
    let err = Config::from_toml_str(
        "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\nweights = [0]\n",
    )
    .expect_err("zero weight is rejected");
    let rendered = err.to_string();
    assert!(
        rendered.contains("upstream.weights[0]") && rendered.contains('0'),
        "unexpected error: {rendered}"
    );

    // The documented bounds themselves are accepted.
    let at_bounds = format!(
        "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\", \"1.0.0.1\"]\nweights = [1, {MAX_UPSTREAM_WEIGHT}]\n"
    );
    Config::from_toml_str(&at_bounds).expect("1 and the upper bound are accepted");
}

/// F1: per-domain rules carry their own index-aligned weights with the same
/// bounds and error paths.
#[test]
fn test_per_domain_upstream_weights_validate_and_round_trip() {
    let document = "config_version = 2\n\
        [upstream]\n\
        servers = [\"1.1.1.1\"]\n\
        [[upstream.per_domain]]\n\
        domains = [\"lan\"]\n\
        servers = [\"192.168.1.1\", \"192.168.1.2\"]\n\
        weights = [4, 1]\n";
    let config = Config::from_toml_str(document).expect("valid per-domain weights");
    assert_eq!(config.upstream.per_domain[0].weights, vec![4, 1]);
    assert_eq!(
        config.upstream.per_domain[0].effective_weights(),
        vec![4, 1]
    );
    let rendered = toml::to_string_pretty(&config).expect("serialize");
    assert!(rendered.contains("weights = ["), "{rendered}");
    let reparsed = Config::from_toml_str(&rendered).expect("round trip");
    assert_eq!(reparsed.upstream.per_domain[0].weights, vec![4, 1]);

    expect_validation_field(
        "config_version = 2\n\
         [upstream]\n\
         servers = [\"1.1.1.1\"]\n\
         [[upstream.per_domain]]\n\
         domains = [\"lan\"]\n\
         servers = [\"192.168.1.1\"]\n\
         weights = [0]\n",
        "upstream.per_domain[0].weights[0]",
    );
    expect_validation_field(
        "config_version = 2\n\
         [upstream]\n\
         servers = [\"1.1.1.1\"]\n\
         [[upstream.per_domain]]\n\
         domains = [\"lan\"]\n\
         servers = [\"192.168.1.1\", \"192.168.1.2\"]\n\
         weights = [2]\n",
        "upstream.per_domain[0].weights",
    );
}

/// F1: weights survive the loader/serializer round trip and remain aligned
/// with the server list (the utilities/UI edit the same document).
#[test]
fn test_upstream_weights_round_trip_through_loader() {
    let document =
        "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\", \"1.0.0.1\"]\nweights = [5, 2]\n";
    let config = Config::from_toml_str(document).expect("valid weighted config");
    let rendered = toml::to_string_pretty(&config).expect("serialize weighted config");
    assert!(
        rendered.contains("weights = [\n    5,\n    2,\n]")
            || rendered.contains("weights = [5, 2]"),
        "{rendered}"
    );

    let reparsed = Config::from_toml_str(&rendered).expect("reload serialized weights");
    assert_eq!(reparsed.upstream.servers, config.upstream.servers);
    assert_eq!(reparsed.upstream.weights, vec![5, 2]);
}

/// 1.9.2 keeps the historical wildcard defaults, so startup must tell the
/// operator that both the plain-HTTP admin UI and the DNS listeners are
/// reachable beyond loopback (fail-closed visibility, truthful default).
#[test]
fn test_default_config_reports_web_and_dns_exposure() {
    let warnings = network_exposure_warnings(&Config::default());
    // 2.0 safe default: the admin UI binds loopback, so only the wildcard
    // DNS listeners are exposed. An operator who exposes the UI still gets
    // the admin warning (covered by the TLS/proxy tests below).
    assert_eq!(
        warnings.len(),
        1,
        "only the wildcard DNS listener is exposed by default: {warnings:?}"
    );
    assert!(
        warnings.iter().any(|w| w.contains("DNS listeners")
            && w.contains("0.0.0.0")
            && w.contains("any source")),
        "missing DNS exposure warning: {warnings:?}"
    );
    let mut exposed = Config::default();
    let mut web = exposed.get_web_config();
    web.bind = IpAddr::from_str("0.0.0.0").expect("valid wildcard");
    exposed.set_web_config(web);
    assert!(
        network_exposure_warnings(&exposed)
            .iter()
            .any(|w| w.contains("admin web UI") && w.contains("0.0.0.0:8080")),
        "an explicitly wildcard admin bind must still warn"
    );
}

/// Loopback listeners are not exposed, and a disabled web UI must never
/// produce an admin warning.
#[test]
fn test_loopback_and_disabled_web_do_not_warn() {
    let mut config = Config::default();
    config.dns.bind = vec![IpAddr::from_str("127.0.0.1").expect("valid loopback")];
    let mut web = config.get_web_config();
    web.bind = IpAddr::from_str("127.0.0.1").expect("valid loopback");
    config.set_web_config(web);
    assert_eq!(
        network_exposure_warnings(&config),
        Vec::<String>::new(),
        "loopback-only listeners must not warn"
    );

    let mut disabled = Config::default();
    disabled.dns.bind = vec![IpAddr::from_str("127.0.0.1").expect("valid loopback")];
    let mut web = disabled.get_web_config();
    web.enabled = false;
    web.bind = IpAddr::from_str("0.0.0.0").expect("valid wildcard");
    disabled.set_web_config(web);
    assert!(
        network_exposure_warnings(&disabled).is_empty(),
        "a disabled web UI must not warn about admin exposure"
    );
}

/// An explicit TLS declaration makes a non-loopback admin bind an
/// intentional reverse-proxy deployment. An explicit `http://` public URL
/// overrides the proxy flag; only `https://` (or the proxy flag when no
/// public URL is set) suppresses the plaintext warning.
#[test]
fn test_tls_reverse_proxy_declaration_suppresses_web_warning() {
    let https_proxy = format!(
        "{TEST_BASE}[dns]\nbind = [\"127.0.0.1\"]\n[web]\nbind = \"0.0.0.0\"\npublic_url = \"https://dns.example.com\"\ntls_terminated_by_proxy = true\n"
    );
    let config = Config::from_toml_str(&https_proxy).expect("valid config");
    assert!(
        network_exposure_warnings(&config).is_empty(),
        "HTTPS reverse proxy declaration must suppress the plaintext warning"
    );

    let proxy_flag_only = format!(
        "{TEST_BASE}[dns]\nbind = [\"127.0.0.1\"]\n[web]\nbind = \"0.0.0.0\"\ntls_terminated_by_proxy = true\n"
    );
    let config = Config::from_toml_str(&proxy_flag_only).expect("valid config");
    assert!(
        network_exposure_warnings(&config).is_empty(),
        "tls_terminated_by_proxy without public_url must suppress the warning"
    );

    let http_public_url = format!(
        "{TEST_BASE}[dns]\nbind = [\"127.0.0.1\"]\n[web]\nbind = \"0.0.0.0\"\npublic_url = \"http://dns.example.com:8080\"\ntls_terminated_by_proxy = true\n"
    );
    let config = Config::from_toml_str(&http_public_url).expect("valid config");
    assert!(
        network_exposure_warnings(&config)
            .iter()
            .any(|w| w.contains("admin web UI")),
        "an explicit http:// public URL must still warn even with the proxy flag"
    );
}

/// D12: bootstrap serving is opt-in and defaults to fail-closed.
#[test]
fn test_acme_allow_bootstrap_cert_defaults_false() {
    let default: AcmeConfig = toml::from_str("enabled = true\ndomains = [\"dns.example.com\"]")
        .expect("parse default acme config");
    assert!(
        !default.allow_bootstrap_cert,
        "bootstrap certificate serving must be disabled by default"
    );

    let opted_in: AcmeConfig = toml::from_str(
        "enabled = true\ndomains = [\"dns.example.com\"]\nallow_bootstrap_cert = true",
    )
    .expect("parse opted-in acme config");
    assert!(opted_in.allow_bootstrap_cert);
}

/// Warnings are written to logs; they must never echo credentials or
/// tokens from unrelated configuration sections.
#[test]
fn test_exposure_warnings_do_not_leak_secrets() {
    let config = Config::from_toml_str(&format!(
            "{TEST_BASE}[dns]\nbind = [\"0.0.0.0\"]\n[web]\nbind = \"0.0.0.0\"\npublic_url = \"http://secret-user:secret-pass@example.test:8080\"\n[ha]\nslave_token = \"top-secret-token\"\n"
        ))
        .expect("valid config");
    let rendered = network_exposure_warnings(&config).join("\n");
    for secret in ["secret-user", "secret-pass", "top-secret-token"] {
        assert!(
            !rendered.contains(secret),
            "warning leaked '{secret}': {rendered}"
        );
    }
}

/// Builds a valid v2 document that sets every field known to the schema.
/// Kept in the test module so the map-drift test cannot silently skip a
/// section.
const SCHEMA_FIXTURE: &str = r#"
config_version = 2

[server]
role = "master"
instance_name = "sito-main"
data_dir = "/var/lib/sito"
log_level = "info"
log_format = "json"
update_require_signature = true

[dns]
bind = ["127.0.0.1"]
port = 5353
dot_port = 853
doh_port = 8443
doq_port = 8853
doh3_port = 8444
doh_dedicated_hostname = "dns.example.com"
dot_padding = true
allow_plaintext_doh = false
edns_udp_size = 1232
rate_limit_per_ip = 20
max_tcp_connections = 256

[dns.cache]
enabled = true
size_mb = 64
min_ttl = 60
max_ttl = 86400
negative_ttl_max = 3600
prefetch = true
serve_stale_hours = 12

[dns.dnssec]
mode = "validate"
validate = true
ntp = ["ntp.example.com"]
nta = ["nta.example.com"]
trust_anchors = ["example.:13:AQIDBA=="]

[dns.tls]
cert = "/etc/sito/cert.pem"
key = "/etc/sito/key.pem"

[[dns.tls.sni_certs]]
domain = "dot.example.com"
cert = "/etc/sito/sni.pem"
key = "/etc/sito/sni.key"

[tls]
cert = "/etc/sito/cert.pem"
key = "/etc/sito/key.pem"

[[tls.sni_certs]]
domain = "tls.example.com"
cert = "/etc/sito/sni.pem"
key = "/etc/sito/sni.key"

[acme]
enabled = true
email = "ops@example.com"
domains = ["dns.example.com"]
staging = false
cache_dir = "/var/lib/sito/acme"
http_port = 8180
allow_bootstrap_cert = false

[upstream]
servers = ["tls://dns.quad9.net"]
bootstrap = ["9.9.9.9"]
strategy = "failover"
timeout_ms = 5000
probe_domain = "example.com"
pool_size = 4
allow_private_targets = false
ecs = "off"
weights = [3]

[[upstream.per_domain]]
domains = ["lan"]
servers = ["192.168.1.1"]
weights = [2]

[filtering]
enabled = true
refresh_interval_hours = 24
blocking_mode = "zero_ip"
blocking_ttl = 10
cname_cloaking = true
fail_closed = true
anti_doh_bypass = "off"
max_rules = 2000000
max_list_bytes = 67108864
allow_empty_list = false
custom_rules = ["0.0.0.0 ads.example.com"]
regex_compile_budget_ms = 250

[[filtering.lists]]
name = "ads"
url = "https://example.com/hosts.txt"
enabled = true
refresh_hours = 24

[privacy]
anonymize_querylog = false

[web]
enabled = true
bind = "127.0.0.1"
port = 9090
trusted_proxies = ["10.0.0.1"]
metrics_auth = true
public_url = "https://dns.example.com"
tls_terminated_by_proxy = true
acme_enabled = true
acme_email = "legacy@example.com"
acme_domains = ["legacy.example.com"]
acme_staging = false
acme_cache_dir = "/var/lib/sito/legacy-acme"

[auth]
session_ttl_hours = 24
login_rate_limit = 5
session_persist = true
token_default_ttl_days = 90
token_max_ttl_days = 365
api_rate_limit_per_minute = 600

[stats]
retention_days = 90
rollup_retention_days = 365
rollup_client_names = false

[clients]
timezone = "UTC"
trust_routeros_lease_names = false
trust_arp = true
default_policy = "deny"

[clients.acl]
allow = ["192.168.1.0/24", "::1/128"]
deny = ["192.168.1.128/25"]
allow_entry_ids = true
deny_response = "drop"

[[clients.entries]]
name = "phone"
ids = ["192.168.1.20"]
group = "kids"
ignore_query_log = false
ignore_stats = false
use_global_upstreams = true
upstreams = ["1.1.1.1"]
trusted = false

[clients.groups.kids]
description = "children"
filtering = true
lists = ["ads"]
custom_rules = ["||fortnite.com^"]
safe_search = true
safe_search_youtube = "strict"
parental = true
parental_categories = ["adult"]
schedule_enabled = true
schedule = "0 0 15-21 * * MON-FRI"

[[clients.groups.kids.blocked_services]]
service = "tiktok"
schedule = "0 0 15-21 * * MON-FRI"

[clients.client_id_secrets]
phone = "change-me"

[rewrites]
auto_ptr = true
ttl = 60

[[rewrites.entries]]
domain = "printer.lan"
id = "r1"
type = "A"
answer = "192.168.1.50"
exception_clients = ["phone"]

[ha]
replication_port = 8953
listen_addr = "0.0.0.0"
master_url = "wss://192.168.1.10:8953"
master_fingerprint = "blake3:abc"
master_pubkey = "abc"
cert = "/etc/sito/ha.crt"
key = "/etc/sito/ha.key"
ca = "/etc/sito/ha-ca.crt"
pinned_slave_fingerprints = ["blake3:def"]
slave_token = "token"
allow_unpinned_tls = false
allow_insecure_ws = false
require_slaves = true
require_all_slaves = true
stats_interval_secs = 30
ping_interval_secs = 15

[ha.promotion]
enabled = false
candidate = false
cluster_id = "home-dns"
node_id = "sito-node-a"
backend = "witness"
lease_ttl_secs = 30
renew_interval_secs = 10
heartbeat_timeout_secs = 90
require_manual_confirmation = false
reconcile_window_secs = 10

[ha.promotion.witness]
url = "https://witness.lan:8954"
ca = "/etc/sito/certs/witness-ca.crt"
server_name = "witness.lan"
fingerprint = "blake3:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
token_file = "/etc/sito/witness.token"

[integrations.mikrotik]
enabled = false
url = "https://192.168.1.1"
token_env = "MIKROTIK_API_TOKEN"
username = "api"
password = "secret"
password_env = "MIKROTIK_PASSWORD"
interval_s = 300
allow_invalid_certs = false

[integrations.lists]
refresh_hours = 24

[integrations.lists.categories.adult]
url = "https://lists.example.com/adult.txt"
refresh_hours = 24
license = "CC0-1.0"
"#;

fn collect_leaf_paths(prefix: &str, value: &toml::Value, out: &mut Vec<String>) {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                collect_leaf_paths(&path, child, out);
            }
        }
        toml::Value::Array(items) => {
            if items.iter().any(toml::Value::is_table) {
                let path = format!("{prefix}[]");
                for item in items {
                    collect_leaf_paths(&path, item, out);
                }
            } else {
                out.push(prefix.to_string());
            }
        }
        _ => out.push(prefix.to_string()),
    }
}

/// WP-1.3 acceptance: the checked-in map and the serde schema must not
/// diverge. Every serialized field needs a map entry, and every `kept`
/// entry must be reachable from the comprehensive fixture.
#[test]
fn test_config_map_covers_every_serde_field() {
    use crate::config_schema::{FieldStatus, schema};

    let config = Config::from_toml_str(SCHEMA_FIXTURE).expect("schema fixture is valid v2");
    let document = toml::to_string_pretty(&config).expect("serialize config");
    let table: toml::Table = toml::from_str(&document).expect("valid TOML");
    let mut paths = Vec::new();
    collect_leaf_paths("", &toml::Value::Table(table), &mut paths);

    let map = schema();
    for path in &paths {
        let Some(field) = map.matching_field(path) else {
            panic!(
                "serde field '{path}' is missing from config-v1-to-v2-map.toml; add a [[field]] entry and document it"
            );
        };
        assert!(
            matches!(field.status, FieldStatus::Kept | FieldStatus::Deprecated),
            "serde field '{path}' has v2-incompatible map status {:?}",
            field.status
        );
    }
    for field in map.fields() {
        if field.status != FieldStatus::Kept {
            continue;
        }
        assert!(
            paths.iter().any(|path| map
                .matching_field(path)
                .is_some_and(|m| m.path == field.path)),
            "map field '{}' is not produced by the schema fixture; add it to the fixture (and the Rust struct)",
            field.path
        );
    }
}
