//! WP-1.3: config v2 schema, one validator, and v1→v2 migration.
//!
//! These tests exercise the public `sito-core` contract. Map/schema drift
//! tests live next to the embedded map in `config_schema.rs`.

use sito_core::ConfigError;
use sito_core::config::{Config, MigrationOptions};

const TEST_BASE: &str = "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n";

fn expect_unknown(toml: &str, key: &str) {
    let err = Config::from_toml_str(toml).expect_err("unknown key must be rejected");
    match err {
        ConfigError::UnknownKey { key: actual, .. } => {
            assert_eq!(actual, key, "unexpected unknown key");
        }
        other => panic!("expected UnknownKey for '{key}', got {other:?}"),
    }
}

fn expect_cross_section(toml: &str, field: &str) {
    let err = Config::from_toml_str(toml).expect_err("invalid config must be rejected");
    match err {
        ConfigError::CrossSection { field: actual, .. } => assert_eq!(actual, field),
        other => panic!("expected CrossSection on '{field}', got {other:?}"),
    }
}

#[test]
fn test_config_v2_is_the_default_and_only_accepted_version() {
    // New installs default to v2, but a *file* must say so explicitly: an
    // unversioned document was a valid v1 file and must go through migration.
    assert_eq!(Config::default().config_version, 2);
    let err = Config::from_toml_str("").expect_err("an unversioned file is treated as v1");
    assert!(matches!(
        err,
        ConfigError::UnsupportedVersion {
            found: 1,
            supported: 2
        }
    ));
    let err = Config::from_toml_str("[upstream]\nservers = [\"1.1.1.1\"]\n")
        .expect_err("an unversioned file is treated as v1");
    assert!(
        err.to_string()
            .contains("sito config migrate --from v1 --to v2 --backup")
    );

    let explicit = Config::from_toml_str(TEST_BASE).expect("v2 is accepted");
    assert_eq!(explicit.config_version, 2);
}

#[test]
fn test_v1_document_is_rejected_with_a_clear_migration_command() {
    let err = Config::from_toml_str("config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n")
        .expect_err("v1 must be rejected by the normal parser");
    let message = err.to_string();
    assert!(
        message.contains("sito config migrate --from v1 --to v2 --backup"),
        "the v1 rejection must name the migration command: {message}"
    );
    assert!(
        matches!(
            err,
            ConfigError::UnsupportedVersion {
                found: 1,
                supported: 2
            }
        ),
        "expected UnsupportedVersion, got {err:?}"
    );

    let future =
        Config::from_toml_str("config_version = 99\n[upstream]\nservers = [\"1.1.1.1\"]\n")
            .expect_err("an unknown future version must be rejected");
    assert!(matches!(
        future,
        ConfigError::UnsupportedVersion { found: 99, .. }
    ));
}

#[test]
fn test_unknown_keys_are_rejected_everywhere() {
    // Top-level typo (D5 [upsteam] example).
    expect_unknown(
        "config_version = 2\n[upsteam]\nservers = [\"1.1.1.1\"]\n",
        "upsteam",
    );
    // Typed section.
    expect_unknown(&format!("{TEST_BASE}[dns]\nbogus = true\n"), "dns.bogus");
    expect_unknown(
        &format!("{TEST_BASE}[dns.cache]\nbogus = 1\n"),
        "dns.cache.bogus",
    );
    // Legacy raw sections are checked by the map walk.
    expect_unknown(
        &format!("{TEST_BASE}[clients]\nbogus = 1\n"),
        "clients.bogus",
    );
    expect_unknown(
        &format!("{TEST_BASE}[web]\nupsteam = true\n"),
        "web.upsteam",
    );
    expect_unknown(
        &format!("{TEST_BASE}[integrations.lists]\nbogus = 1\n"),
        "integrations.lists.bogus",
    );
    expect_unknown(
        &format!("{TEST_BASE}[clients]\n[[clients.entries]]\nname = \"phone\"\nbogus = 1\n"),
        "clients.entries[0].bogus",
    );

    // Removed v1 keys are named explicitly instead of being silently ignored.
    let removed = Config::from_toml_str(&format!(
        "{TEST_BASE}[auth]\nadmin_password_hash = \"secret\"\n"
    ))
    .expect_err("removed key must be rejected");
    assert!(
        removed.to_string().contains("removed"),
        "removed keys must explain the migration: {removed}"
    );
}

#[test]
fn test_duplicate_dns_bind_addresses_are_rejected() {
    expect_cross_section(
        &format!("{TEST_BASE}[dns]\nbind = [\"127.0.0.1\", \"127.0.0.1\"]\n"),
        "dns.bind",
    );
    // Distinct addresses remain accepted, including dual stack.
    Config::from_toml_str(&format!(
        "{TEST_BASE}[dns]\nbind = [\"127.0.0.1\", \"::1\"]\n"
    ))
    .expect("distinct binds are valid");
}

#[test]
fn test_web_listener_port_conflict_is_rejected() {
    // DNS binds the wildcard address, so a web listener on the same TCP port
    // cannot bind.
    expect_cross_section(
        &format!("{TEST_BASE}[dns]\nport = 8080\n[web]\nbind = \"127.0.0.1\"\nport = 8080\n"),
        "web.port",
    );
    // A web port that only collides with an encrypted TCP listener is also a
    // conflict.
    expect_cross_section(
        &format!("{TEST_BASE}[dns]\ndot_port = 8443\n[web]\nbind = \"127.0.0.1\"\nport = 8443\n"),
        "web.port",
    );
    Config::from_toml_str(&format!(
        "{TEST_BASE}[dns]\nport = 53\n[web]\nbind = \"127.0.0.1\"\nport = 8080\n"
    ))
    .expect("distinct ports are valid");
}

#[test]
fn test_empty_data_dir_is_rejected() {
    expect_cross_section(
        "config_version = 2\n[server]\ndata_dir = \"\"\n[upstream]\nservers = [\"1.1.1.1\"]\n",
        "server.data_dir",
    );
}

#[test]
fn test_bad_upstream_targets_are_rejected_in_every_scope() {
    for (toml, field) in [
        (
            "config_version = 2\n[upstream]\nservers = [\"oops-typo\"]\n",
            "upstream.servers[0]",
        ),
        (
            &*format!(
                "{TEST_BASE}[[upstream.per_domain]]\ndomains = [\"lan\"]\nservers = [\"sdns://AQcAAAAAAAA\"]\n"
            ),
            "upstream.per_domain[0].servers[0]",
        ),
        (
            &*format!(
                "{TEST_BASE}[clients]\n[[clients.entries]]\nname = \"phone\"\nupstreams = [\"oops-typo\"]\n"
            ),
            "clients.entries[0].upstreams[0]",
        ),
    ] {
        let err = Config::from_toml_str(toml).expect_err("bad upstream target must fail closed");
        assert!(
            err.to_string().contains("oops-typo")
                || err.to_string().contains("sdns://")
                || err.to_string().contains("Invalid upstream"),
            "unexpected error for {field}: {err}"
        );
        match err {
            ConfigError::CrossSection { field: actual, .. } => assert_eq!(actual, field),
            other => panic!("expected CrossSection on {field}, got {other:?}"),
        }
    }
}

#[test]
fn test_invalid_client_cidr_ids_are_rejected() {
    let err = Config::from_toml_str(&format!(
        "{TEST_BASE}[clients]\n[[clients.entries]]\nname = \"phone\"\nids = [\"10.0.0.0/33\"]\n"
    ))
    .expect_err("an invalid client CIDR must fail closed");
    match err {
        ConfigError::CrossSection { field, .. } => {
            assert_eq!(field, "clients.entries[0].ids[0]");
        }
        other => panic!("expected CrossSection on the client id, got {other:?}"),
    }
}

#[test]
fn test_bad_integrations_lists_are_rejected() {
    expect_cross_section(
        &format!(
            "{TEST_BASE}[integrations.lists]\n[integrations.lists.categories.adult]\nurl = \"ftp://lists.example.com/adult.txt\"\n"
        ),
        "integrations.lists.categories.adult.url",
    );
    expect_cross_section(
        &format!(
            "{TEST_BASE}[integrations.lists]\n[integrations.lists.categories.adult]\nurl = \"https://lists.example.com/adult.txt\"\nrefresh_hours = 0\n"
        ),
        "integrations.lists.categories.adult.refresh_hours",
    );
    Config::from_toml_str(&format!(
        "{TEST_BASE}[integrations.lists]\nrefresh_hours = 24\n[integrations.lists.categories.adult]\nurl = \"https://lists.example.com/adult.txt\"\nlicense = \"CC0-1.0\"\n"
    ))
    .expect("a valid curated list is accepted");
}

#[test]
fn test_invalid_acme_domains_are_rejected() {
    for domain in [
        "",
        "bad domain.example",
        "*.example.com",
        "bad..example.com",
    ] {
        let toml = format!("{TEST_BASE}[acme]\nenabled = true\ndomains = [\"{domain}\"]\n");
        let err = Config::from_toml_str(&toml).expect_err("invalid ACME domain must fail closed");
        assert!(
            err.to_string().contains("acme.domains"),
            "unexpected error for '{domain}': {err}"
        );
    }

    let duplicate = format!(
        "{TEST_BASE}[acme]\nenabled = true\ndomains = [\"dns.example.com\", \"DNS.EXAMPLE.COM\"]\n"
    );
    let err = Config::from_toml_str(&duplicate).expect_err("duplicate ACME domains");
    assert!(err.to_string().contains("duplicate"));

    Config::from_toml_str(&format!(
        "{TEST_BASE}[acme]\nenabled = true\ndomains = [\"dns.example.com\", \"MÜNCHEN.example\"]\n"
    ))
    .expect("IDN ACME domains are normalized to punycode");
}

#[test]
fn test_legacy_aliases_still_parse_in_v2() {
    let parsed = Config::from_toml_str(&format!(
        "{TEST_BASE}[stats]\nquery_log_retention_days = 30\n[privacy]\nanonymize_client_ip = true\n[web]\nacme_enabled = true\nacme_domains = [\"dns.example.com\"]\n[dns.tls]\ncert = \"/etc/sito/cert.pem\"\nkey = \"/etc/sito/key.pem\"\n"
    ))
    .expect("deprecated aliases remain accepted for one 2.0 alpha");
    assert_eq!(parsed.get_stats_config().retention_days, 30);
    assert!(parsed.privacy.anonymize_querylog);
    assert_eq!(
        parsed
            .get_acme_config()
            .and_then(|acme| acme.domains.first().cloned()),
        Some("dns.example.com".to_string())
    );
    assert!(parsed.get_tls_config().is_some());
}

fn v1_document() -> &'static str {
    r#"
config_version = 1

[server]
role = "master"
data_dir = "/var/lib/sito"

[dns]
bind = ["0.0.0.0"]
port = 53

[dns.tls]
cert = "/etc/sito/cert.pem"
key = "/etc/sito/key.pem"

[upstream]
servers = ["tls://dns.quad9.net"]

[stats]
query_log_retention_days = 30

[privacy]
anonymize_client_ip = true

[web]
bind = "0.0.0.0"
port = 8080
acme_enabled = true
acme_email = "ops@example.com"
acme_domains = ["dns.example.com"]
acme_staging = true

[auth]
session_ttl_hours = 12
admin_password_hash = "$argon2id$legacy"
tokens = ["legacy-token"]

[clients]
[[clients.entries]]
name = "phone"
ids = ["192.168.1.20"]
"#
}

#[test]
fn test_migration_is_behavior_preserving_and_moves_aliases() {
    let outcome = Config::migrate_v1_to_v2(v1_document(), &MigrationOptions::default())
        .expect("v1 must migrate");
    assert_eq!(outcome.report.from_version, 1);
    assert_eq!(outcome.report.to_version, 2);

    let document: toml::Value = toml::from_str(&outcome.document).expect("valid TOML");
    assert_eq!(
        document
            .get("config_version")
            .and_then(toml::Value::as_integer),
        Some(2)
    );

    // Every known v1 value is preserved (not replaced by a 2.0 default).
    assert_eq!(
        document
            .get("server")
            .and_then(|v| v.get("data_dir"))
            .and_then(toml::Value::as_str),
        Some("/var/lib/sito")
    );
    assert_eq!(
        document
            .get("stats")
            .and_then(|v| v.get("retention_days"))
            .and_then(toml::Value::as_integer),
        Some(30),
        "the legacy retention alias must become the canonical key"
    );
    assert_eq!(
        document
            .get("privacy")
            .and_then(|v| v.get("anonymize_querylog"))
            .and_then(toml::Value::as_bool),
        Some(true)
    );

    // [dns.tls] moves to typed [tls].
    assert!(
        document.get("dns").and_then(|v| v.get("tls")).is_none(),
        "migration must remove the deprecated [dns.tls] table"
    );
    assert_eq!(
        document
            .get("tls")
            .and_then(|v| v.get("cert"))
            .and_then(toml::Value::as_str),
        Some("/etc/sito/cert.pem")
    );

    // [web] acme_* moves to typed [acme].
    let web = document.get("web").and_then(toml::Value::as_table).unwrap();
    assert!(
        !web.contains_key("acme_enabled") && !web.contains_key("acme_domains"),
        "migration must remove legacy [web] acme_* keys: {web:?}"
    );
    let acme = document
        .get("acme")
        .and_then(toml::Value::as_table)
        .unwrap();
    assert_eq!(
        acme.get("enabled").and_then(toml::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        acme.get("email").and_then(toml::Value::as_str),
        Some("ops@example.com")
    );
    assert_eq!(
        acme.get("staging").and_then(toml::Value::as_bool),
        Some(true)
    );

    // Removed secret-bearing legacy keys are dropped and reported.
    let auth = document
        .get("auth")
        .and_then(toml::Value::as_table)
        .unwrap();
    assert!(!auth.contains_key("admin_password_hash"));
    assert!(!auth.contains_key("tokens"));
    let moved_from: Vec<&str> = outcome
        .report
        .moved
        .iter()
        .map(|change| change.from.as_str())
        .collect();
    assert!(moved_from.contains(&"web.acme_enabled"));
    assert!(moved_from.contains(&"dns.tls.cert"));
    let removed_from: Vec<&str> = outcome
        .report
        .removed
        .iter()
        .map(|change| change.from.as_str())
        .collect();
    assert!(removed_from.contains(&"auth.admin_password_hash"));
    assert!(removed_from.contains(&"auth.tokens"));

    // The result is a valid v2 document.
    let parsed = Config::from_toml_str(&outcome.document).expect("migrated document is valid v2");
    assert_eq!(parsed.config_version, 2);
    assert_eq!(parsed.get_stats_config().retention_days, 30);
    assert_eq!(parsed.get_web_config().bind.to_string(), "0.0.0.0");
    assert!(
        parsed.filtering.fail_closed,
        "v1 fail_closed = true is kept"
    );
}

#[test]
fn test_migration_alias_conflict_precedence_matches_v1_effective_values() {
    let v1 = r#"
config_version = 1
[upstream]
servers = ["1.1.1.1"]

[tls]
cert = "/etc/sito/old-cert.pem"
key = "/etc/sito/old-key.pem"

[dns.tls]
cert = "/etc/sito/new-cert.pem"
key = "/etc/sito/new-key.pem"

[acme]
enabled = false

[web]
acme_enabled = true
acme_domains = ["legacy.example.com"]
"#;
    let outcome = Config::migrate_v1_to_v2(v1, &MigrationOptions::default()).expect("migrate");
    let parsed = Config::from_toml_str(&outcome.document).expect("valid v2");
    assert_eq!(
        parsed.get_tls_config().and_then(|tls| tls.cert.as_deref()),
        Some(std::path::Path::new("/etc/sito/new-cert.pem")),
        "v1 preferred [dns.tls] over [tls]; migration must keep that value"
    );
    assert!(
        !parsed.get_acme_config().expect("acme").enabled,
        "v1 preferred typed [acme] over [web] acme_*; migration must keep that value"
    );
    assert!(
        outcome
            .report
            .warnings
            .iter()
            .any(|warning| warning.contains("dns.tls")),
        "the conflict must be reported: {:?}",
        outcome.report.warnings
    );
}

#[test]
fn test_migration_rejects_unknown_keys_unless_explicitly_allowed() {
    let v1 = "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n[clients]\nbogus = 1\n";
    let err = Config::migrate_v1_to_v2(v1, &MigrationOptions::default())
        .expect_err("unknown keys are errors by default");
    assert!(matches!(err, ConfigError::UnknownKey { .. }), "got {err:?}");

    let options = MigrationOptions {
        ignore_unknown_keys: true,
        ..MigrationOptions::default()
    };
    let outcome = Config::migrate_v1_to_v2(v1, &options).expect("unknown keys dropped on request");
    assert_eq!(outcome.report.unknown_dropped, vec!["clients.bogus"]);
    assert!(
        !outcome.document.contains("bogus"),
        "dropped keys must not survive: {}",
        outcome.document
    );
    Config::from_toml_str(&outcome.document).expect("migrated document is valid");
}

#[test]
fn test_migration_adopt_safe_defaults_opts_into_v2_defaults() {
    let v1 = "config_version = 1\n[web]\nbind = \"0.0.0.0\"\nport = 8080\n[filtering]\nfail_closed = false\n[upstream]\nservers = [\"1.1.1.1\"]\n";

    // Default migration keeps the v1 effective behavior.
    let kept = Config::migrate_v1_to_v2(v1, &MigrationOptions::default()).expect("migrate");
    let parsed = Config::from_toml_str(&kept.document).expect("valid");
    assert_eq!(parsed.get_web_config().bind.to_string(), "0.0.0.0");
    assert!(!parsed.filtering.fail_closed);

    // Opting into safe defaults changes only the documented safe settings.
    let adopted = Config::migrate_v1_to_v2(
        v1,
        &MigrationOptions {
            adopt_safe_defaults: true,
            ..MigrationOptions::default()
        },
    )
    .expect("migrate");
    let parsed = Config::from_toml_str(&adopted.document).expect("valid");
    assert_eq!(parsed.get_web_config().bind.to_string(), "127.0.0.1");
    assert!(parsed.filtering.fail_closed);
    assert!(
        adopted
            .report
            .safe_defaults_applied
            .iter()
            .any(|field| field == "web.bind"),
        "the report must list the adopted safe defaults: {:?}",
        adopted.report.safe_defaults_applied
    );
}

#[test]
fn test_migration_partial_acme_section_ignores_every_web_alias() {
    // v1 resolves ACME at the table level: if `[acme]` exists, the entire
    // `[web] acme_*` block is ignored. A partial `[acme]` must not be merged
    // with alias fields, which could enable issuance that v1 never performed.
    let v1 = r#"
config_version = 1
[upstream]
servers = ["1.1.1.1"]

[acme]
enabled = false

[web]
port = 8080
acme_enabled = true
acme_email = "legacy@example.com"
acme_domains = ["legacy.example.com"]
acme_staging = true
"#;
    let outcome = Config::migrate_v1_to_v2(v1, &MigrationOptions::default()).expect("migrate");
    let parsed = Config::from_toml_str(&outcome.document).expect("valid v2");
    let acme = parsed.get_acme_config().expect("[acme] must survive");
    assert!(!acme.enabled, "the typed [acme] enabled value wins");
    assert!(
        acme.domains.is_empty(),
        "ignored [web] acme_domains must not leak into [acme]: {:?}",
        acme.domains
    );
    assert_eq!(acme.email, None);
    assert!(!acme.staging);
    let web = toml::from_str::<toml::Value>(&outcome.document)
        .expect("valid TOML")
        .get("web")
        .and_then(toml::Value::as_table)
        .cloned()
        .expect("[web] table");
    for alias in [
        "acme_enabled",
        "acme_email",
        "acme_domains",
        "acme_staging",
        "acme_cache_dir",
    ] {
        assert!(
            !web.contains_key(alias),
            "ignored alias '{alias}' must be removed: {web:?}"
        );
    }
    let removed: Vec<&str> = outcome
        .report
        .removed
        .iter()
        .map(|change| change.from.as_str())
        .collect();
    assert!(
        removed.contains(&"web.acme_enabled"),
        "the ignored alias must be reported: {removed:?}"
    );
}

#[test]
fn test_migration_dns_tls_replaces_the_whole_top_level_tls_table() {
    // v1 selected either the whole `[dns.tls]` table or the whole `[tls]`
    // table. A partial top-level `[tls]` must not contribute ignored fields
    // such as `sni_certs`.
    let v1 = r#"
config_version = 1
[upstream]
servers = ["1.1.1.1"]

[tls]
cert = "/etc/sito/old-cert.pem"
key = "/etc/sito/old-key.pem"

[[tls.sni_certs]]
domain = "ignored.example.com"
cert = "/etc/sito/ignored.pem"
key = "/etc/sito/ignored.key"

[dns.tls]
cert = "/etc/sito/new-cert.pem"
key = "/etc/sito/new-key.pem"
"#;
    let outcome = Config::migrate_v1_to_v2(v1, &MigrationOptions::default()).expect("migrate");
    let parsed = Config::from_toml_str(&outcome.document).expect("valid v2");
    let tls = parsed.get_tls_config().expect("tls");
    assert_eq!(
        tls.cert.as_deref(),
        Some(std::path::Path::new("/etc/sito/new-cert.pem"))
    );
    assert!(
        tls.sni_certs.is_empty(),
        "the ignored [tls] sni_certs must not survive: {:?}",
        tls.sni_certs
    );
    assert!(
        outcome
            .report
            .warnings
            .iter()
            .any(|warning| warning.contains("dns.tls") && warning.contains("tls")),
        "the table-level replacement must be reported: {:?}",
        outcome.report.warnings
    );
}

#[test]
fn test_migration_materializes_the_v1_web_bind_default() {
    // A v1 file that omitted web.bind used the 0.0.0.0 default. Migration
    // must preserve the effective behavior unless --adopt-safe-defaults.
    for v1 in [
        "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n",
        "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n[web]\nport = 8080\n",
    ] {
        let outcome = Config::migrate_v1_to_v2(v1, &MigrationOptions::default()).expect("migrate");
        let parsed = Config::from_toml_str(&outcome.document).expect("valid v2");
        assert_eq!(
            parsed.get_web_config().bind.to_string(),
            "0.0.0.0",
            "the v1 default admin bind must be materialized"
        );
        assert!(
            outcome
                .report
                .defaults_materialized
                .iter()
                .any(|field| field == "web.bind"),
            "materializing the default must be reported: {:?}",
            outcome.report.defaults_materialized
        );
    }

    // --adopt-safe-defaults writes the loopback default instead.
    let outcome = Config::migrate_v1_to_v2(
        "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n",
        &MigrationOptions {
            adopt_safe_defaults: true,
            ..MigrationOptions::default()
        },
    )
    .expect("migrate");
    let parsed = Config::from_toml_str(&outcome.document).expect("valid v2");
    assert_eq!(parsed.get_web_config().bind.to_string(), "127.0.0.1");
    assert!(
        outcome
            .report
            .safe_defaults_applied
            .iter()
            .any(|field| field == "web.bind")
    );
    assert!(
        !outcome
            .report
            .defaults_materialized
            .iter()
            .any(|field| field == "web.bind")
    );
}

#[test]
fn test_migration_ignore_unknown_keys_handles_table_arrays_and_nested_sni_fields() {
    let v1 = r#"
config_version = 1
[upstream]
servers = ["1.1.1.1"]

[clients]
[[clients.entries]]
name = "phone"
bogus = 1

[dns.tls]
cert = "/etc/sito/cert.pem"
key = "/etc/sito/key.pem"

[[dns.tls.sni_certs]]
domain = "dot.example.com"
cert = "/etc/sito/sni.pem"
key = "/etc/sito/sni.key"
bogus = 2
"#;
    let outcome = Config::migrate_v1_to_v2(
        v1,
        &MigrationOptions {
            ignore_unknown_keys: true,
            ..MigrationOptions::default()
        },
    )
    .expect("unknown keys are dropped on request");
    assert!(
        outcome
            .report
            .unknown_dropped
            .iter()
            .any(|key| key == "clients.entries[0].bogus"),
        "table-array unknown keys must be reported: {:?}",
        outcome.report.unknown_dropped
    );
    assert!(
        outcome
            .report
            .unknown_dropped
            .iter()
            .any(|key| key == "dns.tls.sni_certs[0].bogus"),
        "nested SNI unknown fields must be reported: {:?}",
        outcome.report.unknown_dropped
    );
    let parsed = Config::from_toml_str(&outcome.document).expect("valid v2");
    assert_eq!(parsed.get_tls_config().expect("tls").sni_certs.len(), 1);
}

#[test]
fn test_listener_conflicts_cover_wildcards_acme_and_dual_stack() {
    // A wildcard web bind covers a specific DNS bind.
    expect_cross_section(
        &format!(
            "{TEST_BASE}[dns]\nbind = [\"127.0.0.1\"]\nport = 8080\n[web]\nbind = \"0.0.0.0\"\nport = 8080\n"
        ),
        "web.port",
    );

    // An ACME HTTP-01 listener cannot share a DNS TCP port.
    expect_cross_section(
        &format!(
            "{TEST_BASE}[dns]\nbind = [\"127.0.0.1\"]\nport = 8053\n[acme]\nenabled = true\ndomains = [\"dns.example.com\"]\nhttp_port = 8053\n"
        ),
        "acme.http_port",
    );

    // Dual-stack `::` overlaps IPv4 listeners on hosts without v6only.
    expect_cross_section(
        &format!(
            "{TEST_BASE}[dns]\nbind = [\"::\"]\nport = 8080\n[web]\nbind = \"127.0.0.1\"\nport = 8080\n"
        ),
        "web.port",
    );
}

#[test]
fn test_migration_rejects_a_v2_or_future_document() {
    for version in [2, 3] {
        let doc = format!("config_version = {version}\n[upstream]\nservers = [\"1.1.1.1\"]\n");
        let err = Config::migrate_v1_to_v2(&doc, &MigrationOptions::default())
            .expect_err("only v1 documents migrate");
        assert!(
            matches!(err, ConfigError::UnsupportedVersion { found, .. } if found == version),
            "got {err:?}"
        );
    }
}

#[test]
fn test_migrated_config_reparses_after_ha_sanitization() {
    let outcome =
        Config::migrate_v1_to_v2(v1_document(), &MigrationOptions::default()).expect("migrate");
    let sanitized = sito_ha_sanitize(&outcome.document);
    Config::from_toml_str(&sanitized).expect("a sanitized HA bundle must parse as v2");
}

/// Local copy of the HA sanitizer's observable contract for this crate-level
/// test: drop `[ha]`, remove node-local identity/secret keys, force the slave
/// role. The real sanitizer is tested in `sito-ha`; this guards parser
/// acceptance of the shape it produces without adding a dependency cycle.
fn sito_ha_sanitize(document: &str) -> String {
    let mut table: toml::Table = toml::from_str(document).expect("valid TOML");
    table.remove("ha");
    if let Some(toml::Value::Table(server)) = table.get_mut("server") {
        server.remove("instance_name");
        server.insert("role".to_string(), toml::Value::String("slave".to_string()));
    }
    if let Some(toml::Value::Table(auth)) = table.get_mut("auth") {
        auth.remove("admin_password_hash");
        auth.remove("tokens");
    }
    if let Some(toml::Value::Table(clients)) = table.get_mut("clients") {
        clients.remove("client_id_secrets");
    }
    toml::to_string_pretty(&table).expect("serialize")
}
