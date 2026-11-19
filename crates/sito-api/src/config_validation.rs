//! Deep validation of TOML-valued configuration sections.
//!
//! `Config::validate` only checks the strongly-typed parts of the
//! configuration (and that the raw sections are TOML tables). Type errors
//! inside `[clients]`, `[rewrites]`, `[integrations]`, `[web]`, `[auth]`,
//! `[stats]` or `[ha]` would otherwise be silently discarded by
//! warn-and-default getters, or accepted by an API write and only rejected
//! later by the startup/file-watcher paths. Every persistence path runs these
//! conversions before writing so an accepted configuration is one the server
//! can actually load.

use sito_core::config::Config;

/// Converts every TOML-valued section into its typed form, returning the first
/// error encountered.
///
/// This is the dependent-crate half of the single validator: it first runs
/// [`sito_core::config::Config::validate_full`] (so every entry point applies
/// the same core rules) and then deserializes the sections whose types live
/// in `sito-clients`, `sito-rewrites` and, when the `ha` feature is enabled,
/// `sito-ha`. A build without `ha` rejects the `[ha]` section and the replica
/// role here with a rebuild instruction instead of silently ignoring them.
///
/// # Errors
///
/// Returns an error naming the offending section when a section exists but
/// does not deserialize into its configuration type.
pub fn validate_typed_sections(config: &Config) -> anyhow::Result<()> {
    // One validator: startup, check-config, API writes, restore and HA apply
    // all reach this path, and the core rules are never duplicated.
    config.validate_full().map_err(|e| anyhow::anyhow!("{e}"))?;

    if let Some(value) = config.clients.as_ref() {
        let clients: sito_clients::ClientsConfig = value
            .clone()
            .try_into()
            .map_err(|e| anyhow::anyhow!("invalid [clients] configuration: {e}"))?;
        validate_client_curated_references(&clients)?;
    }
    if let Some(value) = config.rewrites.as_ref() {
        let rewrites: sito_rewrites::RewritesConfig = value
            .clone()
            .try_into()
            .map_err(|e| anyhow::anyhow!("invalid [rewrites] configuration: {e}"))?;
        rewrites
            .validate()
            .map_err(|e| anyhow::anyhow!("invalid [rewrites] configuration: {e}"))?;
    }
    if let Some(value) = config.integrations.as_ref() {
        let integrations: sito_clients::IntegrationsConfig = value
            .clone()
            .try_into()
            .map_err(|e| anyhow::anyhow!("invalid [integrations] configuration: {e}"))?;
        validate_integrations(&integrations, cfg!(feature = "routeros"))?;
    }
    if let Some(value) = config.web.as_ref() {
        // `public_url` and `tls_terminated_by_proxy` are typed WebConfig
        // fields; `validate_full` already checks their schemes/types.
        let _: sito_core::config::WebConfig = value
            .clone()
            .try_into()
            .map_err(|e| anyhow::anyhow!("invalid [web] configuration: {e}"))?;
    }
    if let Some(value) = config.auth.as_ref() {
        let _: sito_core::config::AuthConfig = value
            .clone()
            .try_into()
            .map_err(|e| anyhow::anyhow!("invalid [auth] configuration: {e}"))?;
    }
    if let Some(value) = config.stats.as_ref() {
        let _: sito_core::config::StatsConfig = value
            .clone()
            .try_into()
            .map_err(|e| anyhow::anyhow!("invalid [stats] configuration: {e}"))?;
    }

    if config.ha.is_some() {
        #[cfg(feature = "ha")]
        sito_ha::config_from(config)
            .map_err(|e| anyhow::anyhow!("invalid [ha] configuration: {e}"))?;
        #[cfg(not(feature = "ha"))]
        return Err(anyhow::anyhow!(
            "invalid [ha] configuration: this build of sito was compiled without high-availability \
             support; rebuild with `cargo build -p sito --features ha` (official artifacts enable it) \
             or remove the [ha] section"
        ));
    }

    #[cfg(not(feature = "ha"))]
    if config.server.role == "slave" {
        return Err(anyhow::anyhow!(
            "invalid [server] configuration: server.role = \"slave\" requires high-availability \
             support, which this build of sito was compiled without; rebuild with \
             `cargo build -p sito --features ha` (official artifacts enable it) or remove the role = \
             \"slave\" setting"
        ));
    }
    Ok(())
}

/// Rejects group policy references the bundled registries cannot resolve.
///
/// `parental_categories` and `blocked_services.service` are plain strings in
/// the TOML schema; without this check a typo is accepted but silently matches
/// nothing at query time. The registries are built once per validation pass.
///
/// Limitation: the check uses the **bundled** registries, because this
/// validation path has no live [`sito_clients::RuntimeLists`] handle. Service
/// ids supplied only by a runtime-refreshed `[integrations.lists]` source are
/// therefore not accepted as client references; startup validation uses the
/// same bundled data. Threading the live store through validation is a
/// follow-up, not part of this fix.
fn validate_client_curated_references(clients: &sito_clients::ClientsConfig) -> anyhow::Result<()> {
    if clients.groups.is_empty() {
        return Ok(());
    }
    let lists = sito_clients::RuntimeLists::try_new()
        .map_err(|e| anyhow::anyhow!("failed to load bundled parental/service registries: {e}"))?;
    for (group_name, group) in &clients.groups {
        for category in &group.parental_categories {
            if !lists.has_parental_category(category) {
                return Err(anyhow::anyhow!(
                    "invalid [clients] configuration: clients.groups.{group_name}.parental_categories \
                     references unknown parental category '{category}'"
                ));
            }
        }
        for blocked in &group.blocked_services {
            if !lists.has_service(&blocked.service) {
                return Err(anyhow::anyhow!(
                    "invalid [clients] configuration: clients.groups.{group_name}.blocked_services \
                     references unknown service '{}'",
                    blocked.service
                ));
            }
        }
    }
    Ok(())
}

/// Rejects an enabled RouterOS integration when this build cannot honour it.
///
/// The `routeros` feature is a property of the `sito` binary, propagated to
/// this crate so the startup/`check-config`/API validation paths fail closed
/// instead of silently ignoring the knob. The capability is a parameter so the
/// behaviour is testable in every feature combination.
fn validate_integrations(
    integrations: &sito_clients::IntegrationsConfig,
    routeros_supported: bool,
) -> anyhow::Result<()> {
    if let Some(lists) = integrations.lists.as_ref() {
        lists
            .validate_known_categories()
            .map_err(|e| anyhow::anyhow!("invalid [integrations.lists] configuration: {e}"))?;
    }
    if !routeros_supported
        && integrations
            .mikrotik
            .as_ref()
            .is_some_and(|mikrotik| mikrotik.enabled)
    {
        return Err(anyhow::anyhow!(
            "invalid [integrations.mikrotik] configuration: enabled = true requires the \
             optional RouterOS integration, which this build does not include; rebuild \
             sito with `cargo build -p sito --features routeros` or set enabled = false"
        ));
    }
    if let Some(mikrotik) = integrations.mikrotik.as_ref()
        && mikrotik.enabled
    {
        // A plaintext http:// URL is allowed (lab opt-out) but never grants
        // client identity; every other scheme is rejected so a typo cannot
        // silently disable the integration.
        let url = reqwest::Url::parse(&mikrotik.url).map_err(|e| {
            anyhow::anyhow!(
                "invalid [integrations.mikrotik] url '{0}': {e}",
                mikrotik.url
            )
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(anyhow::anyhow!(
                "invalid [integrations.mikrotik] url '{}': scheme must be http:// or https://",
                mikrotik.url
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_typed_section_errors() {
        // The single validator now rejects this at parse time, with the same
        // section-named error the API path used to produce.
        let err = Config::from_toml_str(
            "config_version = 2\n[clients]\nentries = \"not-an-array\"\n[upstream]\nservers = [\"1.1.1.1\"]\n",
        )
        .expect_err("must reject bad [clients]");
        assert!(err.to_string().contains("[clients]"), "got: {err}");
    }

    #[test]
    fn test_rejects_invalid_rewrite_entry() {
        let config = Config::from_toml_str(
            "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n[rewrites]\nentries = [{ domain = \"bad..name\", type = \"A\", answer = \"192.168.1.1\" }]\n",
        )
        .expect("parses");
        let err = validate_typed_sections(&config)
            .expect_err("an invalid rewrite entry must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("[rewrites]") && message.contains("entry 0"),
            "the error must name the section and entry: {message}"
        );

        let valid = Config::from_toml_str(
            "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n[rewrites]\nentries = [{ domain = \"*.home.arpa\", type = \"A\", answer = \"192.168.1.1\", exception_clients = [\"10.0.0.0/8\"] }]\n",
        )
        .expect("parses");
        validate_typed_sections(&valid).expect("a valid rewrite entry must be accepted");
    }

    #[test]
    fn test_accepts_valid_sections() {
        let config = Config::from_toml_str(
            "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n[web]\nport = 8080\n",
        )
        .expect("parses");
        validate_typed_sections(&config).expect("valid sections");
    }

    #[test]
    fn test_rejects_unknown_curated_categories() {
        let valid = Config::from_toml_str(
            "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n\
             [integrations.lists.categories.adult]\nurl = \"https://example.com/adult.txt\"\n",
        )
        .expect("parses");
        validate_typed_sections(&valid).expect("a bundled category is accepted");

        let invalid = Config::from_toml_str(
            "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n\
             [integrations.lists.categories.advertising]\nurl = \"https://example.com/ads.txt\"\n",
        )
        .expect("parses");
        let err =
            validate_typed_sections(&invalid).expect_err("an unknown category must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("[integrations.lists]") && message.contains("advertising"),
            "the error must name the section and category: {message}"
        );
    }

    #[test]
    fn test_rejects_unknown_client_curated_references() {
        let valid = Config::from_toml_str(
            "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n\
             [clients.groups.kids]\nparental_categories = [\"adult\"]\n\
             [[clients.groups.kids.blocked_services]]\nservice = \"tiktok\"\n",
        )
        .expect("parses");
        validate_typed_sections(&valid).expect("bundled categories and services are accepted");

        let invalid_category = Config::from_toml_str(
            "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n\
             [clients.groups.kids]\nparental_categories = [\"social\"]\n",
        )
        .expect("parses");
        let err = validate_typed_sections(&invalid_category)
            .expect_err("an unknown parental category must be rejected");
        assert!(
            err.to_string().contains("parental_categories") && err.to_string().contains("social"),
            "unexpected error: {err}"
        );

        let invalid_service = Config::from_toml_str(
            "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n\
             [[clients.groups.kids.blocked_services]]\nservice = \"myspace\"\n",
        )
        .expect("parses");
        let err = validate_typed_sections(&invalid_service)
            .expect_err("an unknown blocked service must be rejected");
        assert!(
            err.to_string().contains("blocked_services") && err.to_string().contains("myspace"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "ha")]
    #[test]
    fn test_validates_typed_ha_section() {
        let mut valid =
            Config::from_toml_str("config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n")
                .expect("parses");
        valid.ha = Some(
            toml::from_str(
                "replication_port = 8953\nallow_insecure_ws = true\nslave_token = \"secret\"\n",
            )
            .expect("valid [ha] table"),
        );
        validate_typed_sections(&valid).expect("a valid master [ha] section is accepted");

        let mut invalid =
            Config::from_toml_str("config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n")
                .expect("parses");
        invalid.ha = Some(
            toml::from_str("replication_port = \"not-a-port\"\n").expect("malformed [ha] table"),
        );
        let err =
            validate_typed_sections(&invalid).expect_err("a malformed [ha] section is rejected");
        assert!(err.to_string().contains("[ha]"), "got: {err}");
    }

    /// A build without the `ha` feature cannot honour `[ha]` or a replica
    /// role. Both are rejected with the rebuild instruction instead of being
    /// silently accepted and ignored at runtime.
    #[cfg(not(feature = "ha"))]
    #[test]
    fn test_rejects_ha_section_without_ha_feature() {
        let mut config =
            Config::from_toml_str("config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n")
                .expect("parses");
        config.ha = Some(
            toml::from_str("replication_port = 8953\n").expect("valid [ha] table for the test"),
        );

        let err = validate_typed_sections(&config)
            .expect_err("a no-HA build must reject the [ha] section");
        let message = err.to_string();
        assert!(
            message.contains("[ha]"),
            "the error must name the rejected section: {message}"
        );
        assert!(
            message.contains("--features ha"),
            "the error must tell the operator how to enable HA: {message}"
        );
    }

    #[cfg(not(feature = "ha"))]
    #[test]
    fn test_rejects_slave_role_without_ha_feature() {
        let mut config =
            Config::from_toml_str("config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n")
                .expect("parses");
        config.server.role = "slave".to_string();

        let err = validate_typed_sections(&config)
            .expect_err("a no-HA build must reject the replica role");
        let message = err.to_string();
        assert!(
            message.contains("server.role") && message.contains("slave"),
            "the error must name the rejected field and value: {message}"
        );
        assert!(
            message.contains("--features ha"),
            "the error must tell the operator how to enable HA: {message}"
        );
    }

    /// RouterOS is an optional integration. A build without the `routeros`
    /// feature must reject `integrations.mikrotik.enabled = true` instead of
    /// silently ignoring the knob at startup. The capability is exercised
    /// directly so the test runs in every feature combination.
    #[test]
    fn test_rejects_enabled_mikrotik_without_routeros_feature() {
        let integrations: sito_clients::IntegrationsConfig =
            toml::from_str("[mikrotik]\nenabled = true\n").expect("parses [integrations]");
        let err = validate_integrations(&integrations, false)
            .expect_err("enabled RouterOS integration requires the routeros feature");
        let message = err.to_string();
        assert!(
            message.contains("routeros") && message.contains("[integrations.mikrotik]"),
            "the error must name the feature and the section: {message}"
        );

        // The same config is accepted by a build that contains the feature.
        validate_integrations(&integrations, true).expect("feature-enabled build accepts it");
    }

    /// The knob is not silently ignored when it is disabled: a disabled
    /// `[integrations.mikrotik]` section is valid in every build.
    #[test]
    fn test_accepts_disabled_mikrotik_without_routeros_feature() {
        let config = Config::from_toml_str(
            "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n[integrations.mikrotik]\nenabled = false\n",
        )
        .expect("parses");
        validate_typed_sections(&config).expect("a disabled RouterOS section must be accepted");
    }

    #[test]
    fn test_rejects_non_http_mikrotik_url_but_accepts_plaintext_lab_opt_out() {
        let unsupported: sito_clients::IntegrationsConfig =
            toml::from_str("[mikrotik]\nenabled = true\nurl = \"ftp://router.lan\"\n")
                .expect("parses [integrations]");
        let err = validate_integrations(&unsupported, true)
            .expect_err("a non-HTTP(S) URL must fail closed");
        assert!(
            err.to_string()
                .contains("scheme must be http:// or https://"),
            "unexpected error: {err}"
        );

        // Plaintext http:// is a documented lab opt-out: accepted, but the
        // RouterOS client marks its leases unverified (display-only).
        let plaintext: sito_clients::IntegrationsConfig =
            toml::from_str("[mikrotik]\nenabled = true\nurl = \"http://router.lan\"\n")
                .expect("parses [integrations]");
        validate_integrations(&plaintext, true).expect("plaintext lab opt-out is accepted");
    }

    #[test]
    fn test_validates_admin_scheme_settings() {
        let valid = Config::from_toml_str(
            "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n[web]\npublic_url = \"https://dns.example.com\"\ntls_terminated_by_proxy = true\n",
        )
        .expect("parses");
        validate_typed_sections(&valid).expect("valid admin scheme settings");

        let bad_url = Config::from_toml_str(
            "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n[web]\npublic_url = \"ftp://dns.example.com\"\n",
        )
        .expect_err("ftp scheme rejected at parse time by the single validator");
        assert!(bad_url.to_string().contains("public_url"), "got: {bad_url}");

        let bad_flag = Config {
            web: Some(
                toml::from_str::<toml::Value>("tls_terminated_by_proxy = \"yes\"\n")
                    .expect("raw web table"),
            ),
            ..Config::default()
        };
        let err = validate_typed_sections(&bad_flag).expect_err("non-bool rejected");
        assert!(err.to_string().contains("[web]"), "got: {err}");
    }
}
