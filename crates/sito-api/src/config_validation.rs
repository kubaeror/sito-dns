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
/// in `sito-clients`, `sito-rewrites` and `sito-ha`.
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
        let _: sito_clients::ClientsConfig = value
            .clone()
            .try_into()
            .map_err(|e| anyhow::anyhow!("invalid [clients] configuration: {e}"))?;
    }
    if let Some(value) = config.rewrites.as_ref() {
        let _: sito_rewrites::RewritesConfig = value
            .clone()
            .try_into()
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

    if let Some(value) = config.ha.as_ref() {
        let ha_cfg = sito_ha::HaConfig::from_toml_value(value)
            .map_err(|e| anyhow::anyhow!("invalid [ha] configuration: {e}"))?;
        ha_cfg
            .validate(&config.server.role)
            .map_err(|e| anyhow::anyhow!("invalid [ha] configuration: {e}"))?;
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
    fn test_accepts_valid_sections() {
        let config = Config::from_toml_str(
            "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]\n[web]\nport = 8080\n",
        )
        .expect("parses");
        validate_typed_sections(&config).expect("valid sections");
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
