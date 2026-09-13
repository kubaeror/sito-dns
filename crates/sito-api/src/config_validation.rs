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
/// # Errors
///
/// Returns an error naming the offending section when a section exists but
/// does not deserialize into its configuration type.
pub fn validate_typed_sections(config: &Config) -> anyhow::Result<()> {
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
        let _: sito_clients::IntegrationsConfig = value
            .clone()
            .try_into()
            .map_err(|e| anyhow::anyhow!("invalid [integrations] configuration: {e}"))?;
    }
    if let Some(value) = config.web.as_ref() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_typed_section_errors() {
        let config = Config::from_toml_str(
            "config_version = 1\n[clients]\nentries = \"not-an-array\"\n[upstream]\nservers = [\"1.1.1.1\"]\n",
        )
        .expect("parses as raw TOML");
        let err = validate_typed_sections(&config).expect_err("must reject bad [clients]");
        assert!(err.to_string().contains("[clients]"));
    }

    #[test]
    fn test_accepts_valid_sections() {
        let config = Config::from_toml_str(
            "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n[web]\nport = 8080\n",
        )
        .expect("parses");
        validate_typed_sections(&config).expect("valid sections");
    }
}
