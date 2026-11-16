//! HA configuration access shared by startup and the admin API.

use sito_core::config::Config;

use crate::error::HaError;

pub use sito_ha_types::HaConfig;

/// Parses the `[ha]` section without validating it against the node role.
///
/// Used by read-only lookups (master URL, token scan) that must not turn an
/// unrelated API request into a configuration-validation failure. A missing
/// section yields an explicitly disabled master config (`replication_port = 0`).
pub fn config_from_unvalidated(config: &Config) -> Result<HaConfig, HaError> {
    match config.ha.as_ref() {
        Some(value) => HaConfig::from_toml_value(value),
        None => Ok(HaConfig {
            replication_port: 0,
            ..HaConfig::default()
        }),
    }
}

/// Parses and role-validates the `[ha]` section for startup/apply paths.
pub fn config_from(config: &Config) -> Result<HaConfig, HaError> {
    let ha = config_from_unvalidated(config)?;
    ha.validate(&config.server.role)?;
    Ok(ha)
}

/// Whether the node's role depends on a working HA replication path.
#[must_use]
pub fn readiness_required(config: &Config) -> bool {
    HaConfig::readiness_required(&config.server.role, config.ha.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_master_ha() -> toml::Value {
        toml::from_str(
            r#"
replication_port = 8953
allow_insecure_ws = true
slave_token = "secret"
"#,
        )
        .expect("valid [ha] table")
    }

    #[test]
    fn missing_section_is_an_explicitly_disabled_master() {
        let config = Config::default();
        let ha = config_from_unvalidated(&config).expect("default [ha]");
        assert_eq!(ha.replication_port, 0);
        assert!(config_from(&config).is_ok());
    }

    #[test]
    fn parses_and_validates_the_configured_section() {
        let mut config = Config::default();
        config.ha = Some(valid_master_ha());
        let ha = config_from(&config).expect("valid master config");
        assert_eq!(ha.replication_port, 8953);
        assert_eq!(ha.slave_token.as_deref(), Some("secret"));
    }

    #[test]
    fn invalid_role_configuration_is_rejected() {
        let mut config = Config::default();
        config.server.role = "slave".to_string();
        config.ha = Some(toml::from_str("replication_port = 8953").expect("table"));
        assert!(config_from(&config).is_err());
    }

    #[test]
    fn readiness_follows_the_role_and_section_presence() {
        let mut config = Config::default();
        assert!(!readiness_required(&config));

        config.ha = Some(toml::from_str("replication_port = 0").expect("table"));
        assert!(!readiness_required(&config));

        config.ha = Some(toml::from_str("replication_port = 8953").expect("table"));
        assert!(readiness_required(&config));

        config.server.role = "slave".to_string();
        config.ha = None;
        assert!(!readiness_required(&config));
        config.ha = Some(valid_master_ha());
        assert!(readiness_required(&config));
    }
}
