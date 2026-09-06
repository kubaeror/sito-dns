//! Configuration structures, deserialization, and validation.

use crate::error::ConfigError;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

/// Top-level configuration container for sito.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_config_version")]
    pub config_version: u32,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub filtering: FilteringConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme: Option<AcmeConfig>,

    // Additional forward-compatible sections that might be present in full configs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clients: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrites: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ha: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrations: Option<toml::Value>,
}

fn default_config_version() -> u32 {
    1
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_version: 1,
            server: ServerConfig::default(),
            dns: DnsConfig::default(),
            upstream: UpstreamConfig::default(),
            filtering: FilteringConfig::default(),
            tls: None,
            acme: None,
            clients: None,
            rewrites: None,
            web: None,
            auth: None,
            stats: None,
            ha: None,
            integrations: None,
        }
    }
}

impl Config {
    /// Parse configuration from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration fields and logic constraints.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.config_version != 1 {
            return Err(ConfigError::validation(
                "config_version",
                format!(
                    "unsupported config_version {}, expected 1",
                    self.config_version
                ),
            ));
        }

        self.server.validate()?;
        self.dns.validate()?;
        self.upstream.validate()?;
        self.filtering.validate()?;
        if let Some(ref tls) = self.tls {
            tls.validate()?;
        }
        if let Some(ref acme) = self.get_acme_config() {
            acme.validate()?;
        }

        Ok(())
    }

    /// Resolves the effective TLS configuration (checking `dns.tls` first, then top-level `tls`).
    pub fn get_tls_config(&self) -> Option<&TlsConfig> {
        if let Some(ref tls) = self.dns.tls {
            return Some(tls);
        }
        if let Some(ref tls) = self.tls {
            return Some(tls);
        }
        None
    }

    /// Resolves the effective ACME configuration (checking `acme` first, then `web.acme_*`).
    pub fn get_acme_config(&self) -> Option<AcmeConfig> {
        if let Some(ref acme) = self.acme {
            return Some(acme.clone());
        }
        if let Some(ref web_val) = self.web
            && let Ok(web_table) = web_val.clone().try_into::<toml::Table>()
        {
            let enabled = web_table
                .get("acme_enabled")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false);
            let email = web_table
                .get("acme_email")
                .and_then(toml::Value::as_str)
                .map(std::string::ToString::to_string);
            let domains: Vec<String> = web_table
                .get("acme_domains")
                .and_then(toml::Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(std::string::ToString::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let staging = web_table
                .get("acme_staging")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false);
            let cache_dir = web_table
                .get("acme_cache_dir")
                .and_then(toml::Value::as_str)
                .map(PathBuf::from);

            if enabled || !domains.is_empty() || email.is_some() {
                return Some(AcmeConfig {
                    enabled,
                    email,
                    domains,
                    staging,
                    cache_dir,
                    http_port: default_acme_http_port(),
                });
            }
        }
        None
    }

    /// Resolves the effective web configuration.
    pub fn get_web_config(&self) -> WebConfig {
        if let Some(ref val) = self.web {
            match val.clone().try_into::<WebConfig>() {
                Ok(cfg) => return cfg,
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse [web] section in configuration, falling back to defaults: {e}"
                    );
                }
            }
        }
        WebConfig::default()
    }

    /// Sets or overrides the web configuration.
    pub fn set_web_config(&mut self, web: WebConfig) {
        if let Ok(val) = toml::Value::try_from(web) {
            self.web = Some(val);
        }
    }

    /// Resolves the effective stats configuration.
    pub fn get_stats_config(&self) -> StatsConfig {
        if let Some(ref val) = self.stats {
            match val.clone().try_into::<StatsConfig>() {
                Ok(cfg) => return cfg,
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse [stats] section in configuration, falling back to defaults: {e}"
                    );
                }
            }
        }
        StatsConfig::default()
    }

    /// Resolves the effective auth configuration.
    pub fn get_auth_config(&self) -> AuthConfig {
        if let Some(ref val) = self.auth {
            match val.clone().try_into::<AuthConfig>() {
                Ok(cfg) => return cfg,
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse [auth] section in configuration, falling back to defaults: {e}"
                    );
                }
            }
        }
        AuthConfig::default()
    }
}

/// Web administrative server parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebConfig {
    #[serde(default = "default_web_enabled")]
    pub enabled: bool,
    #[serde(default = "default_web_bind")]
    pub bind: IpAddr,
    #[serde(default = "default_web_port")]
    pub port: u16,
    #[serde(default)]
    pub trusted_proxies: Vec<IpAddr>,
    #[serde(default = "default_metrics_auth")]
    pub metrics_auth: bool,
}

fn default_metrics_auth() -> bool {
    true
}

fn default_web_enabled() -> bool {
    true
}

fn default_web_bind() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
}

fn default_web_port() -> u16 {
    8080
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: default_web_enabled(),
            bind: default_web_bind(),
            port: default_web_port(),
            trusted_proxies: Vec::new(),
            metrics_auth: default_metrics_auth(),
        }
    }
}

/// Query statistics and retention parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsConfig {
    #[serde(default = "default_retention_days", alias = "query_log_retention_days")]
    pub retention_days: u32,
}

fn default_retention_days() -> u32 {
    90
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            retention_days: default_retention_days(),
        }
    }
}

/// Administrative authentication and session parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_session_ttl_hours")]
    pub session_ttl_hours: u64,
    #[serde(default = "default_login_rate_limit")]
    pub login_rate_limit: usize,
}

fn default_session_ttl_hours() -> u64 {
    24
}

fn default_login_rate_limit() -> usize {
    5
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_ttl_hours: default_session_ttl_hours(),
            login_rate_limit: default_login_rate_limit(),
        }
    }
}

/// Server operational parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_server_role")]
    pub role: String,
    #[serde(default = "default_server_instance_name")]
    pub instance_name: String,
    #[serde(default = "default_server_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_server_log_level")]
    pub log_level: String,
    #[serde(default = "default_server_log_format")]
    pub log_format: String,
}

fn default_server_role() -> String {
    "master".to_string()
}
fn default_server_instance_name() -> String {
    "sito-main".to_string()
}
fn default_server_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/sito")
}
fn default_server_log_level() -> String {
    "info".to_string()
}
fn default_server_log_format() -> String {
    "json".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            role: default_server_role(),
            instance_name: default_server_instance_name(),
            data_dir: default_server_data_dir(),
            log_level: default_server_log_level(),
            log_format: default_server_log_format(),
        }
    }
}

impl ServerConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self.role.as_str() {
            "master" | "slave" => {}
            other => {
                return Err(ConfigError::validation(
                    "server.role",
                    format!("invalid server role '{other}', expected 'master' or 'slave'"),
                ));
            }
        }

        match self.log_level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            other => {
                return Err(ConfigError::validation(
                    "server.log_level",
                    format!(
                        "invalid log level '{other}', expected trace, debug, info, warn, or error"
                    ),
                ));
            }
        }

        match self.log_format.to_lowercase().as_str() {
            "json" | "pretty" => {}
            other => {
                return Err(ConfigError::validation(
                    "server.log_format",
                    format!("invalid log format '{other}', expected 'json' or 'pretty'"),
                ));
            }
        }

        Ok(())
    }
}

/// DNS server listening and protocol parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_dns_bind")]
    pub bind: Vec<IpAddr>,
    #[serde(default = "default_dns_port")]
    pub port: u16,
    #[serde(default = "default_dns_dot_port")]
    pub dot_port: u16,
    #[serde(default = "default_dns_doh_port")]
    pub doh_port: u16,
    #[serde(default = "default_dns_doq_port")]
    pub doq_port: u16,
    #[serde(default = "default_dns_doh3_port")]
    pub doh3_port: u16,
    #[serde(default)]
    pub doh_dedicated_hostname: String,
    #[serde(default)]
    pub dot_padding: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    #[serde(default = "default_dns_edns_udp_size")]
    pub edns_udp_size: u16,
    #[serde(default = "default_dns_rate_limit_per_ip")]
    pub rate_limit_per_ip: u32,
    #[serde(default = "default_dns_max_tcp_connections")]
    pub max_tcp_connections: usize,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub dnssec: DnssecConfig,
}

fn default_dns_bind() -> Vec<IpAddr> {
    vec![
        IpAddr::from_str("0.0.0.0").expect("valid 0.0.0.0"),
        IpAddr::from_str("::").expect("valid ::"),
    ]
}
fn default_dns_port() -> u16 {
    53
}
fn default_dns_dot_port() -> u16 {
    853
}
fn default_dns_doh_port() -> u16 {
    443
}
fn default_dns_doq_port() -> u16 {
    853
}
fn default_dns_doh3_port() -> u16 {
    443
}
fn default_dns_edns_udp_size() -> u16 {
    1232
}
fn default_dns_rate_limit_per_ip() -> u32 {
    20
}
fn default_dns_max_tcp_connections() -> usize {
    256
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            bind: default_dns_bind(),
            port: default_dns_port(),
            dot_port: default_dns_dot_port(),
            doh_port: default_dns_doh_port(),
            doq_port: default_dns_doq_port(),
            doh3_port: default_dns_doh3_port(),
            doh_dedicated_hostname: String::new(),
            dot_padding: false,
            tls: None,
            edns_udp_size: default_dns_edns_udp_size(),
            rate_limit_per_ip: default_dns_rate_limit_per_ip(),
            max_tcp_connections: default_dns_max_tcp_connections(),
            cache: CacheConfig::default(),
            dnssec: DnssecConfig::default(),
        }
    }
}

impl DnsConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::validation(
                "dns.port",
                "port must be greater than 0",
            ));
        }
        if self.bind.is_empty() {
            return Err(ConfigError::validation(
                "dns.bind",
                "bind address list cannot be empty",
            ));
        }
        if self.edns_udp_size < 512 || self.edns_udp_size > 4096 {
            return Err(ConfigError::validation(
                "dns.edns_udp_size",
                format!(
                    "edns_udp_size must be between 512 and 4096 bytes (got {})",
                    self.edns_udp_size
                ),
            ));
        }
        if self.max_tcp_connections == 0 {
            return Err(ConfigError::validation(
                "dns.max_tcp_connections",
                "max_tcp_connections must be greater than 0",
            ));
        }
        if let Some(ref tls) = self.tls {
            tls.validate()?;
        }
        self.cache.validate()?;
        self.dnssec.validate()?;
        Ok(())
    }
}

/// Cache settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_cache_size_mb")]
    pub size_mb: usize,
    #[serde(default = "default_cache_min_ttl")]
    pub min_ttl: u32,
    #[serde(default = "default_cache_max_ttl")]
    pub max_ttl: u32,
    #[serde(default = "default_cache_negative_ttl_max")]
    pub negative_ttl_max: u32,
    #[serde(default = "default_true")]
    pub prefetch: bool,
    #[serde(default = "default_cache_serve_stale_hours")]
    pub serve_stale_hours: u32,
}

fn default_true() -> bool {
    true
}
fn default_cache_size_mb() -> usize {
    64
}
fn default_cache_min_ttl() -> u32 {
    60
}
fn default_cache_max_ttl() -> u32 {
    86400
}
fn default_cache_negative_ttl_max() -> u32 {
    3600
}
fn default_cache_serve_stale_hours() -> u32 {
    12
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            size_mb: default_cache_size_mb(),
            min_ttl: default_cache_min_ttl(),
            max_ttl: default_cache_max_ttl(),
            negative_ttl_max: default_cache_negative_ttl_max(),
            prefetch: true,
            serve_stale_hours: default_cache_serve_stale_hours(),
        }
    }
}

impl CacheConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.size_mb == 0 {
            return Err(ConfigError::validation(
                "dns.cache.size_mb",
                "cache size_mb must be greater than 0",
            ));
        }
        if self.min_ttl > self.max_ttl {
            return Err(ConfigError::validation(
                "dns.cache.min_ttl",
                format!(
                    "min_ttl ({}) cannot be greater than max_ttl ({})",
                    self.min_ttl, self.max_ttl
                ),
            ));
        }
        if self.min_ttl > self.negative_ttl_max {
            return Err(ConfigError::validation(
                "dns.cache.negative_ttl_max",
                format!(
                    "negative_ttl_max ({}) cannot be less than min_ttl ({})",
                    self.negative_ttl_max, self.min_ttl
                ),
            ));
        }
        Ok(())
    }
}

fn default_dnssec_mode() -> String {
    "validate".to_string()
}

/// DNSSEC settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnssecConfig {
    #[serde(default = "default_dnssec_mode")]
    pub mode: String,
    #[serde(default = "default_true")]
    pub validate: bool,
    #[serde(default)]
    pub ntp: Vec<String>,
    #[serde(default)]
    pub nta: Vec<String>,
    #[serde(default)]
    pub trust_anchors: Vec<String>,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            mode: default_dnssec_mode(),
            validate: true,
            ntp: Vec::new(),
            nta: Vec::new(),
            trust_anchors: Vec::new(),
        }
    }
}

impl DnssecConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self.mode.to_ascii_lowercase().as_str() {
            "validate" | "strict" | "log_only" | "log-only" | "permissive" | "off" | "disabled" => {
                Ok(())
            }
            _ => Err(ConfigError::validation(
                "dns.dnssec.mode",
                format!("unrecognized DNSSEC mode: '{}'", self.mode),
            )),
        }
    }

    /// Check if a domain matches any configured Negative Trust Anchor (NTA/NTP).
    pub fn is_nta(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_lowercase();
        for anchor in self.ntp.iter().chain(self.nta.iter()) {
            let a = anchor.trim_end_matches('.').to_lowercase();
            if d == a || d.ends_with(&format!(".{a}")) {
                return true;
            }
        }
        false
    }
}

/// TLS configuration for DoT, DoH, and encrypted listeners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    #[serde(default)]
    pub cert: Option<PathBuf>,
    #[serde(default)]
    pub key: Option<PathBuf>,
    #[serde(default)]
    pub sni_certs: Vec<SniCertConfig>,
}

/// SNI-to-certificate mapping configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SniCertConfig {
    pub domain: String,
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl TlsConfig {
    pub fn sni_tuples(&self) -> Vec<(String, PathBuf, PathBuf)> {
        self.sni_certs
            .iter()
            .map(|s| (s.domain.clone(), s.cert.clone(), s.key.clone()))
            .collect()
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        match (&self.cert, &self.key) {
            (Some(_), None) => {
                return Err(ConfigError::validation(
                    "tls.key",
                    "tls.key must be specified when tls.cert is configured",
                ));
            }
            (None, Some(_)) => {
                return Err(ConfigError::validation(
                    "tls.cert",
                    "tls.cert must be specified when tls.key is configured",
                ));
            }
            (Some(cert), Some(key)) => {
                if cert.as_os_str().is_empty() {
                    return Err(ConfigError::validation(
                        "tls.cert",
                        "tls.cert path cannot be empty",
                    ));
                }
                if key.as_os_str().is_empty() {
                    return Err(ConfigError::validation(
                        "tls.key",
                        "tls.key path cannot be empty",
                    ));
                }
            }
            (None, None) => {}
        }

        for (idx, sni) in self.sni_certs.iter().enumerate() {
            if sni.domain.trim().is_empty() {
                return Err(ConfigError::validation(
                    format!("tls.sni_certs[{idx}].domain"),
                    "SNI domain cannot be empty",
                ));
            }
            if sni.cert.as_os_str().is_empty() {
                return Err(ConfigError::validation(
                    format!("tls.sni_certs[{idx}].cert"),
                    "SNI cert path cannot be empty",
                ));
            }
            if sni.key.as_os_str().is_empty() {
                return Err(ConfigError::validation(
                    format!("tls.sni_certs[{idx}].key"),
                    "SNI key path cannot be empty",
                ));
            }
        }

        Ok(())
    }
}

/// Upstream resolver strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamStrategy {
    Parallel,
    #[default]
    Failover,
    LoadBalance,
}

/// Per-domain upstream forwarder routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerDomainUpstream {
    pub domains: Vec<String>,
    pub servers: Vec<String>,
}

/// Upstream resolvers and forwarding configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamConfig {
    #[serde(default = "default_upstream_servers")]
    pub servers: Vec<String>,
    #[serde(default = "default_upstream_bootstrap")]
    pub bootstrap: Vec<IpAddr>,
    #[serde(default)]
    pub strategy: UpstreamStrategy,
    #[serde(default = "default_upstream_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_upstream_probe_domain")]
    pub probe_domain: String,
    #[serde(default = "default_upstream_pool_size")]
    pub pool_size: usize,
    #[serde(default)]
    pub per_domain: Vec<PerDomainUpstream>,
}

fn default_upstream_servers() -> Vec<String> {
    vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]
}
fn default_upstream_bootstrap() -> Vec<IpAddr> {
    vec![
        IpAddr::from_str("9.9.9.9").expect("valid 9.9.9.9"),
        IpAddr::from_str("149.112.112.112").expect("valid 149.112.112.112"),
    ]
}
fn default_upstream_timeout_ms() -> u64 {
    5000
}
fn default_upstream_probe_domain() -> String {
    "example.com".to_string()
}
fn default_upstream_pool_size() -> usize {
    4
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            servers: default_upstream_servers(),
            bootstrap: default_upstream_bootstrap(),
            strategy: UpstreamStrategy::default(),
            timeout_ms: default_upstream_timeout_ms(),
            probe_domain: default_upstream_probe_domain(),
            pool_size: default_upstream_pool_size(),
            per_domain: Vec::new(),
        }
    }
}

impl UpstreamConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.servers.is_empty() {
            return Err(ConfigError::validation(
                "upstream.servers",
                "servers list cannot be empty",
            ));
        }
        if self.timeout_ms == 0 {
            return Err(ConfigError::validation(
                "upstream.timeout_ms",
                "timeout_ms must be greater than 0",
            ));
        }
        if self.pool_size == 0 {
            return Err(ConfigError::validation(
                "upstream.pool_size",
                "pool_size must be greater than 0",
            ));
        }
        Ok(())
    }
}

/// Filter blocking response modes per ADR-0005 and Section 4.5.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BlockingMode {
    #[default]
    ZeroIp,
    Nxdomain,
    Refused,
    CustomIp(IpAddr),
    NullRdata,
}

impl Serialize for BlockingMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::ZeroIp => serializer.serialize_str("zero_ip"),
            Self::Nxdomain => serializer.serialize_str("nxdomain"),
            Self::Refused => serializer.serialize_str("refused"),
            Self::NullRdata => serializer.serialize_str("null_rdata"),
            Self::CustomIp(ip) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("custom_ip", &ip.to_string())?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for BlockingMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BlockingModeVisitor;

        impl<'de> serde::de::Visitor<'de> for BlockingModeVisitor {
            type Value = BlockingMode;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "a blocking mode string ('zero_ip', 'nxdomain', 'refused', 'null_rdata', 'custom_ip:<ip>', '<ip>') or map with 'custom_ip'",
                )
            }

            fn visit_str<E>(self, v: &str) -> Result<BlockingMode, E>
            where
                E: serde::de::Error,
            {
                match v {
                    "zero_ip" => Ok(BlockingMode::ZeroIp),
                    "nxdomain" => Ok(BlockingMode::Nxdomain),
                    "refused" => Ok(BlockingMode::Refused),
                    "null_rdata" => Ok(BlockingMode::NullRdata),
                    s if s.starts_with("custom_ip:") => {
                        let ip_str = &s["custom_ip:".len()..];
                        ip_str
                            .parse::<IpAddr>()
                            .map(BlockingMode::CustomIp)
                            .map_err(|e| {
                                E::custom(format!("invalid custom IP in blocking_mode: {e}"))
                            })
                    }
                    s => {
                        if let Ok(ip) = s.parse::<IpAddr>() {
                            Ok(BlockingMode::CustomIp(ip))
                        } else {
                            Err(E::unknown_variant(
                                v,
                                &["zero_ip", "nxdomain", "refused", "null_rdata", "custom_ip"],
                            ))
                        }
                    }
                }
            }

            fn visit_map<M>(self, mut map: M) -> Result<BlockingMode, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                while let Some(key) = map.next_key::<String>()? {
                    if key == "custom_ip" {
                        let ip_val: IpAddr = map.next_value()?;
                        return Ok(BlockingMode::CustomIp(ip_val));
                    }
                    let _: serde::de::IgnoredAny = map.next_value()?;
                }
                Err(serde::de::Error::custom("missing 'custom_ip' field in map"))
            }
        }

        deserializer.deserialize_any(BlockingModeVisitor)
    }
}

/// A filter list definition to download and compile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterListConfig {
    pub name: String,
    pub url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Deprecated/legacy per-list refresh interval.
    /// Ignored by scheduler; global `FilteringConfig.refresh_interval_hours` is used instead.
    #[serde(default)]
    pub refresh_hours: Option<u64>,
}

/// Filtering and blocklist configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilteringConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_filtering_refresh_interval_hours")]
    pub refresh_interval_hours: u64,
    #[serde(default)]
    pub blocking_mode: BlockingMode,
    #[serde(default = "default_filtering_blocking_ttl")]
    pub blocking_ttl: u32,
    #[serde(default = "default_true")]
    pub cname_cloaking: bool,
    #[serde(default = "default_filtering_anti_doh_bypass")]
    pub anti_doh_bypass: String,
    #[serde(default)]
    pub lists: Vec<FilterListConfig>,
    #[serde(default)]
    pub custom_rules: Vec<String>,
}

fn default_filtering_refresh_interval_hours() -> u64 {
    24
}
fn default_filtering_blocking_ttl() -> u32 {
    10
}
fn default_filtering_anti_doh_bypass() -> String {
    "off".to_string()
}

impl Default for FilteringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            refresh_interval_hours: default_filtering_refresh_interval_hours(),
            blocking_mode: BlockingMode::default(),
            blocking_ttl: default_filtering_blocking_ttl(),
            cname_cloaking: true,
            anti_doh_bypass: default_filtering_anti_doh_bypass(),
            lists: Vec::new(),
            custom_rules: Vec::new(),
        }
    }
}

impl FilteringConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.refresh_interval_hours == 0 {
            return Err(ConfigError::validation(
                "filtering.refresh_interval_hours",
                "refresh_interval_hours must be greater than 0",
            ));
        }
        for (i, list) in self.lists.iter().enumerate() {
            if list.name.trim().is_empty() {
                return Err(ConfigError::validation(
                    format!("filtering.lists[{i}].name"),
                    "filter list name cannot be empty",
                ));
            }
            if list.url.trim().is_empty() {
                return Err(ConfigError::validation(
                    format!("filtering.lists[{i}].url"),
                    "filter list URL cannot be empty",
                ));
            }
            let url_lower = list.url.trim().to_ascii_lowercase();
            if !url_lower.starts_with("http://")
                && !url_lower.starts_with("https://")
                && !url_lower.starts_with("file://")
            {
                return Err(ConfigError::validation(
                    format!("filtering.lists[{i}].url"),
                    "filter list URL must use http://, https://, or file:// scheme",
                ));
            }
        }
        match self.anti_doh_bypass.as_str() {
            "off" | "block_all" | "block_except_trusted" => {}
            other => {
                return Err(ConfigError::validation(
                    "filtering.anti_doh_bypass",
                    format!(
                        "invalid anti_doh_bypass mode '{other}', expected 'off', 'block_all', or 'block_except_trusted'"
                    ),
                ));
            }
        }

        Ok(())
    }
}

/// ACME automated certificate configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub staging: bool,
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
    #[serde(default = "default_acme_http_port")]
    pub http_port: u16,
}

fn default_acme_http_port() -> u16 {
    80
}

impl AcmeConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled {
            if self.domains.is_empty() {
                return Err(ConfigError::validation(
                    "acme.domains",
                    "acme.domains cannot be empty when ACME is enabled",
                ));
            }
            for (idx, domain) in self.domains.iter().enumerate() {
                if domain.trim().is_empty() {
                    return Err(ConfigError::validation(
                        format!("acme.domains[{idx}]"),
                        "ACME domain cannot be empty",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_section_15_example() {
        let toml_str = r#"
config_version = 1

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
bind = ["0.0.0.0"]

[auth]
session_ttl_hours = 24

[stats]
query_log_enabled = true

[ha]
replication_port = 8953

[integrations.mikrotik]
enabled = false
"#;
        let config =
            Config::from_toml_str(toml_str).expect("section 15 config should parse cleanly");
        assert_eq!(config.config_version, 1);
        assert_eq!(config.server.role, "master");
        assert_eq!(config.dns.port, 53);
        assert_eq!(config.dns.cache.size_mb, 64);
        assert_eq!(config.upstream.strategy, UpstreamStrategy::Parallel);
        assert_eq!(config.filtering.blocking_mode, BlockingMode::ZeroIp);
        assert_eq!(config.filtering.lists.len(), 1);
        assert_eq!(config.filtering.lists[0].name, "OISD");
    }

    #[test]
    fn test_reject_invalid_config() {
        // Bad config version
        let bad_ver = "config_version = 2\n[upstream]\nservers = [\"1.1.1.1\"]";
        let err = Config::from_toml_str(bad_ver).unwrap_err();
        match err {
            ConfigError::Validation { field, .. } => assert_eq!(field, "config_version"),
            other => panic!("expected validation error on config_version, got: {other:?}"),
        }

        // Empty upstream servers
        let empty_up = "config_version = 1\n[upstream]\nservers = []";
        let err = Config::from_toml_str(empty_up).unwrap_err();
        match err {
            ConfigError::Validation { field, .. } => assert_eq!(field, "upstream.servers"),
            other => panic!("expected validation error on upstream.servers, got: {other:?}"),
        }

        // Bad min/max ttl
        let bad_ttl = "config_version = 1\n[dns.cache]\nmin_ttl = 500\nmax_ttl = 100\n[upstream]\nservers = [\"1.1.1.1\"]";
        let err = Config::from_toml_str(bad_ttl).unwrap_err();
        match err {
            ConfigError::Validation { field, .. } => assert_eq!(field, "dns.cache.min_ttl"),
            other => panic!("expected validation error on dns.cache.min_ttl, got: {other:?}"),
        }
    }

    #[test]
    fn test_blocking_mode_deserialization() {
        let toml_null = "config_version = 1\n[filtering]\nblocking_mode = \"null_rdata\"\n[upstream]\nservers = [\"1.1.1.1\"]";
        let cfg = Config::from_toml_str(toml_null).unwrap();
        assert_eq!(cfg.filtering.blocking_mode, BlockingMode::NullRdata);

        let toml_custom = "config_version = 1\n[filtering]\nblocking_mode = \"custom_ip:192.168.1.50\"\n[upstream]\nservers = [\"1.1.1.1\"]";
        let cfg = Config::from_toml_str(toml_custom).unwrap();
        assert_eq!(
            cfg.filtering.blocking_mode,
            BlockingMode::CustomIp("192.168.1.50".parse().unwrap())
        );

        let toml_refused = "config_version = 1\n[filtering]\nblocking_mode = \"refused\"\n[upstream]\nservers = [\"1.1.1.1\"]";
        let cfg = Config::from_toml_str(toml_refused).unwrap();
        assert_eq!(cfg.filtering.blocking_mode, BlockingMode::Refused);

        let toml_nxdomain = "config_version = 1\n[filtering]\nblocking_mode = \"nxdomain\"\n[upstream]\nservers = [\"1.1.1.1\"]";
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
config_version = 1
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
config_version = 1
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
}
