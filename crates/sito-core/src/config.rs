//! Configuration structures, deserialization, and validation.

use crate::error::ConfigError;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
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
    #[serde(default)]
    pub privacy: PrivacyConfig,

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
            privacy: PrivacyConfig::default(),
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
        self.privacy.validate()?;
        if let Some(ref tls) = self.tls {
            tls.validate()?;
        }
        if let Some(ref acme) = self.get_acme_config() {
            acme.validate()?;
        }

        // Validate the structured sections stored as raw TOML so that type
        // errors (e.g. `[web] bind = ["0.0.0.0"]`) fail fast instead of being
        // silently replaced by defaults at runtime.
        if let Some(ref val) = self.web {
            let web: WebConfig = val.clone().try_into().map_err(|e| {
                ConfigError::validation("web", format!("invalid [web] section: {e}"))
            })?;
            web.validate()?;
        }
        if let Some(ref val) = self.auth {
            let auth: AuthConfig = val.clone().try_into().map_err(|e| {
                ConfigError::validation("auth", format!("invalid [auth] section: {e}"))
            })?;
            auth.validate()?;
        }
        if let Some(ref val) = self.stats {
            let stats: StatsConfig = val.clone().try_into().map_err(|e| {
                ConfigError::validation("stats", format!("invalid [stats] section: {e}"))
            })?;
            stats.validate()?;
        }
        for (name, section) in [
            ("ha", &self.ha),
            ("clients", &self.clients),
            ("rewrites", &self.rewrites),
            ("integrations", &self.integrations),
        ] {
            if let Some(val) = section
                && val.as_table().is_none()
            {
                return Err(ConfigError::validation(
                    name,
                    format!("[{name}] must be a table"),
                ));
            }
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

    /// Returns operator-facing warnings for listeners reachable beyond
    /// loopback without an explicit transport-security declaration.
    ///
    /// The messages contain only bind addresses, ports and configuration key
    /// names; they never include credentials, tokens or URL userinfo.
    #[must_use]
    pub fn network_exposure_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        // The admin UI is plain HTTP in-process. A declared TLS reverse proxy
        // is the operator's explicit acknowledgement that a proxy fronts it;
        // otherwise a non-loopback bind exposes credentials directly.
        let web = self.get_web_config();
        if web.enabled && !web.bind.is_loopback() && !self.web_tls_declared() {
            warnings.push(format!(
                "admin web UI is reachable at {} over plain HTTP; credentials, session cookies and the first-boot setup token cross the network in cleartext. Set web.bind = \"127.0.0.1\" and use an SSH tunnel or a TLS reverse proxy, or restrict TCP {} to trusted clients with a host firewall",
                SocketAddr::new(web.bind, web.port),
                web.port
            ));
        }

        // sito has no DNS client allow-list: a wildcard bind accepts recursion
        // from every source. Rate limiting attenuates abuse, it does not
        // authorize clients.
        if self.dns_listeners_exposed() {
            let binds = self
                .dns
                .bind
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            warnings.push(format!(
                "DNS listeners bind to {binds} and accept queries from any source; sito has no DNS client allow-list and rate limiting is not an access control. Restrict the DNS ports to your LAN with a host firewall or set dns.bind to specific LAN addresses"
            ));
        }

        warnings
    }

    /// True when the configuration explicitly declares that the admin scheme
    /// is HTTPS (an `https://` `web.public_url`, or `tls_terminated_by_proxy`
    /// when no public URL is set). An explicit `http://` public URL wins and
    /// keeps the plaintext warning.
    fn web_tls_declared(&self) -> bool {
        let Some(table) = self.web.as_ref().and_then(toml::Value::as_table) else {
            return false;
        };
        if let Some(url) = table.get("public_url").and_then(toml::Value::as_str) {
            return url.split_once("://").is_some_and(|(scheme, rest)| {
                !rest.is_empty() && scheme.eq_ignore_ascii_case("https")
            });
        }
        table
            .get("tls_terminated_by_proxy")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false)
    }

    /// True when any listener bind is a wildcard and at least one DNS port is
    /// enabled. `dns.port` is validated to be nonzero, but the encrypted
    /// listeners are checked too so a future plain-DNS-off mode still warns.
    fn dns_listeners_exposed(&self) -> bool {
        self.dns.bind.iter().any(IpAddr::is_unspecified)
            && [
                self.dns.port,
                self.dns.dot_port,
                self.dns.doh_port,
                self.dns.doq_port,
                self.dns.doh3_port,
            ]
            .into_iter()
            .any(|port| port != 0)
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
    /// Admin API / dashboard TCP port. Must be greater than 0; port 0 would
    /// ask the OS for an ephemeral port that operators and clients cannot
    /// discover.
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

impl WebConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::validation(
                "web.port",
                "port must be greater than 0 (0 would request an ephemeral port that clients cannot discover)",
            ));
        }
        Ok(())
    }
}

/// Query statistics and retention parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsConfig {
    /// Days to keep detailed per-query records before pruning/rollup.
    ///
    /// Must be at least 1: `0` would delete every query-log row on the next
    /// retention sweep while still advertising query logging as enabled.
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

impl StatsConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.retention_days == 0 {
            return Err(ConfigError::validation(
                "stats.retention_days",
                "retention_days must be greater than 0",
            ));
        }
        Ok(())
    }
}

/// Administrative authentication and session parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Web session lifetime in hours. Must be greater than 0: a session
    /// created with a zero TTL is already expired and can never be used.
    #[serde(default = "default_session_ttl_hours")]
    pub session_ttl_hours: u64,
    /// Maximum failed login attempts per minute per IP before lockout.
    /// `0` disables the per-IP login rate limit.
    #[serde(default = "default_login_rate_limit")]
    pub login_rate_limit: usize,
    /// Persist web sessions and API tokens across restarts (`sessions.toml`/`tokens.toml`).
    #[serde(default = "default_session_persist")]
    pub session_persist: bool,
    /// Default lifetime for newly created API tokens in days (`0` = no expiry).
    /// Defaults to 90 days so credentials do not live forever by omission.
    #[serde(default = "default_token_ttl_days")]
    pub token_default_ttl_days: u64,
}

fn default_token_ttl_days() -> u64 {
    90
}

fn default_session_ttl_hours() -> u64 {
    24
}

fn default_login_rate_limit() -> usize {
    5
}

fn default_session_persist() -> bool {
    true
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_ttl_hours: default_session_ttl_hours(),
            login_rate_limit: default_login_rate_limit(),
            session_persist: default_session_persist(),
            token_default_ttl_days: default_token_ttl_days(),
        }
    }
}

impl AuthConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.session_ttl_hours == 0 {
            return Err(ConfigError::validation(
                "auth.session_ttl_hours",
                "session_ttl_hours must be greater than 0 (sessions would expire immediately)",
            ));
        }
        Ok(())
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
    /// Require a verified release signature (cosign) for in-app updates.
    /// Default: true. A signature that is present is always verified; with
    /// this disabled, a missing signature falls back to same-origin SHA-256
    /// only, which does not protect against a compromised release channel.
    #[serde(default = "default_true")]
    pub update_require_signature: bool,
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
            update_require_signature: true,
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
    /// Addresses every listener binds (UDP/TCP DNS, DoT, DoH, DoQ, DoH3).
    #[serde(default = "default_dns_bind")]
    pub bind: Vec<IpAddr>,
    /// Plain UDP/TCP DNS port; must be greater than 0.
    #[serde(default = "default_dns_port")]
    pub port: u16,
    /// DNS-over-TLS (TCP) port; `0` disables the DoT listener.
    #[serde(default = "default_dns_dot_port")]
    pub dot_port: u16,
    /// DNS-over-HTTPS (TCP) port; `0` disables the DoH listener.
    #[serde(default = "default_dns_doh_port")]
    pub doh_port: u16,
    /// DNS-over-QUIC (UDP) port; `0` disables the DoQ listener (the default).
    #[serde(default = "default_dns_doq_port")]
    pub doq_port: u16,
    /// DNS-over-HTTP/3 (UDP) port; `0` disables the DoH3 listener.
    #[serde(default = "default_dns_doh3_port")]
    pub doh3_port: u16,
    #[serde(default)]
    pub doh_dedicated_hostname: String,
    #[serde(default)]
    pub dot_padding: bool,
    /// Allow plaintext HTTP DoH when no TLS certificate is configured
    /// (default: false; ignored for loopback binds).
    #[serde(default)]
    pub allow_plaintext_doh: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    #[serde(default = "default_dns_edns_udp_size")]
    pub edns_udp_size: u16,
    /// Per-source-IP query rate limit (queries/second); `0` disables limiting.
    ///
    /// Accepted range is `0` through [`MAX_RATE_LIMIT_PER_IP`]; see that
    /// constant for why the upper bound exists.
    #[serde(default = "default_dns_rate_limit_per_ip")]
    pub rate_limit_per_ip: u32,
    #[serde(default = "default_dns_max_tcp_connections")]
    pub max_tcp_connections: usize,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub dnssec: DnssecConfig,
}

/// Upper bound accepted for [`DnsConfig::rate_limit_per_ip`].
///
/// The transport layer sizes each client's token bucket as
/// `rate_limit_per_ip * 2` (burst), so values above `u32::MAX / 2` would
/// overflow that multiplication. This bound is deliberately far below the
/// arithmetic limit: a single source IP asking for more than one million
/// queries per second is not a real deployment, and operators who want no
/// limit can set `0` (disabled).
pub const MAX_RATE_LIMIT_PER_IP: u32 = 1_000_000;

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
    0
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
            allow_plaintext_doh: false,
            tls: None,
            edns_udp_size: default_dns_edns_udp_size(),
            rate_limit_per_ip: default_dns_rate_limit_per_ip(),
            max_tcp_connections: default_dns_max_tcp_connections(),
            cache: CacheConfig::default(),
            dnssec: DnssecConfig::default(),
        }
    }
}

/// Rejects two listeners that would contend for the same `addr:port` on the
/// same transport.
///
/// Every listener binds the shared `dns.bind` address list, so equal nonzero
/// ports always collide. Cross-transport pairs (e.g. DoT/TCP and DoQ/UDP) are
/// intentionally accepted.
fn reject_port_conflict(
    first: (&str, u16),
    second: (&str, u16),
    transport: &str,
) -> Result<(), ConfigError> {
    if first.1 > 0 && first.1 == second.1 {
        return Err(ConfigError::validation(
            second.0,
            format!(
                "{} and {} both use {transport} on the same dns.bind addresses; use distinct ports",
                second.0, first.0
            ),
        ));
    }
    Ok(())
}

impl DnsConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::validation(
                "dns.port",
                "port must be greater than 0",
            ));
        }
        if self.rate_limit_per_ip > MAX_RATE_LIMIT_PER_IP {
            return Err(ConfigError::validation(
                "dns.rate_limit_per_ip",
                format!(
                    "rate_limit_per_ip must be 0 (disabled) or between 1 and {MAX_RATE_LIMIT_PER_IP} (got {})",
                    self.rate_limit_per_ip
                ),
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
        // TCP listeners: plain DNS, DoT and DoH. UDP listeners: plain DNS, DoQ
        // and DoH3. Within one transport, equal nonzero ports cannot bind.
        reject_port_conflict(
            ("dns.dot_port", self.dot_port),
            ("dns.doh_port", self.doh_port),
            "TCP",
        )?;
        reject_port_conflict(
            ("dns.doq_port", self.doq_port),
            ("dns.doh3_port", self.doh3_port),
            "UDP",
        )?;
        reject_port_conflict(
            ("dns.port", self.port),
            ("dns.dot_port", self.dot_port),
            "TCP",
        )?;
        reject_port_conflict(
            ("dns.port", self.port),
            ("dns.doh_port", self.doh_port),
            "TCP",
        )?;
        reject_port_conflict(
            ("dns.port", self.port),
            ("dns.doq_port", self.doq_port),
            "UDP",
        )?;
        reject_port_conflict(
            ("dns.port", self.port),
            ("dns.doh3_port", self.doh3_port),
            "UDP",
        )?;
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

/// Validates one `zone:algorithm:base64` trust-anchor entry. An operator typo
/// must fail configuration loading instead of silently producing a different
/// anchor set (the validator used to default the algorithm to ECDSA P-256).
fn validate_trust_anchor(anchor: &str) -> Result<(), ConfigError> {
    use base64::Engine as _;

    let parts: Vec<&str> = anchor.split(':').collect();
    let (domain, algorithm, encoded) = match parts.as_slice() {
        [domain, algorithm, encoded] => (domain.trim(), algorithm.trim(), encoded.trim()),
        [domain, encoded] => (domain.trim(), "13", encoded.trim()),
        _ => {
            return Err(ConfigError::validation(
                "dns.dnssec.trust_anchors",
                format!("'{anchor}' must be 'zone:algorithm:base64' or 'zone:base64'"),
            ));
        }
    };
    if domain.is_empty() {
        return Err(ConfigError::validation(
            "dns.dnssec.trust_anchors",
            format!("'{anchor}' has an empty zone name"),
        ));
    }
    let algorithm: u8 = algorithm.parse().map_err(|_| {
        ConfigError::validation(
            "dns.dnssec.trust_anchors",
            format!("'{anchor}' has an unparsable algorithm number '{algorithm}'"),
        )
    })?;
    if !matches!(algorithm, 8 | 10 | 13 | 14 | 15) {
        return Err(ConfigError::validation(
            "dns.dnssec.trust_anchors",
            format!("'{anchor}' uses unsupported DNSSEC algorithm {algorithm}"),
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| {
            ConfigError::validation(
                "dns.dnssec.trust_anchors",
                format!("'{anchor}' has invalid base64 key material: {e}"),
            )
        })?;
    if bytes.is_empty() {
        return Err(ConfigError::validation(
            "dns.dnssec.trust_anchors",
            format!("'{anchor}' has empty key material"),
        ));
    }
    let name = if domain.ends_with('.') {
        domain.to_string()
    } else {
        format!("{domain}.")
    };
    hickory_proto::rr::Name::from_str(&name).map_err(|e| {
        ConfigError::validation(
            "dns.dnssec.trust_anchors",
            format!("'{anchor}' has an invalid zone name: {e}"),
        )
    })?;
    Ok(())
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
        }?;
        for anchor in &self.trust_anchors {
            validate_trust_anchor(anchor)?;
        }
        Ok(())
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

/// Policy for forwarding the RFC 7871 EDNS Client Subnet option upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamEcs {
    /// Strip client ECS options before forwarding. Upstreams only see this
    /// resolver's address, and all clients share one cache entry per question.
    #[default]
    Off,
    /// Forward client ECS options after validation and prefix clamping
    /// (IPv4 /24, IPv6 /56, source prefix 0 is dropped). This improves CDN
    /// accuracy for the client's network but discloses a coarse location
    /// hint to the upstream resolver and splits cache entries per subnet.
    Forward,
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
    /// Domain queried by upstream health probes; must be a non-empty valid DNS
    /// name.
    #[serde(default = "default_upstream_probe_domain")]
    pub probe_domain: String,
    #[serde(default = "default_upstream_pool_size")]
    pub pool_size: usize,
    /// EDNS Client Subnet (ECS) forwarding policy.
    ///
    /// `"off"` (default) strips client ECS options, so upstream resolvers only
    /// see this resolver's address and all clients share the same cache
    /// entries. `"forward"` forwards client ECS after clamping prefix lengths
    /// (IPv4 /24, IPv6 /56) and dropping a zero source prefix; this improves
    /// CDN locality but discloses a coarse client-location hint to the
    /// upstream and splits the cache by subnet.
    #[serde(default)]
    pub ecs: UpstreamEcs,
    /// Per-domain routing rules. Each rule must list at least one non-empty
    /// domain (otherwise it can never match) and one non-empty server
    /// (otherwise matching queries would fail closed with SERVFAIL).
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
            ecs: UpstreamEcs::default(),
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
        let probe_domain = self.probe_domain.trim();
        if probe_domain.is_empty() {
            return Err(ConfigError::validation(
                "upstream.probe_domain",
                "probe_domain cannot be empty",
            ));
        }
        let probe_name = if probe_domain.ends_with('.') {
            probe_domain.to_string()
        } else {
            format!("{probe_domain}.")
        };
        hickory_proto::rr::Name::from_str(&probe_name).map_err(|e| {
            ConfigError::validation(
                "upstream.probe_domain",
                format!("probe_domain '{probe_domain}' is not a valid DNS name: {e}"),
            )
        })?;

        for (i, rule) in self.per_domain.iter().enumerate() {
            if rule.domains.iter().all(|d| d.trim().is_empty()) {
                return Err(ConfigError::validation(
                    format!("upstream.per_domain[{i}].domains"),
                    "per-domain rule must list at least one non-empty domain",
                ));
            }
            if rule.servers.iter().all(|s| s.trim().is_empty()) {
                return Err(ConfigError::validation(
                    format!("upstream.per_domain[{i}].servers"),
                    "per-domain rule must list at least one non-empty upstream server",
                ));
            }
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
    /// Per-list refresh interval in hours. When unset, the global
    /// `FilteringConfig.refresh_interval_hours` is used. Must be greater than
    /// 0 when set; the scheduler would otherwise silently clamp it to 1 hour.
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
    /// When true, queries are answered with SERVFAIL while filtering is
    /// enabled but no usable rule snapshot has ever loaded (e.g. every list
    /// failed at boot). Prevents a failed initial load from silently
    /// disabling all filtering.
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    #[serde(default = "default_filtering_anti_doh_bypass")]
    pub anti_doh_bypass: String,
    /// Hard cap on the total number of parsed rules (all lists plus custom
    /// rules). A reload that would exceed the cap is rejected instead of
    /// materialising an unbounded rule set.
    #[serde(default = "default_filtering_max_rules")]
    pub max_rules: usize,
    /// Per-list download cap in bytes. Applied before a list (or its disk
    /// cache) is read into memory, so a hostile or misconfigured source cannot
    /// exhaust memory. Lowering it can invalidate larger cached lists.
    #[serde(default = "default_filtering_max_list_bytes")]
    pub max_list_bytes: usize,
    #[serde(default)]
    pub lists: Vec<FilterListConfig>,
    #[serde(default)]
    pub custom_rules: Vec<String>,
    /// Optional wall-clock budget for compiling regex/wildcard rules. When
    /// set, a compile that takes longer is aborted and the previous snapshot
    /// is retained. `None` disables the budget; zero is rejected.
    #[serde(default)]
    pub regex_compile_budget_ms: Option<u64>,
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
fn default_filtering_max_rules() -> usize {
    2_000_000
}
fn default_filtering_max_list_bytes() -> usize {
    64 * 1024 * 1024
}

impl Default for FilteringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            refresh_interval_hours: default_filtering_refresh_interval_hours(),
            blocking_mode: BlockingMode::default(),
            blocking_ttl: default_filtering_blocking_ttl(),
            cname_cloaking: true,
            fail_closed: true,
            anti_doh_bypass: default_filtering_anti_doh_bypass(),
            max_rules: default_filtering_max_rules(),
            max_list_bytes: default_filtering_max_list_bytes(),
            lists: Vec::new(),
            custom_rules: Vec::new(),
            regex_compile_budget_ms: None,
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
        if self.max_rules == 0 {
            return Err(ConfigError::validation(
                "filtering.max_rules",
                "max_rules must be greater than 0",
            ));
        }
        if self.max_list_bytes == 0 {
            return Err(ConfigError::validation(
                "filtering.max_list_bytes",
                "max_list_bytes must be greater than 0",
            ));
        }
        if self.regex_compile_budget_ms == Some(0) {
            return Err(ConfigError::validation(
                "filtering.regex_compile_budget_ms",
                "regex_compile_budget_ms must be greater than 0 when set",
            ));
        }
        let mut seen_names = std::collections::HashSet::new();
        for (i, list) in self.lists.iter().enumerate() {
            if list.name.trim().is_empty() {
                return Err(ConfigError::validation(
                    format!("filtering.lists[{i}].name"),
                    "filter list name cannot be empty",
                ));
            }
            // List names are the engine's identity (status, per-list refresh,
            // group references, cache keys); duplicates silently overwrite one
            // another and must be rejected at config time.
            if !seen_names.insert(list.name.as_str()) {
                return Err(ConfigError::validation(
                    format!("filtering.lists[{i}].name"),
                    format!("duplicate filter list name '{}'", list.name),
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
            if list.refresh_hours == Some(0) {
                return Err(ConfigError::validation(
                    format!("filtering.lists[{i}].refresh_hours"),
                    "refresh_hours must be greater than 0 when set (omit it to use filtering.refresh_interval_hours)",
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

/// Privacy and anonymization configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PrivacyConfig {
    /// Mask client IP addresses in query log database (/24 for IPv4, /56 for IPv6).
    #[serde(default, alias = "anonymize_client_ip")]
    pub anonymize_querylog: bool,
}

impl PrivacyConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
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
    fn test_upstream_ecs_policy_defaults_off_and_parses_forward() {
        let base = "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n";
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
config_version = 1
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
config_version = 1
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

    #[test]
    fn test_default_api_token_ttl_is_bounded() {
        let auth = AuthConfig::default();
        assert_eq!(
            auth.token_default_ttl_days, 90,
            "API tokens must expire by default instead of living forever"
        );
        // Explicit opt-out (no expiry) still parses.
        let cfg = Config::from_toml_str("config_version = 1\n[auth]\ntoken_default_ttl_days = 0\n")
            .unwrap();
        let parsed: AuthConfig = cfg.auth.unwrap().try_into().unwrap();
        assert_eq!(parsed.token_default_ttl_days, 0);
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
        let base = "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n";

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
    const TEST_BASE: &str = "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n";

    fn expect_validation_field(toml: &str, expected: &str) {
        let err = Config::from_toml_str(toml)
            .expect_err(&format!("config must be rejected (expected {expected})"));
        match err {
            ConfigError::Validation { field, .. } => assert_eq!(field, expected),
            other => panic!("expected validation error on {expected}, got {other:?}"),
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
        Config::from_toml_str(&omitted)
            .expect("omitting refresh_hours must use the global interval");

        let positive = format!(
            "{TEST_BASE}[filtering]\nlists = [{{ name = \"ads\", url = \"https://example.com/a.txt\", refresh_hours = 24 }}]\n"
        );
        Config::from_toml_str(&positive).expect("a positive refresh_hours must be accepted");
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

        let custom =
            Config::from_toml_str(&format!("{TEST_BASE}[filtering]\nmax_list_bytes = 1024\n"))
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

    /// Audit 6 / WP-6.5: an empty or malformed probe domain made every
    /// upstream health probe fail at runtime.
    #[test]
    fn test_upstream_probe_domain_validated() {
        expect_validation_field(
            "config_version = 1\n[upstream]\nprobe_domain = \"\"\n",
            "upstream.probe_domain",
        );
        expect_validation_field(
            "config_version = 1\n[upstream]\nprobe_domain = \"bad..name\"\n",
            "upstream.probe_domain",
        );
        Config::from_toml_str("config_version = 1\n[upstream]\nprobe_domain = \"example.com\"\n")
            .expect("a valid probe domain must be accepted");
    }

    /// Audit 6 / WP-6.5: per-domain rules without domains can never match and
    /// rules without servers fail closed with SERVFAIL.
    #[test]
    fn test_upstream_per_domain_requires_domains_and_servers() {
        expect_validation_field(
            &format!(
                "{TEST_BASE}[[upstream.per_domain]]\ndomains = []\nservers = [\"192.168.1.1\"]\n"
            ),
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

    /// 1.9.2 keeps the historical wildcard defaults, so startup must tell the
    /// operator that both the plain-HTTP admin UI and the DNS listeners are
    /// reachable beyond loopback (fail-closed visibility, truthful default).
    #[test]
    fn test_default_config_reports_web_and_dns_exposure() {
        let warnings = Config::default().network_exposure_warnings();
        assert_eq!(
            warnings.len(),
            2,
            "defaults must warn for both exposed services: {warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("admin web UI")
                && w.contains("0.0.0.0:8080")
                && w.contains("plain HTTP")),
            "missing admin UI exposure warning: {warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("DNS listeners")
                && w.contains("0.0.0.0")
                && w.contains("any source")),
            "missing DNS exposure warning: {warnings:?}"
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
            config.network_exposure_warnings(),
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
            disabled.network_exposure_warnings().is_empty(),
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
            config.network_exposure_warnings().is_empty(),
            "HTTPS reverse proxy declaration must suppress the plaintext warning"
        );

        let proxy_flag_only = format!(
            "{TEST_BASE}[dns]\nbind = [\"127.0.0.1\"]\n[web]\nbind = \"0.0.0.0\"\ntls_terminated_by_proxy = true\n"
        );
        let config = Config::from_toml_str(&proxy_flag_only).expect("valid config");
        assert!(
            config.network_exposure_warnings().is_empty(),
            "tls_terminated_by_proxy without public_url must suppress the warning"
        );

        let http_public_url = format!(
            "{TEST_BASE}[dns]\nbind = [\"127.0.0.1\"]\n[web]\nbind = \"0.0.0.0\"\npublic_url = \"http://dns.example.com:8080\"\ntls_terminated_by_proxy = true\n"
        );
        let config = Config::from_toml_str(&http_public_url).expect("valid config");
        assert!(
            config
                .network_exposure_warnings()
                .iter()
                .any(|w| w.contains("admin web UI")),
            "an explicit http:// public URL must still warn even with the proxy flag"
        );
    }

    /// Warnings are written to logs; they must never echo credentials or
    /// tokens from unrelated configuration sections.
    #[test]
    fn test_exposure_warnings_do_not_leak_secrets() {
        let config = Config::from_toml_str(&format!(
            "{TEST_BASE}[dns]\nbind = [\"0.0.0.0\"]\n[web]\nbind = \"0.0.0.0\"\npublic_url = \"http://secret-user:secret-pass@example.test:8080\"\n[ha]\nslave_token = \"top-secret-token\"\n"
        ))
        .expect("valid config");
        let rendered = config.network_exposure_warnings().join("\n");
        for secret in ["secret-user", "secret-pass", "top-secret-token"] {
            assert!(
                !rendered.contains(secret),
                "warning leaked '{secret}': {rendered}"
            );
        }
    }
}
