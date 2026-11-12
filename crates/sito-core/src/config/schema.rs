//! Serde schema types, defaults, and per-section validation.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Top-level configuration container for sito.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    CONFIG_VERSION
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_version: CONFIG_VERSION,
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

/// Web administrative server parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Explicit external URL of the admin UI. The scheme decides Secure
    /// cookies/HSTS; only `http://` and `https://` are accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    /// A trusted reverse proxy terminates TLS in front of the admin UI.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tls_terminated_by_proxy: bool,

    // Deprecated v1 aliases, accepted for one 2.0 alpha. The migration moves
    // them into typed `[acme]`; new configuration must use `[acme]`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub acme_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_email: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acme_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub acme_staging: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_cache_dir: Option<PathBuf>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

fn default_metrics_auth() -> bool {
    true
}

fn default_web_enabled() -> bool {
    true
}

fn default_web_bind() -> IpAddr {
    // 2.0 safe default: the admin UI is plain HTTP, so it binds loopback until
    // the operator explicitly exposes it (D4/§12). Migrated v1 documents keep
    // their old bind unless `--adopt-safe-defaults` is passed.
    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
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
            public_url: None,
            tls_terminated_by_proxy: false,
            acme_enabled: false,
            acme_email: None,
            acme_domains: Vec::new(),
            acme_staging: false,
            acme_cache_dir: None,
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
        if let Some(url) = self.public_url.as_deref() {
            let valid = url.split_once("://").is_some_and(|(scheme, rest)| {
                !rest.is_empty()
                    && (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
            });
            if !valid {
                return Err(ConfigError::validation(
                    "web.public_url",
                    format!("public_url '{url}' must start with http:// or https://"),
                ));
            }
        }
        // Deprecated [web] acme_* aliases share the typed [acme] rules.
        if self.acme_enabled || !self.acme_domains.is_empty() || self.acme_email.is_some() {
            AcmeConfig {
                enabled: self.acme_enabled,
                email: self.acme_email.clone(),
                domains: self.acme_domains.clone(),
                staging: self.acme_staging,
                cache_dir: self.acme_cache_dir.clone(),
                http_port: default_acme_http_port(),
                allow_bootstrap_cert: false,
            }
            .validate()?;
        }
        Ok(())
    }
}

/// Query statistics and retention parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsConfig {
    /// Days to keep detailed per-query records before pruning/rollup.
    ///
    /// Must be at least 1: `0` would delete every query-log row on the next
    /// retention sweep while still advertising query logging as enabled.
    #[serde(default = "default_retention_days", alias = "query_log_retention_days")]
    pub retention_days: u32,
    /// Days to keep hourly rollups (aggregate totals, top domains and hashed
    /// client identifiers) after detailed query-log rows are pruned.
    ///
    /// Rollup rows older than this are deleted. Must be at least 1.
    #[serde(default = "default_rollup_retention_days")]
    pub rollup_retention_days: u32,
    /// Include client display names in hourly rollups. Disabled by default so
    /// long-lived aggregates do not retain identifiable device labels.
    #[serde(default)]
    pub rollup_client_names: bool,
}

fn default_retention_days() -> u32 {
    90
}

fn default_rollup_retention_days() -> u32 {
    365
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            retention_days: default_retention_days(),
            rollup_retention_days: default_rollup_retention_days(),
            rollup_client_names: false,
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
        if self.rollup_retention_days == 0 {
            return Err(ConfigError::validation(
                "stats.rollup_retention_days",
                "rollup_retention_days must be greater than 0",
            ));
        }
        Ok(())
    }
}

/// Administrative authentication and session parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
        let mut seen_binds = std::collections::HashSet::new();
        for bind in &self.bind {
            if !seen_binds.insert(*bind) {
                return Err(ConfigError::cross_section(
                    "dns.bind",
                    format!(
                        "duplicate bind address {bind}; listing one address twice makes the listener fail to bind"
                    ),
                ));
            }
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
            super::validate::validate_trust_anchor(anchor)?;
        }
        Ok(())
    }

    /// Check if a domain matches any configured Negative Trust Anchor (NTA/NTP).
    pub fn is_nta(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_lowercase();
        for anchor in self.ntp.iter().chain(self.nta.iter()) {
            let a = anchor.trim_end_matches('.').to_lowercase();
            if crate::domain::matches_domain_suffix(&d, &a) {
                return true;
            }
        }
        false
    }
}

/// TLS configuration for DoT, DoH, and encrypted listeners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
            NormalizedDomain::parse(&sni.domain).map_err(|e| {
                ConfigError::validation(
                    format!("tls.sni_certs[{idx}].domain"),
                    format!("invalid SNI domain '{}': {e}", sni.domain),
                )
            })?;
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

        let mut seen_domains = std::collections::HashSet::new();
        for (idx, sni) in self.sni_certs.iter().enumerate() {
            let normalized = NormalizedDomain::parse(&sni.domain).map_err(|e| {
                ConfigError::validation(
                    format!("tls.sni_certs[{idx}].domain"),
                    format!("invalid SNI domain '{}': {e}", sni.domain),
                )
            })?;
            if !seen_domains.insert(normalized.into_string()) {
                return Err(ConfigError::cross_section(
                    format!("tls.sni_certs[{idx}].domain"),
                    format!("duplicate SNI domain '{}'", sni.domain),
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
#[serde(deny_unknown_fields)]
pub struct PerDomainUpstream {
    pub domains: Vec<String>,
    pub servers: Vec<String>,
}

/// Upstream resolvers and forwarding configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Allow hostname-configured upstreams to resolve to private, loopback,
    /// link-local or otherwise reserved addresses.
    ///
    /// Disabled by default to prevent a compromised/spoofed bootstrap answer
    /// from redirecting an upstream into the local network or a cloud metadata
    /// endpoint. IP literals in `servers` are always accepted because they are
    /// an explicit operator choice. Set this to `true` only when an internal
    /// resolver is intentionally reached via a hostname.
    #[serde(default)]
    pub allow_private_targets: bool,
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
            allow_private_targets: false,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// Accept an empty list body or a list that yields zero rules instead of
    /// rejecting it and keeping the previous snapshot. Disabled by default:
    /// a broken/hostile source must not silently remove all protection.
    #[serde(default)]
    pub allow_empty_list: bool,
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
            allow_empty_list: false,
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
#[serde(deny_unknown_fields)]
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
    /// Serve a short-lived self-signed bootstrap certificate on encrypted
    /// listeners while the first ACME certificate is being issued.
    ///
    /// Defaults to `false` (fail closed): encrypted listeners stay disabled
    /// until a real certificate exists unless the operator explicitly opts in.
    #[serde(default)]
    pub allow_bootstrap_cert: bool,
}

pub(super) fn default_acme_http_port() -> u16 {
    80
}

impl AcmeConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled && self.domains.is_empty() {
            return Err(ConfigError::validation(
                "acme.domains",
                "acme.domains cannot be empty when ACME is enabled",
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for (idx, domain) in self.domains.iter().enumerate() {
            let field = format!("acme.domains[{idx}]");
            let normalized = NormalizedDomain::parse(domain).map_err(|e| {
                ConfigError::validation(
                    field.clone(),
                    format!("invalid ACME domain '{domain}': {e}"),
                )
            })?;
            if normalized.has_wildcard_labels() {
                return Err(ConfigError::validation(
                    field,
                    format!(
                        "ACME domain '{domain}' cannot be a wildcard; issue one certificate per exact name"
                    ),
                ));
            }
            if normalized.is_root() {
                return Err(ConfigError::validation(
                    field,
                    "the DNS root cannot be an ACME domain",
                ));
            }
            if !seen.insert(normalized.as_str().to_string()) {
                return Err(ConfigError::validation(
                    field,
                    format!("duplicate ACME domain '{domain}' (names are case-insensitive)"),
                ));
            }
        }
        Ok(())
    }
}

/// Privacy and anonymization configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
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
