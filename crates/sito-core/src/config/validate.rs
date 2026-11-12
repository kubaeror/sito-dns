//! Cross-section validation and effective-value compatibility rules.

#[allow(clippy::wildcard_imports)]
use super::*;

impl Config {
    /// Parse configuration from a TOML string.
    ///
    /// This is the single configuration entry point: it rejects unknown keys
    /// and non-v2 documents, then runs [`Config::validate_full`].
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let table: toml::Table =
            toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))?;

        // Check the version before the schema walk so a v1 document gets the
        // actionable migration message rather than a list of v1/v2
        // differences. `config_version` was optional in 1.9, so an unversioned
        // file is a v1 document and must be migrated; only `Config::default()`
        // (new installs) starts at v2.
        let version = match table.get("config_version") {
            Some(value) => {
                u32::try_from(value.as_integer().unwrap_or(i64::MAX)).unwrap_or(u32::MAX)
            }
            None => CONFIG_VERSION_V1,
        };
        if version != CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                found: version,
                supported: CONFIG_VERSION,
            });
        }

        // D5: reject unknown keys/tables before serde sees them, so the error
        // names the exact dotted path and a typo cannot silently fall back to
        // a default.
        config_schema::schema().validate_v2_document(&table)?;

        let config: Self = toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate_full()?;
        Ok(config)
    }

    /// The single full configuration validator (WP-1.3).
    ///
    /// Startup, `check-config`, API writes, restore and HA apply all reach
    /// this method. [`Config::validate`] is a compatibility alias and runs the
    /// same rules.
    pub fn validate_full(&self) -> Result<(), ConfigError> {
        if self.config_version != CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                found: self.config_version,
                supported: CONFIG_VERSION,
            });
        }

        self.server.validate()?;
        if self.server.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::cross_section(
                "server.data_dir",
                "data_dir cannot be empty: persistent state (stats.db, users.toml, TLS and HA state) needs a directory",
            ));
        }
        self.dns.validate()?;
        self.upstream.validate()?;
        self.validate_upstream_targets()?;
        self.filtering.validate()?;
        self.privacy.validate()?;
        if let Some(ref tls) = self.tls {
            tls.validate()?;
        }
        if let Some(ref acme) = self.acme {
            acme.validate()?;
        }
        // Legacy `[web] acme_*` aliases resolve through the same typed config
        // and get the same validation for one 2.0 alpha.
        if let Some(acme) = self.get_acme_config() {
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

        self.validate_legacy_sections()?;
        self.validate_listener_conflicts()
    }

    /// Compatibility alias for [`Config::validate_full`].
    ///
    /// Kept so existing callers keep compiling; it does **not** apply a
    /// different rule set.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_full()
    }

    /// Validates every upstream target in every scope (global and per-domain).
    fn validate_upstream_targets(&self) -> Result<(), ConfigError> {
        for (index, server) in self.upstream.servers.iter().enumerate() {
            validate_upstream_target(server).map_err(|reason| {
                ConfigError::cross_section(
                    format!("upstream.servers[{index}]"),
                    format!("invalid upstream target '{server}': {reason}"),
                )
            })?;
        }
        for (rule_index, rule) in self.upstream.per_domain.iter().enumerate() {
            for (server_index, server) in rule.servers.iter().enumerate() {
                validate_upstream_target(server).map_err(|reason| {
                    ConfigError::cross_section(
                        format!("upstream.per_domain[{rule_index}].servers[{server_index}]"),
                        format!("invalid per-domain upstream target '{server}': {reason}"),
                    )
                })?;
            }
        }
        Ok(())
    }

    /// Rejects unknown/removed keys in the raw legacy sections and validates
    /// the parts of their schemas that live in dependent crates.
    fn validate_legacy_sections(&self) -> Result<(), ConfigError> {
        let mut table = toml::Table::new();
        for (name, section) in [
            ("clients", &self.clients),
            ("rewrites", &self.rewrites),
            ("web", &self.web),
            ("auth", &self.auth),
            ("stats", &self.stats),
            ("ha", &self.ha),
            ("integrations", &self.integrations),
        ] {
            if let Some(value) = section {
                table.insert(name.to_string(), value.clone());
            }
        }
        // `web`, `auth` and `stats` are also deserialized into typed structs,
        // which reject unknown fields; the map walk gives all sections the
        // same precise error and catches the legacy raw tables.
        config_schema::schema().validate_v2_document(&table)?;

        self.validate_clients_section()?;
        self.validate_integrations_section()
    }

    fn validate_clients_section(&self) -> Result<(), ConfigError> {
        let Some(value) = self.clients.as_ref() else {
            return Ok(());
        };
        let table = value
            .as_table()
            .ok_or_else(|| ConfigError::validation("clients", "[clients] must be a table"))?;
        let Some(entries) = table.get("entries") else {
            return Ok(());
        };
        let entries = entries.as_array().ok_or_else(|| {
            ConfigError::validation(
                "clients.entries",
                "invalid [clients] configuration: entries must be an array",
            )
        })?;

        let mut names = std::collections::HashSet::new();
        for (index, entry) in entries.iter().enumerate() {
            let entry = entry.as_table().ok_or_else(|| {
                ConfigError::validation(
                    format!("clients.entries[{index}]"),
                    "each clients.entries item must be a table",
                )
            })?;
            let name = entry
                .get("name")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| {
                    ConfigError::validation(
                        format!("clients.entries[{index}].name"),
                        "client entry name is required and must be a string",
                    )
                })?;
            if name.trim().is_empty() {
                return Err(ConfigError::validation(
                    format!("clients.entries[{index}].name"),
                    "client entry name cannot be empty",
                ));
            }
            if !names.insert(name.to_string()) {
                return Err(ConfigError::validation(
                    format!("clients.entries[{index}].name"),
                    format!("duplicate client entry name '{name}'"),
                ));
            }
            if let Some(ids) = entry.get("ids") {
                let ids = ids.as_array().ok_or_else(|| {
                    ConfigError::validation(
                        format!("clients.entries[{index}].ids"),
                        "clients.entries[].ids must be an array of strings",
                    )
                })?;
                for (id_index, id) in ids.iter().enumerate() {
                    let id = id.as_str().ok_or_else(|| {
                        ConfigError::validation(
                            format!("clients.entries[{index}].ids[{id_index}]"),
                            "client ids must be strings",
                        )
                    })?;
                    // An IP-prefixed CIDR id must parse; the registry would
                    // otherwise silently ignore a typo and the client would
                    // fall back to the default policy. DoH path labels such
                    // as `/dns-query/foo` are not CIDRs.
                    let cidr_like = id.split_once('/').is_some_and(|(address, prefix)| {
                        address.parse::<IpAddr>().is_ok() && !prefix.is_empty()
                    });
                    if cidr_like {
                        crate::net::IpNetwork::parse(id).map_err(|e| {
                            ConfigError::cross_section(
                                format!("clients.entries[{index}].ids[{id_index}]"),
                                format!("invalid client CIDR id '{id}': {e}"),
                            )
                        })?;
                    }
                }
            }
            if let Some(upstreams) = entry.get("upstreams") {
                let upstreams = upstreams.as_array().ok_or_else(|| {
                    ConfigError::validation(
                        format!("clients.entries[{index}].upstreams"),
                        "clients.entries[].upstreams must be an array of strings",
                    )
                })?;
                for (upstream_index, upstream) in upstreams.iter().enumerate() {
                    let upstream = upstream.as_str().ok_or_else(|| {
                        ConfigError::validation(
                            format!("clients.entries[{index}].upstreams[{upstream_index}]"),
                            "client upstream targets must be strings",
                        )
                    })?;
                    validate_upstream_target(upstream).map_err(|reason| {
                        ConfigError::cross_section(
                            format!("clients.entries[{index}].upstreams[{upstream_index}]"),
                            format!("invalid per-client upstream target '{upstream}': {reason}"),
                        )
                    })?;
                }
            }
        }
        Ok(())
    }

    fn validate_integrations_section(&self) -> Result<(), ConfigError> {
        let Some(value) = self.integrations.as_ref() else {
            return Ok(());
        };
        let table = value.as_table().ok_or_else(|| {
            ConfigError::validation("integrations", "[integrations] must be a table")
        })?;

        if let Some(lists) = table.get("lists") {
            let lists = lists.as_table().ok_or_else(|| {
                ConfigError::validation(
                    "integrations.lists",
                    "[integrations.lists] must be a table",
                )
            })?;
            if let Some(default_refresh) = lists.get("refresh_hours") {
                let refresh = default_refresh.as_integer().ok_or_else(|| {
                    ConfigError::validation(
                        "integrations.lists.refresh_hours",
                        "refresh_hours must be an integer",
                    )
                })?;
                if refresh <= 0 {
                    return Err(ConfigError::cross_section(
                        "integrations.lists.refresh_hours",
                        "refresh_hours must be greater than 0",
                    ));
                }
            }
            if let Some(categories) = lists.get("categories") {
                let categories = categories.as_table().ok_or_else(|| {
                    ConfigError::validation(
                        "integrations.lists.categories",
                        "categories must be a table",
                    )
                })?;
                for (category, source) in categories {
                    let source = source.as_table().ok_or_else(|| {
                        ConfigError::validation(
                            format!("integrations.lists.categories.{category}"),
                            "each category source must be a table",
                        )
                    })?;
                    let url = source
                        .get("url")
                        .and_then(toml::Value::as_str)
                        .ok_or_else(|| {
                            ConfigError::validation(
                                format!("integrations.lists.categories.{category}.url"),
                                "category source url is required",
                            )
                        })?;
                    let allowed = ["https://", "http://", "file://"]
                        .iter()
                        .any(|scheme| url.starts_with(scheme));
                    if !allowed {
                        return Err(ConfigError::cross_section(
                            format!("integrations.lists.categories.{category}.url"),
                            "url must use http://, https:// or file://",
                        ));
                    }
                    if let Some(refresh) = source.get("refresh_hours") {
                        let refresh = refresh.as_integer().ok_or_else(|| {
                            ConfigError::validation(
                                format!("integrations.lists.categories.{category}.refresh_hours"),
                                "refresh_hours must be an integer",
                            )
                        })?;
                        if refresh <= 0 {
                            return Err(ConfigError::cross_section(
                                format!("integrations.lists.categories.{category}.refresh_hours"),
                                "refresh_hours must be greater than 0",
                            ));
                        }
                    }
                }
            }
        }

        if let Some(mikrotik) = table.get("mikrotik") {
            let mikrotik = mikrotik.as_table().ok_or_else(|| {
                ConfigError::validation(
                    "integrations.mikrotik",
                    "[integrations.mikrotik] must be a table",
                )
            })?;
            let enabled = mikrotik
                .get("enabled")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false);
            if enabled {
                // A missing url uses the typed default (https://192.168.1.1);
                // only an explicitly configured invalid scheme fails closed.
                if let Some(url) = mikrotik.get("url").and_then(toml::Value::as_str) {
                    let allowed = url.starts_with("https://") || url.starts_with("http://");
                    if !allowed {
                        return Err(ConfigError::cross_section(
                            "integrations.mikrotik.url",
                            "url must use http:// or https://",
                        ));
                    }
                }
                if let Some(interval) = mikrotik.get("interval_s") {
                    let interval = interval.as_integer().ok_or_else(|| {
                        ConfigError::validation(
                            "integrations.mikrotik.interval_s",
                            "interval_s must be an integer",
                        )
                    })?;
                    if interval <= 0 {
                        return Err(ConfigError::cross_section(
                            "integrations.mikrotik.interval_s",
                            "interval_s must be greater than 0",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Rejects two listeners that would contend for the same address:port.
    fn validate_listener_conflicts(&self) -> Result<(), ConfigError> {
        let web = self.get_web_config();
        if web.enabled {
            let web_conflict = |port: u16| port > 0 && port == web.port;
            let dns_tcp_ports = [
                ("dns.port", self.dns.port),
                ("dns.dot_port", self.dns.dot_port),
                ("dns.doh_port", self.dns.doh_port),
            ];
            for (field, port) in dns_tcp_ports {
                if web_conflict(port) && self.web_shares_dns_bind(&web.bind) {
                    return Err(ConfigError::cross_section(
                        "web.port",
                        format!(
                            "web.port {} conflicts with {field} {} on the same bind address; use distinct ports",
                            web.port, port
                        ),
                    ));
                }
            }
            if let Some(acme) = self.get_acme_config()
                && acme.enabled
                && acme.http_port > 0
                && acme.http_port == web.port
            {
                return Err(ConfigError::cross_section(
                    "web.port",
                    format!(
                        "web.port {} conflicts with acme.http_port {}; the ACME HTTP-01 listener and the admin UI cannot share a port",
                        web.port, acme.http_port
                    ),
                ));
            }
        }

        // The ACME HTTP-01 listener binds TCP independently of the admin UI.
        if let Some(acme) = self.get_acme_config()
            && acme.enabled
            && acme.http_port > 0
        {
            for (field, port) in [
                ("dns.port", self.dns.port),
                ("dns.dot_port", self.dns.dot_port),
                ("dns.doh_port", self.dns.doh_port),
            ] {
                if port > 0 && port == acme.http_port {
                    return Err(ConfigError::cross_section(
                        "acme.http_port",
                        format!(
                            "acme.http_port {} conflicts with {field} {port}; the ACME HTTP-01 listener and a DNS TCP listener cannot share a port on the same bind addresses",
                            acme.http_port
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Whether the admin bind can overlap any DNS listener bind. A wildcard
    /// bind (or the dual-stack `::` wildcard) covers the other addresses.
    fn web_shares_dns_bind(&self, web_bind: &IpAddr) -> bool {
        self.dns
            .bind
            .iter()
            .any(|dns_bind| listener_binds_overlap(*dns_bind, *web_bind))
    }

    /// Migrates a config v1 TOML document to validated config v2 (D4).
    ///
    /// `sito config migrate --from v1 --to v2 --backup` calls this. The
    /// migration is behavior-preserving unless `adopt_safe_defaults` is set;
    /// unknown keys are errors unless `ignore_unknown_keys` is set, in which
    /// case each dropped key is reported.
    pub fn migrate_v1_to_v2(
        source: &str,
        options: &crate::config_migrate::MigrationOptions,
    ) -> Result<crate::config_migrate::MigrationOutcome, ConfigError> {
        crate::config_migrate::migrate(source, *options)
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
                    allow_bootstrap_cert: false,
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

    /// Returns the admin-UI exposure warning, if the UI is reachable beyond
    /// loopback over plain HTTP without a declared TLS reverse proxy.
    ///
    /// The caller emits this while the web listener is starting, regardless of
    /// setup-pending state: the admin UI binds in both modes.
    #[must_use]
    pub fn web_exposure_warning(&self) -> Option<String> {
        // The admin UI is plain HTTP in-process. A declared TLS reverse proxy
        // is the operator's explicit acknowledgement that a proxy fronts it;
        // otherwise a non-loopback bind exposes credentials directly.
        let web = self.get_web_config();
        if !web.enabled || web.bind.is_loopback() || self.web_tls_declared() {
            return None;
        }
        Some(format!(
            "admin web UI is reachable at {} over plain HTTP; credentials, session cookies and the first-boot setup token cross the network in cleartext. Set web.bind = \"127.0.0.1\" and use an SSH tunnel or a TLS reverse proxy, or restrict TCP {} to trusted clients with a host firewall",
            SocketAddr::new(web.bind, web.port),
            web.port
        ))
    }

    /// Returns the DNS exposure warning, if listeners are about to bind a
    /// wildcard address without a client allow-list.
    ///
    /// Call this only when DNS listeners are actually starting: during
    /// setup-pending mode no DNS port is bound, so emitting it there would be
    /// false.
    #[must_use]
    pub fn dns_exposure_warning(&self) -> Option<String> {
        // sito has no DNS client allow-list: a wildcard bind accepts recursion
        // from every source. Rate limiting attenuates abuse, it does not
        // authorize clients.
        if !self.dns_listeners_exposed() {
            return None;
        }
        let binds = self
            .dns
            .bind
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        Some(format!(
            "DNS listeners bind to {binds} and accept queries from any source; sito has no DNS client allow-list and rate limiting is not an access control. Restrict the DNS ports to your LAN with a host firewall or set dns.bind to specific LAN addresses"
        ))
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

/// Whether two listener addresses can contend for the same `addr:port`.
///
/// Equal addresses overlap, a wildcard covers every address of its family,
/// and the IPv6 unspecified address is treated as dual-stack because a
/// default socket accepts IPv4-mapped connections on most platforms.
fn listener_binds_overlap(first: IpAddr, second: IpAddr) -> bool {
    if first == second {
        return true;
    }
    let first_wildcard = first.is_unspecified() && first.is_ipv4() == second.is_ipv4();
    let second_wildcard = second.is_unspecified() && second.is_ipv4() == first.is_ipv4();
    let dual_stack = |addr: IpAddr| matches!(addr, IpAddr::V6(v6) if v6.is_unspecified());
    first_wildcard
        || second_wildcard
        || (dual_stack(first) && second.is_ipv4())
        || (dual_stack(second) && first.is_ipv4())
}

/// Validates a single upstream target: `host`, `ip[:port]`, `[v6][:port]` or a
/// `udp://`/`tls://`/`https://`/`quic://` URL.
///
/// Lives in `sito-core` so startup, `check-config`, the API, restore and HA
/// all use the same validator (WP-1.3).
pub fn validate_upstream_target(target: &str) -> Result<(), String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("target is empty".to_string());
    }

    let mut rest = target;
    if let Some((scheme, after)) = target.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "udp" | "tls" | "https" | "quic") {
            return Err(format!(
                "unsupported scheme '{scheme}://' (supported: udp://, tls://, https://, quic://)"
            ));
        }
        if after.is_empty() {
            return Err("missing host".to_string());
        }
        rest = after;
    }

    // Drop a URL path for DoH-style targets.
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err("missing host".to_string());
    }

    let (host, port) = if let Some(after_bracket) = authority.strip_prefix('[') {
        let Some((host, tail)) = after_bracket.split_once(']') else {
            return Err("unterminated IPv6 literal".to_string());
        };
        let port = match tail.strip_prefix(':') {
            Some(port) => Some(port),
            None if tail.is_empty() => None,
            None => return Err("unexpected characters after IPv6 literal".to_string()),
        };
        (host.to_string(), port)
    } else if authority.matches(':').count() >= 2 && authority.parse::<std::net::Ipv6Addr>().is_ok()
    {
        (authority.to_string(), None)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            // More than one colon but not a valid bare IPv6 literal.
            return Err("invalid IPv6 literal (bracket it as [addr])".to_string());
        }
        (host.to_string(), Some(port))
    } else {
        (authority.to_string(), None)
    };

    if host.is_empty() {
        return Err("missing host".to_string());
    }
    if let Some(port) = port {
        let port: u16 = port.parse().map_err(|_| format!("invalid port '{port}'"))?;
        if port == 0 {
            return Err("port must not be 0".to_string());
        }
    }

    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    validate_hostname(&host)
}

/// Hostnames must be FQDN-like (at least one dot). A single-label name such as
/// `oops-typo` is rejected as a typo instead of being resolved through the
/// bootstrap resolver.
fn validate_hostname(host: &str) -> Result<(), String> {
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return Err("missing host".to_string());
    }
    if !host.contains('.') {
        return Err(format!(
            "'{host}' is not an IP address or fully-qualified hostname"
        ));
    }
    if host.len() > 253 {
        return Err("hostname is longer than 253 characters".to_string());
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err("hostname contains an empty label".to_string());
        }
        if label.len() > 63 {
            return Err("hostname label is longer than 63 characters".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("hostname label '{label}' starts or ends with '-'"));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!(
                "hostname label '{label}' contains invalid characters"
            ));
        }
    }
    Ok(())
}

/// Validates one `zone:algorithm:base64` trust-anchor entry. An operator typo
/// must fail configuration loading instead of silently producing a different
/// anchor set (the validator used to default the algorithm to ECDSA P-256).
pub(super) fn validate_trust_anchor(anchor: &str) -> Result<(), ConfigError> {
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
