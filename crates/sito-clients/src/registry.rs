//! Client identification registry and effective policy resolution.
//!
//! Evaluates the identification chain:
//! 1. Shared-secret ClientID from DoH path or DoT/DoQ SNI subdomain
//! 2. Static IP / CIDR (longest-prefix match)
//! 3. Local MAC address
//! 4. RouterOS DHCP lease table (hostname/comment matching is opt-in)
//! 5. Fallback to "default" / unknown client
//!
//! Steps 1 and 4 never trust values a client can choose for itself unless the
//! operator has explicitly enabled them: display `name`s, DoH path segments
//! and DHCP hostnames are not credentials.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use sito_core::client::{ClientContext, ClientId};

use crate::config::{ClientEntryConfig, ClientsConfig};
use crate::mac::{MacResolver, normalize_mac_id};
use crate::policy::EffectivePolicy;
use crate::safe_search::YouTubeSafeSearchMode;

/// Information on a discovered client not explicitly configured in `clients.entries`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnidentifiedClient {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub comment: Option<String>,
}

/// RouterOS DHCP lease entry for matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterOsLease {
    pub mac: String,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub comment: Option<String>,
}

/// Precomputed lookup tables for the static parts of the identification chain.
///
/// Built once per registry snapshot so per-query identification does not parse
/// every configured `id` on each request.
#[derive(Debug, Default)]
struct ClientIndex {
    /// Exact IP address -> entry position.
    exact_ips: HashMap<IpAddr, usize>,
    /// CIDR blocks -> entry position, in configuration order.
    subnets: Vec<(IpAddr, u8, usize)>,
    /// Normalized MAC -> entry position (explicit MAC format only).
    macs: HashMap<String, usize>,
    /// Shared client-id secret -> entry position.
    secrets: HashMap<String, usize>,
}

/// Registry managing clients, groups, and identification resolution.
#[derive(Clone)]
pub struct ClientRegistry {
    config: ClientsConfig,
    index: Arc<ClientIndex>,
    mac_resolver: MacResolver,
    routeros_leases: Arc<RwLock<Vec<RouterOsLease>>>,
    unidentified_clients: Arc<RwLock<HashMap<IpAddr, UnidentifiedClient>>>,
}

impl ClientRegistry {
    /// Create a new client registry from configuration.
    pub fn new(config: ClientsConfig) -> Self {
        Self::with_routeros_leases(config, Arc::new(RwLock::new(Vec::new())))
    }

    /// Creates a registry that shares an existing RouterOS lease store.
    ///
    /// Hot reloads replace the whole registry; carrying the store over keeps
    /// the running lease-sync task visible to every registry generation.
    #[must_use]
    pub fn with_routeros_leases(
        config: ClientsConfig,
        routeros_leases: Arc<RwLock<Vec<RouterOsLease>>>,
    ) -> Self {
        let index = Arc::new(build_client_index(&config));
        Self {
            config,
            index,
            mac_resolver: MacResolver::new(),
            routeros_leases,
            unidentified_clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the shared RouterOS lease store of this registry.
    ///
    /// Pass the result to [`ClientRegistry::with_routeros_leases`] when
    /// replacing the registry so leases survive the reload.
    #[must_use]
    pub fn routeros_leases_store(&self) -> Arc<RwLock<Vec<RouterOsLease>>> {
        Arc::clone(&self.routeros_leases)
    }

    /// Access the internal MacResolver (e.g. to inject mock ARP entries in tests).
    pub fn mac_resolver(&self) -> &MacResolver {
        &self.mac_resolver
    }

    /// Update the RouterOS lease table.
    pub fn update_routeros_leases(&self, leases: Vec<RouterOsLease>) {
        *self.routeros_leases.write().unwrap() = leases;
    }

    /// Resolves an incoming query's ClientContext to an EffectivePolicy,
    /// and populates any missing fields (client_name, group, mac) in `ctx`.
    pub fn resolve(&self, ctx: &mut ClientContext, now: DateTime<Utc>) -> EffectivePolicy {
        // 1. Identify client entry
        if let Some(entry) = self.identify(ctx) {
            ctx.client_name = Some(entry.name.clone());
            ctx.group = Some(entry.group.clone());
            if ctx.id.is_none() {
                ctx.id = Some(ClientId::new(&entry.name));
            }

            return self.build_effective_policy(Some(entry), now);
        }

        // 2. Unknown client fallback
        self.build_effective_policy(None, now)
    }

    fn identify(&self, ctx: &mut ClientContext) -> Option<&ClientEntryConfig> {
        // 1. Shared-secret ClientID from DoH path or DoT/DoQ SNI subdomain.
        //    Only secrets configured in `clients.client_id_secrets` count;
        //    display names and arbitrary SNI labels never identify a client.
        if let Some(matched) = self.match_by_client_id_or_sni(ctx) {
            return Some(matched);
        }

        // 2. Static IP / CIDR matching (most specific prefix wins)
        if let Some(matched) = self.match_by_ip_or_cidr(ctx.ip) {
            return Some(matched);
        }

        // 3. Local MAC matching
        if let Some(mac) = self.mac_resolver.resolve_mac(ctx.ip) {
            ctx.mac = Some(mac.clone());
            if let Some(matched) = self.match_by_mac(&mac) {
                return Some(matched);
            }
        }

        // 4. RouterOS lease table match
        if let Some(matched) = self.match_by_routeros(ctx) {
            return Some(matched);
        }

        None
    }

    fn entry_for_secret(&self, secret: &str) -> Option<&ClientEntryConfig> {
        self.index
            .secrets
            .get(secret)
            .and_then(|&idx| self.config.entries.get(idx))
    }

    fn match_by_client_id_or_sni(&self, ctx: &ClientContext) -> Option<&ClientEntryConfig> {
        if self.index.secrets.is_empty() {
            // Path/SNI identity is disabled (safe default).
            return None;
        }

        // Direct shared-secret ClientID (DoH path, or full SNI set by DoQ).
        if let Some(ref cid) = ctx.id
            && let Some(entry) = self.entry_for_secret(cid.as_str())
        {
            return Some(entry);
        }

        // SNI match: {secret}.dns.domain or {secret}.sub.domain. The candidate
        // must be the configured secret itself.
        if let Some(ref sni) = ctx.sni {
            let sni_lower = sni.to_ascii_lowercase();
            if let Some(candidate) = extract_id_from_sni(&sni_lower)
                && let Some(entry) = self.entry_for_secret(candidate)
            {
                return Some(entry);
            }
        }

        None
    }

    fn match_by_ip_or_cidr(&self, client_ip: IpAddr) -> Option<&ClientEntryConfig> {
        // An exact host address is the most specific match possible.
        if let Some(&idx) = self.index.exact_ips.get(&client_ip) {
            return self.config.entries.get(idx);
        }

        // Otherwise use the longest matching prefix; ties keep the first
        // configured entry so behavior is deterministic.
        let mut best: Option<(u8, usize)> = None;
        for &(network, prefix, idx) in &self.index.subnets {
            if !ip_in_subnet(network, prefix, client_ip) {
                continue;
            }
            match best {
                Some((best_prefix, _)) if best_prefix >= prefix => {}
                _ => best = Some((prefix, idx)),
            }
        }
        best.and_then(|(_, idx)| self.config.entries.get(idx))
    }

    fn match_by_mac(&self, mac: &str) -> Option<&ClientEntryConfig> {
        let normalized = mac.to_ascii_lowercase();
        self.index
            .macs
            .get(&normalized)
            .and_then(|&idx| self.config.entries.get(idx))
    }

    fn match_by_routeros(&self, ctx: &mut ClientContext) -> Option<&ClientEntryConfig> {
        // DHCP hostnames/comments are client-controlled. They only participate
        // in identification when the operator explicitly opts in; MAC/IP lease
        // matching stays active either way.
        let trust_names = self.config.trust_routeros_lease_names;
        let leases = self.routeros_leases.read().unwrap();

        for lease in leases.iter() {
            let matches_ip = lease.ip == Some(ctx.ip);
            let matches_mac = ctx
                .mac
                .as_ref()
                .is_some_and(|m| m.eq_ignore_ascii_case(&lease.mac));

            if matches_ip || matches_mac {
                if ctx.mac.is_none() {
                    ctx.mac = Some(lease.mac.clone());
                }

                // Check if this lease matches any client entry
                for entry in &self.config.entries {
                    if trust_names
                        && let Some(ref h) = lease.hostname
                        && entry.name.eq_ignore_ascii_case(h)
                    {
                        return Some(entry);
                    }
                    for id in &entry.ids {
                        if normalize_mac_id(id).is_some_and(|m| m.eq_ignore_ascii_case(&lease.mac))
                        {
                            return Some(entry);
                        }
                        if !trust_names {
                            continue;
                        }
                        if let Some(ref h) = lease.hostname
                            && id.eq_ignore_ascii_case(h)
                        {
                            return Some(entry);
                        }
                        if let Some(ref c) = lease.comment
                            && id.eq_ignore_ascii_case(c)
                        {
                            return Some(entry);
                        }
                    }
                }

                // Detected but undefined client
                let mut unidentified = self.unidentified_clients.write().unwrap();
                unidentified.insert(
                    ctx.ip,
                    UnidentifiedClient {
                        ip: ctx.ip,
                        mac: Some(lease.mac.clone()),
                        hostname: lease.hostname.clone(),
                        comment: lease.comment.clone(),
                    },
                );

                if trust_names && ctx.client_name.is_none() {
                    ctx.client_name.clone_from(&lease.hostname);
                }
            }
        }

        None
    }

    fn build_effective_policy(
        &self,
        entry: Option<&ClientEntryConfig>,
        now: DateTime<Utc>,
    ) -> EffectivePolicy {
        let group_name = entry.map_or("default", |e| e.group.as_str());
        let group = self.config.groups.get(group_name);

        let mut policy = EffectivePolicy {
            group_name: group_name.to_string(),
            ..Default::default()
        };

        if let Some(e) = entry {
            policy.client_name = Some(e.name.clone());
            policy.ids.clone_from(&e.ids);
            policy.ignore_query_log = e.ignore_query_log;
            policy.ignore_stats = e.ignore_stats;
            policy.use_global_upstreams = e.use_global_upstreams;
            policy.upstreams.clone_from(&e.upstreams);
            policy.trusted = e.trusted;
        }

        if let Some(grp) = group {
            policy.lists.clone_from(&grp.lists);
            policy.custom_rules.clone_from(&grp.custom_rules);
            let group_active = if grp.schedule_enabled {
                if let Some(ref sched) = grp.schedule {
                    sched.is_active(&now)
                } else {
                    true
                }
            } else {
                true
            };

            let filtering_on = grp.filtering && group_active;
            policy.is_filtering_enabled = filtering_on;
            policy.safe_search = filtering_on && grp.safe_search;
            policy.safe_search_youtube = grp
                .safe_search_youtube
                .unwrap_or(YouTubeSafeSearchMode::Strict);
            policy.parental = filtering_on && grp.parental;
            policy.parental_categories = grp.parental_categories.iter().cloned().collect();

            // Evaluate blocked services
            if filtering_on {
                for svc_cfg in &grp.blocked_services {
                    let is_active = if let Some(ref sched) = svc_cfg.schedule {
                        sched.is_active(&now)
                    } else {
                        true
                    };

                    if is_active {
                        policy
                            .active_blocked_services
                            .insert(svc_cfg.service.to_ascii_lowercase());
                    }
                }
            }
        }

        policy
    }
}

/// Extract {id} from {id}.dns.domain.
pub fn extract_id_from_sni(sni: &str) -> Option<&str> {
    let parts: Vec<&str> = sni.split('.').collect();
    if parts.len() >= 3 && parts[1] == "dns" {
        return Some(parts[0]);
    }
    if parts.len() >= 2 {
        return Some(parts[0]);
    }
    None
}

/// Extract and sanitize ClientID from URL path (e.g. `/dns-query/{client_id}`).
pub fn extract_id_from_url_path(path: &str) -> Option<&str> {
    let clean = path.trim_matches('/');
    let segment = if let Some(stripped) = clean.strip_prefix("dns-query/") {
        stripped
    } else {
        clean
    };
    if segment.is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains("..")
    {
        return None;
    }
    Some(segment)
}

/// Builds the static identification index for a client configuration.
fn build_client_index(config: &ClientsConfig) -> ClientIndex {
    let mut index = ClientIndex::default();

    for (entry_idx, entry) in config.entries.iter().enumerate() {
        for id in &entry.ids {
            if let Ok(ip) = id.trim().parse::<IpAddr>() {
                index.exact_ips.entry(ip).or_insert(entry_idx);
            } else if let Some((network, prefix)) = parse_cidr(id) {
                index.subnets.push((network, prefix, entry_idx));
            }
            if let Some(mac) = normalize_mac_id(id) {
                index.macs.entry(mac).or_insert(entry_idx);
            }
        }

        // Iterate entries (not the hash map) so duplicate secrets resolve
        // deterministically to the first configured entry.
        if let Some(secret) = config.client_id_secrets.get(&entry.name)
            && !secret.is_empty()
        {
            if let Some(&existing) = index.secrets.get(secret) {
                tracing::warn!(
                    entry = %entry.name,
                    other = %config.entries[existing].name,
                    "Duplicate clients.client_id_secrets value; the first entry wins"
                );
            } else {
                index.secrets.insert(secret.clone(), entry_idx);
            }
        }
    }

    for name in config.client_id_secrets.keys() {
        if !config.entries.iter().any(|entry| &entry.name == name) {
            tracing::warn!(
                entry = %name,
                "clients.client_id_secrets references an unknown client entry; \
                 the secret is ignored"
            );
        }
    }

    index
}

/// Parses `address/prefix` CIDR notation into an IP address and prefix length.
fn parse_cidr(cidr_str: &str) -> Option<(IpAddr, u8)> {
    let (ip_str, prefix_str) = cidr_str.split_once('/')?;
    let net_ip = ip_str.trim().parse::<IpAddr>().ok()?;
    let prefix = prefix_str.trim().parse::<u8>().ok()?;
    let max_prefix = match net_ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return None;
    }
    Some((net_ip, prefix))
}

/// Checks if `target_ip` is contained within `network/prefix`.
fn ip_in_subnet(network: IpAddr, prefix: u8, target_ip: IpAddr) -> bool {
    match (network, target_ip) {
        (IpAddr::V4(net), IpAddr::V4(tgt)) => {
            if prefix == 0 {
                return true;
            }
            let mask = if prefix >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(net) & mask) == (u32::from(tgt) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(tgt)) => {
            if prefix == 0 {
                return true;
            }
            let mask = if prefix >= 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(net) & mask) == (u128::from(tgt) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample_config() -> ClientsConfig {
        let toml_str = r#"
[[entries]]
name = "Jane's Phone"
ids = ["192.168.1.20", "janes-phone", "AA:BB:CC:DD:EE:FF"]
group = "kids"
ignore_query_log = true

[[entries]]
name = "Office Subnet"
ids = ["10.0.0.0/24"]
group = "office"

[[entries]]
name = "Admin Laptop"
ids = ["admin-laptop"]
group = "admin"
trusted = true

[client_id_secrets]
"Jane's Phone" = "jane-secret-a1"
"Admin Laptop" = "admin-secret-b2"

[groups.kids]
lists = ["OISD"]
safe_search = true
parental = true
[[groups.kids.blocked_services]]
service = "tiktok"

[groups.default]
lists = ["GlobalList"]
"#;
        toml::from_str(toml_str).unwrap()
    }

    #[test]
    fn test_id_by_doh_path() {
        let reg = ClientRegistry::new(sample_config());
        let ip = IpAddr::from_str("172.16.0.5").unwrap();
        let mut ctx = ClientContext::with_id(ip, "jane-secret-a1");

        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.client_name.as_deref(), Some("Jane's Phone"));
        assert_eq!(policy.group_name, "kids");
        assert!(policy.ignore_query_log);
        assert!(policy.safe_search);
        assert!(policy.active_blocked_services.contains("tiktok"));
        assert_eq!(ctx.client_name.as_deref(), Some("Jane's Phone"));
        assert_eq!(ctx.group.as_deref(), Some("kids"));
    }

    #[test]
    fn test_id_by_dot_sni() {
        let reg = ClientRegistry::new(sample_config());
        let ip = IpAddr::from_str("172.16.0.6").unwrap();
        let mut ctx = ClientContext::with_sni(ip, "jane-secret-a1.dns.home.arpa");

        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.client_name.as_deref(), Some("Jane's Phone"));
        assert_eq!(policy.group_name, "kids");
    }

    #[test]
    fn test_display_name_and_ids_do_not_grant_identity_by_path() {
        let reg = ClientRegistry::new(sample_config());
        let ip = IpAddr::from_str("8.8.8.8").unwrap();

        // The entry's display name must never authenticate the client.
        let mut ctx = ClientContext::with_id(ip, "Admin Laptop");
        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.group_name, "default");
        assert!(!policy.trusted);

        // Neither may a guessable value from `ids` (hostname, IP or MAC).
        let mut ctx = ClientContext::with_id(ip, "admin-laptop");
        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.group_name, "default");
        assert!(!policy.trusted);

        // A configured shared secret does authenticate.
        let mut ctx = ClientContext::with_id(ip, "admin-secret-b2");
        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.client_name.as_deref(), Some("Admin Laptop"));
        assert_eq!(policy.group_name, "admin");
        assert!(policy.trusted);
    }

    #[test]
    fn test_guessable_sni_label_does_not_grant_identity() {
        let reg = ClientRegistry::new(sample_config());
        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        let mut ctx = ClientContext::with_sni(ip, "admin.dns.home.arpa");

        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.group_name, "default");
        assert!(!policy.trusted);
    }

    #[test]
    fn test_id_by_static_ip() {
        let reg = ClientRegistry::new(sample_config());
        let ip = IpAddr::from_str("192.168.1.20").unwrap();
        let mut ctx = ClientContext::new(ip);

        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.client_name.as_deref(), Some("Jane's Phone"));
        assert_eq!(policy.group_name, "kids");
    }

    #[test]
    fn test_id_by_cidr() {
        let reg = ClientRegistry::new(sample_config());
        let ip = IpAddr::from_str("10.0.0.55").unwrap();
        let mut ctx = ClientContext::new(ip);

        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.client_name.as_deref(), Some("Office Subnet"));
        assert_eq!(policy.group_name, "office");
    }

    #[test]
    fn test_cidr_longest_prefix_wins() {
        let toml_str = r#"
[[entries]]
name = "Wide"
ids = ["10.0.0.0/8"]
group = "wide"

[[entries]]
name = "Narrow"
ids = ["10.1.2.0/24"]
group = "narrow"

[groups.wide]
[groups.narrow]
"#;
        let cfg: ClientsConfig = toml::from_str(toml_str).unwrap();
        let reg = ClientRegistry::new(cfg);

        // Both subnets match; the /24 must win over the /8 regardless of
        // configuration order.
        let mut ctx = ClientContext::new(IpAddr::from_str("10.1.2.3").unwrap());
        assert_eq!(reg.resolve(&mut ctx, Utc::now()).group_name, "narrow");

        let mut ctx = ClientContext::new(IpAddr::from_str("10.9.9.9").unwrap());
        assert_eq!(reg.resolve(&mut ctx, Utc::now()).group_name, "wide");

        // An exact host address beats every CIDR block.
        let mut ctx = ClientContext::new(IpAddr::from_str("10.1.2.3").unwrap());
        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.group_name, "narrow");
    }

    #[test]
    fn test_id_by_mac() {
        let reg = ClientRegistry::new(sample_config());
        let ip = IpAddr::from_str("192.168.1.99").unwrap();
        let mut arp = HashMap::new();
        arp.insert(ip, "aa:bb:cc:dd:ee:ff".to_string());
        reg.mac_resolver().set_mock_arp(arp);

        let mut ctx = ClientContext::new(ip);
        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.client_name.as_deref(), Some("Jane's Phone"));
        assert_eq!(policy.group_name, "kids");
        assert_eq!(ctx.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_bare_hex_id_is_not_treated_as_mac() {
        let toml_str = r#"
[[entries]]
name = "Hex Named"
ids = ["deadbeefcafe"]
group = "hex"

[groups.hex]
"#;
        let cfg: ClientsConfig = toml::from_str(toml_str).unwrap();
        let reg = ClientRegistry::new(cfg);
        let ip = IpAddr::from_str("192.168.1.77").unwrap();
        let mut arp = HashMap::new();
        arp.insert(ip, "de:ad:be:ef:ca:fe".to_string());
        reg.mac_resolver().set_mock_arp(arp);

        let mut ctx = ClientContext::new(ip);
        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(
            policy.group_name, "default",
            "a 12-hex-char id is a name, not a MAC address"
        );
        assert_eq!(policy.client_name, None);

        // The explicit form is still accepted.
        let mut mac_cfg: ClientsConfig = toml::from_str(
            r#"
[[entries]]
name = "Mac Named"
ids = ["mac:deadbeefcafe"]
group = "hex"
[groups.hex]
"#,
        )
        .unwrap();
        mac_cfg.entries[0].ids = vec!["mac:deadbeefcafe".to_string()];
        let reg = ClientRegistry::new(mac_cfg);
        let ip = IpAddr::from_str("192.168.1.78").unwrap();
        let mut arp = HashMap::new();
        arp.insert(ip, "de:ad:be:ef:ca:fe".to_string());
        reg.mac_resolver().set_mock_arp(arp);
        let mut ctx = ClientContext::new(ip);
        assert_eq!(reg.resolve(&mut ctx, Utc::now()).group_name, "hex");
    }

    #[test]
    fn test_routeros_lease_name_not_trusted_by_default() {
        let reg = ClientRegistry::new(sample_config());
        let ip = IpAddr::from_str("192.168.1.150").unwrap();

        let lease = RouterOsLease {
            mac: "11:22:33:44:55:66".to_string(),
            ip: Some(ip),
            hostname: Some("admin-laptop".to_string()),
            comment: Some("Director laptop".to_string()),
        };
        reg.update_routeros_leases(vec![lease]);

        // A client-controlled DHCP hostname must not grant the entry's
        // group/trusted policy unless explicitly enabled.
        let mut ctx = ClientContext::new(ip);
        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.group_name, "default");
        assert!(!policy.trusted);
        assert_eq!(policy.client_name, None);
        // The MAC learned from the lease is still exposed.
        assert_eq!(ctx.mac.as_deref(), Some("11:22:33:44:55:66"));
    }

    #[test]
    fn test_routeros_lease_name_trusted_when_enabled() {
        let mut cfg = sample_config();
        cfg.trust_routeros_lease_names = true;
        let reg = ClientRegistry::new(cfg);
        let ip = IpAddr::from_str("192.168.1.150").unwrap();

        let lease = RouterOsLease {
            mac: "11:22:33:44:55:66".to_string(),
            ip: Some(ip),
            hostname: Some("admin-laptop".to_string()),
            comment: Some("Director laptop".to_string()),
        };
        reg.update_routeros_leases(vec![lease]);

        let mut ctx = ClientContext::new(ip);
        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.client_name.as_deref(), Some("Admin Laptop"));
        assert_eq!(policy.group_name, "admin");
        assert!(policy.trusted);
        assert_eq!(ctx.client_name.as_deref(), Some("Admin Laptop"));
    }

    #[test]
    fn test_routeros_mac_match_still_works_without_name_trust() {
        let toml_str = r#"
[[entries]]
name = "Known Mac"
ids = ["11:22:33:44:55:66"]
group = "known"

[groups.known]
"#;
        let cfg: ClientsConfig = toml::from_str(toml_str).unwrap();
        let reg = ClientRegistry::new(cfg);
        let ip = IpAddr::from_str("192.168.1.151").unwrap();
        reg.update_routeros_leases(vec![RouterOsLease {
            mac: "11:22:33:44:55:66".to_string(),
            ip: Some(ip),
            hostname: Some("attacker-chosen".to_string()),
            comment: None,
        }]);

        let mut ctx = ClientContext::new(ip);
        assert_eq!(reg.resolve(&mut ctx, Utc::now()).group_name, "known");
    }

    #[test]
    fn test_client_id_secret_beats_ip() {
        let reg = ClientRegistry::new(sample_config());
        // IP matches Jane's Phone, but the shared secret matches Admin Laptop.
        let ip = IpAddr::from_str("192.168.1.20").unwrap();
        let mut ctx = ClientContext::with_id(ip, "admin-secret-b2");

        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.client_name.as_deref(), Some("Admin Laptop"));
        assert_eq!(policy.group_name, "admin");
        assert!(policy.trusted);
    }

    #[test]
    fn test_unknown_secret_references_are_ignored() {
        let mut cfg = sample_config();
        cfg.client_id_secrets
            .insert("Nobody".to_string(), "orphan-secret".to_string());
        let reg = ClientRegistry::new(cfg);
        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        let mut ctx = ClientContext::with_id(ip, "orphan-secret");

        // The orphan secret is not attached to any entry.
        assert_eq!(reg.resolve(&mut ctx, Utc::now()).group_name, "default");
    }

    #[test]
    fn test_routeros_lease_store_is_shared_across_registry_generations() {
        let old = ClientRegistry::new(sample_config());
        let new =
            ClientRegistry::with_routeros_leases(sample_config(), old.routeros_leases_store());

        old.update_routeros_leases(vec![RouterOsLease {
            mac: "AA:BB:CC:DD:EE:01".to_string(),
            ip: None,
            hostname: Some("leased-host".to_string()),
            comment: None,
        }]);

        // A lease written through the pre-reload registry is visible to the
        // replacement registry (the sync task keeps using the old handle).
        let leases = new.routeros_leases_store();
        let leases = leases.read().unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].hostname.as_deref(), Some("leased-host"));
    }

    #[test]
    fn test_fallback_to_default_unknown_client() {
        let reg = ClientRegistry::new(sample_config());
        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        let mut ctx = ClientContext::new(ip);

        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.client_name, None);
        assert_eq!(policy.group_name, "default");
        assert_eq!(policy.lists, vec!["GlobalList"]);
    }
}
