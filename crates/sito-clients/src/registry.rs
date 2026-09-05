//! Client identification registry and effective policy resolution.
//!
//! Evaluates the 5-step identification chain:
//! 1. ClientID from DoH path or DoT SNI subdomain
//! 2. Static IP / CIDR
//! 3. Local MAC address
//! 4. RouterOS DHCP lease table
//! 5. Fallback to "default" / unknown client

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use sito_core::client::{ClientContext, ClientId};

use crate::config::{ClientEntryConfig, ClientsConfig};
use crate::mac::{MacResolver, normalize_mac};
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

/// Registry managing clients, groups, and identification resolution.
#[derive(Clone)]
pub struct ClientRegistry {
    config: ClientsConfig,
    mac_resolver: MacResolver,
    routeros_leases: Arc<RwLock<Vec<RouterOsLease>>>,
    unidentified_clients: Arc<RwLock<HashMap<IpAddr, UnidentifiedClient>>>,
}

impl ClientRegistry {
    /// Create a new client registry from configuration.
    pub fn new(config: ClientsConfig) -> Self {
        Self {
            config,
            mac_resolver: MacResolver::new(),
            routeros_leases: Arc::new(RwLock::new(Vec::new())),
            unidentified_clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Access the internal MacResolver (e.g. to inject mock ARP entries in tests).
    pub fn mac_resolver(&self) -> &MacResolver {
        &self.mac_resolver
    }

    /// Update the RouterOS lease table.
    pub fn update_routeros_leases(&self, leases: Vec<RouterOsLease>) {
        *self.routeros_leases.write().unwrap() = leases;
    }

    /// Get list of detected but undefined clients.
    pub fn get_unidentified_clients(&self) -> Vec<UnidentifiedClient> {
        self.unidentified_clients
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect()
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

            return self.build_effective_policy(Some(&entry), now);
        }

        // 2. Unknown client fallback
        self.build_effective_policy(None, now)
    }

    fn identify(&self, ctx: &mut ClientContext) -> Option<ClientEntryConfig> {
        // 1. ClientID from DoH path or DoT SNI subdomain
        if let Some(matched) = self.match_by_client_id_or_sni(ctx) {
            return Some(matched);
        }

        // 2. Static IP / CIDR matching
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

    fn match_by_client_id_or_sni(&self, ctx: &ClientContext) -> Option<ClientEntryConfig> {
        // Direct ClientID match
        if let Some(ref cid) = ctx.id {
            let id_str = cid.as_str();
            for entry in &self.config.entries {
                if entry.name.eq_ignore_ascii_case(id_str) {
                    return Some(entry.clone());
                }
                for id in &entry.ids {
                    if id.eq_ignore_ascii_case(id_str) {
                        return Some(entry.clone());
                    }
                }
            }
        }

        // SNI match: exact or subdomain {id}.dns.domain
        if let Some(ref sni) = ctx.sni {
            let sni_lower = sni.to_ascii_lowercase();

            // Extract candidate ID from {id}.dns.domain or {id}.sub.domain
            let candidate_id = extract_id_from_sni(&sni_lower);

            for entry in &self.config.entries {
                if entry.name.eq_ignore_ascii_case(&sni_lower) {
                    return Some(entry.clone());
                }
                for id in &entry.ids {
                    if id.eq_ignore_ascii_case(&sni_lower) {
                        return Some(entry.clone());
                    }
                    if let Some(cand) = candidate_id
                        && id.eq_ignore_ascii_case(cand)
                    {
                        return Some(entry.clone());
                    }
                }
            }
        }

        None
    }

    fn match_by_ip_or_cidr(&self, client_ip: IpAddr) -> Option<ClientEntryConfig> {
        for entry in &self.config.entries {
            for id in &entry.ids {
                // Exact IP
                if let Ok(ip) = id.parse::<IpAddr>()
                    && ip == client_ip
                {
                    return Some(entry.clone());
                }
                // CIDR subnet
                if id.contains('/') && cidr_matches(id, client_ip) {
                    return Some(entry.clone());
                }
            }
        }
        None
    }

    fn match_by_mac(&self, mac: &str) -> Option<ClientEntryConfig> {
        for entry in &self.config.entries {
            for id in &entry.ids {
                if let Some(entry_mac) = normalize_mac(id)
                    && entry_mac.eq_ignore_ascii_case(mac)
                {
                    return Some(entry.clone());
                }
            }
        }
        None
    }

    fn match_by_routeros(&self, ctx: &mut ClientContext) -> Option<ClientEntryConfig> {
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
                    if let Some(ref h) = lease.hostname
                        && entry.name.eq_ignore_ascii_case(h)
                    {
                        return Some(entry.clone());
                    }
                    for id in &entry.ids {
                        if normalize_mac(id).is_some_and(|m| m.eq_ignore_ascii_case(&lease.mac)) {
                            return Some(entry.clone());
                        }
                        if let Some(ref h) = lease.hostname
                            && id.eq_ignore_ascii_case(h)
                        {
                            return Some(entry.clone());
                        }
                        if let Some(ref c) = lease.comment
                            && id.eq_ignore_ascii_case(c)
                        {
                            return Some(entry.clone());
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

                if ctx.client_name.is_none() {
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

/// Check if target_ip is contained within a CIDR subnet block.
fn cidr_matches(cidr_str: &str, target_ip: IpAddr) -> bool {
    let Some((ip_str, prefix_str)) = cidr_str.split_once('/') else {
        return false;
    };
    let Ok(net_ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u8>() else {
        return false;
    };

    match (net_ip, target_ip) {
        (IpAddr::V4(net), IpAddr::V4(tgt)) => {
            if prefix > 32 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask = if prefix == 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(net) & mask) == (u32::from(tgt) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(tgt)) => {
            if prefix > 128 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask = if prefix == 128 {
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
        let mut ctx = ClientContext::with_id(ip, "janes-phone");

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
        let mut ctx = ClientContext::with_sni(ip, "janes-phone.dns.home.arpa");

        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.client_name.as_deref(), Some("Jane's Phone"));
        assert_eq!(policy.group_name, "kids");
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
    fn test_id_by_routeros() {
        let reg = ClientRegistry::new(sample_config());
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
    }

    #[test]
    fn test_client_id_beats_ip() {
        let reg = ClientRegistry::new(sample_config());
        // IP matches Jane's Phone, but ClientID matches Admin Laptop
        let ip = IpAddr::from_str("192.168.1.20").unwrap();
        let mut ctx = ClientContext::with_id(ip, "admin-laptop");

        let policy = reg.resolve(&mut ctx, Utc::now());
        assert_eq!(policy.client_name.as_deref(), Some("Admin Laptop"));
        assert_eq!(policy.group_name, "admin");
        assert!(policy.trusted);
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
