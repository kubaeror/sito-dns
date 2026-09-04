//! High-throughput filter engine implementation supporting ABP syntax and multi-structure matching.

use crate::downloader::ListDownloader;
use crate::error::FilterError;
use crate::parser::{Pattern, Rule, RuleKind, parse_rules};
use crate::structures::{CompiledRuleSet, LabelInterner, RuleSetBuilder};
use arc_swap::ArcSwap;
use fnv::FnvHashSet;
use hickory_proto::rr::{Name, RecordType};
use sito_core::client::ClientContext;
use sito_core::config::FilteringConfig;
use sito_core::engine::FilterEngine;
use sito_core::verdict::{BlockReason, RewriteAction, RuleRef, Verdict};
use sito_proto::normalize_domain;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// In-memory snapshot of compiled filter rules.
#[derive(Default, Debug, Clone)]
pub struct FilterSnapshot {
    /// Exact normalized domains to block (retained for backward compatibility).
    pub exact: FnvHashSet<String>,
    /// Interning pool for domain labels across suffix tries.
    pub interner: LabelInterner,
    /// Allowlist structures (`@@` rules).
    pub allowlist: CompiledRuleSet,
    /// Blocklist structures.
    pub blocklist: CompiledRuleSet,
    /// All active compiled rules indexed by rule_id.
    pub rules: Vec<Rule>,
    /// Total count of unique rules in this snapshot.
    pub rule_count: usize,
}

impl FilterSnapshot {
    /// Compiles a slice of parsed rules into high-throughput lookup structures,
    /// resolving `$badfilter` deactivations and deduplicating identical rules.
    pub fn compile(parsed_rules: Vec<Rule>) -> Self {
        let mut interner = LabelInterner::new();
        let mut allow_builder = RuleSetBuilder::new();
        let mut block_builder = RuleSetBuilder::new();
        let mut legacy_exact = FnvHashSet::default();

        // 1. Identify all rules marked with $badfilter
        let mut badfilter_set = FnvHashSet::default();
        for rule in &parsed_rules {
            if rule.modifiers.badfilter {
                badfilter_set.insert(rule.canonical.clone());
            }
        }

        // 2. Filter out badfiltered rules and deduplicate active rules by canonical form
        let mut seen_canonical = FnvHashSet::default();
        let mut active_rules = Vec::new();

        for rule in parsed_rules {
            if rule.modifiers.badfilter {
                continue;
            }
            if badfilter_set.contains(&rule.canonical) {
                continue;
            }
            if !seen_canonical.insert(rule.canonical.clone()) {
                continue;
            }

            let rule_id = active_rules.len() as u32;

            match (&rule.kind, &rule.pattern) {
                (RuleKind::Allow, Pattern::Exact(dom)) => {
                    allow_builder.add_exact(dom.clone(), rule_id);
                }
                (RuleKind::Allow, Pattern::Domain(dom)) => {
                    allow_builder.add_domain(dom.clone(), rule_id);
                }
                (RuleKind::Allow, Pattern::Prefix(p)) => {
                    allow_builder.add_prefix(p.clone(), rule_id);
                }
                (RuleKind::Allow, Pattern::Substring(sub)) => {
                    allow_builder.add_substring(sub.clone(), rule_id);
                }
                (RuleKind::Allow, Pattern::Wildcard(w)) => {
                    allow_builder.add_wildcard(w, rule_id);
                }
                (RuleKind::Allow, Pattern::Regex(r)) => {
                    allow_builder.add_regex(r.clone(), rule_id);
                }

                (RuleKind::Block, Pattern::Exact(dom)) => {
                    legacy_exact.insert(dom.clone());
                    block_builder.add_exact(dom.clone(), rule_id);
                }
                (RuleKind::Block, Pattern::Domain(dom)) => {
                    block_builder.add_domain(dom.clone(), rule_id);
                }
                (RuleKind::Block, Pattern::Prefix(p)) => {
                    block_builder.add_prefix(p.clone(), rule_id);
                }
                (RuleKind::Block, Pattern::Substring(sub)) => {
                    block_builder.add_substring(sub.clone(), rule_id);
                }
                (RuleKind::Block, Pattern::Wildcard(w)) => {
                    block_builder.add_wildcard(w, rule_id);
                }
                (RuleKind::Block, Pattern::Regex(r)) => {
                    block_builder.add_regex(r.clone(), rule_id);
                }
            }

            active_rules.push(rule);
        }

        let allowlist = allow_builder.build(&mut interner);
        let blocklist = block_builder.build(&mut interner);
        let rule_count = active_rules.len();

        Self {
            exact: legacy_exact,
            interner,
            allowlist,
            blocklist,
            rules: active_rules,
            rule_count,
        }
    }

    /// Evaluates a domain against the compiled snapshot following section 4.3 precedence.
    pub fn evaluate(&self, domain: &str, qtype: RecordType, client: &ClientContext) -> Verdict {
        let mut allow_candidates = Vec::new();
        self.allowlist
            .collect_candidates(domain, &self.interner, &mut allow_candidates);

        let mut block_candidates = Vec::new();
        self.blocklist
            .collect_candidates(domain, &self.interner, &mut block_candidates);

        // Stage 1: Important Allowlist (@@...$important)
        for &rule_id in &allow_candidates {
            let rule = &self.rules[rule_id as usize];
            if !rule.modifiers.important {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client {
                if !client_filter.matches(client) {
                    continue;
                }
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype {
                if !dnstype_filter.matches(qtype) {
                    continue;
                }
            }
            let rule_ref = RuleRef::new(&rule.raw).with_source(&rule.source, rule.line as usize);
            return Verdict::Allow(Some(rule_ref));
        }

        // Stage 2: Important Blocklist (...$important)
        for &rule_id in &block_candidates {
            let rule = &self.rules[rule_id as usize];
            if !rule.modifiers.important {
                continue;
            }
            if rule.modifiers.denyallow_matches(domain) {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client {
                if !client_filter.matches(client) {
                    continue;
                }
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype {
                if !dnstype_filter.matches(qtype) {
                    continue;
                }
            }
            if let Some(rewrite) = &rule.modifiers.dnsrewrite {
                return Verdict::Rewrite(RewriteAction::DnsRewrite {
                    rcode: rewrite.rcode.clone(),
                    rtype: rewrite.rtype.clone(),
                    value: rewrite.value.clone(),
                });
            }
            let rule_ref = RuleRef::new(&rule.raw).with_source(&rule.source, rule.line as usize);
            return Verdict::Block(BlockReason::Rule(rule_ref));
        }

        // Stage 3: Standard Allowlist (@@...)
        for &rule_id in &allow_candidates {
            let rule = &self.rules[rule_id as usize];
            if rule.modifiers.important {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client {
                if !client_filter.matches(client) {
                    continue;
                }
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype {
                if !dnstype_filter.matches(qtype) {
                    continue;
                }
            }
            let rule_ref = RuleRef::new(&rule.raw).with_source(&rule.source, rule.line as usize);
            return Verdict::Allow(Some(rule_ref));
        }

        // Stage 4: Standard Blocklist (...)
        for &rule_id in &block_candidates {
            let rule = &self.rules[rule_id as usize];
            if rule.modifiers.important {
                continue;
            }
            if rule.modifiers.denyallow_matches(domain) {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client {
                if !client_filter.matches(client) {
                    continue;
                }
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype {
                if !dnstype_filter.matches(qtype) {
                    continue;
                }
            }
            if let Some(rewrite) = &rule.modifiers.dnsrewrite {
                return Verdict::Rewrite(RewriteAction::DnsRewrite {
                    rcode: rewrite.rcode.clone(),
                    rtype: rewrite.rtype.clone(),
                    value: rewrite.value.clone(),
                });
            }
            let rule_ref = RuleRef::new(&rule.raw).with_source(&rule.source, rule.line as usize);
            return Verdict::Block(BlockReason::Rule(rule_ref));
        }

        Verdict::Allow(None)
    }
}

/// Thread-safe filtering engine implementing AdGuard ABP and hosts blocking.
pub struct HostsFilterEngine {
    snapshot: ArcSwap<FilterSnapshot>,
    config: FilteringConfig,
    data_dir: PathBuf,
    downloader: ListDownloader,
}

impl HostsFilterEngine {
    /// Creates a new `HostsFilterEngine` with an empty snapshot.
    pub fn new(config: FilteringConfig, data_dir: PathBuf) -> Self {
        Self {
            snapshot: ArcSwap::new(Arc::new(FilterSnapshot::default())),
            config,
            data_dir,
            downloader: ListDownloader::default(),
        }
    }

    /// Initializes and loads lists immediately (from download or disk cache).
    pub async fn init(config: FilteringConfig, data_dir: PathBuf) -> Self {
        let engine = Self::new(config, data_dir);
        let _ = engine.reload().await;
        engine
    }

    /// Returns a full reference to the current active `FilterSnapshot`.
    pub fn snapshot(&self) -> Arc<FilterSnapshot> {
        self.snapshot.load_full()
    }

    /// Current number of active loaded blocking rules.
    pub fn rule_count(&self) -> usize {
        self.snapshot.load().rule_count
    }

    /// Reloads all configured blocklists and custom rules, updating snapshot atomically.
    pub async fn reload(&self) -> Result<usize, FilterError> {
        if !self.config.enabled {
            self.snapshot.store(Arc::new(FilterSnapshot::default()));
            return Ok(0);
        }

        let mut list_contents = Vec::new();

        for list in &self.config.lists {
            if !list.enabled {
                continue;
            }

            match self
                .downloader
                .fetch_or_cached(&list.name, &list.url, &self.data_dir)
                .await
            {
                Ok(content) => {
                    list_contents.push((list.name.clone(), content));
                }
                Err(e) => {
                    warn!(
                        list = %list.name,
                        url = %list.url,
                        error = %e,
                        "Failed to load blocklist from network or disk cache; skipping list"
                    );
                }
            }
        }

        let custom_rules = self.config.custom_rules.clone();

        // Compile rules in blocking task to avoid stalling the tokio async runtime
        let (new_snapshot, count) = tokio::task::spawn_blocking(move || {
            let mut all_rules = Vec::new();
            for (name, content) in list_contents {
                let (rules, _) = parse_rules(&content, &name);
                all_rules.extend(rules);
            }
            for rule_text in &custom_rules {
                let (rules, _) = parse_rules(rule_text, "custom");
                all_rules.extend(rules);
            }
            let snapshot = FilterSnapshot::compile(all_rules);
            let count = snapshot.rule_count;
            (snapshot, count)
        })
        .await
        .unwrap_or_else(|_| (FilterSnapshot::default(), 0));

        let prev_count = self.snapshot.load().rule_count;
        if prev_count > 0 && count < prev_count / 2 {
            warn!(
                previous_count = prev_count,
                new_count = count,
                "Rule count dropped by >50%, retaining previous filter snapshot to protect against corrupted source"
            );
            return Ok(prev_count);
        }

        self.snapshot.store(Arc::new(new_snapshot));
        info!(rule_count = count, "Filter snapshot compiled and loaded");
        Ok(count)
    }

    /// Spawns a background task that periodically refreshes the blocklists.
    pub fn spawn_refresh_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval_hours = self.config.refresh_interval_hours.max(1);
        let interval = Duration::from_secs(interval_hours * 3600);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;

            loop {
                ticker.tick().await;
                info!("Running scheduled blocklist refresh...");
                if let Err(err) = self.reload().await {
                    warn!(error = %err, "Scheduled blocklist refresh failed");
                }
            }
        })
    }
}

impl FilterEngine for HostsFilterEngine {
    fn evaluate(&self, qname: &Name, qtype: RecordType, client: &ClientContext) -> Verdict {
        if !self.config.enabled {
            return Verdict::Allow(None);
        }

        let raw_domain = qname.to_utf8();
        let Ok(normalized) = normalize_domain(&raw_domain) else {
            return Verdict::Allow(None);
        };

        let snapshot = self.snapshot.load();
        snapshot.evaluate(&normalized, qtype, client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sito_core::config::FilterListConfig;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_hosts_filter_blocking() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_engine_test_{}", std::process::id()));
        let config = FilteringConfig {
            custom_rules: vec![
                "0.0.0.0 ads.example.com".to_string(),
                "127.0.0.1 tracker.bad.net".to_string(),
            ],
            ..Default::default()
        };

        let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());

        // Blocked domain
        let qname_blocked = Name::from_str("ads.example.com.").unwrap();
        let verdict = engine.evaluate(&qname_blocked, RecordType::A, &client);
        assert!(verdict.is_blocked());

        // Allowed domain
        let qname_allowed = Name::from_str("good.example.com.").unwrap();
        let verdict = engine.evaluate(&qname_allowed, RecordType::A, &client);
        assert!(verdict.is_allowed());

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_abp_rules_and_precedence() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_precedence_test_{}", std::process::id()));
        let config = FilteringConfig {
            custom_rules: vec![
                // Standard block
                "||blocked.example^".to_string(),
                // Allowlist beats standard block
                "@@||sub.blocked.example^".to_string(),
                // Important block beats standard allowlist
                "||important.sub.blocked.example^$important".to_string(),
                // Important allowlist beats important block
                "@@||special.important.sub.blocked.example^$important".to_string(),
            ],
            ..Default::default()
        };

        let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());

        // 1. Standard block
        let q1 = Name::from_str("blocked.example.").unwrap();
        assert!(engine.evaluate(&q1, RecordType::A, &client).is_blocked());

        // 2. Allowlist unblocks
        let q2 = Name::from_str("sub.blocked.example.").unwrap();
        assert!(engine.evaluate(&q2, RecordType::A, &client).is_allowed());

        // 3. Important block overrides allowlist
        let q3 = Name::from_str("important.sub.blocked.example.").unwrap();
        assert!(engine.evaluate(&q3, RecordType::A, &client).is_blocked());

        // 4. Important allowlist overrides important block
        let q4 = Name::from_str("special.important.sub.blocked.example.").unwrap();
        assert!(engine.evaluate(&q4, RecordType::A, &client).is_allowed());

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_modifiers_evaluation() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_modifiers_test_{}", std::process::id()));
        let config = FilteringConfig {
            custom_rules: vec![
                // $client
                "||client-only.com^$client=192.168.1.100|laptop".to_string(),
                // $dnstype
                "||type-only.com^$dnstype=HTTPS|65".to_string(),
                // $denyallow
                "||denyallow.com^$denyallow=allowed.denyallow.com".to_string(),
                // $dnsrewrite
                "||rewrite.com^$dnsrewrite=1.2.3.4".to_string(),
                // $badfilter deactivates a rule
                "||deactivated.com^".to_string(),
                "||deactivated.com^$badfilter".to_string(),
            ],
            ..Default::default()
        };

        let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;

        // $client test
        let client1 = ClientContext::new("192.168.1.100".parse().unwrap());
        let client2 = ClientContext::new("192.168.1.200".parse().unwrap());
        let client3 = ClientContext::with_id("192.168.1.200".parse().unwrap(), "laptop");
        let q_client = Name::from_str("client-only.com.").unwrap();

        assert!(
            engine
                .evaluate(&q_client, RecordType::A, &client1)
                .is_blocked()
        );
        assert!(
            engine
                .evaluate(&q_client, RecordType::A, &client2)
                .is_allowed()
        );
        assert!(
            engine
                .evaluate(&q_client, RecordType::A, &client3)
                .is_blocked()
        );

        // $dnstype test
        let q_type = Name::from_str("type-only.com.").unwrap();
        assert!(
            engine
                .evaluate(&q_type, RecordType::A, &client1)
                .is_allowed()
        );
        assert!(
            engine
                .evaluate(&q_type, RecordType::HTTPS, &client1)
                .is_blocked()
        );

        // $denyallow test
        let q_denied = Name::from_str("denyallow.com.").unwrap();
        let q_excepted = Name::from_str("allowed.denyallow.com.").unwrap();
        assert!(
            engine
                .evaluate(&q_denied, RecordType::A, &client1)
                .is_blocked()
        );
        assert!(
            engine
                .evaluate(&q_excepted, RecordType::A, &client1)
                .is_allowed()
        );

        // $dnsrewrite test
        let q_rewrite = Name::from_str("rewrite.com.").unwrap();
        let verdict = engine.evaluate(&q_rewrite, RecordType::A, &client1);
        match verdict {
            Verdict::Rewrite(RewriteAction::DnsRewrite {
                rcode,
                rtype,
                value,
            }) => {
                assert_eq!(rcode, "NOERROR");
                assert_eq!(rtype.as_deref(), Some("A"));
                assert_eq!(value.as_deref(), Some("1.2.3.4"));
            }
            other => panic!("expected Verdict::Rewrite, got {other:?}"),
        }

        // $badfilter test
        let q_bad = Name::from_str("deactivated.com.").unwrap();
        assert!(
            engine
                .evaluate(&q_bad, RecordType::A, &client1)
                .is_allowed()
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_disk_cache_offline_fallback() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_offline_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir.join("lists"))
            .await
            .unwrap();

        let cached_file = temp_dir.join("lists").join("offline_list.txt");
        tokio::fs::write(&cached_file, "0.0.0.0 cached-ad.com\n")
            .await
            .unwrap();

        let config = FilteringConfig {
            lists: vec![FilterListConfig {
                name: "offline_list".to_string(),
                url: "http://127.0.0.1:1".to_string(),
                enabled: true,
                refresh_hours: None,
            }],
            ..Default::default()
        };

        let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
        assert_eq!(engine.rule_count(), 1);

        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let qname = Name::from_str("cached-ad.com.").unwrap();
        assert!(engine.evaluate(&qname, RecordType::A, &client).is_blocked());

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_protection_against_drastic_rule_drop() {
        let temp_dir = std::env::temp_dir().join(format!("sito_drop_test_{}", std::process::id()));
        let config = FilteringConfig {
            custom_rules: vec![
                "0.0.0.0 ad1.com\n0.0.0.0 ad2.com\n0.0.0.0 ad3.com\n0.0.0.0 ad4.com\n0.0.0.0 ad5.com\n0.0.0.0 ad6.com".to_string(),
            ],
            ..Default::default()
        };

        let mut engine = HostsFilterEngine::init(config.clone(), temp_dir.clone()).await;
        assert_eq!(engine.rule_count(), 6);

        // Update config to drop to 1 rule (>50% drop)
        engine.config.custom_rules = vec!["0.0.0.0 ad1.com".to_string()];
        let count = engine.reload().await.unwrap();
        assert_eq!(count, 6);
        assert_eq!(engine.rule_count(), 6);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
