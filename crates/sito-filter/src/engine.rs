//! Hosts filter engine implementation.

use crate::downloader::ListDownloader;
use crate::error::FilterError;
use crate::parser::parse_hosts;
use arc_swap::ArcSwap;
use fnv::FnvHashSet;
use hickory_proto::rr::{Name, RecordType};
use sito_core::client::ClientContext;
use sito_core::config::FilteringConfig;
use sito_core::engine::FilterEngine;
use sito_core::verdict::{BlockReason, RuleRef, Verdict};
use sito_proto::normalize_domain;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// In-memory snapshot of compiled filter rules.
#[derive(Default, Debug, Clone)]
pub struct FilterSnapshot {
    /// Exact normalized domains to block.
    pub exact: FnvHashSet<String>,
    /// Total count of unique rules in this snapshot.
    pub rule_count: usize,
}

/// Thread-safe filtering engine implementing hosts-format blocking.
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

    /// Current number of loaded blocking rules.
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
        let (new_set, count) = tokio::task::spawn_blocking(move || {
            let mut set = FnvHashSet::default();
            for (_name, content) in list_contents {
                parse_hosts(&content, &mut set);
            }
            for rule in custom_rules {
                parse_hosts(&rule, &mut set);
            }
            let len = set.len();
            (set, len)
        })
        .await
        .unwrap_or_else(|_| (FnvHashSet::default(), 0));

        let prev_count = self.snapshot.load().rule_count;
        if prev_count > 0 && count < prev_count / 2 {
            warn!(
                previous_count = prev_count,
                new_count = count,
                "Rule count dropped by >50%, retaining previous filter snapshot to protect against corrupted source"
            );
            return Ok(prev_count);
        }

        self.snapshot.store(Arc::new(FilterSnapshot {
            exact: new_set,
            rule_count: count,
        }));

        info!(rule_count = count, "Filter snapshot compiled and loaded");
        Ok(count)
    }

    /// Spawns a background task that periodically refreshes the blocklists.
    pub fn spawn_refresh_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval_hours = self.config.refresh_interval_hours.max(1);
        let interval = Duration::from_secs(interval_hours * 3600);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // First tick fires immediately, so skip it since we initialized at startup
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
    fn evaluate(&self, qname: &Name, _qtype: RecordType, _client: &ClientContext) -> Verdict {
        if !self.config.enabled {
            return Verdict::Allow(None);
        }

        let raw_domain = qname.to_utf8();
        let Ok(normalized) = normalize_domain(&raw_domain) else {
            return Verdict::Allow(None);
        };

        let snapshot = self.snapshot.load();
        if snapshot.exact.contains(&normalized) {
            Verdict::Block(BlockReason::Rule(RuleRef::new(normalized)))
        } else {
            Verdict::Allow(None)
        }
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
        let mut config = FilteringConfig::default();
        config.custom_rules = vec![
            "0.0.0.0 ads.example.com".to_string(),
            "127.0.0.1 tracker.bad.net".to_string(),
        ];

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

        let mut config = FilteringConfig::default();
        config.lists = vec![FilterListConfig {
            name: "offline_list".to_string(),
            // Unreachable URL
            url: "http://127.0.0.1:1".to_string(),
            enabled: true,
            refresh_hours: None,
        }];

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
        let mut config = FilteringConfig::default();
        config.custom_rules = vec![
            "0.0.0.0 ad1.com\n0.0.0.0 ad2.com\n0.0.0.0 ad3.com\n0.0.0.0 ad4.com\n0.0.0.0 ad5.com\n0.0.0.0 ad6.com".to_string(),
        ];

        let mut engine = HostsFilterEngine::init(config.clone(), temp_dir.clone()).await;
        assert_eq!(engine.rule_count(), 6);

        // Update config to drop to 1 rule (>50% drop)
        engine.config.custom_rules = vec!["0.0.0.0 ad1.com".to_string()];
        let count = engine.reload().await.unwrap();
        // Should have retained the 6 rules
        assert_eq!(count, 6);
        assert_eq!(engine.rule_count(), 6);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
