//! High-throughput filter engine implementation supporting ABP syntax and multi-structure matching.

use crate::downloader::ListDownloader;
use crate::error::FilterError;
use crate::parser::{Pattern, Rule, RuleKind, parse_rules};
use crate::structures::{
    CompiledRuleSet, LabelInterner, MAX_REGEX_PATTERN_BYTES, MAX_REGEX_PATTERNS, RuleSetBuilder,
};
use arc_swap::ArcSwap;
use fnv::{FnvHashMap, FnvHashSet};
use hickory_proto::rr::{Name, RecordType};
use sito_core::client::ClientContext;
use sito_core::config::FilteringConfig;
use sito_core::engine::FilterEngine;
use sito_core::verdict::{BlockReason, RewriteAction, RuleRef, Verdict};
use sito_proto::normalize_domain;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

/// Lifecycle state of the filter engine's active snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterState {
    /// `filtering.enabled = false`: filtering is intentionally disabled.
    Disabled,
    /// The initial (or first) rule load has not produced a snapshot yet.
    #[default]
    Loading,
    /// A snapshot is active (possibly empty when nothing is configured).
    Ready,
    /// Every configured source failed and no rules are active.
    Failed,
}

/// Observable status of the filter engine.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilterStatus {
    /// Current lifecycle state.
    pub state: FilterState,
    /// Number of active rules in the current snapshot.
    pub rule_count: usize,
    /// Number of configured lists that loaded successfully in the last reload.
    pub loaded_lists: usize,
    /// Names of configured lists that failed to load in the last reload.
    pub failed_lists: Vec<String>,
    /// Most recent reload error, if any.
    pub last_error: Option<String>,
}

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

    /// Evaluates a domain against only `$important` rules using pre-collected candidates (Stages 1 and 2).
    pub fn evaluate_important_candidates(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        allow_candidates: &[u32],
        block_candidates: &[u32],
    ) -> Option<Verdict> {
        // Stage 1: Important Allowlist (@@...$important)
        for &rule_id in allow_candidates {
            let rule = &self.rules[rule_id as usize];
            if !rule.modifiers.important {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client
                && !client_filter.matches(client)
            {
                continue;
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype
                && !dnstype_filter.matches(qtype)
            {
                continue;
            }
            let rule_ref = RuleRef::new(&rule.raw).with_source(&rule.source, rule.line as usize);
            return Some(Verdict::Allow(Some(rule_ref)));
        }

        // Stage 2: Important Blocklist (...$important)
        for &rule_id in block_candidates {
            let rule = &self.rules[rule_id as usize];
            if !rule.modifiers.important {
                continue;
            }
            if rule.modifiers.denyallow_matches(domain) {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client
                && !client_filter.matches(client)
            {
                continue;
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype
                && !dnstype_filter.matches(qtype)
            {
                continue;
            }
            if let Some(rewrite) = &rule.modifiers.dnsrewrite {
                return Some(Verdict::Rewrite(RewriteAction::DnsRewrite {
                    rcode: rewrite.rcode.clone(),
                    rtype: rewrite.rtype.clone(),
                    value: rewrite.value.clone(),
                }));
            }
            let rule_ref = RuleRef::new(&rule.raw).with_source(&rule.source, rule.line as usize);
            return Some(Verdict::Block(BlockReason::Rule(rule_ref)));
        }

        None
    }

    /// Evaluates a domain against standard filter rules using pre-collected candidates (Stages 3 and 4).
    pub fn evaluate_standard_candidates(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        allow_candidates: &[u32],
        block_candidates: &[u32],
    ) -> Verdict {
        // Stage 3: Standard Allowlist (@@...)
        for &rule_id in allow_candidates {
            let rule = &self.rules[rule_id as usize];
            if rule.modifiers.important {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client
                && !client_filter.matches(client)
            {
                continue;
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype
                && !dnstype_filter.matches(qtype)
            {
                continue;
            }
            let rule_ref = RuleRef::new(&rule.raw).with_source(&rule.source, rule.line as usize);
            return Verdict::Allow(Some(rule_ref));
        }

        // Stage 4: Standard Blocklist (...)
        for &rule_id in block_candidates {
            let rule = &self.rules[rule_id as usize];
            if rule.modifiers.important {
                continue;
            }
            if rule.modifiers.denyallow_matches(domain) {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client
                && !client_filter.matches(client)
            {
                continue;
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype
                && !dnstype_filter.matches(qtype)
            {
                continue;
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

    /// Evaluates a domain against only `$important` rules (Stages 1 and 2).
    /// Returns `Some(verdict)` if an `$important` rule matched, or `None` if no `$important` rule applied.
    pub fn evaluate_important(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
    ) -> Option<Verdict> {
        let mut allow_candidates = Vec::new();
        self.allowlist
            .collect_candidates(domain, &self.interner, &mut allow_candidates);

        let mut block_candidates = Vec::new();
        self.blocklist
            .collect_candidates(domain, &self.interner, &mut block_candidates);

        self.evaluate_important_candidates(
            domain,
            qtype,
            client,
            &allow_candidates,
            &block_candidates,
        )
    }

    /// Evaluates a domain against standard filter rules (Stages 3 and 4).
    pub fn evaluate_standard(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
    ) -> Verdict {
        let mut allow_candidates = Vec::new();
        self.allowlist
            .collect_candidates(domain, &self.interner, &mut allow_candidates);

        let mut block_candidates = Vec::new();
        self.blocklist
            .collect_candidates(domain, &self.interner, &mut block_candidates);

        self.evaluate_standard_candidates(
            domain,
            qtype,
            client,
            &allow_candidates,
            &block_candidates,
        )
    }

    /// Evaluates a domain against the compiled snapshot following section 4.3 precedence.
    /// Collects rule candidates once and passes them through both passes on the hot path.
    pub fn evaluate(&self, domain: &str, qtype: RecordType, client: &ClientContext) -> Verdict {
        let mut allow_candidates = Vec::new();
        self.allowlist
            .collect_candidates(domain, &self.interner, &mut allow_candidates);

        let mut block_candidates = Vec::new();
        self.blocklist
            .collect_candidates(domain, &self.interner, &mut block_candidates);

        if let Some(verdict) = self.evaluate_important_candidates(
            domain,
            qtype,
            client,
            &allow_candidates,
            &block_candidates,
        ) {
            return verdict;
        }

        self.evaluate_standard_candidates(
            domain,
            qtype,
            client,
            &allow_candidates,
            &block_candidates,
        )
    }
}

/// Computes the next refresh wake-up and the list names that are due.
///
/// Lists without `refresh_hours` use the global `refresh_interval_hours`.
fn refresh_schedule(
    config: &FilteringConfig,
    next_due: &mut FnvHashMap<String, Instant>,
    now: Instant,
) -> (Duration, Vec<String>) {
    let global = Duration::from_secs(config.refresh_interval_hours.max(1).saturating_mul(3600));
    next_due.retain(|name, _| config.lists.iter().any(|l| l.enabled && &l.name == name));

    let mut due = Vec::new();
    let mut soonest: Option<Instant> = None;
    for list in config.lists.iter().filter(|l| l.enabled) {
        let interval = list.refresh_hours.map_or(global, |hours| {
            Duration::from_secs(hours.max(1).saturating_mul(3600))
        });
        let entry = next_due.entry(list.name.clone()).or_insert(now + interval);
        if *entry <= now {
            due.push(list.name.clone());
        }
        soonest = Some(soonest.map_or(*entry, |s| s.min(*entry)));
    }

    let sleep_for = if due.is_empty() {
        soonest.map_or(global, |s| s.saturating_duration_since(now))
    } else {
        Duration::ZERO
    };
    (sleep_for, due)
}

/// Returns a reason when a parsed list's regex/wildcard load exceeds the
/// per-set compilation limits; the list must then be rejected instead of
/// letting a hostile list consume unbounded DFA compile resources.
fn regex_load_exceeds_limits(rules: &[Rule]) -> Option<String> {
    let mut count = 0usize;
    let mut bytes = 0usize;
    for rule in rules {
        match &rule.pattern {
            Pattern::Regex(pattern) => {
                count += 1;
                bytes += pattern.len();
            }
            Pattern::Wildcard(pattern) => {
                count += 1;
                // Count the expanded regex size so the engine-side limit
                // matches what the DFA builder would have to compile.
                bytes += crate::structures::wildcard_to_regex(pattern).len();
            }
            _ => {}
        }
    }
    if count > MAX_REGEX_PATTERNS {
        return Some(format!(
            "{count} regex/wildcard patterns exceed the limit of {MAX_REGEX_PATTERNS}"
        ));
    }
    if bytes > MAX_REGEX_PATTERN_BYTES {
        return Some(format!(
            "{bytes} regex/wildcard pattern bytes exceed the limit of {MAX_REGEX_PATTERN_BYTES}"
        ));
    }
    None
}

/// Normalizes a query name to its ASCII/punycode, lowercased form.
///
/// `Name::to_utf8()` decodes IDNA labels (`xn--`), which are then rejected by
/// [`normalize_domain`] and silently failed open. The wire/ASCII form keeps
/// IDN queries matchable (e.g. `münchen.de` -> `xn--mnchen-3ya.de`). If the
/// name still cannot be normalized (escaped wire bytes, malformed punycode),
/// fall back to the lowercased ASCII text so the query is still evaluated
/// against substring/regex rules rather than bypassing filtering entirely.
fn normalized_query_domain(qname: &Name) -> String {
    let ascii = qname.to_ascii();
    normalize_domain(&ascii).unwrap_or_else(|_| {
        let fallback = ascii.trim_end_matches('.').to_ascii_lowercase();
        if fallback.is_empty() {
            // Root: keep a non-empty placeholder so substring/regex rules
            // cannot accidentally match the empty string.
            ".".to_string()
        } else {
            fallback
        }
    })
}

/// Thread-safe filtering engine implementing AdGuard ABP and hosts blocking.
pub struct HostsFilterEngine {
    snapshot: ArcSwap<FilterSnapshot>,
    config: ArcSwap<FilteringConfig>,
    data_dir: PathBuf,
    downloader: ListDownloader,
    /// Parsed rules per list, used to refresh individual lists without refetching all.
    list_rules: std::sync::Mutex<FnvHashMap<String, Vec<Rule>>>,
    /// Serializes reload/refresh cycles so concurrent scheduled and API-driven
    /// reloads cannot interleave their list-state reads and writes.
    reload_lock: tokio::sync::Mutex<()>,
    /// Observability state (loading/ready/failed, per-list failures).
    status: ArcSwap<FilterStatus>,
}

impl HostsFilterEngine {
    /// Creates a new `HostsFilterEngine` with an empty snapshot.
    pub fn new(config: FilteringConfig, data_dir: PathBuf) -> Self {
        let status = FilterStatus {
            state: if config.enabled {
                FilterState::Loading
            } else {
                FilterState::Disabled
            },
            ..FilterStatus::default()
        };
        Self {
            snapshot: ArcSwap::new(Arc::new(FilterSnapshot::default())),
            config: ArcSwap::new(Arc::new(config)),
            data_dir,
            downloader: ListDownloader::default(),
            list_rules: std::sync::Mutex::new(FnvHashMap::default()),
            reload_lock: tokio::sync::Mutex::new(()),
            status: ArcSwap::new(Arc::new(status)),
        }
    }

    /// Initializes and loads lists immediately (from download or disk cache).
    ///
    /// Failures are logged and reflected in [`HostsFilterEngine::status`];
    /// the engine keeps a `Failed` state instead of silently advertising an
    /// enabled-but-empty filter snapshot.
    pub async fn init(config: FilteringConfig, data_dir: PathBuf) -> Self {
        let engine = Self::new(config, data_dir);
        match engine.reload().await {
            Ok(count) => info!(rule_count = count, "Filter engine initialized"),
            Err(e) => error!(
                error = %e,
                "Initial filter list load failed; no filter rules are active until a later reload succeeds"
            ),
        }
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

    /// Current observable status of the filter engine.
    pub fn status(&self) -> FilterStatus {
        (*self.status.load_full()).clone()
    }

    /// Current lifecycle state of the filter engine.
    pub fn state(&self) -> FilterState {
        self.status.load().state
    }

    fn set_status(&self, status: FilterStatus) {
        self.status.store(Arc::new(status));
    }

    /// Reloads all configured blocklists and custom rules, updating snapshot atomically.
    /// Applies the >50% drop guard to protect against corrupted remote sources.
    pub async fn reload(&self) -> Result<usize, FilterError> {
        let config = self.config.load_full();
        self.reload_internal(&config, true, None).await
    }

    /// Reloads blocklists and custom rules using an updated filtering configuration.
    /// Does not enforce the >50% drop guard so intentional user deletions/edits take effect.
    /// The new configuration is retained for subsequent scheduled refreshes.
    pub async fn reload_with_config(&self, config: &FilteringConfig) -> Result<usize, FilterError> {
        self.config.store(Arc::new(config.clone()));
        self.reload_internal(config, false, None).await
    }

    /// Refreshes only the named blocklists, keeping rules from all other lists.
    pub async fn reload_lists(&self, names: &[String]) -> Result<usize, FilterError> {
        let config = self.config.load_full();
        self.reload_internal(&config, true, Some(names)).await
    }

    async fn reload_internal(
        &self,
        config: &FilteringConfig,
        apply_drop_guard: bool,
        only_lists: Option<&[String]>,
    ) -> Result<usize, FilterError> {
        // Serialize the whole fetch/merge/store cycle: a concurrent scheduled
        // refresh and API reload previously raced on `list_rules` and could
        // overwrite freshly merged lists with a stale map.
        let _reload_guard = self.reload_lock.lock().await;

        if !config.enabled {
            self.snapshot.store(Arc::new(FilterSnapshot::default()));
            self.list_rules.lock().unwrap().clear();
            self.set_status(FilterStatus {
                state: FilterState::Disabled,
                ..FilterStatus::default()
            });
            return Ok(0);
        }

        let mut list_contents = Vec::new();
        let mut loaded_lists = 0usize;
        let mut failed_lists = Vec::new();

        for list in &config.lists {
            if !list.enabled {
                continue;
            }

            if let Some(only) = only_lists
                && !only.iter().any(|name| name == &list.name)
            {
                continue;
            }

            match self
                .downloader
                .fetch_or_cached(&list.name, &list.url, &self.data_dir)
                .await
            {
                Ok(content) => {
                    loaded_lists += 1;
                    list_contents.push((list.name.clone(), content));
                }
                Err(e) => {
                    failed_lists.push(list.name.clone());
                    warn!(
                        list = %list.name,
                        url = %list.url,
                        error = %e,
                        "Failed to load blocklist from network or disk cache; skipping list"
                    );
                }
            }
        }

        let custom_rules = config.custom_rules.clone();
        let base_rules = self.list_rules.lock().unwrap().clone();
        let enabled_names: FnvHashSet<String> = config
            .lists
            .iter()
            .filter(|l| l.enabled)
            .map(|l| l.name.clone())
            .collect();

        // Compile rules in blocking task to avoid stalling the tokio async runtime
        let (new_snapshot, count, new_list_rules, rejected_lists) =
            tokio::task::spawn_blocking(move || {
                // Merge instead of overwriting: rules from lists that failed to
                // fetch in this cycle (or that are not part of a partial refresh)
                // are retained so a transient failure cannot drop protection.
                let mut map = base_rules;
                // Drop rules for lists that are no longer enabled/configured.
                map.retain(|name, _| enabled_names.contains(name));

                let mut rejected = Vec::new();
                for (name, content) in list_contents {
                    let (rules, _) = parse_rules(&content, &name);
                    if let Some(reason) = regex_load_exceeds_limits(&rules) {
                        error!(
                            list = %name,
                            reason = %reason,
                            "Rejecting blocklist with excessive regex pattern load"
                        );
                        rejected.push(name);
                        continue;
                    }
                    map.insert(name, rules);
                }

                // Deterministic rule-id assignment: lists sorted by name, rule
                // order preserved within each list, custom rules last (config
                // order). Candidate precedence (first match wins) therefore stays
                // stable across reloads and hash-map iteration order changes.
                let mut names: Vec<&String> = map.keys().collect();
                names.sort_unstable();
                let total_rules: usize = map.values().map(Vec::len).sum();
                let mut all_rules = Vec::with_capacity(total_rules + custom_rules.len());
                for name in names {
                    all_rules.extend(map[name].iter().cloned());
                }
                for rule_text in &custom_rules {
                    let (rules, _) = parse_rules(rule_text, "custom");
                    all_rules.extend(rules);
                }
                let snapshot = FilterSnapshot::compile(all_rules);
                let count = snapshot.rule_count;
                (snapshot, count, map, rejected)
            })
            .await
            .map_err(|e| {
                error!("Filter rule compilation task failed: {e}");
                self.set_status(FilterStatus {
                    state: FilterState::Failed,
                    rule_count: self.snapshot.load().rule_count,
                    failed_lists: failed_lists.clone(),
                    last_error: Some(e.to_string()),
                    ..FilterStatus::default()
                });
                FilterError::CompileTaskFailed(e.to_string())
            })?;

        failed_lists.extend(rejected_lists);

        let prev_count = self.snapshot.load().rule_count;
        if apply_drop_guard
            && prev_count > 0
            && (count == 0 || count.saturating_mul(2) < prev_count)
        {
            // retain the previous snapshot; the reload failure is observable
            // through the status instead of being silently swallowed.
            let reason = format!(
                "rule count dropped from {prev_count} to {count} (>50%); retained previous snapshot"
            );
            warn!(
                previous_count = prev_count,
                new_count = count,
                "Rule count dropped by >50%, retaining previous filter snapshot to protect against corrupted source"
            );
            self.set_status(FilterStatus {
                state: FilterState::Ready,
                rule_count: prev_count,
                loaded_lists,
                failed_lists,
                last_error: Some(reason),
            });
            return Ok(prev_count);
        }

        if count == 0 && !failed_lists.is_empty() && prev_count == 0 {
            let details = format!(
                "all {} configured filter source(s) failed to load: {}",
                failed_lists.len(),
                failed_lists.join(", ")
            );
            error!(
                lists = ?failed_lists,
                "No filter rules could be loaded; refusing to advertise an enabled empty snapshot"
            );
            self.set_status(FilterStatus {
                state: FilterState::Failed,
                rule_count: 0,
                loaded_lists,
                failed_lists: failed_lists.clone(),
                last_error: Some(details.clone()),
            });
            return Err(FilterError::NoSourcesLoaded {
                failed: failed_lists.len(),
                details,
            });
        }

        self.snapshot.store(Arc::new(new_snapshot));
        *self.list_rules.lock().unwrap() = new_list_rules;
        let last_error = if failed_lists.is_empty() {
            None
        } else {
            Some(format!(
                "{} list(s) failed to load: {}",
                failed_lists.len(),
                failed_lists.join(", ")
            ))
        };
        self.set_status(FilterStatus {
            state: FilterState::Ready,
            rule_count: count,
            loaded_lists,
            failed_lists,
            last_error,
        });
        info!(rule_count = count, "Filter snapshot compiled and loaded");
        Ok(count)
    }

    /// Spawns a background task that refreshes blocklists according to their
    /// per-list `refresh_hours` (falling back to `refresh_interval_hours`).
    pub fn spawn_refresh_task(
        self: Arc<Self>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut next_due: FnvHashMap<String, Instant> = FnvHashMap::default();
            loop {
                let (sleep_for, due) = {
                    let config = self.config.load_full();
                    refresh_schedule(&config, &mut next_due, Instant::now())
                };

                if due.is_empty() {
                    tokio::select! {
                        () = tokio::time::sleep(sleep_for) => {}
                        res = shutdown_rx.changed() => {
                            if res.is_err() || *shutdown_rx.borrow() {
                                info!("Filter refresh task shutting down");
                                break;
                            }
                        }
                    }
                    continue;
                }

                info!(lists = ?due, "Running scheduled blocklist refresh...");
                if let Err(err) = self.reload_lists(&due).await {
                    warn!(error = %err, "Scheduled blocklist refresh failed");
                }

                let config = self.config.load_full();
                let global =
                    Duration::from_secs(config.refresh_interval_hours.max(1).saturating_mul(3600));
                let now = Instant::now();
                for name in &due {
                    let interval = config
                        .lists
                        .iter()
                        .find(|l| &l.name == name)
                        .and_then(|l| l.refresh_hours)
                        .map_or(global, |hours| {
                            Duration::from_secs(hours.max(1).saturating_mul(3600))
                        });
                    next_due.insert(name.clone(), now + interval);
                }
            }
        })
    }

    /// Evaluates a domain query against only `$important` rules.
    pub fn evaluate_important(
        &self,
        qname: &Name,
        qtype: RecordType,
        client: &ClientContext,
    ) -> Option<Verdict> {
        if !self.config.load().enabled {
            return None;
        }

        let normalized = normalized_query_domain(qname);

        let snapshot = self.snapshot.load();
        snapshot.evaluate_important(&normalized, qtype, client)
    }

    /// Evaluates a domain query against standard filter rules.
    pub fn evaluate_standard(
        &self,
        qname: &Name,
        qtype: RecordType,
        client: &ClientContext,
    ) -> Verdict {
        if !self.config.load().enabled {
            return Verdict::Allow(None);
        }

        let normalized = normalized_query_domain(qname);

        let snapshot = self.snapshot.load();
        snapshot.evaluate_standard(&normalized, qtype, client)
    }
}

impl FilterEngine for HostsFilterEngine {
    fn evaluate(&self, qname: &Name, qtype: RecordType, client: &ClientContext) -> Verdict {
        if !self.config.load().enabled {
            return Verdict::Allow(None);
        }

        let normalized = normalized_query_domain(qname);

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
        let cached_file = crate::downloader::cache_path_for_list(&temp_dir, "offline_list");
        tokio::fs::create_dir_all(cached_file.parent().unwrap())
            .await
            .unwrap();

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

        let engine = HostsFilterEngine::init(config.clone(), temp_dir.clone()).await;
        assert_eq!(engine.rule_count(), 6);

        // Update config to drop to 1 rule (>50% drop)
        let mut droppped = (*engine.config.load_full()).clone();
        droppped.custom_rules = vec!["0.0.0.0 ad1.com".to_string()];
        engine.config.store(std::sync::Arc::new(droppped));
        let count = engine.reload().await.unwrap();
        assert_eq!(count, 6);
        assert_eq!(engine.rule_count(), 6);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_intentional_user_edit_bypasses_drop_guard() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_user_edit_test_{}", std::process::id()));
        let config = FilteringConfig {
            custom_rules: vec![
                "0.0.0.0 ad1.com\n0.0.0.0 ad2.com\n0.0.0.0 ad3.com\n0.0.0.0 ad4.com\n0.0.0.0 ad5.com\n0.0.0.0 ad6.com".to_string(),
            ],
            ..Default::default()
        };

        let engine = HostsFilterEngine::init(config.clone(), temp_dir.clone()).await;
        assert_eq!(engine.rule_count(), 6);

        // User intentionally removes rules via reload_with_config
        let mut new_config = config.clone();
        new_config.custom_rules = vec!["0.0.0.0 ad1.com".to_string()];
        let count = engine.reload_with_config(&new_config).await.unwrap();
        assert_eq!(count, 1);
        assert_eq!(engine.rule_count(), 1);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_compile_error_retains_existing_snapshot() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_join_err_test_{}", std::process::id()));
        let config = FilteringConfig {
            custom_rules: vec!["0.0.0.0 ad1.com".to_string(), "0.0.0.0 ad2.com".to_string()],
            ..Default::default()
        };

        let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
        assert_eq!(engine.rule_count(), 2);

        // Verify CompileTaskFailed error variant can be formatted and matches
        let err = FilterError::CompileTaskFailed("task panicked".to_string());
        assert!(matches!(err, FilterError::CompileTaskFailed(_)));
        assert_eq!(engine.rule_count(), 2);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_important_allowlist_evaluated_as_allow() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_important_test_{}", std::process::id()));
        let config = FilteringConfig {
            custom_rules: vec![
                "@@||ads.example.com^$important".to_string(),
                "||ads.example.com^".to_string(),
            ],
            ..Default::default()
        };
        let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
        let qname = Name::from_str("ads.example.com.").unwrap();
        let client = ClientContext::new(std::net::IpAddr::from_str("192.168.1.20").unwrap());

        // The important allow must win over the standard block.
        assert!(matches!(
            engine.evaluate_important(&qname, RecordType::A, &client),
            Some(Verdict::Allow(_))
        ));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[test]
    fn test_per_list_refresh_schedule() {
        let config = FilteringConfig {
            refresh_interval_hours: 24,
            lists: vec![
                FilterListConfig {
                    name: "fast".to_string(),
                    url: "https://example.com/fast.txt".to_string(),
                    enabled: true,
                    refresh_hours: Some(1),
                },
                FilterListConfig {
                    name: "slow".to_string(),
                    url: "https://example.com/slow.txt".to_string(),
                    enabled: true,
                    refresh_hours: None,
                },
                FilterListConfig {
                    name: "off".to_string(),
                    url: "https://example.com/off.txt".to_string(),
                    enabled: false,
                    refresh_hours: Some(1),
                },
            ],
            ..Default::default()
        };

        let mut next_due = FnvHashMap::default();
        let now = Instant::now();
        let (sleep_for, due) = refresh_schedule(&config, &mut next_due, now);
        assert!(due.is_empty());
        assert_eq!(
            sleep_for,
            Duration::from_secs(3600),
            "the 1h list must be the earliest wake-up"
        );

        // One hour later only the fast list is due.
        let later = now + Duration::from_secs(3601);
        let (_sleep, due) = refresh_schedule(&config, &mut next_due, later);
        assert_eq!(due, vec!["fast".to_string()]);

        // Disabled lists are never scheduled.
        assert!(!next_due.contains_key("off"));
        assert!(next_due.contains_key("slow"));
    }

    #[tokio::test]
    async fn test_idn_punycode_queries_match_ascii_rules() {
        let temp_dir = std::env::temp_dir().join(format!("sito_idn_test_{}", std::process::id()));
        let config = FilteringConfig {
            custom_rules: vec!["||xn--mnchen-3ya.de^".to_string()],
            ..Default::default()
        };
        let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());

        // `Name::from_utf8` stores IDNA labels; the engine must evaluate the
        // ASCII/punycode form, not the decoded Unicode form.
        let idn = Name::from_utf8("münchen.de.").unwrap();
        assert!(
            idn.to_utf8().contains("münchen"),
            "test precondition: the name must carry IDNA labels"
        );
        assert!(
            engine.evaluate(&idn, RecordType::A, &client).is_blocked(),
            "IDN query must not bypass the ASCII punycode rule"
        );

        // The punycode form matches directly as well.
        let ascii = Name::from_str("xn--mnchen-3ya.de.").unwrap();
        assert!(engine.evaluate(&ascii, RecordType::A, &client).is_blocked());

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_cross_list_precedence_is_deterministic() {
        let temp_dir = std::env::temp_dir().join(format!("sito_order_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let a_path = temp_dir.join("a-list.txt");
        let b_path = temp_dir.join("b-list.txt");
        tokio::fs::write(&a_path, "||same.example^\n")
            .await
            .unwrap();
        tokio::fs::write(&b_path, "||same.example^\n")
            .await
            .unwrap();

        // "b-list" is configured first but "a-list" must win (sorted by name)
        // regardless of configuration or hash-map iteration order.
        let config = FilteringConfig {
            lists: vec![
                FilterListConfig {
                    name: "b-list".to_string(),
                    url: format!("file://{}", b_path.display()),
                    enabled: true,
                    refresh_hours: None,
                },
                FilterListConfig {
                    name: "a-list".to_string(),
                    url: format!("file://{}", a_path.display()),
                    enabled: true,
                    refresh_hours: None,
                },
            ],
            ..Default::default()
        };

        let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let qname = Name::from_str("same.example.").unwrap();

        let source =
            |engine: &HostsFilterEngine| match engine.evaluate(&qname, RecordType::A, &client) {
                Verdict::Block(BlockReason::Rule(rule)) => rule.list_name.clone(),
                other => panic!("expected rule block, got {other:?}"),
            };
        assert_eq!(source(&engine).as_deref(), Some("a-list"));

        // Recompiling must not change the winner.
        engine.reload().await.unwrap();
        assert_eq!(source(&engine).as_deref(), Some("a-list"));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_drop_guard_keeps_last_remaining_rule() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_drop_single_test_{}", std::process::id()));
        let config = FilteringConfig {
            custom_rules: vec!["0.0.0.0 only.com".to_string()],
            ..Default::default()
        };
        let engine = HostsFilterEngine::init(config.clone(), temp_dir.clone()).await;
        assert_eq!(engine.rule_count(), 1);

        // Dropping the last rule is a 100% loss and must be guarded.
        let mut dropped = config;
        dropped.custom_rules.clear();
        engine.config.store(Arc::new(dropped));
        let count = engine.reload().await.unwrap();
        assert_eq!(count, 1, "the last rule must survive the drop guard");
        assert_eq!(engine.rule_count(), 1);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_all_list_failure_is_observable_and_not_advertised_ready() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_all_fail_test_{}", std::process::id()));
        let config = FilteringConfig {
            lists: vec![FilterListConfig {
                name: "dead".to_string(),
                url: "http://127.0.0.1:1/list.txt".to_string(),
                enabled: true,
                refresh_hours: None,
            }],
            ..Default::default()
        };
        let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;

        assert_eq!(engine.state(), FilterState::Failed);
        let status = engine.status();
        assert_eq!(status.failed_lists, vec!["dead".to_string()]);
        assert!(status.last_error.is_some());
        assert_eq!(engine.rule_count(), 0);
        assert!(
            engine.reload().await.is_err(),
            "an enabled engine with zero loadable sources must not report success"
        );

        // A later successful reload transitions back to Ready.
        let good = FilteringConfig {
            custom_rules: vec!["0.0.0.0 ok.example".to_string()],
            ..Default::default()
        };
        engine.reload_with_config(&good).await.unwrap();
        assert_eq!(engine.state(), FilterState::Ready);
        assert_eq!(engine.rule_count(), 1);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_reload_retains_rules_from_failed_lists() {
        let temp_dir = std::env::temp_dir().join(format!("sito_merge_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let a_path = temp_dir.join("a.txt");
        let b_path = temp_dir.join("b.txt");
        tokio::fs::write(&a_path, "||a-blocked.example^\n")
            .await
            .unwrap();
        tokio::fs::write(&b_path, "||b-blocked.example^\n")
            .await
            .unwrap();

        let config = FilteringConfig {
            lists: vec![
                FilterListConfig {
                    name: "a".to_string(),
                    url: format!("file://{}", a_path.display()),
                    enabled: true,
                    refresh_hours: None,
                },
                FilterListConfig {
                    name: "b".to_string(),
                    url: format!("file://{}", b_path.display()),
                    enabled: true,
                    refresh_hours: None,
                },
            ],
            ..Default::default()
        };
        let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
        assert_eq!(engine.rule_count(), 2);

        // b's source disappears; a full reload must merge (keep b's last good
        // rules) instead of overwriting the map with only the fetched list.
        tokio::fs::remove_file(&b_path).await.unwrap();
        let count = engine.reload().await.unwrap();
        assert_eq!(count, 2, "rules from the failed list must be retained");
        assert_eq!(engine.rule_count(), 2);
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        assert!(
            engine
                .evaluate(
                    &Name::from_str("b-blocked.example.").unwrap(),
                    RecordType::A,
                    &client
                )
                .is_blocked()
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_concurrent_reloads_do_not_lose_lists() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_concurrent_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let a_path = temp_dir.join("a.txt");
        let b_path = temp_dir.join("b.txt");
        tokio::fs::write(&a_path, "||a-one.example^\n||a-two.example^\n")
            .await
            .unwrap();
        tokio::fs::write(
            &b_path,
            "||b-one.example^\n||b-two.example^\n||b-three.example^\n",
        )
        .await
        .unwrap();

        let config = FilteringConfig {
            lists: vec![
                FilterListConfig {
                    name: "a".to_string(),
                    url: format!("file://{}", a_path.display()),
                    enabled: true,
                    refresh_hours: None,
                },
                FilterListConfig {
                    name: "b".to_string(),
                    url: format!("file://{}", b_path.display()),
                    enabled: true,
                    refresh_hours: None,
                },
            ],
            ..Default::default()
        };

        let engine = Arc::new(HostsFilterEngine::init(config.clone(), temp_dir.clone()).await);
        assert_eq!(engine.rule_count(), 5);

        let mut handles = Vec::new();
        for _ in 0..4 {
            let partial = engine.clone();
            handles.push(tokio::spawn(async move {
                partial.reload_lists(&["a".to_string()]).await.map(|_| ())
            }));
            let full = engine.clone();
            let cfg = config.clone();
            handles.push(tokio::spawn(async move {
                full.reload_with_config(&cfg).await.map(|_| ())
            }));
        }
        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // The final state must contain both lists; serialization prevents a
        // stale partial reload from overwriting the merged map.
        let count = engine.reload().await.unwrap();
        assert_eq!(count, 5);
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        for domain in ["a-one.example", "b-three.example"] {
            assert!(
                engine
                    .evaluate(
                        &Name::from_str(&format!("{domain}.")).unwrap(),
                        RecordType::A,
                        &client
                    )
                    .is_blocked(),
                "{domain} must remain blocked after concurrent reloads"
            );
        }

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_list_with_excessive_regex_patterns_is_rejected() {
        use std::fmt::Write as _;
        let temp_dir = std::env::temp_dir().join(format!("sito_regex_cap_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let huge_path = temp_dir.join("huge.txt");
        let good_path = temp_dir.join("good.txt");

        let mut huge = String::new();
        for i in 0..=MAX_REGEX_PATTERNS {
            let _ = writeln!(huge, "/^r{i}\\.example$/");
        }
        tokio::fs::write(&huge_path, huge).await.unwrap();
        tokio::fs::write(&good_path, "||good.example^\n")
            .await
            .unwrap();

        let config = FilteringConfig {
            lists: vec![
                FilterListConfig {
                    name: "good".to_string(),
                    url: format!("file://{}", good_path.display()),
                    enabled: true,
                    refresh_hours: None,
                },
                FilterListConfig {
                    name: "huge".to_string(),
                    url: format!("file://{}", huge_path.display()),
                    enabled: true,
                    refresh_hours: None,
                },
            ],
            ..Default::default()
        };

        let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
        let status = engine.status();
        assert_eq!(status.state, FilterState::Ready);
        assert_eq!(status.failed_lists, vec!["huge".to_string()]);
        assert_eq!(engine.rule_count(), 1, "good list still loads");

        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        assert!(
            engine
                .evaluate(
                    &Name::from_str("good.example.").unwrap(),
                    RecordType::A,
                    &client
                )
                .is_blocked()
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
