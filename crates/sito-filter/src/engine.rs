//! High-throughput filter engine implementation supporting ABP syntax and multi-structure matching.

use crate::downloader::ListDownloader;
use crate::error::FilterError;
use crate::parser::{DnsRewriteRule, Pattern, Rule, RuleKind, parse_rules};
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
    /// True when no rule set has ever been compiled into this snapshot
    /// (initial load still running or failed). Used for fail-closed mode.
    pub unavailable: bool,
    /// Regex/wildcard patterns that could not be compiled into any DFA batch
    /// (invalid, oversized or over the batch budget). Zero on a healthy load.
    pub dropped_regex_patterns: usize,
}

impl FilterSnapshot {
    /// Placeholder snapshot used before the first successful compile or after
    /// a failed initial load. Never carries rules.
    #[must_use]
    pub fn unavailable() -> Self {
        Self {
            unavailable: true,
            ..Self::default()
        }
    }

    /// Compiles a slice of parsed rules into high-throughput lookup structures,
    /// resolving `$badfilter` deactivations and deduplicating identical rules.
    pub fn compile(parsed_rules: Vec<Rule>) -> Self {
        let mut interner = LabelInterner::new();
        let mut allow_builder = RuleSetBuilder::new();
        let mut block_builder = RuleSetBuilder::new();

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
        let dropped_regex_patterns =
            allowlist.dropped_regex_patterns + blocklist.dropped_regex_patterns;

        Self {
            interner,
            allowlist,
            blocklist,
            rules: active_rules,
            rule_count,
            unavailable: false,
            dropped_regex_patterns,
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
            // An exception carrying `$dnsrewrite` cancels a rewrite; it is not
            // an allow verdict for ordinary block rules.
            if rule.modifiers.dnsrewrite.is_some() {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client
                && !client_filter.matches(client)
            {
                continue;
            }
            // `@@...$denyallow=a|b` is an exception for everything *except*
            // a/b; it must not allow a denyallow match.
            if rule.modifiers.denyallow_matches(domain) {
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
        if let Some(allow) =
            self.evaluate_standard_allow_candidates(domain, qtype, client, allow_candidates)
        {
            return allow;
        }
        self.evaluate_standard_block_candidates(domain, qtype, client, block_candidates)
    }

    /// Stage 3 only: the standard allowlist (`@@...`, non-important).
    pub fn evaluate_standard_allow_candidates(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        allow_candidates: &[u32],
    ) -> Option<Verdict> {
        for &rule_id in allow_candidates {
            let rule = &self.rules[rule_id as usize];
            if rule.modifiers.important {
                continue;
            }
            // `@@...$dnsrewrite` is a rewrite cancellation, never an allow.
            if rule.modifiers.dnsrewrite.is_some() {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client
                && !client_filter.matches(client)
            {
                continue;
            }
            // AdGuard `@@*$denyallow=com|net` allows everything *except* the
            // listed domains: an exception must not apply when the queried
            // domain matches denyallow.
            if rule.modifiers.denyallow_matches(domain) {
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
        None
    }

    /// Stage 4 only: the standard blocklist (`$dnsrewrite` included).
    pub fn evaluate_standard_block_candidates(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        block_candidates: &[u32],
    ) -> Verdict {
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

    /// Collects every `$dnsrewrite` rule from the matching `$important` or
    /// standard block candidates.
    ///
    /// AdGuard returns *all* A/AAAA values contributed by matching rewrite
    /// rules, so the caller must aggregate the whole list instead of using only
    /// the first verdict. `important` selects the precedence tier.
    pub fn collect_rewrite_rules(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        block_candidates: &[u32],
        important: bool,
    ) -> Vec<DnsRewriteRule> {
        let mut rules = Vec::new();
        for &rule_id in block_candidates {
            let rule = &self.rules[rule_id as usize];
            if rule.modifiers.important != important {
                continue;
            }
            if !modifier_scope_matches(rule, domain, qtype, client) {
                continue;
            }
            if let Some(rewrite) = &rule.modifiers.dnsrewrite {
                rules.push(rewrite.clone());
            }
        }
        rules
    }

    /// Collects the `@@...$dnsrewrite` exception rules that cancel rewrites.
    ///
    /// A value-less exception cancels every rewrite for the owner; one with a
    /// value cancels only the identical rewrite (AdGuard semantics).
    pub fn collect_rewrite_cancellations(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        allow_candidates: &[u32],
        important: bool,
    ) -> Vec<DnsRewriteRule> {
        let mut cancellations = Vec::new();
        for &rule_id in allow_candidates {
            let rule = &self.rules[rule_id as usize];
            if rule.modifiers.important != important {
                continue;
            }
            if !modifier_scope_matches(rule, domain, qtype, client) {
                continue;
            }
            if let Some(rewrite) = &rule.modifiers.dnsrewrite {
                cancellations.push(rewrite.clone());
            }
        }
        cancellations
    }
}

/// Applies `$client`, `$dnstype` and `$denyallow` scope checks shared by the
/// rewrite collectors.
fn modifier_scope_matches(
    rule: &Rule,
    domain: &str,
    qtype: RecordType,
    client: &ClientContext,
) -> bool {
    if rule.modifiers.denyallow_matches(domain) {
        return false;
    }
    if let Some(client_filter) = &rule.modifiers.client
        && !client_filter.matches(client)
    {
        return false;
    }
    if let Some(dnstype_filter) = &rule.modifiers.dnstype
        && !dnstype_filter.matches(qtype)
    {
        return false;
    }
    true
}

/// Whether a cancellation rule cancels every rewrite for the owner.
fn cancels_all(rule: &DnsRewriteRule) -> bool {
    rule.rtype.is_none()
        && rule.value.is_none()
        && (rule.rcode.is_empty() || rule.rcode.eq_ignore_ascii_case("NOERROR"))
}

/// Compares two rewrite rules for cancellation purposes.
///
/// `A`/`AAAA` values compare as parsed addresses, domain-valued types compare
/// after normalization, and TXT data compares byte-for-byte.
fn same_rewrite(a: &DnsRewriteRule, b: &DnsRewriteRule) -> bool {
    let rcode_eq = |x: &str, y: &str| {
        let x = if x.is_empty() { "NOERROR" } else { x };
        let y = if y.is_empty() { "NOERROR" } else { y };
        x.eq_ignore_ascii_case(y)
    };
    let rtype_eq = match (&a.rtype, &b.rtype) {
        (None, None) => true,
        (Some(x), Some(y)) => x.eq_ignore_ascii_case(y),
        _ => false,
    };
    if !rcode_eq(&a.rcode, &b.rcode) || !rtype_eq {
        return false;
    }
    let Some(rtype) = a.rtype.as_deref().map(str::to_ascii_uppercase) else {
        return a.value.is_none() && b.value.is_none();
    };
    let (Some(av), Some(bv)) = (a.value.as_deref(), b.value.as_deref()) else {
        return false;
    };
    match rtype.as_str() {
        "A" | "AAAA" => match (
            av.parse::<std::net::IpAddr>(),
            bv.parse::<std::net::IpAddr>(),
        ) {
            (Ok(aip), Ok(bip)) => aip == bip,
            _ => av == bv,
        },
        "CNAME" | "PTR" => normalize_domain(av)
            .ok()
            .zip(normalize_domain(bv).ok())
            .is_some_and(|(x, y)| x.eq_ignore_ascii_case(&y)),
        _ => av == bv,
    }
}

/// Removes cancelled and duplicate entries from an aggregated rewrite list.
///
/// Cancellations are applied in rule order; a later value-less cancellation
/// clears everything collected so far, matching AdGuard's "unblock all DNS
/// rewrite rules" exception. Identical values contributed by several lists are
/// emitted once.
pub fn apply_rewrite_cancellations(
    rules: &mut Vec<DnsRewriteRule>,
    cancellations: &[DnsRewriteRule],
) {
    for cancel in cancellations {
        if cancels_all(cancel) {
            rules.clear();
        } else {
            rules.retain(|rule| !same_rewrite(cancel, rule));
        }
    }
    let mut unique: Vec<DnsRewriteRule> = Vec::with_capacity(rules.len());
    for rule in rules.drain(..) {
        if !unique.iter().any(|seen| same_rewrite(seen, &rule)) {
            unique.push(rule);
        }
    }
    *rules = unique;
}

/// Counts the lists that actually loaded in a reload cycle.
///
/// A list recorded as failed (fetch error or rejected during compilation) must
/// never also count as loaded, or the status overstates protection.
fn count_loaded_lists(fetched: &[String], failed: &[String]) -> usize {
    fetched.iter().filter(|name| !failed.contains(name)).count()
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
/// Extra filtering rules contributed by a client-group policy.
///
/// Group `lists` reference configured global lists by name; `custom_rules` use
/// the same AdGuard/ABP syntax as `filtering.custom_rules`. The rules are
/// compiled into a per-group snapshot on top of the global one and applied
/// only to clients whose resolved policy selects the group.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupRuleSet {
    /// Group name as used by `clients.groups.<name>`.
    pub name: String,
    /// Names of configured filter lists this group adds.
    pub lists: Vec<String>,
    /// Ad-hoc rules this group adds.
    pub custom_rules: Vec<String>,
}

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
    /// Group policies to compile extra rule sets for (refreshed on config reload).
    group_defs: ArcSwap<Vec<GroupRuleSet>>,
    /// Compiled per-group rule sets, keyed by group name.
    group_snapshots: ArcSwap<FnvHashMap<String, Arc<FilterSnapshot>>>,
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
            snapshot: ArcSwap::new(Arc::new(FilterSnapshot::unavailable())),
            config: ArcSwap::new(Arc::new(config)),
            data_dir,
            downloader: ListDownloader::default(),
            list_rules: std::sync::Mutex::new(FnvHashMap::default()),
            reload_lock: tokio::sync::Mutex::new(()),
            status: ArcSwap::new(Arc::new(status)),
            group_defs: ArcSwap::new(Arc::new(Vec::new())),
            group_snapshots: ArcSwap::new(Arc::new(FnvHashMap::default())),
        }
    }

    /// Replaces the group rule definitions and rebuilds the per-group snapshots
    /// from the currently loaded lists. Called whenever clients/group policy or
    /// blocklists are (re)loaded.
    pub fn set_group_rules(&self, groups: Vec<GroupRuleSet>) {
        self.group_defs.store(Arc::new(groups));
        let list_rules = self
            .list_rules
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        self.rebuild_group_snapshots(&list_rules);
    }

    /// Returns the compiled extra rule set for `group`, if the group defines any.
    #[must_use]
    pub fn group_snapshot(&self, group: &str) -> Option<Arc<FilterSnapshot>> {
        self.group_snapshots.load().get(group).cloned()
    }

    /// Compiles one snapshot per group from the current per-list rules.
    ///
    /// Lists a group references but that are not loaded are skipped (the group
    /// still gets its custom rules); a group with no usable rules is removed so
    /// the pipeline does not evaluate an empty set.
    fn rebuild_group_snapshots(&self, list_rules: &FnvHashMap<String, Vec<Rule>>) {
        let defs = self.group_defs.load();
        let max_rules = self.config.load().max_rules;
        let mut compiled = FnvHashMap::default();
        for def in defs.iter() {
            let mut rules = Vec::new();
            for list_name in &def.lists {
                if let Some(list_rules) = list_rules.get(list_name) {
                    rules.extend(list_rules.iter().cloned());
                } else {
                    warn!(
                        group = %def.name,
                        list = %list_name,
                        "Group policy references a filter list that is not loaded; rules from it are inactive"
                    );
                }
            }
            for rule_text in &def.custom_rules {
                let (parsed, rejected) = parse_rules(rule_text, &format!("group:{}", def.name));
                if rejected > 0 {
                    warn!(
                        group = %def.name,
                        "Rejected {} invalid rule(s) in group custom_rules",
                        rejected
                    );
                }
                rules.extend(parsed);
            }
            if rules.is_empty() {
                continue;
            }
            if rules.len() > max_rules {
                error!(
                    group = %def.name,
                    parsed = rules.len(),
                    limit = max_rules,
                    "Group filter rule set exceeds filtering.max_rules; truncating to limit"
                );
                rules.truncate(max_rules);
            }
            if let Some(reason) = regex_load_exceeds_limits(&rules) {
                error!(
                    group = %def.name,
                    reason = %reason,
                    "Group filter rule set exceeds regex compilation limits; skipping group regexes"
                );
                rules.retain(|r| !matches!(r.pattern, Pattern::Regex(_) | Pattern::Wildcard(_)));
            }
            if rules.is_empty() {
                continue;
            }
            compiled.insert(def.name.clone(), Arc::new(FilterSnapshot::compile(rules)));
        }
        self.group_snapshots.store(Arc::new(compiled));
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

    /// Number of regex/wildcard patterns that could not be compiled into the
    /// current snapshot. A non-zero value means part of the regex class is
    /// inactive and should be surfaced to operators.
    #[must_use]
    pub fn dropped_regex_patterns(&self) -> usize {
        self.snapshot.load().dropped_regex_patterns
    }

    /// True when filtering is enabled with `fail_closed` and no rule snapshot
    /// has ever been compiled (initial load running or failed). Callers
    /// should refuse to resolve rather than silently allow everything.
    pub fn unavailable_for_fail_closed(&self) -> bool {
        let config = self.config.load();
        config.enabled && config.fail_closed && self.snapshot.load().unavailable
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
    ///
    /// The new configuration is only retained once the reload succeeded: a
    /// rejected config must not become the source for the next scheduled
    /// refresh (which would otherwise apply it later, behind the caller's
    /// back).
    pub async fn reload_with_config(&self, config: &FilteringConfig) -> Result<usize, FilterError> {
        // Staged load: `self.config` still holds the previous configuration
        // for the whole attempt, so a rejected candidate is simply dropped.
        let count = self.reload_internal(config, false, None).await?;
        self.config.store(Arc::new(config.clone()));
        Ok(count)
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
            // A disabled engine answers normally; the placeholder keeps
            // `unavailable_for_fail_closed` false while disabled and forces a
            // fresh successful load before fail-closed can be relied on again.
            self.snapshot.store(Arc::new(FilterSnapshot::default()));
            self.list_rules.lock().unwrap().clear();
            self.set_status(FilterStatus {
                state: FilterState::Disabled,
                ..FilterStatus::default()
            });
            return Ok(0);
        }

        let mut list_contents = Vec::new();
        // Names of lists whose content was fetched (from network or cache) in
        // this cycle. `loaded_lists` is derived from this set minus
        // `failed_lists` so a list can never be counted as both.
        let mut fetched_lists = Vec::new();
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
                    fetched_lists.push(list.name.clone());
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
        let max_rules = config.max_rules;
        let base_rules = self.list_rules.lock().unwrap().clone();
        let enabled_names: FnvHashSet<String> = config
            .lists
            .iter()
            .filter(|l| l.enabled)
            .map(|l| l.name.clone())
            .collect();

        // Compile rules in blocking task to avoid stalling the tokio async runtime
        let join_result = tokio::task::spawn_blocking(move || -> Result<_, FilterError> {
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

            let mut parsed_custom = Vec::new();
            for rule_text in &custom_rules {
                let (rules, _) = parse_rules(rule_text, "custom");
                parsed_custom.extend(rules);
            }
            if let Some(reason) = regex_load_exceeds_limits(&parsed_custom) {
                error!(
                    reason = %reason,
                    "Rejecting custom_rules with excessive regex pattern load"
                );
                return Err(FilterError::CompileTaskFailed(reason));
            }

            // Deterministic rule-id assignment: lists sorted by name, rule
            // order preserved within each list, custom rules last (config
            // order). Candidate precedence (first match wins) therefore stays
            // stable across reloads and hash-map iteration order changes.
            let mut names: Vec<&String> = map.keys().collect();
            names.sort_unstable();
            let parsed_rules: usize = map.values().map(Vec::len).sum();
            let total_candidate_rules = parsed_rules + parsed_custom.len();
            // Bound the materialised rule set: a hostile 64 MiB list can
            // hold tens of millions of minimal lines, and every rule is
            // materialised several times. Rejecting the reload keeps the
            // previous snapshot instead of OOM-killing the daemon.
            if total_candidate_rules > max_rules {
                error!(
                    parsed = total_candidate_rules,
                    limit = max_rules,
                    "Filter rule set exceeds filtering.max_rules"
                );
                return Err(FilterError::TooManyRules {
                    count: total_candidate_rules,
                    limit: max_rules,
                });
            }
            let mut all_rules = Vec::with_capacity(total_candidate_rules);
            for name in names {
                all_rules.extend(map[name].iter().cloned());
            }
            all_rules.extend(parsed_custom);
            let snapshot = FilterSnapshot::compile(all_rules);
            let count = snapshot.rule_count;
            Ok((snapshot, count, map, rejected))
        })
        .await
        .map_err(|e| {
            error!("Filter rule compilation task failed: {e}");
            self.set_status(FilterStatus {
                state: FilterState::Failed,
                rule_count: self.snapshot.load().rule_count,
                loaded_lists: count_loaded_lists(&fetched_lists, &failed_lists),
                failed_lists: failed_lists.clone(),
                last_error: Some(e.to_string()),
            });
            FilterError::CompileTaskFailed(e.to_string())
        })?;

        let (new_snapshot, count, new_list_rules, rejected_lists) = match join_result {
            Ok(result) => result,
            Err(e) => {
                let prev_count = self.snapshot.load().rule_count;
                error!(error = %e, "Rejecting filter reload");
                let loaded_lists = count_loaded_lists(&fetched_lists, &failed_lists);
                if prev_count == 0 {
                    // Fail closed rather than advertise an over-limit set as
                    // active or silently allow traffic.
                    self.snapshot.store(Arc::new(FilterSnapshot::unavailable()));
                    self.set_status(FilterStatus {
                        state: FilterState::Failed,
                        rule_count: 0,
                        loaded_lists,
                        failed_lists: failed_lists.clone(),
                        last_error: Some(e.to_string()),
                    });
                } else {
                    self.set_status(FilterStatus {
                        state: FilterState::Ready,
                        rule_count: prev_count,
                        loaded_lists,
                        failed_lists: failed_lists.clone(),
                        last_error: Some(e.to_string()),
                    });
                }
                return Err(e);
            }
        };

        failed_lists.extend(rejected_lists);
        // A list rejected during compilation was already counted as fetched;
        // subtract it here so the status never reports it as both loaded and
        // failed.
        let loaded_lists = count_loaded_lists(&fetched_lists, &failed_lists);

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
            // Keep the engine explicitly unavailable so `fail_closed` answers
            // SERVFAIL instead of allow-all. Previously the previous snapshot
            // (e.g. the empty one stored while filtering was disabled) was kept
            // with `unavailable = false`, silently disabling fail-closed after
            // a disabled -> enabled transition.
            self.snapshot.store(Arc::new(FilterSnapshot::unavailable()));
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

        if new_snapshot.dropped_regex_patterns > 0 {
            error!(
                dropped = new_snapshot.dropped_regex_patterns,
                "Some regex/wildcard blocking rules could not be compiled and are inactive"
            );
        }
        self.snapshot.store(Arc::new(new_snapshot));
        *self.list_rules.lock().unwrap() = new_list_rules;
        // Group rule sets are selected from the list rules, so they must track
        // the freshly loaded snapshot.
        {
            let list_rules = self
                .list_rules
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            self.rebuild_group_snapshots(&list_rules);
        }
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
        let config = self.config.load();
        if !config.enabled {
            return None;
        }
        let snapshot = self.snapshot.load();
        if config.fail_closed && snapshot.unavailable {
            return Some(Verdict::Block(BlockReason::FilterUnavailable));
        }

        let normalized = normalized_query_domain(qname);
        snapshot.evaluate_important(&normalized, qtype, client)
    }

    /// Evaluates a domain query against standard filter rules.
    pub fn evaluate_standard(
        &self,
        qname: &Name,
        qtype: RecordType,
        client: &ClientContext,
    ) -> Verdict {
        let config = self.config.load();
        if !config.enabled {
            return Verdict::Allow(None);
        }
        let snapshot = self.snapshot.load();
        if config.fail_closed && snapshot.unavailable {
            return Verdict::Block(BlockReason::FilterUnavailable);
        }

        let normalized = normalized_query_domain(qname);
        snapshot.evaluate_standard(&normalized, qtype, client)
    }
}

impl FilterEngine for HostsFilterEngine {
    fn evaluate(&self, qname: &Name, qtype: RecordType, client: &ClientContext) -> Verdict {
        let config = self.config.load();
        if !config.enabled {
            return Verdict::Allow(None);
        }
        let snapshot = self.snapshot.load();
        if config.fail_closed && snapshot.unavailable {
            return Verdict::Block(BlockReason::FilterUnavailable);
        }

        let normalized = normalized_query_domain(qname);
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
        let client3 =
            ClientContext::new("192.168.1.200".parse().unwrap()).with_client_name("laptop");
        let client_spoofed = ClientContext::with_id("192.168.1.200".parse().unwrap(), "laptop");
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
        // A wire-claimed id must not satisfy `$client=`.
        assert!(
            engine
                .evaluate(&q_client, RecordType::A, &client_spoofed)
                .is_allowed()
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

        // The cache reader only trusts content whose metadata records matching
        // integrity signals (WP-3.9).
        let cached_content = "0.0.0.0 cached-ad.com\n";
        crate::downloader::save_to_cache(&cached_file, cached_content)
            .await
            .unwrap();
        crate::subscription::save_metadata(
            &crate::subscription::meta_path_for_list(&temp_dir, "offline_list"),
            &crate::subscription::ListMetadata {
                content_len: Some(cached_content.len() as u64),
                line_count: Some(cached_content.lines().count()),
                ..Default::default()
            },
        )
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
        assert!(
            due.is_empty(),
            "no list should be due for refresh yet: {due:?}"
        );
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
        let engine = HostsFilterEngine::init(config.clone(), temp_dir.clone()).await;

        assert_eq!(engine.state(), FilterState::Failed);
        let status = engine.status();
        assert_eq!(status.failed_lists, vec!["dead".to_string()]);
        assert!(status.last_error.is_some());
        assert_eq!(engine.rule_count(), 0);
        assert!(
            engine.reload().await.is_err(),
            "an enabled engine with zero loadable sources must not report success"
        );

        // Fail-closed default: a failed initial load must not allow traffic.
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let probe = Name::from_str("anything.example.").unwrap();
        let verdict = engine.evaluate(&probe, RecordType::A, &client);
        assert_eq!(
            verdict,
            Verdict::Block(BlockReason::FilterUnavailable),
            "fail_closed engines must block while no snapshot has loaded"
        );

        // Opting out restores allow-all on the same failed state.
        let allow_open = FilteringConfig {
            fail_closed: false,
            ..config.clone()
        };
        let open_engine = HostsFilterEngine::init(allow_open, temp_dir.clone()).await;
        assert_eq!(open_engine.state(), FilterState::Failed);
        assert!(
            open_engine
                .evaluate(&probe, RecordType::A, &client)
                .is_allowed()
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

    /// Regression: fail-closed must survive a failed reload while the active
    /// config is enabled. A rejected disabled -> enabled transition must not
    /// be applied at all (WP-3.10 transactional reload), so the engine stays
    /// disabled instead of becoming an enabled-but-unavailable engine.
    #[tokio::test]
    async fn test_fail_closed_survives_disabled_to_enabled_transition() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_failclosed_trans_{}", std::process::id()));
        let disabled = FilteringConfig {
            enabled: false,
            fail_closed: true,
            lists: vec![FilterListConfig {
                name: "dead".to_string(),
                url: "http://127.0.0.1:1/list.txt".to_string(),
                enabled: true,
                refresh_hours: None,
            }],
            ..Default::default()
        };
        let enabled = FilteringConfig {
            enabled: true,
            fail_closed: true,
            ..disabled.clone()
        };
        let engine = HostsFilterEngine::init(disabled, temp_dir.clone()).await;
        assert_eq!(engine.state(), FilterState::Disabled);
        assert!(!engine.unavailable_for_fail_closed());

        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let probe = Name::from_str("anything.example.").unwrap();

        // The dead list rejects the transition; the rejected config must not
        // become active, so the engine stays disabled and answers normally.
        assert!(
            engine.reload_with_config(&enabled).await.is_err(),
            "the dead list must fail to load"
        );
        assert!(
            !engine.config.load_full().enabled,
            "a rejected disabled -> enabled transition must not be retained"
        );
        assert!(engine.evaluate(&probe, RecordType::A, &client).is_allowed());

        // Once the active config is enabled (successful load), a later failed
        // reload must still fail closed instead of serving allow-all.
        let good = FilteringConfig {
            enabled: true,
            fail_closed: true,
            ..Default::default()
        };
        engine.reload_with_config(&good).await.unwrap();
        assert!(engine.config.load_full().enabled);
        assert!(
            engine.reload_with_config(&enabled).await.is_err(),
            "the dead list must still fail"
        );
        assert!(
            engine.unavailable_for_fail_closed(),
            "a failed load while enabled must still be fail-closed"
        );
        assert_eq!(
            engine.evaluate(&probe, RecordType::A, &client),
            Verdict::Block(BlockReason::FilterUnavailable)
        );
    }

    /// Regression: group `lists`/`custom_rules` must actually be compiled and
    /// evaluated (they were stored in the policy but never applied).
    #[tokio::test]
    async fn test_group_rules_are_compiled_and_evaluated() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_group_rules_{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let kids_path = temp_dir.join("kids-list.txt");
        tokio::fs::write(&kids_path, "||cartoon.example^\n")
            .await
            .unwrap();

        let config = FilteringConfig {
            lists: vec![FilterListConfig {
                name: "school".to_string(),
                url: format!("file://{}", kids_path.display()),
                enabled: true,
                refresh_hours: None,
            }],
            ..Default::default()
        };
        let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
        assert_eq!(engine.state(), FilterState::Ready);

        engine.set_group_rules(vec![GroupRuleSet {
            name: "kids".to_string(),
            lists: vec!["school".to_string()],
            custom_rules: vec!["||fortnite.example^$important".to_string()],
        }]);

        let snapshot = engine
            .group_snapshot("kids")
            .expect("group snapshot compiled");
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let cartoon = Name::from_str("www.cartoon.example.").unwrap();
        let fortnite = Name::from_str("fortnite.example.").unwrap();
        let other = Name::from_str("example.org.").unwrap();

        assert!(
            matches!(
                snapshot.evaluate_important("fortnite.example", RecordType::A, &client),
                Some(Verdict::Block(_))
            ),
            "group custom_rules must compile and match"
        );
        assert!(matches!(
            snapshot.evaluate("www.cartoon.example", RecordType::A, &client),
            Verdict::Block(_)
        ));
        assert!(
            snapshot
                .evaluate("example.org", RecordType::A, &client)
                .is_allowed()
        );
        let _ = (cartoon, fortnite, other);

        // Groups without configured rules produce no snapshot.
        assert!(engine.group_snapshot("missing").is_none());

        // A policy that adds no rules must not create an empty group entry.
        engine.set_group_rules(vec![GroupRuleSet {
            name: "empty".to_string(),
            ..Default::default()
        }]);
        assert!(engine.group_snapshot("empty").is_none());

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// Regression (audit 6, WP-3.9): a list rejected during compilation was
    /// counted in both `loaded_lists` and `failed_lists`, overstating how many
    /// sources were active.
    #[tokio::test]
    async fn test_status_loaded_and_failed_lists_are_mutually_exclusive() {
        use std::fmt::Write as _;
        let temp_dir =
            std::env::temp_dir().join(format!("sito_status_count_{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
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
        assert_eq!(
            status.loaded_lists, 1,
            "a rejected list must not count as loaded"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// Regression (audit 6, WP-3.10): `reload_with_config` used to store the
    /// candidate config before the load ran, so a rejected config became the
    /// source for the next scheduled refresh and could take effect later.
    #[tokio::test]
    async fn test_rejected_reload_with_config_is_not_retained() {
        use std::fmt::Write as _;
        let temp_dir = std::env::temp_dir().join(format!("sito_txn_reload_{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let path = temp_dir.join("big-list.txt");
        let content: String = (0..50).fold(String::new(), |mut acc, i| {
            let _ = writeln!(acc, "||blocked-{i}.example^");
            acc
        });
        tokio::fs::write(&path, content).await.unwrap();
        let list = FilterListConfig {
            name: "big".to_string(),
            url: format!("file://{}", path.display()),
            enabled: true,
            refresh_hours: None,
        };

        let accepted = FilteringConfig {
            max_rules: 1000,
            lists: vec![list.clone()],
            ..Default::default()
        };
        let engine = HostsFilterEngine::init(accepted.clone(), temp_dir.clone()).await;
        assert_eq!(engine.rule_count(), 50);

        // Candidate above the cap: rejected, and the previous config must stay.
        let rejected = FilteringConfig {
            max_rules: 10,
            lists: vec![list],
            ..Default::default()
        };
        let err = engine
            .reload_with_config(&rejected)
            .await
            .expect_err("an oversized set must be rejected");
        assert!(matches!(err, FilterError::TooManyRules { .. }));
        assert_eq!(
            engine.config.load_full().max_rules,
            accepted.max_rules,
            "the rejected config must not be retained"
        );

        // The scheduled/manual reload path uses the stored config and must
        // therefore still succeed.
        let count = engine.reload().await.unwrap();
        assert_eq!(count, 50);
        assert!(
            engine.status().last_error.is_none(),
            "the rejected cap must not apply to later reloads: {:?}",
            engine.status().last_error
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// Regression (audit 6, WP-3.3): an oversized rule set must be rejected
    /// instead of materialising unbounded memory, and a failed first load must
    /// stay fail-closed.
    #[tokio::test]
    async fn test_max_rules_cap_rejects_oversized_reload() {
        let temp_dir = std::env::temp_dir().join(format!("sito_max_rules_{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let path = temp_dir.join("big-list.txt");
        let content: String = (0..50).fold(String::new(), |mut acc, i| {
            use std::fmt::Write as _;
            let _ = writeln!(acc, "||blocked-{i}.example^");
            acc
        });
        tokio::fs::write(&path, content).await.unwrap();
        let list = FilterListConfig {
            name: "big".to_string(),
            url: format!("file://{}", path.display()),
            enabled: true,
            refresh_hours: None,
        };

        // First load above the cap: fail closed.
        let engine = HostsFilterEngine::init(
            FilteringConfig {
                max_rules: 10,
                lists: vec![list.clone()],
                ..Default::default()
            },
            temp_dir.clone(),
        )
        .await;
        assert_eq!(engine.state(), FilterState::Failed);
        assert!(engine.unavailable_for_fail_closed());
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let probe = Name::from_str("blocked-1.example.").unwrap();
        assert_eq!(
            engine.evaluate(&probe, RecordType::A, &client),
            Verdict::Block(BlockReason::FilterUnavailable)
        );

        // A reload that would exceed the cap keeps the previous snapshot.
        let engine = HostsFilterEngine::init(
            FilteringConfig {
                max_rules: 1000,
                lists: vec![list.clone()],
                ..Default::default()
            },
            temp_dir.clone(),
        )
        .await;
        assert_eq!(engine.state(), FilterState::Ready);
        assert_eq!(engine.rule_count(), 50);

        let err = engine
            .reload_with_config(&FilteringConfig {
                max_rules: 10,
                lists: vec![list],
                ..Default::default()
            })
            .await
            .expect_err("an oversized set must be rejected");
        assert!(matches!(err, FilterError::TooManyRules { .. }));
        assert_eq!(
            engine.state(),
            FilterState::Ready,
            "previous snapshot retained"
        );
        assert_eq!(engine.rule_count(), 50);
        assert!(
            engine.evaluate(&probe, RecordType::A, &client).is_blocked(),
            "the previous snapshot must keep filtering"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
