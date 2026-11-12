//! Thread-safe filter engine facade.
//!
//! The engine keeps one responsibility per sibling module: snapshots,
//! construction, group policies, staged prepare/publish, status, reload, and
//! query evaluation.

//! High-throughput filter engine implementation supporting ABP syntax and multi-structure matching.

use crate::downloader::{DEFAULT_DOWNLOAD_TIMEOUT, ListDownloader};
use crate::error::FilterError;
use crate::parser::{
    DnsRewriteRule, ParseError, ParseLimits, Pattern, Rule, RuleKind, parse_rules_with_limits,
};
use crate::structures::{
    CompileBudget, CompileBudgetExceeded, CompiledRuleSet, LabelInterner, MAX_AC_PATTERN_BYTES,
    MAX_AC_PATTERNS, MAX_PREFIX_PATTERN_BYTES, MAX_PREFIX_PATTERNS, MAX_REGEX_PATTERN_BYTES,
    MAX_REGEX_PATTERNS, RuleSetBuilder,
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

/// Callback receiving the wall-clock duration of each parse+compile attempt.
pub type CompileObserver = Arc<dyn Fn(f64) + Send + Sync>;

/// Callback receiving every new [`FilterStatus`] snapshot (API/metrics sink).
pub type StatusObserver = Arc<dyn Fn(&FilterStatus) + Send + Sync>;

/// Callback receiving the rules published by a scheduled/partial list refresh.
///
/// The server wires it to the runtime snapshot so a background refresh cannot
/// leave queries on an older rule set indefinitely.
pub type SnapshotObserver =
    Arc<dyn Fn(Arc<FilterSnapshot>, Arc<crate::GroupSnapshots>) + Send + Sync>;

/// Lifecycle state of the filter engine's active snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterState {
    /// `filtering.enabled = false`: filtering is intentionally disabled.
    Disabled,
    /// The initial (or first) rule load has not produced a snapshot yet.
    #[default]
    Loading,
    /// A snapshot is active. It is empty only when the operator explicitly
    /// opted into empty lists (`allow_empty_list`).
    Ready,
    /// No usable snapshot is active, or a live apply was rejected while an
    /// older snapshot was retained. Callers distinguish the two with
    /// [`FilterStatus::unavailable`].
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
    /// Names of configured lists that failed to load, yielded no rules, or
    /// were rejected by the parse/pattern budgets in the last reload.
    pub failed_lists: Vec<String>,
    /// Most recent reload error, if any.
    pub last_error: Option<String>,
    /// Wall-clock duration of the last parse+compile attempt in milliseconds,
    /// set on success and failure.
    pub last_compile_ms: Option<u64>,
    /// True when no usable snapshot is active (fail-closed mode answers
    /// SERVFAIL). Mirrors [`FilterSnapshot::unavailable`] for observers that
    /// cannot read the snapshot directly.
    pub unavailable: bool,
    /// Regex/wildcard patterns dropped from the active snapshot because they
    /// could not be compiled.
    pub dropped_regex_patterns: usize,
    /// Groups whose snapshot was published without part of its rule class
    /// (regex/wildcard or substring/prefix) after a budget/limit failure.
    pub degraded_groups: Vec<String>,
    /// Lists whose newest content was rejected (parse/limit/empty) while a
    /// previous snapshot was retained.
    pub degraded_lists: Vec<String>,
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

mod construction;
mod evaluation;
mod groups;
mod prepare;
mod reload;
mod snapshot;
mod status;

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
///
/// Only the bare `@@...$dnsrewrite` form cancels everything. An explicit
/// `$dnsrewrite=NOERROR` is a NODATA rewrite and cancels only an identical one.
fn cancels_all(rule: &DnsRewriteRule) -> bool {
    rule.bare
}

/// Compares two rewrite rules for cancellation purposes.
///
/// `A`/`AAAA` values compare as parsed addresses, domain-valued types compare
/// after normalization, and TXT data compares byte-for-byte.
fn same_rewrite(a: &DnsRewriteRule, b: &DnsRewriteRule) -> bool {
    if a.bare != b.bare {
        return false;
    }
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
/// Cancellations are applied in rule order; a later bare cancellation clears
/// everything collected so far, matching AdGuard's "unblock all DNS rewrite
/// rules" exception. Identical values contributed by several lists are emitted
/// once.
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

/// Returns a reason when a parsed list's Aho-Corasick, prefix or regex load
/// exceeds the per-set compilation limits; the list must then be rejected
/// instead of letting a hostile list consume unbounded compile resources.
fn pattern_load_exceeds_limits(rules: &[Rule]) -> Option<String> {
    let mut regex_count = 0usize;
    let mut regex_bytes = 0usize;
    let mut ac_count = 0usize;
    let mut ac_bytes = 0usize;
    let mut prefix_count = 0usize;
    let mut prefix_bytes = 0usize;
    for rule in rules {
        match &rule.pattern {
            Pattern::Regex(pattern) => {
                regex_count += 1;
                regex_bytes += pattern.len();
            }
            Pattern::Wildcard(pattern) => {
                regex_count += 1;
                // Count the expanded regex size so the engine-side limit
                // matches what the DFA builder would have to compile.
                regex_bytes += crate::structures::wildcard_to_regex(pattern).len();
            }
            Pattern::Substring(pattern) => {
                ac_count += 1;
                ac_bytes += pattern.len();
            }
            Pattern::Prefix(pattern) => {
                prefix_count += 1;
                prefix_bytes += pattern.len();
            }
            _ => {}
        }
    }
    if regex_count > MAX_REGEX_PATTERNS {
        return Some(format!(
            "{regex_count} regex/wildcard patterns exceed the limit of {MAX_REGEX_PATTERNS}"
        ));
    }
    if regex_bytes > MAX_REGEX_PATTERN_BYTES {
        return Some(format!(
            "{regex_bytes} regex/wildcard pattern bytes exceed the limit of {MAX_REGEX_PATTERN_BYTES}"
        ));
    }
    if ac_count > MAX_AC_PATTERNS {
        return Some(format!(
            "{ac_count} substring patterns exceed the limit of {MAX_AC_PATTERNS}"
        ));
    }
    if ac_bytes > MAX_AC_PATTERN_BYTES {
        return Some(format!(
            "{ac_bytes} substring pattern bytes exceed the limit of {MAX_AC_PATTERN_BYTES}"
        ));
    }
    if prefix_count > MAX_PREFIX_PATTERNS {
        return Some(format!(
            "{prefix_count} prefix patterns exceed the limit of {MAX_PREFIX_PATTERNS}"
        ));
    }
    if prefix_bytes > MAX_PREFIX_PATTERN_BYTES {
        return Some(format!(
            "{prefix_bytes} prefix pattern bytes exceed the limit of {MAX_PREFIX_PATTERN_BYTES}"
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

/// Fully staged filter state that is not visible to queries yet.
///
/// Produced by [`HostsFilterEngine::prepare`] and installed by
/// [`HostsFilterEngine::publish_prepared`]. The staging engine holds the
/// engine's reload lock until the prepared value is published or dropped, so a
/// concurrent scheduled refresh cannot interleave between staging and publish.
pub struct PreparedFilterSnapshot {
    /// Compiled global rules for the candidate configuration.
    pub snapshot: Arc<FilterSnapshot>,
    /// Per-group rules compiled against the same candidate.
    pub group_snapshots: Arc<FnvHashMap<String, Arc<FilterSnapshot>>>,
    /// Observable status after the candidate load.
    pub status: FilterStatus,
    /// Filtering configuration the snapshot was compiled from. On a failed
    /// load this is the previous configuration, because the candidate was not
    /// committed.
    pub config: FilteringConfig,
    /// Group definitions the snapshots were compiled for.
    pub group_defs: Vec<GroupRuleSet>,
    /// Staged load error. A failed preparation is not published by the apply
    /// path; the scheduled/API refresh path publishes its status so the
    /// failure is observable.
    pub error: Option<FilterError>,
    /// Held until publish; serializes staging with scheduled refreshes.
    guard: tokio::sync::OwnedMutexGuard<()>,
}

impl std::fmt::Debug for PreparedFilterSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedFilterSnapshot")
            .field("rule_count", &self.snapshot.rule_count)
            .field("state", &self.status.state)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
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
    /// Parsed rules per list, used to refresh individual lists without refetching all.
    list_rules: std::sync::Mutex<FnvHashMap<String, Vec<Rule>>>,
    /// Serializes reload/refresh cycles so concurrent scheduled and API-driven
    /// reloads cannot interleave their list-state reads and writes. Held across
    /// staging and publish so a staged snapshot is never overwritten by a
    /// concurrent scheduled refresh.
    reload_lock: Arc<tokio::sync::Mutex<()>>,
    /// Observability state (loading/ready/failed, per-list failures).
    status: ArcSwap<FilterStatus>,
    /// Group policies to compile extra rule sets for (refreshed on config reload).
    group_defs: ArcSwap<Vec<GroupRuleSet>>,
    /// Compiled per-group rule sets, keyed by group name.
    group_snapshots: ArcSwap<FnvHashMap<String, Arc<FilterSnapshot>>>,
    /// Optional sink for compile durations (wired to the metrics registry by
    /// the server binary; the filter crate cannot depend on sito-stats).
    compile_observer: std::sync::RwLock<Option<CompileObserver>>,
    /// Optional sink for status snapshots (API/metrics observability).
    status_observer: std::sync::RwLock<Option<StatusObserver>>,
    /// Optional sink for the rules published by a list refresh.
    snapshot_observer: std::sync::RwLock<Option<SnapshotObserver>>,
    /// Incremented whenever `list_rules` changes. A group rebuild that started
    /// from an older generation must not publish its stale snapshot.
    list_generation: AtomicU64,
    /// True when `clients.groups.*` contributes non-blank custom rules. The
    /// global `filtering.lists`/`custom_rules` may be empty in a group-only
    /// deployment; that must not mark the engine unavailable or fail every
    /// query closed.
    group_sources_configured: AtomicBool,
}

#[cfg(test)]
mod tests;
