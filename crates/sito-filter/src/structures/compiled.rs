//! Compiled rule set indexing exact, trie, substring, and regex rules.

use super::interner::LabelInterner;
use super::trie::{PrefixTrie, SuffixTrie};
use aho_corasick::{AhoCorasick, MatchKind};
use fnv::FnvHashMap;
use regex_automata::dfa::Automaton;
use regex_automata::dfa::dense::{Builder as DfaBuilder, Config as DfaConfig, DFA};
use regex_automata::{Input, MatchKind as RegexMatchKind, PatternSet};
use std::cell::RefCell;
use tracing::{error, warn};

// Reused pattern-match scratch space for the regex DFA batches: a `PatternSet`
// is sized for the largest batch (`REGEX_BATCH_SIZE`) once per thread and
// cleared before every search, instead of allocating one per query.
thread_local! {
    static REGEX_MATCH_SCRATCH: RefCell<PatternSet> =
        RefCell::new(PatternSet::new(REGEX_BATCH_SIZE));
}

// Test-only count of `PatternSet` (re)allocations on the current thread.
#[cfg(test)]
thread_local! {
    static REGEX_MATCH_SET_ALLOCATIONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// Maximum number of regex/wildcard patterns compiled per rule set.
///
/// A hostile list can otherwise force an unbounded DFA construction. Lists
/// exceeding the limit are rejected by the engine before compilation; the
/// builder enforces the same ceiling as a backstop.
pub const MAX_REGEX_PATTERNS: usize = 10_000;
/// Maximum combined source length (bytes) of regex patterns per rule set.
pub const MAX_REGEX_PATTERN_BYTES: usize = 4 * 1024 * 1024;
/// Maximum length of a single regex pattern source (bytes).
pub const MAX_REGEX_PATTERN_LEN: usize = 16 * 1024;
/// DFA memory ceiling per compiled rule set (10 MB).
pub const MAX_DFA_SIZE_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of regex patterns compiled into a single DFA batch.
///
/// Compilation work for `build_many` grows super-linearly with the pattern
/// count, so the pattern set is partitioned into small batches first; a batch
/// that still cannot be compiled is bisected down to the offending pattern.
pub const REGEX_BATCH_SIZE: usize = 128;
/// Upper bound on the number of compiled DFA batches per rule set.
pub const MAX_REGEX_BATCHES: usize = 512;

/// Builds a bounded regex DFA batch, bisecting on failure so one invalid or
/// oversized pattern cannot drop its neighbours.
fn build_regex_batch(
    patterns: &[String],
    rules: &[Vec<u32>],
    batches: &mut Vec<RegexBatch>,
    dropped: &mut usize,
) {
    if patterns.is_empty() {
        return;
    }
    let make_builder = || {
        let mut builder = DfaBuilder::new();
        builder.configure(
            DfaConfig::new()
                .match_kind(RegexMatchKind::All)
                .dfa_size_limit(Some(MAX_DFA_SIZE_BYTES)),
        );
        builder
    };
    if let Ok(dfa) = make_builder().build_many(patterns) {
        batches.push(RegexBatch {
            dfa,
            pattern_to_rules: rules.to_vec(),
        });
        return;
    }
    if patterns.len() == 1 {
        error!(
            pattern = %patterns[0],
            "Skipping invalid/unsupported regex blocking rule"
        );
        *dropped += 1;
        return;
    }
    let mid = patterns.len() / 2;
    build_regex_batch(&patterns[..mid], &rules[..mid], batches, dropped);
    build_regex_batch(&patterns[mid..], &rules[mid..], batches, dropped);
}

/// Converts an ABP wildcard string into an anchored regex pattern.
pub fn wildcard_to_regex(wildcard: &str) -> String {
    let mut regex = String::from("^");
    for c in wildcard.chars() {
        match c {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(c);
            }
            other => regex.push(other),
        }
    }
    regex.push('$');
    regex
}

/// One bounded batch of regex/wildcard patterns and its dense DFA.
#[derive(Debug, Clone)]
pub struct RegexBatch {
    /// Dense regex DFA for this subset (MatchKind::All).
    pub dfa: DFA<Vec<u32>>,
    /// Maps this batch's pattern index to rule IDs.
    pub pattern_to_rules: Vec<Vec<u32>>,
}

/// Compiled set of patterns belonging to a category (e.g. allowlist or blocklist).
#[derive(Default, Debug, Clone)]
pub struct CompiledRuleSet {
    /// Exact domain matches mapping normalized domain to rule IDs.
    pub exact_rules: FnvHashMap<String, Vec<u32>>,
    /// Suffix trie for domain + subdomains rules.
    pub trie: SuffixTrie,
    /// Aho-Corasick automaton for substring rules.
    pub ac: Option<AhoCorasick>,
    /// Maps AC pattern index to list of rule IDs.
    pub ac_pattern_to_rules: Vec<Vec<u32>>,
    /// Dense regex DFAs compiled in bounded batches. Patterns are partitioned
    /// so one pathological subset cannot stall compilation or disable the
    /// whole regex/wildcard class.
    pub regex_batches: Vec<RegexBatch>,
    /// Regex patterns that could not be compiled (oversized, invalid or over
    /// the global batch budget).
    pub dropped_regex_patterns: usize,
    /// Indexed `|prefix` rules (start-anchored matches).
    pub prefix_trie: PrefixTrie,
}

impl CompiledRuleSet {
    /// Matches `domain` across exact, trie, prefix, substring, and regex structures.
    ///
    /// Matches are collected into `candidates` in order of structural specificity:
    /// exact -> trie -> prefixes -> AC -> regex DFA.
    pub fn collect_candidates(
        &self,
        domain: &str,
        interner: &LabelInterner,
        candidates: &mut Vec<u32>,
    ) {
        // 1. Exact match
        if let Some(rules) = self.exact_rules.get(domain) {
            candidates.extend_from_slice(rules);
        }

        // 2. Suffix trie match (domain + subdomains)
        self.trie.lookup_candidates(domain, interner, candidates);

        // 3. Prefix match (indexed; bounded by the domain length)
        self.prefix_trie.lookup_candidates(domain, candidates);

        // 4. Aho-Corasick substring match.
        //
        // Overlapping iteration is required: with the standard non-overlapping
        // `find_iter`, a match such as `track` embedded in `tracker` (or vice
        // versa) would be silently missed depending on pattern priority.
        if let Some(ac) = &self.ac {
            for mat in ac.find_overlapping_iter(domain) {
                let pat_idx = mat.pattern().as_usize();
                if let Some(rules) = self.ac_pattern_to_rules.get(pat_idx) {
                    candidates.extend_from_slice(rules);
                }
            }
        }

        // 5. Regex DFA match (overlapping, reports every matching pattern).
        // The scratch set is reused across queries instead of allocating one
        // `PatternSet` per batch per query.
        if !self.regex_batches.is_empty() {
            REGEX_MATCH_SCRATCH.with(|cell| {
                let mut patset = cell.borrow_mut();
                for batch in &self.regex_batches {
                    if patset.capacity() < batch.dfa.pattern_len() {
                        #[cfg(test)]
                        REGEX_MATCH_SET_ALLOCATIONS.with(|count| count.set(count.get() + 1));
                        *patset = PatternSet::new(batch.dfa.pattern_len());
                    } else {
                        patset.clear();
                    }
                    if batch
                        .dfa
                        .try_which_overlapping_matches(&Input::new(domain.as_bytes()), &mut patset)
                        .is_ok()
                    {
                        for pat_idx in patset.iter() {
                            if let Some(rules) = batch.pattern_to_rules.get(pat_idx.as_usize()) {
                                candidates.extend_from_slice(rules);
                            }
                        }
                    }
                }
            });
        }
    }

    /// Whether any regex/wildcard pattern is compiled in this rule set.
    #[must_use]
    pub fn has_regex(&self) -> bool {
        !self.regex_batches.is_empty()
    }
}

/// Incremental builder for a `CompiledRuleSet`.
#[derive(Default, Debug)]
pub struct RuleSetBuilder {
    pub exact_rules: FnvHashMap<String, Vec<u32>>,
    pub trie_domains: Vec<(String, u32)>,
    pub prefixes: Vec<(String, u32)>,
    pub substrings: Vec<(String, u32)>,
    pub regexes: Vec<(String, u32)>,
}

impl RuleSetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_exact(&mut self, domain: String, rule_id: u32) {
        self.exact_rules.entry(domain).or_default().push(rule_id);
    }

    pub fn add_domain(&mut self, domain: String, rule_id: u32) {
        self.trie_domains.push((domain, rule_id));
    }

    pub fn add_prefix(&mut self, prefix: String, rule_id: u32) {
        self.prefixes.push((prefix, rule_id));
    }

    pub fn add_substring(&mut self, substring: String, rule_id: u32) {
        self.substrings.push((substring, rule_id));
    }

    pub fn add_regex(&mut self, pattern: String, rule_id: u32) {
        self.regexes.push((pattern, rule_id));
    }

    pub fn add_wildcard(&mut self, wildcard: &str, rule_id: u32) {
        let regex_pat = wildcard_to_regex(wildcard);
        self.regexes.push((regex_pat, rule_id));
    }

    /// Compiles all accumulated patterns into high-throughput lookup structures.
    pub fn build(self, interner: &mut LabelInterner) -> CompiledRuleSet {
        // 1. SuffixTrie
        let mut trie = SuffixTrie::new();
        for (dom, rule_id) in self.trie_domains {
            trie.insert(&dom, rule_id, interner);
        }

        // 2. Prefixes, indexed in a character trie. Candidate precedence is
        // preserved by `lookup_candidates` (matching groups in lowest-rule-id
        // order), so it does not depend on hash iteration order.
        let mut prefix_trie = PrefixTrie::new();
        for (prefix, rule_id) in self.prefixes {
            prefix_trie.insert(&prefix, rule_id);
        }

        // 3. Aho-Corasick for substrings
        let (ac, ac_pattern_to_rules) = if self.substrings.is_empty() {
            (None, Vec::new())
        } else {
            let mut unique_subs: FnvHashMap<String, Vec<u32>> = FnvHashMap::default();
            for (sub, rule_id) in self.substrings {
                unique_subs.entry(sub).or_default().push(rule_id);
            }
            let mut entries: Vec<(String, Vec<u32>)> = unique_subs.into_iter().collect();
            entries.sort_by_key(|(_, rules)| rules.iter().copied().min().unwrap_or(u32::MAX));
            let mut pat_strings = Vec::with_capacity(entries.len());
            let mut pat_to_rules = Vec::with_capacity(entries.len());
            for (sub, rules) in entries {
                pat_strings.push(sub);
                pat_to_rules.push(rules);
            }

            match AhoCorasick::builder()
                .match_kind(MatchKind::Standard)
                .build(&pat_strings)
            {
                Ok(automaton) => (Some(automaton), pat_to_rules),
                Err(e) => {
                    warn!(error = %e, "Failed to build Aho-Corasick automaton for substrings; skipping AC");
                    (None, Vec::new())
                }
            }
        };

        // 4. Regex DFAs, compiled in bounded batches
        let (regex_batches, dropped_regex_patterns) = if self.regexes.is_empty() {
            (Vec::new(), 0)
        } else {
            let mut unique_re: FnvHashMap<String, Vec<u32>> = FnvHashMap::default();
            for (pattern, rule_id) in self.regexes {
                unique_re.entry(pattern).or_default().push(rule_id);
            }
            let mut regex_entries: Vec<(String, Vec<u32>)> = unique_re.into_iter().collect();
            regex_entries.sort_by_key(|(_, rules)| rules.iter().copied().min().unwrap_or(u32::MAX));

            // Drop individual oversized patterns before any compilation so a
            // single pathological pattern cannot consume unbounded resources.
            let mut pat_strings = Vec::with_capacity(regex_entries.len());
            let mut pat_to_rules = Vec::with_capacity(regex_entries.len());
            let mut dropped = 0usize;
            for (pat, rules) in regex_entries {
                if pat.len() > MAX_REGEX_PATTERN_LEN {
                    error!(
                        pattern_bytes = pat.len(),
                        limit = MAX_REGEX_PATTERN_LEN,
                        "Skipping oversized regex blocking rule"
                    );
                    dropped += 1;
                    continue;
                }
                pat_strings.push(pat);
                pat_to_rules.push(rules);
            }

            let total_pattern_bytes: usize = pat_strings.iter().map(String::len).sum();
            if pat_strings.len() > MAX_REGEX_PATTERNS
                || total_pattern_bytes > MAX_REGEX_PATTERN_BYTES
            {
                // Bound total compile work: refuse to build the regex class
                // for this rule set instead of letting a hostile list consume
                // CPU/memory without limit. The rest of the rule set (exact,
                // trie, prefix, substring) remains active.
                error!(
                    patterns = pat_strings.len(),
                    pattern_bytes = total_pattern_bytes,
                    max_patterns = MAX_REGEX_PATTERNS,
                    max_pattern_bytes = MAX_REGEX_PATTERN_BYTES,
                    "Regex rule set exceeds compilation limits; skipping regex and wildcard rules for this set"
                );
                dropped += pat_strings.len();
                (Vec::new(), dropped)
            } else if pat_strings.is_empty() {
                (Vec::new(), dropped)
            } else {
                let mut batches = Vec::new();
                let mut dropped_in_batches = 0usize;
                for (patterns, rules) in pat_strings
                    .chunks(REGEX_BATCH_SIZE)
                    .zip(pat_to_rules.chunks(REGEX_BATCH_SIZE))
                {
                    build_regex_batch(patterns, rules, &mut batches, &mut dropped_in_batches);
                }
                if batches.len() > MAX_REGEX_BATCHES {
                    let extra: usize = batches[MAX_REGEX_BATCHES..]
                        .iter()
                        .map(|batch| batch.pattern_to_rules.len())
                        .sum();
                    error!(
                        batches = batches.len(),
                        limit = MAX_REGEX_BATCHES,
                        "Regex batch budget exceeded; dropping the remaining patterns"
                    );
                    batches.truncate(MAX_REGEX_BATCHES);
                    dropped_in_batches += extra;
                }
                (batches, dropped + dropped_in_batches)
            }
        };

        CompiledRuleSet {
            exact_rules: self.exact_rules,
            trie,
            ac,
            ac_pattern_to_rules,
            regex_batches,
            dropped_regex_patterns,
            prefix_trie,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_to_regex() {
        assert_eq!(
            wildcard_to_regex("bad*.example.com"),
            r"^bad.*\.example\.com$"
        );
        assert_eq!(wildcard_to_regex("*.evil.*"), r"^.*\.evil\..*$");
    }

    #[test]
    fn test_compiled_rule_set_matching() {
        let mut interner = LabelInterner::new();
        let mut builder = RuleSetBuilder::new();

        builder.add_exact("exact.example.com".to_string(), 1);
        builder.add_domain("trie.example.com".to_string(), 2);
        builder.add_prefix("prefix-ad.".to_string(), 3);
        builder.add_substring("adtracker".to_string(), 4);
        builder.add_regex(r"^banner[0-9]+\.com$".to_string(), 5);
        builder.add_wildcard("bad*.net", 6);

        let compiled = builder.build(&mut interner);

        // Exact match
        let mut candidates = Vec::new();
        compiled.collect_candidates("exact.example.com", &interner, &mut candidates);
        assert!(candidates.contains(&1));

        // Subdomain of exact match should NOT match exact rule
        candidates.clear();
        compiled.collect_candidates("sub.exact.example.com", &interner, &mut candidates);
        assert!(!candidates.contains(&1));

        // Trie match (domain + subdomains)
        candidates.clear();
        compiled.collect_candidates("trie.example.com", &interner, &mut candidates);
        assert!(candidates.contains(&2));

        candidates.clear();
        compiled.collect_candidates("sub.trie.example.com", &interner, &mut candidates);
        assert!(candidates.contains(&2));

        // Prefix match
        candidates.clear();
        compiled.collect_candidates("prefix-ad.somewhere.com", &interner, &mut candidates);
        assert!(candidates.contains(&3));

        // Substring match
        candidates.clear();
        compiled.collect_candidates("server-with-adtracker-here.org", &interner, &mut candidates);
        assert!(candidates.contains(&4));

        // Regex match
        candidates.clear();
        compiled.collect_candidates("banner123.com", &interner, &mut candidates);
        assert!(candidates.contains(&5));

        // Wildcard match
        candidates.clear();
        compiled.collect_candidates("badnews.net", &interner, &mut candidates);
        assert!(candidates.contains(&6));

        // Benign non-matching domain
        candidates.clear();
        compiled.collect_candidates("google.com", &interner, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_aho_corasick_collects_overlapping_patterns() {
        let mut interner = LabelInterner::new();
        let mut builder = RuleSetBuilder::new();
        // All three patterns overlap inside "tracker".
        builder.add_substring("track".to_string(), 1);
        builder.add_substring("tracker".to_string(), 2);
        builder.add_substring("rack".to_string(), 3);

        let compiled = builder.build(&mut interner);
        let mut candidates = Vec::new();
        compiled.collect_candidates("tracker.example", &interner, &mut candidates);
        for expected in [1, 2, 3] {
            assert!(
                candidates.contains(&expected),
                "overlapping substring rule {expected} must be collected: {candidates:?}"
            );
        }
    }

    #[test]
    fn test_excessive_regex_patterns_are_capped_without_disabling_other_classes() {
        let mut interner = LabelInterner::new();
        let mut builder = RuleSetBuilder::new();
        builder.add_exact("keep.example".to_string(), 0);
        builder.add_domain("trie.example".to_string(), 1);
        for i in 0..=MAX_REGEX_PATTERNS {
            builder.add_regex(format!("^regex-{i}\\.example$"), i as u32 + 2);
        }

        let compiled = builder.build(&mut interner);
        assert!(
            !compiled.has_regex(),
            "an over-limit regex set must be refused instead of compiled"
        );

        // Other structural classes stay active.
        let mut candidates = Vec::new();
        compiled.collect_candidates("keep.example", &interner, &mut candidates);
        assert!(candidates.contains(&0));
        candidates.clear();
        compiled.collect_candidates("sub.trie.example", &interner, &mut candidates);
        assert!(candidates.contains(&1));
    }

    #[test]
    fn test_single_oversized_regex_is_skipped_but_small_ones_compile() {
        let mut interner = LabelInterner::new();
        let mut builder = RuleSetBuilder::new();
        builder.add_regex("a".repeat(MAX_REGEX_PATTERN_LEN + 1), 1);
        builder.add_regex(r"^ok\.example$".to_string(), 2);

        let compiled = builder.build(&mut interner);
        assert!(compiled.has_regex(), "small regex must still compile");

        let mut candidates = Vec::new();
        compiled.collect_candidates("ok.example", &interner, &mut candidates);
        assert!(candidates.contains(&2));

        // A set where every pattern is oversized must not panic and must not
        // produce a regex class.
        let mut builder = RuleSetBuilder::new();
        builder.add_regex("b".repeat(MAX_REGEX_PATTERN_LEN + 1), 3);
        let compiled = builder.build(&mut interner);
        assert!(!compiled.has_regex());
    }

    #[test]
    fn test_candidate_order_is_deterministic_across_insertion_order() {
        fn build(indices: [usize; 3]) -> (CompiledRuleSet, LabelInterner) {
            let mut interner = LabelInterner::new();
            let mut builder = RuleSetBuilder::new();
            // Three rules with distinct ids that all match "ads.tracker.example".
            let rules: Vec<(&str, u32)> = vec![
                ("ads.", 10),
                ("tracker", 20),
                (r"^ads\.tracker\.example$", 30),
            ];
            // Insert the same rules in the caller-provided order.
            for index in indices {
                match index {
                    0 => builder.add_prefix(rules[0].0.to_string(), rules[0].1),
                    1 => builder.add_substring(rules[1].0.to_string(), rules[1].1),
                    2 => builder.add_regex(rules[2].0.to_string(), rules[2].1),
                    _ => unreachable!(),
                }
            }
            (builder.build(&mut interner), interner)
        }

        let mut results = Vec::new();
        for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]] {
            let (compiled, interner) = build(order);
            let mut candidates = Vec::new();
            compiled.collect_candidates("ads.tracker.example", &interner, &mut candidates);
            assert_eq!(candidates.len(), 3, "all three rules must match");
            results.push(candidates);
        }

        // Precedence may not depend on the hash-map iteration order.
        for candidates in &results {
            assert_eq!(candidates, &results[0]);
        }
        // Within each source the lowest rule id wins first.
        assert_eq!(results[0][0], 10);
    }

    /// Regression (audit 6, WP-3.2): a large but in-limit wildcard set must
    /// compile in bounded time and keep every rule active. Previously the
    /// unified build could take minutes and then silently dropped the whole
    /// regex/wildcard class (allow-all for those rules) while still counting
    /// them as active.
    #[test]
    fn test_pathological_wildcard_set_compiles_in_bounded_batches() {
        let mut interner = LabelInterner::new();
        let mut builder = RuleSetBuilder::new();
        // Three full batches: compilation work per build is bounded by
        // REGEX_BATCH_SIZE instead of growing with the whole pattern set.
        let count = (REGEX_BATCH_SIZE * 3) as u32;
        for i in 0..count {
            builder.add_wildcard(&format!("*.sub{i}.example.com"), i);
        }

        let started = std::time::Instant::now();
        let compiled = builder.build(&mut interner);
        let elapsed = started.elapsed();

        assert!(
            compiled.has_regex(),
            "an in-limit wildcard set must compile, not be dropped wholesale"
        );
        assert_eq!(
            compiled.regex_batches.len(),
            3,
            "patterns must be partitioned into bounded batches"
        );
        assert_eq!(
            compiled.dropped_regex_patterns, 0,
            "no pattern may be silently dropped"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(60),
            "batched compilation must be bounded, took {elapsed:?}"
        );

        // Every rule must still be reachable through matching.
        let mut candidates = Vec::new();
        compiled.collect_candidates("foo.sub7.example.com", &interner, &mut candidates);
        assert!(candidates.contains(&7), "got candidates: {candidates:?}");
        candidates.clear();
        compiled.collect_candidates(
            &format!("foo.sub{}.example.com", count - 1),
            &interner,
            &mut candidates,
        );
        assert!(
            candidates.contains(&(count - 1)),
            "got candidates: {candidates:?}"
        );
    }

    /// Regression (audit 6, WP-3.3): prefix rules were matched with a linear
    /// scan over every configured prefix on each query. Lookup work must be
    /// bounded by the queried domain, not by the prefix count.
    #[test]
    fn test_prefix_lookup_is_indexed_not_linear() {
        use crate::structures::trie::PREFIX_LOOKUP_PROBES;
        use std::sync::atomic::Ordering;

        let mut interner = LabelInterner::new();
        let mut builder = RuleSetBuilder::new();
        for i in 0..10_000u32 {
            builder.add_prefix(format!("adservice-{i}."), i);
        }
        let compiled = builder.build(&mut interner);

        // Matching stays correct for the last configured prefix.
        let mut candidates = Vec::new();
        compiled.collect_candidates("adservice-9999.example.com", &interner, &mut candidates);
        assert!(candidates.contains(&9999), "got candidates: {candidates:?}");
        candidates.clear();
        compiled.collect_candidates("innocent.example.com", &interner, &mut candidates);
        assert!(candidates.is_empty(), "got candidates: {candidates:?}");

        // Work is bounded by the domain length (~26 chars), not by the 10 000
        // prefixes a linear scan would visit.
        PREFIX_LOOKUP_PROBES.store(0, Ordering::Relaxed);
        candidates.clear();
        compiled.collect_candidates("adservice-9999.example.com", &interner, &mut candidates);
        let probes = PREFIX_LOOKUP_PROBES.load(Ordering::Relaxed);
        assert!(
            probes <= 512,
            "prefix lookup must be indexed, but visited {probes} nodes"
        );
    }

    /// Regression (audit 6, WP-3.3): the regex matcher allocated a fresh
    /// `PatternSet` for every batch on every query. The scratch set must be
    /// reused (and cleared between batches and queries).
    #[test]
    fn test_regex_matching_reuses_scratch_pattern_set() {
        let mut interner = LabelInterner::new();
        let mut builder = RuleSetBuilder::new();
        // Two batches, so both the clear path and the first-use path run.
        let count = (REGEX_BATCH_SIZE + 5) as u32;
        for i in 0..count {
            builder.add_regex(format!("^r{i}\\.example$"), i);
        }
        let compiled = builder.build(&mut interner);
        assert_eq!(compiled.regex_batches.len(), 2);
        let last = count - 1;

        // Warm up the thread-local scratch set before measuring.
        let mut candidates = Vec::new();
        compiled.collect_candidates("r0.example", &interner, &mut candidates);

        REGEX_MATCH_SET_ALLOCATIONS.with(|counter| counter.set(0));
        for _ in 0..200 {
            for (domain, expected) in [("r0.example", 0u32), ("r132.example", last)] {
                candidates.clear();
                compiled.collect_candidates(domain, &interner, &mut candidates);
                assert!(
                    candidates.contains(&expected),
                    "{domain}: got candidates {candidates:?}"
                );
            }
        }
        let allocations = REGEX_MATCH_SET_ALLOCATIONS.with(std::cell::Cell::get);
        assert!(
            allocations <= 4,
            "PatternSet scratch space is not reused: {allocations} allocations for 400 queries"
        );
    }

    /// An invalid pattern must only drop itself: its neighbours in the same
    /// batch stay compiled and active.
    #[test]
    fn test_invalid_pattern_drops_only_itself() {
        let mut interner = LabelInterner::new();
        let mut builder = RuleSetBuilder::new();
        builder.add_regex("^valid-one\\.example$".to_string(), 1);
        builder.add_regex("^(".to_string(), 2);
        builder.add_regex("^valid-two\\.example$".to_string(), 3);

        let compiled = builder.build(&mut interner);
        assert!(compiled.has_regex());
        assert_eq!(compiled.dropped_regex_patterns, 1);

        let mut candidates = Vec::new();
        compiled.collect_candidates("valid-one.example", &interner, &mut candidates);
        assert!(candidates.contains(&1));
        candidates.clear();
        compiled.collect_candidates("valid-two.example", &interner, &mut candidates);
        assert!(candidates.contains(&3), "got candidates: {candidates:?}");
    }
}
