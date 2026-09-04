//! Compiled rule set indexing exact, trie, substring, and regex rules.

use super::interner::LabelInterner;
use super::trie::SuffixTrie;
use aho_corasick::{AhoCorasick, MatchKind};
use fnv::FnvHashMap;
use regex_automata::dfa::regex::Regex;
use tracing::warn;

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
    /// Regex DFA for regular expressions and wildcards.
    pub regex: Option<Regex>,
    /// Maps regex pattern index to list of rule IDs.
    pub regex_pattern_to_rules: Vec<Vec<u32>>,
    /// Prefix rules: (prefix, list of rule IDs).
    pub prefixes: Vec<(String, Vec<u32>)>,
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

        // 3. Prefix match
        for (prefix, rules) in &self.prefixes {
            if domain.starts_with(prefix) {
                candidates.extend_from_slice(rules);
            }
        }

        // 4. Aho-Corasick substring match
        if let Some(ac) = &self.ac {
            for mat in ac.find_iter(domain) {
                let pat_idx = mat.pattern().as_usize();
                if let Some(rules) = self.ac_pattern_to_rules.get(pat_idx) {
                    candidates.extend_from_slice(rules);
                }
            }
        }

        // 5. Regex DFA match
        if let Some(re) = &self.regex {
            for mat in re.find_iter(domain.as_bytes()) {
                let pat_idx = mat.pattern().as_usize();
                if let Some(rules) = self.regex_pattern_to_rules.get(pat_idx) {
                    candidates.extend_from_slice(rules);
                }
            }
        }
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

        // 2. Prefixes
        let mut prefix_map: FnvHashMap<String, Vec<u32>> = FnvHashMap::default();
        for (prefix, rule_id) in self.prefixes {
            prefix_map.entry(prefix).or_default().push(rule_id);
        }
        let prefixes: Vec<(String, Vec<u32>)> = prefix_map.into_iter().collect();

        // 3. Aho-Corasick for substrings
        let (ac, ac_pattern_to_rules) = if self.substrings.is_empty() {
            (None, Vec::new())
        } else {
            let mut unique_subs: FnvHashMap<String, Vec<u32>> = FnvHashMap::default();
            for (sub, rule_id) in self.substrings {
                unique_subs.entry(sub).or_default().push(rule_id);
            }
            let mut pat_strings = Vec::with_capacity(unique_subs.len());
            let mut pat_to_rules = Vec::with_capacity(unique_subs.len());
            for (sub, rules) in unique_subs {
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

        // 4. Regex DFA
        let (regex, regex_pattern_to_rules) = if self.regexes.is_empty() {
            (None, Vec::new())
        } else {
            if self.regexes.len() > 5000 {
                warn!(
                    count = self.regexes.len(),
                    "Compiling >5000 regexes into unified DFA; this may take extra compilation time"
                );
            }

            let mut unique_re: FnvHashMap<String, Vec<u32>> = FnvHashMap::default();
            for (pattern, rule_id) in self.regexes {
                unique_re.entry(pattern).or_default().push(rule_id);
            }
            let mut pat_strings = Vec::with_capacity(unique_re.len());
            let mut pat_to_rules = Vec::with_capacity(unique_re.len());
            for (pat, rules) in unique_re {
                pat_strings.push(pat);
                pat_to_rules.push(rules);
            }

            match Regex::new_many(&pat_strings) {
                Ok(re) => (Some(re), pat_to_rules),
                Err(e) => {
                    warn!(error = %e, "Failed to compile regex DFA; skipping regex matcher");
                    (None, Vec::new())
                }
            }
        };

        CompiledRuleSet {
            exact_rules: self.exact_rules,
            trie,
            ac,
            ac_pattern_to_rules,
            regex,
            regex_pattern_to_rules,
            prefixes,
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
}
