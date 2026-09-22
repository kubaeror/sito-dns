//! Suffix and prefix tries for high-throughput domain matching.

use super::interner::LabelInterner;
use fnv::FnvHashMap;

/// Test-only count of trie nodes visited by [`PrefixTrie::lookup_candidates`].
///
/// Used by the indexed-lookup regression test; a linear scan over the same
/// rule set visits one node per configured prefix instead of per domain
/// character.
#[cfg(test)]
pub(crate) static PREFIX_LOOKUP_PROBES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// A single node in the prefix trie.
#[derive(Default, Debug, Clone)]
struct PrefixNode {
    /// Children keyed by the next character of the prefix.
    children: FnvHashMap<char, u32>,
    /// Rule IDs whose prefix terminates at this node.
    rule_ids: Vec<u32>,
}

/// A character trie matching ABP start-anchored (`|prefix`) rules.
///
/// Lookup walks the query domain once and collects every configured prefix
/// that matches it, so per-query work is bounded by the domain length instead
/// of the number of configured prefix rules.
#[derive(Debug, Clone)]
pub struct PrefixTrie {
    nodes: Vec<PrefixNode>,
}

impl Default for PrefixTrie {
    fn default() -> Self {
        Self {
            nodes: vec![PrefixNode::default()],
        }
    }
}

impl PrefixTrie {
    /// Creates a new empty `PrefixTrie` with a root node.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a prefix pattern, associating it with `rule_id`.
    pub fn insert(&mut self, prefix: &str, rule_id: u32) {
        if prefix.is_empty() {
            return;
        }
        let mut node_idx = 0usize;
        for c in prefix.chars() {
            let next = if let Some(&idx) = self.nodes[node_idx].children.get(&c) {
                idx as usize
            } else {
                let idx = self.nodes.len() as u32;
                self.nodes.push(PrefixNode::default());
                self.nodes[node_idx].children.insert(c, idx);
                idx as usize
            };
            node_idx = next;
        }
        self.nodes[node_idx].rule_ids.push(rule_id);
    }

    /// Appends the rule IDs of every prefix that `domain` starts with.
    ///
    /// Matching groups are appended in ascending "lowest rule id" order
    /// (ties cannot occur: every rule id belongs to exactly one prefix), which
    /// preserves the candidate precedence of the previous linear scan.
    pub fn lookup_candidates(&self, domain: &str, candidates: &mut Vec<u32>) {
        if self.nodes.len() == 1 {
            return;
        }

        let mut matched: Vec<&Vec<u32>> = Vec::new();
        let mut node_idx = 0usize;
        for c in domain.chars() {
            #[cfg(test)]
            PREFIX_LOOKUP_PROBES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            let Some(&next) = self.nodes[node_idx].children.get(&c) else {
                break;
            };
            node_idx = next as usize;
            if !self.nodes[node_idx].rule_ids.is_empty() {
                matched.push(&self.nodes[node_idx].rule_ids);
            }
        }

        if matched.len() > 1 {
            matched.sort_by_key(|rules| rules.iter().copied().min().unwrap_or(u32::MAX));
        }
        for rules in matched {
            candidates.extend_from_slice(rules);
        }
    }
}

/// A single node in the suffix trie.
#[derive(Default, Debug, Clone)]
pub struct TrieNode {
    /// Children sorted by `label_id` for binary search: `(label_id, child_node_idx)`.
    pub children: Vec<(u32, u32)>,
    /// Rule IDs terminating at this node (matching this domain and all subdomains).
    pub rule_ids: Vec<u32>,
}

/// Suffix trie matching reversed domain labels.
///
/// Traversal walks from TLD to specific subdomain (e.g. `com` -> `example` -> `ads`).
/// Any terminal rule encountered along the path matches the query domain.
#[derive(Debug, Clone)]
pub struct SuffixTrie {
    pub nodes: Vec<TrieNode>,
}

impl Default for SuffixTrie {
    fn default() -> Self {
        Self {
            nodes: vec![TrieNode::default()],
        }
    }
}

impl SuffixTrie {
    /// Creates a new empty `SuffixTrie` with a root node.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a domain pattern into the trie, associating it with `rule_id`.
    ///
    /// Labels are interned into `interner` and reversed during insertion.
    pub fn insert(&mut self, domain: &str, rule_id: u32, interner: &mut LabelInterner) {
        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if clean.is_empty() {
            return;
        }

        let labels: Vec<&str> = clean.split('.').rev().collect();
        let mut node_idx = 0;

        for label in labels {
            let label_id = interner.intern(label);
            let child_idx = match self.nodes[node_idx]
                .children
                .binary_search_by_key(&label_id, |&(l, _)| l)
            {
                Ok(pos) => self.nodes[node_idx].children[pos].1 as usize,
                Err(insert_pos) => {
                    let next_node_idx = self.nodes.len() as u32;
                    self.nodes.push(TrieNode::default());
                    self.nodes[node_idx]
                        .children
                        .insert(insert_pos, (label_id, next_node_idx));
                    next_node_idx as usize
                }
            };
            node_idx = child_idx;
        }

        self.nodes[node_idx].rule_ids.push(rule_id);
    }

    /// Matches a domain against the suffix trie, appending all matching rule IDs to `candidates`.
    pub fn lookup_candidates(
        &self,
        domain: &str,
        interner: &LabelInterner,
        candidates: &mut Vec<u32>,
    ) {
        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if clean.is_empty() {
            return;
        }

        let labels: Vec<&str> = clean.split('.').rev().collect();
        let mut node_idx = 0;

        for label in labels {
            let Some(label_id) = interner.lookup(label) else {
                return;
            };

            let Ok(pos) = self.nodes[node_idx]
                .children
                .binary_search_by_key(&label_id, |&(l, _)| l)
            else {
                return;
            };

            node_idx = self.nodes[node_idx].children[pos].1 as usize;
            if !self.nodes[node_idx].rule_ids.is_empty() {
                candidates.extend_from_slice(&self.nodes[node_idx].rule_ids);
            }
        }
    }

    /// Returns the total number of nodes in the trie.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_trie_matches_all_matching_prefixes_in_rule_id_order() {
        let mut trie = PrefixTrie::new();
        trie.insert("add", 5);
        trie.insert("addtracker", 2);
        trie.insert("ad", 9);
        trie.insert("zz", 1);

        let mut candidates = Vec::new();
        trie.lookup_candidates("addtracker.example", &mut candidates);
        assert_eq!(candidates, vec![2, 5, 9]);

        candidates.clear();
        trie.lookup_candidates("advert.example", &mut candidates);
        assert_eq!(candidates, vec![9]);

        candidates.clear();
        trie.lookup_candidates("nomatch.example", &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_suffix_trie_subdomain_matching() {
        let mut interner = LabelInterner::new();
        let mut trie = SuffixTrie::new();

        trie.insert("example.com", 1, &mut interner);
        trie.insert("ads.example.com", 2, &mut interner);
        trie.insert("evil.org", 3, &mut interner);

        // Exact match on example.com
        let mut candidates = Vec::new();
        trie.lookup_candidates("example.com", &interner, &mut candidates);
        assert_eq!(candidates, vec![1]);

        // Subdomain of example.com
        candidates.clear();
        trie.lookup_candidates("sub.example.com", &interner, &mut candidates);
        assert_eq!(candidates, vec![1]);

        // Specific subdomain ads.example.com hits both rules (1 and 2)
        candidates.clear();
        trie.lookup_candidates("ads.example.com", &interner, &mut candidates);
        assert_eq!(candidates, vec![1, 2]);

        // Subdomain of ads.example.com hits both rules (1 and 2)
        candidates.clear();
        trie.lookup_candidates("tracker.ads.example.com", &interner, &mut candidates);
        assert_eq!(candidates, vec![1, 2]);

        // Unrelated domain
        candidates.clear();
        trie.lookup_candidates("google.com", &interner, &mut candidates);
        assert!(candidates.is_empty());

        // Evil.org
        candidates.clear();
        trie.lookup_candidates("a.b.evil.org", &interner, &mut candidates);
        assert_eq!(candidates, vec![3]);
    }

    #[test]
    fn test_suffix_trie_case_insensitivity_and_trailing_dots() {
        let mut interner = LabelInterner::new();
        let mut trie = SuffixTrie::new();

        trie.insert("Example.COM.", 10, &mut interner);

        let mut candidates = Vec::new();
        trie.lookup_candidates("EXAMPLE.com.", &interner, &mut candidates);
        assert_eq!(candidates, vec![10]);

        candidates.clear();
        trie.lookup_candidates("sub.example.com", &interner, &mut candidates);
        assert_eq!(candidates, vec![10]);
    }
}
