//! Suffix trie indexing reversed domain labels for high-throughput subdomain matching.

use super::interner::LabelInterner;

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
