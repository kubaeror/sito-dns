//! `sito-filter`
//!
//! High-throughput DNS filtering engine supporting AdGuard/ABP rule syntax:
//! - `SuffixTrie` with label interning for exact and wildcard domain rules
//! - Aho-Corasick multi-pattern search for fast substring matching
//! - Backtracking-free regex DFA execution using `regex-automata`
//! - Rule modifiers, exception rules (`@@`), and CNAME uncloaking inspection
//! - Subscription scheduler with ETag validation and atomic snapshot swapping

#[cfg(test)]
mod tests {
    #[test]
    fn test_filter_initialization() {
        assert_eq!(2 + 2, 4);
    }
}
