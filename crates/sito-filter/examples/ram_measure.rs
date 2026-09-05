use sito_filter::engine::FilterSnapshot;
use sito_filter::parser::Rule;
use sito_filter::parser::{Pattern, RuleKind, RuleModifiers};
use std::fs::File;
use std::io::{BufRead, BufReader};

fn get_rss_mb() -> f64 {
    if let Ok(file) = File::open("/proc/self/status") {
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2
                    && let Ok(kb) = parts[1].parse::<f64>()
                {
                    return kb / 1024.0;
                }
            }
        }
    }
    0.0
}

fn main() {
    let rss_before = get_rss_mb();
    println!("Base RSS: {rss_before:.2} MB");

    let count = 300_000;
    println!("Generating {count} synthetic domain rules...");
    let mut rules = Vec::with_capacity(count);
    for i in 0..count {
        let domain = format!("host-{i}.sub-{}.example.com", i % 10000);
        rules.push(Rule {
            kind: RuleKind::Block,
            pattern: Pattern::Domain(domain.clone()),
            modifiers: RuleModifiers::default(),
            source: "synthetic".to_string(),
            line: (i + 1) as u32,
            raw: format!("||{domain}^"),
            canonical: format!("||{domain}^"),
        });
    }

    let rss_rules_vec = get_rss_mb();
    println!(
        "RSS after rule vector allocation: {rss_rules_vec:.2} MB (diff: {:.2} MB)",
        rss_rules_vec - rss_before
    );

    println!("Compiling into FilterSnapshot (SuffixTrie + LabelInterner)...");
    let snapshot = FilterSnapshot::compile(rules);

    let rss_after = get_rss_mb();
    println!("Total Rule count in snapshot: {}", snapshot.rule_count);
    println!("Total Interned labels: {}", snapshot.interner.len());
    println!(
        "Total SuffixTrie nodes: {}",
        snapshot.blocklist.trie.node_count()
    );
    println!(
        "RSS after compilation: {rss_after:.2} MB (Net Snapshot footprint: {:.2} MB)",
        rss_after - rss_rules_vec
    );
    println!("Total Process RSS: {rss_after:.2} MB (Budget target: < 150 MB)");
}
