use criterion::{Criterion, criterion_group, criterion_main};
use fnv::FnvHashSet;
use hickory_proto::rr::RecordType;
use sito_core::client::ClientContext;
use sito_filter::engine::FilterSnapshot;
use sito_filter::parser::parse_rules;
use sito_filter::structures::{LabelInterner, SuffixTrie};
use std::hint::black_box;

fn bench_exact_hashset(c: &mut Criterion) {
    let mut set = FnvHashSet::default();
    for i in 0..10_000 {
        set.insert(format!("domain-{i}.example.com"));
    }

    c.bench_function("exact_hashset_hit", |b| {
        b.iter(|| {
            let res = set.contains(black_box("domain-5000.example.com"));
            black_box(res);
        });
    });

    c.bench_function("exact_hashset_miss", |b| {
        b.iter(|| {
            let res = set.contains(black_box("nonexistent.example.org"));
            black_box(res);
        });
    });
}

fn bench_suffix_trie(c: &mut Criterion) {
    let mut interner = LabelInterner::new();
    let mut trie = SuffixTrie::new();

    for i in 0..10_000 {
        let domain = format!("adservice-{i}.network.net");
        trie.insert(&domain, i as u32, &mut interner);
    }

    c.bench_function("suffix_trie_exact_hit", |b| {
        let mut candidates = Vec::with_capacity(8);
        b.iter(|| {
            candidates.clear();
            trie.lookup_candidates(
                black_box("adservice-5000.network.net"),
                &interner,
                &mut candidates,
            );
            black_box(!candidates.is_empty());
        });
    });

    c.bench_function("suffix_trie_subdomain_hit", |b| {
        let mut candidates = Vec::with_capacity(8);
        b.iter(|| {
            candidates.clear();
            trie.lookup_candidates(
                black_box("sub.deep.adservice-5000.network.net"),
                &interner,
                &mut candidates,
            );
            black_box(!candidates.is_empty());
        });
    });

    c.bench_function("suffix_trie_miss", |b| {
        let mut candidates = Vec::with_capacity(8);
        b.iter(|| {
            candidates.clear();
            trie.lookup_candidates(
                black_box("unrelated.domain.com"),
                &interner,
                &mut candidates,
            );
            black_box(!candidates.is_empty());
        });
    });
}

fn bench_filter_snapshot_lookup(c: &mut Criterion) {
    // Build a representative synthetic snapshot of 10,000 rules
    use std::fmt::Write;
    let mut rules_src = String::new();
    for i in 0..8_000 {
        let _ = writeln!(rules_src, "||tracker-{i}.example.org^");
    }
    for i in 0..1_500 {
        let _ = writeln!(rules_src, "0.0.0.0 hosts-bad-{i}.net");
    }
    for i in 0..500 {
        let _ = writeln!(rules_src, "telemetry-token-{i}");
    }
    let _ = writeln!(rules_src, "@@||safe.tracker-100.example.org^");

    let (parsed, _) = parse_rules(&rules_src, "bench");
    let snapshot = FilterSnapshot::compile(parsed);
    let client = ClientContext::new("192.168.1.1".parse().unwrap());

    c.bench_function("snapshot_evaluate_trie_hit", |b| {
        b.iter(|| {
            let v = snapshot.evaluate(
                black_box("sub.tracker-4000.example.org"),
                RecordType::A,
                &client,
            );
            black_box(v);
        });
    });

    c.bench_function("snapshot_evaluate_exact_hit", |b| {
        b.iter(|| {
            let v = snapshot.evaluate(black_box("hosts-bad-750.net"), RecordType::A, &client);
            black_box(v);
        });
    });

    c.bench_function("snapshot_evaluate_allowlist_hit", |b| {
        b.iter(|| {
            let v = snapshot.evaluate(
                black_box("safe.tracker-100.example.org"),
                RecordType::A,
                &client,
            );
            black_box(v);
        });
    });

    c.bench_function("snapshot_evaluate_miss", |b| {
        b.iter(|| {
            let v = snapshot.evaluate(
                black_box("completely-innocent-site.org"),
                RecordType::A,
                &client,
            );
            black_box(v);
        });
    });
}

criterion_group!(
    benches,
    bench_exact_hashset,
    bench_suffix_trie,
    bench_filter_snapshot_lookup
);
criterion_main!(benches);
