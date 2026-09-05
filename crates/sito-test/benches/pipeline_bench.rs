use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use sito_cache::DnsCache;
use sito_clients::config::ClientsConfig;
use sito_clients::registry::ClientRegistry;
use sito_core::client::ClientContext;
use sito_core::config::CacheConfig;
use sito_core::engine::FilterEngine;
use sito_proto::{decode_message, encode_message};
use sito_rewrites::config::{RewriteEntryConfig, RewritesConfig};
use sito_rewrites::table::RewriteTable;
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::str::FromStr;

fn bench_wire_decode_encode(c: &mut Criterion) {
    let mut query = Message::new(1001, MessageType::Query, OpCode::Query);
    query.queries.push(Query::query(
        Name::from_str("analytics.tracker.example.com.").unwrap(),
        RecordType::A,
    ));
    let wire_bytes = encode_message(&query).unwrap();

    let mut group = c.benchmark_group("wire_proto");
    group.bench_function("decode_message", |b| {
        b.iter(|| {
            let msg = decode_message(black_box(&wire_bytes)).unwrap();
            black_box(msg);
        });
    });

    group.bench_function("encode_message", |b| {
        b.iter(|| {
            let bytes = encode_message(black_box(&query)).unwrap();
            black_box(bytes);
        });
    });
    group.finish();
}

fn bench_cache_lookup(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let cache = DnsCache::new(CacheConfig {
        enabled: true,
        size_mb: 64,
        min_ttl: 60,
        max_ttl: 86400,
        negative_ttl_max: 3600,
        prefetch: false,
        serve_stale_hours: 12,
    });

    let qname = Name::from_str("cached.example.com.").unwrap();
    let mut query = Message::new(1001, MessageType::Query, OpCode::Query);
    query
        .queries
        .push(Query::query(qname.clone(), RecordType::A));

    let record = Record::from_rdata(
        qname.clone(),
        300,
        RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(93, 184, 216, 34))),
    );

    let mut response = Message::new(1001, MessageType::Response, OpCode::Query);
    response.answers.push(record);

    rt.block_on(async {
        cache.insert(&query, &response).await;
    });

    c.bench_function("cache_hit_lookup", |b| {
        b.iter(|| {
            rt.block_on(async {
                let entry = cache
                    .get(
                        black_box(&qname),
                        black_box(RecordType::A),
                        black_box(DNSClass::IN),
                    )
                    .await;
                black_box(entry);
            });
        });
    });
}

fn bench_filter_matching(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let temp_dir = std::env::temp_dir().join(format!("sito_bench_rules_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    // Populate 10,000 ABP rules
    let mut rules = Vec::with_capacity(10_000);
    for i in 0..10_000 {
        rules.push(format!("||adserver{i}.adnetwork.com^"));
    }
    rules.push("||doubleclick.net^".to_string());
    rules.push("@@||allowed.doubleclick.net^".to_string());

    let config = sito_core::config::FilteringConfig {
        custom_rules: rules,
        ..Default::default()
    };

    let engine = rt.block_on(async {
        sito_filter::engine::HostsFilterEngine::init(config, temp_dir.clone()).await
    });

    let qname_blocked = Name::from_str("adserver5000.adnetwork.com.").unwrap();
    let qname_allowed = Name::from_str("safe.example.com.").unwrap();
    let ctx = ClientContext::new("192.168.1.100".parse().unwrap());

    let mut group = c.benchmark_group("filter_engine");
    group.bench_function("evaluate_blocked_domain", |b| {
        b.iter(|| {
            let verdict =
                engine.evaluate(black_box(&qname_blocked), RecordType::A, black_box(&ctx));
            black_box(verdict);
        });
    });

    group.bench_function("evaluate_clean_domain", |b| {
        b.iter(|| {
            let verdict =
                engine.evaluate(black_box(&qname_allowed), RecordType::A, black_box(&ctx));
            black_box(verdict);
        });
    });
    group.finish();

    let _ = std::fs::remove_dir_all(temp_dir);
}

fn bench_rewrites_and_clients(c: &mut Criterion) {
    let config = RewritesConfig {
        auto_ptr: true,
        entries: vec![
            RewriteEntryConfig {
                domain: "*.home.arpa".to_string(),
                r#type: "A".to_string(),
                answer: "192.168.1.10".to_string(),
                exception_clients: vec![],
            },
            RewriteEntryConfig {
                domain: "nas.lan".to_string(),
                r#type: "A".to_string(),
                answer: "192.168.1.50".to_string(),
                exception_clients: vec![],
            },
        ],
    };
    let rewrites = RewriteTable::new(config);
    let clients_config = ClientsConfig::default();
    let _registry = ClientRegistry::new(clients_config);

    let ctx = ClientContext::new("192.168.1.100".parse().unwrap());
    let qname_rewrite = Name::from_str("printer.home.arpa.").unwrap();

    let mut group = c.benchmark_group("pipeline_stages");
    group.bench_function("rewrite_wildcard_lookup", |b| {
        b.iter(|| {
            let res = rewrites.lookup(
                black_box(&qname_rewrite),
                black_box(RecordType::A),
                black_box(&ctx),
            );
            black_box(res);
        });
    });

    group.bench_function("client_sni_extraction", |b| {
        b.iter(|| {
            let id =
                sito_clients::registry::extract_id_from_sni(black_box("laptop.dns.example.com"));
            black_box(id);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_wire_decode_encode,
    bench_cache_lookup,
    bench_filter_matching,
    bench_rewrites_and_clients,
);
criterion_main!(benches);
