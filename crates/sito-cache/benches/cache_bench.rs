//! Criterion benchmarks for the cache hot path.
//!
//! The bench is deterministic: one inserted A record and a fixed miss name.
//! It is a library bench (`harness = false`) and never part of the default
//! test suite.

use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use sito_cache::DnsCache;
use sito_core::config::CacheConfig;
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::str::FromStr;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime")
}

fn query(name: &Name) -> Message {
    let mut message = Message::new(1001, MessageType::Query, OpCode::Query);
    message
        .queries
        .push(Query::query(name.clone(), RecordType::A));
    message
}

fn bench_cache_lookup(c: &mut Criterion) {
    let rt = runtime();
    let cache = DnsCache::new(CacheConfig {
        enabled: true,
        size_mb: 64,
        min_ttl: 60,
        max_ttl: 86_400,
        negative_ttl_max: 3_600,
        prefetch: false,
        serve_stale_hours: 12,
    });

    let cached_name = Name::from_str("cached.example.com.").expect("parse cached name");
    let cached_query = query(&cached_name);
    let miss_name = Name::from_str("missing.example.com.").expect("parse miss name");

    let mut response = Message::new(1001, MessageType::Response, OpCode::Query);
    response.queries.clone_from(&cached_query.queries);
    response.answers.push(Record::from_rdata(
        cached_name.clone(),
        300,
        RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(93, 184, 216, 34))),
    ));
    rt.block_on(cache.insert(&cached_query, &response));

    let mut group = c.benchmark_group("cache");
    group.bench_function("hit_lookup", |b| {
        b.iter(|| {
            let entry = rt.block_on(cache.get(
                black_box(&cached_name),
                black_box(RecordType::A),
                black_box(DNSClass::IN),
            ));
            black_box(entry);
        });
    });
    group.bench_function("miss_lookup", |b| {
        b.iter(|| {
            let entry = rt.block_on(cache.get(
                black_box(&miss_name),
                black_box(RecordType::A),
                black_box(DNSClass::IN),
            ));
            black_box(entry);
        });
    });
    group.bench_function("insert_response", |b| {
        b.iter(|| {
            rt.block_on(cache.insert(black_box(&cached_query), black_box(&response)));
        });
    });
    group.finish();
}

criterion_group!(benches, bench_cache_lookup);
criterion_main!(benches);
