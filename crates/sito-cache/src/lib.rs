//! `sito-cache`
//!
//! High-performance concurrent DNS response cache based on Moka with byte-size weigher,
//! TTL decrementing upon serve, min/max clamping, and RFC 2308 negative caching.

pub mod cache;
pub mod entry;
pub mod key;

pub use cache::{DnsCache, SingleFlightGuard};
pub use entry::CacheEntry;
pub use key::CacheKey;

#[cfg(test)]
mod tests {
    use super::*;
    use sito_core::config::CacheConfig;
    use sito_proto::rdata::opt::{ClientSubnet, EdnsOption};
    use sito_proto::rdata::{A, NULL, SOA};
    use sito_proto::{
        DNSClass, Edns, Message, MessageType, Name, OpCode, Query, RData, Record, RecordType,
        ResponseCode,
    };
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn make_test_config(min_ttl: u32, max_ttl: u32, negative_ttl_max: u32) -> CacheConfig {
        CacheConfig {
            enabled: true,
            size_mb: 64,
            min_ttl,
            max_ttl,
            negative_ttl_max,
            prefetch: false,
            serve_stale_hours: 0,
        }
    }

    #[tokio::test]
    async fn test_cache_hit_and_ttl_decrement() {
        let config = make_test_config(10, 3600, 3600);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("example.com.").unwrap();
        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(qname.clone(), RecordType::A));

        let mut response = Message::response(1, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::NoError;
        response.answers.push(Record::from_rdata(
            qname.clone(),
            100,
            RData::A(A(std::net::Ipv4Addr::new(93, 184, 216, 34))),
        ));

        // Insert into cache
        cache.insert(&query, &response).await;

        // Immediate retrieval
        let cached = cache
            .get(&qname, RecordType::A, DNSClass::IN)
            .await
            .expect("should hit cache");
        assert_eq!(cached.answers.len(), 1);
        let ttl_first = cached.answers[0].ttl;
        assert!((99..=100).contains(&ttl_first));

        // Sleep 1 second and retrieve again
        tokio::time::sleep(Duration::from_millis(1100)).await;

        let cached2 = cache
            .get(&qname, RecordType::A, DNSClass::IN)
            .await
            .expect("should hit cache");
        let ttl_second = cached2.answers[0].ttl;
        assert!(
            ttl_second < ttl_first,
            "TTL must decrease as time elapses (first: {ttl_first}, second: {ttl_second})"
        );
    }

    #[tokio::test]
    async fn test_cache_ttl_clamping() {
        let config = make_test_config(60, 300, 3600);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("clamp.test.").unwrap();
        let mut query = Message::new(2, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(qname.clone(), RecordType::A));

        // Response with very low TTL (5s, below min 60s)
        let mut response = Message::response(2, OpCode::Query);
        response.queries = query.queries.clone();
        response.answers.push(Record::from_rdata(
            qname.clone(),
            5,
            RData::A(A(std::net::Ipv4Addr::new(1, 1, 1, 1))),
        ));

        cache.insert(&query, &response).await;

        let cached = cache
            .get(&qname, RecordType::A, DNSClass::IN)
            .await
            .unwrap();
        // Clamped up to 60s
        assert!(cached.answers[0].ttl >= 59);

        // Response with very high TTL (10,000s, above max 300s)
        let qname_high = Name::from_str("high.test.").unwrap();
        let mut query_high = Message::new(3, MessageType::Query, OpCode::Query);
        query_high
            .queries
            .push(Query::query(qname_high.clone(), RecordType::A));

        let mut response_high = Message::response(3, OpCode::Query);
        response_high.queries = query_high.queries.clone();
        response_high.answers.push(Record::from_rdata(
            qname_high.clone(),
            10000,
            RData::A(A(std::net::Ipv4Addr::new(2, 2, 2, 2))),
        ));

        cache.insert(&query_high, &response_high).await;

        let cached_high = cache
            .get(&qname_high, RecordType::A, DNSClass::IN)
            .await
            .unwrap();
        // Clamped down to 300s
        assert!(cached_high.answers[0].ttl <= 300);
    }

    #[tokio::test]
    async fn test_negative_caching_nxdomain() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("nonexistent.example.").unwrap();
        let mut query = Message::new(4, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(qname.clone(), RecordType::A));

        let mut response = Message::response(4, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::NXDomain;
        response.authorities.push(Record::from_rdata(
            Name::from_str("example.").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_str("ns1.example.").unwrap(),
                Name::from_str("hostmaster.example.").unwrap(),
                2_026_090_401,
                7200,
                3600,
                1_209_600,
                120, // SOA minimum TTL = 120s
            )),
        ));

        cache.insert(&query, &response).await;

        let cached = cache
            .get(&qname, RecordType::A, DNSClass::IN)
            .await
            .expect("negative response should be cached");
        assert_eq!(cached.metadata.response_code, ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn test_serve_stale_fallback() {
        let mut config = make_test_config(1, 1, 300);
        config.serve_stale_hours = 1;
        let cache = DnsCache::new(config);

        let qname = Name::from_str("stale.example.").unwrap();
        let mut query = Message::new(5, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(qname.clone(), RecordType::A));

        let mut response = Message::response(5, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::NoError;
        response.answers.push(Record::from_rdata(
            qname.clone(),
            1,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        ));

        cache.insert(&query, &response).await;

        // Fresh hit
        let fresh = cache.get(&qname, RecordType::A, DNSClass::IN).await;
        assert!(fresh.is_some());

        // Wait for TTL 1s to expire
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Fresh lookup should now return None
        let expired = cache.get(&qname, RecordType::A, DNSClass::IN).await;
        assert!(expired.is_none());

        // Stale lookup should return the cached message with STALE_SERVE_TTL (30s)
        let stale = cache
            .get_stale(&qname, RecordType::A, DNSClass::IN)
            .await
            .expect("stale response should be available");
        assert_eq!(stale.answers.len(), 1);
        assert_eq!(stale.answers[0].ttl, 30);
        assert_eq!(
            stale.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4)))
        );
    }

    #[tokio::test]
    async fn test_cache_insert_does_not_panic_when_min_ttl_exceeds_negative_max() {
        // min_ttl (300) > negative_ttl_max (60)
        let config = make_test_config(300, 3600, 60);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("nx.test.").unwrap();
        let mut query = Message::new(10, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(qname.clone(), RecordType::A));

        let mut response = Message::response(10, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::NXDomain;
        response.authorities.push(Record::from_rdata(
            Name::from_str("test.").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_str("ns1.test.").unwrap(),
                Name::from_str("hostmaster.test.").unwrap(),
                1,
                7200,
                3600,
                1_209_600,
                120,
            )),
        ));

        // Must not panic on clamp!
        cache.insert(&query, &response).await;

        let cached = cache.get(&qname, RecordType::A, DNSClass::IN).await;
        assert!(cached.is_some());
    }

    async fn insert_answer(cache: &DnsCache, id: u16, name: &str) {
        let qname = Name::from_str(name).unwrap();
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        let mut response = Message::response(id, OpCode::Query);
        response.queries = query.queries.clone();
        response.answers.push(Record::from_rdata(
            qname,
            300,
            RData::A(A(std::net::Ipv4Addr::new(203, 0, 113, id as u8))),
        ));
        cache.insert(&query, &response).await;
    }

    #[tokio::test]
    async fn test_resize_carries_over_live_entries() {
        let mut config = make_test_config(10, 3600, 3600);
        config.size_mb = 64;
        let cache = DnsCache::new(config.clone());

        for (id, name) in [(1, "one.test."), (2, "two.test."), (3, "three.test.")] {
            insert_answer(&cache, id, name).await;
        }

        // Sanity: all three answers are cached before the resize.
        for name in ["one.test.", "two.test.", "three.test."] {
            let qname = Name::from_str(name).unwrap();
            assert!(
                cache
                    .get(&qname, RecordType::A, DNSClass::IN)
                    .await
                    .is_some()
            );
        }

        // Shrink and grow again; cached answers must survive the rebuild.
        config.size_mb = 1;
        cache.update_config(config.clone()).await;

        for name in ["one.test.", "two.test.", "three.test."] {
            let qname = Name::from_str(name).unwrap();
            let hit = cache.get(&qname, RecordType::A, DNSClass::IN).await;
            assert!(hit.is_some(), "entry {name} lost after resize");
        }

        config.size_mb = 64;
        cache.update_config(config).await;
        let qname = Name::from_str("one.test.").unwrap();
        assert!(
            cache
                .get(&qname, RecordType::A, DNSClass::IN)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_update_config_without_size_change_keeps_cache() {
        let config = make_test_config(10, 3600, 3600);
        let cache = DnsCache::new(config.clone());
        insert_answer(&cache, 7, "keep.test.").await;

        cache.update_config(config).await;

        let qname = Name::from_str("keep.test.").unwrap();
        assert!(
            cache
                .get(&qname, RecordType::A, DNSClass::IN)
                .await
                .is_some()
        );
    }

    fn query_for(id: u16, name: &Name) -> Message {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(name.clone(), RecordType::A));
        query
    }

    fn answer_response(id: u16, name: &Name, ip: [u8; 4]) -> Message {
        let mut response = Message::response(id, OpCode::Query);
        response
            .queries
            .push(Query::query(name.clone(), RecordType::A));
        response.answers.push(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(std::net::Ipv4Addr::from(ip))),
        ));
        response
    }

    #[tokio::test]
    async fn test_stale_serve_clears_ad_and_rrsigs() {
        let mut config = make_test_config(1, 1, 300);
        config.serve_stale_hours = 1;
        let cache = DnsCache::new(config);

        let qname = Name::from_str("stale-secure.example.").unwrap();
        let query = query_for(21, &qname);
        let mut response = answer_response(21, &qname, [192, 0, 2, 1]);
        // A validated response carries RRSIGs and the AD bit.
        response.answers.push(Record::from_rdata(
            qname.clone(),
            1,
            RData::Unknown {
                code: RecordType::RRSIG,
                rdata: NULL::default(),
            },
        ));
        response.metadata.authentic_data = true;
        cache.insert(&query, &response).await;

        let fresh = cache
            .get(&qname, RecordType::A, DNSClass::IN)
            .await
            .expect("fresh hit");
        assert!(fresh.metadata.authentic_data, "fresh entry keeps AD");

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let stale = cache
            .get_stale(&qname, RecordType::A, DNSClass::IN)
            .await
            .expect("stale hit");
        assert!(
            !stale.metadata.authentic_data,
            "stale data must never be served as authenticated"
        );
        assert!(
            stale
                .answers
                .iter()
                .all(|record| record.record_type() != RecordType::RRSIG),
            "stale data must not carry RRSIGs"
        );
    }

    #[tokio::test]
    async fn test_negative_without_soa_is_not_cached() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("no-soa.example.").unwrap();
        let query = query_for(22, &qname);
        let mut response = Message::response(22, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::NXDomain;

        cache.insert(&query, &response).await;
        assert!(
            cache
                .get(&qname, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "NXDOMAIN without SOA must not be cached (RFC 2308)"
        );

        // An empty NoError (NODATA) without SOA is likewise not cacheable.
        let mut nodata = Message::response(23, OpCode::Query);
        nodata.queries = query.queries.clone();
        cache.insert(&query, &nodata).await;
        assert!(
            cache
                .get(&qname, RecordType::A, DNSClass::IN)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_cname_only_noerror_requires_soa() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("alias.example.").unwrap();
        let target = Name::from_str("target.example.").unwrap();
        let query = query_for(24, &qname);

        // CNAME-only answer without SOA: NODATA, not cacheable.
        let mut response = Message::response(24, OpCode::Query);
        response.queries = query.queries.clone();
        response.answers.push(Record::from_rdata(
            qname.clone(),
            300,
            RData::CNAME(sito_proto::rdata::CNAME(target.clone())),
        ));
        cache.insert(&query, &response).await;
        assert!(
            cache
                .get(&qname, RecordType::A, DNSClass::IN)
                .await
                .is_none()
        );

        // With an SOA the negative TTL applies and the answer is cached.
        response.authorities.push(Record::from_rdata(
            Name::from_str("example.").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_str("ns1.example.").unwrap(),
                Name::from_str("hostmaster.example.").unwrap(),
                1,
                7200,
                3600,
                1_209_600,
                120,
            )),
        ));
        cache.insert(&query, &response).await;
        assert!(
            cache
                .get(&qname, RecordType::A, DNSClass::IN)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_uncacheable_rcodes_and_truncation_rejected() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        for (id, rcode) in [
            (31, ResponseCode::ServFail),
            (32, ResponseCode::Refused),
            (33, ResponseCode::FormErr),
            (34, ResponseCode::NotImp),
        ] {
            let qname = Name::from_str("rcode.example.").unwrap();
            let query = query_for(id, &qname);
            let mut response = answer_response(id, &qname, [192, 0, 2, id as u8]);
            response.metadata.response_code = rcode;
            cache.insert(&query, &response).await;
            assert!(
                cache
                    .get(&qname, RecordType::A, DNSClass::IN)
                    .await
                    .is_none(),
                "{rcode} responses must not be cached"
            );
        }

        let qname = Name::from_str("truncated.example.").unwrap();
        let query = query_for(35, &qname);
        let mut truncated = answer_response(35, &qname, [192, 0, 2, 35]);
        truncated.metadata.truncation = true;
        cache.insert(&query, &truncated).await;
        assert!(
            cache
                .get(&qname, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "TC=1 responses must not be cached"
        );
    }

    #[tokio::test]
    async fn test_mismatched_question_is_not_cached() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("asked.example.").unwrap();
        let other = Name::from_str("other.example.").unwrap();
        let query = query_for(36, &qname);
        let response = answer_response(36, &other, [192, 0, 2, 36]);

        cache.insert(&query, &response).await;
        assert!(
            cache
                .get(&qname, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "a response for a different question must not be cached"
        );

        // A response without a question section cannot be verified.
        let mut no_question = answer_response(37, &qname, [192, 0, 2, 37]);
        no_question.queries.clear();
        cache.insert(&query, &no_question).await;
        assert!(
            cache
                .get(&qname, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "a response without a question section must not be cached"
        );
    }

    #[tokio::test]
    async fn test_do_cd_and_ecs_split_cache_keys() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("flags.example.").unwrap();
        let plain = query_for(41, &qname);

        // DO=1 query with an ECS option and a matching response.
        let mut do_query = query_for(42, &qname);
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "192.0.2.0".parse().unwrap(),
                24,
                0,
            )));
        do_query.set_edns(edns);
        let do_response = answer_response(42, &qname, [192, 0, 2, 42]);
        cache.insert(&do_query, &do_response).await;

        // A DO=0 / no-ECS query must not see the DO=1 ECS entry.
        assert!(cache.get_for_query(&plain).await.is_none());
        assert!(cache.get_for_query(&do_query).await.is_some());

        // CD=1 gets its own keyspace.
        let mut cd_query = query_for(43, &qname);
        cd_query.metadata.checking_disabled = true;
        assert!(cache.get_for_query(&cd_query).await.is_none());
        let cd_response = answer_response(43, &qname, [192, 0, 2, 43]);
        cache.insert(&cd_query, &cd_response).await;
        assert!(cache.get_for_query(&cd_query).await.is_some());
        assert!(
            cache.get_for_query(&plain).await.is_none(),
            "CD=1 entries must never leak into the CD=0 keyspace"
        );

        // Same subnet data differs: a different ECS subnet is a different key.
        let mut ecs_other = query_for(44, &qname);
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "198.51.100.0".parse().unwrap(),
                24,
                0,
            )));
        ecs_other.set_edns(edns);
        assert!(cache.get_for_query(&ecs_other).await.is_none());
    }

    #[tokio::test]
    async fn test_single_flight_coalesces_concurrent_misses() {
        let config = make_test_config(10, 3600, 3600);
        let cache = Arc::new(DnsCache::new(config));
        let qname = Name::from_str("stampede.example.").unwrap();
        let query = Arc::new(query_for(51, &qname));

        let resolutions = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(8));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let query = Arc::clone(&query);
            let resolutions = Arc::clone(&resolutions);
            let barrier = Arc::clone(&barrier);
            let qname = qname.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                if cache.get_for_query(&query).await.is_some() {
                    return;
                }
                let _flight = cache.single_flight_for_query(&query).await;
                // Double-checked locking: another task may have populated the
                // entry while this one waited for the slot.
                if cache.get_for_query(&query).await.is_some() {
                    return;
                }
                resolutions.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
                let response = answer_response(51, &qname, [192, 0, 2, 51]);
                cache.insert(&query, &response).await;
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            1,
            "concurrent misses must be coalesced into one resolution"
        );
        assert!(cache.get_for_query(&query).await.is_some());
    }

    #[tokio::test]
    async fn test_resize_drops_fully_expired_entries() {
        let mut config = make_test_config(1, 1, 300);
        config.size_mb = 8;
        config.serve_stale_hours = 0;
        let cache = DnsCache::new(config);

        insert_answer(&cache, 61, "expired.test.").await;

        tokio::time::sleep(Duration::from_millis(1100)).await;

        cache.resize(8).await;
        assert_eq!(
            cache.weighted_size(),
            0,
            "fully expired entries must not be cloned into the new generation"
        );
    }
}
