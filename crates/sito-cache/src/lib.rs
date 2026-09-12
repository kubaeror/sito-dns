//! `sito-cache`
//!
//! High-performance concurrent DNS response cache based on Moka with byte-size weigher,
//! TTL decrementing upon serve, min/max clamping, and RFC 2308 negative caching.

pub mod cache;
pub mod entry;
pub mod key;

pub use cache::DnsCache;
pub use entry::CacheEntry;
pub use key::CacheKey;

#[cfg(test)]
mod tests {
    use super::*;
    use sito_core::config::CacheConfig;
    use sito_proto::rdata::{A, SOA};
    use sito_proto::{
        DNSClass, Message, MessageType, Name, OpCode, Query, RData, Record, RecordType,
        ResponseCode,
    };
    use std::str::FromStr;
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
}
