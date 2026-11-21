//! `sito-cache`
//!
//! High-performance concurrent DNS response cache based on Moka with byte-size weigher,
//! TTL decrementing upon serve, min/max clamping, and RFC 2308 negative caching.

pub mod cache;
pub mod entry;
pub mod key;

pub use cache::{
    DNSSEC_BOGUS_CACHE_TTL, DNSSEC_INDETERMINATE_CACHE_TTL, DnsCache, SingleFlightGuard,
};
pub use entry::{CacheEntry, PolicyEpoch, ValidationStatus};
pub use key::CacheKey;

/// Cache-policy generation.
///
/// This is the same type (and counter) as the WP-1.4 [`PolicyEpoch`]:
/// `sito-runtime::RuntimeGeneration` is also an alias of it. It is re-exported
/// under the §10.7 interface name so cache-policy code and runtime code cannot
/// drift onto two counters.
pub type CachePolicyEpoch = PolicyEpoch;

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
    async fn test_negative_ttl_clamped_by_soa_minimum_and_cname_chain() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("alias.example.").unwrap();
        let target = Name::from_str("target.example.").unwrap();
        let query = query_for(70, &qname);
        let mut response = Message::response(70, OpCode::Query);
        response.queries = query.queries.clone();
        // NODATA reached through a CNAME whose TTL (30 s) is shorter than the
        // SOA-derived negative TTL (120 s).
        response.answers.push(Record::from_rdata(
            qname.clone(),
            30,
            RData::CNAME(sito_proto::rdata::CNAME(target)),
        ));
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

        let cached = cache
            .get(&qname, RecordType::A, DNSClass::IN)
            .await
            .expect("negative response must be cached");
        assert_eq!(
            cached.answers[0].ttl, 30,
            "negative TTL must be capped by the CNAME chain TTL"
        );
        assert_eq!(
            cached.authorities[0].ttl, 30,
            "the SOA TTL must not outlive the negative lifespan"
        );

        tokio::time::sleep(Duration::from_millis(1100)).await;
        let later = cache
            .get(&qname, RecordType::A, DNSClass::IN)
            .await
            .expect("still within lifespan");
        assert!(
            later.answers[0].ttl < 30,
            "negative answer TTLs must decrement on serve (got {})",
            later.answers[0].ttl
        );
    }

    #[tokio::test]
    async fn test_negative_ttl_uses_soa_minimum() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("nodata.example.").unwrap();
        let query = query_for(71, &qname);
        let mut response = Message::response(71, OpCode::Query);
        response.queries = query.queries.clone();
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
                60, // SOA MINIMUM is shorter than the SOA record TTL
            )),
        ));
        cache.insert(&query, &response).await;

        let cached = cache
            .get(&qname, RecordType::A, DNSClass::IN)
            .await
            .expect("negative response must be cached");
        assert_eq!(
            cached.authorities[0].ttl, 60,
            "negative TTL must use min(SOA TTL, SOA MINIMUM)"
        );
    }

    #[tokio::test]
    async fn test_negative_soa_must_be_in_bailiwick() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("nx.example.").unwrap();
        let query = query_for(72, &qname);
        let mut response = Message::response(72, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::NXDomain;
        // A SOA for an unrelated zone must not authorize a negative entry.
        response.authorities.push(Record::from_rdata(
            Name::from_str("unrelated.").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_str("ns1.unrelated.").unwrap(),
                Name::from_str("hostmaster.unrelated.").unwrap(),
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
                .is_none(),
            "out-of-bailiwick SOA must not authorize negative caching"
        );
    }

    #[tokio::test]
    async fn test_negative_soa_for_cname_target_zone_is_in_bailiwick() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("alias.example.").unwrap();
        let target = Name::from_str("target.other.").unwrap();
        let query = query_for(78, &qname);
        let mut response = Message::response(78, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::NXDomain;
        response.answers.push(Record::from_rdata(
            qname.clone(),
            300,
            RData::CNAME(sito_proto::rdata::CNAME(target)),
        ));
        // A cross-zone alias legitimately ends in the target's zone.
        response.authorities.push(Record::from_rdata(
            Name::from_str("other.").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_str("ns1.other.").unwrap(),
                Name::from_str("hostmaster.other.").unwrap(),
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
                .is_some(),
            "a SOA for the CNAME target's zone is in bailiwick"
        );
    }

    #[tokio::test]
    async fn test_root_name_is_cacheable_and_invalidation_flushes() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        let root = Name::root();
        let query = query_for(73, &root);
        let response = answer_response(73, &root, [192, 0, 2, 73]);
        cache.insert(&query, &response).await;
        insert_answer(&cache, 74, "example.com.").await;

        assert!(
            cache
                .get(&root, RecordType::A, DNSClass::IN)
                .await
                .is_some(),
            "root queries must be cacheable"
        );
        cache.invalidate_domain(".");
        assert!(
            cache
                .get(&root, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "root invalidation must evict the root entry"
        );
        assert!(
            cache
                .get(
                    &Name::from_str("example.com.").unwrap(),
                    RecordType::A,
                    DNSClass::IN
                )
                .await
                .is_none(),
            "root invalidation covers every descendant"
        );
    }

    /// Domain invalidation must remove the exact name and its strict
    /// subdomains, but not a name that merely shares the suffix
    /// (`notexample.com`). This regressed because moka needs
    /// `support_invalidation_closures()` at build time; without it the
    /// predicate registration failed and was ignored.
    #[tokio::test]
    async fn test_invalidate_domain_removes_exact_and_subdomains_only() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        for (id, name) in [
            (41, "example.com."),
            (42, "www.example.com."),
            (43, "other.com."),
            (44, "notexample.com."),
        ] {
            insert_answer(&cache, id, name).await;
        }

        cache.invalidate_domain("example.com");

        for name in ["example.com.", "www.example.com."] {
            let qname = Name::from_str(name).unwrap();
            assert!(
                cache
                    .get(&qname, RecordType::A, DNSClass::IN)
                    .await
                    .is_none(),
                "{name} must be invalidated"
            );
        }
        for name in ["other.com.", "notexample.com."] {
            let qname = Name::from_str(name).unwrap();
            assert!(
                cache
                    .get(&qname, RecordType::A, DNSClass::IN)
                    .await
                    .is_some(),
                "{name} must survive invalidation of example.com"
            );
        }
    }

    /// Non-root invalidation must evict every cache-key variant of a name, not
    /// only the plain one. `invalidate_domain` matches on `CacheKey::qname`, so
    /// EDNS/DO, CD, ECS and Secure entries must disappear too. The scenario is
    /// repeated after a resize because invalidation closures are attached to
    /// the current moka generation.
    #[tokio::test]
    async fn test_invalidate_domain_removes_all_key_variants_before_and_after_resize() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("example.com.").unwrap();
        let other = Name::from_str("other.example.").unwrap();

        for resize_first in [false, true] {
            if resize_first {
                // Rebuild the cache generation. Live entries are carried over,
                // and invalidation must still work on the new generation.
                cache.resize(8).await;
            }

            for query in seed_key_variants(&cache, &qname).await {
                assert!(
                    cache.get_for_query_with_status(&query).await.is_some(),
                    "variant key must be cached before invalidation"
                );
            }
            insert_answer(&cache, 63, "other.example.").await;

            cache.invalidate_domain("example.com");

            for (query, _) in key_variant_queries(&qname) {
                assert!(
                    cache.get_for_query_with_status(&query).await.is_none(),
                    "invalidate_domain must evict every key variant for {qname}"
                );
            }
            assert!(
                cache
                    .get_for_query_with_status(&query_for(63, &other))
                    .await
                    .is_some(),
                "an unrelated name must survive invalidation"
            );
        }
    }

    /// Builds one query per key dimension: plain, EDNS/DO, CD=1, ECS, and a
    /// Secure-status insert. Returns the queries with the status to store.
    fn key_variant_queries(name: &Name) -> Vec<(Message, ValidationStatus)> {
        let plain = query_for(60, name);

        let mut do_query = query_for(61, name);
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        do_query.set_edns(edns);

        let mut cd_query = query_for(62, name);
        cd_query.metadata.checking_disabled = true;

        let mut ecs_query = query_for(64, name);
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "192.0.2.0".parse().unwrap(),
                24,
                0,
            )));
        ecs_query.set_edns(edns);

        // Secure status is not part of the key, so use a distinct DO+CD
        // variant to keep this entry addressable independently of the others.
        let mut secure_query = query_for(65, name);
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        secure_query.set_edns(edns);
        secure_query.metadata.checking_disabled = true;

        vec![
            (plain, ValidationStatus::Unchecked),
            (do_query, ValidationStatus::Unchecked),
            (cd_query, ValidationStatus::Unchecked),
            (ecs_query, ValidationStatus::Unchecked),
            (secure_query, ValidationStatus::Secure),
        ]
    }

    async fn seed_key_variants(cache: &DnsCache, name: &Name) -> Vec<Message> {
        let mut queries = Vec::new();
        for (query, status) in key_variant_queries(name) {
            let response = answer_response(
                query.metadata.id,
                name,
                [192, 0, 2, query.metadata.id as u8],
            );
            cache.insert_with_status(&query, &response, status).await;
            queries.push(query);
        }
        queries
    }

    /// The cache API supplies Unicode names (`Name::to_string()`), while
    /// cache keys are punycode (`Name::to_ascii()`). Invalidation must normalize
    /// the request through IDNA or an IDN entry can never be evicted.
    #[tokio::test]
    async fn test_invalidate_domain_evicts_idn_punycode_entries() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        insert_answer(&cache, 51, "xn--mnchen-3ya.de.").await;
        insert_answer(&cache, 52, "www.xn--mnchen-3ya.de.").await;
        insert_answer(&cache, 53, "other.example.").await;

        cache.invalidate_domain("münchen.de");

        for name in ["xn--mnchen-3ya.de.", "www.xn--mnchen-3ya.de."] {
            let qname = Name::from_ascii(name).unwrap();
            assert!(
                cache
                    .get(&qname, RecordType::A, DNSClass::IN)
                    .await
                    .is_none(),
                "{name} must be invalidated by the Unicode name"
            );
        }
        let other = Name::from_ascii("other.example.").unwrap();
        assert!(
            cache
                .get(&other, RecordType::A, DNSClass::IN)
                .await
                .is_some(),
            "unrelated entries must survive"
        );
    }

    #[tokio::test]
    async fn test_validation_status_round_trips_through_cache() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("status.example.").unwrap();
        let query = query_for(75, &qname);
        let response = answer_response(75, &qname, [192, 0, 2, 75]);
        cache
            .insert_with_status(&query, &response, ValidationStatus::Insecure)
            .await;

        let (_, status) = cache
            .get_for_query_with_status(&query)
            .await
            .expect("cache hit");
        assert_eq!(status, ValidationStatus::Insecure);

        // The convenience insert must never trust an upstream AD bit: a
        // response the resolver did not validate is stored as Unchecked.
        let mut forged = answer_response(76, &qname, [192, 0, 2, 76]);
        forged.metadata.authentic_data = true;
        let forged_query = query_for(76, &qname);
        cache.insert(&forged_query, &forged).await;
        let (_, status) = cache
            .get_for_query_with_status(&forged_query)
            .await
            .expect("cache hit");
        assert_eq!(
            status,
            ValidationStatus::Unchecked,
            "insert() must not turn an unvalidated upstream AD bit into Secure"
        );
        // The forged bit must not be replayed from the cache either.
        let (forged_cached, _) = cache
            .get_for_query_with_status(&forged_query)
            .await
            .expect("cache hit");
        assert!(
            !forged_cached.metadata.authentic_data,
            "an Unchecked entry must be stored and served with AD=0"
        );
        assert!(
            forged.metadata.authentic_data,
            "the caller's message must not be mutated by insert()"
        );
    }

    /// Only a `Secure` decision may keep the AD bit in the stored entry. A
    /// forged upstream AD on an `Unchecked`/`Insecure` answer must come back
    /// clear, and the caller's message must never be mutated.
    #[tokio::test]
    async fn test_non_secure_inserts_clear_forged_ad() {
        let cache = DnsCache::new(make_test_config(10, 3600, 1800));

        for (id, status) in [
            (80u16, ValidationStatus::Unchecked),
            (81, ValidationStatus::Insecure),
        ] {
            let qname = Name::from_str(&format!("ad-{id}.example.")).unwrap();
            let query = query_for(id, &qname);
            let mut response = answer_response(id, &qname, [192, 0, 2, id as u8]);
            response.metadata.authentic_data = true;

            cache.insert_with_status(&query, &response, status).await;

            let (cached, stored) = cache
                .get_for_query_with_status(&query)
                .await
                .expect("cache hit");
            assert_eq!(stored, status);
            assert!(
                !cached.metadata.authentic_data,
                "{status:?} must be stored and served with AD=0"
            );
            assert!(
                response.metadata.authentic_data,
                "the caller's message must not be mutated"
            );
        }
    }

    #[tokio::test]
    async fn test_secure_insert_preserves_ad() {
        let cache = DnsCache::new(make_test_config(10, 3600, 1800));
        let qname = Name::from_str("secure-ad.example.").unwrap();
        let query = query_for(82, &qname);
        let mut response = answer_response(82, &qname, [192, 0, 2, 82]);
        response.metadata.authentic_data = true;

        cache
            .insert_with_status(&query, &response, ValidationStatus::Secure)
            .await;

        let (cached, status) = cache
            .get_for_query_with_status(&query)
            .await
            .expect("cache hit");
        assert_eq!(status, ValidationStatus::Secure);
        assert!(
            cached.metadata.authentic_data,
            "a Secure entry must keep its authenticated-data bit"
        );
        let statusless = cache
            .get_for_query(&query)
            .await
            .expect("Secure entries are servable by the status-less getter");
        assert!(statusless.metadata.authentic_data);
    }

    /// The fresh status-less getters must hide fail-closed (`Bogus`) and
    /// inconclusive (`Indeterminate`) entries, mirroring the stale getters.
    /// The status-aware getter remains the unfiltered inspection form.
    #[tokio::test]
    async fn test_fresh_statusless_getters_hide_failure_entries() {
        let cache = DnsCache::new(make_test_config(10, 3600, 1800));

        let bogus_name = Name::from_str("fresh-bogus-getter.example.").unwrap();
        let bogus_query = query_for(83, &bogus_name);
        assert!(
            cache
                .insert_validation_failure_at_epochs(
                    &bogus_query,
                    &servfail_response(83, &bogus_query),
                    ValidationStatus::Bogus,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await
        );

        let indeterminate_name = Name::from_str("fresh-indeterminate-getter.example.").unwrap();
        let indeterminate_query = query_for(84, &indeterminate_name);
        cache
            .insert_with_status(
                &indeterminate_query,
                &answer_response(84, &indeterminate_name, [192, 0, 2, 84]),
                ValidationStatus::Indeterminate,
            )
            .await;

        let unchecked_name = Name::from_str("fresh-unchecked-getter.example.").unwrap();
        let unchecked_query = query_for(85, &unchecked_name);
        cache
            .insert(
                &unchecked_query,
                &answer_response(85, &unchecked_name, [192, 0, 2, 85]),
            )
            .await;

        assert_eq!(
            cache
                .get_for_query_with_status(&bogus_query)
                .await
                .map(|(_, status)| status),
            Some(ValidationStatus::Bogus),
            "the status-aware getter must still expose a fresh Bogus entry"
        );
        assert_eq!(
            cache
                .get_for_query_with_status(&indeterminate_query)
                .await
                .map(|(_, status)| status),
            Some(ValidationStatus::Indeterminate),
            "the status-aware getter must still expose a fresh Indeterminate entry"
        );

        assert!(
            cache
                .get(&bogus_name, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "get must not return a fresh Bogus entry"
        );
        assert!(
            cache.get_for_query(&bogus_query).await.is_none(),
            "get_for_query must not return a fresh Bogus entry"
        );
        assert!(
            cache
                .get(&indeterminate_name, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "get must not return a fresh Indeterminate entry"
        );
        assert!(
            cache.get_for_query(&indeterminate_query).await.is_none(),
            "get_for_query must not return a fresh Indeterminate entry"
        );
        assert!(
            cache
                .get(&unchecked_name, RecordType::A, DNSClass::IN)
                .await
                .is_some(),
            "Unchecked must remain returnable from the status-less getters"
        );
        assert!(
            cache.get_for_query(&unchecked_query).await.is_some(),
            "Unchecked must remain returnable from the status-less getters"
        );
    }

    /// P1-27: a DNSSEC policy change must invalidate validation decisions in
    /// the response cache, not only in the chain cache. An entry validated
    /// under the old generation must be invisible immediately, and an insert
    /// from a query that captured the old epoch while validation was in flight
    /// must be rejected even if it happens after the flush.
    #[tokio::test]
    async fn test_policy_epoch_rejects_in_flight_insert_and_hides_old_entries() {
        let cache = DnsCache::new(make_test_config(10, 3600, 1800));
        let qname = Name::from_str("epoch.example.").unwrap();
        let query = query_for(90, &qname);
        let response = answer_response(90, &qname, [192, 0, 2, 90]);

        let old_epoch = cache.policy_epoch();
        assert!(
            cache
                .insert_with_status_at_epoch(
                    &query,
                    &response,
                    ValidationStatus::Secure,
                    old_epoch,
                )
                .await
        );

        // Simulate the config apply: the new validator is installed, then the
        // cache generation advances (before the memory flush).
        cache.advance_policy_epoch();
        let new_epoch = cache.policy_epoch();
        assert!(new_epoch > old_epoch);

        assert!(
            cache.get_for_query_with_status(&query).await.is_none(),
            "an old-generation entry must be unservable immediately"
        );

        // The in-flight query captured `old_epoch` before validation. Its
        // insert arrives after the generation change and must be dropped.
        assert!(
            !cache
                .insert_with_status_at_epoch(
                    &query,
                    &response,
                    ValidationStatus::Secure,
                    old_epoch,
                )
                .await,
            "an insert from the old policy generation must be rejected"
        );
        assert!(
            cache.get_for_query_with_status(&query).await.is_none(),
            "the rejected insert must not become visible"
        );

        // A query that captured the new epoch proceeds normally.
        assert!(
            cache
                .insert_with_status_at_epoch(
                    &query,
                    &response,
                    ValidationStatus::Insecure,
                    new_epoch,
                )
                .await
        );
        let (_, status, epoch) = cache
            .get_for_query_with_status_and_epoch(&query)
            .await
            .expect("new-generation entry");
        assert_eq!(status, ValidationStatus::Insecure);
        assert_eq!(epoch, new_epoch.get());
    }

    /// A filter-only refresh must not let an in-flight query that captured the
    /// old filter snapshot repopulate the cache after the refresh flush.
    #[tokio::test]
    async fn test_filter_epoch_rejects_old_filter_insert_and_hides_entries() {
        let cache = DnsCache::new(make_test_config(10, 3600, 1800));
        let qname = Name::from_str("filter-epoch.example.").unwrap();
        let query = query_for(91, &qname);
        let response = answer_response(91, &qname, [192, 0, 2, 91]);

        let old_filter = cache.filter_epoch();
        assert!(
            cache
                .insert_with_status_at_epochs(
                    &query,
                    &response,
                    ValidationStatus::Unchecked,
                    cache.policy_epoch(),
                    old_filter,
                )
                .await
        );
        assert!(cache.get_for_query(&query).await.is_some());

        cache.set_filter_epoch(old_filter + 1);
        assert!(
            cache.get_for_query(&query).await.is_none(),
            "an entry from the old filter generation must be unservable"
        );
        assert!(
            !cache
                .insert_with_status_at_epochs(
                    &query,
                    &response,
                    ValidationStatus::Unchecked,
                    cache.policy_epoch(),
                    old_filter,
                )
                .await,
            "an insert from the old filter generation must be rejected"
        );

        // A query that captured the new filter epoch inserts and serves.
        assert!(
            cache
                .insert_with_status_at_epochs(
                    &query,
                    &response,
                    ValidationStatus::Unchecked,
                    cache.policy_epoch(),
                    old_filter + 1,
                )
                .await
        );
        assert!(cache.get_for_query(&query).await.is_some());
    }

    #[tokio::test]
    async fn test_filter_epoch_stale_path_rejects_old_filter() {
        let mut config = make_test_config(10, 1, 1);
        config.serve_stale_hours = 1;
        let cache = DnsCache::new(config);
        let qname = Name::from_str("filter-stale.example.").unwrap();
        let query = query_for(92, &qname);
        let response = answer_response(92, &qname, [192, 0, 2, 92]);
        let old_filter = cache.filter_epoch();
        assert!(
            cache
                .insert_with_status_at_epochs(
                    &query,
                    &response,
                    ValidationStatus::Unchecked,
                    cache.policy_epoch(),
                    old_filter,
                )
                .await
        );
        cache
            .backdate_entry_for_test(&query, std::time::Duration::from_secs(5))
            .await;
        assert!(cache.get_stale_for_query(&query).await.is_some());

        cache.set_filter_epoch(old_filter + 1);
        assert!(cache.get_stale_for_query(&query).await.is_none());
    }

    /// `min_ttl` is a cache policy floor for unvalidated data only. Raising a
    /// `Secure` TTL above the RRSIG-authenticated TTL would serve AD=1 data
    /// after its signature/TTL expired.
    #[tokio::test]
    async fn test_secure_ttl_is_not_raised_to_min_ttl() {
        let config = make_test_config(60, 3600, 3600);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("secure-ttl.example.").unwrap();
        let query = query_for(80, &qname);
        let mut response = answer_response(80, &qname, [192, 0, 2, 80]);
        response.answers[0].ttl = 10;
        cache
            .insert_with_status(&query, &response, ValidationStatus::Secure)
            .await;

        let (cached, status) = cache
            .get_for_query_with_status(&query)
            .await
            .expect("cache hit");
        assert_eq!(status, ValidationStatus::Secure);
        assert_eq!(
            cached.answers[0].ttl, 10,
            "a Secure TTL must never be raised above its authenticated value"
        );

        // Unvalidated entries keep the existing min_ttl floor.
        let other = Name::from_str("unchecked-ttl.example.").unwrap();
        let other_query = query_for(81, &other);
        let mut other_response = answer_response(81, &other, [192, 0, 2, 81]);
        other_response.answers[0].ttl = 10;
        cache
            .insert_with_status(&other_query, &other_response, ValidationStatus::Unchecked)
            .await;
        let (cached, _) = cache
            .get_for_query_with_status(&other_query)
            .await
            .expect("cache hit");
        assert_eq!(
            cached.answers[0].ttl, 60,
            "unvalidated entries must still be clamped up to min_ttl"
        );
    }

    /// A Secure negative answer is only as trustworthy as its NSEC/NSEC3
    /// denial proof. The SOA-derived negative TTL must not outlive the denial
    /// record or its RRSIG (RFC 4035 §5.3.3).
    #[tokio::test]
    async fn test_secure_negative_ttl_is_capped_by_denial_proof() {
        let config = make_test_config(60, 3600, 3600);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("missing-ttl.example.").unwrap();
        let query = query_for(83, &qname);
        let mut response = Message::response(83, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::NXDomain;
        // The SOA is signed with a long TTL, while the actual denial proof
        // (NSEC + RRSIG) expires after 10 seconds.
        response.authorities.push(Record::from_rdata(
            Name::from_str("example.").unwrap(),
            3600,
            RData::SOA(SOA::new(
                Name::from_str("ns1.example.").unwrap(),
                Name::from_str("hostmaster.example.").unwrap(),
                1,
                7200,
                3600,
                1_209_600,
                3600,
            )),
        ));
        for code in [RecordType::NSEC, RecordType::RRSIG] {
            response.authorities.push(Record::from_rdata(
                qname.clone(),
                10,
                RData::Unknown {
                    code,
                    rdata: NULL::default(),
                },
            ));
        }
        cache
            .insert_with_status(&query, &response, ValidationStatus::Secure)
            .await;

        let (cached, status) = cache
            .get_for_query_with_status(&query)
            .await
            .expect("cache hit");
        assert_eq!(status, ValidationStatus::Secure);
        assert_eq!(cached.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(
            cached.authorities[0].ttl, 10,
            "the SOA-derived negative TTL must be capped by the denial proof"
        );
        assert!(
            cached.authorities.iter().all(|record| record.ttl <= 10),
            "no authority record may outlive the denial proof: {:?}",
            cached.authorities
        );

        // The entry must decrement from the denial TTL (10 s), not from the
        // 3600 s SOA TTL.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let (later, _) = cache
            .get_for_query_with_status(&query)
            .await
            .expect("still within the denial lifespan");
        assert!(
            later.authorities[0].ttl < 10,
            "the negative lifespan must be the denial TTL (got {})",
            later.authorities[0].ttl
        );
    }

    /// The validator accepts denial proofs from the additional section, so the
    /// cache TTL cap must scan the same sections. A Secure negative whose
    /// NSEC/RRSIG proof was relocated to additionals must still use the proof
    /// TTL, not the SOA TTL.
    #[tokio::test]
    async fn test_secure_negative_proof_in_additionals_caps_lifespan() {
        let config = make_test_config(60, 3600, 3600);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("missing-addl-ttl.example.").unwrap();
        let query = query_for(84, &qname);
        let mut response = Message::response(84, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::NXDomain;
        response.authorities.push(Record::from_rdata(
            Name::from_str("example.").unwrap(),
            3600,
            RData::SOA(SOA::new(
                Name::from_str("ns1.example.").unwrap(),
                Name::from_str("hostmaster.example.").unwrap(),
                1,
                7200,
                3600,
                1_209_600,
                3600,
            )),
        ));
        // Denial proof carried in the additional section.
        for code in [RecordType::NSEC, RecordType::RRSIG] {
            response.additionals.push(Record::from_rdata(
                qname.clone(),
                10,
                RData::Unknown {
                    code,
                    rdata: NULL::default(),
                },
            ));
        }
        cache
            .insert_with_status(&query, &response, ValidationStatus::Secure)
            .await;

        let (cached, status) = cache
            .get_for_query_with_status(&query)
            .await
            .expect("cache hit");
        assert_eq!(status, ValidationStatus::Secure);
        assert_eq!(
            cached.authorities[0].ttl, 10,
            "an additional-section denial proof must cap the negative lifespan"
        );
    }

    /// The stale fallback must expose the recorded validation status (so the
    /// pipeline can refuse Unchecked entries) and strip every DNSSEC RR type,
    /// not just RRSIG.
    #[tokio::test]
    async fn test_stale_lookup_reports_status_and_strips_all_dnssec_records() {
        let mut config = make_test_config(1, 1, 300);
        config.serve_stale_hours = 1;
        let cache = DnsCache::new(config);

        let qname = Name::from_str("stale-status.example.").unwrap();
        let query = query_for(82, &qname);
        let mut response = answer_response(82, &qname, [192, 0, 2, 82]);
        response.metadata.authentic_data = true;
        for code in [
            RecordType::RRSIG,
            RecordType::DNSKEY,
            RecordType::DS,
            RecordType::NSEC3,
        ] {
            response.answers.push(Record::from_rdata(
                qname.clone(),
                1,
                RData::Unknown {
                    code,
                    rdata: NULL::default(),
                },
            ));
        }
        cache
            .insert_with_status(&query, &response, ValidationStatus::Unchecked)
            .await;

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let (stale, status) = cache
            .get_stale_for_query_with_status(&query)
            .await
            .expect("stale hit");
        assert_eq!(
            status,
            ValidationStatus::Unchecked,
            "the stale path must expose the recorded validation status"
        );
        assert!(
            !stale.metadata.authentic_data,
            "stale data must never be served as authenticated"
        );
        assert!(
            stale
                .answers
                .iter()
                .all(|record| !record.record_type().is_dnssec()),
            "stale sanitization must remove every DNSSEC RR type: {:?}",
            stale.answers
        );
    }

    #[tokio::test]
    async fn test_serve_stale_fallback() {
        let mut config = make_test_config(1, 3600, 300);
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
    async fn test_update_config_for_generation_leaves_entries_to_the_epoch() {
        let config = make_test_config(10, 3600, 3600);
        let cache = DnsCache::new(config.clone());
        insert_answer(&cache, 8, "generation.test.").await;

        let mut narrowed = config;
        narrowed.min_ttl = 1;
        narrowed.max_ttl = 1;
        narrowed.size_mb = 1;
        cache.update_config_for_generation(narrowed).await;

        // No re-clamp scan: the old entry is still present and its served TTL
        // is not rewritten. The generation apply advances the epoch next, which
        // invalidates it without touching every entry.
        let qname = Name::from_str("generation.test.").unwrap();
        let hit = cache
            .get(&qname, RecordType::A, DNSClass::IN)
            .await
            .expect("entry survives until the epoch advances");
        assert!(
            hit.answers[0].ttl > 1,
            "generation update must not rewrite entries"
        );

        // The published configuration is live: a post-update insert is clamped
        // by the new max TTL (and the resize carried the old entry over).
        insert_answer(&cache, 9, "generation-new.test.").await;
        let new_qname = Name::from_str("generation-new.test.").unwrap();
        let new_hit = cache
            .get(&new_qname, RecordType::A, DNSClass::IN)
            .await
            .expect("new insert under the updated policy");
        assert_eq!(
            new_hit.answers[0].ttl, 1,
            "update_config_for_generation must publish the new TTL policy"
        );

        cache.advance_policy_epoch();
        assert!(
            cache
                .get(&qname, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "the new epoch must hide the old entry"
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

    fn servfail_response(id: u16, query: &Message) -> Message {
        let mut response = Message::response(id, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::ServFail;
        response
    }

    #[tokio::test]
    async fn test_bogus_validation_failure_is_cached_as_servfail() {
        let cache = DnsCache::new(make_test_config(10, 3600, 1800));
        let qname = Name::from_str("bogus.example.").unwrap();
        let query = query_for(110, &qname);
        let response = servfail_response(110, &query);

        assert!(
            cache
                .insert_validation_failure_at_epochs(
                    &query,
                    &response,
                    ValidationStatus::Bogus,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await,
            "a strict Bogus SERVFAIL must be cached"
        );

        let (cached, status) = cache
            .get_for_query_with_status(&query)
            .await
            .expect("fail-closed entry must be a cache hit");
        assert_eq!(status, ValidationStatus::Bogus);
        assert_eq!(cached.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(cached.answers.len(), 0);
        assert_eq!(cached.queries, query.queries);
    }

    #[tokio::test]
    async fn test_bogus_validation_failure_rejects_old_policy_epoch() {
        let cache = DnsCache::new(make_test_config(10, 3600, 1800));
        let qname = Name::from_str("bogus-epoch.example.").unwrap();
        let query = query_for(111, &qname);
        let response = servfail_response(111, &query);

        let old_epoch = cache.policy_epoch();
        assert!(
            cache
                .insert_validation_failure_at_epochs(
                    &query,
                    &response,
                    ValidationStatus::Bogus,
                    old_epoch,
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await,
            "a current-epoch Bogus failure must be cached"
        );
        assert!(
            cache.get_for_query_with_status(&query).await.is_some(),
            "the current-epoch failure must be visible"
        );

        cache.advance_policy_epoch();
        assert!(
            cache.get_for_query_with_status(&query).await.is_none(),
            "advancing the policy epoch must hide the existing failure entry"
        );

        assert!(
            !cache
                .insert_validation_failure_at_epochs(
                    &query,
                    &response,
                    ValidationStatus::Bogus,
                    old_epoch,
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await,
            "a Bogus failure from an old policy generation must be rejected"
        );
        assert!(
            cache.get_for_query_with_status(&query).await.is_none(),
            "the rejected failure must not become visible"
        );

        assert!(
            cache
                .insert_validation_failure_at_epochs(
                    &query,
                    &response,
                    ValidationStatus::Bogus,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await,
            "a failure from the current filter generation must be cached"
        );
        let old_filter = cache.filter_epoch();
        cache.set_filter_epoch(old_filter + 1);
        assert!(
            cache.get_for_query_with_status(&query).await.is_none(),
            "advancing the filter epoch must hide the existing failure entry"
        );
        assert!(
            !cache
                .insert_validation_failure_at_epochs(
                    &query,
                    &response,
                    ValidationStatus::Bogus,
                    cache.policy_epoch(),
                    old_filter,
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await,
            "a Bogus failure from an old filter generation must be rejected"
        );
    }

    #[tokio::test]
    async fn test_bogus_validation_failure_expires_after_short_ttl() {
        let cache = DnsCache::new(make_test_config(10, 3600, 1800));
        let qname = Name::from_str("bogus-ttl.example.").unwrap();
        let query = query_for(112, &qname);
        let response = servfail_response(112, &query);

        assert!(
            cache
                .insert_validation_failure_at_epochs(
                    &query,
                    &response,
                    ValidationStatus::Bogus,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await
        );
        assert_eq!(DNSSEC_BOGUS_CACHE_TTL, 5, "the Bogus window is 5 s");
        cache
            .backdate_entry_for_test(&query, Duration::from_secs(4))
            .await;
        assert!(
            cache.get_for_query_with_status(&query).await.is_some(),
            "the failure entry must still be fresh before 5 s"
        );

        cache
            .backdate_entry_for_test(
                &query,
                Duration::from_secs(u64::from(DNSSEC_BOGUS_CACHE_TTL)),
            )
            .await;
        assert!(
            cache.get_for_query_with_status(&query).await.is_none(),
            "the failure entry must expire after DNSSEC_BOGUS_CACHE_TTL"
        );
    }

    #[tokio::test]
    async fn test_validation_failure_ttl_is_clamped_to_status_window() {
        let cache = DnsCache::new(make_test_config(10, 3600, 1800));

        // The caller asks for an hour; the cache must enforce the 5 s Bogus
        // window itself rather than trusting the call site constant.
        let bogus_name = Name::from_str("bogus-oversized-ttl.example.").unwrap();
        let bogus_query = query_for(115, &bogus_name);
        assert!(
            cache
                .insert_validation_failure_at_epochs(
                    &bogus_query,
                    &servfail_response(115, &bogus_query),
                    ValidationStatus::Bogus,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    3600,
                )
                .await
        );
        cache
            .backdate_entry_for_test(&bogus_query, Duration::from_secs(4))
            .await;
        assert!(
            cache
                .get_for_query_with_status(&bogus_query)
                .await
                .is_some(),
            "the oversized Bogus request must still serve inside 5 s"
        );
        cache
            .backdate_entry_for_test(
                &bogus_query,
                Duration::from_secs(u64::from(DNSSEC_BOGUS_CACHE_TTL)),
            )
            .await;
        assert!(
            cache
                .get_for_query_with_status(&bogus_query)
                .await
                .is_none(),
            "an oversized Bogus ttl must be clamped to DNSSEC_BOGUS_CACHE_TTL"
        );

        let indeterminate_name = Name::from_str("indeterminate-oversized-ttl.example.").unwrap();
        let indeterminate_query = query_for(116, &indeterminate_name);
        assert!(
            cache
                .insert_validation_failure_at_epochs(
                    &indeterminate_query,
                    &servfail_response(116, &indeterminate_query),
                    ValidationStatus::Indeterminate,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    3600,
                )
                .await,
            "the dedicated path accepts Indeterminate so tests can exercise the cap"
        );
        cache
            .backdate_entry_for_test(&indeterminate_query, Duration::from_secs(29))
            .await;
        assert!(
            cache
                .get_for_query_with_status(&indeterminate_query)
                .await
                .is_some(),
            "the oversized Indeterminate request must still serve inside 30 s"
        );
        cache
            .backdate_entry_for_test(
                &indeterminate_query,
                Duration::from_secs(u64::from(DNSSEC_INDETERMINATE_CACHE_TTL)),
            )
            .await;
        assert!(
            cache
                .get_for_query_with_status(&indeterminate_query)
                .await
                .is_none(),
            "an oversized Indeterminate ttl must be clamped to DNSSEC_INDETERMINATE_CACHE_TTL"
        );
    }

    /// A validation failure is a fail-closed decision: it must never carry the
    /// authenticated-data bit. The defensive check rejects an AD=1 response
    /// even if a future caller forgets to clear it.
    #[tokio::test]
    async fn test_bogus_validation_failure_rejects_authentic_data() {
        let cache = DnsCache::new(make_test_config(10, 3600, 1800));
        let qname = Name::from_str("bogus-ad.example.").unwrap();
        let query = query_for(119, &qname);
        let mut response = servfail_response(119, &query);
        response.metadata.authentic_data = true;

        assert!(
            !cache
                .insert_validation_failure_at_epochs(
                    &query,
                    &response,
                    ValidationStatus::Bogus,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await,
            "a validation failure that asserts AD must never be cached"
        );
        assert!(
            cache.get_for_query_with_status(&query).await.is_none(),
            "the rejected failure must not become visible"
        );
    }

    /// The status-less stale getters are used by call paths that cannot apply
    /// the validation gate themselves, so they must hide fail-closed and
    /// inconclusive entries. The status-aware getter stays unfiltered for
    /// inspection (stale-serving tests, debugging) and `Unchecked` remains
    /// returnable because it is valid when validation is inactive.
    #[tokio::test]
    async fn test_stale_statusless_getters_hide_failure_entries() {
        let mut config = make_test_config(1, 1, 1);
        config.serve_stale_hours = 1;
        let cache = DnsCache::new(config);

        let bogus_name = Name::from_str("stale-bogus-getter.example.").unwrap();
        let bogus_query = query_for(120, &bogus_name);
        assert!(
            cache
                .insert_validation_failure_at_epochs(
                    &bogus_query,
                    &servfail_response(120, &bogus_query),
                    ValidationStatus::Bogus,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await
        );
        cache
            .backdate_entry_for_test(
                &bogus_query,
                Duration::from_secs(u64::from(DNSSEC_BOGUS_CACHE_TTL)),
            )
            .await;

        let indeterminate_name = Name::from_str("stale-indeterminate-getter.example.").unwrap();
        let indeterminate_query = query_for(121, &indeterminate_name);
        assert!(
            cache
                .insert_validation_failure_at_epochs(
                    &indeterminate_query,
                    &servfail_response(121, &indeterminate_query),
                    ValidationStatus::Indeterminate,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    DNSSEC_INDETERMINATE_CACHE_TTL,
                )
                .await
        );
        cache
            .backdate_entry_for_test(
                &indeterminate_query,
                Duration::from_secs(u64::from(DNSSEC_INDETERMINATE_CACHE_TTL)),
            )
            .await;

        // `Unchecked` stays stale-servable: it is a legitimate status when
        // local validation is inactive, and the status-aware pipeline gate
        // decides whether it may be used.
        let unchecked_name = Name::from_str("stale-unchecked-getter.example.").unwrap();
        let unchecked_query = query_for(122, &unchecked_name);
        let mut unchecked_response = answer_response(122, &unchecked_name, [192, 0, 2, 122]);
        unchecked_response.answers[0].ttl = 1;
        cache.insert(&unchecked_query, &unchecked_response).await;
        cache
            .backdate_entry_for_test(&unchecked_query, Duration::from_secs(2))
            .await;

        // The status-aware getter is the unfiltered inspection form.
        assert_eq!(
            cache
                .get_stale_for_query_with_status(&bogus_query)
                .await
                .map(|(_, status)| status),
            Some(ValidationStatus::Bogus),
            "the status-aware stale getter must still expose a Bogus entry"
        );
        assert_eq!(
            cache
                .get_stale_for_query_with_status(&indeterminate_query)
                .await
                .map(|(_, status)| status),
            Some(ValidationStatus::Indeterminate),
            "the status-aware stale getter must still expose an Indeterminate entry"
        );

        // Both status-less getters hide fail-closed and inconclusive entries.
        assert!(
            cache
                .get_stale(&bogus_name, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "get_stale must not return a stale Bogus entry"
        );
        assert!(
            cache.get_stale_for_query(&bogus_query).await.is_none(),
            "get_stale_for_query must not return a stale Bogus entry"
        );
        assert!(
            cache
                .get_stale(&indeterminate_name, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "get_stale must not return a stale Indeterminate entry"
        );
        assert!(
            cache
                .get_stale_for_query(&indeterminate_query)
                .await
                .is_none(),
            "get_stale_for_query must not return a stale Indeterminate entry"
        );

        assert!(
            cache
                .get_stale(&unchecked_name, RecordType::A, DNSClass::IN)
                .await
                .is_some(),
            "Unchecked must remain returnable from the status-less stale getters"
        );
        assert!(
            cache.get_stale_for_query(&unchecked_query).await.is_some(),
            "Unchecked must remain returnable from the status-less stale getters"
        );
    }

    /// Entries copied from an older cache generation may carry raw record TTL
    /// vectors that were never clamped to the status-bound window. The fresh
    /// read path must re-clamp them so the short failure lifespan is a cache
    /// invariant, not just an insert-time convention.
    #[tokio::test]
    async fn test_old_failure_entry_record_ttls_are_capped_on_read() {
        let cache = DnsCache::new(make_test_config(1, 3600, 1800));
        let qname = Name::from_str("old-indeterminate.example.").unwrap();
        let query = query_for(123, &qname);
        let mut response = answer_response(123, &qname, [192, 0, 2, 123]);
        response.answers[0].ttl = 3600;
        response.authorities.push(Record::from_rdata(
            qname.clone(),
            3600,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 124))),
        ));
        response.additionals.push(Record::from_rdata(
            qname.clone(),
            3600,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 125))),
        ));

        cache
            .insert_raw_entry_for_test(
                &query,
                &response,
                ValidationStatus::Indeterminate,
                3600,
                3600,
            )
            .await;

        let (cached, status) = cache
            .get_for_query_with_status(&query)
            .await
            .expect("the injected entry must still be fresh");
        assert_eq!(status, ValidationStatus::Indeterminate);
        for record in cached
            .answers
            .iter()
            .chain(cached.authorities.iter())
            .chain(cached.additionals.iter())
        {
            assert!(
                record.ttl <= DNSSEC_INDETERMINATE_CACHE_TTL,
                "an uncapped old record TTL must be clamped on read (got {})",
                record.ttl
            );
        }

        // The entry's own remaining lifespan is a second upper bound: even a
        // record TTL under the status window must not outlive the entry.
        let short_name = Name::from_str("old-short-indeterminate.example.").unwrap();
        let short_query = query_for(124, &short_name);
        cache
            .insert_raw_entry_for_test(
                &short_query,
                &answer_response(124, &short_name, [192, 0, 2, 126]),
                ValidationStatus::Indeterminate,
                3600,
                20,
            )
            .await;
        let (short_cached, _) = cache
            .get_for_query_with_status(&short_query)
            .await
            .expect("the short-lived injected entry must still be fresh");
        for record in short_cached
            .answers
            .iter()
            .chain(short_cached.authorities.iter())
            .chain(short_cached.additionals.iter())
        {
            assert!(
                record.ttl <= 20,
                "a record TTL must not outlive the entry's remaining lifespan (got {})",
                record.ttl
            );
        }
    }

    #[tokio::test]
    async fn test_validation_failure_rejects_mismatched_question() {
        let cache = DnsCache::new(make_test_config(10, 3600, 1800));
        let qname = Name::from_str("bogus-question.example.").unwrap();
        let query = query_for(117, &qname);
        let other = Name::from_str("other-question.example.").unwrap();
        let mismatched = servfail_response(117, &query_for(117, &other));

        assert!(
            !cache
                .insert_validation_failure_at_epochs(
                    &query,
                    &mismatched,
                    ValidationStatus::Bogus,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await,
            "a failure response for a different question must never be cached"
        );
        assert!(cache.get_for_query_with_status(&query).await.is_none());
    }

    #[tokio::test]
    async fn test_indeterminate_reclamp_never_extends_past_original_lifespan() {
        let cache = DnsCache::new(make_test_config(1, 3600, 1800));
        let qname = Name::from_str("indeterminate-reclamp.example.").unwrap();
        let query = query_for(118, &qname);
        let mut response = answer_response(118, &qname, [192, 0, 2, 118]);
        response.answers[0].ttl = 5;
        cache
            .insert_with_status(&query, &response, ValidationStatus::Indeterminate)
            .await;

        // A raised min_ttl must not stretch the 5 s lifespan the entry was
        // stored with (the re-clamp may tighten, never extend).
        let mut raised = make_test_config(20, 3600, 1800);
        raised.min_ttl = 20;
        cache.update_config(raised).await;

        cache
            .backdate_entry_for_test(&query, Duration::from_secs(6))
            .await;
        assert!(
            cache.get_for_query_with_status(&query).await.is_none(),
            "a min_ttl increase must not extend an Indeterminate entry past \
             its original lifespan"
        );
    }

    #[tokio::test]
    async fn test_bogus_validation_failure_requires_servfail_without_answers() {
        let cache = DnsCache::new(make_test_config(10, 3600, 1800));
        let qname = Name::from_str("bogus-shape.example.").unwrap();
        let query = query_for(113, &qname);

        let mut with_answer = servfail_response(113, &query);
        with_answer.answers.push(Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 113))),
        ));
        assert!(
            !cache
                .insert_validation_failure_at_epochs(
                    &query,
                    &with_answer,
                    ValidationStatus::Bogus,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await,
            "a failure entry must never carry answer data"
        );

        let mut with_authority = servfail_response(113, &query);
        with_authority.authorities.push(Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 113))),
        ));
        assert!(
            !cache
                .insert_validation_failure_at_epochs(
                    &query,
                    &with_authority,
                    ValidationStatus::Bogus,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await,
            "a failure entry must never carry authority data"
        );

        let mut with_additional = servfail_response(113, &query);
        with_additional.additionals.push(Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 113))),
        ));
        assert!(
            !cache
                .insert_validation_failure_at_epochs(
                    &query,
                    &with_additional,
                    ValidationStatus::Bogus,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await,
            "a failure entry must never carry additional data"
        );

        let noerror = answer_response(113, &qname, [192, 0, 2, 113]);
        assert!(
            !cache
                .insert_validation_failure_at_epochs(
                    &query,
                    &noerror,
                    ValidationStatus::Bogus,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await,
            "only a SERVFAIL response may be stored as a Bogus failure"
        );

        assert!(
            !cache
                .insert_validation_failure_at_epochs(
                    &query,
                    &servfail_response(113, &query),
                    ValidationStatus::Secure,
                    cache.policy_epoch(),
                    cache.filter_epoch(),
                    DNSSEC_BOGUS_CACHE_TTL,
                )
                .await,
            "only a fail-closed status may create a failure entry"
        );
    }

    #[tokio::test]
    async fn test_indeterminate_lifespan_and_record_ttls_are_capped() {
        let cache = DnsCache::new(make_test_config(10, 3600, 1800));
        let qname = Name::from_str("indeterminate-ttl.example.").unwrap();
        let query = query_for(114, &qname);
        let response = answer_response(114, &qname, [192, 0, 2, 114]);

        cache
            .insert_with_status(&query, &response, ValidationStatus::Indeterminate)
            .await;
        assert_eq!(
            DNSSEC_INDETERMINATE_CACHE_TTL, 30,
            "the Indeterminate window is 30 s"
        );

        cache
            .backdate_entry_for_test(&query, Duration::from_secs(29))
            .await;
        let (cached, status) = cache
            .get_for_query_with_status(&query)
            .await
            .expect("still fresh before the 30 s cap");
        assert_eq!(status, ValidationStatus::Indeterminate);
        assert!(
            cached.answers[0].ttl <= 1,
            "record TTLs must be capped by the 30 s lifespan (got {})",
            cached.answers[0].ttl
        );

        cache
            .backdate_entry_for_test(
                &query,
                Duration::from_secs(u64::from(DNSSEC_INDETERMINATE_CACHE_TTL)),
            )
            .await;
        assert!(
            cache.get_for_query_with_status(&query).await.is_none(),
            "Indeterminate data must not linger past DNSSEC_INDETERMINATE_CACHE_TTL"
        );
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
        cache
            .insert_with_status(&query, &response, ValidationStatus::Secure)
            .await;

        let fresh = cache
            .get(&qname, RecordType::A, DNSClass::IN)
            .await
            .expect("fresh hit");
        assert!(fresh.metadata.authentic_data, "fresh Secure entry keeps AD");

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
    async fn test_out_of_bailiwick_answer_owner_is_not_cached() {
        let config = make_test_config(10, 3600, 1800);
        let cache = DnsCache::new(config);

        let qname = Name::from_str("asked.example.").unwrap();
        let injected = Name::from_str("victim.other.").unwrap();

        // Question matches the query, but the answer RRset belongs to an
        // unrelated owner: classic additional-section injection.
        let query = query_for(50, &qname);
        let mut response = answer_response(50, &injected, [192, 0, 2, 50]);
        response.queries = query.queries.clone();

        cache.insert(&query, &response).await;
        assert!(
            cache
                .get(&qname, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "out-of-bailiwick answer owners must not be cached"
        );

        // A legitimate CNAME chain (qname -> target) remains cacheable.
        let target = Name::from_str("target.example.").unwrap();
        let mut cname = response.clone();
        cname.answers = vec![
            Record::from_rdata(
                qname.clone(),
                60,
                RData::CNAME(sito_proto::rdata::CNAME(target.clone())),
            ),
            Record::from_rdata(
                target.clone(),
                60,
                RData::A(sito_proto::rdata::A("192.0.2.51".parse().unwrap())),
            ),
        ];
        cache.insert(&query, &cname).await;
        assert!(
            cache
                .get(&qname, RecordType::A, DNSClass::IN)
                .await
                .is_some(),
            "a CNAME chain to the queried name must stay cacheable"
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

    /// P2-22: a hot reload that lowers `max_ttl` must immediately cap every
    /// still-fresh entry. Waiting for the old (longer) lifespan to expire
    /// would serve a TTL above the configured maximum.
    #[tokio::test]
    async fn test_update_config_reclamps_lowered_max_ttl() {
        let mut config = make_test_config(0, 3600, 3600);
        let cache = DnsCache::new(config.clone());
        let qname = Name::from_str("reclamp-max.example.").unwrap();
        let query = query_for(100, &qname);
        let mut response = answer_response(100, &qname, [192, 0, 2, 100]);
        response.answers[0].ttl = 300;
        cache
            .insert_with_status(&query, &response, ValidationStatus::Insecure)
            .await;

        config.max_ttl = 10;
        cache.update_config(config).await;

        let served = cache
            .get_for_query(&query)
            .await
            .expect("entry is still within its lifespan");
        assert!(
            served.answers[0].ttl <= 10,
            "a lowered max_ttl must cap the served TTL (got {})",
            served.answers[0].ttl
        );
        assert!(
            served.answers[0].ttl >= 9,
            "the re-clamped TTL must not be zeroed while the entry is fresh"
        );
    }

    /// P2-22: a hot reload that raises `min_ttl` must immediately raise the
    /// served TTL of unvalidated entries instead of serving the old floor.
    #[tokio::test]
    async fn test_update_config_reclamps_raised_min_ttl() {
        let mut config = make_test_config(10, 3600, 3600);
        let cache = DnsCache::new(config.clone());
        let qname = Name::from_str("reclamp-min.example.").unwrap();
        let query = query_for(101, &qname);
        let mut response = answer_response(101, &qname, [192, 0, 2, 101]);
        response.answers[0].ttl = 10;
        cache
            .insert_with_status(&query, &response, ValidationStatus::Insecure)
            .await;

        config.min_ttl = 120;
        cache.update_config(config).await;

        let served = cache
            .get_for_query(&query)
            .await
            .expect("entry must stay fresh");
        assert!(
            served.answers[0].ttl >= 119,
            "a raised min_ttl must lift the served TTL (got {})",
            served.answers[0].ttl
        );
        assert!(
            served.answers[0].ttl <= 120,
            "the served TTL must not exceed the raised floor"
        );
    }

    /// Secure entries keep the `floor = 0` rule on reload: `min_ttl` must
    /// never extend an authenticated TTL past its signed lifetime.
    #[tokio::test]
    async fn test_update_config_does_not_raise_secure_ttl_to_min_ttl() {
        let mut config = make_test_config(0, 3600, 3600);
        let cache = DnsCache::new(config.clone());
        let qname = Name::from_str("reclamp-secure.example.").unwrap();
        let query = query_for(102, &qname);
        let mut response = answer_response(102, &qname, [192, 0, 2, 102]);
        response.answers[0].ttl = 10;
        cache
            .insert_with_status(&query, &response, ValidationStatus::Secure)
            .await;

        config.min_ttl = 120;
        cache.update_config(config).await;

        let served = cache
            .get_for_query(&query)
            .await
            .expect("entry must stay fresh");
        assert!(
            (9..=10).contains(&served.answers[0].ttl),
            "a raised min_ttl must not extend a Secure TTL (got {})",
            served.answers[0].ttl
        );
    }

    /// P2-22: a lowered `negative_ttl_max` must re-clamp negative entries,
    /// including their SOA authority record.
    /// P-5: `CachePolicyEpoch` is the same counter/type as the WP-1.4
    /// `PolicyEpoch` (and therefore `RuntimeGeneration`), not a second epoch.
    #[test]
    fn test_cache_policy_epoch_is_policy_epoch() {
        fn same_type(_: CachePolicyEpoch, _: PolicyEpoch) {}
        let epoch: CachePolicyEpoch = PolicyEpoch::INITIAL;
        same_type(epoch, epoch);
        assert_eq!(epoch, PolicyEpoch::INITIAL);
        assert_eq!(epoch.next(), PolicyEpoch::new(2));
    }

    /// P2-22: an entry whose original lifespan has passed is not fresh. A
    /// raised `min_ttl` on reload must not resurrect it as a fresh entry.
    #[tokio::test]
    async fn test_update_config_does_not_resurrect_fully_expired_entries() {
        let mut config = make_test_config(1, 10, 300);
        config.serve_stale_hours = 0;
        let cache = DnsCache::new(config.clone());
        let qname = Name::from_str("reclamp-expired.example.").unwrap();
        let query = query_for(104, &qname);
        let mut response = answer_response(104, &qname, [192, 0, 2, 104]);
        response.answers[0].ttl = 10;
        cache
            .insert_with_status(&query, &response, ValidationStatus::Insecure)
            .await;

        cache
            .backdate_entry_for_test(&query, Duration::from_secs(60))
            .await;

        config.min_ttl = 3600;
        config.max_ttl = 3600;
        cache.update_config(config).await;

        assert!(
            cache.get_for_query(&query).await.is_none(),
            "a fully expired entry must not be resurrected by a raised min_ttl"
        );
    }

    /// RFC 8767 recommends a 30-second stale TTL, but the configured
    /// `max_ttl` is still a hard ceiling for data this resolver serves.
    #[tokio::test]
    async fn test_stale_serve_ttl_is_capped_by_max_ttl() {
        for (max_ttl, expected) in [(5u32, 5u32), (3600, 30)] {
            let mut config = make_test_config(1, max_ttl, 300);
            config.serve_stale_hours = 1;
            let cache = DnsCache::new(config);

            let qname = Name::from_str(&format!("stale-ttl-{max_ttl}.example.")).unwrap();
            let query = query_for(130, &qname);
            let mut response = answer_response(130, &qname, [192, 0, 2, 130]);
            response.answers[0].ttl = 1;
            cache.insert(&query, &response).await;
            cache
                .backdate_entry_for_test(&query, Duration::from_secs(2))
                .await;

            let stale = cache
                .get_stale(&qname, RecordType::A, DNSClass::IN)
                .await
                .expect("entry is still inside the stale window");
            assert_eq!(
                stale.answers[0].ttl, expected,
                "stale TTL must be min(RFC 8767 30s, max_ttl={max_ttl})"
            );
        }
    }

    /// P2-22: lowering `serve_stale_hours` on reload must evict entries that
    /// are now fully past the new stale window, keep entries still inside it,
    /// and a later raise must not resurrect what was evicted.
    #[tokio::test]
    async fn test_update_config_reclamps_serve_stale_window() {
        let mut config = make_test_config(1, 1, 300);
        config.serve_stale_hours = 2;
        let cache = DnsCache::new(config.clone());

        let expired_name = Name::from_str("stale-window-expired.example.").unwrap();
        let expired_query = query_for(131, &expired_name);
        let mut expired_response = answer_response(131, &expired_name, [192, 0, 2, 131]);
        expired_response.answers[0].ttl = 1;
        cache.insert(&expired_query, &expired_response).await;
        cache
            .backdate_entry_for_test(&expired_query, Duration::from_mins(90))
            .await;

        let kept_name = Name::from_str("stale-window-kept.example.").unwrap();
        let kept_query = query_for(132, &kept_name);
        let mut kept_response = answer_response(132, &kept_name, [192, 0, 2, 132]);
        kept_response.answers[0].ttl = 1;
        cache.insert(&kept_query, &kept_response).await;
        cache
            .backdate_entry_for_test(&kept_query, Duration::from_mins(30))
            .await;

        // Both are stale-servable under the original two-hour window.
        assert!(
            cache
                .get_stale(&expired_name, RecordType::A, DNSClass::IN)
                .await
                .is_some()
        );
        assert!(
            cache
                .get_stale(&kept_name, RecordType::A, DNSClass::IN)
                .await
                .is_some()
        );

        config.serve_stale_hours = 1;
        cache.update_config(config.clone()).await;

        assert!(
            cache
                .get_stale(&expired_name, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "an entry past the lowered stale window must be evicted"
        );
        assert!(
            cache
                .get_stale(&kept_name, RecordType::A, DNSClass::IN)
                .await
                .is_some(),
            "an entry still inside the new stale window must survive"
        );

        config.serve_stale_hours = 48;
        cache.update_config(config).await;
        assert!(
            cache
                .get_stale(&expired_name, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "raising the stale window must not resurrect an evicted entry"
        );
    }

    #[tokio::test]
    async fn test_update_config_reclamps_negative_ttl_max() {
        let mut config = make_test_config(10, 3600, 3600);
        let cache = DnsCache::new(config.clone());
        let qname = Name::from_str("reclamp-negative.example.").unwrap();
        let query = query_for(103, &qname);
        let mut response = Message::response(103, OpCode::Query);
        response.queries = query.queries.clone();
        response.metadata.response_code = ResponseCode::NXDomain;
        response.authorities.push(Record::from_rdata(
            Name::from_str("example.").unwrap(),
            600,
            RData::SOA(SOA::new(
                Name::from_str("ns1.example.").unwrap(),
                Name::from_str("hostmaster.example.").unwrap(),
                1,
                7200,
                3600,
                1_209_600,
                600,
            )),
        ));
        cache
            .insert_with_status(&query, &response, ValidationStatus::Insecure)
            .await;

        config.negative_ttl_max = 30;
        cache.update_config(config).await;

        let served = cache
            .get_for_query(&query)
            .await
            .expect("negative entry must stay cached");
        assert_eq!(served.metadata.response_code, ResponseCode::NXDomain);
        assert!(
            served.authorities[0].ttl <= 30,
            "a lowered negative_ttl_max must cap the served SOA TTL (got {})",
            served.authorities[0].ttl
        );
    }
}
