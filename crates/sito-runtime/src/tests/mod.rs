//! WP-1.4 regression tests for staged, atomic runtime generation changes.

use super::*;
use sito_cache::ValidationStatus;
use sito_filter::{FilterSnapshot, parse_rules};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn config_with(port: u16, rule: Option<&str>) -> Config {
    let mut config = Config::default();
    config.dns.port = port;
    if let Some(rule) = rule {
        config.filtering.enabled = true;
        config.filtering.custom_rules = vec![rule.to_string()];
    }
    config
}

fn compiled(rule: &str) -> Arc<FilterSnapshot> {
    let (rules, _rejected) = parse_rules(rule, "test");
    Arc::new(FilterSnapshot::compile(rules))
}

fn plan(port: u16, rule: &str) -> ApplyPlan {
    let config = config_with(port, Some(rule));
    ApplyPlan {
        config: config.clone(),
        clients: ClientsConfig::default(),
        rewrites: RewritesConfig::default(),
        filter: Some(compiled(rule)),
        group_filters: Arc::new(GroupSnapshots::default()),
        dnssec_policy: DnssecPolicy::from_config(&config.dns.dnssec),
        cache_policy: config.dns.cache.clone(),
        transport_policy: TransportPolicy::from(&config),
    }
}

fn state() -> (Arc<RuntimeState>, Arc<DnsCache>) {
    let config = Arc::new(ArcSwap::new(Arc::new(Config::default())));
    let clients = Arc::new(ArcSwap::new(Arc::new(ClientRegistry::new(
        ClientsConfig::default(),
    ))));
    let rewrites = Arc::new(ArcSwap::new(Arc::new(RewriteTable::new(
        RewritesConfig::default(),
    ))));
    let cache = Arc::new(DnsCache::new(Config::default().dns.cache));
    let state =
        Arc::new(RuntimeState::new(config, clients, rewrites).with_cache(Arc::clone(&cache)));
    (state, cache)
}

/// A reader must never observe the new config with the old filter (or the old
/// config with the new filter). The test-only pre-publish hook holds the writer
/// after the plan is fully staged, so the assertion does not depend on timing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_query_during_apply_sees_old_or_new_never_torn() {
    let (state, _cache) = state();
    state
        .apply(plan(5300, "||old.example^"))
        .await
        .expect("initial generation");

    let staged = Arc::new(AtomicBool::new(false));
    let rounds = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let pairs = Arc::new(Mutex::new(HashSet::<(u16, Option<String>)>::new()));

    let reader_state = Arc::clone(&state);
    let reader_staged = Arc::clone(&staged);
    let reader_rounds = Arc::clone(&rounds);
    let reader_stop = Arc::clone(&stop);
    let reader_pairs = Arc::clone(&pairs);
    let reader = std::thread::spawn(move || {
        while !reader_stop.load(Ordering::Acquire) {
            let snapshot = reader_state.snapshot();
            let rule = snapshot
                .filter
                .as_ref()
                .and_then(|filter| filter.rules.first().map(|rule| rule.raw.clone()));
            reader_pairs
                .lock()
                .unwrap()
                .insert((snapshot.config.dns.port, rule));
            reader_rounds.fetch_add(1, Ordering::AcqRel);
            if reader_staged.load(Ordering::Acquire) {
                // Keep reading while the writer is parked before the store.
                std::hint::spin_loop();
            }
        }
    });

    let hook_staged = Arc::clone(&staged);
    let hook_rounds = Arc::clone(&rounds);
    state.set_before_publish_hook(Some(Arc::new(move || {
        hook_staged.store(true, Ordering::Release);
        // Deterministic barrier: wait until the reader has observed at least
        // 1_000 complete old generations while the plan is staged.
        while hook_rounds.load(Ordering::Acquire) < 1_000 {
            std::hint::spin_loop();
        }
    })));

    state
        .apply(plan(5301, "||new.example^"))
        .await
        .expect("staged apply");
    stop.store(true, Ordering::Release);
    reader.join().expect("reader thread");

    let pairs = pairs.lock().unwrap();
    assert!(
        pairs.contains(&(5300, Some("||old.example^".to_string()))),
        "the reader must observe the old generation: {pairs:?}"
    );
    assert!(
        pairs.contains(&(5301, Some("||new.example^".to_string()))),
        "the reader must observe the new generation: {pairs:?}"
    );
    for (port, rule) in pairs.iter() {
        let expected = match port {
            5300 => "||old.example^",
            5301 => "||new.example^",
            other => panic!("unexpected port {other}"),
        };
        assert_eq!(
            rule.as_deref(),
            Some(expected),
            "config and filter must come from the same generation"
        );
    }
}

/// A rejected stage publishes nothing: the generation, config and filter
/// snapshot stay exactly as before.
#[tokio::test]
async fn test_failed_stage_leaves_old_generation_and_components() {
    let (state, _cache) = state();
    state
        .apply(plan(5302, "||keep.example^"))
        .await
        .expect("initial generation");
    let before = state.snapshot();
    let generation = before.generation;

    // Validation failure (cache policy is internally inconsistent).
    let mut invalid = plan(5399, "||must-not-stick.example^");
    invalid.config.dns.cache.min_ttl = 600;
    invalid.config.dns.cache.max_ttl = 60;
    invalid.cache_policy = invalid.config.dns.cache.clone();
    let error = state
        .apply(invalid)
        .await
        .expect_err("invalid config must be rejected");
    assert!(matches!(error, ApplyError::Validation(_)), "got {error:?}");

    // Filter-stage failure: filtering is enabled but no compiled snapshot.
    let mut missing_filter = plan(5398, "||must-not-stick.example^");
    missing_filter.filter = None;
    let error = state
        .apply(missing_filter)
        .await
        .expect_err("missing filter must be rejected");
    assert!(matches!(error, ApplyError::Filter(_)), "got {error:?}");

    let after = state.snapshot();
    assert_eq!(after.generation, generation);
    assert_eq!(after.config.dns.port, 5302);
    assert_eq!(
        after.config.filtering.custom_rules,
        vec!["||keep.example^".to_string()]
    );
    assert!(
        Arc::ptr_eq(
            before.filter.as_ref().expect("old filter"),
            after.filter.as_ref().expect("current filter")
        ),
        "the old filter snapshot must remain active"
    );
}

#[tokio::test]
async fn test_generation_increments_and_conflicts_are_reported() {
    let (state, _cache) = state();
    let initial = state.generation();

    let first = state.apply(plan(5303, "||one.example^")).await.unwrap();
    assert_eq!(first, initial.next());
    assert_eq!(state.generation(), first);
    assert_eq!(state.apply_count(), 1);

    let error = state
        .apply_expecting(plan(5304, "||two.example^"), Some(initial))
        .await
        .expect_err("stale generation must conflict");
    match error {
        ApplyError::GenerationConflict { expected, actual } => {
            assert_eq!(expected, initial);
            assert_eq!(actual, first);
        }
        other => panic!("expected GenerationConflict, got {other:?}"),
    }
    assert_eq!(state.generation(), first, "a conflict publishes nothing");

    let second = state
        .apply_expecting(plan(5304, "||two.example^"), Some(first))
        .await
        .unwrap();
    assert_eq!(second, first.next());
    assert_eq!(state.apply_count(), 2);
}

/// Rule 4 / D9: after a DNSSEC policy change, an in-flight query that captured
/// the old cache epoch cannot insert an old-policy validation decision into the
/// new generation.
#[tokio::test]
async fn test_dnssec_policy_change_rejects_in_flight_old_epoch_insert() {
    use sito_proto::{DNSClass, Message, MessageType, OpCode, Query, RData, Record, RecordType};

    let (state, cache) = state();
    state
        .apply(plan(5305, "||dnssec.example^"))
        .await
        .expect("initial generation");
    let old_epoch = state.generation();
    assert_eq!(cache.policy_epoch(), old_epoch);

    let mut next = plan(5305, "||dnssec.example^");
    next.config.dns.dnssec.mode = "log_only".to_string();
    next.dnssec_policy = DnssecPolicy::from_config(&next.config.dns.dnssec);
    let new_epoch = state.apply(next).await.expect("policy change apply");
    assert!(new_epoch > old_epoch);

    let name = sito_proto::Name::from_ascii("dnssec.example.").unwrap();
    let mut query = Message::new(7, MessageType::Query, OpCode::Query);
    query
        .queries
        .push(Query::query(name.clone(), RecordType::A));
    let mut response = Message::response(7, OpCode::Query);
    response.queries = query.queries.clone();
    response.answers.push(Record::from_rdata(
        name.clone(),
        300,
        RData::A(sito_proto::rdata::A("192.0.2.44".parse().unwrap())),
    ));

    // The in-flight query validated under the old policy and captured the old
    // epoch before the apply. Its insert must be rejected.
    let accepted = cache
        .insert_with_status_at_epoch(&query, &response, ValidationStatus::Insecure, old_epoch)
        .await;
    assert!(
        !accepted,
        "an old-policy insert must not become visible after the new generation"
    );
    assert!(
        cache
            .get(&name, RecordType::A, DNSClass::IN)
            .await
            .is_none(),
        "the rejected entry must not be cached"
    );

    // The same insert with the current epoch is accepted, proving the rejection
    // is due to the generation rather than an unrelated validation failure.
    assert!(
        cache
            .insert_with_status_at_epoch(&query, &response, ValidationStatus::Insecure, new_epoch)
            .await
    );
    assert!(
        cache
            .get(&name, RecordType::A, DNSClass::IN)
            .await
            .is_some()
    );
}

/// A filter-only refresh must not advance the config/DNSSEC generation. That is
/// what makes a conflict after the listener/upstream commit unreachable.
#[tokio::test]
async fn test_filter_refresh_does_not_advance_config_generation() {
    let (state, cache) = state();
    state
        .apply(plan(5310, "||config.example^"))
        .await
        .expect("initial generation");
    let generation = state.generation();
    let applies = state.apply_count();

    let refreshed = compiled("||refresh.example^");
    let returned = state
        .publish_filter(
            Some(Arc::clone(&refreshed)),
            Arc::new(GroupSnapshots::default()),
            generation,
        )
        .expect("refresh for the current generation");
    assert_eq!(returned, generation);
    assert_eq!(state.generation(), generation);
    assert_eq!(
        state.apply_count(),
        applies,
        "a refresh is not a config apply"
    );
    assert!(Arc::ptr_eq(
        state.snapshot().filter.as_ref().expect("filter"),
        &refreshed
    ));
    assert_eq!(cache.policy_epoch(), generation);

    // A refresh compiled for an older generation is rejected instead of
    // overwriting the newer filter.
    let stale = compiled("||stale.example^");
    let error = state
        .publish_filter(
            Some(stale),
            Arc::new(GroupSnapshots::default()),
            generation.next(),
        )
        .expect_err("stale refresh must be rejected");
    assert!(matches!(error, ApplyError::GenerationConflict { .. }));
    assert!(Arc::ptr_eq(
        state.snapshot().filter.as_ref().expect("filter"),
        &refreshed
    ));
}

/// The review's race: a filter refresh that starts while an apply is in its
/// commit phase cannot swap a component or make the apply return 409 after the
/// listener/upstream commit.
#[tokio::test]
async fn test_filter_refresh_racing_apply_cannot_swap_components() {
    let (state, _cache) = state();
    state
        .apply(plan(5311, "||base.example^"))
        .await
        .expect("initial generation");
    let generation = state.generation();

    let refresh = compiled("||racing-refresh.example^");
    let before_publish_state = Arc::clone(&state);
    let before_publish = async move {
        // A refresh attempts to publish while the apply holds the apply mutex.
        let error = before_publish_state
            .publish_filter(
                Some(refresh),
                Arc::new(GroupSnapshots::default()),
                generation,
            )
            .expect_err("a refresh must not publish during an apply commit");
        assert!(matches!(error, ApplyError::GenerationConflict { .. }));
        Ok(())
    };

    let generation_after = state
        .apply_expecting_with(
            plan(5312, "||applied.example^"),
            Some(generation),
            before_publish,
        )
        .await
        .expect("apply must not conflict after its generation check");
    assert_eq!(generation_after, generation.next());
    let snapshot = state.snapshot();
    assert_eq!(snapshot.config.dns.port, 5312);
    assert_eq!(
        snapshot
            .filter
            .as_ref()
            .expect("filter")
            .rules
            .first()
            .map(|rule| rule.raw.as_str()),
        Some("||applied.example^"),
        "the apply's filter must be the visible one"
    );
}

/// A failure in the before-publish commit stage publishes nothing.
#[tokio::test]
async fn test_commit_stage_failure_publishes_nothing() {
    let (state, _cache) = state();
    state
        .apply(plan(5313, "||before.example^"))
        .await
        .expect("initial generation");
    let before = state.snapshot();
    let generation = before.generation;

    let error = state
        .apply_expecting_with(
            plan(5314, "||commit-fail.example^"),
            Some(generation),
            async { Err(ApplyError::Internal("injected commit failure".to_string())) },
        )
        .await
        .expect_err("commit failure must reject the apply");
    assert!(matches!(error, ApplyError::Internal(_)));
    let after = state.snapshot();
    assert_eq!(after.generation, generation);
    assert_eq!(after.config.dns.port, 5313);
    assert!(
        Arc::ptr_eq(
            before.filter.as_ref().expect("old filter"),
            after.filter.as_ref().expect("current filter")
        ),
        "the old filter must remain active"
    );
}
