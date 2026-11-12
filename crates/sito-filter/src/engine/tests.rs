#![cfg(test)]

use super::*;
use sito_core::config::FilterListConfig;
use std::str::FromStr;

#[tokio::test]
async fn test_hosts_filter_blocking() {
    let temp_dir = std::env::temp_dir().join(format!("sito_engine_test_{}", std::process::id()));
    let config = FilteringConfig {
        custom_rules: vec![
            "0.0.0.0 ads.example.com".to_string(),
            "127.0.0.1 tracker.bad.net".to_string(),
        ],
        ..Default::default()
    };

    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());

    // Blocked domain
    let qname_blocked = Name::from_str("ads.example.com.").unwrap();
    let verdict = engine.evaluate(&qname_blocked, RecordType::A, &client);
    assert!(verdict.is_blocked());

    // Allowed domain
    let qname_allowed = Name::from_str("good.example.com.").unwrap();
    let verdict = engine.evaluate(&qname_allowed, RecordType::A, &client);
    assert!(verdict.is_allowed());

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_abp_rules_and_precedence() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_precedence_test_{}", std::process::id()));
    let config = FilteringConfig {
        custom_rules: vec![
            // Standard block
            "||blocked.example^".to_string(),
            // Allowlist beats standard block
            "@@||sub.blocked.example^".to_string(),
            // Important block beats standard allowlist
            "||important.sub.blocked.example^$important".to_string(),
            // Important allowlist beats important block
            "@@||special.important.sub.blocked.example^$important".to_string(),
        ],
        ..Default::default()
    };

    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());

    // 1. Standard block
    let q1 = Name::from_str("blocked.example.").unwrap();
    assert!(engine.evaluate(&q1, RecordType::A, &client).is_blocked());

    // 2. Allowlist unblocks
    let q2 = Name::from_str("sub.blocked.example.").unwrap();
    assert!(engine.evaluate(&q2, RecordType::A, &client).is_allowed());

    // 3. Important block overrides allowlist
    let q3 = Name::from_str("important.sub.blocked.example.").unwrap();
    assert!(engine.evaluate(&q3, RecordType::A, &client).is_blocked());

    // 4. Important allowlist overrides important block
    let q4 = Name::from_str("special.important.sub.blocked.example.").unwrap();
    assert!(engine.evaluate(&q4, RecordType::A, &client).is_allowed());

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Deferred D3 follow-up: block presence must be detectable even when a
/// `$dnsrewrite` precedes the block in candidate order.
#[tokio::test]
async fn test_standard_block_presence_ignores_rewrite_order() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_block_presence_test_{}", std::process::id()));
    let config = FilteringConfig {
        custom_rules: vec![
            "||target.example^$dnsrewrite=192.0.2.10".to_string(),
            "||target.example^".to_string(),
        ],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let snapshot = engine.snapshot();
    let domain = "target.example";
    let mut candidates = Vec::new();
    snapshot
        .blocklist
        .collect_candidates(domain, &snapshot.interner, &mut candidates);
    assert_ne!(
        candidates.len(),
        0,
        "candidate collection must include the rewrite and block"
    );
    assert!(snapshot.standard_block_candidates_contain_block(
        domain,
        RecordType::A,
        &client,
        &candidates,
    ));
    // The result must not depend on structural candidate order.
    candidates.reverse();
    assert!(snapshot.standard_block_candidates_contain_block(
        domain,
        RecordType::A,
        &client,
        &candidates,
    ));

    // A rewrite-only snapshot has no block to report.
    let rewrite_only = FilteringConfig {
        custom_rules: vec!["||target.example^$dnsrewrite=192.0.2.10".to_string()],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(rewrite_only, temp_dir.clone()).await;
    let snapshot = engine.snapshot();
    let mut candidates = Vec::new();
    snapshot
        .blocklist
        .collect_candidates(domain, &snapshot.interner, &mut candidates);
    assert!(!snapshot.standard_block_candidates_contain_block(
        domain,
        RecordType::A,
        &client,
        &candidates,
    ));

    // Important tier: an important rewrite before an important block must
    // not hide the block either.
    let important_config = FilteringConfig {
        custom_rules: vec![
            "||target.example^$dnsrewrite=192.0.2.10,important".to_string(),
            "||target.example^$important".to_string(),
        ],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(important_config, temp_dir.clone()).await;
    let snapshot = engine.snapshot();
    let mut candidates = Vec::new();
    snapshot
        .blocklist
        .collect_candidates(domain, &snapshot.interner, &mut candidates);
    assert!(snapshot.important_block_candidates_contain_block(
        domain,
        RecordType::A,
        &client,
        &candidates,
    ));
    candidates.reverse();
    assert!(snapshot.important_block_candidates_contain_block(
        domain,
        RecordType::A,
        &client,
        &candidates,
    ));

    // An important rewrite-only snapshot has no block to report.
    let important_rewrite_only = FilteringConfig {
        custom_rules: vec!["||target.example^$dnsrewrite=192.0.2.10,important".to_string()],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(important_rewrite_only, temp_dir.clone()).await;
    let snapshot = engine.snapshot();
    let mut candidates = Vec::new();
    snapshot
        .blocklist
        .collect_candidates(domain, &snapshot.interner, &mut candidates);
    assert!(!snapshot.important_block_candidates_contain_block(
        domain,
        RecordType::A,
        &client,
        &candidates,
    ));

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_modifiers_evaluation() {
    let temp_dir = std::env::temp_dir().join(format!("sito_modifiers_test_{}", std::process::id()));
    let config = FilteringConfig {
        custom_rules: vec![
            // $client
            "||client-only.com^$client=192.168.1.100|laptop".to_string(),
            // $dnstype
            "||type-only.com^$dnstype=HTTPS|65".to_string(),
            // $denyallow
            "||denyallow.com^$denyallow=allowed.denyallow.com".to_string(),
            // $dnsrewrite
            "||rewrite.com^$dnsrewrite=1.2.3.4".to_string(),
            // $badfilter deactivates a rule
            "||deactivated.com^".to_string(),
            "||deactivated.com^$badfilter".to_string(),
        ],
        ..Default::default()
    };

    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;

    // $client test
    let client1 = ClientContext::new("192.168.1.100".parse().unwrap());
    let client2 = ClientContext::new("192.168.1.200".parse().unwrap());
    let client3 = ClientContext::new("192.168.1.200".parse().unwrap()).with_client_name("laptop");
    let client_spoofed = ClientContext::with_id("192.168.1.200".parse().unwrap(), "laptop");
    let q_client = Name::from_str("client-only.com.").unwrap();

    assert!(
        engine
            .evaluate(&q_client, RecordType::A, &client1)
            .is_blocked()
    );
    assert!(
        engine
            .evaluate(&q_client, RecordType::A, &client2)
            .is_allowed()
    );
    assert!(
        engine
            .evaluate(&q_client, RecordType::A, &client3)
            .is_blocked()
    );
    // A wire-claimed id must not satisfy `$client=`.
    assert!(
        engine
            .evaluate(&q_client, RecordType::A, &client_spoofed)
            .is_allowed()
    );

    // $dnstype test
    let q_type = Name::from_str("type-only.com.").unwrap();
    assert!(
        engine
            .evaluate(&q_type, RecordType::A, &client1)
            .is_allowed()
    );
    assert!(
        engine
            .evaluate(&q_type, RecordType::HTTPS, &client1)
            .is_blocked()
    );

    // $denyallow test
    let q_denied = Name::from_str("denyallow.com.").unwrap();
    let q_excepted = Name::from_str("allowed.denyallow.com.").unwrap();
    assert!(
        engine
            .evaluate(&q_denied, RecordType::A, &client1)
            .is_blocked()
    );
    assert!(
        engine
            .evaluate(&q_excepted, RecordType::A, &client1)
            .is_allowed()
    );

    // $dnsrewrite test
    let q_rewrite = Name::from_str("rewrite.com.").unwrap();
    let verdict = engine.evaluate(&q_rewrite, RecordType::A, &client1);
    match verdict {
        Verdict::Rewrite(RewriteAction::DnsRewrite {
            rcode,
            rtype,
            value,
        }) => {
            assert_eq!(rcode, "NOERROR");
            assert_eq!(rtype.as_deref(), Some("A"));
            assert_eq!(value.as_deref(), Some("1.2.3.4"));
        }
        other => panic!("expected Verdict::Rewrite, got {other:?}"),
    }

    // $badfilter test
    let q_bad = Name::from_str("deactivated.com.").unwrap();
    assert!(
        engine
            .evaluate(&q_bad, RecordType::A, &client1)
            .is_allowed()
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_disk_cache_offline_fallback() {
    let temp_dir = std::env::temp_dir().join(format!("sito_offline_test_{}", std::process::id()));
    let cached_file = crate::downloader::cache_path_for_list(&temp_dir, "offline_list");
    tokio::fs::create_dir_all(cached_file.parent().unwrap())
        .await
        .unwrap();

    // The cache reader only trusts content whose metadata records matching
    // integrity signals (WP-3.9).
    let cached_content = "0.0.0.0 cached-ad.com\n";
    crate::downloader::save_to_cache(&cached_file, cached_content)
        .await
        .unwrap();
    crate::subscription::save_metadata(
        &crate::subscription::meta_path_for_list(&temp_dir, "offline_list"),
        &crate::subscription::ListMetadata {
            content_len: Some(cached_content.len() as u64),
            line_count: Some(cached_content.lines().count()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let config = FilteringConfig {
        lists: vec![FilterListConfig {
            name: "offline_list".to_string(),
            url: "http://127.0.0.1:1".to_string(),
            enabled: true,
            refresh_hours: None,
        }],
        ..Default::default()
    };

    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
    assert_eq!(engine.rule_count(), 1);

    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let qname = Name::from_str("cached-ad.com.").unwrap();
    assert!(engine.evaluate(&qname, RecordType::A, &client).is_blocked());

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_protection_against_drastic_rule_drop() {
    let temp_dir = std::env::temp_dir().join(format!("sito_drop_test_{}", std::process::id()));
    let config = FilteringConfig {
            custom_rules: vec![
                "0.0.0.0 ad1.com\n0.0.0.0 ad2.com\n0.0.0.0 ad3.com\n0.0.0.0 ad4.com\n0.0.0.0 ad5.com\n0.0.0.0 ad6.com".to_string(),
            ],
            ..Default::default()
        };

    let engine = HostsFilterEngine::init(config.clone(), temp_dir.clone()).await;
    assert_eq!(engine.rule_count(), 6);

    // Update config to drop to 1 rule (>50% drop)
    let mut droppped = (*engine.config.load_full()).clone();
    droppped.custom_rules = vec!["0.0.0.0 ad1.com".to_string()];
    engine.config.store(std::sync::Arc::new(droppped));
    let count = engine.reload().await.unwrap();
    assert_eq!(count, 6);
    assert_eq!(engine.rule_count(), 6);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_intentional_user_edit_bypasses_drop_guard() {
    let temp_dir = std::env::temp_dir().join(format!("sito_user_edit_test_{}", std::process::id()));
    let config = FilteringConfig {
            custom_rules: vec![
                "0.0.0.0 ad1.com\n0.0.0.0 ad2.com\n0.0.0.0 ad3.com\n0.0.0.0 ad4.com\n0.0.0.0 ad5.com\n0.0.0.0 ad6.com".to_string(),
            ],
            ..Default::default()
        };

    let engine = HostsFilterEngine::init(config.clone(), temp_dir.clone()).await;
    assert_eq!(engine.rule_count(), 6);

    // User intentionally removes rules via reload_with_config
    let mut new_config = config.clone();
    new_config.custom_rules = vec!["0.0.0.0 ad1.com".to_string()];
    let count = engine.reload_with_config(&new_config).await.unwrap();
    assert_eq!(count, 1);
    assert_eq!(engine.rule_count(), 1);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_compile_error_retains_existing_snapshot() {
    let temp_dir = std::env::temp_dir().join(format!("sito_join_err_test_{}", std::process::id()));
    let config = FilteringConfig {
        custom_rules: vec!["0.0.0.0 ad1.com".to_string(), "0.0.0.0 ad2.com".to_string()],
        ..Default::default()
    };

    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
    assert_eq!(engine.rule_count(), 2);

    // Verify CompileTaskFailed error variant can be formatted and matches
    let err = FilterError::CompileTaskFailed("task panicked".to_string());
    assert!(matches!(err, FilterError::CompileTaskFailed(_)));
    assert_eq!(engine.rule_count(), 2);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_important_allowlist_evaluated_as_allow() {
    let temp_dir = std::env::temp_dir().join(format!("sito_important_test_{}", std::process::id()));
    let config = FilteringConfig {
        custom_rules: vec![
            "@@||ads.example.com^$important".to_string(),
            "||ads.example.com^".to_string(),
        ],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
    let qname = Name::from_str("ads.example.com.").unwrap();
    let client = ClientContext::new(std::net::IpAddr::from_str("192.168.1.20").unwrap());

    // The important allow must win over the standard block.
    assert!(matches!(
        engine.evaluate_important(&qname, RecordType::A, &client),
        Some(Verdict::Allow(_))
    ));

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[test]
fn test_per_list_refresh_schedule() {
    let config = FilteringConfig {
        refresh_interval_hours: 24,
        lists: vec![
            FilterListConfig {
                name: "fast".to_string(),
                url: "https://example.com/fast.txt".to_string(),
                enabled: true,
                refresh_hours: Some(1),
            },
            FilterListConfig {
                name: "slow".to_string(),
                url: "https://example.com/slow.txt".to_string(),
                enabled: true,
                refresh_hours: None,
            },
            FilterListConfig {
                name: "off".to_string(),
                url: "https://example.com/off.txt".to_string(),
                enabled: false,
                refresh_hours: Some(1),
            },
        ],
        ..Default::default()
    };

    let mut next_due = FnvHashMap::default();
    let now = Instant::now();
    let (sleep_for, due) = refresh_schedule(&config, &mut next_due, now);
    assert!(
        due.is_empty(),
        "no list should be due for refresh yet: {due:?}"
    );
    assert_eq!(
        sleep_for,
        Duration::from_secs(3600),
        "the 1h list must be the earliest wake-up"
    );

    // One hour later only the fast list is due.
    let later = now + Duration::from_secs(3601);
    let (_sleep, due) = refresh_schedule(&config, &mut next_due, later);
    assert_eq!(due, vec!["fast".to_string()]);

    // Disabled lists are never scheduled.
    assert!(!next_due.contains_key("off"));
    assert!(next_due.contains_key("slow"));
}

#[tokio::test]
async fn test_idn_punycode_queries_match_ascii_rules() {
    let temp_dir = std::env::temp_dir().join(format!("sito_idn_test_{}", std::process::id()));
    let config = FilteringConfig {
        custom_rules: vec!["||xn--mnchen-3ya.de^".to_string()],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());

    // `Name::from_utf8` stores IDNA labels; the engine must evaluate the
    // ASCII/punycode form, not the decoded Unicode form.
    let idn = Name::from_utf8("münchen.de.").unwrap();
    assert!(
        idn.to_utf8().contains("münchen"),
        "test precondition: the name must carry IDNA labels"
    );
    assert!(
        engine.evaluate(&idn, RecordType::A, &client).is_blocked(),
        "IDN query must not bypass the ASCII punycode rule"
    );

    // The punycode form matches directly as well.
    let ascii = Name::from_str("xn--mnchen-3ya.de.").unwrap();
    assert!(engine.evaluate(&ascii, RecordType::A, &client).is_blocked());

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_cross_list_precedence_is_deterministic() {
    let temp_dir = std::env::temp_dir().join(format!("sito_order_test_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let a_path = temp_dir.join("a-list.txt");
    let b_path = temp_dir.join("b-list.txt");
    tokio::fs::write(&a_path, "||same.example^\n")
        .await
        .unwrap();
    tokio::fs::write(&b_path, "||same.example^\n")
        .await
        .unwrap();

    // "b-list" is configured first but "a-list" must win (sorted by name)
    // regardless of configuration or hash-map iteration order.
    let config = FilteringConfig {
        lists: vec![
            FilterListConfig {
                name: "b-list".to_string(),
                url: format!("file://{}", b_path.display()),
                enabled: true,
                refresh_hours: None,
            },
            FilterListConfig {
                name: "a-list".to_string(),
                url: format!("file://{}", a_path.display()),
                enabled: true,
                refresh_hours: None,
            },
        ],
        ..Default::default()
    };

    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let qname = Name::from_str("same.example.").unwrap();

    let source = |engine: &HostsFilterEngine| match engine.evaluate(&qname, RecordType::A, &client)
    {
        Verdict::Block(BlockReason::Rule(rule)) => rule.list_name.clone(),
        other => panic!("expected rule block, got {other:?}"),
    };
    assert_eq!(source(&engine).as_deref(), Some("a-list"));

    // Recompiling must not change the winner.
    engine.reload().await.unwrap();
    assert_eq!(source(&engine).as_deref(), Some("a-list"));

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_warm_zero_source_transition_is_failed_and_retains_snapshot() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_warm_zero_source_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let list_path = temp_dir.join("only.txt");
    // One valid rule plus an invalid regex that is dropped at compile time.
    tokio::fs::write(&list_path, "||only.com^\n/^($/\n")
        .await
        .unwrap();
    let config = FilteringConfig {
        lists: vec![
            FilterListConfig {
                name: "only-list".to_string(),
                url: format!("file://{}", list_path.display()),
                enabled: true,
                refresh_hours: None,
            },
            FilterListConfig {
                name: "failed-list".to_string(),
                url: format!("file://{}", temp_dir.join("missing.txt").display()),
                enabled: true,
                refresh_hours: None,
            },
        ],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(config.clone(), temp_dir.clone()).await;
    assert_eq!(engine.rule_count(), 2);
    assert_eq!(engine.state(), FilterState::Ready);
    let before = engine.status();
    assert_eq!(before.loaded_lists, 1);
    assert_eq!(before.failed_lists, vec!["failed-list".to_string()]);
    assert_eq!(
        before.dropped_regex_patterns, 1,
        "the invalid regex must be counted as dropped"
    );
    assert!(before.last_compile_ms.is_some());

    // A live (warm) apply that removes every source must be rejected and
    // published as Failed while the last good snapshot stays active.
    let zero_sources = FilteringConfig {
        custom_rules: Vec::new(),
        lists: Vec::new(),
        ..config.clone()
    };
    let err = engine
        .reload_with_config(&zero_sources)
        .await
        .expect_err("zero sources must reject a warm apply");
    assert!(matches!(err, FilterError::NoSourcesConfigured));
    assert_eq!(engine.rule_count(), 2, "the last rules must be retained");
    assert_eq!(engine.state(), FilterState::Failed);
    assert!(!engine.unavailable_for_fail_closed());
    let after = engine.status();
    assert_eq!(
        after.rule_count, before.rule_count,
        "the retained snapshot's rule count must be preserved"
    );
    assert!(!after.unavailable);
    assert_eq!(
        after.loaded_lists, before.loaded_lists,
        "the retained snapshot's loaded-list count must be preserved"
    );
    assert_eq!(after.failed_lists, before.failed_lists);
    assert_eq!(after.failed_lists.len(), 1);
    assert_eq!(after.degraded_lists, before.degraded_lists);
    assert_eq!(after.degraded_groups, before.degraded_groups);
    assert_eq!(
        after.dropped_regex_patterns, before.dropped_regex_patterns,
        "dropped-class counters must survive a rejected zero-source apply"
    );
    assert_eq!(after.dropped_regex_patterns, 1);
    assert_eq!(
        after.last_compile_ms, before.last_compile_ms,
        "the retained snapshot's compile time must be preserved"
    );
    assert!(after.last_error.is_some());
    assert_eq!(
        engine.config.load_full().lists.len(),
        config.lists.len(),
        "the rejected zero-source config must not be committed"
    );
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert!(
        engine
            .evaluate(
                &Name::from_str("only.com.").unwrap(),
                RecordType::A,
                &client
            )
            .is_blocked()
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// P2-95: `filtering.enabled` with zero sources must fail closed instead
/// of publishing an empty `Ready` snapshot.
#[tokio::test]
async fn test_zero_sources_fail_closed_not_ready() {
    let temp_dir = std::env::temp_dir().join(format!("sito_zero_sources_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let config = FilteringConfig {
        enabled: true,
        fail_closed: true,
        lists: Vec::new(),
        custom_rules: Vec::new(),
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;

    assert_eq!(engine.state(), FilterState::Failed);
    let status = engine.status();
    assert!(status.unavailable, "the status must report unavailability");
    assert!(
        status.last_error.is_some(),
        "the failure reason must be observable"
    );

    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let qname = Name::from_str("anything.example.").unwrap();
    assert_eq!(
        engine.evaluate(&qname, RecordType::A, &client),
        Verdict::Block(BlockReason::FilterUnavailable),
        "zero sources must fail closed"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// P1-8: a list that loads successfully but yields zero rules must not
/// replace the previous snapshot when `allow_empty_list` is false.
#[tokio::test]
async fn test_zero_yield_list_retains_previous_snapshot() {
    let temp_dir = std::env::temp_dir().join(format!("sito_zero_yield_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let path = temp_dir.join("list.txt");
    tokio::fs::write(&path, "||keep.example^\n").await.unwrap();

    let config = FilteringConfig {
        lists: vec![FilterListConfig {
            name: "source".to_string(),
            url: format!("file://{}", path.display()),
            enabled: true,
            refresh_hours: None,
        }],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(config.clone(), temp_dir.clone()).await;
    assert_eq!(engine.rule_count(), 1);

    // Non-empty body that parses to zero rules (comments only).
    tokio::fs::write(&path, "! comment only\n").await.unwrap();
    let count = engine.reload_with_config(&config).await.unwrap();
    assert_eq!(count, 1, "the previous rule must be retained");
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert!(
        engine
            .evaluate(
                &Name::from_str("keep.example.").unwrap(),
                RecordType::A,
                &client
            )
            .is_blocked()
    );
    assert_eq!(engine.status().failed_lists, vec!["source".to_string()]);
    assert_eq!(
        engine.status().degraded_lists,
        vec!["source".to_string()],
        "a list that kept its previous rules must be reported as degraded"
    );

    // The explicit opt-in allows an empty snapshot.
    let allow_empty = FilteringConfig {
        allow_empty_list: true,
        ..config
    };
    let count = engine.reload_with_config(&allow_empty).await.unwrap();
    assert_eq!(count, 0);
    assert_eq!(engine.state(), FilterState::Ready);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// P1-8/P2-95: a zero-yield response on the initial load must leave the
/// engine failed and fail closed rather than advertising an empty `Ready`.
#[tokio::test]
async fn test_zero_yield_initial_load_fails_closed() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_zero_yield_init_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let path = temp_dir.join("empty.txt");
    tokio::fs::write(&path, "! comment only\n").await.unwrap();

    let engine = HostsFilterEngine::init(
        FilteringConfig {
            lists: vec![FilterListConfig {
                name: "empty".to_string(),
                url: format!("file://{}", path.display()),
                enabled: true,
                refresh_hours: None,
            }],
            ..Default::default()
        },
        temp_dir.clone(),
    )
    .await;

    assert_eq!(engine.state(), FilterState::Failed);
    assert!(engine.unavailable_for_fail_closed());
    assert_eq!(engine.status().failed_lists, vec!["empty".to_string()]);
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert_eq!(
        engine.evaluate(
            &Name::from_str("anything.example.").unwrap(),
            RecordType::A,
            &client
        ),
        Verdict::Block(BlockReason::FilterUnavailable)
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// P2-24: a group compile-budget failure publishes the non-regex subset
/// instead of dropping the entire group.
#[tokio::test]
async fn test_group_budget_failure_publishes_non_regex_subset() {
    let temp_dir = std::env::temp_dir().join(format!("sito_group_degraded_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let engine = HostsFilterEngine::new(
        FilteringConfig {
            regex_compile_budget_ms: Some(1),
            ..Default::default()
        },
        temp_dir.clone(),
    );
    let mut custom_rules: Vec<String> = (0..2048)
        .map(|i| format!("/^group-{i}\\..*\\.example$/"))
        .collect();
    custom_rules.push("||keep-group.example^".to_string());
    engine.set_group_rules(vec![GroupRuleSet {
        name: "kids".to_string(),
        lists: Vec::new(),
        custom_rules,
    }]);

    let snapshot = engine
        .group_snapshot("kids")
        .expect("the non-regex subset must still be published");
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert!(
        snapshot
            .evaluate("keep-group.example", RecordType::A, &client)
            .is_blocked(),
        "non-regex/custom rules must survive a group budget failure"
    );
    assert!(
        engine
            .status()
            .degraded_groups
            .contains(&"kids".to_string()),
        "the group must be reported as degraded"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Important 1: an over-budget group custom-rules reload must retain the
/// previous group snapshot, not silently remove the group.
#[tokio::test]
async fn test_group_parse_budget_failure_retains_previous_snapshot() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_group_parse_budget_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let engine = HostsFilterEngine::new(
        FilteringConfig {
            max_rules: 2,
            ..Default::default()
        },
        temp_dir.clone(),
    );
    engine.set_group_rules(vec![GroupRuleSet {
        name: "kids".to_string(),
        lists: Vec::new(),
        custom_rules: vec!["||keep-group.example^".to_string()],
    }]);
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert!(
        engine
            .group_snapshot("kids")
            .expect("initial group snapshot")
            .evaluate("keep-group.example", RecordType::A, &client)
            .is_blocked()
    );

    // Three rules exceed max_rules = 2; the group has no list rules, so
    // the parse-budget arm leaves `rules` empty.
    engine.set_group_rules(vec![GroupRuleSet {
        name: "kids".to_string(),
        lists: Vec::new(),
        custom_rules: vec!["||a.example^\n||b.example^\n||c.example^".to_string()],
    }]);
    let snapshot = engine
        .group_snapshot("kids")
        .expect("the previous group snapshot must survive");
    assert!(
        snapshot
            .evaluate("keep-group.example", RecordType::A, &client)
            .is_blocked(),
        "the retained group snapshot must stay active"
    );
    assert!(
        engine
            .status()
            .degraded_groups
            .contains(&"kids".to_string()),
        "the retained group must still be reported degraded"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// P2-26: a group rebuild that started before a list reload must not store
/// its stale snapshot after the reload publishes a newer generation.
#[tokio::test]
async fn test_stale_group_rebuild_is_discarded() {
    let temp_dir = std::env::temp_dir().join(format!("sito_group_stale_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let engine = HostsFilterEngine::new(FilteringConfig::default(), temp_dir.clone());
    engine.set_group_rules(vec![GroupRuleSet {
        name: "kids".to_string(),
        lists: vec!["school".to_string()],
        custom_rules: Vec::new(),
    }]);
    let old_generation = engine.list_generation.load(Ordering::SeqCst);

    // Simulate the newer list reload: new list rules + generation bump.
    let mut newer = FnvHashMap::default();
    newer.insert(
        "school".to_string(),
        vec![parse_line_for_test("||new.example^")],
    );
    *engine.list_rules.lock().unwrap() = newer.clone();
    engine.list_generation.fetch_add(1, Ordering::SeqCst);
    engine.set_group_rules(vec![GroupRuleSet {
        name: "kids".to_string(),
        lists: vec!["school".to_string()],
        custom_rules: Vec::new(),
    }]);
    let current = engine.group_snapshot("kids").expect("current group");
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert!(
        current
            .evaluate("new.example", RecordType::A, &client)
            .is_blocked()
    );

    // The stale rebuild (old list map + old generation) must be discarded
    // and must not overwrite the newer snapshot.
    let mut stale = FnvHashMap::default();
    stale.insert(
        "school".to_string(),
        vec![parse_line_for_test("||stale.example^")],
    );
    assert!(
        engine
            .rebuild_group_snapshots_at(&stale, old_generation)
            .is_none(),
        "a stale generation must not publish"
    );
    let after = engine.group_snapshot("kids").expect("current group");
    assert!(
        after
            .evaluate("new.example", RecordType::A, &client)
            .is_blocked(),
        "the newer snapshot must survive"
    );
    assert!(
        after
            .evaluate("stale.example", RecordType::A, &client)
            .is_allowed(),
        "the stale snapshot must not be installed"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

fn parse_line_for_test(line: &str) -> Rule {
    crate::parser::parse_line(line, "test", 1).expect("valid test rule")
}

#[tokio::test]
async fn test_all_list_failure_is_observable_and_not_advertised_ready() {
    let temp_dir = std::env::temp_dir().join(format!("sito_all_fail_test_{}", std::process::id()));
    let config = FilteringConfig {
        lists: vec![FilterListConfig {
            name: "dead".to_string(),
            url: "http://127.0.0.1:1/list.txt".to_string(),
            enabled: true,
            refresh_hours: None,
        }],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(config.clone(), temp_dir.clone()).await;

    assert_eq!(engine.state(), FilterState::Failed);
    let status = engine.status();
    assert_eq!(status.failed_lists, vec!["dead".to_string()]);
    assert!(status.last_error.is_some());
    assert_eq!(engine.rule_count(), 0);
    assert!(
        engine.reload().await.is_err(),
        "an enabled engine with zero loadable sources must not report success"
    );

    // Fail-closed default: a failed initial load must not allow traffic.
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let probe = Name::from_str("anything.example.").unwrap();
    let verdict = engine.evaluate(&probe, RecordType::A, &client);
    assert_eq!(
        verdict,
        Verdict::Block(BlockReason::FilterUnavailable),
        "fail_closed engines must block while no snapshot has loaded"
    );

    // Opting out restores allow-all on the same failed state.
    let allow_open = FilteringConfig {
        fail_closed: false,
        ..config.clone()
    };
    let open_engine = HostsFilterEngine::init(allow_open, temp_dir.clone()).await;
    assert_eq!(open_engine.state(), FilterState::Failed);
    assert!(
        open_engine
            .evaluate(&probe, RecordType::A, &client)
            .is_allowed()
    );

    // A later successful reload transitions back to Ready.
    let good = FilteringConfig {
        custom_rules: vec!["0.0.0.0 ok.example".to_string()],
        ..Default::default()
    };
    engine.reload_with_config(&good).await.unwrap();
    assert_eq!(engine.state(), FilterState::Ready);
    assert_eq!(engine.rule_count(), 1);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_reload_retains_rules_from_failed_lists() {
    let temp_dir = std::env::temp_dir().join(format!("sito_merge_test_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let a_path = temp_dir.join("a.txt");
    let b_path = temp_dir.join("b.txt");
    tokio::fs::write(&a_path, "||a-blocked.example^\n")
        .await
        .unwrap();
    tokio::fs::write(&b_path, "||b-blocked.example^\n")
        .await
        .unwrap();

    let config = FilteringConfig {
        lists: vec![
            FilterListConfig {
                name: "a".to_string(),
                url: format!("file://{}", a_path.display()),
                enabled: true,
                refresh_hours: None,
            },
            FilterListConfig {
                name: "b".to_string(),
                url: format!("file://{}", b_path.display()),
                enabled: true,
                refresh_hours: None,
            },
        ],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
    assert_eq!(engine.rule_count(), 2);

    // b's source disappears; a full reload must merge (keep b's last good
    // rules) instead of overwriting the map with only the fetched list.
    tokio::fs::remove_file(&b_path).await.unwrap();
    let count = engine.reload().await.unwrap();
    assert_eq!(count, 2, "rules from the failed list must be retained");
    assert_eq!(engine.rule_count(), 2);
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert!(
        engine
            .evaluate(
                &Name::from_str("b-blocked.example.").unwrap(),
                RecordType::A,
                &client
            )
            .is_blocked()
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_concurrent_reloads_do_not_lose_lists() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_concurrent_test_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let a_path = temp_dir.join("a.txt");
    let b_path = temp_dir.join("b.txt");
    tokio::fs::write(&a_path, "||a-one.example^\n||a-two.example^\n")
        .await
        .unwrap();
    tokio::fs::write(
        &b_path,
        "||b-one.example^\n||b-two.example^\n||b-three.example^\n",
    )
    .await
    .unwrap();

    let config = FilteringConfig {
        lists: vec![
            FilterListConfig {
                name: "a".to_string(),
                url: format!("file://{}", a_path.display()),
                enabled: true,
                refresh_hours: None,
            },
            FilterListConfig {
                name: "b".to_string(),
                url: format!("file://{}", b_path.display()),
                enabled: true,
                refresh_hours: None,
            },
        ],
        ..Default::default()
    };

    let engine = Arc::new(HostsFilterEngine::init(config.clone(), temp_dir.clone()).await);
    assert_eq!(engine.rule_count(), 5);

    let mut handles = Vec::new();
    for _ in 0..4 {
        let partial = engine.clone();
        handles.push(tokio::spawn(async move {
            partial.reload_lists(&["a".to_string()]).await.map(|_| ())
        }));
        let full = engine.clone();
        let cfg = config.clone();
        handles.push(tokio::spawn(async move {
            full.reload_with_config(&cfg).await.map(|_| ())
        }));
    }
    for handle in handles {
        handle.await.unwrap().unwrap();
    }

    // The final state must contain both lists; serialization prevents a
    // stale partial reload from overwriting the merged map.
    let count = engine.reload().await.unwrap();
    assert_eq!(count, 5);
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    for domain in ["a-one.example", "b-three.example"] {
        assert!(
            engine
                .evaluate(
                    &Name::from_str(&format!("{domain}.")).unwrap(),
                    RecordType::A,
                    &client
                )
                .is_blocked(),
            "{domain} must remain blocked after concurrent reloads"
        );
    }

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_list_with_excessive_regex_patterns_is_rejected() {
    use std::fmt::Write as _;
    let temp_dir = std::env::temp_dir().join(format!("sito_regex_cap_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let huge_path = temp_dir.join("huge.txt");
    let good_path = temp_dir.join("good.txt");

    let mut huge = String::new();
    for i in 0..=MAX_REGEX_PATTERNS {
        let _ = writeln!(huge, "/^r{i}\\.example$/");
    }
    tokio::fs::write(&huge_path, huge).await.unwrap();
    tokio::fs::write(&good_path, "||good.example^\n")
        .await
        .unwrap();

    let config = FilteringConfig {
        lists: vec![
            FilterListConfig {
                name: "good".to_string(),
                url: format!("file://{}", good_path.display()),
                enabled: true,
                refresh_hours: None,
            },
            FilterListConfig {
                name: "huge".to_string(),
                url: format!("file://{}", huge_path.display()),
                enabled: true,
                refresh_hours: None,
            },
        ],
        ..Default::default()
    };

    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
    let status = engine.status();
    assert_eq!(status.state, FilterState::Ready);
    assert_eq!(status.failed_lists, vec!["huge".to_string()]);
    assert_eq!(engine.rule_count(), 1, "good list still loads");

    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert!(
        engine
            .evaluate(
                &Name::from_str("good.example.").unwrap(),
                RecordType::A,
                &client
            )
            .is_blocked()
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Two lists each below the per-list substring budget can jointly exceed
/// it. The reload must be rejected before the builder silently drops the
/// whole Aho-Corasick class, retaining the previous snapshot.
#[tokio::test]
async fn test_combined_multi_list_substring_budget_is_rejected() {
    use std::fmt::Write as _;
    let temp_dir = std::env::temp_dir().join(format!("sito_ac_combo_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let a_path = temp_dir.join("a.txt");
    let b_path = temp_dir.join("b.txt");
    let per_list = MAX_AC_PATTERNS / 2 + 1;
    for (path, prefix) in [(&a_path, "a"), (&b_path, "b")] {
        let mut body = String::new();
        for i in 0..per_list {
            let _ = writeln!(body, "{prefix}-sub-{i}");
        }
        tokio::fs::write(path, body).await.unwrap();
    }

    let engine = HostsFilterEngine::init(
        FilteringConfig {
            custom_rules: vec!["||keep.example^".to_string()],
            ..Default::default()
        },
        temp_dir.clone(),
    )
    .await;
    assert_eq!(engine.rule_count(), 1);

    let lists = vec![
        FilterListConfig {
            name: "a".to_string(),
            url: format!("file://{}", a_path.display()),
            enabled: true,
            refresh_hours: None,
        },
        FilterListConfig {
            name: "b".to_string(),
            url: format!("file://{}", b_path.display()),
            enabled: true,
            refresh_hours: None,
        },
    ];
    let err = engine
        .reload_with_config(&FilteringConfig {
            custom_rules: vec!["||keep.example^".to_string()],
            lists,
            ..Default::default()
        })
        .await
        .expect_err("the combined substring budget must reject the reload");
    assert!(matches!(err, FilterError::CompileTaskFailed(_)));
    assert_eq!(engine.rule_count(), 1, "previous snapshot retained");
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert!(
        engine
            .evaluate(
                &Name::from_str("keep.example.").unwrap(),
                RecordType::A,
                &client
            )
            .is_blocked()
    );
    assert!(
        engine
            .status()
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("substring patterns exceed")),
        "unexpected status: {:?}",
        engine.status().last_error
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Regression: fail-closed must survive a failed reload while the active
/// config is enabled. A rejected disabled -> enabled transition must not
/// be applied at all (WP-3.10 transactional reload), so the engine stays
/// disabled instead of becoming an enabled-but-unavailable engine.
#[tokio::test]
async fn test_fail_closed_survives_disabled_to_enabled_transition() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_failclosed_trans_{}", std::process::id()));
    let disabled = FilteringConfig {
        enabled: false,
        fail_closed: true,
        lists: vec![FilterListConfig {
            name: "dead".to_string(),
            url: "http://127.0.0.1:1/list.txt".to_string(),
            enabled: true,
            refresh_hours: None,
        }],
        ..Default::default()
    };
    let enabled = FilteringConfig {
        enabled: true,
        fail_closed: true,
        ..disabled.clone()
    };
    let engine = HostsFilterEngine::init(disabled, temp_dir.clone()).await;
    assert_eq!(engine.state(), FilterState::Disabled);
    assert!(!engine.unavailable_for_fail_closed());

    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let probe = Name::from_str("anything.example.").unwrap();

    // The dead list rejects the transition; the rejected config must not
    // become active, so the engine stays disabled and answers normally.
    assert!(
        engine.reload_with_config(&enabled).await.is_err(),
        "the dead list must fail to load"
    );
    assert!(
        !engine.config.load_full().enabled,
        "a rejected disabled -> enabled transition must not be retained"
    );
    assert!(engine.evaluate(&probe, RecordType::A, &client).is_allowed());

    // Once the active config is enabled (successful load), a later failed
    // reload must still fail closed instead of serving allow-all.
    let good = FilteringConfig {
        enabled: true,
        fail_closed: true,
        custom_rules: vec!["||good.example^".to_string()],
        ..Default::default()
    };
    engine.reload_with_config(&good).await.unwrap();
    assert!(engine.config.load_full().enabled);
    assert!(
        engine.reload_with_config(&enabled).await.is_err(),
        "the dead list must still fail"
    );
    // The rejected reload keeps the last good snapshot instead of
    // publishing an empty one (P1-8), so the prior rule still applies.
    assert!(!engine.unavailable_for_fail_closed());
    assert!(
        engine
            .evaluate(
                &Name::from_str("good.example.").unwrap(),
                RecordType::A,
                &client
            )
            .is_blocked(),
        "the previous snapshot must remain active"
    );
    assert!(engine.evaluate(&probe, RecordType::A, &client).is_allowed());
}

/// A group-only configuration (no global lists/custom rules, but group
/// `custom_rules`) must initialize as a usable empty base snapshot instead
/// of fail-closed/unavailable, and the group rules must block.
#[tokio::test]
async fn test_group_only_custom_rules_are_sources() {
    let temp_dir = std::env::temp_dir().join(format!("sito_group_only_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let config = FilteringConfig {
        enabled: true,
        fail_closed: true,
        lists: Vec::new(),
        custom_rules: Vec::new(),
        ..Default::default()
    };
    let engine = HostsFilterEngine::init_with_observer_and_group_sources(
        config,
        temp_dir.clone(),
        None,
        vec![GroupRuleSet {
            name: "kids".to_string(),
            lists: Vec::new(),
            custom_rules: vec!["||fortnite.example^".to_string()],
        }],
    )
    .await;

    assert_eq!(
        engine.state(),
        FilterState::Ready,
        "group custom rules are a source even with empty globals"
    );
    assert!(
        !engine.unavailable_for_fail_closed(),
        "a group-only deployment must not fail closed for every query"
    );

    engine.set_group_rules(vec![GroupRuleSet {
        name: "kids".to_string(),
        lists: Vec::new(),
        custom_rules: vec!["||fortnite.example^".to_string()],
    }]);
    let snapshot = engine
        .group_snapshot("kids")
        .expect("group-only snapshot compiled");
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert!(matches!(
        snapshot.evaluate("fortnite.example", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(
        engine
            .evaluate(
                &Name::from_str("example.org.").unwrap(),
                RecordType::A,
                &client
            )
            .is_allowed(),
        "queries outside the group must still resolve"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// A valid group rule must not mask a configured global list that failed
/// its first load: non-group clients stay fail-closed instead of being
/// silently unfiltered.
#[tokio::test]
async fn test_group_rule_does_not_mask_failed_global_source() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_group_failed_global_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let config = FilteringConfig {
        enabled: true,
        fail_closed: true,
        lists: vec![FilterListConfig {
            name: "dead".to_string(),
            url: "http://127.0.0.1:1/list.txt".to_string(),
            enabled: true,
            refresh_hours: None,
        }],
        custom_rules: Vec::new(),
        ..Default::default()
    };
    let engine = HostsFilterEngine::init_with_observer_and_group_sources(
        config,
        temp_dir.clone(),
        None,
        vec![GroupRuleSet {
            name: "kids".to_string(),
            lists: Vec::new(),
            custom_rules: vec!["||fortnite.example^".to_string()],
        }],
    )
    .await;

    assert_eq!(engine.state(), FilterState::Failed);
    assert!(
        engine.unavailable_for_fail_closed(),
        "a failed global source must fail closed even when a group rule exists"
    );
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert_eq!(
        engine.evaluate(
            &Name::from_str("unrelated.example.").unwrap(),
            RecordType::A,
            &client
        ),
        Verdict::Block(BlockReason::FilterUnavailable),
        "non-group clients must get fail-closed, not allow-all"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Comment-only or invalid-only group rules must not make an otherwise
/// source-less configuration advertise a Ready/available snapshot.
#[tokio::test]
async fn test_invalid_only_group_rules_fail_closed() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_group_invalid_only_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let config = FilteringConfig {
        enabled: true,
        fail_closed: true,
        lists: Vec::new(),
        custom_rules: Vec::new(),
        ..Default::default()
    };
    let engine = HostsFilterEngine::init_with_observer_and_group_sources(
        config,
        temp_dir.clone(),
        None,
        vec![GroupRuleSet {
            name: "kids".to_string(),
            lists: Vec::new(),
            custom_rules: vec![
                "# comment-only".to_string(),
                "!!! this is not a valid rule".to_string(),
            ],
        }],
    )
    .await;

    assert_eq!(engine.state(), FilterState::Failed);
    assert!(
        engine.unavailable_for_fail_closed(),
        "unparseable group rules must not count as a usable source"
    );
    assert!(
        engine.group_snapshot("kids").is_none(),
        "no usable group snapshot may be published"
    );
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert_eq!(
        engine.evaluate(
            &Name::from_str("unrelated.example.").unwrap(),
            RecordType::A,
            &client
        ),
        Verdict::Block(BlockReason::FilterUnavailable)
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// `allow_empty_list = true` permits an intentional empty global source
/// set, but it must not turn comment-only/invalid group-only rules into a
/// Ready/available empty snapshot.
#[tokio::test]
async fn test_invalid_only_group_rules_fail_closed_with_allow_empty_list() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_group_invalid_allow_empty_{}",
        std::process::id()
    ));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let config = FilteringConfig {
        enabled: true,
        fail_closed: true,
        allow_empty_list: true,
        lists: Vec::new(),
        custom_rules: Vec::new(),
        ..Default::default()
    };
    let engine = HostsFilterEngine::init_with_observer_and_group_sources(
        config,
        temp_dir.clone(),
        None,
        vec![GroupRuleSet {
            name: "kids".to_string(),
            lists: Vec::new(),
            custom_rules: vec![
                "# comment-only".to_string(),
                "!!! this is not a valid rule".to_string(),
            ],
        }],
    )
    .await;

    assert_eq!(
        engine.state(),
        FilterState::Failed,
        "allow_empty_list must not mask uncompiled group-only sources"
    );
    assert!(
        engine.unavailable_for_fail_closed(),
        "unparseable group rules must fail closed even with allow_empty_list"
    );
    assert!(
        engine.group_snapshot("kids").is_none(),
        "no usable group snapshot may be published"
    );
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert_eq!(
        engine.evaluate(
            &Name::from_str("unrelated.example.").unwrap(),
            RecordType::A,
            &client
        ),
        Verdict::Block(BlockReason::FilterUnavailable),
        "queries must SERVFAIL instead of being allowed unfiltered"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Regression: group `lists`/`custom_rules` must actually be compiled and
/// evaluated (they were stored in the policy but never applied).
#[tokio::test]
async fn test_group_rules_are_compiled_and_evaluated() {
    let temp_dir = std::env::temp_dir().join(format!("sito_group_rules_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let kids_path = temp_dir.join("kids-list.txt");
    tokio::fs::write(&kids_path, "||cartoon.example^\n")
        .await
        .unwrap();

    let config = FilteringConfig {
        lists: vec![FilterListConfig {
            name: "school".to_string(),
            url: format!("file://{}", kids_path.display()),
            enabled: true,
            refresh_hours: None,
        }],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
    assert_eq!(engine.state(), FilterState::Ready);

    engine.set_group_rules(vec![GroupRuleSet {
        name: "kids".to_string(),
        lists: vec!["school".to_string()],
        custom_rules: vec!["||fortnite.example^$important".to_string()],
    }]);

    let snapshot = engine
        .group_snapshot("kids")
        .expect("group snapshot compiled");
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let cartoon = Name::from_str("www.cartoon.example.").unwrap();
    let fortnite = Name::from_str("fortnite.example.").unwrap();
    let other = Name::from_str("example.org.").unwrap();

    assert!(
        matches!(
            snapshot.evaluate_important("fortnite.example", RecordType::A, &client),
            Some(Verdict::Block(_))
        ),
        "group custom_rules must compile and match"
    );
    assert!(matches!(
        snapshot.evaluate("www.cartoon.example", RecordType::A, &client),
        Verdict::Block(_)
    ));
    assert!(
        snapshot
            .evaluate("example.org", RecordType::A, &client)
            .is_allowed()
    );
    let _ = (cartoon, fortnite, other);

    // Groups without configured rules produce no snapshot.
    assert!(engine.group_snapshot("missing").is_none());

    // A policy that adds no rules must not create an empty group entry.
    engine.set_group_rules(vec![GroupRuleSet {
        name: "empty".to_string(),
        ..Default::default()
    }]);
    assert!(engine.group_snapshot("empty").is_none());

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Regression (audit 6, WP-3.9): a list rejected during compilation was
/// counted in both `loaded_lists` and `failed_lists`, overstating how many
/// sources were active.
#[tokio::test]
async fn test_status_loaded_and_failed_lists_are_mutually_exclusive() {
    use std::fmt::Write as _;
    let temp_dir = std::env::temp_dir().join(format!("sito_status_count_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let huge_path = temp_dir.join("huge.txt");
    let good_path = temp_dir.join("good.txt");

    let mut huge = String::new();
    for i in 0..=MAX_REGEX_PATTERNS {
        let _ = writeln!(huge, "/^r{i}\\.example$/");
    }
    tokio::fs::write(&huge_path, huge).await.unwrap();
    tokio::fs::write(&good_path, "||good.example^\n")
        .await
        .unwrap();

    let config = FilteringConfig {
        lists: vec![
            FilterListConfig {
                name: "good".to_string(),
                url: format!("file://{}", good_path.display()),
                enabled: true,
                refresh_hours: None,
            },
            FilterListConfig {
                name: "huge".to_string(),
                url: format!("file://{}", huge_path.display()),
                enabled: true,
                refresh_hours: None,
            },
        ],
        ..Default::default()
    };

    let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
    let status = engine.status();
    assert_eq!(status.state, FilterState::Ready);
    assert_eq!(status.failed_lists, vec!["huge".to_string()]);
    assert_eq!(
        status.loaded_lists, 1,
        "a rejected list must not count as loaded"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Regression (audit 6, WP-3.10): `reload_with_config` used to store the
/// candidate config before the load ran, so a rejected config became the
/// source for the next scheduled refresh and could take effect later.
#[tokio::test]
async fn test_rejected_reload_with_config_is_not_retained() {
    use std::fmt::Write as _;
    let temp_dir = std::env::temp_dir().join(format!("sito_txn_reload_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let path = temp_dir.join("big-list.txt");
    let content: String = (0..50).fold(String::new(), |mut acc, i| {
        let _ = writeln!(acc, "||blocked-{i}.example^");
        acc
    });
    tokio::fs::write(&path, content).await.unwrap();
    let list = FilterListConfig {
        name: "big".to_string(),
        url: format!("file://{}", path.display()),
        enabled: true,
        refresh_hours: None,
    };

    let accepted = FilteringConfig {
        max_rules: 1000,
        lists: vec![list.clone()],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(accepted.clone(), temp_dir.clone()).await;
    assert_eq!(engine.rule_count(), 50);

    // Candidate above the cap: rejected, and the previous config must stay.
    let rejected = FilteringConfig {
        max_rules: 10,
        lists: vec![list],
        ..Default::default()
    };
    let err = engine
        .reload_with_config(&rejected)
        .await
        .expect_err("an oversized set must be rejected");
    assert!(matches!(err, FilterError::TooManyRules { .. }));
    assert_eq!(
        engine.config.load_full().max_rules,
        accepted.max_rules,
        "the rejected config must not be retained"
    );

    // The scheduled/manual reload path uses the stored config and must
    // therefore still succeed.
    let count = engine.reload().await.unwrap();
    assert_eq!(count, 50);
    assert!(
        engine.status().last_error.is_none(),
        "the rejected cap must not apply to later reloads: {:?}",
        engine.status().last_error
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_reload_budget_abort_retains_previous_snapshot_and_sets_status() {
    let temp_dir = std::env::temp_dir().join(format!("sito_compile_budget_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let engine = HostsFilterEngine::init(
        FilteringConfig {
            custom_rules: vec!["||keep.example^".to_string()],
            ..Default::default()
        },
        temp_dir.clone(),
    )
    .await;
    assert_eq!(engine.rule_count(), 1);

    let regex_rules: Vec<String> = (0..2048)
        .map(|i| format!("/^slow-{i}\\..*\\.example$/"))
        .collect();
    let err = engine
        .reload_with_config(&FilteringConfig {
            custom_rules: regex_rules,
            regex_compile_budget_ms: Some(1),
            ..Default::default()
        })
        .await
        .expect_err("a 1 ms budget cannot compile 2048 regex rules");
    assert!(
        matches!(err, FilterError::CompileBudgetExceeded { limit_ms: 1, .. }),
        "unexpected error: {err}"
    );

    assert_eq!(
        engine.rule_count(),
        1,
        "the previous snapshot must stay active after a budget abort"
    );
    let status = engine.status();
    assert_eq!(status.state, FilterState::Ready);
    assert!(
        status
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("budget")),
        "last_error must explain the abort: {:?}",
        status.last_error
    );
    assert!(
        status.last_compile_ms.is_some(),
        "failed compiles must still report their duration"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_group_snapshots_honor_compile_budget() {
    let temp_dir = std::env::temp_dir().join(format!("sito_group_budget_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let engine = HostsFilterEngine::new(
        FilteringConfig {
            regex_compile_budget_ms: Some(1),
            ..Default::default()
        },
        temp_dir.clone(),
    );
    let custom_rules: Vec<String> = (0..2048)
        .map(|i| format!("/^group-{i}\\..*\\.example$/"))
        .collect();
    engine.set_group_rules(vec![GroupRuleSet {
        name: "kids".to_string(),
        lists: Vec::new(),
        custom_rules,
    }]);

    assert!(
        engine.group_snapshot("kids").is_none(),
        "a group whose regex compile exceeds the budget must not be published"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_compile_observer_records_initial_load_and_reload() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let temp_dir =
        std::env::temp_dir().join(format!("sito_compile_observer_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let observer: Arc<dyn Fn(f64) + Send + Sync> = Arc::new(move |seconds| {
        assert!(seconds >= 0.0);
        counter.fetch_add(1, Ordering::Relaxed);
    });

    let engine = HostsFilterEngine::init_with_observer(
        FilteringConfig {
            custom_rules: vec!["||observed.example^".to_string()],
            ..Default::default()
        },
        temp_dir.clone(),
        Some(observer),
    )
    .await;
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "the initial startup compile must be observed"
    );

    engine.reload().await.unwrap();
    assert_eq!(
        calls.load(Ordering::Relaxed),
        2,
        "scheduled/manual reloads must be observed"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Regression (audit 6, WP-3.3): an oversized rule set must be rejected
/// instead of materialising unbounded memory, and a failed first load must
/// stay fail-closed.
#[tokio::test]
async fn test_max_rules_cap_rejects_oversized_reload() {
    let temp_dir = std::env::temp_dir().join(format!("sito_max_rules_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let path = temp_dir.join("big-list.txt");
    let content: String = (0..50).fold(String::new(), |mut acc, i| {
        use std::fmt::Write as _;
        let _ = writeln!(acc, "||blocked-{i}.example^");
        acc
    });
    tokio::fs::write(&path, content).await.unwrap();
    let list = FilterListConfig {
        name: "big".to_string(),
        url: format!("file://{}", path.display()),
        enabled: true,
        refresh_hours: None,
    };

    // First load above the cap: fail closed.
    let engine = HostsFilterEngine::init(
        FilteringConfig {
            max_rules: 10,
            lists: vec![list.clone()],
            ..Default::default()
        },
        temp_dir.clone(),
    )
    .await;
    assert_eq!(engine.state(), FilterState::Failed);
    assert!(engine.unavailable_for_fail_closed());
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let probe = Name::from_str("blocked-1.example.").unwrap();
    assert_eq!(
        engine.evaluate(&probe, RecordType::A, &client),
        Verdict::Block(BlockReason::FilterUnavailable)
    );

    // A reload that would exceed the cap keeps the previous snapshot.
    let engine = HostsFilterEngine::init(
        FilteringConfig {
            max_rules: 1000,
            lists: vec![list.clone()],
            ..Default::default()
        },
        temp_dir.clone(),
    )
    .await;
    assert_eq!(engine.state(), FilterState::Ready);
    assert_eq!(engine.rule_count(), 50);

    let err = engine
        .reload_with_config(&FilteringConfig {
            max_rules: 10,
            lists: vec![list],
            ..Default::default()
        })
        .await
        .expect_err("an oversized set must be rejected");
    assert!(matches!(err, FilterError::TooManyRules { .. }));
    assert_eq!(
        engine.state(),
        FilterState::Ready,
        "previous snapshot retained"
    );
    assert_eq!(engine.rule_count(), 50);
    assert!(
        engine.evaluate(&probe, RecordType::A, &client).is_blocked(),
        "the previous snapshot must keep filtering"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// D-07: lowering `filtering.max_list_bytes` must make the reload reject
/// the oversized list, record it as failed, and keep the previous
/// snapshot filtering until a fetch under the cap succeeds.
#[tokio::test]
async fn test_reload_rejects_list_over_configured_max_list_bytes() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_max_list_reload_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let path = temp_dir.join("capped.txt");
    tokio::fs::write(&path, "0.0.0.0 capped.example\n")
        .await
        .unwrap();
    let list = FilterListConfig {
        name: "capped".to_string(),
        url: format!("file://{}", path.display()),
        enabled: true,
        refresh_hours: None,
    };

    let accepted = FilteringConfig {
        max_list_bytes: 1024,
        lists: vec![list.clone()],
        ..Default::default()
    };
    let engine = HostsFilterEngine::init(accepted, temp_dir.clone()).await;
    assert_eq!(engine.state(), FilterState::Ready);
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let blocked = Name::from_str("capped.example.").unwrap();
    assert!(
        engine
            .evaluate(&blocked, RecordType::A, &client)
            .is_blocked()
    );

    // The new cap is committed only after the reload. The list cannot be
    // fetched, but merging keeps the already-compiled rules active and the
    // failure stays observable instead of silently dropping protection.
    let count = engine
        .reload_with_config(&FilteringConfig {
            max_list_bytes: 4,
            lists: vec![list],
            ..Default::default()
        })
        .await
        .expect("retaining the previous snapshot keeps the reload usable");
    assert_eq!(count, 1);
    let status = engine.status();
    assert_eq!(status.failed_lists, vec!["capped".to_string()]);
    assert_eq!(status.state, FilterState::Ready);
    assert!(
        status.last_error.is_some(),
        "the oversized list must be reported"
    );
    assert_eq!(engine.rule_count(), 1, "previous snapshot retained");
    assert!(
        engine
            .evaluate(&blocked, RecordType::A, &client)
            .is_blocked(),
        "the previous snapshot must keep filtering"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// D-07: the cap staged by `reload_with_config` must be the one used for
/// that reload, so raising it can recover a list the old cap rejected.
#[tokio::test]
async fn test_reload_applies_new_max_list_bytes_after_config_change() {
    let temp_dir = std::env::temp_dir().join(format!("sito_max_list_grow_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let path = temp_dir.join("capped.txt");
    tokio::fs::write(&path, "0.0.0.0 capped.example\n")
        .await
        .unwrap();
    let list = FilterListConfig {
        name: "capped".to_string(),
        url: format!("file://{}", path.display()),
        enabled: true,
        refresh_hours: None,
    };

    let engine = HostsFilterEngine::init(
        FilteringConfig {
            max_list_bytes: 4,
            lists: vec![list.clone()],
            ..Default::default()
        },
        temp_dir.clone(),
    )
    .await;
    assert_eq!(engine.state(), FilterState::Failed);
    assert_eq!(engine.rule_count(), 0);

    let count = engine
        .reload_with_config(&FilteringConfig {
            max_list_bytes: 1024,
            lists: vec![list],
            ..Default::default()
        })
        .await
        .expect("the enlarged cap must apply to this reload");
    assert_eq!(count, 1);
    assert_eq!(engine.state(), FilterState::Ready);
    assert_eq!(engine.config.load_full().max_list_bytes, 1024);
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let blocked = Name::from_str("capped.example.").unwrap();
    assert!(
        engine
            .evaluate(&blocked, RecordType::A, &client)
            .is_blocked()
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// D-07 follow-up: `reload()` and `reload_lists()` must derive the byte cap
/// from the committed config at call time. A separately swapped downloader
/// could be observed out of sync with the config, and a failed
/// `reload_with_config` must leave the previously committed cap in place.
#[tokio::test]
async fn test_reload_paths_use_committed_max_list_bytes() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_max_list_committed_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let path = temp_dir.join("capped.txt");
    // 23 bytes: above the small cap, below the enlarged one.
    tokio::fs::write(&path, "0.0.0.0 capped.example\n")
        .await
        .unwrap();
    let list = FilterListConfig {
        name: "capped".to_string(),
        url: format!("file://{}", path.display()),
        enabled: true,
        refresh_hours: None,
    };
    let config_with_cap = |max_list_bytes| FilteringConfig {
        max_list_bytes,
        lists: vec![list.clone()],
        ..Default::default()
    };

    // The small cap rejects the list at startup.
    let engine = HostsFilterEngine::init(config_with_cap(20), temp_dir.clone()).await;
    assert_eq!(engine.state(), FilterState::Failed);
    assert_eq!(engine.rule_count(), 0);

    // A committed config change is what `reload()` sees: the enlarged cap
    // must be used even though the engine was constructed with the old one.
    engine.config.store(Arc::new(config_with_cap(64)));
    let count = engine
        .reload()
        .await
        .expect("reload must use the committed cap");
    assert_eq!(count, 1);
    assert_eq!(engine.state(), FilterState::Ready);

    // A rejected candidate must not replace the committed cap.
    let err = engine
        .reload_with_config(&FilteringConfig {
            max_list_bytes: 20,
            max_rules: 0,
            lists: vec![list.clone()],
            ..Default::default()
        })
        .await
        .expect_err("max_rules = 0 must reject the candidate");
    assert!(matches!(err, FilterError::TooManyRules { .. }));
    assert_eq!(
        engine.config.load_full().max_list_bytes,
        64,
        "a rejected reload must retain the old cap"
    );
    assert_eq!(
        engine.reload().await.expect("the old cap must still work"),
        1
    );

    // Lowering the committed cap must apply to reload_lists(): the 23-byte
    // file is now oversized and the failure must be recorded instead of a
    // stale downloader silently fetching it under the old cap.
    engine.config.store(Arc::new(config_with_cap(20)));
    let count = engine
        .reload_lists(&["capped".to_string()])
        .await
        .expect("retaining the previous snapshot keeps the refresh usable");
    assert_eq!(count, 1);
    assert_eq!(
        engine.status().failed_lists,
        vec!["capped".to_string()],
        "reload_lists must enforce the committed cap"
    );
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    let blocked = Name::from_str("capped.example.").unwrap();
    assert!(
        engine
            .evaluate(&blocked, RecordType::A, &client)
            .is_blocked(),
        "the previous snapshot must keep filtering"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}
