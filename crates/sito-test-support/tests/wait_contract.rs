//! Contract tests for the bounded event-driven wait helpers (WP-1.8).

use sito_test_support::wait::{WaitTimeout, wait_for, wait_until};
use std::time::Duration;

#[tokio::test]
async fn wait_until_keeps_compatibility_and_returns_false_on_timeout() {
    assert!(
        wait_until(Duration::from_millis(50), || async { true }).await,
        "an immediately-true condition must succeed"
    );
    assert!(
        !wait_until(Duration::from_millis(30), || async { false }).await,
        "a never-true condition must time out"
    );
}

#[tokio::test]
async fn wait_for_reports_label_and_timeout_on_failure() {
    let error = wait_for("listener to accept", Duration::from_millis(30), || async {
        false
    })
    .await
    .expect_err("a never-true condition must fail");

    assert_eq!(
        error,
        WaitTimeout::new("listener to accept", Duration::from_millis(30))
    );
    let message = error.to_string();
    assert!(
        message.contains("listener to accept") && message.contains("30ms"),
        "the timeout must name the awaited condition and budget: {message}"
    );
}

#[tokio::test]
async fn wait_for_succeeds_after_the_condition_becomes_true() {
    let ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let setter = std::sync::Arc::clone(&ready);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        setter.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    wait_for("flag to become true", Duration::from_secs(1), || {
        let ready = std::sync::Arc::clone(&ready);
        async move { ready.load(std::sync::atomic::Ordering::SeqCst) }
    })
    .await
    .expect("the polled condition must be observed");
}
