//! Contract tests for the deterministic test clock (WP-1.8).
//!
//! These tests define the shape of the clock abstraction before it exists:
//! `Clock::now`/`Clock::sleep`, `SystemClock`, and a `ManualClock` that only
//! advances when the test says so.

use sito_test_support::clock::{Clock, ManualClock, SystemClock};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn system_clock_now_moves_forward() {
    let clock = SystemClock::new();
    let first = clock.now();
    std::thread::sleep(Duration::from_millis(2));
    assert!(
        clock.now() >= first,
        "the system clock must never move backwards"
    );
}

#[tokio::test]
async fn manual_clock_now_only_moves_when_advanced() {
    let clock = ManualClock::new();
    let start = clock.now();

    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(
        clock.now(),
        start,
        "manual time must not advance on its own"
    );

    clock.advance(Duration::from_secs(7));
    assert_eq!(
        clock.now().duration_since(start),
        Duration::from_secs(7),
        "advance must move the manual clock by exactly the requested amount"
    );
}

#[tokio::test]
async fn manual_clock_sleep_only_completes_after_advance() {
    let clock = Arc::new(ManualClock::new());
    let sleeper = {
        let clock = Arc::clone(&clock);
        tokio::spawn(async move {
            clock.sleep(Duration::from_secs(30)).await;
            clock.now()
        })
    };

    // Give the spawned task a chance to register its waiter.
    for _ in 0..100 {
        if clock.waiters() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(clock.waiters(), 1, "the sleeper must register a waiter");
    assert!(
        !sleeper.is_finished(),
        "a manual-clock sleep must not complete in real time"
    );

    clock.advance(Duration::from_secs(29));
    tokio::task::yield_now().await;
    assert_eq!(
        clock.waiters(),
        1,
        "a waiter before its deadline stays parked"
    );
    assert!(!sleeper.is_finished());

    clock.advance(Duration::from_secs(1));
    let woke_at = sleeper.await.expect("sleeper task must not panic");
    assert_eq!(
        woke_at.duration_since(clock.started_at()),
        Duration::from_secs(30),
        "the sleeper must observe exactly the advanced deadline"
    );
    assert_eq!(clock.waiters(), 0, "a completed waiter must be removed");
}

#[tokio::test]
async fn manual_clock_notify_wakes_waiters_without_advancing() {
    let clock = Arc::new(ManualClock::new());
    let sleeper = {
        let clock = Arc::clone(&clock);
        tokio::spawn(async move {
            clock.sleep(Duration::from_secs(30)).await;
        })
    };

    for _ in 0..100 {
        if clock.waiters() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(clock.waiters(), 1);

    // notifying without advancing re-polls the waiter; it must stay pending.
    clock.notify();
    tokio::task::yield_now().await;
    assert!(
        !sleeper.is_finished(),
        "notify alone must not complete a sleep"
    );
    assert_eq!(clock.waiters(), 1);

    clock.advance(Duration::from_secs(30));
    tokio::time::timeout(Duration::from_secs(1), sleeper)
        .await
        .expect("the sleeper must finish after the deadline advance")
        .expect("sleeper task must not panic");
}

#[tokio::test]
async fn manual_clock_zero_and_past_deadlines_complete_immediately() {
    let clock = ManualClock::new();
    tokio::time::timeout(Duration::from_millis(100), clock.sleep(Duration::ZERO))
        .await
        .expect("a zero-duration sleep must complete without an advance");

    let clock = ManualClock::new();
    assert_eq!(clock.waiters(), 0);
}

#[tokio::test]
async fn manual_clock_sleep_created_before_advance_still_completes() {
    let clock = ManualClock::new();
    let sleeper = clock.sleep(Duration::from_secs(10));
    // Advance before the future's first poll: the first poll must observe an
    // expired deadline and complete, rather than registering a past waiter.
    clock.advance(Duration::from_secs(10));
    tokio::time::timeout(Duration::from_millis(100), sleeper)
        .await
        .expect("a sleep whose deadline passed before registration must complete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manual_clock_advance_racing_first_poll_never_loses_wakeup() {
    for _ in 0..2_000 {
        let clock = Arc::new(ManualClock::new());
        let (created_tx, created_rx) = std::sync::mpsc::channel();
        let sleeper_clock = Arc::clone(&clock);
        let sleeper = tokio::spawn(async move {
            // Create the sleep future first, then let the test advance while
            // this task is between registration and its first poll.
            let sleep = sleeper_clock.sleep(Duration::from_secs(1));
            let _ = created_tx.send(());
            sleep.await;
        });
        created_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("sleeper must create its sleep future");
        clock.advance(Duration::from_secs(1));
        let joined = tokio::time::timeout(Duration::from_millis(500), sleeper)
            .await
            .expect("advance raced the first poll and lost the wakeup");
        joined.expect("sleeper task must not panic");
    }
}

#[tokio::test]
async fn dropping_an_unfinished_manual_sleep_clears_its_waiter() {
    let clock = Arc::new(ManualClock::new());
    let sleeper = {
        let clock = Arc::clone(&clock);
        tokio::spawn(async move {
            clock.sleep(Duration::from_secs(60)).await;
        })
    };
    for _ in 0..100 {
        if clock.waiters() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(clock.waiters(), 1);
    sleeper.abort();
    for _ in 0..100 {
        if clock.waiters() == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(clock.waiters(), 0, "dropping a sleeper must unregister it");
}
