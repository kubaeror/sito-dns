//! Concurrency regression tests for the process-wide port broker (WP-1.8).
//!
//! Tests in one binary run in parallel. The broker must guarantee that two
//! harness instances (or transport tests) cannot probe/choose the same port,
//! and that releasing a probe socket does not release the reservation.

use sito_test_support::{
    PortReservations, ReservedPort, release_ports, reserve_port, reserve_udp_port,
};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Serializes assertions that intentionally free a port back into the pool.
static BROKER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn broker_test_guard() -> std::sync::MutexGuard<'static, ()> {
    BROKER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn concurrent_leases_never_return_the_same_port() {
    let _guard = broker_test_guard();
    let leases: Arc<Mutex<Vec<ReservedPort>>> = Arc::new(Mutex::new(Vec::new()));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let leases = Arc::clone(&leases);
            std::thread::spawn(move || {
                let mut held = Vec::new();
                for _ in 0..16 {
                    held.push(reserve_port().expect("reserve TCP from a worker thread"));
                }
                leases
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend(held);
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("reservation worker must not panic");
    }

    let leases = leases
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let ports: HashSet<u16> = leases.iter().map(ReservedPort::port).collect();
    assert_eq!(
        ports.len(),
        leases.len(),
        "two concurrent leases picked the same port"
    );
    assert!(
        ports.iter().all(|port| *port != 0),
        "ephemeral leases must never be port 0"
    );
}

#[tokio::test]
async fn released_probe_socket_stays_reserved_for_concurrent_tests() {
    let mut held = reserve_port().expect("hold one TCP lease");
    let held_port = held.port();
    held.release_listener();

    // While the lease is alive after releasing its probe socket, parallel
    // reservations must not choose that port.
    let mut handles = Vec::new();
    for _ in 0..32 {
        handles.push(tokio::task::spawn_blocking(|| {
            reserve_port().expect("concurrent reservation")
        }));
    }
    let mut concurrent = Vec::new();
    for handle in handles {
        concurrent.push(handle.await.expect("reservation task must not panic"));
    }
    assert!(
        concurrent.iter().all(|lease| lease.port() != held_port),
        "a live lease whose probe listener was released must stay reserved"
    );
}

#[tokio::test]
async fn dropped_lease_returns_the_port_and_live_leases_stay_exclusive() {
    let _guard = broker_test_guard();
    let first = reserve_port().expect("first lease");
    let second = reserve_port().expect("second lease");
    assert_ne!(first.port(), second.port());

    let first_port = first.port();
    let second_port = second.port();
    drop(first);

    let third = reserve_port().expect("third lease");
    assert_ne!(third.port(), second_port, "a live lease stays exclusive");
    assert!(
        third.port() != 0,
        "the released {first_port} may be reused, but must still be a real port"
    );
}

#[tokio::test]
async fn reserve_tcp_udp_returns_one_number_for_both_protocols() {
    let _guard = broker_test_guard();
    let mut broker = PortReservations::new();
    let (listener, socket, port) = broker.reserve_tcp_udp().expect("reserve pair");
    assert_eq!(
        listener.local_addr().expect("tcp addr").port(),
        port,
        "the TCP probe must hold the reserved number"
    );
    assert_eq!(
        socket.local_addr().expect("udp addr").port(),
        port,
        "the UDP probe must hold the same number"
    );
    let _ = broker.commit();
}

#[test]
fn claim_ports_is_all_or_nothing() {
    let _guard = broker_test_guard();
    // The broker does not bind these numbers, so any unused values work.
    let first = 64_990;
    let second = 64_991;
    release_ports(&[first, second]);

    assert!(sito_test_support::claim_ports(&[first, second]));
    assert!(!sito_test_support::claim_ports(&[first]));
    assert!(!sito_test_support::claim_ports(&[second]));
    // A failed claim must not partially insert a new number.
    assert!(!sito_test_support::claim_ports(&[64_992, first]));
    assert!(
        sito_test_support::claim_ports(&[64_992]),
        "the failed all-or-nothing claim must not have inserted the free port"
    );
    release_ports(&[first, second, 64_992]);
}

#[tokio::test]
async fn udp_and_tcp_numbers_can_be_reserved_together_without_collision() {
    let _guard = broker_test_guard();
    let mut broker = PortReservations::new();
    let mut seen = HashSet::new();
    for _ in 0..8 {
        let (tcp, tcp_port) = broker.reserve_tcp().expect("reserve tcp");
        let (udp, udp_port) = broker.reserve_udp().expect("reserve udp");
        drop((tcp, udp));
        assert!(
            seen.insert(tcp_port),
            "the broker returned duplicate TCP port {tcp_port}"
        );
        assert!(
            seen.insert(udp_port),
            "the broker returned duplicate port {udp_port}"
        );
    }
    let committed = broker.commit();
    release_ports(&committed);
}

#[tokio::test(flavor = "current_thread")]
async fn multiple_harness_style_reservations_observe_distinct_ports() {
    let seen: Arc<Mutex<HashSet<u16>>> = Arc::new(Mutex::new(HashSet::new()));
    let duplicates = Arc::new(AtomicUsize::new(0));
    let held: Arc<Mutex<Vec<PortReservations>>> = Arc::new(Mutex::new(Vec::new()));

    let mut tasks = Vec::new();
    for _ in 0..16 {
        let seen = Arc::clone(&seen);
        let duplicates = Arc::clone(&duplicates);
        let held = Arc::clone(&held);
        tasks.push(tokio::task::spawn_blocking(move || {
            let mut reservations = PortReservations::new();
            let (tcp, tcp_port) = reservations.reserve_tcp().expect("reserve tcp");
            let (udp, udp_port) = reservations.reserve_udp().expect("reserve udp");
            drop((tcp, udp));
            {
                let mut seen = seen
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for port in [tcp_port, udp_port] {
                    if !seen.insert(port) {
                        duplicates.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
            // Keep the live leases held until the uniqueness assertion has run;
            // otherwise the OS may legitimately reuse an ephemeral port.
            held.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(reservations);
        }));
    }
    for task in tasks {
        task.await.expect("reservation task must not panic");
    }

    assert_eq!(
        duplicates.load(Ordering::SeqCst),
        0,
        "concurrent harness-style reservations collided on a port"
    );
}

#[test]
fn reservations_release_only_after_the_lease_is_dropped() {
    let _guard = broker_test_guard();
    let lease = reserve_udp_port().expect("reserve udp");
    let port = lease.port();
    let mut broker = PortReservations::new();
    let (socket, other) = broker.reserve_udp().expect("reserve second udp");
    assert_ne!(port, other);
    drop(socket);
    let committed = broker.commit();
    assert!(committed.contains(&other));
    drop(lease);
    release_ports(&committed);
}
