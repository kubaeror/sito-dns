//! Shared admission helpers for transport listeners.
//!
//! This module holds the small, dependency-free building blocks used by every
//! listener: bounded per-IP connection accounting and bounded accept backoff.
//! The full public `AdmissionController`/`ConnectionPermit` interfaces are part
//! of the 2.0 transport work; these helpers deliberately stay internal so the
//! 1.9.4 patch does not grow a new public API.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::task::JoinSet;

/// Reaps every completed task from a `JoinSet<()>` without blocking.
///
/// Tokio retains a completed task's handle until it is joined. Long-lived
/// QUIC/TCP listeners spawn one task per connection/stream, so completed
/// handles must be drained continuously or the set becomes an unbounded
/// per-listener memory leak. All listener tasks return `()`, so outputs can be
/// discarded.
pub(crate) fn reap_finished(tasks: &mut JoinSet<()>) {
    while tasks.try_join_next().is_some() {}
}

/// Upper bound on the time an accept loop waits after a failed `accept`.
///
/// A persistent `EMFILE`/`ENFILE` used to make the loop spin at 100% CPU. The
/// delay grows exponentially from [`ACCEPT_BACKOFF_MIN`] and is reset on the
/// first successful accept.
pub(crate) const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// First backoff delay after a failed accept.
pub(crate) const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(5);

/// Bounded exponential backoff for accept loops.
#[derive(Debug, Default)]
pub(crate) struct AcceptBackoff {
    current: Option<Duration>,
}

impl AcceptBackoff {
    /// Returns the next delay. The first failure waits
    /// [`ACCEPT_BACKOFF_MIN`]; the delay doubles up to [`ACCEPT_BACKOFF_MAX`].
    pub(crate) fn next_delay(&mut self) -> Duration {
        let delay = self.current.map_or(ACCEPT_BACKOFF_MIN, |current| {
            (current * 2).min(ACCEPT_BACKOFF_MAX)
        });
        self.current = Some(delay);
        delay
    }

    /// Resets the backoff after a successful accept.
    pub(crate) fn reset(&mut self) {
        self.current = None;
    }
}

/// Per-IP connection accounting with RAII release.
///
/// The table is keyed by the full source address (users behind one NAT share a
/// budget, but per-prefix keying for *connections* would let a single /24
/// exhaust a whole neighbourhood). Entries are removed once their count drops
/// to zero.
#[derive(Debug)]
pub(crate) struct PerIpConnectionLimiter {
    max_per_ip: usize,
    counts: DashMap<IpAddr, AtomicUsize>,
}

/// RAII permit returned by [`PerIpConnectionLimiter::try_acquire`].
#[derive(Debug)]
pub(crate) struct ConnectionPermit {
    limiter: Arc<PerIpConnectionLimiter>,
    ip: IpAddr,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let Some(count) = self.limiter.counts.get(&self.ip) else {
            return;
        };
        let remaining = count.fetch_sub(1, Ordering::AcqRel);
        // Drop the shard guard before removing the entry. `remove_if` checks
        // the live count under the shard lock, so a concurrent acquire that
        // already re-incremented the bucket is never dropped.
        drop(count);
        if remaining <= 1 {
            let _ = self
                .limiter
                .counts
                .remove_if(&self.ip, |_, count| count.load(Ordering::Acquire) == 0);
        }
    }
}

impl PerIpConnectionLimiter {
    pub(crate) fn new(max_per_ip: usize) -> Arc<Self> {
        Arc::new(Self {
            max_per_ip: max_per_ip.max(1),
            counts: DashMap::new(),
        })
    }

    /// Reserves one connection slot for `ip`, or returns `None` when that
    /// source already holds the maximum number of connections.
    pub(crate) fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnectionPermit> {
        let entry = self.counts.entry(ip).or_insert_with(|| AtomicUsize::new(0));
        // Compare-and-set loop so two concurrent accepts for the same source
        // cannot overshoot the cap.
        let mut current = entry.load(Ordering::Acquire);
        loop {
            if current >= self.max_per_ip {
                // Drop the DashMap guard before returning to keep the shard
                // uncontended for the next accept.
                drop(entry);
                return None;
            }
            match entry.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    drop(entry);
                    return Some(ConnectionPermit {
                        limiter: Arc::clone(self),
                        ip,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.counts.len()
    }
}

/// Default per-source connection cap used by TCP, DoT and DoH listeners.
///
/// The global listener cap still bounds total resources; this bounds how many
/// slots one slowloris source may pin.
pub(crate) const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_accept_backoff_grows_and_saturates() {
        let mut backoff = AcceptBackoff::default();
        assert_eq!(backoff.next_delay(), ACCEPT_BACKOFF_MIN);
        assert_eq!(backoff.next_delay(), ACCEPT_BACKOFF_MIN * 2);
        let mut previous = backoff.next_delay();
        assert!(previous >= ACCEPT_BACKOFF_MIN * 4);
        for _ in 0..20 {
            let next = backoff.next_delay();
            assert!(next <= ACCEPT_BACKOFF_MAX);
            assert!(next >= previous.min(ACCEPT_BACKOFF_MAX));
            previous = next;
        }
        assert_eq!(previous, ACCEPT_BACKOFF_MAX);
        backoff.reset();
        assert_eq!(backoff.next_delay(), ACCEPT_BACKOFF_MIN);
    }

    #[test]
    fn test_per_ip_connection_cap_is_enforced_and_released() {
        let limiter = PerIpConnectionLimiter::new(2);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

        let first = limiter.try_acquire(a).expect("first slot");
        let second = limiter.try_acquire(a).expect("second slot");
        assert!(
            limiter.try_acquire(a).is_none(),
            "a third connection from the same source must be rejected"
        );
        let other = limiter
            .try_acquire(b)
            .expect("another source keeps its own budget");

        drop(first);
        let third = limiter
            .try_acquire(a)
            .expect("releasing a slot must admit the source again");
        assert_eq!(limiter.tracked(), 2);

        drop(second);
        drop(third);
        drop(other);
        assert_eq!(limiter.tracked(), 0);
    }

    #[test]
    fn test_per_ip_connection_cap_handles_ipv6() {
        let limiter = PerIpConnectionLimiter::new(1);
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let permit = limiter.try_acquire(ip).expect("first slot");
        assert!(limiter.try_acquire(ip).is_none());
        drop(permit);
        assert!(limiter.try_acquire(ip).is_some());
    }

    /// Regression (Important 1): completed tasks must be reaped. A `JoinSet`
    /// keeps a handle per finished task until it is joined, so a long-lived
    /// listener that only drains on shutdown grows without bound.
    #[tokio::test]
    async fn test_join_set_reaping_bounds_retained_entries() {
        let mut tasks = JoinSet::new();
        for _ in 0..100 {
            tasks.spawn(async {});
        }
        // Let the spawned tasks complete.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !tasks.is_empty(),
            "the test must observe completed-but-unjoined handles"
        );
        reap_finished(&mut tasks);
        assert_eq!(
            tasks.len(),
            0,
            "completed task handles must not accumulate in the JoinSet"
        );
    }
}
