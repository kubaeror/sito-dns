//! Shared admission controller for transport listeners.
//!
//! Every listener admits work through an [`AdmissionController`]: one global
//! connection semaphore, one bounded per-source connection table, the shared
//! [`RateLimiter`], and one global in-flight request semaphore. The permits it
//! hands out ([`ConnectionPermit`], [`RequestPermit`]) are RAII handles, so a
//! listener cannot leak a slot by forgetting to release it.
//!
//! Bounded accept backoff and completed-task reaping also live here because
//! they are shared by every accept loop.

use dashmap::DashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::limiter::RateLimiter;

/// Rate-limit key for a source address: IPv4 `/24`, IPv6 `/64`.
///
/// Buckets are keyed by network prefix, not the full address, so a client
/// rotating through its own allocation cannot multiply its request budget.
/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) uses the IPv4 `/24` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RateKey(IpAddr);

impl RateKey {
    /// Derives the prefix key for `ip` (IPv4 `/24`, IPv6 `/64`).
    #[must_use]
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4) & 0xFFFF_FF00;
                Self(IpAddr::V4(Ipv4Addr::from(bits)))
            }
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return Self::from_ip(IpAddr::V4(v4));
                }
                let bits = u128::from(v6) & 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000;
                Self(IpAddr::V6(Ipv6Addr::from(bits)))
            }
        }
    }

    /// Returns the masked address used as the bucket key.
    #[must_use]
    pub fn as_ip(self) -> IpAddr {
        self.0
    }
}

impl From<IpAddr> for RateKey {
    fn from(ip: IpAddr) -> Self {
        Self::from_ip(ip)
    }
}

impl fmt::Display for RateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Why an admission attempt was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    /// The listener-wide connection cap is exhausted.
    ConnectionLimit,
    /// The source already holds its maximum number of connections.
    PerSourceConnectionLimit,
    /// The listener-wide in-flight request cap is exhausted.
    RequestLimit,
    /// The source prefix exceeded its request rate budget.
    RateLimited,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::ConnectionLimit => "global connection limit reached",
            Self::PerSourceConnectionLimit => "per-source connection limit reached",
            Self::RequestLimit => "global in-flight request limit reached",
            Self::RateLimited => "rate limit exceeded",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for AdmissionError {}

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

/// RAII slot returned by [`PerIpConnectionLimiter::try_acquire`].
///
/// This is the per-source half of a [`ConnectionPermit`]; listeners interact
/// with the public permit instead.
#[derive(Debug)]
pub(crate) struct PerIpConnectionPermit {
    limiter: Arc<PerIpConnectionLimiter>,
    ip: IpAddr,
}

impl Drop for PerIpConnectionPermit {
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
    pub(crate) fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PerIpConnectionPermit> {
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
                    return Some(PerIpConnectionPermit {
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

/// RAII admission for one accepted connection.
///
/// Holds both the listener-wide connection slot and the per-source slot, so
/// both are released when the connection task ends. Listeners acquire this
/// before any handshake work so a peer cannot pin resources before proving it
/// is a real client.
#[derive(Debug)]
pub struct ConnectionPermit {
    _global: OwnedSemaphorePermit,
    _per_source: PerIpConnectionPermit,
}

/// RAII admission for one in-flight request or stream.
///
/// The permit covers the request until it is answered; acquiring it before the
/// body is read bounds pre-body buffering by the global request budget.
#[derive(Debug)]
pub struct RequestPermit {
    _permit: OwnedSemaphorePermit,
}

/// Shared admission state for every listener.
///
/// The controller owns:
/// - the global connection semaphore (`max_connections`),
/// - the bounded per-source connection table (`max_connections_per_ip`),
/// - the shared [`RateLimiter`] (hot-reloadable rate policy),
/// - the global in-flight request/stream semaphore.
///
/// It is cheap to clone/share via `Arc`; listeners build one at startup and
/// clone the `Arc` into every connection task.
#[derive(Debug)]
pub struct AdmissionController {
    max_connections: usize,
    max_connections_per_ip: usize,
    connection_semaphore: Arc<Semaphore>,
    per_source: Arc<PerIpConnectionLimiter>,
    rate_limiter: Arc<RateLimiter>,
    request_semaphore: Arc<Semaphore>,
}

impl AdmissionController {
    /// Builds a controller from an existing rate limiter and explicit caps.
    ///
    /// `max_in_flight_requests` bounds requests/streams across the whole
    /// listener; listeners that do not use a request budget may pass their
    /// connection cap.
    #[must_use]
    pub fn new(
        max_connections: usize,
        max_connections_per_ip: usize,
        rate_limiter: Arc<RateLimiter>,
        max_in_flight_requests: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            max_connections,
            max_connections_per_ip: max_connections_per_ip.max(1),
            connection_semaphore: Arc::new(Semaphore::new(max_connections)),
            per_source: PerIpConnectionLimiter::new(max_connections_per_ip),
            rate_limiter,
            request_semaphore: Arc::new(Semaphore::new(max_in_flight_requests)),
        })
    }

    /// Builds a controller with a fresh rate limiter derived from
    /// `rate_limit_per_ip` (`burst = 2 * rate`, saturating).
    #[must_use]
    pub fn from_rate_limit(
        max_connections: usize,
        max_connections_per_ip: usize,
        rate_limit_per_ip: u32,
        max_in_flight_requests: usize,
    ) -> Arc<Self> {
        Self::new(
            max_connections,
            max_connections_per_ip,
            Arc::new(RateLimiter::new(
                rate_limit_per_ip,
                RateLimiter::burst_for_rate(rate_limit_per_ip),
            )),
            max_in_flight_requests,
        )
    }

    /// The shared rate limiter, for hot-reload and the background pruner.
    #[must_use]
    pub fn rate_limiter(&self) -> &Arc<RateLimiter> {
        &self.rate_limiter
    }

    /// The configured listener-wide connection cap.
    #[must_use]
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// The configured per-source connection cap.
    #[must_use]
    pub fn max_connections_per_ip(&self) -> usize {
        self.max_connections_per_ip
    }

    /// Acquires a global and per-source connection slot for `ip`.
    ///
    /// The global slot is taken first (matching the historical listener order),
    /// so a per-source rejection releases it automatically.
    pub fn try_acquire_connection(&self, ip: IpAddr) -> Result<ConnectionPermit, AdmissionError> {
        let global = self
            .connection_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmissionError::ConnectionLimit)?;
        let per_source = self
            .per_source
            .try_acquire(ip)
            .ok_or(AdmissionError::PerSourceConnectionLimit)?;
        Ok(ConnectionPermit {
            _global: global,
            _per_source: per_source,
        })
    }

    /// Acquires one global in-flight request/stream slot.
    pub fn try_acquire_request(&self) -> Result<RequestPermit, AdmissionError> {
        self.request_semaphore
            .clone()
            .try_acquire_owned()
            .map(|permit| RequestPermit { _permit: permit })
            .map_err(|_| AdmissionError::RequestLimit)
    }

    /// Charges one token from the source prefix's rate bucket.
    pub fn check_rate(&self, ip: IpAddr) -> Result<(), AdmissionError> {
        if self.rate_limiter.check(ip) {
            Ok(())
        } else {
            Err(AdmissionError::RateLimited)
        }
    }

    /// Charges the rate budget and then acquires a request slot.
    ///
    /// This is the combined pre-body admission used by DoH/DoH3: rate failures
    /// do not consume a request slot, and a request-limit failure does not
    /// consume rate budget beyond the check that already ran.
    pub fn try_admit_request(&self, ip: IpAddr) -> Result<RequestPermit, AdmissionError> {
        self.check_rate(ip)?;
        self.try_acquire_request()
    }

    /// Starts the shared rate-limiter pruner (one per limiter).
    pub fn spawn_pruner(
        &self,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        self.rate_limiter.spawn_pruner(shutdown_rx)
    }
}

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

    fn controller(
        max_connections: usize,
        max_per_ip: usize,
        rate: u32,
        burst: u32,
        max_requests: usize,
    ) -> Arc<AdmissionController> {
        AdmissionController::new(
            max_connections,
            max_per_ip,
            Arc::new(RateLimiter::new(rate, burst)),
            max_requests,
        )
    }

    #[test]
    fn test_admission_controller_global_connection_cap() {
        let controller = controller(1, 4, 0, 1, 4);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

        let first = controller.try_acquire_connection(a).expect("first slot");
        assert_eq!(
            controller.try_acquire_connection(b).unwrap_err(),
            AdmissionError::ConnectionLimit
        );
        drop(first);
        let second = controller
            .try_acquire_connection(b)
            .expect("releasing the global slot must admit another source");
        drop(second);
    }

    #[test]
    fn test_admission_controller_per_source_connection_cap() {
        let controller = controller(4, 1, 0, 1, 4);
        let a = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let b = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));

        let first = controller.try_acquire_connection(a).expect("first slot");
        assert_eq!(
            controller.try_acquire_connection(a).unwrap_err(),
            AdmissionError::PerSourceConnectionLimit
        );
        let other = controller
            .try_acquire_connection(b)
            .expect("another source keeps its own budget");
        drop(first);
        let again = controller
            .try_acquire_connection(a)
            .expect("released slot is reusable");
        drop(again);
        drop(other);
    }

    #[test]
    fn test_admission_controller_request_permits_are_bounded_and_released() {
        let controller = controller(4, 4, 0, 1, 2);
        let first = controller
            .try_acquire_request()
            .expect("first request slot");
        let second = controller
            .try_acquire_request()
            .expect("second request slot");
        assert_eq!(
            controller.try_acquire_request().unwrap_err(),
            AdmissionError::RequestLimit
        );
        drop(first);
        let third = controller
            .try_acquire_request()
            .expect("released request slot is reusable");
        drop(second);
        drop(third);
    }

    #[test]
    fn test_admission_controller_rate_check_uses_prefix_key() {
        let controller = controller(4, 4, 1, 1, 4);
        let a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let same_prefix = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200));
        let other_prefix = IpAddr::V4(Ipv4Addr::new(203, 0, 114, 1));

        controller.check_rate(a).expect("first token");
        assert_eq!(
            controller.check_rate(same_prefix).unwrap_err(),
            AdmissionError::RateLimited,
            "the same /24 shares one bucket"
        );
        controller
            .check_rate(other_prefix)
            .expect("a different /24 has its own budget");
    }

    #[test]
    fn test_admission_controller_admit_request_charges_rate_first() {
        let controller = controller(4, 4, 1, 1, 1);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 115, 1));

        let permit = controller.try_admit_request(ip).expect("admitted");
        assert_eq!(
            controller.try_admit_request(ip).unwrap_err(),
            AdmissionError::RateLimited
        );
        drop(permit);
    }

    #[test]
    fn test_rate_key_masks_ipv4_24_ipv6_64_and_mapped_addresses() {
        assert_eq!(
            RateKey::from_ip("192.0.2.10".parse().expect("IPv4")),
            RateKey::from_ip("192.0.2.99".parse().expect("IPv4"))
        );
        assert_eq!(
            RateKey::from_ip("192.0.2.10".parse().expect("IPv4")).to_string(),
            "192.0.2.0"
        );
        assert_eq!(
            RateKey::from_ip("::ffff:192.0.2.10".parse().expect("mapped IPv4")),
            RateKey::from_ip("192.0.2.10".parse().expect("IPv4")),
            "a mapped address must use its IPv4 /24 key"
        );
        assert_eq!(
            RateKey::from_ip("2001:db8:1:2::1".parse().expect("IPv6")).to_string(),
            "2001:db8:1:2::"
        );
        assert_ne!(
            RateKey::from_ip("2001:db8:1:2::1".parse().expect("IPv6")),
            RateKey::from_ip("2001:db8:1:3::1".parse().expect("IPv6"))
        );
    }

    #[test]
    fn test_admission_error_display_is_specific() {
        assert!(
            AdmissionError::ConnectionLimit
                .to_string()
                .contains("global")
        );
        assert!(
            AdmissionError::PerSourceConnectionLimit
                .to_string()
                .contains("per-source")
        );
        assert!(AdmissionError::RequestLimit.to_string().contains("request"));
        assert!(AdmissionError::RateLimited.to_string().contains("rate"));
    }
}
