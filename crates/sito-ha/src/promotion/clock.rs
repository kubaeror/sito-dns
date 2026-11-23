//! Monotonic and wall clocks for ADR-0010 self-fencing.
//!
//! Safety deadlines use `CLOCK_BOOTTIME` (Linux) or a process monotonic clock,
//! never cross-node wall time. A wall-clock step larger than the lease TTL, an
//! unavailable boot clock, or a boot-id change fences instead of extending the
//! lease.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

/// Boxed future used by the promotion host/timer traits.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A monotonic (suspend-inclusive where available) clock plus boot identity and
/// a wall-clock reading for step detection.
pub trait MonotonicClock: Send + Sync + 'static {
    /// Monotonic time in milliseconds since boot/start.
    fn boot_millis(&self) -> Result<u64, String>;
    /// Stable boot identity. A change while running is a fence condition.
    fn boot_id(&self) -> Result<String, String>;
    /// Wall-clock milliseconds since the Unix epoch. Used only to detect steps,
    /// never to decide lease expiry.
    fn wall_unix_ms(&self) -> i64;
}

/// The process monotonic clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemMonotonicClock;

impl SystemMonotonicClock {
    /// Creates a system clock handle.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn boot_millis(&self) -> Result<u64, String> {
        #[cfg(target_os = "linux")]
        {
            let mut timespec = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // CLOCK_BOOTTIME includes time spent suspended, which is exactly
            // the pause model the ADR relies on.
            let result = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut timespec) };
            if result != 0 {
                return Err(format!(
                    "CLOCK_BOOTTIME unavailable: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let secs = u64::try_from(timespec.tv_sec)
                .map_err(|_| "CLOCK_BOOTTIME returned a negative time".to_string())?;
            let nanos = u64::try_from(timespec.tv_nsec)
                .map_err(|_| "CLOCK_BOOTTIME returned invalid nanoseconds".to_string())?;
            Ok(secs.saturating_mul(1_000).saturating_add(nanos / 1_000_000))
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Non-Linux platforms lack CLOCK_BOOTTIME. A process monotonic clock
            // is the best available fallback; an operator on such a platform
            // must understand that a suspend can extend the apparent lease.
            Err("CLOCK_BOOTTIME is not available on this platform".to_string())
        }
    }

    fn boot_id(&self) -> Result<String, String> {
        #[cfg(target_os = "linux")]
        {
            let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|error| format!("cannot read boot_id: {error}"))?;
            let value = value.trim().to_string();
            if value.is_empty() {
                return Err("boot_id is empty".to_string());
            }
            Ok(value)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("boot_id is not available on this platform".to_string())
        }
    }

    fn wall_unix_ms(&self) -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
            Err(_) => 0,
        }
    }
}

/// A deterministic clock for tests and harnesses.
#[derive(Debug)]
pub struct ManualMonotonicClock {
    boot_millis: AtomicU64,
    wall_unix_ms: AtomicI64,
    boot_id: std::sync::Mutex<String>,
}

impl ManualMonotonicClock {
    /// Creates a clock anchored at `boot_millis`/`wall_unix_ms`.
    #[must_use]
    pub fn new(boot_millis: u64, wall_unix_ms: i64) -> Self {
        Self {
            boot_millis: AtomicU64::new(boot_millis),
            wall_unix_ms: AtomicI64::new(wall_unix_ms),
            boot_id: std::sync::Mutex::new("test-boot".to_string()),
        }
    }

    /// Advances monotonic time (used by deterministic timers).
    pub fn advance_boot(&self, delta_millis: u64) {
        self.boot_millis.fetch_add(delta_millis, Ordering::SeqCst);
    }

    /// Advances wall time independently (to test step detection).
    pub fn advance_wall(&self, delta_millis: i64) {
        self.wall_unix_ms.fetch_add(delta_millis, Ordering::SeqCst);
    }

    /// Changes the boot id (to test boot-id fence detection).
    pub fn set_boot_id(&self, boot_id: impl Into<String>) {
        *self
            .boot_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = boot_id.into();
    }

    /// Sets monotonic time absolute.
    pub fn set_boot(&self, boot_millis: u64) {
        self.boot_millis.store(boot_millis, Ordering::SeqCst);
    }
}

impl MonotonicClock for ManualMonotonicClock {
    fn boot_millis(&self) -> Result<u64, String> {
        Ok(self.boot_millis.load(Ordering::SeqCst))
    }

    fn boot_id(&self) -> Result<String, String> {
        Ok(self
            .boot_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone())
    }

    fn wall_unix_ms(&self) -> i64 {
        self.wall_unix_ms.load(Ordering::SeqCst)
    }
}

/// Async sleeps used by quiesce/reconciliation loops.
///
/// Production uses [`SystemTimers`] (tokio time). Tests use
/// [`ManualTimers`], which advances a [`ManualMonotonicClock`] by the requested
/// duration so a quiesce completes deterministically without wall sleeps.
pub trait PromotionTimers: Send + Sync + 'static {
    /// Sleeps for `duration`.
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()>;
}

/// Tokio-backed timers.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTimers;

impl PromotionTimers for SystemTimers {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// Deterministic timers for tests.
#[derive(Debug, Clone)]
pub struct ManualTimers {
    clock: Arc<ManualMonotonicClock>,
}

impl ManualTimers {
    /// Creates timers that advance `clock` on every sleep.
    #[must_use]
    pub const fn new(clock: Arc<ManualMonotonicClock>) -> Self {
        Self { clock }
    }
}

impl PromotionTimers for ManualTimers {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        let clock = Arc::clone(&self.clock);
        Box::pin(async move {
            clock.advance_boot(duration.as_millis().try_into().unwrap_or(u64::MAX));
            tokio::task::yield_now().await;
        })
    }
}
