//! Clock abstraction for witness expiry decisions.
//!
//! The witness always uses its own clock for `now_unix_ms` and lease expiry;
//! clients never compare `expires_unix_ms` with their own wall clock. Tests use
//! [`ManualClock`] to move witness time deterministically without weakening the
//! expiry rules.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of Unix wall-clock milliseconds used by the witness.
pub trait Clock: Send + Sync + 'static {
    /// Current witness time in Unix milliseconds.
    fn now_unix_ms(&self) -> i64;
}

/// The process system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SystemClock {
    /// Creates a system clock handle.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
            Err(error) => {
                // A clock set before the Unix epoch is not a valid witness
                // clock; clamp to the epoch rather than wrapping. Operators
                // should run NTP; expiry remains monotonic for lease purposes.
                let _ = error;
                0
            }
        }
    }
}

/// A manually advanced clock for deterministic tests.
#[derive(Debug)]
pub struct ManualClock {
    now_unix_ms: AtomicI64,
}

impl ManualClock {
    /// Creates a clock anchored at `now_unix_ms`.
    #[must_use]
    pub const fn new(now_unix_ms: i64) -> Self {
        Self {
            now_unix_ms: AtomicI64::new(now_unix_ms),
        }
    }

    /// Moves the clock forward by `delta_ms` (a negative value moves it back).
    pub fn advance(&self, delta_ms: i64) {
        self.now_unix_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }

    /// Sets the clock to an absolute value.
    pub fn set(&self, now_unix_ms: i64) {
        self.now_unix_ms.store(now_unix_ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_unix_ms(&self) -> i64 {
        self.now_unix_ms.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_moves_forward_and_backward() {
        let clock = ManualClock::new(1_000);
        assert_eq!(clock.now_unix_ms(), 1_000);
        clock.advance(500);
        assert_eq!(clock.now_unix_ms(), 1_500);
        clock.advance(-2_000);
        assert_eq!(clock.now_unix_ms(), -500);
        clock.set(42);
        assert_eq!(clock.now_unix_ms(), 42);
    }
}
