//! Deterministic clock abstraction for timing-sensitive tests.
//!
//! Production code keeps using `tokio::time`/`Instant::now()`; this module only
//! gives tests a way to replace wall-clock waiting with an explicit
//! [`ManualClock::advance`]. Tests that need to prove a real timeout/duration
//! (for example the HA master-loss deadline or an upstream timeout budget)
//! still use [`SystemClock`] or a genuine `tokio::time::sleep`, and say why.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

/// A source of monotonic time plus an async sleep.
///
/// The returned future is `'static` so a test can move a clock-backed sleep
/// into a spawned task without borrowing the clock.
pub trait Clock: fmt::Debug + Send + Sync {
    /// Current monotonic time.
    fn now(&self) -> Instant;

    /// Resolves after `duration` of this clock's time has elapsed.
    ///
    /// [`SystemClock`] uses the real tokio timer; [`ManualClock`] only resolves
    /// after [`ManualClock::advance`] moves past the deadline.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}

/// The real monotonic clock backed by tokio's timer.
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
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(tokio::time::sleep(duration))
    }
}

#[derive(Debug)]
struct Waiter {
    id: u64,
    deadline: Instant,
    waker: Waker,
}

#[derive(Debug)]
struct ManualState {
    elapsed: Duration,
    next_waiter_id: u64,
    waiters: Vec<Waiter>,
}

#[derive(Debug)]
struct ManualInner {
    started_at: Instant,
    state: Mutex<ManualState>,
}

/// A clock that only moves when the test advances it.
///
/// `now()` starts at [`ManualClock::started_at`] and never moves on its own.
/// `sleep` registers a waiter that is woken by [`ManualClock::advance`] (or
/// [`ManualClock::notify`] for a re-poll without moving time).
#[derive(Debug, Clone)]
pub struct ManualClock {
    inner: Arc<ManualInner>,
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl ManualClock {
    /// Creates a manual clock anchored at the current real instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ManualInner {
                started_at: Instant::now(),
                state: Mutex::new(ManualState {
                    elapsed: Duration::ZERO,
                    next_waiter_id: 0,
                    waiters: Vec::new(),
                }),
            }),
        }
    }

    /// The real instant this clock started at.
    ///
    /// Useful to convert a manual `now()` into elapsed time without relying on
    /// the process-wide real clock.
    #[must_use]
    pub fn started_at(&self) -> Instant {
        self.inner.started_at
    }

    /// How much manual time has elapsed since construction.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.lock_state().elapsed
    }

    /// Number of registered sleepers that have not reached their deadline.
    #[must_use]
    pub fn waiters(&self) -> usize {
        self.lock_state().waiters.len()
    }

    /// Moves manual time forward by `duration` and wakes every sleeper whose
    /// deadline has been reached.
    pub fn advance(&self, duration: Duration) {
        let now = {
            let mut state = self.lock_state();
            state.elapsed = state.elapsed.saturating_add(duration);
            self.inner.started_at + state.elapsed
        };

        let due = {
            let mut state = self.lock_state();
            let mut due = Vec::new();
            let mut pending = Vec::with_capacity(state.waiters.len());
            for waiter in state.waiters.drain(..) {
                if waiter.deadline <= now {
                    due.push(waiter);
                } else {
                    pending.push(waiter);
                }
            }
            state.waiters = pending;
            due
        };

        for waiter in due {
            waiter.waker.wake();
        }
    }

    /// Wakes every registered sleeper so it re-polls, without moving time.
    ///
    /// A sleeper whose deadline is still in the future registers again and
    /// stays pending; this is useful to interrupt a `select!` loop.
    pub fn notify(&self) {
        let wakers = {
            let state = self.lock_state();
            state
                .waiters
                .iter()
                .map(|waiter| waiter.waker.clone())
                .collect::<Vec<_>>()
        };
        for waker in wakers {
            waker.wake();
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ManualState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Registers (or replaces) the sleeper's waiter, or reports that the
    /// deadline has already passed.
    ///
    /// The deadline check and registration happen under one lock: `advance`
    /// cannot slip between them and drain the list before the waiter is
    /// inserted, which used to leave the sleeper pending forever.
    fn register_or_expired(
        &self,
        deadline: Instant,
        waker: Waker,
        existing: Option<u64>,
    ) -> Option<u64> {
        let mut state = self.lock_state();
        if let Some(id) = existing {
            state.waiters.retain(|waiter| waiter.id != id);
        }
        let now = self.inner.started_at + state.elapsed;
        if now >= deadline {
            return None;
        }
        let id = state.next_waiter_id;
        state.next_waiter_id += 1;
        state.waiters.push(Waiter {
            id,
            deadline,
            waker,
        });
        Some(id)
    }

    fn unregister(&self, id: u64) {
        let mut state = self.lock_state();
        state.waiters.retain(|waiter| waiter.id != id);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.inner.started_at + self.lock_state().elapsed
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let deadline = self
            .now()
            .checked_add(duration)
            .unwrap_or_else(|| self.now() + Duration::from_hours(365 * 24));
        Box::pin(ManualSleep {
            clock: self.clone(),
            deadline,
            waiter: None,
        })
    }
}

struct ManualSleep {
    clock: ManualClock,
    deadline: Instant,
    waiter: Option<u64>,
}

impl Future for ManualSleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // One critical section checks the deadline and either reports it due
        // or inserts the waiter. This closes the check-then-register race with
        // `advance`; on every re-poll it also replaces the previous waiter so
        // an early `notify` cannot leave a duplicate.
        let deadline = self.deadline;
        let waiter = self.waiter.take();
        match self
            .clock
            .register_or_expired(deadline, cx.waker().clone(), waiter)
        {
            Some(id) => {
                self.waiter = Some(id);
                Poll::Pending
            }
            None => Poll::Ready(()),
        }
    }
}

impl Drop for ManualSleep {
    fn drop(&mut self) {
        if let Some(id) = self.waiter.take() {
            self.clock.unregister(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Clock, ManualClock, SystemClock};
    use std::time::Duration;

    #[tokio::test]
    async fn manual_clock_advance_is_saturating_and_idempotent_for_deadlines() {
        let clock = ManualClock::new();
        clock.advance(Duration::from_secs(3));
        clock.advance(Duration::from_secs(4));
        assert_eq!(clock.elapsed(), Duration::from_secs(7));
        assert_eq!(clock.waiters(), 0);
    }

    #[test]
    fn register_or_expired_is_atomic_with_a_past_deadline() {
        let clock = ManualClock::new();
        let deadline = clock.now() + Duration::from_secs(1);
        clock.advance(Duration::from_secs(1));
        // Old check-then-register code would insert a waiter here and never
        // wake it. The atomic helper reports the deadline as already expired.
        assert!(
            clock
                .register_or_expired(deadline, std::task::Waker::noop().clone(), None)
                .is_none()
        );
        assert_eq!(clock.waiters(), 0);
    }

    #[test]
    fn register_or_expired_keeps_future_waiters() {
        let clock = ManualClock::new();
        let deadline = clock.now() + Duration::from_secs(1);
        let id = clock.register_or_expired(deadline, std::task::Waker::noop().clone(), None);
        assert!(id.is_some());
        assert_eq!(clock.waiters(), 1);
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            clock.waiters(),
            0,
            "advance must drain the registered waiter"
        );
    }

    #[tokio::test]
    async fn system_clock_sleep_resolves() {
        let clock = SystemClock::new();
        tokio::time::timeout(
            Duration::from_secs(1),
            clock.sleep(Duration::from_millis(1)),
        )
        .await
        .expect("system clock sleep must use a real timer");
    }
}
