//! Test-only timing helpers for load-robust performance assertions.
//!
//! Wall-clock bounds on CPU-bound work are sensitive to unrelated load on the
//! host: a concurrent build can inflate wall time by an order of magnitude
//! while the code under test consumes the same amount of CPU. Sampling
//! `CLOCK_THREAD_CPUTIME_ID` measures only the time this thread actually ran,
//! so an assertion stays meaningful on a busy CI host while still catching a
//! real regression in compile work.

use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::Duration;

/// Returns the current thread's consumed CPU time.
///
/// Unix always returns `Some`; a failed `clock_gettime` panics instead of
/// silently skipping the CPU gate, because the CI runner is Linux and the
/// load-robust assertion must not degrade to a wall-clock-only check there.
/// Non-Unix hosts return `None`: they have no portable thread CPU clock, so
/// only a wall-clock guard applies and no in-test CPU bound is claimed. The
/// nightly benchmark gate is Linux-only and, until the next re-baseline, the
/// new benchmark is informational.
// The `Option` is part of the cross-platform signature: Unix always returns
// `Some`, while non-Unix returns `None`. Clippy only sees one cfg branch.
#[allow(clippy::unnecessary_wraps)]
#[cfg(unix)]
pub(crate) fn thread_cpu_time() -> Option<Duration> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `CLOCK_THREAD_CPUTIME_ID` is a valid clock id on Unix and `ts`
    // is a valid, writable `timespec` for the duration of the call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut ts) };
    assert!(
        rc == 0,
        "clock_gettime(CLOCK_THREAD_CPUTIME_ID) failed: {}",
        std::io::Error::last_os_error()
    );
    let (sec, nsec) = (ts.tv_sec, ts.tv_nsec);
    assert!(
        sec >= 0 && (0..1_000_000_000).contains(&nsec),
        "clock_gettime returned an invalid timespec: {sec}s {nsec}ns"
    );
    Some(Duration::new(sec as u64, nsec as u32))
}

/// Non-Unix fallback: no portable thread CPU clock, so callers use only a
/// wall-clock guard. CI runs on Ubuntu, so this is not the gated path.
#[cfg(not(unix))]
pub(crate) fn thread_cpu_time() -> Option<Duration> {
    None
}

/// A CPU-time interval for the current thread.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ThreadCpuTimer {
    started: Option<Duration>,
}

impl ThreadCpuTimer {
    /// Starts sampling at the current thread CPU time.
    ///
    /// Panics on Unix if the thread CPU clock is unavailable; see
    /// [`thread_cpu_time`].
    pub(crate) fn start() -> Self {
        Self {
            started: thread_cpu_time(),
        }
    }

    /// CPU time consumed since [`start`](Self::start), or `None` on a platform
    /// without a thread CPU clock.
    pub(crate) fn elapsed(&self) -> Option<Duration> {
        let started = self.started?;
        Some(thread_cpu_time()?.saturating_sub(started))
    }
}

/// Runs `work` on a worker thread and panics if it does not return within
/// `guard`.
///
/// A post-hoc wall-clock assertion cannot catch a deadlock: if the work never
/// returns, the assertion is never reached. Waiting on a channel with a timeout
/// makes the guard real. The worker thread cannot be killed; on timeout the
/// test panics and the harness terminates the process.
pub(crate) fn with_hang_guard<T, F>(guard: Duration, work: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = channel();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    match rx.recv_timeout(guard) {
        Ok(value) => {
            worker
                .join()
                .expect("guarded worker panicked after sending a result");
            value
        }
        Err(RecvTimeoutError::Timeout) => {
            panic!("guarded work did not finish within the {guard:?} hang guard")
        }
        Err(RecvTimeoutError::Disconnected) => {
            if let Err(payload) = worker.join() {
                std::panic::resume_unwind(payload);
            }
            panic!("guarded worker exited without returning a result");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hint::black_box;

    #[test]
    fn thread_cpu_time_tracks_cpu_work_but_not_sleep() {
        let Some(start) = thread_cpu_time() else {
            // Non-Unix: no thread CPU clock, so only the wall guard applies.
            // On Unix a missing clock panics instead of reaching this branch.
            return;
        };

        // A fixed amount of CPU work. Wall time can stretch under host load,
        // but the thread CPU clock must advance by the work itself.
        // `black_box(i)` prevents the compiler from folding the loop away.
        let mut spin = 0u64;
        for i in 0..20_000_000u64 {
            spin = spin.wrapping_add(black_box(i));
        }
        black_box(spin);

        let after_work = thread_cpu_time().expect("clock is available");
        assert!(
            after_work > start,
            "thread CPU time must advance with CPU work ({start:?} -> {after_work:?})"
        );
        let work_cpu = after_work.saturating_sub(start);
        assert!(
            work_cpu >= Duration::from_millis(1),
            "20M integer adds must consume measurable CPU time, got {work_cpu:?}"
        );
        assert!(
            work_cpu < Duration::from_secs(30),
            "20M integer adds must not consume 30 s of CPU"
        );

        // Sleeping consumes no thread CPU time. This is the property that
        // makes a CPU-time bound load-robust while a wall-clock bound flaked.
        std::thread::sleep(Duration::from_millis(20));
        let after_sleep = thread_cpu_time().expect("clock is available");
        let slept_cpu = after_sleep.saturating_sub(after_work);
        assert!(
            slept_cpu < Duration::from_millis(10),
            "a sleeping thread must not accrue CPU time, got {slept_cpu:?}"
        );

        // The timer wrapper agrees with the raw samples.
        let timer = ThreadCpuTimer::start();
        let mut spin = 0u64;
        for i in 0..1_000_000u64 {
            spin = spin.wrapping_add(black_box(i));
        }
        black_box(spin);
        let elapsed = timer.elapsed().expect("clock is available");
        assert!(
            elapsed < Duration::from_secs(5),
            "1M integer adds must not consume 5 s of CPU, got {elapsed:?}"
        );
    }

    #[test]
    fn hang_guard_returns_completed_work() {
        assert_eq!(
            with_hang_guard(Duration::from_secs(5), || 42u8),
            42,
            "a worker that finishes inside the guard must return its value"
        );
    }

    #[test]
    fn hang_guard_times_out_instead_of_blocking() {
        let result = std::panic::catch_unwind(|| {
            with_hang_guard(Duration::from_millis(20), || {
                std::thread::sleep(Duration::from_millis(250));
                1u8
            })
        });
        assert!(
            result.is_err(),
            "work that outlives the guard must panic instead of blocking the test"
        );
    }
}
