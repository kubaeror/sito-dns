//! Test-only timing helpers for load-robust performance assertions.
//!
//! Wall-clock bounds on CPU-bound work are sensitive to unrelated load on the
//! host: a concurrent build can inflate wall time by an order of magnitude
//! while the code under test consumes the same amount of CPU. Sampling
//! `CLOCK_THREAD_CPUTIME_ID` measures only the time this thread actually ran,
//! so an assertion stays meaningful on a busy CI host while still catching a
//! real regression in compile work.

use std::time::Duration;

/// Returns the current thread's consumed CPU time, if the platform has it.
///
/// Returns `None` when the clock is unavailable (non-Unix, or a failed
/// syscall). Callers must then fall back to a generous wall-clock hang guard
/// and rely on the Criterion benchmark for the performance signal.
#[cfg(unix)]
pub(crate) fn thread_cpu_time() -> Option<Duration> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `CLOCK_THREAD_CPUTIME_ID` is a valid clock id on Unix and `ts`
    // is a valid, writable `timespec` for the duration of the call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut ts) };
    if rc != 0 || ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return None;
    }
    Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

/// Non-Unix fallback: no portable thread CPU clock, so callers use the
/// wall-clock hang guard and the Criterion benchmark gate instead.
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
    pub(crate) fn start() -> Self {
        Self {
            started: thread_cpu_time(),
        }
    }

    /// CPU time consumed since [`start`](Self::start), or `None` when the
    /// clock is unavailable now or was unavailable at start.
    pub(crate) fn elapsed(&self) -> Option<Duration> {
        let started = self.started?;
        Some(thread_cpu_time()?.saturating_sub(started))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hint::black_box;

    #[test]
    fn thread_cpu_time_tracks_cpu_work_but_not_sleep() {
        let Some(start) = thread_cpu_time() else {
            // Non-Unix (or a platform without the thread CPU clock): the
            // wall-clock hang guard is the only timing assertion there.
            return;
        };

        // A fixed amount of CPU work. Wall time can stretch under host load,
        // but the thread CPU clock must advance by the work itself.
        let mut spin = 0u64;
        for i in 0..20_000_000u64 {
            spin = spin.wrapping_add(i);
        }
        black_box(spin);

        let after_work = thread_cpu_time().expect("thread CPU clock disappeared mid-test");
        assert!(
            after_work > start,
            "thread CPU time must advance with CPU work ({start:?} -> {after_work:?})"
        );
        assert!(
            after_work.saturating_sub(start) < Duration::from_secs(30),
            "20M integer adds must not consume 30 s of CPU"
        );

        // Sleeping consumes no thread CPU time. This is the property that
        // makes a CPU-time bound load-robust while a wall-clock bound flaked.
        std::thread::sleep(Duration::from_millis(20));
        let after_sleep = thread_cpu_time().expect("thread CPU clock disappeared mid-test");
        let slept_cpu = after_sleep.saturating_sub(after_work);
        assert!(
            slept_cpu < Duration::from_millis(10),
            "a sleeping thread must not accrue CPU time, got {slept_cpu:?}"
        );

        // The timer wrapper agrees with the raw samples.
        let timer = ThreadCpuTimer::start();
        let mut spin = 0u64;
        for i in 0..1_000_000u64 {
            spin = spin.wrapping_add(i);
        }
        black_box(spin);
        let elapsed = timer.elapsed().expect("clock is available");
        assert!(
            elapsed < Duration::from_secs(5),
            "1M integer adds must not consume 5 s of CPU, got {elapsed:?}"
        );
    }
}
