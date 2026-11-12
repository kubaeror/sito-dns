//! Poison-recovery helpers for standard-library locks.
//!
//! A panic while a lock guard is held poisons the lock. Production readiness,
//! persistence and configuration paths must not panic a second time (or abort a
//! release build) just because an earlier task panicked after it had already
//! written a valid value. The helpers below return the last-good value via
//! [`std::sync::PoisonError::into_inner`] and log the recovery once per process.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Process-wide guard so a poisoned lock is reported once, not on every query.
static POISON_LOGGED: AtomicBool = AtomicBool::new(false);

/// Locks `mutex`, recovering the last-good value when the previous holder
/// panicked instead of propagating the poison.
pub fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    lock_or_recover_named(mutex, "mutex")
}

/// Like [`lock_or_recover`], but names the component in the one-time log line.
pub fn lock_or_recover_named<'a, T>(mutex: &'a Mutex<T>, component: &str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log_recovery(component);
            poisoned.into_inner()
        }
    }
}

/// Reads `lock`, recovering the last-good value when a previous writer panicked.
pub fn read_or_recover<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    read_or_recover_named(lock, "rwlock")
}

/// Like [`read_or_recover`], but names the component in the one-time log line.
pub fn read_or_recover_named<'a, T>(
    lock: &'a RwLock<T>,
    component: &str,
) -> RwLockReadGuard<'a, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log_recovery(component);
            poisoned.into_inner()
        }
    }
}

/// Writes `lock`, recovering the last-good value when a previous holder
/// panicked.
pub fn write_or_recover<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    write_or_recover_named(lock, "rwlock")
}

/// Like [`write_or_recover`], but names the component in the one-time log line.
pub fn write_or_recover_named<'a, T>(
    lock: &'a RwLock<T>,
    component: &str,
) -> RwLockWriteGuard<'a, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log_recovery(component);
            poisoned.into_inner()
        }
    }
}

fn log_recovery(component: &str) {
    if !POISON_LOGGED.swap(true, Ordering::Relaxed) {
        tracing::error!(
            component,
            "Recovered a poisoned lock; using its last-good value. An earlier task panicked while holding it."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn poison_mutex(mutex: &Arc<Mutex<u32>>) {
        let poisoned = Arc::clone(mutex);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.lock().expect("fresh mutex");
            panic!("poison the mutex after writing a valid value");
        })
        .join();
        assert!(mutex.is_poisoned());
    }

    #[test]
    fn test_lock_or_recover_returns_last_good_value_after_poison() {
        let mutex = Arc::new(Mutex::new(vec!["last-good"]));
        let poisoned = Arc::clone(&mutex);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.lock().expect("fresh mutex");
            panic!("poison the mutex after writing a valid value");
        })
        .join();

        // A plain `lock().unwrap()` would panic here; recovery must return the
        // value written before the panic.
        assert_eq!(lock_or_recover(&mutex).as_slice(), ["last-good"]);
    }

    #[test]
    fn test_lock_or_recover_recovers_repeated_poisoned_locks() {
        let mutex = Arc::new(Mutex::new(0u32));
        poison_mutex(&mutex);

        // Recovery must keep working (and not deadlock) after the process-wide
        // one-time log has already fired.
        *lock_or_recover(&mutex) += 1;
        *lock_or_recover(&mutex) += 1;
        assert_eq!(*lock_or_recover(&mutex), 2);
    }

    #[test]
    fn test_rwlock_read_and_write_recover_after_poison() {
        let lock = Arc::new(RwLock::new(vec!["last-good"]));
        let poisoned = Arc::clone(&lock);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.write().expect("fresh rwlock");
            panic!("poison the rwlock");
        })
        .join();
        assert!(lock.is_poisoned());

        assert_eq!(read_or_recover(&lock).as_slice(), ["last-good"]);
        write_or_recover(&lock).push("new");
        assert_eq!(read_or_recover(&lock).as_slice(), ["last-good", "new"]);
    }
}
