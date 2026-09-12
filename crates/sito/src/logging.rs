//! Runtime log-level reloading.
//!
//! The tracing subscriber is installed once at startup; the config file
//! watcher updates the `EnvFilter` through this module without rebuilding the
//! subscriber. `log_format` intentionally stays restart-only.

use std::sync::OnceLock;

type ReloadFn = Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

static RELOAD_FN: OnceLock<ReloadFn> = OnceLock::new();

/// Registers the filter-reload callback. Called once during startup.
///
/// Returns `true` when the callback was installed; `false` when one was
/// already installed (for example in tests that call the initializer twice).
#[must_use]
pub fn install_reload_fn(
    reload: impl Fn(&str) -> Result<(), String> + Send + Sync + 'static,
) -> bool {
    RELOAD_FN.set(Box::new(reload)).is_ok()
}

/// Applies a new log level (for example `"debug"`) to the live subscriber.
///
/// Returns `false` when no reload callback is installed (unit tests, embedded
/// use); callers may log a warning but must not treat it as fatal.
#[must_use]
pub fn reload_level(level: &str) -> bool {
    match RELOAD_FN.get() {
        Some(reload) => match reload(level) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("Failed to reload log level to '{level}': {e}");
                false
            }
        },
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_install_and_reload_level() {
        // Unit tests run without a subscriber installed.
        assert!(!reload_level("debug"));

        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_clone = Arc::clone(&seen);
        assert!(install_reload_fn(move |level| {
            seen_clone.lock().unwrap().push(level.to_string());
            Ok(())
        }));

        assert!(reload_level("trace"));
        assert_eq!(seen.lock().unwrap().as_slice(), ["trace"]);
    }
}
