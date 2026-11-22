//! DNS client ACL logging sampler (ADR-0011).
//!
//! Denied queries are not written to the detailed query log. The first denial
//! for a source is logged at `info`; subsequent denials from that source are
//! logged at `debug` for the next 60 seconds. A global token bucket caps
//! `info` lines at 10 per second so a unique/spoofed-source flood cannot turn
//! logging into the bottleneck. The per-source map is bounded (1024) and
//! pruned after 5 minutes of inactivity.
//!
//! The sampler holds no client identity and never records a query name, DoH
//! path, SNI, header or credential.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Rewrite window: a source denied again inside this window logs at `debug`.
const ACL_INFO_WINDOW: Duration = Duration::from_secs(60);
/// Drop source entries after this much inactivity.
const ACL_SOURCE_IDLE: Duration = Duration::from_secs(300);
/// Minimum interval between idle sweeps, so pruning is not an O(n) per-query
/// cost even below the source cap.
const ACL_PRUNE_INTERVAL: Duration = Duration::from_secs(60);
/// Maximum tracked sources.
const ACL_SOURCE_CAP: usize = 1024;
/// Global `info` lines per second.
const ACL_INFO_BURST: f64 = 10.0;
const ACL_INFO_PER_SECOND: f64 = 10.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AclLogLevel {
    Info,
    Debug,
}

#[derive(Debug)]
struct AclLogState {
    last_info: HashMap<IpAddr, Instant>,
    tokens: f64,
    last_refill: Instant,
    last_prune: Instant,
}

impl AclLogState {
    fn new(now: Instant) -> Self {
        Self {
            last_info: HashMap::new(),
            tokens: ACL_INFO_BURST,
            last_refill: now,
            last_prune: now,
        }
    }
}

/// Thread-safe, bounded ACL denial log sampler.
#[derive(Debug)]
pub(super) struct AclLogSampler {
    state: std::sync::Mutex<AclLogState>,
}

impl Default for AclLogSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl AclLogSampler {
    pub(super) fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(AclLogState::new(Instant::now())),
        }
    }

    /// Records a denied source and returns the level for this denial.
    pub(super) fn record(&self, source: IpAddr) -> AclLogLevel {
        self.record_at(source, Instant::now())
    }

    /// Testable variant with an explicit clock.
    pub(super) fn record_at(&self, source: IpAddr, now: Instant) -> AclLogLevel {
        // Never block the query path on the sampler: if another task is
        // updating it, fall back to debug (dropping an info line is safe).
        let Ok(mut state) = self.state.try_lock() else {
            return AclLogLevel::Debug;
        };

        // Sweep idle sources at most once a minute, not only at the cap.
        if now.saturating_duration_since(state.last_prune) >= ACL_PRUNE_INTERVAL {
            state
                .last_info
                .retain(|_, seen| now.saturating_duration_since(*seen) < ACL_SOURCE_IDLE);
            state.last_prune = now;
        }

        // Bound the map when it is full: drop the oldest entry. This scan is
        // rare (only at the cap with a new source) and never per query.
        if state.last_info.len() >= ACL_SOURCE_CAP
            && !state.last_info.contains_key(&source)
            && let Some(oldest) = state
                .last_info
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(ip, _)| *ip)
        {
            state.last_info.remove(&oldest);
        }

        if let Some(seen) = state.last_info.get(&source)
            && now.saturating_duration_since(*seen) < ACL_INFO_WINDOW
        {
            return AclLogLevel::Debug;
        }

        // Refill the global info bucket.
        let elapsed = now.saturating_duration_since(state.last_refill);
        state.tokens =
            (state.tokens + elapsed.as_secs_f64() * ACL_INFO_PER_SECOND).min(ACL_INFO_BURST);
        state.last_refill = now;

        state.last_info.insert(source, now);

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            AclLogLevel::Info
        } else {
            AclLogLevel::Debug
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_denial_is_info_and_repeat_is_debug() {
        let sampler = AclLogSampler::new();
        let source: IpAddr = "192.0.2.10".parse().unwrap();
        let t0 = Instant::now();
        assert_eq!(sampler.record_at(source, t0), AclLogLevel::Info);
        assert_eq!(
            sampler.record_at(source, t0 + Duration::from_secs(10)),
            AclLogLevel::Debug
        );
        assert_eq!(
            sampler.record_at(source, t0 + ACL_INFO_WINDOW + Duration::from_secs(1)),
            AclLogLevel::Info
        );
    }

    #[test]
    fn global_info_bucket_caps_a_unique_source_flood() {
        let sampler = AclLogSampler::new();
        let t0 = Instant::now();
        let mut info = 0;
        for index in 0..100u32 {
            let source: IpAddr = format!("198.51.100.{index}").parse().unwrap();
            if sampler.record_at(source, t0) == AclLogLevel::Info {
                info += 1;
            }
        }
        assert_eq!(info, ACL_INFO_BURST as usize, "10 info lines per burst");
    }

    #[test]
    fn source_map_is_bounded_and_idle_entries_are_pruned() {
        let sampler = AclLogSampler::new();
        let t0 = Instant::now();
        for index in 0..5000u32 {
            let source = IpAddr::V4(std::net::Ipv4Addr::from(index + 1));
            let at = t0 + Duration::from_millis(u64::from(index));
            let _ = sampler.record_at(source, at);
        }
        let state = sito_core::sync::lock_or_recover(&sampler.state);
        assert!(state.last_info.len() <= ACL_SOURCE_CAP);
    }
}
