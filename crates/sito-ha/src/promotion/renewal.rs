//! Renewal-conflict classification and self-fence deadlines (ADR-0010).
//!
//! A 409 from the witness is not automatically "lease lost". The record is
//! re-read and classified: a lost ACK adopts the new revision, a witness
//! baseline below ours can be retried, and any uncertainty fences.

use std::time::Duration;

use crate::witness::LeaseRecord;

use super::witness_client::WitnessClientError;

use super::clock::MonotonicClock;
use super::state::PublicationBaseline;

/// How the engine should react to a renewal result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalAction {
    /// Renewal succeeded; continue with this revision.
    Continue { revision: u64 },
    /// The witness is behind our published baseline; retry with this revision
    /// and the higher baseline (already held locally).
    RetryHigherBaseline { revision: u64 },
    /// Adopt a lost renewal ACK revision and continue.
    AdoptRevision { revision: u64 },
    /// Retry a transport/5xx failure; the self-fence deadline is still ticking.
    RetryTransport,
    /// Fence immediately with this reason, plus the human-readable detail.
    Fence {
        /// Stable reason code.
        reason: &'static str,
        /// Operator-facing detail.
        detail: String,
    },
}

/// Classifies one failed renewal against the local published baseline.
///
/// `witness_now_unix_ms` is the witness clock from `GET /v1/info`, when known.
/// Expiry is never judged with the node's own wall clock.
pub fn classify_renewal_error(
    error: &WitnessClientError,
    holder: &str,
    term: u64,
    baseline: &PublicationBaseline,
    witness_now_unix_ms: Option<i64>,
) -> RenewalAction {
    match error {
        WitnessClientError::Conflict { current, .. } => match current.as_deref() {
            None => fence("lease_record_missing", "the witness has no lease record"),
            Some(record) => classify_record(record, holder, term, baseline, witness_now_unix_ms),
        },
        WitnessClientError::Auth { detail } => fence(
            "witness_auth_failed",
            format!("witness authentication failed: {detail}"),
        ),
        WitnessClientError::ClusterMismatch { detail } => fence(
            "witness_cluster_mismatch",
            format!("witness cluster mismatch: {detail}"),
        ),
        WitnessClientError::Tls { detail } => fence(
            "witness_tls_failed",
            format!("witness TLS failed: {detail}"),
        ),
        WitnessClientError::Protocol { detail } => fence(
            "witness_protocol_mismatch",
            format!("invalid witness response: {detail}"),
        ),
        WitnessClientError::ProtocolMismatch { found, expected } => fence(
            "witness_protocol_mismatch",
            format!("witness protocol {found} does not match {expected}"),
        ),
        WitnessClientError::Unavailable { .. } => RenewalAction::RetryTransport,
        WitnessClientError::Server { status, .. } if *status >= 500 => {
            RenewalAction::RetryTransport
        }
        WitnessClientError::Server { status, detail, .. } => fence(
            "lease_lost",
            format!(
                "witness rejected renewal with HTTP {status}: {}",
                detail.as_deref().unwrap_or("no detail")
            ),
        ),
        WitnessClientError::InvalidConfig { field, detail } => fence(
            "witness_config_invalid",
            format!("invalid {field}: {detail}"),
        ),
        WitnessClientError::InvalidHash { detail } => fence(
            "invalid_bundle_hash",
            format!("local published hash is invalid: {detail}"),
        ),
        WitnessClientError::Disabled => fence("promotion_disabled", "promotion is disabled"),
    }
}

fn classify_record(
    record: &LeaseRecord,
    holder: &str,
    term: u64,
    baseline: &PublicationBaseline,
    witness_now_unix_ms: Option<i64>,
) -> RenewalAction {
    let expired = witness_now_unix_ms.is_some_and(|now| record.is_expired(now));
    if record.holder != holder || record.term > term {
        return fence(
            "lease_lost",
            format!(
                "the lease is held by '{}' at term {} (this node is '{}' at term {term})",
                record.holder, record.term, holder
            ),
        );
    }
    if record.term < term {
        return fence(
            "lease_version_regression",
            format!(
                "the witness moved backwards to term {} (this node holds term {term})",
                record.term
            ),
        );
    }
    if expired {
        return fence(
            "lease_lost",
            "the witness record expired before the self-fence deadline fired",
        );
    }
    if record.version < baseline.version {
        // The witness is behind our published baseline (for example a lost
        // renewal ACK from an earlier publish). Adopt the revision and retry
        // with the higher baseline; never move our baseline backwards.
        return RenewalAction::RetryHigherBaseline {
            revision: record.revision,
        };
    }
    if record.version > baseline.version || !hashes_equal(&record.bundle_hash, &baseline.hash) {
        return fence(
            "lease_version_regression",
            format!(
                "witness baseline is version {} hash {} but this node published version {} hash {}; refusing to renew below or beside the witness",
                record.version, record.bundle_hash, baseline.version, baseline.hash
            ),
        );
    }
    RenewalAction::AdoptRevision {
        revision: record.revision,
    }
}

fn fence(reason: &'static str, detail: impl Into<String>) -> RenewalAction {
    RenewalAction::Fence {
        reason,
        detail: detail.into(),
    }
}

fn hashes_equal(left: &str, right: &str) -> bool {
    left.trim()
        .trim_start_matches("blake3:")
        .eq_ignore_ascii_case(right.trim().trim_start_matches("blake3:"))
}

/// Self-fence deadline state.
///
/// The deadline is `TTL - max(2, renew_interval)` measured from the last
/// successful ACK. A wall step larger than the TTL, an unavailable boot clock,
/// or a boot-id change returns a fence instead of extending the lease.
#[derive(Debug, Clone)]
pub struct SelfFenceDeadline {
    deadline_millis: u64,
    boot_id: String,
    last_wall_unix_ms: i64,
    ttl_millis: i64,
}

/// What the self-fence monitor observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfFenceCheck {
    /// The lease is still safe.
    Safe,
    /// The deadline has passed.
    DeadlinePassed,
    /// The boot clock is unavailable.
    ClockUnavailable(String),
    /// The boot id changed while running.
    BootIdChanged,
    /// Wall time stepped by more than the TTL.
    WallStep,
}

impl SelfFenceDeadline {
    /// Arms the deadline from `now_boot_millis` after a successful ACK.
    #[must_use]
    pub fn arm(
        now_boot_millis: u64,
        boot_id: impl Into<String>,
        last_wall_unix_ms: i64,
        lease_ttl_secs: u64,
        renew_interval_secs: u64,
    ) -> Self {
        let margin = renew_interval_secs.max(2);
        let deadline_secs = lease_ttl_secs.saturating_sub(margin);
        let deadline_millis = now_boot_millis.saturating_add(deadline_secs.saturating_mul(1_000));
        Self {
            deadline_millis,
            boot_id: boot_id.into(),
            last_wall_unix_ms,
            ttl_millis: i64::try_from(lease_ttl_secs.saturating_mul(1_000)).unwrap_or(i64::MAX),
        }
    }

    /// Re-arms after a successful renewal.
    pub fn renew(
        &mut self,
        now_boot_millis: u64,
        last_wall_unix_ms: i64,
        lease_ttl_secs: u64,
        renew_interval_secs: u64,
    ) {
        *self = Self::arm(
            now_boot_millis,
            self.boot_id.clone(),
            last_wall_unix_ms,
            lease_ttl_secs,
            renew_interval_secs,
        );
    }

    /// The absolute monotonic deadline in milliseconds.
    #[must_use]
    pub const fn deadline_millis(&self) -> u64 {
        self.deadline_millis
    }

    /// Checks the deadline and clock integrity.
    #[must_use]
    pub fn check(&self, clock: &dyn MonotonicClock) -> SelfFenceCheck {
        let now = match clock.boot_millis() {
            Ok(now) => now,
            Err(error) => return SelfFenceCheck::ClockUnavailable(error),
        };
        let boot_id = match clock.boot_id() {
            Ok(boot_id) => boot_id,
            Err(error) => return SelfFenceCheck::ClockUnavailable(error),
        };
        if boot_id != self.boot_id {
            return SelfFenceCheck::BootIdChanged;
        }
        if clock
            .wall_unix_ms()
            .saturating_sub(self.last_wall_unix_ms)
            .unsigned_abs()
            > u64::try_from(self.ttl_millis).unwrap_or(u64::MAX)
        {
            return SelfFenceCheck::WallStep;
        }
        if now >= self.deadline_millis {
            SelfFenceCheck::DeadlinePassed
        } else {
            SelfFenceCheck::Safe
        }
    }

    /// The remaining safe time at `now_boot_millis`.
    #[must_use]
    pub fn remaining(&self, now_boot_millis: u64) -> Duration {
        Duration::from_millis(self.deadline_millis.saturating_sub(now_boot_millis))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::promotion::clock::ManualMonotonicClock;
    use std::sync::Arc;

    fn baseline() -> PublicationBaseline {
        PublicationBaseline::new(7, &"ab".repeat(32)).unwrap()
    }

    fn record(holder: &str, term: u64, revision: u64, version: u64, hash: &str) -> LeaseRecord {
        LeaseRecord {
            schema: 1,
            cluster_id: "home-dns".to_string(),
            holder: holder.to_string(),
            node_id: "node-a".to_string(),
            term,
            revision,
            version,
            bundle_hash: hash.to_string(),
            acquired_unix_ms: 0,
            expires_unix_ms: 10_000,
        }
    }

    fn conflict(current: Option<LeaseRecord>) -> WitnessClientError {
        WitnessClientError::Conflict {
            reason: Some("cas_mismatch".to_string()),
            detail: None,
            current: current.map(Box::new),
        }
    }

    #[test]
    fn lost_ack_adopts_the_advanced_revision() {
        let action = classify_renewal_error(
            &conflict(Some(record("node-a/boot", 4, 12, 7, &"ab".repeat(32)))),
            "node-a/boot",
            4,
            &baseline(),
            Some(5_000),
        );
        assert_eq!(action, RenewalAction::AdoptRevision { revision: 12 });
    }

    #[test]
    fn witness_below_our_baseline_retries_with_the_higher_baseline() {
        let action = classify_renewal_error(
            &conflict(Some(record("node-a/boot", 4, 12, 6, &"cd".repeat(32)))),
            "node-a/boot",
            4,
            &baseline(),
            Some(5_000),
        );
        assert_eq!(action, RenewalAction::RetryHigherBaseline { revision: 12 });
    }

    #[test]
    fn witness_above_or_beside_our_baseline_fences() {
        for record in [
            record("node-a/boot", 4, 12, 8, &"cd".repeat(32)),
            record("node-a/boot", 4, 12, 7, &"cd".repeat(32)),
        ] {
            let action = classify_renewal_error(
                &conflict(Some(record)),
                "node-a/boot",
                4,
                &baseline(),
                Some(5_000),
            );
            assert!(matches!(
                action,
                RenewalAction::Fence {
                    reason: "lease_version_regression",
                    ..
                }
            ));
        }
    }

    #[test]
    fn expired_foreign_and_absent_records_fence() {
        let expired = {
            let mut record = record("node-a/boot", 4, 12, 7, &"ab".repeat(32));
            record.expires_unix_ms = 1_000;
            record
        };
        assert!(matches!(
            classify_renewal_error(
                &conflict(Some(expired)),
                "node-a/boot",
                4,
                &baseline(),
                Some(5_000)
            ),
            RenewalAction::Fence {
                reason: "lease_lost",
                ..
            }
        ));
        assert!(matches!(
            classify_renewal_error(
                &conflict(Some(record("node-b/boot", 4, 12, 7, &"ab".repeat(32)))),
                "node-a/boot",
                4,
                &baseline(),
                Some(5_000)
            ),
            RenewalAction::Fence {
                reason: "lease_lost",
                ..
            }
        ));
        assert!(matches!(
            classify_renewal_error(&conflict(None), "node-a/boot", 4, &baseline(), Some(5_000)),
            RenewalAction::Fence {
                reason: "lease_record_missing",
                ..
            }
        ));
    }

    #[test]
    fn transport_retries_but_auth_fences_immediately() {
        assert_eq!(
            classify_renewal_error(
                &WitnessClientError::Unavailable {
                    detail: "timeout".to_string()
                },
                "node-a/boot",
                4,
                &baseline(),
                None
            ),
            RenewalAction::RetryTransport
        );
        assert!(matches!(
            classify_renewal_error(
                &WitnessClientError::Auth {
                    detail: "401".to_string()
                },
                "node-a/boot",
                4,
                &baseline(),
                None
            ),
            RenewalAction::Fence {
                reason: "witness_auth_failed",
                ..
            }
        ));
    }

    #[test]
    fn deadline_is_ttl_minus_max_of_two_and_renew_interval() {
        let clock = Arc::new(ManualMonotonicClock::new(10_000, 1_000_000));
        let deadline = SelfFenceDeadline::arm(10_000, "test-boot", 1_000_000, 30, 10);
        assert_eq!(deadline.deadline_millis(), 30_000);
        assert_eq!(deadline.check(clock.as_ref()), SelfFenceCheck::Safe);

        clock.set_boot(30_000);
        assert_eq!(
            deadline.check(clock.as_ref()),
            SelfFenceCheck::DeadlinePassed
        );

        // A short TTL uses the 2-second margin.
        let short = SelfFenceDeadline::arm(0, "test-boot", 0, 5, 1);
        assert_eq!(short.deadline_millis(), 3_000);
    }

    #[test]
    fn boot_id_change_and_wall_step_fence() {
        let clock = Arc::new(ManualMonotonicClock::new(10_000, 1_000_000));
        let deadline = SelfFenceDeadline::arm(10_000, "test-boot", 1_000_000, 30, 10);
        clock.set_boot_id("other-boot");
        assert_eq!(
            deadline.check(clock.as_ref()),
            SelfFenceCheck::BootIdChanged
        );

        let clock = Arc::new(ManualMonotonicClock::new(10_000, 1_000_000));
        let deadline = SelfFenceDeadline::arm(10_000, "test-boot", 1_000_000, 30, 10);
        clock.advance_wall(31_000);
        assert_eq!(deadline.check(clock.as_ref()), SelfFenceCheck::WallStep);

        // A step smaller than the TTL (positive or negative) is tolerated.
        clock.set_boot(10_000);
        clock.advance_wall(-31_000 + 1_000);
        assert_eq!(deadline.check(clock.as_ref()), SelfFenceCheck::Safe);
    }
}
