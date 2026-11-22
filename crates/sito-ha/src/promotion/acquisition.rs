//! Acquisition decision table for ADR-0010.
//!
//! This module is pure: it receives the local durable content, the last witness
//! record and the node role, and returns either a concrete acquire plan or a
//! stable refusal reason. No network or filesystem work happens here, so every
//! rule is directly testable and cannot accidentally send a pending version to
//! the witness.

use sito_ha_types::hash::normalize_bundle_hash;
use sito_ha_types::status::PublicationState;

use crate::witness::LeaseRecord;

use super::state::{PromotionBookkeeping, PublicationBaseline};

/// Stable refusal/abort codes from the ADR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionRefusal {
    /// This node is not configured as the candidate.
    NotCandidate,
    /// The configured role may not promote.
    WrongRole,
    /// A fence marker is present.
    Fenced,
    /// The witness has no record but this node has applied/held a term.
    LeaseRecordMissing,
    /// The witness record is older than this node's state term.
    CandidateTermAhead,
    /// The witness record is older than this node's state term (master).
    MasterTermAhead,
    /// The node lacks the witness record's published content.
    CandidateBehind,
    /// The node's published version is below the witness (master).
    MasterStateBehind,
    /// The node has the witness version with different content.
    CandidateForked,
    /// The master has the witness version with different content.
    MasterStateForked,
    /// A local applied/state same-version hash disagreement exists.
    LocalFork,
    /// A reachable peer reports a same-version different hash at a compared
    /// baseline (reconciliation).
    ClusterForked,
    /// A positive baseline has no hash to compare.
    HashUnknown,
    /// The state file was written by an older binary and cannot be trusted as
    /// published without a witness match.
    PromotionInterrupted,
    /// A promotion would exceed `u64::MAX`.
    ArithmeticOverflow,
}

impl PromotionRefusal {
    /// Stable ADR reason code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotCandidate | Self::WrongRole => "not_candidate",
            Self::Fenced => "fenced_until_reconciled",
            Self::LeaseRecordMissing => "lease_record_missing",
            Self::CandidateTermAhead | Self::MasterTermAhead => "candidate_term_ahead",
            Self::CandidateBehind | Self::MasterStateBehind | Self::ArithmeticOverflow => {
                "candidate_behind"
            }
            Self::CandidateForked | Self::MasterStateForked | Self::LocalFork => "candidate_forked",
            Self::ClusterForked => "cluster_forked",
            Self::HashUnknown => "candidate_hash_unknown",
            Self::PromotionInterrupted => "promotion_interrupted",
        }
    }

    /// Master-specific refusal code (status surface), if different.
    #[must_use]
    pub const fn master_code(&self) -> &'static str {
        match self {
            Self::CandidateTermAhead | Self::MasterTermAhead => "master_term_ahead",
            Self::CandidateBehind | Self::MasterStateBehind => "master_state_behind",
            Self::CandidateForked | Self::MasterStateForked => "master_state_forked",
            other => other.code(),
        }
    }
}

/// Local durable content available to an acquisition decision.
#[derive(Debug, Clone, Default)]
pub struct LocalContent {
    /// Last applied term from the slave watermark (0 for a master).
    pub applied_term: u64,
    /// Last applied version from the slave watermark.
    pub applied_version: u64,
    /// Last applied signed-payload hash from the slave watermark.
    pub applied_hash: Option<String>,
    /// Term of the local `ha_state.toml` bundle (0 for a slave).
    pub state_term: u64,
    /// Version of the local `ha_state.toml` bundle.
    pub state_version: u64,
    /// Signed-payload hash of the local `ha_state.toml` bundle, when it can be
    /// recomputed (legacy state has no stored promotion hash).
    pub state_hash: Option<String>,
    /// Promotion bookkeeping from `ha_state.toml`, if any.
    pub bookkeeping: Option<PromotionBookkeeping>,
    /// Version of the staged bundle in `ha_state.toml` (0 when none). This is
    /// the *pending* version and is never used as a witness baseline.
    pub pending_version: u64,
}

impl LocalContent {
    /// Local content for a master state file.
    #[must_use]
    pub fn master(
        state_term: u64,
        bookkeeping: Option<PromotionBookkeeping>,
        last_applied_version: u64,
        last_applied_hash: Option<String>,
    ) -> Self {
        Self {
            applied_term: 0,
            applied_version: last_applied_version,
            applied_hash: last_applied_hash,
            state_term,
            state_version: 0,
            state_hash: None,
            bookkeeping,
            pending_version: 0,
        }
    }

    /// Local content for a slave candidate.
    #[must_use]
    pub fn candidate(
        applied_term: u64,
        applied_version: u64,
        applied_hash: Option<String>,
        bookkeeping: Option<PromotionBookkeeping>,
    ) -> Self {
        Self {
            applied_term,
            applied_version,
            applied_hash,
            state_term: 0,
            state_version: 0,
            state_hash: None,
            bookkeeping,
            pending_version: 0,
        }
    }
}

/// The concrete acquire request fields derived from local content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquirePlan {
    /// Term to request (`current.term + 1`, or 1 when absent).
    pub term: u64,
    /// Expected term for the CAS (`None` when the record is absent).
    pub expected_term: Option<u64>,
    /// Expected revision for the CAS (`None` when the record is absent).
    pub expected_revision: Option<u64>,
    /// Published baseline version to send (never the pending version).
    pub baseline: PublicationBaseline,
    /// Version for the first publish after acquisition.
    pub publish_version: u64,
    /// Whether the publish was inferred from the witness matching the staged
    /// bundle (the bundle should be marked published after acquisition).
    pub inferred_published: bool,
    /// Whether a prior pending/publishing bundle at `publish_version` is being
    /// reused.
    pub reusing_pending: bool,
    /// The witness already holds this node's live grant; resume renewal rather
    /// than issuing an acquire.
    pub existing_grant: bool,
}

/// The decision for one acquisition attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquisitionDecision {
    /// Acquire with these fields.
    Acquire(AcquirePlan),
    /// Do not acquire; the stable reason is reported.
    Refuse(PromotionRefusal),
}

/// Which node role is asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionRole {
    /// A designated candidate applying for the lease after master loss.
    Candidate,
    /// A configured master restarting (it must acquire a new term).
    Master,
}

/// Computes the acquire plan, or a fail-closed refusal.
///
/// ADR order matters:
/// 1. `max(applied_term, state_term) > 0` with an absent record refuses before
///    any acquire.
/// 2. a record older than `max(applied_term, state_term)` refuses
///    `candidate_term_ahead`.
/// 3. a pending/publishing bundle equal to the witness record proves the prior
///    publish succeeded and becomes the published baseline.
/// 4. the baseline is `max(applied_version, state.published_version)`; the
///    pending version is never part of that max.
pub fn decide_acquisition(
    role: AcquisitionRole,
    local: &LocalContent,
    record: Option<&LeaseRecord>,
    holder: &str,
) -> AcquisitionDecision {
    let max_term = local.applied_term.max(local.state_term);
    let record_term = record.map_or(0, |record| record.term);

    let existing_grant = record.is_some_and(|record| record.holder == holder && record.term > 0);

    if record.is_none() && max_term > 0 {
        return AcquisitionDecision::Refuse(PromotionRefusal::LeaseRecordMissing);
    }
    if record.is_some() && max_term > record_term {
        return AcquisitionDecision::Refuse(match role {
            AcquisitionRole::Candidate => PromotionRefusal::CandidateTermAhead,
            AcquisitionRole::Master => PromotionRefusal::MasterTermAhead,
        });
    }

    let witness_version = record.map_or(0, |record| record.version);
    let witness_hash = record.map_or("none", |record| record.bundle_hash.as_str());

    let (mut published_version, mut published_hash) =
        local
            .bookkeeping
            .as_ref()
            .map_or((0, Some("none".to_string())), |bookkeeping| {
                (
                    bookkeeping.published_version,
                    Some(bookkeeping.published_hash.clone()),
                )
            });
    let mut inferred_published = false;

    if let Some(record) = record
        && let Some(ref bookkeeping) = local.bookkeeping
        && bookkeeping.has_pending_bundle()
    {
        let pending_version = pending_version(local);
        let pending_hash = bookkeeping.pending_hash.as_deref();
        if pending_version > 0
            && pending_version == record.version
            && pending_hash.is_some_and(|hash| hashes_equal(hash, &record.bundle_hash))
        {
            published_version = pending_version;
            published_hash = Some(record.bundle_hash.clone());
            inferred_published = true;
        }
    }

    // An older state file without publication fields is unknown. It may only
    // be treated as published when its bundle equals the witness record.
    if local.bookkeeping.is_none()
        && let Some(record) = record
        && record.version > 0
    {
        let state_bundle_version = local.state_version;
        if state_bundle_version == record.version
            && local
                .state_hash
                .as_deref()
                .is_some_and(|hash| hashes_equal(hash, &record.bundle_hash))
        {
            published_version = record.version;
            published_hash = Some(record.bundle_hash.clone());
            inferred_published = true;
        } else if role == AcquisitionRole::Master {
            return AcquisitionDecision::Refuse(PromotionRefusal::PromotionInterrupted);
        }
    }

    let applied_hash = local.applied_hash.as_deref();
    let (baseline_version, baseline_hash) = if local.applied_version > published_version {
        (local.applied_version, applied_hash)
    } else if local.applied_version < published_version {
        (published_version, published_hash.as_deref())
    } else if local.applied_version == 0 && published_version == 0 {
        (0, Some("none"))
    } else if let (Some(applied), Some(state)) = (applied_hash, published_hash.as_deref()) {
        if !hashes_equal(applied, state) {
            return AcquisitionDecision::Refuse(PromotionRefusal::LocalFork);
        }
        (published_version, Some(state))
    } else {
        (
            published_version,
            applied_hash.or(published_hash.as_deref()),
        )
    };

    let Some(baseline_hash) = baseline_hash else {
        return AcquisitionDecision::Refuse(PromotionRefusal::HashUnknown);
    };
    let Ok(baseline) = PublicationBaseline::new(baseline_version, baseline_hash) else {
        return AcquisitionDecision::Refuse(PromotionRefusal::HashUnknown);
    };

    if baseline.version < witness_version {
        return AcquisitionDecision::Refuse(match role {
            AcquisitionRole::Candidate => PromotionRefusal::CandidateBehind,
            AcquisitionRole::Master => PromotionRefusal::MasterStateBehind,
        });
    }
    if baseline.version == witness_version && !hashes_equal(&baseline.hash, witness_hash) {
        return AcquisitionDecision::Refuse(match role {
            AcquisitionRole::Candidate => PromotionRefusal::CandidateForked,
            AcquisitionRole::Master => PromotionRefusal::MasterStateForked,
        });
    }

    let pending = pending_version(local);
    let reusing_pending = pending > 0
        && local
            .bookkeeping
            .as_ref()
            .is_some_and(PromotionBookkeeping::has_pending_bundle);
    let publish_version = match baseline.version.checked_add(1) {
        Some(next) => next.max(pending),
        None => return AcquisitionDecision::Refuse(PromotionRefusal::ArithmeticOverflow),
    };
    let term = match record {
        None => 1,
        Some(record) if existing_grant => record.term,
        Some(record) => match record.term.checked_add(1) {
            Some(term) => term,
            None => return AcquisitionDecision::Refuse(PromotionRefusal::ArithmeticOverflow),
        },
    };

    AcquisitionDecision::Acquire(AcquirePlan {
        term,
        expected_term: record.map(|record| record.term),
        expected_revision: record.map(|record| record.revision),
        baseline,
        publish_version,
        inferred_published,
        reusing_pending,
        existing_grant,
    })
}

fn pending_version(local: &LocalContent) -> u64 {
    local
        .bookkeeping
        .as_ref()
        .filter(|bookkeeping| {
            matches!(
                bookkeeping.publication_state,
                PublicationState::Pending | PublicationState::Publishing
            )
        })
        .map_or(0, |_| local_state_pending_version(local))
}

fn local_state_pending_version(local: &LocalContent) -> u64 {
    // The active bundle's own version is stored in the state file; the engine
    // fills this field when it loads that bundle.
    local.pending_version
}

fn hashes_equal(left: &str, right: &str) -> bool {
    let left = left.trim().trim_start_matches("blake3:");
    let right = right.trim().trim_start_matches("blake3:");
    left.eq_ignore_ascii_case(right)
}

/// Validates that a baseline hash is normalized (used by the engine before it
/// writes the state file).
pub fn normalize_baseline(
    version: u64,
    hash: &str,
) -> Result<PublicationBaseline, crate::error::HaError> {
    PublicationBaseline::new(version, hash)
}

/// Re-exported so callers can validate a witness hash without importing the
/// hash crate directly.
pub fn normalize_hash(version: u64, hash: &str) -> Result<String, crate::error::HaError> {
    normalize_bundle_hash(version, hash).map_err(|error| crate::error::HaError::Validation {
        field: "bundle_hash".to_string(),
        reason: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(term: u64, revision: u64, version: u64, hash: &str) -> LeaseRecord {
        LeaseRecord {
            schema: 1,
            cluster_id: "home-dns".to_string(),
            holder: "node-a/boot".to_string(),
            node_id: "node-a".to_string(),
            term,
            revision,
            version,
            bundle_hash: hash.to_string(),
            acquired_unix_ms: 1,
            expires_unix_ms: 2,
        }
    }

    fn bookkeeping(
        state: PublicationState,
        published: (u64, &str),
        pending_hash: Option<&str>,
        pending_version: u64,
    ) -> (PromotionBookkeeping, u64) {
        (
            PromotionBookkeeping {
                publication_state: state,
                published_version: published.0,
                published_hash: published.1.to_string(),
                pending_hash: pending_hash.map(str::to_string),
                promotion_origin: Some("automatic".to_string()),
                lease_holder: Some("node-a/boot".to_string()),
                cluster_id: Some("home-dns".to_string()),
                node_id: Some("node-a".to_string()),
                promoted_at_unix_ms: Some(1),
                last_applied_version: Some(published.0),
                last_applied_hash: Some(published.1.to_string()),
            },
            pending_version,
        )
    }

    fn candidate(applied_term: u64, version: u64, hash: &str) -> LocalContent {
        LocalContent {
            applied_term,
            applied_version: version,
            applied_hash: Some(hash.to_string()),
            state_term: 0,
            state_version: 0,
            state_hash: None,
            bookkeeping: None,
            pending_version: 0,
        }
    }

    #[test]
    fn candidate_computes_next_term_and_published_baseline() {
        let hash = "ab".repeat(32);
        let decision = decide_acquisition(
            AcquisitionRole::Candidate,
            &candidate(3, 7, &hash),
            Some(&record(3, 11, 7, &hash)),
            "node-b/boot",
        );
        let AcquisitionDecision::Acquire(plan) = decision else {
            panic!("expected acquire, got {decision:?}");
        };
        assert_eq!(plan.term, 4);
        assert_eq!(plan.expected_term, Some(3));
        assert_eq!(plan.expected_revision, Some(11));
        assert_eq!(plan.baseline.version, 7);
        assert_eq!(plan.publish_version, 8);
        assert!(!plan.reusing_pending);
    }

    #[test]
    fn pending_version_is_reused_but_never_sent_as_baseline() {
        let hash = "ab".repeat(32);
        let (bookkeeping, pending_version) = bookkeeping(
            PublicationState::Pending,
            (7, &hash),
            Some(&"cd".repeat(32)),
            8,
        );
        let mut local = candidate(3, 7, &hash);
        local.bookkeeping = Some(bookkeeping);
        local.pending_version = pending_version;

        let decision = decide_acquisition(
            AcquisitionRole::Candidate,
            &local,
            Some(&record(3, 11, 7, &hash)),
            "node-b/boot",
        );
        let AcquisitionDecision::Acquire(plan) = decision else {
            panic!("expected acquire, got {decision:?}");
        };
        assert_eq!(plan.baseline.version, 7);
        assert_eq!(plan.baseline.hash, hash);
        assert_eq!(plan.publish_version, 8, "reuse pending 8, never skip to 9");
        assert!(plan.reusing_pending);
    }

    #[test]
    fn publishing_bundle_matching_the_witness_is_inferred_published() {
        let published = "ab".repeat(32);
        let pending = "cd".repeat(32);
        let (bookkeeping, pending_version) = bookkeeping(
            PublicationState::Publishing,
            (7, &published),
            Some(&pending),
            8,
        );
        let mut local = candidate(3, 7, &published);
        local.bookkeeping = Some(bookkeeping);
        local.pending_version = pending_version;
        // The witness already holds the pending version/hash: the prior publish
        // succeeded even though the local "published" state write did not.
        let decision = decide_acquisition(
            AcquisitionRole::Candidate,
            &local,
            Some(&record(3, 12, 8, &pending)),
            "node-b/boot",
        );
        let AcquisitionDecision::Acquire(plan) = decision else {
            panic!("expected acquire, got {decision:?}");
        };
        assert!(plan.inferred_published);
        assert_eq!(plan.baseline.version, 8);
        assert_eq!(plan.baseline.hash, pending);
        assert_eq!(plan.publish_version, 9);
    }

    #[test]
    fn record_loss_and_term_ahead_refuse_before_acquire() {
        assert_eq!(
            decide_acquisition(
                AcquisitionRole::Candidate,
                &candidate(3, 7, &"ab".repeat(32)),
                None,
                "node-b/boot"
            ),
            AcquisitionDecision::Refuse(PromotionRefusal::LeaseRecordMissing)
        );
        assert_eq!(
            decide_acquisition(
                AcquisitionRole::Candidate,
                &candidate(5, 7, &"ab".repeat(32)),
                Some(&record(4, 1, 7, &"ab".repeat(32))),
                "node-b/boot"
            ),
            AcquisitionDecision::Refuse(PromotionRefusal::CandidateTermAhead)
        );
    }

    #[test]
    fn candidate_behind_and_forked_refuse() {
        let hash = "ab".repeat(32);
        assert_eq!(
            decide_acquisition(
                AcquisitionRole::Candidate,
                &candidate(3, 6, &hash),
                Some(&record(3, 1, 7, &hash)),
                "node-b/boot"
            ),
            AcquisitionDecision::Refuse(PromotionRefusal::CandidateBehind)
        );
        assert_eq!(
            decide_acquisition(
                AcquisitionRole::Candidate,
                &candidate(3, 7, &hash),
                Some(&record(3, 1, 7, &"cd".repeat(32))),
                "node-b/boot"
            ),
            AcquisitionDecision::Refuse(PromotionRefusal::CandidateForked)
        );
        // A local applied/state same-version hash disagreement is also a fork.
        let (bookkeeping, pending) =
            bookkeeping(PublicationState::Published, (7, &"cd".repeat(32)), None, 0);
        let mut local = candidate(3, 7, &hash);
        local.bookkeeping = Some(bookkeeping);
        local.pending_version = pending;
        assert_eq!(
            decide_acquisition(
                AcquisitionRole::Candidate,
                &local,
                Some(&record(3, 1, 7, &hash)),
                "node-b/boot"
            ),
            AcquisitionDecision::Refuse(PromotionRefusal::LocalFork)
        );
    }

    #[test]
    fn published_content_newer_than_the_witness_is_allowed() {
        let hash = "ab".repeat(32);
        let decision = decide_acquisition(
            AcquisitionRole::Candidate,
            &candidate(3, 8, &hash),
            Some(&record(3, 1, 7, &"cd".repeat(32))),
            "node-b/boot",
        );
        let AcquisitionDecision::Acquire(plan) = decision else {
            panic!("expected acquire, got {decision:?}");
        };
        assert_eq!(plan.baseline.version, 8);
        assert_eq!(plan.publish_version, 9);
    }

    #[test]
    fn master_restart_refuses_term_ahead_state_behind_and_fork() {
        let hash = "ab".repeat(32);
        let master = LocalContent::master(5, None, 7, Some(hash.clone()));
        assert_eq!(
            decide_acquisition(
                AcquisitionRole::Master,
                &master,
                Some(&record(4, 1, 7, &hash)),
                "node-a/new-boot"
            ),
            AcquisitionDecision::Refuse(PromotionRefusal::MasterTermAhead)
        );

        let (behind, pending) = bookkeeping(PublicationState::Published, (6, &hash), None, 0);
        let master = LocalContent::master(3, Some(behind), 6, Some(hash.clone()));
        assert_eq!(
            decide_acquisition(
                AcquisitionRole::Master,
                &LocalContent {
                    pending_version: pending,
                    ..master
                },
                Some(&record(3, 1, 7, &hash)),
                "node-a/new-boot"
            ),
            AcquisitionDecision::Refuse(PromotionRefusal::MasterStateBehind)
        );

        let (bookkeeping, pending) = bookkeeping(PublicationState::Published, (7, &hash), None, 0);
        let master = LocalContent::master(3, Some(bookkeeping), 7, Some(hash.clone()));
        assert_eq!(
            decide_acquisition(
                AcquisitionRole::Master,
                &LocalContent {
                    pending_version: pending,
                    ..master
                },
                Some(&record(3, 1, 7, &"cd".repeat(32))),
                "node-a/new-boot"
            ),
            AcquisitionDecision::Refuse(PromotionRefusal::MasterStateForked)
        );
    }

    #[test]
    fn master_restart_publishes_a_new_version_without_a_config_change() {
        let hash = "ab".repeat(32);
        let mut master = LocalContent::master(3, None, 7, Some(hash.clone()));
        master.state_version = 7;
        master.state_hash = Some(hash.clone());
        let AcquisitionDecision::Acquire(plan) = decide_acquisition(
            AcquisitionRole::Master,
            &master,
            Some(&record(3, 4, 7, &hash)),
            "node-a/new-boot",
        ) else {
            panic!("expected acquire");
        };
        assert_eq!(plan.term, 4);
        assert_eq!(plan.baseline.version, 7);
        assert_eq!(
            plan.publish_version, 8,
            "a restart always bumps the version"
        );
    }

    #[test]
    fn candidate_state_term_participates_in_term_ahead_refusal() {
        let hash = "ab".repeat(32);
        let mut local = candidate(1, 7, &hash);
        local.state_term = 5;
        assert_eq!(
            decide_acquisition(
                AcquisitionRole::Candidate,
                &local,
                Some(&record(3, 1, 7, &hash)),
                "node-b/boot"
            ),
            AcquisitionDecision::Refuse(PromotionRefusal::CandidateTermAhead)
        );
    }

    #[test]
    fn absent_record_with_zero_terms_acquires_term_one() {
        let decision = decide_acquisition(
            AcquisitionRole::Candidate,
            &candidate(0, 0, "none"),
            None,
            "node-b/boot",
        );
        let AcquisitionDecision::Acquire(plan) = decision else {
            panic!("expected acquire, got {decision:?}");
        };
        assert_eq!(plan.term, 1);
        assert_eq!(plan.expected_term, None);
        assert_eq!(plan.expected_revision, None);
        assert_eq!(plan.baseline.version, 0);
        assert_eq!(plan.publish_version, 1);
    }
}
