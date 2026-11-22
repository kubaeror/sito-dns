//! Hello-only reconciliation decision table for ADR-0010.
//!
//! The listener accepts TLS/WebSocket/Hello and answers ping/pong while the
//! window is open, but sends no `ConfigPush`. This module evaluates the
//! collected `have_term`/`have_version`/`have_bundle_hash` reports against both
//! the witness record and the local publish baseline.

use std::collections::BTreeSet;

use sito_ha_types::status::PublicationState;

use crate::witness::LeaseRecord;

use super::acquisition::PromotionRefusal;
use super::state::PublicationBaseline;

/// One peer report collected during the reconciliation window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerReport {
    /// Slave instance name.
    pub instance: String,
    /// Last applied cluster term.
    pub have_term: u64,
    /// Last applied configuration version.
    pub have_version: u64,
    /// Applied signed-payload hash; `None` for an old v2 peer that omits it.
    pub have_bundle_hash: Option<String>,
}

/// Inputs for one reconciliation decision.
#[derive(Debug, Clone)]
pub struct ReconcileInput {
    /// The term this node acquired.
    pub term: u64,
    /// The witness record at acquisition/renewal.
    pub witness: LeaseRecord,
    /// The local published baseline (never the pending version).
    pub baseline: PublicationBaseline,
    /// The version this node intends to publish.
    pub publish_version: u64,
    /// The publication state *before* setting `publishing`.
    pub publication_state: PublicationState,
    /// Hash of the staged bundle (only meaningful while `publishing`).
    pub pending_hash: Option<String>,
    /// Peer reports collected during the window.
    pub peers: Vec<PeerReport>,
}

/// The outcome of reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileDecision {
    /// No peer is ahead/forked/unknown. Publish `publish_version`.
    Publish,
    /// A `publishing` state's pending bundle is proven published by a reachable
    /// slave at `publish_version` with the pending hash. Do not republish; mark
    /// the state published and renew.
    AlreadyPublished,
    /// Abort; the listener stays read-only and the lease expires.
    Abort(PromotionRefusal),
}

/// Tracks late ahead peers after the reconciliation window.
///
/// A peer that reports ahead after success is latched: the master never bumps
/// above it or overwrites it, and the operator must reconcile the fork. The
/// latch is intentionally sticky for the process lifetime.
#[derive(Debug, Default, Clone)]
pub struct LatePeerLatch {
    latched: BTreeSet<String>,
    reasons: Vec<(String, String)>,
}

impl LatePeerLatch {
    /// Records a late ahead report. Returns true when this is a new latch.
    pub fn record_late_report(
        &mut self,
        report: &PeerReport,
        term: u64,
        publish_version: u64,
    ) -> bool {
        let reason = if report.have_term > term {
            Some(format!(
                "peer '{}' reports term {} above the master's {term} after the reconcile window",
                report.instance, report.have_term
            ))
        } else if report.have_version > publish_version {
            Some(format!(
                "peer '{}' reports version {} above the master's publish version {publish_version} after the reconcile window",
                report.instance, report.have_version
            ))
        } else {
            None
        };
        match reason {
            Some(reason) => {
                self.reasons.push((report.instance.clone(), reason));
                self.latched.insert(report.instance.clone())
            }
            None => false,
        }
    }

    /// Whether an instance is latched.
    #[must_use]
    pub fn contains(&self, instance: &str) -> bool {
        self.latched.contains(instance)
    }

    /// All latched instance names.
    pub fn instances(&self) -> impl Iterator<Item = &str> {
        self.latched.iter().map(String::as_str)
    }

    /// Recorded latch reasons.
    #[must_use]
    pub fn reasons(&self) -> &[(String, String)] {
        &self.reasons
    }
}

/// Evaluates the reconciliation window.
///
/// The checks are intentionally ordered from the most severe identity/term
/// mismatch to the hash comparisons, and any uncertainty aborts.
#[must_use]
pub fn evaluate(input: &ReconcileInput) -> ReconcileDecision {
    let witness_version = input.witness.version;
    let witness_hash = input.witness.bundle_hash.as_str();
    let pending_allowed =
        input.publication_state == PublicationState::Publishing && input.pending_hash.is_some();
    let mut proven_published = false;

    for peer in &input.peers {
        if peer.have_term > input.term {
            return ReconcileDecision::Abort(PromotionRefusal::CandidateBehind);
        }
        if peer.have_version > input.publish_version {
            return ReconcileDecision::Abort(PromotionRefusal::CandidateBehind);
        }

        // Compare a same-version hash at the witness record. Version 0 has no
        // published content and is not hash-compared.
        if witness_version > 0 && peer.have_version == witness_version {
            match peer.have_bundle_hash.as_deref() {
                None => return ReconcileDecision::Abort(PromotionRefusal::HashUnknown),
                Some(hash) if !hashes_equal(hash, witness_hash) => {
                    return ReconcileDecision::Abort(PromotionRefusal::ClusterForked);
                }
                Some(_) => {}
            }
        }

        // Compare at the local published baseline too: the baseline may be
        // higher than the witness record because this node published content
        // the witness has not recorded yet.
        if input.baseline.version > 0
            && peer.have_version == input.baseline.version
            && input.baseline.version != witness_version
        {
            match peer.have_bundle_hash.as_deref() {
                None => return ReconcileDecision::Abort(PromotionRefusal::HashUnknown),
                Some(hash) if !hashes_equal(hash, &input.baseline.hash) => {
                    return ReconcileDecision::Abort(PromotionRefusal::ClusterForked);
                }
                Some(_) => {}
            }
        }

        if peer.have_version == input.publish_version {
            if !pending_allowed {
                return ReconcileDecision::Abort(PromotionRefusal::CandidateBehind);
            }
            let Some(ref pending_hash) = input.pending_hash else {
                return ReconcileDecision::Abort(PromotionRefusal::HashUnknown);
            };
            match peer.have_bundle_hash.as_deref() {
                None => return ReconcileDecision::Abort(PromotionRefusal::HashUnknown),
                Some(hash) if hashes_equal(hash, pending_hash) => {
                    proven_published = true;
                }
                Some(_) => {
                    return ReconcileDecision::Abort(PromotionRefusal::CandidateBehind);
                }
            }
        } else if peer.have_version > input.baseline.version {
            // An unknown in-flight version above the published baseline that is
            // not the allowed pending publish must never be overwritten.
            return ReconcileDecision::Abort(PromotionRefusal::CandidateBehind);
        }
    }

    if proven_published {
        ReconcileDecision::AlreadyPublished
    } else {
        ReconcileDecision::Publish
    }
}

fn hashes_equal(left: &str, right: &str) -> bool {
    left.trim()
        .trim_start_matches("blake3:")
        .eq_ignore_ascii_case(right.trim().trim_start_matches("blake3:"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(term: u64, version: u64, hash: &str) -> LeaseRecord {
        LeaseRecord {
            schema: 1,
            cluster_id: "home-dns".to_string(),
            holder: "node-a/boot".to_string(),
            node_id: "node-a".to_string(),
            term,
            revision: 1,
            version,
            bundle_hash: hash.to_string(),
            acquired_unix_ms: 1,
            expires_unix_ms: 2,
        }
    }

    fn peer(version: u64, hash: Option<&str>) -> PeerReport {
        PeerReport {
            instance: "slave-1".to_string(),
            have_term: 1,
            have_version: version,
            have_bundle_hash: hash.map(str::to_string),
        }
    }

    fn input(
        state: PublicationState,
        baseline: (u64, &str),
        publish_version: u64,
        witness: (u64, &str),
        pending: Option<&str>,
        peers: Vec<PeerReport>,
    ) -> ReconcileInput {
        ReconcileInput {
            term: 2,
            witness: record(1, witness.0, witness.1),
            baseline: PublicationBaseline::new(baseline.0, baseline.1).unwrap(),
            publish_version,
            publication_state: state,
            pending_hash: pending.map(str::to_string),
            peers,
        }
    }

    #[test]
    fn normal_window_publishes() {
        let baseline = "ab".repeat(32);
        let decision = evaluate(&input(
            PublicationState::Pending,
            (7, &baseline),
            8,
            (7, &baseline),
            None,
            vec![peer(7, Some(&baseline))],
        ));
        assert_eq!(decision, ReconcileDecision::Publish);
    }

    #[test]
    fn ahead_peer_aborts_and_never_overwrites() {
        let baseline = "ab".repeat(32);
        let decision = evaluate(&input(
            PublicationState::Pending,
            (7, &baseline),
            8,
            (7, &baseline),
            None,
            vec![peer(9, Some(&"cd".repeat(32)))],
        ));
        assert_eq!(
            decision,
            ReconcileDecision::Abort(PromotionRefusal::CandidateBehind)
        );
    }

    #[test]
    fn same_version_fork_at_witness_or_baseline_aborts() {
        let baseline = "ab".repeat(32);
        let decision = evaluate(&input(
            PublicationState::Pending,
            (7, &baseline),
            8,
            (7, &baseline),
            None,
            vec![peer(7, Some(&"cd".repeat(32)))],
        ));
        assert_eq!(
            decision,
            ReconcileDecision::Abort(PromotionRefusal::ClusterForked)
        );

        // Baseline raised above the witness record: a slave at the older
        // witness version with a different hash is still a fork.
        let decision = evaluate(&input(
            PublicationState::Pending,
            (8, &"ef".repeat(32)),
            9,
            (7, &baseline),
            None,
            vec![peer(7, Some(&"cd".repeat(32)))],
        ));
        assert_eq!(
            decision,
            ReconcileDecision::Abort(PromotionRefusal::ClusterForked)
        );
    }

    #[test]
    fn missing_hash_at_compared_baseline_or_publish_version_aborts() {
        let baseline = "ab".repeat(32);
        let decision = evaluate(&input(
            PublicationState::Pending,
            (7, &baseline),
            8,
            (7, &baseline),
            None,
            vec![peer(7, None)],
        ));
        assert_eq!(
            decision,
            ReconcileDecision::Abort(PromotionRefusal::HashUnknown)
        );

        let decision = evaluate(&input(
            PublicationState::Publishing,
            (7, &baseline),
            8,
            (7, &baseline),
            Some(&"cd".repeat(32)),
            vec![peer(8, None)],
        ));
        assert_eq!(
            decision,
            ReconcileDecision::Abort(PromotionRefusal::HashUnknown)
        );
    }

    #[test]
    fn unexpected_publish_version_is_an_inflight_abort() {
        let baseline = "ab".repeat(32);
        let decision = evaluate(&input(
            PublicationState::Pending,
            (7, &baseline),
            8,
            (7, &baseline),
            None,
            vec![peer(8, Some(&"cd".repeat(32)))],
        ));
        assert_eq!(
            decision,
            ReconcileDecision::Abort(PromotionRefusal::CandidateBehind)
        );
    }

    #[test]
    fn publishing_state_with_matching_slave_proves_the_publish_succeeded() {
        let baseline = "ab".repeat(32);
        let pending = "cd".repeat(32);
        let decision = evaluate(&input(
            PublicationState::Publishing,
            (7, &baseline),
            8,
            (7, &baseline),
            Some(&pending),
            vec![peer(8, Some(&pending))],
        ));
        assert_eq!(decision, ReconcileDecision::AlreadyPublished);
    }

    #[test]
    fn publishing_state_with_a_different_hash_at_publish_version_aborts() {
        let baseline = "ab".repeat(32);
        let pending = "cd".repeat(32);
        let decision = evaluate(&input(
            PublicationState::Publishing,
            (7, &baseline),
            8,
            (7, &baseline),
            Some(&pending),
            vec![peer(8, Some(&"ef".repeat(32)))],
        ));
        assert_eq!(
            decision,
            ReconcileDecision::Abort(PromotionRefusal::CandidateBehind)
        );
    }

    #[test]
    fn version_zero_is_not_hash_compared_and_late_ahead_latches() {
        let decision = evaluate(&input(
            PublicationState::Pending,
            (0, "none"),
            1,
            (0, "none"),
            None,
            vec![PeerReport {
                instance: "fresh".to_string(),
                have_term: 0,
                have_version: 0,
                have_bundle_hash: None,
            }],
        ));
        assert_eq!(decision, ReconcileDecision::Publish);

        let mut latch = LatePeerLatch::default();
        let ahead = PeerReport {
            instance: "late".to_string(),
            have_term: 1,
            have_version: 9,
            have_bundle_hash: Some("ab".repeat(32)),
        };
        assert!(latch.record_late_report(&ahead, 2, 8));
        assert!(latch.contains("late"));
        assert!(!latch.record_late_report(&ahead, 2, 8), "latch is sticky");
    }
}
