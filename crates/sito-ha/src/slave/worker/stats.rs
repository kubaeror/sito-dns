//! Window-scoped statistics reports sent to the master.

use std::collections::HashMap;

use sito_stats::MetricsRegistry;
use sito_stats::metrics::MetricsSnapshot;

use crate::protocol::{HaMessage, UpstreamReport};

/// Builds a window-scoped stats report from the registry and the snapshot
/// taken at the previous report.
///
/// The registry only exposes lifetime counters and lifetime upstream RTT
/// accumulators; sending those under a `window_s` label would misreport them
/// as recent activity (audit WP-7.3). The report therefore carries deltas
/// since the previous report, including per-upstream RTT samples and upstream
/// error counts. Returns the message to send and the snapshot to pass to the
/// next call.
pub(super) fn build_stats_report(
    metrics: &MetricsRegistry,
    previous: &MetricsSnapshot,
    window_s: u64,
) -> (HaMessage, MetricsSnapshot) {
    let snapshot = metrics.snapshot();
    let delta = snapshot.delta_since(previous);

    let mut upstreams = HashMap::with_capacity(delta.upstreams.len());
    for (name, upstream) in &delta.upstreams {
        upstreams.insert(
            name.clone(),
            UpstreamReport {
                rtt_ms: upstream.mean_rtt_ms(),
                errors: upstream.errors,
            },
        );
    }

    (
        HaMessage::StatsReport {
            window_s,
            queries: delta.queries,
            blocked: delta.blocked,
            upstreams,
        },
        snapshot,
    )
}
