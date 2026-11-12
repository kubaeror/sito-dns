//! Aggregate readiness model shared by `/health` and `/status`.
//!
//! `/health` is a generic probe: it only reports whether the node is ready.
//! `/status` is the authenticated admin view and lists the per-component
//! reasons. Keeping the aggregate in one place stops the two endpoints from
//! disagreeing about whether the node is healthy.

use crate::state::AcmeReadiness;
use serde::{Deserialize, Serialize};
use sito_filter::{FilterState, FilterStatus};
use sito_ha::HaReadiness;
use std::sync::{Arc, Mutex};
use utoipa::ToSchema;

/// Component name for the DNS listener generation.
pub const COMPONENT_LISTENERS: &str = "listeners";
/// Component name for configured TLS acceptors.
pub const COMPONENT_TLS: &str = "tls";
/// Component name for ACME challenge/issuance readiness.
pub const COMPONENT_ACME: &str = "acme";
/// Component name for HA replication readiness.
pub const COMPONENT_HA: &str = "ha";
/// Component name for the filter engine snapshot.
pub const COMPONENT_FILTER: &str = "filter";
/// Component name for the stats database/writer.
pub const COMPONENT_STATS: &str = "stats";

/// One reason a component is not fully ready.
///
/// `message` is a human-readable summary. It never contains credentials,
/// private keys or certificate material; detailed diagnostics stay in the
/// component-specific authenticated endpoints and the logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ReadinessReason {
    /// Component identifier (`listeners`, `tls`, `acme`, `ha`, `filter`, `stats`).
    pub component: String,
    /// Stable machine-readable reason code.
    pub code: String,
    /// Human-readable explanation without secrets.
    pub message: String,
    /// Wall-clock milliseconds when the component became not-ready, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_unix_ms: Option<u64>,
}

impl ReadinessReason {
    fn new(
        component: &str,
        code: impl Into<String>,
        message: impl Into<String>,
        since_unix_ms: Option<u64>,
    ) -> Self {
        Self {
            component: component.to_string(),
            code: code.into(),
            message: message.into(),
            since_unix_ms,
        }
    }
}

/// Aggregate readiness: `ready` is the blocking verdict, `reasons` explains
/// every degraded and blocking component (in component order).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ReadinessReport {
    pub ready: bool,
    pub reasons: Vec<ReadinessReason>,
}

/// Readiness of one server-owned component (`listeners`, `tls`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentReadiness {
    pub ready: bool,
    pub code: Option<&'static str>,
    pub message: Option<String>,
    pub since_unix_ms: Option<u64>,
}

impl Default for ComponentReadiness {
    fn default() -> Self {
        Self {
            ready: true,
            code: None,
            message: None,
            since_unix_ms: None,
        }
    }
}

impl ComponentReadiness {
    /// A component that is operational (or intentionally not applicable).
    #[must_use]
    pub fn ready() -> Self {
        Self::default()
    }

    /// A component that is configured but not serving.
    #[must_use]
    pub fn unavailable(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            ready: false,
            code: Some(code),
            message: Some(message.into()),
            since_unix_ms: Some(unix_now_ms()),
        }
    }

    /// A component that is still serving but needs operator attention (for
    /// example an expiring certificate or a partial filter snapshot).
    #[must_use]
    pub fn degraded(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            ready: true,
            code: Some(code),
            message: Some(message.into()),
            since_unix_ms: Some(unix_now_ms()),
        }
    }
}

/// Live readiness of server-owned components, published by the DNS server and
/// read by the admin API.
#[derive(Debug, Clone)]
pub struct ReadinessState {
    components: Arc<Mutex<Components>>,
}

#[derive(Debug, Clone, Default)]
struct Components {
    listeners: ComponentReadiness,
    tls: ComponentReadiness,
}

impl Default for ReadinessState {
    fn default() -> Self {
        // Before the server publishes its first state nothing is known to be
        // serving. A policy of "ready until proven otherwise" would let a
        // process that failed between web-listener bind and DNS-listener start
        // pass `/health`; default to not-ready and publish `ready` only after
        // the listener/TLS startup step succeeds.
        Self {
            components: Arc::new(Mutex::new(Components {
                listeners: ComponentReadiness::unavailable(
                    "listeners_not_started",
                    "DNS listeners have not started",
                ),
                tls: ComponentReadiness::unavailable(
                    "tls_not_initialized",
                    "TLS readiness has not been evaluated",
                ),
            })),
        }
    }
}

impl ReadinessState {
    /// Marks the DNS listener generation ready.
    pub fn set_listeners_ready(&self) {
        sito_core::sync::lock_or_recover_named(&self.components, "readiness.listeners").listeners =
            ComponentReadiness::ready();
    }

    /// Reports the DNS listener generation as unavailable.
    pub fn set_listeners_unavailable(&self, code: &'static str, message: impl Into<String>) {
        sito_core::sync::lock_or_recover_named(&self.components, "readiness.listeners").listeners =
            ComponentReadiness::unavailable(code, message);
    }

    /// Marks configured TLS acceptors ready.
    pub fn set_tls_ready(&self) {
        sito_core::sync::lock_or_recover_named(&self.components, "readiness.tls").tls =
            ComponentReadiness::ready();
    }

    /// Reports configured TLS material as unavailable.
    pub fn set_tls_unavailable(&self, code: &'static str, message: impl Into<String>) {
        sito_core::sync::lock_or_recover_named(&self.components, "readiness.tls").tls =
            ComponentReadiness::unavailable(code, message);
    }

    /// Reports configured TLS material as serving but degraded.
    pub fn set_tls_degraded(&self, code: &'static str, message: impl Into<String>) {
        sito_core::sync::lock_or_recover_named(&self.components, "readiness.tls").tls =
            ComponentReadiness::degraded(code, message);
    }

    /// Current listener readiness.
    #[must_use]
    pub fn listeners(&self) -> ComponentReadiness {
        sito_core::sync::lock_or_recover_named(&self.components, "readiness.listeners")
            .listeners
            .clone()
    }

    /// Current TLS readiness.
    #[must_use]
    pub fn tls(&self) -> ComponentReadiness {
        sito_core::sync::lock_or_recover_named(&self.components, "readiness.tls")
            .tls
            .clone()
    }
}

/// Inputs for one readiness aggregation.
pub struct ReadinessInputs<'a> {
    /// Server-owned listener readiness.
    pub listeners: ComponentReadiness,
    /// Server-owned TLS readiness.
    pub tls: ComponentReadiness,
    /// ACME challenge/issuance readiness.
    pub acme: &'a AcmeReadiness,
    /// HA replication readiness.
    pub ha: &'a HaReadiness,
    /// Filter engine status.
    pub filter: &'a FilterStatus,
    /// Stats database/writer failure summary, when the probe failed.
    pub stats: Option<&'a str>,
}

impl ReadinessReport {
    /// Aggregates component readiness.
    ///
    /// Blocking components are listeners, TLS, ACME (challenge/expiry/issuance
    /// failure), HA and a filter engine with no usable snapshot. A
    /// retained/partial filter snapshot, an expiring certificate, a renewal
    /// failure and a stats database/writer failure are reported as advisory
    /// reasons: DNS resolution still works, so they must not turn into a DNS
    /// outage. The documented policy is in `docs/runbook-ha.md` and
    /// `docs/audit6-best-effort.md`.
    #[must_use]
    pub fn from_parts(inputs: ReadinessInputs<'_>) -> Self {
        let mut ready = true;
        let mut reasons = Vec::new();

        if !inputs.listeners.ready || inputs.listeners.code.is_some() {
            if !inputs.listeners.ready {
                ready = false;
            }
            reasons.push(ReadinessReason::new(
                COMPONENT_LISTENERS,
                inputs.listeners.code.unwrap_or("listeners_unavailable"),
                inputs
                    .listeners
                    .message
                    .unwrap_or_else(|| "DNS listeners are not bound".to_string()),
                inputs.listeners.since_unix_ms,
            ));
        }

        if !inputs.tls.ready || inputs.tls.code.is_some() {
            if !inputs.tls.ready {
                ready = false;
            }
            reasons.push(ReadinessReason::new(
                COMPONENT_TLS,
                inputs.tls.code.unwrap_or("tls_unavailable"),
                inputs
                    .tls
                    .message
                    .unwrap_or_else(|| "configured TLS listener is not serving".to_string()),
                inputs.tls.since_unix_ms,
            ));
        }

        if inputs.acme.enabled && (inputs.acme.reason.is_some() || !inputs.acme.ready) {
            if !inputs.acme.ready {
                ready = false;
            }
            reasons.push(ReadinessReason::new(
                COMPONENT_ACME,
                inputs.acme.reason.unwrap_or("acme_not_ready"),
                "ACME certificate issuance is not ready",
                None,
            ));
        }

        if !inputs.ha.ready {
            ready = false;
            reasons.push(ReadinessReason::new(
                COMPONENT_HA,
                "ha_not_ready",
                inputs
                    .ha
                    .reason
                    .clone()
                    .unwrap_or_else(|| "HA replication is not ready".to_string()),
                None,
            ));
        }

        if let Some(FilterReadiness {
            blocking,
            code,
            message,
        }) = filter_readiness(inputs.filter)
        {
            if blocking {
                ready = false;
            }
            reasons.push(ReadinessReason::new(COMPONENT_FILTER, code, message, None));
        }

        if let Some(message) = inputs.stats {
            // Advisory only: stats is not on the DNS query path.
            reasons.push(ReadinessReason::new(
                COMPONENT_STATS,
                "stats_unavailable",
                message,
                None,
            ));
        }

        Self { ready, reasons }
    }
}

struct FilterReadiness {
    blocking: bool,
    code: &'static str,
    message: String,
}

fn filter_readiness(status: &FilterStatus) -> Option<FilterReadiness> {
    // Only `unavailable` means no usable snapshot exists. `Failed` without it
    // is a rejected live apply that retained the previous snapshot (see the
    // FilterState documentation and `ensure_reload_sources`).
    if status.unavailable {
        let (code, message) = if status.state == FilterState::Loading {
            (
                "filter_loading",
                "filter engine has not loaded its first rule snapshot yet".to_string(),
            )
        } else {
            (
                "filter_unavailable",
                format!(
                    "filter engine has no usable snapshot ({} failed list(s))",
                    status.failed_lists.len()
                ),
            )
        };
        return Some(FilterReadiness {
            blocking: true,
            code,
            message,
        });
    }

    if status.state == FilterState::Failed {
        return Some(FilterReadiness {
            blocking: false,
            code: "filter_degraded",
            message: "a live filter apply was rejected; the previous snapshot is still serving"
                .to_string(),
        });
    }

    if status.state == FilterState::Loading {
        return Some(FilterReadiness {
            blocking: false,
            code: "filter_loading",
            message: "filter engine is reloading; the previous snapshot remains active".to_string(),
        });
    }

    let degraded = !status.failed_lists.is_empty()
        || !status.degraded_lists.is_empty()
        || !status.degraded_groups.is_empty()
        || status.dropped_regex_patterns > 0
        || status.last_error.is_some();
    degraded.then(|| FilterReadiness {
        blocking: false,
        code: "filter_degraded",
        message: format!(
            "filter engine is serving a partial snapshot ({} failed list(s), {} degraded group(s), {} dropped pattern(s)); last error: {}",
            status.failed_lists.len(),
            status.degraded_groups.len(),
            status.dropped_regex_patterns,
            status.last_error.as_deref().unwrap_or("none")
        ),
    })
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AcmeReadiness;

    fn acme(enabled: bool, ready: bool, reason: Option<&'static str>) -> AcmeReadiness {
        AcmeReadiness {
            enabled,
            ready,
            http01_available: true,
            tls_alpn_available: false,
            reason,
            last_error: reason.map(str::to_string),
        }
    }

    fn filter(state: FilterState) -> FilterStatus {
        FilterStatus {
            state,
            ..FilterStatus::default()
        }
    }

    fn aggregate(
        listeners: ComponentReadiness,
        tls: ComponentReadiness,
        acme: &AcmeReadiness,
        ha: &HaReadiness,
        filter: &FilterStatus,
        stats: Option<&str>,
    ) -> ReadinessReport {
        ReadinessReport::from_parts(ReadinessInputs {
            listeners,
            tls,
            acme,
            ha,
            filter,
            stats,
        })
    }

    #[test]
    fn test_readiness_state_defaults_to_not_ready_until_startup_publishes() {
        let state = ReadinessState::default();
        assert!(!state.listeners().ready, "listeners must not default ready");
        assert!(!state.tls().ready, "TLS must not default ready");
        state.set_listeners_ready();
        state.set_tls_ready();
        assert!(state.listeners().ready);
        assert!(state.tls().ready);
    }

    #[test]
    fn test_readiness_all_ready_has_no_reasons() {
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::ready(),
            &acme(false, true, None),
            &HaReadiness::ready(),
            &filter(FilterState::Disabled),
            None,
        );
        assert!(report.ready);
        assert!(report.reasons.is_empty(), "{:?}", report.reasons);
    }

    #[test]
    fn test_readiness_listener_failure_blocks_and_names_component() {
        let report = aggregate(
            ComponentReadiness::unavailable("listener_bind_failed", "no listener is bound"),
            ComponentReadiness::ready(),
            &acme(false, true, None),
            &HaReadiness::ready(),
            &filter(FilterState::Disabled),
            None,
        );
        assert!(!report.ready);
        assert_eq!(report.reasons.len(), 1);
        assert_eq!(report.reasons[0].component, COMPONENT_LISTENERS);
        assert_eq!(report.reasons[0].code, "listener_bind_failed");
        assert!(report.reasons[0].since_unix_ms.is_some());
    }

    #[test]
    fn test_readiness_tls_failure_blocks() {
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::unavailable("tls_acceptor_unavailable", "no TLS acceptor"),
            &acme(false, true, None),
            &HaReadiness::ready(),
            &filter(FilterState::Disabled),
            None,
        );
        assert!(!report.ready);
        assert_eq!(report.reasons[0].component, COMPONENT_TLS);
        assert_eq!(report.reasons[0].code, "tls_acceptor_unavailable");
    }

    #[test]
    fn test_readiness_acme_failure_blocks_with_stable_code() {
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::ready(),
            &acme(true, false, Some("acme_challenge_unavailable")),
            &HaReadiness::ready(),
            &filter(FilterState::Disabled),
            None,
        );
        assert!(!report.ready);
        assert_eq!(report.reasons[0].component, COMPONENT_ACME);
        assert_eq!(report.reasons[0].code, "acme_challenge_unavailable");
        assert!(
            !report.reasons[0].message.contains("missing.txt"),
            "the readiness message must not leak certificate paths: {}",
            report.reasons[0].message
        );
    }

    #[test]
    fn test_readiness_acme_renewal_failure_is_advisory() {
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::ready(),
            &acme(true, true, Some("acme_renewal_failed")),
            &HaReadiness::ready(),
            &filter(FilterState::Disabled),
            None,
        );
        assert!(
            report.ready,
            "a current valid certificate keeps serving while renewal retries"
        );
        assert_eq!(report.reasons[0].component, COMPONENT_ACME);
        assert_eq!(report.reasons[0].code, "acme_renewal_failed");
    }

    #[test]
    fn test_readiness_acme_expired_certificate_blocks() {
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::ready(),
            &acme(true, false, Some("acme_cert_expired")),
            &HaReadiness::ready(),
            &filter(FilterState::Disabled),
            None,
        );
        assert!(!report.ready);
        assert_eq!(report.reasons[0].code, "acme_cert_expired");
    }

    #[test]
    fn test_readiness_tls_expiring_is_advisory() {
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::degraded("tls_cert_expiring", "static certificate expires soon"),
            &acme(false, true, None),
            &HaReadiness::ready(),
            &filter(FilterState::Disabled),
            None,
        );
        assert!(
            report.ready,
            "an expiring but currently valid static certificate keeps serving"
        );
        assert_eq!(report.reasons[0].component, COMPONENT_TLS);
        assert_eq!(report.reasons[0].code, "tls_cert_expiring");
    }

    #[test]
    fn test_readiness_tls_expired_blocks() {
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::unavailable("tls_cert_expired", "static certificate expired"),
            &acme(false, true, None),
            &HaReadiness::ready(),
            &filter(FilterState::Disabled),
            None,
        );
        assert!(!report.ready);
        assert_eq!(report.reasons[0].code, "tls_cert_expired");
    }

    #[test]
    fn test_readiness_ha_failure_blocks() {
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::ready(),
            &acme(false, true, None),
            &HaReadiness::not_ready("slave lost its master"),
            &filter(FilterState::Disabled),
            None,
        );
        assert!(!report.ready);
        assert_eq!(report.reasons[0].component, COMPONENT_HA);
        assert_eq!(report.reasons[0].code, "ha_not_ready");
        assert!(report.reasons[0].message.contains("lost its master"));
    }

    #[test]
    fn test_readiness_unavailable_filter_blocks() {
        let mut failed = filter(FilterState::Failed);
        failed.unavailable = true;
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::ready(),
            &acme(false, true, None),
            &HaReadiness::ready(),
            &failed,
            None,
        );
        assert!(!report.ready);
        assert_eq!(report.reasons[0].component, COMPONENT_FILTER);
        assert_eq!(report.reasons[0].code, "filter_unavailable");

        let mut loading = filter(FilterState::Loading);
        loading.unavailable = true;
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::ready(),
            &acme(false, true, None),
            &HaReadiness::ready(),
            &loading,
            None,
        );
        assert!(!report.ready);
        assert_eq!(report.reasons[0].code, "filter_loading");
    }

    /// `FilterState::Failed` with `unavailable == false` means a live apply was
    /// rejected while the previous snapshot is still filtering. That is
    /// degraded, not a DNS outage.
    #[test]
    fn test_readiness_failed_filter_with_retained_snapshot_is_advisory() {
        let failed = filter(FilterState::Failed);
        assert!(
            !failed.unavailable,
            "the fixture must represent a retained snapshot"
        );
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::ready(),
            &acme(false, true, None),
            &HaReadiness::ready(),
            &failed,
            None,
        );
        assert!(
            report.ready,
            "a retained snapshot must not take DNS out of rotation: {:?}",
            report.reasons
        );
        assert_eq!(report.reasons[0].component, COMPONENT_FILTER);
        assert_eq!(report.reasons[0].code, "filter_degraded");
    }

    /// `Loading` with `unavailable == false` means a refresh is in flight but a
    /// usable snapshot is still active: advisory, not blocking.
    #[test]
    fn test_readiness_loading_filter_with_snapshot_is_advisory() {
        let loading = filter(FilterState::Loading);
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::ready(),
            &acme(false, true, None),
            &HaReadiness::ready(),
            &loading,
            None,
        );
        assert!(report.ready);
        assert_eq!(report.reasons[0].code, "filter_loading");
    }

    /// A `Ready` engine that recorded a rejected live apply keeps serving the
    /// old snapshot; the error must be visible as an advisory reason.
    #[test]
    fn test_readiness_ready_filter_with_last_error_is_advisory() {
        let mut ready = filter(FilterState::Ready);
        ready.last_error = Some("live apply rejected".to_string());
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::ready(),
            &acme(false, true, None),
            &HaReadiness::ready(),
            &ready,
            None,
        );
        assert!(report.ready);
        assert_eq!(report.reasons[0].code, "filter_degraded");
        assert!(report.reasons[0].message.contains("last error"));
    }

    #[test]
    fn test_readiness_degraded_filter_is_advisory_only() {
        let mut degraded = filter(FilterState::Ready);
        degraded.failed_lists = vec!["ads".to_string()];
        degraded.degraded_groups = vec!["kids".to_string()];
        degraded.dropped_regex_patterns = 2;
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::ready(),
            &acme(false, true, None),
            &HaReadiness::ready(),
            &degraded,
            None,
        );
        assert!(
            report.ready,
            "a partial snapshot must not take the DNS service out of rotation"
        );
        assert_eq!(report.reasons[0].component, COMPONENT_FILTER);
        assert_eq!(report.reasons[0].code, "filter_degraded");
    }

    #[test]
    fn test_readiness_stats_outage_is_advisory_not_a_dns_outage() {
        let report = aggregate(
            ComponentReadiness::ready(),
            ComponentReadiness::ready(),
            &acme(false, true, None),
            &HaReadiness::ready(),
            &filter(FilterState::Disabled),
            Some("stats database probe failed"),
        );
        assert!(
            report.ready,
            "stats is not on the DNS query path; an outage must be a degraded reason, not a readiness failure"
        );
        assert_eq!(report.reasons[0].component, COMPONENT_STATS);
        assert_eq!(report.reasons[0].code, "stats_unavailable");
    }

    #[test]
    fn test_readiness_components_are_ordered() {
        let report = aggregate(
            ComponentReadiness::unavailable("listener_bind_failed", "no listener"),
            ComponentReadiness::unavailable("tls_acceptor_unavailable", "no tls"),
            &acme(true, false, Some("acme_issuance_failed")),
            &HaReadiness::not_ready("not ready"),
            &filter(FilterState::Failed),
            Some("stats down"),
        );
        let order: Vec<&str> = report
            .reasons
            .iter()
            .map(|reason| reason.component.as_str())
            .collect();
        assert_eq!(
            order,
            vec![
                COMPONENT_LISTENERS,
                COMPONENT_TLS,
                COMPONENT_ACME,
                COMPONENT_HA,
                COMPONENT_FILTER,
                COMPONENT_STATS,
            ]
        );
    }

    #[test]
    fn test_poisoned_readiness_mutex_keeps_last_good_value_and_does_not_panic() {
        let state = ReadinessState::default();
        state.set_listeners_ready();
        let components = Arc::clone(&state.components);
        let _ = std::thread::spawn(move || {
            let _guard = components.lock().expect("fresh readiness mutex");
            panic!("poison the readiness mutex");
        })
        .join();

        assert!(
            state.listeners().ready,
            "readiness must recover the last-good value instead of panicking"
        );
        // Mutating through a poisoned mutex must also work.
        state.set_listeners_unavailable("listener_bind_failed", "rebind lost every listener");
        assert!(!state.listeners().ready);
    }
}
