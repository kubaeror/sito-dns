//! Structured audit records for ADR-0010 automatic promotion.
//!
//! Audit records use the stable `ha.promotion.*` event names and a fixed,
//! secret-free field set: `node_id`, `outcome`, `reason`, `term`, `version`
//! and `holder`. Tokens, private keys, certificate material and full witness
//! URLs are deliberately never included. The records are ordinary `tracing`
//! events under the `sito::ha::promotion` target so an operator can route them
//! to an audit sink with the rest of the structured logs.

use tracing::info;

/// Lease acquisition succeeded (grant held at a new term).
pub const LEASE_ACQUIRED: &str = "ha.promotion.lease_acquired";
/// A renewal succeeded.
pub const LEASE_RENEWED: &str = "ha.promotion.lease_renewed";
/// The lease was lost, expired, or the witness record disappeared.
pub const LEASE_LOST: &str = "ha.promotion.lease_lost";
/// A durable fence was recorded / the node self-fenced.
pub const FENCED: &str = "ha.promotion.fenced";
/// A promotion was refused or aborted before it could publish.
pub const REFUSED: &str = "ha.promotion.refused";
/// The pre-publish quiesce window completed.
pub const QUIESCED: &str = "ha.promotion.quiesced";
/// Hello-only reconciliation completed.
pub const RECONCILED: &str = "ha.promotion.reconciled";
/// The promotion completed and the node is the writable master.
pub const COMPLETED: &str = "ha.promotion.completed";
/// The first publish was aborted by reconciliation.
pub const PUBLISH_ABORTED: &str = "ha.promotion.publish_aborted";
/// A confirmation is required before the candidate may acquire.
pub const MANUAL_CONFIRMATION_REQUIRED: &str = "ha.promotion.manual_confirmation_required";
/// The operator confirmation was consumed.
pub const MANUAL_CONFIRMATION_CONFIRMED: &str = "ha.promotion.manual_confirmation_confirmed";

/// One structured audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionAudit {
    /// Stable `ha.promotion.*` event name.
    pub event: &'static str,
    /// Stable node identity.
    pub node_id: String,
    /// Short outcome word (`acquired`, `renewed`, `refused`, ...).
    pub outcome: String,
    /// Stable reason code, when applicable.
    pub reason: Option<String>,
    /// Cluster term at the time of the record.
    pub term: u64,
    /// Active/published bundle version.
    pub version: u64,
    /// Witness holder (`node_id/boot_uuid`), when known.
    pub holder: Option<String>,
}

impl PromotionAudit {
    /// Builds a record with no optional reason/holder.
    #[must_use]
    pub fn new(
        event: &'static str,
        node_id: impl Into<String>,
        outcome: impl Into<String>,
    ) -> Self {
        Self {
            event,
            node_id: node_id.into(),
            outcome: outcome.into(),
            reason: None,
            term: 0,
            version: 0,
            holder: None,
        }
    }

    /// Adds the stable reason code.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Adds term/version context.
    #[must_use]
    pub fn with_bundle(mut self, term: u64, version: u64) -> Self {
        self.term = term;
        self.version = version;
        self
    }

    /// Adds the witness holder identity.
    #[must_use]
    pub fn with_holder(mut self, holder: impl Into<String>) -> Self {
        self.holder = Some(holder.into());
        self
    }

    /// The fixed field set as `(name, value)` pairs.
    ///
    /// Exposed so tests can assert the exact audit schema without parsing a log
    /// line.
    #[must_use]
    pub fn fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("event", self.event.to_string()),
            ("node_id", self.node_id.clone()),
            ("outcome", self.outcome.clone()),
            ("reason", self.reason.clone().unwrap_or_default()),
            ("term", self.term.to_string()),
            ("version", self.version.to_string()),
            ("holder", self.holder.clone().unwrap_or_default()),
        ]
    }

    /// Emits the structured record.
    pub fn emit(&self) {
        info!(
            target: "sito::ha::promotion",
            event = self.event,
            node_id = %self.node_id,
            outcome = %self.outcome,
            reason = %self.reason.as_deref().unwrap_or_default(),
            term = self.term,
            version = self.version,
            holder = %self.holder.as_deref().unwrap_or_default(),
            "ha.promotion"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use tracing::Subscriber;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::prelude::*;

    #[derive(Default)]
    struct FieldVisitor {
        fields: BTreeMap<String, String>,
    }

    impl Visit for FieldVisitor {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

    impl<S: Subscriber> Layer<S> for Capture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = FieldVisitor::default();
            event.record(&mut visitor);
            self.0.lock().unwrap().push(visitor.fields);
        }
    }

    #[test]
    fn audit_records_use_the_fixed_secret_free_schema() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        tracing::subscriber::with_default(subscriber, || {
            PromotionAudit::new(LEASE_ACQUIRED, "sito-node-a", "acquired")
                .with_reason("automatic")
                .with_bundle(8, 128)
                .with_holder("sito-node-a/boot")
                .emit();
        });

        let records = capture.0.lock().unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["event"], LEASE_ACQUIRED);
        assert_eq!(record["node_id"], "sito-node-a");
        assert_eq!(record["outcome"], "acquired");
        assert_eq!(record["reason"], "automatic");
        assert_eq!(record["term"], "8");
        assert_eq!(record["version"], "128");
        assert_eq!(record["holder"], "sito-node-a/boot");

        // No secret-looking field names may ever appear in the audit schema.
        for name in [
            "token",
            "token_file",
            "key",
            "private_key",
            "cert",
            "certificate",
            "password",
            "secret",
            "url",
        ] {
            assert!(
                !record.keys().any(|key| key.contains(name)),
                "audit field {name} leaked into {record:?}"
            );
        }
    }

    #[test]
    fn audit_field_set_is_stable() {
        let audit = PromotionAudit::new(FENCED, "node", "fenced")
            .with_reason("lease_lost")
            .with_bundle(3, 9);
        let fields = audit.fields();
        let names: Vec<&str> = fields.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            vec![
                "event", "node_id", "outcome", "reason", "term", "version", "holder"
            ]
        );
        assert!(!fields.iter().any(|(name, _)| name.contains("token")));
    }
}
