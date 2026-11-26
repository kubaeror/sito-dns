//! Client-side automatic-promotion engine (ADR-0010).
//!
//! C3b2a delivered the configuration (`sito-ha-types`) and the TLS/bearer
//! witness client. This module adds the promotion engine: durable publish
//! baseline state, master startup acquisition/read-only behavior, candidate
//! election, pre-publish quiesce, hello-only reconciliation, first
//! publish/renewal, durable self-fencing and effective-role switching.
//!
//! C3b2c owns the public status object, metrics, audit-event naming, docs and
//! the `confirm-promotion`/`clear-fence` CLI; the internal pieces they need
//! ([`PromotionEngine::snapshot`], [`PromotionEngine::confirmation_store`],
//! [`PromotionEngine::fence_store`]) are exposed here.

pub mod acquisition;
pub mod audit;
pub mod clock;
pub mod confirm;
pub mod engine;
pub mod fence;
pub mod reconcile;
pub mod renewal;
pub mod state;
pub mod witness_client;

#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod tests;

pub use acquisition::{
    AcquirePlan, AcquisitionDecision, AcquisitionRole, LocalContent, PromotionRefusal,
    decide_acquisition,
};
pub use audit::PromotionAudit;
pub use clock::{
    BoxFuture, ManualMonotonicClock, ManualTimers, MonotonicClock, PromotionTimers,
    SystemMonotonicClock, SystemTimers,
};
pub use confirm::{
    CONFIRM_FILE, CONFIRM_PROTOCOL_VERSION, ConfirmationError, ConfirmationFile, ConfirmationStore,
};
pub use engine::{
    ConfiguredRole, EffectiveRole, Eligibility, LeaseBackend, PreparedBundle, PromotionEngine,
    PromotionHost, PromotionOutcome, PromotionPhase, PromotionSnapshot, PublishDeadline,
    manual_clock,
};
pub use fence::{
    FENCE_FILE, FENCE_PENDING_FILE, FENCE_PROTOCOL_VERSION, FenceMarker, FencePersistOutcome,
    FenceReason, FenceStore,
};
pub use reconcile::{LatePeerLatch, PeerReport, ReconcileDecision, ReconcileInput, evaluate};
pub use renewal::{RenewalAction, SelfFenceCheck, SelfFenceDeadline, classify_renewal_error};
pub use state::{
    HaStateStore, LoadedState, PromotionBookkeeping, PublicationBaseline, check_data_dir_integrity,
};
pub use witness_client::{WITNESS_REQUEST_TIMEOUT, WitnessClient, WitnessClientError};
