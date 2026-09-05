//! Master node replication coordination and slave cluster tracking.

pub mod coordinator;
pub mod tracker;

pub use coordinator::{MasterCoordinator, spawn_master_server};
pub use tracker::{ActiveSlave, SlaveStatsSummary, SlaveSummary};
