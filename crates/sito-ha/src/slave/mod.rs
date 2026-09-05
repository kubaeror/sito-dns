//! Replica slave state machine and replication worker.

pub mod state;
pub mod worker;

pub use state::{SlaveState, SlaveStatusTracker};
pub use worker::{SlaveAppHandles, apply_config_push, spawn_slave_worker};
