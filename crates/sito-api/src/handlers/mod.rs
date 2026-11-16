//! REST API handler modules for sito administrative server.

pub mod auth_handlers;
pub mod cache;
pub mod clients;
pub mod config;
pub mod filtering;
#[cfg(feature = "ha")]
pub mod ha;
#[cfg(not(feature = "ha"))]
pub mod ha_stub;
pub mod metrics;
pub mod querylog;
pub mod rewrites;
pub mod stats;
pub mod status;
pub mod update;
pub mod upstream;
