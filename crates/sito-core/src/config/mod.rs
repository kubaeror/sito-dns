//! Configuration schema v2, validation, and compatibility aliases.
//!
//! The facade preserves the historical `sito_core::config` paths. Schema
//! types/defaults live in `schema`; cross-section validation lives in
//! `validate`.

//! Configuration structures, deserialization, and validation.

use crate::config_schema;
use crate::domain::NormalizedDomain;
use crate::error::ConfigError;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

mod schema;
mod validate;

pub use schema::*;
pub use validate::validate_upstream_target;

pub use crate::config_migrate::{
    MigrationChange, MigrationOptions, MigrationOutcome, MigrationReport,
};

/// Config schema version accepted by this build. Frozen at WP-1.3 (D4).
pub const CONFIG_VERSION: u32 = 2;

/// The v1 schema version understood by `sito config migrate`.
pub const CONFIG_VERSION_V1: u32 = 1;

#[cfg(test)]
mod tests;
