//! `sito-core`
//!
//! Core contracts, shared data structures, verdicts (Block, Allow, Rewrite),
//! error definitions, configuration schema, and fundamental traits for the sito DNS server pipeline.

pub mod client;
pub mod config;
pub mod engine;
pub mod error;
pub mod state;
pub mod verdict;

pub use client::{ClientContext, ClientId};
pub use config::{
    BlockingMode, CacheConfig, Config, DnsConfig, DnssecConfig, FilterListConfig, FilteringConfig,
    PerDomainUpstream, ServerConfig, UpstreamConfig, UpstreamStrategy,
};
pub use engine::FilterEngine;
pub use error::{ConfigError, UpstreamError};
pub use state::AppState;
pub use verdict::{BlockReason, RewriteAction, RuleRef, Verdict};
