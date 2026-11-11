//! `sito-core`
//!
//! Core contracts, shared data structures, verdicts (Block, Allow, Rewrite),
//! error definitions, configuration schema, and fundamental traits for the sito DNS server pipeline.

pub mod client;
pub mod config;
pub mod config_migrate;
pub mod config_schema;
pub mod dnssec_fetch;
pub mod domain;
pub mod engine;
pub mod error;
pub mod net;
pub mod ssrf;
pub mod verdict;

pub use client::{ClientContext, ClientId, ClientIdentity, ClientIdentityRef, IdentitySource};
pub use config::{
    AcmeConfig, BlockingMode, CacheConfig, Config, DnsConfig, DnssecConfig, FilterListConfig,
    FilteringConfig, PerDomainUpstream, ServerConfig, SniCertConfig, TlsConfig, UpstreamConfig,
    UpstreamStrategy,
};
pub use config_migrate::{MigrationChange, MigrationOptions, MigrationOutcome, MigrationReport};
pub use config_schema::{FieldStatus, SchemaField};
pub use dnssec_fetch::DnssecKeyFetcher;
pub use domain::{DomainError, NormalizedDomain, matches_domain_suffix, matches_strict_subdomain};
pub use engine::FilterEngine;
pub use error::{ConfigError, UpstreamError};
pub use net::{CidrError, IpNetwork, ip_in_subnet};
pub use ssrf::is_denied_target_ip;
pub use verdict::{BlockReason, RewriteAction, RuleRef, Verdict};
