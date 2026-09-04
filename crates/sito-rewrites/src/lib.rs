//! `sito-rewrites`
//!
//! DNS rewrite tables and local record overrides:
//! - Exact and wildcard domain-to-IP/CNAME mappings
//! - Automated reverse DNS PTR record generation (auto-PTR)
//! - Local `/etc/hosts` file parsing and synchronization
//! - Upstream rewrite exception lists

pub mod config;
pub mod table;

pub use config::{RewriteEntryConfig, RewritesConfig};
pub use table::{
    LocalRecordData, RewriteTable, ipv4_to_in_addr_arpa, ipv6_to_ip6_arpa, is_rfc1918, is_ula,
};
