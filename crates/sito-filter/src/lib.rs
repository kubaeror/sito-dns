//! `sito-filter`
//!
//! High-throughput DNS filtering engine supporting hosts-format blocklists,
//! asynchronous downloading with disk caching, and atomic snapshot updates.

pub mod anti_bypass;
pub mod downloader;
pub mod engine;
pub mod error;
pub mod parser;
pub mod structures;
pub mod subscription;

pub use anti_bypass::AntiBypassRegistry;
pub use downloader::ListDownloader;
pub use engine::{
    CompileObserver, FilterSnapshot, FilterState, FilterStatus, GroupRuleSet, HostsFilterEngine,
    apply_rewrite_cancellations,
};
pub use error::FilterError;
pub use parser::{
    DnsRewriteRule, ParseError, ParseLimits, Pattern, Rule, RuleKind, RuleModifiers, parse_rules,
    parse_rules_with_limits,
};
pub use structures::{CompileBudget, CompileBudgetExceeded};
pub use subscription::{ListMetadata, SubscriptionFetcher};
