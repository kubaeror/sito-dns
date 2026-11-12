//! DNS pipeline facade.
//!
//! Query helpers, response construction, rewrites, verdict precedence, stages,
//! and the QueryHandler entry point live in sibling modules; `DnsPipeline`
//! itself stays here so the public path and field invariants are unchanged.

//! DNS query execution pipeline.

use arc_swap::ArcSwap;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, PTR, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use sito_cache::{DnsCache, ValidationStatus};
use sito_clients::{
    ClientRegistry, EffectivePolicy, ParentalRegistry, RuntimeLists, ServiceRegistry,
    match_safe_search,
};
use sito_core::client::ClientContext;
use sito_core::config::{Config, UpstreamEcs};
use sito_core::verdict::Verdict;
use sito_dnssec::DnssecValidator;
use sito_filter::{AntiBypassRegistry, DnsRewriteRule, FilterSnapshot, HostsFilterEngine};
use sito_proto::wire::{synthesize_cname_response, synthesize_records_response};
use sito_proto::{ResponseShaper, synthesize_blocked_response};
use sito_rewrites::RewriteTable;
use sito_runtime::RuntimeState;
use sito_transport::QueryHandler;
use sito_upstream::UpstreamManager;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{Instrument, debug, error, info, trace, warn};

/// Tracks in-flight queries using RAII.
struct InFlightGuard(Arc<AtomicUsize>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The core DNS query resolution pipeline.
pub struct DnsPipeline {
    runtime: Arc<RuntimeState>,
    anti_bypass: Arc<AntiBypassRegistry>,
    cache: Arc<DnsCache>,
    upstream: Arc<UpstreamManager>,
    lists: Arc<RuntimeLists>,
    in_flight: Arc<AtomicUsize>,
    prefetch_semaphore: Arc<tokio::sync::Semaphore>,
    querylog: Option<sito_stats::QueryLogSender>,
    metrics: Option<sito_stats::MetricsRegistry>,
    /// Per-client upstream managers keyed by `servers.join(",")`; swappable so
    /// client upstream changes hot-reload.
    scoped_upstreams: Arc<ArcSwap<HashMap<String, Arc<UpstreamManager>>>>,
}

mod cache;
mod context;
mod dnssec;
mod filter;
mod finalize;
mod handle;
mod query;
mod responses;
mod rewrites;
mod shaping;
mod stages;
mod upstream;
mod verdict;

#[allow(clippy::wildcard_imports)]
use context::*;
#[allow(clippy::wildcard_imports)]
use query::*;
#[allow(clippy::wildcard_imports)]
use responses::*;
#[allow(clippy::wildcard_imports)]
use rewrites::*;
#[allow(clippy::wildcard_imports)]
use verdict::*;

#[cfg(test)]
mod tests;
