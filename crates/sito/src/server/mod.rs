//! DNS server startup, listeners, TLS/ACME, watchers, and shutdown.
//!
//! The facade re-exports the historical `sito::server` entry points; each
//! sibling module owns one lifecycle phase.

//! Server lifecycle and runner implementation.

use notify::{Event, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{error, info, warn};

use arc_swap::ArcSwap;
use sito_cache::DnsCache;
use sito_core::config::Config;
use sito_dnssec::DnssecValidator;
use sito_filter::HostsFilterEngine;
use sito_stats::{MetricsRegistry, QueryLogWriter, StatsDb};
use sito_transport::{
    AcmeChallengeAvailability, AcmeServiceConfig, CertWatcher, Doh3Config, DohConfig, DoqConfig,
    DotConfig, TcpConfig, TlsAcceptorManager, TlsManagerSet, UdpConfig, generate_self_signed_cert,
    load_server_config, load_server_config_with_challenges, record_bootstrap_cert,
    start_acme_manager_for_transports, start_doh_listener, start_doh3_listener, start_doq_listener,
    start_dot_listener, start_tcp_listener, start_udp_listener, write_secret_file,
};
use sito_upstream::{BootstrapResolver, UpstreamManager};

use crate::pipeline::DnsPipeline;

mod common;
mod ha;
mod listeners;
mod runtime;
mod shutdown;
mod startup;
mod tls;
mod watcher;

#[allow(clippy::wildcard_imports)]
pub use common::*;
#[allow(clippy::wildcard_imports)]
pub use ha::*;
#[allow(clippy::wildcard_imports)]
use listeners::*;
#[allow(clippy::wildcard_imports)]
use runtime::*;
#[allow(clippy::wildcard_imports)]
use shutdown::*;
#[allow(clippy::wildcard_imports)]
pub use startup::*;
#[allow(clippy::wildcard_imports)]
use tls::*;
#[allow(clippy::wildcard_imports)]
use watcher::*;

pub(crate) use runtime::run_list_refresh;

#[cfg(test)]
mod tests;
