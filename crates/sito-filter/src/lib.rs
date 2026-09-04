//! `sito-filter`
//!
//! High-throughput DNS filtering engine supporting hosts-format blocklists,
//! asynchronous downloading with disk caching, and atomic snapshot updates.

pub mod downloader;
pub mod engine;
pub mod error;
pub mod parser;
pub mod structures;

pub use downloader::ListDownloader;
pub use engine::{FilterSnapshot, HostsFilterEngine};
pub use error::FilterError;
pub use parser::parse_hosts;
