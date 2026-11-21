//! Query log entry representation per section 14.1.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A single DNS query log record stored in SQLite or streamed over WebSockets.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct QueryLogEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// Timestamp in unix milliseconds.
    pub ts: i64,
    /// Client IP address (or masked if anonymization is enabled).
    pub client_ip: String,
    /// Optional human-readable client name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// Fully-qualified domain name queried (lowercased without trailing dot).
    pub qname: String,
    /// Query record type (A=1, AAAA=28, HTTPS=65, etc.).
    pub qtype: u16,
    /// Response code (0=NoError, 3=NXDomain, 2=ServFail, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcode: Option<u8>,
    /// Filtering verdict: "allowed" | "blocked" | "whitelisted" | "rewritten" | "stale".
    pub verdict: String,
    /// Matched filter rule text if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Source list name that produced the rule match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_source: Option<String>,
    /// Upstream resolver name or address that answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    /// Total elapsed processing duration in microseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_us: Option<i64>,
    /// DNSSEC outcome: "secure" | "insecure" | "bogus".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnssec: Option<String>,
    /// Incoming protocol: "udp" | "tcp" | "dot" | "doh" | "doq" | "doh3".
    pub proto: String,
}

// P2-60 regression probe: count clones on the current thread so a test can
// prove the live-tail path does not clone without subscribers. Thread-local
// keeps the probe isolated from unrelated tests running in parallel.
#[cfg(test)]
thread_local! {
    static CLONE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_clone_count() {
    CLONE_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn clone_count() -> usize {
    CLONE_COUNT.with(std::cell::Cell::get)
}

impl Clone for QueryLogEntry {
    fn clone(&self) -> Self {
        #[cfg(test)]
        CLONE_COUNT.with(|count| count.set(count.get() + 1));
        Self {
            id: self.id,
            ts: self.ts,
            client_ip: self.client_ip.clone(),
            client_name: self.client_name.clone(),
            qname: self.qname.clone(),
            qtype: self.qtype,
            rcode: self.rcode,
            verdict: self.verdict.clone(),
            rule: self.rule.clone(),
            list_source: self.list_source.clone(),
            upstream: self.upstream.clone(),
            elapsed_us: self.elapsed_us,
            dnssec: self.dnssec.clone(),
            proto: self.proto.clone(),
        }
    }
}

impl QueryLogEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ts: i64,
        client_ip: impl Into<String>,
        client_name: Option<String>,
        qname: impl Into<String>,
        qtype: u16,
        rcode: Option<u8>,
        verdict: impl Into<String>,
        proto: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            ts,
            client_ip: client_ip.into(),
            client_name,
            qname: qname.into(),
            qtype,
            rcode,
            verdict: verdict.into(),
            rule: None,
            list_source: None,
            upstream: None,
            elapsed_us: None,
            dnssec: None,
            proto: proto.into(),
        }
    }
}
