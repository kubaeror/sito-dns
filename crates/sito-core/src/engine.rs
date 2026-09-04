//! Filter engine contract.

use crate::client::ClientContext;
use crate::verdict::Verdict;
use hickory_proto::rr::{Name, RecordType};

/// Common interface for DNS filtering engines.
pub trait FilterEngine: Send + Sync {
    /// Evaluate an incoming DNS query against the active rules.
    fn evaluate(&self, qname: &Name, qtype: RecordType, client: &ClientContext) -> Verdict;
}
