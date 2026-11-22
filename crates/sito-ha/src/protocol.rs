//! Compatibility re-export of the portable HA wire protocol types.

pub use sito_ha_types::protocol::{AckConflict, HaMessage, PROTOCOL_VERSION, UpstreamReport};

/// Capability advertised by a slave that enforces the ADR-0011 DNS client ACL.
///
/// A master with `clients.default_policy = "deny"` reports
/// `acl_capability_missing` readiness while a connected slave does not
/// advertise this capability; the mixed-version cluster must stay on allow
/// until every DNS-serving node is upgraded.
pub const CAPABILITY_CLIENT_ACL: &str = "client_acl";
