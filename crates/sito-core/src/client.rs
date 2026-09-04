//! Client context and identification types.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// An identifier assigned to a specific client.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientId(pub String);

impl ClientId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Context information for a client originating a DNS query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientContext {
    pub ip: IpAddr,
    pub id: Option<ClientId>,
}

impl ClientContext {
    pub fn new(ip: IpAddr) -> Self {
        Self { ip, id: None }
    }

    pub fn with_id(ip: IpAddr, id: impl Into<String>) -> Self {
        Self {
            ip,
            id: Some(ClientId::new(id)),
        }
    }
}
