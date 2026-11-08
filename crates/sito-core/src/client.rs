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

fn default_proto() -> String {
    "udp".to_string()
}

/// Context information for a client originating a DNS query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientContext {
    pub ip: IpAddr,
    #[serde(default = "default_proto")]
    pub proto: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<ClientId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// True only when `id` was resolved by the client registry (a configured
    /// shared secret, or an entry selected by IP/CIDR/MAC/RouterOS).
    ///
    /// Raw DoH path / SNI identifiers are client-controlled and leave this
    /// `false`; consumers such as rewrite exceptions must not trust `id`
    /// without it. Defaults to `false` for older serialized contexts.
    #[serde(default)]
    pub id_authenticated: bool,
}

impl ClientContext {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            proto: default_proto(),
            id: None,
            sni: None,
            mac: None,
            client_name: None,
            group: None,
            id_authenticated: false,
        }
    }

    pub fn with_id(ip: IpAddr, id: impl Into<String>) -> Self {
        Self {
            ip,
            proto: default_proto(),
            id: Some(ClientId::new(id)),
            sni: None,
            mac: None,
            client_name: None,
            group: None,
            id_authenticated: false,
        }
    }

    pub fn with_sni(ip: IpAddr, sni: impl Into<String>) -> Self {
        let s = sni.into();
        Self {
            ip,
            proto: default_proto(),
            id: Some(ClientId::new(s.clone())),
            sni: Some(s),
            mac: None,
            client_name: None,
            group: None,
            id_authenticated: false,
        }
    }

    /// Marks the current `id` as registry-authenticated.
    #[must_use]
    pub fn with_authenticated_id(mut self) -> Self {
        self.id_authenticated = true;
        self
    }

    #[must_use]
    pub fn with_proto(mut self, proto: impl Into<String>) -> Self {
        self.proto = proto.into();
        self
    }

    #[must_use]
    pub fn with_mac(mut self, mac: impl Into<String>) -> Self {
        self.mac = Some(mac.into());
        self
    }

    #[must_use]
    pub fn with_client_name(mut self, name: impl Into<String>) -> Self {
        self.client_name = Some(name.into());
        self
    }

    #[must_use]
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }
}
