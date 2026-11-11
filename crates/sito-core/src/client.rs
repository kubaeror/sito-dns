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

/// Where a client's identity came from.
///
/// D10 trust table: `Ip`, `Cidr`, `Mac`, `Secret` and verified `RouterOs`
/// identities may match policy (`$client`, rewrite exceptions, secret-gated
/// rules). Raw `TlsSni` and `DohPath` labels are client-controlled and are
/// display/statistics-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    /// Exact IP address configured by the operator.
    Ip,
    /// CIDR block configured by the operator.
    Cidr,
    /// MAC address learned from ARP for an operator-configured MAC entry.
    Mac,
    /// Raw TLS SNI label (display only).
    TlsSni,
    /// DoH path label (display only).
    DohPath,
    /// A configured shared secret (DoH path or DoT/DoQ SNI).
    Secret,
    /// A verified RouterOS DHCP lease (HTTPS + certificate verification).
    #[serde(rename = "routeros")]
    RouterOs,
}

impl IdentitySource {
    /// Whether this source is identity-capable under D10.
    #[must_use]
    pub const fn is_trusted(self) -> bool {
        matches!(
            self,
            Self::Ip | Self::Cidr | Self::Mac | Self::Secret | Self::RouterOs
        )
    }

    /// The stable wire/API name of this source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Cidr => "cidr",
            Self::Mac => "mac",
            Self::TlsSni => "tls_sni",
            Self::DohPath => "doh_path",
            Self::Secret => "secret",
            Self::RouterOs => "routeros",
        }
    }
}

impl std::fmt::Display for IdentitySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A borrowed view of [`ClientIdentity`] for hot-path policy matching.
///
/// This avoids cloning the name/group/MAC strings for every rule evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIdentityRef<'a> {
    pub ip: IpAddr,
    pub source: IdentitySource,
    pub authenticated: bool,
    pub name: Option<&'a str>,
    pub group: Option<&'a str>,
    pub mac: Option<&'a str>,
}

impl ClientIdentityRef<'_> {
    /// True when this identity may match secret-gated policy.
    #[must_use]
    pub fn may_match_secret_rules(&self) -> bool {
        self.authenticated && self.source.is_trusted()
    }

    /// True when this identity may match rewrite `exception_clients` or
    /// `$client` rules.
    #[must_use]
    pub fn may_match_client_exception(&self) -> bool {
        self.authenticated && self.source.is_trusted()
    }
}

/// A resolved client identity with provenance.
///
/// Policy code must use [`ClientIdentity::may_match_secret_rules`] or
/// [`ClientIdentity::may_match_client_exception`] before matching `$client`
/// rules or rewrite `exception_clients`. It must never match a raw
/// [`ClientContext::id`] directly: that field may be a client-supplied DoH path
/// or SNI label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientIdentity {
    pub ip: IpAddr,
    pub source: IdentitySource,
    /// True only when the registry authenticated this identity under D10.
    pub authenticated: bool,
    pub name: Option<String>,
    pub group: Option<String>,
    pub mac: Option<String>,
}

impl ClientIdentity {
    /// Builds the policy identity for a context.
    ///
    /// The explicit `identity_source` wins. For backwards compatibility with
    /// library callers that populated the registry-managed fields directly
    /// (`client_name`/`group`), those fields are treated as an in-process,
    /// operator-configured IP identity. The registry always sets an explicit
    /// source (including `RouterOs` for trusted lease names), so this fallback
    /// only affects hand-built contexts. A context with only a wire-claimed
    /// id/SNI has an unauthenticated provenance and cannot match policy.
    #[must_use]
    pub fn from_context(ctx: &ClientContext) -> Option<Self> {
        ctx.identity_ref().map(Self::from)
    }

    /// True when this identity may match secret-gated policy.
    #[must_use]
    pub fn may_match_secret_rules(&self) -> bool {
        self.authenticated && self.source.is_trusted()
    }

    /// True when this identity may match rewrite `exception_clients` or
    /// `$client` rules.
    #[must_use]
    pub fn may_match_client_exception(&self) -> bool {
        self.authenticated && self.source.is_trusted()
    }
}

impl<'a> From<ClientIdentityRef<'a>> for ClientIdentity {
    fn from(identity: ClientIdentityRef<'a>) -> Self {
        Self {
            ip: identity.ip,
            source: identity.source,
            authenticated: identity.authenticated,
            name: identity.name.map(str::to_string),
            group: identity.group.map(str::to_string),
            mac: identity.mac.map(str::to_string),
        }
    }
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
    /// Provenance of the resolved identity.
    ///
    /// `None` for legacy serialized contexts and for queries that carry no
    /// identity at all. Wire transports set `TlsSni`/`DohPath`; the client
    /// registry replaces it with the authenticated source when an entry
    /// matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_source: Option<IdentitySource>,
    /// True only when `id` was resolved by the client registry (a configured
    /// shared secret, or an entry selected by IP/CIDR/MAC/RouterOS).
    ///
    /// Raw DoH path / SNI identifiers are client-controlled and leave this
    /// `false`; consumers must not treat `id` as policy identity without it,
    /// and should prefer [`ClientContext::identity`]. Defaults to `false` for
    /// older serialized contexts.
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
            identity_source: None,
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
            identity_source: Some(IdentitySource::DohPath),
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
            identity_source: Some(IdentitySource::TlsSni),
            id_authenticated: false,
        }
    }

    /// Marks the current `id` as registry-authenticated.
    ///
    /// An authenticated id is a configured shared secret, so it carries
    /// [`IdentitySource::Secret`] provenance.
    #[must_use]
    pub fn with_authenticated_id(mut self) -> Self {
        self.id_authenticated = true;
        self.identity_source = Some(IdentitySource::Secret);
        self
    }

    /// Returns a borrowed policy identity for this context, if one exists.
    ///
    /// Prefer this on hot paths; [`ClientContext::identity`] clones the
    /// name/group/MAC strings.
    #[must_use]
    pub fn identity_ref(&self) -> Option<ClientIdentityRef<'_>> {
        let source = self.identity_source.or_else(|| {
            if self.client_name.is_some() || self.group.is_some() {
                Some(IdentitySource::Ip)
            } else if self.id_authenticated {
                Some(IdentitySource::Secret)
            } else {
                None
            }
        })?;

        Some(ClientIdentityRef {
            ip: self.ip,
            source,
            authenticated: source.is_trusted(),
            name: self.client_name.as_deref(),
            group: self.group.as_deref(),
            mac: self.mac.as_deref(),
        })
    }

    /// Returns the owned policy identity for this context, if one exists.
    #[must_use]
    pub fn identity(&self) -> Option<ClientIdentity> {
        self.identity_ref().map(ClientIdentity::from)
    }

    /// True when this context may match secret-gated policy.
    #[must_use]
    pub fn may_match_secret_rules(&self) -> bool {
        self.identity_ref()
            .is_some_and(|identity| identity.may_match_secret_rules())
    }

    /// True when this context may match `$client` rules or rewrite
    /// `exception_clients`.
    #[must_use]
    pub fn may_match_client_exception(&self) -> bool {
        self.identity_ref()
            .is_some_and(|identity| identity.may_match_client_exception())
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

#[cfg(test)]
mod identity_tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn ip(value: &str) -> IpAddr {
        IpAddr::from_str(value).unwrap()
    }

    fn identity(source: IdentitySource, authenticated: bool) -> ClientIdentity {
        ClientIdentity {
            ip: ip("192.0.2.10"),
            source,
            authenticated,
            name: Some("laptop".to_string()),
            group: Some("kids".to_string()),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
        }
    }

    #[test]
    fn test_identity_trust_table() {
        // D10: only operator network/MAC/verified RouterOS/secret identity may
        // match policy. Raw TLS SNI and DoH path labels are display-only.
        let trusted = [
            IdentitySource::Ip,
            IdentitySource::Cidr,
            IdentitySource::Mac,
            IdentitySource::Secret,
            IdentitySource::RouterOs,
        ];
        for source in trusted {
            let identity = identity(source, true);
            assert!(
                identity.may_match_secret_rules(),
                "{source:?} must be allowed to match secret rules"
            );
            assert!(
                identity.may_match_client_exception(),
                "{source:?} must be allowed to match client exceptions"
            );
        }

        for source in [IdentitySource::TlsSni, IdentitySource::DohPath] {
            let identity = identity(source, false);
            assert!(
                !identity.may_match_secret_rules(),
                "{source:?} must not match secret rules"
            );
            assert!(
                !identity.may_match_client_exception(),
                "{source:?} must not match client exceptions"
            );
        }
    }

    #[test]
    fn test_unauthenticated_identity_never_matches_policy() {
        for source in [
            IdentitySource::Ip,
            IdentitySource::Cidr,
            IdentitySource::Mac,
            IdentitySource::Secret,
            IdentitySource::RouterOs,
            IdentitySource::TlsSni,
            IdentitySource::DohPath,
        ] {
            let identity = identity(source, false);
            assert!(!identity.may_match_secret_rules(), "{source:?}");
            assert!(!identity.may_match_client_exception(), "{source:?}");
        }
    }

    #[test]
    fn test_context_identity_preserves_provenance() {
        let mut ctx = ClientContext::new(ip("192.0.2.10"));
        ctx.client_name = Some("laptop".to_string());
        ctx.group = Some("kids".to_string());
        ctx.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        ctx.identity_source = Some(IdentitySource::Cidr);

        let identity = ctx.identity().expect("a source must produce an identity");
        assert_eq!(identity.source, IdentitySource::Cidr);
        assert!(identity.authenticated);
        assert_eq!(identity.name.as_deref(), Some("laptop"));
        assert_eq!(identity.group.as_deref(), Some("kids"));
        assert_eq!(identity.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert!(ctx.may_match_client_exception());
        assert!(ctx.may_match_secret_rules());
    }

    #[test]
    fn test_untrusted_context_provenance_cannot_match_policy() {
        let mut ctx = ClientContext::with_sni(ip("192.0.2.10"), "laptop.dns.example");
        // Even if a display layer populates a name, the untrusted source wins.
        ctx.client_name = Some("laptop".to_string());
        ctx.group = Some("kids".to_string());

        let identity = ctx.identity().expect("SNI is still recorded for display");
        assert_eq!(identity.source, IdentitySource::TlsSni);
        assert!(!identity.authenticated);
        assert!(!ctx.may_match_client_exception());
        assert!(!ctx.may_match_secret_rules());
    }

    #[test]
    fn test_constructors_record_wire_provenance() {
        let id_ctx = ClientContext::with_id(ip("192.0.2.10"), "alice");
        assert_eq!(id_ctx.identity_source, Some(IdentitySource::DohPath));
        assert!(id_ctx.identity().is_some_and(|i| !i.authenticated));

        let sni_ctx = ClientContext::with_sni(ip("192.0.2.10"), "alice.dns.example");
        assert_eq!(sni_ctx.identity_source, Some(IdentitySource::TlsSni));

        let secret_ctx = ClientContext::with_id(ip("192.0.2.10"), "secret").with_authenticated_id();
        assert_eq!(secret_ctx.identity_source, Some(IdentitySource::Secret));
        assert!(secret_ctx.identity().is_some_and(|i| i.authenticated));
    }

    #[test]
    fn test_legacy_manual_context_still_has_an_identity() {
        // Before WP-1.2, library consumers could populate registry fields
        // directly. Those values are trusted in-process and must keep working.
        let mut ctx = ClientContext::new(ip("192.0.2.10"));
        ctx.client_name = Some("laptop".to_string());
        let identity = ctx
            .identity()
            .expect("registry-populated fields are identity");
        assert!(identity.authenticated);
        assert!(ctx.may_match_client_exception());

        let bare = ClientContext::with_id(ip("192.0.2.10"), "laptop");
        assert!(bare.identity().is_none() || !bare.identity().unwrap().authenticated);
    }

    #[test]
    fn test_identity_source_serde_names_match_as_str() {
        for source in [
            IdentitySource::Ip,
            IdentitySource::Cidr,
            IdentitySource::Mac,
            IdentitySource::TlsSni,
            IdentitySource::DohPath,
            IdentitySource::Secret,
            IdentitySource::RouterOs,
        ] {
            let json = serde_json::to_string(&source).expect("serialize");
            assert_eq!(
                json,
                format!("\"{}\"", source.as_str()),
                "serde name must match IdentitySource::as_str"
            );
            let decoded: IdentitySource = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, source);
        }
    }

    #[test]
    fn test_client_context_serde_defaults_are_backwards_compatible() {
        let json = r#"{"ip":"192.0.2.10","proto":"udp"}"#;
        let ctx: ClientContext = serde_json::from_str(json).expect("legacy context deserializes");
        assert_eq!(ctx.identity_source, None);
        assert!(!ctx.id_authenticated);
        assert!(!ctx.may_match_client_exception());

        let mut new_ctx = ClientContext::new(ip("192.0.2.10"));
        new_ctx.identity_source = Some(IdentitySource::Ip);
        let encoded = serde_json::to_value(&new_ctx).expect("serialize");
        assert_eq!(encoded["identity_source"], "ip");
        let decoded: ClientContext = serde_json::from_value(encoded).expect("roundtrip");
        assert_eq!(decoded.identity_source, Some(IdentitySource::Ip));
    }
}
