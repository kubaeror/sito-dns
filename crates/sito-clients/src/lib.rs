//! `sito-clients`
//!
//! Client identification, registry, and policy routing:
//! - Multi-method identification (IP, CIDR subnet, MAC address, DoH path, DoT SNI)
//! - Client groups with customized filtering profiles
//! - Scheduled access policies and category-based blocking
//! - Router configuration data (`RouterOsConfig`); the optional RouterOS DHCP
//!   snapshot sync lives in the separate `sito-routeros` crate.

pub mod acl;
pub mod bundled;
pub mod catalog;
pub mod config;
pub mod mac;
pub mod parental;
pub mod policy;
pub mod registry;
pub mod routeros;
pub mod runtime_lists;
pub mod safe_search;
pub mod schedule;
pub mod services;
pub mod timezone;

pub use acl::{
    AclAction, AclConfigError, AclDecision, AclFamily, AclIndex, AclPrefix, AclReason,
    MAX_ACL_PREFIXES, canonical_source,
};
pub use bundled::{BundledList, BundledListError, BundledManifest};
pub use catalog::{
    CATALOG_JSON, CATALOG_LICENSE, CATALOG_VERSION, Catalog, CatalogCategory, CatalogError,
    CatalogFilter, CatalogService, CatalogSource, FILTERS_SOURCE_URL, SERVICES_SOURCE_URL,
};
pub use config::{
    AclDefaultPolicy, AclDenyResponse, BlockedServiceConfig, ClientAclConfig, ClientEntryConfig,
    ClientGroupConfig, ClientsConfig, IntegrationsConfig,
};
pub use mac::{MacResolver, normalize_mac, normalize_mac_id};
pub use parental::ParentalRegistry;
pub use policy::EffectivePolicy;
pub use registry::{
    ClientRegistry, MAX_UNIDENTIFIED_CLIENTS, RouterOsLease, UNIDENTIFIED_CLIENT_TTL_HOURS,
    UnidentifiedClient,
};
pub use routeros::RouterOsConfig;
pub use runtime_lists::{ListCategoriesConfig, ListSourceConfig, RuntimeListStatus, RuntimeLists};
pub use safe_search::{YouTubeSafeSearchMode, match_safe_search};
pub use schedule::{Schedule, ScheduleError};
pub use services::ServiceRegistry;
pub use timezone::{ClientTimeZone, TimeZoneError};
