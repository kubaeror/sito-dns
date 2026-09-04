//! `sito-clients`
//!
//! Client identification, registry, and policy routing:
//! - Multi-method identification (IP, CIDR subnet, MAC address, DoH path, DoT SNI)
//! - Client groups with customized filtering profiles
//! - Scheduled access policies and category-based blocking
//! - Router integration (e.g. MikroTik RouterOS DHCP lease synchronization)

pub mod config;
pub mod mac;
pub mod parental;
pub mod policy;
pub mod registry;
pub mod routeros;
pub mod safe_search;
pub mod schedule;
pub mod services;

pub use config::{BlockedServiceConfig, ClientEntryConfig, ClientGroupConfig, ClientsConfig};
pub use mac::{MacResolver, normalize_mac};
pub use parental::ParentalRegistry;
pub use policy::EffectivePolicy;
pub use registry::{ClientRegistry, RouterOsLease, UnidentifiedClient};
pub use routeros::{RouterOsConfig, RouterOsError, fetch_routeros_leases, spawn_routeros_sync};
pub use safe_search::{YouTubeSafeSearchMode, match_safe_search};
pub use schedule::{Schedule, ScheduleError};
pub use services::ServiceRegistry;
