//! `sito-clients`
//!
//! Client identification, registry, and policy routing:
//! - Multi-method identification (IP, CIDR subnet, MAC address, DoH path, DoT SNI)
//! - Client groups with customized filtering profiles
//! - Scheduled access policies and category-based blocking
//! - Router integration (e.g. MikroTik RouterOS DHCP lease synchronization)

pub mod parental;
pub mod safe_search;
pub mod schedule;
pub mod services;

pub use parental::ParentalRegistry;
pub use safe_search::{YouTubeSafeSearchMode, match_safe_search};
pub use schedule::{Schedule, ScheduleError};
pub use services::ServiceRegistry;
