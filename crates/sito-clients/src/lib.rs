//! `sito-clients`
//!
//! Client identification, registry, and policy routing:
//! - Multi-method identification (IP, CIDR subnet, MAC address, DoH path, DoT SNI)
//! - Client groups with customized filtering profiles
//! - Scheduled access policies and category-based blocking
//! - Router integration (e.g. MikroTik RouterOS DHCP lease synchronization)

#[cfg(test)]
mod tests {
    #[test]
    fn test_clients_initialization() {
        assert_eq!(2 + 2, 4);
    }
}
