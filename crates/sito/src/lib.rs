//! `sito`
//!
//! High-performance, self-hosted, filtering DNS server.
//!
//! This crate provides the main entry point and runtime orchestration for
//! the sito DNS server daemon, integrating transport listeners, pipeline
//! processing, caching, filtering, statistics, and administrative interfaces.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the compiled package version.
#[must_use]
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }
}
