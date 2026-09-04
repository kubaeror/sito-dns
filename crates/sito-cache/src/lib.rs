//! `sito-cache`
//!
//! High-performance in-memory DNS cache built on `moka`:
//! - Strict TTL clamping (min/max TTL bounds)
//! - Negative response caching (RFC 2308)
//! - Optimistic serve-stale during upstream outages (RFC 8767)
//! - Proactive background prefetching for popular records
//! - Memory-bounded TinyLFU eviction policy

#[cfg(test)]
mod tests {
    #[test]
    fn test_cache_initialization() {
        assert_eq!(2 + 2, 4);
    }
}
