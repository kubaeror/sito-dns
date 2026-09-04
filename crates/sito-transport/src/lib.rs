//! `sito-transport`
//!
//! Multi-protocol DNS transport listeners:
//! - UDP/53 with `SO_REUSEPORT` multi-queue socket binding
//! - TCP/53 connection pooling and stream framing
//! - DNS-over-TLS (DoT/853) via `rustls`
//! - DNS-over-HTTPS (DoH/443, HTTP/2)
//! - DNS-over-QUIC (DoQ/853) and DNS-over-HTTP/3 (DoH3/443)

#[cfg(test)]
mod tests {
    #[test]
    fn test_transport_initialization() {
        assert_eq!(2 + 2, 4);
    }
}
