//! Broker-backed bind helpers for fixtures.
//!
//! Fixtures that bind their own listeners must participate in the process-wide
//! port broker. These helpers bind an ephemeral loopback socket, then claim its
//! number; if the number is already reserved by another test the socket is
//! closed and a new number is tried. The returned [`PortClaim`] releases the
//! number when the fixture (or test) drops it.

use std::io;

use sito_test_support::{claim_ports, release_ports};
use tokio::net::{TcpListener, UdpSocket};

/// Keeps a claimed ephemeral port reserved until dropped.
#[derive(Debug)]
pub struct PortClaim {
    ports: Vec<u16>,
}

impl PortClaim {
    /// The claimed port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.ports[0]
    }
}

impl Drop for PortClaim {
    fn drop(&mut self) {
        release_ports(&self.ports);
    }
}

/// Binds an ephemeral loopback TCP listener and claims its port.
pub async fn bind_claimed_tcp() -> io::Result<(TcpListener, PortClaim)> {
    for _ in 0..20 {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        if claim_ports(&[port]) {
            return Ok((listener, PortClaim { ports: vec![port] }));
        }
        // Another test reserved this number between bind and claim.
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no unreserved ephemeral TCP port after 20 attempts",
    ))
}

/// Binds an ephemeral loopback UDP socket and claims its port.
pub async fn bind_claimed_udp() -> io::Result<(UdpSocket, PortClaim)> {
    for _ in 0..20 {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let port = socket.local_addr()?.port();
        if claim_ports(&[port]) {
            return Ok((socket, PortClaim { ports: vec![port] }));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no unreserved ephemeral UDP port after 20 attempts",
    ))
}
