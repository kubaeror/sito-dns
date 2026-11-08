//! Shared test support for sito: a process-wide port broker and async wait helper.
//!
//! Integration tests in different crates cannot all depend on `sito-test`
//! without creating a heavy dependency graph, so the small pieces that tests
//! need live here instead.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Ports currently held by tests in this process.
///
/// The OS can hand a just-released ephemeral port to another test before the
/// previous server's sockets are fully torn down; reserving ports removes that
/// race for every test that uses this broker.
static RESERVED_PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();

fn reserved_ports() -> &'static Mutex<HashSet<u16>> {
    RESERVED_PORTS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn try_reserve_port(port: u16) -> bool {
    reserved_ports().lock().unwrap().insert(port)
}

fn release_reserved_ports(ports: &[u16]) {
    let mut guard = reserved_ports().lock().unwrap();
    for port in ports {
        guard.remove(port);
    }
}

fn no_unreserved_port(protocol: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrInUse,
        format!("no unreserved ephemeral {protocol} port after 20 attempts"),
    )
}

/// A loopback TCP port reserved for the lifetime of a test.
///
/// The port is bound on `127.0.0.1:0` so the OS picks a free ephemeral port.
/// Keep the lease alive for the whole test. When the code under test must bind
/// the port itself, call [`ReservedPort::release_listener`] immediately before
/// starting it; the port stays registered in the process-wide reservation set
/// until the lease is dropped, so other tests cannot choose it.
#[derive(Debug)]
pub struct ReservedPort {
    port: u16,
    listener: Option<TcpListener>,
}

impl ReservedPort {
    /// The reserved port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The reserved loopback socket address.
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port)
    }

    /// The probe listener while it is still held, if any.
    pub fn listener(&self) -> Option<&TcpListener> {
        self.listener.as_ref()
    }

    /// Drops the probe listener so the code under test can bind the port.
    ///
    /// The reservation itself is kept until the lease is dropped.
    pub fn release_listener(&mut self) {
        self.listener = None;
    }
}

impl Drop for ReservedPort {
    fn drop(&mut self) {
        // Close the probe socket before returning the port to the pool so a
        // concurrent reservation cannot pick a port that is still bound.
        drop(self.listener.take());
        release_reserved_ports(std::slice::from_ref(&self.port));
    }
}

/// Reserves an ephemeral loopback TCP port for tests that probe a port and then
/// hand it to code which binds it later (for example HA replication listeners).
///
/// The returned lease keeps the port out of the process-wide reservation pool
/// until it is dropped. See [`ReservedPort`] for the listener lifecycle.
#[must_use = "the lease must be held for the port to stay reserved"]
pub fn reserve_port() -> io::Result<ReservedPort> {
    for _ in 0..20 {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        if try_reserve_port(port) {
            return Ok(ReservedPort {
                port,
                listener: Some(listener),
            });
        }
    }
    Err(no_unreserved_port("TCP"))
}

/// Reserves an ephemeral loopback TCP port for the rest of the test process.
///
/// Unlike [`reserve_port`], this drops the probe listener immediately and keeps
/// the reservation until the process exits. Use it when the code under test
/// binds the port itself and the test does not need to hold a probe socket.
pub fn reserve_port_number() -> io::Result<u16> {
    for _ in 0..20 {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        if try_reserve_port(port) {
            return Ok(port);
        }
    }
    Err(no_unreserved_port("TCP"))
}

/// A loopback UDP port reserved for the lifetime of a test.
///
/// The socket is bound on `127.0.0.1:0` so the OS picks a free ephemeral port.
/// Keep the lease alive for the whole test. When the code under test must bind
/// the port itself, call [`ReservedUdpPort::release_socket`] immediately before
/// starting it; the port stays registered in the process-wide reservation set
/// until the lease is dropped.
#[derive(Debug)]
pub struct ReservedUdpPort {
    port: u16,
    socket: Option<UdpSocket>,
}

impl ReservedUdpPort {
    /// The reserved port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The reserved loopback socket address.
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port)
    }

    /// The probe socket while it is still held, if any.
    pub fn socket(&self) -> Option<&UdpSocket> {
        self.socket.as_ref()
    }

    /// Drops the probe socket so the code under test can bind the port.
    ///
    /// The reservation itself is kept until the lease is dropped.
    pub fn release_socket(&mut self) {
        self.socket = None;
    }
}

impl Drop for ReservedUdpPort {
    fn drop(&mut self) {
        // Close the probe socket before returning the port to the pool so a
        // concurrent reservation cannot pick a port that is still bound.
        drop(self.socket.take());
        release_reserved_ports(std::slice::from_ref(&self.port));
    }
}

/// Reserves an ephemeral loopback UDP port for tests that probe a port and then
/// hand it to code which binds it later (for example DoQ/DoH3 listeners).
///
/// The returned lease keeps the port out of the process-wide reservation pool
/// until it is dropped. See [`ReservedUdpPort`] for the socket lifecycle.
#[must_use = "the lease must be held for the port to stay reserved"]
pub fn reserve_udp_port() -> io::Result<ReservedUdpPort> {
    for _ in 0..20 {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let port = socket.local_addr()?.port();
        if try_reserve_port(port) {
            return Ok(ReservedUdpPort {
                port,
                socket: Some(socket),
            });
        }
    }
    Err(no_unreserved_port("UDP"))
}

/// Reserves an ephemeral loopback UDP port for the rest of the test process.
///
/// Unlike [`reserve_udp_port`], this drops the probe socket immediately and
/// keeps the reservation until the process exits. Use it when the code under
/// test binds the port itself and the test does not need to hold a probe
/// socket.
pub fn reserve_udp_port_number() -> io::Result<u16> {
    for _ in 0..20 {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let port = socket.local_addr()?.port();
        if try_reserve_port(port) {
            return Ok(port);
        }
    }
    Err(no_unreserved_port("UDP"))
}

/// RAII broker that reserves ephemeral ports and releases them if startup
/// fails before the owner takes them.
pub struct PortReservations {
    ports: Vec<u16>,
    armed: bool,
}

impl PortReservations {
    /// Creates an empty reservation broker.
    pub fn new() -> Self {
        Self {
            ports: Vec::new(),
            armed: true,
        }
    }

    /// Reserves a loopback TCP port and returns its still-bound listener.
    pub fn reserve_tcp(&mut self) -> io::Result<(TcpListener, u16)> {
        for _ in 0..20 {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port();
            if try_reserve_port(port) {
                self.ports.push(port);
                return Ok((listener, port));
            }
        }
        Err(no_unreserved_port("TCP"))
    }

    /// Reserves a loopback UDP port and returns its still-bound socket.
    pub fn reserve_udp(&mut self) -> io::Result<(UdpSocket, u16)> {
        for _ in 0..20 {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            let port = socket.local_addr()?.port();
            if try_reserve_port(port) {
                self.ports.push(port);
                return Ok((socket, port));
            }
        }
        Err(no_unreserved_port("UDP"))
    }

    /// Transfers ownership of the reserved ports to the caller.
    pub fn commit(mut self) -> Vec<u16> {
        self.armed = false;
        std::mem::take(&mut self.ports)
    }
}

impl Default for PortReservations {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PortReservations {
    fn drop(&mut self) {
        if self.armed {
            release_reserved_ports(&self.ports);
        }
    }
}

/// Releases a set of ports previously reserved by [`PortReservations`] or a
/// numbered reservation.
pub fn release_ports(ports: &[u16]) {
    release_reserved_ports(ports);
}

/// Polls `condition` every 25 ms until it returns true or `timeout` elapses.
///
/// Prefer this over fixed sleeps so tests wait for the actual event (certificate
/// reload, HA sync, ...) instead of depending on machine speed.
pub async fn wait_until<F, Fut>(timeout: Duration, mut condition: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if condition().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        release_ports, reserve_port, reserve_port_number, reserve_udp_port,
        reserve_udp_port_number, wait_until,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[test]
    fn reserve_port_holds_the_port_until_the_lease_is_dropped() {
        let mut lease = reserve_port().expect("reserve an ephemeral TCP port");
        let port = lease.port();

        assert_ne!(port, 0, "an ephemeral port must be nonzero");
        assert_eq!(lease.addr().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(lease.addr().port(), port);

        let listener = lease.listener().expect("the probe listener must be held");
        assert_eq!(
            listener.local_addr().expect("probe local addr").port(),
            port
        );

        lease.release_listener();
        assert!(lease.listener().is_none(), "listener must be released");
        assert!(
            !super::try_reserve_port(port),
            "a released listener must remain reserved by the lease"
        );

        drop(lease);
        assert!(
            super::try_reserve_port(port),
            "dropping the lease must release the port"
        );
        release_ports(&[port]);
    }

    #[test]
    fn reserve_port_returns_distinct_ports_for_live_leases() {
        let first = reserve_port().expect("first reservation");
        let second = reserve_port().expect("second reservation");
        assert_ne!(first.port(), second.port());
    }

    #[test]
    fn reserve_port_number_returns_distinct_reserved_ports() {
        let first = reserve_port_number().expect("first numbered reservation");
        let second = reserve_port_number().expect("second numbered reservation");
        assert_ne!(first, second);
        release_ports(&[first, second]);
    }

    #[test]
    fn reserve_udp_port_holds_the_port_until_the_lease_is_dropped() {
        let mut lease = reserve_udp_port().expect("reserve an ephemeral UDP port");
        let port = lease.port();

        assert_ne!(port, 0, "an ephemeral port must be nonzero");
        assert_eq!(lease.addr().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(lease.addr().port(), port);

        let socket = lease.socket().expect("the probe socket must be held");
        assert_eq!(socket.local_addr().expect("probe local addr").port(), port);

        lease.release_socket();
        assert!(lease.socket().is_none(), "socket must be released");
        assert!(
            !super::try_reserve_port(port),
            "a released socket must remain reserved by the lease"
        );

        drop(lease);
        assert!(
            super::try_reserve_port(port),
            "dropping the lease must release the port"
        );
        release_ports(&[port]);
    }

    #[test]
    fn reserve_udp_port_number_returns_distinct_reserved_ports() {
        let first = reserve_udp_port_number().expect("first UDP numbered reservation");
        let second = reserve_udp_port_number().expect("second UDP numbered reservation");
        assert_ne!(first, second);
        release_ports(&[first, second]);
    }

    #[tokio::test]
    async fn wait_until_returns_true_once_the_condition_is_met() {
        let flag = Arc::new(AtomicBool::new(false));
        let setter = Arc::clone(&flag);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            setter.store(true, Ordering::SeqCst);
        });

        assert!(
            wait_until(Duration::from_secs(1), || {
                let flag = Arc::clone(&flag);
                async move { flag.load(Ordering::SeqCst) }
            })
            .await
        );
    }
}
