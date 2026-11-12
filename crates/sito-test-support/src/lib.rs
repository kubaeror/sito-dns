//! Shared test support for sito: a process-wide port broker and async wait helper.
//!
//! Integration tests in different crates cannot all depend on `sito-test`
//! without creating a heavy dependency graph, so the small pieces that tests
//! need live here instead.

pub mod clock;
pub mod wait;

pub use clock::{Clock, ManualClock, SystemClock};
pub use wait::{WAIT_POLL_INTERVAL, WaitTimeout, wait_for, wait_until};

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::{Mutex, OnceLock};

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

/// Binds an ephemeral loopback TCP probe socket and reserves its port.
///
/// Shared by the standalone leases and [`PortReservations`] so the bind/probe
/// retry policy cannot drift between them. The caller owns the returned
/// listener and must drop it before the code under test binds the port.
fn bind_reserved_tcp() -> io::Result<(TcpListener, u16)> {
    for _ in 0..20 {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        if try_reserve_port(port) {
            return Ok((listener, port));
        }
    }
    Err(no_unreserved_port("TCP"))
}

/// Binds an ephemeral loopback UDP probe socket and reserves its port.
fn bind_reserved_udp() -> io::Result<(UdpSocket, u16)> {
    for _ in 0..20 {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let port = socket.local_addr()?.port();
        if try_reserve_port(port) {
            return Ok((socket, port));
        }
    }
    Err(no_unreserved_port("UDP"))
}

/// Binds an ephemeral loopback TCP+UDP pair on the same number and reserves it.
///
/// DNS listens on UDP and TCP with one configured port, so reserving only one
/// protocol leaves the other open to another test/process choosing the same
/// number. The pair is reserved atomically or the attempt is retried.
fn bind_reserved_tcp_udp() -> io::Result<(TcpListener, UdpSocket, u16)> {
    for _ in 0..20 {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        if !try_reserve_port(port) {
            continue;
        }
        match UdpSocket::bind((Ipv4Addr::LOCALHOST, port)) {
            Ok(socket) => return Ok((listener, socket, port)),
            Err(_) => {
                // Keep the TCP probe until the loop retries; drop the failed
                // port reservation so another test can use it.
                release_reserved_ports(&[port]);
            }
        }
    }
    Err(no_unreserved_port("TCP+UDP"))
}

/// Claims an already-bound port in the process-wide broker.
///
/// Use this for fixtures that must bind the socket themselves (for example a
/// mock DNS upstream that binds UDP and TCP on the same number). Returns false
/// when any port is already reserved; the caller must close its sockets and
/// retry with a different ephemeral port.
pub fn claim_ports(ports: &[u16]) -> bool {
    let mut guard = reserved_ports().lock().unwrap();
    if ports.iter().any(|port| guard.contains(port)) {
        return false;
    }
    for port in ports {
        guard.insert(*port);
    }
    true
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
    let (listener, port) = bind_reserved_tcp()?;
    Ok(ReservedPort {
        port,
        listener: Some(listener),
    })
}

/// Reserves an ephemeral loopback TCP port for the rest of the test process.
///
/// Unlike [`reserve_port`], this drops the probe listener immediately and keeps
/// the reservation until the process exits. Use it when the code under test
/// binds the port itself and the test does not need to hold a probe socket.
pub fn reserve_port_number() -> io::Result<u16> {
    let (listener, port) = bind_reserved_tcp()?;
    drop(listener);
    Ok(port)
}

/// A loopback TCP+UDP pair reserved for the lifetime of a test.
///
/// DNS listeners bind one configured port for both protocols. Keep this lease
/// alive for the whole test; call [`ReservedTcpUdpPort::release_sockets`]
/// immediately before the component under test binds.
#[derive(Debug)]
pub struct ReservedTcpUdpPort {
    port: u16,
    listener: Option<TcpListener>,
    socket: Option<UdpSocket>,
}

impl ReservedTcpUdpPort {
    /// The reserved port (shared by TCP and UDP).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The reserved loopback socket address.
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port)
    }

    /// Drops both probe sockets so the code under test can bind the port.
    ///
    /// The reservation itself is kept until the lease is dropped.
    pub fn release_sockets(&mut self) {
        self.listener = None;
        self.socket = None;
    }
}

impl Drop for ReservedTcpUdpPort {
    fn drop(&mut self) {
        drop(self.listener.take());
        drop(self.socket.take());
        release_reserved_ports(std::slice::from_ref(&self.port));
    }
}

/// Reserves an ephemeral loopback number for both TCP and UDP.
#[must_use = "the lease must be held for the port to stay reserved"]
pub fn reserve_tcp_udp_port() -> io::Result<ReservedTcpUdpPort> {
    let (listener, socket, port) = bind_reserved_tcp_udp()?;
    Ok(ReservedTcpUdpPort {
        port,
        listener: Some(listener),
        socket: Some(socket),
    })
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
    let (socket, port) = bind_reserved_udp()?;
    Ok(ReservedUdpPort {
        port,
        socket: Some(socket),
    })
}

/// Reserves an ephemeral loopback UDP port for the rest of the test process.
///
/// Unlike [`reserve_udp_port`], this drops the probe socket immediately and
/// keeps the reservation until the process exits. Use it when the code under
/// test binds the port itself and the test does not need to hold a probe
/// socket.
pub fn reserve_udp_port_number() -> io::Result<u16> {
    let (socket, port) = bind_reserved_udp()?;
    drop(socket);
    Ok(port)
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
        let (listener, port) = bind_reserved_tcp()?;
        self.ports.push(port);
        Ok((listener, port))
    }

    /// Reserves a loopback UDP port and returns its still-bound socket.
    pub fn reserve_udp(&mut self) -> io::Result<(UdpSocket, u16)> {
        let (socket, port) = bind_reserved_udp()?;
        self.ports.push(port);
        Ok((socket, port))
    }

    /// Reserves one ephemeral loopback number for both TCP and UDP.
    ///
    /// Returns the still-bound probe listener and socket. DNS listeners use one
    /// configured port for both protocols, so reserving a single protocol is
    /// not enough to keep another test from claiming the other.
    pub fn reserve_tcp_udp(&mut self) -> io::Result<(TcpListener, UdpSocket, u16)> {
        let (listener, socket, port) = bind_reserved_tcp_udp()?;
        self.ports.push(port);
        Ok((listener, socket, port))
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

    /// Serializes the port-broker tests: after a lease is dropped another
    /// parallel test could otherwise reserve the same OS-assigned ephemeral
    /// port between the drop and the `try_reserve_port` assertion.
    static PORT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn port_test_guard() -> std::sync::MutexGuard<'static, ()> {
        PORT_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn reserve_port_holds_the_port_until_the_lease_is_dropped() {
        let _guard = port_test_guard();
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
        let _guard = port_test_guard();
        let first = reserve_port().expect("first reservation");
        let second = reserve_port().expect("second reservation");
        assert_ne!(first.port(), second.port());
    }

    #[test]
    fn reserve_port_number_returns_distinct_reserved_ports() {
        let _guard = port_test_guard();
        let first = reserve_port_number().expect("first numbered reservation");
        let second = reserve_port_number().expect("second numbered reservation");
        assert_ne!(first, second);
        release_ports(&[first, second]);
    }

    #[test]
    fn reserve_udp_port_holds_the_port_until_the_lease_is_dropped() {
        let _guard = port_test_guard();
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
        let _guard = port_test_guard();
        let first = reserve_udp_port_number().expect("first UDP numbered reservation");
        let second = reserve_udp_port_number().expect("second UDP numbered reservation");
        assert_ne!(first, second);
        release_ports(&[first, second]);
    }

    /// Deferred D4b: the reservation broker releases every port it holds when
    /// startup fails before `commit`, and `commit` transfers them to the owner.
    #[test]
    fn port_reservations_release_on_drop_and_commit_transfers_ownership() {
        let _guard = port_test_guard();

        let mut abandoned = super::PortReservations::new();
        let (listener, tcp_port) = abandoned.reserve_tcp().expect("reserve TCP");
        drop(listener);
        let (socket, udp_port) = abandoned.reserve_udp().expect("reserve UDP");
        drop(socket);
        drop(abandoned);
        assert!(
            super::try_reserve_port(tcp_port),
            "dropping an uncommitted broker must release its TCP port"
        );
        assert!(
            super::try_reserve_port(udp_port),
            "dropping an uncommitted broker must release its UDP port"
        );
        release_ports(&[tcp_port, udp_port]);

        let mut broker = super::PortReservations::new();
        let (listener, committed_tcp) = broker.reserve_tcp().expect("reserve TCP");
        let (socket, committed_udp) = broker.reserve_udp().expect("reserve UDP");
        drop((listener, socket));
        let committed = broker.commit();
        assert_eq!(committed, vec![committed_tcp, committed_udp]);
        assert!(
            !super::try_reserve_port(committed_tcp),
            "commit must keep the ports reserved for the caller"
        );
        assert!(!super::try_reserve_port(committed_udp));
        release_ports(&committed);
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
