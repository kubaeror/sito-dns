//! Test server harness for launching in-process sito instances on ephemeral ports.

use crate::client::TestDnsClient;
use sito::server::run_server_with_shutdown;
use sito_core::config::Config;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Optional overrides for [`TestServerInstance::spawn_with_options`].
#[derive(Clone, Default)]
pub struct HarnessOptions {
    /// DNS bind addresses. Defaults to loopback IPv4.
    pub dns_bind: Option<Vec<IpAddr>>,
}

/// In-process running test instance of the `sito` DNS server.
pub struct TestServerInstance {
    port: u16,
    dot_port: u16,
    doh_port: u16,
    web_port: u16,
    addr: SocketAddr,
    has_tls: bool,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_task: Option<JoinHandle<anyhow::Result<()>>>,
    data_dir: PathBuf,
    /// Ports reserved for this instance; released when it is dropped.
    reserved_ports: Vec<u16>,
}

/// Serializes probe-then-bind across parallel tests in one binary: without it,
/// two tests can probe the same free port before either server binds it. The
/// lock is held from port probing until the instance reports ready, then
/// released so tests run concurrently.
static SPAWN_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

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

/// Ports currently held by live test instances in this binary.
///
/// The OS can hand a just-released ephemeral port to another test before the
/// previous server's sockets are fully torn down; reserving ports for the
/// lifetime of each instance (plus the spawn lock) removes that race.
static RESERVED_PORTS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
    std::sync::OnceLock::new();

fn try_reserve_port(port: u16) -> bool {
    RESERVED_PORTS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
        .lock()
        .unwrap()
        .insert(port)
}

/// A loopback TCP port reserved for the lifetime of a test.
///
/// The port is bound on `127.0.0.1:0` so the OS picks a free ephemeral port.
/// Keep the lease alive for the whole test. When the code under test must bind
/// the port itself, call [`ReservedPort::release_listener`] immediately before
/// starting it; the port stays registered in the process-wide reservation set
/// until the lease is dropped, so other harness instances cannot choose it.
#[derive(Debug)]
pub struct ReservedPort {
    port: u16,
    listener: Option<std::net::TcpListener>,
}

impl ReservedPort {
    /// The reserved port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The reserved loopback socket address.
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), self.port)
    }

    /// The probe listener while it is still held, if any.
    pub fn listener(&self) -> Option<&std::net::TcpListener> {
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
/// The returned lease keeps the port out of the harness-wide reservation pool
/// until it is dropped. See [`ReservedPort`] for the listener lifecycle.
#[must_use = "the lease must be held for the port to stay reserved"]
pub fn reserve_port() -> std::io::Result<ReservedPort> {
    for _ in 0..20 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        if try_reserve_port(port) {
            return Ok(ReservedPort {
                port,
                listener: Some(listener),
            });
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        "no unreserved ephemeral TCP port after 20 attempts",
    ))
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
    socket: Option<std::net::UdpSocket>,
}

impl ReservedUdpPort {
    /// The reserved port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The reserved loopback socket address.
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), self.port)
    }

    /// The probe socket while it is still held, if any.
    pub fn socket(&self) -> Option<&std::net::UdpSocket> {
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
/// The returned lease keeps the port out of the harness-wide reservation pool
/// until it is dropped. See [`ReservedUdpPort`] for the socket lifecycle.
#[must_use = "the lease must be held for the port to stay reserved"]
pub fn reserve_udp_port() -> std::io::Result<ReservedUdpPort> {
    for _ in 0..20 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let port = socket.local_addr()?.port();
        if try_reserve_port(port) {
            return Ok(ReservedUdpPort {
                port,
                socket: Some(socket),
            });
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        "no unreserved ephemeral UDP port after 20 attempts",
    ))
}

fn release_reserved_ports(ports: &[u16]) {
    if let Some(reserved) = RESERVED_PORTS.get() {
        let mut guard = reserved.lock().unwrap();
        for port in ports {
            guard.remove(port);
        }
    }
}

/// RAII broker that reserves ephemeral ports and releases them if startup
/// fails before the instance takes ownership.
struct PortReservations {
    ports: Vec<u16>,
    armed: bool,
}

impl PortReservations {
    fn new() -> Self {
        Self {
            ports: Vec::new(),
            armed: true,
        }
    }

    fn reserve_tcp(&mut self) -> std::io::Result<(std::net::TcpListener, u16)> {
        for _ in 0..20 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port();
            if try_reserve_port(port) {
                self.ports.push(port);
                return Ok((listener, port));
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "no unreserved ephemeral TCP port after 20 attempts",
        ))
    }

    fn reserve_udp(&mut self) -> std::io::Result<(std::net::UdpSocket, u16)> {
        for _ in 0..20 {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
            let port = socket.local_addr()?.port();
            if try_reserve_port(port) {
                self.ports.push(port);
                return Ok((socket, port));
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "no unreserved ephemeral UDP port after 20 attempts",
        ))
    }

    /// Transfers ownership of the reserved ports to the caller.
    fn commit(mut self) -> Vec<u16> {
        self.armed = false;
        std::mem::take(&mut self.ports)
    }
}

impl Drop for PortReservations {
    fn drop(&mut self) {
        if self.armed {
            release_reserved_ports(&self.ports);
        }
    }
}

impl TestServerInstance {
    /// Spawns a new server instance with the given configuration modifications,
    /// retrying up to 5 times if an ephemeral port collision occurs during parallel test execution.
    pub async fn spawn(config: Config) -> Result<Self, anyhow::Error> {
        Self::spawn_with_options(config, HarnessOptions::default()).await
    }

    /// Spawns a server with explicit harness overrides (e.g. a dual-stack bind
    /// list instead of the default loopback-only test bind).
    pub async fn spawn_with_options(
        config: Config,
        options: HarnessOptions,
    ) -> Result<Self, anyhow::Error> {
        let spawn_lock = SPAWN_LOCK.get_or_init(|| tokio::sync::Mutex::new(()));
        let _guard = spawn_lock.lock().await;

        let mut last_err = anyhow::anyhow!("Failed to spawn test server instance");
        for attempt in 0..5 {
            match Self::try_spawn(config.clone(), options.clone()).await {
                Ok(instance) => return Ok(instance),
                Err(e) => {
                    tracing::warn!(
                        "Test server spawn attempt {} failed: {e}; retrying",
                        attempt + 1
                    );
                    last_err = e;
                    tokio::time::sleep(Duration::from_millis(100 * (attempt + 1))).await;
                }
            }
        }
        Err(last_err)
    }

    async fn try_spawn(mut config: Config, options: HarnessOptions) -> Result<Self, anyhow::Error> {
        // Allocate ephemeral ports through the broker so no two instances in
        // this binary can pick the same port.
        let mut reservations = PortReservations::new();
        let (probe_dns, port) = reservations.reserve_tcp()?;

        let mut dot_port = config.dns.dot_port;
        let mut doh_port = config.dns.doh_port;
        let mut doq_port = config.dns.doq_port;
        let mut doh3_port = config.dns.doh3_port;
        let has_tls = config.get_tls_config().is_some();

        let mut probe_dot = None;
        let mut probe_doh = None;
        let mut probe_doq = None;
        let mut probe_doh3 = None;

        if has_tls {
            if dot_port == 853 || dot_port == 0 {
                let (p, reserved) = reservations.reserve_tcp()?;
                dot_port = reserved;
                config.dns.dot_port = dot_port;
                probe_dot = Some(p);
            }
            if doh_port == 443 || doh_port == 0 {
                let (p, reserved) = reservations.reserve_tcp()?;
                doh_port = reserved;
                config.dns.doh_port = doh_port;
                probe_doh = Some(p);
            }
            if doq_port == 853 || doq_port == 0 {
                let (p, reserved) = reservations.reserve_udp()?;
                doq_port = reserved;
                config.dns.doq_port = doq_port;
                probe_doq = Some(p);
            }
            if doh3_port == 443 || doh3_port == 0 {
                let (p, reserved) = reservations.reserve_udp()?;
                doh3_port = reserved;
                config.dns.doh3_port = doh3_port;
                probe_doh3 = Some(p);
            }
        }

        let mut probe_web = None;
        let mut web_port = config.get_web_config().port;
        if web_port == 8080 || web_port == 0 {
            let (p, reserved) = reservations.reserve_tcp()?;
            web_port = reserved;
            let mut web_cfg = config.get_web_config();
            web_cfg.bind = "127.0.0.1".parse().unwrap();
            web_cfg.port = web_port;
            config.set_web_config(web_cfg);
            probe_web = Some(p);
        }

        // Release all probes simultaneously right before starting the server
        drop(probe_dns);
        drop(probe_dot);
        drop(probe_doh);
        drop(probe_doq);
        drop(probe_doh3);
        drop(probe_web);

        // Tests that need files inside the server data directory (e.g.
        // file:// blocklists) may set it before spawning; otherwise use an
        // isolated per-instance temporary directory.
        let temp_dir = if config.server.data_dir == Path::new("/var/lib/sito") {
            let dir = std::env::temp_dir().join(format!(
                "sito_test_inst_{}_{}_{}",
                std::process::id(),
                port,
                rand::random::<u32>()
            ));
            tokio::fs::create_dir_all(&dir).await?;
            config.server.data_dir = dir.clone();
            dir
        } else {
            tokio::fs::create_dir_all(&config.server.data_dir).await?;
            config.server.data_dir.clone()
        };
        config.dns.bind = options
            .dns_bind
            .unwrap_or_else(|| vec!["127.0.0.1".parse().expect("valid loopback address")]);
        config.dns.port = port;

        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let mut server_task =
            tokio::spawn(async move { run_server_with_shutdown(config, Some(shutdown_rx)).await });

        // Wait until standard server listener is ready (up to 3s for busy CI runners)
        let mut ready = false;
        for _ in 0..150 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if server_task.is_finished() {
                break;
            }
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                ready = true;
                break;
            }
        }

        if server_task.is_finished() {
            (&mut server_task).await??;
            let _ = tokio::fs::remove_dir_all(&temp_dir).await;
            anyhow::bail!("Server task exited unexpectedly during startup");
        }

        if !ready {
            let _ = shutdown_tx.send(());
            let _ = server_task.await;
            let _ = tokio::fs::remove_dir_all(&temp_dir).await;
            anyhow::bail!("Server failed to bind to {addr} within timeout");
        }

        // Wait until DoT listener is ready if configured
        if has_tls && dot_port > 0 {
            let dot_addr = SocketAddr::new(addr.ip(), dot_port);
            let mut dot_ready = false;
            for _ in 0..150 {
                if server_task.is_finished() {
                    break;
                }
                if tokio::net::TcpStream::connect(dot_addr).await.is_ok() {
                    dot_ready = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if server_task.is_finished() {
                (&mut server_task).await??;
                let _ = tokio::fs::remove_dir_all(&temp_dir).await;
                anyhow::bail!("Server task exited unexpectedly during DoT startup");
            }
            if !dot_ready {
                let _ = shutdown_tx.send(());
                let _ = server_task.await;
                let _ = tokio::fs::remove_dir_all(&temp_dir).await;
                anyhow::bail!("DoT listener failed to bind to {dot_addr} within timeout");
            }
        }

        // Wait until DoH listener is ready if configured
        if has_tls && doh_port > 0 {
            let doh_addr = SocketAddr::new(addr.ip(), doh_port);
            let mut doh_ready = false;
            for _ in 0..150 {
                if server_task.is_finished() {
                    break;
                }
                if tokio::net::TcpStream::connect(doh_addr).await.is_ok() {
                    doh_ready = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if server_task.is_finished() {
                (&mut server_task).await??;
                let _ = tokio::fs::remove_dir_all(&temp_dir).await;
                anyhow::bail!("Server task exited unexpectedly during DoH startup");
            }
            if !doh_ready {
                let _ = shutdown_tx.send(());
                let _ = server_task.await;
                let _ = tokio::fs::remove_dir_all(&temp_dir).await;
                anyhow::bail!("DoH listener failed to bind to {doh_addr} within timeout");
            }
        }

        // Brief grace period for UDP and listener tasks to enter event loop
        tokio::time::sleep(Duration::from_millis(50)).await;
        if server_task.is_finished() {
            (&mut server_task).await??;
            let _ = tokio::fs::remove_dir_all(&temp_dir).await;
            anyhow::bail!("Server task exited unexpectedly during initialization grace period");
        }

        Ok(Self {
            port,
            dot_port,
            doh_port,
            web_port,
            addr,
            has_tls,
            shutdown_tx: Some(shutdown_tx),
            server_task: Some(server_task),
            data_dir: temp_dir,
            reserved_ports: reservations.commit(),
        })
    }

    /// Bound address of the test server.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Bound port of the test server.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Bound port of the DoT listener.
    pub fn dot_port(&self) -> u16 {
        self.dot_port
    }

    /// Bound port of the DoH listener.
    pub fn doh_port(&self) -> u16 {
        self.doh_port
    }

    /// Bound port of the web admin interface.
    pub fn web_port(&self) -> u16 {
        self.web_port
    }

    /// Bound address of the DoT listener.
    pub fn dot_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr.ip(), self.dot_port)
    }

    /// Bound address of the DoH listener.
    pub fn doh_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr.ip(), self.doh_port)
    }

    /// Construct full DoH URL for a path (e.g. `/dns-query` or `/dns-query/client-id`).
    pub fn doh_url(&self, path: &str) -> String {
        let clean_path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let scheme = if self.has_tls { "https" } else { "http" };
        format!("{scheme}://127.0.0.1:{}{clean_path}", self.doh_port)
    }

    /// Returns a client pointing at this server instance.
    pub fn client(&self) -> TestDnsClient {
        TestDnsClient::new(self.addr)
    }

    /// Gracefully shuts down the test server instance.
    pub async fn shutdown(mut self) -> Result<(), anyhow::Error> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        if let Some(handle) = self.server_task.take() {
            let res = tokio::time::timeout(Duration::from_secs(6), handle).await;
            match res {
                Ok(join_res) => {
                    join_res??;
                }
                Err(_) => {
                    anyhow::bail!("Server instance shutdown timed out after 6 seconds");
                }
            }
        }

        let _ = tokio::fs::remove_dir_all(&self.data_dir).await;
        Ok(())
    }
}

/// Generates a valid self-signed certificate and private key in PEM format using rcgen.
pub fn generate_test_cert(san_domains: &[&str]) -> (String, String) {
    let key_pair = rcgen::KeyPair::generate().expect("key pair generation");
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "sito-test.local");
    params.distinguished_name = dn;
    for san in san_domains {
        params.subject_alt_names.push(rcgen::SanType::DnsName(
            (*san).to_string().try_into().unwrap(),
        ));
    }

    let cert = params.self_signed(&key_pair).expect("self signed cert");
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem, key_pem)
}

/// Generates an expired self-signed certificate and private key in PEM format using rcgen.
pub fn generate_expired_test_cert(san_domains: &[&str]) -> (String, String) {
    let key_pair = rcgen::KeyPair::generate().expect("key pair generation");
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "sito-expired.local");
    params.distinguished_name = dn;
    for san in san_domains {
        params.subject_alt_names.push(rcgen::SanType::DnsName(
            (*san).to_string().try_into().unwrap(),
        ));
    }
    // Set validity in the past (year 2020)
    params.not_before = time::OffsetDateTime::from_unix_timestamp(1_577_836_800).unwrap(); // 2020-01-01
    params.not_after = time::OffsetDateTime::from_unix_timestamp(1_577_923_200).unwrap(); // 2020-01-02

    let cert = params.self_signed(&key_pair).expect("self signed cert");
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem, key_pem)
}

impl Drop for TestServerInstance {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        release_reserved_ports(&self.reserved_ports);
        let dir = self.data_dir.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::remove_dir_all(&dir).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{release_reserved_ports, reserve_port, reserve_udp_port, try_reserve_port};
    use std::net::{IpAddr, Ipv4Addr};

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

        // The listener is released so the code under test can bind the port,
        // but the port stays reserved until the lease itself is dropped.
        lease.release_listener();
        assert!(lease.listener().is_none(), "listener must be released");
        assert!(
            !try_reserve_port(port),
            "a released listener must remain reserved by the lease"
        );

        drop(lease);
        assert!(
            try_reserve_port(port),
            "dropping the lease must release the port"
        );
        release_reserved_ports(&[port]);
    }

    #[test]
    fn reserve_port_returns_distinct_ports_for_live_leases() {
        let first = reserve_port().expect("first reservation");
        let second = reserve_port().expect("second reservation");
        assert_ne!(first.port(), second.port());
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
            !try_reserve_port(port),
            "a released socket must remain reserved by the lease"
        );

        drop(lease);
        assert!(
            try_reserve_port(port),
            "dropping the lease must release the port"
        );
        release_reserved_ports(&[port]);
    }
}
