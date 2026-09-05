//! Test server harness for launching in-process sito instances on ephemeral ports.

use crate::client::TestDnsClient;
use sito::server::run_server_with_shutdown;
use sito_core::config::Config;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// In-process running test instance of the `sito` DNS server.
pub struct TestServerInstance {
    port: u16,
    dot_port: u16,
    doh_port: u16,
    addr: SocketAddr,
    has_tls: bool,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_task: Option<JoinHandle<anyhow::Result<()>>>,
    data_dir: PathBuf,
}

impl TestServerInstance {
    /// Spawns a new server instance with the given configuration modifications.
    pub async fn spawn(mut config: Config) -> Result<Self, anyhow::Error> {
        // Allocate an ephemeral port for standard DNS (UDP/TCP)
        let probe = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let port = probe.local_addr()?.port();
        drop(probe);

        let mut dot_port = config.dns.dot_port;
        let mut doh_port = config.dns.doh_port;
        let mut doq_port = config.dns.doq_port;
        let mut doh3_port = config.dns.doh3_port;
        let has_tls = config.get_tls_config().is_some();

        if has_tls {
            if dot_port == 853 || dot_port == 0 {
                let p = std::net::TcpListener::bind("127.0.0.1:0")?;
                dot_port = p.local_addr()?.port();
                drop(p);
                config.dns.dot_port = dot_port;
            }
            if doh_port == 443 || doh_port == 0 {
                let p = std::net::TcpListener::bind("127.0.0.1:0")?;
                doh_port = p.local_addr()?.port();
                drop(p);
                config.dns.doh_port = doh_port;
            }
            if doq_port == 853 || doq_port == 0 {
                let p = std::net::UdpSocket::bind("127.0.0.1:0")?;
                doq_port = p.local_addr()?.port();
                drop(p);
                config.dns.doq_port = doq_port;
            }
            if doh3_port == 443 || doh3_port == 0 {
                let p = std::net::UdpSocket::bind("127.0.0.1:0")?;
                doh3_port = p.local_addr()?.port();
                drop(p);
                config.dns.doh3_port = doh3_port;
            }
        }

        let temp_dir =
            std::env::temp_dir().join(format!("sito_test_inst_{}_{}", std::process::id(), port));
        tokio::fs::create_dir_all(&temp_dir).await?;

        config.server.data_dir = temp_dir.clone();
        config.dns.bind = vec!["127.0.0.1".parse().unwrap()];
        config.dns.port = port;

        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_task =
            tokio::spawn(async move { run_server_with_shutdown(config, Some(shutdown_rx)).await });

        // Wait until standard server listener is ready
        let mut ready = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                ready = true;
                break;
            }
        }

        if !ready {
            anyhow::bail!("Server failed to bind to {addr} within timeout");
        }

        // Wait until DoT listener is ready if configured
        if has_tls && dot_port > 0 {
            let dot_addr = SocketAddr::new(addr.ip(), dot_port);
            for _ in 0..50 {
                if tokio::net::TcpStream::connect(dot_addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        // Wait until DoH listener is ready if configured
        if has_tls && doh_port > 0 {
            let doh_addr = SocketAddr::new(addr.ip(), doh_port);
            for _ in 0..50 {
                if tokio::net::TcpStream::connect(doh_addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        // Brief grace period for UDP and listener tasks to enter event loop
        tokio::time::sleep(Duration::from_millis(30)).await;

        Ok(Self {
            port,
            dot_port,
            doh_port,
            addr,
            has_tls,
            shutdown_tx: Some(shutdown_tx),
            server_task: Some(server_task),
            data_dir: temp_dir,
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
        let dir = self.data_dir.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::remove_dir_all(&dir).await;
        });
    }
}
