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
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_task: Option<JoinHandle<anyhow::Result<()>>>,
    data_dir: PathBuf,
}

impl TestServerInstance {
    /// Spawns a new server instance with the given configuration modifications.
    pub async fn spawn(mut config: Config) -> Result<Self, anyhow::Error> {
        // Allocate an ephemeral port
        let probe = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let port = probe.local_addr()?.port();
        drop(probe);

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

        // Wait until server is listening and ready
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
        // Brief grace period for UDP listener tasks to enter event loop
        tokio::time::sleep(Duration::from_millis(30)).await;

        Ok(Self {
            port,
            addr,
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
