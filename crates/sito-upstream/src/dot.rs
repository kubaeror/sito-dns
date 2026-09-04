//! DNS-over-TLS (DoT) upstream implementation with connection pooling.

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::{debug, trace};

use crate::plain::classify_io_error;
use crate::upstream::Upstream;
use sito_core::error::UpstreamError;
use sito_proto::{Message, decode_message, encode_message};

/// A DNS-over-TLS upstream resolver maintaining a connection pool.
pub struct DotUpstream {
    server_addr: SocketAddr,
    tls_server_name: String,
    query_timeout: Duration,
    pool_size: usize,
    connector: TlsConnector,
    pool: Mutex<Vec<TlsStream<TcpStream>>>,
}

impl DotUpstream {
    /// Create a new DotUpstream with root certificates from webpki-roots.
    pub fn new(
        server_addr: SocketAddr,
        tls_server_name: String,
        query_timeout: Duration,
        pool_size: usize,
    ) -> Result<Self, UpstreamError> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        client_config.alpn_protocols = vec![b"dot".to_vec()];

        let connector = TlsConnector::from(Arc::new(client_config));

        Ok(Self {
            server_addr,
            tls_server_name,
            query_timeout,
            pool_size: pool_size.max(1),
            connector,
            pool: Mutex::new(Vec::new()),
        })
    }

    /// Create a DotUpstream with a custom TLS ClientConfig (useful for testing with mock CA).
    pub fn with_custom_config(
        server_addr: SocketAddr,
        tls_server_name: String,
        query_timeout: Duration,
        pool_size: usize,
        client_config: ClientConfig,
    ) -> Self {
        Self {
            server_addr,
            tls_server_name,
            query_timeout,
            pool_size: pool_size.max(1),
            connector: TlsConnector::from(Arc::new(client_config)),
            pool: Mutex::new(Vec::new()),
        }
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    pub fn server_name(&self) -> &str {
        &self.tls_server_name
    }

    async fn connect_tls(&self) -> Result<TlsStream<TcpStream>, UpstreamError> {
        let tcp_stream =
            match timeout(self.query_timeout, TcpStream::connect(self.server_addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(classify_io_error(&e)),
                Err(_) => return Err(UpstreamError::Timeout),
            };

        let server_name = ServerName::try_from(self.tls_server_name.clone()).map_err(|e| {
            UpstreamError::Tls(format!(
                "invalid TLS server name '{}': {e}",
                self.tls_server_name
            ))
        })?;

        let tls_stream = match timeout(
            self.query_timeout,
            self.connector.connect(server_name, tcp_stream),
        )
        .await
        {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => return Err(UpstreamError::Tls(format!("TLS handshake failed: {e}"))),
            Err(_) => return Err(UpstreamError::Timeout),
        };

        debug!(
            "Established new DoT connection to {} ({})",
            self.server_addr, self.tls_server_name
        );
        Ok(tls_stream)
    }

    async fn acquire_connection(&self) -> Result<TlsStream<TcpStream>, UpstreamError> {
        let mut pool = self.pool.lock().await;
        if let Some(conn) = pool.pop() {
            trace!("Reusing idle DoT connection to {}", self.server_addr);
            return Ok(conn);
        }
        drop(pool);

        self.connect_tls().await
    }

    async fn release_connection(&self, conn: TlsStream<TcpStream>) {
        let mut pool = self.pool.lock().await;
        if pool.len() < self.pool_size {
            pool.push(conn);
        }
    }
}

#[async_trait::async_trait]
impl Upstream for DotUpstream {
    async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
        let encoded = encode_message(msg).map_err(|e| UpstreamError::BadResponse(e.to_string()))?;
        let len = encoded.len() as u16;

        let mut conn = self.acquire_connection().await?;

        let query_res = timeout(self.query_timeout, async {
            conn.write_all(&len.to_be_bytes()).await?;
            conn.write_all(&encoded).await?;
            conn.flush().await?;

            let mut len_buf = [0u8; 2];
            conn.read_exact(&mut len_buf).await?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;

            let mut resp_buf = vec![0u8; resp_len];
            conn.read_exact(&mut resp_buf).await?;
            Ok::<Vec<u8>, std::io::Error>(resp_buf)
        })
        .await;

        match query_res {
            Ok(Ok(bytes)) => {
                let response = decode_message(&bytes)
                    .map_err(|e| UpstreamError::BadResponse(e.to_string()))?;
                // Return connection back to the pool
                self.release_connection(conn).await;
                Ok(response)
            }
            Ok(Err(e)) => {
                debug!(
                    "DoT connection to {} dropped on I/O error: {}",
                    self.server_addr, e
                );
                // Broken connection dropped here
                Err(classify_io_error(&e))
            }
            Err(_) => {
                debug!("DoT connection to {} timed out", self.server_addr);
                Err(UpstreamError::Timeout)
            }
        }
    }
}
