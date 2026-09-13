//! DNS-over-TLS (DoT) upstream implementation with connection pooling.

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
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

/// Idle pooled connections older than this are discarded instead of reused.
const POOL_IDLE_TTL: Duration = Duration::from_secs(30);

struct PooledConnection {
    stream: TlsStream<TcpStream>,
    idle_since: Instant,
}

/// A DNS-over-TLS upstream resolver maintaining a connection pool.
pub struct DotUpstream {
    server_addr: SocketAddr,
    tls_server_name: String,
    query_timeout: Duration,
    pool_size: usize,
    connector: TlsConnector,
    pool: Mutex<Vec<PooledConnection>>,
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

        // Select the ring provider explicitly: the workspace feature graph
        // enables both `ring` and `aws_lc_rs` (reqwest/hyper-rustls), so the
        // ambiguous `ClientConfig::builder()` panics at runtime.
        let mut client_config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| UpstreamError::Tls(format!("unsupported TLS protocol versions: {e}")))?
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

    /// Take a pooled connection that is still within its idle TTL.
    async fn take_pooled_connection(&self) -> Option<TlsStream<TcpStream>> {
        let mut pool = self.pool.lock().await;
        // Discard stale sockets (servers commonly close idle DoT sessions).
        while let Some(pooled) = pool.pop() {
            if pooled.idle_since.elapsed() <= POOL_IDLE_TTL {
                trace!("Reusing idle DoT connection to {}", self.server_addr);
                return Some(pooled.stream);
            }
        }
        None
    }

    async fn release_connection(&self, conn: TlsStream<TcpStream>) {
        let mut pool = self.pool.lock().await;
        if pool.len() < self.pool_size {
            pool.push(PooledConnection {
                stream: conn,
                idle_since: Instant::now(),
            });
        }
    }

    /// Send one query over the given connection, returning it to the pool on success.
    async fn query_on_connection(
        &self,
        mut conn: TlsStream<TcpStream>,
        msg: &Message,
        encoded: &[u8],
    ) -> Result<Message, UpstreamError> {
        let Ok(len) = u16::try_from(encoded.len()) else {
            return Err(UpstreamError::BadResponse(
                "DoT query exceeds the 65535-byte DNS-over-TCP limit".to_string(),
            ));
        };

        let query_res = timeout(self.query_timeout, async {
            conn.write_all(&len.to_be_bytes()).await?;
            conn.write_all(encoded).await?;
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
                crate::upstream::validate_response(msg, &response)?;
                self.release_connection(conn).await;
                Ok(response)
            }
            Ok(Err(e)) => {
                debug!(
                    "DoT connection to {} dropped on I/O error: {}",
                    self.server_addr, e
                );
                Err(classify_io_error(&e))
            }
            Err(_) => {
                debug!("DoT connection to {} timed out", self.server_addr);
                Err(UpstreamError::Timeout)
            }
        }
    }
}

#[async_trait::async_trait]
impl Upstream for DotUpstream {
    async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
        let encoded = encode_message(msg).map_err(|e| UpstreamError::BadResponse(e.to_string()))?;

        // Reuse a pooled connection when one is fresh; a dead pooled socket is
        // dropped and the query is retried once on a brand-new connection.
        if let Some(conn) = self.take_pooled_connection().await {
            match self.query_on_connection(conn, msg, &encoded).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    debug!(
                        "Pooled DoT connection to {} failed ({}); retrying on a fresh connection",
                        self.server_addr, e
                    );
                }
            }
        }

        let conn = self.connect_tls().await?;
        self.query_on_connection(conn, msg, &encoded).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use sito_proto::{MessageType, OpCode, Query, RecordType};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::net::TcpListener;

    fn make_query(id: u16) -> Message {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            sito_proto::Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        query
    }

    /// Minimal DoT server that answers one query per connection and closes the
    /// first connection immediately afterwards, simulating a stale pooled socket.
    async fn spawn_closing_dot_server() -> (SocketAddr, CertificateDer<'static>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.clone());
        let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

        let mut server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.into())
        .unwrap();
        server_cfg.alpn_protocols = vec![b"dot".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&connections);

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let connection_index = counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut len_buf = [0u8; 2];
                    if tls.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];
                    if tls.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    let Ok(query) = decode_message(&buf) else {
                        return;
                    };
                    let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                    resp.queries = query.queries.clone();
                    let Ok(encoded) = encode_message(&resp) else {
                        return;
                    };
                    let _ = tls.write_all(&(encoded.len() as u16).to_be_bytes()).await;
                    let _ = tls.write_all(&encoded).await;
                    let _ = tls.flush().await;
                    if connection_index == 0 {
                        // Close the first connection so it becomes a stale pool entry.
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });

        (addr, cert_der)
    }

    #[test]
    fn test_dot_upstream_new_does_not_panic_on_ambiguous_crypto_providers() {
        // Regression: the workspace enables both rustls `ring` and `aws_lc_rs`
        // (pulled in by reqwest). `ClientConfig::builder()` aborts the process
        // in that configuration; construction must select the ring provider.
        let upstream = DotUpstream::new(
            "127.0.0.1:853".parse().unwrap(),
            "dns.example.com".to_string(),
            Duration::from_secs(2),
            4,
        )
        .expect("DotUpstream::new must succeed with both providers enabled");
        assert_eq!(upstream.server_name(), "dns.example.com");
    }

    #[tokio::test]
    async fn test_dot_retries_once_on_stale_pooled_connection() {
        let (addr, cert_der) = spawn_closing_dot_server().await;

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut client_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client_cfg.alpn_protocols = vec![b"dot".to_vec()];

        let upstream = DotUpstream::with_custom_config(
            addr,
            "localhost".to_string(),
            Duration::from_secs(2),
            2,
            client_cfg,
        );

        // First query populates the pool, then the server closes the socket.
        let first = upstream
            .resolve(&make_query(1))
            .await
            .expect("first DoT query should succeed");
        assert_eq!(first.metadata.id, 1);

        // Second query must recover by retrying on a fresh connection.
        let second = upstream
            .resolve(&make_query(2))
            .await
            .expect("stale pooled connection must be retried on a fresh connection");
        assert_eq!(second.metadata.id, 2);
    }
}
