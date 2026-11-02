//! DNS-over-TLS (DoT) upstream implementation with connection pooling.

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
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
use sito_proto::{Message, MessageType, OpCode, Query, RecordType, decode_message, encode_message};

/// Idle pooled connections older than this are discarded instead of reused.
const POOL_IDLE_TTL: Duration = Duration::from_secs(30);

/// Pooled connections idle for at least this long are health-pinged.
const PING_IDLE_AFTER: Duration = Duration::from_secs(5);

/// Upper bound on a single pool health ping, regardless of the query timeout.
const PING_TIMEOUT: Duration = Duration::from_secs(2);

/// Rolling identifier for best-effort pool health pings.
static PING_QUERY_ID: AtomicU16 = AtomicU16::new(0);

/// Maximum number of simultaneously outstanding *new* DoT connections. Bounds
/// outbound FD/TLS-handshake amplification when the upstream is slow or the
/// query flood is large; pooled connections are reused without a permit.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

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
    connect_semaphore: Arc<tokio::sync::Semaphore>,
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
            connect_semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
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
            connect_semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
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

    /// Send one already-encoded message over `conn`, returning the decoded
    /// response together with the still-usable connection on success.
    async fn exchange(
        &self,
        mut conn: TlsStream<TcpStream>,
        msg: &Message,
        encoded: &[u8],
        timeout: Duration,
    ) -> Result<(Message, TlsStream<TcpStream>), UpstreamError> {
        let Ok(len) = u16::try_from(encoded.len()) else {
            return Err(UpstreamError::BadResponse(
                "DoT query exceeds the 65535-byte DNS-over-TCP limit".to_string(),
            ));
        };

        let query_res = tokio::time::timeout(timeout, async {
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
                Ok((response, conn))
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

    /// Send one query over the given connection, returning it to the pool on success.
    async fn query_on_connection(
        &self,
        conn: TlsStream<TcpStream>,
        msg: &Message,
        encoded: &[u8],
    ) -> Result<Message, UpstreamError> {
        let (response, conn) = self
            .exchange(conn, msg, encoded, self.query_timeout)
            .await?;
        self.release_connection(conn).await;
        Ok(response)
    }

    /// Pings pooled connections that have been idle for at least
    /// [`PING_IDLE_AFTER`] and drops the ones that no longer answer.
    ///
    /// The pool is drained under one short lock and the pings run concurrently
    /// outside it, so a slow or dead upstream cannot block queries. Failures are
    /// expected (servers commonly close idle DoT sessions) and are logged only:
    /// the health-ping hook never fails a query and never returns an error.
    async fn ping_idle(&self) {
        let drained = {
            let mut pool = self.pool.lock().await;
            let mut fresh = Vec::with_capacity(pool.len());
            let mut idle = Vec::new();
            for pooled in pool.drain(..) {
                if pooled.idle_since.elapsed() >= PING_IDLE_AFTER {
                    idle.push(pooled.stream);
                } else {
                    fresh.push(pooled);
                }
            }
            *pool = fresh;
            idle
        };

        if drained.is_empty() {
            return;
        }

        let id = PING_QUERY_ID.fetch_add(1, Ordering::Relaxed);
        let mut ping = Message::new(id, MessageType::Query, OpCode::Query);
        ping.queries
            .push(Query::query(sito_proto::Name::root(), RecordType::NS));
        let encoded = match encode_message(&ping) {
            Ok(encoded) => encoded,
            Err(e) => {
                debug!("Failed to encode DoT health ping: {}", e);
                for conn in drained {
                    self.release_connection(conn).await;
                }
                return;
            }
        };

        let ping_timeout = self.query_timeout.min(PING_TIMEOUT);
        let results = futures_util::future::join_all(
            drained
                .into_iter()
                .map(|conn| self.exchange(conn, &ping, &encoded, ping_timeout)),
        )
        .await;

        for result in results {
            match result {
                Ok((_, conn)) => self.release_connection(conn).await,
                Err(e) => debug!(
                    "Dropping idle DoT connection to {} after failed health ping: {}",
                    self.server_addr, e
                ),
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

        // Bound newly opened connections; pooled reuse is not limited.
        let permit = match timeout(
            self.query_timeout,
            Arc::clone(&self.connect_semaphore).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                return Err(UpstreamError::BadResponse(
                    "DoT connection limiter closed".to_string(),
                ));
            }
            Err(_) => return Err(UpstreamError::Timeout),
        };
        let conn = self.connect_tls().await?;
        let result = self.query_on_connection(conn, msg, &encoded).await;
        drop(permit);
        result
    }

    /// Periodic maintenance hook: probes idle pooled sockets before a query
    /// would discover a stale one.
    async fn refresh(&self) -> Result<(), UpstreamError> {
        self.ping_idle().await;
        Ok(())
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

    /// Minimal DoT server that answers queries per connection.
    ///
    /// Each accepted connection is counted, as is every query it answers. When
    /// `close_first_connection` is set, the first connection is closed right
    /// after its first answer, simulating a stale pooled socket.
    struct DotTestServer {
        addr: SocketAddr,
        cert: CertificateDer<'static>,
        connections: Arc<AtomicU32>,
        queries: Arc<AtomicU32>,
    }

    async fn spawn_dot_server(close_first_connection: bool) -> DotTestServer {
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
        let queries = Arc::new(AtomicU32::new(0));
        let connection_counter = Arc::clone(&connections);
        let query_counter = Arc::clone(&queries);

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let connection_index = connection_counter.fetch_add(1, Ordering::SeqCst);
                let query_counter = Arc::clone(&query_counter);
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    loop {
                        let mut len_buf = [0u8; 2];
                        if tls.read_exact(&mut len_buf).await.is_err() {
                            break;
                        }
                        let len = u16::from_be_bytes(len_buf) as usize;
                        let mut buf = vec![0u8; len];
                        if tls.read_exact(&mut buf).await.is_err() {
                            break;
                        }
                        let Ok(query) = decode_message(&buf) else {
                            break;
                        };
                        query_counter.fetch_add(1, Ordering::SeqCst);
                        let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                        resp.queries = query.queries.clone();
                        let Ok(encoded) = encode_message(&resp) else {
                            break;
                        };
                        if tls
                            .write_all(&(encoded.len() as u16).to_be_bytes())
                            .await
                            .is_err()
                        {
                            break;
                        }
                        if tls.write_all(&encoded).await.is_err() {
                            break;
                        }
                        if tls.flush().await.is_err() {
                            break;
                        }
                        if connection_index == 0 && close_first_connection {
                            // Close the first connection so it becomes a stale pool entry.
                            let _ = tls.shutdown().await;
                            break;
                        }
                    }
                });
            }
        });

        DotTestServer {
            addr,
            cert: cert_der,
            connections,
            queries,
        }
    }

    fn test_client_config(cert_der: CertificateDer<'static>) -> ClientConfig {
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
        client_cfg
    }

    fn test_upstream(server: &DotTestServer) -> DotUpstream {
        DotUpstream::with_custom_config(
            server.addr,
            "localhost".to_string(),
            Duration::from_secs(2),
            2,
            test_client_config(server.cert.clone()),
        )
    }

    /// Ages every pooled socket beyond [`PING_IDLE_AFTER`].
    async fn age_pool(upstream: &DotUpstream) {
        let mut pool = upstream.pool.lock().await;
        assert!(!pool.is_empty(), "expected a pooled DoT connection");
        for pooled in pool.iter_mut() {
            pooled.idle_since = Instant::now()
                .checked_sub(PING_IDLE_AFTER + Duration::from_secs(1))
                .expect("test instant is older than the ping idle threshold");
        }
    }

    async fn pooled_len(upstream: &DotUpstream) -> usize {
        upstream.pool.lock().await.len()
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
        let server = spawn_dot_server(true).await;
        let upstream = test_upstream(&server);

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
        assert_eq!(server.connections.load(Ordering::SeqCst), 2);
    }

    /// D-13: an idle pooled socket that no longer answers is dropped by the
    /// health ping instead of being handed to a query.
    #[tokio::test]
    async fn test_dot_refresh_discards_dead_idle_connection() {
        let server = spawn_dot_server(true).await;
        let upstream = test_upstream(&server);

        upstream
            .resolve(&make_query(1))
            .await
            .expect("first DoT query should succeed");
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
        age_pool(&upstream).await;

        upstream
            .refresh()
            .await
            .expect("a failed pool ping must not fail the refresh hook");

        assert_eq!(
            pooled_len(&upstream).await,
            0,
            "a dead idle socket must be dropped"
        );
        assert_eq!(
            server.connections.load(Ordering::SeqCst),
            1,
            "a failed ping must not open a replacement connection"
        );

        // The next query still succeeds on a fresh connection.
        upstream
            .resolve(&make_query(2))
            .await
            .expect("a query after a discarded idle socket should succeed");
        assert_eq!(server.connections.load(Ordering::SeqCst), 2);
    }

    /// D-13: a live idle socket is pinged and returned to the pool, so the
    /// next query reuses it without a new TLS handshake.
    #[tokio::test]
    async fn test_dot_refresh_keeps_live_idle_connection() {
        let server = spawn_dot_server(false).await;
        let upstream = test_upstream(&server);

        upstream
            .resolve(&make_query(1))
            .await
            .expect("first DoT query should succeed");
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
        assert_eq!(server.queries.load(Ordering::SeqCst), 1);
        age_pool(&upstream).await;

        upstream
            .refresh()
            .await
            .expect("a successful pool ping must not fail the refresh hook");

        assert_eq!(
            server.queries.load(Ordering::SeqCst),
            2,
            "the idle socket must receive exactly one health ping"
        );
        assert_eq!(
            pooled_len(&upstream).await,
            1,
            "a live pinged socket must return to the pool"
        );

        upstream
            .resolve(&make_query(2))
            .await
            .expect("a query after a successful ping should succeed");
        assert_eq!(
            server.connections.load(Ordering::SeqCst),
            1,
            "the next query must reuse the pinged socket"
        );
        assert_eq!(server.queries.load(Ordering::SeqCst), 3);
    }

    /// D-13: fresh pool entries are left untouched so the maintenance hook does
    /// not add traffic for sockets that are still in active use.
    #[tokio::test]
    async fn test_dot_refresh_skips_recent_connection() {
        let server = spawn_dot_server(false).await;
        let upstream = test_upstream(&server);

        upstream
            .resolve(&make_query(1))
            .await
            .expect("first DoT query should succeed");

        upstream
            .refresh()
            .await
            .expect("a skipped ping must not fail the refresh hook");

        assert_eq!(
            server.queries.load(Ordering::SeqCst),
            1,
            "a recently used socket must not be pinged"
        );
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
        assert_eq!(pooled_len(&upstream).await, 1);
    }
}
