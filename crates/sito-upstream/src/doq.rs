//! DNS-over-QUIC (DoQ, RFC 9250) upstream transport.
//!
//! Each query uses a dedicated bidirectional QUIC stream, the DNS message ID is
//! forced to 0 on the wire, and responses are validated against the outgoing
//! query. Bootstrap resolution is performed by the caller (the manager), so the
//! endpoint receives an explicit peer address while retaining the hostname for
//! TLS server-name validation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::trace;

use crate::upstream::{Upstream, validate_response};
use sito_core::error::UpstreamError;
use sito_proto::{Message, decode_message, encode_message};

/// Maximum accepted DNS message size over a DoQ stream.
const MAX_DOQ_MESSAGE_BYTES: usize = 65_535;

/// RFC 9250 section 4.2: DoQ connections negotiate the `doq` ALPN. Reject a
/// completed QUIC handshake that selected anything else (or nothing).
fn ensure_doq_alpn(negotiated: Option<&[u8]>, remote: SocketAddr) -> Result<(), UpstreamError> {
    if negotiated == Some(&b"doq"[..]) {
        return Ok(());
    }
    Err(UpstreamError::Tls(format!(
        "DoQ server {remote} did not negotiate ALPN 'doq' (got {})",
        negotiated.map_or_else(
            || "none".to_string(),
            |protocol| format!("'{}'", String::from_utf8_lossy(protocol))
        )
    )))
}

/// A DNS-over-QUIC upstream (RFC 9250).
pub struct QuicUpstream {
    endpoint: quinn::Endpoint,
    server_name: String,
    remote_addr: SocketAddr,
    timeout: Duration,
    connection: Mutex<Option<quinn::Connection>>,
}

impl std::fmt::Debug for QuicUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicUpstream")
            .field("server_name", &self.server_name)
            .field("remote_addr", &self.remote_addr)
            .finish_non_exhaustive()
    }
}

impl QuicUpstream {
    /// Creates a DoQ upstream with system root certificates.
    pub fn new(
        host: &str,
        remote_addr: SocketAddr,
        timeout: Duration,
    ) -> Result<Self, UpstreamError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut rustls_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| UpstreamError::Tls(format!("failed to configure TLS versions: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        rustls_cfg.alpn_protocols = vec![b"doq".to_vec()];

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
            .map_err(|e| UpstreamError::Tls(format!("invalid QUIC client TLS config: {e}")))?;
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));

        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(timeout)
                .map_err(|e| UpstreamError::Io(format!("invalid idle timeout: {e}")))?,
        ));
        client_cfg.transport_config(Arc::new(transport));

        Self::with_client_config(host, remote_addr, timeout, client_cfg)
    }

    /// Creates a DoQ upstream from an explicit QUIC client configuration (tests
    /// and custom certificate stores).
    pub fn with_client_config(
        host: &str,
        remote_addr: SocketAddr,
        timeout: Duration,
        client_config: quinn::ClientConfig,
    ) -> Result<Self, UpstreamError> {
        let bind_addr: SocketAddr = if remote_addr.is_ipv6() {
            "[::]:0".parse().expect("valid bind addr")
        } else {
            "0.0.0.0:0".parse().expect("valid bind addr")
        };
        let mut endpoint = quinn::Endpoint::client(bind_addr)
            .map_err(|e| UpstreamError::Io(format!("failed to create QUIC endpoint: {e}")))?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            server_name: host.to_string(),
            remote_addr,
            timeout,
            connection: Mutex::new(None),
        })
    }

    async fn get_connection(&self) -> Result<quinn::Connection, UpstreamError> {
        let mut guard = self.connection.lock().await;
        if let Some(conn) = guard.as_ref()
            && conn.close_reason().is_none()
        {
            return Ok(conn.clone());
        }

        let connecting = self
            .endpoint
            .connect(self.remote_addr, &self.server_name)
            .map_err(|e| UpstreamError::Io(format!("QUIC connect setup failed: {e}")))?;
        let conn = tokio::time::timeout(self.timeout, connecting)
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(|e| UpstreamError::Io(format!("QUIC handshake failed: {e}")))?;

        // RFC 9250 section 4.2: DoQ uses the "doq" ALPN. A handshake that
        // completes without it is not DoQ, so never cache or use that
        // connection.
        let negotiated = conn
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|data| data.protocol);
        if let Err(error) = ensure_doq_alpn(negotiated.as_deref(), self.remote_addr) {
            conn.close(0u32.into(), b"ALPN mismatch");
            return Err(error);
        }

        trace!(peer = %self.remote_addr, "Established DoQ connection");
        *guard = Some(conn.clone());
        Ok(conn)
    }

    /// Opens one bidirectional stream, retrying once on failure.
    ///
    /// A cached connection can be wedged at its stream limit while the QUIC
    /// connection itself still reports no close reason. Invalidate it and make
    /// one fresh connection so a single stuck stream does not fail the query.
    async fn open_stream(
        &self,
    ) -> Result<(quinn::Connection, quinn::SendStream, quinn::RecvStream), UpstreamError> {
        let mut last_error = None;
        for attempt in 0..2 {
            let conn = match self.get_connection().await {
                Ok(conn) => conn,
                Err(e) => {
                    last_error = Some(e);
                    if attempt == 0 {
                        continue;
                    }
                    break;
                }
            };

            match tokio::time::timeout(self.timeout, conn.open_bi()).await {
                Ok(Ok((send, recv))) => return Ok((conn, send, recv)),
                Ok(Err(e)) => {
                    let error = UpstreamError::Io(format!("failed to open DoQ stream: {e}"));
                    trace!(
                        peer = %self.remote_addr,
                        "DoQ stream open failed ({}); invalidating connection and retrying",
                        error
                    );
                    self.invalidate_connection(&conn).await;
                    last_error = Some(error);
                }
                Err(_) => {
                    trace!(
                        peer = %self.remote_addr,
                        "DoQ stream open timed out; invalidating connection and retrying"
                    );
                    self.invalidate_connection(&conn).await;
                    last_error = Some(UpstreamError::Timeout);
                }
            }
        }
        Err(last_error.unwrap_or(UpstreamError::Timeout))
    }

    /// Forget the cached connection after a stream failure, unless another task
    /// has already replaced it.
    async fn invalidate_connection(&self, stale: &quinn::Connection) {
        let mut guard = self.connection.lock().await;
        if guard
            .as_ref()
            .is_some_and(|current| current.stable_id() == stale.stable_id())
        {
            *guard = None;
            trace!(peer = %self.remote_addr, "Dropped wedged cached DoQ connection");
        }
    }
}

#[async_trait::async_trait]
impl Upstream for QuicUpstream {
    async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
        // RFC 9250 section 4.2.1: the DNS message ID MUST be 0 on the wire.
        let mut wire_query = msg.clone();
        wire_query.metadata.id = 0;
        let encoded =
            encode_message(&wire_query).map_err(|e| UpstreamError::BadResponse(e.to_string()))?;
        // The 2-octet length prefix caps the message at 65535 bytes; reject
        // instead of truncating the cast.
        let Ok(encoded_len) = u16::try_from(encoded.len()) else {
            return Err(UpstreamError::BadResponse(format!(
                "DoQ query of {} bytes exceeds the {MAX_DOQ_MESSAGE_BYTES} byte limit",
                encoded.len()
            )));
        };

        // `open_stream` invalidates a connection whose stream slot is wedged
        // and reconnects once, so the caller still gets one query attempt.
        let (conn, mut send, mut recv) = self.open_stream().await?;

        let result = async {
            let write = async {
                send.write_all(&encoded_len.to_be_bytes())
                    .await
                    .map_err(|e| UpstreamError::Io(format!("DoQ stream write failed: {e}")))?;
                send.write_all(&encoded)
                    .await
                    .map_err(|e| UpstreamError::Io(format!("DoQ stream write failed: {e}")))?;
                let _ = send.finish();
                Ok::<(), UpstreamError>(())
            };
            tokio::time::timeout(self.timeout, write)
                .await
                .map_err(|_| UpstreamError::Timeout)??;

            let read = async {
                let mut len_buf = [0u8; 2];
                recv.read_exact(&mut len_buf)
                    .await
                    .map_err(|e| UpstreamError::Io(format!("DoQ stream read failed: {e}")))?;
                let resp_len = u16::from_be_bytes(len_buf) as usize;
                if resp_len == 0 {
                    return Err(UpstreamError::BadResponse("empty DoQ response".to_string()));
                }
                let mut resp_buf = vec![0u8; resp_len];
                recv.read_exact(&mut resp_buf)
                    .await
                    .map_err(|e| UpstreamError::Io(format!("DoQ stream read failed: {e}")))?;
                Ok::<Vec<u8>, UpstreamError>(resp_buf)
            };
            let resp_buf = tokio::time::timeout(self.timeout, read)
                .await
                .map_err(|_| UpstreamError::Timeout)??;

            let mut response = decode_message(&resp_buf)
                .map_err(|e| UpstreamError::BadResponse(format!("invalid DoQ response: {e}")))?;
            // RFC 9250 section 4.2.1: responses MUST use DNS message ID 0. Check the
            // wire ID before rewriting it, otherwise the mismatch check is vacuous.
            if response.metadata.id != 0 {
                return Err(UpstreamError::BadResponse(format!(
                    "DoQ response ID must be 0 on the wire, got {}",
                    response.metadata.id
                )));
            }
            response.metadata.id = msg.metadata.id;
            validate_response(msg, &response)?;
            Ok(response)
        }
        .await;

        // Drop a cached connection whose stream failed. Without this a wedged
        // connection that has not reported a close reason would keep being
        // reused for every query.
        if result.is_err() {
            self.invalidate_connection(&conn).await;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sito_proto::{MessageType, OpCode, Query, RecordType};
    use std::str::FromStr;
    use std::sync::atomic::Ordering;

    fn make_query(id: u16) -> Message {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            sito_proto::Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        query
    }

    /// Starts a minimal RFC 9250 echo server with a fresh self-signed
    /// certificate, replying with the given wire DNS message ID. When
    /// `wedged_first_connection` is set, the first connection is held open but
    /// never answered, so the client must reconnect after timing out.
    fn doq_server_config(
        cert_der: &rustls::pki_types::CertificateDer<'static>,
        key_der: rustls::pki_types::PrivatePkcs8KeyDer<'static>,
        alpn: Option<&[u8]>,
        max_bidi_streams: Option<u32>,
    ) -> quinn::ServerConfig {
        let mut server_rustls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.into())
        .unwrap();
        if let Some(alpn) = alpn {
            server_rustls.alpn_protocols = vec![alpn.to_vec()];
        }

        let quic_crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_rustls)).unwrap();
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        if let Some(max_bidi_streams) = max_bidi_streams {
            let mut transport = quinn::TransportConfig::default();
            transport.max_concurrent_bidi_streams(max_bidi_streams.into());
            server_cfg.transport_config(Arc::new(transport));
        }
        server_cfg
    }

    /// Serves queries on one accepted DoQ connection.
    async fn serve_doq_connection(conn: quinn::Connection, response_id: u16) {
        loop {
            let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                break;
            };
            let mut len_buf = [0u8; 2];
            if recv.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let query_len = u16::from_be_bytes(len_buf) as usize;
            let mut query_buf = vec![0u8; query_len];
            if recv.read_exact(&mut query_buf).await.is_err() {
                break;
            }
            let query = decode_message(&query_buf).unwrap();
            // RFC 9250: queries use ID 0.
            assert_eq!(query.metadata.id, 0);
            let mut resp = Message::new(response_id, MessageType::Response, OpCode::Query);
            resp.metadata.response_code = sito_proto::ResponseCode::NoError;
            resp.queries = query.queries.clone();
            let encoded = encode_message(&resp).unwrap();
            let _ = send.write_all(&(encoded.len() as u16).to_be_bytes()).await;
            let _ = send.write_all(&encoded).await;
            let _ = send.finish();
        }
    }

    fn spawn_doq_server(
        response_id: u16,
        wedged_first_connection: bool,
    ) -> (SocketAddr, rustls::pki_types::CertificateDer<'static>) {
        spawn_doq_server_with_alpn_and_wedge(response_id, wedged_first_connection, Some(b"doq"))
    }

    fn spawn_doq_server_with_alpn_and_wedge(
        response_id: u16,
        wedged_first_connection: bool,
        alpn: Option<&[u8]>,
    ) -> (SocketAddr, rustls::pki_types::CertificateDer<'static>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let server_cfg = doq_server_config(&cert_der, key_der, alpn, None);

        let endpoint = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();

        tokio::spawn(async move {
            let mut connection_index = 0usize;
            let mut held_open = Vec::new();
            let mut held_streams = Vec::new();
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else {
                    continue;
                };
                connection_index += 1;
                if wedged_first_connection && connection_index == 1 {
                    // Read part of the query but never answer it, and keep the
                    // stream handles alive so the client observes a timeout
                    // rather than an early stream finish.
                    if let Ok((send, mut recv)) = conn.accept_bi().await {
                        let mut len_buf = [0u8; 2];
                        let _ = recv.read_exact(&mut len_buf).await;
                        held_streams.push((send, recv));
                    }
                    held_open.push(conn);
                    continue;
                }
                held_open.push(conn.clone());
                tokio::spawn(serve_doq_connection(conn, response_id));
            }
        });

        (addr, cert_der)
    }

    /// Accepts the first connection with zero bidirectional stream credit and
    /// every later connection normally, so the first `open_bi` times out while
    /// a reconnect succeeds.
    fn spawn_doq_server_with_first_connection_stream_limit(
        response_id: u16,
    ) -> (
        SocketAddr,
        rustls::pki_types::CertificateDer<'static>,
        Arc<std::sync::atomic::AtomicU32>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.clone());
        let key_bytes = cert.signing_key.serialize_der();
        let normal = doq_server_config(
            &cert_der,
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_bytes.clone()),
            Some(b"doq"),
            None,
        );
        let limited = doq_server_config(
            &cert_der,
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_bytes),
            Some(b"doq"),
            Some(0),
        );

        let endpoint =
            quinn::Endpoint::server(normal.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let connections = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = Arc::clone(&connections);

        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(incoming) = endpoint.accept().await {
                let index = counter.fetch_add(1, Ordering::SeqCst) + 1;
                let cfg = if index == 1 {
                    limited.clone()
                } else {
                    normal.clone()
                };
                let Ok(connecting) = incoming.accept_with(Arc::new(cfg)) else {
                    continue;
                };
                let Ok(conn) = connecting.await else {
                    continue;
                };
                if index == 1 {
                    // Keep the connection alive but grant no streams.
                    held.push(conn);
                    continue;
                }
                tokio::spawn(serve_doq_connection(conn, response_id));
            }
        });

        (addr, cert_der, connections)
    }

    fn client_config_trusting(
        cert: &rustls::pki_types::CertificateDer<'static>,
    ) -> quinn::ClientConfig {
        client_config_trusting_with_alpn(cert, Some(b"doq"))
    }

    fn client_config_trusting_with_alpn(
        cert: &rustls::pki_types::CertificateDer<'static>,
        alpn: Option<&[u8]>,
    ) -> quinn::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let mut rustls_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        if let Some(alpn) = alpn {
            rustls_cfg.alpn_protocols = vec![alpn.to_vec()];
        }
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg).unwrap();
        quinn::ClientConfig::new(Arc::new(quic_crypto))
    }

    #[tokio::test]
    async fn test_doq_query_roundtrip_uses_id_zero_on_wire() {
        let (addr, cert) = spawn_doq_server(0, false);
        let upstream = QuicUpstream::with_client_config(
            "localhost",
            addr,
            Duration::from_secs(3),
            client_config_trusting(&cert),
        )
        .unwrap();

        let query = make_query(0x4242);
        let resp = upstream
            .resolve(&query)
            .await
            .expect("DoQ query should succeed");
        assert_eq!(resp.metadata.id, 0x4242, "caller ID must be restored");
        assert_eq!(resp.queries.len(), 1);
    }

    #[tokio::test]
    async fn test_doq_untrusted_certificate_rejected() {
        let (addr, _cert) = spawn_doq_server(0, false);
        // Trust a different self-signed certificate than the server presents.
        let other = rcgen::generate_simple_self_signed(vec!["other.local".to_string()]).unwrap();
        let other_der = rustls::pki_types::CertificateDer::from(other.cert);
        let upstream = QuicUpstream::with_client_config(
            "localhost",
            addr,
            Duration::from_secs(2),
            client_config_trusting(&other_der),
        )
        .unwrap();

        let err = upstream.resolve(&make_query(1)).await.unwrap_err();
        assert!(
            matches!(err, UpstreamError::Io(_) | UpstreamError::Timeout),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_doq_drops_wedged_cached_connection_and_reconnects() {
        let (addr, cert) = spawn_doq_server(0, true);
        let upstream = QuicUpstream::with_client_config(
            "localhost",
            addr,
            Duration::from_millis(250),
            client_config_trusting(&cert),
        )
        .unwrap();

        // First connection is accepted but never answered: the query times out
        // and the cached connection must be discarded.
        let first = upstream.resolve(&make_query(0x1111)).await;
        assert!(
            matches!(first, Err(UpstreamError::Timeout)),
            "wedged connection must surface as a timeout: {first:?}"
        );

        // The next query must open a fresh connection and succeed.
        let second = tokio::time::timeout(
            Duration::from_secs(3),
            upstream.resolve(&make_query(0x2222)),
        )
        .await
        .expect("second query must not hang on the wedged connection")
        .expect("a fresh DoQ connection must answer");
        assert_eq!(second.metadata.id, 0x2222);
    }

    /// WP-2.7: a completed QUIC handshake without the `doq` ALPN is not an
    /// RFC 9250 resolver and must be rejected with a TLS error. rustls aborts
    /// a mismatched handshake itself, so the post-handshake check is exercised
    /// directly with the values rustls could hand back.
    #[test]
    fn test_doq_alpn_mismatch_rejected() {
        let remote: SocketAddr = "127.0.0.1:853".parse().unwrap();
        for negotiated in [None, Some(&b"h3"[..])] {
            let err = ensure_doq_alpn(negotiated, remote).unwrap_err();
            assert!(
                matches!(err, UpstreamError::Tls(ref msg) if msg.contains("ALPN")),
                "negotiated {negotiated:?} must be rejected, got {err:?}"
            );
        }
        ensure_doq_alpn(Some(b"doq"), remote).expect("the doq ALPN must be accepted");
    }

    /// WP-2.7: a connection that grants no bidirectional streams makes
    /// `open_bi` time out; the client must discard it, reconnect once and then
    /// complete the query instead of failing the whole lookup.
    #[tokio::test]
    async fn test_doq_reconnects_after_stream_open_failure() {
        let (addr, cert, connections) = spawn_doq_server_with_first_connection_stream_limit(0);
        let upstream = QuicUpstream::with_client_config(
            "localhost",
            addr,
            Duration::from_millis(200),
            client_config_trusting(&cert),
        )
        .unwrap();

        let resp = tokio::time::timeout(
            Duration::from_secs(3),
            upstream.resolve(&make_query(0x5151)),
        )
        .await
        .expect("the reconnect must stay bounded")
        .expect("the query must succeed on the second connection");
        assert_eq!(resp.metadata.id, 0x5151);
        assert_eq!(
            connections.load(Ordering::SeqCst),
            2,
            "the wedged stream must trigger exactly one reconnect"
        );
    }

    #[tokio::test]
    async fn test_doq_rejects_nonzero_wire_id() {
        // RFC 9250: responses MUST carry DNS message ID 0. A server echoing a
        // non-zero ID must be rejected (previously the check was vacuous
        // because the ID was overwritten before validation).
        let (addr, cert) = spawn_doq_server(0x1234, false);
        let upstream = QuicUpstream::with_client_config(
            "localhost",
            addr,
            Duration::from_secs(3),
            client_config_trusting(&cert),
        )
        .unwrap();

        let err = upstream.resolve(&make_query(0x4242)).await.unwrap_err();
        assert!(
            matches!(err, UpstreamError::BadResponse(ref msg) if msg.contains("must be 0")),
            "unexpected error: {err:?}"
        );
    }
}
