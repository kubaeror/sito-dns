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

        trace!(peer = %self.remote_addr, "Established DoQ connection");
        *guard = Some(conn.clone());
        Ok(conn)
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

        let conn = self.get_connection().await?;
        let (mut send, mut recv) = tokio::time::timeout(self.timeout, conn.open_bi())
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(|e| UpstreamError::Io(format!("failed to open DoQ stream: {e}")))?;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use sito_proto::{MessageType, OpCode, Query, RecordType};
    use std::str::FromStr;

    fn make_query(id: u16) -> Message {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            sito_proto::Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        query
    }

    /// Starts a minimal RFC 9250 echo server with a fresh self-signed
    /// certificate, replying with the given wire DNS message ID.
    fn spawn_doq_server(
        response_id: u16,
    ) -> (SocketAddr, rustls::pki_types::CertificateDer<'static>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

        let mut server_rustls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.into())
        .unwrap();
        server_rustls.alpn_protocols = vec![b"doq".to_vec()];

        let quic_crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_rustls)).unwrap();
        let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        let endpoint = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();

        tokio::spawn(async move {
            if let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else {
                    return;
                };
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
        });

        (addr, cert_der)
    }

    fn client_config_trusting(
        cert: &rustls::pki_types::CertificateDer<'static>,
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
        rustls_cfg.alpn_protocols = vec![b"doq".to_vec()];
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg).unwrap();
        quinn::ClientConfig::new(Arc::new(quic_crypto))
    }

    #[tokio::test]
    async fn test_doq_query_roundtrip_uses_id_zero_on_wire() {
        let (addr, cert) = spawn_doq_server(0);
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
        let (addr, _cert) = spawn_doq_server(0);
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
    async fn test_doq_rejects_nonzero_wire_id() {
        // RFC 9250: responses MUST carry DNS message ID 0. A server echoing a
        // non-zero ID must be rejected (previously the check was vacuous
        // because the ID was overwritten before validation).
        let (addr, cert) = spawn_doq_server(0x1234);
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
