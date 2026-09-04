//! DNS client test helper simulating queries over UDP, TCP, DoT, and DoH.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use rustls_pki_types::ServerName;
use sito_proto::{decode_message, encode_message};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;

#[derive(Debug)]
struct NoServerVerifier;

impl rustls::client::danger::ServerCertVerifier for NoServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// An active TLS connection to a DoT server, supporting repeated/pipelined queries.
pub struct DotConnection {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    timeout: Duration,
}

impl DotConnection {
    /// Sends a query for `name` and `qtype` and reads the response.
    pub async fn query(&mut self, name: &str, qtype: RecordType) -> Result<Message, anyhow::Error> {
        let fqdn = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };

        let mut query = Message::new(rand::random(), MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query
            .queries
            .push(Query::query(Name::from_str(&fqdn)?, qtype));

        self.query_message(&query).await
    }

    /// Sends a DNS `Message` and reads the response.
    pub async fn query_message(&mut self, query: &Message) -> Result<Message, anyhow::Error> {
        let wire = encode_message(query)?;
        let resp_bytes = self.query_raw(&wire).await?;
        let response = decode_message(&resp_bytes)?;
        Ok(response)
    }

    /// Sends raw wire bytes prefixed by a 2-byte big-endian length and receives raw response bytes.
    pub async fn query_raw(&mut self, wire: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let len_bytes = (wire.len() as u16).to_be_bytes();
        self.stream.write_all(&len_bytes).await?;
        self.stream.write_all(wire).await?;
        self.stream.flush().await?;

        let mut resp_len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, self.stream.read_exact(&mut resp_len_buf))
            .await
            .map_err(|_| anyhow::anyhow!("DoT read length timed out after {:?}", self.timeout))??;

        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(self.timeout, self.stream.read_exact(&mut resp_buf))
            .await
            .map_err(|_| anyhow::anyhow!("DoT read body timed out after {:?}", self.timeout))??;

        Ok(resp_buf)
    }

    /// Access the underlying TLS stream directly.
    pub fn get_mut(&mut self) -> &mut tokio_rustls::client::TlsStream<TcpStream> {
        &mut self.stream
    }

    /// Consume into underlying TLS stream.
    pub fn into_inner(self) -> tokio_rustls::client::TlsStream<TcpStream> {
        self.stream
    }
}

/// Test client for sending DNS queries over UDP, TCP, DoT, and DoH.
#[derive(Debug, Clone)]
pub struct TestDnsClient {
    server_addr: SocketAddr,
    timeout: Duration,
}

impl TestDnsClient {
    /// Creates a new test client targeting `server_addr`.
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            timeout: Duration::from_secs(3),
        }
    }

    /// Customizes the query timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Returns the target server address.
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Returns the timeout duration.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Sends a DNS query over UDP.
    pub async fn query_udp(&self, name: &str, qtype: RecordType) -> Result<Message, anyhow::Error> {
        let bind_addr = if self.server_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(self.server_addr).await?;

        let fqdn = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };

        let mut query = Message::new(rand::random(), MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query
            .queries
            .push(Query::query(Name::from_str(&fqdn)?, qtype));

        let wire = encode_message(&query)?;
        socket.send(&wire).await?;

        let mut buf = [0u8; 4096];
        let len = tokio::time::timeout(self.timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("UDP query timed out after {:?}", self.timeout))??;

        let response = decode_message(&buf[..len])?;
        Ok(response)
    }

    /// Sends a DNS query over TCP with 2-byte length prefix.
    pub async fn query_tcp(&self, name: &str, qtype: RecordType) -> Result<Message, anyhow::Error> {
        let mut stream = tokio::time::timeout(self.timeout, TcpStream::connect(self.server_addr))
            .await
            .map_err(|_| anyhow::anyhow!("TCP connect timed out after {:?}", self.timeout))??;

        let fqdn = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };

        let mut query = Message::new(rand::random(), MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query
            .queries
            .push(Query::query(Name::from_str(&fqdn)?, qtype));

        let wire = encode_message(&query)?;
        let len_bytes = (wire.len() as u16).to_be_bytes();

        stream.write_all(&len_bytes).await?;
        stream.write_all(&wire).await?;
        stream.flush().await?;

        let mut resp_len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut resp_len_buf))
            .await
            .map_err(|_| anyhow::anyhow!("TCP read length timed out after {:?}", self.timeout))??;

        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut resp_buf))
            .await
            .map_err(|_| anyhow::anyhow!("TCP read body timed out after {:?}", self.timeout))??;

        let response = decode_message(&resp_buf)?;
        Ok(response)
    }

    /// Connects to a DoT endpoint and returns an active `DotConnection`.
    pub async fn connect_dot(
        &self,
        dot_addr: SocketAddr,
        server_name: &str,
        alpn: Option<Vec<Vec<u8>>>,
    ) -> Result<DotConnection, anyhow::Error> {
        let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("Failed TLS protocol versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoServerVerifier))
        .with_no_client_auth();

        client_config.alpn_protocols = alpn.unwrap_or_else(|| vec![b"dot".to_vec()]);

        let connector = TlsConnector::from(Arc::new(client_config));
        let tcp_stream = tokio::time::timeout(self.timeout, TcpStream::connect(dot_addr))
            .await
            .map_err(|_| anyhow::anyhow!("DoT TCP connect timed out after {:?}", self.timeout))??;

        let server_name_val = ServerName::try_from(server_name.to_string())?.to_owned();
        let tls_stream =
            tokio::time::timeout(self.timeout, connector.connect(server_name_val, tcp_stream))
                .await
                .map_err(|_| {
                    anyhow::anyhow!("DoT TLS handshake timed out after {:?}", self.timeout)
                })??;

        Ok(DotConnection {
            stream: tls_stream,
            timeout: self.timeout,
        })
    }

    /// Sends a DNS query over DoT.
    pub async fn query_dot(
        &self,
        dot_addr: SocketAddr,
        server_name: &str,
        name: &str,
        qtype: RecordType,
    ) -> Result<Message, anyhow::Error> {
        let mut conn = self.connect_dot(dot_addr, server_name, None).await?;
        conn.query(name, qtype).await
    }

    /// Sends a pre-constructed DNS `Message` over DoT.
    pub async fn query_dot_message(
        &self,
        dot_addr: SocketAddr,
        server_name: &str,
        query: &Message,
    ) -> Result<Message, anyhow::Error> {
        let mut conn = self.connect_dot(dot_addr, server_name, None).await?;
        conn.query_message(query).await
    }

    /// Creates a pre-configured `reqwest::Client` suitable for DoH queries.
    pub fn doh_http_client(&self) -> Result<reqwest::Client, anyhow::Error> {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(self.timeout)
            .build()
            .map_err(Into::into)
    }

    /// Sends a DNS query over DoH via POST (`application/dns-message`).
    pub async fn query_doh_post(
        &self,
        doh_url: &str,
        name: &str,
        qtype: RecordType,
    ) -> Result<Message, anyhow::Error> {
        let fqdn = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };

        let mut query = Message::new(rand::random(), MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query
            .queries
            .push(Query::query(Name::from_str(&fqdn)?, qtype));

        self.query_doh_post_message(doh_url, &query).await
    }

    /// Sends a pre-constructed DNS `Message` over DoH via POST.
    pub async fn query_doh_post_message(
        &self,
        doh_url: &str,
        query: &Message,
    ) -> Result<Message, anyhow::Error> {
        let wire = encode_message(query)?;
        let client = self.doh_http_client()?;

        let resp = client
            .post(doh_url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(wire)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("DoH POST failed with HTTP status {}", resp.status());
        }

        let bytes = resp.bytes().await?;
        let response = decode_message(&bytes)?;
        Ok(response)
    }

    /// Sends a DNS query over DoH via GET (`?dns=<base64url>`).
    pub async fn query_doh_get(
        &self,
        doh_url: &str,
        name: &str,
        qtype: RecordType,
    ) -> Result<Message, anyhow::Error> {
        let fqdn = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };

        let mut query = Message::new(rand::random(), MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query
            .queries
            .push(Query::query(Name::from_str(&fqdn)?, qtype));

        self.query_doh_get_message(doh_url, &query).await
    }

    /// Sends a pre-constructed DNS `Message` over DoH via GET.
    pub async fn query_doh_get_message(
        &self,
        doh_url: &str,
        query: &Message,
    ) -> Result<Message, anyhow::Error> {
        let wire = encode_message(query)?;
        let b64 = URL_SAFE_NO_PAD.encode(&wire);
        let url = if doh_url.contains('?') {
            format!("{doh_url}&dns={b64}")
        } else {
            format!("{doh_url}?dns={b64}")
        };

        let client = self.doh_http_client()?;
        let resp = client
            .get(&url)
            .header("Accept", "application/dns-message")
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("DoH GET failed with HTTP status {}", resp.status());
        }

        let bytes = resp.bytes().await?;
        let response = decode_message(&bytes)?;
        Ok(response)
    }
}
