//! DNS client test helper simulating queries over UDP and TCP.

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use sito_proto::{decode_message, encode_message};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Test client for sending DNS queries over UDP and TCP.
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
}
