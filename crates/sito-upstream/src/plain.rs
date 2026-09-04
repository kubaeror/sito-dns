//! Plain DNS upstream (UDP with automatic TCP fallback on TC=1).

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, trace};

use crate::upstream::Upstream;
use sito_core::error::UpstreamError;
use sito_proto::{Message, decode_message, encode_message};

/// A plain DNS upstream resolver speaking UDP and TCP.
pub struct PlainUpstream {
    server_addr: SocketAddr,
    query_timeout: Duration,
}

impl PlainUpstream {
    pub fn new(server_addr: SocketAddr, query_timeout: Duration) -> Self {
        Self {
            server_addr,
            query_timeout,
        }
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    async fn resolve_tcp(&self, encoded_query: &[u8]) -> Result<Message, UpstreamError> {
        let mut stream =
            match timeout(self.query_timeout, TcpStream::connect(self.server_addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(classify_io_error(&e)),
                Err(_) => return Err(UpstreamError::Timeout),
            };

        let len = encoded_query.len() as u16;
        let res = timeout(self.query_timeout, async {
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(encoded_query).await?;
            stream.flush().await?;

            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;

            let mut resp_buf = vec![0u8; resp_len];
            stream.read_exact(&mut resp_buf).await?;
            Ok::<Vec<u8>, std::io::Error>(resp_buf)
        })
        .await;

        match res {
            Ok(Ok(bytes)) => {
                decode_message(&bytes).map_err(|e| UpstreamError::BadResponse(e.to_string()))
            }
            Ok(Err(e)) => Err(classify_io_error(&e)),
            Err(_) => Err(UpstreamError::Timeout),
        }
    }
}

#[async_trait::async_trait]
impl Upstream for PlainUpstream {
    async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
        let encoded = encode_message(msg).map_err(|e| UpstreamError::BadResponse(e.to_string()))?;

        let bind_addr: SocketAddr = if self.server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| classify_io_error(&e))?;
        socket
            .connect(self.server_addr)
            .await
            .map_err(|e| classify_io_error(&e))?;

        let send_res = timeout(self.query_timeout, socket.send(&encoded)).await;
        match send_res {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(classify_io_error(&e)),
            Err(_) => return Err(UpstreamError::Timeout),
        }

        let mut buf = vec![0u8; 4096];
        let recv_res = timeout(self.query_timeout, socket.recv(&mut buf)).await;
        let bytes_read = match recv_res {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(classify_io_error(&e)),
            Err(_) => return Err(UpstreamError::Timeout),
        };

        let response = decode_message(&buf[..bytes_read])
            .map_err(|e| UpstreamError::BadResponse(e.to_string()))?;

        // Fallback to TCP if UDP response was truncated
        if response.metadata.truncation {
            debug!(
                "Upstream {} returned TC=1 over UDP, retrying over TCP",
                self.server_addr
            );
            return self.resolve_tcp(&encoded).await;
        }

        trace!(
            "Received {} bytes from upstream {} over UDP",
            bytes_read, self.server_addr
        );
        Ok(response)
    }
}

pub fn classify_io_error(err: &std::io::Error) -> UpstreamError {
    match err.kind() {
        std::io::ErrorKind::TimedOut => UpstreamError::Timeout,
        std::io::ErrorKind::ConnectionRefused => UpstreamError::Refused,
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
            UpstreamError::Refused
        }
        _ => UpstreamError::Io(err.to_string()),
    }
}
