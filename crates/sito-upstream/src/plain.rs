//! Plain DNS upstream (UDP with automatic TCP fallback on TC=1).

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout_at};
use tracing::{debug, trace};

use crate::upstream::{Upstream, validate_response};
use sito_core::error::UpstreamError;
use sito_proto::{Message, client_edns_payload_size, decode_message, encode_message};

/// Minimum UDP receive buffer (classic DNS limit when no EDNS is advertised).
const MIN_UDP_BUFFER_SIZE: usize = 512;

/// Maximum UDP receive buffer (the resolver's practical EDNS0 ceiling).
const MAX_UDP_BUFFER_SIZE: usize = 4096;

/// Size the UDP receive buffer from the outgoing query's advertised EDNS size.
fn udp_recv_buffer_size(query: &Message) -> usize {
    usize::from(client_edns_payload_size(query)).clamp(MIN_UDP_BUFFER_SIZE, MAX_UDP_BUFFER_SIZE)
}

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

    async fn resolve_tcp(
        &self,
        query: &Message,
        encoded_query: &[u8],
        deadline: Instant,
    ) -> Result<Message, UpstreamError> {
        let Ok(len) = u16::try_from(encoded_query.len()) else {
            return Err(UpstreamError::BadResponse(
                "plain DNS query exceeds the 65535-byte DNS-over-TCP limit".to_string(),
            ));
        };

        let mut stream = match timeout_at(deadline, TcpStream::connect(self.server_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(classify_io_error(&e)),
            Err(_) => return Err(UpstreamError::Timeout),
        };

        let res = timeout_at(deadline, async {
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
                let response = decode_message(&bytes)
                    .map_err(|e| UpstreamError::BadResponse(e.to_string()))?;
                validate_response(query, &response)?;
                Ok(response)
            }
            Ok(Err(e)) => Err(classify_io_error(&e)),
            Err(_) => Err(UpstreamError::Timeout),
        }
    }
}

#[async_trait::async_trait]
impl Upstream for PlainUpstream {
    async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
        // One overall deadline for the whole resolution (UDP attempt + TCP
        // fallback); phases must not each restart the full timeout.
        let deadline = Instant::now() + self.query_timeout;

        let encoded = encode_message(msg).map_err(|e| UpstreamError::BadResponse(e.to_string()))?;
        if encoded.len() > u16::MAX as usize {
            return Err(UpstreamError::BadResponse(
                "plain DNS query exceeds the 65535-byte DNS-over-TCP limit".to_string(),
            ));
        }

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

        match timeout_at(deadline, socket.send(&encoded)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(classify_io_error(&e)),
            Err(_) => return Err(UpstreamError::Timeout),
        }

        // Size the receive buffer to the EDNS payload advertised in the query
        // (512..4096) instead of a fixed 4096.
        let buffer_size = udp_recv_buffer_size(msg);
        let mut buf = vec![0u8; buffer_size];
        let recv_res = timeout_at(deadline, socket.recv(&mut buf)).await;
        let bytes_read = match recv_res {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(classify_io_error(&e)),
            Err(_) => return Err(UpstreamError::Timeout),
        };

        let response = match decode_message(&buf[..bytes_read]) {
            Ok(response) => response,
            // A full buffer combined with a decode failure usually means the
            // datagram did not fit; retry over TCP before giving up.
            Err(e) if bytes_read == buf.len() => {
                debug!(
                    "Upstream {} response may have been truncated at {} bytes ({}); retrying over TCP",
                    self.server_addr, buffer_size, e
                );
                return self.resolve_tcp(msg, &encoded, deadline).await;
            }
            Err(e) => return Err(UpstreamError::BadResponse(e.to_string())),
        };
        validate_response(msg, &response)?;

        // Fallback to TCP if UDP response was truncated
        if response.metadata.truncation {
            debug!(
                "Upstream {} returned TC=1 over UDP, retrying over TCP",
                self.server_addr
            );
            return self.resolve_tcp(msg, &encoded, deadline).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use sito_proto::set_edns_payload_size;
    use sito_proto::{MessageType, OpCode, Query, RecordType};
    use std::str::FromStr;

    fn make_query() -> Message {
        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            sito_proto::Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        query
    }

    #[test]
    fn test_udp_buffer_defaults_to_512_without_edns() {
        assert_eq!(udp_recv_buffer_size(&make_query()), MIN_UDP_BUFFER_SIZE);
    }

    #[test]
    fn test_udp_buffer_follows_advertised_edns_size() {
        let mut query = make_query();
        set_edns_payload_size(&mut query, 1232);
        assert_eq!(udp_recv_buffer_size(&query), 1232);

        set_edns_payload_size(&mut query, 4096);
        assert_eq!(udp_recv_buffer_size(&query), 4096);
    }

    #[test]
    fn test_udp_buffer_is_bounded() {
        let mut query = make_query();
        set_edns_payload_size(&mut query, 65535);
        assert_eq!(
            udp_recv_buffer_size(&query),
            MAX_UDP_BUFFER_SIZE,
            "buffer must not exceed the UDP ceiling"
        );
    }
}
