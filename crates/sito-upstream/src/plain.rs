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

/// Whether a full-buffer datagram that failed to decode plausibly belongs to
/// this query and may have been truncated.
///
/// Requiring the matching wire ID and the QR bit prevents an off-path attacker
/// from forcing a TCP fallback with a full-size garbage datagram.
fn looks_like_truncated_response(bytes: &[u8], query_id: u16) -> bool {
    bytes.len() >= 12
        && u16::from_be_bytes([bytes[0], bytes[1]]) == query_id
        && bytes[2] & 0x80 != 0
}

/// A plain DNS upstream resolver speaking UDP and TCP.
pub struct PlainUpstream {
    server_addr: SocketAddr,
    query_timeout: Duration,
    /// Test-only count of ignored datagrams, used to synchronize tests that
    /// need to prove junk was processed before the genuine reply arrives.
    #[cfg(test)]
    rejected_datagrams: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl PlainUpstream {
    pub fn new(server_addr: SocketAddr, query_timeout: Duration) -> Self {
        Self {
            server_addr,
            query_timeout,
            #[cfg(test)]
            rejected_datagrams: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    #[cfg(test)]
    fn rejected_datagrams(&self) -> usize {
        self.rejected_datagrams
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    fn record_rejected_datagram(&self) {
        self.rejected_datagrams
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    async fn resolve_tcp(
        &self,
        query: &Message,
        encoded_query: &[u8],
        deadline: Instant,
        original_id: u16,
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
                let mut response = decode_message(&bytes)
                    .map_err(|e| UpstreamError::BadResponse(e.to_string()))?;
                validate_response(query, &response)?;
                response.metadata.id = original_id;
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

        // RFC 5452 §9.1: randomize the message ID on the wire so an off-path
        // attacker cannot predict it from the (client-chosen) ID, and restore
        // the caller's ID on the response. TLS/QUIC upstreams do not need this
        // and keep the caller's ID.
        let original_id = msg.metadata.id;
        let mut wire_msg = msg.clone();
        wire_msg.metadata.id = rand::random();
        let encoded =
            encode_message(&wire_msg).map_err(|e| UpstreamError::BadResponse(e.to_string()))?;
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
        // P2-9: keep receiving until the deadline. An off-path attacker can
        // inject malformed or mismatched datagrams; those must be ignored rather
        // than aborting a query whose genuine response is still in flight.
        let response = loop {
            let bytes_read = match timeout_at(deadline, socket.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(classify_io_error(&e)),
                Err(_) => return Err(UpstreamError::Timeout),
            };

            let mut candidate = match decode_message(&buf[..bytes_read]) {
                Ok(response) => response,
                // A full buffer combined with a decode failure usually means
                // the datagram did not fit; retry over TCP before giving up.
                Err(e)
                    if bytes_read == buf.len()
                        && looks_like_truncated_response(
                            &buf[..bytes_read],
                            wire_msg.metadata.id,
                        ) =>
                {
                    debug!(
                        "Upstream {} response may have been truncated at {} bytes ({}); retrying over TCP",
                        self.server_addr, buffer_size, e
                    );
                    return self
                        .resolve_tcp(&wire_msg, &encoded, deadline, original_id)
                        .await;
                }
                Err(e) => {
                    trace!(
                        "Ignoring malformed datagram from upstream {}: {}",
                        self.server_addr, e
                    );
                    #[cfg(test)]
                    self.record_rejected_datagram();
                    continue;
                }
            };

            match validate_response(&wire_msg, &candidate) {
                Ok(()) => {
                    candidate.metadata.id = original_id;
                    break candidate;
                }
                Err(e) => {
                    trace!(
                        "Ignoring mismatched datagram from upstream {}: {}",
                        self.server_addr, e
                    );
                    #[cfg(test)]
                    self.record_rejected_datagram();
                }
            }
        };

        // Fallback to TCP if UDP response was truncated
        if response.metadata.truncation {
            debug!(
                "Upstream {} returned TC=1 over UDP, retrying over TCP",
                self.server_addr
            );
            return self
                .resolve_tcp(&wire_msg, &encoded, deadline, original_id)
                .await;
        }

        trace!(
            "Received response from upstream {} over UDP",
            self.server_addr
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
    use sito_proto::rdata::A;
    use sito_proto::set_edns_payload_size;
    use sito_proto::{MessageType, OpCode, Query, RData, Record, RecordType, ResponseCode};
    use std::str::FromStr;
    use std::time::Duration;

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

    /// P2-9: structurally invalid and mismatched datagrams must be ignored
    /// until the deadline, not abort the query.
    #[tokio::test]
    async fn test_plain_udp_ignores_malformed_and_mismatched_datagrams() {
        use std::time::Duration;

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let query = decode_message(&buf[..n]).unwrap();

            // 1. Garbage that is not a DNS message.
            server.send_to(b"not a dns message", peer).await.unwrap();

            // 2. Structurally valid but answering a different ID/question.
            let mut spoofed = Message::response(query.metadata.id ^ 0xffff, query.metadata.op_code);
            spoofed.queries = query.queries.clone();
            spoofed.metadata.response_code = ResponseCode::NoError;
            let spoofed = encode_message(&spoofed).unwrap();
            server.send_to(&spoofed, peer).await.unwrap();

            // 3. The genuine response.
            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            resp.answers.push(Record::from_rdata(
                query.queries[0].name().clone(),
                300,
                RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
            ));
            let bytes = encode_message(&resp).unwrap();
            server.send_to(&bytes, peer).await.unwrap();
        });

        let upstream = PlainUpstream::new(addr, Duration::from_secs(2));
        let response = upstream
            .resolve(&make_query())
            .await
            .expect("valid response after junk must be accepted");
        server_task.await.unwrap();

        assert_eq!(response.metadata.id, 7);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            response.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4)))
        );
    }

    /// Waits until the upstream has ignored at least one datagram, so a test
    /// cannot send the genuine reply first and pass without exercising junk.
    async fn wait_for_rejected_datagram(upstream: &PlainUpstream) {
        for _ in 0..200 {
            if upstream.rejected_datagrams() > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("junk datagram was not rejected before the genuine reply");
    }

    /// P2-9 Important 2: an attacker who knows the port must not be able to
    /// force a TCP fallback (and fail the query) with a full-buffer garbage
    /// datagram whose header does not match the query.
    #[tokio::test]
    async fn test_plain_udp_ignores_full_buffer_junk() {
        use std::sync::Arc;
        use std::time::Duration;

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let release = Arc::new(tokio::sync::Notify::new());
        let server_release = Arc::clone(&release);

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let query = decode_message(&buf[..n]).unwrap();

            // Full 512-byte garbage with a deliberately wrong ID and no QR bit.
            // There is no TCP listener, so treating this as truncation would
            // fail the query instead of ignoring it.
            let mut junk = vec![0xffu8; MIN_UDP_BUFFER_SIZE];
            junk[0..2].copy_from_slice(&(query.metadata.id ^ 0xffff).to_be_bytes());
            junk[2] = 0x00;
            server.send_to(&junk, peer).await.unwrap();
            server_release.notified().await;

            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            resp.answers.push(Record::from_rdata(
                query.queries[0].name().clone(),
                300,
                RData::A(A(std::net::Ipv4Addr::new(4, 3, 2, 1))),
            ));
            let bytes = encode_message(&resp).unwrap();
            server.send_to(&bytes, peer).await.unwrap();
        });

        let upstream = Arc::new(PlainUpstream::new(addr, Duration::from_secs(2)));
        let resolve = {
            let upstream = Arc::clone(&upstream);
            tokio::spawn(async move { upstream.resolve(&make_query()).await })
        };
        wait_for_rejected_datagram(&upstream).await;
        release.notify_one();
        let response = resolve
            .await
            .unwrap()
            .expect("genuine response after full-buffer junk must be accepted");
        server_task.await.unwrap();

        assert_eq!(
            response.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(4, 3, 2, 1)))
        );
    }

    /// Deferred D4b: a full-buffer datagram with the matching ID but QR=0 must
    /// not trigger the TCP fallback. This isolates the QR half of
    /// `looks_like_truncated_response` (the combined test also sets a wrong ID).
    #[tokio::test]
    async fn test_plain_udp_ignores_full_buffer_junk_with_matching_id_and_no_qr() {
        use std::sync::Arc;
        use std::time::Duration;

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let release = Arc::new(tokio::sync::Notify::new());
        let server_release = Arc::clone(&release);

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let query = decode_message(&buf[..n]).unwrap();

            let mut junk = vec![0xffu8; MIN_UDP_BUFFER_SIZE];
            junk[0..2].copy_from_slice(&query.metadata.id.to_be_bytes());
            junk[2] = 0x00; // QR=0
            server.send_to(&junk, peer).await.unwrap();
            server_release.notified().await;

            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            resp.answers.push(Record::from_rdata(
                query.queries[0].name().clone(),
                300,
                RData::A(A(std::net::Ipv4Addr::new(5, 6, 7, 8))),
            ));
            let bytes = encode_message(&resp).unwrap();
            server.send_to(&bytes, peer).await.unwrap();
        });

        let upstream = Arc::new(PlainUpstream::new(addr, Duration::from_secs(2)));
        let resolve = {
            let upstream = Arc::clone(&upstream);
            tokio::spawn(async move { upstream.resolve(&make_query()).await })
        };
        wait_for_rejected_datagram(&upstream).await;
        release.notify_one();
        let response = resolve
            .await
            .unwrap()
            .expect("genuine response after matching-ID QR=0 junk must be accepted");
        server_task.await.unwrap();

        assert_eq!(
            response.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(5, 6, 7, 8)))
        );
    }

    /// Deferred D4b: a full-buffer datagram with QR=1 but a wrong ID must not
    /// trigger the TCP fallback. This isolates the ID half of
    /// `looks_like_truncated_response`.
    #[tokio::test]
    async fn test_plain_udp_ignores_full_buffer_junk_with_qr_and_wrong_id() {
        use std::sync::Arc;
        use std::time::Duration;

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let release = Arc::new(tokio::sync::Notify::new());
        let server_release = Arc::clone(&release);

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let query = decode_message(&buf[..n]).unwrap();

            let mut junk = vec![0xffu8; MIN_UDP_BUFFER_SIZE];
            junk[0..2].copy_from_slice(&(query.metadata.id ^ 0xffff).to_be_bytes());
            junk[2] = 0x80; // QR=1
            server.send_to(&junk, peer).await.unwrap();
            server_release.notified().await;

            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            resp.answers.push(Record::from_rdata(
                query.queries[0].name().clone(),
                300,
                RData::A(A(std::net::Ipv4Addr::new(8, 7, 6, 5))),
            ));
            let bytes = encode_message(&resp).unwrap();
            server.send_to(&bytes, peer).await.unwrap();
        });

        let upstream = Arc::new(PlainUpstream::new(addr, Duration::from_secs(2)));
        let resolve = {
            let upstream = Arc::clone(&upstream);
            tokio::spawn(async move { upstream.resolve(&make_query()).await })
        };
        wait_for_rejected_datagram(&upstream).await;
        release.notify_one();
        let response = resolve
            .await
            .unwrap()
            .expect("genuine response after QR=1 wrong-ID junk must be accepted");
        server_task.await.unwrap();

        assert_eq!(
            response.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(8, 7, 6, 5)))
        );
    }

    #[tokio::test]
    async fn test_plain_udp_randomizes_wire_id_and_restores_caller_id() {
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let seen: Arc<Mutex<Option<u16>>> = Arc::new(Mutex::new(None));
        let seen_server = Arc::clone(&seen);

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let query = decode_message(&buf[..n]).unwrap();
            *seen_server.lock().unwrap() = Some(query.metadata.id);

            let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
            resp.queries = query.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            let bytes = encode_message(&resp).unwrap();
            server.send_to(&bytes, peer).await.unwrap();
        });

        let upstream = PlainUpstream::new(addr, Duration::from_secs(2));
        let response = upstream.resolve(&make_query()).await.expect("resolve");
        server_task.await.unwrap();

        let wire_id = seen.lock().unwrap().expect("server saw a query");
        assert_ne!(wire_id, 7, "the on-the-wire ID must be randomized");
        assert_eq!(
            response.metadata.id, 7,
            "the caller's message ID must be restored"
        );
    }
}
