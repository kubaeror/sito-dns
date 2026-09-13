//! High-performance multi-socket UDP listener with SO_REUSEPORT, PKTINFO, and EDNS0/TC support.

#[cfg(not(unix))]
compile_error!("sito-transport UDP listener requires a Unix-based operating system (Linux/macOS)");

use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::watch::Receiver;
use tracing::{debug, error, info, trace, warn};

use sito_core::client::ClientContext;
use sito_proto::{client_edns_payload_size, decode_message, encode_message, set_edns_payload_size};

use crate::handler::QueryHandler;
use crate::limiter::RateLimiter;
use crate::pktinfo::{enable_pktinfo, recv_with_pktinfo, send_with_pktinfo};

/// Size of the per-worker receive buffer for inbound UDP datagrams.
const UDP_RECV_BUFFER_SIZE: usize = 4096;

/// Backoff applied after a transient receive error before retrying.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(10);

/// Whether a failed `recvmsg` is transient (EINTR, ENOBUFS, ICMP-induced
/// connection errors) and the worker should retry rather than exit.
fn is_transient_recv_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::OutOfMemory
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
    ) || err.raw_os_error() == Some(libc::ENOBUFS)
}

/// Options for configuring a UDP listener instance.
#[derive(Debug, Clone)]
pub struct UdpConfig {
    pub bind_addr: SocketAddr,
    pub worker_count: usize,
    pub edns_udp_size: u16,
    pub rate_limit_per_ip: u32,
    /// Optional shared limiter; lets the server hot-reload the rate
    /// limit while keeping listener state. Built from `rate_limit_per_ip`
    /// when absent.
    pub rate_limiter: Option<Arc<RateLimiter>>,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:53".parse().expect("valid socket addr"),
            worker_count: 1,
            edns_udp_size: 1232,
            rate_limit_per_ip: 20,
            rate_limiter: None,
        }
    }
}

/// Create a single non-blocking UDP socket configured with SO_REUSEPORT and SO_REUSEADDR.
pub fn create_reuseport_udp_socket(addr: &SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let domain = Domain::for_address(*addr);
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    unsafe {
        let opt: libc::c_int = 1;
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            (&raw const opt).cast::<libc::c_void>(),
            std::mem::size_of_val(&opt) as libc::socklen_t,
        );
    }

    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }

    socket.bind(&socket2::SockAddr::from(*addr))?;
    socket.set_nonblocking(true)?;

    enable_pktinfo(socket.as_raw_fd(), addr);

    Ok(socket.into())
}

/// Start UDP worker listeners across `worker_count` tasks.
pub fn start_udp_listener<H: QueryHandler>(
    config: &UdpConfig,
    handler: &Arc<H>,
    shutdown_rx: &Receiver<bool>,
) -> std::io::Result<Vec<tokio::task::JoinHandle<()>>> {
    let rate_limiter = config.rate_limiter.clone().unwrap_or_else(|| {
        Arc::new(RateLimiter::new(
            config.rate_limit_per_ip,
            config.rate_limit_per_ip * 2,
        ))
    });
    let mut tasks = Vec::new();
    tasks.push(rate_limiter.spawn_pruner(shutdown_rx.clone()));

    for worker_id in 0..config.worker_count {
        let std_socket = create_reuseport_udp_socket(&config.bind_addr)?;
        let local_addr = std_socket.local_addr()?;
        let async_fd = Arc::new(AsyncFd::new(std_socket)?);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1024));

        let handler = Arc::clone(handler);
        let rate_limiter = Arc::clone(&rate_limiter);
        let mut shutdown_rx = shutdown_rx.clone();
        let edns_udp_size = config.edns_udp_size;

        info!(
            "Spawned UDP worker #{} listening on {}",
            worker_id, local_addr
        );

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
            let fd = async_fd.get_ref().as_raw_fd();

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            debug!("UDP worker #{} stopping due to cancellation", worker_id);
                            break;
                        }
                    }
                    guard = async_fd.readable() => {
                        let mut guard = match guard {
                            Ok(g) => g,
                            Err(e) => {
                                error!("UDP worker #{} readable error: {}", worker_id, e);
                                break;
                            }
                        };

                        loop {
                            match recv_with_pktinfo(fd, &mut buf) {
                                Ok((len, peer_addr, dst_ip)) => {
                                    trace!("UDP received {} bytes from {} (dst: {:?})", len, peer_addr, dst_ip);

                                    let client_ip = peer_addr.ip();
                                    if !rate_limiter.check(client_ip) {
                                        debug!("Rate limit exceeded for client {}", client_ip);
                                        continue;
                                    }

                                    let query = match decode_message(&buf[..len]) {
                                        Ok(q) => q,
                                        Err(e) => {
                                            debug!("Failed to decode UDP DNS query from {}: {}", peer_addr, e);
                                            continue;
                                        }
                                    };

                                    let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                                        warn!(
                                            "UDP worker #{} concurrency limit reached; dropping query from {}",
                                            worker_id, peer_addr
                                        );
                                        continue;
                                    };

                                    let handler = Arc::clone(&handler);
                                    let async_fd = Arc::clone(&async_fd);

                                    // Process query concurrently to avoid head-of-line blocking
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        let fd = async_fd.get_ref().as_raw_fd();
                                        // Never amplify beyond the configured server maximum:
                                        // the effective bound is min(client-advertised, configured).
                                        let client_max_payload = client_edns_payload_size(&query);
                                        let max_payload = client_max_payload.min(edns_udp_size);
                                        let resp = handler.handle(query, ClientContext::new(client_ip)).await;

                                        if let Some(mut response) = resp {
                                            // Advertise server EDNS size if EDNS was present
                                            if response.edns.is_some() {
                                                set_edns_payload_size(&mut response, edns_udp_size);
                                            }

                                            let mut encoded = match encode_message(&response) {
                                                Ok(bytes) => bytes,
                                                Err(e) => {
                                                    warn!("Failed to encode response for {}: {}", peer_addr, e);
                                                    return;
                                                }
                                            };

                                            // If answer exceeds the negotiated payload, truncate (TC=1)
                                            if encoded.len() > max_payload as usize {
                                                debug!(
                                                    "Response size {} exceeds negotiated max payload {} (client {}, server {}), setting TC=1",
                                                    encoded.len(),
                                                    max_payload,
                                                    client_max_payload,
                                                    edns_udp_size
                                                );
                                                let mut truncated = response.truncate();
                                                if truncated.edns.is_some() {
                                                    set_edns_payload_size(&mut truncated, edns_udp_size);
                                                }
                                                if let Ok(truncated_bytes) = encode_message(&truncated) {
                                                    encoded = truncated_bytes;
                                                }
                                            }

                                            if let Err(e) = send_with_pktinfo(fd, &encoded, &peer_addr, dst_ip) {
                                                warn!("Failed to send UDP response to {}: {}", peer_addr, e);
                                            }
                                        }
                                    });
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    guard.clear_ready();
                                    break;
                                }
                                // Oversized datagrams are dropped: the kernel consumed
                                // them already, so the worker can keep serving.
                                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                                    debug!("UDP worker #{} dropping malformed/oversized datagram: {}", worker_id, e);
                                }
                                // Transient socket errors (EINTR, ENOBUFS, ICMP) must not
                                // kill the worker; retry with a small backoff.
                                Err(e) if is_transient_recv_error(&e) => {
                                    warn!(
                                        "UDP worker #{} transient recv error: {}; retrying after {:?}",
                                        worker_id, e, RECV_ERROR_BACKOFF
                                    );
                                    tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                                }
                                Err(e) => {
                                    warn!("UDP worker #{} fatal recv error: {}; stopping", worker_id, e);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });

        tasks.push(handle);
    }

    Ok(tasks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transient_recv_errors_are_retried() {
        assert!(is_transient_recv_error(&std::io::Error::from(
            std::io::ErrorKind::Interrupted
        )));
        assert!(is_transient_recv_error(&std::io::Error::from(
            std::io::ErrorKind::OutOfMemory
        )));
        assert!(is_transient_recv_error(&std::io::Error::from_raw_os_error(
            libc::ENOBUFS
        )));
        assert!(!is_transient_recv_error(&std::io::Error::from(
            std::io::ErrorKind::InvalidInput
        )));
        assert!(!is_transient_recv_error(&std::io::Error::from(
            std::io::ErrorKind::NotFound
        )));
    }
}
