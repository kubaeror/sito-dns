//! RFC 7766 compliant TCP DNS listener with pipelining, idle timeouts, and connection limits.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;
use tracing::{debug, info, trace, warn};

use sito_core::client::ClientContext;
use sito_proto::{decode_message, encode_message};

use crate::handler::QueryHandler;
use crate::limiter::RateLimiter;

/// Configuration options for the TCP listener.
#[derive(Debug, Clone, Copy)]
pub struct TcpConfig {
    pub bind_addr: SocketAddr,
    pub max_connections: usize,
    pub idle_timeout: Duration,
    pub rate_limit_per_ip: u32,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:53".parse().expect("valid socket addr"),
            max_connections: 256,
            idle_timeout: Duration::from_secs(10),
            rate_limit_per_ip: 20,
        }
    }
}

/// Start the TCP listener on the configured address.
pub async fn start_tcp_listener<H: QueryHandler>(
    config: TcpConfig,
    handler: Arc<H>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    let local_addr = listener.local_addr()?;
    info!("TCP listener started on {}", local_addr);

    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let rate_limiter = Arc::new(RateLimiter::new(
        config.rate_limit_per_ip,
        config.rate_limit_per_ip * 2,
    ));
    rate_limiter.spawn_pruner(shutdown_rx.clone());

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        debug!("TCP listener stopping due to shutdown");
                        break;
                    }
                }
                accept_res = listener.accept() => {
                    let (stream, peer_addr) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("TCP accept error: {}", e);
                            continue;
                        }
                    };

                    let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                        warn!(
                            "TCP max connections ({}) reached; rejecting connection from {}",
                            config.max_connections, peer_addr
                        );
                        continue;
                    };

                    let client_ip = peer_addr.ip();
                    if !rate_limiter.check(client_ip) {
                        debug!("TCP rate limit exceeded for client {}", client_ip);
                        continue;
                    }

                    let handler = Arc::clone(&handler);
                    let idle_timeout = config.idle_timeout;

                    tokio::spawn(async move {
                        let _permit = permit; // Holds connection slot until task ends
                        if let Err(e) = handle_tcp_connection(stream, peer_addr, handler, idle_timeout).await {
                            trace!("TCP connection from {} closed with info: {}", peer_addr, e);
                        }
                    });
                }
            }
        }
    });

    Ok(handle)
}

async fn handle_tcp_connection<H: QueryHandler>(
    stream: TcpStream,
    peer_addr: SocketAddr,
    handler: Arc<H>,
    idle_timeout: Duration,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);

    // Writer task
    let write_task = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            let len = bytes.len() as u16;
            writer.write_all(&len.to_be_bytes()).await?;
            writer.write_all(&bytes).await?;
            writer.flush().await?;
        }
        Ok::<(), std::io::Error>(())
    });

    // Reader loop with RFC 7766 pipelining
    let client_ip = peer_addr.ip();
    loop {
        let mut len_buf = [0u8; 2];
        let read_len = match timeout(idle_timeout, reader.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => u16::from_be_bytes(len_buf) as usize,
            Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break; // Client closed connection cleanly
            }
            Ok(Err(e)) => {
                debug!("TCP read error from {}: {}", peer_addr, e);
                break;
            }
            Err(_) => {
                debug!(
                    "TCP idle timeout ({}s) reached for {}",
                    idle_timeout.as_secs(),
                    peer_addr
                );
                break;
            }
        };

        if read_len == 0 {
            continue;
        }

        let mut msg_buf = vec![0u8; read_len];
        match timeout(idle_timeout, reader.read_exact(&mut msg_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                debug!("TCP read body error from {}: {}", peer_addr, e);
                break;
            }
            Err(_) => {
                debug!("TCP read body timeout for {}", peer_addr);
                break;
            }
        }

        let query = match decode_message(&msg_buf) {
            Ok(q) => q,
            Err(e) => {
                warn!("TCP invalid DNS message from {}: {}", peer_addr, e);
                break;
            }
        };

        let handler = Arc::clone(&handler);
        let tx = tx.clone();

        // Pipelining: process queries asynchronously on the connection
        tokio::spawn(async move {
            if let Some(response) = handler
                .handle(query, ClientContext::new(client_ip).with_proto("tcp"))
                .await
                && let Ok(encoded) = encode_message(&response)
            {
                let _ = tx.send(encoded).await;
            }
        });
    }

    drop(tx);
    let _ = write_task.await;
    Ok(())
}
