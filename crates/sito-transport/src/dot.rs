//! RFC 7858 compliant DNS over TLS (DoT) listener with ALPN enforcement,
//! connection pipelining, and RFC 8467 response padding.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Instant, timeout};
use tracing::{debug, info, trace, warn};

use sito_core::client::ClientContext;
use sito_proto::{DOT_PADDING_BLOCK_SIZE, apply_dot_padding, decode_message, encode_message};

use crate::handler::QueryHandler;
use crate::limiter::RateLimiter;
use crate::tls::TlsAcceptorManager;

/// Configuration options for the DoT listener.
#[derive(Clone)]
pub struct DotConfig {
    pub bind_addr: SocketAddr,
    pub acceptor_mgr: TlsAcceptorManager,
    pub max_connections: usize,
    pub idle_timeout: Duration,
    pub max_queries_per_connection: usize,
    pub max_connection_duration: Duration,
    pub rate_limit_per_ip: u32,
    pub dot_padding: bool,
}

impl DotConfig {
    pub fn new(bind_addr: SocketAddr, acceptor_mgr: TlsAcceptorManager) -> Self {
        Self {
            bind_addr,
            acceptor_mgr,
            max_connections: 256,
            idle_timeout: Duration::from_secs(30),
            max_queries_per_connection: 1000,
            max_connection_duration: Duration::from_secs(300),
            rate_limit_per_ip: 20,
            dot_padding: true,
        }
    }
}

/// Start the DNS over TLS listener on the configured address.
pub async fn start_dot_listener<H: QueryHandler>(
    config: DotConfig,
    handler: Arc<H>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    let local_addr = listener.local_addr()?;
    info!("DoT listener started on {}", local_addr);

    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let rate_limiter = Arc::new(RateLimiter::new(
        config.rate_limit_per_ip,
        config.rate_limit_per_ip * 2,
    ));

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        debug!("DoT listener stopping due to shutdown");
                        break;
                    }
                }
                accept_res = listener.accept() => {
                    let (stream, peer_addr) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("DoT accept error: {}", e);
                            continue;
                        }
                    };

                    let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                        warn!(
                            "DoT max connections ({}) reached; rejecting connection from {}",
                            config.max_connections, peer_addr
                        );
                        continue;
                    };

                    let client_ip = peer_addr.ip();
                    if !rate_limiter.check(client_ip) {
                        debug!("DoT rate limit exceeded for client {}", client_ip);
                        continue;
                    }

                    let acceptor = config.acceptor_mgr.acceptor();
                    let handler = Arc::clone(&handler);
                    let cfg = config.clone();

                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = handle_dot_connection(stream, peer_addr, acceptor, handler, cfg).await {
                            trace!("DoT connection from {} ended: {}", peer_addr, e);
                        }
                    });
                }
            }
        }
    });

    Ok(handle)
}

async fn handle_dot_connection<H: QueryHandler>(
    stream: TcpStream,
    peer_addr: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    handler: Arc<H>,
    config: DotConfig,
) -> std::io::Result<()> {
    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            debug!("DoT TLS handshake failed for {}: {}", peer_addr, e);
            return Ok(());
        }
    };

    // ALPN verification: if ALPN protocol negotiated, ensure it's "dot"
    let negotiated_alpn = tls_stream.get_ref().1.alpn_protocol();
    if let Some(alpn) = negotiated_alpn {
        if alpn != b"dot" {
            debug!("DoT invalid ALPN protocol negotiated: {:?}", alpn);
            return Ok(());
        }
    }

    // SNI extraction
    let server_name = tls_stream
        .get_ref()
        .1
        .server_name()
        .map(ToString::to_string);
    let client_ctx = match server_name {
        Some(ref sni) => ClientContext::with_sni(peer_addr.ip(), sni),
        None => ClientContext::new(peer_addr.ip()),
    };

    let (mut reader, mut writer) = tokio::io::split(tls_stream);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);

    // Writer task
    let write_task = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            let len = bytes.len() as u16;
            writer.write_all(&len.to_be_bytes()).await?;
            writer.write_all(&bytes).await?;
            writer.flush().await?;
        }
        let _ = writer.shutdown().await;
        Ok::<(), std::io::Error>(())
    });

    let conn_start = Instant::now();
    let mut query_count = 0usize;

    loop {
        if conn_start.elapsed() >= config.max_connection_duration {
            debug!(
                "DoT connection duration limit ({}s) reached for {}",
                config.max_connection_duration.as_secs(),
                peer_addr
            );
            break;
        }

        if query_count >= config.max_queries_per_connection {
            debug!(
                "DoT max queries ({}) reached for connection {}",
                config.max_queries_per_connection, peer_addr
            );
            break;
        }

        let mut len_buf = [0u8; 2];
        let read_len = match timeout(config.idle_timeout, reader.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => u16::from_be_bytes(len_buf) as usize,
            Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break; // Clean client close
            }
            Ok(Err(e)) => {
                debug!("DoT read error from {}: {}", peer_addr, e);
                break;
            }
            Err(_) => {
                debug!(
                    "DoT idle timeout ({}s) reached for {}",
                    config.idle_timeout.as_secs(),
                    peer_addr
                );
                break;
            }
        };

        if read_len == 0 {
            continue;
        }

        let mut msg_buf = vec![0u8; read_len];
        match timeout(config.idle_timeout, reader.read_exact(&mut msg_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                debug!("DoT read body error from {}: {}", peer_addr, e);
                break;
            }
            Err(_) => {
                debug!("DoT read body timeout for {}", peer_addr);
                break;
            }
        }

        query_count += 1;

        let query = match decode_message(&msg_buf) {
            Ok(q) => q,
            Err(e) => {
                warn!("DoT invalid DNS message from {}: {}", peer_addr, e);
                break;
            }
        };

        let handler = Arc::clone(&handler);
        let tx = tx.clone();
        let client_ctx = client_ctx.clone();
        let dot_padding = config.dot_padding;

        // Pipelining: handle query concurrently
        tokio::spawn(async move {
            if let Some(mut response) = handler.handle(query, client_ctx).await {
                if dot_padding {
                    let _ = apply_dot_padding(&mut response, DOT_PADDING_BLOCK_SIZE);
                }
                if let Ok(encoded) = encode_message(&response) {
                    let _ = tx.send(encoded).await;
                }
            }
        });
    }

    drop(tx);
    let _ = write_task.await;
    Ok(())
}
