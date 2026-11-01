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
use crate::tcp::{MAX_PIPELINED_QUERIES, frame_prefix};
use crate::tls::TlsAcceptorManager;

/// Bounded wait for the TLS handshake; slowloris clients must not hold a
/// connection permit indefinitely.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on a single write/flush operation to a client.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Optional shared limiter; lets the server hot-reload the rate
    /// limit while keeping listener state. Built from `rate_limit_per_ip`
    /// when absent.
    pub rate_limiter: Option<Arc<RateLimiter>>,
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
            rate_limiter: None,
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
    let rate_limiter = config.rate_limiter.clone().unwrap_or_else(|| {
        Arc::new(RateLimiter::new(
            config.rate_limit_per_ip,
            config.rate_limit_per_ip * 2,
        ))
    });
    rate_limiter.spawn_pruner(shutdown_rx.clone());

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

                    // Rate limiting is per query inside handle_dot_connection;
                    // the connection cap above already bounds connection setup.
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
    let tls_stream = match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!("DoT TLS handshake failed for {}: {}", peer_addr, e);
            return Ok(());
        }
        Err(_) => {
            debug!(
                "DoT TLS handshake timed out after {}s for {}",
                TLS_HANDSHAKE_TIMEOUT.as_secs(),
                peer_addr
            );
            return Ok(());
        }
    };

    // ALPN verification: if ALPN protocol negotiated, ensure it's "dot"
    let negotiated_alpn = tls_stream.get_ref().1.alpn_protocol();
    if let Some(alpn) = negotiated_alpn
        && alpn != b"dot"
    {
        debug!("DoT invalid ALPN protocol negotiated: {:?}", alpn);
        return Ok(());
    }

    // SNI extraction
    let server_name = tls_stream
        .get_ref()
        .1
        .server_name()
        .map(ToString::to_string);
    let client_ctx = match server_name {
        Some(ref sni) => ClientContext::with_sni(peer_addr.ip(), sni).with_proto("dot"),
        None => ClientContext::new(peer_addr.ip()).with_proto("dot"),
    };

    let (mut reader, mut writer) = tokio::io::split(tls_stream);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);

    // Writer task. Frames are u16 length-prefixed; oversized responses are
    // dropped rather than wrapped around.
    let write_task = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            let Some(len) = frame_prefix(bytes.len()) else {
                warn!(
                    "DoT response of {} bytes exceeds the 65535-byte DNS-over-TCP limit; dropping",
                    bytes.len()
                );
                continue;
            };
            let write_res = timeout(WRITE_TIMEOUT, async {
                writer.write_all(&len).await?;
                writer.write_all(&bytes).await?;
                writer.flush().await?;
                Ok::<(), std::io::Error>(())
            })
            .await;
            match write_res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    warn!(
                        "DoT write to {} timed out after {}s; closing connection",
                        peer_addr,
                        WRITE_TIMEOUT.as_secs()
                    );
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "DoT write timeout",
                    ));
                }
            }
        }
        let _ = writer.shutdown().await;
        Ok::<(), std::io::Error>(())
    });

    // Bound in-flight pipelined queries per connection (same cap as TCP).
    let pipeline_semaphore = Arc::new(Semaphore::new(
        config
            .max_queries_per_connection
            .clamp(1, MAX_PIPELINED_QUERIES),
    ));

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
            // Zero-length frames are a protocol violation; close instead of
            // spinning on the 00 00 prefix.
            debug!(
                "DoT client {} sent a zero-length frame; closing connection",
                peer_addr
            );
            break;
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

        // Per-query budget: the accept-time check alone lets one connection
        // issue unlimited queries.
        if let Some(ref limiter) = config.rate_limiter
            && !limiter.check(peer_addr.ip())
        {
            debug!(
                "DoT per-query rate limit exceeded for client {}; dropping query",
                peer_addr.ip()
            );
            continue;
        }

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
        let Ok(pipeline_permit) = Arc::clone(&pipeline_semaphore).acquire_owned().await else {
            break;
        };

        // Pipelining: handle query concurrently, bounded by the per-connection cap
        tokio::spawn(async move {
            let _permit = pipeline_permit;
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
