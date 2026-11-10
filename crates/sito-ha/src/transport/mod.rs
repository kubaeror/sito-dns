//! Transport layer supporting mutual TLS and WebSocket replication.

pub mod backoff;
pub mod mtls;

use std::time::Duration;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

pub use backoff::ExponentialBackoff;
pub use mtls::{
    PinnedClientCertVerifier, PinnedServerCertVerifier, build_client_tls_config,
    build_server_tls_config, load_certs_pem, load_key_pem,
};

/// Maximum accepted WebSocket message/frame size on either end of the HA
/// replication channel. Bundles are small configuration documents; anything
/// above this is a protocol error and must not be buffered.
pub const MAX_WS_MESSAGE_SIZE: usize = 1024 * 1024;

/// WebSocket protocol limits shared by the master listener and the slave
/// client: oversized messages/frames are rejected by the codec instead of
/// being accumulated in memory.
#[must_use]
pub fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
        .max_frame_size(Some(MAX_WS_MESSAGE_SIZE))
}

/// Upper bound on the slave's TCP/TLS connect and WebSocket upgrade; mirrors
/// the master's 10 s handshake budget so a stalled peer cannot pin the worker.
pub const SLAVE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on a single WebSocket write.
///
/// A peer that stops reading must not pin a replication session (and its
/// per-slave queue) forever. Sends on both the master and slave sides use this
/// deadline.
pub const WS_SEND_TIMEOUT: Duration = Duration::from_secs(10);
