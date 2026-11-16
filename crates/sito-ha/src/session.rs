//! Shared WebSocket frame and message helpers for both HA roles.
//!
//! Master and slave sessions speak the same wire protocol: JSON-encoded
//! [`HaMessage`] values in WebSocket text frames, with plain-text binary frames
//! accepted for compatibility. Keeping the frame parsing, wire-size accounting,
//! and write deadlines here keeps both roles on one implementation.

use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message;

use crate::error::HaError;
use crate::protocol::HaMessage;
use crate::transport::WS_SEND_TIMEOUT;

/// Returns the exact serialized JSON byte length of `message`, or 0 if it
/// cannot be serialized.
///
/// The length is the byte count of the text frame that [`send_ha_message`]
/// will write; the master uses it for per-slave queue accounting. Size
/// validation against the WebSocket limit uses a fallible serialization path
/// so a serialization failure cannot be mistaken for an empty message.
pub fn wire_size(message: &HaMessage) -> usize {
    message.to_json().map_or(0, |json| json.len())
}

/// Extracts the JSON text carried by a [`Message::Text`] or [`Message::Binary`]
/// frame without allocating.
///
/// Returns `None` for other frame types and for binary frames that are not
/// valid UTF-8.
pub fn frame_text(message: &Message) -> Option<&str> {
    match message {
        Message::Text(text) => Some(text.as_str()),
        Message::Binary(bytes) => std::str::from_utf8(bytes).ok(),
        _ => None,
    }
}

/// Sends one raw frame with the shared [`WS_SEND_TIMEOUT`] write deadline.
///
/// A slow or stalled peer must not pin the session task (and its queues)
/// forever; the caller closes the session on timeout. `role` names the sending
/// side ("master" or "slave") in the timeout error.
pub(crate) async fn send_frame<S>(
    ws_stream: &mut tokio_tungstenite::WebSocketStream<S>,
    frame: Message,
    role: &str,
    context: &str,
) -> Result<(), HaError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(WS_SEND_TIMEOUT, ws_stream.send(frame))
        .await
        .map_err(|_| {
            HaError::Timeout(format!(
                "HA {role} {context} send timed out after {WS_SEND_TIMEOUT:?}"
            ))
        })?
        .map_err(|e| HaError::Connection(format!("Failed to send {context}: {e}")))
}

/// Serializes and sends one [`HaMessage`] as a WebSocket text frame with the
/// shared [`WS_SEND_TIMEOUT`] write deadline.
pub async fn send_ha_message<S>(
    ws_stream: &mut tokio_tungstenite::WebSocketStream<S>,
    message: &HaMessage,
    role: &str,
    context: &str,
) -> Result<(), HaError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let json = message.to_json()?;
    send_frame(ws_stream, Message::Text(json.into()), role, context).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    #[test]
    fn test_wire_size_matches_serialized_json() {
        let message = HaMessage::Hello {
            instance: "slave-1".to_string(),
            have_version: 7,
            have_term: 2,
            capabilities: vec!["stats-v1".to_string()],
            token: None,
            role: Some("slave".to_string()),
            protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
        };
        let json = message.to_json().unwrap();
        assert_eq!(wire_size(&message), json.len());
    }

    /// The size is a byte count, not a character count: non-ASCII text must be
    /// measured as UTF-8 bytes, exactly as it is framed on the wire. This
    /// pins a raw serializer to keep the test from merely mirroring
    /// `wire_size`'s implementation.
    #[test]
    fn test_wire_size_counts_utf8_bytes() {
        let message = HaMessage::Hello {
            instance: "réplica-λ".to_string(),
            have_version: 1,
            have_term: 0,
            capabilities: Vec::new(),
            token: None,
            role: None,
            protocol_version: None,
        };
        let json = r#"{"type":"hello","instance":"réplica-λ","have_version":1,"have_term":0,"capabilities":[]}"#;
        assert_eq!(wire_size(&message), 90);
        assert_eq!(wire_size(&message), json.len());
        assert_eq!(
            wire_size(&message),
            json.chars().count() + 2,
            "the two non-ASCII characters take two UTF-8 bytes each"
        );
    }

    #[test]
    fn test_frame_text_reads_text_frame() {
        let frame = WsMessage::Text("{\"type\":\"ping\",\"ts\":1}".into());
        assert_eq!(frame_text(&frame), Some("{\"type\":\"ping\",\"ts\":1}"));
    }

    #[test]
    fn test_frame_text_reads_binary_frame() {
        let frame = WsMessage::Binary(b"{\"type\":\"pong\"}".as_slice().into());
        assert_eq!(frame_text(&frame), Some("{\"type\":\"pong\"}"));
    }

    #[test]
    fn test_frame_text_rejects_unsupported_and_invalid_frames() {
        assert_eq!(frame_text(&WsMessage::Ping(Vec::new().into())), None);
        assert_eq!(frame_text(&WsMessage::Pong(Vec::new().into())), None);
        assert_eq!(frame_text(&WsMessage::Close(None)), None);
        // Binary frames that are not valid UTF-8 cannot be parsed as JSON.
        assert_eq!(
            frame_text(&WsMessage::Binary(vec![0xff, 0xfe].into())),
            None
        );
    }

    #[tokio::test]
    async fn test_send_ha_message_writes_text_frame() {
        use tokio_tungstenite::tungstenite::protocol::Role;

        let (local, remote) = tokio::io::duplex(16 * 1024);
        let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            local,
            Role::Server,
            Some(crate::transport::ws_config()),
        )
        .await;
        let mut peer = tokio_tungstenite::WebSocketStream::from_raw_socket(
            remote,
            Role::Client,
            Some(crate::transport::ws_config()),
        )
        .await;

        let message = HaMessage::Ping { ts: 42 };
        send_ha_message(&mut ws, &message, "master", "heartbeat ping")
            .await
            .unwrap();

        let frame = peer.next().await.unwrap().unwrap();
        assert!(matches!(frame, WsMessage::Text(_)));
        assert_eq!(
            frame_text(&frame),
            Some(message.to_json().unwrap().as_str())
        );
    }

    #[tokio::test]
    async fn test_send_frame_writes_raw_pong() {
        use tokio_tungstenite::tungstenite::protocol::Role;

        let (local, remote) = tokio::io::duplex(16 * 1024);
        let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            local,
            Role::Server,
            Some(crate::transport::ws_config()),
        )
        .await;
        let mut peer = tokio_tungstenite::WebSocketStream::from_raw_socket(
            remote,
            Role::Client,
            Some(crate::transport::ws_config()),
        )
        .await;

        send_frame(
            &mut ws,
            WsMessage::Pong(b"keepalive".as_slice().into()),
            "slave",
            "Pong",
        )
        .await
        .unwrap();

        let frame = peer.next().await.unwrap().unwrap();
        assert_eq!(frame, WsMessage::Pong(b"keepalive".as_slice().into()));
    }

    #[tokio::test(start_paused = true)]
    async fn test_send_ha_message_timeout_names_role_and_context() {
        use tokio_tungstenite::tungstenite::protocol::Role;

        // A one-byte pipe plus a message that cannot fit makes the write stall
        // until the shared send deadline expires.
        let (local, _remote) = tokio::io::duplex(1);
        let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            local,
            Role::Server,
            Some(crate::transport::ws_config()),
        )
        .await;

        let message = HaMessage::Hello {
            instance: "stalled-slave".to_string(),
            have_version: 1,
            have_term: 0,
            capabilities: Vec::new(),
            token: None,
            role: Some("slave".to_string()),
            protocol_version: None,
        };
        let err = send_ha_message(&mut ws, &message, "slave", "Hello")
            .await
            .expect_err("a stalled peer must time out");
        match err {
            HaError::Timeout(text) => assert_eq!(
                text,
                format!(
                    "HA slave Hello send timed out after {:?}",
                    crate::transport::WS_SEND_TIMEOUT
                )
            ),
            other => panic!("expected a timeout error, got {other:?}"),
        }
    }
}
