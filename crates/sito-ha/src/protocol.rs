//! High Availability (HA) replication protocol message definitions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::HaError;

/// Protocol version number.
pub const PROTOCOL_VERSION: u32 = 1;

/// High-level protocol messages exchanged over the WebSocket replication channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum HaMessage {
    /// Slave announces presence and local synchronized version after TLS handshake.
    #[serde(rename = "hello")]
    Hello {
        instance: String,
        have_version: u64,
        #[serde(default)]
        capabilities: Vec<String>,
    },

    /// Master pushes a signed configuration state bundle to connected slave(s).
    #[serde(rename = "config_push")]
    ConfigPush {
        version: u64,
        hash_blake3: String,
        signature_ed25519: String,
        payload_b64: String,
        payload_hash_blake3: String,
    },

    /// Slave acknowledges success or failure of applying a received configuration push.
    #[serde(rename = "ack")]
    Ack {
        version: u64,
        applied: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },

    /// Periodic health and traffic statistics report from slave to master (every 30s).
    #[serde(rename = "stats_report")]
    StatsReport {
        window_s: u64,
        queries: u64,
        blocked: u64,
        #[serde(default)]
        upstreams: HashMap<String, UpstreamReport>,
    },

    /// Heartbeat ping sent every 15s.
    #[serde(rename = "ping")]
    Ping { ts: u64 },

    /// Heartbeat response to ping.
    #[serde(rename = "pong")]
    Pong { ts: u64 },
}

impl HaMessage {
    /// Serializes message to JSON string.
    pub fn to_json(&self) -> Result<String, HaError> {
        serde_json::to_string(self)
            .map_err(|e| HaError::Serialization(format!("Failed to serialize HA message: {e}")))
    }

    /// Deserializes message from JSON string.
    pub fn from_json(s: &str) -> Result<Self, HaError> {
        serde_json::from_str(s)
            .map_err(|e| HaError::Protocol(format!("Failed to parse HA message: {e}")))
    }
}

/// Upstream health metrics included in periodic stats reports.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpstreamReport {
    pub rtt_ms: f64,
    pub errors: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_message_serialization_roundtrip() {
        let hello = HaMessage::Hello {
            instance: "slave-pi".to_string(),
            have_version: 41,
            capabilities: vec!["stats-v1".to_string()],
        };
        let json = hello.to_json().unwrap();
        assert!(json.contains("\"type\":\"hello\""));
        assert!(json.contains("\"instance\":\"slave-pi\""));
        assert!(json.contains("\"have_version\":41"));

        let deserialized = HaMessage::from_json(&json).unwrap();
        assert_eq!(hello, deserialized);

        let push = HaMessage::ConfigPush {
            version: 42,
            hash_blake3: "hash1".to_string(),
            signature_ed25519: "sig1".to_string(),
            payload_b64: "payload1".to_string(),
            payload_hash_blake3: "hash1".to_string(),
        };
        let push_json = push.to_json().unwrap();
        assert!(push_json.contains("\"type\":\"config_push\""));
        let push_de = HaMessage::from_json(&push_json).unwrap();
        assert_eq!(push, push_de);

        let ack = HaMessage::Ack {
            version: 42,
            applied: true,
            error: None,
        };
        let ack_json = ack.to_json().unwrap();
        assert!(ack_json.contains("\"type\":\"ack\""));
        assert_eq!(ack, HaMessage::from_json(&ack_json).unwrap());

        let mut upstreams = HashMap::new();
        upstreams.insert(
            "tls://a".to_string(),
            UpstreamReport {
                rtt_ms: 8.2,
                errors: 0,
            },
        );
        let stats = HaMessage::StatsReport {
            window_s: 30,
            queries: 81234,
            blocked: 12044,
            upstreams,
        };
        let stats_json = stats.to_json().unwrap();
        assert!(stats_json.contains("\"type\":\"stats_report\""));
        assert_eq!(stats, HaMessage::from_json(&stats_json).unwrap());

        let ping = HaMessage::Ping { ts: 1_690_000_000 };
        let pong = HaMessage::Pong { ts: 1_690_000_000 };
        assert_eq!(
            ping,
            HaMessage::from_json(&ping.to_json().unwrap()).unwrap()
        );
        assert_eq!(
            pong,
            HaMessage::from_json(&pong.to_json().unwrap()).unwrap()
        );
    }
}
