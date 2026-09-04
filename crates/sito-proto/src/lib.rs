//! `sito-proto`
//!
//! Wire format decoding, encoding, domain name normalization, and synthesized responses for sito.

pub mod error;
pub mod normalize;
pub mod wire;

pub use error::ProtoError;
pub use normalize::normalize_domain;
pub use wire::{
    DOT_PADDING_BLOCK_SIZE, apply_dot_padding, client_edns_payload_size, decode_message,
    encode_message, extract_query_info, set_edns_payload_size, synthesize_blocked_response,
};

// Re-export core hickory types so other sito crates don't need direct hickory-proto dependency
pub use hickory_proto::op::{
    Edns, Header, Message, MessageType, Metadata, OpCode, Query, ResponseCode,
};
pub use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
