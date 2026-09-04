//! DNS wire-format encoding, decoding, and synthesized responses.

use crate::error::ProtoError;
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use sito_core::config::BlockingMode;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Parse a raw DNS message buffer into a Hickory Message.
pub fn decode_message(bytes: &[u8]) -> Result<Message, ProtoError> {
    Message::from_vec(bytes).map_err(|e| ProtoError::DecodeError(e.to_string()))
}

/// Serialize a Hickory Message into wire-format bytes.
pub fn encode_message(msg: &Message) -> Result<Vec<u8>, ProtoError> {
    msg.to_vec()
        .map_err(|e| ProtoError::EncodeError(e.to_string()))
}

/// Extract primary query question information (Name, RecordType, DNSClass).
pub fn extract_query_info(msg: &Message) -> Option<(Name, RecordType, DNSClass)> {
    msg.queries
        .first()
        .map(|q| (q.name().clone(), q.query_type(), q.query_class()))
}

/// Get the maximum UDP payload size advertised by the client via EDNS(0).
/// Defaults to 512 bytes if EDNS(0) is not present, clamped to minimum 512.
pub fn client_edns_payload_size(msg: &Message) -> u16 {
    if let Some(edns) = &msg.edns {
        edns.max_payload().max(512)
    } else {
        512
    }
}

/// Set EDNS with maximum payload size.
pub fn set_edns_payload_size(msg: &mut Message, max_payload: u16) {
    let mut edns = msg.edns.clone().unwrap_or_default();
    edns.set_max_payload(max_payload);
    msg.set_edns(edns);
}

/// Default block size for RFC 8467 DNS-over-TLS response padding.
pub const DOT_PADDING_BLOCK_SIZE: usize = 468;

/// Apply RFC 8467 block-length padding to a DNS message using EDNS(0) option 12.
pub fn apply_dot_padding(msg: &mut Message, block_size: usize) -> Result<(), ProtoError> {
    use hickory_proto::rr::rdata::opt::EdnsOption;

    if block_size == 0 {
        return Ok(());
    }

    if msg.edns.is_none() {
        msg.set_edns(Edns::new());
    }

    let wire = encode_message(msg)?;
    let current_len = wire.len();

    let mut target_len = if current_len % block_size == 0 {
        current_len
    } else {
        ((current_len / block_size) + 1) * block_size
    };

    if target_len < current_len + 4 {
        target_len += block_size;
    }

    let padding_len = target_len - (current_len + 4);
    if let Some(edns) = msg.edns.as_mut() {
        edns.options_mut()
            .insert(EdnsOption::Unknown(12, vec![0u8; padding_len]));
    }

    Ok(())
}

/// Synthesize a response for a blocked domain according to the configured BlockingMode.
pub fn synthesize_blocked_response(
    query: &Message,
    blocking_mode: &BlockingMode,
    blocking_ttl: u32,
) -> Message {
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.queries.clone_from(&query.queries);

    // Echo back EDNS if client had it
    if let Some(client_edns) = &query.edns {
        let mut resp_edns = Edns::new();
        resp_edns.set_max_payload(client_edns.max_payload());
        response.set_edns(resp_edns);
    }

    match blocking_mode {
        BlockingMode::ZeroIp => {
            response.metadata.response_code = ResponseCode::NoError;
            for query_item in &query.queries {
                let name = query_item.name().clone();
                match query_item.query_type() {
                    RecordType::A => {
                        let record = Record::from_rdata(
                            name,
                            blocking_ttl,
                            RData::A(A(Ipv4Addr::UNSPECIFIED)),
                        );
                        response.answers.push(record);
                    }
                    RecordType::AAAA => {
                        let record = Record::from_rdata(
                            name,
                            blocking_ttl,
                            RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
                        );
                        response.answers.push(record);
                    }
                    _ => {
                        // NODATA: NOERROR with empty answer section
                    }
                }
            }
        }
        BlockingMode::Nxdomain => {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
        BlockingMode::Refused => {
            response.metadata.response_code = ResponseCode::Refused;
        }
        BlockingMode::CustomIp(ip) => {
            response.metadata.response_code = ResponseCode::NoError;
            for query_item in &query.queries {
                let name = query_item.name().clone();
                match (query_item.query_type(), ip) {
                    (RecordType::A, std::net::IpAddr::V4(v4)) => {
                        let record = Record::from_rdata(name, blocking_ttl, RData::A(A(*v4)));
                        response.answers.push(record);
                    }
                    (RecordType::AAAA, std::net::IpAddr::V6(v6)) => {
                        let record = Record::from_rdata(name, blocking_ttl, RData::AAAA(AAAA(*v6)));
                        response.answers.push(record);
                    }
                    _ => {}
                }
            }
        }
        BlockingMode::NullRdata => {
            response.metadata.response_code = ResponseCode::NoError;
            // Empty answer section for all query types (NODATA)
        }
    }

    response
}

/// Synthesize a response containing a CNAME record.
pub fn synthesize_cname_response(query: &Message, cname_target: &Name, ttl: u32) -> Message {
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = ResponseCode::NoError;
    response.queries.clone_from(&query.queries);

    if let Some(client_edns) = &query.edns {
        let mut resp_edns = Edns::new();
        resp_edns.set_max_payload(client_edns.max_payload());
        response.set_edns(resp_edns);
    }

    if let Some(q) = query.queries.first() {
        let record = Record::from_rdata(
            q.name().clone(),
            ttl,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(cname_target.clone())),
        );
        response.answers.push(record);
    }

    response
}

/// Synthesize a response containing custom answer records.
pub fn synthesize_records_response(query: &Message, answers: Vec<Record>) -> Message {
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = ResponseCode::NoError;
    response.queries.clone_from(&query.queries);

    if let Some(client_edns) = &query.edns {
        let mut resp_edns = Edns::new();
        resp_edns.set_max_payload(client_edns.max_payload());
        response.set_edns(resp_edns);
    }

    response.answers = answers;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use std::str::FromStr;

    #[test]
    fn test_apply_dot_padding() {
        let mut msg = Message::new(1234, MessageType::Response, OpCode::Query);
        let qname = Name::from_str("example.com.").unwrap();
        msg.queries.push(Query::query(qname, RecordType::A));

        apply_dot_padding(&mut msg, DOT_PADDING_BLOCK_SIZE).unwrap();

        let encoded = encode_message(&msg).unwrap();
        assert_eq!(encoded.len() % DOT_PADDING_BLOCK_SIZE, 0);
        assert_eq!(encoded.len(), 468);

        // Decode and verify EDNS option exists
        let decoded = decode_message(&encoded).unwrap();
        assert!(decoded.edns.is_some());
    }

    #[test]
    fn test_synthesize_blocked_zero_ip_a_record() {
        let mut query = Message::new(1234, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        let qname = Name::from_str("ads.example.com.").unwrap();
        let q = Query::query(qname.clone(), RecordType::A);
        query.queries.push(q);

        let resp = synthesize_blocked_response(&query, &BlockingMode::ZeroIp, 60);
        assert_eq!(resp.metadata.id, 1234);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        let ans = &resp.answers[0];
        assert_eq!(ans.name, qname);
        assert_eq!(ans.record_type(), RecordType::A);
        assert_eq!(ans.ttl, 60);
        assert_eq!(ans.data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_synthesize_blocked_zero_ip_aaaa_record() {
        let mut query = Message::new(5678, MessageType::Query, OpCode::Query);
        let qname = Name::from_str("track.example.com.").unwrap();
        let q = Query::query(qname.clone(), RecordType::AAAA);
        query.queries.push(q);

        let resp = synthesize_blocked_response(&query, &BlockingMode::ZeroIp, 10);
        assert_eq!(resp.metadata.id, 5678);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        let ans = &resp.answers[0];
        assert_eq!(ans.record_type(), RecordType::AAAA);
        assert_eq!(ans.ttl, 10);
        assert_eq!(ans.data, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_synthesize_blocked_zero_ip_nodata_for_other_types() {
        let mut query = Message::new(9999, MessageType::Query, OpCode::Query);
        let qname = Name::from_str("ads.example.com.").unwrap();
        let q = Query::query(qname.clone(), RecordType::TXT);
        query.queries.push(q);

        let resp = synthesize_blocked_response(&query, &BlockingMode::ZeroIp, 60);
        assert_eq!(resp.metadata.id, 9999);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty()); // NODATA
    }

    #[test]
    fn test_synthesize_blocked_nxdomain() {
        let mut query = Message::new(42, MessageType::Query, OpCode::Query);
        let qname = Name::from_str("ads.example.com.").unwrap();
        query.queries.push(Query::query(qname, RecordType::A));

        let resp = synthesize_blocked_response(&query, &BlockingMode::Nxdomain, 60);
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
        assert!(resp.answers.is_empty());
    }

    #[test]
    fn test_synthesize_blocked_refused() {
        let mut query = Message::new(43, MessageType::Query, OpCode::Query);
        let qname = Name::from_str("ads.example.com.").unwrap();
        query.queries.push(Query::query(qname, RecordType::A));

        let resp = synthesize_blocked_response(&query, &BlockingMode::Refused, 60);
        assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
    }

    #[test]
    fn test_synthesize_blocked_null_rdata() {
        let mut query = Message::new(44, MessageType::Query, OpCode::Query);
        let qname = Name::from_str("ads.example.com.").unwrap();
        query.queries.push(Query::query(qname, RecordType::A));

        let resp = synthesize_blocked_response(&query, &BlockingMode::NullRdata, 60);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty());
    }

    #[test]
    fn test_synthesize_blocked_custom_ip() {
        let mut query = Message::new(45, MessageType::Query, OpCode::Query);
        let qname = Name::from_str("ads.example.com.").unwrap();
        query.queries.push(Query::query(qname, RecordType::A));

        let ip = "192.168.1.10".parse().unwrap();
        let resp = synthesize_blocked_response(&query, &BlockingMode::CustomIp(ip), 60);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(
            resp.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 10)))
        );
    }
}
