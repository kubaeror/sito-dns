//! Core Upstream trait definition.

use async_trait::async_trait;
use sito_core::error::UpstreamError;
use sito_proto::{Message, MessageType};

/// Trait implemented by DNS upstream resolvers.
#[async_trait]
pub trait Upstream: Send + Sync {
    /// Resolve a DNS query against the upstream.
    async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError>;

    /// Optional periodic maintenance hook, called by the health prober for
    /// multi-address upstreams that need to re-resolve their hostname.
    /// The default implementation is a no-op and never fails.
    async fn refresh(&self) -> Result<(), UpstreamError> {
        Ok(())
    }
}

/// Validates that a decoded upstream response actually answers the query that
/// was sent: message ID, QR bit and (when present) the question section must
/// match. This prevents mismatched/spoofed replies from being accepted.
pub fn validate_response(query: &Message, response: &Message) -> Result<(), UpstreamError> {
    if response.metadata.message_type != MessageType::Response {
        return Err(UpstreamError::BadResponse(
            "upstream reply is not a response message".to_string(),
        ));
    }

    if response.metadata.id != query.metadata.id {
        return Err(UpstreamError::BadResponse(format!(
            "upstream reply ID mismatch: expected {}, got {}",
            query.metadata.id, response.metadata.id
        )));
    }

    if let Some(expected) = query.queries.first() {
        match response.queries.first() {
            Some(actual) => {
                if actual.name() != expected.name()
                    || actual.query_type() != expected.query_type()
                    || actual.query_class() != expected.query_class()
                {
                    return Err(UpstreamError::BadResponse(
                        "upstream reply question does not match the query".to_string(),
                    ));
                }
            }
            None => {
                return Err(UpstreamError::BadResponse(
                    "upstream reply is missing the question section".to_string(),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sito_proto::{OpCode, Query, RecordType};
    use std::str::FromStr;

    fn make_query() -> Message {
        let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            sito_proto::Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        query
    }

    #[test]
    fn test_validate_response_accepts_matching_reply() {
        let query = make_query();
        let mut response = Message::response(0x1234, OpCode::Query);
        response.queries = query.queries.clone();
        assert!(validate_response(&query, &response).is_ok());
    }

    #[test]
    fn test_validate_response_rejects_id_mismatch() {
        let query = make_query();
        let mut response = Message::response(0x9999, OpCode::Query);
        response.queries = query.queries.clone();
        assert!(validate_response(&query, &response).is_err());
    }

    #[test]
    fn test_validate_response_rejects_question_mismatch() {
        let query = make_query();
        let mut response = Message::response(0x1234, OpCode::Query);
        response.queries.push(Query::query(
            sito_proto::Name::from_str("evil.example.").unwrap(),
            RecordType::A,
        ));
        assert!(validate_response(&query, &response).is_err());

        let missing_question = Message::response(0x1234, OpCode::Query);
        assert!(validate_response(&query, &missing_question).is_err());
    }
}
