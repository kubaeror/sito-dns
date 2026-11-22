//! Opaque keyset cursor for query-log pagination.
//!
//! # Wire format
//!
//! A cursor is the base64url encoding (no padding) of a fixed 25-byte payload:
//!
//! ```text
//! offset  size  field
//! 0       1     cursor format version (currently 1)
//! 1       8     ts, signed 64-bit big-endian
//! 9       8     id, signed 64-bit big-endian
//! 17      8     first 8 bytes of BLAKE3(filter key)
//! ```
//!
//! The payload is deliberately **not** a stable public format. Callers must
//! treat the string as opaque and only replay it unchanged. The version exists
//! so a future layout can be introduced without accepting a stale cursor.
//!
//! # Filter binding
//!
//! The hash covers the filter parameters that affect the result set:
//! `client`, `domain`, `status`, `qtype`, `from`, `to`, in that fixed order.
//! Each field is length-prefixed and tagged as present/absent, so different
//! field combinations cannot collide by concatenation. `limit` and the cursor
//! itself are excluded: changing the page size while paging is allowed. A
//! cursor replayed against a different filter set is rejected with
//! [`StatsError::InvalidCursor`] instead of silently returning a wrong page.
//!
//! # Keyset semantics
//!
//! Pages are ordered by `(ts, id)` descending and the next page starts strictly
//! below the last returned `(ts, id)`. This is keyset (not snapshot) pagination:
//! rows inserted with a newer `(ts, id)` than the cursor are not seen by later
//! pages, and rows deleted between pages simply disappear. Rows that remain do
//! not duplicate or skip. Ties on `ts` are broken deterministically by `id`.

use base64::Engine as _;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;

use super::QueryLogFilter;
use crate::error::StatsError;

/// Version byte written into every cursor payload.
const CURSOR_VERSION: u8 = 1;

/// Domain separator for the filter hash, so the digest cannot be confused with
/// an unrelated BLAKE3 use.
const FILTER_HASH_DOMAIN: &[u8] = b"sito-querylog-cursor-filter-v1";

/// Total payload length for version 1: version + ts + id + hash prefix.
const PAYLOAD_LEN: usize = 1 + 8 + 8 + 8;

/// Builds an opaque cursor pointing at the last row of a page.
pub(super) fn encode_cursor(filter: &QueryLogFilter, ts: i64, id: i64) -> String {
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[0] = CURSOR_VERSION;
    payload[1..9].copy_from_slice(&ts.to_be_bytes());
    payload[9..17].copy_from_slice(&id.to_be_bytes());
    payload[17..25].copy_from_slice(&filter_hash(filter));
    BASE64_URL_SAFE_NO_PAD.encode(payload)
}

/// Decodes and verifies a cursor against the active filter set.
///
/// Returns the `(ts, id)` keyset position. Every failure (bad base64, wrong
/// length, unknown version, filter mismatch) is [`StatsError::InvalidCursor`],
/// which the API maps to a `400 Bad Request`.
pub(super) fn decode_cursor(filter: &QueryLogFilter, raw: &str) -> Result<(i64, i64), StatsError> {
    let payload = BASE64_URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| invalid("cursor is not valid base64url"))?;

    if payload.len() != PAYLOAD_LEN {
        return Err(invalid(format!(
            "cursor payload must be {PAYLOAD_LEN} bytes, got {}",
            payload.len()
        )));
    }

    if payload[0] != CURSOR_VERSION {
        return Err(invalid(format!(
            "unsupported cursor version {}",
            payload[0]
        )));
    }

    let ts = i64::from_be_bytes(
        payload[1..9]
            .try_into()
            .map_err(|_| invalid("cursor timestamp is malformed"))?,
    );
    let id = i64::from_be_bytes(
        payload[9..17]
            .try_into()
            .map_err(|_| invalid("cursor id is malformed"))?,
    );
    let expected = filter_hash(filter);
    if payload[17..25] != expected {
        return Err(invalid(
            "cursor does not belong to the current filter set; restart from the first page",
        ));
    }

    Ok((ts, id))
}

/// Computes the 8-byte filter binding embedded in a cursor.
fn filter_hash(filter: &QueryLogFilter) -> [u8; 8] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FILTER_HASH_DOMAIN);

    // Fixed canonical order. Each option is tagged and length-prefixed so
    // `("ab", "c")` and `("a", "bc")` cannot hash the same.
    update_optional_bytes(&mut hasher, filter.client.as_deref());
    update_optional_bytes(&mut hasher, filter.domain.as_deref());
    update_optional_bytes(&mut hasher, filter.status.as_deref());
    update_optional_i64(&mut hasher, filter.qtype.map(i64::from));
    update_optional_i64(&mut hasher, filter.from);
    update_optional_i64(&mut hasher, filter.to);

    let digest = hasher.finalize();
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest.as_bytes()[..8]);
    prefix
}

fn update_optional_bytes(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hasher.update(&(value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn update_optional_i64(hasher: &mut blake3::Hasher, value: Option<i64>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hasher.update(&value.to_be_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn invalid(detail: impl Into<String>) -> StatsError {
    StatsError::InvalidCursor(detail.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter() -> QueryLogFilter {
        QueryLogFilter {
            client: Some("192.0.2.10".into()),
            domain: Some("example.com".into()),
            status: Some("blocked".into()),
            qtype: Some(1),
            from: Some(1_700_000_000_000),
            to: Some(1_700_000_086_400),
            ..Default::default()
        }
    }

    #[test]
    fn test_cursor_round_trip() {
        let filter = filter();
        let encoded = encode_cursor(&filter, 1_700_000_000_123, 42);
        assert_eq!(
            decode_cursor(&filter, &encoded).unwrap(),
            (1_700_000_000_123, 42)
        );
    }

    #[test]
    fn test_cursor_is_base64url_without_padding() {
        let encoded = encode_cursor(&filter(), 1, 2);
        assert!(
            !encoded.contains('='),
            "cursor must not be padded: {encoded}"
        );
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "cursor must use the URL-safe alphabet: {encoded}"
        );
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), PAYLOAD_LEN);
        assert_eq!(decoded[0], CURSOR_VERSION);
    }

    #[test]
    fn test_cursor_version_mismatch_is_rejected() {
        let filter = filter();
        let mut decoded = BASE64_URL_SAFE_NO_PAD
            .decode(encode_cursor(&filter, 10, 20))
            .unwrap();
        decoded[0] = 2;
        let cursor = BASE64_URL_SAFE_NO_PAD.encode(decoded);
        let err = decode_cursor(&filter, &cursor).unwrap_err();
        assert!(
            matches!(err, StatsError::InvalidCursor(ref message) if message.contains("version")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_cursor_rejects_bad_base64_and_short_payload() {
        let filter = filter();
        assert!(matches!(
            decode_cursor(&filter, "not a cursor!!").unwrap_err(),
            StatsError::InvalidCursor(message) if message.contains("base64url")
        ));

        let short = BASE64_URL_SAFE_NO_PAD.encode([CURSOR_VERSION, 0, 0]);
        assert!(matches!(
            decode_cursor(&filter, &short).unwrap_err(),
            StatsError::InvalidCursor(message) if message.contains("payload")
        ));
    }

    #[test]
    fn test_cursor_filter_mismatch_is_rejected() {
        let cursor = encode_cursor(&filter(), 10, 20);

        let mut different_client = filter();
        different_client.client = Some("192.0.2.11".into());
        assert!(matches!(
            decode_cursor(&different_client, &cursor).unwrap_err(),
            StatsError::InvalidCursor(message) if message.contains("filter set")
        ));

        // A field that changes the result set must invalidate the cursor even
        // when the cursor is otherwise well formed.
        let mut different_status = filter();
        different_status.status = Some("allowed".into());
        assert!(decode_cursor(&different_status, &cursor).is_err());
    }

    #[test]
    fn test_cursor_filter_hash_ignores_limit_and_cursor() {
        let first = filter();
        let mut second = first.clone();
        second.limit = Some(1);
        second.cursor = Some("ignored".into());

        assert_eq!(filter_hash(&first), filter_hash(&second));
        let cursor = encode_cursor(&first, 5, 6);
        assert_eq!(decode_cursor(&second, &cursor).unwrap(), (5, 6));
    }

    #[test]
    fn test_cursor_filter_hash_separates_absent_and_empty_fields() {
        let absent = QueryLogFilter::default();
        let empty = QueryLogFilter {
            client: Some(String::new()),
            ..Default::default()
        };
        assert_ne!(filter_hash(&absent), filter_hash(&empty));
    }

    #[test]
    fn test_cursor_filter_hash_is_order_and_boundary_safe() {
        let split_a = QueryLogFilter {
            client: Some("ab".into()),
            domain: Some("c".into()),
            ..Default::default()
        };
        let split_b = QueryLogFilter {
            client: Some("a".into()),
            domain: Some("bc".into()),
            ..Default::default()
        };
        assert_ne!(filter_hash(&split_a), filter_hash(&split_b));

        let qtype_only = QueryLogFilter {
            qtype: Some(1),
            ..Default::default()
        };
        let from_only = QueryLogFilter {
            from: Some(1),
            ..Default::default()
        };
        assert_ne!(filter_hash(&qtype_only), filter_hash(&from_only));
    }
}
