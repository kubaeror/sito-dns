//! DNS cache management endpoints.

use axum::Json;
use axum::extract::{Query, State};
use std::str::FromStr;

use crate::auth::rbac::RequireOperator;
use crate::error::ProblemDetails;
use crate::models::{GenericMessageResponse, InvalidateCacheQuery};
use crate::state::ServerContext;

/// Flush entire DNS response cache.
#[utoipa::path(
    post,
    path = "/api/v2/cache/flush",
    responses(
        (status = 200, description = "Cache flushed successfully", body = GenericMessageResponse),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    tag = "Cache",
)]
pub async fn flush_cache(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
) -> Json<GenericMessageResponse> {
    ctx.cache.flush();
    ctx.publish_cache_size();
    Json(GenericMessageResponse {
        message: "DNS cache flushed successfully".to_string(),
    })
}

/// Invalidate cache entries matching a domain.
#[utoipa::path(
    post,
    path = "/api/v2/cache/invalidate",
    params(InvalidateCacheQuery),
    responses(
        (status = 200, description = "Cache entries invalidated", body = GenericMessageResponse),
        (status = 400, description = "Bad request", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    tag = "Cache",
)]
pub async fn invalidate_cache(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Query(query): Query<InvalidateCacheQuery>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    let domain = query.domain.trim();
    if domain.is_empty() {
        return Err(ProblemDetails::bad_request(
            "domain parameter must not be empty",
        ));
    }

    // Reject unparseable domains instead of reporting a successful
    // invalidation for a string the cache can never match.
    let name = sito_proto::Name::from_str(domain)
        .map_err(|e| ProblemDetails::bad_request(format!("Invalid domain name '{domain}': {e}")))?;

    ctx.cache.invalidate_domain(&name.to_string());
    ctx.publish_cache_size();

    Ok(Json(GenericMessageResponse {
        message: format!("Invalidated cache entries matching '{}'", query.domain),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::rbac::{AuthUser, RequireOperator};
    use crate::auth::token::Role;

    fn operator() -> RequireOperator {
        RequireOperator(AuthUser {
            username: "operator".to_string(),
            role: Role::Operator,
            token_id: None,
        })
    }

    /// P2-63: a flush/invalidate must publish the reclaimed cache footprint;
    /// otherwise `sito_cache_size_bytes` reports memory that is already free.
    #[tokio::test]
    async fn test_cache_management_updates_size_gauge() {
        use sito_proto::{Message, MessageType, OpCode, Query, RData, Record, RecordType};

        async fn seed(ctx: &crate::state::ServerContext, name: &str) {
            let name = sito_proto::Name::from_ascii(name).unwrap();
            let mut query = Message::new(43, MessageType::Query, OpCode::Query);
            query
                .queries
                .push(Query::query(name.clone(), RecordType::A));
            let mut response = Message::response(43, OpCode::Query);
            response.queries = query.queries.clone();
            response.answers.push(Record::from_rdata(
                name,
                300,
                RData::A(sito_proto::rdata::A("192.0.2.210".parse().unwrap())),
            ));
            ctx.cache.insert(&query, &response).await;
        }

        let temp_dir = crate::test_support::temp_dir("sito_cache_size_gauge");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        seed(&ctx, "keep.example.").await;
        seed(&ctx, "drop.example.").await;
        // Seed a deliberately wrong gauge: moka's weight accounting may settle
        // asynchronously, so the assertion is that the handler republishes the
        // cache's current weight, not a particular byte count.
        ctx.metrics.set_cache_size_bytes(4_096);

        let _ = flush_cache(operator(), State(ctx.clone())).await;
        assert_eq!(ctx.cache.weighted_size(), 0);
        assert!(
            ctx.metrics
                .render_prometheus()
                .contains("sito_cache_size_bytes 0"),
            "flush must publish the empty cache size"
        );

        seed(&ctx, "keep.example.").await;
        seed(&ctx, "drop.example.").await;
        ctx.metrics.set_cache_size_bytes(4_096);

        let _ = invalidate_cache(
            operator(),
            State(ctx.clone()),
            Query(InvalidateCacheQuery {
                domain: "drop.example".to_string(),
            }),
        )
        .await
        .expect("valid domain accepted");

        let after = ctx.cache.weighted_size();
        assert!(
            ctx.metrics
                .render_prometheus()
                .contains(&format!("sito_cache_size_bytes {after}")),
            "invalidate must publish the current cache size"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// WP-4.5: an unparseable domain must be a 400, not a fake success.
    #[tokio::test]
    async fn test_invalidate_cache_rejects_unparseable_domains() {
        let temp_dir = crate::test_support::temp_dir("sito_cache_invalidate");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        for domain in ["not a domain!!", "exa mple.com", "..", "a..b"] {
            let err = invalidate_cache(
                operator(),
                State(ctx.clone()),
                Query(InvalidateCacheQuery {
                    domain: domain.to_string(),
                }),
            )
            .await
            .expect_err("unparseable domain must be rejected");
            assert_eq!(err.status, 400, "domain '{domain}' must yield 400");
        }

        let ok = invalidate_cache(
            operator(),
            State(ctx.clone()),
            Query(InvalidateCacheQuery {
                domain: "example.com".to_string(),
            }),
        )
        .await
        .expect("valid domain accepted");
        assert!(ok.0.message.contains("example.com"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// The REST invalidation path must evict seeded entries (including a
    /// non-plain key variant) and leave unrelated names alone.
    #[tokio::test]
    async fn test_invalidate_cache_evicts_seeded_entries() {
        use sito_proto::rdata::A;
        use sito_proto::{
            DNSClass, Edns, Message, MessageType, Name, OpCode, Query, RData, Record, RecordType,
        };
        use std::str::FromStr;

        let temp_dir = crate::test_support::temp_dir("sito_cache_invalidate_seeded");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let name = Name::from_str("example.com.").unwrap();
        let other = Name::from_str("other.example.").unwrap();

        let mut plain = Message::new(1, MessageType::Query, OpCode::Query);
        plain
            .queries
            .push(Query::query(name.clone(), RecordType::A));
        let mut plain_response = Message::response(1, OpCode::Query);
        plain_response.queries = plain.queries.clone();
        plain_response.answers.push(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        ctx.cache.insert(&plain, &plain_response).await;

        let mut edns_query = plain.clone();
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns_query.set_edns(edns);
        let mut edns_response = Message::response(2, OpCode::Query);
        edns_response.queries = edns_query.queries.clone();
        edns_response.answers.push(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A("192.0.2.2".parse().unwrap())),
        ));
        ctx.cache.insert(&edns_query, &edns_response).await;

        let mut other_query = Message::new(3, MessageType::Query, OpCode::Query);
        other_query
            .queries
            .push(Query::query(other.clone(), RecordType::A));
        let mut other_response = Message::response(3, OpCode::Query);
        other_response.queries = other_query.queries.clone();
        other_response.answers.push(Record::from_rdata(
            other.clone(),
            300,
            RData::A(A("192.0.2.3".parse().unwrap())),
        ));
        ctx.cache.insert(&other_query, &other_response).await;

        assert!(ctx.cache.get_for_query(&plain).await.is_some());
        assert!(ctx.cache.get_for_query(&edns_query).await.is_some());

        let ok = invalidate_cache(
            operator(),
            State(ctx.clone()),
            Query(InvalidateCacheQuery {
                domain: "example.com".to_string(),
            }),
        )
        .await
        .expect("valid domain accepted");
        assert!(ok.0.message.contains("example.com"));

        assert!(
            ctx.cache
                .get(&name, RecordType::A, DNSClass::IN)
                .await
                .is_none(),
            "the plain entry must be evicted"
        );
        assert!(
            ctx.cache.get_for_query(&edns_query).await.is_none(),
            "DO/EDNS key variants must be evicted too"
        );
        assert!(
            ctx.cache.get_for_query(&other_query).await.is_some(),
            "an unrelated name must survive"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
