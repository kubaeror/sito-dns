//! Role-Based Access Control (RBAC) Axum extractors per section 12.1 and 12.2.
//!
//! Enforces viewer, operator, and admin permissions across REST API endpoints.

use crate::auth::manager::AuthManager;
use crate::auth::rate_limit::ApiAccountKey;
use crate::auth::session::extract_session_cookie;
use crate::auth::token::Role;
use crate::error::ProblemDetails;
use axum::extract::FromRequestParts;
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::request::Parts;
use std::ops::Deref;
use std::sync::Arc;

/// Authenticated user / token context.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub username: String,
    pub role: Role,
    pub token_id: Option<String>,
    /// Account that owns the presented API token. `None` for sessions and for
    /// legacy ownerless tokens, which are Admin-managed rather than tied to an
    /// account. Only used for account-wide bookkeeping such as rate limiting;
    /// `username` keeps exposing the token name for API-token authentication.
    pub owner: Option<String>,
}

/// Extractor requiring at least `Viewer` role (Viewer, Operator, or Admin).
#[derive(Debug, Clone)]
pub struct RequireViewer(pub AuthUser);

/// Extractor requiring at least `Operator` role (Operator or Admin).
#[derive(Debug, Clone)]
pub struct RequireOperator(pub AuthUser);

/// Extractor requiring `Admin` role.
#[derive(Debug, Clone)]
pub struct RequireAdmin(pub AuthUser);

/// Request-scoped marker: the account-wide limiter already charged this
/// request, so a second auth extractor must not consume another token.
#[derive(Debug, Clone, Copy)]
struct ApiRateCharged;

/// Charges the per-account API rate limit once per request.
///
/// Called only after successful authentication, so invalid credentials and the
/// unauthenticated login/TOTP endpoints never consume an account bucket. The
/// marker in the request extensions guarantees that a handler using more than
/// one auth extractor is charged at most once.
fn charge_api_rate_limit(
    parts: &mut Parts,
    auth_mgr: &AuthManager,
    user: &AuthUser,
) -> Result<(), ProblemDetails> {
    if parts.extensions.get::<ApiRateCharged>().is_some() {
        return Ok(());
    }
    let key = match (user.token_id.as_deref(), user.owner.as_deref()) {
        (Some(token_id), None) => ApiAccountKey::Ownerless(token_id),
        (_, Some(owner)) => ApiAccountKey::Account(owner),
        (None, None) => ApiAccountKey::Account(&user.username),
    };
    if let Err(retry_after) = auth_mgr.check_api_rate_limit(key) {
        let limit = auth_mgr.api_rate_limit_per_minute();
        return Err(ProblemDetails::too_many_requests_with_retry(
            format!(
                "API rate limit exceeded for this account: {limit} request(s) per minute. Retry after {retry_after} second(s)."
            ),
            u16::try_from(retry_after).unwrap_or(u16::MAX),
        ));
    }
    parts.extensions.insert(ApiRateCharged);
    Ok(())
}

impl Deref for RequireViewer {
    type Target = AuthUser;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for RequireOperator {
    type Target = AuthUser;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for RequireAdmin {
    type Target = AuthUser;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Helper to authenticate from request parts against AuthManager.
pub fn authenticate_request(
    parts: &Parts,
    auth_mgr: &AuthManager,
) -> Result<AuthUser, ProblemDetails> {
    // 1. Try Bearer token in Authorization header
    if let Some(auth_header) = parts.headers.get(AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let clean_token = token.trim();
        if let Some(meta) = auth_mgr.validate_token(clean_token) {
            return Ok(AuthUser {
                username: meta.name,
                role: meta.scope,
                token_id: Some(meta.id),
                owner: meta.owner,
            });
        }
        return Err(ProblemDetails::unauthorized("Invalid or expired API token"));
    }

    // 2. Try session cookie
    if let Some(cookie_header) = parts.headers.get(COOKIE)
        && let Ok(cookie_str) = cookie_header.to_str()
        && let Some(session_id) = extract_session_cookie(cookie_str)
    {
        if let Some(session) = auth_mgr.validate_session(&session_id) {
            return Ok(AuthUser {
                username: session.username,
                role: session.role,
                token_id: None,
                owner: None,
            });
        }
        return Err(ProblemDetails::unauthorized(
            "Invalid or expired session cookie",
        ));
    }

    Err(ProblemDetails::unauthorized(
        "Authentication required (Bearer token or session cookie)",
    ))
}

// Axum FromRequestParts implementations

#[allow(clippy::unused_async_trait_impl)]
impl<S> FromRequestParts<S> for RequireViewer
where
    S: Send + Sync,
    Arc<AuthManager>: axum::extract::FromRef<S>,
{
    type Rejection = ProblemDetails;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_mgr: Arc<AuthManager> = axum::extract::FromRef::from_ref(state);
        let user = authenticate_request(parts, &auth_mgr)?;
        charge_api_rate_limit(parts, &auth_mgr, &user)?;
        if user.role >= Role::Viewer {
            Ok(RequireViewer(user))
        } else {
            Err(ProblemDetails::forbidden(
                "Insufficient privileges: requires at least Viewer role",
            ))
        }
    }
}

#[allow(clippy::unused_async_trait_impl)]
impl<S> FromRequestParts<S> for RequireOperator
where
    S: Send + Sync,
    Arc<AuthManager>: axum::extract::FromRef<S>,
{
    type Rejection = ProblemDetails;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_mgr: Arc<AuthManager> = axum::extract::FromRef::from_ref(state);
        let user = authenticate_request(parts, &auth_mgr)?;
        charge_api_rate_limit(parts, &auth_mgr, &user)?;
        if user.role >= Role::Operator {
            Ok(RequireOperator(user))
        } else {
            Err(ProblemDetails::forbidden(
                "Insufficient privileges: requires at least Operator role",
            ))
        }
    }
}

#[allow(clippy::unused_async_trait_impl)]
impl<S> FromRequestParts<S> for RequireAdmin
where
    S: Send + Sync,
    Arc<AuthManager>: axum::extract::FromRef<S>,
{
    type Rejection = ProblemDetails;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_mgr: Arc<AuthManager> = axum::extract::FromRef::from_ref(state);
        let user = authenticate_request(parts, &auth_mgr)?;
        charge_api_rate_limit(parts, &auth_mgr, &user)?;
        if user.role >= Role::Admin {
            Ok(RequireAdmin(user))
        } else {
            Err(ProblemDetails::forbidden(
                "Insufficient privileges: requires Admin role",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use axum::http::header::{AUTHORIZATION, CONNECTION, UPGRADE};

    #[tokio::test]
    async fn test_query_token_rejected_for_non_websocket_requests() {
        let mgr = AuthManager::new();
        let (_, resp) = mgr
            .create_token("ws", Role::Viewer, None)
            .await
            .expect("token");
        let req = Request::builder()
            .uri(format!("/api/v2/querylog?token={}", resp.token))
            .body(())
            .unwrap();
        let (parts, ()) = req.into_parts();
        let err = authenticate_request(&parts, &mgr).unwrap_err();
        assert!(err.detail.contains("Authentication required"));
    }

    /// BC-8: the legacy query parameter is not accepted on any path, including
    /// the query-log WebSocket upgrade.
    #[tokio::test]
    async fn test_querylog_stream_rejects_query_token() {
        let mgr = AuthManager::new();
        let (_, resp) = mgr
            .create_token("ws", Role::Viewer, None)
            .await
            .expect("token");

        let req = Request::builder()
            .uri(format!("/api/v2/querylog/stream?token={}", resp.token))
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "Upgrade")
            .body(())
            .unwrap();
        let (parts, ()) = req.into_parts();
        let err = authenticate_request(&parts, &mgr).unwrap_err();
        assert!(err.detail.contains("Authentication required"));
    }

    #[tokio::test]
    async fn test_querylog_stream_accepts_bearer_header() {
        let mgr = AuthManager::new();
        let (_, resp) = mgr
            .create_token("ws", Role::Viewer, None)
            .await
            .expect("token");

        let req = Request::builder()
            .uri("/api/v2/querylog/stream")
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "Upgrade")
            .header(AUTHORIZATION, format!("Bearer {}", resp.token))
            .body(())
            .unwrap();
        let (parts, ()) = req.into_parts();
        let user = authenticate_request(&parts, &mgr).expect("Bearer token");
        assert_eq!(user.role, Role::Viewer);
    }

    // ------------------------------------------------------------------
    // Per-account API rate limit (D5a)
    // ------------------------------------------------------------------

    use crate::auth::manager::LoginResult;
    use crate::state::ServerContext;
    use crate::test_support::{mock_context, temp_dir};
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    fn viewer_parts_bearer(token: &str) -> Parts {
        Request::builder()
            .uri("/api/v2/status")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    fn viewer_parts_session(session_id: &str) -> Parts {
        Request::builder()
            .uri("/api/v2/status")
            .header(COOKIE, format!("sito_session={session_id}"))
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    fn viewer_parts_unauthenticated() -> Parts {
        Request::builder()
            .uri("/api/v2/status")
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    async fn add_account(ctx: &ServerContext, username: &str, ip: &str) -> String {
        ctx.auth_mgr
            .create_user(username, "correct horse battery staple", Role::Viewer)
            .await;
        match ctx
            .auth_mgr
            .login(username, "correct horse battery staple", ip)
            .await
        {
            LoginResult::Success(session) => session.id,
            other => panic!("login for {username} failed: {other:?}"),
        }
    }

    async fn extract_viewer(
        ctx: &ServerContext,
        mut parts: Parts,
    ) -> Result<RequireViewer, ProblemDetails> {
        <RequireViewer as FromRequestParts<ServerContext>>::from_request_parts(&mut parts, ctx)
            .await
    }

    #[tokio::test]
    async fn test_account_limit_is_independent_and_session_token_share_a_bucket() {
        let dir = temp_dir("sito_api_rate_accounts");
        let ctx = mock_context(&dir).await;
        ctx.auth_mgr.set_api_rate_limit(1);

        let alice_session = add_account(&ctx, "alice", "10.0.1.1").await;
        let bob_session = add_account(&ctx, "bob", "10.0.1.2").await;
        let (_, alice_token) = ctx
            .auth_mgr
            .create_token("alice-ci", Role::Viewer, Some("alice"))
            .await
            .expect("alice token");

        // The session uses alice's only request for this window.
        extract_viewer(&ctx, viewer_parts_session(&alice_session))
            .await
            .expect("alice's first request is allowed");
        // Bob has his own bucket and is unaffected.
        extract_viewer(&ctx, viewer_parts_session(&bob_session))
            .await
            .expect("bob has an independent allowance");
        // Alice's API token shares the account bucket, so it is already spent.
        let err = extract_viewer(&ctx, viewer_parts_bearer(&alice_token.token))
            .await
            .expect_err("an owned token must share the owner's bucket");
        assert_eq!(err.status, 429);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_ownerless_tokens_have_separate_buckets() {
        let dir = temp_dir("sito_api_rate_ownerless");
        let ctx = mock_context(&dir).await;
        ctx.auth_mgr.set_api_rate_limit(1);

        let (_, first) = ctx
            .auth_mgr
            .create_token("legacy-a", Role::Viewer, None)
            .await
            .expect("first ownerless token");
        let (_, second) = ctx
            .auth_mgr
            .create_token("legacy-b", Role::Viewer, None)
            .await
            .expect("second ownerless token");

        extract_viewer(&ctx, viewer_parts_bearer(&first.token))
            .await
            .expect("first token has its own allowance");
        let err = extract_viewer(&ctx, viewer_parts_bearer(&first.token))
            .await
            .expect_err("the same ownerless token is limited");
        assert_eq!(err.status, 429);
        extract_viewer(&ctx, viewer_parts_bearer(&second.token))
            .await
            .expect("a different ownerless token has a separate bucket");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_zero_disables_and_failed_auth_does_not_consume_a_bucket() {
        let dir = temp_dir("sito_api_rate_disabled");
        let ctx = mock_context(&dir).await;
        let session = add_account(&ctx, "carol", "10.0.1.3").await;

        // Failed authentication returns before the limiter is charged.
        ctx.auth_mgr.set_api_rate_limit(1);
        let err = extract_viewer(&ctx, viewer_parts_unauthenticated())
            .await
            .expect_err("missing credentials are rejected");
        assert_eq!(err.status, 401);
        extract_viewer(&ctx, viewer_parts_session(&session))
            .await
            .expect("a failed auth attempt must not consume the account's allowance");

        // 0 disables the account-wide ceiling entirely.
        ctx.auth_mgr.set_api_rate_limit(0);
        for _ in 0..8 {
            extract_viewer(&ctx, viewer_parts_session(&session))
                .await
                .expect("a disabled limit never rejects");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_rate_limit_rejection_has_problem_details_and_retry_after() {
        let dir = temp_dir("sito_api_rate_headers");
        let ctx = mock_context(&dir).await;
        ctx.auth_mgr.set_api_rate_limit(1);
        let session = add_account(&ctx, "dave", "10.0.1.4").await;

        extract_viewer(&ctx, viewer_parts_session(&session))
            .await
            .expect("first request is allowed");
        let err = extract_viewer(&ctx, viewer_parts_session(&session))
            .await
            .expect_err("second request is limited");

        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("60"),
            "Retry-After must report seconds until the window resets"
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/problem+json")
        );
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read problem body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("problem JSON");
        assert_eq!(body["status"], 429);
        assert_eq!(body["title"], "Too Many Requests");
        let detail = body["detail"].as_str().expect("detail string");
        assert!(
            detail.contains("1 request(s) per minute"),
            "detail must include the configured limit: {detail}"
        );
        assert!(
            body.get("retry_after_secs").is_none(),
            "the retry hint belongs in the header, not the JSON body"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A handler that extracts two auth types must be charged only once.
    #[tokio::test]
    async fn test_multiple_extractors_charge_once_per_request() {
        let dir = temp_dir("sito_api_rate_once");
        let ctx = mock_context(&dir).await;
        ctx.auth_mgr.set_api_rate_limit(1);
        let session = add_account(&ctx, "erin", "10.0.1.5").await;
        let mut parts = viewer_parts_session(&session);

        <RequireViewer as FromRequestParts<ServerContext>>::from_request_parts(&mut parts, &ctx)
            .await
            .expect("first extractor consumes the only request");
        <RequireViewer as FromRequestParts<ServerContext>>::from_request_parts(&mut parts, &ctx)
            .await
            .expect("a second extractor on the same request must not charge again");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
