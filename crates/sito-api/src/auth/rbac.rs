//! Role-Based Access Control (RBAC) Axum extractors per section 12.1 and 12.2.
//!
//! Enforces viewer, operator, and admin permissions across REST API endpoints.

use crate::auth::manager::AuthManager;
use crate::auth::session::extract_session_cookie;
use crate::auth::token::Role;
use crate::error::ProblemDetails;
use axum::extract::FromRequestParts;
use axum::http::header::{AUTHORIZATION, CONNECTION, COOKIE, UPGRADE};
use axum::http::request::Parts;
use std::collections::HashSet;
use std::ops::Deref;
use std::sync::{Arc, Mutex, OnceLock};

/// Authenticated user / token context.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub username: String,
    pub role: Role,
    pub token_id: Option<String>,
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

/// True when the request is a WebSocket upgrade (`Upgrade: websocket` +
/// `Connection: Upgrade`).
pub fn is_websocket_upgrade(parts: &Parts) -> bool {
    let upgrade = parts
        .headers
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let connection = parts
        .headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        });
    upgrade && connection
}

/// Logs the `?token=` deprecation warning once per API token (identified by
/// its Blake3 digest so plaintext tokens never reach the logs).
fn warn_query_token_deprecation(token: &str) {
    static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let digest = blake3::hash(token.as_bytes()).to_hex().to_string();
    let warned = WARNED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut set = warned
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if set.insert(digest) {
        tracing::warn!(
            "Deprecated `?token=` query authentication used on a WebSocket upgrade. \
             Support will be removed in sito 2.0; use the `Authorization: Bearer` header instead."
        );
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
            });
        }
        return Err(ProblemDetails::unauthorized(
            "Invalid or expired session cookie",
        ));
    }

    // 3. Legacy `?token=` query parameter: only for WebSocket upgrades without
    //    an Authorization header. Deprecated, warned and slated for removal in
    //    2.0. Every other endpoint must use the header or a session cookie.
    if is_websocket_upgrade(parts)
        && let Some(query) = parts.uri.query()
    {
        for param in query.split('&') {
            let (key, value) = param.split_once('=').unwrap_or((param, ""));
            if key == "token" {
                let clean_token = value.trim();
                if let Some(meta) = auth_mgr.validate_token(clean_token) {
                    warn_query_token_deprecation(clean_token);
                    return Ok(AuthUser {
                        username: meta.name,
                        role: meta.scope,
                        token_id: Some(meta.id),
                    });
                }
                return Err(ProblemDetails::unauthorized("Invalid or expired API token"));
            }
        }
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

    #[test]
    fn test_websocket_upgrade_detection() {
        let ws = Request::builder()
            .uri("/api/v1/querylog/stream?token=abc")
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "keep-alive, Upgrade")
            .body(())
            .unwrap();
        assert!(is_websocket_upgrade(&ws.into_parts().0));

        let plain = Request::builder()
            .uri("/api/v1/querylog?token=abc")
            .body(())
            .unwrap();
        assert!(!is_websocket_upgrade(&plain.into_parts().0));
    }

    #[test]
    fn test_query_token_ignored_for_non_websocket_requests() {
        let mgr = AuthManager::new();
        let (_, resp) = mgr.create_token("ws", Role::Viewer);
        let req = Request::builder()
            .uri(format!("/api/v1/querylog?token={}", resp.token))
            .body(())
            .unwrap();
        let (parts, ()) = req.into_parts();
        let err = authenticate_request(&parts, &mgr).unwrap_err();
        assert!(err.detail.contains("Authentication required"));
    }
}
