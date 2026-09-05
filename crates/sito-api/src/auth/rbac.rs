//! Role-Based Access Control (RBAC) Axum extractors per section 12.1 and 12.2.
//!
//! Enforces viewer, operator, and admin permissions across REST API endpoints.

use crate::auth::manager::AuthManager;
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

/// Helper to authenticate from request parts against AuthManager.
pub fn authenticate_request(
    parts: &Parts,
    auth_mgr: &AuthManager,
) -> Result<AuthUser, ProblemDetails> {
    // 1. Try Bearer token in Authorization header
    if let Some(auth_header) = parts.headers.get(AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
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
        }
    }

    // 2. Try session cookie
    if let Some(cookie_header) = parts.headers.get(COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            if let Some(session_id) = extract_session_cookie(cookie_str) {
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
