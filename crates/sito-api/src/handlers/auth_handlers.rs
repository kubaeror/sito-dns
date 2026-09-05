//! Authentication, session, TOTP 2FA, and API token handlers.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::header::{HeaderMap, SET_COOKIE};
use axum::response::{IntoResponse, Response};
use std::str::FromStr;

use crate::auth::manager::LoginResult;
use crate::auth::rbac::RequireAdmin;
use crate::auth::session::SESSION_COOKIE_NAME;
use crate::auth::token::{ApiTokenMeta, CreateTokenResponse, Role};
use crate::auth::totp::TotpSetupResponse;
use crate::auth::{MaybeConnectInfo, resolve_client_ip};
use crate::error::ProblemDetails;
use crate::models::{
    CreateTokenRequest, GenericMessageResponse, LoginRequest, LoginResponse, TotpConfirmRequest,
    TotpVerifyRequest,
};
use crate::state::ServerContext;

/// User login endpoint.
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful or TOTP required", body = LoginResponse),
        (status = 401, description = "Invalid credentials", body = ProblemDetails),
        (status = 429, description = "Locked out or rate limited", body = ProblemDetails)
    )
)]
pub async fn login(
    State(ctx): State<ServerContext>,
    MaybeConnectInfo(peer_addr): MaybeConnectInfo,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Response, ProblemDetails> {
    let trusted_proxies = ctx.config.load().get_web_config().trusted_proxies;
    let client_ip = resolve_client_ip(peer_addr, &headers, &trusted_proxies);
    let result = ctx.auth_mgr.login(&req.user, &req.pass, &client_ip);

    match result {
        LoginResult::Success(session) => {
            let cookie_header = session.to_cookie_header();
            let body = Json(LoginResponse {
                session_id: Some(session.id),
                username: Some(session.username),
                role: Some(session.role.to_string()),
                totp_required: false,
                partial_token: None,
            });
            let mut response = body.into_response();
            if let Ok(cookie_val) = cookie_header.parse() {
                response.headers_mut().insert(SET_COOKIE, cookie_val);
            }
            Ok(response)
        }
        LoginResult::TotpRequired { partial_token } => {
            let body = Json(LoginResponse {
                session_id: None,
                username: Some(req.user),
                role: None,
                totp_required: true,
                partial_token: Some(partial_token),
            });
            Ok(body.into_response())
        }
        LoginResult::LockedOut { remaining_seconds } => {
            Err(ProblemDetails::too_many_requests(format!(
                "Account locked out due to repeated failures. Try again in {remaining_seconds}s."
            )))
        }
        LoginResult::RateLimited => Err(ProblemDetails::too_many_requests(
            "Too many login attempts from this IP address. Please wait.",
        )),
        LoginResult::InvalidCredentials { remaining_attempts } => {
            Err(ProblemDetails::unauthorized(format!(
                "Invalid credentials. Remaining attempts before lockout: {remaining_attempts}"
            )))
        }
    }
}

/// Second login phase: verify TOTP code.
#[utoipa::path(
    post,
    path = "/api/v1/auth/totp/verify",
    request_body = TotpVerifyRequest,
    responses(
        (status = 200, description = "TOTP verified, session established", body = LoginResponse),
        (status = 401, description = "Invalid or expired code", body = ProblemDetails)
    )
)]
pub async fn verify_totp(
    State(ctx): State<ServerContext>,
    Json(req): Json<TotpVerifyRequest>,
) -> Result<Response, ProblemDetails> {
    let session = ctx
        .auth_mgr
        .verify_totp(&req.partial_token, &req.code)
        .ok_or_else(|| {
            ProblemDetails::unauthorized("Invalid, expired, or previously used TOTP code")
        })?;

    let cookie_header = session.to_cookie_header();
    let body = Json(LoginResponse {
        session_id: Some(session.id),
        username: Some(session.username),
        role: Some(session.role.to_string()),
        totp_required: false,
        partial_token: None,
    });
    let mut response = body.into_response();
    if let Ok(cookie_val) = cookie_header.parse() {
        response.headers_mut().insert(SET_COOKIE, cookie_val);
    }
    Ok(response)
}

/// Logout endpoint invalidating current session cookie.
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    responses(
        (status = 200, description = "Logged out successfully", body = GenericMessageResponse)
    )
)]
pub async fn logout(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    if let Some(cookie_header) = headers.get("cookie")
        && let Ok(cookie_str) = cookie_header.to_str()
    {
        for pair in cookie_str.split(';') {
            let mut parts = pair.splitn(2, '=');
            if let (Some(k), Some(v)) = (parts.next(), parts.next())
                && k.trim() == SESSION_COOKIE_NAME
            {
                ctx.auth_mgr.logout(v.trim());
            }
        }
    }

    let expired_cookie =
        format!("{SESSION_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0");
    let mut resp = Json(GenericMessageResponse {
        message: "Logged out successfully".to_string(),
    })
    .into_response();

    if let Ok(cookie_val) = expired_cookie.parse() {
        resp.headers_mut().insert(SET_COOKIE, cookie_val);
    }
    resp
}

/// Initiate TOTP 2FA setup.
#[utoipa::path(
    get,
    path = "/api/v1/auth/totp/setup",
    responses(
        (status = 200, description = "TOTP setup credentials generated", body = TotpSetupResponse),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn get_totp_setup(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
) -> Result<Json<TotpSetupResponse>, ProblemDetails> {
    let setup = ctx
        .auth_mgr
        .init_totp_setup("admin")
        .ok_or_else(|| ProblemDetails::internal_error("Failed to generate TOTP credentials"))?;

    Ok(Json(setup))
}

/// Enable TOTP 2FA by verifying setup code.
#[utoipa::path(
    post,
    path = "/api/v1/auth/totp/enable",
    request_body = TotpConfirmRequest,
    responses(
        (status = 200, description = "TOTP enabled successfully", body = GenericMessageResponse),
        (status = 400, description = "Invalid code", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn enable_totp(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
    Json(req): Json<TotpConfirmRequest>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    if ctx.auth_mgr.confirm_totp_setup("admin", &req.code) {
        Ok(Json(GenericMessageResponse {
            message: "TOTP 2FA enabled successfully".to_string(),
        }))
    } else {
        Err(ProblemDetails::bad_request(
            "Invalid TOTP verification code",
        ))
    }
}

/// Disable TOTP 2FA.
#[utoipa::path(
    post,
    path = "/api/v1/auth/totp/disable",
    responses(
        (status = 200, description = "TOTP disabled successfully", body = GenericMessageResponse),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn disable_totp(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
) -> Json<GenericMessageResponse> {
    ctx.auth_mgr.disable_totp("admin");
    Json(GenericMessageResponse {
        message: "TOTP 2FA disabled successfully".to_string(),
    })
}

/// List all API tokens.
#[utoipa::path(
    get,
    path = "/api/v1/auth/tokens",
    responses(
        (status = 200, description = "List of API tokens", body = Vec<ApiTokenMeta>),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn list_tokens(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
) -> Json<Vec<ApiTokenMeta>> {
    Json(ctx.auth_mgr.list_tokens())
}

/// Create a new API token.
#[utoipa::path(
    post,
    path = "/api/v1/auth/tokens",
    request_body = CreateTokenRequest,
    responses(
        (status = 200, description = "API token created", body = CreateTokenResponse),
        (status = 400, description = "Invalid scope", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn create_token(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<CreateTokenResponse>, ProblemDetails> {
    let scope = Role::from_str(&req.scope)
        .map_err(|e| ProblemDetails::bad_request(format!("Invalid token scope: {e}")))?;

    let (_meta, resp) = ctx.auth_mgr.create_token(&req.name, scope);
    Ok(Json(resp))
}

/// Revoke an API token by ID.
#[utoipa::path(
    delete,
    path = "/api/v1/auth/tokens/{id}",
    responses(
        (status = 200, description = "Token revoked", body = GenericMessageResponse),
        (status = 404, description = "Token not found", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn delete_token(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
    Path(id): Path<String>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    if ctx.auth_mgr.delete_token(&id) {
        Ok(Json(GenericMessageResponse {
            message: format!("Token {id} successfully revoked"),
        }))
    } else {
        Err(ProblemDetails::not_found(format!("Token '{id}' not found")))
    }
}
