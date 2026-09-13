//! Authentication, session, TOTP 2FA, and API token handlers.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::header::{HeaderMap, SET_COOKIE};
use axum::response::{IntoResponse, Response};
use std::str::FromStr;

use crate::auth::manager::{LoginResult, TotpVerifyResult};
use crate::auth::rbac::RequireAdmin;
use crate::auth::session::{
    Session, build_clear_csrf_cookie, build_clear_session_cookie, build_csrf_cookie,
};
use crate::auth::token::{ApiTokenMeta, CreateTokenResponse, Role};
use crate::auth::totp::TotpSetupResponse;
use crate::auth::{MaybeConnectInfo, is_https_request, resolve_client_ip};
use crate::error::ProblemDetails;
use crate::models::{
    CreateTokenRequest, DisableTotpRequest, GenericMessageResponse, LoginRequest, LoginResponse,
    TotpConfirmRequest, TotpVerifyRequest,
};
use crate::state::ServerContext;

fn append_set_cookie(response: &mut Response, value: &str) {
    if let Ok(cookie_val) = value.parse() {
        response.headers_mut().append(SET_COOKIE, cookie_val);
    }
}

fn append_session_cookies(response: &mut Response, session: &Session, secure: bool) {
    let max_age = (session.expires_at - chrono::Utc::now().timestamp()).max(0);
    append_set_cookie(
        response,
        &crate::auth::session::build_session_cookie(&session.id, max_age, secure),
    );
    append_set_cookie(
        response,
        &build_csrf_cookie(&session.csrf_token, max_age, secure),
    );
}

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
    let config = ctx.config.load();
    let trusted_proxies = config.get_web_config().trusted_proxies;
    let tls_enabled = config.get_tls_config().is_some();
    let is_secure = is_https_request(peer_addr, &headers, &trusted_proxies, tls_enabled);
    let client_ip = resolve_client_ip(peer_addr, &headers, &trusted_proxies);
    let result = ctx.auth_mgr.login(&req.user, &req.pass, &client_ip).await;

    match result {
        LoginResult::Success(session) => {
            let body = Json(LoginResponse {
                session_id: Some(session.id.clone()),
                username: Some(session.username.clone()),
                role: Some(session.role.to_string()),
                totp_required: false,
                partial_token: None,
            });
            let mut response = body.into_response();
            append_session_cookies(&mut response, &session, is_secure);
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
    MaybeConnectInfo(peer_addr): MaybeConnectInfo,
    headers: HeaderMap,
    Json(req): Json<TotpVerifyRequest>,
) -> Result<Response, ProblemDetails> {
    let config = ctx.config.load();
    let trusted_proxies = config.get_web_config().trusted_proxies;
    let client_ip = resolve_client_ip(peer_addr, &headers, &trusted_proxies);

    let session = match ctx
        .auth_mgr
        .verify_totp(&req.partial_token, &req.code, &client_ip)
        .await
    {
        TotpVerifyResult::Success(session) => session,
        TotpVerifyResult::LockedOut { remaining_seconds } => {
            return Err(ProblemDetails::too_many_requests(format!(
                "Account locked out due to repeated failures. Try again in {remaining_seconds}s."
            )));
        }
        TotpVerifyResult::RateLimited => {
            return Err(ProblemDetails::too_many_requests(
                "Too many login attempts from this IP address. Please wait.",
            ));
        }
        TotpVerifyResult::Invalid | TotpVerifyResult::TokenExpired => {
            return Err(ProblemDetails::unauthorized(
                "Invalid, expired, or previously used TOTP code",
            ));
        }
    };

    let tls_enabled = config.get_tls_config().is_some();
    let is_secure = is_https_request(peer_addr, &headers, &trusted_proxies, tls_enabled);

    let body = Json(LoginResponse {
        session_id: Some(session.id.clone()),
        username: Some(session.username.clone()),
        role: Some(session.role.to_string()),
        totp_required: false,
        partial_token: None,
    });
    let mut response = body.into_response();
    append_session_cookies(&mut response, &session, is_secure);
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
pub async fn logout(
    State(ctx): State<ServerContext>,
    MaybeConnectInfo(peer_addr): MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    if let Some(cookie_header) = headers.get("cookie")
        && let Ok(cookie_str) = cookie_header.to_str()
        && let Some(session_id) = crate::auth::session::extract_session_cookie(cookie_str)
    {
        ctx.auth_mgr.logout(&session_id);
    }

    let config = ctx.config.load();
    let trusted_proxies = config.get_web_config().trusted_proxies;
    let tls_enabled = config.get_tls_config().is_some();
    let is_secure = is_https_request(peer_addr, &headers, &trusted_proxies, tls_enabled);
    let mut resp = Json(GenericMessageResponse {
        message: "Logged out successfully".to_string(),
    })
    .into_response();

    append_set_cookie(&mut resp, &build_clear_session_cookie(is_secure));
    append_set_cookie(&mut resp, &build_clear_csrf_cookie(is_secure));
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
    admin: RequireAdmin,
    State(ctx): State<ServerContext>,
) -> Result<Json<TotpSetupResponse>, ProblemDetails> {
    let username = session_username(&admin)?;
    let setup = ctx
        .auth_mgr
        .init_totp_setup(username)
        .await
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
    admin: RequireAdmin,
    State(ctx): State<ServerContext>,
    Json(req): Json<TotpConfirmRequest>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    let username = session_username(&admin)?;
    if ctx.auth_mgr.confirm_totp_setup(username, &req.code).await {
        Ok(Json(GenericMessageResponse {
            message: "TOTP 2FA enabled successfully".to_string(),
        }))
    } else {
        Err(ProblemDetails::bad_request(
            "Invalid TOTP verification code",
        ))
    }
}

/// Disable TOTP 2FA. Requires the account password and, when TOTP is enabled,
/// a valid TOTP or backup code.
#[utoipa::path(
    post,
    path = "/api/v1/auth/totp/disable",
    request_body = DisableTotpRequest,
    responses(
        (status = 200, description = "TOTP disabled successfully", body = GenericMessageResponse),
        (status = 400, description = "Missing second-factor code", body = ProblemDetails),
        (status = 401, description = "Invalid password or code", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn disable_totp(
    admin: RequireAdmin,
    State(ctx): State<ServerContext>,
    Json(req): Json<DisableTotpRequest>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    let username = session_username(&admin)?.to_string();

    if !ctx
        .auth_mgr
        .verify_user_password(&username, &req.password)
        .await
    {
        return Err(ProblemDetails::unauthorized(
            "Re-authentication failed: invalid password",
        ));
    }

    if ctx.auth_mgr.totp_enabled(&username) {
        let code = req
            .code
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .ok_or_else(|| {
                ProblemDetails::bad_request("A TOTP or backup code is required to disable 2FA")
            })?;
        if !ctx.auth_mgr.verify_second_factor(&username, code).await {
            return Err(ProblemDetails::unauthorized(
                "Re-authentication failed: invalid TOTP or backup code",
            ));
        }
    }

    if !ctx.auth_mgr.disable_totp(&username) {
        return Err(ProblemDetails::not_found("User account not found"));
    }
    Ok(Json(GenericMessageResponse {
        message: "TOTP 2FA disabled successfully".to_string(),
    }))
}

/// TOTP management is only meaningful for real user sessions, not API tokens.
fn session_username(admin: &RequireAdmin) -> Result<&str, ProblemDetails> {
    if admin.token_id.is_some() {
        return Err(ProblemDetails::forbidden(
            "TOTP management requires an authenticated user session, not an API token",
        ));
    }
    Ok(&admin.username)
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
