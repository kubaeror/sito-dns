//! Authentication, session, TOTP 2FA, and API token handlers.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::header::{HeaderMap, SET_COOKIE};
use axum::response::{IntoResponse, Response};
use std::str::FromStr;

use crate::auth::manager::{LoginResult, TotpVerifyResult, UserMutationError};
use crate::auth::rbac::RequireAdmin;
use crate::auth::session::{
    Session, build_clear_csrf_cookie, build_clear_partial_cookie, build_clear_session_cookie,
    build_csrf_cookie, build_partial_cookie, extract_partial_cookie,
};
use crate::auth::token::{CreateTokenResponse, Role};
use crate::auth::totp::TotpSetupResponse;
use crate::auth::{
    AdminSchemeConfig, MaybeConnectInfo, admin_scheme_config, is_https_request, resolve_client_ip,
};
use crate::error::ProblemDetails;
use crate::models::{
    ApiTokenDto, ChangePasswordRequest, CreateTokenRequest, CreateUserRequest, DisableTotpRequest,
    GenericMessageResponse, LoginRequest, LoginResponse, TotpConfirmRequest, TotpVerifyRequest,
    UpdateUserRequest, UserDto,
};
use crate::state::ServerContext;

/// Header that opts a non-browser client into receiving the TOTP partial token
/// in the JSON body instead of an HttpOnly cookie.
pub const TOKEN_DELIVERY_HEADER: &str = "x-sito-token-delivery";

/// True when the request asked for the partial token in the JSON body.
fn wants_partial_token_in_body(headers: &HeaderMap) -> bool {
    headers
        .get(TOKEN_DELIVERY_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("body"))
}

/// Resolves the admin scheme from the raw `[web]` section (never from DNS TLS).
fn admin_scheme(config: &sito_core::config::Config) -> AdminSchemeConfig {
    admin_scheme_config(config.web.as_ref())
}

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
    let (trusted_proxies, is_secure) = {
        let config = ctx.config.load();
        let trusted_proxies = config.get_web_config().trusted_proxies;
        let scheme = admin_scheme(&config);
        let is_secure = is_https_request(peer_addr, &headers, &trusted_proxies, &scheme);
        (trusted_proxies, is_secure)
    };
    let client_ip = resolve_client_ip(peer_addr, &headers, &trusted_proxies);
    let result = ctx.auth_mgr.login(&req.user, &req.pass, &client_ip).await;

    match result {
        LoginResult::Success(session) => {
            let body = Json(LoginResponse {
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
            let deliver_in_body = wants_partial_token_in_body(&headers);
            let body = Json(LoginResponse {
                username: Some(req.user),
                role: None,
                totp_required: true,
                partial_token: deliver_in_body.then(|| partial_token.clone()),
            });
            let mut response = body.into_response();
            // Browser clients get the partial token as an HttpOnly cookie; it
            // is a short-lived credential and must not be readable from JS.
            append_set_cookie(
                &mut response,
                &build_partial_cookie(
                    &partial_token,
                    crate::auth::PARTIAL_COOKIE_MAX_AGE_SECS,
                    is_secure,
                ),
            );
            Ok(response)
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
    let (trusted_proxies, is_secure) = {
        let config = ctx.config.load();
        let trusted_proxies = config.get_web_config().trusted_proxies;
        let scheme = admin_scheme(&config);
        let is_secure = is_https_request(peer_addr, &headers, &trusted_proxies, &scheme);
        (trusted_proxies, is_secure)
    };
    let client_ip = resolve_client_ip(peer_addr, &headers, &trusted_proxies);

    // The partial token comes from the body (CLI/API opt-in) or, for browser
    // clients, from the HttpOnly `sito_partial` cookie set by `/auth/login`.
    let partial_token = {
        let from_body = req.partial_token.trim();
        if from_body.is_empty() {
            headers
                .get(axum::http::header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .and_then(extract_partial_cookie)
                .unwrap_or_default()
        } else {
            from_body.to_string()
        }
    };

    let session = match ctx
        .auth_mgr
        .verify_totp(&partial_token, &req.code, &client_ip)
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

    let body = Json(LoginResponse {
        username: Some(session.username.clone()),
        role: Some(session.role.to_string()),
        totp_required: false,
        partial_token: None,
    });
    let mut response = body.into_response();
    append_session_cookies(&mut response, &session, is_secure);
    // The partial token is single-use: clear the cookie on success.
    append_set_cookie(&mut response, &build_clear_partial_cookie(is_secure));
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
        ctx.auth_mgr.logout(&session_id).await;
    }

    let config = ctx.config.load();
    let trusted_proxies = config.get_web_config().trusted_proxies;
    let scheme = admin_scheme(&config);
    let is_secure = is_https_request(peer_addr, &headers, &trusted_proxies, &scheme);
    drop(config);
    let mut resp = Json(GenericMessageResponse {
        message: "Logged out successfully".to_string(),
    })
    .into_response();

    append_set_cookie(&mut resp, &build_clear_session_cookie(is_secure));
    append_set_cookie(&mut resp, &build_clear_csrf_cookie(is_secure));
    append_set_cookie(&mut resp, &build_clear_partial_cookie(is_secure));
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

    if !ctx.auth_mgr.disable_totp(&username).await {
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
        (status = 200, description = "List of API tokens (hashes are never returned)", body = Vec<ApiTokenDto>),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn list_tokens(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
) -> Json<Vec<ApiTokenDto>> {
    Json(
        ctx.auth_mgr
            .list_tokens()
            .iter()
            .map(ApiTokenDto::from)
            .collect(),
    )
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
    admin: RequireAdmin,
    State(ctx): State<ServerContext>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<CreateTokenResponse>, ProblemDetails> {
    let scope = Role::from_str(&req.scope)
        .map_err(|e| ProblemDetails::bad_request(format!("Invalid token scope: {e}")))?;
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ProblemDetails::bad_request("Token name is required"));
    }
    if name.len() > 128 {
        return Err(ProblemDetails::bad_request(
            "Token name must be at most 128 characters",
        ));
    }

    // Session-created tokens belong to the signed-in account. A bearer-token
    // caller inherits the owner of the token it authenticated with (or stays
    // ownerless for legacy tokens), so ownership chains correctly.
    let owner = match admin.token_id.as_deref() {
        Some(token_id) => ctx
            .auth_mgr
            .list_tokens()
            .into_iter()
            .find(|token| token.id == token_id)
            .and_then(|token| token.owner),
        None => Some(admin.username.clone()),
    };

    let (_meta, resp) = ctx
        .auth_mgr
        .create_token(name, scope, owner.as_deref())
        .await
        .map_err(|e| ProblemDetails::bad_request(e.to_string()))?;
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
    if ctx.auth_mgr.delete_token(&id).await {
        Ok(Json(GenericMessageResponse {
            message: format!("Token {id} successfully revoked"),
        }))
    } else {
        Err(ProblemDetails::not_found(format!("Token '{id}' not found")))
    }
}

// ---------------------------------------------------------------------------
// User management (WP-4.4)
// ---------------------------------------------------------------------------

/// Rejects usernames that would be ambiguous in logs/config or empty.
pub(crate) fn validate_username(username: &str) -> Result<(), ProblemDetails> {
    let trimmed = username.trim();
    if trimmed.is_empty() {
        return Err(ProblemDetails::bad_request("Username must not be empty"));
    }
    if trimmed.len() > 64 {
        return Err(ProblemDetails::bad_request(
            "Username must be at most 64 characters",
        ));
    }
    if matches!(trimmed, "." | "..") {
        return Err(ProblemDetails::bad_request(
            "Username must not be '.' or '..'",
        ));
    }
    if trimmed
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, ':' | '/' | '\\'))
    {
        return Err(ProblemDetails::bad_request(
            "Username must not contain whitespace, control characters, ':', '/' or '\\'",
        ));
    }
    Ok(())
}

/// Shared password policy used by user creation, change-password and the wizard.
pub fn validate_password_policy(password: &str) -> Result<(), ProblemDetails> {
    if password.len() < 8 {
        return Err(ProblemDetails::bad_request(
            "Password must be at least 8 characters long",
        ));
    }
    if password.len() > 1024 {
        return Err(ProblemDetails::bad_request("Password is too long"));
    }
    if password.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return Err(ProblemDetails::bad_request(
            "Password must not contain whitespace or control characters",
        ));
    }
    if password.eq_ignore_ascii_case("adminadmin") {
        return Err(ProblemDetails::bad_request(
            "The default password is not allowed",
        ));
    }
    Ok(())
}

/// Maps an atomic user-mutation failure onto the REST error contract:
/// `404` for unknown accounts and `400` for the last-admin guard.
pub(crate) fn user_mutation_problem(
    username: &str,
    action: &str,
    err: UserMutationError,
) -> ProblemDetails {
    match err {
        UserMutationError::NotFound => {
            ProblemDetails::not_found(format!("User '{username}' not found"))
        }
        UserMutationError::LastAdmin => {
            ProblemDetails::bad_request(format!("Cannot {action} the last remaining admin account"))
        }
    }
}

/// List local user accounts.
#[utoipa::path(
    get,
    path = "/api/v1/auth/users",
    responses(
        (status = 200, description = "User accounts", body = Vec<UserDto>),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn list_users(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
) -> Json<Vec<UserDto>> {
    Json(ctx.auth_mgr.list_users())
}

/// Create a local user account.
#[utoipa::path(
    post,
    path = "/api/v1/auth/users",
    request_body = CreateUserRequest,
    responses(
        (status = 200, description = "User created", body = UserDto),
        (status = 400, description = "Invalid username, password or role", body = ProblemDetails),
        (status = 409, description = "Username already exists", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn create_user(
    _admin: RequireAdmin,
    State(ctx): State<ServerContext>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserDto>, ProblemDetails> {
    validate_username(&req.username)?;
    validate_password_policy(&req.password)?;
    let role = Role::from_str(req.role.trim())
        .map_err(|e| ProblemDetails::bad_request(format!("Invalid role: {e}")))?;
    // Normalize surrounding whitespace exactly like the web UI so both paths
    // create the same account name.
    let username = req.username.trim();

    if ctx.auth_mgr.has_user(username) {
        return Err(ProblemDetails::conflict(format!(
            "User '{username}' already exists"
        )));
    }
    ctx.auth_mgr
        .create_user(username, &req.password, role)
        .await;
    Ok(Json(UserDto {
        username: username.to_string(),
        role: role.to_string(),
        totp_enabled: false,
    }))
}

/// Update a user's role.
#[utoipa::path(
    put,
    path = "/api/v1/auth/users/{username}",
    request_body = UpdateUserRequest,
    params(("username" = String, Path, description = "Username")),
    responses(
        (status = 200, description = "User role updated", body = UserDto),
        (status = 400, description = "Invalid role or last-admin protection", body = ProblemDetails),
        (status = 404, description = "User not found", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn update_user(
    admin: RequireAdmin,
    State(ctx): State<ServerContext>,
    Path(username): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserDto>, ProblemDetails> {
    let role = Role::from_str(req.role.trim())
        .map_err(|e| ProblemDetails::bad_request(format!("Invalid role: {e}")))?;

    // Check and mutate atomically so concurrent demotions cannot race past the
    // last-admin guard.
    ctx.auth_mgr
        .set_user_role_checked(&username, role)
        .await
        .map_err(|err| user_mutation_problem(&username, "demote", err))?;
    tracing::info!(
        actor = %admin.username,
        target = %username,
        role = %role,
        "Administrator changed a user role"
    );
    Ok(Json(UserDto {
        username,
        role: role.to_string(),
        totp_enabled: false,
    }))
}

/// Delete a local user account.
#[utoipa::path(
    delete,
    path = "/api/v1/auth/users/{username}",
    params(("username" = String, Path, description = "Username")),
    responses(
        (status = 200, description = "User deleted", body = GenericMessageResponse),
        (status = 400, description = "Last-admin protection", body = ProblemDetails),
        (status = 404, description = "User not found", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn delete_user(
    admin: RequireAdmin,
    State(ctx): State<ServerContext>,
    Path(username): Path<String>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    // Check and delete atomically so concurrent deletions/demotions cannot
    // race past the last-admin guard.
    ctx.auth_mgr
        .delete_user_checked(&username)
        .await
        .map_err(|err| user_mutation_problem(&username, "delete", err))?;
    tracing::info!(
        actor = %admin.username,
        target = %username,
        "Administrator deleted a user account"
    );
    Ok(Json(GenericMessageResponse {
        message: format!("User '{username}' deleted successfully"),
    }))
}

/// Change a password. Self-service requires the current password; an Admin may
/// override another account (audited) with `username` set.
#[utoipa::path(
    post,
    path = "/api/v1/auth/change-password",
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed", body = GenericMessageResponse),
        (status = 400, description = "Password policy violation", body = ProblemDetails),
        (status = 401, description = "Missing/wrong current password", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn change_password(
    admin: RequireAdmin,
    State(ctx): State<ServerContext>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<GenericMessageResponse>, ProblemDetails> {
    if admin.token_id.is_some() {
        return Err(ProblemDetails::forbidden(
            "Changing passwords requires an authenticated user session, not an API token",
        ));
    }
    validate_password_policy(&req.new_password)?;

    let target = req
        .username
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .unwrap_or(&admin.username)
        .to_string();

    let is_override = target != admin.username;
    if is_override {
        if !ctx.auth_mgr.has_user(&target) {
            return Err(ProblemDetails::not_found(format!(
                "User '{target}' not found"
            )));
        }
        tracing::warn!(
            actor = %admin.username,
            target = %target,
            "Administrator overrode a user password without the current password"
        );
    } else {
        let current = req
            .current_password
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .ok_or_else(|| {
                ProblemDetails::unauthorized("Current password is required to change your password")
            })?;
        if !ctx.auth_mgr.verify_user_password(&target, current).await {
            return Err(ProblemDetails::unauthorized(
                "Current password is incorrect",
            ));
        }
    }

    if !ctx
        .auth_mgr
        .update_user_password(&target, &req.new_password)
        .await
    {
        return Err(ProblemDetails::not_found(format!(
            "User '{target}' not found"
        )));
    }
    Ok(Json(GenericMessageResponse {
        message: format!("Password updated for user '{target}'"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::rbac::AuthUser;
    use axum::extract::Path as AxumPath;
    use axum::http::header::SET_COOKIE;
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    fn admin() -> RequireAdmin {
        RequireAdmin(AuthUser {
            username: "admin".to_string(),
            role: Role::Admin,
            token_id: None,
        })
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn set_cookies(response: &Response) -> Vec<String> {
        response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(str::to_string)
            .collect()
    }

    /// WP-4.1: a DNS `[tls]` certificate must not make the plain-HTTP admin UI
    /// believe it is serving HTTPS (Secure cookie would be dropped by the
    /// browser, breaking login).
    #[tokio::test]
    async fn test_login_ignores_dns_tls_for_cookie_secure_flag() {
        let temp_dir = crate::test_support::temp_dir("sito_auth_scheme");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        {
            let mut config = (**ctx.config.load()).clone();
            config.tls = Some(sito_core::config::TlsConfig {
                cert: Some(std::path::PathBuf::from("/etc/sito/dot-cert.pem")),
                key: Some(std::path::PathBuf::from("/etc/sito/dot-key.pem")),
                sni_certs: Vec::new(),
            });
            ctx.set_config(config);
        }

        let response = login(
            State(ctx.clone()),
            MaybeConnectInfo(None),
            HeaderMap::new(),
            Json(LoginRequest {
                user: "admin".to_string(),
                pass: "adminadmin".to_string(),
            }),
        )
        .await
        .expect("login succeeds");

        let cookies = set_cookies(&response);
        assert!(
            cookies.iter().any(|c| c.starts_with("sito_session=")),
            "session cookie must be set: {cookies:?}"
        );
        assert!(
            cookies.iter().all(|c| !c.contains("Secure")),
            "plain-HTTP admin cookies must not be Secure even with [tls] configured: {cookies:?}"
        );

        // With an explicit HTTPS public_url the Secure attribute is applied.
        {
            let mut config = (**ctx.config.load()).clone();
            config.web = Some(
                toml::from_str::<toml::Value>(r#"public_url = "https://dns.example.com""#).unwrap(),
            );
            ctx.set_config(config);
        }
        let response = login(
            State(ctx),
            MaybeConnectInfo(None),
            HeaderMap::new(),
            Json(LoginRequest {
                user: "admin".to_string(),
                pass: "adminadmin".to_string(),
            }),
        )
        .await
        .expect("login succeeds");
        assert!(
            set_cookies(&response).iter().all(|c| c.contains("Secure")),
            "explicit https public_url must yield Secure cookies"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// WP-4.3: the session id and TOTP partial token must not be echoed in the
    /// JSON body by default.
    #[tokio::test]
    async fn test_login_response_never_contains_session_or_partial_token() {
        let temp_dir = crate::test_support::temp_dir("sito_auth_login_body");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let response = login(
            State(ctx.clone()),
            MaybeConnectInfo(None),
            HeaderMap::new(),
            Json(LoginRequest {
                user: "admin".to_string(),
                pass: "adminadmin".to_string(),
            }),
        )
        .await
        .expect("login succeeds");
        let json = body_json(response).await;
        assert!(
            json.get("session_id").is_none(),
            "session id must never be returned in the body: {json}"
        );
        assert_eq!(json["totp_required"], false);

        // Enable TOTP so the next login returns a partial token.
        let setup = ctx.auth_mgr.init_totp_setup("admin").await.expect("setup");
        assert!(
            ctx.auth_mgr
                .confirm_totp_setup("admin", &setup.backup_codes[0])
                .await
        );

        let response = login(
            State(ctx.clone()),
            MaybeConnectInfo(None),
            HeaderMap::new(),
            Json(LoginRequest {
                user: "admin".to_string(),
                pass: "adminadmin".to_string(),
            }),
        )
        .await
        .expect("totp required");
        let cookies = set_cookies(&response);
        assert!(
            cookies
                .iter()
                .any(|c| c.starts_with("sito_partial=") && c.contains("HttpOnly")),
            "browser clients must receive the partial token as an HttpOnly cookie: {cookies:?}"
        );
        let json = body_json(response).await;
        assert_eq!(json["totp_required"], true);
        assert!(
            json.get("partial_token").is_none(),
            "partial token must not be in the body without explicit opt-in: {json}"
        );

        // Non-browser clients can opt in with the delivery header.
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(TOKEN_DELIVERY_HEADER),
            HeaderValue::from_static("body"),
        );
        let response = login(
            State(ctx.clone()),
            MaybeConnectInfo(None),
            headers,
            Json(LoginRequest {
                user: "admin".to_string(),
                pass: "adminadmin".to_string(),
            }),
        )
        .await
        .expect("totp required");
        let json = body_json(response).await;
        assert!(
            json["partial_token"]
                .as_str()
                .is_some_and(|t| !t.is_empty()),
            "explicit opt-in must return the partial token: {json}"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// WP-4.3: the token API must never return the stored hash.
    #[tokio::test]
    async fn test_token_api_never_returns_hashes() {
        let temp_dir = crate::test_support::temp_dir("sito_auth_tokens");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        let (meta, _resp) = ctx
            .auth_mgr
            .create_token("grafana", Role::Viewer, None)
            .await
            .expect("token");

        let Json(dtos) = list_tokens(admin(), State(ctx.clone())).await;
        assert_eq!(dtos.len(), 1);
        let json = serde_json::to_string(&dtos).unwrap();
        assert!(
            !json.contains(&meta.hash),
            "token hash leaked in the API response: {json}"
        );
        assert!(!json.contains("\"hash\""));
        assert_eq!(dtos[0].id, meta.id);
        assert_eq!(dtos[0].scope, "viewer");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// WP-4.4: minimal user management with last-admin protection and a
    /// change-password endpoint that requires the current password.
    #[tokio::test]
    async fn test_user_management_and_change_password() {
        let temp_dir = crate::test_support::temp_dir("sito_auth_users");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let Json(users) = list_users(admin(), State(ctx.clone())).await;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin");

        let created = create_user(
            admin(),
            State(ctx.clone()),
            Json(CreateUserRequest {
                username: "alice".to_string(),
                password: "AlicePassword1".to_string(),
                role: "operator".to_string(),
            }),
        )
        .await
        .expect("user created");
        assert_eq!(created.0.role, "operator");

        let conflict = create_user(
            admin(),
            State(ctx.clone()),
            Json(CreateUserRequest {
                username: "alice".to_string(),
                password: "AlicePassword2".to_string(),
                role: "viewer".to_string(),
            }),
        )
        .await
        .expect_err("duplicate user rejected");
        assert_eq!(conflict.status, 409);

        let updated = update_user(
            admin(),
            State(ctx.clone()),
            AxumPath("alice".to_string()),
            Json(UpdateUserRequest {
                role: "viewer".to_string(),
            }),
        )
        .await
        .expect("role updated");
        assert_eq!(updated.0.role, "viewer");

        // Last-admin protection: demoting/deleting the only Admin fails.
        let demote = update_user(
            admin(),
            State(ctx.clone()),
            AxumPath("admin".to_string()),
            Json(UpdateUserRequest {
                role: "viewer".to_string(),
            }),
        )
        .await
        .expect_err("last admin cannot be demoted");
        assert_eq!(demote.status, 400);
        let delete = delete_user(admin(), State(ctx.clone()), AxumPath("admin".to_string()))
            .await
            .expect_err("last admin cannot be deleted");
        assert_eq!(delete.status, 400);

        // Unknown accounts stay 404 on both mutations.
        let unknown_role = update_user(
            admin(),
            State(ctx.clone()),
            AxumPath("ghost".to_string()),
            Json(UpdateUserRequest {
                role: "admin".to_string(),
            }),
        )
        .await
        .expect_err("unknown user rejected");
        assert_eq!(unknown_role.status, 404);
        let unknown_delete =
            delete_user(admin(), State(ctx.clone()), AxumPath("ghost".to_string()))
                .await
                .expect_err("unknown user rejected");
        assert_eq!(unknown_delete.status, 404);

        // Self-service password change requires the current password.
        let wrong = change_password(
            admin(),
            State(ctx.clone()),
            Json(ChangePasswordRequest {
                username: None,
                current_password: Some("wrong".to_string()),
                new_password: "NewAdminPassword1".to_string(),
            }),
        )
        .await
        .expect_err("wrong current password rejected");
        assert_eq!(wrong.status, 401);

        let _ = change_password(
            admin(),
            State(ctx.clone()),
            Json(ChangePasswordRequest {
                username: None,
                current_password: Some("adminadmin".to_string()),
                new_password: "NewAdminPassword1".to_string(),
            }),
        )
        .await
        .expect("password changed");
        assert!(matches!(
            ctx.auth_mgr
                .login("admin", "NewAdminPassword1", "127.0.0.1")
                .await,
            LoginResult::Success(_)
        ));

        // Admin override for another account (no current password required).
        let _ = change_password(
            admin(),
            State(ctx.clone()),
            Json(ChangePasswordRequest {
                username: Some("alice".to_string()),
                current_password: None,
                new_password: "AliceNewPassword1".to_string(),
            }),
        )
        .await
        .expect("admin override");
        assert!(matches!(
            ctx.auth_mgr
                .login("alice", "AliceNewPassword1", "127.0.0.1")
                .await,
            LoginResult::Success(_)
        ));

        let _ = delete_user(admin(), State(ctx.clone()), AxumPath("alice".to_string()))
            .await
            .expect("user deleted");
        assert!(!ctx.auth_mgr.has_user("alice"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Tokens cannot be used to change passwords (session-only operation).
    #[tokio::test]
    async fn test_change_password_rejects_api_tokens() {
        let temp_dir = crate::test_support::temp_dir("sito_auth_token_pw");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let token_admin = RequireAdmin(AuthUser {
            username: "ci".to_string(),
            role: Role::Admin,
            token_id: Some("tok_123".to_string()),
        });
        let err = change_password(
            token_admin,
            State(ctx.clone()),
            Json(ChangePasswordRequest {
                username: None,
                current_password: Some("adminadmin".to_string()),
                new_password: "NewPassword123".to_string(),
            }),
        )
        .await
        .expect_err("tokens must not change passwords");
        assert_eq!(err.status, 403);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_password_policy_rejects_default_and_short_passwords() {
        let temp_dir = crate::test_support::temp_dir("sito_auth_policy");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        for password in ["short", "adminadmin", "has space123"] {
            let err = create_user(
                admin(),
                State(ctx.clone()),
                Json(CreateUserRequest {
                    username: "bob".to_string(),
                    password: password.to_string(),
                    role: "viewer".to_string(),
                }),
            )
            .await
            .expect_err("weak password rejected");
            assert_eq!(err.status, 400, "password '{password}' must be rejected");
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_create_user_trims_whitespace_and_rejects_dot_names() {
        let temp_dir = crate::test_support::temp_dir("sito_auth_user_names");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let created = create_user(
            admin(),
            State(ctx.clone()),
            Json(CreateUserRequest {
                username: "  alice  ".to_string(),
                password: "AlicePassword1".to_string(),
                role: "viewer".to_string(),
            }),
        )
        .await
        .expect("user created");
        assert_eq!(created.0.username, "alice");
        assert!(ctx.auth_mgr.has_user("alice"));
        assert!(
            !ctx.auth_mgr.has_user("  alice  "),
            "the stored username must be normalized exactly like the UI"
        );

        for username in [".", ".."] {
            let err = create_user(
                admin(),
                State(ctx.clone()),
                Json(CreateUserRequest {
                    username: username.to_string(),
                    password: "AlicePassword1".to_string(),
                    role: "viewer".to_string(),
                }),
            )
            .await
            .expect_err("dot names must be rejected");
            assert_eq!(err.status, 400, "username '{username}' must be rejected");
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_create_token_trims_name_and_records_owner() {
        let temp_dir = crate::test_support::temp_dir("sito_auth_token_name");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let Json(resp) = create_token(
            admin(),
            State(ctx.clone()),
            Json(CreateTokenRequest {
                name: "  ci-deploy  ".to_string(),
                scope: "viewer".to_string(),
            }),
        )
        .await
        .expect("token created");
        assert_eq!(resp.name, "ci-deploy");

        let token = ctx
            .auth_mgr
            .list_tokens()
            .into_iter()
            .find(|token| token.id == resp.id)
            .expect("token listed");
        assert_eq!(token.name, "ci-deploy");
        assert_eq!(token.owner.as_deref(), Some("admin"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_create_token_via_bearer_inherits_owner_not_token_name() {
        let temp_dir = crate::test_support::temp_dir("sito_auth_bearer_owner");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        // The authenticating bearer token is named "ci-auth" but is owned by
        // the admin account; RBAC exposes the name as `AuthUser.username`.
        let (parent, _) = ctx
            .auth_mgr
            .create_token("ci-auth", Role::Admin, Some("admin"))
            .await
            .expect("parent token");
        let bearer = RequireAdmin(AuthUser {
            username: "ci-auth".to_string(),
            role: Role::Admin,
            token_id: Some(parent.id.clone()),
        });

        let Json(resp) = create_token(
            bearer,
            State(ctx.clone()),
            Json(CreateTokenRequest {
                name: "child".to_string(),
                scope: "viewer".to_string(),
            }),
        )
        .await
        .expect("child token created");

        let child = ctx
            .auth_mgr
            .list_tokens()
            .into_iter()
            .find(|token| token.id == resp.id)
            .expect("child token listed");
        assert_eq!(child.owner.as_deref(), Some("admin"));
        assert_ne!(
            child.owner.as_deref(),
            Some("ci-auth"),
            "ownership must chain through the authenticating token, not its name"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
