//! Self-service account page: password, tokens, and TOTP.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(crate) fn token_view_items(ctx: &ServerContext, user: &AuthUser) -> Vec<TokenViewItem> {
    let is_admin = user.role == Role::Admin;
    ctx.auth_mgr
        .list_tokens()
        .iter()
        .filter(|token| {
            token.owner.as_deref() == Some(user.username.as_str())
                || (is_admin && token.owner.is_none())
        })
        .map(|token| TokenViewItem {
            id: token.id.clone(),
            name: token.name.clone(),
            scope: token.scope.to_string(),
            owner: token
                .owner
                .clone()
                .unwrap_or_else(|| "(legacy / ownerless)".to_string()),
            created_at: format_token_timestamp(Some(token.created_at)),
            last_used: format_token_timestamp(token.last_used),
            expires_at: format_token_expiry_timestamp(token.expires_at),
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_account_page(
    ctx: &ServerContext,
    user: &AuthUser,
    csrf: &str,
    error_message: &str,
    notice_message: &str,
    new_token: Option<&crate::auth::token::CreateTokenResponse>,
    totp_setup: Option<TotpSetupView>,
    status: StatusCode,
) -> Response {
    let tokens = token_view_items(ctx, user);
    let totp_enabled = ctx.auth_mgr.totp_enabled(&user.username);
    let (token_value, token_name, token_scope) = match new_token {
        Some(token) => (
            Some(token.token.as_str()),
            token.name.as_str(),
            token.scope.to_string(),
        ),
        None => (None, "", String::new()),
    };
    let mut response = HtmlTemplate(AccountTemplate {
        csrf_token: csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: user.role.as_str(),
        active_tab: "account",
        version: env!("CARGO_PKG_VERSION"),
        tokens,
        totp_enabled,
        totp_setup,
        can_create_operator_token: user.role >= Role::Operator,
        can_create_admin_token: user.role >= Role::Admin,
        error_message,
        notice_message,
        new_token: token_value,
        new_token_name: token_name,
        new_token_scope: &token_scope,
    })
    .into_response();
    *response.status_mut() = status;
    response
}

pub async fn account_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let (user, csrf) = match session_or_redirect(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    render_account_page(&ctx, &user, &csrf, "", "", None, None, StatusCode::OK)
}

#[derive(Deserialize)]
pub struct AccountPasswordForm {
    pub current_password: String,
    pub new_password: String,
}

pub async fn account_password_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<AccountPasswordForm>,
) -> Response {
    let (user, csrf) = match session_or_redirect(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    if let Err(problem) = validate_password_policy(&form.new_password) {
        return account_problem_page(&ctx, &user, &csrf, problem);
    }
    if form.current_password.is_empty() {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::bad_request("Current password is required"),
        );
    }
    if !ctx
        .auth_mgr
        .verify_user_password(&user.username, form.current_password.trim())
        .await
    {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::bad_request("Current password is incorrect"),
        );
    }
    if let Err(err) = ctx
        .auth_mgr
        .update_user_password_checked(&user.username, &form.new_password)
        .await
    {
        let problem = match err {
            UserMutationError::NotFound => ProblemDetails::not_found("User account not found"),
            UserMutationError::LastAdmin => {
                ProblemDetails::bad_request("Cannot remove the last remaining admin account")
            }
            UserMutationError::Persistence(detail) => ProblemDetails::internal_error(format!(
                "Failed to persist the user store while changing the password: {detail}"
            )),
        };
        return account_problem_page(&ctx, &user, &csrf, problem);
    }
    tracing::info!(user = %user.username, "User changed their password from the web UI");
    // Password changes revoke every session for the account, including this
    // one, so send the browser back to the login page.
    Redirect::to("/login").into_response()
}

#[derive(Deserialize)]
pub struct CreateAccountTokenForm {
    pub name: String,
    pub scope: String,
}

pub async fn account_token_create_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<CreateAccountTokenForm>,
) -> Response {
    let (user, csrf) = match session_or_redirect(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    let name = form.name.trim();
    if name.is_empty() {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::bad_request("Token name is required"),
        );
    }
    if name.len() > 128 {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::bad_request("Token name must be at most 128 characters"),
        );
    }
    let scope = match Role::from_str(form.scope.trim()) {
        Ok(scope) => scope,
        Err(e) => {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::bad_request(format!("Invalid token scope: {e}")),
            );
        }
    };
    // Tokens are owned per account, and a token must never outrank its owner.
    if scope > user.role {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::forbidden("A token scope may not exceed your own role"),
        );
    }

    let (_meta, token) = match ctx
        .auth_mgr
        .create_token(name, scope, Some(&user.username))
        .await
    {
        Ok(token) => token,
        Err(e) => {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::bad_request(e.to_string()),
            );
        }
    };
    tracing::info!(user = %user.username, token = %token.id, "User created an API token from the web UI");
    // The plaintext token is shown only in this response and is never stored
    // or logged; reloading the page lists metadata only.
    render_account_page(
        &ctx,
        &user,
        &csrf,
        "",
        "",
        Some(&token),
        None,
        StatusCode::OK,
    )
}

pub async fn account_token_delete_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (user, csrf) = match session_or_redirect(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    let Some(token) = ctx
        .auth_mgr
        .list_tokens()
        .into_iter()
        .find(|token| token.id == id)
    else {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::not_found(format!("Token '{id}' not found")),
        );
    };
    // Only the owner may revoke a token. Admins additionally manage legacy
    // ownerless tokens created before ownership was tracked. Another user's
    // token ID must look indistinguishable from a missing token.
    let is_own = token.owner.as_deref() == Some(user.username.as_str());
    let is_admin_legacy = user.role == Role::Admin && token.owner.is_none();
    if !is_own && !is_admin_legacy {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::not_found(format!("Token '{id}' not found")),
        );
    }

    if !ctx.auth_mgr.delete_token(&id).await {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::not_found(format!("Token '{id}' not found")),
        );
    }
    tracing::info!(user = %user.username, token = %id, "User revoked an API token from the web UI");
    Redirect::to("/account").into_response()
}

#[derive(Deserialize)]
pub struct AccountTotpSetupForm {
    pub password: String,
    #[serde(default)]
    pub code: Option<String>,
}

/// Re-authenticate and begin TOTP enrollment (self-service for every role).
pub async fn account_totp_setup_handler(
    State(ctx): State<ServerContext>,
    crate::auth::MaybeConnectInfo(peer_addr): crate::auth::MaybeConnectInfo,
    headers: HeaderMap,
    Form(form): Form<AccountTotpSetupForm>,
) -> Response {
    let (user, csrf) = match session_or_redirect(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let Some(session_id) = current_session_id(&ctx, &headers) else {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::forbidden("TOTP enrollment requires an authenticated user session"),
        );
    };
    let client_ip = {
        let config = ctx.config.load();
        let trusted_proxies = config.get_web_config().trusted_proxies;
        resolve_client_ip(peer_addr, &headers, &trusted_proxies)
    };

    let ticket = match ctx
        .auth_mgr
        .reauth(
            &user.username,
            &form.password,
            form.code.as_deref(),
            &session_id,
            &client_ip,
        )
        .await
    {
        Ok(ticket) => ticket,
        Err(ReauthError::InvalidCredentials) => {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::bad_request(
                    "Re-authentication failed: invalid password or second factor",
                ),
            );
        }
        Err(ReauthError::SecondFactorRequired) => {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::bad_request(
                    "A current TOTP or backup code is required to replace 2FA",
                ),
            );
        }
        Err(ReauthError::RateLimited) => {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::too_many_requests("Too many attempts. Please wait."),
            );
        }
        Err(ReauthError::LockedOut { remaining_seconds }) => {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::too_many_requests(format!(
                    "Account locked out due to repeated failures. Try again in {remaining_seconds}s."
                )),
            );
        }
    };

    let Some(setup) = ctx.auth_mgr.begin_totp_enrollment(&user.username).await else {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::internal_error("Failed to generate TOTP credentials"),
        );
    };
    let view = TotpSetupView {
        secret: setup.secret,
        otpauth_url: setup.otpauth_url,
        qr_code: setup.qr_code,
        backup_codes: setup.backup_codes,
        reauth_token: ticket.token,
    };
    render_account_page(&ctx, &user, &csrf, "", "", None, Some(view), StatusCode::OK)
}

#[derive(Deserialize)]
pub struct AccountTotpEnableForm {
    pub reauth_token: String,
    pub code: String,
}

/// Confirm a pending TOTP enrollment using a re-auth ticket.
pub async fn account_totp_enable_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<AccountTotpEnableForm>,
) -> Response {
    let (user, csrf) = match session_or_redirect(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let Some(session_id) = current_session_id(&ctx, &headers) else {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::forbidden("TOTP enrollment requires an authenticated user session"),
        );
    };
    if !ctx
        .auth_mgr
        .check_reauth_token(&form.reauth_token, &user.username, &session_id)
    {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::unauthorized(
                "Re-authentication is missing or expired. Start the enrollment again.",
            ),
        );
    }
    if let Err(err) = ctx
        .auth_mgr
        .try_confirm_totp_setup(&user.username, &form.code)
        .await
    {
        let problem = match err {
            TotpMutationError::NotFound => ProblemDetails::not_found("User account not found"),
            TotpMutationError::InvalidCode => {
                ProblemDetails::bad_request("Invalid TOTP verification code")
            }
            TotpMutationError::Persistence(detail) => ProblemDetails::internal_error(format!(
                "Failed to persist the user store while enabling TOTP: {detail}"
            )),
        };
        return account_problem_page(&ctx, &user, &csrf, problem);
    }
    let _ = ctx
        .auth_mgr
        .consume_reauth_token(&form.reauth_token, &user.username, &session_id);
    tracing::info!(user = %user.username, "User enabled TOTP 2FA from the web UI");
    // Enabling TOTP revokes every session for the account by design.
    Redirect::to("/login").into_response()
}

#[derive(Deserialize)]
pub struct DisableAccountTotpForm {
    pub password: String,
    #[serde(default)]
    pub code: Option<String>,
}

pub async fn account_totp_disable_handler(
    State(ctx): State<ServerContext>,
    crate::auth::MaybeConnectInfo(peer_addr): crate::auth::MaybeConnectInfo,
    headers: HeaderMap,
    Form(form): Form<DisableAccountTotpForm>,
) -> Response {
    let (user, csrf) = match session_or_redirect(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let Some(session_id) = current_session_id(&ctx, &headers) else {
        return account_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::forbidden("TOTP management requires an authenticated user session"),
        );
    };
    let client_ip = {
        let config = ctx.config.load();
        let trusted_proxies = config.get_web_config().trusted_proxies;
        resolve_client_ip(peer_addr, &headers, &trusted_proxies)
    };

    // Mirror the REST disable handler: a fresh re-authentication proves the
    // current password and, when TOTP is enabled, a current TOTP/backup code.
    match ctx
        .auth_mgr
        .reauth(
            &user.username,
            &form.password,
            form.code.as_deref(),
            &session_id,
            &client_ip,
        )
        .await
    {
        Ok(ticket) => {
            let _ = ctx
                .auth_mgr
                .consume_reauth_token(&ticket.token, &user.username, &session_id);
        }
        Err(ReauthError::InvalidCredentials) => {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::bad_request(
                    "Re-authentication failed: invalid password or second factor",
                ),
            );
        }
        Err(ReauthError::SecondFactorRequired) => {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::bad_request("A TOTP or backup code is required to disable 2FA"),
            );
        }
        Err(ReauthError::RateLimited) => {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::too_many_requests("Too many attempts. Please wait."),
            );
        }
        Err(ReauthError::LockedOut { remaining_seconds }) => {
            return account_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::too_many_requests(format!(
                    "Account locked out due to repeated failures. Try again in {remaining_seconds}s."
                )),
            );
        }
    }

    if let Err(err) = ctx.auth_mgr.try_disable_totp(&user.username).await {
        let problem = match err {
            TotpMutationError::NotFound => ProblemDetails::not_found("User account not found"),
            TotpMutationError::InvalidCode => {
                ProblemDetails::bad_request("Invalid TOTP verification code")
            }
            TotpMutationError::Persistence(detail) => ProblemDetails::internal_error(format!(
                "Failed to persist the user store while disabling TOTP: {detail}"
            )),
        };
        return account_problem_page(&ctx, &user, &csrf, problem);
    }
    tracing::info!(user = %user.username, "User disabled TOTP 2FA from the web UI");
    // Disabling 2FA revokes every session for the account by design.
    Redirect::to("/login").into_response()
}
