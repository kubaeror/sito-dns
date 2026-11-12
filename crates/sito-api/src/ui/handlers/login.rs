//! Root, login, and logout pages.

#[allow(clippy::wildcard_imports)]
use super::*;

// ---------------------------------------------------------------------------

pub async fn root_handler(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    if get_session_user(&ctx, &headers).is_some() {
        Redirect::to("/dashboard").into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

pub async fn login_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    if get_session_user(&ctx, &headers).is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    HtmlTemplate(LoginTemplate {
        is_authenticated: false,
        username: "",
        user_role: "",
        active_tab: "login",
        version: env!("CARGO_PKG_VERSION"),
        error_message: "",
        csrf_token: "",
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
}

pub async fn login_submit(
    State(ctx): State<ServerContext>,
    crate::auth::MaybeConnectInfo(peer_addr): crate::auth::MaybeConnectInfo,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let (trusted_proxies, is_secure) = {
        let config = ctx.config.load();
        let trusted_proxies = config.get_web_config().trusted_proxies;
        let scheme = crate::auth::admin_scheme_config(config.web.as_ref());
        let is_secure =
            crate::auth::is_https_request(peer_addr, &headers, &trusted_proxies, &scheme);
        (trusted_proxies, is_secure)
    };
    let client_ip = resolve_client_ip(peer_addr, &headers, &trusted_proxies);
    let result = ctx
        .auth_mgr
        .login(&form.username, &form.password, &client_ip)
        .await;

    match result {
        LoginResult::Success(session) => {
            let mut resp = Redirect::to("/dashboard").into_response();
            let max_age = (session.expires_at - Utc::now().timestamp()).max(0);
            append_cookie(
                &mut resp,
                &crate::auth::session::build_session_cookie(&session.id, max_age, is_secure),
            );
            append_cookie(
                &mut resp,
                &build_csrf_cookie(&session.csrf_token, max_age, is_secure),
            );
            resp
        }
        LoginResult::TotpRequired { partial_token } => {
            if let Some(ref code) = form.totp
                && !code.trim().is_empty()
            {
                match ctx
                    .auth_mgr
                    .verify_totp(&partial_token, code.trim(), &client_ip)
                    .await
                {
                    crate::auth::manager::TotpVerifyResult::Success(session) => {
                        let mut resp = Redirect::to("/dashboard").into_response();
                        let max_age = (session.expires_at - Utc::now().timestamp()).max(0);
                        append_cookie(
                            &mut resp,
                            &crate::auth::session::build_session_cookie(
                                &session.id,
                                max_age,
                                is_secure,
                            ),
                        );
                        append_cookie(
                            &mut resp,
                            &build_csrf_cookie(&session.csrf_token, max_age, is_secure),
                        );
                        return resp;
                    }
                    crate::auth::manager::TotpVerifyResult::LockedOut { .. } => {
                        return HtmlTemplate(LoginTemplate {
                            is_authenticated: false,
                            username: &form.username,
                            user_role: "",
                            active_tab: "login",
                            version: env!("CARGO_PKG_VERSION"),
                            error_message: "Account locked out due to failed attempts. Try again later.",
                            csrf_token: "",
                        })
                        .into_response();
                    }
                    crate::auth::manager::TotpVerifyResult::RateLimited => {
                        return HtmlTemplate(LoginTemplate {
                            is_authenticated: false,
                            username: &form.username,
                            user_role: "",
                            active_tab: "login",
                            version: env!("CARGO_PKG_VERSION"),
                            error_message: "Too many attempts. Please wait and try again.",
                            csrf_token: "",
                        })
                        .into_response();
                    }
                    crate::auth::manager::TotpVerifyResult::Invalid
                    | crate::auth::manager::TotpVerifyResult::TokenExpired => {}
                }
            }
            HtmlTemplate(LoginTemplate {
                is_authenticated: false,
                username: &form.username,
                user_role: "",
                active_tab: "login",
                version: env!("CARGO_PKG_VERSION"),
                error_message: "2FA TOTP code required or code is invalid.",
                csrf_token: "",
            })
            .into_response()
        }
        LoginResult::LockedOut { .. } => HtmlTemplate(LoginTemplate {
            is_authenticated: false,
            username: &form.username,
            user_role: "",
            active_tab: "login",
            version: env!("CARGO_PKG_VERSION"),
            error_message: "Account locked out due to failed attempts. Try again later.",
            csrf_token: "",
        })
        .into_response(),
        LoginResult::RateLimited => HtmlTemplate(LoginTemplate {
            is_authenticated: false,
            username: &form.username,
            user_role: "",
            active_tab: "login",
            version: env!("CARGO_PKG_VERSION"),
            error_message: "Too many attempts from this IP address. Please wait.",
            csrf_token: "",
        })
        .into_response(),
        LoginResult::InvalidCredentials { .. } | LoginResult::StaleCredentials => {
            HtmlTemplate(LoginTemplate {
                is_authenticated: false,
                username: &form.username,
                user_role: "",
                active_tab: "login",
                version: env!("CARGO_PKG_VERSION"),
                error_message: "Invalid username or password.",
                csrf_token: "",
            })
            .into_response()
        }
    }
}

pub async fn logout_handler(
    State(ctx): State<ServerContext>,
    crate::auth::MaybeConnectInfo(peer_addr): crate::auth::MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    if let Some(cookie_hdr) = headers.get("cookie")
        && let Ok(s) = cookie_hdr.to_str()
        && let Some(session_id) = extract_session_cookie(s)
    {
        ctx.auth_mgr.logout(&session_id).await;
    }
    let is_secure = {
        let config = ctx.config.load();
        let trusted_proxies = config.get_web_config().trusted_proxies;
        let scheme = crate::auth::admin_scheme_config(config.web.as_ref());
        crate::auth::is_https_request(peer_addr, &headers, &trusted_proxies, &scheme)
    };
    let mut resp = Redirect::to("/login").into_response();
    append_cookie(&mut resp, &build_clear_session_cookie(is_secure));
    append_cookie(&mut resp, &build_clear_csrf_cookie(is_secure));
    resp
}
