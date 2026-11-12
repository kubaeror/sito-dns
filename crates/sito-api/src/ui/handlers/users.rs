//! User administration page and handlers.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(crate) fn user_view_items(ctx: &ServerContext, current_username: &str) -> Vec<UserViewItem> {
    ctx.auth_mgr
        .list_users()
        .into_iter()
        .map(|user| {
            let encoded = percent_encode_path_segment(&user.username);
            UserViewItem {
                is_current: user.username == current_username,
                username: user.username,
                role: user.role,
                totp_enabled: user.totp_enabled,
                role_action: format!("/ui/users/{encoded}/role"),
                delete_action: format!("/ui/users/{encoded}/delete"),
            }
        })
        .collect()
}

pub(crate) fn render_users_page(
    ctx: &ServerContext,
    user: &AuthUser,
    csrf: &str,
    error_message: &str,
    status: StatusCode,
) -> Response {
    let users = user_view_items(ctx, &user.username);
    let mut response = HtmlTemplate(UsersTemplate {
        csrf_token: csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: user.role.as_str(),
        active_tab: "users",
        version: env!("CARGO_PKG_VERSION"),
        users,
        error_message,
    })
    .into_response();
    *response.status_mut() = status;
    response
}

pub(crate) fn users_problem_page(
    ctx: &ServerContext,
    user: &AuthUser,
    csrf: &str,
    problem: ProblemDetails,
) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::BAD_REQUEST);
    let detail = problem.detail;
    render_users_page(ctx, user, csrf, &detail, status)
}

pub(crate) fn account_problem_page(
    ctx: &ServerContext,
    user: &AuthUser,
    csrf: &str,
    problem: ProblemDetails,
) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::BAD_REQUEST);
    let detail = problem.detail;
    render_account_page(ctx, user, csrf, &detail, "", None, None, status)
}

pub async fn users_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let (user, csrf) = match admin_or_forbidden(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    render_users_page(&ctx, &user, &csrf, "", StatusCode::OK)
}

#[derive(Deserialize)]
pub struct CreateUserForm {
    pub username: String,
    pub password: String,
    pub role: String,
}

pub async fn users_create_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<CreateUserForm>,
) -> Response {
    let (user, csrf) = match admin_or_forbidden(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    let username = form.username.trim();
    let role = match validate_username(username)
        .and_then(|()| validate_password_policy(&form.password))
        .and_then(|()| {
            Role::from_str(form.role.trim())
                .map_err(|e| ProblemDetails::bad_request(format!("Invalid role: {e}")))
        }) {
        Ok(role) => role,
        Err(problem) => return users_problem_page(&ctx, &user, &csrf, problem),
    };

    if ctx.auth_mgr.has_user(username) {
        return users_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::conflict(format!("User '{username}' already exists")),
        );
    }

    if let Err(e) = ctx
        .auth_mgr
        .create_user_persisted(username, &form.password, role)
        .await
    {
        return users_problem_page(
            &ctx,
            &user,
            &csrf,
            ProblemDetails::internal_error(format!("Failed to persist the user store: {e}")),
        );
    }
    tracing::info!(
        actor = %user.username,
        target = %username,
        role = %role,
        "Administrator created a user account"
    );
    Redirect::to("/users").into_response()
}

#[derive(Deserialize)]
pub struct UpdateUserRoleForm {
    pub role: String,
}

pub async fn users_role_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Form(form): Form<UpdateUserRoleForm>,
) -> Response {
    let (user, csrf) = match admin_or_forbidden(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    let role = match Role::from_str(form.role.trim()) {
        Ok(role) => role,
        Err(e) => {
            return users_problem_page(
                &ctx,
                &user,
                &csrf,
                ProblemDetails::bad_request(format!("Invalid role: {e}")),
            );
        }
    };
    if let Err(err) = ctx.auth_mgr.set_user_role_checked(&username, role).await {
        let problem = user_mutation_problem(&username, "demote", err);
        return users_problem_page(&ctx, &user, &csrf, problem);
    }
    tracing::info!(
        actor = %user.username,
        target = %username,
        role = %role,
        "Administrator changed a user role"
    );
    Redirect::to("/users").into_response()
}

pub async fn users_delete_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Response {
    let (user, csrf) = match admin_or_forbidden(&ctx, &headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    if let Err(err) = ctx.auth_mgr.delete_user_checked(&username).await {
        let problem = user_mutation_problem(&username, "delete", err);
        return users_problem_page(&ctx, &user, &csrf, problem);
    }
    tracing::info!(
        actor = %user.username,
        target = %username,
        "Administrator deleted a user account"
    );
    Redirect::to("/users").into_response()
}
