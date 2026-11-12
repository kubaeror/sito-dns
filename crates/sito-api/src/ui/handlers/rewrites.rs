//! Rewrite page and add/delete handlers.

#[allow(clippy::wildcard_imports)]
use super::*;

// ---------------------------------------------------------------------------
// DNS Rewrites
// ---------------------------------------------------------------------------

pub async fn rewrites_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let csrf = get_csrf_token(&ctx, &headers);

    let store = crate::handlers::rewrites::load_rewrite_store(&ctx);
    let rewrites: Vec<RewriteViewItem> = store
        .ids
        .into_iter()
        .zip(store.cfg.entries)
        .map(|(id, r)| RewriteViewItem {
            id,
            domain: r.domain,
            record_type: r.r#type,
            answer: r.answer,
        })
        .collect();

    HtmlTemplate(RewritesTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "rewrites",
        version: env!("CARGO_PKG_VERSION"),
        rewrites,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct AddRewriteForm {
    pub domain: String,
    pub record_type: String,
    pub answer: String,
}

pub async fn rewrites_add_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<AddRewriteForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let _apply_guard = ctx.lock_config_apply().await;
    let mut store = crate::handlers::rewrites::load_rewrite_store(&ctx);
    store.cfg.entries.push(sito_rewrites::RewriteEntryConfig {
        domain: form.domain,
        r#type: form.record_type,
        answer: form.answer,
        exception_clients: Vec::new(),
    });
    store.ids.push(crate::handlers::rewrites::new_rewrite_id());

    if let Err(e) = crate::handlers::rewrites::save_rewrite_store_locked(&ctx, &store).await {
        tracing::error!("Failed to persist rewrites: {e:?}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to persist rewrites: {}", e.detail),
        );
    }

    Redirect::to("/rewrites").into_response()
}

#[derive(Deserialize)]
pub struct DeleteRewriteForm {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub record_type: Option<String>,
    #[serde(default)]
    pub answer: Option<String>,
}

pub async fn rewrites_delete_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Form(form): Form<DeleteRewriteForm>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Operator {
        return StatusCode::FORBIDDEN.into_response();
    }

    let _apply_guard = ctx.lock_config_apply().await;
    let mut store = crate::handlers::rewrites::load_rewrite_store(&ctx);
    let idx = if let Some(ref id) = form.id {
        crate::handlers::rewrites::resolve_rewrite_index(&store, id)
    } else {
        store.cfg.entries.iter().position(|e| {
            form.domain.as_deref().is_none_or(|d| e.domain == d)
                && form.record_type.as_deref().is_none_or(|t| e.r#type == t)
                && form.answer.as_deref().is_none_or(|a| e.answer == a)
        })
    };
    let Some(idx) = idx else {
        return error_response(StatusCode::NOT_FOUND, "Rewrite not found");
    };
    store.cfg.entries.remove(idx);
    store.ids.remove(idx);

    if let Err(e) = crate::handlers::rewrites::save_rewrite_store_locked(&ctx, &store).await {
        tracing::error!("Failed to persist rewrites: {e:?}");
        return error_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &format!("Failed to persist rewrites: {}", e.detail),
        );
    }

    Redirect::to("/rewrites").into_response()
}
