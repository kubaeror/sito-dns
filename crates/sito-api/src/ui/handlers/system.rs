//! System page, reload, and self-update handlers.

#[allow(clippy::wildcard_imports)]
use super::*;

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

pub async fn system_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let csrf = get_csrf_token(&ctx, &headers);

    let status = get_status_response(&ctx);
    let uptime_str = format_duration(status.uptime_seconds);

    HtmlTemplate(SystemTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "system",
        version: env!("CARGO_PKG_VERSION"),
        status: &status,
        uptime_str,
    })
    .into_response()
}

pub async fn system_reload_handler(
    State(ctx): State<ServerContext>,
    Extension(hooks): Extension<ApplyHooks>,
    headers: HeaderMap,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if user.role < Role::Admin {
        return StatusCode::FORBIDDEN.into_response();
    }

    let toml_str = match tokio::fs::read_to_string(&ctx.config_path).await {
        Ok(content) => content,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to read configuration file: {e}"),
            );
        }
    };
    // One shared apply/publish path with the REST reload and file watcher:
    // deep validation, rollback on failure, D8 HA semantics, and oversized
    // bundle rollback all behave identically here.
    match apply_config_document_event(&ctx, &toml_str, FilterApply::Sync, hooks.as_dyn()).await {
        ConfigFileApplyOutcome::SelfWriteIgnored | ConfigFileApplyOutcome::Applied(_) => {
            Redirect::to("/system").into_response()
        }
        ConfigFileApplyOutcome::Rejected(e) => {
            tracing::error!("Failed to apply configuration on reload: {e:?}");
            error_response(
                StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                &format!("Failed to apply configuration: {}", e.detail),
            )
        }
    }
}

/// Renders the update action row for the system page.
///
/// Session-authenticated HTMX posts must carry the session CSRF token. The
/// form includes it as a hidden field (matching the Askama forms) and lets
/// htmx perform the submission; calling `form.submit()` natively would bypass
/// htmx and still lack the token.
pub(crate) fn update_action_html(info: &crate::updater::UpdateInfo, csrf_token: &str) -> String {
    if info.is_docker {
        return r#"<div style="margin-top: 14px; padding: 12px; background: rgba(56, 189, 248, 0.1); border: 1px solid var(--accent); border-radius: 6px;">
                <div style="font-weight: 600; color: var(--accent); margin-bottom: 4px;">Docker Environment Detected</div>
                <div style="font-size: 0.85rem; color: var(--text-secondary);">
                    In-app binary updates are disabled in containers. Upgrade by running:
                    <pre style="margin-top: 6px; padding: 6px 10px; background: var(--bg-surface); border-radius: 4px;"><code>docker compose pull && docker compose up -d</code></pre>
                </div>
            </div>"#
            .to_string();
    }

    format!(
        r##"<form hx-post="/ui/system/update/apply" hx-target="#update-container" hx-swap="innerHTML" hx-disabled-elt="button" style="margin-top: 14px;">
            <input type="hidden" name="csrf_token" value="{}">
            <button type="submit" class="btn btn-primary" @click="this.innerText='Updating...';">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>
                Download & Install v{}
            </button>
        </form>"##,
        escape_html(csrf_token),
        escape_html(&info.latest_version)
    )
}

pub async fn system_update_check_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
) -> Response {
    if get_session_user(&ctx, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }
    let csrf = get_csrf_token(&ctx, &headers);

    match crate::updater::check_for_update(None).await {
        Ok(info) => {
            if info.update_available {
                let install_or_docker = update_action_html(&info, &csrf);

                axum::response::Html(format!(
                    r#"<div>
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
                            <div>
                                <span class="badge badge-warning" style="font-size: 0.85rem;">New version available: v{}</span>
                                <span style="font-size: 0.85rem; color: var(--text-secondary); margin-left: 8px;">(Current: v{})</span>
                            </div>
                            <a href="{}" target="_blank" rel="noopener" class="btn btn-outline" style="font-size: 0.8rem; padding: 4px 10px;">View on GitHub</a>
                        </div>
                        <div style="background: var(--bg-base); padding: 12px; border-radius: 6px; font-size: 0.85rem; max-height: 150px; overflow-y: auto; white-space: pre-wrap; font-family: monospace;">{}</div>
                        {}
                    </div>"#,
                    escape_html(&info.latest_version),
                    escape_html(&info.current_version),
                    escape_html(&info.release_url),
                    escape_html(&info.release_notes),
                    install_or_docker
                )).into_response()
            } else {
                axum::response::Html(format!(
                    r##"<div>
                        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
                            <span class="badge badge-success" style="font-size: 0.85rem;">Up to date</span>
                            <span style="font-size: 0.875rem; color: var(--text-secondary);">sito is running the latest release (v{})</span>
                        </div>
                        <button hx-get="/ui/system/update/check" hx-target="#update-container" hx-swap="innerHTML" class="btn btn-outline" style="font-size: 0.8rem; padding: 4px 10px;">
                            Check Again
                        </button>
                    </div>"##,
                    escape_html(&info.current_version)
                )).into_response()
            }
        }
        Err(e) => {
            axum::response::Html(format!(
                r##"<div>
                    <div style="padding: 10px 14px; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); border-radius: 6px; color: var(--danger); font-size: 0.875rem; margin-bottom: 12px;">
                        Failed to check for updates: {}
                    </div>
                    <button hx-get="/ui/system/update/check" hx-target="#update-container" hx-swap="innerHTML" class="btn btn-outline" style="font-size: 0.8rem; padding: 4px 10px;">
                        Retry
                    </button>
                </div>"##,
                escape_html(&e.to_string())
            )).into_response()
        }
    }
}

pub async fn system_update_apply_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };

    if user.role != crate::auth::token::Role::Admin {
        return axum::response::Html(
            r#"<div style="padding: 12px; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); border-radius: 6px; color: var(--danger); font-size: 0.875rem;">
                Permission denied: Only administrators can install updates.
            </div>"#,
        ).into_response();
    }

    let require_signature = ctx.config.load().server.update_require_signature;
    match crate::updater::apply_update(None, false, require_signature).await {
        Ok(msg) => axum::response::Html(format!(
            r#"<div style="padding: 14px; background: rgba(34, 197, 94, 0.1); border: 1px solid var(--success); border-radius: 6px;">
                <div style="font-weight: 600; color: var(--success); margin-bottom: 4px;">Update Successful!</div>
                <div style="font-size: 0.875rem; color: var(--text-primary);">{}</div>
            </div>"#,
            escape_html(&msg)
        )).into_response(),
        Err(e) => axum::response::Html(format!(
            r##"<div>
                <div style="padding: 14px; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); border-radius: 6px; color: var(--danger); font-size: 0.875rem; margin-bottom: 12px;">
                    <strong>Update Failed:</strong> {}
                </div>
                <button hx-get="/ui/system/update/check" hx-target="#update-container" hx-swap="innerHTML" class="btn btn-outline" style="font-size: 0.8rem; padding: 4px 10px;">
                    Back to Update Status
                </button>
            </div>"##,
            escape_html(&e.to_string())
        )).into_response(),
    }
}
