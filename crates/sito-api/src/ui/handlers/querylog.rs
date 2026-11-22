//! Query log page, rows, and filters.

#[allow(clippy::wildcard_imports)]
use super::*;

// ---------------------------------------------------------------------------
// Query Log
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct QueryLogParams {
    pub domain: Option<String>,
    pub client: Option<String>,
    pub status: Option<String>,
    pub qtype: Option<String>,
    /// Opaque keyset cursor for the next/older page.
    ///
    /// The live refresh and filter controls deliberately never send this, so a
    /// filter change or refresh starts again at the newest page.
    pub cursor: Option<String>,
}

/// One rendered query-log page plus the cursor for the page below it.
///
/// The UI keeps the cursor out of the filter form: it is attached to the
/// explicit "Load older" control only, so filters/refresh reset pagination.
pub(crate) struct QueryLogRowsPage {
    pub entries: Vec<QueryLogRowItem>,
    pub next_cursor: Option<String>,
}

/// Builds the query-log filter used by the live UI refresh.
///
/// Exposed to the tests so a regression cannot silently bring back a total
/// count on every poll. The page read path never counts; `next_cursor` is
/// ignored here because the live 3 s refresh always shows the newest page.
pub(crate) fn live_query_log_filter(p: &QueryLogParams) -> QueryLogFilter {
    let qtype_num = p.qtype.as_deref().and_then(|s| {
        if s == "all" || s.is_empty() {
            None
        } else {
            s.parse::<u16>().ok()
        }
    });

    let status_filter = p.status.as_deref().and_then(|s| {
        if s == "all" || s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    });

    QueryLogFilter {
        client: p.client.clone().filter(|s| !s.is_empty()),
        domain: p.domain.clone().filter(|s| !s.is_empty()),
        status: status_filter,
        qtype: qtype_num,
        from: None,
        to: None,
        cursor: None,
        limit: Some(50),
    }
}

/// Builds the page filter, carrying the explicit history cursor when one was
/// supplied. An empty cursor is treated as absent so the live page stays the
/// default for filter and refresh requests.
pub(crate) fn query_log_filter(p: &QueryLogParams) -> QueryLogFilter {
    let mut filter = live_query_log_filter(p);
    filter.cursor = p.cursor.clone().filter(|cursor| !cursor.is_empty());
    filter
}

pub(crate) async fn fetch_query_rows(ctx: &ServerContext, p: &QueryLogParams) -> QueryLogRowsPage {
    let filter = query_log_filter(p);

    let page_res = ctx.stats_db.query_logs(&filter).await;
    let (entries, next_cursor) = match page_res {
        Ok(page) => (page.items, page.next_cursor),
        Err(_) => (Vec::new(), None),
    };

    let entries = entries
        .into_iter()
        .map(|e| {
            let dt = DateTime::<Utc>::from_timestamp_millis(e.ts).unwrap_or_default();
            let time_str = dt.format("%H:%M:%S").to_string();
            let latency_str = if let Some(us) = e.elapsed_us {
                format!("{:.1} ms", (us as f64) / 1000.0)
            } else {
                "<1 ms".to_string()
            };
            QueryLogRowItem {
                // Stable client-side key for de-duplicating rows appended by
                // "Load older"; the DB row id is unique even when two queries
                // share a millisecond timestamp.
                row_key: e
                    .id
                    .map_or_else(|| format!("ts-{}", e.ts), |id| format!("id-{id}")),
                ts: e.ts,
                time_str,
                client_ip: e.client_ip,
                client_name: e.client_name,
                qname: e.qname,
                qtype_str: qtype_to_str(e.qtype).to_string(),
                verdict: e.verdict,
                latency_str,
                rule: e.rule,
                upstream: e.upstream,
            }
        })
        .collect();

    QueryLogRowsPage {
        entries,
        next_cursor,
    }
}

pub async fn querylog_page(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Query(params): Query<QueryLogParams>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };

    // A full page load always starts in live mode at the newest page, even if a
    // stale `?cursor=` is present in the URL. History is only entered through
    // the explicit HTMX Load older control.
    let page = fetch_query_rows(
        &ctx,
        &QueryLogParams {
            cursor: None,
            ..params
        },
    )
    .await;
    let csrf = get_csrf_token(&ctx, &headers);

    HtmlTemplate(QueryLogTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "querylog",
        version: env!("CARGO_PKG_VERSION"),
        entries: &page.entries,
        next_cursor: page.next_cursor.as_deref(),
        // A full page load always starts in live mode at the newest page.
        history_mode: false,
        controls_oob: false,
    })
    .into_response()
}

pub async fn querylog_rows_partial(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Query(params): Query<QueryLogParams>,
) -> Response {
    if get_session_user(&ctx, &headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let page = fetch_query_rows(&ctx, &params).await;
    HtmlTemplate(QueryLogRowsPartialTemplate {
        entries: &page.entries,
        next_cursor: page.next_cursor.as_deref(),
        // A request that carried a cursor is an explicit history page; the
        // response must keep polling paused. Requests without a cursor are
        // live refresh/filter/back-to-live responses.
        history_mode: params.cursor.as_deref().is_some_and(|c| !c.is_empty()),
        controls_oob: true,
    })
    .into_response()
}
