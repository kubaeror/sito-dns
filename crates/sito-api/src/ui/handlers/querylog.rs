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
}

pub(crate) async fn fetch_query_rows(
    ctx: &ServerContext,
    p: &QueryLogParams,
) -> Vec<QueryLogRowItem> {
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

    let filter = QueryLogFilter {
        client: p.client.clone().filter(|s| !s.is_empty()),
        domain: p.domain.clone().filter(|s| !s.is_empty()),
        status: status_filter,
        qtype: qtype_num,
        from: None,
        to: None,
        cursor: None,
        limit: Some(50),
        // Live 3 s polling must not run a filtered COUNT(*) over query_log.
        include_total: Some(false),
    };

    let page_res = ctx.stats_db.query_logs(&filter).await;
    let entries = match page_res {
        Ok(p) => p.entries,
        Err(_) => Vec::new(),
    };

    entries
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
        .collect()
}

pub async fn querylog_page(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Query(params): Query<QueryLogParams>,
) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };

    let entries = fetch_query_rows(&ctx, &params).await;
    let csrf = get_csrf_token(&ctx, &headers);

    HtmlTemplate(QueryLogTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "querylog",
        version: env!("CARGO_PKG_VERSION"),
        entries: &entries,
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
    let entries = fetch_query_rows(&ctx, &params).await;
    HtmlTemplate(QueryLogRowsPartialTemplate { entries: &entries }).into_response()
}
