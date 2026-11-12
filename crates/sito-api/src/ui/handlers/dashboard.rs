//! Dashboard page and live statistics partial.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn get_upstreams_list(ctx: &ServerContext) -> Vec<UpstreamViewItem> {
    let cfg = ctx.config.load();
    let statuses = ctx.upstream.statuses().await;
    let stats = ctx
        .stats_db
        .get_upstream_stats_cached(86_400_000)
        .await
        .unwrap_or_default();

    let mut res = Vec::new();
    for addr_str in &cfg.upstream.servers {
        let proto = if addr_str.starts_with("tls://") {
            "DoT (TLS)"
        } else if addr_str.starts_with("udp://")
            || addr_str.contains(":53")
            || !addr_str.contains(':')
        {
            "UDP"
        } else {
            "DNS"
        };

        let is_healthy = statuses
            .iter()
            .find(|(name, _)| name == addr_str)
            .is_none_or(|(_, status)| *status != sito_upstream::HealthStatus::Down);

        let (total_queries, avg_latency_ms) = stats
            .iter()
            .find(|s| &s.upstream == addr_str || addr_str.contains(&s.upstream))
            .map_or((0, 0.0), |s| {
                (s.total_queries, (s.avg_elapsed_us as f64) / 1000.0)
            });

        res.push(UpstreamViewItem {
            address: addr_str.clone(),
            protocol: proto.to_string(),
            is_healthy,
            weight: 100,
            total_queries: total_queries.max(0) as u64,
            avg_latency_ms,
        });
    }
    res
}

pub async fn dashboard_page(State(ctx): State<ServerContext>, headers: HeaderMap) -> Response {
    let Some(user) = get_session_user(&ctx, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let csrf = get_csrf_token(&ctx, &headers);

    let stats = ctx
        .stats_db
        .get_global_stats_cached(86_400_000)
        .await
        .unwrap_or_default();
    let status = get_status_response(&ctx).await;
    let uptime_str = format_duration(status.uptime_seconds);
    let blocked_pct_str = format!("{:.1}", stats.blocked_percentage);
    let upstreams = get_upstreams_list(&ctx).await;

    let hourly = ctx
        .stats_db
        .get_hourly_activity_cached(24)
        .await
        .unwrap_or_default();
    let times: Vec<i64> = hourly.iter().map(|h| h.timestamp_sec).collect();
    let totals: Vec<i64> = hourly.iter().map(|h| h.total_queries).collect();
    let blocked: Vec<i64> = hourly.iter().map(|h| h.blocked_queries).collect();

    let hourly_times_json = serde_json::to_string(&times).unwrap_or_else(|_| "[]".to_string());
    let hourly_totals_json = serde_json::to_string(&totals).unwrap_or_else(|_| "[]".to_string());
    let hourly_blocked_json = serde_json::to_string(&blocked).unwrap_or_else(|_| "[]".to_string());

    HtmlTemplate(DashboardTemplate {
        csrf_token: &csrf,
        is_authenticated: true,
        username: &user.username,
        user_role: &user.role.to_string(),
        active_tab: "dashboard",
        version: env!("CARGO_PKG_VERSION"),
        stats: &stats,
        status: &status,
        uptime_str,
        blocked_pct_str,
        upstreams,
        hourly_times_json,
        hourly_totals_json,
        hourly_blocked_json,
    })
    .into_response()
}

pub async fn dashboard_stats_partial(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
) -> Response {
    if get_session_user(&ctx, &headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let stats = ctx
        .stats_db
        .get_global_stats_cached(86_400_000)
        .await
        .unwrap_or_default();
    let status = get_status_response(&ctx).await;
    let uptime_str = format_duration(status.uptime_seconds);
    let blocked_pct_str = format!("{:.1}", stats.blocked_percentage);

    HtmlTemplate(DashboardStatsPartialTemplate {
        stats: &stats,
        status: &status,
        uptime_str,
        blocked_pct_str,
    })
    .into_response()
}
