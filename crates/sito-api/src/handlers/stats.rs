//! Statistics endpoint handlers.
//!
//! Long windows are answered from the `stats_hourly` rollups, so requesting
//! more than the detailed query-log retention still reports the archived
//! totals instead of silently returning only retained data.
//!
//! The bounded per-client/per-upstream endpoints return at most
//! [`sito_stats::MAX_AGGREGATE_ROWS`] rows and expose the number of distinct
//! matching rows in the `X-Total-Count` response header.

use crate::auth::RequireViewer;
use crate::error::ProblemDetails;
use crate::models::StatsQuery;
use crate::state::ServerContext;
use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use sito_stats::{ClientStats, GlobalStats, UpstreamStats};

/// Longest accepted statistics window (5 years) — prevents absurd inputs from
/// overflowing the millisecond conversion.
pub const MAX_WINDOW_HOURS: i64 = 24 * 366 * 5;

/// Builds the `X-Total-Count` header describing how many distinct rows match
/// the window before the bounded aggregate query truncated the list.
fn total_count_header(total: i64) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let value =
        HeaderValue::from_str(&total.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0"));
    headers.insert(HeaderName::from_static("x-total-count"), value);
    headers
}

/// Parses the `window` query parameter into milliseconds, clamping the result
/// and rejecting absurd values with `400 Bad Request`.
pub fn parse_window_ms(window: Option<&str>) -> Result<i64, ProblemDetails> {
    let hours = match window {
        None | Some("" | "24h") => 24,
        Some("1h") => 1,
        Some("7d") => 7 * 24,
        Some("30d") => 30 * 24,
        Some("90d") => 90 * 24,
        Some(other) => {
            let trimmed = other.trim();
            let Some(raw_hours) = trimmed.strip_suffix('h') else {
                return Err(ProblemDetails::bad_request(format!(
                    "Invalid window '{other}'. Use 1h, 24h, 7d, 30d or 90d."
                )));
            };
            match raw_hours.parse::<i64>() {
                Ok(hours) if (1..=MAX_WINDOW_HOURS).contains(&hours) => hours,
                Ok(_) => {
                    return Err(ProblemDetails::bad_request(format!(
                        "Window '{other}' is out of range (max {MAX_WINDOW_HOURS}h)."
                    )));
                }
                Err(_) => {
                    return Err(ProblemDetails::bad_request(format!(
                        "Invalid window '{other}'. Use 1h, 24h, 7d, 30d or 90d."
                    )));
                }
            }
        }
    };

    hours
        .checked_mul(3600)
        .and_then(|secs| secs.checked_mul(1000))
        .ok_or_else(|| ProblemDetails::bad_request("Statistics window is too large."))
}

#[utoipa::path(
    get,
    path = "/api/v1/stats",
    params(StatsQuery),
    responses(
        (status = 200, description = "Global statistics retrieved", body = GlobalStats),
        (status = 400, description = "Invalid window", body = ProblemDetails),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Stats"
)]
pub async fn get_stats(
    _viewer: RequireViewer,
    State(ctx): State<ServerContext>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<GlobalStats>, ProblemDetails> {
    let window_ms = parse_window_ms(query.window.as_deref())?;
    let stats = ctx
        .stats_db
        .get_global_stats(window_ms)
        .await
        .map_err(|e| ProblemDetails::internal_error(e.to_string()))?;
    Ok(Json(stats))
}

#[utoipa::path(
    get,
    path = "/api/v1/stats/clients",
    params(StatsQuery),
    responses(
        (status = 200, description = "Per-client statistics retrieved", body = Vec<ClientStats>,
            headers(("X-Total-Count", description = "Number of distinct matching rows before the response limit"))),
        (status = 400, description = "Invalid window", body = ProblemDetails),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Stats"
)]
pub async fn get_client_stats(
    _viewer: RequireViewer,
    State(ctx): State<ServerContext>,
    Query(query): Query<StatsQuery>,
) -> Result<(HeaderMap, Json<Vec<ClientStats>>), ProblemDetails> {
    let window_ms = parse_window_ms(query.window.as_deref())?;
    let total = ctx
        .stats_db
        .count_client_stats(window_ms)
        .await
        .map_err(|e| ProblemDetails::internal_error(e.to_string()))?;
    let stats = ctx
        .stats_db
        .get_client_stats(window_ms)
        .await
        .map_err(|e| ProblemDetails::internal_error(e.to_string()))?;
    Ok((total_count_header(total), Json(stats)))
}

#[utoipa::path(
    get,
    path = "/api/v1/stats/upstreams",
    params(StatsQuery),
    responses(
        (status = 200, description = "Per-upstream statistics retrieved", body = Vec<UpstreamStats>,
            headers(("X-Total-Count", description = "Number of distinct matching rows before the response limit"))),
        (status = 400, description = "Invalid window", body = ProblemDetails),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    ),
    tag = "Stats"
)]
pub async fn get_upstream_stats(
    _viewer: RequireViewer,
    State(ctx): State<ServerContext>,
    Query(query): Query<StatsQuery>,
) -> Result<(HeaderMap, Json<Vec<UpstreamStats>>), ProblemDetails> {
    let window_ms = parse_window_ms(query.window.as_deref())?;
    let total = ctx
        .stats_db
        .count_upstream_stats(window_ms)
        .await
        .map_err(|e| ProblemDetails::internal_error(e.to_string()))?;
    let stats = ctx
        .stats_db
        .get_upstream_stats(window_ms)
        .await
        .map_err(|e| ProblemDetails::internal_error(e.to_string()))?;
    Ok((total_count_header(total), Json(stats)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_parsing_and_clamping() {
        assert_eq!(parse_window_ms(None).unwrap(), 24 * 3600 * 1000);
        assert_eq!(parse_window_ms(Some("1h")).unwrap(), 3600 * 1000);
        assert_eq!(parse_window_ms(Some("7d")).unwrap(), 7 * 24 * 3600 * 1000);
        assert_eq!(parse_window_ms(Some("48h")).unwrap(), 48 * 3600 * 1000);

        // Absurd inputs are rejected instead of overflowing.
        assert!(parse_window_ms(Some("999999999999999999h")).is_err());
        assert!(parse_window_ms(Some("99999999999999999999")).is_err());
        assert!(parse_window_ms(Some("not-a-window")).is_err());
        assert!(parse_window_ms(Some("0h")).is_err());
        // The documented maximum (5 years) is still accepted.
        assert!(parse_window_ms(Some(&format!("{MAX_WINDOW_HOURS}h"))).is_ok());
        assert!(parse_window_ms(Some(&format!("{}h", MAX_WINDOW_HOURS + 1))).is_err());
    }

    use crate::auth::AuthUser;
    use crate::auth::token::Role;
    use arc_swap::ArcSwap;
    use sito_core::config::Config;
    use sito_stats::QueryLogEntry;
    use std::sync::{Arc, Mutex};

    async fn mock_context(temp_dir: &std::path::Path) -> ServerContext {
        let db_path = temp_dir.join("test.db");
        let stats_db = sito_stats::StatsDb::open(&db_path).await.unwrap();
        let querylog_writer = sito_stats::QueryLogWriter::spawn(stats_db.clone(), 100);
        let querylog_sender = querylog_writer.sender();
        let metrics = sito_stats::MetricsRegistry::new("1.2.1", "test");
        let auth_mgr = Arc::new(crate::auth::AuthManager::new());
        let config = Config::default();
        let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
        let filter = Arc::new(
            sito_filter::HostsFilterEngine::init(Default::default(), temp_dir.to_path_buf()).await,
        );
        let cache = Arc::new(sito_cache::DnsCache::new(Default::default()));
        let bootstrap = sito_upstream::BootstrapResolver::new(
            vec!["127.0.0.1".parse().unwrap()],
            std::time::Duration::from_secs(1),
        );
        let upstream = Arc::new(
            sito_upstream::UpstreamManager::from_config(&Default::default(), &bootstrap)
                .await
                .unwrap(),
        );
        let clients = Arc::new(ArcSwap::new(Arc::new(sito_clients::ClientRegistry::new(
            Default::default(),
        ))));
        let rewrites = Arc::new(ArcSwap::new(Arc::new(sito_rewrites::RewriteTable::new(
            Default::default(),
        ))));
        let runtime = Arc::new(sito_runtime::RuntimeState::new(
            config_arc.clone(),
            clients.clone(),
            rewrites.clone(),
        ));
        let runtime_lists = Arc::new(sito_clients::RuntimeLists::from_arcs(
            Arc::new(
                sito_clients::ParentalRegistry::try_bundled()
                    .expect("bundled parental lists must load"),
            ),
            Arc::new(
                sito_clients::ServiceRegistry::try_bundled().expect("bundled services must load"),
            ),
        ));

        ServerContext {
            config: config_arc,
            runtime,
            runtime_lists,
            config_path: temp_dir.join("config.toml"),
            auth_mgr,
            stats_db,
            querylog_sender,
            metrics,
            filter,
            cache,
            upstream,
            clients,
            rewrites,
            start_time: std::time::Instant::now(),
            restore_tokens: Arc::new(Mutex::new(std::collections::HashMap::new())),
            apply_lock: Arc::new(tokio::sync::Mutex::new(())),
            master_coordinator: None,
            slave_tracker: None,
            resync_sender: None,
            setup_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            dns_starter: None,
        }
    }

    fn viewer() -> RequireViewer {
        RequireViewer(AuthUser {
            username: "viewer".to_string(),
            role: Role::Viewer,
            token_id: None,
        })
    }

    /// WP-7.2: a window longer than the detailed retention must include the
    /// hourly rollups instead of silently returning only retained data, and the
    /// bounded aggregate endpoints report the distinct totals.
    #[tokio::test]
    async fn test_long_window_merges_archived_rollups() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_stats_handler_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ctx = mock_context(&temp_dir).await;

        let now = chrono::Utc::now().timestamp_millis();
        let old_ts = now - 100 * 86_400_000;
        let mut entries = Vec::new();
        for i in 0..3 {
            let mut entry = QueryLogEntry::new(
                old_ts + i,
                "10.0.0.1",
                Some("archive-host".into()),
                "archived.example",
                1,
                Some(0),
                "allowed",
                "udp",
            );
            entry.upstream = Some("tls://9.9.9.9".into());
            entry.elapsed_us = Some(1_000);
            entries.push(entry);
        }
        ctx.stats_db.insert_batch(&entries).await.unwrap();
        let report = ctx.stats_db.cleanup_retention(90).await.unwrap();
        assert_eq!(report.deleted_records, 3);

        let Json(stats) = get_stats(
            viewer(),
            State(ctx.clone()),
            Query(StatsQuery {
                window: Some("8760h".into()),
            }),
        )
        .await
        .unwrap();
        assert_eq!(stats.total_queries, 3);
        assert_eq!(
            stats.top_domains.first(),
            Some(&("archived.example".to_string(), 3))
        );

        let (headers, Json(clients)) = get_client_stats(
            viewer(),
            State(ctx.clone()),
            Query(StatsQuery {
                window: Some("8760h".into()),
            }),
        )
        .await
        .unwrap();
        assert_eq!(headers.get("x-total-count").unwrap(), "1");
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].client_name.as_deref(), Some("archive-host"));

        let (headers, Json(upstreams)) = get_upstream_stats(
            viewer(),
            State(ctx),
            Query(StatsQuery {
                window: Some("8760h".into()),
            }),
        )
        .await
        .unwrap();
        assert_eq!(headers.get("x-total-count").unwrap(), "1");
        assert_eq!(upstreams.len(), 1);
        assert_eq!(upstreams[0].total_queries, 3);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
