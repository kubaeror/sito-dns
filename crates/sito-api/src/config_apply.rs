//! Single configuration apply/validate pipeline (WP-4.2).
//!
//! Every write path — the file watcher, `PUT /config`, `POST /config/reload`,
//! backup restore and the setup wizard — goes through [`apply_full_config`]:
//!
//! 1. deep validation of the whole candidate (typed sections plus every
//!    upstream target, including `per_domain[].servers`);
//! 2. apply to the live components (upstream manager, filter engine, clients,
//!    rewrites, cache, query log, runtime snapshot and — through
//!    [`ConfigApplyHooks`] — DNSSEC, per-client scoped upstreams, rate
//!    limiters, listener rebind and log level);
//! 3. roll the in-memory components back to the previous configuration when
//!    any step fails.
//!
//! [`apply_and_persist_config`] adds the persist step *after* a successful
//! apply and rolls back the in-memory apply when the write fails, so the file
//! and the runtime never diverge silently.

use crate::config_validation::validate_typed_sections;
use crate::config_writer::save_config_document_atomic;
use crate::error::ProblemDetails;
use crate::state::ServerContext;
use sito_core::config::Config;
use sito_upstream::BootstrapResolver;
use std::sync::Arc;
use std::time::Duration;

/// Future returned by [`ConfigApplyHooks::apply`] (boxed so the trait stays
/// object-safe without an extra macro dependency in the server binary).
pub type ApplyFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ProblemDetails>> + Send + 'a>>;

/// Components owned by the server binary rather than [`ServerContext`]
/// (DNSSEC validator, per-client scoped upstreams, rate limiters, DNS listener
/// rebind, log level). Implemented in `crates/sito/src/server.rs` and shared
/// with the API through an axum `Extension`.
pub trait ConfigApplyHooks: Send + Sync {
    /// Applies the hook-owned components for `cfg`. Returning an error makes
    /// the whole apply fail and triggers a rollback.
    fn apply<'a>(
        &'a self,
        cfg: &'a Config,
        clients: &'a sito_clients::ClientsConfig,
    ) -> ApplyFuture<'a>;
}

/// Router extension carrying the optional apply hooks. `None` in unit tests
/// and embedders that do not own the extra components.
#[derive(Clone, Default)]
pub struct ApplyHooks(pub Option<Arc<dyn ConfigApplyHooks>>);

impl ApplyHooks {
    #[must_use]
    pub fn new(hooks: Arc<dyn ConfigApplyHooks>) -> Self {
        Self(Some(hooks))
    }

    #[must_use]
    pub fn as_dyn(&self) -> Option<&dyn ConfigApplyHooks> {
        self.0.as_deref()
    }
}

/// Whether the filter engine is reloaded synchronously or the (network)
/// blocklist fetch is queued for a background refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterApply {
    /// Fetch/compile blocklists before returning (API writes, watcher).
    Sync,
    /// Apply everything else and let the caller queue the list fetch (wizard
    /// first boot: the request must not download blocklists synchronously).
    Deferred,
}

/// Result of a successful apply.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppliedReport {
    /// Settings that changed but are only read at process start.
    pub restart_required: Vec<String>,
}

/// Deep validation of a candidate configuration.
///
/// Beyond the typed sections this validates every upstream target
/// syntactically, so `servers = ["oops-typo"]` is rejected before any
/// component or file is touched.
pub fn validate_full_config(cfg: &Config) -> Result<(), ProblemDetails> {
    validate_full_config_sync(cfg)
        .map_err(|e| ProblemDetails::bad_request(format!("Configuration error: {e}")))
}

/// Synchronous core of [`validate_full_config`] for callers that cannot await
/// (archive pre-validation, `check-config`).
pub fn validate_full_config_sync(cfg: &Config) -> Result<(), String> {
    validate_typed_sections(cfg).map_err(|e| e.to_string())?;
    for server in &cfg.upstream.servers {
        validate_upstream_target(server)
            .map_err(|e| format!("Invalid upstream server '{server}': {e}"))?;
    }
    for per_domain in &cfg.upstream.per_domain {
        if per_domain.servers.is_empty() {
            return Err("Each [upstream.per_domain] entry needs at least one server".to_string());
        }
        for server in &per_domain.servers {
            validate_upstream_target(server)
                .map_err(|e| format!("Invalid per-domain upstream server '{server}': {e}"))?;
        }
    }
    Ok(())
}

/// Validates a single upstream target: `host`, `ip[:port]`, `[v6][:port]` or a
/// `udp://`/`tls://`/`https://`/`quic://` URL.
pub fn validate_upstream_target(target: &str) -> Result<(), String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("target is empty".to_string());
    }

    let mut rest = target;
    if let Some((scheme, after)) = target.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "udp" | "tls" | "https" | "quic") {
            return Err(format!(
                "unsupported scheme '{scheme}://' (supported: udp://, tls://, https://, quic://)"
            ));
        }
        if after.is_empty() {
            return Err("missing host".to_string());
        }
        rest = after;
    }

    // Drop a URL path for DoH-style targets.
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err("missing host".to_string());
    }

    let (host, port) = if let Some(after_bracket) = authority.strip_prefix('[') {
        let Some((host, tail)) = after_bracket.split_once(']') else {
            return Err("unterminated IPv6 literal".to_string());
        };
        let port = match tail.strip_prefix(':') {
            Some(port) => Some(port),
            None if tail.is_empty() => None,
            None => return Err("unexpected characters after IPv6 literal".to_string()),
        };
        (host.to_string(), port)
    } else if authority.matches(':').count() >= 2 && authority.parse::<std::net::Ipv6Addr>().is_ok()
    {
        (authority.to_string(), None)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            // More than one colon but not a valid bare IPv6 literal.
            return Err("invalid IPv6 literal (bracket it as [addr])".to_string());
        }
        (host.to_string(), Some(port))
    } else {
        (authority.to_string(), None)
    };

    if host.is_empty() {
        return Err("missing host".to_string());
    }
    if let Some(port) = port {
        let port: u16 = port.parse().map_err(|_| format!("invalid port '{port}'"))?;
        if port == 0 {
            return Err("port must not be 0".to_string());
        }
    }

    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    validate_hostname(&host)
}

/// Hostnames must be FQDN-like (at least one dot). A single-label name such as
/// `oops-typo` is rejected as a typo instead of being resolved through the
/// bootstrap resolver.
fn validate_hostname(host: &str) -> Result<(), String> {
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return Err("missing host".to_string());
    }
    if !host.contains('.') {
        return Err(format!(
            "'{host}' is not an IP address or fully-qualified hostname"
        ));
    }
    if host.len() > 253 {
        return Err("hostname is longer than 253 characters".to_string());
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err("hostname contains an empty label".to_string());
        }
        if label.len() > 63 {
            return Err("hostname label is longer than 63 characters".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("hostname label '{label}' starts or ends with '-'"));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!(
                "hostname label '{label}' contains invalid characters"
            ));
        }
    }
    Ok(())
}

/// Applies `candidate` to the live server, rolling back on failure.
///
/// Every apply path acquires [`ServerContext::apply_lock`], so an older
/// document that was already read from disk cannot overwrite the runtime after
/// a newer push acquired the lock first.
pub async fn apply_full_config(
    ctx: &ServerContext,
    candidate: &Config,
    filter_apply: FilterApply,
    hooks: Option<&dyn ConfigApplyHooks>,
) -> Result<AppliedReport, ProblemDetails> {
    let _apply_guard = ctx.apply_lock.lock().await;
    apply_full_config_locked(ctx, candidate, filter_apply, hooks).await
}

/// Apply implementation that must be called with [`ServerContext::apply_lock`]
/// already held.
async fn apply_full_config_locked(
    ctx: &ServerContext,
    candidate: &Config,
    filter_apply: FilterApply,
    hooks: Option<&dyn ConfigApplyHooks>,
) -> Result<AppliedReport, ProblemDetails> {
    validate_full_config(candidate)?;

    let previous = (**ctx.config.load()).clone();

    match apply_inner(ctx, candidate, filter_apply, hooks).await {
        Ok(()) => Ok(AppliedReport {
            restart_required: restart_required_fields(&previous, candidate),
        }),
        Err(e) => {
            // Roll the components applied so far back to the previous
            // configuration. Best effort: a failed rollback is logged loudly.
            if let Err(rollback_err) = apply_inner(ctx, &previous, FilterApply::Sync, hooks).await {
                tracing::error!(
                    error = %rollback_err.detail,
                    "Failed to roll back configuration apply; runtime may be partially updated"
                );
            }
            Err(e)
        }
    }
}

/// Applies `candidate` and persists it only after the apply succeeded. A
/// persist failure rolls the in-memory apply back so file and runtime stay in
/// sync.
pub async fn apply_and_persist_config(
    ctx: &ServerContext,
    candidate: &Config,
    filter_apply: FilterApply,
    hooks: Option<&dyn ConfigApplyHooks>,
) -> Result<AppliedReport, ProblemDetails> {
    let _apply_guard = ctx.lock_config_apply().await;
    apply_and_persist_config_locked(ctx, candidate, filter_apply, hooks).await
}

/// Applies `candidate` and persists it, assuming the caller already holds
/// [`ServerContext::apply_lock`].
///
/// The caller **must** hold `ServerContext::apply_lock` (acquired through
/// [`ServerContext::lock_config_apply`]) from before it reads the current
/// configuration until this future completes. Calling this without the guard
/// re-introduces the lost-update race; do not call
/// [`apply_and_persist_config`] while already holding the lock (it would
/// deadlock).
pub async fn apply_and_persist_config_locked(
    ctx: &ServerContext,
    candidate: &Config,
    filter_apply: FilterApply,
    hooks: Option<&dyn ConfigApplyHooks>,
) -> Result<AppliedReport, ProblemDetails> {
    let document = toml::to_string_pretty(candidate)
        .map_err(|e| ProblemDetails::internal_error(format!("Serialization failed: {e}")))?;
    apply_and_persist_document_locked(ctx, candidate, &document, filter_apply, hooks).await
}

/// Applies `candidate` and atomically persists `document` only after the apply
/// succeeded.
///
/// The HA slave uses this variant to keep the exact document built from the
/// pushed configuration plus node-local fields. A persist failure rolls the
/// in-memory apply back so the file and the running server stay in sync.
pub async fn apply_and_persist_document(
    ctx: &ServerContext,
    candidate: &Config,
    document: &str,
    filter_apply: FilterApply,
    hooks: Option<&dyn ConfigApplyHooks>,
) -> Result<AppliedReport, ProblemDetails> {
    let _apply_guard = ctx.apply_lock.lock().await;
    apply_and_persist_document_locked(ctx, candidate, document, filter_apply, hooks).await
}

/// HA push variant of [`apply_and_persist_document`].
///
/// A restart-only change cannot take effect in the running process, so the
/// candidate is rejected **before** anything is applied or persisted. The HA
/// slave worker then ACKs `applied: false` and both the live configuration and
/// the persisted file keep their previous state. The check runs under
/// [`ServerContext::apply_lock`] together with the apply, so a concurrent
/// watcher write cannot invalidate it between check and persist.
pub async fn apply_and_persist_document_rejecting_restart(
    ctx: &ServerContext,
    candidate: &Config,
    document: &str,
    filter_apply: FilterApply,
    hooks: Option<&dyn ConfigApplyHooks>,
) -> Result<AppliedReport, ProblemDetails> {
    let _apply_guard = ctx.apply_lock.lock().await;
    let previous = (**ctx.config.load()).clone();
    let restart_required = restart_required_fields(&previous, candidate);
    if !restart_required.is_empty() {
        return Err(ProblemDetails::bad_request(format!(
            "restart_required: this push changes restart-only fields ({}); restart the slave with the new configuration or update them locally",
            restart_required.join(", ")
        )));
    }
    apply_and_persist_document_locked(ctx, candidate, document, filter_apply, hooks).await
}

/// Persist variant that must be called with [`ServerContext::apply_lock`] held.
async fn apply_and_persist_document_locked(
    ctx: &ServerContext,
    candidate: &Config,
    document: &str,
    filter_apply: FilterApply,
    hooks: Option<&dyn ConfigApplyHooks>,
) -> Result<AppliedReport, ProblemDetails> {
    let previous = (**ctx.config.load()).clone();
    let report = apply_full_config_locked(ctx, candidate, filter_apply, hooks).await?;

    if let Err(e) = save_config_document_atomic(&ctx.config_path, document, candidate).await {
        if let Err(rollback_err) =
            apply_full_config_locked(ctx, &previous, FilterApply::Sync, hooks).await
        {
            tracing::error!(
                error = %rollback_err.detail,
                "Failed to roll back in-memory configuration after persist failure"
            );
        }
        return Err(e);
    }
    ctx.publish_bundle().await;
    Ok(report)
}

/// Result of handling a configuration file change.
#[derive(Debug)]
pub enum ConfigFileApplyOutcome {
    /// The file already matches the live runtime configuration (typically the
    /// HA applier's own write or an identical save); nothing was re-applied.
    SelfWriteIgnored,
    /// The new configuration was applied and published to slaves.
    Applied(AppliedReport),
    /// The document was rejected; the running configuration is untouched.
    Rejected(ProblemDetails),
}

/// Applies a configuration document read from disk (file-watcher path).
///
/// Every event is serialized with the other apply/persist paths and then
/// re-reads the file. The document is suppressed only when it parses to the
/// *current* runtime configuration (typically the HA applier's own write, a
/// duplicate event, or an identical external save). An identical external save
/// therefore does not force a full re-apply; use `POST /api/v1/config/reload`
/// when an explicit reload is required. A file that differs from the runtime —
/// including an external revert to an older document — is always applied.
///
/// If the on-disk document is rejected (parse or validation failure), the
/// running configuration is left untouched by design. In that case the file
/// and runtime can diverge until an operator fixes the file or restores a
/// valid document; the runtime is not rolled forward to a rejected file.
pub async fn apply_config_document_event(
    ctx: &ServerContext,
    document: &str,
    filter_apply: FilterApply,
    hooks: Option<&dyn ConfigApplyHooks>,
) -> ConfigFileApplyOutcome {
    // Serialize with every other apply/persist path, then re-read the file.
    // An event for push A can be delivered after push B has already written
    // and applied; applying the stale A document would regress the runtime to
    // an older configuration even though B was ACKed.
    let _apply_guard = ctx.apply_lock.lock().await;

    let mut current = document.to_string();
    match tokio::fs::read_to_string(&ctx.config_path).await {
        Ok(on_disk) if on_disk != current => {
            tracing::debug!(
                path = %ctx.config_path.display(),
                "Configuration watcher event was stale; applying the current file content"
            );
            current = on_disk;
        }
        _ => {}
    }

    let new_cfg = match Config::from_toml_str(&current) {
        Ok(cfg) => cfg,
        Err(e) => {
            return ConfigFileApplyOutcome::Rejected(ProblemDetails::bad_request(format!(
                "Invalid hot-reloaded configuration: {e}"
            )));
        }
    };

    // Compare against the live runtime, not a time-limited record of writes: an
    // external revert to an older (but recently self-written) document must be
    // applied.
    if new_cfg == **ctx.config.load() {
        return ConfigFileApplyOutcome::SelfWriteIgnored;
    }

    match apply_full_config_locked(ctx, &new_cfg, filter_apply, hooks).await {
        Ok(report) => {
            ctx.publish_bundle().await;
            ConfigFileApplyOutcome::Applied(report)
        }
        Err(e) => ConfigFileApplyOutcome::Rejected(e),
    }
}

async fn apply_inner(
    ctx: &ServerContext,
    cfg: &Config,
    filter_apply: FilterApply,
    hooks: Option<&dyn ConfigApplyHooks>,
) -> Result<(), ProblemDetails> {
    // 1. Upstream manager: constructing it validates every configured server
    //    (including per-domain scopes) before anything is swapped.
    let bootstrap = BootstrapResolver::new(
        cfg.upstream.bootstrap.clone(),
        Duration::from_millis(cfg.upstream.timeout_ms),
    );
    ctx.upstream
        .reload(&cfg.upstream, &bootstrap)
        .await
        .map_err(|e| ProblemDetails::bad_request(format!("Invalid upstream configuration: {e}")))?;

    // 2. Filter engine (unless the caller queues the list fetch).
    if filter_apply == FilterApply::Sync {
        ctx.filter
            .reload_with_config(&cfg.filtering)
            .await
            .map_err(|e| {
                ProblemDetails::internal_error(format!("Failed to apply filter configuration: {e}"))
            })?;
        ctx.metrics.set_filter_rules(ctx.filter.rule_count());
        // Filter rules changed: drop cached answers that may now be blocked.
        ctx.cache.flush();
    }

    let clients = clients_from_config(cfg)?;
    let rewrites = rewrites_from_config(cfg)?;

    // 3. Hook-owned components (DNSSEC, scoped upstreams, rate limiters,
    //    listener rebind, log level).
    if let Some(hooks) = hooks {
        hooks.apply(cfg, &clients).await?;
    }

    // A DNSSEC mode/validate/anchor/NTA change invalidates every cached
    // validation decision. Without this, an entry validated under the old
    // policy would keep being served (Secure with AD=1 after an anchor was
    // removed, or Unchecked after validation was enabled).
    if ctx.config.load().dns.dnssec != cfg.dns.dnssec {
        ctx.cache.flush();
    }

    // 4. Cache policy, query-log privacy and the coherent runtime snapshot.
    ctx.cache.update_config(cfg.dns.cache.clone()).await;
    ctx.querylog_sender
        .set_anonymize(cfg.privacy.anonymize_querylog);
    let current_clients = ctx.clients.load();
    let clients_registry = sito_clients::ClientRegistry::with_stores(
        clients,
        current_clients.routeros_leases_store(),
        current_clients.unidentified_store(),
    );
    drop(current_clients);
    ctx.runtime.replace(sito_runtime::RuntimeSnapshot {
        config: Arc::new(cfg.clone()),
        clients: Arc::new(clients_registry),
        rewrites: Arc::new(sito_rewrites::RewriteTable::new(rewrites)),
    });
    Ok(())
}

fn clients_from_config(cfg: &Config) -> Result<sito_clients::ClientsConfig, ProblemDetails> {
    match cfg.clients.as_ref() {
        Some(value) => value.clone().try_into().map_err(|e| {
            ProblemDetails::bad_request(format!("invalid [clients] configuration: {e}"))
        }),
        None => Ok(sito_clients::ClientsConfig::default()),
    }
}

fn rewrites_from_config(cfg: &Config) -> Result<sito_rewrites::RewritesConfig, ProblemDetails> {
    match cfg.rewrites.as_ref() {
        Some(value) => value.clone().try_into().map_err(|e| {
            ProblemDetails::bad_request(format!("invalid [rewrites] configuration: {e}"))
        }),
        None => Ok(sito_rewrites::RewritesConfig::default()),
    }
}

/// Queues a background blocklist refresh for the given filtering config and
/// returns its join handle. Used by the wizard so the HTTP request does not
/// download lists synchronously; the caller can await the handle to know when
/// the filter engine is ready.
pub fn queue_filter_refresh(
    ctx: &ServerContext,
    filtering: sito_core::config::FilteringConfig,
) -> tokio::task::JoinHandle<()> {
    let engine = ctx.filter.clone();
    let metrics = ctx.metrics.clone();
    let cache = ctx.cache.clone();
    tokio::spawn(async move {
        match engine.reload_with_config(&filtering).await {
            Ok(_) => {
                metrics.set_filter_rules(engine.rule_count());
                cache.flush();
                tracing::info!("Background blocklist refresh completed");
            }
            Err(e) => {
                tracing::error!(
                    "Background blocklist refresh failed; the filter engine keeps its previous \
                     snapshot: {e}"
                );
            }
        }
    })
}

/// Settings that are only read at process start; changing them needs a
/// restart. This is the single matrix shared by the REST API, the UI and the
/// watcher's warning log.
///
/// Everything else — `[dns]` (including the DNSSEC validator and rate
/// limiters), `[upstream]`, `[filtering]`, `[clients]`, `[rewrites]`,
/// `[privacy]`, `[stats]` and `server.log_level` — is hot-applied by
/// [`apply_full_config`], directly or through the hooks.
#[must_use]
pub fn restart_required_fields(old: &Config, new: &Config) -> Vec<String> {
    let mut fields = Vec::new();
    let mark = |changed: bool, name: &str, fields: &mut Vec<String>| {
        if changed {
            fields.push(name.to_string());
        }
    };

    // `[server]`: role/instance/data-dir shape HA and the runtime, log_format
    // is installed at startup. `log_level` is hot-reloadable.
    mark(
        old.server.role != new.server.role,
        "server.role",
        &mut fields,
    );
    mark(
        old.server.instance_name != new.server.instance_name,
        "server.instance_name",
        &mut fields,
    );
    mark(
        old.server.data_dir != new.server.data_dir,
        "server.data_dir",
        &mut fields,
    );
    mark(
        old.server.log_format != new.server.log_format,
        "server.log_format",
        &mut fields,
    );
    // [auth] sessions/token policy is read once at startup.
    mark(old.auth != new.auth, "auth", &mut fields);
    // Only the admin listener's enabled/bind/port are bound at startup;
    // `web.trusted_proxies`, `web.metrics_auth`, `web.public_url` and
    // `web.tls_terminated_by_proxy` are read per request and hot-applied.
    let web_old = old.get_web_config();
    let web_new = new.get_web_config();
    mark(
        web_old.enabled != web_new.enabled
            || web_old.bind != web_new.bind
            || web_old.port != web_new.port,
        "web",
        &mut fields,
    );
    // TLS/ACME material feeds the listener acceptors built at startup.
    mark(old.tls != new.tls, "tls", &mut fields);
    mark(old.acme != new.acme, "acme", &mut fields);
    // HA workers and integrations are initialized at startup.
    mark(old.ha != new.ha, "ha", &mut fields);
    mark(
        old.integrations != new.integrations,
        "integrations",
        &mut fields,
    );
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upstream_target_validation_rejects_typos() {
        // Regression: `PUT /config` with a typo used to be persisted (and only
        // later rejected by the watcher, or never for per-domain servers).
        assert!(validate_upstream_target("oops-typo").is_err());
        assert!(validate_upstream_target("localhost").is_err());
        assert!(validate_upstream_target("").is_err());
        assert!(validate_upstream_target("sdns://AQcAAAAAAAA").is_err());
        assert!(validate_upstream_target("1.1.1.1:notaport").is_err());
        assert!(validate_upstream_target("1.1.1.1:0").is_err());
        assert!(validate_upstream_target("[::1").is_err());
    }

    #[test]
    fn test_upstream_target_validation_accepts_real_targets() {
        for target in [
            "1.1.1.1",
            "1.1.1.1:53",
            "9.9.9.9",
            "[::1]:853",
            "[2001:db8::1]",
            "2001:db8::1",
            "dns.quad9.net",
            "dns.quad9.net.",
            "udp://1.1.1.1",
            "tls://dns.quad9.net",
            "tls://dns.quad9.net:853",
            "https://cloudflare-dns.com/dns-query",
            "quic://dns.adguard-dns.com",
            "dns1.example",
        ] {
            assert!(
                validate_upstream_target(target).is_ok(),
                "target '{target}' must be accepted"
            );
        }
    }

    /// A DNSSEC policy change invalidates every cached validation decision:
    /// an old Insecure/Unchecked entry must not outlive the policy that
    /// produced it.
    #[tokio::test]
    async fn test_dnssec_policy_change_flushes_response_cache() {
        use sito_proto::{
            DNSClass, Message, MessageType, OpCode, Query, RData, Record, RecordType,
        };

        let temp_dir = crate::test_support::temp_dir("sito_cfg_dnssec_flush");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        for (index, change) in ["mode", "trust_anchors", "nta"].into_iter().enumerate() {
            let name = sito_proto::Name::from_ascii(format!("policy-{index}.example.")).unwrap();
            let mut query = Message::new(
                u16::try_from(index).unwrap() + 1,
                MessageType::Query,
                OpCode::Query,
            );
            query
                .queries
                .push(Query::query(name.clone(), RecordType::A));
            let mut response = Message::response(query.metadata.id, OpCode::Query);
            response.queries = query.queries.clone();
            response.answers.push(Record::from_rdata(
                name.clone(),
                300,
                RData::A(sito_proto::rdata::A("192.0.2.200".parse().unwrap())),
            ));
            ctx.cache.insert(&query, &response).await;
            assert!(
                ctx.cache
                    .get(&name, RecordType::A, DNSClass::IN)
                    .await
                    .is_some(),
                "cache seed for {change} must succeed"
            );

            let mut candidate = (**ctx.config.load()).clone();
            match change {
                "mode" => candidate.dns.dnssec.mode = "disabled".to_string(),
                "trust_anchors" => candidate
                    .dns
                    .dnssec
                    .trust_anchors
                    .push("example.:13:AQID".to_string()),
                "nta" => candidate.dns.dnssec.nta.push("nta.example".to_string()),
                other => panic!("unhandled policy change {other}"),
            }
            apply_full_config(&ctx, &candidate, FilterApply::Deferred, None)
                .await
                .unwrap();

            assert!(
                ctx.cache
                    .get(&name, RecordType::A, DNSClass::IN)
                    .await
                    .is_none(),
                "changing dnssec {change} must flush cached validation decisions"
            );
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// B regression: two rapid pushes end at the newer document (a stale event
    /// for A re-reads B), but an external revert to the older A document within
    /// the old 120 s window must be applied, leaving runtime and file at A.
    #[tokio::test]
    async fn test_rapid_pushes_end_at_newest_and_external_revert_is_applied() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_rapid_pushes");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let mut first = (**ctx.config.load()).clone();
        first.upstream.servers = vec!["1.1.1.1".to_string()];
        let first_document = toml::to_string_pretty(&first).unwrap();
        let mut second = first.clone();
        second.upstream.servers = vec!["9.9.9.9".to_string()];
        let second_document = toml::to_string_pretty(&second).unwrap();

        // Push A then push B before A's watcher event is handled. The file
        // already contains B when the stale A event arrives.
        tokio::fs::write(&ctx.config_path, &first_document)
            .await
            .unwrap();
        tokio::fs::write(&ctx.config_path, &second_document)
            .await
            .unwrap();

        match apply_config_document_event(&ctx, &first_document, FilterApply::Sync, None).await {
            ConfigFileApplyOutcome::Applied(_) => {}
            other => panic!("the current file (B) must be applied, got {other:?}"),
        }
        assert_eq!(
            ctx.runtime.snapshot().config.upstream.servers,
            vec!["9.9.9.9".to_string()],
            "the stale A event must apply the current file B, not A"
        );

        // A pending stale-A event delivered after B is live re-reads B and is a
        // no-op: the runtime stays at B.
        match apply_config_document_event(&ctx, &first_document, FilterApply::Sync, None).await {
            ConfigFileApplyOutcome::SelfWriteIgnored => {}
            other => panic!("a stale event must re-read the live B file, got {other:?}"),
        }
        assert_eq!(
            ctx.runtime.snapshot().config.upstream.servers,
            vec!["9.9.9.9".to_string()],
            "two rapid pushes must end at the newer document"
        );

        // An external revert to A (which was a self-write moments ago) must be
        // applied: the runtime must not stay ahead of the file.
        tokio::fs::write(&ctx.config_path, &first_document)
            .await
            .unwrap();
        match apply_config_document_event(&ctx, &first_document, FilterApply::Sync, None).await {
            ConfigFileApplyOutcome::Applied(_) => {}
            other => panic!("an external revert must be applied, got {other:?}"),
        }
        assert_eq!(
            ctx.runtime.snapshot().config.upstream.servers,
            vec!["1.1.1.1".to_string()],
            "the runtime and file must both end at the reverted document"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// The watcher suppresses only a document that already matches the live
    /// runtime; changed documents are applied normally.
    #[tokio::test]
    async fn test_config_document_event_suppresses_only_current_runtime() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_watcher");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let equal_document = toml::to_string_pretty(&**ctx.config.load()).unwrap();
        match apply_config_document_event(&ctx, &equal_document, FilterApply::Sync, None).await {
            ConfigFileApplyOutcome::SelfWriteIgnored => {}
            other => panic!("an equal document must be ignored, got {other:?}"),
        }

        let mut changed = (**ctx.config.load()).clone();
        changed.upstream.servers = vec!["9.9.9.9".to_string()];
        let changed_document = toml::to_string_pretty(&changed).unwrap();
        match apply_config_document_event(&ctx, &changed_document, FilterApply::Sync, None).await {
            ConfigFileApplyOutcome::Applied(_) => {}
            other => panic!("a changed document must be applied, got {other:?}"),
        }
        assert_eq!(
            ctx.runtime.snapshot().config.upstream.servers,
            vec!["9.9.9.9".to_string()]
        );

        match apply_config_document_event(&ctx, &changed_document, FilterApply::Sync, None).await {
            ConfigFileApplyOutcome::SelfWriteIgnored => {}
            other => panic!("the runtime-matching document must be suppressed, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// D-01: the HA path persists the exact document it built (preserving
    /// `[ha]`, identity and credentials) while applying the same config.
    #[tokio::test]
    async fn test_apply_and_persist_document_preserves_document() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_document");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let mut candidate = (**ctx.config.load()).clone();
        candidate.upstream.servers = vec!["9.9.9.9".to_string()];
        candidate.dns.cache.min_ttl = 60;
        // The document intentionally contains formatting/comments the typed
        // serializer would drop; it must be written byte-for-byte.
        let document = format!(
            "{}\n# node-local section preserved by the HA applier\n",
            toml::to_string_pretty(&candidate).unwrap()
        );

        apply_and_persist_document(&ctx, &candidate, &document, FilterApply::Sync, None)
            .await
            .unwrap();

        assert_eq!(
            tokio::fs::read_to_string(&ctx.config_path).await.unwrap(),
            document,
            "the persisted document must not be re-serialized"
        );
        assert_eq!(
            ctx.runtime.snapshot().config.upstream.servers,
            vec!["9.9.9.9".to_string()]
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// D-01: a persist failure rolls the applied components back, including
    /// the live filter snapshot.
    #[tokio::test]
    async fn test_apply_and_persist_document_rolls_back_on_persist_failure() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_document_rollback");
        let mut ctx = crate::test_support::mock_context(&temp_dir).await;
        ctx.config_path = std::path::PathBuf::from("/proc/forbidden_document_test/config.toml");

        let original_ttl = ctx.config.load().dns.cache.min_ttl;
        let mut candidate = (**ctx.config.load()).clone();
        candidate.dns.cache.min_ttl = original_ttl.saturating_add(42);
        candidate.filtering.custom_rules = vec!["||must-not-stick.test^".to_string()];
        let document = toml::to_string_pretty(&candidate).unwrap();

        let err = apply_and_persist_document(&ctx, &candidate, &document, FilterApply::Sync, None)
            .await
            .expect_err("persist must fail");
        assert_eq!(err.status, 500);
        assert_eq!(ctx.config.load().dns.cache.min_ttl, original_ttl);
        assert!(
            ctx.runtime
                .snapshot()
                .config
                .filtering
                .custom_rules
                .is_empty(),
            "the runtime snapshot must be rolled back"
        );
        assert_eq!(
            ctx.filter.rule_count(),
            0,
            "the live filter snapshot must be rolled back"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_restart_required_matrix_is_truthful() {
        let old = Config::default();
        let mut new = old.clone();

        // Hot-applied sections must not claim restart-required.
        new.dns.port = old.dns.port.saturating_add(1);
        new.dns.rate_limit_per_ip = old.dns.rate_limit_per_ip.saturating_add(1);
        new.server.log_level = "debug".to_string();
        new.upstream.servers = vec!["9.9.9.9".to_string()];
        assert!(
            restart_required_fields(&old, &new).is_empty(),
            "hot-applied fields reported as restart-only: {:?}",
            restart_required_fields(&old, &new)
        );

        // Restart-only sections are reported.
        let mut auth = toml::Table::new();
        auth.insert("session_ttl_hours".to_string(), toml::Value::Integer(1));
        new.auth = Some(toml::Value::Table(auth));
        let fields = restart_required_fields(&old, &new);
        assert!(fields.iter().any(|f| f == "auth"), "got {fields:?}");

        new.web = Some(toml::from_str::<toml::Value>("port = 9090").unwrap());
        let fields = restart_required_fields(&old, &new);
        assert!(fields.iter().any(|f| f == "web"), "got {fields:?}");

        // Hot-applied `[web]` settings must not be reported as restart-only.
        let mut new_web = old.clone();
        new_web.web = Some(
            toml::from_str::<toml::Value>(
                r#"
                trusted_proxies = ["10.0.0.1"]
                public_url = "https://dns.example.com"
                "#,
            )
            .unwrap(),
        );
        assert!(
            restart_required_fields(&old, &new_web).is_empty(),
            "trusted_proxies/public_url are hot-applied: {:?}",
            restart_required_fields(&old, &new_web)
        );

        // `dns.doh_dedicated_hostname` is rebound in-process by the watcher and
        // must not be reported (WP-6.5 false positive).
        let mut new2 = old.clone();
        new2.dns.doh_dedicated_hostname = "dns.example.com".to_string();
        assert!(
            restart_required_fields(&old, &new2).is_empty(),
            "changing only the DoH hostname must not require a restart: {:?}",
            restart_required_fields(&old, &new2)
        );
    }

    mod write_serialization {
        use super::*;
        use crate::auth::AuthUser;
        use crate::auth::RequireOperator;
        use crate::auth::token::Role;
        use crate::models::{ClientDto, UpdateFilterListRequest, UpstreamConfigDto};
        use axum::Json;
        use axum::extract::{Extension, Path, State};
        use sito_core::config::FilterListConfig;

        fn operator() -> RequireOperator {
            RequireOperator(AuthUser {
                username: "operator".to_string(),
                role: Role::Operator,
                token_id: None,
            })
        }

        fn local_list(temp_dir: &std::path::Path) -> FilterListConfig {
            let list_path = temp_dir.join("local-list.txt");
            std::fs::write(&list_path, "||ads.example^\n||tracker.example^\n").unwrap();
            FilterListConfig {
                name: "Local".to_string(),
                url: format!("file://{}", list_path.display()),
                enabled: true,
                refresh_hours: None,
            }
        }

        /// Two admin writers started concurrently must both survive: the second
        /// one re-reads the config only after acquiring `apply_lock`, so it
        /// cannot overwrite the first one's change with a stale snapshot.
        #[tokio::test]
        async fn test_concurrent_filter_toggle_and_client_save_preserve_both() {
            let temp_dir = crate::test_support::temp_dir("sito_cfg_concurrent_writers");
            let ctx = crate::test_support::mock_context(&temp_dir).await;

            let mut seed = (**ctx.config.load()).clone();
            seed.filtering.lists = vec![local_list(&temp_dir)];
            apply_and_persist_config(&ctx, &seed, FilterApply::Sync, None)
                .await
                .unwrap();

            let toggle = crate::handlers::filtering::update_filter_list(
                operator(),
                State(ctx.clone()),
                Path("Local".to_string()),
                Json(UpdateFilterListRequest {
                    name: None,
                    url: None,
                    enabled: Some(false),
                    refresh_hours: None,
                }),
            );
            let add = crate::handlers::clients::create_client(
                operator(),
                State(ctx.clone()),
                Extension(ApplyHooks::default()),
                Json(ClientDto {
                    name: "phone".to_string(),
                    ip: vec!["10.50.0.5".to_string()],
                    mac: Vec::new(),
                    subnet: Vec::new(),
                    group: "default".to_string(),
                    doh_path: None,
                    dot_sni: None,
                    ignore_query_log: false,
                    ignore_stats: false,
                    use_global_upstreams: None,
                    upstreams: None,
                    trusted: None,
                    has_secret: false,
                    secret_hint: None,
                }),
            );

            let (toggle_result, add_result) = tokio::join!(toggle, add);
            let _ = toggle_result.expect("filter toggle must succeed");
            let _ = add_result.expect("client save must succeed");

            let live = ctx.config.load();
            assert_eq!(
                live.filtering.lists.len(),
                1,
                "the filter list must not be lost by the concurrent client save"
            );
            assert!(
                !live.filtering.lists[0].enabled,
                "the filter toggle must not be overwritten by the client save"
            );
            let live_clients: sito_clients::ClientsConfig =
                live.clients.clone().unwrap().try_into().unwrap();
            assert!(
                live_clients.entries.iter().any(|c| c.name == "phone"),
                "the client save must not be overwritten by the filter toggle"
            );

            // The same both-changes invariant must hold in the runtime snapshot
            // and in the persisted file (which is what a restart reads).
            let snapshot = ctx.runtime.snapshot();
            assert!(!snapshot.config.filtering.lists[0].enabled);
            let runtime_clients: sito_clients::ClientsConfig =
                snapshot.config.clients.clone().unwrap().try_into().unwrap();
            assert!(runtime_clients.entries.iter().any(|c| c.name == "phone"));

            let persisted =
                Config::from_toml_str(&tokio::fs::read_to_string(&ctx.config_path).await.unwrap())
                    .expect("persisted config must parse");
            assert_eq!(persisted.filtering.lists.len(), 1);
            assert!(!persisted.filtering.lists[0].enabled);
            let persisted_clients: sito_clients::ClientsConfig =
                persisted.clients.clone().unwrap().try_into().unwrap();
            assert!(persisted_clients.entries.iter().any(|c| c.name == "phone"));

            let _ = std::fs::remove_dir_all(&temp_dir);
        }

        /// A persist failure must not leave a partially applied writer live.
        #[tokio::test]
        async fn test_config_write_persist_failure_rolls_back_live_state() {
            let temp_dir = crate::test_support::temp_dir("sito_cfg_write_rollback");
            let mut ctx = crate::test_support::mock_context(&temp_dir).await;

            let mut seed = (**ctx.config.load()).clone();
            seed.filtering.lists = vec![local_list(&temp_dir)];
            seed.filtering.custom_rules = vec!["||keep.test^".to_string()];
            seed.upstream.servers = vec!["1.1.1.1".to_string()];
            let mut clients: sito_clients::ClientsConfig = seed
                .clients
                .clone()
                .map_or_else(Default::default, |value| value.try_into().unwrap());
            clients.entries.push(sito_clients::ClientEntryConfig {
                name: "keep".to_string(),
                ids: vec!["10.60.0.5".to_string()],
                group: "default".to_string(),
                ignore_query_log: false,
                ignore_stats: false,
                use_global_upstreams: true,
                upstreams: None,
                trusted: false,
            });
            seed.clients = Some(toml::Value::try_from(&clients).unwrap());
            apply_and_persist_config(&ctx, &seed, FilterApply::Sync, None)
                .await
                .unwrap();

            let previous_runtime = ctx.runtime.snapshot();
            let previous_upstreams = ctx.upstream.statuses().await;
            let previous_rules = ctx.filter.snapshot().rules.len();

            // Every write now fails at the persist step, after the live apply.
            ctx.config_path = std::path::PathBuf::from("/proc/forbidden_writer_test/config.toml");

            let filter_err = crate::handlers::filtering::set_filtering_rules(
                operator(),
                State(ctx.clone()),
                Json(crate::models::CustomRulesDto {
                    rules: vec!["||must-not-stick.test^".to_string()],
                }),
            )
            .await
            .expect_err("filter persist must fail");
            assert_eq!(filter_err.status, 500);
            assert_eq!(
                ctx.config.load().filtering.custom_rules,
                vec!["||keep.test^".to_string()],
                "the previous filter rules must stay live"
            );
            assert_eq!(
                ctx.filter.snapshot().rules.len(),
                previous_rules,
                "the previous filter snapshot must stay live"
            );

            let client_err = crate::handlers::clients::create_client(
                operator(),
                State(ctx.clone()),
                Extension(ApplyHooks::default()),
                Json(ClientDto {
                    name: "must-not-stick".to_string(),
                    ip: vec!["10.60.0.9".to_string()],
                    mac: Vec::new(),
                    subnet: Vec::new(),
                    group: "default".to_string(),
                    doh_path: None,
                    dot_sni: None,
                    ignore_query_log: false,
                    ignore_stats: false,
                    use_global_upstreams: None,
                    upstreams: None,
                    trusted: None,
                    has_secret: false,
                    secret_hint: None,
                }),
            )
            .await
            .expect_err("client persist must fail");
            assert_eq!(client_err.status, 500);
            let live_clients: sito_clients::ClientsConfig = ctx
                .config
                .load()
                .clients
                .clone()
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                live_clients
                    .entries
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>(),
                vec!["keep"],
                "the previous client must stay live"
            );
            let registry = ctx.clients.load();
            let mut probe = sito_core::client::ClientContext::new("10.60.0.9".parse().unwrap());
            let _ = registry.resolve(&mut probe, registry.timezone().at_utc(chrono::Utc::now()));
            assert!(
                probe.client_name.is_none(),
                "the rejected client must not reach the registry"
            );

            let upstream_err = crate::handlers::upstream::update_upstream_config(
                operator(),
                State(ctx.clone()),
                Extension(ApplyHooks::default()),
                Json(UpstreamConfigDto {
                    servers: vec!["9.9.9.9".to_string()],
                    bootstrap: vec!["1.0.0.1".to_string()],
                    strategy: "failover".to_string(),
                    timeout_ms: 2000,
                    probe_domain: "example.com".to_string(),
                    pool_size: 2,
                }),
            )
            .await
            .expect_err("upstream persist must fail");
            assert_eq!(upstream_err.status, 500);
            assert_eq!(
                ctx.config.load().upstream.servers,
                vec!["1.1.1.1".to_string()],
                "the previous upstream config must stay live"
            );
            assert_eq!(
                ctx.upstream.statuses().await,
                previous_upstreams,
                "the previous upstream manager must stay live"
            );
            assert_eq!(
                ctx.runtime.snapshot().config.filtering.custom_rules,
                previous_runtime.config.filtering.custom_rules,
                "the runtime snapshot must be rolled back after each failure"
            );

            let _ = std::fs::remove_dir_all(&temp_dir);
        }

        /// Guard against re-introducing a direct `save_config_atomic` call in
        /// an admin handler: every write must acquire `apply_lock` and persist
        /// through the apply pipeline.
        ///
        /// Startup/restore-only code that cannot use the runtime pipeline may
        /// be whitelisted by adding its `src/...` path here with a comment.
        #[test]
        fn test_no_direct_config_writes_in_handlers_or_ui() {
            let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
            let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(src.join("handlers"))
                .expect("handlers directory")
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
                .collect();
            files.push(src.join("ui").join("handlers.rs"));

            // Startup/restore-only exceptions (none today).
            let allowlist: &[&str] = &[];
            let mut offenders = Vec::new();
            for file in files {
                let Ok(content) = std::fs::read_to_string(&file) else {
                    continue;
                };
                let relative = file
                    .strip_prefix(&src)
                    .unwrap_or(&file)
                    .display()
                    .to_string();
                for (index, line) in content.lines().enumerate() {
                    if line.contains("save_config_atomic(")
                        && !allowlist.contains(&relative.as_str())
                    {
                        offenders.push(format!("{relative}:{}", index + 1));
                    }
                }
            }

            assert!(
                offenders.is_empty(),
                "direct config writes bypass the apply lock: {offenders:?}"
            );
        }
    }
}
