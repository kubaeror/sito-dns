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
use sito_filter::PreparedFilterSnapshot;
use sito_runtime::{ApplyError, ApplyPlan, DnssecPolicy, RuntimeGeneration, TransportPolicy};
use sito_upstream::{BootstrapResolver, PreparedUpstream};
use std::any::Any;
use std::sync::Arc;

/// Future returned by the apply hooks (boxed so the trait stays object-safe
/// without an extra macro dependency in the server binary).
pub type ApplyFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ApplyError>> + Send + 'a>>;

/// Future returned by [`ConfigApplyHooks::prepare`].
pub type PrepareFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<PreparedHooks, ApplyError>> + Send + 'a>,
>;

/// Hook-owned components prepared for a staged apply but not yet live.
///
/// `commit` is opaque to `sito-api` so the server binary can carry DNSSEC,
/// per-client upstream, rate-limiter and listener state without the API crate
/// depending on every transport type. It is typed as `Any` only for
/// downcasting in the single implementation; it is never inspected here.
pub struct PreparedHooks {
    /// DNSSEC policy and validator the plan publishes.
    pub dnssec_policy: DnssecPolicy,
    /// Opaque, fully prepared commit payload.
    pub commit: Box<dyn Any + Send + Sync>,
}

impl std::fmt::Debug for PreparedHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedHooks")
            .field("dnssec_policy", &self.dnssec_policy)
            .finish_non_exhaustive()
    }
}

/// Components owned by the server binary rather than [`ServerContext`]
/// (DNSSEC validator, per-client scoped upstreams, rate limiters, DNS listener
/// rebind, log level). Implemented in `crates/sito/src/server.rs` and shared
/// with the API through an axum `Extension`.
///
/// `prepare` must not change any live component; `commit` installs the
/// prepared state and is the only fallible step that may still reject the
/// apply (for example a listener cannot rebind). Neither method publishes the
/// runtime snapshot: [`sito_runtime::RuntimeState::apply`] is the only writer.
pub trait ConfigApplyHooks: Send + Sync {
    /// Prepares the hook-owned components for `cfg`/`clients` without
    /// publishing them.
    fn prepare<'a>(
        &'a self,
        cfg: &'a Config,
        clients: &'a sito_clients::ClientsConfig,
    ) -> PrepareFuture<'a>;

    /// Installs the prepared components. Called only after every other stage
    /// succeeded and before the runtime snapshot is published.
    fn commit(&self, prepared: PreparedHooks) -> ApplyFuture<'_>;
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
    /// HA publication result on a master, or `None` for non-HA nodes.
    pub ha_publish: Option<HaPublishReport>,
}

/// Client-visible summary of an HA publication attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaPublishReport {
    /// `published`, `no_slaves` or `failed`.
    pub status: String,
    /// Failure detail, never containing secret material.
    pub error: Option<String>,
    /// RFC3339 timestamp of the first scheduled retry.
    pub retry_at: Option<String>,
}

impl HaPublishReport {
    #[must_use]
    pub fn from_outcome(outcome: sito_ha::PublishOutcome) -> Self {
        match outcome {
            sito_ha::PublishOutcome::Published { .. } => Self {
                status: "published".to_string(),
                error: None,
                retry_at: None,
            },
            sito_ha::PublishOutcome::NoSlaves => Self {
                status: "no_slaves".to_string(),
                error: None,
                retry_at: None,
            },
            // Callers normally treat this as an apply error before building a
            // report; keep a faithful representation for completeness.
            sito_ha::PublishOutcome::TooLarge { bytes, limit } => Self {
                status: "failed".to_string(),
                error: Some(format!(
                    "configuration bundle is {bytes} bytes, above the {limit}-byte replication limit"
                )),
                retry_at: None,
            },
        }
    }

    /// Builds a failed report with the historical one-second retry estimate.
    ///
    /// Compatibility wrapper for external callers; use
    /// [`Self::failed_with_retry`] when the caller knows the delay of the retry
    /// loop that was actually scheduled.
    #[must_use]
    pub fn failed(error: impl Into<String>) -> Self {
        Self::failed_with_retry(error, Some(std::time::Duration::from_secs(1)))
    }

    /// Builds a failed report from the actual retry schedule.
    ///
    /// `retry_delay` is the delay before the first attempt of the retry loop
    /// that was actually started, or `None` when no new loop was scheduled
    /// (HA inactive, or an existing loop already owns the backoff schedule).
    /// Guessing a fixed one-second delay misleads operators when the next
    /// attempt is much later.
    #[must_use]
    pub fn failed_with_retry(
        error: impl Into<String>,
        retry_delay: Option<std::time::Duration>,
    ) -> Self {
        let retry_at = retry_delay.and_then(|delay| {
            let delta = chrono::TimeDelta::from_std(delay).ok()?;
            chrono::Utc::now()
                .checked_add_signed(delta)
                .map(|at| at.to_rfc3339())
        });
        Self {
            status: "failed".to_string(),
            error: Some(error.into()),
            retry_at,
        }
    }
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
///
/// This is the single full validator pipeline: core v2 rules (including
/// unknown-key rejection and upstream targets) followed by the dependent-crate
/// typed sections.
pub fn validate_full_config_sync(cfg: &Config) -> Result<(), String> {
    cfg.validate_full().map_err(|e| e.to_string())?;
    validate_typed_sections(cfg).map_err(|e| e.to_string())
}

/// Validates a single upstream target: `host`, `ip[:port]`, `[v6][:port]` or a
/// `udp://`/`tls://`/`https://`/`quic://` URL.
///
/// Compatibility wrapper around the `sito-core` validator so existing API
/// callers keep their path while every entry point shares one implementation.
pub fn validate_upstream_target(target: &str) -> Result<(), String> {
    sito_core::config::validate_upstream_target(target)
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

/// Fully staged apply: every component was validated/prepared and no live
/// state has changed yet.
struct StagedApply {
    plan: ApplyPlan,
    prepared_filter: PreparedFilterSnapshot,
    prepared_upstream: PreparedUpstream,
    prepared_hooks: Option<PreparedHooks>,
    /// Generation observed before staging; `apply_expecting` rejects the plan
    /// if a concurrent writer published in between.
    expected: RuntimeGeneration,
}

/// Apply implementation that must be called with [`ServerContext::apply_lock`]
/// already held.
///
/// WP-1.4: nothing is published until every stage succeeded. The only
/// fallible commit step is the hook-owned listener rebind, which runs before
/// the runtime snapshot store; a failure there leaves the previous generation
/// (`ctx.runtime.snapshot()`) untouched.
async fn apply_full_config_locked(
    ctx: &ServerContext,
    candidate: &Config,
    filter_apply: FilterApply,
    hooks: Option<&dyn ConfigApplyHooks>,
) -> Result<AppliedReport, ProblemDetails> {
    validate_full_config(candidate)?;

    let previous = (**ctx.config.load()).clone();
    // Box both large stages so an admin handler's future stays small. The
    // staged plan owns the compiled filter and upstream generation; keeping it
    // in the caller's async state would balloon every handler future.
    let staged = Box::pin(stage_config(ctx, candidate, filter_apply, hooks)).await?;
    Box::pin(commit_staged(ctx, staged, hooks, previous, candidate)).await
}

/// Commits a fully staged plan: hook-owned components, upstream generation,
/// then the single runtime snapshot publish.
async fn commit_staged(
    ctx: &ServerContext,
    staged: StagedApply,
    hooks: Option<&dyn ConfigApplyHooks>,
    previous: Config,
    candidate: &Config,
) -> Result<AppliedReport, ProblemDetails> {
    let StagedApply {
        plan,
        prepared_filter,
        prepared_upstream,
        prepared_hooks,
        expected,
    } = staged;
    let anonymize = plan.config.privacy.anonymize_querylog;

    // The generation check and every commit run inside
    // `RuntimeState::apply_expecting_with`'s critical section. A filter refresh
    // cannot advance the config generation, and another config apply cannot
    // interleave, so a conflict can no longer be reported after the listener
    // rebind or upstream publish.
    let before_publish = async {
        if let (Some(hooks), Some(prepared)) = (hooks, prepared_hooks) {
            // Listener rebind is the only fallible higher-layer step. It runs
            // first; DNSSEC/scoped-upstream installs after it are infallible.
            hooks.commit(prepared).await?;
        }
        // Upstream publication is infallible (all construction/validation was
        // staged).
        ctx.upstream.publish(prepared_upstream);
        Ok(())
    };
    let _generation = ctx
        .runtime
        .apply_expecting_with(plan, Some(expected), before_publish)
        .await
        .map_err(problem_from_apply)?;

    // Publish the filter to the engine for status/API/scheduled-refresh
    // bookkeeping. The query path already reads the snapshot published above,
    // so this cannot tear a query. The prepared guard is still held here, so a
    // refresh cannot publish an older filter in between.
    match ctx.filter.publish_prepared(prepared_filter) {
        Ok(rule_count) => ctx.metrics.set_filter_rules(rule_count),
        Err(e) => {
            tracing::error!(
                error = %e,
                "Applied runtime generation, but the filter engine rejected the staged snapshot"
            );
            ctx.metrics.set_filter_rules(ctx.filter.rule_count());
        }
    }
    ctx.querylog_sender.set_anonymize(anonymize);

    Ok(AppliedReport {
        restart_required: restart_required_fields(&previous, candidate),
        ha_publish: None,
    })
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
    // D11: an admin write that changes a restart-only field is a 409 and is
    // not persisted. Do this under the apply lock so the comparison cannot
    // race a concurrent apply.
    let previous = (**ctx.config.load()).clone();
    ensure_no_restart_required(&previous, candidate)?;
    apply_and_persist_config_locked(ctx, candidate, filter_apply, hooks).await
}

/// Rejects a candidate that changes a restart-only field (D11).
///
/// The error is a 409 Conflict carrying `restart_required`; callers must not
/// apply or persist the candidate. Startup-only settings never produce a
/// silent no-op write.
pub fn ensure_no_restart_required(
    previous: &Config,
    candidate: &Config,
) -> Result<(), ProblemDetails> {
    let restart_required = restart_required_fields(previous, candidate);
    if restart_required.is_empty() {
        return Ok(());
    }
    Err(ProblemDetails::conflict_with_restart(
        restart_required.clone(),
        format!(
            "restart_required: configuration changes restart-only fields ({}); nothing was applied or persisted. Edit config.toml and restart the service (or use the installer). GET /api/v1/config/restart-required lists the matrix",
            restart_required.join(", ")
        ),
    ))
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
    ensure_no_restart_required(&previous, candidate)?;
    apply_and_persist_document_locked(ctx, candidate, document, filter_apply, hooks).await
}

/// How the previous `config.toml` was read before an apply, for rollback.
#[derive(Debug)]
enum PreviousDocumentRead {
    Present(String),
    Missing,
    /// The file existed but could not be read. A rollback must not treat this
    /// like `Missing`: deleting the newly written document could destroy the
    /// only copy of a configuration that was previously present.
    Unreadable(std::io::Error),
}

async fn read_previous_document(path: &std::path::Path) -> PreviousDocumentRead {
    match tokio::fs::read_to_string(path).await {
        Ok(document) => PreviousDocumentRead::Present(document),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => PreviousDocumentRead::Missing,
        Err(e) => PreviousDocumentRead::Unreadable(e),
    }
}

/// Restores (or removes) the on-disk document after an oversized HA bundle.
///
/// `Missing` is the only case where removing the new document is safe. An
/// unreadable previous document is preserved and logged: the apply already
/// failed, and deleting the file would make the operator's previous
/// configuration unrecoverable.
async fn rollback_document_after_oversized_bundle(
    config_path: &std::path::Path,
    previous: &Config,
    previous_document: &PreviousDocumentRead,
) {
    match previous_document {
        PreviousDocumentRead::Present(document) => {
            if let Err(e) = save_config_document_atomic(config_path, document, previous).await {
                tracing::error!(
                    error = %e.detail,
                    "Failed to restore the previous configuration document after an oversized HA bundle"
                );
            }
        }
        PreviousDocumentRead::Missing => {
            if let Err(e) = tokio::fs::remove_file(config_path).await
                && e.kind() != std::io::ErrorKind::NotFound
            {
                tracing::error!(
                    error = %e,
                    "Failed to remove the rejected configuration document after an oversized HA bundle"
                );
            }
        }
        PreviousDocumentRead::Unreadable(error) => {
            tracing::error!(
                error = %error,
                "Could not read the previous configuration document during an oversized-HA-bundle rollback; preserving the newly written document instead of deleting it. Fix or restore config.toml before restarting."
            );
        }
    }
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
    let previous_document = read_previous_document(&ctx.config_path).await;
    let mut report = apply_full_config_locked(ctx, candidate, filter_apply, hooks).await?;

    if let Err(e) = save_config_document_atomic(&ctx.config_path, document, candidate).await {
        // Roll back with the same filter mode that was applied: a Deferred
        // apply never touched the filter engine, so a Sync rollback could
        // fail on an unrelated filter-source error and leave the runtime at
        // the rejected candidate.
        if let Err(rollback_err) =
            apply_full_config_locked(ctx, &previous, filter_apply, hooks).await
        {
            tracing::error!(
                error = %rollback_err.detail,
                "Failed to roll back in-memory configuration after persist failure"
            );
        }
        return Err(e);
    }

    let (publish_result, retry_delay) = ctx.publish_bundle_with_retry().await;
    match publish_result {
        Ok(sito_ha::PublishOutcome::TooLarge { bytes, limit }) => {
            // An oversized bundle is the one HA failure that is an apply
            // error: the configuration cannot be replicated at all. Roll both
            // the live configuration and the persisted document back (D8) and
            // republish the restored configuration so readiness recovers.
            tracing::error!(
                bytes,
                limit,
                "HA bundle exceeds the replication limit; rolling back the local apply"
            );
            rollback_document_after_oversized_bundle(
                &ctx.config_path,
                &previous,
                &previous_document,
            )
            .await;
            if let Err(e) = apply_full_config_locked(ctx, &previous, filter_apply, hooks).await {
                tracing::error!(
                    error = %e.detail,
                    "Failed to roll back in-memory configuration after an oversized HA bundle"
                );
            }
            if let Err(e) = ctx.publish_bundle().await {
                tracing::warn!(
                    error = %e,
                    "Failed to republish the restored configuration after an oversized HA bundle"
                );
            }
            return Err(ProblemDetails::bad_request(format!(
                "The configuration produces a {bytes}-byte HA bundle, above the {limit}-byte WebSocket replication limit; it was not applied. Reduce filter lists/rules or configuration size"
            )));
        }
        Ok(outcome) => {
            if ctx.master_coordinator.is_some() {
                report.ha_publish = Some(HaPublishReport::from_outcome(outcome));
            }
        }
        Err(e) => {
            // D8: the local apply and persist succeeded; an HA publish failure
            // must not roll it back. Surface the failure, leave HA readiness
            // false, and let the background retry recover.
            tracing::error!(error = %e, "HA publication failed after a successful local apply");
            report.ha_publish = Some(HaPublishReport::failed_with_retry(
                e.to_string(),
                retry_delay,
            ));
        }
    }

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

    // Capture the live configuration before applying so an unreplicable
    // (oversized) document can be rolled back. The file itself is the
    // operator's external edit and is left in place; only the running
    // configuration must not adopt it.
    let previous = (**ctx.config.load()).clone();
    match apply_full_config_locked(ctx, &new_cfg, filter_apply, hooks).await {
        Ok(report) => {
            // A slave's shared configuration is master-owned. If an external
            // edit changed the document, the applied-config digest no longer
            // matches and the node must stop reporting `Synced` instead of
            // silently serving drift until the next push.
            if let Some(ref tracker) = ctx.slave_tracker
                && let Err(e) = tracker.verify_applied_config(&current)
            {
                tracing::warn!(error = %e, "Failed to verify the applied HA configuration digest");
            }
            match ctx.publish_bundle().await {
                Ok(sito_ha::PublishOutcome::TooLarge { bytes, limit }) => {
                    if let Err(e) =
                        apply_full_config_locked(ctx, &previous, filter_apply, hooks).await
                    {
                        tracing::error!(
                            error = %e.detail,
                            "Failed to roll back an oversized file-watcher apply"
                        );
                    }
                    if let Err(e) = ctx.publish_bundle().await {
                        tracing::warn!(
                            error = %e,
                            "Failed to republish the restored configuration after an oversized file-watcher apply"
                        );
                    }
                    ConfigFileApplyOutcome::Rejected(ProblemDetails::bad_request(format!(
                        "The configuration produces a {bytes}-byte HA bundle, above the {limit}-byte replication limit; the previous configuration remains active and the file was not rolled back"
                    )))
                }
                Ok(_) => ConfigFileApplyOutcome::Applied(report),
                Err(e) => {
                    // D8: a persisted local edit is not rolled back because HA
                    // publication failed; readiness and retry handle recovery.
                    tracing::warn!(error = %e, "HA publication failed after a file-watcher apply");
                    ConfigFileApplyOutcome::Applied(report)
                }
            }
        }
        Err(e) => ConfigFileApplyOutcome::Rejected(e),
    }
}

/// Stages every component for `candidate` without changing live state.
async fn stage_config(
    ctx: &ServerContext,
    candidate: &Config,
    filter_apply: FilterApply,
    hooks: Option<&dyn ConfigApplyHooks>,
) -> Result<StagedApply, ProblemDetails> {
    let expected = ctx.runtime.generation();

    // Typed dependent-crate sections are validated by the single validator
    // (`validate_full_config` above); here they are converted for the plan.
    let clients = clients_from_config(candidate)?;
    let rewrites = rewrites_from_config(candidate)?;

    // Filter: compile/fetch on a staging engine. On failure the live snapshot
    // and status are untouched and the apply returns before any publish.
    let prepared_filter = match filter_apply {
        FilterApply::Sync => {
            ctx.filter
                .prepare_with_groups(
                    &candidate.filtering,
                    Some(sito_runtime::group_rule_sets(&clients)),
                )
                .await
        }
        FilterApply::Deferred => {
            ctx.filter
                .prepare_current_with_groups(Some(sito_runtime::group_rule_sets(&clients)))
                .await
        }
    };
    if let Some(error) = prepared_filter.error.as_ref() {
        return Err(ProblemDetails::internal_error(format!(
            "Failed to apply filter configuration: {error}"
        )));
    }

    // Upstream: construct and validate every server (including per-domain
    // scopes) into a prepared manager that is not live yet.
    let bootstrap = BootstrapResolver::from_config(&candidate.upstream);
    let prepared_upstream = ctx
        .upstream
        .prepare(&candidate.upstream, &bootstrap)
        .await
        .map_err(|e| problem_from_apply(ApplyError::Upstream(e)))?;

    // Hook-owned components: DNSSEC validator, scoped upstreams, listener
    // plan. Prepare must not mutate anything.
    let prepared_hooks = match hooks {
        Some(hooks) => Some(
            hooks
                .prepare(candidate, &clients)
                .await
                .map_err(problem_from_apply)?,
        ),
        None => None,
    };
    let dnssec_policy = prepared_hooks.as_ref().map_or_else(
        || DnssecPolicy::from_config(&candidate.dns.dnssec),
        |p| p.dnssec_policy.clone(),
    );

    let plan = ApplyPlan {
        config: candidate.clone(),
        clients,
        rewrites,
        filter: Some(Arc::clone(&prepared_filter.snapshot)),
        group_filters: Arc::clone(&prepared_filter.group_snapshots),
        dnssec_policy,
        cache_policy: candidate.dns.cache.clone(),
        transport_policy: TransportPolicy::from(candidate),
    };

    Ok(StagedApply {
        plan,
        prepared_filter,
        prepared_upstream,
        prepared_hooks,
        expected,
    })
}

/// Maps an apply error to the REST problem document.
pub(crate) fn problem_from_apply(error: ApplyError) -> ProblemDetails {
    match error {
        ApplyError::Validation(e) => {
            ProblemDetails::bad_request(format!("Configuration error: {e}"))
        }
        ApplyError::Upstream(e) => {
            ProblemDetails::bad_request(format!("Invalid upstream configuration: {e}"))
        }
        ApplyError::Filter(e) => {
            ProblemDetails::internal_error(format!("Failed to apply filter configuration: {e}"))
        }
        ApplyError::Tls(e) => {
            ProblemDetails::internal_error(format!("Failed to prepare TLS/listeners: {e}"))
        }
        ApplyError::Internal(reason) => {
            ProblemDetails::internal_error(format!("Configuration apply failed: {reason}"))
        }
        ApplyError::GenerationConflict { expected, actual } => ProblemDetails::conflict(format!(
            "configuration generation changed while the write was staged (expected {expected}, current {actual}); retry the write"
        )),
    }
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
    let runtime = ctx.runtime.clone();
    tokio::spawn(async move {
        // Capture the generation the caller's `filtering` value belongs to
        // before staging. The helper re-checks both the generation and the
        // filtering config after acquiring the engine guard: an apply that
        // committed before this task started makes the refresh stale even
        // though the generation read here is already the new one.
        let expected = runtime.generation();
        match apply_filter_refresh(&engine, &runtime, &filtering, expected).await {
            Ok(_) => {
                cache.flush();
                metrics.set_filter_rules(engine.rule_count());
                tracing::info!("Background blocklist refresh completed");
            }
            Err(ApplyError::GenerationConflict { .. }) => {
                tracing::debug!(
                    "Discarding a background blocklist refresh compiled for an older configuration"
                );
            }
            Err(error) => {
                tracing::error!(
                    "Background blocklist refresh failed; the filter engine keeps its previous \
                     snapshot: {error}"
                );
            }
        }
    })
}

/// Stages and publishes one filter refresh, tied to `expected` (the config
/// generation the caller captured together with `filtering`).
///
/// Both the generation **and** the filtering configuration are re-checked after
/// the engine guard is acquired. A refresh whose `filtering` value came from an
/// older config therefore cannot overwrite the newer generation's filter, even
/// when its own generation read happened after that apply committed.
pub(crate) async fn apply_filter_refresh(
    engine: &sito_filter::HostsFilterEngine,
    runtime: &sito_runtime::RuntimeState,
    filtering: &sito_core::config::FilteringConfig,
    expected: RuntimeGeneration,
) -> Result<usize, ApplyError> {
    let prepared = engine.prepare(filtering).await;

    // The prepared value holds the engine reload guard. While it is held no
    // config apply can stage/publish a new filter, so this check is stable.
    let live = runtime.snapshot();
    if live.generation != expected || &live.config.filtering != filtering {
        // Dropping `prepared` releases the guard without publishing either the
        // engine state or the runtime snapshot.
        return Err(ApplyError::GenerationConflict {
            expected,
            actual: live.generation,
        });
    }

    if prepared.error.is_some() {
        // Keep the previous rules; publish the failure status only. With the
        // staged error still present, `publish_prepared` returns it after
        // installing the status, so that error is the one we report. An `Ok`
        // here would mean the staged error vanished; surface that as an
        // internal error instead of logging a false success/failure.
        let publish = engine.publish_prepared(prepared);
        if let Err(error) = publish {
            return Err(ApplyError::Filter(error));
        }
        tracing::error!("Filter publish unexpectedly succeeded after a staged load failure");
        return Err(ApplyError::Internal(
            "filter apply failed but the staged error was not reported".to_string(),
        ));
    }

    let snapshot = prepared.snapshot.clone();
    let groups = prepared.group_snapshots.clone();
    runtime.publish_filter(Some(snapshot), groups, expected)?;
    engine
        .publish_prepared(prepared)
        .map_err(ApplyError::Filter)
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
    // [auth] sessions/token policy is read once at startup. Compare the
    // effective typed policy, not the raw TOML: an explicitly configured
    // default (`[auth]` with the default values) is equivalent to omitting the
    // section, and HA sanitization strips inert legacy keys such as
    // `admin_password_hash`/`tokens` from the replicated table.
    mark(
        old.get_auth_config() != new.get_auth_config(),
        "auth",
        &mut fields,
    );
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
    // TLS/ACME material feeds the listener acceptors built at startup. Compare
    // the effective configuration (`dns.tls` wins over top-level `[tls]`;
    // `[acme]` wins over legacy `[web] acme_*`) and the raw top-level aliases,
    // so editing either alias is reported even when the other is unchanged.
    mark(
        old.get_tls_config() != new.get_tls_config()
            || old.dns.tls != new.dns.tls
            || old.tls != new.tls,
        "tls",
        &mut fields,
    );
    mark(
        old.get_acme_config() != new.get_acme_config() || old.acme != new.acme,
        "acme",
        &mut fields,
    );
    // HA workers and integrations are initialized at startup.
    mark(old.ha != new.ha, "ha", &mut fields);
    mark(
        old.integrations != new.integrations,
        "integrations",
        &mut fields,
    );
    fields
}

/// The complete restart-only matrix (D11), in the order reported by
/// [`restart_required_fields`].
///
/// `GET /api/v1/config/restart-required` publishes this list so the UI can
/// show which edits require a process restart. Keep it in sync with the
/// comparisons above; the parity test asserts every name is reachable.
#[must_use]
pub fn restart_required_field_names() -> Vec<&'static str> {
    vec![
        "server.role",
        "server.instance_name",
        "server.data_dir",
        "server.log_format",
        "auth",
        "web",
        "tls",
        "acme",
        "ha",
        "integrations",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Deferred D4b: `retry_at` must reflect the retry loop that was actually
    /// scheduled, and must be absent when no new loop was started.
    #[test]
    fn test_ha_publish_report_retry_at_matches_actual_schedule() {
        let before = chrono::Utc::now();
        let report =
            HaPublishReport::failed_with_retry("publish failed", Some(Duration::from_secs(2)));
        assert_eq!(report.status, "failed");
        let retry_at = chrono::DateTime::parse_from_rfc3339(
            report
                .retry_at
                .as_deref()
                .expect("a scheduled retry has a time"),
        )
        .expect("RFC3339 retry_at")
        .with_timezone(&chrono::Utc);
        let delay = retry_at.signed_duration_since(before);
        assert!(
            delay >= chrono::TimeDelta::try_seconds(1).unwrap()
                && delay <= chrono::TimeDelta::try_seconds(3).unwrap(),
            "retry_at must be the scheduled delay, not a fixed guess: {delay}"
        );

        let report = HaPublishReport::failed_with_retry("publish failed", None);
        assert!(
            report.retry_at.is_none(),
            "an already-running retry loop must not advertise a new retry time"
        );

        // The compatibility constructor keeps the historical one-second
        // estimate so external Rust callers do not need to change.
        let report = HaPublishReport::failed("publish failed");
        assert!(report.retry_at.is_some());
    }

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

    /// `[dns.tls]` is the effective TLS source (top-level `[tls]` is the
    /// alias). Both must be restart-required, as must legacy `[web] acme_*`
    /// keys resolved through `get_acme_config()`.
    #[test]
    fn test_restart_required_tracks_effective_tls_and_legacy_acme() {
        let old = Config::default();

        let mut dns_tls = old.clone();
        dns_tls.dns.tls = Some(
            toml::from_str::<sito_core::config::TlsConfig>(
                r#"
                cert = "/etc/sito/new-cert.pem"
                key = "/etc/sito/new-key.pem"
                "#,
            )
            .unwrap(),
        );
        assert!(
            restart_required_fields(&old, &dns_tls)
                .iter()
                .any(|field| field == "tls"),
            "[dns.tls] changes feed the startup TLS acceptors"
        );

        let mut top_level_tls = old.clone();
        top_level_tls.tls = dns_tls.dns.tls.clone();
        assert!(
            restart_required_fields(&old, &top_level_tls)
                .iter()
                .any(|field| field == "tls"),
            "top-level [tls] is still a supported alias and requires a restart"
        );

        let mut legacy_acme = old.clone();
        legacy_acme.web = Some(
            toml::from_str::<toml::Value>(
                r#"
                acme_enabled = true
                acme_domains = ["dns.example.com"]
                "#,
            )
            .unwrap(),
        );
        assert!(
            restart_required_fields(&old, &legacy_acme)
                .iter()
                .any(|field| field == "acme"),
            "legacy [web] acme_* keys are resolved by get_acme_config() and must be restart-required"
        );

        // An unrelated [web] change remains hot-applied.
        let mut unrelated_web = old.clone();
        unrelated_web.web =
            Some(toml::from_str::<toml::Value>(r#"trusted_proxies = ["10.0.0.1"]"#).unwrap());
        assert_eq!(
            restart_required_fields(&old, &unrelated_web),
            Vec::<String>::new()
        );
    }

    /// Regression: HA restores the slave's node-local `[web]` identity before
    /// the restart check runs. A master with `web.enabled = true` (and its own
    /// proxy/public-URL settings) must therefore not make a slave that
    /// disabled the listener report `restart_required: web`. A genuine
    /// listener-shape change on the slave still requires a restart.
    #[test]
    fn test_restart_web_ignores_preserved_node_local_identity() {
        let live = Config::from_toml_str(
            r#"
config_version = 2

[web]
enabled = false
bind = "127.0.0.1"
port = 8081
trusted_proxies = ["10.0.0.2"]
metrics_auth = false
public_url = "https://slave.example"
tls_terminated_by_proxy = true
"#,
        )
        .expect("live slave config");

        // Document as produced by `build_persisted_config`: the live web
        // identity is restored while the master's cluster-shared `[web]`
        // keys survive.
        let preserved = Config::from_toml_str(
            r#"
config_version = 2

[web]
enabled = false
bind = "127.0.0.1"
port = 8081
trusted_proxies = ["10.0.0.2"]
metrics_auth = false
public_url = "https://slave.example"
tls_terminated_by_proxy = true
acme_enabled = false
"#,
        )
        .expect("merged persisted config");

        assert!(
            restart_required_fields(&live, &preserved).is_empty(),
            "preserved node-local web identity must not require a restart: {:?}",
            restart_required_fields(&live, &preserved)
        );

        // Changing the actual listener shape locally still requires a restart.
        let mut enabled = preserved.clone();
        let mut web = enabled.get_web_config();
        web.enabled = true;
        enabled.set_web_config(web);
        let fields = restart_required_fields(&live, &enabled);
        assert!(
            fields.iter().any(|field| field == "web"),
            "a genuine web listener change must still be reported: {fields:?}"
        );
    }

    /// Regression: `[auth]` was compared as raw TOML, so a master that spells
    /// out the default policy (or carries inert legacy keys) was treated as a
    /// restart-only change against a slave that omits `[auth]`. That made
    /// every push fail with `restart_required: auth`. Only a real effective
    /// policy difference may require a restart.
    #[test]
    fn test_restart_auth_compares_effective_policy_not_raw_toml() {
        let without_auth = Config::default();

        let mut with_default_auth = without_auth.clone();
        with_default_auth.auth = Some(
            toml::from_str(
                r"
                session_ttl_hours = 24
                login_rate_limit = 5
                session_persist = true
                token_default_ttl_days = 90
                ",
            )
            .unwrap(),
        );
        assert!(
            restart_required_fields(&without_auth, &with_default_auth).is_empty(),
            "explicit defaults must be equivalent to omitting [auth]: {:?}",
            restart_required_fields(&without_auth, &with_default_auth)
        );
        assert!(
            restart_required_fields(&with_default_auth, &without_auth).is_empty(),
            "removing an explicit-default [auth] must not require a restart: {:?}",
            restart_required_fields(&with_default_auth, &without_auth)
        );

        // Sanitization strips these inert legacy keys from replicated bundles;
        // their presence must not look like a policy change either.
        let mut legacy_auth = without_auth.clone();
        legacy_auth.auth = Some(
            toml::from_str(
                r#"
                admin_password_hash = "$argon2id$legacy"
                tokens = ["legacy-token"]
                "#,
            )
            .unwrap(),
        );
        assert!(
            restart_required_fields(&without_auth, &legacy_auth).is_empty(),
            "inert legacy [auth] keys must not require a restart: {:?}",
            restart_required_fields(&without_auth, &legacy_auth)
        );

        // A genuine policy change still needs a restart.
        let mut changed_policy = without_auth.clone();
        changed_policy.auth = Some(toml::from_str("session_ttl_hours = 1").unwrap());
        let fields = restart_required_fields(&without_auth, &changed_policy);
        assert!(
            fields.iter().any(|field| field == "auth"),
            "a real [auth] policy change must be reported: {fields:?}"
        );
    }

    /// Hook used to observe what the runtime snapshot contains at the moment
    /// hook-owned components are applied.
    struct RuntimeProbeHook {
        runtime: Arc<sito_runtime::RuntimeState>,
        seen_filter_enabled: Arc<std::sync::atomic::AtomicBool>,
        fail: bool,
    }

    impl ConfigApplyHooks for RuntimeProbeHook {
        fn prepare<'a>(
            &'a self,
            cfg: &'a Config,
            _clients: &'a sito_clients::ClientsConfig,
        ) -> PrepareFuture<'a> {
            Box::pin(async move {
                // A prepare stage must observe the previous generation.
                self.seen_filter_enabled.store(
                    self.runtime.snapshot().config.filtering.enabled,
                    std::sync::atomic::Ordering::SeqCst,
                );
                if self.fail {
                    return Err(ApplyError::Internal("injected hook failure".to_string()));
                }
                Ok(PreparedHooks {
                    dnssec_policy: DnssecPolicy::from_config(&cfg.dns.dnssec),
                    commit: Box::new(()),
                })
            })
        }

        fn commit(&self, _prepared: PreparedHooks) -> ApplyFuture<'_> {
            Box::pin(async { Ok(()) })
        }
    }

    /// WP-1.4: config, clients, rewrites and the compiled filter snapshot are
    /// staged first and published together. A prepare hook observes the old
    /// generation; after apply a reader observes the new config and the new
    /// rules from one snapshot.
    #[tokio::test]
    async fn test_apply_publishes_config_and_filter_together_after_staging() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_filter_order");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let mut previous = (**ctx.config.load()).clone();
        previous.filtering.enabled = false;
        previous.filtering.lists.clear();
        previous.filtering.custom_rules.clear();
        ctx.config.store(Arc::new(previous.clone()));

        let mut candidate = previous.clone();
        candidate.filtering.enabled = true;
        candidate.filtering.custom_rules = vec!["||ordered.example^".to_string()];

        let seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook = RuntimeProbeHook {
            runtime: Arc::clone(&ctx.runtime),
            seen_filter_enabled: Arc::clone(&seen),
            fail: false,
        };
        apply_full_config(&ctx, &candidate, FilterApply::Sync, Some(&hook))
            .await
            .unwrap();

        assert!(
            !seen.load(std::sync::atomic::Ordering::SeqCst),
            "prepare must observe the previous generation, not the candidate"
        );
        let snapshot = ctx.runtime.snapshot();
        assert_eq!(
            snapshot.config.filtering.custom_rules,
            vec!["||ordered.example^".to_string()]
        );
        let filter = snapshot
            .filter
            .as_ref()
            .expect("the applied generation carries the compiled filter");
        assert_eq!(filter.rule_count, 1);
        assert_eq!(ctx.filter.rule_count(), 1);
        assert_eq!(ctx.filter.status().state, sito_filter::FilterState::Ready);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// P1-26: a later hook failure rolls the runtime snapshot back so the old
    /// config and the old filter snapshot both remain active.
    #[tokio::test]
    async fn test_failed_hook_leaves_old_config_and_filter() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_filter_hook_fail");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let mut previous = (**ctx.config.load()).clone();
        previous.filtering.enabled = true;
        previous.filtering.custom_rules = vec!["||old.example^".to_string()];
        apply_full_config(&ctx, &previous, FilterApply::Sync, None)
            .await
            .unwrap();
        assert_eq!(ctx.filter.rule_count(), 1);

        let mut candidate = previous.clone();
        candidate.filtering.custom_rules = vec!["||new.example^".to_string()];

        let hook = RuntimeProbeHook {
            runtime: Arc::clone(&ctx.runtime),
            seen_filter_enabled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            fail: true,
        };
        apply_full_config(&ctx, &candidate, FilterApply::Sync, Some(&hook))
            .await
            .expect_err("the injected hook failure must reject the apply");

        assert_eq!(
            ctx.runtime.snapshot().config.filtering.custom_rules,
            vec!["||old.example^".to_string()],
            "the runtime snapshot must be rolled back"
        );
        let snapshot = ctx.filter.snapshot();
        let client = sito_core::client::ClientContext::new("127.0.0.1".parse().unwrap());
        assert!(
            snapshot
                .evaluate("old.example", sito_proto::RecordType::A, &client)
                .is_blocked(),
            "the old filter snapshot must remain active"
        );
        assert!(
            snapshot
                .evaluate("new.example", sito_proto::RecordType::A, &client)
                .is_allowed(),
            "the rejected filter snapshot must not remain active"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
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

        /// Guard against re-introducing a direct config write in an admin
        /// handler: every write must acquire `apply_lock` and persist through
        /// the apply pipeline.
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
                    // `config_writer::save_config_document_atomic` is the only
                    // persistence primitive; handlers must go through
                    // `config_apply` instead of calling it directly.
                    if line.contains("save_config") && !allowlist.contains(&relative.as_str()) {
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

    /// D11: the preview matrix must cover exactly the fields the comparison
    /// can report. Each name is reachable with a minimal mutation.
    #[test]
    fn test_restart_matrix_names_are_all_reachable() {
        let old = Config::default();
        let names = restart_required_field_names();
        let mut seen = std::collections::HashSet::new();

        let mutations: Vec<(&str, Config)> = vec![
            ("server.role", {
                let mut c = old.clone();
                c.server.role = "slave".to_string();
                c
            }),
            ("server.instance_name", {
                let mut c = old.clone();
                c.server.instance_name = "other".to_string();
                c
            }),
            ("server.data_dir", {
                let mut c = old.clone();
                c.server.data_dir = std::path::PathBuf::from("/srv/sito");
                c
            }),
            ("server.log_format", {
                let mut c = old.clone();
                c.server.log_format = "pretty".to_string();
                c
            }),
            ("auth", {
                let mut c = old.clone();
                c.auth = Some(toml::from_str::<toml::Value>("session_ttl_hours = 1").unwrap());
                c
            }),
            ("web", {
                let mut c = old.clone();
                c.web = Some(toml::from_str::<toml::Value>("port = 9090").unwrap());
                c
            }),
            ("tls", {
                let mut c = old.clone();
                c.dns.tls = Some(
                    toml::from_str::<sito_core::config::TlsConfig>(
                        "cert = \"/etc/sito/cert.pem\"\nkey = \"/etc/sito/key.pem\"",
                    )
                    .unwrap(),
                );
                c
            }),
            ("acme", {
                let mut c = old.clone();
                c.acme = Some(sito_core::config::AcmeConfig {
                    enabled: true,
                    domains: vec!["dns.example.com".to_string()],
                    ..Default::default()
                });
                c
            }),
            ("ha", {
                let mut c = old.clone();
                c.ha = Some(toml::from_str::<toml::Value>("replication_port = 8954").unwrap());
                c
            }),
            ("integrations", {
                let mut c = old.clone();
                c.integrations =
                    Some(toml::from_str::<toml::Value>("[lists]\nrefresh_hours = 12").unwrap());
                c
            }),
        ];

        for (expected, candidate) in mutations {
            let fields = restart_required_fields(&old, &candidate);
            assert!(
                fields.iter().any(|field| field == expected),
                "mutation should report '{expected}': {fields:?}"
            );
            for field in fields {
                assert!(
                    names.contains(&field.as_str()),
                    "reported field '{field}' is missing from the preview matrix"
                );
                seen.insert(field);
            }
        }

        for name in names {
            assert!(
                seen.contains(name),
                "restart-only field '{name}' has no reachable mutation; the matrix is not truthful"
            );
        }
    }

    /// WP-1.4 acceptance: the admin API, HA push and file watcher all execute
    /// the same staged apply and publish exactly one runtime generation.
    #[tokio::test]
    async fn test_api_ha_and_watcher_share_one_apply_function() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_apply_parity");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let mut api_config = (**ctx.config.load()).clone();
        api_config.upstream.servers = vec!["1.1.1.1".to_string()];
        let generation = ctx.runtime.generation();
        let applies = ctx.runtime.apply_count();
        apply_and_persist_config(&ctx, &api_config, FilterApply::Deferred, None)
            .await
            .expect("admin API apply");
        assert_eq!(ctx.runtime.apply_count(), applies + 1, "API applies once");
        assert_eq!(
            ctx.runtime.generation(),
            generation.next(),
            "API advances the generation"
        );
        assert_eq!(
            ctx.runtime.snapshot().config.upstream.servers,
            vec!["1.1.1.1"]
        );

        // HA slave push: same function, exact document preserved.
        let mut ha_config = api_config.clone();
        ha_config.upstream.servers = vec!["9.9.9.9".to_string()];
        let ha_document = toml::to_string_pretty(&ha_config).unwrap();
        let generation = ctx.runtime.generation();
        let applies = ctx.runtime.apply_count();
        apply_and_persist_document_rejecting_restart(
            &ctx,
            &ha_config,
            &ha_document,
            FilterApply::Deferred,
            None,
        )
        .await
        .expect("HA apply");
        assert_eq!(ctx.runtime.apply_count(), applies + 1, "HA applies once");
        assert_eq!(
            ctx.runtime.generation(),
            generation.next(),
            "HA advances the generation"
        );
        assert_eq!(
            ctx.runtime.snapshot().config.upstream.servers,
            vec!["9.9.9.9"]
        );

        // File watcher: same function again.
        let mut watched = ha_config.clone();
        watched.upstream.servers = vec!["1.0.0.1".to_string()];
        let watched_document = toml::to_string_pretty(&watched).unwrap();
        tokio::fs::write(&ctx.config_path, &watched_document)
            .await
            .unwrap();
        let generation = ctx.runtime.generation();
        let applies = ctx.runtime.apply_count();
        match apply_config_document_event(&ctx, &watched_document, FilterApply::Deferred, None)
            .await
        {
            ConfigFileApplyOutcome::Applied(_) => {}
            other => panic!("watcher must apply the changed document, got {other:?}"),
        }
        assert_eq!(
            ctx.runtime.apply_count(),
            applies + 1,
            "watcher applies once"
        );
        assert_eq!(
            ctx.runtime.generation(),
            generation.next(),
            "watcher advances the generation"
        );
        assert_eq!(
            ctx.runtime.snapshot().config.upstream.servers,
            vec!["1.0.0.1"]
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Source guard: no entry point may publish runtime components directly.
    /// The single publish is `RuntimeState::apply`; every path stages a plan
    /// and calls it with an expected generation.
    #[test]
    fn test_no_entry_point_publishes_runtime_components_directly() {
        let source = include_str!("config_apply.rs");
        let direct_replace = concat!("runtime", ".replace(");
        assert!(
            !source.contains(direct_replace),
            "config_apply must publish through RuntimeState::apply, not replace()"
        );
        assert!(
            source.contains("stage_config(") && source.contains("apply_expecting_with("),
            "every apply path must stage a plan and call apply_expecting_with"
        );
    }

    /// End-to-end variant of the torn-read test: a reader thread observes the
    /// API apply through `ServerContext::runtime`, and every snapshot must pair
    /// the config with the filter compiled for it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_end_to_end_reader_never_sees_torn_config_and_filter() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_e2e_torn");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let mut seed = (**ctx.config.load()).clone();
        seed.filtering.enabled = true;
        seed.filtering.custom_rules = vec!["||old-e2e.example^".to_string()];
        apply_and_persist_config(&ctx, &seed, FilterApply::Sync, None)
            .await
            .expect("seed apply");

        let start = Arc::new(std::sync::Barrier::new(2));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let new_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pairs = Arc::new(std::sync::Mutex::new(std::collections::HashSet::<(
            String,
            Option<String>,
        )>::new()));
        let reader_runtime = Arc::clone(&ctx.runtime);
        let reader_start = Arc::clone(&start);
        let reader_stop = Arc::clone(&stop);
        let reader_first = Arc::clone(&first_read);
        let reader_new = Arc::clone(&new_seen);
        let reader_pairs = Arc::clone(&pairs);
        let reader = std::thread::spawn(move || {
            reader_start.wait();
            while !reader_stop.load(std::sync::atomic::Ordering::Acquire) {
                let snapshot = reader_runtime.snapshot();
                let config_rule = snapshot.config.filtering.custom_rules.first().cloned();
                let filter_rule = snapshot
                    .filter
                    .as_ref()
                    .and_then(|filter| filter.rules.first().map(|rule| rule.raw.clone()));
                let config_rule = config_rule.unwrap_or_default();
                if config_rule == "||new-e2e.example^" {
                    reader_new.store(true, std::sync::atomic::Ordering::Release);
                }
                reader_pairs
                    .lock()
                    .unwrap()
                    .insert((config_rule, filter_rule));
                reader_first.store(true, std::sync::atomic::Ordering::Release);
            }
        });

        start.wait();
        while !first_read.load(std::sync::atomic::Ordering::Acquire) {
            std::hint::spin_loop();
        }
        let mut next = seed.clone();
        next.filtering.custom_rules = vec!["||new-e2e.example^".to_string()];
        apply_and_persist_config(&ctx, &next, FilterApply::Sync, None)
            .await
            .expect("new generation apply");
        // The apply has returned, so the new snapshot is live. Wait until the
        // reader has actually observed it before stopping, otherwise this test
        // depends on thread scheduling.
        while !new_seen.load(std::sync::atomic::Ordering::Acquire) {
            std::hint::spin_loop();
        }
        stop.store(true, std::sync::atomic::Ordering::Release);
        reader.join().expect("reader thread");

        let pairs = pairs.lock().unwrap();
        assert!(
            pairs.contains(&(
                "||old-e2e.example^".to_string(),
                Some("||old-e2e.example^".to_string())
            )),
            "the reader must observe the old generation: {pairs:?}"
        );
        assert!(
            pairs.contains(&(
                "||new-e2e.example^".to_string(),
                Some("||new-e2e.example^".to_string())
            )),
            "the reader must observe the new generation: {pairs:?}"
        );
        for (config_rule, filter_rule) in pairs.iter() {
            assert_eq!(
                filter_rule.as_deref(),
                Some(config_rule.as_str()),
                "config and filter must be from the same generation"
            );
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Finding 4 regression: a background refresh whose `filtering` value was
    /// captured before a newer config apply must be discarded even when its
    /// generation read happens after that apply committed.
    #[tokio::test]
    async fn test_stale_filter_refresh_cannot_overwrite_newer_generation() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_stale_refresh");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let mut old = (**ctx.config.load()).clone();
        old.filtering.enabled = true;
        old.filtering.custom_rules = vec!["||old-refresh.example^".to_string()];
        apply_and_persist_config(&ctx, &old, FilterApply::Sync, None)
            .await
            .expect("old generation");
        let stale_filtering = old.filtering.clone();
        let stale_expected = ctx.runtime.generation();

        let mut new = old.clone();
        new.filtering.custom_rules = vec!["||new-config.example^".to_string()];
        apply_and_persist_config(&ctx, &new, FilterApply::Sync, None)
            .await
            .expect("new generation");
        let after_apply = ctx.runtime.snapshot();
        assert_eq!(
            after_apply.config.filtering.custom_rules,
            vec!["||new-config.example^".to_string()]
        );

        let error = crate::config_apply::apply_filter_refresh(
            &ctx.filter,
            &ctx.runtime,
            &stale_filtering,
            stale_expected,
        )
        .await
        .expect_err("a refresh compiled for the older filtering config must be discarded");
        assert!(
            matches!(error, ApplyError::GenerationConflict { .. }),
            "got {error:?}"
        );

        let after_refresh = ctx.runtime.snapshot();
        assert_eq!(
            after_refresh.config.filtering.custom_rules,
            vec!["||new-config.example^".to_string()],
            "the newer config must survive the stale refresh"
        );
        assert_eq!(
            after_refresh
                .filter
                .as_ref()
                .unwrap()
                .rules
                .first()
                .map(|rule| rule.raw.as_str()),
            Some("||new-config.example^"),
            "the newer filter must survive the stale refresh"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// A failure in the hook commit step (e.g. a listener cannot rebind) must
    /// leave the runtime snapshot, filter engine and upstream manager on the
    /// previous generation.
    struct CommitFailHook;

    impl ConfigApplyHooks for CommitFailHook {
        fn prepare<'a>(
            &'a self,
            cfg: &'a Config,
            _clients: &'a sito_clients::ClientsConfig,
        ) -> PrepareFuture<'a> {
            Box::pin(async move {
                Ok(PreparedHooks {
                    dnssec_policy: DnssecPolicy::from_config(&cfg.dns.dnssec),
                    commit: Box::new(()),
                })
            })
        }

        fn commit(&self, _prepared: PreparedHooks) -> ApplyFuture<'_> {
            Box::pin(async {
                Err(ApplyError::Internal(
                    "injected listener commit failure".to_string(),
                ))
            })
        }
    }

    #[tokio::test]
    async fn test_commit_failure_leaves_every_component_on_the_old_generation() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_commit_fail");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let mut seed = (**ctx.config.load()).clone();
        seed.upstream.servers = vec!["1.1.1.1".to_string()];
        seed.filtering.enabled = true;
        seed.filtering.custom_rules = vec!["||keep.example^".to_string()];
        apply_and_persist_config(&ctx, &seed, FilterApply::Sync, None)
            .await
            .expect("seed apply");

        let before = ctx.runtime.snapshot();
        let generation = before.generation;
        let upstream_before = ctx.upstream.statuses().await;
        let rules_before = ctx.filter.rule_count();

        let mut candidate = seed.clone();
        candidate.upstream.servers = vec!["9.9.9.9".to_string()];
        candidate.filtering.custom_rules = vec!["||must-not-stick.example^".to_string()];
        let error = apply_full_config(&ctx, &candidate, FilterApply::Sync, Some(&CommitFailHook))
            .await
            .expect_err("the injected commit failure must reject the apply");
        assert_eq!(error.status, 500);

        assert_eq!(ctx.runtime.generation(), generation);
        assert_eq!(
            ctx.runtime.snapshot().config.filtering.custom_rules,
            vec!["||keep.example^".to_string()]
        );
        assert_eq!(ctx.config.load().upstream.servers, vec!["1.1.1.1"]);
        assert_eq!(
            ctx.upstream.statuses().await,
            upstream_before,
            "the staged upstream set must not be published on commit failure"
        );
        assert_eq!(
            ctx.filter.rule_count(),
            rules_before,
            "the staged filter must not be published on commit failure"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// A Deferred apply (clients API/UI save) must rebuild the per-group
    /// snapshots from the already-loaded rules; otherwise a new group rule is
    /// not enforced until the next scheduled refresh.
    #[tokio::test]
    async fn test_deferred_apply_rebuilds_group_snapshots() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_deferred_groups");
        let ctx = crate::test_support::mock_context(&temp_dir).await;

        let mut clients = sito_clients::ClientsConfig::default();
        clients.groups.insert(
            "kids".to_string(),
            sito_clients::ClientGroupConfig {
                custom_rules: vec!["||blocked-by-group.example^".to_string()],
                ..Default::default()
            },
        );

        let mut candidate = (**ctx.config.load()).clone();
        candidate.clients = Some(toml::Value::try_from(&clients).unwrap());
        apply_and_persist_config(&ctx, &candidate, FilterApply::Deferred, None)
            .await
            .expect("deferred clients save");

        let snapshot = ctx.runtime.snapshot();
        let group_snapshot = snapshot
            .group_filters
            .get("kids")
            .expect("the deferred apply must compile the new group rules");
        let client = sito_core::client::ClientContext::new("127.0.0.1".parse().unwrap());
        assert!(
            group_snapshot
                .evaluate(
                    "blocked-by-group.example",
                    sito_proto::RecordType::A,
                    &client
                )
                .is_blocked(),
            "the new group rule must be enforced immediately"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// D11: an admin write that changes a restart-only field returns 409 and
    /// must not apply or persist anything.
    #[tokio::test]
    async fn test_restart_only_write_is_conflict_and_not_persisted() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_restart_conflict");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        let original = (**ctx.config.load()).clone();

        let mut candidate = original.clone();
        candidate.server.role = "slave".to_string();

        let err = apply_and_persist_config(&ctx, &candidate, FilterApply::Deferred, None)
            .await
            .expect_err("restart-only write must be rejected");
        assert_eq!(err.status, 409);
        assert!(
            err.restart_required
                .as_deref()
                .is_some_and(|fields| fields == &["server.role".to_string()])
        );
        assert_eq!(ctx.config.load().server.role, "master");
        assert!(
            !ctx.config_path.exists(),
            "a rejected restart-only write must not persist a file"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// D11 parity: the HA push path uses the same matrix and returns 409
    /// without applying or persisting.
    #[tokio::test]
    async fn test_ha_restart_only_push_is_conflict_and_not_persisted() {
        let temp_dir = crate::test_support::temp_dir("sito_cfg_ha_restart_conflict");
        let ctx = crate::test_support::mock_context(&temp_dir).await;
        let original = (**ctx.config.load()).clone();
        tokio::fs::write(&ctx.config_path, toml::to_string_pretty(&original).unwrap())
            .await
            .unwrap();

        let mut candidate = original.clone();
        candidate.server.data_dir = std::path::PathBuf::from("/srv/other");
        let document = toml::to_string_pretty(&candidate).unwrap();

        let err = apply_and_persist_document_rejecting_restart(
            &ctx,
            &candidate,
            &document,
            FilterApply::Deferred,
            None,
        )
        .await
        .expect_err("HA push must reject restart-only fields");
        assert_eq!(err.status, 409);
        assert!(
            err.restart_required
                .as_deref()
                .is_some_and(|fields| fields.contains(&"server.data_dir".to_string()))
        );
        assert_eq!(ctx.config.load().server.data_dir, original.server.data_dir);
        assert_eq!(
            tokio::fs::read_to_string(&ctx.config_path).await.unwrap(),
            toml::to_string_pretty(&original).unwrap(),
            "the HA file must keep the previous document"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

#[cfg(test)]
mod rollback_document_tests {
    use super::*;

    fn temp_config_path(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = crate::test_support::temp_dir(label);
        let path = dir.join("config.toml");
        (dir, path)
    }

    /// A read error is not "no previous document": the rollback must preserve
    /// the newly written file instead of deleting the only copy.
    #[tokio::test]
    async fn test_unreadable_previous_document_preserves_the_new_file() {
        let (dir, path) = temp_config_path("sito_rollback_unreadable");
        tokio::fs::write(&path, "new-document")
            .await
            .expect("write new document");
        let unreadable = PreviousDocumentRead::Unreadable(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        ));

        rollback_document_after_oversized_bundle(&path, &Config::default(), &unreadable).await;

        assert_eq!(
            tokio::fs::read_to_string(&path)
                .await
                .expect("new document must survive"),
            "new-document"
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn test_missing_previous_document_removes_the_new_file() {
        let (dir, path) = temp_config_path("sito_rollback_missing");
        tokio::fs::write(&path, "new-document")
            .await
            .expect("write new document");

        rollback_document_after_oversized_bundle(
            &path,
            &Config::default(),
            &PreviousDocumentRead::Missing,
        )
        .await;

        assert!(
            !path.exists(),
            "a genuinely absent previous document is removed so restart cannot load the rejected config"
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn test_present_previous_document_is_restored() {
        let (dir, path) = temp_config_path("sito_rollback_present");
        tokio::fs::write(&path, "new-document")
            .await
            .expect("write new document");

        rollback_document_after_oversized_bundle(
            &path,
            &Config::default(),
            &PreviousDocumentRead::Present("config_version = 2\n".to_string()),
        )
        .await;

        assert_eq!(
            tokio::fs::read_to_string(&path)
                .await
                .expect("restored document"),
            "config_version = 2\n"
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
