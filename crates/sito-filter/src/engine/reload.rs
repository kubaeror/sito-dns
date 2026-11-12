//! List reload, refresh scheduling, and snapshot retention.

#[allow(clippy::wildcard_imports)]
use super::*;

struct CompiledReload {
    snapshot: FilterSnapshot,
    count: usize,
    list_rules: FnvHashMap<String, Vec<Rule>>,
    rejected_lists: Vec<String>,
    compile_elapsed_ms: u64,
}

#[allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::needless_pass_by_value
)]
fn compile_reload_rules(
    custom_rules: Vec<String>,
    max_rules: usize,
    max_list_bytes: usize,
    allow_empty: bool,
    base_rules: FnvHashMap<String, Vec<Rule>>,
    enabled_names: FnvHashSet<String>,
    list_contents: Vec<(String, String)>,
    regex_compile_budget_ms: Option<u64>,
) -> Result<
    (
        FilterSnapshot,
        usize,
        FnvHashMap<String, Vec<Rule>>,
        Vec<String>,
    ),
    FilterError,
> {
    let budget = regex_compile_budget_ms.map(Duration::from_millis);
    let budget = budget.map(CompileBudget::new);
    // Merge instead of overwriting: rules from lists that failed to
    // fetch in this cycle (or that are not part of a partial refresh)
    // are retained so a transient failure cannot drop protection.
    let mut map = base_rules;
    // Drop rules for lists that are no longer enabled/configured.
    map.retain(|name, _| enabled_names.contains(name));

    // A fetched list replaces its previous entry only after parsing
    // succeeds. Budget accounting therefore starts from the retained
    // entries and any failures keep the old rules in place.
    let fetched_names: FnvHashSet<String> =
        list_contents.iter().map(|(name, _)| name.clone()).collect();
    let mut candidate_total: usize = map
        .iter()
        .filter(|(name, _)| !fetched_names.contains(*name))
        .map(|(_, rules)| rules.len())
        .sum();

    let mut rejected = Vec::new();
    for (name, content) in list_contents {
        let remaining = max_rules.saturating_sub(candidate_total);
        let limits = ParseLimits::new(remaining, max_list_bytes);
        let rules = match parse_rules_with_limits(&content, &name, limits) {
            Ok((rules, _)) => rules,
            Err(ParseError::TooManyRules { count, limit }) => {
                error!(
                    list = %name,
                    count,
                    limit,
                    "Rejecting blocklist that exceeds the parsing rule budget"
                );
                return Err(FilterError::TooManyRules {
                    count: candidate_total.saturating_add(count),
                    limit: max_rules,
                });
            }
            Err(e) => {
                error!(
                    list = %name,
                    error = %e,
                    limit = max_list_bytes,
                    "Rejecting blocklist that exceeds the parsing byte budget"
                );
                return Err(FilterError::CompileTaskFailed(format!("{name}: {e}")));
            }
        };
        if rules.is_empty() && !allow_empty {
            // An empty 200 response, an HTML error page that parsed
            // into nothing, or a zero-yield list must not replace the
            // previous rules with an empty set.
            warn!(
                list = %name,
                bytes = content.len(),
                "Rejecting empty/zero-yield blocklist response"
            );
            rejected.push(name);
            continue;
        }
        if let Some(reason) = pattern_load_exceeds_limits(&rules) {
            error!(
                list = %name,
                reason = %reason,
                "Rejecting blocklist with excessive pattern load"
            );
            rejected.push(name);
            continue;
        }
        candidate_total = candidate_total.saturating_add(rules.len());
        map.insert(name, rules);
    }

    let mut parsed_custom = Vec::new();
    for rule_text in &custom_rules {
        let remaining = max_rules.saturating_sub(candidate_total + parsed_custom.len());
        match parse_rules_with_limits(
            rule_text,
            "custom",
            ParseLimits::new(remaining, max_list_bytes),
        ) {
            Ok((rules, _)) => parsed_custom.extend(rules),
            Err(ParseError::TooManyRules { count, .. }) => {
                return Err(FilterError::TooManyRules {
                    count: candidate_total
                        .saturating_add(parsed_custom.len())
                        .saturating_add(count),
                    limit: max_rules,
                });
            }
            Err(e) => {
                return Err(FilterError::CompileTaskFailed(format!("custom: {e}")));
            }
        }
    }
    if let Some(reason) = pattern_load_exceeds_limits(&parsed_custom) {
        error!(
            reason = %reason,
            "Rejecting custom_rules with excessive pattern load"
        );
        return Err(FilterError::CompileTaskFailed(reason));
    }

    // Deterministic rule-id assignment: lists sorted by name, rule
    // order preserved within each list, custom rules last (config
    // order). Candidate precedence (first match wins) therefore stays
    // stable across reloads and hash-map iteration order changes.
    let mut names: Vec<&String> = map.keys().collect();
    names.sort_unstable();
    let parsed_rules: usize = map.values().map(Vec::len).sum();
    let total_candidate_rules = parsed_rules + parsed_custom.len();
    // Bound the materialised rule set: a hostile 64 MiB list can
    // hold tens of millions of minimal lines, and every rule is
    // materialised several times. Rejecting the reload keeps the
    // previous snapshot instead of OOM-killing the daemon.
    if total_candidate_rules > max_rules {
        error!(
            parsed = total_candidate_rules,
            limit = max_rules,
            "Filter rule set exceeds filtering.max_rules"
        );
        return Err(FilterError::TooManyRules {
            count: total_candidate_rules,
            limit: max_rules,
        });
    }
    let mut all_rules = Vec::with_capacity(total_candidate_rules);
    for name in names {
        all_rules.extend(map[name].iter().cloned());
    }
    all_rules.extend(parsed_custom);
    // Per-list checks cannot see two individually valid lists whose
    // combined Aho-Corasick/prefix/regex load exceeds the budget. The
    // builder would silently skip the whole class, so reject the
    // reload instead and keep the previous snapshot.
    if let Some(reason) = pattern_load_exceeds_limits(&all_rules) {
        error!(
            reason = %reason,
            "Combined filter rule set exceeds pattern compilation limits"
        );
        return Err(FilterError::CompileTaskFailed(reason));
    }
    let snapshot =
        FilterSnapshot::compile_with_budget(all_rules, budget.as_ref()).map_err(|e| {
            FilterError::CompileBudgetExceeded {
                elapsed_ms: e.elapsed_ms,
                limit_ms: e.limit_ms,
            }
        })?;
    let count = snapshot.rule_count;
    Ok((snapshot, count, map, rejected))
}

impl HostsFilterEngine {
    /// Reloads all configured blocklists and custom rules, updating snapshot atomically.
    /// Applies the >50% drop guard to protect against corrupted remote sources.
    pub async fn reload(&self) -> Result<usize, FilterError> {
        let config = self.config.load_full();
        self.reload_internal(&config, true, None).await
    }

    /// Reloads blocklists and custom rules using an updated filtering configuration.
    /// Does not enforce the >50% drop guard so intentional user deletions/edits take effect.
    ///
    /// The new configuration is only retained once the reload succeeded: a
    /// rejected config must not become the source for the next scheduled
    /// refresh (which would otherwise apply it later, behind the caller's
    /// back).
    ///
    /// This installs engine state only. It does not publish a runtime
    /// snapshot, so it is not a query-visible path; config applies and
    /// scheduled/manual refreshes use [`Self::prepare`] +
    /// [`Self::publish_prepared`] while holding the engine guard, and publish
    /// the runtime snapshot before releasing it.
    pub async fn reload_with_config(&self, config: &FilteringConfig) -> Result<usize, FilterError> {
        // Stage on a private engine and publish in one step. The reload lock
        // is held from the start of staging until the prepared state is
        // installed, so a rejected candidate never becomes the source for the
        // next scheduled refresh.
        let prepared = self.prepare(config).await;
        self.publish_prepared(prepared)
    }

    /// Refreshes only the named blocklists, keeping rules from all other lists.
    ///
    /// The engine guard is held while the runtime observer publishes the new
    /// filter, so a config apply cannot stage/publish a newer generation
    /// between the engine reload and the runtime snapshot update.
    pub async fn reload_lists(&self, names: &[String]) -> Result<usize, FilterError> {
        let guard = self.reload_lock.clone().lock_owned().await;
        let config = self.config.load_full();
        let result = self
            .reload_internal_locked(&config, true, Some(names))
            .await;
        // A scheduled/partial refresh publishes rules outside a config apply;
        // hand the new coherent filter generation to the runtime observer
        // while the guard is still held.
        self.observe_snapshot();
        drop(guard);
        result
    }

    pub(super) async fn reload_internal(
        &self,
        config: &FilteringConfig,
        apply_drop_guard: bool,
        only_lists: Option<&[String]>,
    ) -> Result<usize, FilterError> {
        // Serialize the whole fetch/merge/store cycle: a concurrent scheduled
        // refresh and API reload previously raced on `list_rules` and could
        // overwrite freshly merged lists with a stale map.
        let _reload_guard = self.reload_lock.lock().await;
        self.reload_internal_locked(config, apply_drop_guard, only_lists)
            .await
    }

    /// Reload body; the caller must hold the engine reload guard.
    pub(super) async fn reload_internal_locked(
        &self,
        config: &FilteringConfig,
        apply_drop_guard: bool,
        only_lists: Option<&[String]>,
    ) -> Result<usize, FilterError> {
        if let Some(count) = self.ensure_reload_sources(config)? {
            return Ok(count);
        }

        let has_global_source = config.lists.iter().any(|list| list.enabled)
            || config
                .custom_rules
                .iter()
                .any(|rule| !rule.trim().is_empty());
        let group_hint = self.group_sources_configured.load(Ordering::Acquire);
        let (list_contents, fetched_lists, mut failed_lists) =
            self.fetch_reload_lists(config, only_lists).await;
        let compiled = self
            .compile_reload_lists(config, list_contents, &fetched_lists, &failed_lists)
            .await?;

        // Lists whose newest content was rejected (empty/HTML/zero-yield or
        // over the pattern budget) retain their previous rules but are
        // reported as both failed (not refreshed) and degraded.
        let degraded_lists = compiled.rejected_lists.clone();
        failed_lists.extend(compiled.rejected_lists.iter().cloned());
        let loaded_lists = count_loaded_lists(&fetched_lists, &failed_lists);
        let prev_count = self.snapshot.load().rule_count;
        if let Some(count) = self.validate_reload_count(
            config,
            compiled.count,
            prev_count,
            &failed_lists,
            loaded_lists,
            compiled.compile_elapsed_ms,
            has_global_source,
            group_hint,
            apply_drop_guard,
        )? {
            return Ok(count);
        }
        let new_snapshot = compiled.snapshot;
        let count = compiled.count;
        let new_list_rules = compiled.list_rules;
        let compile_elapsed_ms = compiled.compile_elapsed_ms;

        if new_snapshot.dropped_regex_patterns > 0 {
            error!(
                dropped = new_snapshot.dropped_regex_patterns,
                "Some regex/wildcard blocking rules could not be compiled and are inactive"
            );
        }
        let dropped_prefix_rules = new_snapshot.allowlist.dropped_prefix_rules
            + new_snapshot.blocklist.dropped_prefix_rules;
        if dropped_prefix_rules > 0 {
            error!(
                dropped = dropped_prefix_rules,
                "Some prefix filtering rules could not be compiled and are inactive"
            );
        }
        let dropped_substring_rules = new_snapshot.allowlist.dropped_substring_rules
            + new_snapshot.blocklist.dropped_substring_rules;
        if dropped_substring_rules > 0 {
            error!(
                dropped = dropped_substring_rules,
                "Some substring filtering rules could not be compiled and are inactive"
            );
        }
        self.snapshot.store(Arc::new(new_snapshot));
        *sito_core::sync::lock_or_recover(&self.list_rules) = new_list_rules;
        // Bump the generation before rebuilding groups. A concurrent
        // `set_group_rules` that started from the old list map will detect the
        // change and discard its stale compilation instead of overwriting the
        // fresh snapshot.
        self.list_generation.fetch_add(1, Ordering::SeqCst);
        // Group rule sets are selected from the list rules, so they must track
        // the freshly loaded snapshot.
        let degraded_groups = {
            let list_rules = sito_core::sync::lock_or_recover(&self.list_rules).clone();
            self.rebuild_group_snapshots(&list_rules)
                .unwrap_or_default()
        };
        let last_error = if failed_lists.is_empty() {
            None
        } else {
            Some(format!(
                "{} list(s) failed to load: {}",
                failed_lists.len(),
                failed_lists.join(", ")
            ))
        };
        self.set_status(FilterStatus {
            state: FilterState::Ready,
            rule_count: count,
            loaded_lists,
            failed_lists,
            last_error,
            last_compile_ms: Some(compile_elapsed_ms),
            unavailable: false,
            dropped_regex_patterns: self.snapshot.load().dropped_regex_patterns,
            degraded_groups,
            degraded_lists,
        });
        info!(rule_count = count, "Filter snapshot compiled and loaded");
        Ok(count)
    }

    /// Handles the disabled/no-source preconditions. Returns `Some(0)` when
    /// the engine is disabled and `None` when the reload should continue.
    fn ensure_reload_sources(
        &self,
        config: &FilteringConfig,
    ) -> Result<Option<usize>, FilterError> {
        if !config.enabled {
            // A disabled engine answers normally; the placeholder keeps
            // `unavailable_for_fail_closed` false while disabled and forces a
            // fresh successful load before fail-closed can be relied on again.
            self.snapshot.store(Arc::new(FilterSnapshot::default()));
            sito_core::sync::lock_or_recover(&self.list_rules).clear();
            self.set_status(FilterStatus {
                state: FilterState::Disabled,
                ..FilterStatus::default()
            });
            return Ok(Some(0));
        }

        // P2-95: filtering enabled with nothing to load must fail closed, not
        // advertise an empty `Ready` snapshot. Custom rules count as a source
        // when at least one non-blank entry is configured.
        let has_global_source = config.lists.iter().any(|list| list.enabled)
            || config
                .custom_rules
                .iter()
                .any(|rule| !rule.trim().is_empty());
        // A group custom rule is only an alternative source when there is no
        // configured global source at all. It must never mask a global list
        // that was configured but failed/returned nothing.
        let group_hint = self.group_sources_configured.load(Ordering::Acquire);
        let has_source = has_global_source || group_hint;
        if !has_source {
            let prev_count = self.snapshot.load().rule_count;
            if prev_count > 0 && !self.snapshot.load().unavailable {
                // A configured-but-now-empty source set must not replace the
                // last good snapshot, but it must not look healthy either:
                // publish Failed (the snapshot stays usable, so `unavailable`
                // remains false) and reject the config so a live apply does
                // not commit a zero-source configuration.
                let reason = "filtering.enabled has no configured sources; retained the previous filter snapshot".to_string();
                error!("{reason}");
                // Preserve the retained snapshot's observable status fields
                // (loaded/failed/degraded lists, dropped-class counters and
                // compile time); only the lifecycle state and error change.
                let mut status = self.status();
                status.state = FilterState::Failed;
                status.rule_count = prev_count;
                status.last_error = Some(reason);
                status.unavailable = false;
                self.set_status(status);
                return Err(FilterError::NoSourcesConfigured);
            }
            self.snapshot.store(Arc::new(FilterSnapshot::unavailable()));
            sito_core::sync::lock_or_recover(&self.list_rules).clear();
            self.set_status(FilterStatus {
                state: FilterState::Failed,
                rule_count: 0,
                unavailable: true,
                last_error: Some(
                    "filtering.enabled is true but no filter lists or custom rules are configured"
                        .to_string(),
                ),
                ..FilterStatus::default()
            });
            return Err(FilterError::NoSourcesConfigured);
        }

        Ok(None)
    }

    /// Fetches enabled lists (network or disk cache) for this reload cycle.
    async fn fetch_reload_lists(
        &self,
        config: &FilteringConfig,
        only_lists: Option<&[String]>,
    ) -> (Vec<(String, String)>, Vec<String>, Vec<String>) {
        let mut list_contents = Vec::new();
        // Build the downloader from the configuration being applied instead of
        // caching one next to `self.config`: the two would otherwise be
        // independent values that a concurrent reload could observe as a
        // mismatched pair (new cap, old downloader or vice versa).
        let downloader = ListDownloader::new(DEFAULT_DOWNLOAD_TIMEOUT, config.max_list_bytes)
            .with_allow_empty(config.allow_empty_list);
        // Names of lists whose content was fetched (from network or cache) in
        // this cycle. `loaded_lists` is derived from this set minus
        // `failed_lists` so a list can never be counted as both.
        let mut fetched_lists = Vec::new();
        let mut failed_lists = Vec::new();

        for list in &config.lists {
            if !list.enabled {
                continue;
            }

            if let Some(only) = only_lists
                && !only.iter().any(|name| name == &list.name)
            {
                continue;
            }

            match downloader
                .fetch_or_cached(&list.name, &list.url, &self.data_dir)
                .await
            {
                Ok(content) => {
                    fetched_lists.push(list.name.clone());
                    list_contents.push((list.name.clone(), content));
                }
                Err(e) => {
                    failed_lists.push(list.name.clone());
                    warn!(
                        list = %list.name,
                        url = %list.url,
                        error = %e,
                        "Failed to load blocklist from network or disk cache; skipping list"
                    );
                }
            }
        }

        (list_contents, fetched_lists, failed_lists)
    }

    /// Compiles the fetched lists off the async runtime and records a failed
    /// compilation in the observable status.
    async fn compile_reload_lists(
        &self,
        config: &FilteringConfig,
        list_contents: Vec<(String, String)>,
        fetched_lists: &[String],
        failed_lists: &[String],
    ) -> Result<CompiledReload, FilterError> {
        let custom_rules = config.custom_rules.clone();
        let max_rules = config.max_rules;
        let max_list_bytes = config.max_list_bytes;
        let allow_empty = config.allow_empty_list;
        let base_rules = sito_core::sync::lock_or_recover(&self.list_rules).clone();
        let enabled_names: FnvHashSet<String> = config
            .lists
            .iter()
            .filter(|l| l.enabled)
            .map(|l| l.name.clone())
            .collect();

        // Compile rules in blocking task to avoid stalling the tokio async runtime
        let compile_started = Instant::now();
        let regex_compile_budget_ms = config.regex_compile_budget_ms;

        let join_result = tokio::task::spawn_blocking(move || {
            compile_reload_rules(
                custom_rules,
                max_rules,
                max_list_bytes,
                allow_empty,
                base_rules,
                enabled_names,
                list_contents,
                regex_compile_budget_ms,
            )
        })
        .await
        .map_err(|e| {
            error!("Filter rule compilation task failed: {e}");
            self.observe_compile(compile_started.elapsed());
            self.set_status(FilterStatus {
                state: FilterState::Failed,
                rule_count: self.snapshot.load().rule_count,
                loaded_lists: count_loaded_lists(fetched_lists, failed_lists),
                failed_lists: failed_lists.to_vec(),
                last_error: Some(e.to_string()),
                last_compile_ms: Some(
                    u64::try_from(compile_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                ),
                unavailable: self.snapshot.load().unavailable,
                ..FilterStatus::default()
            });
            FilterError::CompileTaskFailed(e.to_string())
        })?;

        self.observe_compile(compile_started.elapsed());
        let compile_elapsed_ms =
            u64::try_from(compile_started.elapsed().as_millis()).unwrap_or(u64::MAX);

        match join_result {
            Ok((snapshot, count, list_rules, rejected_lists)) => Ok(CompiledReload {
                snapshot,
                count,
                list_rules,
                rejected_lists,
                compile_elapsed_ms,
            }),
            Err(error) => {
                self.record_compile_rejection(
                    &error,
                    fetched_lists,
                    failed_lists,
                    compile_elapsed_ms,
                );
                Err(error)
            }
        }
    }

    /// Records a rejected (over-budget/failed) reload without replacing the
    /// previous snapshot.
    fn record_compile_rejection(
        &self,
        e: &FilterError,
        fetched_lists: &[String],
        failed_lists: &[String],
        compile_elapsed_ms: u64,
    ) {
        let prev_count = self.snapshot.load().rule_count;
        error!(error = %e, "Rejecting filter reload");
        let loaded_lists = count_loaded_lists(fetched_lists, failed_lists);
        if prev_count == 0 {
            // Fail closed rather than advertise an over-limit set as
            // active or silently allow traffic.
            self.snapshot.store(Arc::new(FilterSnapshot::unavailable()));
            self.set_status(FilterStatus {
                state: FilterState::Failed,
                rule_count: 0,
                loaded_lists,
                failed_lists: failed_lists.to_vec(),
                last_error: Some(e.to_string()),
                last_compile_ms: Some(compile_elapsed_ms),
                unavailable: true,
                ..FilterStatus::default()
            });
        } else {
            self.set_status(FilterStatus {
                state: FilterState::Ready,
                rule_count: prev_count,
                loaded_lists,
                failed_lists: failed_lists.to_vec(),
                last_error: Some(e.to_string()),
                last_compile_ms: Some(compile_elapsed_ms),
                unavailable: false,
                dropped_regex_patterns: self.snapshot.load().dropped_regex_patterns,
                ..FilterStatus::default()
            });
        }
    }

    /// Validates the compiled rule count. Returns `Some(previous_count)` when
    /// the drop guard deliberately keeps the previous snapshot.
    #[allow(clippy::too_many_arguments)]
    fn validate_reload_count(
        &self,
        config: &FilteringConfig,
        count: usize,
        prev_count: usize,
        failed_lists: &[String],
        loaded_lists: usize,
        compile_elapsed_ms: u64,
        has_global_source: bool,
        group_hint: bool,
        apply_drop_guard: bool,
    ) -> Result<Option<usize>, FilterError> {
        // A group-only configuration legitimately has zero global rules while
        // the group snapshots hold the effective rules. Bypass the empty/failed
        // branches only when:
        //   * there is no configured global source at all, and
        //   * at least one group custom rule actually parses/compiles.
        // A failed global list always fails closed here, even when a group
        // rule exists, so non-group clients are never silently unfiltered.
        let group_only_sources =
            !has_global_source && group_hint && self.group_custom_rules_compile();
        // A raw group hint that did not compile is not a usable source. This
        // must fail closed even when `allow_empty_list = true`: that option
        // only permits an *intentional* empty global source set, never a
        // configured-but-unparseable group-only configuration.
        let group_only_unusable = !has_global_source && group_hint && !group_only_sources;
        if count == 0 && !group_only_sources && (!config.allow_empty_list || group_only_unusable) {
            // No usable rules were produced. This covers an empty/HTML/zero
            // list on a reload as well as a comment-only source: never publish
            // an empty snapshot that would silently disable filtering.
            if prev_count > 0 {
                let reason = if failed_lists.is_empty() {
                    "new configuration yielded no rules; retained the previous filter snapshot"
                        .to_string()
                } else {
                    format!(
                        "new configuration yielded no usable rules ({} list(s) failed); retained the previous filter snapshot: {}",
                        failed_lists.len(),
                        failed_lists.join(", ")
                    )
                };
                warn!("{reason}");
                self.set_status(FilterStatus {
                    state: FilterState::Ready,
                    rule_count: prev_count,
                    loaded_lists,
                    failed_lists: failed_lists.to_vec(),
                    last_error: Some(reason.clone()),
                    last_compile_ms: Some(compile_elapsed_ms),
                    unavailable: false,
                    dropped_regex_patterns: self.snapshot.load().dropped_regex_patterns,
                    ..FilterStatus::default()
                });
                return Err(FilterError::NoUsableRules { details: reason });
            }
            let details = if failed_lists.is_empty() {
                "configured filter sources yielded no usable rules".to_string()
            } else {
                format!(
                    "all {} configured filter source(s) failed to load or yielded no rules: {}",
                    failed_lists.len(),
                    failed_lists.join(", ")
                )
            };
            error!(details = %details, "Refusing to advertise an enabled empty filter snapshot");
            self.snapshot.store(Arc::new(FilterSnapshot::unavailable()));
            self.set_status(FilterStatus {
                state: FilterState::Failed,
                rule_count: 0,
                loaded_lists,
                failed_lists: failed_lists.to_vec(),
                last_error: Some(details.clone()),
                last_compile_ms: Some(compile_elapsed_ms),
                unavailable: true,
                ..FilterStatus::default()
            });
            return Err(FilterError::NoUsableRules { details });
        }

        if apply_drop_guard
            && prev_count > 0
            && (count == 0 || count.saturating_mul(2) < prev_count)
        {
            // retain the previous snapshot; the reload failure is observable
            // through the status instead of being silently swallowed.
            let reason = format!(
                "rule count dropped from {prev_count} to {count} (>50%); retained previous snapshot"
            );
            warn!(
                previous_count = prev_count,
                new_count = count,
                "Rule count dropped by >50%, retaining previous filter snapshot to protect against corrupted source"
            );
            self.set_status(FilterStatus {
                state: FilterState::Ready,
                rule_count: prev_count,
                loaded_lists,
                failed_lists: failed_lists.to_vec(),
                last_error: Some(reason),
                last_compile_ms: Some(compile_elapsed_ms),
                unavailable: false,
                dropped_regex_patterns: self.snapshot.load().dropped_regex_patterns,
                ..FilterStatus::default()
            });
            return Ok(Some(prev_count));
        }

        if count == 0 && !failed_lists.is_empty() && prev_count == 0 && !group_only_sources {
            let details = format!(
                "all {} configured filter source(s) failed to load: {}",
                failed_lists.len(),
                failed_lists.join(", ")
            );
            error!(
                lists = ?failed_lists,
                "No filter rules could be loaded; refusing to advertise an enabled empty snapshot"
            );
            // Keep the engine explicitly unavailable so `fail_closed` answers
            // SERVFAIL instead of allow-all. Previously the previous snapshot
            // (e.g. the empty one stored while filtering was disabled) was kept
            // with `unavailable = false`, silently disabling fail-closed after
            // a disabled -> enabled transition.
            self.snapshot.store(Arc::new(FilterSnapshot::unavailable()));
            self.set_status(FilterStatus {
                state: FilterState::Failed,
                rule_count: 0,
                loaded_lists,
                failed_lists: failed_lists.to_vec(),
                last_error: Some(details.clone()),
                last_compile_ms: Some(compile_elapsed_ms),
                unavailable: true,
                ..FilterStatus::default()
            });
            return Err(FilterError::NoSourcesLoaded {
                failed: failed_lists.len(),
                details,
            });
        }

        Ok(None)
    }

    /// Spawns a background task that refreshes blocklists according to their
    /// per-list `refresh_hours` (falling back to `refresh_interval_hours`).
    pub fn spawn_refresh_task(
        self: Arc<Self>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut next_due: FnvHashMap<String, Instant> = FnvHashMap::default();
            loop {
                let (sleep_for, due) = {
                    let config = self.config.load_full();
                    refresh_schedule(&config, &mut next_due, Instant::now())
                };

                if due.is_empty() {
                    tokio::select! {
                        () = tokio::time::sleep(sleep_for) => {}
                        res = shutdown_rx.changed() => {
                            if res.is_err() || *shutdown_rx.borrow() {
                                info!("Filter refresh task shutting down");
                                break;
                            }
                        }
                    }
                    continue;
                }

                info!(lists = ?due, "Running scheduled blocklist refresh...");
                if let Err(err) = self.reload_lists(&due).await {
                    warn!(error = %err, "Scheduled blocklist refresh failed");
                }

                let config = self.config.load_full();
                let global =
                    Duration::from_secs(config.refresh_interval_hours.max(1).saturating_mul(3600));
                let now = Instant::now();
                for name in &due {
                    let interval = config
                        .lists
                        .iter()
                        .find(|l| &l.name == name)
                        .and_then(|l| l.refresh_hours)
                        .map_or(global, |hours| {
                            Duration::from_secs(hours.max(1).saturating_mul(3600))
                        });
                    next_due.insert(name.clone(), now + interval);
                }
            }
        })
    }

    /// Evaluates a domain query against only `$important` rules.
    pub fn evaluate_important(
        &self,
        qname: &Name,
        qtype: RecordType,
        client: &ClientContext,
    ) -> Option<Verdict> {
        let config = self.config.load();
        if !config.enabled {
            return None;
        }
        let snapshot = self.snapshot.load();
        if config.fail_closed && snapshot.unavailable {
            return Some(Verdict::Block(BlockReason::FilterUnavailable));
        }

        let normalized = normalized_query_domain(qname);
        snapshot.evaluate_important(&normalized, qtype, client)
    }

    /// Evaluates a domain query against standard filter rules.
    pub fn evaluate_standard(
        &self,
        qname: &Name,
        qtype: RecordType,
        client: &ClientContext,
    ) -> Verdict {
        let config = self.config.load();
        if !config.enabled {
            return Verdict::Allow(None);
        }
        let snapshot = self.snapshot.load();
        if config.fail_closed && snapshot.unavailable {
            return Verdict::Block(BlockReason::FilterUnavailable);
        }

        let normalized = normalized_query_domain(qname);
        snapshot.evaluate_standard(&normalized, qtype, client)
    }
}
