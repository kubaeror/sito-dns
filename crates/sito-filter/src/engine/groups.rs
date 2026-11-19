//! Per-client-group rule compilation and snapshot publication.

#[allow(clippy::wildcard_imports)]
use super::*;

impl HostsFilterEngine {
    /// Whether any group defines non-blank custom rules. A `lists` reference
    /// alone is not an independent source.
    pub(super) fn has_group_custom_rules(groups: &[GroupRuleSet]) -> bool {
        groups.iter().any(|group| {
            group
                .custom_rules
                .iter()
                .any(|rule| !rule.trim().is_empty())
        })
    }

    /// Cheap dry-run used only for the group-only initial decision: does at
    /// least one group custom rule actually parse and compile to a non-empty
    /// snapshot?
    ///
    /// Comment-only, invalid-only, or over-budget group rules must not make
    /// the engine advertise an available empty snapshot. List references are
    /// ignored here because they are not independent sources; they only work
    /// when a global list of that name loaded.
    pub(super) fn group_custom_rules_compile(&self) -> bool {
        let defs = self.group_defs.load();
        if defs.is_empty() {
            return false;
        }
        let config = self.config.load();
        for def in defs.iter() {
            let mut rules = Vec::new();
            let mut over_budget = false;
            for rule_text in &def.custom_rules {
                let limits = ParseLimits::new(
                    config.max_rules.saturating_sub(rules.len()),
                    config.max_list_bytes,
                );
                if let Ok((parsed, _)) = parse_rules_with_limits(rule_text, "group", limits) {
                    rules.extend(parsed);
                } else {
                    over_budget = true;
                    break;
                }
            }
            if over_budget || rules.is_empty() || rules.len() > config.max_rules {
                continue;
            }
            if pattern_load_exceeds_limits(&rules).is_some() {
                continue;
            }
            let budget = config
                .regex_compile_budget_ms
                .map(Duration::from_millis)
                .map(CompileBudget::new);
            if FilterSnapshot::compile_with_budget(rules, budget.as_ref())
                .is_ok_and(|snapshot| snapshot.rule_count > 0)
            {
                return true;
            }
        }
        false
    }

    /// Replaces the group rule definitions and rebuilds the per-group snapshots
    /// from the currently loaded lists. Called whenever clients/group policy or
    /// blocklists are (re)loaded.
    pub fn set_group_rules(&self, groups: Vec<GroupRuleSet>) {
        // A group `lists` entry only selects a globally configured list; it is
        // not an independent source (and an unloaded/disabled global list
        // yields no rules). Only group `custom_rules` can make an otherwise
        // source-less configuration non-empty.
        let has_group_sources = Self::has_group_custom_rules(&groups);
        self.group_sources_configured
            .store(has_group_sources, Ordering::Release);
        self.group_defs.store(Arc::new(groups));
        // Capture the generation before cloning the list map. A reload that
        // completes between the clone and the rebuild must not let this
        // rebuild publish its (then stale) rules under the newer generation.
        let generation = self.list_generation.load(Ordering::SeqCst);
        let list_rules = sito_core::sync::lock_or_recover(&self.list_rules).clone();
        #[cfg(test)]
        self.run_group_rebuild_gate();
        if let Some(degraded) = self.rebuild_group_snapshots_at(&list_rules, generation) {
            self.update_group_status(degraded);
        }
    }

    /// Updates only the group portion of the published status.
    pub(super) fn update_group_status(&self, degraded: Vec<String>) {
        let mut status = self.status();
        if status.degraded_groups == degraded {
            return;
        }
        status.degraded_groups = degraded;
        self.set_status(status);
    }

    /// Returns the compiled extra rule set for `group`, if the group defines any.
    #[must_use]
    pub fn group_snapshot(&self, group: &str) -> Option<Arc<FilterSnapshot>> {
        self.group_snapshots.load().get(group).cloned()
    }

    /// Compiles one snapshot per group from the current per-list rules.
    ///
    /// Lists a group references but that are not loaded are skipped (the group
    /// still gets its custom rules) and mark it degraded. A group with
    /// configured sources but no usable rules keeps its previous snapshot and
    /// is reported degraded so it never disappears silently.
    pub(super) fn rebuild_group_snapshots(
        &self,
        list_rules: &FnvHashMap<String, Vec<Rule>>,
    ) -> Option<Vec<String>> {
        // Capture the list generation this rebuild is based on. A concurrent
        // list reload bumps the generation; publishing a snapshot compiled
        // from the older map must then be discarded.
        let generation = self.list_generation.load(Ordering::SeqCst);
        self.rebuild_group_snapshots_at(list_rules, generation)
    }

    pub(super) fn rebuild_group_snapshots_at(
        &self,
        list_rules: &FnvHashMap<String, Vec<Rule>>,
        generation: u64,
    ) -> Option<Vec<String>> {
        let defs = self.group_defs.load();
        let config = self.config.load();
        let max_rules = config.max_rules;
        let compile_budget_ms = config.regex_compile_budget_ms;
        let previous = self.group_snapshots.load();
        let mut compiled = FnvHashMap::default();
        let mut degraded_groups = Vec::new();
        for def in defs.iter() {
            // A group with configured sources must never disappear silently:
            // if none of them yields usable rules, the group is degraded.
            // A group with no configured sources is simply inactive.
            let has_sources = !def.lists.is_empty() || !def.custom_rules.is_empty();
            let mut rules = Vec::new();
            let mut degraded = false;
            for list_name in &def.lists {
                if let Some(list_rules) = list_rules.get(list_name) {
                    rules.extend(list_rules.iter().cloned());
                } else {
                    warn!(
                        group = %def.name,
                        list = %list_name,
                        "Group policy references a filter list that is not loaded; rules from it are inactive"
                    );
                    degraded = true;
                }
            }
            let source = format!("group:{}", def.name);
            for rule_text in &def.custom_rules {
                let limits =
                    ParseLimits::new(max_rules.saturating_sub(rules.len()), config.max_list_bytes);
                match parse_rules_with_limits(rule_text, &source, limits) {
                    Ok((parsed, rejected)) => {
                        if rejected > 0 {
                            warn!(
                                group = %def.name,
                                "Rejected {} invalid rule(s) in group custom_rules",
                                rejected
                            );
                        }
                        rules.extend(parsed);
                    }
                    Err(ParseError::TooManyRules { .. } | ParseError::TooManyBytes { .. }) => {
                        error!(
                            group = %def.name,
                            "Group custom_rules exceed the parsing budget; truncating group rules"
                        );
                        degraded = true;
                        break;
                    }
                }
            }
            if rules.is_empty() {
                // No usable rule from any configured source: missing or
                // unloaded lists, invalid-only custom rules, an empty list,
                // or a parse budget that consumed everything. Keep the
                // previous snapshot when one exists so the group never
                // disappears silently.
                if has_sources {
                    degraded_groups.push(def.name.clone());
                    if let Some(previous) = previous.get(&def.name) {
                        compiled.insert(def.name.clone(), Arc::clone(previous));
                    }
                }
                continue;
            }
            if rules.len() > max_rules {
                error!(
                    group = %def.name,
                    parsed = rules.len(),
                    limit = max_rules,
                    "Group filter rule set exceeds filtering.max_rules; truncating to limit"
                );
                rules.truncate(max_rules);
                degraded = true;
            }

            // Never drop a whole group on a compile-limit failure: first
            // remove only the offending class (regex/wildcard, then
            // substring/prefix) so exact/domain/custom rules still apply.
            if let Some(reason) = pattern_load_exceeds_limits(&rules) {
                error!(
                    group = %def.name,
                    reason = %reason,
                    "Group filter rule set exceeds regex compilation limits; publishing the non-regex subset"
                );
                rules.retain(|r| !matches!(r.pattern, Pattern::Regex(_) | Pattern::Wildcard(_)));
                degraded = true;
                if let Some(reason) = pattern_load_exceeds_limits(&rules) {
                    error!(
                        group = %def.name,
                        reason = %reason,
                        "Group substring/prefix load still exceeds limits; publishing only exact/domain rules"
                    );
                    rules.retain(|r| {
                        !matches!(r.pattern, Pattern::Substring(_) | Pattern::Prefix(_))
                    });
                }
            }
            if rules.is_empty() {
                // All rules were in a rejected class. Keep the previous
                // snapshot when one exists and mark the group degraded so it
                // never disappears silently.
                degraded_groups.push(def.name.clone());
                if let Some(previous) = previous.get(&def.name) {
                    compiled.insert(def.name.clone(), Arc::clone(previous));
                }
                continue;
            }
            let budget = compile_budget_ms
                .map(Duration::from_millis)
                .map(CompileBudget::new);
            match FilterSnapshot::compile_with_budget(rules.clone(), budget.as_ref()) {
                Ok(snapshot) => {
                    compiled.insert(def.name.clone(), Arc::new(snapshot));
                }
                Err(e) => {
                    error!(
                        group = %def.name,
                        elapsed_ms = e.elapsed_ms,
                        limit_ms = e.limit_ms,
                        "Group snapshot exceeded the regex compile budget; publishing the non-regex subset"
                    );
                    degraded = true;
                    rules
                        .retain(|r| !matches!(r.pattern, Pattern::Regex(_) | Pattern::Wildcard(_)));
                    if rules.is_empty() {
                        if let Some(previous) = previous.get(&def.name) {
                            compiled.insert(def.name.clone(), Arc::clone(previous));
                        }
                    } else {
                        match FilterSnapshot::compile_with_budget(rules, None) {
                            Ok(snapshot) => {
                                compiled.insert(def.name.clone(), Arc::new(snapshot));
                            }
                            Err(e) => {
                                error!(
                                    group = %def.name,
                                    elapsed_ms = e.elapsed_ms,
                                    limit_ms = e.limit_ms,
                                    "Group non-regex fallback compilation failed; retaining the previous snapshot"
                                );
                                if let Some(previous) = previous.get(&def.name) {
                                    compiled.insert(def.name.clone(), Arc::clone(previous));
                                }
                            }
                        }
                    }
                }
            }
            if degraded {
                degraded_groups.push(def.name.clone());
            }
        }

        if self.list_generation.load(Ordering::SeqCst) != generation {
            warn!(
                generation,
                "Discarding stale group snapshot rebuild; a list reload completed concurrently"
            );
            return None;
        }
        degraded_groups.sort_unstable();
        degraded_groups.dedup();
        self.group_snapshots.store(Arc::new(compiled));
        Some(degraded_groups)
    }

    /// Runs the test-only interleaving hook, if one is installed.
    #[cfg(test)]
    fn run_group_rebuild_gate(&self) {
        let gate = sito_core::sync::lock_or_recover(&self.group_rebuild_gate).take();
        if let Some(gate) = gate {
            gate();
        }
    }
}
