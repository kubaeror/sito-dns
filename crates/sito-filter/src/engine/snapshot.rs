//! Compiled filter snapshots and rule evaluation helpers.

#[allow(clippy::wildcard_imports)]
use super::*;

impl FilterSnapshot {
    /// Placeholder snapshot used before the first successful compile or after
    /// a failed initial load. Never carries rules.
    #[must_use]
    pub fn unavailable() -> Self {
        Self {
            unavailable: true,
            ..Self::default()
        }
    }

    /// Compiles a slice of parsed rules into high-throughput lookup structures,
    /// resolving `$badfilter` deactivations and deduplicating identical rules.
    pub fn compile(parsed_rules: Vec<Rule>) -> Self {
        match Self::compile_inner(parsed_rules, None) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                // A `None` budget cannot expire; keep a logic error observable
                // and fail closed instead of panicking the reload worker.
                error!(
                    elapsed_ms = e.elapsed_ms,
                    limit_ms = e.limit_ms,
                    "Filter compilation aborted without a configured budget"
                );
                Self::unavailable()
            }
        }
    }

    /// Compiles rules while honouring an optional [`CompileBudget`].
    ///
    /// Returns [`CompileBudgetExceeded`] when the regex compiler runs past the
    /// budget, allowing callers to keep the previous snapshot.
    pub fn compile_with_budget(
        parsed_rules: Vec<Rule>,
        budget: Option<&CompileBudget>,
    ) -> Result<Self, CompileBudgetExceeded> {
        Self::compile_inner(parsed_rules, budget)
    }

    pub(super) fn compile_inner(
        parsed_rules: Vec<Rule>,
        budget: Option<&CompileBudget>,
    ) -> Result<Self, CompileBudgetExceeded> {
        let mut interner = LabelInterner::new();
        let mut allow_builder = RuleSetBuilder::new();
        let mut block_builder = RuleSetBuilder::new();

        // 1. Identify all rules marked with $badfilter
        let mut badfilter_set = FnvHashSet::default();
        for rule in &parsed_rules {
            if rule.modifiers.badfilter {
                badfilter_set.insert(rule.canonical.clone());
            }
        }

        // 2. Filter out badfiltered rules and deduplicate active rules by canonical form
        let mut seen_canonical = FnvHashSet::default();
        let mut active_rules = Vec::new();

        for rule in parsed_rules {
            if rule.modifiers.badfilter {
                continue;
            }
            if badfilter_set.contains(&rule.canonical) {
                continue;
            }
            if !seen_canonical.insert(rule.canonical.clone()) {
                continue;
            }

            let rule_id = active_rules.len() as u32;

            match (&rule.kind, &rule.pattern) {
                (RuleKind::Allow, Pattern::Exact(dom)) => {
                    allow_builder.add_exact(dom.clone(), rule_id);
                }
                (RuleKind::Allow, Pattern::Domain(dom)) => {
                    allow_builder.add_domain(dom.clone(), rule_id);
                }
                (RuleKind::Allow, Pattern::Prefix(p)) => {
                    allow_builder.add_prefix(p.clone(), rule_id);
                }
                (RuleKind::Allow, Pattern::Substring(sub)) => {
                    allow_builder.add_substring(sub.clone(), rule_id);
                }
                (RuleKind::Allow, Pattern::Wildcard(w)) => {
                    allow_builder.add_wildcard(w, rule_id);
                }
                (RuleKind::Allow, Pattern::Regex(r)) => {
                    allow_builder.add_regex(r.clone(), rule_id);
                }

                (RuleKind::Block, Pattern::Exact(dom)) => {
                    block_builder.add_exact(dom.clone(), rule_id);
                }
                (RuleKind::Block, Pattern::Domain(dom)) => {
                    block_builder.add_domain(dom.clone(), rule_id);
                }
                (RuleKind::Block, Pattern::Prefix(p)) => {
                    block_builder.add_prefix(p.clone(), rule_id);
                }
                (RuleKind::Block, Pattern::Substring(sub)) => {
                    block_builder.add_substring(sub.clone(), rule_id);
                }
                (RuleKind::Block, Pattern::Wildcard(w)) => {
                    block_builder.add_wildcard(w, rule_id);
                }
                (RuleKind::Block, Pattern::Regex(r)) => {
                    block_builder.add_regex(r.clone(), rule_id);
                }
            }

            active_rules.push(rule);
        }

        let allowlist = allow_builder.build_with_budget(&mut interner, budget)?;
        let blocklist = block_builder.build_with_budget(&mut interner, budget)?;
        let rule_count = active_rules.len();
        let dropped_regex_patterns =
            allowlist.dropped_regex_patterns + blocklist.dropped_regex_patterns;

        Ok(Self {
            interner,
            allowlist,
            blocklist,
            rules: active_rules,
            rule_count,
            unavailable: false,
            dropped_regex_patterns,
        })
    }

    /// Evaluates a domain against only `$important` rules using pre-collected candidates (Stages 1 and 2).
    pub fn evaluate_important_candidates(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        allow_candidates: &[u32],
        block_candidates: &[u32],
    ) -> Option<Verdict> {
        // Stage 1: Important Allowlist (@@...$important)
        for &rule_id in allow_candidates {
            let rule = &self.rules[rule_id as usize];
            if !rule.modifiers.important {
                continue;
            }
            // An exception carrying `$dnsrewrite` cancels a rewrite; it is not
            // an allow verdict for ordinary block rules.
            if rule.modifiers.dnsrewrite.is_some() {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client
                && !client_filter.matches(client)
            {
                continue;
            }
            // `@@...$denyallow=a|b` is an exception for everything *except*
            // a/b; it must not allow a denyallow match.
            if rule.modifiers.denyallow_matches(domain) {
                continue;
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype
                && !dnstype_filter.matches(qtype)
            {
                continue;
            }
            let rule_ref = RuleRef::new(&rule.raw).with_source(&rule.source, rule.line as usize);
            return Some(Verdict::Allow(Some(rule_ref)));
        }

        // Stage 2: Important Blocklist (...$important)
        for &rule_id in block_candidates {
            let rule = &self.rules[rule_id as usize];
            if !rule.modifiers.important {
                continue;
            }
            if rule.modifiers.denyallow_matches(domain) {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client
                && !client_filter.matches(client)
            {
                continue;
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype
                && !dnstype_filter.matches(qtype)
            {
                continue;
            }
            if let Some(rewrite) = &rule.modifiers.dnsrewrite {
                return Some(Verdict::Rewrite(RewriteAction::DnsRewrite {
                    rcode: rewrite.rcode.clone(),
                    rtype: rewrite.rtype.clone(),
                    value: rewrite.value.clone(),
                }));
            }
            let rule_ref = RuleRef::new(&rule.raw).with_source(&rule.source, rule.line as usize);
            return Some(Verdict::Block(BlockReason::Rule(rule_ref)));
        }

        None
    }

    /// Evaluates a domain against standard filter rules using pre-collected candidates (Stages 3 and 4).
    pub fn evaluate_standard_candidates(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        allow_candidates: &[u32],
        block_candidates: &[u32],
    ) -> Verdict {
        if let Some(allow) =
            self.evaluate_standard_allow_candidates(domain, qtype, client, allow_candidates)
        {
            return allow;
        }
        self.evaluate_standard_block_candidates(domain, qtype, client, block_candidates)
    }

    /// Stage 3 only: the standard allowlist (`@@...`, non-important).
    pub fn evaluate_standard_allow_candidates(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        allow_candidates: &[u32],
    ) -> Option<Verdict> {
        for &rule_id in allow_candidates {
            let rule = &self.rules[rule_id as usize];
            if rule.modifiers.important {
                continue;
            }
            // `@@...$dnsrewrite` is a rewrite cancellation, never an allow.
            if rule.modifiers.dnsrewrite.is_some() {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client
                && !client_filter.matches(client)
            {
                continue;
            }
            // AdGuard `@@*$denyallow=com|net` allows everything *except* the
            // listed domains: an exception must not apply when the queried
            // domain matches denyallow.
            if rule.modifiers.denyallow_matches(domain) {
                continue;
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype
                && !dnstype_filter.matches(qtype)
            {
                continue;
            }
            let rule_ref = RuleRef::new(&rule.raw).with_source(&rule.source, rule.line as usize);
            return Some(Verdict::Allow(Some(rule_ref)));
        }
        None
    }

    /// Stage 4 only: the standard blocklist (`$dnsrewrite` included).
    pub fn evaluate_standard_block_candidates(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        block_candidates: &[u32],
    ) -> Verdict {
        for &rule_id in block_candidates {
            let rule = &self.rules[rule_id as usize];
            if rule.modifiers.important {
                continue;
            }
            if rule.modifiers.denyallow_matches(domain) {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client
                && !client_filter.matches(client)
            {
                continue;
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype
                && !dnstype_filter.matches(qtype)
            {
                continue;
            }
            if let Some(rewrite) = &rule.modifiers.dnsrewrite {
                return Verdict::Rewrite(RewriteAction::DnsRewrite {
                    rcode: rewrite.rcode.clone(),
                    rtype: rewrite.rtype.clone(),
                    value: rewrite.value.clone(),
                });
            }
            let rule_ref = RuleRef::new(&rule.raw).with_source(&rule.source, rule.line as usize);
            return Verdict::Block(BlockReason::Rule(rule_ref));
        }

        Verdict::Allow(None)
    }

    /// Stage 4 only: returns true when any matching standard block rule applies,
    /// ignoring `$dnsrewrite` rules.
    ///
    /// [`Self::evaluate_standard_block_candidates`] returns the first matching
    /// rule, so a `$dnsrewrite` that appears before a block in candidate order
    /// hides the block. Callers that cannot apply a rewrite (for example the
    /// CNAME-target re-check) use this to detect a block independently of the
    /// rewrite verdict.
    pub fn standard_block_candidates_contain_block(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        block_candidates: &[u32],
    ) -> bool {
        for &rule_id in block_candidates {
            let rule = &self.rules[rule_id as usize];
            if rule.modifiers.important {
                continue;
            }
            if rule.modifiers.denyallow_matches(domain) {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client
                && !client_filter.matches(client)
            {
                continue;
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype
                && !dnstype_filter.matches(qtype)
            {
                continue;
            }
            if rule.modifiers.dnsrewrite.is_some() {
                continue;
            }
            return true;
        }

        false
    }

    /// Stage 2 only: returns true when any matching `$important` block rule
    /// applies, ignoring `$dnsrewrite` rules.
    ///
    /// [`Self::evaluate_important_candidates`] returns the first matching
    /// important rule, so an important `$dnsrewrite` that appears before an
    /// important block in candidate order hides the block. Callers that cannot
    /// apply a rewrite (for example the CNAME-target re-check) use this to
    /// detect an important block independently of the rewrite verdict.
    pub fn important_block_candidates_contain_block(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        block_candidates: &[u32],
    ) -> bool {
        for &rule_id in block_candidates {
            let rule = &self.rules[rule_id as usize];
            if !rule.modifiers.important {
                continue;
            }
            if rule.modifiers.denyallow_matches(domain) {
                continue;
            }
            if let Some(client_filter) = &rule.modifiers.client
                && !client_filter.matches(client)
            {
                continue;
            }
            if let Some(dnstype_filter) = &rule.modifiers.dnstype
                && !dnstype_filter.matches(qtype)
            {
                continue;
            }
            if rule.modifiers.dnsrewrite.is_some() {
                continue;
            }
            return true;
        }

        false
    }

    /// Evaluates a domain against only `$important` rules (Stages 1 and 2).
    /// Returns `Some(verdict)` if an `$important` rule matched, or `None` if no `$important` rule applied.
    pub fn evaluate_important(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
    ) -> Option<Verdict> {
        let mut allow_candidates = Vec::new();
        self.allowlist
            .collect_candidates(domain, &self.interner, &mut allow_candidates);

        let mut block_candidates = Vec::new();
        self.blocklist
            .collect_candidates(domain, &self.interner, &mut block_candidates);

        self.evaluate_important_candidates(
            domain,
            qtype,
            client,
            &allow_candidates,
            &block_candidates,
        )
    }

    /// Evaluates a domain against standard filter rules (Stages 3 and 4).
    pub fn evaluate_standard(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
    ) -> Verdict {
        let mut allow_candidates = Vec::new();
        self.allowlist
            .collect_candidates(domain, &self.interner, &mut allow_candidates);

        let mut block_candidates = Vec::new();
        self.blocklist
            .collect_candidates(domain, &self.interner, &mut block_candidates);

        self.evaluate_standard_candidates(
            domain,
            qtype,
            client,
            &allow_candidates,
            &block_candidates,
        )
    }

    /// Evaluates a domain against the compiled snapshot following section 4.3 precedence.
    /// Collects rule candidates once and passes them through both passes on the hot path.
    pub fn evaluate(&self, domain: &str, qtype: RecordType, client: &ClientContext) -> Verdict {
        let mut allow_candidates = Vec::new();
        self.allowlist
            .collect_candidates(domain, &self.interner, &mut allow_candidates);

        let mut block_candidates = Vec::new();
        self.blocklist
            .collect_candidates(domain, &self.interner, &mut block_candidates);

        if let Some(verdict) = self.evaluate_important_candidates(
            domain,
            qtype,
            client,
            &allow_candidates,
            &block_candidates,
        ) {
            return verdict;
        }

        self.evaluate_standard_candidates(
            domain,
            qtype,
            client,
            &allow_candidates,
            &block_candidates,
        )
    }

    /// Collects every `$dnsrewrite` rule from the matching `$important` or
    /// standard block candidates.
    ///
    /// AdGuard returns *all* A/AAAA values contributed by matching rewrite
    /// rules, so the caller must aggregate the whole list instead of using only
    /// the first verdict. `important` selects the precedence tier.
    pub fn collect_rewrite_rules(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        block_candidates: &[u32],
        important: bool,
    ) -> Vec<DnsRewriteRule> {
        let mut rules = Vec::new();
        for &rule_id in block_candidates {
            let rule = &self.rules[rule_id as usize];
            if rule.modifiers.important != important {
                continue;
            }
            if !modifier_scope_matches(rule, domain, qtype, client) {
                continue;
            }
            if let Some(rewrite) = &rule.modifiers.dnsrewrite {
                rules.push(rewrite.clone());
            }
        }
        rules
    }

    /// Collects the `@@...$dnsrewrite` exception rules that cancel rewrites.
    ///
    /// A bare exception cancels every rewrite for the owner; one with a value
    /// cancels only the identical rewrite (AdGuard semantics).
    pub fn collect_rewrite_cancellations(
        &self,
        domain: &str,
        qtype: RecordType,
        client: &ClientContext,
        allow_candidates: &[u32],
        important: bool,
    ) -> Vec<DnsRewriteRule> {
        let mut cancellations = Vec::new();
        for &rule_id in allow_candidates {
            let rule = &self.rules[rule_id as usize];
            if rule.modifiers.important != important {
                continue;
            }
            if !modifier_scope_matches(rule, domain, qtype, client) {
                continue;
            }
            if let Some(rewrite) = &rule.modifiers.dnsrewrite {
                cancellations.push(rewrite.clone());
            }
        }
        cancellations
    }
}
