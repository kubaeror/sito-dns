# Historical documentation

This directory explains how historical audit and planning documents relate to
the current documentation. The files themselves stay where they were; moving
them would churn links without improving their status.

## The rule: historical documents are leads, not evidence

An audit, follow-up plan, release note or changelog entry records what its
author believed at a particular commit. It may be right, partially right or
wrong about the current tree. **Do not cite a historical document as proof of
current behavior.**

To establish what is true now:

1. Read the implementation and the tests at `HEAD`.
2. Use the current reference documents below for the operator-facing contract.
3. Run the named check/test for the claim. The
   [P0/P1 test evidence matrix](../audit6-test-matrix.md) maps findings to named
   tests and commands; the [best-effort allowlist](../audit6-best-effort.md)
   maps intentional error-swallowing sites to reviewed reasons.
4. If a historical claim matters, re-verify it and record the result in the
   current evidence document rather than editing the historical record to look
   correct.

The [audit 6 claim matrix](../audit6-claim-matrix.md) is the historical
truth-matrix snapshot: it records which prior claims were true or false at the
audited revision and what 1.9.4 changed. It is useful context, but the code and
tests at `HEAD` remain authoritative.

## Current reference documents

Start here:

- [2.0 migration guide](../2.0-migration.md) — upgrade steps, breaking-change
  IDs and the Phase 1/Phase 2 boundary.
- [Config v2](../config-v2.md) — schema freeze, unknown-key policy, migration
  report and restart-only matrix.
- [2.0 public API diff](../2.0-public-api-diff.md) — source-level changes and
  the stable breaking-change IDs.
- [Configuration reference](../configuration-reference.md) — every typed and
  legacy key, defaults and hot-reload/restart behavior.
- [HA runbook](../runbook-ha.md) — replication, readiness, promotion and
  certificate rotation.
- [Security review](../security-audit.md) — implemented controls and accepted
  limitations.
- [P0/P1 test evidence](../audit6-test-matrix.md) and
  [reviewed best-effort error handling](../audit6-best-effort.md) — the
  regression evidence behind the safety claims.
- [CI and release workflows](../ci.md) and
  [release verification](../release-verification.md) — gates, fuzz, benchmarks
  and release evidence.
- [Test harness](../test-harness.md) — deterministic clock, ports and fixtures.
- [Installation](../installation.md), [benchmarks](../benchmarks.md) and the
  [1.9.5 release notes](../release-notes-1.9.5.md) — stable-line operational
  context.

## Historical documents

These carry a "Historical document — not evidence" banner:

| Document | What it records |
|---|---|
| [audit.md](../audit.md) | Original full audit and fix plan. |
| [audit2.md](../audit2.md) | v1.2.1 post-remediation audit. |
| [audit3.md](../audit3.md) | v1.4.0 full audit. |
| [audit3-followup-plan.md](../audit3-followup-plan.md) | Deferred Audit 3 work plan. |
| [audit4-followup-plan.md](../audit4-followup-plan.md) | v1.6.0 remediation plan. *(There is no separate `audit4.md` in this tree.)* |
| [audit5.md](../audit5.md) | Independent v1.6.0 audit. |
| [audit6.md](../audit6.md) | 2.0 readiness audit at v1.9.3 and the Phase 0 status. |
| [audit6-claim-matrix.md](../audit6-claim-matrix.md) | Appendix C prior-claim verdicts at v1.9.3/1.9.4. |
| [audit6-followup-plan.md](../audit6-followup-plan.md) | The phased 2.0 remediation plan and target design (the source plan for Phase 1). |

The release notes for 1.9.0–1.9.5 are also point-in-time records. The current
stable line is 1.9.5; the development line on `main` is 2.0.0-alpha.1. See the
[migration guide](../2.0-migration.md) for the upgrade boundary.
