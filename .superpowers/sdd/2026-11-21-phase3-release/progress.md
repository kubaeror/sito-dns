# SDD ledger — Phase 3 release verification
Plan: /home/ubuntu/.opencode/plan/2026-11-21-phase3-release.md
Worktree: /home/ubuntu/.local/share/opencode/worktree/a49ba7/phase3
Branch: feat/2.0-phase3-release, base 67269ea (Phase 2 merged).
Approval gates: no tag/release without operator approval; 24h fuzz requires a
decision (previously deferred "Not now").
Operator decisions (2026-11-21): 24h fuzz remains deferred ("jeszcze nie
teraz"); tag is approved (2.0.0-rc.1) once the Phase 3 gates pass. Do not tag
before version bump/release notes/verification.

## COMPACT CHECKPOINT (2026-11-21)

Phase 2: COMPLETE and merged. PR #28 merged at 67269ea on main; main CI run
44951151451 success. Phase 2 final baseline 1819 all-features / 1711 default.
Old Phase 2 worktree and merged local/remote branches removed/cleaned.

Phase 3:
- Worktree: /home/ubuntu/.local/share/opencode/worktree/a49ba7/phase3
- Branch: feat/2.0-phase3-release, base 67269ea (clean except .superpowers).
- Plan: /home/ubuntu/.opencode/plan/2026-11-21-phase3-release.md (WP-3.1..3.4).
- Operator decisions: 24h fuzz DEFERRED ("jeszcze nie teraz"); tag APPROVED
  (2.0.0-rc.1) only after version bump/release notes/full Phase 3 gate.
- Running at checkpoint: `cargo test --workspace --all-features --locked` on
  phase3, log /tmp/opencode/phase3-all.log; Phase 3 gap audit subagent
  ses_e00014d16ffeS1rs6PlMxaV53o.
- Next: read audit, implement WP-3.1 (local/bench/Docker/installer; fuzz sanity,
  24h deferred), WP-3.2 migration/compat, WP-3.3 security review, WP-3.4
  version bump/release notes/rc.1 tag + release verification.
- Known Phase 3 gates: no tag before full green; 24h fuzz explicitly deferred.

## WP-3.1/3.2/3.3 audit (2026-11-21)

Key findings:
- .github/workflows/fuzz.yml emits a bare JSON array for strategy.matrix;
  GitHub rejects it ("A sequence was not expected"). All nine scheduled fuzz
  runs red, only prepare ran. Fix: wrap as {"include":[...]} and add a static
  policy test. 24h recipe (4x21600s) exceeds timeout-minutes: 360; use 5x17280s
  (or 8x10800s) and update docs.
- Bench baseline is github-ubuntu-24.04; latest green run on c417ddd. Phase 3
  candidate needs a reference-only local run + record; docs claiming a dev-host
  baseline/ inactive gate are stale.
- WP-3.2 scope resolved to the documented Phase 2 contract: SQLite is
  compatibility-only (no new schema tool / SITO_DB_AUTO_MIGRATE); /api/v1 stays
  canonical, /api/v2 and a v1 compatibility facade are explicitly absent.
  Acceptance = real 1.9.5 data-dir copy + exact 1.9.3 migration set + HA v1
  rejection evidence + /api/v2 absent test.
- WP-3.3 needs a dated review: unsafe/FFI inventory (pktinfo, updater xattrs),
  P1-1 DNAME residual acceptance, RUSTSEC-2026-0543 review, stale test names,
  SECURITY.md fuzz/bench truth, threat-model rc.1 additions.
- WP-3.4 version is still 2.0.0-alpha.1; needs bump, Cargo.lock, OpenAPI regen,
  release notes/known issues, merge to main, tag (approved), verification.
