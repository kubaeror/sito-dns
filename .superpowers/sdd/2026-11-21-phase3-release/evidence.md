# Phase 3 evidence ledger (2026-11-21)

Base: 67269ea (Phase 2 merged to main). Branch: feat/2.0-phase3-release.

## WP-3.1

- all-features workspace on 67269ea: 1819 passed / 0 failed / 1 ignored
  (/tmp/opencode/phase3-all.log)
- default workspace on 67269ea: 1711 passed / 0 failed / 1 ignored
  (/tmp/opencode/phase3-default.log)
- fmt, clippy -D warnings, cargo deny: green on 67269ea.
- installer E2E: `bash contrib/tests/test-installer.sh` -> installer E2E OK
- compose/systemd static: OK
- release-gate unit tests: 11 cases 0 failures; release workflow policy OK;
  platform checker 7 cases 0 failures.
- fuzz workflow fix: 60 s local smoke all five targets PASS; GitHub Actions
  smoke https://github.com/kubaeror/sito-dns/actions/runs/44954171674 SUCCESS.
  24h campaign explicitly deferred by operator.
- benchmark: GitHub-hosted bench
  https://github.com/kubaeror/sito-dns/actions/runs/44954195766 SUCCESS
  (baseline github-ubuntu-24.04, tolerance 10%).
- Docker upgrade E2E `scripts/test-docker-upgrade.sh`:
  1.9.5 -> config v1->v2 (0600 backup) -> 2.0.0-rc.1 -> DNS + healthy ->
  rollback to 1.9.5 and DNS again. PASS 2026-11-21.
- release workflow now starts the attested image, asserts a local rewrite and
  Docker healthy before publishing.

## WP-3.2

- `bash scripts/test-migration-1.9.5.sh` PASS:
  real 1.9.5 data dir, rewrite, stats.db, config migrate + 0600 .v1.bak,
  2.0.0-rc.1 serves rewrite, /api/v1/status version=2.0.0-rc.1, stats
  integrity=ok with all four migrations, users/TOTP byte-identical, rollback
  1.9.5 serves and opens the additive DB.
- `test_exact_v1_9_3_schema_stays_readable_after_additive_upgrade` PASS
  (exact four v1.9.3 migration files; no new sqlx version).
- `bash scripts/test-ha-v1-compat.sh` PASS (5 rejection tests).
- `test_api_surface_has_no_v2_and_keeps_v1_status_canonical` PASS
  (/api/v2 404, /api/v1/status 401/200, OpenAPI has no v2).
- Scope: SQLite compatibility-only; /api/v1 canonical; no facade.

## WP-3.3 / WP-3.4

- Pending: security review commit; final rc.1 gate; merge to main; tag.
