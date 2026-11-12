> **Historical document — not evidence.** This document records the state at
> its original commit and is kept for context only. Historical audits and plans
> are leads; verify every claim against the current code and tests. Current
> references: [2.0 migration guide](2.0-migration.md),
> [config v2](config-v2.md), [2.0 public API diff](2.0-public-api-diff.md),
> [P0/P1 test evidence](audit6-test-matrix.md) and the
> [historical/current documentation index](history/README.md).

# Audit 6 — Prior Claim Matrix (Appendix C)

This is Appendix C of the [audit 6 remediation plan](audit6-followup-plan.md).
Prior audits, release notes, and changelog entries are leads, not evidence.
Verdicts below were source-verified against HEAD `acccdc4` (v1.9.3) during the
audit 6 review. The 1.9.4 status column records what the Phase 0 safety gate
changed; see [audit6.md](audit6.md) and the
[1.9.4 release notes](release-notes-1.9.4.md) for the current record.

| Claim | Source | Verdict at v1.9.3 | Status in 1.9.4 | Evidence |
|---|---|---|---|---|
| Overall readiness ~8/10 after audit 5 | [docs/audit5.md](audit5.md), “Production-readiness snapshot” | **False** | **Still false as an 8/10 claim.** Phase 0 targets ~6/10; the 2.0 refactor remains. | P0 ACME/DNSSEC and P1 HA/API/transport gaps existed at v1.9.3. |
| DNSSEC chain/denial fixed | Audits 3/4/5 | **Partial** | **Fixed for the audited gaps.** | Parent-side denial, junk-RRSIG probing, unsigned CNAME, wildcard, policy generation, and a 5 s deadline are covered by regression tests. |
| HA state/replication fixed | Audits 4/5 | **Partial** | **Fixed for the audited gaps.** | Heartbeat deadline, config-digest drift, publish outcomes, per-slave divergence, signing-key identity, per-IP admission. The 2.0 session model still owns local-field editability. |
| Rate limiting shared per-IP | [docs/audit5.md](audit5.md), “P1 — high” (P1-11) | **Partial** | **Improved.** | Shared limiter now keys IPv4 `/24`/IPv6 `/64`, samples LRU eviction, and admission happens before DoH/DoQ bodies; account-based budgets remain out of scope. |
| Cache flushes every filter reload | [docs/audit5.md](audit5.md), “P2 — fixed in this branch” | **False as written** | **Still overbroad.** | Config/API apply paths flush; a scheduled list reload is not a full config flush. Filtering runs before cache, so the bypass is limited. |
| `/metrics` unauthenticated | [docs/audit.md](audit.md), section 11 | **False/outdated** | **Docs corrected.** | `web.metrics_auth` defaults `true`; the handler requires a Viewer+ bearer token or session. |
| TOTP backup codes Argon2id | [docs/security-audit.md](security-audit.md), section 1 | **False** | **Docs corrected.** | Backup codes use BLAKE3 `b3:` digests; legacy Argon2 hashes are refused. |
| Signed archives always verified by installer | [docs/security-audit.md](security-audit.md), section 1 | **False** | **True in 1.9.4.** | `SITO_REQUIRE_SIGNATURE` defaults to `1`; missing cosign/`.sig`/`.pem` fails closed unless explicitly opted out. |
| Fuzz harness exists/nightly fuzz works | [docs/audit5.md](audit5.md), P1-12; release notes | **False at audit HEAD (`acccdc4`)** | **Docs corrected; harness remains removed at current HEAD.** | The v1.9.3 tag still contained `fuzz/` and `nightly-fuzz.yml`; the post-tag CI rework (`d114143`) removed them before the audit HEAD. Release-note `fuzz/Cargo.toml` commands are marked v1.9.3-and-earlier historical. |
| Config auto-migrations | [docs/configuration-reference.md](configuration-reference.md), section 1 | **False** | **Docs corrected.** | Only `config_version = 1` is accepted; migrations are a 2.0 item. |
| `tls.cert` protects Web UI | [docs/configuration-reference.md](configuration-reference.md), section 6 | **False** | **Docs corrected.** | The admin UI is plain axum HTTP; the DNS TLS certificate secures DoT/DoH/DoQ/DoH3 only. |
| Schedules use UTC | [docs/policy-matrix.md](policy-matrix.md), section 2 | **False** | **Docs corrected.** | `clients.timezone` defaults to `"local"` (host zone, DST-aware); UTC/fixed offsets are opt-in. |
| `--no-setup` leaves `admin/adminadmin` | [docs/migration-adguard.md](migration-adguard.md), section 4 | **False** | **Docs corrected.** | On a first boot with no `config.toml`, a random password is printed once and the panel binds to loopback; with an existing config, `--no-setup` neither creates nor rotates credentials, and bootstrap login is rejected. |
| Benchmarks are v1.9 | [README.md](../README.md), feature comparison | **False** | **Docs corrected.** | Numbers are the v1.0.0 reference-hardware run in [docs/benchmarks.md](benchmarks.md). |
| Weekly CI gates performance | [docs/benchmarks.md](benchmarks.md), intro | **False** | **Docs corrected.** | `cargo bench` uploads estimates; there is no threshold or regression failure. |
| Docs/config truth pass complete | [docs/audit5.md](audit5.md), follow-ups | **Incomplete** | **Complete for 1.9.4.** | ACME/TLS/metrics/HA/API/fuzz/benchmark/config-default drifts are fixed and checked by scripts; 2.0 docs remain future work. |
| All GitHub Actions SHA-pinned | [docs/ci.md](ci.md), action pin policy | **True** | **Still true.** | Every third-party `uses:` is a full commit SHA; `scripts/test-release-workflow.sh` enforces the policy. |
| DoH body cap and redirect policy | [docs/audit5.md](audit5.md), P2 — fixed | **True per request** | **Expanded.** | 65,535-byte cap plus pre-body admission, global request cap, H2 stream cap, and absolute deadlines. |
| Docker `/etc/sito` owned by nonroot | [docs/audit5.md](audit5.md), follow-ups | **True** | **Still true.** | Dockerfile chowns `/etc/sito` to 65532; docs explain host-bind vs in-container bind. |
| Per-archive `.sha256` published | [docs/audit5.md](audit5.md), follow-ups | **True** | **Still true.** | Real v1.9.3 assets contain `.sha256`/`.sig`/`.pem`; 1.9.4 keeps the same release layout. |
