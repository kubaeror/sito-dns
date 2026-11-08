# Audit 6 — Prior Claim Matrix (Appendix C)

This is Appendix C of the [audit 6 remediation plan](audit6-followup-plan.md).
Prior audits, release notes, and changelog entries are leads, not evidence.
Verdicts below were source-verified against HEAD `acccdc4` (v1.9.3) during the
audit 6 review.

| Claim | Source | Verdict | Evidence |
|---|---|---|---|
| Overall readiness ~8/10 after audit 5 | `docs/audit5.md:108-123` | **False** | P0 ACME and P0 DNSSEC denial bypass, plus P1 HA/API/transport, remain. Current 4/10. |
| DNSSEC chain/denial fixed | Audit 3/4/5 | **Partial** | Chain walk exists, but ancestor-delegation denial and fail-open paths remain. |
| HA state/replication fixed | Audit 4/5 | **Partial** | Version/term/signature work is real; no master-loss timeout, watermark hides local drift, publish can fail silently. |
| Rate limiting shared per-IP | `docs/audit5.md:40` | **Partial** | Shared limiter exists; full-address keying, arbitrary eviction, post-body checks. |
| Cache flushes every filter reload | `docs/audit5.md:46-48` | **False as written** | Config/API paths flush; scheduled `reload_lists` does not. Filtering runs before cache, so limited bypass, but claim is overbroad. |
| `/metrics` unauthenticated | `docs/audit.md:64` | **False/outdated** | `metrics_auth` defaults true; handler authenticates Viewer. |
| TOTP backup codes Argon2id | `docs/security-audit.md:22-23` | **False** | BLAKE3 `b3:` digests with rationale; legacy Argon2 hashes refused. |
| Signed archives always verified by installer | `docs/security-audit.md:31` | **False** | `SITO_REQUIRE_SIGNATURE=0` default; missing assets fall back to SHA-256. |
| Fuzz harness exists/nightly fuzz works | `docs/audit5.md:41`, release notes | **False at HEAD** | `git ls-files fuzz` empty; nightly workflow absent; post-v1.9.3 CI removed it. |
| Config auto-migrations | `docs/configuration-reference.md:18` | **False** | `config_version != 1` is rejected; no migration. |
| `tls.cert` protects Web UI | `docs/configuration-reference.md:153` | **False** | Admin UI is plain axum HTTP; DNS TLS cert is separate. |
| Schedules use UTC | `docs/policy-matrix.md:52` | **False** | `clients.timezone` defaults `"local"`. |
| `--no-setup` leaves `admin/adminadmin` | `docs/migration-adguard.md:77` | **False** | Random password generated, printed once, loopback bind; `adminadmin` rejected. |
| Benchmarks are v1.9 | `README.md:24-26` | **False** | `docs/benchmarks.md` says numbers captured at v1.0.0. |
| Weekly CI gates performance | `docs/benchmarks.md:5-9` | **False** | `cargo bench` uploads estimates; no threshold/regression failure. |
| Docs/config truth pass complete | `docs/audit5.md:96-102` | **Incomplete** | ACME/TLS/metrics/HA/API/fuzz/benchmark drifts remain. |
| All GitHub Actions SHA-pinned | `docs/ci.md:275-300` | **True** | Verified all `uses:` full SHAs. |
| DoH body cap and redirect policy | `docs/audit5.md:52` | **True per request** | 65,535-byte cap, redirects disabled; pre-body buffering/global concurrency still missing. |
| Docker `/etc/sito` owned by nonroot | `docs/audit5.md:101` | **True** | Dockerfile chowns 65532. |
| Per-archive `.sha256` published | `docs/audit5.md:102` | **True** | Real v1.9.3 assets contain `.sha256`/`.sig`/`.pem`. |
