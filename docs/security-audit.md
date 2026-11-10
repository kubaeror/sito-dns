# Security Review and Threat Model (current)

This document summarizes the **implemented** security controls and known
limitations of the current tree (1.9.x). It replaces an earlier v1.0.0/v1.2.1
audit record whose claims had drifted from the code. Point-in-time audits with
file/line evidence and remediation status live in:

* [`docs/audit6.md`](audit6.md) — current readiness audit and Phase 0 status.
* [`docs/audit5.md`](audit5.md) — independent audit of v1.6.0 (historical).
* [`docs/audit4-followup-plan.md`](audit4-followup-plan.md) — previous batch (historical).

Everything below is verifiable in the source; the referenced modules are the
implementation of record.

---

## 1. Control summary

| Domain | Control | Implementation |
|---|---|---|
| **SSRF** | Subscription schemes restricted to `http://`, `https://`, `file://`. HTTP fetches disable redirects and proxies, resolve and pin the target address, and deny loopback, RFC 1918/ULA, link-local/metadata (including CGNAT, reserved, documentation, and IPv4 embeddings via IPv4-mapped, NAT64, 6to4 and Teredo). `file://` is allowlisted to the data directory plus explicit programmatic roots, rejecting pseudo-filesystems. | `sito-filter::subscription`, `sito-core::config` |
| **ReDoS** | User regex and ABP wildcards compile to dense DFAs with hard budgets (≤ 10k patterns, ≤ 4 MiB pattern bytes, ≤ 16 KiB per pattern, ≤ 10 MiB DFA) and a bounded per-pattern fallback. Linear-time matching, no backtracking. A budget-truncated `RuleSetBuilder` result exposes `dropped_regex_patterns`, `dropped_prefix_rules`, `dropped_substring_rules` and `has_dropped_classes()`; direct callers must check them, so a partial set cannot be mistaken for a complete one. | `sito-filter::structures::compiled` |
| **Auth timing** | Argon2id ($m=64$ MiB, $t=3$, $p=4$) for passwords; constant-time comparisons (`subtle`) for API tokens, session cookies, setup tokens and TOTP codes. Login usernames/passwords are length-capped before hashing. | `sito-api::auth` |
| **2FA** | TOTP with replay cache, BLAKE3 (`b3:`) backup-code digests (not Argon2id), lockout and IP throttling; verification serialized so codes/backup codes are single-use under concurrency. Setup, enable, replacement and disable require a short-lived re-authentication ticket bound to the account, session and credential epoch. | `sito-api::auth::manager`, `auth::totp` |
| **First boot** | One-time setup token (CSPRNG, console-printed, per-IP rate-limited) gates the wizard until setup completes; the token is not pruned while first-run is pending. The wizard is strictly bootstrap-only: after setup it returns `403` even for an Admin session, and admin password changes use the authenticated account flow. | `sito-api::auth::manager`, `sito-api::router` |
| **CSRF / browser** | Strict same-origin `Origin`/`Referer` checks (missing origin fails closed for cookie sessions), session-bound CSRF tokens for mutating requests, `__Host-` cookies on TLS, `HttpOnly`, `SameSite=Strict`, `no-store` on auth/config responses, CSP/HSTS/X-Frame-Options/nosniff. | `sito-api::security`, `auth::session` |
| **DoS / flooding** | One shared token bucket across UDP/TCP/DoT/DoH/DoQ/DoH3, keyed by IPv4 `/24` and IPv6 `/64` and checked before reading request bodies on DoH/DoQ; per-source connection caps, handshake/request deadlines, maximum connection lifetimes, bounded QUIC windows/streams, and approximate-LRU rate-limit eviction. | `sito-transport`, `crates/sito/src/server.rs` |
| **HA security** | mTLS with BLAKE3 certificate pinning (optional explicit insecure WS for isolated networks), constant-time shared-token check, Ed25519-signed bundles with monotonic versions, master-loss heartbeat deadline (`3 × ping_interval_secs`), applied-config digest drift detection, per-slave publish outcomes that make `/health` false on failure, 64-global/8-per-IP session admission, and a bounded signing-key identity check on state restore. | `sito-ha` |
| **Secrets** | HA bundles strip TLS/web keys, auth hashes/tokens, RouterOS credentials and per-client shared secrets (`${SECRET:*}` placeholders where applicable; node-local values are restored on the slave). Config/users/tokens/sessions and ACME keys are written 0600 atomically. Headers and cookies are never logged. | `sito-ha::bundle`, `sito-api::config_writer`, `sito-transport::acme` |
| **TLS** | rustls-only, TLS 1.2/1.3, AEAD cipher suites, RPK/SNI certificate support, atomic certificate reload, native ACME (TLS-ALPN-01 with a bound TCP 443 listener, otherwise HTTP-01). Bootstrap certificates are 7-day self-signed placeholders and are not served unless `acme.allow_bootstrap_cert = true`; invalid, expired, or mismatched configured TLS material is a startup error. A successful issuance reloads DoT, DoH, DoQ, and DoH3. | `sito-transport::tls`, `::acme` |
| **DNSSEC** | Fail-closed validation with trust-anchor chains, DS/DNSKEY walking, NSEC/NSEC3 denial proofs (including wildcard denial and delegation-boundary checks), algorithm/digest policy, key-cache bounds, a 5-second per-query validation deadline, CD/DO semantics and AD only for validated answers. | `sito-dnssec` |
| **Supply chain** | `cargo deny` (advisories/bans/licenses/sources) in CI, SHA-pinned GitHub Actions, digest-pinned container bases, signed (cosign) release archives. The **installer** requires signatures by default (`SITO_REQUIRE_SIGNATURE=1`, explicit `=0` opt-out); the **self-updater** uses `server.update_require_signature = true` by default (explicit `false` opt-out). When verification runs, a signature that is present is always checked. With `required = false` and no verifier configured, the updater logs a warning and proceeds without verification; this is an explicit operator opt-out, not a silent downgrade. Release tags are gated on the required branch plus green CI/security checks, and container images are scanned and cosign-signed. | `deny.toml`, `.github/workflows`, `contrib/install.sh`, `sito-api::updater` |
| **API integrity** | Config writes run the same deep typed-section validation as startup, invalid configs are rejected before persisting, restore archives are decompression-capped, tokens expire by default (90 days), deleting a user revokes sessions. | `sito-api::config_validation`, `handlers::config`, `auth::manager` |

---

## 2. Threat notes

* **Malicious upstream / on-path attacker:** DNSSEC validation is
  non-bypassable in `validate`/`strict` modes, prefetch re-validates before
  caching, and cross-zone signatures are rejected. A chain that cannot be
  proven fails closed.
* **Malicious subscription lists:** list parsing is fail-closed for regex
  budgets; hostile prefix/ACL load is bounded by the per-list byte cap and the
  parse pipeline never panics.
* **Compromised client identity claims:** DoH path segments and DoT/DoQ SNI
  only identify a client when they match a configured shared secret; filter
  `$client=` matching uses only registry-resolved identity.
* **First-boot exposure:** the web UI binds `0.0.0.0:8080` during setup but no
  DNS listener is bound and the wizard is token-gated. Operators exposing the
  setup endpoint beyond a trusted network should treat the printed token as
  the only credential until setup completes.
* **Container isolation:** images run as nonroot (uid/gid 65532) with
  `NET_BIND_SERVICE` required for ports < 1024; `/var/lib/sito` and `/etc/sito`
  are owned by that uid so fresh named volumes are writable. Docker's `ports`
  mapping controls host exposure; keep `web.bind = "0.0.0.0"` inside the
  container and publish the admin port only on loopback
  (`-p 127.0.0.1:8080:8080`).

---

## 3. Verification

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo deny check
python3 scripts/check_config_reference.py
python3 scripts/check_markdown_links.py
```

Scheduled fuzzing was intentionally removed and is not part of CI; there is no
`fuzz/` harness in this repository. See
[docs/ci.md](ci.md#scheduled-fuzzing-was-intentionally-removed).

---

## 4. Known accepted limitations

* The deprecated `?token=` query parameter is accepted **only** on the
  WebSocket upgrade when no `Authorization` header is present, logs a warning,
  and is scheduled for removal in 2.0. Use `Authorization` headers or
  `__Host-` session cookies.
* Rate-limiting budgets are enforced per network prefix (IPv4 `/24`, IPv6
  `/64`), not per authenticated account.
* The account lockout map is bounded at 10,000 entries. If every entry is an
  active lockout, a new key is not tracked and relies on the per-IP login rate
  limit when `auth.login_rate_limit > 0` (setting it to `0` disables that
  fallback too). This is a deliberate bounded-memory trade-off; an active
  lockout is never evicted to make room.
* `auth.token_default_ttl_days = 0` disables token expiry for operators who
  explicitly opt out; the default is 90 days.
* DNSSEC wildcard denial requires complete NSEC/NSEC3 proofs; responses whose
  proofs are incomplete are treated as `Bogus` (fail closed) rather than
  downgraded to `Insecure`.
* Self-update under systemd requires running `sito update` as root with the
  service stopped (the unit keeps `ProtectSystem=strict`).
* Statistics retention and rollup privacy (P1-19/P1-23/P1-24) now use keyed
  rollup hashes, rollup retention, clear/vacuum, optional query-log totals,
  cached dashboard aggregates, and bounded retention chunks. See the
  [1.9.4 release notes](release-notes-1.9.4.md#stats-privacy-retention-and-polling).
* RouterOS integration remains experimental/niche and is not part of the core
  security posture; it is planned to move behind an optional feature in 2.0.
* The weekly benchmark workflow records estimates but does not enforce a
  performance threshold or fail on regression.
