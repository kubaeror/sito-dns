# Security Review and Threat Model (current)

This document summarizes the **implemented** security controls and known
limitations of the current tree. It replaces an earlier v1.0.0/v1.2.1 audit
record whose claims had drifted from the code. Point-in-time audits with
`file:line` evidence and remediation status live in:

* [`docs/audit5.md`](audit5.md) — most recent independent audit (v1.6.0).
* [`docs/audit4-followup-plan.md`](audit4-followup-plan.md) — previous batch.

Everything below is verifiable in the source; the referenced modules are the
implementation of record.

---

## 1. Control summary

| Domain | Control | Implementation |
|---|---|---|
| **SSRF** | Subscription schemes restricted to `http://`, `https://`, `file://`. HTTP fetches disable redirects and proxies, resolve and pin the target address, and deny loopback, RFC 1918/ULA, link-local/metadata (including CGNAT, reserved, documentation, and IPv4 embeddings via IPv4-mapped, NAT64, 6to4 and Teredo). `file://` is allowlisted to the data directory plus explicit programmatic roots, rejecting pseudo-filesystems. | `sito-filter::subscription`, `sito-core::config` |
| **ReDoS** | User regex and ABP wildcards compile to dense DFAs with hard budgets (≤ 10k patterns, ≤ 4 MiB pattern bytes, ≤ 16 KiB per pattern, ≤ 10 MiB DFA) and a bounded per-pattern fallback. Linear-time matching, no backtracking. | `sito-filter::structures::compiled` |
| **Auth timing** | Argon2id ($m=64$ MiB, $t=3$, $p=4$) for passwords and TOTP backup codes; constant-time comparisons (`subtle`) for API tokens, session cookies, setup tokens and TOTP codes. | `sito-api::auth` |
| **2FA** | TOTP with replay cache, Argon2id-hashed backup codes, lockout and IP throttling; verification serialized so codes/backup codes are single-use under concurrency. | `sito-api::auth::manager`, `auth::totp` |
| **First boot** | One-time setup token (CSPRNG, console-printed, per-IP rate-limited) gates the wizard until setup completes; the token is not pruned while first-run is pending. | `sito-api::auth::manager`, `sito-api::router` |
| **CSRF / browser** | Strict same-origin `Origin`/`Referer` checks (missing origin fails closed for cookie sessions), session-bound CSRF tokens for mutating requests, `__Host-` cookies on TLS, `HttpOnly`, `SameSite=Strict`, `no-store` on auth/config responses, CSP/HSTS/X-Frame-Options/nosniff. | `sito-api::security`, `auth::session` |
| **DoS / flooding** | One shared per-client token bucket across UDP/TCP/DoT/DoH/DoQ/DoH3, checked per query; connection caps; TLS/handshake and write timeouts; bounded per-connection pipelining; bounded rate-limiter tables; UDP truncation to the negotiated EDNS size. | `sito-transport`, `crates/sito/src/server.rs` |
| **HA security** | mTLS with certificate pinning (optional explicit insecure WS for isolated networks), constant-time shared-token check, Ed25519-signed bundles with monotonic versions, handshake timeout and connection cap on the master listener, per-session identity so stale connections cannot mutate live state. | `sito-ha` |
| **Secrets** | HA bundles strip TLS/web keys, auth hashes/tokens, RouterOS credentials and per-client shared secrets (`${SECRET:*}` placeholders where applicable; node-local values are restored on the slave). Config/users/tokens/sessions and ACME keys are written 0600 atomically. Headers and cookies are never logged. | `sito-ha::bundle`, `sito-api::config_writer`, `sito-transport::acme` |
| **TLS** | rustls-only, TLS 1.2/1.3, AEAD cipher suites, RPK/SNI certificate support, atomic certificate reload, native ACME (TLS-ALPN-01 and HTTP-01). No SSLv3/TLS 1.0/1.1 or CBC/RC4 negotiation paths. | `sito-transport::tls`, `::acme` |
| **DNSSEC** | Fail-closed validation with trust-anchor chains, DS/DNSKEY walking, NSEC/NSEC3 denial proofs (including wildcard denial), algorithm/digest policy, key-cache bounds, CD/DO semantics and AD only for validated answers. | `sito-dnssec` |
| **Supply chain** | `cargo deny` (advisories/bans/licenses/sources) in CI, SHA-pinned GitHub Actions, digest-pinned container bases, signed (cosign) release archives verified by the installer and the self-updater; updater signatures are required by default with the identity pinned to the release workflow on tag refs. | `deny.toml`, `.github/workflows`, `contrib/install.sh`, `sito-api::updater` |
| **API integrity** | Config writes run the same deep typed-section validation as startup, invalid configs are rejected before persisting, restore archives are decompression-capped, tokens expire by default (90 days), deleting a user revokes sessions. | `sito-api::config_validation`, `handlers::config`, `auth::manager` |

---

## 2. Threat notes

* **Malicious upstream / on-path attacker:** DNSSEC validation is
  non-bypassable in `validate`/`strict` modes, prefetch re-validates before
  caching, and cross-zone signatures are rejected. A chain that cannot be
  proven fails closed.
* **Malicious subscription lists:** list parsing is fail-closed for regex
  budgets; hostile prefix/ACL load is bounded by the per-list byte cap and the
  parse pipeline never panics (fuzz-tested).
* **Compromised client identity claims:** DoH path segments and DoT/DoQ SNI
  only identify a client when they match a configured shared secret; filter
  `$client=` matching uses only registry-resolved identity.
* **First-boot exposure:** the web UI binds `0.0.0.0:8080` during setup but no
  DNS listener is bound and the wizard is token-gated. Operators exposing the
  setup endpoint beyond a trusted network should treat the printed token as
  the only credential until setup completes.
* **Container isolation:** images run as nonroot (uid/gid 65532) with
  `NET_BIND_SERVICE` required for ports < 1024; `/var/lib/sito` and `/etc/sito`
  are owned by that uid so fresh named volumes are writable.

---

## 3. Verification

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo deny check
python3 scripts/check_config_reference.py
```

Fuzzing targets (`fuzz/`) cover DNS wire parsing, ABP parsing, TOML config,
client IDs, DNSSEC responses and HA bundles; `nightly-fuzz.yml` runs them with
a pinned nightly toolchain.

---

## 4. Known accepted limitations

* The deprecated `?token=` query parameter is accepted **only** on the
  WebSocket upgrade when no `Authorization` header is present, logs a warning,
  and is scheduled for removal in 2.0. Use `Authorization` headers or
  `__Host-` session cookies.
* Rate-limiting budgets are enforced per client IP, not per authenticated
  account.
* `auth.token_default_ttl_days = 0` disables token expiry for operators who
  explicitly opt out; the default is 90 days.
* DNSSEC wildcard denial requires complete NSEC/NSEC3 proofs; responses whose
  proofs are incomplete are treated as `Bogus` (fail closed) rather than
  downgraded to `Insecure`.
* Self-update under systemd requires running `sito update` as root with the
  service stopped (the unit keeps `ProtectSystem=strict`).
