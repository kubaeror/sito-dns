# Phase 3 Security Review and Threat Model Update

**Date:** 2026-11-21
**Commit:** `67269ea32a78becd87198d8edf650d72e58e216b` (`67269ea`)
**Scope:** 2.0.0-rc.1 candidate on `feat/2.0-phase3-security`, read-only code review
**Companion documents:** [security audit and threat model](security-audit.md),
[P0/P1 test matrix](audit6-test-matrix.md), [2.0 claim matrix](2.0-claim-matrix.md)

This review re-runs the audit streams represented by the audit-6 P0/P1 findings
against the Phase 3 tree. It does not replace the historical audit records; it
records what is true at `67269ea`.

## 1. Verdict

| Item | Result |
|---|---|
| Open P0 | **None.** P0-1 (ACME bootstrap) and P0-2 (DNSSEC delegation denial) remain closed and have named regression tests. |
| Open P1 | **P1-1 DNAME sub-item only.** It is fail-closed in `validate`/`strict` mode and is accepted for rc.1 as an availability limitation (see §4). P1-2 through P1-27 are closed and mapped to existing named tests. |
| Test matrix integrity | Every backticked test/script name in `docs/audit6-test-matrix.md` resolves (`python3 scripts/check_test_matrix.py`, 783 unique tokens). Two stale names and the missing `progress.md` reference were fixed in this pass. |
| Production `unsafe`/FFI | Three production modules plus a test-only allocation counter: UDP socket setup (`sito-transport::udp`), packet-info syscalls (`sito-transport::pktinfo`) and updater xattr preservation (`sito-api::updater`). No memory-unsafety finding; safety arguments are recorded in §5. |
| Secrets and permissions | Config, users/TOTP, HA keys/state, stats salt/database, backups and updater scratch are owner-only or safely repaired; see §6. |
| Supply chain | Advisories, bans, licenses and sources pass with two reviewed, non-exploitable suppressions; see §11. |
| rc.1 security decision | **No security fix is required before rc.1.** The DNAME residual and the remaining availability/operational residuals are accepted with review dates in §13. |

No open P0. One open P1 sub-item (DNAME) is accepted for rc.1 because the
validate/strict path fails closed; the other P1 findings remain closed.

Every P0 (`P0-1`..`P0-2`) and P1 (`P1-1`..`P1-27`) row in
[`docs/audit6-test-matrix.md`](audit6-test-matrix.md) maps to at least one
backticked named test or script. `python3 scripts/check_test_matrix.py` resolves
all 783 unique backticked tokens against the tree. This pass corrected two stale
names (`test_temp_exe_removed_when_rename_fails` →
`test_replace_restores_backup_when_rename_fails` and
`parsed_canonical_matches_recomputed_canonical` →
`parsed_canonical_matches_independent_oracle`) and removed the dangling
`progress.md` reference.

## 2. Method and evidence

The review used the following evidence sources:

- Source inspection of the production paths named in the audit-6 findings.
- The focused tests in [`docs/audit6-test-matrix.md`](audit6-test-matrix.md),
  re-run on this tree.
- A new mechanical check, `scripts/check_test_matrix.py`, plus its fixture suite
  `scripts/test_check_test_matrix.py`.
- The deployment checks (`scripts/test-compose-defaults.sh`,
  `scripts/test-systemd-hardening.sh`, `contrib/tests/test-installer.sh`).
- `cargo deny check advisories` and `cargo tree` for the two suppressions.

The machine-readable verification results are recorded in §12. The review is
read-only for product code; documentation and checker scripts are the only
changes in this work package.

## 3. Audit streams

### 3.1 DNS and transport exposure

**Current control.** The resolver accepts UDP/TCP/DoT/DoH/DoQ/DoH3 through
bounded listeners. Admission is acquired before TLS handshakes and before DoH
and DoQ request bodies are read. Global and per-source connection budgets,
request/stream semaphores, H2/H3 stream caps, connection lifetimes, and
accept-loop backoff bound unauthenticated resource growth. Response encoding is
truncated to the 65,535-byte DNS framing limit with `TC=1` on every transport.
`dns.bind` still defaults to wildcard; the shipped Compose file publishes DNS
explicitly and the admin port on loopback.

**Evidence.** `test_admission_controller_global_connection_cap`,
`test_admission_controller_per_source_connection_cap`,
`test_dot_connection_permit_held_before_handshake`,
`test_doq_connection_lifetime_closes_active_connection`,
`test_doh3_connection_lifetime_closes_active_connection`,
`test_tcp_truncates_oversized_response`,
`test_udp_truncates_to_configured_edns_size_even_when_client_advertises_larger`;
`cargo test -p sito-transport --locked` passed (107 tests).

**Residual risk.** The resolver is still reachable from every interface unless
the operator restricts `dns.bind` or adds a firewall rule; this is the documented
default-wildcard/ACL residual, not a new finding. A hostile client can consume
its share of the bounded budget, but cannot grow it without limit. Bounded
resource use is not a guarantee of availability against a volumetric attack.

### 3.2 DNSSEC validation

**Current control.** Validation is fail-closed in `validate`/`strict` mode:
trust-anchor chains, DS/DNSKEY walking, NSEC/NSEC3 denial including
closest-encloser and delegation-boundary checks, algorithm/digest policy,
per-response verification budgets, a shared 5-second per-query key-fetch
deadline, and cache policy epochs. `Indeterminate` is not served as validated
data; strict Bogus is cached as SERVFAIL. CD/DO semantics and AD are applied
only to authenticated answers.

**Evidence.** `test_parent_delegation_nsec_cannot_prove_nxdomain_below_cut`,
`test_parent_delegation_nsec3_cannot_prove_nxdomain_below_cut`,
`test_parent_delegation_nsec3_nodata_only_denies_ds`,
`test_ds_nodata_at_delegation_is_secure`,
`test_forged_covering_rrsig_still_probes_unsigned_delegation`,
`test_signed_cname_to_stripped_target_without_ds_denial_is_bogus`,
`test_dname_unknown_rdata_fails_closed`,
`test_m11_cd1_bypasses_post_fetch_indeterminate`,
`test_m11_blocked_key_fetch_is_bounded_and_servfails`;
`cargo test -p sito-dnssec --locked` passed (170 tests);
`cargo test -p sito-test --features ha --test m11_dnssec_security` passed.

**Residual risk.** DNAME is the one accepted P1 residual; see §4. In
`log_only` mode Bogus answers are deliberately returned without AD, so a
validating client must still make its own decision; `disabled` mode performs no
validation by definition. Local write access to the chain cache or trust
anchors is equivalent to local compromise and is outside the remote-attacker
threat model.

### 3.3 Filtering and rewrites

**Current control.** Parser and compiler budgets are enforced before
materialisation (line, token, byte, rule and DFA limits). Empty or zero-yield
list responses are rejected unless `filtering.allow_empty_list = true`; a failed
reload retains the previous snapshot and is observable. Rule precedence is
`Allow > Rewrite > Block` within a tier, group overlay wins ties, `$important`
outranks standard, and invalid modifier tokens reject the whole rule. Rewrite
exceptions require an authenticated, provenance-bearing identity; a raw DoH path
or SNI string cannot grant it.

**Evidence.** `test_hostile_line_and_rule_count_hit_parse_budget`,
`test_zero_yield_list_retains_previous_snapshot`,
`test_partial_invalid_dnstype_and_denyallow_tokens_reject_rule`,
`test_ip_identified_client_cannot_spoof_exception_with_untrusted_id`,
`test_cname_target_same_snapshot_rewrite_before_block_still_blocks`,
`test_group_budget_failure_publishes_non_regex_subset`,
`test_exception_requires_authenticated_identity`;
`cargo test -p sito-filter --locked` and
`cargo test -p sito-rewrites --locked` passed (41 rewrite tests).

**Residual risk.** A subscription-list publisher can still change blocking
decisions (availability/quality), but cannot execute code or widen rule scope
through malformed tokens. Group and global list precedence remains complex;
the acceptance suite is the guard. `file://` list access is restricted to the
data directory or explicit programmatic roots.

### 3.4 Clients, identity and schedules

**Current control.** Client identity comes from the registry and a
provenance-tagged `ClientContext`; unauthenticated wire claims and unverified
RouterOS leases never match policy. MAC IDs use a strict parser; ARP snapshot
changes invalidate both positive and negative caches. Schedules are evaluated in
the configured timezone; reversed numeric ranges are rejected at load. Safe
search is limited to A/AAAA/HTTPS and never rewrites a host to itself.

**Evidence.** `test_identity_trust_table`,
`test_untrusted_context_provenance_cannot_match_policy`,
`test_client_name_requires_authenticated_identity`,
`test_guessable_sni_label_does_not_grant_identity`,
`test_arp_snapshot_change_invalidates_positive_cache`,
`test_reversed_ranges_rejected_with_field_number`,
`test_split_overnight_window_is_valid_and_active_across_midnight`,
`test_safe_search_targets_pass_through_without_self_cname`;
`cargo test -p sito-clients --locked` passed (110 tests).

**Residual risk.** MAC identity is only as trustworthy as the local L2/ARP
environment; an on-link attacker can spoof it. IANA timezone names are not
supported (no tzdb dependency); `local` follows the host zone and DST
behaviour. RouterOS remains optional/experimental and absent from the default
build.

### 3.5 Upstreams, bootstrap and SSRF

**Current control.** Subscription schemes are limited to `http`, `https` and
`file`. HTTP fetches disable redirects and proxies, resolve and pin the target
address, and reject loopback, RFC 1918/ULA, link-local/metadata, CGNAT,
benchmarking, documentation, reserved and IPv4-embedding IPv6 ranges. Bootstrap
answers apply the same denylist and denied-only answers are not cached.
`upstream.allow_private_targets` is the explicit hostname opt-in; configured IP
literals are the documented operator allowlist path. Production DoH ignores
ambient proxy variables and does not follow redirects. The updater is restricted
to the allowed GitHub repository, validates download hosts and, by default,
requires cosign signatures.

**Evidence.** `test_private_targets_are_rejected_without_network_access`,
`test_bootstrap_rejects_private_answers_by_default`,
`test_bootstrap_rejects_nat64_embedded_private_answers`,
`test_bootstrap_rejects_ipv4_embedded_private_answers`,
`test_bootstrap_denied_answer_is_not_cached`,
`test_manager_rejects_private_hostname_before_building_transport`,
`test_doh_new_ignores_ambient_https_proxy`,
`test_doh_redirects_are_not_followed`,
`test_m9_security_ssrf_url_scheme_allowlist`;
`cargo test -p sito-upstream --locked` passed (84 tests).

**Residual risk.** Explicit IP literals bypass the denylist by design. The
self-updater follows normal HTTPS redirects for GitHub endpoints; the initial
URL and asset URLs are host-checked and signatures are mandatory by default, but
the redirect target itself is not revalidated. This is accepted for rc.1; a
release-metadata attacker who can also redirect downloads still cannot produce a
valid cosign signature.

### 3.6 Authentication, sessions, re-authentication and CSRF

**Current control.** Passwords use Argon2id with a four-operation concurrency
cap. API tokens, session cookies, setup tokens and TOTP codes use constant-time
comparison. Login inputs are length-capped before hashing; lockout keys are
BLAKE3 digests and active lockouts are not evicted. TOTP setup, enable,
replacement and disable require a short-lived, session-bound, single-use
re-authentication ticket. Session cookies are `HttpOnly`, `SameSite=Strict`,
`__Host-` on TLS, and authenticated responses are `no-store` with `Vary:
Cookie`. Mutating requests require same-origin `Origin`/`Referer` and a
session-bound CSRF token; missing origin fails closed for cookie sessions.
Querylog WebSocket upgrades reject `Origin: null` and cross-origin requests,
require an Origin for session clients, and accept credentials only from a
Bearer header or cookie.

**Evidence.** `test_login_rejects_oversized_credentials_before_lockout`,
`test_login_lockout_key_is_a_digest`,
`test_active_lockout_is_not_evicted_at_capacity`,
`test_argon2_verification_concurrency_is_bounded`,
`test_totp_setup_and_enable_require_reauth_token`,
`test_existing_totp_cannot_be_replaced_without_reauth`,
`test_disable_totp_requires_reauth_token`,
`test_websocket_origin_validation`,
`test_querylog_stream_rejects_query_token`,
`test_sensitive_responses_have_no_store_and_vary_cookie`;
`cargo test -p sito-api --all-features --lib --locked` passed (375 tests).

**Residual risk.** Admin API tokens are exempt from sensitive re-authentication
(an explicit operator decision), and `auth.token_default_ttl_days = 0` disables
token expiry. The lockout map is bounded at 10,000 entries; if every entry is an
active lockout, a new key relies on the per-IP login rate limit. Rate limits are
per network prefix, not per account. These are documented operator trade-offs.

### 3.7 API and configuration integrity

**Current control.** Config writes run the same typed-section validation as
startup before persisting. Unknown keys and tables are rejected; v1 documents
are rejected with the migration command. Restart-only writes return `409` and
persist nothing. Restore archives are decompression-capped, unknown metadata
versions are rejected, and `config.toml` is written atomically with mode `0600`.
OpenAPI paths, methods, tags and security schemes match the router. `/metrics`
requires Viewer-or-higher authentication by default. `/health` is generic;
detailed reasons are on authenticated status endpoints.

**Evidence.** `test_unknown_keys_are_rejected_everywhere`,
`test_restart_only_write_is_conflict_and_not_persisted`,
`test_update_config_restart_only_is_conflict_and_not_persisted`,
`test_restore_archive_rejects_unknown_metadata_version`,
`test_backup_config_member_is_mode_0600`,
`test_openapi_paths_match_router`,
`test_openapi_security_schemes_and_operation_security`,
`test_sensitive_responses_have_no_store_and_vary_cookie`;
`cargo test -p sito-core --test config_v2 --locked` passed (26 tests).

**Residual risk.** `/api/v2` and the API v1 compatibility facade are not
implemented and remain deferred. There is no default-deny DNS client ACL;
`dns.bind` wildcard plus firewall is the documented mitigation. The admin UI is
plain HTTP by default and must be kept on loopback or behind a TLS reverse
proxy. A malformed or unreadable config fails closed rather than silently
returning defaults.

### 3.8 High availability (HA) protocol v2

**Current control.** Replication uses mTLS, BLAKE3 certificate pinning,
optional CA validation with hostname/SAN checks, a constant-time shared token,
and Ed25519-signed bundles that bind the signing-key fingerprint and the shared
config digest. Term/version/fork continuity and a bounded publish history
prevent replay and division; a slave that misses `3 x ping_interval_secs` leaves
`Synced` and becomes not-ready. Publish outcomes distinguish connected, queued,
coalesced and no-delivery states. Bundles strip TLS/web keys, auth material,
RouterOS credentials and per-client shared secrets; node-local values are
restored on the slave. State, watermark and private keys are `0600`.

**Evidence.** `test_master_rejects_v1_slave_and_keeps_listening`,
`test_restore_preserves_term_and_rejects_v1_state`,
`test_signed_identity_must_match_key_and_config`,
`test_same_term_key_rotation_requires_promotion`,
`test_slave_goes_not_ready_when_master_stops_sending_frames`,
`test_server_ca_only_verification_and_wrong_ca`,
`test_pin_plus_ca_enforces_san`,
`test_client_cert_chain_must_match_configured_ca`,
`test_expired_server_certificate_is_rejected`,
`test_publish_outcome_reports_connected_closed_and_queued`;
`cargo test -p sito-ha --locked` passed (147 tests);
`cargo test -p sito-test --features ha --test m11_ha_partition` passed (6 tests).

**Residual risk.** `allow_unpinned_tls = true` and `allow_insecure_ws = true`
are explicit insecure opt-outs; a configured pin or CA is still enforced. There
is no automatic promotion. API mutations on a slave are rejected
(`test_m8_slave_read_only_enforcement`), but a direct edit of the config file is
not rejected at edit time; shared-field drift is detected after the write and
requires a full apply. A partitioned slave keeps serving its last applied
configuration while not-ready. These are availability/operability risks, not
authentication bypasses.

### 3.9 Statistics, query log and PII

**Current control.** Hourly rollups use keyed BLAKE3 client identifiers; client
names are opt-in and can be scrubbed. Retention is row-bounded per hour, clear
and vacuum are available, `keep_aggregates` is opt-in, and dashboard polling is
served from a 30-second cache with optional total counts. The per-install salt
and SQLite database/WAL/SHM files are `0600`; a corrupt or short salt is a hard
error, and a symlinked salt is refused. The live-tail clone only happens when a
subscriber exists.

**Evidence.** `test_rollup_pii_hashes_client_ip_and_omits_names_by_default`,
`test_rollup_retention_deletes_expired_domains_and_rows`,
`test_stats_files_are_private_and_loose_permissions_are_repaired`,
`test_salt_persists_and_corrupt_salt_is_rejected`,
`test_clear_query_log_vacuums_and_secure_delete_is_on`,
`test_live_tail_clone_only_with_subscribers`,
`test_retention_concurrent_insert_does_not_drop_batches`;
`cargo test -p sito-stats --locked` passed (86 tests plus the Prometheus
exposition test).

**Residual risk.** Query-log anonymization is forward-only: existing detailed
rows are not rewritten. The `keep_aggregates` whole-range clear and a 1M-row /
90-day soak remain capacity residuals. A local root/data-directory attacker can
read the database; this is local compromise, outside the remote threat model.

### 3.10 Operations, deployment and release integrity

**Current control.** The shipped Compose default binds the admin UI to
`127.0.0.1`, uses a named config volume and a pinned non-local image; HA uses
valid DHCP hex and parameterized topology. The systemd unit and installer
fallback share `EnvironmentFile`, `UMask=0077`, `PrivateTmp`, `ProtectProc`,
namespace/SUID/personality restrictions and native syscall architecture. The
installer E2E covers fresh install, live upgrade, rollback, signature policy,
capability handling and uninstall. Release actions are SHA-pinned; release tags
are gated on the required branch and green `ci-gate`/`cargo-deny` checks; release
archives are cosign-signed and the image is scanned and signed.

**Evidence.** `scripts/test-compose-defaults.sh`,
`scripts/test-systemd-hardening.sh`,
`contrib/tests/test-installer.sh`,
`scripts/test-verify-release-gate.sh`,
`scripts/test-release-workflow.sh`,
`scripts/test-release-attestation-gate.sh`;
`.github/workflows/container.yml` builds the image and asserts a live DNS
rewrite; `.github/workflows/artifact-e2e.yml` verifies archive checksums,
cosign identity and every packaged binary's `--version`/`check-config`.

**Residual risk.** Image vulnerability scanning is linux/amd64 only; per-arch
scanning and a live DNS query against the published release image remain
WP-3.1 work (the PR container smoke does run a live DNS query on the dev image).
The root-gated HA certificate ownership test remains a manual/weekly step. The
release image's `healthcheck` entrypoint is shipped but not exercised in CI.
Installer/updater signature policy is only as strong as the operator's cosign
installation and the release workflow's identity; both are documented and fail
closed when the policy requires a signature.

### 3.11 Supply chain and dependency policy

**Current control.** `cargo deny` covers advisories, bans, licenses and
sources in CI. GitHub Actions are SHA-pinned. Container bases are digest-pinned.
Release archives are cosign-signed and the release workflow checks the signature
identity. The installer requires signatures by default (`SITO_REQUIRE_SIGNATURE=1`,
explicit `=0` opt-out); the self-updater requires them by default
(`server.update_require_signature = true`). A present signature is always
verified even when optional; an incomplete or unverifiable pair fails closed.

**Evidence.** `cargo deny check advisories` → `advisories ok`;
`python3 scripts/test_check_bench_regression.py`,
`bash scripts/test-release-workflow.sh`, and
`bash scripts/test-release-attestation-gate.sh` pass. See §11 for the two
reviewed suppressions.

**Residual risk.** The two unmaintained-crate suppressions below; the image
scan is amd64-only; and the release process still depends on the GitHub Actions
runner and cosign identity. These are tracked, not hidden.

## 4. P1-1 DNAME residual and rc.1 risk acceptance

**Finding.** The pinned `hickory-proto 0.26.3` has no `RData::DNAME` variant. A
DNAME record on the wire decodes as `RData::Unknown { code: DNAME }`; site
cannot inspect, validate or follow the alias.

**Is it fail-closed?** Yes in `validate`/`strict` mode. The regression test
`test_dname_unknown_rdata_fails_closed` proves the wire decode and asserts:

- the validation outcome is `Bogus`;
- the response code becomes `SERVFAIL`;
- `AD` is clear;
- the uninterpretable answer is removed;
- the validator records one `bogus` metric.

The resolver's strict-Bogus path caches the failure as a fail-closed SERVFAIL
with empty answer/authority/additional sections and does not serve AD=1. In
`log_only` mode the answer is returned without AD by the documented policy for
all Bogus responses; a validating client must not treat it as authenticated.
`disabled` mode performs no validation. There is no path where a DNAME response
is served as `Secure`.

**Impact.** A legitimate DNAME alias returns SERVFAIL in validate/strict mode
until hickory gains DNAME support or the resolver implements local DNAME RDATA.
This is an availability/compatibility limitation, not an authentication bypass.

**Risk acceptance for rc.1.** Accepted. The residual is closed only by a
hickory upgrade or a local DNAME implementation, both larger than the rc.1
security scope. The acceptance is contingent on the test above remaining green;
re-review on any hickory upgrade or by **2027-01-31**, whichever comes first.

## 5. Production `unsafe` and FFI review

The tree contains no `unsafe` in the DNS parser, filter, DNSSEC, cache, auth or
HA protocol logic. The production modules are `sito-transport::udp`,
`sito-transport::pktinfo` and `sito-api::updater`; the only other `unsafe` is a
test-only allocation counter.

### 5.1 `crates/sito-transport/src/udp.rs`

**Scope.** Creates one non-blocking UDP socket per worker with `SO_REUSEPORT`,
registers it with Tokio's `AsyncFd`, and enables packet-info.

**Safety argument.**

- `SO_REUSEPORT` is set with `setsockopt` on `socket.as_raw_fd()` while the
  `socket2::Socket` is alive and before it is moved; the option pointer and
  length refer to a live `c_int` for the duration of the call. A failure is
  returned with the OS error instead of silently falling through to a confusing
  `EADDRINUSE`.
- `AsyncFd::register(std_socket)` is the documented I/O-safety-preserving
  constructor (`AsyncFd::new` is deprecated as unsound). The socket is moved
  into the `AsyncFd`; no second handle closes, replaces or duplicates it while
  registered.
- The returned `std::net::UdpSocket` is owned by the `AsyncFd`; the worker only
  uses raw descriptors borrowed from that owner for the packet-info helpers.

**Residual.** `set_only_v6(false)` is best-effort and its error is ignored; a
platform that refuses dual-stack behaviour affects reachability, not memory
safety. The UDP listener is Unix-only (`compile_error!` otherwise), and the
tested CI scope is Linux.

### 5.2 `crates/sito-transport/src/pktinfo.rs`

**Scope.** Unix-only (`compile_error!` on non-Unix); used by the UDP listener to
enable `IP_PKTINFO`/`IPV6_RECVPKTINFO`, receive the local destination address,
and send replies from the address the client queried. The shipped/tested CI
targets are Linux; the module's macOS path is not CI-covered.

**Safety argument.**

- `RawFd` is supplied by the owning socket and is valid for the duration of the
  call; no file descriptor is stored or closed here.
- `recv_with_pktinfo` passes a valid `iovec` for `buf.len()` and a fixed 512-byte
  control buffer. The kernel writes at most that buffer; `CMSG_FIRSTHDR`/
  `CMSG_NXTHDR` walk only kernel-provided control messages, and data is cast
  only after matching the expected level/type.
- `MSG_TRUNC` is checked before returning, so a datagram larger than the buffer
  is reported as an error rather than parsed as a partial DNS message.
- The source `sockaddr_storage` is kernel-filled; the family is checked before
  casting to `sockaddr_in`/`sockaddr_in6`.
- `send_with_pktinfo` only installs a control message when `CMSG_SPACE` fits the
  fixed buffer, sets `cmsg_len` with `CMSG_LEN`, and falls back to `sendto` with
  an explicit warning if the source-address send fails. The fallback can change
  the source address on a multi-homed host; that is visible in logs and is an
  availability/behaviour trade-off, not memory unsafety.
- `socket_addr_to_sockaddr` copies only the concrete `sockaddr_in`/`sockaddr_in6`
  size into a zero-initialised storage and returns the matching length.

**Residual.** The module-level `#![allow(clippy::all, clippy::pedantic)]`
suppresses style lints in this file, not memory-safety lints. macOS is claimed
by the compile gate but not exercised in CI; treat Linux as the supported
tested platform for this release.

### 5.3 `crates/sito-api/src/updater.rs` xattr wrappers

**Scope.** `#[cfg(unix)]` production helpers `list_xattr_names`, `get_xattr`,
`copy_xattrs` (plus the test-only `set_test_xattr`) preserve the existing
executable's extended attributes, notably `security.capability`, across the
atomic update rename.

**Safety argument.**

- Paths and attribute names are converted to `CString` first; an embedded NUL is
  rejected before the syscall.
- Each read does a size query with a null buffer, allocates exactly that size,
  and retries on `ERANGE` if attributes grow between the calls. The returned
  length is checked non-negative and truncated into the buffer before use.
- `listxattr` returns NUL-separated names; the code splits, drops empty names and
  re-encodes each name before `getxattr`/`setxattr`.
- `setxattr` receives a valid value pointer and length; the return code is
  checked. `copy_xattrs` runs in `spawn_blocking`, and any failure aborts the
  update before the rename.
- The source and destination are the current executable and a random temporary
  sibling; asset names are rejected if they contain separators or are not plain
  file names.

**Residual.** On a filesystem without xattr support, `listxattr` returns
`ENOTSUP` and the code treats it as "nothing to preserve"; this is safe but
cannot preserve a capability that the filesystem cannot store. The
`security.capability` regression test skips when not root or when `setcap` is
unavailable, so the exact capability path is root-gated; the mode/xattr
preservation test runs unprivileged. A failed xattr copy aborts the update
before replacing the binary.

### 5.4 Test-only allocator in `crates/sito-stats/src/metrics.rs`

`CountingAllocator` lives in `#[cfg(test)] mod allocation_tests` and is installed
with `#[global_allocator]` only in the test binary. It delegates `alloc`,
`alloc_zeroed`, `dealloc` and `realloc` to `System` and increments a thread-local
counter. The `GlobalAlloc` contract is therefore upheld by delegation; no
production target links this allocator.

### 5.5 Other `unsafe`

`geteuid` in the root-gated capability test, `set_var`/`remove_var` in
serialized test guards, and `setxattr` in updater tests are test-only. No
production FFI exists outside the two scopes above.

## 6. Secrets and file permissions

| Secret / file | Control | Evidence |
|---|---|---|
| `config.toml` | Atomic temp file narrowed to `0600` before content is written; fsync, rename; HA tokens not world-readable | `sito-api::config_writer`, `docs/security-audit.md` |
| `users.toml` | Atomic rewrite `0600`; TOTP secrets sealed with `totp.key`; legacy plaintext migrated on load; sanitized recovery backup `0600` | `test_users_file_encrypts_totp_secret`, `test_plaintext_totp_secret_migrates_on_load`, `test_reset_admin_backup_seals_legacy_plaintext`, `test_totp_key_file_is_0600` |
| `totp.key` | Created `0600` with `create_new`; wider modes repaired | `test_key_file_created_0600_and_repaired` |
| HA signing key | `0600`, created with mode at open; wider modes repaired | `crates/sito-ha/src/crypto/signing.rs` tests |
| HA CA/server/slave keys | `0600`; reusing an existing CA repairs `ca.key` without rewriting it | `test_reusing_ca_repairs_insecure_key_mode`, `test_generate_complete_ha_certs_set` |
| `ha_state.toml`, `ha_watermark.toml` | Atomic writes `0600` | `test_async_persist_roundtrip_and_permissions`, `test_watermark_persists_0600_and_loads_on_restart` |
| `stats.db`, WAL, SHM, `stats-salt` | `0600`, repaired on open; salt symlink refused; short/corrupt salt is a hard error | `test_stats_files_are_private_and_loose_permissions_are_repaired`, `test_salt_persists_and_corrupt_salt_is_rejected` |
| Backup archive | `config.toml` member `0600`; metadata non-secret | `test_backup_config_member_is_mode_0600` |
| Updater downloads | Assets `0600`; signature scratch `0700`; temp exe `0600` then preserved mode/xattrs; backup retained only until rename succeeds | `test_private_signature_dir_is_0700`, `test_replace_restores_backup_when_rename_fails` |
| Installer env file | Created with `umask 077`, `0600`, never overwritten or removed by uninstall | `scripts/test-systemd-hardening.sh` |
| Service logs | Headers and cookies are not logged; config/HA secrets are redacted | source review, `docs/security-audit.md` |

**Residual.** A local root or data-directory reader can read the files; file
permissions defend against other local users, not root compromise. Operators
must keep the config/data directories and backups on trusted storage. The
`users.toml` plaintext migration path is fail-closed for unparseable files and
does not copy raw secrets into the backup.

**Low local-race residual (R-14).** The atomic config and `users.toml` writers
create the temporary sibling with the process umask and narrow it to `0600`
before writing any content. A local user who opens the empty inode during that
short window can retain a read descriptor and observe the eventual content.
Content is never written while the file is group/world-readable, and the
directory is normally root-owned, so this is a local-only hardening gap rather
than a remote exposure. The recommended fix is `OpenOptionsExt::mode(0o600)` at
creation; it is not rc.1-blocking.

## 7. SSRF, bootstrap and redirect review

- Subscription HTTP: `http`/`https` only; redirects disabled; proxies disabled;
  target resolved and pinned; every resolved address checked with the shared
  denylist; `file://` is allowlisted to the data directory or explicit roots and
  rejects pseudo-filesystems and non-regular files.
- Bootstrap: RD=1; the same denylist applies to A/AAAA answers; a denied-only
  answer fails rather than being cached; `upstream.allow_private_targets` is the
  only hostname opt-in; explicit IP literals are the operator allowlist path.
- DoH upstream: production `HttpsUpstream::new` disables redirects and ambient
  proxies, pins resolved addresses and validates the server name. The
  `with_client` escape hatch is documented as caller-responsibility.
- Updater: repository allowlist, fixed GitHub API endpoints, HTTPS download-host
  allowlist, capped streaming download, signature policy. The residual redirect
  trust is recorded in §3.5.

## 8. Auth, session, re-authentication, CSRF and WebSocket Origin review

The controls in §3.6 were reviewed against the audit findings P1-15, P1-16,
P1-20, P2-45 and P2-46. The important invariants are:

- Cookie-authenticated mutating requests fail closed when `Origin`/`Referer` is
  missing or cross-origin; `Origin: null` is always rejected.
- The CSRF cookie and the request token must both match the session token; a
  Bearer-authenticated request does not need the cookie token but still needs a
  same-origin `Origin` when it presents one.
- Re-authentication tickets are bound to account, session and credential epoch,
  have a five-minute TTL, are capped at 10,000 live tickets, and are consumed
  before the sensitive mutation. A failure after consumption leaves the ticket
  consumed.
- Querylog WebSocket credentials never come from the query string. Session
  clients need a same-origin Origin; Bearer clients may omit it.
- Login/re-auth/change-password cap attacker-controlled input before Argon2 and
  share the lockout path.

No open finding in this area. The explicit API-token and token-TTL opt-outs in
§3.6 are the only accepted exceptions.

## 9. HA v2 identity, CA and SAN review

The HA transport identity is bound in three places:

1. **Peer certificate**: BLAKE3 pin or CA chain. CA-only is a supported trust
   mode; a configured CA validates chain, validity, hostname/SAN even when a pin
   is also present. `allow_unpinned_tls` applies only when neither trust anchor
   exists.
2. **Signed bundle**: Ed25519 signature over the payload hash, with the master
   key fingerprint and shared config digest inside the signed identity. A
   same-term key change requires higher-term promotion.
3. **Persisted watermark**: term, version, payload hash, shared-config digest,
   signing-key fingerprint and timestamp; a restart cannot replay or early-ACK a
   locally edited shared configuration.

Evidence: `test_server_ca_only_verification_and_wrong_ca`,
`test_pin_plus_ca_enforces_san`,
`test_client_cert_chain_must_match_configured_ca`,
`test_expired_server_certificate_is_rejected`,
`test_signed_identity_must_match_key_and_config`,
`test_same_term_key_rotation_requires_promotion`,
`test_watermark_persists_signing_key_fingerprint`,
`test_restore_preserves_term_and_rejects_v1_state`.

The CA-only mode is documented in the HA runbook and configuration reference;
it does not require the insecure opt-out. The remaining HA risks are operational
(no automatic promotion, no edit-time read-only enforcement) and are listed in
§13.

## 10. DNSSEC threat update

The remote-attacker model is unchanged: an on-path or malicious upstream may
strip, forge or replay DNSSEC data. The validator must produce `Secure` only
with a complete authenticated chain and must never serve a cached `Secure`
answer from a removed policy. The Phase 2 policy-epoch work closes the removal
case; the strict `Indeterminate` path is closed; the delegation-denial and
CNAME cases are pinned by the tests in §3.2. The remaining DNAME case fails
closed and is accepted in §4.

## 11. `deny.toml` suppression review

`deny.toml` currently ignores two advisories. Neither was removed without
verifying the graph; both suppressions remain in place.

### 11.1 RUSTSEC-2026-0374 — `basic-toml`

- **Graph:** `basic-toml 0.1.10` is a build-time dependency of
  `askama_derive 0.16.1` (via `askama`/`askama_macros`). `cargo tree -i
  basic-toml@0.1.10 --workspace --all-features` shows the proc-macro path; it is
  not linked into the shipped runtime binary.
- **Impact/reachability:** build-host only. A malicious or buggy TOML parser
  could affect the build, not a running resolver. The crate is unmaintained and
  has no safe upgrade yet.
- **Expiry/review:** remove when `askama` moves off `basic-toml`; re-review by
  **2027-01-31**.
- **Local note:** `cargo deny check advisories` reported
  `advisory-not-detected` for this ID, meaning the current local advisory DB did
  not match it; CI's advisory DB is expected to detect it. The suppression is
  kept for CI stability, not used to silence a detected reachable issue.

### 11.2 RUSTSEC-2026-0543 — `chrono`

- **Graph:** `chrono 0.4.45` is a direct dependency of `sito`, `sito-api`,
  `sito-clients`, `sito-ha`, `sito-stats` and `sito-test`, and a transitive
  dependency of `croner 4.0.2` and the dev-only `prometheus-parse`. The
  `deny.toml` comment describing it as croner/prometheus-parse-only understates
  the graph.
- **Impact/reachability:** `chrono` is reachable in production for timestamps,
  schedule/timezone evaluation, HA and CLI formatting. The advisory is
  "unmaintained", not a known exploitable memory-safety CVE at review time. The
  risk is that future bugs will not receive upstream fixes.
- **Expiry/review:** re-review by **2027-01-31**; remove the suppression when
  `chrono` is maintained again or the direct and transitive users migrate to a
  maintained time crate.
- **Decision:** keep the suppression for rc.1. Removing it today would fail
  `cargo deny` and would not remove the code from the binary.

## 12. Verification evidence

Run on `67269ea` on 2026-11-21:

| Command | Result |
|---|---|
| `cargo fmt --all --check` | Pass |
| `cargo clippy --workspace --all-features --all-targets --locked -- -D warnings` | Pass |
| `cargo test --workspace --all-features --locked --no-run` | Pass (all test/binaries compiled) |
| `cargo test --workspace --all-features --locked` | 1,819 passed, 0 failed, 0 ignored |
| `cargo test -p sito-dnssec --locked` | 170 passed |
| `cargo test -p sito-filter --locked` | Pass |
| `cargo test -p sito-rewrites --locked` | 41 passed |
| `cargo test -p sito-clients --locked` | 110 passed |
| `cargo test -p sito-transport --locked` | 107 passed |
| `cargo test -p sito-upstream --locked` | 84 passed |
| `cargo test -p sito-stats --locked` | 86 passed plus Prometheus exposition |
| `cargo test -p sito-ha --locked` | 147 passed |
| `cargo test -p sito-api --all-features --lib --locked` | 375 passed |
| `cargo test -p sito-core --test config_v2 --locked` | 26 passed |
| `cargo test -p sito-test --features ha --test m11_ha_partition --test m11_dnssec_security --test m9_acceptance` | Pass |
| `cargo test -p sito-test --features ha,embed-ui --test m6_acceptance --test m10_api_security` | 7 + 15 passed |
| `python3 scripts/check_test_matrix.py` | 783 unique named tests/checks resolve |
| `python3 scripts/test_check_test_matrix.py` | 4 passed |
| `python3 scripts/check_markdown_links.py --github` | Pass (71 files) |
| `python3 scripts/check_migration_guide.py --github` | Pass (9 BC IDs) |
| `python3 scripts/check-fuzz-targets.py` | Pass (5 targets) |
| `python3 scripts/test_check_fuzz_targets.py` | 11 passed |
| `python3 scripts/test_check_bench_regression.py` | 18 passed |
| `bash scripts/test-compose-defaults.sh` | Pass |
| `bash scripts/test-systemd-hardening.sh` | Pass |
| `bash contrib/tests/test-installer.sh` | Pass (installer E2E OK) |
| `bash scripts/test-verify-release-gate.sh` | 11 cases, 0 failures |
| `bash scripts/test-release-workflow.sh` | Pass |
| `cargo deny check advisories` | advisories ok (with expected not-detected warning for the reviewed suppression) |
| `git diff --check` | Pass |

## 13. Residual risk register

| ID | Residual | Severity | Disposition |
|---|---|---|---|
| R-1 | DNAME decoded as `RData::Unknown`; validate/strict returns SERVFAIL, log-only returns AD=0 | P1 (availability/compatibility) | **Accepted for rc.1**; fail-closed test required; re-review by 2027-01-31 or hickory upgrade |
| R-2 | 24-hour fuzz campaign is a release-checklist item and has not been run for rc.1; nightly smoke is the active evidence | Release evidence | Deferred to the release checklist; do not claim a 24h clean run |
| R-3 | Real 1.9.3 data-directory migration acceptance, SQLite schema migration and `/api/v2` compatibility are not implemented | Migration scope | Deferred; config v1→v2 and HA v1 rejection are covered by tests |
| R-4 | Image scan is linux/amd64 only; the published release image is smoke-tested with `--version`/`check-config`, not a live DNS query | Release evidence | Deferred to WP-3.1; PR container smoke does run a live DNS query |
| R-5 | `dns.bind` defaults to wildcard; no default-deny DNS client ACL | Exposure | Operator firewall/ACL is the documented mitigation |
| R-6 | HA API mutations on a slave are rejected, but direct config-file edits are not rejected at edit time and there is no automatic promotion | Availability | Documented; shared-field drift is detected after the write |
| R-7 | Stats query-log anonymization is forward-only; `keep_aggregates` clear and 1M-row/90-day soak remain capacity residuals | Privacy/capacity | Documented; forward-only rewrite is deferred |
| R-8 | `chrono` is unmaintained and reachable in production | Supply chain | Suppression accepted; review by 2027-01-31 |
| R-9 | `basic-toml` is unmaintained and build-time only | Supply chain | Suppression accepted; review by 2027-01-31 |
| R-10 | `allow_unpinned_tls` / `allow_insecure_ws` are explicit insecure opt-outs | Operator choice | Documented; a configured pin/CA is always enforced |
| R-11 | Rate limits are per prefix, not per account; lockout map is bounded; token expiry can be disabled | Auth/DoS | Documented operator trade-offs |
| R-12 | Self-updater follows HTTPS redirects; initial and asset URLs are host-checked, signatures are mandatory by default | Supply chain | Accepted for rc.1; add redirect revalidation in a future hardening pass |
| R-13 | macOS `pktinfo` path is compile-gated but not CI-covered | Platform coverage | Treat Linux as the tested platform for rc.1 |
| R-14 | Config/`users.toml` temp files are created with the process umask and narrowed to `0600` before content is written; a local opener in the window can retain a read descriptor | Local-only low | Accepted for rc.1; recommended `OpenOptionsExt::mode(0o600)` hardening in a future pass |

No open P0. The only open P1 is the DNAME sub-item (R-1), which is fail-closed
in validate/strict mode and accepted for rc.1. All other residuals are
availability, exposure, release-evidence or supply-chain items with an owner or
review date.

## 14. Threat-model delta

The Phase 3 tree does not add a new remotely reachable trust boundary. The
changes since the Phase 2 audit are documentation, verification and the test
matrix checker. The threat model remains:

- **Remote network attacker:** bounded by DNSSEC fail-closed validation,
  admission/rate limits, response shaping and SSRF-filtered outbound fetches.
- **Malicious list or upstream data:** bounded by parser budgets, fail-closed
  snapshot retention and DNSSEC.
- **Stolen admin session:** bounded by re-authentication tickets, CSRF/Origin
  checks, session epochs and `no-store` responses.
- **Compromised HA peer:** bounded by mTLS pin/CA validation, signed bundles,
  term/version continuity and secret stripping.
- **Local data-directory attacker:** equivalent to local compromise; file modes
  protect against other users, not root.
- **Supply-chain attacker:** bounded by SHA-pinned actions, `cargo deny`,
  cosign-signed releases, mandatory signatures by default and digest-pinned
  images.

The accepted residuals above are the complete list for the rc.1 threat model.
