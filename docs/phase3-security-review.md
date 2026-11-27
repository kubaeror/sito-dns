# 2.0.0 Security Review and Threat Model Update

**Date:** 2026-11-27
**Commit:** `39ba6da71f1068dd7da2ebf339909328bff2df26` (`39ba6da`)
**Scope:** frozen 2.0.0 release tree on `feat/2.0.0` (workspace version
`2.0.0`; the `v2.0.0` tag and publication are release-manager steps);
read-only code and release-configuration review
**Companion documents:** [security audit and threat model](security-audit.md),
[P0/P1 test matrix](audit6-test-matrix.md), [2.0 claim matrix](2.0-claim-matrix.md),
[HA runbook](runbook-ha.md), [ADR-0010](adr/0010-ha-automatic-promotion.md),
[ADR-0011](adr/0011-default-deny-dns-client-acl.md)

This review updates the Phase 3 review originally run at
`67269ea` on 2026-11-21 to the final 2.0.0 tree. The earlier review was correct
for its commit but several of its “deferred” gaps were delivered later; this
document records what is true at `39ba6da`. Historical release notes and
point-in-time audits remain historical and are not rewritten.

## 1. Verdict

| Item | Result |
|---|---|
| Open P0 | **None.** P0-1 (ACME bootstrap) and P0-2 (DNSSEC delegation denial) remain closed and have named regression tests. |
| Open P1 | **R-1 DNAME only.** It is fail-closed in `validate`/`strict` mode and is accepted for 2.0.0 as an availability/compatibility limitation (§4). P1-2 through P1-27 remain closed and mapped to named tests. |
| Test matrix integrity | Every backticked test/script name in `docs/audit6-test-matrix.md` resolves (`python3 scripts/check_test_matrix.py`, **821** unique tokens on this tree). |
| API surface | `/api/v2` is the only mounted administrative API; `/api/v1` is `404` with no alias, redirect or facade. Auth/RBAC, CSRF, re-auth, account rate limits, cursor binding and WebSocket credentials reviewed. |
| DNS client ACL | ADR-0011 deny-by-default for fresh wizard installs that keep the checked default, compatibility `allow` for upgrades/headless/opt-out, typed default, HA capability and provisioning gate, bundle sanitization, hot reload and data-plane ordering reviewed. |
| Client identity | `clients.trust_arp` is default false and MAC-only; identity is registry/provenance based; ARP snapshot changes invalidate positive and negative caches. |
| HA promotion | Opt-in default off; witness lease/fencing, acquisition/renewal/expiry, quiesce/reconcile, durable fence, rotated-state/old-key fail-closed, corrupt-state-in-place, no slave publish and capability readiness reviewed. |
| Outbound EDNS | COOKIE/NSID/padding/DAU/DHU/N3U stripped; ECS policy-driven; DO/payload/DNSSEC preserved; response shaper keeps only EDE across cache boundaries. |
| DB/PII | Schema v2 fail-closed startup, `sito db migrate`, `SITO_DB_AUTO_MIGRATE`, 0600 backups, chunked/resumable anonymize and `keep_aggregates`, and diagnostic-only `stats_watermark` reviewed. |
| Secrets/unsafe/FFI | Key/state/cert/token modes, no private-key/token logging, five production unsafe modules and the advisory suppressions reviewed (§5, §6, §11). |
| Supply chain/release | `cargo deny check` green; SHA-pinned actions, digest-pinned bases, SBOM/provenance/image-signature gates and the release-bound catalog pin reviewed. |
| 2.0.0 security decision | **No security fix is required before the final tag.** The DNAME residual and the accepted operational/supply-chain residuals have owners and review dates in §13. |

No open P0. The only open P1 is R-1 (DNAME), accepted because the
validate/strict path fails closed; the other P1 findings remain closed.

Every P0 (`P0-1`..`P0-2`) and P1 (`P1-1`..`P1-27`) row in
[`docs/audit6-test-matrix.md`](audit6-test-matrix.md) maps to at least one
backticked named test or script. `python3 scripts/check_test_matrix.py`
resolves all 821 unique backticked tokens against this tree.

## 2. Method and evidence

The review used the following evidence sources:

- Source inspection of the production paths named in the audit-6 findings and
  in the eight 2.0 focus areas (API v2, client ACL, `trust_arp`, HA promotion,
  outbound EDNS, DB/PII, secrets/unsafe/FFI, supply chain/release).
- The focused tests in [`docs/audit6-test-matrix.md`](audit6-test-matrix.md)
  plus the 2.0 feature tests listed in §3 and §12.
- The mechanical check `scripts/check_test_matrix.py` and its fixture suite
  `scripts/test_check_test_matrix.py`.
- The deployment/release checks (`scripts/test-compose-defaults.sh`,
  `scripts/test-systemd-hardening.sh`, `contrib/tests/test-installer.sh`,
  `scripts/test-verify-release-gate.sh`, `scripts/test-release-workflow.sh`,
  `scripts/test-release-attestation-gate.sh`).
- `cargo deny check` and `cargo tree` for the two suppressions.
- The controller-recorded frozen full gate on `39ba6da`: fmt, clippy
  all-features/all-targets `-D warnings`,
  `cargo test --workspace --all-features --locked` (65 suites, **2,469 passed /
  0 failed / 5 ignored**), `cargo test --workspace --locked` (**2,229 passed /
  0 failed / 5 ignored**), catalog check and the docs/config/migration/
  test-matrix/fuzz/bench checks.

This review is read-only for product code, configuration and tests. The only
changes are documentation truth updates. The full workspace suite was not
rerun; the focused reruns and their results are in §12.

## 3. Audit streams

### 3.1 API v2 only, auth ordering, RBAC and OpenAPI

**Current control.** `create_router` nests only `/api/v2`; the fallback returns
`404`, so `/api/v1` has no alias, redirect or compatibility facade. Every
non-login `/api/v2` handler takes a `RequireViewer`/`RequireOperator`/`RequireAdmin`
extractor, which validates the Bearer token or session before the handler body
runs; `/metrics` uses the same check when `web.metrics_auth = true` (default).
Mutating requests pass the shared Origin/Referer + CSRF middleware before
handlers. Sensitive account/credential mutations additionally require the
session-bound, single-use `X-Reauth-Token`; self-service password changes
verify the current password and TOTP when enrolled. Authenticated requests are
charged once against the account-wide API rate limit and receive `429` with
`Retry-After`. The OpenAPI document is generated from the same route handlers
and advertises only `/api/v2` paths, with the cookie/bearer schemes and the
conditional re-auth header.

**Evidence.** `test_api_surface_uses_only_v2_and_removes_v1` (v1 paths 404, v2
status 401/200, every OpenAPI path under `/api/v2`),
`test_openapi_paths_match_router`,
`test_openapi_security_schemes_and_operation_security`,
`test_querylog_stream_rejects_query_token`,
`test_stolen_admin_session_requires_reauth_for_sensitive_changes`,
`test_delete_user_and_token_require_sensitive_reauth`,
`test_account_limit_is_independent_and_session_token_share_a_bucket`,
`test_rate_limit_rejection_has_problem_details_and_retry_after`,
`test_sensitive_responses_have_no_store_and_vary_cookie`.
Focused reruns: `test_api_surface_uses_only_v2_and_removes_v1` and
`test_querylog_stream_rejects_query_token` passed.

**Residual risk.** Admin API tokens are exempt from the interactive re-auth
ticket (an explicit operator decision; they cannot manage TOTP). Token expiry
can be disabled with `auth.token_default_ttl_days = 0`. Rate limits are per
network prefix for unauthenticated traffic and per account for authenticated
traffic, not per endpoint. The Swagger UI and `/api/docs/openapi.json` are
intentionally unauthenticated documentation surfaces; restrict them at the
reverse proxy if the deployment requires it.

### 3.2 DNS client ACL (ADR-0011)

**Current control.** The ACL is a pure function of the shared `[clients]`
configuration and the observed peer address. The pipeline evaluates it before
identity resolution, multi-question/formerr handling, cache, filter, rewrite
and upstream work. Order is deny (authoritative) → explicit allow → opt-in
client-entry allow (`allow_entry_ids`, default false) → typed
`default_policy`. The compiled index is immutable per registry snapshot and
hot-swapped atomically; a malformed index fails closed. Denied sources get
`REFUSED` or no response (`deny_response = "drop"`; DoH/DoH3 return `204`) and
write no query-log row, discovery entry or expensive-stage metrics. The ACL
reads no DoH path, SNI, header, MAC/ARP, RouterOS lease, secret or group.

The typed `default_policy` remains `"allow"` so upgrades and headless installs
keep 1.9.x behaviour. The **fresh-install wizard presents `deny` checked by
default**; keeping that default writes `default_policy = "deny"` and an explicit
allow set, while unchecking it is an explicit operator choice to keep `allow`.
The wizard requires
acknowledgement for loopback-only and public networks and exact
`ALLOW ALL` confirmation for a catch-all. Setup-token/re-auth recovery never
rewrites an existing ACL. On HA, the ACL is shared configuration in the signed
bundle; the sanitizer preserves it while stripping only per-client secrets. A
master enforcing deny reports `acl_capability_missing` while a connected peer
does not advertise `client_acl`. A fresh slave reports `acl_unprovisioned` and
does not bind DNS until the first watermarked bundle; a restart with a
watermark serves the persisted applied configuration.

**Evidence.** `test_acl_deny_is_authoritative`,
`test_acl_entry_ids_do_not_admit_by_default`,
`test_acl_doh_path_sni_and_secret_are_not_credentials`,
`test_acl_refused_udp_has_no_pipeline_side_effects`,
`test_acl_denied_query_writes_no_query_log_or_discovery`,
`test_acl_drop_suppresses_response_and_counts_drop`,
`test_acl_precedes_wire_error_paths`,
`test_acl_hot_reload_swaps_policy_atomically`,
`test_acl_doh_trusted_proxy_xff_cannot_override_raw_peer`,
`test_wizard_fresh_template_explicit_allow_still_shows_acl`,
`test_wizard_public_peer_is_not_seeded`,
`test_wizard_loopback_only_requires_ack`,
`test_wizard_manual_catch_all_requires_allow_all_confirmation`,
`test_wizard_setup_token_recovery_preserves_existing_acl`,
`test_ha_dns_gate_waits_for_setup_and_applied_bundle`,
`test_fresh_slave_is_acl_unprovisioned_until_first_bundle`,
`test_restarted_slave_with_watermark_serves_persisted_config`,
`test_ha_invalid_acl_bundle_rejects_whole_push`,
`test_mixed_version_acl_capability_is_required_only_for_deny`,
`test_ha_sanitizer_preserves_acl_and_strips_only_client_secrets`.
Focused reruns: all 21 `sito-clients` ACL tests and
`test_acl_hot_reload_swaps_policy_atomically` passed.

**Residual risk.** The ACL is not a blanket default-deny for upgrades,
headless installs or hand-written configuration; those keep `allow` until the
operator opts in. `dns.bind` still defaults to wildcard, so a host firewall
and/or a non-wildcard bind remains defense in depth. The HA DNS gate is tested
through the startup seam, not with a full socket-level listener integration
test. A trusted reverse proxy necessarily makes the proxy address the ACL
source; allow the proxy network and enforce client policy at the proxy.

### 3.3 Client identity and `clients.trust_arp`

**Current control.** Identity comes from the client registry with provenance:
configured IP/CIDR, a configured shared secret (DoH path or DoT/DoQ SNI), a
configured MAC entry, or a verified RouterOS lease. A raw DoH path/SNI label,
an unverified lease or a display name is never a policy identity. `trust_arp`
defaults to **false**; when true it can grant only a trusted
`IdentitySource::Mac` for an ARP-resolved MAC, even when no entry lists that
MAC. It does not invent a name/group or consult another ARP attribute. A
stronger trusted identity is never overwritten. The ARP snapshot is refreshed
off the query path (2 s); a new snapshot increments the epoch, so both positive
and negative caches from the old generation are ignored. MAC IDs use the strict
parser; IP/CIDR-looking IDs never become MAC identities.

**Evidence.** `test_identity_trust_table`,
`test_untrusted_context_provenance_cannot_match_policy`,
`test_client_name_requires_authenticated_identity`,
`test_guessable_sni_label_does_not_grant_identity`,
`test_arp_snapshot_change_invalidates_positive_cache`,
`test_arp_snapshot_change_invalidates_negative_cache`,
`test_unlisted_arp_mac_is_display_only_without_trust_arp`,
`test_trust_arp_grants_mac_identity_for_unlisted_mac`,
`test_trust_arp_is_off_by_default_and_configured_mac_still_works`,
`test_trust_arp_never_overrides_stronger_identity`,
`test_ip_or_cidr_id_is_never_a_mac_identity`.
Focused rerun: all 5 `trust_arp` tests passed.

**Residual risk.** MAC identity is only as trustworthy as the local L2/ARP
environment; an on-link attacker can spoof ARP. This is why `trust_arp` is
default-off and MAC-only. Identity is not authentication of the DNS client;
use DoH/DoT client secrets or network segmentation where that matters.

### 3.4 Filtering and rewrites

**Current control.** Parser and compiler budgets are enforced before
materialisation (line, token, byte, rule and DFA limits). Empty or zero-yield
list responses are rejected unless `filtering.allow_empty_list = true`; a
failed reload retains the previous snapshot and is observable. Rule precedence
is `Allow > Rewrite > Block` within a tier, group overlay wins ties,
`$important` outranks standard, and invalid modifier tokens reject the whole
rule. Rewrite exceptions require an authenticated, provenance-bearing
identity; a raw DoH path or SNI string cannot grant it. Group-budget failures
publish only the non-regex subset, never a silently emptied set.

**Evidence.** `test_hostile_line_and_rule_count_hit_parse_budget`,
`test_zero_yield_list_retains_previous_snapshot`,
`test_partial_invalid_dnstype_and_denyallow_tokens_reject_rule`,
`test_ip_identified_client_cannot_spoof_exception_with_untrusted_id`,
`test_exception_requires_authenticated_identity`,
`test_group_budget_failure_publishes_non_regex_subset`.
The focused `sito-filter`/`sito-rewrites` suites are recorded in the frozen
gate.

**Residual risk.** A subscription-list publisher can still change blocking
decisions (availability/quality), but cannot execute code or widen rule scope
through malformed tokens. Group/global precedence remains complex; the
acceptance suite is the guard. `file://` list access is restricted to the data
directory or explicit programmatic roots.

### 3.5 Upstreams, SSRF and outbound EDNS

**Current control.** Subscription schemes are limited to `http`, `https` and
`file`. HTTP fetches disable redirects and proxies, resolve and pin the target
address, and reject loopback, RFC 1918/ULA, link-local/metadata, CGNAT,
benchmarking, documentation, reserved and IPv4-embedding IPv6 ranges. Bootstrap
answers apply the same denylist and denied-only answers are not cached.
`upstream.allow_private_targets` is the explicit hostname opt-in; configured IP
literals are the documented operator allowlist path. Production DoH disables
redirects and ambient proxies and pins the resolved address; the `with_client`
escape hatch is documented caller responsibility.

Outbound EDNS is sanitized in one place: `COOKIE`, `NSID`, `PADDING`, `DAU`,
`DHU` and `N3U` are removed from every upstream query. ECS is policy-driven
(`off` strips and deduplicates cache keys; `forward` clamps IPv4 to `/24`,
IPv6 to `/56`, clears scope and zeroes host bits; a zero-length opt-out is
never forwarded). The DO bit, configured payload behaviour and DNSSEC records
are preserved. The query cache keys on DO/CD/EDNS/ECS but not on client-only
options. On the response path, `ResponseShaper` rebuilds OPT from the client
query, retains only RFC 8914 EDE across a cache/upstream boundary, clears AD
unless the client signalled DNSSEC awareness and validation permitted it, and
strips DNSSEC records/DO-only options for DO=0 clients.

**Evidence.** `test_private_targets_are_rejected_without_network_access`,
`test_bootstrap_rejects_private_answers_by_default`,
`test_bootstrap_rejects_nat64_embedded_private_answers`,
`test_bootstrap_rejects_ipv4_embedded_private_answers`,
`test_bootstrap_denied_answer_is_not_cached`,
`test_manager_rejects_private_hostname_before_building_transport`,
`test_doh_new_ignores_ambient_https_proxy`,
`test_doh_redirects_are_not_followed`,
`test_m9_security_ssrf_url_scheme_allowlist`,
`test_upstream_query_strips_client_only_edns_options_ecs_off`,
`test_upstream_query_strips_client_only_edns_options_ecs_forward`,
`test_upstream_query_without_edns_stays_without_edns`,
`test_upstream_query_force_dnssec_adds_edns_without_client_options`,
`test_upstream_query_force_dnssec_preserves_configured_payload`,
`test_cache_key_ignores_client_only_edns_options`.
Focused reruns: the five EDNS/cache tests passed.

**Residual risk.** Explicit IP literals bypass the denylist by design. A
compromised bootstrap resolver can still answer with a public address that the
operator did not intend; DNSSEC and the configured upstream policy remain the
controls. The updater no longer accepts arbitrary redirects (see §7), but a
compromised allowlisted download host is mitigated by the mandatory signature
policy, not by host allowlisting alone.

### 3.6 Authentication, sessions, re-authentication and WebSocket Origin

**Current control.** Passwords use Argon2id with a four-operation concurrency
cap; API tokens, session cookies, setup tokens and TOTP codes use constant-time
comparison. Login inputs are length-capped before hashing; lockout keys are
BLAKE3 digests and active lockouts are not evicted. TOTP setup, enable,
replacement and disable require a short-lived, session-bound, single-use
re-authentication ticket. Session cookies are `HttpOnly`, `SameSite=Strict`,
`__Host-` on TLS, and authenticated responses are `no-store` with
`Vary: Cookie`. Mutating requests require same-origin `Origin`/`Referer` and a
session-bound CSRF token; missing origin fails closed for cookie sessions.
Querylog WebSocket upgrades reject `Origin: null` and cross-origin requests,
require an Origin for session clients, and accept credentials only from a
Bearer header or cookie (never `?token=`).

**Evidence.** `test_login_rejects_oversized_credentials_before_lockout`,
`test_login_lockout_key_is_a_digest`,
`test_active_lockout_is_not_evicted_at_capacity`,
`test_argon2_verification_concurrency_is_bounded`,
`test_totp_setup_and_enable_require_reauth_token`,
`test_existing_totp_cannot_be_replaced_without_reauth`,
`test_disable_totp_requires_reauth_token`,
`test_websocket_origin_validation`,
`test_querylog_stream_rejects_query_token`,
`test_querylog_stream_accepts_bearer_header`,
`test_sensitive_responses_have_no_store_and_vary_cookie`.

**Residual risk.** Admin API tokens are exempt from sensitive
re-authentication (an explicit operator decision), and
`auth.token_default_ttl_days = 0` disables token expiry. The lockout map is
bounded at 10,000 entries; if every entry is an active lockout, a new key
relies on the per-IP login rate limit. Rate limits are per network prefix for
unauthenticated traffic, not per account. These are documented operator
trade-offs.

### 3.7 API and configuration integrity

**Current control.** Config writes run the same typed-section validation as
startup before persisting. Unknown keys and tables are rejected; v1 documents
are rejected with the migration command. Restart-only writes return `409` and
persist nothing. Restore archives are decompression-capped, unknown metadata
versions are rejected, and `config.toml` is written atomically with mode
`0600`. OpenAPI paths, methods, tags and security schemes match the router.
`/metrics` requires Viewer-or-higher authentication by default. `/health` is
generic; detailed reasons are on authenticated status endpoints.

**Evidence.** `test_unknown_keys_are_rejected_everywhere`,
`test_restart_only_write_is_conflict_and_not_persisted`,
`test_update_config_restart_only_is_conflict_and_not_persisted`,
`test_restore_archive_rejects_unknown_metadata_version`,
`test_backup_config_member_is_mode_0600`,
`test_openapi_paths_match_router`,
`test_openapi_security_schemes_and_operation_security`,
`test_sensitive_responses_have_no_store_and_vary_cookie`; the frozen gate
recorded 26 `config_v2` tests.

**Residual risk.** The admin UI is plain HTTP by default and must be kept on
loopback or behind a TLS reverse proxy. A malformed or unreadable config fails
closed rather than silently returning defaults. The config writer's
temporary-file creation race is R-14.

### 3.8 High availability: protocol v2, automatic promotion and rotation

**Replication control.** Replication uses mTLS, BLAKE3 certificate pinning,
optional CA validation with hostname/SAN checks, a constant-time shared token,
and Ed25519-signed bundles that bind the signing-key fingerprint and the shared
config digest. Term/version/fork continuity and a bounded publish history
prevent replay and division; a slave that misses `3 x ping_interval_secs`
leaves `Synced` and becomes not-ready. Publish outcomes distinguish connected,
queued, coalesced and no-delivery states. Bundles strip TLS/web keys, auth
material, RouterOS credentials and per-client shared secrets; node-local values
are restored on the slave. State, watermark and private keys are `0600`.

**Automatic promotion control.** Promotion is opt-in and **default false**
(`ha.promotion.enabled`; `candidate` is also false by default). A configured
candidate uses the external witness lease: acquire with the last published
`(version, hash)` baseline, quiesce, read peer reports during the reconcile
window, refuse an ahead/forked/unknown-hash peer, renew before the deadline,
publish, and only then become writable. The node is read-only from process
start until it holds a live lease and has published; a restart with the role
still `slave` never becomes writable from state alone. The engine fences on
lease loss/expiry, renewal conflict, witness record loss, clock/boot-id change,
state-write failure, role-switch failure, witness auth/protocol failure, and a
first publish that crosses the deadline. A durable `ha_fence.pending` +
`ha_fence.json` marker (0600) blocks every restart until the operator runs
`confirm-promotion`/`clear-fence`; a pending-only write is still a fence, and
both writes failing is a critical local failure. Late peers are latched and
reported, not silently ignored. Readiness reports
`promotion_peer_capability_missing` while a connected peer cannot report
`have_bundle_hash`; promotion stays off until peers are upgraded.

**State and rotation control.** Promotion-enabled startup loads
`ha_state.toml` strictly and validates the persisted signing-key identity
before acquisition. An old key paired with rotated state is refused with
`promotion_interrupted`; no bundle is prepared, re-signed or published. A
corrupt, v1, partial or foreign-cluster/node state file is refused with no
backup-and-reset: the file is left byte-for-byte in place and every restart
keeps failing closed until a matching backup is restored or the operator
explicitly moves it aside. The coordinator writes state through the shared
atomic `0600` writer. `sito ha rotate-signing-key --confirm` refuses a live
service or missing confirmation, backs up the key and state at `0600`
(preserving ownership), generates a new `0600` key, re-seals the state at a
strictly higher term/version, and prints the `master_pubkey`, witness term floor
and preserved published baseline without contacting the witness or publishing.
A term-only `lease-admin set --allow-equal-version` raises the witness term
without changing the published version/hash; a rotated master can then
acquire. Only a master/effective master can publish; a replica's API/UI
mutations are rejected (shared-field apply changes return
`urn:sito:ha:shared_config_read_only`), and a slave never writes the master
state or publishes a bundle.

**Evidence.** `test_master_rejects_v1_slave_and_keeps_listening`,
`test_restore_preserves_term_and_rejects_v1_state`,
`test_signed_identity_must_match_key_and_config`,
`test_same_term_key_rotation_requires_promotion`,
`test_slave_goes_not_ready_when_master_stops_sending_frames`,
`test_server_ca_only_verification_and_wrong_ca`,
`test_pin_plus_ca_enforces_san`,
`test_client_cert_chain_must_match_configured_ca`,
`test_expired_server_certificate_is_rejected`,
`test_publish_outcome_reports_connected_closed_and_queued`,
`test_state_persists_and_restores_across_restart`,
`corrupt_v1_and_foreign_state_fail_closed`,
`promotion_master_refuses_old_key_with_rotated_state_before_acquisition`,
`self_fence_persists_and_a_restart_refuses_to_acquire`,
`test_promotion_enabled_master_acquires_and_publishes`,
`test_promotion_fenced_master_restart_stays_read_only`,
`test_rotation_writes_new_key_backs_up_and_reseals_state`,
`test_old_key_no_longer_matches_rotated_state`,
`test_new_key_push_is_accepted_after_the_higher_term_and_version`,
`test_rotation_refuses_non_monotonic_term_and_version`,
`test_rotation_has_no_witness_or_lease_side_effects`,
`term_only_witness_bump_unblocks_a_rotated_master`,
`lease_admin_term_only_raises_the_term_on_an_equal_version_and_hash`,
`test_fresh_slave_is_acl_unprovisioned_until_first_bundle`,
`test_mixed_version_acl_capability_is_required_only_for_deny`.
Focused reruns: `corrupt_v1_and_foreign_state_fail_closed`,
`test_state_persists_and_restores_across_restart`,
`promotion_master_refuses_old_key_with_rotated_state_before_acquisition`,
`self_fence_persists_and_a_restart_refuses_to_acquire`,
`test_fresh_slave_is_acl_unprovisioned_until_first_bundle`,
`test_mixed_version_acl_capability_is_required_only_for_deny`,
`test_rotation_writes_new_key_backs_up_and_reseals_state` and
`test_old_key_no_longer_matches_rotated_state` passed.

**Residual risk.** `allow_unpinned_tls = true` and `allow_insecure_ws = true`
are explicit insecure opt-outs; a configured pin or CA is still enforced and
plaintext requires a non-empty shared token on both ends. There is no
automatic promotion unless the operator enables it; the manual procedure
remains supported. Direct edits of shared `config.toml` fields are not
rejected at edit time; drift is detected after the write and requires a full
apply (role/logging/legacy auth keys are excluded from the projection). A
partitioned slave keeps serving its last applied configuration while not-ready.
The witness is a single point of availability and a trusted safety authority
(R-15). The DNS gate is startup-seam tested (R-16).

### 3.9 Statistics, query log and PII

**Current control.** Hourly rollups use keyed BLAKE3 client identifiers; client
names are opt-in and can be scrubbed. Retention is row-bound per hour, clear
and vacuum are available, `keep_aggregates` is opt-in, and dashboard polling is
served from a 30-second cache with optional total counts. `keep_aggregates`
clears are hour/row-bounded, commit each chunk, resume safely, serialize with
retention, preserve concurrent rollup updates and bound the top-N
approximation. The per-install salt and SQLite database/WAL/SHM files are
`0600`; a corrupt/short salt is a hard error and a symlinked salt is refused.
The live-tail clone only happens when a subscriber exists.

Schema v2 is explicit. Server startup inspects the database without writes and
refuses an older schema unless `SITO_DB_AUTO_MIGRATE=1/true`; with the opt-in
it takes the shared migration lock, writes a `0600` backup, migrates, verifies
and only then opens it for serving. A newer, corrupt or unrecognized schema is
refused before any write. `sito db migrate` supports `--dry-run`,
`--no-backup`, refuses a live service, refuses to overwrite a backup and
restores ownership for root-run migrations. `sito db anonymize --all` rewrites
detailed rows in 1,000-row chunks (IPv4 `/24`, IPv6 `/56`, client name
cleared), commits each chunk, resumes after a crash, vacuums and truncates the
WAL when anything changed, and is idempotent. `stats_watermark` is written for
progress diagnostics and v1.9 compatibility only; no production path reads it
to skip rows, and backdated rows are aggregated on the next sweep.

**Evidence.** `test_rollup_pii_hashes_client_ip_and_omits_names_by_default`,
`test_rollup_retention_deletes_expired_domains_and_rows`,
`test_stats_files_are_private_and_loose_permissions_are_repaired`,
`test_salt_persists_and_corrupt_salt_is_rejected`,
`test_clear_query_log_vacuums_and_secure_delete_is_on`,
`test_live_tail_clone_only_with_subscribers`,
`test_retention_concurrent_insert_does_not_drop_batches`,
`test_keep_aggregates_clear_chunks_multiple_hours_and_preserves_rollups`,
`test_keep_aggregates_clear_resumes_after_mid_run_failure`,
`test_keep_aggregates_clear_merges_concurrent_rollup_update`,
`test_anonymize_query_log_chunk_boundary_and_resume`,
`test_anonymize_query_log_vacuums_and_secure_delete_is_on`.
Focused reruns: all 13 `db_migrate_cli` tests, all 9 `db_anonymize_cli` tests,
the keep-aggregates chunk/resume tests and the anonymize chunk/resume test
passed. The 1M-row/90-day capacity tests are `#[ignore]` evidence, not default
CI.

**Residual risk.** Live anonymization is forward-only; existing detailed rows
are rewritten only by the explicit offline command. The 1M/90-day capacity
evidence is gated (R-19). A local root/data-directory attacker can read the
database; this is local compromise, outside the remote threat model.

### 3.10 Operations, deployment and release integrity

**Current control.** The shipped Compose default binds the admin UI to
`127.0.0.1`, uses a named config volume and a non-local image; HA uses valid
DHCP hex and parameterized topology. The systemd unit and installer fallback
share `EnvironmentFile`, `UMask=0077`, `PrivateTmp`, `ProtectProc`,
namespace/SUID/personality restrictions and native syscall architecture. The
installer E2E covers fresh install, live upgrade, DB migration, rollback,
signature policy, capability handling and uninstall. Release actions are
SHA-pinned; release tags are gated on the required branch and green
`ci-gate`/`cargo-deny` checks; release archives are cosign-signed, a draft is
verified by `artifact-e2e`, and the multi-arch image is attested, scanned per
platform, signed and smoke-tested before publication.

**Evidence.** `scripts/test-compose-defaults.sh`,
`scripts/test-systemd-hardening.sh`,
`contrib/tests/test-installer.sh`,
`scripts/test-verify-release-gate.sh`,
`scripts/test-release-workflow.sh`,
`scripts/test-release-attestation-gate.sh`;
`.github/workflows/container.yml` builds the image and asserts a live DNS
rewrite; `.github/workflows/artifact-e2e.yml` verifies checksums, cosign
identity and every packaged binary's `--version`/`check-config`;
`docker-build-push` scans `linux/amd64`, `linux/arm64` and `linux/arm/v7` from
the published digest and runs the live DNS/health/API-v2/schema-v2 smoke.
These checks were green in the frozen gate; H4 reran the catalog check and
`cargo deny`, not the GitHub-hosted release workflows.

**Residual risk.** Image scanning fails only on **fixed** HIGH/CRITICAL
findings; unfixed findings are reported but do not block (R-4). The H1 24-hour
fuzz campaign is green at `39ba6da` (run 45922217501, 25/25 fuzz jobs, zero crash
artifacts); the H2 7-day live soak is in progress and is not claimed (R-2).
The root-gated HA certificate-ownership lane remains a manual/weekly workflow.
The Compose images stay pinned to `1.9.5` until the release manager moves them
at the final tag (H10); this is a release step, not a security gap.

### 3.11 Supply chain and dependency policy

**Current control.** `cargo deny` covers advisories, bans, licenses and
sources in CI. GitHub Actions are SHA-pinned; container bases are
digest-pinned; the Trivy scanner image is digest-pinned. Release archives are
cosign-signed and the release workflow checks the signature identity. The
installer requires signatures by default (`SITO_REQUIRE_SIGNATURE=1`, explicit
`=0` opt-out); the self-updater requires them by default
(`server.update_require_signature = true`). A present signature is always
verified even when optional; an incomplete or unverifiable pair fails closed.
Release assets include `SHA256SUMS` and an SPDX SBOM; the image carries
BuildKit provenance and an SPDX SBOM attestation. The embedded catalog is
release-bound by `CATALOG_SHA256` and the offline
`python3 scripts/generate-catalog.py --check`, which never uses the network.

**Evidence.** `cargo deny check` →
`advisories ok, bans ok, licenses ok, sources ok` (with the expected
`advisory-not-detected` warning for the basic-toml suppression);
`python3 scripts/generate-catalog.py --check` → `catalog check passed`;
`python3 scripts/test_check_bench_regression.py`,
`bash scripts/test-release-workflow.sh`,
`bash scripts/test-release-attestation-gate.sh` pass in the frozen gate.

**Residual risk.** The two unmaintained-crate suppressions below; per-arch
scanning ignores unfixed findings; and the release process still depends on
the GitHub Actions runner, cosign identity and the allowlisted download hosts.
These are tracked, not hidden.

## 4. P1-1 DNAME residual and 2.0.0 risk acceptance

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

**Risk acceptance for 2.0.0.** Accepted. The residual is closed only by a
hickory upgrade or a local DNAME implementation, both larger than this release
scope. The acceptance is contingent on the test above remaining green.
**Owner:** DNSSEC maintainer. **Accepted:** 2026-11-27. **Re-review:** on any
`hickory-proto` upgrade or by **2027-01-31**, whichever comes first.

## 5. Production `unsafe` and FFI review

The tree contains no `unsafe` in the DNS parser, filter, DNSSEC, cache, auth or
HA protocol logic. The production modules are `sito-transport::udp`,
`sito-transport::pktinfo`, `sito-api::updater`,
`sito-api::ui::handlers::wizard_acl` and `sito-ha::promotion::clock`. The only
other `unsafe` is test-only (the stats allocation counter, filter timing
helpers, test env/xattr/euid helpers).

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
by the compile gate but not exercised in CI (R-13).

### 5.3 `crates/sito-api/src/updater.rs` xattr, lock and ownership syscalls

**Scope.** `#[cfg(unix)]` production helpers preserve the existing executable's
extended attributes, notably `security.capability`, across the atomic update
rename; take a cross-process `flock` on the update lock; and, when running as
root, `fchown` a root-created lock file to the data-directory owner so the
unprivileged server can reuse it. Test-only helpers use `geteuid`/`setxattr`.

**Safety argument.**

- Xattr paths and attribute names are converted to `CString` first; an embedded
  NUL is rejected before the syscall. Size queries allocate exactly the
  reported size and retry on `ERANGE`; returned lengths are checked
  non-negative and truncated into the buffer. `listxattr` names are split,
  empty names dropped and each name re-encoded. `setxattr` receives a valid
  value pointer/length and its return code is checked. Any failure aborts the
  update before rename.
- `flock` receives a descriptor owned by a live `File` for the duration of the
  call; the lock is advisory and released on close. The lock path is opened
  with `O_NOFOLLOW` and mode `0600`.
- `geteuid` has no preconditions. `fchown` runs only after a root check and
  receives the live descriptor plus uid/gid taken from the data-directory
  metadata; its return code is checked. An unprivileged caller returns early.
- The source and destination are the current executable and a random temporary
  sibling; asset names are rejected if they contain separators or are not
  plain file names.

**Residual.** On a filesystem without xattr support, `listxattr` returns
`ENOTSUP` and the code treats it as "nothing to preserve"; this is safe but
cannot preserve a capability the filesystem cannot store. The
`security.capability` regression test skips when not root or when `setcap` is
unavailable, so the exact capability path is root-gated; mode/xattr
preservation runs unprivileged. A failed xattr copy aborts the update before
replacing the binary.

### 5.4 `crates/sito-api/src/ui/handlers/wizard_acl.rs` interface discovery

**Scope.** The first-boot wizard enumerates local interface addresses and
netmasks with `getifaddrs`/`freeifaddrs` to offer ACL candidates. The module is
`#[cfg(unix)]`; non-Unix returns no candidates.

**Safety argument.**

- The returned `ifaddrs` list is owned by the guard, which calls
  `freeifaddrs` exactly once on drop; a null list is never freed.
- Every node is checked non-null before dereference; `ifa_addr` is checked
  before its `sa_family` is read. Only `AF_INET`/`AF_INET6` entries are cast,
  and the cast follows the family check. `ifa_name` is read as a NUL-terminated
  `CStr` owned by the list.
- `ifa_netmask` is null-checked, its family is checked against the address
  family, and the mask is accepted only when it is a contiguous prefix. The
  address is masked before use; invalid prefixes are rejected.
- No pointer or list node escapes the function; all values are copied into
  owned candidate structures.

**Residual.** macOS/BSD are compile-gated but not CI-covered; Linux is the
tested platform. Interface enumeration is a first-boot UI convenience, not an
authorization decision; the operator still selects and acknowledges the ACL.

### 5.5 `crates/sito-ha/src/promotion/clock.rs`

**Scope.** `CLOCK_BOOTTIME` supplies the monotonic lease/fence clock and
suspend-inclusive deadlines for ADR-0010. Non-Linux returns an error rather
than silently using wall time.

**Safety argument.** `clock_gettime` receives a valid clock id and a writable
`timespec` for the duration of the call; the return code and the
seconds/nanoseconds ranges are checked before conversion. A failure is a typed
error that fences rather than extending a lease. `/proc/sys/kernel/random/boot_id`
is read as text and an empty/unreadable id is an error.

**Residual.** The clock is Linux-specific; non-Linux promotion is unsupported
rather than unsafe. A boot-id or wall-clock step is a fence condition by
design.

### 5.6 Test-only `unsafe`

`CountingAllocator` in `crates/sito-stats/src/metrics.rs` delegates
`alloc`/`alloc_zeroed`/`dealloc`/`realloc` to `System` and is installed only in
the test binary. `sito-filter::structures::timing` samples
`CLOCK_THREAD_CPUTIME_ID` in `#[cfg(test)]` code. `geteuid`, `set_var`,
`remove_var`, `setxattr` and test `flock` helpers are test-only. No production
FFI exists outside the five scopes above.

## 6. Secrets and file permissions

| Secret / file | Control | Evidence |
|---|---|---|
| `config.toml` | Atomic temp file narrowed to `0600` before content is written; fsync, rename; HA tokens not world-readable | `sito-api::config_writer`, R-14 |
| `users.toml` | Atomic rewrite `0600`; TOTP secrets sealed with `totp.key`; legacy plaintext migrated on load; sanitized recovery backup `0600` | `test_users_file_encrypts_totp_secret`, `test_plaintext_totp_secret_migrates_on_load`, `test_reset_admin_backup_seals_legacy_plaintext` |
| `totp.key` | Created `0600` at open with `create_new`; wider modes repaired | `test_totp_key_file_is_0600`, `test_key_file_created_0600_and_repaired` |
| HA signing key | `0600`, created with mode at open; wider modes repaired | `crates/sito-ha/src/crypto/signing.rs` tests |
| HA CA/server/slave/witness keys | `0600`; reusing an existing CA repairs `ca.key` without rewriting it | `test_reusing_ca_repairs_insecure_key_mode`, `test_generate_complete_ha_certs_set` |
| `ha_state.toml`, `ha_watermark.toml`, `ha_fence.*` | Atomic writes `0600` | `test_async_persist_roundtrip_and_permissions`, `test_watermark_persists_0600_and_loads_on_restart`, `marker_roundtrips_pending_then_final_and_blocks_restart` |
| Witness `lease.json`, lock, initialized marker | State dir `0700`; files `0600`; token file must be `0600` | `acquire_on_empty_state_grants_term_one_and_persists_files`, `token_file_permissions_are_enforced_at_startup` |
| `stats.db`, WAL, SHM, `stats-salt` | `0600`, repaired on open; salt symlink refused; short/corrupt salt is a hard error | `test_stats_files_are_private_and_loose_permissions_are_repaired`, `test_salt_persists_and_corrupt_salt_is_rejected` |
| Backup archive | `config.toml` member `0600`; metadata non-secret | `test_backup_config_member_is_mode_0600` |
| Updater downloads | Assets `0600`; signature scratch `0700`; temp exe `0600` then preserved mode/xattrs; backup retained only until rename succeeds; lock `0600`/`O_NOFOLLOW` | `test_private_signature_dir_is_0700`, `test_replace_restores_backup_when_rename_fails` |
| Installer env file | Created with `umask 077`, `0600`, never overwritten or removed by uninstall | `scripts/test-systemd-hardening.sh` |
| Service logs | Headers and cookies are not logged; config/HA secrets are redacted; TOTP debug is redacted | source review, `test_totp_setup_view_debug_redacts_enrollment_material` |

**Residual.** A local root or data-directory reader can read the files; file
permissions defend against other local users, not root compromise. Operators
must keep the config/data directories and backups on trusted storage. The
`users.toml` plaintext migration path is fail-closed for unparseable files and
does not copy raw secrets into the backup.

**Low local-race residual (R-14).** The atomic config and `users.toml` writers
create the temporary sibling with the process umask and narrow it to `0600`
before writing any content. A local user who opens the empty inode during that
short window can retain a read descriptor and observe the eventual content.
Content is never written while group/world-readable, and the directory is
normally root-owned, so this is a local-only hardening gap rather than a
remote exposure. The recommended fix is `OpenOptionsExt::mode(0o600)` at
creation; it is accepted, not rc-blocking.

**Latent debug residual (R-18).** `sito_ha::WitnessCert` derives `Debug` and
contains `key_pem`. No current production call site formats the whole struct,
so there is no active key leak; a redacted `Debug` is the recommended
hardening. This does not change the “no private-key logging” control today.

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
  allowlist, capped streaming download, signature policy, and a redirect policy
  that revalidates every hop against the HTTPS/host allowlist, rejects
  cross-host redirects, HTTPS downgrades, loops and excess hops. The residual
  trust is the allowlisted host plus the mandatory signature.

## 8. Auth, session, re-authentication, CSRF and WebSocket Origin review

The controls in §3.1/§3.6 were reviewed against the audit findings P1-15,
P1-16, P1-20, P2-45 and P2-46. The important invariants are:

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

## 9. HA v2 identity, CA, SAN and promotion review

The HA transport identity is bound in three places:

1. **Peer certificate**: BLAKE3 pin or CA chain. CA-only is a supported trust
   mode; a configured CA validates chain, validity, hostname/SAN even when a
   pin is also present. `allow_unpinned_tls` applies only when neither trust
   anchor exists.
2. **Signed bundle**: Ed25519 signature over the payload hash, with the master
   key fingerprint and shared config digest inside the signed identity. A
   same-term key change requires higher-term promotion.
3. **Persisted watermark/state**: term, version, payload hash, shared-config
   digest, signing-key fingerprint and timestamp; a restart cannot replay or
   early-ACK a locally edited shared configuration. Promotion state also binds
   the published `(version, hash)` baseline and the witness holder.

The automatic-promotion safety argument is: the witness lease is the
single-writer authority; the published baseline is the only value sent to the
witness; a pending bundle is never treated as published; a peer that is ahead,
forked or hash-unknown aborts reconciliation; a fenced node never re-acquires
across restarts; and a rotated state with the old signing key is refused before
acquisition. The DNS gate waits for setup completion and, on a fresh slave, the
first applied watermarked bundle.

Evidence: `test_server_ca_only_verification_and_wrong_ca`,
`test_pin_plus_ca_enforces_san`,
`test_client_cert_chain_must_match_configured_ca`,
`test_expired_server_certificate_is_rejected`,
`test_signed_identity_must_match_key_and_config`,
`test_same_term_key_rotation_requires_promotion`,
`test_watermark_persists_signing_key_fingerprint`,
`test_restore_preserves_term_and_rejects_v1_state`,
`promotion_master_refuses_old_key_with_rotated_state_before_acquisition`,
`self_fence_persists_and_a_restart_refuses_to_acquire`,
`two_candidates_only_one_acquires`,
`reconciliation_aborts_on_ahead_peer_and_publishes_nothing`,
`reconciliation_aborts_on_same_version_fork_and_unknown_hash`,
`test_fresh_slave_is_acl_unprovisioned_until_first_bundle`.

The CA-only mode is documented in the HA runbook and configuration reference;
it does not require the insecure opt-out. The remaining HA risks are
operational (witness availability/trust, direct-edit drift, startup-seam ACL
gate, no automatic promotion unless opted in) and are listed in §13.

## 10. DNSSEC threat update

The remote-attacker model is unchanged: an on-path or malicious upstream may
strip, forge or replay DNSSEC data. The validator must produce `Secure` only
with a complete authenticated chain and must never serve a cached `Secure`
answer from a removed policy. The Phase 2 policy-epoch work closes the removal
case; the strict `Indeterminate` path is closed; the delegation-denial and
CNAME cases are pinned by the tests in §3.5/§3.8. The remaining DNAME case
fails closed and is accepted in §4. A cache hit is only served with data when
its validation status is `Secure`/`Insecure` (or a fail-closed SERVFAIL), and
stale answers are never served as authenticated while validation is active.

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
- **Local note:** `cargo deny check advisories` reports
  `advisory-not-detected` for this ID, meaning the current local advisory DB did
  not match it; CI's advisory DB is expected to detect it. The suppression is
  kept for CI stability, not used to silence a detected reachable issue.

### 11.2 RUSTSEC-2026-0543 — `chrono`

- **Graph:** `chrono 0.4.45` is a direct dependency of `sito`, `sito-api`,
  `sito-clients`, `sito-ha`, `sito-stats` and `sito-test`, and a transitive
  dependency of `croner 4.0.2` and the dev-only `prometheus-parse`. The
  `deny.toml` comment describing it as croner/prometheus-parse-only understates
  the graph; this review records the actual direct dependency set.
- **Impact/reachability:** `chrono` is reachable in production for timestamps,
  schedule/timezone evaluation, HA and CLI formatting. The advisory is
  "unmaintained", not a known exploitable memory-safety CVE at review time. The
  risk is that future bugs will not receive upstream fixes.
- **Expiry/review:** re-review by **2027-01-31**; remove the suppression when
  `chrono` is maintained again or the direct and transitive users migrate to a
  maintained time crate.
- **Decision:** keep the suppression for 2.0.0. Removing it today would fail
  `cargo deny` and would not remove the code from the binary.

## 12. Verification evidence

Run on `39ba6da` on 2026-11-27. The controller-recorded frozen full gate on this
same SHA is green: fmt; clippy all-features/all-targets `-D warnings`;
`cargo test --workspace --all-features --locked` 65 suites, **2,469 passed / 0
failed / 5 ignored**; `cargo test --workspace --locked` **2,229 passed / 0
failed / 5 ignored**; `cargo deny check`; catalog check and the
docs/config/migration/test-matrix/fuzz/bench checks. H4 did not rerun the full
workspace suite.

Focused H4/H5 reruns:

| Command | Result |
|---|---|
| `cargo test -p sito-api --all-features --lib test_api_surface_uses_only_v2_and_removes_v1` | 1 passed |
| `cargo test -p sito-api --all-features --lib test_querylog_stream_rejects_query_token` | 1 passed |
| `cargo test -p sito-api --all-features --lib test_redirect_rejects_cross_host_target` | 1 passed |
| `cargo test -p sito-api --all-features --lib test_redirect_rejects_https_downgrade` | 1 passed |
| `cargo test -p sito-clients --all-features --lib acl` | 21 passed |
| `cargo test -p sito-clients --all-features --lib trust_arp` | 5 passed |
| `cargo test -p sito-ha --all-features --lib corrupt_v1_and_foreign_state_fail_closed` | 1 passed |
| `cargo test -p sito-ha --all-features --lib test_state_persists_and_restores_across_restart` | 1 passed |
| `cargo test -p sito-ha --all-features --lib promotion_master_refuses_old_key_with_rotated_state_before_acquisition` | 1 passed |
| `cargo test -p sito-ha --all-features --lib self_fence_persists_and_a_restart_refuses_to_acquire` | 1 passed |
| `cargo test -p sito-ha --all-features --lib test_fresh_slave_is_acl_unprovisioned_until_first_bundle` | 1 passed |
| `cargo test -p sito-ha --all-features --lib test_mixed_version_acl_capability_is_required_only_for_deny` | 1 passed |
| `cargo test -p sito-ha --all-features --lib test_rotation_writes_new_key_backs_up_and_reseals_state` | 1 passed |
| `cargo test -p sito-ha --all-features --lib test_old_key_no_longer_matches_rotated_state` | 1 passed |
| `cargo test -p sito --all-features --lib test_upstream_query_strips_client_only_edns_options` | 2 passed |
| `cargo test -p sito --all-features --lib test_upstream_query_force_dnssec_adds_edns_without_client_options` | 1 passed |
| `cargo test -p sito --all-features --lib test_cache_key_ignores_client_only_edns_options` | 1 passed |
| `cargo test -p sito --all-features --lib test_acl_hot_reload_swaps_policy_atomically` | 1 passed |
| `cargo test -p sito --all-features --lib test_acl_doh_path_sni_and_secret_are_not_credentials` | 1 passed |
| `cargo test -p sito --all-features --test db_migrate_cli` | 13 passed |
| `cargo test -p sito --all-features --test db_anonymize_cli` | 9 passed |
| `cargo test -p sito-stats --all-features --lib test_keep_aggregates_clear_chunks_multiple_hours_and_preserves_rollups` | 1 passed |
| `cargo test -p sito-stats --all-features --lib test_keep_aggregates_clear_resumes_after_mid_run_failure` | 1 passed |
| `cargo test -p sito-stats --all-features --lib test_anonymize_query_log_chunk_boundary_and_resume` | 1 passed |
| `cargo deny check` | `advisories ok, bans ok, licenses ok, sources ok` (expected `advisory-not-detected` warning for basic-toml) |
| `python3 scripts/generate-catalog.py --check` | `catalog check passed` |
| `python3 scripts/check_test_matrix.py` | 821 unique named tests/checks resolve |
| `python3 scripts/check_markdown_links.py` | Internal Markdown links OK (82 files) |
| `python3 scripts/check_migration_guide.py` | 12 breaking-change IDs each map to a migration step and affected doc/test |
| `git diff --check` | Pass |

## 13. Residual risk register

| ID | Residual | Severity | Disposition |
|---|---|---|---|
| R-1 | DNAME decoded as `RData::Unknown`; validate/strict returns SERVFAIL, log-only returns AD=0 | P1 (availability/compatibility) | **Open P1, accepted for 2.0.0**; fail-closed test required; owner DNSSEC maintainer; re-review by 2027-01-31 or hickory upgrade |
| R-2 | The H1 24-hour fuzz campaign is green at `39ba6da` (run 45922217501, 25/25 fuzz jobs, 17,281 s per shard, zero crash artifacts). The H2 7-day live soak started `2026-11-27T10:38+01:00` and is in progress; it is not recorded as complete for this SHA | Release evidence | H1 closed; soak remains an open release-checklist item; owner release manager; do not claim a clean soak until the accepted window and transcript are recorded |
| R-3 | Installer/container `config.toml` auto-migration remains deferred; config v1→v2 and the SQLite schema/PII migration are delivered | Migration scope | Documented product scope; owner ops; the config migration command is the supported path |
| R-4 | Image scan fails only on **fixed** HIGH/CRITICAL findings and depends on the scanner/runner | Release evidence | Accepted; owner release manager; unfixed findings are visible but non-blocking |
| R-5 | DNS ACL typed default is `allow`; only fresh wizard installs write `deny`; `dns.bind` defaults to wildcard | Exposure | Accepted compatibility trade-off; owner security reviewer; firewall/bind restriction is defense in depth |
| R-6 | HA shared `config.toml` edits are drift-detected after the write, not rejected at edit time; filtering/clients/rewrites/upstreams UI pages rely on the slave middleware 409 | Availability/operability | Accepted; owner HA maintainer; API/UI apply paths are covered, direct edits reconcile on the next push/restart |
| R-7 | Live query-log anonymization is forward-only; existing rows need the explicit offline `sito db anonymize --all`; capacity tests are gated | Privacy/capacity | Accepted; owner stats maintainer; the explicit command and 0600 backup path are documented |
| R-8 | `chrono` is unmaintained and reachable in production | Supply chain | Suppression accepted; owner security reviewer; review by 2027-01-31 |
| R-9 | `basic-toml` is unmaintained and build-time only | Supply chain | Suppression accepted; owner security reviewer; review by 2027-01-31 |
| R-10 | `allow_unpinned_tls` / `allow_insecure_ws` are explicit insecure opt-outs | Operator choice | Accepted; owner operator/HA maintainer; a configured pin/CA is always enforced and plaintext requires a token |
| R-11 | Rate limits are per prefix for unauthenticated traffic; lockout map is bounded; token expiry can be disabled | Auth/DoS | Accepted operator trade-offs; owner auth maintainer |
| R-12 | Updater redirects are restricted to an allowlisted GitHub host set, but an allowlisted-host compromise is mitigated by the mandatory signature policy | Supply chain | Accepted; owner release manager; signature required by default |
| R-13 | macOS `pktinfo`/`getifaddrs` paths are compile-gated but not CI-covered | Platform coverage | Accepted; owner platform maintainer; Linux is the tested platform |
| R-14 | Config/`users.toml` temp files are created with the process umask and narrowed to `0600` before content is written; a local opener in the window can retain a read descriptor | Local-only low | Accepted for 2.0.0; owner API maintainer; recommended `OpenOptionsExt::mode(0o600)` hardening |
| R-15 | The promotion witness is a single point of availability and a trusted safety authority; its compromise can break the single-writer guarantee | HA availability/trust | Accepted; owner HA maintainer; run on a separate hardened host and back up `lease.json`; review by 2027-01-31 |
| R-16 | The slave DNS/ACL gate is tested through the startup seam, not a full socket-level listener integration test | Test depth | Accepted; owner HA maintainer; startup predicate and worker/apply paths are covered separately |
| R-17 | `trust_arp` MAC identity can be spoofed by an on-link attacker | Network identity | Accepted; default off; owner security reviewer; use secrets/segmentation where identity matters |
| R-18 | `WitnessCert` derives `Debug` while containing `key_pem`; no current production path prints it | Latent secret exposure | Accepted low; owner HA maintainer; add redacted `Debug` in a hardening pass |
| R-19 | The 1M-row/90-day capacity/soak tests are `#[ignore]`/gated, not default CI | Capacity evidence | Accepted; owner stats maintainer; run as release evidence and record the result |
| R-20 | The query-log cursor is unkeyed (forgeable) but only readable by an authenticated Viewer and not a capability | API data scope | Accepted; owner API maintainer; a forged cursor stays within the viewer's query-log authorization |

No open P0. The only open P1 is R-1 (DNAME), which is fail-closed in
validate/strict mode and accepted for 2.0.0 with an owner and review date. All
other residuals are availability, exposure, release-evidence or supply-chain
items with an owner or review date.

## 14. Threat-model delta

The 2.0.0 tree does not add a new remotely reachable trust boundary without a
corresponding gate. The changes since the Phase 3 review at `67269ea` are the
final API v2 surface, the ADR-0011 DNS client ACL, `trust_arp`, ADR-0010
automatic promotion with an external witness, outbound EDNS stripping, the
schema-v2/PII migration, the hardened updater redirect policy and the
per-architecture release image gates. The threat model remains:

- **Remote network attacker:** bounded by fail-closed DNSSEC validation,
  default-deny ACL where enabled, admission/rate limits, response shaping and
  SSRF-filtered outbound fetches.
- **Spoofed/on-link client:** bounded by source-address ACL before identity,
  registry/provenance identity, default-off `trust_arp`, and the ARP epoch
  invalidation; MAC spoofing on the local segment is an accepted residual.
- **Malicious list or upstream data:** bounded by parser budgets, fail-closed
  snapshot retention, DNSSEC and outbound EDNS sanitation.
- **Stolen admin session:** bounded by re-authentication tickets, CSRF/Origin
  checks, session epochs and `no-store` responses.
- **Compromised HA peer:** bounded by mTLS pin/CA validation, signed bundles,
  term/version continuity, secret stripping and the rule that only a
  master/effective master publishes.
- **Compromised witness:** can defeat single-writer safety (accepted trust
  assumption) but cannot forge a signed configuration; run it separately and
  protect its token/state.
- **Local data-directory attacker:** equivalent to local compromise; file modes
  protect against other users, not root.
- **Supply-chain attacker:** bounded by SHA-pinned actions, `cargo deny`,
  cosign-signed releases, mandatory signatures by default, digest-pinned
  images, SBOM/provenance attestations, per-arch scans and the catalog pin.

The accepted residuals above are the complete list for the 2.0.0 threat model.
