# Audit 6 — P0/P1 test evidence matrix (D14)

Every P0 and P1 finding from the 2.0 readiness audit is mapped to at least one
named test (or a named script check for release/installer policy) that failed
before the 1.9.4 fix and passes on this branch. The command column is the
focused command; the full gate remains:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features --locked
cargo deny check
python3 scripts/check_config_reference.py --github
python3 scripts/check_markdown_links.py
bash scripts/check-error-swallowing.sh
```

Blank/deferred rows are explained in `docs/release-notes-1.9.4.md` and
`progress.md`. A test name without a crate prefix is a unit test in the crate
named by the command.

| ID | Named test / check | Focused command |
|---|---|---|
| P0-1 | `test_fresh_bootstrap_certificate_requires_renewal`, `test_legacy_self_signed_bootstrap_requires_renewal`, `test_acme_bootstrap_issuance_all_transports_and_renewal` | `cargo test -p sito-transport test_fresh_bootstrap_certificate_requires_renewal`; `cargo test -p sito-test --test m11_acme test_legacy_self_signed_bootstrap_requires_renewal` |
| P0-2 | `test_parent_delegation_nsec_cannot_prove_nxdomain_below_cut`, `test_parent_delegation_nsec3_cannot_prove_nxdomain_below_cut`, `test_parent_delegation_nsec3_nodata_only_denies_ds`, `test_ds_nodata_at_delegation_is_secure` | `cargo test -p sito-dnssec parent_delegation` |
| P1-1 | `test_forged_covering_rrsig_still_probes_unsigned_delegation`, `test_signed_cname_to_stripped_target_without_ds_denial_is_bogus`, `test_m11_cd1_bypasses_post_fetch_indeterminate`, `test_dname_unknown_rdata_fails_closed`; DNAME handling remains a documented residual (see `docs/audit6.md`) | `cargo test -p sito-dnssec forged_covering_rrsig`; `cargo test -p sito-dnssec test_dname_unknown_rdata_fails_closed`; `cargo test -p sito-test --test m11_dnssec_security test_m11_cd1_bypasses_post_fetch_indeterminate` |
| P1-2 | `test_m11_blocked_key_fetch_is_bounded_and_servfails`, `test_m11_eight_hop_chain_is_bounded_end_to_end` | `cargo test -p sito-test --test m11_dnssec_security test_m11_blocked_key_fetch_is_bounded_and_servfails` |
| P1-3 | `test_slave_goes_not_ready_when_master_stops_sending_frames` | `cargo test -p sito-test --test m11_ha_partition test_slave_goes_not_ready_when_master_stops_sending_frames` |
| P1-4 | `test_restart_with_locally_modified_shared_config_does_not_early_ack_synced`, `test_legacy_watermark_without_digest_forces_full_apply` | `cargo test -p sito-test --test m11_ha_partition test_restart_with_locally_modified_shared_config_does_not_early_ack_synced` |
| P1-5 | `test_delayed_same_version_fork_ack_after_newer_publish_is_divergence` | `cargo test -p sito-test --test m11_ha_partition test_delayed_same_version_fork_ack_after_newer_publish_is_divergence` |
| P1-6 | `test_publish_bundle_propagates_sanitize_failure_and_rejects_oversize`, `test_file_watcher_rejects_oversized_bundle_and_rolls_back` | `cargo test -p sito-test --test m11_ha_partition test_publish_bundle_propagates_sanitize_failure_and_rejects_oversize` |
| P1-7 | `test_hostile_line_and_rule_count_hit_parse_budget`, `test_reload_budget_abort_retains_previous_snapshot_and_sets_status`, `test_combined_multi_list_substring_budget_is_rejected` | `cargo test -p sito-filter test_hostile_line_and_rule_count_hit_parse_budget` |
| P1-8 | `test_zero_yield_list_retains_previous_snapshot`, `test_zero_yield_initial_load_fails_closed`, `test_all_list_failure_is_observable_and_not_advertised_ready` | `cargo test -p sito-filter zero_yield` |
| P1-9 | `test_partial_invalid_dnstype_and_denyallow_tokens_reject_rule`, `test_ip_identified_client_cannot_spoof_exception_with_untrusted_id` | `cargo test -p sito-filter test_partial_invalid_dnstype_and_denyallow_tokens_reject_rule`; `cargo test -p sito-rewrites test_ip_identified_client_cannot_spoof_exception_with_untrusted_id` |
| P1-10 | `test_doq_quic_windows_and_stream_caps_are_bounded`, `test_doq_rate_check_before_body_read`, `test_doq_global_stream_semaphore_rejects_excess_streams` | `cargo test -p sito-transport test_doq_quic_windows_and_stream_caps_are_bounded` |
| P1-11 | `test_doh_rate_check_before_body_read`, `test_doh_global_request_cap_returns_503`, `test_doh_truncates_oversized_response` | `cargo test -p sito-transport test_doh_rate_check_before_body_read` |
| P1-12 | `test_acme_without_443_listener_falls_back_to_http01`, `test_failed_post_issuance_reload_is_reported`, `test_acme_bootstrap_issuance_all_transports_and_renewal` | `cargo test -p sito-test --test m11_acme test_acme_without_443_listener_falls_back_to_http01` |
| P1-13 | `test_response_shaping_strips_upstream_edns_and_opt_for_non_edns_clients`, `test_response_shaping_copies_question_flags_and_do`, `test_cache_hit_copies_current_question_and_flags` | `cargo test -p sito test_response_shaping_` |
| P1-14 | `test_doh_truncates_oversized_response`, `test_doh3_truncates_oversized_response` | `cargo test -p sito-transport truncates_oversized_response` |
| P1-15 | `test_totp_setup_and_enable_require_reauth_token`, `test_existing_totp_cannot_be_replaced_without_reauth`, `test_disable_totp_requires_reauth_token` | `cargo test -p sito-api test_totp_setup_and_enable_require_reauth_token` |
| P1-16 | `test_wizard_forbidden_after_setup_even_for_admin`, `test_wizard_completion_requires_setup_token_when_provisioned` | `cargo test -p sito-api test_wizard_forbidden_after_setup_even_for_admin` |
| P1-17 | `contrib/tests/test-installer.sh` atomic replacement/rollback cases | `bash contrib/tests/test-installer.sh` |
| P1-18 | `test_invalidate_domain_removes_exact_and_subdomains_only`, `test_root_name_is_cacheable_and_invalidation_flushes` | `cargo test -p sito-cache invalidate_domain` |
| P1-19 | `test_rollup_pii_hashes_client_ip_and_omits_names_by_default`, `test_rollup_retention_deletes_expired_domains_and_rows`, `test_delete_query_logs_default_clears_rollups`, `test_delete_query_logs_keep_aggregates_preserves_rollups`, `test_migration_from_v19_schema_hashes_rollups_and_stays_old_compatible`, `test_stats_files_are_private_and_loose_permissions_are_repaired`, `test_b3_ipv6_literal_is_hashed_not_treated_as_digest`, `test_backfill_neutralizes_malformed_rollup_payload`, `test_rollup_client_names_true_to_false_scrubs_existing_names`, `test_backfill_preserves_names_when_enabled`, `test_salt_persists_and_corrupt_salt_is_rejected`, `test_clear_query_log_vacuums_and_secure_delete_is_on` | `cargo test -p sito-stats rollup_pii`; `cargo test -p sito-stats delete_query_logs`; `cargo test -p sito-stats backfill` |
| P1-20 | `test_login_rejects_oversized_credentials_before_lockout`, `test_login_lockout_key_is_a_digest`, `test_active_lockout_is_not_evicted_at_capacity` | `cargo test -p sito-api test_login_rejects_oversized_credentials_before_lockout` |
| P1-21 | `scripts/test-verify-release-gate.sh`, `scripts/test-release-workflow.sh`, `scripts/test-release-attestation-gate.sh` | `bash scripts/test-verify-release-gate.sh` |
| P1-22 | `test_update_signature_policy_fails_closed`, `test_signature_policy_required_without_verifier_fails`, installer signature-policy cases | `cargo test -p sito test_update_signature_policy_fails_closed`; `bash contrib/tests/test-installer.sh` |
| P1-23 | `test_query_logs_include_total_is_optional`, `test_dashboard_cache_serves_within_ttl_and_clear_invalidates`, `test_stats_rate_limiter_blocks_after_budget` | `cargo test -p sito-stats include_total`; `cargo test -p sito-api stats_rate_limiter` |
| P1-24 | `test_retention_uses_bounded_chunks_and_records_success`, `test_retention_concurrent_insert_does_not_drop_batches`, `test_large_single_hour_is_row_bounded`, `test_large_same_timestamp_hour_is_row_bounded`, `test_retention_hour_discovery_uses_ts_index`, `test_retention_chunk_queries_use_ts_id_index`, `test_rollup_top_n_preserves_heavy_hitter_across_chunks`, `test_retention_startup_delay_schedules_recent_success`, `test_retention_metrics_record_success_and_failure` | `cargo test -p sito-stats retention_uses_bounded_chunks`; `cargo test -p sito-stats retention_concurrent_insert`; `cargo test -p sito-stats large_single_hour`; `cargo test -p sito-stats same_timestamp`; `cargo test -p sito-stats retention_hour_discovery`; `cargo test -p sito-stats retention_chunk_queries`; `cargo test -p sito-stats rollup_top_n`; `cargo test -p sito test_retention_startup_delay`; `cargo test -p sito-stats retention_metrics` |
| P1-25 | `test_health_probe_sets_recursion_desired`, `test_forced_refresh_picks_up_rotated_address`, `test_formerr_triggers_one_no_edns_retry` | `cargo test -p sito-upstream test_health_probe_sets_recursion_desired` |
| P1-26 | `test_runtime_snapshot_is_published_before_filter_reload`, `test_failed_hook_leaves_old_config_and_filter` | `cargo test -p sito-api test_runtime_snapshot_is_published_before_filter_reload` |
| P1-27 | `test_dnssec_policy_change_flushes_response_cache`, `test_policy_epoch_rejects_in_flight_insert_and_hides_old_entries`, `test_m11_policy_change_rejects_in_flight_cache_insert` | `cargo test -p sito-api test_dnssec_policy_change_flushes_response_cache`; `cargo test -p sito-cache test_policy_epoch_rejects_in_flight_insert_and_hides_old_entries`; `cargo test -p sito-test --test m11_dnssec_security test_m11_policy_change_rejects_in_flight_cache_insert` |

## 1.9.4 final-review additions

| Finding | Named test / check | Focused command |
|---|---|---|
| Group-only filtering | `test_group_only_custom_rules_are_sources`, `test_group_only_filter_configuration_resolves_end_to_end`, `test_group_rule_does_not_mask_failed_global_source`, `test_group_rule_does_not_mask_failed_global_source_end_to_end`, `test_invalid_only_group_rules_fail_closed`, `test_invalid_only_group_rules_fail_closed_with_allow_empty_list` | `cargo test -p sito-filter group_rule_does_not_mask`; `cargo test -p sito-filter test_invalid_only_group_rules_fail_closed`; `cargo test -p sito test_group_rule_does_not_mask_failed_global_source_end_to_end` |
| `[dns.tls]`/legacy ACME restart | `test_restart_required_tracks_effective_tls_and_legacy_acme` | `cargo test -p sito-api test_restart_required_tracks_effective_tls_and_legacy_acme` |
| `--no-setup` fresh boot | `test_no_setup_without_config_generates_random_password_on_loopback`, `test_no_setup_fresh_boot_resolves_a_query` | `cargo test -p sito test_no_setup_without_config`; `cargo test -p sito-test --test m11_no_setup` |
| ACME domain-change reissue | `test_certificate_needs_renewal_when_domains_change` | `cargo test -p sito-transport test_certificate_needs_renewal_when_domains_change` |
| D12 challenge readiness | `test_acme_readiness_no_80_no_443` | `cargo test -p sito-api test_acme_readiness_no_80_no_443` |
| IPv4-mapped rate key | `test_ipv4_mapped_ipv6_uses_ipv4_24_bucket` | `cargo test -p sito-transport test_ipv4_mapped_ipv6_uses_ipv4_24_bucket` |
| Filter-unavailable metric | `test_render_prometheus_golden_output`, `test_filter_metrics_are_reported` | `cargo test -p sito-stats filter_metrics` |
| DNAME | `test_dname_unknown_rdata_fails_closed` (wire decode as `Unknown`, strict Bogus/SERVFAIL, no AD); handling remains a documented residual | `cargo test -p sito-dnssec test_dname_unknown_rdata_fails_closed` |

## Deferred D3 — policy/transport/docs cleanup

| Finding | Named test / check | Focused command |
|---|---|---|
| CNAME target rewrite/block precedence | `test_cname_target_important_rewrite_is_dropped`, `test_cname_target_group_rewrite_does_not_suppress_global_block_end_to_end`, `test_cname_target_same_snapshot_rewrite_before_block_still_blocks`, `test_cname_target_same_snapshot_important_rewrite_before_block_still_blocks`, `test_standard_block_presence_ignores_rewrite_order` | `cargo test -p sito test_cname_target_`; `cargo test -p sito-filter test_standard_block_presence_ignores_rewrite_order` |
| DoH3 deadline parity (504) | `test_doh3_total_request_deadline_returns_gateway_timeout` | `cargo test -p sito-transport test_doh3_total_request_deadline_returns_gateway_timeout` |
| Stats 429 retry hint | `test_stats_rate_limit_response_has_retry_after` | `cargo test -p sito-api test_stats_rate_limit_response_has_retry_after` |
| Stats large-hour/index commands | `test_large_single_hour_is_row_bounded`, `test_large_same_timestamp_hour_is_row_bounded`, `test_retention_hour_discovery_uses_ts_index`, `test_retention_chunk_queries_use_ts_id_index` | `cargo test -p sito-stats large_single_hour`; `cargo test -p sito-stats same_timestamp`; `cargo test -p sito-stats retention_hour_discovery`; `cargo test -p sito-stats retention_chunk_queries` |
| Lockout capacity residual | Documented in `docs/release-notes-1.9.4.md` and `docs/security-audit.md` | `python3 scripts/check_markdown_links.py` |
| `with_client` caveat | Doc comment on `HttpsUpstream::with_client` | `cargo test -p sito-upstream` |

## Deferred D4a — stats/filter/transport quality cleanup

| Finding | Named test / check | Focused command |
|---|---|---|
| Query-log 429 retry hint | `test_querylog_rate_limit_response_has_retry_after` | `cargo test -p sito-api test_querylog_rate_limit_response_has_retry_after` |
| DoH3 deadline reset branch | `test_doh3_deadline_resets_stream_when_response_already_started`, `test_doh3_deadline_sends_gateway_timeout_when_writable`, `test_doh3_deadline_resets_stream_when_gateway_timeout_fails` | `cargo test -p sito-transport doh3_deadline` |
| Filter dropped-class counters | `test_excessive_ac_and_prefix_patterns_are_capped_before_build`, `test_excessive_regex_patterns_are_capped_without_disabling_other_classes` | `cargo test -p sito-filter excessive_` |
| Warm zero-source status retention | `test_warm_zero_source_transition_is_failed_and_retains_snapshot` (seeded failed list + dropped regex) | `cargo test -p sito-filter warm_zero_source` |
| Retention wrapper no longer detailed-only | `test_compat_cleanup_retention_applies_default_rollup_retention` | `cargo test -p sito-stats compat_cleanup_retention` |
| Writer busy timeout / retry budget / shutdown bound | `test_on_disk_busy_timeout_is_30s`, `test_writer_retry_budget_is_bounded_and_counts_dropped_batch`, `test_shutdown_flush_deadline_counts_dropped_batch`, `test_shutdown_counts_in_flight_normal_flush`, `test_writer_waits_out_a_slow_write_lock_without_dropping`, `test_flush_retry_delay_is_bounded_and_grows` | `cargo test -p sito-stats writer::tests` |

## Deferred D4b — auth/upstream/tests/docs cleanup

| Finding | Named test / check | Focused command |
|---|---|---|
| Re-auth lockout threshold | `test_reauth_lockout_triggers_on_the_fifth_failure` | `cargo test -p sito-api test_reauth_lockout_triggers_on_the_fifth_failure` |
| Re-auth oversized input on locked account | `test_reauth_rejects_oversized_credentials_before_lockout` | `cargo test -p sito-api test_reauth_rejects_oversized_credentials_before_lockout` |
| Re-auth ticket consumed after session purge | `test_enable_totp_consumes_ticket_after_session_purge` | `cargo test -p sito-api test_enable_totp_consumes_ticket_after_session_purge` |
| Sync DNSSEC API fails closed without a fetcher | `test_sync_validate_response_fails_closed_without_key_fetcher` | `cargo test -p sito-dnssec test_sync_validate_response_fails_closed_without_key_fetcher` |
| Port reservation broker release/commit | `port_reservations_release_on_drop_and_commit_transfers_ownership` | `cargo test -p sito-test-support port_reservations` |
| Full-buffer QR and ID checks are independent | `test_plain_udp_ignores_full_buffer_junk_with_matching_id_and_no_qr`, `test_plain_udp_ignores_full_buffer_junk_with_qr_and_wrong_id` | `cargo test -p sito-upstream full_buffer_junk` |
| Direct probe rejects FORMERR/BADVERS | `test_probe_rejects_edns_failure_replies` | `cargo test -p sito-api test_probe_rejects_edns_failure_replies` |
| HA `retry_at` reflects the actual retry schedule | `test_ha_publish_report_retry_at_matches_actual_schedule` | `cargo test -p sito-api test_ha_publish_report_retry_at_matches_actual_schedule` |

## Deferred D5 — final test/UI/metric nits

| Finding | Named test / check | Focused command |
|---|---|---|
| Pending TOTP enrollment hides enrollment-start forms (starter and replace) | `test_account_template_suppresses_starter_form_during_pending_enrollment`, `test_account_template_suppresses_replace_form_during_pending_enrollment`, `test_account_template_shows_enrollment_forms_without_pending_setup`, `test_self_service_totp_enrollment_for_all_roles` | `cargo test -p sito-api --all-features test_account_template_`; `cargo test -p sito-api --all-features test_self_service_totp_enrollment_for_all_roles` |
| Response shaping aligns ID/opcode/AA with the current query | `test_response_shaping_copies_question_flags_and_do`, `test_cache_hit_copies_current_question_and_flags` | `cargo test -p sito --lib test_response_shaping_`; `cargo test -p sito --lib test_cache_hit_copies_current_question_and_flags` |
| DNSSEC sync outcome recorded exactly once | `test_sync_validate_response_fails_closed_without_key_fetcher` | `cargo test -p sito-dnssec test_sync_validate_response_fails_closed_without_key_fetcher` |

## WP-1.2 — normalized domain and client identity

| Finding | Named test / check | Focused command |
|---|---|---|
| IDN/punycode, trailing dot, uppercase, wildcard labels (P2-31..P2-35) | `test_normalized_domain_table`, `test_normalized_domain_root_is_representable`, `test_normalized_domain_serde_roundtrip_and_normalizes_on_deserialize`, `test_normalized_domain_suffix_matching` | `cargo test -p sito-core normalized_domain` |
| Invalid labels, punycode and length limits | `test_normalized_domain_invalid_inputs`, `test_normalized_domain_label_and_name_length_limits`, `test_normalized_domain_ascii_constructor_keeps_wire_semantics`, `test_normalized_domain_idna_wire_constructor` | `cargo test -p sito-core normalized_domain` |
| IDN gap in filter lists and `$denyallow` | `test_filter_patterns_and_denyallow_normalize_idn`, `test_wildcard_and_prefix_patterns_normalize_idn`, `test_exact_patterns_reject_wildcard_labels` | `cargo test -p sito-filter test_filter_patterns_and_denyallow_normalize_idn`; `cargo test -p sito-filter test_wildcard_and_prefix_patterns_normalize_idn` |
| IDN cache invalidation | `test_invalidate_domain_evicts_idn_punycode_entries` | `cargo test -p sito-cache test_invalidate_domain_evicts_idn_punycode_entries` |
| IDN/trailing-dot rewrite domains | `test_idn_and_trailing_dot_rewrite_domains_match_punycode_queries`, `test_idn_rewrite_entries_match_punycode_queries` | `cargo test -p sito-rewrites test_idn_` |
| Shared CIDR v4/v6 matcher (P2-97..P2-99) | `test_ipv4_prefix_zero_and_host_prefix`, `test_ipv4_network_boundaries_and_host_bits`, `test_ipv6_prefix_zero_and_full_prefix`, `test_mixed_address_families_never_match`, `test_prefix_bounds_are_validated`, `test_cidr_parse_rejects_invalid_input`, `test_from_str_and_new_constructor` | `cargo test -p sito-core net::tests` |
| D10 identity trust table | `test_identity_trust_table`, `test_unauthenticated_identity_never_matches_policy`, `test_context_identity_preserves_provenance`, `test_untrusted_context_provenance_cannot_match_policy`, `test_identity_source_serde_names_match_as_str` | `cargo test -p sito-core identity_tests` |
| Registry provenance (P1-9) | `test_identity_source_is_recorded_for_authenticated_matches`, `test_identity_source_is_untrusted_for_wire_claims_and_unverified_leases`, `test_trusted_routeros_hostname_without_entry_keeps_routeros_provenance` | `cargo test -p sito-clients test_identity_source`; `cargo test -p sito-clients test_trusted_routeros_hostname_without_entry_keeps_routeros_provenance` |
| `$client` policy gate (P1-9) | `test_client_name_requires_authenticated_identity`, `test_guessable_sni_label_does_not_grant_identity` | `cargo test -p sito-filter test_client_name_requires_authenticated_identity`; `cargo test -p sito-filter test_guessable_sni_label_does_not_grant_identity` |
| Rewrite exception policy gate (P1-9) | `test_exception_requires_authenticated_identity`, `test_ip_identified_client_cannot_spoof_exception_with_untrusted_id`, `test_unidentified_client_id_does_not_bypass_exception` | `cargo test -p sito-rewrites test_exception_requires_authenticated_identity`; `cargo test -p sito-rewrites test_ip_identified_client_cannot_spoof_exception_with_untrusted_id` |
| Serde/backwards compatibility of `ClientContext` | `test_client_context_serde_defaults_are_backwards_compatible` | `cargo test -p sito-core test_client_context_serde_defaults_are_backwards_compatible` |
