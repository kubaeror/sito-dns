# Catalog coverage matrix (F2f)

This page audits the 2.0 catalog plan's F2f test/docs list against the tree.
It names the existing evidence for each requirement and records the few focused
additions made during the audit. It is not a second test plan: F2a–F2d tests
are linked, never duplicated or weakened.

Scope: the embedded HostlistsRegistry metadata, the Filtering catalog picker,
the per-group services picker, the runtime list refresh/status paths those
selections use, and the license/attribution/help text. See
[Embedded catalog](catalog.md) for behaviour and the
[release-time refresh runbook](catalog.md#release-time-refresh-runbook).

## Requirement → evidence

| Requirement | Existing evidence | Status |
| --- | --- | --- |
| Parse and validate the embedded catalog | `embedded_catalog_parses_and_validates`, `committed_catalog_has_pinned_shape`, `category_mapping_and_counts_are_non_empty`, `no_filter_body_or_icon_fields` in `crates/sito-clients/src/catalog.rs` | Covered |
| Reject invalid entries and references | `duplicate_filter_id_is_rejected`, `duplicate_service_id_is_rejected`, `empty_filter_name_is_rejected`, `empty_service_rules_are_rejected`, `unknown_references_are_rejected` | Covered |
| Catalog schema version | `unsupported_catalog_version_is_rejected`; loader rejects unknown versions and fields | Covered |
| SHA-256 pin and canonical bytes | `generator_check_passes_against_committed_catalog`, `generator_check_rejects_content_and_line_ending_tampering`; `python3 scripts/generate-catalog.py --check` | Covered |
| No runtime catalog fetch | `catalog_module_has_no_network_path` (new source/manifest tripwire); `docs/catalog.md` scope statement; release gate row 17 and the CI catalog-check step | **Added + covered** |
| Add from catalog (multiple, one apply) | `test_filtering_add_catalog_handler_adds_multiple_lists_once`; `test_add_catalog_route_preserves_repeated_selected_fields_through_csrf` | Covered |
| Already-added entries are disabled and skipped | `test_catalog_page_views_sorted_and_already_added_flags`, `test_catalog_lists_to_add_maps_dedupes_and_skips_existing`, `test_filtering_catalog_modal_renders_selection_controls` | Covered |
| Dedupe repeated ids and case-insensitive name/URL | `test_catalog_lists_to_add_maps_dedupes_and_skips_existing`; services: `test_group_blocked_services_matches_ids_case_insensitively` | Covered |
| Empty selection is a no-op | `test_filtering_add_catalog_handler_rbac_and_empty_selection` (empty catalog add persists nothing); `test_selected_catalog_ids_reads_only_selected_field` (blank `selected` values are dropped) | Covered |
| Invalid, deprecated, unknown and oversized selections write nothing | `test_catalog_lists_to_add_rejects_unknown_deprecated_and_oversize`, `test_filtering_add_catalog_handler_rejects_invalid_selection_without_partial_write`, `test_filtering_add_catalog_apply_failure_persists_nothing`; services: `test_clients_group_services_handler_rejects_duplicates`, `test_clients_group_services_handler_rejects_oversized_selection`, `test_clients_group_services_handler_rejects_unknown_group_and_service` | Covered |
| Filter-list add/remove/toggle and custom URL | `test_filtering_custom_url_add_toggle_and_delete_round_trip` (new); `test_add_filter_list_returns_201_with_body` (API); `test_filtering_catalog_empty_degrades_without_broken_modal` (custom-URL fallback still renders) | **Added + covered** |
| Services add/remove/toggle per group | `test_clients_group_services_handler_adds_and_removes`, `test_clients_group_services_handler_preserves_schedules`, `test_clients_group_services_handler_creates_implied_default_group` | Covered |
| Bundled-only/legacy services survive and can be removed | `test_clients_service_views_marks_configured_bundled_only_services_unlisted`, `test_clients_group_services_handler_preserves_bundled_only_services` | Covered |
| Catalog-only services are accepted; zero-rule entries are unavailable | `test_clients_service_views_groups_and_catalog`, `test_clients_service_views_marks_zero_rule_catalog_service_unavailable`, `test_group_blocked_services_accepts_every_catalog_service`, `test_group_blocked_services_rejects_zero_rule_catalog_service`, `test_clients_group_services_handler_accepts_every_catalog_service` | Covered |
| Corrupt/missing catalog degrades without a broken form | `test_filtering_catalog_empty_degrades_without_broken_modal`, `test_clients_service_views_corrupt_catalog_degrades`, `test_clients_blocked_services_without_catalog_degrades`, `test_bundled_list_views_corrupt_manifest_returns_runtime_rows_without_panic` | Covered |
| Runtime refresh/status/error after adding a list | `test_filtering_refresh_route_success_and_failure` (new route-level `/api/v2/filtering/refresh` success + 500 retention), `test_filtering_status_is_exposed`, `test_filter_lists_expose_real_rule_counts`; engine failures: `test_all_list_failure_is_observable_and_not_advertised_ready`, `test_reload_retains_rules_from_failed_lists` | **Added + covered** |
| Size limits and SSRF for list bodies | `test_reload_rejects_list_over_configured_max_list_bytes` (engine list-body cap), `test_cache_read_rejects_oversized_file` (cache cap), `test_empty_200_body_is_rejected`, `test_html_200_body_is_rejected`, `test_private_targets_are_rejected_without_network_access`, `test_denied_target_ip_ranges`, `test_m9_security_ssrf_url_scheme_allowlist` | Covered (existing downloader/engine gates) |
| Viewer URL redaction | `test_filtering_page_redacts_subscription_urls_below_operator`, `test_redact_text_urls_preserves_punctuation_and_hides_credentials` | Covered |
| License and attribution | `catalog_attribution_names_embedded_source` (new); `committed_catalog_has_pinned_shape`; `THIRD_PARTY_NOTICES` | **Added + covered** |
| UI docs and help text match behaviour | `test_filtering_catalog_modal_renders_selection_controls`, `test_filtering_catalog_metadata_is_html_escaped`, `test_clients_blocked_services_picker_renders_groups_and_modal`, `test_clients_blocked_services_shared_modal_renders_once`, `test_clients_blocked_services_metadata_is_html_escaped`, `test_render_all_views`; [configuration reference §8](configuration-reference.md#8-filtering--ad--malware-blocking-engine) now names the catalog/custom-URL path | Covered |
| Custom URL remains available | `test_filtering_catalog_empty_degrades_without_broken_modal`, `test_filtering_custom_url_add_toggle_and_delete_round_trip`, `test_add_filter_list_returns_201_with_body` | Covered |

## New evidence added by this audit

- `catalog_module_has_no_network_path` — a source/manifest tripwire (not a
  formal proof) that the production catalog module reads `CATALOG_JSON`, has no
  obvious HTTP-client/socket path, and that `sito-clients` does not depend on an
  HTTP client.
- `catalog_attribution_names_embedded_source` — asserts
  `THIRD_PARTY_NOTICES` names AdguardTeam/HostlistsRegistry, both upstream index
  URLs, the upstream “GNU General Public License, version 3” phrase, the
  metadata-only statement and the no-filter-list-body statement.
- `test_filtering_custom_url_add_toggle_and_delete_round_trip` — handler/config
  round trip for the custom-URL fallback's add, duplicate-name conflict, toggle
  both ways and delete path, including reading the persisted name/URL/refresh
  interval back from `config.toml`.
- `test_filtering_refresh_route_success_and_failure` — route-level
  `/api/v2/filtering/refresh` success and staging-failure retention, previously
  absent.
- `docs/catalog.md` release-time refresh runbook and explicit 2.0 non-goals.
- `docs/release-verification.md` gate row 17 with the corrected focused command
  and expected evidence.
- CI `test` job step `Verify the embedded catalog and pin are current`.

## Deliberate gaps

- No browser/JavaScript E2E test (the modal interactions are covered by
  rendered-HTML assertions plus handler tests). Adding a browser harness is
  outside this release's test stack.
- No signed or remote catalog-update test: 2.0 does not implement that path.
  The absence is documented in the catalog guide and has a source/manifest
  tripwire in `catalog_module_has_no_network_path`; that test is not proof that
  no network path can ever exist.
- List-body size-cap evidence lives in the filter engine/downloader tests
  (`test_reload_rejects_list_over_configured_max_list_bytes`,
  `test_cache_read_rejects_oversized_file`), and SSRF evidence in the shared
  downloader tests. The catalog supplies URLs, so the existing gates apply
  without a catalog-specific duplicate.
- `/api/v2/filtering/refresh` is now covered at the route level; scheduled
  refresh timing and the UI “Update All” JavaScript are not separately
  browser-tested.
