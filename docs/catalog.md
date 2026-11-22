# Embedded catalog

`sito-clients` embeds a catalog of filter and blocked-service metadata derived
from the [AdGuard HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry).
The web UI uses the catalog to offer AdGuard-style filter and blocked-service
selection without making a network request to discover what is available.

The catalog is **metadata only**:

- filter ids, names, categories, descriptions, homepages, download/subscription
  URLs, versions, refresh intervals, languages and deprecation flags;
- blocked-service ids, names, groups and their small `||domain^` block rules;
- no filter-list text or list bodies;
- no `icon_svg` blobs in 2.0.

## Source and license

The upstream indexes are:

- <https://adguardteam.github.io/HostlistsRegistry/assets/filters.json>
- <https://adguardteam.github.io/HostlistsRegistry/assets/services.json>

AdguardTeam/HostlistsRegistry is licensed under GPL-3.0 and sito is
GPL-3.0-only, so embedding the metadata is license-compatible. Attribution and
the upstream URLs are recorded in `THIRD_PARTY_NOTICES` at the repository root
and in the catalog's own `source` block.

## Generation and update policy

The catalog is **release-bound**, not fetched at runtime. The binary embeds the
committed `crates/sito-clients/src/catalog/catalog.json` with `include_str!`;
2.0 has no catalog URL, HTTP client or update command. Metadata never updates
itself, and list bodies remain runtime downloads (see
[Runtime behaviour](#runtime-behaviour)).

### Release-time refresh runbook

Run this only when cutting a release (or when deliberately refreshing metadata):

1. **Fetch the upstream indexes at release time only.** Either let the
   generator fetch them, or download them yourself so the input is reviewable:

   ```bash
   refresh_dir="$(mktemp -d)"
   curl -fsSL https://adguardteam.github.io/HostlistsRegistry/assets/filters.json \
     -o "$refresh_dir/filters.json"
   curl -fsSL https://adguardteam.github.io/HostlistsRegistry/assets/services.json \
     -o "$refresh_dir/services.json"
   ```

   Keep this shell for step 2 so `$refresh_dir` is still set.

2. **Regenerate and review the diff.** The generator is deterministic and
   never reads list bodies. If the catalog changed it prints the new SHA-256;
   an unchanged regeneration reports `catalog unchanged`.

   ```bash
   python3 scripts/generate-catalog.py \
     --filters-file "$refresh_dir/filters.json" \
     --services-file "$refresh_dir/services.json"
   git diff -- crates/sito-clients/src/catalog/catalog.json
   ```

3. **Update the pin.** `--check` is the offline tamper/canonicalization guard:
   the committed bytes must match `CATALOG_SHA256` *and* equal the canonical
   bytes the generator would emit. Copy the digest printed by step 2 into
   `CATALOG_SHA256` in `scripts/generate-catalog.py`, then run
   `python3 scripts/generate-catalog.py --check` until it passes.

4. **Bump `catalog_version` only on schema changes.** The JSON value (currently
   `1`) guards compatibility; a metadata-only refresh must not change it. A
   schema change also needs the Rust loader, consuming UI/handlers and the
   tests updated in the same commit.

5. **Review upstream license and attribution.** Check the upstream
   HostlistsRegistry license and README (not the hardcoded
   `CATALOG_LICENSE`/`THIRD_PARTY_NOTICES` values) before release. If the
   upstream project, license or index URLs changed, update
   `THIRD_PARTY_NOTICES`, `FILTERS_URL`/`SERVICES_URL`, `CATALOG_LICENSE` and
   the catalog `source` fields together, and keep the metadata-only/no-list-bodies
   statement accurate.

6. **Commit together.** The regenerated JSON, the `CATALOG_SHA256` pin and any
   consuming code or tests belong in one reviewable change. Never commit a
   catalog file and its pin in separate commits.

7. **Keep list bodies runtime-downloaded.** The refresh changes metadata and
   URLs only. Existing `[filtering].lists` subscriptions still refresh through
   the normal scheduler, **Update All**, or the force-refresh API.

The default `--check` is the **offline tamper/canonicalization guard**. It
never touches the network and requires:

1. the committed file's raw bytes to match the pinned `CATALOG_SHA256` — this
   catches removed or changed filters/services, names, URLs, descriptions,
   versions, line endings (including CRLF) and any other byte-level edit;
2. the file to validate structurally and equal the canonical bytes the
   generator would emit for that data — this catches unknown fields, unsorted
   entries and formatting drift.

Upstream drift is a separate release-time check: rerun the generator against
the live indexes and review the diff, or pass both `--filters-file` and
`--services-file` to `--check` to regenerate from locally pinned index copies
without network access.

`catalog_version` in the JSON (currently `1`) guards schema compatibility. The
Rust loader `Catalog::embedded()` rejects unknown versions, unknown fields,
duplicate ids, empty names/URLs/rules, unexpected source URLs/license and
references to undeclared categories or service groups.

### What 2.0 does not do

- It does **not** fetch the catalog at runtime (startup, UI request or refresh).
- It has **no** `sito catalog update` command and no background metadata
  auto-update.
- It does **not** auto-update catalog versions, URLs or service rules.
- Future signed/checksummed catalog updates are out of scope for 2.0.

The release gate records the integrity evidence in
[release verification](release-verification.md#catalog-release-bound-integrity-f2e);
the requirement-to-test audit is in the [catalog coverage matrix](catalog-coverage.md).

## Choose from catalog (web UI)

Operators can open **+ Add from catalog** on the Filtering page to choose
from the embedded metadata. The dialog:

- searches by filter name or description and groups entries by category with
  per-category counts;
- shows each filter's name, description, version, homepage and source link;
- disables entries that are already configured with an **Added** badge, and
  disables deprecated entries with a **Deprecated** badge;
- submits only repeated `selected` catalog ids to
  `POST /ui/filtering/add-catalog`; names and URLs always come from the
  embedded catalog, never from the browser;
- labels the effective stored name when an upstream name has to be sanitized
  for routing (for example a name containing `/` becomes `-`), so the operator
  knows what will appear in the list table;
- caps one selection at 20 filters, enforced in both the UI and the handler.

The dialog also links to the [HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry)
(GPL-3.0-only) and this document. If the embedded catalog is missing or
corrupt, the catalog button and dialog are omitted and the custom-URL
**+ Add Blocklist** flow remains available as the fallback.

## Parental controls and the catalog

The catalog has **no dedicated parental/family filter** and no `parental` flag
on its entries. Parental control in 2.0 is a per-client-group policy that reads
the bundled `adult`/`gambling` runtime lists; it is off by default and the
setup wizard does not enable it.

Catalog entries are manual, global selections only. The nearest entry is
`hagezi_gambling_blocklist` (HaGeZi's Gambling Blocklist, category `other`,
"Blocks gambling content"), which an operator can add with **+ Add from
catalog**. Adding it creates a normal `[[filtering.lists]]` subscription for
every filtering-enabled group; it is never enabled by `parental = true` and it
does not replace `parental_categories`. See the
[parental controls guide](parental-controls.md) for the group configuration,
the bundled category limits, `[integrations.lists]` and audit steps.

## Blocked services by group (web UI)

Operators can manage per-group blocked services on the **Clients** page. The
**Blocked services by group** card lists every configured client group plus the
implicit `default` group, with the number of selected services and a chip for
each service. A service limited by a cron schedule shows that schedule next to
its chip.

**Edit services** opens a single shared dialog populated for the chosen group:

- search matches a service name, catalog id or catalog group id;
- services are grouped by their catalog group with per-group counts;
- services already configured for the group are checked when the dialog opens
  for that group, and the group table shows each existing schedule;
- configured services that are missing from the embedded catalog (bundled-only
  ids such as `ads`, `hbo`, `primevideo`, `zoom`, or a legacy custom id) appear
  in an **Other configured services** section, checked and showing any existing
  schedule. Leaving one checked preserves it; unchecking removes it. These ids
  can be retained or removed for their group, but they are not offered as new
  selections for another group;
- every catalog row shows its rule count; a catalog service that this build
  cannot enforce (no usable blocking rule) is disabled and marked
  **Unavailable** instead of being offered as a silent no-op;
- the dialog shows a live selected count and allows an empty selection, which
  clears that group's blocked services;
- saving submits the hidden `group` plus repeated `selected` ids and the CSRF
  token to `POST /ui/clients/group-services`. The handler requires new ids to
  come from the embedded catalog, accepts an already-configured id that the
  catalog cannot represent, keeps schedules for services that stay selected,
  and applies the whole group in one configuration update.

If the embedded catalog is missing or corrupt, the group table still renders
the current selections and schedules, but the edit controls and dialog are
omitted and the card explains that services cannot be edited. The catalog is
never fetched at runtime.

## Runtime behaviour

Filter-list bodies are **not** embedded. The catalog only records their
metadata and URLs; when an operator selects a filter, the runtime downloads the
list body through the existing subscription/list machinery. Fetching the
catalog itself at runtime is not part of 2.0.

## Category mapping

HostlistsRegistry filter groups map to stable category ids:

| Upstream group id | Category id | Name     |
| ----------------- | ----------- | -------- |
| 1                 | `general`   | General  |
| 2                 | `other`     | Other    |
| 3                 | `regional`  | Regional |
| 4                 | `security`  | Security |

Blocked services keep their upstream group ids (`ai`, `cdn`, `dating`,
`gambling`, `gaming`, `hosting`, `messenger`, `privacy`, `shopping`,
`social_network`, `software`, `streaming`).
