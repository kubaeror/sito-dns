# Embedded catalog

`sito-clients` embeds a catalog of filter and blocked-service metadata derived
from the [AdGuard HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry).
The catalog lets the UI and API offer AdGuard-style filter selection (and,
later, service selection) without making a network request to discover what is
available.

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

The catalog is **release-bound**, not fetched at runtime.

Release-time regeneration (network) refreshes the catalog and prints its
SHA-256:

```bash
python3 scripts/generate-catalog.py
python3 scripts/generate-catalog.py --check
```

The generator fetches the two indexes and writes the deterministic
`crates/sito-clients/src/catalog/catalog.json`. When intentionally refreshing
the catalog, review the diff, update `CATALOG_SHA256` in the generator to the
digest it prints, and commit the JSON, the pin and the consuming code together.

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

## Blocked services by group (web UI)

Operators can manage per-group blocked services on the **Clients** page. The
**Blocked services by group** card lists every configured client group plus the
implicit `default` group, with the number of selected services and a chip for
each service. A service limited by a cron schedule shows that schedule next to
its chip.

**Edit services** opens a dialog for one group:

- search matches a service name, catalog id or catalog group id;
- services are grouped by their catalog group with per-group counts;
- services already configured for the group are prechecked, and their existing
  schedule is shown beside the name;
- every row shows its rule count; a catalog service with no usable blocking
  rule is disabled and marked **Unavailable** instead of being offered as a
  silent no-op;
- the dialog shows a live selected count and allows an empty selection, which
  clears that group's blocked services;
- saving submits the hidden `group` plus repeated `selected` catalog ids and
  the CSRF token to `POST /ui/clients/group-services`. The handler validates
  every id against the embedded catalog, keeps schedules for services that
  stay selected, and applies the whole group in one configuration update.

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
