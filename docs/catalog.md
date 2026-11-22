# Embedded catalog

`sito-clients` embeds a catalog of filter and blocked-service metadata derived
from the [AdGuard HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry).
The catalog lets the UI and API (follow-up work) offer AdGuard-style filter and
service selection without making a network request to discover what is
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

The catalog is **release-bound**, not fetched at runtime:

```bash
python3 scripts/generate-catalog.py
python3 scripts/generate-catalog.py --check
```

The generator fetches the two indexes and writes the deterministic
`crates/sito-clients/src/catalog/catalog.json`. Regenerate it at release/build
time when refreshing the catalog, review the diff, and commit the JSON with the
code that consumes it. `--check` runs offline: it validates the committed file
and verifies that it matches the canonical bytes the generator would emit for
that data, failing on hand edits, unknown fields, unsorted entries or formatting
drift. Supplying both `--filters-file` and `--services-file` also lets
`--check` regenerate from pinned local copies without network access.

`catalog_version` in the JSON (currently `1`) guards schema compatibility. The
Rust loader `Catalog::embedded()` rejects unknown versions, unknown fields,
duplicate ids, empty names/URLs/rules and references to undeclared categories
or service groups.

## Runtime behaviour

Filter-list bodies are **not** embedded. The catalog only records their
metadata and URLs; when an operator selects a filter, the runtime selection
work (follow-up F2c) downloads the list body through the existing
subscription/list machinery. Fetching the catalog itself at runtime is not part
of 2.0.

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
