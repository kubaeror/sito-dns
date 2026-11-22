# Parental controls

Parental control in sito 2.0 is a **per-client-group policy**, not a global
switch:

- it is configured on a `[clients.groups.<name>]` table with
  `parental = true` plus an explicit `parental_categories` list;
- it blocks from the **bundled** `adult` and `gambling` runtime lists (or the
  operator-supplied replacements configured under
  [`[integrations.lists]`](#broader-coverage-integrationslists));
- nothing is enabled by default, and the first-time setup wizard does not
  create client groups or turn parental control on.

The embedded catalog has **no dedicated parental/family filter**. Catalog
entries are manual selections and are never enabled by `parental = true`. See
[catalog.md](catalog.md) for the catalog itself and
[configuration-reference.md §9](configuration-reference.md#9-clients--client-identification--policies)
for every client/group field.

## Quick start: a kids group

Identify the devices first, then give them a group that enables the categories
you want:

```toml
config_version = 2

[upstream]
servers = ["1.1.1.1", "9.9.9.9"]

[clients]

[[clients.entries]]
name = "kids-tablet"
ids = ["192.168.1.55", "dc:a6:32:11:22:33"]
group = "kids"

[clients.groups.kids]
description = "Kids devices (parental policy)"
filtering = true
parental = true
parental_categories = ["adult", "gambling"]
```

Notes:

- `parental = true` on its own blocks nothing. The categories named in
  `parental_categories` are the block set.
- A client reaches the group through its configured identifiers (IP, CIDR,
  MAC, or an authenticated DoT SNI / DoH path label). Devices not matched by
  any entry fall back to the implicit `default` group, which keeps the off
  defaults unless you add a `[clients.groups.default]` table.
- Parental blocking is part of the filtering stages, so it is evaluated only
  when the global `[filtering]` `enabled = true` (the default) **and** the
  group's `filtering = true` (the default). Setting either to `false` disables
  parental blocking for that group even when `parental = true`.
- Unknown category ids are rejected by `sito check-config`, startup, API config
  writes and HA apply with an error naming
  `clients.groups.<group>.parental_categories`. Categories are validated
  against the bundled registries, not against a runtime-refreshed source.

The same settings can be written through the API
(`POST /api/v2/clients/groups` or `PUT /api/v2/clients/groups/{name}` with
`parental_control` and `parental_categories`). The web UI's Clients page has no
parental switch; it manages identification and blocked services only.

## How blocking is evaluated

Parental categories are checked at ADR-0007 stage 3 (standard filtering,
parental control and blocked services), after `$important` rules and local
rewrites and before the safe-search rewrite. The match is domain-based:
`example.com` in a category blocks `example.com` and any subdomain such as
`a.example.com`, on label boundaries only (no substring or partial-label
matches). CNAME targets that are followed by CNAME cloaking are checked
against the same categories.

Blocked answers use the normal `[filtering] blocking_mode` (`"zero_ip"` by
default) and `blocking_ttl`. The query log records the block with rule
`parental`; there is no separate parental metric series.

## Bundled categories and their limits

Both categories are always present in the binary. There is no per-list enable
toggle: they are active only for groups whose `parental_categories` names them.

| Category id | Bundled entries | Version | License | Covers |
|---|---|---|---|---|
| `adult` | 40 | `2026.09.2` | CC0-1.0 | Commonly known adult sites and their subdomains |
| `gambling` | 40 | `2026.09.2` | CC0-1.0 | Common betting, casino and poker sites and their subdomains |

Limits to plan around:

- the bundled data is a **minimal built-in fallback**, not a maintained
  external dataset. It covers common providers only, is not continuously
  curated and is not security-reviewed;
- matching is exact-domain plus parent-suffix only. There are no regex,
  wildcard, path or IP rules, so a site that is not in the list is not blocked;
- the bundled version and entry count are visible on the Filtering page, but
  2.0 does not ship a larger parental dataset. Treat `adult`/`gambling` as a
  starting point and use `[integrations.lists]` below for real coverage.

The Filtering page's **Built-in Curated Lists** table shows each category's
version, entry count, license, source, status and last refresh/attempt/error.
After a successful `[integrations.lists]` refresh the row shows the external
source instead of the bundled fallback.

## Catalog: manual selection only

The embedded HostlistsRegistry catalog groups filters as `general`, `other`,
`regional` and `security`. It has **no parental/family category and no
parental flag** on catalog entries. The only parental-adjacent entry in the
2.0 catalog is:

| Catalog id | Name | Catalog group | Description |
|---|---|---|---|
| `hagezi_gambling_blocklist` | HaGeZi's Gambling Blocklist | `other` | Blocks gambling content. |

To use it, open **Filtering → + Add from catalog**, search for `gambling`, and
add the entry. That creates a normal global subscription in
`[[filtering.lists]]`; names and URLs come from the embedded catalog, never
from the browser. Catalog lists are applied to every filtering-enabled group,
so a catalog entry is **not** a per-group parental list and does not replace
`parental_categories`. A custom URL can be added with **+ Add Blocklist**
instead.

Neither `parental = true` nor the wizard enables a catalog list, and the
catalog itself is metadata only: the list body is downloaded by the normal
subscription machinery. By default a failed download, an empty body or a list
that parses to zero rules is rejected and the previous snapshot is kept rather
than silently removing protection; setting
`filtering.allow_empty_list = true` opts into accepting empty bodies at the
cost of losing that protection. See
[catalog.md § Choose from catalog](catalog.md#choose-from-catalog-web-ui) for
the dialog behaviour and limits.

## Broader coverage: `[integrations.lists]`

For maintained coverage, point the built-in categories at your own sources.
The bundled content remains the fallback until the first successful refresh:

```toml
[integrations.lists]
refresh_hours = 24

[integrations.lists.categories.adult]
url = "https://lists.example.com/adult.txt"
license = "CC0-1.0"
# refresh_hours = 12

[integrations.lists.categories.gambling]
url = "https://lists.example.com/gambling.txt"
license = "CC0-1.0"
```

Behaviour to rely on:

- a background task downloads each configured category through the shared
  subscription downloader (ETag/If-Modified-Since, on-disk cache under
  `data_dir`, size caps) and swaps the runtime registry without a restart;
- the category key must be one of the bundled ids: `adult`, `gambling` or
  `services` (case-insensitive). A refreshed domain list replaces that
  category's content; `services` expects service JSON. New parental category
  ids cannot be introduced at runtime;
- domain sources accept plain domains, ABP `||domain^` rules and hosts-format
  lines. Malformed lines and boilerplate hosts entries are skipped;
- a failed fetch, a zero-yield result or invalid `services` JSON keeps the
  previous content and records `last_error`. For domain sources, parsing skips
  malformed lines and applies the valid remainder, so only content that yields
  no usable entries is rejected. A periodic refresh that shrinks a previously
  refreshed category by more than 50% is rejected; an operator can force an
  intentional shrink with `POST /api/v2/integrations/lists/{category}/refresh`
  (empty content is still refused);
- `GET /api/v2/integrations/lists` reports, per category, whether the active
  content is the bundled fallback, the deployed source URL, entry count, last
  refresh/attempt and the most recent error. The Filtering page shows the same
  state; the web UI has no separate refresh button.

Full key types, defaults and validation are in
[configuration-reference.md §15](configuration-reference.md#15-integrationslists--curated-list-updates).
The bundled data limitation remains even with `[integrations.lists]`
configured: coverage is only as good as the source you point at.

## Defaults, wizard, migration and HA

**Defaults.** `parental` defaults to `false` and `parental_categories` to an
empty list on every group, including the implicit `default` group. No parental
list, catalog entry or integration source is enabled by default.

**Wizard.** The first-time setup wizard covers administrator, listeners,
upstreams, cache/DNSSEC, filtering subscriptions and web statistics. It has no
client-group or parental step, creates no group, and writes the same off
defaults when it persists `config.toml`. `--no-setup` on a fresh install also
leaves parental off, but it starts from built-in defaults without persisting a
config file, and it disables filtering when no list or custom rule is
configured so DNS resolution still works. Either way, configure parental
control after setup with the snippet above. See
[the README's first-time setup section](../README.md#-first-time-setup-wizard).

**Migration.** `clients.groups.*.parental` and
`clients.groups.*.parental_categories` are kept v1→v2 fields, so an existing
parental configuration migrates unchanged. Migration never invents a group or
enables parental control.

**HA.** `[clients]` groups (including `parental` and `parental_categories`) are
part of the replicated shared configuration: set them on the master, and the
signed bundle applies them on every slave. `clients.client_id_secrets` and the
RouterOS integration stay node-local and are stripped from the replicated
projection, so provision those per node. Do not hand-edit shared `[clients]`
fields on a slave; the API blocks slave mutations and shared-field drift is
detected after a write and requires a full apply. Both nodes validate category
ids against their own bundled registry, and each node downloads the configured
`[integrations.lists]` sources into its own `data_dir`, so per-node status
(`GET /api/v2/integrations/lists`) can differ if a source is unreachable from
one node.

See the [HA runbook](runbook-ha.md) for bundle, drift and promotion details.

## Verify and audit

1. **Configuration check.** Run `sito check-config --config /etc/sito/config.toml`.
   It rejects unknown categories, malformed groups and invalid list sources
   before a restart. It validates ids against the bundled registries; it does
   not prove the downloaded content is complete.
2. **Group policy and on-disk config.** `GET /api/v2/clients/groups` (requires
   **Operator** or higher) returns each group's DTO from the live configuration
   with `parental_control` and `parental_categories`, including the implicit
   `default` group. `GET /api/v2/config` (requires **Admin**) returns the
   masked on-disk TOML as `config_toml`, where the same setting is the group
   key `parental`; it does not expose the `parental_control` DTO field. The
   Clients page shows group assignments but no parental control.
3. **Active list data.** `GET /api/v2/integrations/lists` and the Filtering
   page's Built-in Curated Lists table show whether `adult`/`gambling` are
   bundled or refreshed, from which source, with how many entries and the last
   error.
4. **Functional test.** From a device in the kids group (or with `dig -b` from
   that address on the same segment), query a known list domain:

   ```bash
   dig @192.168.1.1 pornhub.com A
   ```

   Expect the configured block response (`0.0.0.0` by default). The same query
   from a device in a group that does not enable parental blocking should
   resolve upstream.
5. **Query log.** A blocked parental query appears with rule `parental` and
   verdict `blocked`; use it to confirm which client and group hit the block.
6. **After a source change.** Re-check the status row (`bundled = false`,
   expected entry count, `last_error` absent) and repeat the functional test.

## What 2.0 does not do

- no per-client parental toggle: the policy is per group only;
- no catalog parental/family filter and no `parental` flag in catalog metadata;
- no automatic enablement of `hagezi_gambling_blocklist` or any other catalog
  list;
- no parental switch in the web UI, the wizard or the Filtering page;
- no new parental list content beyond the two bundled categories.
