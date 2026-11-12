# Config v2

Config v2 is the configuration schema for the 2.0 line. It is **frozen at
WP-1.3**: later work may add optional fields with defaults (or a v2.1
migration), but must not change the meaning of an existing key or its default
without a migration.

[`docs/2.0-migration.md`](2.0-migration.md) links here from the full 2.0
upgrade guide. This page is the schema, validation, migration and restart
reference.

## 1. Version and schema freeze

- New installs (`Config::default()`) start at `config_version = 2`.
- A configuration **file** must say `config_version = 2` explicitly. The key
  was optional in 1.9, so an unversioned file is treated as a v1 document.
- Only version `2` is accepted by startup, `check-config`, API writes, backup
  restore and HA apply.
- A `config_version = 1` (or unversioned) document is rejected with:

  ```
  unsupported config_version 1: this build requires config_version = 2.
  Migrate the document with `sito config migrate --from v1 --to v2 --backup`
  ```

- Unknown keys and tables are **errors**. There is no warn-and-default path.
- New installs use the 2.0 safe defaults (§4). Migrated v1 documents keep
  their v1 effective behavior unless the operator passes
  `--adopt-safe-defaults`.

The full field inventory is the checked-in
[`config-v1-to-v2-map.toml`](../crates/sito-core/config-v1-to-v2-map.toml). It is embedded in
the binary at compile time and drives both unknown-key rejection and the
migration. A unit test
(`config::tests::test_config_map_covers_every_serde_field`) fails when the map
and the serde schema diverge.

## 2. One validator

`Config::validate_full()` in `sito-core` is the single full validator.
`Config::validate()` remains as a compatibility alias that runs the same
rules. Every entry point reaches it:

| Entry point | Path |
|---|---|
| Startup (`sito`) | `Config::from_toml_str` → `validate_full` |
| `sito check-config` | `Config::from_toml_str` + `validate_typed_sections` |
| API write (`PUT /api/v1/config`) | `Config::from_toml_str` + `validate_full_config` |
| Backup restore | `Config::from_toml_str` + `validate_full_config` |
| HA apply | `Config::from_toml_str` + `validate_full_config` + restart rejection |
| File watcher / `POST /config/reload` | `Config::from_toml_str` + `validate_full_config` |

`validate_full` performs:

- the version check;
- every typed section's field validation;
- upstream-target syntax for `upstream.servers`, `upstream.per_domain[].servers`
  and `clients.entries[].upstreams`;
- ACME domain normalization, duplicate detection and wildcard rejection;
- duplicate `dns.bind` addresses and listener port conflicts (DNS TCP
  listeners and the admin UI, plus ACME HTTP-01 vs the admin UI);
- an empty `server.data_dir`;
- unknown/removed keys in legacy raw sections (`[clients]`, `[rewrites]`,
  `[web]`, `[auth]`, `[stats]`, `[ha]`, `[integrations]`);
- `[integrations.lists]` category URLs/refresh values and
  `[integrations.mikrotik]` URL/interval;
- duplicate client entry names and per-client upstream targets.

The dependent-crate typed conversions (`sito-clients`, `sito-rewrites`,
`sito-ha`) run in `sito-api::config_validation::validate_typed_sections` after
the core rules. This is the same pipeline, not a second validator with a
different rule set.

## 3. Unknown keys and typos

Startup, `check-config`, API writes, restore and HA apply reject unknown keys
by default. This prevents a typo such as `[upsteam]` from silently reverting a
whole section to defaults.

```text
unknown configuration key 'upsteam' in [upsteam]: this key is not part of
config v2 and was rejected instead of being silently ignored.
```

Keys removed in v2 (for example `auth.admin_password_hash`,
`auth.tokens`, `integrations.mikrotik.token`) produce a different error that
says the key was removed and points at the replacement where one exists.

The only path that accepts unknown keys is migration with an explicit flag:

```bash
sito config migrate --from v1 --to v2 --backup --ignore-unknown-keys
```

Every dropped key is reported; it is never preserved and never silently
dropped.

## 4. 2.0 safe defaults

New installs (`Config::default()`) and `--adopt-safe-defaults` use these
values:

| Setting | 2.0 safe default |
|---|---|
| `web.bind` | `"127.0.0.1"` (loopback admin UI) |
| `filtering.fail_closed` | `true` |
| `web.metrics_auth` | `true` |
| `acme.allow_bootstrap_cert` | `false` |
| `upstream.allow_private_targets` | `false` |
| `auth.token_default_ttl_days` | `90` |
| `stats.rollup_client_names` | `false` |
| `server.update_require_signature` | `true` |

Migration preserves v1 behavior by default. If a v1 document omits
`web.bind` (the key was optional in 1.9 and defaulted to `0.0.0.0`), migration
materializes `web.bind = "0.0.0.0"` and lists it in
`defaults_materialized`, so the admin UI stays reachable after the upgrade. An
explicit v1 bind is copied unchanged. Pass `--adopt-safe-defaults` to write the
loopback default instead; the report lists every changed field.

`dns.bind` remains `["0.0.0.0", "::"]` because a default-deny DNS client ACL
is not part of this work package. Keep the startup warning and restrict the
DNS ports with a host firewall.

## 5. Migration

```bash
sudo systemctl stop sito
sudo sito config migrate --from v1 --to v2 --backup
sudo systemctl start sito
```

`--from` and `--to` are explicit; only `v1` → `v2` is supported. The command:

1. parses the v1 document and rejects unknown keys unless
   `--ignore-unknown-keys` is given;
2. copies every known v1 key/value (behavior-preserving);
3. moves `[dns.tls]` to typed `[tls]`;
4. moves `[web] acme_*` to typed `[acme]` (an existing canonical value wins
   and the conflict is reported);
5. rewrites `stats.query_log_retention_days` →
   `stats.retention_days` and `privacy.anonymize_client_ip` →
   `privacy.anonymize_querylog`;
6. drops removed/dead keys and reports them;
7. writes `config_version = 2` and validates the result with the normal v2
   parser before it touches the file.

The original document is written atomically to `<config>.v1.bak` (mode
`0600`) when `--backup` is passed. The migrated document is written the same
way: a private sibling, fsync, atomic rename and mode `0600`. The
parent-directory fsync is best-effort, matching the other atomic writers.

Rollback: restore the `.v1.bak` file **and** the previous binary; downgrade is
not supported in place.

`--json` prints the machine-readable report:

```json
{
  "from_version": 1,
  "to_version": 2,
  "moved": [
    { "from": "web.acme_enabled", "to": "acme.enabled", "reason": "..." }
  ],
  "removed": [
    { "from": "auth.admin_password_hash", "reason": "..." }
  ],
  "unknown_dropped": [],
  "defaults_materialized": ["web.bind"],
  "safe_defaults_applied": [],
  "warnings": []
}
```

Automated migration by the installer/Docker entrypoint (only when
`config_version = 1`) and `--no-migrate` belong to WP-2.13; the CLI above is
the supported manual path in Phase 1. The full narrative migration guide is
[`docs/2.0-migration.md`](2.0-migration.md).

## 6. Deprecated aliases (one 2.0 alpha)

These v1 spellings remain accepted in v2 and are rewritten by migration:

| v1 alias | v2 path |
|---|---|
| `[dns.tls] cert/key/sni_certs` | `[tls] cert/key/sni_certs` |
| `[web] acme_enabled` | `[acme] enabled` |
| `[web] acme_email` | `[acme] email` |
| `[web] acme_domains` | `[acme] domains` |
| `[web] acme_staging` | `[acme] staging` |
| `[web] acme_cache_dir` | `[acme] cache_dir` |
| `stats.query_log_retention_days` | `stats.retention_days` |
| `privacy.anonymize_client_ip` | `privacy.anonymize_querylog` |

They are removed in a later 2.0 release after the compatibility window.

## 7. Restart-only matrix (D11)

Some settings are read once at process start. An admin write that changes one
of them returns **409 Conflict** with `restart_required` and is **not
persisted**. Edit `config.toml` and restart, or use the installer.

`GET /api/v1/config/restart-required` (the existing API version; `/api/v2` is
Phase 2 work) is a read-only preview:

```json
{
  "restart_required_fields": [
    "server.role", "server.instance_name", "server.data_dir",
    "server.log_format", "auth", "web", "tls", "acme", "ha",
    "integrations"
  ],
  "message": "...",
  "apply_endpoint": "/api/v1/config"
}
```

| Field group | Why |
|---|---|
| `server.role`, `server.instance_name`, `server.data_dir`, `server.log_format` | Read once at process start; role/data-dir shape HA and runtime state. |
| `web.enabled`, `web.bind`, `web.port` | Admin listener is bound at startup. Other `[web]` keys are hot-applied. |
| `[tls]` / `[dns.tls]` | TLS acceptors are built at startup. Certificate *content* is hot-reloaded by the watcher; configured paths are restart-only. |
| `[acme]` / legacy `[web] acme_*` | ACME workers and cache are initialized at startup. |
| `[auth]` | The auth manager/session policy is created at startup. |
| `[ha]`, `[integrations]` | Replication and integration tasks are spawned at startup. |

The same matrix is used by:

- `PUT /api/v1/config` and backup restore (409, no persist);
- the HA slave apply path (409, ACK `applied: false`, no persist);
- `restart_required_fields()` for the file-watcher warning and reload report;
- the read-only preview endpoint.

The first-boot wizard is the one deliberate exception: it completes initial
configuration and reports restart-only fields instead of failing a fresh
setup. It still uses the same validator and matrix.

## 8. HA bundles

The HA sanitizer strips `[ha]`, secrets (`client_id_secrets`, legacy auth
verifiers, RouterOS credentials) and node-local identity. The sanitized
document is a normal v2 document: `Config::from_toml_str` accepts it, and the
node-local listener/TLS/ACME/web identity is restored before it is persisted.
The `sito-ha` round-trip tests cover this, including a v2 document with
removed legacy keys.

## 9. Extending the map

When you add a configuration field:

1. add the serde field to the Rust struct (typed sections get
   `#[serde(deny_unknown_fields)]`);
2. add a `[[field]]` entry to `config-v1-to-v2-map.toml` with the dotted path
   and status (`kept`, `deprecated` + `to`, `removed`, `dead`);
3. for a legacy raw section, add the path (including `[]` array markers and
   `*` map keys) so the walker accepts it;
4. add the field to `SCHEMA_FIXTURE` in `crates/sito-core/src/config.rs` so the
   drift test exercises it;
5. document it in `docs/configuration-reference.md`;
6. run `cargo test -p sito-core config_schema` and
   `cargo test -p sito-core test_config_map_covers_every_serde_field`.

Missing map entries fail CI; a field that is only in the map and not in the
schema also fails the fixture test.

## 10. Deferred fields

- `clients.trust_arp` is **not** added in config v2. D10 defines the trust
  table, but the optional ARP-trust knob is deferred to WP-2.5 and will be an
  optional v2 field with default `false`.
- `/api/v2` and the API v1 compatibility facade are Phase 2 work (WP-2.11);
  the Phase 1 preview deliberately uses `/api/v1/config/restart-required`.
- Installer/Docker auto-migration is WP-2.13. The full narrative migration
  guide is [`docs/2.0-migration.md`](2.0-migration.md). This document does not
  change their contracts.
