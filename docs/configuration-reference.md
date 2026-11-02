# Configuration Reference

This document is the exhaustive configuration reference for **sito v1.8.0**.

`sito` is configured using a single TOML file (default path: `/etc/sito/config.toml` or specified via `--config <path>`). Environment-variable configuration overrides are **not supported**; all settings come from the TOML file. HA secret placeholders (`${SECRET:name}`) resolve from the `DNSD_SECRET_<name>` environment variable, then a bare `<name>` environment variable; there is no on-disk local secret store, and a placeholder that cannot be resolved rejects the whole pushed configuration.

> [!NOTE]
> The tables below are validated against the Rust config structs in CI (`scripts/check_config_reference.py`); adding a setting without documenting it fails the build.
>
> Configuration persistence round-trips modeled fields via the `Config` schema. Unrecognized or unmodeled keys and comments are omitted when the configuration is saved back to disk by the web console or API.

---

## 1. Top-Level Options

| Key | Type | Default | Description |
|---|---|---|---|
| `config_version` | integer | `1` | Configuration schema version. Used for automatic configuration migrations. |

---

## 2. `[server]` — System and Runtime

```toml
[server]
role = "master"                        # "master" | "slave"
instance_name = "sito-main"            # Unique identifier in cluster
data_dir = "/var/lib/sito"             # Base path for database, caches, and state
log_level = "info"                     # "trace" | "debug" | "info" | "warn" | "error"
log_format = "json"                    # "pretty" | "json"
update_require_signature = true        # require cosign-verified release signatures for self-update
```

| Key | Type | Default | Description |
|---|---|---|---|
| `role` | string | `"master"` | HA cluster role: `"master"` (reads/writes, replicates state) or `"slave"` (read-only replica). |
| `instance_name` | string | `"sito-main"` | Name of this server instance, reported in metrics and logs. |
| `data_dir` | string | `"/var/lib/sito"` | Directory where the persistent SQLite DB (`stats.db`), list caches, TLS state, user credentials (`users.toml`, 0600), the TOTP encryption key (`totp.key`, 0600), and the DNSSEC chain cache (`dnssec-chain-cache.toml`, 0600) are stored. |
| `log_level` | string | `"info"` | Logging verbosity: `"trace"`, `"debug"`, `"info"`, `"warn"`, or `"error"`. |
| `log_format` | string | `"json"` | Formatting for stdout logs: `"pretty"` (human readable with colors) or `"json"` (structured). |
| `update_require_signature` | boolean | `true` | When `true`, in-app updates and `sito update` require a valid cosign signature (`.sig`/`.pem` assets). A signature that is present is always verified even when this is `false`; when `true`, a missing signature or missing `cosign` binary aborts the update. Set to `false` only if you intentionally accept same-origin SHA-256-only integrity. |

---

## 3. `[dns]` — Listener Protocols and Sockets

```toml
[dns]
bind = ["0.0.0.0", "::"]
port = 53
dot_port = 853
doh_port = 443
doq_port = 0
doh3_port = 443
doh_dedicated_hostname = "dns.example.com"
dot_padding = false
edns_udp_size = 1232
rate_limit_per_ip = 20
max_tcp_connections = 256
allow_plaintext_doh = false
```

| Key | Type | Default | Description |
|---|---|---|---|
| `bind` | array of strings | `["0.0.0.0", "::"]` | IP addresses to bind listeners on. |
| `port` | integer | `53` | Standard UDP and TCP DNS listener port (must be greater than 0). |
| `dot_port` | integer | `853` | DNS-over-TLS (DoT) listener port. `0` disables DoT. |
| `doh_port` | integer | `443` | DNS-over-HTTPS (DoH, HTTP/1.1 and HTTP/2) port. `0` disables DoH. |
| `doq_port` | integer | `0` | DNS-over-QUIC (DoQ) UDP port. `0` (default) disables DoQ; set `853` only when it does not conflict with DoT. |
| `doh3_port` | integer | `443` | DNS-over-HTTP/3 (DoH3) UDP port. `0` disables DoH3. |
| `doh_dedicated_hostname` | string | `""` | When set, DoH/DoH3 requests whose Host/authority does not match are rejected with `421 Misdirected Request`. Empty allows any hostname. |
| `dot_padding` | boolean | `false` | RFC 7830/8467 padding on DoT responses to mitigate traffic analysis. |
| `edns_udp_size` | integer | `1232` | Maximum EDNS0 UDP buffer size (1232 bytes prevents IPv6 fragmentation). |
| `rate_limit_per_ip` | integer | `20` | Maximum queries per second allowed from an individual client IP (`0` disables rate limiting; maximum `1000000`). |
| `max_tcp_connections` | integer | `256` | Maximum concurrent TCP, DoT, and DoH client connections. |
| `allow_plaintext_doh` | boolean | `false` | Allow binding the plaintext DoH listener on non-loopback addresses. When `false`, plaintext DoH is restricted to loopback. |

---

## 4. `[dns.cache]` — Caching Layer

```toml
[dns.cache]
enabled = true
size_mb = 64
min_ttl = 60
max_ttl = 86400
negative_ttl_max = 3600
prefetch = true
serve_stale_hours = 12
```

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Enables or disables in-memory caching. |
| `size_mb` | integer | `64` | Memory allocation ceiling for the cache in megabytes. |
| `min_ttl` | integer | `60` | Minimum TTL (seconds) to assign to cached answers (overrides smaller upstream TTLs). |
| `max_ttl` | integer | `86400` | Maximum TTL (seconds) to assign to cached answers (caps excessively high upstream TTLs). |
| `negative_ttl_max` | integer | `3600` | Maximum TTL (seconds) for negative caching (NXDOMAIN / NODATA). |
| `prefetch` | boolean | `true` | When `true`, automatically re-resolves frequently requested domains before TTL expires. |
| `serve_stale_hours` | integer | `12` | Hours to serve expired cache records as fallback when upstreams are unreachable. |

---

## 5. `[dns.dnssec]` — DNSSEC Validation

```toml
[dns.dnssec]
mode = "validate"
validate = true
ntp = ["local.internal"]
```

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | string | `"validate"` | Validation mode. Accepted: `"validate"`/`"strict"` (bogus = SERVFAIL), `"log_only"`/`"log-only"`/`"permissive"` (log and clear AD), `"off"`/`"disabled"`. |
| `validate` | boolean | `true` | Enable DNSSEC processing. Validation walks DS/DNSKEY links present in the response and, when the chain is incomplete, resolves the missing DNSKEY/DS records through the configured upstreams (bounded per-query fetch budget). NSEC/NSEC3 denial proofs are enumerated; opt-out NXDOMAIN answers are treated as insecure. |
| `ntp` | array of strings | `[]` | Negative Trust Anchors: domains exempt from DNSSEC validation (RFC 7646). Alias retained for compatibility; `nta` is the preferred key. |
| `nta` | array of strings | `[]` | Negative Trust Anchors: domains exempt from DNSSEC validation (RFC 7646). |
| `trust_anchors` | array of strings | `[]` | Trust anchors used as the top of the DS/DNSKEY chain (DS or DNSKEY records in zone-file/hex form). Empty uses validation of RRSIGs against configured anchors only. |

---

## 6. `[tls]` and `[acme]` — Certificates and Encryption

```toml
[tls]
cert = "/etc/sito/cert.pem"
key = "/etc/sito/key.pem"

[[tls.sni_certs]]
domain = "*.example.com"
cert = "/etc/sito/wildcard_cert.pem"
key = "/etc/sito/wildcard_key.pem"

[acme]
enabled = false
email = "admin@example.com"
domains = ["dns.example.com"]
staging = false
```

| Key | Type | Default | Description |
|---|---|---|---|
| `tls.cert` | string | `None` | Path to PEM-encoded certificate chain for DoT, DoH, and Web UI. |
| `tls.key` | string | `None` | Path to PEM-encoded unencrypted PKCS#8 or RSA/EC private key. |
| `tls.sni_certs` | array of tables | `[]` | Additional certificate/key pairs mapped to specific SNI hostnames. |
| `acme.enabled` | boolean | `false` | Enables automated certificate issuance via Let's Encrypt / ACME. |
| `acme.email` | string | `None` | Contact email address for ACME registration. |
| `acme.domains` | array of strings | `[]` | Domain names for ACME TLS-ALPN-01 / HTTP-01 certificates. |
| `acme.staging` | boolean | `false` | When `true`, uses Let's Encrypt Staging API to avoid rate limits during testing. |
| `acme.cache_dir` | string | `None` | Directory used to persist ACME account keys and certificates (defaults to `<data_dir>/acme`). |
| `acme.http_port` | integer | `80` | Port for the dedicated ACME HTTP-01 challenge listener. |

---

## 7. `[upstream]` — Forwarding and Upstream Resolvers

```toml
[upstream]
servers = [
    "tls://dns.quad9.net",
    "https://cloudflare-dns.com/dns-query",
    "quic://dns.adguard-dns.com",
    "udp://1.1.1.1:53"
]
bootstrap = ["9.9.9.9", "1.1.1.1"]
strategy = "parallel"                  # "parallel" | "failover" | "load_balance"
timeout_ms = 5000
probe_domain = "example.com"
pool_size = 4

[[upstream.per_domain]]
domains = ["*.lan", "168.192.in-addr.arpa"]
servers = ["udp://192.168.1.1:53"]
```

| Key | Type | Default | Description |
|---|---|---|---|
| `servers` | array of strings | `["1.1.1.1", "1.0.0.1"]` | Upstream resolvers. Schemes: `udp://` or `host:port` (UDP with TCP fallback), `tls://` (DoT), `https://host[:port]/dns-query` (DoH, RFC 8484 with GET fallback), `quic://host[:port]` (DoQ, RFC 9250, default port 853). |
| `bootstrap` | array of IPs | `["9.9.9.9", "149.112.112.112"]` | Plain IP addresses used to bootstrap resolution of encrypted upstream domain names. |
| `strategy` | string | `"failover"` | Forwarding strategy: `"parallel"` (fastest answer wins), `"failover"` (sequential fallback), or `"load_balance"`. |
| `timeout_ms` | integer | `5000` | Overall per-query budget in milliseconds, shared across failover/load-balance retries (each sequential attempt gets an equal share of the remaining budget; parallel races use the full budget). |
| `probe_domain` | string | `"example.com"` | Test domain used for periodic health-checking of upstreams. |
| `ecs` | string | `"off"` | EDNS Client Subnet policy: `"off"` strips client ECS before forwarding and deduplicates cache keys; `"forward"` forwards ECS after clamping IPv4 to /24 and IPv6 to /56 (zero source prefixes dropped). Forwarding can improve CDN locality but discloses a coarse client-location hint and splits cache entries by subnet. |
| `pool_size` | integer | `4` | Number of persistent TCP/TLS connections maintained per upstream endpoint. |
| `per_domain` | array of tables | `[]` | Domain-specific upstream forwarder rules (e.g., routing LAN domains to internal router). |

---

## 8. `[filtering]` — Ad & Malware Blocking Engine

```toml
[filtering]
enabled = true
refresh_interval_hours = 24
blocking_mode = "zero_ip"              # "zero_ip" | "nxdomain" | "refused" | "null_rdata" | "custom_ip:x.x.x.x"
blocking_ttl = 10
cname_cloaking = true
fail_closed = true
anti_doh_bypass = "block_all"          # "off" | "block_all" | "block_except_trusted"
custom_rules = [
    "||badtracker.com^",
    "@@||allowed-service.com^"
]

[[filtering.lists]]
name = "OISD Big"
url = "https://big.oisd.nl"
enabled = true
```

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Master toggle for blocklist filtering and custom rules. |
| `refresh_interval_hours` | integer | `24` | Default interval between automated subscription list re-downloads. |
| `blocking_mode` | string | `"zero_ip"` | DNS answer returned for blocked domains: `"zero_ip"` (`0.0.0.0` / `::`), `"nxdomain"`, `"refused"`, `"null_rdata"`, or `"custom_ip:<ip>"`. |
| `blocking_ttl` | integer | `10` | TTL in seconds returned on blocked responses (low TTL allows rapid unblocking). |
| `cname_cloaking` | boolean | `true` | Follow CNAME chains upstream and apply filter rules against intermediate canonical names. |
| `fail_closed` | boolean | `true` | Answer SERVFAIL while filtering is enabled but no rule snapshot has ever loaded (e.g. every list failed at boot), instead of silently allowing traffic. |
| `anti_doh_bypass` | string | `"off"` | Block known public DoH/DoT resolvers to enforce network-wide filtering: `"off"`, `"block_all"`, or `"block_except_trusted"`. |
| `max_rules` | integer | `2000000` | Hard cap on the total parsed rules (all lists plus custom rules). A reload above the cap is rejected and the previous snapshot is retained (or the engine stays fail-closed when nothing loaded yet). |
| `max_list_bytes` | integer | `67108864` | Hard cap in bytes for each downloaded subscription list and its disk-cache read, enforced before the body is buffered. Must be greater than 0. Lowering it invalidates larger cached lists. After a restart (or when no previous snapshot exists), an invalidated larger cache with `fail_closed = true` and no network answers SERVFAIL until a fetch under the new cap succeeds; a live reload keeps the previous snapshot and records the list in `failed_lists`. |
| `custom_rules` | array of strings | `[]` | In-line custom ABP / AdGuard filter rules. |
| `lists` | array of tables | `[]` | Subscription lists to download and compile (`name`, `url`, `enabled`). Schemes: `http://`, `https://`, `file://`. Global `refresh_interval_hours` controls update frequency. |

---

## 9. `[clients]` — Client Identification & Policies

```toml
[clients]

[[clients.entries]]
name = "kids-tablet"
ids = ["192.168.1.55", "tablet.dns.example.com", "dc:a6:32:11:22:33"]
group = "kids"
ignore_query_log = false
trusted = false

[clients.groups.kids]
description = "Kids devices (parental policy)"
filtering = true
lists = ["OISD"]
custom_rules = ["||fortnite.com^$important"]
safe_search = true
parental = true
parental_categories = ["adult", "gambling"]
schedule_enabled = true
schedule = "0 0 15-21 * * MON-FRI"

[[clients.groups.kids.blocked_services]]
service = "tiktok"
schedule = "0 0 15-21 * * MON-FRI"

# Shared secrets for DoH path / DoT SNI identification. Keys are entry names.
[clients.client_id_secrets]
"kids-tablet" = "change-me-shared-secret"
```

| Key | Type | Default | Description |
|---|---|---|---|
| `entries` | array of tables | `[]` | Client definitions mapping IP addresses, plus shared-secret DoT SNI / DoH path identifiers and MAC addresses, to groups. Available entry keys: `name`, `ids`, `group`, `ignore_query_log`, `ignore_stats` (skip Prometheus counters), `use_global_upstreams`, `upstreams` (when `use_global_upstreams = false`, the client resolves through these servers only and its answers bypass the shared cache), `trusted`. Display names and `ids` never authenticate a client on their own. |
| `groups` | table (map of name → group) | `{}` | Policy groups keyed by group name, e.g. `[clients.groups.kids]`, with optional `[[clients.groups.<name>.blocked_services]]` entries. Group fields: description (optional operator note), filtering, lists, custom_rules, safe_search, safe_search_youtube, parental, parental_categories, schedule_enabled, schedule, blocked_services. |
| `client_id_secrets` | table (map of entry name → secret) | `{}` | Shared secrets accepted as the first DoT SNI label (`<secret>.dns.example.com`) or the DoH path segment (`/dns-query/<secret>`). Empty disables path/SNI identification. |
| `trust_routeros_lease_names` | boolean | `false` | Trust RouterOS DHCP lease host names/comments for client identification. Off by default because lease data is client-controlled. |
| `timezone` | string | `"local"` | Timezone used to evaluate client schedules and time-of-day rules. `"local"`/`"system"` uses the host zone (DST-aware); `"UTC"` and fixed offsets (`"+02:00"`, `"-05:30"`, `"+0530"`, `"UTC+2"`) are also accepted. IANA names are not supported (no tzdb dependency); schedules in UTC-only deployments should set this explicitly. |

---

## 10. `[rewrites]` — Local DNS Records & Overrides

```toml
[rewrites]
auto_ptr = true   # opt-in; the section default is false (see note below)
ttl = 60

[[rewrites.entries]]
domain = "*.home.arpa"
type = "A"
answer = "192.168.1.10"
exception_clients = ["admin-laptop"]
```

| Key | Type | Default | Description |
|---|---|---|---|
| `auto_ptr` | boolean | `false` | Automatically synthesize reverse PTR records (`in-addr.arpa` / `ip6.arpa`) for local A/AAAA rewrites in RFC 1918 / ULA ranges. Opt-in. |
| `ttl` | integer | `60` | TTL for synthesized rewrite records. |
| `entries` | array of tables | `[]` | Local record rewrites (`domain`, `type` (`A`/`AAAA`/`CNAME`/`PTR`/`TXT`), `answer`, and optional `exception_clients`). |

---

## 11. `[web]` & `[auth]` — Administration API and Web Interface

```toml
[web]
enabled = true
port = 8080
bind = "0.0.0.0"          # single IP address, not an array
metrics_auth = true
trusted_proxies = ["10.0.0.1", "192.168.1.10"]   # individual proxy IPs

[auth]
session_ttl_hours = 24
login_rate_limit = 5
session_persist = true          # persist sessions/tokens across restarts
token_default_ttl_days = 90     # 0 = API tokens never expire
```

| Key | Type | Default | Description |
|---|---|---|---|
| `web.enabled` | boolean | `true` | Enable the web dashboard and REST API. |
| `web.port` | integer | `8080` | Port for the Web Dashboard and REST API (`/api/v1/`; must be ≥ 1). |
| `web.bind` | string (IP address) | `"0.0.0.0"` | Bind address for the web server. |
| `web.metrics_auth` | boolean | `true` | Require authentication (token or session) for `/metrics`. |
| `web.trusted_proxies`| array of IP addresses | `[]` | Individual proxy IPs trusted to supply `X-Forwarded-For`/`X-Forwarded-Proto` (CIDR is **not** supported here). |
| `auth.session_ttl_hours` | integer | `24` | Web session lifetime before re-authentication is required (must be ≥ 1). |
| `auth.login_rate_limit` | integer | `5` | Maximum failed login attempts allowed per minute per IP before lockout. |
| `auth.session_persist` | boolean | `true` | Persist sessions (`sessions.toml`) and API tokens (`tokens.toml`) in `data_dir` (0600). Sessions/tokens survive restarts until their TTL; corrupt stores are backed up and start empty. Use `sito reset-sessions` to invalidate everything. |
| `auth.token_default_ttl_days` | integer | `90` | Default lifetime of newly created API tokens in days; `0` means no expiry. |

Accounts are stored in `<data_dir>/users.toml` (0600). TOTP secrets are
encrypted at rest with AES-256-GCM using `<data_dir>/totp.key` (0600, created
automatically). Treat `totp.key` as a credential: **back it up together with
`users.toml`**. Restoring both is equivalent to the previous plaintext user
store; restoring only one is a lockout. If the key is missing or does not match
the stored secrets, the server refuses to start rather than silently disabling
2FA (`sito reset-admin` is the recovery path). An HA slave keeps its own
`totp.key`; `users.toml` is never replicated or included in HA bundles.

Two additional `[web]` keys are read from the raw table:

* `web.public_url` (string, unset) — external URL of the admin UI. Its scheme
  decides `Secure` cookies, HSTS and the expected CSRF origin. Set it when the
  UI is reached through a reverse proxy; it is authoritative over request
  headers and over the DNS `[tls]` certificate settings.
* `web.tls_terminated_by_proxy` (boolean, `false`) — TLS is terminated by a
  trusted reverse proxy in front of the server (the immediate peer must be in
  `web.trusted_proxies` or `X-Forwarded-Proto` is ignored).

The admin scheme is never derived from the DNS DoT/DoH certificate config.


---

## 12. `[stats]` — Metrics and Query Logging

```toml
[stats]
# `retention_days` also accepts the legacy alias `query_log_retention_days`
retention_days = 90

[privacy]
anonymize_querylog = false
```

| Key | Type | Default | Description |
|---|---|---|---|
| `stats.retention_days` | integer | `90` | Days to keep detailed per-query records before automated pruning and hourly aggregation (must be ≥ 1; alias: `query_log_retention_days`). |
| `privacy.anonymize_querylog` | boolean | `false` | Mask client IPs (/24 for IPv4, /56 for IPv6) before persisting to database and before live-tail broadcast. |

> Query logging is always enabled when `[stats]` is present; Prometheus metrics are always exposed on `/metrics` and protected according to `web.metrics_auth`.

---

## 13. `[ha]` — High-Availability Master/Slave Replication

```toml
[ha]
replication_port = 8953
# ping_interval_secs = 15        # master heartbeat; slaves silent for 3x are dropped

# On Slave instance:
# master_url = "wss://192.168.1.10:8953"
# master_fingerprint = "blake3:4f8a12..."
# master_pubkey = "<ed25519 public key>"   # required on slaves (signed bundle verification)
# cert = "/etc/sito/ha_slave.crt"
# key = "/etc/sito/ha_slave.key"
# ca = "/etc/sito/ha_ca.crt"
```

| Key | Type | Default | Description |
|---|---|---|---|
| `replication_port` | integer | `8953` | Mutual-TLS WebSocket port for config synchronization. |
| `listen_addr` | string | `"0.0.0.0"` | Address the master replication listener binds to. |
| `master_url` | string | `None` | (Slave only) WebSocket URL of the master instance. |
| `master_fingerprint` | string | `None` | (Slave only) Expected Blake3 public certificate fingerprint of master for pinning. |
| `master_pubkey` | string | `None` | (Slave only, **required**) Ed25519 public key of the master used to verify signed configuration pushes. |
| `cert` / `key` / `ca` | string | `None` | Paths to mTLS certificates and CA bundles for replication. When `ca` is set, the peer chain is additionally validated against it (on top of BLAKE3 pinning). |
| `ping_interval_secs` | integer | `15` | Master heartbeat interval. Slaves silent for 3× this interval are disconnected and removed from the active tracker. |
| `slave_token` | string | `None` | Pre-shared token for slave authentication (mandatory when serving plaintext `ws://`). |
| `pinned_slave_fingerprints` | array of strings | `[]` | BLAKE3 fingerprints of slave certificates accepted by the master. |
| `allow_unpinned_tls` | boolean | `false` | Allow TLS peers without a configured fingerprint (insecure; only for controlled networks). |
| `allow_insecure_ws` | boolean | `false` | Allow plaintext `ws://` replication. Requires a non-empty `slave_token`; must be set explicitly on both ends. |
| `stats_interval_secs` | integer | `30` | Interval between slave-to-master statistics reports. |

---

## 14. `[integrations.mikrotik]` — RouterOS Integration

```toml
[integrations.mikrotik]
enabled = false
url = "https://192.168.1.1"
token_env = "MIKROTIK_API_TOKEN"
interval_s = 300
```

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Enable automated client discovery from RouterOS DHCP server. |
| `url` | string | `"https://192.168.1.1"` | Base URL of RouterOS REST API (`https://router.lan`). |
| `token_env` | string | `"MIKROTIK_API_TOKEN"` | Environment variable containing the RouterOS API token. |
| `username` | string | `None` | Username for HTTP basic authentication when no token is used. |
| `password` | string | `None` | Password for HTTP basic authentication (prefer `password_env` to keep secrets out of the config). |
| `password_env` | string | `None` | Environment variable containing the RouterOS password. |
| `allow_invalid_certs` | boolean | `false` | Accept untrusted/self-signed RouterOS TLS certificates (insecure; lab use only). |
| `interval_s` | integer | `300` | Polling interval in seconds to refresh active DHCP lease table. |

---

## 15. `[integrations.lists]` — Curated List Updates

Point the bundled parental/service categories at maintained sources; a
background task downloads them through the shared subscription downloader
(ETag/If-Modified-Since, disk cache under `data_dir`, size caps) and swaps the
runtime registries without a restart. The bundled data remains the fallback
until the first successful refresh.

```toml
[integrations.lists]
refresh_hours = 24

[integrations.lists.categories.adult]
url = "https://lists.example.com/adult.txt"
license = "CC0-1.0"
# refresh_hours = 12

[integrations.lists.categories.services]
url = "https://lists.example.com/services.json"
```

| Key | Type | Default | Description |
|---|---|---|---|
| `refresh_hours` | integer | `24` | Default refresh interval in hours for categories without an override (must be ≥ 1). |
| `categories` | table (map of category → source) | `{}` | Sources keyed by category id (`adult`, `gambling`, `services`, or any custom parental category). Each entry has a required `url` (`https://`, `http://` or `file://`), an optional `refresh_hours` override and an optional `license` string for operator reference. Refreshed domain lists replace the bundled content of that category; `services` expects service JSON. |

---

## 16. Hot Reload Matrix

The running server watches the file passed to `--config` (the CLI default is
the relative `config.toml`; the systemd unit and container image pass
`/etc/sito/config.toml`) and re-applies the settings below in-process. A
configuration that cannot be parsed or validated is rejected as a whole: the
previous settings stay active and the error is logged. The REST API reports
restart-only changes in the `restart_required` field of `PUT /api/v1/config`
and `POST /api/v1/config/reload`.

### 16.1 Applied live (no restart)

| Setting | How it is applied |
|---|---|
| `server.log_level` | Log-level filter reloaded. |
| `server.update_require_signature` | Read when an update is started, not at boot. |
| `web.metrics_auth`, `web.trusted_proxies`, `web.public_url`, `web.tls_terminated_by_proxy` | Read from the live configuration when a request is handled. |
| `dns.bind`, `dns.port`, `dns.dot_port`, `dns.doh_port`, `dns.doq_port`, `dns.doh3_port`, `dns.doh_dedicated_hostname`, `dns.dot_padding`, `dns.edns_udp_size`, `dns.max_tcp_connections`, `dns.allow_plaintext_doh` | DNS listeners are stopped and rebound in-process when the listener plan changes; a failed rebind restores the previous bindings. TLS listeners need the acceptors created at startup. |
| `dns.rate_limit_per_ip` | Live rate limiters updated. |
| `dns.cache.enabled`, `dns.cache.size_mb`, `dns.cache.min_ttl`, `dns.cache.max_ttl`, `dns.cache.negative_ttl_max`, `dns.cache.prefetch`, `dns.cache.serve_stale_hours` | Cache configuration updated. |
| `dns.dnssec.mode`, `dns.dnssec.validate`, `dns.dnssec.ntp`, `dns.dnssec.nta`, `dns.dnssec.trust_anchors` | DNSSEC validator swapped for the new configuration. |
| `upstream.servers`, `upstream.strategy`, `upstream.timeout_ms`, `upstream.probe_domain`, `upstream.pool_size`, `upstream.ecs`, `upstream.per_domain` | Upstream manager and per-client scoped upstream managers rebuilt. |
| `filtering.enabled`, `filtering.refresh_interval_hours`, `filtering.blocking_mode`, `filtering.blocking_ttl`, `filtering.cname_cloaking`, `filtering.fail_closed`, `filtering.anti_doh_bypass`, `filtering.max_rules`, `filtering.max_list_bytes`, `filtering.lists`, `filtering.custom_rules` | Filter engine reloaded with the new lists/rules; cached answers are flushed. List downloads continue asynchronously after the reload. |
| `clients.entries`, `clients.groups`, `clients.client_id_secrets`, `clients.trust_routeros_lease_names`, `clients.timezone` | Client registry, per-group rule sets, schedule timezone and per-client upstream scopes rebuilt. |
| `rewrites.auto_ptr`, `rewrites.ttl`, `rewrites.entries` | Rewrite table replaced. |
| `privacy.anonymize_querylog` | Query-log writer updated. |
| `stats.retention_days` | Re-read on the next retention sweep (every 24 h). |

### 16.2 Requires a restart

| Setting | Why |
|---|---|
| `server.role`, `server.instance_name`, `server.data_dir`, `server.log_format` | Read once at process start. |
| `upstream.bootstrap` | The file watcher reuses the bootstrap resolver created at startup; `POST /api/v1/config/reload` rebuilds it immediately, but a config-file edit alone needs a restart. |
| `web.enabled`, `web.bind`, `web.port` | The admin HTTP listener is bound at startup. |
| `auth.session_ttl_hours`, `auth.login_rate_limit`, `auth.session_persist`, `auth.token_default_ttl_days` | Auth manager is created at startup. |
| `tls.cert`, `tls.key`, `tls.sni_certs`, `acme.*` | TLS/ACME setup is initialized at startup. (Certificate file *contents* are re-read by the certificate watcher; changing the configured paths needs a restart.) |
| `ha.*` | HA replication tasks are created at startup. |
| `integrations.mikrotik.*`, `integrations.lists.*` | Integration sync/refresh tasks are spawned at startup. |

> [!NOTE]
> `restart_required` is computed from the same change matrix as the table
> above: `[server]` except `log_level`, `[auth]`, the web listener fields
> (`enabled`/`bind`/`port`), `[tls]`, `[acme]`, `[ha]` and `[integrations]`.
> Everything else applies live. Editing a config file also logs a warning for
> restart-only changes (the watcher applies the rest).
>
> Same-transport port collisions are rejected at validation: `dns.dot_port`
> with `dns.doh_port` (both TCP) and `dns.doq_port` with `dns.doh3_port` (both
> UDP) must differ, as must any of them with `dns.port`. `dot_port` and
> `doq_port` may share a number (different protocols).
>
> `config_version` is evaluated whenever the file is loaded; only version `1`
> is accepted.
