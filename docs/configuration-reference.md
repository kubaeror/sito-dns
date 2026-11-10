# Configuration Reference

This document is the exhaustive configuration reference for **sito v1.9.4**.

`sito` is configured using a single TOML file (default path: `/etc/sito/config.toml` or specified via `--config <path>`). Environment-variable configuration overrides are **not supported**; all settings come from the TOML file. HA secret placeholders (`${SECRET:name}`) resolve from the `DNSD_SECRET_<name>` environment variable, then a bare `<name>` environment variable; there is no on-disk local secret store, and a placeholder that cannot be resolved rejects the whole pushed configuration.

> [!NOTE]
> The tables below are validated against the Rust config structs in CI (`scripts/check_config_reference.py`); adding a setting without documenting it fails the build.
>
> Configuration persistence round-trips modeled fields via the `Config` schema. Unrecognized or unmodeled keys and comments are omitted when the configuration is saved back to disk by the web console or API.

---

## 1. Top-Level Options

| Key | Type | Default | Description |
|---|---|---|---|
| `config_version` | integer | `1` | Configuration schema version. Only version `1` is accepted; there are **no automatic configuration migrations** in 1.9.x. The 2.0 line adds an explicit migration path. |

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
# Deprecated alias: [dns.tls] accepts the same cert/key/sni_certs fields as
# [tls] and takes precedence when both are present. Prefer [tls] for new configs.
# [dns.tls]
# cert = "/etc/sito/cert.pem"
# key = "/etc/sito/key.pem"
```

| Key | Type | Default | Description |
|---|---|---|---|
| `bind` | array of IP addresses | `["0.0.0.0", "::"]` | IP addresses to bind listeners on. |
| `port` | integer | `53` | Standard UDP and TCP DNS listener port (must be greater than 0). |
| `dot_port` | integer | `853` | DNS-over-TLS (DoT) listener port. `0` disables DoT. |
| `doh_port` | integer | `443` | DNS-over-HTTPS (DoH, HTTP/1.1 and HTTP/2) port. `0` disables DoH. |
| `doq_port` | integer | `0` | DNS-over-QUIC (DoQ) UDP port. `0` (default) disables DoQ; set `853` only when it does not conflict with DoT. |
| `doh3_port` | integer | `443` | DNS-over-HTTP/3 (DoH3) UDP port. `0` disables DoH3. |
| `doh_dedicated_hostname` | string | `""` | When set, DoH/DoH3 requests whose Host/authority does not match are rejected with `421 Misdirected Request`. Empty allows any hostname. |
| `dot_padding` | boolean | `false` | RFC 7830/8467 padding on DoT responses to mitigate traffic analysis. |
| `tls` | table | `None` | `[dns.tls]` is the effective TLS table and takes precedence over the top-level `[tls]` alias when both exist (same `cert`, `key`, `sni_certs` fields). Prefer `[dns.tls]` for new configuration; changing either table requires a restart. |
| `edns_udp_size` | integer | `1232` | Maximum EDNS0 UDP buffer size (1232 bytes prevents IPv6 fragmentation). |
| `rate_limit_per_ip` | integer | `20` | Maximum queries per second allowed from an individual source prefix (`0` disables rate limiting; maximum `1000000`). IPv4 budgets are keyed per `/24` and IPv6 per `/64`. |
| `max_tcp_connections` | integer | `256` | Maximum concurrent TCP, DoT, and DoH client connections. |
| `allow_plaintext_doh` | boolean | `false` | Allow binding the plaintext DoH listener on non-loopback addresses. When `false`, plaintext DoH is restricted to loopback. |

> [!WARNING]
> `dns.bind` defaults to `["0.0.0.0", "::"]`, and 1.9.4 has **no DNS client allow-list**.
> `rate_limit_per_ip` only limits rate; it does not authorize clients. A wildcard bind therefore accepts recursive queries from any source
> that can reach the host. Restrict the DNS ports to your LAN with a host
> firewall, or bind specific LAN addresses. The server emits a startup warning
> when a wildcard DNS bind is combined with an enabled DNS port. A
> default-deny DNS client ACL is planned for 1.10.0.

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
| `min_ttl` | integer | `60` | Minimum TTL (seconds) for unvalidated cached answers (overrides smaller upstream TTLs). DNSSEC-validated (`Secure`) answers keep the smaller authenticated TTL/RRSIG validity, so this floor can never extend their lifetime; Secure negative answers are also capped by the NSEC/NSEC3 denial proof TTL. |
| `max_ttl` | integer | `86400` | Maximum TTL (seconds) to assign to cached answers (caps excessively high upstream TTLs). |
| `negative_ttl_max` | integer | `3600` | Maximum TTL (seconds) for negative caching (NXDOMAIN / NODATA). |
| `prefetch` | boolean | `true` | When `true`, automatically re-resolves frequently requested domains before TTL expires. |
| `serve_stale_hours` | integer | `12` | Hours to serve expired cache records as fallback when upstreams are unreachable. Stale answers are served with all DNSSEC records removed and AD=0; while DNSSEC validation is active, entries cached without validation (`Unchecked`) or with an inconclusive result (`Indeterminate`) are not served. |

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
| `validate` | boolean | `true` | Enable DNSSEC processing. Validation walks DS/DNSKEY links present in the response and, when the chain is incomplete, resolves the missing DNSKEY/DS records through the configured upstreams (bounded per-query fetch budget). Cryptographic verification is bounded per response (256 RRSIG checks, at most 8 candidate keys per signature). NSEC/NSEC3 denial proofs are enumerated; NSEC3 records above 150 iterations are ignored (RFC 9276) and opt-out NXDOMAIN answers are treated as insecure. |
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
allow_bootstrap_cert = false
```

| Key | Type | Default | Description |
|---|---|---|---|
| `tls.cert` | string | `None` | Path to PEM-encoded certificate chain for DoT, DoH, DoQ and DoH3. It does **not** secure the admin Web UI, which is plain HTTP behind your reverse proxy/SSH tunnel. |
| `tls.key` | string | `None` | Path to PEM-encoded unencrypted PKCS#8 or RSA/EC private key. |
| `tls.sni_certs` | array of tables | `[]` | Additional certificate/key pairs mapped to specific SNI hostnames. |
| `acme.enabled` | boolean | `false` | Enables automated certificate issuance via Let's Encrypt / ACME. |
| `acme.email` | string | `None` | Contact email address for ACME registration. |
| `acme.domains` | array of strings | `[]` | Domain names for ACME TLS-ALPN-01 / HTTP-01 certificates. TLS-ALPN-01 is selected only when a DoH listener is actually bound on TCP 443; otherwise HTTP-01 is used when its listener binds. |
| `acme.staging` | boolean | `false` | When `true`, uses Let's Encrypt Staging API to avoid rate limits during testing. |
| `acme.cache_dir` | string | `None` | Directory used to persist ACME account keys and certificates (defaults to `<data_dir>/acme`). |
| `acme.http_port` | integer | `80` | Port for the dedicated ACME HTTP-01 challenge listener. |
| `acme.allow_bootstrap_cert` | boolean | `false` | Serve a short-lived self-signed certificate on encrypted listeners while the first ACME certificate is being issued. When `false` (default), DoT/DoH/DoQ/DoH3 stay disabled until a trusted certificate exists. |

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
# false (default): hostname-configured upstreams must resolve to public
# addresses. IP literals are always accepted as an explicit choice.
allow_private_targets = false

[[upstream.per_domain]]
domains = ["*.lan", "168.192.in-addr.arpa"]
servers = ["udp://192.168.1.1:53"]
```

| Key | Type | Default | Description |
|---|---|---|---|
| `servers` | array of strings | `["1.1.1.1", "1.0.0.1"]` | Upstream resolvers. Schemes: `udp://` or `host:port` (UDP with TCP fallback), `tls://` (DoT), `https://host[:port][/path]` (DoH, RFC 8484 with GET fallback; a bare `https://host` uses `/dns-query`), `quic://host[:port]` (DoQ, RFC 9250, default port 853). |
| `bootstrap` | array of IP addresses | `["9.9.9.9", "149.112.112.112"]` | Plain IP addresses used to bootstrap resolution of encrypted upstream domain names. Bootstrap and health-probe queries set RD=1. |
| `strategy` | string | `"failover"` | Forwarding strategy: `"parallel"` (fastest answer wins), `"failover"` (sequential fallback), or `"load_balance"`. |
| `timeout_ms` | integer | `5000` | Overall per-query budget in milliseconds, shared across failover/load-balance retries (each sequential attempt gets an equal share of the remaining budget; parallel races use the full budget). |
| `probe_domain` | string | `"example.com"` | Test domain used for periodic health-checking of upstreams. |
| `ecs` | string | `"off"` | EDNS Client Subnet policy: `"off"` strips client ECS before forwarding and deduplicates cache keys; `"forward"` forwards ECS after clamping IPv4 to /24 and IPv6 to /56 (zero source prefixes dropped). Forwarding can improve CDN locality but discloses a coarse client-location hint and splits cache entries by subnet. |
| `pool_size` | integer | `4` | Number of persistent TCP/TLS connections maintained per upstream endpoint. |
| `allow_private_targets` | boolean | `false` | Allow hostname-configured upstreams to resolve to private/loopback/link-local/reserved addresses. Disabled by default so a compromised or spoofed bootstrap cannot redirect an upstream into the local network or cloud metadata. IP literals in `servers` are always accepted as an explicit operator choice. This is a config-file-only key: the REST/UI upstream update preserves the current value rather than accepting it in the DTO. |
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
regex_compile_budget_ms = 250          # optional; abort slow regex compilation
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
| `allow_empty_list` | boolean | `false` | Accept an empty list body or a list that parses to zero rules. By default such a response is rejected, the previous snapshot is retained, and the list is marked failed so a broken CDN error page or compromised source cannot silently remove all protection. |
| `regex_compile_budget_ms` | integer | unset | Optional wall-clock budget for compiling regex/wildcard rules. When a reload exceeds it, compilation is aborted and the previous snapshot is retained; the failure is reported through `last_error` and `last_compile_ms`. Unset disables the budget; `0` is rejected. |
| `custom_rules` | array of strings | `[]` | In-line custom ABP / AdGuard filter rules. |
| `lists` | array of tables | `[]` | Subscription lists to download and compile. Schemes: `http://`, `https://`, `file://`. Global `refresh_interval_hours` controls update frequency unless a list sets `refresh_hours`. |

### `[[filtering.lists]]` entries

| Key | Type | Default | Description |
|---|---|---|---|
| `lists.name` | string | required | Unique list name shown in status, API and UI. |
| `lists.url` | string | required | Source URL (`http://`, `https://` or `file://`). |
| `lists.enabled` | boolean | `true` | Download and compile this list. |
| `lists.refresh_hours` | integer | `None` | Per-list refresh interval in hours. When unset, `filtering.refresh_interval_hours` is used. Must be greater than 0 when set. |

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
| `web.bind` | string (IP address) | `"0.0.0.0"` | Bind address for the web server. The admin UI is served over plain HTTP; see the exposure warning below. |
| `web.metrics_auth` | boolean | `true` | Require authentication (token or session) for `/metrics`. |
| `web.trusted_proxies`| array of IP addresses | `[]` | Individual proxy IPs trusted to supply `X-Forwarded-For`/`X-Forwarded-Proto` (CIDR is **not** supported here). |
| `auth.session_ttl_hours` | integer | `24` | Web session lifetime before re-authentication is required (must be ≥ 1). |
| `auth.login_rate_limit` | integer | `5` | Maximum failed login attempts allowed per minute per IP before lockout. |
| `auth.session_persist` | boolean | `true` | Persist sessions (`sessions.toml`) and API tokens (`tokens.toml`) in `data_dir` (0600). Sessions/tokens survive restarts until their TTL, but are revalidated against `users.toml` on load and on every request (account exists, role and credential epoch match); entries written before credential epochs existed are rejected once, so users re-login and API tokens are re-issued after upgrading. Corrupt stores are backed up and start empty. Stop the service before `sito reset-sessions`; the reset refuses to run against a live server unless `--force` is given. |
| `auth.token_default_ttl_days` | integer | `90` | Default lifetime of newly created API tokens in days; `0` means no expiry. |

> [!WARNING]
> `web.bind` defaults to `0.0.0.0` and the admin UI is served over plain HTTP
> by axum (the DNS `[tls]` certificate never protects the admin scheme). Do not
> expose port `8080` to the internet. The server emits a startup warning when
> the UI is reachable beyond loopback unless an `https://` `web.public_url` (or
> `web.tls_terminated_by_proxy = true` with no public URL) declares a TLS
> reverse proxy. For remote access, bind `web.bind = "127.0.0.1"` and use an SSH
> tunnel or reverse proxy. The loopback default is planned for 1.10.0; 1.9.4
> keeps the historical default so existing configurations keep working.


The running server holds an exclusive advisory lease on `<data_dir>/sito.pid`
and keeps users, sessions, API tokens and the auth generation in memory.
`sito reset-sessions` and `sito reset-admin` inspect that lease and refuse to
run while it is held, because a file-only reset would not revoke live
credentials. Stop the service (`sudo systemctl stop sito`), run the reset, then
start it (`sudo systemctl start sito`). `--force` performs the on-disk reset
while the server runs and warns that live sessions/tokens and any new admin
password take effect only after a restart. A leftover `sito.pid` from a crash is
harmless: only the lock, not the file's existence, marks the service as running.

Accounts are stored in `<data_dir>/users.toml` (0600). TOTP secrets are
encrypted at rest with AES-256-GCM using `<data_dir>/totp.key` (0600, created
automatically). Treat `totp.key` as a credential: **back it up together with
`users.toml`**. Restoring both is equivalent to the previous plaintext user
store; restoring only one is a lockout. If the key is missing or does not match
the stored secrets, the server refuses to start rather than silently disabling
2FA (`sito reset-admin` is the recovery path). An HA slave keeps its own
`totp.key`; `users.toml` is never replicated or included in HA bundles.

While a first-boot setup token is active, or `users.toml` still contains the
bootstrap `admin` / `adminadmin` credential, the HTTP middleware disables login,
token authentication and every non-wizard API/UI route. Only `/wizard`,
`/ui/wizard/*`, static assets, `/health` and `/status` remain reachable. On an
already-configured deployment this state is recovered by stopping the service
and running `sito reset-admin` (then starting it again): without `--password` it
generates a new random password and prints it once, supplied passwords must pass
the shared policy, and non-admin accounts are preserved unless `--reset-all` is
given. The command refuses to run while the service lease is held unless
`--force` is passed.

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
rollup_retention_days = 365
rollup_client_names = false

[privacy]
anonymize_querylog = false
```

| Key | Type | Default | Description |
|---|---|---|---|
| `stats.retention_days` | integer | `90` | Days to keep detailed per-query records before automated pruning and hourly aggregation (must be ≥ 1; alias: `query_log_retention_days`). |
| `stats.rollup_retention_days` | integer | `365` | Days to keep hourly rollups (aggregate totals, top domains and keyed-hash client identifiers) before deleting them (must be ≥ 1). |
| `stats.rollup_client_names` | boolean | `false` | Include client display names in hourly rollups. Off by default; raw client IPs are never stored in rollups (keyed BLAKE3 hashes are used). |
| `privacy.anonymize_querylog` | boolean | `false` | Mask client IPs (/24 for IPv4, /56 for IPv6) before persisting to database and before live-tail broadcast. |

> Clearing the query log (`DELETE /api/v1/querylog`, `sito clear-query-log`, or
> the UI “Clear Logs” button) deletes both `query_log` and `stats_hourly` by
> default. Pass `?keep_aggregates=true` (API) or `--keep-aggregates` (CLI) to
> preserve rollups. Large clears are vacuumed and
> SQLite runs with `secure_delete=ON`. Rollup client IPs are keyed BLAKE3
> hashes using `<data_dir>/stats-salt` (0600); client names are omitted unless
> `rollup_client_names = true`. Switching `rollup_client_names` from `true` to
> `false` scrubs names from existing rollups on the next startup. Archived
> per-client rows therefore show the keyed hash (`blake3:…`) instead of a raw
> address for data older than the detailed query-log retention. Existing raw
> rollups are hashed once on startup by the database backfill; existing raw
> `query_log` rows are not retroactively anonymized. `sito clear-query-log`
> takes the service lease and refuses a running server unless `--force` is
> given.

> Query logging is always enabled when `[stats]` is present. Prometheus metrics
> are exposed at `/metrics` and require a Viewer-or-higher bearer token or
> session when `web.metrics_auth = true` (the default); set
> `web.metrics_auth = false` only for a deliberately unauthenticated scrape
> network.

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
| `cert` / `key` / `ca` | string | `None` | Paths to mTLS certificates and CA bundles for replication. When `ca` is set, the peer chain is validated against it **including hostname/SAN verification**, even when BLAKE3 pinning is also configured. |
| `ping_interval_secs` | integer | `15` | Master heartbeat interval. Slaves silent for 3× this interval are disconnected and removed from the active tracker. |
| `slave_token` | string | `None` | Pre-shared token for slave authentication (mandatory when serving plaintext `ws://`). |
| `pinned_slave_fingerprints` | array of strings | `[]` | BLAKE3 fingerprints of slave certificates accepted by the master. |
| `allow_unpinned_tls` | boolean | `false` | Allow TLS peers without a configured fingerprint (insecure; only for controlled networks). |
| `allow_insecure_ws` | boolean | `false` | Allow plaintext `ws://` replication. Requires a non-empty `slave_token`; must be set explicitly on both ends. |
| `stats_interval_secs` | integer | `30` | Interval between slave-to-master statistics reports. |

The slave stores a **single** `master_fingerprint`; the master stores a list of
accepted `pinned_slave_fingerprints`. During certificate rotation, the master
can pin both the old and new slave fingerprints at once, while each slave must
switch its one master fingerprint to the new value. `allow_unpinned_tls = true`
is an explicit insecure opt-out; with `ca` configured, the server name is still
checked against the certificate SAN.

Private keys referenced by `key` are read by the unprivileged service account
(`sito` under systemd, uid/gid `65532` in the container image). Generate them
with ownership transfer (`sito ha gen-certs --uid <UID> --gid <GID>`, both
required together) or `chown` them after copying; a key owned by another user
fails the mTLS listener even though DNS keeps answering. Replication readiness
is exposed as `ready` and `readiness_reason` in `GET /api/v1/ha/status`; the
unauthenticated `/health` endpoint reports only a generic ready flag, and the
`healthcheck` subcommand fails when `[ha]` requires replication but the master
listener or slave handshake is not ready. Because
readiness is reported by the admin web listener, keep `[web] enabled = true`
(the default) on HA nodes; with the web listener disabled the healthcheck
fails closed rather than assuming replication is healthy.

Slaves persist the last successfully applied bundle identity to
`<data_dir>/ha_watermark.toml` (JSON, mode `0600`, written atomically) after
the configuration is applied and before the push is acknowledged. The file
records the term, version, signed payload hash and application timestamp. It is
restored at startup: pushes from an older term are rejected, pushes below the
recorded version within the same term are rejected, and a push at the same
version is only accepted when the signed payload hash matches. A corrupt or
unreadable watermark fails startup rather than resetting to version 0; delete
it only when you intend to force a full resync from the master. The watermark
is node-local and must not be copied between slaves.

A slave must receive a frame (push, ping/pong, stats or close) within
`3 × ping_interval_secs` (default 45 s); otherwise it leaves `Synced`, records a
`readiness_reason`, and `/health` reports not ready while DNS keeps serving the
last applied configuration. The watermark also records a BLAKE3 digest of the
exact applied `config.toml`; a local edit or revert marks the node `Degraded`
and forces a full apply before it can report `Synced` again. A watermark written
by 1.9.3 or earlier has no digest and forces one full apply after upgrade.
Master publish failures are reported through `ha_publish` on config writes and
make HA readiness false. `POST /api/v1/ha/resync` returns `200` when the request
was accepted (including a master with no connected slaves and no active bundle,
which reports `slaves_notified: 0`). It returns `503` when replication is
inactive, the slave worker is stopped, or a master has connected slaves and an
active bundle but the push could not be queued for any of them.

Replication preserves node-local identity. The master does not overwrite a
slave's `dns.bind`, `[dns.tls]`/`[tls]` certificate paths, `[acme]` account and
cache settings, the `[web]` admin identity (`enabled`, `bind`, `port`,
`trusted_proxies`, `metrics_auth`, `public_url`, `tls_terminated_by_proxy`),
`[ha]`, `server.instance_name`, `server.data_dir`,
`[integrations.mikrotik]` or `clients.client_id_secrets`. Web identity is
node-local: a slave may disable the admin listener or reach it through a
different bind/proxy/URL than the master, and those differences do not make a
push fail. `dns.port` and the other listener ports are shared configuration;
the runbook's master `bind = ["0.0.0.0", "::"]` and slave
`bind = ["0.0.0.0"]` therefore coexist, including on hosts without IPv6.

If a push changes a restart-only field that is **not** preserved as node-local
(for example `server.log_format` or `[auth]`), the slave rejects the push before
applying or persisting anything: it keeps its previous live configuration and
file, enters `Degraded`, and ACKs `applied: false` with a `restart_required`
reason naming the fields. Restart the slave with the intended configuration (or
change those fields locally) before expecting the master to report it synced.

`[auth]` is compared as effective policy: an explicit table containing the
default values is equivalent to omitting `[auth]`, and legacy keys already
stripped from replicated bundles (`admin_password_hash`, `tokens`) do not count
as changes. Non-default `session_ttl_hours`, `login_rate_limit`,
`session_persist` or `token_default_ttl_days` still require a restart.

Cluster terms are node-persisted, not configuration keys: the master stores the
current term inside `ha_state.toml` and only an explicit promotion (editing the
state file and restarting, see `docs/runbook-ha.md`) raises it. A promotion must
raise both the term and the version above the cluster high-water mark: a higher
term alone does not bypass version continuity, so a promoted node with a stale
state file cannot roll the cluster back. Upgrade every slave before promoting a
master so the new term is persisted; a stale master from an older term then
cannot overwrite newer configuration even if its version counter is higher.

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
| `token_env` | string | `None` | Environment variable containing the RouterOS API token. When unset, no bearer-token authentication is attempted (use `username`/`password_env` instead). |
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

The running server watches the file passed to `--config`. Without an explicit
flag an existing `./config.toml` is preferred, then `/etc/sito/config.toml`
(the systemd unit and container image pass `/etc/sito/config.toml` explicitly)
and re-applies the settings below in-process. A
configuration that cannot be parsed or validated is rejected as a whole: the
previous settings stay active and the error is logged. The REST API reports
restart-only changes in the `restart_required` field of `PUT /api/v1/config`
and `POST /api/v1/config/reload`.

> [!NOTE]
> The watcher compares the parsed file with the running configuration before
> applying it. An identical external save (including a file already written by
> the HA applier) is ignored and does **not** force a full re-apply. When an
> explicit reload is required, use `POST /api/v1/config/reload`: it re-reads
> the file and applies it even when the content matches the current runtime.

### 16.1 Applied live (no restart)

| Setting | How it is applied |
|---|---|
| `server.log_level` | Log-level filter reloaded. |
| `server.update_require_signature` | Read when an update is started, not at boot. |
| `web.metrics_auth`, `web.trusted_proxies`, `web.public_url`, `web.tls_terminated_by_proxy` | Read from the live configuration when a request is handled. |
| `dns.bind`, `dns.port`, `dns.dot_port`, `dns.doh_port`, `dns.doq_port`, `dns.doh3_port`, `dns.doh_dedicated_hostname`, `dns.dot_padding`, `dns.edns_udp_size`, `dns.max_tcp_connections`, `dns.allow_plaintext_doh` | DNS listeners are stopped and rebound in-process when the listener plan changes; a failed rebind restores the previous bindings. TLS listeners need the acceptors created at startup. |
| `dns.rate_limit_per_ip` | Live rate limiters updated. |
| `dns.cache.enabled`, `dns.cache.size_mb`, `dns.cache.min_ttl`, `dns.cache.max_ttl`, `dns.cache.negative_ttl_max`, `dns.cache.prefetch`, `dns.cache.serve_stale_hours` | Cache configuration updated. |
| `dns.dnssec.mode`, `dns.dnssec.validate`, `dns.dnssec.ntp`, `dns.dnssec.nta`, `dns.dnssec.trust_anchors` | DNSSEC validator swapped for the new configuration; the response cache is flushed because cached validation decisions belong to the old policy. |
| `upstream.servers`, `upstream.bootstrap`, `upstream.strategy`, `upstream.timeout_ms`, `upstream.probe_domain`, `upstream.pool_size`, `upstream.ecs`, `upstream.allow_private_targets`, `upstream.per_domain` | Upstream manager and per-client scoped upstream managers rebuilt, including a fresh bootstrap resolver and SSRF policy. |
| `filtering.enabled`, `filtering.refresh_interval_hours`, `filtering.blocking_mode`, `filtering.blocking_ttl`, `filtering.cname_cloaking`, `filtering.fail_closed`, `filtering.anti_doh_bypass`, `filtering.max_rules`, `filtering.max_list_bytes`, `filtering.allow_empty_list`, `filtering.regex_compile_budget_ms`, `filtering.lists`, `filtering.custom_rules` | Filter engine reloaded with the new lists/rules; cached answers are flushed. List downloads continue asynchronously after the reload. |
| `clients.entries`, `clients.groups`, `clients.client_id_secrets`, `clients.trust_routeros_lease_names`, `clients.timezone` | Client registry, per-group rule sets, schedule timezone and per-client upstream scopes rebuilt. |
| `rewrites.auto_ptr`, `rewrites.ttl`, `rewrites.entries` | Rewrite table replaced. |
| `privacy.anonymize_querylog` | Query-log writer updated. |
| `stats.retention_days`, `stats.rollup_retention_days`, `stats.rollup_client_names` | Re-read on the next retention sweep (every 24 h). |

### 16.2 Requires a restart

| Setting | Why |
|---|---|
| `server.role`, `server.instance_name`, `server.data_dir`, `server.log_format` | Read once at process start. |
| `web.enabled`, `web.bind`, `web.port` | The admin HTTP listener is bound at startup. |
| `auth.session_ttl_hours`, `auth.login_rate_limit`, `auth.session_persist`, `auth.token_default_ttl_days` | Auth manager is created at startup. |
| `tls.cert`, `tls.key`, `tls.sni_certs`, `dns.tls.cert`, `dns.tls.key`, `dns.tls.sni_certs`, `acme.*` | TLS/ACME setup is initialized at startup. (Certificate file *contents* are re-read by the certificate watcher; changing the configured paths needs a restart.) |
| `ha.*` | HA replication tasks are created at startup. |
| `integrations.mikrotik.*`, `integrations.lists.*` | Integration sync/refresh tasks are spawned at startup. |

> [!NOTE]
> `restart_required` is computed from the same change matrix as the table
> above: `[server]` except `log_level`, `[auth]`, the web listener fields
> (`enabled`/`bind`/`port`), `[tls]`, `[acme]`, `[ha]` and `[integrations]`.
> Everything else applies live. Editing a config file also logs a warning for
> restart-only changes (the watcher applies the rest).
>
> On HA slaves the master's `[web]` values are replaced with the node-local
> ones before this check, so an intentional difference in web identity does
> not produce `restart_required: web`. Changing a slave's own listener shape
> still requires restarting that slave.
>
> The HA readiness healthcheck still requires the admin web listener. A slave
> with `web.enabled = false` can replicate and become `Synced`, but it reports
> not ready; this policy is unchanged.
>
> Same-transport port collisions are rejected at validation: `dns.dot_port`
> with `dns.doh_port` (both TCP) and `dns.doq_port` with `dns.doh3_port` (both
> UDP) must differ, as must any of them with `dns.port`. `dot_port` and
> `doq_port` may share a number (different protocols).
>
> `config_version` is evaluated whenever the file is loaded; only version `1`
> is accepted.
