# Configuration Reference

This document is the exhaustive configuration reference for **sito v1.0.0**.

`sito` is configured using a single TOML file (default path: `/etc/sito/config.toml` or specified via `--config <path>`). Environment variables can override any setting using the `DNSD__<SECTION>__<KEY>` naming convention (double underscores between hierarchy levels).

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
instance_name = "sito-node-01"         # Unique identifier in cluster
data_dir = "/var/lib/sito"             # Base path for database, caches, and state
log_level = "info"                     # "trace" | "debug" | "info" | "warn" | "error"
log_format = "pretty"                  # "pretty" | "json"
```

| Key | Type | Default | Description |
|---|---|---|---|
| `role` | string | `"master"` | HA cluster role: `"master"` (reads/writes, replicates state) or `"slave"` (read-only replica). |
| `instance_name` | string | `"sito-node-01"` | Name of this server instance, reported in metrics and logs. |
| `data_dir` | string | `"/var/lib/sito"` | Directory where persistent SQLite DB (`sito.db`), list caches, and TLS state are stored. |
| `log_level` | string | `"info"` | Logging verbosity: `"trace"`, `"debug"`, `"info"`, `"warn"`, or `"error"`. |
| `log_format` | string | `"pretty"` | Formatting for stdout logs: `"pretty"` (human readable with colors) or `"json"` (structured). |

---

## 3. `[dns]` — Listener Protocols and Sockets

```toml
[dns]
bind = ["0.0.0.0", "::"]
port = 53
dot_port = 853
doh_port = 443
doq_port = 853
doh3_port = 443
doh_dedicated_hostname = "dns.example.com"
dot_padding = false
edns_udp_size = 1232
rate_limit_per_ip = 20
max_tcp_connections = 256
```

| Key | Type | Default | Description |
|---|---|---|---|
| `bind` | array of strings | `["0.0.0.0", "::"]` | IP addresses to bind listeners on. |
| `port` | integer | `53` | Standard UDP and TCP DNS listener port. `0` disables plain UDP/TCP. |
| `dot_port` | integer | `853` | DNS-over-TLS (DoT) listener port. `0` disables DoT. |
| `doh_port` | integer | `443` | DNS-over-HTTPS (DoH, HTTP/1.1 and HTTP/2) port. `0` disables DoH. |
| `doq_port` | integer | `853` | DNS-over-QUIC (DoQ) UDP port. `0` disables DoQ. |
| `doh3_port` | integer | `443` | DNS-over-HTTP/3 (DoH3) UDP port. `0` disables DoH3. |
| `doh_dedicated_hostname` | string | `""` | Optional hostname restriction for DoH virtual hosts. Empty string allows any Host/SNI. |
| `dot_padding` | boolean | `false` | RFC 7830/8467 padding on DoT responses to mitigate traffic analysis. |
| `edns_udp_size` | integer | `1232` | Maximum EDNS0 UDP buffer size (1232 bytes prevents IPv6 fragmentation). |
| `rate_limit_per_ip` | integer | `20` | Maximum queries per second allowed from an individual client IP. `0` disables rate limiting. |
| `max_tcp_connections` | integer | `256` | Maximum concurrent TCP, DoT, and DoH client connections. |

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
| `mode` | string | `"validate"` | Validation mode (`"validate"`, `"log_only"`, or `"off"`). |
| `validate` | boolean | `true` | Enable RFC 4035 cryptographic DNSSEC validation against root trust anchors. |
| `ntp` | array of strings | `[]` | Negative Trust Anchors: domains exempt from DNSSEC validation. |

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
domain = "dns.example.com"
staging = false
```

| Key | Type | Default | Description |
|---|---|---|---|
| `tls.cert` | string | `None` | Path to PEM-encoded certificate chain for DoT, DoH, and Web UI. |
| `tls.key` | string | `None` | Path to PEM-encoded unencrypted PKCS#8 or RSA/EC private key. |
| `tls.sni_certs` | array of tables | `[]` | Additional certificate/key pairs mapped to specific SNI hostnames. |
| `acme.enabled` | boolean | `false` | Enables automated certificate issuance via Let's Encrypt / ACME. |
| `acme.email` | string | `""` | Contact email address for ACME registration. |
| `acme.domain` | string | `""` | Primary domain name for ACME TLS-ALPN-01 / HTTP-01 certificates. |
| `acme.staging` | boolean | `false` | When `true`, uses Let's Encrypt Staging API to avoid rate limits during testing. |

---

## 7. `[upstream]` — Forwarding and Upstream Resolvers

```toml
[upstream]
servers = [
    "tls://dns.quad9.net",
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
| `servers` | array of strings | `["tls://..."]` | Upstream resolvers. Schemes: `udp://` or `host:port` (UDP with TCP fallback), `tls://` (DoT). |
| `bootstrap` | array of IPs | `["9.9.9.9"]` | Plain IP addresses used to bootstrap resolution of encrypted upstream domain names. |
| `strategy` | string | `"failover"` | Forwarding strategy: `"parallel"` (fastest answer wins), `"failover"` (sequential fallback), or `"load_balance"`. |
| `timeout_ms` | integer | `5000` | Request timeout per upstream query in milliseconds. |
| `probe_domain` | string | `"example.com"` | Test domain used for periodic health-checking of upstreams. |
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
| `anti_doh_bypass` | string | `"off"` | Block known public DoH/DoT resolvers to enforce network-wide filtering: `"off"`, `"block_all"`, or `"block_except_trusted"`. |
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
safe_search = true
parental_control = true
blocked_services = ["tiktok", "youtube"]

[[clients.groups]]
name = "kids"
filtering_enabled = true
safe_search = true
parental_control = true
blocked_categories = ["adult", "gambling"]
```

| Key | Type | Default | Description |
|---|---|---|---|
| `entries` | array of tables | `[]` | Client definitions mapping IP addresses, CIDR subnets, MAC addresses, or DoT/DoH ClientIDs to groups. |
| `groups` | array of tables | `[]` | Policy groups with distinct filtering, safe search, parental control, and service schedules. |

---

## 10. `[rewrites]` — Local DNS Records & Overrides

```toml
[rewrites]
auto_ptr = true

[[rewrites.entries]]
domain = "*.home.arpa"
type = "A"
answer = "192.168.1.10"
exception_clients = ["admin-laptop"]
```

| Key | Type | Default | Description |
|---|---|---|---|
| `auto_ptr` | boolean | `true` | Automatically synthesize reverse PTR records (`in-addr.arpa` / `ip6.arpa`) for local A/AAAA rewrites in RFC 1918 / ULA ranges. |
| `entries` | array of tables | `[]` | Local record rewrites (`domain`, `type` (`A`/`AAAA`/`CNAME`/`PTR`/`TXT`), `answer`, and optional `exception_clients`). |

---

## 11. `[web]` & `[auth]` — Administration API and Web Interface

```toml
[web]
port = 8080
bind = ["0.0.0.0"]
https = false
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

[auth]
session_ttl_hours = 24
login_rate_limit = 5
```

| Key | Type | Default | Description |
|---|---|---|---|
| `web.port` | integer | `8080` | Port for the Web Dashboard and REST API (`/api/v1/`). |
| `web.bind` | array of strings | `["0.0.0.0"]` | Bind addresses for web server. |
| `web.https` | boolean | `false` | When `true`, serves Web UI exclusively over HTTPS using `tls.cert`/`tls.key`. |
| `web.trusted_proxies`| array of CIDRs | `[]` | CIDR blocks trusted to forward client IP headers (`X-Forwarded-For`). |
| `auth.session_ttl_hours` | integer | `24` | Web session lifetime before re-authentication is required. |
| `auth.login_rate_limit` | integer | `5` | Maximum failed login attempts allowed per minute per IP before lockout. |

---

## 12. `[stats]` — Metrics and Query Logging

```toml
[stats]
query_log_enabled = true
query_log_retention_days = 90
anonymize_client_ip = false
prometheus_enabled = true
```

| Key | Type | Default | Description |
|---|---|---|---|
| `query_log_enabled` | boolean | `true` | Enable recording queries to persistent SQLite storage. |
| `query_log_retention_days` | integer | `90` | Days to keep detailed per-query records before automated pruning and hourly aggregation. |
| `anonymize_client_ip` | boolean | `false` | Mask client IPs (/24 for IPv4, /56 for IPv6) before persisting to database for privacy. |
| `prometheus_enabled` | boolean | `true` | Expose Prometheus metrics on `/metrics` endpoint. |

---

## 13. `[ha]` — High-Availability Master/Slave Replication

```toml
[ha]
replication_port = 8953

# On Slave instance:
# master_url = "wss://192.168.1.10:8953"
# master_fingerprint = "blake3:4f8a12..."
# cert = "/etc/sito/ha_slave.crt"
# key = "/etc/sito/ha_slave.key"
# ca = "/etc/sito/ha_ca.crt"
```

| Key | Type | Default | Description |
|---|---|---|---|
| `replication_port` | integer | `8953` | Mutual-TLS WebSocket port for config synchronization. |
| `master_url` | string | `None` | (Slave only) WebSocket URL of the master instance. |
| `master_fingerprint` | string | `None` | (Slave only) Expected Blake3 public certificate fingerprint of master for pinning. |
| `cert` / `key` / `ca` | string | `None` | Paths to mTLS certificates and CA bundles for replication channel. |

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
| `url` | string | `""` | Base URL of RouterOS REST API (`https://router.lan`). |
| `token_env` | string | `""` | Environment variable containing HTTP basic/bearer authentication token. |
| `interval_s` | integer | `300` | Polling interval in seconds to refresh active DHCP lease table. |
