# Policy Resolution Matrix & Evaluation Architecture (Phase M4)

This document formalizes the client identification pipeline, policy routing, schedule evaluation, and ADR-0007 query resolution precedence implemented in `sito` Phase M4.

---

## 1. Client Identification Chain

Every incoming DNS query is associated with a client context resolved through a 5-tier identification chain evaluated in strict order of specificity:

```
Incoming Request
      │
      ▼
1. DoH ClientID / URL Path (`/dns-query/{client_id}`)
      │ (not found / not DoH)
      ▼
2. DoT SNI Subdomain (`{client_id}.dns.<domain>` or direct SNI)
      │ (not found / not DoT)
      ▼
3. Static IP or CIDR Subnet Match (e.g. `192.168.1.50`, `192.168.2.0/24`)
      │ (no IP match in configured clients)
      ▼
4. Hardware MAC Address Matching:
      ├─ Kernel ARP table (`/proc/net/arp` or `ip neigh` with 60s TTL cache)
      └─ MikroTik RouterOS DHCP Lease Import (`GET /rest/ip/dhcp-server/lease`)
      │ (no MAC match)
      ▼
5. Fallback to `default` Client Profile / Unidentified Client Tracking
```

### Invariants:
1. **Explicit Identity Beats IP:** A client ID provided in the DoH path (`/dns-query/kids-phone`) or DoT SNI (`kids-phone.dns.lan`) always overrides the client's source IP address.
2. **Graceful Fallback:** Unidentified clients are routed to the `default` group. Unidentified clients discovered via RouterOS or ARP are recorded in `unidentified_clients` for administrative discovery without interrupting resolution.
3. **RouterOS Lease Sync:** Queries the RouterOS REST API periodically (default 300s). Router outages or network partitions trigger warnings and gracefully degrade, retaining existing leases.

---

## 2. Policy Resolution & Lazy Schedule Evaluation

When a client is resolved, its effective group policy is compiled lazily at query time:

| Attribute | Kids Group | Adults Group | Bypass Group | Default Group |
|---|---|---|---|---|
| **Ad & Tracker Filtering** | Enabled | Enabled | **Disabled** (`filtering = false`) | Enabled |
| **Safe Search** | Enabled (`strict` YouTube) | Disabled | Disabled | Disabled |
| **Parental Controls** | Enabled (`adult`, `gambling`) | Disabled | Disabled | Disabled |
| **Blocked Services** | `["tiktok", "youtube"]` | None | None | None |
| **Schedules** | 5- or 6-field cron expressions | None | None | None |

### Schedule Evaluation (`croner`):
- Evaluated lazily at query timestamp using UTC.
- Supports both standard 5-field cron (`min hour dom month dow`) and 6-field cron with seconds (`sec min hour dom month dow`).
- Supports interval ranges (e.g. `0 0 15-21 * * MON-FRI` for 15:00:00 through 21:59:59).
- Syntax errors in configuration are rejected at load time via `sito check-config` with the exact 1-indexed field number that failed validation.

---

## 3. ADR-0007 Query Resolution Precedence

The pipeline guarantees strict deterministic resolution order ratifying [ADR-0007](file:///home/ubuntu/sito-dns/docs/adr/0007-precedence-rewrites-vs-important.md):

```
                        Incoming DNS Query
                                │
                                ▼
                 Client Identification & Policy Resolve
                                │
                   Is filtering enabled for group?
                                ├── No ───► Skip Stages 1 & 3
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 1: $important Filter Evaluation                                  │
│ - @@...$important (explicit allow)                                      │
│ - ||...$important (explicit block)                                      │
│ * $important BLOCK beats Local Rewrites!                                │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ (not blocked by $important)
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 2: Local DNS Rewrites & Auto-PTR (sito-rewrites)                  │
│ - Client exemption check (exception_clients bypasses rewrite)           │
│ - Exact record match (A, AAAA, PTR, TXT)                                │
│ - Exact CNAME with local chain resolution                               │
│ - Auto-PTR table (RFC1918 IPv4 & ULA IPv6 reverse zones)                │
│ - Wildcard match (*.home.arpa)                                          │
│ * Local rewrites beat standard filter blocks, cache, and upstream!     │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ (no local rewrite matched)
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 3: Standard Filtering, Parental Control & Service Blocking        │
│ - Parental Control categories (adult, gambling)                         │
│ - Service Blocking (AdGuard-compatible services.json, scheduled)        │
│ - Standard filter rules (allowlist @@, denylist ||, regex, badfilter)   │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ (not blocked)
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 4: Safe Search System Rewrites                                    │
│ - Google, Bing, DuckDuckGo CNAME rewrite                                │
│ - YouTube strict/moderate CNAME rewrite                                 │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ (no safe search rewrite)
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 5: Cache Lookup & Upstream Resolution                             │
│ - In-memory LRU/SLRU DNS cache hit                                      │
│ - Upstream forwarding (UDP / TCP / DoT / DoH)                            │
│ - CNAME uncloaking verification against FilterEngine                     │
│ - DNSSEC validation & cache insertion                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Test Matrix Verification

The implementation is verified by unit and end-to-end acceptance tests in `crates/sito-test`:

| Scenario | Input Query | Client / Group | Expected Verdict | Verified Test |
|---|---|---|---|---|
| **Parental Control** | `pornhub.com` | `kid-device` (kids) | **Blocked** (`0.0.0.0`) | `test_acceptance_m4_policy_matrix_devices_and_groups` |
| **Parental Control** | `pornhub.com` | `adult-device` (adults) | **Allowed** (upstream IP) | `test_acceptance_m4_policy_matrix_devices_and_groups` |
| **Bypass Group** | `ad-tracker.com` | `guest-device` (bypass) | **Allowed** (bypasses filter) | `test_acceptance_m4_policy_matrix_devices_and_groups` |
| **Service Blocking** | `tiktok.com` | `kid-device` (kids) | **Blocked** (`0.0.0.0`) | `test_acceptance_m4_policy_matrix_devices_and_groups` |
| **Safe Search** | `www.google.com` | `kid-device` (kids) | **CNAME** `forcesafesearch.google.com.` | `test_acceptance_m4_policy_matrix_devices_and_groups` |
| **Wildcard Rewrite** | `nas.home.arpa` | Any client | **Rewritten** (`192.168.1.10`) | `test_acceptance_m4_local_rewrites_wildcard_and_auto_ptr` |
| **Auto-PTR** | `50.1.168.192.in-addr.arpa` | Any client | **PTR** `printer.lan.` | `test_acceptance_m4_local_rewrites_wildcard_and_auto_ptr` |
| **CNAME Chain** | `app.lan` | Any client | **CNAME** `web.lan` + **A** `192.168.1.80` | `test_acceptance_m4_local_rewrites_wildcard_and_auto_ptr` |
| **Rewrite Exemption** | `nas.lan` | `admin-laptop` | **Bypassed** (upstream IP) | `test_acceptance_m4_local_rewrites_wildcard_and_auto_ptr` |
| **ADR-0007 Block** | `tracker.lan` (`$important`) | Any client | **Blocked** (`0.0.0.0`, beats rewrite) | `test_acceptance_m4_adr007_precedence_important_vs_rewrite` |
| **ADR-0007 Rewrite** | `printer.lan` (standard block) | Any client | **Rewritten** (`192.168.1.50`, beats block) | `test_acceptance_m4_adr007_precedence_important_vs_rewrite` |
| **DoT SNI ID** | `www.google.com` | SNI `phone.dns.sito-test.local` | **CNAME** `forcesafesearch.google.com.` | `test_acceptance_m4_dot_sni_client_identification` |
| **Bad Cron Validation** | `bad_cron.toml` | N/A | **Rejected** with field error | `test_acceptance_check_config_rejects_bad_cron` |
