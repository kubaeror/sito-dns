# Migrating from AdGuard Home to sito

This guide explains how to migrate existing AdGuard Home configurations, subscription lists, custom ABP rules, client definitions, and DNS rewrites to **sito**.

---

## 1. Automated Migration Using `adguard_to_sito.py`

`sito` provides an automated Python conversion script located in `contrib/adguard_to_sito.py`. It parses an existing `AdGuardHome.yaml` file and generates a complete, valid `config.toml` for `sito`.

### 1.1 Running the Converter
```bash
# Locate your AdGuardHome.yaml (usually in /opt/AdGuardHome or /etc/AdGuardHome)
python3 contrib/adguard_to_sito.py \
  -i /opt/AdGuardHome/AdGuardHome.yaml \
  -o /etc/sito/config.toml
```

### 1.2 Verifying the Generated Configuration
Before starting the server, validate the converted configuration against the sito schema:
```bash
sito check-config --config /etc/sito/config.toml
```
If validation passes, the command exits with code `0` and prints `"Configuration is valid."`.

---

## 2. Component Mapping Overview

| AdGuard Home Setting | sito Equivalent | Notes |
|---|---|---|
| `dns.upstream_dns` | `[upstream] servers = [...]` | Full support for DoT (`tls://`), DoH (`https://`), plain DNS, and DoQ (`quic://`). |
| `dns.bootstrap_dns` | `[upstream] bootstrap = [...]` | Bootstrap IP addresses for encrypted upstreams. |
| `dns.blocking_mode` | `[filtering] blocking_mode = "..."` | `default`/`null_ip` maps to `zero_ip` (`0.0.0.0`/`::`). |
| `filters` (subscriptions) | `[[filtering.lists]]` | Preserves list name, URL, and enabled status. |
| `user_rules` (custom rules) | `[filtering] custom_rules = [...]` | 100% ABP syntax compatibility (domain anchors, wildcards, `$badfilter`, `$client`, `$dnsrewrite`). |
| `clients.persistent` | `[[clients.entries]]` | Maps client IP, CIDR, MAC address, and DoT/DoH ClientID tokens. |
| `dns.rewrites` | `[[rewrites.entries]]` | Exact domain and wildcard (`*.example.com`) local DNS overrides. |
| `tls.certificate_path` | `[tls] cert = "..."` | Direct PEM certificate reuse. |
| `tls.private_key_path` | `[tls] key = "..."` | Direct private key reuse. |

---

## 3. Key Differences and Deliberate Decisions

### 3.1 Precedence: Local Rewrites vs. `$important` Rules (ADR-0007)
* **AdGuard Home Behavior:** Local DNS rewrites unconditionally override block rules, even if an adblock rule specifies the `$important` modifier.
* **sito Behavior (ADR-0007):** In `sito`, explicit `$important` rules represent an absolute administrative block and take precedence over local rewrites. If you need a local rewrite to override an `$important` block, add an explicit allowlist rule (`@@||domain.com^$important`) or remove `$important` from the blocking rule.

### 3.2 High-Availability Replication (M8)
* While AdGuard Home relies on third-party synchronization tools (`adguardhome-sync`) that execute API poll loops, `sito` includes native, real-time master/slave state push over mutual-TLS WebSockets (`[ha]`), with cryptographic Ed25519 signing and sub-second convergence.

### 3.3 Resource Efficiency & Throughput
* `sito` uses single-binary Rust architecture with lock-free data structures, processing cache hits in < 1 µs with zero runtime GC pauses, compared to Go runtime garbage collection overhead under heavy load.

---

## 4. Cutover Procedure

1. **Stop AdGuard Home:**
   ```bash
   sudo systemctl stop AdGuardHome
   sudo systemctl disable AdGuardHome
   ```
2. **Start sito:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now sito
   ```
3. **Verify Resolution:**
   ```bash
   dig @127.0.0.1 -p 53 doubleclick.net +short
   # Should return: 0.0.0.0
   ```
4. **Access Dashboard:**
   Navigate to `http://<server-ip>:8080` and log in with default credentials (`admin` / `adminadmin`).
