# Security Review and Threat Model Audit (v1.0.0)

This document provides a comprehensive security review of **sito v1.0.0**, detailing the audit findings, defensive mechanisms, and verification procedures across all critical attack vectors identified in **Plan Section 18** and **Phase M9.3**.

---

## 1. Security Audit Checklist

| Domain | Control / Verification | Implementation Reference | Status |
|---|---|---|---|
| **Supply Chain** | `cargo deny check` & `cargo audit` clean | `deny.toml`, root `Cargo.lock` | **VERIFIED** |
| **SSRF** | URL scheme allowlist (`http`, `https`, `file`) | `sito-filter::downloader`, `sito-core::config` | **VERIFIED** |
| **ReDoS** | Strict DFA compile budgets; zero backtracking | `sito-filter::structures::compiled` | **VERIFIED** |
| **Auth Timing** | Constant-time password, token & backup code checks | `sito-api::auth::manager`, `subtle` | **VERIFIED** |
| **DoS / Flooding** | Per-IP token bucket limiter, connection caps | `sito-transport::limiter`, `sito-transport::tcp` | **VERIFIED** |
| **Secret Leakage** | Zero credentials in logs, errors, or HA bundles | `sito-stats`, `sito-api::error`, `sito-ha` | **VERIFIED** |
| **TLS Hardening** | TLS 1.2+ mandatory; TLS < 1.2 rejected; AEAD ciphers | `sito-transport::tls` | **VERIFIED** |

---

## 2. Detailed Threat Analysis & Mitigations

### 2.1 Server-Side Request Forgery (SSRF) Protection
* **Threat:** Malicious blocklist subscription URLs (e.g., `gopher://`, `dict://`, `file:///etc/shadow`, `ldap://`) passed via API or configuration to pivot inside private network perimeters or read local system files.
* **Mitigations Implemented:**
  1. **Strict Scheme Allowlist:** In `FilteringConfig::validate()` and `sito-filter::downloader`, URLs are restricted to `http://`, `https://`, and `file://`. Any URL containing unapproved protocols is rejected at configuration validation time with HTTP 400 Bad Request.
  2. **File URI Sandboxing:** `file://` URIs are intended for local list mounts (e.g., in Docker or air-gapped homelabs) and require file system read permissions of the unprivileged `sito` daemon user.
  3. **LAN Subscription Documentation:** Subscriptions are permitted to contact LAN IPs (RFC 1918 / ULA) because users commonly host custom lists on internal Pi-hole or RouterOS HTTP servers. When deployed in untrusted multi-tenant environments, operators may enforce network namespace egress firewalls.

### 2.2 Regular Expression Denial of Service (ReDoS) Protection
* **Threat:** User-supplied custom regular expressions in blocklists (e.g., `/(a+)+$/` or nested quantifiers) causing exponential backtracking in regex engines, freezing worker threads.
* **Mitigations Implemented:**
  1. **Deterministic Finite Automata (DFA):** All user regex patterns and ABP wildcards are compiled exclusively using `regex-automata` dense DFAs. DFAs execute in strictly deterministic linear time $O(N)$ proportional only to the length of the query domain string, completely eliminating algorithmic backtracking.
  2. **DFA Memory Compilation Ceiling:** A hard memory limit of 10 MB is enforced on DFA state graphs during compilation (`dense::Config::new().dfa_size_limit(Some(10 * 1024 * 1024))`). Any adversarial pattern attempting state explosion is rejected cleanly without crashing or starving heap memory.

### 2.3 Constant-Time Authentication & Timing Attack Protection
* **Threat:** Statistical timing analysis of password verification, API bearer token validation, or TOTP backup code matching to infer secret contents character-by-character.
* **Mitigations Implemented:**
  1. **Argon2id for Passwords:** Passwords utilize Argon2id ($m=64\text{ MiB}, t=3, p=4$) with salt generation via cryptographically secure OS RNG (`OsRng`). The `argon2` crate internally performs constant-time hash comparison via the `subtle` crate.
  2. **API Token Lookup:** `sito-api::auth::manager::validate_token` compares the Blake3 hash of the provided bearer token against stored token hashes using `subtle::ConstantTimeEq` across all registered entries, eliminating hash-comparison timing leaks.
  3. **TOTP Backup Codes:** One-time recovery codes are verified using `subtle::ConstantTimeEq` against stored Blake3 hashes before removal.

### 2.4 Denial of Service (DoS) & Resource Exhaustion Controls
* **Threat:** Flooding DNS listeners or Web API with high-frequency queries or opening thousands of idle TCP connections to exhaust system memory and file descriptors.
* **Mitigations Implemented:**
  1. **DNS Rate Limiter:** Per-IP token bucket limiter (`dns.rate_limit_per_ip`, default 20 QPS with burst allowance) implemented with high-speed lockless atomics in `sito-transport::limiter`.
  2. **TCP Connection Limits:** `dns.max_tcp_connections` (default 256) bounds concurrent TCP, DoT, and DoH connections using Tokio `Semaphore`. Exceeding connections are dropped or refused immediately.
  3. **Connection Timeouts:** Strict 10-second idle connection timeouts on TCP and DoT sockets prevent slowloris connection starvation.
  4. **Login Brute-Force Lockout:** IP-based and user-based lockout in `sito-api::auth::lockout`: 5 consecutive failed login attempts trigger an immediate 15-minute lockout.

### 2.5 Zero Secret Leakage Invariant
* **Threat:** Accidental exposure of API tokens, session cookies, database credentials, or HA TLS private keys in query logs, error bodies, or replication snapshots.
* **Mitigations Implemented:**
  1. **Sanitized Query Logs:** SQLite `query_log` schema stores only DNS wire parameters (`qname`, `qtype`, `client_ip`, `verdict`, `rule`, `elapsed_us`). HTTP request headers, Authorization headers, and session cookies are never logged.
  2. **RFC 7807 Error Responses:** REST API errors return sanitized `application/problem+json` envelopes. Internal stack traces, raw SQL queries, and local absolute filesystem paths are stripped from HTTP response bodies.
  3. **High-Availability Secret Redaction:** In `sito-ha`, master-to-slave config replication bundles strip sensitive sections (`web.key`, `integrations.mikrotik.token_env`, `auth` user password hashes) and replace them with `${SECRET:*}` placeholders.

### 2.6 TLS Hardening & Modern Protocol Enforcement
* **Threat:** Man-in-the-middle downgrade attacks against encrypted transports using legacy SSLv3, TLS 1.0, or TLS 1.1 protocols with insecure ciphers (RC4, 3DES, CBC mode).
* **Mitigations Implemented:**
  1. **Minimum TLS 1.2:** Transports configured through `rustls` strictly enforce TLS 1.2 and TLS 1.3. Protocols prior to TLS 1.2 are entirely disabled at the library level and cannot be negotiated by connecting clients.
  2. **AEAD Cipher Suites:** Only authenticated encryption with associated data (AEAD) ciphers (such as TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256) are supported.
