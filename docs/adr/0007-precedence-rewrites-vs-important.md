# ADR-0007: Rule Precedence Architecture (Local Rewrites vs $important Rules)

* **Status:** Accepted
* **Date:** 2026-09-04
* **Deciders:** sito core team
* **Consulted:** Rule engine and local network operations review
* **Informed:** All contributors

## Context

In an ad-blocking and filtering DNS server, conflicting verdicts can occur for a single requested domain:
- **Local DNS Rewrites:** Explicit operator-defined mappings (e.g., in `/etc/hosts` or the web UI) directing domains to local IP addresses (e.g. `printer.lan`, `nas.home.arpa`, or development domain intercepts).
- **Standard Filter Rules:** Subscription-based blocking rules (`||tracker.example^`) and exception rules (`@@||tracker.example^`).
- **`$important` Modifier Rules:** In AdGuard syntax, the `$important` modifier elevates a rule above normal priority, specifically intended to prevent subscription rules from being superseded by standard exceptions.

Conflict scenarios arise:
- If an upstream subscription contains a block rule with `$important` for a domain that the local network administrator has explicitly rewritten to an internal server IP.
- If a user whitelists a service, but an upstream list marks an ad sub-resource as `$important`.

Prematurely freezing the exact edge-case precedence before the filtering engine (M2) and client/rewrite engines (M4) are built risks incompatible behavior with AdGuard Home expectations or breaking local homelab network operations.

## Decision

We formally **ratify and finalize the pipeline precedence architecture** for Phase M4 (Clients and Rewrites):

### Final Pipeline Precedence Order:
1. **Client Exemptions:** Client-level bypass policies (e.g. `exception_clients` bypassing local rewrites, unmanaged devices).
2. **Important Rules:**
   - **Important Exceptions:** Filter exception rules with `$important` (`@@||domain^$important`) grant immediate allowlist clearance.
   - **Important Block Rules:** Filter blocking rules with `$important` (`||domain^$important`) take precedence over local rewrites.
     *Security Invariant:* An administrator's explicit `$important` block cannot be subverted or circumvented by a local DNS rewrite or standard exception.
3. **Local DNS Rewrites & Auto-PTR (`sito-rewrites`):**
   - Exact and wildcard local mappings (`printer.lan`, `*.home.arpa`, auto-generated PTR records) take precedence over standard public filter subscriptions and cache, ensuring local LAN reachability is never disrupted by external adblock lists.
4. **Standard Filter Rules, Safe Search, Parental & Services:**
   - Standard exception rules (`@@||domain^`).
   - Standard blocking rules (`||domain^`).
   - Safe search system rewrites (Google, Bing, YouTube, DuckDuckGo).
   - Parental control category blocks (adult, gambling).
   - Service blocks (TikTok, Steam, etc., with schedules).
5. **DNS Cache Lookup:** Returning cached non-expired responses.
6. **Upstream Forwarding & DNSSEC Validation:** Resolving external queries via configured upstream providers.

This order is verified in conformance integration tests (`tests/precedence.rs` and `crates/sito-test/src/lib.rs`).

## Consequences

### Positive
- Strict security guarantees: malicious or rogue local records cannot bypass critical administrator security blocks marked with `$important`.
- Homelab reliability: local network hostnames and RFC1918 auto-PTR records reliably resolve even if public third-party filter subscriptions contain false-positive standard blocking rules.
- 100% adherence to AdGuard Home rule evaluation and ABP ecosystem expectations.

### Negative
- Administrators must be aware that adding an `$important` blocking rule will intercept queries even if a local rewrite exists for that domain.

### Neutral / Operational
- Conformance test table in `docs/policy-matrix.md` and integration test matrix document and verify all edge cases.

## Alternatives Considered

### Alternative 1: Local Rewrites Overriding Everything (Including `$important`)
- **Pros:** Homelab rewrites are always unconditionally respected.
- **Cons:** Violates the fundamental security invariant where an operator attempts to block a dangerous domain network-wide using an explicit `$important` custom rule, only to have it bypassed by a local or imported rewrite entry.
- **Why not chosen:** Security invariant requires `$important` blocks to have absolute veto power.

### Alternative 2: Disallow the `$important` Modifier Completely
- **Pros:** Simplifies the filtering engine and precedence resolution.
- **Cons:** Breaks compatibility with major filter lists (e.g., AdGuard Base, OISD, Hagezi lists) that rely on `$important` to resolve complex anti-adblock unblocking rules.
- **Why not chosen:** High compatibility with established AdGuard/ABP filter lists is a core design goal.

## Amendment: Phase 2 global/group overlay (WP-2.4)

* **Date:** 2026-11-19
* **Status:** Accepted (amends, does not replace, the decision above)
* **Resolves:** audit finding P2-25 (precedence ambiguity between global and
  group rules)

The Phase 2 implementation makes the per-tier combination explicit. Global and
per-group rule sets are evaluated independently, then combined with this rank:

| Rank (within one tier) | Verdict |
|---|---|
| 3 | `Allow` (`@@...`) |
| 2 | `Rewrite` (`$dnsrewrite`) |
| 1 | `Block` (`||...^`) |
| 0 | no match (`Allow(None)`) |

1. Within a tier the order is `Allow > Rewrite > Block`.
2. The per-group overlay wins ties against the global set. A group no-match
   (`Allow(None)`) is ignored and never erases a global verdict.
3. `$important` rules form a tier evaluated before local rewrites and standard
   rules, so an important verdict always outranks a standard verdict regardless
   of source (global or group).

Consequently, on the direct-resolution path a group standard `$dnsrewrite`
intentionally overrides a global standard block (the rewrite is the higher rank
within that tier), while a global or group `$important` block still outranks it.
This is the intended P2-25 resolution, not an accident of ordering. The CNAME
target path is unchanged: a `$dnsrewrite` cannot be applied there and is
dropped, so it cannot hide a block.

The decision is pinned by parsed-rule end-to-end tests in
`crates/sito/src/pipeline/tests.rs` and documented in
[`docs/policy-matrix.md`](../policy-matrix.md#global-and-group-rule-overlay-wp-24).

