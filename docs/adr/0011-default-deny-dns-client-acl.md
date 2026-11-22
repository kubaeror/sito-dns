# ADR-0011: Default-Deny DNS Client ACL for New Installs

* **Status:** Accepted (design; implemented by D7b)
* **Date:** 2026-11-22
* **Deciders:** sito core team
* **Consulted:** Security review, HA/operations review, 2.0 release planning
* **Informed:** All contributors

## Context

Every DNS listener currently admits any source that can reach it. The address
family, listener protocol, connection caps and per-prefix rate limit are
handled by the transport admission controller
(`crates/sito-transport/src/admission.rs`), but there is no authorization
decision: once a datagram or stream is read, the query enters the pipeline.

The pipeline resolves the client after admission
(`crates/sito/src/pipeline/handle.rs`): `ClientRegistry::resolve` maps the source
IP and any configured identity to an `EffectivePolicy`, and cache, rewrites,
filtering, DNSSEC and upstream resolution follow. Unidentified clients are
served with the `default` group; they are only recorded for administrative
discovery. `dns.bind` defaults to `["0.0.0.0", "::"]`, so a fresh 2.0 install
is an open resolver until the operator adds a host firewall or narrows the
bind. `docs/installation.md` documents the firewall as the current mitigation,
and the 2.0 migration guide explicitly calls a default-deny DNS client ACL
deferred work.

The 2.0 decision is to add that ACL, but **not** to cut off existing
deployments. An upgrade must preserve the current allow-everything behavior:
1.9 and pre-ACL 2.0 configs have no ACL, and their clients may use addresses
and topologies the migration cannot infer. Only a fresh install completed
through the first-boot wizard should start denied, with an allow rule the
operator explicitly selected from the wizard's detected networks.

Client identity has several provenances
(`sito_core::client::IdentitySource`):

- trusted: exact IP, configured CIDR, configured MAC, configured shared secret,
  and a verified RouterOS lease;
- untrusted/display-only: raw DoH path segment and raw TLS SNI label.

The D10 trust table already forbids raw DoH path/SNI from matching policy.
This ADR goes further: **the ACL never admits on DoH path or SNI at all**, even
when a shared secret authenticates the label, because the transport value is
attacker-chosen and the same entry can normally also be reached by spoofing or
guessing a URL. Admission is based on the observed peer address.

HA makes this a distributed-systems decision as well as a filtering decision.
The master pushes a sanitized shared configuration to slaves; each node serves
DNS independently from its last applied bundle. An ACL that consulted
node-local, transient state (ARP, RouterOS leases, interface names, a local
allow file) would produce different answers on master and slave for the same
query and would make a failover change client access. The ACL must therefore be
a pure function of the shared configuration and the observed source address.

## Threat model and scope

### Assets and adversaries

The asset is the resolver's work and its trust boundary: cache entries, filter
decisions, upstream capacity, DNSSEC validation work, query-log/stats storage,
and the operator's assumption that only managed clients use the service. A
denied client must not be able to consume any of those.

Adversaries in scope:

- an unmanaged host on a reachable network (guest VLAN, IoT VLAN, compromised
  laptop) sending queries directly to the resolver;
- an off-path or on-path host that can reach an exposed DNS listener and wants
  to use it as an open resolver, an amplifier, or a cache-poisoning oracle;
- a client that can choose its DoH path, HTTP `Host`, DoT/DoQ SNI and DHCP
  hostname, and therefore can present any display-only "identity" it likes;
- a client that rotates through its own address allocation to multiply its
  budget (bounded by the existing per-prefix rate limit, not by this ACL).

Out of scope: a host with root/operator access to the resolver, a compromised
upstream, spoofed source addresses that pass the network's ingress filtering,
and volumetric DDoS that saturates the link before the process sees it. The ACL
is an authorization control, not a DDoS mitigation.

### Scope: DNS listeners only

The ACL applies to DNS service traffic on every DNS listener: UDP/53, TCP/53,
DoT, DoH (HTTP/1.1, HTTP/2 and HTTP/3) and DoQ. All of them converge on
`sito_transport::QueryHandler`, so one pipeline-stage check covers them.

It does **not** apply to:

- the admin UI and `/api/v2` (including `/health`, `/metrics`, config writes,
  query-log views and HA status). Those have their own authentication, RBAC,
  rate limits and trusted-proxy handling. An ACL mistake must never lock an
  operator out of the admin surface;
- the HA replication listener (mTLS + signed bundles);
- the witness/lease listener;
- outbound traffic to upstream resolvers;
- filter-list/ACME/update HTTP clients.

A reverse proxy in front of the DoH listener is outside the per-client model:
the resolver sees the proxy's address, so the ACL admits or denies the proxy
as one client. DNS DoH code uses the TCP peer address and deliberately ignores
`X-Forwarded-For`; `web.trusted_proxies` is an admin-listener setting and is
never consulted for DNS. Deployments that need per-client DoH ACLs must expose
the DoH listener directly (or run one listener per client network), not behind
a shared TLS terminator.

### Topologies that collapse or bypass per-client admission

The ACL is a **per observed source address** control. It is not a per-device or
per-user identity control. The following topologies are explicitly documented
as limitations, not silently treated as enforcement:

- **NAT gateway / router doing DNS forwarding.** Every downstream client
  appears as the router's address. Admitting the router admits every client
  behind it; denying it denies all of them. The ACL cannot distinguish them.
- **Local forwarder on the resolver host** (dnsmasq, systemd-resolved,
  unbound, a container sidecar, Docker's embedded DNS). Every query appears
  from loopback or a bridge address. Admitting loopback or the bridge admits
  the forwarder and therefore its downstream clients. If the forwarder itself
  must be denied, the downstream clients cannot be selectively allowed by this
  ACL.
- **Reverse proxy in front of DoH/DoH3.** Every client appears as the proxy.
  The proxy's `X-Forwarded-For` is ignored by DNS transports on purpose; there
  is no trusted-proxy ACL mode for DNS.
- **Docker bridge / CNI / VPN / overlay interfaces.** These host-local
  interfaces can appear as attractive candidates during setup, but they
  represent the local container/overlay gateway, not the clients beyond it.
- **Multiple sites / subnets.** A shared allow list must contain every site's
  client networks. There is no per-node ACL override in HA. A list that only
  describes site A denies site B clients once the bundle is applied.

The wizard shows these interfaces and warns before selecting a
`bridge_or_tunnel` candidate. `docs/installation.md`, the HA runbook and the
configuration reference must repeat the warning. A deployment that needs
per-device admission must enforce it at the access layer (separate VLANs /
listener instances) or use a per-device identity control that is explicitly in
scope; this ACL does not provide one.

### Why DoH path and SNI are not admission credentials

The DoH path (`/dns-query/<label>`) and the first label of the DoT/DoQ SNI are
chosen by the client. They are not a cryptographic proof of network location:

- the path is visible in URLs, browser history, proxy logs and screenshots;
- the SNI is visible on the wire and in any TLS-terminating middlebox;
- a configured shared secret authenticates *possession of a string*, not
  membership of a network, and the same client can present it from any allowed
  or denied source;
- using a display label for admission would let an attacker who learns a label
  bypass a network boundary the operator believes is enforced.

The existing D10 rule (a raw path/SNI label never matches policy) is preserved.
A secret-authenticated client may still receive its configured group and
per-client upstreams **after** admission, but it cannot use the secret to pass
the ACL. If its source address is denied, the query is refused.

Similarly, MAC addresses do not participate in admission:

- ARP is node-local and transient, and differs between master and slave;
- ARP/MAC is only meaningful on the same L2 segment, so it cannot describe a
  routed client;
- a local attacker can poison ARP or present a spoofed MAC;
- `clients.trust_arp` and RouterOS lease names are explicitly opt-in identity
  hints, not network admission facts.

An explicit MAC in `clients.entries[].ids` remains a trusted *policy* identity
(per D10), but it does not create an allow rule. Only static IP and CIDR values
do.

## Decision

Add an IP-source ACL to the DNS query pipeline:

- `[clients] default_policy` selects what happens when no explicit rule
  matches.
- `[clients.acl] allow` lists operator-approved client networks.
- `[clients.acl] deny` lists explicit exclusions and always wins.
- `[clients.acl] deny_response` selects REFUSED (default) or silent drop.
- `[clients.acl] allow_entry_ids` (default `false`) opts in to treating static
  IP/CIDR values in `clients.entries[].ids` as implicit allow rules. They are
  identity, not admission, unless the operator explicitly enables this.
- The default is `default_policy = "allow"`, so an existing config, a migrated
  v1 config and a hand-written config behave exactly as before.
- The first-boot wizard is the only automatic path that writes
  `default_policy = "deny"`. It shows the detected interfaces and requires the
  operator to select which client networks are allowed; it never seeds every
  private/ULA prefix automatically.
- The decision is made once, before client identity resolution, and before any
  cache, rewrite, filter, DNSSEC, upstream or query-log work.

## Config shape

### Keys and defaults

The example below shows the **fresh-install/wizard shape** (deny). When the
keys are omitted entirely, the defaults are `default_policy = "allow"`,
`allow = []`, `deny = []`, `allow_entry_ids = false` and
`deny_response = "refused"`.

```toml
[clients]
# The wizard writes "deny" and the operator-selected allow list below; the
# typed default for an omitted key is "allow" (upgrade compatibility).
default_policy = "deny"

[clients.acl]
# Client networks that may use the DNS listeners. The wizard never fills this
# with every interface prefix; the operator selects or enters these.
allow = ["127.0.0.1/32", "::1/128", "192.168.1.0/24", "fd00:1::/64"]

# Explicit exclusions. A match here denies even when a broader allow or a
# client entry contains the address.
deny = ["192.168.1.128/25"]

# Whether static IP/CIDR values in clients.entries[].ids also admit the
# client. Default false: an entry identifies a client for policy, but does not
# by itself punch through a deny default.
allow_entry_ids = false

# What a denied client receives: "refused" (default) or "drop".
deny_response = "refused"
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `clients.default_policy` | string enum | `"allow"` | Action when no `deny` rule, no `allow` rule and (only when enabled) no static client-entry IP/CIDR matches. Accepted values are exactly `"allow"` and `"deny"` (lowercase). Any other value is a configuration error naming the key. |
| `clients.acl.allow` | array of strings | `[]` | IPv4/IPv6 addresses or CIDR blocks whose source addresses may use the DNS listeners. Bare addresses are treated as `/32` (IPv4) or `/128` (IPv6). |
| `clients.acl.deny` | array of strings | `[]` | IPv4/IPv6 addresses or CIDR blocks that are always denied. Deny is authoritative regardless of the prefix length of an allow rule. |
| `clients.acl.allow_entry_ids` | boolean | `false` | When `true`, static IP/CIDR values in `clients.entries[].ids` are also allow rules. Off by default so a stale or broad entry cannot silently weaken a deny default. MAC/hostname/secret/SNI ids never admit. |
| `clients.acl.deny_response` | string enum | `"refused"` | `"refused"` sends DNS RCODE 5; `"drop"` sends no DNS response. Any other value is a configuration error naming the key. |

`[clients.acl]` is a normal sub-table of `[clients]`; it is not a new top-level
section and it is not node-local. `clients.client_id_secrets` remains
node-local and is still stripped from HA bundles.

The default values are chosen for compatibility, not for a fresh security
posture:

- `default_policy = "allow"` means a 1.9 config, a migrated v1 config, and a
  config that simply omits `[clients]` are unchanged.
- `allow = []` and `deny = []` are inert while the default is allow.
- `allow_entry_ids = false` means a client entry never changes admission by
  itself. An operator converting an existing install to deny must decide
  whether to list networks in `allow` or opt in to entry-derived admission.
- `deny_response = "refused"` is the default even for allow configs, but it is
  only observable once a deny rule exists or the default becomes deny.

### Effective admission rules

For each query, before client identity resolution and before the pipeline
stages, the resolver computes the following with the source address `ip` (the
observed TCP peer or UDP source, never a header or path value):

1. **Canonicalize the family.** An IPv4-mapped IPv6 source
   (`::ffff:a.b.c.d`) is treated as IPv4, matching the rate-limiter key. IPv4
   and IPv6 rules are otherwise independent: `::/0` does not cover IPv4 and
   `0.0.0.0/0` does not cover IPv6.
2. **Deny first.** If any `clients.acl.deny` prefix contains `ip`, the result
   is **deny**. Deny wins even when a longer, more specific allow or a client
   entry would otherwise match. This lets an operator exclude one guest host
   from a broad LAN allow without editing the LAN prefix.
3. **Explicit allow.** If any `clients.acl.allow` prefix contains `ip`, the
   result is **allow**.
4. **Entry allow (opt-in).** If `clients.acl.allow_entry_ids = true` and any
   IP/CIDR value in any `clients.entries[].ids` contains `ip`, the result is
   **allow**. With the default `false`, entries never admit; they remain
   identity/policy only.
5. **Default policy.** Otherwise the result is `default_policy`: `"allow"`
   admits, `"deny"` refuses.

Longest-prefix match is used for rule selection and reporting, not for
overriding deny. When several prefixes of the same action match, the most
specific prefix is the one recorded in the metric label and the rate-limited
log line; the action is identical. Ties are impossible within one list after
duplicate rejection, and an exact allow/deny conflict is rejected at load time
(below), so the result is deterministic.

This is deliberately **not** a combined longest-prefix table where a `/32`
allow can punch through a `/8` deny. A deny rule is an explicit security
exclusion; letting a more specific allow silently win would make a "deny the
guest VLAN" rule fragile.

### Interaction with existing `clients.entries` and `clients.groups`

`clients.default_policy` is an admission setting only. It is not
`clients.groups.default`, does not replace the `default` policy group, and does
not change filtering/safe-search/parental behavior for an admitted client.
Likewise it is independent of `filtering.fail_closed`, which controls a
different failure (no filter snapshot) after admission.

- Entries never grant admission by default. Only when
  `clients.acl.allow_entry_ids = true` do `entries[].ids` values that parse as
  an IP address or CIDR become allow rules. Bare IPs are host prefixes. This
  opt-in keeps a deny default closed even when an old or overly broad entry
  remains in the file.
- Hostname ids, MAC ids (`aa:bb:...` or `mac:...`), DoH path/SNI labels and
  names never create an allow rule, even with `allow_entry_ids = true`. A
  query from an address that matches no IP/CIDR and no explicit allow is
  subject to `default_policy` even if its MAC is in an entry, its RouterOS
  lease matches, its secret matches, or its DoH path matches.
- `groups` never affect admission. Group membership cannot add or remove an
  allow; `filtering = false`, `trusted = true`, schedules and blocked services
  are policy after admission, not network authorization.
- `clients.trust_arp`, `clients.trust_routeros_lease_names`, RouterOS lease
  tables and `client_id_secrets` never affect admission.
- An explicit `deny` beats an entry CIDR. Adding an entry for a host inside a
  denied range does not re-admit it; remove the deny or narrow it.
- `clients.entries[].upstreams` / `use_global_upstreams` still apply only after
  admission.

`allow_entry_ids = true` is a deliberate compatibility convenience for
operators who already maintain a complete static entry list. It is not the
default because entries are policy objects, not firewall rules: a stale entry,
a broad `/16` used for one device, or a template copied from another site would
silently widen admission. When enabled, config validation emits a prominent
warning if any entry id is `0.0.0.0/0` or `::/0`, and the startup summary names
the opt-in. An operator converting an existing install to deny should prefer
explicit `[clients.acl] allow` networks and turn this on only if the entry
list is the intended admission source.

### IPv4/IPv6, duplicates and conflicts

- CIDR parsing uses `sito_core::net::IpNetwork`. The prefix is validated against
  the address family; `192.0.2.0/33` and `2001:db8::/129` are errors.
- Host bits are canonicalized on load: `192.168.1.7/24` is stored and reported
  as `192.168.1.0/24`. Membership always masks, so this does not change
  meaning; it makes duplicate detection stable.
- Exact duplicates after canonicalization within `allow` (or within `deny`)
  are configuration errors naming the field and the duplicate value. Silently
  accepting them would make the "which rule matched" report ambiguous.
- The same canonical prefix in both `allow` and `deny` is a configuration
  error: the operator must choose one action. Overlapping *different* prefixes
  are allowed; deny wins for addresses in the overlap, and the most specific
  deny prefix is reported.
- With `allow_entry_ids = true`, an entry-derived allow may duplicate or
  overlap an `allow` prefix; that is harmless (same action) and is not an
  error. An entry-derived allow that overlaps a `deny` is allowed but the deny
  wins, so the entry has no effect for those addresses. With the default
  `false`, entry ids are not part of the admission index at all.
- `allow` and `deny` are each capped at 1024 prefixes. Exceeding the cap is a
  configuration error naming the key. The compiled index is built once per
  registry/runtime snapshot, not per query; 1024 is far above realistic LAN
  policy and bounds both match cost and metric cardinality.
- `0.0.0.0/0` and `::/0` are legal but must be written explicitly. They are
  never synthesized except by the wizard's separately confirmed "allow all"
  path. With `allow_entry_ids = true`, an entry id that parses to
  `0.0.0.0/0` or `::/0` is an implicit allow-all and must produce a prominent
  validation/startup warning naming the entry; it is not an error because a
  catch-all policy entry is a legitimate (if broad) configuration.
- Under `default_policy = "deny"` with an empty or loopback-only allow list,
  local queries from `127.0.0.1`/`::1` are also denied unless listed. The ACL
  has no implicit loopback exception; the wizard always offers loopback as a
  selected network, and administrators who hand-write a deny policy must add
  it themselves. Loopback-only is a valid, explicitly confirmable wizard
  outcome. This is documented in the configuration reference in D7b.

### Example: existing install upgraded (behavior preserved)

```toml
[clients]
default_policy = "allow"

[clients.acl]
allow = []
deny = []
allow_entry_ids = false

[[clients.entries]]
name = "kids-tablet"
ids = ["192.168.1.55"]
group = "kids"
```

Every client behaves as in 1.9. The entry identifies `kids-tablet` for policy;
with `allow_entry_ids = false` it grants no admission, which is irrelevant
while the default is allow.

### Example: new install from the wizard

```toml
[clients]
default_policy = "deny"

[clients.acl]
allow = ["127.0.0.1/32", "::1/128", "192.168.1.0/24"]
deny = []
allow_entry_ids = false
deny_response = "refused"
```

The selected LAN may resolve; loopback may resolve; any other source gets
REFUSED and never reaches cache, filtering or upstream.

## Enforcement point

The check is a new pipeline stage in
`crates/sito/src/pipeline/handle.rs`, in `DnsPipeline::handle`:

1. `in_flight` accounting and the existing QR=1 drop happen first (a response
   is never a query; dropping it is not an authorization decision).
2. The runtime snapshot is taken once.
3. **ACL stage.** The stage reads only `client.ip` and the shared ACL index
   from that snapshot and returns `Allow` or `Deny`. It does not call
   `ClientRegistry::resolve`, so it touches no ARP table, RouterOS lease table,
   schedule, MAC resolver or `unidentified_clients` store.
4. On deny, the handler synthesizes the configured response, records ACL
   metrics and returns. It does **not** resolve identity, build
   `PipelineContext`, call `execute`, increment `clients_identified`, touch the
   filter, look up the cache, resolve rewrites, perform DNSSEC work, contact
   upstream, or write the detailed query log.
5. On allow, execution continues unchanged: `clients.resolve`, multi-question
   FORMERR, BADVERS, NOTIMP, filter/rewrite/cache/upstream/DNSSEC, and the
   normal `finish` path.

Running the ACL before `resolve` has two deliberate consequences:

- a denied client cannot cause ARP/RouterOS lookups, cannot enter the
  `unidentified_clients` discovery map, and cannot create identity side
  effects while being refused;
- malformed and multi-question queries from denied sources are refused instead
  of exercising wire-level error paths. The existing FORMERR/BADVERS helpers
  stay after the ACL stage.

The ACL index is therefore independent of identity resolution: it is built
from `clients.default_policy`, `[clients.acl]`, and (only when
`allow_entry_ids = true`) the static IP/CIDR ids of entries. This is the same
shared data on every HA node and does not depend on what the registry later
resolves.

The transport admission controller still runs before the pipeline (global and
per-source connection caps, per-prefix rate limit). That controller protects
the process from resource exhaustion, including from denied clients; it is not
the authorization decision. No listener may bypass the pipeline: every
listener already goes through `QueryHandler::handle`, and D7b must add a test
that denies one query on each protocol to prove it.

The ACL index is built once from the typed `ClientsConfig` and carried in the
same runtime snapshot as the client registry. A reload that changes the ACL
takes effect atomically with the rest of the config; there is no per-query lock
and no window where one query sees the new ACL and the next sees the old one
within the same snapshot. Queries already past the stage finish under their
captured snapshot.

### Why not at the listener / socket layer

A listener-level check would need its own copy of the shared ACL and would
duplicate the decision on UDP, TCP, DoT, DoH, DoH3 and DoQ. It would also
receive protocol-specific context (`Host`, path, SNI, proxy headers) that the
ACL must not consult, inviting an accidental trust decision in one transport
but not another. The pipeline is the single choke point, reads only `client.ip`
plus the shared snapshot, and automatically covers a future transport.
Socket-level firewall rules remain a valid *additional* defense; they are not
this ACL.

## Response behavior

### REFUSED (default)

`deny_response = "refused"` returns a normal DNS response with:

- `QR = 1`, same ID and opcode as the query;
- `RCODE = 5` (REFUSED);
- `RD` copied from the query, `RA = 1`, `TC = 0`;
- the question section echoed;
- EDNS(0) version 0 with the server's configured UDP payload when the query
  had EDNS, no upstream-only options, no answer/authority/additional records;
- no DNSSEC records regardless of the DO bit (there is no signed answer).

REFUSED is chosen over NXDOMAIN and zero-IP because it is an explicit policy
answer, not a claim about whether a name exists, and it does not create a
synthetic cacheable answer. It is chosen over silence as the default because
an operator can diagnose a misconfigured allow list immediately, and clients
distinguish "policy refusal" from "server down".

The response is shaped by the same `ResponseShaper` as every other response,
so the UDP payload size is the configured `dns.edns_udp_size` clamped to the
client's advertised size. The response reveals only that the source is not
authorized; it never includes the matched prefix, the config path, the DoH
path/SNI, or a reason string.

### Drop

`deny_response = "drop"` makes `QueryHandler::handle` return `None`:

- UDP: no datagram is sent;
- TCP/DoT/DoQ: no DNS frame is sent; the connection remains subject to its
  idle/connection limits until the client or the limits close it;
- DoH/DoH3: the HTTP layer returns `204 No Content` (existing behavior for
  `None`), not a `403` and not a DNS body.

Drop is for operators who do not want to confirm the resolver's existence to
unmanaged networks. It costs a socket read and is still bounded by the
transport admission controller. It is not the default because silent failure
is operationally expensive and because clients may interpret it as a network
outage and retry elsewhere.

### Rate limiting and logging

- Denied clients are subject to the existing `dns.rate_limit_per_ip`
  (IPv4 `/24`, IPv6 `/64` buckets) and the per-source connection cap. No new
  rate limit is introduced; a denial never creates a new token bucket.
- The first denial for a source IP is logged at `info` with the source IP, the
  protocol, the action, and the matched prefix (or `default`). Subsequent
  denials from that source are logged at `debug` for the next 60 seconds.
  A global token bucket caps `info` ACL lines at 10 per second so a flood of
  unique/spoofed sources cannot turn logging into the bottleneck; excess
  lines fall to `debug`. The sampling map is bounded (1024 sources) and pruned
  after 5 minutes of inactivity. Logging is best effort and must not block the
  query path.
- The detailed query log does **not** receive denied queries. This avoids
  storing unmanaged clients' names, addresses and domains, prevents a denied
  client from flooding the SQLite writer, and keeps the query log a record of
  served policy. ACL counters and the sampled system log are the audit trail.
- ACL logs contain only network metadata: source IP, protocol, action and the
  configured matched prefix. They contain no query name, DoH path, SNI, HTTP
  header, client entry/group name or credential. The source IP is the minimum
  operational identifier needed to find the offending host; it is subject to
  the same log retention as existing transport logs and is never copied into a
  metric label.

### Metrics

New counters in `sito-stats`:

```text
sito_dns_acl_decisions_total{action="allow"|"deny",reason="explicit_allow"|"explicit_deny"|"client_entry"|"default_policy",family="ipv4"|"ipv6"}
sito_dns_acl_matched_prefix_total{action="allow"|"deny",prefix="192.168.1.0/24",family="ipv4"}
sito_dns_acl_dropped_total{family="ipv4"|"ipv6"}
```

- `sito_dns_acl_decisions_total` answers "how much traffic is denied and why"
  without per-client cardinality. `family` separates IPv4 and IPv6 so an
  operator can see a missing IPv6 or IPv4 allow rule.
- `sito_dns_acl_matched_prefix_total` reports the most specific matching
  configured prefix. Its label value is always the canonical network address
  with host bits masked (for example `192.168.1.0/24`, never
  `192.168.1.77/24`). Values come only from operator configuration (allow,
  deny and, when opted in, entry IP/CIDR ids), never from a client-supplied
  value. At most 1024 prefixes per list exist by validation; the exporter
  additionally collapses labels beyond 256 distinct series into
  `prefix="__other__"` to bound scrape size.
- `sito_dns_acl_dropped_total` increments only for `deny_response = "drop"`, so
  a silent policy still has a counter.
- Denied queries with a synthesized response also increment
  `sito_queries_total{proto=...,qtype=...,verdict="refused"}`, so existing
  query-rate dashboards remain correct. With `drop`, that query counter is not
  emitted and `sito_dns_acl_dropped_total` is authoritative.
- ACL counters are security telemetry and always increment. Because the ACL
  runs before identity resolution, `ignore_stats` is not known at the decision
  point and therefore does not suppress `sito_queries_total{verdict="refused"}`
  for denied traffic either. Once a query is allowed, the normal resolved
  policy applies to all per-client/cache/filter metrics and `ignore_stats`
  behaves exactly as today. This is documented so a denied client cannot
  silence its own denial telemetry.

## Wizard seed

The first-boot wizard is the only place a new install is switched to deny,
because it is the only place where the server knows the operator is present and
can show the detected networks. The wizard gains a "Client access control" step
after the DNS-listener step. **It never auto-selects a non-loopback client
network.**

### Form fields (UI names, not config keys)

- `client_acl_default_deny` — checkbox. Checked by default on **every**
  bootstrapping run, even when the base template explicitly says
  `default_policy = "allow"`. In that case the step shows a prominent warning
  ("this template currently admits every client") and the operator must
  actively uncheck deny to keep the template's allow policy. A template
  cannot make a fresh wizard install silently skip default deny.
- `client_acl_selected` — one checkbox or token per interface candidate. Only
  loopback is selected by default. Every non-loopback candidate starts
  unchecked, regardless of family or RFC 1918/ULA status.
- `client_acl_manual` — textarea for additional IPv4/IPv6 addresses or CIDRs,
  one per line. Empty by default. This is the only way to add a network that
  interface enumeration did not expose.
- `client_acl_loopback_only_ack` — checkbox. Required when deny is selected and
  no non-loopback allow network was selected or entered. It explicitly
  confirms "only this host may resolve".
- `client_acl_public_ack` — checkbox. Required when any selected or manually
  entered allow network is public (not RFC 1918/ULA/loopback). It confirms the
  operator intends to expose a resolver on a public address.
- `client_acl_allow_entry_ids` — checkbox, unchecked by default (even when the
  base config had `allow_entry_ids = true`; that case shows a warning). It lets
  the operator opt in to entry-derived admission for this install.
- `client_acl_allow_all` + `client_acl_allow_all_confirm` — a checkbox and a
  text field that must both be supplied. The text field must equal
  `ALLOW ALL` exactly. This writes `0.0.0.0/0` and `::/0` and is shown with a
  persistent warning in the wizard and post-setup summary.

On success the wizard writes the keys from the config-shape section through
the existing `WizardCompleteForm::build_config` → `Config::validate` →
atomic persist path. It does not append raw TOML and does not add a second
writer. `allow_entry_ids` is written explicitly and is `false` unless the
operator checks `client_acl_allow_entry_ids`; a base template value of `true`
does not carry through silently. The server re-runs `getifaddrs(3)` on POST and
accepts only candidate ids it is currently offering (plus the manual
textarea); a submitted interface/prefix string is never written without
re-validation against the live interface list.

### Interface discovery

The wizard enumerates candidates with `getifaddrs(3)` (`libc`, already a
`sito-api` dependency) on Unix:

- skip interfaces that are down or have no address;
- skip link-local addresses (`169.254.0.0/16`, `fe80::/10`);
- always add `127.0.0.1/32` and `::1/128` as the fixed loopback candidate;
- for every remaining IPv4/IPv6 address, show the interface name, address,
  netmask-derived prefix, family and a classification: `private_v4`
  (RFC 1918), `ula_v6` (`fc00::/7`), `public`, or `bridge_or_tunnel` (name
  heuristics such as `docker*`, `br-*`, `veth*`, `virbr*`, `cni*`,
  `flannel*`, `podman*`, `tun*`, `tap*`, `wg*`, `tailscale*`, `zt*`). The
  classification is a warning label, not a trust decision.

No candidate is preselected except loopback. On a multi-homed host the operator
sees the WAN, VPN, Docker bridge and management interfaces and must choose the
LAN(s) that actually contain DNS clients. Selecting a `public` or
`bridge_or_tunnel` candidate requires an additional inline confirmation and
shows the forwarder/NAT warning from the limitation section below. A Docker
bridge is usually the wrong choice: admitting it admits the host-side
forwarder, not the containers' downstream clients.

If the platform exposes no netmask, the prefix is shown as a `/24` (IPv4) or
`/64` (IPv6) **suggestion** with its source labelled; the operator must still
select it. On a non-Unix build (no `getifaddrs`), the candidate list is
loopback plus the raw-peer suggestion only; manual entry remains available.

### The wizard's own peer is not a seed

The wizard does not automatically add the HTTP client's network. It may show
one candidate derived from the **raw TCP peer address** of the admin request
(`ConnectInfo`), with the same prefix convention. It never uses
`X-Forwarded-For` or `web.trusted_proxies` for this candidate. If the raw peer
is public, the candidate is labelled `public` and is not selected. If the admin
is behind a reverse proxy, SSH tunnel or NAT, the raw peer is the proxy or
loopback; the operator must enter the real LAN manually. Header-injected values
therefore cannot seed an allow network.

### Validation and fail-closed behavior

- Deny selected, at least one non-loopback candidate or manual CIDR selected:
  write `default_policy = "deny"` and the selected allow list. Any public
  network requires `client_acl_public_ack`; otherwise the form returns `400`.
- Deny selected, no non-loopback allow: this is a valid **loopback-only**
  install, but only when `client_acl_loopback_only_ack` is checked. The wizard
  writes deny plus `127.0.0.1/32` and `::1/128` and shows a post-setup warning
  that only the local host can resolve. Without the acknowledgement, the form
  returns `400` naming the confirmation.
- Deny unchecked: write `default_policy = "allow"`; selected networks are not
  needed. If the template explicitly specified allow, the step still appears
  and states that every client is admitted.
- Allow-all: both `client_acl_allow_all` and the exact `ALLOW ALL` text are
  required. A checked box alone or any other text returns `400`. The resulting
  config is explicitly warned as an open resolver and is never produced by
  default.

The previous draft rejected loopback-only. That was wrong: it removed the
safest option and pushed operators toward allow-all. Loopback-only is now an
explicit, supported choice. Detection failure simply leaves the candidate list
with only loopback; it does not fall back to allow and does not force
allow-all.

### When the wizard must/must not touch the ACL

- `bootstrapping == true` (first-admin setup, including a fresh template): the
  ACL step is **always rendered and applied**, even when the template already
  contains `clients.default_policy` or `[clients.acl]`. Existing allow lists
  are shown, deny is checked by default, and the operator must confirm or
  change the choice. This closes the bypass where a fresh template with an
  explicit `default_policy = "allow"` skipped the step.
- `bootstrapping == false` (post-setup admin recovery via setup token or
  re-auth): the ACL section is not applied; an existing ACL is untouched.
- A template that pre-creates an admin account is a provisioned install, not a
  wizard-completed install. It must set its intended ACL explicitly; the
  installation guide will say so and the startup warning will report an
  effective allow policy on a wildcard bind.

### After setup

There is no separate ACL editor in D7b. The operator edits
`[clients] default_policy`, `[clients.acl]` and their entries through the
configuration file or the normal config API; changes are validated and applied
as shared configuration. The configuration reference will show the exact keys
and the lockout warning. A dedicated visual ACL builder is future work, not
part of this decision.

## Migration

### v1 → v2 and pre-ACL v2 configs

- `sito config migrate --from v1 --to v2` materializes
  `clients.default_policy = "allow"` when the key is absent and reports it in
  `defaults_materialized`. This makes the preserved behavior explicit in the
  migrated document.
- Migration never writes a deny policy, never writes `allow_entry_ids = true`
  and never invents allow rules. An omitted `allow_entry_ids` uses the typed
  default `false`.
- The materialization happens exactly once, in the migration command. Config
  load, startup, `check-config`, restore and HA apply do not rewrite a file to
  add the key; a document without the key simply uses the typed default
  `"allow"`.
- An ordinary API config save does not materialize `default_policy` merely
  because the default is allow. It persists what the serialized config
  contains; only a write that explicitly builds the clients table (the wizard)
  adds the key. This is distinct from the one-shot migration materialization.
- Re-running migration on the same v1 input is deterministic. An already-v2
  document is rejected by the documented v1→v2 command (only that path is
  supported), so there is no second materialization path.
- `--adopt-safe-defaults` **does not** change `default_policy`. The ACL is not
  added to the safe-default table because v1 has no ACL information from which
  reachable clients could be inferred; flipping the policy would cut off
  clients and violate the behavior-preserving contract. The migration report
  includes a warning telling the operator to use the wizard or set
  `default_policy = "deny"` plus explicit allow rules deliberately.
  `--adopt-safe-defaults` therefore stays behavior-preserving for admission;
  the ACL is intentionally not part of that table, and the migration guide
  will say so.
- `--backup` still writes `config.toml.v1.bak` before replacement. The backup
  has no ACL key and restores cleanly to a pre-ACL binary (which rejects
  unknown keys, so a downgrade must remove the new keys first; see below).

### New installs

A fresh provider/VM install that completes the wizard writes
`default_policy = "deny"` and the operator-selected allow networks (or an
explicit loopback-only acknowledgement). A headless install started with
`--no-setup`, a hand-written minimal config, or `Config::default()` still gets
`default_policy = "allow"`: the typed default is compatibility-first. This is
deliberate; "new install" in this ADR means "completed the first-boot wizard",
as required by the release decision. The installation guide will tell headless
operators to add the ACL explicitly.

A fresh template with an explicit `default_policy = "allow"` is not treated as
ACL-configured merely because the key exists. If it still has first-run admin
state, the bootstrap wizard always shows the ACL step, preselects deny and
warns that the template currently admits every client; the operator must
actively uncheck deny to keep the template's policy. If the template
pre-creates an admin, it is a provisioned install and must set the intended ACL
itself; the startup exposure warning will say that DNS is open.

### Downgrade and rollback

- The keys are additive v2 fields; there is no `config_version` bump.
- An older 2.0 RC binary rejects unknown keys by design. Before downgrading to
  a binary without ACL support, remove `clients.default_policy`,
  `[clients.acl]` and re-run `check-config`. The migration guide will state
  this in the downgrade section.
- A config rollback that restores an allow file restores allow behavior. A HA
  version rollback cannot replay a bundle below the slave watermark (existing
  rule), so ACL rollback follows the normal HA version rules, not a separate
  path.

### HA push and rollback

- `[clients] default_policy`, `[clients.acl] allow`, `[clients.acl] deny`,
  `[clients.acl] allow_entry_ids` and `[clients.acl] deny_response` are shared
  configuration and are included in the sanitized bundle and in the
  shared-projection digest. The sanitizer continues to remove
  `clients.client_id_secrets` only; it must not remove the ACL.
- A push that changes the ACL is applied atomically with the rest of the
  bundle. If the bundle is invalid (for example a duplicate prefix or an
  unknown value), the slave rejects the whole bundle and keeps its last known
  good runtime generation; it never applies a partial ACL.
- A master rollback that publishes an older valid bundle is subject to the
  existing monotonic version/term rules. The ACL is not exempt: an old bundle
  cannot lower the slave's watermark.
- A newly promoted slave already has the last applied shared ACL. Promotion
  does not re-evaluate or reset it.

## HA

- The ACL is shared configuration only. There are no `[ha]` ACL keys, no
  per-node ACL file, no interface-name-dependent rule and no node-local
  override.
- The decision depends only on the shared `[clients]` configuration and the
  **observed peer address on that node**. It does not depend on ARP, RouterOS
  leases, DNS answers, wall-clock time, random state or the node's role.
- The guarantee is precise: **for the same observed source address and the
  same applied bundle, every ACL-aware node makes the same decision.** It is
  not a per-device guarantee. If a client reaches master through a different
  NAT, proxy or reverse path than the slave, the two nodes observe different
  addresses and can legitimately decide differently. See the
  topology-limitation section.
- A slave that is disconnected from the master keeps serving DNS with the last
  applied configuration, including its ACL. There is no fallback to allow on
  disconnect and no fallback to deny beyond what the last bundle says. A
  client's access therefore changes only when a newer valid bundle is applied.
- **Fresh slave startup.** A slave with no applied bundle and no watermark
  must not start DNS with an implicit allow policy while a master may be
  denying. D7b must fail closed: the slave starts its admin/HA client, reports
  `acl_unprovisioned`, and does **not** bind DNS listeners until it has
  applied the first valid bundle. A restart with a watermark starts normally
  from the persisted applied config. This rule also covers a rebuilt/replaced
  slave. The HA runbook must document that a first-boot slave cannot serve DNS
  while the master is unavailable; recover or promote instead.
- **Mixed versions.** A pre-ACL binary has no ACL and serves allow even when
  the master is denying. Enabling `default_policy = "deny"` is supported only
  after every DNS-serving node runs an ACL-aware build. D7b must advertise
  `client_acl` in the existing `Hello.capabilities` field and make master
  readiness report `acl_capability_missing` while a connected slave lacks it;
  the master logs a prominent warning and the docs require upgrading all nodes
  before enabling deny. A mixed-version cluster must stay on allow.
- **Multiple sites.** The ACL is one shared policy with no per-node override.
  If site B clients are not in `[clients.acl] allow` (or covered by an opted-in
  entry id), they are denied after the bundle applies even though the master
  runs at site A. Operators must agree on an all-site address plan and include
  every site's client CIDRs before enabling deny. A single-site list is a
  deliberate denial of the other sites, not a local default.
- A read-only slave rejects local config API writes (existing behavior). If an
  operator edits a shared ACL field directly in the slave's `config.toml`, the
  shared-projection digest diverges, the node is marked `Degraded`, and a full
  apply from the master is required before it reports `Synced` again. This is
  the existing divergence rule, not a new ACL-specific mechanism.
- Edit-time read-only enforcement for shared configuration remains deferred;
  this ADR does not add it.
- Node-local listener identity still differs: a master may bind
  `["0.0.0.0", "::"]` and a slave `["0.0.0.0"]`. The ACL is evaluated against
  the peer address observed by each node, which is the correct per-node
  network fact. The *policy* is shared; the *observed addresses* are not.
- ACL metrics are per node and are not merged into the master's Prometheus
  registry, matching the existing HA stats model. Scrape each node separately.
- A slave that is behind may briefly serve the previous ACL. This is the same
  bounded staleness as every other shared setting and is visible as
  `Synced`/`Degraded` in HA status. A slave that has never applied a bundle is
  covered by the fresh-slave rule above, not by a temporary allow.

## Consequences

### Positive

- A fresh install is not an open resolver after the wizard, without requiring
  the operator to write firewall rules first.
- Upgrades do not cut off a single existing client: the default remains allow
  until an operator opts in.
- For the same observed source address and applied bundle, admission is
  deterministic across HA nodes and survives failover.
- Untrusted DoH path/SNI and node-local MAC/ARP data cannot be used to bypass a
  network boundary.
- The decision is one pipeline stage before identity resolution and all
  expensive work, so denied clients consume no ARP/RouterOS, cache, filter,
  DNSSEC or upstream capacity and are not recorded as discovered clients.
- REFUSED plus a dropped-query counter makes misconfiguration diagnosable
  without exposing policy details to the client.
- ACL configuration is ordinary shared config: hot reload, validation,
  migration reporting and HA push all reuse existing mechanisms.

### Negative

- A fresh-install operator who does not notice the new wizard step can lock out
  clients; showing interfaces instead of auto-seeding, the explicit
  loopback-only acknowledgement, the two-step allow-all confirmation and the
  post-setup warning mitigate but do not eliminate this.
- The wizard's interface discovery is heuristic. Routed clients on a different
  subnet, NAT, a Docker/VM bridge, a local forwarder or a public resolver
  address require manual entry or a topology change.
- Per-device admission is impossible behind NAT, a reverse proxy or a local
  forwarder; those deployments need network segmentation or a different
  identity control.
- A first-boot HA slave without an applied bundle does not serve DNS; this is
  safe but reduces availability during a master outage.
- A mixed-version cluster cannot enable deny safely until every node is
  ACL-aware.
- REFUSED tells an unmanaged client that a resolver exists; `drop` is available
  but hides failures from the operator as well.
- Denied clients are still subject to transport admission work (a socket read
  and rate-limit check) before the ACL stage. This is deliberate: moving the
  check into each transport would duplicate it six ways.
- ACLs are per observed source IP; clients behind one NAT share an admission
  decision. Per-device admission requires the operator to split the network.
- 1024 prefixes per list is a hard cap. Very large enterprise policies must be
  aggregated.

### Neutral / operational

- `docs/configuration-reference.md` §9 and §13, `docs/installation.md`,
  `docs/runbook-ha.md`, `docs/2.0-migration.md`,
  `docs/2.0-claim-matrix.md`, `docs/policy-matrix.md` and the wizard text must
  be updated by D7b; this ADR does not change them.
  `docs/first-time-setup.md` is a historical implementation plan with a
  historical banner; D7b should point it at the current wizard/ACL docs rather
  than present its old field list as current.
- `dns.bind` remains `["0.0.0.0", "::"]`. The ACL is not a substitute for a
  host firewall, and the installation guide keeps recommending both.
- Query-log retention, PII hashing and stats are untouched. Denied queries are
  intentionally absent from the query log; ACL counters are aggregate only.
- The admin UI/API is never ACL-filtered, so an ACL mistake cannot lock out
  the operator's management path.

## Test plan (D7b)

All behavioral tests must use the real loader and the real pipeline/transport
paths, not only struct parsing. Use the deterministic clock/ports and
`crates/sito-test-support` fixtures where they exist. Suggested test names are
shown in parentheses.

### A. Config, schema and docs

| Intent | Expected |
|---|---|
| Full v2 fixture with `default_policy`, `allow`, `deny`, `allow_entry_ids`, `deny_response` through `Config::from_toml_str`, `Config::load` and `sito check-config` | Parses; every value and default is retained; no warning (`test_acl_config_real_loader_and_check_config`) |
| Minimal `[clients]` without ACL keys | `default_policy` is `"allow"`, `allow`/`deny` are empty, `allow_entry_ids` is `false`, `deny_response` is `"refused"` (`test_acl_defaults_are_compatibility_first`) |
| Invalid `default_policy`, `deny_response`, `allow_entry_ids` type, CIDR, family/prefix overflow, duplicate canonical prefix, allow+deny exact conflict, >1024 list entries | Validation errors name the exact key and value; `check-config` exits non-zero (`test_acl_config_rejections`) |
| `allow_entry_ids = true` with a `0.0.0.0/0`/`::/0` entry id | Loads but emits a prominent validation/startup warning naming the entry (`test_acl_entry_allow_all_warns`) |
| `[clients]` ACL keys in a HA-sanitized document | All five proposed keys survive; only `client_id_secrets` is removed (`test_ha_sanitizer_preserves_acl`) |
| `docs/configuration-reference.md` §9/§13, `docs/config-v2.md`, `docs/2.0-migration.md`, `docs/runbook-ha.md`, `docs/installation.md` | Document every key, the allow-entry opt-in, topology limitations and downgrade; `check_config_reference.py` and Markdown link checks pass (`test_acl_config_docs_keys`) |

### B. Matching semantics

| Intent | Expected |
|---|---|
| Allow IPv4 `/24`, query from inside and outside | Inside admitted (`reason=explicit_allow`), outside denied under deny default (`test_acl_allow_deny_ipv4`) |
| Allow IPv6 `/64` plus `::1/128`, query from both and from another prefix | IPv6 family counters and outcomes correct; no cross-family match (`test_acl_allow_deny_ipv6`) |
| Nested allow prefixes `/16` and `/24` | Query in `/24` is allowed; metric reports `/24` (longest prefix) (`test_acl_longest_prefix_reported`) |
| Broad `deny` plus more specific `allow` and an exact entry id inside the deny | All addresses in deny are denied; specific allow does not override; entry does not re-admit (`test_acl_deny_is_authoritative`) |
| Two overlapping deny prefixes | Most specific reported; action deny (`test_acl_longest_deny_reported`) |
| IPv4-mapped IPv6 source `::ffff:192.0.2.10` with an IPv4 `/24` allow | Matches the IPv4 rule and increments the IPv4 family label (`test_acl_mapped_ipv6_uses_ipv4_rules`) |
| `0.0.0.0/0` without `::/0` | IPv4 admitted, IPv6 falls to default deny; counters show the asymmetry (`test_acl_zero_prefix_is_family_scoped`) |
| Duplicate/conflicting rules in a fixture | Load rejected before startup/listener bind (`test_acl_duplicate_and_conflict_rejected`) |

### C. Admission and identity (the core security claim)

| Intent | Expected |
|---|---|
| Static IP/CIDR entry under default deny, `allow_entry_ids = false` (default), no `acl.allow` | Query denied; an entry does not admit by default (`test_acl_entry_ids_do_not_admit_by_default`) |
| Same entry with `allow_entry_ids = true` | Query admitted as `reason=client_entry` (`test_acl_entry_ids_opt_in_admits`) |
| Entry with only a MAC id, or only a hostname/name id, under default deny, even with `allow_entry_ids = true` | Query denied; MAC/name does not admit (`test_acl_non_ip_entry_ids_do_not_admit`) |
| `trust_arp = true`, ARP snapshot contains the source MAC and an entry lists it | Query still denied; trust_arp does not participate (`test_acl_trust_arp_never_admits`) |
| Verified RouterOS lease matches by IP/MAC/hostname | Query denied; lease identity does not admit (`test_acl_routeros_identity_never_admits`) |
| `client_id_secrets` configured; correct DoH path and DoT SNI presented from a denied IP | Query denied; secret auth does not bypass ACL (`test_acl_doh_path_and_sni_are_not_credentials`) |
| Wrong/unknown DoH path from an allowed IP | Admitted; unknown path does not deny and does not grant group policy (`test_acl_unknown_path_from_allowed_ip_is_admitted`) |
| `trusted = true` or `filtering = false` group from a denied IP | Still denied; policy flags do not bypass ACL (`test_acl_policy_flags_do_not_admit`) |
| Default allow, no rules | All existing client-identification tests behave unchanged (`test_acl_default_allow_preserves_existing_behavior`) |

### D. Response and protocol behavior

| Intent | Expected |
|---|---|
| Denied UDP query, `deny_response = "refused"` | One response, RCODE 5, same ID/opcode, question echoed, no answer, EDNS payload respected, no upstream call (`test_acl_refused_udp`) |
| Denied TCP, DoT, DoQ query | RCODE 5 framed on the existing connection; no upstream (`test_acl_refused_stream_transports`) |
| Denied DoH GET/POST | HTTP 200 `application/dns-message` with DNS RCODE 5; no `403`, no policy detail (`test_acl_refused_doh`) |
| Denied DoH3 | Same DNS-level result over HTTP/3 (`test_acl_refused_doh3`) |
| Denied DoH peer sends `X-Forwarded-For: <allowed address>` | Still denied; DNS DoH never consults the header (`test_acl_doh_ignores_x_forwarded_for`) |
| Denied DoH3 peer sends `X-Forwarded-For: <allowed address>` | Still denied; DoH3 never consults the header (`test_acl_doh3_ignores_x_forwarded_for`) |
| Allowed DoH peer sends `X-Forwarded-For: <denied address>` | Still admitted; header cannot revoke either (`test_acl_doh_ignores_xff_for_allow`) |
| `deny_response = "drop"` on UDP/TCP/DoT/DoQ | No DNS response; connection/rate limits still apply (`test_acl_drop_suppresses_response`) |
| `deny_response = "drop"` on DoH and DoH3 | HTTP 204, not 403 (`test_acl_drop_doh_is_204`) |
| Denied multi-question / BADVERS-shaped query | REFUSED from ACL, not FORMERR/BADVERS (`test_acl_precedes_wire_error_paths`) |
| Denied query with `qname` | Identity resolution, ARP/RouterOS, cache/filter/upstream mocks observe zero calls; `unidentified_clients` stays empty; query log sender observes zero entries (`test_acl_denied_query_does_no_pipeline_work`) |
| Local forwarder on loopback with a denied downstream client | The forwarder's source is admitted/denied as one client; downstream identity is not visible and the docs state the limitation (`test_acl_forwarder_collapses_to_one_source`) |

### E. Upgrade, new install and wizard

| Intent | Expected |
|---|---|
| v1 config without `[clients]` migrated | `clients.default_policy = "allow"` is materialized and reported in `defaults_materialized`; no deny (`test_migration_materializes_default_allow`) |
| v1 config with clients/entries migrated | Entries preserved; default allow; no ACL invented (`test_migration_preserves_clients_and_allows`) |
| `--adopt-safe-defaults` on a v1 config with clients | `default_policy` stays `"allow"`; warning present; report shows the field was not changed (`test_migration_adopt_safe_defaults_does_not_enable_acl_deny`) |
| Repeated migration/idempotency check | Existing `"deny"` or `"allow"` is never overwritten; materialization happens once (`test_migration_acl_is_not_rewritten`) |
| Fresh wizard, operator selects the private LAN candidate | Writes `default_policy = "deny"`, loopback + selected CIDR, `deny_response = "refused"`; DNS starts and the LAN resolves (`test_wizard_selected_lan_default_deny`) |
| Fresh wizard on a multi-homed host (LAN + WAN + VPN + Docker bridge) | All candidates are shown; only loopback is preselected; no WAN/private/bridge prefix is written unless selected (`test_wizard_does_not_seed_all_interfaces`) |
| Fresh wizard reached from a public client address | The public peer is shown but not selected; no public prefix appears in `allow` unless explicitly selected or entered (`test_wizard_public_peer_is_not_seeded`) |
| Fresh wizard, manual public CIDR without `client_acl_public_ack` | Returns 400; public exposure requires explicit confirmation (`test_wizard_public_manual_requires_ack`) |
| Fresh wizard, no non-loopback network selected, loopback-only acknowledged | Writes deny + loopback only; no 400; post-setup warning says only the local host can resolve (`test_wizard_loopback_only_is_allowed_with_ack`) |
| Fresh wizard, no non-loopback network selected, acknowledgement missing | Returns 400 naming the loopback-only confirmation; setup stays pending, no config/DNS start (`test_wizard_loopback_only_requires_ack`) |
| Fresh wizard, allow-all checkbox only | Returns 400; no open resolver written (`test_wizard_allow_all_requires_exact_text`) |
| Fresh wizard, allow-all checkbox + exact `ALLOW ALL` text | Writes `0.0.0.0/0` and `::/0` plus a visible warning (`test_wizard_allow_all_is_explicit`) |
| Wizard POST selects a candidate id not offered by the current interface list | Returns 400 and writes nothing; submitted prefixes are re-validated (`test_wizard_rejects_forged_interface_candidate`) |
| Fresh template with `allow_entry_ids = true` | Wizard writes `false` unless `client_acl_allow_entry_ids` is checked; warning shown (`test_wizard_entry_ids_opt_in_is_explicit`) |
| Fresh template with explicit `default_policy = "allow"` and first-run admin state | ACL step is still rendered, deny is preselected, the template's allow is noted with a warning, and the operator must actively keep allow (`test_wizard_fresh_template_explicit_allow_still_shows_acl`) |
| Fresh template that pre-creates an admin | Wizard not applicable; startup warning reports effective allow on wildcard bind (`test_fresh_provisioned_template_warns_open_resolver`) |
| Wizard recovery on an existing install | Existing ACL and default policy untouched (`test_wizard_recovery_does_not_change_acl`) |
| Wizard unchecked deny | Writes/keeps `default_policy = "allow"` and does not create a locking ACL (`test_wizard_can_keep_default_allow`) |
| Wizard raw peer behind an untrusted `X-Forwarded-For` | Header cannot add a candidate; only the raw peer can be suggested, and it is not selected (`test_wizard_acl_peer_ignores_xff`) |
| `--no-setup`/minimal fresh config | Default allow, no ACL keys required; startup warning remains (`test_headless_fresh_install_stays_allow`) |

### F. HA

| Intent | Expected |
|---|---|
| Master publishes ACL allow/deny change | Slave applies it atomically; for the **same observed source IP and bundle**, both nodes allow/deny identically (`test_ha_acl_same_observed_source_is_deterministic`) |
| Master and slave observe different NAT/proxy addresses | Outcomes may differ; the test asserts the documented per-observed-source rule, not a per-device guarantee (`test_ha_acl_different_observed_sources_can_differ`) |
| Fresh slave with no watermark/applied bundle | Admin/HA starts, DNS listeners do not; status is `acl_unprovisioned`; first bundle enables DNS with the shared ACL (`test_ha_fresh_slave_fails_closed_until_first_bundle`) |
| Restarted slave with a watermark | Starts from persisted applied ACL without waiting for a new push (`test_ha_restarted_slave_uses_persisted_acl`) |
| Mixed-version slave without ACL capability | Master readiness reports `acl_capability_missing`; deny is not advertised as fully enforced; log warning (`test_ha_mixed_version_acl_capability`) |
| Multi-site allow list that omits site B | Site B clients are denied on both nodes after the bundle; test documents the shared-policy behavior (`test_ha_multi_site_omission_denies_site_b`) |
| Invalid ACL bundle | Slave rejects the whole bundle, keeps previous ACL, reports Degraded; no partial apply (`test_ha_invalid_acl_rejects_bundle`) |
| Master disconnect | Slave keeps the last applied ACL; no allow fallback (`test_ha_acl_survives_disconnect`) |
| Local edit of a shared ACL field on a slave | Shared digest diverges; node Degraded until full apply (`test_ha_acl_local_edit_latches_divergence`) |
| Promotion of a slave | ACL from the last applied bundle remains; no reset (`test_ha_promotion_preserves_acl`) |
| Sanitizer/round-trip | All ACL keys in sanitized bundle and shared projection; secrets still stripped (`test_ha_acl_round_trip`) |

### G. Metrics, logging, privacy and reload

| Intent | Expected |
|---|---|
| Allow/deny through IPv4 and IPv6 | `sito_dns_acl_decisions_total` has bounded `action`/`reason`/`family` series; no client IP or qname labels (`test_acl_metrics_are_bounded_and_private`) |
| Nested prefixes, including `192.168.1.77/24` written as host bits | `sito_dns_acl_matched_prefix_total` uses canonical `192.168.1.0/24` and collapses overflow to `__other__` (`test_acl_prefix_metric_is_canonical_and_bounded`) |
| `drop` mode | `sito_dns_acl_dropped_total` increments; no query-log entry and no `sito_queries_total` refused series (`test_acl_drop_metric_and_no_querylog`) |
| Denied burst from one source and a unique-source flood | One `info` line per sampling window, remaining at `debug`; global 10/s cap holds; bounded map (`test_acl_denied_logs_are_sampled`) |
| Denied query with a name/DoH path/SNI | Captured logs contain only IP/proto/action/prefix: no qname, path, SNI, header, entry/group name or credential (`test_acl_logs_contain_only_network_metadata`) |
| Hot reload changes allow to deny | New snapshot denies immediately; in-flight query finishes under old snapshot; no torn decision (`test_acl_hot_reload_is_atomic`) |
| `ignore_stats = true` on a denied client | ACL counters and `sito_queries_total{verdict="refused"}` increment; no query-log row; allowed traffic still honors `ignore_stats` (`test_acl_denied_traffic_ignores_ignore_stats`) |

### H. Regression

| Intent | Expected |
|---|---|
| Full `cargo test --workspace --all-features` | No existing client/policy/HA/cache/filter test changes outcome |
| Existing config corpus and `SCHEMA_FIXTURE` | No map drift; all existing configs load |
| Markdown/config-reference checks | `check_markdown_links.py`, `check_config_reference.py`, `check_migration_guide.py` pass |
| Docs mention forwarder/NAT/reverse-proxy/multi-site limitations | `docs/installation.md`, `docs/runbook-ha.md` and configuration reference §9/§13 contain the warnings (`test_acl_docs_cover_forwarder_and_ha_limits`) |

## Implementation checklist for D7b

Every proposed config key must be registered in the machine-checked schema map
and exercised by the fixture through the **real loader**. A direct
`ClientsConfig`/serde struct test is not sufficient: those tests do not catch a
missing map entry, an unknown-key rejection, or a `check-config` regression.

1. **Typed config** — `crates/sito-clients/src/config.rs`
   - add `default_policy` (enum or validated string with `"allow"` default) and
     `acl` (`ClientAclConfig { allow, deny, allow_entry_ids, deny_response }`)
     to `ClientsConfig`;
   - implement parsing/validation: enum values, CIDR family/prefix, host-bit
     canonicalization, duplicate rejection, allow/deny exact-conflict
     rejection, 1024-entry caps, and the entry-id allow-all warning when
     `allow_entry_ids = true`;
   - ensure hot reload rebuilds the index and does not require a restart.
2. **Schema map** — `crates/sito-core/config-v1-to-v2-map.toml`
   - add `[[field]]` entries for `clients.default_policy`,
     `clients.acl.allow`, `clients.acl.deny`, `clients.acl.allow_entry_ids`,
     `clients.acl.deny_response`, all `status = "kept"`.
3. **Schema fixture** — `crates/sito-core/src/config/tests.rs`
   - add a `[clients] default_policy = "deny"` and a `[clients.acl]` table with
     every key to `SCHEMA_FIXTURE`;
   - run `cargo test -p sito-core config_schema` and
     `cargo test -p sito-core test_config_map_covers_every_serde_field`.
4. **Real loader / `check-config` tests**
   - positive fixture through `Config::from_toml_str`, `Config::load` and the
     `sito check-config` CLI path;
   - negative fixtures for the validation rules above;
   - assert `defaults_materialized` / migration reporting from the real
     migration command.
5. **Runtime index** — build the ACL decision index once per runtime snapshot:
   - explicit allow, explicit deny, and entry-derived IP/CIDR allow only when
     `allow_entry_ids = true`;
   - canonicalized prefixes, most-specific match lookup, deny short-circuit;
   - no per-query allocation in the common path;
   - the index must be usable without calling `clients.resolve`.
6. **Pipeline** — `crates/sito/src/pipeline/handle.rs` plus a small
   `acl.rs`/helper:
   - run the ACL stage **before** `clients.resolve` and before the
     multi-question FORMERR check; keep the QR=1 drop first;
   - `QueryOutcome`-style REFUSED builder and `None` for drop;
   - metrics and sampled logging; no query-log entry; no ARP/RouterOS/
     `unidentified_clients` side effect and no `clients_identified` increment
     on deny.
   - adjust the startup network-exposure warnings
     (`exposure_warnings_for_phase(config, ExposurePhase::DnsListeners)`) so a
     wildcard `dns.bind` under an effective deny policy is not reported as an
     unqualified open resolver; it must name the ACL as the active control and
     still warn about the admin UI separately;
   - emit a warning (not an error) when deny is effective and no allow rule
     outside loopback exists, so an accidental total lockout is visible in the
     log even when it was hand-written rather than produced by the wizard;
   - emit a warning when an ACL-aware master has a connected slave without the
     ACL capability (see HA below).
7. **Metrics** — `crates/sito-stats/src/metrics.rs`
   - add the three counters with Help/Type lines, canonical prefix labels,
     bounded labels and the overflow prefix; update exposition tests and the
     metrics documentation.
8. **Wizard** — `crates/sito-api/src/ui/handlers/wizard.rs` and template:
   - `getifaddrs(3)` candidate enumeration with interface name/prefix/
     classification and no non-loopback preselection;
   - fields `client_acl_default_deny`, `client_acl_selected`,
     `client_acl_manual`, `client_acl_loopback_only_ack`,
     `client_acl_public_ack`, `client_acl_allow_entry_ids`,
     `client_acl_allow_all` + exact `client_acl_allow_all_confirm`;
   - apply the ACL step whenever `bootstrapping == true`, even when the base
     template has explicit ACL keys; skip it only for recovery
     (`bootstrapping == false`);
   - raw-peer suggestion only; do not use `X-Forwarded-For`/
     `web.trusted_proxies` for the ACL candidate;
   - no raw TOML append; use `build_config` and the existing persist path.
9. **Migration** — `crates/sito-core/src/config_migrate.rs`:
   - materialize `clients.default_policy = "allow"` exactly once and report it;
   - leave it unchanged under `--adopt-safe-defaults` and add the warning;
   - do not materialize `allow_entry_ids` (default false) and do not rewrite
     the file on ordinary API saves;
   - update both migration report shapes (extend `defaults_materialized` or use
     the existing warnings list; do not silently drop the signal).
10. **HA** — `crates/sito-ha/src/bundle.rs`, `crates/sito-ha/src/slave/`,
    `crates/sito-ha-types/`:
    - verify all ACL keys survive sanitization and are part of the shared
      projection;
    - implement the fresh-slave `acl_unprovisioned` gate and persisted-config
      restart path;
    - advertise `client_acl` in the existing `Hello.capabilities`, expose
      `acl_capability_missing` in readiness, and test mixed-version behavior;
    - add round-trip, push, invalid-bundle, disconnect, divergence, same- and
      different-observed-source, multi-site and promotion tests;
    - do not add ACL keys to the node-local lists and do not add a per-node
      ACL override.
11. **Docs** — update `docs/configuration-reference.md` §9 and §13 (key table,
    lockout/downgrade, topology and HA limitations), `docs/config-v2.md`
    (fixture/safe-defaults), `docs/2.0-migration.md` (behavior-preserving ACL
    and downgrade), `docs/installation.md`, `docs/runbook-ha.md` (fresh slave,
    mixed versions, multi-site) and `README.md` (wizard behavior), and
    `docs/2.0-claim-matrix.md` (deferred → delivered/release-gated). Add the
    keys to `docs/policy-matrix.md` so admission is documented before policy.
    Keep the historical banner in `docs/first-time-setup.md` and point it at
    the current wizard/ACL sections instead of rewriting it as current.
12. **Verification** — `git diff --check`,
    `python3 scripts/check_markdown_links.py`,
    `python3 scripts/check_config_reference.py`,
    `cargo test -p sito-core config_schema`,
    `cargo test -p sito-core test_config_map_covers_every_serde_field`, then the
    ACL test suites and `cargo test --workspace --all-features --locked`.

## Rejected scope

- **Full resource-model redesign.** No new "resource" object, no ACL attached
  to groups/upstreams/rewrites, no schema beyond the five keys. Groups remain
  policy, entries remain identity, ACL remains source admission.
- **Per-query UI prompt.** The resolver never asks an operator to approve an
  individual query. A DNS query path has no human in the loop, and a prompt
  would be a DoS vector and an HA divergence source.
- **External policy engine.** No OPA/Rego, no external PDP, no network call in
  the query path. The ACL must work offline, during master disconnect, and
  inside a single process with no new failure mode.
- **Automatic default deny on upgrade.** Rejected: it cannot infer reachable
  clients and would silently break installations.
- **Admission by DoH path/SNI or shared secret.** Rejected as spoofable and
  because it authenticates a string, not a network location.
- **Admission by MAC, ARP or RouterOS lease.** Rejected as node-local,
  transient, L2-scoped and spoofable, and therefore non-deterministic across
  HA nodes.
- **ACL on the admin API/UI.** Rejected: management access is protected by
  authentication/RBAC, and an ACL mistake must not lock out recovery.
- **GeoIP/ASN/hostname-based rules.** Deferred; no external data dependency in
  the admission path.
- **Automatic firewall management.** Out of scope; the ACL is in-process.
- **A separate ACL service/daemon.** Out of scope; it would duplicate the
  runtime snapshot and add a failure domain.
- **Per-node ACL overrides.** Rejected; HA determinism requires one shared
  policy.

## Alternatives Considered

### Alternative 1: Default deny for every install, including upgrades

- **Pros:** The strongest posture immediately; no compatibility branch.
- **Cons:** Existing clients can be cut off with no warning; the migration
  cannot infer LAN/routed/NAT topology; violates the release decision that
  upgrades preserve behavior.
- **Why not chosen:** A resolver that stops answering after an upgrade is a
  worse outcome than a documented opt-in, and operators already have the
  firewall mitigation until they choose the ACL.

### Alternative 2: Host-firewall-only guidance

- **Pros:** No code, no new failure mode, works for any protocol.
- **Cons:** Not portable across systemd/Docker/container deployments; a
  container port publish can bypass the host rule; DoH behind a reverse proxy
  hides the source; no per-client visibility in the resolver; an operator can
  forget it.
- **Why not chosen:** The code already has a single pipeline choke point and a
  wizard; in-process enforcement is testable and works with the existing
  config/HA model. Firewall guidance remains as defense in depth.

### Alternative 3: Combined longest-prefix allow/deny table (deny only on tie)

- **Pros:** Familiar router ACL semantics; a specific allow can punch through a
  broad deny.
- **Cons:** Makes "deny the guest VLAN" fragile; an accidental or overly broad
  entry CIDR can silently re-admit a host inside a denied range; harder to
  explain to operators.
- **Why not chosen:** Deny is an explicit security exclusion and must be
  authoritative. Longest-prefix is retained for reporting and for selecting
  among same-action rules.

### Alternative 4: Drop by default

- **Pros:** Does not confirm the resolver to unmanaged networks; no response
  amplification.
- **Cons:** Misconfiguration looks like an outage; clients retry and fail over
  to other resolvers; operators lose the immediate diagnostic signal; some
  clients interpret silence as a network error.
- **Why not chosen:** REFUSED is more debuggable and still cheap. `drop` is
  available explicitly.

### Alternative 5: Admit DoH/DoT clients by path/SNI/secret

- **Pros:** Works through NAT and for roaming clients without IP planning; no
  network discovery in the wizard.
- **Cons:** The value is client-chosen and often guessable; it leaks through
  URLs/logs/SNI; possession of a string is not network membership; an attacker
  who learns the label bypasses the boundary.
- **Why not chosen:** Violates the explicit constraint. Secrets remain useful
  for policy identity after source admission, not for admission itself.

### Alternative 6: Admit by MAC/ARP/RouterOS identity

- **Pros:** Stable across DHCP address changes on one L2 segment; already part
  of the D10 trust table for policy.
- **Cons:** ARP is node-local/transient; master and slave can disagree; routed
  clients have no ARP entry; local spoofing is easy; RouterOS may be offline.
- **Why not chosen:** Breaks HA determinism and does not describe routed
  clients. MAC remains a policy identity only.

### Alternative 7: External policy engine (OPA/Rego or a sidecar PDP)

- **Pros:** Expressive policy, central management, reusable across services.
- **Cons:** New failure domain and dependency in the query path; offline/HA
  behavior, latency, auth and cache invalidation all become problems; overkill
  for five keys.
- **Why not chosen:** Out of scope and contrary to the single-process,
  offline-capable resolver model.

## References

- [Configuration reference §9 `[clients]`](../configuration-reference.md#9-clients--client-identification--policies)
- [Configuration reference §13 `[ha]`](../configuration-reference.md#13-ha--high-availability-masterslave-replication)
- [Config v2 and migration](0004-configuration-single-toml.md)
- [HA master/slave push](0002-ha-master-slave-push.md)
- [HA automatic promotion](0010-ha-automatic-promotion.md)
- [Policy resolution matrix](../policy-matrix.md)
- [2.0 migration guide §4.4](../2.0-migration.md#44-safe-defaults-vs-behavior-preserving-upgrade)
- [Installation and network exposure](../installation.md)
- `crates/sito-clients/src/config.rs`, `crates/sito-clients/src/registry.rs`
- `crates/sito/src/pipeline/handle.rs`
- `crates/sito-transport/src/admission.rs`
- `crates/sito-core/config-v1-to-v2-map.toml`,
  `crates/sito-core/src/config/tests.rs` (`SCHEMA_FIXTURE`)
