# Installation and Deployment Guide

This guide covers deploying **sito** on Linux hosts using the automated one-line installer, manual systemd service configuration, Docker, or Docker Compose.

> **Development status:** the `main` line is the **2.0.0 final tree** (code
> frozen at `39ba6da`; the workspace version remains `2.0.0-rc.2` until the
> release-manager version bump). The published stable release remains **1.9.5**,
> and the pinned examples below intentionally target it. The `v2.0.0` tag and
> publication (H10) are pending; prerelease/2.0 builds are not stable artifacts.
> Deferred scope is listed in the [2.0 claim matrix](2.0-claim-matrix.md).

## Platform Support

**Linux is the supported production and test platform** (kernel 5.4+ strongly
recommended; CI and release artifacts target `linux/amd64`, `linux/arm64` and
`linux/arm/v7`). **macOS is supported for development builds only**: the
`sito-transport::pktinfo` and wizard `getifaddrs` paths are compile-gated for
Unix, but they are not CI-covered. **Windows is not supported**; the UDP
listener and packet-info modules emit a compile error on non-Unix targets.
The shipped command-line, daemon and container guidance in this guide is
Linux-only.

---

## Network Exposure and Firewall

**Read this before the host is reachable from an untrusted network.** These are
LAN defaults, not internet-safe defaults. The stable 1.9.5 line and the 2.0
line differ in the admin default:

* **1.9.5 (stable):** `web.bind` defaults to `0.0.0.0`, the admin UI is served
  over plain HTTP, and port `8080` accepts setup and login requests from every
  reachable source. There is no TLS in the admin listener itself.
* **2.0.0 (final tree):** `web.bind` defaults to `127.0.0.1` (the
  config v2 safe default). Existing v1 configurations migrated without
  `--adopt-safe-defaults` keep their old bind, including `0.0.0.0`.
* **Both lines:** `dns.bind` defaults to `["0.0.0.0", "::"]`. 2.0 adds the
  ADR-0011 source-address ACL, but its typed default is `default_policy =
  "allow"` so upgrades are unchanged. Only a fresh install completed through the
  first-boot wizard starts with default deny. `dns.rate_limit_per_ip` limits
  request rate; it is **not** an access control. Keep the DNS ports behind the
  firewall examples below as defense in depth, and configure `[clients.acl]`
  deliberately (see the [configuration reference](configuration-reference.md#clientsacl--dns-client-admission)).

Sito logs a startup warning for each exposed listener. Reach the panel through
an SSH tunnel or a TLS reverse proxy. The firewall examples below allow SSH
before enabling the default-deny policy and **do not open 8080**, so the direct
`http://<server-ip>:8080` URL stops working after `ufw enable`; use the tunnel
or add the temporary LAN-scoped rule shown under "Safe admin access".

### Recommended LAN-only firewall

Replace `192.168.0.0/24` with your LAN subnet. The examples intentionally do
**not** open the admin port:

```bash
# UFW: allow SSH first so a remote session survives enabling the firewall
sudo ufw allow OpenSSH
sudo ufw default deny incoming
sudo ufw allow from 192.168.0.0/24 to any port 53 proto udp comment 'sito DNS (UDP, LAN)'
sudo ufw allow from 192.168.0.0/24 to any port 53 proto tcp comment 'sito DNS (TCP, LAN)'
sudo ufw enable

# firewalld (equivalent)
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.0.0/24" port port="53" protocol="udp" accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.0.0/24" port port="53" protocol="tcp" accept'
sudo firewall-cmd --reload
```

> [!CAUTION]
> On a remote host, enable the SSH rule **before** `ufw enable`. Enabling a
> default-deny policy without it drops the SSH session.

If you enable DoT/DoH/DoH3, restrict `853`/`443` to the clients that actually
need them instead of opening them to everyone.

### Safe admin access

Do not publish port `8080` to the internet. Use an SSH tunnel from your
workstation:

```bash
ssh -L 8080:127.0.0.1:8080 user@server
# then browse http://127.0.0.1:8080
```

If you need direct browser access from the LAN only during first-time setup,
add a temporary LAN-scoped rule and remove it when setup is complete:

```bash
sudo ufw allow from 192.168.0.0/24 to any port 8080 proto tcp
# after setup:
sudo ufw delete allow from 192.168.0.0/24 to any port 8080 proto tcp
```

For browser access without a tunnel, keep `web.bind = "127.0.0.1"` and put a
TLS reverse proxy on the same host in front of it (set `web.trusted_proxies`
and, for external URLs, `web.public_url = "https://..."`
or `web.tls_terminated_by_proxy = true`). For DNS clients outside the LAN,
restrict the DNS ports to those client addresses at the firewall.

Docker users: `-p 8080:8080` publishes the panel on every host interface.
Prefer `-p 127.0.0.1:8080:8080` plus an SSH tunnel or reverse proxy, and publish
DNS only to the interface your clients use. The shipped compose file binds the
admin UI to `127.0.0.1:8080` and keeps configuration in a named volume, so the
safe choice is the default; a bind-mounted `./config` needs an explicit chown.

> [!NOTE]
> The loopback admin default is already in the **2.0** config v2 schema. The
> first-boot wizard's **Client Access Control** step starts a fresh install in
> default deny with only loopback preselected; you choose the client networks.
> An upgrade preserves the existing allow behavior until you opt in. Headless
> installs (`--no-setup`, a hand-written minimal config, or `Config::default()`)
> still get the compatibility default `default_policy = "allow"` and must set
> `[clients.acl]` explicitly. The startup warning and this firewall guidance
> remain the mitigation until then. 1.9.5 keeps its historical `0.0.0.0` admin
> default so existing configurations continue to work. See the
> [2.0 migration guide](2.0-migration.md) before moving an existing install.

---

## 1. Quick Install (Automated Shell Script)

For systemd-based distributions (Debian/Ubuntu, Arch, RHEL/Fedora). Alpine
and other non-systemd systems are not covered by the automated installer
(it requires `useradd`/`groupadd` and systemd); install the release binary
manually and supervise it with your init system.

```bash
# Download and inspect the installer from the tag you intend to run.
curl -fsSL https://raw.githubusercontent.com/kubaeror/sito-dns/v1.9.5/contrib/install.sh -o sito-install.sh
sed -n '1,120p' sito-install.sh
sudo SITO_VERSION=1.9.5 bash sito-install.sh
```

The installer automatically:
1. Detects your CPU architecture (`x86_64`, `aarch64`, or `armv7`).
2. Fetches the selected release binary and verifies cosign release signatures
   (required by default) plus SHA256 checksums.
3. Creates the unprivileged system user `sito`.
4. Grants `CAP_NET_BIND_SERVICE` capability to bind ports 53 and 443 without root.
5. Deploys the hardened systemd unit, enables, and starts the service.
6. Runs post-install health verification (`systemctl is-active` and HTTP check).
7. Prompts you to complete setup via the web wizard. The **1.9.5** installer
   prints `http://<server-ip>:8080`; a **2.0 config-v2** install binds the admin
   UI to `127.0.0.1`, so use the SSH tunnel. The advice allows SSH first, does
   not open 8080, and points at the tunnel or a temporary LAN-scoped rule for
   first-time setup.

### 1.1 The 2.0 line

The one-line installer and published container tags above install the **stable
1.9.5** release. The 2.0.0 final line is built from source until the `v2.0.0`
release is published (the workspace currently reports `2.0.0-rc.2`):

```bash
cargo build --release --locked --features "embed-ui,ha,mimalloc"
sudo install -m 0755 target/release/sito /usr/local/bin/sito
```

Official release archives and the container image enable
`embed-ui,ha,mimalloc`. `ha` is opt-in for source builds; the command above
matches the official feature set. Drop `ha` only for a deliberate no-HA build:
it runs as a master, rejects `[ha]`/`server.role = "slave"`, answers
`/api/v2/ha/*` with `501 ha_not_supported`, and omits `sito ha gen-certs`.

2.0 uses config v2. A new install starts from the [safe defaults](2.0-migration.md#44-safe-defaults-vs-behavior-preserving-upgrade);
an existing 1.9.x config must be migrated before the 2.0 binary will start:

```bash
sudo systemctl stop sito
sudo sito config migrate --from v1 --to v2 --backup --config /etc/sito/config.toml
sudo systemctl start sito
```

Do not mix a 2.0 binary with an unmigrated v1 file, and do not point an old
1.9.5 binary at a migrated v2 file. The [2.0 migration guide](2.0-migration.md)
covers the report, unknown-key policy, restart-only matrix and rollback.

A `stats.db` written by 1.9.x is **schema version 1** until it is migrated;
2.0 supports **schema version 2**. A 2.0 server **fails closed by default** when
the database needs a migration: it does not serve DNS/API and does not write the
database. There are two supported ways to upgrade:

**Option A — explicit CLI migration (recommended).** Migrate while the service
is stopped. The command holds the service lease and a database migration lock,
refuses to run against a live server, and has no `--force`:

```bash
sudo systemctl stop sito
# Inspect only: prints found/supported versions and the backup path; no database writes
sudo sito db migrate --config /etc/sito/config.toml --dry-run
# Consistent 0600 snapshot at stats.db.v1.bak, then upgrade to schema version 2
sudo sito db migrate --config /etc/sito/config.toml
sudo systemctl start sito
```

**Option B — opt in to startup auto-migration.** Start the 2.0 binary with
`SITO_DB_AUTO_MIGRATE=1` (or `true`). Startup then takes the same shared
migration lock, writes the same consistent 0600 backup
(`<server.data_dir>/stats.db.v<found>.bak`, normally
`/var/lib/sito/stats.db.v1.bak`), migrates, verifies that the schema is current,
and only then opens the runtime database and starts DNS/API. On any failure it
aborts startup, reports the backup path, and never serves. `0`, `false`, empty
or unset mean “no auto-migration”; any other value is an invalid-value startup
error. An existing backup is never overwritten.

A new install (no `stats.db`) creates the current schema normally without a
backup, and an already-current database opens without one. A newer schema is
refused without writes; a corrupt marker fails closed.

**Installer and Docker upgrades run the explicit migration.** The supported
package upgrade paths use the same `sito db migrate` command:

- `contrib/install.sh` stops the old service, installs the new binary, and, for
  a **2.0-or-newer target**, runs `sito db migrate --config
  /etc/sito/config.toml` after the stop and before the new service starts. A
  1.9.x → 1.9.x update never invokes this step. The database step requires an
  already-migrated config v2 document; the installer does not rewrite
  `config.toml`. If the document is still v1, the installer leaves the new 2.0
  binary installed, keeps the service stopped, and prints the exact runnable
  recovery command:
  `sudo /usr/local/bin/sito config migrate --from v1 --to v2 --backup --config
  /etc/sito/config.toml`, followed by `sudo systemctl start sito` (or a re-run
  of the installer after the config is migrated).
  It only runs the database step when the configured `server.data_dir` already
  contains `stats.db`, so fresh installs skip it.
- If the migration fails after B2 wrote its pre-migration backup, the installer
  restores that `<server.data_dir>/stats.db.v<found>.bak` (normally
  `/var/lib/sito/stats.db.v1.bak`, mode `0600`) before rolling back. If no single
  new backup can be identified, it leaves the 2.0 binary installed and the
  service stopped with recovery instructions instead of restarting a server
  against a database whose state is unknown.
- On a pre-2.0 rollback, a 1.9.x binary is only paired with a matching v1
  config: the installer restores `<config>.v1.bak` (written by
  `sito config migrate --backup`) when the target configuration is v2. If that
  file is missing, it refuses to restore the 1.9.x binary and keeps the 2.0
  binary installed with the service stopped.
- `[clients] default_policy` and `[clients.acl]` are additive v2 keys with no
  `config_version` bump. An older 2.0 RC binary without ACL support rejects
  unknown keys, so before downgrading to such a binary remove
  `clients.default_policy` and `[clients.acl]`, then re-run `check-config`.
  A 1.9.x rollback uses the v1 backup as above.
- The container image entrypoint runs that migration before the server when the
  data volume already has a `stats.db`, and exits without starting DNS/API if it
  fails. A fresh volume has no database and is created normally on first start.

Pass `--no-migrate` to the installer or set `SITO_NO_MIGRATE=1` in the
container to skip the migration for a controlled upgrade. The installer writes
`SITO_DB_AUTO_MIGRATE=0` to `/etc/sito/sito.env`, so a preserved B3 opt-in
cannot override the explicit no-migrate choice. The container entrypoint also
refuses the conflicting `SITO_NO_MIGRATE=1` + `SITO_DB_AUTO_MIGRATE=1` pair and
exits before serving. With only the opt-out set, the new server fails closed on
an old database with the B3 message; run the explicit command yourself, restart,
and re-run the upgrade without the opt-out.

The command and startup both restore the data-directory ownership even under
`sudo`: every file created or changed (`stats.db`, `-wal`/`-shm`, `stats-salt`,
the `.bak`) is restored to the owner of the existing `stats.db`, so the
`User=sito` service can open it again. Running the command as the service user
(`sudo -u sito sito db migrate ...`) also avoids the issue.

The backup is mode `0600`, and an existing backup is never overwritten — move
it aside first. The upgrade is forward-only: there is no downgrade and no
`--to`/`--from`. A newer schema is refused, and a corrupt or unknown marker
fails closed. Roll back by stopping the service, restoring the `.bak` over
`stats.db` (remove `stats.db-wal`/`stats.db-shm` first) and starting it.
`--no-backup` skips the snapshot but is not recommended.

A fresh 2.0 install creates a version 2 database when the server starts;
`sito db migrate` fails clearly instead of creating an empty database.

### 1.2 Retroactive anonymization (optional)

Enabling `privacy.anonymize_querylog` only affects new rows. To mask raw client
IPs and remove client names that were already stored in `query_log`, run the
explicit command while the service is stopped:

```bash
sudo systemctl stop sito
# Recommended: keep a pre-anonymization copy; this rewrite cannot be undone
sudo install -d -m 0700 /var/backups/sito-pre-anonymize
sudo tar -C /var/lib/sito -czf /var/backups/sito-pre-anonymize/var-lib-sito.tgz .
# Inspect only: counts rows on a private copy; no live database writes
sudo sito db anonymize --all --config /etc/sito/config.toml --dry-run
# Mask client_ip (IPv4 /24, IPv6 /56) and set client_name = NULL
sudo sito db anonymize --all --config /etc/sito/config.toml
sudo systemctl start sito
```

`--all` is required in 2.0. Detailed rows, their timestamps, query names,
verdicts and all other statistics columns are preserved; only `client_ip` is
masked and `client_name` becomes `NULL`. `stats_hourly` rollups are not touched
(their client identifiers are hashed separately by the rollup PII backfill).

The rewrite is chunked (1,000 rows per committed transaction), crash-resumable
and idempotent: rerunning it skips already-anonymized rows and reports
`0 changed`, and a full run that changed rows ends with `VACUUM` plus a WAL
truncate. It takes the same service lease and `db-migrate.lock` as
`sito db migrate`, refuses a running server and has no `--force`. The database
must already be at schema version 2; run `sito db migrate` first if it is not.
There is no automatic anonymization at startup. See
[the migration guide §6](2.0-migration.md#6-database) for the full behavior and
rollback guidance.

---

## 2. Linux Bare-Metal Installation (systemd)

### 2.1 Resolving `systemd-resolved` Port 53 Conflicts
By default, modern Ubuntu and Debian distributions run `systemd-resolved` listening on `127.0.0.53:53`, which blocks port 53:

1. Disable the local DNS stub listener:
   ```bash
   sudo mkdir -p /etc/systemd/resolved.conf.d
   echo -e "[Resolve]\nDNSStubListener=no" | sudo tee /etc/systemd/resolved.conf.d/disable-stub.conf
   ```
2. Symlink resolv.conf to upstream nameservers and restart:
   ```bash
   sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
   sudo systemctl restart systemd-resolved
   ```

### 2.2 User and Directory Setup
```bash
# Create dedicated system group and user
sudo groupadd --system sito
sudo useradd --system -g sito -d /var/lib/sito -s /usr/sbin/nologin sito

# Create configuration and data directories
sudo mkdir -p /etc/sito /var/lib/sito
sudo chown -R sito:sito /etc/sito /var/lib/sito
sudo chmod 750 /var/lib/sito /etc/sito
```

### 2.3 Binary Placement & Capabilities
```bash
sudo cp target/release/sito /usr/local/bin/sito
sudo chmod 755 /usr/local/bin/sito
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/sito
```

### 2.4 Configuration Skeleton (Optional)
> [!NOTE]
> On a clean boot without an existing `config.toml`, **sito** starts in
> **setup-pending mode** serving only the web panel on port 8080. The reachable
> address depends on the line:
>
> * **1.9.5 (stable):** the setup-pending panel binds the historical
>   `0.0.0.0:8080`, so `http://<server-ip>:8080` is reachable from the LAN. The
>   LAN-only firewall in this guide does not open 8080; use the SSH tunnel
>   (`ssh -L 8080:127.0.0.1:8080 user@server`) or the temporary LAN-scoped rule
>   while completing setup.
> * **2.0 rc (config v2):** the safe default is
>   `web.bind = "127.0.0.1"`, so the setup-pending wizard is **loopback-only too**.
>   Use an SSH tunnel/port-forward (`ssh -L 8080:127.0.0.1:8080 user@server`),
>   or explicitly configure a non-loopback `web.bind` for the setup window if
>   you accept the LAN exposure.
>
> `--no-setup` boots immediately with a generated administrator password
> (printed once) and the panel bound to loopback on both lines.
>
> If you prefer to supply configuration up-front, create `/etc/sito/config.toml`:

```toml
# Current 2.0 rc / config v2. A 1.9.x file is v1 and must be migrated:
#   sito config migrate --from v1 --to v2 --backup
config_version = 2

[server]
role = "master"
instance_name = "sito-main"
data_dir = "/var/lib/sito"
log_level = "info"

[dns]
# The wizard writes a default-deny [clients.acl] on a fresh install. A
# hand-written/headless config keeps allow unless you add [clients.acl]; keep
# the firewall in place as defense in depth.
bind = ["0.0.0.0", "::"]
port = 53
dot_port = 853
doh_port = 443
doq_port = 0

[clients]
# Required for a headless default-deny install (the wizard writes this for a
# fresh GUI install). Add every client network; loopback is not implicit.
default_policy = "deny"

[clients.acl]
allow = ["127.0.0.1/32", "::1/128", "192.168.0.0/24"]
deny = []
allow_entry_ids = false
deny_response = "refused"

[upstream]
servers = ["tls://dns.quad9.net", "1.1.1.1:53"]
bootstrap = ["9.9.9.9", "1.1.1.1"]
strategy = "load_balance"
# Optional, index-aligned with `servers`; default 1 each. Values 1..=100 and
# only used by load_balance. A failed weighted pick still fails over.
weights = [3, 1]

[filtering]
enabled = true
blocking_mode = "zero_ip"

[[filtering.lists]]
name = "OISD Big"
url = "https://big.oisd.nl"
enabled = true

[web]
port = 8080
# 2.0 safe default. Use an SSH tunnel or TLS reverse proxy; only set 0.0.0.0
# if the host firewall/network restricts access to the admin port.
bind = "127.0.0.1"
```

#### Upstream weights

`upstream.weights` is optional and index-aligned with the **global**
`upstream.servers` list; `[[upstream.per_domain]]` rules accept the same
`weights` list for their own servers. Leave it out (or set every value to `1`)
for the historical behavior. Under `strategy = "load_balance"`, a weight of
`3` receives roughly three times as many first attempts as a weight of `1`;
if that pick fails, the resolver still tries the remaining healthy upstreams
in configuration order within the normal `timeout_ms` budget. Weights never
override health checks: a server marked down is skipped at any weight and is
only used by the all-down emergency path. `0` is rejected instead of disabling
a server silently.

The upstream page and the REST `UpstreamConfigDto` expose only the **global**
list. `per_domain.weights` is config-file-only (there is no per-domain editor
in 2.0). Per-client `clients.entries[].upstreams` scopes have no weight field:
they are always unweighted (round-robin) and never inherit `upstream.weights`,
so a global weight change does not reweight them. The HA bundle carries the
global weights; per-node client secrets remain local.

### 2.5 Install Systemd Unit
The canonical unit is [`contrib/systemd/sito.service`](../contrib/systemd/sito.service);
the installer copies that file (or its embedded fallback with the same hardening
directives). Copy it to `/etc/systemd/system/sito.service`:
```ini
[Unit]
Description=sito high-performance filtering DNS server
Documentation=https://github.com/kubaeror/sito-dns
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sito
Group=sito
ExecStart=/usr/local/bin/sito --config /etc/sito/config.toml
# Optional environment overrides (for example RUST_LOG). The leading '-' keeps
# the unit valid when the file is absent; the installer creates it mode 0600.
EnvironmentFile=-/etc/sito/sito.env
# The service runs unprivileged with ProtectSystem=strict, so in-app updates
# cannot replace the binary in /usr/local/bin. Updates must be applied as root
# while the service is stopped: sudo systemctl stop sito && sudo sito update
# (or re-run this installer). The installer also installs cosign because
# server.update_require_signature defaults to true. See docs/installation.md
# "Updating sito".
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectProc=invisible
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077
PrivateTmp=true
ReadWritePaths=/var/lib/sito /etc/sito
LimitNOFILE=1048576
Restart=on-failure
RestartSec=2s
# Allow the bounded query-log shutdown flush to finish before systemd kills the
# process. The writer bounds its own final flush to 3 s; this is a safety net.
TimeoutStopSec=180

[Install]
WantedBy=multi-user.target
```

The unit reads optional overrides from `/etc/sito/sito.env`. The installer
creates that file mode `0600` only when it is absent, preserves it on upgrade,
and leaves it in place on `--uninstall` alongside `config.toml`.

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sito
```

### 2.6 Updating sito

The hardened unit runs as the unprivileged `sito` user with
`ProtectSystem=strict`, and `/usr/local/bin/sito` is root-owned. The in-process
self-update therefore cannot replace its own binary while the service is
running (the write returns `EACCES`). The built-in updater must be run as root
with the service stopped; the installer performs the stop/replace/start
sequence itself:

```bash
# Option A: built-in updater
sudo systemctl stop sito
sudo sito update --check   # optional: preview the release first
sudo sito update
sudo systemctl start sito

# Option B: re-run the installer (SITO_VERSION pins a release)
# The installer stops the service, replaces the binary atomically, and starts it.
sudo SITO_VERSION=1.9.5 bash contrib/install.sh
```

Without `--config`, the CLI prefers an existing `/etc/sito/config.toml` and
otherwise uses `./config.toml`, so the updater commands above work from `/root`
after the service is stopped. If both files exist, or when the server runs with
a custom `--config <path>`, pass the same `--config <path>` to `sito update`
(or `sito --config <path> update`); the updater refuses to guess because the
server and CLI must lock the same `server.data_dir` update lock. If neither
location exists, `sito update` refuses to run instead of guessing the signature
policy. `server.data_dir` must be an absolute path so the shared update lock
cannot depend on each process's working directory.

When the update crosses the 1.9.x → 2.0 line, migrate the configuration first
(see [§1.1](#11-the-20-line)); the installer does not rewrite
`config.toml` automatically. If the document is still v1, the installer leaves
the new 2.0 binary installed, stops the service, and prints the exact
`config migrate` command to run with that binary. For a 2.0 target, the
installer then migrates the statistics database: after stopping the service and
replacing the binary, it runs `sudo sito db migrate --config
/etc/sito/config.toml` (only when the configured data directory already has
`stats.db`) and then starts the new service. A 1.9.x → 1.9.x update skips this.
The `0600` backup is `<server.data_dir>/stats.db.v1.bak` (normally
`/var/lib/sito/stats.db.v1.bak`). On failure it restores that backup before a
rollback; if no new backup exists it keeps the 2.0 binary installed and the
service stopped with recovery instructions. For a controlled upgrade,
`--no-migrate` (or `SITO_NO_MIGRATE=1`) skips the automatic migration and forces
`SITO_DB_AUTO_MIGRATE=0` in `/etc/sito/sito.env`; the 2.0 server then fails
closed until you run `sudo sito db migrate --config /etc/sito/config.toml`
yourself. Use `--dry-run` first to confirm the plan and the backup path.

A health-check rollback after a *successful* migration restores the previous
binary and config only when the previous binary is 2.0+, or when a matching
`<config>.v1.bak` exists for a 1.9.x rollback. Otherwise the 2.0 binary stays
installed and the service stays stopped. A successful migration leaves the
database at schema version 2; that is additive and 1.9.x can open it. To roll
the database itself back, stop the service, remove `stats.db-wal`/`stats.db-shm`,
restore the `.v1.bak` over `stats.db`, and start the service.

`sito update` verifies the release with cosign because
`server.update_require_signature` defaults to `true`. The installer installs a
checksum-verified `cosign` (v2.6.5, matching the release workflow) to
`/usr/local/bin` when it is missing and records
`/usr/local/bin/cosign.installed-by-sito`; `--uninstall` removes that marked
binary but keeps a pre-existing user-managed cosign. `SITO_INSTALL_COSIGN=0`
skips this, and `COSIGN_VERSION` pins a different cosign release. `sito update` refuses before
downloading anything when signatures are required but cosign is unavailable,
and names both the missing verifier and the configuration key. If you installed
the binary manually, install cosign first; only set
`server.update_require_signature = false` when you intentionally accept
SHA-256-only integrity.

The web UI's update button uses the same updater and signature policy. Under
the hardened systemd unit the unprivileged service still cannot replace the
root-owned binary: the updater detects the systemd service environment and
refuses in-app apply with the stop/CLI/start commands above. Docker deployments
are refused for the same reason and must pull a new image. `GET
/api/v2/system/update/check` and `sito update --check` remain available to
preview a release.

The CLI updater downloads assets with `0600` permissions, verifies the staged
binary with `--version`, keeps a backup of the current executable and restores
it if replacement fails, then renames the verified binary into place. It also
refuses to report “up to date” when the release tag cannot be compared as
semver; use `sito update --force` for an explicit reinstall. The updater copies
the existing executable's mode and extended attributes, including
`security.capability`; a missing attribute or failed rename aborts and removes
the temporary file. If you replace the binary manually, re-apply
`sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/sito` after the update.
The installer restores capabilities itself.

The installer stops the service first, then backs up the previous binary to
`/usr/local/bin/sito.bak` and `/etc/sito/config.toml` to
`/etc/sito/config.toml.bak`. Backing up the config after the stop avoids
capturing a file the running service was still rewriting. It writes the
replacement binary to a temporary file in the destination directory, flushes
it, and renames it over `/usr/local/bin/sito` (so a live upgrade cannot fail
with `ETXTBSY`), re-applies the bind capability, and starts the service. A
failed health check restores both backups; a pre-2.0 rollback restores the
matching `<config>.v1.bak` instead of a v2 document, and keeps the 2.0 binary
with the service stopped when that backup is missing. The config restore is
itself temp-file + rename, so a crash cannot leave a truncated `config.toml`.

If `setcap` fails or is unavailable, the installer prints a warning with the
manual command instead of silently continuing, and verifies the result with
`getcap` when it is installed. A `sito update` run as root performs its own
atomic replacement and copies the existing executable's permission bits and
extended attributes (including `security.capability`) onto the new binary, so
an update cannot silently drop the capability needed for ports 53/443/853.
If you manage the binary manually, stop the service, replace
`/usr/local/bin/sito`, re-apply the bind capability
(`sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/sito`), then start the
service again. Docker deployments are updated by pulling the new image tag, not
from inside the container.

---

## 3. Docker Deployment

### 3.1 Standard Container (`docker run`)
```bash
docker run -d \
  --name sito \
  --restart unless-stopped \
  --cap-add=NET_BIND_SERVICE \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 853:853/tcp \
  -p 853:853/udp \
  -p 443:443/tcp \
  -p 443:443/udp \
  -p 127.0.0.1:8080:8080 \
  -v /opt/sito/config:/etc/sito \
  -v sito-data:/var/lib/sito \
  ghcr.io/kubaeror/sito-dns:1.9.5
```

The image defines a healthcheck that probes DNS on the configured port and only
accepts the admin web interface while the API reports first-boot setup pending
(`sito healthcheck --setup-fallback`).

> **Stats database upgrade.** The image entrypoint runs `sito db migrate`
> before the server when `/var/lib/sito/stats.db` already exists. The migration
> writes a consistent `0600` snapshot (`stats.db.v1.bak` for a 1.9.x database),
> takes the service lease and migration lock, and only then starts DNS/API. A
> failed migration exits the container without starting the server. Fresh
> volumes and already-current databases start normally. To run the migration
> yourself during a controlled upgrade, stop the container, run the explicit
> command against the same volumes, then start it with `SITO_NO_MIGRATE=1` (or
> `SITO_NO_MIGRATE: "1"` in Compose); the server then fails closed on an old
> database until the migration has run. If `SITO_DB_AUTO_MIGRATE=1` is also set,
> the entrypoint refuses the conflicting pair and exits without serving. Example:
>
> ```bash
> docker stop sito
> docker run --rm \
>   -v sito-data:/var/lib/sito \
>   -v sito-config:/etc/sito \
>   <new-image> db migrate --config /etc/sito/config.toml
> docker start sito
> ```
>
> Back up the data volume and the config volume together before an upgrade.

> **Config directory permissions.** The image runs as UID/GID `65532`
> (non-root). When bind-mounting a host directory for `/etc/sito`, hand it to
> that user once: `sudo chown -R 65532:65532 /opt/sito/config`. Alternatively
> keep configuration in a named volume mounted at `/etc/sito` (the image
> ships that path owned by `65532:65532`, and Docker initialises fresh named
> volumes from the image path), though the Compose example below bind-mounts
> `./config` for convenience.

> **Data directory permissions.** Fresh named volumes (such as `sito-data`)
> inherit the `65532:65532` ownership created in the image, so no manual step
> is needed. If you bind-mount a host directory at `/var/lib/sito` instead,
> hand it to the same user once: `sudo chown -R 65532:65532 /opt/sito/data`.
> Volumes created by images older than 1.6.0 may already be root-owned; fix
> them once with
> `docker run --rm -v sito-data:/data busybox chown -R 65532:65532 /data`.

---

## 4. Docker Compose Deployment

### 4.1 Single Node (`docker-compose.yml`)
The shipped [`docker-compose.yml`](../docker-compose.yml) is the canonical
single-node file; this block mirrors its ports, named volumes and hardening.
```yaml
services:
  sito:
    # Pinned release tag. Pin the digest as well for reproducible deploys:
    # ghcr.io/kubaeror/sito-dns:1.9.5@sha256:<digest>
    image: ghcr.io/kubaeror/sito-dns:1.9.5
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "853:853/tcp"
      - "853:853/udp"
      - "443:443/tcp"
      - "443:443/udp"
      - "127.0.0.1:8080:8080/tcp"   # loopback-only admin UI
    volumes:
      - sito-config:/etc/sito
      - sito-data:/var/lib/sito
    restart: unless-stopped
    stop_grace_period: 30s
    healthcheck:
      test: ["CMD", "/usr/bin/sito", "--config", "/etc/sito/config.toml", "healthcheck", "--setup-fallback"]
      interval: 30s
      timeout: 5s
      start_period: 30s
      retries: 3

volumes:
  sito-config:
  sito-data:
```

The `--setup-fallback` healthcheck flag keeps the container healthy while the
first-boot wizard is active; once setup completes the DNS probe must succeed, so
a broken DNS listener still turns the container unhealthy.

The entrypoint migrates an existing stats database before starting the server
(see [§3.1](#31-standard-container-docker-run)). For a controlled upgrade, add
the opt-out to the service:

```yaml
environment:
  SITO_NO_MIGRATE: "1"
```

The server then fails closed on an un-migrated database; run
`sito db migrate --config /etc/sito/config.toml` against the same data volume,
then remove the variable and recreate the container. Do not combine
`SITO_NO_MIGRATE=1` with `SITO_DB_AUTO_MIGRATE=1`: the entrypoint rejects the
conflicting policy and exits before serving.

`/etc/sito` defaults to the named `sito-config` volume, which the image
initialises with uid/gid `65532` ownership. To keep configuration on the host,
replace it with `./config:/etc/sito` and hand the directory to the container
user once: `sudo chown -R 65532:65532 ./config`.

> **Migrating an older bind-mounted deployment.** Existing deployments that
> mount `./config:/etc/sito` are not converted automatically. Either keep the
> bind mount and `chown` it to `65532:65532`, or create the named volume and
> copy the files before starting the new Compose definition:
>
> ```bash
> docker volume create <project>_sito-config
> docker run --rm \
>   -v "$PWD/config:/from:ro" \
>   -v "<project>_sito-config:/to" \
>   busybox sh -c 'cp -a /from/. /to/ && chown -R 65532:65532 /to'
> ```
>
> Use `docker compose config --volumes` to confirm the project-prefixed volume
> name. `sito.env`, `config.toml`, `users.toml`, ACME state and HA key material
> must move together; a config volume without its data volume is not a complete
> backup.

To build and run the working tree instead of the pinned release image, layer
the build override:

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

> **Host binding vs in-container binding.** Docker's `ports` mapping controls
> which host interface accepts connections; `web.bind` controls where the
> process listens *inside* the container. Keep `web.bind = "0.0.0.0"` in the
> container and publish the admin port only on loopback
> (`127.0.0.1:8080:8080`) with an SSH tunnel or TLS reverse proxy in front.
> Publishing `8080:8080` exposes the plain-HTTP admin UI on every host
> interface. Pin the image tag (`1.9.5`) instead of `latest` in production.

For reproducible deploys, pin the published digest as well as the tag:

```bash
docker buildx imagetools inspect ghcr.io/kubaeror/sito-dns:1.9.5 \
  --format '{{.Manifest.Digest}}'
# then set:
#   image: ghcr.io/kubaeror/sito-dns:1.9.5@sha256:<digest>
```

A digest cannot be moved by retagging, so upgrades become an explicit edit. The
same rule applies to the HA services in `docker-compose.ha.yml`.

### 4.2 High-Availability Master/Slave on LAN (`macvlan`)
Run redundant master and slave instances on separate dedicated LAN IPs on a single server:

```yaml
networks:
  lan:
    driver: macvlan
    driver_opts:
      parent: ${SITO_HA_PARENT:-eth0}
    ipam:
      config:
        - subnet: ${SITO_HA_SUBNET:-192.168.1.0/24}
          gateway: ${SITO_HA_GATEWAY:-192.168.1.1}

services:
  sito-master:
    image: ghcr.io/kubaeror/sito-dns:1.9.5
    container_name: sito-master
    cap_add: [NET_BIND_SERVICE]
    security_opt: [no-new-privileges:true]
    read_only: true
    networks:
      lan:
        ipv4_address: ${SITO_HA_MASTER_IP:-192.168.1.10}
    volumes:
      - ./ha/master/config:/etc/sito
      - ./ha/master/certs:/etc/sito/certs:ro
      - sito-master-data:/var/lib/sito
    healthcheck:
      test: ["CMD", "/usr/bin/sito", "--config", "/etc/sito/config.toml", "healthcheck", "--setup-fallback"]
      interval: 15s
      timeout: 5s
      retries: 3

  sito-slave:
    image: ghcr.io/kubaeror/sito-dns:1.9.5
    container_name: sito-slave
    cap_add: [NET_BIND_SERVICE]
    security_opt: [no-new-privileges:true]
    read_only: true
    networks:
      lan:
        ipv4_address: ${SITO_HA_SLAVE_IP:-192.168.1.11}
    volumes:
      - ./ha/slave/config:/etc/sito
      - ./ha/slave/certs:/etc/sito/certs:ro
      - sito-slave-data:/var/lib/sito
    healthcheck:
      test: ["CMD", "/usr/bin/sito", "--config", "/etc/sito/config.toml", "healthcheck", "--setup-fallback"]
      interval: 15s
      timeout: 5s
      retries: 3

volumes:
  sito-master-data:
  sito-slave-data:
```

Set the topology in the shell or a `.env` file next to the compose file:
`SITO_HA_PARENT`, `SITO_HA_SUBNET`, `SITO_HA_GATEWAY`,
`SITO_HA_MASTER_IP`, `SITO_HA_SLAVE_IP` (and `SITO_HA_SLAVE2_IP` for the
optional third node). If you change the IPs, regenerate the RouterOS DHCP
Option 6 hex value; the shipped example `0xc0a8010ac0a8010b` is
`192.168.1.10,192.168.1.11` and must have an even number of hex digits.

> [!NOTE]
> Configuration, including `[ha] master_url`, is read exclusively from the
> mounted `config.toml`; environment overrides (for example
> `DNSD__HA__MASTER_URL`) are not supported: `SITO_HA_*` only parameterizes the
> compose topology. Make the host config and certificate directories writable
> by uid/gid 65532 once:
> `sudo chown -R 65532:65532 ha/master/config ha/master/certs ha/slave/config ha/slave/certs`,
> then `sudo chmod 0600 ha/master/certs/*.key ha/slave/certs/*.key`. The full
> macvlan reference deployment, including certificate handling and the RouterOS
> DHCP hints, is in `docker-compose.ha.yml`. RouterOS lease sync is an optional,
> experimental integration: the default binary does not include it. Build with
> `cargo build -p sito --features routeros` to enable it.

---

## 5. Post-Installation Verification

### 5.1 Test DNS Resolution
```bash
# Verify plain UDP resolution
dig @127.0.0.1 -p 53 example.com +short

# Verify ad-blocking
dig @127.0.0.1 -p 53 doubleclick.net +short
# Expected output: 0.0.0.0
```

### 5.2 Verify API and Web Panel
The `/api/v2/*` endpoints used below require a session cookie or API token.
Create a token in the web UI or sign in, then:

```bash
export SITO=http://127.0.0.1:8080
export TOKEN='sito_...'   # Viewer, Operator, or Admin API token
curl -fsSL -H "Authorization: Bearer $TOKEN" "$SITO/api/v2/status" | jq .
```

For a pre-authentication liveness probe use the dedicated `/health` endpoint
instead; it exposes only a generic ready flag.

The CLI health probe requires a matching DNS response with a `NOERROR` rcode:

```bash
sito --config /etc/sito/config.toml healthcheck

# First-boot window only: accept the admin web interface while the API reports
# setup pending (DNS listeners are not bound until setup completes).
sito --config /etc/sito/config.toml healthcheck --setup-fallback
```

When the configuration contains a `[ha]` section with HA enabled for the node's
role, the probe also requires replication to be ready: the master listener must
have bound with its mTLS key, and a slave must have reached `Synced`. A healthy
DNS response alone no longer masks an HA failure. See `docs/runbook-ha.md`
(certificate ownership) if the probe reports an unreadable key.

Open `http://<host-ip>:8080` in your browser to run the first-time setup wizard (or use the SSH tunnel above when the LAN-only firewall is enabled). **On 2.0 the default `web.bind` is `127.0.0.1`, so the setup-pending wizard is loopback-only**: open `http://127.0.0.1:8080` through the SSH tunnel above, or explicitly configure a non-loopback `web.bind` for the setup window. See the setup-pending reachability note above. While setup is pending the server prints a one-time setup token to the console; open `http://<host-ip>:8080/wizard?setup_token=<token>` or send the `X-Setup-Token` header. Login, API tokens and every non-wizard route stay disabled until setup completes, including when `config.toml` already exists but `users.toml` still contains the bootstrap `admin` / `adminadmin` account.

**Client Access Control (ADR-0011).** After the DNS-listener step the fresh-install wizard shows every usable interface plus the raw admin peer, classified as loopback, RFC 1918, IPv6 ULA, public, or bridge/tunnel. Loopback and any `[clients.acl] allow` prefixes already present in the base template are preselected; no other non-loopback network is auto-added, and `X-Forwarded-For`/`trusted_proxies` is never used to seed one. Template prefixes are shown as locked/kept and cannot be removed through this step. Default deny is checked even when the base template says `default_policy = "allow"`; uncheck it to keep the template's allow policy. A loopback-only install needs the loopback-only acknowledgement; any public network needs the public exposure acknowledgement; allow-all requires both the checkbox and the exact text `ALLOW ALL` (manual and template catch-alls do not bypass this). Existing template `allow`/`deny` prefixes and `deny_response` are preserved, and `allow_entry_ids` stays off unless explicitly checked. The setup-token/re-auth recovery wizard on an existing install does **not** render or apply this step, and an install with a usable Admin (including a template that pre-creates one) is treated as provisioned rather than fresh, so an existing ACL is never rewritten. A fresh POST that lacks the ACL marker (a stale or cached form) returns 400 and writes nothing; reload `/wizard`.

If the wizard is skipped with `--no-setup` **on a first boot with no `config.toml`**, a random administrator password is generated and printed once, and the panel binds to loopback. A headless install is **not** default-deny: add `[clients] default_policy = "deny"` and the explicit `[clients.acl] allow` networks (including loopback) to `config.toml` before starting DNS. When a config file already exists, `--no-setup` neither creates nor rotates credentials. If credentials are lost later, stop the service so the running process cannot keep serving the old credentials, reset the account, then start it again:

```bash
sudo systemctl stop sito

# Generate a new random password and print it once:
sudo sito --config /etc/sito/config.toml reset-admin

# Or supply your own strong password (same policy as the wizard/API):
sudo sito --config /etc/sito/config.toml reset-admin --password '<new-password>'

sudo systemctl start sito
```

`reset-admin` preserves other accounts. Add `--reset-all` (alias
`--reset-users`) only when you explicitly want to remove every non-admin
account. The reset commands refuse to run while the service holds
`<data_dir>/sito.pid`; `--force` only updates the on-disk state and requires a
restart before the new password or session revocation takes effect.

---

## 6. Verifying Releases

Every release archive is published with a `.sha256` checksum, a cosign keyless
signature (`.sig` + `.pem`), and a `SHA256SUMS` file covering the archives and
the SPDX SBOM (`sito.spdx.json`).

### 6.1 Checksums

The unified `SHA256SUMS` covers every archive plus the SPDX SBOM, so download
**all** release assets into one directory before checking it:

```bash
sha256sum -c SHA256SUMS
```

If you only downloaded one archive, verify its per-archive checksum instead
(the `.sha256` filename matches the archive):

```bash
sha256sum -c sito-v1.9.5-x86_64-unknown-linux-gnu.tar.gz.sha256
```

### 6.2 cosign signature (keyless)

```bash
cosign verify-blob \
  --certificate sito-v1.9.5-x86_64-unknown-linux-gnu.tar.gz.pem \
  --signature   sito-v1.9.5-x86_64-unknown-linux-gnu.tar.gz.sig \
  --certificate-identity-regexp \
      '^https://github.com/kubaeror/sito-dns/\.github/workflows/release\.yml@refs/tags/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sito-v1.9.5-x86_64-unknown-linux-gnu.tar.gz
```

The identity pins the artifact to this repository's release workflow and the
OIDC issuer pins it to GitHub Actions. `install.sh` requires a valid cosign
signature by default: if cosign or the `.sig`/`.pem` assets are missing, the
install fails instead of falling back to a SHA-256 checksum from the same
release channel. Set `SITO_REQUIRE_SIGNATURE=0` only for an intentional
SHA-256-only installation. The installer also installs cosign itself
(checksum-verified, `COSIGN_VERSION` defaults to `v2.6.5`) so the default
`sito update` signature policy works after a fresh install; set
`SITO_INSTALL_COSIGN=0` to manage cosign externally (the installer then refuses
to continue unless unauthenticated installs are explicitly allowed with
`SITO_REQUIRE_SIGNATURE=0`).

### 6.3 SBOM

The SPDX 2.3 document `sito.spdx.json` is attached to every release and is
covered by `SHA256SUMS`.

### 6.4 Reproducibility

Release binaries are built in GitHub Actions with `cargo build --release
--locked --features "embed-ui,ha,mimalloc"`, so the dependency graph is exactly
the committed `Cargo.lock`,
using the pinned Rust toolchain in `rust-toolchain.toml` and the release
profile (`lto = "fat"`, `codegen-units = 1`, `strip = true`). Rebuilding the
same tag locally with the same toolchain produces a functionally identical
binary; bit-for-bit identity is not guaranteed across host toolchains or
archive timestamps.
