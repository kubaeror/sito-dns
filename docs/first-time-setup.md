> **Historical document.** This was the implementation plan for the first-boot
> setup wizard and installer changes; it is kept for design history. Several
> "Current State" claims below (missing-wizard hard error, installer-generated
> config, default credentials, port conflicts) no longer describe the tree.
> For current behavior see [first-boot setup in the
> README](../README.md#-first-time-setup-wizard),
> [security-audit.md](security-audit.md) and [audit5.md](audit5.md).

# Plan: Web-Based First-Time Setup Wizard + Installer Hardening

**Repo:** `sito-dns` (Rust workspace, axum-based DNS server with HTMX admin panel)
**Branch target:** `main`

## Objective
Replace the installer-generated default `config.toml` flow with a web-based first-time setup experience: when the server starts without a config file, it boots in a **setup-pending mode** serving only the web panel, and a full first-run wizard collects all key configuration options (including the admin account and password). Every form field is optional — empty/unfilled fields fall back to built-in defaults. Additionally, apply the previously agreed installer hardening improvements.

## Current State (verified facts)
- `crates/sito/src/main.rs:99` — hard error if `config.toml` is missing; server refuses to start.
- A minimal wizard already exists: `GET /wizard` (`crates/sito-api/src/ui/handlers.rs:1421`), `POST /ui/wizard/complete` (`handlers.rs:1447`), template `crates/sito-api/templates/wizard.html`. Current form only collects: admin user, admin password, one upstream, adblock toggle.
- `crates/sito-api/src/auth/manager.rs:339` — `AuthManager::is_first_run()` (no users / default `admin/adminadmin` still active). Wizard gating for first-run vs admin session already implemented (returns 403 once initialized) and covered by tests in `crates/sito-test/tests/m6_acceptance.rs` and unit tests in `handlers.rs:1549+`.
- `crates/sito-api/src/config_writer.rs` — atomic config persistence (`save_config_atomic`) with pre-commit `Config::validate()`, tmp-file + fsync + rename (ADR-0004).
- `contrib/install.sh` — writes a full default `config.toml` (lines 125–200), prints default credentials `admin/adminadmin` (line 246), and swallows download failures with `|| true` (lines 74–78).
- Default config conflict: `dot_port = 853` and `doq_port = 853` in the installer heredoc (lines 142, 144) — both protocols on the same port.
- CI workflows: `.github/workflows/ci.yml` (5 jobs), `.github/workflows/release.yml` (3 jobs). No shellcheck anywhere.

## Part A — First-Time Setup (server + wizard)

### A1. Bootstrap mode when config file is missing — `crates/sito/src/main.rs`, `crates/sito/src/cli.rs`
- If the config file (default `config.toml`, flag `--config`) does **not** exist at startup: build `Config::default()` in memory (do NOT error, do NOT write to disk yet), set `setup_pending = true`, log a prominent message: `First run detected: open http://<host>:8080 to complete setup`.
- In `setup_pending` mode, start **only** the web/API server (bind from `web.bind`/`web.port`, default `0.0.0.0:8080`). **Do not bind DNS ports** (53/853/443) until the wizard saves the config.
- Add CLI flag `--no-setup` (clap, in `crates/sito/src/cli.rs`): skips the gating entirely — server starts normally (DNS + panel) with built-in defaults, for headless installs. Config is still not written to disk until saved via panel or supplied by the operator.
- Config file that exists but is invalid keeps the current hard-fail behavior (do not silently fall back to defaults for a *present* file).

### A2. Setup-pending state and route gating — `crates/sito-api/src/state.rs`, `router.rs`, `ui/mod.rs`
- Add `setup_pending: bool` to `ServerContext` (populated from A1; flipped to `false` after wizard completion).
- Add a routing middleware/layer: while `setup_pending == true`:
  - Allow: `/wizard`, `/ui/wizard/complete`, `/static/*` (logo, css, js), health endpoint if present.
  - Everything else UI: HTTP 302 redirect to `/wizard`.
  - Everything `/api/v1/*`: HTTP 503 with body `Setup not completed`.
  - `/login`: redirect to `/wizard` too (no accounts exist yet in meaningful state).
- Keep the existing `is_first_run()` / admin-session wizard gating intact for post-setup access (admins can re-open `/wizard` to change admin credentials — current behavior).

### A3. Expanded wizard — `crates/sito-api/src/ui/handlers.rs`, `crates/sito-api/templates/wizard.html`
Single page, grouped sections (steps), all fields pre-filled with current defaults; empty fields → defaults:

1. **Administrator account** — username, password, confirm-password. Reuse existing validation (≥8 chars, no whitespace/control chars, `admin_user` handling in `wizard_complete_handler`).
2. **DNS listeners** — `dns.bind` (IPv4/IPv6 checkboxes), `port` (53), `dot_port` (853), `doh_port` (443). DoQ disabled by default (resolves the 853/853 conflict).
3. **Upstreams** — multi-value server list with presets (Quad9, Cloudflare, Google + custom entry), `upstream.strategy` (parallel/failover), `bootstrap` IPs, `timeout_ms`. Add a "Test latency" button reusing the existing upstream latency-test endpoint (`crates/sito-api/src/handlers/upstream.rs`).
4. **Cache & DNSSEC** — `dns.cache.enabled`, `dns.cache.size_mb`, `dns.dnssec.mode` / `validate`.
5. **Filtering** — `filtering.enabled`, `blocking_mode` (zero_ip / NXDOMAIN / ...), blocklist presets as checkboxes (OISD Big, OISD Small, StevenBlack, Hagezi), `cname_cloaking` toggle.
6. **Web panel & stats** — `web.bind`, `web.port`, `stats.retention_days`.

Handler changes:
- Extend `WizardCompleteForm` with `Option<String>` fields (all optional) and build a full `Config` from the form; per-section: missing → `Config::default()` values. Reuse/extend the section-mapping helpers already used by `POST /api/v1/config` (`crates/sito-api/src/handlers/config.rs`) where possible to avoid duplicating validation logic.
- Persist via existing `save_config_atomic` (`config_writer.rs`) — includes `Config::validate()` for free.
- Hot-reload as today: `ctx.config.store(...)`, `ctx.filter.reload_with_config(...)`, `ctx.upstream.reload(...)`, `crate::publish_bundle(&ctx)`.
- **Start DNS listeners after setup, in-process** (preferred): thread a start handle from the bootstrap-mode path in `run_server_full` (`crates/sito/src/lib.rs`) through `ServerContext` so wizard completion can build and bind the DNS pipeline without a process restart. **Fallback** (if the pipeline structurally requires restart): after saving, show a UI banner + log message instructing `systemctl restart sito`, and flip `setup_pending` to `false` so the next boot starts normally.
- After successful save: flip `setup_pending` to `false`, then redirect to `/login`.

### A4. Installer stops generating config — `contrib/install.sh`
- Remove the full `config.toml` heredoc (lines 125–200); keep only directory creation (`/etc/sito`, `/var/lib/sito`) and permissions.
- Update the final summary block: remove `admin / adminadmin` credentials and the "change default password" warning; instead print `Open http://<host-ip>:8080 to complete first-time setup`.

## Part B — Installer Hardening

1. **Download error handling** (`contrib/install.sh`): remove `|| true` on the curl/wget calls (lines 74–78); retry up to 3 attempts with short backoff; hard-exit with a clear network-error message on failure.
2. **Cosign verification**: if the release ships `.sig`/`.pem` artifacts and `cosign` is installed, verify keyless signature for repo `kubaeror/sito-dns`; if no signature artifacts exist, keep the current hard SHA-256 requirement and print a warning to prefer releases with signatures.
3. **Post-install health check**: after `systemctl restart`, run `systemctl is-active sito` and `curl -fsS http://localhost:8080`; on failure print `journalctl -u sito -n 50 --no-pager` and troubleshooting hints.
4. **Upgrade vs fresh detection**: compare installed binary version (`sito --version` if present) — back up the old binary to `/usr/local/bin/sito.bak`, print `Upgrading sito vX → vY` or `Fresh install`.
5. **Firewall hints**: final summary lists required ports (53, 853, 443, 8080) with example `ufw allow` / `firewall-cmd` commands.
6. **Shellcheck in CI**: new `shellcheck` job in `.github/workflows/ci.yml` (`runs-on: ubuntu-latest`, `shellcheck -S error contrib/install.sh`; use `rhysd/action-shellcheck@v1` or `sudo apt-get install shellcheck`). Mirror the same step in `.github/workflows/release.yml` so release artifacts pass the same check.
7. **Port conflict fix**: remove/adjust `doq_port = 853` in `Config::default()` (`crates/sito-core/src/config.rs`) if present there too, so code-level defaults are conflict-free.

## Part C — Documentation & Tests
- Update `docs/installation.md`, `README.md` (installer + first-run flow sections), `CHANGELOG.md`: no default passwords, wizard-driven first run, `--no-setup` flag for headless.
- Tests:
  - `crates/sito-api/src/ui/handlers.rs` unit tests: new form fields, empty-field → default mapping, port validation.
  - `crates/sito-test/tests/m6_acceptance.rs`: in setup-pending mode all UI routes redirect to `/wizard`, `/api/v1/*` returns 503, DNS ports not bound until setup completes.
  - `crates/sito-test/tests/m9_acceptance.rs`: update installer assertions (no generated config file).
  - CLI test for `--no-setup` flag parsing/behavior.

## Verification (DoD)
- `cargo test --workspace` passes.
- `shellcheck -S error contrib/install.sh` clean; CI shellcheck job green.
- Manual smoke: delete `config.toml` → start `sito` → only web panel on 8080 responds, port 53 closed; completing the wizard writes `config.toml`, DNS starts; second boot starts fully without wizard.
- Installer smoke on a clean VM: service runs, no `config.toml` created, no default-credentials message printed.

## Step → Files → Verification Traceability
| Step | Files | Verification |
|---|---|---|
| A1 bootstrap mode + `--no-setup` | `crates/sito/src/main.rs`, `crates/sito/src/cli.rs` | CLI test; smoke without config |
| A2 setup-pending gating | `crates/sito-api/src/state.rs`, `router.rs`, `ui/mod.rs` | m6_acceptance redirect/503 tests |
| A3 expanded wizard | `crates/sito-api/src/ui/handlers.rs`, `templates/wizard.html` | handler unit tests |
| A4 + B1–B5 installer | `contrib/install.sh` | shellcheck, m9_acceptance, clean-VM smoke |
| B6 shellcheck CI | `.github/workflows/ci.yml`, `.github/workflows/release.yml` | green CI job |
| B7 port conflict | `crates/sito-core/src/config.rs` | config validation test |
| C docs & tests | `docs/installation.md`, `README.md`, `CHANGELOG.md`, test files | `cargo test --workspace` |

## Execution Order / Dependencies
A1 → A2 → A3 (state + gating must exist before the expanded wizard can be gated correctly). A4 and B1–B6 are independent of A1–A3 and can be done in parallel. C lands last, after the code it documents is stable.
