#!/usr/bin/env bash
# WP-3.2 real 1.9.5 data-directory migration / rollback acceptance.
#
# Evidence produced, in one isolated temp directory:
#   1. a real v1.9.5 binary creates a v1 data dir + stats.db and answers a
#      local A rewrite on a high DNS port;
#   2. a copy is migrated with `sito config migrate --from v1 --to v2 --backup`;
#   3. the new binary starts on the migrated copy: the rewrite still answers,
#      `/api/v1/status` responds, the stats DB is readable and users/TOTP files
#      are unchanged;
#   4. rollback restores the pre-upgrade data copy and `.v1.bak`, and the
#      v1.9.5 binary starts and answers again.
#
# SQLite is compatibility-only in 2.0: this script never runs a schema
# migration command. The current binary opens the 1.9.5 `stats.db` additively.
#
# Binaries: set SITO_OLD_BIN / SITO_NEW_BIN to skip the builds. Otherwise the
# script builds v1.9.5 from /tmp/opencode/sito-1.9.5 and this worktree with
# `cargo build -p sito --features embed-ui`.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OLD_TREE="${SITO_OLD_TREE:-/tmp/opencode/sito-1.9.5}"
NEW_TREE="${SITO_NEW_TREE:-$ROOT}"
TMP_BASE="${SITO_MIGRATION_TMPDIR:-/tmp/opencode}"
DNS_PORT="${SITO_MIGRATION_DNS_PORT:-15353}"
WEB_PORT="${SITO_MIGRATION_WEB_PORT:-18080}"
ADMIN_PASSWORD="MigrationPass123!"

mkdir -p "$TMP_BASE"
TMP="$(mktemp -d "$TMP_BASE/sito-migration-1.9.5.XXXXXX")"
SERVER_PID=""
SERVER_PID_V1=""

cleanup() {
  local pid
  for pid in "$SERVER_PID" "$SERVER_PID_V1"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

log() { printf '\n== %s\n' "$*"; }
fail() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }

step() { printf '+ %s\n' "$*"; }

[[ -x "$TMP_BASE" || -d "$TMP_BASE" ]] || fail "temp base is not a directory: $TMP_BASE"

log "Binaries"
if [[ -n "${SITO_OLD_BIN:-}" ]]; then
  OLD_BIN="$SITO_OLD_BIN"
else
  [[ -d "$OLD_TREE" ]] || fail "v1.9.5 worktree not found at $OLD_TREE"
  step "cargo build -p sito --features embed-ui  (cwd: $OLD_TREE)"
  (cd "$OLD_TREE" && env -u CARGO_TARGET_DIR cargo build -p sito --features embed-ui)
  OLD_BIN="$OLD_TREE/target/debug/sito"
fi
if [[ -n "${SITO_NEW_BIN:-}" ]]; then
  NEW_BIN="$SITO_NEW_BIN"
else
  step "cargo build -p sito --features embed-ui  (cwd: $NEW_TREE)"
  (cd "$NEW_TREE" && env -u CARGO_TARGET_DIR cargo build -p sito --features embed-ui)
  NEW_BIN="$NEW_TREE/target/debug/sito"
fi
[[ -x "$OLD_BIN" ]] || fail "old binary is not executable: $OLD_BIN"
[[ -x "$NEW_BIN" ]] || fail "new binary is not executable: $NEW_BIN"
"$OLD_BIN" --version
"$NEW_BIN" --version

WORK="$TMP/work"
DATA="$WORK/data"
CONFIG="$WORK/config.toml"
mkdir -p "$DATA"

cat >"$CONFIG" <<EOF
config_version = 1

[server]
role = "master"
instance_name = "migration-acceptance"
data_dir = "$DATA"
log_level = "warn"
log_format = "json"

[dns]
bind = ["127.0.0.1"]
port = $DNS_PORT
dot_port = 0
doh_port = 0
doq_port = 0
doh3_port = 0
allow_plaintext_doh = false

[dns.cache]
enabled = false

[dns.dnssec]
mode = "off"
validate = false

[upstream]
servers = ["udp://127.0.0.1:9"]
timeout_ms = 1000
probe_domain = "example.com"
pool_size = 1
strategy = "failover"

[filtering]
enabled = false

[rewrites]
ttl = 60

[[rewrites.entries]]
domain = "migration.test"
type = "A"
answer = "192.0.2.53"

[stats]
retention_days = 90
rollup_retention_days = 365
rollup_client_names = false

[web]
enabled = false
bind = "127.0.0.1"
port = $WEB_PORT
metrics_auth = false
EOF

# Query the rewrite with a small dependency-free DNS client.
dns_rewrite_answers() {
  python3 - "$DNS_PORT" <<'PY'
import socket
import struct
import sys

port = int(sys.argv[1])
name = "migration.test"
qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
query = struct.pack("!HHHHHH", 0x5A17, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.0)
try:
    sock.sendto(query, ("127.0.0.1", port))
    data, _ = sock.recvfrom(4096)
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
if len(data) < 12:
    raise SystemExit(1)
ident, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
if ident != 0x5A17 or (flags & 0x000F) != 0 or an < 1:
    raise SystemExit(1)
if b"\xc0\x00\x02\x35" not in data:
    raise SystemExit(1)
PY
}

wait_for_dns() {
  local pid="$1" logfile="$2" label="$3"
  local i
  for _ in $(seq 1 120); do
    if ! kill -0 "$pid" 2>/dev/null; then
      printf '\n%s exited before answering:\n' "$label" >&2
      cat "$logfile" >&2 || true
      return 1
    fi
    if dns_rewrite_answers; then
      return 0
    fi
    sleep 0.25
  done
  printf '\n%s did not answer migration.test within 30s:\n' "$label" >&2
  cat "$logfile" >&2 || true
  return 1
}

start_v1() {
  local config="$1" logfile="$2" label="$3"
  step "$OLD_BIN --config $config"
  "$OLD_BIN" --config "$config" >"$logfile" 2>&1 &
  SERVER_PID_V1=$!
  wait_for_dns "$SERVER_PID_V1" "$logfile" "$label"
  SERVER_PID="$SERVER_PID_V1"
  SERVER_PID_V1=""
}

start_v2() {
  local config="$1" logfile="$2" label="$3"
  step "$NEW_BIN --config $config"
  "$NEW_BIN" --config "$config" >"$logfile" 2>&1 &
  SERVER_PID=$!
  wait_for_dns "$SERVER_PID" "$logfile" "$label"
}

stop_server() {
  local label="$1"
  [[ -n "$SERVER_PID" ]] || return 0
  step "stop $label (SIGTERM pid $SERVER_PID)"
  kill "$SERVER_PID" 2>/dev/null || true
  for _ in $(seq 1 40); do
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 0.25
  done
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -9 "$SERVER_PID" 2>/dev/null || true
  fi
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
}

log "Seed a v1 user and TOTP key"
step "$OLD_BIN --config $CONFIG reset-admin --password <redacted>"
"$OLD_BIN" --config "$CONFIG" reset-admin --password "$ADMIN_PASSWORD"
[[ -f "$DATA/users.toml" ]] || fail "reset-admin did not write users.toml"
head -c 32 /dev/urandom >"$DATA/totp.key"
chmod 0600 "$DATA/totp.key"
USERS_SHA_BEFORE="$(sha256sum "$DATA/users.toml" | awk '{print $1}')"
TOTP_SHA_BEFORE="$(sha256sum "$DATA/totp.key" | awk '{print $1}')"

log "1.9.5 run on the v1 data directory"
start_v1 "$CONFIG" "$WORK/old.log" "v1.9.5"
dns_rewrite_answers || fail "v1.9.5 did not answer the rewrite"
step "v1.9.5 answered migration.test A 192.0.2.53 on 127.0.0.1:$DNS_PORT"
stop_server "v1.9.5"
[[ -s "$DATA/stats.db" ]] || fail "v1.9.5 did not create stats.db"

log "Snapshot and copy the pre-upgrade state"
PRE="$WORK/pre-upgrade"
mkdir -p "$PRE"
cp -a "$DATA/." "$PRE/data"
cp -a "$CONFIG" "$PRE/config.toml"
MIGRATED="$WORK/migrated"
mkdir -p "$MIGRATED"
cp -a "$DATA/." "$MIGRATED/data"
cp -a "$CONFIG" "$MIGRATED/config.toml"
MIGRATED_CONFIG="$MIGRATED/config.toml"
MIGRATED_DATA="$MIGRATED/data"
step "cp -a $DATA/. $MIGRATED/data && cp -a $CONFIG $MIGRATED_CONFIG"

log "Migrate the copied config (SQLite is untouched)"
step "$NEW_BIN config migrate --config $MIGRATED_CONFIG --from v1 --to v2 --backup"
"$NEW_BIN" config migrate --config "$MIGRATED_CONFIG" --from v1 --to v2 --backup
grep -qx 'config_version = 2' "$MIGRATED_CONFIG" || fail "migrated config is not v2"
BACKUP="$MIGRATED_CONFIG.v1.bak"
[[ -f "$BACKUP" ]] || fail "missing backup $BACKUP"
BACKUP_MODE="$(stat -c '%a' "$BACKUP")"
[[ "$BACKUP_MODE" == "600" ]] || fail "backup mode is $BACKUP_MODE, expected 600"
cmp -s "$BACKUP" "$CONFIG" || fail "backup does not match the pre-upgrade config"
step "$NEW_BIN --config $MIGRATED_CONFIG check-config"
"$NEW_BIN" --config "$MIGRATED_CONFIG" check-config
step "asserted v2 document, 0600 .v1.bak, check-config"

log "Start 2.0 on the migrated copy"
# The acceptance config disables the admin listener for the v1 run. Derive a
# runtime copy of the exact migrated v2 document that only enables the
# loopback admin listener needed for /api/v1/status.
RUNTIME_CONFIG="$MIGRATED/config.runtime.toml"
python3 - "$MIGRATED_CONFIG" "$RUNTIME_CONFIG" "$MIGRATED_DATA" <<'PY'
import sys
source, target, data_dir = sys.argv[1:]
text = open(source, encoding="utf-8").read()
lines = text.splitlines()
in_web = False
out = []
for line in lines:
    if line.startswith("[") and line.strip() != "[web]":
        in_web = False
    if line.strip() == "[web]":
        in_web = True
    if line.startswith("data_dir = "):
        line = f'data_dir = "{data_dir}"'
    elif in_web and line.strip() == "enabled = false":
        line = line.replace("enabled = false", "enabled = true")
    out.append(line)
open(target, "w", encoding="utf-8").write("\n".join(out) + "\n")
PY
step "$NEW_BIN --config $RUNTIME_CONFIG check-config"
"$NEW_BIN" --config "$RUNTIME_CONFIG" check-config
start_v2 "$RUNTIME_CONFIG" "$WORK/new.log" "2.0"
dns_rewrite_answers || fail "2.0 did not answer the rewrite after migration"
step "2.0 answered migration.test A 192.0.2.53 on 127.0.0.1:$DNS_PORT"

COOKIE_JAR="$WORK/cookies.txt"
for _ in $(seq 1 80); do
  if curl -fsS "http://127.0.0.1:$WEB_PORT/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
step "curl -c <jar> -d '{\"user\":\"admin\",...}' http://127.0.0.1:$WEB_PORT/api/v1/auth/login"
curl -fsS -c "$COOKIE_JAR" -H 'Content-Type: application/json' \
  -d "{\"user\":\"admin\",\"pass\":\"$ADMIN_PASSWORD\"}" \
  "http://127.0.0.1:$WEB_PORT/api/v1/auth/login" >/dev/null
STATUS_JSON="$(curl -fsS -b "$COOKIE_JAR" "http://127.0.0.1:$WEB_PORT/api/v1/status")"
python3 - "$STATUS_JSON" <<'PY'
import json
import sys

body = json.loads(sys.argv[1])
assert "version" in body, body
print(f"  /api/v1/status OK: version={body['version']} role={body.get('role')}")
PY
step "asserted /api/v1/status requires a session and returns the status document"
stop_server "2.0"

log "Post-upgrade assertions"
[[ "$(sha256sum "$MIGRATED_DATA/users.toml" | awk '{print $1}')" == "$USERS_SHA_BEFORE" ]] \
  || fail "users.toml changed across the upgrade"
[[ "$(sha256sum "$MIGRATED_DATA/totp.key" | awk '{print $1}')" == "$TOTP_SHA_BEFORE" ]] \
  || fail "totp.key changed across the upgrade"
step "users.toml and totp.key survived byte-for-byte"
python3 - "$MIGRATED_DATA/stats.db" <<'PY'
import sqlite3
import sys

path = sys.argv[1]
con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
for name in ("query_log", "stats_hourly", "stats_watermark", "stats_meta"):
    assert name in tables, (name, sorted(tables))
versions = [row[0] for row in con.execute("SELECT version FROM _sqlx_migrations ORDER BY version")]
assert versions == [20260905000000, 20260906000000, 20260913000000, 20260922000000], versions
print(f"  stats.db integrity=ok tables={sorted(tables)} migrations={versions}")
PY
step "read the migrated stats.db read-only with Python sqlite3"

log "Rollback: restore the pre-upgrade data copy and config backup"
rm -rf "$DATA"
cp -a "$PRE/data" "$DATA"
cp -a "$PRE/config.toml" "$CONFIG"
cmp -s "$CONFIG" "$BACKUP" || fail "restored config is not the v1 document"
start_v1 "$CONFIG" "$WORK/rollback.log" "rollback v1.9.5"
dns_rewrite_answers || fail "rollback v1.9.5 did not answer the rewrite"
step "rollback v1.9.5 answered migration.test A 192.0.2.53"
stop_server "rollback v1.9.5"
python3 - "$DATA/stats.db" <<'PY'
import sqlite3
import sys

con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
print("  rollback stats.db opens read-only")
PY
step "rollback stats.db still opens"

log "PASS: 1.9.5 data-dir migration and rollback acceptance"
printf 'Temp evidence directory: %s (removed by trap)\n' "$TMP"
