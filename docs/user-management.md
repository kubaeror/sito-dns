# User Management, Roles, and API Tokens

sito keeps its accounts in `<data_dir>/users.toml` (mode `0600`) and has no
self-registration or e-mail-based password reset. Accounts, roles, and API
tokens can be managed from the web panel (`/users` and `/account`) or through
the administrative REST API under `/api/v1/auth/*`. TOTP enrollment, replacement,
and disabling are available to every role from the Account page and the REST
API.

## Web UI

The embedded web panel provides the common account workflows without `curl`.
Navigation links are role-aware: **Users** is shown only to Admins and
**Account** is shown to every signed-in user.

| Page | Who can open it | What it does |
|---|---|---|
| `/users` | Admin only | Lists local accounts with role and TOTP status; creates accounts; changes roles; deletes accounts with last-admin protection. |
| `/account` | Any authenticated user | Shows profile and TOTP status; changes the caller's own password; creates, lists, and revokes the caller's own API tokens; enrolls, replaces, and disables the caller's own TOTP after re-authentication. |

- **Visibility.** Operators and Viewers receive `403 Forbidden` from `/users`.
  Anonymous requests to either page redirect to `/login`.
- **Token visibility.** `/account` lists only tokens owned by the signed-in
  account. Admins additionally see legacy ownerless tokens and an Owner column;
  non-Admins cannot see those tokens. Token creation is capped at the caller's
  role, so a Viewer cannot mint an Operator or Admin token.
- **CSRF/RBAC.** Every mutating form includes a session-bound CSRF token and is
  rejected with `403` when the token is missing or wrong. Role checks are
  enforced server-side, not just by hiding navigation links.
- **Flows.** Successful mutations redirect (POST/Redirect/GET) back to the page;
  validation failures re-render the page with a visible error. Password changes
  and TOTP disable revoke all sessions for the account, so they return to
  `/login`. A newly created token's plaintext is shown exactly once; reloading
  `/account` never reveals it again.
- **TOTP.** The Account page can enroll, replace, and disable TOTP after
  re-authentication with the current password and a valid TOTP or backup code.
  The same workflows are available through the REST API (section 7).
- The **Clients** page shows the operator-only “Discovered but unidentified”
  table, matching `GET /api/v1/clients/unidentified`. Viewers see only the
  configured clients.

All examples below use the REST API:

```bash
export SITO=http://127.0.0.1:8080
export TOKEN='sito_...'   # an Admin API token, or use a session cookie instead
```

## 1. Account Lifecycle

1. **Bootstrap.** On a fresh installation the first administrator is created by
   the setup wizard at `/wizard`. For headless installs with no `config.toml`,
   `sito --no-setup` generates a random password, prints it once, and binds the
   panel to loopback. When a config file already exists, `--no-setup` neither
   creates nor rotates credentials. The bootstrap account is named `admin`.
   While the first-boot setup token is active, or `admin/adminadmin` is still the
   stored bootstrap credential, login, `/api/v1/auth/*`, API tokens and every
   non-wizard routes are disabled. Only `/wizard`, `/ui/wizard/*`, static assets,
   `/health` and `/status` are reachable; the wizard requires the one-time token
   printed in the server logs. The wizard is bootstrap-only and returns `403`
   after setup completes, even for an Admin session; use the authenticated
   account flow for later password changes.
2. **Create** additional accounts with `POST /api/v1/auth/users` or the Admin
   **Users** page at `/users`.
3. **Operate.** Users sign in at `/login` (session cookie) or authenticate with
   an API token (`Authorization: Bearer ...`).
4. **Delete** an account with `DELETE /api/v1/auth/users/{username}` or the
   **Users** page. Sessions and every API token owned by that account are
   revoked immediately. Legacy ownerless tokens are not tied to an account and
   remain Admin-managed until explicitly revoked.
5. **Recover.** If credentials are lost, an operator with shell access must
   stop the service first, then reset the admin account and start it again:

   ```bash
   sudo systemctl stop sito
   sudo sito reset-admin --config /etc/sito/config.toml --password '<new-password>'
   sudo systemctl start sito
   ```

   Supplied passwords must meet the same policy as the API and wizard (at least
   8 characters, no whitespace or control characters, and not `adminadmin`). If
   `--password` is omitted, a 192-bit random password is generated and printed
   exactly once. The reset preserves every non-admin account and invalidates
   **all** persisted sessions and tokens by rotating the auth generation. Add
   `--reset-all` (alias `--reset-users`) only when a full account-store
   replacement is intended; a corrupt `users.toml` requires that explicit
   option.

   `reset-admin` and `reset-sessions` detect the running server through the
   service lease at `<data_dir>/sito.pid` and **refuse to run while it is
   active**, because the process keeps users, sessions, tokens and the auth
   generation in memory. Stopping the service is therefore part of the recovery
   procedure, not an optional step. `--force` overrides the refusal but only
   changes the files on disk: existing sessions/API tokens remain valid and the
   new admin password is not accepted until the service is restarted. Use
   `--force` only when you deliberately want the on-disk state prepared for a
   restart that will happen immediately afterwards. In a container, stop the
   container instead of using `systemctl`.

Account data never leaves the node: `users.toml` is not replicated by HA and
must be backed up together with `<data_dir>/totp.key` (see
[configuration-reference.md](configuration-reference.md)).

## 2. Roles and RBAC

Three hierarchical roles exist; each role includes everything the role below it
can do:

| Role | Typical use | Capabilities |
|---|---|---|
| `viewer` | Dashboards, read-only integrations | Read status, statistics, query log, clients, rewrites, and filter rules |
| `operator` | Daily DNS administration | Viewer capabilities plus cache invalidation/flush, filter-list refreshes, client/rewrite/upstream changes |
| `admin` | Full control | Operator capabilities plus configuration access, HA operations, update apply, user/token/TOTP management, and password overrides |

Role checks are enforced by the API extractors (`RequireViewer`,
`RequireOperator`, `RequireAdmin`). An API token carries its own scope, which is
treated as that token's role. A role change applies to future requests
immediately and revokes all existing sessions of the affected account.

## 3. Create, List, and Delete Accounts

Requires an Admin session or an Admin-scoped API token.

List accounts (never includes password hashes or TOTP secrets):

```bash
curl -sS -H "Authorization: Bearer $TOKEN" "$SITO/api/v1/auth/users"
```

Create an account:

```bash
curl -sS -X POST "$SITO/api/v1/auth/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"CorrectHorse1","role":"operator"}'
```

Rules enforced by the API:

* Usernames: 1–64 characters, no whitespace or control characters, and none of
  `:`, `/`, `\`. Usernames are case-sensitive.
* Passwords: at least 8 characters, at most 1024, no whitespace or control
  characters, and not the bootstrap password `adminadmin`.
* Roles: `viewer`, `operator`, or `admin` (case-insensitive).
* Creating a username that already exists returns `409 Conflict`.

Delete an account:

```bash
curl -sS -X DELETE -H "Authorization: Bearer $TOKEN" \
  "$SITO/api/v1/auth/users/alice"
```

The last remaining `admin` account cannot be deleted (or demoted); the API
returns `400 Bad Request`. Create or promote another admin first. This guard
prevents locking every administrator out of the API and UI.

Deleting an account revokes that account's sessions **and every API token it
owns**. Tokens created before ownership tracking (ownerless/legacy tokens) are
not linked to an account, so they survive account deletion and remain
Admin-managed; revoke them explicitly if they were issued to the deleted user.

Password changes, TOTP enable/disable, role changes, and overwriting/recreating
an account also revoke **all API tokens owned by that account**: a credential
must not outlive the password, second factor, or privileges it was issued
under.
Legacy ownerless tokens are never matched by these revocations and remain
Admin-managed until explicitly revoked.

## 4. Change a Role

```bash
curl -sS -X PUT "$SITO/api/v1/auth/users/alice" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role":"viewer"}'
```

A role change revokes all sessions belonging to the target account **and all
API tokens it owns**, so the new role (and the loss of old privileges) is
enforced on the next request. Demoting the last admin is rejected with
`400 Bad Request`.

Because promotion and demotion both revoke owned tokens, the account must
create fresh tokens after a role change. This prevents an old Admin-scoped
token from surviving a demotion. The last-admin check and the role update are
atomic, so two concurrent demotions cannot both succeed and leave the
deployment without an Admin.

### Credential epochs and upgrade re-login

Every account carries a persisted `credential_epoch` in `users.toml`. Sessions
and API tokens record the account and role they were issued under together with
that epoch, and every request re-checks the user table: the account must still
exist, its role must be unchanged, and the epoch must be current. Password
changes, role changes, TOTP enable/disable, deletion/recreation and
`reset-admin` advance the epoch. A login or TOTP verification that raced one of
those mutations is refused instead of creating a session with the old role or
for a deleted account; an interrupted revocation is re-checked after a restart.

Sessions and tokens persisted by an older release have no epoch. They are
rejected once after upgrading, so every user must sign in again and every API
token must be re-issued. Plan the upgrade accordingly; no data is lost, but old
credentials stop working immediately.

Credential writes are fail-closed. If `users.toml` cannot be written, creating
an account, changing a password or role, enabling/disabling TOTP, deleting an
account or running `reset-admin` returns an error (`500 Internal Server Error`
through the API) and rolls the in-memory change back. The operation is never
reported as successful before it is durable.

## 5. Change a Password

Requires an authenticated **user session**. API tokens are rejected with
`403 Forbidden` so a leaked token cannot rotate an account password.

Self-service (current password required):

```bash
curl -sS -X POST "$SITO/api/v1/auth/change-password" \
  -H "Cookie: sito_session=<session-id>" \
  -H 'Content-Type: application/json' \
  -d '{"current_password":"CorrectHorse1","new_password":"NewCorrectHorse2"}'
```

Administrator override for another account (audited at `warn` level). This also
requires a user session; API tokens cannot change passwords:

```bash
curl -sS -X POST "$SITO/api/v1/auth/change-password" \
  -H "Cookie: sito_session=<admin-session-id>" \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","new_password":"NewCorrectHorse2"}'
```

The same password policy as account creation applies. A successful change
revokes all sessions **and all owned API tokens** of the target account,
including the caller's own session when changing your own password. Legacy
ownerless tokens are unaffected.

## 6. API Tokens

API tokens are long-lived credentials for scripts and integrations. Only a
Blake3 hash is stored in `<data_dir>/tokens.toml`; the plaintext value is
returned **once**, when the token is created. Each token records the account
that created it as its owner.

List token metadata (never the hash or plaintext):

```bash
curl -sS -H "Authorization: Bearer $TOKEN" "$SITO/api/v1/auth/tokens"
```

The REST listing is Admin-only and returns metadata for all tokens. The
`/account` page instead lists only the signed-in user's own tokens; Admins also
see legacy ownerless tokens there and get an Owner column. The owner is stored
internally and is not part of the REST response schema.

Create a token:

```bash
curl -sS -X POST "$SITO/api/v1/auth/tokens" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"grafana","scope":"viewer"}'
```

The response contains `id`, `name`, `scope`, and the plaintext `token`
(`sito_...`). Store it in a secret manager; it cannot be retrieved again.
New tokens expire after `auth.token_default_ttl_days` (default 90 days, `0`
disables expiry).

Tokens created from an Admin session or from `/account` are owned by that
account. Tokens created with a bearer credential inherit the owner of the
authenticating token. Tokens written by older releases have no owner; they are
legacy/ownerless and remain Admin-managed.

A single account may hold at most **16 tokens**
(`MAX_API_TOKENS_PER_OWNER`). The limit is enforced when tokens are created:
creating a 17th token evicts that account's oldest token; another account's
tokens are never touched. A `tokens.toml` written before this quota existed may
temporarily contain more than 16 tokens for one owner; that owner's next create
trims the excess down to 16. Independently, the global store is capped at
**256 tokens** (`MAX_API_TOKENS`). When the global cap is
reached, creating another token evicts only the oldest token owned by the same
account. If that account has no token to evict, creation fails with
`400 Bad Request` instead of deleting another account's credential. Legacy
ownerless tokens are not an owner: they rely on the global cap and remain
Admin-managed.

API tokens are revoked automatically by:

* an account password change (self-service or Admin override);
* enabling or disabling TOTP for the account;
* any role change (promotion or demotion);
* overwriting/recreating the account (for example via the setup wizard or CLI);
* deleting the account.

The revocation is immediate in memory and persisted to `tokens.toml`; the
account must create a new token afterwards. Because a role change revokes its
tokens, an old token can never retain privileges the account no longer has.

Use a token as a Bearer credential:

```bash
curl -sS -H "Authorization: Bearer sito_..." "$SITO/api/v1/status"
```

Revoke a token by ID:

```bash
curl -sS -X DELETE -H "Authorization: Bearer $TOKEN" \
  "$SITO/api/v1/auth/tokens/<token-id>"
```

The REST revoke endpoint is Admin-only. On `/account`, a user may revoke only
their own tokens (Admins may also revoke legacy ownerless tokens); another
user's token ID returns `404`, indistinguishable from a missing token.

Revocation takes effect immediately. To invalidate every persisted session and
token at once, stop the service, run
`sito reset-sessions --config /etc/sito/config.toml` (or `sito reset-admin`),
then start it again. The reset rotates the auth generation so copies of the
deleted stores cannot be replayed. It refuses to run while the server is
running: an in-memory session or token would stay valid until restart, so
claiming otherwise would be false. `--force` performs the on-disk reset anyway
and prints a warning that the restart is required to revoke live credentials.

Tokens authenticate API requests and count as their configured scope. They
cannot change passwords or manage TOTP; those operations require a real user
session.

## 7. TOTP Two-Factor Authentication

TOTP is per-account and self-service for every role (Viewer, Operator, and
Admin). The **Account** page at `/account` provides a password-confirmed
enrollment flow (QR code, secret, and one-time backup codes); the REST API can
be used instead. API bearer tokens cannot manage TOTP — a real user session is
required.

1. Re-authenticate for a short-lived ticket (5 minutes). The current password is
   required; when TOTP is already enabled, a current TOTP or backup code is
   required too:

   ```bash
   curl -sS -X POST "$SITO/api/v1/auth/reauth" \
     -H "Cookie: sito_session=<session-id>" \
     -H 'Content-Type: application/json' \
     -d '{"password":"NewCorrectHorse2","code":"123456"}'
   ```

   The response contains `reauth_token` and `expires_in`. The ticket is bound to
   the session and credential state that requested it.

2. Start setup with the ticket in `X-Reauth-Token`:

   ```bash
   curl -sS -H "Cookie: sito_session=<session-id>" \
     -H "X-Reauth-Token: <reauth-token>" \
     "$SITO/api/v1/auth/totp/setup"
   ```

   The response contains the Base32 secret, an `otpauth://` URI, a QR-code data
   URL for authenticator apps, and single-use backup codes. The pending setup
   expires after 10 minutes.

3. Confirm with a current code (or a backup code) and the same ticket:

   ```bash
   curl -sS -X POST "$SITO/api/v1/auth/totp/enable" \
     -H "Cookie: sito_session=<session-id>" \
     -H "X-Reauth-Token: <reauth-token>" \
     -H 'Content-Type: application/json' \
     -d '{"code":"123456"}'
   ```

   An absent, expired, or differently-bound ticket returns `401`. Replacing an
   existing authenticator requires a fresh re-auth that proves the current
   password and second factor.

4. Subsequent logins return `202 Accepted` with `"totp_required": true` and a
   short-lived partial token. Browser clients receive it as an HttpOnly cookie;
   API clients can send `X-Sito-Token-Delivery: body` to receive it in the JSON
   response. Finish the login with `POST /api/v1/auth/totp/verify`. Partial
   tokens expire after 5 minutes and allow at most 5 wrong codes before the
   account is locked.

5. Disable TOTP with a fresh re-authentication ticket (the same
   password + current TOTP/backup-code proof as step 1):

   ```bash
   curl -sS -X POST "$SITO/api/v1/auth/totp/disable" \
     -H "Cookie: sito_session=<session-id>" \
     -H "X-Reauth-Token: <reauth-token>" \
     -H 'Content-Type: application/json' \
     -d '{"password":"NewCorrectHorse2","code":"123456"}'
   ```

   The body credentials are retained for compatibility but are not trusted; the
   re-authentication ticket is what authorizes the change. An absent, expired,
   or differently-bound ticket returns `401`.

Enabling or disabling TOTP revokes all sessions of the account **and every API
token it owns**, because either change to the second factor is a credential
change. Scripts that authenticated with an owned token must create a new token
after enabling 2FA. Legacy ownerless tokens are not matched and remain
Admin-managed.

TOTP secrets are encrypted at rest with AES-256-GCM using
`<data_dir>/totp.key`. Back up `users.toml` and `totp.key` together: restoring
only one is a lockout, and the server refuses to start when the key is missing
or does not match the stored secrets. Stop the service before running the
documented `sito reset-admin` recovery path so the new credentials are loaded
on the next start (see section 1).

## 8. Sessions and Lockout

* Sessions are `HttpOnly` cookies valid for `auth.session_ttl_hours` (default
  24). The cookie is named `sito_session`, or `__Host-sito_session` when the
  admin panel is served over HTTPS. `POST /api/v1/auth/logout` revokes the
  current session.
* With `auth.session_persist = true` (default), sessions and tokens survive a
  restart until their TTL. The stores are mode `0600`; corrupt stores are backed
  up and start empty.
* Login attempts are rate-limited per IP (`auth.login_rate_limit`, default 5
  per minute). After five failed attempts for one account, that account is
  locked for 15 minutes. Usernames over 64 bytes and passwords over 1024 bytes
  are rejected before lockout bookkeeping or password hashing. Lockout keys are
  BLAKE3 digests (the raw username is never retained), and username spraying
  cannot evict an account whose lockout is still active.
* Expired tokens are rejected immediately and removed from memory; their
  on-disk snapshot is rewritten by the background pruner within 60 seconds.
* The legacy `?token=` query parameter is accepted only on a WebSocket upgrade
  with no `Authorization` header, logs a deprecation warning, and is scheduled
  for removal in 2.0. Use `Authorization: Bearer` or a session cookie.

## 9. Audit Trail

Role changes, account deletions, and administrator password overrides are logged
with the acting administrator and the target account. Secrets, password hashes,
TOTP secrets, and token plaintext are never intentionally logged. One exception
is a corrupt `users.toml` parse error: the TOML parser's diagnostic can include
the offending source line, so treat startup logs with the same care as the users
file itself (and never paste them into a public issue).

## See Also

* [Configuration reference](configuration-reference.md) — `[auth]` and `[web]`
  keys, `users.toml`/`totp.key` handling.
* [First-boot setup](../README.md#-first-time-setup-wizard) — initial admin and
  the setup wizard.
* [Security review](security-audit.md) — threat model and constant-time auth.
* Interactive API reference: `http://<host>:8080/api/docs`.
