# User Management, Roles, and API Tokens

sito keeps its accounts in `<data_dir>/users.toml` (mode `0600`) and has no
self-registration or e-mail-based password reset. Accounts, roles, and API
tokens can be managed from the web panel (`/users` and `/account`) or through
the administrative REST API under `/api/v1/auth/*`. TOTP status and disabling
are available in the web UI; TOTP enrollment/setup remains API-only.

## Web UI

The embedded web panel provides the common account workflows without `curl`.
Navigation links are role-aware: **Users** is shown only to Admins and
**Account** is shown to every signed-in user.

| Page | Who can open it | What it does |
|---|---|---|
| `/users` | Admin only | Lists local accounts with role and TOTP status; creates accounts; changes roles; deletes accounts with last-admin protection. |
| `/account` | Any authenticated user | Shows profile and TOTP status; changes the caller's own password; creates, lists, and revokes the caller's own API tokens; disables the caller's own TOTP. |

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
- **TOTP.** The Account page can disable TOTP after re-authentication with the
  current password and a valid TOTP or backup code. Initial TOTP setup/enable
  remains an API workflow (section 7).
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
   the setup wizard at `/wizard` (or, for headless installs, by
   `sito --no-setup`, which generates a random password and binds the panel to
   loopback). The bootstrap account is named `admin`.
2. **Create** additional accounts with `POST /api/v1/auth/users` or the Admin
   **Users** page at `/users`.
3. **Operate.** Users sign in at `/login` (session cookie) or authenticate with
   an API token (`Authorization: Bearer ...`).
4. **Delete** an account with `DELETE /api/v1/auth/users/{username}` or the
   **Users** page. Sessions and every API token owned by that account are
   revoked immediately. Legacy ownerless tokens are not tied to an account and
   remain Admin-managed until explicitly revoked.
5. **Recover.** If credentials are lost, an operator with shell access can run
   `sito reset-admin --config /etc/sito/config.toml --password '<new-password>'`.
   This recreates the `admin` account and invalidates **all** sessions and
   tokens by rotating the auth generation.

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
Password changes and TOTP changes revoke sessions but do not revoke API tokens.

## 4. Change a Role

```bash
curl -sS -X PUT "$SITO/api/v1/auth/users/alice" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role":"viewer"}'
```

A role change revokes all sessions belonging to the target account so the new
role is enforced on the next request. Demoting the last admin is rejected with
`400 Bad Request`.

Role demotion does **not** rewrite the scope of API tokens the account already
created. A token keeps its original scope until it is revoked or reissued.
After demoting an account, review and revoke/reissue its tokens if the old
scope is no longer appropriate.

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
revokes all sessions of the target account, including the caller's own session
when changing your own password.

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

When the global token cap (`MAX_API_TOKENS`, currently 256) is reached, creating
another token evicts only the oldest token owned by the same account. If that
account has no token to evict, creation fails with `400 Bad Request` instead of
deleting another account's credential. A role demotion does not change the
scope of existing tokens; revoke or reissue them when the old scope is no longer
appropriate.

Deleting the owning account revokes its tokens immediately. Legacy ownerless
tokens survive account deletion and must be revoked explicitly by an Admin.

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

Revocation takes effect immediately. To invalidate every session and token at
once, run `sito reset-sessions --config /etc/sito/config.toml` (or
`sito reset-admin`), which also rotates the auth generation so copies of the
deleted stores cannot be replayed.

Tokens authenticate API requests and count as their configured scope. They
cannot change passwords or manage TOTP; those operations require a real user
session.

## 7. TOTP Two-Factor Authentication

TOTP is per-account and managed by the signed-in user. Initial setup/enable is
an API workflow (Admin session required by the current API guards); the
**Account** page at `/account` can show the current status and disable TOTP.

1. Start setup:

   ```bash
   curl -sS -H "Cookie: sito_session=<session-id>" \
     "$SITO/api/v1/auth/totp/setup"
   ```

   The response contains the Base32 secret, an `otpauth://` URI, a QR-code data
   URL for authenticator apps, and single-use backup codes. The pending setup
   expires after 10 minutes.

2. Confirm with a current code (or a backup code):

   ```bash
   curl -sS -X POST "$SITO/api/v1/auth/totp/enable" \
     -H "Cookie: sito_session=<session-id>" \
     -H 'Content-Type: application/json' \
     -d '{"code":"123456"}'
   ```

3. Subsequent logins return `200 OK` with `"totp_required": true` and a
   short-lived partial token. Browser clients receive it as an HttpOnly cookie;
   API clients can send `X-Sito-Token-Delivery: body` to receive it in the JSON
   response. Finish the login with `POST /api/v1/auth/totp/verify`. Partial
   tokens expire after 5 minutes and allow at most 5 wrong codes before the
   account is locked.

4. Disable TOTP by re-authenticating with the password and a valid TOTP or
   backup code:

   ```bash
   curl -sS -X POST "$SITO/api/v1/auth/totp/disable" \
     -H "Cookie: sito_session=<session-id>" \
     -H 'Content-Type: application/json' \
     -d '{"password":"NewCorrectHorse2","code":"123456"}'
   ```

Enabling or disabling TOTP revokes all sessions of the account.

TOTP secrets are encrypted at rest with AES-256-GCM using
`<data_dir>/totp.key`. Back up `users.toml` and `totp.key` together: restoring
only one is a lockout, and the server refuses to start when the key is missing
or does not match the stored secrets. `sito reset-admin` is the documented
recovery path.

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
  locked for 15 minutes.
* Expired tokens are rejected immediately and removed from memory; their
  on-disk snapshot is rewritten by the background pruner within 60 seconds.

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
