# SSO login

**Status:** approved
**Date:** 2026-05-06
**Scope:** add OIDC single sign-on as a third login method alongside username/password and access token, end-to-end (backend OIDC flow + login page UI).

## Summary

The login modal today shows two methods: `Username` and `Token`. Add a third method, `Sign in with SSO`, that is visible only when an admin has configured SSO. Implement the OIDC authorization-code-with-PKCE flow that backs the button. Link an SSO identity to an existing Gatehouse user account by IdP-verified email. No auto-provisioning. No claim-to-policy mapping. No SAML.

## Goals

- Admin enables SSO once (via the existing Settings UI). End users see a `Sign in with SSO` button on the login page.
- One click takes the user to the IdP, then back to Gatehouse, then into the app, with a Gatehouse JWT identical in shape to the password-login JWT.
- The login flow remains usable for non-SSO users (password and token tabs unchanged).
- Existing users on a fresh upgrade see no behavior change until SSO is configured.

## Non-goals

- Group/role mapping from IdP claims (conflicts with explicit policy authoring).
- Auto-provisioning new users on first SSO login.
- Multi-IdP per Gatehouse instance.
- SAML.
- RP-initiated logout.
- OIDC refresh tokens (24h JWT TTL with re-login matches existing posture).

## Decisions

| Question | Decision | Rationale |
|---|---|---|
| Protocol | OIDC only | Existing settings schema (`issuer`, `scopes: openid profile email`) already implies OIDC. SAML adds large surface for unclear homelab benefit. |
| Account model | Strict link-only by IdP-verified email | Matches the project's "no auto-grants" preference. A misconfigured IdP cannot mint privileged accounts. |
| `email_verified` enforcement | Required `true` from IdP | Free signal; rejects IdPs that let users self-attest emails. |
| `users.email` requirement | Must be non-NULL for SSO to link | Existing column. Admins populate as they roll SSO out. Users without email keep using password/token. |
| Source of truth for SSO config | DB `settings/sso` row | Admin owns the toggle from the UI. Env vars (`GATEHOUSE_OAUTH_*`) seed the DB row on first boot if no row exists, then are ignored. |
| TOTP interaction | SSO bypasses local TOTP | IdP is the identity authority and enforces its own MFA. |
| IP allowlist | None (matches existing user login) | The `users` table has no `ip_allowlist` column. IP allowlists exist only for AppRoles today. SSO matches password-login behavior. A user-level IP allowlist is a separate future feature. |
| Logout | Local-only (clear JWT) | RP-initiated logout is rarely what users want for a homelab vault. |
| Login modal layout | SSO button on top, then divider, then existing tabs | SSO is one click vs typing creds; admins enable it because they want it used. |
| OIDC client library | `oauth4webapi` | Web-API native, fits Bun/Hono posture, small enough to audit. |

## Architecture

```
Browser                          Gatehouse                         IdP
   │                                 │                              │
   │ GET /                           │                              │
   │ ──────────────────────────────► │                              │
   │ ◄────────── login page ──────── │                              │
   │ GET /v1/auth/sso/status         │                              │
   │ ──────────────────────────────► │                              │
   │ ◄────── { enabled: true } ───── │                              │
   │  [render SSO button]            │                              │
   │ click → GET /v1/auth/sso/start  │                              │
   │ ──────────────────────────────► │                              │
   │                                 │ persist state+nonce+pkce     │
   │                                 │ build auth URL               │
   │ ◄── 302 to IdP authorize ────── │                              │
   │ ──────────────────────────────────────────────────────────────►│
   │                       [user signs in at IdP]                   │
   │ ◄────────────── 302 to /v1/auth/sso/callback?code=…&state=… ──│
   │ ──────────────────────────────► │                              │
   │                                 │ load+delete state row        │
   │                                 │ exchange code (PKCE)         │
   │                                 │ ───────────────────────────► │
   │                                 │ ◄── id_token + access_token ─│
   │                                 │ verify id_token (jwks+nonce) │
   │                                 │ fetch userinfo               │
   │                                 │ ───────────────────────────► │
   │                                 │ ◄── claims (email, etc.) ────│
   │                                 │ link by verified email       │
   │                                 │ mint Gatehouse JWT           │
   │ ◄── 302 to /#sso=<jwt> ──────── │                              │
   │ [SPA reads fragment, stores JWT, enters app]                   │
```

## Components

### `src/auth/oidc.ts` (new)

Pure functions wrapping `oauth4webapi`. No Hono coupling. Caller passes the SSO config; functions return values.

- `getDiscovery(issuer)`: fetches and caches `<issuer>/.well-known/openid-configuration`. TTL 1 hour.
- `getJwks(jwksUri)`: fetches and caches JWKS. Honors HTTP cache headers with a 5-minute floor; re-fetches on `kid` miss.
- `buildAuthUrl({ config, state, nonce, codeVerifier })`: returns the IdP authorization URL. Always sets `response_type=code`, `code_challenge_method=S256`.
- `exchangeCode({ config, code, codeVerifier })`: POSTs to the token endpoint. Returns `{ idToken, accessToken }`.
- `verifyIdToken({ config, idToken, expectedNonce })`: verifies signature, `iss`, `aud`, `exp`, `nonce`. Returns claims.
- `fetchUserinfo({ config, accessToken })`: GETs userinfo, returns claims.

### `src/api/auth.ts` (extend)

Three new routes inside the existing `authRouter` (mounted at `/v1/auth`, pre-auth-middleware).

#### `GET /v1/auth/sso/status` (public)

Returns `{ "enabled": boolean }`. `enabled` is `true` iff the `settings/sso` row has `enabled === true && issuer && client_id`. No other fields returned. Rate-limited identically to `/v1/auth/login`.

#### `GET /v1/auth/sso/start` (public)

1. Load `settings/sso`. If not enabled, return 404.
2. Generate `state`, `nonce`, `code_verifier` (32 bytes each, base64url).
3. Insert into `sso_login_state`.
4. Build authorization URL via `oauth4webapi`.
5. Return 302 to the authorization URL.

Audit event: `sso.start`.

#### `GET /v1/auth/sso/callback` (public)

1. Read `state` and `code` from query string. If state row missing or older than 10 minutes, render error page (audit `sso.callback.invalid_state`).
2. Delete the state row (one-shot; replays of the same state fail step 1).
3. Exchange `code` for tokens with the stored PKCE verifier. On failure, render error page (audit `sso.callback.exchange_failed`).
4. Verify ID token: signature against cached JWKS, `iss`, `aud`, `exp`, `nonce`. On failure, audit `sso.callback.exchange_failed`, render error page.
5. Fetch userinfo using the access token. Read `email` and `email_verified`. Fall back to ID token claims if userinfo omits them.
6. If `email_verified !== true`, audit `sso.callback.unverified_email`, render error page.
7. `SELECT username FROM users WHERE email = ? AND enabled = 1`.
   - 0 rows: audit `sso.callback.no_user_match`, render error page.
   - >1 row: audit `sso.callback.email_collision`, render error page.
8. Mint a Gatehouse JWT identical in shape to the password-login JWT: `sub: user:<username>`, `policies: ["admin"]`, 24h TTL. No `ip_allowlist` claim (matches existing user login). No TOTP step regardless of `totp_enabled`.
9. Update `users.last_login`. Audit `sso.callback.success`.
10. Return 302 to `/#sso=<jwt>`. URL fragment, not query string, so the JWT does not appear in `Referer` headers or server access logs.

### `src/api/auth.ts` settings extension

`POST /v1/settings/sso` (existing handler) gains a one-shot validation: when `enabled: true` and a non-empty `issuer` is supplied, fetch `<issuer>/.well-known/openid-configuration` and confirm the response is JSON containing `authorization_endpoint`, `token_endpoint`, `jwks_uri`. If discovery fails, return 400 with the upstream error and do not write the row.

### `src/db/init.ts` (extend)

Add one new table. No `ALTER`. No column adds.

```sql
CREATE TABLE IF NOT EXISTS sso_login_state (
  state          TEXT PRIMARY KEY,
  nonce          TEXT NOT NULL,
  code_verifier  TEXT NOT NULL,
  created_at     INTEGER NOT NULL  -- unix seconds
);
CREATE INDEX IF NOT EXISTS idx_sso_login_state_created_at
  ON sso_login_state(created_at);
```

### Lease reaper (existing): extend

The lease reaper that runs every 30 seconds also deletes `sso_login_state` rows older than 10 minutes. One additional `DELETE` statement.

### `src/config.ts` and boot sequence

Remove the `oauth?` field from `GatehouseConfig`. On boot, if `process.env.GATEHOUSE_OAUTH_ISSUER` is set AND `settings/sso` row does not exist, insert a row:

```js
{
  enabled: true,
  issuer: process.env.GATEHOUSE_OAUTH_ISSUER,
  client_id: process.env.GATEHOUSE_OAUTH_CLIENT_ID || "",
  client_secret: process.env.GATEHOUSE_OAUTH_CLIENT_SECRET || "",
  redirect_uri: process.env.GATEHOUSE_OAUTH_REDIRECT_URI || "",
  scopes: "openid profile email",
}
```

After boot, env vars are not consulted. Update `/v1/config` so its `oauth_enabled` and `oauth_issuer` fields read from the DB row instead of `config.oauth`. Field shape preserved so the existing settings-page badge keeps working.

### `src/ui/index.html` (extend)

Two markup additions inside `#login-screen`, just before the existing `.login-tabs`:

```html
<button id="login-sso-btn" class="btn btn-primary login-btn-full hidden"
        onclick="doSSOLogin()">
  Sign in with SSO
</button>
<div id="login-sso-divider" class="login-divider hidden">or</div>
```

The existing `.login-divider` style is reused.

JS additions:

```js
async function initLoginScreen() {
  try {
    const res = await fetch('/v1/auth/sso/status');
    if (res.ok && (await res.json()).enabled) {
      document.getElementById('login-sso-btn').classList.remove('hidden');
      document.getElementById('login-sso-divider').classList.remove('hidden');
    }
  } catch { /* ignore - SSO stays hidden */ }

  const m = location.hash.match(/^#sso=([^&]+)/);
  if (m) {
    const jwt = decodeURIComponent(m[1]);
    history.replaceState(null, '', location.pathname);
    completeLogin(jwt);
  }
}

function doSSOLogin() {
  window.location.href = '/v1/auth/sso/start';
}
```

`initLoginScreen()` is called once on page load alongside the existing init code.

The tail of the existing `doLogin()` (store JWT, hide login, show app) is extracted into `completeLogin(jwt)` so password-login and SSO-callback share one path. No behavior change to password login.

The Settings page SSO card gains a "Test SSO" link that opens `/v1/auth/sso/start` in a new tab. Validation errors from the save endpoint surface via the existing `toast()` helper.

## Error handling

Callback runs in a browser navigation context. Render minimal HTML error pages (no external assets). Each page includes a short message, a "Back to login" link, and the `request_id` in small text.

| Failure | User-visible message | Audit event |
|---|---|---|
| state row missing/expired/reused | "Login link expired. Please try again." | `sso.callback.invalid_state` |
| code exchange fails | "Sign-in failed. Please try again." | `sso.callback.exchange_failed` |
| ID token verification fails | "Sign-in failed. Please try again." | `sso.callback.exchange_failed` |
| `email_verified !== true` | "Your identity provider didn't confirm your email. Contact your admin." | `sso.callback.unverified_email` |
| no matching user, user disabled, or multiple matches | "No Gatehouse account is linked to this identity." | `sso.callback.no_user_match` or `sso.callback.email_collision` |

The "no matching user" message intentionally collapses three cases into one user-visible string. Admins distinguish via the audit log; users get no enumeration oracle.

## Edge cases

- **Concurrent flows from one browser**: each `/start` mints its own state row. Callbacks consume their specific row independently.
- **Discovery / JWKS / userinfo network failures**: treated as `exchange_failed` (vague message). Audit log captures the upstream URL and HTTP status.
- **JWKS rotation during a request**: `oauth4webapi` re-fetches JWKS on `kid` miss; cached result is used otherwise.
- **Admin disables SSO mid-flow**: `/callback` does not re-check `enabled`. A flow that started with valid config completes. New `/start` calls reject.
- **Admin changes `client_id` mid-flow**: ID token `aud` will not match new `client_id`, verification fails, user retries with fresh config.
- **User has password, TOTP, and SSO**: each method works independently. No cross-method constraints.
- **User row deleted while a JWT is live**: existing `authMiddleware` re-checks the user row on every request. Deleted/disabled users are rejected immediately regardless of how the JWT was minted.
- **`email` populated after the fact**: no migration needed. SSO link works on next attempt.
- **Onboarding / rotate / approle / MCP flows**: untouched. SSO is human-account only.

## Database scope

| Object | Change | Existing-user impact |
|---|---|---|
| `sso_login_state` (new) | `CREATE TABLE IF NOT EXISTS`; 4 columns; ephemeral data. | None. |
| Index `idx_sso_login_state_created_at` | `CREATE INDEX IF NOT EXISTS` | None. |
| `users.email` | No change. Column already in original `CREATE TABLE`. | None. |
| `settings` | No schema change. Existing `sso` row format kept. | None. |

Zero `ALTER`, zero column additions, zero data migrations. Pure additive.

## Upgrade path

Standard `docker compose pull && docker compose up -d`. The `gatehouse-data` named volume preserves the SQLite file across container replacement. `initDB()` runs on container start and creates the new table if absent. The env-var seeding step runs once after `initDB()` to populate `settings/sso` if the user previously set `GATEHOUSE_OAUTH_*` env vars.

Rollback: `docker compose up -d` with the previous tag. The orphan `sso_login_state` table is harmless to the older binary.

Release-note item: existing users with `email = NULL` who want to use SSO must have their email populated by an admin before their first SSO attempt.

## Audit events added

`sso.start`, `sso.callback.success`, `sso.callback.exchange_failed`, `sso.callback.invalid_state`, `sso.callback.unverified_email`, `sso.callback.no_user_match`, `sso.callback.email_collision`.

## Testing

The codebase favors integration tests with real dependencies. SSO follows that posture: a tiny in-process fake IdP, run alongside the real Hono app and a real `:memory:` SQLite.

### Test infrastructure

`test/helpers/fake-oidc.ts` exposes a Hono sub-app implementing the four endpoints we touch: discovery, JWKS, token, userinfo. A keypair is generated at test setup; ID tokens are signed with it via `jose`. Helper methods: `setIdpUser({ email, email_verified, sub })`, `simulateUserConsent()`. The fake mounts on a random port; the test points the `settings/sso` row at it.

### Unit tests (`test/auth.oidc.test.ts`)

- Discovery cache: hits network once; second call is cached; expires after TTL.
- JWKS cache: same caching behavior; `kid` miss triggers re-fetch.
- ID token verification: rejects bad signature, bad `iss`, bad `aud`, expired `exp`, mismatched `nonce`.
- Authorization URL build: includes `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`, configured scopes.

### Integration tests (`test/auth.sso.test.ts`)

Each test runs `/start` through `/callback` against the fake IdP.

Happy path:
- Admin saves SSO settings; `/v1/auth/sso/status` returns `{enabled: true}`.
- `/start` 302s to the fake IdP with valid params; state row exists.
- Callback completes; JWT works against `/v1/secrets/...`; state row is deleted; `users.last_login` is updated; audit log contains `sso.callback.success`.

Failure paths (one test each, asserts user-visible message and audit event):
- State row missing → `invalid_state`
- State expired → `invalid_state`
- State reused → second call gets `invalid_state`
- Code exchange returns 400 → `exchange_failed`
- ID token signed with wrong key → `exchange_failed`
- ID token has wrong `aud` → `exchange_failed`
- Nonce mismatch → `exchange_failed`
- `email_verified: false` → `unverified_email`
- `email_verified` claim absent → `unverified_email`
- Email not in `users` → `no_user_match`
- Email matches `enabled = 0` user → `no_user_match`
- Email matches multiple users → `email_collision`

State management:
- Two parallel `/start` calls produce two distinct state rows; each completes independently.
- Reaper deletes rows older than 10 minutes, keeps newer ones.

Settings validation:
- `POST /v1/settings/sso` with `enabled: true` and a bad issuer → 400, no row written.
- Same call with reachable issuer → 200, row written.

Bootstrap / migration:
- Boot with `GATEHOUSE_OAUTH_*` and no `settings/sso` row → row written with `enabled: true`.
- Boot with env vars AND existing row → row not overwritten.
- Boot without env vars and without row → no row, no error.

### Frontend

Manual verification during implementation: SSO button hidden when `/status` returns `{enabled: false}`; visible when `{enabled: true}`; click navigates to IdP; callback fragment lands the user in the app.

### Coverage gate

Every audit event listed above corresponds to at least one integration test. Every error message in the table corresponds to at least one assertion. Paths without tests do not ship.
