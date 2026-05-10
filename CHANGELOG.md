# Changelog

All notable changes to Gatehouse are documented here. The auto-generated GitHub
release notes (built from conventional-commit subjects between tags) carry the
fine-grained per-commit log. This file summarises each release at a higher
level.

## [0.12.0] - 2026-05-09

### Added

- **Configurable proxy runtime limits.** The previously-hardcoded 120-second
  upstream timeout cap and 10 MiB upstream-response body cap are now editable
  from a new "Proxy Limits" card in the Settings UI. Useful when an agent
  legitimately needs to call a slow upstream (large file fetches, audio
  transcription, image generation) without raising every limit globally at
  the binary level.
- **New endpoints**: `GET /v1/settings/proxy-limits` and
  `POST /v1/settings/proxy-limits` (both admin-only). Body shape:
  `{"max_timeout_ms": 120000, "max_body_bytes": 10485760}`. Validation
  enforces a 1 second to 30 minute timeout range and a 1 KiB to 100 MiB body
  range; values outside the range are rejected with HTTP 400 plus an
  `errors[]` array.
- **Cache + audit.** Settings are cached in memory (the proxy is in the hot
  path); `setProxyLimits` invalidates on save. Every change writes a
  `settings.proxy_limits.update` audit row with old + new values as
  `metadata`.
- **Both proxy code paths honor the same setting.** Regression-guard tests
  assert that no `Math.min(..., 120_000)` cap remains in either
  `src/api/proxy.ts` (REST `/v1/proxy`) or `src/mcp/server.ts` (MCP
  `gatehouse_proxy` tool); both consult `getProxyLimits(db)` per request.

### Changed

- The web UI's `api()` helper now surfaces a server-returned `errors[]` array
  in the thrown error message (joined with `; `). Saving with an out-of-range
  value now shows the actual server validation message instead of `HTTP 400`.

### UI polish

- Removed up/down spinners from `<input type="number">` site-wide via
  `appearance: textfield`. Validation is explicit (min/max + JS check), so the
  spinners just added visual noise.
- Numeric settings inputs are now compact (140px) with a visible unit suffix
  (`seconds`, `MiB`) and right-aligned tabular numerals, instead of
  full-width text boxes with the unit baked into the label.
- Trust-email toggle in the SSO card no longer inherits the form-row grid's
  160px label column (was rendered slightly off from the other toggles).
- Inline form errors use the theme `--danger` / `--danger-subtle` variables
  so the alert state reads correctly in both dark and light themes.

### Database

- No schema changes. Settings persist in the existing `settings` table under
  key `proxy_limits`; the row is absent until first save and the proxy falls
  back to the original 120 s / 10 MiB defaults.

### Notes for upgrading

- Pure additive. No migration; no behavior change until an admin saves new
  values from the UI. Existing deployments continue to use the 120 s / 10 MiB
  defaults.

## [0.11.0] - 2026-05-06

### Added

- **OIDC single sign-on** for the web UI. The login modal now shows a
  `Sign in with SSO` button when an admin has configured SSO; the rest of the
  login screen (username + token tabs) still works for non-SSO users. New
  endpoints: `GET /v1/auth/sso/{status,start,callback}`.
- **Strict link-by-verified-email account model.** SSO callers must match an
  existing Gatehouse user by `email`. The IdP's `email_verified` claim must be
  `true` by default, with a per-deployment `trust_unverified_email` opt-in for
  IdPs (notably PocketID) that intentionally omit the claim because the email
  is administrator-controlled at the IdP.
- **Configure SSO from Settings.** New section in the SSO / OAuth Configuration
  card: enable toggle, issuer URL, client ID, client secret, redirect URI,
  scopes, and the new "Trust email without `email_verified` claim" toggle. A
  `Test SSO` link opens the IdP authorize URL in a new tab so admins can probe
  the round-trip without logging out.
- **RFC 9207 (Authorization Server Issuer Identification) support.** The
  callback handler forwards the IdP's `iss` query param into
  `oauth4webapi.validateAuthResponse` so PocketID, recent Keycloak builds, and
  Authelia work end-to-end.
- **Issuer discovery probe on save.** `POST /v1/settings/sso` now fetches
  `<issuer>/.well-known/openid-configuration` before persisting the row and
  refuses to save if the discovery document is unreachable or missing the
  required endpoints.
- **Env-var bootstrap.** If `GATEHOUSE_OAUTH_ISSUER` (and friends) are set on
  first boot, Gatehouse seeds the `settings/sso` row with `enabled: true` so
  upgraders don't have to re-enter their config in the UI. After boot, the DB
  row is the single source of truth.
- **Audit events**: `sso.start`, `sso.callback.{success,invalid_state,exchange_failed,unverified_email,no_user_match,email_collision}`.

### Security

- ID token verification (signature, iss, aud, exp, nonce) plus an explicit
  `validateApplicationLevelSignature` call against the IdP's JWKS.
- Userinfo `sub` is cross-checked against the ID token `sub` per
  OIDC Core §5.3.2 to defeat access-token substitution.
- The Gatehouse JWT is delivered via URL fragment (`/#sso=<jwt>`), not a query
  string, so it never appears in `Referer` headers or server access logs.
- Rate limiting on all three `/sso` endpoints to slow down enumeration probing
  and code-replay grinding.
- `allowInsecureRequests` is gated to loopback HTTP only; production HTTPS
  enforcement remains intact.
- One-shot `sso_login_state` rows: deleted on first read in `/callback`, reaped
  every minute for any abandoned 10-minute-stale entries.

### Changed

- `config.oauth` field removed from `GatehouseConfig`. `/v1/config` now derives
  `oauth_enabled` and `oauth_issuer` from the DB `settings/sso` row instead.
  Response shape unchanged.

### Database

- New table `sso_login_state` (state PK, nonce, code_verifier, created_at).
  Pure additive: no `ALTER`, no migration, no impact on existing data.

### Notes for upgrading

- Existing users with `email = NULL` need their email populated before they
  can log in via SSO. Username/password login is unaffected.
- If you ran a prior version with `GATEHOUSE_OAUTH_*` env vars set, those will
  seed the new DB row on first boot and SSO will be enabled automatically.
- Configure your IdP's allowed redirect URI to match the `redirect_uri` field
  in the Gatehouse Settings page exactly (e.g.
  `https://gatehouse.example.com/v1/auth/sso/callback`).
- For PocketID: enable the "Trust email without `email_verified` claim" toggle
  after saving the rest of the config.
