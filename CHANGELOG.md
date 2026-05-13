# Changelog

All notable changes to Gatehouse are documented here. The auto-generated GitHub
release notes (built from conventional-commit subjects between tags) carry the
fine-grained per-commit log. This file summarises each release at a higher
level.

## [0.14.2] - 2026-05-12

### Bug fix

- **`proxy.forward` audit rows now stamp the authorizing `lease_id` as a top-level column** (not just in metadata) when exactly one approval lease gated the call. The audit page can now filter "all value reveals authorized by this approval lease" without parsing metadata JSON. Applies to both REST `/v1/proxy` and MCP `gatehouse_proxy`. Multi-secret calls keep the comma-joined list in metadata only, since the column is a single-value foreign-key-ish field.

## [0.14.1] - 2026-05-12

### Bug fix

- **Approval request endpoint accepts `proxy` capability.** `POST /v1/lease/<path>/request` and the `gatehouse_request_access` MCP tool previously required `lease` capability on the secret. That made the approval workflow unreachable for any agent with only `proxy` cap on an approval-gated secret: their proxy call was blocked by the gate, and they couldn't request access either. The endpoint now accepts either `proxy` or `lease` cap, matching the set of operations the approval gate actually applies to.

## [0.14.0] - 2026-05-12

### Features

- **Rate limits on proxy calls.** AppRoles gain three optional limits (per-minute, per-hour, per-day) settable from the UI or `POST/PUT /v1/auth/approle` body. Secrets accept a per-secret `metadata.rate_limit_per_minute`. Both apply independently; the most restrictive wins. Hitting either returns `429` with `Retry-After`. Root tokens and user JWTs are exempt. Counters are fixed-window and in-memory. Limit ceilings: 10K/min, 100K/hour, 1M/day.
- **Approval-gated leases.** Mark a secret with `metadata.requires_approval=true` and agents must call `gatehouse_request_access(path, ttl, justification)` and wait for a human approval before `gatehouse_proxy` or `gatehouse_lease` will succeed. The approved lease IS the access window: revoking it kills access atomically. Status drives lifecycle (`pending` → `approved`/`denied`/`expired`). Auto-approve for trusted networks via `metadata.auto_approve_from_ip` (comma-separated CIDRs) plus optional `metadata.auto_approve_ttl_seconds`.
- **Approval webhook.** Set `GATEHOUSE_APPROVAL_WEBHOOK_URL` to fire a POST on every `lease.request_created`. Payload includes `approve_url` and `ui_url` so the receiver can deep-link a Slack/Discord/PagerDuty bridge to the approval. Optional `GATEHOUSE_APPROVAL_WEBHOOK_SECRET` enables HMAC-SHA256 signing over `${timestamp}.${body}` with `X-Gatehouse-Timestamp` and `X-Gatehouse-Signature` headers (5-minute replay window). When unset, no signature headers (URL-secrecy mode).
- **New MCP tool `gatehouse_request_access`.** Agents call this to ask for approval. `gatehouse_status` now returns `pending_leases` so agents can poll for status changes.
- **UI: Leases page redesigned.** Tabs for Active and Pending Approval. Approve/Deny actions with justification preview. Sidebar Leases nav gains a pending-count badge driven by SSE. AppRole modals gain a Rate Limits group. Approval-gated secrets get a `🔒 approval` chip in the tree and a banner in the detail panel.
- **SSE: `lease_request_created` and `lease_status_changed` events.** Live-update the pending tab and the sidebar badge without polling. Identity-scoped server-side (non-admins only see events for leases they own).

### New metadata keys

- `requires_approval` (`"true"` to gate the secret)
- `auto_approve_from_ip` (comma-separated CIDRs)
- `auto_approve_ttl_seconds` (default 300)
- `rate_limit_per_minute` (positive integer; per-secret cap)

### New AppRole columns

- `rate_limit_per_minute`, `rate_limit_per_hour`, `rate_limit_per_day` (all nullable; NULL means no limit)

### New audit actions

`lease.request_created`, `lease.approved`, `lease.denied`, `lease.request_expired`, `lease.auto_approved`, `lease.access`, `proxy.blocked.rate_limit`, `proxy.blocked.approval`.

### Migration

Schema-only; safe on a live v0.13.2 database. Six nullable columns added to `leases` (with `status` defaulting to `'approved'` so every existing row stays valid) and three nullable columns to `app_roles`. New index `idx_leases_pending`. Existing proxy and lease behaviour is unchanged for secrets without the new metadata.

## [0.13.2] - 2026-05-10

### Documentation

- **Web UI tour Settings section rewritten** to reflect the current set of cards: Health Status, Appearance, Server Configuration, SSO / OAuth Configuration, Proxy Limits, Two-Factor Authentication, and Danger Zone. Previously listed only the Danger Zone actions.
- **Security & Threat Model expanded** with a "Proxy hardening" subsection covering the three scoping layers (policy, `allowed_domains`, `allowed_path_prefixes`), the `GATEHOUSE_PROXY_ALLOW_PRIVATE` default and how to invert it for public-internet deployments, and a "SSO assurance shift" subsection documenting that SSO bypasses local TOTP by design.
- **Integrations page** gains a "Proxy runtime limits" subsection describing the configurable timeout and body cap, with the REST API examples and the cache invariant.
- **For Agents** mentions `metadata.allowed_path_prefixes` as a hint to scope outbound URLs without probing.
- **Getting Started** Next Steps points at the SSO setup pathway and the Security & Threat Model page.
- **README** drops the now-redundant `GATEHOUSE_PROXY_ALLOW_PRIVATE=true` line from the Quick Start (private networks are allowed by default since 0.11.x). Adds a Changelog row to the docs table.
- **API reference** proxy-limits row range wording cleaned up (`1 second to 30 minutes; 1 KiB to 100 MiB`).
- Stale "Generated from README/CLAUDE.md 2026-04-10" markers removed from seven docs pages; the docs have evolved well past that date.

No code changes; the running container is functionally identical to v0.13.1.

## [0.13.1] - 2026-05-09

### Internal

- The `docs/superpowers/` directory (plans + design specs) is no longer
  published to the GitHub mirror. These were always meant as in-progress
  dev notes; they read as authoritative documentation when discovered out
  of context. The two specs that previously appeared on GitHub
  (`2026-04-10-marketing-site-design.md` and `2026-05-06-sso-login-design.md`)
  are removed from `bshandley/gatehouse:main` by this release. The full
  history remains on the internal Gitea remote.
- No code changes; the running container is functionally identical to
  v0.13.0. This release bump exists to anchor the public-doc cleanup.

## [0.13.0] - 2026-05-09

### Added

- **Per-secret URL path-prefix allowlist (`allowed_path_prefixes` metadata).**
  Parallel to `allowed_domains`. When set on a secret, the proxy enforces
  that the upstream URL's path matches one of the listed comma-separated
  prefixes. Match is path-segment aligned: a prefix
  `/repos/bshandley/gatehouse` matches `/repos/bshandley/gatehouse` exactly
  and `/repos/bshandley/gatehouse/<anything>`, but NOT
  `/repos/bshandley/gatehouse-evil`. Trailing slashes in stored prefixes
  are normalized at check time.

  Useful for scoping a broad PAT (e.g. a GitHub fine-grained token that
  has `contents:write` on multiple repos) to a single repository's API
  surface without minting a new credential.

  Example: a `git/github-pat` secret with metadata
  `allowed_path_prefixes = "/repos/bshandley/gatehouse/,/user"` permits
  Git Database calls against the gatehouse repo and a self-info read,
  but rejects `/orgs/<x>/members` or `/repos/bshandley/some-other-repo/...`.

- **`target_path` field in proxy audit metadata.** Every `proxy.forward`
  and `proxy.forward.mcp` audit row now includes `target_path` (the URL
  pathname, query-string-stripped) alongside the existing `target_url`.
  Lets operators filter audits by which API surface was hit
  (`SELECT * FROM audit_log WHERE json_extract(metadata, '$.target_path')
  LIKE '/repos/%'`) without parsing the full URL.

### Changed

- Proxy denial paths (policy, domain, path-prefix, SSRF) all log the same
  metadata shape now, including `target_url` and `target_path`. Previously
  some paths logged only one of those.

### Notes for upgrading

- Pure additive. Secrets without `allowed_path_prefixes` metadata behave
  exactly as before. Existing audit consumers see one new field; nothing
  else moves.

## [0.12.1] - 2026-05-09

### Fixed

- **Proxy body scan no longer false-positives on literal `{{secret:...}}`
  strings in request bodies.** Both `POST /v1/proxy` and the MCP
  `gatehouse_proxy` tool now treat a template placeholder whose path
  doesn't resolve to a real secret as literal text, forwarded unchanged
  to the upstream. Previously, a body that legitimately contained the
  literal string `{{secret:path}}` (e.g. source code or docs explaining
  the proxy's own injection syntax) was rejected with
  `Forbidden: no proxy capability on path` because the scanner tried to
  authorize a phantom secret named `path`.
- Explicit references (`inject` / `auto_inject`) are unchanged: the secret
  must still exist AND the AppRole must still have `proxy` capability on
  it, otherwise the request fails loudly.

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
