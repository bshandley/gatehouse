# Rate limits and approval-gated leases

**Status:** approved
**Date:** 2026-05-12
**Scope:** Single feature release shipping two related capabilities: (1) per-AppRole and per-secret rate limits on proxy calls, and (2) approval-required leases extending the existing lease model to gate `gatehouse_proxy` and `gatehouse_lease` on a human-approved, time-bounded grant.
**Version target:** v0.14.0

## Summary

Today Gatehouse trusts any authenticated AppRole to call proxy as often as it likes against any secret it has the `proxy` capability for. This release introduces two complementary brakes:

1. **Rate limits** on proxy traffic, configurable per AppRole (minute/hour/day) and per secret (minute). Limits are token-bucket-style fixed-window counters held in memory. Hitting a limit returns 429 with `Retry-After`.
2. **Approval-gated leases**: a secret can require human approval before agents can use it. The agent calls `gatehouse_request_access(path, ttl, justification)` and waits. A human approves or denies from the UI (or an external system via the webhook). Once approved, the resulting lease is the agent's access window — every subsequent proxy or lease call against that secret is audited against that lease until it expires, is revoked, or is denied.

The lease model is unified: one row per access grant, status drives the lifecycle. No second "checkout" lease is created for approval-gated secrets.

## Goals

- Operators can put per-AppRole rate limits on proxy traffic to bound damage from a runaway agent.
- Operators can put per-secret per-minute rate limits to bound damage to expensive upstreams (LLM APIs, paid SaaS).
- Operators can mark sensitive secrets as `requires_approval`, and agents that try to use them get a clear "ask a human" workflow instead of silent success.
- An external system (Slack bot, paging, Discord) can subscribe to approval events via a signed webhook.
- An approved lease can be revoked atomically. One row, one delete, access is gone.
- Existing AppRoles, leases, and proxy calls continue to work unchanged for anyone who doesn't opt into the new metadata keys.

## Non-goals

- Cost tracking (`auto_approve_under_usd`). Follow-up release.
- Approval-required dynamic secrets (only static + proxy in v1).
- Per-AppRole-per-secret combined rate limit. Per-AppRole and per-secret apply independently; both must pass.
- Per-tool MCP rate limits. Only proxy is rate-limited.
- Configurable webhook URL editable in the UI. Env var only for v1.
- Renew-counter or per-renew approval. Renew on an approved lease works as today.

## Decisions

| Question | Decision | Rationale |
|---|---|---|
| Two leases (approval + checkout) or one unified | **Unified.** Lease IS the access window. `status` drives lifecycle. | Atomic revoke. No cascade logic. Single source of truth on the leases page. Footgun-free. |
| `status` column collapses `revoked` | **Keep both.** `status: pending\|approved\|denied\|expired` plus existing `revoked` boolean. | Minimum-touch migration. Existing callsites continue checking `revoked`; new approval flow drives `status`. Reaper flips both when applicable. |
| Webhook auth | **HMAC-SHA256 + timestamp.** Optional env-var secret; if set, send `X-Gatehouse-Timestamp` and `X-Gatehouse-Signature: sha256=<hex>` headers signing `${timestamp}.${body}`. Receiver rejects timestamps older than 300s. | Defends against forgery and replay. Matches GitHub/Stripe/Slack pattern. Secure-when-configured, convenient-by-default (mirrors `GATEHOUSE_PROXY_ALLOW_PRIVATE`). |
| Rate-limit window mechanism | **Fixed windows** keyed on `floor(now / window_ms)`. | ~10× simpler than sliding ring buffers. Plenty of precision for proxy-call defense. Minor burst-at-boundary tradeoff. |
| Hono route shape for new lease endpoints | **Single greedy route, suffix dispatch.** Match the existing `/renew` pattern. | Avoids route-precedence collision with the existing `:path{.+}` checkout handler. |
| Duplicated enforcement (REST proxy + MCP proxy) | **Extract `enforceProxyGates()` helper.** | Three new gates × two callsites = guaranteed drift. Single helper, both callsites consume it. |
| Audit action naming for blocked-at-gate calls | **Distinct actions.** `proxy.blocked.rate_limit` and `proxy.blocked.approval`. | Cleaner audit filtering. `proxy.forward` keeps its semantic ("we tried to hit upstream"). |
| Pending-lease API surface | **`GET /v1/lease/pending` only.** No `?include_pending` on the existing list endpoint. | Single source of truth, simpler skill docs. |
| Justification storage in audit | **Full text on the lease row; truncated to 200 chars in audit metadata.** | Audit metadata is `Record<string, string>`; up to 2000-char justifications would bloat audit rows. Full text reachable via lease lookup. |
| AppRole delete → pending leases | **Explicit cleanup.** `DELETE FROM leases WHERE identity = ? AND status = 'pending'` in AppRole delete handler. | No FK cascade exists (leases FK is to `secrets`, not `app_roles`). Approved leases stay revoked-but-visible for audit. |
| Renew on approval-gated lease | **Allowed.** Behaves identically to today's renew. Bounded by `max_lease_ttl=86400`. | "Human approved access" — extending within global cap stays within their consent envelope. No special re-approval step. |
| MCP `gatehouse_request_access` polling cadence | **Document 30–60s in the skill.** No server-side enforcement. | Operators control fast polling via the new AppRole rate limits if they care. |
| AuthContext `role_id` exposure | **Add `role_id?: string`.** Populated from JWT payload in middleware. | Required by rate limiter and audit metadata enrichment. Middleware already inspects this field for the AppRole branch. |

## Architecture

### Lease lifecycle (unified)

```
                       gatehouse_request_access
                              │
                              ▼
                          [pending] ──── request_expires_at ───▶ [expired] (reaper)
                              │
                ┌─────────────┼──────────────┐
                ▼             ▼              ▼
            approve()      deny()      revoke()
                │             │              │
                ▼             ▼              ▼
            [approved]   [denied]      [revoked]
                │
                ├── proxy/lease calls audited as proxy.forward / lease.access
                │   with lease_id metadata
                │
                ├── renew() extends expires_at within max_lease_ttl
                │
                ├── expires_at ─── reaper ──▶ [expired] (revoked=1)
                │
                └── revoke() ──▶ [approved, revoked=1]
```

Non-approval-gated secrets bypass this entire flow — `LeaseManager.checkout()` creates a `status='approved'` row directly (today's behavior, default value via DDL).

### Module layout

```
src/
  rateLimits/
    limiter.ts                      # NEW: fixed-window counters
    rateLimitValidation.ts          # NEW: validate AppRole limit inputs
  lease/
    manager.ts                      # extended: status field, request/approve/deny, autoApprove, hasActiveApprovedLease
    webhook.ts                      # NEW: HMAC-signed POST to GATEHOUSE_APPROVAL_WEBHOOK_URL
  api/
    proxy.ts                        # rate-limit + approval enforcement (via gates helper)
    lease.ts                        # new routes: /request, /approve, /deny, /pending
    proxyGates.ts                   # NEW: enforceProxyGates(ctx) shared by REST + MCP
    auth.ts                         # AppRole CRUD now accepts rate_limit_* fields
    onboard.ts                      # situation table adds gatehouse_request_access
  mcp/
    server.ts                       # new tool: gatehouse_request_access; proxy/lease gates via helper
  events/
    bus.ts                          # new event variants
  auth/
    middleware.ts                   # AuthContext.role_id
  db/
    init.ts                         # migrations for app_roles + leases columns
  templates/
    onboard.md                      # new "Approval-gated secrets" section + error decoder updates
  ui/
    index.html                      # rate-limit form, leases page tabs, badges, SSE handling
  index.ts                          # wire rate limiter + webhook; /v1/config additions; reaper handles pending
  version.ts                        # 0.14.0
```

## Data model

Migrations in `src/db/init.ts` use the existing PRAGMA `table_info`-driven conditional ALTER pattern. Each column added only if not already present.

### `app_roles` additions

```sql
ALTER TABLE app_roles ADD COLUMN rate_limit_per_minute INTEGER;
ALTER TABLE app_roles ADD COLUMN rate_limit_per_hour INTEGER;
ALTER TABLE app_roles ADD COLUMN rate_limit_per_day INTEGER;
```

All NULL by default. NULL means no limit on that axis.

### `leases` additions

```sql
ALTER TABLE leases ADD COLUMN status TEXT NOT NULL DEFAULT 'approved';
ALTER TABLE leases ADD COLUMN justification TEXT;
ALTER TABLE leases ADD COLUMN approved_by TEXT;
ALTER TABLE leases ADD COLUMN approved_at TEXT;
ALTER TABLE leases ADD COLUMN denied_reason TEXT;
ALTER TABLE leases ADD COLUMN request_expires_at TEXT;
```

Default `'approved'` keeps every existing row valid (they all behave as approved today via implicit consent).

### New index

```sql
CREATE INDEX IF NOT EXISTS idx_leases_pending
  ON leases(identity, secret_path, status)
  WHERE status = 'pending' OR status = 'approved';
```

Speeds up `hasActiveApprovedLease()` and `listPending()`.

### Status values

- `pending` — agent has asked, awaiting human decision. `expires_at` is hypothetical (time the window would close *if* approved now). `request_expires_at` is when the pending request itself auto-expires.
- `approved` — usable. `expires_at` is the access-window close time.
- `denied` — terminal. Reason in `denied_reason`. Does NOT block re-request.
- `expired` — terminal. Reached via reaper from `pending` past `request_expires_at`.
- `revoked=1` (column) — orthogonal. Admin killed access manually. Reaper also sets this when approved leases expire.

## Module 1: rate limits

### `src/rateLimits/limiter.ts`

Module-level state held in memory. Loss on restart is acceptable.

```typescript
export interface AppRoleLimits {
  per_minute: number | null;
  per_hour: number | null;
  per_day: number | null;
}

export interface RateLimitDecision {
  allowed: boolean;
  reason?: string;
  limitKind?: "approle_minute" | "approle_hour" | "approle_day" | "secret_minute";
  retryAfterSeconds?: number;
  current?: number;
  limit?: number;
}

export class RateLimiter {
  checkApprole(roleId: string, limits: AppRoleLimits): RateLimitDecision;
  checkSecret(path: string, perMinute: number | null): RateLimitDecision;
  recordCall(roleId: string, paths: string[]): void;
}

export function _resetRateLimitsForTests(): void;
```

**Mechanism.** Fixed windows. Per `(roleId, window)` and per `(path, "minute")`, store `{ epoch, count }`. On check:

1. Compute `current_epoch = Math.floor(now_ms / window_ms)`.
2. If stored `epoch !== current_epoch`, reset to `{ epoch: current_epoch, count: 0 }`.
3. If `count >= limit`, decision is `{ allowed: false, retryAfterSeconds: secondsUntilNextWindow }`.
4. Otherwise `{ allowed: true }`.

`recordCall` increments the per-AppRole counters for minute/hour/day, and the per-secret minute counter for each path in `paths`. Called only AFTER a successful gate pass and forward (or attempted forward — upstream 4xx/5xx still counts; auth/policy/gate failures don't).

### Hard ceilings

```typescript
HARD_CEILING_PER_MINUTE = 10_000
HARD_CEILING_PER_HOUR   = 100_000
HARD_CEILING_PER_DAY    = 1_000_000
HARD_FLOOR              = 1
```

`src/rateLimits/rateLimitValidation.ts`:

```typescript
export function validateAppRoleLimits(input: unknown): { ok: true; limits: AppRoleLimits } | { ok: false; error: string };
```

Reject anything below 1 or above the ceiling with a clear error.

### Per-secret limits via metadata

Read `secret.metadata.rate_limit_per_minute` (string in storage, parsed to int). Invalid or missing → no per-secret limit. Documented in the skill. No new UI; the existing metadata KV editor handles it.

### Order of operations in proxy handler (REST + MCP)

The `enforceProxyGates()` helper sequences these checks. Called by both REST proxy (`src/api/proxy.ts`) and MCP `gatehouse_proxy` (`src/mcp/server.ts`):

1. AppRole rate-limit check (skipped if `auth.source !== "approle"` — root and user JWTs are exempt).
2. Per-secret rate-limit check for each path in `secretPaths`.
3. Approval check: for each secret with `metadata.requires_approval === "true"`, verify an active approved lease exists for `(identity, path)` OR `auto_approve_from_ip` matches the source IP (in which case auto-create an approved lease and audit `lease.auto_approved`).
4. Returns either `{ allowed: true, leaseIds: Record<path, leaseId> }` or `{ allowed: false, status: 429|403, body: {...} }`.

On allowed-and-forwarded, caller invokes `rateLimiter.recordCall(roleId, secretPaths)`.

### Audit emissions

- `proxy.blocked.rate_limit`, metadata `{ limit_kind, limit, current }`, `success: false`.
- `proxy.blocked.approval`, metadata `{ requires_approval: <comma-joined paths> }`, `success: false`.
- Existing `proxy.forward` unchanged, but metadata now includes `lease_id` when any approval-gated secret authorized the call.

## Module 2: approval-gated leases (unified)

### LeaseManager extensions in `src/lease/manager.ts`

```typescript
export type LeaseStatus = "pending" | "approved" | "denied" | "expired";

export interface Lease {
  id: string;
  secret_path: string;
  identity: string;
  ttl_seconds: number;
  created_at: string;
  expires_at: string;
  revoked: boolean;
  status: LeaseStatus;
  justification: string | null;
  approved_by: string | null;
  approved_at: string | null;
  denied_reason: string | null;
  request_expires_at: string | null;
}

class LeaseManager {
  // existing methods unchanged: checkout(), getLease(), listActive(), revoke(), renew(), reapExpired()

  // NEW
  requestAccess(
    secretPath: string,
    identity: string,
    ttlSeconds: number,
    justification: string,
    requestTtlSeconds?: number
  ): Lease;

  approve(leaseId: string, approverIdentity: string): Lease | null;
  deny(leaseId: string, approverIdentity: string, reason: string): Lease | null;

  autoApprove(
    secretPath: string,
    identity: string,
    ttlSeconds: number,
    approvedBy: string,
    justification: string
  ): Lease;

  listPending(identity?: string): Lease[];
  hasActiveApprovedLease(identity: string, secretPath: string): boolean;
  findActiveApprovedLease(identity: string, secretPath: string): Lease | null;

  attachBus(bus: EventBus): void;
}
```

### `checkout()` behavior under the unified model

```typescript
checkout(secretPath, identity, ttlSeconds): { lease, value } | null {
  const meta = this.secrets.getMeta(secretPath);
  if (meta?.metadata?.requires_approval === "true") {
    const existing = this.findActiveApprovedLease(identity, secretPath);
    if (!existing) return null;  // caller emits 403 with requires_approval hint
    const value = this.secrets.get(secretPath);
    this.audit.log({
      identity, action: "lease.access", path: secretPath, lease_id: existing.id,
    });
    if (this.bus) this.bus.emit({ type: "lease_access", lease_id: existing.id, identity });
    return { lease: existing, value };
  }
  // Existing logic: create new lease row, return.
}
```

### `requestAccess()` semantics

- Validate `justification` length (10–2000 chars) before write. Outside range → throws a typed error the API layer turns into 400.
- Deduplicate: if `(identity, secretPath)` already has a `status='pending'` row that isn't expired, return that row (same response shape).
- `request_expires_at` default 3600s, clamped to [60, 86400].
- Insert with `status='pending'`, `expires_at = now + ttl_seconds` (hypothetical; updated on approval).
- Audit `lease.request_created` with truncated justification metadata.
- Emit `lease_request_created` bus event AND fire the webhook (async, fire-and-forget).

### `approve()` / `deny()`

- 404 if lease doesn't exist. 409 if not `pending`.
- `approve`: set `status='approved'`, `approved_by`, `approved_at=now`, `expires_at = now + ttl_seconds`.
- `deny`: set `status='denied'`, `denied_reason`. Reaper does NOT remove denied rows (kept for audit).
- Both emit `lease_status_changed` bus event and audit (`lease.approved` or `lease.denied`).

### Reaper updates

`reapExpired()` extended to:

- Flip `pending` rows past `request_expires_at` to `status='expired'`, set `revoked=1`. Emit `lease.request_expired` audit and `lease_status_changed` event.
- Existing approved-row reaping unchanged (sets `revoked=1` past `expires_at`).

### Approval webhook (`src/lease/webhook.ts`)

If `GATEHOUSE_APPROVAL_WEBHOOK_URL` is set, POST after each `lease.request_created`:

```json
{
  "event": "lease_request_created",
  "lease_id": "lease-...",
  "identity": "approle:claude-code-agent",
  "secret_path": "api-keys/example",
  "justification": "...",
  "ttl_seconds": 300,
  "request_expires_at": "2026-05-12T16:00:00Z",
  "approve_url": "<server-base>/v1/lease/lease-.../approve",
  "ui_url": "<server-base>/#leases"
}
```

Delivery rules:

- 5s total timeout (`AbortSignal.timeout(5000)`). No retry.
- SSRF rules match proxy: private hosts allowed iff `GATEHOUSE_PROXY_ALLOW_PRIVATE=true`. If the URL points to a private host and the env var is unset, log a one-time warning at startup, never deliver.
- If `GATEHOUSE_APPROVAL_WEBHOOK_SECRET` is set, send:
  - `X-Gatehouse-Timestamp: <unix-seconds>`
  - `X-Gatehouse-Signature: sha256=<hex HMAC-SHA256(secret, `${timestamp}.${body}`)>`
- If unset, no signature headers (URL-secrecy mode).
- Fire-and-forget via `.catch(console.error)`. Never blocks `requestAccess()`.

### Auto-approval via IP allowlist

When a secret has `metadata.requires_approval === "true"` AND `metadata.auto_approve_from_ip = "10.0.0.0/8,..."` AND the proxy/lease call's source IP matches one of the CIDRs:

- `LeaseManager.autoApprove()` creates a `status='approved'` row directly.
- TTL = `parseInt(metadata.auto_approve_ttl_seconds, 10) || 300`.
- `approved_by = "system:auto_approve_from_ip"`, `justification = "Auto-approved from <ip>"`.
- Audit `lease.auto_approved`.

CIDR matching reuses `ipMatchesAllowlist()` in `src/auth/cidr.ts`.

## API surface

All new endpoints live in `src/api/lease.ts`. The existing `router.post("/:path{.+}")` handler is extended to suffix-dispatch on `/request`, `/approve`, `/deny`, alongside the existing `/renew`.

### `POST /v1/lease/<path>/request`

Requires `lease` capability on path. Body:

```json
{ "ttl": 300, "justification": "string", "request_ttl": 3600 }
```

- `ttl`: required int, 10..86400. Lease lifetime after approval.
- `justification`: required string, 10..2000 chars (trimmed).
- `request_ttl`: optional int, 60..86400. Default 3600.

Response 202 on creation, 200 on dedup:

```json
{
  "lease_id": "lease-...",
  "status": "pending",
  "request_expires_at": "...",
  "expires_at_if_approved": "..."
}
```

### `POST /v1/lease/<lease-id>/approve`

Admin only. Empty body. Returns the updated lease. 404 if not found, 409 if not `pending`.

### `POST /v1/lease/<lease-id>/deny`

Admin only. Body: `{ "reason": "string" }` (optional, max 500). Returns the updated lease. 404/409 same as approve.

### `GET /v1/lease/pending`

Admin sees all pending. Non-admin sees only their own. Response: `{ leases: [...] }` with full approval fields.

### `GET /v1/lease/<lease-id>`

Owner or admin. Returns the lease object. 404 / 403 as appropriate.

### `GET /v1/lease/`

Existing. Unchanged. Approved active leases only. (No `?include_pending` flag — use `/v1/lease/pending` for that.)

### `POST /v1/lease/<path>` (existing checkout)

Behavior change for approval-gated paths:

- Has active approved lease for `(identity, path)`: return existing lease + value (audit `lease.access`, NOT `lease.checkout`). No new row.
- Auto-approve IP match: create approved lease, return value (audit `lease.auto_approved`, then `lease.access`).
- Otherwise: 403 with `{ error, requires_approval: true, hint: "Use POST /v1/lease/<path>/request" }`.

Non-approval paths: behavior unchanged (new lease row per call).

### `POST /v1/lease/<lease-id>/renew` (existing)

Behavior unchanged for `status='approved'` rows: extends `expires_at` by `ttl_seconds`, capped at `max_lease_ttl`. Returns 409 for `status` in `pending|denied|expired` (renew on those states is meaningless).

## MCP tools (`src/mcp/server.ts`)

### New: `gatehouse_request_access`

```ts
{
  name: "gatehouse_request_access",
  description: "Request approval to access an approval-gated secret. Returns lease_id and status='pending'. Poll gatehouse_status for status changes or use the lease GET endpoint. Once approved, subsequent gatehouse_proxy and gatehouse_lease calls against this secret will succeed for the lease TTL.",
  inputSchema: {
    type: "object",
    properties: {
      path: { type: "string", description: "Secret path to request access to" },
      ttl: { type: "number", description: "Lease duration in seconds after approval (default 300, min 10, max 86400)" },
      justification: { type: "string", description: "What you'll do with the credential. NEVER include the secret value, request body, or anything credential-shaped. Describe intent only (1–3 sentences)." }
    },
    required: ["path", "justification"]
  }
}
```

Handler delegates to `leases.requestAccess()` and returns the same JSON shape as the REST endpoint.

### Modified

- `gatehouse_proxy`: gated by `enforceProxyGates()`. On 429 returns `{ error, retry_after_seconds, limit_kind }`. On 403 approval returns `{ error, requires_approval: [paths], hint: "Use gatehouse_request_access(...)" }`. Both marked `isError: true`.
- `gatehouse_lease`: same gating logic for approval-required secrets. New error shape mirrors proxy.
- `gatehouse_list`: result rows surface `requires_approval` and `auto_approve_from_ip` from metadata (already passed through; documented in the skill).
- `gatehouse_status`: response now includes `pending_leases` (count of `status='pending'` rows for the caller's identity) in addition to existing fields.

## UI changes (`src/ui/index.html`)

### AppRole modals

In both create and edit AppRole modals, add a "Rate Limits (optional)" section with three number inputs (per minute / per hour / per day). Placeholders read `(no limit)`. Wire to the create/edit handlers; an empty/missing value sends `null` to the API.

In the AppRole list row, when any limit is set, render a small badge `⏱ rate-limited` with the values in `title`.

### Secrets tree

`renderSecretTree()` adds a `🔒 approval` badge when `metadata.requires_approval === "true"`. Tooltip: "Requires human approval before agents can use".

### Leases page

Two tabs: **Active** (today's view) and **Pending Approval (N)**.

Active tab additions:
- New column "Status" (currently always `approved` for visible rows; presence makes future filters obvious).
- For approval-gated rows, show small `approved_by` chip in identity column.
- Revoke action emits the existing revoke call; no new endpoint.

Pending tab:
- Columns: Identity, Path, Justification (first 80 chars + expand), Requested TTL, Time Waiting, Request Expires, Actions (Approve / Deny).
- Approve: confirmation modal showing full justification, then POST `/v1/lease/<id>/approve`.
- Deny: `ghPrompt` for reason, then POST `/v1/lease/<id>/deny`.
- Auto-refresh on `lease_request_created` and `lease_status_changed` SSE events.

### Sidebar

`Leases` nav item gains a badge showing pending count when > 0. Fetched on app load from `/v1/lease/pending`; updated live via SSE.

### Secret detail panel

When viewing a secret with `requires_approval === "true"`:
- Banner: "🔒 Requires approval before agents can use it."
- List of active approved leases against this path (identity, expires_at, approved_by).

### SSE handling

The `/v1/events` handler in `src/index.ts` is extended:

```js
// Inside the subscriber callback, after the audit case:
if (e.type === "lease_request_created") {
  if (isAdmin || e.lease.identity === self) {
    send(`event: lease_request_created\ndata: ${JSON.stringify(e.lease)}\n\n`);
  }
} else if (e.type === "lease_status_changed") {
  if (isAdmin || e.identity === self) {
    send(`event: lease_status_changed\ndata: ${JSON.stringify(e)}\n\n`);
  }
}
```

The bus event payload for `lease_status_changed` includes `identity` so server-side filtering doesn't need a DB re-fetch.

## Event bus (`src/events/bus.ts`)

```typescript
export type GatehouseEvent =
  | { type: "audit"; record: Record<string, unknown> }
  | { type: "heartbeat"; ts: number }
  | { type: "lease_request_created"; lease: SanitizedLease }
  | { type: "lease_status_changed"; lease_id: string; status: LeaseStatus; identity: string; approved_by?: string };
```

Sanitized lease excludes nothing sensitive — justification is intended for the approver. Bus-side filtering is identity-based at SSE delivery.

## Skill template (`src/templates/onboard.md`)

### New section after "First call to any secret, in order"

```markdown
## Approval-gated secrets

Some secrets require human approval before you can use them. In
`gatehouse_list`, these appear with `metadata.requires_approval: "true"`.
Do NOT try to proxy or lease them directly. The call will fail with 403
and `requires_approval` in the response.

The flow:

1. Call `gatehouse_request_access(path, ttl, justification)`. Pick a TTL that
   covers what you need to do (default 300s, max 86400s). Write a clear
   justification (1–3 sentences) describing what API endpoint you'll hit
   and roughly what for.
2. Wait. Poll `gatehouse_status` every 30–60 seconds (NOT faster) to check
   `pending_leases`. Do not re-request — duplicates dedupe to the same
   lease_id.
3. Once approved, your `gatehouse_proxy` and `gatehouse_lease` calls against
   this secret succeed for the lease duration. The approved lease IS your
   access window; revoking it kills access immediately. Each call audits
   as `lease.access` against the lease_id.
4. If denied, read `denied_reason`. Adjust your justification and re-request
   if appropriate (a denied lease does NOT block re-requests).
5. After expiry, you must re-request. Renew works on approved leases (extends
   `expires_at` within `max_lease_ttl`) but don't renew speculatively.
6. If the operator hasn't responded after ~10 minutes, surface to the user
   ("waiting on approval for X") rather than spamming polls.

### Writing justifications

The justification is shown to the human approver and lands in the audit log.

GOOD: "Fetching Q4 revenue data from Salesforce for the quarterly summary
the user requested. Single GET to /services/data/v59.0/query."

BAD: "Need OpenAI." (too vague)
BAD: "POST {...full request body with prompt...}" (don't include the body)
BAD: "Bearer <the value>" (NEVER include credentials)

NEVER include secret values, request bodies, raw URLs with query params,
or anything credential-shaped. Justifications are for INTENT, not implementation.
```

### Error decoder additions

```markdown
- **403 with `requires_approval`**: the secret needs human approval first.
  Call `gatehouse_request_access` with a justification.
- **429 from Gatehouse with `Retry-After`**: you've hit a rate limit
  (per-AppRole or per-secret). Wait the Retry-After value. Do NOT retry
  faster. If you keep hitting it, surface to the user that you're
  rate-limited.
```

### `renderSituationTable()` update

Insert near the proxy entry, when any policy grants `lease`:

```typescript
push("Request access to an approval-gated secret", "`gatehouse_request_access`");
```

## Settings export (`GET /v1/config`)

Add to the existing response:

```json
{
  "approval_webhook_set": true,
  "approval_webhook_signed": true,
  "approval_request_default_ttl": 3600,
  "approval_request_max_ttl": 86400
}
```

`approval_webhook_set` reflects `!!process.env.GATEHOUSE_APPROVAL_WEBHOOK_URL`. `approval_webhook_signed` reflects `!!process.env.GATEHOUSE_APPROVAL_WEBHOOK_SECRET`.

## Tests

### `tests/rateLimits.test.ts`

- AppRole with `per_minute=5` allows 5 calls, blocks 6th, returns 429 with `Retry-After`.
- Per-secret `per_minute=3` blocks 4th call to that secret even if AppRole limit not hit.
- Root token bypasses all limits.
- User JWT bypasses all limits.
- Failed upstream calls (4xx/5xx) still count toward limits.
- Gate-rejected calls (rate-limit or approval failure) do NOT count.
- After window expires, calls resume.
- `_resetRateLimitsForTests()` clears state.
- Validation: `per_minute > 10000` rejected with 400.
- Validation: `per_minute=0` or negative rejected with 400.

### `tests/leaseApproval.test.ts`

- Secret without `requires_approval` metadata: proxy and lease work as today.
- Secret with `requires_approval=true`: proxy returns 403 with `requires_approval: [path]`.
- `POST /v1/lease/<path>/request` creates pending lease, emits `lease.request_created` audit.
- Duplicate request returns the same pending lease (no new row).
- Admin approves: status flips, audit emits, proxy call now succeeds.
- After lease expiry: proxy call fails again with `requires_approval`.
- Admin denies: status flips, audit emits, re-request works.
- `request_expires_at` past: reaper flips to `expired`, audit emits `lease.request_expired`.
- `auto_approve_from_ip` matching IP creates an approved lease without human action.
- `auto_approve_from_ip` non-matching IP still requires approval.
- AppRole delete clears pending leases for that identity.
- Approving non-pending lease: 409. Approving non-existent: 404.
- `gatehouse_lease` against approval-gated path with active approved lease: reuses lease, audits `lease.access`, no new row.
- Revoking the approved lease atomically blocks subsequent proxy calls.

### `tests/leaseWebhook.test.ts`

- When `GATEHOUSE_APPROVAL_WEBHOOK_URL` set, webhook fires on `lease.request_created`.
- When `_SECRET` set, headers include valid `X-Gatehouse-Timestamp` and `X-Gatehouse-Signature` matching `sha256=hex(hmac(secret, ts+"."+body))`.
- When `_SECRET` unset, no signature headers.
- Webhook timeout doesn't block lease creation.
- Webhook pointing at private host without `GATEHOUSE_PROXY_ALLOW_PRIVATE` is refused at startup with a warning, and no delivery is attempted.

### `tests/skillTemplate.test.ts` (extend if exists, else create)

- Skill body contains "Approval-gated secrets" section.
- Skill body contains 429 entry in error decoder.
- Situation table includes `gatehouse_request_access` row when `lease` policy granted.

### `tests/sseEvents.test.ts` (extend if exists, else create)

- `lease_request_created` delivered to admin subscribers.
- `lease_request_created` delivered to the requesting agent.
- `lease_request_created` NOT delivered to other AppRoles.
- `lease_status_changed` delivered on approve/deny to admin and the lease owner.

## Acceptance criteria

The release ships when all are true:

1. Migration runs cleanly on a v0.13.2 database. No data loss. Existing leases have `status='approved'`.
2. AppRole rate-limit fields editable in the UI; persisted; reflected in API responses.
3. `per_minute=2` AppRole — 3rd proxy call within 60s returns 429 with sane Retry-After. Audit row uses action `proxy.blocked.rate_limit` with `limit_kind=approle_minute` metadata.
4. Secret with `requires_approval=true` cannot be proxied without an approved lease. 403 with `requires_approval: [path]`.
5. `gatehouse_request_access` creates a pending lease, fires `lease_request_created` SSE event, fires webhook (with signed headers if secret set).
6. UI Pending Approval tab shows the request in real time without reload.
7. Approve flips status to approved; agent's next proxy call succeeds; `proxy.forward` audit carries `lease_id`.
8. Subsequent `gatehouse_lease` against an approval-gated secret with an active approved lease reuses the same `lease_id`, audits `lease.access`, no new row.
9. Lease expires → next proxy call fails with `requires_approval`.
10. `auto_approve_from_ip` matching IP creates an auto-approved lease without human action; audit `lease.auto_approved`.
11. Pending request past `request_expires_at` is reaped to `expired`.
12. Revoking an approved lease immediately blocks subsequent proxy/lease calls (atomic, no cascade logic).
13. `gatehouse_status` returns `pending_leases` count.
14. Sidebar Leases badge shows pending count when > 0.
15. `/v1/skill` body contains the new "Approval-gated secrets" section.
16. All existing tests pass.
17. All new tests pass.
18. README has a short "Approval-gated leases" subsection under "What it does".
19. CHANGELOG entry summarizes both features.
20. Version is `0.14.0`.

## Style

- TypeScript strict mode. Explicit types on exports.
- No `any` outside the existing `as { ... }` cast pattern for raw SQLite rows.
- No new dependencies. Bun built-ins (`crypto.createHmac`), Hono, jose, tweetnacl.
- Match existing audit shape; no helper proliferation.
- Module-level state always has a `_resetForTests()` hook.
- All error responses include `request_id: c.get("requestId")`.
- All audit rows include `source_ip: c.get("sourceIp")` where available.

## File checklist

### Modified
- `src/db/init.ts`
- `src/auth/middleware.ts`
- `src/api/auth.ts`
- `src/api/proxy.ts`
- `src/api/lease.ts`
- `src/lease/manager.ts`
- `src/mcp/server.ts`
- `src/events/bus.ts`
- `src/index.ts`
- `src/api/onboard.ts`
- `src/templates/onboard.md`
- `src/ui/index.html`
- `README.md`
- `CHANGELOG.md`
- `src/version.ts` (→ 0.14.0)

### Added
- `src/rateLimits/limiter.ts`
- `src/rateLimits/rateLimitValidation.ts`
- `src/lease/webhook.ts`
- `src/api/proxyGates.ts`
- `tests/rateLimits.test.ts`
- `tests/leaseApproval.test.ts`
- `tests/leaseWebhook.test.ts`
- `tests/skillTemplate.test.ts` (or extend)
- `tests/sseEvents.test.ts` (or extend)
