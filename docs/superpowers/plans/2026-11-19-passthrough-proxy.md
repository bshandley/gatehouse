# Passthrough Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `ANY /p/<alias>/<rest>` forwards to an operator-pinned upstream with the bound secret injected and the response streamed back natively, so any SDK works by changing its base URL.

**Architecture:** The proxy controls that live inline in `src/api/proxy.ts` and again in `src/mcp/server.ts` move into `src/proxy/pipeline.ts` first, with no behavior change. Passthrough is then a third caller of that pipeline: a Hono router at `/p` with its own caller authentication (Gatehouse bearer token or a `gatehouse_pt_` key read from the API-key slot), a pure URL join, and a streaming byte-level scrubber.

**Tech Stack:** Bun, Hono, bun:sqlite, `bun test`. No new runtime dependencies. One new dev dependency (`openai`, Task 7).

**Spec:** `docs/superpowers/specs/2026-11-19-passthrough-proxy-design.md`

## Global Constraints

- Never an em dash, in code, comments, docs, tests, or commit messages.
- No tokens, LAN addresses, or credentialed URLs in any committed file. Tests and docs use `api-keys/example`, `api-keys/example2`, and `https://api.example.com`. Never a real provider name after `api-keys/`.
- The key prefix is exactly `gatehouse_pt_`.
- No feature writes a policy. Setting an alias grants nothing.
- Fail closed: if a control cannot be applied to a passthrough request, the request is denied.
- The caller never chooses the upstream host. It comes only from `metadata.upstream_url`.
- No Gatehouse credential reaches the upstream. No raw secret value reaches the caller, including across stream chunk boundaries.
- Tasks 1 and 2 are behavior-preserving: `test/proxy.test.ts`, `test/proxyApprovalAudit.test.ts`, `test/rateLimits.test.ts`, and `test/mcp.test.ts` pass with zero edits to those files.
- Audit action for passthrough is `proxy.forward` with `metadata.mode = "passthrough"` and `metadata.alias`. The query string is never logged.
- After every `bun test` run, report the count as `✓ N pass`.
- Commit per task, style `feat(passthrough): summary`. Push the feature branch to `origin` only. Only a push of `main` redeploys the maintainer's live instance; feature-branch pushes do not.
- Release is 0.24.0 (0.23.0 shipped distribution).

## Review Focus

1. Client disconnects mid-stream. Expected: the upstream fetch is aborted, exactly one audit row is written, nothing leaks. Test in Task 6 and Task 7.
2. Request body with no `Content-Length` (chunked) larger than `GATEHOUSE_MAX_BODY_SIZE`. The global middleware only checks the header. Expected: 413, nothing forwarded. Test in Task 7.
3. Bodyless responses: `HEAD`, `204`, `304`. Expected: status and headers arrive, the request completes, one audit row. Test in Task 7.
4. `/p/<alias>` with no trailing slash and `/p/<alias>/` with an empty remainder. Expected: both forward to the `upstream_url` path itself, neither 404s from the router. Test in Task 5 and Task 7.
5. Remainder that starts with a slash (`/p/a//other.example.com/x`). Expected: 400 `bad_path` or a URL still on the pinned origin, never a request to `other.example.com`. Test in Task 5.

---

### Task 1: Shared proxy pipeline, REST caller

**Files:**
- Create: `src/proxy/pipeline.ts`
- Create: `test/proxyPipeline.test.ts`
- Modify: `src/api/proxy.ts` (the `router.post("/")` handler, lines 252 to 761)

**Interfaces:**
- Produces:

```ts
export interface ProxyDeps {
  secrets: SecretsEngine;
  policies: PolicyEngine;
  audit: AuditLog;
  db?: Database;
  rateLimiter?: RateLimiter;
  leases?: LeaseManager;
  patterns?: PatternEngine;
}

export interface ProxyCall {
  auth: AuthContext;
  sourceIp: string;
  requestId?: string;
  secretPaths: string[];
  /** URL as the caller wrote it, before substitution. Goes in audit metadata. */
  auditUrl: string;
  /** Upstream URL given the secrets resolved so far. */
  resolveUrl: (resolved: Map<string, string>) => string;
  auditAction: "proxy.forward" | "proxy.forward.mcp";
  /** Merged into the metadata of every audit row this call writes. */
  auditExtra?: Record<string, string>;
}

export type ProxyDenial =
  | { code: "policy_denied"; path: string }
  | { code: "gate_blocked"; gate: GatesBlocked }
  | { code: "secret_not_found"; path: string }
  | { code: "domain_blocked"; path: string; hostname: string }
  | { code: "path_prefix_blocked"; path: string; resolvedPath: string }
  | { code: "ssrf_blocked"; reason: string }
  | { code: "bad_protocol"; protocol: string }
  | { code: "invalid_url" };

export type ProxyAuthorization =
  | { ok: true; resolved: Map<string, string>; upstreamUrl: string;
      leaseIds: Record<string, string>; roleId: string; tlsInsecure: boolean }
  | { ok: false; denial: ProxyDenial };

export function authorizeProxyCall(deps: ProxyDeps, call: ProxyCall): ProxyAuthorization;

export interface ProxyOutcome {
  method: string;
  /** Set when the upstream answered. */
  status?: number;
  redactionCount?: number;
  /** Set when the call failed after authorization (timeout, network, cap). */
  failureReason?: string;
  /** Passed to patterns.record when present. */
  pattern?: { url: string; requestHeaderNames: string[]; requestBody?: unknown; responseBody?: unknown };
}

/** Counts the call against rate limits. Call once, when the upstream fetch has been attempted. */
export function recordProxyCall(deps: ProxyDeps, call: ProxyCall, authz: { roleId: string }): void;
/** Writes the audit row and records the pattern. */
export function recordProxyOutcome(deps: ProxyDeps, call: ProxyCall,
  authz: { leaseIds: Record<string, string>; upstreamUrl: string }, outcome: ProxyOutcome): void;
```

`authorizeProxyCall` runs, in today's order: policy check per path, `enforceProxyGates` (only when `rateLimiter`, `leases`, and `db` are all present), then per path: resolve value, `allowed_domains`, `allowed_path_prefixes`; then `checkPrivateNetworkPolicy`, then the protocol check. It writes the same denial audit rows the REST handler writes today, with the same metadata keys, using `call.auditAction`. It returns a denial code and data, never a message: each caller formats its own response text so existing messages do not change. `recordProxyCall` is separate from `recordProxyOutcome` because a streaming caller counts the call at response headers and audits at end of stream.

- [ ] **Step 1: Write `test/proxyPipeline.test.ts`.** Build deps the way `test/proxy.test.ts` does. One test per denial code asserting the returned `denial` and the audit row (`action`, `success: false`, `metadata.reason`). One success test asserting `resolved`, `upstreamUrl`, `leaseIds`, `tlsInsecure` (true only when a referenced secret has `tls_allow_insecure: "true"`). One test that `auditExtra` appears in a denial row and a success row. One test that `recordProxyCall` increments the limiter and a denial does not.
- [ ] **Step 2: Run `bun test test/proxyPipeline.test.ts`.** Expected: FAIL, module not found.
- [ ] **Step 3: Implement `src/proxy/pipeline.ts`** by moving the logic out of `src/api/proxy.ts`. Keep `resolveAutoInject`, `checkPrivateNetworkPolicy`, and `allowPrivateGlobally` exported from `src/api/proxy.ts` (other modules import them from there).
- [ ] **Step 4: Rewrite the REST handler** to call `authorizeProxyCall`, map each denial code to the exact status and message it returns today, then `recordProxyCall` and `recordProxyOutcome`. The handler keeps: request parsing, `extractSecretRefs`, header and body injection, the fetch, the buffered `readCappedText` response, suggestions.
- [ ] **Step 5: Run `bun test`.** Expected: every existing test passes with no edits to `test/proxy.test.ts`, `test/proxyApprovalAudit.test.ts`, `test/rateLimits.test.ts`. `git diff --stat main -- test/` shows only the new file.
- [ ] **Step 6: Commit** `refactor(passthrough): extract shared proxy pipeline, REST caller`.

### Task 2: MCP caller on the pipeline

**Files:**
- Modify: `src/mcp/server.ts` (`case "gatehouse_proxy"`, about lines 589 to 857)

**Interfaces:**
- Consumes: `authorizeProxyCall`, `recordProxyCall`, `recordProxyOutcome` from Task 1.

The MCP path differs from REST today and must keep differing: audit action `proxy.forward.mcp`, its own error strings, no `basic:` inject shorthand, no `tls_allow_insecure`, no response header forwarding, no pattern recording, and a failure audit row with no `reason` key. Preserve all of it (ignore `tlsInsecure`, pass no `pattern`, and add an option to `recordProxyOutcome` if the missing `reason` key cannot otherwise be reproduced). Do not fix these in this task.

- [ ] **Step 1: Run `bun test test/mcp.test.ts`** and record the pass count.
- [ ] **Step 2: Replace the inline policy, gate, allowlist, SSRF, rate-limit, and audit code** in the `gatehouse_proxy` case with pipeline calls. Map each denial code to today's exact `error(...)` string.
- [ ] **Step 3: Run `bun test`.** Expected: same counts, zero edits to `test/mcp.test.ts`.
- [ ] **Step 4: Write the divergences above into the task report** as a list, so the maintainer can decide separately whether MCP should gain `tls_allow_insecure` and `basic:`.
- [ ] **Step 5: Commit** `refactor(passthrough): MCP proxy uses the shared pipeline`.

### Task 3: Alias metadata, validation, unique index

**Files:**
- Modify: `src/secrets/metadataValidation.ts`
- Modify: `src/db/init.ts`
- Modify: `src/secrets/engine.ts`
- Modify: `src/api/secrets.ts` (three call sites: bulk import near line 119, POST near 396, PATCH near 448)
- Modify: `src/mcp/server.ts` (`gatehouse_put`, near line 550)
- Test: `test/secrets.metadataValidation.test.ts`, `test/secrets.test.ts`, `test/mcp.test.ts`

**Interfaces:**
- Produces:

```ts
export const PASSTHROUGH_ALIAS_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
/** List validation plus passthrough validation. Replaces validateListMetadata at every call site. */
export function validateSecretMetadata<T extends Record<string, string> | undefined>(metadata: T): MetadataValidation<T>;
// SecretsEngine
findByAlias(alias: string): StoredSecret | null;
```

Rules (spec D1): `passthrough_alias` matches the pattern. `upstream_url` is an absolute `http` or `https` URL with no query, fragment, or userinfo; it may carry a path. Both or neither, judged on the metadata that will be stored (for PATCH, check what `setMetadata` stores: if it merges, validate the merged result). If `allowed_domains` is also present, the `upstream_url` host must satisfy it (`hostAllowed`). An empty string for either key counts as absent.

Index, in `src/db/init.ts`:

```sql
CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_passthrough_alias
  ON secrets(json_extract(metadata, '$.passthrough_alias'))
  WHERE json_extract(metadata, '$.passthrough_alias') IS NOT NULL
    AND json_extract(metadata, '$.passthrough_alias') != ''
```

`findByAlias` queries with the same expression so it hits the index.

Duplicate handling: each write path calls `findByAlias` before writing. A hit on a different path is a 409. The body names the other secret's path only if the writer has `list` on it, otherwise `{"error": "passthrough_alias is already in use"}`. The unique index is the backstop: catch the constraint error and return the generic 409. Bulk import validates all items up front (it already does), including duplicates inside the batch, and imports nothing on conflict. MCP `gatehouse_put` returns the same text through `error(...)`.

- [ ] **Step 1: Write failing tests.** Validation: alias format (uppercase, leading hyphen, 64 chars, empty), alias without URL, URL without alias, URL with query, fragment, userinfo, `ftp:` scheme, relative URL, URL with path prefix accepted, `allowed_domains` disagreement rejected, agreement accepted. API: POST duplicate alias is 409; PATCH onto an existing alias is 409; PATCH that keeps a secret's own alias is 200; the 409 names the other path only with `list`; bulk import with an internal duplicate imports nothing; deleting a secret frees its alias. Engine: `findByAlias` hit and miss. Init: running `initDb` twice is clean, and against a db created before this change.
- [ ] **Step 2: Run the three test files.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `bun test`.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(passthrough): alias and upstream_url metadata with a unique index`.

### Task 4: Caller authentication

> Note (2026-11-19): `src/auth/verifyBearer.ts` already exists. It shipped in 0.23.0 with the interface below (`createBearerVerifier(config, db)`), and `authMiddleware` and the stdio MCP entry already use it. Do not recreate it. This task is now the login limiter extraction and the passthrough key.

**Files:**
- Create: `src/auth/verifyBearer.ts`
- Create: `src/auth/loginLimiter.ts`
- Create: `src/proxy/passthroughKey.ts`
- Modify: `src/auth/middleware.ts`, `src/api/auth.ts`
- Test: `test/passthroughKey.test.ts`, `test/auth.test.ts`

**Interfaces:**
- Produces:

```ts
// src/auth/verifyBearer.ts
export type BearerResult =
  | { ok: true; auth: AuthContext }
  | { ok: false; status: 401 | 403; error: string };
export function createBearerVerifier(config: GatehouseConfig, db?: Database):
  (token: string, sourceIp: string) => Promise<BearerResult>;

// src/auth/loginLimiter.ts (moved out of src/api/auth.ts, same behavior: 5 failures per IP per 60s)
export function checkRateLimit(ip: string): boolean;
export function recordFailure(ip: string): void;
export function retryAfterSeconds(ip: string): number;
export function _resetRateLimitForTests(): void;   // src/api/auth.ts re-exports this name

// src/proxy/passthroughKey.ts
export const PASSTHROUGH_KEY_PREFIX = "gatehouse_pt_";
export function encodePassthroughKey(roleId: string, secretId: string): string;
export function parsePassthroughKey(key: string): { roleId: string; secretId: string } | null;
export function createPassthroughKeyVerifier(db: Database, opts?: { ttlMs?: number; maxEntries?: number; now?: () => number }):
  (key: string, sourceIp: string) => Promise<BearerResult>;
export function _resetPassthroughKeyCacheForTests(): void;
```

`createBearerVerifier` is the body of `authMiddleware` after the header parse (root token, JWT, `totp-pending`, token IP allowlist, user re-check), with identical error strings and statuses. `authMiddleware` becomes: parse header, call the verifier, set `auth` or return the error.

Passthrough key: `gatehouse_pt_` + base64url (no padding) of `role_id + ":" + secret_id`, split on the first colon. Verification mirrors `/v1/auth/approle/login`: unknown role and wrong secret are both 401 `Invalid credentials`; suspension (403) and the IP allowlist (403) are checked after the secret verifies and on every request, cached or not. The resulting `AuthContext` is `{ identity: "approle:" + display_name, policies: <parsed from the row, every request>, source: "approle", role_id }`, the same identity a JWT for that role carries, so approval leases match.

Cache: key `sha256(key)` hex, value `{ secretHash, expiresAt }`, default `ttlMs` 300000, `maxEntries` 1000, oldest-inserted evicted first. A hit is valid only if the row's current `secret_hash` equals the cached one and the entry has not expired. Only successful verifications are cached. A cache miss that verifies updates `app_roles.last_used`. The verifier does not touch the login limiter; the route does (Task 7).

- [ ] **Step 1: Write failing tests** in `test/passthroughKey.test.ts`: encode and parse round-trip; parse rejects a wrong prefix, bad base64url, a payload with no colon, an empty role or secret; a `secret_id` containing a colon round-trips; verify succeeds; wrong secret 401; unknown role 401 with the same body; suspended role 403 both on a miss and on a cached hit; IP outside the allowlist 403 on a cached hit; policies changed in the db are reflected on the next cached request; rotating `secret_hash` makes the old key fail on the next request; `Bun.password.verify` runs once across two requests (inject a counting wrapper or assert via timing-free spy) and again after `ttlMs` with an injected `now`; eviction at `maxEntries`. In `test/auth.test.ts`: the existing middleware tests pass unchanged, plus one test calling the verifier directly for root, JWT, and a `totp-pending` token.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `bun test`.** Expected: PASS, no edits to existing auth tests.
- [ ] **Step 5: Commit** `feat(passthrough): reusable bearer verifier and passthrough keys`.

### Task 5: Request shaping (pure functions)

**Files:**
- Create: `src/proxy/passthroughRequest.ts`
- Test: `test/passthroughRequest.test.ts`

**Interfaces:**
- Produces:

```ts
/** rawRest is the undecoded request path after "/p/<alias>", "" or starting with "/". rawQuery is "" or starts with "?". */
export function joinUpstreamUrl(upstreamUrl: string, rawRest: string, rawQuery: string):
  { ok: true; url: string } | { ok: false };

/** Candidate caller credentials in spec D3 order, de-duplicated. meta may be null (unknown alias). */
export function extractCallerCredentials(headers: Headers, meta: { metadata?: Record<string, string> } | null): string[];

/** Header and value to inject. Same as resolveAutoInject, except auth_scheme "Basic" with a schemeless value yields "Basic " + btoa(value). */
export function resolvePassthroughInject(secretValue: string, meta: { metadata?: Record<string, string> } | null):
  { headerName: string; headerValue: string };

/** Request headers for the upstream: caller headers minus the strip list, plus the injected credential. */
export function buildUpstreamHeaders(headers: Headers, meta: { metadata?: Record<string, string> } | null, secretValue: string): Headers;

/** Response headers for the caller, each value scrubbed. Returns the redaction count. */
export function buildResponseHeaders(upstream: Headers, redactValues: string[]): { headers: Headers; redactions: number };

/** Rewrites a same-origin Location to /p/<alias>/..., or reports cross-origin. */
export function rewriteLocation(location: string, requestUrl: string, upstreamUrl: string, alias: string, publicBase: string):
  { ok: true; location: string } | { ok: false };
```

Rules:
- `joinUpstreamUrl` rejects a remainder with a `.` or `..` segment after percent-decoding, `%2f`, `%5c` (any case), or a literal backslash. It concatenates `upstream_url`'s path (trailing slash trimmed) with `rawRest`, appends `rawQuery`, parses the result, and requires its origin to equal `upstream_url`'s origin. An empty remainder yields `upstream_url` itself.
- `extractCallerCredentials` order: the secret's injection header (`metadata.header_name`, default `Authorization`) with its scheme prefix removed, and for `Basic` the base64-decoded password (text after the first colon); then `Authorization: Bearer`; then `x-api-key`. With `meta` null, only the last two.
- Request strip list: hop-by-hop (`connection`, `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailer`, `transfer-encoding`, `upgrade`, plus every header named in `Connection`), `host`, `content-length`, every `x-forwarded-*`, `x-real-ip`, `authorization`, `x-api-key`, and the secret's injection header. Then set the injected header.
- Response strip list: the hop-by-hop set, `content-length`, `content-encoding`. `set-cookie` passes (use `getSetCookie()` so multiple cookies survive). Every value goes through `scrubResponseBody`.
- `rewriteLocation`: resolve `location` against the upstream request URL. Same origin as `upstream_url` and path under its prefix: return `publicBase + "/p/" + alias + <path after the prefix> + <query>`. Anything else: `{ ok: false }`.

- [ ] **Step 1: Write failing tests**, one per rule above. Include Review Focus 4 (empty remainder, `/`) and 5 (remainder `//other.example.com/x` never yields a URL whose host is `other.example.com`), `%2e%2e`, `..%2f`, mixed-case `%2F`, query preserved byte for byte, an `upstream_url` with a path prefix, a caller credential in each location, a caller `Authorization` never present in the output headers when the injection header is `x-api-key` (and the reverse), a header named in `Connection` stripped, two `Set-Cookie` headers preserved, a secret echoed in a response header redacted and counted.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `bun test test/passthroughRequest.test.ts`.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(passthrough): URL join, credential extraction, header filtering`.

### Task 6: Streaming scrubber

**Files:**
- Create: `src/proxy/streamScrub.ts`
- Test: `test/streamScrub.test.ts`

**Interfaces:**
- Produces:

```ts
export type StreamEnd = "complete" | "byte_cap" | "idle_timeout" | "upstream_error" | "client_abort";
export interface ScrubStats { bytesIn: number; redactions: number; end: StreamEnd }
export function scrubStream(source: ReadableStream<Uint8Array> | null, opts: {
  redactValues: string[];
  maxBytes: number;
  idleMs: number;
  onEnd: (stats: ScrubStats) => void;   // called exactly once
  abortUpstream?: () => void;           // called on byte_cap, idle_timeout, client_abort
}): ReadableStream<Uint8Array>;
```

Behavior: values are matched as UTF-8 bytes and replaced with the bytes of `[REDACTED]`. Values shorter than 8 characters are skipped, the same rule as `scrubResponseBody`. After each chunk the last `maxValueByteLength - 1` bytes are held back and prepended to the next chunk; the tail is scrubbed and flushed at end of stream. With no usable redact values nothing is held back. `maxBytes` counts upstream bytes read: on overrun, emit what is under the cap, close, end `byte_cap`. `idleMs` is the longest wait for the next chunk: on expiry close, end `idle_timeout`. A `null` source yields an empty stream that ends `complete`. Consumer cancel ends `client_abort`. Output must be incremental: a chunk larger than the holdback produces output before the next chunk arrives.

- [ ] **Step 1: Write failing tests:** passthrough of bytes with no secrets is byte-identical (use random binary including invalid UTF-8); a secret inside one chunk; a secret split across two chunks at every split point; a secret split across three chunks; two different secrets; a secret at the very end of the stream; overlapping candidates; redaction count; first chunk is readable before the source produces the second (controlled source); `byte_cap` cuts at the cap and calls `abortUpstream`; `idle_timeout` with a small `idleMs`; a source that keeps producing for longer than `idleMs` in total survives; source error ends `upstream_error`; consumer cancel ends `client_abort` and calls `abortUpstream` (Review Focus 1); `onEnd` fires exactly once in every case; `null` source.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `bun test test/streamScrub.test.ts`.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(passthrough): streaming byte-level response scrubber`.

### Task 7: The `/p` route

**Files:**
- Create: `src/api/passthrough.ts`
- Modify: `src/index.ts` (mount, after the request-id and source-IP middleware; `/p` is outside `/v1/*` so the auth middleware does not apply)
- Modify: `package.json` (dev dependency `openai`)
- Test: `test/passthrough.test.ts`, `test/passthrough.sdk.test.ts`

**Interfaces:**
- Consumes: everything from Tasks 1, 3, 4, 5, 6.
- Produces: `export function passthroughRouter(deps: ProxyDeps & { db: Database; config: GatehouseConfig }): Hono`, mounted with `app.route("/p", ...)`. Register both `/:alias` and `/:alias/*` (Review Focus 4). Take the remainder from the raw request URL, not from a decoded Hono param.

Request flow, in this order:
1. Method not in GET, POST, PUT, PATCH, DELETE, HEAD: 405.
2. Login limiter: `checkRateLimit(sourceIp)` false gives 429 `rate_limited` with `Retry-After`.
3. Look up the alias (`findByAlias`). Extract candidate credentials (`meta` null when the alias is unknown). Try each: a `gatehouse_pt_` value goes to the key verifier, anything else to the bearer verifier. First success wins. No success: `recordFailure(sourceIp)`, then 401 `unauthenticated`, or the verifier's 403 as `forbidden` if any candidate produced one. This happens before the alias result is revealed.
4. Unknown alias: 404 `unknown_alias`.
5. `joinUpstreamUrl`. Failure: 400 `bad_path`.
6. Read the body as bytes for methods other than GET and HEAD. More than `GATEHOUSE_MAX_BODY_SIZE` (default 1048576): 413 (Review Focus 2).
7. `authorizeProxyCall` with `secretPaths: [path]`, `auditAction: "proxy.forward"`, `auditUrl` = the joined URL without its query, `auditExtra: { mode: "passthrough", alias }`. Denial mapping: `policy_denied` to 403 `forbidden`; `gate_blocked` with status 429 to 429 `rate_limited` plus its headers; `gate_blocked` with status 403 to 403 `approval_required`, carrying the gate body's fields; `path_prefix_blocked` to 403 `path_not_allowed`; `ssrf_blocked` to 403 `private_network_blocked`; `domain_blocked` to 403 `forbidden`; `secret_not_found` to 404 `unknown_alias`; `bad_protocol` and `invalid_url` to 400 `bad_path`.
8. Turn Bun's idle timeout off for this request, the way `/v1/events` does in `src/index.ts` (`c.env.timeout(c.req.raw, 0)`, guarded). The scrubber's `idleMs` is the idle timeout from here on.
9. Fetch with `buildUpstreamHeaders`, the raw body, `redirect: "manual"`, `tls: { rejectUnauthorized: false }` when `tlsInsecure`, and an abort controller. `max_timeout_ms` bounds time to response headers. Abort is 504 `upstream_timeout`; any other fetch error is 502 `upstream_unreachable`. Both call `recordProxyCall` and `recordProxyOutcome` with a `failureReason`.
10. `recordProxyCall` once headers arrive.
11. A 3xx with `Location`: `rewriteLocation`. Cross-origin: abort the upstream, 502 `upstream_redirect_cross_origin`, audit with that reason.
12. Respond with the upstream status, `buildResponseHeaders`, and `scrubStream(upstream.body, { redactValues: secretRedactionValues([value]), maxBytes: limits.max_body_bytes, idleMs: limits.max_timeout_ms, ... })`. In `onEnd`, call `recordProxyOutcome` with the status, header plus body redaction count, `failureReason` set to the `StreamEnd` when it is not `complete`, and `pattern: { url: <joined URL without query>, requestHeaderNames }` with no bodies.

Errors Gatehouse originates: JSON `{ "error", "code", "request_id" }` plus header `X-Gatehouse-Error: 1`. An upstream error response never carries that header (strip it from upstream responses).

- [ ] **Step 1: Write `test/passthrough.test.ts`** against a local `Bun.serve` upstream on port 0 and the app's `fetch`. Cover: each credential location and both credential forms; wrong key; 401 for an unknown alias with no credential and 404 with a valid one; 403 without `proxy`; five bad credentials then 429; rotated `secret_id`; suspended role; IP allowlist. Forwarding: the upstream receives the real secret in the configured header and never sees the caller credential in any header; binary request and response bodies byte-identical; query preserved; `upstream_url` path prefix; Anthropic-style secret (`header_name: x-api-key`, `auth_scheme: ""`); Basic secret. Every D7 code with its audit row, and `X-Gatehouse-Error: 1` present on each and absent on an upstream 500. Streaming: an SSE upstream whose first event is readable before it sends the second; a secret split across two upstream writes is redacted; byte cap cuts the stream and the audit row says `byte_cap`; client abort mid-stream closes the upstream and writes one audit row (Review Focus 1). Redirects: same-origin `Location` rewritten to `/p/<alias>/...`, cross-origin gives 502 and the upstream `Location` is not in the response. Review Focus 2 (chunked body over the limit is 413 and the upstream sees no request), 3 (HEAD, 204, 304), 4 (`/p/alias` and `/p/alias/`). Audit: `mode`, `alias`, no query string anywhere in the row; approval lease id on the row; `redaction_count`. Rate limits: per-AppRole and per-secret limits count passthrough calls and return 429 `rate_limited`. Posture: the redaction count shows up in `/v1/stats` the same way a `/v1/proxy` redaction does. Gzip upstream: body arrives decoded with no `Content-Encoding`.
- [ ] **Step 2: Write `test/passthrough.sdk.test.ts`.** Start the real server on a free port the way `test/firstBoot.test.ts` does, and a fake upstream that answers `POST /v1/chat/completions` with an SSE stream. Use the real `openai` package with `baseURL: http://127.0.0.1:<port>/p/example/v1` and `apiKey: <passthrough key>`. Assert a non-streaming call returns the fake completion, a streaming call yields chunks, and the upstream saw `Authorization: Bearer <real secret>`. Add a streaming case where the upstream pauses 12 seconds between two events and the stream still completes (this proves step 8; give the test a 30 second timeout). `openai` goes in `devDependencies` only: the image installs with `--production`.
- [ ] **Step 3: Run both.** Expected: FAIL.
- [ ] **Step 4: Implement the router and mount it.**
- [ ] **Step 5: Run `bun test`.** Expected: PASS.
- [ ] **Step 6: Commit** `feat(passthrough): /p/<alias> route with native streaming responses`.

### Task 8: Web UI and skill template

**Files:**
- Modify: `src/ui/index.html` (secret create and edit forms near the existing `header_name` fields, secret detail view, AppRole create and rotate reveal dialogs)
- Modify: `src/templates/skill.md`
- Test: `test/secretFormMetadata.test.ts`, `test/secretDetailRender.test.ts`, `test/skillTemplate.test.ts`, `test/uiAssets.test.ts` as fits

Follow the patterns those tests already assert for `header_name` and the other structured metadata fields.

- Secret form: a "Passthrough" group with "Alias" and "Upstream URL". Client-side checks mirror Task 3 (pattern, both or neither). A 409 from the server is shown on the alias field.
- Secret detail: when both keys are set, show the base URL `<origin>/p/<alias>` with a copy button, and one line: "Point an SDK's base URL here and use a Gatehouse credential as its API key."
- AppRoles: wherever a new `secret_id` is revealed (create, rotate), a "Copy passthrough key" button that builds `gatehouse_pt_` + base64url(`role_id:secret_id`) in the browser from the values on screen. No new endpoint.
- `src/templates/skill.md`: one short section. An agent holding a JWT can call `/p/<alias>/...` with plain `curl -H "Authorization: Bearer $TOKEN"`, and finds aliases in the `passthrough_alias` metadata that `gatehouse_list` already returns.

- [ ] **Step 1: Write failing tests** for the form state round-trip of both keys, the detail render with and without an alias, the key assembly function (same output as `encodePassthroughKey` for three inputs, including a `secret_id` with `+`, `/`, and `:`), and the skill template section.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `bun test`.** Expected: PASS. Then start the server locally and exercise the three surfaces in a browser, light and dark theme. Record what was and was not checked in the task report.
- [ ] **Step 5: Commit** `feat(passthrough): alias fields, base URL, and passthrough key in the UI`.

### Task 9: Docs and release

**Files:**
- Create: `site/src/content/docs/passthrough.mdx`
- Modify: `site/src/content/docs/for-agents.mdx`, `security.mdx`, `api-reference.mdx`, `concepts.mdx`, `README.md`, `CHANGELOG.md`, `src/version.ts`, `package.json`
- Regenerate: `docs/docs/**` (site build needs `bun --bun`)
- Modify: `docs/superpowers/specs/2026-11-19-passthrough-proxy-design.md` (status line)

- `passthrough.mdx`: what it is, the two metadata keys, the two credential forms, then recipes that were each run against a local fake upstream before being written down: OpenAI Python SDK, Anthropic SDK (`header_name: x-api-key`, `auth_scheme: ""`), `curl`, n8n, Home Assistant REST. State the limits: no WebSocket, no query-parameter credentials, no request signing, the byte cap cuts a stream without a clean error, cross-origin redirects return 502. A table of the D7 error codes and the `X-Gatehouse-Error` header. No angle-bracket placeholders inside pasteable commands.
- `security.mdx`: one sentence, `write` on a secret is equivalent to being able to disclose it (spec "Known exposure"), and a paragraph on what a passthrough key is (the AppRole credential in one token; rotate the `secret_id` to revoke).
- `README.md`: passthrough becomes the lead example; the JSON envelope moves below it.
- `CHANGELOG.md`: 0.24.0 block. Mention the pipeline refactor and that REST and MCP behavior is unchanged.

- [ ] **Step 1: Write the docs.** Run every recipe's command against a fake upstream and paste nothing that did not work.
- [ ] **Step 2: Bump `src/version.ts` and `package.json` to 0.24.0**, regenerate `docs/docs/**`, set the spec status to `shipped in 0.24.0`.
- [ ] **Step 3: Run `bun test` and `grep -rn $'\u2014' site/src README.md CHANGELOG.md src test docs/superpowers/plans/2026-11-19-passthrough-proxy.md`.** Expected: all pass, no matches.
- [ ] **Step 4: Commit** `feat(0.24.0): passthrough proxy: use the vault from any SDK by changing a base URL`. Stop here. Merging to `main`, tagging, and pushing to `github` need the maintainer's go-ahead.
