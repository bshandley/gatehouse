# Passthrough proxy: use the vault from any SDK by changing a base URL

Date: 2026-11-19
Status: shipped in 0.24.0 (amended 2026-11-20 to match what shipped: see
"As shipped in 0.24.0")
Target release: 0.24.0 (after recoverability 0.22.0 and distribution 0.23.0)

## Intent

Today the only way to make a credentialed call through Gatehouse is
`POST /v1/proxy` with a JSON envelope (`src/api/proxy.ts:252`) or the
`gatehouse_proxy` MCP tool. Only a client that has learned Gatehouse's protocol
can use it. Every existing SDK, CLI, script, n8n node, and Home Assistant
integration is locked out, and so is the whole homelab that is not an agent.

Passthrough mode makes Gatehouse look like the upstream API. The operator gives
a secret an alias and an upstream URL. Any client then points its base URL at
Gatehouse and puts a Gatehouse credential where the real key would go:

```sh
export OPENAI_BASE_URL=https://gatehouse.example.com/p/openai/v1
export OPENAI_API_KEY=gatehouse_pt_...      # a Gatehouse credential, not the real key
python my_script.py                          # unmodified, streaming included
```

Gatehouse authenticates the caller, runs every existing proxy control, swaps in
the real credential, and streams the upstream response back unchanged.

Why now: the comparable projects that found an audience all lead with "no code
changes". This is the smallest version of that promise, and it needs no CA
certificate on the client.

## Goals

- `ANY /p/<alias>/<rest>` forwards to `<upstream_url>/<rest>` with the bound
  secret injected, and returns the upstream status, headers, and body natively
  (no JSON envelope).
- Works with unmodified OpenAI-compatible and Anthropic SDKs, `curl`, and
  anything else with a configurable base URL and a single API-key slot.
- Streams responses (SSE and chunked) without buffering the whole body.
- Every control that applies to `/v1/proxy` applies here with identical
  semantics: `proxy` capability, AppRole and per-secret rate limits,
  approval-gated leases, `allowed_path_prefixes`, private-network policy,
  `tls_allow_insecure`, response scrubbing, audit, posture counters.
- A long-lived caller credential that fits in an API-key slot, with no new
  credential type to manage.
- One shared implementation of the proxy controls for REST, MCP, and
  passthrough.

## Non-goals

- `HTTPS_PROXY` / `CONNECT` forward-proxy mode with TLS interception. That is
  the follow-up for tools with no base-URL setting. Separate spec.
- WebSocket upgrade.
- `{{secret:path}}` template substitution in passthrough URLs, headers, or
  bodies. One alias binds exactly one secret.
- Credentials injected as query parameters, or request signing (AWS SigV4).
- Any feature that writes a policy for the user. An AppRole still needs a
  hand-authored policy granting `proxy` on the secret. Setting an alias grants
  nothing.

## Anti-goals

- A passthrough path that is weaker than `/v1/proxy`. If a control cannot be
  applied to a request, the request fails closed.
- The caller choosing the upstream host. The host comes only from the secret's
  metadata, written by someone with `write` on that secret.
- A raw secret value reaching the caller through an echoed header or body,
  including across stream chunk boundaries.

## Approaches

**A. Base-URL passthrough with an operator-defined alias (chosen).** Described
above. No client-side trust changes, works on any network path, the upstream is
pinned by the operator, and it reuses the per-secret metadata that already
exists (`header_name`, `auth_scheme`, `allowed_path_prefixes`). Cost: only
helps tools that expose a base-URL setting.

**B. `HTTPS_PROXY` forward proxy with TLS interception.** Covers every tool,
including ones with hard-coded hosts. Cost: a private CA that every client must
trust, certificate minting, `CONNECT` handling outside Hono, and a much larger
attack surface in a vault. Right second step, wrong first step.

**C. `/p/<secret-path>/<full upstream URL>` with no alias.** No new metadata.
Cost: secret paths contain slashes so the split is ambiguous, the caller picks
the host (back to relying only on `allowed_domains`), and SDKs cannot express
it as a base URL cleanly. Rejected.

The maintainer handed over the choice ("just pick the base-URL variant").
A is the pick.

## Design

### D1. Two new secret metadata keys

| Key | Rule |
|---|---|
| `passthrough_alias` | `^[a-z0-9][a-z0-9-]{0,62}$`. Unique across all secrets. |
| `upstream_url` | Absolute `http` or `https` URL. No query, fragment, or userinfo. May carry a path prefix. |

Both or neither. Validated on every write path that
`src/secrets/metadataValidation.ts` already covers (REST POST and PATCH, bulk
import, MCP put). If the secret also has `allowed_domains`, the `upstream_url`
host must satisfy it at write time. Uniqueness is enforced by a unique
expression index on `json_extract(metadata, '$.passthrough_alias')`, which also
makes the per-request alias lookup an index hit. A duplicate alias is a 409
naming the conflict only if the writer can `list` the other secret, otherwise a
generic 409.

A secret with no alias is unreachable through `/p/`. Passthrough is opt-in per
secret.

### D2. Route and URL mapping

`app.all("/p/:alias/*")`, mounted outside the `/v1/*` auth middleware, with its
own authentication (D3). Methods: GET, POST, PUT, PATCH, DELETE, HEAD. OPTIONS
is answered by the existing CORS middleware and never forwarded.

Upstream URL = `upstream_url` with its path joined to the raw remainder of the
request path, plus the original query string. The join must not let the caller
escape the configured prefix: reject (400) any remainder that contains a `..`
or `.` segment after percent-decoding, an encoded slash or backslash, or a
backslash. The joined URL's origin must equal the origin of `upstream_url`,
checked after construction.

### D3. Caller authentication in the API-key slot

An SDK has one place for a key and sends it wherever that API expects it. So
Gatehouse reads the caller's credential from the same header it is about to
overwrite. Lookup order, first hit wins:

1. The secret's injection header (`metadata.header_name`, default
   `Authorization`), with any scheme prefix removed. For `Basic`, the
   credential is the decoded password.
2. `Authorization: Bearer`.
3. `x-api-key`.

When the alias does not exist, steps 2 and 3 still run, and a request with no
valid credential gets `401` whether or not the alias exists. An authenticated
caller gets `404` for an unknown alias and `403` for an alias whose secret
they lack `proxy` on. That ordering keeps alias names from leaking to
unauthenticated probes.

Two credential forms are accepted:

- **A Gatehouse bearer token** (AppRole JWT, user JWT, root token), verified by
  the same code as `/v1/*`. Extract the verification body of
  `authMiddleware` into a reusable `verifyBearer(token, sourceIp)` so there is
  one implementation.
- **A passthrough key**: `gatehouse_pt_` followed by
  `base64url(role_id + ":" + secret_id)`. This is the AppRole's existing
  credential in a single-token shape, for clients that cannot refresh a 24 hour
  JWT. It is not a new credential type: rotating the AppRole's `secret_id`
  revokes it, suspension and the IP allowlist apply on every request, and
  nothing new is stored.

Passthrough keys are verified with `Bun.password.verify` (argon2), which is too
slow per request. Cache successful verifications in memory for 5 minutes, keyed
by `sha256(key)` and bound to the stored `secret_hash`, so a rotation
invalidates the entry on the next request. `suspended`, `ip_allowlist`, and
`policies` are read from `app_roles` on every request and never cached. Failed
passthrough-key verifications count against the existing login rate limiter
for the source IP. JWT and root-token candidates are verified without it, as on
`/v1/*` (see "As shipped in 0.24.0").

The web UI offers "Copy passthrough key" next to the new `secret_id` on
AppRole create. It is assembled client-side from values already on screen.
Rotate is not covered: it hands out a single-use link and never shows a
`secret_id`, so there is nothing on screen to build a key from.

### D4. Shared proxy pipeline

The controls live inline in a 500-line handler in `src/api/proxy.ts`, and again
in the `gatehouse_proxy` case in `src/mcp/server.ts` (around lines 589 to 857).
A third copy is not acceptable in a vault. Extract `src/proxy/pipeline.ts`:

- `authorizeProxyCall(...)`: policy check, `enforceProxyGates`, domain
  allowlist, path-prefix allowlist, private-network policy, protocol check.
  Returns either a structured denial (status, body, audit reason) or the
  resolved secret values, lease ids, and gate role id.
- `recordProxyOutcome(...)`: rate-limit accounting, audit row, pattern
  recording.

REST, MCP, and passthrough all call these. The refactor is behavior-preserving
for REST and MCP: `test/proxy.test.ts`, `test/proxyApprovalAudit.test.ts`,
`test/rateLimits.test.ts`, and `test/mcp.test.ts` pass unchanged. It lands as
its own commits before any passthrough code.

### D5. Request forwarding

- Body: forwarded as raw bytes, not parsed. The route enforces
  `GATEHOUSE_MAX_BODY_SIZE` itself, on the declared length and on the bytes
  read (`413 body_too_large`).
- Headers: forward everything except hop-by-hop headers, `Host`,
  `Content-Length` (recomputed), `X-Forwarded-*`, `X-Real-IP`, `Forwarded`,
  `Via`, `Range`, `If-Range`, `Accept-Encoding`, `Expect`, and every header
  that D3 reads a credential from. No Gatehouse credential may ever reach the
  upstream.
- Injection: `resolveAutoInject(secretValue, meta)` as today. A secret whose
  value is `user:password` with `auth_scheme` `Basic` is base64-encoded, the
  same result as the `basic:` inject shorthand.
- `redirect: "manual"`, `tls_allow_insecure` honored, as today.

### D6. Response streaming and scrubbing

- Status passes through, unless it is outside 200 to 599 (see "As shipped in
  0.24.0"). Response headers pass through except hop-by-hop,
  `Content-Length`, and `Content-Encoding` (Bun's fetch has already decoded the
  body). `Set-Cookie` passes through. Every header value is scrubbed.
- The body is streamed through a byte-level scrubber that redacts the same
  values `secretRedactionValues` produces. It holds back a fixed tail of the
  longest value's length minus 1 bytes so a secret split across two chunks is
  still caught. It flushes the tail only at a normal end of stream; on every
  abnormal end the tail is dropped (see "As shipped in 0.24.0").
- `max_body_bytes` is a cap on total bytes streamed. On overrun the stream is
  cut and the audit row says so. The status has already been sent, so there is
  no clean error: the body ends normally on the wire. Documented.
- `max_timeout_ms` bounds time to response headers, then acts as an idle
  timeout between chunks. A stream that keeps producing is not cut for being
  long.
- Redirects: a `Location` on the upstream's own origin is rewritten to the
  matching `/p/<alias>/...` URL. A cross-origin `Location` is not forwarded:
  the caller gets `502` with error code `upstream_redirect_cross_origin`,
  because a client that follows it may resend its Gatehouse credential to a
  third party.

### D7. Errors that Gatehouse originates

JSON `{ "error", "code", "request_id" }` with header `X-Gatehouse-Error: 1`, so
a human reading SDK output can tell a vault denial from an upstream error.
Codes: `unauthenticated` (401), `forbidden` (403), `unknown_alias` (404),
`rate_limited` (429, with `Retry-After`), `approval_required` (403, carrying
the same lease fields `/v1/proxy` returns), `path_not_allowed` (403),
`private_network_blocked` (403), `bad_path` (400),
`upstream_redirect_cross_origin` (502), `upstream_unreachable` (502),
`upstream_timeout` (504). The code has four more, listed in "As shipped in
0.24.0".

### D8. Audit, patterns, posture

- Audit action stays `proxy.forward`, with `metadata.mode = "passthrough"` and
  `metadata.alias`. Target host, path, method, status, lease id, and redaction
  count as today. The query string is not logged, in the audit row or in the
  request log line.
- Pattern learning records method, URL template, request header names, and
  status. No request or response bodies from passthrough.
- The redaction count feeds the same posture counter as `/v1/proxy`.

### D9. Surfaces

- Web UI, secret form: a "Passthrough" group with alias and upstream URL, and
  on the detail view the resulting base URL with a copy button.
- Web UI, AppRoles: "Copy passthrough key" on create (D3).
- `src/templates/skill.md` and the For Agents doc: one short section. An agent
  holding a JWT can call `/p/<alias>/...` with plain `curl` instead of building
  a `/v1/proxy` envelope.
- `gatehouse_list` and `GET /v1/secrets` already return metadata, so agents
  discover aliases with no new endpoint.
- Docs: a Passthrough page with tested recipes for the OpenAI Python SDK, the
  Anthropic SDK (`header_name: x-api-key`, `auth_scheme: ""`), `curl`, n8n, and
  Home Assistant's REST integration. README: passthrough becomes the lead
  example, the JSON envelope moves below it.

## As shipped in 0.24.0

Recorded 2026-11-20, after the final review. Where this section and the body
above differ, this section is what the code does.

- **Copy passthrough key** is on AppRole create only. Rotate shows no
  `secret_id`, so the docs give a one-line shell command for building the key
  by hand.
- **Error codes beyond D7**: `405 method_not_allowed` (any method outside
  GET, POST, PUT, PATCH, DELETE, HEAD; carries `Allow`), `413 body_too_large`,
  `500 gates_unavailable` (the rate-limit or approval gates cannot be applied,
  so the request fails closed), and `500 internal_error` (the response stream
  could not be set up). An upstream status outside 200 to 599 cannot be passed
  on (the Response constructor rejects it): it is answered `502
  upstream_unreachable`, the audit row has reason `invalid_status`, and the
  upstream body is cancelled. No new code for it.
- **Fixed hold-back, dropped on every abnormal end.** The scrubber always
  holds back the last (longest redact value in bytes, minus 1) bytes, whatever
  they contain, and drops them on `byte_cap`, `idle_timeout`,
  `upstream_error`, and `client_abort`. Only a normal end flushes them. Reason:
  a hold that depended on content (holding only a tail that looks like the
  start of the secret) would make emission timing a prefix oracle. Against an
  upstream that echoes caller input, a caller could send a guess and watch
  whether it is delayed, or dropped at a cut it arranged, and recover the
  secret one character at a time.
- **Cut streams end normally on the wire.** On `byte_cap` and `idle_timeout`
  the scrubbed stream is closed, not errored. The final review ruled that it
  should error instead, so a client sees a failed transfer, provided Bun
  delivers an unclean end. It does not: on Bun 1.3.14, through the real `/p`
  route, an errored response stream still ends with the normal `0\r\n\r\n`
  chunk (curl exits 0, a `fetch` body read resolves), and Bun prints the error
  to stderr. So the close stays, and a client cannot tell a cut from
  completion. The audit row is a failure (`success` false) with the reason.
- **Request headers stripped** in addition to D5's list: `Range` and
  `If-Range` (the scrubber needs the whole body), `Accept-Encoding` (the fetch
  decodes only encodings it asked for), and `Expect` (the body is read in full
  before forwarding).
- **Private-network check is hostname-based.** It classifies the literal host
  in the joined URL and does no DNS lookup, so it offers no defence against a
  public name that resolves to a private address (shared with `/v1/proxy`).
- **Login limiter scope.** On `/p`, the per-IP login limiter is consulted and
  charged only around a passthrough-key verification. A request with no
  credential gets its `401` without touching it. JWT and root-token candidates
  are verified without it, as on `/v1/*`. Before a `gatehouse_pt_` candidate is
  verified the limiter is checked (`429 rate_limited` with `Retry-After` when
  exhausted, after any JWT or root candidate ahead of it has failed), and a
  failed key charges it once per request. A valid JWT therefore works while the
  IP is locked out for bad keys. Reason: bearer tokens are not brute-forceable,
  and gating them let anonymous junk requests shut passthrough off for every
  client behind a source IP.
- **Upstream content is sandboxed.** Every response that carries upstream
  content gets `Content-Security-Policy: sandbox`, replacing any upstream CSP,
  because it is served from the vault UI's origin.

## Constraints

- Single instance, in-process: the verification cache is a plain `Map` with a
  size bound.
- Bun's HTTP server closes idle connections by default, and `src/index.ts`
  sets no `idleTimeout` today. The builder must confirm how long a quiet
  stream survives (check how `/v1/events` stays open) and set a per-request or
  server timeout that agrees with D6 before writing the stream. The streaming
  tests in this spec are what prove it.
- No new runtime dependencies.
- The key prefix is `gatehouse_pt_`. Do not shorten it to anything that
  resembles another provider's token format (push protection scans for those).
- No em dashes. Docs and tests use `api-keys/example` and
  `https://api.example.com`.

## Known exposure, unchanged by this work

A principal with both `write` and `proxy` on a secret can point
`upstream_url` at a host they control and receive the injected credential.
The same principal can already do this today by editing `allowed_domains` and
calling `/v1/proxy`. `write` on a secret is, and remains, equivalent to being
able to disclose it. The Security page should say so in one sentence.

## Testing

- Pipeline refactor: existing proxy, approval, rate-limit, and MCP suites pass
  unchanged.
- Metadata: alias format, both-or-neither, uniqueness (including PATCH onto an
  existing alias and bulk import with an internal duplicate), `upstream_url`
  shape, `allowed_domains` agreement.
- Auth: each credential location, each credential form, wrong key, rotated
  key (cache invalidation), suspended role, IP allowlist, 401 before 404.
- Path: prefix join, `..`, encoded traversal, encoded slash, query
  preservation, origin pinning.
- Forwarding: against a local `Bun.serve` upstream. Caller credential never
  arrives upstream in any header. Binary body round-trips byte-identical.
- Streaming: SSE arrives incrementally (first chunk before the upstream
  finishes), a secret split across two chunks is redacted, the byte cap cuts
  the stream, idle timeout fires, long active streams survive.
- Redirects: same-origin rewrite, cross-origin 502.
- Every denial code in D7, each with its audit row.
- One end-to-end test with the real OpenAI SDK pointed at a fake upstream, if
  the SDK can be a dev dependency without touching the production image.
  Otherwise a `curl`-shaped request that mirrors what the SDK sends.

## Left to the builder

- Module layout under `src/proxy/` beyond `pipeline.ts`.
- The exact hop-by-hop header list (start from RFC 9110 section 7.6.1).
- Cache size bound and eviction.
- UI layout of the Passthrough group, within the existing secret form
  patterns.

## Rollout

1. Shared pipeline extraction (D4), no behavior change.
2. Metadata keys, validation, index (D1).
3. Route, auth, forwarding, streaming scrub (D2, D3, D5, D6, D7, D8).
4. UI and skill template (D9).
5. Docs and recipes, release 0.24.0.
