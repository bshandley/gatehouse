# Gatehouse credential vault, read and install

You are about to start using a Gatehouse vault for authenticated API
calls. Before you do anything else in this conversation, install these
instructions so future sessions will automatically use Gatehouse
without being re-told.

This document contains a one-time bootstrap token. The token is only
consumed when you call `/exchange` in Step 2, NOT when you fetch this
document. If your context gets compacted mid-install or you lose these
instructions, you can re-fetch the same URL until exchange. Do not
log, echo, or store the token anywhere except to make the exchange
call in Step 2.

Your identity for this vault: **{{ROLE_DISPLAY_NAME}}**
Your policies: {{POLICIES}}

## Step 1: Detect your harness

Your own identity is the most reliable signal. A host machine can
have `~/.hermes/`, `~/.claude/`, and `~/.openclaw/` all at once,
because the operator runs multiple agents on it, so filesystem markers
are the WEAKEST evidence. Work this ladder top-down and stop at the
first match:

1. **Self-identification.** If you already know which runtime you
   are (Claude Code, opencode, Hermes Agent, OpenClaw, Codex, Cursor,
   Windsurf, Copilot CLI, Gemini CLI, or anything else), pick that
   one and skip the rest of the ladder. Do not second-guess your own
   identity from filesystem contents, those belong to other agents
   sharing the host.
2. **Tool signals.** If you genuinely don't know:
   - A `skill_manage` tool means **Hermes Agent**.
   - A `Skill` tool that loads from `~/.claude/skills/` means
     **Claude Code**.
3. **Filesystem, as a last resort.** Only if the two steps above
   didn't resolve, AND exactly one of `~/.hermes/`, `~/.openclaw/`,
   `~/.claude/` exists, use that as the harness. If two or more
   exist, stop and ask the operator which runtime this is.
4. **Generic file-writer fallback.** File tools but no skills system
   and no clear identity: write `.env.gatehouse` and update
   `AGENTS.md` in the current working directory. This is the right
   bucket for Codex, Cursor, Windsurf, opencode without self-ID, and
   anything else that can edit files but doesn't have a harness-native
   skills directory.
5. **No filesystem at all.** Hold credentials in conversation state
   only and tell the operator the next session will need a new
   onboarding link.

## Step 2: Exchange the bootstrap token

Make exactly one call:

    POST {{BASE_URL}}/v1/onboard/{{ONBOARD_TOKEN}}/exchange

No body. No Authorization header. The response contains your durable
AppRole credentials and a 24h JWT:

    {
      "token": "<jwt>",
      "role_id": "role-...",
      "secret_id": "...",
      "base_url": "{{BASE_URL}}",
      "mcp_url": "{{BASE_URL}}/v1/mcp",
      "role_display_name": "{{ROLE_DISPLAY_NAME}}",
      "policies": [...],
      "expires_in": 86400
    }

Hold these values in memory. Never echo role_id, secret_id, or the
JWT into conversation output, logs, or tool arguments visible to the
user. They only get written to the specific credential location in
Step 3.

If exchange returns 410 Gone, the token has already been used or
expired. Stop and tell the operator to generate a new onboarding link.

If exchange returns 403, either your source IP is not in the AppRole's
allowlist, or the AppRole has been suspended. Stop and tell the
operator.

## Step 3: Persist credentials and install the skill

The skill body for Step 5 is delimited by the markers
`<!-- GATEHOUSE-SKILL-BEGIN -->` and `<!-- GATEHOUSE-SKILL-END -->`.
Copy the content between those markers verbatim (excluding the markers
themselves) into the path specified for your harness.

Based on Step 1:

### Hermes Agent

Write to `~/.hermes/.env`:

    GATEHOUSE_URL=<base_url>
    GATEHOUSE_ROLE_ID=<role_id>
    GATEHOUSE_SECRET_ID=<secret_id>

Then call `skill_manage` with action `create`, name `gatehouse`, and
the skill body from Step 5. Verify with `skill_view`.

### OpenClaw

Write the three env vars above to `~/.openclaw/workspace/.env`.
Write the Step 5 body to `~/.openclaw/skills/gatehouse/SKILL.md`.
Append one line to `~/.openclaw/workspace/MEMORY.md`:

    Use the gatehouse skill for all authenticated API calls.

### Claude Code

Write the env vars to `~/.claude/.env.gatehouse` and tell the user to
source it or export the variables.
Write the Step 5 body to `~/.claude/skills/gatehouse/SKILL.md`.

### Generic file-writer (opencode, Codex, Cursor, Windsurf, or similar)

Write the env vars to `.env.gatehouse` in the current working
directory. Tell the user to source it.
Append only the "Operating rules" and "Situation, tool" sections of
Step 5 to `AGENTS.md` at the repo root, under a `## Gatehouse`
heading. These harnesses don't have a skills system, so the full
skill body is more than they need.

Do NOT write into `~/.hermes/`, `~/.openclaw/`, or `~/.claude/` from
this bucket. Those belong to other agents on the same host.

### No filesystem

Hold the JWT in conversation state only. Keep it out of tool outputs.
Tell the operator you'll need a new onboarding link next session.

## Step 4: Confirm

Reply in one line:

    Gatehouse installed at <path>, role {{ROLE_DISPLAY_NAME}}, policies {{POLICIES}}.

Or, if no persistence:

    Gatehouse session-only, role {{ROLE_DISPLAY_NAME}}. New onboard link
    needed next session.

Then wait for the next instruction. Do not attempt any API calls
before completing Step 3.

## Step 5: Skill body (write verbatim to the path from Step 3)

<!-- GATEHOUSE-SKILL-BEGIN -->
---
name: gatehouse
description: Use when calling any authenticated external HTTP API, when an API key or bearer token is needed, when the user mentions credentials, secrets, vault, tokens, or keys, when a 401/403 comes back from an upstream API, or when picking up temporary database or SSH credentials (dynamic secrets, checked out via gatehouse_checkout). Routes all credential access through the Gatehouse vault so raw secrets never enter the agent context window.
---

# Gatehouse

A Gatehouse vault holds credentials for this environment. You never
see raw credential values. You describe HTTP requests and Gatehouse
injects secrets server-side.

## Connect

The three env vars `GATEHOUSE_URL`, `GATEHOUSE_ROLE_ID`, and
`GATEHOUSE_SECRET_ID` hold everything you need. Never read, print,
echo, log, or pass role_id or secret_id as literals in code, tool
calls, or output. Read them from the environment only at the moment
you exchange them for a JWT.

Login: `POST {GATEHOUSE_URL}/v1/auth/approle/login` with body
`{"role_id": "$GATEHOUSE_ROLE_ID", "secret_id": "$GATEHOUSE_SECRET_ID"}`.
Store the returned JWT in memory only. The JWT expires in 24h.

To extend a session before expiry without re-reading role_id/secret_id,
call `POST {GATEHOUSE_URL}/v1/auth/refresh` with the current valid JWT
as `Authorization: Bearer <jwt>`. The response is a fresh JWT with a
full 24h TTL. Refresh is the recommended path for long-running agents
(it also re-checks AppRole suspension and IP allowlist, so a revoked
role can't keep refreshing). On 401 from `/refresh`, the token is
already expired or the role was deleted, fall back to a full re-login
from role_id/secret_id.

Prefer the streamable HTTP MCP endpoint at `{GATEHOUSE_URL}/v1/mcp`
when your harness supports it. The tools listed below are exposed
there natively.

## HTTP fallback (when MCP tools aren't wired up)

If your harness can only make raw HTTP calls, every `gatehouse_*` tool
below maps to an authenticated endpoint. Send `Authorization: Bearer
<jwt>` on each.

| Tool | HTTP |
| --- | --- |
| `gatehouse_list` | `GET /v1/secrets?prefix=<p>` returns `{"secrets": [...]}`. Static and dynamic entries are merged; each entry has a `kind: "static" \| "dynamic"` field. `prefix` is starts-with on the full path (`prefix=api` matches `api-keys/...`, NOT `services/api-foo`). |
| `gatehouse_patterns` | `GET /v1/proxy/patterns?secret=<path>` returns `{"patterns": [...]}` with fields `method`, `url_template`, `request_headers`, `request_body_schema`, `confidence`. Static secrets only. |
| `gatehouse_proxy` | `POST /v1/proxy` with the body shape in "Injection styles" below. Static secrets only. |
| `gatehouse_get` | `GET /v1/secrets/<path>/value` (requires `read`). Static secrets only. |
| `gatehouse_lease` | `POST /v1/lease/<path>` with `{"ttl": 300}`. Returns `{lease, value}`. STATIC secrets only. |
| `gatehouse_checkout` | `POST /v1/dynamic/<path>/checkout` with `{"ttl": 300}`. DYNAMIC secrets only (SSH, DB). Returns `{lease_id, path, provider_type, credential, ttl_seconds, expires_at}`. |
| `gatehouse_revoke` | `DELETE /v1/lease/<lease_id>`. Works for both static and dynamic lease IDs (dispatch is by `lease-` vs `dlease-` prefix on the server). `DELETE /v1/dynamic/lease/<lease_id>` still works as an alias. |
| (no MCP tool) | `GET /v1/lease` returns your active leases (static + dynamic merged). Each entry has `kind: "static" \| "dynamic"`, `id`, `path`, `identity`, `expires_at`, plus `provider_type` for dynamic. Useful for finding a lease ID you forgot to record. |
| `gatehouse_status` | `GET /v1/auth/whoami` returns `{identity, policies, source, expires_at, expires_in}` for the current bearer token. Use it to check who you are, what you're allowed to do, and how long until your JWT expires (so you can `/v1/auth/refresh` before it does). |
| (no MCP tool) | `GET /v1/skill` returns the current skill body rendered for your policies. Overwrite your installed skill file with the response to pick up template improvements without re-onboarding. Auth: your normal Bearer JWT. |
| (no MCP tool) | `POST /v1/rotate/<token>/exchange` is the consume endpoint of the operator-initiated rotate flow. The operator hands you a one-shot rotate URL when your `secret_id` needs to change; you fetch the URL for instructions, then call exchange to receive the new `secret_id` (your `role_id` and policies stay the same). |
| `gatehouse_scrub` | `POST /v1/scrub` with `{"text": "..."}`. |

## First call to any secret, in order

1. `gatehouse_list` (prefix optional). Returns every secret you can
   use, static and dynamic merged. HTTP response is
   `{"secrets": [...]}`; MCP returns the array directly. Per-entry
   fields:
   - `kind`: `"static"` (stored value, API key style) or `"dynamic"`
     (ephemeral credential minted on demand, SSH cert or DB user).
     Branch on this before picking a tool.
   - `caps`: capabilities you hold on this secret, e.g.
     `["read","proxy"]`. Filter by `caps.includes("proxy")` when
     you're looking for something to call through the proxy.
   - Static only: `pattern_count` (how many known-good request shapes
     exist) and `top_pattern` (the highest-confidence pattern, e.g.
     `POST http://10.0.0.102:5230/api/v1/memos`). `top_pattern` IS
     your endpoint.
   - Dynamic only: `provider_type` (e.g. `postgresql`, `ssh-cert`) and
     a `metadata` object with advisory routing info (`allowed_hosts`
     for ssh-cert, `host`/`port`/`database` for DB providers). These
     are not called via `gatehouse_proxy`; use `gatehouse_checkout` to
     mint a credential.
   Prefix is starts-with on the full path, not a substring match.
   Use `prefix=services/` to see all `services/*`, not `prefix=memos`
   to find `services/memos-pat`.
2. **If `gatehouse_list` returns an empty array, STOP.** Your policy
   grants nothing. Do not probe, scan, or guess endpoints, the
   credential you need is not reachable by you. Tell the operator
   their AppRole needs policies attached and wait. The same applies
   mid-task: if the specific secret you need is missing from the
   list, stop and ask, don't go looking for the upstream service by
   hand.
3. If `pattern_count > 0` for your target secret, call
   `gatehouse_patterns` with the secret path and copy the
   top-confidence pattern's method, URL, headers, and body schema.
   Don't guess, don't probe, don't scan for ports. Another agent
   already verified this shape.
4. If `pattern_count == 0`, read `allowed_domains` from the secret's
   metadata, that's the canonical host. Still don't probe, use what's
   listed. Your first successful call seeds the pattern for the next
   agent.
5. Call `gatehouse_proxy` with the template or inject shorthand
   (below). Never `gatehouse_get` just to read a value into context.

## Dynamic secrets (SSH, DB)

Entries with `kind: "dynamic"` are NOT stored values, they are
generators. Each `gatehouse_checkout` mints a fresh credential on the
backend (a signed SSH certificate, an ephemeral DB user, etc.) that
auto-revokes at TTL. Treat them like leases with a single return value
and a clock.

- Discover them through `gatehouse_list` like anything else. If a
  dynamic secret you need is absent from the list, your policy
  doesn't grant `lease` on it, apply the same "STOP, ask the
  operator" rule as for static secrets.
- Check out with `gatehouse_checkout` (MCP) or
  `POST /v1/dynamic/<path>/checkout` (HTTP). The response body
  includes a `credential` object whose shape depends on
  `provider_type`: SSH cert configs return
  `{private_key, certificate, username, ...}`, DB providers return
  `{username, password, host, ...}`.
- Do NOT pass the credential to `gatehouse_proxy`. Proxy only knows
  static secrets. Consume the credential directly in your tool call
  (SSH client, DB driver).
- **Routing**: the entry's `metadata` in `gatehouse_list` and matching
  fields on the checkout response tell you where to connect. For
  `ssh-cert`, read `credential.allowed_hosts` and pick one of those
  IPs/hostnames. For DB providers, `credential.host` /
  `credential.port` / `credential.database` are your target. If
  `allowed_hosts` is empty or absent, ask the operator instead of
  guessing.
- **SSH specifics**:
  - Read `credential.principals` and use one of those as the SSH
    username. The cert is bound to those names.
  - Write `credential.private_key` and `credential.certificate` to
    TWO SEPARATE files using the OpenSSH sibling convention: pick a
    base path like `/tmp/gh_key` and write the private key there
    (mode 0600), then write the certificate to the same path with
    `-cert.pub` appended (e.g. `/tmp/gh_key-cert.pub`). `ssh -i
    /tmp/gh_key ...` will auto-discover the cert. Use one shell
    expansion (jq or python piped to `>` redirect). Do NOT
    concatenate the two contents into one file — it will parse as a
    malformed pubkey and SSH will silently skip cert auth.
  - Prefer the sibling convention above to `-o CertificateFile=`.
    Some OpenSSH builds error out with `Load key: error in libcrypto`
    when the cert is passed via the explicit flag depending on file
    ordering or trailing-whitespace edge cases. The sibling
    convention always works.
  - Do NOT `cat`, `head`, or otherwise echo the files to verify.
    Many harnesses scrub credential-shaped strings from tool output,
    so the content will look redacted even though the file is intact.
    If you need to check the files landed, use `wc -c <path>` (byte
    count) or `stat <path>`, which reveal nothing.
  - Do NOT run `ssh-keygen -l -f <private-key>` to verify. That
    command expects a public key or cert and will error on a private
    key in a way that looks like corruption. Use `ssh-keygen -L -f
    <cert>` to inspect the CERT (principals, validity, CA
    fingerprint) — that's safe and useful for debugging.
  - Do NOT try to "verify cert and key match" by extracting base64
    blobs from the cert file and comparing to the private key. The
    cert is a wire-format SSH structure, not a bare pubkey, so any
    naive comparison will look like a mismatch. The credential
    Gatehouse returns is always internally consistent (private_key,
    public_key, and certificate are a matched triple, asserted by a
    test). If SSH still fails, the cause is somewhere else: wrong
    username, wrong host, agent interference, server CA trust, etc.
  - Always pass `-o IdentitiesOnly=yes -o IdentityAgent=none` to
    `ssh`. Without these, keys in your local ssh-agent get offered
    first and sshd closes the connection for too many auth failures
    before ever seeing the cert.
  - `credential.usage` on the response gives you the canonical
    command shape for the current credential. Copy it verbatim,
    don't "improve" it.
- `gatehouse_revoke` works on dynamic `lease_id`s too. Revoke as
  soon as you're done, don't wait for the TTL.
- Never `gatehouse_get` or `gatehouse_lease` a dynamic path, both
  will miss. Dynamic configs live on a separate path namespace on
  the server.

## Operating rules

1. Never echo role_id, secret_id, JWT, or any secret value into
   context, logs, or output.
2. For any authenticated outbound API call against a STATIC secret,
   use `gatehouse_proxy`. It keeps the credential out of your context
   entirely.
3. On 4xx/5xx from upstream, the `gatehouse_proxy` response includes
   a `suggestions` array of up to 5 verified patterns for that secret.
   Use them before retrying.
4. If an SDK refuses HTTP-level injection, fall back to
   `gatehouse_lease` with a 60-600 second TTL. Call `gatehouse_revoke`
   the moment you're done. Use `gatehouse_get` only if both proxy and
   lease are unavailable.
5. For DYNAMIC secrets (entries with `kind: "dynamic"`), use
   `gatehouse_checkout`, not `gatehouse_lease` or `gatehouse_proxy`.
   See the Dynamic secrets section above.
6. Before returning or logging any text that might contain a
   credential (stack traces, tool output, echoed requests), pass it
   through `gatehouse_scrub`.
7. **Metadata is in `gatehouse_list` already.** Every secret's
   `kind`, `allowed_domains`, `header_name`, `auth_scheme`, `caps`,
   `pattern_count`, `top_pattern`, and `provider_type` are returned
   by `gatehouse_list`. Don't fetch a secret by path just to inspect
   metadata. Never call `gatehouse_get` just to see metadata, it
   returns the raw value and requires `read`.

## Injection styles for gatehouse_proxy

**Template**: `{{secret:path}}` placeholders anywhere in headers, URL,
or body. Gatehouse substitutes server-side.

**Inject shorthand**: map header name to secret path. Authorization
headers auto-prefix "Bearer ". Prefix with `basic:` for HTTP Basic
auth with a `user:password` value.

    "inject": {"Authorization": "api-keys/openai"}
    "inject": {"Authorization": "basic:infra/opnsense"}

**Auto-inject**: pass secret paths in an array. Defaults to
`Authorization: Bearer <value>`. Per-secret metadata `header_name`
(e.g. `X-API-Key`) and `auth_scheme` (empty string disables Bearer)
override this.

    "auto_inject": ["api-keys/anthropic"]

## Situation, tool

{{SITUATION_TABLE}}

## Error decoder

- **401 from Gatehouse**: JWT expired. Re-login with role_id +
  secret_id from the environment. Retry once.
- **403 on proxy**: policy lacks `proxy` on that secret path, OR the
  target domain isn't in the secret's `allowed_domains` metadata, OR
  the target is a private IP and the secret has `allow_private=false`.
  Check `gatehouse_status` and `gatehouse_list`. Don't work around,
  tell the operator.
- **403 on lease or checkout**: policy lacks `lease` on that secret
  path. Confirm with `gatehouse_list` (does the entry appear? what
  are its `caps`?) and tell the operator if `lease` is missing.
- **`Dynamic secret not found` on checkout**: you called
  `gatehouse_checkout` against a path that isn't a dynamic config,
  or you called `gatehouse_lease`/`gatehouse_get` against a dynamic
  path. Re-read the entry's `kind` in `gatehouse_list` and pick the
  matching tool.
- **4xx/5xx from upstream**: use the `suggestions` in the error
  response before retrying.
- **Secret not in gatehouse_list**: your policy doesn't grant any
  usable access to it. Ask the operator to extend your policy. This
  applies to static AND dynamic secrets, both appear in the same
  list.
<!-- GATEHOUSE-SKILL-END -->
