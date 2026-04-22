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

Pick the first option that matches your runtime:

1. **Hermes Agent** if you have a `skill_manage` tool, or `~/.hermes/`
   exists on disk.
2. **OpenClaw** if `~/.openclaw/` exists on disk.
3. **Claude Code** if you have Write/Edit tools and `~/.claude/` exists
   or is writable.
4. **Codex / Cursor / Windsurf** if you have file tools but no skills
   system and no `~/.claude/` or `~/.hermes/`. You can write to
   `AGENTS.md` at the current working directory.
5. **None of the above** if you have no persistent filesystem. Use these
   instructions for this session only and tell the operator the next
   session will need a new onboarding link.

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

### Codex / Cursor / Windsurf

Write the env vars to `.env.gatehouse` in the current working
directory. Tell the user to source it.
Append only the "Operating rules" and "Situation, tool" sections of
Step 5 to `AGENTS.md` at the repo root, under a `## Gatehouse`
heading. These harnesses don't have a skills system, so the full
skill body is more than they need.

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
description: Use when calling any authenticated external HTTP API, when an API key or bearer token is needed, when the user mentions credentials, secrets, vault, tokens, or keys, when a 401/403 comes back from an upstream API, or when picking up temporary database or SSH credentials. Routes all credential access through the Gatehouse vault so raw secrets never enter the agent context window.
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
Store the returned JWT in memory only. The JWT expires in 24h; re-login
on 401. Prefer the streamable HTTP MCP endpoint at
`{GATEHOUSE_URL}/v1/mcp` when your harness supports it. The tools
listed below are exposed there natively.

## HTTP fallback (when MCP tools aren't wired up)

If your harness can only make raw HTTP calls, every `gatehouse_*` tool
below maps to an authenticated endpoint. Send `Authorization: Bearer
<jwt>` on each.

| Tool | HTTP |
| --- | --- |
| `gatehouse_list` | `GET /v1/secrets?prefix=<p>` returns `{"secrets": [...]}`. `prefix` is starts-with on the full path (`prefix=api` matches `api-keys/...`, NOT `services/api-foo`). |
| `gatehouse_patterns` | `GET /v1/proxy/patterns?secret=<path>` returns `{"patterns": [...]}` with fields `method`, `url_template`, `request_headers`, `request_body_schema`, `confidence`. |
| `gatehouse_proxy` | `POST /v1/proxy` with the body shape in "Injection styles" below. |
| `gatehouse_get` | `GET /v1/secrets/<path>/value` (requires `read`). |
| `gatehouse_lease` | `POST /v1/lease/<path>` with `{"ttl": 300}`. Returns `{lease, value}`. |
| `gatehouse_revoke` | `DELETE /v1/lease/<lease_id>`. |
| `gatehouse_scrub` | `POST /v1/scrub` with `{"text": "..."}`. |

## First call to any secret, in order

1. `gatehouse_list` (prefix optional). Returns every secret you can
   use. HTTP response is `{"secrets": [...]}`; MCP returns the array
   directly. Per-entry fields:
   - `caps`: capabilities you hold on this secret, e.g.
     `["read","proxy"]`. Filter by `caps.includes("proxy")` when
     you're looking for something to call through the proxy.
   - `pattern_count`: how many known-good request shapes exist.
   - `top_pattern`: the highest-confidence pattern, e.g.
     `POST http://10.0.0.102:5230/api/v1/memos`. This IS your endpoint.
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

## Operating rules

1. Never echo role_id, secret_id, JWT, or any secret value into
   context, logs, or output.
2. For any authenticated outbound API call, use `gatehouse_proxy`.
   It keeps the credential out of your context entirely.
3. On 4xx/5xx from upstream, the `gatehouse_proxy` response includes
   a `suggestions` array of up to 5 verified patterns for that secret.
   Use them before retrying.
4. If an SDK refuses HTTP-level injection, fall back to
   `gatehouse_lease` with a 60-600 second TTL. Call `gatehouse_revoke`
   the moment you're done. Use `gatehouse_get` only if both proxy and
   lease are unavailable.
5. Before returning or logging any text that might contain a
   credential (stack traces, tool output, echoed requests), pass it
   through `gatehouse_scrub`.
6. **Metadata is in `gatehouse_list` already.** Every secret's
   `allowed_domains`, `header_name`, `auth_scheme`, `caps`,
   `pattern_count`, and `top_pattern` are returned by `gatehouse_list`.
   Don't fetch a secret by path just to inspect metadata. Never call
   `gatehouse_get` just to see metadata, it returns the raw value and
   requires `read`.

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
- **4xx/5xx from upstream**: use the `suggestions` in the error
  response before retrying.
- **Secret not in gatehouse_list**: your policy doesn't grant any
  usable access to it. Ask the operator to extend your policy.
<!-- GATEHOUSE-SKILL-END -->
