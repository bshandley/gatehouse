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
   Windsurf, Copilot CLI, Gemini CLI, Pi, or anything else), pick
   that one and skip the rest of the ladder. Do not second-guess
   your own identity from filesystem contents, those belong to other
   agents sharing the host.
2. **Tool signals.** If you genuinely don't know:
   - A `skill_manage` tool means **Hermes Agent**.
   - A `Skill` tool means **Claude Code**.
3. **Filesystem, as a last resort.** Only if the two steps above
   didn't resolve, AND exactly one of `~/.hermes/`, `~/.openclaw/`,
   `~/.claude/`, `~/.pi/` exists, use that as the harness. If two or
   more exist, stop and ask the operator which runtime this is.
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

In bash:

    curl -fsSL -X POST {{BASE_URL}}/v1/onboard/{{ONBOARD_TOKEN}}/exchange

No body. No Authorization header. The response contains your durable
AppRole credentials and a 24h JWT:

    {
      "token": "<jwt>",
      "role_id": "role-...",
      "secret_id": "...",
      "base_url": "{{BASE_URL}}",
      "internal_url": "<set if the operator configured one, else absent>",
      "mcp_url": "{{BASE_URL}}/v1/mcp",
      "role_display_name": "{{ROLE_DISPLAY_NAME}}",
      "policies": [...],
      "expires_in": 86400
    }
{{INTERNAL_URL_BLOCK}}

Hold these values in memory. Never echo role_id, secret_id, or the
JWT into conversation output, logs, or tool arguments visible to the
user. They only get written to the specific credential location in
Step 3.

If exchange returns 410 Gone, the token has already been used or
expired. Stop and tell the operator to generate a new onboarding link.

If exchange returns 403, either your source IP is not in the AppRole's
allowlist, or the AppRole has been suspended. Stop and tell the
operator.

If the initial fetch fails with a transient network error (connection
refused, timeout, DNS failure), retry once before escalating to the
operator. Fetching this bootstrap URL is idempotent until `/exchange`
is called.

## Step 3: Persist credentials and install the skill

Fetch your rendered skill body using the JWT from Step 2. The response
is markdown, already tailored to your policies; write it verbatim to
the skill path for your harness:

    curl -fsSL -H "Authorization: Bearer <jwt>" {{BASE_URL}}/v1/skill

You can re-fetch this URL any time after install to pick up skill
template improvements without re-onboarding.

Based on Step 1:

### Hermes Agent

Write to `~/.hermes/.env`:

    GATEHOUSE_URL=<base_url>
    GATEHOUSE_ROLE_ID=<role_id>
    GATEHOUSE_SECRET_ID=<secret_id>

Then call `skill_manage` with action `create`, name `gatehouse`, and
the body fetched from `/v1/skill` above. Verify with `skill_view`.

### OpenClaw

Write the three env vars above to `~/.openclaw/workspace/.env`.
Save the `/v1/skill` body to `~/.openclaw/skills/gatehouse/SKILL.md`.
Append one line to `~/.openclaw/workspace/MEMORY.md`:

    Use the gatehouse skill for all authenticated API calls.

### Claude Code

Write the env vars to `~/.claude/.env.gatehouse` and tell the user to
source it or export the variables.
Save the `/v1/skill` body to `~/.claude/skills/gatehouse/SKILL.md`.

If the user is in Claude Code Desktop (not the CLI), the skills panel
won't list the new skill until the app is restarted. Tell them to quit
and reopen (Cmd-Q on macOS); the skill auto-loads in any new session.

### Pi

Write the env vars to `~/.pi/agent/.env.gatehouse` and tell the user
to source it or export the variables.
Pi has no skills directory, so append the full `/v1/skill` body to
`~/.pi/agent/AGENTS.md` under a `## Gatehouse` heading. Pi reads
`AGENTS.md` at startup.

### Generic file-writer (opencode, Codex, Cursor, Windsurf, or similar)

Write the env vars to `.env.gatehouse` in the current working
directory. Tell the user to source it.
Fetch the `/v1/skill` body and append only its `## Operating rules` and
`## Situation, tool` sections to `AGENTS.md` at the repo root, under a
`## Gatehouse` heading. These harnesses don't have a skills system, so
the full body is more than they need.

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

## Reference: situation to tool

Quick lookup for your current policies. The full skill body fetched in
Step 3 also contains this table along with the rest of the operating
rules.

{{SITUATION_TABLE}}
