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

**Steps:**

1. Detect your harness
2. Exchange the bootstrap token
3. Fetch the skill body and verify (in memory)
4. Persist env vars and skill to disk
5. Confirm

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
Step 4.

If exchange returns 410 Gone, the token has already been used or
expired. Stop and tell the operator to generate a new onboarding link.

If exchange returns 403, either your source IP is not in the AppRole's
allowlist, or the AppRole has been suspended. Stop and tell the
operator.

If the initial fetch fails with a transient network error (connection
refused, timeout, DNS failure), retry once before escalating to the
operator. Fetching this bootstrap URL is idempotent until `/exchange`
is called.

## Step 3: Fetch and verify (in memory)

Two HTTP calls, both using the JWT from Step 2. Hold both responses
in memory; do NOT touch disk yet. If either call fails or the verify
doesn't match, stop now. Nothing has been persisted, so re-issuing
the onboard link is clean.

**Fetch the rendered skill body:**

    curl -fsSL -H "Authorization: Bearer <jwt>" {{BASE_URL}}/v1/skill

The response is markdown, already tailored to your policies. Keep it
in memory for Step 4. You can also re-fetch this same URL any time
later to pick up skill template improvements without re-onboarding.

**Verify your install end-to-end:**

    curl -fsSL -H "Authorization: Bearer <jwt>" {{BASE_URL}}/v1/auth/whoami

Compare the whoami response against the exchange response from
Step 2 (the canonical source: those JSON fields, NOT the prose at
the top of this document):

- `whoami.identity` must equal `"approle:" + exchange.role_display_name`.
- `whoami.policies` must equal `exchange.policies` as a SET. Sort both
  arrays (or pipe through `jq 'sort'`) before comparing; ordering
  between the two endpoints is not guaranteed.

If either check fails, stop and tell the operator. Likely causes:
your JWT was minted against a different role than promised, the
AppRole was edited between exchange and whoami, or values were copied
wrong. The strict-equality check is intentional, extra or missing
policies surface a real problem. Do not persist mismatched values.

If you're on the "No filesystem" branch from Step 1, the verify is
your finish line. Hold the JWT in memory, skip Step 4, and reply per
Step 5.

## Step 4: Persist credentials and the skill

If the env file or skill file for your harness (see paths below)
already exists, you are replacing a previous Gatehouse install on
this machine. The old AppRole stays valid in the vault, but this
agent loses its previous identity (and whatever policies came with
it). If you didn't expect to swap identities, confirm with the
operator before continuing.

Use the skill body fetched in Step 3 and the env values from Step 2.
The env file is always these three lines:

    GATEHOUSE_URL=<see "Choosing the URL" below>
    GATEHOUSE_ROLE_ID=<exchange.role_id>
    GATEHOUSE_SECRET_ID=<exchange.secret_id>

**Choosing the URL**: if the exchange response includes `internal_url`,
the operator has opted into split-DNS. Write `internal_url` so every
future call from this agent takes the LAN fast path. Otherwise write
`base_url`.

Based on Step 1:

### Hermes Agent

Write the env block above to `~/.hermes/.env`.
Then call `skill_manage` with action `create`, name `gatehouse`, and
the skill body from Step 3. Verify with `skill_view`.

### OpenClaw

Write the three env vars above to `~/.openclaw/workspace/.env`.
Save the Step 3 skill body to `~/.openclaw/skills/gatehouse/SKILL.md`.
Append one line to `~/.openclaw/workspace/MEMORY.md`:

    Use the gatehouse skill for all authenticated API calls.

### Claude Code

Write the env vars to `~/.claude/.env.gatehouse` and tell the user to
source it or export the variables.
Save the Step 3 skill body to `~/.claude/skills/gatehouse/SKILL.md`.

If the user is in Claude Code Desktop (not the CLI), the skills panel
won't list the new skill until the app is restarted. Tell them to quit
and reopen (Cmd-Q on macOS); the skill auto-loads in any new session.

### Pi

Write the env vars to `~/.pi/agent/.env.gatehouse` and tell the user
to source it or export the variables.
Pi has no skills directory, so append the full Step 3 skill body to
`~/.pi/agent/AGENTS.md` under a `## Gatehouse` heading. Pi reads
`AGENTS.md` at startup.

### Generic file-writer (opencode, Codex, Cursor, Windsurf, or similar)

Write the env vars to `.env.gatehouse` in the current working
directory. Tell the user to source it.
Append only the `## Operating rules` and `## Situation, tool` sections
of the Step 3 skill body to `AGENTS.md` at the repo root, under a
`## Gatehouse` heading. These harnesses don't have a skills system, so
the full body is more than they need.

Do NOT write into `~/.hermes/`, `~/.openclaw/`, or `~/.claude/` from
this bucket. Those belong to other agents on the same host.

## Step 5: Confirm

Reply in one line. If your harness wrote to more than one path (an
env file plus a skill file, typically), list both in parentheses:

    Gatehouse installed (~/.claude/.env.gatehouse + ~/.claude/skills/gatehouse/SKILL.md), role {{ROLE_DISPLAY_NAME}}, policies {{POLICIES}}.

Single path is fine too:

    Gatehouse installed (~/.pi/agent/AGENTS.md), role {{ROLE_DISPLAY_NAME}}, policies {{POLICIES}}.

Or, if no persistence:

    Gatehouse session-only, role {{ROLE_DISPLAY_NAME}}. New onboard link
    needed next session.

Then wait for the next instruction.

## Reference: situation to tool

Quick lookup for your current policies. The full skill body fetched in
Step 3 also contains this table along with the rest of the operating
rules.

{{SITUATION_TABLE}}
