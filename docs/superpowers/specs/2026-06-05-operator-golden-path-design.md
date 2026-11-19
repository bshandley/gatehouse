# Operator golden path: guided first run

Date: 2026-06-05
Status: design
Sub-project C of the ubiquity roadmap. Builds on A, pairs with B.

## Problem

The agent side of onboarding is the best thing in the codebase: a one-time
token, a self-installing skill, and a harness-detection ladder across nine
harnesses (`src/templates/onboard.md`, `src/api/onboard.ts`). The human side
is rough. Today the operator lands straight on the dashboard after pasting a
root token, then must, with no guidance: understand AppRoles, hand-author a
policy, attach it, generate an onboarding link, and know to remove the
bootstrap token afterward. The first ten minutes decide whether a tool sticks,
and right now those ten minutes are a scavenger hunt.

There is no first-run wizard today. Empty states exist (the zero-policy STOP
warning in the onboard markdown, the secrets and leases empty hints), and the
settings panel nudges unsetting the root token, but nothing strings the path
together.

## Goals

A guided first-run flow in the web UI that takes a fresh operator from login to
"my Claude Code is now calling through Gatehouse," and ends with them off the
bootstrap root token. Specifically:

1. Detect first run (root token in use, no admin principal, no AppRoles).
2. Create a durable admin login so the operator is not dependent on the
   bootstrap token (an admin user, or an admin AppRole).
3. Author or pick a policy, reviewed and saved explicitly by the operator.
4. Create the agent's AppRole with that policy attached.
5. Generate the onboarding link and show it.
6. Close the loop: detect the agent's token exchange live and confirm
   "connected."
7. Walk the operator off the root token, with a re-check.

## Non-goals, and one hard constraint

- No auto-policy, no grants, no quick-grant buttons, no policy written on the
  user's behalf without their explicit review and save. This is a standing
  design rule for the project. The wizard's policy step presents a prefilled,
  editable policy that the operator reads and saves. A prefilled editor is not
  an auto-grant: the operator is the author and can change every line before it
  is written. The distinction must be visible in the UI copy.
- No change to the agent-side onboarding protocol. The wizard orchestrates the
  existing endpoints exactly as they are.
- Not a replacement for the existing pages. The wizard is an overlay that hands
  off to the normal dashboard when done or skipped.

## Existing endpoints the wizard orchestrates

All verified present:

- `GET /v1/config` returns `root_token_set` (drives first-run detection and the
  final nudge).
- `POST /v1/auth/users` creates the first admin user (durable login).
- `POST /v1/auth/approle` creates an AppRole, returns `role_id` and a one-time
  `secret_id` with the "save it now" warning.
- `POST /v1/policy/` creates or updates a hand-authored policy
  (`{name, rules:[{paths, capabilities}]}`; capabilities are read, write,
  delete, list, lease, proxy, admin).
- `POST /v1/onboard` returns `onboard_url`, `onboard_url_internal`, `token`,
  `expires_at`.
- The token's consumption is observable: `onboarding_tokens.consumed_at` is set
  on exchange, and `onboard.token.exchange` is written to the audit log.

## Design decisions (vetoable at review)

### D1. A dismissible wizard overlay, triggered on detected first run

When the dashboard loads and `GET /v1/config` shows `root_token_set: true` and
there are no AppRoles and no non-root users, show the wizard overlay over the
dashboard. It is dismissible ("I'll do this manually") and re-openable from a
"Setup" item so it is a guide, not a gate. State lives client-side; each step
is just orchestration of the endpoints above. No new persistence except a
settings flag `setup_completed` so the overlay does not nag after success.

### D2. Step order matches the operator's real path

1. Welcome and orientation. One short paragraph on the model: secrets live in
   the vault, agents authenticate as AppRoles, policies say what an AppRole can
   touch, the proxy means raw secrets never reach the agent. Sets the mental
   model the rest depends on.
2. Create a durable admin. Prefer an admin user (username plus password, with
   the existing TOTP available later) so the operator has a real login that
   survives removing the bootstrap token. Calls `POST /v1/auth/users`.
3. Author the agent's policy. Present two or three starter templates as
   prefilled, editable policy editors (see D3). The operator reviews and saves
   via `POST /v1/policy/`. Copy is explicit: "Review this policy. You are
   attaching it. Edit anything before saving."
4. Create the agent's AppRole with the saved policy attached. Calls
   `POST /v1/auth/approle`, shows the one-time `secret_id` with the existing
   warning, and reminds that the onboarding link delivers a fresh secret to the
   agent so the operator does not have to handle it.
5. Generate and present the onboarding link. Calls `POST /v1/onboard`. Shows
   the URL (internal-preferred when split-DNS is configured, matching current
   behavior), a copy button, and a plain-language "paste this to your Claude
   Code / agent" instruction.
6. Wait for connection. Poll `GET /v1/config`-adjacent state, specifically the
   token's `consumed_at` (a small read endpoint, see D4) or the audit log for
   `onboard.token.exchange` on this token. When it fires, show a green
   "your agent connected as approle:<name>" with the verified identity and
   policies. This is the single best activation moment in the product and it
   should feel like a payoff.
7. Walk off the root token. Show the exact step (remove `GATEHOUSE_ROOT_TOKEN`
   from the environment, restart) and a "re-check" button that re-reads
   `GET /v1/config` and confirms `root_token_set: false`. If B's generated
   bootstrap token wrote `bootstrap-root.token`, instruct deleting it too. On
   success, set `setup_completed`.

### D3. Starter policy templates are reviewed, not auto-applied

Ship two or three named starter templates as static client-side objects, each a
complete policy the operator opens in an editor and saves:

- `agent-readonly`: `paths: ["api-keys/*", "services/*"]`,
  `capabilities: ["read", "proxy"]`. The common case: an agent that calls APIs
  through the proxy and reads keys it is allowed to.
- `proxy-only`: `capabilities: ["proxy"]` over a chosen prefix. The strongest
  posture: the agent can make authenticated calls but never read a raw secret.
- `db-lease`: `capabilities: ["lease"]` over `db/*`. For agents picking up
  dynamic database credentials.

Each is rendered into the existing policy editor, fully editable, with the path
prefixes highlighted for the operator to adjust. Saving calls `POST /v1/policy/`
unchanged. The templates are a starting point the operator authors from, which
keeps the no-auto-policy rule intact.

### D4. A minimal token-status read for the live wait

Step 6 needs to know when a specific onboarding token has been exchanged. The
cleanest addition is a small authenticated read, `GET /v1/onboard/:id/status`,
returning `{ consumed: boolean, consumed_at, role_display_name, policies }` for
the token row the wizard just created. The wizard polls it every few seconds
with a timeout that matches the token TTL, falling back to "link expired,
generate a new one." This avoids scraping the audit log from the client and
keeps the wait responsive.

## Components

- `src/ui/index.html`: the wizard overlay (HTML, the existing vanilla JS
  style, the existing `.stat-card` and form patterns), first-run detection,
  step state machine, the polling for step 6.
- `src/api/onboard.ts`: add `GET /v1/onboard/:id/status` (admin-gated, scoped
  to tokens the caller created).
- `settings` table: a `setup_completed` flag read at dashboard load.
- Starter templates: static objects in the UI, no server change.

## Error handling

- Operator dismisses mid-flow: state is client-side, the dashboard is fully
  usable, the wizard re-opens where it left off from the "Setup" entry.
- Onboarding link expires before the agent connects (step 6 timeout): offer
  "generate a new link" without redoing the policy and AppRole steps.
- Operator removes the root token before creating a durable admin: prevented by
  ordering (step 2 before step 7) and by the step-7 re-check, which warns if no
  durable admin exists yet.
- Policy save validation error: surfaced inline in the editor, the existing
  policy endpoint error shape.

## Testing

- First-run detection: with no AppRoles and root token set, the overlay
  triggers; with an AppRole present or `setup_completed`, it does not.
- The `GET /v1/onboard/:id/status` endpoint: returns not-consumed before
  exchange, consumed after, and refuses tokens the caller did not create.
- A scripted end-to-end (server-side test plus a redeem) that walks create
  user, save policy, create approle, create link, exchange, and asserts the
  status endpoint flips to consumed.

## Rollout

1. `GET /v1/onboard/:id/status` and the `setup_completed` flag.
2. The wizard overlay and first-run detection.
3. Starter templates and the policy-review copy.
4. Docs: a short "first run" page that mirrors the wizard for operators who
   prefer the CLI or skipped the overlay.

## Open questions

- Durable admin as a user (username and password) or as an admin AppRole?
  Leaning user, because a human login with optional TOTP is the natural
  operator credential and the AppRole path is for agents. Decide at review.
- Should step 7 offer to delete `bootstrap-root.token` for the operator (a
  small privileged file op) or only instruct it? Leaning instruct-only to keep
  the server out of the business of deleting its own bootstrap material.
