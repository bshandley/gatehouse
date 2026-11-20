# Changelog

All notable changes to Gatehouse are documented here. The auto-generated GitHub
release notes (built from conventional-commit subjects between tags) carry the
fine-grained per-commit log. This file summarises each release at a higher
level.

## [0.23.0] - 2026-11-19

Distribution. A bare container now boots with nothing configured, and there are install templates for four self-hosting catalogs.

### Added

- **Bootstrap root token.** With `GATEHOUSE_ROOT_TOKEN` unset or empty and no admin, first boot generates a one-time token (16 random bytes, 32 hex characters), writes it to `bootstrap-root.token` in the data dir (mode 0600), and prints it to stderr under `GATEHOUSE BOOTSTRAP ROOT TOKEN`. A restart before an admin exists reuses the saved token. On the first restart after an admin exists (an enabled admin user, or a non-suspended AppRole holding the `admin` policy) there is no root token and the file is deleted. If the data dir is not writable the banner says `NOT SAVED`. `GET /v1/config` `root_token_source` is `env`, `bootstrap`, or `null`.
- **Startup warning for the old default root token.** If `GATEHOUSE_ROOT_TOKEN` equals the pre-0.23.0 compose default, a WARNING banner on stderr says a publicly known root token is active. The token still works; the warning is the only change.
- **Zero-secret reference compose.** `docker-compose.yml` needs no `.env`. Both `GATEHOUSE_MASTER_KEY` and `GATEHOUSE_ROOT_TOKEN` are passed through empty by default, so first boot generates them.
- **First-boot smoke test** at `scripts/smoke-first-boot.sh`.
- **Catalog templates** under `packaging/` for Unraid, Umbrel, CasaOS, and Coolify, each pinned to the release image tag. They are templates you can use yourself. None is submitted or listed upstream. `packaging/README.md` records each catalog's constraints and checklist, and `test/packaging.test.ts` fails if a pin drifts from `src/version.ts`.

### Changed

- **Breaking: the stdio MCP entry verifies `GATEHOUSE_TOKEN`.** It used to compare the token only with the root token and otherwise ignore it, running with `GATEHOUSE_POLICIES` (default `admin`) whatever the token was. A token is now verified like an HTTP bearer token: the root token or a Gatehouse JWT, which runs as its own identity and policies. A token that does not verify makes the process exit 1. If your stdio config passes a placeholder or an expired JWT as `GATEHOUSE_TOKEN`, remove it or replace it.
- **Breaking: the stdio MCP entry no longer defaults to the `admin` policy.** With no token, `GATEHOUSE_POLICIES` used to default to `admin`, so an agent connected over stdio could read and write every secret unless the operator remembered to restrict it. `GATEHOUSE_POLICIES` is now required when no token is given, and the process exits 1 without it. Set `GATEHOUSE_POLICIES` to your policy name in every stdio MCP config (`admin` still works, but must be written out). An unknown policy name logs a warning.
- **The stdio MCP entry uses the server's policies.** Policies created in the web UI or API now apply, not only YAML files.
- **No default root token.** The reference compose no longer falls back to a fixed placeholder token. `GATEHOUSE_ROOT_TOKEN`, when set and non-empty, still always wins and behaves as before. A whitespace-only value now counts as unset.
- **`docker-compose.yml` uses the published image** (`ghcr.io/bshandley/gatehouse`) instead of building. To build from a checkout: `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build`.
- A suspended AppRole holding the `admin` policy no longer counts as an admin for the bootstrap token decision.
- Docs now start from the bootstrap token flow: README, getting started, authentication, security, and integrations. The security page documents the token lifecycle.
- **The image runs under an arbitrary uid.** App files are world-readable (`chmod -R a+rX /app`) and uid 99 (Unraid's default) has a passwd entry, because `ssh-keygen` refuses a uid with none.

### Fixed

- The stdio MCP entry wrote audit rows and policy load notices to stdout, between JSON-RPC responses. They now go to stderr.
- CORS preflight now allows `PATCH`, which `PATCH /v1/secrets/:path` needs from a browser on another origin.
- The Codex CLI example in the integrations page used a config shape Codex does not accept.
- **Browser Back and Forward move between pages inside the web UI.** Every in-app navigation replaced the history entry, so Back left the app for whatever was open before it. Navigation now pushes an entry; the first page after load or sign-in, and a re-click of the current page, still replace.

### Upgrade notes

- **Action required if your compose file predates 0.23.0.** The old default lived in your compose file, not in the image: `GATEHOUSE_ROOT_TOKEN=${GATEHOUSE_ROOT_TOKEN:-gatehouse-root-changeme}`. Pulling the new image does not change that line, the env token wins, and the publicly known token `gatehouse-root-changeme` stays active. The old `.env.example` carried the same value, so a `.env` copied from it has it too. It stops working only once neither your compose file nor your `.env` supplies `gatehouse-root-changeme`. Remove it from both now, then recreate the container with `docker compose up -d` (a plain restart keeps the old environment). Check with `docker compose config | grep GATEHOUSE_ROOT_TOKEN`: it must not print `gatehouse-root-changeme`. That reads your files, not the running container, so also confirm the startup WARNING is gone from `docker logs gatehouse`: 0.23.0 logs it on every start while the token is active. If your `.env` sets a root token of your own, it still wins; remove it too once you have an admin.
- **Installs with no admin.** If there is no enabled admin user, no active (non-suspended) admin AppRole, and no env token, first boot of 0.23.0 generates a bootstrap root token and prints it to the container log (`docker logs gatehouse`). Create an admin and restart to retire it. Either way, confirm your master key is escrowed off this host ([Backup & Recovery](https://gatehouse.to/docs/backup/)).
- An install that keeps `GATEHOUSE_MASTER_KEY` in `.env` is unchanged. A non-empty value always wins over a generated one.

## [0.22.0] - 2026-11-19

Recoverability. A fresh install no longer needs a master key up front, and the vault can be backed up, exported, restored and checked from the image. See the new Backup & Recovery docs page.

### Added

- **First-boot key generation.** With `GATEHOUSE_MASTER_KEY` unset or empty and no `gatehouse.db` in the data dir, Gatehouse generates a key, writes it to `master.key` (mode 0600), and prints an escrow banner to stderr. A set key always wins over the file. A set key shorter than 64 characters is an error. A longer value that is not clean 64-character hex boots with a warning and is decoded as older versions did. A data dir that has a database but no key still refuses to start. The key file shares a volume with the database, which is a deliberate convenience tradeoff.
- **`backup`, `export`, `import`, `verify` commands.** `backup` takes a consistent snapshot of the database. `export` writes a passphrase-sealed bundle (scrypt, secretbox) that includes the master key by default (`--no-key` opts out; passphrase of 12 or more characters). `import` is a full replace from a bundle; it keeps the old database as `gatehouse.db.pre-import-<stamp>`, rolls back on failure, and refuses a mismatched key (exit 2) or a live server (exit 3). `verify` prints the key fingerprint and checks that it decrypts the data. Passphrases come from `--passphrase-env` or a TTY prompt, never a flag value. `backup`, `export` and `verify` are safe against a running server.
- **`GET /v1/admin/key-verify`** and an "Encryption key: matches data" row in Settings.
- **Heartbeat lock.** The server touches `gatehouse.lock` in the data dir every 10 seconds. Import treats a lock younger than 30 seconds as a live server. A clean stop removes the lock; only a crash leaves one to age out.
- **Key rotation persists the new key.** On a key-file install (`master.key`, including a generated one), `POST /v1/admin/rotate-key` writes the new key to `master.key` crash-safely and keeps the old one as `master.key.pre-rotate-<stamp>`. On an env install nothing is written and the response carries a `warning` to update `GATEHOUSE_MASTER_KEY` before the next restart. The endpoint now requires `new_master_key` to be exactly 64 hex characters (400 otherwise) and returns `rotated`, `secrets_rewrapped`, `dynamic_configs_rewrapped`, `key_persisted_to`, `previous_key_kept_as`, `message`, and `warning` when the key was not saved. A rotation that stops partway can leave `master.key.next`, and the server warns about it at boot.
- **Rotate result dialog.** The Settings rotate dialog asks for the new key twice and, after rotating, stays open on a result that shows the counts, the warning, and where the key went, until closed. Failures show in a dialog too.
- **The stdio MCP entry reads `master.key`.** `src/mcp-stdio.ts` (and the image's `mcp` argument) takes the key from `GATEHOUSE_MASTER_KEY` or `master.key` in the data dir and never generates one, so it cannot start a second vault.
- **Export refuses a key that does not decrypt the vault.** `export` checks the resolved key against the data before writing, and exits 1 with no file if it fails (for example a stale `master.key` after a rotation on an env install).

### Changed

- **The image has a real entrypoint.** `docker-entrypoint.sh` routes `backup`, `export`, `import`, `verify` and `mcp`. No arguments, or `src/index.ts`, still starts the server.
- `GATEHOUSE_MASTER_KEY` is optional in `.env.example` and the docs.

## [0.21.0] - 2026-11-18

List entry in the web UI is rebuilt around one input, the allowed-domains matcher now honours the forms the product documents, and the UI shell gets keyboard, phone and offline fixes.

### Added

- **One list input for every multi-value field.** Allowed domains, allowed path prefixes, auto-approve IPs, AppRole source IPs, and the dynamic secret grants, roles, principals, extensions and allowed hosts all use the same chip input. Enter, comma, space, Tab or clicking away adds an entry. Pasting a list splits it on commas, spaces and newlines. Backspace removes the last entry; clicking an entry puts it back in the field to edit. Each entry is validated as it is added, and an invalid one turns red with the reason and blocks Save.
- **Policy paths accept lists.** The policy rule path field now commits on comma, space and Tab as well as Enter, accepts a pasted list, validates each path, and no longer drops a path that was typed but not committed when you click Save.
- **AppRole "Allowed source IPs" in the UI.** The `ip_allowlist` field has been in the API since AppRole IP restrictions shipped and had no form. It is now on the create and edit dialogs, and restricted AppRoles show an **IP-restricted** badge.
- **`allowed_domains` entries can carry a port, a wildcard, or a range.** `host:port` restricts the port, `*.example.com` matches subdomains only, and a CIDR such as `10.0.0.0/24` matches any IP-literal host in the range. IPv6 literals are supported (`[fd00::1]:8080`).
- **Phone layout.** Below 700px the sidebar becomes a drawer opened from a top bar, pages no longer scroll sideways, and wide tables scroll inside their card.

### Fixed

- **`allowed_domains` entries with a port or a `*.` prefix never matched.** The matcher compared the URL hostname to the entry verbatim, so `10.0.0.50:5230` (the form shown in the agent reference) and `*.example.org` (the form's own placeholder) blocked every request. The REST proxy and the MCP proxy now share one matcher that implements both. **If a secret has such an entry, it starts to allow the host it names.** Entries that matched before match exactly as before.
- **Secret metadata lists are validated when written.** `allowed_domains`, `allowed_path_prefixes` and `auto_approve_from_ip` were stored unchecked, so a mistyped or space-separated list saved and then never matched. `POST` and `PATCH /v1/secrets/:path`, the bulk import and the MCP `gatehouse_put` tool now return an error naming the key and the bad entry. Valid lists are stored as `a, b, c`. Existing values are untouched until the next write, and readers now split on whitespace as well as commas.
- **The live event stream was cut every 10 seconds.** `GET /v1/events` sends a heartbeat every 20s, but Bun closes idle connections after 10s. The stream now opts out of the idle timeout.
- **Dialogs close on Escape, trap focus, and keep their buttons visible.** Escape does what clicking the backdrop does, so dialogs that confirm before closing still do. Focus moves into a dialog when it opens and returns to the opener when it closes. The Save and Cancel row stays pinned while a long dialog scrolls. Dialogs are announced as dialogs, and form labels are tied to their fields.

### Changed

- **The UI makes no third-party requests.** Its three fonts (DM Sans, Instrument Sans, JetBrains Mono, all SIL OFL) are bundled and served from `/ui/fonts/`. Before, the page loaded them from Google Fonts and blocked on that request when the host was unreachable. The page's Content-Security-Policy no longer lists any external origin.
- "Auto-approve from IP" is now "Auto-approve from IPs". It always accepted a list; the form now says so.

## [0.20.2] - 2026-11-18

An accuracy release. The docs were audited against the route handlers and corrected wherever they disagreed with the code; two bugs found along the way are fixed.

### Fixed

- **`DELETE /v1/dynamic/:path` now returns 404 for a config that does not exist.** The handler did not `await` the async delete, so the not-found check never fired and every delete reported `{"deleted": true}`.
- **Skill template no longer sends agents a literal `{{BASE_URL}}`.** Two URLs in the approval-flow section of `src/templates/skill.md` (served at `GET /v1/skill`) used a placeholder that nothing substitutes. They now use `{GATEHOUSE_URL}` like the rest of the template. A test fails if the template gains another unsubstituted placeholder.
- **`docker-compose.yml` no longer blocks private-network proxying by default.** The compose file defaulted `GATEHOUSE_PROXY_ALLOW_PRIVATE` to `false` while its own comment, `.env.example` and the server default all said private ranges are allowed. It now defaults to `true`. **If you run the stock compose file on an internet-exposed host and relied on the old default, set `GATEHOUSE_PROXY_ALLOW_PRIVATE=false` explicitly.**
- **Order-dependent test failures.** The login, onboarding and rotation rate limiters are module-level state shared by every test file. A shared test preload (`test/preload.ts`, wired through `bunfig.toml`) now resets them before each test. CI runs on Bun 1.3, matching the Docker image.

### Removed

- **"Purge Expired Leases" button** in Settings. It showed a confirmation and a toast and did nothing; there is no lease purge endpoint. Expired leases are already handled by the reaper.
- **`debug` as a documented `GATEHOUSE_LOG_LEVEL` value.** It never differed from `info`. The values are `info` (request logging on) and `error` (request logging off).
- **`db:migrate` script** from `package.json`. It pointed at a file that does not exist; the schema is created and upgraded at startup.

### Docs

- **API reference:** the Patterns routes live under `/v1/proxy/patterns` (not `/v1/patterns`), pin is `PUT`, and there is no get-by-id route. `POST /v1/onboard` returns `onboard_url`, not `url`. Onboarding links are revoked by `id`, not by token. The MCP tools table lists all 11 tools with the capabilities the code checks.
- **Dynamic secret providers:** every example config is rewritten to the real shape (`path`, `provider_type`, and a flat string `config`). The old examples used fields that do not exist, such as `connection_string` and `creation_statements`, and the SSH provider type is `ssh-cert`.
- **Security:** the JWT secret is derived from the master key on every start, not persisted. The master key is read only from the environment; the Docker secrets file mount the docs described is not supported.
- **Web UI:** removed descriptions of lease history, a master key fingerprint, last-rotation date and an audit date-range filter, none of which exist. Reload imports new YAML policies and does not overwrite existing ones. Pinning a pattern does not protect it from deletion.
- **Agent reference and integrations:** private-network proxying is allowed by default. Corrected the secret value, lease, scrub and pattern response shapes, and the tool counts (11, not 8 or 9).
- **Also corrected:** the `inject` example in Concepts (a bare secret path, not `Bearer {path}`), the lease response in Getting Started, the 2FA location in Authentication, the SSO redirect URI in `.env.example` (`/v1/auth/sso/callback`), and `AGENTS.md`.

### Changed

- **Site builds on Astro 7.** `site/bun.lock` still pinned Astro 6 after the dependency bump; it now matches `site/package.json`. `bun run site:build` runs Astro under the Bun runtime, so it no longer depends on the installed Node version.
- `package.json` now carries the real version.

## [0.20.1] - 2026-06-19

### Fixed

- **`set +o history` no longer aborts the shell-login snippet.** The "Login from a shell" block in the gatehouse skill template (`src/templates/skill.md`, served at `GET /v1/skill`) opened with `set +o history 2>/dev/null`. Under the non-interactive zsh of the Claude Code Bash tool, that builtin returns non-zero and aborts the rest of the command, so the login never ran and produced no output (the harness's secret-scrubbing hid the failure). Tool-call commands never touch interactive shell history, so the line protected nothing. Removed it; the snippet still keeps secrets out of context by writing the JWT to a file and `unset`-ing the vars.
- **Skill template now self-heals when the AppRole env vars are absent.** Onboarding writes `GATEHOUSE_ROLE_ID`/`GATEHOUSE_SECRET_ID` to a `.env.gatehouse` file and defers sourcing to the operator, but the skill's Connect section assumed the vars were already exported and never named the file, so a fresh session that had not sourced it had no credentials and no recovery path. The Connect section now points at the per-harness `.env.gatehouse` path (`~/.claude/.env.gatehouse` for Claude Code, `~/.pi/agent/.env.gatehouse` for Pi, `.env.gatehouse` in the working directory otherwise), shows how to source it (`set -a; . <path>; set +a`), and says to re-run onboarding if neither the vars nor the file exist.

## [0.20.0] - 2026-06-07

### Added

- **Posture and value view on the dashboard.** The posture row surfaces "credentials kept out of agent context" (a rolling 7-day count of redactions) and blocked egress (with a by-reason breakdown on hover), plus a hygiene nudge that appears only when secrets need attention (unused 90d, older than 18mo) and links to the secrets list.
- **`GET /v1/stats/posture?window=7d` (admin only)**: windowed posture aggregation from the audit log and the secrets table.
- **`secrets.last_accessed_at`**: stamped on every value reveal (REST and MCP) and on static lease checkout. Existing rows are backfilled to `updated_at`.
- **`scrub.redact` audit event**: recorded on explicit scrubs (`POST /v1/scrub` and the `gatehouse_scrub` MCP tool) when something was redacted.
- **Secret-hygiene badges** ("stale", "18mo+") in the secrets tree and a "Last used" field in the secret detail panel.

### Changed

- **`scrubResponseBody` now returns the scrubbed body plus a redaction count.** The count is recorded in `proxy.forward` and `proxy.forward.mcp` audit metadata as `redaction_count`. As a side effect, an oversized upstream body that aborts the read now produces only a failure audit row, not a success row too.
- **Dashboard simplified to a single posture row.** The standalone Active Leases, Audit Events (24h), and Policies stat cards have been removed: the active-lease count now rides in the Active Leases table header, Total Secrets moved into the posture row, and recent activity is covered by the audit feed below.

### Notes

- Hygiene thresholds (90 days unused, 18 months since update) are constants in this release. No automatic rotation or deletion: the view nudges, it never acts.

## [0.19.0] - 2026-05-30

### Security

- **`X-Forwarded-For` is no longer trusted by default for IP-based security decisions.** The source IP feeds every network-origin control in Gatehouse (AppRole IP allowlists, the rotate-token IP allowlist, and the lease/proxy `auto_approve_from_ip` gate). Previously the source IP was taken from the client-supplied `X-Forwarded-For` (or `X-Real-IP`) header unconditionally, so an off-network attacker holding valid credentials could set `X-Forwarded-For: <trusted-ip>` to satisfy an IP allowlist or auto-approve a secret that should have required human approval. Gatehouse now honors forwarded headers only when the request's immediate TCP peer is a trusted proxy, and otherwise uses the real socket address. Loopback (`127.0.0.0/8`, `::1`) is trusted by default so a reverse proxy colocated on the same host keeps working out of the box.

  - **New `GATEHOUSE_TRUSTED_PROXIES` env var** (comma-separated CIDRs) to trust additional upstreams, e.g. a Docker network gateway or a LAN reverse proxy. It is additive to the always-on loopback defaults. When a forwarded chain is present, the right-most hop that is not itself a trusted proxy is taken as the real client.
  - **Behavior change for reverse-proxy deployments.** If you run Gatehouse behind a proxy that is not on loopback (e.g. a separate host, or a Docker network that is not `127.0.0.1`) and you rely on IP allowlists or `auto_approve_from_ip`, set `GATEHOUSE_TRUSTED_PROXIES` to your proxy's address. Until you do, those controls fail closed: allowlisted logins are denied and auto-approve falls back to the human approval flow. Direct-connection deployments need no change.

- **Proxy response scrubber now redacts the base64 form of injected credentials.** The `basic:` inject shorthand puts `Basic <base64(user:pass)>` on the wire. The response scrubber only redacted the raw secret value, so an upstream that echoed the `Authorization` header back in its body (common in 4xx errors) could return the credential in a base64 form the scrubber missed, which the agent could trivially decode. The scrubber now also redacts the base64 encoding of every injected value, on both the REST `/v1/proxy` and MCP `gatehouse_proxy` paths.

## [0.18.3] - 2026-05-25

### Docs

- **Step 3 verify check now names the exchange response as the canonical source**, not the prose at the top of the bootstrap doc. Two concrete comparisons: `whoami.identity` equals `"approle:" + exchange.role_display_name`, and `whoami.policies` equals `exchange.policies` **as a set**. Adds an explicit "sort both arrays before comparing; ordering is not guaranteed" note so a naive `==` against ordered arrays can't pass review and then fail in the wild. Also documents that the strict-equality check (extra policies fail too) is intentional, since extra policies typically mean the AppRole was modified mid-onboard.
- **Step 4 hoists the env block to the top of the step**. Previously the Hermes subsection inlined the three env-var lines and the other subsections referenced "the env vars above" against an inconsistent anchor. The env block now lives once at the top with a `Choosing the URL` callout: if `internal_url` is in the exchange response, write that for `GATEHOUSE_URL` so the agent's future calls take the LAN fast path; otherwise write `base_url`. Closes the previously-undefined case where the onboard doc said "prefer internal URL" but the persistent env file always pointed at `base_url`.
- **Short TOC at the top** (Steps 1-5 in five lines) so an agent skimming a fresh fetch can orient before diving in. Adds about 130 bytes, the trade is worth it given the doc has grown across the recent iterations.

## [0.18.2] - 2026-05-25

### Fix

- **`GATEHOUSE_INTERNAL_URL` and `GATEHOUSE_PUBLIC_URL` are now passed through `docker-compose.yml`.** Both env vars were honored by the Bun process but `docker-compose.yml` didn't reference them, so operators who set the value in their host environment (or hand-edited their deployed compose file) saw the value disappear on the next `git pull` + `docker compose up`. Both are now sourced via `${VAR:-}` substitution, matching the pattern used for `GATEHOUSE_MASTER_KEY` and the other forwarded vars. Set the value in the `.env` file alongside your `docker-compose.yml` (the file Docker Compose auto-loads), or export it in the shell environment that runs `docker compose`. The auto-deploy will then preserve it across pulls.
- `.env.example` now documents `GATEHOUSE_INTERNAL_URL` (it documented `GATEHOUSE_PUBLIC_URL` already).

## [0.18.1] - 2026-05-25

### Docs

- **Onboarding steps reordered to verify before persisting.** Old flow was: Step 3 wrote env + skill files to disk, then Step 4 ran `whoami`. If the verify failed, the agent had already touched disk. New flow:
  - **Step 3 (Fetch and verify)**: two HTTP calls, both with the JWT from Step 2, both held in memory. Fetch `/v1/skill`, run `/v1/auth/whoami`, compare. If either fails, the agent stops with nothing on disk and the operator can simply re-issue the link.
  - **Step 4 (Persist)**: the per-harness env-file + skill-file instructions move here. Each subsection now refers to "the Step 3 skill body" instead of re-fetching.
  - **Step 5 (Confirm)**: unchanged in spirit, but the response template now uses parentheses to accommodate multi-path harnesses (e.g. `Gatehouse installed (~/.claude/.env.gatehouse + ~/.claude/skills/gatehouse/SKILL.md), role X, policies Y.`). Single-path harnesses use the same shape with one path inside the parens.
- **Step 3 verify check is now a literal failure condition** instead of "match the top of this document". Reads: *"If `identity` != `approle:{{ROLE_DISPLAY_NAME}}`, or the returned `policies` set differs from `{{POLICIES}}`, stop and tell the operator."* Concrete, harder to skim past, no ambiguity about what "match" means.
- **No filesystem branch**: Step 1's "No filesystem at all" rung now routes the agent directly from Step 3's verify to Step 5's confirm. Step 4 (Persist) is for filesystem-writing harnesses only. The previous "No filesystem" subsection inside Step 3 (now Step 4) is removed because Step 3 handles that branch explicitly.

## [0.18.0] - 2026-05-25

### Feature

- **Split-DNS deployments now default to the internal URL throughout onboarding.** Previously, the `GATEHOUSE_INTERNAL_URL` feature shipped in 0.17.0 returned `internal_url` in API responses and showed an "Internal URL" copy field tucked inside a collapsed `<details>` section, but the operator's primary copy action (the "Paste this to the agent" prompt) was hardcoded to the public URL. An agent fetching the bootstrap doc via the public URL then got `{{BASE_URL}}` rendered as the public URL throughout every curl example (Step 2 `/exchange`, Step 3 `/v1/skill`, Step 4 `/v1/auth/whoami`), even if they later switched to the internal URL for performance.

  Two-layer fix:

  - **Server (`originFromRequest`)**: when `GATEHOUSE_INTERNAL_URL` is configured and the inbound request's Host (or `X-Forwarded-Host`) matches the internal URL's host, the rendered onboarding markdown now uses `internalUrl` for `{{BASE_URL}}` substitution. All subsequent curl examples stay on the LAN path. The same fix applies to the rotate-flow doc (`src/api/rotate.ts`). Non-split-DNS deployments (no `internalUrl`) see no change.
  - **Admin UI** (`src/ui/index.html`): when `GATEHOUSE_INTERNAL_URL` is configured, the "Paste this to the agent" prompt textarea now uses the internal URL by default. A small note explains the choice and points the operator at the public URL fallback (now labeled, in the collapsed "Just the URL" section, alongside the internal URL which appears first). For deployments without `GATEHOUSE_INTERNAL_URL`, the prompt behaves exactly as before (public URL only).

- Treats "operator configured `GATEHOUSE_INTERNAL_URL`" as the explicit opt-in to "default new agents to the LAN path". Operators with a mix of LAN and cloud agents still grab the public URL from the collapsed section for the off-LAN case.

### Tests

- Added two split-DNS regression tests in `test/onboard.test.ts`: bootstrap doc fetched via the internal host renders internalUrl in all curl examples; bootstrap doc fetched via the public host renders publicUrl (unchanged behavior). `buildApp` test helper now accepts optional `Partial<GatehouseConfig>` overrides.

## [0.17.3] - 2026-05-25

### Docs

- **Onboarding now includes an end-to-end verify step.** New Step 4 (Verify) tells the agent to `curl /v1/auth/whoami` with its fresh JWT and confirm the returned `identity` + `policies` match what was promised at the top of the bootstrap doc. Catches the class of failure where env vars point at the wrong file, the AppRole was edited mid-onboard, or the agent copied the wrong values out of `/exchange`. Step 5 (Confirm) now sits after Verify; the reply reflects verified state instead of just decoded JWT state.
- **Step 3 warns about overwriting an existing install.** If the env file or skill file already exists for the harness, the agent is replacing a previous Gatehouse identity on that machine. The old AppRole stays valid in the vault, but the agent loses its previous identity and policies. The doc now tells the agent to confirm with the operator before continuing if they didn't expect to swap.
- No API change.

## [0.17.2] - 2026-05-25

### Docs

- **Onboarding doc no longer inlines the skill body.** The bootstrap markdown (`GET /v1/onboard/:token`) used to carry the ~330-line skill content inside `<!-- GATEHOUSE-SKILL-BEGIN/END -->` markers, and Step 3 asked the agent to transcribe it verbatim through a file-write tool. Onboarding agents reported this as the single biggest source of friction: token-heavy, error-prone, and pointless when `/v1/skill` already returns the rendered body. Step 3 now tells agents to `curl -H "Authorization: Bearer <jwt>" {{BASE_URL}}/v1/skill` after exchange and write the response to the harness-specific skill path. The bootstrap doc shrinks from ~490 lines to ~165.
- **Skill body moved to `src/templates/skill.md`** as a standalone file; `/v1/skill` reads from it directly. `src/api/skill.ts` no longer parses markers out of `onboard.md`. The situation table stays as a footer reference in the bootstrap doc so the agent can glance at what their role grants without fetching the full skill.
- **New "Login from a shell" snippet** in the skill body's HTTP fallback section. A copy-pasteable bash sequence that performs AppRole login, stashes the JWT to a mode-0600 file, unsets `GATEHOUSE_ROLE_ID` / `GATEHOUSE_SECRET_ID`, and shows the refresh pattern. Onboarding agents previously had to reinvent this dance from the rules in Operating Rules #1; some got it subtly wrong.
- **Other onboarding template fixes**:
  - Step 2 now shows the literal `curl -fsSL -X POST` command next to the `POST {{BASE_URL}}/v1/onboard/.../exchange` prose, so agents don't add `-H Content-Type: application/json -d '{}'` defensively.
  - Step 2 adds a transient-error retry hint: if the initial network call fails with connection refused / timeout / DNS, retry once before escalating (fetching the bootstrap URL is idempotent until `/exchange`).
  - Step 3 (Claude Code section) now tells the agent to surface the "quit and reopen Claude Code Desktop (Cmd-Q on macOS)" requirement to the user, so the skills panel rescans.
  - Step 1 (Tool signals) drops the unverifiable "`Skill` tool that loads from `~/.claude/skills/`" clause. Agents can't introspect a tool's load paths from their context, so the simpler "a `Skill` tool means Claude Code" is what's left.
- No API or wire-format change. Tests cover the new layout: `/v1/skill` still returns policy-aware content and `/v1/onboard/:token` still substitutes `{{SITUATION_TABLE}}` for the same gatehouse-tool assertions as before.

## [0.17.1] - 2026-05-15

### Fix

- **Static lease reaper now catches same-day expirations.** The static lease manager wrote `expires_at` via JavaScript's `toISOString()` (`'2026-05-15T10:00:00.000Z'`) but compared it in SQLite against `datetime('now')` (`'2026-05-15 10:00:00'`). At character position 10 of those two strings, `'T'` (0x54) is lexicographically greater than `' '` (0x20), so any approved lease whose `expires_at` falls on the same UTC calendar day as the current moment lex-compared as still-in-the-future. Effect: `listActive()` kept showing those rows on the Active Leases page after they expired, and `reapExpired()` never revoked them until the UTC date rolled over. The dynamic lease manager already converted to SQLite format before storing and was unaffected. Fix: every static-lease WHERE clause that compared `expires_at` or `request_expires_at` to `datetime('now')` now uses `strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`, which produces the byte-identical format `toISOString()` emits. No DB migration required (the stored format is unchanged). No API/wire format change.
- Test fix: `test("reapExpired marks expired leases as revoked")` was manually overwriting `expires_at` with SQLite's space-separated format via `datetime('now', '-1 minute')`, bypassing the production write path and masking the bug. Test now writes via `new Date(...).toISOString()` matching how production writes. Added a regression test specifically for the same-day expiration case.

## [0.17.0] - 2026-05-15

### Feature

- **Internal URL support for split-DNS deployments**: new optional env var `GATEHOUSE_INTERNAL_URL` (e.g. `http://10.0.0.102:3100`) for operators who host Gatehouse behind a reverse proxy whose public hostname isn't reachable from inside the LAN. When set:
  - The onboarding token create response (`POST /v1/onboard`) returns both `onboard_url` and `onboard_url_internal`.
  - The onboarding admin UI shows a second copy field labeled "Internal URL" so operators can hand the right URL to LAN-only agents (e.g. a Raspberry Pi that can't reach the public proxy).
  - The rendered onboarding markdown (`GET /v1/onboard/:token`) includes a callout in Step 2 telling agents to prefer the internal URL when reachable.
  - The exchange response (`POST /v1/onboard/:token/exchange`) includes `internal_url` so agents can persist whichever endpoint actually works for them.
- **Onboarding docs cleanup**:
  - `gatehouse_request_access` now has a documented HTTP fallback (`POST /v1/lease/<path>/request`) in the onboarding template's HTTP route table.
  - JSON-RPC over `/v1/mcp` is documented as a catch-all bridge for harnesses without MCP tool wiring.
  - `/v1/proxy` now has a concrete flat-envelope JSON example so non-MCP agents stop guessing whether the body is nested.
  - 403-on-proxy error decoder split: the `requires_approval` case points at the approval flow instead of the generic "tell the operator" advice.
  - Pi added to the harness ladder (Step 1 self-ID + Step 3 persistence at `~/.pi/agent/`).
- Stripped two pre-existing em dashes that violated project rules.

## [0.16.0] - 2026-05-14

### Feature

- **Secrets page detail panel redesign**: replaced the flat metadata table with five structured blocks. Identity at the top (path + click-to-copy `{{secret:...}}` reference chip + description paragraph + a single stamps line). Posture (semantic-colored chips for `auth_scheme`, `allowed_domains`, `allowed_path_prefixes`, `rate_limit_per_minute`, `requires_approval`, `allow_private`, `tls_allow_insecure`, auto-approval IP/TTL). Activity (parallel-fetched active leases + recent audit events, with view-all links to the Leases and Audit pages). Value reveal (unchanged). Actions (Create Lease becomes primary). Unknown metadata keys land in an Other Metadata table at the bottom.
- Tree: each row now shows a small `[bearer]` / `[header:X-API-Key]` chip after the secret name when an auth scheme is set.
- Empty state: when no secret is selected, the panel shows a tertiary line summarizing total secrets, approval-gated count, and secrets touched this week.
- No server changes. Existing endpoints (`/v1/secrets`, `/v1/lease`, `/v1/audit`) supply all data.

## [0.15.0] - 2026-05-13

### Feature

- **Secret form**: replaced the generic key/value editor in the create/edit modal with dedicated controls. `requires_approval` is now a first-class toggle. A new `description` field captures what each secret is for. Known metadata keys (`auth_scheme`, `header_name`, `allowed_domains`, `allowed_path_prefixes`, `allow_private`, `tls_allow_insecure`, `rate_limit_per_minute`, `auto_approve_from_ip`, `auto_approve_ttl_seconds`) live under a single collapsed Advanced section with the right control type for each (dropdown, toggle, number). Unknown keys keep working via an "Other metadata" escape hatch. Edit round-trip is preserved with two intentional normalizations: legacy `requires_approval=false` is dropped (now equivalent to omitted), and orphan `auto_approve_ttl_seconds` (no paired IP) is dropped.
- No server-side changes. Wire format is unchanged.

## [0.14.6] - 2026-05-12

### Bug fix

- **Secret detail panel: "Active Approved Leases" section now loads.** The UI was calling `GET /v1/lease/?path=…` (trailing slash) for this section while every other lease call used `/v1/lease`. Hono's `app.route("/v1/lease", router)` mount matches `/v1/lease` cleanly but returns 404 for `/v1/lease/` in the version we run. Dropped the trailing slash in the UI; server-side normalization is deferred (would need request-path-rewrite middleware that could mask similar bugs elsewhere).

## [0.14.5] - 2026-05-12

### Bug fix

- **Lease approve/deny audits are now visible to the requesting agent.** Previously only the operator's `lease.approved` / `lease.denied` row was written, identity-scoped to the operator. Since the `/v1/audit` endpoint filters by caller identity for non-admins, agents could not see decisions on their own pending leases in their audit feed; the data was only reachable via `GET /v1/lease/<id>` polling or the SSE `lease_status_changed` event. Now a second mirror row is written under the agent's identity for both decisions, carrying `approved_by` (and `reason` for denials) in metadata. Admin audit views are unchanged; non-admin agents now see their own decision history.

## [0.14.4] - 2026-05-12

### Bug fix

- **UI SSE stream now actually starts.** `startEventStream` referenced `_sseController` (a `let` binding declared next to the function) while being invoked from `showApp()` during module init, before that `let` line had executed. Firefox surfaced this as `ReferenceError: can't access lexical declaration '_sseController' before initialization`; Chrome silently ate the rejected promise. End result: every browser was running with a dead SSE stream, so `lease_request_created` and `lease_status_changed` events never reached the toast or the sidebar pending-count badge. Moved the binding to the module state block at the top so it initialises before `showApp()` runs.

## [0.14.3] - 2026-05-12

### Bug fix

- **UI HTML now serves with `Cache-Control: no-cache, must-revalidate`.** The `/` route previously sent no cache header, so browsers held onto the old single-file HTML across Gatehouse upgrades. Operators upgrading from v0.13.x to v0.14.x kept seeing the pre-approval UI (no toast, no sidebar badge update on SSE events) until they hard-refreshed. The HTML is ~300 KB and the revalidation round trip is negligible; correctness wins over the byte savings.

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
