# Gatehouse: Claude Code workflow notes

This file is workflow context for AI assistants working in this repo. It is
public, like everything else on `main`. Keep machine-specific details (LAN
addresses, tokens, local paths) out of it.

## Project

Gatehouse is an **agent secrets vault**: a self-hosted secrets manager built
for AI agent harnesses. Primary search positioning targets the phrase
"agent secrets vault" verbatim. Keep it prominent in README, site meta, and
GitHub About copy. Secondary phrases: "secrets manager for AI agents",
"self-hosted Vault alternative", "MCP secrets server", "homelab credential
vault".

Maintainer: Bradley, a homelabber running self-hosted infrastructure.

## Workflow and Linear (project bindings)

The general brainstorm-to-ship loop, the source-of-truth lanes, and the Linear
usage policy live in `~/.claude/CLAUDE.md` (user-level, applies to all
projects). Gatehouse-specific bindings:

- **Linear:** team `Bradley` / prefix `BRA`, project `Gatehouse`. Milestones
  A-E mirror `docs/superpowers/specs/2026-06-05-ubiquity-roadmap-design.md`.
- **Specs and plans** live under `docs/superpowers/` and are public.
- **Ship steps** for this repo: the Versioning section and the remotes
  section below.

## Remotes: one history, two homes

Design: `docs/superpowers/specs/2026-11-18-single-history-design.md`.

| Remote   | Where          | Holds                                          |
|----------|----------------|------------------------------------------------|
| `origin` | private Gitea  | `main`, release tags, private feature branches |
| `github` | `github.com/bshandley/gatehouse` | `main` and release tags only |

GitHub `main` is the canonical public branch. Gitea carries the same commits
with identical SHAs. There is no sync script and no divergent history.

`origin` is Gitea on purpose: a bare `git push` lands privately. Publishing is
always an explicit push to `github`.

### Day to day

```sh
# feature work: private until merged
git switch -c my-feature main
git push -u origin my-feature        # after every commit, push to origin

# landing: squash-merge, then publish main to both remotes
git switch main
git merge --squash my-feature && git commit
git push origin main
git push github main
```

- **Push after every commit.** Feature branches go to `origin` only. `main`
  goes to `origin` and `github`. Do not wait to be asked.
- **Squash-merge is the default** for landing a feature branch, so
  intermediate private commits never become public history.
- **GitHub-side changes** (dependabot, outside pull requests) are merged on
  GitHub, then brought down: `git pull --ff-only github main` followed by
  `git push origin main`. Never re-author them by hand on Gitea.
- **Never force-push `main`** on either remote.

### What must never reach `github`

- Feature branches. Only `main` and `v*.*.*` tags are pushed there.
- `git push github --all`, `--mirror`, or `--tags`. Push release tags by name.
- A spec or fix for an unfixed security issue. Keep it on a Gitea-only branch
  until the fix merges.
- Anything from the pre-2026-11 history. It was archived to a separate private
  repo (`gatehouse-legacy`) precisely so it cannot be pushed from here.

Everything committed on a feature branch becomes public when it merges. Treat
every commit as public from the start: no tokens, no LAN addresses, no
credentialed URLs, including in plans.

### Secret-scanner trap

GitHub push protection rescans the entire content of every file in a pushed
diff, not just the touched lines. Pre-existing literals like
`api-keys/` followed by a real provider name, or the matching
`{{secret:...}}` form, will trip provider-key protection on any file you
modify, even if those lines were not part of your change.

Use `api-keys/example` (or `api-keys/example2` for a second placeholder) in
docs, specs, plans, and new tests. If a push to `github` is rejected, fix the
literal in a new commit. Do not bypass the protection.

## Versioning

Single source of truth: `src/version.ts` (`export const VERSION`).

- `test/mcp.test.ts` imports VERSION at runtime, so it stays in sync
  automatically.
- `Dockerfile` accepts `VERSION` as a build arg.
- `package.json` carries the same version. It is not load-bearing, but bump
  it with `src/version.ts` so the two do not drift.

Bump rules (pre-1.0):

- **MINOR** (`0.x.0`): new features, breaking changes.
- **PATCH** (`0.0.x`): bug fixes, doc-only changes.

Release procedure:

1. Update `VERSION` in `src/version.ts` and `version` in `package.json`.
2. Update `CHANGELOG.md` with the new version block.
3. Commit using the existing style: `feat(0.x.y): summary` or `fix(0.x.y): summary`
   (`git log` shows the pattern).
4. Push `main` to `origin` and `github`.
5. `git tag v0.x.y`, then `git push origin v0.x.y && git push github v0.x.y`.
   The tag push triggers the GitHub release and Docker image workflows.

## Style and voice

- **Never use em dashes** anywhere: code, docs, commit messages, chat
  output, anywhere. Use periods, colons, commas, parentheses, or
  restructure the sentence. This is a hard rule.
- Voice across README, site, and release notes is terse, opinionated,
  technical. Avoid marketing fluff and keyword stuffing.

## Design decisions to preserve

- **No grants / auto-policy feature.** Do not propose or rebuild a grants
  UI, `auto:approle:<role_id>` namespace, `/v1/grants/secret` endpoint,
  per-secret quick-grant buttons, or anything that writes policies on the
  user's behalf. The model is: hand-author a policy, attach it to an
  agent. If a design tempts you toward auto-policies, flag it and propose
  the explicit path instead.

## Credentials and secrets

The repo contains no secrets. Runtime needs:

- **Gitea push access**: a credential helper, never a token in a remote URL
  or in any committed file.
- **GitHub push access**: the maintainer's `gh` login or a credential helper.
- Runtime config: see `.env.example`. The real `.env` is gitignored.

## Onboarding a new machine

1. Clone from Gitea (this makes it `origin`).
2. Add the public remote and pin what it may receive:
   ```sh
   git remote add github https://github.com/bshandley/gatehouse.git
   git config remote.github.push refs/heads/main:refs/heads/main
   git config remote.github.tagOpt --no-tags
   ```
3. Install: `bun install`.
4. Local `.env` (copy from `.env.example` and fill).
5. Read this file.

That is the full handoff. No memory-system files need to follow.
