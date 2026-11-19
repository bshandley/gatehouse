# Single history: GitHub main is canonical

Date: 2026-11-18
Status: design, approved in chat, cutover pending
Scope: repository topology and release workflow. No product code changes.

## Problem

Gatehouse had two remotes with intentionally divergent histories. Gitea held
granular commits plus private paths (`docs/superpowers/`, `scripts/internal/`,
`CLAUDE.md`). GitHub held one squash commit per release, produced by
`scripts/internal/sync-to-github.ts`, with the private paths stripped.

That model only holds while nothing ever writes to GitHub. It broke on
2026-10-13 when dependabot PR #4 (astro 6 to 7) was merged on GitHub:

- The merge commit could not be pulled into Gitea. The change had to be
  re-authored by hand as a "companion" commit (`1343bb1`).
- The two trees drifted anyway. GitHub kept `@astrojs/mdx ^4` next to astro 7.
- The sync overlaid files without deleting removed ones, so three stale CSS
  files had been sitting on GitHub since April.
- Any outside pull request would hit the same wall. That works against the
  ubiquity roadmap.

## Decision

One history. GitHub `main` is the canonical public branch. Gitea carries the
same commits (identical SHAs) and additionally holds private work in progress.

| Remote   | Name     | Holds                                             |
|----------|----------|---------------------------------------------------|
| Gitea    | `origin` | `main`, release tags, private feature branches    |
| GitHub   | `github` | `main` and release tags only                      |

`origin` stays Gitea on purpose: a bare `git push` lands privately. Publishing
is always an explicit `git push github main`.

GitHub has no private branches in a public repo, so "private branch" means "a
branch that exists only on Gitea".

## What becomes public

- `docs/superpowers/specs/` and `docs/superpowers/plans/`. Public design docs
  are normal for open source and an asset for a secrets vault: the threat
  model and reasoning are inspectable.
- `CLAUDE.md`, rewritten for the new workflow with LAN details removed.

What does not:

- `scripts/internal/` is deleted. The sync script has no job in a single
  history.
- A spec for an unfixed security issue stays on a Gitea-only branch until the
  fix merges.

## Scrub performed before publication

- Three plans embedded a Gitea access token in `git push http://user:token@...`
  lines (39 occurrences). Replaced with `git push origin`. The token must be
  rotated regardless: it remains in the legacy history.
- `api-keys/openai` literals in two specs rewritten to `api-keys/example`
  (GitHub push protection trap).
- Checked for LAN addresses, hostnames, emails, and credentialed URLs across
  all specs and plans. None remain beyond RFC 1918 example values that were
  already public in tests and the changelog.

## Cutover

1. Archive: mirror every current Gitea ref (branches and all 55 tags) to a new
   private Gitea repo, `gatehouse-legacy`. The old granular history stays
   readable there.
2. Publish: one commit on top of GitHub `main` that brings the tree level with
   Gitea `main`, adds the scrubbed private paths, deletes the three stale CSS
   files, and removes `scripts/internal/`. Fast-forward only. GitHub `main` is
   never force-pushed.
3. Realign Gitea: force `main` to the GitHub commit, replace tags with
   GitHub's, delete the legacy branches and the 14 tags that never reached
   GitHub (they live on in `gatehouse-legacy`).
4. Realign clones: every other working copy must be re-cloned or hard reset.
   Old and new `main` share no ancestor.

Step 3 is why the legacy history leaves the working repo entirely instead of
living on as a `legacy/main` branch. Any legacy ref left in the repo is one
`git push github --tags` away from publishing the old history, token included.

## Workflow after cutover

- Feature work: branch from `main`, push the branch to `origin` only.
- Landing: squash-merge into `main`, then push `main` to both remotes. Squash
  is the default so intermediate private commits never become public history.
- GitHub-side changes (dependabot, outside PRs): merge on GitHub, then
  `git pull github main` and `git push origin main`.
- Releases: tag on `main`, push the tag to both remotes. The existing GitHub
  workflows (`docker.yml`, `release.yml`) already trigger on `v*.*.*` tags.
- Guard: `remote.github.push` is pinned to `refs/heads/main` so a bare
  `git push github` can only ever push `main`.

## Trade-offs accepted

- Public history before this date stays squash-per-release. The granular
  history is private in `gatehouse-legacy`.
- Anything committed on a feature branch becomes public at merge (the tree, if
  squashed). Secrets hygiene moves from sync time to commit time.
- `docs/` is the GitHub Pages root with `.nojekyll`, so the markdown under
  `docs/superpowers/` is reachable by URL on the site domain. It is unlinked
  and already public on GitHub. Left as is to keep the path convention.
- The sync script was a working example of driving the GitHub API through the
  Gatehouse proxy without the PAT entering the agent process. That dogfooding
  is lost. Pushes now use ordinary git credentials.
