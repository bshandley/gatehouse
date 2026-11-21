# Distribution: zero-config first boot and catalog presence

Date: 2026-06-05
Status: shipped in 0.23.0
Sub-project B of the ubiquity roadmap. Depends on A (first-boot key).

## Problem

Ubiquity for a homelab tool is a packaging problem, not a feature problem. The
publish pipeline already exists (GHCR via `.github/workflows/docker.yml`,
multi-arch amd64 and arm64, semver and `latest` tags). What is missing is
being one click away inside the places homelabbers already live, and a first
boot that does not punish a curious newcomer.

Two concrete blockers in the current packaging:

1. A bare `docker run` crashes: `GATEHOUSE_MASTER_KEY` is required and the app
   exits without it (`src/config.ts:13`). The newcomer's first experience is a
   stack trace.
2. The shipped `docker-compose.yml` sets `GATEHOUSE_ROOT_TOKEN=gatehouse-root-changeme`
   as a default. A copy-paste deployer runs a vault with a known root token.

## Goals

- A bare `docker run -v gatehouse-data:/data ghcr.io/bshandley/gatehouse`
  boots, generates and escrows a master key (via A), and is usable.
- No insecure shipped default for the root token.
- One-click or near-one-click install in Unraid Community Apps, Umbrel,
  CasaOS, and Coolify.
- A clean reference `docker-compose.yml` with sane defaults and inline
  comments.
- The "single-instance by design" fact stated wherever someone chooses to
  deploy.

## Non-goals

- Kubernetes manifests or Helm charts. Out of scope for the homelab audience.
- Multi-instance or HA. Explicitly disclaimed, not enabled.
- Changing the build or publish pipeline. It works.

## Design decisions (vetoable at review)

### D1. First boot is zero-secret, built on A

Distribution does not re-solve key generation. It consumes A's first-boot
behavior: no `GATEHOUSE_MASTER_KEY` set and a fresh volume means a key is
generated, persisted to `/data/master.key` (0600), and printed with the escrow
banner. The catalog templates therefore do not need to ask the user to paste a
key. They mount a persistent volume and start.

### D2. Generate the bootstrap root token, never ship a fixed one

Remove `GATEHOUSE_ROOT_TOKEN=gatehouse-root-changeme` from the reference
compose and all catalog templates. Instead, on first boot, if no root token
env is set and no admin user or admin AppRole exists yet, generate a random
bootstrap root token, persist it next to the master key
(`/data/bootstrap-root.token`, 0600), and print it in the boot banner with the
URL to use it. The golden path (sub-project C) consumes this token to mint the
first real admin and then walks the operator off it, after which the token
file can be deleted and the recommended steady state (`root_token_set: false`)
is reached.

Rationale: the operator needs exactly one credential to get in the door on
first boot, it must be unique per install, and it must be visibly temporary.
This matches the existing settings nudge that already calls "Not set" the
recommended steady state.

### D3. Catalog templates, one per ecosystem

Add a `packaging/` tree, Gitea-tracked, with a template per catalog. Each
references `ghcr.io/bshandley/gatehouse:latest` (or a pinned version), a named
data volume, port 3100, and the healthcheck on `/health`. None sets a master
key or a root token (D1, D2 handle those).

- `packaging/unraid/gatehouse.xml`: Unraid Community Apps template. Volume
  `/data`, optional `/config`, port mapping, the icon and description, the
  WebUI link, and the env vars exposed as optional advanced fields
  (`GATEHOUSE_PUBLIC_URL`, `GATEHOUSE_TRUSTED_PROXIES`,
  `GATEHOUSE_PROXY_ALLOW_PRIVATE`, the OAuth set).
- `packaging/umbrel/`: `docker-compose.yml` plus `umbrel-app.yml` manifest
  (id, name, tagline, category Security, the single-instance note in the
  description, port, the proxy/app-proxy block Umbrel expects).
- `packaging/casaos/`: CasaOS appfile (compose plus the CasaOS `x-casaos`
  metadata block: icon, tagline, the volume and port mapping, the post-install
  tip pointing at the first-run wizard).
- `packaging/coolify/`: a one-click compose with Coolify magic-env hints for
  the generated values and the persistent volume.

Submission to each upstream catalog is a manual PR per ecosystem, tracked as
release tasks, not code in this repo. The templates are the source of truth we
keep in sync on each release.

### D4. Reference compose, hardened

Rewrite `docker-compose.yml` to the zero-secret default: named volume, port,
healthcheck, resource limits (keep the existing 256M / 1 CPU), log rotation,
the Homepage labels. Drop the root-token default. Comments call out the
generated-key escrow step, the optional reverse-proxy and split-DNS vars, and
the single-instance fact. Keep the commented OAuth bootstrap block.

### D5. Single-instance positioning, stated everywhere it matters

One sentence, consistent, in: the README near the top, every catalog
description, and a comment in the reference compose. Wording: "Gatehouse is
single-instance by design (in-memory rate limiting and an in-process event
bus). Run one. It is built for a homelab, not a cluster." This is honesty that
prevents a class of bad deploys and support load.

## Components

- A's `keyfile.ts` and the new `bootstrap-root.token` generation in the boot
  path (small addition to startup in `src/index.ts`, gated on "no token env
  and no admin principal exists").
- `packaging/` templates (one dir per ecosystem).
- Rewritten `docker-compose.yml`.
- README and docs copy for D5.
- A release checklist addition: bump the pinned image tag in each template,
  open or update the upstream catalog PRs.

## Error handling and edge cases

- Read-only `/data` volume: A's fallback applies (print key, warn, continue).
  The root-token generation uses the same fallback: print it, do not crash.
- Existing installs that already set `GATEHOUSE_ROOT_TOKEN`: unchanged, env
  always wins. The generated bootstrap token only appears when nothing is set
  and no admin principal exists.
- A user upgrading from the old compose with the `changeme` token keeps it
  until they remove it. Release notes call this out as a recommended action.

## Testing

- Boot the image with an empty volume and no env, assert it serves `/health`
  and that the banner printed both a master key and a bootstrap root token.
- Boot again against the same volume, assert no new key or token is generated
  and the same key fingerprint is reported.
- Lint each catalog template against its schema where a validator exists
  (Unraid template XML, Umbrel app manifest).

## Rollout

1. Bootstrap-root-token generation in the boot path (after A lands).
2. Rewritten reference compose, README and docs positioning.
3. `packaging/` templates.
4. Upstream catalog submissions, one PR per ecosystem, tracked per release.

## Resolved questions (2026-11-19)

Plan: `docs/superpowers/plans/2026-11-19-distribution.md`.

- The bootstrap root token is persisted to `/data/bootstrap-root.token`
  (0600). It does not wait for the golden path to retire it: on any boot where
  an admin principal exists and no root token env is set, the file is deleted
  and no root token is active. The golden path (C) can later retire it live,
  without the restart.
- An admin principal is an enabled `users` row with role `admin`, or an
  AppRole whose policy list contains `admin` exactly.
- Catalog templates pin a version tag. `test/packaging.test.ts` fails until
  every template matches `VERSION`, so a release cannot forget them.
- The reference compose pulls the published image. Building from source moves
  to a `docker-compose.dev.yml` override.
- Upstream catalog submissions are manual and need the maintainer's go-ahead
  each time.

## Amendment (2026-11-21): TrueNAS SCALE

TrueNAS was missed in the original target list, not excluded. Before 24.10
(Electric Eel) SCALE apps ran on k3s, which the Kubernetes non-goal covers.
From 24.10 on they are plain Docker Compose, so TrueNAS is a fifth D3 target.

- `packaging/truenas/docker-compose.yml`: a compose for SCALE's
  Apps, Discover, Install via YAML (custom app). Literal values only: the
  YAML editor does not read `.env` or expand `${VAR:-default}`.
- Named volume at `/data`, image default user. This dodges the bind-mount
  ownership trap (README, Known limitation) and needs no passwd entry for a
  foreign uid. A commented host-path alternative (a dataset under `/mnt`,
  run as the TrueNAS `apps` user `568:568`) is documented, with the `chown`
  step, for operators who want the vault on a snapshotted dataset.
- Shipped as a patch release. A `truenas/apps` community-train catalog
  entry (`app.yaml`, `questions.yaml`, Jinja templates) is later work under
  the upstream submission task, not this amendment.
