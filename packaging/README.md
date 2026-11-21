# Catalog templates

Gatehouse is single-instance by design (in-memory rate limiting and an in-process event bus). Run one. It is built for a homelab, not a cluster.

Static install templates for five self-hosting platforms. None of them sets a master key or a root token. On first boot the container generates both and prints them once to the container log; copy them from there, and escrow the master key off-box.

Every template pins `ghcr.io/bshandley/gatehouse:<VERSION>` (the value in `src/version.ts`). Bump them with the version at release time. `test/packaging.test.ts` fails if they drift.

Submissions to the upstream catalogs are manual and need the maintainer's go-ahead. Nothing here has been submitted, and no template has been installed on a real platform.

## Known limitation: bind-mount ownership

Docker creates a missing bind-mount source as `root:root` mode 0755. The Unraid, Umbrel, and CasaOS templates bind-mount a host directory and run the container as a non-root uid (`99:100` or `1000:1000`), so on a fresh install first boot fails writing `/data/master.key` unless the directory already exists with the right owner. Each section below gives the commands to run before first start. The image does not start as root and fix ownership itself (the common `chown`-then-drop-privileges entrypoint). Whether to change that is an open decision for the maintainer. The Coolify and TrueNAS templates use a named volume, which takes the image's ownership, so they are not affected (TrueNAS documents an optional host-path variant with its own `chown` step).

## Upstream docs read (2026-11-19)

Format sources, read before writing:

- Umbrel: https://raw.githubusercontent.com/getumbrel/umbrel-apps/master/AGENTS.md and `.agents/skills/umbrel-package-app/SKILL.md` in the same repo; reference app `vaultwarden/` (manifest and compose).
- CasaOS: https://raw.githubusercontent.com/IceWhaleTech/CasaOS-AppStore/main/CONTRIBUTING.md, `docs/specs/overview.md`, `docs/specs/compose-and-x-casaos.md`, `docs/quick-start/overview.md`; reference app `Apps/Vaultwarden/docker-compose.yml`.
- Coolify: https://coolify.io/docs/knowledge-base/docker/compose, https://coolify.io/docs/get-started/contribute/service; reference templates `templates/compose/vaultwarden.yaml` and `uptime-kuma.yaml` in `coollabsio/coolify` (branch `v4.x`).
- TrueNAS: https://apps.truenas.com/managing-apps/installing-custom-apps/ and https://www.truenas.com/docs/scale/apps/installcustomappscreens (Install via YAML, SCALE 24.10 and later).
- Unraid: https://ca.unraid.net/submit/help, https://ca.unraid.net/submit/help/xml-field-reference, https://ca.unraid.net/submit/help/repository-xml; reference template `templates/vaultwarden.xml` in `selfhosters/unRAID-CA-templates`.

Unverified: the Unraid `Config` attribute and Category value lists were not on the pages reachable (the field reference page does not document them). The Config elements follow the reference template and the repository-xml example. Umbrel's category taxonomy list was not found; `developer` is a best guess. Marked "format unverified" below where it matters.

## Unraid Community Applications

- Template: `unraid/gatehouse.xml`. Upstream: submit through https://ca.unraid.net/submit/new (needs a public template repository with `ca_profile.xml` and an OSI license).
- Test locally: copy the file to `/boot/config/plugins/dockerMan/templates-user/gatehouse.xml` on an Unraid box, then Docker tab, Add Container, pick the template.
- Ownership: untested on a real install. The template runs the container as `99:100` (`<ExtraParams>--user 99:100</ExtraParams>`, the same mechanism as other CA templates such as autobrr and podgrab). On a fresh install, expect first boot to fail with a permission error writing `/data/master.key` unless `/mnt/user/appdata/gatehouse` already exists owned by `99:100`. Before first start, from the Unraid terminal: `mkdir -p /mnt/user/appdata/gatehouse && chown -R 99:100 /mnt/user/appdata/gatehouse`.
- uid 99 has a passwd entry in the image (user `unraid`, group 100) because `ssh-keygen`, used by the SSH certificate provider, exits with "No user exists for uid" without one. The CI smoke job checks this under `--user 99:100`; it has not been checked on Unraid itself.
- Checklist:
  - [ ] Maintainer approves submission.
  - [ ] Test the template on a real Unraid box, including first boot with a fresh appdata directory.
  - [ ] Test SSH certificate checkout (the `ssh-keygen` path) on a real install running as `99:100`.
  - [ ] Unraid forum support thread created; put its URL in `<Support>` (currently the GitHub issues page).
  - [ ] Repository for the template with `ca_profile.xml` and an OSI-approved `LICENSE`.
  - [ ] Icon: `docs/logo.svg` is used via raw GitHub URL. Unraid templates in the wild use PNG; confirm SVG renders, else produce a PNG (open item, not invented here).
  - [ ] Run Validate and Scan in the submission flow.
  - [ ] Bump the `<Repository>` tag with each release.

## Umbrel

- Files: `umbrel/umbrel-app.yml`, `umbrel/docker-compose.yml`, `umbrel/data/.gitkeep`. Upstream: https://github.com/getumbrel/umbrel-apps (a directory named `gatehouse/` holds all three).
- Test locally: copy the directory into a community app store repo (or `app-stores/`) on an umbrelOS dev instance and install it.
- Conflicts with upstream rules, left open on purpose:
  - Upstream requires `image:tag@sha256:<multi-arch digest>`. The digest only exists once the release image is published, so the template carries the tag only. Add `@sha256:...` from `docker buildx imagetools inspect` at submission time.
  - Upstream wants `port` unique across the store. 3100 is not checked for collisions.
  - Proxy auth: the template sets `PROXY_AUTH_ADD: "false"` on `app_proxy` (confirmed against Umbrel's reference `vaultwarden/docker-compose.yml`, same variable and placement). Gatehouse has its own login, and agents and MCP clients cannot pass Umbrel's, so Umbrel's login is not layered in front. Untested on a real Umbrel. Umbrel's guidance prefers keeping its auth on with a narrow whitelist; a reviewer may ask for that instead.
  - `GATEHOUSE_PUBLIC_URL` and `GATEHOUSE_TRUSTED_PROXIES` are left unset (upstream says avoid fixed public URLs). Users with IP allowlists behind the proxy must set the trusted proxy CIDR.
  - Icon and gallery are hosted by the Umbrel team, not in the package.
- Ownership: untested on a real install. The service runs as `1000:1000` (Umbrel's guidance and its vaultwarden app do the same for `${APP_DATA_DIR}/data`). The package ships `umbrel/data/.gitkeep` so the `data/` directory exists in the package; Umbrel copies the package's data directory into `${APP_DATA_DIR}` with the app user as owner, so `${APP_DATA_DIR}/data` should already belong to `1000:1000` on first start. If it does not (expected if the directory is missing and Docker creates it as root), first boot fails writing `/data/master.key`. Before first start, or to recover: `sudo mkdir -p ~/umbrel/app-data/gatehouse/data && sudo chown -R 1000:1000 ~/umbrel/app-data/gatehouse/data` (path assumes the default Umbrel install root).
- Checklist:
  - [ ] Maintainer approves submission.
  - [ ] Test the template on a real umbrelOS install, including first boot, restart, and proxy access without Umbrel login.
  - [ ] Add image digest, confirm `linux/amd64` and `linux/arm64` are in the manifest list.
  - [ ] Decide app_proxy auth whitelist.
  - [ ] Set `submission` (PR URL) and confirm the category.
  - [ ] Test install, restart, and update on umbrelOS; confirm `/data` survives.

## CasaOS / ZimaOS

- File: `casaos/docker-compose.yml`. Upstream: https://github.com/IceWhaleTech/CasaOS-AppStore (`Apps/Gatehouse/`, next to `icon.svg`, `thumbnail.png`, `screenshot-1.png`).
- Test locally: `docker compose -f casaos/docker-compose.yml config -q`, then CasaOS custom install (import compose). Store build: `./scripts/build_dist.sh` in a clone of the store repo.
- Notes: published port 3100 is required by the store model (`port_map`); Developer is the closest category. `x-casaos.id` uses a reverse-domain placeholder (`to.gatehouse.gatehouse`) to confirm with the maintainer. The legacy store used a `org.icewhale.*` id for first-party apps only.
- Ownership: untested on a real install. The service runs as `1000:1000`, the convention in the store's non-root apps (BeaverHabitTracker, LibreChat). `PUID`/`PGID` variables are a linuxserver.io image feature and do nothing here. On a fresh install, expect first boot to fail with a permission error writing `/data/master.key` unless `/DATA/AppData/gatehouse/data` already exists owned by `1000:1000`. Before first start: `sudo mkdir -p /DATA/AppData/gatehouse/data && sudo chown -R 1000:1000 /DATA/AppData/gatehouse/data`.
- Checklist:
  - [ ] Maintainer approves submission.
  - [ ] Test the template on a real CasaOS or ZimaOS install, including first boot with a fresh data directory.
  - [ ] Icon: store build rewrites it, but the repo convention is a file in the app folder; SVG is accepted (`icon.svg`).
  - [ ] Thumbnail and screenshots (not created here).
  - [ ] Run `./scripts/build_dist.sh` and `docker compose config -q`.

## Coolify

- File: `coolify/docker-compose.yml` (a service template; upstream path is `templates/compose/gatehouse.yaml`). Upstream: https://github.com/coollabsio/coolify.
- Test locally: in Coolify, create a Docker Compose Empty resource and paste the file. Confirm the generated domain loads and the data volume persists across redeploy.
- Notes: `SERVICE_URL_GATEHOUSE_3100` makes Coolify generate a domain routed to container port 3100 and feeds `GATEHOUSE_PUBLIC_URL` (the URL form includes the scheme, which is what Gatehouse wants; the FQDN form does not). Trusted proxies default to empty: Coolify's Traefik is on a Docker network, so IP allowlists behind it fail closed until the user sets the proxy CIDR.
- Upstream conditions: the service project needs at least 1,000 GitHub stars, external template contributions were paused at the time of reading, and a docs PR is required with the template PR. The logo path (`svgs/gatehouse.svg`) must be added in that PR.
- Checklist:
  - [ ] Maintainer approves submission and the star threshold is met.
  - [ ] Add `svgs/gatehouse.svg` and the docs page.
  - [ ] Test on a Docker Compose Empty resource.
  - [ ] Confirm whether `SERVICE_URL_GATEHOUSE_3100` carries a `:3100` port suffix. If it does, `GATEHOUSE_PUBLIC_URL` points past the proxy and needs a different source.
  - [ ] Bump the image tag with each release.

## TrueNAS SCALE

- File: `truenas/docker-compose.yml`. For SCALE 24.10 (Electric Eel) and later, where apps are Docker Compose. Earlier releases ran apps on k3s and are not supported.
- Install: Apps, Discover, the three-dot menu, Install via YAML. Name the app `gatehouse`, paste the file. The editor does not read `.env` or expand `${VAR}`, so the template uses literal values; edit them in the editor.
- Storage: a named volume by default (lands in the `ix-apps` dataset, no ownership setup). The file's header comments give the host-path variant: a dataset under `/mnt/<pool>`, `chown -R 568:568`, and `user: "568:568"` on the service. uid 568 (`apps`) has a passwd entry in the image so `ssh-keygen` works under it; the CI smoke job checks this, it has not been checked on TrueNAS itself.
- Known UI limit: a YAML-installed custom app shows the generic app icon.
- Upstream: no catalog entry yet. The official catalog is https://github.com/truenas/apps (`community` train), which takes its own format (`app.yaml`, `questions.yaml`, `ix_values.yaml`, a Jinja compose on their render library). That is later work, tracked with the other submissions.
- Checklist:
  - [ ] Test Install via YAML on a real SCALE 24.10+ box: first boot, logs show key and token, restart keeps `/data`.
  - [ ] Test the host-path variant as `568:568`, including SSH certificate checkout.
  - [ ] Catalog entry for `truenas/apps` (community train), with maintainer go-ahead.
  - [ ] Bump the image tag with each release.
