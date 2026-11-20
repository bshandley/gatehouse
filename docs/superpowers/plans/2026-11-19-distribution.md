# Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A bare `docker run` with only a volume gives a usable vault with a unique bootstrap root token, and Gatehouse ships install templates for Unraid, Umbrel, CasaOS, and Coolify.

**Architecture:** A small `src/auth/bootstrapToken.ts` runs once at server start, after the database opens. When no root token is configured and no admin principal exists, it generates a token, persists it beside the master key, and exports it into `process.env.GATEHOUSE_ROOT_TOKEN` so the six existing root-token checks need no change. Packaging is static files under `packaging/`, guarded by one test that pins them to `VERSION`.

**Tech Stack:** Bun, `bun:sqlite`, the `yaml` package already in dependencies, Docker, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-06-05-distribution-design.md`

**Depends on:** `docs/superpowers/plans/2026-11-19-recoverability.md` merged (first-boot master key, `docker-entrypoint.sh`, `test/firstBoot.test.ts`).

## Global Constraints

- No Kubernetes manifests, no Helm chart, no HA.
- No template, compose file, or doc sets a master key or a root token value. The string `gatehouse-root-changeme` must not exist anywhere in the repo after this plan, outside `CHANGELOG.md` and the specs.
- `GATEHOUSE_ROOT_TOKEN` in the environment always wins and behaves exactly as today.
- Bootstrap token file: `${GATEHOUSE_DATA_DIR}/bootstrap-root.token`, mode `0600`, 32 hex chars (16 random bytes).
- The bootstrap banner goes to **stderr**.
- Image reference in every template: `ghcr.io/bshandley/gatehouse:<VERSION>`, pinned, bumped per release. Port `3100`. Healthcheck on `/health`. Data volume at `/data`.
- Single-instance sentence, verbatim, in the README near the top, every catalog description, and a comment in the reference compose: "Gatehouse is single-instance by design (in-memory rate limiting and an in-process event bus). Run one. It is built for a homelab, not a cluster."
- Everything under `packaging/` is public. No LAN addresses, no hostnames from the maintainer's network.
- No em dashes anywhere. Docs and tests use `api-keys/example`.
- Show the `bun test` pass count in every task report.
- Upstream catalog submissions are pull requests to other people's repositories. They are not part of any task here. They happen only on the maintainer's explicit go-ahead.
- Ships as `0.23.0`.

## Review Focus

1. **Admin exists but a stale `bootstrap-root.token` is still on the volume.** It must not be loaded. A leftover file must never be a standing root credential. Pinned in Task 1.
2. **Upgrade from the old compose.** An install whose `.env` never set `GATEHOUSE_ROOT_TOKEN` was running with the `changeme` default. After the upgrade that token must stop working, and the operator must not be locked out when an admin user exists. Pinned in Task 1 (admin exists, no env: no root token at all).
3. **Admin deleted or disabled later.** With zero enabled admins and no admin AppRole, the next boot must mint a fresh bootstrap token so the vault is recoverable, not reuse a consumed one that was already deleted. Pinned in Task 1.
4. **Read-only `/data`.** Token generation must print and continue, same as the master key fallback. Pinned in Task 1.
5. **Template drift at release.** A version bump that forgets `packaging/` ships catalogs pointing at an old image. Pinned in Task 3 (test fails until every template matches `VERSION`).

## File Structure

| File | Responsibility |
|---|---|
| `src/auth/bootstrapToken.ts` (new) | Decide, generate, persist, and announce the bootstrap root token |
| `src/index.ts` | Call it after `initDB`, expose `root_token_source` in `/v1/config` |
| `docker-compose.yml` | Reference compose: pulls the published image, zero secrets |
| `docker-compose.dev.yml` (new) | Local build override (`build: .`) |
| `packaging/unraid/gatehouse.xml` (new) | Unraid Community Apps template |
| `packaging/umbrel/` (new) | `umbrel-app.yml`, `docker-compose.yml` |
| `packaging/casaos/docker-compose.yml` (new) | CasaOS appfile with `x-casaos` |
| `packaging/coolify/docker-compose.yml` (new) | Coolify one-click compose |
| `packaging/README.md` (new) | What each template is, how to test it, the submission checklist |
| `scripts/smoke-first-boot.sh` (new) | Build the image, boot it bare, assert the first-boot contract |

---

### Task 0: Confirm the deploy receiver before touching the compose (maintainer)

The live instance redeploys on every push to `origin` through a webhook receiver. `docker-compose.yml` today has `build: .`. If the receiver runs `docker compose up --build` from this file, Task 2 changes what production runs.

- [ ] **Step 1:** Ask the maintainer what the receiver executes. Record the answer in the Linear issue for this chunk.
- [ ] **Step 2:** If it builds from `docker-compose.yml`, the receiver must switch to `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build` before Task 2 lands on `main`. Do not merge Task 2 until that is done.

---

### Task 1: Bootstrap root token

**Files:**
- Create: `src/auth/bootstrapToken.ts`, `test/bootstrapToken.test.ts`
- Modify: `src/index.ts` (immediately after `initDB`, and the `/v1/config` handler near line 246), `src/ui/index.html` (root token hint near line 6620), `test/firstBoot.test.ts`

**Interfaces:**
- Produces:

```ts
export const BOOTSTRAP_TOKEN_FILE = "bootstrap-root.token";
export function hasAdminPrincipal(db: Database): boolean;
export function resolveBootstrapRootToken(opts: {
  db: Database; dataDir: string; envToken: string | undefined;
  publicUrl: string; log?: (line: string) => void;   // log defaults to console.error
}): { token: string | null; source: "env" | "file" | "generated" | "generated-unpersisted" | "none" };
```

- `hasAdminPrincipal` is true when any `users` row has `role = 'admin'` and `enabled = 1`, or any `app_roles` row's `policies` JSON array contains `"admin"`.
- Decision order:
  1. `envToken` non-empty: `{ token: envToken, source: "env" }`. Touch nothing on disk.
  2. `hasAdminPrincipal(db)`: `{ token: null, source: "none" }`. If the token file exists, delete it and log `[gatehouse] removed stale bootstrap-root.token (an admin exists)`.
  3. Token file exists and holds 32 hex chars: `source: "file"`. Log a short reminder with the path, not the token.
  4. Otherwise generate, write `0600`, log the banner: `source: "generated"`. A write failure logs the banner with a not-persisted warning and returns `"generated-unpersisted"`.
- Banner (stderr):

```
============================================================
 GATEHOUSE BOOTSTRAP ROOT TOKEN
 Saved to: /data/bootstrap-root.token

   <the 32-char token>

 Open <publicUrl> and sign in with this token to create
 your first admin user. It stops working, and this file is
 removed, on the first restart after an admin exists.
============================================================
```

- [ ] **Step 1: Write the failing tests** in `test/bootstrapToken.test.ts` (fresh temp dir and `initDB` per test):

```ts
test("env token wins and no file is written", () => { /* source "env", file absent */ });
test("fresh vault generates a 32-hex token, 0600, and logs it with the URL", () => {
  const lines: string[] = [];
  const r = resolveBootstrapRootToken({ db, dataDir: dir, envToken: undefined, publicUrl: "http://localhost:3100", log: (l) => lines.push(l) });
  expect(r.source).toBe("generated");
  expect(r.token).toMatch(/^[0-9a-f]{32}$/);
  expect(statSync(join(dir, "bootstrap-root.token")).mode & 0o777).toBe(0o600);
  expect(lines.join("\n")).toContain(r.token!);
  expect(lines.join("\n")).toContain("http://localhost:3100");
});
test("second call with no admin reuses the file and does not log the token", () => { /* source "file", same token, log lacks it */ });
test("enabled admin user: no token, stale file deleted", () => { /* insert users row; source "none", token null, file gone */ });
test("admin AppRole counts as an admin principal", () => { /* app_roles.policies = '["admin"]' */ });
test("an AppRole whose policy is named 'administrator-readonly' does not count", () => { /* policies '["administrator-readonly"]' => hasAdminPrincipal false */ });
test("disabled admin does not count, a fresh token is minted", () => { /* enabled = 0 => source "generated" */ });
test("empty-string env token is treated as unset", () => { /* envToken "" => generated */ });
test("corrupt token file is replaced by a fresh token", () => { /* file "x" => generated, file now 32 hex */ });
test("unwritable data dir returns generated-unpersisted and still logs the token", () => { /* skip as root */ });
```

- [ ] **Step 2: Run** `bun test test/bootstrapToken.test.ts`. Expected: FAIL, module not found.

- [ ] **Step 3: Implement** `src/auth/bootstrapToken.ts`. Parse `app_roles.policies` with `JSON.parse` and an exact `includes("admin")`, not `LIKE`.

- [ ] **Step 4: Wire it** in `src/index.ts` right after `initDB`: call it with `process.env.GATEHOUSE_ROOT_TOKEN` and the resolved public URL. When `source` is `file`, `generated`, or `generated-unpersisted`, assign `process.env.GATEHOUSE_ROOT_TOKEN = token`. Add `root_token_source` (`"env" | "bootstrap" | null`) to the `/v1/config` response. In the Settings root token hint, when the source is `"bootstrap"`, say: "Temporary bootstrap token. Create an admin user and restart to retire it."

- [ ] **Step 5: Extend `test/firstBoot.test.ts`:**

```ts
test("bare boot prints a bootstrap token that authenticates as root", async () => {
  // token = contents of bootstrap-root.token; GET /v1/config with Bearer token => 200 and root_token_source "bootstrap"
  // stdout does not contain the token
});
test("the old default token does not authenticate", async () => {
  // Bearer gatehouse-root-changeme => 401
});
test("after an admin user is created, a restart retires the token", async () => {
  // create a user through the API with the bootstrap token, SIGTERM, start again:
  // file is gone, old token => 401, /v1/config (with a user login) reports root_token_set false
});
```

- [ ] **Step 6: Run** `bun test`. Expected: all pass.

- [ ] **Step 7: Commit** `feat(distribution): generated bootstrap root token`

---

### Task 2: Reference compose, env example, and first-boot smoke test in CI

**Files:**
- Create: `docker-compose.dev.yml`, `scripts/smoke-first-boot.sh`
- Modify: `docker-compose.yml`, `.env.example`, `.github/workflows/test.yml`

**Interfaces:**
- Consumes: Task 1 behavior, the entrypoint from the recoverability plan.
- Produces: `scripts/smoke-first-boot.sh [image]` (default builds `gatehouse:smoke` from the working tree). Exit `0` only when every assertion below holds.

- [ ] **Step 1: Write `scripts/smoke-first-boot.sh`** (`set -eu`, cleans up its container and volume in a `trap`). Assertions, in order:
  1. `docker run -d -p 127.0.0.1:0:3100 -v <fresh volume>:/data <image>` with no `-e` flags reaches `/health` 200 within 30 seconds.
  2. `docker logs` contains `GATEHOUSE GENERATED A NEW MASTER KEY` and `GATEHOUSE BOOTSTRAP ROOT TOKEN`.
  3. The token from the log returns 200 on `GET /v1/config`.
  4. `docker run --rm -v <same volume>:/data <image> verify` exits `0`. Record the fingerprint it prints.
  5. Restart the container. Logs since the restart contain neither banner. `verify` prints the same fingerprint.

- [ ] **Step 2: Run it** against the current tree. Expected: FAIL at assertion 2 only if Task 1 is missing. With Task 1 merged it passes, which proves the script before the compose changes.

- [ ] **Step 3: Rewrite `docker-compose.yml`:** `image: ghcr.io/bshandley/gatehouse:latest` in place of `build: .`. Remove the `GATEHOUSE_MASTER_KEY` and `GATEHOUSE_ROOT_TOKEN` lines and replace them with a comment block: first boot generates both, where they are saved, escrow the key (link to the Backup and Recovery page), and the optional stronger posture of setting `GATEHOUSE_MASTER_KEY`. Add the single-instance sentence as a comment at the top. Keep the healthcheck, the 256M and 1 CPU limits, log rotation, Homepage labels, every existing optional variable, and the commented OAuth block.

- [ ] **Step 4: Create `docker-compose.dev.yml`** containing only `services.gatehouse.build: .` and `image: gatehouse:dev`, with a header comment giving the two-file command.

- [ ] **Step 5: Update `.env.example`:** `GATEHOUSE_MASTER_KEY` and `GATEHOUSE_ROOT_TOKEN` become commented-out optional entries with no default value. Rename the "Required" section to "Optional: bring your own key".

- [ ] **Step 6: Add a CI job** `first-boot` to `.github/workflows/test.yml` that runs `scripts/smoke-first-boot.sh` on `ubuntu-latest`.

- [ ] **Step 7: Verify.** `docker compose config -q` and `docker compose -f docker-compose.yml -f docker-compose.dev.yml config -q` both exit `0`. `grep -rn "changeme" --include="*.yml" --include="*.example" --include="*.md" --include="*.mdx" --include="*.astro" . --exclude-dir=node_modules --exclude-dir=docs/superpowers --exclude=CHANGELOG.md` prints only lines Task 4 will fix (README and site).

- [ ] **Step 8: Commit** `feat(distribution): zero-secret reference compose and first-boot smoke test`

---

### Task 3: Catalog templates

**Files:**
- Create: `packaging/unraid/gatehouse.xml`, `packaging/umbrel/umbrel-app.yml`, `packaging/umbrel/docker-compose.yml`, `packaging/casaos/docker-compose.yml`, `packaging/coolify/docker-compose.yml`, `packaging/README.md`, `test/packaging.test.ts`

**Interfaces:**
- Consumes: `VERSION` from `src/version.ts`.

- [ ] **Step 1: Read the current upstream format for each catalog before writing anything.** Formats change. Do not write from memory. Sources: the Unraid Community Applications template documentation and one recently merged template, the `getumbrel/umbrel-apps` README, the `IceWhaleTech/CasaOS-AppStore` CONTRIBUTING guide, and the Coolify docs on service templates and magic environment variables. Record the URL and the date read at the top of `packaging/README.md`.

- [ ] **Step 2: Write the failing test** `test/packaging.test.ts`:

```ts
const TEMPLATES = ["packaging/unraid/gatehouse.xml", "packaging/umbrel/umbrel-app.yml", "packaging/umbrel/docker-compose.yml", "packaging/casaos/docker-compose.yml", "packaging/coolify/docker-compose.yml"];
const SINGLE = "Gatehouse is single-instance by design";
test.each(TEMPLATES)("%s exists and sets no master key or root token value", (p) => {
  const text = readFileSync(p, "utf8");
  expect(text).not.toMatch(/GATEHOUSE_MASTER_KEY\s*[=:]\s*\S/);
  expect(text).not.toMatch(/GATEHOUSE_ROOT_TOKEN\s*[=:]\s*\S/);
  expect(text).not.toContain("changeme");
});
test.each(TEMPLATES.filter((p) => !p.endsWith("umbrel-app.yml")))("%s pins the image to VERSION", (p) => {
  expect(readFileSync(p, "utf8")).toContain(`ghcr.io/bshandley/gatehouse:${VERSION}`);
});
test.each(TEMPLATES.filter((p) => p.endsWith(".yml")))("%s is valid YAML", (p) => { expect(() => YAML.parse(readFileSync(p, "utf8"))).not.toThrow(); });
test("the Unraid template is well-formed XML with a /data volume and port 3100", () => { /* balanced tags, contains Target="/data" and 3100 */ });
test("umbrel-app.yml version equals VERSION and its description carries the single-instance sentence", () => { /* ... */ });
test.each(["packaging/unraid/gatehouse.xml", "packaging/umbrel/umbrel-app.yml", "packaging/casaos/docker-compose.yml"])("%s description carries the single-instance sentence", (p) => { expect(readFileSync(p, "utf8")).toContain(SINGLE); });
test("no template contains a private address", () => { /* no 10.x, 192.168.x, 172.16-31.x, or .lan/.home.arpa hostnames */ });
test.each(TEMPLATES.filter((p) => p.includes("compose")))("%s mounts a persistent volume at /data", (p) => { /* parsed services.*.volumes has a target of /data */ });
```

- [ ] **Step 3: Run** `bun test test/packaging.test.ts`. Expected: FAIL, files missing.

- [ ] **Step 4: Write the templates** to the formats read in Step 1. Shared content: icon from `docs/logo.svg` (raw GitHub URL on `main`), category Security, WebUI on port `3100`, tagline "The agent secrets vault. Credentials never leave the vault.", post-install note that the bootstrap token and the master key are in the container log and that the key must be escrowed. Unraid exposes `GATEHOUSE_PUBLIC_URL`, `GATEHOUSE_TRUSTED_PROXIES`, `GATEHOUSE_PROXY_ALLOW_PRIVATE`, and the OAuth set as optional advanced fields. Coolify uses its generated-FQDN variable for `GATEHOUSE_PUBLIC_URL`.

- [ ] **Step 5: Write `packaging/README.md`:** one section per catalog with the upstream repo, how to test the template locally, and a submission checklist. State that submissions are manual and need the maintainer's go-ahead.

- [ ] **Step 6: Run** `bun test test/packaging.test.ts`. Expected: PASS. Run any upstream validator Step 1 turned up and note the result in the task report.

- [ ] **Step 7: Commit** `feat(distribution): Unraid, Umbrel, CasaOS, and Coolify templates`

---

### Task 4: Docs, positioning, and release 0.23.0

**Files:**
- Modify: `README.md`, `site/src/components/QuickStart.astro`, `site/src/content/docs/getting-started.mdx`, `site/src/content/docs/authentication.mdx`, `site/src/content/docs/security.mdx`, `site/src/content/docs/integrations.mdx`, `docs/integrations.md`, `CLAUDE.md` (release procedure), `docs/superpowers/specs/2026-06-05-distribution-design.md` (`Status: shipped in 0.23.0`), `CHANGELOG.md`, `src/version.ts`, `package.json`, every file under `packaging/` (version pin)

- [ ] **Step 1: README.** Quick start becomes:

```bash
docker run -d --name gatehouse -p 3100:3100 -v gatehouse-data:/data ghcr.io/bshandley/gatehouse:latest
docker logs gatehouse   # your master key and one-time bootstrap token
```

  followed by two sentences: save the master key somewhere off this host, then open the UI and sign in with the bootstrap token. Add the single-instance sentence directly under the opening paragraph. Add an "Install" line linking `packaging/` for Unraid, Umbrel, CasaOS, and Coolify, worded as "templates", not "available in" (they are not listed upstream yet).

- [ ] **Step 2: Site.** Apply the same quick start to `QuickStart.astro` and `getting-started.mdx`. Replace every instruction to set or later unset `GATEHOUSE_ROOT_TOKEN` in `authentication.mdx`, `security.mdx`, `integrations.mdx`, and `docs/integrations.md` with the bootstrap token flow, keeping the env var documented as the override. `security.mdx` gains the bootstrap token lifecycle and the upgrade note: installs that relied on the old `changeme` default lose that token on upgrade, which is intended.

- [ ] **Step 3: Release procedure.** In `CLAUDE.md` Versioning, add to step 1: "and the pinned image tag in every file under `packaging/` (`test/packaging.test.ts` fails until they match)". Add a step 6: "If `packaging/` changed, update the open upstream catalog pull requests."

- [ ] **Step 4: Bump** to `0.23.0` in `src/version.ts`, `package.json`, and `packaging/`. Add the CHANGELOG block, including a "Recommended action" line for operators upgrading from the old compose.

- [ ] **Step 5: Verify.** `bun test` passes. `bun run site:build` succeeds. `scripts/smoke-first-boot.sh` passes. The `changeme` grep from Task 2 Step 7 prints nothing. `grep -rn $'\u2014' README.md packaging site/src/content/docs CHANGELOG.md` prints nothing.

- [ ] **Step 6: Commit** `feat(0.23.0): zero-config first boot, bootstrap token, catalog templates`. Landing, tagging, and publishing follow the repo release procedure and need the maintainer's go-ahead, since a push to `origin` redeploys the live instance.

- [ ] **Step 7: Hand off the submissions.** Create one Linear issue per catalog (Unraid CA, Umbrel, CasaOS, Coolify), each labelled `needs-bradley`, each with the upstream repo and the checklist from `packaging/README.md`. Do not open any upstream pull request.
