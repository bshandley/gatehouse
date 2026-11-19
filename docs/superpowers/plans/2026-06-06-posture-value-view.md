# Posture and Value View Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Gatehouse's invisible security work visible: persist a count of credentials kept out of agent context, surface secret-hygiene nudges (stale / old), and show blocked egress, all on the existing dashboard.

**Architecture:** Three independent slices on top of the existing SQLite + Hono + vanilla-JS stack. (1) Hygiene: a `last_accessed_at` column on `secrets`, written on every read path, queried for stale/old counts. (2) Value: `scrubResponseBody` returns a redaction count that is threaded into the existing `proxy.forward*` audit metadata, plus a new `scrub.redact` audit event for explicit scrubs. (3) A single windowed read endpoint `GET /v1/stats/posture` that aggregates from the audit log and the `secrets` table, rendered as dashboard cards. No new analytics pipeline, no hot-path writes beyond fields already being assembled, no security-critical path touched.

**Tech Stack:** Bun, `bun:sqlite`, Hono, TypeScript, vanilla JS (no framework), `bun test`.

---

## Source spec

`docs/superpowers/specs/2026-06-05-posture-value-view-design.md` (sub-project D of the ubiquity roadmap).

## Conventions in this codebase (verified)

- **No em dashes anywhere** (code, comments, commits). Hard project rule.
- Migrations live inline in `src/db/init.ts` using the `PRAGMA table_info(<table>)` guard pattern (see `init.ts:231-285`).
- Audit metadata is `Record<string, string>` (all values stringified). See `src/audit/logger.ts:4-12`.
- Audit actions already in use: `proxy.forward`, `proxy.forward.mcp` (success and `success:false`), `proxy.blocked.rate_limit`, `proxy.blocked.approval`, `secret.reveal_value`, `secret.read.mcp`. Blocked-forward rows carry `metadata.reason` in `{ssrf_blocked, domain_blocked, path_prefix_blocked, policy_denied}`.
- Endpoint tests build a `new Hono()`, inject auth via a test middleware that calls `c.set("auth", {...})`, and use `app.request(...)`. Pattern: `test/secrets.test.ts:275-287` and `test/proxy.test.ts:48-60`.
- UI pure formatters live in `src/ui/secret-detail-render.js` (imported by both `bun test` and `index.html` via `window.SecretDetail`). Tests: `test/secretDetailRender.test.ts`.
- Run a single test file: `bun test test/<file>.ts`. Run all: `bun test`.
- Admin gate: `policies.check(auth.policies, "*", "admin")` (see `src/api/audit.ts:11`).
- **Surface the test pass count** ("✓ N pass") in the summary after every `bun test` run.

## File map

- `src/db/init.ts` — Modify: add `last_accessed_at` to the `secrets` CREATE TABLE and a migration block. (Task 1)
- `src/secrets/engine.ts` — Modify: expose `last_accessed_at`, add `markAccessed()` and `hygieneCounts()`. (Tasks 2, 3)
- `src/api/secrets.ts` — Modify: call `markAccessed` on value reads. (Task 4)
- `src/mcp/server.ts` — Modify: call `markAccessed` on `gatehouse_get`; thread redaction count into `proxy.forward.mcp`; emit `scrub.redact`. (Tasks 4, 7, 8)
- `src/api/lease.ts` — Modify: call `markAccessed` on static lease checkout. (Task 4)
- `src/security/ssrf.ts` — Modify: `scrubResponseBody` returns `{ body, count }`. (Task 5)
- `src/api/proxy.ts` — Modify: consume `.body`; thread redaction count into `proxy.forward`. (Tasks 5, 6)
- `src/api/scrub.ts` — Modify: accept `audit`, emit `scrub.redact`. (Task 8)
- `src/audit/logger.ts` — Modify: add `sumRedactions()` and `blockedEgress()`. (Task 9)
- `src/api/stats.ts` — Create: `GET /v1/stats/posture`. (Task 10)
- `src/index.ts` — Modify: pass `audit` to `scrubRouter`, mount `statsRouter`. (Tasks 8, 10)
- `src/ui/secret-detail-render.js` — Modify: add `hygieneFlags`, `hygieneBadgeHtml`, `formatHygieneSummary`. (Task 12)
- `src/ui/index.html` — Modify: posture cards, hygiene summary, tree badges, detail "Last used". (Task 13)
- `src/version.ts`, `CHANGELOG.md` — Modify: bump to 0.20.0. (Task 14)
- `test/posture.hygiene.test.ts` — Create (Tasks 1-4).
- `test/posture.stats.test.ts` — Create (Tasks 9, 10).
- `test/scrubResponseBody.test.ts` — Modify (Task 5).
- `test/secretDetailRender.test.ts` — Modify (Task 12).

---

## Task 1: `last_accessed_at` column + backfill migration

**Files:**
- Modify: `src/db/init.ts:18-30` (secrets CREATE TABLE) and `src/db/init.ts:287` (after the lease migration block, before the `// Indexes` comment)
- Test: `test/posture.hygiene.test.ts`

- [ ] **Step 1: Write the failing test**

Create `test/posture.hygiene.test.ts`:

```ts
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("last_accessed_at migration", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-posture-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test("fresh init creates the secrets.last_accessed_at column", () => {
    const db = initDB(dir);
    const cols = (db.query("PRAGMA table_info(secrets)").all() as { name: string }[]).map(
      (c) => c.name
    );
    expect(cols).toContain("last_accessed_at");
    db.close();
  });

  test("existing db without the column is migrated and backfilled to updated_at", () => {
    // Simulate a legacy database: a secrets table without last_accessed_at.
    const dbPath = join(dir, "gatehouse.db");
    const legacy = new Database(dbPath, { create: true });
    legacy.run(`
      CREATE TABLE secrets (
        path TEXT PRIMARY KEY,
        encrypted_value BLOB NOT NULL,
        nonce BLOB NOT NULL,
        encrypted_dek BLOB NOT NULL,
        dek_nonce BLOB NOT NULL,
        metadata TEXT DEFAULT '{}',
        version INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT '2020-01-01 00:00:00'
      )
    `);
    legacy.run(
      "INSERT INTO secrets (path, encrypted_value, nonce, encrypted_dek, dek_nonce) VALUES ('old/secret', x'00', x'00', x'00', x'00')"
    );
    legacy.close();

    const db = initDB(dir);
    const cols = (db.query("PRAGMA table_info(secrets)").all() as { name: string }[]).map(
      (c) => c.name
    );
    expect(cols).toContain("last_accessed_at");

    const row = db
      .query("SELECT updated_at, last_accessed_at FROM secrets WHERE path = 'old/secret'")
      .get() as { updated_at: string; last_accessed_at: string };
    expect(row.last_accessed_at).toBe(row.updated_at);
    expect(row.last_accessed_at).toBe("2020-01-01 00:00:00");
    db.close();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/posture.hygiene.test.ts`
Expected: FAIL. Both tests fail because `last_accessed_at` does not exist (`cols` does not contain it; the migrated query throws or returns undefined).

- [ ] **Step 3: Add the column to the CREATE TABLE**

In `src/db/init.ts`, change the secrets table definition (currently lines 18-30) to add the column after `updated_at`:

```ts
  // Secrets table
  db.run(`
    CREATE TABLE IF NOT EXISTS secrets (
      path TEXT PRIMARY KEY,
      encrypted_value BLOB NOT NULL,
      nonce BLOB NOT NULL,
      encrypted_dek BLOB NOT NULL,
      dek_nonce BLOB NOT NULL,
      metadata TEXT DEFAULT '{}',
      version INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      last_accessed_at TEXT
    )
  `);
```

- [ ] **Step 4: Add the migration block for existing databases**

In `src/db/init.ts`, immediately after the lease migration block (after line 286, the closing of the `request_expires_at` check) and before the `// Indexes` comment, add:

```ts
  // Secrets migration: last_accessed_at for hygiene/posture (sub-project D).
  // Backfill existing rows to updated_at as a reasonable "last touched" floor.
  const secretCols = db.query("PRAGMA table_info(secrets)").all() as { name: string }[];
  const secretColNames = secretCols.map((c) => c.name);
  if (secretColNames.length > 0 && !secretColNames.includes("last_accessed_at")) {
    db.run("ALTER TABLE secrets ADD COLUMN last_accessed_at TEXT");
    db.run("UPDATE secrets SET last_accessed_at = updated_at WHERE last_accessed_at IS NULL");
  }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bun test test/posture.hygiene.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add src/db/init.ts test/posture.hygiene.test.ts
git commit -m "feat(0.20.0): add secrets.last_accessed_at column + backfill migration"
git push origin main
```

---

## Task 2: SecretsEngine exposes `last_accessed_at` and `markAccessed()`

**Files:**
- Modify: `src/secrets/engine.ts` (the `StoredSecret` interface at lines 6-12; `getMeta` at 227-243; `list` at 245-259; add `markAccessed`)
- Test: `test/posture.hygiene.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `test/posture.hygiene.test.ts` (add `SecretsEngine` to imports at the top: `import { SecretsEngine } from "../src/secrets/engine";`):

```ts
describe("SecretsEngine.markAccessed and last_accessed_at exposure", () => {
  let db: Database;
  let engine: SecretsEngine;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-posture-eng-"));
    db = initDB(dir);
    engine = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("a freshly put secret has null last_accessed_at", () => {
    engine.put("svc/key", "v");
    expect(engine.getMeta("svc/key")!.last_accessed_at).toBeNull();
  });

  test("markAccessed sets last_accessed_at and is reflected by getMeta and list", () => {
    engine.put("svc/key", "v");
    engine.markAccessed("svc/key");
    const meta = engine.getMeta("svc/key")!;
    expect(meta.last_accessed_at).not.toBeNull();
    const listed = engine.list("svc/").find((s) => s.path === "svc/key")!;
    expect(listed.last_accessed_at).toBe(meta.last_accessed_at);
  });

  test("markAccessed on a missing path is a no-op (does not throw)", () => {
    expect(() => engine.markAccessed("does/not/exist")).not.toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/posture.hygiene.test.ts`
Expected: FAIL. `last_accessed_at` is not a property of `StoredSecret` (undefined, not null) and `engine.markAccessed` is not a function.

- [ ] **Step 3: Extend the StoredSecret interface**

In `src/secrets/engine.ts`, change the interface (lines 6-12):

```ts
export interface StoredSecret {
  path: string;
  metadata: Record<string, string>;
  version: number;
  created_at: string;
  updated_at: string;
  last_accessed_at: string | null;
}
```

- [ ] **Step 4: Add last_accessed_at to getMeta and list SELECTs**

In `src/secrets/engine.ts`, update `getMeta` (lines 227-243):

```ts
  getMeta(path: string): StoredSecret | null {
    const row = this.db
      .query(
        "SELECT path, metadata, version, created_at, updated_at, last_accessed_at FROM secrets WHERE path = ?"
      )
      .get(path) as any;

    if (!row) return null;

    return {
      path: row.path,
      metadata: JSON.parse(row.metadata),
      version: row.version,
      created_at: row.created_at,
      updated_at: row.updated_at,
      last_accessed_at: row.last_accessed_at ?? null,
    };
  }
```

Update `list` (lines 245-259):

```ts
  list(prefix: string = ""): StoredSecret[] {
    const rows = this.db
      .query(
        "SELECT path, metadata, version, created_at, updated_at, last_accessed_at FROM secrets WHERE path LIKE ? ORDER BY path"
      )
      .all(`${prefix}%`) as any[];

    return rows.map((r) => ({
      path: r.path,
      metadata: JSON.parse(r.metadata),
      version: r.version,
      created_at: r.created_at,
      updated_at: r.updated_at,
      last_accessed_at: r.last_accessed_at ?? null,
    }));
  }
```

- [ ] **Step 5: Add the markAccessed method**

In `src/secrets/engine.ts`, add this method immediately after `getMeta` (after line 243):

```ts
  /**
   * Record that a secret's value was read, for hygiene/posture (sub-project D).
   * One indexed-by-primary-key UPDATE on a path already doing a decrypt; cheap.
   * Silently no-ops on a missing path so read handlers never have to guard.
   */
  markAccessed(path: string): void {
    this.db
      .query("UPDATE secrets SET last_accessed_at = datetime('now') WHERE path = ?")
      .run(path);
  }
```

- [ ] **Step 6: Run test to verify it passes**

Run: `bun test test/posture.hygiene.test.ts`
Expected: PASS (all tests including Task 1's).

- [ ] **Step 7: Run the full suite to catch StoredSecret consumers**

Run: `bun test`
Expected: PASS. The new `last_accessed_at` field is additive; existing `StoredSecret` consumers keep compiling. Report the pass count.

- [ ] **Step 8: Commit**

```bash
git add src/secrets/engine.ts test/posture.hygiene.test.ts
git commit -m "feat(0.20.0): SecretsEngine exposes last_accessed_at + markAccessed()"
git push origin main
```

---

## Task 3: SecretsEngine `hygieneCounts()`

**Files:**
- Modify: `src/secrets/engine.ts` (add method after `markAccessed`)
- Test: `test/posture.hygiene.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `test/posture.hygiene.test.ts`:

```ts
describe("SecretsEngine.hygieneCounts", () => {
  let db: Database;
  let engine: SecretsEngine;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-posture-hyg-"));
    db = initDB(dir);
    engine = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("empty vault reports all zeros", () => {
    expect(engine.hygieneCounts()).toEqual({ stale_90d: 0, older_18mo: 0, total_secrets: 0 });
  });

  test("buckets stale (>90d since access) and old (>18mo since update)", () => {
    // Fresh + just accessed: neither stale nor old.
    engine.put("fresh/key", "v");
    engine.markAccessed("fresh/key");

    // Stale: accessed long ago. Force last_accessed_at back 200 days.
    engine.put("stale/key", "v");
    db.run("UPDATE secrets SET last_accessed_at = datetime('now','-200 days') WHERE path = 'stale/key'");

    // Old: updated_at 2 years ago (and never accessed -> last_accessed_at falls back to updated_at).
    engine.put("old/key", "v");
    db.run("UPDATE secrets SET updated_at = datetime('now','-2 years'), last_accessed_at = NULL WHERE path = 'old/key'");

    const h = engine.hygieneCounts();
    expect(h.total_secrets).toBe(3);
    // stale/key is stale; old/key is also stale (never accessed, updated 2y ago).
    expect(h.stale_90d).toBe(2);
    expect(h.older_18mo).toBe(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/posture.hygiene.test.ts`
Expected: FAIL with "engine.hygieneCounts is not a function".

- [ ] **Step 3: Implement hygieneCounts**

In `src/secrets/engine.ts`, add immediately after `markAccessed`:

```ts
  /**
   * Hygiene buckets for the posture view (sub-project D). Index-free counts
   * straight from the secrets table. Staleness uses last_accessed_at, falling
   * back to updated_at so a freshly written but never-read secret is not flagged.
   * Thresholds are constants in v1 (90 days unused, 18 months since update).
   */
  hygieneCounts(): { stale_90d: number; older_18mo: number; total_secrets: number } {
    const row = this.db
      .query(
        `SELECT
           COUNT(*) AS total_secrets,
           COALESCE(SUM(CASE WHEN COALESCE(last_accessed_at, updated_at) < datetime('now','-90 days') THEN 1 ELSE 0 END), 0) AS stale_90d,
           COALESCE(SUM(CASE WHEN updated_at < datetime('now','-18 months') THEN 1 ELSE 0 END), 0) AS older_18mo
         FROM secrets`
      )
      .get() as { total_secrets: number; stale_90d: number; older_18mo: number };
    return {
      stale_90d: row.stale_90d,
      older_18mo: row.older_18mo,
      total_secrets: row.total_secrets,
    };
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test test/posture.hygiene.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/secrets/engine.ts test/posture.hygiene.test.ts
git commit -m "feat(0.20.0): SecretsEngine.hygieneCounts for stale/old buckets"
git push origin main
```

---

## Task 4: Wire `markAccessed` into the read paths

**Files:**
- Modify: `src/api/secrets.ts:261-303` (value + version reveal handlers)
- Modify: `src/mcp/server.ts:305-318` (`gatehouse_get`)
- Modify: `src/api/lease.ts:214-222` (static lease checkout)
- Test: `test/posture.hygiene.test.ts`

- [ ] **Step 1: Write the failing endpoint test**

Append to `test/posture.hygiene.test.ts` (add imports at top: `import { Hono } from "hono"; import { AuditLog } from "../src/audit/logger"; import { PolicyEngine } from "../src/policy/engine"; import { secretsRouter } from "../src/api/secrets"; import { mkdirSync, writeFileSync } from "node:fs";`):

```ts
describe("reveal sets last_accessed_at (wiring)", () => {
  let db: Database;
  let engine: SecretsEngine;
  let dir: string;
  let app: Hono;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-posture-wire-"));
    const configDir = join(dir, "config");
    mkdirSync(join(configDir, "policies"), { recursive: true });
    writeFileSync(
      join(configDir, "policies", "reader.yaml"),
      `name: reader\nrules:\n  - path: "svc/*"\n    capabilities: [read]\n`
    );
    db = initDB(dir);
    engine = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
    const audit = new AuditLog(db);
    const policies = new PolicyEngine(configDir);
    engine.put("svc/key", "the-value");

    app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "test-req-id");
      c.set("sourceIp", "127.0.0.1");
      c.set("auth", { identity: "test", policies: ["reader"] });
      await next();
    });
    app.route("/v1/secrets", secretsRouter(engine, policies, audit));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("GET /v1/secrets/:path/value stamps last_accessed_at", async () => {
    expect(engine.getMeta("svc/key")!.last_accessed_at).toBeNull();
    const res = await app.request("/v1/secrets/svc/key/value");
    expect(res.status).toBe(200);
    expect(engine.getMeta("svc/key")!.last_accessed_at).not.toBeNull();
  });

  test("metadata-only read does NOT stamp last_accessed_at", async () => {
    const res = await app.request("/v1/secrets/svc/key");
    expect(res.status).toBe(200);
    expect(engine.getMeta("svc/key")!.last_accessed_at).toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/posture.hygiene.test.ts`
Expected: FAIL on "GET /v1/secrets/:path/value stamps last_accessed_at" (last_accessed_at stays null because the handler does not call markAccessed yet).

- [ ] **Step 3: Wire markAccessed into the REST value reveal**

In `src/api/secrets.ts`, in the `isValueRequest` branch, add the `markAccessed` call right after the audit log (currently lines 267-272). New version:

```ts
      audit.log({
        identity: auth.identity,
        action: "secret.reveal_value",
        path,
        source_ip: c.get("sourceIp"),
      });
      secrets.markAccessed(path);
```

And in the `versionMatch` branch, after its audit log (currently lines 294-300):

```ts
      audit.log({
        identity: auth.identity,
        action: "secret.reveal_value",
        path,
        metadata: { version: String(v) },
        source_ip: c.get("sourceIp"),
      });
      secrets.markAccessed(path);
```

(`secrets` is the `SecretsEngine` parameter of `secretsRouter`.)

- [ ] **Step 4: Run the endpoint test to verify it passes**

Run: `bun test test/posture.hygiene.test.ts`
Expected: PASS.

- [ ] **Step 5: Wire markAccessed into the MCP get path**

In `src/mcp/server.ts`, in `case "gatehouse_get":`, after the audit log (currently lines 312-317), add the call before `return text(value);`:

```ts
          audit.log({
            identity: auth.identity,
            action: "secret.read.mcp",
            path: args.path,
            source_ip: sourceIp,
          });
          secrets.markAccessed(args.path);
          return text(value);
```

(`secrets` is in scope: it is the first parameter of `mcpHttpRouter` / the handler closure.)

- [ ] **Step 6: Wire markAccessed into static lease checkout**

In `src/api/lease.ts`, after a successful `leases.checkout` (currently lines 214-222), add the stamp before returning:

```ts
    const result = leases.checkout(rawPath, auth.identity, ttl);
    if (!result) {
      return c.json({ error: "Secret not found", request_id: c.get("requestId") }, 404);
    }

    secrets.markAccessed(rawPath);

    return c.json({
      lease: result.lease,
      value: result.value,
    });
```

(`secrets` is the last parameter of `leaseRouter` and is already in scope.)

- [ ] **Step 7: Run the full suite**

Run: `bun test`
Expected: PASS. Report the pass count.

- [ ] **Step 8: Commit**

```bash
git add src/api/secrets.ts src/mcp/server.ts src/api/lease.ts test/posture.hygiene.test.ts
git commit -m "feat(0.20.0): stamp last_accessed_at on value reveal, MCP get, lease checkout"
git push origin main
```

---

## Task 5: `scrubResponseBody` returns `{ body, count }`

**Files:**
- Modify: `src/security/ssrf.ts:197-207`
- Modify: `src/api/proxy.ts:656-676` (consume `.body`)
- Modify: `src/mcp/server.ts:811` (consume `.body`)
- Test: `test/scrubResponseBody.test.ts`

This task changes the signature and updates every call site to consume `.body`, with no behavior change to the proxy yet. Threading the count into audit metadata happens in Tasks 6 and 7.

- [ ] **Step 1: Update the existing unit tests for the new return shape**

In `test/scrubResponseBody.test.ts`, the `describe("scrubResponseBody", ...)` block asserts on the return value as a string. Update each `scrubResponseBody(...)` assertion to use `.body`, and add a count assertion. Replace the four tests in that block with:

```ts
describe("scrubResponseBody", () => {
  test("redacts a raw secret value echoed by the upstream", () => {
    const out = scrubResponseBody(
      "your token is sk-test-openai-key-123 ok",
      secretRedactionValues(["sk-test-openai-key-123"])
    );
    expect(out.body).not.toContain("sk-test-openai-key-123");
    expect(out.body).toContain("[REDACTED]");
    expect(out.count).toBe(1);
  });

  test("redacts the base64 form of a basic-auth credential", () => {
    const cred = "admin:SuperSecretPass99";
    const encoded = btoa(cred);
    const upstreamBody = `{"error":"invalid auth","received":"Basic ${encoded}"}`;

    const out = scrubResponseBody(upstreamBody, secretRedactionValues([cred]));

    expect(out.body).not.toContain(encoded);
    expect(out.body).toContain("[REDACTED]");
    expect(out.count).toBe(1);
  });

  test("does not mangle short values below the 8-char floor", () => {
    const out = scrubResponseBody("price is 1234567", secretRedactionValues(["1234567"]));
    expect(out.body).toBe("price is 1234567");
    expect(out.count).toBe(0);
  });

  test("leaves unrelated text untouched and reports zero redactions", () => {
    const clean = "all good, nothing secret here";
    const out = scrubResponseBody(clean, secretRedactionValues(["sk-test-openai-key-123"]));
    expect(out.body).toBe(clean);
    expect(out.count).toBe(0);
  });

  test("counts every occurrence of a repeated secret", () => {
    const v = "sk-test-openai-key-123";
    const out = scrubResponseBody(`${v} and again ${v}`, secretRedactionValues([v]));
    expect(out.count).toBe(2);
    expect(out.body).not.toContain(v);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/scrubResponseBody.test.ts`
Expected: FAIL. `out.body` is undefined because `scrubResponseBody` returns a string.

- [ ] **Step 3: Change the scrubResponseBody implementation**

In `src/security/ssrf.ts`, replace `scrubResponseBody` (lines 197-207):

```ts
export function scrubResponseBody(
  body: string,
  secretValues: Iterable<string>
): { body: string; count: number } {
  let out = body;
  let count = 0;
  for (const v of secretValues) {
    if (!v || v.length < 8) continue;
    if (out.includes(v)) {
      // split length minus 1 == number of occurrences replaced.
      const parts = out.split(v);
      count += parts.length - 1;
      out = parts.join("[REDACTED]");
    }
  }
  return { body: out, count };
}
```

Also update the doc comment above it (lines 190-196) to mention the returned count:

```ts
/**
 * Replace every occurrence of an injected secret value in a response body
 * with "[REDACTED]". This defeats naive upstream echo ("your token is X").
 * Returns the scrubbed body and the number of redactions made (used by the
 * posture view to count credentials kept out of agent context).
 *
 * We intentionally skip values shorter than 8 chars to avoid mangling
 * arbitrary substrings, and skip values that are all-whitespace or empty.
 */
```

- [ ] **Step 4: Update the proxy.ts call sites to consume `.body`**

In `src/api/proxy.ts`, update lines 656-676. Replace:

```ts
      const redactValues = secretRedactionValues(resolved.values());
      const responseBody = scrubResponseBody(rawResponseBody, redactValues);
      const responseHeaders: Record<string, string> = {};

      // Forward safe response headers (scrub any echoed secret values)
      const safeHeaders = [
        "content-type",
        "x-request-id",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "retry-after",
      ];
      for (const h of safeHeaders) {
        const v = upstream.headers.get(h);
        if (v) responseHeaders[h] = scrubResponseBody(v, redactValues);
      }
      // Surface redirect target so callers know why they got a 3xx
      if (upstream.status >= 300 && upstream.status < 400) {
        const loc = upstream.headers.get("location");
        if (loc) responseHeaders["location"] = scrubResponseBody(loc, redactValues);
      }
```

with:

```ts
      const redactValues = secretRedactionValues(resolved.values());
      const bodyScrub = scrubResponseBody(rawResponseBody, redactValues);
      const responseBody = bodyScrub.body;
      let redactionCount = bodyScrub.count;
      const responseHeaders: Record<string, string> = {};

      // Forward safe response headers (scrub any echoed secret values)
      const safeHeaders = [
        "content-type",
        "x-request-id",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "retry-after",
      ];
      for (const h of safeHeaders) {
        const v = upstream.headers.get(h);
        if (v) {
          const hs = scrubResponseBody(v, redactValues);
          responseHeaders[h] = hs.body;
          redactionCount += hs.count;
        }
      }
      // Surface redirect target so callers know why they got a 3xx
      if (upstream.status >= 300 && upstream.status < 400) {
        const loc = upstream.headers.get("location");
        if (loc) {
          const ls = scrubResponseBody(loc, redactValues);
          responseHeaders["location"] = ls.body;
          redactionCount += ls.count;
        }
      }
```

(`redactionCount` is consumed in Task 6. It is declared `let` here so Task 6 can read it. TypeScript will not error on an unused mutable local.)

- [ ] **Step 5: Update the mcp/server.ts call site to consume `.body`**

In `src/mcp/server.ts`, replace line 811:

```ts
            const responseBody = scrubResponseBody(rawBody, secretRedactionValues(resolved.values())).body;
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `bun test test/scrubResponseBody.test.ts test/proxy.test.ts test/mcp.test.ts`
Expected: PASS. The proxy and MCP behavior is unchanged; only the internal call shape changed.

- [ ] **Step 7: Commit**

```bash
git add src/security/ssrf.ts src/api/proxy.ts src/mcp/server.ts test/scrubResponseBody.test.ts
git commit -m "feat(0.20.0): scrubResponseBody returns redaction count alongside body"
git push origin main
```

---

## Task 6: Thread `redaction_count` into `proxy.forward` audit metadata

**Files:**
- Modify: `src/api/proxy.ts:617-657` (reorder the success audit log to after the scrub so the count is available)
- Test: `test/proxy.test.ts`

The success `proxy.forward` audit row is currently written (lines 635-642) before the body is read and scrubbed (lines 653-676). To include `redaction_count`, move the success audit log to after the scrub. A side benefit: a `BODY_TOO_LARGE` throw during `readCappedText` now produces only the failure row (via the catch), not both a success and a failure row.

- [ ] **Step 1: Write the failing test**

First inspect `test/proxy.test.ts` for the existing success-path test and how it reads the audit log (it constructs `audit` via `new AuditLog(db)` and uses an upstream `fetch` stub). Add a test that asserts `redaction_count` is present on the success row. Append inside the main `describe` block in `test/proxy.test.ts`:

```ts
  test("proxy.forward success row carries redaction_count when upstream echoes a secret", async () => {
    // Arrange a secret whose value the fake upstream will echo back.
    secrets.put("api-keys/example", "sk-test-echo-secret-1234567890");
    policies.savePolicy("proxy-agent", [
      { path: "api-keys/example", capabilities: ["proxy"] },
      { path: "*", capabilities: ["admin"] },
    ]);

    const origFetch = globalThis.fetch;
    // @ts-expect-error test stub
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ echoed: "sk-test-echo-secret-1234567890" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    try {
      const res = await app.request("/v1/proxy", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Test-Policies": JSON.stringify(["proxy-agent"]) },
        body: JSON.stringify({
          url: "https://api.example.com/echo",
          method: "GET",
          headers: { Authorization: "Bearer {{secret:api-keys/example}}" },
        }),
      });
      expect(res.status).toBe(200);
    } finally {
      globalThis.fetch = origFetch;
    }

    const rows = audit.query({ action: "proxy.forward", limit: 10 });
    const success = rows.find((r) => r.success);
    expect(success).toBeDefined();
    expect(success!.metadata.redaction_count).toBe("1");
  });
```

NOTE: align the request shape (field names, header injection, secret metadata for `allowed_domains`) with the existing passing success-path test in this file. If that test sets `allowed_domains` metadata or a specific body schema, mirror it here so the call reaches the forward stage. Read the nearest existing `"/v1/proxy"` success test before finalizing this test body.

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/proxy.test.ts`
Expected: FAIL. `success.metadata.redaction_count` is undefined because the success row is logged before the scrub.

- [ ] **Step 3: Reorder the success audit log to after the scrub**

In `src/api/proxy.ts`, remove the current success audit log block (lines 635-642):

```ts
      audit.log({
        identity: auth.identity,
        action: "proxy.forward",
        path: secretPaths.join(","),
        source_ip: sourceIp,
        ...(topLeaseId ? { lease_id: topLeaseId } : {}),
        metadata: successMeta,
      });
```

Then, after the redirect-location scrub block from Task 5 (right before the `// Record pattern (fire-and-forget...)` comment at line 678), insert:

```ts
      // Now that the body/header scrub has run, the redaction count is known.
      // Logging here (rather than before the upstream read) means an oversized
      // upstream that throws in readCappedText produces only the failure row.
      successMeta.redaction_count = String(redactionCount);
      audit.log({
        identity: auth.identity,
        action: "proxy.forward",
        path: secretPaths.join(","),
        source_ip: sourceIp,
        ...(topLeaseId ? { lease_id: topLeaseId } : {}),
        metadata: successMeta,
      });
```

(`successMeta`, `topLeaseId`, and `redactionCount` are all in scope at this point. `recordCall` at line 648 stays where it is.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test test/proxy.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/api/proxy.ts test/proxy.test.ts
git commit -m "feat(0.20.0): record redaction_count in proxy.forward audit metadata"
git push origin main
```

---

## Task 7: Thread `redaction_count` into `proxy.forward.mcp` audit metadata

**Files:**
- Modify: `src/mcp/server.ts:783-818` (reorder the success audit log to after the scrub)
- Test: `test/mcp.test.ts`

- [ ] **Step 1: Write the failing test**

Read the existing `gatehouse_proxy` success test in `test/mcp.test.ts` to match its setup (auth, secret with `proxy` cap, fetch stub). Add a test asserting `redaction_count` on the `proxy.forward.mcp` success row. Append inside the relevant `describe` block:

```ts
  test("proxy.forward.mcp success row carries redaction_count", async () => {
    secrets.put("api-keys/example", "sk-test-mcp-echo-1234567890");
    policies.savePolicy("mcp-agent", [
      { path: "api-keys/example", capabilities: ["proxy"] },
      { path: "*", capabilities: ["admin"] },
    ]);

    const origFetch = globalThis.fetch;
    // @ts-expect-error test stub
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ echoed: "sk-test-mcp-echo-1234567890" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    try {
      await callTool("gatehouse_proxy", {
        url: "https://api.example.com/echo",
        method: "GET",
        headers: { Authorization: "Bearer {{secret:api-keys/example}}" },
      });
    } finally {
      globalThis.fetch = origFetch;
    }

    const rows = audit.query({ action: "proxy.forward.mcp", limit: 10 });
    const success = rows.find((r) => r.success);
    expect(success).toBeDefined();
    expect(success!.metadata.redaction_count).toBe("1");
  });
```

NOTE: `callTool`, `secrets`, `policies`, and `audit` must match how `test/mcp.test.ts` already exposes them. Read the file's setup and the nearest existing `gatehouse_proxy` test, and mirror its exact helpers and request shape before finalizing.

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/mcp.test.ts`
Expected: FAIL. `success.metadata.redaction_count` is undefined.

- [ ] **Step 3: Reorder the MCP success audit log to after the scrub**

In `src/mcp/server.ts`, remove the current success audit block (lines 795-802):

```ts
            audit.log({
              identity: auth.identity,
              action: "proxy.forward.mcp",
              path: [...refs].join(","),
              source_ip: sourceIp,
              ...(mcpTopLeaseId ? { lease_id: mcpTopLeaseId } : {}),
              metadata: mcpSuccessMeta,
            });
```

Then change the body read + scrub (lines 808-813) to compute and record the count, then log:

```ts
            // Cap upstream body + scrub any injected secret values echoed back
            // (raw values plus their on-the-wire encodings, e.g. base64).
            const rawBody = await readCappedText(upstream, limits.max_body_bytes);
            const mcpScrub = scrubResponseBody(rawBody, secretRedactionValues(resolved.values()));
            const responseBody = mcpScrub.body;
            mcpSuccessMeta.redaction_count = String(mcpScrub.count);
            audit.log({
              identity: auth.identity,
              action: "proxy.forward.mcp",
              path: [...refs].join(","),
              source_ip: sourceIp,
              ...(mcpTopLeaseId ? { lease_id: mcpTopLeaseId } : {}),
              metadata: mcpSuccessMeta,
            });
            let parsed: any;
            try { parsed = JSON.parse(responseBody); } catch { parsed = responseBody; }
```

(This replaces the Task 5 line `const responseBody = scrubResponseBody(...).body;`. `recordCall` at lines 804-806 stays. As with the REST path, a `BODY_TOO_LARGE` throw now lands only in the catch as a failure row.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test test/mcp.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/mcp/server.ts test/mcp.test.ts
git commit -m "feat(0.20.0): record redaction_count in proxy.forward.mcp audit metadata"
git push origin main
```

---

## Task 8: Emit `scrub.redact` for explicit scrubs

**Files:**
- Modify: `src/api/scrub.ts` (accept `audit`, emit event on nonzero count)
- Modify: `src/index.ts:508` (pass `audit` to `scrubRouter`)
- Modify: `src/mcp/server.ts:557-570` (`gatehouse_scrub` emits the event)
- Test: `test/posture.stats.test.ts`

`scrub.redact` carries `metadata.count` (a string). `/v1/scrub` is behind `authMiddleware` (`src/index.ts:248`), so `c.get("auth")` is available.

- [ ] **Step 1: Write the failing test**

Create `test/posture.stats.test.ts`:

```ts
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { initDB } from "../src/db/init";
import { AuditLog } from "../src/audit/logger";
import { scrubRouter } from "../src/api/scrub";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("POST /v1/scrub emits scrub.redact", () => {
  let db: Database;
  let audit: AuditLog;
  let dir: string;
  let app: Hono;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-scrub-"));
    db = initDB(dir);
    audit = new AuditLog(db);
    app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "rid");
      c.set("sourceIp", "127.0.0.1");
      c.set("auth", { identity: "test", policies: ["*"] });
      await next();
    });
    app.route("/v1/scrub", scrubRouter(audit));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("logs scrub.redact with the count when credentials are found", async () => {
    const res = await app.request("/v1/scrub", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: "key is sk-ant-aaaaaaaaaaaaaaaaaaaaaaaa here" }),
    });
    expect(res.status).toBe(200);
    const rows = audit.query({ action: "scrub.redact", limit: 10 });
    expect(rows.length).toBe(1);
    expect(rows[0].metadata.count).toBe("1");
  });

  test("does NOT log when nothing was redacted", async () => {
    const res = await app.request("/v1/scrub", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: "nothing secret here" }),
    });
    expect(res.status).toBe(200);
    expect(audit.query({ action: "scrub.redact", limit: 10 }).length).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/posture.stats.test.ts`
Expected: FAIL. `scrubRouter(audit)` does not accept an argument and emits no event.

- [ ] **Step 3: Update scrubRouter to accept audit and emit the event**

Replace `src/api/scrub.ts` entirely:

```ts
import { Hono } from "hono";
import { scrubValue, containsCredentials } from "../scrub/scrubber";
import type { AuthContext } from "../auth/middleware";
import type { AuditLog } from "../audit/logger";

export function scrubRouter(audit: AuditLog) {
  const router = new Hono();

  // POST /v1/scrub - redact credentials from text
  router.post("/", async (c) => {
    let body: { text: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    if (!body.text || typeof body.text !== "string") {
      return c.json({ error: "Missing 'text' field", request_id: c.get("requestId") }, 400);
    }

    const result = scrubValue(body.text);

    // Posture: count credentials kept out of agent context. Only explicit,
    // low-volume user-driven scrubs are logged, and only when something matched.
    if (result.redactions.length > 0) {
      const auth = c.get("auth") as AuthContext | undefined;
      audit.log({
        identity: auth?.identity || "anonymous",
        action: "scrub.redact",
        metadata: { count: String(result.redactions.length) },
        source_ip: c.get("sourceIp"),
      });
    }

    return c.json(result);
  });

  // POST /v1/scrub/check - quick boolean check for credential patterns
  router.post("/check", async (c) => {
    let body: { text: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    if (!body.text || typeof body.text !== "string") {
      return c.json({ error: "Missing 'text' field", request_id: c.get("requestId") }, 400);
    }

    return c.json({ contains_credentials: containsCredentials(body.text) });
  });

  return router;
}
```

- [ ] **Step 4: Update the mount point in index.ts**

In `src/index.ts`, change line 508:

```ts
app.route("/v1/scrub", scrubRouter(audit));
```

(`audit` is the `AuditLog` instance already constructed earlier in `index.ts`; confirm the variable name by reading the construction site, it is used in the other `app.route` calls such as line 503.)

- [ ] **Step 5: Emit scrub.redact from the MCP gatehouse_scrub tool**

In `src/mcp/server.ts`, update `case "gatehouse_scrub":` (lines 557-570):

```ts
        case "gatehouse_scrub": {
          const result = scrubValue(args.text);
          if (result.redactions.length > 0) {
            audit.log({
              identity: auth.identity,
              action: "scrub.redact",
              metadata: { count: String(result.redactions.length) },
              source_ip: sourceIp,
            });
          }
          return text(
            JSON.stringify(
              {
                scrubbed: result.scrubbed,
                redaction_count: result.redactions.length,
                redactions: result.redactions,
              },
              null,
              2
            )
          );
        }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `bun test test/posture.stats.test.ts test/mcp.test.ts`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/api/scrub.ts src/index.ts src/mcp/server.ts test/posture.stats.test.ts
git commit -m "feat(0.20.0): emit scrub.redact audit event on explicit scrubs"
git push origin main
```

---

## Task 9: AuditLog aggregation methods `sumRedactions` and `blockedEgress`

**Files:**
- Modify: `src/audit/logger.ts` (add two methods after `count()`)
- Test: `test/posture.stats.test.ts`

These do direct SQL aggregation rather than scanning via `query()` (which caps at 10000 rows). `redaction_count` and `count` are stored as JSON string values; `json_extract` returns them as strings, `CAST(... AS INTEGER)` converts.

- [ ] **Step 1: Write the failing test**

Append to `test/posture.stats.test.ts`:

```ts
describe("AuditLog.sumRedactions and blockedEgress", () => {
  let db: Database;
  let audit: AuditLog;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-agg-"));
    db = initDB(dir);
    audit = new AuditLog(db);
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const longAgo = "2000-01-01T00:00:00.000Z";

  test("sumRedactions adds proxy.forward, proxy.forward.mcp, and scrub.redact counts", () => {
    audit.log({ identity: "a", action: "proxy.forward", metadata: { redaction_count: "3" } });
    audit.log({ identity: "a", action: "proxy.forward.mcp", metadata: { redaction_count: "2" } });
    audit.log({ identity: "a", action: "scrub.redact", metadata: { count: "5" } });
    // Rows without a count contribute zero.
    audit.log({ identity: "a", action: "proxy.forward", metadata: { target_url: "x" } });
    // Unrelated action ignored.
    audit.log({ identity: "a", action: "secret.reveal_value", path: "p" });

    expect(audit.sumRedactions(longAgo)).toBe(10);
  });

  test("sumRedactions respects the since window", () => {
    audit.log({ identity: "a", action: "scrub.redact", metadata: { count: "4" } });
    const future = "2999-01-01T00:00:00.000Z";
    expect(audit.sumRedactions(future)).toBe(0);
  });

  test("blockedEgress counts distinct blocked actions and failed-forward reasons", () => {
    audit.log({ identity: "a", action: "proxy.blocked.rate_limit" });
    audit.log({ identity: "a", action: "proxy.blocked.rate_limit" });
    audit.log({ identity: "a", action: "proxy.blocked.approval" });
    audit.log({ identity: "a", action: "proxy.forward", success: false, metadata: { reason: "ssrf_blocked" } });
    audit.log({ identity: "a", action: "proxy.forward.mcp", success: false, metadata: { reason: "domain_blocked" } });
    audit.log({ identity: "a", action: "proxy.forward", success: false, metadata: { reason: "path_prefix_blocked" } });
    audit.log({ identity: "a", action: "proxy.forward", success: false, metadata: { reason: "policy_denied" } });
    // A successful forward is not blocked egress.
    audit.log({ identity: "a", action: "proxy.forward", success: true, metadata: { reason: "n/a", redaction_count: "0" } });

    const be = audit.blockedEgress(longAgo);
    expect(be.total).toBe(7);
    expect(be.by_reason).toEqual({
      rate_limit: 2,
      approval: 1,
      ssrf_blocked: 1,
      domain_blocked: 1,
      path_prefix_blocked: 1,
      policy_denied: 1,
    });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/posture.stats.test.ts`
Expected: FAIL with "audit.sumRedactions is not a function".

- [ ] **Step 3: Implement the methods**

In `src/audit/logger.ts`, add after `count()` (after line 168, before the closing brace of the class):

```ts
  /**
   * Sum the redaction counts recorded on proxy and scrub audit rows since the
   * given ISO timestamp. proxy.forward* rows store the count under
   * metadata.redaction_count; scrub.redact rows store it under metadata.count.
   * Powers the "credentials kept out of agent context" posture stat.
   */
  sumRedactions(since: string): number {
    const row = this.db
      .query(
        `SELECT COALESCE(SUM(
           CAST(COALESCE(
             json_extract(metadata, '$.redaction_count'),
             json_extract(metadata, '$.count'),
             '0'
           ) AS INTEGER)
         ), 0) AS total
         FROM audit_log
         WHERE timestamp >= ?
           AND action IN ('proxy.forward', 'proxy.forward.mcp', 'scrub.redact')`
      )
      .get(since) as { total: number };
    return row.total;
  }

  /**
   * Count blocked outbound proxy attempts since the given ISO timestamp,
   * broken down by reason. Two sources: dedicated blocked actions
   * (proxy.blocked.rate_limit, proxy.blocked.approval) and failed proxy
   * forwards carrying a blocking metadata.reason. Powers the posture
   * "blocked egress" stat.
   */
  blockedEgress(since: string): { total: number; by_reason: Record<string, number> } {
    const by_reason: Record<string, number> = {};

    const blockedActions = this.db
      .query(
        `SELECT action, COUNT(*) AS cnt FROM audit_log
         WHERE timestamp >= ?
           AND action IN ('proxy.blocked.rate_limit', 'proxy.blocked.approval')
         GROUP BY action`
      )
      .all(since) as { action: string; cnt: number }[];
    for (const r of blockedActions) {
      const key = r.action === "proxy.blocked.rate_limit" ? "rate_limit" : "approval";
      by_reason[key] = (by_reason[key] || 0) + r.cnt;
    }

    const failedForwards = this.db
      .query(
        `SELECT json_extract(metadata, '$.reason') AS reason, COUNT(*) AS cnt FROM audit_log
         WHERE timestamp >= ?
           AND action IN ('proxy.forward', 'proxy.forward.mcp')
           AND success = 0
           AND json_extract(metadata, '$.reason') IN
             ('ssrf_blocked', 'domain_blocked', 'path_prefix_blocked', 'policy_denied')
         GROUP BY reason`
      )
      .all(since) as { reason: string; cnt: number }[];
    for (const r of failedForwards) {
      by_reason[r.reason] = (by_reason[r.reason] || 0) + r.cnt;
    }

    const total = Object.values(by_reason).reduce((a, b) => a + b, 0);
    return { total, by_reason };
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test test/posture.stats.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/audit/logger.ts test/posture.stats.test.ts
git commit -m "feat(0.20.0): AuditLog.sumRedactions + blockedEgress aggregation"
git push origin main
```

---

## Task 10: `GET /v1/stats/posture` endpoint

**Files:**
- Create: `src/api/stats.ts`
- Modify: `src/index.ts` (import + mount)
- Test: `test/posture.stats.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `test/posture.stats.test.ts` (add imports: `import { SecretsEngine } from "../src/secrets/engine"; import { PolicyEngine } from "../src/policy/engine"; import { statsRouter } from "../src/api/stats"; import { mkdirSync, writeFileSync } from "node:fs";`):

```ts
describe("GET /v1/stats/posture", () => {
  let db: Database;
  let audit: AuditLog;
  let secrets: SecretsEngine;
  let dir: string;
  let app: Hono;

  function buildApp(policiesList: string[]) {
    const a = new Hono();
    a.use("*", async (c, next) => {
      c.set("requestId", "rid");
      c.set("sourceIp", "127.0.0.1");
      c.set("auth", { identity: "test", policies: policiesList });
      await next();
    });
    const configDir = join(dir, "config");
    mkdirSync(join(configDir, "policies"), { recursive: true });
    writeFileSync(
      join(configDir, "policies", "admin.yaml"),
      `name: admin\nrules:\n  - path: "*"\n    capabilities: [admin]\n`
    );
    writeFileSync(
      join(configDir, "policies", "noadmin.yaml"),
      `name: noadmin\nrules:\n  - path: "svc/*"\n    capabilities: [read]\n`
    );
    const policies = new PolicyEngine(configDir);
    a.route("/v1/stats", statsRouter(audit, secrets, policies));
    return a;
  }

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-stats-"));
    db = initDB(dir);
    audit = new AuditLog(db);
    secrets = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("returns the posture shape for an admin", async () => {
    audit.log({ identity: "a", action: "scrub.redact", metadata: { count: "7" } });
    audit.log({ identity: "a", action: "proxy.blocked.rate_limit" });
    secrets.put("svc/key", "v");

    app = buildApp(["admin"]);
    const res = await app.request("/v1/stats/posture?window=7d");
    expect(res.status).toBe(200);
    const body = await res.json();

    expect(body.redactions).toEqual({ window: "7d", count: 7 });
    expect(body.blocked_egress.window).toBe("7d");
    expect(body.blocked_egress.total).toBe(1);
    expect(body.blocked_egress.by_reason).toEqual({ rate_limit: 1 });
    expect(body.hygiene).toEqual({ stale_90d: 0, older_18mo: 0, total_secrets: 1 });
  });

  test("defaults to a 7d window when none is given", async () => {
    app = buildApp(["admin"]);
    const res = await app.request("/v1/stats/posture");
    const body = await res.json();
    expect(body.redactions.window).toBe("7d");
  });

  test("rejects a non-admin caller with 403", async () => {
    app = buildApp(["noadmin"]);
    const res = await app.request("/v1/stats/posture");
    expect(res.status).toBe(403);
  });

  test("clamps an absurd window and still returns a valid shape", async () => {
    app = buildApp(["admin"]);
    const res = await app.request("/v1/stats/posture?window=banana");
    expect(res.status).toBe(200);
    const body = await res.json();
    // Unparseable window falls back to the 7d default.
    expect(body.redactions.window).toBe("7d");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/posture.stats.test.ts`
Expected: FAIL. `../src/api/stats` does not exist.

- [ ] **Step 3: Create the stats router**

Create `src/api/stats.ts`:

```ts
import { Hono } from "hono";
import type { AuditLog } from "../audit/logger";
import type { SecretsEngine } from "../secrets/engine";
import type { PolicyEngine } from "../policy/engine";
import type { AuthContext } from "../auth/middleware";

/**
 * Parse a window string like "7d", "30d", or "24h" into a normalized label
 * and an ISO "since" timestamp. Unparseable input falls back to 7 days.
 * Magnitude is clamped to 365 days so a hostile value can't widen the scan.
 */
export function parseWindow(raw: string | undefined): { label: string; since: string } {
  const def = 7 * 24 * 60 * 60 * 1000;
  let ms = def;
  let label = "7d";
  const m = (raw || "").trim().match(/^(\d+)([dh])$/);
  if (m) {
    const n = parseInt(m[1], 10);
    const unit = m[2];
    let candidate = unit === "h" ? n * 60 * 60 * 1000 : n * 24 * 60 * 60 * 1000;
    const maxMs = 365 * 24 * 60 * 60 * 1000;
    if (candidate > maxMs) candidate = maxMs;
    if (candidate > 0) {
      ms = candidate;
      label = `${n}${unit}`;
    }
  }
  const since = new Date(Date.now() - ms).toISOString();
  return { label, since };
}

export function statsRouter(
  audit: AuditLog,
  secrets: SecretsEngine,
  policies: PolicyEngine
) {
  const router = new Hono();

  // GET /v1/stats/posture?window=7d - the posture and value view (admin only).
  router.get("/posture", (c) => {
    const auth = c.get("auth") as AuthContext;
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const { label, since } = parseWindow(c.req.query("window"));

    const redactionCount = audit.sumRedactions(since);
    const blocked = audit.blockedEgress(since);
    const hygiene = secrets.hygieneCounts();

    return c.json({
      redactions: { window: label, count: redactionCount },
      blocked_egress: { window: label, total: blocked.total, by_reason: blocked.by_reason },
      hygiene,
    });
  });

  return router;
}
```

- [ ] **Step 4: Mount the router in index.ts**

In `src/index.ts`, add the import near the other api imports (after line 20, `import { scrubRouter } from "./api/scrub";`):

```ts
import { statsRouter } from "./api/stats";
```

And mount it next to the other `/v1` routes (after line 509, `app.route("/v1/me", ...)`):

```ts
app.route("/v1/stats", statsRouter(audit, secrets, policies));
```

(`audit`, `secrets`, and `policies` are all already constructed in `index.ts`; confirm the variable names from the surrounding `app.route` calls, e.g. line 499 uses `secrets` and `policies`, line 503 uses `audit`.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `bun test test/posture.stats.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/api/stats.ts src/index.ts test/posture.stats.test.ts
git commit -m "feat(0.20.0): GET /v1/stats/posture windowed posture endpoint"
git push origin main
```

---

## Task 11: UI hygiene helpers (pure, testable)

**Files:**
- Modify: `src/ui/secret-detail-render.js` (add three functions + export them on `window.SecretDetail`)
- Test: `test/secretDetailRender.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `test/secretDetailRender.test.ts` (add `hygieneFlags, hygieneBadgeHtml, formatHygieneSummary` to the import block at the top):

```ts
describe("hygieneFlags", () => {
  const daysAgo = (n) => new Date(Date.now() - n * 86_400_000).toISOString();

  test("fresh secret is neither stale nor old", () => {
    const f = hygieneFlags({ updated_at: daysAgo(1), created_at: daysAgo(1), last_accessed_at: daysAgo(1) });
    expect(f).toEqual({ stale: false, old: false });
  });

  test("unused over 90 days is stale (falls back to updated_at when never accessed)", () => {
    const f = hygieneFlags({ updated_at: daysAgo(100), created_at: daysAgo(100), last_accessed_at: null });
    expect(f.stale).toBe(true);
  });

  test("recent access keeps it non-stale even if updated long ago", () => {
    const f = hygieneFlags({ updated_at: daysAgo(400), created_at: daysAgo(400), last_accessed_at: daysAgo(2) });
    expect(f.stale).toBe(false);
  });

  test("updated over 18 months ago is old", () => {
    const f = hygieneFlags({ updated_at: daysAgo(560), created_at: daysAgo(560), last_accessed_at: daysAgo(1) });
    expect(f.old).toBe(true);
  });
});

describe("hygieneBadgeHtml", () => {
  const daysAgo = (n) => new Date(Date.now() - n * 86_400_000).toISOString();

  test("returns empty string for a healthy secret", () => {
    expect(hygieneBadgeHtml({ updated_at: daysAgo(1), created_at: daysAgo(1), last_accessed_at: daysAgo(1) })).toBe("");
  });

  test("renders a stale badge", () => {
    const html = hygieneBadgeHtml({ updated_at: daysAgo(100), created_at: daysAgo(100), last_accessed_at: null });
    expect(html).toContain("stale");
  });
});

describe("formatHygieneSummary", () => {
  test("empty string when nothing flagged", () => {
    expect(formatHygieneSummary({ stale_90d: 0, older_18mo: 0, total_secrets: 5 })).toBe("");
  });

  test("summarizes stale and old counts", () => {
    expect(formatHygieneSummary({ stale_90d: 3, older_18mo: 1, total_secrets: 42 })).toBe(
      "3 unused 90d, 1 over 18mo"
    );
  });

  test("shows only the nonzero bucket", () => {
    expect(formatHygieneSummary({ stale_90d: 2, older_18mo: 0, total_secrets: 9 })).toBe("2 unused 90d");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/secretDetailRender.test.ts`
Expected: FAIL. The three functions are not exported.

- [ ] **Step 3: Implement the helpers**

In `src/ui/secret-detail-render.js`, add these functions before the `if (typeof window !== "undefined")` block (after `treeAuthChip`, line 153):

```js
// Hygiene thresholds (sub-project D). Constants in v1.
const STALE_MS = 90 * 86_400_000;        // 90 days unused
const OLD_MS = 18 * 30 * 86_400_000;     // ~18 months since update

function _parseTs(iso) {
  if (!iso) return null;
  const d = new Date(String(iso).endsWith("Z") ? iso : iso + "Z");
  const t = d.getTime();
  return Number.isFinite(t) ? t : null;
}

export function hygieneFlags(secret) {
  const now = Date.now();
  // Staleness uses last access, falling back to updated_at so a freshly
  // written but never-read secret is not flagged (matches the server query).
  const access = _parseTs(secret && secret.last_accessed_at) ?? _parseTs(secret && secret.updated_at);
  const updated = _parseTs(secret && secret.updated_at);
  const stale = access != null ? now - access > STALE_MS : false;
  const old = updated != null ? now - updated > OLD_MS : false;
  return { stale, old };
}

export function hygieneBadgeHtml(secret) {
  const f = hygieneFlags(secret);
  let html = "";
  if (f.stale) {
    html += ` <span class="badge" style="font-size:9px;background:rgba(251,191,36,0.12);color:var(--warning)" title="Not accessed in over 90 days">stale</span>`;
  }
  if (f.old) {
    html += ` <span class="badge" style="font-size:9px;background:rgba(251,191,36,0.12);color:var(--warning)" title="Not updated in over 18 months">18mo+</span>`;
  }
  return html;
}

export function formatHygieneSummary(hygiene) {
  if (!hygiene) return "";
  const parts = [];
  if (hygiene.stale_90d > 0) parts.push(`${hygiene.stale_90d} unused 90d`);
  if (hygiene.older_18mo > 0) parts.push(`${hygiene.older_18mo} over 18mo`);
  return parts.join(", ");
}
```

And add them to the `window.SecretDetail` export object (lines 156-166):

```js
if (typeof window !== "undefined") {
  window.SecretDetail = {
    referenceChipHtml,
    postureChips,
    postureChipsHtml,
    relativeTime,
    formatActivityRow,
    formatLeaseRow,
    emptyStateStats,
    emptyStateStatsLine,
    treeAuthChip,
    hygieneFlags,
    hygieneBadgeHtml,
    formatHygieneSummary,
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test test/secretDetailRender.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ui/secret-detail-render.js test/secretDetailRender.test.ts
git commit -m "feat(0.20.0): UI hygiene helpers (flags, badge, summary)"
git push origin main
```

---

## Task 12: Dashboard posture cards + hygiene summary + tree badges + detail "Last used"

**Files:**
- Modify: `src/ui/index.html` (stat grid at 2111-2116; `loadDashboard` at 3217-3246; `renderSecretTree` at 3284-3312; secret detail render in `selectSecret`)

This task is DOM wiring with no new unit-testable logic (the logic lives in Task 11's helpers). Verify it manually by running the app (Step 6).

- [ ] **Step 1: Add posture stat cards to the dashboard grid**

In `src/ui/index.html`, replace the stat-grid block (lines 2111-2116):

```html
        <div class="stat-grid">
          <div class="stat-card stagger-1"><div class="stat-label">Total Secrets</div><div class="stat-value" id="stat-secrets">-</div></div>
          <div class="stat-card stagger-2"><div class="stat-label">Active Leases</div><div class="stat-value" id="stat-leases">-</div></div>
          <div class="stat-card stagger-3"><div class="stat-label">Audit Events (24h)</div><div class="stat-value" id="stat-audit">-</div></div>
          <div class="stat-card stagger-4"><div class="stat-label">Policies</div><div class="stat-value" id="stat-policies">-</div></div>
        </div>

        <div class="stat-grid">
          <div class="stat-card stagger-1"><div class="stat-label">Kept Out of Agent Context (7d)</div><div class="stat-value" id="stat-redactions">-</div></div>
          <div class="stat-card stagger-2"><div class="stat-label">Blocked Egress (7d)</div><div class="stat-value" id="stat-blocked" title="">-</div></div>
          <div class="stat-card stagger-3"><div class="stat-label">Secret Hygiene</div><div class="stat-value" id="stat-hygiene" style="font-size:14px;line-height:1.4">-</div></div>
          <div class="stat-card stagger-4"><div class="stat-label">Encryption</div><div class="stat-value" id="stat-encryption" style="font-size:14px">vault active</div></div>
        </div>
```

(The fourth card is a static placeholder so the row has four cells; `stat-encryption` is not wired in this sub-project. Leave it static.)

- [ ] **Step 2: Fetch and render posture stats in loadDashboard**

In `src/ui/index.html`, in `loadDashboard` (lines 3217-3246), add a posture fetch to the `Promise.all` and render the new cards. Replace the body of `loadDashboard` up to `renderLeaseTable` with:

```js
  async function loadDashboard() {
    try {
      const [secretsData, leasesData, auditData, policiesData, postureData] = await Promise.all([
        api('/v1/secrets').catch(() => ({ secrets: [] })),
        api('/v1/lease').catch(() => ({ leases: [] })),
        api('/v1/audit?limit=100').catch(() => ({ entries: [] })),
        api('/v1/policy').catch(() => ({ policies: [] })),
        api('/v1/stats/posture?window=7d').catch(() => null)
      ]);

      document.getElementById('stat-secrets').textContent = secretsData.secrets?.length ?? 0;
      document.getElementById('stat-leases').textContent = leasesData.leases?.length ?? 0;
      const now = new Date();
      const dayAgo = new Date(now.getTime() - 86400000).toISOString();
      const recent = (auditData.entries || []).filter(e => e.timestamp >= dayAgo);
      document.getElementById('stat-audit').textContent = recent.length;
      const pArr = policiesData.policies || [];
      document.getElementById('stat-policies').textContent = Array.isArray(pArr) ? pArr.length : 0;

      renderPosture(postureData);
```

Then add a new `renderPosture` function immediately after `loadDashboard` (after line 3246):

```js
  function renderPosture(posture) {
    const redEl = document.getElementById('stat-redactions');
    const blkEl = document.getElementById('stat-blocked');
    const hygEl = document.getElementById('stat-hygiene');
    if (!posture) {
      if (redEl) redEl.textContent = '-';
      if (blkEl) blkEl.textContent = '-';
      if (hygEl) hygEl.textContent = '-';
      return;
    }
    if (redEl) redEl.textContent = posture.redactions?.count ?? 0;
    if (blkEl) {
      const be = posture.blocked_egress || { total: 0, by_reason: {} };
      blkEl.textContent = be.total ?? 0;
      const breakdown = Object.entries(be.by_reason || {})
        .map(([k, v]) => `${k}: ${v}`)
        .join(', ');
      blkEl.title = breakdown || 'No blocked egress in the last 7 days';
    }
    if (hygEl) {
      const summary = window.SecretDetail ? window.SecretDetail.formatHygieneSummary(posture.hygiene) : '';
      hygEl.textContent = summary || 'all healthy';
    }
  }
```

- [ ] **Step 3: Add hygiene badges to the secrets tree**

In `src/ui/index.html`, in `renderSecretTree` (lines 3297-3307), add a hygiene badge next to the existing chips. Change the per-item block to:

```js
      for (const item of items) {
        const name = item.path.split('/').pop();
        const active = item.path === selectedSecretPath ? 'active' : '';
        const approvalBadge = _isApprovalRequired(item)
          ? ' <span class="badge" style="font-size:9px;background:rgba(251,191,36,0.12);color:var(--warning)" title="Requires human approval before agents can use this secret">🔒 approval</span>'
          : '';
        const authChip = window.SecretDetail ? window.SecretDetail.treeAuthChip(item.metadata) : '';
        const hygieneBadge = window.SecretDetail ? window.SecretDetail.hygieneBadgeHtml(item) : '';
        html += `<div class="tree-item ${active}" onclick="window._selectSecret('${esc(item.path)}')">${esc(name)}${authChip}${approvalBadge}${hygieneBadge}</div>`;
      }
```

- [ ] **Step 4: Add a "Last used" field to the secret detail panel**

In `src/ui/index.html`, find the static-secret branch of `selectSecret` where the detail meta fields (Kind / Version / Updated / Created) are rendered. Add a "Last used" field alongside "Updated", using `window.SecretDetail.relativeTime`. The exact markup mirrors the existing `<div><div class="detail-field-label">Updated</div>...</div>` cells. Insert after the "Updated" cell:

```js
          <div><div class="detail-field-label">Last used</div><div class="detail-field-value">${meta.last_accessed_at ? esc(window.SecretDetail.relativeTime(meta.last_accessed_at)) : 'never'}</div></div>
```

NOTE: locate the static-secret detail block (not the `meta.kind === 'dynamic'` branch at 3332-3346, which has no value reveal). Read the static branch that follows it and insert the cell where the other `detail-field-label` cells are rendered. `meta` is the `allSecrets.find(...)` object, which now carries `last_accessed_at` from the `/v1/secrets` list response.

- [ ] **Step 5: Run the full test suite**

Run: `bun test`
Expected: PASS (no UI unit tests changed here, but confirm nothing regressed). Report the pass count.

- [ ] **Step 6: Manual verification**

Use the `run` skill (or `bun run src/index.ts` with a `GATEHOUSE_MASTER_KEY` set and a temp data dir) to launch the app, then:
- Load the dashboard; confirm the second stat row shows "Kept Out of Agent Context", "Blocked Egress" (hover for the by-reason breakdown), and "Secret Hygiene".
- Make a proxy call whose upstream echoes the secret (or call `POST /v1/scrub` with a key), reload, confirm the redaction count increments.
- Confirm a secret with an old `updated_at` shows a "stale"/"18mo+" badge in the tree and a "Last used" value in the detail panel.

- [ ] **Step 7: Commit**

```bash
git add src/ui/index.html
git commit -m "feat(0.20.0): dashboard posture cards, hygiene summary, tree badges, last-used"
git push origin main
```

---

## Task 13: Version bump, changelog, docs

**Files:**
- Modify: `src/version.ts`
- Modify: `CHANGELOG.md`
- Optional: a short "Posture" docs page if the site has a docs tree (check `docs/` / site sources; only add if a natural home exists)

- [ ] **Step 1: Bump the version**

In `src/version.ts`, change:

```ts
export const VERSION = "0.20.0";
```

- [ ] **Step 2: Add the changelog entry**

Read the top of `CHANGELOG.md` to match the existing block style, then add a `## 0.20.0` block above the previous entry. Content (no em dashes):

```markdown
## 0.20.0

### Added
- Posture and value view on the dashboard. A second stat row surfaces
  "credentials kept out of agent context" (a rolling 7d count of redactions),
  blocked egress (with a by-reason breakdown on hover), and a secret-hygiene
  summary (unused 90d, older than 18mo).
- `GET /v1/stats/posture?window=7d` (admin only): windowed posture aggregation
  from the audit log and the secrets table.
- `secrets.last_accessed_at`: stamped on every value reveal (REST and MCP) and
  on static lease checkout. Existing rows are backfilled to `updated_at`.
- `scrub.redact` audit event recorded on explicit scrubs (`POST /v1/scrub` and
  the `gatehouse_scrub` MCP tool) when something was redacted.
- Secret-hygiene badges ("stale", "18mo+") in the secrets tree and a "Last used"
  field in the secret detail panel.

### Changed
- `scrubResponseBody` now returns `{ body, count }`; the redaction count is
  recorded in `proxy.forward` and `proxy.forward.mcp` audit metadata as
  `redaction_count`. As a side effect, an oversized upstream body that aborts
  the read now produces only a failure audit row, not a success row too.

### Notes
- Hygiene thresholds (90 days unused, 18 months since update) are constants in
  this release. No automatic rotation or deletion: the view nudges, it never
  acts.
```

- [ ] **Step 3: Run the full suite one final time**

Run: `bun test`
Expected: PASS. Report the pass count ("✓ N pass") in the summary.

- [ ] **Step 4: Commit**

```bash
git add src/version.ts CHANGELOG.md
git commit -m "feat(0.20.0): posture and value view release"
git push origin main
```

- [ ] **Step 5: Tag the release (only when the maintainer confirms cutting the release)**

```bash
git tag v0.20.0 && git push --tags
```

(GitHub sync via `scripts/internal/sync-to-github.ts v0.20.0` is a separate, maintainer-driven step per CLAUDE.md. Before syncing, grep the modified files for `api-keys/openai` literals and rewrite to `api-keys/example` to avoid the push-protection trap.)

---

## Self-review against the spec

- **D1 (persist redaction counts where the scrub happens):** Tasks 5-8. Proxy/MCP forward rows get `redaction_count`; explicit scrubs get `scrub.redact` with `count`. The "credentials kept out (7d)" sum is `AuditLog.sumRedactions` (Task 9), surfaced in the endpoint (Task 10) and dashboard (Task 12). The optional `counters` rollup table is explicitly deferred in the spec and not built. Covered.
- **D2 (`last_accessed_at` column):** Tasks 1-4. Column added (fresh + migration), backfilled to `updated_at`, written on all enumerated read paths, used by `hygieneCounts` with the `COALESCE(last_accessed_at, updated_at)` fallback. Powers the detail "Last used" field (Task 12). Covered.
- **D3 (hygiene signals as badges + summary):** Tasks 11-12. Tree badges (stale, 18mo+), dashboard hygiene summary. Thresholds are constants. No rotate/delete buttons. Covered.
- **D4 (posture row in the stat grid):** Task 12. Three live cards (redactions, blocked egress with by-reason on hover, hygiene) plus a static fourth to keep the 4-column row. Covered.
- **D5 (one stats endpoint, windowed):** Task 10. `GET /v1/stats/posture?window=7d` returns exactly the spec's `{redactions, blocked_egress: {total, by_reason}, hygiene}` shape, admin-gated, computed server-side. Covered.
- **Error handling (empty windows return zeros; missing `redaction_count` treated as zero):** `sumRedactions` COALESCEs absent metadata to 0 (Task 9 test "rows without a count contribute zero"); `hygieneCounts`/`blockedEgress` return zeros on empty data (tested); `renderPosture` tolerates a null posture response. Covered.
- **Testing (scrub count; last_accessed set on read; endpoint shape/window):** Tasks 5, 4, 10 respectively. Covered.
- **Rollout (3 slices: hygiene half, value half, endpoint+cards):** The task order maps to the spec's three rollout steps and stays shippable at each commit. Covered.
- **Open questions:** Thresholds hard-coded (chosen, per spec lean). `scrub.redact` logs count only (not credential types); this is the safe subset of the spec's "leaning count plus types", deferrable if types are wanted later. Flag for the maintainer at review.

## Open decisions to confirm at review

1. `scrub.redact` records only `count`, not the matched credential types. The spec leaned "count plus types." Easy to add `types` to the metadata later; left out here to keep the first cut minimal. Confirm whether types are wanted now.
2. The fourth card in the new posture row ("Encryption: vault active") is a static placeholder to fill the 4-column grid. If undesired, drop it and let the row hold three cards, or wire it to the recoverability sub-project's `verify` result once that lands.
