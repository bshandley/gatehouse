import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { initDB } from "../src/db/init";
import { rotateRouter, _resetRotateRateLimits } from "../src/api/rotate";
import { skillRouter } from "../src/api/skill";
import { authRouter } from "../src/api/auth";
import { authMiddleware } from "../src/auth/middleware";
import { AuditLog } from "../src/audit/logger";
import { PolicyEngine } from "../src/policy/engine";
import type { GatehouseConfig } from "../src/config";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { deriveKey } from "../src/secrets/engine";

const TEST_MASTER_KEY = Buffer.from("a".repeat(64), "hex");
const TEST_ROOT_TOKEN = "test-root-token-for-rotate-tests";
const TEST_JWT_SECRET = Buffer.from(
  deriveKey(TEST_MASTER_KEY, "gatehouse-jwt")
).toString("hex");

function buildApp(db: Database, policies: PolicyEngine) {
  const config: GatehouseConfig = {
    port: 3100,
    dataDir: "/tmp",
    configDir: "/tmp",
    masterKey: TEST_MASTER_KEY,
    jwtSecret: TEST_JWT_SECRET,
  };

  const app = new Hono();
  app.use("*", async (c, next) => {
    c.set("requestId", crypto.randomUUID());
    c.set("sourceIp", c.req.header("x-forwarded-for") || "127.0.0.1");
    await next();
  });

  const audit = new AuditLog(db);
  app.route("/v1/auth", authRouter(db, config));
  app.route("/v1/rotate", rotateRouter(db, audit, config));

  // Skill route is mounted AFTER auth middleware (authed agents only).
  app.use("/v1/*", authMiddleware(config));
  app.route("/v1/skill", skillRouter(policies, audit));

  return app;
}

async function createRole(
  app: ReturnType<typeof buildApp>,
  display_name: string,
  policies: string[] = ["agent"]
): Promise<{ role_id: string; secret_id: string }> {
  const res = await app.request("/v1/auth/approle", {
    method: "POST",
    headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ display_name, policies }),
  });
  expect(res.status).toBe(201);
  return res.json();
}

async function generateRotateLink(
  app: ReturnType<typeof buildApp>,
  role_id: string,
  extra: Record<string, any> = {}
): Promise<any> {
  const res = await app.request("/v1/rotate", {
    method: "POST",
    headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ role_id, ...extra }),
  });
  return { status: res.status, body: await res.json() };
}

// Each login uses a unique source IP because auth.ts has a module-level
// rate limiter (5 failed attempts per IP per 60s) that bleeds across the
// whole bun-test process. Without unique IPs the limiter saturates from
// earlier test files (auth.test.ts, onboard.test.ts) and our logins
// start returning 429.
let _ipCounter = 0;
function nextIp(): string {
  _ipCounter++;
  return `10.40.${(_ipCounter >> 8) & 0xff}.${_ipCounter & 0xff}`;
}

async function loginWith(
  app: ReturnType<typeof buildApp>,
  role_id: string,
  secret_id: string,
  ip: string = nextIp()
): Promise<{ status: number; body: any }> {
  const res = await app.request("/v1/auth/approle/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Forwarded-For": ip },
    body: JSON.stringify({ role_id, secret_id }),
  });
  return { status: res.status, body: await res.json() };
}

describe("Rotate API", () => {
  let db: Database;
  let app: ReturnType<typeof buildApp>;
  let dir: string;
  let policies: PolicyEngine;

  beforeEach(async () => {
    _resetRotateRateLimits();
    dir = mkdtempSync(join(tmpdir(), "gatehouse-rotate-test-"));
    const polDir = join(dir, "policies");
    mkdirSync(polDir);
    writeFileSync(
      join(polDir, "agent.yaml"),
      `name: agent
rules:
  - paths: ["*"]
    capabilities: [proxy, read]
  - paths: ["db/*"]
    capabilities: [lease]
`
    );
    db = initDB(dir);
    process.env.GATEHOUSE_ROOT_TOKEN = TEST_ROOT_TOKEN;
    policies = new PolicyEngine(dir, db);
    app = buildApp(db, policies);
    // Let the skill template finish loading from disk.
    await new Promise((r) => setTimeout(r, 30));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
    delete process.env.GATEHOUSE_ROOT_TOKEN;
  });

  test("admin can create a rotate token for an existing AppRole", async () => {
    const role = await createRole(app, "rot-1", ["agent"]);
    const { status, body } = await generateRotateLink(app, role.role_id, { label: "monthly" });
    expect(status).toBe(200);
    expect(body.token).toBeTruthy();
    expect(body.id).toStartWith("rotate-");
    expect(body.rotate_url).toContain("/v1/rotate/");
    expect(body.role_display_name).toBe("rot-1");
  });

  test("non-admin cannot create a rotate token", async () => {
    const role = await createRole(app, "rot-2", ["agent"]);
    const res = await app.request("/v1/rotate", {
      method: "POST",
      headers: { Authorization: "Bearer wrong-token", "Content-Type": "application/json" },
      body: JSON.stringify({ role_id: role.role_id }),
    });
    expect(res.status).toBe(403);
  });

  test("create rejects unknown role_id", async () => {
    const { status, body } = await generateRotateLink(app, "role-does-not-exist");
    expect(status).toBe(404);
    expect(body.error).toContain("not found");
  });

  test("GET /v1/rotate/:token returns markdown for a valid unconsumed token", async () => {
    const role = await createRole(app, "rot-md", ["agent"]);
    const { body } = await generateRotateLink(app, role.role_id);

    const md = await app.request(`/v1/rotate/${body.token}`);
    expect(md.status).toBe(200);
    expect(md.headers.get("content-type")).toContain("text/markdown");
    const text = await md.text();
    expect(text).toContain("rot-md");
    expect(text).toContain(role.role_id);
    expect(text).toContain(`/v1/rotate/${body.token}/exchange`);
    // Must NOT include the bootstrap onboard skill body or markers.
    expect(text).not.toContain("GATEHOUSE-SKILL-BEGIN");
    expect(text).not.toContain("Step 5");
  });

  test("exchange rotates secret_id without changing role_id; old secret_id stops working", async () => {
    const role = await createRole(app, "rot-exch", ["agent"]);
    const { body: link } = await generateRotateLink(app, role.role_id);

    // Confirm the original secret_id works pre-rotation.
    const pre = await loginWith(app, role.role_id, role.secret_id);
    expect(pre.status).toBe(200);

    const ex = await app.request(`/v1/rotate/${link.token}/exchange`, { method: "POST" });
    expect(ex.status).toBe(200);
    const exBody = await ex.json();
    expect(exBody.role_id).toBe(role.role_id);
    expect(exBody.secret_id).toBeTruthy();
    expect(exBody.secret_id).not.toBe(role.secret_id);
    expect(exBody.role_display_name).toBe("rot-exch");

    // Old secret_id no longer authenticates. Use a fresh IP so the
    // shared-IP rate limiter doesn't poison the assertion.
    const oldFails = await loginWith(app, role.role_id, role.secret_id, "10.30.0.1");
    expect(oldFails.status).toBe(401);

    // New secret_id authenticates (different IP again).
    const newWorks = await loginWith(app, role.role_id, exBody.secret_id, "10.30.0.2");
    expect(newWorks.status).toBe(200);
  });

  test("exchange is single-use - second call returns 410 Gone", async () => {
    const role = await createRole(app, "rot-once", ["agent"]);
    const { body: link } = await generateRotateLink(app, role.role_id);

    const first = await app.request(`/v1/rotate/${link.token}/exchange`, { method: "POST" });
    expect(first.status).toBe(200);

    const second = await app.request(`/v1/rotate/${link.token}/exchange`, { method: "POST" });
    expect(second.status).toBe(410);
  });

  test("exchange refuses if AppRole is suspended (and consumes the token)", async () => {
    const role = await createRole(app, "rot-susp", ["agent"]);
    const { body: link } = await generateRotateLink(app, role.role_id);

    // Suspend the role
    await app.request(`/v1/auth/approle/${role.role_id}/suspend`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ suspended: true }),
    });

    const ex = await app.request(`/v1/rotate/${link.token}/exchange`, { method: "POST" });
    expect(ex.status).toBe(403);

    // Token must be marked consumed so a compromised link can't be re-tried.
    const retry = await app.request(`/v1/rotate/${link.token}/exchange`, { method: "POST" });
    expect(retry.status).toBe(410);
  });

  test("GET /v1/rotate/:token returns 410 for an expired token", async () => {
    const role = await createRole(app, "rot-ttl", ["agent"]);
    const { body: link } = await generateRotateLink(app, role.role_id, { ttl_seconds: 60 });
    // Force the token expired by directly modifying the DB.
    db.query(
      "UPDATE rotate_tokens SET expires_at = datetime('now', '-1 minute') WHERE id = ?"
    ).run(link.id);

    const md = await app.request(`/v1/rotate/${link.token}`);
    expect(md.status).toBe(410);
  });
});

describe("Skill self-update API", () => {
  let db: Database;
  let app: ReturnType<typeof buildApp>;
  let dir: string;
  let policies: PolicyEngine;

  beforeEach(async () => {
    _resetRotateRateLimits();
    dir = mkdtempSync(join(tmpdir(), "gatehouse-skill-test-"));
    const polDir = join(dir, "policies");
    mkdirSync(polDir);
    writeFileSync(
      join(polDir, "agent.yaml"),
      `name: agent
rules:
  - paths: ["*"]
    capabilities: [proxy, read]
  - paths: ["ssh/*"]
    capabilities: [lease]
`
    );
    db = initDB(dir);
    process.env.GATEHOUSE_ROOT_TOKEN = TEST_ROOT_TOKEN;
    policies = new PolicyEngine(dir, db);
    app = buildApp(db, policies);
    await new Promise((r) => setTimeout(r, 30));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
    delete process.env.GATEHOUSE_ROOT_TOKEN;
  });

  test("GET /v1/skill returns the skill body with a policy-aware situation table", async () => {
    const role = await createRole(app, "skill-fetch", ["agent"]);
    const login = await loginWith(app, role.role_id, role.secret_id);
    expect(login.status).toBe(200);

    const res = await app.request("/v1/skill", {
      headers: { Authorization: `Bearer ${login.body.token}` },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/markdown");
    const md = await res.text();

    // The body must NOT include the bootstrap-only material (Step 1
    // through Step 4 of the onboard template). Use bootstrap-specific
    // markers, not just "/exchange" — the rotate-flow row in the HTTP
    // fallback table also mentions /v1/rotate/<token>/exchange, which
    // is intentional skill content.
    expect(md).not.toContain("Step 1: Detect your harness");
    expect(md).not.toContain("/v1/onboard/");
    expect(md).not.toContain("GATEHOUSE-SKILL-BEGIN");

    // Should contain the skill heading, operating rules, and a
    // policy-derived situation row (agent has lease on ssh/*).
    expect(md).toContain("# Gatehouse");
    expect(md).toContain("## Operating rules");
    expect(md).toContain("gatehouse_checkout` on `ssh/");
  });

  test("GET /v1/skill rejects unauthenticated callers", async () => {
    const res = await app.request("/v1/skill");
    expect(res.status).toBe(401);
  });

  test("GET /v1/skill rejects invalid bearer tokens", async () => {
    const res = await app.request("/v1/skill", {
      headers: { Authorization: "Bearer not-a-real-jwt" },
    });
    expect(res.status).toBe(401);
  });

  test("situation table reflects the caller's policies (not the role's stored policies)", async () => {
    // Create a role with NO ssh-relevant policies so the situation table
    // has no SSH/DB rows.
    writeFileSync(
      join(dir, "policies", "minimal.yaml"),
      `name: minimal
rules:
  - paths: ["api-keys/*"]
    capabilities: [proxy]
`
    );
    // Reload policies
    policies = new PolicyEngine(dir, db);
    app = buildApp(db, policies);
    await new Promise((r) => setTimeout(r, 30));

    const role = await createRole(app, "skill-min", ["minimal"]);
    const login = await loginWith(app, role.role_id, role.secret_id);
    const res = await app.request("/v1/skill", {
      headers: { Authorization: `Bearer ${login.body.token}` },
    });
    const md = await res.text();
    expect(md).toContain("gatehouse_proxy");
    expect(md).not.toContain("gatehouse_checkout` on `ssh/");
    expect(md).not.toContain("gatehouse_checkout` on `db/");
  });
});
