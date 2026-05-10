import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { initDB } from "../src/db/init";
import { authRouter } from "../src/api/auth";
import { authMiddleware } from "../src/auth/middleware";
import { AuditLog } from "../src/audit/logger";
import { PolicyEngine } from "../src/policy/engine";
import { deriveKey } from "../src/secrets/engine";
import { DEFAULT_PROXY_LIMITS, _resetProxyLimitsCacheForTests } from "../src/settings/proxyLimits";
import type { GatehouseConfig } from "../src/config";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SignJWT } from "jose";

const TEST_MASTER_KEY = Buffer.from("a".repeat(64), "hex");
const TEST_JWT_SECRET = Buffer.from(deriveKey(TEST_MASTER_KEY, "gatehouse-jwt")).toString("hex");
const TEST_ROOT_TOKEN = "test-root-token-pl-api";

async function adminJwt(): Promise<string> {
  const secret = new TextEncoder().encode(TEST_JWT_SECRET);
  return await new SignJWT({ sub: "user:admin", policies: ["admin"] })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("gatehouse")
    .setIssuedAt()
    .setExpirationTime("24h")
    .sign(secret);
}

async function readonlyJwt(): Promise<string> {
  const secret = new TextEncoder().encode(TEST_JWT_SECRET);
  return await new SignJWT({ sub: "user:bob", policies: ["readonly"] })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("gatehouse")
    .setIssuedAt()
    .setExpirationTime("24h")
    .sign(secret);
}

function buildApp(db: Database): { app: Hono; audit: AuditLog } {
  const config: GatehouseConfig = {
    port: 3100,
    dataDir: "/tmp",
    configDir: "/tmp",
    masterKey: TEST_MASTER_KEY,
    jwtSecret: TEST_JWT_SECRET,
  };
  const audit = new AuditLog(db);
  const policies = new PolicyEngine(config.configDir, db);

  // Seed user rows so the auth middleware's per-request DB check passes.
  // password_hash is unused in these tests (we bypass login entirely).
  db.query(
    "INSERT OR IGNORE INTO users (username, password_hash, display_name) VALUES (?, ?, ?)"
  ).run("admin", "unused", "Admin User");
  db.query(
    "INSERT OR IGNORE INTO users (username, password_hash, display_name) VALUES (?, ?, ?)"
  ).run("bob", "unused", "Bob Readonly");

  const app = new Hono();
  app.use("*", async (c, next) => {
    c.set("requestId", crypto.randomUUID());
    c.set("sourceIp", c.req.header("x-forwarded-for") || "127.0.0.1");
    await next();
  });
  app.route("/v1/auth", authRouter(db, config, audit));

  // Mount the proxy-limits handlers exactly as production does.
  // The implementer needs to either export the handlers or reproduce the
  // dispatch pattern here. The simplest harness: register the handlers
  // inline using the same code as src/index.ts.
  const { handleGetProxyLimits, handlePostProxyLimits } = require("../src/api/settings.proxyLimits");
  app.use("/v1/*", authMiddleware(config, db));
  app.get("/v1/settings/proxy-limits", (c) => handleGetProxyLimits(c, db, policies));
  app.post("/v1/settings/proxy-limits", (c) => handlePostProxyLimits(c, db, policies, audit));

  return { app, audit };
}

describe("GET /v1/settings/proxy-limits", () => {
  let db: Database;
  let app: Hono;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-pl-api-"));
    db = initDB(dir);
    process.env.GATEHOUSE_ROOT_TOKEN = TEST_ROOT_TOKEN;
    _resetProxyLimitsCacheForTests();
    app = buildApp(db).app;
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
    delete process.env.GATEHOUSE_ROOT_TOKEN;
    _resetProxyLimitsCacheForTests();
  });

  test("returns defaults when no row exists (admin)", async () => {
    const jwt = await adminJwt();
    const res = await app.request("/v1/settings/proxy-limits", {
      headers: { Authorization: `Bearer ${jwt}` },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(DEFAULT_PROXY_LIMITS);
  });

  test("returns persisted values", async () => {
    db.query("INSERT INTO settings (key, value) VALUES ('proxy_limits', ?)").run(
      JSON.stringify({ max_timeout_ms: 60_000, max_body_bytes: 5_000_000 })
    );
    _resetProxyLimitsCacheForTests();
    const jwt = await adminJwt();
    const res = await app.request("/v1/settings/proxy-limits", {
      headers: { Authorization: `Bearer ${jwt}` },
    });
    expect(await res.json()).toEqual({ max_timeout_ms: 60_000, max_body_bytes: 5_000_000 });
  });

  test("403 for non-admin caller", async () => {
    const jwt = await readonlyJwt();
    const res = await app.request("/v1/settings/proxy-limits", {
      headers: { Authorization: `Bearer ${jwt}` },
    });
    expect(res.status).toBe(403);
  });

  test("401 without Authorization", async () => {
    const res = await app.request("/v1/settings/proxy-limits");
    expect(res.status).toBe(401);
  });
});

describe("POST /v1/settings/proxy-limits", () => {
  let db: Database;
  let app: Hono;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-pl-api-post-"));
    db = initDB(dir);
    process.env.GATEHOUSE_ROOT_TOKEN = TEST_ROOT_TOKEN;
    _resetProxyLimitsCacheForTests();
    app = buildApp(db).app;
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
    delete process.env.GATEHOUSE_ROOT_TOKEN;
    _resetProxyLimitsCacheForTests();
  });

  test("admin can save valid limits", async () => {
    const jwt = await adminJwt();
    const res = await app.request("/v1/settings/proxy-limits", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ max_timeout_ms: 60_000, max_body_bytes: 5_000_000 }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.saved).toBe(true);

    const row = db.query("SELECT value FROM settings WHERE key = 'proxy_limits'").get() as any;
    expect(JSON.parse(row.value)).toEqual({ max_timeout_ms: 60_000, max_body_bytes: 5_000_000 });

    const auditRow = db
      .query(
        "SELECT identity, action FROM audit_log WHERE action = 'settings.proxy_limits.update' ORDER BY id DESC LIMIT 1"
      )
      .get() as any;
    expect(auditRow.identity).toBe("user:admin");
  });

  test("rejects invalid limits with 400 + error array", async () => {
    const jwt = await adminJwt();
    const res = await app.request("/v1/settings/proxy-limits", {
      method: "POST",
      headers: { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" },
      body: JSON.stringify({ max_timeout_ms: 0, max_body_bytes: 100 }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(Array.isArray(body.errors)).toBe(true);
    expect(body.errors.length).toBeGreaterThan(0);

    const row = db.query("SELECT 1 FROM settings WHERE key = 'proxy_limits'").get();
    expect(row).toBeNull();
  });

  test("rejects malformed JSON with 400", async () => {
    const jwt = await adminJwt();
    const res = await app.request("/v1/settings/proxy-limits", {
      method: "POST",
      headers: { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" },
      body: "not-json",
    });
    expect(res.status).toBe(400);
  });

  test("403 for non-admin", async () => {
    const jwt = await readonlyJwt();
    const res = await app.request("/v1/settings/proxy-limits", {
      method: "POST",
      headers: { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" },
      body: JSON.stringify({ max_timeout_ms: 60_000, max_body_bytes: 5_000_000 }),
    });
    expect(res.status).toBe(403);
  });

  test("ignores extra fields in body", async () => {
    const jwt = await adminJwt();
    const res = await app.request("/v1/settings/proxy-limits", {
      method: "POST",
      headers: { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        max_timeout_ms: 60_000,
        max_body_bytes: 5_000_000,
        evil: "should-not-persist",
      }),
    });
    expect(res.status).toBe(200);
    const row = db.query("SELECT value FROM settings WHERE key = 'proxy_limits'").get() as any;
    const stored = JSON.parse(row.value);
    expect(stored.evil).toBeUndefined();
    expect(stored).toEqual({ max_timeout_ms: 60_000, max_body_bytes: 5_000_000 });
  });
});
