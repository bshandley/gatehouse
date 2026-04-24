import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { initDB } from "../src/db/init";
import { onboardRouter, _resetOnboardRateLimits } from "../src/api/onboard";
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
const TEST_ROOT_TOKEN = "test-root-token-for-onboard-tests";
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
  app.route("/v1/onboard", onboardRouter(db, audit, policies, config));

  // Protected test route used to verify minted JWTs work end-to-end.
  app.use("/v1/*", authMiddleware(config));
  app.get("/v1/whoami", (c) => {
    const auth = c.get("auth") as any;
    return c.json({ identity: auth.identity, policies: auth.policies });
  });
  return app;
}

async function createRole(
  app: ReturnType<typeof buildApp>,
  display_name: string,
  policies: string[],
  extra: Record<string, any> = {}
): Promise<{ role_id: string; secret_id: string }> {
  const res = await app.request("/v1/auth/approle", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ display_name, policies, ...extra }),
  });
  expect(res.status).toBe(201);
  return res.json();
}

async function generateLink(
  app: ReturnType<typeof buildApp>,
  role_id: string,
  extra: Record<string, any> = {}
): Promise<any> {
  const res = await app.request("/v1/onboard", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ role_id, ...extra }),
  });
  return { status: res.status, body: await res.json() };
}

describe("Onboarding API", () => {
  let db: Database;
  let app: ReturnType<typeof buildApp>;
  let dir: string;
  let policies: PolicyEngine;

  beforeEach(async () => {
    _resetOnboardRateLimits();
    dir = mkdtempSync(join(tmpdir(), "gatehouse-onboard-test-"));
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
    // Allow the template to finish loading from disk.
    await new Promise((r) => setTimeout(r, 30));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
    delete process.env.GATEHOUSE_ROOT_TOKEN;
  });

  test("create + fetch + exchange happy path rotates secret_id and mints JWT", async () => {
    const role = await createRole(app, "memos-user", ["agent"]);

    const { status, body } = await generateLink(app, role.role_id, { ttl_seconds: 600, label: "test link" });
    expect(status).toBe(200);
    expect(body.onboard_url).toContain("/v1/onboard/");
    expect(body.token).toBeTruthy();
    expect(body.role_display_name).toBe("memos-user");

    // Fetch markdown (unauth)
    const mdRes = await app.request(`/v1/onboard/${body.token}`);
    expect(mdRes.status).toBe(200);
    expect(mdRes.headers.get("content-type")).toContain("text/markdown");
    const md = await mdRes.text();
    expect(md).toContain("memos-user");
    expect(md).toContain(`/v1/onboard/${body.token}/exchange`);
    expect(md).toContain("gatehouse_proxy");
    expect(md).toContain("gatehouse_checkout` on `db/");

    // Exchange (unauth)
    const ex = await app.request(`/v1/onboard/${body.token}/exchange`, { method: "POST" });
    expect(ex.status).toBe(200);
    const exBody = await ex.json();
    expect(exBody.token).toBeTruthy();
    expect(exBody.secret_id).toBeTruthy();
    expect(exBody.role_id).toBe(role.role_id);
    expect(exBody.role_display_name).toBe("memos-user");
    expect(exBody.mcp_url).toContain("/v1/mcp");

    // The minted JWT should authenticate against a protected route.
    const who = await app.request("/v1/whoami", {
      headers: { Authorization: `Bearer ${exBody.token}` },
    });
    expect(who.status).toBe(200);
    const whoBody = await who.json();
    expect(whoBody.identity).toBe("approle:memos-user");
    expect(whoBody.policies).toEqual(["agent"]);

    // Original secret_id should now be invalid - the exchange rotated it.
    // Use a fresh x-forwarded-for so the shared auth rate limiter (module-level
    // in src/api/auth.ts) doesn't interfere when run alongside other tests.
    const oldLogin = await app.request("/v1/auth/approle/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-forwarded-for": "10.10.10.1" },
      body: JSON.stringify({ role_id: role.role_id, secret_id: role.secret_id }),
    });
    expect(oldLogin.status).toBe(401);

    // Rotated secret_id DOES work.
    const newLogin = await app.request("/v1/auth/approle/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-forwarded-for": "10.10.10.2" },
      body: JSON.stringify({ role_id: role.role_id, secret_id: exBody.secret_id }),
    });
    expect(newLogin.status).toBe(200);
  });

  test("exchange is single-use; second attempt returns 410", async () => {
    const role = await createRole(app, "agent-a", ["agent"]);
    const { body } = await generateLink(app, role.role_id);

    const first = await app.request(`/v1/onboard/${body.token}/exchange`, { method: "POST" });
    expect(first.status).toBe(200);

    const second = await app.request(`/v1/onboard/${body.token}/exchange`, { method: "POST" });
    expect(second.status).toBe(410);
  });

  test("fetch returns 410 with plain text for unknown token", async () => {
    const res = await app.request("/v1/onboard/totally-fake-token-value");
    expect(res.status).toBe(410);
    expect(res.headers.get("content-type")).toContain("text/plain");
  });

  test("create requires admin", async () => {
    const role = await createRole(app, "a", ["agent"]);
    const noAuth = await app.request("/v1/onboard", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role_id: role.role_id }),
    });
    expect(noAuth.status).toBe(403);
  });

  test("create rejects unknown role_id", async () => {
    const { status, body } = await generateLink(app, "role-does-not-exist");
    expect(status).toBe(404);
    expect(body.error).toContain("not found");
  });

  test("create rejects ttl outside bounds", async () => {
    const role = await createRole(app, "a", ["agent"]);
    const tooShort = await generateLink(app, role.role_id, { ttl_seconds: 5 });
    expect(tooShort.status).toBe(400);
    const tooLong = await generateLink(app, role.role_id, { ttl_seconds: 99999 });
    expect(tooLong.status).toBe(400);
  });

  test("exchange blocked for suspended role, token is consumed", async () => {
    const role = await createRole(app, "a", ["agent"]);
    const { body } = await generateLink(app, role.role_id);

    await app.request(`/v1/auth/approle/${role.role_id}/suspend`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ suspended: true }),
    });

    const ex = await app.request(`/v1/onboard/${body.token}/exchange`, { method: "POST" });
    expect(ex.status).toBe(403);
    // Token is now consumed - a second attempt after unsuspension should also fail.
    await app.request(`/v1/auth/approle/${role.role_id}/suspend`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ suspended: false }),
    });
    const retry = await app.request(`/v1/onboard/${body.token}/exchange`, { method: "POST" });
    expect(retry.status).toBe(410);
  });

  test("exchange blocked for IP not in allowlist does NOT consume the token", async () => {
    const role = await createRole(app, "a", ["agent"], { ip_allowlist: ["10.0.0.0/8"] });
    const { body } = await generateLink(app, role.role_id);

    const wrongIp = await app.request(`/v1/onboard/${body.token}/exchange`, {
      method: "POST",
      headers: { "x-forwarded-for": "192.168.1.5" },
    });
    expect(wrongIp.status).toBe(403);

    // Retry from the right network within TTL must still work.
    const rightIp = await app.request(`/v1/onboard/${body.token}/exchange`, {
      method: "POST",
      headers: { "x-forwarded-for": "10.0.0.42" },
    });
    expect(rightIp.status).toBe(200);
  });

  test("revoke unused token returns 410 on subsequent exchange", async () => {
    const role = await createRole(app, "a", ["agent"]);
    const { body } = await generateLink(app, role.role_id);

    const revoke = await app.request(`/v1/onboard/${body.id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}` },
    });
    expect(revoke.status).toBe(200);

    const ex = await app.request(`/v1/onboard/${body.token}/exchange`, { method: "POST" });
    expect(ex.status).toBe(410);
  });

  test("list shows active token and hides it once consumed", async () => {
    const role = await createRole(app, "a", ["agent"]);
    const { body } = await generateLink(app, role.role_id, { label: "for bot" });

    const l1 = await app.request(`/v1/onboard?role_id=${role.role_id}`, {
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}` },
    });
    const l1Body = await l1.json();
    expect(l1Body.tokens.length).toBe(1);
    expect(l1Body.tokens[0].status).toBe("active");
    expect(l1Body.tokens[0].label).toBe("for bot");

    // Responses must never include the token or its hash.
    expect(JSON.stringify(l1Body)).not.toContain(body.token);

    await app.request(`/v1/onboard/${body.token}/exchange`, { method: "POST" });

    const l2 = await app.request(`/v1/onboard?role_id=${role.role_id}`, {
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}` },
    });
    expect((await l2.json()).tokens.length).toBe(0);

    const l3 = await app.request(`/v1/onboard?role_id=${role.role_id}&include_consumed=true`, {
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}` },
    });
    const l3Body = await l3.json();
    expect(l3Body.tokens[0].status).toBe("consumed");
  });

  test("situation table reflects role capabilities", async () => {
    // Role has proxy+read on *, lease on db/*. Should include proxy, patterns,
    // db checkout (dynamic), and raw get; should NOT include write or ssh.
    const role = await createRole(app, "agent", ["agent"]);
    const { body } = await generateLink(app, role.role_id);
    const md = await (await app.request(`/v1/onboard/${body.token}`)).text();

    expect(md).toContain("gatehouse_proxy");
    expect(md).toContain("gatehouse_patterns");
    expect(md).toContain("gatehouse_checkout` on `db/");
    expect(md).not.toContain("gatehouse_checkout` on `ssh/");
    expect(md).toContain("gatehouse_get");
    expect(md).not.toContain("gatehouse_put");
  });
});
