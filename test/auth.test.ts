import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { initDB } from "../src/db/init";
import { authRouter } from "../src/api/auth";
import { authMiddleware } from "../src/auth/middleware";
import type { GatehouseConfig } from "../src/config";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { deriveKey } from "../src/secrets/engine";

const TEST_MASTER_KEY = Buffer.from("a".repeat(64), "hex");
const TEST_ROOT_TOKEN = "test-root-token-for-auth-tests";
const TEST_JWT_SECRET = Buffer.from(
  deriveKey(TEST_MASTER_KEY, "gatehouse-jwt")
).toString("hex");

function buildApp(db: Database) {
  const config: GatehouseConfig = {
    port: 3100,
    dataDir: "/tmp",
    configDir: "/tmp",
    masterKey: TEST_MASTER_KEY,
    jwtSecret: TEST_JWT_SECRET,
  };

  const app = new Hono();

  // Request ID + source IP middleware
  app.use("*", async (c, next) => {
    c.set("requestId", crypto.randomUUID());
    c.set("sourceIp", c.req.header("x-forwarded-for") || "127.0.0.1");
    await next();
  });

  app.route("/v1/auth", authRouter(db, config));

  // Protected test route to verify tokens work
  app.use("/v1/*", authMiddleware(config));
  app.get("/v1/whoami", (c) => {
    const auth = c.get("auth") as any;
    return c.json({ identity: auth.identity, policies: auth.policies });
  });

  return app;
}

describe("Auth API", () => {
  let db: Database;
  let app: ReturnType<typeof buildApp>;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-auth-test-"));
    db = initDB(dir);
    process.env.GATEHOUSE_ROOT_TOKEN = TEST_ROOT_TOKEN;
    app = buildApp(db);
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
    delete process.env.GATEHOUSE_ROOT_TOKEN;
  });

  // AppRole creation

  test("POST /approle creates an AppRole with root token", async () => {
    const res = await app.request("/v1/auth/approle", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        display_name: "test-agent",
        policies: ["agent-readonly"],
      }),
    });

    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.role_id).toStartWith("role-");
    expect(body.secret_id).toBeDefined();
    expect(body.display_name).toBe("test-agent");
    expect(body.policies).toEqual(["agent-readonly"]);
    expect(body.warning).toContain("secret_id");
  });

  test("POST /approle rejects without root token", async () => {
    const res = await app.request("/v1/auth/approle", {
      method: "POST",
      headers: {
        Authorization: "Bearer wrong-token",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ display_name: "bad", policies: [] }),
    });

    expect(res.status).toBe(403);
  });

  test("POST /approle validates display_name", async () => {
    const res = await app.request("/v1/auth/approle", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ display_name: "", policies: [] }),
    });

    expect(res.status).toBe(400);
  });

  test("POST /approle validates policies is array", async () => {
    const res = await app.request("/v1/auth/approle", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ display_name: "test", policies: "not-array" }),
    });

    expect(res.status).toBe(400);
  });

  // AppRole login

  test("POST /approle/login returns JWT for valid credentials", async () => {
    // Create an AppRole first
    const createRes = await app.request("/v1/auth/approle", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        display_name: "login-test",
        policies: ["agent-readonly"],
      }),
    });
    const { role_id, secret_id } = await createRes.json();

    // Login
    const loginRes = await app.request("/v1/auth/approle/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role_id, secret_id }),
    });

    expect(loginRes.status).toBe(200);
    const loginBody = await loginRes.json();
    expect(loginBody.token).toBeDefined();
    expect(loginBody.identity).toBe("approle:login-test");
    expect(loginBody.policies).toEqual(["agent-readonly"]);
    expect(loginBody.expires_in).toBe(86400);
  });

  test("POST /approle/login rejects invalid secret_id", async () => {
    const createRes = await app.request("/v1/auth/approle", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ display_name: "bad-login", policies: [] }),
    });
    const { role_id } = await createRes.json();

    const loginRes = await app.request("/v1/auth/approle/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role_id, secret_id: "wrong-secret" }),
    });

    expect(loginRes.status).toBe(401);
  });

  test("POST /approle/login rejects unknown role_id", async () => {
    const res = await app.request("/v1/auth/approle/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role_id: "role-nonexistent", secret_id: "x" }),
    });

    expect(res.status).toBe(401);
  });

  test("POST /approle/login rejects missing fields", async () => {
    const res = await app.request("/v1/auth/approle/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role_id: "x" }),
    });

    expect(res.status).toBe(400);
  });

  test("JWT from AppRole login works on protected routes", async () => {
    // Create + login
    const createRes = await app.request("/v1/auth/approle", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ display_name: "jwt-test", policies: ["admin"] }),
    });
    const { role_id, secret_id } = await createRes.json();

    const loginRes = await app.request("/v1/auth/approle/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role_id, secret_id }),
    });
    const { token } = await loginRes.json();

    // Use token on a protected route
    const whoami = await app.request("/v1/whoami", {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(whoami.status).toBe(200);
    const body = await whoami.json();
    expect(body.identity).toBe("approle:jwt-test");
    expect(body.policies).toEqual(["admin"]);
  });

  // AppRole list / delete

  test("GET /approle lists roles with root token", async () => {
    // Create two roles
    for (const name of ["role-a", "role-b"]) {
      await app.request("/v1/auth/approle", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ display_name: name, policies: [] }),
      });
    }

    const res = await app.request("/v1/auth/approle", {
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}` },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.roles.length).toBe(2);
  });

  test("DELETE /approle/:roleId deletes a role", async () => {
    const createRes = await app.request("/v1/auth/approle", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ display_name: "del-me", policies: [] }),
    });
    const { role_id } = await createRes.json();

    const delRes = await app.request(`/v1/auth/approle/${role_id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}` },
    });

    expect(delRes.status).toBe(200);
    const body = await delRes.json();
    expect(body.deleted).toBe(true);

    // Verify it's gone
    const listRes = await app.request("/v1/auth/approle", {
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}` },
    });
    const list = await listRes.json();
    expect(list.roles.length).toBe(0);
  });

  test("DELETE /approle/:roleId returns 404 for unknown role", async () => {
    const res = await app.request("/v1/auth/approle/role-nonexistent", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}` },
    });

    expect(res.status).toBe(404);
  });

  // Rate limiting

  test("rate limits after 5 failed login attempts", async () => {
    // Create a role so we have a valid role_id
    const createRes = await app.request("/v1/auth/approle", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ display_name: "rate-test", policies: [] }),
    });
    const { role_id } = await createRes.json();

    // 5 failed attempts
    for (let i = 0; i < 5; i++) {
      await app.request("/v1/auth/approle/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Forwarded-For": "10.0.0.99",
        },
        body: JSON.stringify({ role_id, secret_id: "wrong" }),
      });
    }

    // 6th attempt should be rate limited
    const res = await app.request("/v1/auth/approle/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Forwarded-For": "10.0.0.99",
      },
      body: JSON.stringify({ role_id, secret_id: "wrong" }),
    });

    expect(res.status).toBe(429);
  });

  // User login

  test("POST /login returns JWT for valid user credentials", async () => {
    // Create a user first
    const createRes = await app.request("/v1/auth/users", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "testadmin",
        password: "securepass123",
        display_name: "Test Admin",
      }),
    });
    expect(createRes.status).toBe(201);

    // Login
    const loginRes = await app.request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "testadmin", password: "securepass123" }),
    });

    expect(loginRes.status).toBe(200);
    const body = await loginRes.json();
    expect(body.token).toBeDefined();
    expect(body.identity).toBe("user:testadmin");
    expect(body.display_name).toBe("Test Admin");
  });

  test("POST /login rejects wrong password", async () => {
    await app.request("/v1/auth/users", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "wrongpw",
        password: "correctpass1",
        display_name: "User",
      }),
    });

    const res = await app.request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "wrongpw", password: "wrongpassword" }),
    });

    expect(res.status).toBe(401);
  });

  test("POST /login rejects unknown username", async () => {
    const res = await app.request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "ghost", password: "whatever1" }),
    });

    expect(res.status).toBe(401);
  });

  test("POST /login rejects missing fields", async () => {
    const res = await app.request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "x" }),
    });

    expect(res.status).toBe(400);
  });

  // User CRUD

  test("POST /users creates a user", async () => {
    const res = await app.request("/v1/auth/users", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "newuser",
        password: "password123",
        display_name: "New User",
        email: "new@test.com",
      }),
    });

    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.username).toBe("newuser");
    expect(body.display_name).toBe("New User");
    expect(body.email).toBe("new@test.com");
  });

  test("POST /users rejects duplicate username", async () => {
    const headers = {
      Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
      "Content-Type": "application/json",
    };
    const body = JSON.stringify({
      username: "dupe",
      password: "password123",
      display_name: "Dupe",
    });

    await app.request("/v1/auth/users", { method: "POST", headers, body });
    const res = await app.request("/v1/auth/users", { method: "POST", headers, body });

    expect(res.status).toBe(409);
  });

  test("POST /users validates username format", async () => {
    const res = await app.request("/v1/auth/users", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "bad user!",
        password: "password123",
        display_name: "Bad",
      }),
    });

    expect(res.status).toBe(400);
  });

  test("POST /users validates password length", async () => {
    const res = await app.request("/v1/auth/users", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "shortpw",
        password: "short",
        display_name: "Short",
      }),
    });

    expect(res.status).toBe(400);
  });

  test("GET /users lists all users", async () => {
    const headers = {
      Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
      "Content-Type": "application/json",
    };

    await app.request("/v1/auth/users", {
      method: "POST",
      headers,
      body: JSON.stringify({ username: "u1", password: "password123", display_name: "U1" }),
    });
    await app.request("/v1/auth/users", {
      method: "POST",
      headers,
      body: JSON.stringify({ username: "u2", password: "password123", display_name: "U2" }),
    });

    const res = await app.request("/v1/auth/users", {
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}` },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.users.length).toBe(2);
    // Should not include password_hash
    expect(body.users[0].password_hash).toBeUndefined();
  });

  test("PUT /users/:username updates user fields", async () => {
    await app.request("/v1/auth/users", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "updateme",
        password: "password123",
        display_name: "Before",
      }),
    });

    const res = await app.request("/v1/auth/users/updateme", {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ display_name: "After", email: "after@test.com" }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.updated).toBe(true);
  });

  test("PUT /users/:username can disable a user", async () => {
    await app.request("/v1/auth/users", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "disableme",
        password: "password123",
        display_name: "DisableMe",
      }),
    });

    await app.request("/v1/auth/users/disableme", {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ enabled: false }),
    });

    // Disabled user can't login
    const loginRes = await app.request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "disableme", password: "password123" }),
    });

    expect(loginRes.status).toBe(401);
  });

  test("PUT /users/:username returns 404 for unknown user", async () => {
    const res = await app.request("/v1/auth/users/ghost", {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ display_name: "Ghost" }),
    });

    expect(res.status).toBe(404);
  });

  test("DELETE /users/:username deletes a user", async () => {
    await app.request("/v1/auth/users", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "deleteme",
        password: "password123",
        display_name: "DeleteMe",
      }),
    });

    const res = await app.request("/v1/auth/users/deleteme", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}` },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.deleted).toBe(true);
  });

  test("DELETE /users/:username returns 404 for unknown user", async () => {
    const res = await app.request("/v1/auth/users/ghost", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}` },
    });

    expect(res.status).toBe(404);
  });

  // Root token protection

  test("protected route rejects invalid token", async () => {
    const res = await app.request("/v1/whoami", {
      headers: { Authorization: "Bearer completely-wrong-token" },
    });

    expect(res.status).toBe(401);
  });

  test("protected route rejects missing auth header", async () => {
    const res = await app.request("/v1/whoami");
    expect(res.status).toBe(401);
  });

  test("root token works on protected routes", async () => {
    const res = await app.request("/v1/whoami", {
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}` },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.identity).toBe("root");
    expect(body.policies).toEqual(["admin"]);
  });
});
