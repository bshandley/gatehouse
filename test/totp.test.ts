import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { initDB } from "../src/db/init";
import { authRouter } from "../src/api/auth";
import { meRouter } from "../src/api/me";
import { authMiddleware } from "../src/auth/middleware";
import { AuditLog } from "../src/audit/logger";
import type { GatehouseConfig } from "../src/config";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { deriveKey } from "../src/secrets/engine";
import {
  base32Encode,
  base32Decode,
  hotp,
  totp,
  verifyTotp,
  generateTotpSecret,
  buildOtpauthUri,
  generateRecoveryCodes,
} from "../src/auth/totp";

const TEST_MASTER_KEY = Buffer.from("b".repeat(64), "hex");
const TEST_ROOT_TOKEN = "test-root-token-totp";
const TEST_JWT_SECRET = Buffer.from(deriveKey(TEST_MASTER_KEY, "gatehouse-jwt")).toString("hex");

function buildApp(db: Database) {
  const config: GatehouseConfig = {
    port: 3100,
    dataDir: "/tmp",
    configDir: "/tmp",
    masterKey: TEST_MASTER_KEY,
    jwtSecret: TEST_JWT_SECRET,
  };

  const audit = new AuditLog(db);
  const app = new Hono();

  // Use a unique "source IP" per test-app instance so the module-level
  // failed-login rate limiter in auth.ts doesn't leak state across test files.
  const fakeIp = `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

  app.use("*", async (c, next) => {
    c.set("requestId", crypto.randomUUID());
    c.set("sourceIp", fakeIp);
    await next();
  });

  app.route("/v1/auth", authRouter(db, config));
  app.use("/v1/*", authMiddleware(config));
  app.route("/v1/me", meRouter(db, audit));

  return app;
}

// ═══════════════════════════════════════════════════════════
// TOTP library unit tests (RFC 6238 / RFC 4226 test vectors)
// ═══════════════════════════════════════════════════════════

describe("TOTP library", () => {
  // RFC 4226 Appendix D HOTP test vectors
  // Secret: "12345678901234567890" (ASCII) — "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" in base32
  const RFC4226_SECRET = base32Encode(Buffer.from("12345678901234567890"));

  test("base32 encode/decode roundtrip", () => {
    const input = Buffer.from("Hello, world!");
    const encoded = base32Encode(input);
    const decoded = base32Decode(encoded);
    expect(Buffer.from(decoded).toString()).toBe("Hello, world!");
  });

  test("base32 decode is case-insensitive and tolerates spaces", () => {
    const a = base32Decode("jbswy3dpehpk3pxp");
    const b = base32Decode("JBSWY3DP EHPK3PXP");
    const c = base32Decode("JBSWY3DPEHPK3PXP");
    expect(Buffer.from(a)).toEqual(Buffer.from(c));
    expect(Buffer.from(b)).toEqual(Buffer.from(c));
  });

  test("HOTP matches RFC 4226 test vectors", () => {
    const expected = [
      "755224", "287082", "359152", "969429", "338314",
      "254676", "287922", "162583", "399871", "520489",
    ];
    for (let counter = 0; counter < expected.length; counter++) {
      expect(hotp(RFC4226_SECRET, BigInt(counter))).toBe(expected[counter]);
    }
  });

  test("TOTP matches RFC 6238 test vector at T=59", () => {
    // RFC 6238 Appendix B: T=59 → counter=1, expected SHA1 code = 94287082
    // Truncated to 6 digits = "287082"
    expect(totp(RFC4226_SECRET, 59)).toBe("287082");
  });

  test("TOTP matches RFC 6238 test vector at T=1111111109", () => {
    expect(totp(RFC4226_SECRET, 1111111109)).toBe("081804");
  });

  test("verifyTotp accepts the current code", () => {
    const secret = generateTotpSecret();
    const now = 1_700_000_000;
    const code = totp(secret, now);
    expect(verifyTotp(secret, code, now)).toBe(true);
  });

  test("verifyTotp accepts codes within ±1 step window", () => {
    const secret = generateTotpSecret();
    const now = 1_700_000_000;
    const past = totp(secret, now - 30);
    const future = totp(secret, now + 30);
    expect(verifyTotp(secret, past, now)).toBe(true);
    expect(verifyTotp(secret, future, now)).toBe(true);
  });

  test("verifyTotp rejects codes outside the window", () => {
    const secret = generateTotpSecret();
    const now = 1_700_000_000;
    const stale = totp(secret, now - 120);
    expect(verifyTotp(secret, stale, now)).toBe(false);
  });

  test("verifyTotp rejects malformed codes", () => {
    const secret = generateTotpSecret();
    expect(verifyTotp(secret, "abcdef")).toBe(false);
    expect(verifyTotp(secret, "12345")).toBe(false);
    expect(verifyTotp(secret, "")).toBe(false);
  });

  test("generateTotpSecret returns a 32-char base32 string", () => {
    const s = generateTotpSecret();
    expect(s.length).toBe(32);
    expect(/^[A-Z2-7]+$/.test(s)).toBe(true);
  });

  test("buildOtpauthUri produces a well-formed URI", () => {
    const uri = buildOtpauthUri({
      secret: "JBSWY3DPEHPK3PXP",
      accountName: "alice@example.com",
      issuer: "Gatehouse",
    });
    expect(uri).toStartWith("otpauth://totp/Gatehouse%3Aalice");
    expect(uri).toContain("secret=JBSWY3DPEHPK3PXP");
    expect(uri).toContain("issuer=Gatehouse");
    expect(uri).toContain("algorithm=SHA1");
    expect(uri).toContain("digits=6");
    expect(uri).toContain("period=30");
  });

  test("generateRecoveryCodes produces 10 distinct XXXX-XXXX codes", () => {
    const codes = generateRecoveryCodes(10);
    expect(codes.length).toBe(10);
    expect(new Set(codes).size).toBe(10);
    for (const c of codes) {
      expect(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(c)).toBe(true);
    }
  });
});

// ═══════════════════════════════════════════════════════════
// TOTP endpoint integration tests
// ═══════════════════════════════════════════════════════════

describe("TOTP endpoints", () => {
  let db: Database;
  let app: ReturnType<typeof buildApp>;
  let dir: string;

  async function createUserAndLogin(): Promise<string> {
    // Create a user via root
    await app.request("/v1/auth/users", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_ROOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "alice",
        password: "correcthorsebatterystaple",
        display_name: "Alice",
      }),
    });

    // Log in
    const loginRes = await app.request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "alice", password: "correcthorsebatterystaple" }),
    });
    const loginBody = await loginRes.json();
    return loginBody.token;
  }

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-totp-test-"));
    db = initDB(dir);
    process.env.GATEHOUSE_ROOT_TOKEN = TEST_ROOT_TOKEN;
    app = buildApp(db);
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
    delete process.env.GATEHOUSE_ROOT_TOKEN;
  });

  test("GET /me/totp reports disabled by default", async () => {
    const token = await createUserAndLogin();
    const res = await app.request("/v1/me/totp", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.enabled).toBe(false);
    expect(body.recovery_codes_remaining).toBe(0);
  });

  test("TOTP setup + verify enables 2FA and returns recovery codes", async () => {
    const token = await createUserAndLogin();

    const setupRes = await app.request("/v1/me/totp/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(setupRes.status).toBe(200);
    const setup = await setupRes.json();
    expect(setup.secret).toBeString();
    expect(setup.otpauth_uri).toStartWith("otpauth://totp/");
    expect(setup.qr_data_uri).toStartWith("data:image/png;base64,");

    const code = totp(setup.secret);
    const verifyRes = await app.request("/v1/me/totp/verify", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });
    expect(verifyRes.status).toBe(200);
    const verify = await verifyRes.json();
    expect(verify.enabled).toBe(true);
    expect(verify.recovery_codes).toBeArray();
    expect(verify.recovery_codes.length).toBe(10);

    // Status should now report enabled
    const statusRes = await app.request("/v1/me/totp", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect((await statusRes.json()).enabled).toBe(true);
  });

  test("verify rejects a wrong code", async () => {
    const token = await createUserAndLogin();
    await app.request("/v1/me/totp/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const res = await app.request("/v1/me/totp/verify", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ code: "000000" }),
    });
    expect(res.status).toBe(401);
  });

  test("login with TOTP-enabled user returns totp_required and totp_token", async () => {
    const token = await createUserAndLogin();
    const setup = await (await app.request("/v1/me/totp/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    })).json();
    await app.request("/v1/me/totp/verify", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ code: totp(setup.secret) }),
    });

    // Now login again — should require TOTP
    const loginRes = await app.request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "alice", password: "correcthorsebatterystaple" }),
    });
    expect(loginRes.status).toBe(200);
    const loginBody = await loginRes.json();
    expect(loginBody.totp_required).toBe(true);
    expect(loginBody.totp_token).toBeString();
    expect(loginBody.token).toBeUndefined();
  });

  test("totp-pending token is rejected by the auth middleware", async () => {
    const token = await createUserAndLogin();
    const setup = await (await app.request("/v1/me/totp/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    })).json();
    await app.request("/v1/me/totp/verify", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ code: totp(setup.secret) }),
    });

    const loginRes = await app.request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "alice", password: "correcthorsebatterystaple" }),
    });
    const { totp_token } = await loginRes.json();

    // Try to use the pre-auth token against a protected endpoint
    const whoamiRes = await app.request("/v1/me/totp", {
      headers: { Authorization: `Bearer ${totp_token}` },
    });
    expect(whoamiRes.status).toBe(401);
  });

  test("POST /login/totp exchanges pre-auth token + code for a full JWT", async () => {
    const token = await createUserAndLogin();
    const setup = await (await app.request("/v1/me/totp/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    })).json();
    await app.request("/v1/me/totp/verify", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ code: totp(setup.secret) }),
    });

    const { totp_token } = await (await app.request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "alice", password: "correcthorsebatterystaple" }),
    })).json();

    const res = await app.request("/v1/auth/login/totp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ totp_token, code: totp(setup.secret) }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.token).toBeString();
    expect(body.identity).toBe("user:alice");
    expect(body.recovery_code_consumed).toBe(false);
  });

  test("POST /login/totp rejects an invalid code", async () => {
    const token = await createUserAndLogin();
    const setup = await (await app.request("/v1/me/totp/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    })).json();
    await app.request("/v1/me/totp/verify", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ code: totp(setup.secret) }),
    });

    const { totp_token } = await (await app.request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "alice", password: "correcthorsebatterystaple" }),
    })).json();

    const res = await app.request("/v1/auth/login/totp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ totp_token, code: "000000" }),
    });
    expect(res.status).toBe(401);
  });

  test("recovery code logs in and is single-use", async () => {
    const token = await createUserAndLogin();
    const setup = await (await app.request("/v1/me/totp/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    })).json();
    const verifyBody = await (await app.request("/v1/me/totp/verify", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ code: totp(setup.secret) }),
    })).json();
    const recoveryCode = verifyBody.recovery_codes[0];

    // First use — succeeds
    const login1 = await (await app.request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "alice", password: "correcthorsebatterystaple" }),
    })).json();
    const res1 = await app.request("/v1/auth/login/totp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ totp_token: login1.totp_token, code: recoveryCode }),
    });
    expect(res1.status).toBe(200);
    const body1 = await res1.json();
    expect(body1.recovery_code_consumed).toBe(true);

    // Second use of same recovery code — fails
    const login2 = await (await app.request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "alice", password: "correcthorsebatterystaple" }),
    })).json();
    const res2 = await app.request("/v1/auth/login/totp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ totp_token: login2.totp_token, code: recoveryCode }),
    });
    expect(res2.status).toBe(401);
  });

  test("DELETE /me/totp disables 2FA after password reconfirmation", async () => {
    const token = await createUserAndLogin();
    const setup = await (await app.request("/v1/me/totp/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    })).json();
    await app.request("/v1/me/totp/verify", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ code: totp(setup.secret) }),
    });

    // Wrong password
    const wrong = await app.request("/v1/me/totp", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ password: "wrong" }),
    });
    expect(wrong.status).toBe(401);

    // Correct password
    const right = await app.request("/v1/me/totp", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ password: "correcthorsebatterystaple" }),
    });
    expect(right.status).toBe(200);
  });

  test("admin can force-reset TOTP on a user via PUT /users/:username", async () => {
    const token = await createUserAndLogin();
    const setup = await (await app.request("/v1/me/totp/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    })).json();
    await app.request("/v1/me/totp/verify", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ code: totp(setup.secret) }),
    });

    // Admin resets it
    const res = await app.request("/v1/auth/users/alice", {
      method: "PUT",
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ reset_totp: true }),
    });
    expect(res.status).toBe(200);

    // Login should no longer require TOTP
    const loginRes = await app.request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "alice", password: "correcthorsebatterystaple" }),
    });
    const loginBody = await loginRes.json();
    expect(loginBody.totp_required).toBeUndefined();
    expect(loginBody.token).toBeString();
  });

  test("AppRole cannot manage TOTP (only user accounts can)", async () => {
    // Create an approle and log in
    const createRes = await app.request("/v1/auth/approle", {
      method: "POST",
      headers: { Authorization: `Bearer ${TEST_ROOT_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ display_name: "agent", policies: ["admin"] }),
    });
    const { role_id, secret_id } = await createRes.json();
    const loginRes = await app.request("/v1/auth/approle/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role_id, secret_id }),
    });
    const { token } = await loginRes.json();

    const res = await app.request("/v1/me/totp/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(403);
  });
});
