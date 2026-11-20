import { describe, test, expect, beforeEach, afterEach, spyOn } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { initDB } from "../src/db/init";
import {
  PASSTHROUGH_KEY_PREFIX,
  encodePassthroughKey,
  parsePassthroughKey,
  createPassthroughKeyVerifier,
  _resetPassthroughKeyCacheForTests,
} from "../src/proxy/passthroughKey";
import { checkRateLimit, recordFailure, _resetRateLimitForTests as resetFromLimiter } from "../src/auth/loginLimiter";
import { _resetRateLimitForTests as resetFromAuth } from "../src/api/auth";
import { createBearerVerifier } from "../src/auth/verifyBearer";
import { SignJWT } from "jose";

// Fixed vectors, shared with the UI test that builds the same key in the browser.
export const VECTORS = [
  { roleId: "role-1", secretId: "abc", key: "gatehouse_pt_cm9sZS0xOmFiYw" },
  { roleId: "r", secretId: "a+b/c=d:e", key: "gatehouse_pt_cjphK2IvYz1kOmU" },
  {
    roleId: "r\u00f4le-\u00e9",
    secretId: "s\u00e9cret-\u65e5\u672c\u8a9e:\u2713",
    key: "gatehouse_pt_csO0bGUtw6k6c8OpY3JldC3ml6XmnKzoqp464pyT",
  },
];

describe("passthrough key encoding", () => {
  test("prefix", () => expect(PASSTHROUGH_KEY_PREFIX).toBe("gatehouse_pt_"));

  for (const v of VECTORS) {
    test(`vector ${v.roleId}`, () => {
      expect(encodePassthroughKey(v.roleId, v.secretId)).toBe(v.key);
      expect(parsePassthroughKey(v.key)).toEqual({ roleId: v.roleId, secretId: v.secretId });
    });
  }

  test("a secret_id containing colons round-trips (split on the first colon)", () => {
    const k = encodePassthroughKey("r1", "a:b:c");
    expect(parsePassthroughKey(k)).toEqual({ roleId: "r1", secretId: "a:b:c" });
  });

  test("rejects wrong prefix, bad base64url, no colon, empty parts", () => {
    const b = (s: string) => Buffer.from(s).toString("base64url");
    expect(parsePassthroughKey("gatehouse_xx_" + b("r:s"))).toBeNull();
    expect(parsePassthroughKey(b("r:s"))).toBeNull();
    expect(parsePassthroughKey(PASSTHROUGH_KEY_PREFIX)).toBeNull();
    expect(parsePassthroughKey(PASSTHROUGH_KEY_PREFIX + b("nocolon"))).toBeNull();
    expect(parsePassthroughKey(PASSTHROUGH_KEY_PREFIX + b(":secret"))).toBeNull();
    expect(parsePassthroughKey(PASSTHROUGH_KEY_PREFIX + b("role:"))).toBeNull();
    // Padding, standard-alphabet characters, and stray characters the lenient decoder would skip.
    expect(parsePassthroughKey(PASSTHROUGH_KEY_PREFIX + b("r:s") + "=")).toBeNull();
    expect(parsePassthroughKey(PASSTHROUGH_KEY_PREFIX + "cjphK2Iv+z1kOmU")).toBeNull();
    expect(parsePassthroughKey(PASSTHROUGH_KEY_PREFIX + b("r:s") + "!!")).toBeNull();
    expect(parsePassthroughKey(PASSTHROUGH_KEY_PREFIX + " " + b("r:s"))).toBeNull();
    // Valid base64url of bytes that are not UTF-8.
    expect(parsePassthroughKey(PASSTHROUGH_KEY_PREFIX + Buffer.from([0x72, 0x3a, 0xff]).toString("base64url"))).toBeNull();
  });
});

describe("passthrough key verifier", () => {
  let dir: string;
  let db: ReturnType<typeof initDB>;
  let t = 1_000_000;
  const now = () => t;
  let verifySpy: ReturnType<typeof spyOn>;

  async function addRole(roleId: string, secretId: string, extra: { policies?: string[]; allow?: string[] } = {}) {
    const hash = await Bun.password.hash(secretId);
    db.query(
      "INSERT INTO app_roles (role_id, secret_hash, display_name, policies, ip_allowlist) VALUES (?, ?, ?, ?, ?)"
    ).run(roleId, hash, "Agent " + roleId, JSON.stringify(extra.policies ?? ["reader"]), extra.allow ? JSON.stringify(extra.allow) : null);
  }

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gh-ptkey-"));
    db = initDB(dir);
    t = 1_000_000;
    _resetPassthroughKeyCacheForTests();
    verifySpy = spyOn(Bun.password, "verify");
  });
  afterEach(() => {
    verifySpy.mockRestore();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("valid key authenticates as the approle identity with policies from the row", async () => {
    await addRole("r1", "sekret", { policies: ["reader", "writer"] });
    const v = createPassthroughKeyVerifier(db, { now });
    const res = await v(encodePassthroughKey("r1", "sekret"), "10.0.0.1");
    expect(res).toEqual({
      ok: true,
      auth: { identity: "approle:Agent r1", policies: ["reader", "writer"], source: "approle", role_id: "r1" },
    });
    const row = db.query("SELECT last_used FROM app_roles WHERE role_id = 'r1'").get() as any;
    expect(row.last_used).not.toBeNull();
  });

  test("wrong secret and unknown role give the same 401 body, malformed key too", async () => {
    await addRole("r1", "sekret");
    const v = createPassthroughKeyVerifier(db, { now });
    const wrong = await v(encodePassthroughKey("r1", "nope"), "10.0.0.1");
    const unknown = await v(encodePassthroughKey("ghost", "sekret"), "10.0.0.1");
    const bad = await v("gatehouse_pt_!!!", "10.0.0.1");
    expect(wrong).toEqual({ ok: false, status: 401, error: "Invalid credentials" });
    expect(unknown).toEqual(wrong);
    expect(bad).toEqual(wrong);
  });

  test("a failed verification is never cached", async () => {
    await addRole("r1", "sekret");
    const v = createPassthroughKeyVerifier(db, { now });
    await v(encodePassthroughKey("r1", "nope"), "10.0.0.1");
    await v(encodePassthroughKey("r1", "nope"), "10.0.0.1");
    expect(verifySpy).toHaveBeenCalledTimes(2);
  });

  test("suspended: 403 after the secret verifies, on a miss and on a cached hit; wrong secret on a suspended role stays 401", async () => {
    await addRole("r1", "sekret");
    const v = createPassthroughKeyVerifier(db, { now });
    const key = encodePassthroughKey("r1", "sekret");
    db.query("UPDATE app_roles SET suspended = 1 WHERE role_id = 'r1'").run();
    expect((await v(key, "10.0.0.1")).ok).toBe(false);
    expect(await v(key, "10.0.0.1")).toMatchObject({ status: 403, error: "AppRole is suspended" });
    expect(await v(encodePassthroughKey("r1", "nope"), "10.0.0.1")).toMatchObject({ status: 401 });

    db.query("UPDATE app_roles SET suspended = 0 WHERE role_id = 'r1'").run();
    expect((await v(key, "10.0.0.1")).ok).toBe(true); // now cached
    db.query("UPDATE app_roles SET suspended = 1 WHERE role_id = 'r1'").run();
    expect(await v(key, "10.0.0.1")).toMatchObject({ ok: false, status: 403 });
  });

  test("IP allowlist: 403 on a miss and on a cached hit", async () => {
    await addRole("r1", "sekret", { allow: ["10.0.0.0/24"] });
    const v = createPassthroughKeyVerifier(db, { now });
    const key = encodePassthroughKey("r1", "sekret");
    expect(await v(key, "192.168.1.1")).toMatchObject({ status: 403, error: "Source IP not permitted for this AppRole" });
    expect((await v(key, "10.0.0.5")).ok).toBe(true); // cached
    expect(await v(key, "192.168.1.1")).toMatchObject({ ok: false, status: 403 });
    db.query("UPDATE app_roles SET ip_allowlist = NULL WHERE role_id = 'r1'").run();
    expect((await v(key, "192.168.1.1")).ok).toBe(true);
  });

  test("policies changed in the db show up on the next cached request", async () => {
    await addRole("r1", "sekret", { policies: ["reader"] });
    const v = createPassthroughKeyVerifier(db, { now });
    const key = encodePassthroughKey("r1", "sekret");
    await v(key, "10.0.0.1");
    db.query("UPDATE app_roles SET policies = ? WHERE role_id = 'r1'").run(JSON.stringify(["admin"]));
    const res = await v(key, "10.0.0.1");
    expect(res.ok && res.auth.policies).toEqual(["admin"]);
    expect(verifySpy).toHaveBeenCalledTimes(1);
  });

  test("rotating secret_hash invalidates the old key on the next request", async () => {
    await addRole("r1", "sekret");
    const v = createPassthroughKeyVerifier(db, { now });
    const old = encodePassthroughKey("r1", "sekret");
    expect((await v(old, "10.0.0.1")).ok).toBe(true);
    db.query("UPDATE app_roles SET secret_hash = ? WHERE role_id = 'r1'").run(await Bun.password.hash("new-secret"));
    expect(await v(old, "10.0.0.1")).toMatchObject({ ok: false, status: 401 });
    expect((await v(encodePassthroughKey("r1", "new-secret"), "10.0.0.1")).ok).toBe(true);
  });

  test("deleting the AppRole invalidates a cached key", async () => {
    await addRole("r1", "sekret");
    const v = createPassthroughKeyVerifier(db, { now });
    const key = encodePassthroughKey("r1", "sekret");
    expect((await v(key, "10.0.0.1")).ok).toBe(true);
    db.query("DELETE FROM app_roles WHERE role_id = 'r1'").run();
    expect(await v(key, "10.0.0.1")).toEqual({ ok: false, status: 401, error: "Invalid credentials" });
  });

  test("argon2 verify runs once across two requests, and again after ttlMs", async () => {
    await addRole("r1", "sekret");
    const v = createPassthroughKeyVerifier(db, { now, ttlMs: 1000 });
    const key = encodePassthroughKey("r1", "sekret");
    await v(key, "10.0.0.1");
    await v(key, "10.0.0.1");
    expect(verifySpy).toHaveBeenCalledTimes(1);
    t += 999;
    await v(key, "10.0.0.1");
    expect(verifySpy).toHaveBeenCalledTimes(1);
    t += 1;
    await v(key, "10.0.0.1");
    expect(verifySpy).toHaveBeenCalledTimes(2);
  });

  test("last_used is written on a miss only", async () => {
    await addRole("r1", "sekret");
    const v = createPassthroughKeyVerifier(db, { now });
    const key = encodePassthroughKey("r1", "sekret");
    await v(key, "10.0.0.1");
    db.query("UPDATE app_roles SET last_used = 'sentinel' WHERE role_id = 'r1'").run();
    await v(key, "10.0.0.1");
    expect((db.query("SELECT last_used FROM app_roles WHERE role_id = 'r1'").get() as any).last_used).toBe("sentinel");
  });

  test("eviction at maxEntries drops the oldest-inserted entry", async () => {
    await addRole("a", "sa");
    await addRole("b", "sb");
    await addRole("c", "sc");
    const v = createPassthroughKeyVerifier(db, { now, maxEntries: 2 });
    const [ka, kb, kc] = [encodePassthroughKey("a", "sa"), encodePassthroughKey("b", "sb"), encodePassthroughKey("c", "sc")];
    await v(ka, "10.0.0.1");
    await v(kb, "10.0.0.1");
    await v(kc, "10.0.0.1"); // evicts a
    expect(verifySpy).toHaveBeenCalledTimes(3);
    await v(kb, "10.0.0.1");
    await v(kc, "10.0.0.1");
    expect(verifySpy).toHaveBeenCalledTimes(3);
    await v(ka, "10.0.0.1"); // a was evicted: verifies again
    expect(verifySpy).toHaveBeenCalledTimes(4);
  });

  test("does not touch the login limiter", async () => {
    await addRole("r1", "sekret");
    const v = createPassthroughKeyVerifier(db, { now });
    for (let i = 0; i < 10; i++) await v(encodePassthroughKey("r1", "nope"), "10.9.9.9");
    expect(checkRateLimit("10.9.9.9")).toBe(true);
  });
});

describe("login limiter", () => {
  test("one shared state: the re-export from api/auth is the same function", () => {
    expect(resetFromAuth).toBe(resetFromLimiter);
    for (let i = 0; i < 5; i++) recordFailure("203.0.113.9");
    expect(checkRateLimit("203.0.113.9")).toBe(false);
    resetFromAuth();
    expect(checkRateLimit("203.0.113.9")).toBe(true);
  });
});

describe("bearer verifier called directly", () => {
  const SECRET = "verifier-direct-jwt-secret";
  const sign = (claims: Record<string, unknown>) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("gatehouse")
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(new TextEncoder().encode(SECRET));

  test("root token, JWT, and totp-pending token", async () => {
    process.env.GATEHOUSE_ROOT_TOKEN = "direct-root-token";
    try {
      const verify = createBearerVerifier({ jwtSecret: SECRET });
      expect(await verify("direct-root-token", "1.1.1.1")).toEqual({
        ok: true,
        auth: { identity: "root", policies: ["admin"], source: "root" },
      });
      const jwt = await sign({ sub: "approle:x", role_id: "r1", policies: ["p"] });
      expect(await verify(jwt, "1.1.1.1")).toEqual({
        ok: true,
        auth: { identity: "approle:x", policies: ["p"], source: "approle", role_id: "r1" },
      });
      const pending = await sign({ sub: "user:alice", purpose: "totp-pending" });
      expect(await verify(pending, "1.1.1.1")).toEqual({ ok: false, status: 401, error: "TOTP verification required" });
    } finally {
      delete process.env.GATEHOUSE_ROOT_TOKEN;
    }
  });
});
