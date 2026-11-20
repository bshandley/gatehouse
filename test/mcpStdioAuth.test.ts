import { test, expect, describe } from "bun:test";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { SignJWT } from "jose";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { PolicyEngine } from "../src/policy/engine";

const ROOT = join(import.meta.dir, "..");
const KEY = "ab".repeat(32);
const JWT_SECRET = "stdio-test-jwt-secret";

async function jwt(claims: Record<string, unknown>, secret = JWT_SECRET, exp = "1h") {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("gatehouse")
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(new TextEncoder().encode(secret));
}

/** Seed a vault with one secret and one policy that exists only in the database. */
function seed(): string {
  const dir = mkdtempSync(join(tmpdir(), "gh-stdio-auth-"));
  const db = initDB(dir);
  new SecretsEngine(db, Buffer.from(KEY, "hex")).put("api-keys/example", "s3cret-value-123", {});
  new PolicyEngine(dir, db).savePolicy("ui-made-reader", [{ path: "api-keys/*", capabilities: ["read"] }]);
  db.query("INSERT INTO users (username, display_name, password_hash, role, enabled) VALUES ('alice', 'Alice', 'x', 'admin', 1)").run();
  db.query("INSERT INTO users (username, display_name, password_hash, role, enabled) VALUES ('gone', 'Gone', 'x', 'admin', 0)").run();
  db.close();
  return dir;
}

async function run(dir: string, extraEnv: Record<string, string>, requests: unknown[] = [], argv: string[] = []) {
  const env: Record<string, string | undefined> = {
    ...process.env,
    GATEHOUSE_DATA_DIR: dir,
    GATEHOUSE_CONFIG_DIR: dir,
    GATEHOUSE_MASTER_KEY: KEY,
    GATEHOUSE_JWT_SECRET: JWT_SECRET,
    ...extraEnv,
  };
  for (const k of ["GATEHOUSE_TOKEN", "GATEHOUSE_ROOT_TOKEN", "GATEHOUSE_IDENTITY", "GATEHOUSE_POLICIES"]) {
    if (!(k in extraEnv)) delete env[k];
  }
  const proc = Bun.spawn(["bun", "run", "src/mcp-stdio.ts", ...argv], { cwd: ROOT, env, stdin: "pipe", stdout: "pipe", stderr: "pipe" });
  for (const r of requests) proc.stdin.write(JSON.stringify(r) + "\n");
  proc.stdin.end();
  const code = await proc.exited;
  const stdout = await new Response(proc.stdout as ReadableStream).text();
  const stderr = await new Response(proc.stderr as ReadableStream).text();
  const responses = stdout.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  return { code, stderr, stdout, responses };
}

const getSecret = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "gatehouse_get", arguments: { path: "api-keys/example" } } };
const textOf = (r: any) => JSON.stringify(r?.result ?? r?.error ?? r);

describe("stdio MCP identity", () => {
  test("a token that is neither the root token nor a valid JWT is refused, and nothing is served", async () => {
    const dir = seed();
    try {
      const r = await run(dir, { GATEHOUSE_TOKEN: "not-a-real-token" }, [getSecret]);
      expect(r.code).toBe(1);
      expect(r.stderr).toContain("GATEHOUSE_TOKEN was rejected");
      expect(r.stdout).toBe("");
      expect(r.stderr).not.toContain("not-a-real-token");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test("a JWT signed with the wrong secret is refused", async () => {
    const dir = seed();
    try {
      const t = await jwt({ sub: "user:alice", policies: ["admin"] }, "some-other-secret");
      const r = await run(dir, { GATEHOUSE_TOKEN: t }, [getSecret]);
      expect(r.code).toBe(1);
      expect(r.stdout).toBe("");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test("an expired JWT, a TOTP pre-auth JWT, and a disabled user's JWT are refused", async () => {
    const dir = seed();
    try {
      const expired = await jwt({ sub: "user:alice", policies: ["admin"] }, JWT_SECRET, "-1h");
      const pre = await jwt({ sub: "user:alice", purpose: "totp-pending" });
      const disabled = await jwt({ sub: "user:gone", policies: ["admin"] });
      for (const t of [expired, pre, disabled]) {
        const r = await run(dir, { GATEHOUSE_TOKEN: t }, [getSecret]);
        expect(r.code).toBe(1);
        expect(r.stdout).toBe("");
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test("a valid JWT runs as its own identity and policies, not GATEHOUSE_POLICIES", async () => {
    const dir = seed();
    try {
      const t = await jwt({ sub: "approle:reader", role_id: "r1", policies: ["no-such-policy"] });
      const r = await run(dir, { GATEHOUSE_TOKEN: t, GATEHOUSE_POLICIES: "admin", GATEHOUSE_IDENTITY: "someone-else" }, [getSecret]);
      expect(r.code).toBe(0);
      expect(r.stderr).toContain('identity="approle:reader"');
      expect(textOf(r.responses[0])).not.toContain("s3cret-value-123");
      expect(textOf(r.responses[0]).toLowerCase()).toContain("denied");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test("a valid JWT whose policy exists only in the database can use it", async () => {
    const dir = seed();
    try {
      const t = await jwt({ sub: "approle:reader", role_id: "r1", policies: ["ui-made-reader"] });
      const r = await run(dir, { GATEHOUSE_TOKEN: t }, [getSecret]);
      expect(r.code).toBe(0);
      expect(textOf(r.responses[0])).toContain("s3cret-value-123");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test("stdout carries only JSON-RPC responses: audit and policy log lines go to stderr", async () => {
    const dir = seed();
    try {
      const t = await jwt({ sub: "approle:reader", role_id: "r1", policies: ["ui-made-reader"] });
      const r = await run(dir, { GATEHOUSE_TOKEN: t }, [getSecret, { ...getSecret, id: 2 }]);
      expect(r.responses.length).toBe(2);
      for (const res of r.responses) expect(res.jsonrpc).toBe("2.0");
      expect(r.responses.map((x: any) => x.id)).toEqual([1, 2]);
      expect(r.stderr).toContain("secret.read.mcp");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test("the root token runs as root", async () => {
    const dir = seed();
    try {
      const r = await run(dir, { GATEHOUSE_TOKEN: "root-token-for-this-test", GATEHOUSE_ROOT_TOKEN: "root-token-for-this-test" }, [getSecret]);
      expect(r.code).toBe(0);
      expect(r.stderr).toContain('identity="root"');
      expect(textOf(r.responses[0])).toContain("s3cret-value-123");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test("a token passed as the first argument is verified the same way", async () => {
    const dir = seed();
    try {
      const r = await run(dir, {}, [getSecret], ["not-a-real-token"]);
      expect(r.code).toBe(1);
      expect(r.stdout).toBe("");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test("with no token and no GATEHOUSE_POLICIES it refuses to start: admin is never a default", async () => {
    const dir = seed();
    try {
      for (const extra of [{}, { GATEHOUSE_POLICIES: "" }, { GATEHOUSE_POLICIES: " , " }, { GATEHOUSE_IDENTITY: "local-dev" }]) {
        const r = await run(dir, extra as Record<string, string>, [getSecret]);
        expect(r.code).toBe(1);
        expect(r.stdout).toBe("");
        expect(r.stderr).toContain("GATEHOUSE_POLICIES");
        expect(r.stderr).not.toContain("s3cret-value-123");
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test("with no token, explicit GATEHOUSE_POLICIES apply, scoped or admin", async () => {
    const dir = seed();
    try {
      const scoped = await run(dir, { GATEHOUSE_IDENTITY: "local-dev", GATEHOUSE_POLICIES: "ui-made-reader" }, [getSecret]);
      expect(scoped.code).toBe(0);
      expect(scoped.stderr).toContain('identity="local-dev"');
      expect(scoped.stderr).toContain("ui-made-reader");
      expect(textOf(scoped.responses[0])).toContain("s3cret-value-123");
      const none = await run(dir, { GATEHOUSE_POLICIES: "no-such-policy" }, [getSecret]);
      expect(none.code).toBe(0);
      expect(textOf(none.responses[0])).not.toContain("s3cret-value-123");
      expect(none.stderr).toContain("no such policy: no-such-policy");
      expect(scoped.stderr).not.toContain("no such policy");
      const admin = await run(dir, { GATEHOUSE_POLICIES: "admin" }, [getSecret]);
      expect(admin.code).toBe(0);
      expect(admin.stderr).toContain('identity="mcp-agent"');
      expect(textOf(admin.responses[0])).toContain("s3cret-value-123");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe("stdio MCP proxy gates", () => {
  /** A vault whose only proxyable secret is approval-gated. */
  function seedGated(): string {
    const dir = mkdtempSync(join(tmpdir(), "gh-stdio-gates-"));
    const db = initDB(dir);
    new SecretsEngine(db, Buffer.from(KEY, "hex")).put("api-keys/example", "sk-example-value-123", { requires_approval: "true" });
    new PolicyEngine(dir, db).savePolicy("proxy-agent", [{ path: "api-keys/*", capabilities: ["proxy"] }]);
    db.close();
    return dir;
  }

  test("an approval-gated secret is gated over stdio, not refused as gates_unavailable", async () => {
    const dir = seedGated();
    try {
      const call = {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "gatehouse_proxy", arguments: { method: "GET", url: "https://api.example.com/v1", auto_inject: ["api-keys/example"] } },
      };
      const r = await run(dir, { GATEHOUSE_IDENTITY: "local-dev", GATEHOUSE_POLICIES: "proxy-agent" }, [call]);
      expect(r.code).toBe(0);
      const text = textOf(r.responses[0]);
      expect(text).not.toContain("gates are unavailable");
      expect(text).toContain("requires_approval");
      expect(text).not.toContain("sk-example-value-123");
      const db = initDB(dir);
      const reasons = (db.query("SELECT action, metadata FROM audit_log WHERE action LIKE 'proxy.%'").all() as any[]).map(
        (row) => `${row.action}:${JSON.parse(row.metadata ?? "{}").reason ?? ""}`
      );
      db.close();
      expect(reasons.some((x) => x.endsWith(":gates_unavailable"))).toBe(false);
      expect(reasons.some((x) => x.startsWith("proxy.blocked."))).toBe(true);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
