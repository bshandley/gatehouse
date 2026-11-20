import { describe, test, expect, beforeEach, afterEach, beforeAll, afterAll } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { SignJWT } from "jose";
import { gzipSync } from "node:zlib";
import { mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { PolicyEngine } from "../src/policy/engine";
import { AuditLog } from "../src/audit/logger";
import { LeaseManager } from "../src/lease/manager";
import { RateLimiter } from "../src/rateLimits/limiter";
import { PatternEngine } from "../src/patterns/engine";
import { statsRouter } from "../src/api/stats";
import { passthroughRouter } from "../src/api/passthrough";
import { parseMaxBodySize } from "../src/http/middleware";
import { encodePassthroughKey, _resetPassthroughKeyCacheForTests } from "../src/proxy/passthroughKey";
import { setProxyLimits, _resetProxyLimitsCacheForTests } from "../src/settings/proxyLimits";
import type { GatehouseConfig } from "../src/config";

// ------------------------------------------------------------------ fixtures

const SECRET = "sk-example-real-secret-0123456789";
const SECRET_B64 = btoa(SECRET);
/** The scrubber holds back (longest redact value - 1) bytes; the base64 form is the longest. */
const HOLD_BACK = SECRET_B64.length - 1;
const ROLE = "role-pt";
const SID = "sid-example-0001";
const KEY = encodePassthroughKey(ROLE, SID);
const NOPROXY_KEY = encodePassthroughKey("role-noproxy", "sid-example-0002");
const BAD_KEY = encodePassthroughKey(ROLE, "sid-wrong-9999");
const JWT_SECRET = "test-jwt-secret-for-passthrough-0123456789";
const IP = "192.0.2.10";

interface Seen {
  method: string;
  url: URL;
  headers: Headers;
  body: Uint8Array;
}

type Handler = (req: Request, seen: Seen) => Response | Promise<Response>;

let upstream: ReturnType<typeof Bun.serve>;
let upstreamBase: string;
let handler: Handler;
let seen: Seen[] = [];

beforeAll(() => {
  upstream = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    idleTimeout: 0,
    async fetch(req) {
      const s: Seen = {
        method: req.method,
        url: new URL(req.url),
        headers: new Headers(req.headers),
        body: new Uint8Array(await req.arrayBuffer()),
      };
      seen.push(s);
      return handler(req, s);
    },
  });
  upstreamBase = `http://127.0.0.1:${upstream.port}`;
});

afterAll(() => {
  upstream.stop(true);
});

const enc = new TextEncoder();
const dec = new TextDecoder();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface AuditRow {
  identity: string;
  action: string;
  path: string | null;
  lease_id: string | null;
  source_ip: string | null;
  metadata: Record<string, string>;
  success: number;
}

describe("passthrough route /p/<alias>", () => {
  let dir: string;
  let db: Database;
  let secrets: SecretsEngine;
  let policies: PolicyEngine;
  let audit: AuditLog;
  let leases: LeaseManager;
  let rateLimiter: RateLimiter;
  let patterns: PatternEngine;
  let app: Hono;
  let config: GatehouseConfig;
  const prevAllowPrivate = process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE;

  function rows(): AuditRow[] {
    return (db.query("SELECT * FROM audit_log WHERE action LIKE 'proxy.%' ORDER BY id").all() as any[]).map((r) => ({
      ...r,
      metadata: r.metadata ? JSON.parse(r.metadata) : {},
    }));
  }

  function forwardRows(): AuditRow[] {
    return rows().filter((r) => r.action === "proxy.forward");
  }

  async function addRole(roleId: string, secretId: string, extra: { policies?: string[]; allow?: string[] } = {}) {
    db.query(
      "INSERT INTO app_roles (role_id, secret_hash, display_name, policies, ip_allowlist) VALUES (?, ?, ?, ?, ?)"
    ).run(
      roleId,
      await Bun.password.hash(secretId),
      "agent-" + roleId,
      JSON.stringify(extra.policies ?? ["pt-agent"]),
      extra.allow ? JSON.stringify(extra.allow) : null
    );
  }

  function setAlias(meta: Record<string, string> = {}, value = SECRET, path = "api-keys/example") {
    secrets.put(path, value, {
      passthrough_alias: "example",
      upstream_url: `${upstreamBase}/base`,
      ...meta,
    });
  }

  async function jwt(claims: Record<string, unknown> = { policies: ["pt-agent"], role_id: ROLE }) {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("gatehouse")
      .setSubject("approle:jwt-agent")
      .setExpirationTime("1h")
      .sign(enc.encode(JWT_SECRET));
  }

  function req(path: string, init: RequestInit & { ip?: string } = {}) {
    const headers = new Headers(init.headers);
    headers.set("x-test-ip", init.ip ?? IP);
    return app.request(path, { ...init, headers });
  }

  function withKey(extra: Record<string, string> = {}, key = KEY): Record<string, string> {
    return { Authorization: `Bearer ${key}`, ...extra };
  }

  async function expectGatehouseError(res: Response, status: number, code: string) {
    expect(res.status).toBe(status);
    expect(res.headers.get("x-gatehouse-error")).toBe("1");
    const body = (await res.json()) as any;
    expect(body.code).toBe(code);
    expect(typeof body.error).toBe("string");
    expect(body.request_id).toBe("req-test");
    return body;
  }

  beforeEach(async () => {
    delete process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE;
    _resetPassthroughKeyCacheForTests();
    _resetProxyLimitsCacheForTests();
    seen = [];
    handler = () => new Response("ok", { headers: { "content-type": "text/plain" } });

    dir = mkdtempSync(join(tmpdir(), "gatehouse-passthrough-"));
    mkdirSync(join(dir, "config", "policies"), { recursive: true });
    db = initDB(dir);
    secrets = new SecretsEngine(db, Buffer.from("e".repeat(64), "hex"));
    policies = new PolicyEngine(join(dir, "config"), db);
    audit = new AuditLog(db);
    leases = new LeaseManager(db, secrets, audit);
    rateLimiter = new RateLimiter();
    patterns = new PatternEngine(db);

    policies.savePolicy("pt-agent", [{ paths: ["api-keys/*"], capabilities: ["proxy"] }]);
    policies.savePolicy("reader", [{ paths: ["api-keys/*"], capabilities: ["read"] }]);
    await addRole(ROLE, SID);
    await addRole("role-noproxy", "sid-example-0002", { policies: ["reader"] });
    setAlias();

    config = {
      port: 0,
      dataDir: dir,
      configDir: join(dir, "config"),
      masterKey: Buffer.from("e".repeat(64), "hex"),
      masterKeySource: "env",
      jwtSecret: JWT_SECRET,
    };

    app = buildApp();
  });

  function buildApp(): Hono {
    const app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "req-test");
      c.set("sourceIp", c.req.header("x-test-ip") || IP);
      await next();
    });
    app.use("/v1/*", async (c, next) => {
      c.set("auth", { identity: "root", policies: ["admin"], source: "root" });
      await next();
    });
    app.route("/v1/stats", statsRouter(audit, secrets, policies));
    app.route("/p", passthroughRouter({ secrets, policies, audit, db, rateLimiter, leases, patterns, config }));
    return app;
  }

  afterEach(() => {
    leases.stopReaper();
    db.close();
    rmSync(dir, { recursive: true, force: true });
    _resetProxyLimitsCacheForTests();
    if (prevAllowPrivate === undefined) delete process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE;
    else process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE = prevAllowPrivate;
  });

  // ------------------------------------------------------------ authentication

  describe("authentication", () => {
    test("passthrough key in Authorization: Bearer", async () => {
      const res = await req("/p/example/v1/models", { headers: withKey() });
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
      // A complete stream is a success row.
      expect(forwardRows().at(-1)!.success).toBe(1);
      expect(seen[0].headers.get("authorization")).toBe(`Bearer ${SECRET}`);
    });

    test("passthrough key in x-api-key", async () => {
      const res = await req("/p/example/v1/models", { headers: { "x-api-key": KEY } });
      expect(res.status).toBe(200);
      expect(seen[0].headers.get("authorization")).toBe(`Bearer ${SECRET}`);
      expect(seen[0].headers.get("x-api-key")).toBeNull();
    });

    test("passthrough key in the secret's own injection header", async () => {
      setAlias({ header_name: "X-Example-Key", auth_scheme: "" });
      const res = await req("/p/example/v1/models", { headers: { "X-Example-Key": KEY } });
      expect(res.status).toBe(200);
      expect(seen[0].headers.get("x-example-key")).toBe(SECRET);
    });

    test("passthrough key as the Basic password when the secret uses Basic", async () => {
      setAlias({ auth_scheme: "Basic" }, "user:pass-example-1234");
      const res = await req("/p/example/v1/models", {
        headers: { Authorization: "Basic " + btoa(`anyone:${KEY}`) },
      });
      expect(res.status).toBe(200);
      expect(seen[0].headers.get("authorization")).toBe("Basic " + btoa("user:pass-example-1234"));
    });

    test("Gatehouse JWT as the bearer credential", async () => {
      const token = await jwt();
      const res = await req("/p/example/v1/models", { headers: { Authorization: `Bearer ${token}` } });
      expect(res.status).toBe(200);
      await res.text();
      for (const [, v] of seen[0].headers) expect(v).not.toContain(token);
      expect(forwardRows().at(-1)!.identity).toBe("approle:jwt-agent");
    });

    test("every candidate is tried in order: a bad header credential does not mask a good x-api-key", async () => {
      const res = await req("/p/example/v1/models", {
        headers: { Authorization: "Bearer not-a-real-token", "x-api-key": KEY },
      });
      expect(res.status).toBe(200);
    });

    test("wrong key is 401 unauthenticated with an audit row, nothing forwarded", async () => {
      const res = await req("/p/example/v1/models", { headers: withKey({}, BAD_KEY) });
      await expectGatehouseError(res, 401, "unauthenticated");
      expect(seen).toHaveLength(0);
      const r = forwardRows();
      expect(r).toHaveLength(1);
      expect(r[0].success).toBe(0);
      expect(r[0].identity).toBe("anonymous");
      expect(r[0].metadata).toMatchObject({ mode: "passthrough", alias: "example", reason: "unauthenticated" });
    });

    test("unknown alias: 401 with no credential, 404 unknown_alias with a valid one", async () => {
      await expectGatehouseError(await req("/p/nosuch/v1/models"), 401, "unauthenticated");
      await expectGatehouseError(await req("/p/nosuch/v1/models", { headers: withKey() }), 404, "unknown_alias");
      // With no credential, an existing alias is indistinguishable.
      await expectGatehouseError(await req("/p/example/v1/models"), 401, "unauthenticated");
      expect(seen).toHaveLength(0);
      const r = forwardRows();
      expect(r.map((x) => x.metadata.reason)).toEqual(["unauthenticated", "unknown_alias", "unauthenticated"]);
      expect(r[1].identity).toBe("approle:agent-role-pt");
    });

    test("403 forbidden without proxy capability, with the policy_denied row", async () => {
      const res = await req("/p/example/v1/models", { headers: withKey({}, NOPROXY_KEY) });
      await expectGatehouseError(res, 403, "forbidden");
      expect(seen).toHaveLength(0);
      const [row] = forwardRows();
      expect(row.success).toBe(0);
      expect(row.path).toBe("api-keys/example");
      expect(row.metadata).toMatchObject({ mode: "passthrough", alias: "example", reason: "policy_denied" });
    });

    test("five bad credentials, then the sixth request is 429 rate_limited even with a good key", async () => {
      for (let i = 0; i < 5; i++) {
        expect((await req("/p/example/v1/models", { headers: withKey({}, BAD_KEY) })).status).toBe(401);
      }
      const res = await req("/p/example/v1/models", { headers: withKey() });
      await expectGatehouseError(res, 429, "rate_limited");
      expect(Number(res.headers.get("retry-after"))).toBeGreaterThan(0);
      expect(seen).toHaveLength(0);
      // Another IP is not affected.
      expect((await req("/p/example/v1/models", { headers: withKey(), ip: "192.0.2.11" })).status).toBe(200);
    });

    test("anonymous junk requests to a nonexistent alias never lock out a valid key", async () => {
      for (let i = 0; i < 8; i++) {
        await expectGatehouseError(await req("/p/nosuch/v1/models"), 401, "unauthenticated");
      }
      for (let i = 0; i < 8; i++) {
        await expectGatehouseError(
          await req("/p/nosuch/v1/models", { headers: { Authorization: "Bearer junk-not-a-token" } }),
          401,
          "unauthenticated"
        );
      }
      expect((await req("/p/example/v1/models", { headers: withKey() })).status).toBe(200);
    });

    test("a valid JWT works while the IP is locked out for bad keys", async () => {
      for (let i = 0; i < 5; i++) {
        expect((await req("/p/example/v1/models", { headers: withKey({}, BAD_KEY) })).status).toBe(401);
      }
      await expectGatehouseError(await req("/p/example/v1/models", { headers: withKey() }), 429, "rate_limited");
      const token = await jwt();
      const res = await req("/p/example/v1/models", { headers: { Authorization: `Bearer ${token}` } });
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });

    test("a JWT tried ahead of a key during a lockout still authenticates", async () => {
      for (let i = 0; i < 5; i++) {
        expect((await req("/p/example/v1/models", { headers: withKey({}, BAD_KEY) })).status).toBe(401);
      }
      const token = await jwt();
      const res = await req("/p/example/v1/models", { headers: { Authorization: `Bearer ${token}`, "x-api-key": KEY } });
      expect(res.status).toBe(200);
      // A failed JWT ahead of the key: the key is then refused by the limiter.
      const res2 = await req("/p/example/v1/models", { headers: { Authorization: "Bearer junk-not-a-token", "x-api-key": KEY } });
      await expectGatehouseError(res2, 429, "rate_limited");
    });

    test("successes never count against the login limiter", async () => {
      for (let i = 0; i < 8; i++) {
        expect((await req("/p/example/v1/models", { headers: withKey() })).status).toBe(200);
      }
    });

    test("a rotated secret_id revokes the key on the next request", async () => {
      expect((await req("/p/example/v1/models", { headers: withKey() })).status).toBe(200);
      db.query("UPDATE app_roles SET secret_hash = ? WHERE role_id = ?").run(
        await Bun.password.hash("sid-example-rotated"),
        ROLE
      );
      await expectGatehouseError(await req("/p/example/v1/models", { headers: withKey() }), 401, "unauthenticated");
      const rotated = encodePassthroughKey(ROLE, "sid-example-rotated");
      expect((await req("/p/example/v1/models", { headers: withKey({}, rotated) })).status).toBe(200);
    });

    test("a suspended role is 403 forbidden and counts as a failure", async () => {
      db.query("UPDATE app_roles SET suspended = 1 WHERE role_id = ?").run(ROLE);
      for (let i = 0; i < 5; i++) {
        await expectGatehouseError(await req("/p/example/v1/models", { headers: withKey() }), 403, "forbidden");
      }
      await expectGatehouseError(await req("/p/example/v1/models", { headers: withKey() }), 429, "rate_limited");
      expect(seen).toHaveLength(0);
      expect(forwardRows()[0].metadata.reason).toBe("forbidden");
    });

    test("the AppRole IP allowlist applies", async () => {
      db.query("UPDATE app_roles SET ip_allowlist = ? WHERE role_id = ?").run(JSON.stringify(["198.51.100.0/24"]), ROLE);
      await expectGatehouseError(await req("/p/example/v1/models", { headers: withKey() }), 403, "forbidden");
      expect((await req("/p/example/v1/models", { headers: withKey(), ip: "198.51.100.7" })).status).toBe(200);
    });
  });

  // ---------------------------------------------------------------- forwarding

  describe("forwarding", () => {
    test("upstream gets the real secret and never a caller credential in any header", async () => {
      const token = await jwt();
      const res = await req("/p/example/v1/models", {
        headers: {
          Authorization: `Bearer ${KEY}`,
          "x-api-key": token,
          "X-Custom": "kept",
        },
      });
      expect(res.status).toBe(200);
      const h = seen[0].headers;
      expect(h.get("authorization")).toBe(`Bearer ${SECRET}`);
      expect(h.get("x-custom")).toBe("kept");
      for (const [, v] of h) {
        expect(v).not.toContain(KEY);
        expect(v).not.toContain(token);
        expect(v).not.toContain(SID);
      }
    });

    test("binary request and response bodies are byte-identical", async () => {
      const payload = new Uint8Array(4096);
      for (let i = 0; i < payload.length; i++) payload[i] = (i * 31 + 7) & 0xff;
      handler = (_r, s) => new Response(s.body, { headers: { "content-type": "application/octet-stream" } });
      const res = await req("/p/example/upload", {
        method: "POST",
        headers: withKey({ "content-type": "application/octet-stream" }),
        body: payload,
      });
      expect(res.status).toBe(200);
      expect(seen[0].body).toEqual(payload);
      expect(new Uint8Array(await res.arrayBuffer())).toEqual(payload);
    });

    test("query string preserved; upstream_url path prefix joined", async () => {
      const res = await req("/p/example/v1/models?limit=2&x=a%20b", { headers: withKey() });
      expect(res.status).toBe(200);
      expect(seen[0].url.pathname).toBe("/base/v1/models");
      expect(seen[0].url.search).toBe("?limit=2&x=a%20b");
    });

    test("Anthropic-style secret: x-api-key with no scheme", async () => {
      setAlias({ header_name: "x-api-key", auth_scheme: "" });
      const res = await req("/p/example/v1/messages", {
        method: "POST",
        headers: { "x-api-key": KEY, "content-type": "application/json" },
        body: JSON.stringify({ model: "m" }),
      });
      expect(res.status).toBe(200);
      expect(seen[0].headers.get("x-api-key")).toBe(SECRET);
      expect(seen[0].headers.get("authorization")).toBeNull();
      expect(dec.decode(seen[0].body)).toBe('{"model":"m"}');
    });

    test("Basic secret is base64-encoded", async () => {
      setAlias({ auth_scheme: "Basic" }, "user:pass-example-1234");
      expect((await req("/p/example/x", { headers: withKey() })).status).toBe(200);
      expect(seen[0].headers.get("authorization")).toBe("Basic " + btoa("user:pass-example-1234"));
    });

    test("Range and If-Range never reach the upstream", async () => {
      handler = () => new Response("whole body");
      const res = await req("/p/example/file", { headers: withKey({ Range: "bytes=0-3", "If-Range": '"e1"' }) });
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("whole body");
      expect(seen[0].headers.get("range")).toBeNull();
      expect(seen[0].headers.get("if-range")).toBeNull();
    });

    test("the caller's Accept-Encoding is replaced by one the fetch can decode", async () => {
      await req("/p/example/x", { headers: withKey({ "Accept-Encoding": "compress" }) });
      expect(seen[0].headers.get("accept-encoding")).not.toContain("compress");
    });

    test("gzip upstream: body arrives decoded with no Content-Encoding", async () => {
      handler = () =>
        new Response(gzipSync(Buffer.from("decoded payload " + "z".repeat(200))), {
          headers: { "content-encoding": "gzip", "content-type": "text/plain" },
        });
      const res = await req("/p/example/x", { headers: withKey() });
      expect(res.status).toBe(200);
      expect(res.headers.get("content-encoding")).toBeNull();
      expect(await res.text()).toBe("decoded payload " + "z".repeat(200));
    });

    test("an upstream error passes through without X-Gatehouse-Error, even if the upstream sets it", async () => {
      handler = () => new Response('{"error":"boom"}', { status: 500, headers: { "x-gatehouse-error": "1" } });
      const res = await req("/p/example/x", { headers: withKey() });
      expect(res.status).toBe(500);
      expect(res.headers.get("x-gatehouse-error")).toBeNull();
      expect(await res.text()).toBe('{"error":"boom"}');
      const row = forwardRows().at(-1)!;
      expect(row.metadata.status).toBe("500");
    });

    test("upstream content carries Content-Security-Policy: sandbox, replacing the upstream's own", async () => {
      handler = () =>
        new Response("<script>alert(1)</script>", {
          headers: { "content-type": "text/html", "content-security-policy": "default-src *" },
        });
      const res = await req("/p/example/page", { headers: withKey() });
      expect(res.status).toBe(200);
      expect(res.headers.get("content-security-policy")).toBe("sandbox");
      await res.text();
      handler = () => new Response("nope", { status: 404 });
      const err = await req("/p/example/missing", { headers: withKey() });
      expect(err.headers.get("content-security-policy")).toBe("sandbox");
      await err.text();
      handler = () => new Response(null, { status: 302, headers: { location: "/base/next" } });
      const redir = await req("/p/example/start", { headers: withKey() });
      expect(redir.headers.get("content-security-policy")).toBe("sandbox");
    });

    test("405 for a method passthrough does not forward", async () => {
      const res = await req("/p/example/x", { method: "PROPFIND", headers: withKey() });
      expect(res.status).toBe(405);
      expect(res.headers.get("x-gatehouse-error")).toBe("1");
      expect(seen).toHaveLength(0);
    });
  });

  // --------------------------------------------------------------- D7 codes

  describe("Gatehouse-originated errors", () => {
    test("rate_limited from the per-secret limit carries Retry-After and the gate row", async () => {
      setAlias({ rate_limit_per_minute: "1" });
      expect((await req("/p/example/x", { headers: withKey() })).status).toBe(200);
      const res = await req("/p/example/x", { headers: withKey() });
      await expectGatehouseError(res, 429, "rate_limited");
      expect(Number(res.headers.get("retry-after"))).toBeGreaterThan(0);
      expect(seen).toHaveLength(1);
      const gate = rows().find((r) => r.action === "proxy.blocked.rate_limit")!;
      expect(gate.metadata).toMatchObject({ mode: "passthrough", alias: "example", limit_kind: "secret_minute" });
    });

    test("rate_limited from the per-AppRole limit counts passthrough calls", async () => {
      db.query("UPDATE app_roles SET rate_limit_per_minute = 2 WHERE role_id = ?").run(ROLE);
      expect((await req("/p/example/x", { headers: withKey() })).status).toBe(200);
      expect((await req("/p/example/x", { headers: withKey() })).status).toBe(200);
      const body = await expectGatehouseError(await req("/p/example/x", { headers: withKey() }), 429, "rate_limited");
      expect(body.limit_kind).toBe("approle_minute");
      expect(seen).toHaveLength(2);
    });

    test("approval_required carries the lease fields /v1/proxy returns", async () => {
      setAlias({ requires_approval: "true" });
      const body = await expectGatehouseError(await req("/p/example/x", { headers: withKey() }), 403, "approval_required");
      expect(body.requires_approval).toEqual(["api-keys/example"]);
      expect(typeof body.hint).toBe("string");
      expect(seen).toHaveLength(0);
      const row = rows().find((r) => r.action === "proxy.blocked.approval")!;
      expect(row.metadata).toMatchObject({ mode: "passthrough", alias: "example" });
    });

    test("path_not_allowed for a path outside allowed_path_prefixes", async () => {
      setAlias({ allowed_path_prefixes: "/base/v1/" });
      expect((await req("/p/example/v1/models", { headers: withKey() })).status).toBe(200);
      await expectGatehouseError(await req("/p/example/admin", { headers: withKey() }), 403, "path_not_allowed");
      expect(seen).toHaveLength(1);
      expect(forwardRows().at(-1)!.metadata).toMatchObject({ mode: "passthrough", reason: "path_prefix_blocked" });
    });

    test("private_network_blocked", async () => {
      setAlias({ allow_private: "false" });
      await expectGatehouseError(await req("/p/example/x", { headers: withKey() }), 403, "private_network_blocked");
      expect(seen).toHaveLength(0);
      expect(forwardRows().at(-1)!.metadata).toMatchObject({ mode: "passthrough", reason: "ssrf_blocked" });
    });

    test("domain allowlist mismatch is forbidden", async () => {
      setAlias({ allowed_domains: "api.example.com" });
      await expectGatehouseError(await req("/p/example/x", { headers: withKey() }), 403, "forbidden");
      expect(seen).toHaveLength(0);
      expect(forwardRows().at(-1)!.metadata).toMatchObject({ mode: "passthrough", reason: "domain_blocked" });
    });

    test("bad_path for an encoded slash", async () => {
      await expectGatehouseError(await req("/p/example/a%2fb", { headers: withKey() }), 400, "bad_path");
      expect(seen).toHaveLength(0);
      expect(forwardRows().at(-1)!.metadata).toMatchObject({ mode: "passthrough", alias: "example", reason: "bad_path" });
    });

    test("bad_path for a remainder over the length cap", async () => {
      await expectGatehouseError(await req("/p/example/" + "a".repeat(9000), { headers: withKey() }), 400, "bad_path");
      expect(seen).toHaveLength(0);
    });

    test("a secret that cannot be injected is denied with a row and nothing is forwarded", async () => {
      setAlias({ auth_scheme: "Basic" }, "user:päss-日本-example");
      await expectGatehouseError(await req("/p/example/x", { headers: withKey() }), 403, "forbidden");
      expect(seen).toHaveLength(0);
      expect(forwardRows().at(-1)!.metadata).toMatchObject({ mode: "passthrough", reason: "inject_failed" });
    });

    test("an invalid injection header name is a denial, not a 500", async () => {
      // Metadata written before validation existed: stored directly.
      setAlias({ header_name: "bad header", auth_scheme: "" });
      await expectGatehouseError(await req("/p/example/x", { headers: withKey() }), 403, "forbidden");
      expect(seen).toHaveLength(0);
      expect(forwardRows().at(-1)!.metadata.reason).toBe("inject_failed");
    });

    test("upstream_unreachable", async () => {
      const dead = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("") });
      const port = dead.port;
      dead.stop(true);
      secrets.put("api-keys/example", SECRET, { passthrough_alias: "example", upstream_url: `http://127.0.0.1:${port}` });
      await expectGatehouseError(await req("/p/example/x", { headers: withKey() }), 502, "upstream_unreachable");
      const row = forwardRows().at(-1)!;
      expect(row.success).toBe(0);
      expect(row.metadata).toMatchObject({ mode: "passthrough", reason: "upstream_unreachable" });
    });

    test("an upstream status outside 200 to 599 is 502 upstream_unreachable, one invalid_status row, body cancelled", async () => {
      // An HTTP server cannot answer 999, so the upstream is raw TCP. It sends
      // a chunked body that never ends; only a cancel closes the socket.
      let closed = false;
      const raw = Bun.listen({
        hostname: "127.0.0.1",
        port: 0,
        socket: {
          data(sock) {
            sock.write("HTTP/1.1 999 Odd\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n");
          },
          close() {
            closed = true;
          },
        },
      });
      try {
        secrets.put("api-keys/example", SECRET, { passthrough_alias: "example", upstream_url: `http://127.0.0.1:${raw.port}` });
        const res = await req("/p/example/x", { headers: withKey() });
        await expectGatehouseError(res, 502, "upstream_unreachable");
        const deadline = Date.now() + 3000;
        while (!closed && Date.now() < deadline) await sleep(20);
        expect(closed).toBe(true);
        const r = forwardRows();
        expect(r).toHaveLength(1);
        expect(r[0].success).toBe(0);
        expect(r[0].metadata).toMatchObject({ mode: "passthrough", alias: "example", reason: "invalid_status" });
      } finally {
        raw.stop(true);
      }
    });

    test("upstream_timeout when headers do not arrive within max_timeout_ms", async () => {
      setProxyLimits(db, audit, "root", null, { max_timeout_ms: 1000, max_body_bytes: 1024 * 1024 });
      handler = async () => {
        await sleep(1500);
        return new Response("late");
      };
      await expectGatehouseError(await req("/p/example/x", { headers: withKey() }), 504, "upstream_timeout");
      const row = forwardRows().at(-1)!;
      expect(row.success).toBe(0);
      expect(row.metadata).toMatchObject({ mode: "passthrough", reason: "upstream_timeout" });
    });

    test("413 for a chunked request body over the limit; the upstream sees no request", async () => {
      const total = 1048576 + 4096;
      let sent = 0;
      const body = new ReadableStream<Uint8Array>({
        pull(c) {
          if (sent >= total) return c.close();
          const n = Math.min(65536, total - sent);
          sent += n;
          c.enqueue(new Uint8Array(n));
        },
      });
      const res = await req("/p/example/upload", { method: "POST", headers: withKey(), body });
      await expectGatehouseError(res, 413, "body_too_large");
      expect(seen).toHaveLength(0);
      expect(forwardRows().at(-1)!.metadata.reason).toBe("body_too_large");
    });

    test("a malformed GATEHOUSE_MAX_BODY_SIZE falls back to 1048576, never to no cap", async () => {
      const prev = process.env.GATEHOUSE_MAX_BODY_SIZE;
      process.env.GATEHOUSE_MAX_BODY_SIZE = "lots";
      try {
        app = buildApp();
      } finally {
        if (prev === undefined) delete process.env.GATEHOUSE_MAX_BODY_SIZE;
        else process.env.GATEHOUSE_MAX_BODY_SIZE = prev;
      }
      const total = 1048576 + 4096;
      let sent = 0;
      const body = new ReadableStream<Uint8Array>({
        pull(c) {
          if (sent >= total) return c.close();
          const n = Math.min(65536, total - sent);
          sent += n;
          c.enqueue(new Uint8Array(n));
        },
      });
      await expectGatehouseError(
        await req("/p/example/upload", { method: "POST", headers: withKey(), body }),
        413,
        "body_too_large"
      );
      expect(seen).toHaveLength(0);
    });

    test("parseMaxBodySize accepts only positive integers", () => {
      expect(parseMaxBodySize(undefined)).toBe(1048576);
      expect(parseMaxBodySize("")).toBe(1048576);
      expect(parseMaxBodySize("lots")).toBe(1048576);
      expect(parseMaxBodySize("12abc")).toBe(1048576);
      expect(parseMaxBodySize("1.5")).toBe(1048576);
      expect(parseMaxBodySize("-5")).toBe(1048576);
      expect(parseMaxBodySize("0")).toBe(1048576);
      expect(parseMaxBodySize("1e9")).toBe(1048576);
      expect(parseMaxBodySize("99999999999999999999")).toBe(1048576);
      expect(parseMaxBodySize("2048")).toBe(2048);
      expect(parseMaxBodySize(" 4096\n")).toBe(4096);
    });

    test("413 for a declared Content-Length over the limit", async () => {
      const res = await req("/p/example/upload", {
        method: "POST",
        headers: withKey({ "content-length": String(2 * 1048576) }),
        body: new Uint8Array(10),
      });
      expect(res.status).toBe(413);
      expect(seen).toHaveLength(0);
    });
  });

  // ---------------------------------------------------------------- streaming

  describe("streaming", () => {
    test("SSE: the first event is readable before the upstream sends the second", async () => {
      let releaseSecond!: () => void;
      const second = new Promise<void>((r) => (releaseSecond = r));
      let secondSent = false;
      const first = "data: " + "a".repeat(HOLD_BACK * 4) + "\n\n";
      handler = () =>
        new Response(
          new ReadableStream({
            async start(c) {
              c.enqueue(enc.encode(first));
              await second;
              secondSent = true;
              c.enqueue(enc.encode("data: second\n\n"));
              c.close();
            },
          }),
          { headers: { "content-type": "text/event-stream" } }
        );
      const res = await req("/p/example/v1/stream", { headers: withKey() });
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/event-stream");
      const reader = res.body!.getReader();
      let text = "";
      // Everything except the fixed hold-back tail is readable now.
      const readable = first.slice(0, first.length - HOLD_BACK);
      while (!text.includes(readable)) {
        const r = await reader.read();
        if (r.done) throw new Error("ended early");
        text += dec.decode(r.value);
      }
      expect(secondSent).toBe(false);
      releaseSecond();
      for (;;) {
        const r = await reader.read();
        if (r.done) break;
        text += dec.decode(r.value);
      }
      expect(text).toBe(first + "data: second\n\n");
      expect(forwardRows()).toHaveLength(1);
    });

    test("a secret split across two upstream writes is redacted", async () => {
      handler = () =>
        new Response(
          new ReadableStream({
            async start(c) {
              c.enqueue(enc.encode("echo: " + SECRET.slice(0, 10)));
              await sleep(20);
              c.enqueue(enc.encode(SECRET.slice(10) + " end"));
              c.close();
            },
          })
        );
      const res = await req("/p/example/echo", { headers: withKey() });
      const text = await res.text();
      expect(text).toBe("echo: [REDACTED] end");
      const row = forwardRows().at(-1)!;
      expect(row.metadata.redaction_count).toBe("1");
    });

    test("byte cap cuts the stream and the row says byte_cap", async () => {
      setProxyLimits(db, audit, "root", null, { max_timeout_ms: 120000, max_body_bytes: 1024 });
      handler = () =>
        new Response(
          new ReadableStream({
            async start(c) {
              for (let i = 0; i < 8; i++) {
                c.enqueue(enc.encode("x".repeat(512)));
                await sleep(5);
              }
              c.close();
            },
          })
        );
      const res = await req("/p/example/big", { headers: withKey() });
      expect(res.status).toBe(200);
      const got = await res.arrayBuffer();
      // Cut at the cap, less the fixed hold-back that is dropped on a cut.
      expect(got.byteLength).toBe(1024 - HOLD_BACK);
      const row = forwardRows().at(-1)!;
      expect(row.metadata.reason).toBe("byte_cap");
      expect(row.metadata.status).toBe("200");
      expect(row.success).toBe(0);
      expect(Number(row.metadata.bytes_read_upstream)).toBeGreaterThan(1024);
      expect(row.metadata.dropped_bytes).toBe(String(HOLD_BACK));
    });

    test("idle timeout between chunks ends the stream with idle_timeout", async () => {
      setProxyLimits(db, audit, "root", null, { max_timeout_ms: 1000, max_body_bytes: 1024 * 1024 });
      handler = () =>
        new Response(
          new ReadableStream({
            async start(c) {
              c.enqueue(enc.encode("y".repeat(200)));
              await sleep(1800);
              try {
                c.enqueue(enc.encode("late"));
                c.close();
              } catch {}
            },
          })
        );
      const res = await req("/p/example/slow", { headers: withKey() });
      const text = await res.text();
      expect(text).toBe("y".repeat(200 - HOLD_BACK));
      expect(forwardRows().at(-1)!.metadata.reason).toBe("idle_timeout");
      expect(forwardRows().at(-1)!.success).toBe(0);
    });

    test("client abort mid-stream closes the upstream and writes exactly one row", async () => {
      let upstreamCancelled = false;
      handler = () =>
        new Response(
          new ReadableStream({
            async pull(c) {
              await sleep(10);
              c.enqueue(enc.encode("z".repeat(256)));
            },
            cancel() {
              upstreamCancelled = true;
            },
          })
        );
      const res = await req("/p/example/forever", { headers: withKey() });
      const reader = res.body!.getReader();
      await reader.read();
      await reader.cancel();
      const deadline = Date.now() + 3000;
      while (!upstreamCancelled && Date.now() < deadline) await sleep(20);
      expect(upstreamCancelled).toBe(true);
      await sleep(50);
      const r = forwardRows();
      expect(r).toHaveLength(1);
      expect(r[0].metadata.reason).toBe("client_abort");
      expect(r[0].metadata.status).toBe("200");
      expect(r[0].success).toBe(0);
    });
  });

  // ---------------------------------------------------------------- redirects

  describe("redirects", () => {
    test("same-origin Location is rewritten to /p/<alias>/... and scrubbed", async () => {
      handler = () => new Response(null, { status: 302, headers: { location: `/base/v1/next?x=1&t=${SECRET}` } });
      const res = await req("/p/example/v1/start", { headers: withKey() });
      expect(res.status).toBe(302);
      expect(res.headers.get("location")).toBe("/p/example/v1/next?x=1&t=[REDACTED]");
      await res.arrayBuffer();
      expect(forwardRows().at(-1)!.metadata.status).toBe("302");
    });

    test("cross-origin Location is 502 and the Location is not in the response", async () => {
      handler = () =>
        new Response("moved", { status: 302, headers: { location: "https://api.example.com/elsewhere" } });
      const res = await req("/p/example/v1/start", { headers: withKey() });
      expect(res.headers.get("location")).toBeNull();
      const body = await expectGatehouseError(res, 502, "upstream_redirect_cross_origin");
      expect(JSON.stringify(body)).not.toContain("api.example.com");
      const row = forwardRows().at(-1)!;
      expect(row.success).toBe(0);
      expect(row.metadata.reason).toBe("upstream_redirect_cross_origin");
      expect(JSON.stringify(row)).not.toContain("elsewhere");
    });
  });

  // ------------------------------------------------------ bodyless and paths

  describe("bodyless responses and alias paths", () => {
    test("HEAD: status and headers arrive, no body, one row", async () => {
      handler = () => new Response(null, { headers: { "x-upstream": "yes", "content-type": "text/plain" } });
      const res = await req("/p/example/x", { method: "HEAD", headers: withKey() });
      expect(res.status).toBe(200);
      expect(res.headers.get("x-upstream")).toBe("yes");
      expect((await res.arrayBuffer()).byteLength).toBe(0);
      expect(seen[0].method).toBe("HEAD");
      expect(forwardRows()).toHaveLength(1);
      expect(forwardRows()[0].metadata.method).toBe("HEAD");
    });

    for (const status of [204, 304]) {
      test(`${status}: status arrives, request completes, one row`, async () => {
        handler = () => new Response(null, { status, headers: { "x-upstream": "yes" } });
        const res = await req("/p/example/x", { headers: withKey() });
        expect(res.status).toBe(status);
        expect(res.headers.get("x-upstream")).toBe("yes");
        expect((await res.arrayBuffer()).byteLength).toBe(0);
        const r = forwardRows();
        expect(r).toHaveLength(1);
        expect(r[0].metadata.status).toBe(String(status));
      });
    }

    test("/p/alias forwards to upstream_url itself; /p/alias/ adds a slash", async () => {
      expect((await req("/p/example", { headers: withKey() })).status).toBe(200);
      expect((await req("/p/example/", { headers: withKey() })).status).toBe(200);
      expect(seen.map((s) => s.url.pathname)).toEqual(["/base", "/base/"]);
    });
  });

  // ---------------------------------------------------------------- audit

  describe("audit, patterns, posture", () => {
    test("row carries mode and alias, and no query string anywhere", async () => {
      const res = await req("/p/example/v1/models?q=zzz-query-marker", { headers: withKey() });
      expect(res.status).toBe(200);
      await res.text();
      const [row] = forwardRows();
      expect(row.success).toBe(1);
      expect(row.metadata).toMatchObject({
        mode: "passthrough",
        alias: "example",
        method: "GET",
        status: "200",
        target_path: "/base/v1/models",
        target_url: `${upstreamBase}/base/v1/models`,
        target_host: "127.0.0.1",
      });
      const everything = JSON.stringify(db.query("SELECT * FROM audit_log").all());
      expect(everything).not.toContain("zzz-query-marker");
      const pats = JSON.stringify(db.query("SELECT * FROM proxy_patterns").all());
      expect(pats).not.toContain("zzz-query-marker");
      expect(pats).toContain("/base/v1/models");
    });

    test("approval lease id is on the row", async () => {
      setAlias({ requires_approval: "true", auto_approve_from_ip: "192.0.2.0/24" });
      const res = await req("/p/example/x", { headers: withKey() });
      expect(res.status).toBe(200);
      await res.text();
      const row = forwardRows().at(-1)!;
      expect(row.lease_id).toBeTruthy();
      expect(row.metadata.lease_id).toBe(row.lease_id!);
    });

    test("redaction_count covers headers and body, and feeds /v1/stats posture", async () => {
      handler = () =>
        new Response(`a ${SECRET} b ${SECRET_B64} c`, { headers: { "x-echo": `k=${SECRET}` } });
      const res = await req("/p/example/x", { headers: withKey() });
      expect(res.headers.get("x-echo")).toBe("k=[REDACTED]");
      const text = await res.text();
      expect(text).toBe("a [REDACTED] b [REDACTED] c");
      expect(forwardRows().at(-1)!.metadata.redaction_count).toBe("3");
      const stats = (await (await req("/v1/stats/posture?window=1d")).json()) as any;
      expect(stats.redactions.count).toBe(3);
    });
  });
});
