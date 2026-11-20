import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { LeaseManager } from "../src/lease/manager";
import { PolicyEngine } from "../src/policy/engine";
import { AuditLog } from "../src/audit/logger";
import { RateLimiter } from "../src/rateLimits/limiter";
import { createMCPHandler } from "../src/mcp/server";
import { setProxyLimits, _resetProxyLimitsCacheForTests } from "../src/settings/proxyLimits";
import type { AuthContext } from "../src/auth/middleware";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

/**
 * The gatehouse_proxy MCP tool on the shared proxy pipeline. Pins the tool's
 * own error strings and audit rows, and covers the two behaviors the shared
 * code brings to the MCP path: an oversized upstream body counts once against
 * rate limits, and gated secrets are denied when the gate deps are missing.
 */

interface Row {
  action: string;
  path: string | null;
  lease_id: string | null;
  source_ip: string | null;
  metadata: Record<string, string>;
  success: number;
}

describe("gatehouse_proxy MCP tool on the pipeline", () => {
  let db: Database;
  let secrets: SecretsEngine;
  let policies: PolicyEngine;
  let audit: AuditLog;
  let leases: LeaseManager;
  let rateLimiter: RateLimiter;
  let dir: string;
  let savedFetch: typeof fetch;
  let fetchCalls: number;
  let upstreamBody: string;
  const prevAllowPrivate = process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE;

  const auth: AuthContext = {
    identity: "approle:mcp-agent",
    policies: ["proxy-agent"],
    source: "approle",
    role_id: "role-mcp",
  } as AuthContext;

  function full() {
    return createMCPHandler(secrets, leases, policies, audit, undefined, undefined, db, rateLimiter);
  }
  /** A handler built with db but no rate limiter: the fail-closed shape. */
  function stdioLike() {
    return createMCPHandler(secrets, leases, policies, audit, undefined, undefined, db);
  }

  function rows(): Row[] {
    return (
      db.query("SELECT action, path, lease_id, source_ip, metadata, success FROM audit_log ORDER BY id").all() as any[]
    ).map((r) => ({ ...r, metadata: JSON.parse(r.metadata) }));
  }
  function proxyRows(): Row[] {
    return rows().filter((r) => r.action.startsWith("proxy."));
  }

  beforeEach(() => {
    _resetProxyLimitsCacheForTests();
    delete process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE;
    dir = mkdtempSync(join(tmpdir(), "gatehouse-mcp-pipeline-"));
    mkdirSync(join(dir, "config", "policies"), { recursive: true });
    db = initDB(dir);
    secrets = new SecretsEngine(db, Buffer.from("e".repeat(64), "hex"));
    policies = new PolicyEngine(join(dir, "config"), db);
    audit = new AuditLog(db);
    leases = new LeaseManager(db, secrets, audit);
    rateLimiter = new RateLimiter();
    policies.savePolicy("proxy-agent", [
      { paths: ["api-keys/*"], capabilities: ["proxy"] },
      { paths: ["db/*"], capabilities: ["read"] },
    ]);
    secrets.put("api-keys/example", "sk-example-value-123");
    secrets.put("db/example", "postgres-example");
    expect(setProxyLimits(db, audit, "test", null, { max_timeout_ms: 30_000, max_body_bytes: 1024 }).ok).toBe(true);
    // Settings writes are audited; start each test with an empty log.
    db.run("DELETE FROM audit_log");

    savedFetch = globalThis.fetch;
    fetchCalls = 0;
    upstreamBody = JSON.stringify({ ok: true });
    globalThis.fetch = (async () => {
      fetchCalls++;
      return new Response(upstreamBody, { status: 200, headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = savedFetch;
    _resetProxyLimitsCacheForTests();
    leases.stopReaper();
    db.close();
    rmSync(dir, { recursive: true, force: true });
    if (prevAllowPrivate === undefined) delete process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE;
    else process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE = prevAllowPrivate;
  });

  describe("oversized upstream body", () => {
    test("returns the size error, writes one failure row with no reason or method, counts once", async () => {
      secrets.put("api-keys/example", "sk-example-value-123", { rate_limit_per_minute: "2" });
      upstreamBody = "x".repeat(4096);
      const r = await full().handleToolCall(
        "gatehouse_proxy",
        { method: "GET", url: "https://api.example.com/big", auto_inject: ["api-keys/example"] },
        auth,
        "127.0.0.1"
      );
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toBe("Upstream response exceeds 1024 bytes");

      const forward = proxyRows();
      expect(forward).toHaveLength(1);
      expect(forward[0].action).toBe("proxy.forward.mcp");
      expect(forward[0].path).toBe("api-keys/example");
      expect(forward[0].success).toBe(0);
      expect(forward[0].lease_id).toBeNull();
      expect(forward[0].metadata).toEqual({ target_url: "https://api.example.com/big", target_path: "/big" });

      // rate_limit_per_minute is 2: one attempted call leaves room for one more.
      expect(rateLimiter.checkSecret("api-keys/example", 2).allowed).toBe(true);
      expect(rateLimiter.checkSecret("api-keys/example", 1).allowed).toBe(false);
    });
  });

  describe("gates unavailable (handler built without a rate limiter)", () => {
    test("requires_approval secret is denied without reaching the upstream", async () => {
      secrets.put("api-keys/example", "sk-example-value-123", { requires_approval: "true" });
      const r = await stdioLike().handleToolCall(
        "gatehouse_proxy",
        { method: "GET", url: "https://api.example.com/v1", auto_inject: ["api-keys/example"] },
        auth,
        null
      );
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toBe('Proxy gates are unavailable for "api-keys/example"');
      expect(fetchCalls).toBe(0);
      const [row] = proxyRows();
      expect(row.action).toBe("proxy.forward.mcp");
      expect(row.path).toBe("api-keys/example");
      expect(row.success).toBe(0);
      expect(row.metadata).toEqual({ target_url: "https://api.example.com/v1", target_path: "/v1", reason: "gates_unavailable" });
    });

    test("rate_limit_per_minute secret is denied", async () => {
      secrets.put("api-keys/example", "sk-example-value-123", { rate_limit_per_minute: "5" });
      const r = await stdioLike().handleToolCall(
        "gatehouse_proxy",
        { method: "GET", url: "https://api.example.com/v1", auto_inject: ["api-keys/example"] },
        auth
      );
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toBe('Proxy gates are unavailable for "api-keys/example"');
      expect(fetchCalls).toBe(0);
    });

    test("ungated secret still proxies without a rate limiter", async () => {
      const r = await stdioLike().handleToolCall(
        "gatehouse_proxy",
        { method: "GET", url: "https://api.example.com/v1", auto_inject: ["api-keys/example"] },
        auth
      );
      expect(r.isError).toBeUndefined();
      expect(JSON.parse(r.content[0].text)).toEqual({ status: 200, body: { ok: true } });
      expect(fetchCalls).toBe(1);
    });
  });

  describe("preserved MCP behavior", () => {
    async function proxy(args: Record<string, unknown>) {
      return full().handleToolCall("gatehouse_proxy", args, auth, "127.0.0.1");
    }

    test("validation errors", async () => {
      expect((await proxy({ method: "GET" })).content[0].text).toBe("url is required");
      expect((await proxy({ url: "https://api.example.com" })).content[0].text).toBe("method is required");
      expect((await proxy({ method: "TRACE", url: "https://api.example.com" })).content[0].text).toBe("Unsupported method: TRACE");
      expect((await proxy({ method: "GET", url: "https://api.example.com/v1" })).content[0].text).toBe(
        'No secret references found. Use {{secret:path}} in url/headers/body, "inject", or "auto_inject".'
      );
    });

    test("policy denial: message and audit row", async () => {
      const r = await proxy({ method: "GET", url: "https://api.example.com/v1", auto_inject: ["db/example"] });
      expect(r.content[0].text).toBe('Access denied: no proxy permission on "db/example"');
      const [row] = proxyRows();
      expect(row.action).toBe("proxy.forward.mcp");
      expect(row.source_ip).toBe("127.0.0.1");
      expect(row.metadata).toEqual({ target_url: "https://api.example.com/v1", target_path: "/v1", reason: "policy_denied" });
    });

    test("gate denial returns the gate body as JSON text", async () => {
      secrets.put("api-keys/example", "sk-example-value-123", { requires_approval: "true" });
      const r = await proxy({ method: "GET", url: "https://api.example.com/v1", auto_inject: ["api-keys/example"] });
      expect(r.isError).toBe(true);
      const body = JSON.parse(r.content[0].text);
      expect(body.requires_approval).toEqual(["api-keys/example"]);
      expect(body.error).toBe("These secrets require an approved lease: api-keys/example");
      expect(fetchCalls).toBe(0);
    });

    test("secret not found", async () => {
      const r = await proxy({ method: "GET", url: "https://api.example.com/v1", auto_inject: ["api-keys/missing"] });
      expect(r.content[0].text).toBe('Secret not found: "api-keys/missing"');
    });

    test("domain allowlist: message and audit row", async () => {
      secrets.put("api-keys/example", "sk-example-value-123", { allowed_domains: "other.example.com" });
      const r = await proxy({ method: "GET", url: "https://api.example.com/v1", auto_inject: ["api-keys/example"] });
      expect(r.content[0].text).toBe('Domain api.example.com not in allowed domains for secret "api-keys/example"');
      const [row] = proxyRows();
      expect(row.metadata).toEqual({
        target_url: "https://api.example.com/v1",
        target_path: "/v1",
        hostname: "api.example.com",
        reason: "domain_blocked",
        allowed_domains: "other.example.com",
      });
    });

    test("path prefix allowlist", async () => {
      secrets.put("api-keys/example", "sk-example-value-123", { allowed_path_prefixes: "/v2" });
      const r = await proxy({ method: "GET", url: "https://api.example.com/v1/x", auto_inject: ["api-keys/example"] });
      expect(r.content[0].text).toBe("Path '/v1/x' is not in allowed_path_prefixes for secret \"api-keys/example\"");
      expect(proxyRows()[0].metadata.reason).toBe("path_prefix_blocked");
    });

    test("private network blocked: reason text and audit row", async () => {
      process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE = "false";
      const r = await proxy({ method: "GET", url: "http://127.0.0.1/v1", auto_inject: ["api-keys/example"] });
      expect(r.content[0].text).toContain("Private network proxying is disabled");
      expect(proxyRows()[0].metadata).toEqual({ target_host: "127.0.0.1", target_path: "/v1", reason: "ssrf_blocked" });
    });

    test("protocol and invalid URL", async () => {
      expect((await proxy({ method: "GET", url: "ftp://api.example.com/x", auto_inject: ["api-keys/example"] })).content[0].text).toBe(
        "Unsupported protocol: ftp:"
      );
      expect((await proxy({ method: "GET", url: "not a url", auto_inject: ["api-keys/example"] })).content[0].text).toBe(
        "Invalid upstream URL"
      );
    });

    test("tls_allow_insecure is not honored and no response headers are returned", async () => {
      secrets.put("api-keys/example", "sk-example-value-123", { tls_allow_insecure: "true" });
      let seen: any;
      globalThis.fetch = (async (_url: string, init: any) => {
        seen = init;
        return new Response("{}", { status: 200, headers: { "content-type": "application/json", "x-request-id": "u1" } });
      }) as unknown as typeof fetch;
      const r = await proxy({ method: "GET", url: "https://api.example.com/v1", auto_inject: ["api-keys/example"] });
      expect(seen.tls).toBeUndefined();
      expect(Object.keys(JSON.parse(r.content[0].text))).toEqual(["status", "body"]);
    });

    test("inject has no basic: shorthand: the prefixed path is a literal secret path", async () => {
      const r = await proxy({ method: "GET", url: "https://api.example.com/v1", inject: { Authorization: "basic:api-keys/example" } });
      expect(r.content[0].text).toBe('Access denied: no proxy permission on "basic:api-keys/example"');
    });

    test("success row and limiter count", async () => {
      secrets.put("api-keys/example", "sk-example-value-123", { rate_limit_per_minute: "1" });
      const r = await proxy({ method: "POST", url: "https://api.example.com/v1", auto_inject: ["api-keys/example"], body: { a: 1 } });
      expect(r.isError).toBeUndefined();
      const [row] = proxyRows();
      expect(row.success).toBe(1);
      expect(row.lease_id).toBeNull();
      expect(row.metadata).toEqual({
        target_host: "api.example.com",
        target_path: "/v1",
        target_url: "https://api.example.com/v1",
        method: "POST",
        status: "200",
        redaction_count: "0",
      });
      expect(rateLimiter.checkSecret("api-keys/example", 1).allowed).toBe(false);
      expect(rateLimiter.checkApprole("role-mcp", { per_minute: 1, per_hour: null, per_day: null }).allowed).toBe(false);
    });

    test("upstream failure: message, bare failure row, counted once", async () => {
      globalThis.fetch = (async () => {
        throw new Error("connection refused");
      }) as unknown as typeof fetch;
      secrets.put("api-keys/example", "sk-example-value-123", { rate_limit_per_minute: "2" });
      const r = await proxy({ method: "GET", url: "https://api.example.com/v1", auto_inject: ["api-keys/example"] });
      expect(r.content[0].text).toBe("Upstream request failed: connection refused");
      const [row] = proxyRows();
      expect(row.success).toBe(0);
      expect(row.metadata).toEqual({ target_url: "https://api.example.com/v1", target_path: "/v1" });
      expect(rateLimiter.checkSecret("api-keys/example", 2).allowed).toBe(true);
      expect(rateLimiter.checkSecret("api-keys/example", 1).allowed).toBe(false);
    });
  });
});
