import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { PolicyEngine } from "../src/policy/engine";
import { AuditLog } from "../src/audit/logger";
import { LeaseManager } from "../src/lease/manager";
import { RateLimiter } from "../src/rateLimits/limiter";
import {
  authorizeProxyCall,
  recordProxyCall,
  recordProxyOutcome,
  type ProxyCall,
  type ProxyDeps,
} from "../src/proxy/pipeline";
import type { AuthContext } from "../src/auth/middleware";
import { proxyRouter } from "../src/api/proxy";
import { setProxyLimits, _resetProxyLimitsCacheForTests } from "../src/settings/proxyLimits";
import { Hono } from "hono";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const SECRET_REF = /\{\{secret:([a-zA-Z0-9/_-]+)\}\}/g;

interface AuditRow {
  action: string;
  path: string | null;
  lease_id: string | null;
  metadata: Record<string, string>;
  success: number;
}

describe("proxy pipeline", () => {
  let db: Database;
  let secrets: SecretsEngine;
  let policies: PolicyEngine;
  let audit: AuditLog;
  let leases: LeaseManager;
  let rateLimiter: RateLimiter;
  let deps: ProxyDeps;
  let dir: string;
  const prevAllowPrivate = process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE;

  const auth: AuthContext = {
    identity: "approle:pipeline-agent",
    policies: ["proxy-agent"],
    source: "approle",
    role_id: "role-pipeline",
  } as AuthContext;

  function call(url: string, secretPaths: string[], extra: Partial<ProxyCall> = {}): ProxyCall {
    return {
      auth,
      sourceIp: "127.0.0.1",
      requestId: "req-1",
      secretPaths,
      auditUrl: url,
      resolveUrl: (resolved) =>
        url.replace(SECRET_REF, (_, p) => resolved.get(p) ?? `{{secret:${p}}}`),
      auditAction: "proxy.forward",
      ...extra,
    };
  }

  function rows(): AuditRow[] {
    return (db.query("SELECT action, path, lease_id, metadata, success FROM audit_log ORDER BY id").all() as any[]).map(
      (r) => ({ ...r, metadata: JSON.parse(r.metadata) })
    );
  }

  beforeEach(() => {
    delete process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE;
    dir = mkdtempSync(join(tmpdir(), "gatehouse-pipeline-test-"));
    mkdirSync(join(dir, "config", "policies"), { recursive: true });
    db = initDB(dir);
    secrets = new SecretsEngine(db, Buffer.from("c".repeat(64), "hex"));
    policies = new PolicyEngine(join(dir, "config"), db);
    audit = new AuditLog(db);
    leases = new LeaseManager(db, secrets, audit);
    rateLimiter = new RateLimiter();
    deps = { secrets, policies, audit, db, rateLimiter, leases };

    policies.savePolicy("proxy-agent", [
      { paths: ["api-keys/*"], capabilities: ["proxy"] },
      { paths: ["db/*"], capabilities: ["read"] },
    ]);
    secrets.put("api-keys/example", "sk-example-value-123");
    secrets.put("db/example", "postgres-example");
  });

  afterEach(() => {
    leases.stopReaper();
    db.close();
    rmSync(dir, { recursive: true, force: true });
    if (prevAllowPrivate === undefined) delete process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE;
    else process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE = prevAllowPrivate;
  });

  test("policy_denied: returns the path and audits per path", () => {
    const r = authorizeProxyCall(deps, call("https://api.example.com/v1", ["db/example"]));
    expect(r).toEqual({ ok: false, denial: { code: "policy_denied", path: "db/example" } });
    const [row] = rows();
    expect(row.action).toBe("proxy.forward");
    expect(row.path).toBe("db/example");
    expect(row.success).toBe(0);
    expect(row.metadata).toEqual({
      target_url: "https://api.example.com/v1",
      target_path: "/v1",
      reason: "policy_denied",
    });
  });

  test("policy_denied uses the caller's audit action", () => {
    authorizeProxyCall(deps, call("https://api.example.com/v1", ["db/example"], { auditAction: "proxy.forward.mcp" }));
    expect(rows()[0].action).toBe("proxy.forward.mcp");
  });

  test("gate_blocked: approval gate denial is returned with its status and body, already audited", () => {
    secrets.put("api-keys/example", "sk-example-value-123", { requires_approval: "true" });
    const r = authorizeProxyCall(deps, call("https://api.example.com/v1", ["api-keys/example"]));
    expect(r.ok).toBe(false);
    if (r.ok || r.denial.code !== "gate_blocked") throw new Error("expected gate_blocked");
    expect(r.denial.gate.status).toBe(403);
    expect(r.denial.gate.body.requires_approval).toEqual(["api-keys/example"]);
    expect(r.denial.gate.body.request_id).toBe("req-1");
    const all = rows();
    expect(all).toHaveLength(1);
    expect(all[0].action).toBe("proxy.blocked.approval");
    expect(all[0].success).toBe(0);
    expect(all[0].metadata).toEqual({ requires_approval: "api-keys/example" });
  });

  test("gate_blocked: per-secret rate limit returns 429 with Retry-After", () => {
    secrets.put("api-keys/example", "sk-example-value-123", { rate_limit_per_minute: "1" });
    rateLimiter.recordCall("role-pipeline", ["api-keys/example"]);
    const r = authorizeProxyCall(deps, call("https://api.example.com/v1", ["api-keys/example"]));
    if (r.ok || r.denial.code !== "gate_blocked") throw new Error("expected gate_blocked");
    expect(r.denial.gate.status).toBe(429);
    expect(r.denial.gate.headers?.["Retry-After"]).toBeDefined();
    const [row] = rows();
    expect(row.action).toBe("proxy.blocked.rate_limit");
    expect(row.path).toBe("api-keys/example");
    expect(row.success).toBe(0);
    // No auditExtra: metadata is exactly what the gate wrote before the pipeline.
    expect(row.metadata).toEqual({ limit_kind: "secret_minute", limit: "1", current: "1" });
  });

  test("gates_unavailable: deps missing and requires_approval denies with an audit row", () => {
    secrets.put("api-keys/example", "sk-example-value-123", { requires_approval: "true" });
    const r = authorizeProxyCall(
      { secrets, policies, audit, rateLimiter, leases },
      call("https://api.example.com/v1", ["api-keys/example"])
    );
    expect(r).toEqual({ ok: false, denial: { code: "gates_unavailable", path: "api-keys/example" } });
    const [row] = rows();
    expect(row.action).toBe("proxy.forward");
    expect(row.path).toBe("api-keys/example");
    expect(row.success).toBe(0);
    expect(row.metadata).toEqual({
      target_url: "https://api.example.com/v1",
      target_path: "/v1",
      reason: "gates_unavailable",
    });
  });

  test("gates_unavailable: deps missing and a positive rate_limit_per_minute denies, first gated path", () => {
    secrets.put("api-keys/example2", "sk-example-value-456", { rate_limit_per_minute: "5" });
    const r = authorizeProxyCall(
      { secrets, policies, audit },
      call("https://api.example.com/v1", ["api-keys/example", "api-keys/example2"], { auditAction: "proxy.forward.mcp" })
    );
    expect(r).toEqual({ ok: false, denial: { code: "gates_unavailable", path: "api-keys/example2" } });
    const [row] = rows();
    expect(row.action).toBe("proxy.forward.mcp");
    expect(row.path).toBe("api-keys/example2");
    expect(row.metadata.reason).toBe("gates_unavailable");
  });

  test("deps missing and no referenced secret needs a gate: authorized, gates skipped", () => {
    secrets.put("api-keys/example", "sk-example-value-123", { rate_limit_per_minute: "0" });
    const r = authorizeProxyCall({ secrets, policies, audit }, call("https://api.example.com/v1", ["api-keys/example"]));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.roleId).toBe("");
    expect(r.leaseIds).toEqual({});
    expect(rows()).toHaveLength(0);
  });

  for (const missing of ["rateLimiter", "leases", "db"] as const) {
    test(`gates_unavailable when only ${missing} is missing`, () => {
      secrets.put("api-keys/example", "sk-example-value-123", { requires_approval: "true" });
      const partial: ProxyDeps = { ...deps };
      delete partial[missing];
      const r = authorizeProxyCall(partial, call("https://api.example.com/v1", ["api-keys/example"]));
      expect(r).toEqual({ ok: false, denial: { code: "gates_unavailable", path: "api-keys/example" } });
    });
  }

  test("secret_not_found: explicit path that passed policy but does not exist, no audit row", () => {
    const r = authorizeProxyCall(deps, call("https://api.example.com/v1", ["api-keys/missing"]));
    expect(r).toEqual({ ok: false, denial: { code: "secret_not_found", path: "api-keys/missing" } });
    expect(rows()).toHaveLength(0);
  });

  test("domain_blocked: returns hostname and audits allowed_domains", () => {
    secrets.put("api-keys/example", "sk-example-value-123", { allowed_domains: "api.example.com" });
    const r = authorizeProxyCall(deps, call("https://evil.example.net/x", ["api-keys/example"]));
    expect(r).toEqual({
      ok: false,
      denial: { code: "domain_blocked", path: "api-keys/example", hostname: "evil.example.net" },
    });
    const [row] = rows();
    expect(row.action).toBe("proxy.forward");
    expect(row.path).toBe("api-keys/example");
    expect(row.success).toBe(0);
    expect(row.metadata).toEqual({
      target_url: "https://evil.example.net/x",
      target_path: "/x",
      hostname: "evil.example.net",
      reason: "domain_blocked",
      allowed_domains: "api.example.com",
    });
  });

  test("path_prefix_blocked: returns the resolved path and audits allowed_path_prefixes", () => {
    secrets.put("api-keys/example", "sk-example-value-123", { allowed_path_prefixes: "/v1/" });
    const r = authorizeProxyCall(deps, call("https://api.example.com/admin", ["api-keys/example"]));
    expect(r).toEqual({
      ok: false,
      denial: { code: "path_prefix_blocked", path: "api-keys/example", resolvedPath: "/admin" },
    });
    const [row] = rows();
    expect(row.success).toBe(0);
    expect(row.metadata).toEqual({
      target_url: "https://api.example.com/admin",
      target_path: "/admin",
      reason: "path_prefix_blocked",
      allowed_path_prefixes: "/v1/",
    });
  });

  test("ssrf_blocked: audits with the comma-joined path list", () => {
    secrets.put("api-keys/example", "sk-example-value-123", { allow_private: "false" });
    secrets.put("api-keys/example2", "sk-example-value-456");
    const r = authorizeProxyCall(deps, call("http://127.0.0.1/x", ["api-keys/example", "api-keys/example2"]));
    expect(r.ok).toBe(false);
    if (r.ok || r.denial.code !== "ssrf_blocked") throw new Error("expected ssrf_blocked");
    expect(r.denial.reason).toContain("allow_private=false");
    const [row] = rows();
    expect(row.action).toBe("proxy.forward");
    expect(row.path).toBe("api-keys/example,api-keys/example2");
    expect(row.success).toBe(0);
    expect(row.metadata).toEqual({ target_host: "127.0.0.1", target_path: "/x", reason: "ssrf_blocked" });
  });

  test("bad_protocol: non-HTTP scheme, no audit row", () => {
    const r = authorizeProxyCall(deps, call("ftp://api.example.com/x", ["api-keys/example"]));
    expect(r).toEqual({ ok: false, denial: { code: "bad_protocol", protocol: "ftp:" } });
    expect(rows()).toHaveLength(0);
  });

  test("invalid_url: unparseable upstream, no audit row", () => {
    const r = authorizeProxyCall(deps, call("not a url", ["api-keys/example"]));
    expect(r).toEqual({ ok: false, denial: { code: "invalid_url" } });
    expect(rows()).toHaveLength(0);
  });

  test("success: resolved values, substituted upstream URL, lease ids, tlsInsecure false", () => {
    secrets.put("api-keys/example2", "sk-example-value-456", { requires_approval: "true" });
    const approved = leases.autoApprove("api-keys/example2", auth.identity, 300, "admin", "test");
    const r = authorizeProxyCall(
      deps,
      call("https://api.example.com/{{secret:api-keys/example}}/x", ["api-keys/example", "api-keys/example2"])
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect([...r.resolved.entries()]).toEqual([
      ["api-keys/example", "sk-example-value-123"],
      ["api-keys/example2", "sk-example-value-456"],
    ]);
    expect(r.upstreamUrl).toBe("https://api.example.com/sk-example-value-123/x");
    expect(r.leaseIds).toEqual({ "api-keys/example2": approved.id });
    expect(r.roleId).toBe("role-pipeline");
    expect(r.tlsInsecure).toBe(false);
    expect(rows().filter((x) => x.action.startsWith("proxy."))).toHaveLength(0);
  });

  test("success: tlsInsecure true when any referenced secret has tls_allow_insecure", () => {
    secrets.put("api-keys/example2", "sk-example-value-456", { tls_allow_insecure: "true" });
    const r = authorizeProxyCall(deps, call("https://api.example.com/", ["api-keys/example", "api-keys/example2"]));
    expect(r.ok && r.tlsInsecure).toBe(true);
  });

  test("auditExtra is merged into denial and success rows", () => {
    const extra = { mode: "passthrough", alias: "example" };
    authorizeProxyCall(deps, call("https://api.example.com/v1", ["db/example"], { auditExtra: extra }));

    const c = call("https://api.example.com/v1", ["api-keys/example"], { auditExtra: extra });
    const r = authorizeProxyCall(deps, c);
    if (!r.ok) throw new Error("expected ok");
    recordProxyOutcome(deps, c, r, { method: "GET", status: 200, redactionCount: 0 });

    const [denied, ok] = rows();
    expect(denied.metadata).toEqual({
      mode: "passthrough",
      alias: "example",
      target_url: "https://api.example.com/v1",
      target_path: "/v1",
      reason: "policy_denied",
    });
    expect(ok.success).toBe(1);
    expect(ok.metadata).toEqual({
      mode: "passthrough",
      alias: "example",
      target_host: "api.example.com",
      target_path: "/v1",
      target_url: "https://api.example.com/v1",
      method: "GET",
      status: "200",
      redaction_count: "0",
    });
  });

  describe("auditExtra cannot overwrite Gatehouse's own keys", () => {
    const hostile = { reason: "ok", target_host: "spoofed.example.com", mode: "passthrough" };

    test("policy-denied row", () => {
      authorizeProxyCall(deps, call("https://api.example.com/v1", ["db/example"], { auditExtra: hostile }));
      expect(rows()[0].metadata).toEqual({
        reason: "policy_denied",
        target_host: "spoofed.example.com",
        mode: "passthrough",
        target_url: "https://api.example.com/v1",
        target_path: "/v1",
      });
    });

    test("ssrf row", () => {
      secrets.put("api-keys/example", "sk-example-value-123", { allow_private: "false" });
      authorizeProxyCall(deps, call("http://127.0.0.1/x", ["api-keys/example"], { auditExtra: hostile }));
      expect(rows()[0].metadata).toEqual({
        mode: "passthrough",
        target_host: "127.0.0.1",
        target_path: "/x",
        reason: "ssrf_blocked",
      });
    });

    test("success row", () => {
      const c = call("https://api.example.com/v1", ["api-keys/example"], {
        auditExtra: { ...hostile, status: "999", method: "PUT", redaction_count: "0", lease_id: "spoofed" },
      });
      recordProxyOutcome(
        deps,
        c,
        { leaseIds: { "api-keys/example": "lease-1" }, upstreamUrl: "https://api.example.com/v1" },
        { method: "GET", status: 200, redactionCount: 3 }
      );
      const [row] = rows();
      expect(row.lease_id).toBe("lease-1");
      expect(row.metadata).toEqual({
        reason: "ok",
        mode: "passthrough",
        target_host: "api.example.com",
        target_path: "/v1",
        target_url: "https://api.example.com/v1",
        method: "GET",
        status: "200",
        lease_id: "lease-1",
        redaction_count: "3",
      });
    });

    test("gate rate-limit row keeps its keys; non-colliding extras appear", () => {
      secrets.put("api-keys/example", "sk-example-value-123", { rate_limit_per_minute: "1" });
      rateLimiter.recordCall("role-pipeline", ["api-keys/example"]);
      authorizeProxyCall(
        deps,
        call("https://api.example.com/v1", ["api-keys/example"], {
          auditExtra: { ...hostile, limit_kind: "none", limit: "99", current: "0" },
        })
      );
      const [row] = rows();
      expect(row.action).toBe("proxy.blocked.rate_limit");
      expect(row.metadata).toEqual({
        reason: "ok",
        target_host: "spoofed.example.com",
        mode: "passthrough",
        limit_kind: "secret_minute",
        limit: "1",
        current: "1",
      });
    });

    test("gate approval row keeps its keys; non-colliding extras appear", () => {
      secrets.put("api-keys/example", "sk-example-value-123", { requires_approval: "true" });
      authorizeProxyCall(
        deps,
        call("https://api.example.com/v1", ["api-keys/example"], {
          auditExtra: { mode: "passthrough", alias: "example", requires_approval: "nothing" },
        })
      );
      const [row] = rows();
      expect(row.action).toBe("proxy.blocked.approval");
      expect(row.metadata).toEqual({
        mode: "passthrough",
        alias: "example",
        requires_approval: "api-keys/example",
      });
    });
  });

  test("recordProxyOutcome success row matches the REST shape, single lease on the top-level column", () => {
    const c = call("https://api.example.com/v1/{{secret:api-keys/example}}", ["api-keys/example"]);
    recordProxyOutcome(
      deps,
      c,
      { leaseIds: { "api-keys/example": "lease-1" }, upstreamUrl: "https://api.example.com/v1/sk-example-value-123" },
      { method: "POST", status: 201, redactionCount: 2 }
    );
    const [row] = rows();
    expect(row.action).toBe("proxy.forward");
    expect(row.path).toBe("api-keys/example");
    expect(row.lease_id).toBe("lease-1");
    expect(row.success).toBe(1);
    expect(row.metadata).toEqual({
      target_host: "api.example.com",
      target_path: "/v1/%7B%7Bsecret:api-keys/example%7D%7D",
      target_url: "https://api.example.com/v1/{{secret:api-keys/example}}",
      method: "POST",
      status: "201",
      lease_id: "lease-1",
      redaction_count: "2",
    });
  });

  test("recordProxyOutcome failure row carries the reason and no lease column", () => {
    const c = call("https://api.example.com/v1", ["api-keys/example", "api-keys/example2"]);
    recordProxyOutcome(
      deps,
      c,
      { leaseIds: { a: "lease-1", b: "lease-2" }, upstreamUrl: "https://api.example.com/v1" },
      { method: "GET", failureReason: "timeout" }
    );
    const [row] = rows();
    expect(row.path).toBe("api-keys/example,api-keys/example2");
    expect(row.lease_id).toBeNull();
    expect(row.success).toBe(0);
    expect(row.metadata).toEqual({
      target_url: "https://api.example.com/v1",
      target_path: "/v1",
      method: "GET",
      reason: "timeout",
    });
  });

  test("recordProxyOutcome bareFailureRow: failure row has only target_url and target_path (MCP shape)", () => {
    const c = call("https://api.example.com/v1", ["api-keys/example"], {
      auditAction: "proxy.forward.mcp",
      auditExtra: { mode: "passthrough" },
    });
    recordProxyOutcome(
      deps,
      c,
      { leaseIds: {}, upstreamUrl: "https://api.example.com/v1" },
      { method: "GET", failureReason: "timeout", bareFailureRow: true }
    );
    const [row] = rows();
    expect(row.action).toBe("proxy.forward.mcp");
    expect(row.success).toBe(0);
    expect(row.metadata).toEqual({
      mode: "passthrough",
      target_url: "https://api.example.com/v1",
      target_path: "/v1",
    });
  });

  test("recordProxyOutcome bareFailureRow does not change the success row", () => {
    const c = call("https://api.example.com/v1", ["api-keys/example"]);
    recordProxyOutcome(
      deps,
      c,
      { leaseIds: {}, upstreamUrl: "https://api.example.com/v1" },
      { method: "GET", status: 200, redactionCount: 0, bareFailureRow: true }
    );
    const [row] = rows();
    expect(row.success).toBe(1);
    expect(row.metadata.method).toBe("GET");
    expect(row.metadata.status).toBe("200");
  });

  test("recordProxyCall increments the limiter; a denial does not", () => {
    secrets.put("api-keys/example", "sk-example-value-123", { rate_limit_per_minute: "1" });
    // A denial (policy) for the same secret set must not count.
    const denied = authorizeProxyCall(deps, call("https://api.example.com/v1", ["api-keys/example", "db/example"]));
    expect(denied.ok).toBe(false);
    expect(rateLimiter.checkSecret("api-keys/example", 1).allowed).toBe(true);

    const c = call("https://api.example.com/v1", ["api-keys/example"]);
    const r = authorizeProxyCall(deps, c);
    if (!r.ok) throw new Error("expected ok");
    expect(rateLimiter.checkSecret("api-keys/example", 1).allowed).toBe(true);
    recordProxyCall(deps, c, r);
    expect(rateLimiter.checkSecret("api-keys/example", 1).allowed).toBe(false);
    expect(rateLimiter.checkApprole("role-pipeline", { per_minute: 1, per_hour: null, per_day: null }).allowed).toBe(false);
  });
});

describe("REST proxy on the pipeline: oversized upstream", () => {
  let db: Database;
  let secrets: SecretsEngine;
  let audit: AuditLog;
  let leases: LeaseManager;
  let rateLimiter: RateLimiter;
  let app: Hono;
  let dir: string;
  let upstream: Server;
  let port: number;

  beforeEach(async () => {
    _resetProxyLimitsCacheForTests();
    dir = mkdtempSync(join(tmpdir(), "gatehouse-pipeline-rest-"));
    mkdirSync(join(dir, "config", "policies"), { recursive: true });
    db = initDB(dir);
    secrets = new SecretsEngine(db, Buffer.from("d".repeat(64), "hex"));
    const policies = new PolicyEngine(join(dir, "config"), db);
    audit = new AuditLog(db);
    leases = new LeaseManager(db, secrets, audit);
    rateLimiter = new RateLimiter();
    policies.savePolicy("proxy-agent", [{ paths: ["api-keys/*"], capabilities: ["proxy"] }]);
    secrets.put("api-keys/example", "sk-example-value-123", { allow_private: "true", rate_limit_per_minute: "2" });
    expect(setProxyLimits(db, audit, "test", null, { max_timeout_ms: 30_000, max_body_bytes: 1024 }).ok).toBe(true);

    upstream = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("x".repeat(4096));
    });
    await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
    port = (upstream.address() as { port: number }).port;

    app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "req-rest");
      c.set("sourceIp", "127.0.0.1");
      c.set("auth", { identity: "approle:pipeline-agent", policies: ["proxy-agent"], source: "approle", role_id: "role-rest" });
      await next();
    });
    app.route("/v1/proxy", proxyRouter(secrets, policies, audit, undefined, db, rateLimiter, leases));
  });

  afterEach(async () => {
    _resetProxyLimitsCacheForTests();
    leases.stopReaper();
    await new Promise<void>((r) => upstream.close(() => r()));
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("returns 502, writes only the failure row, and counts the call once", async () => {
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ method: "GET", url: `http://127.0.0.1:${port}/big`, auto_inject: ["api-keys/example"] }),
    });
    expect(res.status).toBe(502);
    expect((await res.json()).error).toBe("Upstream response exceeds 1024 bytes");

    const forwardRows = (db.query("SELECT metadata, success FROM audit_log WHERE action = 'proxy.forward'").all() as any[]);
    expect(forwardRows).toHaveLength(1);
    expect(forwardRows[0].success).toBe(0);
    expect(JSON.parse(forwardRows[0].metadata).reason).toBe("Upstream response exceeds 1024 bytes");

    // rate_limit_per_minute is 2: one attempted call leaves room for one more.
    expect(rateLimiter.checkSecret("api-keys/example", 2).allowed).toBe(true);
    expect(rateLimiter.checkSecret("api-keys/example", 1).allowed).toBe(false);
  });
});
