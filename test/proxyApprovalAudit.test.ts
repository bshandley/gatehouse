import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { PolicyEngine } from "../src/policy/engine";
import { AuditLog } from "../src/audit/logger";
import { LeaseManager } from "../src/lease/manager";
import { RateLimiter } from "../src/rateLimits/limiter";
import { proxyRouter } from "../src/api/proxy";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("proxy.forward audit row stamps approval lease_id", () => {
  let db: Database;
  let secrets: SecretsEngine;
  let policies: PolicyEngine;
  let audit: AuditLog;
  let leases: LeaseManager;
  let rateLimiter: RateLimiter;
  let app: Hono;
  let dir: string;
  let upstream: Server;
  let upstreamPort: number;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-proxy-audit-"));
    mkdirSync(join(dir, "config", "policies"), { recursive: true });

    db = initDB(dir);
    secrets = new SecretsEngine(db, Buffer.from("e".repeat(64), "hex"));
    policies = new PolicyEngine(join(dir, "config"), db);
    audit = new AuditLog(db);
    leases = new LeaseManager(db, secrets, audit);
    rateLimiter = new RateLimiter();

    policies.savePolicy("proxy-agent", [
      { paths: ["*"], capabilities: ["proxy", "lease"] },
    ]);

    // Approval-gated secret. allow_private=true so the proxy will hit the
    // local mock upstream.
    secrets.put("api-keys/gated", "secret-value-xyz", {
      requires_approval: "true",
      allow_private: "true",
    });

    upstream = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"ok":true}');
    });
    await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
    upstreamPort = (upstream.address() as { port: number }).port;

    app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "test-req-id");
      c.set("sourceIp", "127.0.0.1");
      c.set("auth", {
        identity: "approle:test-agent",
        policies: ["proxy-agent"],
        source: "approle",
        role_id: "role-test-agent",
      });
      await next();
    });
    app.route("/v1/proxy", proxyRouter(secrets, policies, audit, undefined, db, rateLimiter, leases));
  });

  afterEach(async () => {
    leases.stopReaper();
    await new Promise<void>((r) => upstream.close(() => r()));
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("authorized by an approval lease: audit row has top-level lease_id", async () => {
    const approved = leases.autoApprove(
      "api-keys/gated",
      "approle:test-agent",
      300,
      "user:tester",
      "Pre-seeded for the audit-row test."
    );

    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        method: "GET",
        url: `http://127.0.0.1:${upstreamPort}/anything`,
        auto_inject: ["api-keys/gated"],
      }),
    });
    expect(res.status).toBe(200);

    const rows = audit.query({ action: "proxy.forward", limit: 5 });
    expect(rows.length).toBeGreaterThanOrEqual(1);
    const latest = rows[0];
    expect(latest.lease_id).toBe(approved.id);
    expect(latest.metadata?.lease_id).toBe(approved.id);
  });

  test("non-approval secret: top-level lease_id stays null", async () => {
    secrets.put("api-keys/open", "open-value", { allow_private: "true" });

    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        method: "GET",
        url: `http://127.0.0.1:${upstreamPort}/anything`,
        auto_inject: ["api-keys/open"],
      }),
    });
    expect(res.status).toBe(200);

    const rows = audit.query({ action: "proxy.forward", limit: 5 });
    const latest = rows[0];
    expect(latest.lease_id).toBeNull();
    expect(latest.metadata?.lease_id).toBeUndefined();
  });
});
