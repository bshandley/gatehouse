import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { initDB } from "../src/db/init";
import { AuditLog } from "../src/audit/logger";
import { scrubRouter } from "../src/api/scrub";
import { SecretsEngine } from "../src/secrets/engine";
import { PolicyEngine } from "../src/policy/engine";
import { statsRouter, parseWindow } from "../src/api/stats";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("POST /v1/scrub emits scrub.redact", () => {
  let db: Database;
  let audit: AuditLog;
  let dir: string;
  let app: Hono;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-scrub-"));
    db = initDB(dir);
    audit = new AuditLog(db);
    app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "rid");
      c.set("sourceIp", "127.0.0.1");
      c.set("auth", { identity: "test", policies: ["*"] });
      await next();
    });
    app.route("/v1/scrub", scrubRouter(audit));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("logs scrub.redact with the count when credentials are found", async () => {
    const res = await app.request("/v1/scrub", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: "key is sk-ant-aaaaaaaaaaaaaaaaaaaaaaaa here" }),
    });
    expect(res.status).toBe(200);
    const rows = audit.query({ action: "scrub.redact", limit: 10 });
    expect(rows.length).toBe(1);
    expect(rows[0].metadata.count).toBe("1");
  });

  test("does NOT log when nothing was redacted", async () => {
    const res = await app.request("/v1/scrub", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: "nothing secret here" }),
    });
    expect(res.status).toBe(200);
    expect(audit.query({ action: "scrub.redact", limit: 10 }).length).toBe(0);
  });
});

describe("AuditLog.sumRedactions and blockedEgress", () => {
  let db: Database;
  let audit: AuditLog;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-agg-"));
    db = initDB(dir);
    audit = new AuditLog(db);
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const longAgo = "2000-01-01T00:00:00.000Z";

  test("sumRedactions adds proxy.forward, proxy.forward.mcp, and scrub.redact counts", () => {
    audit.log({ identity: "a", action: "proxy.forward", metadata: { redaction_count: "3" } });
    audit.log({ identity: "a", action: "proxy.forward.mcp", metadata: { redaction_count: "2" } });
    audit.log({ identity: "a", action: "scrub.redact", metadata: { count: "5" } });
    // Rows without a count contribute zero.
    audit.log({ identity: "a", action: "proxy.forward", metadata: { target_url: "x" } });
    // Unrelated action ignored.
    audit.log({ identity: "a", action: "secret.reveal_value", path: "p" });

    expect(audit.sumRedactions(longAgo)).toBe(10);
  });

  test("sumRedactions respects the since window", () => {
    audit.log({ identity: "a", action: "scrub.redact", metadata: { count: "4" } });
    const future = "2999-01-01T00:00:00.000Z";
    expect(audit.sumRedactions(future)).toBe(0);
  });

  test("query() with an ISO since (T separator) still includes same-day rows", () => {
    // audit_log.timestamp is stored as "YYYY-MM-DD HH:MM:SS" (space). A raw ISO
    // since with a "T" would lexically exclude the whole boundary day; query()
    // normalizes it so the row is found.
    audit.log({ identity: "a", action: "scrub.redact", metadata: { count: "1" } });
    const row = db
      .query("SELECT timestamp FROM audit_log LIMIT 1")
      .get() as { timestamp: string };
    const day = row.timestamp.slice(0, 10); // YYYY-MM-DD
    const isoSince = `${day}T00:00:00.000Z`;
    const results = audit.query({ since: isoSince, action: "scrub.redact" });
    expect(results.length).toBe(1);
  });

  test("blockedEgress counts distinct blocked actions and failed-forward reasons", () => {
    audit.log({ identity: "a", action: "proxy.blocked.rate_limit" });
    audit.log({ identity: "a", action: "proxy.blocked.rate_limit" });
    audit.log({ identity: "a", action: "proxy.blocked.approval" });
    audit.log({ identity: "a", action: "proxy.forward", success: false, metadata: { reason: "ssrf_blocked" } });
    audit.log({ identity: "a", action: "proxy.forward.mcp", success: false, metadata: { reason: "domain_blocked" } });
    audit.log({ identity: "a", action: "proxy.forward", success: false, metadata: { reason: "path_prefix_blocked" } });
    audit.log({ identity: "a", action: "proxy.forward", success: false, metadata: { reason: "policy_denied" } });
    // A successful forward is not blocked egress.
    audit.log({ identity: "a", action: "proxy.forward", success: true, metadata: { reason: "n/a", redaction_count: "0" } });

    const be = audit.blockedEgress(longAgo);
    expect(be.total).toBe(7);
    expect(be.by_reason).toEqual({
      rate_limit: 2,
      approval: 1,
      ssrf_blocked: 1,
      domain_blocked: 1,
      path_prefix_blocked: 1,
      policy_denied: 1,
    });
  });
});

describe("parseWindow", () => {
  test("formats since in SQLite datetime form (space separator, no fractional/Z)", () => {
    const { label, since } = parseWindow("7d");
    expect(label).toBe("7d");
    expect(since).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  });

  test("defaults to 7d for missing or unparseable input", () => {
    expect(parseWindow(undefined).label).toBe("7d");
    expect(parseWindow("banana").label).toBe("7d");
  });

  test("accepts hours and days", () => {
    expect(parseWindow("24h").label).toBe("24h");
    expect(parseWindow("30d").label).toBe("30d");
  });
});

describe("GET /v1/stats/posture", () => {
  let db: Database;
  let audit: AuditLog;
  let secrets: SecretsEngine;
  let dir: string;
  let app: Hono;

  function buildApp(policiesList: string[]) {
    const a = new Hono();
    a.use("*", async (c, next) => {
      c.set("requestId", "rid");
      c.set("sourceIp", "127.0.0.1");
      c.set("auth", { identity: "test", policies: policiesList });
      await next();
    });
    const configDir = join(dir, "config");
    mkdirSync(join(configDir, "policies"), { recursive: true });
    writeFileSync(
      join(configDir, "policies", "admin.yaml"),
      `name: admin\nrules:\n  - path: "*"\n    capabilities: [admin]\n`
    );
    writeFileSync(
      join(configDir, "policies", "noadmin.yaml"),
      `name: noadmin\nrules:\n  - path: "svc/*"\n    capabilities: [read]\n`
    );
    const policies = new PolicyEngine(configDir);
    a.route("/v1/stats", statsRouter(audit, secrets, policies));
    return a;
  }

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-stats-"));
    db = initDB(dir);
    audit = new AuditLog(db);
    secrets = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("returns the posture shape for an admin", async () => {
    audit.log({ identity: "a", action: "scrub.redact", metadata: { count: "7" } });
    audit.log({ identity: "a", action: "proxy.blocked.rate_limit" });
    secrets.put("svc/key", "v");

    app = buildApp(["admin"]);
    const res = await app.request("/v1/stats/posture?window=7d");
    expect(res.status).toBe(200);
    const body = await res.json();

    expect(body.redactions).toEqual({ window: "7d", count: 7 });
    expect(body.blocked_egress.window).toBe("7d");
    expect(body.blocked_egress.total).toBe(1);
    expect(body.blocked_egress.by_reason).toEqual({ rate_limit: 1 });
    expect(body.hygiene).toEqual({ stale_90d: 0, older_18mo: 0, total_secrets: 1 });
  });

  test("defaults to a 7d window when none is given", async () => {
    app = buildApp(["admin"]);
    const res = await app.request("/v1/stats/posture");
    const body = await res.json();
    expect(body.redactions.window).toBe("7d");
  });

  test("rejects a non-admin caller with 403", async () => {
    app = buildApp(["noadmin"]);
    const res = await app.request("/v1/stats/posture");
    expect(res.status).toBe(403);
  });

  test("clamps an absurd window and still returns a valid shape", async () => {
    app = buildApp(["admin"]);
    const res = await app.request("/v1/stats/posture?window=banana");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.redactions.window).toBe("7d");
  });
});
