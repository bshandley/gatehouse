import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { LeaseManager } from "../src/lease/manager";
import { AuditLog } from "../src/audit/logger";
import { PolicyEngine } from "../src/policy/engine";
import { leaseRouter } from "../src/api/lease";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("Lease approval flow (HTTP)", () => {
  let app: Hono;
  let db: Database;
  let secrets: SecretsEngine;
  let leases: LeaseManager;
  let policies: PolicyEngine;
  let audit: AuditLog;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-lease-approval-"));
    db = initDB(dir);
    audit = new AuditLog(db);
    const masterKey = Buffer.from("d".repeat(64), "hex");
    secrets = new SecretsEngine(db, masterKey);
    leases = new LeaseManager(db, secrets, audit);
    policies = new PolicyEngine(join(dir, "config"), db);

    // Agent policy: read+lease on everything.
    policies.savePolicy("agent", [
      { paths: ["*"], capabilities: ["read", "lease"] },
    ]);

    // Proxy-only policy: used to verify /request still accepts proxy-cap
    // agents (regression for v0.14.0 -> v0.14.1 footgun).
    policies.savePolicy("proxy-only", [
      { paths: ["*"], capabilities: ["proxy"] },
    ]);

    // Seed secrets: gated, open, auto-ip.
    secrets.put("secret/gated", "gated-value", { requires_approval: "true" });
    secrets.put("secret/open", "open-value");
    secrets.put("secret/auto-ip", "auto-ip-value", {
      requires_approval: "true",
      auto_approve_from_ip: "10.0.0.0/8",
    });

    app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "test-req-id");
      // Test middleware lets each call override sourceIp via X-Test-Source-IP.
      const ip = c.req.header("X-Test-Source-IP") || "127.0.0.1";
      c.set("sourceIp", ip);
      const idHeader = c.req.header("X-Test-Identity") || "agent-a";
      const polHeader = c.req.header("X-Test-Policies");
      c.set("auth", {
        identity: idHeader,
        policies: polHeader ? JSON.parse(polHeader) : ["agent"],
        source: "approle",
      });
      await next();
    });
    app.route("/v1/lease", leaseRouter(leases, policies, audit, undefined, secrets));
  });

  afterEach(() => {
    leases.stopReaper();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  // ------------------------------------------------------------------
  // Baseline: non-approval-gated secret behaves normally.
  // ------------------------------------------------------------------

  test("checkout of secret/open succeeds without approval", async () => {
    const res = await app.request("/v1/lease/secret/open", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({ ttl: 300 }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.value).toBe("open-value");
  });

  // ------------------------------------------------------------------
  // 403 without an approved lease, with helpful error body.
  // ------------------------------------------------------------------

  // ------------------------------------------------------------------
  // Regression: an agent with proxy-only cap on an approval-gated secret
  // must still be able to call /request. Without this, proxy-only agents
  // are unreachable on gated secrets (proxy blocked AND request blocked).
  // ------------------------------------------------------------------

  test("/request accepts proxy-only cap on approval-gated secret", async () => {
    const res = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-proxy-only",
        "X-Test-Policies": JSON.stringify(["proxy-only"]),
      },
      body: JSON.stringify({
        ttl: 300,
        justification: "Need this for a proxy call I can't make without approval.",
      }),
    });
    expect(res.status).toBe(202);
    const body = await res.json();
    expect(body.status).toBe("pending");
    expect(body.lease_id).toMatch(/^lease-/);
  });

  test("/request denies an agent with neither proxy nor lease cap", async () => {
    // No-policy agent: middleware will pass an empty policies array.
    const res = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-nopol",
        "X-Test-Policies": JSON.stringify([]),
      },
      body: JSON.stringify({
        ttl: 300,
        justification: "Should be denied because no relevant cap.",
      }),
    });
    expect(res.status).toBe(403);
  });

  test("checkout of approval-gated secret without lease returns 403", async () => {
    const res = await app.request("/v1/lease/secret/gated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({ ttl: 300 }),
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.requires_approval).toBe(true);
  });

  // ------------------------------------------------------------------
  // Request flow.
  // ------------------------------------------------------------------

  test("POST /request creates pending lease and returns 202", async () => {
    const res = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({
        ttl: 600,
        justification: "Need to debug the production outage",
      }),
    });
    expect(res.status).toBe(202);
    const body = await res.json();
    expect(body.lease_id).toStartWith("lease-");
    expect(body.status).toBe("pending");
    expect(typeof body.request_expires_at).toBe("string");
    expect(typeof body.expires_at_if_approved).toBe("string");
  });

  test("re-POST /request for same (identity, path) dedups to same lease and 200", async () => {
    const first = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({
        ttl: 600,
        justification: "Need to debug the production outage",
      }),
    });
    expect(first.status).toBe(202);
    const firstBody = await first.json();

    // Sleep > 1s so the dedup heuristic in api/lease.ts (Date.now()-created_at > 1000)
    // recognises this as a dedup return.
    await new Promise((r) => setTimeout(r, 1100));

    const second = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({
        ttl: 600,
        justification: "Need to debug the production outage",
      }),
    });
    expect(second.status).toBe(200);
    const secondBody = await second.json();
    expect(secondBody.lease_id).toBe(firstBody.lease_id);
  });

  // ------------------------------------------------------------------
  // Admin approves -> agent can checkout, reuses lease, then revoke.
  // ------------------------------------------------------------------

  test("admin approve -> checkout returns value; second checkout reuses lease; revoke blocks", async () => {
    // 1. Agent requests.
    const reqRes = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({
        ttl: 600,
        justification: "Need to debug the production outage",
      }),
    });
    expect(reqRes.status).toBe(202);
    const { lease_id } = await reqRes.json();

    // 2. Admin approves.
    const approveRes = await app.request(`/v1/lease/${lease_id}/approve`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "admin-1",
        "X-Test-Policies": JSON.stringify(["admin"]),
      },
      body: JSON.stringify({}),
    });
    expect(approveRes.status).toBe(200);
    const approvedBody = await approveRes.json();
    expect(approvedBody.lease.status).toBe("approved");

    // 3. Agent now checks out and gets the value.
    const co1 = await app.request("/v1/lease/secret/gated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({ ttl: 300 }),
    });
    expect(co1.status).toBe(200);
    const co1Body = await co1.json();
    expect(co1Body.value).toBe("gated-value");

    // 4. Second checkout reuses the same lease - still only one row for
    //    (agent-a, secret/gated).
    const co2 = await app.request("/v1/lease/secret/gated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({ ttl: 300 }),
    });
    expect(co2.status).toBe(200);

    const rowCount = (
      db
        .query(
          "SELECT COUNT(*) AS n FROM leases WHERE identity = ? AND secret_path = ?"
        )
        .get("agent-a", "secret/gated") as { n: number }
    ).n;
    expect(rowCount).toBe(1);

    // 5. Revoke -> next checkout 403 again.
    const delRes = await app.request(`/v1/lease/${lease_id}`, {
      method: "DELETE",
      headers: { "X-Test-Identity": "agent-a" },
    });
    expect(delRes.status).toBe(200);

    const co3 = await app.request("/v1/lease/secret/gated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({ ttl: 300 }),
    });
    expect(co3.status).toBe(403);
  });

  // ------------------------------------------------------------------
  // Audit: after approve+checkout, action is lease.access not lease.checkout.
  // ------------------------------------------------------------------

  test("post-approval checkout audits lease.access", async () => {
    const req = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({
        ttl: 300,
        justification: "Audit verification test path",
      }),
    });
    const { lease_id } = await req.json();

    await app.request(`/v1/lease/${lease_id}/approve`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "admin-1",
        "X-Test-Policies": JSON.stringify(["admin"]),
      },
      body: JSON.stringify({}),
    });

    await app.request("/v1/lease/secret/gated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({ ttl: 300 }),
    });

    const access = audit.query({
      identity: "agent-a",
      action: "lease.access",
    });
    expect(access.length).toBeGreaterThanOrEqual(1);
    expect(access[0].path).toBe("secret/gated");

    const checkout = audit.query({
      identity: "agent-a",
      action: "lease.checkout",
      path: "secret/gated",
    });
    expect(checkout.length).toBe(0);
  });

  // ------------------------------------------------------------------
  // Deny flow.
  // ------------------------------------------------------------------

  test("admin deny sets denied_reason; agent may re-request afterwards", async () => {
    const req = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({
        ttl: 300,
        justification: "Initial attempt that gets denied",
      }),
    });
    const { lease_id: firstId } = await req.json();

    const denyRes = await app.request(`/v1/lease/${firstId}/deny`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "admin-1",
        "X-Test-Policies": JSON.stringify(["admin"]),
      },
      body: JSON.stringify({ reason: "Not approved at this time" }),
    });
    expect(denyRes.status).toBe(200);
    const denied = await denyRes.json();
    expect(denied.lease.status).toBe("denied");
    expect(denied.lease.denied_reason).toBe("Not approved at this time");

    // A denied lease should NOT block re-requests - a new pending lease is created.
    const reReq = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({
        ttl: 300,
        justification: "Second attempt after denial",
      }),
    });
    expect(reReq.status).toBe(202);
    const reBody = await reReq.json();
    expect(reBody.lease_id).not.toBe(firstId);
    expect(reBody.status).toBe("pending");
  });

  // ------------------------------------------------------------------
  // GET /pending visibility.
  // ------------------------------------------------------------------

  test("GET /pending: admin sees all; non-admin sees only own", async () => {
    // agent-a requests
    await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({ ttl: 300, justification: "Agent A justification text" }),
    });
    // agent-b requests
    await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-b",
      },
      body: JSON.stringify({ ttl: 300, justification: "Agent B justification text" }),
    });

    const adminRes = await app.request("/v1/lease/pending", {
      headers: {
        "X-Test-Identity": "admin-1",
        "X-Test-Policies": JSON.stringify(["admin"]),
      },
    });
    const adminBody = await adminRes.json();
    expect(adminBody.leases.length).toBe(2);

    const agentRes = await app.request("/v1/lease/pending", {
      headers: { "X-Test-Identity": "agent-a" },
    });
    const agentBody = await agentRes.json();
    expect(agentBody.leases.length).toBe(1);
    expect(agentBody.leases[0].identity).toBe("agent-a");
  });

  // ------------------------------------------------------------------
  // GET /:leaseId authz.
  // ------------------------------------------------------------------

  test("GET /v1/lease/<id> 403 for non-owner non-admin", async () => {
    const req = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({ ttl: 300, justification: "Some valid justification" }),
    });
    const { lease_id } = await req.json();

    const res = await app.request(`/v1/lease/${lease_id}`, {
      headers: { "X-Test-Identity": "agent-b" },
    });
    expect(res.status).toBe(403);
  });

  // ------------------------------------------------------------------
  // Approve error paths.
  // ------------------------------------------------------------------

  test("approve an already-approved lease returns 409", async () => {
    const req = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({ ttl: 300, justification: "A 10+ char justification" }),
    });
    const { lease_id } = await req.json();

    await app.request(`/v1/lease/${lease_id}/approve`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "admin-1",
        "X-Test-Policies": JSON.stringify(["admin"]),
      },
      body: JSON.stringify({}),
    });

    const dupe = await app.request(`/v1/lease/${lease_id}/approve`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "admin-1",
        "X-Test-Policies": JSON.stringify(["admin"]),
      },
      body: JSON.stringify({}),
    });
    expect(dupe.status).toBe(409);
  });

  test("approve non-existent lease returns 404", async () => {
    const res = await app.request("/v1/lease/lease-does-not-exist/approve", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "admin-1",
        "X-Test-Policies": JSON.stringify(["admin"]),
      },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(404);
  });

  // ------------------------------------------------------------------
  // IP-allowlist auto-approve.
  //
  // The HTTP /v1/lease endpoint only consults sourceIp through c.get("sourceIp")
  // which our test middleware reads from X-Test-Source-IP. So we can drive both
  // paths through HTTP.
  // ------------------------------------------------------------------

  test("auto_approve_from_ip: request from allowlisted IP returns value", async () => {
    const res = await app.request("/v1/lease/secret/auto-ip", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-ip",
        "X-Test-Source-IP": "10.0.0.5",
      },
      body: JSON.stringify({ ttl: 300 }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.value).toBe("auto-ip-value");

    // A lease should now exist for this identity+path.
    const lease = leases.findActiveApprovedLease("agent-ip", "secret/auto-ip");
    expect(lease).not.toBeNull();
    expect(lease!.approved_by).toBe("system:auto_approve_from_ip");
  });

  test("auto_approve_from_ip: request from off-allowlist IP returns 403", async () => {
    const res = await app.request("/v1/lease/secret/auto-ip", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-ip",
        "X-Test-Source-IP": "192.168.1.1",
      },
      body: JSON.stringify({ ttl: 300 }),
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.requires_approval).toBe(true);
  });

  // ------------------------------------------------------------------
  // Justification length validation.
  // ------------------------------------------------------------------

  test("justification < 10 chars returns 400", async () => {
    const res = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({ ttl: 300, justification: "short" }),
    });
    expect(res.status).toBe(400);
  });

  test("justification > 2000 chars returns 400", async () => {
    const res = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({ ttl: 300, justification: "x".repeat(2001) }),
    });
    expect(res.status).toBe(400);
  });

  // ------------------------------------------------------------------
  // Reaper + manual cleanup.
  // ------------------------------------------------------------------

  test("reapExpired flips expired pending leases and audits lease.request_expired", async () => {
    const req = await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({ ttl: 300, justification: "Long enough justification" }),
    });
    const { lease_id } = await req.json();

    // Manually expire the request window.
    db.query("UPDATE leases SET request_expires_at = datetime('now', '-1 minute') WHERE id = ?").run(lease_id);

    const reaped = leases.reapExpired();
    expect(reaped).toBeGreaterThanOrEqual(1);

    const lease = leases.getLease(lease_id);
    expect(lease!.status).toBe("expired");
    expect(lease!.revoked).toBe(true);

    const events = audit.query({ action: "lease.request_expired" });
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0].lease_id).toBe(lease_id);
  });

  test("deletePendingForIdentity removes pending rows for that identity", async () => {
    await app.request("/v1/lease/secret/gated/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Identity": "agent-a",
      },
      body: JSON.stringify({ ttl: 300, justification: "Pending row to be deleted" }),
    });

    const before = leases.listPending("agent-a");
    expect(before.length).toBe(1);

    const deleted = leases.deletePendingForIdentity("agent-a");
    expect(deleted).toBe(1);

    const after = leases.listPending("agent-a");
    expect(after.length).toBe(0);
  });
});
