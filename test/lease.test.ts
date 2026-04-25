import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { LeaseManager } from "../src/lease/manager";
import { AuditLog } from "../src/audit/logger";
import { PolicyEngine } from "../src/policy/engine";
import { DynamicSecretsManager } from "../src/dynamic/manager";
import type { DynamicProvider, DynamicCredential } from "../src/dynamic/provider";
import { leaseRouter } from "../src/api/lease";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("LeaseManager", () => {
  let db: Database;
  let leases: LeaseManager;
  let secrets: SecretsEngine;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-test-"));
    db = initDB(dir);
    const audit = new AuditLog(db);
    secrets = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
    leases = new LeaseManager(db, secrets, audit);
    secrets.put("test/key", "secret-value");
    secrets.put("test/key2", "secret-value-2");
  });

  afterEach(() => {
    leases.stopReaper();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("checkout returns value and lease", () => {
    const result = leases.checkout("test/key", "test-agent", 300);
    expect(result).not.toBeNull();
    expect(result!.value).toBe("secret-value");
    expect(result!.lease.ttl_seconds).toBe(300);
    expect(result!.lease.revoked).toBe(false);
    expect(result!.lease.secret_path).toBe("test/key");
    expect(result!.lease.identity).toBe("test-agent");
    expect(result!.lease.id).toStartWith("lease-");
  });

  test("checkout returns null for missing secret", () => {
    expect(leases.checkout("missing", "test-agent")).toBeNull();
  });

  test("checkout uses default TTL of 300", () => {
    const result = leases.checkout("test/key", "test-agent");
    expect(result!.lease.ttl_seconds).toBe(300);
  });

  test("revoke marks lease as revoked", () => {
    const result = leases.checkout("test/key", "test-agent", 300)!;
    const revoked = leases.revoke(result.lease.id, "test-agent");
    expect(revoked).toBe(true);
    const lease = leases.getLease(result.lease.id);
    expect(lease!.revoked).toBe(true);
  });

  test("revoke returns false for already-revoked lease", () => {
    const result = leases.checkout("test/key", "test-agent")!;
    leases.revoke(result.lease.id, "test-agent");
    const secondRevoke = leases.revoke(result.lease.id, "test-agent");
    expect(secondRevoke).toBe(false);
  });

  test("getLease returns null for unknown ID", () => {
    expect(leases.getLease("lease-nonexistent")).toBeNull();
  });

  test("listActive returns only active leases", () => {
    leases.checkout("test/key", "agent-a", 300);
    leases.checkout("test/key2", "agent-b", 300);
    const r3 = leases.checkout("test/key", "agent-a", 300)!;
    leases.revoke(r3.lease.id, "agent-a");

    const active = leases.listActive();
    expect(active.length).toBe(2);
  });

  test("listActive filters by identity", () => {
    leases.checkout("test/key", "agent-a", 300);
    leases.checkout("test/key2", "agent-b", 300);

    const aLeases = leases.listActive("agent-a");
    expect(aLeases.length).toBe(1);
    expect(aLeases[0].identity).toBe("agent-a");
  });

  test("revokeByPath revokes all leases for a path", () => {
    leases.checkout("test/key", "agent-a", 300);
    leases.checkout("test/key", "agent-b", 300);
    leases.checkout("test/key2", "agent-c", 300);

    const count = leases.revokeByPath("test/key", "admin");
    expect(count).toBe(2);

    // key2 lease should still be active
    const active = leases.listActive();
    expect(active.length).toBe(1);
    expect(active[0].secret_path).toBe("test/key2");
  });

  test("reapExpired marks expired leases as revoked", () => {
    // Create a lease with 1-second TTL
    const result = leases.checkout("test/key", "test-agent", 10)!;

    // Manually set expires_at to the past
    db.query("UPDATE leases SET expires_at = datetime('now', '-1 minute') WHERE id = ?").run(
      result.lease.id
    );

    const reaped = leases.reapExpired();
    expect(reaped).toBe(1);

    const lease = leases.getLease(result.lease.id);
    expect(lease!.revoked).toBe(true);
  });

  test("reapExpired returns 0 when no leases expired", () => {
    leases.checkout("test/key", "test-agent", 3600);
    expect(leases.reapExpired()).toBe(0);
  });

  test("lease expires_at is correctly calculated", () => {
    const before = Date.now();
    const result = leases.checkout("test/key", "test-agent", 600)!;
    const after = Date.now();

    const expiresAt = new Date(result.lease.expires_at).getTime();
    expect(expiresAt).toBeGreaterThanOrEqual(before + 600 * 1000 - 1000);
    expect(expiresAt).toBeLessThanOrEqual(after + 600 * 1000 + 1000);
  });

  test("multiple leases for same secret path work independently", () => {
    const l1 = leases.checkout("test/key", "agent-a", 300)!;
    const l2 = leases.checkout("test/key", "agent-b", 600)!;

    expect(l1.lease.id).not.toBe(l2.lease.id);

    leases.revoke(l1.lease.id, "agent-a");
    const l2Check = leases.getLease(l2.lease.id);
    expect(l2Check!.revoked).toBe(false);
  });

  test("renew extends expires_at and updates ttl_seconds", async () => {
    const result = leases.checkout("test/key", "test-agent", 300)!;
    const originalExpiry = new Date(result.lease.expires_at).getTime();
    await new Promise((r) => setTimeout(r, 15));
    const renewed = leases.renew(result.lease.id, 600, "test-agent");
    expect(renewed).not.toBeNull();
    expect(renewed!.ttl_seconds).toBe(600);
    expect(new Date(renewed!.expires_at).getTime()).toBeGreaterThan(originalExpiry);
  });

  test("renew returns null for revoked lease", () => {
    const result = leases.checkout("test/key", "test-agent", 300)!;
    leases.revoke(result.lease.id, "test-agent");
    expect(leases.renew(result.lease.id, 600, "test-agent")).toBeNull();
  });

  test("renew returns null for unknown lease", () => {
    expect(leases.renew("lease-does-not-exist", 600, "test-agent")).toBeNull();
  });
});

class FakeProvider implements DynamicProvider {
  readonly type = "fake-mock";
  revoked: Set<string> = new Set();
  requiredConfig() { return ["host"]; }
  async create(config: Record<string,string>, identity: string, ttl: number): Promise<DynamicCredential> {
    const handle = `h-${crypto.randomUUID().slice(0, 8)}`;
    return { credential: { username: identity, password: handle, host: config.host }, revocation_handle: handle };
  }
  async revoke(_c: Record<string,string>, h: string): Promise<void> { this.revoked.add(h); }
  async validate() { return { ok: true }; }
}

describe("HTTP /v1/lease (unified static + dynamic)", () => {
  let app: Hono;
  let leases: LeaseManager;
  let dynamic: DynamicSecretsManager;
  let provider: FakeProvider;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-leaseapi-"));
    const configDir = join(dir, "config");
    mkdirSync(join(configDir, "policies"), { recursive: true });
    writeFileSync(
      join(configDir, "policies", "agent.yaml"),
      `name: agent
rules:
  - path: "*"
    capabilities: [read, lease]
`
    );

    const db = initDB(dir);
    const audit = new AuditLog(db);
    const masterKey = Buffer.from("c".repeat(64), "hex");
    const secrets = new SecretsEngine(db, masterKey);
    leases = new LeaseManager(db, secrets, audit);
    const policies = new PolicyEngine(configDir);
    dynamic = new DynamicSecretsManager(db, audit, masterKey);
    provider = new FakeProvider();
    dynamic.registerProvider(provider);

    secrets.put("svc/static-token", "staticval");
    dynamic.saveConfig("db/fake", "fake-mock", { host: "h" });

    app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "test-req-id");
      c.set("sourceIp", "127.0.0.1");
      const idHeader = c.req.header("X-Test-Identity");
      const polHeader = c.req.header("X-Test-Policies");
      c.set("auth", {
        identity: idHeader || "agent-a",
        policies: polHeader ? JSON.parse(polHeader) : ["agent"],
      });
      await next();
    });
    app.route("/v1/lease", leaseRouter(leases, policies, audit, dynamic));
  });

  afterEach(() => {
    dynamic.stopReaper();
    leases.stopReaper();
    rmSync(dir, { recursive: true, force: true });
  });

  test("GET /v1/lease merges static + dynamic for the caller", async () => {
    leases.checkout("svc/static-token", "agent-a", 300);
    await dynamic.checkout("db/fake", "agent-a", 300);

    const res = await app.request("/v1/lease", {
      headers: { "X-Test-Identity": "agent-a" },
    });
    expect(res.status).toBe(200);
    const { leases: rows } = await res.json();
    expect(rows).toHaveLength(2);
    const kinds = rows.map((r: any) => r.kind).sort();
    expect(kinds).toEqual(["dynamic", "static"]);
    const dynRow = rows.find((r: any) => r.kind === "dynamic");
    expect(dynRow.id).toStartWith("dlease-");
    expect(dynRow.path).toBe("db/fake");
    expect(dynRow.provider_type).toBe("fake-mock");
    const stRow = rows.find((r: any) => r.kind === "static");
    expect(stRow.id).toStartWith("lease-");
    expect(stRow.path).toBe("svc/static-token");
  });

  test("GET /v1/lease scopes by identity for non-admin", async () => {
    leases.checkout("svc/static-token", "agent-a", 300);
    await dynamic.checkout("db/fake", "agent-b", 300);

    const res = await app.request("/v1/lease", {
      headers: { "X-Test-Identity": "agent-a" },
    });
    const { leases: rows } = await res.json();
    expect(rows).toHaveLength(1);
    expect(rows[0].identity).toBe("agent-a");
    expect(rows[0].kind).toBe("static");
  });

  test("GET /v1/lease as admin returns all identities", async () => {
    leases.checkout("svc/static-token", "agent-a", 300);
    await dynamic.checkout("db/fake", "agent-b", 300);

    const res = await app.request("/v1/lease", {
      headers: {
        "X-Test-Identity": "admin-1",
        "X-Test-Policies": JSON.stringify(["admin"]),
      },
    });
    const { leases: rows } = await res.json();
    expect(rows).toHaveLength(2);
    const identities = rows.map((r: any) => r.identity).sort();
    expect(identities).toEqual(["agent-a", "agent-b"]);
  });

  test("DELETE /v1/lease/<dlease-...> revokes dynamic via provider", async () => {
    const lease = await dynamic.checkout("db/fake", "agent-a", 300);
    expect(provider.revoked.size).toBe(0);

    const res = await app.request(`/v1/lease/${lease!.lease_id}`, {
      method: "DELETE",
      headers: { "X-Test-Identity": "agent-a" },
    });
    expect(res.status).toBe(200);
    expect(provider.revoked.size).toBe(1);
  });

  test("DELETE /v1/lease/<dlease-...> denies non-owner non-admin", async () => {
    const lease = await dynamic.checkout("db/fake", "agent-a", 300);

    const res = await app.request(`/v1/lease/${lease!.lease_id}`, {
      method: "DELETE",
      headers: { "X-Test-Identity": "agent-b" },
    });
    expect(res.status).toBe(403);
    expect(provider.revoked.size).toBe(0);
  });

  test("DELETE /v1/lease/<lease-...> still revokes static (no regression)", async () => {
    const checkout = leases.checkout("svc/static-token", "agent-a", 300)!;
    const res = await app.request(`/v1/lease/${checkout.lease.id}`, {
      method: "DELETE",
      headers: { "X-Test-Identity": "agent-a" },
    });
    expect(res.status).toBe(200);
    // Confirm it's marked revoked in the manager.
    const after = leases.getLease(checkout.lease.id);
    expect(after?.revoked).toBe(true);
  });

  test("DELETE /v1/lease/<unknown> returns 404 for both prefixes", async () => {
    const r1 = await app.request(`/v1/lease/dlease-nope`, {
      method: "DELETE",
      headers: { "X-Test-Identity": "agent-a" },
    });
    expect(r1.status).toBe(404);
    const r2 = await app.request(`/v1/lease/lease-nope`, {
      method: "DELETE",
      headers: { "X-Test-Identity": "agent-a" },
    });
    expect(r2.status).toBe(404);
  });
});
