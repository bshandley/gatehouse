import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { LeaseManager } from "../src/lease/manager";
import { AuditLog } from "../src/audit/logger";
import { mkdtempSync, rmSync } from "node:fs";
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
});
