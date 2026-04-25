import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { AuditLog } from "../src/audit/logger";
import { DynamicSecretsManager } from "../src/dynamic/manager";
import type { DynamicProvider, DynamicCredential } from "../src/dynamic/provider";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

/**
 * Mock dynamic secrets provider for testing.
 * Creates fake credentials in memory instead of connecting to a real database.
 */
class MockProvider implements DynamicProvider {
  readonly type = "mock";
  created: Map<string, { identity: string; ttl: number }> = new Map();
  revoked: Set<string> = new Set();
  shouldFail = false;

  requiredConfig(): string[] {
    return ["host"];
  }

  async create(
    config: Record<string, string>,
    identity: string,
    ttlSeconds: number
  ): Promise<DynamicCredential> {
    if (this.shouldFail) {
      throw new Error("Mock provider: simulated creation failure");
    }

    const handle = `mock_${crypto.randomUUID().slice(0, 8)}`;
    this.created.set(handle, { identity, ttl: ttlSeconds });

    return {
      credential: {
        username: handle,
        password: "mock-password-" + handle,
        host: config.host,
      },
      revocation_handle: handle,
    };
  }

  async revoke(
    _config: Record<string, string>,
    revocationHandle: string
  ): Promise<void> {
    if (this.shouldFail) {
      throw new Error("Mock provider: simulated revocation failure");
    }
    this.revoked.add(revocationHandle);
    this.created.delete(revocationHandle);
  }

  async validate(
    config: Record<string, string>
  ): Promise<{ ok: boolean; error?: string }> {
    if (this.shouldFail) {
      return { ok: false, error: "Connection failed" };
    }
    if (!config.host) {
      return { ok: false, error: "Missing host" };
    }
    return { ok: true };
  }
}

describe("DynamicSecretsManager", () => {
  let db: Database;
  let audit: AuditLog;
  let manager: DynamicSecretsManager;
  let mockProvider: MockProvider;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-dynamic-"));
    db = initDB(dir);
    audit = new AuditLog(db);
    const testKey = Buffer.from("a".repeat(64), "hex");
    manager = new DynamicSecretsManager(db, audit, testKey);

    // Register mock provider
    mockProvider = new MockProvider();
    manager.registerProvider(mockProvider);
  });

  afterEach(() => {
    manager.stopReaper();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  // Provider registration

  test("lists registered provider types", () => {
    const types = manager.getProviderTypes();
    expect(types).toContain("postgresql");
    expect(types).toContain("mock");
  });

  test("getProvider returns registered provider", () => {
    expect(manager.getProvider("mock")).toBe(mockProvider);
    expect(manager.getProvider("nonexistent")).toBeUndefined();
  });

  // Config CRUD

  test("saveConfig creates a new config", () => {
    const config = manager.saveConfig("db/test-pg", "mock", {
      host: "localhost",
    });
    expect(config.path).toBe("db/test-pg");
    expect(config.provider_type).toBe("mock");
    expect(config.config.host).toBe("localhost");
  });

  test("saveConfig updates existing config", () => {
    manager.saveConfig("db/test-pg", "mock", { host: "host1" });
    const updated = manager.saveConfig("db/test-pg", "mock", {
      host: "host2",
    });
    expect(updated.config.host).toBe("host2");
  });

  test("saveConfig rejects unknown provider", () => {
    expect(() =>
      manager.saveConfig("db/test", "unknown_provider", { host: "x" })
    ).toThrow("Unknown provider type");
  });

  test("saveConfig validates required config keys", () => {
    expect(() =>
      manager.saveConfig("db/test", "mock", {})
    ).toThrow("Missing required config keys");
  });

  test("getConfig returns null for nonexistent path", () => {
    expect(manager.getConfig("nonexistent")).toBeNull();
  });

  test("listConfigs returns all configs", () => {
    manager.saveConfig("db/pg1", "mock", { host: "host1" });
    manager.saveConfig("db/pg2", "mock", { host: "host2" });
    manager.saveConfig("cache/redis", "mock", { host: "host3" });

    const all = manager.listConfigs();
    expect(all).toHaveLength(3);

    const dbOnly = manager.listConfigs("db/");
    expect(dbOnly).toHaveLength(2);
  });

  test("listConfigs does not expose config details", () => {
    manager.saveConfig("db/pg1", "mock", { host: "host1" });
    const configs = manager.listConfigs();
    // Listed configs should not have the config field
    expect((configs[0] as any).config).toBeUndefined();
  });

  test("deleteConfig removes the config", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });
    expect(await manager.deleteConfig("db/test")).toBe(true);
    expect(manager.getConfig("db/test")).toBeNull();
  });

  test("deleteConfig returns false for nonexistent", async () => {
    expect(await manager.deleteConfig("nonexistent")).toBe(false);
  });

  // Checkout (create dynamic credential)

  test("checkout creates a lease with credential", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });

    const lease = await manager.checkout("db/test", "agent-1", 300);
    expect(lease).not.toBeNull();
    expect(lease!.lease_id).toStartWith("dlease-");
    expect(lease!.path).toBe("db/test");
    expect(lease!.identity).toBe("agent-1");
    expect(lease!.credential.username).toBeDefined();
    expect(lease!.credential.password).toBeDefined();
    expect(lease!.credential.host).toBe("localhost");
    expect(lease!.ttl_seconds).toBe(300);
    expect(lease!.provider_type).toBe("mock");
  });

  test("checkout returns null for nonexistent config", async () => {
    const lease = await manager.checkout("nonexistent", "agent-1", 300);
    expect(lease).toBeNull();
  });

  test("checkout creates credential at provider", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });
    const lease = await manager.checkout("db/test", "agent-1", 300);

    // Mock provider should have recorded the creation
    expect(mockProvider.created.has(lease!.revocation_handle)).toBe(true);
    expect(mockProvider.created.get(lease!.revocation_handle)?.identity).toBe(
      "agent-1"
    );
  });

  test("checkout logs to audit", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });
    await manager.checkout("db/test", "agent-1", 300);

    const logs = audit.query({ action: "dynamic.checkout" });
    expect(logs.length).toBe(1);
    expect(logs[0].identity).toBe("agent-1");
    expect(logs[0].path).toBe("db/test");
  });

  test("checkout propagates provider errors", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });
    mockProvider.shouldFail = true;

    await expect(
      manager.checkout("db/test", "agent-1", 300)
    ).rejects.toThrow("simulated creation failure");
  });

  // Lease management

  test("getLease returns active lease", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });
    const lease = await manager.checkout("db/test", "agent-1", 300);

    const retrieved = manager.getLease(lease!.lease_id);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.lease_id).toBe(lease!.lease_id);
  });

  test("getLease returns null for nonexistent", () => {
    expect(manager.getLease("dlease-nonexistent")).toBeNull();
  });

  test("listActiveLeases returns active leases", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });
    await manager.checkout("db/test", "agent-1", 300);
    await manager.checkout("db/test", "agent-2", 600);

    const leases = manager.listActiveLeases("db/test");
    expect(leases).toHaveLength(2);
  });

  test("listActiveLeases filters by path", async () => {
    manager.saveConfig("db/pg1", "mock", { host: "host1" });
    manager.saveConfig("db/pg2", "mock", { host: "host2" });
    await manager.checkout("db/pg1", "agent-1", 300);
    await manager.checkout("db/pg2", "agent-2", 300);

    const pg1Leases = manager.listActiveLeases("db/pg1");
    expect(pg1Leases).toHaveLength(1);
    expect(pg1Leases[0].path).toBe("db/pg1");
  });

  // Revocation

  test("revokeLease calls provider.revoke and marks as revoked", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });
    const lease = await manager.checkout("db/test", "agent-1", 300);
    const handle = lease!.revocation_handle;

    const result = await manager.revokeLease(lease!.lease_id, "agent-1");
    expect(result).toBe(true);

    // Provider should have revoked
    expect(mockProvider.revoked.has(handle)).toBe(true);

    // Lease should no longer be active
    expect(manager.getLease(lease!.lease_id)).toBeNull();
  });

  test("revokeLease returns false for nonexistent", async () => {
    const result = await manager.revokeLease("dlease-nonexistent", "agent-1");
    expect(result).toBe(false);
  });

  test("revokeLease still marks as revoked even if provider fails", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });
    const lease = await manager.checkout("db/test", "agent-1", 300);

    mockProvider.shouldFail = true;

    // Should not throw - should still mark as revoked
    const result = await manager.revokeLease(lease!.lease_id, "agent-1");
    expect(result).toBe(true);
    expect(manager.getLease(lease!.lease_id)).toBeNull();
  });

  test("revokeLease logs to audit", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });
    const lease = await manager.checkout("db/test", "agent-1", 300);

    await manager.revokeLease(lease!.lease_id, "agent-1");

    const logs = audit.query({ action: "dynamic.revoke" });
    expect(logs.length).toBe(1);
    expect(logs[0].lease_id).toBe(lease!.lease_id);
  });

  // Reaper

  test("reapExpired revokes expired leases", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });

    // Create a lease that's already expired (TTL = 0 trick: insert directly)
    const lease = await manager.checkout("db/test", "agent-1", 10);

    // Manually set expires_at to the past
    db.query("UPDATE dynamic_leases SET expires_at = datetime('now', '-1 minute') WHERE id = ?")
      .run(lease!.lease_id);

    const reaped = await manager.reapExpired();
    expect(reaped).toBe(1);

    // Provider should have revoked
    expect(mockProvider.revoked.has(lease!.revocation_handle)).toBe(true);
  });

  test("reapExpired logs to audit", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });
    const lease = await manager.checkout("db/test", "agent-1", 10);

    db.query("UPDATE dynamic_leases SET expires_at = datetime('now', '-1 minute') WHERE id = ?")
      .run(lease!.lease_id);

    await manager.reapExpired();

    const logs = audit.query({ action: "dynamic.reap" });
    expect(logs.length).toBe(1);
    expect(logs[0].metadata.expired_count).toBe("1");
  });

  // Config deletion cascades to leases

  test("deleteConfig revokes active leases first", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });
    const lease = await manager.checkout("db/test", "agent-1", 300);
    const handle = lease!.revocation_handle;

    await manager.deleteConfig("db/test");

    // Should have called provider.revoke
    expect(mockProvider.revoked.has(handle)).toBe(true);
  });

  // Validation

  test("validateConfig returns ok for valid config", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });
    const result = await manager.validateConfig("db/test");
    expect(result.ok).toBe(true);
  });

  test("validateConfig returns error for invalid config", async () => {
    manager.saveConfig("db/test", "mock", { host: "localhost" });
    mockProvider.shouldFail = true;

    const result = await manager.validateConfig("db/test");
    expect(result.ok).toBe(false);
    expect(result.error).toBeDefined();
  });

  test("validateConfig returns error for nonexistent", async () => {
    const result = await manager.validateConfig("nonexistent");
    expect(result.ok).toBe(false);
  });

  // Built-in providers are registered

  test("all built-in providers are registered by default", () => {
    const fresh = new DynamicSecretsManager(db, audit, Buffer.from("a".repeat(64), "hex"));
    const types = fresh.getProviderTypes();
    expect(types).toContain("postgresql");
    expect(types).toContain("mysql");
    expect(types).toContain("mongodb");
    expect(types).toContain("redis");
    expect(types).toContain("ssh-cert");
  });

  test("postgresql provider requires host, database, user, password", () => {
    const pg = manager.getProvider("postgresql")!;
    const required = pg.requiredConfig();
    expect(required).toContain("host");
    expect(required).toContain("database");
    expect(required).toContain("user");
    expect(required).toContain("password");
  });

  test("mysql provider requires host, database, user, password", () => {
    const p = manager.getProvider("mysql")!;
    expect(p.type).toBe("mysql");
    const required = p.requiredConfig();
    expect(required).toContain("host");
    expect(required).toContain("database");
    expect(required).toContain("user");
    expect(required).toContain("password");
  });

  test("mongodb provider requires host, database, user, password", () => {
    const p = manager.getProvider("mongodb")!;
    expect(p.type).toBe("mongodb");
    const required = p.requiredConfig();
    expect(required).toContain("host");
    expect(required).toContain("database");
    expect(required).toContain("user");
    expect(required).toContain("password");
  });

  test("redis provider requires host, password", () => {
    const p = manager.getProvider("redis")!;
    expect(p.type).toBe("redis");
    const required = p.requiredConfig();
    expect(required).toContain("host");
    expect(required).toContain("password");
    expect(required).not.toContain("database");
  });

  test("ssh-cert provider requires ca_private_key", () => {
    const p = manager.getProvider("ssh-cert")!;
    expect(p.type).toBe("ssh-cert");
    const required = p.requiredConfig();
    expect(required).toContain("ca_private_key");
    expect(required).toHaveLength(1);
  });

  test("saveConfig rejects missing required keys for mysql", () => {
    expect(() =>
      manager.saveConfig("db/mysql-test", "mysql", { host: "localhost" })
    ).toThrow("Missing required config keys");
  });

  test("saveConfig rejects missing required keys for ssh-cert", () => {
    expect(() =>
      manager.saveConfig("ssh/test", "ssh-cert", {})
    ).toThrow("Missing required config keys");
  });

  // Config key rotation

  test("rotateConfigKey re-encrypts configs and they remain readable", () => {
    manager.saveConfig("db/rot1", "mock", { host: "host1" });
    manager.saveConfig("db/rot2", "mock", { host: "host2" });

    const newKey = Buffer.from("b".repeat(64), "hex");
    const rotated = manager.rotateConfigKey(newKey);
    expect(rotated).toBe(2);

    // Configs should still be readable
    const c1 = manager.getConfig("db/rot1");
    expect(c1!.config.host).toBe("host1");
    const c2 = manager.getConfig("db/rot2");
    expect(c2!.config.host).toBe("host2");
  });

  test("rotateConfigKey returns 0 for no configs", () => {
    const newKey = Buffer.from("c".repeat(64), "hex");
    expect(manager.rotateConfigKey(newKey)).toBe(0);
  });

  // Public metadata surfaced in listConfigs — advisory routing info agents
  // need at discovery time to pick the right host, without exposing secrets.

  test("listConfigs metadata is empty for unknown provider types", () => {
    manager.saveConfig("x/mock1", "mock", { host: "localhost" });
    const [entry] = manager.listConfigs("x/");
    expect(entry.metadata).toEqual({});
  });

  test("listConfigs metadata exposes postgres routing fields", () => {
    manager.saveConfig("db/pg", "postgresql", {
      host: "pg.lab",
      port: "5433",
      database: "app",
      user: "admin",
      password: "secretpw",
    });
    const [entry] = manager.listConfigs("db/");
    expect(entry.metadata.host).toBe("pg.lab");
    expect(entry.metadata.port).toBe("5433");
    expect(entry.metadata.database).toBe("app");
    // Secrets must NEVER appear in list metadata
    expect(entry.metadata.password).toBeUndefined();
    expect(entry.metadata.user).toBeUndefined();
  });

  test("listConfigs metadata omits empty/missing public keys", () => {
    // redis only needs host; we leave port default to undefined
    manager.saveConfig("cache/r", "redis", {
      host: "redis.lab",
      password: "pw",
    });
    const [entry] = manager.listConfigs("cache/");
    expect(entry.metadata.host).toBe("redis.lab");
    expect(entry.metadata.port).toBeUndefined();
    expect(entry.metadata.password).toBeUndefined();
  });

  test("ssh-cert saveConfig trims whitespace from CSV fields", () => {
    const caDir = mkdtempSync(join(tmpdir(), "gh-ssh-csvtrim-"));
    try {
      const caPath = join(caDir, "ca");
      execSync(`ssh-keygen -t ed25519 -f ${caPath} -N "" -q`);
      const caKey = readFileSync(caPath, "utf-8");

      // Save with deliberately sloppy whitespace and an empty trailing entry.
      manager.saveConfig("ssh/sloppy", "ssh-cert", {
        ca_private_key: caKey,
        principals: "  deploy ,  root,  ,",
        extensions: " permit-pty , permit-port-forwarding ",
        allowed_hosts: "10.0.0.107 ,  10.0.0.108  ",
      });

      const stored = manager.getConfig("ssh/sloppy");
      expect(stored!.config.principals).toBe("deploy,root");
      expect(stored!.config.extensions).toBe("permit-pty,permit-port-forwarding");
      expect(stored!.config.allowed_hosts).toBe("10.0.0.107,10.0.0.108");
    } finally {
      rmSync(caDir, { recursive: true, force: true });
    }
  });

  test("ssh-cert: normalized principals flow into the issued cert", async () => {
    const caDir = mkdtempSync(join(tmpdir(), "gh-ssh-norm-"));
    try {
      const caPath = join(caDir, "ca");
      execSync(`ssh-keygen -t ed25519 -f ${caPath} -N "" -q`);
      const caKey = readFileSync(caPath, "utf-8");

      manager.saveConfig("ssh/clean", "ssh-cert", {
        ca_private_key: caKey,
        principals: " bradley ",
      });
      const lease = await manager.checkout("ssh/clean", "agent", 60);
      expect(lease!.credential.principals).toBe("bradley");

      // Inspect the actual cert principal list - regression catches a
      // future change that signs with an untrimmed principal.
      const workDir = mkdtempSync(join(tmpdir(), "gh-ssh-norm-work-"));
      try {
        const certPath = join(workDir, "k-cert.pub");
        const fs = require("node:fs");
        fs.writeFileSync(certPath, lease!.credential.certificate);
        const out = execSync(`ssh-keygen -L -f ${certPath}`, { encoding: "utf-8" });
        const principalsBlock = out.split(/Principals:\s*\n/)[1].split(/\n[A-Z]/)[0];
        const lines = principalsBlock.split("\n").map((l: string) => l.trim()).filter(Boolean);
        expect(lines).toContain("bradley");
        expect(lines).not.toContain(" bradley");
      } finally {
        rmSync(workDir, { recursive: true, force: true });
      }
    } finally {
      rmSync(caDir, { recursive: true, force: true });
    }
  });

  test("ssh-cert config surfaces allowed_hosts + principals in list metadata", () => {
    // Use a real but throwaway ed25519 CA; we never call checkout here, just
    // save the config so listConfigs can read it back.
    const caDir = mkdtempSync(join(tmpdir(), "gh-ssh-test-ca-"));
    try {
      const caPath = join(caDir, "ca");
      execSync(`ssh-keygen -t ed25519 -f ${caPath} -N "" -q`);
      const caKey = readFileSync(caPath, "utf-8");

      manager.saveConfig("ssh/lab", "ssh-cert", {
        ca_private_key: caKey,
        principals: "deploy,root",
        allowed_hosts: "10.0.0.107,db.lab",
      });

      const [entry] = manager.listConfigs("ssh/");
      expect(entry.provider_type).toBe("ssh-cert");
      expect(entry.metadata.allowed_hosts).toBe("10.0.0.107,db.lab");
      expect(entry.metadata.principals).toBe("deploy,root");
      expect(entry.metadata.ca_private_key).toBeUndefined();
    } finally {
      rmSync(caDir, { recursive: true, force: true });
    }
  });

  test("ssh-cert checkout echoes allowed_hosts in credential", async () => {
    const caDir = mkdtempSync(join(tmpdir(), "gh-ssh-test-ca-"));
    try {
      const caPath = join(caDir, "ca");
      execSync(`ssh-keygen -t ed25519 -f ${caPath} -N "" -q`);
      const caKey = readFileSync(caPath, "utf-8");

      manager.saveConfig("ssh/has-hosts", "ssh-cert", {
        ca_private_key: caKey,
        principals: "deploy",
        allowed_hosts: "10.0.0.107",
      });
      const lease = await manager.checkout("ssh/has-hosts", "test-agent", 60);
      expect(lease).not.toBeNull();
      expect(lease!.credential.allowed_hosts).toBe("10.0.0.107");
      expect(lease!.credential.principals).toBe("deploy");
      expect(lease!.credential.private_key).toContain("PRIVATE KEY");
      expect(lease!.credential.certificate).toContain("ssh-ed25519-cert");
      // usage string should carry the IdentitiesOnly / IdentityAgent hint
      // and the sibling-cert convention.
      expect(lease!.credential.usage).toContain("IdentitiesOnly=yes");
      expect(lease!.credential.usage).toContain("IdentityAgent=none");
      expect(lease!.credential.usage).toContain("-cert.pub");

      // Without allowed_hosts, the field must be absent (not an empty string)
      manager.saveConfig("ssh/no-hosts", "ssh-cert", {
        ca_private_key: caKey,
        principals: "deploy",
      });
      const lease2 = await manager.checkout("ssh/no-hosts", "test-agent", 60);
      expect(lease2!.credential.allowed_hosts).toBeUndefined();
    } finally {
      rmSync(caDir, { recursive: true, force: true });
    }
  });

  // Regression: the certificate must be signed against the SAME public key
  // that we return as private_key. An agent reported a "key/cert mismatch"
  // claim that turned out to be a misreading of the cert's wire format,
  // but the underlying invariant is load-bearing: derive pub from priv,
  // compare to credential.public_key AND to the cert's embedded pubkey.
  test("ssh-cert checkout: private_key, public_key, and certificate are a consistent triple", async () => {
    const caDir = mkdtempSync(join(tmpdir(), "gh-ssh-pair-"));
    try {
      const caPath = join(caDir, "ca");
      execSync(`ssh-keygen -t ed25519 -f ${caPath} -N "" -q`);
      const caKey = readFileSync(caPath, "utf-8");

      manager.saveConfig("ssh/pair", "ssh-cert", {
        ca_private_key: caKey,
        principals: "deploy",
      });
      const lease = await manager.checkout("ssh/pair", "test-agent", 60);
      expect(lease).not.toBeNull();

      // Write priv + cert to disk so we can run ssh-keygen against them.
      const workDir = mkdtempSync(join(tmpdir(), "gh-ssh-pair-work-"));
      try {
        const privPath = join(workDir, "k");
        const certPath = join(workDir, "k-cert.pub");
        const fs = require("node:fs");
        fs.writeFileSync(privPath, lease!.credential.private_key, { mode: 0o600 });
        fs.writeFileSync(certPath, lease!.credential.certificate);

        // Pub derived from the private key.
        const derivedPub = execSync(`ssh-keygen -y -f ${privPath}`, {
          encoding: "utf-8",
        }).trim();
        const derivedFp = execSync(`ssh-keygen -lf ${privPath}`, {
          encoding: "utf-8",
        })
          .trim()
          .split(/\s+/)[1]; // "256 SHA256:... comment (ED25519)"

        // The credential.public_key field must match exactly.
        expect(lease!.credential.public_key.split(/\s+/).slice(0, 2).join(" "))
          .toBe(derivedPub.split(/\s+/).slice(0, 2).join(" "));

        // The cert's embedded pubkey fingerprint (from -L output) must
        // match the derived pubkey fingerprint. Same key => same SHA256.
        const certInspect = execSync(`ssh-keygen -L -f ${certPath}`, {
          encoding: "utf-8",
        });
        const certPubFpMatch = certInspect.match(/Public key:\s+\S+\s+(SHA256:\S+)/);
        expect(certPubFpMatch).not.toBeNull();
        expect(certPubFpMatch![1]).toBe(derivedFp);
      } finally {
        rmSync(workDir, { recursive: true, force: true });
      }
    } finally {
      rmSync(caDir, { recursive: true, force: true });
    }
  });
});
