import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { LeaseManager } from "../src/lease/manager";
import { PolicyEngine } from "../src/policy/engine";
import { AuditLog } from "../src/audit/logger";
import { createMCPHandler } from "../src/mcp/server";
import { DynamicSecretsManager } from "../src/dynamic/manager";
import type { DynamicProvider, DynamicCredential } from "../src/dynamic/provider";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AuthContext } from "../src/auth/middleware";

describe("MCP Server", () => {
  let mcp: ReturnType<typeof createMCPHandler>;
  let secrets: SecretsEngine;
  let audit: AuditLog;
  let dir: string;

  const adminAuth: AuthContext = {
    identity: "test-admin",
    policies: ["admin"],
    source: "root",
  };

  const readonlyAuth: AuthContext = {
    identity: "readonly-agent",
    policies: ["readonly"],
    source: "user",
  };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-mcp-"));
    const configDir = join(dir, "config");
    mkdirSync(join(configDir, "policies"), { recursive: true });
    writeFileSync(
      join(configDir, "policies", "test.yaml"),
      `name: readonly
rules:
  - path: "api-keys/*"
    capabilities: [read, lease, list]
`
    );

    const db = initDB(dir);
    audit = new AuditLog(db);
    secrets = new SecretsEngine(db, Buffer.from("b".repeat(64), "hex"));
    const leases = new LeaseManager(db, secrets, audit);
    const policies = new PolicyEngine(configDir);
    mcp = createMCPHandler(secrets, leases, policies, audit);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  // Protocol tests
  test("initialize returns server info", async () => {
    const res = await mcp.handleRequest(
      { jsonrpc: "2.0", id: 1, method: "initialize" },
      adminAuth
    );
    expect(res.result.serverInfo.name).toBe("gatehouse");
    const { VERSION } = await import("../src/version");
    expect(res.result.serverInfo.version).toBe(VERSION);
    expect(res.result.protocolVersion).toBe("2024-11-05");
    expect(res.result.capabilities.tools).toBeDefined();
  });

  test("tools/list returns all 10 tools", async () => {
    const res = await mcp.handleRequest(
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      adminAuth
    );
    expect(res.result.tools).toHaveLength(10);
    const names = res.result.tools.map((t: any) => t.name);
    expect(names).toContain("gatehouse_get");
    expect(names).toContain("gatehouse_lease");
    expect(names).toContain("gatehouse_checkout");
    expect(names).toContain("gatehouse_revoke");
    expect(names).toContain("gatehouse_list");
    expect(names).toContain("gatehouse_put");
    expect(names).toContain("gatehouse_scrub");
    expect(names).toContain("gatehouse_proxy");
    expect(names).toContain("gatehouse_status");
    expect(names).toContain("gatehouse_patterns");
  });

  test("ping returns empty result", async () => {
    const res = await mcp.handleRequest(
      { jsonrpc: "2.0", id: 1, method: "ping" },
      adminAuth
    );
    expect(res.result).toEqual({});
  });

  test("unknown method returns error", async () => {
    const res = await mcp.handleRequest(
      { jsonrpc: "2.0", id: 1, method: "unknown/method" },
      adminAuth
    );
    expect(res.error).toBeDefined();
    expect(res.error!.code).toBe(-32601);
  });

  // Tool call tests
  test("gatehouse_put stores a secret", async () => {
    const result = await mcp.handleToolCall(
      "gatehouse_put",
      { path: "api-keys/test", value: "secret123", metadata: { env: "test" } },
      adminAuth
    );
    expect(result.content[0].text).toContain("api-keys/test");
    expect(result.content[0].text).toContain("version 1");
    expect(result.isError).toBeUndefined();
  });

  test("gatehouse_get retrieves a secret", async () => {
    await mcp.handleToolCall(
      "gatehouse_put",
      { path: "api-keys/test", value: "secret123" },
      adminAuth
    );
    const result = await mcp.handleToolCall(
      "gatehouse_get",
      { path: "api-keys/test" },
      adminAuth
    );
    expect(result.content[0].text).toBe("secret123");
  });

  test("gatehouse_get returns error for missing secret", async () => {
    const result = await mcp.handleToolCall(
      "gatehouse_get",
      { path: "nonexistent" },
      adminAuth
    );
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  test("gatehouse_list returns secrets metadata", async () => {
    await mcp.handleToolCall(
      "gatehouse_put",
      { path: "api-keys/a", value: "v1" },
      adminAuth
    );
    await mcp.handleToolCall(
      "gatehouse_put",
      { path: "api-keys/b", value: "v2" },
      adminAuth
    );
    const result = await mcp.handleToolCall(
      "gatehouse_list",
      { prefix: "api-keys/" },
      adminAuth
    );
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveLength(2);
    expect(parsed[0]).toHaveProperty("path");
    expect(parsed[0]).not.toHaveProperty("value");
    expect(parsed[0].kind).toBe("static");
  });

  test("gatehouse_lease creates a lease and returns value", async () => {
    await mcp.handleToolCall(
      "gatehouse_put",
      { path: "api-keys/test", value: "secret123" },
      adminAuth
    );
    const result = await mcp.handleToolCall(
      "gatehouse_lease",
      { path: "api-keys/test", ttl: 60 },
      adminAuth
    );
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.value).toBe("secret123");
    expect(parsed.lease_id).toStartWith("lease-");
    expect(parsed.ttl_seconds).toBe(60);
  });

  test("gatehouse_lease returns error for missing secret", async () => {
    const result = await mcp.handleToolCall(
      "gatehouse_lease",
      { path: "nonexistent" },
      adminAuth
    );
    expect(result.isError).toBe(true);
  });

  test("gatehouse_revoke revokes a lease", async () => {
    await mcp.handleToolCall(
      "gatehouse_put",
      { path: "api-keys/test", value: "secret123" },
      adminAuth
    );
    const leaseResult = await mcp.handleToolCall(
      "gatehouse_lease",
      { path: "api-keys/test" },
      adminAuth
    );
    const { lease_id } = JSON.parse(leaseResult.content[0].text);
    const revokeResult = await mcp.handleToolCall(
      "gatehouse_revoke",
      { lease_id },
      adminAuth
    );
    expect(revokeResult.content[0].text).toContain("revoked");
  });

  test("gatehouse_revoke returns error for unknown lease", async () => {
    const result = await mcp.handleToolCall(
      "gatehouse_revoke",
      { lease_id: "lease-nonexistent" },
      adminAuth
    );
    expect(result.isError).toBe(true);
  });

  test("gatehouse_scrub redacts credentials", async () => {
    const result = await mcp.handleToolCall(
      "gatehouse_scrub",
      { text: "key: sk-proj-abc123def456ghi789jkl012mno" },
      adminAuth
    );
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.redaction_count).toBeGreaterThan(0);
    expect(parsed.scrubbed).toContain("***REDACTED***");
  });

  test("gatehouse_scrub handles clean text", async () => {
    const result = await mcp.handleToolCall(
      "gatehouse_scrub",
      { text: "just normal text" },
      adminAuth
    );
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.redaction_count).toBe(0);
    expect(parsed.scrubbed).toBe("just normal text");
  });

  test("gatehouse_status returns identity and health", async () => {
    const result = await mcp.handleToolCall("gatehouse_status", {}, adminAuth);
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.identity).toBe("test-admin");
    expect(parsed.status).toBe("ok");
    expect(parsed.policies).toContain("admin");
  });

  test("unknown tool returns error", async () => {
    const result = await mcp.handleToolCall("nonexistent_tool", {}, adminAuth);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown tool");
  });

  // Authorization tests
  test("denies read on unauthorized path", async () => {
    await mcp.handleToolCall(
      "gatehouse_put",
      { path: "api-keys/test", value: "secret" },
      adminAuth
    );
    const result = await mcp.handleToolCall(
      "gatehouse_get",
      { path: "api-keys/test" },
      readonlyAuth
    );
    // readonly has read on api-keys/*, so this should succeed
    expect(result.isError).toBeUndefined();
  });

  test("denies write for readonly policy", async () => {
    const result = await mcp.handleToolCall(
      "gatehouse_put",
      { path: "api-keys/new", value: "val" },
      readonlyAuth
    );
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Access denied");
  });

  test("denies lease revocation by non-owner non-admin", async () => {
    await mcp.handleToolCall(
      "gatehouse_put",
      { path: "api-keys/test", value: "secret" },
      adminAuth
    );
    const leaseResult = await mcp.handleToolCall(
      "gatehouse_lease",
      { path: "api-keys/test" },
      adminAuth
    );
    const { lease_id } = JSON.parse(leaseResult.content[0].text);

    const revokeResult = await mcp.handleToolCall(
      "gatehouse_revoke",
      { lease_id },
      readonlyAuth
    );
    expect(revokeResult.isError).toBe(true);
    expect(revokeResult.content[0].text).toContain("Access denied");
  });

  // Source IP propagation: audit rows from MCP tool calls must record
  // the caller's IP, same as HTTP-path audit rows.
  test("MCP tool calls record source_ip in audit log", async () => {
    await mcp.handleToolCall(
      "gatehouse_put",
      { path: "api-keys/test", value: "val" },
      adminAuth,
      "10.9.8.7"
    );
    await mcp.handleToolCall(
      "gatehouse_get",
      { path: "api-keys/test" },
      adminAuth,
      "10.9.8.7"
    );
    await mcp.handleRequest(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "gatehouse_list", arguments: {} },
      },
      adminAuth,
      "10.9.8.7"
    );
    const rows = audit.query({ limit: 10 });
    const mcpRows = rows.filter((r) => r.action.endsWith(".mcp"));
    expect(mcpRows.length).toBeGreaterThanOrEqual(3);
    for (const r of mcpRows) {
      expect(r.source_ip).toBe("10.9.8.7");
    }
  });

  // tools/call via handleRequest
  test("tools/call via handleRequest works", async () => {
    await mcp.handleToolCall(
      "gatehouse_put",
      { path: "api-keys/test", value: "val" },
      adminAuth
    );
    const res = await mcp.handleRequest(
      {
        jsonrpc: "2.0",
        id: 42,
        method: "tools/call",
        params: { name: "gatehouse_get", arguments: { path: "api-keys/test" } },
      },
      adminAuth
    );
    expect(res.id).toBe(42);
    expect(res.result.content[0].text).toBe("val");
  });
});

/**
 * Minimal dynamic provider that mints a fake SSH-cert-shaped credential
 * without talking to a real host. Used to exercise gatehouse_checkout and
 * the dynamic branch of gatehouse_list and gatehouse_revoke.
 */
class FakeSSHProvider implements DynamicProvider {
  readonly type = "fake-ssh";
  revoked: Set<string> = new Set();

  requiredConfig(): string[] {
    return ["host"];
  }

  async create(
    config: Record<string, string>,
    identity: string,
    ttlSeconds: number
  ): Promise<DynamicCredential> {
    const handle = `fake-ssh-${crypto.randomUUID().slice(0, 8)}`;
    return {
      credential: {
        username: identity,
        private_key: `-----BEGIN FAKE KEY-----\n${handle}\n-----END FAKE KEY-----`,
        host: config.host,
        ttl_seconds: String(ttlSeconds),
      },
      revocation_handle: handle,
    };
  }

  async revoke(
    _config: Record<string, string>,
    revocationHandle: string
  ): Promise<void> {
    this.revoked.add(revocationHandle);
  }

  async validate(): Promise<{ ok: boolean; error?: string }> {
    return { ok: true };
  }
}

describe("MCP Server - dynamic secrets", () => {
  let mcp: ReturnType<typeof createMCPHandler>;
  let secrets: SecretsEngine;
  let audit: AuditLog;
  let dynamic: DynamicSecretsManager;
  let fakeProvider: FakeSSHProvider;
  let dir: string;

  const dynAgentAuth: AuthContext = {
    identity: "dyn-agent",
    policies: ["homelab-ssh-user"],
    source: "approle",
  };

  const adminAuth: AuthContext = {
    identity: "test-admin",
    policies: ["admin"],
    source: "root",
  };

  const strangerAuth: AuthContext = {
    identity: "stranger",
    policies: ["homelab-ssh-user"],
    source: "approle",
  };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-mcp-dyn-"));
    const configDir = join(dir, "config");
    mkdirSync(join(configDir, "policies"), { recursive: true });
    writeFileSync(
      join(configDir, "policies", "homelab-ssh-user.yaml"),
      `name: homelab-ssh-user
rules:
  - path: "ssh/*"
    capabilities: [lease]
`
    );

    const db = initDB(dir);
    audit = new AuditLog(db);
    const masterKey = Buffer.from("c".repeat(64), "hex");
    secrets = new SecretsEngine(db, masterKey);
    const leases = new LeaseManager(db, secrets, audit);
    const policies = new PolicyEngine(configDir);
    dynamic = new DynamicSecretsManager(db, audit, masterKey);
    fakeProvider = new FakeSSHProvider();
    dynamic.registerProvider(fakeProvider);

    // Seed a dynamic ssh config
    dynamic.saveConfig("ssh/lab", "fake-ssh", { host: "10.0.0.50" });

    mcp = createMCPHandler(secrets, leases, policies, audit, undefined, dynamic);
  });

  afterEach(() => {
    dynamic.stopReaper();
    rmSync(dir, { recursive: true, force: true });
  });

  test("gatehouse_list merges dynamic configs with kind: 'dynamic'", async () => {
    // Also put a static secret the agent CAN'T see (no policy) and one at
    // an ssh/* path that still should not show up unless stored as dynamic.
    await mcp.handleToolCall(
      "gatehouse_put",
      { path: "api-keys/hidden", value: "nope" },
      adminAuth
    );

    const result = await mcp.handleToolCall(
      "gatehouse_list",
      {},
      dynAgentAuth
    );
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].path).toBe("ssh/lab");
    expect(parsed[0].kind).toBe("dynamic");
    expect(parsed[0].provider_type).toBe("fake-ssh");
    expect(parsed[0].caps).toContain("lease");
    expect(parsed[0]).not.toHaveProperty("value");
    // Every dynamic entry carries a metadata object (possibly empty for
    // unknown provider types). Agents rely on this for routing fields
    // like allowed_hosts / host.
    expect(parsed[0].metadata).toEqual({});
  });

  test("gatehouse_list with kind:'dynamic' omits pattern_count/top_pattern", async () => {
    const result = await mcp.handleToolCall(
      "gatehouse_list",
      { prefix: "ssh/" },
      dynAgentAuth
    );
    const [entry] = JSON.parse(result.content[0].text);
    expect(entry.kind).toBe("dynamic");
    expect(entry).not.toHaveProperty("pattern_count");
    expect(entry).not.toHaveProperty("top_pattern");
    // Dynamic entries DO carry a metadata object (routing info like
    // allowed_hosts / host); it's the static-only shape-specific
    // `pattern_count` and `top_pattern` that should be absent.
    expect(entry.metadata).toBeDefined();
  });

  test("gatehouse_checkout mints a dynamic credential", async () => {
    const result = await mcp.handleToolCall(
      "gatehouse_checkout",
      { path: "ssh/lab", ttl: 120 },
      dynAgentAuth
    );
    expect(result.isError).toBeUndefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.lease_id).toStartWith("dlease-");
    expect(parsed.path).toBe("ssh/lab");
    expect(parsed.provider_type).toBe("fake-ssh");
    expect(parsed.ttl_seconds).toBe(120);
    expect(parsed.credential.username).toBe("dyn-agent");
    expect(parsed.credential.host).toBe("10.0.0.50");
    expect(parsed.credential.private_key).toContain("FAKE KEY");
  });

  test("gatehouse_checkout denies without lease capability", async () => {
    const noLeaseAuth: AuthContext = {
      identity: "nope",
      policies: ["policy-that-does-not-exist"],
      source: "approle",
    };
    const result = await mcp.handleToolCall(
      "gatehouse_checkout",
      { path: "ssh/lab" },
      noLeaseAuth
    );
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Access denied");
    expect(result.content[0].text).toContain("lease");
  });

  test("gatehouse_checkout errors on unknown dynamic path", async () => {
    const result = await mcp.handleToolCall(
      "gatehouse_checkout",
      { path: "ssh/nonexistent" },
      dynAgentAuth
    );
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  test("gatehouse_revoke works on dynamic lease_id", async () => {
    const checkout = await mcp.handleToolCall(
      "gatehouse_checkout",
      { path: "ssh/lab" },
      dynAgentAuth
    );
    const { lease_id } = JSON.parse(checkout.content[0].text);

    const revoke = await mcp.handleToolCall(
      "gatehouse_revoke",
      { lease_id },
      dynAgentAuth
    );
    expect(revoke.isError).toBeUndefined();
    expect(revoke.content[0].text).toContain("revoked");
    // Provider should have seen the revocation
    expect(fakeProvider.revoked.size).toBe(1);
  });

  test("gatehouse_revoke denies non-owner non-admin for dynamic lease", async () => {
    const checkout = await mcp.handleToolCall(
      "gatehouse_checkout",
      { path: "ssh/lab" },
      dynAgentAuth
    );
    const { lease_id } = JSON.parse(checkout.content[0].text);

    const revoke = await mcp.handleToolCall(
      "gatehouse_revoke",
      { lease_id },
      strangerAuth
    );
    expect(revoke.isError).toBe(true);
    expect(revoke.content[0].text).toContain("Access denied");
  });

  test("gatehouse_checkout errors if dynamic manager is absent", async () => {
    const configDir = join(dir, "config");
    const db2 = initDB(join(dir, "x"));
    const audit2 = new AuditLog(db2);
    const masterKey = Buffer.from("d".repeat(64), "hex");
    const secrets2 = new SecretsEngine(db2, masterKey);
    const leases2 = new LeaseManager(db2, secrets2, audit2);
    const policies2 = new PolicyEngine(configDir);
    const mcpNoDyn = createMCPHandler(
      secrets2,
      leases2,
      policies2,
      audit2
      // no dynamic manager
    );

    const result = await mcpNoDyn.handleToolCall(
      "gatehouse_checkout",
      { path: "ssh/lab" },
      dynAgentAuth
    );
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not available");
  });

  test("gatehouse_list surfaces ssh-cert allowed_hosts in metadata", async () => {
    // Seed an ssh-cert config with a real CA + allowed_hosts so the
    // provider-type lookup in listConfigs finds it in PUBLIC_CONFIG_KEYS.
    const { execSync } = await import("node:child_process");
    const { readFileSync, mkdtempSync, rmSync } = await import("node:fs");
    const caDir = mkdtempSync(join(tmpdir(), "gh-mcp-ca-"));
    try {
      const caPath = join(caDir, "ca");
      execSync(`ssh-keygen -t ed25519 -f ${caPath} -N "" -q`);
      const caKey = readFileSync(caPath, "utf-8");
      dynamic.saveConfig("ssh/real", "ssh-cert", {
        ca_private_key: caKey,
        principals: "bradley",
        allowed_hosts: "10.0.0.107,db.lab",
      });

      const result = await mcp.handleToolCall(
        "gatehouse_list",
        { prefix: "ssh/real" },
        dynAgentAuth
      );
      const [entry] = JSON.parse(result.content[0].text);
      expect(entry.path).toBe("ssh/real");
      expect(entry.kind).toBe("dynamic");
      expect(entry.provider_type).toBe("ssh-cert");
      expect(entry.metadata.allowed_hosts).toBe("10.0.0.107,db.lab");
      expect(entry.metadata.principals).toBe("bradley");
      expect(entry.metadata.ca_private_key).toBeUndefined();
    } finally {
      rmSync(caDir, { recursive: true, force: true });
    }
  });

  test("tools/list advertises gatehouse_checkout with schema", async () => {
    const res = await mcp.handleRequest(
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      dynAgentAuth
    );
    const checkout = res.result.tools.find(
      (t: any) => t.name === "gatehouse_checkout"
    );
    expect(checkout).toBeDefined();
    expect(checkout.inputSchema.required).toContain("path");
    expect(checkout.description).toContain("dynamic");
  });
});
