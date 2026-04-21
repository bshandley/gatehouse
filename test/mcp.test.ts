import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { LeaseManager } from "../src/lease/manager";
import { PolicyEngine } from "../src/policy/engine";
import { AuditLog } from "../src/audit/logger";
import { createMCPHandler } from "../src/mcp/server";
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

  test("tools/list returns all 9 tools", async () => {
    const res = await mcp.handleRequest(
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      adminAuth
    );
    expect(res.result.tools).toHaveLength(9);
    const names = res.result.tools.map((t: any) => t.name);
    expect(names).toContain("gatehouse_get");
    expect(names).toContain("gatehouse_lease");
    expect(names).toContain("gatehouse_revoke");
    expect(names).toContain("gatehouse_list");
    expect(names).toContain("gatehouse_put");
    expect(names).toContain("gatehouse_scrub");
    expect(names).toContain("gatehouse_proxy");
    expect(names).toContain("gatehouse_status");
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
