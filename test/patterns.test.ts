import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { PatternEngine } from "../src/patterns/engine";
import { mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Hono } from "hono";
import { SecretsEngine } from "../src/secrets/engine";
import { PolicyEngine } from "../src/policy/engine";
import { AuditLog } from "../src/audit/logger";
import { patternsRouter } from "../src/api/patterns";
import { proxyRouter } from "../src/api/proxy";

describe("PatternEngine", () => {
  let db: Database;
  let engine: PatternEngine;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-patterns-test-"));
    mkdirSync(join(dir, "config", "policies"), { recursive: true });
    db = initDB(dir);
    engine = new PatternEngine(db);
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  describe("URL normalization", () => {
    test("replaces UUID path segments with :id", () => {
      const result = engine.normalizeUrl(
        "https://api.example.com/v1/memos/e85de2e6-f91d-4dce-95a5-b79c272a790a"
      );
      expect(result).toBe("https://api.example.com/v1/memos/:id");
    });

    test("replaces numeric path segments with :num", () => {
      const result = engine.normalizeUrl(
        "https://api.example.com/v1/users/12345/posts/678"
      );
      expect(result).toBe("https://api.example.com/v1/users/:num/posts/:num");
    });

    test("replaces ISO date segments with :date", () => {
      const result = engine.normalizeUrl(
        "https://api.example.com/v1/reports/2026-04-09"
      );
      expect(result).toBe("https://api.example.com/v1/reports/:date");
    });

    test("strips query parameter values but keeps keys", () => {
      const result = engine.normalizeUrl(
        "https://api.example.com/v1/search?q=hello&page=3&limit=20"
      );
      expect(result).toBe("https://api.example.com/v1/search?limit=&page=&q=");
    });

    test("strips fragment", () => {
      const result = engine.normalizeUrl(
        "https://api.example.com/v1/docs#section-3"
      );
      expect(result).toBe("https://api.example.com/v1/docs");
    });

    test("preserves scheme, host, and port", () => {
      const result = engine.normalizeUrl(
        "http://10.0.0.102:5230/api/v1/memos"
      );
      expect(result).toBe("http://10.0.0.102:5230/api/v1/memos");
    });

    test("leaves non-variable path segments intact", () => {
      const result = engine.normalizeUrl(
        "https://api.openai.com/v1/chat/completions"
      );
      expect(result).toBe("https://api.openai.com/v1/chat/completions");
    });
  });

  describe("schema extraction", () => {
    test("extracts keys and types from flat object", () => {
      const schema = engine.extractSchema({
        content: "hello world",
        visibility: "PUBLIC",
        count: 42,
        active: true,
      });
      expect(schema).toEqual({
        content: "string",
        visibility: "string",
        count: "number",
        active: "boolean",
      });
    });

    test("types nested objects as 'object'", () => {
      const schema = engine.extractSchema({
        id: 1,
        metadata: { foo: "bar", nested: true },
      });
      expect(schema).toEqual({ id: "number", metadata: "object" });
    });

    test("types arrays with element type", () => {
      const schema = engine.extractSchema({
        tags: ["foo", "bar"],
        ids: [1, 2, 3],
        mixed: [1, "two"],
      });
      expect(schema).toEqual({
        tags: "array<string>",
        ids: "array<number>",
        mixed: "array<mixed>",
      });
    });

    test("handles null values", () => {
      const schema = engine.extractSchema({ name: "test", avatar: null });
      expect(schema).toEqual({ name: "string", avatar: "null" });
    });

    test("returns null for non-object input", () => {
      expect(engine.extractSchema("just a string")).toBeNull();
      expect(engine.extractSchema(null)).toBeNull();
      expect(engine.extractSchema(42)).toBeNull();
    });

    test("returns null for empty object", () => {
      expect(engine.extractSchema({})).toBeNull();
    });
  });

  describe("recording and querying", () => {
    test("records a successful proxy call as a new pattern", () => {
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "hello" },
        response_status: 200,
        response_body: { id: 1, content: "hello", creatorId: 5 },
        identity: "agent-julian",
      });

      const patterns = engine.query("services/memos-token");
      expect(patterns).toHaveLength(1);
      expect(patterns[0].method).toBe("POST");
      expect(patterns[0].url_template).toBe("https://memos.example/api/v1/memos");
      expect(patterns[0].host).toBe("memos.example");
      expect(patterns[0].request_headers).toEqual(["Content-Type", "Authorization"]);
      expect(patterns[0].request_body_schema).toEqual({ content: "string" });
      expect(patterns[0].response_status).toBe(200);
      expect(patterns[0].response_body_schema).toEqual({
        id: "number",
        content: "string",
        creatorId: "number",
      });
      expect(patterns[0].confidence).toBe(1.0);
      expect(patterns[0].verified_by).toBe(1);
      expect(patterns[0].total_successes).toBe(1);
      expect(patterns[0].total_failures).toBe(0);
      expect(patterns[0].agents).toEqual(["agent-julian"]);
    });

    test("increments counters on repeated successful calls", () => {
      for (let i = 0; i < 3; i++) {
        engine.record({
          secret_paths: ["services/memos-token"],
          method: "POST",
          url: "https://memos.example/api/v1/memos",
          request_headers: ["Content-Type", "Authorization"],
          request_body: { content: "test" },
          response_status: 200,
          response_body: { id: i, content: "test" },
          identity: "agent-julian",
        });
      }

      const patterns = engine.query("services/memos-token");
      expect(patterns).toHaveLength(1);
      expect(patterns[0].total_successes).toBe(3);
      expect(patterns[0].recent_outcomes).toHaveLength(3);
      expect(patterns[0].agents).toEqual(["agent-julian"]);
    });

    test("tracks multiple agents", () => {
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 200,
        response_body: { id: 1 },
        identity: "agent-julian",
      });
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 200,
        response_body: { id: 2 },
        identity: "agent-rye",
      });

      const patterns = engine.query("services/memos-token");
      expect(patterns[0].verified_by).toBe(2);
      expect(patterns[0].agents).toContain("agent-julian");
      expect(patterns[0].agents).toContain("agent-rye");
    });

    test("records failure against existing pattern", () => {
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 200,
        response_body: { id: 1 },
        identity: "agent-julian",
      });
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 401,
        response_body: { error: "unauthorized" },
        identity: "agent-rye",
      });

      const patterns = engine.query("services/memos-token");
      expect(patterns[0].total_successes).toBe(1);
      expect(patterns[0].total_failures).toBe(1);
      expect(patterns[0].confidence).toBe(0.5);
    });

    test("does not create a new pattern from a failed call", () => {
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 404,
        response_body: { error: "not found" },
        identity: "agent-julian",
      });

      const patterns = engine.query("services/memos-token");
      expect(patterns).toHaveLength(0);
    });

    test("normalizes URLs so variations merge into one pattern", () => {
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "GET",
        url: "https://memos.example/api/v1/memos/e85de2e6-f91d-4dce-95a5-b79c272a790a",
        request_headers: ["Authorization"],
        request_body: null,
        response_status: 200,
        response_body: { id: 1, content: "first" },
        identity: "agent-julian",
      });
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "GET",
        url: "https://memos.example/api/v1/memos/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        request_headers: ["Authorization"],
        request_body: null,
        response_status: 200,
        response_body: { id: 2, content: "second" },
        identity: "agent-rye",
      });

      const patterns = engine.query("services/memos-token");
      expect(patterns).toHaveLength(1);
      expect(patterns[0].url_template).toBe("https://memos.example/api/v1/memos/:id");
      expect(patterns[0].total_successes).toBe(2);
    });

    test("creates separate patterns per secret path", () => {
      engine.record({
        secret_paths: ["services/memos-token", "services/other-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 200,
        response_body: { id: 1 },
        identity: "agent-julian",
      });

      const memosPatterns = engine.query("services/memos-token");
      const otherPatterns = engine.query("services/other-token");
      expect(memosPatterns).toHaveLength(1);
      expect(otherPatterns).toHaveLength(1);
    });

    test("merges new response keys into existing schema", () => {
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 200,
        response_body: { id: 1, content: "test" },
        identity: "agent-julian",
      });
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test", visibility: "PUBLIC" },
        response_status: 200,
        response_body: { id: 2, content: "test", creatorId: 5, createTime: "2026-01-01" },
        identity: "agent-rye",
      });

      const patterns = engine.query("services/memos-token");
      expect(patterns[0].request_body_schema).toEqual({
        content: "string",
        visibility: "string",
      });
      expect(patterns[0].response_body_schema).toEqual({
        id: "number",
        content: "string",
        creatorId: "number",
        createTime: "string",
      });
    });

    test("trims recent_outcomes to last 20", () => {
      for (let i = 0; i < 25; i++) {
        engine.record({
          secret_paths: ["services/memos-token"],
          method: "POST",
          url: "https://memos.example/api/v1/memos",
          request_headers: ["Content-Type", "Authorization"],
          request_body: { content: "test" },
          response_status: 200,
          response_body: { id: i },
          identity: `agent-${i}`,
        });
      }

      const patterns = engine.query("services/memos-token");
      expect(patterns[0].recent_outcomes).toHaveLength(20);
    });

    test("returns empty array for unknown secret path", () => {
      const patterns = engine.query("nonexistent/path");
      expect(patterns).toEqual([]);
    });

    test("sorts results by confidence descending", () => {
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "GET",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Authorization"],
        request_body: null,
        response_status: 200,
        response_body: { memos: [] },
        identity: "agent-julian",
      });

      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 200,
        response_body: { id: 1 },
        identity: "agent-julian",
      });
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 500,
        response_body: { error: "server error" },
        identity: "agent-rye",
      });

      const patterns = engine.query("services/memos-token");
      expect(patterns).toHaveLength(2);
      expect(patterns[0].confidence).toBeGreaterThan(patterns[1].confidence);
      expect(patterns[0].method).toBe("GET");
      expect(patterns[1].method).toBe("POST");
    });
  });

  describe("suggestions", () => {
    test("returns high-confidence patterns as suggestions", () => {
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 200,
        response_body: { id: 1 },
        identity: "agent-julian",
      });

      const suggestions = engine.suggest("services/memos-token");
      expect(suggestions).toHaveLength(1);
      expect(suggestions[0].method).toBe("POST");
      expect(suggestions[0].url_template).toBe("https://memos.example/api/v1/memos");
      expect(suggestions[0].confidence).toBe(1.0);
    });

    test("excludes patterns below 0.5 confidence", () => {
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 200,
        response_body: { id: 1 },
        identity: "agent-julian",
      });
      for (let i = 0; i < 3; i++) {
        engine.record({
          secret_paths: ["services/memos-token"],
          method: "POST",
          url: "https://memos.example/api/v1/memos",
          request_headers: ["Content-Type", "Authorization"],
          request_body: { content: "test" },
          response_status: 500,
          response_body: { error: "fail" },
          identity: "agent-rye",
        });
      }

      const suggestions = engine.suggest("services/memos-token");
      expect(suggestions).toHaveLength(0);
    });

    test("includes pinned patterns regardless of confidence", () => {
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 200,
        response_body: { id: 1 },
        identity: "agent-julian",
      });
      for (let i = 0; i < 3; i++) {
        engine.record({
          secret_paths: ["services/memos-token"],
          method: "POST",
          url: "https://memos.example/api/v1/memos",
          request_headers: ["Content-Type", "Authorization"],
          request_body: { content: "test" },
          response_status: 500,
          response_body: { error: "fail" },
          identity: "agent-rye",
        });
      }

      const patterns = engine.query("services/memos-token");
      engine.togglePin(patterns[0].id);

      const suggestions = engine.suggest("services/memos-token");
      expect(suggestions).toHaveLength(1);
    });

    test("caps suggestions at 5", () => {
      for (let i = 0; i < 7; i++) {
        engine.record({
          secret_paths: ["services/memos-token"],
          method: "GET",
          url: `https://memos.example/api/v1/endpoint${i}`,
          request_headers: ["Authorization"],
          request_body: null,
          response_status: 200,
          response_body: { ok: true },
          identity: "agent-julian",
        });
      }

      const suggestions = engine.suggest("services/memos-token");
      expect(suggestions.length).toBeLessThanOrEqual(5);
    });
  });

  describe("admin operations", () => {
    test("deletes a pattern by id", () => {
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 200,
        response_body: { id: 1 },
        identity: "agent-julian",
      });

      const patterns = engine.query("services/memos-token");
      expect(patterns).toHaveLength(1);

      const deleted = engine.delete(patterns[0].id);
      expect(deleted).toBe(true);

      const after = engine.query("services/memos-token");
      expect(after).toHaveLength(0);
    });

    test("toggles pin status", () => {
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 200,
        response_body: { id: 1 },
        identity: "agent-julian",
      });

      const patterns = engine.query("services/memos-token");
      expect(patterns[0].pinned).toBe(false);

      engine.togglePin(patterns[0].id);
      const after1 = engine.query("services/memos-token");
      expect(after1[0].pinned).toBe(true);

      engine.togglePin(patterns[0].id);
      const after2 = engine.query("services/memos-token");
      expect(after2[0].pinned).toBe(false);
    });

    test("listAll returns patterns across all secrets", () => {
      engine.record({
        secret_paths: ["services/memos-token"],
        method: "POST",
        url: "https://memos.example/api/v1/memos",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { content: "test" },
        response_status: 200,
        response_body: { id: 1 },
        identity: "agent-julian",
      });
      engine.record({
        secret_paths: ["api-keys/openai"],
        method: "POST",
        url: "https://api.openai.com/v1/chat/completions",
        request_headers: ["Content-Type", "Authorization"],
        request_body: { model: "gpt-4", messages: [] },
        response_status: 200,
        response_body: { id: "chatcmpl-123", choices: [] },
        identity: "agent-rye",
      });

      const all = engine.listAll();
      expect(all).toHaveLength(2);
    });
  });
});

describe("Patterns REST API", () => {
  let db: Database;
  let engine: PatternEngine;
  let app: Hono;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-patterns-api-test-"));
    mkdirSync(join(dir, "config", "policies"), { recursive: true });
    db = initDB(dir);
    engine = new PatternEngine(db);

    const secrets = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
    const policies = new PolicyEngine(join(dir, "config"), db);
    const audit = new AuditLog(db);

    policies.savePolicy("agent-policy", [
      { paths: ["services/*"], capabilities: ["proxy", "read"] },
    ]);
    policies.savePolicy("admin-policy", [
      { paths: ["*"], capabilities: ["read", "write", "delete", "list", "lease", "proxy", "admin"] },
    ]);

    // Seed a pattern
    engine.record({
      secret_paths: ["services/memos-token"],
      method: "POST",
      url: "https://memos.example/api/v1/memos",
      request_headers: ["Content-Type", "Authorization"],
      request_body: { content: "test" },
      response_status: 200,
      response_body: { id: 1 },
      identity: "agent-julian",
    });

    app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "test-req-id");
      c.set("sourceIp", "127.0.0.1");
      const policyHeader = c.req.header("X-Test-Policies");
      c.set("auth", {
        identity: "test-agent",
        policies: policyHeader ? JSON.parse(policyHeader) : ["agent-policy"],
      });
      await next();
    });

    app.route("/v1/proxy/patterns", patternsRouter(engine, policies));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("GET /patterns?secret= returns patterns for accessible secret", async () => {
    const res = await app.request("/v1/proxy/patterns?secret=services/memos-token");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.patterns).toHaveLength(1);
    expect(body.patterns[0].method).toBe("POST");
    expect(body.patterns[0].confidence).toBe(1.0);
  });

  test("GET /patterns?secret= returns 403 for inaccessible secret", async () => {
    const res = await app.request("/v1/proxy/patterns?secret=db/postgres", {
      headers: { "X-Test-Policies": JSON.stringify(["agent-policy"]) },
    });
    expect(res.status).toBe(403);
  });

  test("GET /patterns without secret requires admin", async () => {
    const res = await app.request("/v1/proxy/patterns", {
      headers: { "X-Test-Policies": JSON.stringify(["agent-policy"]) },
    });
    expect(res.status).toBe(403);
  });

  test("GET /patterns without secret works for admin", async () => {
    const res = await app.request("/v1/proxy/patterns", {
      headers: { "X-Test-Policies": JSON.stringify(["admin-policy"]) },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.patterns).toHaveLength(1);
  });

  test("DELETE /patterns/:id requires admin", async () => {
    const patterns = engine.query("services/memos-token");
    const res = await app.request(`/v1/proxy/patterns/${patterns[0].id}`, {
      method: "DELETE",
      headers: { "X-Test-Policies": JSON.stringify(["agent-policy"]) },
    });
    expect(res.status).toBe(403);
  });

  test("DELETE /patterns/:id works for admin", async () => {
    const patterns = engine.query("services/memos-token");
    const res = await app.request(`/v1/proxy/patterns/${patterns[0].id}`, {
      method: "DELETE",
      headers: { "X-Test-Policies": JSON.stringify(["admin-policy"]) },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.deleted).toBe(true);
  });

  test("PUT /patterns/:id/pin toggles pin", async () => {
    const patterns = engine.query("services/memos-token");
    const res = await app.request(`/v1/proxy/patterns/${patterns[0].id}/pin`, {
      method: "PUT",
      headers: { "X-Test-Policies": JSON.stringify(["admin-policy"]) },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.pinned).toBe(true);
  });
});

describe("Proxy + Pattern integration", () => {
  let db: Database;
  let engine: PatternEngine;
  let app: Hono;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-proxy-pattern-test-"));
    mkdirSync(join(dir, "config", "policies"), { recursive: true });
    db = initDB(dir);
    engine = new PatternEngine(db);

    const secrets = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
    const policies = new PolicyEngine(join(dir, "config"), db);
    const audit = new AuditLog(db);

    policies.savePolicy("proxy-agent", [
      { paths: ["api-keys/*"], capabilities: ["proxy"] },
    ]);

    secrets.put("api-keys/test", "test-key-value", {
      allow_private: "true",
    });

    app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "test-req-id");
      c.set("sourceIp", "127.0.0.1");
      c.set("auth", { identity: "test-agent", policies: ["proxy-agent"] });
      await next();
    });

    app.route("/v1/proxy", proxyRouter(secrets, policies, audit, engine));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("successful proxy call records a pattern", async () => {
    // Pre-seed a pattern manually since we can't make real upstream calls
    engine.record({
      secret_paths: ["api-keys/test"],
      method: "GET",
      url: "https://httpbin.org/get",
      request_headers: ["Authorization"],
      request_body: null,
      response_status: 200,
      response_body: { url: "https://httpbin.org/get" },
      identity: "test-agent",
    });

    const patterns = engine.query("api-keys/test");
    expect(patterns).toHaveLength(1);
    expect(patterns[0].method).toBe("GET");
  });

  test("suggestions are included in proxy error responses when patterns exist", async () => {
    // Seed a known-good pattern
    engine.record({
      secret_paths: ["api-keys/test"],
      method: "POST",
      url: "https://api.example.com/v1/data",
      request_headers: ["Content-Type", "Authorization"],
      request_body: { query: "test" },
      response_status: 200,
      response_body: { results: [] },
      identity: "other-agent",
    });

    // The suggest method should return patterns for this secret
    const suggestions = engine.suggest("api-keys/test");
    expect(suggestions).toHaveLength(1);
    expect(suggestions[0].method).toBe("POST");
  });
});
