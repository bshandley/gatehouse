import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Hono } from "hono";
import { initDB } from "../src/db/init";
import { AuditLog } from "../src/audit/logger";
import { PolicyEngine } from "../src/policy/engine";
import { SecretsEngine } from "../src/secrets/engine";
import { secretsRouter, bulkSecretsRouter } from "../src/api/secrets";
import { validateListMetadata } from "../src/secrets/metadataValidation";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("validateListMetadata", () => {
  test("passes through metadata with no list keys", () => {
    expect(validateListMetadata({ env: "prod" })).toEqual({ ok: true, metadata: { env: "prod" } });
  });
  test("undefined metadata is fine", () => {
    expect(validateListMetadata(undefined)).toEqual({ ok: true, metadata: undefined });
  });
  test("normalises valid lists and leaves other keys alone", () => {
    const r = validateListMetadata({
      allowed_domains: "api.example.com 10.0.0.50:5230,*.example.org",
      allowed_path_prefixes: "/v1/\n/v2/",
      auto_approve_from_ip: "10.0.0.5,10.0.0.0/24",
      note: "keep  my   spacing, please",
    });
    expect(r).toEqual({
      ok: true,
      metadata: {
        allowed_domains: "api.example.com, 10.0.0.50:5230, *.example.org",
        allowed_path_prefixes: "/v1/, /v2/",
        auto_approve_from_ip: "10.0.0.5, 10.0.0.0/24",
        note: "keep  my   spacing, please",
      },
    });
  });
  test("does not mutate its input", () => {
    const input = { allowed_domains: "a.test b.test" };
    validateListMetadata(input);
    expect(input.allowed_domains).toBe("a.test b.test");
  });
  test("names the key and entry on failure", () => {
    const r = validateListMetadata({ auto_approve_from_ip: "10.0.0.5, office" });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error).toContain("auto_approve_from_ip");
      expect(r.error).toContain("office");
    }
  });
  test("an empty list value is allowed and stays empty", () => {
    expect(validateListMetadata({ allowed_domains: "  " })).toEqual({ ok: true, metadata: { allowed_domains: "" } });
  });
});

describe("secret metadata list validation over HTTP", () => {
  let dir: string;
  let engine: SecretsEngine;
  let app: Hono;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-meta-validate-"));
    const db = initDB(dir);
    const audit = new AuditLog(db);
    engine = new SecretsEngine(db, Buffer.from("b".repeat(64), "hex"));
    const policies = new PolicyEngine(dir);
    engine.put("svc/existing", "v", {});
    app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "test-req-id");
      c.set("sourceIp", "127.0.0.1");
      c.set("auth", { identity: "root", policies: ["admin"] });
      await next();
    });
    app.route("/v1/secrets", secretsRouter(engine, policies, audit));
    app.route("/v1/secrets-bulk", bulkSecretsRouter(engine, policies, audit));
  });

  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const send = (method: string, path: string, body: unknown) =>
    app.request(path, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

  test("POST rejects an invalid allowed_domains entry with 400 and stores nothing", async () => {
    const res = await send("POST", "/v1/secrets/svc/new", { value: "v", metadata: { allowed_domains: "https://api.example.com" } });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain("allowed_domains");
    expect(body.error).toContain("https://api.example.com");
    expect(engine.getMeta("svc/new")).toBeNull();
  });

  test("POST normalises a space-separated list", async () => {
    const res = await send("POST", "/v1/secrets/svc/new", { value: "v", metadata: { auto_approve_from_ip: "10.0.0.5 10.0.0.6" } });
    expect(res.status).toBe(201);
    expect(engine.getMeta("svc/new")!.metadata.auto_approve_from_ip).toBe("10.0.0.5, 10.0.0.6");
  });

  test("PATCH rejects an invalid path prefix with 400 and keeps the old metadata", async () => {
    const res = await send("PATCH", "/v1/secrets/svc/existing", { metadata: { allowed_path_prefixes: "v1" } });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toContain("allowed_path_prefixes");
    expect(engine.getMeta("svc/existing")!.metadata.allowed_path_prefixes).toBeUndefined();
  });

  test("PATCH normalises valid lists", async () => {
    const res = await send("PATCH", "/v1/secrets/svc/existing", { metadata: { allowed_domains: "a.test,b.test:8443" } });
    expect(res.status).toBe(200);
    expect(engine.getMeta("svc/existing")!.metadata.allowed_domains).toBe("a.test, b.test:8443");
  });

  test("bulk import rejects the whole batch when one item has an invalid list", async () => {
    const res = await send("POST", "/v1/secrets-bulk", {
      secrets: [
        { path: "svc/a", value: "1", metadata: { allowed_domains: "a.test" } },
        { path: "svc/b", value: "2", metadata: { auto_approve_from_ip: "nope" } },
      ],
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain("svc/b");
    expect(body.error).toContain("auto_approve_from_ip");
    expect(engine.getMeta("svc/a")).toBeNull();
  });
});
