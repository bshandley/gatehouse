import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Hono } from "hono";
import { initDB } from "../src/db/init";
import { AuditLog } from "../src/audit/logger";
import { PolicyEngine } from "../src/policy/engine";
import { SecretsEngine } from "../src/secrets/engine";
import { secretsRouter, bulkSecretsRouter } from "../src/api/secrets";
import { validateListMetadata, validateSecretMetadata } from "../src/secrets/metadataValidation";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
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

describe("validateSecretMetadata (passthrough keys)", () => {
  const ok = (m: Record<string, string>) => validateSecretMetadata(m);
  const U = "https://api.example.com";

  test("keeps list validation", () => {
    const r = validateSecretMetadata({ allowed_domains: "a.test,b.test" });
    expect(r).toEqual({ ok: true, metadata: { allowed_domains: "a.test, b.test" } });
    expect(validateSecretMetadata({ allowed_domains: "https://x" }).ok).toBe(false);
  });

  test("accepts a valid pair, with and without a path prefix", () => {
    expect(ok({ passthrough_alias: "example", upstream_url: U }).ok).toBe(true);
    expect(ok({ passthrough_alias: "a1-b2", upstream_url: `${U}/v1/prefix` }).ok).toBe(true);
    expect(ok({ passthrough_alias: "x", upstream_url: "http://api.example.com:8080/" }).ok).toBe(true);
  });

  test("rejects bad alias formats", () => {
    for (const a of ["Example", "-lead", "a".repeat(64), "has_underscore", "sp ace"]) {
      const r = ok({ passthrough_alias: a, upstream_url: U });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error).toContain("passthrough_alias");
    }
    expect(ok({ passthrough_alias: "a".repeat(63), upstream_url: U }).ok).toBe(true);
  });

  test("empty alias counts as absent", () => {
    expect(ok({ passthrough_alias: "", upstream_url: U }).ok).toBe(false);
    expect(ok({ passthrough_alias: "", upstream_url: "" }).ok).toBe(true);
    expect(ok({ passthrough_alias: "", env: "x" }).ok).toBe(true);
  });

  test("both or neither", () => {
    const a = ok({ passthrough_alias: "example" });
    expect(a.ok).toBe(false);
    if (!a.ok) expect(a.error).toContain("upstream_url");
    const b = ok({ upstream_url: U });
    expect(b.ok).toBe(false);
    if (!b.ok) expect(b.error).toContain("passthrough_alias");
  });

  test("rejects unsafe or malformed upstream_url", () => {
    for (const u of [
      `${U}/x?a=1`,
      `${U}/x#frag`,
      "https://user:pw@api.example.com",
      "https://user@api.example.com",
      "ftp://api.example.com",
      "/relative/path",
      "api.example.com",
      "https://api.example.com\\evil.test",
      "https://api.example.com/a b",
    ]) {
      const r = ok({ passthrough_alias: "example", upstream_url: u });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error).toContain("upstream_url");
    }
  });

  test("rejects non-canonical or dangerous upstream_url forms", () => {
    for (const u of [
      "http:example.com",
      "http:/example.com",
      "http:///x",
      "https://",
      "https://api.example.com:0",
      "https://api.example.com./v1",
      `${U}/a/../b`,
      `${U}/./b`,
      `${U}/a/%2e%2e/b`,
      `${U}/a/%2E/b`,
      `${U}/a%2fb`,
      `${U}/a%2Fb`,
      `${U}/a%5cb`,
      `${U}/a%5Cb`,
      `${U}/%zz`,
    ]) {
      const r = ok({ passthrough_alias: "example", upstream_url: u });
      expect(r.ok).toBe(false);
    }
  });

  test("stores the canonical upstream_url", () => {
    const canon = (u: string) => {
      const r = ok({ passthrough_alias: "example", upstream_url: u });
      if (!r.ok) throw new Error(r.error);
      return r.metadata.upstream_url;
    };
    expect(canon("HTTPS://API.Example.com/v1/")).toBe("https://api.example.com/v1");
    expect(canon("https://api.example.com/")).toBe("https://api.example.com");
    expect(canon("https://api.example.com")).toBe("https://api.example.com");
    expect(canon("https://api.example.com:443/v1")).toBe("https://api.example.com/v1");
    expect(canon("http://api.example.com:80")).toBe("http://api.example.com");
    expect(canon("https://api.example.com:8443/Mixed/Case")).toBe("https://api.example.com:8443/Mixed/Case");
  });

  test("IP literal hosts are accepted", () => {
    const v6 = ok({ passthrough_alias: "example", upstream_url: "http://[::1]:8080/x" });
    expect(v6.ok && v6.metadata.upstream_url).toBe("http://[::1]:8080/x");
    expect(ok({ passthrough_alias: "example", upstream_url: "http://10.0.0.5:9000" }).ok).toBe(true);
    expect(ok({ passthrough_alias: "example", upstream_url: "http://127.0.0.1" }).ok).toBe(true);
  });

  test("allowed_domains is checked against the canonical host", () => {
    expect(ok({ passthrough_alias: "example", upstream_url: "https://API.Example.com", allowed_domains: "example.com" }).ok).toBe(true);
  });

  test("allowed_domains must admit the upstream host", () => {
    const bad = ok({ passthrough_alias: "example", upstream_url: U, allowed_domains: "other.test" });
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.error).toContain("allowed_domains");
    expect(ok({ passthrough_alias: "example", upstream_url: U, allowed_domains: "example.com" }).ok).toBe(true);
    expect(ok({ passthrough_alias: "example", upstream_url: U, allowed_domains: "other.test, api.example.com" }).ok).toBe(true);
    expect(ok({ passthrough_alias: "example", upstream_url: U, allowed_domains: "" }).ok).toBe(true);
  });

  test("does not mutate its input", () => {
    const input = { passthrough_alias: "example", upstream_url: U };
    validateSecretMetadata(input);
    expect(input).toEqual({ passthrough_alias: "example", upstream_url: U });
  });
});

describe("passthrough alias uniqueness over HTTP", () => {
  let dir: string;
  let engine: SecretsEngine;
  let app: Hono;
  const A = { passthrough_alias: "example", upstream_url: "https://api.example.com" };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-alias-"));
    mkdirSync(join(dir, "policies"), { recursive: true });
    writeFileSync(
      join(dir, "policies", "narrow.yaml"),
      `name: narrow\nrules:\n  - path: "mine/*"\n    capabilities: [read, write, list]\n`
    );
    const db = initDB(dir);
    const audit = new AuditLog(db);
    engine = new SecretsEngine(db, Buffer.from("b".repeat(64), "hex"));
    const policies = new PolicyEngine(dir);
    app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "test-req-id");
      c.set("sourceIp", "127.0.0.1");
      const h = c.req.header("X-Test-Policies");
      c.set("auth", { identity: "t", policies: h ? JSON.parse(h) : ["admin"] });
      await next();
    });
    app.route("/v1/secrets", secretsRouter(engine, policies, audit));
    app.route("/v1/secrets-bulk", bulkSecretsRouter(engine, policies, audit));
  });

  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const send = (method: string, path: string, body: unknown, policies?: string[]) =>
    app.request(path, {
      method,
      headers: { "Content-Type": "application/json", ...(policies ? { "X-Test-Policies": JSON.stringify(policies) } : {}) },
      body: JSON.stringify(body),
    });

  test("POST duplicate alias is 409 and stores nothing", async () => {
    engine.put("svc/one", "v", A);
    const res = await send("POST", "/v1/secrets/svc/two", { value: "v", metadata: A });
    expect(res.status).toBe(409);
    expect(engine.getMeta("svc/two")).toBeNull();
  });

  test("POST that rewrites a secret's own alias is allowed", async () => {
    engine.put("svc/one", "v", A);
    const res = await send("POST", "/v1/secrets/svc/one", { value: "v2", metadata: A });
    expect(res.status).toBe(201);
    expect(engine.findByAlias("example")!.path).toBe("svc/one");
  });

  test("PATCH onto an existing alias is 409, keeping own alias is 200", async () => {
    engine.put("svc/one", "v", A);
    engine.put("svc/two", "v", {});
    const dup = await send("PATCH", "/v1/secrets/svc/two", { metadata: A });
    expect(dup.status).toBe(409);
    expect(engine.getMeta("svc/two")!.metadata).toEqual({});
    const own = await send("PATCH", "/v1/secrets/svc/one", { metadata: { ...A, env: "prod" } });
    expect(own.status).toBe(200);
  });

  test("PATCH replaces metadata: dropping only one passthrough key is rejected", async () => {
    engine.put("svc/one", "v", A);
    const res = await send("PATCH", "/v1/secrets/svc/one", { metadata: { passthrough_alias: "example" } });
    expect(res.status).toBe(400);
    expect(engine.getMeta("svc/one")!.metadata).toEqual(A);
  });

  test("409 names the other path only when the writer can list it", async () => {
    engine.put("svc/one", "v", A);
    const admin = await send("POST", "/v1/secrets/mine/two", { value: "v", metadata: A });
    expect(admin.status).toBe(409);
    expect((await admin.json()).error).toContain("svc/one");

    const narrow = await send("POST", "/v1/secrets/mine/two", { value: "v", metadata: A }, ["narrow"]);
    expect(narrow.status).toBe(409);
    const body = await narrow.json();
    expect(body.error).toBe("passthrough_alias is already in use");
    expect(body.error).not.toContain("svc/one");
  });

  test("bulk import with an internal duplicate imports nothing", async () => {
    const res = await send("POST", "/v1/secrets-bulk", {
      secrets: [
        { path: "svc/a", value: "1", metadata: A },
        { path: "svc/b", value: "2", metadata: A },
      ],
    });
    expect(res.status).toBe(409);
    expect(engine.getMeta("svc/a")).toBeNull();
    expect(engine.getMeta("svc/b")).toBeNull();
  });

  test("bulk import conflicting with a stored alias imports nothing", async () => {
    engine.put("svc/one", "v", A);
    const res = await send("POST", "/v1/secrets-bulk", {
      secrets: [
        { path: "svc/a", value: "1", metadata: {} },
        { path: "svc/b", value: "2", metadata: A },
      ],
    });
    expect(res.status).toBe(409);
    expect(engine.getMeta("svc/a")).toBeNull();
  });

  test("bulk import validates passthrough metadata", async () => {
    const res = await send("POST", "/v1/secrets-bulk", {
      secrets: [{ path: "svc/a", value: "1", metadata: { passthrough_alias: "example" } }],
    });
    expect(res.status).toBe(400);
  });

  test("deleting a secret frees its alias", async () => {
    engine.put("svc/one", "v", A);
    await app.request("/v1/secrets/svc/one", { method: "DELETE" });
    const res = await send("POST", "/v1/secrets/svc/two", { value: "v", metadata: A });
    expect(res.status).toBe(201);
  });

  test("rollback that would resurrect a taken alias is 409 and changes nothing", async () => {
    engine.put("svc/one", "v1", A);
    engine.put("svc/one", "v2", {}); // v1 archived with the alias
    engine.put("svc/two", "v", A); // another secret takes it
    const res = await send("POST", "/v1/secrets/svc/one/rollback", { version: 1 });
    expect(res.status).toBe(409);
    expect(engine.getMeta("svc/one")!.version).toBe(2);
    expect(engine.getMeta("svc/one")!.metadata).toEqual({});
    expect(engine.findByAlias("example")!.path).toBe("svc/two");
  });

  test("rollback refuses archived metadata that fails validation and changes nothing", async () => {
    const cases: Array<[string, Record<string, string>]> = [
      ["query string", { passthrough_alias: "old", upstream_url: "https://api.example.com/x?k=1" }],
      ["half pair", { passthrough_alias: "old" }],
      ["host outside allowed_domains", { passthrough_alias: "old", upstream_url: "https://api.example.com", allowed_domains: "other.test" }],
    ];
    for (const [i, [, meta]] of cases.entries()) {
      const path = `svc/rb${i}`;
      engine.put(path, "v1", meta); // bypasses the validator
      engine.put(path, "v2", { env: "ok" });
      const res = await send("POST", `/v1/secrets/${path}/rollback`, { version: 1 });
      expect(res.status).toBe(400);
      expect(engine.getMeta(path)!.version).toBe(2);
      expect(engine.getMeta(path)!.metadata).toEqual({ env: "ok" });
      expect(engine.get(path)).toBe("v2");
    }
  });

  test("bulk import writes nothing when a put fails partway", async () => {
    const real = engine.put.bind(engine);
    let n = 0;
    const origErr = console.error;
    console.error = () => {}; // Hono logs the injected failure
    engine.put = ((...a: Parameters<typeof engine.put>) => {
      if (++n === 3) throw new Error("boom");
      return real(...a);
    }) as typeof engine.put;
    const res = await send("POST", "/v1/secrets-bulk", {
      secrets: [
        { path: "svc/a", value: "1" },
        { path: "svc/b", value: "2" },
        { path: "svc/c", value: "3" },
      ],
    });
    engine.put = real;
    console.error = origErr;
    expect(res.status).toBe(500);
    for (const p of ["svc/a", "svc/b", "svc/c"]) expect(engine.getMeta(p)).toBeNull();
  });

  test("rollback to a version with a still-free alias works", async () => {
    engine.put("svc/one", "v1", A);
    engine.put("svc/one", "v2", {});
    const res = await send("POST", "/v1/secrets/svc/one/rollback", { version: 1 });
    expect(res.status).toBe(200);
    expect(engine.findByAlias("example")!.path).toBe("svc/one");
  });
});

describe("passthrough header_name restriction", () => {
  const U = "https://api.example.com";
  test("forbidden header_name rejected with an alias, naming the header", () => {
    for (const h of ["Cookie", "host", "X-Forwarded-For", "Via", "content-length"]) {
      const r = validateSecretMetadata({ passthrough_alias: "example", upstream_url: U, header_name: h });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error).toContain(h);
    }
  });
  test("allowed header_name passes with an alias", () => {
    expect(validateSecretMetadata({ passthrough_alias: "example", upstream_url: U, header_name: "x-api-key" }).ok).toBe(true);
  });
  test("secret without an alias may have any header_name", () => {
    for (const h of ["Cookie", "host", "X-Forwarded-For"]) {
      expect(validateSecretMetadata({ header_name: h }).ok).toBe(true);
    }
  });
});
