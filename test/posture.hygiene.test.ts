import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Hono } from "hono";
import { AuditLog } from "../src/audit/logger";
import { PolicyEngine } from "../src/policy/engine";
import { secretsRouter } from "../src/api/secrets";

describe("last_accessed_at migration", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-posture-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test("fresh init creates the secrets.last_accessed_at column", () => {
    const db = initDB(dir);
    const cols = (db.query("PRAGMA table_info(secrets)").all() as { name: string }[]).map(
      (c) => c.name
    );
    expect(cols).toContain("last_accessed_at");
    db.close();
  });

  test("existing db without the column is migrated and backfilled to updated_at", () => {
    // Simulate a legacy database: a secrets table without last_accessed_at.
    const dbPath = join(dir, "gatehouse.db");
    const legacy = new Database(dbPath, { create: true });
    legacy.run(`
      CREATE TABLE secrets (
        path TEXT PRIMARY KEY,
        encrypted_value BLOB NOT NULL,
        nonce BLOB NOT NULL,
        encrypted_dek BLOB NOT NULL,
        dek_nonce BLOB NOT NULL,
        metadata TEXT DEFAULT '{}',
        version INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT '2020-01-01 00:00:00'
      )
    `);
    legacy.run(
      "INSERT INTO secrets (path, encrypted_value, nonce, encrypted_dek, dek_nonce) VALUES ('old/secret', x'00', x'00', x'00', x'00')"
    );
    legacy.close();

    const db = initDB(dir);
    const cols = (db.query("PRAGMA table_info(secrets)").all() as { name: string }[]).map(
      (c) => c.name
    );
    expect(cols).toContain("last_accessed_at");

    const row = db
      .query("SELECT updated_at, last_accessed_at FROM secrets WHERE path = 'old/secret'")
      .get() as { updated_at: string; last_accessed_at: string };
    expect(row.last_accessed_at).toBe(row.updated_at);
    expect(row.last_accessed_at).toBe("2020-01-01 00:00:00");
    db.close();
  });
});

describe("SecretsEngine.markAccessed and last_accessed_at exposure", () => {
  let db: Database;
  let engine: SecretsEngine;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-posture-eng-"));
    db = initDB(dir);
    engine = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("a freshly put secret has null last_accessed_at", () => {
    engine.put("svc/key", "v");
    expect(engine.getMeta("svc/key")!.last_accessed_at).toBeNull();
  });

  test("markAccessed sets last_accessed_at and is reflected by getMeta and list", () => {
    engine.put("svc/key", "v");
    engine.markAccessed("svc/key");
    const meta = engine.getMeta("svc/key")!;
    expect(meta.last_accessed_at).not.toBeNull();
    const listed = engine.list("svc/").find((s) => s.path === "svc/key")!;
    expect(listed.last_accessed_at).toBe(meta.last_accessed_at);
  });

  test("markAccessed on a missing path is a no-op (does not throw)", () => {
    expect(() => engine.markAccessed("does/not/exist")).not.toThrow();
  });
});

describe("SecretsEngine.hygieneCounts", () => {
  let db: Database;
  let engine: SecretsEngine;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-posture-hyg-"));
    db = initDB(dir);
    engine = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("empty vault reports all zeros", () => {
    expect(engine.hygieneCounts()).toEqual({ stale_90d: 0, older_18mo: 0, total_secrets: 0 });
  });

  test("buckets stale (>90d since access) and old (>18mo since update)", () => {
    // Fresh + just accessed: neither stale nor old.
    engine.put("fresh/key", "v");
    engine.markAccessed("fresh/key");

    // Stale: accessed long ago. Force last_accessed_at back 200 days.
    engine.put("stale/key", "v");
    db.run("UPDATE secrets SET last_accessed_at = datetime('now','-200 days') WHERE path = 'stale/key'");

    // Old: updated_at 2 years ago (and never accessed -> last_accessed_at falls back to updated_at).
    engine.put("old/key", "v");
    db.run("UPDATE secrets SET updated_at = datetime('now','-2 years'), last_accessed_at = NULL WHERE path = 'old/key'");

    const h = engine.hygieneCounts();
    expect(h.total_secrets).toBe(3);
    // stale/key is stale; old/key is also stale (never accessed, updated 2y ago).
    expect(h.stale_90d).toBe(2);
    expect(h.older_18mo).toBe(1);
  });
});

describe("reveal sets last_accessed_at (wiring)", () => {
  let db: Database;
  let engine: SecretsEngine;
  let dir: string;
  let app: Hono;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-posture-wire-"));
    const configDir = join(dir, "config");
    mkdirSync(join(configDir, "policies"), { recursive: true });
    writeFileSync(
      join(configDir, "policies", "reader.yaml"),
      `name: reader\nrules:\n  - path: "svc/*"\n    capabilities: [read]\n`
    );
    db = initDB(dir);
    engine = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
    const audit = new AuditLog(db);
    const policies = new PolicyEngine(configDir);
    engine.put("svc/key", "the-value");

    app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "test-req-id");
      c.set("sourceIp", "127.0.0.1");
      c.set("auth", { identity: "test", policies: ["reader"] });
      await next();
    });
    app.route("/v1/secrets", secretsRouter(engine, policies, audit));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("GET /v1/secrets/:path/value stamps last_accessed_at", async () => {
    expect(engine.getMeta("svc/key")!.last_accessed_at).toBeNull();
    const res = await app.request("/v1/secrets/svc/key/value");
    expect(res.status).toBe(200);
    expect(engine.getMeta("svc/key")!.last_accessed_at).not.toBeNull();
  });

  test("metadata-only read does NOT stamp last_accessed_at", async () => {
    const res = await app.request("/v1/secrets/svc/key");
    expect(res.status).toBe(200);
    expect(engine.getMeta("svc/key")!.last_accessed_at).toBeNull();
  });
});
