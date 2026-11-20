import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { initDB } from "../src/db/init";
import { SecretsEngine, keyFingerprint } from "../src/secrets/engine";
import { AuditLog } from "../src/audit/logger";
import { DynamicSecretsManager } from "../src/dynamic/manager";
import { PolicyEngine } from "../src/policy/engine";
import { verifyVault } from "../src/backup/verify";
import { keyVerifyRouter } from "../src/api/keyVerify";

const KEY_A = Buffer.from("a".repeat(64), "hex");
const KEY_B = Buffer.from("b".repeat(64), "hex");

describe("verifyVault", () => {
  let db: Database;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-verify-"));
    db = initDB(dir);
  });
  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("good key verifies against a secret", () => {
    new SecretsEngine(db, KEY_A).put("api-keys/example", "v");
    expect(verifyVault(db, KEY_A)).toEqual({
      fingerprint: keyFingerprint(KEY_A),
      tested: "secret",
      ok: true,
    });
  });

  test("wrong key fails", () => {
    new SecretsEngine(db, KEY_A).put("api-keys/example", "v");
    const r = verifyVault(db, KEY_B);
    expect(r.tested).toBe("secret");
    expect(r.ok).toBe(false);
    expect(r.fingerprint).toBe(keyFingerprint(KEY_B));
  });

  test("no secrets falls back to a dynamic config", () => {
    const mgr = new DynamicSecretsManager(db, new AuditLog(db), KEY_A);
    mgr.saveConfig("dyn/example", "postgresql", {
      host: "localhost", port: "5432", database: "x", user: "u", password: "p",
    });
    expect(verifyVault(db, KEY_A).tested).toBe("dynamic");
    expect(verifyVault(db, KEY_A).ok).toBe(true);
    expect(verifyVault(db, KEY_B)).toMatchObject({ tested: "dynamic", ok: false });
  });

  test("empty vault reports none and ok", () => {
    expect(verifyVault(db, KEY_A)).toMatchObject({ tested: "none", ok: true });
  });

  test("verify does not bump last_accessed_at or write audit rows", () => {
    new SecretsEngine(db, KEY_A).put("api-keys/example", "v");
    const q = "SELECT last_accessed_at FROM secrets WHERE path = 'api-keys/example'";
    const before = db.query(q).get();
    const auditBefore = (db.query("SELECT COUNT(*) AS n FROM audit_log").get() as any).n;
    verifyVault(db, KEY_A);
    verifyVault(db, KEY_B);
    expect(db.query(q).get()).toEqual(before);
    expect((db.query("SELECT COUNT(*) AS n FROM audit_log").get() as any).n).toBe(auditBefore);
  });

  const TABLES = ["secrets", "dynamic_secrets", "audit_log", "dynamic_leases"];
  function dump(): string {
    return JSON.stringify(
      TABLES.map((t) =>
        (db.query(`SELECT * FROM ${t}`).all() as any[]).map((r) =>
          Object.fromEntries(
            Object.entries(r).map(([k, v]) => [k, v instanceof Uint8Array ? Buffer.from(v).toString("hex") : v])
          )
        )
      )
    );
  }
  const PG = { host: "localhost", port: "5432", database: "x", user: "u", password: "p" };

  test("wrong key leaves every table byte-identical, including legacy plaintext rows", () => {
    new SecretsEngine(db, KEY_A).put("api-keys/example", "v");
    new DynamicSecretsManager(db, new AuditLog(db), KEY_A).saveConfig("dyn/example", "postgresql", PG);
    db.query("INSERT INTO dynamic_secrets (path, provider_type, config) VALUES (?, ?, ?)").run(
      "dyn/legacy", "postgresql", Buffer.from(JSON.stringify({ ...PG, note: "x".repeat(40) }))
    );
    const before = dump();
    expect(verifyVault(db, KEY_B).ok).toBe(false);
    expect(dump()).toBe(before);
  });

  test("right key leaves the database byte-identical", () => {
    new SecretsEngine(db, KEY_A).put("api-keys/example", "v");
    new DynamicSecretsManager(db, new AuditLog(db), KEY_A).saveConfig("dyn/example", "postgresql", PG);
    db.query("INSERT INTO dynamic_secrets (path, provider_type, config) VALUES (?, ?, ?)").run(
      "dyn/legacy", "postgresql", Buffer.from(JSON.stringify({ ...PG, note: "x".repeat(40) }))
    );
    const before = dump();
    expect(verifyVault(db, KEY_A).ok).toBe(true);
    expect(dump()).toBe(before);
  });

  test("dynamic-only vault: right key ok, wrong key not ok, legacy-only is untested", () => {
    new DynamicSecretsManager(db, new AuditLog(db), KEY_A).saveConfig("dyn/example", "postgresql", PG);
    expect(verifyVault(db, KEY_A)).toMatchObject({ tested: "dynamic", ok: true });
    expect(verifyVault(db, KEY_B)).toMatchObject({ tested: "dynamic", ok: false });
    db.query("DELETE FROM dynamic_secrets").run();
    db.query("INSERT INTO dynamic_secrets (path, provider_type, config) VALUES (?, ?, ?)").run(
      "dyn/legacy", "postgresql", Buffer.from(JSON.stringify({ ...PG, note: "x".repeat(40) }))
    );
    expect(verifyVault(db, KEY_B)).toMatchObject({ tested: "none", ok: true });
  });

  describe("GET /v1/admin/key-verify", () => {
    function appFor(policies: string[]) {
      const app = new Hono();
      app.use("*", async (c, next) => {
        c.set("requestId", "test-req-id");
        c.set("auth", { identity: "test", policies });
        await next();
      });
      app.route("/v1/admin/key-verify", keyVerifyRouter(db, () => KEY_A, new PolicyEngine(dir)));
      return app;
    }

    test("is 403 without admin and 200 with", async () => {
      new SecretsEngine(db, KEY_A).put("api-keys/example", "v");
      const denied = await appFor(["writer"]).request("/v1/admin/key-verify");
      expect(denied.status).toBe(403);
      expect(await denied.json()).toEqual({ error: "Forbidden", request_id: "test-req-id" });
      const ok = await appFor(["admin"]).request("/v1/admin/key-verify");
      expect(ok.status).toBe(200);
      expect(await ok.json()).toEqual({
        fingerprint: keyFingerprint(KEY_A),
        tested: "secret",
        ok: true,
      });
    });
  });
});
