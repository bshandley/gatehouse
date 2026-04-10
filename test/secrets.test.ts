import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("SecretsEngine", () => {
  let db: Database;
  let engine: SecretsEngine;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-test-"));
    db = initDB(dir);
    engine = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("put and get round-trip", () => {
    engine.put("test/secret", "my-secret-value");
    const value = engine.get("test/secret");
    expect(value).toBe("my-secret-value");
  });

  test("get returns null for missing secret", () => {
    expect(engine.get("nonexistent")).toBeNull();
  });

  test("put overwrites existing secret and increments version", () => {
    const v1 = engine.put("test/key", "value1");
    expect(v1.version).toBe(1);

    const v2 = engine.put("test/key", "value2");
    expect(v2.version).toBe(2);

    expect(engine.get("test/key")).toBe("value2");
  });

  test("version increments on each update", () => {
    engine.put("v/test", "a");
    engine.put("v/test", "b");
    const v3 = engine.put("v/test", "c");
    expect(v3.version).toBe(3);
  });

  test("delete removes secret", () => {
    engine.put("del/me", "gone");
    expect(engine.delete("del/me")).toBe(true);
    expect(engine.get("del/me")).toBeNull();
  });

  test("delete returns false for nonexistent path", () => {
    expect(engine.delete("nope")).toBe(false);
  });

  test("list returns metadata without values", () => {
    engine.put("a/1", "val1", { env: "prod" });
    engine.put("a/2", "val2");
    engine.put("b/1", "val3");

    const all = engine.list();
    expect(all.length).toBe(3);
    // No value field on list results
    for (const item of all) {
      expect(item).not.toHaveProperty("value");
      expect(item).toHaveProperty("path");
      expect(item).toHaveProperty("version");
      expect(item).toHaveProperty("created_at");
      expect(item).toHaveProperty("updated_at");
    }
  });

  test("list with prefix filter", () => {
    engine.put("api-keys/openai", "sk-1");
    engine.put("api-keys/anthropic", "sk-2");
    engine.put("db/prod", "pg-conn");

    const apiKeys = engine.list("api-keys/");
    expect(apiKeys.length).toBe(2);
    expect(apiKeys.map((s) => s.path)).toContain("api-keys/openai");
    expect(apiKeys.map((s) => s.path)).toContain("api-keys/anthropic");

    const dbSecrets = engine.list("db/");
    expect(dbSecrets.length).toBe(1);
  });

  test("metadata is stored and retrieved correctly", () => {
    engine.put("meta/test", "value", { service: "openai", env: "prod" });
    const meta = engine.getMeta("meta/test");
    expect(meta).not.toBeNull();
    expect(meta!.metadata).toEqual({ service: "openai", env: "prod" });
  });

  test("getMeta returns null for nonexistent path", () => {
    expect(engine.getMeta("nope")).toBeNull();
  });

  test("exists checks path existence", () => {
    engine.put("exists/test", "val");
    expect(engine.exists("exists/test")).toBe(true);
    expect(engine.exists("nope")).toBe(false);
  });

  test("envelope encryption: different secrets get different DEKs", () => {
    engine.put("s1", "value1");
    engine.put("s2", "value2");

    const row1 = db
      .query("SELECT encrypted_dek, dek_nonce FROM secrets WHERE path = ?")
      .get("s1") as any;
    const row2 = db
      .query("SELECT encrypted_dek, dek_nonce FROM secrets WHERE path = ?")
      .get("s2") as any;

    // Encrypted DEKs should differ (different random DEKs)
    const dek1 = Buffer.from(row1.encrypted_dek);
    const dek2 = Buffer.from(row2.encrypted_dek);
    expect(dek1.equals(dek2)).toBe(false);
  });

  test("different master key cannot decrypt secrets", () => {
    engine.put("secure/key", "secret-data");

    const engine2 = new SecretsEngine(db, Buffer.from("b".repeat(64), "hex"));
    expect(() => engine2.get("secure/key")).toThrow();
  });

  test("handles special characters in values", () => {
    const special = 'p@$$w0rd!#%^&*(){}[]|\\:";\'<>?,./~`';
    engine.put("special", special);
    expect(engine.get("special")).toBe(special);
  });

  test("handles unicode values", () => {
    const unicode = "password: 密码 🔐";
    engine.put("unicode", unicode);
    expect(engine.get("unicode")).toBe(unicode);
  });

  test("handles empty metadata", () => {
    engine.put("no-meta", "val");
    const meta = engine.getMeta("no-meta");
    expect(meta!.metadata).toEqual({});
  });

  test("created_at and updated_at are set", () => {
    const result = engine.put("ts/test", "val");
    expect(result.created_at).toBeTruthy();
    expect(result.updated_at).toBeTruthy();
  });

  // ── Key rotation ───────────────────────────────────────────

  test("rotateKEK re-wraps all DEKs and values are still readable", () => {
    engine.put("rot/s1", "secret-one");
    engine.put("rot/s2", "secret-two");
    engine.put("rot/s3", "secret-three");

    const newKey = Buffer.from("b".repeat(64), "hex");
    const rotated = engine.rotateKEK(newKey);
    expect(rotated).toBe(3);

    // Values should still decrypt with the new KEK
    expect(engine.get("rot/s1")).toBe("secret-one");
    expect(engine.get("rot/s2")).toBe("secret-two");
    expect(engine.get("rot/s3")).toBe("secret-three");
  });

  test("rotateKEK makes old KEK unable to decrypt", () => {
    engine.put("rot/key", "my-secret");
    const newKey = Buffer.from("c".repeat(64), "hex");
    engine.rotateKEK(newKey);

    // A fresh engine with the OLD key should fail
    const oldEngine = new SecretsEngine(db, Buffer.from("a".repeat(64), "hex"));
    expect(() => oldEngine.get("rot/key")).toThrow();
  });

  test("rotateKEK returns 0 for empty vault", () => {
    const newKey = Buffer.from("d".repeat(64), "hex");
    expect(engine.rotateKEK(newKey)).toBe(0);
  });

  test("new secrets work after rotation", () => {
    engine.put("pre/rotation", "before");
    const newKey = Buffer.from("e".repeat(64), "hex");
    engine.rotateKEK(newKey);

    // Write a new secret after rotation
    engine.put("post/rotation", "after");

    expect(engine.get("pre/rotation")).toBe("before");
    expect(engine.get("post/rotation")).toBe("after");
  });
});
