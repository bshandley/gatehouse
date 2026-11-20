import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync, readdirSync, chmodSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { initDB } from "../src/db/init";
import { SecretsEngine, keyFingerprint } from "../src/secrets/engine";
import { AuditLog } from "../src/audit/logger";
import { DynamicSecretsManager } from "../src/dynamic/manager";
import { PolicyEngine } from "../src/policy/engine";
import { rotateKeyRouter } from "../src/api/rotateKey";
import { keyVerifyRouter } from "../src/api/keyVerify";
import { resolveMasterKey } from "../src/backup/keyfile";
import type { GatehouseConfig } from "../src/config";
import type { MasterKeySource } from "../src/backup/keyfile";

const OLD_HEX = "a1".repeat(32);
const NEW_HEX = "b2".repeat(32);
const OLD = Buffer.from(OLD_HEX, "hex");
const NOW = new Date("2026-11-19T12:34:56Z");

let root: string;
let dataDir: string;
let db: Database;
let audited: any[] = [];

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "gh-rotate-"));
  dataDir = join(root, "data");
  mkdirSync(dataDir);
  db = initDB(dataDir);
  audited = [];
});
afterEach(() => {
  db.close();
  try { chmodSync(dataDir, 0o700); } catch {}
  rmSync(root, { recursive: true, force: true });
});

function configFor(source: MasterKeySource): GatehouseConfig {
  return {
    port: 0,
    dataDir,
    configDir: root,
    masterKey: OLD,
    masterKeySource: source,
    jwtSecret: "x",
  };
}

function appFor(config: GatehouseConfig, over: { secrets?: any; dynamicSecrets?: any } = {}) {
  const audit = new AuditLog(db);
  (audit as any).log = (e: any) => audited.push(e); // keep test output quiet
  const policies = new PolicyEngine(root);
  const secrets = over.secrets ?? new SecretsEngine(db, config.masterKey);
  const dynamicSecrets = over.dynamicSecrets ?? new DynamicSecretsManager(db, audit, config.masterKey);
  const app = new Hono();
  app.use("*", async (c, next) => {
    c.set("requestId", "req");
    c.set("auth", { identity: "test", policies: ["admin"] });
    await next();
  });
  app.route("/v1/admin/rotate-key", rotateKeyRouter({ secrets, dynamicSecrets, policies, audit, config, now: () => NOW }));
  app.route("/v1/admin/key-verify", keyVerifyRouter(db, () => config.masterKey, policies));
  return { app, secrets };
}

const rotate = (app: Hono, hex = NEW_HEX) =>
  app.request("/v1/admin/rotate-key", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ new_master_key: hex }),
  });

function seedSecret() {
  new SecretsEngine(db, OLD).put("api-keys/example", "v1");
}

describe("POST /v1/admin/rotate-key", () => {
  test("file source: master.key gets the new key, the old one is kept, the response says where", async () => {
    writeFileSync(join(dataDir, "master.key"), OLD_HEX + "\n", { mode: 0o600 });
    seedSecret();
    const config = configFor("file");
    const { app } = appFor(config);
    const res = await rotate(app);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.rotated).toBe(true);
    expect(body.secrets_rewrapped).toBe(1);
    expect(body.key_persisted_to).toBe(join(dataDir, "master.key"));
    expect(body.previous_key_kept_as).toBe(join(dataDir, "master.key.pre-rotate-20261119T123456Z"));
    expect(body.warning).toBeUndefined();
    expect(body.message).toContain("fresh export");

    expect(readFileSync(join(dataDir, "master.key"), "utf8").trim()).toBe(NEW_HEX);
    expect(readFileSync(body.previous_key_kept_as, "utf8").trim()).toBe(OLD_HEX);
    expect(existsSync(join(dataDir, "master.key.next"))).toBe(false);
    expect(config.masterKey.toString("hex")).toBe(NEW_HEX);
    expect(audited).toHaveLength(1);
    expect(audited[0].metadata.key_persisted).toBe("file");

    const restart = resolveMasterKey({ envKey: undefined, dataDir, log: () => {} });
    expect(restart.source).toBe("file");
    expect(restart.key.toString("hex")).toBe(NEW_HEX);
    expect(new SecretsEngine(db, restart.key).get("api-keys/example")).toBe("v1");
  });

  test("generated source persists the same way", async () => {
    const gen = resolveMasterKey({ envKey: undefined, dataDir: join(root, "gen"), log: () => {} });
    expect(gen.source).toBe("generated");
    writeFileSync(join(dataDir, "master.key"), OLD_HEX + "\n");
    const config = configFor("generated");
    const { app } = appFor(config);
    const body = await (await rotate(app)).json();
    expect(body.key_persisted_to).toBe(join(dataDir, "master.key"));
    expect(readFileSync(join(dataDir, "master.key"), "utf8").trim()).toBe(NEW_HEX);
  });

  test("env source: unchanged behavior, nothing written, the env warning stays", async () => {
    seedSecret();
    const config = configFor("env");
    const { app } = appFor(config);
    const before = readdirSync(dataDir).sort();
    const body = await (await rotate(app)).json();
    expect(body.rotated).toBe(true);
    expect(body.warning).toBe("Update GATEHOUSE_MASTER_KEY env var to the new key before restarting");
    expect(body.key_persisted_to).toBeNull();
    expect(body.message).toContain("NOT saved");
    expect(body.message).not.toContain("GATEHOUSE_MASTER_KEY");
    expect(readdirSync(dataDir).sort()).toEqual(before);
    expect(config.masterKey.toString("hex")).toBe(NEW_HEX);
  });

  for (const [label, bad] of [
    ["63 chars", NEW_HEX.slice(0, 63)],
    ["65 chars", NEW_HEX + "a"],
    ["66 chars", NEW_HEX + "ab"],
    ["non-hex", "z" + NEW_HEX.slice(1)],
  ] as const) {
    test(`rejects a new key of ${label} with 400 and no state change`, async () => {
      seedSecret();
      const config = configFor("env");
      const { app, secrets } = appFor(config);
      const before = readdirSync(dataDir).sort();
      const res = await rotate(app, bad);
      expect(res.status).toBe(400);
      expect((await res.json()).error).toContain("64 hex");
      expect(config.masterKey.toString("hex")).toBe(OLD_HEX);
      expect(readdirSync(dataDir).sort()).toEqual(before);
      expect(secrets.get("api-keys/example")).toBe("v1");
    });
  }

  test("generated-unpersisted source: nothing written, env warning", async () => {
    const config = configFor("generated-unpersisted");
    const { app } = appFor(config);
    const body = await (await rotate(app)).json();
    expect(body.key_persisted_to).toBeNull();
    expect(body.warning).toContain("GATEHOUSE_MASTER_KEY");
    expect(existsSync(join(dataDir, "master.key.next"))).toBe(false);
  });

  test("cannot write master.key.next: 500 before the db is touched", async () => {
    if (process.getuid?.() === 0) return;
    seedSecret();
    const config = configFor("file");
    let called = false;
    const { app } = appFor(config, {
      secrets: { rotateKEK: () => { called = true; return 0; } },
      dynamicSecrets: { rotateConfigKey: () => { called = true; return 0; } },
    });
    chmodSync(dataDir, 0o500);
    const res = await rotate(app);
    chmodSync(dataDir, 0o700);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toContain("Nothing was changed");
    expect(called).toBe(false);
    expect(config.masterKey.equals(OLD)).toBe(true);
  });

  test("rotation throws before committing: master.key.next is removed, master.key untouched", async () => {
    writeFileSync(join(dataDir, "master.key"), OLD_HEX + "\n");
    const config = configFor("file");
    const { app } = appFor(config, {
      secrets: { rotateKEK: () => { throw new Error("Failed to decrypt DEK during rotation"); } },
    });
    const res = await rotate(app);
    expect(res.status).toBe(500);
    expect((await res.json()).error).toBe("Rotation failed: Failed to decrypt DEK during rotation");
    expect(readdirSync(dataDir).filter((f) => f.startsWith("master.key"))).toEqual(["master.key"]);
    expect(readFileSync(join(dataDir, "master.key"), "utf8").trim()).toBe(OLD_HEX);
    expect(config.masterKey.equals(OLD)).toBe(true);
  });

  test("dynamic rotation fails after secrets committed: master.key.next is kept and named", async () => {
    writeFileSync(join(dataDir, "master.key"), OLD_HEX + "\n");
    const config = configFor("file");
    const { app } = appFor(config, {
      secrets: { rotateKEK: () => 3 },
      dynamicSecrets: { rotateConfigKey: () => { throw new Error("boom"); } },
    });
    const res = await rotate(app);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toContain(join(dataDir, "master.key.next"));
    expect(body.error).toContain("Retry");
    expect(readFileSync(join(dataDir, "master.key.next"), "utf8").trim()).toBe(NEW_HEX);
    expect(readFileSync(join(dataDir, "master.key"), "utf8").trim()).toBe(OLD_HEX);
  });
});

describe("key verify follows a rotation (F2)", () => {
  test("verify is ok before and after, with the new fingerprint after", async () => {
    writeFileSync(join(dataDir, "master.key"), OLD_HEX + "\n");
    seedSecret();
    const config = configFor("file");
    const { app } = appFor(config);
    const before = await (await app.request("/v1/admin/key-verify")).json();
    expect(before).toEqual({ fingerprint: keyFingerprint(OLD), tested: "secret", ok: true });
    expect((await rotate(app)).status).toBe(200);
    const after = await (await app.request("/v1/admin/key-verify")).json();
    expect(after).toEqual({ fingerprint: keyFingerprint(Buffer.from(NEW_HEX, "hex")), tested: "secret", ok: true });
  });
});
