import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { copyFileSync, mkdtempSync, mkdirSync, rmSync, existsSync, readdirSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { initDB } from "../src/db/init";
import { AuditLog } from "../src/audit/logger";
import { SecretsEngine, keyFingerprint } from "../src/secrets/engine";
import { DynamicSecretsManager } from "../src/dynamic/manager";
import { resolveMasterKey } from "../src/backup/keyfile";
import { runCli } from "../src/cli";
import { Hono } from "hono";
import { PolicyEngine } from "../src/policy/engine";
import { rotateKeyRouter } from "../src/api/rotateKey";

const PW = "correct horse battery staple";
const NOW = new Date("2026-11-19T12:34:56Z");
const KEY_A_HEX = "a1".repeat(32);
const KEY_B_HEX = "b2".repeat(32);
const KEY_A = Buffer.from(KEY_A_HEX, "hex");
const KEY_B = Buffer.from(KEY_B_HEX, "hex");

let root: string;
let data: string;
let work: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "gh-drill-"));
  data = join(root, "data");
  work = join(root, "work");
  mkdirSync(data);
  mkdirSync(work);
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

async function cli(argv: string[], env: Record<string, string | undefined>) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await runCli(argv, {
    env: { GATEHOUSE_BUNDLE_SCRYPT_LOGN: "10", ...env },
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    isTTY: false,
    now: () => NOW,
  });
  return { code, out, err, all: [...out, ...err].join("\n") };
}

const values = (n: number) => Array.from({ length: n }, (_, i) => [`api-keys/example-${i}`, `value-${i}-${"x".repeat(i + 3)}`]);

function readAll(dir: string, key: Buffer, paths: string[]): (string | null)[] {
  const db = new Database(join(dir, "gatehouse.db"), { readonly: true });
  try {
    const e = new SecretsEngine(db, key);
    return paths.map((p) => e.get(p));
  } finally {
    db.close();
  }
}

function seed(dir: string, key: Buffer, withDynamic: boolean) {
  const db = initDB(dir);
  const e = new SecretsEngine(db, key);
  for (const [p, v] of values(5)) e.put(p, v);
  if (withDynamic) {
    new DynamicSecretsManager(db, new AuditLog(db), key).saveConfig("db/drill", "redis", {
      host: "cache.internal",
      password: "dyn-config-password",
    });
  }
  db.close();
}

describe("restore drill", () => {
  test("sealed drill: export, lose everything, import, read back", async () => {
    const env = { GATEHOUSE_DATA_DIR: data, PW };
    const { key, source } = resolveMasterKey({ envKey: undefined, dataDir: data, log: () => {} });
    expect(source).toBe("generated");
    seed(data, key, true);
    const fp = keyFingerprint(key);

    const bundle = join(work, "drill.bundle");
    expect((await cli(["export", "--out", bundle, "--passphrase-env", "PW"], env)).code).toBe(0);

    rmSync(data, { recursive: true, force: true });
    mkdirSync(data);
    expect(readdirSync(data)).toEqual([]);

    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], env);
    expect(r.code).toBe(0);

    const again = resolveMasterKey({ envKey: undefined, dataDir: data, log: () => {} });
    expect(again.source).toBe("file");
    expect(keyFingerprint(again.key)).toBe(fp);

    const vs = values(5);
    expect(readAll(data, again.key, vs.map(([p]) => p))).toEqual(vs.map(([, v]) => v));

    const db = new Database(join(data, "gatehouse.db"), { readonly: true });
    try {
      const cfg = new DynamicSecretsManager(db, new AuditLog(db), again.key).getConfig("db/drill");
      expect(cfg?.config.password).toBe("dyn-config-password");
      expect(cfg?.config.host).toBe("cache.internal");
    } finally {
      db.close();
    }
  });

  test("unsealed drill: a different master key is refused, the right one restores", async () => {
    seed(data, KEY_A, true);
    const bundle = join(work, "drill.bundle");
    const ex = await cli(["export", "--out", bundle, "--passphrase-env", "PW", "--no-key"], {
      GATEHOUSE_DATA_DIR: data,
      GATEHOUSE_MASTER_KEY: KEY_A_HEX,
      PW,
    });
    expect(ex.code).toBe(0);

    rmSync(data, { recursive: true, force: true });
    mkdirSync(data);

    const bad = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], {
      GATEHOUSE_DATA_DIR: data,
      GATEHOUSE_MASTER_KEY: KEY_B_HEX,
      PW,
    });
    expect(bad.code).toBe(2);
    expect(readdirSync(data)).toEqual([]);

    const ok = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], {
      GATEHOUSE_DATA_DIR: data,
      GATEHOUSE_MASTER_KEY: KEY_A_HEX,
      PW,
    });
    expect(ok.code).toBe(0);
    expect(existsSync(join(data, "master.key"))).toBe(false);
    const vs = values(5);
    expect(readAll(data, KEY_A, vs.map(([p]) => p))).toEqual(vs.map(([, v]) => v));
  });

  test("stale WAL from the replaced vault is not replayed into the restored db", async () => {
    // bundle source: a different vault with its own secret
    const srcDir = join(root, "src");
    mkdirSync(srcDir);
    const sdb = initDB(srcDir);
    new SecretsEngine(sdb, KEY_A).put("api-keys/example-bundle", "from-bundle");
    sdb.close();
    const bundle = join(work, "drill.bundle");
    expect(
      (await cli(["export", "--out", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: srcDir, GATEHOUSE_MASTER_KEY: KEY_A_HEX, PW })).code
    ).toBe(0);

    // target: a real old vault (encrypted under KEY_B; the env key is the bundle's KEY_A),
    // handle held open so its writes sit in the WAL
    const old = initDB(data);
    const oldEngine = new SecretsEngine(old, KEY_B);
    oldEngine.put("api-keys/example-old", "from-old");
    oldEngine.put("api-keys/example-old2", "from-old-2");
    expect(existsSync(join(data, "gatehouse.db-wal"))).toBe(true);
    try {
      const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], {
        GATEHOUSE_DATA_DIR: data,
        GATEHOUSE_MASTER_KEY: KEY_A_HEX,
        PW,
      });
      expect(r.code).toBe(0);

      const files = readdirSync(data);
      expect(files.filter((f) => f.startsWith("gatehouse.db.pre-import-")).length).toBeGreaterThan(0);
      expect(existsSync(join(data, "gatehouse.db-wal"))).toBe(false);
      expect(existsSync(join(data, "gatehouse.db-shm"))).toBe(false);

      const db = new Database(join(data, "gatehouse.db"), { readonly: true });
      try {
        const e = new SecretsEngine(db, KEY_A);
        expect(e.list().map((s) => s.path)).toEqual(["api-keys/example-bundle"]);
        expect(e.get("api-keys/example-bundle")).toBe("from-bundle");
        expect(e.get("api-keys/example-old")).toBeNull();
        expect(e.get("api-keys/example-old2")).toBeNull();
      } finally {
        db.close();
      }

      // the old vault stays recoverable beside it
      const pre = files.find((f) => /^gatehouse\.db\.pre-import-[^.]*$/.test(f) && !f.endsWith("-wal"))!;
      expect(pre).toBeDefined();
      expect(existsSync(join(data, `${pre}-wal`))).toBe(true);

      // copy the pair (keeping the name/name-wal pairing) and read the old vault back,
      // including rows that only ever lived in the uncheckpointed WAL
      const scratch = join(root, "pre-copy");
      mkdirSync(scratch);
      copyFileSync(join(data, pre), join(scratch, "old.db"));
      copyFileSync(join(data, `${pre}-wal`), join(scratch, "old.db-wal"));
      const odb = new Database(join(scratch, "old.db"));
      try {
        const oe = new SecretsEngine(odb, KEY_B);
        expect(oe.get("api-keys/example-old")).toBe("from-old");
        expect(oe.get("api-keys/example-old2")).toBe("from-old-2");
      } finally {
        odb.close();
      }
    } finally {
      old.close();
    }
  });

  test("export from a db held open with uncheckpointed writes includes those writes", async () => {
    const db = initDB(data);
    const e = new SecretsEngine(db, KEY_A);
    for (const [p, v] of values(5)) e.put(p, v);
    expect(existsSync(join(data, "gatehouse.db-wal"))).toBe(true);
    const bundle = join(work, "drill.bundle");
    try {
      const r = await cli(["export", "--out", bundle, "--passphrase-env", "PW"], {
        GATEHOUSE_DATA_DIR: data,
        GATEHOUSE_MASTER_KEY: KEY_A_HEX,
        PW,
      });
      expect(r.code).toBe(0);
    } finally {
      db.close();
    }
    const target = join(root, "restore");
    mkdirSync(target);
    const im = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: target, PW });
    expect(im.code).toBe(0);
    const vs = values(5);
    expect(readAll(target, KEY_A, vs.map(([p]) => p))).toEqual(vs.map(([, v]) => v));
  });

  test("rotation drill: generated key, rotate, restart reads the NEW key, export and restore", async () => {
    const env = { GATEHOUSE_DATA_DIR: data, PW };
    const boot = resolveMasterKey({ envKey: undefined, dataDir: data, log: () => {} });
    expect(boot.source).toBe("generated");
    seed(data, boot.key, true);

    // The server's rotate route, on the same objects index.ts wires up.
    const db = initDB(data);
    const config = { port: 0, dataDir: data, configDir: root, masterKey: boot.key, masterKeySource: boot.source, jwtSecret: "x" };
    const audit = new AuditLog(db);
    (audit as any).log = () => {};
    const app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "req");
      c.set("auth", { identity: "drill", policies: ["admin"] });
      await next();
    });
    app.route(
      "/v1/admin/rotate-key",
      rotateKeyRouter({
        secrets: new SecretsEngine(db, config.masterKey),
        dynamicSecrets: new DynamicSecretsManager(db, audit, config.masterKey),
        policies: new PolicyEngine(root),
        audit,
        config,
        now: () => NOW,
      })
    );
    try {
      const res = await app.request("/v1/admin/rotate-key", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ new_master_key: KEY_B_HEX }),
      });
      expect(res.status).toBe(200);
      expect((await res.json()).key_persisted_to).toBe(join(data, "master.key"));
    } finally {
      db.close();
    }

    // Restart.
    const again = resolveMasterKey({ envKey: undefined, dataDir: data, log: () => {} });
    expect(again.source).toBe("file");
    expect(keyFingerprint(again.key)).toBe(keyFingerprint(KEY_B));
    expect(keyFingerprint(again.key)).not.toBe(keyFingerprint(boot.key));

    const v = await cli(["verify"], env);
    expect(v.code).toBe(0);
    expect(v.all).toContain(keyFingerprint(KEY_B));

    const bundle = join(work, "rotated.bundle");
    expect((await cli(["export", "--out", bundle, "--passphrase-env", "PW"], env)).code).toBe(0);

    const target = join(root, "restore");
    mkdirSync(target);
    expect((await cli(["import", "--in", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: target, PW })).code).toBe(0);
    const restored = resolveMasterKey({ envKey: undefined, dataDir: target, log: () => {} });
    expect(keyFingerprint(restored.key)).toBe(keyFingerprint(KEY_B));
    const vs = values(5);
    expect(readAll(target, restored.key, vs.map(([p]) => p))).toEqual(vs.map(([, v]) => v));
    const rdb = new Database(join(target, "gatehouse.db"), { readonly: true });
    try {
      expect(new DynamicSecretsManager(rdb, new AuditLog(rdb), restored.key).getConfig("db/drill")?.config.password).toBe(
        "dyn-config-password"
      );
    } finally {
      rdb.close();
    }
  });

  test("export with a key that does not decrypt the vault exits 1 and writes nothing", async () => {
    seed(data, KEY_A, false);
    for (const extra of [[], ["--no-key"]]) {
      const bundle = join(work, `wrong-key${extra.length}.bundle`);
      const r = await cli(["export", "--out", bundle, "--passphrase-env", "PW", ...extra], {
        GATEHOUSE_DATA_DIR: data,
        GATEHOUSE_MASTER_KEY: KEY_B_HEX,
        PW,
      });
      expect(r.code).toBe(1);
      expect(r.all).toContain("does not decrypt this vault");
      expect(r.all).toContain("-e GATEHOUSE_MASTER_KEY");
      expect(existsSync(bundle)).toBe(false);
    }
    expect(readdirSync(work)).toEqual([]);
  });

  test("export of an empty vault proceeds", async () => {
    initDB(data).close();
    const bundle = join(work, "empty.bundle");
    const r = await cli(["export", "--out", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: data, GATEHOUSE_MASTER_KEY: KEY_A_HEX, PW });
    expect(r.code).toBe(0);
    expect(existsSync(bundle)).toBe(true);
  });
});
