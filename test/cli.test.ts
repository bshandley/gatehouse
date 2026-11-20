import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  existsSync,
  readFileSync,
  readdirSync,
  writeFileSync,
  statSync,
} from "fs";
import { createHash } from "crypto";
import { tmpdir } from "os";
import { join } from "path";
import { initDB } from "../src/db/init";
import { SecretsEngine, keyFingerprint } from "../src/secrets/engine";
import { startHeartbeat } from "../src/backup/snapshot";
import { sealBundle } from "../src/backup/bundle";
import { runCli, _swapIntoPlace, _rollbackImport } from "../src/cli";
import { persistKeyFile } from "../src/backup/keyfile";
import { renameSync } from "fs";

const KEY_A_HEX = "a1".repeat(32);
const KEY_B_HEX = "b2".repeat(32);
const KEY_A = Buffer.from(KEY_A_HEX, "hex");
const KEY_B = Buffer.from(KEY_B_HEX, "hex");
const PW = "correct horse battery staple";
const NOW = new Date("2026-11-19T12:34:56Z");
const STAMP = "20261119T123456Z";

let root: string;
let src: string; // source vault data dir
let dst: string; // import target data dir
let work: string; // where bundles and backups land

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "gh-cli-"));
  src = join(root, "src");
  dst = join(root, "dst");
  work = join(root, "work");
  mkdirSync(src);
  mkdirSync(dst);
  mkdirSync(work);
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

type Cap = { code: number; out: string[]; err: string[]; all: string };

async function cli(
  argv: string[],
  env: Record<string, string | undefined> = {},
  extra: { isTTY?: boolean; prompt?: (label: string) => Promise<string> } = {}
): Promise<Cap> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await runCli(argv, {
    env: { GATEHOUSE_BUNDLE_SCRYPT_LOGN: "10", ...env },
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    isTTY: extra.isTTY ?? false,
    prompt: extra.prompt,
    now: () => NOW,
  });
  return { code, out, err, all: [...out, ...err].join("\n") };
}

/** A vault in dir with one secret, encrypted under key. */
function makeVault(dir: string, key: Buffer, value = "v-src") {
  const db = initDB(dir);
  new SecretsEngine(db, key).put("api-keys/example", value);
  db.close();
}

/** filename -> sha256 of contents, for byte-identical comparisons. */
function dirHash(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!existsSync(dir)) return out;
  for (const f of readdirSync(dir).sort()) {
    const p = join(dir, f);
    out[f] = statSync(p).isDirectory() ? "dir" : createHash("sha256").update(readFileSync(p)).digest("hex");
  }
  return out;
}

/**
 * Like dirHash, but the -shm file is compared by presence only. A WAL reader
 * must update the shared-memory index (read marks), so even a read-only open
 * of a live db touches it. That is SQLite's reader protocol, not a data write.
 */
function dirHashReader(dir: string): Record<string, string> {
  const h = dirHash(dir);
  for (const k of Object.keys(h)) if (k.endsWith("-shm")) h[k] = "present";
  return h;
}

function readSecret(dir: string, key: Buffer): string | null {
  const db = new Database(join(dir, "gatehouse.db"), { readonly: true });
  try {
    return new SecretsEngine(db, key).get("api-keys/example");
  } finally {
    db.close();
  }
}

const srcEnvA = () => ({ GATEHOUSE_DATA_DIR: src, GATEHOUSE_MASTER_KEY: KEY_A_HEX, PW });

async function exportSealed(file = join(work, "v.bundle")) {
  makeVault(src, KEY_A);
  const r = await cli(["export", "--out", file, "--passphrase-env", "PW"], srcEnvA());
  expect(r.code).toBe(0);
  return file;
}
async function exportUnsealed(file = join(work, "v.bundle")) {
  makeVault(src, KEY_A);
  const r = await cli(["export", "--out", file, "--passphrase-env", "PW", "--no-key"], srcEnvA());
  expect(r.code).toBe(0);
  return file;
}

function noStack(c: Cap) {
  expect(c.all).not.toMatch(/^\s+at /m);
}

describe("backup", () => {
  test("backup writes a readable snapshot and prints the key reminder", async () => {
    makeVault(src, KEY_A);
    const before = dirHashReader(src);
    const out = join(work, "b.db");
    const r = await cli(["backup", "--out", out], { GATEHOUSE_DATA_DIR: src });
    expect(r.code).toBe(0);
    expect(r.out.join("\n")).toContain("back up your master key separately");
    const db = new Database(out, { readonly: true });
    expect(new SecretsEngine(db, KEY_A).get("api-keys/example")).toBe("v-src");
    db.close();
    expect(dirHashReader(src)).toEqual(before);
  });

  test("backup with no database exits 1", async () => {
    const r = await cli(["backup", "--out", join(work, "b.db")], { GATEHOUSE_DATA_DIR: src });
    expect(r.code).toBe(1);
    expect(existsSync(join(work, "b.db"))).toBe(false);
  });

  test("backup works on a WAL db whose sidecars are gone (cleanly stopped server)", async () => {
    makeVault(src, KEY_A);
    const db = new Database(join(src, "gatehouse.db"));
    db.run("PRAGMA wal_checkpoint(TRUNCATE)");
    db.close();
    rmSync(join(src, "gatehouse.db-wal"), { force: true });
    rmSync(join(src, "gatehouse.db-shm"), { force: true });
    const before = dirHash(src);
    const out = join(work, "b.db");
    const r = await cli(["backup", "--out", out], { GATEHOUSE_DATA_DIR: src });
    expect(r.code).toBe(0);
    expect(dirHash(src)).toEqual(before);
    const s = new Database(out, { readonly: true });
    expect(new SecretsEngine(s, KEY_A).get("api-keys/example")).toBe("v-src");
    s.close();
  });
});

describe("export", () => {
  test("export fails closed with no passphrase source and no TTY", async () => {
    makeVault(src, KEY_A);
    const out = join(work, "v.bundle");
    const r = await cli(["export", "--out", out], srcEnvA());
    expect(r.code).toBe(1);
    expect(existsSync(out)).toBe(false);
    expect(r.err.join("\n")).toMatch(/passphrase/i);
  });

  test("export fails closed when the named env var is unset or empty", async () => {
    makeVault(src, KEY_A);
    const out = join(work, "v.bundle");
    expect((await cli(["export", "--out", out, "--passphrase-env", "NOPE"], srcEnvA())).code).toBe(1);
    expect((await cli(["export", "--out", out, "--passphrase-env", "PW"], { ...srcEnvA(), PW: "" })).code).toBe(1);
    expect(existsSync(out)).toBe(false);
  });

  test("export rejects a passphrase under 12 chars", async () => {
    makeVault(src, KEY_A);
    const out = join(work, "v.bundle");
    const r = await cli(["export", "--out", out, "--passphrase-env", "PW"], { ...srcEnvA(), PW: "elevenchars" });
    expect(r.code).toBe(1);
    expect(existsSync(out)).toBe(false);
    // 12 UTF-16 units but 6 characters after NFC: still too short
    const decomposed = "é".repeat(6);
    expect(decomposed.length).toBe(12);
    const r2 = await cli(["export", "--out", out, "--passphrase-env", "PW"], { ...srcEnvA(), PW: decomposed });
    expect(r2.code).toBe(1);
    expect(existsSync(out)).toBe(false);
    // exactly 12 is accepted
    const r3 = await cli(["export", "--out", out, "--passphrase-env", "PW"], { ...srcEnvA(), PW: "twelve chars" });
    expect(r3.code).toBe(0);
  });

  test("export refuses to overwrite", async () => {
    makeVault(src, KEY_A);
    const out = join(work, "v.bundle");
    writeFileSync(out, "original");
    const r = await cli(["export", "--out", out, "--passphrase-env", "PW"], srcEnvA());
    expect(r.code).toBe(1);
    expect(readFileSync(out, "utf8")).toBe("original");
  });

  test("export file is mode 0600 and the data dir is untouched", async () => {
    makeVault(src, KEY_A);
    const before = dirHashReader(src);
    const out = await (async () => {
      const f = join(work, "v.bundle");
      const r = await cli(["export", "--out", f, "--passphrase-env", "PW"], srcEnvA());
      expect(r.code).toBe(0);
      return f;
    })();
    expect(statSync(out).mode & 0o777).toBe(0o600);
    expect(dirHashReader(src)).toEqual(before);
  });

  test("export with a prompt asks twice and rejects a mismatch", async () => {
    makeVault(src, KEY_A);
    const out = join(work, "v.bundle");
    const answers = [PW, PW + "x"];
    const r = await cli(["export", "--out", out], srcEnvA(), {
      isTTY: true,
      prompt: async () => answers.shift() as string,
    });
    expect(r.code).toBe(1);
    expect(existsSync(out)).toBe(false);
    const ok = [PW, PW];
    const labels: string[] = [];
    const r2 = await cli(["export", "--out", out], srcEnvA(), {
      isTTY: true,
      prompt: async (l) => { labels.push(l); return ok.shift() as string; },
    });
    expect(r2.code).toBe(0);
    expect(labels.length).toBe(2);
  });

  test("export never echoes the passphrase or the master key", async () => {
    makeVault(src, KEY_A);
    const env = srcEnvA();
    const runs: Cap[] = [];
    runs.push(await cli(["export", "--out", join(work, "a.bundle"), "--passphrase-env", "PW"], env));
    runs.push(await cli(["export", "--out", join(work, "b.bundle"), "--passphrase-env", "PW", "--no-key"], env));
    runs.push(await cli(["export", "--out", join(work, "a.bundle"), "--passphrase-env", "PW"], env)); // exists
    runs.push(await cli(["export", "--out", join(work, "c.bundle"), "--passphrase-env", "PW"], { ...env, PW: "short pw" }));
    // passphrase mistakenly supplied as a flag value or as the env var name
    runs.push(await cli(["export", "--out", join(work, "d.bundle"), `--passphrase=${PW}`], env));
    runs.push(await cli(["export", "--out", join(work, "d.bundle"), "--passphrase", PW], env));
    runs.push(await cli(["export", "--out", join(work, "d.bundle"), "--passphrase-env", PW], env));
    runs.push(await cli(["export", "--out", join(work, "d.bundle"), "--passphrase-env", "Hunter2Hunter2Hunter2"], env));
    runs.push(await cli(["export", PW], env));
    expect(runs[0].code).toBe(0);
    expect(runs[1].code).toBe(0);
    for (const r of runs.slice(2)) expect(r.code).not.toBe(0);
    for (const r of runs) {
      expect(r.all).not.toContain(PW);
      expect(r.all).not.toContain("short pw");
      expect(r.all).not.toContain("Hunter2Hunter2Hunter2");
      expect(r.all.toLowerCase()).not.toContain(KEY_A_HEX);
      noStack(r);
    }
    // the fingerprint is fine to show
    expect(runs[0].all).toContain(keyFingerprint(KEY_A));
  });

  test("export with a short legacy env key exits 1 with one line and cleans its temp snapshot", async () => {
    makeVault(src, KEY_A);
    const tmp = join(root, "tmp");
    mkdirSync(tmp);
    const prev = process.env.TMPDIR;
    process.env.TMPDIR = tmp;
    try {
      // 64+ chars, non-hex: accepted by resolveMasterKey as legacy, decodes to fewer than 32 bytes
      const legacy = "zz" + "a".repeat(64);
      const out = join(work, "v.bundle");
      const r = await cli(["export", "--out", out, "--passphrase-env", "PW"], {
        ...srcEnvA(),
        GATEHOUSE_MASTER_KEY: legacy,
      });
      expect(r.code).toBe(1);
      expect(existsSync(out)).toBe(false);
      noStack(r);
      expect(r.all).not.toContain(legacy);
      expect(r.err.some((l) => /32 bytes/.test(l))).toBe(true);
      expect(readdirSync(tmp)).toEqual([]);
    } finally {
      if (prev === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = prev;
    }
  });

  test("export deletes its temp snapshot when writing the output fails", async () => {
    makeVault(src, KEY_A);
    const tmp = join(root, "tmp");
    mkdirSync(tmp);
    const prev = process.env.TMPDIR;
    process.env.TMPDIR = tmp;
    try {
      const out = join(work, "missing-dir", "v.bundle");
      const r = await cli(["export", "--out", out, "--passphrase-env", "PW"], srcEnvA());
      expect(r.code).toBe(1);
      noStack(r);
      expect(existsSync(out)).toBe(false);
      expect(readdirSync(tmp)).toEqual([]);
    } finally {
      if (prev === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = prev;
    }
  });
});

describe("import", () => {
  test("import refuses a live server with exit 3", async () => {
    const bundle = await exportSealed();
    makeVault(dst, KEY_B, "v-dst");
    const stop = startHeartbeat(dst, 60_000, () => {});
    try {
      const before = dirHash(dst);
      const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: dst, PW });
      expect(r.code).toBe(3);
      expect(r.err.join("\n")).toMatch(/stop/i);
      expect(dirHash(dst)).toEqual(before);
    } finally {
      stop();
    }
  });

  test("import with a wrong passphrase exits 1 and leaves the data dir byte-identical", async () => {
    const bundle = await exportSealed();
    makeVault(dst, KEY_B, "v-dst");
    const before = dirHash(dst);
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], {
      GATEHOUSE_DATA_DIR: dst,
      PW: "not the passphrase",
    });
    expect(r.code).toBe(1);
    expect(r.err.length).toBe(1);
    noStack(r);
    expect(dirHash(dst)).toEqual(before);
  });

  test("import of a non-bundle file exits 1 with a one-line error", async () => {
    makeVault(dst, KEY_B, "v-dst");
    const before = dirHash(dst);
    const junk = join(work, "junk.bin");
    writeFileSync(junk, "this is not a bundle at all, just some bytes");
    const r = await cli(["import", "--in", junk, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: dst, PW });
    expect(r.code).toBe(1);
    expect(r.err.length).toBe(1);
    expect(r.err[0]).not.toContain("\n");
    noStack(r);
    expect(dirHash(dst)).toEqual(before);
    // a missing file is also one line
    const r2 = await cli(["import", "--in", join(work, "nope"), "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: dst, PW });
    expect(r2.code).toBe(1);
    expect(r2.err.length).toBe(1);
  });

  test("a bundle whose payload is not a SQLite database exits 1 and writes nothing", async () => {
    const bundle = join(work, "fake.bundle");
    writeFileSync(
      bundle,
      sealBundle({
        db: new TextEncoder().encode("not sqlite"),
        passphrase: PW,
        masterKey: KEY_A,
        includeKey: true,
        createdAt: NOW.toISOString(),
        rowCounts: {},
        scryptLogN: 10,
      })
    );
    makeVault(dst, KEY_B, "v-dst");
    const before = dirHash(dst);
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: dst, PW });
    expect(r.code).toBe(1);
    noStack(r);
    expect(dirHash(dst)).toEqual(before);
  });

  test("unsealed import with a different key exits 2 and writes nothing", async () => {
    const bundle = await exportUnsealed();
    makeVault(dst, KEY_B, "v-dst");
    const before = dirHash(dst);
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], {
      GATEHOUSE_DATA_DIR: dst,
      GATEHOUSE_MASTER_KEY: KEY_B_HEX,
      PW,
    });
    expect(r.code).toBe(2);
    expect(r.err.join("\n")).toContain("different master key");
    expect(dirHash(dst)).toEqual(before);
  });

  test("unsealed import with no key available exits 2 and writes nothing", async () => {
    const bundle = await exportUnsealed();
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: dst, PW });
    expect(r.code).toBe(2);
    expect(readdirSync(dst)).toEqual([]);
  });

  test("unsealed import with the matching key restores and does not write master.key", async () => {
    const bundle = await exportUnsealed();
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], {
      GATEHOUSE_DATA_DIR: dst,
      GATEHOUSE_MASTER_KEY: KEY_A_HEX,
      PW,
    });
    expect(r.code).toBe(0);
    expect(existsSync(join(dst, "master.key"))).toBe(false);
    expect(readSecret(dst, KEY_A)).toBe("v-src");
  });

  test("unsealed import with --force restores anyway", async () => {
    const bundle = await exportUnsealed();
    makeVault(dst, KEY_B, "v-dst");
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW", "--force"], {
      GATEHOUSE_DATA_DIR: dst,
      GATEHOUSE_MASTER_KEY: KEY_B_HEX,
      PW,
    });
    expect(r.code).toBe(0);
    expect(readSecret(dst, KEY_A)).toBe("v-src");
    expect(existsSync(join(dst, `gatehouse.db.pre-import-${STAMP}`))).toBe(true);
  });

  test("sealed import with a conflicting GATEHOUSE_MASTER_KEY exits 2", async () => {
    const bundle = await exportSealed();
    makeVault(dst, KEY_B, "v-dst");
    const before = dirHash(dst);
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], {
      GATEHOUSE_DATA_DIR: dst,
      GATEHOUSE_MASTER_KEY: KEY_B_HEX,
      PW,
    });
    expect(r.code).toBe(2);
    expect(r.err.join("\n")).toContain(
      "GATEHOUSE_MASTER_KEY is set to a different key than this backup carries. Unset it, or set it to the backup's key."
    );
    expect(dirHash(dst)).toEqual(before);
  });

  test("sealed import treats an empty GATEHOUSE_MASTER_KEY as unset", async () => {
    const bundle = await exportSealed();
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], {
      GATEHOUSE_DATA_DIR: dst,
      GATEHOUSE_MASTER_KEY: "  ",
      PW,
    });
    expect(r.code).toBe(0);
    expect(readFileSync(join(dst, "master.key"), "utf8").trim()).toBe(KEY_A_HEX);
  });

  test("sealed import with a matching GATEHOUSE_MASTER_KEY does not write master.key", async () => {
    const bundle = await exportSealed();
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], {
      GATEHOUSE_DATA_DIR: dst,
      GATEHOUSE_MASTER_KEY: KEY_A_HEX,
      PW,
    });
    expect(r.code).toBe(0);
    expect(existsSync(join(dst, "master.key"))).toBe(false);
    expect(readSecret(dst, KEY_A)).toBe("v-src");
  });

  test("sealed import into an empty dir writes master.key 0600 and never prints the key", async () => {
    const bundle = await exportSealed();
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: dst, PW });
    expect(r.code).toBe(0);
    const kp = join(dst, "master.key");
    expect(readFileSync(kp, "utf8").trim()).toBe(KEY_A_HEX);
    expect(statSync(kp).mode & 0o777).toBe(0o600);
    expect(readSecret(dst, KEY_A)).toBe("v-src");
    expect(r.all.toLowerCase()).not.toContain(KEY_A_HEX);
    expect(r.all).not.toContain(PW);
    expect(r.out.join("\n")).toContain(keyFingerprint(KEY_A));
  });

  test("import keeps the previous db as gatehouse.db.pre-import-<stamp>", async () => {
    const bundle = await exportSealed();
    makeVault(dst, KEY_A, "v-dst");
    const oldDb = readFileSync(join(dst, "gatehouse.db"));
    const hadWal = existsSync(join(dst, "gatehouse.db-wal"));
    const oldWal = hadWal ? readFileSync(join(dst, "gatehouse.db-wal")) : null;
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: dst, PW });
    expect(r.code).toBe(0);
    const pre = join(dst, `gatehouse.db.pre-import-${STAMP}`);
    expect(readFileSync(pre).equals(oldDb)).toBe(true);
    if (oldWal) expect(readFileSync(`${pre}-wal`).equals(oldWal)).toBe(true);
    expect(r.out.join("\n")).toContain(pre);
    expect(readSecret(dst, KEY_A)).toBe("v-src");
    // the pre-import copy (with its WAL beside it) still holds the old data
    expect(readSecret_at(pre, KEY_A)).toBe("v-dst");
  });

  test("a second import in the same second does not clobber the first pre-import copy", async () => {
    const bundle = await exportSealed();
    makeVault(dst, KEY_A, "v-dst");
    expect((await cli(["import", "--in", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: dst, PW })).code).toBe(0);
    const first = readFileSync(join(dst, `gatehouse.db.pre-import-${STAMP}`));
    expect((await cli(["import", "--in", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: dst, PW })).code).toBe(0);
    expect(readFileSync(join(dst, `gatehouse.db.pre-import-${STAMP}`)).equals(first)).toBe(true);
    expect(readdirSync(dst).filter((f) => f.startsWith("gatehouse.db.pre-import-") && !/-(wal|shm)$/.test(f)).length).toBe(2);
  });

  test("sealed import keeps a different existing master.key as master.key.pre-import-<stamp>", async () => {
    const bundle = await exportSealed();
    makeVault(dst, KEY_B, "v-dst");
    writeFileSync(join(dst, "master.key"), KEY_B_HEX + "\n", { mode: 0o600 });
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: dst, PW });
    expect(r.code).toBe(0);
    expect(readFileSync(join(dst, "master.key"), "utf8").trim()).toBe(KEY_A_HEX);
    expect(readFileSync(join(dst, `master.key.pre-import-${STAMP}`), "utf8").trim()).toBe(KEY_B_HEX);
  });

  test("import leaves no WAL sidecars beside the restored db", async () => {
    const bundle = await exportSealed();
    makeVault(dst, KEY_B, "v-dst");
    // stray sidecars with no db beside them are removed too
    const lone = join(root, "lone");
    mkdirSync(lone);
    writeFileSync(join(lone, "gatehouse.db-wal"), "garbage");
    writeFileSync(join(lone, "gatehouse.db-shm"), "garbage");
    for (const d of [dst, lone]) {
      const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: d, PW });
      expect(r.code).toBe(0);
      expect(existsSync(join(d, "gatehouse.db-wal"))).toBe(false);
      expect(existsSync(join(d, "gatehouse.db-shm"))).toBe(false);
      expect(existsSync(join(d, "gatehouse.db.import-tmp"))).toBe(false);
    }
  });

  test("export refuses a vault whose key does not verify it", async () => {
    makeVault(src, KEY_A);
    const db = new Database(join(src, "gatehouse.db"));
    db.query("UPDATE secrets SET dek_nonce = ?").run(new Uint8Array(3));
    db.close();
    const bundle = join(work, "v.bundle");
    const r = await cli(["export", "--out", bundle, "--passphrase-env", "PW"], srcEnvA());
    expect(r.code).toBe(1);
    noStack(r);
    expect(existsSync(bundle)).toBe(false);
  });

  test("import whose restored data fails verification exits 1 without --force", async () => {
    // a vault whose secret row is corrupt (wrong-length nonce makes verifyVault throw)
    makeVault(src, KEY_A);
    const db = new Database(join(src, "gatehouse.db"));
    db.query("UPDATE secrets SET dek_nonce = ?").run(new Uint8Array(3));
    db.close();
    // export now refuses a vault its key cannot verify, so seal this one directly
    const bundle = join(work, "v.bundle");
    const rawDb = new Database(join(src, "gatehouse.db"));
    rawDb.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    rawDb.close();
    writeFileSync(
      bundle,
      sealBundle({
        db: new Uint8Array(readFileSync(join(src, "gatehouse.db"))),
        passphrase: PW,
        masterKey: KEY_A,
        includeKey: true,
        createdAt: NOW.toISOString(),
        rowCounts: {},
        scryptLogN: 10,
      })
    );
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: dst, PW });
    expect(r.code).toBe(1);
    noStack(r);
    const r2 = await cli(["import", "--in", bundle, "--passphrase-env", "PW", "--force"], { GATEHOUSE_DATA_DIR: dst, PW });
    expect(r2.code).toBe(0);
  });
});

function readSecret_at(dbPath: string, key: Buffer): string | null {
  const db = new Database(dbPath, { readonly: true });
  try {
    return new SecretsEngine(db, key).get("api-keys/example");
  } finally {
    db.close();
  }
}

describe("verify", () => {
  test("verify exits 0 on a good key and 1 on a wrong one", async () => {
    makeVault(src, KEY_A);
    const before = dirHashReader(src);
    const good = await cli(["verify"], { GATEHOUSE_DATA_DIR: src, GATEHOUSE_MASTER_KEY: KEY_A_HEX });
    expect(good.code).toBe(0);
    expect(good.out.join("\n")).toContain(keyFingerprint(KEY_A));
    const bad = await cli(["verify"], { GATEHOUSE_DATA_DIR: src, GATEHOUSE_MASTER_KEY: KEY_B_HEX });
    expect(bad.code).toBe(1);
    expect(bad.all).toContain(keyFingerprint(KEY_B));
    expect(good.all + bad.all).not.toContain(KEY_A_HEX);
    expect(dirHashReader(src)).toEqual(before);
  });

  test("verify reads master.key when no env key is set", async () => {
    makeVault(src, KEY_A);
    writeFileSync(join(src, "master.key"), KEY_A_HEX + "\n", { mode: 0o600 });
    const r = await cli(["verify"], { GATEHOUSE_DATA_DIR: src });
    expect(r.code).toBe(0);
  });

  test("verify on an empty data dir exits 1 and does not create master.key", async () => {
    const r = await cli(["verify"], { GATEHOUSE_DATA_DIR: dst });
    expect(r.code).toBe(1);
    expect(r.err.join("\n")).toContain("no master key");
    expect(readdirSync(dst)).toEqual([]);
  });

  test("verify with a key but no database exits 1", async () => {
    const r = await cli(["verify"], { GATEHOUSE_DATA_DIR: dst, GATEHOUSE_MASTER_KEY: KEY_A_HEX });
    expect(r.code).toBe(1);
    expect(readdirSync(dst)).toEqual([]);
  });

  test("verify treats a throwing verifyVault (corrupt row) as a one-line failure", async () => {
    makeVault(src, KEY_A);
    const db = new Database(join(src, "gatehouse.db"));
    db.query("UPDATE secrets SET dek_nonce = ?").run(new Uint8Array(3));
    db.close();
    const r = await cli(["verify"], { GATEHOUSE_DATA_DIR: src, GATEHOUSE_MASTER_KEY: KEY_A_HEX });
    expect(r.code).toBe(1);
    noStack(r);
  });

  test("verify works on a WAL db whose sidecars are gone, without creating any", async () => {
    makeVault(src, KEY_A);
    const db = new Database(join(src, "gatehouse.db"));
    db.run("PRAGMA wal_checkpoint(TRUNCATE)");
    db.close();
    rmSync(join(src, "gatehouse.db-wal"), { force: true });
    rmSync(join(src, "gatehouse.db-shm"), { force: true });
    const before = dirHash(src);
    const r = await cli(["verify"], { GATEHOUSE_DATA_DIR: src, GATEHOUSE_MASTER_KEY: KEY_A_HEX });
    expect(r.code).toBe(0);
    expect(dirHash(src)).toEqual(before);
  });
});

describe("dispatch", () => {
  test("unknown command prints usage and exits 1", async () => {
    const r = await cli(["frobnicate"]);
    expect(r.code).toBe(1);
    expect(r.out).toEqual([]);
    expect(r.err.join("\n")).toContain("gatehouse backup");
    const none = await cli([]);
    expect(none.code).toBe(1);
  });

  test("--help prints usage to stderr and exits 0", async () => {
    for (const argv of [["--help"], ["-h"], ["export", "--help"]]) {
      const r = await cli(argv);
      expect(r.code).toBe(0);
      expect(r.out).toEqual([]);
      expect(r.err.join("\n")).toContain("gatehouse import");
    }
    expect((await cli(["--help"])).all).not.toContain("SCRYPT");
  });

  test("missing required options exit 1", async () => {
    expect((await cli(["backup"])).code).toBe(1);
    expect((await cli(["export", "--passphrase-env", "PW"])).code).toBe(1);
    expect((await cli(["import"])).code).toBe(1);
    expect((await cli(["verify", "--force"])).code).toBe(1);
  });
});

describe("review fixes", () => {
  test("backup output file is mode 0600", async () => {
    makeVault(src, KEY_A);
    const out = join(work, "b.db");
    expect((await cli(["backup", "--out", out], { GATEHOUSE_DATA_DIR: src })).code).toBe(0);
    expect(statSync(out).mode & 0o777).toBe(0o600);
  });

  test("a prompt that cannot hide input fails closed in one line", async () => {
    makeVault(src, KEY_A);
    const out = join(work, "v.bundle");
    const r = await cli(["export", "--out", out], srcEnvA(), {
      isTTY: true,
      prompt: async () => {
        throw new Error("cannot turn off echo on this terminal. Use --passphrase-env VAR instead");
      },
    });
    expect(r.code).toBe(1);
    expect(r.err.length).toBe(1);
    expect(r.err[0]).toContain("--passphrase-env");
    noStack(r);
    expect(existsSync(out)).toBe(false);
    // import fails closed the same way, before any write
    const bundle = await exportSealed(join(work, "w.bundle"));
    const r2 = await cli(["import", "--in", bundle], { GATEHOUSE_DATA_DIR: dst }, {
      isTTY: true,
      prompt: async () => { throw new Error("cannot turn off echo"); },
    });
    expect(r2.code).toBe(1);
    expect(readdirSync(dst)).toEqual([]);
  });

  test("sealed --force past a conflicting env key reports verify SKIPPED, not ok", async () => {
    const bundle = await exportSealed();
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW", "--force"], {
      GATEHOUSE_DATA_DIR: dst,
      GATEHOUSE_MASTER_KEY: KEY_B_HEX,
      PW,
    });
    expect(r.code).toBe(0);
    const out = r.out.join("\n");
    expect(out).toContain("verify: SKIPPED. GATEHOUSE_MASTER_KEY overrides the restored key and does not match this data.");
    expect(out).not.toContain("verify: ok");
    expect(existsSync(join(dst, "master.key"))).toBe(false);
  });

  /** dst holds a vault (db + WAL) and a master.key for a different key than KEY_A. */
  function seedTarget() {
    makeVault(dst, KEY_B, "v-dst");
    writeFileSync(join(dst, "gatehouse.db-wal"), "wal bytes that must survive");
    writeFileSync(join(dst, "master.key"), KEY_B_HEX + "\n", { mode: 0o600 });
  }

  test("a failure after step 4 rolls back to a byte-identical data dir", async () => {
    const bundle = await exportSealed();
    seedTarget();
    mkdirSync(join(dst, "gatehouse.db.import-tmp")); // makes the step 5 write fail
    const before = dirHashReader(dst);
    const r = await cli(["import", "--in", bundle, "--passphrase-env", "PW"], { GATEHOUSE_DATA_DIR: dst, PW });
    expect(r.code).toBe(1);
    expect(r.err.length).toBe(1);
    expect(r.err[0]).toContain("Nothing was changed");
    noStack(r);
    expect(dirHashReader(dst)).toEqual(before);
  });

  const swapArgs = () => ({
    dataDir: dst,
    db: new Uint8Array(readFileSync(join(work, "restored.db"))),
    stamp: STAMP,
    keyHex: KEY_A_HEX,
    keyFingerprint: keyFingerprint(KEY_A),
    log: () => {},
  });
  const failingPersist: typeof persistKeyFile = () => ({ ok: false, exists: false, error: "disk full" });

  function prepRestored() {
    makeVault(src, KEY_A);
    const db = new Database(join(src, "gatehouse.db"), { readonly: true });
    db.query("VACUUM INTO ?").run(join(work, "restored.db"));
    db.close();
  }

  test("a failing key-file step restores master.key, the db and its WAL", () => {
    prepRestored();
    seedTarget();
    const before = dirHash(dst);
    let thrown: any;
    try {
      _swapIntoPlace(swapArgs(), { renameSync, persistKeyFile: failingPersist });
    } catch (e) {
      thrown = e;
    }
    expect(thrown?.message).toContain("disk full");
    expect(thrown?.message).toContain("Nothing was changed");
    expect(thrown?.code).toBe(1);
    const after = dirHash(dst);
    for (const f of ["gatehouse.db", "gatehouse.db-wal", "master.key"]) expect(after[f]).toBe(before[f]);
    // -shm is a rebuildable index that step 5 deletes; nothing else may differ
    delete before["gatehouse.db-shm"];
    expect(after).toEqual(before);
  });

  test("a rollback that cannot put the previous db back says where it is, never 'nothing changed'", () => {
    prepRestored();
    seedTarget();
    const oldDb = readFileSync(join(dst, "gatehouse.db"));
    const pre = join(dst, `gatehouse.db.pre-import-${STAMP}`);
    const stuck = (from: string, to: string) => {
      if (from === pre) throw new Error("EACCES: simulated");
      renameSync(from, to);
    };
    let thrown: any;
    try {
      _swapIntoPlace(swapArgs(), { renameSync: stuck, persistKeyFile: failingPersist });
    } catch (e) {
      thrown = e;
    }
    expect(thrown?.code).toBe(1);
    expect(thrown?.message).toContain("rollback incomplete");
    expect(thrown?.message).toContain(`previous database is at ${pre}; move it back to ${join(dst, "gatehouse.db")}`);
    expect(thrown?.message).not.toContain("Nothing was changed");
    expect(thrown?.message).not.toContain("\n");
    expect(readFileSync(pre).equals(oldDb)).toBe(true);
    // the rest was still undone
    expect(readFileSync(join(dst, "master.key"), "utf8").trim()).toBe(KEY_B_HEX);
    expect(readFileSync(join(dst, "gatehouse.db-wal"), "utf8")).toBe("wal bytes that must survive");
    expect(existsSync(join(dst, "gatehouse.db"))).toBe(false);
  });

  test("a failed write of the restored db leaves gatehouse.db in place under its own name", () => {
    prepRestored();
    seedTarget();
    const before = dirHash(dst);
    let thrown: any;
    try {
      _swapIntoPlace(swapArgs(), {
        renameSync,
        persistKeyFile,
        writeFile: (path) => {
          writeFileSync(path, "partial");
          throw new Error("ENOSPC: simulated");
        },
      });
    } catch (e) {
      thrown = e;
    }
    expect(thrown?.code).toBe(1);
    expect(thrown?.message).toContain("ENOSPC");
    expect(thrown?.message).toContain("Nothing was changed");
    // byte-identical, including the -shm: nothing was moved or cleared
    expect(dirHash(dst)).toEqual(before);
    expect(existsSync(join(dst, "gatehouse.db.import-tmp"))).toBe(false);
  });

  test("the restored db is written and fsynced before the previous one is moved", () => {
    prepRestored();
    seedTarget();
    const args = swapArgs();
    const seen: string[] = [];
    _swapIntoPlace(args, {
      persistKeyFile,
      renameSync: (from, to) => {
        if (from === join(dst, "gatehouse.db")) {
          const tmp = readFileSync(join(dst, "gatehouse.db.import-tmp"));
          expect(tmp.equals(Buffer.from(args.db))).toBe(true);
          seen.push("db-moved-with-tmp-complete");
        }
        renameSync(from, to);
      },
    });
    expect(seen).toEqual(["db-moved-with-tmp-complete"]);
    expect(readFileSync(join(dst, "gatehouse.db")).equals(Buffer.from(args.db))).toBe(true);
  });

  test("a server that appears before the swap is refused with exit 3 and nothing changes", () => {
    prepRestored();
    seedTarget();
    const before = dirHash(dst);
    let thrown: any;
    try {
      _swapIntoPlace({ ...swapArgs(), isLive: () => true });
    } catch (e) {
      thrown = e;
    }
    expect(thrown?.code).toBe(3);
    expect(thrown?.message).toContain("Nothing was changed");
    expect(dirHash(dst)).toEqual(before);
  });

  test("_rollbackImport reports a master key it could not put back", () => {
    const keep = join(dst, `master.key.pre-import-${STAMP}`);
    const problems = _rollbackImport(
      { createdTmp: null, restoredDb: null, renames: [[join(dst, "master.key"), keep]] },
      () => { throw new Error("EXDEV"); }
    );
    expect(problems).toEqual([
      `previous master key is at ${keep}; move it back to ${join(dst, "master.key")} before starting the server (EXDEV)`,
    ]);
    expect(_rollbackImport({ createdTmp: null, restoredDb: null, renames: [] })).toEqual([]);
  });
});
