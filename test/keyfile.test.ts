import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { hkdfSync } from "crypto";
import { mkdtempSync, writeFileSync, readFileSync, statSync, existsSync, chmodSync, rmSync, readdirSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { keyFingerprint } from "../src/secrets/engine";
import {
  resolveMasterKey,
  persistKeyFile,
  MasterKeyError,
  KEY_FILE_NAME,
  NEXT_KEY_FILE_NAME,
  writeNextKeyFile,
  discardNextKeyFile,
  installNextKeyFile,
  KeyInstallError,
} from "../src/backup/keyfile";

const HEX_A = "a".repeat(64);
const HEX_B = "b".repeat(64);

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "gh-keyfile-"));
});
afterEach(() => {
  try { chmodSync(dir, 0o700); } catch {}
  rmSync(dir, { recursive: true, force: true });
});

describe("keyFingerprint", () => {
  test("matches the documented HKDF output", () => {
    const expected = Buffer.from(
      hkdfSync("sha256", Buffer.from(HEX_A, "hex"), "gatehouse-v1", "gatehouse-fingerprint", 16)
    ).toString("hex");
    const fp = keyFingerprint(Buffer.from(HEX_A, "hex"));
    expect(fp).toBe(expected);
    expect(fp).toHaveLength(32);
  });
});

describe("resolveMasterKey", () => {
  test("KEY_FILE_NAME is master.key", () => {
    expect(KEY_FILE_NAME).toBe("master.key");
  });

  test("env key wins even when a key file exists", () => {
    writeFileSync(join(dir, "master.key"), HEX_B);
    const r = resolveMasterKey({ envKey: HEX_A, dataDir: dir, log: () => {} });
    expect(r.source).toBe("env");
    expect(r.key.toString("hex")).toBe(HEX_A);
  });

  test("invalid env key throws invalid_env and does not fall through to the file", () => {
    writeFileSync(join(dir, "master.key"), HEX_B);
    expect(() => resolveMasterKey({ envKey: "short", dataDir: dir })).toThrow(
      expect.objectContaining({ code: "invalid_env" })
    );
  });

  test("non-empty env key under 64 chars is a MasterKeyError invalid_env", () => {
    try {
      resolveMasterKey({ envKey: "short", dataDir: dir });
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(MasterKeyError);
    }
  });

  test("empty and whitespace-only env keys count as unset and generate on a fresh dir", () => {
    for (const envKey of ["", "   "]) {
      const d = mkdtempSync(join(tmpdir(), "gh-keyfile-"));
      const r = resolveMasterKey({ envKey, dataDir: d, log: () => {} });
      expect(r.source).toBe("generated");
      rmSync(d, { recursive: true, force: true });
    }
  });

  test("empty env key with an existing db and no key file throws missing", () => {
    writeFileSync(join(dir, "gatehouse.db"), "");
    expect(() => resolveMasterKey({ envKey: "", dataDir: dir })).toThrow(
      expect.objectContaining({ code: "missing" })
    );
  });

  test("64+ char non-hex env value is accepted as legacy, with a warning", () => {
    const bad = "z".repeat(10) + "a".repeat(60);
    const lines: string[] = [];
    const r = resolveMasterKey({ envKey: bad, dataDir: dir, log: (l) => lines.push(l) });
    expect(r.source).toBe("env");
    expect(r.key.equals(Buffer.from(bad, "hex"))).toBe(true);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("not valid hex");
    expect(lines[0]).toContain("re-key");
  });

  test("valid hex env key logs nothing", () => {
    const lines: string[] = [];
    resolveMasterKey({ envKey: HEX_A, dataDir: dir, log: (l) => lines.push(l) });
    expect(lines).toHaveLength(0);
  });

  test("persistKeyFile reports EEXIST without touching the existing file", () => {
    writeFileSync(join(dir, "master.key"), HEX_B);
    const res = persistKeyFile(dir, join(dir, "master.key"), HEX_A);
    expect(res).toEqual({ ok: false, exists: true });
    expect(readFileSync(join(dir, "master.key"), "utf8")).toBe(HEX_B);
  });

  test("persistKeyFile surfaces the underlying error for other failures", () => {
    if (process.getuid?.() === 0) return;
    chmodSync(dir, 0o500);
    const res = persistKeyFile(dir, join(dir, "master.key"), HEX_A);
    expect(res.ok).toBe(false);
    expect((res as any).exists).toBe(false);
    expect((res as any).error).toMatch(/EACCES|permission/i);
  });

  test("key file is read, surrounding whitespace tolerated", () => {
    writeFileSync(join(dir, "master.key"), "  " + HEX_B + "\n");
    const r = resolveMasterKey({ envKey: undefined, dataDir: dir });
    expect(r.source).toBe("file");
    expect(r.key.toString("hex")).toBe(HEX_B);
  });

  test("garbage key file throws invalid_file and is left untouched", () => {
    writeFileSync(join(dir, "master.key"), "not-hex");
    expect(() => resolveMasterKey({ envKey: undefined, dataDir: dir })).toThrow(
      expect.objectContaining({ code: "invalid_file" })
    );
    expect(readFileSync(join(dir, "master.key"), "utf8")).toBe("not-hex");
  });

  test("fresh dir generates, persists 0600, and logs the banner with the key", () => {
    const lines: string[] = [];
    const r = resolveMasterKey({ envKey: undefined, dataDir: dir, log: (l) => lines.push(l) });
    expect(r.source).toBe("generated");
    expect(statSync(join(dir, "master.key")).mode & 0o777).toBe(0o600);
    expect(readFileSync(join(dir, "master.key"), "utf8").trim()).toBe(r.key.toString("hex"));
    expect(lines.join("\n")).toContain("GATEHOUSE GENERATED A NEW MASTER KEY");
    expect(lines.join("\n")).toContain(r.key.toString("hex"));
    expect(lines.join("\n")).toContain(join(dir, "master.key"));
  });

  test("second resolve on the same dir reuses the key and logs nothing", () => {
    const first = resolveMasterKey({ envKey: undefined, dataDir: dir, log: () => {} });
    const lines: string[] = [];
    const second = resolveMasterKey({ envKey: undefined, dataDir: dir, log: (l) => lines.push(l) });
    expect(second.source).toBe("file");
    expect(second.key.equals(first.key)).toBe(true);
    expect(lines).toHaveLength(0);
  });

  test("db present but no key anywhere throws missing, writes nothing", () => {
    writeFileSync(join(dir, "gatehouse.db"), "");
    expect(() => resolveMasterKey({ envKey: undefined, dataDir: dir })).toThrow(
      expect.objectContaining({ code: "missing" })
    );
    expect(existsSync(join(dir, "master.key"))).toBe(false);
  });

  test("allowGenerate false on a fresh dir throws missing", () => {
    expect(() => resolveMasterKey({ envKey: undefined, dataDir: dir, allowGenerate: false })).toThrow(
      expect.objectContaining({ code: "missing" })
    );
    expect(existsSync(join(dir, "master.key"))).toBe(false);
  });

  test("unwritable data dir returns generated-unpersisted and still logs the key", () => {
    if (process.getuid?.() === 0) return;
    chmodSync(dir, 0o500);
    const lines: string[] = [];
    const r = resolveMasterKey({ envKey: undefined, dataDir: dir, log: (l) => lines.push(l) });
    expect(r.source).toBe("generated-unpersisted");
    const out = lines.join("\n");
    expect(out).toContain(r.key.toString("hex"));
    expect(out).toContain("NOT SAVED");
    expect(out).toMatch(/EACCES|permission/i);
    expect(existsSync(join(dir, "master.key"))).toBe(false);
  });

  test("data dir that does not exist yet is created", () => {
    const nested = join(dir, "nested");
    const r = resolveMasterKey({ envKey: undefined, dataDir: nested, log: () => {} });
    expect(r.source).toBe("generated");
    expect(existsSync(join(nested, "master.key"))).toBe(true);
  });
});

describe("env key whitespace (F5)", () => {
  test("64-hex env key with a trailing newline or spaces logs nothing", () => {
    for (const envKey of [HEX_A + "\n", HEX_A + "  ", HEX_A + "\r\n"]) {
      const lines: string[] = [];
      const r = resolveMasterKey({ envKey, dataDir: dir, log: (l) => lines.push(l) });
      expect(r.source).toBe("env");
      expect(r.key.toString("hex")).toBe(HEX_A);
      expect(lines).toHaveLength(0);
    }
  });

  test("valid hex that does not decode to 32 bytes still warns", () => {
    const lines: string[] = [];
    resolveMasterKey({ envKey: HEX_A + "ab", dataDir: dir, log: (l) => lines.push(l) });
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("re-key");
  });
});

describe("persistKeyFile partial writes (F5)", () => {
  test("a write failure after create removes the partial file", () => {
    const keyPath = join(dir, "master.key");
    const res = persistKeyFile(dir, keyPath, HEX_A, () => {
      throw Object.assign(new Error("ENOSPC: no space left on device"), { code: "ENOSPC" });
    });
    expect(res).toEqual({ ok: false, exists: false, error: "ENOSPC: no space left on device" });
    expect(existsSync(keyPath)).toBe(false);
  });
});

describe("rotation key file steps (F1b)", () => {
  const next = () => join(dir, NEXT_KEY_FILE_NAME);
  const cur = () => join(dir, KEY_FILE_NAME);

  test("NEXT_KEY_FILE_NAME is master.key.next", () => {
    expect(NEXT_KEY_FILE_NAME).toBe("master.key.next");
  });

  test("writeNextKeyFile writes the hex key mode 0600, replacing a leftover", () => {
    writeFileSync(next(), "leftover", { mode: 0o644 });
    const p = writeNextKeyFile(dir, HEX_B);
    expect(p).toBe(next());
    expect(readFileSync(p, "utf8").trim()).toBe(HEX_B);
    expect(statSync(p).mode & 0o777).toBe(0o600);
  });

  test("writeNextKeyFile throws and leaves nothing when the write fails", () => {
    expect(() =>
      writeNextKeyFile(dir, HEX_B, () => {
        throw new Error("EIO: i/o error");
      })
    ).toThrow("EIO");
    expect(existsSync(next())).toBe(false);
  });

  test("writeNextKeyFile throws on an unwritable dir", () => {
    if (process.getuid?.() === 0) return;
    chmodSync(dir, 0o500);
    expect(() => writeNextKeyFile(dir, HEX_B)).toThrow(/EACCES|permission/i);
  });

  test("discardNextKeyFile removes it and tolerates absence", () => {
    writeNextKeyFile(dir, HEX_B);
    discardNextKeyFile(dir);
    expect(existsSync(next())).toBe(false);
    expect(() => discardNextKeyFile(dir)).not.toThrow();
  });

  test("installNextKeyFile keeps the old key as pre-rotate and installs the new one", () => {
    writeFileSync(cur(), HEX_A + "\n", { mode: 0o600 });
    writeNextKeyFile(dir, HEX_B);
    const r = installNextKeyFile(dir, "20261119T123456Z");
    expect(r.keyPath).toBe(cur());
    expect(r.previous).toBe(join(dir, "master.key.pre-rotate-20261119T123456Z"));
    expect(readFileSync(cur(), "utf8").trim()).toBe(HEX_B);
    expect(readFileSync(r.previous!, "utf8").trim()).toBe(HEX_A);
    expect(statSync(cur()).mode & 0o777).toBe(0o600);
    expect(existsSync(next())).toBe(false);
    const again = resolveMasterKey({ envKey: undefined, dataDir: dir, log: () => {} });
    expect(again.source).toBe("file");
    expect(again.key.toString("hex")).toBe(HEX_B);
  });

  test("installNextKeyFile picks a free pre-rotate name", () => {
    writeFileSync(join(dir, "master.key.pre-rotate-S"), "taken");
    writeFileSync(cur(), HEX_A);
    writeNextKeyFile(dir, HEX_B);
    const r = installNextKeyFile(dir, "S");
    expect(r.previous).toBe(join(dir, "master.key.pre-rotate-S-2"));
    expect(readFileSync(join(dir, "master.key.pre-rotate-S"), "utf8")).toBe("taken");
  });

  test("installNextKeyFile with no current master.key just installs", () => {
    writeNextKeyFile(dir, HEX_B);
    const r = installNextKeyFile(dir, "S");
    expect(r.previous).toBeNull();
    expect(readFileSync(cur(), "utf8").trim()).toBe(HEX_B);
  });

  test("a failed final rename leaves the old key in place and names the file holding the new one", () => {
    writeFileSync(cur(), HEX_A);
    writeNextKeyFile(dir, HEX_B);
    let err: unknown;
    try {
      installNextKeyFile(dir, "S", {
        renameSync: () => {
          throw new Error("EXDEV: boom");
        },
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(KeyInstallError);
    expect((err as KeyInstallError).newKeyPath).toBe(next());
    expect((err as Error).message).toContain(next());
    expect(readFileSync(cur(), "utf8").trim()).toBe(HEX_A);
    expect(readFileSync(next(), "utf8").trim()).toBe(HEX_B);
  });

  test("a failure keeping the previous key aborts before master.key is touched", () => {
    writeFileSync(cur(), HEX_A);
    writeNextKeyFile(dir, HEX_B);
    let err: unknown;
    try {
      installNextKeyFile(dir, "S", {
        linkSync: () => {
          throw new Error("EPERM: no links");
        },
        copyFileSync: () => {
          throw new Error("EIO: no copy");
        },
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(KeyInstallError);
    expect((err as KeyInstallError).newKeyPath).toBe(next());
    expect(readFileSync(cur(), "utf8").trim()).toBe(HEX_A);
    expect(readdirSync(dir).sort()).toEqual(["master.key", "master.key.next"]);
  });

  test("link not supported falls back to a 0600 copy", () => {
    writeFileSync(cur(), HEX_A, { mode: 0o600 });
    writeNextKeyFile(dir, HEX_B);
    const r = installNextKeyFile(dir, "S", {
      linkSync: () => {
        throw new Error("EPERM: no links");
      },
    });
    expect(readFileSync(r.previous!, "utf8").trim()).toBe(HEX_A);
    expect(statSync(r.previous!).mode & 0o777).toBe(0o600);
    expect(readFileSync(cur(), "utf8").trim()).toBe(HEX_B);
  });

  test("resolveMasterKey warns about a leftover master.key.next", () => {
    writeFileSync(cur(), HEX_A);
    writeFileSync(next(), HEX_B);
    const lines: string[] = [];
    const r = resolveMasterKey({ envKey: undefined, dataDir: dir, log: (l) => lines.push(l) });
    expect(r.key.toString("hex")).toBe(HEX_A);
    expect(lines.join("\n")).toContain(next());
  });
});

describe("env key leading whitespace keeps its warning", () => {
  test("a leading space or tab before 64 hex chars still warns", () => {
    for (const prefix of [" ", "\t"]) {
      const dir = mkdtempSync(join(tmpdir(), "gh-keyws-"));
      const logs: string[] = [];
      resolveMasterKey({ envKey: prefix + "ab".repeat(32), dataDir: dir, log: (m) => logs.push(m) });
      expect(logs.some((m) => m.includes("not valid hex"))).toBe(true);
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
