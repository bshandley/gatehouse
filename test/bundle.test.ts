import { describe, test, expect } from "bun:test";
import { sealBundle, openBundle, BundleError } from "../src/backup/bundle";
import { keyFingerprint } from "../src/secrets/engine";
import { VERSION } from "../src/version";
import nacl from "tweetnacl";
import { scryptSync } from "node:crypto";

const KEY = Buffer.alloc(32, 7);
const DB = new Uint8Array([1, 2, 3, 4, 5, 0, 255, 128]);
const counts = { secrets: 2, "api-keys/example": 1 };

function seal(includeKey: boolean, passphrase = "pw") {
  return sealBundle({
    db: DB, passphrase, masterKey: KEY, includeKey,
    createdAt: "2026-11-19T00:00:00.000Z", rowCounts: counts, scryptLogN: 10,
  });
}

function code(fn: () => unknown): string | undefined {
  try { fn(); } catch (e) {
    if (!(e instanceof BundleError)) throw e;
    return e.code;
  }
  return undefined;
}

describe("bundle", () => {
  test("sealed round-trip returns db bytes, header, and the master key", () => {
    const out = openBundle(seal(true), "pw");
    expect(Array.from(out.db)).toEqual(Array.from(DB));
    expect(out.masterKey?.equals(KEY)).toBe(true);
    expect(out.header.sealed).toBe(true);
    expect(out.header.format).toBe(1);
    expect(out.header.gatehouse_version).toBe(VERSION);
    expect(out.header.created_at).toBe("2026-11-19T00:00:00.000Z");
    expect(out.header.key_fingerprint).toBe(keyFingerprint(KEY));
    expect(out.header.row_counts).toEqual(counts);
  });

  test("default mode carries no key", () => {
    const out = openBundle(seal(false), "pw");
    expect(out.masterKey).toBeNull();
    expect(out.header.sealed).toBe(false);
    expect("master_key" in out.header).toBe(false);
    expect(Array.from(out.db)).toEqual(Array.from(DB));
  });

  test("wrong passphrase is bad_passphrase", () => {
    expect(code(() => openBundle(seal(true), "nope"))).toBe("bad_passphrase");
  });

  test("foreign file is bad_format", () => {
    const foreign = new TextEncoder().encode("SQLite format 3\0" + "x".repeat(100));
    expect(code(() => openBundle(foreign, "pw"))).toBe("bad_format");
  });

  test("truncated bundle is bad_format", () => {
    const s = seal(true);
    expect(code(() => openBundle(s.slice(0, 40), "pw"))).toBe("bad_format");
    expect(code(() => openBundle(s.slice(0, 60), "pw"))).toBe("bad_format");
    expect(code(() => openBundle(new Uint8Array(0), "pw"))).toBe("bad_format");
  });

  test("flipped ciphertext byte is bad_passphrase, not a crash", () => {
    const s = seal(true);
    s[s.length - 1] ^= 1;
    expect(code(() => openBundle(s, "pw"))).toBe("bad_passphrase");
    const t = seal(true);
    t[60] ^= 1;
    expect(code(() => openBundle(t, "pw"))).toBe("bad_passphrase");
  });

  test("version byte 2 is unsupported_version", () => {
    const s = seal(true);
    s[8] = 2;
    expect(code(() => openBundle(s, "pw"))).toBe("unsupported_version");
  });

  test("log2(N) outside 10..20 in the file is bad_format", () => {
    for (const n of [0, 9, 21, 255]) {
      const s = seal(true);
      s[9] = n;
      expect(code(() => openBundle(s, "pw"))).toBe("bad_format");
    }
  });

  test("two seals of the same input differ", () => {
    const a = seal(true);
    const b = seal(true);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    expect(Buffer.from(a.slice(10, 50)).equals(Buffer.from(b.slice(10, 50)))).toBe(false);
  });

  test("rejects out-of-range scryptLogN on seal", () => {
    expect(() => sealBundle({
      db: DB, passphrase: "pw", masterKey: KEY, includeKey: false,
      createdAt: "x", rowCounts: {}, scryptLogN: 25,
    })).toThrow();
  });

  test("seal refuses what open would reject", () => {
    const base = { db: DB, passphrase: "pw", includeKey: false, createdAt: "x", scryptLogN: 10 };
    expect(() => sealBundle({ ...base, masterKey: Buffer.alloc(31, 7), rowCounts: {} })).toThrow();
    for (const bad of [NaN, -1, 1.5]) {
      expect(() => sealBundle({ ...base, masterKey: KEY, rowCounts: { a: bad } })).toThrow();
    }
  });

  test("passphrase is NFC-normalized on seal and open", () => {
    const nfc = "caf\u00e9-passphrase";
    const nfd = "cafe\u0301-passphrase";
    expect(nfc).not.toBe(nfd);
    expect(openBundle(seal(false, nfc), nfd).db).toEqual(DB);
    expect(openBundle(seal(false, nfd), nfc).db).toEqual(DB);
  });

  test("__proto__ row_counts key round-trips as an own property", () => {
    const rc = {};
    Object.defineProperty(rc, "__proto__", { value: 3, enumerable: true, configurable: true, writable: true });
    const s = sealBundle({ db: DB, passphrase: "pw", masterKey: KEY, includeKey: false, createdAt: "x", rowCounts: rc, scryptLogN: 10 });
    const out = openBundle(s, "pw");
    expect(Object.prototype.hasOwnProperty.call(out.header.row_counts, "__proto__")).toBe(true);
    expect(Object.getOwnPropertyDescriptor(out.header.row_counts, "__proto__")?.value).toBe(3);
  });

  test("production default writes log2(N) = 17", () => {
    const s = sealBundle({
      db: DB, passphrase: "pw", masterKey: KEY, includeKey: false,
      createdAt: "2026-11-19T00:00:00.000Z", rowCounts: {},
    });
    expect(s[9]).toBe(17);
  });
});

// Build a bundle with an arbitrary (valid-box) payload to exercise header parsing.
function forge(payload: Uint8Array, pw = "pw"): Uint8Array {
  const salt = new Uint8Array(16).fill(1);
  const nonce = new Uint8Array(24).fill(2);
  const k = scryptSync(pw, salt, 32, { N: 1024, r: 8, p: 1, maxmem: 256 * 1024 * 8 });
  const box = nacl.secretbox(payload, nonce, new Uint8Array(k));
  const out = new Uint8Array(50 + box.length);
  out.set(new TextEncoder().encode("GHBUNDLE"), 0);
  out[8] = 1; out[9] = 10;
  out.set(salt, 10); out.set(nonce, 26); out.set(box, 50);
  return out;
}
function payloadOf(headerBytes: Uint8Array, declared: number, db = new Uint8Array(3)) {
  const p = new Uint8Array(4 + headerBytes.length + db.length);
  new DataView(p.buffer).setUint32(0, declared, false);
  p.set(headerBytes, 4); p.set(db, 4 + headerBytes.length);
  return p;
}

describe("bundle hostile payloads (correct passphrase)", () => {
  const enc = (s: string) => new TextEncoder().encode(s);
  test("header length larger than payload is bad_format", () => {
    const h = enc("{}");
    expect(code(() => openBundle(forge(payloadOf(h, 0xffffffff)), "pw"))).toBe("bad_format");
  });
  test("payload shorter than 4 bytes is bad_format", () => {
    expect(code(() => openBundle(forge(new Uint8Array(2)), "pw"))).toBe("bad_format");
  });
  test("non-JSON header is bad_format", () => {
    const h = enc("not json");
    expect(code(() => openBundle(forge(payloadOf(h, h.length)), "pw"))).toBe("bad_format");
  });
  test("non-object and wrong-shape headers are bad_format", () => {
    for (const j of ["null", "[]", "5", "{}",
      JSON.stringify({ format: 1, gatehouse_version: "x", created_at: "x", key_fingerprint: "x", sealed: true, row_counts: {} }),
      JSON.stringify({ format: 1, gatehouse_version: "x", created_at: "x", key_fingerprint: "x", sealed: true, master_key: "zz", row_counts: {} }),
      JSON.stringify({ format: 1, gatehouse_version: "x", created_at: "x", key_fingerprint: "x", sealed: false, row_counts: { a: "b" } }),
    ]) {
      const h = enc(j);
      expect(code(() => openBundle(forge(payloadOf(h, h.length)), "pw"))).toBe("bad_format");
    }
  });
  test("header format other than 1 is unsupported_version", () => {
    const h = enc(JSON.stringify({ format: 2 }));
    expect(code(() => openBundle(forge(payloadOf(h, h.length)), "pw"))).toBe("unsupported_version");
  });
  test("sealed header whose fingerprint mismatches its master_key is bad_format", () => {
    const h = enc(JSON.stringify({
      format: 1, gatehouse_version: "x", created_at: "x", key_fingerprint: "00".repeat(16),
      sealed: true, master_key: KEY.toString("hex"), row_counts: {},
    }));
    expect(code(() => openBundle(forge(payloadOf(h, h.length)), "pw"))).toBe("bad_format");
  });
});
