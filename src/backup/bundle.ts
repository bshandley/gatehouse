import { scryptSync, randomBytes } from "node:crypto";
import nacl from "tweetnacl";
import { keyFingerprint } from "../secrets/engine";
import { VERSION } from "../version";

export interface BundleHeader {
  format: 1;
  gatehouse_version: string;
  created_at: string;
  key_fingerprint: string;
  sealed: boolean;
  master_key?: string;
  row_counts: Record<string, number>;
}

export class BundleError extends Error {
  code: "bad_passphrase" | "bad_format" | "unsupported_version";
  constructor(code: BundleError["code"], message: string) {
    super(message);
    this.name = "BundleError";
    this.code = code;
  }
}

const MAGIC = new TextEncoder().encode("GHBUNDLE");
const FORMAT = 1;
const DEFAULT_LOG_N = 17;
const MIN_LOG_N = 10;
const MAX_LOG_N = 20;
const SALT_LEN = 16;
const NONCE_LEN = 24;
const OFF_SALT = 10;
const OFF_NONCE = OFF_SALT + SALT_LEN;
const OFF_BOX = OFF_NONCE + NONCE_LEN; // 50
const MAX_HEADER_LEN = 1024 * 1024;

function deriveKey(passphrase: string, salt: Uint8Array, logN: number): Uint8Array {
  const N = 2 ** logN;
  const k = scryptSync(passphrase.normalize("NFC"), salt, 32, { N, r: 8, p: 1, maxmem: 256 * N * 8 });
  return new Uint8Array(k);
}

export function sealBundle(input: {
  db: Uint8Array;
  passphrase: string;
  masterKey: Buffer;
  includeKey: boolean;
  createdAt: string;
  rowCounts: Record<string, number>;
  scryptLogN?: number;
}): Uint8Array {
  const logN = input.scryptLogN ?? DEFAULT_LOG_N;
  if (!Number.isInteger(logN) || logN < MIN_LOG_N || logN > MAX_LOG_N) {
    throw new Error("scryptLogN out of range");
  }
  if (input.masterKey.length !== 32) throw new Error("masterKey must be 32 bytes");
  for (const v of Object.values(input.rowCounts)) {
    if (!isCount(v)) throw new Error("rowCounts values must be non-negative safe integers");
  }
  const header: BundleHeader = {
    format: 1,
    gatehouse_version: VERSION,
    created_at: input.createdAt,
    key_fingerprint: keyFingerprint(input.masterKey),
    sealed: input.includeKey,
    row_counts: input.rowCounts,
  };
  if (input.includeKey) header.master_key = input.masterKey.toString("hex");

  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const payload = new Uint8Array(4 + headerBytes.length + input.db.length);
  new DataView(payload.buffer).setUint32(0, headerBytes.length, false);
  payload.set(headerBytes, 4);
  payload.set(input.db, 4 + headerBytes.length);

  const salt = new Uint8Array(randomBytes(SALT_LEN));
  const nonce = new Uint8Array(randomBytes(NONCE_LEN));
  const box = nacl.secretbox(payload, nonce, deriveKey(input.passphrase, salt, logN));

  const out = new Uint8Array(OFF_BOX + box.length);
  out.set(MAGIC, 0);
  out[8] = FORMAT;
  out[9] = logN;
  out.set(salt, OFF_SALT);
  out.set(nonce, OFF_NONCE);
  out.set(box, OFF_BOX);
  return out;
}

function isCount(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

function parseHeader(raw: string): BundleHeader {
  let obj: unknown;
  try {
    obj = JSON.parse(raw);
  } catch {
    throw new BundleError("bad_format", "bundle header is not valid JSON");
  }
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
    throw new BundleError("bad_format", "bundle header is not an object");
  }
  const h = obj as Record<string, unknown>;
  if (h.format !== FORMAT) {
    if (typeof h.format === "number") {
      throw new BundleError("unsupported_version", "unsupported bundle header format");
    }
    throw new BundleError("bad_format", "bundle header has no format");
  }
  if (
    typeof h.gatehouse_version !== "string" ||
    typeof h.created_at !== "string" ||
    typeof h.key_fingerprint !== "string" ||
    typeof h.sealed !== "boolean"
  ) {
    throw new BundleError("bad_format", "bundle header fields are malformed");
  }
  const rc = h.row_counts;
  if (typeof rc !== "object" || rc === null || Array.isArray(rc)) {
    throw new BundleError("bad_format", "bundle row_counts is malformed");
  }
  const rowCounts: Record<string, number> = {};
  for (const [k, v] of Object.entries(rc as Record<string, unknown>)) {
    if (!isCount(v)) throw new BundleError("bad_format", "bundle row_counts is malformed");
    // defineProperty so a "__proto__" key is kept as an own property.
    Object.defineProperty(rowCounts, k, { value: v, enumerable: true, writable: true, configurable: true });
  }
  if (h.sealed) {
    if (typeof h.master_key !== "string" || !/^[0-9a-f]{64}$/i.test(h.master_key)) {
      throw new BundleError("bad_format", "bundle master_key is malformed");
    }
  } else if ("master_key" in h) {
    throw new BundleError("bad_format", "unsealed bundle carries a master_key");
  }
  const out: BundleHeader = {
    format: 1,
    gatehouse_version: h.gatehouse_version,
    created_at: h.created_at,
    key_fingerprint: h.key_fingerprint,
    sealed: h.sealed,
    row_counts: rowCounts,
  };
  if (h.sealed) out.master_key = h.master_key as string;
  return out;
}

export function openBundle(
  bytes: Uint8Array,
  passphrase: string,
): { header: BundleHeader; db: Uint8Array; masterKey: Buffer | null } {
  if (bytes.length < MAGIC.length) throw new BundleError("bad_format", "not a gatehouse bundle");
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC[i]) throw new BundleError("bad_format", "not a gatehouse bundle");
  }
  if (bytes.length < OFF_BOX + nacl.secretbox.overheadLength) {
    throw new BundleError("bad_format", "bundle is truncated");
  }
  if (bytes[8] !== FORMAT) {
    throw new BundleError("unsupported_version", `unsupported bundle version ${bytes[8]}`);
  }
  const logN = bytes[9];
  if (logN < MIN_LOG_N || logN > MAX_LOG_N) {
    throw new BundleError("bad_format", "bundle scrypt cost is out of range");
  }
  const salt = bytes.slice(OFF_SALT, OFF_SALT + SALT_LEN);
  const nonce = bytes.slice(OFF_NONCE, OFF_NONCE + NONCE_LEN);
  const box = bytes.slice(OFF_BOX);

  const payload = nacl.secretbox.open(box, nonce, deriveKey(passphrase, salt, logN));
  if (!payload) throw new BundleError("bad_passphrase", "wrong passphrase or corrupted bundle");

  if (payload.length < 4) throw new BundleError("bad_format", "bundle payload is truncated");
  const headerLen = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(0, false);
  if (headerLen > MAX_HEADER_LEN || headerLen > payload.length - 4) {
    throw new BundleError("bad_format", "bundle header length is invalid");
  }
  let headerText: string;
  try {
    headerText = new TextDecoder("utf-8", { fatal: true }).decode(payload.subarray(4, 4 + headerLen));
  } catch {
    throw new BundleError("bad_format", "bundle header is not valid UTF-8");
  }
  const header = parseHeader(headerText);
  const db = payload.slice(4 + headerLen);
  const masterKey = header.sealed ? Buffer.from(header.master_key as string, "hex") : null;
  if (masterKey && keyFingerprint(masterKey) !== header.key_fingerprint) {
    throw new BundleError("bad_format", "bundle key fingerprint does not match its master key");
  }
  return { header, db, masterKey };
}
