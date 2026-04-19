import { createHmac, randomBytes } from "node:crypto";

/**
 * TOTP (RFC 6238) implementation using HMAC-SHA1, 30-second step, 6 digits.
 * Compatible with Google Authenticator, Authy, 1Password, Bitwarden, etc.
 *
 * No external dependencies - just node:crypto primitives that ship with Bun.
 */

const STEP_SECONDS = 30;
const DIGITS = 6;
const ALGO = "sha1";

// RFC 4648 base32 alphabet
const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Encode raw bytes as RFC 4648 base32 (no padding - authenticators don't care). */
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += B32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

/** Decode a base32 string (case-insensitive, ignores spaces and padding). */
export function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/[\s=]/g, "");
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`Invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** Generate a cryptographically random 20-byte TOTP secret, base32-encoded. */
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

/** Compute HOTP (RFC 4226) for a given counter. */
export function hotp(secretB32: string, counter: bigint): string {
  const key = base32Decode(secretB32);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(counter);
  const hmac = createHmac(ALGO, key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const code = bin % 10 ** DIGITS;
  return code.toString().padStart(DIGITS, "0");
}

/** Compute the TOTP code for a given UNIX time (default: now). */
export function totp(secretB32: string, nowSeconds: number = Math.floor(Date.now() / 1000)): string {
  const counter = BigInt(Math.floor(nowSeconds / STEP_SECONDS));
  return hotp(secretB32, counter);
}

/**
 * Verify a user-supplied TOTP code against a secret, accepting the current
 * step plus a window of ±1 steps (30 seconds) for clock drift.
 * Returns true if the code matches any step in [now-1, now, now+1].
 */
export function verifyTotp(
  secretB32: string,
  code: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
  window: number = 1
): boolean {
  const normalized = code.replace(/\s/g, "");
  if (!/^\d{6}$/.test(normalized)) return false;
  const counter = BigInt(Math.floor(nowSeconds / STEP_SECONDS));
  for (let i = -window; i <= window; i++) {
    const candidate = hotp(secretB32, counter + BigInt(i));
    // Constant-time compare on 6 ASCII digits
    if (constantTimeEqual(candidate, normalized)) return true;
  }
  return false;
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Build an otpauth:// URI for enrollment. Authenticator apps parse this into
 * a QR-scannable entry (label, issuer, secret, algorithm, digits, period).
 */
export function buildOtpauthUri(params: {
  secret: string;
  accountName: string;
  issuer: string;
}): string {
  const label = encodeURIComponent(`${params.issuer}:${params.accountName}`);
  const query = new URLSearchParams({
    secret: params.secret,
    issuer: params.issuer,
    algorithm: "SHA1",
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${query.toString()}`;
}

/** Generate N random alphanumeric recovery codes of the form XXXX-XXXX. */
export function generateRecoveryCodes(count: number = 10): string[] {
  const codes: string[] = [];
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I
  for (let i = 0; i < count; i++) {
    const bytes = randomBytes(8);
    let code = "";
    for (let j = 0; j < 8; j++) {
      code += alphabet[bytes[j] % alphabet.length];
      if (j === 3) code += "-";
    }
    codes.push(code);
  }
  return codes;
}

/** Hash a recovery code for storage (one-way). */
export async function hashRecoveryCode(code: string): Promise<string> {
  return await Bun.password.hash(code.toUpperCase().replace(/[^A-Z0-9]/g, ""));
}

/** Verify a recovery code against a stored hash. */
export async function verifyRecoveryCode(code: string, hash: string): Promise<boolean> {
  const normalized = code.toUpperCase().replace(/[^A-Z0-9]/g, "");
  return await Bun.password.verify(normalized, hash);
}
