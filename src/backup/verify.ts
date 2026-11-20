import type { Database } from "bun:sqlite";
import { SecretsEngine, keyFingerprint } from "../secrets/engine";
import { verifyDynamicConfigKey } from "../dynamic/manager";

export interface VerifyResult {
  fingerprint: string;
  tested: "secret" | "dynamic" | "none";
  ok: boolean;
}

/**
 * Check that masterKey decrypts the data in db. Tries one secret first, and
 * a dynamic config only when there are no secrets. An empty vault reports
 * tested "none" and ok true. Strictly read-only: SELECTs only, no objects with constructor side effects.
 */
export function verifyVault(db: Database, masterKey: Buffer): VerifyResult {
  const fingerprint = keyFingerprint(masterKey);

  const secret = new SecretsEngine(db, masterKey).verifyKey();
  if (secret.tested) return { fingerprint, tested: "secret", ok: secret.ok };

  const dynamic = verifyDynamicConfigKey(db, masterKey);
  if (dynamic.tested) return { fingerprint, tested: "dynamic", ok: dynamic.ok };

  return { fingerprint, tested: "none", ok: true };
}
