/**
 * SSO integration helpers: DB-side and admin-side functions that complement
 * the OIDC protocol layer in `oidc.ts`. These are kept out of `src/index.ts`
 * so tests can import them without triggering server boot side effects.
 */

import type { Database } from "bun:sqlite";

/**
 * Probe a candidate OIDC issuer URL by fetching its discovery document.
 * Confirms it returns JSON containing the three required endpoints.
 * Throws on any failure (used by the settings save handler for fail-fast feedback).
 */
export async function validateOidcIssuerForSettings(issuer: string): Promise<void> {
  const url = new URL(issuer.replace(/\/$/, "") + "/.well-known/openid-configuration");
  let res: Response;
  try {
    res = await fetch(url, { headers: { accept: "application/json" } });
  } catch (err: any) {
    throw new Error(`Could not reach issuer: ${err?.message || err}`);
  }
  if (!res.ok) {
    throw new Error(`Issuer discovery returned HTTP ${res.status}`);
  }
  let body: any;
  try {
    body = await res.json();
  } catch {
    throw new Error("Issuer discovery did not return JSON");
  }
  for (const key of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
    if (!body[key]) throw new Error(`Issuer discovery missing required field: ${key}`);
  }
}

/** Delete `sso_login_state` rows older than 10 minutes. Returns the number deleted. */
export function reapExpiredSsoState(db: Database): number {
  const cutoff = Math.floor(Date.now() / 1000) - 600;
  const result = db
    .query("DELETE FROM sso_login_state WHERE created_at < ?")
    .run(cutoff);
  return result.changes;
}

/**
 * One-shot: if GATEHOUSE_OAUTH_ISSUER is set and no `settings/sso` row exists,
 * seed the row with enabled:true. After boot, env vars are not consulted again.
 */
export function seedSsoFromEnv(db: Database): void {
  const issuer = process.env.GATEHOUSE_OAUTH_ISSUER;
  if (!issuer) return;
  const existing = db.query("SELECT 1 FROM settings WHERE key = 'sso'").get();
  if (existing) return;
  const seeded = {
    enabled: true,
    issuer,
    client_id: process.env.GATEHOUSE_OAUTH_CLIENT_ID || "",
    client_secret: process.env.GATEHOUSE_OAUTH_CLIENT_SECRET || "",
    redirect_uri: process.env.GATEHOUSE_OAUTH_REDIRECT_URI || "",
    scopes: "openid profile email",
  };
  db.query("INSERT INTO settings (key, value) VALUES ('sso', ?)").run(JSON.stringify(seeded));
  console.log("[gatehouse:sso] seeded settings/sso row from environment variables");
}
