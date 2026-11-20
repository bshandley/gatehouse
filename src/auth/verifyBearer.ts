import { jwtVerify } from "jose";
import type { Database } from "bun:sqlite";
import type { GatehouseConfig } from "../config";
import { ipMatchesAllowlist } from "./cidr";
import { type AuthContext, safeEqual } from "./middleware";

export type BearerResult =
  | { ok: true; auth: AuthContext }
  | { ok: false; status: 401 | 403; error: string };

/**
 * The one implementation of "is this bearer token valid, and who is it".
 * Used by the HTTP auth middleware and by the stdio MCP entry, so a token
 * means the same thing on every surface.
 *
 * Accepts the root token (GATEHOUSE_ROOT_TOKEN, read once when the verifier
 * is created) and Gatehouse JWTs. When `db` is given, a user JWT is re-checked
 * against the users table on every call, so disabling or deleting a user
 * takes effect immediately rather than at the end of the JWT's lifetime.
 */
export function createBearerVerifier(
  config: Pick<GatehouseConfig, "jwtSecret">,
  db?: Database
): (token: string, sourceIp: string) => Promise<BearerResult> {
  const rootToken = process.env.GATEHOUSE_ROOT_TOKEN;
  const secret = new TextEncoder().encode(config.jwtSecret);

  return async (token, sourceIp) => {
    // Root token first (for bootstrapping), timing-safe.
    if (rootToken && token.length === rootToken.length && safeEqual(token, rootToken)) {
      return { ok: true, auth: { identity: "root", policies: ["admin"], source: "root" } };
    }

    let payload;
    try {
      ({ payload } = await jwtVerify(token, secret, { issuer: "gatehouse" }));
    } catch {
      return { ok: false, status: 401, error: "Invalid or expired token" };
    }

    // Pre-auth TOTP tokens are only valid for POST /v1/auth/login/totp. Reject
    // them everywhere else so a stolen pre-auth token is not a full token.
    if (payload.purpose === "totp-pending") {
      return { ok: false, status: 401, error: "TOTP verification required" };
    }

    // A token minted with an IP allowlist is not usable from outside it.
    const tokenAllowlist = payload.ip_allowlist as string[] | undefined;
    if (Array.isArray(tokenAllowlist) && tokenAllowlist.length > 0) {
      if (!ipMatchesAllowlist(sourceIp || "unknown", tokenAllowlist)) {
        return { ok: false, status: 403, error: "Source IP not permitted for this token" };
      }
    }

    // AppRole JWTs carry role_id in the payload; user JWTs do not.
    const isApprole = typeof payload.role_id === "string";

    if (!isApprole && db) {
      const sub = String(payload.sub || "");
      const username = sub.startsWith("user:") ? sub.slice(5) : null;
      if (!username) {
        return { ok: false, status: 401, error: "Unrecognized user subject" };
      }
      const userRow = db.query("SELECT enabled FROM users WHERE username = ?").get(username) as
        | { enabled: number }
        | null;
      if (!userRow || !userRow.enabled) {
        return { ok: false, status: 401, error: "User account is disabled or removed" };
      }
    }

    return {
      ok: true,
      auth: {
        identity: payload.sub || "unknown",
        policies: (payload.policies as string[]) || [],
        source: isApprole ? "approle" : "user",
        ...(isApprole ? { role_id: payload.role_id as string } : {}),
      },
    };
  };
}
