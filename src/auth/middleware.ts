import type { Context, Next } from "hono";
import { jwtVerify } from "jose";
import { timingSafeEqual } from "crypto";
import type { Database } from "bun:sqlite";
import type { GatehouseConfig } from "../config";
import { ipMatchesAllowlist } from "./cidr";

export interface AuthContext {
  identity: string;
  policies: string[];
  source: "user" | "approle" | "root";
}

/**
 * Constant-time string comparison to prevent timing attacks.
 */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * Auth middleware: checks for Bearer token in Authorization header.
 *
 * Supports:
 * - JWT tokens (from OAuth or /v1/auth/token)
 * - Root token (GATEHOUSE_ROOT_TOKEN env var, for bootstrapping)
 *
 * Sets c.set("auth", AuthContext) for downstream handlers.
 *
 * When `db` is provided, user JWTs (sub starts with "user:") are
 * re-checked against the users table on EVERY request: if the row is
 * missing or `enabled = 0`, the JWT is rejected. This means disabling
 * or deleting a user takes effect immediately, not at the end of the
 * 24h JWT TTL. AppRole JWT validity is unaffected here (suspension is
 * enforced at /refresh and at login; per-request DB hits for AppRoles
 * would add latency to the agent hot path without a comparable revocation
 * win, since AppRoles are revoked by deleting the role - which evicts
 * future logins - and operators can rotate the secret_id via /v1/rotate
 * to invalidate any in-flight JWTs at next refresh).
 */
export function authMiddleware(config: GatehouseConfig, db?: Database) {
  const rootToken = process.env.GATEHOUSE_ROOT_TOKEN;
  const secret = new TextEncoder().encode(config.jwtSecret);

  return async (c: Context, next: Next) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return c.json({ error: "Missing or invalid Authorization header", request_id: c.get("requestId") }, 401);
    }

    const token = authHeader.slice(7);

    // Check root token first (for bootstrapping) - timing-safe comparison
    if (rootToken && token.length === rootToken.length && safeEqual(token, rootToken)) {
      c.set("auth", {
        identity: "root",
        policies: ["admin"],
        source: "root",
      } satisfies AuthContext);
      return next();
    }

    // Try JWT verification
    try {
      const { payload } = await jwtVerify(token, secret, {
        issuer: "gatehouse",
      });

      // Pre-auth TOTP tokens are only valid for POST /v1/auth/login/totp.
      // Reject them anywhere else so a stolen pre-auth token can't be used
      // as a full access token.
      if (payload.purpose === "totp-pending") {
        return c.json({ error: "TOTP verification required", request_id: c.get("requestId") }, 401);
      }

      // If the token was minted with an IP allowlist, reject requests whose
      // source IP has drifted outside it since login - a stolen token must
      // not be usable from a different network.
      const tokenAllowlist = payload.ip_allowlist as string[] | undefined;
      if (Array.isArray(tokenAllowlist) && tokenAllowlist.length > 0) {
        const ip = c.get("sourceIp") || "unknown";
        if (!ipMatchesAllowlist(ip, tokenAllowlist)) {
          return c.json({ error: "Source IP not permitted for this token", request_id: c.get("requestId") }, 403);
        }
      }

      // AppRole JWTs carry role_id in the payload; user JWTs do not.
      const isApprole = typeof payload.role_id === "string";

      // For user JWTs, recheck the underlying user row on every request
      // so disable/delete takes effect immediately. Without this, a JWT
      // minted before disable keeps working until its 24h TTL, and an
      // attacker with a stolen JWT could even self-renew via /refresh
      // to retain admin indefinitely (see auth.ts /refresh fix).
      if (!isApprole && db) {
        const sub = String(payload.sub || "");
        const username = sub.startsWith("user:") ? sub.slice(5) : null;
        if (!username) {
          return c.json({ error: "Unrecognized user subject", request_id: c.get("requestId") }, 401);
        }
        const userRow = db
          .query("SELECT enabled FROM users WHERE username = ?")
          .get(username) as { enabled: number } | null;
        if (!userRow || !userRow.enabled) {
          return c.json({ error: "User account is disabled or removed", request_id: c.get("requestId") }, 401);
        }
      }

      c.set("auth", {
        identity: payload.sub || "unknown",
        policies: (payload.policies as string[]) || [],
        source: isApprole ? "approle" : "user",
      } satisfies AuthContext);

      return next();
    } catch {
      return c.json({ error: "Invalid or expired token", request_id: c.get("requestId") }, 401);
    }
  };
}
