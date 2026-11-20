import type { Context, Next } from "hono";
import { timingSafeEqual } from "crypto";
import type { Database } from "bun:sqlite";
import type { GatehouseConfig } from "../config";
import { createBearerVerifier } from "./verifyBearer";

export interface AuthContext {
  identity: string;
  policies: string[];
  source: "user" | "approle" | "root";
  role_id?: string;
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
  const verify = createBearerVerifier(config, db);

  return async (c: Context, next: Next) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return c.json({ error: "Missing or invalid Authorization header", request_id: c.get("requestId") }, 401);
    }

    const result = await verify(authHeader.slice(7), c.get("sourceIp") || "unknown");
    if (!result.ok) {
      return c.json({ error: result.error, request_id: c.get("requestId") }, result.status);
    }
    c.set("auth", result.auth satisfies AuthContext);
    return next();
  };
}
