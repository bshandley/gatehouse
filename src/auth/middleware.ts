import type { Context, Next } from "hono";
import { jwtVerify } from "jose";
import { timingSafeEqual } from "crypto";
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
 */
export function authMiddleware(config: GatehouseConfig) {
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
