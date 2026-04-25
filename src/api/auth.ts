import { Hono } from "hono";
import { SignJWT, jwtVerify } from "jose";
import { Database } from "bun:sqlite";
import type { GatehouseConfig } from "../config";
import { safeEqual } from "../auth/middleware";
import { verifyTotp, verifyRecoveryCode } from "../auth/totp";
import { ipMatchesAllowlist, validateCIDRs } from "../auth/cidr";

// Simple in-memory rate limiter: 5 failed attempts per IP per 60s window
const failedAttempts = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_MS = 60_000;

// Periodic cleanup to prevent memory leak from accumulated stale entries
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of failedAttempts) {
    if (now > entry.resetAt) {
      failedAttempts.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW_MS * 2);

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = failedAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    return true; // Not rate limited
  }
  return entry.count < RATE_LIMIT_MAX;
}

/** Seconds remaining until the rate-limit window resets for this IP. */
function retryAfterSeconds(ip: string): number {
  const entry = failedAttempts.get(ip);
  if (!entry) return 0;
  const remaining = Math.ceil((entry.resetAt - Date.now()) / 1000);
  return Math.max(1, remaining);
}

function recordFailure(ip: string) {
  const now = Date.now();
  const entry = failedAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    failedAttempts.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
  } else {
    entry.count++;
  }
}

export function authRouter(db: Database, config: GatehouseConfig) {
  const router = new Hono();
  const secret = new TextEncoder().encode(config.jwtSecret);

  /**
   * Admin gate for user/AppRole management endpoints.
   *
   * The /v1/auth/* router is mounted BEFORE the global auth middleware
   * (so login endpoints remain unauthenticated), which means c.get("auth")
   * is never populated here - we have to verify the bearer token ourselves.
   *
   * Accepts either the bootstrap root token or any valid JWT whose
   * policies include "admin". User logins always sign JWTs with
   * policies: ["admin"], so logging in as a created user works.
   */
  async function requireAdmin(c: any): Promise<boolean> {
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) return false;
    const token = authHeader.slice(7);

    const rootToken = process.env.GATEHOUSE_ROOT_TOKEN;
    if (rootToken && token.length === rootToken.length && safeEqual(token, rootToken)) {
      return true;
    }

    try {
      const { payload } = await jwtVerify(token, secret, { issuer: "gatehouse" });
      // Pre-auth TOTP tokens must not grant admin access.
      if (payload.purpose === "totp-pending") return false;
      const policies = (payload.policies as string[]) || [];
      return policies.includes("admin");
    } catch {
      return false;
    }
  }

  // AppRole login: exchange role_id + secret for a JWT
  router.post("/approle/login", async (c) => {
    const ip = c.get("sourceIp") || "unknown";

    if (!checkRateLimit(ip)) {
      const retry = retryAfterSeconds(ip);
      c.header("Retry-After", String(retry));
      return c.json(
        { error: "Too many failed login attempts. Try again later.", retry_after: retry, request_id: c.get("requestId") },
        429
      );
    }

    let body: { role_id: string; secret_id: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const { role_id, secret_id } = body;
    if (!role_id || !secret_id) {
      return c.json({ error: "role_id and secret_id are required", request_id: c.get("requestId") }, 400);
    }

    const role = db
      .query("SELECT * FROM app_roles WHERE role_id = ?")
      .get(role_id) as any;

    if (!role) {
      recordFailure(ip);
      return c.json({ error: "Invalid credentials", request_id: c.get("requestId") }, 401);
    }

    // Verify secret (using Bun's built-in password hashing)
    const valid = await Bun.password.verify(secret_id, role.secret_hash);
    if (!valid) {
      recordFailure(ip);
      return c.json({ error: "Invalid credentials", request_id: c.get("requestId") }, 401);
    }

    // Check suspension AFTER password verification so attackers who lack
    // valid credentials can't enumerate which roles are suspended.
    if (role.suspended) {
      recordFailure(ip);
      return c.json({ error: "AppRole is suspended", request_id: c.get("requestId") }, 403);
    }

    // Enforce IP allowlist at login. If set, source IP must match at least one CIDR.
    const allowlist: string[] = role.ip_allowlist ? JSON.parse(role.ip_allowlist) : [];
    if (allowlist.length > 0 && !ipMatchesAllowlist(ip, allowlist)) {
      recordFailure(ip);
      return c.json({ error: "Source IP not permitted for this AppRole", request_id: c.get("requestId") }, 403);
    }

    // Update last_used
    db.query("UPDATE app_roles SET last_used = datetime('now') WHERE role_id = ?").run(
      role_id
    );

    const policies = JSON.parse(role.policies);
    const token = await new SignJWT({
      sub: `approle:${role.display_name}`,
      role_id,
      policies,
      ip_allowlist: allowlist.length > 0 ? allowlist : undefined,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("gatehouse")
      .setIssuedAt()
      .setExpirationTime("24h")
      .sign(secret);

    return c.json({
      token,
      identity: `approle:${role.display_name}`,
      policies,
      expires_in: 86400,
    });
  });

  // Anticipatory JWT refresh: a still-valid bearer JWT is exchanged for a
  // new one with a full 24h TTL. Lets long-running agents extend before
  // expiry without re-reading role_id/secret_id from the environment.
  //
  // Threat model: a compromised JWT can already be used for its full TTL
  // by the attacker, and the attacker would also have role_id/secret_id
  // (they live in the same env file), so refresh doesn't extend the
  // breach window beyond what re-login would. We do NOT issue refresh
  // from EXPIRED tokens - that would be a refresh-token model. Expired
  // means re-login from environment.
  //
  // For AppRole tokens we re-check role suspension and IP allowlist on
  // every refresh, so suspending a role takes effect at the next refresh
  // (or sooner if the operator revokes via other means) instead of having
  // to wait out a full 24h.
  router.post("/refresh", async (c) => {
    const ip = c.get("sourceIp") || "unknown";

    if (!checkRateLimit(ip)) {
      const retry = retryAfterSeconds(ip);
      c.header("Retry-After", String(retry));
      return c.json(
        { error: "Too many failed attempts. Try again later.", retry_after: retry, request_id: c.get("requestId") },
        429
      );
    }

    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      recordFailure(ip);
      return c.json({ error: "Missing or invalid Authorization header", request_id: c.get("requestId") }, 401);
    }
    const tokenStr = authHeader.slice(7);

    let payload: any;
    try {
      const verified = await jwtVerify(tokenStr, secret, { issuer: "gatehouse" });
      payload = verified.payload;
    } catch {
      recordFailure(ip);
      return c.json(
        { error: "Token expired or invalid; re-login from role_id + secret_id", request_id: c.get("requestId") },
        401
      );
    }

    // Pre-auth TOTP tokens are a separate lifecycle; refusing here keeps
    // the contract narrow.
    if (payload.purpose === "totp-pending") {
      return c.json(
        { error: "TOTP-pending tokens cannot be refreshed; complete TOTP first", request_id: c.get("requestId") },
        400
      );
    }

    if (payload.role_id) {
      const role = db
        .query("SELECT suspended, ip_allowlist, display_name, policies FROM app_roles WHERE role_id = ?")
        .get(payload.role_id) as any;
      if (!role) {
        recordFailure(ip);
        return c.json({ error: "AppRole no longer exists", request_id: c.get("requestId") }, 401);
      }
      if (role.suspended) {
        return c.json({ error: "AppRole is suspended", request_id: c.get("requestId") }, 403);
      }
      const allowlist: string[] = role.ip_allowlist ? JSON.parse(role.ip_allowlist) : [];
      if (allowlist.length > 0 && !ipMatchesAllowlist(ip, allowlist)) {
        recordFailure(ip);
        return c.json({ error: "Source IP not permitted for this AppRole", request_id: c.get("requestId") }, 403);
      }

      const policies = JSON.parse(role.policies);
      const newToken = await new SignJWT({
        sub: `approle:${role.display_name}`,
        role_id: payload.role_id,
        policies,
        ip_allowlist: allowlist.length > 0 ? allowlist : undefined,
      })
        .setProtectedHeader({ alg: "HS256" })
        .setIssuer("gatehouse")
        .setIssuedAt()
        .setExpirationTime("24h")
        .sign(secret);

      db.query("UPDATE app_roles SET last_used = datetime('now') WHERE role_id = ?").run(payload.role_id);

      return c.json({
        token: newToken,
        identity: `approle:${role.display_name}`,
        policies,
        expires_in: 86400,
      });
    }

    // Non-AppRole JWTs (user logins). Re-check the underlying user row
    // before re-signing: a disabled or deleted user holding a still-valid
    // JWT must not be able to perpetually self-renew it. Re-derive the
    // policy claim from the current users.role rather than echoing
    // payload.policies, so a role downgrade also takes effect at refresh.
    const sub = String(payload.sub || "");
    const username = sub.startsWith("user:") ? sub.slice(5) : null;
    if (!username) {
      return c.json(
        { error: "Unrecognized subject; re-login from credentials", request_id: c.get("requestId") },
        401
      );
    }
    const userRow = db
      .query("SELECT username, display_name, enabled, role FROM users WHERE username = ?")
      .get(username) as { username: string; display_name: string; enabled: number; role: string } | null;
    if (!userRow || !userRow.enabled) {
      return c.json(
        { error: "User account is disabled or removed", request_id: c.get("requestId") },
        401
      );
    }

    // Current role->policy mapping mirrors the user-login handlers:
    // every UI user is granted ["admin"] today. Keep this in lockstep
    // if a richer role model ever lands.
    const freshPolicies = ["admin"];

    const newToken = await new SignJWT({
      sub: `user:${userRow.username}`,
      policies: freshPolicies,
      display_name: userRow.display_name,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("gatehouse")
      .setIssuedAt()
      .setExpirationTime("24h")
      .sign(secret);

    return c.json({
      token: newToken,
      identity: `user:${userRow.username}`,
      policies: freshPolicies,
      expires_in: 86400,
    });
  });

  // Identity introspection: who am I, what can I do, when does my token
  // expire. Useful for HTTP-only agents that don't have gatehouse_status
  // available via MCP. Same threat surface as login - reveals nothing the
  // caller doesn't already control.
  router.get("/whoami", async (c) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return c.json({ error: "Missing or invalid Authorization header", request_id: c.get("requestId") }, 401);
    }
    const tokenStr = authHeader.slice(7);

    // Root token: no expiry, full admin.
    const rootToken = process.env.GATEHOUSE_ROOT_TOKEN;
    if (rootToken && tokenStr.length === rootToken.length && safeEqual(tokenStr, rootToken)) {
      return c.json({
        identity: "root",
        policies: ["admin"],
        source: "root",
      });
    }

    let payload: any;
    try {
      const verified = await jwtVerify(tokenStr, secret, { issuer: "gatehouse" });
      payload = verified.payload;
    } catch {
      return c.json({ error: "Token expired or invalid", request_id: c.get("requestId") }, 401);
    }

    if (payload.purpose === "totp-pending") {
      return c.json({ error: "TOTP-pending tokens cannot introspect; complete TOTP first", request_id: c.get("requestId") }, 400);
    }

    const expSec = typeof payload.exp === "number" ? payload.exp : null;
    const expiresAt = expSec ? new Date(expSec * 1000).toISOString() : null;
    const expiresIn = expSec ? Math.max(0, expSec - Math.floor(Date.now() / 1000)) : null;

    return c.json({
      identity: payload.sub,
      policies: payload.policies || [],
      source: payload.role_id ? "approle" : "user",
      expires_at: expiresAt,
      expires_in: expiresIn,
    });
  });

  // List all AppRoles (requires root token)
  router.get("/approle", async (c) => {
    if (!(await requireAdmin(c))) {
      return c.json({ error: "Admin access required", request_id: c.get("requestId") }, 403);
    }

    const roles = db
      .query("SELECT role_id, display_name, policies, suspended, created_at, last_used, ip_allowlist FROM app_roles ORDER BY created_at DESC")
      .all() as any[];

    return c.json({
      roles: roles.map((r) => ({
        role_id: r.role_id,
        display_name: r.display_name,
        policies: JSON.parse(r.policies),
        suspended: !!r.suspended,
        created_at: r.created_at,
        last_used: r.last_used,
        ip_allowlist: r.ip_allowlist ? JSON.parse(r.ip_allowlist) : [],
      })),
    });
  });

  // Update an AppRole (requires root token)
  router.put("/approle/:roleId", async (c) => {
    if (!(await requireAdmin(c))) {
      return c.json({ error: "Admin access required", request_id: c.get("requestId") }, 403);
    }

    const roleId = c.req.param("roleId");
    const role = db.query("SELECT role_id, display_name, policies FROM app_roles WHERE role_id = ?").get(roleId) as any;
    if (!role) {
      return c.json({ error: "AppRole not found", request_id: c.get("requestId") }, 404);
    }

    let body: { display_name?: string; policies?: string[]; ip_allowlist?: string[] };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const displayName = body.display_name?.trim() || role.display_name;
    const policies = body.policies || JSON.parse(role.policies);

    if (!displayName) {
      return c.json({ error: "display_name is required", request_id: c.get("requestId") }, 400);
    }
    if (!Array.isArray(policies) || policies.length === 0) {
      return c.json({ error: "At least one policy is required", request_id: c.get("requestId") }, 400);
    }

    let allowlistJson: string | null | undefined = undefined;
    if (body.ip_allowlist !== undefined) {
      if (!Array.isArray(body.ip_allowlist)) {
        return c.json({ error: "ip_allowlist must be an array of CIDR strings", request_id: c.get("requestId") }, 400);
      }
      const cleaned = body.ip_allowlist.map((s) => String(s).trim()).filter(Boolean);
      const err = validateCIDRs(cleaned);
      if (err) return c.json({ error: err, request_id: c.get("requestId") }, 400);
      allowlistJson = cleaned.length > 0 ? JSON.stringify(cleaned) : null;
    }

    if (allowlistJson !== undefined) {
      db.query("UPDATE app_roles SET display_name = ?, policies = ?, ip_allowlist = ? WHERE role_id = ?")
        .run(displayName, JSON.stringify(policies), allowlistJson, roleId);
    } else {
      db.query("UPDATE app_roles SET display_name = ?, policies = ? WHERE role_id = ?")
        .run(displayName, JSON.stringify(policies), roleId);
    }

    return c.json({
      role_id: roleId,
      display_name: displayName,
      policies,
      ip_allowlist: allowlistJson ? JSON.parse(allowlistJson) : [],
    });
  });

  // Suspend or reinstate an AppRole (requires root token)
  router.patch("/approle/:roleId/suspend", async (c) => {
    if (!(await requireAdmin(c))) {
      return c.json({ error: "Admin access required", request_id: c.get("requestId") }, 403);
    }

    const roleId = c.req.param("roleId");
    const role = db.query("SELECT role_id, display_name, suspended FROM app_roles WHERE role_id = ?").get(roleId) as any;
    if (!role) {
      return c.json({ error: "AppRole not found", request_id: c.get("requestId") }, 404);
    }

    let body: { suspended: boolean };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const suspended = !!body.suspended;
    db.query("UPDATE app_roles SET suspended = ? WHERE role_id = ?")
      .run(suspended ? 1 : 0, roleId);

    return c.json({
      role_id: roleId,
      display_name: role.display_name,
      suspended,
    });
  });

  // Delete an AppRole (requires root token)
  router.delete("/approle/:roleId", async (c) => {
    if (!(await requireAdmin(c))) {
      return c.json({ error: "Admin access required", request_id: c.get("requestId") }, 403);
    }

    const roleId = c.req.param("roleId");
    const role = db.query("SELECT role_id FROM app_roles WHERE role_id = ?").get(roleId);
    if (!role) {
      return c.json({ error: "AppRole not found", request_id: c.get("requestId") }, 404);
    }

    db.query("DELETE FROM app_roles WHERE role_id = ?").run(roleId);
    return c.json({ deleted: true });
  });

  // User (human account) login: username + password → JWT
  router.post("/login", async (c) => {
    const ip = c.get("sourceIp") || "unknown";

    if (!checkRateLimit(ip)) {
      const retry = retryAfterSeconds(ip);
      c.header("Retry-After", String(retry));
      return c.json(
        { error: "Too many failed login attempts. Try again later.", retry_after: retry, request_id: c.get("requestId") },
        429
      );
    }

    let body: { username: string; password: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const { username, password } = body;
    if (!username || !password) {
      return c.json({ error: "username and password are required", request_id: c.get("requestId") }, 400);
    }

    const user = db
      .query("SELECT * FROM users WHERE username = ? AND enabled = 1")
      .get(username) as any;

    if (!user) {
      recordFailure(ip);
      return c.json({ error: "Invalid credentials", request_id: c.get("requestId") }, 401);
    }

    const valid = await Bun.password.verify(password, user.password_hash);
    if (!valid) {
      recordFailure(ip);
      return c.json({ error: "Invalid credentials", request_id: c.get("requestId") }, 401);
    }

    // If TOTP is enabled for this user, issue a short-lived "pre-auth" token
    // that can only be used to submit the second factor at POST /v1/auth/login/totp.
    // The full access JWT is only issued after the TOTP code is verified.
    if (user.totp_enabled && user.totp_secret) {
      const totpToken = await new SignJWT({
        sub: `user:${user.username}`,
        purpose: "totp-pending",
      })
        .setProtectedHeader({ alg: "HS256" })
        .setIssuer("gatehouse")
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(secret);

      return c.json({
        totp_required: true,
        totp_token: totpToken,
      });
    }

    db.query("UPDATE users SET last_login = datetime('now') WHERE username = ?").run(username);

    // All UI users are admins - policies are for AppRoles (agents), not humans
    const token = await new SignJWT({
      sub: `user:${user.username}`,
      policies: ["admin"],
      display_name: user.display_name,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("gatehouse")
      .setIssuedAt()
      .setExpirationTime("24h")
      .sign(secret);

    return c.json({
      token,
      identity: `user:${user.username}`,
      display_name: user.display_name,
      role: user.role || "admin",
      expires_in: 86400,
    });
  });

  // TOTP second-factor login
  // Exchange a totp-pending token + 6-digit code (or recovery code) for a full JWT
  router.post("/login/totp", async (c) => {
    const ip = c.get("sourceIp") || "unknown";

    if (!checkRateLimit(ip)) {
      const retry = retryAfterSeconds(ip);
      c.header("Retry-After", String(retry));
      return c.json(
        { error: "Too many failed login attempts. Try again later.", retry_after: retry, request_id: c.get("requestId") },
        429
      );
    }

    let body: { totp_token: string; code: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const { totp_token, code } = body;
    if (!totp_token || !code) {
      return c.json({ error: "totp_token and code are required", request_id: c.get("requestId") }, 400);
    }

    // Verify the pre-auth token
    let username: string;
    try {
      const { payload } = await jwtVerify(totp_token, secret, { issuer: "gatehouse" });
      if (payload.purpose !== "totp-pending" || typeof payload.sub !== "string") {
        throw new Error("wrong purpose");
      }
      username = payload.sub.replace(/^user:/, "");
    } catch {
      return c.json({ error: "Invalid or expired TOTP session", request_id: c.get("requestId") }, 401);
    }

    const user = db
      .query("SELECT * FROM users WHERE username = ? AND enabled = 1")
      .get(username) as any;

    if (!user || !user.totp_enabled || !user.totp_secret) {
      recordFailure(ip);
      return c.json({ error: "Invalid credentials", request_id: c.get("requestId") }, 401);
    }

    // Accept either a 6-digit TOTP code or an 8-char recovery code (XXXX-XXXX)
    const trimmed = code.trim();
    let ok = false;
    let consumedRecoveryIdx = -1;

    if (/^\d{6}$/.test(trimmed.replace(/\s/g, ""))) {
      ok = verifyTotp(user.totp_secret, trimmed);
    } else {
      // Try recovery codes
      const hashes: string[] = user.totp_recovery_codes ? JSON.parse(user.totp_recovery_codes) : [];
      for (let i = 0; i < hashes.length; i++) {
        if (await verifyRecoveryCode(trimmed, hashes[i])) {
          ok = true;
          consumedRecoveryIdx = i;
          break;
        }
      }
    }

    if (!ok) {
      recordFailure(ip);
      return c.json({ error: "Invalid TOTP code", request_id: c.get("requestId") }, 401);
    }

    // Consume a used recovery code so it can't be reused
    if (consumedRecoveryIdx >= 0) {
      const hashes: string[] = JSON.parse(user.totp_recovery_codes);
      hashes.splice(consumedRecoveryIdx, 1);
      db.query("UPDATE users SET totp_recovery_codes = ? WHERE username = ?").run(
        JSON.stringify(hashes),
        username
      );
    }

    db.query("UPDATE users SET last_login = datetime('now') WHERE username = ?").run(username);

    const token = await new SignJWT({
      sub: `user:${user.username}`,
      policies: ["admin"],
      display_name: user.display_name,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("gatehouse")
      .setIssuedAt()
      .setExpirationTime("24h")
      .sign(secret);

    return c.json({
      token,
      identity: `user:${user.username}`,
      display_name: user.display_name,
      role: user.role || "admin",
      expires_in: 86400,
      recovery_code_consumed: consumedRecoveryIdx >= 0,
    });
  });

  // User CRUD (requires root token)
  // Users are admin accounts for the UI - not tied to policies

  // List users
  router.get("/users", async (c) => {
    if (!(await requireAdmin(c))) {
      return c.json({ error: "Admin access required", request_id: c.get("requestId") }, 403);
    }

    const users = db
      .query("SELECT username, display_name, email, role, enabled, totp_enabled, created_at, updated_at, last_login FROM users ORDER BY created_at DESC")
      .all() as any[];

    return c.json({
      users: users.map((u) => ({
        username: u.username,
        display_name: u.display_name,
        email: u.email,
        role: u.role || "admin",
        enabled: !!u.enabled,
        totp_enabled: !!u.totp_enabled,
        created_at: u.created_at,
        updated_at: u.updated_at,
        last_login: u.last_login,
      })),
    });
  });

  // Create user
  router.post("/users", async (c) => {
    if (!(await requireAdmin(c))) {
      return c.json({ error: "Admin access required", request_id: c.get("requestId") }, 403);
    }

    let body: { username: string; password: string; display_name: string; email?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const { username, password, display_name, email } = body;

    if (!username || typeof username !== "string" || username.length < 2) {
      return c.json({ error: "username must be at least 2 characters", request_id: c.get("requestId") }, 400);
    }
    if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
      return c.json({ error: "username must contain only letters, numbers, dots, hyphens, underscores", request_id: c.get("requestId") }, 400);
    }
    if (!password || password.length < 8) {
      return c.json({ error: "password must be at least 8 characters", request_id: c.get("requestId") }, 400);
    }
    if (!display_name || typeof display_name !== "string") {
      return c.json({ error: "display_name is required", request_id: c.get("requestId") }, 400);
    }

    const existing = db.query("SELECT username FROM users WHERE username = ?").get(username);
    if (existing) {
      return c.json({ error: "Username already exists", request_id: c.get("requestId") }, 409);
    }

    const password_hash = await Bun.password.hash(password);

    db.query(
      "INSERT INTO users (username, password_hash, display_name, email) VALUES (?, ?, ?, ?)"
    ).run(username, password_hash, display_name, email || null);

    return c.json({ username, display_name, email: email || null, role: "admin", enabled: true }, 201);
  });

  // Update user
  router.put("/users/:username", async (c) => {
    if (!(await requireAdmin(c))) {
      return c.json({ error: "Admin access required", request_id: c.get("requestId") }, 403);
    }

    const username = c.req.param("username");
    const existing = db.query("SELECT username FROM users WHERE username = ?").get(username);
    if (!existing) {
      return c.json({ error: "User not found", request_id: c.get("requestId") }, 404);
    }

    let body: { display_name?: string; email?: string; password?: string; enabled?: boolean; reset_totp?: boolean };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    if (body.password !== undefined && body.password.length < 8) {
      return c.json({ error: "password must be at least 8 characters", request_id: c.get("requestId") }, 400);
    }

    const updates: string[] = [];
    const params: any[] = [];

    if (body.display_name !== undefined) { updates.push("display_name = ?"); params.push(body.display_name); }
    if (body.email !== undefined) { updates.push("email = ?"); params.push(body.email || null); }
    if (body.enabled !== undefined) { updates.push("enabled = ?"); params.push(body.enabled ? 1 : 0); }
    if (body.reset_totp) {
      // Admin force-disable of 2FA (e.g., user lost their authenticator)
      updates.push("totp_enabled = 0");
      updates.push("totp_secret = NULL");
      updates.push("totp_recovery_codes = NULL");
    }
    if (body.password) {
      const hash = await Bun.password.hash(body.password);
      updates.push("password_hash = ?");
      params.push(hash);
    }

    if (updates.length === 0) {
      return c.json({ error: "No fields to update", request_id: c.get("requestId") }, 400);
    }

    updates.push("updated_at = datetime('now')");
    params.push(username);

    db.query(`UPDATE users SET ${updates.join(", ")} WHERE username = ?`).run(...params);

    return c.json({ updated: true });
  });

  // Delete user
  router.delete("/users/:username", async (c) => {
    if (!(await requireAdmin(c))) {
      return c.json({ error: "Admin access required", request_id: c.get("requestId") }, 403);
    }

    const username = c.req.param("username");
    const existing = db.query("SELECT username FROM users WHERE username = ?").get(username);
    if (!existing) {
      return c.json({ error: "User not found", request_id: c.get("requestId") }, 404);
    }

    db.query("DELETE FROM users WHERE username = ?").run(username);
    return c.json({ deleted: true });
  });

  // Create an AppRole (requires root token)
  router.post("/approle", async (c) => {
    if (!(await requireAdmin(c))) {
      return c.json({ error: "Admin access required", request_id: c.get("requestId") }, 403);
    }

    let body: { display_name: string; policies: string[]; ip_allowlist?: string[] };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const { display_name, policies } = body;

    if (!display_name || typeof display_name !== "string" || display_name.length < 1) {
      return c.json({ error: "display_name is required", request_id: c.get("requestId") }, 400);
    }
    if (!Array.isArray(policies)) {
      return c.json({ error: "policies must be an array of strings", request_id: c.get("requestId") }, 400);
    }

    let allowlistJson: string | null = null;
    if (body.ip_allowlist !== undefined) {
      if (!Array.isArray(body.ip_allowlist)) {
        return c.json({ error: "ip_allowlist must be an array of CIDR strings", request_id: c.get("requestId") }, 400);
      }
      const cleaned = body.ip_allowlist.map((s) => String(s).trim()).filter(Boolean);
      const err = validateCIDRs(cleaned);
      if (err) return c.json({ error: err, request_id: c.get("requestId") }, 400);
      allowlistJson = cleaned.length > 0 ? JSON.stringify(cleaned) : null;
    }

    const role_id = `role-${crypto.randomUUID()}`;
    const secret_id = crypto.randomUUID();
    const secret_hash = await Bun.password.hash(secret_id);

    db.query(
      "INSERT INTO app_roles (role_id, secret_hash, display_name, policies, ip_allowlist) VALUES (?, ?, ?, ?, ?)"
    ).run(role_id, secret_hash, display_name, JSON.stringify(policies), allowlistJson);

    return c.json(
      {
        role_id,
        secret_id,
        display_name,
        policies,
        ip_allowlist: allowlistJson ? JSON.parse(allowlistJson) : [],
        warning: "Save the secret_id now, it cannot be retrieved later",
      },
      201
    );
  });

  return router;
}
