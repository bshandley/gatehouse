import { Hono } from "hono";
import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import type { GatehouseConfig } from "../config";
import { safeEqual } from "../auth/middleware";
import { ipMatchesAllowlist } from "../auth/cidr";
import type { AuditLog } from "../audit/logger";
import { jwtVerify } from "jose";

/**
 * Rotate flow: operator generates a one-shot link that swaps the
 * AppRole's secret_id without changing role_id, policies, or the
 * installed skill. Same single-use, time-bound token semantics as
 * onboard, just a narrower payload.
 *
 * Endpoints:
 *   POST   /v1/rotate            (admin)   create rotate token
 *   GET    /v1/rotate/:token              fetch self-installing markdown
 *   POST   /v1/rotate/:token/exchange     consume token, rotate secret_id
 *
 * The exchange returns ONLY the new secret_id (and unchanged role_id +
 * base_url). It does NOT mint a JWT; the agent's existing JWT remains
 * valid until its TTL, and the next login uses the new secret_id.
 */

const DEFAULT_TTL = 900;
const MIN_TTL = 60;
const MAX_TTL = 3600;

const createCounter = new Map<string, { count: number; resetAt: number }>();
const exchangeCounter = new Map<string, { count: number; resetAt: number }>();
const CREATE_MAX = 5;
const EXCHANGE_MAX = 10;
const WINDOW_MS = 60_000;

setInterval(() => {
  const now = Date.now();
  for (const m of [createCounter, exchangeCounter]) {
    for (const [k, v] of m) if (now > v.resetAt) m.delete(k);
  }
}, WINDOW_MS * 2);

/** Test-only: reset rate limiters. */
export function _resetRotateRateLimits() {
  createCounter.clear();
  exchangeCounter.clear();
}

function hit(map: Map<string, { count: number; resetAt: number }>, ip: string, max: number) {
  const now = Date.now();
  const entry = map.get(ip);
  if (!entry || now > entry.resetAt) {
    map.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return { ok: true, retryAfter: 0 };
  }
  entry.count++;
  if (entry.count > max) {
    return { ok: false, retryAfter: Math.max(1, Math.ceil((entry.resetAt - now) / 1000)) };
  }
  return { ok: true, retryAfter: 0 };
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function randomToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function originFromRequest(c: any, config: GatehouseConfig): string {
  if (config.publicUrl) return config.publicUrl;
  const proto = c.req.header("x-forwarded-proto") || "http";
  const host = c.req.header("x-forwarded-host") || c.req.header("host") || `localhost:${config.port}`;
  return `${proto}://${host}`;
}

function renderRotateMarkdown(opts: {
  baseUrl: string;
  rotateToken: string;
  roleDisplayName: string;
  roleId: string;
}): string {
  return `# Gatehouse credential rotation

You are about to receive a fresh \`secret_id\` for an existing
AppRole. Your \`role_id\`, your policies, and the installed Gatehouse
skill all stay the same — only the \`secret_id\` changes.

This document contains a one-time rotate token. The token is consumed
when you call \`/exchange\` in Step 2, NOT when you fetch this
document. If you lose these instructions before exchange, you can
re-fetch the same URL.

Identity to be rotated: **${opts.roleDisplayName}** (${opts.roleId})

## Step 1: Detect your harness (same ladder as onboarding)

Use whichever harness identification you settled on at first install.
This rotation rewrites only your env file at the same path you wrote
the originals to:

- **Hermes Agent**: \`~/.hermes/.env\`
- **OpenClaw**: \`~/.openclaw/workspace/.env\`
- **Claude Code**: \`~/.claude/.env.gatehouse\`
- **Generic file-writer (opencode, Codex, Cursor, Windsurf)**: \`.env.gatehouse\` in the working directory you used at install

## Step 2: Exchange the rotate token

Make exactly one call:

    POST ${opts.baseUrl}/v1/rotate/${opts.rotateToken}/exchange

No body. No Authorization header. The response is:

    {
      "role_id": "${opts.roleId}",
      "secret_id": "<new-secret-id>",
      "base_url": "${opts.baseUrl}",
      "role_display_name": "${opts.roleDisplayName}"
    }

Hold the \`secret_id\` in memory only.

If exchange returns 410 Gone, the token has been used or expired.
Stop and tell the operator to generate a new one.

## Step 3: Rewrite \`GATEHOUSE_SECRET_ID\` in your env file

In the env file detected in Step 1, replace ONLY the
\`GATEHOUSE_SECRET_ID=...\` line with the new value. Do NOT change
\`GATEHOUSE_ROLE_ID\` or \`GATEHOUSE_URL\`. Do NOT touch the
installed Gatehouse skill — rotation does not change skill content.

## Step 4: Confirm

Reply in one line:

    Gatehouse secret_id rotated for role ${opts.roleDisplayName}.

The next login (or 401 + relogin) will use the new \`secret_id\`. Any
JWT you currently hold remains valid until its 24h TTL — that's
expected.
`;
}

export function rotateRouter(
  db: Database,
  audit: AuditLog,
  config: GatehouseConfig
) {
  const router = new Hono();
  const secret = new TextEncoder().encode(config.jwtSecret);

  async function requireAdminIdentity(c: any): Promise<{ ok: boolean; identity: string }> {
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) return { ok: false, identity: "" };
    const token = authHeader.slice(7);

    const rootToken = process.env.GATEHOUSE_ROOT_TOKEN;
    if (rootToken && token.length === rootToken.length && safeEqual(token, rootToken)) {
      return { ok: true, identity: "root" };
    }
    try {
      const { payload } = await jwtVerify(token, secret, { issuer: "gatehouse" });
      if (payload.purpose === "totp-pending") return { ok: false, identity: "" };
      const policiesList = (payload.policies as string[]) || [];
      if (!policiesList.includes("admin")) return { ok: false, identity: "" };
      return { ok: true, identity: (payload.sub as string) || "admin" };
    } catch {
      return { ok: false, identity: "" };
    }
  }

  // POST /v1/rotate - create a one-shot rotate link (admin)
  router.post("/", async (c) => {
    const ip = (c.get("sourceIp") as string) || "unknown";
    const rl = hit(createCounter, ip, CREATE_MAX);
    if (!rl.ok) {
      c.header("Retry-After", String(rl.retryAfter));
      return c.json({ error: "Rate limit exceeded", request_id: c.get("requestId") }, 429);
    }

    const admin = await requireAdminIdentity(c);
    if (!admin.ok) {
      return c.json({ error: "Admin access required", request_id: c.get("requestId") }, 403);
    }

    let body: { role_id?: string; ttl_seconds?: number; label?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const roleId = (body.role_id || "").trim();
    if (!roleId) {
      return c.json({ error: "role_id is required", request_id: c.get("requestId") }, 400);
    }
    const role = db
      .query("SELECT role_id, display_name, policies FROM app_roles WHERE role_id = ?")
      .get(roleId) as any;
    if (!role) {
      return c.json({ error: "AppRole not found", request_id: c.get("requestId") }, 404);
    }

    let ttl = body.ttl_seconds === undefined ? DEFAULT_TTL : Number(body.ttl_seconds);
    if (!Number.isFinite(ttl) || ttl < MIN_TTL || ttl > MAX_TTL) {
      return c.json(
        { error: `ttl_seconds must be between ${MIN_TTL} and ${MAX_TTL}`, request_id: c.get("requestId") },
        400
      );
    }
    ttl = Math.floor(ttl);

    const label = (body.label || "").toString().slice(0, 200) || null;

    const token = randomToken();
    const tokenHash = hashToken(token);
    const id = `rotate-${crypto.randomUUID()}`;

    db.query(
      `INSERT INTO rotate_tokens (id, token_hash, role_id, created_by, label, expires_at, creator_ip)
       VALUES (?, ?, ?, ?, ?, datetime('now', '+' || ? || ' seconds'), ?)`
    ).run(id, tokenHash, roleId, admin.identity, label, ttl, ip);

    const expiresRow = db
      .query("SELECT expires_at FROM rotate_tokens WHERE id = ?")
      .get(id) as { expires_at: string };

    audit.log({
      identity: admin.identity,
      action: "rotate.token.create",
      source_ip: ip,
      metadata: { role_id: roleId, token_id: id, ttl: String(ttl), label: label || "" },
    });

    const origin = originFromRequest(c, config);
    return c.json({
      id,
      rotate_url: `${origin}/v1/rotate/${token}`,
      token,
      expires_at: expiresRow.expires_at,
      role_display_name: role.display_name,
      policies: JSON.parse(role.policies || "[]"),
    });
  });

  // GET /v1/rotate/:token - self-installing markdown (unauthenticated)
  router.get("/:token", async (c) => {
    const token = c.req.param("token");
    const row = db
      .query(
        `SELECT t.id, t.role_id, t.expires_at, t.consumed_at, r.display_name
         FROM rotate_tokens t
         LEFT JOIN app_roles r ON r.role_id = t.role_id
         WHERE t.token_hash = ?
           AND t.consumed_at IS NULL
           AND t.expires_at > datetime('now')`
      )
      .get(hashToken(token)) as any;

    if (!row) {
      c.header("Content-Type", "text/plain; charset=utf-8");
      return c.body(
        "This rotate link has expired or been used. Ask the operator to generate a new one.",
        410
      );
    }

    audit.log({
      identity: "rotate:fetch",
      action: "rotate.token.fetch",
      source_ip: (c.get("sourceIp") as string) || null,
      metadata: { token_id: row.id, role_id: row.role_id },
    });

    const origin = originFromRequest(c, config);
    const md = renderRotateMarkdown({
      baseUrl: origin,
      rotateToken: token,
      roleDisplayName: row.display_name || "",
      roleId: row.role_id,
    });

    c.header("Content-Type", "text/markdown; charset=utf-8");
    c.header("Cache-Control", "no-store");
    return c.body(md);
  });

  // POST /v1/rotate/:token/exchange - single-use consume
  router.post("/:token/exchange", async (c) => {
    const ip = (c.get("sourceIp") as string) || "unknown";
    const rl = hit(exchangeCounter, ip, EXCHANGE_MAX);
    if (!rl.ok) {
      c.header("Retry-After", String(rl.retryAfter));
      return c.json({ error: "Rate limit exceeded", request_id: c.get("requestId") }, 429);
    }

    const token = c.req.param("token");
    const tokenHash = hashToken(token);

    const row = db
      .query(
        `SELECT t.id, t.role_id, t.expires_at, t.consumed_at,
                r.display_name, r.suspended, r.ip_allowlist
         FROM rotate_tokens t
         LEFT JOIN app_roles r ON r.role_id = t.role_id
         WHERE t.token_hash = ?
           AND t.consumed_at IS NULL
           AND t.expires_at > datetime('now')`
      )
      .get(tokenHash) as any;

    if (!row) {
      return c.json(
        { error: "Rotate link has expired or been used", request_id: c.get("requestId") },
        410
      );
    }

    // IP allowlist: do NOT consume on failure (operator can retry).
    const allowlist: string[] = row.ip_allowlist ? JSON.parse(row.ip_allowlist) : [];
    if (allowlist.length > 0 && !ipMatchesAllowlist(ip, allowlist)) {
      audit.log({
        identity: `approle:${row.display_name}`,
        action: "rotate.token.exchange",
        source_ip: ip,
        success: false,
        metadata: { token_id: row.id, role_id: row.role_id, reason: "ip_not_allowed" },
      });
      return c.json(
        { error: "Source IP not permitted for this AppRole", request_id: c.get("requestId") },
        403
      );
    }

    // Suspension: DO consume to prevent retry against a flagged role.
    if (row.suspended) {
      db.query(
        "UPDATE rotate_tokens SET consumed_at = datetime('now'), consumer_ip = ? WHERE id = ? AND consumed_at IS NULL"
      ).run(ip, row.id);
      audit.log({
        identity: `approle:${row.display_name}`,
        action: "rotate.token.exchange",
        source_ip: ip,
        success: false,
        metadata: { token_id: row.id, role_id: row.role_id, reason: "role_suspended" },
      });
      return c.json(
        { error: "AppRole is suspended", request_id: c.get("requestId") },
        403
      );
    }

    // Happy path: rotate secret_id and consume token atomically.
    const newSecretId = crypto.randomUUID();
    const newSecretHash = await Bun.password.hash(newSecretId);

    const consumed = db.transaction(() => {
      const result = db
        .query(
          "UPDATE rotate_tokens SET consumed_at = datetime('now'), consumer_ip = ? WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > datetime('now')"
        )
        .run(ip, tokenHash);
      if (result.changes !== 1) return false;
      db.query("UPDATE app_roles SET secret_hash = ?, last_used = datetime('now') WHERE role_id = ?")
        .run(newSecretHash, row.role_id);
      return true;
    })();

    if (!consumed) {
      return c.json(
        { error: "Rotate link has expired or been used", request_id: c.get("requestId") },
        410
      );
    }

    audit.log({
      identity: `approle:${row.display_name}`,
      action: "rotate.token.exchange",
      source_ip: ip,
      metadata: { token_id: row.id, role_id: row.role_id, rotated: "true" },
    });

    const origin = originFromRequest(c, config);
    return c.json({
      role_id: row.role_id,
      secret_id: newSecretId,
      base_url: origin,
      role_display_name: row.display_name,
    });
  });

  return router;
}
