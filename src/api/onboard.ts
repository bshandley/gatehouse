import { Hono } from "hono";
import { SignJWT, jwtVerify } from "jose";
import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import type { GatehouseConfig } from "../config";
import { safeEqual } from "../auth/middleware";
import { ipMatchesAllowlist } from "../auth/cidr";
import type { AuditLog } from "../audit/logger";
import type { PolicyEngine } from "../policy/engine";

const DEFAULT_TTL = 900;
const MIN_TTL = 60;
const MAX_TTL = 3600;
const EXCHANGE_TTL_SECONDS = 86400;

// Per-route in-memory rate limiter. Separate from the shared auth.ts limiter
// so UI clicks and agent exchanges don't starve each other's budgets.
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

/** Test-only: reset the in-memory rate limiters. Not exposed via HTTP. */
export function _resetOnboardRateLimits() {
  createCounter.clear();
  exchangeCounter.clear();
}

function hit(map: Map<string, { count: number; resetAt: number }>, ip: string, max: number): { ok: boolean; retryAfter: number } {
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
  // base64url, no padding
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

function renderSituationTable(policies: PolicyEngine, roleNames: string[]): string {
  const rows: string[] = [];
  const push = (situation: string, tool: string) => rows.push(`| ${situation} | ${tool} |`);

  if (policies.check(roleNames, "*", "proxy")) {
    push("Call an authenticated API", "`gatehouse_proxy`");
  }
  if (policies.check(roleNames, "*", "proxy") || policies.check(roleNames, "*", "read")) {
    push("Find known-good request shapes", "`gatehouse_patterns`");
  }
  if (policies.hasCapabilityOnPrefix(roleNames, "db/", "lease")) {
    push(
      "Temporary DB credential",
      "`gatehouse_checkout` on `db/<name>` (dynamic)"
    );
  }
  if (policies.hasCapabilityOnPrefix(roleNames, "ssh/", "lease")) {
    push(
      "SSH somewhere",
      "`gatehouse_checkout` on `ssh/<name>` (dynamic)"
    );
  }
  push("Check your policies / health", "`gatehouse_status`");
  push("List secrets you can access", "`gatehouse_list`");
  push("Redact credentials from text", "`gatehouse_scrub`");
  if (policies.check(roleNames, "*", "read")) {
    push("Raw secret value (last resort)", "`gatehouse_get`");
  }
  if (policies.check(roleNames, "*", "write")) {
    push("Write a secret", "`gatehouse_put`");
  }

  return ["| Situation | Tool |", "| --- | --- |", ...rows].join("\n");
}

export function onboardRouter(
  db: Database,
  audit: AuditLog,
  policies: PolicyEngine,
  config: GatehouseConfig
) {
  const router = new Hono();
  const secret = new TextEncoder().encode(config.jwtSecret);

  // Load the template once at module init.
  const templateUrl = new URL("../templates/onboard.md", import.meta.url).pathname;
  let templateContent = "";
  Bun.file(templateUrl)
    .text()
    .then((t) => {
      templateContent = t;
    })
    .catch((e) => {
      console.error(`[gatehouse:onboard] failed to load template from ${templateUrl}:`, e);
    });

  /** Returns { ok, identity } for admin-only routes. */
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

  // POST /v1/onboard - create a one-time onboarding link (admin)
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
    const id = `onboard-${crypto.randomUUID()}`;

    // Use SQLite's datetime() so stored format matches the 'YYYY-MM-DD HH:MM:SS'
    // used by datetime('now') in comparisons. Mixing ISO strings with SQLite
    // datetime text would break lexicographic comparison.
    db.query(
      `INSERT INTO onboarding_tokens (id, token_hash, role_id, created_by, label, expires_at, creator_ip)
       VALUES (?, ?, ?, ?, ?, datetime('now', '+' || ? || ' seconds'), ?)`
    ).run(id, tokenHash, roleId, admin.identity, label, ttl, ip);

    const expiresRow = db
      .query("SELECT expires_at FROM onboarding_tokens WHERE id = ?")
      .get(id) as { expires_at: string };
    const expiresAt = expiresRow.expires_at;

    audit.log({
      identity: admin.identity,
      action: "onboard.token.create",
      source_ip: ip,
      metadata: { role_id: roleId, token_id: id, ttl: String(ttl), label: label || "" },
    });

    const origin = originFromRequest(c, config);
    return c.json({
      id,
      onboard_url: `${origin}/v1/onboard/${token}`,
      token,
      expires_at: expiresAt,
      role_display_name: role.display_name,
      policies: JSON.parse(role.policies || "[]"),
    });
  });

  // GET /v1/onboard - list tokens (admin)
  router.get("/", async (c) => {
    const admin = await requireAdminIdentity(c);
    if (!admin.ok) {
      return c.json({ error: "Admin access required", request_id: c.get("requestId") }, 403);
    }

    const roleFilter = c.req.query("role_id");
    const includeConsumed = c.req.query("include_consumed") === "true";

    let sql = `
      SELECT t.id, t.role_id, t.label, t.created_at, t.created_by, t.expires_at,
             t.consumed_at, t.creator_ip, t.consumer_ip, r.display_name
      FROM onboarding_tokens t
      LEFT JOIN app_roles r ON r.role_id = t.role_id
      WHERE 1=1
    `;
    const params: any[] = [];
    if (roleFilter) {
      sql += " AND t.role_id = ?";
      params.push(roleFilter);
    }
    if (!includeConsumed) {
      sql += " AND t.consumed_at IS NULL AND t.expires_at > datetime('now')";
    }
    sql += " ORDER BY t.created_at DESC LIMIT 100";

    const rows = db.query(sql).all(...params) as any[];
    const parseSqliteUtc = (s: string) => new Date(s.replace(" ", "T") + "Z");
    const now = new Date();
    return c.json({
      tokens: rows.map((r) => {
        let status: "consumed" | "expired" | "active" = "active";
        if (r.consumed_at) status = "consumed";
        else if (parseSqliteUtc(r.expires_at) < now) status = "expired";
        return {
          id: r.id,
          role_id: r.role_id,
          role_display_name: r.display_name,
          label: r.label,
          created_at: r.created_at,
          created_by: r.created_by,
          expires_at: r.expires_at,
          consumed_at: r.consumed_at,
          creator_ip: r.creator_ip,
          consumer_ip: r.consumer_ip,
          status,
        };
      }),
    });
  });

  // DELETE /v1/onboard/:id - revoke an unused token (admin)
  // Accepts onboard-* id only; if this ever collides with a token value
  // we route by the onboard- prefix to keep the public token path unreachable.
  router.delete("/:id{onboard-.+}", async (c) => {
    const admin = await requireAdminIdentity(c);
    if (!admin.ok) {
      return c.json({ error: "Admin access required", request_id: c.get("requestId") }, 403);
    }

    const id = c.req.param("id");
    const existing = db
      .query("SELECT id, role_id, consumed_at FROM onboarding_tokens WHERE id = ?")
      .get(id) as any;
    if (!existing) {
      return c.json({ error: "Token not found", request_id: c.get("requestId") }, 404);
    }
    if (existing.consumed_at) {
      return c.json({ error: "Token already consumed or revoked", request_id: c.get("requestId") }, 410);
    }

    db.query("UPDATE onboarding_tokens SET consumed_at = datetime('now') WHERE id = ? AND consumed_at IS NULL")
      .run(id);

    audit.log({
      identity: admin.identity,
      action: "onboard.token.revoke",
      source_ip: (c.get("sourceIp") as string) || null,
      metadata: { token_id: id, role_id: existing.role_id },
    });

    return c.json({ revoked: true });
  });

  // GET /v1/onboard/:token - fetch self-installing markdown
  router.get("/:token", async (c) => {
    const token = c.req.param("token");
    const row = db
      .query(
        `SELECT t.id, t.role_id, t.expires_at, t.consumed_at, r.display_name, r.policies
         FROM onboarding_tokens t
         LEFT JOIN app_roles r ON r.role_id = t.role_id
         WHERE t.token_hash = ?
           AND t.consumed_at IS NULL
           AND t.expires_at > datetime('now')`
      )
      .get(hashToken(token)) as any;

    if (!row) {
      c.header("Content-Type", "text/plain; charset=utf-8");
      return c.body(
        "This onboarding link has expired or been used. Ask the operator to generate a new one.",
        410
      );
    }

    audit.log({
      identity: "onboard:fetch",
      action: "onboard.token.fetch",
      source_ip: (c.get("sourceIp") as string) || null,
      metadata: { token_id: row.id, role_id: row.role_id },
    });

    const origin = originFromRequest(c, config);
    const policyList: string[] = JSON.parse(row.policies || "[]");
    const situationTable = renderSituationTable(policies, policyList);

    const rendered = templateContent
      .replaceAll("{{BASE_URL}}", origin)
      .replaceAll("{{ONBOARD_TOKEN}}", token)
      .replaceAll("{{ROLE_DISPLAY_NAME}}", row.display_name || "")
      .replaceAll(
        "{{POLICIES}}",
        policyList.join(", ") ||
          "**(none)** — STOP. This AppRole has zero policies attached. After installing the skill in Step 3, do not probe for anything. `gatehouse_list` will be empty and every proxy call will be denied. Tell the operator they need to attach policies to this AppRole."
      )
      .replaceAll("{{SITUATION_TABLE}}", situationTable);

    c.header("Content-Type", "text/markdown; charset=utf-8");
    c.header("Cache-Control", "no-store");
    return c.body(rendered);
  });

  // POST /v1/onboard/:token/exchange - single-use consume
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
                r.display_name, r.policies, r.suspended, r.ip_allowlist
         FROM onboarding_tokens t
         LEFT JOIN app_roles r ON r.role_id = t.role_id
         WHERE t.token_hash = ?
           AND t.consumed_at IS NULL
           AND t.expires_at > datetime('now')`
      )
      .get(tokenHash) as any;

    if (!row) {
      return c.json(
        { error: "Onboarding link has expired or been used", request_id: c.get("requestId") },
        410
      );
    }

    // IP allowlist check: do NOT consume the token on failure - operator can
    // retry from the correct network within the TTL.
    const allowlist: string[] = row.ip_allowlist ? JSON.parse(row.ip_allowlist) : [];
    if (allowlist.length > 0 && !ipMatchesAllowlist(ip, allowlist)) {
      audit.log({
        identity: `approle:${row.display_name}`,
        action: "onboard.token.exchange",
        source_ip: ip,
        success: false,
        metadata: { token_id: row.id, role_id: row.role_id, reason: "ip_not_allowed" },
      });
      return c.json(
        { error: "Source IP not permitted for this AppRole", request_id: c.get("requestId") },
        403
      );
    }

    // Suspension check: DO consume the token (blocks retry of a compromised link
    // against a role that's been flagged).
    if (row.suspended) {
      db.query(
        "UPDATE onboarding_tokens SET consumed_at = datetime('now'), consumer_ip = ? WHERE id = ? AND consumed_at IS NULL"
      ).run(ip, row.id);
      audit.log({
        identity: `approle:${row.display_name}`,
        action: "onboard.token.exchange",
        source_ip: ip,
        success: false,
        metadata: { token_id: row.id, role_id: row.role_id, reason: "role_suspended" },
      });
      return c.json(
        { error: "AppRole is suspended", request_id: c.get("requestId") },
        403
      );
    }

    // Happy path: rotate secret_id and mark token consumed atomically.
    const newSecretId = crypto.randomUUID();
    const newSecretHash = await Bun.password.hash(newSecretId);

    const consumed = db.transaction(() => {
      const result = db
        .query(
          "UPDATE onboarding_tokens SET consumed_at = datetime('now'), consumer_ip = ? WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > datetime('now')"
        )
        .run(ip, tokenHash);
      if (result.changes !== 1) return false;
      db.query("UPDATE app_roles SET secret_hash = ?, last_used = datetime('now') WHERE role_id = ?")
        .run(newSecretHash, row.role_id);
      return true;
    })();

    if (!consumed) {
      return c.json(
        { error: "Onboarding link has expired or been used", request_id: c.get("requestId") },
        410
      );
    }

    const policyList: string[] = JSON.parse(row.policies || "[]");
    const jwt = await new SignJWT({
      sub: `approle:${row.display_name}`,
      role_id: row.role_id,
      policies: policyList,
      ip_allowlist: allowlist.length > 0 ? allowlist : undefined,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("gatehouse")
      .setIssuedAt()
      .setExpirationTime("24h")
      .sign(secret);

    audit.log({
      identity: `approle:${row.display_name}`,
      action: "onboard.token.exchange",
      source_ip: ip,
      metadata: { token_id: row.id, role_id: row.role_id, rotated: "true" },
    });

    const origin = originFromRequest(c, config);
    return c.json({
      token: jwt,
      identity: `approle:${row.display_name}`,
      policies: policyList,
      expires_in: EXCHANGE_TTL_SECONDS,
      role_id: row.role_id,
      secret_id: newSecretId,
      base_url: origin,
      mcp_url: `${origin}/v1/mcp`,
      role_display_name: row.display_name,
    });
  });

  return router;
}
