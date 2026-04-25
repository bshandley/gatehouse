import { Hono } from "hono";
import { logger } from "hono/logger";
import { cors } from "hono/cors";
import { secretsRouter, bulkSecretsRouter } from "./api/secrets";
import { leaseRouter } from "./api/lease";
import { authRouter } from "./api/auth";
import { onboardRouter } from "./api/onboard";
import { meRouter } from "./api/me";
import { policyRouter } from "./api/policy";
import { auditRouter } from "./api/audit";
import { authMiddleware } from "./auth/middleware";
import { mcpHttpRouter } from "./mcp/server";
import { proxyRouter } from "./api/proxy";
import { dynamicRouter } from "./api/dynamic";
import { scrubRouter } from "./api/scrub";
import { DynamicSecretsManager } from "./dynamic/manager";
import { PatternEngine } from "./patterns/engine";
import { patternsRouter } from "./api/patterns";
import { initDB } from "./db/init";
import { LeaseManager } from "./lease/manager";
import { AuditLog } from "./audit/logger";
import { SecretsEngine } from "./secrets/engine";
import { PolicyEngine } from "./policy/engine";
import { getConnInfo } from "hono/bun";
import { loadConfig } from "./config";
import { VERSION } from "./version";
import { EventBus } from "./events/bus";
import { hkdfSync } from "crypto";

const config = loadConfig();
const db = initDB(config.dataDir);
const eventBus = new EventBus();
const audit = new AuditLog(db, eventBus);
const secrets = new SecretsEngine(db, config.masterKey);
const policies = new PolicyEngine(config.configDir, db);
const leases = new LeaseManager(db, secrets, audit);
const dynamicSecrets = new DynamicSecretsManager(db, audit, config.masterKey);
const patternEngine = new PatternEngine(db);

// Start lease reapers (check for expired leases every 30s)
leases.startReaper(30_000);
dynamicSecrets.startReaper(30_000);

// Audit log retention purge + onboarding token cleanup (check every hour)
const auditPurgeInterval = setInterval(() => {
  const purged = audit.purgeExpired();
  if (purged > 0) {
    console.log(`[gatehouse:audit] purged ${purged} expired audit entries`);
  }
  // Keep expired/consumed tokens for 24h of audit visibility, then drop.
  const dropped = db
    .query("DELETE FROM onboarding_tokens WHERE expires_at < datetime('now', '-1 day')")
    .run();
  if (dropped.changes > 0) {
    console.log(`[gatehouse:onboard] purged ${dropped.changes} expired tokens`);
  }
}, 3_600_000);

const startTime = Date.now();
const app = new Hono();

// Request ID middleware - adds X-Request-Id to every response
app.use("*", async (c, next) => {
  const requestId = c.req.header("X-Request-Id") || crypto.randomUUID();
  c.set("requestId", requestId);
  await next();
  c.header("X-Request-Id", requestId);
});

// Source IP middleware - prefers x-forwarded-for (behind reverse proxy), falls back to connection IP
app.use("*", async (c, next) => {
  const forwarded = c.req.header("x-forwarded-for");
  const realIp = c.req.header("x-real-ip");
  let sourceIp = forwarded?.split(",")[0]?.trim() || realIp || "unknown";
  if (sourceIp === "unknown") {
    try {
      const info = getConnInfo(c);
      sourceIp = info.remote?.address || "unknown";
    } catch { /* not available in all contexts */ }
  }
  // Strip IPv4-mapped IPv6 prefix (::ffff:10.0.0.1 → 10.0.0.1)
  if (sourceIp.startsWith("::ffff:")) sourceIp = sourceIp.slice(7);
  c.set("sourceIp", sourceIp);
  await next();
});

// Conditional logging based on log level
const logLevel = (process.env.GATEHOUSE_LOG_LEVEL || "info").toLowerCase();
if (logLevel !== "error") {
  app.use("*", logger());
}

// CORS - restrict to configured origins
const corsOrigins = process.env.GATEHOUSE_CORS_ORIGINS
  ? process.env.GATEHOUSE_CORS_ORIGINS.split(",").map((o) => o.trim())
  : [`http://localhost:${config.port}`];

app.use(
  "*",
  cors({
    origin: corsOrigins,
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization", "X-Request-Id"],
    credentials: true,
    maxAge: 3600,
  })
);

// Body size limit (1MB default, protects against memory exhaustion)
const MAX_BODY_SIZE = parseInt(process.env.GATEHOUSE_MAX_BODY_SIZE || "1048576", 10);
app.use("*", async (c, next) => {
  const contentLength = c.req.header("content-length");
  if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
    return c.json(
      { error: "Request body too large", request_id: c.get("requestId") },
      413
    );
  }
  await next();
});

// Security headers on all responses
app.use("*", async (c, next) => {
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  c.header("X-XSS-Protection", "1; mode=block");
  c.header("Referrer-Policy", "strict-origin-when-cross-origin");
});

// Health check (no auth) - checks DB connectivity
app.get("/health", (c) => {
  try {
    db.query("SELECT 1").get();
  } catch {
    return c.json(
      { status: "unhealthy", error: "database unreachable", request_id: c.get("requestId") },
      503
    );
  }
  return c.json({
    status: "ok",
    version: VERSION,
    uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
  });
});

// Web UI (no auth - the UI handles its own login)
app.get("/", async (c) => {
  const uiPath = new URL("./ui/index.html", import.meta.url).pathname;
  try {
    const html = await Bun.file(uiPath).text();
    c.header(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:;"
    );
    return c.html(html);
  } catch {
    return c.text("UI not found. Build the UI first.", 404);
  }
});

// Auth routes (login, token exchange - no auth middleware)
app.route("/v1/auth", authRouter(db, config));

// Onboarding routes (public fetch/exchange + admin-gated create/list/revoke).
// Mounted BEFORE authMiddleware: the onboarding token in the URL path is the
// auth for public routes, and admin-gated routes verify the bearer token
// themselves (same pattern as /v1/auth). Do NOT read c.get("auth") here.
app.route("/v1/onboard", onboardRouter(db, audit, policies, config));

// Protected routes
app.use("/v1/*", authMiddleware(config));

// Server config (non-sensitive values only, requires auth)
app.get("/v1/config", (c) => {
  return c.json({
    port: config.port,
    jwt_expiry: "24h",
    oauth_enabled: !!config.oauth,
    oauth_issuer: config.oauth?.issuer ?? "",
    root_token_set: !!process.env.GATEHOUSE_ROOT_TOKEN,
    lease_reaper_interval: 30,
    max_lease_ttl: 86400,
    min_lease_ttl: 10,
    default_lease_ttl: 300,
  });
});

// SSO / OAuth settings (stored in DB settings table)
app.get("/v1/settings/sso", (c) => {
  const auth = c.get("auth") as any;
  if (!policies.check(auth.policies, "*", "admin")) {
    return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
  }
  const row = db.query("SELECT value FROM settings WHERE key = 'sso'").get() as { value: string } | null;
  if (!row) {
    return c.json({ enabled: false, issuer: "", client_id: "", redirect_uri: "", scopes: "openid profile email" });
  }
  const sso = JSON.parse(row.value);
  // Never return client_secret in full
  if (sso.client_secret) {
    sso.client_secret_set = true;
    sso.client_secret = "";
  }
  return c.json(sso);
});

app.post("/v1/settings/sso", async (c) => {
  const auth = c.get("auth") as any;
  if (!policies.check(auth.policies, "*", "admin")) {
    return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
  }

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
  }

  // Merge with existing settings so partial updates work
  const existing = db.query("SELECT value FROM settings WHERE key = 'sso'").get() as { value: string } | null;
  const current = existing ? JSON.parse(existing.value) : {};

  // If client_secret is empty string, keep existing
  if (body.client_secret === "") {
    body.client_secret = current.client_secret || "";
  }

  const sso = {
    enabled: body.enabled ?? current.enabled ?? false,
    issuer: body.issuer ?? current.issuer ?? "",
    client_id: body.client_id ?? current.client_id ?? "",
    client_secret: body.client_secret ?? current.client_secret ?? "",
    redirect_uri: body.redirect_uri ?? current.redirect_uri ?? "",
    scopes: body.scopes ?? current.scopes ?? "openid profile email",
  };

  db.query(
    `INSERT INTO settings (key, value) VALUES ('sso', ?)
     ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')`
  ).run(JSON.stringify(sso), JSON.stringify(sso));

  audit.log({
    identity: auth.identity,
    action: "settings.sso.update",
    source_ip: c.get("sourceIp"),
  });

  return c.json({ saved: true });
});

// Non-reversible fingerprint of the active master key. Useful for operators
// to confirm which key a running instance has loaded without revealing it.
app.get("/v1/admin/key-fingerprint", (c) => {
  const auth = c.get("auth") as any;
  if (!policies.check(auth.policies, "*", "admin")) {
    return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
  }
  const fp = Buffer.from(
    hkdfSync("sha256", config.masterKey, "gatehouse-v1", "gatehouse-fingerprint", 16)
  ).toString("hex");
  return c.json({ fingerprint: fp, algorithm: "HKDF-SHA256/gatehouse-fingerprint" });
});

// Key rotation ceremony (admin only)
app.post("/v1/admin/rotate-key", async (c) => {
  const auth = c.get("auth") as any;
  if (!policies.check(auth.policies, "*", "admin")) {
    return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
  }

  let body: { new_master_key: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
  }

  const { new_master_key } = body;
  if (!new_master_key || typeof new_master_key !== "string" || new_master_key.length < 64) {
    return c.json({
      error: "new_master_key must be a 64+ char hex string (openssl rand -hex 32)",
      request_id: c.get("requestId"),
    }, 400);
  }

  // Validate it's valid hex
  if (!/^[0-9a-fA-F]+$/.test(new_master_key)) {
    return c.json({ error: "new_master_key must be a hex string", request_id: c.get("requestId") }, 400);
  }

  const newKey = Buffer.from(new_master_key, "hex");

  try {
    // Re-wrap all secret DEKs
    const secretsRotated = secrets.rotateKEK(newKey);

    // Re-encrypt all dynamic secret configs
    const dynamicRotated = dynamicSecrets.rotateConfigKey(newKey);

    audit.log({
      identity: auth.identity,
      action: "admin.key_rotation",
      metadata: {
        secrets_rotated: String(secretsRotated),
        dynamic_configs_rotated: String(dynamicRotated),
      },
      source_ip: c.get("sourceIp"),
    });

    return c.json({
      rotated: true,
      secrets_rewrapped: secretsRotated,
      dynamic_configs_rewrapped: dynamicRotated,
      warning: "Update GATEHOUSE_MASTER_KEY env var to the new key before restarting",
    });
  } catch (err: any) {
    return c.json({
      error: `Rotation failed: ${err.message}`,
      request_id: c.get("requestId"),
    }, 500);
  }
});

// Server-Sent Events stream: audit fanout + heartbeat ticks.
// Admins see all events; non-admins see only events whose identity matches theirs.
app.get("/v1/events", (c) => {
  const auth = c.get("auth") as any;
  const isAdmin = policies.check(auth.policies, "*", "admin");
  const self = auth.identity;

  const stream = new ReadableStream({
    start(controller) {
      const enc = new TextEncoder();
      const send = (data: string) => {
        try { controller.enqueue(enc.encode(data)); } catch { /* closed */ }
      };

      send(`: gatehouse events v1\n\n`);
      send(`event: ready\ndata: {"ok":true}\n\n`);

      const unsub = eventBus.subscribe((e) => {
        if (e.type === "audit") {
          const rec = e.record as any;
          // Non-admins only see their own events - broadcasting other
          // identities' audit entries would be a privacy regression.
          if (!isAdmin && rec.identity !== self) return;
          send(`event: audit\ndata: ${JSON.stringify(rec)}\n\n`);
        } else if (e.type === "heartbeat") {
          send(`event: heartbeat\ndata: ${JSON.stringify(e)}\n\n`);
        }
      });

      const heartbeat = setInterval(() => {
        eventBus.emit({ type: "heartbeat", ts: Date.now() });
      }, 20_000);

      const close = () => {
        clearInterval(heartbeat);
        unsub();
        try { controller.close(); } catch { /* already closed */ }
      };

      const signal = c.req.raw.signal;
      if (signal.aborted) close();
      else signal.addEventListener("abort", close, { once: true });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      "Connection": "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
});

app.route("/v1/secrets", secretsRouter(secrets, policies, audit, patternEngine, dynamicSecrets));
app.route("/v1/secrets-bulk", bulkSecretsRouter(secrets, policies, audit));
app.route("/v1/lease", leaseRouter(leases, policies, audit, dynamicSecrets));
app.route("/v1/policy", policyRouter(policies, audit));
app.route("/v1/audit", auditRouter(audit, policies));
app.route("/v1/mcp", mcpHttpRouter(secrets, leases, policies, audit, patternEngine, dynamicSecrets));
app.route("/v1/proxy/patterns", patternsRouter(patternEngine, policies));
app.route("/v1/proxy", proxyRouter(secrets, policies, audit, patternEngine));
app.route("/v1/dynamic", dynamicRouter(dynamicSecrets, policies, audit));
app.route("/v1/scrub", scrubRouter());
app.route("/v1/me", meRouter(db, audit));

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("[gatehouse] shutting down...");
  leases.stopReaper();
  dynamicSecrets.stopReaper();
  clearInterval(auditPurgeInterval);
  db.close();
  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("[gatehouse] interrupted, shutting down...");
  leases.stopReaper();
  dynamicSecrets.stopReaper();
  clearInterval(auditPurgeInterval);
  db.close();
  process.exit(0);
});

const port = config.port;
console.log(`[gatehouse] listening on :${port}`);
console.log(`[gatehouse] web UI at http://localhost:${port}`);
console.log(`[gatehouse] MCP endpoint at http://localhost:${port}/v1/mcp`);

export default {
  port,
  fetch: app.fetch,
};
