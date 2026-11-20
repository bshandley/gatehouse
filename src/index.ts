import { Hono } from "hono";
import { cors } from "hono/cors";
import { secretsRouter, bulkSecretsRouter } from "./api/secrets";
import { leaseRouter } from "./api/lease";
import { authRouter } from "./api/auth";
import { onboardRouter } from "./api/onboard";
import { rotateRouter } from "./api/rotate";
import { skillRouter } from "./api/skill";
import { versionRouter } from "./api/version";
import { keyVerifyRouter } from "./api/keyVerify";
import { rotateKeyRouter } from "./api/rotateKey";
import { meRouter } from "./api/me";
import { policyRouter } from "./api/policy";
import { auditRouter } from "./api/audit";
import { authMiddleware } from "./auth/middleware";
import { validateOidcIssuerForSettings, reapExpiredSsoState, seedSsoFromEnv } from "./auth/sso";
import { mcpHttpRouter } from "./mcp/server";
import { proxyRouter } from "./api/proxy";
import { passthroughRouter } from "./api/passthrough";
import { handleGetProxyLimits, handlePostProxyLimits } from "./api/settings.proxyLimits";
import { dynamicRouter } from "./api/dynamic";
import { scrubRouter } from "./api/scrub";
import { statsRouter } from "./api/stats";
import { DynamicSecretsManager } from "./dynamic/manager";
import { PatternEngine } from "./patterns/engine";
import { patternsRouter } from "./api/patterns";
import { initDB } from "./db/init";
import { resolveBootstrapRootToken } from "./auth/bootstrapToken";
import { LeaseManager } from "./lease/manager";
import { AuditLog } from "./audit/logger";
import { SecretsEngine, keyFingerprint } from "./secrets/engine";
import { PolicyEngine } from "./policy/engine";
import { getConnInfo } from "hono/bun";
import { resolveSourceIp, parseTrustedProxies } from "./auth/sourceIp";
import { validateCIDRs } from "./auth/cidr";
import { uiAssetsRouter, UI_CSP } from "./api/uiAssets";
import { loadConfig } from "./config";
import { startHeartbeat } from "./backup/snapshot";
import { VERSION } from "./version";
import { EventBus } from "./events/bus";
import { RateLimiter } from "./rateLimits/limiter";
import { warnIfWebhookPrivate } from "./lease/webhook";
import { bodySizeLimit, maxBodySizeFromEnv, requestLogger } from "./http/middleware";

const config = loadConfig();
const db = initDB(config.dataDir);

// Bootstrap root token. Must run before authMiddleware(...) is constructed
// (it captures GATEHOUSE_ROOT_TOKEN at construction) and before any request.
const publicUrl = process.env.GATEHOUSE_PUBLIC_URL || `http://localhost:${config.port}`;
const bootstrap = resolveBootstrapRootToken({
  db,
  dataDir: config.dataDir,
  envToken: process.env.GATEHOUSE_ROOT_TOKEN,
  publicUrl: process.env.GATEHOUSE_PUBLIC_URL || undefined,
  port: config.port,
});
if (bootstrap.source === "file" || bootstrap.source === "generated" || bootstrap.source === "generated-unpersisted") {
  process.env.GATEHOUSE_ROOT_TOKEN = bootstrap.token!;
} else if (bootstrap.source === "none") {
  // Env was unset, empty, or whitespace-only: make sure nothing downstream sees it.
  delete process.env.GATEHOUSE_ROOT_TOKEN;
}
const rootTokenSource: "env" | "bootstrap" | null =
  bootstrap.source === "env" ? "env" : bootstrap.token ? "bootstrap" : null;
const stopHeartbeat = startHeartbeat(config.dataDir);
seedSsoFromEnv(db);
const eventBus = new EventBus();
const audit = new AuditLog(db, eventBus);
const secrets = new SecretsEngine(db, config.masterKey);
const policies = new PolicyEngine(config.configDir, db);
const leases = new LeaseManager(db, secrets, audit);
leases.attachBus(eventBus);
const dynamicSecrets = new DynamicSecretsManager(db, audit, config.masterKey);
const patternEngine = new PatternEngine(db);
const rateLimiter = new RateLimiter();

// Resolve and remember the public-facing server URL so approval webhooks can
// build absolute /v1/lease/<id>/approve and #leases links. Falls back to the
// local port when not configured.
leases.setServerBaseUrl(publicUrl);
warnIfWebhookPrivate();

// Start lease reapers (check for expired leases every 30s)
leases.startReaper(30_000);
dynamicSecrets.startReaper(30_000);

const ssoStateReaperInterval = setInterval(() => {
  const removed = reapExpiredSsoState(db);
  if (removed > 0) {
    console.log(`[gatehouse:sso] reaped ${removed} stale state row(s)`);
  }
}, 60_000);

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

// Source IP middleware. The source IP feeds every network-origin security
// control (AppRole IP allowlists, the rotate-token allowlist, and the
// lease/proxy auto_approve_from_ip gate), so forwarded headers are honored
// only when the socket peer is a configured trusted proxy. Loopback is always
// trusted; add more via GATEHOUSE_TRUSTED_PROXIES. See src/auth/sourceIp.ts.
const trustedProxies = parseTrustedProxies(process.env.GATEHOUSE_TRUSTED_PROXIES);
if (process.env.GATEHOUSE_TRUSTED_PROXIES) {
  const cidrErr = validateCIDRs(trustedProxies);
  if (cidrErr) {
    console.warn(`[gatehouse] GATEHOUSE_TRUSTED_PROXIES has an invalid entry: ${cidrErr}`);
  }
  console.log(`[gatehouse] honoring forwarded client IP from proxies: ${trustedProxies.join(", ")}`);
}
app.use("*", async (c, next) => {
  let socketIp: string | null = null;
  try {
    socketIp = getConnInfo(c).remote?.address ?? null;
  } catch { /* connection info not available in all contexts */ }
  c.set("sourceIp", resolveSourceIp({
    socketIp,
    forwardedFor: c.req.header("x-forwarded-for"),
    realIp: c.req.header("x-real-ip"),
    trustedProxies,
  }));
  await next();
});

// Conditional logging based on log level. /p requests are logged without
// their query string (src/http/middleware.ts).
const logLevel = (process.env.GATEHOUSE_LOG_LEVEL || "info").toLowerCase();
if (logLevel !== "error") {
  app.use("*", requestLogger());
}

// CORS - restrict to configured origins
const corsOrigins = process.env.GATEHOUSE_CORS_ORIGINS
  ? process.env.GATEHOUSE_CORS_ORIGINS.split(",").map((o) => o.trim())
  : [`http://localhost:${config.port}`];

app.use(
  "*",
  cors({
    origin: corsOrigins,
    allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization", "X-Request-Id"],
    credentials: true,
    maxAge: 3600,
  })
);

// Body size limit (1MB default, protects against memory exhaustion).
// Passthrough enforces the same limit itself, on the declared length and on
// the bytes actually read, and answers in its own error shape.
// A malformed GATEHOUSE_MAX_BODY_SIZE logs one warning and keeps the default.
app.use("*", bodySizeLimit(maxBodySizeFromEnv(process.env.GATEHOUSE_MAX_BODY_SIZE)));

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
      UI_CSP
    );
    // Force revalidation on every request. Without this, browsers cache the
    // single-file HTML aggressively and operators keep running stale UIs
    // after a Gatehouse upgrade. The cost is negligible (one ETag-style
    // round trip) and the file is ~300KB.
    c.header("Cache-Control", "no-cache, must-revalidate");
    return c.html(html);
  } catch {
    return c.text("UI not found. Build the UI first.", 404);
  }
});

// UI helper modules and bundled fonts (see src/api/uiAssets.ts).
app.route("/ui", uiAssetsRouter());

// Passthrough: /p/<alias>/... forwards to the alias's upstream with its
// secret injected. Outside /v1/*, so the auth middleware does not apply: the
// route authenticates the caller's credential itself (src/api/passthrough.ts).
app.route("/p", passthroughRouter({ secrets, policies, audit, db, rateLimiter, leases, patterns: patternEngine, config }));

// Auth routes (login, token exchange - no auth middleware)
app.route("/v1/auth", authRouter(db, config, audit, leases));

// Onboarding routes (public fetch/exchange + admin-gated create/list/revoke).
// Mounted BEFORE authMiddleware: the onboarding token in the URL path is the
// auth for public routes, and admin-gated routes verify the bearer token
// themselves (same pattern as /v1/auth). Do NOT read c.get("auth") here.
app.route("/v1/onboard", onboardRouter(db, audit, policies, config));

// Rotate routes (same pattern as onboard - public fetch/exchange + admin
// create). One-shot link rotates an existing AppRole's secret_id without
// touching role_id, policies, or the installed skill.
app.route("/v1/rotate", rotateRouter(db, audit, config));

// Protected routes
app.use("/v1/*", authMiddleware(config, db));

// Server config (non-sensitive values only, requires auth)
app.get("/v1/config", (c) => {
  const ssoRow = db
    .query("SELECT value FROM settings WHERE key = 'sso'")
    .get() as { value: string } | null;
  let ssoEnabled = false;
  let ssoIssuer = "";
  if (ssoRow) {
    try {
      const s = JSON.parse(ssoRow.value);
      ssoEnabled = s.enabled === true && !!s.issuer && !!s.client_id;
      ssoIssuer = s.issuer || "";
    } catch { /* malformed; leave defaults */ }
  }
  return c.json({
    port: config.port,
    jwt_expiry: "24h",
    oauth_enabled: ssoEnabled,
    oauth_issuer: ssoIssuer,
    root_token_set: !!process.env.GATEHOUSE_ROOT_TOKEN,
    root_token_source: rootTokenSource,
    lease_reaper_interval: 30,
    max_lease_ttl: 86400,
    min_lease_ttl: 10,
    default_lease_ttl: 300,
    approval_webhook_set: !!process.env.GATEHOUSE_APPROVAL_WEBHOOK_URL,
    approval_webhook_signed: !!process.env.GATEHOUSE_APPROVAL_WEBHOOK_SECRET,
    approval_request_default_ttl: 3600,
    approval_request_max_ttl: 86400,
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

  if ((body.enabled ?? current.enabled) && (body.issuer ?? current.issuer)) {
    try {
      await validateOidcIssuerForSettings(body.issuer ?? current.issuer);
    } catch (err: any) {
      return c.json(
        { error: `Issuer validation failed: ${err?.message || err}`, request_id: c.get("requestId") },
        400
      );
    }
  }

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
    trust_unverified_email: body.trust_unverified_email ?? current.trust_unverified_email ?? false,
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

// Proxy runtime limits: max upstream timeout + max upstream response body.
// Module: src/settings/proxyLimits.ts owns validation + cache + audit.
app.get("/v1/settings/proxy-limits", (c) => handleGetProxyLimits(c, db, policies));
app.post("/v1/settings/proxy-limits", (c) => handlePostProxyLimits(c, db, policies, audit));

// Non-reversible fingerprint of the active master key. Useful for operators
// to confirm which key a running instance has loaded without revealing it.
app.get("/v1/admin/key-fingerprint", (c) => {
  const auth = c.get("auth") as any;
  if (!policies.check(auth.policies, "*", "admin")) {
    return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
  }
  const fp = keyFingerprint(config.masterKey);
  return c.json({ fingerprint: fp, algorithm: "HKDF-SHA256/gatehouse-fingerprint" });
});

// Key rotation ceremony (admin only). Persists the new key to master.key on
// key-file installs; see src/api/rotateKey.ts.
app.route("/v1/admin/rotate-key", rotateKeyRouter({ secrets, dynamicSecrets, policies, audit, config }));

// Server-Sent Events stream: audit fanout + heartbeat ticks.
// Admins see all events; non-admins see only events whose identity matches theirs.
app.get("/v1/events", (c) => {
  // Bun closes a connection that is idle for 10s by default, which is shorter
  // than the 20s heartbeat and cut every stream mid-flight. Turn the idle
  // timeout off for this request only. Under Bun, Hono's c.env is the server.
  try {
    (c.env as { timeout?: (req: Request, seconds: number) => void } | undefined)?.timeout?.(c.req.raw, 0);
  } catch { /* not running under Bun.serve (tests) */ }
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
        } else if (e.type === "lease_request_created") {
          const leaseIdentity = (e.lease as { identity?: string }).identity;
          if (!isAdmin && leaseIdentity !== self) return;
          send(`event: lease_request_created\ndata: ${JSON.stringify(e.lease)}\n\n`);
        } else if (e.type === "lease_status_changed") {
          if (!isAdmin && e.identity !== self) return;
          send(`event: lease_status_changed\ndata: ${JSON.stringify(e)}\n\n`);
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

app.route("/v1/skill", skillRouter(policies, audit));
app.route("/v1/version", versionRouter());
app.route("/v1/admin/key-verify", keyVerifyRouter(db, () => config.masterKey, policies));
app.route("/v1/secrets", secretsRouter(secrets, policies, audit, patternEngine, dynamicSecrets));
app.route("/v1/secrets-bulk", bulkSecretsRouter(secrets, policies, audit));
app.route("/v1/lease", leaseRouter(leases, policies, audit, dynamicSecrets, secrets));
app.route("/v1/policy", policyRouter(policies, audit));
app.route("/v1/audit", auditRouter(audit, policies));
app.route("/v1/mcp", mcpHttpRouter(secrets, leases, policies, audit, patternEngine, dynamicSecrets, db, rateLimiter));
app.route("/v1/proxy/patterns", patternsRouter(patternEngine, policies));
app.route("/v1/proxy", proxyRouter(secrets, policies, audit, patternEngine, db, rateLimiter, leases));
app.route("/v1/dynamic", dynamicRouter(dynamicSecrets, policies, audit));
app.route("/v1/scrub", scrubRouter(audit));
app.route("/v1/stats", statsRouter(audit, secrets, policies));
app.route("/v1/me", meRouter(db, audit));

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("[gatehouse] shutting down...");
  leases.stopReaper();
  dynamicSecrets.stopReaper();
  clearInterval(auditPurgeInterval);
  clearInterval(ssoStateReaperInterval);
  stopHeartbeat();
  db.close();
  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("[gatehouse] interrupted, shutting down...");
  leases.stopReaper();
  dynamicSecrets.stopReaper();
  clearInterval(auditPurgeInterval);
  clearInterval(ssoStateReaperInterval);
  stopHeartbeat();
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
