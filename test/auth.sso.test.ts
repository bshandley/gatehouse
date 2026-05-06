import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { startFakeIdp } from "./helpers/fake-oidc";
import { validateOidcIssuerForSettings, reapExpiredSsoState, seedSsoFromEnv } from "../src/auth/sso";
import { _resetCachesForTests } from "../src/auth/oidc";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Hono } from "hono";
import { authRouter, _resetRateLimitForTests } from "../src/api/auth";
import { AuditLog } from "../src/audit/logger";
import { deriveKey } from "../src/secrets/engine";
import type { GatehouseConfig } from "../src/config";

describe("SSO DB schema", () => {
  let db: Database;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-sso-test-"));
    db = initDB(dir);
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("sso_login_state table exists with the expected columns", () => {
    const cols = db
      .query("PRAGMA table_info(sso_login_state)")
      .all() as { name: string; type: string }[];
    const names = cols.map((c) => c.name).sort();
    expect(names).toEqual(["code_verifier", "created_at", "nonce", "state"]);
  });

  test("sso_login_state has an index on created_at", () => {
    const indexes = db
      .query("PRAGMA index_list(sso_login_state)")
      .all() as { name: string }[];
    expect(indexes.some((i) => i.name === "idx_sso_login_state_created_at")).toBe(true);
  });

  test("inserting + selecting a row works", () => {
    db.query(
      "INSERT INTO sso_login_state (state, nonce, code_verifier, created_at) VALUES (?, ?, ?, ?)"
    ).run("s1", "n1", "v1", 1700000000);
    const row = db
      .query("SELECT state, nonce, code_verifier, created_at FROM sso_login_state WHERE state = ?")
      .get("s1");
    expect(row).toEqual({ state: "s1", nonce: "n1", code_verifier: "v1", created_at: 1700000000 });
  });
});

describe("Fake OIDC IdP helper", () => {
  test("publishes a working discovery document", async () => {
    const idp = await startFakeIdp({ clientId: "c", clientSecret: "s" });
    try {
      const res = await fetch(`${idp.url}/.well-known/openid-configuration`);
      expect(res.status).toBe(200);
      const meta = await res.json();
      expect(meta.token_endpoint).toBe(`${idp.url}/token`);
      expect(meta.jwks_uri).toBe(`${idp.url}/jwks`);
    } finally {
      await idp.stop();
    }
  });

  test("/jwks returns one RS256 signing key", async () => {
    const idp = await startFakeIdp({ clientId: "c", clientSecret: "s" });
    try {
      const res = await fetch(`${idp.url}/jwks`);
      const body = await res.json();
      expect(body.keys.length).toBe(1);
      expect(body.keys[0].alg).toBe("RS256");
      expect(body.keys[0].kid).toBe("test-kid");
    } finally {
      await idp.stop();
    }
  });
});

const TEST_MASTER_KEY = Buffer.from("a".repeat(64), "hex");
const TEST_JWT_SECRET = Buffer.from(deriveKey(TEST_MASTER_KEY, "gatehouse-jwt")).toString("hex");

function buildSsoApp(db: Database) {
  const config: GatehouseConfig = {
    port: 3100,
    dataDir: "/tmp",
    configDir: "/tmp",
    masterKey: TEST_MASTER_KEY,
    jwtSecret: TEST_JWT_SECRET,
  };
  const app = new Hono();
  app.use("*", async (c, next) => {
    c.set("requestId", crypto.randomUUID());
    c.set("sourceIp", c.req.header("x-forwarded-for") || "127.0.0.1");
    await next();
  });
  app.route("/v1/auth", authRouter(db, config, new AuditLog(db)));
  return app;
}

describe("GET /v1/auth/sso/status", () => {
  let db: Database;
  let app: ReturnType<typeof buildSsoApp>;
  let dir: string;

  beforeEach(() => {
    _resetRateLimitForTests();
    dir = mkdtempSync(join(tmpdir(), "gatehouse-sso-status-"));
    db = initDB(dir);
    app = buildSsoApp(db);
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("returns enabled:false when no settings row exists", async () => {
    const res = await app.request("/v1/auth/sso/status");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ enabled: false });
  });

  test("returns enabled:false when row exists but disabled", async () => {
    db.query("INSERT INTO settings (key, value) VALUES ('sso', ?)").run(
      JSON.stringify({ enabled: false, issuer: "https://idp.test", client_id: "x" })
    );
    const res = await app.request("/v1/auth/sso/status");
    expect(await res.json()).toEqual({ enabled: false });
  });

  test("returns enabled:true only when enabled and issuer and client_id are all present", async () => {
    db.query("INSERT INTO settings (key, value) VALUES ('sso', ?)").run(
      JSON.stringify({ enabled: true, issuer: "https://idp.test", client_id: "x" })
    );
    const res = await app.request("/v1/auth/sso/status");
    expect(await res.json()).toEqual({ enabled: true });
  });

  test("returns enabled:false when enabled but issuer missing", async () => {
    db.query("INSERT INTO settings (key, value) VALUES ('sso', ?)").run(
      JSON.stringify({ enabled: true, issuer: "", client_id: "x" })
    );
    const res = await app.request("/v1/auth/sso/status");
    expect(await res.json()).toEqual({ enabled: false });
  });

  test("response contains no other fields (no info leak)", async () => {
    db.query("INSERT INTO settings (key, value) VALUES ('sso', ?)").run(
      JSON.stringify({ enabled: true, issuer: "https://idp.test", client_id: "secret-client" })
    );
    const res = await app.request("/v1/auth/sso/status");
    const body = await res.json();
    expect(Object.keys(body).sort()).toEqual(["enabled"]);
  });
});

describe("GET /v1/auth/sso/start", () => {
  let db: Database;
  let app: ReturnType<typeof buildSsoApp>;
  let dir: string;
  let idp: Awaited<ReturnType<typeof startFakeIdp>>;

  beforeEach(async () => {
    _resetRateLimitForTests();
    dir = mkdtempSync(join(tmpdir(), "gatehouse-sso-start-"));
    db = initDB(dir);
    app = buildSsoApp(db);
    idp = await startFakeIdp({ clientId: "gh-client", clientSecret: "gh-secret" });
    db.query("INSERT INTO settings (key, value) VALUES ('sso', ?)").run(
      JSON.stringify({
        enabled: true,
        issuer: idp.url,
        client_id: "gh-client",
        client_secret: "gh-secret",
        redirect_uri: "http://gatehouse.test/v1/auth/sso/callback",
        scopes: "openid profile email",
      })
    );
  });

  afterEach(async () => {
    await idp.stop();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("returns 404 when SSO is not enabled", async () => {
    db.query("UPDATE settings SET value = ? WHERE key = 'sso'").run(
      JSON.stringify({ enabled: false })
    );
    const res = await app.request("/v1/auth/sso/start", { redirect: "manual" });
    expect(res.status).toBe(404);
  });

  test("redirects to IdP authorize URL with all OIDC params", async () => {
    const res = await app.request("/v1/auth/sso/start", { redirect: "manual" });
    expect(res.status).toBe(302);
    const location = res.headers.get("location")!;
    const url = new URL(location);
    expect(url.origin + url.pathname).toBe(`${idp.url}/authorize`);
    expect(url.searchParams.get("client_id")).toBe("gh-client");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("state")).toBeTruthy();
    expect(url.searchParams.get("nonce")).toBeTruthy();
  });

  test("inserts a row in sso_login_state matching the redirect's state param", async () => {
    const res = await app.request("/v1/auth/sso/start", { redirect: "manual" });
    const location = res.headers.get("location")!;
    const state = new URL(location).searchParams.get("state")!;
    const row = db
      .query("SELECT state, nonce, code_verifier, created_at FROM sso_login_state WHERE state = ?")
      .get(state) as any;
    expect(row).toBeTruthy();
    expect(row.nonce.length).toBeGreaterThan(20);
    expect(row.code_verifier.length).toBeGreaterThan(40);
    expect(typeof row.created_at).toBe("number");
  });

  test("two parallel calls produce distinct state rows", async () => {
    const r1 = await app.request("/v1/auth/sso/start", { redirect: "manual" });
    const r2 = await app.request("/v1/auth/sso/start", { redirect: "manual" });
    const s1 = new URL(r1.headers.get("location")!).searchParams.get("state")!;
    const s2 = new URL(r2.headers.get("location")!).searchParams.get("state")!;
    expect(s1).not.toBe(s2);
    const count = db.query("SELECT COUNT(*) as n FROM sso_login_state").get() as any;
    expect(count.n).toBe(2);
  });
});

async function setupCallbackEnv(db: Database, app: ReturnType<typeof buildSsoApp>) {
  // Drive a /start to mint a state/nonce/verifier row.
  const startRes = await app.request("/v1/auth/sso/start", { redirect: "manual" });
  const state = new URL(startRes.headers.get("location")!).searchParams.get("state")!;
  const stateRow = db
    .query("SELECT nonce FROM sso_login_state WHERE state = ?")
    .get(state) as any;
  return { state, nonce: stateRow.nonce };
}

describe("GET /v1/auth/sso/callback - happy path", () => {
  let db: Database;
  let app: ReturnType<typeof buildSsoApp>;
  let dir: string;
  let idp: Awaited<ReturnType<typeof startFakeIdp>>;

  beforeEach(async () => {
    _resetRateLimitForTests();
    dir = mkdtempSync(join(tmpdir(), "gatehouse-sso-cb-"));
    db = initDB(dir);
    app = buildSsoApp(db);
    idp = await startFakeIdp({ clientId: "gh-client", clientSecret: "gh-secret" });
    db.query("INSERT INTO settings (key, value) VALUES ('sso', ?)").run(
      JSON.stringify({
        enabled: true,
        issuer: idp.url,
        client_id: "gh-client",
        client_secret: "gh-secret",
        redirect_uri: "http://gatehouse.test/v1/auth/sso/callback",
        scopes: "openid profile email",
      })
    );
    db.query(
      "INSERT INTO users (username, password_hash, display_name, email) VALUES (?, ?, ?, ?)"
    ).run("alice", "x", "Alice", "alice@example.com");
  });

  afterEach(async () => {
    await idp.stop();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("matched email: redirect to /#sso=<jwt>, state row deleted, last_login updated, audit success", async () => {
    const { state, nonce } = await setupCallbackEnv(db, app);
    idp.setNextNonce(nonce);
    idp.setNextUser({ sub: "u1", email: "alice@example.com", email_verified: true });

    const res = await app.request(
      `/v1/auth/sso/callback?state=${state}&code=test-code`,
      { redirect: "manual" }
    );
    expect(res.status).toBe(302);
    const loc = res.headers.get("location")!;
    expect(loc.startsWith("/#sso=")).toBe(true);
    const jwt = decodeURIComponent(loc.slice("/#sso=".length));
    expect(jwt.split(".").length).toBe(3);

    // Decode the JWT payload (no signature verification needed; oidc.test
    // already proves we mint valid signatures) and assert its shape matches
    // the password-login JWT exactly.
    const payload = JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString());
    expect(payload.sub).toBe("user:alice");
    expect(payload.policies).toEqual(["admin"]);
    expect(payload.display_name).toBe("Alice");
    expect(payload.iss).toBe("gatehouse");
    expect(typeof payload.exp).toBe("number");
    expect(payload.exp - payload.iat).toBe(24 * 60 * 60);

    const stateAfter = db
      .query("SELECT 1 FROM sso_login_state WHERE state = ?")
      .get(state);
    expect(stateAfter).toBeNull();

    const userRow = db
      .query("SELECT last_login FROM users WHERE username = 'alice'")
      .get() as any;
    expect(userRow.last_login).not.toBeNull();

    const auditRow = db
      .query("SELECT action FROM audit_log WHERE action = 'sso.callback.success' ORDER BY id DESC LIMIT 1")
      .get();
    expect(auditRow).toBeTruthy();
  });

  // Regression guard for RFC 9207 (Authorization Server Issuer Identification).
  // PocketID and recent Keycloak builds declare
  // `authorization_response_iss_parameter_supported: true` and emit `iss` in
  // the callback redirect. Our wrapper must forward that param into
  // validateAuthResponse or every login fails with `exchange_failed`.
  test("forwards RFC 9207 `iss` callback param when AS declares support", async () => {
    // Re-init: turn on iss-supported BEFORE the discovery doc is cached.
    _resetCachesForTests();
    idp.setIssParameterSupported(true);

    const { state, nonce } = await setupCallbackEnv(db, app);
    idp.setNextNonce(nonce);
    idp.setNextUser({ sub: "u1", email: "alice@example.com", email_verified: true });

    // Pass `iss` in the callback URL the way PocketID does.
    const issParam = encodeURIComponent(idp.url);
    const res = await app.request(
      `/v1/auth/sso/callback?state=${state}&code=test-code&iss=${issParam}`,
      { redirect: "manual" }
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")?.startsWith("/#sso=")).toBe(true);
  });

  test("AS declares `iss` supported but callback omits it -> exchange_failed", async () => {
    _resetCachesForTests();
    idp.setIssParameterSupported(true);

    const { state, nonce } = await setupCallbackEnv(db, app);
    idp.setNextNonce(nonce);
    idp.setNextUser({ sub: "u1", email: "alice@example.com", email_verified: true });

    // Deliberately omit `iss` from the callback to verify the gate fires.
    const res = await app.request(
      `/v1/auth/sso/callback?state=${state}&code=test-code`,
      { redirect: "manual" }
    );
    expect(res.status).toBe(400);
    const audit = db
      .query("SELECT action FROM audit_log WHERE action = 'sso.callback.exchange_failed' ORDER BY id DESC LIMIT 1")
      .get();
    expect(audit).toBeTruthy();
  });
});

describe("GET /v1/auth/sso/callback - invalid_state failures", () => {
  let db: Database;
  let app: ReturnType<typeof buildSsoApp>;
  let dir: string;
  let idp: Awaited<ReturnType<typeof startFakeIdp>>;

  beforeEach(async () => {
    _resetRateLimitForTests();
    dir = mkdtempSync(join(tmpdir(), "gatehouse-sso-cb-state-"));
    db = initDB(dir);
    app = buildSsoApp(db);
    idp = await startFakeIdp({ clientId: "gh-client", clientSecret: "gh-secret" });
    db.query("INSERT INTO settings (key, value) VALUES ('sso', ?)").run(
      JSON.stringify({
        enabled: true,
        issuer: idp.url,
        client_id: "gh-client",
        client_secret: "gh-secret",
        redirect_uri: "http://gatehouse.test/v1/auth/sso/callback",
        scopes: "openid profile email",
      })
    );
  });

  afterEach(async () => {
    await idp.stop();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("missing state row -> 400 + invalid_state audit", async () => {
    const res = await app.request("/v1/auth/sso/callback?state=does-not-exist&code=x");
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Login link expired");
    const a = db
      .query("SELECT action FROM audit_log WHERE action = 'sso.callback.invalid_state'")
      .all();
    expect(a.length).toBe(1);
  });

  test("expired state row -> invalid_state", async () => {
    db.query(
      "INSERT INTO sso_login_state (state, nonce, code_verifier, created_at) VALUES (?, ?, ?, ?)"
    ).run("old-state", "n", "v".repeat(43), Math.floor(Date.now() / 1000) - 700);
    const res = await app.request("/v1/auth/sso/callback?state=old-state&code=x");
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Login link expired");
  });

  test("reused state row -> second call invalid_state", async () => {
    // First, drive a real /start so we have a real state.
    const startRes = await app.request("/v1/auth/sso/start", { redirect: "manual" });
    const state = new URL(startRes.headers.get("location")!).searchParams.get("state")!;

    // First callback: token exchange will fail (no nonce set up on IdP), but state is consumed.
    await app.request(`/v1/auth/sso/callback?state=${state}&code=test-code`);

    // Second callback with the same state: should be invalid_state because row was deleted.
    const res2 = await app.request(`/v1/auth/sso/callback?state=${state}&code=test-code`);
    expect(res2.status).toBe(400);
    expect(await res2.text()).toContain("Login link expired");
  });
});

describe("GET /v1/auth/sso/callback - exchange and verify failures", () => {
  let db: Database;
  let app: ReturnType<typeof buildSsoApp>;
  let dir: string;
  let idp: Awaited<ReturnType<typeof startFakeIdp>>;

  beforeEach(async () => {
    _resetRateLimitForTests();
    dir = mkdtempSync(join(tmpdir(), "gatehouse-sso-cb-fail-"));
    db = initDB(dir);
    app = buildSsoApp(db);
    idp = await startFakeIdp({ clientId: "gh-client", clientSecret: "gh-secret" });
    db.query("INSERT INTO settings (key, value) VALUES ('sso', ?)").run(
      JSON.stringify({
        enabled: true,
        issuer: idp.url,
        client_id: "gh-client",
        client_secret: "gh-secret",
        redirect_uri: "http://gatehouse.test/v1/auth/sso/callback",
        scopes: "openid profile email",
      })
    );
  });

  afterEach(async () => {
    await idp.stop();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  async function startState(): Promise<{ state: string; nonce: string }> {
    const res = await app.request("/v1/auth/sso/start", { redirect: "manual" });
    const state = new URL(res.headers.get("location")!).searchParams.get("state")!;
    const row = db.query("SELECT nonce FROM sso_login_state WHERE state = ?").get(state) as any;
    return { state, nonce: row.nonce };
  }

  function lastAuditAction(): string | undefined {
    const r = db
      .query("SELECT action FROM audit_log WHERE action LIKE 'sso.callback.%' ORDER BY id DESC LIMIT 1")
      .get() as any;
    return r?.action;
  }

  test("token endpoint returns 400 -> exchange_failed", async () => {
    const { state } = await startState();
    idp.failNextTokenExchange(400);
    const res = await app.request(`/v1/auth/sso/callback?state=${state}&code=test-code`);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Sign-in failed");
    expect(lastAuditAction()).toBe("sso.callback.exchange_failed");
  });

  test("ID token signed with wrong key -> exchange_failed", async () => {
    const { state, nonce } = await startState();
    idp.useWrongKeyForNext(true);
    idp.setNextNonce(nonce);
    const res = await app.request(`/v1/auth/sso/callback?state=${state}&code=test-code`);
    expect(res.status).toBe(400);
    expect(lastAuditAction()).toBe("sso.callback.exchange_failed");
  });

  test("ID token wrong audience -> exchange_failed", async () => {
    const { state, nonce } = await startState();
    idp.setNextAud("wrong-aud");
    idp.setNextNonce(nonce);
    const res = await app.request(`/v1/auth/sso/callback?state=${state}&code=test-code`);
    expect(res.status).toBe(400);
    expect(lastAuditAction()).toBe("sso.callback.exchange_failed");
  });

  test("nonce mismatch -> exchange_failed", async () => {
    const { state } = await startState();
    idp.setNextNonce("not-the-real-nonce");
    const res = await app.request(`/v1/auth/sso/callback?state=${state}&code=test-code`);
    expect(res.status).toBe(400);
    expect(lastAuditAction()).toBe("sso.callback.exchange_failed");
  });

  test("email_verified false -> unverified_email", async () => {
    const { state, nonce } = await startState();
    idp.setNextNonce(nonce);
    idp.setNextUser({ sub: "u", email: "x@example.com", email_verified: false });
    const res = await app.request(`/v1/auth/sso/callback?state=${state}&code=test-code`);
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("confirm your email");
    expect(lastAuditAction()).toBe("sso.callback.unverified_email");
  });

  test("email_verified absent -> unverified_email", async () => {
    const { state, nonce } = await startState();
    idp.setNextNonce(nonce);
    idp.setNextUser({ sub: "u", email: "x@example.com", email_verified: undefined });
    const res = await app.request(`/v1/auth/sso/callback?state=${state}&code=test-code`);
    expect(res.status).toBe(403);
    expect(lastAuditAction()).toBe("sso.callback.unverified_email");
  });

  test("trust_unverified_email=true allows email_verified=false", async () => {
    // Re-save settings with trust_unverified_email enabled.
    db.query("UPDATE settings SET value = ? WHERE key = 'sso'").run(
      JSON.stringify({
        enabled: true,
        issuer: idp.url,
        client_id: "gh-client",
        client_secret: "gh-secret",
        redirect_uri: "http://gatehouse.test/v1/auth/sso/callback",
        scopes: "openid profile email",
        trust_unverified_email: true,
      })
    );
    // Insert a user that matches the email so the link succeeds.
    db.query(
      "INSERT INTO users (username, password_hash, display_name, email) VALUES (?, ?, ?, ?)"
    ).run("alice", "x", "Alice", "alice@example.com");

    const { state, nonce } = await startState();
    idp.setNextNonce(nonce);
    idp.setNextUser({ sub: "u", email: "alice@example.com", email_verified: false });
    const res = await app.request(`/v1/auth/sso/callback?state=${state}&code=test-code`);
    // Should succeed: 302 to /#sso=<jwt>, no unverified_email audit.
    expect(res.status).toBe(302);
    expect(res.headers.get("location")?.startsWith("/#sso=")).toBe(true);
    const audit = db
      .query("SELECT 1 FROM audit_log WHERE action = 'sso.callback.unverified_email'")
      .all();
    expect(audit.length).toBe(0);
    const success = db
      .query("SELECT 1 FROM audit_log WHERE action = 'sso.callback.success'")
      .all();
    expect(success.length).toBe(1);
  });

  test("trust_unverified_email=true allows email_verified absent", async () => {
    db.query("UPDATE settings SET value = ? WHERE key = 'sso'").run(
      JSON.stringify({
        enabled: true,
        issuer: idp.url,
        client_id: "gh-client",
        client_secret: "gh-secret",
        redirect_uri: "http://gatehouse.test/v1/auth/sso/callback",
        scopes: "openid profile email",
        trust_unverified_email: true,
      })
    );
    db.query(
      "INSERT INTO users (username, password_hash, display_name, email) VALUES (?, ?, ?, ?)"
    ).run("bob", "x", "Bob", "bob@example.com");

    const { state, nonce } = await startState();
    idp.setNextNonce(nonce);
    idp.setNextUser({ sub: "u", email: "bob@example.com", email_verified: undefined });
    const res = await app.request(`/v1/auth/sso/callback?state=${state}&code=test-code`);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")?.startsWith("/#sso=")).toBe(true);
  });
});

describe("GET /v1/auth/sso/callback - user lookup failures", () => {
  let db: Database;
  let app: ReturnType<typeof buildSsoApp>;
  let dir: string;
  let idp: Awaited<ReturnType<typeof startFakeIdp>>;

  beforeEach(async () => {
    _resetRateLimitForTests();
    dir = mkdtempSync(join(tmpdir(), "gatehouse-sso-cb-user-"));
    db = initDB(dir);
    app = buildSsoApp(db);
    idp = await startFakeIdp({ clientId: "gh-client", clientSecret: "gh-secret" });
    db.query("INSERT INTO settings (key, value) VALUES ('sso', ?)").run(
      JSON.stringify({
        enabled: true,
        issuer: idp.url,
        client_id: "gh-client",
        client_secret: "gh-secret",
        redirect_uri: "http://gatehouse.test/v1/auth/sso/callback",
        scopes: "openid profile email",
      })
    );
  });

  afterEach(async () => {
    await idp.stop();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  async function startAndComplete(email: string, email_verified = true): Promise<Response> {
    const startRes = await app.request("/v1/auth/sso/start", { redirect: "manual" });
    const state = new URL(startRes.headers.get("location")!).searchParams.get("state")!;
    const nonce = (db.query("SELECT nonce FROM sso_login_state WHERE state = ?").get(state) as any).nonce;
    idp.setNextNonce(nonce);
    idp.setNextUser({ sub: "u", email, email_verified });
    return await app.request(`/v1/auth/sso/callback?state=${state}&code=test-code`);
  }

  function lastAudit(action: string): boolean {
    return !!db
      .query("SELECT 1 FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1")
      .get(action);
  }

  test("no user has this email -> no_user_match", async () => {
    const res = await startAndComplete("nobody@example.com");
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("No Gatehouse account is linked");
    expect(lastAudit("sso.callback.no_user_match")).toBe(true);
  });

  test("user with email exists but enabled=0 -> no_user_match", async () => {
    db.query(
      "INSERT INTO users (username, password_hash, display_name, email, enabled) VALUES (?, ?, ?, ?, 0)"
    ).run("disabled", "x", "Disabled", "disabled@example.com");
    const res = await startAndComplete("disabled@example.com");
    expect(res.status).toBe(403);
    expect(lastAudit("sso.callback.no_user_match")).toBe(true);
  });

  test("multiple users share an email -> email_collision", async () => {
    db.query(
      "INSERT INTO users (username, password_hash, display_name, email) VALUES (?, ?, ?, ?)"
    ).run("a", "x", "A", "shared@example.com");
    db.query(
      "INSERT INTO users (username, password_hash, display_name, email) VALUES (?, ?, ?, ?)"
    ).run("b", "x", "B", "shared@example.com");
    const res = await startAndComplete("shared@example.com");
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("No Gatehouse account is linked");
    expect(lastAudit("sso.callback.email_collision")).toBe(true);
  });
});

describe("validateOidcIssuerForSettings", () => {
  let idp: Awaited<ReturnType<typeof startFakeIdp>>;
  beforeEach(async () => {
    idp = await startFakeIdp({ clientId: "x", clientSecret: "y" });
  });
  afterEach(async () => { await idp.stop(); });

  test("reachable issuer with required endpoints passes", async () => {
    await expect(validateOidcIssuerForSettings(idp.url)).resolves.toBeUndefined();
  });

  test("unreachable issuer rejects", async () => {
    await expect(validateOidcIssuerForSettings("http://localhost:1")).rejects.toThrow();
  });

  test("issuer that returns non-JSON rejects", async () => {
    const broken = Bun.serve({
      port: 0,
      fetch: () => new Response("nope", { status: 200, headers: { "content-type": "text/plain" } }),
    });
    try {
      await expect(
        validateOidcIssuerForSettings(`http://localhost:${broken.port}`)
      ).rejects.toThrow();
    } finally {
      broken.stop();
    }
  });
});

describe("SSO state reaper", () => {
  let db: Database;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-sso-reap-"));
    db = initDB(dir);
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("deletes rows older than 10 minutes, keeps newer rows", () => {
    const now = Math.floor(Date.now() / 1000);
    db.query(
      "INSERT INTO sso_login_state (state, nonce, code_verifier, created_at) VALUES (?, ?, ?, ?)"
    ).run("fresh", "n", "v".repeat(43), now);
    db.query(
      "INSERT INTO sso_login_state (state, nonce, code_verifier, created_at) VALUES (?, ?, ?, ?)"
    ).run("aging", "n", "v".repeat(43), now - 599);
    db.query(
      "INSERT INTO sso_login_state (state, nonce, code_verifier, created_at) VALUES (?, ?, ?, ?)"
    ).run("stale", "n", "v".repeat(43), now - 700);

    const removed = reapExpiredSsoState(db);
    expect(removed).toBe(1);
    const remaining = db
      .query("SELECT state FROM sso_login_state ORDER BY state")
      .all() as any[];
    expect(remaining.map((r) => r.state)).toEqual(["aging", "fresh"]);
  });
});

describe("SSO env-var seeding on boot", () => {
  let db: Database;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-sso-seed-"));
    db = initDB(dir);
    delete process.env.GATEHOUSE_OAUTH_ISSUER;
    delete process.env.GATEHOUSE_OAUTH_CLIENT_ID;
    delete process.env.GATEHOUSE_OAUTH_CLIENT_SECRET;
    delete process.env.GATEHOUSE_OAUTH_REDIRECT_URI;
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("no env, no row -> no row written", () => {
    seedSsoFromEnv(db);
    const row = db.query("SELECT 1 FROM settings WHERE key = 'sso'").get();
    expect(row).toBeNull();
  });

  test("env set, no row -> row written with enabled:true", () => {
    process.env.GATEHOUSE_OAUTH_ISSUER = "https://idp.example";
    process.env.GATEHOUSE_OAUTH_CLIENT_ID = "cid";
    process.env.GATEHOUSE_OAUTH_CLIENT_SECRET = "csec";
    process.env.GATEHOUSE_OAUTH_REDIRECT_URI = "http://gh/v1/auth/sso/callback";
    seedSsoFromEnv(db);
    const row = db.query("SELECT value FROM settings WHERE key = 'sso'").get() as any;
    expect(row).toBeTruthy();
    const v = JSON.parse(row.value);
    expect(v.enabled).toBe(true);
    expect(v.issuer).toBe("https://idp.example");
    expect(v.client_id).toBe("cid");
    expect(v.scopes).toBe("openid profile email");
  });

  test("env set, row already present -> row not overwritten", () => {
    db.query("INSERT INTO settings (key, value) VALUES ('sso', ?)").run(
      JSON.stringify({ enabled: false, issuer: "https://kept.example", client_id: "kept" })
    );
    process.env.GATEHOUSE_OAUTH_ISSUER = "https://idp.example";
    seedSsoFromEnv(db);
    const v = JSON.parse(
      (db.query("SELECT value FROM settings WHERE key = 'sso'").get() as any).value
    );
    expect(v.issuer).toBe("https://kept.example");
    expect(v.client_id).toBe("kept");
    expect(v.enabled).toBe(false);
  });
});
