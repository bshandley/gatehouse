import { Hono } from "hono";
import { Database } from "bun:sqlite";
import QRCode from "qrcode";
import type { AuditLog } from "../audit/logger";
import {
  generateTotpSecret,
  verifyTotp,
  buildOtpauthUri,
  generateRecoveryCodes,
  hashRecoveryCode,
} from "../auth/totp";

/**
 * Self-service user routes — operate on the currently-authenticated user.
 * All endpoints here require a full access JWT (the auth middleware is
 * applied at the /v1 mount, so it rejects totp-pending tokens and AppRoles
 * via the identity check below).
 */
export function meRouter(db: Database, audit: AuditLog) {
  const router = new Hono();

  /**
   * Only human user accounts (not AppRoles) can manage their own TOTP here.
   * AppRoles authenticate with role_id + secret_id, not passwords — no 2FA.
   */
  function requireUser(c: any): { username: string } | null {
    const auth = c.get("auth") as { identity: string };
    if (!auth?.identity?.startsWith("user:")) return null;
    return { username: auth.identity.slice(5) };
  }

  /**
   * GET /v1/me/totp
   * Returns whether TOTP is enabled for the current user.
   */
  router.get("/totp", (c) => {
    const u = requireUser(c);
    if (!u) return c.json({ error: "Only user accounts can manage TOTP", request_id: c.get("requestId") }, 403);

    const row = db
      .query("SELECT totp_enabled, totp_recovery_codes FROM users WHERE username = ?")
      .get(u.username) as any;
    const codes = row?.totp_recovery_codes ? JSON.parse(row.totp_recovery_codes) : [];
    return c.json({
      enabled: !!row?.totp_enabled,
      recovery_codes_remaining: codes.length,
    });
  });

  /**
   * POST /v1/me/totp/setup
   * Generates a candidate secret (stored pending) and returns the otpauth URI
   * and raw secret so the user can add it to their authenticator app.
   * The secret is NOT activated until /v1/me/totp/verify succeeds.
   */
  router.post("/totp/setup", async (c) => {
    const u = requireUser(c);
    if (!u) return c.json({ error: "Only user accounts can manage TOTP", request_id: c.get("requestId") }, 403);

    const user = db
      .query("SELECT username, display_name, totp_enabled FROM users WHERE username = ?")
      .get(u.username) as any;
    if (!user) return c.json({ error: "User not found", request_id: c.get("requestId") }, 404);

    if (user.totp_enabled) {
      return c.json(
        { error: "TOTP is already enabled. Disable it first to re-enroll.", request_id: c.get("requestId") },
        409
      );
    }

    const secret = generateTotpSecret();
    // Store the candidate secret but keep enabled = 0 until verified
    db.query("UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE username = ?").run(
      secret,
      u.username
    );

    const uri = buildOtpauthUri({
      secret,
      accountName: u.username,
      issuer: "Gatehouse",
    });

    // Render the QR code server-side so the raw TOTP secret never leaves
    // the Gatehouse host. Returned as a base64 PNG data URI so the UI can
    // set it as <img src> under the existing img-src 'self' data: CSP.
    const qrDataUri = await QRCode.toDataURL(uri, {
      errorCorrectionLevel: "M",
      margin: 1,
      width: 240,
      color: { dark: "#0a0a0f", light: "#e8e6e3" },
    });

    return c.json({
      secret,
      otpauth_uri: uri,
      qr_data_uri: qrDataUri,
      issuer: "Gatehouse",
      account: u.username,
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    });
  });

  /**
   * POST /v1/me/totp/verify
   * Confirms the user's authenticator is correctly set up, flips totp_enabled
   * to 1, and returns 10 one-time recovery codes. The recovery codes are only
   * shown this once.
   */
  router.post("/totp/verify", async (c) => {
    const u = requireUser(c);
    if (!u) return c.json({ error: "Only user accounts can manage TOTP", request_id: c.get("requestId") }, 403);

    let body: { code: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }
    if (!body.code) {
      return c.json({ error: "code is required", request_id: c.get("requestId") }, 400);
    }

    const user = db
      .query("SELECT totp_secret, totp_enabled FROM users WHERE username = ?")
      .get(u.username) as any;
    if (!user?.totp_secret) {
      return c.json({ error: "No pending TOTP setup. Call /totp/setup first.", request_id: c.get("requestId") }, 400);
    }

    if (!verifyTotp(user.totp_secret, body.code)) {
      return c.json({ error: "Invalid TOTP code", request_id: c.get("requestId") }, 401);
    }

    // Generate recovery codes and store their hashes
    const recoveryCodes = generateRecoveryCodes(10);
    const hashes = await Promise.all(recoveryCodes.map(hashRecoveryCode));

    db.query(
      "UPDATE users SET totp_enabled = 1, totp_recovery_codes = ?, updated_at = datetime('now') WHERE username = ?"
    ).run(JSON.stringify(hashes), u.username);

    audit.log({
      identity: `user:${u.username}`,
      action: "user.totp.enable",
      source_ip: c.get("sourceIp"),
    });

    return c.json({
      enabled: true,
      recovery_codes: recoveryCodes,
      warning: "Save these recovery codes now. They will not be shown again.",
    });
  });

  /**
   * DELETE /v1/me/totp
   * Disables TOTP for the current user. Requires the current password so that
   * a hijacked session can't silently turn off 2FA.
   */
  router.delete("/totp", async (c) => {
    const u = requireUser(c);
    if (!u) return c.json({ error: "Only user accounts can manage TOTP", request_id: c.get("requestId") }, 403);

    let body: { password: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }
    if (!body.password) {
      return c.json({ error: "password is required to disable TOTP", request_id: c.get("requestId") }, 400);
    }

    const user = db
      .query("SELECT password_hash, totp_enabled FROM users WHERE username = ?")
      .get(u.username) as any;
    if (!user) return c.json({ error: "User not found", request_id: c.get("requestId") }, 404);

    const valid = await Bun.password.verify(body.password, user.password_hash);
    if (!valid) {
      return c.json({ error: "Invalid password", request_id: c.get("requestId") }, 401);
    }

    db.query(
      "UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_recovery_codes = NULL, updated_at = datetime('now') WHERE username = ?"
    ).run(u.username);

    audit.log({
      identity: `user:${u.username}`,
      action: "user.totp.disable",
      source_ip: c.get("sourceIp"),
    });

    return c.json({ disabled: true });
  });

  /**
   * POST /v1/me/totp/recovery-codes/regenerate
   * Replaces the existing recovery codes with a fresh set. Requires password.
   */
  router.post("/totp/recovery-codes/regenerate", async (c) => {
    const u = requireUser(c);
    if (!u) return c.json({ error: "Only user accounts can manage TOTP", request_id: c.get("requestId") }, 403);

    let body: { password: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }
    if (!body.password) {
      return c.json({ error: "password is required", request_id: c.get("requestId") }, 400);
    }

    const user = db
      .query("SELECT password_hash, totp_enabled FROM users WHERE username = ?")
      .get(u.username) as any;
    if (!user) return c.json({ error: "User not found", request_id: c.get("requestId") }, 404);
    if (!user.totp_enabled) {
      return c.json({ error: "TOTP is not enabled", request_id: c.get("requestId") }, 400);
    }

    const valid = await Bun.password.verify(body.password, user.password_hash);
    if (!valid) {
      return c.json({ error: "Invalid password", request_id: c.get("requestId") }, 401);
    }

    const recoveryCodes = generateRecoveryCodes(10);
    const hashes = await Promise.all(recoveryCodes.map(hashRecoveryCode));
    db.query("UPDATE users SET totp_recovery_codes = ? WHERE username = ?").run(
      JSON.stringify(hashes),
      u.username
    );

    audit.log({
      identity: `user:${u.username}`,
      action: "user.totp.recovery_regenerate",
      source_ip: c.get("sourceIp"),
    });

    return c.json({
      recovery_codes: recoveryCodes,
      warning: "Save these recovery codes now. They will not be shown again.",
    });
  });

  return router;
}
