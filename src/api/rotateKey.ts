import { Hono } from "hono";
import type { GatehouseConfig } from "../config";
import type { SecretsEngine } from "../secrets/engine";
import type { DynamicSecretsManager } from "../dynamic/manager";
import type { PolicyEngine } from "../policy/engine";
import type { AuditLog } from "../audit/logger";
import {
  writeNextKeyFile,
  discardNextKeyFile,
  installNextKeyFile,
  fileStamp,
  NEXT_KEY_FILE_NAME,
} from "../backup/keyfile";
import { join } from "path";

const ENV_WARNING = "Update GATEHOUSE_MASTER_KEY env var to the new key before restarting";
const ENV_NOT_SAVED = "The new key is NOT saved to disk.";
const EXPORT_NOTE =
  "Exports taken before this rotation need the old key (or their own passphrase, for sealed exports). Take a fresh export now.";

/**
 * POST / : admin only. Re-wrap every secret DEK and dynamic config under a
 * new master key, and on key-file installs persist the new key crash-safely:
 *
 *   1. write master.key.next (abort with nothing changed if that fails)
 *   2. run the rotation transactions (remove master.key.next if nothing committed)
 *   3. keep master.key as master.key.pre-rotate-STAMP, move master.key.next into place
 *
 * On success config.masterKey is the new key, so every route that reads it
 * (key fingerprint, key verify) follows the rotation.
 */
export function rotateKeyRouter(deps: {
  secrets: SecretsEngine;
  dynamicSecrets: DynamicSecretsManager;
  policies: PolicyEngine;
  audit: AuditLog;
  config: GatehouseConfig;
  now?: () => Date;
}) {
  const { secrets, dynamicSecrets, policies, audit, config } = deps;
  const now = deps.now ?? (() => new Date());
  const router = new Hono();

  router.post("/", async (c) => {
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
    if (typeof new_master_key !== "string" || !/^[0-9a-fA-F]{64}$/.test(new_master_key)) {
      return c.json({
        error: "new_master_key must be exactly 64 hex characters (32 bytes, openssl rand -hex 32)",
        request_id: c.get("requestId"),
      }, 400);
    }

    const newKey = Buffer.from(new_master_key, "hex");
    const persist = config.masterKeySource === "file" || config.masterKeySource === "generated";
    const nextPath = join(config.dataDir, NEXT_KEY_FILE_NAME);

    // 1. The new key reaches disk before any data is re-wrapped under it.
    if (persist) {
      try {
        writeNextKeyFile(config.dataDir, newKey.toString("hex"));
      } catch (err: any) {
        return c.json({
          error: `Rotation aborted: could not write the new key to ${nextPath} (${err?.message ?? err}). Nothing was changed.`,
          request_id: c.get("requestId"),
        }, 500);
      }
    }

    // 2. The rotation itself: two transactions, unchanged.
    let secretsRotated: number;
    try {
      secretsRotated = secrets.rotateKEK(newKey);
    } catch (err: any) {
      // Nothing committed: the old key still decrypts everything.
      if (persist) discardNextKeyFile(config.dataDir);
      return c.json({ error: `Rotation failed: ${err.message}`, request_id: c.get("requestId") }, 500);
    }
    let dynamicRotated: number;
    try {
      dynamicRotated = dynamicSecrets.rotateConfigKey(newKey);
    } catch (err: any) {
      // Secrets are already under the new key, dynamic configs are not. Keep
      // master.key.next: it is the only on-disk copy of the key the secrets need.
      const where = persist
        ? ` The new key is kept in ${nextPath}; master.key still holds the old key.`
        : "";
      return c.json({
        error:
          `Rotation failed partway: secrets were re-wrapped under the new key but dynamic configs were not (${err.message}).` +
          where +
          " Retry the rotation with the same new key before restarting the server.",
        request_id: c.get("requestId"),
      }, 500);
    }
    config.masterKey = newKey;

    // 3. Swap the key file.
    let keyPersistedTo: string | null = null;
    let previousKeyKeptAs: string | null = null;
    let warning: string | undefined;
    let message: string;
    if (persist) {
      try {
        const r = installNextKeyFile(config.dataDir, fileStamp(now()));
        keyPersistedTo = r.keyPath;
        previousKeyKeptAs = r.previous;
        config.masterKeySource = "file";
        message =
          `New key saved to ${r.keyPath}.` +
          (r.previous ? ` The previous key is kept as ${r.previous}.` : "") +
          ` ${EXPORT_NOTE}`;
      } catch (err: any) {
        keyPersistedTo = null;
        warning = `The data is rotated but the key file was not updated: ${err?.message ?? err}`;
        message = `${warning} ${EXPORT_NOTE}`;
      }
    } else {
      warning = ENV_WARNING;
      message = `${ENV_NOT_SAVED} ${EXPORT_NOTE}`;
    }

    audit.log({
      identity: auth.identity,
      action: "admin.key_rotation",
      metadata: {
        secrets_rotated: String(secretsRotated),
        dynamic_configs_rotated: String(dynamicRotated),
        key_persisted: keyPersistedTo ? "file" : "no",
      },
      source_ip: c.get("sourceIp"),
    });

    return c.json({
      rotated: true,
      secrets_rewrapped: secretsRotated,
      dynamic_configs_rewrapped: dynamicRotated,
      key_persisted_to: keyPersistedTo,
      previous_key_kept_as: previousKeyKeptAs,
      message,
      ...(warning ? { warning } : {}),
    });
  });

  return router;
}
