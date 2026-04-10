import type { Database } from "bun:sqlite";
import type { DynamicProvider, DynamicCredential } from "./provider";
import type { AuditLog } from "../audit/logger";
import { PostgreSQLProvider } from "./postgresql";
import { MySQLProvider } from "./mysql";
import { MongoDBProvider } from "./mongodb";
import { RedisProvider } from "./redis";
import { SSHCertProvider } from "./ssh";
import nacl from "tweetnacl";
import { deriveKey } from "../secrets/engine";

export interface DynamicSecretConfig {
  path: string;
  provider_type: string;
  config: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface DynamicLease {
  lease_id: string;
  path: string;
  identity: string;
  credential: Record<string, string>;
  revocation_handle: string;
  provider_type: string;
  ttl_seconds: number;
  created_at: string;
  expires_at: string;
}

/**
 * Dynamic Secrets Manager
 *
 * Manages the lifecycle of dynamic secrets:
 * 1. Admin configures a connection (e.g. PostgreSQL admin creds)
 * 2. Agent requests a lease → manager calls provider.create()
 * 3. On lease expiry/revoke → manager calls provider.revoke()
 *
 * Dynamic secret configs are encrypted at rest using a dedicated key
 * derived from the master key via HKDF. Dynamic leases are tracked
 * in a separate table so the reaper can clean them up.
 */
export class DynamicSecretsManager {
  private db: Database;
  private audit: AuditLog;
  private providers: Map<string, DynamicProvider> = new Map();
  private reaperTimer: ReturnType<typeof setInterval> | null = null;
  private configKey: Uint8Array; // 32-byte key for encrypting dynamic configs

  constructor(db: Database, audit: AuditLog, masterKey?: Buffer) {
    this.db = db;

    // Derive a dedicated encryption key for dynamic configs
    if (masterKey) {
      this.configKey = deriveKey(masterKey, "gatehouse-dynamic-config");
    } else {
      // Test mode — use a zero key (tests that don't pass masterKey get plaintext)
      this.configKey = new Uint8Array(32);
    }

    // Register built-in providers
    this.registerProvider(new PostgreSQLProvider());
    this.registerProvider(new MySQLProvider());
    this.registerProvider(new MongoDBProvider());
    this.registerProvider(new RedisProvider());
    this.registerProvider(new SSHCertProvider());

    this.audit = audit;
  }

  private encryptConfig(config: Record<string, string>): Buffer {
    const plaintext = new TextEncoder().encode(JSON.stringify(config));
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const ciphertext = nacl.secretbox(plaintext, nonce, this.configKey);
    // Store as nonce + ciphertext concatenated
    const combined = new Uint8Array(nonce.length + ciphertext.length);
    combined.set(nonce);
    combined.set(ciphertext, nonce.length);
    return Buffer.from(combined);
  }

  private decryptConfig(data: Buffer | Uint8Array): Record<string, string> {
    const bytes = new Uint8Array(data);
    const nonceLen = nacl.secretbox.nonceLength;

    // If the data looks like valid JSON, it's a legacy plaintext config — migrate it
    try {
      const text = new TextDecoder().decode(bytes);
      const parsed = JSON.parse(text);
      if (typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch {
      // Not JSON — proceed with decryption
    }

    const nonce = bytes.slice(0, nonceLen);
    const ciphertext = bytes.slice(nonceLen);
    const plaintext = nacl.secretbox.open(ciphertext, nonce, this.configKey);
    if (!plaintext) {
      throw new Error("Failed to decrypt dynamic secret config");
    }
    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  registerProvider(provider: DynamicProvider) {
    this.providers.set(provider.type, provider);
  }

  getProviderTypes(): string[] {
    return Array.from(this.providers.keys());
  }

  getProvider(type: string): DynamicProvider | undefined {
    return this.providers.get(type);
  }

  /**
   * Store a dynamic secret configuration.
   * The config contains admin/connection credentials for the provider.
   */
  saveConfig(
    path: string,
    providerType: string,
    config: Record<string, string>
  ): DynamicSecretConfig {
    const provider = this.providers.get(providerType);
    if (!provider) {
      throw new Error(`Unknown provider type: ${providerType}`);
    }

    // Validate required config keys
    const missing = provider.requiredConfig().filter((k) => !config[k]);
    if (missing.length > 0) {
      throw new Error(
        `Missing required config keys for ${providerType}: ${missing.join(", ")}`
      );
    }

    const encryptedConfig = this.encryptConfig(config);

    this.db
      .query(
        `INSERT INTO dynamic_secrets (path, provider_type, config)
         VALUES (?, ?, ?)
         ON CONFLICT(path) DO UPDATE SET
           provider_type = excluded.provider_type,
           config = excluded.config,
           updated_at = datetime('now')`
      )
      .run(path, providerType, encryptedConfig);

    return this.getConfig(path)!;
  }

  getConfig(path: string): DynamicSecretConfig | null {
    const row = this.db
      .query(
        "SELECT path, provider_type, config, created_at, updated_at FROM dynamic_secrets WHERE path = ?"
      )
      .get(path) as any;

    if (!row) return null;

    return {
      path: row.path,
      provider_type: row.provider_type,
      config: this.decryptConfig(row.config),
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  listConfigs(prefix: string = ""): Omit<DynamicSecretConfig, "config">[] {
    const rows = this.db
      .query(
        "SELECT path, provider_type, created_at, updated_at FROM dynamic_secrets WHERE path LIKE ? ORDER BY path"
      )
      .all(`${prefix}%`) as any[];

    return rows.map((r) => ({
      path: r.path,
      provider_type: r.provider_type,
      created_at: r.created_at,
      updated_at: r.updated_at,
    }));
  }

  async deleteConfig(path: string): Promise<boolean> {
    // Revoke all active dynamic leases for this path first
    const activeLeases = this.listActiveLeases(path);
    for (const lease of activeLeases) {
      await this.revokeLease(lease.lease_id, "system:config-delete").catch(() => {});
    }

    // Also force-delete any remaining lease rows (revoked or not) to satisfy FK
    this.db
      .query("DELETE FROM dynamic_leases WHERE path = ?")
      .run(path);

    const result = this.db
      .query("DELETE FROM dynamic_secrets WHERE path = ?")
      .run(path);
    return result.changes > 0;
  }

  /**
   * Create a dynamic credential via the configured provider.
   * Returns the temporary credential + a lease tracking it.
   */
  async checkout(
    path: string,
    identity: string,
    ttlSeconds: number
  ): Promise<DynamicLease | null> {
    const config = this.getConfig(path);
    if (!config) return null;

    const provider = this.providers.get(config.provider_type);
    if (!provider) {
      throw new Error(`Provider not registered: ${config.provider_type}`);
    }

    // Create the dynamic credential
    const result = await provider.create(
      config.config,
      identity,
      ttlSeconds
    );

    // Store the dynamic lease
    const leaseId = `dlease-${crypto.randomUUID()}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

    // Encrypt credentials at rest
    const encryptedCred = this.encryptConfig(result.credential);

    this.db
      .query(
        `INSERT INTO dynamic_leases
         (id, path, identity, credential, revocation_handle, provider_type, ttl_seconds, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        leaseId,
        path,
        identity,
        encryptedCred,
        result.revocation_handle,
        config.provider_type,
        ttlSeconds,
        expiresAt.toISOString().replace("T", " ").slice(0, 19)
      );

    this.audit.log({
      identity,
      action: "dynamic.checkout",
      path,
      lease_id: leaseId,
      metadata: {
        provider: config.provider_type,
        ttl: String(ttlSeconds),
      },
    });

    const lease = this.getLease(leaseId);
    return lease;
  }

  getLease(leaseId: string): DynamicLease | null {
    const row = this.db
      .query(
        `SELECT id, path, identity, credential, revocation_handle, provider_type,
                ttl_seconds, created_at, expires_at
         FROM dynamic_leases
         WHERE id = ? AND revoked = 0`
      )
      .get(leaseId) as any;

    if (!row) return null;

    return {
      lease_id: row.id,
      path: row.path,
      identity: row.identity,
      credential: this.decryptConfig(row.credential),
      revocation_handle: row.revocation_handle,
      provider_type: row.provider_type,
      ttl_seconds: row.ttl_seconds,
      created_at: row.created_at,
      expires_at: row.expires_at,
    };
  }

  listActiveLeases(path?: string): DynamicLease[] {
    let sql = `SELECT id, path, identity, credential, revocation_handle, provider_type,
                      ttl_seconds, created_at, expires_at
               FROM dynamic_leases
               WHERE revoked = 0 AND expires_at > datetime('now')`;
    const params: any[] = [];

    if (path) {
      sql += " AND path = ?";
      params.push(path);
    }

    sql += " ORDER BY created_at DESC";

    const rows = this.db.query(sql).all(...params) as any[];

    return rows.map((r) => ({
      lease_id: r.id,
      path: r.path,
      identity: r.identity,
      credential: this.decryptConfig(r.credential),
      revocation_handle: r.revocation_handle,
      provider_type: r.provider_type,
      ttl_seconds: r.ttl_seconds,
      created_at: r.created_at,
      expires_at: r.expires_at,
    }));
  }

  /**
   * Revoke a dynamic lease — calls the provider to destroy the credential.
   */
  async revokeLease(leaseId: string, identity: string): Promise<boolean> {
    const lease = this.getLease(leaseId);
    if (!lease) return false;

    const config = this.getConfig(lease.path);
    if (config) {
      const provider = this.providers.get(lease.provider_type);
      if (provider) {
        try {
          await provider.revoke(config.config, lease.revocation_handle);
        } catch (err: any) {
          // Log the failure but still mark as revoked locally
          this.audit.log({
            identity,
            action: "dynamic.revoke.error",
            path: lease.path,
            lease_id: leaseId,
            metadata: { error: err.message },
            success: false,
          });
          console.error(
            `[gatehouse:dynamic] Failed to revoke credential at provider: ${err.message}`
          );
        }
      }
    }

    // Mark as revoked and scrub credential data from DB
    this.db
      .query("UPDATE dynamic_leases SET revoked = 1, credential = '{}' WHERE id = ?")
      .run(leaseId);

    this.audit.log({
      identity,
      action: "dynamic.revoke",
      path: lease.path,
      lease_id: leaseId,
      metadata: { provider: lease.provider_type },
    });

    return true;
  }

  /**
   * Reap expired dynamic leases — calls providers to clean up credentials.
   */
  async reapExpired(): Promise<number> {
    const expired = this.db
      .query(
        `SELECT id FROM dynamic_leases
         WHERE revoked = 0 AND expires_at <= datetime('now')`
      )
      .all() as { id: string }[];

    let count = 0;
    for (const { id } of expired) {
      try {
        await this.revokeLease(id, "system:reaper");
        count++;
      } catch (err: any) {
        console.error(
          `[gatehouse:dynamic] Reaper failed to revoke ${id}: ${err.message}`
        );
      }
    }

    if (count > 0) {
      this.audit.log({
        identity: "system:reaper",
        action: "dynamic.reap",
        metadata: { expired_count: String(count) },
      });
    }

    return count;
  }

  /**
   * Start the periodic reaper for dynamic leases.
   */
  startReaper(intervalMs: number) {
    this.reaperTimer = setInterval(() => this.reapExpired(), intervalMs);
  }

  stopReaper() {
    if (this.reaperTimer) {
      clearInterval(this.reaperTimer);
      this.reaperTimer = null;
    }
  }

  /**
   * Validate a dynamic secret config against its provider.
   */
  async validateConfig(
    path: string
  ): Promise<{ ok: boolean; error?: string }> {
    const config = this.getConfig(path);
    if (!config) return { ok: false, error: "Config not found" };

    const provider = this.providers.get(config.provider_type);
    if (!provider) return { ok: false, error: "Provider not registered" };

    return provider.validate(config.config);
  }

  /**
   * Re-encrypt all dynamic secret configs with a new master key.
   * Called during key rotation.
   */
  rotateConfigKey(newMasterKey: Buffer): number {
    const rows = this.db
      .query("SELECT path, config FROM dynamic_secrets")
      .all() as { path: string; config: Buffer | Uint8Array }[];

    const newConfigKey = deriveKey(newMasterKey, "gatehouse-dynamic-config");
    let count = 0;

    for (const row of rows) {
      // Decrypt with current key
      const config = this.decryptConfig(row.config);

      // Re-encrypt with new key
      const plaintext = new TextEncoder().encode(JSON.stringify(config));
      const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
      const ciphertext = nacl.secretbox(plaintext, nonce, newConfigKey);
      const combined = new Uint8Array(nonce.length + ciphertext.length);
      combined.set(nonce);
      combined.set(ciphertext, nonce.length);

      this.db
        .query("UPDATE dynamic_secrets SET config = ?, updated_at = datetime('now') WHERE path = ?")
        .run(Buffer.from(combined), row.path);

      count++;
    }

    // Switch to new key
    this.configKey = newConfigKey;
    return count;
  }
}
