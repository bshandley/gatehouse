import Redis from "ioredis";
import type { DynamicProvider, DynamicCredential } from "./provider";

/**
 * Redis Dynamic Secrets Provider
 *
 * Creates temporary Redis ACL users with scoped command and key permissions.
 * On revoke, deletes the ACL user (disconnecting active sessions).
 *
 * Requires Redis 6+ with ACL support.
 *
 * Required config:
 *   host     - Redis host
 *   port     - Redis port (default: 6379)
 *   password - Admin password (for AUTH)
 *   commands - Allowed commands (default: "+@read")
 *              Examples: "+@all", "+@read +@write", "+get +set +del"
 *   keys     - Key pattern access (default: "~*")
 *              Examples: "~myapp:*", "~cache:* ~session:*"
 */
export class RedisProvider implements DynamicProvider {
  readonly type = "redis";

  requiredConfig(): string[] {
    return ["host", "password"];
  }

  async create(
    config: Record<string, string>,
    identity: string,
    ttlSeconds: number
  ): Promise<DynamicCredential> {
    const client = this.connect(config);

    try {
      const suffix = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
      const username = `gh_${sanitize(identity)}_${suffix}`;
      const password = crypto.randomUUID() + crypto.randomUUID().slice(0, 8);

      const commands = config.commands || "+@read";
      const keys = config.keys || "~*";

      // Build ACL SETUSER command
      // Format: ACL SETUSER <username> on ><password> <commands> <keys>
      const aclArgs = [
        username,
        "on",
        `>${password}`,
        ...commands.split(/\s+/).filter(Boolean),
        ...keys.split(/\s+/).filter(Boolean),
      ];

      await client.call("ACL", "SETUSER", ...aclArgs);

      const port = config.port || "6379";
      const connectionString = `redis://${username}:${password}@${config.host}:${port}`;

      return {
        credential: {
          username,
          password,
          host: config.host,
          port,
          commands,
          keys,
          connection_string: connectionString,
        },
        revocation_handle: username,
      };
    } finally {
      client.disconnect();
    }
  }

  async revoke(
    config: Record<string, string>,
    revocationHandle: string
  ): Promise<void> {
    // Only revoke ACL users this provider created.
    if (!/^gh_[a-zA-Z0-9_]{1,64}$/.test(revocationHandle)) {
      throw new Error(
        `Redis: refusing to revoke user with non-gatehouse handle "${revocationHandle}"`
      );
    }
    const client = this.connect(config);
    const username = revocationHandle;

    try {
      // ACL DELUSER disconnects all clients authenticated as this user
      await client.call("ACL", "DELUSER", username);
    } finally {
      client.disconnect();
    }
  }

  async validate(
    config: Record<string, string>
  ): Promise<{ ok: boolean; error?: string }> {
    const client = this.connect(config);

    try {
      // Check connectivity
      const pong = await client.ping();
      if (pong !== "PONG") {
        return { ok: false, error: "Unexpected PING response" };
      }

      // Check ACL support (Redis 6+)
      try {
        await client.call("ACL", "WHOAMI");
      } catch {
        return { ok: false, error: "Redis server does not support ACL commands (requires Redis 6+)" };
      }

      return { ok: true };
    } catch (err: any) {
      return { ok: false, error: err.message };
    } finally {
      client.disconnect();
    }
  }

  private connect(config: Record<string, string>): Redis {
    // TLS modes:
    //   ssl="true"      -> TLS with cert verification (default strict)
    //   ssl="insecure"  -> TLS without cert verification (homelab opt-in)
    //   otherwise       -> plaintext
    let tls: any = undefined;
    if (config.ssl === "true") tls = { rejectUnauthorized: true };
    else if (config.ssl === "insecure") tls = { rejectUnauthorized: false };
    if (tls && config.ssl_ca) tls.ca = config.ssl_ca;

    return new Redis({
      host: config.host,
      port: parseInt(config.port || "6379"),
      password: config.password,
      db: parseInt(config.db || "0"),
      connectTimeout: 10_000,
      tls,
      lazyConnect: false,
    });
  }
}

function sanitize(s: string): string {
  return s.replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 20);
}
