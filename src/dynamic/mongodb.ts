import { MongoClient } from "mongodb";
import type { DynamicProvider, DynamicCredential } from "./provider";

/**
 * MongoDB Dynamic Secrets Provider
 *
 * Creates temporary MongoDB users with scoped roles on a database.
 * On revoke, drops the user.
 *
 * Required config:
 *   host     - MongoDB host (or replica set URI)
 *   port     - MongoDB port (default: 27017)
 *   database - Database to create the user on (and default auth source)
 *   user     - Admin username (must have userAdmin or userAdminAnyDatabase role)
 *   password - Admin password
 *   roles    - Comma-separated MongoDB roles (default: "read")
 *              e.g. "read", "readWrite", "dbAdmin", "readWrite,dbAdmin"
 */
export class MongoDBProvider implements DynamicProvider {
  readonly type = "mongodb";

  requiredConfig(): string[] {
    return ["host", "database", "user", "password"];
  }

  async create(
    config: Record<string, string>,
    identity: string,
    ttlSeconds: number
  ): Promise<DynamicCredential> {
    const client = await this.connect(config);

    try {
      const suffix = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
      const username = `gh_${sanitize(identity)}_${suffix}`;
      const password = crypto.randomUUID() + crypto.randomUUID().slice(0, 8);
      const database = config.database;

      // Parse roles - each role is scoped to the target database
      const roleNames = (config.roles || "read")
        .split(",")
        .map((r) => r.trim())
        .filter(Boolean);
      const roles = roleNames.map((role) => ({ role, db: database }));

      const db = client.db(database);
      await db.command({
        createUser: username,
        pwd: password,
        roles,
      });

      const port = config.port || "27017";
      const connectionString = `mongodb://${username}:${password}@${config.host}:${port}/${database}?authSource=${database}`;

      return {
        credential: {
          username,
          password,
          host: config.host,
          port,
          database,
          roles: roleNames.join(","),
          connection_string: connectionString,
        },
        revocation_handle: `${database}:${username}`,
      };
    } finally {
      await client.close();
    }
  }

  async revoke(
    config: Record<string, string>,
    revocationHandle: string
  ): Promise<void> {
    const [database, username] = revocationHandle.split(":", 2);
    if (!username || !/^gh_[a-zA-Z0-9_]{1,64}$/.test(username)) {
      throw new Error(
        `MongoDB: refusing to revoke user with non-gatehouse handle "${username}"`
      );
    }

    const client = await this.connect(config);

    try {
      const db = client.db(database);

      // Kill user sessions
      try {
        const adminDb = client.db("admin");
        const currentOps = await adminDb.command({
          currentOp: true,
          $all: true,
        }).catch(() => ({ inprog: [] }));

        for (const op of currentOps.inprog || []) {
          if (op.effectiveUsers?.some((u: any) => u.user === username && u.db === database)) {
            await adminDb.command({ killOp: 1, op: op.opid }).catch(() => {});
          }
        }
      } catch {
        // Non-critical - session cleanup is best-effort
      }

      await db.command({ dropUser: username });
    } finally {
      await client.close();
    }
  }

  async validate(
    config: Record<string, string>
  ): Promise<{ ok: boolean; error?: string }> {
    try {
      const client = await this.connect(config);
      const db = client.db(config.database);

      // Check that we can administer users
      const result = await db.command({ usersInfo: config.user });
      await client.close();

      if (!result.users || result.users.length === 0) {
        return { ok: false, error: "Could not look up admin user info" };
      }

      const adminRoles = result.users[0].roles || [];
      const hasUserAdmin = adminRoles.some(
        (r: any) =>
          r.role === "userAdmin" ||
          r.role === "userAdminAnyDatabase" ||
          r.role === "root"
      );

      if (!hasUserAdmin) {
        return {
          ok: false,
          error: `User "${config.user}" needs userAdmin or userAdminAnyDatabase role`,
        };
      }

      return { ok: true };
    } catch (err: any) {
      return { ok: false, error: err.message };
    }
  }

  private async connect(config: Record<string, string>): Promise<MongoClient> {
    const port = config.port || "27017";
    const authSource = config.auth_source || config.database || "admin";
    // TLS modes:
    //   ssl="true"      -> TLS with cert verification (default strict)
    //   ssl="insecure"  -> TLS without cert verification (homelab opt-in)
    //   otherwise       -> plaintext
    let tlsParams = "";
    if (config.ssl === "true") {
      tlsParams = "&tls=true";
    } else if (config.ssl === "insecure") {
      tlsParams = "&tls=true&tlsAllowInvalidCertificates=true";
    }
    const uri = `mongodb://${encodeURIComponent(config.user)}:${encodeURIComponent(config.password)}@${config.host}:${port}/${config.database}?authSource=${authSource}${tlsParams}`;

    const client = new MongoClient(uri, {
      connectTimeoutMS: 10_000,
      serverSelectionTimeoutMS: 10_000,
    });
    await client.connect();
    return client;
  }
}

function sanitize(s: string): string {
  return s.replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 20);
}
