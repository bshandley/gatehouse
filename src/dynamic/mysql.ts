import mysql from "mysql2/promise";
import type { DynamicProvider, DynamicCredential } from "./provider";

/**
 * MySQL / MariaDB Dynamic Secrets Provider
 *
 * Creates temporary MySQL users with random passwords and scoped grants.
 * On revoke, drops the user (which cascades all grants).
 *
 * Required config:
 *   host     - MySQL host
 *   port     - MySQL port (default: 3306)
 *   database - Database to grant access on
 *   user     - Admin username (must have CREATE USER and GRANT OPTION)
 *   password - Admin password
 *   grants   - Comma-separated list of privileges (default: "SELECT")
 */
export class MySQLProvider implements DynamicProvider {
  readonly type = "mysql";

  requiredConfig(): string[] {
    return ["host", "database", "user", "password"];
  }

  async create(
    config: Record<string, string>,
    identity: string,
    ttlSeconds: number
  ): Promise<DynamicCredential> {
    const conn = await this.connect(config);

    try {
      const suffix = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
      const username = `gh_${sanitize(identity)}_${suffix}`;
      const password = crypto.randomUUID() + crypto.randomUUID().slice(0, 8);
      const database = config.database;
      const grants = config.grants || "SELECT";
      const host = config.allowed_host || "%";

      // Create user — MySQL/MariaDB don't support parameterized placeholders
      // for user@host in DDL statements, so we use quoted identifiers.
      // Username is generated from sanitize() + UUID, host is from config.
      await conn.execute(
        `CREATE USER ${quoteString(username)}@${quoteString(host)} IDENTIFIED BY ${quoteString(password)}`
      );

      // Grant privileges on the database
      const privList = grants
        .split(",")
        .map((g) => g.trim().toUpperCase())
        .filter(Boolean)
        .join(", ");

      await conn.execute(
        `GRANT ${privList} ON ${quoteIdent(database)}.* TO ${quoteString(username)}@${quoteString(host)}`
      );

      await conn.execute("FLUSH PRIVILEGES");

      const port = config.port || "3306";
      const connectionString = `mysql://${username}:${password}@${config.host}:${port}/${database}`;

      return {
        credential: {
          username,
          password,
          host: config.host,
          port,
          database,
          connection_string: connectionString,
        },
        revocation_handle: `${username}@${host}`,
      };
    } finally {
      await conn.end();
    }
  }

  async revoke(
    config: Record<string, string>,
    revocationHandle: string
  ): Promise<void> {
    const conn = await this.connect(config);

    try {
      // Parse "username@host" from revocation handle
      const atIdx = revocationHandle.lastIndexOf("@");
      const username = revocationHandle.slice(0, atIdx);
      const host = revocationHandle.slice(atIdx + 1);

      // Kill active connections
      const [rows] = await conn.execute(
        "SELECT ID FROM information_schema.processlist WHERE USER = ?",
        [username]
      ) as any;
      for (const row of rows) {
        await conn.execute(`KILL ${row.ID}`).catch(() => {});
      }

      // Revoke all and drop
      await conn.execute(`REVOKE ALL PRIVILEGES, GRANT OPTION FROM ${quoteString(username)}@${quoteString(host)}`).catch(() => {});
      await conn.execute(`DROP USER IF EXISTS ${quoteString(username)}@${quoteString(host)}`);
      await conn.execute("FLUSH PRIVILEGES");
    } finally {
      await conn.end();
    }
  }

  async validate(
    config: Record<string, string>
  ): Promise<{ ok: boolean; error?: string }> {
    try {
      const conn = await this.connect(config);

      // Check that we have CREATE USER and GRANT OPTION
      const [rows] = await conn.execute("SHOW GRANTS FOR CURRENT_USER()") as any;
      await conn.end();

      const allGrants = rows.map((r: any) => Object.values(r)[0]).join(" ");
      if (
        allGrants.includes("ALL PRIVILEGES") ||
        (allGrants.includes("CREATE USER") && allGrants.includes("GRANT OPTION"))
      ) {
        return { ok: true };
      }

      return {
        ok: false,
        error: `User "${config.user}" needs CREATE USER and GRANT OPTION privileges`,
      };
    } catch (err: any) {
      return { ok: false, error: err.message };
    }
  }

  private async connect(config: Record<string, string>) {
    return mysql.createConnection({
      host: config.host,
      port: parseInt(config.port || "3306"),
      database: config.database,
      user: config.user,
      password: config.password,
      connectTimeout: 10_000,
      ssl: config.ssl === "true" ? { rejectUnauthorized: false } : undefined,
    });
  }
}

function sanitize(s: string): string {
  return s.replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 20);
}

function quoteIdent(s: string): string {
  return `\`${s.replace(/`/g, "``")}\``;
}

function quoteString(s: string): string {
  return `'${s.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
}
