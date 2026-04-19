import mysql from "mysql2/promise";
import type { DynamicProvider, DynamicCredential } from "./provider";
import { validateMySQLGrants } from "./grants";

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

    // Validate grants BEFORE touching the database - only allowlisted
    // privilege keywords may reach a GRANT statement.
    const validatedPrivileges = validateMySQLGrants(config.grants || "SELECT");
    const privList = validatedPrivileges.join(", ");

    try {
      const suffix = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
      const username = `gh_${sanitize(identity)}_${suffix}`;
      const password = crypto.randomUUID() + crypto.randomUUID().slice(0, 8);
      const database = config.database;
      const host = validateAllowedHost(config.allowed_host);

      // Create user - MySQL/MariaDB don't support parameterized placeholders
      // for user@host in DDL statements, so we use quoted identifiers.
      // Username is generated from sanitize() + UUID, host is validated.
      await conn.execute(
        `CREATE USER ${quoteString(username)}@${quoteString(host)} IDENTIFIED BY ${quoteString(password)}`
      );

      // Grant privileges on the database (privList validated above)
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
    // Only revoke users this provider created.
    const atIdx = revocationHandle.lastIndexOf("@");
    if (atIdx <= 0) {
      throw new Error(`MySQL: malformed revocation handle "${revocationHandle}"`);
    }
    const username = revocationHandle.slice(0, atIdx);
    const host = revocationHandle.slice(atIdx + 1);
    if (!/^gh_[a-zA-Z0-9_]{1,64}$/.test(username)) {
      throw new Error(
        `MySQL: refusing to revoke user with non-gatehouse handle "${username}"`
      );
    }
    // Re-validate host in case someone tampered with the stored handle.
    validateAllowedHost(host);

    const conn = await this.connect(config);

    try {

      // Kill active connections. KILL takes a numeric thread id and does
      // not accept placeholders on many MySQL versions - coerce to integer
      // defensively so nothing but digits ever touches the query string.
      const [rows] = await conn.execute(
        "SELECT ID FROM information_schema.processlist WHERE USER = ?",
        [username]
      ) as any;
      for (const row of rows) {
        const pid = Number.parseInt(String(row.ID), 10);
        if (Number.isFinite(pid) && pid > 0) {
          await conn.execute(`KILL ${pid}`).catch(() => {});
        }
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
    // TLS modes:
    //   ssl="true"      -> verify upstream cert (default strict)
    //   ssl="insecure"  -> TLS on, skip verification (homelab opt-in)
    //   otherwise       -> plaintext
    let ssl: any = undefined;
    if (config.ssl === "true") ssl = { rejectUnauthorized: true };
    else if (config.ssl === "insecure") ssl = { rejectUnauthorized: false };
    if (ssl && config.ssl_ca) ssl.ca = config.ssl_ca;

    return mysql.createConnection({
      host: config.host,
      port: parseInt(config.port || "3306"),
      database: config.database,
      user: config.user,
      password: config.password,
      connectTimeout: 10_000,
      ssl,
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

/**
 * Restrict allowed_host to characters that legitimately appear in a MySQL
 * host grant literal: letters, digits, `.`, `-`, `_`, `%`, `:`, `/` (for
 * CIDR), and the wildcard `%`. This prevents quote-escape tricks via a
 * tampered config even though quoteString should also contain them.
 */
function validateAllowedHost(host: string | undefined): string {
  const h = (host || "%").trim();
  if (!/^[a-zA-Z0-9._:\-\/%]{1,255}$/.test(h)) {
    throw new Error(
      `MySQL: allowed_host "${h}" contains invalid characters. Allowed: letters, digits, . - _ : / %`
    );
  }
  return h;
}
