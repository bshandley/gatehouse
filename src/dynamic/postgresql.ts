import { Client } from "pg";
import type { DynamicProvider, DynamicCredential } from "./provider";

/**
 * PostgreSQL Dynamic Secrets Provider
 *
 * Creates temporary PostgreSQL roles with random passwords and auto-expiry.
 * On revoke, drops the role and terminates any active connections.
 *
 * Required config:
 *   host     - PostgreSQL host
 *   port     - PostgreSQL port (default: 5432)
 *   database - Database name
 *   user     - Admin username (must have CREATEROLE privilege)
 *   password - Admin password
 *   grants   - Comma-separated list of database privileges (default: "SELECT")
 *   schema   - Schema to grant on (default: "public")
 */
export class PostgreSQLProvider implements DynamicProvider {
  readonly type = "postgresql";

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
      // Generate a unique role name and password
      const suffix = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
      const roleName = `gh_${sanitize(identity)}_${suffix}`;
      const password = crypto.randomUUID() + crypto.randomUUID().slice(0, 8);

      // Calculate expiry timestamp
      const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
      const validUntil = expiresAt.toISOString();

      const grants = (config.grants || "SELECT").toUpperCase();
      const schema = config.schema || "public";
      const database = config.database;

      // Create the role with login privilege and expiry
      await client.query(
        `CREATE ROLE ${quoteIdent(roleName)} WITH LOGIN PASSWORD ${quoteLiteral(password)} VALID UNTIL ${quoteLiteral(validUntil)}`
      );

      // Grant connect on the database
      await client.query(
        `GRANT CONNECT ON DATABASE ${quoteIdent(database)} TO ${quoteIdent(roleName)}`
      );

      // Grant usage on schema
      await client.query(
        `GRANT USAGE ON SCHEMA ${quoteIdent(schema)} TO ${quoteIdent(roleName)}`
      );

      // Grant table privileges
      // Parse grants like "SELECT,INSERT" into individual privileges
      const privileges = grants.split(",").map((g) => g.trim()).filter(Boolean);
      for (const priv of privileges) {
        await client.query(
          `GRANT ${priv} ON ALL TABLES IN SCHEMA ${quoteIdent(schema)} TO ${quoteIdent(roleName)}`
        );
      }

      // Also grant on future tables so the role works for newly created tables
      await client.query(
        `ALTER DEFAULT PRIVILEGES IN SCHEMA ${quoteIdent(schema)} GRANT ${grants} ON TABLES TO ${quoteIdent(roleName)}`
      );

      const port = config.port || "5432";
      const connectionString = `postgresql://${roleName}:${password}@${config.host}:${port}/${database}`;

      return {
        credential: {
          username: roleName,
          password,
          host: config.host,
          port,
          database,
          connection_string: connectionString,
        },
        revocation_handle: roleName,
      };
    } finally {
      await client.end();
    }
  }

  async revoke(
    config: Record<string, string>,
    revocationHandle: string
  ): Promise<void> {
    const client = await this.connect(config);
    const roleName = revocationHandle;

    try {
      // Terminate active connections by this role
      await client.query(
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = ${quoteLiteral(roleName)}`
      );

      const schema = config.schema || "public";
      const database = config.database;

      // Revoke all privileges
      await client.query(
        `REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ${quoteIdent(schema)} FROM ${quoteIdent(roleName)}`
      ).catch(() => {}); // ignore if already revoked

      await client.query(
        `REVOKE ALL PRIVILEGES ON DATABASE ${quoteIdent(database)} FROM ${quoteIdent(roleName)}`
      ).catch(() => {});

      await client.query(
        `REVOKE USAGE ON SCHEMA ${quoteIdent(schema)} FROM ${quoteIdent(roleName)}`
      ).catch(() => {});

      // Remove default privileges
      await client.query(
        `ALTER DEFAULT PRIVILEGES IN SCHEMA ${quoteIdent(schema)} REVOKE ALL ON TABLES FROM ${quoteIdent(roleName)}`
      ).catch(() => {});

      // Drop the role
      await client.query(`DROP ROLE IF EXISTS ${quoteIdent(roleName)}`);
    } finally {
      await client.end();
    }
  }

  async validate(
    config: Record<string, string>
  ): Promise<{ ok: boolean; error?: string }> {
    try {
      const client = await this.connect(config);
      // Check that we have CREATEROLE privilege
      const result = await client.query(
        "SELECT rolcreaterole FROM pg_roles WHERE rolname = current_user"
      );
      await client.end();

      if (result.rows.length === 0) {
        return { ok: false, error: "Could not determine user privileges" };
      }
      if (!result.rows[0].rolcreaterole) {
        return {
          ok: false,
          error: `User "${config.user}" does not have CREATEROLE privilege`,
        };
      }
      return { ok: true };
    } catch (err: any) {
      return { ok: false, error: err.message };
    }
  }

  private async connect(config: Record<string, string>): Promise<Client> {
    const client = new Client({
      host: config.host,
      port: parseInt(config.port || "5432"),
      database: config.database,
      user: config.user,
      password: config.password,
      connectionTimeoutMillis: 10_000,
      // Allow self-signed certs in homelab environments
      ssl: config.ssl === "true" ? { rejectUnauthorized: false } : false,
    });
    await client.connect();
    return client;
  }
}

/**
 * Sanitize an identity string for use in a PostgreSQL role name.
 * Only keeps alphanumeric and underscores, truncates to 20 chars.
 */
function sanitize(s: string): string {
  return s.replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 20);
}

/**
 * Quote a PostgreSQL identifier (table name, role name, etc.)
 * Uses double quotes and escapes any existing double quotes.
 */
function quoteIdent(s: string): string {
  return `"${s.replace(/"/g, '""')}"`;
}

/**
 * Quote a PostgreSQL string literal.
 * Uses single quotes and escapes any existing single quotes.
 */
function quoteLiteral(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}
