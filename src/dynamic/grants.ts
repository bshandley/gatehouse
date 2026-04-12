/**
 * Privilege allowlists for dynamic secret GRANT statements.
 *
 * DDL like `GRANT {priv}` cannot be parameterized in PostgreSQL or
 * MySQL/MariaDB, so the privilege tokens are interpolated. To prevent SQL
 * injection we accept only a fixed set of known privilege keywords.
 *
 * Each provider calls validateGrants with its own allowlist before any
 * grant string touches a query. Unknown tokens throw synchronously.
 */

const POSTGRESQL_PRIVILEGES = new Set([
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE",
  "TRUNCATE",
  "REFERENCES",
  "TRIGGER",
  "ALL",
  "ALL PRIVILEGES",
]);

const MYSQL_PRIVILEGES = new Set([
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE",
  "CREATE",
  "DROP",
  "INDEX",
  "ALTER",
  "CREATE TEMPORARY TABLES",
  "LOCK TABLES",
  "EXECUTE",
  "CREATE VIEW",
  "SHOW VIEW",
  "CREATE ROUTINE",
  "ALTER ROUTINE",
  "EVENT",
  "TRIGGER",
  "REFERENCES",
  "ALL",
  "ALL PRIVILEGES",
]);

/**
 * Parse a comma-separated grants string, uppercase each token, reject any
 * token that isn't in the allowlist. Returns the normalized tokens.
 */
function validateAgainst(
  grants: string,
  allowed: Set<string>,
  label: string
): string[] {
  const tokens = (grants || "")
    .split(",")
    .map((g) => g.trim().toUpperCase())
    .filter(Boolean);

  if (tokens.length === 0) {
    throw new Error(`${label}: grants must contain at least one privilege`);
  }

  for (const t of tokens) {
    if (!allowed.has(t)) {
      throw new Error(
        `${label}: privilege "${t}" is not in the allowlist. Allowed: ${[...allowed].join(", ")}`
      );
    }
  }
  return tokens;
}

export function validatePostgresGrants(grants: string): string[] {
  return validateAgainst(grants, POSTGRESQL_PRIVILEGES, "PostgreSQL");
}

export function validateMySQLGrants(grants: string): string[] {
  return validateAgainst(grants, MYSQL_PRIVILEGES, "MySQL");
}

export const POSTGRESQL_ALLOWED_PRIVILEGES = [...POSTGRESQL_PRIVILEGES];
export const MYSQL_ALLOWED_PRIVILEGES = [...MYSQL_PRIVILEGES];
