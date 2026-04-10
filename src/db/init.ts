import { Database } from "bun:sqlite";
import { mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";

export function initDB(dataDir: string): Database {
  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true });
  }

  const dbPath = join(dataDir, "gatehouse.db");
  const db = new Database(dbPath, { create: true });

  // WAL mode for concurrent reads
  db.run("PRAGMA journal_mode = WAL");
  db.run("PRAGMA foreign_keys = ON");

  // Secrets table
  db.run(`
    CREATE TABLE IF NOT EXISTS secrets (
      path TEXT PRIMARY KEY,
      encrypted_value BLOB NOT NULL,
      nonce BLOB NOT NULL,
      encrypted_dek BLOB NOT NULL,
      dek_nonce BLOB NOT NULL,
      metadata TEXT DEFAULT '{}',
      version INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // Leases table
  db.run(`
    CREATE TABLE IF NOT EXISTS leases (
      id TEXT PRIMARY KEY,
      secret_path TEXT NOT NULL,
      identity TEXT NOT NULL,
      ttl_seconds INTEGER NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL,
      revoked INTEGER DEFAULT 0,
      FOREIGN KEY (secret_path) REFERENCES secrets(path)
    )
  `);

  // Audit log table
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT DEFAULT (datetime('now')),
      identity TEXT NOT NULL,
      action TEXT NOT NULL,
      path TEXT,
      lease_id TEXT,
      source_ip TEXT,
      metadata TEXT DEFAULT '{}',
      success INTEGER DEFAULT 1
    )
  `);

  // Auth tokens (AppRole)
  db.run(`
    CREATE TABLE IF NOT EXISTS app_roles (
      role_id TEXT PRIMARY KEY,
      secret_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      policies TEXT DEFAULT '[]',
      created_at TEXT DEFAULT (datetime('now')),
      last_used TEXT
    )
  `);

  // Policies table (UI-managed, supplements YAML-loaded policies)
  db.run(`
    CREATE TABLE IF NOT EXISTS policies (
      name TEXT PRIMARY KEY,
      rules TEXT NOT NULL DEFAULT '[]',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // Settings table (key-value store for runtime config like SSO)
  db.run(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // Users table (human admin accounts for managing the app)
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      email TEXT,
      role TEXT DEFAULT 'admin',
      enabled INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      last_login TEXT
    )
  `);

  // Dynamic secrets config (connection configs for dynamic providers, encrypted at rest)
  db.run(`
    CREATE TABLE IF NOT EXISTS dynamic_secrets (
      path TEXT PRIMARY KEY,
      provider_type TEXT NOT NULL,
      config BLOB NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // Dynamic leases (track temp credentials created by dynamic providers)
  db.run(`
    CREATE TABLE IF NOT EXISTS dynamic_leases (
      id TEXT PRIMARY KEY,
      path TEXT NOT NULL,
      identity TEXT NOT NULL,
      credential TEXT NOT NULL DEFAULT '{}',
      revocation_handle TEXT NOT NULL,
      provider_type TEXT NOT NULL,
      ttl_seconds INTEGER NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL,
      revoked INTEGER DEFAULT 0,
      FOREIGN KEY (path) REFERENCES dynamic_secrets(path)
    )
  `);

  // Proxy call patterns (learned from real proxy traffic)
  db.run(`
    CREATE TABLE IF NOT EXISTS proxy_patterns (
      id TEXT PRIMARY KEY,
      secret_path TEXT NOT NULL,
      method TEXT NOT NULL,
      url_template TEXT NOT NULL,
      host TEXT NOT NULL,
      request_headers TEXT DEFAULT '[]',
      request_body_schema TEXT DEFAULT NULL,
      response_status INTEGER DEFAULT 200,
      response_body_schema TEXT DEFAULT NULL,
      recent_outcomes TEXT DEFAULT '[]',
      agents TEXT DEFAULT '[]',
      total_successes INTEGER DEFAULT 0,
      total_failures INTEGER DEFAULT 0,
      pinned INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // Migrations: handle schema changes on existing databases
  const userCols = db.query("PRAGMA table_info(users)").all() as { name: string }[];
  const userColNames = userCols.map((c) => c.name);
  if (userColNames.length > 0 && !userColNames.includes("role")) {
    db.run("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'admin'");
  }

  // Indexes
  db.run(
    "CREATE INDEX IF NOT EXISTS idx_leases_expires ON leases(expires_at) WHERE revoked = 0"
  );
  db.run(
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)"
  );
  db.run("CREATE INDEX IF NOT EXISTS idx_audit_identity ON audit_log(identity)");
  db.run(
    "CREATE INDEX IF NOT EXISTS idx_dynamic_leases_expires ON dynamic_leases(expires_at) WHERE revoked = 0"
  );
  db.run(
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_patterns_lookup ON proxy_patterns(secret_path, method, url_template)"
  );
  db.run(
    "CREATE INDEX IF NOT EXISTS idx_patterns_secret ON proxy_patterns(secret_path)"
  );

  return db;
}
