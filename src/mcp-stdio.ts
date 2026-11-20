#!/usr/bin/env bun
/**
 * Gatehouse MCP stdio transport.
 *
 * Run as a local MCP server for Claude Code, Codex, OpenClaw, etc.
 * The agent harness launches this process and communicates via stdin/stdout.
 *
 * It reads the master key from GATEHOUSE_MASTER_KEY or the data dir's
 * master.key, and never generates one: it will not create a new vault.
 * The token comes from GATEHOUSE_TOKEN (or the first argument).
 *
 * Usage:
 *   GATEHOUSE_TOKEN=... bunx gatehouse-mcp
 *
 * Or via the Docker image, against the server's data volume:
 *   docker run --rm -i -v gatehouse-data:/data -e GATEHOUSE_TOKEN gatehouse:latest mcp
 */

import { initDB } from "./db/init";
import { SecretsEngine } from "./secrets/engine";
import { LeaseManager } from "./lease/manager";
import { PolicyEngine } from "./policy/engine";
import { AuditLog } from "./audit/logger";
import { DynamicSecretsManager } from "./dynamic/manager";
import { runStdioTransport } from "./mcp/server";
import { loadConfig } from "./config";
import { MasterKeyError } from "./backup/keyfile";
import { type AuthContext, safeEqual } from "./auth/middleware";

let config: ReturnType<typeof loadConfig>;
try {
  config = loadConfig({ allowGenerate: false });
} catch (e) {
  if (!(e instanceof MasterKeyError)) throw e;
  console.error(`[gatehouse:mcp] ${e.message}`);
  process.exit(1);
}
const db = initDB(config.dataDir);
const audit = new AuditLog(db);
const secrets = new SecretsEngine(db, config.masterKey);
const policies = new PolicyEngine(config.configDir);
const leases = new LeaseManager(db, secrets, audit);
const dynamicSecrets = new DynamicSecretsManager(db, audit, config.masterKey);

// Resolve identity from token or env
const token = process.env.GATEHOUSE_TOKEN || process.argv[2];
const rootToken = process.env.GATEHOUSE_ROOT_TOKEN;

let auth: AuthContext;

if (rootToken && token && token.length === rootToken.length && safeEqual(token, rootToken)) {
  auth = { identity: "root", policies: ["admin"], source: "root" };
} else {
  // Look up AppRole by token (simplified for stdio - in production, verify JWT)
  const identity = process.env.GATEHOUSE_IDENTITY || "mcp-agent";
  const policyList = (process.env.GATEHOUSE_POLICIES || "admin").split(",");
  auth = { identity, policies: policyList, source: "approle" };
}

console.error(
  `[gatehouse:mcp] stdio transport started for identity="${auth.identity}"`
);

await runStdioTransport(secrets, leases, policies, audit, auth, dynamicSecrets, db);
