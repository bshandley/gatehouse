#!/usr/bin/env bun
/**
 * Gatehouse MCP stdio transport.
 *
 * Run as a local MCP server for Claude Code, Codex, OpenClaw, etc.
 * The agent harness launches this process and communicates via stdin/stdout.
 *
 * Usage:
 *   GATEHOUSE_MASTER_KEY=<hex> GATEHOUSE_TOKEN=<token> bunx gatehouse-mcp
 *
 * Or via the Docker image:
 *   docker run --rm -i gatehouse:latest mcp --token <token>
 */

import { initDB } from "./db/init";
import { SecretsEngine } from "./secrets/engine";
import { LeaseManager } from "./lease/manager";
import { PolicyEngine } from "./policy/engine";
import { AuditLog } from "./audit/logger";
import { DynamicSecretsManager } from "./dynamic/manager";
import { runStdioTransport } from "./mcp/server";
import { loadConfig } from "./config";
import { type AuthContext, safeEqual } from "./auth/middleware";

const config = loadConfig();
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

await runStdioTransport(secrets, leases, policies, audit, auth, dynamicSecrets);
