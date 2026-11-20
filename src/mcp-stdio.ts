#!/usr/bin/env bun
/**
 * Gatehouse MCP stdio transport.
 *
 * Run as a local MCP server for Claude Code, Codex, OpenClaw, etc.
 * The agent harness launches this process and communicates via stdin/stdout.
 *
 * It reads the master key from GATEHOUSE_MASTER_KEY or the data dir's
 * master.key, and never generates one: it will not create a new vault.
 *
 * Identity: GATEHOUSE_TOKEN (or the first argument) is verified like an HTTP
 * bearer token: the root token or a Gatehouse JWT. An invalid token exits 1.
 * With no token, GATEHOUSE_POLICIES is required and the process runs as
 * GATEHOUSE_IDENTITY (default "mcp-agent") with exactly those policies. There
 * is no default policy: full access means writing GATEHOUSE_POLICIES=admin.
 *
 * Usage:
 *   GATEHOUSE_TOKEN=... bunx gatehouse-mcp
 *
 * Or via the Docker image, against the server's data volume:
 *   docker run --rm -i -v gatehouse-data:/data -e GATEHOUSE_TOKEN ghcr.io/bshandley/gatehouse:latest mcp
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
import type { AuthContext } from "./auth/middleware";
import { createBearerVerifier } from "./auth/verifyBearer";

// stdout is the JSON-RPC channel. Audit rows, policy load notices and the
// lease reaper all log with console.log, which would interleave non-protocol
// lines into it. Send every such line to stderr before anything can log.
console.log = (...args: unknown[]) => console.error(...args);

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
// Pass the database so policies created in the web UI apply here too, not
// only the YAML files under the config dir.
const policies = new PolicyEngine(config.configDir, db);
const leases = new LeaseManager(db, secrets, audit);
const dynamicSecrets = new DynamicSecretsManager(db, audit, config.masterKey);

// Identity. A token, when given, is verified exactly as the HTTP API verifies
// a bearer token (root token or a Gatehouse JWT). A token that does not verify
// stops the process: it must never fall through to the local defaults.
const token = (process.env.GATEHOUSE_TOKEN || process.argv[2] || "").trim();

let auth: AuthContext;

if (token) {
  const result = await createBearerVerifier(config, db)(token, "stdio");
  if (!result.ok) {
    console.error(
      `[gatehouse:mcp] GATEHOUSE_TOKEN was rejected: ${result.error}. ` +
        "Pass the root token or a current Gatehouse JWT, or unset it to run as the local operator " +
        "(GATEHOUSE_IDENTITY, GATEHOUSE_POLICIES)."
    );
    process.exit(1);
  }
  auth = result.auth;
} else {
  // No token: the operator who starts this process chooses what the agent on
  // the other end of the pipe may do. There is no default. An agent must never
  // get the whole vault because one variable was left out, so admin has to be
  // asked for by name.
  const policyList = (process.env.GATEHOUSE_POLICIES || "")
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  if (policyList.length === 0) {
    console.error(
      "[gatehouse:mcp] refusing to start: no GATEHOUSE_TOKEN and no GATEHOUSE_POLICIES. " +
        "Set GATEHOUSE_POLICIES to the comma-separated policy names this agent may use " +
        "(for full access, GATEHOUSE_POLICIES=admin, on purpose), or pass a Gatehouse JWT or the root token as GATEHOUSE_TOKEN."
    );
    process.exit(1);
  }
  const known = new Set(["admin", ...policies.listPolicies()]);
  const unknown = policyList.filter((p) => !known.has(p));
  if (unknown.length > 0) {
    console.error(`[gatehouse:mcp] WARNING: no such policy: ${unknown.join(", ")}. An unknown policy grants nothing.`);
  }
  auth = { identity: process.env.GATEHOUSE_IDENTITY || "mcp-agent", policies: policyList, source: "approle" };
}

console.error(
  `[gatehouse:mcp] stdio transport started for identity="${auth.identity}" policies="${auth.policies.join(",")}"`
);

await runStdioTransport(secrets, leases, policies, audit, auth, dynamicSecrets, db);
