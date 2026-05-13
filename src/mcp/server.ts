import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import type { Database } from "bun:sqlite";
import type { SecretsEngine } from "../secrets/engine";
import type { LeaseManager } from "../lease/manager";
import type { PolicyEngine } from "../policy/engine";
import { ALL_CAPABILITIES } from "../policy/engine";
import type { AuditLog } from "../audit/logger";
import type { AuthContext } from "../auth/middleware";
import type { DynamicSecretsManager } from "../dynamic/manager";
import { scrubValue } from "../scrub/scrubber";
import { v4 as uuid } from "uuid";
import type { PatternEngine } from "../patterns/engine";
import { isPrivateHost, scrubResponseBody, readCappedText, pathMatchesAnyPrefix } from "../security/ssrf";
import { checkPrivateNetworkPolicy, resolveAutoInject } from "../api/proxy";
import { getProxyLimits } from "../settings/proxyLimits";
import { VERSION } from "../version";
import type { RateLimiter } from "../rateLimits/limiter";
import { enforceProxyGates } from "../api/proxyGates";
import { LeaseValidationError } from "../lease/manager";

/**
 * Gatehouse MCP Server
 *
 * Exposes secrets management as MCP tools that any agent harness can consume.
 * Supports both Streamable HTTP (for Windsurf, Cursor, OpenCode, remote agents)
 * and stdio (for Claude Code, Codex, OpenClaw local configs).
 *
 * Tools exposed:
 *   gatehouse_get       - Read a static secret value (with audit)
 *   gatehouse_lease     - Checkout a static secret with a TTL
 *   gatehouse_checkout  - Mint a dynamic credential (DB/SSH) with a TTL
 *   gatehouse_revoke    - Revoke an active static or dynamic lease
 *   gatehouse_list      - List secret paths (static + dynamic, metadata only)
 *   gatehouse_put       - Store/update a secret
 *   gatehouse_scrub     - Scrub text for leaked credentials
 *   gatehouse_status    - Health check and active lease count
 *   gatehouse_patterns  - Query learned API call patterns for a secret
 */

// MCP protocol types
interface MCPRequest {
  jsonrpc: "2.0";
  id: string | number;
  method: string;
  params?: Record<string, any>;
}

interface MCPResponse {
  jsonrpc: "2.0";
  id: string | number;
  result?: any;
  error?: { code: number; message: string };
}

interface MCPTool {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, any>;
    required?: string[];
  };
}

const TOOLS: MCPTool[] = [
  {
    name: "gatehouse_get",
    description:
      "Read a secret value from the vault. Returns the decrypted value. Use gatehouse_lease instead if you need time-bounded access.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description:
            'Secret path, e.g. "api-keys/example" or "db/prod/password"',
        },
      },
      required: ["path"],
    },
  },
  {
    name: "gatehouse_lease",
    description:
      "Check out a STATIC secret (stored value, like an API key) with a time-to-live. The lease auto-revokes after the TTL expires. For DYNAMIC secrets (entries with kind: 'dynamic' in gatehouse_list, e.g. SSH keys and DB credentials minted on demand), use gatehouse_checkout instead.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Static secret path to lease",
        },
        ttl: {
          type: "number",
          description:
            "Lease duration in seconds (default: 300, min: 10, max: 86400)",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "gatehouse_checkout",
    description:
      "Mint a DYNAMIC credential (ephemeral DB user, signed SSH cert, etc.) with a time-to-live. Use this for entries with kind: 'dynamic' in gatehouse_list. The returned credential is created on the backend at checkout time and auto-revoked when the TTL expires. For STATIC secrets with a stored value, use gatehouse_lease instead.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description:
            "Dynamic secret path to check out, e.g. 'ssh/lab' or 'db/prod-pg'",
        },
        ttl: {
          type: "number",
          description:
            "Credential lifetime in seconds (default: 300, min: 10, max: 86400)",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "gatehouse_revoke",
    description:
      "Revoke an active lease before its TTL expires. Works for both static leases (from gatehouse_lease) and dynamic leases (from gatehouse_checkout).",
    inputSchema: {
      type: "object",
      properties: {
        lease_id: {
          type: "string",
          description:
            "The lease ID returned from gatehouse_lease or gatehouse_checkout",
        },
      },
      required: ["lease_id"],
    },
  },
  {
    name: "gatehouse_list",
    description:
      "List available secret paths. Returns metadata only, never values.",
    inputSchema: {
      type: "object",
      properties: {
        prefix: {
          type: "string",
          description:
            'Optional prefix filter, e.g. "api-keys/" to list only API keys',
        },
      },
    },
  },
  {
    name: "gatehouse_put",
    description: "Store or update a secret in the vault.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Secret path to store under",
        },
        value: {
          type: "string",
          description: "The secret value to encrypt and store",
        },
        metadata: {
          type: "object",
          description:
            'Optional key-value metadata, e.g. {"service": "openai", "env": "prod"}',
        },
      },
      required: ["path", "value"],
    },
  },
  {
    name: "gatehouse_scrub",
    description:
      "Scan text for leaked credentials and return a redacted version. Use this to sanitize tool output before including it in conversation.",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "Text to scan for credential patterns",
        },
      },
      required: ["text"],
    },
  },
  {
    name: "gatehouse_proxy",
    description:
      'Forward an HTTP request with secrets injected. You never see the raw credentials. Three styles: (1) Template: use {{secret:path}} in headers/URL/body. (2) Inject shorthand: {"inject": {"Authorization": "api-keys/example"}} auto-sets headers. Use "basic:path" prefix for HTTP Basic auth. (3) Auto-inject: {"auto_inject": ["api-keys/example"]} reads metadata.header_name to determine the header automatically. TIP: Before calling an unfamiliar API, use gatehouse_patterns to check if other agents have already learned the correct request format. Failed proxy calls include pattern suggestions automatically.',
    inputSchema: {
      type: "object",
      properties: {
        method: {
          type: "string",
          description: "HTTP method (GET, POST, PUT, PATCH, DELETE)",
        },
        url: {
          type: "string",
          description:
            'Target URL, e.g. "https://api.openai.com/v1/chat/completions"',
        },
        headers: {
          type: "object",
          description:
            'Request headers. Can use {{secret:path}} for inline injection, e.g. {"Authorization": "Bearer {{secret:api-keys/example}}"}',
        },
        inject: {
          type: "object",
          description:
            'Shorthand: map header names to secret paths. Authorization headers auto-prefix "Bearer ". Use "basic:path" for HTTP Basic auth (secret value should be "user:password"). Example: {"Authorization": "api-keys/example"} or {"Authorization": "basic:infra/opnsense"}',
        },
        auto_inject: {
          type: "array",
          items: { type: "string" },
          description:
            'Array of secret paths. Gatehouse sets the target header for you. Defaults to Authorization: Bearer <value>; override per-secret with metadata.header_name (e.g. "X-API-Key") and metadata.auth_scheme (empty string disables the Bearer prefix). The simplest option when the upstream expects a bearer token.',
        },
        body: {
          type: "object",
          description: "Request body (will be JSON-serialized)",
        },
        timeout: {
          type: "number",
          description:
            "Timeout in milliseconds (default: 30000, capped by /v1/settings/proxy-limits)",
        },
      },
      required: ["method", "url"],
    },
  },
  {
    name: "gatehouse_status",
    description:
      "Check vault health, your identity, active lease count, and available policies.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "gatehouse_patterns",
    description:
      "Query known-good API call patterns for a secret. Returns learned request templates, response schemas, and confidence scores based on real proxy traffic. Use this before making your first proxy call to a new API to see what has worked for other agents.",
    inputSchema: {
      type: "object",
      properties: {
        secret_path: {
          type: "string",
          description: "The secret path to query patterns for (e.g. 'services/memos-token')",
        },
      },
      required: ["secret_path"],
    },
  },
  {
    name: "gatehouse_request_access",
    description:
      "Request approval to use an approval-gated secret. Returns a lease_id and status='pending'. Once a human approves it, your subsequent gatehouse_proxy and gatehouse_lease calls against this secret succeed for the lease TTL. Use this when gatehouse_list shows a secret with metadata.requires_approval='true', or when a proxy call fails with 403 and 'requires_approval' in the response. Re-requests for the same (identity, path) are deduplicated to the same lease_id, so don't spam this tool. Poll gatehouse_status every 30 to 60 seconds to see your pending_leases count drop.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "The secret path to request access to.",
        },
        ttl: {
          type: "number",
          description: "Lease duration in seconds AFTER approval (default 300, min 10, max 86400).",
        },
        justification: {
          type: "string",
          description: "Why you need it. Describe INTENT (1-3 sentences). Never include the secret value, raw request body, or anything credential-shaped. 10-2000 chars.",
        },
      },
      required: ["path", "justification"],
    },
  },
];

export function createMCPHandler(
  secrets: SecretsEngine,
  leases: LeaseManager,
  policies: PolicyEngine,
  audit: AuditLog,
  patterns?: PatternEngine,
  dynamic?: DynamicSecretsManager,
  db?: Database,
  rateLimiter?: RateLimiter
) {
  async function handleToolCall(
    toolName: string,
    args: Record<string, any>,
    auth: AuthContext,
    sourceIp: string | null = null
  ): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
    try {
      switch (toolName) {
        case "gatehouse_get": {
          if (!policies.check(auth.policies, args.path, "read")) {
            return error(`Access denied: no read permission on "${args.path}"`);
          }
          const value = secrets.get(args.path);
          if (value === null) return error(`Secret not found: "${args.path}"`);

          audit.log({
            identity: auth.identity,
            action: "secret.read.mcp",
            path: args.path,
            source_ip: sourceIp,
          });
          return text(value);
        }

        case "gatehouse_lease": {
          if (!policies.check(auth.policies, args.path, "lease")) {
            return error(
              `Access denied: no lease permission on "${args.path}"`
            );
          }
          const ttl = Math.max(10, Math.min(86400, args.ttl || 300));

          // Approval-gated check before checkout: an approval-gated secret
          // without an active approved lease (and without an IP-allowlist
          // match) returns a structured isError so the agent knows to call
          // gatehouse_request_access.
          const meta = secrets.getMeta(args.path);
          if (meta?.metadata?.requires_approval === "true") {
            if (!leases.hasActiveApprovedLease(auth.identity, args.path)) {
              const allowlistRaw = meta.metadata.auto_approve_from_ip;
              let autoApproved = false;
              if (allowlistRaw && sourceIp) {
                const cidrs = allowlistRaw.split(",").map((s: string) => s.trim()).filter(Boolean);
                const { ipMatchesAllowlist } = await import("../auth/cidr");
                if (ipMatchesAllowlist(sourceIp, cidrs)) {
                  const autoTtl = parseInt(meta.metadata.auto_approve_ttl_seconds || "300", 10);
                  leases.autoApprove(
                    args.path,
                    auth.identity,
                    Number.isFinite(autoTtl) && autoTtl > 0 ? autoTtl : 300,
                    "system:auto_approve_from_ip",
                    `Auto-approved from ${sourceIp}`
                  );
                  autoApproved = true;
                }
              }
              if (!autoApproved) {
                audit.log({
                  identity: auth.identity,
                  action: "proxy.blocked.approval",
                  path: args.path,
                  source_ip: sourceIp,
                  metadata: { requires_approval: args.path },
                  success: false,
                });
                return error(
                  JSON.stringify({
                    error: `Secret ${args.path} requires an approved lease`,
                    requires_approval: [args.path],
                    hint: "Call gatehouse_request_access(path, ttl, justification) and wait for human approval.",
                  })
                );
              }
            }
          }

          const result = leases.checkout(args.path, auth.identity, ttl);
          if (!result) return error(`Secret not found: "${args.path}"`);

          return text(
            JSON.stringify(
              {
                lease_id: result.lease.id,
                expires_at: result.lease.expires_at,
                ttl_seconds: result.lease.ttl_seconds,
                value: result.value,
              },
              null,
              2
            )
          );
        }

        case "gatehouse_checkout": {
          if (!dynamic) {
            return error(
              "Dynamic secrets are not available on this Gatehouse deployment"
            );
          }
          if (!policies.check(auth.policies, args.path, "lease")) {
            return error(
              `Access denied: no lease permission on "${args.path}"`
            );
          }
          const ttl = Math.max(10, Math.min(86400, args.ttl || 300));
          try {
            const lease = await dynamic.checkout(
              args.path,
              auth.identity,
              ttl
            );
            if (!lease) {
              return error(
                `Dynamic secret not found: "${args.path}" (use gatehouse_list to find entries with kind: "dynamic")`
              );
            }
            return text(
              JSON.stringify(
                {
                  lease_id: lease.lease_id,
                  path: lease.path,
                  provider_type: lease.provider_type,
                  credential: lease.credential,
                  ttl_seconds: lease.ttl_seconds,
                  expires_at: lease.expires_at,
                },
                null,
                2
              )
            );
          } catch (e: any) {
            return error(
              `Failed to mint dynamic credential: ${e.message || e}`
            );
          }
        }

        case "gatehouse_revoke": {
          // Try static lease first, then fall back to dynamic.
          const staticLease = leases.getLease(args.lease_id);
          if (staticLease) {
            if (
              staticLease.identity !== auth.identity &&
              !policies.check(auth.policies, "*", "admin")
            ) {
              return error(
                "Access denied: you can only revoke your own leases"
              );
            }
            leases.revoke(args.lease_id, auth.identity);
            return text(`Lease ${args.lease_id} revoked`);
          }

          if (dynamic) {
            const dynLease = dynamic.getLease(args.lease_id);
            if (dynLease) {
              if (
                dynLease.identity !== auth.identity &&
                !policies.check(auth.policies, "*", "admin")
              ) {
                return error(
                  "Access denied: you can only revoke your own leases"
                );
              }
              await dynamic.revokeLease(args.lease_id, auth.identity);
              return text(`Lease ${args.lease_id} revoked`);
            }
          }

          return error(`Lease not found: "${args.lease_id}"`);
        }

        case "gatehouse_list": {
          // Show the caller every secret they can actually use via any
          // capability (list / read / proxy / lease). No separate "list"
          // cap gate - discovery is table stakes for agents. Dynamic
          // configs are merged into the same list so agents don't need
          // to know about a second discovery surface.
          const USABLE_CAPS = ["list", "read", "proxy", "lease"] as const;
          const prefix = args.prefix || "";

          const staticWithCaps = secrets.list(prefix).map((s) => ({
            s,
            caps: ALL_CAPABILITIES.filter((cap) =>
              policies.check(auth.policies, s.path, cap)
            ),
          }));
          const staticItems = staticWithCaps.filter(({ caps }) =>
            USABLE_CAPS.some((cap) => caps.includes(cap))
          );

          const dynamicItems = dynamic
            ? dynamic.listConfigs(prefix).map((d) => ({
                d,
                caps: ALL_CAPABILITIES.filter((cap) =>
                  policies.check(auth.policies, d.path, cap)
                ),
              })).filter(({ caps }) =>
                // Dynamic configs only expose lease + admin semantics.
                // Surface them to anyone who can lease or admin the path.
                caps.includes("lease") || caps.includes("admin")
              )
            : [];

          audit.log({
            identity: auth.identity,
            action: "secret.list.mcp",
            path: prefix || "*",
            source_ip: sourceIp,
          });

          const summary = patterns?.summaryByPath();
          const staticEntries = staticItems.map(({ s, caps }) => {
            const hit = summary?.get(s.path);
            return {
              path: s.path,
              kind: "static" as const,
              metadata: s.metadata,
              version: s.version,
              updated_at: s.updated_at,
              caps,
              pattern_count: hit?.count ?? 0,
              ...(hit ? { top_pattern: hit.top } : {}),
            };
          });
          const dynamicEntries = dynamicItems.map(({ d, caps }) => ({
            path: d.path,
            kind: "dynamic" as const,
            provider_type: d.provider_type,
            metadata: d.metadata,
            updated_at: d.updated_at,
            caps,
          }));

          // Sort merged list by path for stable output.
          const merged = [...staticEntries, ...dynamicEntries].sort((a, b) =>
            a.path < b.path ? -1 : a.path > b.path ? 1 : 0
          );

          return text(JSON.stringify(merged, null, 2));
        }

        case "gatehouse_put": {
          if (!policies.check(auth.policies, args.path, "write")) {
            return error(
              `Access denied: no write permission on "${args.path}"`
            );
          }
          const stored = secrets.put(args.path, args.value, args.metadata);
          audit.log({
            identity: auth.identity,
            action: "secret.write.mcp",
            path: args.path,
            source_ip: sourceIp,
          });
          return text(
            `Secret stored at "${stored.path}" (version ${stored.version})`
          );
        }

        case "gatehouse_scrub": {
          const result = scrubValue(args.text);
          return text(
            JSON.stringify(
              {
                scrubbed: result.scrubbed,
                redaction_count: result.redactions.length,
                redactions: result.redactions,
              },
              null,
              2
            )
          );
        }

        case "gatehouse_proxy": {
          const limits = db
            ? getProxyLimits(db)
            : { max_timeout_ms: 120_000, max_body_bytes: 10 * 1024 * 1024 };
          // Validate required fields
          if (!args.url) return error("url is required");
          if (!args.method) return error("method is required");

          // Extract the URL path from the user-supplied URL for audit metadata.
          const targetPath = (() => {
            try { return new URL(args.url).pathname; } catch { return ""; }
          })();

          const method = args.method.toUpperCase();
          if (!["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"].includes(method)) {
            return error(`Unsupported method: ${method}`);
          }

          // Find secret references, classified by source.
          // Template candidates (from {{secret:...}} scans) are best-effort:
          // a placeholder whose path doesn't resolve to a real secret is
          // treated as literal text and forwarded unchanged. Explicit
          // references (inject / auto_inject) must exist + have policy.
          const refPattern = /\{\{secret:([a-zA-Z0-9/_-]+)\}\}/g;
          const scan = (s: string) => [...s.matchAll(refPattern)].map(m => m[1]);
          const templateCandidates = new Set<string>();
          const explicit = new Set<string>();
          scan(args.url).forEach(r => templateCandidates.add(r));
          if (args.headers) {
            for (const v of Object.values(args.headers as Record<string, string>)) {
              scan(v).forEach(r => templateCandidates.add(r));
            }
          }
          if (args.body) {
            scan(typeof args.body === "string" ? args.body : JSON.stringify(args.body)).forEach(r => templateCandidates.add(r));
          }
          if (args.inject) {
            for (const secretPath of Object.values(args.inject as Record<string, string>)) {
              explicit.add(secretPath);
            }
          }
          if (args.auto_inject) {
            for (const secretPath of (args.auto_inject as string[])) {
              explicit.add(secretPath);
            }
          }

          // Drop template candidates whose secret doesn't exist; the literal
          // {{secret:...}} string is forwarded as-is in that case.
          const liveTemplate = [...templateCandidates].filter(p => Boolean(secrets.get(p)));
          const refs = new Set<string>([...liveTemplate, ...explicit]);

          if (refs.size === 0) {
            return error('No secret references found. Use {{secret:path}} in url/headers/body, "inject", or "auto_inject".');
          }

          // Check policy first across all refs so the rate-limit gate sees
          // an already-authorized set. We pay the cost of two iterations to
          // keep the gate evaluation symmetric with the REST proxy.
          for (const path of refs) {
            if (!policies.check(auth.policies, path, "proxy")) {
              audit.log({ identity: auth.identity, action: "proxy.forward.mcp", path, source_ip: sourceIp, metadata: { target_url: args.url, target_path: targetPath, reason: "policy_denied" }, success: false });
              return error(`Access denied: no proxy permission on "${path}"`);
            }
          }

          // Gates: per-AppRole rate limits, per-secret rate limits, approval.
          // Capture leaseIds so we can stamp the authorizing approval lease
          // onto the success audit row below.
          let mcpGateLeaseIds: Record<string, string> = {};
          if (rateLimiter && db) {
            const gate = enforceProxyGates({
              auth,
              secretPaths: [...refs],
              sourceIp: sourceIp || "",
              db,
              rateLimiter,
              leases,
              secrets,
              audit,
            });
            if (!gate.allowed) {
              return {
                content: [{ type: "text", text: JSON.stringify(gate.body) }],
                isError: true,
              };
            }
            mcpGateLeaseIds = gate.leaseIds;
          }

          const resolved = new Map<string, string>();
          for (const path of refs) {
            const val = secrets.get(path);
            if (!val) return error(`Secret not found: "${path}"`);
            resolved.set(path, val);

            // Resolve the URL (it may contain secret refs) for domain/path checks.
            const resolvedUrl = args.url.replace(refPattern, (_: string, p: string) => resolved.get(p) ?? `{{secret:${p}}}`);
            let parsedResolvedUrl: URL | null = null;
            try { parsedResolvedUrl = new URL(resolvedUrl); } catch { /* invalid URL caught later */ }

            // Domain allowlist check
            const meta = secrets.getMeta(path);
            if (meta?.metadata?.allowed_domains) {
              const domains = meta.metadata.allowed_domains.split(",").map((d: string) => d.trim()).filter(Boolean);
              if (domains.length > 0) {
                const hostname = parsedResolvedUrl?.hostname ?? "invalid";
                if (!parsedResolvedUrl || !domains.some((d: string) => hostname === d || hostname.endsWith(`.${d}`))) {
                  audit.log({ identity: auth.identity, action: "proxy.forward.mcp", path, source_ip: sourceIp, metadata: { target_url: args.url, target_path: targetPath, hostname, reason: "domain_blocked", allowed_domains: meta.metadata.allowed_domains }, success: false });
                  return error(`Domain ${hostname} not in allowed domains for secret "${path}"`);
                }
              }
            }

            // Path-prefix allowlist check
            if (meta?.metadata?.allowed_path_prefixes) {
              const prefixes = meta.metadata.allowed_path_prefixes.split(",").map((p: string) => p.trim()).filter(Boolean);
              if (prefixes.length > 0) {
                const resolvedPath = parsedResolvedUrl?.pathname ?? targetPath;
                if (!pathMatchesAnyPrefix(resolvedPath, prefixes)) {
                  audit.log({ identity: auth.identity, action: "proxy.forward.mcp", path, source_ip: sourceIp, metadata: { target_url: args.url, target_path: targetPath, reason: "path_prefix_blocked", allowed_path_prefixes: meta.metadata.allowed_path_prefixes }, success: false });
                  return error(`Path '${resolvedPath}' is not in allowed_path_prefixes for secret "${path}"`);
                }
              }
            }
          }

          // Inject secrets
          const inject = (s: string) => s.replace(refPattern, (_, p) => resolved.get(p) ?? `{{secret:${p}}}`);
          const upstreamUrl = inject(args.url);

          // SSRF protection: private-network policy is shared with HTTP proxy.
          try {
            const parsedUrl = new URL(upstreamUrl);
            const ssrf = checkPrivateNetworkPolicy(
              parsedUrl.hostname,
              [...refs],
              (p) => secrets.getMeta(p)
            );
            if (!ssrf.allowed) {
              audit.log({
                identity: auth.identity,
                action: "proxy.forward.mcp",
                path: [...refs].join(","),
                source_ip: sourceIp,
                metadata: { target_host: parsedUrl.hostname, target_path: targetPath, reason: "ssrf_blocked" },
                success: false,
              });
              return error(ssrf.reason);
            }
            if (!["http:", "https:"].includes(parsedUrl.protocol)) {
              return error(`Unsupported protocol: ${parsedUrl.protocol}`);
            }
          } catch {
            return error("Invalid upstream URL");
          }
          const upstreamHeaders: Record<string, string> = {};
          if (args.headers) {
            for (const [k, v] of Object.entries(args.headers as Record<string, string>)) {
              upstreamHeaders[k] = inject(v);
            }
          }
          // Apply inject shorthand
          if (args.inject) {
            for (const [headerName, secretPath] of Object.entries(args.inject as Record<string, string>)) {
              const secretValue = resolved.get(secretPath);
              if (secretValue) {
                if (headerName.toLowerCase() === "authorization" && !secretValue.match(/^(Bearer|Basic|Token|Digest)\s/i)) {
                  upstreamHeaders[headerName] = `Bearer ${secretValue}`;
                } else {
                  upstreamHeaders[headerName] = secretValue;
                }
              }
            }
          }
          // Apply auto-inject. Defaults: Authorization + Bearer if the
          // secret's metadata does not declare header_name/auth_scheme.
          if (args.auto_inject) {
            for (const secretPath of (args.auto_inject as string[])) {
              const secretValue = resolved.get(secretPath);
              if (!secretValue) continue;
              const { headerName, headerValue } = resolveAutoInject(
                secretValue,
                secrets.getMeta(secretPath)
              );
              upstreamHeaders[headerName] = headerValue;
            }
          }
          let upstreamBody: string | undefined;
          if (args.body && method !== "GET" && method !== "HEAD") {
            upstreamBody = inject(typeof args.body === "string" ? args.body : JSON.stringify(args.body));
            if (!upstreamHeaders["content-type"] && !upstreamHeaders["Content-Type"]) {
              upstreamHeaders["Content-Type"] = "application/json";
            }
          }

          const timeout = Math.min(args.timeout || 30_000, limits.max_timeout_ms);
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);

          try {
            const upstream = await fetch(upstreamUrl, {
              method,
              headers: upstreamHeaders,
              body: upstreamBody,
              signal: controller.signal,
              // Never auto-follow redirects - would bypass SSRF pre-flight
              redirect: "manual",
            });
            clearTimeout(timer);

            const mcpSuccessMeta: Record<string, string> = {
              target_host: new URL(upstreamUrl).hostname,
              target_path: targetPath,
              target_url: args.url,
              method,
              status: String(upstream.status),
            };
            const mcpLeaseIdsList = Object.values(mcpGateLeaseIds);
            if (mcpLeaseIdsList.length > 0) {
              mcpSuccessMeta.lease_id = mcpLeaseIdsList.join(",");
            }
            const mcpTopLeaseId = mcpLeaseIdsList.length === 1 ? mcpLeaseIdsList[0] : undefined;
            audit.log({
              identity: auth.identity,
              action: "proxy.forward.mcp",
              path: [...refs].join(","),
              source_ip: sourceIp,
              ...(mcpTopLeaseId ? { lease_id: mcpTopLeaseId } : {}),
              metadata: mcpSuccessMeta,
            });

            if (rateLimiter) {
              rateLimiter.recordCall(auth.role_id || "", [...refs]);
            }

            // Cap upstream body + scrub any injected secret values echoed back
            const rawBody = await readCappedText(upstream, limits.max_body_bytes);
            const responseBody = scrubResponseBody(rawBody, resolved.values());
            let parsed: any;
            try { parsed = JSON.parse(responseBody); } catch { parsed = responseBody; }

            return text(JSON.stringify({
              status: upstream.status,
              body: parsed,
            }, null, 2));
          } catch (e: any) {
            clearTimeout(timer);
            audit.log({
              identity: auth.identity,
              action: "proxy.forward.mcp",
              path: [...refs].join(","),
              source_ip: sourceIp,
              metadata: { target_url: args.url, target_path: targetPath },
              success: false,
            });
            if (rateLimiter) {
              rateLimiter.recordCall(auth.role_id || "", [...refs]);
            }
            if (e.name === "AbortError") return error(`Request timed out after ${timeout}ms`);
            if (e.code === "BODY_TOO_LARGE") return error(`Upstream response exceeds ${limits.max_body_bytes} bytes`);
            return error(`Upstream request failed: ${e.message}`);
          }
        }

        case "gatehouse_status": {
          const active = leases.listActive(auth.identity);
          const pending = leases.listPending(auth.identity);
          return text(
            JSON.stringify(
              {
                status: "ok",
                version: VERSION,
                identity: auth.identity,
                policies: auth.policies,
                active_leases: active.length,
                pending_leases: pending.length,
              },
              null,
              2
            )
          );
        }

        case "gatehouse_request_access": {
          // Same widened check as POST /v1/lease/<path>/request: the approval
          // gate applies to both proxy and lease, so either cap is enough.
          const canProxy = policies.check(auth.policies, args.path, "proxy");
          const canLease = policies.check(auth.policies, args.path, "lease");
          if (!canProxy && !canLease) {
            return error(`Access denied: no proxy or lease permission on "${args.path}"`);
          }
          const meta = secrets.getMeta(args.path);
          if (!meta) return error(`Secret not found: "${args.path}"`);
          const ttl = typeof args.ttl === "number" ? args.ttl : 300;
          const justification = typeof args.justification === "string" ? args.justification : "";
          try {
            const lease = leases.requestAccess(args.path, auth.identity, ttl, justification);
            return text(
              JSON.stringify(
                {
                  lease_id: lease.id,
                  status: lease.status,
                  request_expires_at: lease.request_expires_at,
                  expires_at_if_approved: lease.expires_at,
                  hint:
                    "Poll gatehouse_status every 30-60 seconds. When pending_leases drops, your proxy/lease calls against this secret will succeed.",
                },
                null,
                2
              )
            );
          } catch (e: unknown) {
            if (e instanceof LeaseValidationError) {
              return error(e.message);
            }
            throw e;
          }
        }

        case "gatehouse_patterns": {
          if (
            !policies.check(auth.policies, args.secret_path, "proxy") &&
            !policies.check(auth.policies, args.secret_path, "read")
          ) {
            return error(`Access denied: no proxy or read permission on "${args.secret_path}"`);
          }
          const patternResults = patterns?.query(args.secret_path) ?? [];
          return text(
            JSON.stringify(
              patternResults.map((p) => ({
                method: p.method,
                url_template: p.url_template,
                request_headers: p.request_headers,
                request_body_schema: p.request_body_schema,
                response_status: p.response_status,
                response_body_schema: p.response_body_schema,
                confidence: p.confidence,
                verified_by: p.verified_by,
                total_successes: p.total_successes,
                last_used: p.updated_at,
              })),
              null,
              2
            )
          );
        }

        default:
          return error(`Unknown tool: ${toolName}`);
      }
    } catch (e: any) {
      return error(e.message || "Internal error");
    }
  }

  async function handleRequest(req: MCPRequest, auth: AuthContext, sourceIp: string | null = null): Promise<MCPResponse> {
    switch (req.method) {
      case "initialize":
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: {
            protocolVersion: "2024-11-05",
            capabilities: { tools: {} },
            serverInfo: {
              name: "gatehouse",
              version: VERSION,
            },
          },
        };

      case "tools/list":
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: { tools: TOOLS },
        };

      case "tools/call": {
        const { name, arguments: args } = req.params || {};
        const result = await handleToolCall(name, args || {}, auth, sourceIp);
        return {
          jsonrpc: "2.0",
          id: req.id,
          result,
        };
      }

      case "ping":
        return { jsonrpc: "2.0", id: req.id, result: {} };

      default:
        return {
          jsonrpc: "2.0",
          id: req.id,
          error: { code: -32601, message: `Method not found: ${req.method}` },
        };
    }
  }

  return { handleRequest, handleToolCall, tools: TOOLS };
}

// Helpers
function text(
  value: string
): { content: Array<{ type: string; text: string }> } {
  return { content: [{ type: "text", text: value }] };
}

function error(
  message: string
): { content: Array<{ type: string; text: string }>; isError: boolean } {
  return { content: [{ type: "text", text: message }], isError: true };
}

/**
 * Create Hono routes for Streamable HTTP MCP transport.
 * This is what Windsurf, Cursor, OpenCode, and remote agents connect to.
 */
export function mcpHttpRouter(
  secrets: SecretsEngine,
  leases: LeaseManager,
  policies: PolicyEngine,
  audit: AuditLog,
  patterns?: PatternEngine,
  dynamic?: DynamicSecretsManager,
  db?: Database,
  rateLimiter?: RateLimiter
) {
  const router = new Hono();
  const mcp = createMCPHandler(secrets, leases, policies, audit, patterns, dynamic, db, rateLimiter);

  // Streamable HTTP endpoint (POST /mcp)
  router.post("/", async (c) => {
    const auth = c.get("auth") as AuthContext;
    const req = (await c.req.json()) as MCPRequest;
    const res = await mcp.handleRequest(req, auth, (c.get("sourceIp") as string) || null);
    return c.json(res);
  });

  // SSE endpoint for clients that prefer event streams
  router.get("/sse", (c) => {
    const auth = c.get("auth") as AuthContext;

    return streamSSE(c, async (stream) => {
      const sessionId = uuid();

      // Send endpoint event so the client knows where to POST
      await stream.writeSSE({
        event: "endpoint",
        data: `/v1/mcp/message?session=${sessionId}`,
      });

      // Keep alive
      const keepAlive = setInterval(async () => {
        try {
          await stream.writeSSE({ event: "ping", data: "" });
        } catch {
          clearInterval(keepAlive);
        }
      }, 30_000);

      stream.onAbort(() => clearInterval(keepAlive));
    });
  });

  // SSE message handler
  router.post("/message", async (c) => {
    const auth = c.get("auth") as AuthContext;
    const req = (await c.req.json()) as MCPRequest;
    const res = await mcp.handleRequest(req, auth, (c.get("sourceIp") as string) || null);
    return c.json(res);
  });

  // Tool listing (convenience, non-MCP)
  router.get("/tools", (c) => {
    return c.json({ tools: mcp.tools });
  });

  return router;
}

/**
 * stdio MCP transport for local integrations.
 * Run with: bunx gatehouse-mcp --token <GATEHOUSE_TOKEN>
 *
 * Used by Claude Code, Codex, OpenClaw when configured as a local stdio MCP server.
 */
export async function runStdioTransport(
  secrets: SecretsEngine,
  leases: LeaseManager,
  policies: PolicyEngine,
  audit: AuditLog,
  auth: AuthContext,
  dynamic?: DynamicSecretsManager,
  db?: Database
) {
  const mcp = createMCPHandler(secrets, leases, policies, audit, undefined, dynamic, db);

  const decoder = new TextDecoder();
  let buffer = "";

  process.stdout.write(""); // ensure stdout is open

  for await (const chunk of Bun.stdin.stream()) {
    buffer += decoder.decode(chunk);

    // Process complete JSON-RPC messages (newline-delimited)
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      try {
        const req = JSON.parse(trimmed) as MCPRequest;
        const res = await mcp.handleRequest(req, auth);
        process.stdout.write(JSON.stringify(res) + "\n");
      } catch (e: any) {
        const errorRes: MCPResponse = {
          jsonrpc: "2.0",
          id: 0,
          error: { code: -32700, message: `Parse error: ${e.message}` },
        };
        process.stdout.write(JSON.stringify(errorRes) + "\n");
      }
    }
  }
}
