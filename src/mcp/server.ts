import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import type { SecretsEngine } from "../secrets/engine";
import type { LeaseManager } from "../lease/manager";
import type { PolicyEngine } from "../policy/engine";
import type { AuditLog } from "../audit/logger";
import type { AuthContext } from "../auth/middleware";
import { scrubValue } from "../scrub/scrubber";
import { v4 as uuid } from "uuid";
import type { PatternEngine } from "../patterns/engine";
import { isPrivateHost, scrubResponseBody, readCappedText, MAX_UPSTREAM_BODY_BYTES } from "../security/ssrf";

/**
 * Gatehouse MCP Server
 *
 * Exposes secrets management as MCP tools that any agent harness can consume.
 * Supports both Streamable HTTP (for Windsurf, Cursor, OpenCode, remote agents)
 * and stdio (for Claude Code, Codex, OpenClaw local configs).
 *
 * Tools exposed:
 *   gatehouse_get      - Read a secret value (with audit)
 *   gatehouse_lease    - Checkout a secret with a TTL
 *   gatehouse_revoke   - Revoke an active lease
 *   gatehouse_list     - List secret paths (metadata only)
 *   gatehouse_put      - Store/update a secret
 *   gatehouse_scrub    - Scrub text for leaked credentials
 *   gatehouse_status   - Health check and active lease count
 *   gatehouse_patterns - Query learned API call patterns for a secret
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
            'Secret path, e.g. "api-keys/openai" or "db/prod/password"',
        },
      },
      required: ["path"],
    },
  },
  {
    name: "gatehouse_lease",
    description:
      "Checkout a secret with a time-to-live. The secret auto-revokes after the TTL expires. Prefer this over gatehouse_get for agent workflows.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Secret path to lease",
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
    name: "gatehouse_revoke",
    description: "Revoke an active lease before its TTL expires.",
    inputSchema: {
      type: "object",
      properties: {
        lease_id: {
          type: "string",
          description: "The lease ID returned from gatehouse_lease",
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
      'Forward an HTTP request with secrets injected. You never see the raw credentials. Three styles: (1) Template: use {{secret:path}} in headers/URL/body. (2) Inject shorthand: {"inject": {"Authorization": "api-keys/openai"}} auto-sets headers. (3) Auto-inject: {"auto_inject": ["api-keys/openai"]} reads metadata.header_name to determine the header automatically. Secrets with allowed_domains metadata restrict which hosts they can be sent to.',
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
            'Request headers. Can use {{secret:path}} for inline injection, e.g. {"Authorization": "Bearer {{secret:api-keys/openai}}"}',
        },
        inject: {
          type: "object",
          description:
            'Shorthand: map header names to secret paths. Gatehouse sets the header value from the secret. Authorization headers auto-prefix "Bearer " unless the value already has a scheme. Example: {"Authorization": "api-keys/openai", "X-Custom-Key": "api-keys/custom"}',
        },
        auto_inject: {
          type: "array",
          items: { type: "string" },
          description:
            'Array of secret paths. Gatehouse reads metadata.header_name from each secret to determine which header to set. The simplest option — you just provide secret paths, Gatehouse handles the rest.',
        },
        body: {
          type: "object",
          description: "Request body (will be JSON-serialized)",
        },
        timeout: {
          type: "number",
          description:
            "Timeout in milliseconds (default: 30000, max: 120000)",
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
];

export function createMCPHandler(
  secrets: SecretsEngine,
  leases: LeaseManager,
  policies: PolicyEngine,
  audit: AuditLog,
  patterns?: PatternEngine
) {
  async function handleToolCall(
    toolName: string,
    args: Record<string, any>,
    auth: AuthContext
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

        case "gatehouse_revoke": {
          const lease = leases.getLease(args.lease_id);
          if (!lease) return error(`Lease not found: "${args.lease_id}"`);
          if (
            lease.identity !== auth.identity &&
            !policies.check(auth.policies, "*", "admin")
          ) {
            return error("Access denied: you can only revoke your own leases");
          }
          leases.revoke(args.lease_id, auth.identity);
          return text(`Lease ${args.lease_id} revoked`);
        }

        case "gatehouse_list": {
          if (!policies.check(auth.policies, args.prefix || "*", "list")) {
            return error("Access denied: no list permission");
          }
          const items = secrets.list(args.prefix || "");
          audit.log({
            identity: auth.identity,
            action: "secret.list.mcp",
            path: args.prefix || "*",
          });
          return text(
            JSON.stringify(
              items.map((s) => ({
                path: s.path,
                metadata: s.metadata,
                version: s.version,
                updated_at: s.updated_at,
              })),
              null,
              2
            )
          );
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
          // Validate required fields
          if (!args.url) return error("url is required");
          if (!args.method) return error("method is required");

          const method = args.method.toUpperCase();
          if (!["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"].includes(method)) {
            return error(`Unsupported method: ${method}`);
          }

          // Find secret references (template + inject shorthand)
          const refPattern = /\{\{secret:([a-zA-Z0-9/_-]+)\}\}/g;
          const scan = (s: string) => [...s.matchAll(refPattern)].map(m => m[1]);
          const refs = new Set<string>();
          scan(args.url).forEach(r => refs.add(r));
          if (args.headers) {
            for (const v of Object.values(args.headers as Record<string, string>)) {
              scan(v).forEach(r => refs.add(r));
            }
          }
          if (args.body) {
            scan(typeof args.body === "string" ? args.body : JSON.stringify(args.body)).forEach(r => refs.add(r));
          }
          if (args.inject) {
            for (const secretPath of Object.values(args.inject as Record<string, string>)) {
              refs.add(secretPath);
            }
          }
          if (args.auto_inject) {
            for (const secretPath of (args.auto_inject as string[])) {
              refs.add(secretPath);
            }
          }

          if (refs.size === 0) {
            return error('No secret references found. Use {{secret:path}} in url/headers/body, "inject", or "auto_inject".');
          }

          // Check policy + resolve secrets
          const resolved = new Map<string, string>();
          for (const path of refs) {
            if (!policies.check(auth.policies, path, "proxy")) {
              audit.log({ identity: auth.identity, action: "proxy.forward.mcp", path, success: false });
              return error(`Access denied: no proxy permission on "${path}"`);
            }
            const val = secrets.get(path);
            if (!val) return error(`Secret not found: "${path}"`);
            resolved.set(path, val);

            // Domain allowlist check
            const meta = secrets.getMeta(path);
            if (meta?.metadata?.allowed_domains) {
              const domains = meta.metadata.allowed_domains.split(",").map((d: string) => d.trim()).filter(Boolean);
              if (domains.length > 0) {
                const resolvedUrl = args.url.replace(refPattern, (_: string, p: string) => resolved.get(p) ?? `{{secret:${p}}}`);
                try {
                  const hostname = new URL(resolvedUrl).hostname;
                  if (!domains.some((d: string) => hostname === d || hostname.endsWith(`.${d}`))) {
                    audit.log({ identity: auth.identity, action: "proxy.forward.mcp", path, success: false });
                    return error(`Domain ${hostname} not in allowed domains for secret "${path}"`);
                  }
                } catch {
                  return error("Invalid URL");
                }
              }
            }
          }

          // Inject secrets
          const inject = (s: string) => s.replace(refPattern, (_, p) => resolved.get(p) ?? `{{secret:${p}}}`);
          const upstreamUrl = inject(args.url);

          // SSRF protection: block private/internal networks
          try {
            const parsedUrl = new URL(upstreamUrl);
            const h = parsedUrl.hostname;
            if (isPrivateHost(h)) {
              const allowPrivateEnv = (process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE || "").toLowerCase() === "true";
              const anySecretAllowsPrivate = [...refs].some(rp => {
                const m = secrets.getMeta(rp);
                return m?.metadata?.allow_private === "true";
              });
              if (!allowPrivateEnv && !anySecretAllowsPrivate) {
                audit.log({ identity: auth.identity, action: "proxy.forward.mcp", path: [...refs].join(","), success: false });
                return error("Requests to private/internal networks are blocked. Set secret metadata allow_private=true or GATEHOUSE_PROXY_ALLOW_PRIVATE=true to allow.");
              }
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
          // Apply auto-inject: use secret metadata.header_name
          if (args.auto_inject) {
            for (const secretPath of (args.auto_inject as string[])) {
              const secretValue = resolved.get(secretPath);
              if (!secretValue) continue;
              const meta = secrets.getMeta(secretPath);
              const headerName = meta?.metadata?.header_name;
              if (!headerName) {
                return error(`Secret "${secretPath}" has no header_name in metadata. Set it to use auto_inject.`);
              }
              if (headerName.toLowerCase() === "authorization" && !secretValue.match(/^(Bearer|Basic|Token|Digest)\s/i)) {
                upstreamHeaders[headerName] = `Bearer ${secretValue}`;
              } else {
                upstreamHeaders[headerName] = secretValue;
              }
            }
          }
          let upstreamBody: string | undefined;
          if (args.body && method !== "GET" && method !== "HEAD") {
            upstreamBody = inject(typeof args.body === "string" ? args.body : JSON.stringify(args.body));
            if (!upstreamHeaders["content-type"] && !upstreamHeaders["Content-Type"]) {
              upstreamHeaders["Content-Type"] = "application/json";
            }
          }

          const timeout = Math.min(args.timeout || 30_000, 120_000);
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);

          try {
            const upstream = await fetch(upstreamUrl, {
              method,
              headers: upstreamHeaders,
              body: upstreamBody,
              signal: controller.signal,
              // Never auto-follow redirects — would bypass SSRF pre-flight
              redirect: "manual",
            });
            clearTimeout(timer);

            audit.log({
              identity: auth.identity,
              action: "proxy.forward.mcp",
              path: [...refs].join(","),
              metadata: {
                target_host: new URL(upstreamUrl).hostname,
                method,
                status: String(upstream.status),
              },
            });

            // Cap upstream body + scrub any injected secret values echoed back
            const rawBody = await readCappedText(upstream, MAX_UPSTREAM_BODY_BYTES);
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
              success: false,
            });
            if (e.name === "AbortError") return error(`Request timed out after ${timeout}ms`);
            if (e.code === "BODY_TOO_LARGE") return error(`Upstream response exceeds ${MAX_UPSTREAM_BODY_BYTES} bytes`);
            return error(`Upstream request failed: ${e.message}`);
          }
        }

        case "gatehouse_status": {
          const active = leases.listActive(auth.identity);
          return text(
            JSON.stringify(
              {
                status: "ok",
                version: "0.1.0",
                identity: auth.identity,
                policies: auth.policies,
                active_leases: active.length,
              },
              null,
              2
            )
          );
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

  async function handleRequest(req: MCPRequest, auth: AuthContext): Promise<MCPResponse> {
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
              version: "0.1.0",
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
        const result = await handleToolCall(name, args || {}, auth);
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
  patterns?: PatternEngine
) {
  const router = new Hono();
  const mcp = createMCPHandler(secrets, leases, policies, audit, patterns);

  // Streamable HTTP endpoint (POST /mcp)
  router.post("/", async (c) => {
    const auth = c.get("auth") as AuthContext;
    const req = (await c.req.json()) as MCPRequest;
    const res = await mcp.handleRequest(req, auth);
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
    const res = await mcp.handleRequest(req, auth);
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
  auth: AuthContext
) {
  const mcp = createMCPHandler(secrets, leases, policies, audit);

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
