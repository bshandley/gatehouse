import { Hono } from "hono";
import type { Database } from "bun:sqlite";
import type { SecretsEngine } from "../secrets/engine";
import type { PolicyEngine } from "../policy/engine";
import type { AuditLog } from "../audit/logger";
import type { PatternEngine } from "../patterns/engine";
import type { RateLimiter } from "../rateLimits/limiter";
import type { LeaseManager } from "../lease/manager";
import type { AuthContext } from "../auth/middleware";
import { scrubResponseBody, secretRedactionValues, readCappedText } from "../security/ssrf";
import { getProxyLimits } from "../settings/proxyLimits";
import {
  authorizeProxyCall,
  recordProxyCall,
  recordProxyOutcome,
  type ProxyCall,
  type ProxyDeps,
} from "../proxy/pipeline";

// Re-exported: src/mcp/server.ts and others import these from here.
export { allowPrivateGlobally, checkPrivateNetworkPolicy } from "../proxy/pipeline";

/**
 * Proxy request format - three injection styles supported:
 *
 * 1. Template style (Vault-like):
 *    Headers/URL/body contain {{secret:path}} placeholders that get resolved.
 *
 * 2. Inject shorthand (API Gateway-like):
 *    An "inject" map tells Gatehouse which headers to set from secrets,
 *    without the agent needing to know the template syntax.
 *
 * 3. Auto-inject (metadata-driven):
 *    An "auto_inject" array of secret paths. Gatehouse sets the target
 *    header for you - defaults to Authorization: Bearer <value>, and
 *    can be overridden per-secret via metadata.header_name (e.g.
 *    "X-API-Key") and metadata.auth_scheme (empty string disables the
 *    Bearer prefix). The agent doesn't need to know the API's auth
 *    header at all.
 *
 * All styles can be combined in the same request.
 */
interface ProxyRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: any;
  timeout?: number;
  /** Shorthand: { "Header-Name": "secret-path" } - Gatehouse sets the header to the secret value */
  inject?: Record<string, string>;
  /** Auto-inject: secret paths whose metadata.header_name determines the header */
  auto_inject?: string[];
}

/**
 * Resolve an auto_inject request to a concrete (header, value) pair.
 *
 * Secret metadata can specify:
 *   - header_name: the header Gatehouse should set (default: "Authorization")
 *   - auth_scheme: the scheme prefix for Authorization values (default: "Bearer")
 *
 * When `header_name` is missing we default to Authorization because that's
 * what the overwhelming majority of bearer-token APIs want, and requiring
 * every secret to carry the metadata creates friction that surprises
 * homelabbers. Operators can set `header_name` to override (e.g. "X-API-Key"
 * with auth_scheme="" for raw-token-in-a-custom-header APIs).
 *
 * For the Authorization header, if the secret's value does not already start
 * with a known scheme, Gatehouse prepends one. Pass auth_scheme="" to disable.
 */
export function resolveAutoInject(
  secretValue: string,
  meta: { metadata?: Record<string, string> } | null
): { headerName: string; headerValue: string } {
  const headerName = meta?.metadata?.header_name || "Authorization";
  const rawSchemeMeta = meta?.metadata?.auth_scheme;
  // Distinguish "unset" (use default) from "explicit empty string" (no scheme).
  const scheme =
    rawSchemeMeta === undefined
      ? headerName.toLowerCase() === "authorization"
        ? "Bearer"
        : ""
      : rawSchemeMeta;
  const hasScheme = /^(Bearer|Basic|Token|Digest|ApiKey)\s/i.test(secretValue);
  const headerValue = scheme && !hasScheme ? `${scheme} ${secretValue}` : secretValue;
  return { headerName, headerValue };
}

// Match {{secret:path/to/secret}} in strings
const SECRET_REF_PATTERN = /\{\{secret:([a-zA-Z0-9/_-]+)\}\}/g;

/**
 * Extract secret references from a proxy request, classified by source.
 *
 * - `templateCandidates`: paths discovered by scanning url/headers/body for
 *   `{{secret:path}}` placeholders. These are CANDIDATES, not commitments.
 *   The caller must check whether each path resolves to a real secret. If
 *   it does not, the placeholder is treated as literal text and forwarded
 *   to the upstream unchanged. This avoids false-positive policy denials
 *   for bodies that legitimately contain the literal string `{{secret:...}}`
 *   (e.g. source code documenting the proxy API).
 *
 * - `explicit`: paths the caller named directly via `inject` or `auto_inject`.
 *   These are commitments: the secret must exist AND the AppRole must have
 *   `proxy` capability on it. Failure is a 403/404, not silent pass-through.
 */
function extractSecretRefs(req: ProxyRequest): { templateCandidates: string[]; explicit: string[] } {
  const templateCandidates = new Set<string>();
  const explicit = new Set<string>();

  const scan = (value: string) => {
    for (const match of value.matchAll(SECRET_REF_PATTERN)) {
      templateCandidates.add(match[1]);
    }
  };

  scan(req.url);
  if (req.headers) {
    for (const v of Object.values(req.headers)) scan(v);
  }
  if (req.body !== undefined) {
    scan(typeof req.body === "string" ? req.body : JSON.stringify(req.body));
  }

  // Inject shorthand: values are secret paths (optionally prefixed with "basic:")
  if (req.inject) {
    for (const secretPath of Object.values(req.inject)) {
      explicit.add(secretPath.replace(/^basic:/, ""));
    }
  }

  // Auto-inject: paths from array
  if (req.auto_inject) {
    for (const secretPath of req.auto_inject) explicit.add(secretPath);
  }

  return { templateCandidates: Array.from(templateCandidates), explicit: Array.from(explicit) };
}

/**
 * Replace all {{secret:path}} references in a string with resolved values.
 */
function injectSecrets(
  template: string,
  resolved: Map<string, string>
): string {
  return template.replace(SECRET_REF_PATTERN, (_, path) => {
    return resolved.get(path) ?? `{{secret:${path}}}`;
  });
}


export function proxyRouter(
  secrets: SecretsEngine,
  policies: PolicyEngine,
  audit: AuditLog,
  patterns: PatternEngine | undefined,
  db: Database,
  rateLimiter?: RateLimiter,
  leases?: LeaseManager
) {
  const router = new Hono();

  /**
   * POST /v1/proxy
   *
   * Forward an HTTP request with secrets injected. The agent never sees
   * the raw credential - Gatehouse resolves references, makes the upstream
   * call, and returns the response.
   *
   * Two injection styles:
   *
   * Template style (inline {{secret:path}} references):
   * {
   *   "method": "POST",
   *   "url": "https://api.openai.com/v1/chat/completions",
   *   "headers": {
   *     "Authorization": "Bearer {{secret:api-keys/example}}",
   *     "Content-Type": "application/json"
   *   },
   *   "body": { "model": "gpt-4", ... }
   * }
   *
   * Inject shorthand (header → secret path mapping):
   * {
   *   "method": "POST",
   *   "url": "https://api.openai.com/v1/chat/completions",
   *   "headers": { "Content-Type": "application/json" },
   *   "inject": {
   *     "Authorization": "api-keys/example"
   *   },
   *   "body": { "model": "gpt-4", ... }
   * }
   *
   * inject values are set as "Bearer <value>" for Authorization headers,
   * or raw value for all other headers. Prefix with "basic:" for HTTP Basic
   * auth: {"Authorization": "basic:infra/opnsense"} base64-encodes the
   * secret value and sets "Basic <encoded>".
   *
   * Auto-inject (metadata-driven - agent doesn't need to know the header):
   * {
   *   "method": "POST",
   *   "url": "https://api.anthropic.com/v1/messages",
   *   "auto_inject": ["api-keys/example2"],
   *   "body": { "model": "claude-3", ... }
   * }
   * Gatehouse reads metadata.header_name from the secret to set the right header.
   *
   * All styles can be combined. Requires "proxy" capability on each secret.
   * Domain allowlisting via secret metadata key "allowed_domains".
   * Private network proxying is allowed by default (homelab-friendly).
   * Disable globally with GATEHOUSE_PROXY_ALLOW_PRIVATE=false, or block
   * a specific secret by setting its metadata allow_private=false.
   */
  router.post("/", async (c) => {
    const auth = c.get("auth") as AuthContext;
    const sourceIp = c.get("sourceIp") || "unknown";
    const limits = getProxyLimits(db);

    // Parse request
    let req: ProxyRequest;
    try {
      req = await c.req.json();
    } catch {
      return c.json(
        { error: "Invalid JSON body", request_id: c.get("requestId") },
        400
      );
    }

    // Validate required fields
    if (!req.url || typeof req.url !== "string") {
      return c.json(
        { error: "url is required", request_id: c.get("requestId") },
        400
      );
    }
    if (!req.method || typeof req.method !== "string") {
      return c.json(
        { error: "method is required", request_id: c.get("requestId") },
        400
      );
    }

    const method = req.method.toUpperCase();
    if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(method)) {
      return c.json(
        { error: `Unsupported method: ${method}`, request_id: c.get("requestId") },
        400
      );
    }

    // Validate timeout
    const timeout = Math.min(req.timeout || 30_000, limits.max_timeout_ms);

    // Extract secret references, classified by source.
    // Template candidates (from {{secret:...}} scans) are best-effort: a
    // placeholder whose path doesn't resolve to a real secret is treated
    // as literal text and forwarded unchanged. Explicit references (inject
    // / auto_inject) are commitments: must exist + must have policy.
    const { templateCandidates, explicit } = extractSecretRefs(req);

    // Filter template candidates to only those that actually resolve to a
    // real secret. Unresolved candidates are dropped here; injectSecrets()
    // leaves any unmatched {{secret:path}} pattern literal in the output.
    const liveTemplate = templateCandidates.filter((p) => Boolean(secrets.get(p)));

    // The set of secrets that will actually be used by this request.
    const secretPaths = Array.from(new Set([...liveTemplate, ...explicit]));

    if (secretPaths.length === 0) {
      return c.json(
        {
          error:
            'No secret references found. Use {{secret:path}} in url/headers/body, or the "inject" shorthand.',
          request_id: c.get("requestId"),
        },
        400
      );
    }

    // Policy, rate-limit and approval gates, domain and path allowlists,
    // private-network policy, protocol. Shared with the MCP tool and
    // passthrough; denials are already audited, this handler only formats
    // the response.
    const deps: ProxyDeps = { secrets, policies, audit, db, rateLimiter, leases, patterns };
    const call: ProxyCall = {
      auth,
      sourceIp,
      requestId: c.get("requestId"),
      secretPaths,
      auditUrl: req.url,
      resolveUrl: (resolved) => injectSecrets(req.url, resolved),
      auditAction: "proxy.forward",
    };
    const authz = authorizeProxyCall(deps, call);
    if (!authz.ok) {
      const d = authz.denial;
      const requestId = c.get("requestId");
      switch (d.code) {
        case "policy_denied":
          return c.json({ error: `Forbidden: no proxy capability on ${d.path}`, request_id: requestId }, 403);
        case "gate_blocked":
          if (d.gate.headers) {
            for (const [k, v] of Object.entries(d.gate.headers)) c.header(k, v);
          }
          return c.json(d.gate.body, d.gate.status);
        case "gates_unavailable":
          return c.json({ error: `Proxy gates are unavailable for ${d.path}`, request_id: requestId }, 500);
        case "secret_not_found":
          return c.json({ error: `Secret not found: ${d.path}`, request_id: requestId }, 404);
        case "domain_blocked":
          return c.json(
            { error: `Domain ${d.hostname} is not in the allowed domains for secret ${d.path}`, request_id: requestId },
            403
          );
        case "path_prefix_blocked":
          return c.json(
            { error: `Path '${d.resolvedPath}' is not in allowed_path_prefixes for secret '${d.path}'`, request_id: requestId },
            403
          );
        case "ssrf_blocked":
          return c.json({ error: d.reason, request_id: requestId }, 403);
        case "bad_protocol":
          return c.json({ error: `Unsupported protocol: ${d.protocol}`, request_id: requestId }, 400);
        case "invalid_url":
          return c.json({ error: "Invalid upstream URL", request_id: requestId }, 400);
      }
    }
    const { resolved, upstreamUrl, tlsInsecure } = authz;

    // Build the upstream request with secrets injected
    const upstreamHeaders: Record<string, string> = {};
    if (req.headers) {
      for (const [key, value] of Object.entries(req.headers)) {
        upstreamHeaders[key] = injectSecrets(value, resolved);
      }
    }

    // Apply inject shorthand: set headers from secret values
    if (req.inject) {
      for (const [headerName, rawPath] of Object.entries(req.inject)) {
        // "basic:path/to/secret" => base64-encode value as HTTP Basic auth
        const isBasic = rawPath.startsWith("basic:");
        const secretPath = isBasic ? rawPath.slice(6) : rawPath;
        const secretValue = resolved.get(secretPath);
        if (secretValue) {
          if (isBasic) {
            // Secret value should be "user:password" format
            const encoded = btoa(secretValue);
            upstreamHeaders[headerName] = `Basic ${encoded}`;
          } else if (
            headerName.toLowerCase() === "authorization" &&
            !secretValue.match(/^(Bearer|Basic|Token|Digest)\s/i)
          ) {
            upstreamHeaders[headerName] = `Bearer ${secretValue}`;
          } else {
            upstreamHeaders[headerName] = secretValue;
          }
        }
      }
    }

    // Apply auto-inject. Defaults: Authorization + Bearer if the secret's
    // metadata does not declare header_name/auth_scheme (handled inside
    // resolveAutoInject).
    if (req.auto_inject) {
      for (const secretPath of req.auto_inject) {
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
    if (req.body !== undefined && method !== "GET" && method !== "HEAD") {
      if (typeof req.body === "string") {
        upstreamBody = injectSecrets(req.body, resolved);
      } else {
        // JSON body - serialize, inject, done
        upstreamBody = injectSecrets(JSON.stringify(req.body), resolved);
        if (!upstreamHeaders["content-type"] && !upstreamHeaders["Content-Type"]) {
          upstreamHeaders["Content-Type"] = "application/json";
        }
      }
    }

    // Make the upstream request
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    let counted = false;

    try {
      const fetchOptions: any = {
        method,
        headers: upstreamHeaders,
        body: upstreamBody,
        signal: controller.signal,
        // Never auto-follow redirects: the redirect target may be a private
        // host that bypasses the pre-flight SSRF check. Callers receive the
        // 3xx status and Location header and can choose to re-submit after
        // their own validation.
        redirect: "manual",
      };

      // Bun supports per-request TLS options via tls property
      if (tlsInsecure) {
        fetchOptions.tls = { rejectUnauthorized: false };
      }

      const upstream = await fetch(upstreamUrl, fetchOptions);

      clearTimeout(timer);

      // Count this call against AppRole + per-secret rate-limit buckets.
      // Upstream 4xx/5xx still counts: the gate work happened and the
      // upstream connection consumed proxy capacity. Pre-forward failures
      // (rate-limited, approval-required, policy denied) do NOT count.
      recordProxyCall(deps, call, authz);
      counted = true;

      // Return the upstream response. Read with a hard body cap so an
      // oversized/hostile upstream can't exhaust memory, then scrub any
      // injected secret values that the upstream echoed back.
      const rawResponseBody = await readCappedText(upstream, limits.max_body_bytes);
      // Redact both the raw secret values and their on-the-wire encodings (e.g.
      // the base64 form used by the basic: inject shorthand).
      const redactValues = secretRedactionValues(resolved.values());
      const bodyScrub = scrubResponseBody(rawResponseBody, redactValues);
      const responseBody = bodyScrub.body;
      let redactionCount = bodyScrub.count;
      const responseHeaders: Record<string, string> = {};

      // Forward safe response headers (scrub any echoed secret values)
      const safeHeaders = [
        "content-type",
        "x-request-id",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "retry-after",
      ];
      for (const h of safeHeaders) {
        const v = upstream.headers.get(h);
        if (v) {
          const hs = scrubResponseBody(v, redactValues);
          responseHeaders[h] = hs.body;
          redactionCount += hs.count;
        }
      }
      // Surface redirect target so callers know why they got a 3xx
      if (upstream.status >= 300 && upstream.status < 400) {
        const loc = upstream.headers.get("location");
        if (loc) {
          const ls = scrubResponseBody(loc, redactValues);
          responseHeaders["location"] = ls.body;
          redactionCount += ls.count;
        }
      }

      // Now that the body/header scrub has run, the redaction count is known.
      // Logging here (rather than before the upstream read) means an oversized
      // upstream that throws in readCappedText produces only the failure row.
      // The pattern uses the pre-injection URL (with {{secret:...}}
      // placeholders) so resolved values never reach the patterns table.
      recordProxyOutcome(deps, call, authz, {
        method,
        status: upstream.status,
        redactionCount,
        pattern: {
          url: req.url,
          requestHeaderNames: Object.keys(upstreamHeaders),
          requestBody: req.body,
          responseBody: tryParseJson(responseBody),
        },
      });

      const responseJson: Record<string, any> = {
        status: upstream.status,
        headers: responseHeaders,
        body: tryParseJson(responseBody),
      };

      // Include pattern suggestions on error responses, and a hint on success
      if (patterns) {
        const suggestions = patterns.suggest(secretPaths[0]);
        if (upstream.status >= 400 && suggestions.length > 0) {
          responseJson.suggestions = suggestions;
          responseJson.hint = "These are known-good patterns for this secret. Use the gatehouse_patterns MCP tool or GET /v1/proxy/patterns?secret=<path> to browse all patterns.";
        } else if (upstream.status < 300) {
          // On success, let agents know patterns are available
          responseJson.patterns_available = true;
        }
      }

      return c.json(responseJson);
    } catch (err: any) {
      clearTimeout(timer);

      const reason =
        err.name === "AbortError" ? "timeout" : err.message || "unknown";

      recordProxyOutcome(deps, call, authz, { method, failureReason: reason });

      // Failed upstream calls still count against rate limits: we did the
      // gate + injection work and made the outbound request. Counted once:
      // a body-cap overrun after the fetch was already counted above.
      if (!counted) recordProxyCall(deps, call, authz);

      if (err.name === "AbortError") {
        const resp: any = {
          error: `Upstream request timed out after ${timeout}ms`,
          request_id: c.get("requestId"),
        };
        if (patterns) {
          const suggestions = patterns.suggest(secretPaths[0]);
          if (suggestions.length > 0) {
            resp.suggestions = suggestions;
            resp.hint = "Check known-good patterns with gatehouse_patterns MCP tool or GET /v1/proxy/patterns?secret=<path>";
          }
        }
        return c.json(resp, 504);
      }

      if (err.code === "BODY_TOO_LARGE") {
        return c.json(
          {
            error: `Upstream response exceeds ${limits.max_body_bytes} bytes`,
            request_id: c.get("requestId"),
          },
          502
        );
      }

      const resp: any = {
        error: `Upstream request failed: ${reason}`,
        request_id: c.get("requestId"),
      };
      if (patterns) {
        const suggestions = patterns.suggest(secretPaths[0]);
        if (suggestions.length > 0) {
          resp.suggestions = suggestions;
          resp.hint = "Check known-good patterns with gatehouse_patterns MCP tool or GET /v1/proxy/patterns?secret=<path>";
        }
      }
      return c.json(resp, 502);
    }
  });

  return router;
}

function tryParseJson(text: string): any {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
