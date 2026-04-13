import { Hono } from "hono";
import type { SecretsEngine } from "../secrets/engine";
import type { PolicyEngine } from "../policy/engine";
import type { AuditLog } from "../audit/logger";
import type { PatternEngine } from "../patterns/engine";
import { isPrivateHost, scrubResponseBody, readCappedText, MAX_UPSTREAM_BODY_BYTES } from "../security/ssrf";

/**
 * Proxy request format — three injection styles supported:
 *
 * 1. Template style (Vault-like):
 *    Headers/URL/body contain {{secret:path}} placeholders that get resolved.
 *
 * 2. Inject shorthand (API Gateway-like):
 *    An "inject" map tells Gatehouse which headers to set from secrets,
 *    without the agent needing to know the template syntax.
 *
 * 3. Auto-inject (metadata-driven):
 *    An "auto_inject" array of secret paths. Gatehouse reads the secret's
 *    metadata.header_name to determine which header to set. The agent
 *    doesn't need to know the API's auth header at all.
 *
 * All styles can be combined in the same request.
 */
interface ProxyRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: any;
  timeout?: number;
  /** Shorthand: { "Header-Name": "secret-path" } — Gatehouse sets the header to the secret value */
  inject?: Record<string, string>;
  /** Auto-inject: secret paths whose metadata.header_name determines the header */
  auto_inject?: string[];
}

/** Whether private network proxying is globally allowed */
const ALLOW_PRIVATE = (process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE || "").toLowerCase() === "true";

// Match {{secret:path/to/secret}} in strings
const SECRET_REF_PATTERN = /\{\{secret:([a-zA-Z0-9/_-]+)\}\}/g;

/**
 * Extract all secret references from a proxy request.
 * Scans URL, headers, body for {{secret:path}} patterns,
 * and also collects paths from the inject shorthand map.
 */
function extractSecretRefs(req: ProxyRequest): string[] {
  const refs = new Set<string>();

  const scan = (value: string) => {
    for (const match of value.matchAll(SECRET_REF_PATTERN)) {
      refs.add(match[1]);
    }
  };

  scan(req.url);
  if (req.headers) {
    for (const v of Object.values(req.headers)) {
      scan(v);
    }
  }
  if (req.body !== undefined) {
    scan(typeof req.body === "string" ? req.body : JSON.stringify(req.body));
  }

  // Inject shorthand: values are secret paths (optionally prefixed with "basic:")
  if (req.inject) {
    for (const secretPath of Object.values(req.inject)) {
      refs.add(secretPath.replace(/^basic:/, ""));
    }
  }

  // Auto-inject: paths from array
  if (req.auto_inject) {
    for (const secretPath of req.auto_inject) {
      refs.add(secretPath);
    }
  }

  return Array.from(refs);
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


/**
 * Validate that a URL's hostname is in the allowed domains list.
 */
function checkDomainAllowlist(
  url: string,
  allowedDomains: string[]
): { allowed: boolean; hostname: string } {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;
    const allowed =
      allowedDomains.length === 0 ||
      allowedDomains.some(
        (d) => hostname === d || hostname.endsWith(`.${d}`)
      );
    return { allowed, hostname };
  } catch {
    return { allowed: false, hostname: "invalid" };
  }
}

export function proxyRouter(
  secrets: SecretsEngine,
  policies: PolicyEngine,
  audit: AuditLog,
  patterns?: PatternEngine
) {
  const router = new Hono();

  /**
   * POST /v1/proxy
   *
   * Forward an HTTP request with secrets injected. The agent never sees
   * the raw credential — Gatehouse resolves references, makes the upstream
   * call, and returns the response.
   *
   * Two injection styles:
   *
   * Template style (inline {{secret:path}} references):
   * {
   *   "method": "POST",
   *   "url": "https://api.openai.com/v1/chat/completions",
   *   "headers": {
   *     "Authorization": "Bearer {{secret:api-keys/openai}}",
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
   *     "Authorization": "api-keys/openai"
   *   },
   *   "body": { "model": "gpt-4", ... }
   * }
   *
   * inject values are set as "Bearer <value>" for Authorization headers,
   * or raw value for all other headers. Prefix with "basic:" for HTTP Basic
   * auth: {"Authorization": "basic:infra/opnsense"} base64-encodes the
   * secret value and sets "Basic <encoded>".
   *
   * Auto-inject (metadata-driven — agent doesn't need to know the header):
   * {
   *   "method": "POST",
   *   "url": "https://api.anthropic.com/v1/messages",
   *   "auto_inject": ["api-keys/anthropic"],
   *   "body": { "model": "claude-3", ... }
   * }
   * Gatehouse reads metadata.header_name from the secret to set the right header.
   *
   * All styles can be combined. Requires "proxy" capability on each secret.
   * Domain allowlisting via secret metadata key "allowed_domains".
   * Private network proxying via GATEHOUSE_PROXY_ALLOW_PRIVATE=true or
   * per-secret metadata key "allow_private"="true".
   */
  router.post("/", async (c) => {
    const auth = c.get("auth") as { identity: string; policies: string[] };
    const sourceIp = c.get("sourceIp") || "unknown";

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
    const timeout = Math.min(req.timeout || 30_000, 120_000); // max 2 minutes

    // Extract secret references (both template and inject styles)
    const secretPaths = extractSecretRefs(req);
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

    // Check policy for each referenced secret
    for (const path of secretPaths) {
      if (!policies.check(auth.policies, path, "proxy")) {
        audit.log({
          identity: auth.identity,
          action: "proxy.forward",
          path,
          source_ip: sourceIp,
          metadata: { target_url: req.url, reason: "policy_denied" },
          success: false,
        });
        return c.json(
          {
            error: `Forbidden: no proxy capability on ${path}`,
            request_id: c.get("requestId"),
          },
          403
        );
      }
    }

    // Resolve secrets and check domain allowlists
    const resolved = new Map<string, string>();
    for (const path of secretPaths) {
      const value = secrets.get(path);
      if (!value) {
        return c.json(
          {
            error: `Secret not found: ${path}`,
            request_id: c.get("requestId"),
          },
          404
        );
      }
      resolved.set(path, value);

      // Check domain allowlist from secret metadata
      const meta = secrets.getMeta(path);
      if (meta?.metadata?.allowed_domains) {
        const domains = meta.metadata.allowed_domains
          .split(",")
          .map((d) => d.trim())
          .filter(Boolean);

        if (domains.length > 0) {
          // Resolve URL first (it might contain secret refs too)
          const resolvedUrl = injectSecrets(req.url, resolved);
          const { allowed, hostname } = checkDomainAllowlist(
            resolvedUrl,
            domains
          );

          if (!allowed) {
            audit.log({
              identity: auth.identity,
              action: "proxy.forward",
              path,
              source_ip: sourceIp,
              metadata: {
                target_url: req.url,
                hostname,
                reason: "domain_blocked",
                allowed_domains: meta.metadata.allowed_domains,
              },
              success: false,
            });
            return c.json(
              {
                error: `Domain ${hostname} is not in the allowed domains for secret ${path}`,
                request_id: c.get("requestId"),
              },
              403
            );
          }
        }
      }
    }

    // SSRF protection: block requests to private/internal networks
    // Can be bypassed globally via GATEHOUSE_PROXY_ALLOW_PRIVATE=true
    // or per-secret via metadata.allow_private=true
    const upstreamUrl = injectSecrets(req.url, resolved);
    try {
      const parsedUpstream = new URL(upstreamUrl);
      if (isPrivateHost(parsedUpstream.hostname)) {
        const anySecretAllowsPrivate = secretPaths.some(p => {
          const meta = secrets.getMeta(p);
          return meta?.metadata?.allow_private === "true";
        });
        if (!ALLOW_PRIVATE && !anySecretAllowsPrivate) {
          audit.log({
            identity: auth.identity,
            action: "proxy.forward",
            path: secretPaths.join(","),
            source_ip: sourceIp,
            metadata: { target_host: parsedUpstream.hostname, reason: "ssrf_blocked" },
            success: false,
          });
          return c.json(
            { error: "Requests to private/internal networks are blocked. Set secret metadata allow_private=true or GATEHOUSE_PROXY_ALLOW_PRIVATE=true to allow.", request_id: c.get("requestId") },
            403
          );
        }
      }
      // Block non-HTTP(S) schemes
      if (!["http:", "https:"].includes(parsedUpstream.protocol)) {
        return c.json(
          { error: `Unsupported protocol: ${parsedUpstream.protocol}`, request_id: c.get("requestId") },
          400
        );
      }
    } catch {
      return c.json({ error: "Invalid upstream URL", request_id: c.get("requestId") }, 400);
    }

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

    // Apply auto-inject: use secret metadata.header_name to determine the header
    if (req.auto_inject) {
      for (const secretPath of req.auto_inject) {
        const secretValue = resolved.get(secretPath);
        if (!secretValue) continue;
        const meta = secrets.getMeta(secretPath);
        const headerName = meta?.metadata?.header_name;
        if (!headerName) {
          return c.json(
            { error: `Secret "${secretPath}" has no header_name in metadata. Set it to use auto_inject.`, request_id: c.get("requestId") },
            400
          );
        }
        // Same auto-Bearer logic as inject shorthand
        if (
          headerName.toLowerCase() === "authorization" &&
          !secretValue.match(/^(Bearer|Basic|Token|Digest)\s/i)
        ) {
          upstreamHeaders[headerName] = `Bearer ${secretValue}`;
        } else {
          upstreamHeaders[headerName] = secretValue;
        }
      }
    }

    let upstreamBody: string | undefined;
    if (req.body !== undefined && method !== "GET" && method !== "HEAD") {
      if (typeof req.body === "string") {
        upstreamBody = injectSecrets(req.body, resolved);
      } else {
        // JSON body — serialize, inject, done
        upstreamBody = injectSecrets(JSON.stringify(req.body), resolved);
        if (!upstreamHeaders["content-type"] && !upstreamHeaders["Content-Type"]) {
          upstreamHeaders["Content-Type"] = "application/json";
        }
      }
    }

    // Check if any referenced secret has tls_allow_insecure metadata
    const tlsInsecure = secretPaths.some(p => {
      const meta = secrets.getMeta(p);
      return meta?.metadata?.tls_allow_insecure === "true";
    });

    // Make the upstream request
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

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

      // Log success (never log the resolved URL — it might contain secrets in path)
      audit.log({
        identity: auth.identity,
        action: "proxy.forward",
        path: secretPaths.join(","),
        source_ip: sourceIp,
        metadata: {
          target_host: new URL(upstreamUrl).hostname,
          method,
          status: String(upstream.status),
        },
      });

      // Return the upstream response. Read with a hard body cap so an
      // oversized/hostile upstream can't exhaust memory, then scrub any
      // injected secret values that the upstream echoed back.
      const rawResponseBody = await readCappedText(upstream, MAX_UPSTREAM_BODY_BYTES);
      const responseBody = scrubResponseBody(rawResponseBody, resolved.values());
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
        if (v) responseHeaders[h] = scrubResponseBody(v, resolved.values());
      }
      // Surface redirect target so callers know why they got a 3xx
      if (upstream.status >= 300 && upstream.status < 400) {
        const loc = upstream.headers.get("location");
        if (loc) responseHeaders["location"] = scrubResponseBody(loc, resolved.values());
      }

      // Record pattern (fire-and-forget, non-critical)
      // Use the pre-injection URL (with {{secret:...}} placeholders) to avoid
      // storing resolved secret values in the patterns table.
      if (patterns) {
        try {
          patterns.record({
            secret_paths: secretPaths,
            method,
            url: req.url,
            request_headers: Object.keys(upstreamHeaders),
            request_body: req.body,
            response_status: upstream.status,
            response_body: tryParseJson(responseBody),
            identity: auth.identity,
          });
        } catch {
          // Pattern recording must never fail a proxy call
        }
      }

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

      audit.log({
        identity: auth.identity,
        action: "proxy.forward",
        path: secretPaths.join(","),
        source_ip: sourceIp,
        metadata: { method, reason },
        success: false,
      });

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
            error: `Upstream response exceeds ${MAX_UPSTREAM_BODY_BYTES} bytes`,
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
