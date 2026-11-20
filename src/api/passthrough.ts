/**
 * Passthrough route: `ANY /p/<alias>/<rest>` (spec 2026-11-19, D2 to D8).
 *
 * The caller authenticates with a Gatehouse credential in the API-key slot,
 * the shared proxy pipeline applies every /v1/proxy control, the bound
 * secret is injected, and the upstream response is streamed back natively
 * with the secret scrubbed. Mounted outside the /v1/* auth middleware: this
 * route authenticates for itself.
 */

import { Hono, type Context } from "hono";
import type { Database } from "bun:sqlite";
import type { GatehouseConfig } from "../config";
import type { AuthContext } from "../auth/middleware";
import { createBearerVerifier } from "../auth/verifyBearer";
import { checkRateLimit, recordFailure, retryAfterSeconds } from "../auth/loginLimiter";
import { PASSTHROUGH_KEY_PREFIX, createPassthroughKeyVerifier } from "../proxy/passthroughKey";
import {
  buildResponseHeaders,
  buildUpstreamHeaders,
  extractCallerCredentials,
  joinUpstreamUrl,
  rewriteLocation,
} from "../proxy/passthroughRequest";
import { scrubStream } from "../proxy/streamScrub";
import {
  authorizeProxyCall,
  recordProxyCall,
  recordProxyOutcome,
  type ProxyCall,
  type ProxyDenial,
  type ProxyDeps,
} from "../proxy/pipeline";
import { getProxyLimits } from "../settings/proxyLimits";
import { scrubResponseBody, secretRedactionValues } from "../security/ssrf";
import { parseMaxBodySize } from "../http/middleware";

const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]);
const ALIAS_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
/** Statuses whose response may not carry a body. */
const NULL_BODY_STATUS = new Set([204, 205, 304]);

type Ctx = Context;

/** JSON error that Gatehouse itself originates (spec D7). */
function gatehouseError(
  c: Ctx,
  status: number,
  code: string,
  error: string,
  opts: { extra?: Record<string, unknown>; headers?: Record<string, string> } = {}
): Response {
  const headers = new Headers(opts.headers);
  headers.set("content-type", "application/json");
  headers.set("x-gatehouse-error", "1");
  const body = { ...opts.extra, error, code, request_id: c.get("requestId") };
  return new Response(JSON.stringify(body), { status, headers });
}

/**
 * Path and query exactly as the request carried them, never decoded. Bun's
 * server has already resolved dot segments (including %2e forms), so this is
 * the path the router matched on.
 */
function rawPathAndQuery(url: string): { path: string; query: string } {
  const schemeEnd = url.indexOf("://");
  const start = url.indexOf("/", schemeEnd < 0 ? 0 : schemeEnd + 3);
  if (start < 0) return { path: "/", query: "" };
  let rest = url.slice(start);
  const hash = rest.indexOf("#");
  if (hash >= 0) rest = rest.slice(0, hash);
  const q = rest.indexOf("?");
  return q < 0 ? { path: rest, query: "" } : { path: rest.slice(0, q), query: rest.slice(q) };
}

/** Read a request body with a byte cap. Null when the cap is exceeded. */
async function readCappedBody(body: ReadableStream<Uint8Array> | null, max: number): Promise<Uint8Array<ArrayBuffer> | null> {
  if (!body) return new Uint8Array(0);
  const reader = body.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const r = await reader.read();
    if (r.done) break;
    total += r.value.length;
    if (total > max) {
      reader.cancel().catch(() => {});
      return null;
    }
    parts.push(r.value);
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function passthroughRouter(deps: ProxyDeps & { db: Database; config: GatehouseConfig }): Hono {
  const verifyBearer = createBearerVerifier(deps.config, deps.db);
  const verifyKey = createPassthroughKeyVerifier(deps.db);
  const maxBodySize = parseMaxBodySize(process.env.GATEHOUSE_MAX_BODY_SIZE);
  // Empty: a rewritten Location is a path on whatever host the caller used.
  const publicBase = deps.config.publicUrl ?? "";
  const router = new Hono();

  const handle = async (c: Ctx): Promise<Response> => {
    const method = c.req.method.toUpperCase();
    if (!METHODS.has(method)) {
      return gatehouseError(c, 405, "method_not_allowed", `Method ${method} is not supported by passthrough`, {
        headers: { Allow: [...METHODS].join(", ") },
      });
    }

    const sourceIp: string = c.get("sourceIp") || "unknown";
    const requestId: string | undefined = c.get("requestId");
    const { path: rawPath, query: rawQuery } = rawPathAndQuery(c.req.raw.url);
    const afterP = rawPath.startsWith("/p/") ? rawPath.slice(3) : "";
    const slash = afterP.indexOf("/");
    const rawAlias = slash < 0 ? afterP : afterP.slice(0, slash);
    const rawRest = slash < 0 ? "" : afterP.slice(slash);
    const validAlias = ALIAS_RE.test(rawAlias);
    const alias = validAlias ? rawAlias : "(invalid)";
    const auditExtra = { mode: "passthrough", alias };

    /** Audit row for a denial the shared pipeline does not write itself. */
    const auditDenial = (identity: string, reason: string, path?: string) =>
      deps.audit.log({
        identity,
        action: "proxy.forward",
        path,
        source_ip: sourceIp,
        metadata: { ...auditExtra, method, reason },
        success: false,
      });

    // 2 and 3. Authenticate before the alias result is revealed. The limiter
    // guards passthrough-key verification only (a key carries an AppRole
    // secret_id, which is guessable in principle). JWTs and the root token
    // are verified without it, as on /v1, so junk requests cannot lock a
    // whole source IP out of passthrough.
    const stored = validAlias ? deps.secrets.findByAlias(rawAlias) : null;
    const meta = stored ? { metadata: stored.metadata } : null;
    let auth: AuthContext | null = null;
    let forbidden: string | null = null;
    let charged = false;
    for (const cand of extractCallerCredentials(c.req.raw.headers, meta)) {
      let r: Awaited<ReturnType<typeof verifyKey>>;
      if (cand.startsWith(PASSTHROUGH_KEY_PREFIX)) {
        if (!checkRateLimit(sourceIp)) {
          return gatehouseError(c, 429, "rate_limited", "Too many failed authentication attempts", {
            headers: { "Retry-After": String(retryAfterSeconds(sourceIp)) },
          });
        }
        r = await verifyKey(cand, sourceIp);
        // One charge per request, however many keys it carried.
        if (!r.ok && !charged) {
          recordFailure(sourceIp);
          charged = true;
        }
      } else {
        r = await verifyBearer(cand, sourceIp);
      }
      if (r.ok) {
        auth = r.auth;
        break;
      }
      if (r.status === 403 && forbidden === null) forbidden = r.error;
    }
    if (!auth) {
      auditDenial("anonymous", forbidden !== null ? "forbidden" : "unauthenticated");
      return forbidden !== null
        ? gatehouseError(c, 403, "forbidden", forbidden)
        : gatehouseError(c, 401, "unauthenticated", "A valid Gatehouse credential is required");
    }

    // 4. Unknown alias.
    if (!stored) {
      auditDenial(auth.identity, "unknown_alias");
      return gatehouseError(c, 404, "unknown_alias", "Unknown passthrough alias");
    }
    const secretPath = stored.path;

    // 5. Join the caller's remainder onto the pinned upstream URL.
    const joined = joinUpstreamUrl(stored.metadata.upstream_url ?? "", rawRest, rawQuery);
    if (!joined.ok) {
      auditDenial(auth.identity, "bad_path", secretPath);
      return gatehouseError(c, 400, "bad_path", "Request path cannot be forwarded");
    }
    const upstreamUrl = joined.url;
    const noQuery = new URL(upstreamUrl);
    noQuery.search = "";
    const auditUrl = noQuery.href;

    // 6. Request body, raw bytes, capped whatever the framing.
    let reqBody: Uint8Array<ArrayBuffer> | undefined;
    if (method !== "GET" && method !== "HEAD") {
      const declared = c.req.header("content-length");
      const read =
        declared && parseInt(declared, 10) > maxBodySize ? null : await readCappedBody(c.req.raw.body, maxBodySize);
      if (read === null) {
        auditDenial(auth.identity, "body_too_large", secretPath);
        return gatehouseError(c, 413, "body_too_large", `Request body exceeds ${maxBodySize} bytes`);
      }
      if (read.length > 0) reqBody = read;
    }

    // 7. Every /v1/proxy control, through the shared pipeline.
    const call: ProxyCall = {
      auth,
      sourceIp,
      requestId,
      secretPaths: [secretPath],
      auditUrl,
      resolveUrl: () => upstreamUrl,
      auditAction: "proxy.forward",
      auditExtra,
    };
    const authz = authorizeProxyCall(deps, call);
    if (!authz.ok) return denialResponse(c, authz.denial, (reason) => auditDenial(auth.identity, reason, secretPath));

    const secretValue = authz.resolved.get(secretPath)!;
    const redactValues = secretRedactionValues([secretValue]);

    // Any failure to build the injected headers (a value that cannot be
    // encoded, an invalid header name) is a denial: nothing is forwarded.
    let upstreamHeaders: Headers;
    try {
      upstreamHeaders = buildUpstreamHeaders(c.req.raw.headers, meta, secretValue);
    } catch {
      auditDenial(auth.identity, "inject_failed", secretPath);
      return gatehouseError(c, 403, "forbidden", "The secret for this alias cannot be injected; check its header_name and auth_scheme");
    }

    // 8. Bun closes a connection idle for 10s by default; the scrubber's
    // idle timeout governs this response instead. Under Bun, c.env is the server.
    try {
      (c.env as { timeout?: (req: Request, seconds: number) => void } | undefined)?.timeout?.(c.req.raw, 0);
    } catch {
      /* not running under Bun.serve (tests) */
    }

    // 9. Fetch. max_timeout_ms bounds the time to response headers.
    const limits = getProxyLimits(deps.db);
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, limits.max_timeout_ms);
    // A caller that leaves before the headers arrive takes the upstream call with it.
    const clientSignal = c.req.raw.signal;
    const onClientAbort = () => controller.abort();
    clientSignal?.addEventListener("abort", onClientAbort, { once: true });

    let upstream: Response;
    try {
      const init: RequestInit & { tls?: { rejectUnauthorized: boolean } } = {
        method,
        headers: upstreamHeaders,
        body: reqBody,
        signal: controller.signal,
        redirect: "manual",
      };
      if (authz.tlsInsecure) init.tls = { rejectUnauthorized: false };
      upstream = await fetch(upstreamUrl, init);
    } catch {
      clearTimeout(timer);
      clientSignal?.removeEventListener("abort", onClientAbort);
      const reason = timedOut ? "upstream_timeout" : clientSignal?.aborted ? "client_abort" : "upstream_unreachable";
      recordProxyCall(deps, call, authz);
      recordProxyOutcome(deps, call, authz, { method, failureReason: reason });
      return timedOut
        ? gatehouseError(c, 504, "upstream_timeout", `Upstream did not respond within ${limits.max_timeout_ms}ms`)
        : gatehouseError(c, 502, "upstream_unreachable", "Upstream request failed");
    }
    clearTimeout(timer);
    clientSignal?.removeEventListener("abort", onClientAbort);

    // 10. The call happened: count it.
    recordProxyCall(deps, call, authz);

    const abortUpstream = () => {
      controller.abort();
      upstream.body?.cancel().catch(() => {});
    };
    /** Nothing of this response is passed on: upstream cancelled, one row, a Gatehouse error. */
    const refuse = (reason: string, httpStatus: number, code: string, message: string): Response => {
      abortUpstream();
      recordProxyOutcome(deps, call, authz, { method, failureReason: reason });
      return gatehouseError(c, httpStatus, code, message);
    };

    // 11. A status the Response constructor rejects (outside 200 to 599)
    // cannot be passed on. Caught here, before any stream exists.
    const status = upstream.status;
    if (!Number.isInteger(status) || status < 200 || status > 599) {
      return refuse("invalid_status", 502, "upstream_unreachable", "Upstream returned a status outside 200 to 599");
    }

    // Everything from here to the returned Response runs inside this try, so
    // no throw can escape without an audit row and an upstream abort.
    let body: ReadableStream<Uint8Array> | undefined;
    let setupFailure: string | undefined;
    try {
      // 12. Redirects: same-origin Location rewritten, cross-origin refused.
      // Scrubbed before the rewrite and again after it, so neither form of the
      // value can carry the secret.
      const { headers: responseHeaders, redactions: headerRedactions } = buildResponseHeaders(upstream.headers, redactValues);
      let redactionsSoFar = headerRedactions;
      const location = upstream.headers.get("location");
      if (status >= 300 && status < 400 && location !== null) {
        const before = scrubResponseBody(location, redactValues);
        const rewritten = rewriteLocation(before.body, upstreamUrl, stored.metadata.upstream_url, alias, publicBase);
        if (!rewritten.ok) {
          return refuse(
            "upstream_redirect_cross_origin",
            502,
            "upstream_redirect_cross_origin",
            "Upstream redirected to another origin; not followed"
          );
        }
        const after = scrubResponseBody(rewritten.location, redactValues);
        // The header pass already counted the original value's matches.
        redactionsSoFar += after.count;
        responseHeaders.set("location", after.body);
      }

      // 13. Stream the body through the scrubber. Set up before the status is
      // committed, so a setup failure is still a clean Gatehouse error.
      const bodyless = method === "HEAD" || NULL_BODY_STATUS.has(status);
      const requestHeaderNames = [...upstreamHeaders.keys()];
      if (bodyless) upstream.body?.cancel().catch(() => {});
      body = scrubStream(bodyless ? null : upstream.body, {
        redactValues,
        maxBytes: limits.max_body_bytes,
        idleMs: limits.max_timeout_ms,
        abortUpstream,
        onEnd: (stats) => {
          try {
            const extra: Record<string, string> = { ...auditExtra, bytes_read_upstream: String(stats.bytesIn) };
            if (stats.droppedBytes !== 0) extra.dropped_bytes = String(stats.droppedBytes);
            recordProxyOutcome(deps, { ...call, auditExtra: extra }, authz, {
              method,
              status,
              redactionCount: redactionsSoFar + stats.redactions,
              failureReason: setupFailure ?? (stats.end === "complete" ? undefined : stats.end),
              pattern: { url: auditUrl, requestHeaderNames },
            });
          } catch (err) {
            const name = err instanceof Error ? err.name : typeof err;
            console.error(`[gatehouse:passthrough] outcome audit failed: ${name}`);
          }
        },
      });
      // Upstream content is served from the vault UI's origin: sandbox it so
      // an HTML or SVG body cannot run script there. Replaces any upstream CSP.
      responseHeaders.set("content-security-policy", "sandbox");
      return new Response(bodyless ? null : body, { status, headers: responseHeaders });
    } catch {
      if (!body) return refuse("stream_setup_failed", 500, "internal_error", "Response stream could not be set up");
      // The scrubber exists: cancelling it aborts the upstream and writes the
      // one row (through onEnd) with this reason.
      setupFailure = "stream_setup_failed";
      body.cancel().catch(() => {});
      return gatehouseError(c, 500, "internal_error", "Response stream could not be set up");
    }
  };

  router.all("/:alias", handle);
  router.all("/:alias/*", handle);
  return router;
}

/** Maps a pipeline denial to its D7 response. Writes a row where the pipeline does not. */
function denialResponse(c: Ctx, d: ProxyDenial, audit: (reason: string) => void): Response {
  switch (d.code) {
    case "policy_denied":
      return gatehouseError(c, 403, "forbidden", "No proxy capability on this alias's secret");
    case "domain_blocked":
      return gatehouseError(c, 403, "forbidden", "Upstream host is not in the secret's allowed domains");
    case "gate_blocked": {
      const { error: _e, request_id: _r, code: _c, ...fields } = d.gate.body as Record<string, unknown>;
      const message = typeof d.gate.body.error === "string" ? d.gate.body.error : "Blocked";
      return d.gate.status === 429
        ? gatehouseError(c, 429, "rate_limited", message, { extra: fields, headers: d.gate.headers })
        : gatehouseError(c, 403, "approval_required", message, { extra: fields, headers: d.gate.headers });
    }
    case "gates_unavailable":
      return gatehouseError(c, 500, "gates_unavailable", "Proxy gates are unavailable");
    case "path_prefix_blocked":
      return gatehouseError(c, 403, "path_not_allowed", "Path is not in the secret's allowed path prefixes");
    case "ssrf_blocked":
      return gatehouseError(c, 403, "private_network_blocked", d.reason);
    case "secret_not_found":
      audit("secret_not_found");
      return gatehouseError(c, 404, "unknown_alias", "Unknown passthrough alias");
    case "bad_protocol":
    case "invalid_url":
      audit(d.code);
      return gatehouseError(c, 400, "bad_path", "Request path cannot be forwarded");
  }
}
