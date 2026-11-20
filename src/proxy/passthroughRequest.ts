import { resolveAutoInject } from "../api/proxy";
import { scrubResponseBody } from "../security/ssrf";
import { isForbiddenInjectHeader } from "./injectHeader";

export { isForbiddenInjectHeader };

/** Thrown when the secret cannot be injected safely; the route denies the request. */
export class PassthroughInjectError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PassthroughInjectError";
  }
}

type Meta = { metadata?: Record<string, string> } | null;

/**
 * Backstops, not product limits: the caller maps a failed join to
 * `400 bad_path`.
 * Longest remainder (path after the alias) the join accepts.
 */
const MAX_REST_LENGTH = 8192;
/** Longest query string the join accepts. */
const MAX_QUERY_LENGTH = 16384;

// eslint-disable-next-line no-control-regex
const CONTROL_OR_SPACE = /[\u0000- \u007f]/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;

/**
 * Join the pinned upstream URL with the caller-controlled remainder.
 *
 * Rules for rawRest (decode exactly once, per segment):
 *  - "" yields upstream_url itself; otherwise it must start with "/".
 *  - Rejected raw: backslash, "#", "?", any control character or space, length
 *    over 8192.
 *  - Each segment must percent-decode (once) without error. After that single
 *    decode a segment is rejected if it is "." or "..", if the part before the
 *    first ";" (path parameters, which Tomcat and others strip) is "." or "..",
 *    if it contains "/", "\" or a control character, or if it still contains
 *    "%2e", "%2f" or "%5c" in any case (double encoding that a second decode
 *    on the upstream would turn into traversal). A literal percent sign
 *    ("%25") is fine.
 * rawQuery is "" or starts with "?" and is appended byte for byte; it may not
 * contain "#", a control character or a space.
 * Finally the origin and path prefix of the result are re-checked.
 */
export function joinUpstreamUrl(
  upstreamUrl: string,
  rawRest: string,
  rawQuery: string
): { ok: true; url: string } | { ok: false } {
  const fail = { ok: false } as const;
  let base: URL;
  try {
    base = new URL(upstreamUrl);
  } catch {
    return fail;
  }
  if (rawRest.length > MAX_REST_LENGTH || rawQuery.length > MAX_QUERY_LENGTH) return fail;
  if (rawRest !== "" && !rawRest.startsWith("/")) return fail;
  if (rawQuery !== "" && !rawQuery.startsWith("?")) return fail;
  if (/[\\#?]/.test(rawRest) || CONTROL_OR_SPACE.test(rawRest)) return fail;
  if (rawQuery.includes("#") || CONTROL_OR_SPACE.test(rawQuery)) return fail;

  for (const seg of rawRest.split("/")) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(seg);
    } catch {
      return fail;
    }
    if (decoded === "." || decoded === "..") return fail;
    const beforeParams = decoded.split(";")[0];
    if (beforeParams === "." || beforeParams === "..") return fail;
    if (/%(2e|2f|5c)/i.test(decoded)) return fail;
    if (decoded.includes("/") || decoded.includes("\\") || CONTROL.test(decoded)) return fail;
  }

  const prefix = base.pathname.replace(/\/+$/, "");
  const candidate = `${base.origin}${prefix}${rawRest}${rawQuery}`;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return fail;
  }
  if (parsed.origin !== base.origin) return fail;
  if (parsed.username || parsed.password || parsed.hash) return fail;
  if (prefix && parsed.pathname !== prefix && !parsed.pathname.startsWith(prefix + "/")) return fail;
  return { ok: true, url: parsed.href };
}

const KNOWN_SCHEMES = /^(Bearer|Basic|Token|Digest|ApiKey)$/i;

/** Split "Scheme rest" tolerating extra spaces. Returns null scheme for a bare token. */
function splitScheme(value: string, extraScheme?: string): { scheme: string | null; rest: string } {
  const v = value.trim();
  const m = /^(\S+)\s+(.*)$/.exec(v);
  if (m) {
    const s = m[1];
    if (KNOWN_SCHEMES.test(s) || (extraScheme && s.toLowerCase() === extraScheme.toLowerCase())) {
      return { scheme: s, rest: m[2].trim() };
    }
  }
  // A lone scheme word ("Basic", "Bearer") carries no credential.
  if (KNOWN_SCHEMES.test(v)) return { scheme: v, rest: "" };
  return { scheme: null, rest: v };
}

function basicPassword(encoded: string): string | null {
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(encoded.trim())) return null;
  try {
    const decoded = Buffer.from(encoded.trim(), "base64").toString("utf8");
    const idx = decoded.indexOf(":");
    if (idx < 0) return null;
    return decoded.slice(idx + 1);
  } catch {
    return null;
  }
}

/** Candidate caller credentials in spec D3 order, de-duplicated. */
export function extractCallerCredentials(headers: Headers, meta: Meta): string[] {
  const out: string[] = [];
  const add = (v: string | null | undefined) => {
    if (v && !out.includes(v)) out.push(v);
  };

  if (meta) {
    const headerName = meta.metadata?.header_name || "Authorization";
    let raw: string | null = null;
    try {
      raw = headers.get(headerName);
    } catch {
      // Not a valid header name (stored before validation): no caller
      // credential can be there. The other locations are still read, and
      // injection into that name fails closed later.
    }
    if (raw) {
      const { scheme, rest } = splitScheme(raw, meta.metadata?.auth_scheme || undefined);
      if (scheme && scheme.toLowerCase() === "basic") add(basicPassword(rest));
      else add(rest);
    }
  }

  const auth = headers.get("authorization");
  if (auth) {
    const { scheme, rest } = splitScheme(auth);
    if (scheme && scheme.toLowerCase() === "bearer") add(rest);
  }

  const apiKey = headers.get("x-api-key");
  if (apiKey) add(apiKey.trim());
  return out;
}

/** Same as resolveAutoInject, except Basic with a schemeless value is base64-encoded. */
export function resolvePassthroughInject(
  secretValue: string,
  meta: Meta
): { headerName: string; headerValue: string } {
  const base = resolveAutoInject(secretValue, meta);
  const scheme = meta?.metadata?.auth_scheme;
  const hasScheme = /^(Bearer|Basic|Token|Digest|ApiKey)\s/i.test(secretValue);
  if (scheme && scheme.toLowerCase() === "basic" && !hasScheme) {
    let encoded: string;
    try {
      // Latin1 only on purpose: secretRedactionValues registers only this form.
      encoded = btoa(secretValue);
    } catch {
      throw new PassthroughInjectError("secret value cannot be encoded for Basic auth (non-Latin1 characters)");
    }
    return { headerName: base.headerName, headerValue: `${scheme} ${encoded}` };
  }
  return base;
}

const HOP_BY_HOP = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

function connectionTokens(headers: Headers): Set<string> {
  const out = new Set<string>();
  const c = headers.get("connection");
  if (c) {
    for (const t of c.split(",")) {
      const n = t.trim().toLowerCase();
      if (n) out.add(n);
    }
  }
  return out;
}

const REQUEST_STRIP = new Set([
  ...HOP_BY_HOP,
  "host",
  "content-length",
  "x-real-ip",
  "forwarded",
  "via",
  "authorization",
  "x-api-key",
  // The scrubber cannot recognise a fragment of a secret, so the upstream
  // must always answer with the whole body: no ranged requests.
  "range",
  "if-range",
  // The fetch decodes only the encodings it asks for itself. A caller-chosen
  // encoding it cannot decode would reach the scrubber still encoded.
  "accept-encoding",
  // The request body is read in full before the fetch, so a 100-continue
  // handshake has nothing left to negotiate.
  "expect",
]);

/** Request headers for the upstream: caller headers minus the strip list, plus the injected credential. */
export function buildUpstreamHeaders(headers: Headers, meta: Meta, secretValue: string): Headers {
  const inject = resolvePassthroughInject(secretValue, meta);
  if (isForbiddenInjectHeader(inject.headerName)) {
    throw new PassthroughInjectError(`header "${inject.headerName}" cannot be used for credential injection`);
  }
  const injectName = inject.headerName.toLowerCase();
  const named = connectionTokens(headers);
  const out = new Headers();
  headers.forEach((value, name) => {
    const n = name.toLowerCase();
    if (REQUEST_STRIP.has(n) || n.startsWith("x-forwarded-") || named.has(n) || n === injectName) return;
    out.append(name, value);
  });
  out.set(inject.headerName, inject.headerValue);
  return out;
}

const RESPONSE_STRIP = new Set([
  ...HOP_BY_HOP,
  "content-length",
  "content-encoding",
  "x-gatehouse-error",
]);

/** Response headers for the caller, each value scrubbed. */
export function buildResponseHeaders(
  upstream: Headers,
  redactValues: string[]
): { headers: Headers; redactions: number } {
  const out = new Headers();
  let redactions = 0;
  const named = connectionTokens(upstream);
  const scrub = (v: string) => {
    const r = scrubResponseBody(v, redactValues);
    redactions += r.count;
    return r.body;
  };
  upstream.forEach((value, name) => {
    const n = name.toLowerCase();
    if (n === "set-cookie" || RESPONSE_STRIP.has(n) || named.has(n)) return;
    out.append(name, scrub(value));
  });
  if (!named.has("set-cookie")) for (const c of upstream.getSetCookie()) out.append("set-cookie", scrub(c));
  return { headers: out, redactions };
}

/** Rewrites a same-origin Location to /p/<alias>/..., or reports cross-origin. */
export function rewriteLocation(
  location: string,
  requestUrl: string,
  upstreamUrl: string,
  alias: string,
  publicBase: string
): { ok: true; location: string } | { ok: false } {
  let target: URL;
  let base: URL;
  try {
    base = new URL(upstreamUrl);
    target = new URL(location, requestUrl);
  } catch {
    return { ok: false };
  }
  if (target.origin !== base.origin) return { ok: false };
  const prefix = base.pathname.replace(/\/+$/, "");
  const path = target.pathname;
  if (path !== prefix && !path.startsWith(prefix + "/")) return { ok: false };
  return {
    ok: true,
    location: `${publicBase}/p/${alias}${path.slice(prefix.length)}${target.search}${target.hash}`,
  };
}
