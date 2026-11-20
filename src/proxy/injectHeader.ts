const FORBIDDEN_INJECT = new Set([
  "host",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "content-length",
  "forwarded",
  "via",
  "x-real-ip",
  "cookie",
]);

/** Headers that can never be a credential slot for passthrough injection. */
export function isForbiddenInjectHeader(name: string): boolean {
  const n = name.trim().toLowerCase();
  return FORBIDDEN_INJECT.has(n) || n.startsWith("x-forwarded-");
}
