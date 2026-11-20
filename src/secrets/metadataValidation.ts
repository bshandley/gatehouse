/**
 * Validation for the secret metadata keys that hold lists. Applied on every
 * write path (REST POST and PATCH, bulk import, MCP put) so a list that can
 * never match is rejected when it is saved, not discovered at request time.
 *
 * The rules themselves live in src/ui/list-validate.js, which the web UI's
 * list input also loads, so client and server agree.
 */
import { normalizeList, splitList, canonicalizeUpstreamUrl, PASSTHROUGH_ALIAS_PATTERN } from "../ui/list-validate.js";
import { isForbiddenInjectHeader } from "../proxy/injectHeader";
import { hostAllowed } from "../security/domainAllowlist";

/** Metadata key to list kind. */
export const LIST_METADATA_KEYS: Record<string, string> = {
  allowed_domains: "host",
  allowed_path_prefixes: "pathPrefix",
  auto_approve_from_ip: "cidr",
};

export type MetadataValidation<T> = { ok: true; metadata: T } | { ok: false; error: string };

/**
 * Returns a copy of `metadata` with each list key normalised to "a, b, c", or
 * an error naming the key and the first invalid entry. Non-list keys and
 * non-string values are passed through untouched (type checks happen in the
 * caller).
 */
export function validateListMetadata<T extends Record<string, string> | undefined>(
  metadata: T
): MetadataValidation<T> {
  if (!metadata || typeof metadata !== "object") return { ok: true, metadata };
  const out: Record<string, string> = { ...metadata };
  for (const [key, kind] of Object.entries(LIST_METADATA_KEYS)) {
    const raw = out[key];
    if (typeof raw !== "string") continue;
    const result = normalizeList(kind, raw);
    if (!result.ok) {
      return { ok: false, error: `metadata "${key}": invalid entry "${result.entry}" (${result.reason})` };
    }
    out[key] = result.value;
  }
  return { ok: true, metadata: out as T };
}

export { PASSTHROUGH_ALIAS_PATTERN };

/** A key counts as absent when missing or an empty string. */
function present(v: unknown): boolean {
  return v !== undefined && v !== null && v !== "";
}

/**
 * List validation plus passthrough validation (passthrough_alias and
 * upstream_url). Judged on the metadata that will be stored: callers pass the
 * full object they are about to write (PATCH replaces, so the body is it).
 * Replaces validateListMetadata at every write site.
 */
export function validateSecretMetadata<T extends Record<string, string> | undefined>(
  metadata: T
): MetadataValidation<T> {
  const listed = validateListMetadata(metadata);
  if (!listed.ok) return listed;
  const m = listed.metadata as Record<string, unknown> | undefined;
  if (!m || typeof m !== "object") return listed;

  const hasAlias = present(m.passthrough_alias);
  const hasUrl = present(m.upstream_url);
  if (!hasAlias && !hasUrl) return listed;

  if (hasAlias && (typeof m.passthrough_alias !== "string" || !PASSTHROUGH_ALIAS_PATTERN.test(m.passthrough_alias))) {
    return { ok: false, error: 'metadata "passthrough_alias": must match ^[a-z0-9][a-z0-9-]{0,62}$' };
  }
  if (hasAlias && typeof m.header_name === "string" && isForbiddenInjectHeader(m.header_name)) {
    return { ok: false, error: `metadata "header_name": "${m.header_name}" cannot be used with passthrough_alias` };
  }
  if (hasAlias && !hasUrl) {
    return { ok: false, error: 'metadata "passthrough_alias" requires "upstream_url"' };
  }
  if (hasUrl && !hasAlias) {
    return { ok: false, error: 'metadata "upstream_url" requires "passthrough_alias"' };
  }

  const raw = m.upstream_url;
  const bad = (why: string): MetadataValidation<T> => ({ ok: false, error: `metadata "upstream_url": ${why}` });
  if (typeof raw !== "string") return bad("must be a string");
  const parsed = canonicalizeUpstreamUrl(raw);
  if (!parsed.ok) return bad(parsed.reason);
  const canonical = parsed.value;
  const url = new URL(canonical);

  if (present(m.allowed_domains)) {
    const entries = splitList(String(m.allowed_domains));
    if (entries.length > 0 && !hostAllowed(new URL(canonical), entries).allowed) {
      return bad(`host "${url.hostname}" is not permitted by allowed_domains`);
    }
  }
  return { ok: true, metadata: { ...(listed.metadata as Record<string, string>), upstream_url: canonical } as T };
}

