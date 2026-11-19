/**
 * Validation for the secret metadata keys that hold lists. Applied on every
 * write path (REST POST and PATCH, bulk import, MCP put) so a list that can
 * never match is rejected when it is saved, not discovered at request time.
 *
 * The rules themselves live in src/ui/list-validate.js, which the web UI's
 * list input also loads, so client and server agree.
 */
import { normalizeList } from "../ui/list-validate.js";

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
