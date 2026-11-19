// Validation rules for multi-value fields. Shared by the browser (served at
// /ui/list-validate.js, used by the list input) and the server (imported by
// the secret metadata validation), so the two cannot drift.
//
// No DOM access at import time.

/**
 * Split free text into entries and dedupe. By default commas and any
 * whitespace separate. With mode "comma", only commas and newlines separate
 * and an entry may contain spaces (for values like "ALL PRIVILEGES").
 */
export function splitList(text, mode = "any") {
  if (typeof text !== "string") return [];
  const seen = new Set();
  const out = [];
  const parts = mode === "comma" ? text.split(/[,\n\r]+/) : text.split(/[\s,]+/);
  for (const part of parts) {
    const raw = mode === "comma" ? part.trim().replace(/\s+/g, " ") : part;
    if (!raw || seen.has(raw)) continue;
    seen.add(raw);
    out.push(raw);
  }
  return out;
}

/** Kinds whose entries may contain spaces, so only commas and newlines split. */
export function splitModeFor(kind) {
  return kind === "phrase" ? "comma" : "any";
}

function isIPv4(s) {
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function isIPv6(s) {
  if (!s.includes(":") || !/^[0-9a-fA-F:.]+$/.test(s)) return false;
  const halves = s.split("::");
  if (halves.length > 2) return false;
  const groupsOf = (h) => (h === "" ? [] : h.split(":"));
  const head = groupsOf(halves[0]);
  const tail = halves.length === 2 ? groupsOf(halves[1]) : [];
  const all = [...head, ...tail];
  let count = 0;
  for (let i = 0; i < all.length; i++) {
    const g = all[i];
    // An embedded IPv4 address is allowed only as the last group.
    if (g.includes(".")) {
      if (i !== all.length - 1 || !isIPv4(g)) return false;
      count += 2;
      continue;
    }
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return false;
    count += 1;
  }
  return halves.length === 2 ? count < 8 : count === 8;
}

function validateCidr(entry) {
  const slash = entry.indexOf("/");
  const addr = slash === -1 ? entry : entry.slice(0, slash);
  const len = slash === -1 ? null : entry.slice(slash + 1);
  const v4 = isIPv4(addr);
  const v6 = !v4 && isIPv6(addr);
  if (!v4 && !v6) return "not an IP address or CIDR range";
  if (len !== null) {
    const max = v4 ? 32 : 128;
    if (!/^\d{1,3}$/.test(len) || Number(len) > max) return `prefix length must be 0 to ${max}`;
  }
  return null;
}

const LABEL = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?";
const HOSTNAME_RE = new RegExp(`^${LABEL}(?:\\.${LABEL})*$`);

function validPort(p) {
  return /^\d{1,5}$/.test(p) && Number(p) >= 1 && Number(p) <= 65535;
}

function validateHost(entry) {
  if (entry.includes("://")) return "enter a host, not a URL (drop the scheme)";

  // CIDR range, e.g. 10.0.0.0/24. A slash is otherwise a path, which is not a host.
  if (entry.includes("/")) {
    return validateCidr(entry) === null ? null : "enter a host, not a path (or a valid CIDR range)";
  }

  // Bracketed IPv6, optionally with a port.
  if (entry.startsWith("[")) {
    const close = entry.indexOf("]");
    if (close === -1) return "missing closing bracket";
    if (!isIPv6(entry.slice(1, close))) return "not a valid IPv6 address";
    const rest = entry.slice(close + 1);
    if (rest === "") return null;
    if (!rest.startsWith(":") || !validPort(rest.slice(1))) return "port must be 1 to 65535";
    return null;
  }

  // Bare IPv6 (no port possible without brackets).
  if ((entry.match(/:/g) || []).length >= 2) {
    return isIPv6(entry) ? null : "not a valid IPv6 address (use [addr]:port for a port)";
  }

  let host = entry;
  const colon = entry.lastIndexOf(":");
  if (colon !== -1) {
    if (!validPort(entry.slice(colon + 1))) return "port must be 1 to 65535";
    host = entry.slice(0, colon);
  }

  if (host.startsWith("*.")) host = host.slice(2);
  if (host.includes("*")) return "a wildcard is only allowed as a leading *.";
  if (host.length === 0 || host.length > 253) return "not a valid hostname";
  if (/^[\d.]+$/.test(host)) return isIPv4(host) ? null : "not a valid IPv4 address";
  return HOSTNAME_RE.test(host) ? null : "not a valid hostname";
}

function validatePathPrefix(entry) {
  if (!entry.startsWith("/")) return "must start with /";
  if (/[?#]/.test(entry)) return "must be a path only, without ? or #";
  return null;
}

function validatePolicyPath(entry) {
  return /^[A-Za-z0-9/_*-]+$/.test(entry) ? null : "use letters, digits, / _ - and * only";
}

function validateWord(entry) {
  return /^[^\s,]+$/.test(entry) ? null : "must not be empty or contain spaces or commas";
}

function validatePhrase(entry) {
  return /^[^,\n\r]+$/.test(entry) && entry.trim() !== "" ? null : "must not be empty or contain commas";
}

const VALIDATORS = {
  phrase: validatePhrase,
  cidr: validateCidr,
  host: validateHost,
  pathPrefix: validatePathPrefix,
  policyPath: validatePolicyPath,
  word: validateWord,
};

export const KINDS = Object.keys(VALIDATORS);

/** Returns null when the entry is valid for the kind, or a short reason. */
export function validateEntry(kind, entry) {
  const fn = VALIDATORS[kind];
  if (!fn) throw new Error(`unknown list kind: ${kind}`);
  if (typeof entry !== "string" || entry === "") return "must not be empty";
  return fn(entry);
}

/** Split text and validate every entry. */
export function parseList(kind, text) {
  const entries = splitList(text, splitModeFor(kind));
  const errors = [];
  for (const entry of entries) {
    const reason = validateEntry(kind, entry);
    if (reason) errors.push({ entry, reason });
  }
  return { entries, errors };
}

/**
 * Canonical stored form of a list. Returns { ok: true, value } or
 * { ok: false, entry, reason } for the first invalid entry.
 */
export function normalizeList(kind, text, separator = ", ") {
  const { entries, errors } = parseList(kind, text);
  if (errors.length > 0) return { ok: false, entry: errors[0].entry, reason: errors[0].reason };
  return { ok: true, value: entries.join(separator) };
}

if (typeof window !== "undefined") {
  window.ListValidate = { splitList, splitModeFor, validateEntry, parseList, normalizeList, KINDS };
}
