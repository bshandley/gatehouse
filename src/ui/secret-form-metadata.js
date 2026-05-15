// Exported as ES module so bun test can import; also attached to
// window.SecretForm so the inline modal handlers in index.html can call in.

const KNOWN_AUTH_SCHEMES = new Set(["none", "bearer", "basic", "header", "query"]);

export function DEFAULT_STATE() {
  return {
    description: "",
    requires_approval: false,
    auth_scheme: "none",
    header_name: "",
    allowed_domains: "",
    allowed_path_prefixes: "",
    allow_private: false,
    tls_allow_insecure: false,
    rate_limit_per_minute: "",
    auto_approve_from_ip: "",
    auto_approve_ttl_seconds: "",
    custom: [],
  };
}

function writeIfNonEmpty(out, key, value) {
  const trimmed = String(value ?? "").trim();
  if (trimmed) out[key] = trimmed;
}

function writeIfTrue(out, key, value) {
  if (value === true) out[key] = "true";
}

function writeIfPositiveInt(out, key, value) {
  const trimmed = String(value ?? "").trim();
  if (!trimmed) return;
  const n = Number(trimmed);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 1) return;
  out[key] = String(n);
}

export function buildMetadata(state) {
  const out = {};

  writeIfNonEmpty(out, "description", state.description);
  writeIfTrue(out, "requires_approval", state.requires_approval);

  if (state.auth_scheme === "header") {
    const headerName = String(state.header_name ?? "").trim();
    if (!headerName) {
      throw new Error("header_name required when auth_scheme is 'header'");
    }
    out.auth_scheme = "header";
    out.header_name = headerName;
  } else if (state.auth_scheme && state.auth_scheme !== "none") {
    out.auth_scheme = state.auth_scheme;
  }

  writeIfNonEmpty(out, "allowed_domains", state.allowed_domains);
  writeIfNonEmpty(out, "allowed_path_prefixes", state.allowed_path_prefixes);
  writeIfTrue(out, "allow_private", state.allow_private);
  writeIfTrue(out, "tls_allow_insecure", state.tls_allow_insecure);
  writeIfPositiveInt(out, "rate_limit_per_minute", state.rate_limit_per_minute);

  // Auto-approval is paired: TTL alone is meaningless.
  const ip = String(state.auto_approve_from_ip ?? "").trim();
  if (ip) {
    out.auto_approve_from_ip = ip;
    writeIfPositiveInt(out, "auto_approve_ttl_seconds", state.auto_approve_ttl_seconds);
  }

  // Custom rows last; structured fields win on key collision.
  for (const row of state.custom || []) {
    const k = String(row[0] ?? "").trim();
    if (!k) continue;
    if (k in out) continue;
    out[k] = String(row[1] ?? "");
  }

  return out;
}

export function hydrateMetadata(metadata) {
  const s = DEFAULT_STATE();
  const remaining = { ...(metadata || {}) };

  if ("description" in remaining) {
    s.description = String(remaining.description ?? "");
    delete remaining.description;
  }
  if ("requires_approval" in remaining) {
    s.requires_approval = String(remaining.requires_approval).toLowerCase() === "true";
    delete remaining.requires_approval;
  }
  if ("auth_scheme" in remaining) {
    const raw = String(remaining.auth_scheme ?? "");
    if (KNOWN_AUTH_SCHEMES.has(raw) && raw !== "none") {
      s.auth_scheme = raw;
      delete remaining.auth_scheme;
    }
    // Unknown auth_scheme value: leave it in `remaining` so it falls through
    // to custom rows, and keep s.auth_scheme = "none" so the dropdown doesn't lie.
  }
  if ("header_name" in remaining && s.auth_scheme === "header") {
    s.header_name = String(remaining.header_name ?? "");
    delete remaining.header_name;
  }
  if ("allowed_domains" in remaining) {
    s.allowed_domains = String(remaining.allowed_domains ?? "");
    delete remaining.allowed_domains;
  }
  if ("allowed_path_prefixes" in remaining) {
    s.allowed_path_prefixes = String(remaining.allowed_path_prefixes ?? "");
    delete remaining.allowed_path_prefixes;
  }
  if ("allow_private" in remaining) {
    s.allow_private = String(remaining.allow_private).toLowerCase() === "true";
    delete remaining.allow_private;
  }
  if ("tls_allow_insecure" in remaining) {
    s.tls_allow_insecure = String(remaining.tls_allow_insecure).toLowerCase() === "true";
    delete remaining.tls_allow_insecure;
  }
  if ("rate_limit_per_minute" in remaining) {
    s.rate_limit_per_minute = String(remaining.rate_limit_per_minute ?? "");
    delete remaining.rate_limit_per_minute;
  }
  if ("auto_approve_from_ip" in remaining) {
    s.auto_approve_from_ip = String(remaining.auto_approve_from_ip ?? "");
    delete remaining.auto_approve_from_ip;
  }
  if ("auto_approve_ttl_seconds" in remaining) {
    s.auto_approve_ttl_seconds = String(remaining.auto_approve_ttl_seconds ?? "");
    delete remaining.auto_approve_ttl_seconds;
  }

  s.custom = Object.entries(remaining).map(([k, v]) => [k, String(v ?? "")]);
  return s;
}

if (typeof window !== "undefined") {
  window.SecretForm = { buildMetadata, hydrateMetadata, DEFAULT_STATE };
}
