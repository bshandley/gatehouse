// Pure formatters for the Secrets page detail panel.
// No DOM, no globals. Imported by bun test and by index.html.

const KNOWN_AUTH_SCHEMES = new Set(["bearer", "basic", "header", "query"]);

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function referenceChipHtml(path) {
  const ref = `{{secret:${path}}}`;
  const escRef = esc(ref);
  return `<button class="detail-ref-chip" type="button" onclick="window._copySecretRef('${esc(path)}')" title="Click to copy reference">${escRef}</button>`;
}

export function postureChips(metadata) {
  const m = metadata || {};
  const chips = [];

  if (m.auth_scheme && m.auth_scheme !== "none" && KNOWN_AUTH_SCHEMES.has(m.auth_scheme)) {
    const value = m.auth_scheme === "header"
      ? (m.header_name ? `header:${m.header_name}` : "header")
      : m.auth_scheme;
    chips.push({ label: "AUTH", value, variant: "neutral" });
  }

  if (m.allowed_domains) {
    chips.push({ label: "SCOPE", value: m.allowed_domains, variant: "neutral" });
  } else if (m.auth_scheme && m.auth_scheme !== "none") {
    chips.push({ label: "SCOPE", value: "no allowed_domains", variant: "warn" });
  }

  if (m.allowed_path_prefixes) {
    chips.push({ label: "PATHS", value: m.allowed_path_prefixes, variant: "neutral" });
  }

  if (m.rate_limit_per_minute) {
    chips.push({ label: "RATE", value: `${m.rate_limit_per_minute} / min`, variant: "neutral" });
  }

  if (m.requires_approval === "true") {
    chips.push({ label: "APPROVAL", value: "required", variant: "accent" });
  }

  if (m.allow_private === "true") {
    chips.push({ label: "PRIVATE", value: "private IPs ok", variant: "warn" });
  }

  if (m.tls_allow_insecure === "true") {
    chips.push({ label: "TLS", value: "insecure TLS ok", variant: "warn" });
  }

  if (m.auto_approve_from_ip) {
    chips.push({ label: "AUTO-IP", value: m.auto_approve_from_ip, variant: "warn" });
  }

  if (m.auto_approve_ttl_seconds) {
    chips.push({ label: "AUTO-TTL", value: `${m.auto_approve_ttl_seconds}s`, variant: "warn" });
  }

  return chips;
}

export function postureChipsHtml(metadata) {
  const chips = postureChips(metadata);
  if (!chips.length) return "";
  const items = chips.map(c => {
    const cls = c.variant === "accent" ? "posture-chip is-accent"
      : c.variant === "warn" ? "posture-chip is-warn"
      : "posture-chip";
    return `<div class="${cls}"><div class="posture-chip-label">${esc(c.label)}</div><div class="posture-chip-value" title="${esc(c.value)}">${esc(c.value)}</div></div>`;
  }).join("");
  return `<div class="detail-section"><div class="detail-section-heading">POSTURE</div><div class="posture-chips">${items}</div></div>`;
}

export function relativeTime(iso) {
  if (!iso) return "";
  const d = new Date(String(iso).endsWith("Z") ? iso : iso + "Z");
  const ms = Date.now() - d.getTime();
  if (!Number.isFinite(ms)) return "";
  if (ms < 5_000) return "now";
  if (ms < 60_000) return `${Math.floor(ms / 1000)}s ago`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
  if (ms < 7 * 86_400_000) return `${Math.floor(ms / 86_400_000)}d ago`;
  if (ms < 30 * 86_400_000) return `${Math.floor(ms / (7 * 86_400_000))}w ago`;
  return `${Math.floor(ms / (30 * 86_400_000))}mo ago`;
}

export function formatActivityRow(entry) {
  const t = relativeTime(entry.timestamp);
  const id = entry.identity ? esc(entry.identity) : "-";
  const ok = entry.success;
  const tag = ok
    ? `<span class="activity-row-tag is-ok">ok</span>`
    : `<span class="activity-row-tag is-fail">fail</span>`;
  return `<div class="activity-row"><span class="activity-row-time">${esc(t)}</span><span class="activity-row-id"><span style="font-family:var(--font-mono);color:var(--text-primary)">${esc(entry.action || "")}</span> <span style="color:var(--text-tertiary);margin-left:8px">${id}</span></span>${tag}</div>`;
}

export function formatLeaseRow(lease, requiresApproval) {
  const id = lease.identity ? esc(lease.identity) : "-";
  const exp = lease.expires_at ? esc(formatLeaseExpiry(lease.expires_at)) : "-";
  const gated = (requiresApproval && lease.status === "approved")
    ? ` <span class="activity-row-tag is-meta">(gated)</span>`
    : "";
  return `<div class="activity-row"><span class="activity-row-id">${id}${gated}</span><span></span><span class="activity-row-time">expires ${exp}</span></div>`;
}

function formatLeaseExpiry(iso) {
  if (!iso) return "-";
  try {
    const d = new Date(String(iso).endsWith("Z") ? iso : iso + "Z");
    return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch {
    return iso;
  }
}

export function emptyStateStats(allSecrets) {
  const total = allSecrets.length;
  let gated = 0;
  let touchedThisWeek = 0;
  const oneWeekAgo = Date.now() - 7 * 86_400_000;
  for (const s of allSecrets) {
    if (s.metadata && s.metadata.requires_approval === "true") gated++;
    if (s.updated_at) {
      const d = new Date(String(s.updated_at).endsWith("Z") ? s.updated_at : s.updated_at + "Z");
      if (d.getTime() >= oneWeekAgo) touchedThisWeek++;
    }
  }
  return { total, gated, touchedThisWeek };
}

export function emptyStateStatsLine(allSecrets) {
  const s = emptyStateStats(allSecrets);
  if (s.total === 0) return "";
  return `<div class="detail-empty-stats">${s.total} secrets . ${s.gated} require approval . ${s.touchedThisWeek} touched this week</div>`;
}

export function treeAuthChip(metadata) {
  const m = metadata || {};
  if (!m.auth_scheme || m.auth_scheme === "none") return "";
  if (!KNOWN_AUTH_SCHEMES.has(m.auth_scheme)) return "";
  const value = m.auth_scheme === "header"
    ? (m.header_name ? `header:${m.header_name}` : "header")
    : m.auth_scheme;
  return `<span class="tree-item-auth">[${esc(value)}]</span>`;
}

// Hygiene thresholds (sub-project D). Constants in v1.
const STALE_MS = 90 * 86_400_000;        // 90 days unused
const OLD_MS = 18 * 30 * 86_400_000;     // ~18 months since update

function _parseTs(iso) {
  if (!iso) return null;
  const d = new Date(String(iso).endsWith("Z") ? iso : iso + "Z");
  const t = d.getTime();
  return Number.isFinite(t) ? t : null;
}

export function hygieneFlags(secret) {
  const now = Date.now();
  // Staleness uses last access, falling back to updated_at so a freshly
  // written but never-read secret is not flagged (matches the server query).
  const access = _parseTs(secret && secret.last_accessed_at) ?? _parseTs(secret && secret.updated_at);
  const updated = _parseTs(secret && secret.updated_at);
  const stale = access != null ? now - access > STALE_MS : false;
  const old = updated != null ? now - updated > OLD_MS : false;
  return { stale, old };
}

export function hygieneBadgeHtml(secret) {
  const f = hygieneFlags(secret);
  let html = "";
  if (f.stale) {
    html += ` <span class="badge" style="font-size:9px;background:rgba(251,191,36,0.12);color:var(--warning)" title="Not accessed in over 90 days">stale</span>`;
  }
  if (f.old) {
    html += ` <span class="badge" style="font-size:9px;background:rgba(251,191,36,0.12);color:var(--warning)" title="Not updated in over 18 months">18mo+</span>`;
  }
  return html;
}

export function formatHygieneSummary(hygiene) {
  if (!hygiene) return "";
  const parts = [];
  if (hygiene.stale_90d > 0) parts.push(`${hygiene.stale_90d} unused 90d`);
  if (hygiene.older_18mo > 0) parts.push(`${hygiene.older_18mo} over 18mo`);
  return parts.join(", ");
}

if (typeof window !== "undefined") {
  window.SecretDetail = {
    referenceChipHtml,
    postureChips,
    postureChipsHtml,
    relativeTime,
    formatActivityRow,
    formatLeaseRow,
    emptyStateStats,
    emptyStateStatsLine,
    treeAuthChip,
    hygieneFlags,
    hygieneBadgeHtml,
    formatHygieneSummary,
  };
}
