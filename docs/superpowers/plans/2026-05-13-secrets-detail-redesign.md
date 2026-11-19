# Secrets Page Detail Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the flat metadata-table detail panel on the Secrets page with a five-block structured layout (Identity, Posture, Activity, Value, Actions) plus an unknown-metadata escape hatch, and surface an auth chip in the tree.

**Architecture:** Pure formatters (`postureChipsHtml`, `formatActivityRow`, `relativeTime`, `emptyStateStats`, `treeAuthChip`, `referenceChipHtml`) live in a new ES module `src/ui/secret-detail-render.js` served via `GET /ui/secret-detail-render.js` and attached to `window.SecretDetail`. The inline `selectSecret()` in `index.html` uses the helpers to render the new blocks synchronously and then kicks off two parallel fetches (`/v1/lease?path=` and `/v1/audit?path=`) that paint the Activity block when they return. No server changes.

**Tech Stack:** Bun runtime, Hono router, vanilla JS for the SPA. Tests run under `bun test`. New JS module is plain JS (not TypeScript) so the browser loads it without a build step.

**Spec:** `docs/superpowers/specs/2026-05-13-secrets-detail-redesign-design.md` (commit `6cb336c`).

---

## Implementation notes

- The codebase forbids em dashes (U+2014) and en dashes (U+2013) anywhere: code, comments, commit messages, doc strings, CHANGELOG. Use colons or rephrase. Scan every new file with `grep -P '[\x{2014}\x{2013}]' <file>` before committing (returns no matches when the file is clean).
- After every commit, push to Gitea:
  `git push origin main`
  Do NOT push to GitHub. There is a separate `scripts/sync-to-github.ts` for the curated GitHub mirror; do not run it.
- All new JS module code is plain JavaScript (`.js`), not TypeScript. The browser loads it directly via `<script type="module">`; bun test imports it via filesystem path.
- Helpers must be pure (DOM-free) so bun test can exercise them. DOM glue lives in `index.html`.
- Existing reusable patterns already in the codebase: `.toggle`, `<select class="input">`, `.kv-row`, `.form-group`, `.modal-overlay`, `.btn-primary`, `.btn-ghost`, `.btn-danger`, `.meta-table`, `.advanced-details`, `.form-subheading`, `.form-help`, `var(--accent)`, `var(--warning)`, `var(--text-tertiary)`. Reuse these; do not introduce new equivalents.
- The existing `fmtTime(iso)` returns absolute timestamps. The new feature needs a relative-time formatter (`2h ago`, `3d ago`). Add it as `relativeTime(iso)` in the new module and use it for the stamps line + audit-event rows.
- Test runner is `bun test`. Tests live in `test/`. The new test file is `test/secretDetailRender.test.ts`. The existing test suite is 526 tests at the start of this work; all must continue to pass.

## File map

**Created:**
- `src/ui/secret-detail-render.js`: pure helpers `referenceChipHtml`, `postureChips`, `postureChipsHtml`, `relativeTime`, `formatActivityRow`, `emptyStateStats`, `treeAuthChip`, `escAttr` (a private helper if needed). Window-attach via `window.SecretDetail = { ... }`.
- `test/secretDetailRender.test.ts`: unit tests for each helper.

**Modified:**
- `src/index.ts` (after the existing `/ui/secret-form-metadata.js` route, around line 207): add `GET /ui/secret-detail-render.js` route.
- `src/ui/index.html`:
  - Head: add `<script type="module" src="/ui/secret-detail-render.js"></script>` alongside the existing form-metadata script tag (around line 1811).
  - CSS block (around line 920, immediately before the `.kv-row` rule or after the `.reveal-value` block): add the new `.detail-identity`, `.detail-ref-chip`, `.detail-description`, `.detail-stamps`, `.detail-section`, `.detail-section-heading`, `.detail-section-summary`, `.posture-chips`, `.posture-chip`, `.posture-chip-label`, `.posture-chip-value`, `.activity-subsection`, `.activity-subhead`, `.activity-row`, `.activity-row-time`, `.activity-row-id`, `.activity-row-tag`, `.tree-item-auth`, `.detail-empty-stats` rules.
  - `selectSecret(path)` (around line 3172): rewrite the static-secret branch (the dynamic branch at line 3181 stays unchanged). Use `window.SecretDetail.*` helpers; add `_loadActivityForPath(path, requiresApproval)` async hook.
  - `renderSecretTree(secrets)` (around line 3134): append `window.SecretDetail.treeAuthChip(item.metadata)` to each tree row after the name.
  - `loadSecrets()` (around line 3107): update the empty-state HTML to include the stats line above the existing icon when there are secrets selected to be deselected.
  - The `secret-detail-empty` initial markup at line 2035 (in the static page HTML): leave alone; `loadSecrets` overwrites it.
- `src/version.ts`: bump to `0.16.0`.
- `CHANGELOG.md`: add `0.16.0` entry.

---

## Task 1: Create the pure-helper module and its tests

**Files:**
- Create: `src/ui/secret-detail-render.js`
- Create: `test/secretDetailRender.test.ts`

The module exports nine functions, all pure (no DOM access, no window globals consumed inside the function bodies):

- `referenceChipHtml(path: string): string` returns a `<button>` HTML string with class `detail-ref-chip` and an inline onclick that copies `{{secret:<path>}}` to the clipboard via `navigator.clipboard.writeText` (with `document.execCommand('copy')` fallback) and shows a toast.
- `postureChips(metadata: Record<string, string>): Array<{ label: string, value: string, variant: 'neutral'|'accent'|'warn' }>` returns the ordered chip set per the spec, omitting absent/default values. Includes the inferred warning chip when `auth_scheme` is set but `allowed_domains` is absent.
- `postureChipsHtml(metadata: Record<string, string>): string` returns the wrapping container HTML for the chip block, or an empty string when there are zero chips.
- `relativeTime(iso: string | null | undefined): string` returns `now`, `Ns`, `Nm ago`, `Nh ago`, `Nd ago`, `Nw ago`, or `Nmo ago`. Returns empty string when iso is falsy.
- `formatActivityRow(entry: { timestamp, action, identity, success }): string` returns the HTML for one row of the events sub-block.
- `formatLeaseRow(lease: { identity, expires_at, status, secret_path, path }, requiresApproval: boolean): string` returns the HTML for one row of the leases sub-block; appends a `(gated)` tag when `requiresApproval && status === 'approved'`.
- `emptyStateStats(allSecrets: Array<{ metadata, updated_at }>): { total: number, gated: number, touchedThisWeek: number }` derives the counts.
- `emptyStateStatsLine(allSecrets): string` returns the rendered HTML for the stats line (or empty string when total is 0).
- `treeAuthChip(metadata: Record<string, string> | undefined): string` returns the HTML `<span>` for the auth chip when `metadata.auth_scheme` is present and not `'none'`, otherwise empty string.

- [ ] **Step 1: Create the test file with all behavioral cases**

Create `test/secretDetailRender.test.ts`:

```typescript
import { describe, test, expect } from "bun:test";
import {
  referenceChipHtml,
  postureChips,
  postureChipsHtml,
  relativeTime,
  formatActivityRow,
  formatLeaseRow,
  emptyStateStats,
  emptyStateStatsLine,
  treeAuthChip,
} from "../src/ui/secret-detail-render.js";

describe("referenceChipHtml", () => {
  test("includes the {{secret:<path>}} text verbatim", () => {
    const html = referenceChipHtml("api-keys/anthropic");
    expect(html).toContain("{{secret:api-keys/anthropic}}");
    expect(html).toContain("detail-ref-chip");
  });

  test("HTML-escapes the path", () => {
    const html = referenceChipHtml('weird"path');
    expect(html).not.toContain('weird"path');
    expect(html).toContain("&quot;");
  });
});

describe("postureChips", () => {
  test("empty metadata produces no chips", () => {
    expect(postureChips({})).toEqual([]);
  });

  test("bearer auth + allowed_domains produces AUTH and SCOPE chips", () => {
    const chips = postureChips({ auth_scheme: "bearer", allowed_domains: "api.anthropic.com" });
    expect(chips).toEqual([
      { label: "AUTH", value: "bearer", variant: "neutral" },
      { label: "SCOPE", value: "api.anthropic.com", variant: "neutral" },
    ]);
  });

  test("header auth includes header_name in the AUTH value", () => {
    const chips = postureChips({ auth_scheme: "header", header_name: "X-API-Key", allowed_domains: "x" });
    expect(chips[0]).toEqual({ label: "AUTH", value: "header:X-API-Key", variant: "neutral" });
  });

  test("auth without allowed_domains adds inferred warning chip", () => {
    const chips = postureChips({ auth_scheme: "bearer" });
    expect(chips).toContainEqual({ label: "SCOPE", value: "no allowed_domains", variant: "warn" });
  });

  test("requires_approval=true is an accent chip", () => {
    const chips = postureChips({ requires_approval: "true" });
    expect(chips).toContainEqual({ label: "APPROVAL", value: "required", variant: "accent" });
  });

  test("requires_approval=false omits the chip", () => {
    expect(postureChips({ requires_approval: "false" })).toEqual([]);
  });

  test("allow_private=true is a warn chip", () => {
    const chips = postureChips({ allow_private: "true" });
    expect(chips).toContainEqual({ label: "PRIVATE", value: "private IPs ok", variant: "warn" });
  });

  test("tls_allow_insecure=true is a warn chip", () => {
    const chips = postureChips({ tls_allow_insecure: "true" });
    expect(chips).toContainEqual({ label: "TLS", value: "insecure TLS ok", variant: "warn" });
  });

  test("rate_limit_per_minute renders as Nrate per min", () => {
    const chips = postureChips({ rate_limit_per_minute: "60" });
    expect(chips).toContainEqual({ label: "RATE", value: "60 / min", variant: "neutral" });
  });

  test("auto-approval IP + TTL render as separate warn chips", () => {
    const chips = postureChips({ auto_approve_from_ip: "10.0.0.5", auto_approve_ttl_seconds: "3600" });
    expect(chips).toContainEqual({ label: "AUTO-IP", value: "10.0.0.5", variant: "warn" });
    expect(chips).toContainEqual({ label: "AUTO-TTL", value: "3600s", variant: "warn" });
  });

  test("path prefixes render as PATHS chip", () => {
    const chips = postureChips({ allowed_path_prefixes: "/v1/, /v2/" });
    expect(chips).toContainEqual({ label: "PATHS", value: "/v1/, /v2/", variant: "neutral" });
  });

  test("full posture produces correct ordering", () => {
    const chips = postureChips({
      auth_scheme: "bearer",
      allowed_domains: "api.anthropic.com",
      allowed_path_prefixes: "/v1/",
      rate_limit_per_minute: "60",
      requires_approval: "true",
    });
    expect(chips.map(c => c.label)).toEqual(["AUTH", "SCOPE", "PATHS", "RATE", "APPROVAL"]);
  });
});

describe("postureChipsHtml", () => {
  test("returns empty string when no chips", () => {
    expect(postureChipsHtml({})).toBe("");
  });

  test("wraps chips in a posture-chips container with section heading", () => {
    const html = postureChipsHtml({ auth_scheme: "bearer", allowed_domains: "x" });
    expect(html).toContain("POSTURE");
    expect(html).toContain("posture-chips");
    expect(html).toContain("posture-chip");
    expect(html).toContain("AUTH");
    expect(html).toContain("bearer");
  });

  test("warn variant renders the is-warn class", () => {
    const html = postureChipsHtml({ allow_private: "true" });
    expect(html).toContain("is-warn");
  });

  test("accent variant renders the is-accent class", () => {
    const html = postureChipsHtml({ requires_approval: "true" });
    expect(html).toContain("is-accent");
  });
});

describe("relativeTime", () => {
  const now = Date.now();
  const iso = (offsetMs: number) => new Date(now - offsetMs).toISOString();

  test("returns empty string for falsy input", () => {
    expect(relativeTime("")).toBe("");
    expect(relativeTime(null)).toBe("");
    expect(relativeTime(undefined)).toBe("");
  });

  test("returns 'now' for very recent times", () => {
    expect(relativeTime(iso(500))).toBe("now");
  });

  test("returns Ns for seconds", () => {
    expect(relativeTime(iso(30_000))).toBe("30s ago");
  });

  test("returns Nm ago for minutes", () => {
    expect(relativeTime(iso(5 * 60_000))).toBe("5m ago");
  });

  test("returns Nh ago for hours", () => {
    expect(relativeTime(iso(3 * 3600_000))).toBe("3h ago");
  });

  test("returns Nd ago for days", () => {
    expect(relativeTime(iso(2 * 86_400_000))).toBe("2d ago");
  });

  test("returns Nw ago for weeks", () => {
    expect(relativeTime(iso(3 * 7 * 86_400_000))).toBe("3w ago");
  });

  test("returns Nmo ago for months", () => {
    expect(relativeTime(iso(3 * 30 * 86_400_000))).toBe("3mo ago");
  });
});

describe("formatActivityRow", () => {
  test("renders time, action, identity, ok tag", () => {
    const ts = new Date(Date.now() - 2 * 3600_000).toISOString();
    const html = formatActivityRow({ timestamp: ts, action: "secret.read", identity: "bradley", success: true });
    expect(html).toContain("2h ago");
    expect(html).toContain("secret.read");
    expect(html).toContain("bradley");
    expect(html).toContain("is-ok");
  });

  test("success=false renders is-fail tag", () => {
    const ts = new Date(Date.now() - 60_000).toISOString();
    const html = formatActivityRow({ timestamp: ts, action: "secret.read", identity: "bradley", success: false });
    expect(html).toContain("is-fail");
    expect(html).toContain("fail");
  });

  test("missing identity falls back to '-'", () => {
    const ts = new Date(Date.now() - 60_000).toISOString();
    const html = formatActivityRow({ timestamp: ts, action: "secret.read", identity: "", success: true });
    expect(html).toContain(">-<");
  });
});

describe("formatLeaseRow", () => {
  test("renders identity + expires", () => {
    const html = formatLeaseRow({ identity: "agent-alice", expires_at: "2026-05-15T14:00:00Z", status: "active" }, false);
    expect(html).toContain("agent-alice");
    expect(html).toContain("expires");
  });

  test("appends (gated) tag when requires_approval && status=approved", () => {
    const html = formatLeaseRow({ identity: "agent-bob", expires_at: "2026-05-15T14:00:00Z", status: "approved" }, true);
    expect(html).toContain("(gated)");
  });

  test("no (gated) tag when secret doesn't require approval", () => {
    const html = formatLeaseRow({ identity: "agent-bob", expires_at: "2026-05-15T14:00:00Z", status: "approved" }, false);
    expect(html).not.toContain("(gated)");
  });
});

describe("emptyStateStats", () => {
  const recent = new Date(Date.now() - 2 * 86_400_000).toISOString();
  const old = new Date(Date.now() - 30 * 86_400_000).toISOString();

  test("zero secrets", () => {
    expect(emptyStateStats([])).toEqual({ total: 0, gated: 0, touchedThisWeek: 0 });
  });

  test("counts gated + touched correctly", () => {
    const secrets = [
      { metadata: { requires_approval: "true" }, updated_at: recent },
      { metadata: {}, updated_at: recent },
      { metadata: { requires_approval: "true" }, updated_at: old },
      { metadata: {}, updated_at: old },
    ];
    expect(emptyStateStats(secrets)).toEqual({ total: 4, gated: 2, touchedThisWeek: 2 });
  });

  test("emptyStateStatsLine returns empty string when zero secrets", () => {
    expect(emptyStateStatsLine([])).toBe("");
  });

  test("emptyStateStatsLine renders the counts when non-empty", () => {
    const secrets = [{ metadata: {}, updated_at: recent }];
    const line = emptyStateStatsLine(secrets);
    expect(line).toContain("1 secrets");
    expect(line).toContain("0 require approval");
    expect(line).toContain("1 touched this week");
  });
});

describe("treeAuthChip", () => {
  test("returns empty string when auth_scheme is absent", () => {
    expect(treeAuthChip({})).toBe("");
    expect(treeAuthChip(undefined)).toBe("");
  });

  test("returns empty string when auth_scheme is 'none'", () => {
    expect(treeAuthChip({ auth_scheme: "none" })).toBe("");
  });

  test("renders bearer", () => {
    const html = treeAuthChip({ auth_scheme: "bearer" });
    expect(html).toContain("[bearer]");
    expect(html).toContain("tree-item-auth");
  });

  test("renders header:Name when scheme=header", () => {
    const html = treeAuthChip({ auth_scheme: "header", header_name: "X-API-Key" });
    expect(html).toContain("[header:X-API-Key]");
  });

  test("renders bare header when scheme=header but no header_name", () => {
    const html = treeAuthChip({ auth_scheme: "header" });
    expect(html).toContain("[header]");
  });
});
```

- [ ] **Step 2: Run the failing tests**

```bash
bun test test/secretDetailRender.test.ts
```

Expected: all tests fail with import-resolution errors (the module doesn't exist yet).

- [ ] **Step 3: Implement the module**

Create `src/ui/secret-detail-render.js`:

```javascript
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
  // Inline onclick keeps the chip self-contained; the global _copyRef
  // helper (defined in index.html) handles clipboard write + toast.
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
  // Match the existing fmtTime style (absolute datetime) for lease expiries:
  // operators care WHEN a lease expires, not "in 3h".
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
  };
}
```

- [ ] **Step 4: Re-run the tests; expect all to pass**

```bash
bun test test/secretDetailRender.test.ts
```

Expected: all tests pass. If any fail, fix the module (not the tests).

- [ ] **Step 5: Run the full test suite**

```bash
bun test
```

Expected: all tests pass (the new file plus the existing 526). If any pre-existing test breaks, that's a blocker.

- [ ] **Step 6: Em-dash scan + commit**

```bash
grep -P '[\x{2014}\x{2013}]' src/ui/secret-detail-render.js test/secretDetailRender.test.ts
```

Expected: no matches.

```bash
git add src/ui/secret-detail-render.js test/secretDetailRender.test.ts
git commit -m "$(cat <<'EOF'
feat(ui): add pure formatters for the secrets detail panel

postureChips, formatActivityRow, formatLeaseRow, relativeTime,
emptyStateStats, treeAuthChip, referenceChipHtml. Pure JS module,
ES exports, also attached to window.SecretDetail for the inline
modal handlers in the next task.
EOF
)"
git push origin main
```

---

## Task 2: Serve the helper module from Hono

**Files:**
- Modify: `src/index.ts`

- [ ] **Step 1: Add the route**

Open `src/index.ts`. Find the existing route at `app.get("/ui/secret-form-metadata.js", ...)` (added in the v0.15.0 work, around line 193-207). Immediately after its closing `});`, add the new route:

```typescript
// Serve the secret-detail render helper module.
app.get("/ui/secret-detail-render.js", async (c) => {
  const jsPath = new URL("./ui/secret-detail-render.js", import.meta.url).pathname;
  try {
    const js = await Bun.file(jsPath).text();
    c.header("Content-Type", "application/javascript; charset=utf-8");
    c.header("Cache-Control", "no-cache, must-revalidate");
    return c.body(js);
  } catch {
    return c.text("Not found", 404);
  }
});
```

- [ ] **Step 2: Smoke-test the route**

```bash
GATEHOUSE_MASTER_KEY=$(printf 'a%.0s' {1..64}) GATEHOUSE_DATA_DIR=$(mktemp -d) bun run src/index.ts &
sleep 1
curl -sS -i http://localhost:3100/ui/secret-detail-render.js | head -10
kill %1 2>/dev/null || true
```

Expected: HTTP/1.1 200 OK, `content-type: application/javascript; charset=utf-8`, body begins with `// Pure formatters for the Secrets page detail panel.`

- [ ] **Step 3: Run the test suite**

```bash
bun test
```

Expected: all tests pass (server-side change doesn't affect existing tests).

- [ ] **Step 4: Commit**

```bash
git add src/index.ts
git commit -m "feat(ui): serve /ui/secret-detail-render.js"
git push origin main
```

---

## Task 3: Wire script tag + add new CSS

**Files:**
- Modify: `src/ui/index.html` (head + `<style>` block)

- [ ] **Step 1: Add the script tag**

Find the existing line `<script type="module" src="/ui/secret-form-metadata.js"></script>` (around line 1811). Immediately after it, on a new line with matching indentation, add:

```html
    <script type="module" src="/ui/secret-detail-render.js"></script>
```

- [ ] **Step 2: Add the new CSS**

Find the `.kv-row` CSS rule (around line 991-992). Immediately AFTER the existing `.advanced-details` block (the one added in v0.15.0, which ends around line 1033 with `.advanced-details[open] > summary svg { transform: rotate(90deg); }` and the `.form-help` rule), add the new rules. Use the same 4-space indentation as sibling rules.

```css

    .detail-identity { display: flex; flex-direction: column; gap: 6px; margin-bottom: 20px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
    .detail-identity-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .detail-path-mono { font-family: var(--font-mono); font-size: 16px; font-weight: 500; color: var(--text-primary); }
    .detail-ref-chip {
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-secondary);
      background: var(--bg-primary);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 3px 8px;
      cursor: pointer;
      transition: border-color 0.15s, color 0.15s;
    }
    .detail-ref-chip:hover { border-color: var(--accent); color: var(--accent); }
    .detail-description { font-size: 13px; color: var(--text-secondary); line-height: 1.5; }
    .detail-stamps { font-size: 11px; color: var(--text-tertiary); font-family: var(--font-mono); }

    .detail-section { margin: 20px 0; }
    .detail-section-heading {
      font-family: var(--font-heading);
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-tertiary);
      margin-bottom: 10px;
      display: flex;
      align-items: baseline;
      justify-content: space-between;
    }
    .detail-section-summary { font-family: var(--font-mono); font-size: 11px; color: var(--text-tertiary); text-transform: none; letter-spacing: 0; font-weight: 400; }

    .posture-chips { display: flex; flex-wrap: wrap; gap: 12px; }
    .posture-chip {
      display: flex;
      flex-direction: column;
      gap: 2px;
      min-width: 80px;
      max-width: 280px;
      padding: 8px 12px;
      background: var(--bg-primary);
      border: 1px solid var(--border);
      border-radius: var(--radius);
    }
    .posture-chip-label {
      font-family: var(--font-heading);
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-tertiary);
    }
    .posture-chip-value {
      font-size: 13px;
      color: var(--text-primary);
      font-family: var(--font-mono);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .posture-chip.is-accent .posture-chip-value { color: var(--accent); }
    .posture-chip.is-warn {
      background: rgba(251,191,36,0.06);
      border-color: rgba(251,191,36,0.2);
    }
    .posture-chip.is-warn .posture-chip-value { color: var(--warning); }

    .activity-subsection { margin-top: 12px; }
    .activity-subhead {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      margin-bottom: 6px;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-tertiary);
      font-weight: 600;
    }
    .activity-subhead a {
      font-size: 11px;
      color: var(--text-secondary);
      text-transform: none;
      letter-spacing: 0;
      font-weight: 400;
      text-decoration: none;
      cursor: pointer;
    }
    .activity-subhead a:hover { color: var(--accent); }
    .activity-row {
      display: grid;
      grid-template-columns: auto 1fr auto;
      gap: 12px;
      padding: 6px 0;
      font-size: 12px;
      align-items: center;
      border-bottom: 1px solid var(--border);
    }
    .activity-row:last-child { border-bottom: none; }
    .activity-row-time {
      font-family: var(--font-mono);
      color: var(--text-tertiary);
      font-size: 11px;
      min-width: 60px;
    }
    .activity-row-id { color: var(--text-secondary); }
    .activity-row-tag {
      font-size: 10px;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: var(--font-mono);
    }
    .activity-row-tag.is-ok { color: var(--text-tertiary); background: var(--bg-tertiary); }
    .activity-row-tag.is-fail { color: var(--danger); background: var(--danger-subtle); }
    .activity-row-tag.is-meta { color: var(--text-tertiary); background: transparent; padding-left: 0; }

    .tree-item-auth {
      font-family: var(--font-mono);
      font-size: 10px;
      color: var(--text-tertiary);
      margin-left: 4px;
      opacity: 0.7;
    }

    .detail-empty-stats {
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-tertiary);
      margin-bottom: 24px;
      text-align: center;
    }

    .actions-bar {
      display: flex;
      gap: 8px;
      align-items: center;
      padding-top: 8px;
    }
    .actions-bar .actions-bar-spacer { flex: 1; }
```

- [ ] **Step 3: Smoke-test**

```bash
GATEHOUSE_MASTER_KEY=$(printf 'a%.0s' {1..64}) GATEHOUSE_DATA_DIR=$(mktemp -d) bun run src/index.ts &
sleep 1
curl -sS http://localhost:3100/ | grep -c "secret-detail-render.js"
curl -sS http://localhost:3100/ | grep -c "posture-chip\|detail-ref-chip\|activity-row"
kill %1 2>/dev/null || true
```

Expected: both `grep -c` outputs are positive integers. The first should be 1 (script tag), the second should be 3 or more (one match per CSS class).

- [ ] **Step 4: Em-dash scan + commit**

```bash
grep -P '[\x{2014}\x{2013}]' src/ui/index.html
```

Expected: only pre-existing matches (compare with `git diff` if needed).

```bash
git add src/ui/index.html
git commit -m "feat(ui): wire secret-detail-render.js + add new detail-panel CSS"
git push origin main
```

---

## Task 4: Rewrite the static-secret branch of selectSecret()

**Files:**
- Modify: `src/ui/index.html` (`selectSecret(path)` function around line 3172, plus new helpers nearby)

This is the biggest change of the plan. The function `selectSecret(path)` has two branches: dynamic secrets (line 3181) and static secrets (line 3211 onwards). The dynamic branch stays untouched; the static branch gets a full rewrite.

The new layout for the static branch:
1. Existing approval banner (kept when `requiresApproval`)
2. Identity block (path heading + ref chip + description paragraph + stamps line)
3. Posture block (via `window.SecretDetail.postureChipsHtml`)
4. Activity placeholder (rendered immediately, populated async by `_loadActivityForPath`)
5. Value reveal box (existing)
6. Action bar (Create Lease primary, Edit, Delete right-aligned)
7. Unknown metadata block (any keys NOT consumed by Identity or Posture)

The existing approved-leases section at the top (the one rendered before the metadata table for approval-gated secrets) is REMOVED; its data now flows through the Activity block.

- [ ] **Step 1: Replace the static-secret branch and add the activity helpers**

Find `async function selectSecret(path)` around line 3172. The function structure is:

```javascript
async function selectSecret(path) {
  // path validation + meta lookup
  // dynamic branch (line 3181-3209)
  // static branch (line 3211 to end of function)
}
```

Replace the static branch (everything from `let metaRows = '';` around line 3211 down to and including the closing brace of `selectSecret` that comes BEFORE `// Cache of revealed values...` comment around line 3314). Leave the dynamic branch alone.

The replacement code:

```javascript
    // Approval-gated secrets get a prominent banner near the top of the
    // detail view.
    const requiresApproval = _isApprovalRequired(meta);
    const approvalBanner = requiresApproval
      ? `<div style="background:rgba(251,191,36,0.08);border:1px solid var(--warning);padding:8px;border-radius:6px;color:var(--text-primary);font-size:13px;margin-bottom:14px">🔒 This secret requires approval before agents can use it.</div>`
      : '';

    // Identity: path + reference chip + description paragraph + stamps line.
    const description = (meta.metadata && meta.metadata.description) ? meta.metadata.description : '';
    const identityHtml = `
      <div class="detail-identity">
        <div class="detail-identity-row">
          <span class="detail-path-mono">${esc(path)}</span>
          ${window.SecretDetail.referenceChipHtml(path)}
        </div>
        ${description ? `<div class="detail-description">${esc(description)}</div>` : ''}
        <div class="detail-stamps">v${meta.version} . created ${esc(window.SecretDetail.relativeTime(meta.created_at))} . updated ${esc(window.SecretDetail.relativeTime(meta.updated_at))}</div>
      </div>
    `;

    // Posture: structured chips from known metadata keys.
    const postureHtml = window.SecretDetail.postureChipsHtml(meta.metadata || {});

    // Activity placeholder; populated async below.
    const activityHtml = `
      <div class="detail-section" id="detail-activity">
        <div class="detail-section-heading">ACTIVITY <span class="detail-section-summary" id="detail-activity-summary">loading...</span></div>
        <div id="detail-activity-body" style="color:var(--text-tertiary);font-size:12px;">Loading activity...</div>
      </div>
    `;

    // Value reveal stays as-is.
    const valueHtml = `
      <div class="detail-section">
        <div class="reveal-box">
          <div class="reveal-header">
            <span class="reveal-label">Secret Value</span>
            <button class="btn btn-ghost btn-sm" id="reveal-btn" aria-pressed="false" onclick="window._toggleRevealSecret('${esc(path)}')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              <span id="reveal-btn-label">Reveal</span>
            </button>
          </div>
          <div class="reveal-value" id="secret-value-display" style="color:var(--text-tertiary)">Click reveal to decrypt and display value</div>
        </div>
      </div>
    `;

    // Unknown metadata: any keys NOT in the structured set get a small
    // demoted table at the bottom.
    const KNOWN_STRUCTURED_KEYS = new Set([
      'description',
      'requires_approval',
      'auth_scheme',
      'header_name',
      'allowed_domains',
      'allowed_path_prefixes',
      'allow_private',
      'tls_allow_insecure',
      'rate_limit_per_minute',
      'auto_approve_from_ip',
      'auto_approve_ttl_seconds',
    ]);
    const unknownEntries = Object.entries(meta.metadata || {}).filter(([k]) => !KNOWN_STRUCTURED_KEYS.has(k));
    const unknownHtml = unknownEntries.length
      ? `<div class="detail-section"><div class="detail-section-heading">OTHER METADATA</div><table class="meta-table"><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>${
          unknownEntries.map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td>${esc(String(v))}</td></tr>`).join('')
        }</tbody></table></div>`
      : '';

    // Action bar: Create Lease primary, Edit ghost, Delete danger.
    const actionsHtml = `
      <div class="actions-bar">
        <button class="btn btn-primary btn-sm" onclick="window._leaseSecret('${esc(path)}')">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Create Lease
        </button>
        <button class="btn btn-ghost btn-sm" onclick="window._editSecret('${esc(path)}')">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          Edit
        </button>
        <div class="actions-bar-spacer"></div>
        <button class="btn btn-danger btn-sm" onclick="window._deleteSecret('${esc(path)}')">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          Delete
        </button>
      </div>
    `;

    detail.innerHTML = approvalBanner + identityHtml + postureHtml + activityHtml + valueHtml + unknownHtml + actionsHtml;

    // Kick off async activity fetch; populates the placeholder when done.
    _loadActivityForPath(path, requiresApproval);
  }
```

That closes `selectSecret`. The `// Cache of revealed values...` comment block follows immediately.

- [ ] **Step 2: Add the activity loader, ref-copy helper, and remove the now-dead approved-leases helper**

Immediately AFTER the closing brace of `selectSecret` (and before `// Cache of revealed values...`), add:

```javascript

  // Populate the Activity section with active leases and recent audit events.
  // Both fetches are issued in parallel and run client-side filters because the
  // server's path filter is a LIKE prefix match.
  async function _loadActivityForPath(path, requiresApproval) {
    const summaryEl = document.getElementById('detail-activity-summary');
    const bodyEl = document.getElementById('detail-activity-body');
    if (!summaryEl || !bodyEl) return;
    try {
      const [leaseData, auditData] = await Promise.all([
        api('/v1/lease?path=' + encodeURIComponent(path)).catch(() => ({ leases: [] })),
        api('/v1/audit?path=' + encodeURIComponent(path) + '&limit=20').catch(() => ({ entries: [] })),
      ]);
      const leases = (leaseData.leases || []).filter(l =>
        (l.secret_path === path || l.path === path) && !l.revoked && (l.status === 'active' || l.status === 'approved')
      );
      const events = (auditData.entries || []).filter(e => e.path === path);

      // Header summary.
      const last24h = events.filter(e => {
        const ts = new Date(String(e.timestamp).endsWith('Z') ? e.timestamp : e.timestamp + 'Z');
        return (Date.now() - ts.getTime()) < 86_400_000;
      }).length;
      summaryEl.textContent = `${leases.length} active leases . ${last24h} events / 24h`;

      // Empty-empty case.
      if (!leases.length && !events.length) {
        bodyEl.innerHTML = '<div style="color:var(--text-tertiary);font-size:12px;">No recent activity.</div>';
        return;
      }

      let html = '';
      if (leases.length) {
        const visible = leases.slice(0, 3);
        const viewAll = leases.length > 3
          ? `<a onclick="showPage('leases')">view all (${leases.length})</a>`
          : '';
        html += `<div class="activity-subsection"><div class="activity-subhead">LEASES${viewAll ? '' : ''}<span>${viewAll}</span></div>${
          visible.map(l => window.SecretDetail.formatLeaseRow(l, requiresApproval)).join('')
        }</div>`;
      }
      if (events.length) {
        const visible = events.slice(0, 3);
        const viewAll = events.length > 3
          ? `<a onclick="window._showAuditForPath('${esc(path)}')">view all (${events.length})</a>`
          : '';
        html += `<div class="activity-subsection"><div class="activity-subhead">EVENTS${viewAll ? '' : ''}<span>${viewAll}</span></div>${
          visible.map(e => window.SecretDetail.formatActivityRow(e)).join('')
        }</div>`;
      }
      bodyEl.innerHTML = html;
    } catch (e) {
      summaryEl.textContent = '';
      bodyEl.innerHTML = '<div style="color:var(--danger);font-size:12px;">Failed to load activity.</div>';
    }
  }

  // Helper to jump to the Audit page with this path's filter pre-set.
  window._showAuditForPath = function(path) {
    showPage('audit');
    const inp = document.getElementById('audit-filter-path');
    if (inp) {
      inp.value = path;
      if (typeof loadAuditLog === 'function') loadAuditLog();
    }
  };

  // Copy the {{secret:<path>}} reference to the clipboard.
  window._copySecretRef = async function(path) {
    const ref = `{{secret:${path}}}`;
    try {
      await navigator.clipboard.writeText(ref);
      toast('Reference copied', 'success');
    } catch {
      try {
        const ta = document.createElement('textarea');
        ta.value = ref;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        toast('Reference copied', 'success');
      } catch {
        toast('Copy failed', 'error');
      }
    }
  };
```

The existing `_loadApprovedLeasesForPath` function (around line 3286) is now dead code (the new `_loadActivityForPath` supersedes it). Delete the entire `async function _loadApprovedLeasesForPath(path) { ... }` block.

- [ ] **Step 3: Smoke-test**

```bash
GATEHOUSE_MASTER_KEY=$(printf 'a%.0s' {1..64}) GATEHOUSE_DATA_DIR=$(mktemp -d) bun run src/index.ts &
sleep 1
# Confirm the new HTML structures are present in the rendered template:
curl -sS http://localhost:3100/ | grep -cE "detail-identity|detail-path-mono|detail-ref-chip|posture-chip|activity-subsection|actions-bar"
kill %1 2>/dev/null || true
```

Expected: 0 (these classes appear in dynamically-rendered HTML, not the static template). This is normal; the smoke test for THIS task is the next step.

```bash
bun test
```

Expected: 526+ existing tests + 30+ new tests all pass.

- [ ] **Step 4: Manual click-through** (mark complete after performing)

```bash
GATEHOUSE_MASTER_KEY=$(printf 'a%.0s' {1..64}) GATEHOUSE_DATA_DIR=$(mktemp -d) bun run src/index.ts &
```

Open the UI, log in. Create a secret with description + bearer auth + allowed_domains + requires_approval. Click into the Secrets page, select that secret. Verify:

- Identity block at top: path heading, reference chip showing `{{secret:<path>}}` (clicking it copies + toasts), description paragraph below, single stamps line `v1 . created Ns ago . updated Ns ago`.
- POSTURE block: chips for AUTH=bearer, SCOPE=<the domain>, APPROVAL=required (accent color).
- ACTIVITY block: loads quickly with "0 active leases . 0 events / 24h" and "No recent activity."
- Value reveal: still works (Reveal → masked unmask).
- Action bar at the bottom: `+ Create Lease` (primary, filled), `Edit`, then right-aligned `Delete`.
- The approval banner (yellow) sits ABOVE the Identity block.

Edit the same secret to remove `allowed_domains`. Re-select. The POSTURE block now has a warning-tinted `SCOPE / no allowed_domains` chip.

Edit again to add a custom metadata key `x-team=platform`. Re-select. An `OTHER METADATA` table appears between the value reveal and the actions bar with the `x-team` row.

Create a lease for the secret. Re-select. Activity block now shows a LEASES sub-section with one row.

Reveal the value. Re-select the secret (or just observe the panel reload). Activity now shows an EVENTS sub-section with a `secret.read` row.

Kill the server (`kill %1`).

- [ ] **Step 5: Em-dash scan + commit**

```bash
grep -P '[\x{2014}\x{2013}]' src/ui/index.html
```

Expected: only pre-existing matches.

```bash
git add src/ui/index.html
git commit -m "$(cat <<'EOF'
feat(ui): redesign Secrets detail panel with 5 structured blocks

Replace the flat metadata-table layout with Identity (path + click-to-copy
ref chip + description + stamps), Posture (semantic-color chips), Activity
(parallel-fetched leases + audit events), Value reveal, and Actions
(Create Lease primary, Edit, Delete). Unknown metadata stays in an Other
Metadata table at the bottom. Removes the dead _loadApprovedLeasesForPath.
EOF
)"
git push origin main
```

---

## Task 5: Tree auth chip + empty-state stats line

**Files:**
- Modify: `src/ui/index.html` (`renderSecretTree` around line 3134, `loadSecrets` around line 3107)

- [ ] **Step 1: Add auth chip to the tree rendering**

Find `function renderSecretTree(secrets)` around line 3134. The inner loop currently looks like:

```javascript
      for (const item of items) {
        const name = item.path.split('/').pop();
        const active = item.path === selectedSecretPath ? 'active' : '';
        const approvalBadge = _isApprovalRequired(item)
          ? ' <span class="badge" style="font-size:9px;background:rgba(251,191,36,0.12);color:var(--warning)" title="Requires human approval before agents can use this secret">🔒 approval</span>'
          : '';
        html += `<div class="tree-item ${active}" onclick="window._selectSecret('${esc(item.path)}')">${esc(name)}${approvalBadge}</div>`;
      }
```

Replace the inner loop body with:

```javascript
      for (const item of items) {
        const name = item.path.split('/').pop();
        const active = item.path === selectedSecretPath ? 'active' : '';
        const approvalBadge = _isApprovalRequired(item)
          ? ' <span class="badge" style="font-size:9px;background:rgba(251,191,36,0.12);color:var(--warning)" title="Requires human approval before agents can use this secret">🔒 approval</span>'
          : '';
        const authChip = window.SecretDetail ? window.SecretDetail.treeAuthChip(item.metadata) : '';
        html += `<div class="tree-item ${active}" onclick="window._selectSecret('${esc(item.path)}')">${esc(name)}${authChip}${approvalBadge}</div>`;
      }
```

The auth chip renders BEFORE the approval badge, separated by the chip's own internal `margin-left: 4px`.

- [ ] **Step 2: Add stats line to the empty state in loadSecrets**

Find `async function loadSecrets()` around line 3107. The initial empty-state innerHTML currently is:

```javascript
    if (detail) {
      detail.innerHTML = `
        <div class="secret-detail-empty">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          Select a secret to view details
        </div>`;
    }
```

This runs at the START of loadSecrets, BEFORE the secrets list is fetched. So the stats line can't be rendered there yet. Instead, after `allSecrets = data.secrets || [];` (around line 3120), inject the stats line above the empty-icon block when no secret is selected.

Replace the existing initial-render block:

```javascript
    if (detail) {
      detail.innerHTML = `
        <div class="secret-detail-empty">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          Select a secret to view details
        </div>`;
    }
    try {
      const data = await api('/v1/secrets');
      allSecrets = data.secrets || [];
      renderSecretTree(allSecrets);
    } catch (e) {
      toast('Failed to load secrets', 'error');
    }
  }
```

with:

```javascript
    if (detail) {
      detail.innerHTML = `
        <div class="secret-detail-empty">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          Select a secret to view details
        </div>`;
    }
    try {
      const data = await api('/v1/secrets');
      allSecrets = data.secrets || [];
      renderSecretTree(allSecrets);
      // Add a stats line above the empty-icon block when no secret is
      // selected; depends on allSecrets being populated, hence after the fetch.
      if (detail && !selectedSecretPath && window.SecretDetail) {
        const statsLine = window.SecretDetail.emptyStateStatsLine(allSecrets);
        if (statsLine) {
          detail.innerHTML = statsLine + detail.innerHTML;
        }
      }
    } catch (e) {
      toast('Failed to load secrets', 'error');
    }
  }
```

- [ ] **Step 3: Smoke-test**

```bash
GATEHOUSE_MASTER_KEY=$(printf 'a%.0s' {1..64}) GATEHOUSE_DATA_DIR=$(mktemp -d) bun run src/index.ts &
sleep 1
# This change is in dynamically-rendered HTML so curl can't catch it.
# Run the test suite instead.
kill %1 2>/dev/null || true
bun test
```

Expected: 526+ existing tests + 30+ new tests all pass.

- [ ] **Step 4: Manual verification** (mark complete after performing)

Open the UI. On the Secrets page, with at least one secret that has `auth_scheme` set (created in Task 4):

- Tree shows the secret name with `[bearer]` (or `[basic]`, etc.) chip after it, in tertiary mono.
- A secret without `auth_scheme` shows no chip.
- The approval-gated secret shows BOTH the auth chip AND the lock chip after the name.
- Click into the page WITHOUT selecting a secret. The empty state shows a small mono tertiary line above the lock icon: `N secrets . M require approval . K touched this week`.
- With zero secrets, the line is hidden and the existing "No secrets stored yet" message appears in the tree.

- [ ] **Step 5: Em-dash scan + commit**

```bash
grep -P '[\x{2014}\x{2013}]' src/ui/index.html
```

Expected: only pre-existing matches.

```bash
git add src/ui/index.html
git commit -m "feat(ui): tree auth chip + empty-state stats line"
git push origin main
```

---

## Task 6: Version bump, changelog, tag

**Files:**
- Modify: `src/version.ts`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Bump src/version.ts to 0.16.0**

Replace the version line in `src/version.ts` so the full file content is exactly:

```typescript
// Single source of truth for the Gatehouse version.
// Update this value when cutting a release, then tag the commit.
export const VERSION = "0.16.0";
```

(Minor bump: new visible UX feature, no breaking change, no wire-format change.)

- [ ] **Step 2: Add CHANGELOG entry**

Open `CHANGELOG.md`. The current top entry is `0.15.0`. Above it, add:

```markdown
## 0.16.0

- **Secrets page detail panel redesign**: replaced the flat metadata table with five structured blocks. Identity at the top (path + click-to-copy `{{secret:...}}` reference chip + description paragraph + a single stamps line). Posture (semantic-colored chips for `auth_scheme`, `allowed_domains`, `allowed_path_prefixes`, `rate_limit_per_minute`, `requires_approval`, `allow_private`, `tls_allow_insecure`, auto-approval IP/TTL). Activity (parallel-fetched active leases + recent audit events, with view-all links to the Leases and Audit pages). Value reveal (unchanged). Actions (Create Lease becomes primary). Unknown metadata keys land in an Other Metadata table at the bottom.
- Tree: each row now shows a small `[bearer]` / `[header:X-API-Key]` chip after the secret name when an auth scheme is set.
- Empty state: when no secret is selected, the panel shows a tertiary line summarizing total secrets, approval-gated count, and secrets touched this week.
- No server changes. Existing endpoints (`/v1/secrets`, `/v1/lease`, `/v1/audit`) supply all data.
```

- [ ] **Step 3: Run the full test suite and dash scan**

```bash
bun test
grep -P '[\x{2014}\x{2013}]' src/version.ts CHANGELOG.md
```

Expected:
- All tests pass.
- Dash scan returns only pre-existing matches in CHANGELOG (not introduced by this entry).

- [ ] **Step 4: Commit + tag + push (Gitea only, no GitHub)**

```bash
git add src/version.ts CHANGELOG.md
git commit -m "$(cat <<'EOF'
feat(0.16.0): redesign Secrets page detail panel

- Identity block: path, copy-to-clipboard reference chip, description
  paragraph, single relative-time stamps line
- Posture block: semantic-color chips with warning tint on relaxed
  defaults (allow_private, tls_allow_insecure, no allowed_domains)
- Activity block: up to 3 active leases + 3 recent audit events with
  view-all links to the existing Leases and Audit pages
- Tree: small auth-scheme chip after each secret name
- Empty state: stats line when no secret is selected
EOF
)"
git tag v0.16.0
git push origin main
git push origin v0.16.0
```

DO NOT push to GitHub. DO NOT run `scripts/sync-to-github.ts`.

---

## Self-review

Walking the spec section by section against the plan:

- **Problem / Goals 1-7**: covered by Tasks 1, 4, 5.
- **Non-goals**: respected. No new server endpoints; the only server-side change is one new static-file route (Task 2) which serves a JS file. No tabs. No mobile redesign. No filter chips above tree. No mini-dashboard empty state. Dynamic-secret branch left alone.
- **Block 1 Identity**: Task 4 builds the `identityHtml` exactly as specified (path + ref chip + optional description + stamps line). The 3-col Version/Created/Updated grid is removed.
- **Block 2 Posture**: Task 1 implements `postureChips` + `postureChipsHtml` with all 9 chip types and the inferred "no allowed_domains" warning chip. Task 4 calls into them.
- **Block 3 Activity**: Task 4 adds `_loadActivityForPath` which Promise.all-fetches leases + audit, filters client-side, and renders. Task 1 implements `formatLeaseRow` and `formatActivityRow`. Empty / partial-empty states handled.
- **Block 4 Value reveal**: unchanged structurally; Task 4 keeps the existing reveal box markup.
- **Block 5 Action bar**: Task 4 implements the new `.actions-bar` div with Create Lease primary, Edit ghost, spacer, Delete danger right-aligned.
- **Block 6 Unknown metadata**: Task 4 filters `meta.metadata` by `KNOWN_STRUCTURED_KEYS` and renders the leftover keys in the existing `.meta-table` style.
- **Tree-pane**: Task 5 wires `treeAuthChip` (implemented in Task 1) into `renderSecretTree`.
- **Empty state**: Task 5 prepends `emptyStateStatsLine` (implemented in Task 1) when no secret is selected and there are secrets to count.
- **Data sources**: all three (`/v1/secrets`, `/v1/lease?path=`, `/v1/audit?path=`) already exist. Verified in Task 4's `_loadActivityForPath`.
- **Visual specifics**: every CSS rule from the spec is reproduced in Task 3.
- **Validation / error handling**: clipboard fallback covered in Task 4's `_copySecretRef`. Activity fetch failure handled. Exact-match audit filter covered. Empty-state with zero secrets correctly hides the stats line (`emptyStateStatsLine` returns `""`).
- **Test plan unit (1-5)**: all five categories have explicit tests in Task 1.

Type consistency check: `window.SecretDetail.*` named exports match between Task 1 (declaration), Task 4 (usage), and Task 5 (usage). DOM ids `detail-activity-summary`, `detail-activity-body`, `audit-filter-path`, `reveal-btn`, `secret-value-display`, `reveal-btn-label` are consistent. Function names `formatActivityRow`, `formatLeaseRow`, `postureChipsHtml`, `referenceChipHtml`, `treeAuthChip`, `emptyStateStatsLine` all match between definition and call sites.

Placeholder scan: no TBDs, no TODOs, no "implement later", no "similar to Task N", no vague "appropriate error handling". Every code step shows the actual code.

Em-dash scan: the plan itself uses no em or en dashes (only `:` and `.` for separators).
