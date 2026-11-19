# Secret Form Structured Fields Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the generic key/value editor in the Secret create/edit modal with dedicated controls for the metadata keys Gatehouse actually reads (`requires_approval` toggle, `description` text, plus a collapsed Advanced section for `auth_scheme`, `allowed_domains`, `rate_limit_per_minute`, etc.). The raw key/value editor stays as an escape hatch for unknown keys.

**Architecture:** Two pure helpers (`buildMetadata`, `hydrateMetadata`) live in a new ES module `src/ui/secret-form-metadata.js`. The module is served via a new `GET /ui/secret-form-metadata.js` route and imported into `index.html` as `<script type="module">`, attaching `window.SecretForm = { buildMetadata, hydrateMetadata }`. The index.html HTML for the two modals is rebuilt around the new control layout; submit/edit handlers call into `window.SecretForm`. Server-side: no change. The wire format stays `metadata: Record<string,string>`; defaults are omitted at build time.

**Tech Stack:** Bun runtime, Hono router, vanilla JS for the SPA, plain DOM (no framework). Tests run under `bun test`.

**Spec:** `docs/superpowers/specs/2026-05-13-secret-form-structured-fields-design.md` (commit `00271aa`).

---

## Implementation notes

- The codebase forbids em dashes everywhere. Use colons or rephrase. (Same applies to code comments and commit messages.)
- After every commit, push to Gitea: `git push origin main`.
- The UI is a single HTML file (`src/ui/index.html`) served at `GET /`. There is no frontend build step. Static JS modules must be served by their own Hono route. The CSP allows `script-src 'self' 'unsafe-inline'`, so a same-origin `<script type="module" src="/ui/...">` works.
- `src/ui/secret-form-metadata.js` is plain JavaScript (not TypeScript) so the browser can load it directly without compilation. Bun's test runner can still `import` it as an ES module via its filesystem path.
- Helpers are pure functions on plain objects (no DOM dependency), so they unit-test cleanly under `bun test`. The DOM glue stays inline in `index.html`.
- Existing test runner: `bun test`. Tests live in `test/` alongside the existing `*.test.ts` files. There are no UI tests in the codebase today and we are not introducing a browser harness; UI HTML changes are verified manually per the test plan in Task 7.
- Reuse existing components and CSS variables: `.toggle` / `.toggle-wrap` (index.html:1386), `<select class="input">` styling (index.html:572), `.form-group` / `.form-label`, `.modal-overlay` / `.modal`, `.kv-row` (index.html:991), `.btn`, `.hidden`. New CSS introduces only what isn't already there (Advanced details summary, section subheading, header_name auto-hide).

## File map

**Created:**
- `src/ui/secret-form-metadata.js`: pure helpers `buildMetadata(state)` and `hydrateMetadata(metadata)`, plus window export.
- `test/secretFormMetadata.test.ts`: unit tests for the two helpers.

**Modified:**
- `src/index.ts` (around line 191): add `GET /ui/secret-form-metadata.js` route serving the JS file.
- `src/ui/index.html`:
  - Head: add `<script type="module" src="/ui/secret-form-metadata.js"></script>`.
  - CSS block: add styles for `.advanced-details > summary`, `.advanced-details[open] > summary svg`, `.form-subheading`.
  - `openCreateSecretModal()` (~3363): rebuild modal HTML; update `_saveNewSecret()` to call `window.SecretForm.buildMetadata`.
  - `_editSecret()` (~3445): rebuild modal HTML; hydrate via `window.SecretForm.hydrateMetadata`; update `_saveEditSecret()` to call `buildMetadata`.
- `src/version.ts`: bump to `0.15.0` (new visible feature: minor bump).
- `CHANGELOG.md`: add `0.15.0` entry.

---

## Task 1: Create the pure-helper module and its tests

**Files:**
- Create: `src/ui/secret-form-metadata.js`
- Create: `test/secretFormMetadata.test.ts`

The helpers operate on a plain `state` object whose shape is the union of all dedicated form controls plus a `custom` array for unknown key/value pairs:

```text
state = {
  description: string,                  // "" means omit
  requires_approval: boolean,           // false means omit
  auth_scheme: "none"|"bearer"|"basic"|"header"|"query",  // "none" means omit
  header_name: string,                  // only meaningful when auth_scheme === "header"
  allowed_domains: string,              // "" means omit
  allowed_path_prefixes: string,        // "" means omit
  allow_private: boolean,               // false means omit
  tls_allow_insecure: boolean,          // false means omit
  rate_limit_per_minute: string,        // "" means omit; non-empty parses to int >= 1
  auto_approve_from_ip: string,         // "" means omit
  auto_approve_ttl_seconds: string,     // "" or orphan means omit
  custom: Array<[string, string]>,      // raw kv editor rows
}
```

Note: numeric fields are kept as strings in the state object to preserve user-typed values exactly. `buildMetadata` parses and validates them when writing the output map.

- [ ] **Step 1: Create the test file**

Create `test/secretFormMetadata.test.ts`:

```typescript
import { describe, test, expect } from "bun:test";
import { buildMetadata, hydrateMetadata, DEFAULT_STATE } from "../src/ui/secret-form-metadata.js";

describe("buildMetadata", () => {
  test("default state produces empty metadata", () => {
    expect(buildMetadata(DEFAULT_STATE())).toEqual({});
  });

  test("requires_approval=true writes the string 'true'", () => {
    const s = DEFAULT_STATE();
    s.requires_approval = true;
    expect(buildMetadata(s)).toEqual({ requires_approval: "true" });
  });

  test("requires_approval=false omits the key", () => {
    const s = DEFAULT_STATE();
    s.requires_approval = false;
    expect(buildMetadata(s)).toEqual({});
  });

  test("auth_scheme=none omits the key", () => {
    const s = DEFAULT_STATE();
    s.auth_scheme = "none";
    expect(buildMetadata(s)).toEqual({});
  });

  test("auth_scheme=bearer writes 'bearer'", () => {
    const s = DEFAULT_STATE();
    s.auth_scheme = "bearer";
    expect(buildMetadata(s)).toEqual({ auth_scheme: "bearer" });
  });

  test("auth_scheme=header without header_name throws", () => {
    const s = DEFAULT_STATE();
    s.auth_scheme = "header";
    s.header_name = "";
    expect(() => buildMetadata(s)).toThrow(/header_name required/);
  });

  test("auth_scheme=header with header_name writes both", () => {
    const s = DEFAULT_STATE();
    s.auth_scheme = "header";
    s.header_name = "X-API-Key";
    expect(buildMetadata(s)).toEqual({ auth_scheme: "header", header_name: "X-API-Key" });
  });

  test("description trims and omits when blank", () => {
    const s = DEFAULT_STATE();
    s.description = "   ";
    expect(buildMetadata(s)).toEqual({});
    s.description = "  Anthropic API key  ";
    expect(buildMetadata(s)).toEqual({ description: "Anthropic API key" });
  });

  test("rate_limit_per_minute parses integer; non-numeric is omitted", () => {
    const s = DEFAULT_STATE();
    s.rate_limit_per_minute = "60";
    expect(buildMetadata(s)).toEqual({ rate_limit_per_minute: "60" });
    s.rate_limit_per_minute = "abc";
    expect(buildMetadata(s)).toEqual({});
    s.rate_limit_per_minute = "0";
    expect(buildMetadata(s)).toEqual({}); // clamped: must be >= 1
  });

  test("auto_approve_ttl_seconds without auto_approve_from_ip is omitted", () => {
    const s = DEFAULT_STATE();
    s.auto_approve_from_ip = "";
    s.auto_approve_ttl_seconds = "3600";
    expect(buildMetadata(s)).toEqual({});
  });

  test("auto_approve_from_ip without TTL writes only the IP", () => {
    const s = DEFAULT_STATE();
    s.auto_approve_from_ip = "10.0.0.5";
    s.auto_approve_ttl_seconds = "";
    expect(buildMetadata(s)).toEqual({ auto_approve_from_ip: "10.0.0.5" });
  });

  test("auto_approve_from_ip + TTL writes both", () => {
    const s = DEFAULT_STATE();
    s.auto_approve_from_ip = "10.0.0.5";
    s.auto_approve_ttl_seconds = "3600";
    expect(buildMetadata(s)).toEqual({ auto_approve_from_ip: "10.0.0.5", auto_approve_ttl_seconds: "3600" });
  });

  test("boolean toggles write 'true' or omit", () => {
    const s = DEFAULT_STATE();
    s.allow_private = true;
    s.tls_allow_insecure = false;
    expect(buildMetadata(s)).toEqual({ allow_private: "true" });
  });

  test("text fields are trimmed; empty after trim is omitted", () => {
    const s = DEFAULT_STATE();
    s.allowed_domains = "  api.example.com, *.example.org  ";
    s.allowed_path_prefixes = "   ";
    expect(buildMetadata(s)).toEqual({ allowed_domains: "api.example.com, *.example.org" });
  });

  test("custom kv rows are appended, structured fields win on key collision", () => {
    const s = DEFAULT_STATE();
    s.description = "from form";
    s.custom = [
      ["description", "from kv"],   // collision: structured wins
      ["x-internal", "team-eng"],   // unknown key: kept
      ["", "skip me"],              // empty key: dropped
    ];
    expect(buildMetadata(s)).toEqual({ description: "from form", "x-internal": "team-eng" });
  });
});

describe("hydrateMetadata", () => {
  test("empty metadata produces default state", () => {
    expect(hydrateMetadata({})).toEqual(DEFAULT_STATE());
  });

  test("known keys populate their controls", () => {
    const s = hydrateMetadata({
      description: "Anthropic key",
      requires_approval: "true",
      auth_scheme: "bearer",
      allowed_domains: "api.anthropic.com",
      rate_limit_per_minute: "60",
    });
    expect(s.description).toBe("Anthropic key");
    expect(s.requires_approval).toBe(true);
    expect(s.auth_scheme).toBe("bearer");
    expect(s.allowed_domains).toBe("api.anthropic.com");
    expect(s.rate_limit_per_minute).toBe("60");
    expect(s.custom).toEqual([]);
  });

  test("requires_approval=false hydrates as off (will normalize on save)", () => {
    const s = hydrateMetadata({ requires_approval: "false" });
    expect(s.requires_approval).toBe(false);
  });

  test("unknown keys land in custom rows", () => {
    const s = hydrateMetadata({
      description: "known",
      "x-team": "platform",
      "x-cost-center": "1234",
    });
    expect(s.description).toBe("known");
    expect(s.custom).toEqual([["x-team", "platform"], ["x-cost-center", "1234"]]);
  });

  test("unknown auth_scheme value falls back to none + becomes a custom row", () => {
    const s = hydrateMetadata({ auth_scheme: "weird" });
    expect(s.auth_scheme).toBe("none");
    expect(s.custom).toEqual([["auth_scheme", "weird"]]);
  });

  test("round-trip: build(hydrate(x)) == x for canonical metadata", () => {
    const original = {
      description: "Anthropic key",
      requires_approval: "true",
      auth_scheme: "header",
      header_name: "X-API-Key",
      allowed_domains: "api.anthropic.com",
      allow_private: "true",
      rate_limit_per_minute: "60",
      "x-team": "platform",
    };
    expect(buildMetadata(hydrateMetadata(original))).toEqual(original);
  });

  test("round-trip normalizes legacy requires_approval=false to omitted", () => {
    const out = buildMetadata(hydrateMetadata({ requires_approval: "false" }));
    expect(out).toEqual({});
  });

  test("round-trip normalizes orphan auto_approve_ttl_seconds", () => {
    const out = buildMetadata(hydrateMetadata({ auto_approve_ttl_seconds: "3600" }));
    expect(out).toEqual({});
  });
});
```

- [ ] **Step 2: Run the failing tests**

```bash
bun test test/secretFormMetadata.test.ts
```

Expected: all tests fail with "Cannot find module ../src/ui/secret-form-metadata.js" (or similar import error). This confirms the test harness is wired and the module doesn't exist yet.

- [ ] **Step 3: Implement the module**

Create `src/ui/secret-form-metadata.js`:

```javascript
// Pure helpers for the secret create/edit modal.
// State <-> metadata. No DOM, no globals.
// Exported as ES module AND attached to window.SecretForm so browser
// inline scripts can call into it.

const KNOWN_AUTH_SCHEMES = new Set(["none", "bearer", "basic", "header", "query"]);

const KNOWN_KEYS = new Set([
  "description",
  "requires_approval",
  "auth_scheme",
  "header_name",
  "allowed_domains",
  "allowed_path_prefixes",
  "allow_private",
  "tls_allow_insecure",
  "rate_limit_per_minute",
  "auto_approve_from_ip",
  "auto_approve_ttl_seconds",
]);

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
  if ("header_name" in remaining) {
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
```

- [ ] **Step 4: Re-run the tests; expect all to pass**

```bash
bun test test/secretFormMetadata.test.ts
```

Expected: all tests pass. If any fail, fix the helper; do not skip or weaken tests.

- [ ] **Step 5: Run the full test suite to make sure nothing else broke**

```bash
bun test
```

Expected: all tests pass (including the new file). The existing suite should be unaffected.

- [ ] **Step 6: Commit**

```bash
git add src/ui/secret-form-metadata.js test/secretFormMetadata.test.ts
git commit -m "$(cat <<'EOF'
feat(ui): add pure helpers for secret-form metadata round-trip

buildMetadata + hydrateMetadata. No DOM dependency, exported as ES
module so bun test can exercise them. Window attach for the inline
modal handlers in the next task.
EOF
)"
git push origin main
```

---

## Task 2: Serve the helper module from the Hono app

**Files:**
- Modify: `src/index.ts` (around line 191, immediately after the `app.get("/")` handler that serves index.html)

- [ ] **Step 1: Add the route**

Open `src/index.ts`. Find the `app.get("/", async (c) => { ... });` block (around line 174). Immediately after the closing `});` of that handler, add:

```typescript
// Serve the secret-form metadata helper module. The UI imports this as
// <script type="module" src="/ui/secret-form-metadata.js"> from index.html
// so the inline modal handlers can call window.SecretForm.buildMetadata().
app.get("/ui/secret-form-metadata.js", async (c) => {
  const jsPath = new URL("./ui/secret-form-metadata.js", import.meta.url).pathname;
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

- [ ] **Step 2: Start the server and verify the route serves the file**

```bash
bun run src/index.ts &
SERVER_PID=$!
sleep 1
curl -sS -i http://localhost:3100/ui/secret-form-metadata.js | head -20
kill $SERVER_PID
```

Expected: HTTP 200 with `content-type: application/javascript; charset=utf-8`, and the response body begins with the `// Pure helpers for the secret create/edit modal.` comment. If the server fails to start because of port conflicts or missing config, run with `GATEHOUSE_DATA_DIR=$(mktemp -d) bun run src/index.ts &` instead.

- [ ] **Step 3: Commit**

```bash
git add src/index.ts
git commit -m "feat(ui): serve /ui/secret-form-metadata.js"
git push origin main
```

---

## Task 3: Wire the script tag and new CSS into index.html

**Files:**
- Modify: `src/ui/index.html` (head + CSS block)

- [ ] **Step 1: Add the script tag to `<head>`**

Open `src/ui/index.html`. Find the `<head>` block and the closing `</head>`. Just before `</head>`, add:

```html
    <script type="module" src="/ui/secret-form-metadata.js"></script>
```

If there are existing `<script>` tags in head, place this one alongside them (order does not matter for ES modules; they are deferred by default).

- [ ] **Step 2: Add new CSS in the existing `<style>` block**

Find the `.kv-row` rule (around line 991). Immediately after it, add:

```css
    .advanced-details { margin-top: 8px; }
    .advanced-details > summary {
      list-style: none;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 8px 0;
      font-family: var(--font-body);
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      border-top: 1px solid var(--border);
      user-select: none;
      transition: color 0.15s;
    }
    .advanced-details > summary::-webkit-details-marker { display: none; }
    .advanced-details > summary:hover { color: var(--text-primary); }
    .advanced-details > summary svg {
      width: 12px; height: 12px;
      transition: transform 0.15s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .advanced-details[open] > summary svg { transform: rotate(90deg); }

    .form-subheading {
      font-family: var(--font-heading);
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-tertiary);
      margin: 16px 0 8px;
    }
    .form-subheading:first-child { margin-top: 8px; }

    .form-help {
      font-size: 11px;
      color: var(--text-tertiary);
      margin-top: 4px;
    }
```

- [ ] **Step 3: Start the dev server and verify**

```bash
bun run src/index.ts &
SERVER_PID=$!
sleep 1
curl -sS http://localhost:3100/ | grep -c "secret-form-metadata.js"
curl -sS http://localhost:3100/ | grep -c "advanced-details"
kill $SERVER_PID
```

Expected: both `grep -c` commands print `1` (or more, if matched in multiple places). If either prints `0`, the edit didn't land where expected.

- [ ] **Step 4: Commit**

```bash
git add src/ui/index.html
git commit -m "feat(ui): wire secret-form-metadata.js + add Advanced section CSS"
git push origin main
```

---

## Task 4: Rebuild the create-secret modal

**Files:**
- Modify: `src/ui/index.html` (`openCreateSecretModal()` and `_saveNewSecret`, currently around lines 3363-3443)

- [ ] **Step 1: Replace the create-modal markup and handler**

Find the function `openCreateSecretModal()` (around line 3363). Replace its body, starting from the `const html = \`` template and ending at the closing brace of the function (before `window._editSecret = function(path)`), with the version below.

The replacement keeps the existing path-prefix-chip block intact at the top (compute `prefixList`, `prefixChips`), adds a description textarea, the `requires_approval` toggle, and the Advanced `<details>` section. `_saveNewSecret` is rewritten to use `window.SecretForm.buildMetadata` against state read from the DOM.

```javascript
  function openCreateSecretModal() {
    // Gather existing prefixes for suggestions
    const prefixes = new Set();
    for (const s of allSecrets) {
      const parts = s.path.split('/');
      if (parts.length > 1) prefixes.add(parts.slice(0, -1).join('/'));
    }
    const prefixList = Array.from(prefixes).sort();

    const prefixChips = prefixList.length > 0
      ? `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:6px;">${prefixList.map(p =>
          `<button class="btn btn-ghost" style="font-size:11px;padding:2px 8px;font-family:var(--font-mono);background:var(--bg-tertiary);border:1px solid var(--border);" onclick="document.getElementById('new-secret-path').value='${esc(p)}/';document.getElementById('new-secret-path').focus();">${esc(p)}/</button>`
        ).join('')}</div>`
      : '';

    const html = `
      <div class="modal-overlay" onclick="if(event.target===this)this.remove()">
        <div class="modal">
          <div class="modal-header">
            <h3 class="modal-title">New Secret</h3>
            <button class="modal-close" onclick="this.closest('.modal-overlay').remove()" aria-label="Close">&times;</button>
          </div>
          <div class="form-group">
            <label class="form-label">Path</label>
            <input type="text" id="new-secret-path" placeholder="category/name" spellcheck="false" style="font-family:var(--font-mono);font-size:12px" list="secret-path-suggestions">
            <datalist id="secret-path-suggestions">
              ${prefixList.map(p => `<option value="${esc(p)}/">`).join('')}
            </datalist>
            <div class="form-help">Use forward slashes to organize secrets, e.g. <span style="font-family:var(--font-mono);">api-keys/example</span>, <span style="font-family:var(--font-mono);">db/postgres</span></div>
            ${prefixChips}
          </div>
          <div class="form-group">
            <label class="form-label">Value</label>
            <textarea id="new-secret-value" placeholder="sk-..." rows="3" spellcheck="false"></textarea>
          </div>
          <div class="form-group">
            <label class="form-label">Description</label>
            <textarea id="new-secret-description" placeholder="What is this credential for? Who issued it?" rows="2" spellcheck="false"></textarea>
          </div>
          <div class="form-group">
            <div class="toggle-wrap">
              <div class="toggle" id="new-secret-requires-approval" onclick="this.classList.toggle('on')"></div>
              <label class="form-label" for="new-secret-requires-approval" style="margin:0;cursor:pointer;" onclick="document.getElementById('new-secret-requires-approval').click()">Require human approval</label>
            </div>
            <div class="form-help">Each checkout will pause until an admin approves it.</div>
          </div>

          <details class="advanced-details">
            <summary>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 6l6 6-6 6"/></svg>
              Advanced
            </summary>

            <div class="form-subheading">Auth</div>
            <div class="form-group">
              <label class="form-label">Auth scheme</label>
              <select id="new-secret-auth-scheme" class="input" onchange="document.getElementById('new-secret-header-name-group').classList.toggle('hidden', this.value !== 'header')">
                <option value="none">none</option>
                <option value="bearer">bearer</option>
                <option value="basic">basic</option>
                <option value="header">header</option>
                <option value="query">query</option>
              </select>
            </div>
            <div class="form-group hidden" id="new-secret-header-name-group">
              <label class="form-label">Header name</label>
              <input type="text" id="new-secret-header-name" placeholder="X-API-Key" spellcheck="false">
            </div>

            <div class="form-subheading">Network scope</div>
            <div class="form-group">
              <label class="form-label">Allowed domains</label>
              <input type="text" id="new-secret-allowed-domains" placeholder="api.example.com, *.example.org" spellcheck="false">
            </div>
            <div class="form-group">
              <label class="form-label">Allowed path prefixes</label>
              <input type="text" id="new-secret-allowed-path-prefixes" placeholder="/v1/, /v2/" spellcheck="false">
            </div>
            <div class="form-group">
              <div class="toggle-wrap">
                <div class="toggle" id="new-secret-allow-private" onclick="this.classList.toggle('on')"></div>
                <label class="form-label" style="margin:0;cursor:pointer;" onclick="document.getElementById('new-secret-allow-private').click()">Allow private IPs</label>
              </div>
            </div>
            <div class="form-group">
              <div class="toggle-wrap">
                <div class="toggle" id="new-secret-tls-allow-insecure" onclick="this.classList.toggle('on')"></div>
                <label class="form-label" style="margin:0;cursor:pointer;" onclick="document.getElementById('new-secret-tls-allow-insecure').click()">Allow insecure TLS</label>
              </div>
            </div>
            <div class="form-group">
              <label class="form-label">Rate limit (per minute)</label>
              <input type="number" id="new-secret-rate-limit" min="1" placeholder="60">
            </div>

            <div class="form-subheading">Auto-approval</div>
            <div class="form-group">
              <label class="form-label">Auto-approve from IP</label>
              <input type="text" id="new-secret-auto-ip" placeholder="10.0.0.5" spellcheck="false" oninput="document.getElementById('new-secret-auto-ttl').disabled = !this.value.trim()">
            </div>
            <div class="form-group">
              <label class="form-label">Auto-approve TTL (seconds)</label>
              <input type="number" id="new-secret-auto-ttl" min="1" placeholder="3600" disabled>
            </div>

            <div class="form-subheading">Other metadata</div>
            <div class="form-group">
              <div id="kv-editor"></div>
              <button class="btn btn-ghost btn-sm" onclick="window._addKVRow()" style="margin-top:4px">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                Add field
              </button>
            </div>
          </details>

          <div class="modal-actions">
            <button class="btn btn-ghost" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
            <button class="btn btn-primary" onclick="window._saveNewSecret()">Save Secret</button>
          </div>
        </div>
      </div>
    `;
    document.getElementById('modal-container').innerHTML = html;

    window._addKVRow = function() {
      const editor = document.getElementById('kv-editor');
      const row = document.createElement('div');
      row.className = 'kv-row';
      row.innerHTML = `<input type="text" placeholder="key" style="font-family:var(--font-mono);font-size:12px"><input type="text" placeholder="value"><button class="btn btn-ghost btn-sm" onclick="this.parentElement.remove()" style="flex-shrink:0">&times;</button>`;
      editor.appendChild(row);
    };

    window._saveNewSecret = async function() {
      const path = document.getElementById('new-secret-path').value.trim();
      const value = document.getElementById('new-secret-value').value;
      if (!path || !value) { toast('Path and value required', 'error'); return; }

      const state = window.SecretForm.DEFAULT_STATE();
      state.description = document.getElementById('new-secret-description').value;
      state.requires_approval = document.getElementById('new-secret-requires-approval').classList.contains('on');
      state.auth_scheme = document.getElementById('new-secret-auth-scheme').value;
      state.header_name = document.getElementById('new-secret-header-name').value;
      state.allowed_domains = document.getElementById('new-secret-allowed-domains').value;
      state.allowed_path_prefixes = document.getElementById('new-secret-allowed-path-prefixes').value;
      state.allow_private = document.getElementById('new-secret-allow-private').classList.contains('on');
      state.tls_allow_insecure = document.getElementById('new-secret-tls-allow-insecure').classList.contains('on');
      state.rate_limit_per_minute = document.getElementById('new-secret-rate-limit').value;
      state.auto_approve_from_ip = document.getElementById('new-secret-auto-ip').value;
      state.auto_approve_ttl_seconds = document.getElementById('new-secret-auto-ttl').value;
      state.custom = [];
      document.querySelectorAll('#kv-editor .kv-row').forEach(row => {
        const inputs = row.querySelectorAll('input');
        state.custom.push([inputs[0].value, inputs[1].value]);
      });

      let metadata;
      try {
        metadata = window.SecretForm.buildMetadata(state);
      } catch (e) {
        toast(e.message, 'error');
        return;
      }

      try {
        await api(`/v1/secrets/${path}`, { method: 'POST', body: { value, metadata } });
        toast('Secret created', 'success');
        document.querySelector('.modal-overlay')?.remove();
        loadSecrets();
      } catch (e) {
        toast('Failed: ' + e.message, 'error');
      }
    };
  }
```

- [ ] **Step 2: Smoke-test the served HTML contains the new fields**

```bash
bun run src/index.ts &
SERVER_PID=$!
sleep 1
curl -sS http://localhost:3100/ | grep -E "new-secret-description|new-secret-requires-approval|new-secret-auth-scheme" | wc -l
kill $SERVER_PID
```

Expected: `3` (one line per matching id).

- [ ] **Step 3: Manual click-through** (mark complete after performing)

Open the UI in a browser. Click "New Secret". Verify:
- Description textarea and "Require human approval" toggle are visible by default.
- Advanced section is collapsed; clicking the chevron rotates it and reveals the four subgroups.
- Changing Auth scheme to "header" reveals the Header name field; switching away hides it.
- Typing in Auto-approve from IP enables the TTL field; clearing it disables (and greys out) the TTL field.
- "Other metadata" still has the Add field button and rows behave like before.
- Save: create a secret with description = "test", `requires_approval` on, and one custom kv `x-team=platform`. After save, the new secret appears in the list. Open it; the detail panel shows the metadata keys `description`, `requires_approval`, `x-team`.

- [ ] **Step 4: Commit**

```bash
git add src/ui/index.html
git commit -m "feat(ui): structured create-secret form with Advanced section"
git push origin main
```

---

## Task 5: Rebuild the edit-secret modal with hydration

**Files:**
- Modify: `src/ui/index.html` (`window._editSecret` and `_saveEditSecret`, currently around lines 3445-3525)

- [ ] **Step 1: Replace the edit-modal markup and handler**

Find `window._editSecret = function(path) {` (around line 3445). Replace its body up to and including the closing of `_saveEditSecret` (the final `};` before the `// Leases` comment around line 3525) with:

```javascript
  window._editSecret = function(path) {
    const meta = (window.allSecrets || allSecrets).find(s => s.path === path);
    if (!meta) { toast('Secret not found', 'error'); return; }
    if (meta.kind === 'dynamic') { toast('Dynamic secrets are edited on the Dynamic Secrets page', 'error'); return; }

    const state = window.SecretForm.hydrateMetadata(meta.metadata || {});

    const customRowsHtml = state.custom.length
      ? state.custom.map(([k, v]) =>
          `<div class="kv-row"><input type="text" value="${esc(k)}" style="font-family:var(--font-mono);font-size:12px"><input type="text" value="${esc(String(v))}"><button class="btn btn-ghost btn-sm" onclick="this.parentElement.remove()" style="flex-shrink:0">&times;</button></div>`
        ).join('')
      : '';

    const html = `
      <div class="modal-overlay" onclick="if(event.target===this)this.remove()">
        <div class="modal">
          <div class="modal-header">
            <h3 class="modal-title">Edit Secret</h3>
            <button class="modal-close" onclick="this.closest('.modal-overlay').remove()" aria-label="Close">&times;</button>
          </div>
          <div class="form-group">
            <label class="form-label">Path</label>
            <input type="text" value="${esc(path)}" readonly style="font-family:var(--font-mono);font-size:12px;opacity:0.7">
          </div>
          <div class="form-group">
            <label class="form-label">New Value <span style="color:var(--text-tertiary);font-weight:400;">(leave blank to keep current value and edit metadata only)</span></label>
            <textarea id="edit-secret-value" placeholder="Leave blank to keep current value" rows="3" spellcheck="false"></textarea>
          </div>
          <div class="form-group">
            <label class="form-label">Description</label>
            <textarea id="edit-secret-description" placeholder="What is this credential for? Who issued it?" rows="2" spellcheck="false">${esc(state.description)}</textarea>
          </div>
          <div class="form-group">
            <div class="toggle-wrap">
              <div class="toggle ${state.requires_approval ? 'on' : ''}" id="edit-secret-requires-approval" onclick="this.classList.toggle('on')"></div>
              <label class="form-label" style="margin:0;cursor:pointer;" onclick="document.getElementById('edit-secret-requires-approval').click()">Require human approval</label>
            </div>
            <div class="form-help">Each checkout will pause until an admin approves it.</div>
          </div>

          <details class="advanced-details" ${state.auth_scheme !== 'none' || state.allowed_domains || state.allowed_path_prefixes || state.allow_private || state.tls_allow_insecure || state.rate_limit_per_minute || state.auto_approve_from_ip || state.custom.length ? 'open' : ''}>
            <summary>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 6l6 6-6 6"/></svg>
              Advanced
            </summary>

            <div class="form-subheading">Auth</div>
            <div class="form-group">
              <label class="form-label">Auth scheme</label>
              <select id="edit-secret-auth-scheme" class="input" onchange="document.getElementById('edit-secret-header-name-group').classList.toggle('hidden', this.value !== 'header')">
                ${['none','bearer','basic','header','query'].map(v =>
                  `<option value="${v}" ${state.auth_scheme === v ? 'selected' : ''}>${v}</option>`
                ).join('')}
              </select>
            </div>
            <div class="form-group ${state.auth_scheme === 'header' ? '' : 'hidden'}" id="edit-secret-header-name-group">
              <label class="form-label">Header name</label>
              <input type="text" id="edit-secret-header-name" value="${esc(state.header_name)}" placeholder="X-API-Key" spellcheck="false">
            </div>

            <div class="form-subheading">Network scope</div>
            <div class="form-group">
              <label class="form-label">Allowed domains</label>
              <input type="text" id="edit-secret-allowed-domains" value="${esc(state.allowed_domains)}" placeholder="api.example.com, *.example.org" spellcheck="false">
            </div>
            <div class="form-group">
              <label class="form-label">Allowed path prefixes</label>
              <input type="text" id="edit-secret-allowed-path-prefixes" value="${esc(state.allowed_path_prefixes)}" placeholder="/v1/, /v2/" spellcheck="false">
            </div>
            <div class="form-group">
              <div class="toggle-wrap">
                <div class="toggle ${state.allow_private ? 'on' : ''}" id="edit-secret-allow-private" onclick="this.classList.toggle('on')"></div>
                <label class="form-label" style="margin:0;cursor:pointer;" onclick="document.getElementById('edit-secret-allow-private').click()">Allow private IPs</label>
              </div>
            </div>
            <div class="form-group">
              <div class="toggle-wrap">
                <div class="toggle ${state.tls_allow_insecure ? 'on' : ''}" id="edit-secret-tls-allow-insecure" onclick="this.classList.toggle('on')"></div>
                <label class="form-label" style="margin:0;cursor:pointer;" onclick="document.getElementById('edit-secret-tls-allow-insecure').click()">Allow insecure TLS</label>
              </div>
            </div>
            <div class="form-group">
              <label class="form-label">Rate limit (per minute)</label>
              <input type="number" id="edit-secret-rate-limit" min="1" value="${esc(state.rate_limit_per_minute)}" placeholder="60">
            </div>

            <div class="form-subheading">Auto-approval</div>
            <div class="form-group">
              <label class="form-label">Auto-approve from IP</label>
              <input type="text" id="edit-secret-auto-ip" value="${esc(state.auto_approve_from_ip)}" placeholder="10.0.0.5" spellcheck="false" oninput="document.getElementById('edit-secret-auto-ttl').disabled = !this.value.trim()">
            </div>
            <div class="form-group">
              <label class="form-label">Auto-approve TTL (seconds)</label>
              <input type="number" id="edit-secret-auto-ttl" min="1" value="${esc(state.auto_approve_ttl_seconds)}" placeholder="3600" ${state.auto_approve_from_ip ? '' : 'disabled'}>
            </div>

            <div class="form-subheading">Other metadata</div>
            <div class="form-group">
              <div id="kv-editor-edit">${customRowsHtml}</div>
              <button class="btn btn-ghost btn-sm" onclick="window._addKVRowEdit()" style="margin-top:4px">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                Add field
              </button>
            </div>
          </details>

          <div class="modal-actions">
            <button class="btn btn-ghost" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
            <button class="btn btn-primary" onclick="window._saveEditSecret('${esc(path)}')">Save Changes</button>
          </div>
        </div>
      </div>
    `;
    document.getElementById('modal-container').innerHTML = html;

    window._addKVRowEdit = function() {
      const editor = document.getElementById('kv-editor-edit');
      const row = document.createElement('div');
      row.className = 'kv-row';
      row.innerHTML = `<input type="text" placeholder="key" style="font-family:var(--font-mono);font-size:12px"><input type="text" placeholder="value"><button class="btn btn-ghost btn-sm" onclick="this.parentElement.remove()" style="flex-shrink:0">&times;</button>`;
      editor.appendChild(row);
    };

    window._saveEditSecret = async function(targetPath) {
      const newValue = document.getElementById('edit-secret-value').value;

      const editState = window.SecretForm.DEFAULT_STATE();
      editState.description = document.getElementById('edit-secret-description').value;
      editState.requires_approval = document.getElementById('edit-secret-requires-approval').classList.contains('on');
      editState.auth_scheme = document.getElementById('edit-secret-auth-scheme').value;
      editState.header_name = document.getElementById('edit-secret-header-name').value;
      editState.allowed_domains = document.getElementById('edit-secret-allowed-domains').value;
      editState.allowed_path_prefixes = document.getElementById('edit-secret-allowed-path-prefixes').value;
      editState.allow_private = document.getElementById('edit-secret-allow-private').classList.contains('on');
      editState.tls_allow_insecure = document.getElementById('edit-secret-tls-allow-insecure').classList.contains('on');
      editState.rate_limit_per_minute = document.getElementById('edit-secret-rate-limit').value;
      editState.auto_approve_from_ip = document.getElementById('edit-secret-auto-ip').value;
      editState.auto_approve_ttl_seconds = document.getElementById('edit-secret-auto-ttl').value;
      editState.custom = [];
      document.querySelectorAll('#kv-editor-edit .kv-row').forEach(row => {
        const inputs = row.querySelectorAll('input');
        editState.custom.push([inputs[0].value, inputs[1].value]);
      });

      let metadata;
      try {
        metadata = window.SecretForm.buildMetadata(editState);
      } catch (e) {
        toast(e.message, 'error');
        return;
      }

      try {
        if (newValue) {
          await api(`/v1/secrets/${targetPath}`, { method: 'POST', body: { value: newValue, metadata } });
          toast('Secret updated (new version)', 'success');
        } else {
          await api(`/v1/secrets/${targetPath}`, { method: 'PATCH', body: { metadata } });
          toast('Metadata updated', 'success');
        }
        document.querySelector('.modal-overlay')?.remove();
        await loadSecrets();
        window._selectSecret(targetPath);
      } catch (e) {
        toast('Failed: ' + e.message, 'error');
      }
    };
  };
```

Note: the original `_editSecret` is replaced wholesale; the existing `// Leases` comment block immediately after must remain untouched. Be careful with the closing braces.

- [ ] **Step 2: Smoke-test the served HTML**

```bash
bun run src/index.ts &
SERVER_PID=$!
sleep 1
curl -sS http://localhost:3100/ | grep -E "edit-secret-description|edit-secret-auth-scheme|kv-editor-edit" | wc -l
kill $SERVER_PID
```

Expected: `3`.

- [ ] **Step 3: Manual round-trip test** (mark complete after performing)

Open the UI in a browser:
1. Edit the secret created in Task 4 Step 3 (the one with description="test", requires_approval=on, x-team=platform). Verify:
   - The Description field is pre-filled with "test".
   - The "Require human approval" toggle is on.
   - The Advanced section is open (because there's custom metadata).
   - The "Other metadata" rows show `x-team` / `platform`.
2. Save with no edits. Toast "Metadata updated" appears. Re-open the same secret in edit. All fields are still the same. Open the detail panel; metadata is still exactly `{ description, requires_approval, x-team }`. No new keys, no dropped keys.
3. Edit again. Turn requires_approval OFF. Save. Re-open in edit; the toggle is now off. Detail panel no longer shows `requires_approval`.
4. Create a secret called `api-keys/test-roundtrip` via raw API call with a legacy `requires_approval=false`:
   ```bash
   curl -sS -X POST http://localhost:3100/v1/secrets/api-keys/test-roundtrip \
     -H "Authorization: Bearer <your token>" \
     -H "Content-Type: application/json" \
     -d '{"value":"x","metadata":{"requires_approval":"false","auth_scheme":"bearer"}}'
   ```
   Open it in the UI's edit modal. Confirm: toggle is off, auth_scheme dropdown shows "bearer". Save with no other edit. Confirm the detail panel now shows only `auth_scheme=bearer` (the legacy `false` was normalized away).
5. Create a secret with a hand-crafted custom auth scheme (unknown to the form):
   ```bash
   curl -sS -X POST http://localhost:3100/v1/secrets/api-keys/test-weird-scheme \
     -H "Authorization: Bearer <your token>" \
     -H "Content-Type: application/json" \
     -d '{"value":"x","metadata":{"auth_scheme":"weird-scheme"}}'
   ```
   Open in edit. Confirm: dropdown is on "none", and the Other metadata section shows `auth_scheme` / `weird-scheme`. Save with no other edit. Detail panel still shows `auth_scheme=weird-scheme` (unknown values survive round-trip via the custom kv path).

- [ ] **Step 4: Commit**

```bash
git add src/ui/index.html
git commit -m "feat(ui): structured edit-secret form with metadata hydration"
git push origin main
```

---

## Task 6: Version bump, changelog, tag

**Files:**
- Modify: `src/version.ts`
- Modify: `CHANGELOG.md`
- Modify: `package.json` (version field, if it tracks; verify first)

- [ ] **Step 1: Inspect the current version sources**

```bash
grep -E "version|VERSION" src/version.ts package.json | head -5
```

Expected: `src/version.ts` exports `VERSION = "0.14.6"`. `package.json` has its own `"version": "0.2.1"` that is unrelated to releases (used for npm metadata). The release-tracked version is `src/version.ts` only.

- [ ] **Step 2: Bump `src/version.ts` to 0.15.0**

Replace the line in `src/version.ts`:

```typescript
export const VERSION = "0.15.0";
```

(Minor bump: new visible feature, no breaking change.)

- [ ] **Step 3: Add a CHANGELOG entry**

Open `CHANGELOG.md`. Find the top of the file (most recent release). Insert a new entry directly above the most recent one:

```markdown
## 0.15.0

- **Secret form**: replaced the generic key/value editor in the create/edit modal with dedicated controls. `requires_approval` is now a first-class toggle. A new `description` field captures what each secret is for. Known metadata keys (`auth_scheme`, `header_name`, `allowed_domains`, `allowed_path_prefixes`, `allow_private`, `tls_allow_insecure`, `rate_limit_per_minute`, `auto_approve_from_ip`, `auto_approve_ttl_seconds`) live under a single collapsed Advanced section with the right control type for each (dropdown, toggle, number). Unknown keys keep working via an "Other metadata" escape hatch. Edit round-trip is preserved with two intentional normalizations: legacy `requires_approval=false` is dropped (now equivalent to omitted), and orphan `auto_approve_ttl_seconds` (no paired IP) is dropped.
- No server-side changes. Wire format is unchanged.
```

- [ ] **Step 4: Verify the bump and run the full test suite**

```bash
grep VERSION src/version.ts
bun test
```

Expected: `VERSION = "0.15.0"` and the full suite passes.

- [ ] **Step 5: Commit and tag**

```bash
git add src/version.ts CHANGELOG.md
git commit -m "$(cat <<'EOF'
feat(0.15.0): structured fields in secret create/edit modal

- requires_approval becomes a first-class toggle
- new description field for self-documenting secrets
- known metadata keys grouped under a collapsed Advanced section
- raw kv editor preserved as the escape hatch for unknown keys
- round-trip safe; two intentional normalizations
EOF
)"
git tag v0.15.0
git push origin main
git push origin v0.15.0
```

- [ ] **Step 6: Sync to GitHub** (per project convention: GitHub is a curated mirror)

The project has a sync script for pushing the curated state to GitHub. Run it if it exists:

```bash
ls scripts/ | grep -iE "sync.?github"
```

If a sync script is present (e.g., `scripts/sync-to-github.ts`), run it per its usage instructions. If not, skip this step and ask the user whether to sync; do NOT manually push to GitHub from this repo (CLAUDE.md / plans/ must never leak).

---

## Self-review

After implementing, re-read the spec section by section and confirm:

- [ ] **Spec goal 1** (requires_approval toggle): Task 4 + Task 5 markup contains `<div class="toggle" id="new-secret-requires-approval">` and `id="edit-secret-requires-approval"`. ✓
- [ ] **Spec goal 2** (description text field): Task 4 + Task 5 markup contains `id="new-secret-description"` and `id="edit-secret-description"`. ✓
- [ ] **Spec goal 3** (Advanced collapsed section with the rest): Task 4 + Task 5 markup contains `<details class="advanced-details">` with the four subgroups. ✓
- [ ] **Spec goal 4** (raw kv editor preserved): Task 4 + Task 5 keep `kv-editor` / `kv-editor-edit` and the Add field button inside the Advanced section. ✓
- [ ] **Spec goal 5** (no server change): only `src/index.ts` is modified for the new static file route. No change to secrets engine, secrets router, or lease/proxy code. ✓
- [ ] **Wire format**: `buildMetadata` omits defaults; structured fields win on key collision. Test suite in Task 1 covers all of these. ✓
- [ ] **Edit hydration**: round-trip preserves canonical metadata; the two intentional normalizations (`requires_approval=false` -> omitted; orphan `auto_approve_ttl_seconds` -> omitted) are explicitly tested. ✓
- [ ] **Validation**: `auth_scheme=header` without `header_name` throws in `buildMetadata`; the save handlers catch and toast the error. Number fields clamp via `min="1"` HTML attr and `writeIfPositiveInt` ignores invalid values. ✓
- [ ] **Visual details**: section subheadings in font-heading 11px uppercase; details summary chevron rotates on open; native `<details>` disclosure; no new keyframes. Task 3 CSS covers each. ✓
- [ ] **Implementation surface**: only `src/ui/index.html`, `src/ui/secret-form-metadata.js`, `src/index.ts`, `src/version.ts`, `CHANGELOG.md`, and the new test file are touched. ✓

If any of the above is unchecked after implementation, fix before finishing.
