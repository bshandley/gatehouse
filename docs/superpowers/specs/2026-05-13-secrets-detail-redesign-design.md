# Secrets Page Detail Redesign

Date: 2026-05-13
Status: Draft

## Problem

The Secrets page detail panel is a flat scroll of equal-weight sections: Version/Created/Updated grid, a generic `key | value` metadata table, an approval banner (for gated secrets), a reveal box, and three small buttons (Edit, Create Lease, Delete). The `description` field added in v0.15.0 renders as just another row in the metadata table, and so do `auth_scheme`, `allowed_domains`, and `rate_limit_per_minute`. The structured create/edit form has no structured display surface to match.

Operators auditing a secret should be able to answer five questions in order, without clicking through tabs:

1. What is this credential? (identity)
2. How is it locked down? (posture)
3. Is it being used? (activity)
4. What is the value? (reveal)
5. What do I do with it? (actions)

The current panel buries 1 and 2 behind a generic table and gives 3 only inconsistent treatment (the approval-gated section). The redesign promotes each question to its own block with information hierarchy that matches operator priority.

## Goals

1. Promote `description` from a metadata-table row to a paragraph at the top.
2. Render security-relevant metadata (`auth_scheme`, `allowed_domains`, `allowed_path_prefixes`, `rate_limit_per_minute`, `requires_approval`, `allow_private`, `tls_allow_insecure`) as a labeled-chip block, with subtle semantic color when a value relaxes the default posture.
3. Show recent activity inline: up to 3 active leases AND up to 3 recent audit events, with a "view all" link to deeper surfaces.
4. Add a click-to-copy chip showing the exact `{{secret:<path>}}` reference syntax.
5. Reorder action buttons so Create Lease becomes the primary action.
6. Tree-pane: append a small auth-scheme chip after each secret name when `auth_scheme` is set.
7. Empty-state: add a single tertiary stats line above the existing icon.

## Non-goals

- New server endpoints. The existing `/v1/audit?path=<path>&limit=N` already supports the audit feed; the existing `/v1/lease?path=<path>` supplies the leases.
- A Versions UI (the engine supports `listVersions` / `rollback` but the UI for it is out of scope for this redesign).
- A tabbed detail panel. Tabs hide information; for a security tool everything-visible-at-once beats organized-but-hidden.
- Mobile / narrow-viewport redesign. The two-pane grid stays.
- Filter chips above the tree. Defer.
- Mini-dashboard empty state. Defer.
- Changes to the Dynamic Secrets detail variant (the existing dynamic-kind detail branch stays as-is; this work targets static secrets).

## Detail panel design

The panel becomes a vertical scroll of five blocks plus an optional unknown-metadata block at the bottom. Each block has a small uppercase section heading in `--font-heading` 11px (matching the form's `.form-subheading`) and shows nothing when its underlying data is empty.

### Block 1: Identity

Top of panel. Existing approval banner (if `requires_approval=true`) stays above this block for prominence.

Contents:
- Path: existing mono heading, 16px, with the existing 16px bottom-padding + border.
- Reference chip: inline, immediately right of the path, mono 11px, rendering `{{secret:<path>}}` verbatim inside a 1px bordered pill. Click copies to clipboard; toast on success ("Reference copied"). Tooltip on hover: "Click to copy".
- Description: paragraph below the path/chip row. Pulled from `metadata.description`. If absent, the description block is omitted entirely (no placeholder).
- Stamps line: single tertiary-color row below description, format: `v{version} · created {fmtTime(created_at)} · updated {fmtTime(updated_at)}`.

The existing 3-column grid for Version / Created / Updated is removed.

### Block 2: Posture

Heading: `POSTURE`. Always rendered if the secret has ANY structured posture data; otherwise the whole block is omitted (only the unknown-metadata table at the bottom would render).

Layout: a flex-wrap row of stacked chips. Each chip is:
- A small uppercase label in tertiary color (`AUTH`, `SCOPE`, `PATHS`, `RATE`, `APPROVAL`)
- A value line below in primary color (`bearer`, `api.anthropic.com`, `60/min`, `required`)

Chip set, in order, omitting any chip whose value is empty/default:

| Chip | Source | Default-omit | Value rendering |
|---|---|---|---|
| AUTH | `auth_scheme`, `header_name` | when `auth_scheme` absent or `none` | `bearer`, `basic`, `query`, or `header:X-API-Key` (when scheme=header) |
| SCOPE | `allowed_domains` | when absent | comma-joined list, truncated with ellipsis past ~40 chars (tooltip shows full) |
| PATHS | `allowed_path_prefixes` | when absent | comma-joined |
| RATE | `rate_limit_per_minute` | when absent | `{n} / min` |
| APPROVAL | `requires_approval` | when not "true" | `required` |
| PRIVATE | `allow_private` | when not "true" | `private IPs ok` |
| TLS | `tls_allow_insecure` | when not "true" | `insecure TLS ok` |
| AUTO-IP | `auto_approve_from_ip` | when absent | the IP value |
| AUTO-TTL | `auto_approve_ttl_seconds` | when absent | `{n}s` |

Semantic color logic:
- APPROVAL chip when set: accent color (`--accent`) value text.
- PRIVATE, TLS, AUTO-IP, AUTO-TTL chips: subtle warning tint (`--warning` value, `rgba(251,191,36,0.06)` background). These all relax the default posture.
- All other chips: neutral (primary value text, no tint).

If `SCOPE` is absent AND `auth_scheme` is set (i.e., the secret has auth wiring but no host allowlist, making it usable against any host), render a single small warning-tint chip in its slot: `SCOPE / no allowed_domains`. This is the one inferred-from-absence chip; everything else only renders when its underlying key is present.

### Block 3: Activity

Heading: `ACTIVITY`. To the right of the heading, a single tertiary-color summary line shows counts: `{N} active leases · {M} events / 24h`. Both counts populate asynchronously; while loading the line reads `loading...`.

Underneath, two sub-blocks. Each sub-block has its own micro-heading (`LEASES`, `EVENTS`) and a "view all" link aligned to the right of the micro-heading. Each renders up to 3 rows; if more exist the "view all" link is shown; otherwise the link is hidden.

LEASES rows (one line each):
- Format: `{identity}    expires {fmtTime(expires_at)}` (left + right justified within the row)
- If `secret.requires_approval && lease.status === 'approved'`, append a small inline tag `(gated)` in tertiary color
- Empty state: omit the LEASES sub-block entirely (don't show "no leases")

EVENTS rows (single line each):
- Format: `{relativeTime}    {action}    {identity}    {ok|fail}`
- `action` uses the raw audit action string (`secret.read`, `lease.created`, `lease.approved`, `proxy.forward`, etc.); render in mono
- `ok|fail` is a tiny tag: `ok` in neutral, `fail` in warning
- Empty state: omit the EVENTS sub-block entirely

When BOTH sub-blocks are empty: render a single tertiary line under the ACTIVITY heading: `No recent activity.`

"View all" link behavior:
- LEASES → navigates to the Leases page with a search pre-applied filtering this path (uses an existing pattern; if no client-side filter exists for leases-page-by-path, the link drops the filter and just navigates)
- EVENTS → navigates to the Audit page with the path filter pre-applied (the existing audit page already supports `?path=` query; if not, the link sets the filter input value and triggers its filter handler)

### Block 4: Value

Heading: implicit (the existing `reveal-label` "Secret Value" reads as the block heading). The existing `.reveal-box` stays as-is in structure (border, padding, reveal toggle, masked display). Visual weight is lower than Posture/Activity because the operator rarely needs the raw value.

### Block 5: Action bar

A flex row at the bottom of the panel.

- `+ Create Lease`: primary button (filled `--accent`), uses the existing `_leaseSecret(path)` handler. Left-aligned.
- `Edit`: ghost button, uses the existing `_editSecret(path)` handler. Inline after Create Lease.
- `Delete`: danger ghost button, uses the existing `_deleteSecret(path)` handler. Right-aligned (push to end via `margin-left: auto`).

The existing icons stay on each button.

### Block 6 (optional): Unknown metadata

Heading: `OTHER METADATA` (tertiary, small). Rendered ONLY if there are metadata keys present that are NOT consumed by the Posture chip set or the Identity description.

Same `.meta-table` styling as today; one row per unknown key. Demoted visually (smaller heading, table inside a softer container or with reduced contrast). This is the symmetric counterpart to the form's "Other metadata" escape hatch.

## Tree-pane changes

The only change to the left tree: append a small auth-scheme chip after each secret name when `metadata.auth_scheme` is present and not `"none"`.

- Chip format: `[bearer]`, `[basic]`, `[query]`, or `[header:<X-Header-Name>]` (full header name when scheme=header)
- Styling: 10px mono, `--text-tertiary`, no background, lightly faded; rendered with a single leading space after the name
- Hide when `auth_scheme` is absent

The existing approval lock chip (`🔒 approval`) keeps its current styling and position.

No filter chips, no tree-level posture warnings, no other tree-row changes.

## Empty state

When no secret is selected, the existing icon + "Select a secret to view details" stays. Above it, render a single tertiary-color line in `--font-mono` 11px:

```
{N} secrets · {M} require approval · {K} touched this week
```

Counts:
- N: `allSecrets.length`
- M: count of `allSecrets` where `metadata.requires_approval === "true"`
- K: count of `allSecrets` where `updated_at` is within the last 7 days

When `N === 0`, hide the stats line and keep only the existing "No secrets stored yet" empty-state message.

## Data sources

All data comes from endpoints that already exist; no server work.

- Secret metadata: `GET /v1/secrets` (already loaded into `allSecrets`)
- Active leases for this path: `GET /v1/lease?path={path}`, client-side filter `lease.secret_path === path` (or `lease.path`), keep only non-revoked. Same fetch pattern as `_loadApprovedLeasesForPath` today; extend to ALL secrets, not just approval-gated ones. Cap displayed rows at 3.
- Recent audit events for this path: `GET /v1/audit?path={path}&limit=10`, then client-side filter to `entry.path === path` (the server-side filter is a `LIKE` prefix match so we may receive entries for `api-keys/anthropic-staging` when asking for `api-keys/anthropic`). Cap displayed at 3. Compute "events / 24h" count from the full set.
- Stats line counts: derived from `allSecrets` already in memory.

All Activity fetches run in parallel (`Promise.all`) and are non-blocking: the rest of the panel renders synchronously; the Activity block shows `loading...` and then swaps in.

## Visual specifics

New CSS rules (added near the existing detail-pane styles around `index.html:920`):

```css
.detail-identity { display: flex; flex-direction: column; gap: 6px; margin-bottom: 20px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
.detail-identity-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.detail-path-mono { font-family: var(--font-mono); font-size: 16px; font-weight: 500; }
.detail-ref-chip {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-secondary);
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 3px 8px;
  cursor: pointer;
  user-select: all;
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
.posture-chip-value { font-size: 13px; color: var(--text-primary); font-family: var(--font-mono); }
.posture-chip.is-accent .posture-chip-value { color: var(--accent); }
.posture-chip.is-warn { background: rgba(251,191,36,0.06); border-color: rgba(251,191,36,0.2); }
.posture-chip.is-warn .posture-chip-value { color: var(--warning); }

.activity-subsection { margin-top: 12px; }
.activity-subhead { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 6px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-tertiary); font-weight: 600; }
.activity-subhead a { font-size: 11px; color: var(--text-secondary); text-transform: none; letter-spacing: 0; font-weight: 400; }
.activity-row { display: grid; grid-template-columns: auto 1fr auto; gap: 12px; padding: 6px 0; font-size: 12px; align-items: center; border-bottom: 1px solid var(--border); }
.activity-row:last-child { border-bottom: none; }
.activity-row-time { font-family: var(--font-mono); color: var(--text-tertiary); font-size: 11px; min-width: 60px; }
.activity-row-id { color: var(--text-secondary); }
.activity-row-tag { font-size: 10px; padding: 2px 6px; border-radius: 4px; font-family: var(--font-mono); }
.activity-row-tag.is-ok { color: var(--text-tertiary); background: var(--bg-tertiary); }
.activity-row-tag.is-fail { color: var(--danger); background: var(--danger-subtle); }
.activity-row-tag.is-meta { color: var(--text-tertiary); background: transparent; padding-left: 0; }

.tree-item-auth { font-family: var(--font-mono); font-size: 10px; color: var(--text-tertiary); margin-left: 4px; opacity: 0.7; }

.detail-empty-stats { font-family: var(--font-mono); font-size: 11px; color: var(--text-tertiary); margin-bottom: 24px; text-align: center; }
```

Matches existing `.form-subheading` / `.form-help` / `.toggle` typography conventions; uses existing CSS vars only; no new fonts.

## Implementation surface

Single file: `src/ui/index.html`.

Functions touched:
- `selectSecret(path)` (around line 3172): rewrite the static-secret branch's `innerHTML` template to use the new block structure. The dynamic-kind branch stays unchanged. Add the two async fetches (`/v1/lease?path=` and `/v1/audit?path=`) and wire the Activity block to a separate render function.
- `renderSecretTree(secrets)` (around line 3134): append the auth chip when `_isApprovalRequired` is read (the same loop can read `metadata.auth_scheme`).
- `loadSecrets()` (around line 3107): the empty-state HTML it writes gets the new stats line.
- The CSS block in `<style>` (around line 920): add the new rules above.

New helper functions (inline in the same `<script>` block):
- `_renderPostureBlock(meta)` → HTML string for Block 2. Pure: takes metadata, returns HTML.
- `_renderActivityBlock(path, requiresApproval)` → returns the placeholder HTML for Block 3; kicks off `_loadActivityForPath(path)` which populates it.
- `_loadActivityForPath(path)` → parallel fetch of leases + audit, render into the placeholder.
- `_referenceChipForPath(path)` → HTML for the click-to-copy chip.

Like the v0.15.0 form work, the pure helpers (`_renderPostureBlock`, the activity-line formatters) take primitive inputs and return strings; they can be unit-tested without a browser if extracted to a separate ES module. **Decision: extract** the pure formatters to `src/ui/secret-detail-render.js`, served from a new route mirroring the form-metadata file. This keeps testability symmetric with v0.15.0 and lets the unit tests cover the chip-selection / semantic-color / activity-row logic.

## Validation / error handling

- Reference-chip copy failure: fall back to `document.execCommand('copy')` if `navigator.clipboard.writeText` throws (older browsers/non-secure contexts). Toast on success ("Reference copied"). If both fail, toast error ("Copy failed").
- Activity fetch failure: render `Failed to load activity.` in tertiary color in place of the rows. Don't block the rest of the panel.
- Audit prefix-collision: client-side filter is `entry.path === path` exact match. Tested in the unit tests.
- Stats line: if `allSecrets` is empty, render the existing "No secrets stored yet" message instead.

## Test plan

Unit (bun test) for the extracted module:

1. Posture chip selection: given various `metadata` shapes, returns the right set of chips (omits absent keys, includes inferred `SCOPE / no allowed_domains` warning when auth is set without domains).
2. Posture color assignment: `requires_approval=true` → accent class; `allow_private=true` → warn class; canonical bearer-token secret has no warn classes.
3. Activity-row formatter: given a raw audit entry, produces the time/action/identity/ok-fail row HTML; handles `success=false` (warn tag), missing identity (renders `-`).
4. Reference chip output: given a path, produces the `{{secret:<path>}}` text and HTML.
5. Empty-state stats: given `allSecrets`, computes the correct counts (total, approval-gated, touched-in-last-7-days).

Manual:

1. Create a secret with description, bearer auth, allowed_domains, rate_limit_per_minute, requires_approval. Open detail: Identity has description + reference chip; Posture has 5 chips with APPROVAL in accent color; Activity shows "no recent activity" (fresh secret); Value reveal works; Create Lease is primary.
2. Click the reference chip: toast "Reference copied", clipboard contains `{{secret:<path>}}`.
3. Create a lease for the secret, then re-open detail. Activity now shows the lease row; if it's approval-gated and approved, the `(gated)` tag is present.
4. Reveal the value, then re-open detail. Activity shows a `secret.read` event row.
5. Edit a secret to remove `allowed_domains` while keeping `auth_scheme=bearer`. Detail shows the warning-tinted `SCOPE / no allowed_domains` chip.
6. Edit a secret to add `allow_private=true`. Detail shows a warning-tinted `PRIVATE / private IPs ok` chip.
7. Tree: secrets with `auth_scheme` set show `[bearer]` (etc.) after the name. Secrets without `auth_scheme` show no chip.
8. With no secret selected, the empty state shows the stats line. With zero secrets, it shows "No secrets stored yet" (unchanged).
9. Click "view all" beside Activity LEASES: navigates to Leases page. Click "view all" beside EVENTS: navigates to Audit page with this path filtered.
10. Theme: light + dark both render the new chips and rows correctly (warning tint visible in both, accent color present in both).
11. Long values: a `SCOPE` chip with 5 comma-separated domains gets truncated with ellipsis; hover shows full value via title attribute.

## Risk

Low to moderate. Pure UI work on a single file plus one new helper file. The async activity fetch is a new pattern but follows the same approach as the existing `_loadApprovedLeasesForPath`. The Posture chip logic is testable in isolation. Rollback is a single revert. The biggest risk is theme-drift (warning tint and accent color rendering correctly in both light/dark); covered by the manual theme test.
