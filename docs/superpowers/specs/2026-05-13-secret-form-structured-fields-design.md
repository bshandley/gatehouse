# Secret Form: Structured Fields Design

Date: 2026-05-13
Status: Draft

## Problem

The Secret create/edit modal is currently a generic key/value editor. There is no UI affordance for the metadata keys Gatehouse actually reads at runtime (`requires_approval`, `allowed_domains`, `auth_scheme`, `rate_limit_per_minute`, etc.). Operators must remember the exact key names and acceptable string values, with no defaults and no visual signal of which fields matter most.

The most consequential field is `requires_approval`: forgetting to set it leaves a secret that checks out silently without human approval. It deserves a first-class toggle, not a buried key/value row.

## Goals

1. Promote `requires_approval` to a visible toggle at the top of the create/edit modal.
2. Promote a `description` text field so secrets become self-documenting.
3. Group the rest of the known metadata keys (auth, network scope, auto-approval) under a single collapsed "Advanced" section with dedicated controls.
4. Preserve the existing raw key/value editor inside Advanced as the escape hatch for unknown keys.
5. No server change. The form still emits `metadata: Record<string,string>` exactly as today.

## Non-goals

- Adding new server-side semantics (e.g., `enabled`, `expires_at`, rotation reminders, tags). Easy to add later; doing it now would mean empty fields with no behavior.
- Validating field values server-side. The server still accepts any string.
- Touching the dynamic-secrets edit flow. This work is scoped to static secrets only.

## UI design

The modal stays in its current size (~440-560px wide). Fields are added in a single column matching the existing `.form-group` rhythm.

### Visible by default

Order, top to bottom:

1. **Path** (text, existing, read-only when editing).
2. **Value** (textarea, existing). Placeholder unchanged. When editing, the existing "leave blank to keep current value" hint is preserved.
3. **Description** (textarea, 2 rows, new). Maps to `metadata.description`. Placeholder: "What is this credential for? Who issued it?". No length cap. Empty string is not written to metadata (the key is omitted).
4. **Require human approval** (toggle, new). Maps to `metadata.requires_approval`. When on, written as the literal string `"true"`. When off, the key is omitted entirely (not written as `"false"`). Helper line below the toggle in `--text-tertiary`: "Each checkout will pause until an admin approves it."

### Toggle control

Reuse the existing `.toggle` / `.toggle-wrap` component (defined at index.html:1386). It is a 36x20 sliding switch that glows with `--accent` when on. Do not use a native `<input type=checkbox>` here. The toggle is the same control used elsewhere in the admin UI, so it preserves visual consistency and gives the field a satisfying flick rather than a square tick.

### Advanced section

A single `<details>` block titled "Advanced", default collapsed. Reuse the existing `<details>/<summary>` pattern already in the codebase (index.html:4520) but with a section-header style summary: 13px, `--text-secondary`, with a rotating chevron. When opened, content reveals naturally via the native disclosure (no JS animation).

Inside, fields are grouped with small subheadings in `--font-heading` and a tertiary divider line:

**Auth**
- `auth_scheme` (`<select class="input">`): `none`, `bearer`, `basic`, `header`, `query`. Default `none`. Writes the selected string, except `none` which omits the key.
- `header_name` (text). Hidden via the existing `.hidden` class unless `auth_scheme === "header"`. Toggled via a change listener on the auth_scheme select.

**Network scope**
- `allowed_domains` (text, csv). Placeholder: `api.example.com, *.example.org`.
- `allowed_path_prefixes` (text, csv). Placeholder: `/v1/, /v2/`.
- `allow_private` (toggle). Off by default. On writes `"true"`; off omits.
- `tls_allow_insecure` (toggle). Off by default.
- `rate_limit_per_minute` (`<input type=number>`, min 1). Empty omits the key.

**Auto-approval**
- `auto_approve_from_ip` (text). Placeholder: `10.0.0.5`.
- `auto_approve_ttl_seconds` (`<input type=number>`, min 1). Greyed out (`disabled`) until `auto_approve_from_ip` is non-empty; visual signal that the two are paired. If `auto_approve_from_ip` is empty at save time, `auto_approve_ttl_seconds` is also omitted regardless of its value (the TTL alone is meaningless without an IP to auto-approve).

**Other metadata**
- The existing `.kv-row` key/value editor, unchanged. Used for any key Gatehouse does not surface as a dedicated control.

### Field ordering rationale

Description sits below value rather than above it because the value is the primary action that brought the operator to the modal. Description and the approval toggle are paired immediately after value so the operator sees them before they hit Save. Advanced is the last section so the modal looks small at rest.

## Wire format

On submit, the form constructs a `metadata` object by walking each control in order:

1. Start with `metadata = {}`.
2. For each structured control, if its value differs from the default (empty string, off toggle, `auth_scheme === "none"`, etc.), write it under its canonical key name.
3. For each `.kv-row` in the custom-metadata editor with a non-empty key, write that pair, **unless** the key is already present from step 2 (structured fields win to prevent duplicates if an operator typed the same key in both places).
4. Submit the existing payload shape: `POST /v1/secrets/<path>` with `{ value, metadata }`, or `PATCH /v1/secrets/<path>` with `{ metadata }` for metadata-only edits.

No backend changes. The server already accepts `metadata: Record<string,string>` and stores it verbatim.

## Edit-mode hydration

When opening the edit modal for an existing secret:

1. Read `meta.metadata`.
2. For each canonical key the form knows about, pop it from a working copy and hydrate the matching control. `requires_approval === "true"` flips the toggle on; any other value (or missing key) leaves it off. Numeric fields parse the string with `Number()`; if `NaN`, leave the input empty.
3. Anything left in the working copy becomes a `.kv-row` in the custom-metadata editor.
4. On save, the same wire-format rules apply. A round-trip with no edits MUST produce a metadata object semantically equal to the original (no spurious keys added or dropped).

The only intentional asymmetry: a stored `requires_approval=false` (legacy or hand-edited) is hydrated as "off" and on save will be omitted, not rewritten as `"false"`. This is desirable: it normalizes existing inconsistent data toward "key present means true."

## Validation

Client-side, light-touch:

- `allowed_domains`: trim each csv entry; warn (but do not block) if any entry contains `://` or whitespace.
- `auth_scheme === "header"`: require `header_name` non-empty before submit. Inline error below the field on attempted save.
- `rate_limit_per_minute`, `auto_approve_ttl_seconds`: clamp to integers >= 1 on blur. Empty is fine.
- `auto_approve_from_ip`: no format check (could be v4, v6, or CIDR depending on future server behavior). Free-form text.

No new server-side validation. The server today accepts any string; this stays true.

## Visual details

- Section subheadings inside Advanced: `font-family: var(--font-heading)`, `font-size: 11px`, `text-transform: uppercase`, `letter-spacing: 0.08em`, `color: var(--text-tertiary)`, `margin: 16px 0 8px`. Matches the typographic restraint of the rest of the admin UI.
- Each subheading sits above its group with no horizontal rule. Visual grouping comes from the type contrast, not from boxes or borders.
- The Advanced `<summary>` chevron uses the same SVG style as `<select>` (index.html:572). Rotate 90deg when `<details>` is open via the `[open] > summary svg` CSS selector.
- Spacing: existing `.form-group` margin (16px) between every field. No tighter grouping inside Advanced; the type subheadings do the grouping work.
- No new animations. The native `<details>` disclosure is enough; the modal's existing `modalIn` keyframe handles entry.

## Out-of-scope follow-ups (recorded for later)

- Surface `description` in the secret-detail panel (currently the panel iterates raw metadata; description would render better as a top-level paragraph above the metadata table).
- Surface `description` in `gatehouse_list` MCP output so agents can see the human description without an extra round trip.
- Add an `enabled` field (kill-switch separate from delete). Requires server-side gating in proxy + lease paths.
- Add `expires_at` / `next_rotation_at` reminders. Requires a reaper or notification path.

## Test plan

Unit-level (form logic, testable in JSDOM or via Playwright):

1. Create flow: every default value omitted produces `metadata: {}`.
2. Create flow: toggling `requires_approval` on writes `{ requires_approval: "true" }` and nothing else.
3. Create flow: setting `auth_scheme=header` without `header_name` blocks submit and shows the inline error.
4. Edit flow: round-trip with no edits leaves stored metadata semantically equal (with two intentional exceptions: legacy `requires_approval=false` becomes omitted, and orphan `auto_approve_ttl_seconds` without a paired IP becomes omitted).
5. Edit flow: legacy `requires_approval=false` is hydrated as off, omitted on save.
6. Edit flow: unknown keys land in the custom-metadata editor and survive round-trip.
7. Submit flow: structured field beats custom-metadata row if both target the same key.

Manual:

1. Create a secret with all defaults; confirm in the secret detail panel that metadata renders as empty.
2. Create an approval-gated bearer-token secret with `allowed_domains`; confirm the proxy honors all three.
3. Edit a hand-crafted secret with the raw key/value editor today; confirm Advanced fields hydrate correctly.
4. Theme: open the modal in both dark and light themes; toggle, select chevron, and section subheadings render correctly in both.

## Implementation surface

Single file, single function-pair touch:

- `src/ui/index.html`: `_addSecret()` (creates the modal HTML and `_saveNewSecret` handler) and `_editSecret()` (creates the edit modal HTML and `_saveEditSecret` handler). Both currently live around lines 3370-3525.
- New helpers (likely inline in the same script block): `buildStructuredMetadata(form)` and `hydrateStructuredFields(form, metadata)`. Sharing them keeps the two flows symmetric.
- No new CSS files. New section-subheading and details-summary styles added to the existing `<style>` block.
- No server change. No new tests outside the UI tier.

## Risk

Low. Pure UI work. Worst case: a typo in `hydrateStructuredFields` could drop a known key on round-trip; the round-trip test in the plan catches that. Server semantics are untouched and rollback is a single revert.
