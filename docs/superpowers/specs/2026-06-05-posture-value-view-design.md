# Posture and value view

Date: 2026-06-05
Status: design
Sub-project D of the ubiquity roadmap. Cheap, independent, slot in anytime.

## Problem

A security layer that works is invisible, and invisible tools get uninstalled.
Gatehouse is already sitting on the data for a posture view, but it shows the
operator almost none of it.

Two specific gaps, both verified:

1. The scrubber runs but records nothing. `scrubResponseBody` strips secret
   values out of proxied responses (`src/api/proxy.ts:657`,
   `src/mcp/server.ts:811`) and `gatehouse_scrub` returns `redaction_count`
   (`src/mcp/server.ts:563`), but no count is ever persisted. The single most
   compelling sentence the product could say, "credentials kept out of your
   agents' context this week: N," cannot be computed today.

2. Static secrets never expire and the `secrets` table has no last-access
   column (only `created_at`, `updated_at`, `version`). The audit log does
   record read events, so "unused 90 days" and "18 months old, rotate" are
   computable, but nothing computes or shows them.

The dashboard already has a 4-card `.stat-grid` (total secrets, active leases,
audit events 24h, policies), so there is a natural home for new numbers.

## Goals

- Persist a count of credentials kept out of agent context, and show it as a
  rolling-window stat.
- Compute and surface secret-hygiene signals: unused for 90 days, older than 18
  months, never rotated.
- Make blocked egress visible: SSRF, denied lease/approval, rate-limit, domain
  and path rejections are already logged; show the operator that the guard is
  doing work.

## Non-goals

- No alerting, email, or webhooks for hygiene. Surface in the UI only.
- No automatic rotation or deletion. Nudge, never act. (Consistent with the
  no-auto-action stance elsewhere in the project.)
- No new analytics pipeline. Compute from the SQLite data that exists.

## What the data supports today

- Read events per secret: `secret.reveal_value`, `secret.read_metadata`,
  `secret.read.mcp`, plus `lease.access` and `lease.checkout`. Enough to derive
  last-access by path.
- Blocked egress: `proxy.blocked.rate_limit`, `proxy.blocked.approval` as
  distinct actions, plus `proxy.forward` rows with `success: false` and a
  `metadata.reason` of `ssrf_blocked`, `domain_blocked`, `path_prefix_blocked`,
  or `policy_denied`.
- Age: `secrets.created_at` and `updated_at`.
- The audit log is indexed on `timestamp` and `identity` but not on `action`,
  so action-filtered scans over a long window are full scans.

## Design decisions (vetoable at review)

### D1. Persist redaction counts where the scrub already happens

The "credentials kept out of context" number needs a source. Two scrub sites:

- Proxy response scrubbing: change `scrubResponseBody` to return a count
  alongside the scrubbed body, and add `redaction_count` to the metadata of the
  existing `proxy.forward` and `proxy.forward.mcp` audit rows. No new event
  type, no new write on the hot path beyond a field already being assembled.
- `gatehouse_scrub` tool and `POST /v1/scrub`: emit a lightweight
  `scrub.redact` audit event with `metadata.count` when the count is greater
  than zero. These are explicit user-driven scrubs, low volume, fine to log.

"Credentials kept out of agent context (7d)" is then the sum of
`redaction_count` over `proxy.forward*` rows plus `scrub.redact` counts in the
window. At homelab volume a windowed scan with JSON parse is acceptable. If
volume ever justifies it, a tiny `counters(name, value)` rollup table updated
on write is the optimization, noted but not built now.

### D2. Add `last_accessed_at` to the secrets table

Computing last-access by scanning the audit log on every dashboard load is a
full scan (no `action` index) and gets slower as the log grows. Instead add a
`last_accessed_at TEXT` column to `secrets`, set it on every successful read
path (the same handlers that already emit `secret.reveal_value`,
`secret.read.mcp`, and lease access). One indexed-by-primary-key update on a
path that is already doing a decrypt is negligible.

This makes both hygiene queries trivial and index-free: "unused 90 days" is
`last_accessed_at < now-90d OR last_accessed_at IS NULL`, and it powers a
last-used column in the secrets list that mirrors the one AppRoles already
have. Migration backfills `last_accessed_at = updated_at` for existing rows as
a reasonable floor.

Rationale for a column over pure audit-log derivation: the review framed
hygiene as "cheap on top of existing data," and it is, but the cheapest correct
version stores the one timestamp it repeatedly needs rather than recomputing it
from an unindexed scan. It is a one-column migration.

### D3. Hygiene signals are nudges rendered as badges and a summary

- In the secrets list: a "last used" cell, and a small badge for stale (unused
  90 days) and old (created over 18 months ago, or `updated_at` over 18 months
  for never-rotated). Thresholds are constants, not configurable in v1.
- On the dashboard: a hygiene summary line, "3 secrets unused 90d, 1 over
  18mo," linking to the filtered secrets list.
- No action buttons that rotate or delete. The nudge points the operator at the
  secret; they decide. This keeps the tool advisory.

### D4. A posture row in the existing stat grid

Add to the dashboard `.stat-grid`:

- "Kept out of agent context (7d)": the D1 sum. The headline value sentence.
- "Blocked egress (7d)": count of `proxy.blocked.*` plus `proxy.forward`
  failures with a blocking `reason`. Hover or click breaks it down by reason
  (SSRF, approval, rate limit, domain, path, policy).
- The hygiene summary from D3.

These reuse the existing stat-card rendering. The numbers come from one new
read endpoint (D5).

### D5. One stats endpoint, windowed

Add `GET /v1/stats/posture?window=7d` (admin-gated) returning:

```
{
  "redactions": { "window": "7d", "count": 1240 },
  "blocked_egress": {
    "window": "7d", "total": 18,
    "by_reason": { "ssrf_blocked": 2, "rate_limit": 5, "approval": 9,
                   "domain_blocked": 1, "path_prefix_blocked": 1 }
  },
  "hygiene": { "stale_90d": 3, "older_18mo": 1, "total_secrets": 42 }
}
```

Redactions and blocked egress come from windowed audit queries (the existing
`query({ action, since })` shape). Hygiene comes from `secrets` columns
directly. One endpoint, one render pass, no client-side audit scraping.

## Components

- `src/security/ssrf.ts`: `scrubResponseBody` returns `{ body, count }`.
- `src/api/proxy.ts`, `src/mcp/server.ts`: thread the count into the existing
  `proxy.forward*` audit metadata.
- `src/api/scrub.ts`, `src/mcp/server.ts`: emit `scrub.redact` on nonzero
  counts.
- `src/db/init.ts`: `last_accessed_at` column plus backfill migration.
- The read handlers: set `last_accessed_at` on successful reads.
- `src/api/stats.ts` (new): `GET /v1/stats/posture`.
- `src/ui/index.html`: the posture cards, hygiene summary, and the secrets-list
  last-used column and badges.

## Error handling

- Empty windows return zeros, not errors. A fresh install shows "0 kept out
  this week," which is honest and becomes a positive number fast.
- The redaction sum tolerates missing `redaction_count` metadata on old audit
  rows (treat as zero), so the migration needs no audit backfill.

## Testing

- `scrubResponseBody` returns the correct count for known inputs, and a
  `proxy.forward` row carries it.
- A read sets `last_accessed_at`; the hygiene query buckets a seeded set of
  secrets correctly across the thresholds.
- `GET /v1/stats/posture` returns the expected shape and respects the window.

## Rollout

This whole sub-project is independent and low-risk, so it can land in one or
two PRs and is a good candidate for the first visible win while A is in design.

1. `last_accessed_at` column, backfill, read-path writes, and the
   secrets-list last-used column. (Hygiene half.)
2. `scrubResponseBody` count, audit metadata, `scrub.redact`. (Value half.)
3. `GET /v1/stats/posture` and the dashboard cards.

## Open questions

- Thresholds (90 days, 18 months) hard-coded in v1 or a setting? Leaning
  hard-coded constants now, configurable later if asked.
- Should `scrub.redact` log the redaction types (which credential pattern
  matched) or only the count? Types are more useful for posture but slightly
  more revealing in the audit log. Leaning count plus types, since the audit
  log is already operator-only.
